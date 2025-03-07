/* Copyright (c) 2023, Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <stdbool.h>

#include "lflow.h"
#include "local_data.h"
#include "lport.h"
#include "mac-cache.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "ovn/logical-fields.h"
#include "ovn-sb-idl.h"
#include "pinctrl.h"

VLOG_DEFINE_THIS_MODULE(mac_cache);

#define MAX_BUFFERED_PACKETS        1000
#define BUFFER_QUEUE_DEPTH          4
#define BUFFERED_PACKETS_TIMEOUT_MS 10000
#define BUFFERED_PACKETS_LOOKUP_MS  100

static uint32_t
mac_binding_data_hash(const struct mac_binding_data *mb_data);
static inline bool
mac_binding_data_equals(const struct mac_binding_data *a,
                        const struct mac_binding_data *b);
static void mac_binding_update_log(const char *action,
                                   const struct mac_binding_data *,
                                   bool print_times,
                                   const struct mac_cache_threshold *,
                                   int64_t idle_age_ms,
                                   uint64_t since_updated_ms);
static uint32_t
fdb_data_hash(const struct fdb_data *fdb_data);
static inline bool
fdb_data_equals(const struct fdb_data *a, const struct fdb_data *b);
static uint64_t
mac_cache_threshold_get_value_ms(const struct sbrec_datapath_binding *dp);
static void
mac_cache_threshold_remove(struct hmap *thresholds,
                           struct mac_cache_threshold *threshold);
static void
mac_cache_update_req_delay(struct hmap *thresholds, uint64_t *req_delay);

static struct buffered_packets *
buffered_packets_find(struct buffered_packets_ctx *ctx,
                      const struct mac_binding_data *mb_data);

static void
buffered_packets_remove(struct buffered_packets_ctx *ctx,
                        struct buffered_packets *bp);

static void
buffered_packets_db_lookup(struct buffered_packets *bp,
                           struct ds *ip, struct eth_addr *mac,
                           struct ovsdb_idl_index *sbrec_pb_by_key,
                           struct ovsdb_idl_index *sbrec_dp_by_key,
                           struct ovsdb_idl_index *sbrec_pb_by_name,
                           struct ovsdb_idl_index *sbrec_mb_by_lport_ip);

/* Thresholds. */
void
mac_cache_threshold_add(struct mac_cache_data *data,
                        const struct sbrec_datapath_binding *dp)
{
    struct mac_cache_threshold *threshold =
            mac_cache_threshold_find(data, dp->tunnel_key);
    if (threshold) {
        return;
    }

    uint64_t value = mac_cache_threshold_get_value_ms(dp);
    if (!value) {
        return;
    }

    threshold = xmalloc(sizeof *threshold);
    threshold->dp_key = dp->tunnel_key;
    threshold->value = value;
    threshold->dump_period = (3 * value) / 16;
    threshold->cooldown_period = (3 * value) / 16;

    /* (cooldown_period + dump_period) is the maximum time the timestamp may
     * be not updated for an entry with IP + MAC combination from which we see
     * incoming traffic.  For the entry that is used only in Tx direction
     * (e.g., an entry for a default gateway of the chassis) this time is
     * doubled, because an ARP/ND probe will need to be sent first and the
     * (cooldown_period + dump_period) will be the maximum time between such
     * probes.  Hence, 2 * (cooldown_period + dump_period) should be less than
     * a threshold, otherwise we may fail to update an active MAC binding in
     * time and risk it being removed.  Giving it an extra 1/10 of the time
     * for all the processing that needs to happen. */
    ovs_assert(2 * (threshold->cooldown_period + threshold->dump_period)
               < (9 * value) / 10);

    hmap_insert(&data->thresholds, &threshold->hmap_node, dp->tunnel_key);
}

void
mac_cache_threshold_replace(struct mac_cache_data *data,
                            const struct sbrec_datapath_binding *dp,
                            const struct hmap *local_datapaths)
{
    struct mac_cache_threshold *threshold =
            mac_cache_threshold_find(data, dp->tunnel_key);
    if (threshold) {
        mac_cache_threshold_remove(&data->thresholds, threshold);
    }

    if (!get_local_datapath(local_datapaths, dp->tunnel_key)) {
        return;
    }

    mac_cache_threshold_add(data, dp);
}


struct mac_cache_threshold *
mac_cache_threshold_find(struct mac_cache_data *data, uint32_t dp_key)
{
    struct mac_cache_threshold *threshold;
    HMAP_FOR_EACH_WITH_HASH (threshold, hmap_node, dp_key, &data->thresholds) {
        if (threshold->dp_key == dp_key) {
            return threshold;
        }
    }

    return NULL;
}

void
mac_cache_thresholds_sync(struct mac_cache_data *data,
                          const struct hmap *local_datapaths)
{
    struct mac_cache_threshold *threshold;
    HMAP_FOR_EACH_SAFE (threshold, hmap_node, &data->thresholds) {
        if (!get_local_datapath(local_datapaths, threshold->dp_key)) {
            mac_cache_threshold_remove(&data->thresholds, threshold);
        }
    }
}

void
mac_cache_thresholds_clear(struct mac_cache_data *data)
{
    struct mac_cache_threshold *threshold;
    HMAP_FOR_EACH_POP (threshold, hmap_node, &data->thresholds) {
        free(threshold);
    }
}

/* MAC binding. */
void
mac_binding_add(struct hmap *map, struct mac_binding_data mb_data,
                const struct sbrec_mac_binding *smb, long long timestamp)
{
    struct mac_binding *mb = mac_binding_find(map, &mb_data);
    if (!mb) {
        mb = xmalloc(sizeof *mb);
        hmap_insert(map, &mb->hmap_node, mac_binding_data_hash(&mb_data));
    }

    mb->data = mb_data;
    mb->sbrec = smb;
    mb->timestamp = timestamp;
    mac_binding_update_log("Added", &mb_data, false, NULL, 0, 0);
}

void
mac_binding_remove(struct hmap *map, struct mac_binding *mb)
{
    mac_binding_update_log("Removed", &mb->data, false, NULL, 0, 0);
    hmap_remove(map, &mb->hmap_node);
    free(mb);
}

struct mac_binding *
mac_binding_find(const struct hmap *map,
                 const struct mac_binding_data *mb_data) {
    uint32_t hash = mac_binding_data_hash(mb_data);

    struct mac_binding *mb;
    HMAP_FOR_EACH_WITH_HASH (mb, hmap_node, hash, map) {
        if (mac_binding_data_equals(&mb->data, mb_data)) {
            return mb;
        }
    }

    return NULL;
}

bool
mac_binding_data_parse(struct mac_binding_data *data,
                       uint32_t dp_key, uint32_t port_key,
                       const char *ip_str, const char *mac_str)
{
    struct eth_addr mac;
    struct in6_addr ip;

    if (!ip46_parse(ip_str, &ip) || !eth_addr_from_string(mac_str, &mac)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Couldn't parse MAC binding: ip=%s, mac=%s",
                     ip_str, mac_str);
        return false;
    }

    mac_binding_data_init(data, dp_key, port_key, ip, mac);
    return true;
}

bool
mac_binding_data_from_sbrec(struct mac_binding_data *data,
                            const struct sbrec_mac_binding *mb)
{
    /* This explicitly sets the port_key to 0 as port_binding tunnel_keys
     * can change.  Instead use add the SB.MAC_Binding UUID as key; this
     * makes the mac_binding_data key unique. */
    if (!mac_binding_data_parse(data, mb->datapath->tunnel_key, 0,
                                mb->ip, mb->mac)) {
        return false;
    }

    data->cookie = mb->header_.uuid.parts[0];
    return true;
}

void
mac_bindings_clear(struct hmap *map)
{
    struct mac_binding *mb;
    HMAP_FOR_EACH_POP (mb, hmap_node, map) {
        free(mb);
    }
}

static void
mac_binding_data_to_string(const struct mac_binding_data *data,
                           struct ds *out_data)
{
    char ip[INET6_ADDRSTRLEN];

    if (!ipv6_string_mapped(ip, &data->ip)) {
        return;
    }
    ds_put_format(out_data, "cookie: 0x%08"PRIx64", "
                            "datapath-key: %"PRIu32", "
                            "port-key: %"PRIu32", "
                            "ip: %s, mac: " ETH_ADDR_FMT,
                  data->cookie, data->dp_key, data->port_key,
                  ip, ETH_ADDR_ARGS(data->mac));
}

void
mac_bindings_to_string(const struct hmap *map, struct ds *out_data)
{
    struct mac_binding *mb;
    HMAP_FOR_EACH (mb, hmap_node, map) {
        mac_binding_data_to_string(&mb->data, out_data);
        ds_put_char(out_data, '\n');
    }
}

bool
sb_mac_binding_updated(const struct sbrec_mac_binding *mb)
{
    bool updated = false;
    for (size_t i = 0; i < SBREC_MAC_BINDING_N_COLUMNS; i++) {
        /* Ignore timestamp update as this does not affect the existing nodes
         * at all. */
        if (i == SBREC_MAC_BINDING_COL_TIMESTAMP) {
            continue;
        }
        updated |= sbrec_mac_binding_is_updated(mb, i);
    }

    return updated || sbrec_mac_binding_is_deleted(mb);
}

const struct sbrec_mac_binding *
mac_binding_lookup(struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                   const char *logical_port, const char *ip) {
    struct sbrec_mac_binding *mb =
            sbrec_mac_binding_index_init_row(sbrec_mac_binding_by_lport_ip);
    sbrec_mac_binding_index_set_logical_port(mb, logical_port);
    sbrec_mac_binding_index_set_ip(mb, ip);

    const struct sbrec_mac_binding *retval =
            sbrec_mac_binding_index_find(sbrec_mac_binding_by_lport_ip, mb);

    sbrec_mac_binding_index_destroy_row(mb);

    return retval;
}

/* FDB. */
struct fdb *
fdb_add(struct hmap *map, struct fdb_data fdb_data) {
    struct fdb *fdb = fdb_find(map, &fdb_data);

    if (!fdb) {
        fdb = xmalloc(sizeof *fdb);
        fdb->sbrec_fdb = NULL;
        hmap_insert(map, &fdb->hmap_node, fdb_data_hash(&fdb_data));
    }

    fdb->data = fdb_data;

    return fdb;
}

void
fdb_remove(struct hmap *map, struct fdb *fdb)
{
    hmap_remove(map, &fdb->hmap_node);
    free(fdb);
}

bool
fdb_data_from_sbrec(struct fdb_data *data, const struct sbrec_fdb *fdb)
{
    if (!eth_addr_from_string(fdb->mac, &data->mac)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Couldn't parse FDB: mac=%s", fdb->mac);
        return false;
    }

    data->dp_key = fdb->dp_key;
    data->port_key = fdb->port_key;

    return true;
}

struct fdb *
fdb_find(const struct hmap *map, const struct fdb_data *fdb_data)
{
    uint32_t hash = fdb_data_hash(fdb_data);

    struct fdb *fdb;
    HMAP_FOR_EACH_WITH_HASH (fdb, hmap_node, hash, map) {
        if (fdb_data_equals(&fdb->data, fdb_data)) {
            return fdb;
        }
    }

    return NULL;
}

bool
sb_fdb_updated(const struct sbrec_fdb *fdb)
{
    bool updated = false;
    for (size_t i = 0; i < SBREC_FDB_N_COLUMNS; i++) {
        /* Ignore timestamp update as this does not affect the existing nodes
         * at all. */
        if (i == SBREC_FDB_COL_TIMESTAMP) {
            continue;
        }
        updated |= sbrec_fdb_is_updated(fdb, i);
    }

    return updated || sbrec_fdb_is_deleted(fdb);
}

void
fdbs_clear(struct hmap *map)
{
    struct fdb *fdb;
    HMAP_FOR_EACH_POP (fdb, hmap_node, map) {
        free(fdb);
    }
}

struct mac_cache_stats {
    struct ovs_list list_node;

    int64_t idle_age_ms;

    union {
        /* Common data to identify MAC binding. */
        struct mac_binding_data mb;
        /* Common data to identify FDB. */
        struct fdb_data fdb;
    } data;
};

/* MAC binding stat processing. */
void
mac_binding_stats_process_flow_stats(struct ovs_list *stats_list,
                                     struct ofputil_flow_stats *ofp_stats)
{
    struct mac_cache_stats *stats = xmalloc(sizeof *stats);

    stats->idle_age_ms = ofp_stats->idle_age * 1000;
    stats->data.mb = (struct mac_binding_data) {
        .cookie = ntohll(ofp_stats->cookie),
        /* The port_key must be zero to match mac_binding_data_from_sbrec. */
        .port_key = 0,
        .dp_key = ntohll(ofp_stats->match.flow.metadata),
        .mac = ofp_stats->match.flow.dl_src
    };

    if (ofp_stats->match.flow.dl_type == htons(ETH_TYPE_IP) ||
        ofp_stats->match.flow.dl_type == htons(ETH_TYPE_ARP)) {
        stats->data.mb.ip = in6_addr_mapped_ipv4(ofp_stats->match.flow.nw_src);
    } else {
        stats->data.mb.ip = ofp_stats->match.flow.ipv6_src;
    }

    ovs_list_push_back(stats_list, &stats->list_node);
}

static void
mac_binding_update_log(const char *action,
                       const struct mac_binding_data *data,
                       bool print_times,
                       const struct mac_cache_threshold *threshold,
                       int64_t idle_age_ms, uint64_t since_updated_ms)
{
    if (!VLOG_IS_DBG_ENABLED()) {
        return;
    }

    struct ds s = DS_EMPTY_INITIALIZER;

    ds_put_cstr(&s, action);
    ds_put_cstr(&s, " MAC binding (");
    mac_binding_data_to_string(data, &s);
    if (print_times) {
        ds_put_format(&s, "), last update: %"PRIu64"ms ago,"
                          " idle age: %"PRIi64"ms, threshold: %"PRIu64"ms",
                      since_updated_ms, idle_age_ms, threshold->value);
    } else {
        ds_put_char(&s, ')');
    }
    VLOG_DBG("%s.", ds_cstr_ro(&s));
    ds_destroy(&s);
}

void
mac_binding_stats_run(
        struct rconn *swconn OVS_UNUSED,
        struct ovsdb_idl_index *sbrec_port_binding_by_name OVS_UNUSED,
        struct ovs_list *stats_list, uint64_t *req_delay, void *data)
{
    struct mac_cache_data *cache_data = data;
    long long timewall_now = time_wall_msec();

    struct mac_cache_stats *stats;
    LIST_FOR_EACH_POP (stats, list_node, stats_list) {
        struct mac_binding *mb = mac_binding_find(&cache_data->mac_bindings,
                                                  &stats->data.mb);
        if (!mb) {
            mac_binding_update_log("Not found in the cache:", &stats->data.mb,
                                   false, NULL, 0, 0);
            free(stats);
            continue;
        }

        uint64_t since_updated_ms = timewall_now - mb->sbrec->timestamp;
        struct mac_cache_threshold *threshold =
                mac_cache_threshold_find(cache_data, mb->data.dp_key);

        /* If "idle_age" is under threshold it means that the mac binding is
         * used on this chassis. */
        if (stats->idle_age_ms < threshold->value) {
            if (since_updated_ms >= threshold->cooldown_period) {
                mac_binding_update_log("Updating active", &mb->data, true,
                                       threshold, stats->idle_age_ms,
                                       since_updated_ms);
                sbrec_mac_binding_set_timestamp(mb->sbrec, timewall_now);
            } else {
                /* Postponing the update to avoid sending database transactions
                 * too frequently. */
                mac_binding_update_log("Not updating active", &mb->data, true,
                                       threshold, stats->idle_age_ms,
                                       since_updated_ms);
            }
        } else {
            mac_binding_update_log("Not updating non-active", &mb->data, true,
                                   threshold, stats->idle_age_ms,
                                   since_updated_ms);
        }
        free(stats);
    }

    mac_cache_update_req_delay(&cache_data->thresholds, req_delay);
    if (*req_delay) {
        VLOG_DBG("MAC binding statistics dalay: %"PRIu64, *req_delay);
    }
}

/* FDB stat processing. */
void
fdb_stats_process_flow_stats(struct ovs_list *stats_list,
                             struct ofputil_flow_stats *ofp_stats)
{
    struct mac_cache_stats *stats = xmalloc(sizeof *stats);

    stats->idle_age_ms = ofp_stats->idle_age * 1000;
    stats->data.fdb = (struct fdb_data) {
            .port_key = ofp_stats->match.flow.regs[MFF_LOG_INPORT - MFF_REG0],
            .dp_key = ntohll(ofp_stats->match.flow.metadata),
            .mac = ofp_stats->match.flow.dl_src
    };

    ovs_list_push_back(stats_list, &stats->list_node);
}

static void
fdb_update_log(const char *action,
               const struct fdb_data *data,
               bool print_times,
               const struct mac_cache_threshold *threshold,
               int64_t idle_age_ms, uint64_t since_updated_ms)
{
    if (!VLOG_IS_DBG_ENABLED()) {
        return;
    }

    struct ds s = DS_EMPTY_INITIALIZER;

    ds_put_cstr(&s, action);
    ds_put_format(&s, " FDB entry (datapath-key: %"PRIu32", "
                      "port-key: %"PRIu32", mac: " ETH_ADDR_FMT,
                  data->dp_key, data->port_key, ETH_ADDR_ARGS(data->mac));
    if (print_times) {
        ds_put_format(&s, "), last update: %"PRIu64"ms ago,"
                          " idle age: %"PRIi64"ms, threshold: %"PRIu64"ms",
                      since_updated_ms, idle_age_ms, threshold->value);
    } else {
        ds_put_char(&s, ')');
    }
    VLOG_DBG("%s.", ds_cstr_ro(&s));
    ds_destroy(&s);
}

void
fdb_stats_run(struct rconn *swconn OVS_UNUSED,
              struct ovsdb_idl_index *sbrec_port_binding_by_name OVS_UNUSED,
              struct ovs_list *stats_list,
              uint64_t *req_delay, void *data)
{
    struct mac_cache_data *cache_data = data;
    long long timewall_now = time_wall_msec();

    struct mac_cache_stats *stats;
    LIST_FOR_EACH_POP (stats, list_node, stats_list) {
        struct fdb *fdb = fdb_find(&cache_data->fdbs, &stats->data.fdb);

        if (!fdb) {
            fdb_update_log("Not found in the cache:", &stats->data.fdb,
                           false, NULL, 0, 0);
            free(stats);
            continue;
        }

        uint64_t since_updated_ms = timewall_now - fdb->sbrec_fdb->timestamp;
        struct mac_cache_threshold *threshold =
                mac_cache_threshold_find(cache_data, fdb->data.dp_key);

        /* If "idle_age" is under threshold it means that the fdb entry is
         * used on this chassis. */
        if (stats->idle_age_ms < threshold->value) {
            if (since_updated_ms >= threshold->cooldown_period) {
                fdb_update_log("Updating active", &fdb->data, true,
                               threshold, stats->idle_age_ms,
                               since_updated_ms);
                sbrec_fdb_set_timestamp(fdb->sbrec_fdb, timewall_now);
            } else {
                /* Postponing the update to avoid sending database transactions
                 * too frequently. */
                fdb_update_log("Not updating active", &fdb->data, true,
                               threshold, stats->idle_age_ms,
                               since_updated_ms);
            }
        } else {
            fdb_update_log("Not updating non-active", &fdb->data, true,
                           threshold, stats->idle_age_ms, since_updated_ms);
        }

        free(stats);
    }

    mac_cache_update_req_delay(&cache_data->thresholds, req_delay);
    if (*req_delay) {
        VLOG_DBG("FDB entry statistics dalay: %"PRIu64, *req_delay);
    }
}

/* Packet buffering. */
struct bp_packet_data *
bp_packet_data_create(const struct ofputil_packet_in *pin,
                      const struct ofpbuf *continuation) {
    struct bp_packet_data *pd = xmalloc(sizeof *pd);

    pd->pin = (struct ofputil_packet_in) {
            .packet = xmemdup(pin->packet, pin->packet_len),
            .packet_len = pin->packet_len,
            .flow_metadata = pin->flow_metadata,
            .reason = pin->reason,
            .table_id = pin->table_id,
            .cookie = pin->cookie,
            /* Userdata are empty on purpose,
             * it is not needed for the continuation. */
            .userdata = NULL,
            .userdata_len = 0,
    };
    pd->continuation = ofpbuf_clone(continuation);

    return pd;
}


void
bp_packet_data_destroy(struct bp_packet_data *pd) {
    free(pd->pin.packet);
    ofpbuf_delete(pd->continuation);
    free(pd);
}

struct buffered_packets *
buffered_packets_add(struct buffered_packets_ctx *ctx,
                     struct mac_binding_data mb_data) {
    uint32_t hash = mac_binding_data_hash(&mb_data);

    struct buffered_packets *bp = buffered_packets_find(ctx, &mb_data);
    if (!bp) {
        if (hmap_count(&ctx->buffered_packets) >= MAX_BUFFERED_PACKETS) {
            return NULL;
        }

        bp = xmalloc(sizeof *bp);
        hmap_insert(&ctx->buffered_packets, &bp->hmap_node, hash);
        bp->mb_data = mb_data;
        /* Schedule the freshly added buffered packet to do lookup
         * immediately. */
        bp->lookup_at_ms = 0;
        ovs_list_init(&bp->queue);
    }

    bp->expire_at_ms = time_msec() + BUFFERED_PACKETS_TIMEOUT_MS;

    return bp;
}

void
buffered_packets_packet_data_enqueue(struct buffered_packets *bp,
                                     struct bp_packet_data *pd) {
    if (ovs_list_size(&bp->queue) == BUFFER_QUEUE_DEPTH) {
        struct bp_packet_data *p = CONTAINER_OF(ovs_list_pop_front(&bp->queue),
                                                struct bp_packet_data, node);

        bp_packet_data_destroy(p);
    }
    ovs_list_push_back(&bp->queue, &pd->node);
}

void
buffered_packets_ctx_run(struct buffered_packets_ctx *ctx,
                         const struct hmap *recent_mbs,
                         struct ovsdb_idl_index *sbrec_pb_by_key,
                         struct ovsdb_idl_index *sbrec_dp_by_key,
                         struct ovsdb_idl_index *sbrec_pb_by_name,
                         struct ovsdb_idl_index *sbrec_mb_by_lport_ip) {
    struct ds ip = DS_EMPTY_INITIALIZER;
    long long now = time_msec();

    struct buffered_packets *bp;
    HMAP_FOR_EACH_SAFE (bp, hmap_node, &ctx->buffered_packets) {
        struct eth_addr mac = eth_addr_zero;
        /* Remove expired buffered packets. */
        if (now > bp->expire_at_ms) {
            buffered_packets_remove(ctx, bp);
            continue;
        }

        struct mac_binding *mb = mac_binding_find(recent_mbs, &bp->mb_data);
        if (mb) {
            mac = mb->data.mac;
        } else if (now >= bp->lookup_at_ms) {
            /* Check if we can do a full lookup. */
            buffered_packets_db_lookup(bp, &ip, &mac, sbrec_pb_by_key,
                                       sbrec_dp_by_key, sbrec_pb_by_name,
                                       sbrec_mb_by_lport_ip);
            /* Schedule next lookup even if we found the MAC address,
             * if the address was found this struct will be deleted anyway. */
            bp->lookup_at_ms = now + BUFFERED_PACKETS_LOOKUP_MS;
        }

        if (eth_addr_is_zero(mac)) {
            continue;
        }

        struct bp_packet_data *pd;
        LIST_FOR_EACH_POP (pd, node, &bp->queue) {
            struct dp_packet packet;
            dp_packet_use_const(&packet, pd->pin.packet, pd->pin.packet_len);

            struct eth_header *eth = dp_packet_data(&packet);
            eth->eth_dst = mac;

            ovs_list_push_back(&ctx->ready_packets_data, &pd->node);
        }

        buffered_packets_remove(ctx, bp);
    }

    ds_destroy(&ip);
}

bool
buffered_packets_ctx_is_ready_to_send(struct buffered_packets_ctx *ctx) {
    return !ovs_list_is_empty(&ctx->ready_packets_data);
}

bool
buffered_packets_ctx_has_packets(struct buffered_packets_ctx *ctx) {
    return !hmap_is_empty(&ctx->buffered_packets);
}

void
buffered_packets_ctx_init(struct buffered_packets_ctx *ctx) {
    hmap_init(&ctx->buffered_packets);
    ovs_list_init(&ctx->ready_packets_data);
}

void
buffered_packets_ctx_destroy(struct buffered_packets_ctx *ctx) {
    struct bp_packet_data *pd;
    LIST_FOR_EACH_POP (pd, node, &ctx->ready_packets_data) {
        bp_packet_data_destroy(pd);
    }

    struct buffered_packets *bp;
    HMAP_FOR_EACH_SAFE (bp, hmap_node, &ctx->buffered_packets) {
        buffered_packets_remove(ctx, bp);
    }
    hmap_destroy(&ctx->buffered_packets);
}


void
mac_cache_stats_destroy(struct ovs_list *stats_list)
{
    struct mac_cache_stats *stats;
    LIST_FOR_EACH_POP (stats, list_node, stats_list) {
        free(stats);
    }
}

static uint32_t
mac_binding_data_hash(const struct mac_binding_data *mb_data)
{
    uint32_t hash = hash_uint64(mb_data->cookie);

    hash = hash_add(hash, mb_data->port_key);
    hash = hash_add(hash, mb_data->dp_key);
    hash = hash_add_in6_addr(hash, &mb_data->ip);

    return hash_finish(hash, 24);
}

static inline bool
mac_binding_data_equals(const struct mac_binding_data *a,
                        const struct mac_binding_data *b)
{
    return a->cookie == b->cookie &&
           a->port_key == b->port_key &&
           a->dp_key == b->dp_key &&
           ipv6_addr_equals(&a->ip, &b->ip);
}

static uint32_t
fdb_data_hash(const struct fdb_data *fdb_data)
{
    uint32_t hash = 0;

    hash = hash_add(hash, fdb_data->dp_key);
    hash = hash_add64(hash, eth_addr_to_uint64(fdb_data->mac));

    return hash_finish(hash, 12);
}

static inline bool
fdb_data_equals(const struct fdb_data *a, const struct fdb_data *b)
{
    return a->dp_key == b->dp_key &&
           eth_addr_equals(a->mac, b->mac);
}

static uint64_t
mac_cache_threshold_get_value_ms(const struct sbrec_datapath_binding *dp)
{
    uint64_t mb_value =
            smap_get_uint(&dp->external_ids, "mac_binding_age_threshold", 0);
    uint64_t fdb_value =
            smap_get_uint(&dp->external_ids, "fdb_age_threshold", 0);

    if (mb_value && fdb_value) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Invalid aging threshold configuration for datapath:"
                          " "UUID_FMT, UUID_ARGS(&dp->header_.uuid));
        return 0;
    }

    return mb_value ? mb_value * 1000 : fdb_value * 1000;
}

static void
mac_cache_threshold_remove(struct hmap *thresholds,
                           struct mac_cache_threshold *threshold)
{
    hmap_remove(thresholds, &threshold->hmap_node);
    free(threshold);
}

static void
mac_cache_update_req_delay(struct hmap *thresholds, uint64_t *req_delay)
{
    struct mac_cache_threshold *threshold;

    uint64_t dump_period = UINT64_MAX;
    HMAP_FOR_EACH (threshold, hmap_node, thresholds) {
        dump_period = MIN(dump_period, threshold->dump_period);
    }

    *req_delay = dump_period < UINT64_MAX ? dump_period : 0;
}

static struct buffered_packets *
buffered_packets_find(struct buffered_packets_ctx *ctx,
                      const struct mac_binding_data *mb_data) {
    uint32_t hash = mac_binding_data_hash(mb_data);

    struct buffered_packets *bp;
    HMAP_FOR_EACH_WITH_HASH (bp, hmap_node, hash, &ctx->buffered_packets) {
        if (mac_binding_data_equals(&bp->mb_data, mb_data)) {
            return bp;
        }
    }

    return NULL;
}

static void
buffered_packets_remove(struct buffered_packets_ctx *ctx,
                        struct buffered_packets *bp) {
    struct bp_packet_data *pd;
    LIST_FOR_EACH_POP (pd, node, &bp->queue) {
        bp_packet_data_destroy(pd);
    }

    hmap_remove(&ctx->buffered_packets, &bp->hmap_node);
    free(bp);
}

static void
buffered_packets_db_lookup(struct buffered_packets *bp, struct ds *ip,
                           struct eth_addr *mac,
                           struct ovsdb_idl_index *sbrec_pb_by_key,
                           struct ovsdb_idl_index *sbrec_dp_by_key,
                           struct ovsdb_idl_index *sbrec_pb_by_name,
                           struct ovsdb_idl_index *sbrec_mb_by_lport_ip) {
    const struct sbrec_port_binding *pb =
            lport_lookup_by_key(sbrec_dp_by_key, sbrec_pb_by_key,
                                bp->mb_data.dp_key, bp->mb_data.port_key);
    if (!pb) {
        return;
    }

    if (!strcmp(pb->type, "chassisredirect")) {
        const char *dgp_name =
                smap_get_def(&pb->options, "distributed-port", "");
        pb = lport_lookup_by_name(sbrec_pb_by_name, dgp_name);
        if (!pb) {
            return;
        }
    }

    ipv6_format_mapped(&bp->mb_data.ip, ip);
    const struct sbrec_mac_binding *smb =
            mac_binding_lookup(sbrec_mb_by_lport_ip, pb->logical_port,
                               ds_cstr_ro(ip));
    ds_clear(ip);

    if (!smb) {
        return;
    }

    eth_addr_from_string(smb->mac, mac);
}

void
mac_binding_probe_stats_process_flow_stats(
        struct ovs_list *stats_list,
        struct ofputil_flow_stats *ofp_stats)
{
    struct mac_cache_stats *stats = xmalloc(sizeof *stats);

    stats->idle_age_ms = ofp_stats->idle_age * 1000;
    stats->data.mb = (struct mac_binding_data) {
        .cookie = ntohll(ofp_stats->cookie),
        /* The port_key must be zero to match mac_binding_data_from_sbrec. */
        .port_key = 0,
        .dp_key = ntohll(ofp_stats->match.flow.metadata),
    };

    if (ofp_stats->match.flow.regs[0]) {
        stats->data.mb.ip =
            in6_addr_mapped_ipv4(htonl(ofp_stats->match.flow.regs[0]));
    } else {
        ovs_be128 ip6 = hton128(flow_get_xxreg(&ofp_stats->match.flow, 1));
        memcpy(&stats->data.mb.ip, &ip6, sizeof stats->data.mb.ip);
    }

    ovs_list_push_back(stats_list, &stats->list_node);
}

void
mac_binding_probe_stats_run(
        struct rconn *swconn,
        struct ovsdb_idl_index *sbrec_port_binding_by_name,
        struct ovs_list *stats_list,
        uint64_t *req_delay, void *data)
{
    long long timewall_now = time_wall_msec();
    struct mac_cache_data *cache_data = data;

    struct mac_cache_stats *stats;
    LIST_FOR_EACH_POP (stats, list_node, stats_list) {
        struct mac_binding *mb = mac_binding_find(&cache_data->mac_bindings,
                                                  &stats->data.mb);
        if (!mb) {
            mac_binding_update_log("Probe: not found in the cache:",
                                   &stats->data.mb, false, NULL, 0, 0);
            free(stats);
            continue;
        }

        struct mac_cache_threshold *threshold =
                mac_cache_threshold_find(cache_data, mb->data.dp_key);
        uint64_t since_updated_ms = timewall_now - mb->sbrec->timestamp;
        const struct sbrec_mac_binding *sbrec = mb->sbrec;

        if (stats->idle_age_ms > threshold->value) {
            mac_binding_update_log("Not sending ARP/ND request for non-active",
                                   &mb->data, true, threshold,
                                   stats->idle_age_ms, since_updated_ms);
            free(stats);
            continue;
        }

        if (since_updated_ms < threshold->cooldown_period) {
            mac_binding_update_log(
                    "Not sending ARP/ND request for recently updated",
                    &mb->data, true, threshold, stats->idle_age_ms,
                    since_updated_ms);
            free(stats);
            continue;
        }

        const struct sbrec_port_binding *pb =
            lport_lookup_by_name(sbrec_port_binding_by_name,
                                 sbrec->logical_port);
        if (!pb) {
            free(stats);
            continue;
        }

        struct lport_addresses laddr;
        if (!extract_lsp_addresses(pb->mac[0], &laddr)) {
            free(stats);
            continue;
        }

        if (laddr.n_ipv4_addrs || laddr.n_ipv6_addrs) {
            struct in6_addr local = laddr.n_ipv4_addrs
                ? in6_addr_mapped_ipv4(laddr.ipv4_addrs[0].addr)
                : laddr.ipv6_addrs[0].addr;

            mac_binding_update_log("Sending ARP/ND request for active",
                                   &mb->data, true, threshold,
                                   stats->idle_age_ms, since_updated_ms);

            send_self_originated_neigh_packet(swconn,
                                              sbrec->datapath->tunnel_key,
                                              pb->tunnel_key, laddr.ea,
                                              &local, &mb->data.ip,
                                              OFTABLE_LOCAL_OUTPUT);
        }

        free(stats);
        destroy_lport_addresses(&laddr);
    }

    mac_cache_update_req_delay(&cache_data->thresholds, req_delay);
    if (*req_delay) {
        VLOG_DBG("MAC probe binding statistics delay: %"PRIu64, *req_delay);
    }
}
