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
#include "lib/mac-binding-index.h"
#include "lib/vec.h"
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
#define PROBE_MULICAST_THRESHOLD     2

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
static uint64_t mac_cache_scope_threshold_get_value_ms(
    const struct sbrec_mac_binding_scope *);
static void
mac_cache_threshold_remove(struct hmap *thresholds,
                           struct mac_cache_threshold *threshold);
static void
mac_cache_update_req_delay(struct hmap *thresholds, uint64_t *req_delay);
static struct mac_cache_threshold *mac_cache_threshold_find__(
    struct mac_cache_data *, uint32_t, bool);
static void mac_cache_threshold_add__(struct mac_cache_data *, uint32_t,
                                      uint64_t, bool);

static struct buffered_packets *
buffered_packets_find(struct cmap *bp_map,
                      const struct mac_binding_data *mb_data);

static void
buffered_packets_free(struct buffered_packets *bp);

static void
buffered_packets_db_lookup(struct buffered_packets *bp,
                           struct ds *ip, struct eth_addr *mac,
                           struct ovsdb_idl_index *sbrec_pb_by_key,
                           struct ovsdb_idl_index *sbrec_dp_by_key,
                           struct ovsdb_idl_index *sbrec_pb_by_name,
                           struct ovsdb_idl_index *sbrec_mb_by_lport_ip,
                           struct ovsdb_idl_index *shared_mb_by_scope_ip);

static const struct sbrec_port_binding *
buffered_packets_get_pb(const struct buffered_packets *bp,
                        struct ovsdb_idl_index *sbrec_pb_by_key,
                        struct ovsdb_idl_index *sbrec_dp_by_key,
                        struct ovsdb_idl_index *sbrec_pb_by_name);

/* Thresholds. */
void
mac_cache_threshold_add(struct mac_cache_data *data,
                        const struct sbrec_datapath_binding *dp)
{
    mac_cache_threshold_add__(data, dp->tunnel_key,
                              mac_cache_threshold_get_value_ms(dp), false);
}

void
mac_cache_threshold_add_scope(struct mac_cache_data *data,
                              const struct sbrec_mac_binding_scope *scope)
{
    mac_cache_threshold_add__(data, scope->binding_key,
                              mac_cache_scope_threshold_get_value_ms(scope),
                              true);
}

static void
mac_cache_threshold_add__(struct mac_cache_data *data, uint32_t key,
                          uint64_t value, bool is_scope)
{
    struct mac_cache_threshold *threshold =
        mac_cache_threshold_find__(data, key, is_scope);
    if (threshold) {
        return;
    }
    if (!value) {
        return;
    }

    threshold = xmalloc(sizeof *threshold);
    threshold->dp_key = key;
    threshold->is_scope = is_scope;
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

    hmap_insert(&data->thresholds, &threshold->hmap_node,
                hash_2words(key, is_scope));
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
    return mac_cache_threshold_find__(data, dp_key, false);
}

struct mac_cache_threshold *
mac_cache_threshold_find_scope(struct mac_cache_data *data,
                               uint32_t binding_key)
{
    return mac_cache_threshold_find__(data, binding_key, true);
}

static struct mac_cache_threshold *
mac_cache_threshold_find__(struct mac_cache_data *data, uint32_t key,
                           bool is_scope)
{
    struct mac_cache_threshold *threshold;
    HMAP_FOR_EACH_WITH_HASH (threshold, hmap_node,
                             hash_2words(key, is_scope),
                             &data->thresholds) {
        if (threshold->dp_key == key && threshold->is_scope == is_scope) {
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
        if (!threshold->is_scope &&
            !get_local_datapath(local_datapaths, threshold->dp_key)) {
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
    mb->shared_sbrec = NULL;
    mb->timestamp = timestamp;
    mb->arp_attempts = 0;
    mac_binding_update_log("Added", &mb_data, false, NULL, 0, 0);
}

void
mac_binding_add_shared(struct hmap *map, struct mac_binding_data mb_data,
                       const struct sbrec_shared_mac_binding *smb,
                       long long timestamp)
{
    struct mac_binding *mb = mac_binding_find(map, &mb_data);
    if (!mb) {
        mb = xmalloc(sizeof *mb);
        hmap_insert(map, &mb->hmap_node, mac_binding_data_hash(&mb_data));
    }

    mb->data = mb_data;
    mb->sbrec = NULL;
    mb->shared_sbrec = smb;
    mb->timestamp = timestamp;
    mb->arp_attempts = 0;
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

bool
mac_binding_data_from_shared_sbrec(
    struct mac_binding_data *data,
    const struct sbrec_shared_mac_binding *mb)
{
    if (!mac_binding_data_parse(data, mb->scope->binding_key, 0,
                                mb->ip, mb->mac)) {
        return false;
    }

    data->cookie = mb->header_.uuid.parts[0];
    data->is_scope = true;
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
                            "namespace: %s, "
                            "datapath-key: %"PRIu32", "
                            "port-key: %"PRIu32", "
                            "ip: %s, mac: " ETH_ADDR_FMT,
                  data->cookie, data->is_scope ? "scope" : "datapath",
                  data->dp_key, data->port_key,
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

/* FDB. */
struct fdb *
fdb_add(struct hmap *map, struct fdb_data fdb_data, long long timestamp)
{
    struct fdb *fdb = fdb_find(map, &fdb_data);

    if (!fdb) {
        fdb = xmalloc(sizeof *fdb);
        fdb->sbrec_fdb = NULL;
        hmap_insert(map, &fdb->hmap_node, fdb_data_hash(&fdb_data));
    }

    fdb->data = fdb_data;
    fdb->timestamp = timestamp;
    fdb->cfg = -1;

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

void
fdbs_clear(struct hmap *map)
{
    struct fdb *fdb;
    HMAP_FOR_EACH_POP (fdb, hmap_node, map) {
        free(fdb);
    }
}

/* MAC binding stat processing. */
void
mac_binding_stats_process_flow_stats(struct vector *stats_vec,
                                     struct ofputil_flow_stats *ofp_stats)
{
    if (!ofp_stats->packet_count) {
        return;
    }

    struct mac_cache_stats stats = (struct mac_cache_stats) {
        .idle_age_ms = ofp_stats->idle_age >= 0
                       ? ofp_stats->idle_age * 1000
                       : 0,
        .data.mb = (struct mac_binding_data) {
            .cookie = ntohll(ofp_stats->cookie),
            /* The port_key must be zero to match
             * mac_binding_data_from_sbrec. */
            .port_key = 0,
            .dp_key = ntohll(ofp_stats->match.flow.metadata),
            .is_scope =
                ofp_stats->match.flow.regs[MFF_LOG_INPORT - MFF_REG0] == 0,
            .mac = ofp_stats->match.flow.dl_src
        },
    };

    if (ofp_stats->match.flow.dl_type == htons(ETH_TYPE_IP) ||
        ofp_stats->match.flow.dl_type == htons(ETH_TYPE_ARP)) {
        stats.data.mb.ip = in6_addr_mapped_ipv4(ofp_stats->match.flow.nw_src);
    } else {
        stats.data.mb.ip = ofp_stats->match.flow.ipv6_src;
    }
    vector_push(stats_vec, &stats);
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
mac_binding_stats_run(struct vector *stats_vec, uint64_t *req_delay,
                      void *data, long long timewall_now)
{
    struct mac_cache_data *cache_data = data;

    struct mac_cache_stats *stats;
    VECTOR_FOR_EACH_PTR (stats_vec, stats) {
        struct mac_binding *mb = mac_binding_find(&cache_data->mac_bindings,
                                                  &stats->data.mb);
        if (!mb) {
            mac_binding_update_log("Not found in the cache:", &stats->data.mb,
                                   false, NULL, 0, 0);
            continue;
        }

        int64_t timestamp = mb->data.is_scope
                            ? mb->shared_sbrec->timestamp
                            : mb->sbrec->timestamp;
        uint64_t since_updated_ms = timewall_now - timestamp;
        struct mac_cache_threshold *threshold = mb->data.is_scope
            ? mac_cache_threshold_find_scope(cache_data, mb->data.dp_key)
            : mac_cache_threshold_find(cache_data, mb->data.dp_key);

        /* If "idle_age" is under threshold it means that the mac binding is
         * used on this chassis. */
        if (stats->idle_age_ms < threshold->value) {
            if (since_updated_ms >= threshold->cooldown_period) {
                mac_binding_update_log("Updating active", &mb->data, true,
                                       threshold, stats->idle_age_ms,
                                       since_updated_ms);
                if (mb->data.is_scope) {
                    sbrec_shared_mac_binding_set_timestamp(mb->shared_sbrec,
                                                           timewall_now);
                } else {
                    sbrec_mac_binding_set_timestamp(mb->sbrec, timewall_now);
                }
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
    }

    mac_cache_update_req_delay(&cache_data->thresholds, req_delay);
    if (*req_delay) {
        VLOG_DBG("MAC binding statistics delay: %"PRIu64, *req_delay);
    }
}

/* FDB stat processing. */
void
fdb_stats_process_flow_stats(struct vector *stats_vec,
                             struct ofputil_flow_stats *ofp_stats)
{
    if (!ofp_stats->packet_count) {
        return;
    }

    struct mac_cache_stats stats = (struct mac_cache_stats) {
        .idle_age_ms = ofp_stats->idle_age >= 0
                       ? ofp_stats->idle_age * 1000
                       : 0,
        .data.fdb = (struct fdb_data) {
            .port_key = ofp_stats->match.flow.regs[MFF_LOG_INPORT - MFF_REG0],
            .dp_key = ntohll(ofp_stats->match.flow.metadata),
            .mac = ofp_stats->match.flow.dl_src
        },
    };
    vector_push(stats_vec, &stats);
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
fdb_stats_run(struct vector *stats_vec, uint64_t *req_delay, void *data,
              long long timewall_now)
{
    struct mac_cache_data *cache_data = data;

    struct mac_cache_stats *stats;
    VECTOR_FOR_EACH_PTR (stats_vec, stats) {
        struct fdb *fdb = fdb_find(&cache_data->fdbs, &stats->data.fdb);

        if (!fdb) {
            fdb_update_log("Not found in the cache:", &stats->data.fdb,
                           false, NULL, 0, 0);
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
    }

    mac_cache_update_req_delay(&cache_data->thresholds, req_delay);
    if (*req_delay) {
        VLOG_DBG("FDB entry statistics delay: %"PRIu64, *req_delay);
    }
}

/* Packet buffering. */
void
bp_packet_data_destroy(struct bp_packet_data *pd) {
    free(pd->pin.packet);
    ofpbuf_delete(pd->continuation);
}

struct buffered_packets *
buffered_packets_add(struct cmap *bp_map, struct mac_binding_data mb_data) {
    uint32_t hash = mac_binding_data_hash(&mb_data);

    struct buffered_packets *bp = buffered_packets_find(bp_map, &mb_data);
    if (!bp) {
        if (cmap_count(bp_map) >= MAX_BUFFERED_PACKETS) {
            return NULL;
        }

        bp = xmalloc(sizeof *bp);
        bp->mb_data = mb_data;
        atomic_init(&bp->resolved_mac, 0);
        /* Schedule the freshly added buffered packet to do lookup
         * immediately. */
        bp->lookup_at_ms = 0;
        bp->queue = VECTOR_CAPACITY_INITIALIZER(struct bp_packet_data,
                                                BUFFER_QUEUE_DEPTH);
        cmap_insert(bp_map, &bp->cmap_node, hash);
    }

    bp->expire_at_ms = time_msec() + BUFFERED_PACKETS_TIMEOUT_MS;

    return bp;
}

void
buffered_packets_packet_data_enqueue(struct buffered_packets *bp,
                                     const struct ofputil_packet_in *pin,
                                     const struct ofpbuf *continuation)
{
    if (vector_len(&bp->queue) == BUFFER_QUEUE_DEPTH) {
        struct bp_packet_data pd;
        vector_remove(&bp->queue, 0, &pd);
        bp_packet_data_destroy(&pd);
    }

    struct bp_packet_data pd = (struct bp_packet_data) {
        .pin = (struct ofputil_packet_in) {
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
        },
        .continuation = ofpbuf_clone(continuation),
    };

    vector_push(&bp->queue, &pd);
}

bool
buffered_packets_lookup_run(struct cmap *bp_map, const struct hmap *recent_mbs,
                            struct ovsdb_idl_index *sbrec_pb_by_key,
                            struct ovsdb_idl_index *sbrec_dp_by_key,
                            struct ovsdb_idl_index *sbrec_pb_by_name,
                            struct ovsdb_idl_index *sbrec_mb_by_lport_ip,
                            struct ovsdb_idl_index *shared_mb_by_scope_ip) {
    struct ds ip = DS_EMPTY_INITIALIZER;
    long long now = time_msec();
    bool updated = false;

    struct buffered_packets *bp;
    CMAP_FOR_EACH (bp, cmap_node, bp_map) {
        uint64_t mac64;
        atomic_read(&bp->resolved_mac, &mac64);
        /* MAC for given entry was already resolved,
         * no need to resolve it again. */
        if (mac64) {
            continue;
        }

        struct eth_addr mac = eth_addr_zero;

        struct mac_binding_data lookup_data = bp->mb_data;
        const struct sbrec_port_binding *pb = buffered_packets_get_pb(
            bp, sbrec_pb_by_key, sbrec_dp_by_key, sbrec_pb_by_name);
        if (pb && pb->mac_binding_scope) {
            lookup_data.dp_key = pb->mac_binding_scope->binding_key;
            lookup_data.port_key = 0;
            lookup_data.is_scope = true;
        }

        struct mac_binding *mb = mac_binding_find(recent_mbs, &lookup_data);
        if (mb) {
            mac = mb->data.mac;
        } else if (now >= bp->lookup_at_ms) {
            /* Check if we can do a full lookup. */
            buffered_packets_db_lookup(bp, &ip, &mac, sbrec_pb_by_key,
                                       sbrec_dp_by_key, sbrec_pb_by_name,
                                       sbrec_mb_by_lport_ip,
                                       shared_mb_by_scope_ip);
            /* Schedule next lookup even if we found the MAC address,
             * if the address was found this struct will be deleted anyway. */

            bp->lookup_at_ms = now + BUFFERED_PACKETS_LOOKUP_MS;
        }

        if (!eth_addr_is_zero(mac)) {
            atomic_store(&bp->resolved_mac, eth_addr_to_uint64(mac));
            updated = true;
        }
    }

    ds_destroy(&ip);

    return updated;
}

void
buffered_packets_run(struct cmap *bp_map, struct vector *rpd)
{
    long long now = time_msec();

    struct buffered_packets *bp;
    CMAP_FOR_EACH (bp, cmap_node, bp_map) {
        uint32_t hash = mac_binding_data_hash(&bp->mb_data);

        /* Remove expired buffered packets. */
        if (now > bp->expire_at_ms) {
            cmap_remove(bp_map, &bp->cmap_node, hash);
            ovsrcu_postpone(buffered_packets_free, bp);
            continue;
        }

        uint64_t mac64;
        atomic_read(&bp->resolved_mac, &mac64);
        if (!mac64) {
            continue;
        }

        struct eth_addr mac;
        eth_addr_from_uint64(mac64, &mac);

        struct bp_packet_data *pd;
        VECTOR_FOR_EACH_PTR (&bp->queue, pd) {
            struct dp_packet packet;
            dp_packet_use_const(&packet, pd->pin.packet, pd->pin.packet_len);

            struct eth_header *eth = dp_packet_data(&packet);
            eth->eth_dst = mac;
        }

        vector_push_array(rpd, vector_get_array(&bp->queue),
                          vector_len(&bp->queue));
        vector_clear(&bp->queue);

        cmap_remove(bp_map, &bp->cmap_node, hash);
        ovsrcu_postpone(buffered_packets_free, bp);
    }
}

void
buffered_packets_map_destroy(struct cmap *bp_map) {
    struct buffered_packets *bp;
    CMAP_FOR_EACH (bp, cmap_node, bp_map) {
        cmap_remove(bp_map, &bp->cmap_node,
                    mac_binding_data_hash(&bp->mb_data));
        ovsrcu_postpone(buffered_packets_free, bp);
    }

    cmap_destroy(bp_map);
}

static uint32_t
mac_binding_data_hash(const struct mac_binding_data *mb_data)
{
    uint32_t hash = hash_uint64(mb_data->cookie);

    hash = hash_add(hash, mb_data->port_key);
    hash = hash_add(hash, mb_data->dp_key);
    hash = hash_add(hash, mb_data->is_scope);
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
           a->is_scope == b->is_scope &&
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

static uint64_t
mac_cache_scope_threshold_get_value_ms(
    const struct sbrec_mac_binding_scope *scope)
{
    if (!scope->mac_binding_age_threshold) {
        return 0;
    }

    uint64_t min_value = UINT64_MAX;
    char *thresholds = xstrdup(scope->mac_binding_age_threshold);
    char *save_ptr = NULL;
    for (char *entry = strtok_r(thresholds, ";", &save_ptr); entry;
         entry = strtok_r(NULL, ";", &save_ptr)) {
        const char *value_str = strrchr(entry, ':');
        value_str = value_str ? value_str + 1 : entry;

        unsigned int value;
        if (!str_to_uint(value_str, 10, &value)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Invalid MAC binding aging threshold '%s' "
                         "for scope '%s'", entry, scope->name);
            free(thresholds);
            return 0;
        }
        if (value) {
            min_value = MIN(min_value, value);
        }
    }
    free(thresholds);

    return min_value == UINT64_MAX ? 0 : min_value * 1000;
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
buffered_packets_find(struct cmap *bp_map,
                      const struct mac_binding_data *mb_data) {
    uint32_t hash = mac_binding_data_hash(mb_data);

    struct buffered_packets *bp;
    CMAP_FOR_EACH_WITH_HASH (bp, cmap_node, hash, bp_map) {
        if (mac_binding_data_equals(&bp->mb_data, mb_data)) {
            return bp;
        }
    }

    return NULL;
}

static void
buffered_packets_free(struct buffered_packets *bp) {
    struct bp_packet_data *pd;
    VECTOR_FOR_EACH_PTR (&bp->queue, pd) {
        bp_packet_data_destroy(pd);
    }

    vector_destroy(&bp->queue);
    free(bp);
}

static void
buffered_packets_db_lookup(struct buffered_packets *bp, struct ds *ip,
                           struct eth_addr *mac,
                           struct ovsdb_idl_index *sbrec_pb_by_key,
                           struct ovsdb_idl_index *sbrec_dp_by_key,
                           struct ovsdb_idl_index *sbrec_pb_by_name,
                           struct ovsdb_idl_index *sbrec_mb_by_lport_ip,
                           struct ovsdb_idl_index *shared_mb_by_scope_ip) {
    const struct sbrec_port_binding *pb = buffered_packets_get_pb(
        bp, sbrec_pb_by_key, sbrec_dp_by_key, sbrec_pb_by_name);
    if (!pb) {
        return;
    }

    ipv6_format_mapped(&bp->mb_data.ip, ip);
    if (pb->mac_binding_scope) {
        const struct sbrec_shared_mac_binding *smb =
            shared_mac_binding_lookup(shared_mb_by_scope_ip,
                                      pb->mac_binding_scope,
                                      ds_cstr_ro(ip));
        ds_clear(ip);
        if (smb) {
            eth_addr_from_string(smb->mac, mac);
        }
        return;
    }

    const struct sbrec_mac_binding *smb =
        mac_binding_lookup(sbrec_mb_by_lport_ip, pb->logical_port,
                           ds_cstr_ro(ip));
    ds_clear(ip);

    if (smb) {
        eth_addr_from_string(smb->mac, mac);
    }
}

static const struct sbrec_port_binding *
buffered_packets_get_pb(const struct buffered_packets *bp,
                        struct ovsdb_idl_index *sbrec_pb_by_key,
                        struct ovsdb_idl_index *sbrec_dp_by_key,
                        struct ovsdb_idl_index *sbrec_pb_by_name)
{
    const struct sbrec_port_binding *pb =
            lport_lookup_by_key(sbrec_dp_by_key, sbrec_pb_by_key,
                                bp->mb_data.dp_key, bp->mb_data.port_key);
    if (!pb) {
        return NULL;
    }

    if (!strcmp(pb->type, "chassisredirect")) {
        const char *dgp_name =
                smap_get_def(&pb->options, "distributed-port", "");
        pb = lport_lookup_by_name(sbrec_pb_by_name, dgp_name);
    }
    return pb;
}

void
mac_binding_probe_stats_process_flow_stats(
        struct vector *stats_vec,
        struct ofputil_flow_stats *ofp_stats)
{
    if (!ofp_stats->packet_count) {
        return;
    }

    struct mac_cache_stats stats = (struct mac_cache_stats) {
        .idle_age_ms = ofp_stats->idle_age >= 0
               ? ofp_stats->idle_age * 1000
               : 0,
        .data.mb = (struct mac_binding_data) {
            .cookie = ntohll(ofp_stats->cookie),
            /* The port_key must be zero to match
             * mac_binding_data_from_sbrec. */
            .port_key = 0,
            .dp_key = ntohll(ofp_stats->match.flow.metadata),
            .is_scope = false,
            .mac = ofp_stats->match.flow.dl_src
        },
    };

    if (ofp_stats->match.flow.regs[0]) {
        stats.data.mb.ip =
            in6_addr_mapped_ipv4(htonl(ofp_stats->match.flow.regs[0]));
    } else {
        ovs_be128 ip6 = hton128(flow_get_xxreg(&ofp_stats->match.flow, 1));
        memcpy(&stats.data.mb.ip, &ip6, sizeof stats.data.mb.ip);
    }

    vector_push(stats_vec, &stats);
}

void
shared_mac_binding_probe_stats_process_flow_stats(
        struct vector *stats_vec,
        struct ofputil_flow_stats *ofp_stats)
{
    size_t old_size = vector_len(stats_vec);

    mac_binding_probe_stats_process_flow_stats(stats_vec, ofp_stats);
    if (vector_len(stats_vec) > old_size) {
        struct mac_cache_stats *stats = vector_get_ptr(stats_vec, old_size);
        stats->data.mb.is_scope = true;
    }
}

static bool
mac_binding_probe_get_local_address(const struct sbrec_port_binding *pb,
                                    const struct in6_addr *target,
                                    struct lport_addresses *laddr,
                                    struct in6_addr *local)
{
    if (!pb->datapath || !pb->n_mac ||
        !extract_lsp_addresses(pb->mac[0], laddr)) {
        return false;
    }

    *local = in6addr_any;
    if (IN6_IS_ADDR_V4MAPPED(target)) {
        ovs_be32 ip4 = in6_addr_get_mapped_ipv4(target);
        for (size_t i = 0; i < laddr->n_ipv4_addrs; i++) {
            struct ipv4_netaddr address = laddr->ipv4_addrs[i];
            if (address.network == (ip4 & address.mask)) {
                *local = in6_addr_mapped_ipv4(address.addr);
                break;
            }
        }
    } else {
        for (size_t i = 0; i < laddr->n_ipv6_addrs; i++) {
            struct ipv6_netaddr address = laddr->ipv6_addrs[i];
            struct in6_addr neigh_prefix =
                ipv6_addr_bitand(target, &address.mask);
            if (ipv6_addr_equals(&address.network, &neigh_prefix)) {
                *local = address.addr;
                break;
            }
        }
    }

    if (ipv6_addr_equals(local, &in6addr_any)) {
        destroy_lport_addresses(laddr);
        return false;
    }
    return true;
}

static const struct sbrec_port_binding *
mac_binding_probe_get_port(const struct mac_binding *mb,
                           const struct mac_binding_probe_data *probe_data,
                           struct lport_addresses *laddr,
                           struct in6_addr *local)
{
    if (!mb->data.is_scope) {
        const struct sbrec_port_binding *pb = lport_lookup_by_name(
            probe_data->sbrec_port_binding_by_name,
            mb->sbrec->logical_port);
        if (!pb || !lport_pb_is_local(
                probe_data->sbrec_port_binding_by_name,
                probe_data->chassis, pb)) {
            return NULL;
        }
        return mac_binding_probe_get_local_address(
            pb, &mb->data.ip, laddr, local) ? pb : NULL;
    }

    struct sbrec_port_binding *target = sbrec_port_binding_index_init_row(
        probe_data->sbrec_port_binding_by_mac_binding_scope);
    sbrec_port_binding_index_set_mac_binding_scope(
        target, mb->shared_sbrec->scope);

    const struct sbrec_port_binding *pb;
    const struct sbrec_port_binding *found = NULL;
    SBREC_PORT_BINDING_FOR_EACH_EQUAL (
        pb, target, probe_data->sbrec_port_binding_by_mac_binding_scope) {
        if (strcmp(pb->type, "chassisredirect") &&
            lport_pb_is_local(probe_data->sbrec_port_binding_by_name,
                              probe_data->chassis, pb) &&
            mac_binding_probe_get_local_address(
                pb, &mb->data.ip, laddr, local)) {
            found = pb;
            break;
        }
    }
    sbrec_port_binding_index_destroy_row(target);
    return found;
}

void
mac_binding_probe_stats_run(struct vector *stats_vec, uint64_t *req_delay,
                            void *data, long long timewall_now)
{
    struct mac_binding_probe_data *probe_data = data;
    struct mac_cache_data *cache_data = probe_data->cache_data;

    struct mac_cache_stats *stats;
    VECTOR_FOR_EACH_PTR (stats_vec, stats) {
        struct mac_binding *mb = mac_binding_find(&cache_data->mac_bindings,
                                                  &stats->data.mb);
        if (!mb) {
            mac_binding_update_log("Probe: not found in the cache:",
                                   &stats->data.mb, false, NULL, 0, 0);
            continue;
        }

        struct mac_cache_threshold *threshold = mb->data.is_scope
            ? mac_cache_threshold_find_scope(cache_data, mb->data.dp_key)
            : mac_cache_threshold_find(cache_data, mb->data.dp_key);
        int64_t timestamp = mb->data.is_scope
                            ? mb->shared_sbrec->timestamp
                            : mb->sbrec->timestamp;
        uint64_t since_updated_ms = timewall_now - timestamp;

        if (stats->idle_age_ms > threshold->value) {
            mac_binding_update_log("Not sending ARP/ND request for non-active",
                                   &mb->data, true, threshold,
                                   stats->idle_age_ms, since_updated_ms);
            continue;
        }

        if (since_updated_ms < threshold->cooldown_period) {
            mac_binding_update_log(
                    "Not sending ARP/ND request for recently updated",
                    &mb->data, true, threshold, stats->idle_age_ms,
                    since_updated_ms);
            mb->arp_attempts = 0;
            continue;
        }

        struct lport_addresses laddr;
        struct in6_addr local;
        const struct sbrec_port_binding *pb = mac_binding_probe_get_port(
            mb, probe_data, &laddr, &local);
        if (!pb) {
            mac_binding_update_log("Not sending ARP/ND request for non-local",
                                   &mb->data, true, threshold,
                                   stats->idle_age_ms, since_updated_ms);
            continue;
        }

        struct eth_addr eth_dst =
            mb->arp_attempts < PROBE_MULICAST_THRESHOLD
            ? mb->data.mac
            : eth_addr_zero;

        mac_binding_update_log("Sending ARP/ND request for active",
                               &mb->data, true, threshold,
                               stats->idle_age_ms, since_updated_ms);

        send_self_originated_neigh_packet(probe_data->swconn,
                                          pb->datapath->tunnel_key,
                                          pb->tunnel_key, laddr.ea,
                                          eth_dst, &local,
                                          &mb->data.ip,
                                          OFTABLE_LOCAL_OUTPUT);
        mb->arp_attempts++;

        destroy_lport_addresses(&laddr);
    }

    mac_cache_update_req_delay(&cache_data->thresholds, req_delay);
    if (*req_delay) {
        VLOG_DBG("MAC probe binding statistics delay: %"PRIu64, *req_delay);
    }
}
