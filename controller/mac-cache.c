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

#include "lport.h"
#include "mac-cache.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "ovn/logical-fields.h"
#include "ovn-sb-idl.h"

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
static uint32_t
fdb_data_hash(const struct fdb_data *fdb_data);
static inline bool
fdb_data_equals(const struct fdb_data *a, const struct fdb_data *b);
static struct mac_cache_threshold *
mac_cache_threshold_find(struct hmap *thresholds, const struct uuid *uuid);
static uint64_t
mac_cache_threshold_get_value_ms(const struct sbrec_datapath_binding *dp,
                                 enum mac_cache_type type);
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
bool
mac_cache_threshold_add(struct mac_cache_data *data,
                        const struct sbrec_datapath_binding *dp,
                        enum mac_cache_type type)
{
    struct hmap *thresholds = &data->thresholds[type];
    struct mac_cache_threshold *threshold =
            mac_cache_threshold_find(thresholds, &dp->header_.uuid);
    if (threshold) {
        return true;
    }

    uint64_t value = mac_cache_threshold_get_value_ms(dp, type);
    if (!value) {
        return false;
    }

    threshold = xmalloc(sizeof *threshold);
    threshold->uuid = dp->header_.uuid;
    threshold->value = value;
    threshold->dump_period = (3 * value) / 4;

    hmap_insert(thresholds, &threshold->hmap_node,
                uuid_hash(&dp->header_.uuid));

    return true;
}

bool
mac_cache_threshold_replace(struct mac_cache_data *data,
                            const struct sbrec_datapath_binding *dp,
                            enum mac_cache_type type)
{
    struct hmap *thresholds = &data->thresholds[type];
    struct mac_cache_threshold *threshold =
            mac_cache_threshold_find(thresholds, &dp->header_.uuid);
    if (threshold) {
        mac_cache_threshold_remove(thresholds, threshold);
    }

    return mac_cache_threshold_add(data, dp, type);
}

void
mac_cache_thresholds_clear(struct mac_cache_data *data)
{
    for (size_t i = 0; i < MAC_CACHE_MAX; i++) {
        struct mac_cache_threshold *threshold;
        HMAP_FOR_EACH_POP (threshold, hmap_node, &data->thresholds[i]) {
            free(threshold);
        }
    }
}

/* MAC binding. */
struct mac_binding *
mac_binding_add(struct hmap *map, struct mac_binding_data mb_data,
                long long timestamp) {

    struct mac_binding *mb = mac_binding_find(map, &mb_data);
    if (!mb) {
        mb = xmalloc(sizeof *mb);
        mb->sbrec_mb = NULL;
        hmap_insert(map, &mb->hmap_node, mac_binding_data_hash(&mb_data));
    }

    mb->data = mb_data;
    mb->timestamp = timestamp;

    return mb;
}

void
mac_binding_remove(struct hmap *map, struct mac_binding *mb) {
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
mac_binding_data_from_sbrec(struct mac_binding_data *data,
                            const struct sbrec_mac_binding *mb,
                            struct ovsdb_idl_index *sbrec_pb_by_name)
{
    const struct sbrec_port_binding *pb =
            lport_lookup_by_name(sbrec_pb_by_name, mb->logical_port);

    if (!pb || !pb->datapath || !ip46_parse(mb->ip, &data->ip) ||
        !eth_addr_from_string(mb->mac, &data->mac)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Couldn't parse MAC binding: ip=%s, mac=%s, "
                     "logical_port=%s", mb->ip, mb->mac, mb->logical_port);
        return false;
    }

    data->dp_key = mb->datapath->tunnel_key;
    data->port_key = pb->tunnel_key;

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
        fdb->dp_uuid = UUID_ZERO;
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
        .port_key = ofp_stats->match.flow.regs[MFF_LOG_INPORT - MFF_REG0],
        .dp_key = ntohll(ofp_stats->match.flow.metadata),
        .mac = ofp_stats->match.flow.dl_src
    };

    if (ofp_stats->match.flow.dl_type == htons(ETH_TYPE_IP)) {
        stats->data.mb.ip = in6_addr_mapped_ipv4(ofp_stats->match.flow.nw_src);
    } else {
        stats->data.mb.ip = ofp_stats->match.flow.ipv6_src;
    }

    ovs_list_push_back(stats_list, &stats->list_node);
}

void
mac_binding_stats_run(struct ovs_list *stats_list, uint64_t *req_delay,
                      void *data)
{
    struct mac_cache_data *cache_data = data;
    struct hmap *thresholds = &cache_data->thresholds[MAC_CACHE_MAC_BINDING];
    long long timewall_now = time_wall_msec();

    struct mac_cache_stats *stats;
    LIST_FOR_EACH_POP (stats, list_node, stats_list) {
        struct mac_binding *mb = mac_binding_find(&cache_data->mac_bindings,
                                                  &stats->data.mb);
        if (!mb) {
            free(stats);
            continue;
        }

        struct uuid *dp_uuid = &mb->sbrec_mb->datapath->header_.uuid;
        struct mac_cache_threshold *threshold =
                mac_cache_threshold_find(thresholds, dp_uuid);

        /* If "idle_age" is under threshold it means that the mac binding is
         * used on this chassis. Also make sure that we don't update the
         * timestamp more than once during the dump period. */
        if (stats->idle_age_ms < threshold->value &&
                (timewall_now - mb->sbrec_mb->timestamp) >=
            threshold->dump_period) {
            sbrec_mac_binding_set_timestamp(mb->sbrec_mb, timewall_now);
        }

        free(stats);
    }

    mac_cache_update_req_delay(thresholds, req_delay);
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

void
fdb_stats_run(struct ovs_list *stats_list, uint64_t *req_delay,
              void *data)
{
    struct mac_cache_data *cache_data = data;
    struct hmap *thresholds = &cache_data->thresholds[MAC_CACHE_FDB];
    long long timewall_now = time_wall_msec();

    struct mac_cache_stats *stats;
    LIST_FOR_EACH_POP (stats, list_node, stats_list) {
        struct fdb *fdb = fdb_find(&cache_data->fdbs, &stats->data.fdb);

        if (!fdb) {
            free(stats);
            continue;
        }

        struct mac_cache_threshold *threshold =
                mac_cache_threshold_find(thresholds, &fdb->dp_uuid);
        /* If "idle_age" is under threshold it means that the mac binding is
         * used on this chassis. Also make sure that we don't update the
         * timestamp more than once during the dump period. */
        if (stats->idle_age_ms < threshold->value &&
                (timewall_now - fdb->sbrec_fdb->timestamp) >=
            threshold->dump_period) {
            sbrec_fdb_set_timestamp(fdb->sbrec_fdb, timewall_now);
        }

        free(stats);
    }

    mac_cache_update_req_delay(thresholds, req_delay);
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
    uint32_t hash = 0;

    hash = hash_add(hash, mb_data->port_key);
    hash = hash_add(hash, mb_data->dp_key);
    hash = hash_add_in6_addr(hash, &mb_data->ip);

    return hash_finish(hash, 24);
}

static inline bool
mac_binding_data_equals(const struct mac_binding_data *a,
                        const struct mac_binding_data *b)
{
    return a->port_key == b->port_key &&
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


static struct mac_cache_threshold *
mac_cache_threshold_find(struct hmap *thresholds, const struct uuid *uuid)
{
    uint32_t hash = uuid_hash(uuid);

    struct mac_cache_threshold *threshold;
    HMAP_FOR_EACH_WITH_HASH (threshold, hmap_node, hash, thresholds) {
        if (uuid_equals(&threshold->uuid, uuid)) {
            return threshold;
        }
    }

    return NULL;
}

static uint64_t
mac_cache_threshold_get_value_ms(const struct sbrec_datapath_binding *dp,
                                 enum mac_cache_type type)
{
    uint64_t value = 0;
    switch (type) {
    case MAC_CACHE_MAC_BINDING:
        value = smap_get_uint(&dp->external_ids, "mac_binding_age_threshold",
                              0);
        break;
    case MAC_CACHE_FDB:
        value = smap_get_uint(&dp->external_ids, "fdb_age_threshold", 0);
        break;
    case MAC_CACHE_MAX:
    default:
        break;
    }

    return value * 1000;
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
