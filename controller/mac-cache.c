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

static uint32_t
mac_cache_mb_data_hash(const struct mac_cache_mb_data *mb_data);
static inline bool
mac_cache_mb_data_equals(const struct mac_cache_mb_data *a,
                          const struct mac_cache_mb_data *b);
static struct mac_cache_mac_binding *
mac_cache_mac_binding_find(struct mac_cache_data *data,
                           const struct mac_cache_mb_data *mb_data);
static bool
mac_cache_mb_data_from_sbrec(struct mac_cache_mb_data *data,
                              const struct sbrec_mac_binding *mb);
static void mac_cache_mac_binding_update_log(
    const char *action,
    const struct mac_cache_mb_data *,
    bool print_times,
    const struct mac_cache_threshold *,
    int64_t idle_age_ms,
    uint64_t since_updated_ms);
static uint32_t
mac_cache_fdb_data_hash(const struct mac_cache_fdb_data *fdb_data);
static inline bool
mac_cache_fdb_data_equals(const struct mac_cache_fdb_data *a,
                          const struct mac_cache_fdb_data *b);
static bool
mac_cache_fdb_data_from_sbrec(struct mac_cache_fdb_data *data,
                              const struct sbrec_fdb *fdb);
static struct mac_cache_fdb *
mac_cache_fdb_find(struct mac_cache_data *data,
                   const struct mac_cache_fdb_data *fdb_data);
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
    threshold->dump_period = value / 2;
    threshold->cooldown_period = value / 4;

    /* (cooldown_period + dump_period) is the maximum time the timestamp may
     * be not updated.  So, the sum of those times must be lower than the
     * threshold, otherwise we may fail to update an active MAC binding in
     * time and risk it being removed.  Giving it an extra 1/10 of the time
     * for all the processing that needs to happen. */
    ovs_assert(threshold->cooldown_period + threshold->dump_period
               < (9 * value) / 10);

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

void
mac_cache_mac_binding_add(struct mac_cache_data *data,
                           const struct sbrec_mac_binding *mb)
{
    struct mac_cache_mb_data mb_data;
    if (!mac_cache_mb_data_from_sbrec(&mb_data, mb)) {
        return;
    }

    struct mac_cache_mac_binding *mc_mb = mac_cache_mac_binding_find(data,
                                                                     &mb_data);
    if (!mc_mb) {
        mc_mb = xmalloc(sizeof *mc_mb);
        hmap_insert(&data->mac_bindings, &mc_mb->hmap_node,
                    mac_cache_mb_data_hash(&mb_data));
    }

    mc_mb->data = mb_data;
    mc_mb->sbrec = mb;
    mac_cache_mac_binding_update_log("Added", &mb_data, false, NULL, 0, 0);
}

void
mac_cache_mac_binding_remove(struct mac_cache_data *data,
                             const struct sbrec_mac_binding *mb)
{
    struct mac_cache_mb_data mb_data;
    if (!mac_cache_mb_data_from_sbrec(&mb_data, mb)) {
        return;
    }

    struct mac_cache_mac_binding *mc_mb = mac_cache_mac_binding_find(data,
                                                                     &mb_data);
    if (!mc_mb) {
        return;
    }

    mac_cache_mac_binding_update_log("Removed", &mc_mb->data, false,
                                     NULL, 0, 0);
    hmap_remove(&data->mac_bindings, &mc_mb->hmap_node);
    free(mc_mb);
}

void
mac_cache_mac_bindings_clear(struct mac_cache_data *data)
{
    struct mac_cache_mac_binding *mc_mb;
    HMAP_FOR_EACH_POP (mc_mb, hmap_node, &data->mac_bindings) {
        free(mc_mb);
    }
}


static void
mac_cache_mac_binding_data_to_string(const struct mac_cache_mb_data *data,
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
mac_cache_mac_bindings_to_string(const struct hmap *map, struct ds *out_data)
{
    struct mac_cache_mac_binding *mb;
    HMAP_FOR_EACH (mb, hmap_node, map) {
        mac_cache_mac_binding_data_to_string(&mb->data, out_data);
        ds_put_char(out_data, '\n');
    }
}

void
mac_cache_fdb_add(struct mac_cache_data *data, const struct sbrec_fdb *fdb,
                  struct uuid dp_uuid)
{
    struct mac_cache_fdb_data fdb_data;
    if (!mac_cache_fdb_data_from_sbrec(&fdb_data, fdb)) {
        return;
    }

    struct mac_cache_fdb *mc_fdb = mac_cache_fdb_find(data, &fdb_data);

    if (!mc_fdb) {
        mc_fdb = xmalloc(sizeof *mc_fdb);
        hmap_insert(&data->fdbs, &mc_fdb->hmap_node,
                    mac_cache_fdb_data_hash(&fdb_data));
    }

    mc_fdb->sbrec_fdb = fdb;
    mc_fdb->data = fdb_data;
    mc_fdb->dp_uuid = dp_uuid;
}

void
mac_cache_fdb_remove(struct mac_cache_data *data, const struct sbrec_fdb *fdb)
{
    struct mac_cache_fdb_data fdb_data;
    if (!mac_cache_fdb_data_from_sbrec(&fdb_data, fdb)) {
        return;
    }

    struct mac_cache_fdb *mc_fdb = mac_cache_fdb_find(data, &fdb_data);
    if (!mc_fdb) {
        return;
    }

    hmap_remove(&data->fdbs, &mc_fdb->hmap_node);
    free(mc_fdb);
}

void
mac_cache_fdbs_clear(struct mac_cache_data *data)
{
    struct mac_cache_fdb *mc_fdb;
    HMAP_FOR_EACH_POP (mc_fdb, hmap_node, &data->fdbs) {
        free(mc_fdb);
    }
}

struct mac_cache_stats {
    struct ovs_list list_node;

    int64_t idle_age_ms;

    union {
        /* Common data to identify MAC binding. */
        struct mac_cache_mb_data mb;
        /* Common data to identify FDB. */
        struct mac_cache_fdb_data fdb;
    } data;
};

void
mac_cache_mb_stats_process_flow_stats(struct ovs_list *stats_list,
                                      struct ofputil_flow_stats *ofp_stats)
{
    struct mac_cache_stats *stats = xmalloc(sizeof *stats);

    stats->idle_age_ms = ofp_stats->idle_age * 1000;
    stats->data.mb = (struct mac_cache_mb_data) {
        .cookie = ntohll(ofp_stats->cookie),
        /* The port_key must be zero to match mac_binding_data_from_sbrec. */
        .port_key = 0,
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

static void
mac_cache_mac_binding_update_log(
    const char *action,
    const struct mac_cache_mb_data *data,
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
    mac_cache_mac_binding_data_to_string(data, &s);
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
mac_cache_mb_stats_run(struct ovs_list *stats_list, uint64_t *req_delay,
                       void *data)
{
    struct mac_cache_data *cache_data = data;
    struct hmap *thresholds = &cache_data->thresholds[MAC_CACHE_MAC_BINDING];
    long long timewall_now = time_wall_msec();

    struct mac_cache_stats *stats;
    LIST_FOR_EACH_POP (stats, list_node, stats_list) {
        struct mac_cache_mac_binding *mc_mb =
                mac_cache_mac_binding_find(cache_data, &stats->data.mb);
        if (!mc_mb) {
            mac_cache_mac_binding_update_log("Not found in the cache:",
                                             &stats->data.mb, false,
                                             NULL, 0, 0);
            free(stats);
            continue;
        }

        struct uuid *dp_uuid = &mc_mb->sbrec->datapath->header_.uuid;
        uint64_t since_updated_ms = timewall_now - mc_mb->sbrec->timestamp;
        struct mac_cache_threshold *threshold =
                mac_cache_threshold_find(thresholds, dp_uuid);

        /* If "idle_age" is under threshold it means that the mac binding is
         * used on this chassis. */
        if (stats->idle_age_ms < threshold->value) {
            if (since_updated_ms >= threshold->cooldown_period) {
                mac_cache_mac_binding_update_log("Updating active",
                                                 &mc_mb->data, true, threshold,
                                                 stats->idle_age_ms,
                                                 since_updated_ms);
                sbrec_mac_binding_set_timestamp(mc_mb->sbrec, timewall_now);
            } else {
                /* Postponing the update to avoid sending database transactions
                 * too frequently. */
                mac_cache_mac_binding_update_log("Not updating active",
                                                 &mc_mb->data, true, threshold,
                                                 stats->idle_age_ms,
                                                 since_updated_ms);
            }
        } else {
            mac_cache_mac_binding_update_log("Not updating non-active",
                                             &mc_mb->data, true, threshold,
                                             stats->idle_age_ms,
                                             since_updated_ms);
        }
        free(stats);
    }

    mac_cache_update_req_delay(thresholds, req_delay);
    if (*req_delay) {
        VLOG_DBG("MAC binding statistics dalay: %"PRIu64, *req_delay);
    }
}

void
mac_cache_fdb_stats_process_flow_stats(struct ovs_list *stats_list,
                                       struct ofputil_flow_stats *ofp_stats)
{
    struct mac_cache_stats *stats = xmalloc(sizeof *stats);

    stats->idle_age_ms = ofp_stats->idle_age * 1000;
    stats->data.fdb = (struct mac_cache_fdb_data) {
            .port_key = ofp_stats->match.flow.regs[MFF_LOG_INPORT - MFF_REG0],
            .dp_key = ntohll(ofp_stats->match.flow.metadata),
            .mac = ofp_stats->match.flow.dl_src
    };

    ovs_list_push_back(stats_list, &stats->list_node);
}

static void
mac_cache_fdb_update_log(const char *action,
                         const struct mac_cache_fdb_data *data,
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
mac_cache_fdb_stats_run(struct ovs_list *stats_list, uint64_t *req_delay,
                        void *data)
{
    struct mac_cache_data *cache_data = data;
    struct hmap *thresholds = &cache_data->thresholds[MAC_CACHE_FDB];
    long long timewall_now = time_wall_msec();

    struct mac_cache_stats *stats;
    LIST_FOR_EACH_POP (stats, list_node, stats_list) {
        struct mac_cache_fdb *mc_fdb = mac_cache_fdb_find(cache_data,
                                                          &stats->data.fdb);
        if (!mc_fdb) {
            mac_cache_fdb_update_log("Not found in the cache:",
                                     &stats->data.fdb, false, NULL, 0, 0);
            free(stats);
            continue;
        }

        uint64_t since_updated_ms =
            timewall_now - mc_fdb->sbrec_fdb->timestamp;
        struct mac_cache_threshold *threshold =
                mac_cache_threshold_find(thresholds, &mc_fdb->dp_uuid);
        /* If "idle_age" is under threshold it means that the fdb entry is
         * used on this chassis. */
        if (stats->idle_age_ms < threshold->value) {
            if (since_updated_ms >= threshold->cooldown_period) {
                mac_cache_fdb_update_log("Updating active",
                                         &mc_fdb->data, true, threshold,
                                        stats->idle_age_ms,
                                        since_updated_ms);
                sbrec_fdb_set_timestamp(mc_fdb->sbrec_fdb, timewall_now);
            } else {
                /* Postponing the update to avoid sending database transactions
                 * too frequently. */
                mac_cache_fdb_update_log("Not updating active",
                                         &mc_fdb->data, true, threshold,
                                         stats->idle_age_ms,
                                         since_updated_ms);
            }
        } else {
            mac_cache_fdb_update_log("Not updating non-active",
                                     &mc_fdb->data, true, threshold,
                                     stats->idle_age_ms, since_updated_ms);
        }

        free(stats);
    }

    mac_cache_update_req_delay(thresholds, req_delay);
    if (*req_delay) {
        VLOG_DBG("FDB entry statistics dalay: %"PRIu64, *req_delay);
    }
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
mac_cache_mb_data_hash(const struct mac_cache_mb_data *mb_data)
{
    uint32_t hash = hash_uint64(mb_data->cookie);

    hash = hash_add(hash, mb_data->port_key);
    hash = hash_add(hash, mb_data->dp_key);
    hash = hash_add_in6_addr(hash, &mb_data->ip);
    hash = hash_add64(hash, eth_addr_to_uint64(mb_data->mac));

    return hash_finish(hash, 32);
}

static inline bool
mac_cache_mb_data_equals(const struct mac_cache_mb_data *a,
                          const struct mac_cache_mb_data *b)
{
    return a->cookie == b->cookie &&
           a->port_key == b->port_key &&
           a->dp_key == b->dp_key &&
           ipv6_addr_equals(&a->ip, &b->ip) &&
           eth_addr_equals(a->mac, b->mac);
}

static bool
mac_cache_mb_data_parse(struct mac_cache_mb_data *data,
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

    mac_cache_mac_binding_data_init(data, dp_key, port_key, ip, mac);
    return true;
}

static bool
mac_cache_mb_data_from_sbrec(struct mac_cache_mb_data *data,
                              const struct sbrec_mac_binding *mb)
{
    /* This explicitly sets the port_key to 0 as port_binding tunnel_keys
     * can change.  Instead use add the SB.MAC_Binding UUID as key; this
     * makes the mac_binding_data key unique. */
    if (!mac_cache_mb_data_parse(data, mb->datapath->tunnel_key, 0,
                                 mb->ip, mb->mac)) {
        return false;
    }

    data->cookie = mb->header_.uuid.parts[0];
    return true;
}

static struct mac_cache_mac_binding *
mac_cache_mac_binding_find(struct mac_cache_data *data,
                           const struct mac_cache_mb_data *mb_data)
{
    uint32_t hash = mac_cache_mb_data_hash(mb_data);

    struct mac_cache_mac_binding *mb;
    HMAP_FOR_EACH_WITH_HASH (mb, hmap_node, hash, &data->mac_bindings) {
        if (mac_cache_mb_data_equals(&mb->data, mb_data)) {
            return mb;
        }
    }

    return NULL;
}

static uint32_t
mac_cache_fdb_data_hash(const struct mac_cache_fdb_data *fdb_data)
{
    uint32_t hash = 0;

    hash = hash_add(hash, fdb_data->port_key);
    hash = hash_add(hash, fdb_data->dp_key);
    hash = hash_add64(hash, eth_addr_to_uint64(fdb_data->mac));

    return hash_finish(hash, 16);
}

static inline bool
mac_cache_fdb_data_equals(const struct mac_cache_fdb_data *a,
                          const struct mac_cache_fdb_data *b)
{
    return a->port_key == b->port_key &&
           a->dp_key == b->dp_key &&
           eth_addr_equals(a->mac, b->mac);
}

static bool
mac_cache_fdb_data_from_sbrec(struct mac_cache_fdb_data *data,
                              const struct sbrec_fdb *fdb)
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

static struct mac_cache_fdb *
mac_cache_fdb_find(struct mac_cache_data *data,
                   const struct mac_cache_fdb_data *fdb_data)
{
    uint32_t hash = mac_cache_fdb_data_hash(fdb_data);

    struct mac_cache_fdb *fdb;
    HMAP_FOR_EACH_WITH_HASH (fdb, hmap_node, hash, &data->fdbs) {
        if (mac_cache_fdb_data_equals(&fdb->data, fdb_data)) {
            return fdb;
        }
    }

    return NULL;
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
