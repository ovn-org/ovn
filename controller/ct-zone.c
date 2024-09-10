/* Copyright (c) 2024, Red Hat, Inc.
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
#include <errno.h>

#include "binding.h"
#include "chassis.h"
#include "ct-zone.h"
#include "local_data.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ct_zone);

static void
ct_zone_restore(const struct sbrec_datapath_binding_table *dp_table,
                struct ct_zone_ctx *ctx, const char *name, int zone);
static void ct_zone_add_pending(struct shash *pending_ct_zones,
                                enum ct_zone_pending_state state,
                                struct ct_zone *zone, bool add,
                                const char *name);
static int ct_zone_get_snat(const struct sbrec_datapath_binding *dp);
static bool ct_zone_assign_unused(struct ct_zone_ctx *ctx,
                                  const char *zone_name,
                                  int *scan_start, int scan_stop);
static bool ct_zone_remove(struct ct_zone_ctx *ctx, const char *name);
static void ct_zone_add(struct ct_zone_ctx *ctx, const char *name,
                        uint16_t zone, bool set_pending);
static void
ct_zone_limits_update_per_dp(struct ct_zone_ctx *ctx,
                             const struct local_datapath *local_dp,
                             const struct shash *local_lports,
                             const char *name);
static bool ct_zone_limit_update(struct ct_zone_ctx *ctx, const char *name,
                                 int64_t limit);
static int64_t ct_zone_get_dp_limit(const struct sbrec_datapath_binding *dp);
static int64_t ct_zone_get_pb_limit(const struct sbrec_port_binding *pb);
static int64_t ct_zone_limit_normalize(int64_t limit);

void
ct_zone_ctx_init(struct ct_zone_ctx *ctx)
{
    shash_init(&ctx->pending);
    shash_init(&ctx->current);
}

void
ct_zone_ctx_destroy(struct ct_zone_ctx *ctx)
{
    shash_destroy_free_data(&ctx->current);
    shash_destroy_free_data(&ctx->pending);
}

void
ct_zones_restore(struct ct_zone_ctx *ctx,
                 const struct ovsrec_open_vswitch_table *ovs_table,
                 const struct sbrec_datapath_binding_table *dp_table,
                 const struct ovsrec_bridge *br_int)
{
    memset(ctx->bitmap, 0, sizeof ctx->bitmap);
    bitmap_set1(ctx->bitmap, 0); /* Zone 0 is reserved. */

    struct shash_node *pending_node;
    SHASH_FOR_EACH (pending_node, &ctx->pending) {
        struct ct_zone_pending_entry *ctpe = pending_node->data;

        if (ctpe->add) {
            ct_zone_restore(dp_table, ctx, pending_node->name,
                            ctpe->ct_zone.zone);
        }
    }

    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_table_first(ovs_table);
    if (!cfg) {
        return;
    }

    if (!br_int) {
        /* If the integration bridge hasn't been defined, assume that
         * any existing ct-zone definitions aren't valid. */
        return;
    }

    struct smap_node *node;
    SMAP_FOR_EACH (node, &br_int->external_ids) {
        if (strncmp(node->key, "ct-zone-", 8)) {
            continue;
        }

        const char *user = node->key + 8;
        if (!user[0]) {
            continue;
        }

        if (shash_find(&ctx->pending, user)) {
            continue;
        }

        unsigned int zone;
        if (!str_to_uint(node->value, 10, &zone)) {
            continue;
        }

        ct_zone_restore(dp_table, ctx, user, zone);
    }
}

void
ct_zones_parse_range(const struct ovsrec_open_vswitch_table *ovs_table,
                     int *min_ct_zone, int *max_ct_zone)
{
    /* Set default values. */
    *min_ct_zone = 1;
    *max_ct_zone = MAX_CT_ZONES;

    const struct ovsrec_open_vswitch *cfg =
        ovsrec_open_vswitch_table_first(ovs_table);
    if (!cfg) {
        return;
    }

    const char *chassis_id = get_ovs_chassis_id(ovs_table);
    const char *range = get_chassis_external_id_value(&cfg->external_ids,
                                                      chassis_id,
                                                      "ct-zone-range", NULL);
    if (!range) {
        return;
    }

    char *ptr = NULL, *tokstr = xstrdup(range);
    char *range_min = strtok_r(tokstr, "-", &ptr);
    if (!range_min) {
        goto out;
    }

    int min = strtol(range_min, NULL, 10);
    if (errno == EINVAL || min < 1) {
        goto out;
    }
    *min_ct_zone = min;

    char *range_max = strtok_r(NULL, "-", &ptr);
    if (!range_max) {
        goto out;
    }

    int max = strtol(range_max, NULL, 10);
    if (errno == EINVAL || max > MAX_CT_ZONES) {
        goto out;
    }
    *max_ct_zone = max;
out:
    free(tokstr);
}

void
ct_zones_update(const struct sset *local_lports,
                const struct ovsrec_open_vswitch_table *ovs_table,
                const struct hmap *local_datapaths, struct ct_zone_ctx *ctx)
{
    int min_ct_zone, max_ct_zone;
    const char *user;
    struct sset all_users = SSET_INITIALIZER(&all_users);
    struct simap req_snat_zones = SIMAP_INITIALIZER(&req_snat_zones);
    unsigned long *unreq_snat_zones_map = bitmap_allocate(MAX_CT_ZONES);
    struct simap unreq_snat_zones = SIMAP_INITIALIZER(&unreq_snat_zones);

    const char *local_lport;
    SSET_FOR_EACH (local_lport, local_lports) {
        sset_add(&all_users, local_lport);
    }

    /* Local patched datapath (gateway routers) need zones assigned. */
    const struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
        /* XXX Add method to limit zone assignment to logical router
         * datapaths with NAT */
        const char *name = smap_get(&ld->datapath->external_ids, "name");
        if (!name) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_ERR_RL(&rl, "Missing name for datapath '"UUID_FMT"' "
                        "skipping zone assignment.",
                        UUID_ARGS(&ld->datapath->header_.uuid));
            continue;
        }

        char *dnat = alloc_nat_zone_key(name, "dnat");
        char *snat = alloc_nat_zone_key(name, "snat");
        sset_add(&all_users, dnat);
        sset_add(&all_users, snat);

        int req_snat_zone = ct_zone_get_snat(ld->datapath);
        if (req_snat_zone >= 0) {
            simap_put(&req_snat_zones, snat, req_snat_zone);
        }
        free(dnat);
        free(snat);
    }

    ct_zones_parse_range(ovs_table, &min_ct_zone, &max_ct_zone);

    /* Delete zones that do not exist in above sset. */
    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &ctx->current) {
        struct ct_zone *ct_zone = node->data;
        if (!sset_contains(&all_users, node->name)) {
            ct_zone_remove(ctx, node->name);
        } else if (!simap_find(&req_snat_zones, node->name)) {
            if (ct_zone->zone < min_ct_zone || ct_zone->zone > max_ct_zone) {
                ct_zone_remove(ctx, node->name);
            } else {
                bitmap_set1(unreq_snat_zones_map, ct_zone->zone);
                simap_put(&unreq_snat_zones, node->name, ct_zone->zone);
            }
        }
    }

    /* Prioritize requested CT zones */
    struct simap_node *snat_req_node;
    SIMAP_FOR_EACH (snat_req_node, &req_snat_zones) {
        /* Determine if someone already had this zone auto-assigned.
         * If so, then they need to give up their assignment since
         * that zone is being explicitly requested now.
         */
        if (bitmap_is_set(unreq_snat_zones_map, snat_req_node->data)) {
            struct simap_node *unreq_node;
            SIMAP_FOR_EACH_SAFE (unreq_node, &unreq_snat_zones) {
                if (unreq_node->data == snat_req_node->data) {
                    ct_zone_remove(ctx, unreq_node->name);
                    simap_delete(&unreq_snat_zones, unreq_node);
                }
            }

            /* Set this bit to 0 so that if multiple datapaths have requested
             * this zone, we don't needlessly double-detect this condition.
             */
            bitmap_set0(unreq_snat_zones_map, snat_req_node->data);
        }

        struct ct_zone *ct_zone = shash_find_data(&ctx->current,
                                                  snat_req_node->name);
        bool flush = !(ct_zone && ct_zone->zone == snat_req_node->data);
        if (ct_zone && ct_zone->zone != snat_req_node->data) {
            ct_zone_remove(ctx, snat_req_node->name);
        }
        ct_zone_add(ctx, snat_req_node->name, snat_req_node->data, flush);
    }

    /* xxx This is wasteful to assign a zone to each port--even if no
     * xxx security policy is applied. */

    /* Assign a unique zone id for each logical port and two zones
     * to a gateway router. */
    SSET_FOR_EACH (user, &all_users) {
        if (shash_find(&ctx->current, user)) {
            continue;
        }

        ct_zone_assign_unused(ctx, user, &min_ct_zone, max_ct_zone);
    }

    simap_destroy(&req_snat_zones);
    simap_destroy(&unreq_snat_zones);
    sset_destroy(&all_users);
    bitmap_free(unreq_snat_zones_map);
}

void
ct_zones_commit(const struct ovsrec_bridge *br_int,
                const struct ovsrec_datapath *ovs_dp,
                struct ovsdb_idl_txn *ovs_idl_txn,
                struct ct_zone_ctx *ctx)
{
    if (shash_is_empty(&ctx->pending)) {
        return;
    }

    struct ovsrec_ct_zone **all_zones =
            xzalloc(sizeof *all_zones * (MAX_CT_ZONES + 1));
    for (size_t i = 0; i < ovs_dp->n_ct_zones; i++) {
        all_zones[ovs_dp->key_ct_zones[i]] = ovs_dp->value_ct_zones[i];
    }

    struct shash_node *iter;
    SHASH_FOR_EACH (iter, &ctx->pending) {
        struct ct_zone_pending_entry *ctzpe = iter->data;
        struct ct_zone *ct_zone = &ctzpe->ct_zone;

        /* The transaction is open, so any pending entries in the
         * CT_ZONE_DB_QUEUED must be sent and any in CT_ZONE_DB_QUEUED
         * need to be retried. */
        if (ctzpe->state != CT_ZONE_DB_QUEUED
            && ctzpe->state != CT_ZONE_DB_SENT) {
            continue;
        }

        char *user_str = xasprintf("ct-zone-%s", iter->name);
        if (ctzpe->add) {
            char *zone_str = xasprintf("%"PRIu16, ct_zone->zone);
            struct smap_node *node =
                    smap_get_node(&br_int->external_ids, user_str);
            if (!node || strcmp(node->value, zone_str)) {
                ovsrec_bridge_update_external_ids_setkey(br_int,
                                                         user_str, zone_str);
            }
            free(zone_str);
        } else {
            if (smap_get(&br_int->external_ids, user_str)) {
                ovsrec_bridge_update_external_ids_delkey(br_int, user_str);
            }
        }
        free(user_str);

        struct ovsrec_ct_zone *ovs_zone = all_zones[ct_zone->zone];
        if ((!ctzpe->add || ct_zone->limit < 0) && ovs_zone) {
            ovsrec_datapath_update_ct_zones_delkey(ovs_dp, ct_zone->zone);
        } else if (ctzpe->add && ct_zone->limit >= 0) {
            if (!ovs_zone) {
                ovs_zone = ovsrec_ct_zone_insert(ovs_idl_txn);
                ovsrec_datapath_update_ct_zones_setkey(ovs_dp, ct_zone->zone,
                                                       ovs_zone);
            }
            ovsrec_ct_zone_set_limit(ovs_zone, &ct_zone->limit, 1);
        }

        ctzpe->state = CT_ZONE_DB_SENT;
    }

    free(all_zones);
}

void
ct_zones_pending_clear_commited(struct shash *pending)
{
    struct shash_node *iter;
    SHASH_FOR_EACH_SAFE (iter, pending) {
        struct ct_zone_pending_entry *ctzpe = iter->data;
        if (ctzpe->state == CT_ZONE_DB_SENT) {
            shash_delete(pending, iter);
            free(ctzpe);
        }
    }
}

/* Returns "true" when there is no need for full recompute. */
bool
ct_zone_handle_dp_update(struct ct_zone_ctx *ctx,
                         const struct local_datapath *local_dp,
                         const struct shash *local_lports)
{
    const char *name = smap_get(&local_dp->datapath->external_ids, "name");
    if (!name) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_ERR_RL(&rl, "Missing name for datapath '"UUID_FMT"' skipping"
                    "zone check.",
                    UUID_ARGS(&local_dp->datapath->header_.uuid));
        return true;
    }

    ct_zone_limits_update_per_dp(ctx, local_dp, local_lports, name);

    int req_snat_zone = ct_zone_get_snat(local_dp->datapath);
    if (req_snat_zone == -1) {
        /* datapath snat ct zone is not set.  This condition will also hit
         * when CMS clears the snat-ct-zone for the logical router.
         * In this case there is no harm in using the previosly specified
         * snat ct zone for this datapath.  Also it is hard to know
         * if this option was cleared or if this option is never set. */
        return true;
    }

    /* Check if the requested snat zone has changed for the datapath
     * or not.  If so, then fall back to full recompute of
     * ct_zone engine. */
    char *snat_dp_zone_key = alloc_nat_zone_key(name, "snat");
    struct ct_zone *ct_zone = shash_find_data(&ctx->current, snat_dp_zone_key);
    free(snat_dp_zone_key);
    if (!ct_zone || ct_zone->zone != req_snat_zone) {
        return false;
    }

    return true;
}

/* Returns "true" if there was an update to the context. */
bool
ct_zone_handle_port_update(struct ct_zone_ctx *ctx,
                           const struct sbrec_port_binding *pb,
                           bool updated, int *scan_start,
                           int min_ct_zone, int max_ct_zone)
{
    struct shash_node *node = shash_find(&ctx->current, pb->logical_port);

    if (node) {
        struct ct_zone *ct_zone = node->data;
        if (ct_zone->zone < min_ct_zone || ct_zone->zone > max_ct_zone) {
            ct_zone_remove(ctx, node->name);
            node = NULL;
        }
    }

    if (updated) {
        if (!node) {
            ct_zone_assign_unused(ctx, pb->logical_port,
                                  scan_start, max_ct_zone);
        }
        ct_zone_limit_update(ctx, pb->logical_port, ct_zone_get_pb_limit(pb));
        return true;
    } else if (node && ct_zone_remove(ctx, node->name)) {
        return true;
    }

    return false;
}

uint16_t
ct_zone_find_zone(const struct shash *ct_zones, const char *name)
{
    struct ct_zone *ct_zone = shash_find_data(ct_zones, name);
    return ct_zone ? ct_zone->zone : 0;
}

void
ct_zones_limits_sync(struct ct_zone_ctx *ctx,
                     const struct hmap *local_datapaths,
                     const struct shash *local_lports)
{
    const struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
        const char *name = smap_get(&ld->datapath->external_ids, "name");
        if (!name) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_ERR_RL(&rl, "Missing name for datapath '"UUID_FMT"' "
                        "skipping zone assignment.",
                        UUID_ARGS(&ld->datapath->header_.uuid));
            continue;
        }

        ct_zone_limits_update_per_dp(ctx, ld, local_lports, name);
    }
}

static bool
ct_zone_assign_unused(struct ct_zone_ctx *ctx, const char *zone_name,
                      int *scan_start, int scan_stop)
{
    /* We assume that there are 64K zones and that we own them all. */
    int zone = bitmap_scan(ctx->bitmap, 0, *scan_start, scan_stop + 1);
    if (zone == scan_stop + 1) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "exhausted all ct zones");
        return false;
    }

    *scan_start = zone + 1;
    ct_zone_add(ctx, zone_name, zone, true);

    return true;
}

static bool
ct_zone_remove(struct ct_zone_ctx *ctx, const char *name)
{
    struct shash_node *node = shash_find(&ctx->current, name);
    if (!node) {
        return false;
    }

    struct ct_zone *ct_zone = node->data;

    VLOG_DBG("removing ct zone %"PRIu16" for '%s'", ct_zone->zone, name);

    ct_zone_add_pending(&ctx->pending, CT_ZONE_OF_QUEUED,
                        ct_zone, false, name);
    bitmap_set0(ctx->bitmap, ct_zone->zone);
    shash_delete(&ctx->current, node);
    free(ct_zone);

    return true;
}

static void
ct_zone_add(struct ct_zone_ctx *ctx, const char *name, uint16_t zone,
            bool set_pending)
{
    VLOG_DBG("assigning ct zone %"PRIu16" for '%s'", zone, name);

    struct ct_zone *ct_zone = shash_find_data(&ctx->current, name);
    if (!ct_zone) {
        ct_zone = xmalloc(sizeof *ct_zone);
        shash_add(&ctx->current, name, ct_zone);
    }

    *ct_zone = (struct ct_zone) {
        .zone = zone,
        .limit = -1,
    };

    if (set_pending) {
        ct_zone_add_pending(&ctx->pending, CT_ZONE_OF_QUEUED,
                            ct_zone, true, name);
    }
    bitmap_set1(ctx->bitmap, zone);
}

static int
ct_zone_get_snat(const struct sbrec_datapath_binding *dp)
{
    return smap_get_int(&dp->external_ids, "snat-ct-zone", -1);
}

static void
ct_zone_add_pending(struct shash *pending_ct_zones,
                    enum ct_zone_pending_state state,
                    struct ct_zone *zone, bool add, const char *name)
{
    /* Its important that we add only one entry for the key 'name'.
     * Replace 'pending' with 'existing' and free up 'existing'.
     * Otherwise, we may end up in a continuous loop of adding
     * and deleting the zone entry in the 'external_ids' of
     * integration bridge.
     */
    struct ct_zone_pending_entry *entry =
            shash_find_data(pending_ct_zones, name);

    if (!entry) {
        entry = xmalloc(sizeof *entry);
        entry->state = state;

        shash_add(pending_ct_zones, name, entry);
    }

    *entry = (struct ct_zone_pending_entry) {
        .ct_zone = *zone,
        .state = MIN(entry->state, state),
        .add = add,
    };
}

/* Replaces a UUID prefix from 'uuid_zone' (if any) with the
 * corresponding Datapath_Binding.external_ids.name.  Returns it
 * as a new string that will be owned by the caller. */
static char *
ct_zone_name_from_uuid(const struct sbrec_datapath_binding_table *dp_table,
                       const char *uuid_zone)
{
    struct uuid uuid;
    if (!uuid_from_string_prefix(&uuid, uuid_zone)) {
        return NULL;
    }

    const struct sbrec_datapath_binding *dp =
            sbrec_datapath_binding_table_get_for_uuid(dp_table, &uuid);
    if (!dp) {
        return NULL;
    }

    const char *entity_name = smap_get(&dp->external_ids, "name");
    if (!entity_name) {
        return NULL;
    }

    return xasprintf("%s%s", entity_name, uuid_zone + UUID_LEN);
}

static void
ct_zone_restore(const struct sbrec_datapath_binding_table *dp_table,
                struct ct_zone_ctx *ctx, const char *name, int zone)
{
    VLOG_DBG("restoring ct zone %"PRId32" for '%s'", zone, name);

    char *new_name = ct_zone_name_from_uuid(dp_table, name);
    const char *current_name = name;
    if (new_name) {
        VLOG_DBG("ct zone %"PRId32" replace uuid name '%s' with '%s'",
                 zone, name, new_name);

        struct ct_zone ct_zone = {
            .zone = zone,
            .limit = -1,
        };
        /* Make sure we remove the uuid one in the next OvS DB commit without
         * flush. */
        ct_zone_add_pending(&ctx->pending, CT_ZONE_DB_QUEUED,
                            &ct_zone, false, name);
        /* Store the zone in OvS DB with name instead of uuid without flush.
         * */
        ct_zone_add_pending(&ctx->pending, CT_ZONE_DB_QUEUED,
                            &ct_zone, true, new_name);
        current_name = new_name;
    }

    ct_zone_add(ctx, current_name, zone, false);
    free(new_name);
}

static void
ct_zone_limits_update_per_dp(struct ct_zone_ctx *ctx,
                             const struct local_datapath *local_dp,
                             const struct shash *local_lports,
                             const char *name)
{

    int64_t dp_limit = ct_zone_get_dp_limit(local_dp->datapath);
    char *dnat = alloc_nat_zone_key(name, "dnat");
    char *snat = alloc_nat_zone_key(name, "snat");

    bool zone_updated = ct_zone_limit_update(ctx, dnat, dp_limit);
    zone_updated |= ct_zone_limit_update(ctx, snat, dp_limit);

    if (local_dp->is_switch && zone_updated) {
        const struct shash_node *node;
        SHASH_FOR_EACH (node, local_lports) {
            const struct binding_lport *lport = node->data;

            if (lport->pb->datapath != local_dp->datapath) {
                continue;
            }

            ct_zone_limit_update(ctx, lport->name,
                                 ct_zone_get_pb_limit(lport->pb));
        }
    }

    free(dnat);
    free(snat);
}

static bool
ct_zone_limit_update(struct ct_zone_ctx *ctx, const char *name, int64_t limit)
{
    struct ct_zone *ct_zone = shash_find_data(&ctx->current, name);

    if (!ct_zone || ct_zone->limit == limit) {
        return false;
    }

    ct_zone->limit = limit;
    /* Add pending entry only for DB store to avoid flushing the zone. */
    ct_zone_add_pending(&ctx->pending, CT_ZONE_DB_QUEUED, ct_zone, true, name);
    VLOG_DBG("setting ct zone %"PRIu16" limit to %"PRId64,
             ct_zone->zone, ct_zone->limit);

    return true;
}

static int64_t
ct_zone_get_dp_limit(const struct sbrec_datapath_binding *dp)
{
    int64_t limit = ovn_smap_get_llong(&dp->external_ids, "ct-zone-limit", -1);
    return ct_zone_limit_normalize(limit);
}

static int64_t
ct_zone_get_pb_limit(const struct sbrec_port_binding *pb)
{
    int64_t dp_limit = ovn_smap_get_llong(&pb->datapath->external_ids,
                                          "ct-zone-limit", -1);
    int64_t limit = ovn_smap_get_llong(&pb->options,
                                       "ct-zone-limit", dp_limit);
    return ct_zone_limit_normalize(limit);
}

static int64_t
ct_zone_limit_normalize(int64_t limit)
{
    return limit >= 0 && limit <= UINT32_MAX ? limit : -1;
}
