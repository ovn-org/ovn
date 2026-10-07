/*
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

#include "en-az.h"
#include "en-service-monitor.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "openvswitch/vlog.h"
#include "ovn-ic.h"
#include "ovsdb-idl.h"

VLOG_DEFINE_THIS_MODULE(en_ic_service_monitor);

struct service_monitor_info {
    struct hmap_node hmap_node;
    union {
        const struct sbrec_service_monitor *sb_rec;
        const struct icsbrec_service_monitor *ic_rec;
    } db_rec;
    /* Destination availability zone name. */
    char *dst_az_name;
    /* Source availability zone name. */
    char *src_az_name;
    /* Chassis name associated with monitor logical port. */
    char *chassis_name;
};

struct sync_service_monitor_data {
    /* Map of service monitors to be pushed to other AZs. */
    struct hmap pushed_svcs_map;
    /* Map of service monitors synced from other AZs to our. */
    struct hmap synced_svcs_map;
    /* Map of local service monitors in the ICSBDB. */
    struct hmap local_ic_svcs_map;
    /* Map of local service monitors in SBDB. */
    struct hmap local_sb_svcs_map;
    /* MAC address used for service monitor.  */
    char *prpg_svc_monitor_mac;
};

static void
create_service_monitor_info(struct hmap *svc_map,
                            const void *db_rec,
                            const struct uuid *uuid,
                            const char *src_az_name,
                            const char *target_az_name,
                            const char *chassis_name,
                            bool ic_rec)
{
    struct service_monitor_info *svc_mon = xzalloc(sizeof(*svc_mon));
    size_t hash = uuid_hash(uuid);

    if (ic_rec) {
        svc_mon->db_rec.ic_rec =
            (const struct icsbrec_service_monitor *) db_rec;
    } else {
        svc_mon->db_rec.sb_rec =
            (const struct sbrec_service_monitor *) db_rec;
    }

    svc_mon->dst_az_name = target_az_name ? xstrdup(target_az_name) : NULL;
    svc_mon->chassis_name = chassis_name ? xstrdup(chassis_name) : NULL;
    svc_mon->src_az_name = xstrdup(src_az_name);

    hmap_insert(svc_map, &svc_mon->hmap_node, hash);
}

static void
destroy_service_monitor_info(struct service_monitor_info *svc_mon)
{
    free(svc_mon->src_az_name);
    free(svc_mon->dst_az_name);
    free(svc_mon->chassis_name);
    free(svc_mon);
}

static void
refresh_sb_record_cache(struct hmap *svc_mon_map,
                        const struct sbrec_service_monitor *lookup_rec)
{
    size_t hash = uuid_hash(&lookup_rec->header_.uuid);
    struct service_monitor_info *svc_mon;

    HMAP_FOR_EACH_WITH_HASH (svc_mon, hmap_node, hash, svc_mon_map) {
        ovs_assert(svc_mon->db_rec.sb_rec);
        if (svc_mon->db_rec.sb_rec == lookup_rec) {
            hmap_remove(svc_mon_map, &svc_mon->hmap_node);
            destroy_service_monitor_info(svc_mon);
            return;
        }
    }
}

static void
refresh_ic_record_cache(struct hmap *svc_mon_map,
                        const struct icsbrec_service_monitor *lookup_rec)
{
    size_t hash = uuid_hash(&lookup_rec->header_.uuid);
    struct service_monitor_info *svc_mon;

    HMAP_FOR_EACH_WITH_HASH (svc_mon, hmap_node, hash, svc_mon_map) {
        ovs_assert(svc_mon->db_rec.ic_rec);
        if (svc_mon->db_rec.ic_rec == lookup_rec) {
            hmap_remove(svc_mon_map, &svc_mon->hmap_node);
            destroy_service_monitor_info(svc_mon);
            return;
        }
    }
}

static void
remove_unused_ic_records(struct hmap *local_ic_svcs_map)
{
    struct service_monitor_info *svc_mon;
    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, local_ic_svcs_map) {
        icsbrec_service_monitor_delete(svc_mon->db_rec.ic_rec);
        destroy_service_monitor_info(svc_mon);
    }

    hmap_destroy(local_ic_svcs_map);
}

static void
remove_unused_sb_records(struct hmap *local_sb_svcs_map)
{
    struct service_monitor_info *svc_mon;
    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, local_sb_svcs_map) {
        sbrec_service_monitor_delete(svc_mon->db_rec.sb_rec);
        destroy_service_monitor_info(svc_mon);
    }

    hmap_destroy(local_sb_svcs_map);
}

static void
create_pushed_svcs_mon(struct ic_context *ctx,
                       const struct icsbrec_availability_zone *runned_az,
                       struct hmap *pushed_svcs_map)
{
    struct sbrec_service_monitor *key =
        sbrec_service_monitor_index_init_row(
            ctx->sbrec_service_monitor_by_remote_type);

    sbrec_service_monitor_index_set_remote(key, true);

    const struct sbrec_service_monitor *sb_rec;
    SBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (sb_rec, key,
        ctx->sbrec_service_monitor_by_remote_type) {
        const char *target_az_name = smap_get(&sb_rec->options,
                                              "az-name");
        if (!target_az_name) {
            continue;
        }
        create_service_monitor_info(pushed_svcs_map, sb_rec,
                                    &sb_rec->header_.uuid,
                                    runned_az->name, target_az_name,
                                    NULL, false);
    }

    sbrec_service_monitor_index_destroy_row(key);
}

static void
create_synced_svcs_mon(struct ic_context *ctx,
                       const struct icsbrec_availability_zone *runned_az,
                       struct hmap *synced_svcs_map)
{
    struct icsbrec_service_monitor *key =
        icsbrec_service_monitor_index_init_row(
          ctx->icsbrec_service_monitor_by_target_az);

    icsbrec_service_monitor_index_set_target_availability_zone(
        key, runned_az->name);

    const struct icsbrec_service_monitor *ic_rec;
    ICSBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (ic_rec, key,
        ctx->icsbrec_service_monitor_by_target_az) {

        const struct sbrec_port_binding *pb =
            find_sb_pb_by_name(ctx->sbrec_port_binding_by_name,
                               ic_rec->logical_port);

        if (!pb || !pb->up) {
            continue;
        }

        const char *chassis_name = pb->chassis ? pb->chassis->name : NULL;
        create_service_monitor_info(synced_svcs_map, ic_rec,
                                    &ic_rec->header_.uuid,
                                    runned_az->name,
                                    NULL, chassis_name, true);
    }

    icsbrec_service_monitor_index_destroy_row(key);
}

static void
create_local_ic_svcs_map(struct ic_context *ctx,
                         const struct icsbrec_availability_zone *runned_az,
                         struct hmap *owned_svc_map)
{
    struct icsbrec_service_monitor *key =
        icsbrec_service_monitor_index_init_row(
          ctx->icsbrec_service_monitor_by_source_az);

    icsbrec_service_monitor_index_set_source_availability_zone(
        key, runned_az->name);

    const struct icsbrec_service_monitor *ic_rec;
    ICSBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (ic_rec, key,
        ctx->icsbrec_service_monitor_by_source_az) {
        create_service_monitor_info(owned_svc_map, ic_rec,
                                    &ic_rec->header_.uuid,
                                    runned_az->name, NULL,
                                    NULL, true);
    }

    icsbrec_service_monitor_index_destroy_row(key);
}

static void
create_local_sb_svcs_map(struct ic_context *ctx,
                         const struct icsbrec_availability_zone *runned_az,
                         struct hmap *owned_svc_map)
{
    struct sbrec_service_monitor *key =
        sbrec_service_monitor_index_init_row(
          ctx->sbrec_service_monitor_by_ic_learned);

    sbrec_service_monitor_index_set_ic_learned(
        key, true);

    const struct sbrec_service_monitor *sb_rec;
    SBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (sb_rec, key,
        ctx->sbrec_service_monitor_by_ic_learned) {
        create_service_monitor_info(owned_svc_map, sb_rec,
                                    &sb_rec->header_.uuid,
                                    runned_az->name, NULL,
                                    NULL, false);
    }

    sbrec_service_monitor_index_destroy_row(key);
}

static const struct sbrec_service_monitor *
lookup_sb_svc_rec(struct ic_context *ctx,
                  const struct service_monitor_info *svc_mon)
{
    const struct icsbrec_service_monitor *db_rec =
        svc_mon->db_rec.ic_rec;
    struct sbrec_service_monitor *key =
        sbrec_service_monitor_index_init_row(
            ctx->sbrec_service_monitor_by_remote_type_logical_port);

    sbrec_service_monitor_index_set_remote(key, false);
    sbrec_service_monitor_index_set_logical_port(key, db_rec->logical_port);

    const struct sbrec_service_monitor *sb_rec;
    SBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (sb_rec, key,
        ctx->sbrec_service_monitor_by_remote_type_logical_port) {
        if (db_rec->port == sb_rec->port &&
            ((db_rec->type && sb_rec->type &&
              !strcmp(db_rec->type, sb_rec->type)) ||
             (!db_rec->type && !sb_rec->type)) &&
            !strcmp(db_rec->ip, sb_rec->ip) &&
            !strcmp(db_rec->src_ip, sb_rec->src_ip) &&
            !strcmp(db_rec->protocol, sb_rec->protocol)) {
            sbrec_service_monitor_index_destroy_row(key);
            return sb_rec;
        }
    }

    sbrec_service_monitor_index_destroy_row(key);

    return NULL;
}

static const struct icsbrec_service_monitor *
lookup_icsb_svc_rec(struct ic_context *ctx,
                    const struct service_monitor_info *svc_mon)
{
    const struct sbrec_service_monitor *db_rec =
       svc_mon->db_rec.sb_rec;
    struct icsbrec_service_monitor *key =
        icsbrec_service_monitor_index_init_row(
        ctx->icsbrec_service_monitor_by_target_az_logical_port);

    ovs_assert(svc_mon->dst_az_name);
    icsbrec_service_monitor_index_set_target_availability_zone(
        key, svc_mon->dst_az_name);

    icsbrec_service_monitor_index_set_logical_port(
        key, db_rec->logical_port);

    const struct icsbrec_service_monitor *ic_rec;
    ICSBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (ic_rec, key,
        ctx->icsbrec_service_monitor_by_target_az_logical_port) {
        if (db_rec->port == ic_rec->port &&
            ((db_rec->type && ic_rec->type &&
              !strcmp(db_rec->type, ic_rec->type)) ||
             (!db_rec->type && !ic_rec->type)) &&
            !strcmp(db_rec->ip, ic_rec->ip) &&
            !strcmp(db_rec->src_ip, ic_rec->src_ip) &&
            !strcmp(db_rec->protocol, ic_rec->protocol) &&
            !strcmp(db_rec->logical_port, ic_rec->logical_port)) {
            icsbrec_service_monitor_index_destroy_row(key);
            return ic_rec;
        }
    }

    icsbrec_service_monitor_index_destroy_row(key);

    return NULL;
}

static void
create_service_monitor_data(struct ic_context *ctx,
                            const struct icsbrec_availability_zone *runned_az,
                            struct sync_service_monitor_data *sync_data)
{
    const struct sbrec_sb_global *ic_sb = sbrec_sb_global_first(
                                                ctx->ovnsb_idl);
    const char *svc_monitor_mac = smap_get(&ic_sb->options,
                                           "svc_monitor_mac");

    if (!svc_monitor_mac) {
        return;
    }

    sync_data->prpg_svc_monitor_mac = xstrdup(svc_monitor_mac);
    create_pushed_svcs_mon(ctx, runned_az, &sync_data->pushed_svcs_map);
    create_synced_svcs_mon(ctx, runned_az, &sync_data->synced_svcs_map);
    create_local_ic_svcs_map(ctx, runned_az, &sync_data->local_ic_svcs_map);
    create_local_sb_svcs_map(ctx, runned_az, &sync_data->local_sb_svcs_map);
}

static void
destroy_service_monitor_data(struct sync_service_monitor_data *sync_data)
{
    struct service_monitor_info *svc_mon;
    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &sync_data->pushed_svcs_map) {
        destroy_service_monitor_info(svc_mon);
    }

    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &sync_data->synced_svcs_map) {
        destroy_service_monitor_info(svc_mon);
    }

    hmap_destroy(&sync_data->pushed_svcs_map);
    hmap_destroy(&sync_data->synced_svcs_map);
    free(sync_data->prpg_svc_monitor_mac);
}

static void
sync_service_monitor(struct ic_context *ctx,
                     const struct icsbrec_availability_zone *runned_az)
{
    if (!ctx->ovnisb_unlocked_txn || !ctx->ovnsb_txn) {
        return;
    }

    struct sync_service_monitor_data sync_data;
    memset(&sync_data, 0, sizeof(sync_data));
    hmap_init(&sync_data.pushed_svcs_map);
    hmap_init(&sync_data.synced_svcs_map);
    hmap_init(&sync_data.local_ic_svcs_map);
    hmap_init(&sync_data.local_sb_svcs_map);

    create_service_monitor_data(ctx, runned_az, &sync_data);

    struct service_monitor_info *svc_mon;
    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &sync_data.pushed_svcs_map) {
        const struct sbrec_service_monitor *db_rec = svc_mon->db_rec.sb_rec;
        const struct icsbrec_service_monitor *ic_rec =
            lookup_icsb_svc_rec(ctx, svc_mon);

        if (ic_rec) {
            sbrec_service_monitor_set_status(db_rec, ic_rec->status);
        } else {
            ic_rec = icsbrec_service_monitor_insert(ctx->ovnisb_unlocked_txn);
            icsbrec_service_monitor_set_type(ic_rec, db_rec->type);
            icsbrec_service_monitor_set_ip(ic_rec, db_rec->ip);
            icsbrec_service_monitor_set_port(ic_rec, db_rec->port);
            icsbrec_service_monitor_set_src_ip(ic_rec, db_rec->src_ip);
            icsbrec_service_monitor_set_src_mac(ic_rec,
                sync_data.prpg_svc_monitor_mac);
            icsbrec_service_monitor_set_protocol(ic_rec, db_rec->protocol);
            icsbrec_service_monitor_set_logical_port(ic_rec,
                db_rec->logical_port);
            icsbrec_service_monitor_set_target_availability_zone(ic_rec,
                svc_mon->dst_az_name);
            icsbrec_service_monitor_set_source_availability_zone(ic_rec,
                svc_mon->src_az_name);
        }

        /* Always update options because they change from NB. */
        icsbrec_service_monitor_set_options(ic_rec, &db_rec->options);
        refresh_ic_record_cache(&sync_data.local_ic_svcs_map, ic_rec);
    }

    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &sync_data.synced_svcs_map) {
        const struct icsbrec_service_monitor *db_rec =
            svc_mon->db_rec.ic_rec;
        const struct sbrec_service_monitor *sb_rec =
            lookup_sb_svc_rec(ctx, svc_mon);

        if (sb_rec) {
            icsbrec_service_monitor_set_status(svc_mon->db_rec.ic_rec,
                                               sb_rec->status);
        } else {
            sb_rec = sbrec_service_monitor_insert(ctx->ovnsb_txn);
            sbrec_service_monitor_set_type(sb_rec, db_rec->type);
            sbrec_service_monitor_set_ip(sb_rec, db_rec->ip);
            sbrec_service_monitor_set_port(sb_rec, db_rec->port);
            sbrec_service_monitor_set_src_ip(sb_rec, db_rec->src_ip);
            /* Set svc_monitor_mac from local SBDB. */
            sbrec_service_monitor_set_src_mac(sb_rec,
                sync_data.prpg_svc_monitor_mac);
            sbrec_service_monitor_set_protocol(sb_rec,
                db_rec->protocol);
            sbrec_service_monitor_set_logical_port(sb_rec,
                db_rec->logical_port);
            sbrec_service_monitor_set_remote(sb_rec, false);
            sbrec_service_monitor_set_ic_learned(sb_rec, true);
        }

        /* Only update if ic owns it */
        if (sb_rec->ic_learned) {
            /* Always update options since they may change via
             * NB configuration. Also update chassis_name if
             * the port has been reassigned to a different chassis.
             */
            if (svc_mon->chassis_name) {
                sbrec_service_monitor_set_chassis_name(sb_rec,
                    svc_mon->chassis_name);
            }
            sbrec_service_monitor_set_options(sb_rec, &db_rec->options);
            refresh_sb_record_cache(&sync_data.local_sb_svcs_map, sb_rec);
        }
    }

    /* Delete local created records that are no longer used. */
    remove_unused_ic_records(&sync_data.local_ic_svcs_map);
    remove_unused_sb_records(&sync_data.local_sb_svcs_map);

    destroy_service_monitor_data(&sync_data);
}

enum engine_node_state
en_service_monitor_run(struct engine_node *node,
                       void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    const struct ed_type_az *az = engine_get_input_data("az", node);

    /* runned_az is resolved by the upstream en_az node.  Without an AZ there
     * is nothing to sync (mirrors the previous main-loop gating). */
    if (!az->runned_az) {
        return EN_UNCHANGED;
    }

    sync_service_monitor(ctx, az->runned_az);

    return EN_UPDATED;
}

/* True if 'logical_port' backs a service monitor targeting this AZ - i.e. a
 * port whose 'up'/'chassis' state create_synced_svcs_mon() reads. */
static bool
svc_monitor_target_lport(struct ic_context *ctx,
                         const struct icsbrec_availability_zone *runned_az,
                         const char *logical_port)
{
    struct icsbrec_service_monitor *key =
        icsbrec_service_monitor_index_init_row(
            ctx->icsbrec_service_monitor_by_target_az_logical_port);
    icsbrec_service_monitor_index_set_target_availability_zone(
        key, runned_az->name);
    icsbrec_service_monitor_index_set_logical_port(key, logical_port);
    const struct icsbrec_service_monitor *ic_rec =
        icsbrec_service_monitor_index_find(
            ctx->icsbrec_service_monitor_by_target_az_logical_port, key);
    icsbrec_service_monitor_index_destroy_row(key);
    return ic_rec != NULL;
}

/* SB Port_Binding: sync_service_monitor() reads a port binding only through
 * create_synced_svcs_mon(), which - for each IC-SB service monitor targeting
 * this AZ - looks up the backing SB port binding by logical_port and reads its
 * 'up' and 'chassis'.  So a port-binding change matters only when it is
 * new/deleted or its 'up'/'chassis' changed AND the port backs such a service
 * monitor.  Every other SB port-binding change (other columns, or ports that
 * are not service-monitor backends - the vast majority of SB churn) is a
 * no-op, instead of forcing a full recompute of this node. */
enum engine_input_handler_result
en_service_monitor_sb_port_binding_handler(struct engine_node *node,
                                           void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    const struct ed_type_az *az = engine_get_input_data("az", node);

    if (!az->runned_az) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct sbrec_port_binding_table *tbl =
        EN_OVSDB_GET(engine_get_input("SB_port_binding", node));
    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (pb, tbl) {
        if (!sbrec_port_binding_is_new(pb) &&
            !sbrec_port_binding_is_deleted(pb) &&
            !ovsdb_idl_track_is_updated(&pb->header_,
                                        &sbrec_port_binding_col_up) &&
            !ovsdb_idl_track_is_updated(&pb->header_,
                                        &sbrec_port_binding_col_chassis)) {
            continue;
        }
        if (svc_monitor_target_lport(ctx, az->runned_az, pb->logical_port)) {
            return EN_UNHANDLED;
        }
    }

    return EN_HANDLED_UNCHANGED;
}

void *
en_service_monitor_init(struct engine_node *node OVS_UNUSED,
                        struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_service_monitor_cleanup(void *data OVS_UNUSED)
{
}
