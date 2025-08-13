/*
 * Copyright (c) 2025, Red Hat, Inc.
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

#include "uuidset.h"

#include "en-datapath-sync.h"
#include "en-global-config.h"
#include "datapath-sync.h"
#include "ovn-sb-idl.h"
#include "openvswitch/vlog.h"
#include "vec.h"

VLOG_DEFINE_THIS_MODULE(datapath_sync);

void *
en_datapath_sync_init(struct engine_node *node OVS_UNUSED,
                      struct engine_arg *args OVS_UNUSED)
{
    struct ovn_synced_datapaths *synced_datapaths
        = xmalloc(sizeof *synced_datapaths);
    *synced_datapaths = (struct ovn_synced_datapaths) {
        .synced_dps = HMAP_INITIALIZER(&synced_datapaths->synced_dps),
        .dp_tnlids = HMAP_INITIALIZER(&synced_datapaths->dp_tnlids),
        .new = HMAPX_INITIALIZER(&synced_datapaths->new),
        .deleted = HMAPX_INITIALIZER(&synced_datapaths->deleted),
        .updated = HMAPX_INITIALIZER(&synced_datapaths->updated),
    };

    return synced_datapaths;
}

static struct ovn_unsynced_datapath *
find_unsynced_datapath(const struct ovn_unsynced_datapath_map **maps,
                       const struct sbrec_datapath_binding *sb_dp)
{
    enum ovn_datapath_type dp_type;
    const char *type;
    struct uuid nb_uuid;

    if (!datapath_get_nb_uuid_and_type(sb_dp, &nb_uuid, &type)) {
        return NULL;
    }

    dp_type = ovn_datapath_type_from_string(type);
    if (dp_type == DP_MAX) {
        /* This record was not created by us. It's invalid. */
        return NULL;
    }

    uint32_t hash = uuid_hash(&nb_uuid);
    struct ovn_unsynced_datapath *dp;
    HMAP_FOR_EACH_WITH_HASH (dp, hmap_node, hash, &maps[dp_type]->dps) {
        if (uuid_equals(&nb_uuid, &dp->nb_row->uuid)) {
            return dp;
        }
    }

    return NULL;
}

static struct ovn_synced_datapath *
find_synced_datapath_from_udp(
        const struct ovn_synced_datapaths *synced_datapaths,
        const struct ovn_unsynced_datapath *udp)
{
    struct ovn_synced_datapath *sdp;
    uint32_t hash = uuid_hash(&udp->nb_row->uuid);
    HMAP_FOR_EACH_WITH_HASH (sdp, hmap_node, hash,
                             &synced_datapaths->synced_dps) {
        if (uuid_equals(&sdp->nb_row->uuid, &udp->nb_row->uuid)) {
            return sdp;
        }
    }

    return NULL;
}

static struct ovn_synced_datapath *
find_synced_datapath_from_sb(const struct hmap *datapaths,
                             const struct sbrec_datapath_binding *sb_dp)
{
    struct ovn_synced_datapath *sdp;
    uint32_t hash = uuid_hash(&sb_dp->header_.uuid);
    HMAP_FOR_EACH_WITH_HASH (sdp, hmap_node, hash, datapaths) {
        if (uuid_equals(&sdp->nb_row->uuid, &sb_dp->header_.uuid)) {
            return sdp;
        }
    }

    return NULL;
}

struct candidate_sdp {
    struct ovn_synced_datapath *sdp;
    uint32_t requested_tunnel_key;
    uint32_t existing_tunnel_key;
    bool tunnel_key_assigned;
};

static struct ovn_synced_datapath *
synced_datapath_alloc(const struct ovn_unsynced_datapath *udp,
                      const struct sbrec_datapath_binding *sb_dp,
                      bool pending_sb_dp)
{
    struct ovn_synced_datapath *sdp;
    sdp = xmalloc(sizeof *sdp);
    *sdp = (struct ovn_synced_datapath) {
        .sb_dp = sb_dp,
        .nb_row = udp->nb_row,
        .pending_sb_dp = pending_sb_dp
    };
    return sdp;
}

static void
synced_datapath_set_sb_fields(const struct sbrec_datapath_binding *sb_dp,
                              const struct ovn_unsynced_datapath *udp)
{
    sbrec_datapath_binding_set_external_ids(sb_dp, &udp->external_ids);
    sbrec_datapath_binding_set_type(sb_dp,
                                    ovn_datapath_type_to_string(udp->type));
}

static void
clear_tracked_data(struct ovn_synced_datapaths *synced_datapaths)
{
    hmapx_clear(&synced_datapaths->new);
    hmapx_clear(&synced_datapaths->updated);

    struct hmapx_node *node;
    HMAPX_FOR_EACH_SAFE (node, &synced_datapaths->deleted) {
        free(node->data);
        hmapx_delete(&synced_datapaths->deleted, node);
    }
}

static void
reset_synced_datapaths(struct ovn_synced_datapaths *synced_datapaths)
{
    struct ovn_synced_datapath *sdp;
    HMAP_FOR_EACH_POP (sdp, hmap_node, &synced_datapaths->synced_dps) {
        free(sdp);
    }
    ovn_destroy_tnlids(&synced_datapaths->dp_tnlids);
    clear_tracked_data(synced_datapaths);
    hmap_init(&synced_datapaths->dp_tnlids);
}

static void
create_synced_datapath_candidates_from_sb(
    const struct sbrec_datapath_binding_table *sb_dp_table,
    struct uuidset *visited,
    const struct ovn_unsynced_datapath_map **input_maps,
    struct vector *candidate_sdps)
{
    const struct sbrec_datapath_binding *sb_dp;
    SBREC_DATAPATH_BINDING_TABLE_FOR_EACH_SAFE (sb_dp, sb_dp_table) {
        struct ovn_unsynced_datapath *udp = find_unsynced_datapath(input_maps,
                                                                   sb_dp);
        if (!udp) {
            sbrec_datapath_binding_delete(sb_dp);
            continue;
        }

        if (uuidset_find(visited, &udp->nb_row->uuid)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(
                &rl, "deleting Datapath_Binding "UUID_FMT" with "
                "duplicate nb_uuid "UUID_FMT,
                UUID_ARGS(&sb_dp->header_.uuid),
                UUID_ARGS(&udp->nb_row->uuid));
            sbrec_datapath_binding_delete(sb_dp);
            continue;
        }

        struct candidate_sdp candidate = {
            .sdp = synced_datapath_alloc(udp, sb_dp, false),
            .requested_tunnel_key = udp->requested_tunnel_key,
            .existing_tunnel_key = sb_dp->tunnel_key,
        };
        synced_datapath_set_sb_fields(sb_dp, udp);
        vector_push(candidate_sdps, &candidate);
        uuidset_insert(visited, &udp->nb_row->uuid);
    }
}

static void
create_synced_datapath_candidates_from_nb(
    const struct ovn_unsynced_datapath_map **input_maps,
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    struct uuidset *visited,
    struct vector *candidate_sdps)
{
    for (size_t i = 0; i < DP_MAX; i++) {
        const struct ovn_unsynced_datapath_map *map = input_maps[i];
        struct ovn_unsynced_datapath *udp;
        HMAP_FOR_EACH (udp, hmap_node, &map->dps) {
            if (uuidset_find(visited, &udp->nb_row->uuid)) {
                continue;
            }
            struct sbrec_datapath_binding *sb_dp;
            sb_dp = sbrec_datapath_binding_insert_persist_uuid(
                        ovnsb_idl_txn, &udp->nb_row->uuid);
            struct candidate_sdp candidate = {
                .sdp = synced_datapath_alloc(udp, sb_dp, true),
                .requested_tunnel_key = udp->requested_tunnel_key,
                .existing_tunnel_key = sb_dp->tunnel_key,
            };
            synced_datapath_set_sb_fields(sb_dp, udp);
            vector_push(candidate_sdps, &candidate);
        }
    }
}

static void
assign_requested_tunnel_keys(struct vector *candidate_sdps,
                             struct ovn_synced_datapaths *synced_datapaths)
{
    struct candidate_sdp *candidate;
    VECTOR_FOR_EACH_PTR (candidate_sdps, candidate) {
        if (!candidate->requested_tunnel_key) {
            continue;
        }
        if (!ovn_add_tnlid(&synced_datapaths->dp_tnlids,
                           candidate->requested_tunnel_key)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Logical datapath "UUID_FMT" requests same "
                         "tunnel key %"PRIu32" as another logical datapath",
                         UUID_ARGS(&candidate->sdp->nb_row->uuid),
                         candidate->requested_tunnel_key);
            continue;
        }
        sbrec_datapath_binding_set_tunnel_key(candidate->sdp->sb_dp,
                                              candidate->requested_tunnel_key);
        hmap_insert(&synced_datapaths->synced_dps, &candidate->sdp->hmap_node,
                    uuid_hash(&candidate->sdp->sb_dp->header_.uuid));
        candidate->tunnel_key_assigned = true;
    }
}

static void
assign_existing_tunnel_keys(struct vector *candidate_sdps,
                            struct ovn_synced_datapaths *synced_datapaths)
{
    struct candidate_sdp *candidate;
    VECTOR_FOR_EACH_PTR (candidate_sdps, candidate) {
        if (!candidate->existing_tunnel_key ||
            candidate->tunnel_key_assigned) {
            continue;
        }
        /* Existing southbound DP. If this key is available,
         * reuse it.
         */
        if (ovn_add_tnlid(&synced_datapaths->dp_tnlids,
                          candidate->existing_tunnel_key)) {
            hmap_insert(&synced_datapaths->synced_dps,
                        &candidate->sdp->hmap_node,
                        uuid_hash(&candidate->sdp->sb_dp->header_.uuid));
            candidate->tunnel_key_assigned = true;
        }
    }
}

static void
allocate_tunnel_keys(struct vector *candidate_sdps,
                     uint32_t max_dp_tunnel_id,
                     struct ovn_synced_datapaths *synced_datapaths)
{
    uint32_t hint = 0;
    struct candidate_sdp *candidate;
    VECTOR_FOR_EACH_PTR (candidate_sdps, candidate) {
        if (candidate->tunnel_key_assigned) {
            continue;
        }
        uint32_t tunnel_key =
            ovn_allocate_tnlid(&synced_datapaths->dp_tnlids, "datapath",
                               OVN_MIN_DP_KEY_LOCAL,
                               max_dp_tunnel_id, &hint);
        if (!tunnel_key) {
            continue;
        }
        sbrec_datapath_binding_set_tunnel_key(candidate->sdp->sb_dp,
                                              tunnel_key);
        hmap_insert(&synced_datapaths->synced_dps, &candidate->sdp->hmap_node,
                    uuid_hash(&candidate->sdp->sb_dp->header_.uuid));
        candidate->tunnel_key_assigned = true;
    }
}

static void
delete_unassigned_candidates(struct vector *candidate_sdps)
{
    struct candidate_sdp *candidate;
    VECTOR_FOR_EACH_PTR (candidate_sdps, candidate) {
        if (candidate->tunnel_key_assigned) {
            continue;
        }
        sbrec_datapath_binding_delete(candidate->sdp->sb_dp);
        free(candidate->sdp);
    }
}

static enum engine_input_handler_result
datapath_sync_unsynced_datapath_handler(
        const struct ovn_unsynced_datapath_map *map,
        const struct ed_type_global_config *global_config,
        struct ovsdb_idl_txn *ovnsb_idl_txn, void *data)
{
    enum engine_input_handler_result ret = EN_HANDLED_UNCHANGED;
    struct ovn_synced_datapaths *synced_datapaths = data;
    struct ovn_unsynced_datapath *udp;
    struct ovn_synced_datapath *sdp;

    if (hmapx_is_empty(&map->new) &&
        hmapx_is_empty(&map->deleted) &&
        hmapx_is_empty(&map->updated)) {
        return EN_UNHANDLED;
    }

    struct hmapx_node *n;
    HMAPX_FOR_EACH (n, &map->deleted) {
        udp = n->data;
        sdp = find_synced_datapath_from_udp(synced_datapaths, udp);
        if (!sdp) {
            return EN_UNHANDLED;
        }
        hmap_remove(&synced_datapaths->synced_dps, &sdp->hmap_node);
        hmapx_add(&synced_datapaths->deleted, sdp);
        ovn_free_tnlid(&synced_datapaths->dp_tnlids,
                       sdp->sb_dp->tunnel_key);
        sbrec_datapath_binding_delete(sdp->sb_dp);
        ret = EN_HANDLED_UPDATED;
    }

    HMAPX_FOR_EACH (n, &map->new) {
        udp = n->data;
        uint32_t tunnel_key;

        if (find_synced_datapath_from_udp(synced_datapaths, udp)) {
            return EN_UNHANDLED;
        }

        if (udp->requested_tunnel_key) {
            tunnel_key = udp->requested_tunnel_key;
            if (!ovn_add_tnlid(&synced_datapaths->dp_tnlids, tunnel_key)) {
                return EN_UNHANDLED;
            }
        } else {
            uint32_t hint = 0;
            tunnel_key = ovn_allocate_tnlid(&synced_datapaths->dp_tnlids,
                                            "datapath", OVN_MIN_DP_KEY_LOCAL,
                                            global_config->max_dp_tunnel_id,
                                            &hint);
            if (!tunnel_key) {
                return EN_UNHANDLED;
            }
        }

        struct sbrec_datapath_binding *sb_dp =
            sbrec_datapath_binding_insert_persist_uuid(ovnsb_idl_txn,
                                                       &udp->nb_row->uuid);
        sbrec_datapath_binding_set_tunnel_key(sb_dp, tunnel_key);
        sdp = synced_datapath_alloc(udp, sb_dp, true);
        synced_datapath_set_sb_fields(sb_dp, udp);
        hmap_insert(&synced_datapaths->synced_dps, &sdp->hmap_node,
                    uuid_hash(&udp->nb_row->uuid));
        hmapx_add(&synced_datapaths->new, sdp);
        ret = EN_HANDLED_UPDATED;
    }

    HMAPX_FOR_EACH (n, &map->updated) {
        udp = n->data;
        sdp = find_synced_datapath_from_udp(synced_datapaths, udp);
        if (!sdp || !sdp->sb_dp) {
            return EN_UNHANDLED;
        }
        if (udp->requested_tunnel_key &&
            udp->requested_tunnel_key != sdp->sb_dp->tunnel_key) {
            ovn_free_tnlid(&synced_datapaths->dp_tnlids,
                           sdp->sb_dp->tunnel_key);
            if (!ovn_add_tnlid(&synced_datapaths->dp_tnlids,
                               udp->requested_tunnel_key)) {
                return EN_UNHANDLED;
            }
            sbrec_datapath_binding_set_tunnel_key(sdp->sb_dp,
                                                  udp->requested_tunnel_key);
        }
        if (!smap_equal(&udp->external_ids, &sdp->sb_dp->external_ids)) {
            sbrec_datapath_binding_set_external_ids(sdp->sb_dp,
                                                    &udp->external_ids);
        }
        hmapx_add(&synced_datapaths->updated, sdp);
        ret = EN_HANDLED_UPDATED;
    }

    return ret;
}

enum engine_input_handler_result
datapath_sync_logical_switch_handler(struct engine_node *node, void *data)
{
    const struct ovn_unsynced_datapath_map *map =
        engine_get_input_data("datapath_logical_switch", node);
    const struct engine_context *eng_ctx = engine_get_context();
    const struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);

    return datapath_sync_unsynced_datapath_handler(map, global_config,
                                                   eng_ctx->ovnsb_idl_txn,
                                                   data);
}

enum engine_input_handler_result
datapath_sync_logical_router_handler(struct engine_node *node, void *data)
{
    const struct ovn_unsynced_datapath_map *map =
        engine_get_input_data("datapath_logical_router", node);
    const struct engine_context *eng_ctx = engine_get_context();
    const struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);

    return datapath_sync_unsynced_datapath_handler(map, global_config,
                                                   eng_ctx->ovnsb_idl_txn,
                                                   data);
}

enum engine_input_handler_result
datapath_sync_global_config_handler(struct engine_node *node, void *data)
{
    const struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);
    struct ovn_synced_datapaths *synced_datapaths = data;

    if (synced_datapaths->vxlan_mode !=
        global_config->vxlan_mode) {
        /* If VXLAN mode changes, then the range of datapath tunnel IDs
         * has completely been upended and we need to recompute.
         */
        return EN_UNHANDLED;
    }

    return EN_HANDLED_UNCHANGED;
}

enum engine_input_handler_result
datapath_sync_sb_datapath_binding(struct engine_node *node, void *data)
{
    const struct sbrec_datapath_binding_table *sb_dp_table =
        EN_OVSDB_GET(engine_get_input("SB_datapath_binding", node));
    enum engine_input_handler_result ret = EN_HANDLED_UNCHANGED;
    struct ovn_synced_datapaths *synced_datapaths = data;

    const struct sbrec_datapath_binding *sb_dp;
    SBREC_DATAPATH_BINDING_TABLE_FOR_EACH_TRACKED (sb_dp, sb_dp_table) {
        struct ovn_synced_datapath *sdp =
            find_synced_datapath_from_sb(&synced_datapaths->synced_dps, sb_dp);
        if (sbrec_datapath_binding_is_deleted(sb_dp)) {
            if (sdp) {
                /* The SB datapath binding was deleted, but we still have a
                 * record of it locally. This implies the SB datapath binding
                 * was deleted by something other than ovn-northd. We need
                 * to recompute in this case.
                 */
                return EN_UNHANDLED;
            }
            continue;
        }

        if (sbrec_datapath_binding_is_new(sb_dp)) {
            if (!sdp) {
                /* There is a new datapath binding, but we have no record
                 * of the synced datapath. This indicates that
                 * something other than ovn-northd added this datapath
                 * binding to the database, and we need to recompute.
                 */
                return EN_UNHANDLED;
            } else {
                if (sdp->pending_sb_dp) {
                    /* Update the existing synced datapath pointer to the safer
                     * version to cache.
                     */
                    sdp->sb_dp = sb_dp;
                    sdp->pending_sb_dp = false;
                } else {
                    /* Someone inserted a duplicate datapath into SB, do a full
                     * recompute in that case.
                     */
                    return EN_UNHANDLED;
                }
            }
            continue;
        }

        /* Datapath binding is updated. This happens if the northbound
         * logical datapath is updated and we make changes to the existing
         * southbound datapath binding. In this case, the handler for the
         * unsynced datapath will add sdp to synced_datapaths->updated, so
         * we don't need to do anything here.
         */
    }

    return ret;
}

void
en_datapath_sync_clear_tracked_data(void *data)
{
    struct ovn_synced_datapaths *synced_datapaths = data;

    clear_tracked_data(synced_datapaths);
}

enum engine_node_state
en_datapath_sync_run(struct engine_node *node , void *data)
{
    const struct sbrec_datapath_binding_table *sb_dp_table =
        EN_OVSDB_GET(engine_get_input("SB_datapath_binding", node));
    const struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);
    const struct ovn_unsynced_datapath_map *unsynced_ls_map =
        engine_get_input_data("datapath_logical_switch", node);
    const struct ovn_unsynced_datapath_map *unsynced_lr_map =
        engine_get_input_data("datapath_logical_router", node);

    const struct ovn_unsynced_datapath_map *input_maps[DP_MAX];
    struct ovn_synced_datapaths *synced_datapaths = data;

    input_maps[unsynced_ls_map->dp_type] = unsynced_ls_map;
    input_maps[unsynced_lr_map->dp_type] = unsynced_lr_map;

    size_t num_datapaths = 0;
    for (enum ovn_datapath_type i = 0; i < DP_MAX; i++) {
        ovs_assert(input_maps[i]);
        num_datapaths += hmap_count(&input_maps[i]->dps);
    }

    reset_synced_datapaths(synced_datapaths);

    synced_datapaths->vxlan_mode = global_config->vxlan_mode;

    struct uuidset visited = UUIDSET_INITIALIZER(&visited);
    struct vector candidate_sdps =
        VECTOR_CAPACITY_INITIALIZER(struct candidate_sdp, num_datapaths);
    create_synced_datapath_candidates_from_sb(sb_dp_table, &visited,
                                              input_maps, &candidate_sdps);

    const struct engine_context *eng_ctx = engine_get_context();
    create_synced_datapath_candidates_from_nb(input_maps,
                                              eng_ctx->ovnsb_idl_txn, &visited,
                                              &candidate_sdps);
    uuidset_destroy(&visited);

    assign_requested_tunnel_keys(&candidate_sdps, synced_datapaths);
    assign_existing_tunnel_keys(&candidate_sdps, synced_datapaths);
    allocate_tunnel_keys(&candidate_sdps, global_config->max_dp_tunnel_id,
                         synced_datapaths);

    delete_unassigned_candidates(&candidate_sdps);
    vector_destroy(&candidate_sdps);

    return EN_UPDATED;
}

void en_datapath_sync_cleanup(void *data)
{
    struct ovn_synced_datapaths *synced_datapaths = data;
    struct ovn_synced_datapath *sdp;

    hmapx_destroy(&synced_datapaths->new);
    hmapx_destroy(&synced_datapaths->updated);
    struct hmapx_node *node;
    HMAPX_FOR_EACH_SAFE (node, &synced_datapaths->deleted) {
        free(node->data);
    }
    hmapx_destroy(&synced_datapaths->deleted);

    HMAP_FOR_EACH_POP (sdp, hmap_node, &synced_datapaths->synced_dps) {
        free(sdp);
    }
    hmap_destroy(&synced_datapaths->synced_dps);
    ovn_destroy_tnlids(&synced_datapaths->dp_tnlids);
}
