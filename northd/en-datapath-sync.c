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

struct candidate_sdp {
    struct ovn_synced_datapath *sdp;
    uint32_t requested_tunnel_key;
    uint32_t existing_tunnel_key;
    bool tunnel_key_assigned;
};

static struct ovn_synced_datapath *
synced_datapath_alloc(const struct ovn_unsynced_datapath *udp,
                      const struct sbrec_datapath_binding *sb_dp)
{
    struct ovn_synced_datapath *sdp;
    sdp = xmalloc(sizeof *sdp);
    *sdp = (struct ovn_synced_datapath) {
        .sb_dp = sb_dp,
        .nb_row = udp->nb_row,
    };
    sbrec_datapath_binding_set_external_ids(sb_dp, &udp->external_ids);

    sbrec_datapath_binding_set_type(sb_dp,
                                    ovn_datapath_type_to_string(udp->type));
    return sdp;
}

static void
reset_synced_datapaths(struct ovn_synced_datapaths *synced_datapaths)
{
    struct ovn_synced_datapath *sdp;
    HMAP_FOR_EACH_POP (sdp, hmap_node, &synced_datapaths->synced_dps) {
        free(sdp);
    }
    ovn_destroy_tnlids(&synced_datapaths->dp_tnlids);
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
            .sdp = synced_datapath_alloc(udp, sb_dp),
            .requested_tunnel_key = udp->requested_tunnel_key,
            .existing_tunnel_key = sb_dp->tunnel_key,
        };
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
                .sdp = synced_datapath_alloc(udp, sb_dp),
                .requested_tunnel_key = udp->requested_tunnel_key,
                .existing_tunnel_key = sb_dp->tunnel_key,
            };
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

    HMAP_FOR_EACH_POP (sdp, hmap_node, &synced_datapaths->synced_dps) {
        free(sdp);
    }
    hmap_destroy(&synced_datapaths->synced_dps);
    ovn_destroy_tnlids(&synced_datapaths->dp_tnlids);
}
