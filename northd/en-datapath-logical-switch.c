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

#include "openvswitch/hmap.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"

#include "inc-proc-eng.h"
#include "ovn-nb-idl.h"
#include "datapath-sync.h"
#include "en-datapath-logical-switch.h"
#include "en-global-config.h"
#include "ovn-util.h"

VLOG_DEFINE_THIS_MODULE(en_datapath_logical_switch);

void *
en_datapath_logical_switch_init(struct engine_node *node OVS_UNUSED,
                                struct engine_arg *args OVS_UNUSED)
{
    struct ovn_unsynced_datapath_map *map = xmalloc(sizeof *map);
    ovn_unsynced_datapath_map_init(map, DP_SWITCH);
    return map;
}

static uint32_t
get_requested_tunnel_key(const struct nbrec_logical_switch *nbs,
                         bool vxlan_mode)
{
    uint32_t requested_tunnel_key = smap_get_int(&nbs->other_config,
                                                 "requested-tnl-key", 0);
    const char *ts = smap_get(&nbs->other_config, "interconn-ts");

    if (!ts && vxlan_mode && requested_tunnel_key >= 1 << 12) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "Tunnel key %"PRIu32" for datapath %s is "
                     "incompatible with VXLAN", requested_tunnel_key,
                     nbs->name);
        requested_tunnel_key = 0;
    }

    return requested_tunnel_key;
}

static void
gather_external_ids(const struct nbrec_logical_switch *nbs,
                    struct smap *external_ids)
{
    smap_add(external_ids, "name", nbs->name);
    const char *neutron_network = smap_get(&nbs->other_config,
                                           "neutron:network_name");
    if (neutron_network && neutron_network[0]) {
        smap_add(external_ids, "name2", neutron_network);
    }

    int64_t ct_zone_limit = ovn_smap_get_llong(&nbs->other_config,
                                               "ct-zone-limit", -1);
    if (ct_zone_limit > 0) {
        smap_add_format(external_ids, "ct-zone-limit", "%"PRId64,
                        ct_zone_limit);
    }

    const char *ts = smap_get(&nbs->other_config, "interconn-ts");
    if (ts) {
        smap_add(external_ids, "interconn-ts", ts);
    }

    uint32_t age_threshold = smap_get_uint(&nbs->other_config,
                                           "fdb_age_threshold", 0);
    if (age_threshold) {
        smap_add_format(external_ids, "fdb_age_threshold",
                        "%u", age_threshold);
    }

    const char *vni = smap_get(&nbs->other_config, "dynamic-routing-vni");
    if (vni) {
        smap_add(external_ids, "dynamic-routing-vni", vni);
    }

    const char *redistribute =
        smap_get(&nbs->other_config, "dynamic-routing-redistribute");
    if (redistribute) {
        smap_add(external_ids, "dynamic-routing-redistribute", redistribute);
    }

    /* For backwards-compatibility, also store the NB UUID in
     * external-ids:logical-switch. This is useful if ovn-controller
     * has not updated and expects this to be where to find the
     * UUID.
     */
    smap_add_format(external_ids, "logical-switch", UUID_FMT,
                    UUID_ARGS(&nbs->header_.uuid));
}

static struct ovn_unsynced_datapath *
datapath_unsynced_new_logical_switch_handler(
        const struct nbrec_logical_switch *nbs,
        const struct ed_type_global_config *global_config,
        struct ovn_unsynced_datapath_map *map)
{
    uint32_t requested_tunnel_key = get_requested_tunnel_key(
        nbs, global_config->vxlan_mode);

    struct ovn_unsynced_datapath *udp =
        ovn_unsynced_datapath_alloc(nbs->name, DP_SWITCH,
                                    requested_tunnel_key, &nbs->header_);

    gather_external_ids(nbs, &udp->external_ids);
    hmap_insert(&map->dps, &udp->hmap_node, uuid_hash(&nbs->header_.uuid));
    return udp;
}

enum engine_input_handler_result
datapath_logical_switch_handler(struct engine_node *node, void *data)
{
    const struct nbrec_logical_switch_table *nb_ls_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));
    const struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);
    struct ovn_unsynced_datapath_map *map = data;

    const struct nbrec_logical_switch *nbs;
    NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH_TRACKED (nbs, nb_ls_table) {
        struct ovn_unsynced_datapath *udp =
            ovn_unsynced_datapath_find(map, &nbs->header_.uuid);

        if (nbrec_logical_switch_is_new(nbs)) {
            if (udp) {
                return EN_UNHANDLED;
            }
            udp = datapath_unsynced_new_logical_switch_handler(nbs,
                                                               global_config,
                                                               map);
            hmapx_add(&map->new, udp);
        } else if (nbrec_logical_switch_is_deleted(nbs)) {
            if (!udp) {
                return EN_UNHANDLED;
            }
            hmap_remove(&map->dps, &udp->hmap_node);
            hmapx_add(&map->deleted, udp);
        } else {
            if (!udp) {
                return EN_UNHANDLED;
            }

            udp->requested_tunnel_key = get_requested_tunnel_key(
                    nbs, global_config->vxlan_mode);
            smap_destroy(&udp->external_ids);
            smap_init(&udp->external_ids);
            gather_external_ids(nbs, &udp->external_ids);
            hmapx_add(&map->updated, udp);
        }
    }

    if (!(hmapx_is_empty(&map->new) &&
          hmapx_is_empty(&map->updated) &&
          hmapx_is_empty(&map->deleted))) {
        return EN_HANDLED_UPDATED;
    }

    return EN_HANDLED_UNCHANGED;
}

void
en_datapath_logical_switch_clear_tracked_data(void *data)
{
    struct ovn_unsynced_datapath_map *map = data;
    ovn_unsynced_datapath_map_clear_tracked_data(map);
}

enum engine_node_state
en_datapath_logical_switch_run(struct engine_node *node , void *data)
{
    const struct nbrec_logical_switch_table *nb_ls_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));
    const struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);

    struct ovn_unsynced_datapath_map *map = data;

    ovn_unsynced_datapath_map_destroy(map);
    ovn_unsynced_datapath_map_init(map, DP_SWITCH);

    const struct nbrec_logical_switch *nbs;
    NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH (nbs, nb_ls_table) {
        datapath_unsynced_new_logical_switch_handler(nbs, global_config, map);
    }

    return EN_UPDATED;
}

void
en_datapath_logical_switch_cleanup(void *data)
{
    struct ovn_unsynced_datapath_map *map = data;
    ovn_unsynced_datapath_map_destroy(map);
}

struct ovn_synced_logical_switch *
ovn_synced_logical_switch_find(const struct ovn_synced_logical_switch_map *map,
                               const struct uuid *nb_uuid)
{
    struct ovn_synced_logical_switch *lsw;
    HMAP_FOR_EACH_WITH_HASH (lsw, hmap_node, uuid_hash(nb_uuid),
                             &map->synced_switches) {
        if (uuid_equals(&lsw->nb->header_.uuid, nb_uuid)) {
            return lsw;
        }
    }

    return NULL;
}

static void
synced_logical_switch_map_init(
    struct ovn_synced_logical_switch_map *switch_map)
{
    *switch_map = (struct ovn_synced_logical_switch_map) {
        .synced_switches = HMAP_INITIALIZER(&switch_map->synced_switches),
        .new = HMAPX_INITIALIZER(&switch_map->new),
        .updated = HMAPX_INITIALIZER(&switch_map->updated),
        .deleted = HMAPX_INITIALIZER(&switch_map->deleted),
    };
}

static void
synced_logical_switch_map_destroy(
    struct ovn_synced_logical_switch_map *switch_map)
{
    hmapx_destroy(&switch_map->new);
    hmapx_destroy(&switch_map->updated);

    struct hmapx_node *node;
    struct ovn_synced_logical_switch *ls;
    HMAPX_FOR_EACH_SAFE (node, &switch_map->deleted) {
        ls = node->data;
        free(ls);
        hmapx_delete(&switch_map->deleted, node);
    }
    hmapx_destroy(&switch_map->deleted);
    HMAP_FOR_EACH_POP (ls, hmap_node, &switch_map->synced_switches) {
        free(ls);
    }
    hmap_destroy(&switch_map->synced_switches);
}

void *
en_datapath_synced_logical_switch_init(struct engine_node *node OVS_UNUSED,
                                      struct engine_arg *args OVS_UNUSED)
{
    struct ovn_synced_logical_switch_map *switch_map;
    switch_map = xmalloc(sizeof *switch_map);
    synced_logical_switch_map_init(switch_map);

    return switch_map;
}

static struct ovn_synced_logical_switch *
synced_logical_switch_alloc(const struct ovn_synced_datapath *sdp)
{
    struct ovn_synced_logical_switch *lsw = xmalloc(sizeof *lsw);
    *lsw = (struct ovn_synced_logical_switch) {
        .nb = CONTAINER_OF(sdp->nb_row, struct nbrec_logical_switch,
                           header_),
        .sdp = sdp,
    };
    return lsw;
}

enum engine_node_state
en_datapath_synced_logical_switch_run(struct engine_node *node , void *data)
{
    const struct ovn_synced_datapaths *dps =
        engine_get_input_data("datapath_sync", node);
    struct ovn_synced_logical_switch_map *switch_map = data;

    synced_logical_switch_map_destroy(switch_map);
    synced_logical_switch_map_init(switch_map);

    struct ovn_synced_datapath *sdp;
    HMAP_FOR_EACH (sdp, hmap_node, &dps->synced_dps) {
        if (sdp->nb_row->table->class_ != &nbrec_table_logical_switch) {
            continue;
        }
        struct ovn_synced_logical_switch *lsw =
            synced_logical_switch_alloc(sdp);
        hmap_insert(&switch_map->synced_switches, &lsw->hmap_node,
                    uuid_hash(&lsw->nb->header_.uuid));
    }

    return EN_UPDATED;
}

void
en_datapath_synced_logical_switch_clear_tracked_data(void *data)
{
    struct ovn_synced_logical_switch_map *switch_map = data;

    hmapx_clear(&switch_map->new);
    hmapx_clear(&switch_map->updated);

    struct hmapx_node *node;
    HMAPX_FOR_EACH_SAFE (node, &switch_map->deleted) {
        struct ovn_synced_logical_router *lr = node->data;
        free(lr);
        hmapx_delete(&switch_map->deleted, node);
    }
}


enum engine_input_handler_result
en_datapath_synced_logical_switch_datapath_sync_handler(
        struct engine_node *node, void *data)
{
    const struct ovn_synced_datapaths *dps =
        engine_get_input_data("datapath_sync", node);
    struct ovn_synced_logical_switch_map *switch_map = data;

    if (hmapx_is_empty(&dps->deleted) &&
        hmapx_is_empty(&dps->new) &&
        hmapx_is_empty(&dps->updated)) {
        return EN_UNHANDLED;
    }

    struct hmapx_node *hmapx_node;
    struct ovn_synced_datapath *sdp;
    struct ovn_synced_logical_switch *lsw;
    HMAPX_FOR_EACH (hmapx_node, &dps->new) {
        sdp = hmapx_node->data;
        if (sdp->nb_row->table->class_ != &nbrec_table_logical_switch) {
            continue;
        }
        lsw = synced_logical_switch_alloc(sdp);
        hmap_insert(&switch_map->synced_switches, &lsw->hmap_node,
                    uuid_hash(&lsw->nb->header_.uuid));
        hmapx_add(&switch_map->new, lsw);
    }

    HMAPX_FOR_EACH (hmapx_node, &dps->deleted) {
        sdp = hmapx_node->data;
        if (sdp->nb_row->table->class_ != &nbrec_table_logical_switch) {
            continue;
        }
        lsw = ovn_synced_logical_switch_find(switch_map, &sdp->nb_row->uuid);
        if (!lsw) {
            return EN_UNHANDLED;
        }
        hmap_remove(&switch_map->synced_switches, &lsw->hmap_node);
        hmapx_add(&switch_map->deleted, lsw);
    }

    HMAPX_FOR_EACH (hmapx_node, &dps->updated) {
        sdp = hmapx_node->data;
        if (sdp->nb_row->table->class_ != &nbrec_table_logical_switch) {
            continue;
        }
        lsw = ovn_synced_logical_switch_find(switch_map, &sdp->nb_row->uuid);
        if (!lsw) {
            return EN_UNHANDLED;
        }
        lsw->nb = CONTAINER_OF(sdp->nb_row, struct nbrec_logical_switch,
                               header_);
        lsw->sdp = sdp;
        hmapx_add(&switch_map->updated, lsw);
    }

    if (hmapx_is_empty(&switch_map->new) &&
        hmapx_is_empty(&switch_map->updated) &&
        hmapx_is_empty(&switch_map->deleted)) {
        return EN_HANDLED_UNCHANGED;
    }

    return EN_HANDLED_UPDATED;
}

void en_datapath_synced_logical_switch_cleanup(void *data)
{
    struct ovn_synced_logical_switch_map *switch_map = data;
    synced_logical_switch_map_destroy(switch_map);
}
