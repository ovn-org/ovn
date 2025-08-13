/* Copyright (c) 2025, Red Hat, Inc.
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

#include "datapath-sync.h"
#include "ovsdb-idl-provider.h"
#include "uuid.h"

static const char *ovn_datapath_strings[] = {
    [DP_SWITCH] = "logical-switch",
    [DP_ROUTER] = "logical-router",
    [DP_MAX] = "<invalid>",
};

enum ovn_datapath_type
ovn_datapath_type_from_string(const char *type_str)
{
    for (enum ovn_datapath_type i = DP_SWITCH; i < DP_MAX; i++) {
        if (!strcmp(type_str, ovn_datapath_strings[i])) {
            return i;
        }
    }

    return DP_MAX;
}

const char *
ovn_datapath_type_to_string(enum ovn_datapath_type dp_type)
{
    if (dp_type > DP_MAX) {
        dp_type = DP_MAX;
    }
    return ovn_datapath_strings[dp_type];
}

struct ovn_unsynced_datapath *
ovn_unsynced_datapath_alloc(const char *name, enum ovn_datapath_type type,
                            uint32_t requested_tunnel_key,
                            const struct ovsdb_idl_row *nb_row)
{
    struct ovn_unsynced_datapath *dp = xmalloc(sizeof *dp);
    *dp = (struct ovn_unsynced_datapath) {
        .name = xstrdup(name),
        .type = type,
        .requested_tunnel_key = requested_tunnel_key,
        .nb_row = nb_row,
        .external_ids = SMAP_INITIALIZER(&dp->external_ids),
    };

    return dp;
}

void
ovn_unsynced_datapath_destroy(struct ovn_unsynced_datapath *dp)
{
    free(dp->name);
    smap_destroy(&dp->external_ids);
}

void
ovn_unsynced_datapath_map_init(struct ovn_unsynced_datapath_map *map,
                               enum ovn_datapath_type dp_type)
{
    *map = (struct ovn_unsynced_datapath_map) {
        .dps = HMAP_INITIALIZER(&map->dps),
        .new = HMAPX_INITIALIZER(&map->new),
        .deleted = HMAPX_INITIALIZER(&map->deleted),
        .updated = HMAPX_INITIALIZER(&map->updated),
        .dp_type = dp_type,
    };
}

void
ovn_unsynced_datapath_map_destroy(struct ovn_unsynced_datapath_map *map)
{
    struct ovn_unsynced_datapath *dp;
    struct hmapx_node *node;

    hmapx_destroy(&map->new);
    hmapx_destroy(&map->updated);
    HMAPX_FOR_EACH_SAFE (node, &map->deleted) {
       /* Items in the deleted hmapx need to be freed individually since
        * they are not in map->dps.
        */
        dp = node->data;
        ovn_unsynced_datapath_destroy(dp);
        free(dp);
    }
    hmapx_destroy(&map->deleted);

    HMAP_FOR_EACH_POP (dp, hmap_node, &map->dps) {
        ovn_unsynced_datapath_destroy(dp);
        free(dp);
    }
    hmap_destroy(&map->dps);
}

struct ovn_unsynced_datapath *
ovn_unsynced_datapath_find(const struct ovn_unsynced_datapath_map *map,
                           const struct uuid *datapath_uuid)
{
    uint32_t hash = uuid_hash(datapath_uuid);

    struct ovn_unsynced_datapath *udp;
    HMAP_FOR_EACH_WITH_HASH (udp, hmap_node, hash, &map->dps) {
        if (uuid_equals(&udp->nb_row->uuid, datapath_uuid)) {
            return udp;
        }
    }
    return NULL;
}

void
ovn_unsynced_datapath_map_clear_tracked_data(
    struct ovn_unsynced_datapath_map *map)
{
    hmapx_clear(&map->new);
    hmapx_clear(&map->updated);

    /* Deleted entries need to be freed since they don't
     * exist in map->dps.
     */
    struct hmapx_node *node;
    HMAPX_FOR_EACH_SAFE (node, &map->deleted) {
        struct ovn_unsynced_datapath *udp = node->data;
        ovn_unsynced_datapath_destroy(udp);
        free(udp);
        hmapx_delete(&map->deleted, node);
    }
}
