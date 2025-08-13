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
        .dp_type = dp_type,
    };
}

void
ovn_unsynced_datapath_map_destroy(struct ovn_unsynced_datapath_map *map)
{
    struct ovn_unsynced_datapath *dp;
    HMAP_FOR_EACH_POP (dp, hmap_node, &map->dps) {
        ovn_unsynced_datapath_destroy(dp);
        free(dp);
    }
    hmap_destroy(&map->dps);
}
