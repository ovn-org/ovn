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

#ifndef DATAPATH_SYNC_H
#define DATAPATH_SYNC_H 1

#include "openvswitch/hmap.h"
#include "smap.h"
#include "hmapx.h"

/* Datapath syncing API. This file consists of utility functions
 * that can be used when syncing northbound datapath types (e.g.
 * Logical_Router and Logical_Switch) to southbound Datapath_Bindings.
 *
 * The basic flow of data is as such.
 * 1. A northbound type is converted into an ovn_unsynced_datapath.
 * All ovn_unsynced_datapaths are placed into an ovn_unsynced_datapath_map.
 * 2. The en_datapath_sync node takes all of the maps in as input and
 * syncs them with southbound datapath bindings. This includes allocating
 * tunnel keys across all datapath types. The output of this node is
 * ovn_synced_datapaths, which contains a list of all synced datapaths.
 * 3. A northbound type-aware node then takes the ovn_synced_datapaths,
 * and decodes the generic synced datapaths back into a type-specific
 * version (e.g. ovn_synced_logical_router). Later nodes can then consume
 * these type-specific synced datapath types in order to perform
 * further processing.
 */

enum ovn_datapath_type {
    DP_MIN = 0,
    DP_SWITCH = DP_MIN,
    DP_ROUTER,
    DP_MAX,
};

enum ovn_datapath_type ovn_datapath_type_from_string(const char *type_str);
const char *ovn_datapath_type_to_string(enum ovn_datapath_type dp_type);

/* Represents a datapath from the northbound database
 * that has not yet been synced with the southbound database.
 */
struct ovn_unsynced_datapath {
    struct hmap_node hmap_node;
    char *name;
    enum ovn_datapath_type type;
    uint32_t requested_tunnel_key;
    struct smap external_ids;
    const struct ovsdb_idl_row *nb_row;
};

struct ovn_unsynced_datapath_map {
    /* ovn_unsynced_datapath */
    struct hmap dps;
    enum ovn_datapath_type dp_type;

    /* Data for incremental case. */
    struct hmapx new;
    struct hmapx updated;
    struct hmapx deleted;
};

struct ovn_synced_datapath {
    struct hmap_node hmap_node;
    const struct ovsdb_idl_row *nb_row;
    const struct sbrec_datapath_binding *sb_dp;
    /* This boolean indicates if the synced datapath
     * has a transient sb_dp pointer. If "true", then
     * it means the sb_dp field is the return value of
     * sbrec_datapath_binding_insert(). If "false", then
     * it means the sb_dp field was provided by an IDL
     * update.
     *
     * This field is only necessary in order to distinguish
     * duplicate southbound datapath binding records. If a
     * mischievous agent inserts a datapath binding that walks,
     * looks, and quacks like an existing datapath binding,
     * this is what helps us distinguish that the inserted
     * datapath is actually a duplicate of a known datapath.
     */
    bool pending_sb_dp;
};

struct ovn_synced_datapaths {
    struct hmap synced_dps;
    struct hmap dp_tnlids;

    struct hmapx new;
    struct hmapx updated;
    struct hmapx deleted;

    /* Cache the vxlan mode setting. This is an easy way for us to detect if
     * the global configuration resulted in a change to this value.
     */
    bool vxlan_mode;
};

struct ovn_unsynced_datapath *ovn_unsynced_datapath_alloc(
    const char *name, enum ovn_datapath_type type,
    uint32_t requested_tunnel_key, const struct ovsdb_idl_row *nb_row);
void ovn_unsynced_datapath_destroy(struct ovn_unsynced_datapath *);

void ovn_unsynced_datapath_map_init(struct ovn_unsynced_datapath_map *,
                                    enum ovn_datapath_type);
void ovn_unsynced_datapath_map_destroy(struct ovn_unsynced_datapath_map *);

struct ovn_unsynced_datapath *
ovn_unsynced_datapath_find(const struct ovn_unsynced_datapath_map *,
                           const struct uuid *);

void ovn_unsynced_datapath_map_clear_tracked_data(
    struct ovn_unsynced_datapath_map *);

#endif /* DATAPATH_SYNC_H */
