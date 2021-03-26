/* Copyright (c) 2015, 2016 Nicira, Inc.
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

#ifndef OVN_PATCH_H
#define OVN_PATCH_H 1

/* Patch Ports
 * ===========
 *
 * This module adds and removes patch ports between the integration bridge and
 * physical bridges, as directed by other-config:ovn-bridge-mappings. */

struct hmap;
struct ovsdb_idl_txn;
struct ovsdb_idl_index;
struct ovsrec_bridge;
struct ovsrec_bridge_table;
struct ovsrec_open_vswitch_table;
struct ovsrec_port_table;
struct sbrec_port_binding_table;
struct sbrec_chassis;
struct shash;

void add_ovs_bridge_mappings(const struct ovsrec_open_vswitch_table *ovs_table,
                             const struct ovsrec_bridge_table *bridge_table,
                             struct shash *bridge_mappings);
void patch_run(struct ovsdb_idl_txn *ovs_idl_txn,
               struct ovsdb_idl_index *sbrec_port_binding_by_type,
               const struct ovsrec_bridge_table *,
               const struct ovsrec_open_vswitch_table *,
               const struct ovsrec_port_table *,
               const struct ovsrec_bridge *br_int,
               const struct sbrec_chassis *,
               const struct hmap *local_datapaths);
void patch_init(void);
void patch_destroy(void);

#endif /* controller/patch.h */
