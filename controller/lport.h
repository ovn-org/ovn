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

#ifndef OVN_LPORT_H
#define OVN_LPORT_H 1

#include <stdint.h>

struct ovsdb_idl_index;
struct sbrec_chassis;
struct sbrec_datapath_binding;
struct sbrec_multicast_group;
struct sbrec_port_binding;
struct sset;


/* Database indexes.
 * =================
 *
 * If the database IDL were a little smarter, it would allow us to directly
 * look up data based on values of its fields.  It's not that smart (yet), so
 * instead we define our own indexes.
 */

const struct sbrec_port_binding *lport_lookup_by_name(
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const char *name);

const struct sbrec_port_binding *lport_lookup_by_key(
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_key,
    uint64_t dp_key, uint64_t port_key);

const struct sbrec_port_binding *lport_lookup_by_key_with_dp(
    struct ovsdb_idl_index *sbrec_port_binding_by_key,
    const struct sbrec_datapath_binding *dp, uint64_t port_key);

enum can_bind {
    CANNOT_BIND = 0,
    CAN_BIND_AS_MAIN,
    CAN_BIND_AS_ADDITIONAL,
};

enum can_bind
lport_can_bind_on_this_chassis(const struct sbrec_chassis *chassis_rec,
                               const struct sbrec_port_binding *pb);

const struct sbrec_datapath_binding *datapath_lookup_by_key(
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key, uint64_t dp_key);

const struct sbrec_multicast_group *mcgroup_lookup_by_dp_name(
    struct ovsdb_idl_index *sbrec_multicast_group_by_name_datapath,
    const struct sbrec_datapath_binding *, const char *name);
bool
lport_is_chassis_resident(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                          const struct sbrec_chassis *chassis,
                          const struct sset *active_tunnels,
                          const char *port_name);
const struct sbrec_port_binding *lport_get_peer(
    const struct sbrec_port_binding *,
    struct ovsdb_idl_index *sbrec_port_binding_by_name);
const struct sbrec_port_binding *lport_get_l3gw_peer(
    const struct sbrec_port_binding *,
    struct ovsdb_idl_index *sbrec_port_binding_by_name);
bool
lport_is_activated_by_activation_strategy(const struct sbrec_port_binding *pb,
                                          const struct sbrec_chassis *chassis);
#endif /* controller/lport.h */
