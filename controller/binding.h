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


#ifndef OVN_BINDING_H
#define OVN_BINDING_H 1

#include <stdbool.h>
#include "openvswitch/shash.h"
#include "openvswitch/hmap.h"
#include "openvswitch/uuid.h"
#include "openvswitch/list.h"
# include "lib/ovn-util.h"
#include "sset.h"
#include "lport.h"

struct hmap;
struct ovsdb_idl;
struct ovsdb_idl_index;
struct ovsdb_idl_txn;
struct ovsrec_bridge;
struct ovsrec_port_table;
struct ovsrec_qos_table;
struct ovsrec_bridge_table;
struct ovsrec_open_vswitch_table;
struct sbrec_chassis;
struct sbrec_port_binding_table;
struct sset;
struct sbrec_port_binding;
struct ds;
struct if_status_mgr;

struct binding_ctx_in {
    struct ovsdb_idl_txn *ovnsb_idl_txn;
    struct ovsdb_idl_txn *ovs_idl_txn;
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key;
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    struct ovsdb_idl_index *ovsrec_port_by_qos;
    struct ovsdb_idl_index *ovsrec_queue_by_external_ids;
    const struct ovsrec_qos_table *qos_table;
    const struct sbrec_port_binding_table *port_binding_table;
    const struct ovsrec_bridge *br_int;
    const struct sbrec_chassis *chassis_rec;
    const struct sset *active_tunnels;
    const struct ovsrec_bridge_table *bridge_table;
    const struct ovsrec_open_vswitch_table *ovs_table;
    const struct ovsrec_interface_table *iface_table;
    struct shash *iface_table_external_ids_old;
};

/* Locally relevant port bindings, e.g., VIFs that might be bound locally,
 * patch ports.
 */
struct related_lports {
    struct sset lport_names; /* Set of port names. */
    struct sset lport_ids;   /* Set of <datapath-tunnel-key>_<port-tunnel-key>
                              * IDs for fast lookup.
                              */
};

void related_lports_init(struct related_lports *);
void related_lports_destroy(struct related_lports *);

struct binding_ctx_out {
    struct hmap *local_datapaths;
    struct shash *local_active_ports_ipv6_pd;
    struct shash *local_active_ports_ras;
    struct local_binding_data *lbinding_data;

    /* sset of (potential) local lports. */
    struct sset *local_lports;
    /* Track if local_lports have been updated. */
    bool local_lports_changed;

    /* Port bindings that are relevant to the local chassis. */
    struct related_lports *related_lports;
    bool related_lports_changed;

    /* Track if non-vif port bindings (e.g., patch, external) have been
     * added/deleted.
     */
    bool non_vif_ports_changed;

    struct hmap *qos_map;
    /* smap of OVS interface name as key and
     * OVS interface external_ids:iface-id as value. */
    struct smap *local_iface_ids;

    /* hmap of 'struct tracked_binding_datapath' which the
     * callee (binding_handle_ovs_interface_changes and
     * binding_handle_port_binding_changes) fills in for
     * the changed datapaths and port bindings. */
    struct hmap *tracked_dp_bindings;

    struct if_status_mgr *if_mgr;

    struct sset *postponed_ports;

    bool localnet_learn_fdb;
    bool localnet_learn_fdb_changed;
};

/* Local bindings. binding.c module binds the logical port (represented by
 * Port_Binding rows) and sets the 'chassis' column when it sees the
 * OVS interface row (of type "" or "internal") with the
 * external_ids:iface-id=<logical_port name> set.
 *
 * This module also manages the other port_bindings.
 *
 * To better manage the local bindings with the associated OVS interfaces,
 * 'struct local_binding' is used. A shash of these local bindings is
 * maintained with the 'external_ids:iface-id' as the key to the shash.
 *
 * struct local_binding has 3 main fields:
 *    - name : 'external_ids:iface-id' of the OVS interface (key).
 *    - OVS interface row object.
 *    - List of 'binding_lport' objects with the primary lport
 *      in the front of the list (if present).
 *
 *  An object of 'struct local_binding' is created:
 *    - For each interface that has external_ids:iface-id configured.
 *
 *    - For each port binding (also referred as lport) of type 'LP_VIF'
 *      if it is a parent lport of container lports even if there is no
 *      corresponding OVS interface.
 */
struct local_binding {
    char *name;
    const struct ovsrec_interface *iface;
    struct ovs_list binding_lports;
    bool multiple_bindings;
};

struct local_binding_data {
    struct shash bindings;
    struct shash lports;
};

struct local_binding *local_binding_find(
    const struct shash *local_bindings, const char *name);

void local_binding_data_init(struct local_binding_data *);
void local_binding_data_destroy(struct local_binding_data *);

const struct sbrec_port_binding *local_binding_get_primary_pb(
    const struct shash *local_bindings, const char *pb_name);
ofp_port_t local_binding_get_lport_ofport(const struct shash *local_bindings,
                                          const char *pb_name);

bool local_binding_is_up(struct shash *local_bindings, const char *pb_name,
                         const struct sbrec_chassis *);
bool local_binding_is_down(struct shash *local_bindings, const char *pb_name,
                           const struct sbrec_chassis *);

bool local_binding_is_ovn_installed(struct shash *local_bindings,
                                    const char *pb_name);
void local_binding_remove_ovn_installed(
        struct shash *local_bindings,
        const struct ovsrec_interface_table *iface_table,
        const char *pb_name,
        bool ovs_readonly);

void local_binding_set_up(struct shash *local_bindings, const char *pb_name,
                          const struct sbrec_chassis *chassis_rec,
                          const char *ts_now_str, bool sb_readonly,
                          bool ovs_readonly);
void local_binding_set_down(struct shash *local_bindings, const char *pb_name,
                            const struct sbrec_chassis *chassis_rec,
                            bool sb_readonly, bool ovs_readonly);
void local_binding_set_pb(struct shash *local_bindings, const char *pb_name,
                          const struct sbrec_chassis *chassis_rec,
                          struct hmap *tracked_datapaths,
                          bool is_set, enum can_bind);
bool local_bindings_pb_chassis_is_set(struct shash *local_bindings,
                                      const char *pb_name,
                                      const struct sbrec_chassis *chassis_rec);

void binding_register_ovs_idl(struct ovsdb_idl *);
void binding_run(struct binding_ctx_in *, struct binding_ctx_out *);
bool binding_cleanup(struct ovsdb_idl_txn *ovnsb_idl_txn,
                     const struct sbrec_port_binding_table *,
                     const struct sbrec_chassis *);

bool binding_handle_ovs_interface_changes(struct binding_ctx_in *,
                                          struct binding_ctx_out *);
bool binding_handle_port_binding_changes(struct binding_ctx_in *,
                                         struct binding_ctx_out *);
void binding_tracked_dp_destroy(struct hmap *tracked_datapaths);

void binding_dump_local_bindings(struct local_binding_data *, struct ds *);

bool is_additional_chassis(const struct sbrec_port_binding *pb,
                           const struct sbrec_chassis *chassis_rec);

void set_pb_chassis_in_sbrec(const struct sbrec_port_binding *pb,
                             const struct sbrec_chassis *chassis_rec,
                             bool is_set);
void
set_pb_additional_chassis_in_sbrec(const struct sbrec_port_binding *pb,
                                   const struct sbrec_chassis *chassis_rec,
                                   bool is_set);

void remove_ovn_installed_for_uuid(const struct ovsrec_interface_table *,
                                   const struct uuid *);

void port_binding_set_down(const struct sbrec_chassis *chassis_rec,
                           const struct sbrec_port_binding_table *pb_table,
                           const char *iface_id,
                           const struct uuid *pb_uuid);
void port_binding_set_up(const struct sbrec_chassis *chassis_rec,
                         const struct sbrec_port_binding_table *,
                         const char *iface_id,
                         const struct uuid *pb_uuid);
void port_binding_set_pb(const struct sbrec_chassis *chassis_rec,
                         const struct sbrec_port_binding_table *,
                         const char *iface_id,
                         const struct uuid *pb_uuid,
                         enum can_bind bind_type);
bool port_binding_pb_chassis_is_set(const struct sbrec_chassis *chassis_rec,
                                    const struct sbrec_port_binding_table *,
                                    const struct uuid *pb_uuid);

/* This structure represents a logical port (or port binding)
 * which is associated with 'struct local_binding'.
 *
 * An instance of 'struct binding_lport' is created for a logical port
 *  - If the OVS interface's iface-id corresponds to the logical port.
 *  - If it is a container or virtual logical port and its parent
 *    has a 'local binding'.
 *
 */
struct binding_lport {
    struct ovs_list list_node; /* Node in local_binding.binding_lports. */

    char *name;
    const struct sbrec_port_binding *pb;
    struct local_binding *lbinding;
    enum en_lport_type type;

    /* Cached port security. */
    char **port_security;
    size_t n_port_security;
};

struct sset *get_postponed_ports(void);

/* Schedule any pending binding work. */
void binding_wait(void);

/* Clean up module state. */
void binding_destroy(void);

void destroy_qos_map(struct hmap *);

void update_qos(struct ovsdb_idl_index * sbrec_port_binding_by_name,
                struct ovsdb_idl_txn *ovs_idl_txn,
                struct ovsdb_idl_index *ovsrec_port_by_qos,
                const struct ovsrec_qos_table *qos_table,
                struct hmap *qos_map,
                const struct ovsrec_open_vswitch_table *ovs_table,
                const struct ovsrec_bridge_table *bridge_table);

bool lport_maybe_postpone(const char *port_name, long long int now,
                          struct sset *postponed_ports);

void claimed_lport_set_up(const struct sbrec_port_binding *pb,
                          const struct sbrec_port_binding *parent_pb);
bool port_binding_is_up(const struct sbrec_chassis *chassis_rec,
                        const struct sbrec_port_binding_table *,
                        const struct uuid *pb_uuid);
#endif /* controller/binding.h */
