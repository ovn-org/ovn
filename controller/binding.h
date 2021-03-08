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

struct binding_ctx_in {
    struct ovsdb_idl_txn *ovnsb_idl_txn;
    struct ovsdb_idl_txn *ovs_idl_txn;
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key;
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    const struct ovsrec_port_table *port_table;
    const struct ovsrec_qos_table *qos_table;
    const struct sbrec_port_binding_table *port_binding_table;
    const struct ovsrec_bridge *br_int;
    const struct sbrec_chassis *chassis_rec;
    const struct sset *active_tunnels;
    const struct ovsrec_bridge_table *bridge_table;
    const struct ovsrec_open_vswitch_table *ovs_table;
    const struct ovsrec_interface_table *iface_table;
};

struct binding_ctx_out {
    struct hmap *local_datapaths;
    struct local_binding_data *lbinding_data;

    /* sset of (potential) local lports. */
    struct sset *local_lports;
    /* Track if local_lports have been updated. */
    bool local_lports_changed;

    /* sset of local lport ids in the format
     * <datapath-tunnel-key>_<port-tunnel-key>. */
    struct sset *local_lport_ids;
    /* Track if local_lport_ids has been updated. */
    bool local_lport_ids_changed;

    /* Track if non-vif port bindings (e.g., patch, external) have been
     * added/deleted.
     */
    bool non_vif_ports_changed;

    struct sset *egress_ifaces;
    /* smap of OVS interface name as key and
     * OVS interface external_ids:iface-id as value. */
    struct smap *local_iface_ids;

    /* hmap of 'struct tracked_binding_datapath' which the
     * callee (binding_handle_ovs_interface_changes and
     * binding_handle_port_binding_changes) fills in for
     * the changed datapaths and port bindings. */
    struct hmap *tracked_dp_bindings;
};

struct local_binding_data {
    struct shash bindings;
    struct shash lports;
};

void local_binding_data_init(struct local_binding_data *);
void local_binding_data_destroy(struct local_binding_data *);

const struct sbrec_port_binding *local_binding_get_primary_pb(
    struct shash *local_bindings, const char *pb_name);

/* Represents a tracked binding logical port. */
struct tracked_binding_lport {
    const struct sbrec_port_binding *pb;
};

/* Represent a tracked binding datapath. */
struct tracked_binding_datapath {
    struct hmap_node node;
    const struct sbrec_datapath_binding *dp;
    bool is_new;
    struct shash lports; /* shash of struct tracked_binding_lport. */
};

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

void binding_init(void);
void binding_seqno_run(struct local_binding_data *lbinding_data);
void binding_seqno_install(struct local_binding_data *lbinding_data);
void binding_seqno_flush(void);
void binding_dump_local_bindings(struct local_binding_data *, struct ds *);
#endif /* controller/binding.h */
