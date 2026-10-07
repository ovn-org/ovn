/*
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

#ifndef OVN_IC_H
#define OVN_IC_H 1

#include "ovsdb-idl.h"
#include "unixctl.h"

struct ic_context {
    struct ovsdb_idl *ovnnb_idl;
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl *ovninb_idl;
    struct ovsdb_idl *ovnisb_idl;
    struct ovsdb_idl *ovnisb_unlocked_idl;
    struct ovsdb_idl_txn *ovnnb_txn;
    struct ovsdb_idl_txn *ovnsb_txn;
    struct ovsdb_idl_txn *ovninb_txn;
    struct ovsdb_idl_txn *ovnisb_txn;
    struct ovsdb_idl_txn *ovnisb_unlocked_txn;
    struct ovsdb_idl_index *nbrec_ls_by_name;
    struct ovsdb_idl_index *nbrec_lr_by_name;
    struct ovsdb_idl_index *nbrec_lrp_by_name;
    struct ovsdb_idl_index *nbrec_port_by_name;
    struct ovsdb_idl_index *sbrec_chassis_by_name;
    struct ovsdb_idl_index *sbrec_datapath_binding_by_nb_uuid;
    struct ovsdb_idl_index *sbrec_learned_route_by_datapath;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    struct ovsdb_idl_index *sbrec_service_monitor_by_remote_type;
    struct ovsdb_idl_index *sbrec_service_monitor_by_ic_learned;
    struct ovsdb_idl_index *sbrec_service_monitor_by_remote_type_logical_port;
    struct ovsdb_idl_index *icnbrec_transit_switch_by_name;
    struct ovsdb_idl_index *icnbrec_transit_router_by_name;
    struct ovsdb_idl_index *icsbrec_port_binding_by_az;
    struct ovsdb_idl_index *icsbrec_port_binding_by_ts;
    struct ovsdb_idl_index *icsbrec_port_binding_by_ts_az;
    struct ovsdb_idl_index *icsbrec_route_by_az;
    struct ovsdb_idl_index *icsbrec_route_by_ts;
    struct ovsdb_idl_index *icsbrec_route_by_ts_az;
    struct ovsdb_idl_index *icsbrec_service_monitor_by_source_az;
    struct ovsdb_idl_index *icsbrec_service_monitor_by_target_az;
    struct ovsdb_idl_index *icsbrec_service_monitor_by_target_az_logical_port;
};

struct ic_state {
    bool had_lock; /* Lock to local AZ SB */
    bool had_isb_lock; /* Lock to ISB */
    bool paused;
};

enum ic_datapath_type { IC_SWITCH, IC_ROUTER, IC_DATAPATH_MAX };
enum ic_port_binding_type { IC_SWITCH_PORT, IC_ROUTER_PORT, IC_PORT_MAX };

struct hmap;
struct shash;
struct sset;
struct icsbrec_availability_zone;
struct icsbrec_datapath_binding;
struct sbrec_chassis_table;
struct icsbrec_gateway_table;
struct nbrec_logical_switch_port;
struct nbrec_logical_router_port;

enum ic_datapath_type ic_dp_get_type(
    const struct icsbrec_datapath_binding *isb_dp);

void address_set_run(struct ic_context *ctx,
                     const struct icsbrec_availability_zone *runned_az);
struct icsbrec_port_binding;
enum ic_port_binding_type ic_pb_get_type(
    const struct icsbrec_port_binding *isb_pb);

/* Reconciles the AZ NB Logical_Switch mirrors of the transit switches named in
 * 'ts_scope' (NULL reconciles every transit switch).  'isb_ts_dps' is the
 * transit-switch IC-SB Datapath_Binding map (keyed by transit-switch name),
 * read only to copy each committed tunnel key into the mirror's
 * requested-tnl-key.  IC-SB Datapath_Binding creation/keying/GC is owned by
 * the en_tunnel_key node. */
void ts_sync_scope(struct ic_context *ctx, struct shash *isb_ts_dps,
                   const struct sset *ts_scope);

/* True if transit-switch datapaths must use the VXLAN tunnel-key range: IC-NB
 * requests vxlan_mode and the IC-SB actually has a VXLAN encap. */
bool ic_ts_compute_vxlan_mode(struct ic_context *ctx);

/* Scope-resolution helpers for the en_port_binding change handlers.  Build the
 * reverse maps once per handler invocation, then resolve each changed port
 * with the *_collect_* helpers. */
void port_binding_lsp_ts_map_init(struct ic_context *ctx, struct shash *map);
void port_binding_collect_lsp_ts(const struct shash *lsp_ts_map,
                                 const struct nbrec_logical_switch_port *lsp,
                                 struct sset *ts_scope);

/* Shared IC helpers used by more than one engine node. */
uint32_t
allocate_dp_key(struct hmap *dp_tnlids, bool vxlan_mode, const char *name);
const struct sbrec_chassis *
find_sb_chassis(struct ic_context *ctx, const char *name);
const struct sbrec_port_binding *
find_sb_pb_by_name(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                   const char *name);
const struct nbrec_logical_switch *
find_ts_in_nb(struct ic_context *ctx, char *ts_name);
const struct nbrec_logical_router_port *
get_lrp_by_lrp_name(struct ic_context *ctx, const char *lrp_name);
const struct nbrec_logical_switch_port *
get_lsp_by_ts_port_name(struct ic_context *ctx, const char *ts_port_name);
bool
is_az_leader(struct ovsdb_idl_txn *txn);

#endif /* OVN_IC_H */
