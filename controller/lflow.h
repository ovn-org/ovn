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

#ifndef OVN_LFLOW_H
#define OVN_LFLOW_H 1

#include "lib/ovn-util.h"
#include "lib/objdep.h"
#include "lib/uuidset.h"
#include "ovn/logical-fields.h"

/* Logical_Flow table translation to OpenFlow
 * ==========================================
 *
 * The Logical_Flow table obtained from the OVN_Southbound database works in
 * terms of logical entities, that is, logical flows among logical datapaths
 * and logical ports.  This code translates these logical flows into OpenFlow
 * flows that, again, work in terms of logical entities implemented through
 * OpenFlow extensions (e.g. registers represent the logical input and output
 * ports).
 *
 * Physical-to-logical and logical-to-physical translation are implemented in
 * physical.[ch] as separate OpenFlow tables that run before and after,
 * respectively, the logical pipeline OpenFlow tables.
 */

#include <stdint.h>
#include "lflow-cache.h"
#include "lflow-conj-ids.h"
#include "openvswitch/hmap.h"
#include "openvswitch/uuid.h"
#include "openvswitch/list.h"

struct hmap;
struct hmap_node;
struct ovn_desired_flow_table;
struct ovn_extend_table;
struct ovsdb_idl_index;
struct ovsrec_flow_sample_collector_set_table;
struct sbrec_chassis;
struct sbrec_load_balancer;
struct sbrec_logical_flow_table;
struct sbrec_mac_binding_table;
struct sbrec_datapath_binding;
struct sbrec_port_binding;
struct simap;
struct sset;
struct uuid;

/* OpenFlow table numbers.
 *
 * These are heavily documented in ovn-architecture(7), please update it if
 * you make any changes. */
#define OFTABLE_PHY_TO_LOG                0

/* Start of LOG_PIPELINE_LEN tables. */
#define OFTABLE_LOG_INGRESS_PIPELINE      8
#define OFTABLE_OUTPUT_LARGE_PKT_DETECT  37
#define OFTABLE_OUTPUT_LARGE_PKT_PROCESS 38
#define OFTABLE_REMOTE_OUTPUT            39
#define OFTABLE_LOCAL_OUTPUT             40
#define OFTABLE_CHECK_LOOPBACK           41

/* Start of the OUTPUT section of the pipeline. */
#define OFTABLE_OUTPUT_INIT OFTABLE_OUTPUT_LARGE_PKT_DETECT

/* Start of LOG_PIPELINE_LEN tables. */
#define OFTABLE_LOG_EGRESS_PIPELINE      42
#define OFTABLE_SAVE_INPORT              64
#define OFTABLE_LOG_TO_PHY               65
#define OFTABLE_MAC_BINDING              66
#define OFTABLE_MAC_LOOKUP               67
#define OFTABLE_CHK_LB_HAIRPIN           68
#define OFTABLE_CHK_LB_HAIRPIN_REPLY     69
#define OFTABLE_CT_SNAT_HAIRPIN          70
#define OFTABLE_GET_FDB                  71
#define OFTABLE_LOOKUP_FDB               72
#define OFTABLE_CHK_IN_PORT_SEC          73
#define OFTABLE_CHK_IN_PORT_SEC_ND       74
#define OFTABLE_CHK_OUT_PORT_SEC         75
#define OFTABLE_ECMP_NH_MAC              76
#define OFTABLE_ECMP_NH                  77
#define OFTABLE_CHK_LB_AFFINITY          78

struct lflow_ctx_in {
    struct ovsdb_idl_index *sbrec_multicast_group_by_name_datapath;
    struct ovsdb_idl_index *sbrec_logical_flow_by_logical_datapath;
    struct ovsdb_idl_index *sbrec_logical_flow_by_logical_dp_group;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    struct ovsdb_idl_index *sbrec_port_binding_by_key;
    struct ovsdb_idl_index *sbrec_fdb_by_dp_key;
    struct ovsdb_idl_index *sbrec_mac_binding_by_datapath;
    struct ovsdb_idl_index *sbrec_static_mac_binding_by_datapath;
    const struct sbrec_port_binding_table *port_binding_table;
    const struct sbrec_datapath_binding_table *dp_binding_table;
    const struct sbrec_mac_binding_table *mac_binding_table;
    const struct sbrec_logical_flow_table *logical_flow_table;
    const struct sbrec_logical_dp_group_table *logical_dp_group_table;
    const struct sbrec_multicast_group_table *mc_group_table;
    const struct sbrec_fdb_table *fdb_table;
    const struct sbrec_chassis *chassis;
    const struct sbrec_static_mac_binding_table *static_mac_binding_table;
    const struct hmap *local_datapaths;
    const struct shash *addr_sets;
    const struct shash *port_groups;
    const struct sset *active_tunnels;
    const struct sset *related_lport_ids;
    const struct shash *binding_lports;
    const struct hmap *chassis_tunnels;
    const struct hmap *nd_ra_opts;
    const struct hmap *dhcp_opts;
    const struct hmap *dhcpv6_opts;
    const struct controller_event_options *controller_event_opts;
    const struct smap *template_vars;
    const struct flow_collector_ids *collector_ids;
    const struct hmap *local_lbs;
    bool lb_hairpin_use_ct_mark;
    bool localnet_learn_fdb;
    bool localnet_learn_fdb_changed;
};

struct lflow_ctx_out {
    struct ovn_desired_flow_table *flow_table;
    struct ovn_extend_table *group_table;
    struct ovn_extend_table *meter_table;
    struct objdep_mgr *lflow_deps_mgr;
    struct objdep_mgr *lb_deps_mgr;
    struct lflow_cache *lflow_cache;
    struct conj_ids *conj_ids;
    struct uuidset *objs_processed;
};

void lflow_init(void);
void lflow_run(struct lflow_ctx_in *, struct lflow_ctx_out *);
void lflow_handle_cached_flows(struct lflow_cache *,
                               const struct sbrec_logical_flow_table *);
bool lflow_handle_changed_flows(struct lflow_ctx_in *,
                                struct lflow_ctx_out *);

struct addr_set_diff {
    struct expr_constant_set *added;
    struct expr_constant_set *deleted;
};
bool lflow_handle_addr_set_update(const char *as_name, struct addr_set_diff *,
                                  struct lflow_ctx_in *,
                                  struct lflow_ctx_out *,
                                  bool *changed);
bool lflow_handle_changed_ref(enum objdep_type, const char *res_name,
                              struct ovs_list *objs_todo,
                              const void *in_arg, void *out_arg);

void lflow_handle_changed_mac_bindings(
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct sbrec_mac_binding_table *mac_binding_table,
    const struct hmap *local_datapaths,
    struct ovn_desired_flow_table *);
void lflow_handle_changed_static_mac_bindings(
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct sbrec_static_mac_binding_table *smb_table,
    const struct hmap *local_datapaths,
    struct ovn_desired_flow_table *);
bool lflow_handle_changed_lbs(struct lflow_ctx_in *l_ctx_in,
                              struct lflow_ctx_out *l_ctx_out,
                              const struct uuidset *deleted_lbs,
                              const struct uuidset *updated_lbs,
                              const struct uuidset *new_lbs,
                              const struct hmap *old_lbs);
bool lflow_handle_changed_fdbs(struct lflow_ctx_in *, struct lflow_ctx_out *);
void lflow_destroy(void);

bool lflow_add_flows_for_datapath(const struct sbrec_datapath_binding *,
                                  struct lflow_ctx_in *,
                                  struct lflow_ctx_out *);
bool lflow_handle_flows_for_lport(const struct sbrec_port_binding *,
                                  struct lflow_ctx_in *,
                                  struct lflow_ctx_out *);
bool lflow_handle_changed_mc_groups(struct lflow_ctx_in *,
                                    struct lflow_ctx_out *);
bool lflow_handle_changed_port_bindings(struct lflow_ctx_in *,
                                        struct lflow_ctx_out *);

#endif /* controller/lflow.h */
