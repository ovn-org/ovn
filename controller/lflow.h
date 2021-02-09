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
#include "openvswitch/hmap.h"
#include "openvswitch/uuid.h"
#include "openvswitch/list.h"

struct ovn_extend_table;
struct ovsdb_idl_index;
struct ovn_desired_flow_table;
struct hmap;
struct hmap_node;
struct sbrec_chassis;
struct sbrec_dhcp_options_table;
struct sbrec_dhcpv6_options_table;
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
#define OFTABLE_PHY_TO_LOG            0
#define OFTABLE_LOG_INGRESS_PIPELINE  8 /* First of LOG_PIPELINE_LEN tables. */
#define OFTABLE_REMOTE_OUTPUT        32
#define OFTABLE_LOCAL_OUTPUT         33
#define OFTABLE_CHECK_LOOPBACK       34
#define OFTABLE_LOG_EGRESS_PIPELINE  40 /* First of LOG_PIPELINE_LEN tables. */
#define OFTABLE_SAVE_INPORT          64
#define OFTABLE_LOG_TO_PHY           65
#define OFTABLE_MAC_BINDING          66
#define OFTABLE_MAC_LOOKUP           67
#define OFTABLE_CHK_LB_HAIRPIN       68
#define OFTABLE_CHK_LB_HAIRPIN_REPLY 69
#define OFTABLE_CT_SNAT_FOR_VIP      70

/* The number of tables for the ingress and egress pipelines. */
#define LOG_PIPELINE_LEN 24

enum ref_type {
    REF_TYPE_ADDRSET,
    REF_TYPE_PORTGROUP,
    REF_TYPE_PORTBINDING
};

struct ref_lflow_node {
    struct hmap_node node; /* node in lflow_resource_ref.ref_lflow_table. */
    enum ref_type type; /* key */
    char *ref_name; /* key */
    struct hmap lflow_uuids; /* Contains lflow_ref_list_node. Use hmap instead
                                of list so that lflow_resource_add() can check
                                and avoid adding redundant entires in O(1). */
};

struct lflow_ref_node {
    struct hmap_node node; /* node in lflow_resource_ref.lflow_ref_table. */
    struct uuid lflow_uuid; /* key */
    struct ovs_list lflow_ref_head; /* Contains lflow_ref_list_node. */
};

/* Maintains the relationship for a pair of named resource and
 * a lflow, indexed by both ref_lflow_table and lflow_ref_table. */
struct lflow_ref_list_node {
    struct ovs_list list_node; /* node in lflow_ref_node.lflow_ref_head. */
    struct hmap_node hmap_node; /* node in ref_lflow_node.lflow_uuids. */
    struct uuid lflow_uuid;
    struct ref_lflow_node *rlfn;
};

struct lflow_resource_ref {
    /* A map from a referenced resource type & name (e.g. address_set AS1)
     * to a list of lflows that are referencing the named resource. Data
     * type of each node in this hmap is struct ref_lflow_node. The
     * ref_lflow_head in each node points to a list of
     * lflow_ref_list_node.ref_list. */
    struct hmap ref_lflow_table;

    /* A map from a lflow uuid to a list of named resources that are
     * referenced by the lflow. Data type of each node in this hmap is
     * struct lflow_ref_node. The lflow_ref_head in each node points to
     * a list of lflow_ref_list_node.lflow_list. */
    struct hmap lflow_ref_table;
};

void lflow_resource_init(struct lflow_resource_ref *);
void lflow_resource_destroy(struct lflow_resource_ref *);
void lflow_resource_clear(struct lflow_resource_ref *);

struct lflow_ctx_in {
    struct ovsdb_idl_index *sbrec_multicast_group_by_name_datapath;
    struct ovsdb_idl_index *sbrec_logical_flow_by_logical_datapath;
    struct ovsdb_idl_index *sbrec_logical_flow_by_logical_dp_group;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    const struct sbrec_dhcp_options_table *dhcp_options_table;
    const struct sbrec_dhcpv6_options_table *dhcpv6_options_table;
    const struct sbrec_datapath_binding_table *dp_binding_table;
    const struct sbrec_mac_binding_table *mac_binding_table;
    const struct sbrec_logical_flow_table *logical_flow_table;
    const struct sbrec_logical_dp_group_table *logical_dp_group_table;
    const struct sbrec_multicast_group_table *mc_group_table;
    const struct sbrec_chassis *chassis;
    const struct sbrec_load_balancer_table *lb_table;
    const struct hmap *local_datapaths;
    const struct shash *addr_sets;
    const struct shash *port_groups;
    const struct sset *active_tunnels;
    const struct sset *local_lport_ids;
};

struct lflow_ctx_out {
    struct ovn_desired_flow_table *flow_table;
    struct ovn_extend_table *group_table;
    struct ovn_extend_table *meter_table;
    struct lflow_resource_ref *lfrr;
    struct lflow_cache *lflow_cache;
    uint32_t *conj_id_ofs;
    bool conj_id_overflow;
};

void lflow_init(void);
void lflow_run(struct lflow_ctx_in *, struct lflow_ctx_out *);
void lflow_handle_cached_flows(struct lflow_cache *,
                               const struct sbrec_logical_flow_table *);
bool lflow_handle_changed_flows(struct lflow_ctx_in *, struct lflow_ctx_out *);
bool lflow_handle_changed_ref(enum ref_type, const char *ref_name,
                              struct lflow_ctx_in *, struct lflow_ctx_out *,
                              bool *changed);
void lflow_handle_changed_neighbors(
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct sbrec_mac_binding_table *,
    const struct hmap *local_datapaths,
    struct ovn_desired_flow_table *);
bool lflow_handle_changed_lbs(struct lflow_ctx_in *, struct lflow_ctx_out *);
void lflow_destroy(void);

bool lflow_add_flows_for_datapath(const struct sbrec_datapath_binding *,
                                  struct lflow_ctx_in *,
                                  struct lflow_ctx_out *);
bool lflow_handle_flows_for_lport(const struct sbrec_port_binding *,
                                  struct lflow_ctx_in *,
                                  struct lflow_ctx_out *);
#endif /* controller/lflow.h */
