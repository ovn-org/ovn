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
#ifndef NORTHD_H
#define NORTHD_H 1

#include "ovsdb-idl.h"

#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/ovs-atomic.h"
#include "lib/sset.h"
#include "northd/en-port-group.h"
#include "northd/ipam.h"
#include "openvswitch/hmap.h"
#include "simap.h"
#include "ovs-thread.h"

struct northd_input {
    /* Northbound table references */
    const struct nbrec_logical_switch_table *nbrec_logical_switch_table;
    const struct nbrec_logical_router_table *nbrec_logical_router_table;
    const struct nbrec_static_mac_binding_table
        *nbrec_static_mac_binding_table;
    const struct nbrec_chassis_template_var_table
        *nbrec_chassis_template_var_table;
    const struct nbrec_mirror_table *nbrec_mirror_table;

    /* Southbound table references */
    const struct sbrec_datapath_binding_table *sbrec_datapath_binding_table;
    const struct sbrec_port_binding_table *sbrec_port_binding_table;
    const struct sbrec_mac_binding_table *sbrec_mac_binding_table;
    const struct sbrec_ha_chassis_group_table *sbrec_ha_chassis_group_table;
    const struct sbrec_chassis_table *sbrec_chassis_table;
    const struct sbrec_fdb_table *sbrec_fdb_table;
    const struct sbrec_service_monitor_table *sbrec_service_monitor_table;
    const struct sbrec_dns_table *sbrec_dns_table;
    const struct sbrec_ip_multicast_table *sbrec_ip_multicast_table;
    const struct sbrec_static_mac_binding_table
        *sbrec_static_mac_binding_table;
    const struct sbrec_chassis_template_var_table
        *sbrec_chassis_template_var_table;
    const struct sbrec_mirror_table *sbrec_mirror_table;

    /* Northd lb data node inputs*/
    const struct hmap *lbs;
    const struct hmap *lbgrps;

    /* Global config data node inputs. */
    const struct smap *nb_options;
    const struct smap *sb_options;
    const char *svc_monitor_mac;
    struct eth_addr svc_monitor_mac_ea;
    const struct chassis_features *features;

    /* Indexes */
    struct ovsdb_idl_index *sbrec_chassis_by_name;
    struct ovsdb_idl_index *sbrec_chassis_by_hostname;
    struct ovsdb_idl_index *sbrec_ha_chassis_grp_by_name;
    struct ovsdb_idl_index *sbrec_ip_mcast_by_dp;
    struct ovsdb_idl_index *sbrec_static_mac_binding_by_lport_ip;
    struct ovsdb_idl_index *sbrec_fdb_by_dp_and_port;
};

/* A collection of datapaths. E.g. all logical switch datapaths, or all
 * logical router datapaths. */
struct ovn_datapaths {
    /* Contains struct ovn_datapath elements. */
    struct hmap datapaths;

    /* The array index of each element in 'datapaths'. */
    struct ovn_datapath **array;
};

static inline size_t
ods_size(const struct ovn_datapaths *datapaths)
{
    return hmap_count(&datapaths->datapaths);
}

struct ovn_datapath *
ovn_datapath_find_by_key(struct hmap *datapaths, uint32_t dp_key);

bool od_has_lb_vip(const struct ovn_datapath *od);

/* List of routing and routing-related protocols which
 * OVN is capable of redirecting from LRP to specific LSP. */
enum redirected_routing_protcol_flag_type {
    REDIRECT_BGP = (1 << 0),
    REDIRECT_BFD = (1 << 1),
};

struct tracked_ovn_ports {
    /* tracked created ports.
     * hmapx node data is 'struct ovn_port *' */
    struct hmapx created;

    /* tracked updated ports.
     * hmapx node data is 'struct ovn_port *' */
    struct hmapx updated;

    /* tracked deleted ports.
     * hmapx node data is 'struct ovn_port *' */
    struct hmapx deleted;
};

struct tracked_lbs {
    /* Tracked created or updated load balancers.
     * hmapx node data is 'struct ovn_lb_datapaths' */
    struct hmapx crupdated;

    /* Tracked deleted lbs.
     * hmapx node data is 'struct ovn_lb_datapaths' */
    struct hmapx deleted;
};

enum northd_tracked_data_type {
    NORTHD_TRACKED_NONE,
    NORTHD_TRACKED_PORTS    = (1 << 0),
    NORTHD_TRACKED_LBS      = (1 << 1),
    NORTHD_TRACKED_LR_NATS  = (1 << 2),
    NORTHD_TRACKED_LS_LBS   = (1 << 3),
    NORTHD_TRACKED_LS_ACLS  = (1 << 4),
};

/* Track what's changed in the northd engine node.
 * Now only tracks ovn_ports (of vif type) - created, updated
 * and deleted. */
struct northd_tracked_data {
    /* Indicates the type of data tracked.  One or all of NORTHD_TRACKED_*. */
    enum northd_tracked_data_type type;
    struct tracked_ovn_ports trk_lsps;
    struct tracked_lbs trk_lbs;

    /* Tracked logical routers whose NATs have changed.
     * hmapx node is 'struct ovn_datapath *'. */
    struct hmapx trk_nat_lrs;

    /* Tracked logical switches whose load balancers have changed.
     * hmapx node is 'struct ovn_datapath *'. */
    struct hmapx ls_with_changed_lbs;

    /* Tracked logical switches whose ACLs have changed.
     * hmapx node is 'struct ovn_datapath *'. */
    struct hmapx ls_with_changed_acls;
};

struct northd_data {
    /* Global state for 'en-northd'. */
    struct ovn_datapaths ls_datapaths;
    struct ovn_datapaths lr_datapaths;
    struct hmap ls_ports;
    struct hmap lr_ports;
    struct hmap lb_datapaths_map;
    struct hmap lb_group_datapaths_map;
    struct ovs_list lr_list;
    struct sset svc_monitor_lsps;
    struct hmap svc_monitor_map;

    /* Change tracking data. */
    struct northd_tracked_data trk_data;
};

struct route_policy {
    struct hmap_node key_node;
    const struct nbrec_logical_router_policy *rule;
    size_t n_valid_nexthops;
    char **valid_nexthops;
    const struct nbrec_logical_router *nbr;
    bool stale;
};

struct static_routes_data {
    struct hmap parsed_routes;
    struct simap route_tables;
    struct hmap bfd_active_connections;
};

struct route_policies_data {
    struct hmap route_policies;
    struct hmap bfd_active_connections;
};

struct bfd_data {
    struct hmap bfd_connections;
};

struct bfd_sync_data {
    struct sset bfd_ports;
};

struct ecmp_nexthop_data {
    struct simap nexthops;
};

struct lr_nat_table;

struct lflow_input {
    /* Southbound table references */
    const struct sbrec_logical_flow_table *sbrec_logical_flow_table;
    const struct sbrec_multicast_group_table *sbrec_multicast_group_table;
    const struct sbrec_igmp_group_table *sbrec_igmp_group_table;
    const struct sbrec_logical_dp_group_table *sbrec_logical_dp_group_table;

    /* Indexes */
    struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp;

    const struct ovn_datapaths *ls_datapaths;
    const struct ovn_datapaths *lr_datapaths;
    const struct hmap *ls_ports;
    const struct hmap *lr_ports;
    const struct ls_port_group_table *ls_port_groups;
    const struct lr_stateful_table *lr_stateful_table;
    const struct ls_stateful_table *ls_stateful_table;
    const struct shash *meter_groups;
    const struct hmap *lb_datapaths_map;
    const struct sset *bfd_ports;
    const struct chassis_features *features;
    const struct hmap *svc_monitor_map;
    bool ovn_internal_version_changed;
    const char *svc_monitor_mac;
    const struct sampling_app_table *sampling_apps;
    struct hmap *parsed_routes;
    struct hmap *route_policies;
    struct simap *route_tables;
    struct simap *nexthops_table;
};

extern int parallelization_state;
enum {
    STATE_NULL,               /* parallelization is off */
    STATE_INIT_HASH_SIZES,    /* parallelization is on; hashes sizing needed */
    STATE_USE_PARALLELIZATION /* parallelization is on */
};

extern thread_local size_t thread_lflow_counter;

/*
 * Multicast snooping and querier per datapath configuration.
 */
struct mcast_switch_info {

    bool enabled;               /* True if snooping enabled. */
    bool querier;               /* True if querier enabled. */
    bool flood_unregistered;    /* True if unregistered multicast should be
                                 * flooded.
                                 */
    bool flood_relay;           /* True if the switch is connected to a
                                 * multicast router and unregistered multicast
                                 * should be flooded to the mrouter. Only
                                 * applicable if flood_unregistered == false.
                                 */
    bool flood_reports;         /* True if the switch has at least one port
                                 * configured to flood reports.
                                 */
    bool flood_static;          /* True if the switch has at least one port
                                 * configured to flood traffic.
                                 */
    int64_t table_size;         /* Max number of IP multicast groups. */
    int64_t idle_timeout;       /* Timeout after which an idle group is
                                 * flushed.
                                 */
    int64_t query_interval;     /* Interval between multicast queries. */
    char *eth_src;              /* ETH src address of the queries. */
    char *ipv4_src;             /* IPv4 src address of the queries. */
    char *ipv6_src;             /* IPv6 src address of the queries. */

    int64_t query_max_response; /* Expected time after which reports should
                                 * be received for queries that were sent out.
                                 */

    atomic_uint64_t active_v4_flows;   /* Current number of active IPv4
                                        * multicast flows.
                                        */
    atomic_uint64_t active_v6_flows;   /* Current number of active IPv6
                                        * multicast flows.
                                        */
};

struct mcast_router_info {
    bool relay;        /* True if the router should relay IP multicast. */
    bool flood_static; /* True if the router has at least one port configured
                        * to flood traffic.
                        */
};

struct mcast_info {

    struct hmap group_tnlids;  /* Group tunnel IDs in use on this DP. */
    uint32_t group_tnlid_hint; /* Hint for allocating next group tunnel ID. */
    struct ovs_list groups;    /* List of groups learnt on this DP. */

    union {
        struct mcast_switch_info sw;  /* Switch specific multicast info. */
        struct mcast_router_info rtr; /* Router specific multicast info. */
    };
};

struct mcast_port_info {
    bool flood;         /* True if the port should flood IP multicast traffic
                         * regardless if it's registered or not. */
    bool flood_reports; /* True if the port should flood IP multicast reports
                         * (e.g., IGMP join/leave). */
};

/* The 'key' comes from nbs->header_.uuid or nbr->header_.uuid or
 * sb->external_ids:logical-switch. */
struct ovn_datapath {
    struct hmap_node key_node;  /* Index on 'key'. */
    struct uuid key;            /* (nbs/nbr)->header_.uuid. */

    size_t index;   /* A unique index across all datapaths.
                     * Datapath indexes are sequential and start from zero. */

    struct ovn_datapaths *datapaths; /* The collection of datapaths that
                                        contains this datapath. */

    const struct nbrec_logical_switch *nbs;  /* May be NULL. */
    const struct nbrec_logical_router *nbr;  /* May be NULL. */
    const struct sbrec_datapath_binding *sb; /* May be NULL. */

    struct ovs_list list;       /* In list of similar records. */

    uint32_t tunnel_key;

    /* Logical router data. */
    struct ovn_datapath **ls_peers;
    size_t n_ls_peers;
    size_t n_allocated_ls_peers;
    struct sset router_ips; /* Router port IPs except the IPv6 LLAs. */

    /* Logical switch data. */
    struct ovn_port **router_ports;
    size_t n_router_ports;
    size_t n_allocated_router_ports;

    struct hmap port_tnlids;
    uint32_t port_key_hint;

    bool has_unknown;
    bool has_vtep_lports;
    bool has_arp_proxy_port;

    /* IPAM data. */
    struct ipam_info ipam_info;

    /* Multicast data. */
    struct mcast_info mcast_info;

    /* Applies to only logical router datapath.
     * True if logical router is a gateway router. i.e options:chassis is set.
     * If this is true, then 'l3dgw_ports' will be ignored. */
    bool is_gw_router;

    /* OVN northd only needs to know about logical router gateway ports for
     * NAT/LB on a distributed router.  The "distributed gateway ports" are
     * populated only when there is a gateway chassis or ha chassis group
     * specified for some of the ports on the logical router. Otherwise this
     * will be NULL. */
    struct ovn_port **l3dgw_ports;
    size_t n_l3dgw_ports;
    size_t n_allocated_l3dgw_ports;

    /* router datapath has a logical port with redirect-type set to bridged. */
    bool redirect_bridged;

    struct ovn_port **localnet_ports;
    size_t n_localnet_ports;

    struct ovs_list lr_list; /* In list of logical router datapaths. */
    /* The logical router group to which this datapath belongs.
     * Valid only if it is logical router datapath. NULL otherwise. */
    struct lrouter_group *lr_group;

    /* Map of ovn_port objects belonging to this datapath.
     * This map doesn't include derived ports. */
    struct hmap ports;
};

const struct ovn_datapath *ovn_datapath_find(const struct hmap *datapaths,
                                             const struct uuid *uuid);
static inline struct ovn_datapath *
ovn_datapaths_find_by_index(const struct ovn_datapaths *ovn_datapaths,
                            size_t od_index)
{
    ovs_assert(od_index <= hmap_count(&ovn_datapaths->datapaths));
    return ovn_datapaths->array[od_index];
}

struct ovn_datapath *ovn_datapath_from_sbrec(
    const struct hmap *ls_datapaths, const struct hmap *lr_datapaths,
    const struct sbrec_datapath_binding *);

static inline bool
ovn_datapath_is_stale(const struct ovn_datapath *od)
{
    return !od->nbr && !od->nbs;
};

/* Pipeline stages. */

/* The two purposes for which ovn-northd uses OVN logical datapaths. */
enum ovn_datapath_type {
    DP_SWITCH,                  /* OVN logical switch. */
    DP_ROUTER                   /* OVN logical router. */
};

/* Returns an "enum ovn_stage" built from the arguments.
 *
 * (It's better to use ovn_stage_build() for type-safety reasons, but inline
 * functions can't be used in enums or switch cases.) */
#define OVN_STAGE_BUILD(DP_TYPE, PIPELINE, TABLE) \
    (((DP_TYPE) << 9) | ((PIPELINE) << 8) | (TABLE))

/* A stage within an OVN logical switch or router.
 *
 * An "enum ovn_stage" indicates whether the stage is part of a logical switch
 * or router, whether the stage is part of the ingress or egress pipeline, and
 * the table within that pipeline.  The first three components are combined to
 * form the stage's full name, e.g. S_SWITCH_IN_PORT_SEC_L2,
 * S_ROUTER_OUT_DELIVERY. */
enum ovn_stage {
#define PIPELINE_STAGES                                                   \
    /* Logical switch ingress stages. */                                  \
    PIPELINE_STAGE(SWITCH, IN,  CHECK_PORT_SEC, 0, "ls_in_check_port_sec")   \
    PIPELINE_STAGE(SWITCH, IN,  APPLY_PORT_SEC, 1, "ls_in_apply_port_sec")   \
    PIPELINE_STAGE(SWITCH, IN,  LOOKUP_FDB ,    2, "ls_in_lookup_fdb")    \
    PIPELINE_STAGE(SWITCH, IN,  PUT_FDB,        3, "ls_in_put_fdb")       \
    PIPELINE_STAGE(SWITCH, IN,  PRE_ACL,        4, "ls_in_pre_acl")       \
    PIPELINE_STAGE(SWITCH, IN,  PRE_LB,         5, "ls_in_pre_lb")        \
    PIPELINE_STAGE(SWITCH, IN,  PRE_STATEFUL,   6, "ls_in_pre_stateful")  \
    PIPELINE_STAGE(SWITCH, IN,  ACL_HINT,       7, "ls_in_acl_hint")      \
    PIPELINE_STAGE(SWITCH, IN,  ACL_EVAL,       8, "ls_in_acl_eval")      \
    PIPELINE_STAGE(SWITCH, IN,  ACL_SAMPLE,     9, "ls_in_acl_sample")    \
    PIPELINE_STAGE(SWITCH, IN,  ACL_ACTION,    10, "ls_in_acl_action")    \
    PIPELINE_STAGE(SWITCH, IN,  QOS,           11, "ls_in_qos")    \
    PIPELINE_STAGE(SWITCH, IN,  LB_AFF_CHECK,  12, "ls_in_lb_aff_check")  \
    PIPELINE_STAGE(SWITCH, IN,  LB,            13, "ls_in_lb")            \
    PIPELINE_STAGE(SWITCH, IN,  LB_AFF_LEARN,  14, "ls_in_lb_aff_learn")  \
    PIPELINE_STAGE(SWITCH, IN,  PRE_HAIRPIN,   15, "ls_in_pre_hairpin")   \
    PIPELINE_STAGE(SWITCH, IN,  NAT_HAIRPIN,   16, "ls_in_nat_hairpin")   \
    PIPELINE_STAGE(SWITCH, IN,  HAIRPIN,       17, "ls_in_hairpin")       \
    PIPELINE_STAGE(SWITCH, IN,  ACL_AFTER_LB_EVAL,  18, \
                   "ls_in_acl_after_lb_eval")                             \
     PIPELINE_STAGE(SWITCH, IN,  ACL_AFTER_LB_SAMPLE,  19, \
                   "ls_in_acl_after_lb_sample")  \
    PIPELINE_STAGE(SWITCH, IN,  ACL_AFTER_LB_ACTION,  20, \
                   "ls_in_acl_after_lb_action")  \
    PIPELINE_STAGE(SWITCH, IN,  STATEFUL,      21, "ls_in_stateful")      \
    PIPELINE_STAGE(SWITCH, IN,  ARP_ND_RSP,    22, "ls_in_arp_rsp")       \
    PIPELINE_STAGE(SWITCH, IN,  DHCP_OPTIONS,  23, "ls_in_dhcp_options")  \
    PIPELINE_STAGE(SWITCH, IN,  DHCP_RESPONSE, 24, "ls_in_dhcp_response") \
    PIPELINE_STAGE(SWITCH, IN,  DNS_LOOKUP,    25, "ls_in_dns_lookup")    \
    PIPELINE_STAGE(SWITCH, IN,  DNS_RESPONSE,  26, "ls_in_dns_response")  \
    PIPELINE_STAGE(SWITCH, IN,  EXTERNAL_PORT, 27, "ls_in_external_port") \
    PIPELINE_STAGE(SWITCH, IN,  L2_LKUP,       28, "ls_in_l2_lkup")       \
    PIPELINE_STAGE(SWITCH, IN,  L2_UNKNOWN,    29, "ls_in_l2_unknown")    \
                                                                          \
    /* Logical switch egress stages. */                                   \
    PIPELINE_STAGE(SWITCH, OUT, PRE_ACL,      0, "ls_out_pre_acl")        \
    PIPELINE_STAGE(SWITCH, OUT, PRE_LB,       1, "ls_out_pre_lb")         \
    PIPELINE_STAGE(SWITCH, OUT, PRE_STATEFUL, 2, "ls_out_pre_stateful")   \
    PIPELINE_STAGE(SWITCH, OUT, ACL_HINT,     3, "ls_out_acl_hint")       \
    PIPELINE_STAGE(SWITCH, OUT, ACL_EVAL,     4, "ls_out_acl_eval")       \
    PIPELINE_STAGE(SWITCH, OUT, ACL_SAMPLE,   5, "ls_out_acl_sample")     \
    PIPELINE_STAGE(SWITCH, OUT, ACL_ACTION,   6, "ls_out_acl_action")     \
    PIPELINE_STAGE(SWITCH, OUT, QOS,          7, "ls_out_qos")       \
    PIPELINE_STAGE(SWITCH, OUT, STATEFUL,     8, "ls_out_stateful")       \
    PIPELINE_STAGE(SWITCH, OUT, CHECK_PORT_SEC,  9, "ls_out_check_port_sec") \
    PIPELINE_STAGE(SWITCH, OUT, APPLY_PORT_SEC, 10, "ls_out_apply_port_sec") \
                                                                      \
    /* Logical router ingress stages. */                              \
    PIPELINE_STAGE(ROUTER, IN,  ADMISSION,       0, "lr_in_admission")    \
    PIPELINE_STAGE(ROUTER, IN,  LOOKUP_NEIGHBOR, 1, "lr_in_lookup_neighbor") \
    PIPELINE_STAGE(ROUTER, IN,  LEARN_NEIGHBOR,  2, "lr_in_learn_neighbor") \
    PIPELINE_STAGE(ROUTER, IN,  IP_INPUT,        3, "lr_in_ip_input")     \
    PIPELINE_STAGE(ROUTER, IN,  DHCP_RELAY_REQ,  4, "lr_in_dhcp_relay_req") \
    PIPELINE_STAGE(ROUTER, IN,  UNSNAT,          5, "lr_in_unsnat")       \
    PIPELINE_STAGE(ROUTER, IN,  DEFRAG,          6, "lr_in_defrag")       \
    PIPELINE_STAGE(ROUTER, IN,  LB_AFF_CHECK,    7, "lr_in_lb_aff_check") \
    PIPELINE_STAGE(ROUTER, IN,  DNAT,            8, "lr_in_dnat")         \
    PIPELINE_STAGE(ROUTER, IN,  LB_AFF_LEARN,    9, "lr_in_lb_aff_learn") \
    PIPELINE_STAGE(ROUTER, IN,  ECMP_STATEFUL,   10, "lr_in_ecmp_stateful") \
    PIPELINE_STAGE(ROUTER, IN,  ND_RA_OPTIONS,   11, "lr_in_nd_ra_options") \
    PIPELINE_STAGE(ROUTER, IN,  ND_RA_RESPONSE,  12, "lr_in_nd_ra_response") \
    PIPELINE_STAGE(ROUTER, IN,  IP_ROUTING_PRE,  13, "lr_in_ip_routing_pre")  \
    PIPELINE_STAGE(ROUTER, IN,  IP_ROUTING,      14, "lr_in_ip_routing")      \
    PIPELINE_STAGE(ROUTER, IN,  IP_ROUTING_ECMP, 15, "lr_in_ip_routing_ecmp") \
    PIPELINE_STAGE(ROUTER, IN,  POLICY,          16, "lr_in_policy")          \
    PIPELINE_STAGE(ROUTER, IN,  POLICY_ECMP,     17, "lr_in_policy_ecmp")     \
    PIPELINE_STAGE(ROUTER, IN,  DHCP_RELAY_RESP_CHK, 18,                      \
                  "lr_in_dhcp_relay_resp_chk")                                \
    PIPELINE_STAGE(ROUTER, IN,  DHCP_RELAY_RESP, 19,                          \
                  "lr_in_dhcp_relay_resp")                                    \
    PIPELINE_STAGE(ROUTER, IN,  ARP_RESOLVE,     20, "lr_in_arp_resolve")     \
    PIPELINE_STAGE(ROUTER, IN,  CHK_PKT_LEN,     21, "lr_in_chk_pkt_len")     \
    PIPELINE_STAGE(ROUTER, IN,  LARGER_PKTS,     22, "lr_in_larger_pkts")     \
    PIPELINE_STAGE(ROUTER, IN,  GW_REDIRECT,     23, "lr_in_gw_redirect")     \
    PIPELINE_STAGE(ROUTER, IN,  ARP_REQUEST,     24, "lr_in_arp_request")     \
                                                                      \
    /* Logical router egress stages. */                               \
    PIPELINE_STAGE(ROUTER, OUT, CHECK_DNAT_LOCAL,   0,                       \
                   "lr_out_chk_dnat_local")                                  \
    PIPELINE_STAGE(ROUTER, OUT, UNDNAT,             1, "lr_out_undnat")      \
    PIPELINE_STAGE(ROUTER, OUT, POST_UNDNAT,        2, "lr_out_post_undnat") \
    PIPELINE_STAGE(ROUTER, OUT, SNAT,               3, "lr_out_snat")        \
    PIPELINE_STAGE(ROUTER, OUT, POST_SNAT,          4, "lr_out_post_snat")   \
    PIPELINE_STAGE(ROUTER, OUT, EGR_LOOP,           5, "lr_out_egr_loop")    \
    PIPELINE_STAGE(ROUTER, OUT, DELIVERY,           6, "lr_out_delivery")

#define PIPELINE_STAGE(DP_TYPE, PIPELINE, STAGE, TABLE, NAME)   \
    S_##DP_TYPE##_##PIPELINE##_##STAGE                          \
        = OVN_STAGE_BUILD(DP_##DP_TYPE, P_##PIPELINE, TABLE),
    PIPELINE_STAGES
#undef PIPELINE_STAGE
};

enum ovn_datapath_type ovn_stage_to_datapath_type(enum ovn_stage stage);


/* Returns 'od''s datapath type. */
static inline enum ovn_datapath_type
ovn_datapath_get_type(const struct ovn_datapath *od)
{
    return od->nbs ? DP_SWITCH : DP_ROUTER;
}

/* Returns an "enum ovn_stage" built from the arguments. */
static inline enum ovn_stage
ovn_stage_build(enum ovn_datapath_type dp_type, enum ovn_pipeline pipeline,
                uint8_t table)
{
    return OVN_STAGE_BUILD(dp_type, pipeline, table);
}

/* Returns the pipeline to which 'stage' belongs. */
static inline enum ovn_pipeline
ovn_stage_get_pipeline(enum ovn_stage stage)
{
    return (stage >> 8) & 1;
}

/* Returns the pipeline name to which 'stage' belongs. */
static inline const char *
ovn_stage_get_pipeline_name(enum ovn_stage stage)
{
    return ovn_stage_get_pipeline(stage) == P_IN ? "ingress" : "egress";
}

/* Returns the table to which 'stage' belongs. */
static inline uint8_t
ovn_stage_get_table(enum ovn_stage stage)
{
    return stage & 0xff;
}

/* Returns a string name for 'stage'. */
static inline const char *
ovn_stage_to_str(enum ovn_stage stage)
{
    switch (stage) {
#define PIPELINE_STAGE(DP_TYPE, PIPELINE, STAGE, TABLE, NAME)       \
        case S_##DP_TYPE##_##PIPELINE##_##STAGE: return NAME;
    PIPELINE_STAGES
#undef PIPELINE_STAGE
        default: return "<unknown>";
    }
}

/* A logical switch port or logical router port.
 *
 * In steady state, an ovn_port points to a northbound Logical_Switch_Port
 * record (via 'nbsp') *or* a Logical_Router_Port record (via 'nbrp'), and to a
 * southbound Port_Binding record (via 'sb').  As the state of the system
 * changes, join_logical_ports() may determine that there is a new LSP or LRP
 * that has no corresponding Port_Binding record (in which case build_ports())
 * will create the missing Port_Binding) or that a Port_Binding record exists
 * that has no coresponding LSP (in which case build_ports() will delete the
 * spurious Port_Binding).  Thus, after build_ports() runs, any given ovn_port
 * will have 'sb' nonnull, and 'nbsp' xor 'nbrp' nonnull.
 *
 * Ordinarily there is only one ovn_port that points to a given LSP or LRP (but
 * distributed gateway ports point a "derived" ovn_port to a duplicate LRP).
 */
struct ovn_port {
    /* Port name aka key.
     *
     * This is ordinarily the same as nbsp->name or nbrp->name and
     * sb->logical_port.  (A distributed gateway port creates a "derived"
     * ovn_port with key "cr-%s" % nbrp->name.) */
    struct hmap_node key_node;  /* Index on 'key'. */
    char *key;                  /* nbsp->name, nbrp->name, sb->logical_port. */
    char *json_key;             /* 'key', quoted for use in JSON. */

    const struct sbrec_port_binding *sb;         /* May be NULL. */

    uint32_t tunnel_key;

    /* Logical switch port data. */
    const struct nbrec_logical_switch_port *nbsp; /* May be NULL. */

    struct lport_addresses *lsp_addrs;  /* Logical switch port addresses. */
    unsigned int n_lsp_addrs;  /* Total length of lsp_addrs. */
    unsigned int n_lsp_non_router_addrs; /* Number of elements from the
                                          * beginning of 'lsp_addrs' extracted
                                          * directly from LSP 'addresses'. */

    struct lport_addresses *ps_addrs;   /* Port security addresses. */
    unsigned int n_ps_addrs;

    bool lsp_can_be_inc_processed; /* If it can be incrementally processed when
                                      the port changes. */

    /* Logical router port data. */
    const struct nbrec_logical_router_port *nbrp; /* May be NULL. */

    struct lport_addresses lrp_networks;

    /* Logical port multicast data. */
    struct mcast_port_info mcast_info;

    /* At most one of primary_port and cr_port can be not NULL. */

    /* If this ovn_port is a derived port, then 'primary_port' points to the
     * port from which this ovn_port is derived. */
    struct ovn_port *primary_port;

    /* This is set to the "derived" chassis-redirect port of this port if and
     * only if this port is a distributed gateway port. Otherwise this is set
     * to NULL. */
    struct ovn_port *cr_port;

    bool has_unknown; /* If the addresses have 'unknown' defined. */

    /* The port's peer:
     *
     *     - A switch port S of type "router" has a router port R as a peer,
     *       and R in turn has S has its peer.
     *
     *     - Two connected logical router ports have each other as peer.
     *
     *     - Other kinds of ports have no peer. */
    struct ovn_port *peer;

    struct ovn_datapath *od;

    struct ovs_list list;       /* In list of similar records. */

    struct hmap_node dp_node;   /* Node in od->ports. */

    struct lport_addresses proxy_arp_addrs;

    /* Temporarily used for traversing a list (or hmap) of ports. */
    bool visited;

    /* Only used for the router type LSP whose peer is l3dgw_port */
    bool enable_router_port_acl;

    /* Reference of lflows generated for this ovn_port.
     *
     * This data is initialized and destroyed by the en_northd node, but
     * populated and used only by the en_lflow node. Ideally this data should
     * be maintained as part of en_lflow's data (struct lflow_data): a hash
     * index from ovn_port key to lflows.  However, it would be less efficient
     * and more complex:
     *
     * 1. It would require an extra search (using the index) to find the
     * lflows.
     *
     * 2. Building the index needs to be thread-safe, using either a global
     * lock which is obviously less efficient, or hash-based lock array which
     * is more complex.
     *
     * Adding the list here is more straightforward. The drawback is that we
     * need to keep in mind that this data belongs to en_lflow node, so never
     * access it from any other nodes.
     *
     * 'lflow_ref' is used to reference generic logical flows generated for
     *  this ovn_port.
     *
     * 'stateful_lflow_ref' is used for logical switch ports of type
     * 'patch/router' to reference logical flows generated fo this ovn_port
     *  from the 'lr_stateful' record of the peer port's datapath.
     *
     * Note: lflow_ref and stateful_lflow_ref are not thread safe.  Only one
     * thread should access ovn_ports->lflow_ref/stateful_lflow_ref at any
     * given time.
     */
    struct lflow_ref *lflow_ref;
    struct lflow_ref *stateful_lflow_ref;
};

struct parsed_route {
    struct hmap_node key_node;
    struct in6_addr prefix;
    unsigned int plen;
    bool is_src_route;
    uint32_t route_table_id;
    uint32_t hash;
    const struct nbrec_logical_router_static_route *route;
    bool ecmp_symmetric_reply;
    bool is_discard_route;
    const struct nbrec_logical_router *nbr;
    bool stale;
};

void ovnnb_db_run(struct northd_input *input_data,
                  struct northd_data *data,
                  struct ovsdb_idl_txn *ovnnb_txn,
                  struct ovsdb_idl_txn *ovnsb_txn);
void ovnsb_db_run(struct ovsdb_idl_txn *ovnnb_txn,
                  struct ovsdb_idl_txn *ovnsb_txn,
                  const struct sbrec_port_binding_table *,
                  const struct sbrec_ha_chassis_group_table *,
                  struct hmap *ls_ports,
                  struct hmap *lr_ports);
bool northd_handle_ls_changes(struct ovsdb_idl_txn *,
                              const struct northd_input *,
                              struct northd_data *);
bool northd_handle_lr_changes(const struct northd_input *,
                              struct northd_data *);
void destroy_northd_data_tracked_changes(struct northd_data *);
void northd_destroy(struct northd_data *data);
void northd_init(struct northd_data *data);
void northd_indices_create(struct northd_data *data,
                           struct ovsdb_idl *ovnsb_idl);

void route_policies_init(struct route_policies_data *);
void route_policies_destroy(struct route_policies_data *);
void build_parsed_routes(struct ovn_datapath *, const struct hmap *,
                         const struct hmap *, struct hmap *, struct simap *,
                         struct hmap *);
uint32_t get_route_table_id(struct simap *, const char *);
void static_routes_init(struct static_routes_data *);
void static_routes_destroy(struct static_routes_data *);

void bfd_init(struct bfd_data *);
void bfd_destroy(struct bfd_data *);

void bfd_sync_init(struct bfd_sync_data *);
void bfd_sync_destroy(struct bfd_sync_data *);

void build_ecmp_nexthop_table(struct ovsdb_idl_txn *,
                              struct hmap *, struct simap *,
                              const struct sbrec_ecmp_nexthop_table *);
void ecmp_nexthop_init(struct ecmp_nexthop_data *);
void ecmp_nexthop_destroy(struct ecmp_nexthop_data *);

struct lflow_table;
struct lr_stateful_tracked_data;
struct ls_stateful_tracked_data;

void build_lflows(struct ovsdb_idl_txn *ovnsb_txn,
                  struct lflow_input *input_data,
                  struct lflow_table *);
void lflow_reset_northd_refs(struct lflow_input *);

bool lflow_handle_northd_port_changes(struct ovsdb_idl_txn *ovnsb_txn,
                                      struct tracked_ovn_ports *,
                                      struct lflow_input *,
                                      struct lflow_table *lflows);
bool lflow_handle_northd_lb_changes(struct ovsdb_idl_txn *ovnsb_txn,
                                    struct tracked_lbs *,
                                    struct lflow_input *,
                                    struct lflow_table *lflows);
bool lflow_handle_lr_stateful_changes(struct ovsdb_idl_txn *,
                                      struct lr_stateful_tracked_data *,
                                      struct lflow_input *,
                                      struct lflow_table *lflows);
bool lflow_handle_ls_stateful_changes(struct ovsdb_idl_txn *,
                                      struct ls_stateful_tracked_data *,
                                      struct lflow_input *,
                                      struct lflow_table *lflows);
bool northd_handle_sb_port_binding_changes(
    const struct sbrec_port_binding_table *, struct hmap *ls_ports,
    struct hmap *lr_ports);

struct tracked_lb_data;
bool northd_handle_lb_data_changes(struct tracked_lb_data *,
                                   struct ovn_datapaths *ls_datapaths,
                                   struct ovn_datapaths *lr_datapaths,
                                   struct hmap *lb_datapaths_map,
                                   struct hmap *lbgrp_datapaths_map,
                                   struct northd_tracked_data *);

void build_route_policies(struct ovn_datapath *, const struct hmap *,
                          const struct hmap *, struct hmap *, struct hmap *);
void bfd_table_sync(struct ovsdb_idl_txn *, const struct nbrec_bfd_table *,
                    const struct hmap *, const struct hmap *,
                    const struct hmap *, const struct hmap *,
                    struct sset *);
void build_bfd_map(const struct nbrec_bfd_table *,
                   const struct sbrec_bfd_table *, struct hmap *);
void run_update_worker_pool(int n_threads);

const struct ovn_datapath *northd_get_datapath_for_port(
    const struct hmap *ls_ports, const char *port_name);

struct lr_stateful_table;
void sync_pbs(struct ovsdb_idl_txn *, struct hmap *ls_ports,
              struct hmap *lr_ports,
              const struct lr_stateful_table *);
bool sync_pbs_for_northd_changed_ovn_ports(
    struct tracked_ovn_ports *,
    const struct lr_stateful_table *);

static inline bool
northd_has_tracked_data(struct northd_tracked_data *trk_nd_changes) {
    return trk_nd_changes->type != NORTHD_TRACKED_NONE;
}

static inline bool
northd_has_lbs_in_tracked_data(struct northd_tracked_data *trk_nd_changes)
{
    return trk_nd_changes->type & NORTHD_TRACKED_LBS;
}

static inline bool
northd_has_lsps_in_tracked_data(struct northd_tracked_data *trk_nd_changes)
{
    return trk_nd_changes->type & NORTHD_TRACKED_PORTS;
}

static inline bool
northd_has_lr_nats_in_tracked_data(struct northd_tracked_data *trk_nd_changes)
{
    return trk_nd_changes->type & NORTHD_TRACKED_LR_NATS;
}

static inline bool
northd_has_ls_lbs_in_tracked_data(struct northd_tracked_data *trk_nd_changes)
{
    return trk_nd_changes->type & NORTHD_TRACKED_LS_LBS;
}

static inline bool
northd_has_ls_acls_in_tracked_data(struct northd_tracked_data *trk_nd_changes)
{
    return trk_nd_changes->type & NORTHD_TRACKED_LS_ACLS;
}

/* Returns 'true' if the IPv4 'addr' is on the same subnet with one of the
 * IPs configured on the router port.
 */
bool lrouter_port_ipv4_reachable(const struct ovn_port *, ovs_be32 addr);

/* Returns 'true' if the IPv6 'addr' is on the same subnet with one of the
 * IPs configured on the router port.
 */
bool lrouter_port_ipv6_reachable(const struct ovn_port *,
                                 const struct in6_addr *);

static inline bool
lr_has_multiple_gw_ports(const struct ovn_datapath *od)
{
    return od->n_l3dgw_ports > 1 && !od->is_gw_router;
}

bool
is_vxlan_mode(const struct smap *nb_options,
              const struct sbrec_chassis_table *sbrec_chassis_table);

uint32_t get_ovn_max_dp_key_local(bool _vxlan_mode);

#endif /* NORTHD_H */
