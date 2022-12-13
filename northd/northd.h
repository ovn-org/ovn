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

#include "lib/ovn-util.h"
#include "lib/ovs-atomic.h"
#include "lib/sset.h"
#include "northd/ipam.h"
#include "openvswitch/hmap.h"

struct northd_input {
    /* Northbound table references */
    const struct nbrec_nb_global_table *nbrec_nb_global_table;
    const struct nbrec_logical_switch_table *nbrec_logical_switch;
    const struct nbrec_logical_router_table *nbrec_logical_router;
    const struct nbrec_load_balancer_table *nbrec_load_balancer_table;
    const struct nbrec_load_balancer_group_table
        *nbrec_load_balancer_group_table;
    const struct nbrec_port_group_table *nbrec_port_group_table;
    const struct nbrec_meter_table *nbrec_meter_table;
    const struct nbrec_acl_table *nbrec_acl_table;
    const struct nbrec_static_mac_binding_table
        *nbrec_static_mac_binding_table;
    const struct nbrec_chassis_template_var_table
        *nbrec_chassis_template_var_table;
    const struct nbrec_mirror_table *nbrec_mirror_table;

    /* Southbound table references */
    const struct sbrec_sb_global_table *sbrec_sb_global_table;
    const struct sbrec_datapath_binding_table *sbrec_datapath_binding_table;
    const struct sbrec_port_binding_table *sbrec_port_binding_table;
    const struct sbrec_mac_binding_table *sbrec_mac_binding_table;
    const struct sbrec_ha_chassis_group_table *sbrec_ha_chassis_group_table;
    const struct sbrec_chassis_table *sbrec_chassis;
    const struct sbrec_fdb_table *sbrec_fdb_table;
    const struct sbrec_load_balancer_table *sbrec_load_balancer_table;
    const struct sbrec_service_monitor_table *sbrec_service_monitor_table;
    const struct sbrec_port_group_table *sbrec_port_group_table;
    const struct sbrec_meter_table *sbrec_meter_table;
    const struct sbrec_dns_table *sbrec_dns_table;
    const struct sbrec_ip_multicast_table *sbrec_ip_multicast_table;
    const struct sbrec_chassis_private_table *sbrec_chassis_private_table;
    const struct sbrec_static_mac_binding_table
        *sbrec_static_mac_binding_table;
    const struct sbrec_chassis_template_var_table
        *sbrec_chassis_template_var_table;
    const struct sbrec_mirror_table *sbrec_mirror_table;

    /* Indexes */
    struct ovsdb_idl_index *sbrec_chassis_by_name;
    struct ovsdb_idl_index *sbrec_chassis_by_hostname;
    struct ovsdb_idl_index *sbrec_ha_chassis_grp_by_name;
    struct ovsdb_idl_index *sbrec_ip_mcast_by_dp;
    struct ovsdb_idl_index *sbrec_static_mac_binding_by_lport_ip;
};

struct chassis_features {
    bool ct_no_masked_label;
    bool mac_binding_timestamp;
};

struct northd_data {
    /* Global state for 'en-northd'. */
    struct hmap datapaths;
    struct hmap ports;
    struct hmap port_groups;
    struct shash meter_groups;
    struct hmap lbs;
    struct hmap lb_groups;
    struct hmap bfd_connections;
    struct ovs_list lr_list;
    bool ovn_internal_version_changed;
    struct chassis_features features;
};

struct lflow_input {
    /* Northbound table references */
    const struct nbrec_bfd_table *nbrec_bfd_table;

    /* Southbound table references */
    const struct sbrec_bfd_table *sbrec_bfd_table;
    const struct sbrec_logical_flow_table *sbrec_logical_flow_table;
    const struct sbrec_multicast_group_table *sbrec_multicast_group_table;
    const struct sbrec_igmp_group_table *sbrec_igmp_group_table;

    /* Indexes */
    struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp;

    const struct hmap *datapaths;
    const struct hmap *ports;
    const struct hmap *port_groups;
    const struct shash *meter_groups;
    const struct hmap *lbs;
    const struct hmap *bfd_connections;
    const struct chassis_features *features;
    bool ovn_internal_version_changed;
};

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

    const struct nbrec_logical_switch *nbs;  /* May be NULL. */
    const struct nbrec_logical_router *nbr;  /* May be NULL. */
    const struct sbrec_datapath_binding *sb; /* May be NULL. */

    struct ovs_list list;       /* In list of similar records. */

    uint32_t tunnel_key;

    /* Logical router data. */
    struct ovn_datapath **ls_peers;
    size_t n_ls_peers;
    size_t n_allocated_ls_peers;

    /* Logical switch data. */
    struct ovn_port **router_ports;
    size_t n_router_ports;
    size_t n_allocated_router_ports;

    struct hmap port_tnlids;
    uint32_t port_key_hint;

    bool has_stateful_acl;
    bool has_lb_vip;
    bool has_unknown;
    bool has_acls;
    bool has_vtep_lports;

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

    /* NAT entries configured on the router. */
    struct ovn_nat *nat_entries;
    size_t n_nat_entries;

    bool has_distributed_nat;
    /* router datapath has a logical port with redirect-type set to bridged. */
    bool redirect_bridged;

    /* Set of nat external ips on the router. */
    struct sset external_ips;

    /* SNAT IPs owned by the router (shash of 'struct ovn_snat_ip'). */
    struct shash snat_ips;

    struct lport_addresses dnat_force_snat_addrs;
    struct lport_addresses lb_force_snat_addrs;
    bool lb_force_snat_router_ip;

    /* Load Balancer vIPs relevant for this datapath. */
    struct ovn_lb_ip_set *lb_ips;

    struct ovn_port **localnet_ports;
    size_t n_localnet_ports;

    struct ovs_list lr_list; /* In list of logical router datapaths. */
    /* The logical router group to which this datapath belongs.
     * Valid only if it is logical router datapath. NULL otherwise. */
    struct lrouter_group *lr_group;

    /* Port groups related to the datapath, used only when nbs is NOT NULL. */
    struct hmap nb_pgs;

    struct ovs_list port_list;
};

void northd_run(struct northd_input *input_data,
                struct northd_data *data,
                struct ovsdb_idl_txn *ovnnb_txn,
                struct ovsdb_idl_txn *ovnsb_txn);
void northd_destroy(struct northd_data *data);
void northd_init(struct northd_data *data);
void northd_indices_create(struct northd_data *data,
                           struct ovsdb_idl *ovnsb_idl);
void build_lflows(struct lflow_input *input_data,
                  struct ovsdb_idl_txn *ovnsb_txn);
void build_bfd_table(struct lflow_input *input_data,
                     struct ovsdb_idl_txn *ovnsb_txn,
                     struct hmap *bfd_connections, struct hmap *ports);
void bfd_cleanup_connections(struct lflow_input *input_data,
                             struct hmap *bfd_map);
void run_update_worker_pool(int n_threads);

const char *northd_get_svc_monitor_mac(void);
#endif /* NORTHD_H */
