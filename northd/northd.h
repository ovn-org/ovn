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

struct northd_input {
    /* Northbound table references */
    const struct nbrec_nb_global_table *nbrec_nb_global_table;
    const struct nbrec_logical_switch_table *nbrec_logical_switch_table;
    const struct nbrec_logical_router_table *nbrec_logical_router_table;
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

    /* Indexes */
    struct ovsdb_idl_index *sbrec_chassis_by_name;
    struct ovsdb_idl_index *sbrec_chassis_by_hostname;
    struct ovsdb_idl_index *sbrec_ha_chassis_grp_by_name;
    struct ovsdb_idl_index *sbrec_ip_mcast_by_dp;
    struct ovsdb_idl_index *sbrec_static_mac_binding_by_lport_ip;
    struct ovsdb_idl_index *sbrec_fdb_by_dp_and_port;
};

struct chassis_features {
    bool ct_no_masked_label;
    bool mac_binding_timestamp;
    bool ct_lb_related;
    bool fdb_timestamp;
};

/* A collection of datapaths. E.g. all logical switch datapaths, or all
 * logical router datapaths. */
struct ovn_datapaths {
    /* Contains struct ovn_datapath elements. */
    struct hmap datapaths;

    /* The array index of each element in 'datapaths'. */
    struct ovn_datapath **array;
};

/* Track what's changed for a single LS.
 * Now only track port changes. */
struct ls_change {
    struct ovs_list list_node;
    struct ovn_datapath *od;
    struct ovs_list added_ports;
    struct ovs_list deleted_ports;
    struct ovs_list updated_ports;
    bool had_only_router_ports;
};

/* Track what's changed for logical switches.
 * Now only track updated ones (added or deleted may be supported in the
 * future). */
struct tracked_ls_changes {
    struct ovs_list updated; /* Contains struct ls_change */
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
    bool ovn_internal_version_changed;
    struct chassis_features features;
    struct sset svc_monitor_lsps;
    struct hmap svc_monitor_map;
    bool change_tracked;
    struct tracked_ls_changes tracked_ls_changes;
};

struct lflow_data {
    struct hmap lflows;
};

void lflow_data_init(struct lflow_data *);
void lflow_data_destroy(struct lflow_data *);

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

    const struct ovn_datapaths *ls_datapaths;
    const struct ovn_datapaths *lr_datapaths;
    const struct hmap *ls_ports;
    const struct hmap *lr_ports;
    const struct ls_port_group_table *ls_port_groups;
    const struct shash *meter_groups;
    const struct hmap *lb_datapaths_map;
    const struct hmap *bfd_connections;
    const struct chassis_features *features;
    const struct hmap *svc_monitor_map;
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
    uint64_t max_acl_tier;
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

    /* Map of ovn_port objects belonging to this datapath.
     * This map doesn't include derived ports. */
    struct hmap ports;
};

void ovnnb_db_run(struct northd_input *input_data,
                  struct northd_data *data,
                  struct ovsdb_idl_txn *ovnnb_txn,
                  struct ovsdb_idl_txn *ovnsb_txn);
void ovnsb_db_run(struct ovsdb_idl_txn *ovnnb_txn,
                  struct ovsdb_idl_txn *ovnsb_txn,
                  const struct sbrec_port_binding_table *,
                  const struct sbrec_ha_chassis_group_table *,
                  struct ovsdb_idl_index *sb_ha_ch_grp_by_name,
                  struct hmap *ls_ports,
                  struct hmap *lr_ports);
bool northd_handle_ls_changes(struct ovsdb_idl_txn *,
                              const struct northd_input *,
                              struct northd_data *);
void destroy_northd_data_tracked_changes(struct northd_data *);
void northd_destroy(struct northd_data *data);
void northd_init(struct northd_data *data);
void northd_indices_create(struct northd_data *data,
                           struct ovsdb_idl *ovnsb_idl);
void build_lflows(struct ovsdb_idl_txn *ovnsb_txn,
                  struct lflow_input *input_data,
                  struct hmap *lflows);
bool lflow_handle_northd_ls_changes(struct ovsdb_idl_txn *ovnsb_txn,
                                    struct tracked_ls_changes *,
                                    struct lflow_input *, struct hmap *lflows);
bool northd_handle_sb_port_binding_changes(
    const struct sbrec_port_binding_table *, struct hmap *ls_ports);

struct tracked_lb_data;
bool northd_handle_lb_data_changes(struct tracked_lb_data *,
                                   struct ovn_datapaths *ls_datapaths,
                                   struct ovn_datapaths *lr_datapaths,
                                   struct hmap *lb_datapaths_map,
                                   struct hmap *lb_group_datapaths_map);

void build_bfd_table(struct ovsdb_idl_txn *ovnsb_txn,
                     const struct nbrec_bfd_table *,
                     const struct sbrec_bfd_table *,
                     const struct hmap *lr_ports,
                     struct hmap *bfd_connections);
void bfd_cleanup_connections(const struct nbrec_bfd_table *,
                             struct hmap *bfd_map);
void run_update_worker_pool(int n_threads);

const char *northd_get_svc_monitor_mac(void);

const struct ovn_datapath *northd_get_datapath_for_port(
    const struct hmap *ls_ports, const char *port_name);
void sync_lbs(struct ovsdb_idl_txn *, const struct sbrec_load_balancer_table *,
              struct ovn_datapaths *ls_datapaths, struct hmap *lbs);

#endif /* NORTHD_H */
