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

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "chassis-index.h"
#include "ip-mcast-index.h"
#include "static-mac-binding-index.h"
#include "lib/inc-proc-eng.h"
#include "lib/mac-binding-index.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "mcast-group-index.h"
#include "northd/mac-binding-aging.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "inc-proc-northd.h"
#include "en-northd.h"
#include "en-lflow.h"
#include "en-northd-output.h"
#include "en-sync-sb.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(inc_proc_northd);

#define NB_NODES \
    NB_NODE(nb_global, "nb_global") \
    NB_NODE(copp, "copp") \
    NB_NODE(logical_switch, "logical_switch") \
    NB_NODE(logical_switch_port, "logical_switch_port") \
    NB_NODE(forwarding_group, "forwarding_group") \
    NB_NODE(address_set, "address_set") \
    NB_NODE(port_group, "port_group") \
    NB_NODE(load_balancer, "load_balancer") \
    NB_NODE(load_balancer_group, "load_balancer_group") \
    NB_NODE(load_balancer_health_check, "load_balancer_health_check") \
    NB_NODE(acl, "acl") \
    NB_NODE(logical_router, "logical_router") \
    NB_NODE(qos, "qos") \
    NB_NODE(mirror, "mirror") \
    NB_NODE(meter, "meter") \
    NB_NODE(meter_band, "meter_band") \
    NB_NODE(logical_router_port, "logical_router_port") \
    NB_NODE(logical_router_static_route, "logical_router_static_route") \
    NB_NODE(logical_router_policy, "logical_router_policy") \
    NB_NODE(nat, "nat") \
    NB_NODE(dhcp_options, "dhcp_options") \
    NB_NODE(connection, "connection") \
    NB_NODE(dns, "dns") \
    NB_NODE(ssl, "ssl") \
    NB_NODE(gateway_chassis, "gateway_chassis") \
    NB_NODE(ha_chassis_group, "ha_chassis_group") \
    NB_NODE(ha_chassis, "ha_chassis") \
    NB_NODE(bfd, "bfd") \
    NB_NODE(static_mac_binding, "static_mac_binding") \
    NB_NODE(chassis_template_var, "chassis_template_var")

    enum nb_engine_node {
#define NB_NODE(NAME, NAME_STR) NB_##NAME,
    NB_NODES
#undef NB_NODE
    };

/* Define engine node functions for nodes that represent NB tables
 *
 * en_nb_<TABLE_NAME>_run()
 * en_nb_<TABLE_NAME>_init()
 * en_nb_<TABLE_NAME>_cleanup()
 */
#define NB_NODE(NAME, NAME_STR) ENGINE_FUNC_NB(NAME);
    NB_NODES
#undef NB_NODE

#define SB_NODES \
    SB_NODE(sb_global, "sb_global") \
    SB_NODE(chassis, "chassis") \
    SB_NODE(chassis_private, "chassis_private") \
    SB_NODE(encap, "encap") \
    SB_NODE(address_set, "address_set") \
    SB_NODE(port_group, "port_group") \
    SB_NODE(logical_flow, "logical_flow") \
    SB_NODE(logical_dp_group, "logical_DP_group") \
    SB_NODE(multicast_group, "multicast_group") \
    SB_NODE(mirror, "mirror") \
    SB_NODE(meter, "meter") \
    SB_NODE(meter_band, "meter_band") \
    SB_NODE(datapath_binding, "datapath_binding") \
    SB_NODE(port_binding, "port_binding") \
    SB_NODE(mac_binding, "mac_binding") \
    SB_NODE(dhcp_options, "dhcp_options") \
    SB_NODE(dhcpv6_options, "dhcpv6_options") \
    SB_NODE(connection, "connection") \
    SB_NODE(ssl, "ssl") \
    SB_NODE(dns, "dns") \
    SB_NODE(rbac_role, "rbac_role") \
    SB_NODE(rbac_permission, "rbac_permission") \
    SB_NODE(gateway_chassis, "gateway_chassis") \
    SB_NODE(ha_chassis, "ha_chassis") \
    SB_NODE(ha_chassis_group, "ha_chassis_group") \
    SB_NODE(controller_event, "controller_event") \
    SB_NODE(ip_multicast, "ip_multicast") \
    SB_NODE(igmp_group, "igmp_group") \
    SB_NODE(service_monitor, "service_monitor") \
    SB_NODE(load_balancer, "load_balancer") \
    SB_NODE(bfd, "bfd") \
    SB_NODE(fdb, "fdb") \
    SB_NODE(static_mac_binding, "static_mac_binding") \
    SB_NODE(chassis_template_var, "chassis_template_var")

enum sb_engine_node {
#define SB_NODE(NAME, NAME_STR) SB_##NAME,
    SB_NODES
#undef SB_NODE
};

/* Define engine node functions for nodes that represent SB tables
 *
 * en_sb_<TABLE_NAME>_run()
 * en_sb_<TABLE_NAME>_init()
 * en_sb_<TABLE_NAME>_cleanup()
 */
#define SB_NODE(NAME, NAME_STR) ENGINE_FUNC_SB(NAME);
    SB_NODES
#undef SB_NODE

/* Define engine nodes for NB and SB tables
 *
 * struct engine_node en_nb_<TABLE_NAME>
 * struct engine_node en_sb_<TABLE_NAME>
 *
 * Define nodes as static to avoid sparse errors.
 */
#define NB_NODE(NAME, NAME_STR) static ENGINE_NODE_NB(NAME, NAME_STR);
    NB_NODES
#undef NB_NODE

#define SB_NODE(NAME, NAME_STR) static ENGINE_NODE_SB(NAME, NAME_STR);
    SB_NODES
#undef SB_NODE

/* Define engine nodes for other nodes. They should be defined as static to
 * avoid sparse errors. */
static ENGINE_NODE(northd, "northd");
static ENGINE_NODE(lflow, "lflow");
static ENGINE_NODE(mac_binding_aging, "mac_binding_aging");
static ENGINE_NODE(mac_binding_aging_waker, "mac_binding_aging_waker");
static ENGINE_NODE(northd_output, "northd_output");
static ENGINE_NODE(sync_to_sb, "sync_to_sb");
static ENGINE_NODE(sync_to_sb_addr_set, "sync_to_sb_addr_set");

void inc_proc_northd_init(struct ovsdb_idl_loop *nb,
                          struct ovsdb_idl_loop *sb)
{
    /* Define relationships between nodes where first argument is dependent
     * on the second argument */
    engine_add_input(&en_northd, &en_nb_nb_global, NULL);
    engine_add_input(&en_northd, &en_nb_copp, NULL);
    engine_add_input(&en_northd, &en_nb_logical_switch, NULL);
    engine_add_input(&en_northd, &en_nb_logical_switch_port, NULL);
    engine_add_input(&en_northd, &en_nb_forwarding_group, NULL);
    engine_add_input(&en_northd, &en_nb_port_group, NULL);
    engine_add_input(&en_northd, &en_nb_load_balancer, NULL);
    engine_add_input(&en_northd, &en_nb_load_balancer_group, NULL);
    engine_add_input(&en_northd, &en_nb_load_balancer_health_check, NULL);
    engine_add_input(&en_northd, &en_nb_acl, NULL);
    engine_add_input(&en_northd, &en_nb_logical_router, NULL);
    engine_add_input(&en_northd, &en_nb_qos, NULL);
    engine_add_input(&en_northd, &en_nb_mirror, NULL);
    engine_add_input(&en_northd, &en_nb_meter, NULL);
    engine_add_input(&en_northd, &en_nb_meter_band, NULL);
    engine_add_input(&en_northd, &en_nb_logical_router_port, NULL);
    engine_add_input(&en_northd, &en_nb_logical_router_static_route, NULL);
    engine_add_input(&en_northd, &en_nb_logical_router_policy, NULL);
    engine_add_input(&en_northd, &en_nb_nat, NULL);
    engine_add_input(&en_northd, &en_nb_dhcp_options, NULL);
    engine_add_input(&en_northd, &en_nb_connection, NULL);
    engine_add_input(&en_northd, &en_nb_dns, NULL);
    engine_add_input(&en_northd, &en_nb_ssl, NULL);
    engine_add_input(&en_northd, &en_nb_gateway_chassis, NULL);
    engine_add_input(&en_northd, &en_nb_ha_chassis_group, NULL);
    engine_add_input(&en_northd, &en_nb_ha_chassis, NULL);
    engine_add_input(&en_northd, &en_nb_static_mac_binding, NULL);
    engine_add_input(&en_northd, &en_nb_chassis_template_var, NULL);

    engine_add_input(&en_northd, &en_sb_sb_global, NULL);
    engine_add_input(&en_northd, &en_sb_chassis, NULL);
    engine_add_input(&en_northd, &en_sb_chassis_private, NULL);
    engine_add_input(&en_northd, &en_sb_encap, NULL);
    engine_add_input(&en_northd, &en_sb_port_group, NULL);
    engine_add_input(&en_northd, &en_sb_logical_dp_group, NULL);
    engine_add_input(&en_northd, &en_sb_mirror, NULL);
    engine_add_input(&en_northd, &en_sb_meter, NULL);
    engine_add_input(&en_northd, &en_sb_meter_band, NULL);
    engine_add_input(&en_northd, &en_sb_datapath_binding, NULL);
    engine_add_input(&en_northd, &en_sb_port_binding, NULL);
    engine_add_input(&en_northd, &en_sb_mac_binding, NULL);
    engine_add_input(&en_northd, &en_sb_dhcp_options, NULL);
    engine_add_input(&en_northd, &en_sb_dhcpv6_options, NULL);
    engine_add_input(&en_northd, &en_sb_connection, NULL);
    engine_add_input(&en_northd, &en_sb_ssl, NULL);
    engine_add_input(&en_northd, &en_sb_dns, NULL);
    engine_add_input(&en_northd, &en_sb_rbac_role, NULL);
    engine_add_input(&en_northd, &en_sb_rbac_permission, NULL);
    engine_add_input(&en_northd, &en_sb_gateway_chassis, NULL);
    engine_add_input(&en_northd, &en_sb_ha_chassis, NULL);
    engine_add_input(&en_northd, &en_sb_ha_chassis_group, NULL);
    engine_add_input(&en_northd, &en_sb_controller_event, NULL);
    engine_add_input(&en_northd, &en_sb_ip_multicast, NULL);
    engine_add_input(&en_northd, &en_sb_service_monitor, NULL);
    engine_add_input(&en_northd, &en_sb_load_balancer, NULL);
    engine_add_input(&en_northd, &en_sb_fdb, NULL);
    engine_add_input(&en_northd, &en_sb_static_mac_binding, NULL);
    engine_add_input(&en_northd, &en_sb_chassis_template_var, NULL);
    engine_add_input(&en_mac_binding_aging, &en_nb_nb_global, NULL);
    engine_add_input(&en_mac_binding_aging, &en_sb_mac_binding, NULL);
    engine_add_input(&en_mac_binding_aging, &en_northd, NULL);
    engine_add_input(&en_mac_binding_aging, &en_mac_binding_aging_waker, NULL);
    engine_add_input(&en_lflow, &en_nb_bfd, NULL);
    engine_add_input(&en_lflow, &en_sb_bfd, NULL);
    engine_add_input(&en_lflow, &en_sb_logical_flow, NULL);
    engine_add_input(&en_lflow, &en_sb_multicast_group, NULL);
    engine_add_input(&en_lflow, &en_sb_igmp_group, NULL);
    engine_add_input(&en_lflow, &en_northd, NULL);
    /* XXX: The "en_mac_binding_aging" should be separate "root" node
     * once I-P engine allows multiple root nodes. */
    engine_add_input(&en_lflow, &en_mac_binding_aging, NULL);

    engine_add_input(&en_sync_to_sb_addr_set, &en_nb_address_set,
                     sync_to_sb_addr_set_nb_address_set_handler);
    engine_add_input(&en_sync_to_sb_addr_set, &en_nb_port_group,
                     sync_to_sb_addr_set_nb_port_group_handler);
    engine_add_input(&en_sync_to_sb_addr_set, &en_northd, NULL);
    engine_add_input(&en_sync_to_sb_addr_set, &en_sb_address_set, NULL);

    /* en_sync_to_sb engine node syncs the SB database tables from
     * the NB database tables.
     * Right now this engine only syncs the SB Address_Set table.
     */
    engine_add_input(&en_sync_to_sb, &en_sync_to_sb_addr_set, NULL);
    engine_add_input(&en_northd_output, &en_sync_to_sb,
                     northd_output_sync_to_sb_handler);
    engine_add_input(&en_northd_output, &en_lflow,
                     northd_output_lflow_handler);

    struct engine_arg engine_arg = {
        .nb_idl = nb->idl,
        .sb_idl = sb->idl,
    };

    struct ovsdb_idl_index *sbrec_chassis_by_name =
                         chassis_index_create(sb->idl);
    struct ovsdb_idl_index *sbrec_ha_chassis_grp_by_name =
                         ha_chassis_group_index_create(sb->idl);
    struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp =
                         mcast_group_index_create(sb->idl);
    struct ovsdb_idl_index *sbrec_ip_mcast_by_dp =
                         ip_mcast_index_create(sb->idl);
    struct ovsdb_idl_index *sbrec_chassis_by_hostname =
        chassis_hostname_index_create(sb->idl);
    struct ovsdb_idl_index *sbrec_static_mac_binding_by_lport_ip
        = static_mac_binding_index_create(sb->idl);
    struct ovsdb_idl_index *sbrec_mac_binding_by_datapath
        = mac_binding_by_datapath_index_create(sb->idl);

    engine_init(&en_northd_output, &engine_arg);

    engine_ovsdb_node_add_index(&en_sb_chassis,
                                "sbrec_chassis_by_name",
                                sbrec_chassis_by_name);
    engine_ovsdb_node_add_index(&en_sb_chassis,
                                "sbrec_chassis_by_hostname",
                                sbrec_chassis_by_hostname);
    engine_ovsdb_node_add_index(&en_sb_ha_chassis_group,
                                "sbrec_ha_chassis_grp_by_name",
                                sbrec_ha_chassis_grp_by_name);
    engine_ovsdb_node_add_index(&en_sb_multicast_group,
                                "sbrec_mcast_group_by_name",
                                sbrec_mcast_group_by_name_dp);
    engine_ovsdb_node_add_index(&en_sb_ip_multicast,
                                "sbrec_ip_mcast_by_dp",
                                sbrec_ip_mcast_by_dp);
    engine_ovsdb_node_add_index(&en_sb_static_mac_binding,
                                "sbrec_static_mac_binding_by_lport_ip",
                                sbrec_static_mac_binding_by_lport_ip);
    engine_ovsdb_node_add_index(&en_sb_mac_binding,
                                "sbrec_mac_binding_by_datapath",
                                sbrec_mac_binding_by_datapath);

    struct ovsdb_idl_index *sbrec_address_set_by_name
        = ovsdb_idl_index_create1(sb->idl, &sbrec_address_set_col_name);
    engine_ovsdb_node_add_index(&en_sb_address_set,
                                "sbrec_address_set_by_name",
                                sbrec_address_set_by_name);
}

void inc_proc_northd_run(struct ovsdb_idl_txn *ovnnb_txn,
                         struct ovsdb_idl_txn *ovnsb_txn,
                         bool recompute) {
    engine_init_run();

    /* Force a full recompute if instructed to, for example, after a NB/SB
     * reconnect event.  However, make sure we don't overwrite an existing
     * force-recompute request if 'recompute' is false.
     */
    if (recompute) {
        engine_set_force_recompute(recompute);
    }

    struct engine_context eng_ctx = {
        .ovnnb_idl_txn = ovnnb_txn,
        .ovnsb_idl_txn = ovnsb_txn,
    };

    engine_set_context(&eng_ctx);

    if (ovnnb_txn && ovnsb_txn) {
        engine_run(true);
    }

    if (!engine_has_run()) {
        if (engine_need_run()) {
            VLOG_DBG("engine did not run, force recompute next time.");
            engine_set_force_recompute(true);
            poll_immediate_wake();
        } else {
            VLOG_DBG("engine did not run, and it was not needed");
        }
    } else if (engine_aborted()) {
        VLOG_DBG("engine was aborted, force recompute next time.");
        engine_set_force_recompute(true);
        poll_immediate_wake();
    } else {
        engine_set_force_recompute(false);
    }
}

void inc_proc_northd_cleanup(void)
{
    engine_cleanup();
    engine_set_context(NULL);
}
