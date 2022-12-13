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

#include "en-northd.h"
#include "lib/inc-proc-eng.h"
#include "openvswitch/list.h" /* TODO This is needed for ovn-parallel-hmap.h.
                               * lib/ovn-parallel-hmap.h should be updated
                               * to include this dependency itself */
#include "lib/ovn-parallel-hmap.h"
#include "northd.h"
#include "lib/util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(en_northd);

void en_northd_run(struct engine_node *node, void *data)
{
    const struct engine_context *eng_ctx = engine_get_context();

    struct northd_input input_data;

    northd_destroy(data);
    northd_init(data);

    input_data.sbrec_chassis_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_chassis", node),
            "sbrec_chassis_by_name");
    input_data.sbrec_chassis_by_hostname =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_chassis", node),
            "sbrec_chassis_by_hostname");
    input_data.sbrec_ha_chassis_grp_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_ha_chassis_group", node),
            "sbrec_ha_chassis_grp_by_name");
    input_data.sbrec_ip_mcast_by_dp =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_ip_multicast", node),
            "sbrec_ip_mcast_by_dp");
    input_data.sbrec_static_mac_binding_by_lport_ip =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_static_mac_binding", node),
            "sbrec_static_mac_binding_by_lport_ip");

    input_data.nbrec_nb_global_table =
        EN_OVSDB_GET(engine_get_input("NB_nb_global", node));
    input_data.nbrec_logical_switch =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));
    input_data.nbrec_logical_router =
        EN_OVSDB_GET(engine_get_input("NB_logical_router", node));
    input_data.nbrec_load_balancer_table =
        EN_OVSDB_GET(engine_get_input("NB_load_balancer", node));
    input_data.nbrec_load_balancer_group_table =
        EN_OVSDB_GET(engine_get_input("NB_load_balancer_group", node));
    input_data.nbrec_port_group_table =
        EN_OVSDB_GET(engine_get_input("NB_port_group", node));
    input_data.nbrec_meter_table =
        EN_OVSDB_GET(engine_get_input("NB_meter", node));
    input_data.nbrec_acl_table =
        EN_OVSDB_GET(engine_get_input("NB_acl", node));
    input_data.nbrec_static_mac_binding_table =
        EN_OVSDB_GET(engine_get_input("NB_static_mac_binding", node));
    input_data.nbrec_chassis_template_var_table =
        EN_OVSDB_GET(engine_get_input("NB_chassis_template_var", node));
    input_data.nbrec_mirror_table =
        EN_OVSDB_GET(engine_get_input("NB_mirror", node));

    input_data.sbrec_sb_global_table =
        EN_OVSDB_GET(engine_get_input("SB_sb_global", node));
    input_data.sbrec_datapath_binding_table =
        EN_OVSDB_GET(engine_get_input("SB_datapath_binding", node));
    input_data.sbrec_port_binding_table =
        EN_OVSDB_GET(engine_get_input("SB_port_binding", node));
    input_data.sbrec_mac_binding_table =
        EN_OVSDB_GET(engine_get_input("SB_mac_binding", node));
    input_data.sbrec_ha_chassis_group_table =
        EN_OVSDB_GET(engine_get_input("SB_ha_chassis_group", node));
    input_data.sbrec_chassis =
        EN_OVSDB_GET(engine_get_input("SB_chassis", node));
    input_data.sbrec_fdb_table =
        EN_OVSDB_GET(engine_get_input("SB_fdb", node));
    input_data.sbrec_load_balancer_table =
        EN_OVSDB_GET(engine_get_input("SB_load_balancer", node));
    input_data.sbrec_service_monitor_table =
        EN_OVSDB_GET(engine_get_input("SB_service_monitor", node));
    input_data.sbrec_port_group_table =
        EN_OVSDB_GET(engine_get_input("SB_port_group", node));
    input_data.sbrec_meter_table =
        EN_OVSDB_GET(engine_get_input("SB_meter", node));
    input_data.sbrec_dns_table =
        EN_OVSDB_GET(engine_get_input("SB_dns", node));
    input_data.sbrec_ip_multicast_table =
        EN_OVSDB_GET(engine_get_input("SB_ip_multicast", node));
    input_data.sbrec_chassis_private_table =
        EN_OVSDB_GET(engine_get_input("SB_chassis_private", node));
    input_data.sbrec_static_mac_binding_table =
        EN_OVSDB_GET(engine_get_input("SB_static_mac_binding", node));
    input_data.sbrec_chassis_template_var_table =
        EN_OVSDB_GET(engine_get_input("SB_chassis_template_var", node));
    input_data.sbrec_mirror_table =
        EN_OVSDB_GET(engine_get_input("SB_mirror", node));

    northd_run(&input_data, data,
               eng_ctx->ovnnb_idl_txn,
               eng_ctx->ovnsb_idl_txn);
    engine_set_node_state(node, EN_UPDATED);

}
void *en_northd_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct northd_data *data = xmalloc(sizeof *data);

    northd_init(data);

    return data;
}

void en_northd_cleanup(void *data)
{
    northd_destroy(data);
}
