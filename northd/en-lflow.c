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

#include "en-lflow.h"
#include "en-northd.h"

#include "lib/inc-proc-eng.h"
#include "northd.h"
#include "stopwatch.h"
#include "lib/stopwatch-names.h"
#include "timeval.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(en_lflow);

void en_lflow_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();

    struct lflow_input lflow_input;

    struct northd_data *northd_data = engine_get_input_data("northd", node);

    lflow_input.nbrec_bfd_table =
        EN_OVSDB_GET(engine_get_input("NB_bfd", node));
    lflow_input.sbrec_bfd_table =
        EN_OVSDB_GET(engine_get_input("SB_bfd", node));
    lflow_input.sbrec_logical_flow_table =
        EN_OVSDB_GET(engine_get_input("SB_logical_flow", node));
    lflow_input.sbrec_multicast_group_table =
        EN_OVSDB_GET(engine_get_input("SB_multicast_group", node));
    lflow_input.sbrec_igmp_group_table =
        EN_OVSDB_GET(engine_get_input("SB_igmp_group", node));

    lflow_input.sbrec_mcast_group_by_name_dp =
           engine_ovsdb_node_get_index(
                          engine_get_input("SB_multicast_group", node),
                         "sbrec_mcast_group_by_name");

    lflow_input.ls_datapaths = &northd_data->ls_datapaths;
    lflow_input.lr_datapaths = &northd_data->lr_datapaths;
    lflow_input.ls_ports = &northd_data->ls_ports;
    lflow_input.lr_ports = &northd_data->lr_ports;
    lflow_input.port_groups = &northd_data->port_groups;
    lflow_input.meter_groups = &northd_data->meter_groups;
    lflow_input.lbs = &northd_data->lbs;
    lflow_input.bfd_connections = &northd_data->bfd_connections;
    lflow_input.features = &northd_data->features;
    lflow_input.ovn_internal_version_changed =
                      northd_data->ovn_internal_version_changed;

    stopwatch_start(BUILD_LFLOWS_STOPWATCH_NAME, time_msec());
    build_bfd_table(eng_ctx->ovnsb_idl_txn,
                    lflow_input.nbrec_bfd_table,
                    lflow_input.sbrec_bfd_table,
                    &northd_data->bfd_connections,
                    &northd_data->lr_ports);
    build_lflows(&lflow_input, eng_ctx->ovnsb_idl_txn);
    bfd_cleanup_connections(lflow_input.nbrec_bfd_table,
                            &northd_data->bfd_connections);
    stopwatch_stop(BUILD_LFLOWS_STOPWATCH_NAME, time_msec());

    engine_set_node_state(node, EN_UPDATED);
}
void *en_lflow_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void en_lflow_cleanup(void *data OVS_UNUSED)
{
}
