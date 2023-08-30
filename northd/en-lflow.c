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
#include "en-meters.h"

#include "lib/inc-proc-eng.h"
#include "northd.h"
#include "stopwatch.h"
#include "lib/stopwatch-names.h"
#include "timeval.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(en_lflow);

static void
lflow_get_input_data(struct engine_node *node,
                     struct lflow_input *lflow_input)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    struct port_group_data *pg_data =
        engine_get_input_data("port_group", node);
    struct sync_meters_data *sync_meters_data =
        engine_get_input_data("sync_meters", node);
    lflow_input->nbrec_bfd_table =
        EN_OVSDB_GET(engine_get_input("NB_bfd", node));
    lflow_input->sbrec_bfd_table =
        EN_OVSDB_GET(engine_get_input("SB_bfd", node));
    lflow_input->sbrec_logical_flow_table =
        EN_OVSDB_GET(engine_get_input("SB_logical_flow", node));
    lflow_input->sbrec_multicast_group_table =
        EN_OVSDB_GET(engine_get_input("SB_multicast_group", node));
    lflow_input->sbrec_igmp_group_table =
        EN_OVSDB_GET(engine_get_input("SB_igmp_group", node));

    lflow_input->sbrec_mcast_group_by_name_dp =
           engine_ovsdb_node_get_index(
                          engine_get_input("SB_multicast_group", node),
                         "sbrec_mcast_group_by_name");

    lflow_input->ls_datapaths = &northd_data->ls_datapaths;
    lflow_input->lr_datapaths = &northd_data->lr_datapaths;
    lflow_input->ls_ports = &northd_data->ls_ports;
    lflow_input->lr_ports = &northd_data->lr_ports;
    lflow_input->ls_port_groups = &pg_data->ls_port_groups;
    lflow_input->meter_groups = &sync_meters_data->meter_groups;
    lflow_input->lbs = &northd_data->lbs;
    lflow_input->features = &northd_data->features;
    lflow_input->ovn_internal_version_changed =
                      northd_data->ovn_internal_version_changed;
    lflow_input->bfd_connections = NULL;
}

void en_lflow_run(struct engine_node *node, void *data)
{
    const struct engine_context *eng_ctx = engine_get_context();

    struct lflow_input lflow_input;
    lflow_get_input_data(node, &lflow_input);

    struct hmap bfd_connections = HMAP_INITIALIZER(&bfd_connections);
    lflow_input.bfd_connections = &bfd_connections;

    struct lflow_data *lflow_data = data;
    lflow_data_destroy(lflow_data);
    lflow_data_init(lflow_data);

    stopwatch_start(BUILD_LFLOWS_STOPWATCH_NAME, time_msec());
    build_bfd_table(eng_ctx->ovnsb_idl_txn,
                    lflow_input.nbrec_bfd_table,
                    lflow_input.sbrec_bfd_table,
                    lflow_input.lr_ports,
                    &bfd_connections);
    build_lflows(eng_ctx->ovnsb_idl_txn, &lflow_input, &lflow_data->lflows);
    bfd_cleanup_connections(lflow_input.nbrec_bfd_table,
                            &bfd_connections);
    hmap_destroy(&bfd_connections);
    stopwatch_stop(BUILD_LFLOWS_STOPWATCH_NAME, time_msec());

    engine_set_node_state(node, EN_UPDATED);
}

bool
lflow_northd_handler(struct engine_node *node,
                     void *data)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_data->change_tracked) {
        return false;
    }
    const struct engine_context *eng_ctx = engine_get_context();
    struct lflow_data *lflow_data = data;

    struct lflow_input lflow_input;
    lflow_get_input_data(node, &lflow_input);

    if (!lflow_handle_northd_ls_changes(eng_ctx->ovnsb_idl_txn,
                                        &northd_data->tracked_ls_changes,
                                        &lflow_input, &lflow_data->lflows)) {
        return false;
    }

    engine_set_node_state(node, EN_UPDATED);
    return true;
}

bool
lflow_port_group_handler(struct engine_node *node, void *data OVS_UNUSED)
{
    struct port_group_data *pg_data =
        engine_get_input_data("port_group", node);

    /* If the set of switches per port group didn't change then there's no
     * need to reprocess lflows.  Otherwise, there might be a need to
     * add/delete port-group ACLs to/from switches. */
    if (pg_data->ls_port_groups_sets_changed) {
        return false;
    }

    engine_set_node_state(node, EN_UPDATED);
    return true;
}

void *en_lflow_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct lflow_data *data = xmalloc(sizeof *data);
    lflow_data_init(data);
    return data;
}

void en_lflow_cleanup(void *data)
{
    lflow_data_destroy(data);
}
