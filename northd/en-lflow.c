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

#include "en-global-config.h"
#include "en-lflow.h"
#include "en-lr-nat.h"
#include "en-lr-stateful.h"
#include "en-ls-stateful.h"
#include "en-northd.h"
#include "en-meters.h"
#include "en-sampling-app.h"
#include "lflow-mgr.h"

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
    struct bfd_sync_data *bfd_sync_data =
        engine_get_input_data("bfd_sync", node);
    struct static_routes_data *static_routes_data =
        engine_get_input_data("static_routes", node);
    struct route_policies_data *route_policies_data =
        engine_get_input_data("route_policies", node);
    struct port_group_data *pg_data =
        engine_get_input_data("port_group", node);
    struct sync_meters_data *sync_meters_data =
        engine_get_input_data("sync_meters", node);
    struct ed_type_lr_stateful *lr_stateful_data =
        engine_get_input_data("lr_stateful", node);
    struct ed_type_ls_stateful *ls_stateful_data =
        engine_get_input_data("ls_stateful", node);
    struct ecmp_nexthop_data *nexthop_data =
        engine_get_input_data("ecmp_nexthop", node);

    lflow_input->sbrec_logical_flow_table =
        EN_OVSDB_GET(engine_get_input("SB_logical_flow", node));
    lflow_input->sbrec_multicast_group_table =
        EN_OVSDB_GET(engine_get_input("SB_multicast_group", node));
    lflow_input->sbrec_igmp_group_table =
        EN_OVSDB_GET(engine_get_input("SB_igmp_group", node));
    lflow_input->sbrec_logical_dp_group_table =
        EN_OVSDB_GET(engine_get_input("SB_logical_dp_group", node));

    lflow_input->sbrec_mcast_group_by_name_dp =
           engine_ovsdb_node_get_index(
                          engine_get_input("SB_multicast_group", node),
                         "sbrec_mcast_group_by_name");

    lflow_input->ls_datapaths = &northd_data->ls_datapaths;
    lflow_input->lr_datapaths = &northd_data->lr_datapaths;
    lflow_input->ls_ports = &northd_data->ls_ports;
    lflow_input->lr_ports = &northd_data->lr_ports;
    lflow_input->ls_port_groups = &pg_data->ls_port_groups;
    lflow_input->lr_stateful_table = &lr_stateful_data->table;
    lflow_input->ls_stateful_table = &ls_stateful_data->table;
    lflow_input->meter_groups = &sync_meters_data->meter_groups;
    lflow_input->lb_datapaths_map = &northd_data->lb_datapaths_map;
    lflow_input->svc_monitor_map = &northd_data->svc_monitor_map;
    lflow_input->bfd_connections = &bfd_sync_data->bfd_connections;
    lflow_input->parsed_routes = &static_routes_data->parsed_routes;
    lflow_input->route_tables = &static_routes_data->route_tables;
    lflow_input->route_policies = &route_policies_data->route_policies;
    lflow_input->nexthops_table = &nexthop_data->nexthops;

    struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);
    lflow_input->features = &global_config->features;
    lflow_input->ovn_internal_version_changed =
        global_config->ovn_internal_version_changed;
    lflow_input->svc_monitor_mac = global_config->svc_monitor_mac;

    struct ed_type_sampling_app_data *sampling_app_data =
        engine_get_input_data("sampling_app", node);
    lflow_input->sampling_apps = &sampling_app_data->apps;
}

void en_lflow_run(struct engine_node *node, void *data)
{
    const struct engine_context *eng_ctx = engine_get_context();

    struct lflow_input lflow_input;
    lflow_get_input_data(node, &lflow_input);

    stopwatch_start(BUILD_LFLOWS_STOPWATCH_NAME, time_msec());

    struct lflow_data *lflow_data = data;
    lflow_table_clear(lflow_data->lflow_table);
    lflow_reset_northd_refs(&lflow_input);

    build_lflows(eng_ctx->ovnsb_idl_txn, &lflow_input,
                 lflow_data->lflow_table);
    stopwatch_stop(BUILD_LFLOWS_STOPWATCH_NAME, time_msec());

    engine_set_node_state(node, EN_UPDATED);
}

bool
lflow_northd_handler(struct engine_node *node,
                     void *data)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_has_tracked_data(&northd_data->trk_data)) {
        return false;
    }

    const struct engine_context *eng_ctx = engine_get_context();
    struct lflow_data *lflow_data = data;

    struct lflow_input lflow_input;
    lflow_get_input_data(node, &lflow_input);

    if (!lflow_handle_northd_port_changes(eng_ctx->ovnsb_idl_txn,
                                          &northd_data->trk_data.trk_lsps,
                                          &lflow_input,
                                          lflow_data->lflow_table)) {
        return false;
    }

    if (!lflow_handle_northd_lb_changes(
            eng_ctx->ovnsb_idl_txn, &northd_data->trk_data.trk_lbs,
            &lflow_input, lflow_data->lflow_table)) {
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

bool
lflow_lr_stateful_handler(struct engine_node *node, void *data)
{
    struct ed_type_lr_stateful *lr_sful_data =
        engine_get_input_data("lr_stateful", node);

    if (!lr_stateful_has_tracked_data(&lr_sful_data->trk_data)) {
        return false;
    }

    const struct engine_context *eng_ctx = engine_get_context();
    struct lflow_data *lflow_data = data;
    struct lflow_input lflow_input;

    lflow_get_input_data(node, &lflow_input);
    if (!lflow_handle_lr_stateful_changes(eng_ctx->ovnsb_idl_txn,
                                          &lr_sful_data->trk_data,
                                          &lflow_input,
                                          lflow_data->lflow_table)) {
        return false;
    }

    engine_set_node_state(node, EN_UPDATED);
    return true;
}

bool
lflow_ls_stateful_handler(struct engine_node *node, void *data)
{
    struct ed_type_ls_stateful *ls_sful_data =
        engine_get_input_data("ls_stateful", node);

    if (!ls_stateful_has_tracked_data(&ls_sful_data->trk_data)) {
        return false;
    }

    const struct engine_context *eng_ctx = engine_get_context();
    struct lflow_data *lflow_data = data;
    struct lflow_input lflow_input;

    lflow_get_input_data(node, &lflow_input);
    if (!lflow_handle_ls_stateful_changes(eng_ctx->ovnsb_idl_txn,
                                          &ls_sful_data->trk_data,
                                          &lflow_input,
                                          lflow_data->lflow_table)) {
        return false;
    }

    engine_set_node_state(node, EN_UPDATED);
    return true;
}

void *en_lflow_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct lflow_data *data = xmalloc(sizeof *data);
    data->lflow_table = lflow_table_alloc();
    lflow_table_init(data->lflow_table);
    return data;
}

void en_lflow_cleanup(void *data_)
{
    struct lflow_data *data = data_;
    lflow_table_destroy(data->lflow_table);
}
