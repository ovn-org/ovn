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
#include "en-multicast.h"
#include "en-northd.h"
#include "en-meters.h"
#include "en-sampling-app.h"
#include "en-group-ecmp-route.h"
#include "en-datapath-sync.h"
#include "lflow-mgr.h"

#include "lib/inc-proc-eng.h"
#include "northd.h"
#include "timeval.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(en_lflow);

extern int search_mode;

static void
lflow_get_input_data(struct engine_node *node,
                     struct lflow_input *lflow_input)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    struct bfd_sync_data *bfd_sync_data =
        engine_get_input_data("bfd_sync", node);
    struct routes_data *routes_data =
        engine_get_input_data("routes", node);
    struct group_ecmp_route_data *group_ecmp_route_data =
        engine_get_input_data("group_ecmp_route", node);
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
    struct multicast_igmp_data *multicat_igmp_data =
        engine_get_input_data("multicast_igmp", node);
    struct ic_learned_svc_monitors_data *ic_learned_svc_monitors_data =
        engine_get_input_data("ic_learned_svc_monitors", node);
    struct all_synced_datapaths *all_dps =
        engine_get_input_data("datapath_sync", node);

    lflow_input->sbrec_acl_id_table =
        EN_OVSDB_GET(engine_get_input("SB_acl_id", node));

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
    lflow_input->local_svc_monitors_map =
        &northd_data->local_svc_monitors_map;
    lflow_input->bfd_ports = &bfd_sync_data->bfd_ports;
    lflow_input->route_data = group_ecmp_route_data;
    lflow_input->route_tables = &routes_data->route_tables;
    lflow_input->route_policies = &route_policies_data->route_policies;
    lflow_input->igmp_groups = &multicat_igmp_data->igmp_groups;
    lflow_input->igmp_lflow_ref = multicat_igmp_data->lflow_ref;
    lflow_input->ic_learned_svc_monitors_map =
        &ic_learned_svc_monitors_data->ic_learned_svc_monitors_map;
    lflow_input->ic_learned_svc_monitors_lflow_ref =
        ic_learned_svc_monitors_data->lflow_ref;

    struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);
    lflow_input->features = &global_config->features;
    lflow_input->ovn_internal_version_changed =
        global_config->ovn_internal_version_changed;
    lflow_input->svc_monitor_mac =
        global_config->svc_global_addresses.mac_src;

    struct ed_type_sampling_app_data *sampling_app_data =
        engine_get_input_data("sampling_app", node);
    lflow_input->sampling_apps = &sampling_app_data->apps;
    lflow_input->dps = all_dps->synced_dps;
}

enum engine_node_state
en_lflow_run(struct engine_node *node, void *data)
{
    struct lflow_input lflow_input;
    lflow_get_input_data(node, &lflow_input);

    struct lflow_data *lflow_data = data;
    lflow_table_clear(lflow_data->lflow_table,
        search_mode == LFLOW_TABLE_SEARCH_FIELDS);
    lflow_reset_northd_refs(&lflow_input);
    lflow_ref_clear(lflow_input.igmp_lflow_ref);

    build_lflows(&lflow_input, lflow_data->lflow_table);

    return EN_UPDATED;
}

enum engine_input_handler_result
lflow_northd_handler(struct engine_node *node,
                     void *data)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_has_tracked_data(&northd_data->trk_data)) {
        return EN_UNHANDLED;
    }

    if (northd_has_lswitches_in_tracked_data(&northd_data->trk_data)) {
        return EN_UNHANDLED;
    }

    struct lflow_data *lflow_data = data;

    struct lflow_input lflow_input;
    lflow_get_input_data(node, &lflow_input);

    lflow_handle_northd_lr_changes(&northd_data->trk_data.trk_routers,
                                   &lflow_input,
                                   lflow_data->lflow_table,
                                   &lflow_data->trk_data.dirty_lflow_refs);

    lflow_handle_northd_port_changes(&northd_data->trk_data.trk_lsps,
                                     &lflow_input,
                                     lflow_data->lflow_table,
                                     &lflow_data->trk_data.dirty_lflow_refs);

    lflow_handle_northd_lb_changes(&northd_data->trk_data.trk_lbs,
                                   &lflow_input,
                                   lflow_data->lflow_table,
                                   &lflow_data->trk_data.dirty_lflow_refs);

    return EN_HANDLED_UPDATED;
}

enum engine_input_handler_result
lflow_lr_stateful_handler(struct engine_node *node, void *data)
{
    struct ed_type_lr_stateful *lr_sful_data =
        engine_get_input_data("lr_stateful", node);

    if (!lr_stateful_has_tracked_data(&lr_sful_data->trk_data)
        || lr_sful_data->trk_data.vip_nats_changed) {
        return EN_UNHANDLED;
    }

    struct lflow_data *lflow_data = data;
    struct lflow_input lflow_input;

    lflow_get_input_data(node, &lflow_input);
    lflow_handle_lr_stateful_changes(&lr_sful_data->trk_data,
                                     &lflow_input,
                                     lflow_data->lflow_table,
                                     &lflow_data->trk_data.dirty_lflow_refs);

    return EN_HANDLED_UPDATED;
}

enum engine_input_handler_result
lflow_ls_stateful_handler(struct engine_node *node, void *data)
{
    struct ed_type_ls_stateful *ls_sful_data =
        engine_get_input_data("ls_stateful", node);

    if (!ls_stateful_has_tracked_data(&ls_sful_data->trk_data)) {
        return EN_UNHANDLED;
    }

    struct lflow_data *lflow_data = data;
    struct lflow_input lflow_input;

    lflow_get_input_data(node, &lflow_input);
    lflow_handle_ls_stateful_changes(&ls_sful_data->trk_data,
                                     &lflow_input,
                                     lflow_data->lflow_table,
                                     &lflow_data->trk_data.dirty_lflow_refs);

    return EN_HANDLED_UPDATED;
}

enum engine_input_handler_result
lflow_multicast_igmp_handler(struct engine_node *node, void *data)
{
    struct multicast_igmp_data *mcast_igmp_data =
        engine_get_input_data("multicast_igmp", node);

    struct lflow_data *lflow_data = data;
    struct lflow_input lflow_input;
    lflow_get_input_data(node, &lflow_input);

    lflow_ref_unlink_and_prune(mcast_igmp_data->lflow_ref,
                              lflow_data->lflow_table);

    build_igmp_lflows(&mcast_igmp_data->igmp_groups,
                      &lflow_input.ls_datapaths->datapaths,
                      lflow_data->lflow_table,
                      mcast_igmp_data->lflow_ref);

    lflow_data->trk_data.needs_full_sync = true;

    return EN_HANDLED_UPDATED;
}

enum engine_input_handler_result
lflow_group_ecmp_route_change_handler(struct engine_node *node,
                                      void *data OVS_UNUSED)
{
    struct group_ecmp_route_data *group_ecmp_route_data =
        engine_get_input_data("group_ecmp_route", node);

    /* If we do not have tracked data we need to recompute. */
    if (!group_ecmp_route_data->tracked) {
        return EN_UNHANDLED;
    }

    struct lflow_data *lflow_data = data;

    struct lflow_input lflow_input;
    lflow_get_input_data(node, &lflow_input);

    struct group_ecmp_datapath *route_node;
    struct hmapx_node *hmapx_node;

    HMAPX_FOR_EACH (hmapx_node,
                    &group_ecmp_route_data->trk_data.deleted_datapath_routes) {
        route_node = hmapx_node->data;
        lflow_ref_unlink_lflows(route_node->lflow_ref,
                                lflow_data->lflow_table);

        hmapx_add(&lflow_data->trk_data.dirty_lflow_refs,
                  route_node->lflow_ref);
    }

    struct hmapx *crupdated_datapath_routes =
        &group_ecmp_route_data->trk_data.crupdated_datapath_routes;
    HMAPX_FOR_EACH (hmapx_node, crupdated_datapath_routes) {
        route_node = hmapx_node->data;
        lflow_ref_unlink_lflows(route_node->lflow_ref,
                                lflow_data->lflow_table);
        build_route_data_flows_for_lrouter(
            route_node->od, lflow_data->lflow_table,
            route_node, lflow_input.bfd_ports);
        hmapx_add(&lflow_data->trk_data.dirty_lflow_refs,
                  route_node->lflow_ref);
    }

    return EN_HANDLED_UPDATED;
}

enum engine_input_handler_result
lflow_ic_learned_svc_mons_handler(struct engine_node *node,
                                  void *data)
{
    struct ic_learned_svc_monitors_data *ic_learned_svc_monitors_data =
        engine_get_input_data("ic_learned_svcs", node);

    struct lflow_data *lflow_data = data;
    struct lflow_input lflow_input;
    lflow_get_input_data(node, &lflow_input);

    struct svc_monitors_map_data svc_mons_data =
        svc_monitors_map_data_init(
            NULL,
            &ic_learned_svc_monitors_data->ic_learned_svc_monitors_map,
            ic_learned_svc_monitors_data->lflow_ref);

    lflow_ref_unlink_and_prune(ic_learned_svc_monitors_data->lflow_ref,
                               lflow_data->lflow_table);

    build_lswitch_arp_nd_ic_learned_svc_mon(
        &svc_mons_data,
        lflow_input.ls_ports,
        lflow_input.svc_monitor_mac,
        lflow_data->lflow_table);

    lflow_data->trk_data.needs_full_sync = true;

    return EN_HANDLED_UPDATED;
}

void *en_lflow_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct lflow_data *data = xmalloc(sizeof *data);
    data->lflow_table = lflow_table_alloc();
    lflow_table_init(data->lflow_table);
    hmapx_init(&data->trk_data.dirty_lflow_refs);
    data->trk_data.needs_full_sync = false;

    return data;
}

void en_lflow_cleanup(void *data_)
{
    struct lflow_data *data = data_;
    lflow_table_destroy(data->lflow_table);
    hmapx_destroy(&data->trk_data.dirty_lflow_refs);
}

void en_lflow_clear_tracked_data(void *data_)
{
    struct lflow_data *data = data_;
    hmapx_clear(&data->trk_data.dirty_lflow_refs);
    data->trk_data.needs_full_sync = false;
}
