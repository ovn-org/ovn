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
#include "northd/aging.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "inc-proc-northd.h"
#include "en-lb-data.h"
#include "en-northd.h"
#include "en-lflow.h"
#include "en-northd-output.h"
#include "en-meters.h"
#include "en-sync-sb.h"
#include "en-sync-from-sb.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(inc_proc_northd);

static unixctl_cb_func chassis_features_list;

#define NB_NODES \
    NB_NODE(nb_global, "nb_global") \
    NB_NODE(logical_switch, "logical_switch") \
    NB_NODE(address_set, "address_set") \
    NB_NODE(port_group, "port_group") \
    NB_NODE(load_balancer, "load_balancer") \
    NB_NODE(load_balancer_group, "load_balancer_group") \
    NB_NODE(acl, "acl") \
    NB_NODE(logical_router, "logical_router") \
    NB_NODE(mirror, "mirror") \
    NB_NODE(meter, "meter") \
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
    SB_NODE(address_set, "address_set") \
    SB_NODE(port_group, "port_group") \
    SB_NODE(logical_flow, "logical_flow") \
    SB_NODE(multicast_group, "multicast_group") \
    SB_NODE(mirror, "mirror") \
    SB_NODE(meter, "meter") \
    SB_NODE(datapath_binding, "datapath_binding") \
    SB_NODE(port_binding, "port_binding") \
    SB_NODE(mac_binding, "mac_binding") \
    SB_NODE(dns, "dns") \
    SB_NODE(ha_chassis_group, "ha_chassis_group") \
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
static ENGINE_NODE_WITH_CLEAR_TRACK_DATA(northd, "northd");
static ENGINE_NODE(sync_from_sb, "sync_from_sb");
static ENGINE_NODE(lflow, "lflow");
static ENGINE_NODE(mac_binding_aging, "mac_binding_aging");
static ENGINE_NODE(mac_binding_aging_waker, "mac_binding_aging_waker");
static ENGINE_NODE(northd_output, "northd_output");
static ENGINE_NODE(sync_meters, "sync_meters");
static ENGINE_NODE(sync_to_sb, "sync_to_sb");
static ENGINE_NODE(sync_to_sb_addr_set, "sync_to_sb_addr_set");
static ENGINE_NODE_WITH_CLEAR_TRACK_DATA(port_group, "port_group");
static ENGINE_NODE(fdb_aging, "fdb_aging");
static ENGINE_NODE(fdb_aging_waker, "fdb_aging_waker");
static ENGINE_NODE(sync_to_sb_lb, "sync_to_sb_lb");
static ENGINE_NODE_WITH_CLEAR_TRACK_DATA(lb_data, "lb_data");

void inc_proc_northd_init(struct ovsdb_idl_loop *nb,
                          struct ovsdb_idl_loop *sb)
{
    /* Define relationships between nodes where first argument is dependent
     * on the second argument */
    engine_add_input(&en_lb_data, &en_nb_load_balancer,
                     lb_data_load_balancer_handler);
    engine_add_input(&en_lb_data, &en_nb_load_balancer_group,
                     lb_data_load_balancer_group_handler);

    engine_add_input(&en_northd, &en_nb_logical_router, NULL);
    engine_add_input(&en_northd, &en_nb_mirror, NULL);
    engine_add_input(&en_northd, &en_nb_static_mac_binding, NULL);
    engine_add_input(&en_northd, &en_nb_chassis_template_var, NULL);

    engine_add_input(&en_northd, &en_sb_sb_global, NULL);
    engine_add_input(&en_northd, &en_sb_chassis, NULL);
    engine_add_input(&en_northd, &en_sb_mirror, NULL);
    engine_add_input(&en_northd, &en_sb_meter, NULL);
    engine_add_input(&en_northd, &en_sb_datapath_binding, NULL);
    engine_add_input(&en_northd, &en_sb_mac_binding, NULL);
    engine_add_input(&en_northd, &en_sb_dns, NULL);
    engine_add_input(&en_northd, &en_sb_ha_chassis_group, NULL);
    engine_add_input(&en_northd, &en_sb_ip_multicast, NULL);
    engine_add_input(&en_northd, &en_sb_service_monitor, NULL);
    engine_add_input(&en_northd, &en_sb_fdb, NULL);
    engine_add_input(&en_northd, &en_sb_static_mac_binding, NULL);
    engine_add_input(&en_northd, &en_sb_chassis_template_var, NULL);

    engine_add_input(&en_northd, &en_sb_port_binding,
                     northd_sb_port_binding_handler);
    engine_add_input(&en_northd, &en_nb_nb_global,
                     northd_nb_nb_global_handler);
    engine_add_input(&en_northd, &en_nb_logical_switch,
                     northd_nb_logical_switch_handler);
    engine_add_input(&en_northd, &en_lb_data, northd_lb_data_handler);

    engine_add_input(&en_mac_binding_aging, &en_nb_nb_global, NULL);
    engine_add_input(&en_mac_binding_aging, &en_sb_mac_binding, NULL);
    engine_add_input(&en_mac_binding_aging, &en_northd, NULL);
    engine_add_input(&en_mac_binding_aging, &en_mac_binding_aging_waker, NULL);

    engine_add_input(&en_fdb_aging, &en_nb_nb_global, NULL);
    engine_add_input(&en_fdb_aging, &en_sb_fdb, NULL);
    engine_add_input(&en_fdb_aging, &en_northd, NULL);
    engine_add_input(&en_fdb_aging, &en_fdb_aging_waker, NULL);

    engine_add_input(&en_sync_meters, &en_nb_acl, NULL);
    engine_add_input(&en_sync_meters, &en_nb_meter, NULL);
    engine_add_input(&en_sync_meters, &en_sb_meter, NULL);

    engine_add_input(&en_lflow, &en_nb_bfd, NULL);
    engine_add_input(&en_lflow, &en_nb_acl, NULL);
    engine_add_input(&en_lflow, &en_sync_meters, NULL);
    engine_add_input(&en_lflow, &en_sb_bfd, NULL);
    engine_add_input(&en_lflow, &en_sb_logical_flow, NULL);
    engine_add_input(&en_lflow, &en_sb_multicast_group, NULL);
    engine_add_input(&en_lflow, &en_sb_igmp_group, NULL);
    engine_add_input(&en_lflow, &en_northd, lflow_northd_handler);
    engine_add_input(&en_lflow, &en_port_group, lflow_port_group_handler);

    engine_add_input(&en_sync_to_sb_addr_set, &en_nb_address_set,
                     sync_to_sb_addr_set_nb_address_set_handler);
    engine_add_input(&en_sync_to_sb_addr_set, &en_nb_port_group,
                     sync_to_sb_addr_set_nb_port_group_handler);
    engine_add_input(&en_sync_to_sb_addr_set, &en_northd, NULL);
    engine_add_input(&en_sync_to_sb_addr_set, &en_sb_address_set, NULL);

    engine_add_input(&en_port_group, &en_nb_port_group,
                     port_group_nb_port_group_handler);
    engine_add_input(&en_port_group, &en_sb_port_group, NULL);
    /* No need for an explicit handler for northd changes.  Port changes
     * that affect port_groups trigger updates to the NB.Port_Group
     * table too (because of the explicit dependency in the schema). */
    engine_add_input(&en_port_group, &en_northd, engine_noop_handler);

    engine_add_input(&en_sync_to_sb_lb, &en_northd,
                     sync_to_sb_lb_northd_handler);
    engine_add_input(&en_sync_to_sb_lb, &en_sb_load_balancer, NULL);

    /* en_sync_to_sb engine node syncs the SB database tables from
     * the NB database tables.
     * Right now this engine syncs the SB Address_Set table, Port_Group table
     * SB Meter/Meter_Band tables and SB Load_Balancer table.
     */
    engine_add_input(&en_sync_to_sb, &en_sync_to_sb_addr_set, NULL);
    engine_add_input(&en_sync_to_sb, &en_port_group, NULL);
    engine_add_input(&en_sync_to_sb, &en_sync_meters, NULL);
    engine_add_input(&en_sync_to_sb, &en_sync_to_sb_lb, NULL);

    engine_add_input(&en_sync_from_sb, &en_northd,
                     sync_from_sb_northd_handler);
    engine_add_input(&en_sync_from_sb, &en_sb_port_binding, NULL);
    engine_add_input(&en_sync_from_sb, &en_sb_ha_chassis_group, NULL);

    engine_add_input(&en_northd_output, &en_sync_from_sb, NULL);
    engine_add_input(&en_northd_output, &en_sync_to_sb,
                     northd_output_sync_to_sb_handler);
    engine_add_input(&en_northd_output, &en_lflow,
                     northd_output_lflow_handler);
    engine_add_input(&en_northd_output, &en_mac_binding_aging,
                     northd_output_mac_binding_aging_handler);
    engine_add_input(&en_northd_output, &en_fdb_aging,
                     northd_output_fdb_aging_handler);

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
    struct ovsdb_idl_index *fdb_by_dp_key =
        ovsdb_idl_index_create1(sb->idl, &sbrec_fdb_col_dp_key);

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
    engine_ovsdb_node_add_index(&en_sb_fdb,
                                "fdb_by_dp_key",
                                fdb_by_dp_key);

    struct ovsdb_idl_index *sbrec_address_set_by_name
        = ovsdb_idl_index_create1(sb->idl, &sbrec_address_set_col_name);
    engine_ovsdb_node_add_index(&en_sb_address_set,
                                "sbrec_address_set_by_name",
                                sbrec_address_set_by_name);

    struct ovsdb_idl_index *sbrec_port_group_by_name
        = ovsdb_idl_index_create1(sb->idl, &sbrec_port_group_col_name);
    engine_ovsdb_node_add_index(&en_sb_port_group,
                                "sbrec_port_group_by_name",
                                sbrec_port_group_by_name);

    struct ovsdb_idl_index *sbrec_fdb_by_dp_and_port
        = ovsdb_idl_index_create2(sb->idl, &sbrec_fdb_col_dp_key,
                                  &sbrec_fdb_col_port_key);
    engine_ovsdb_node_add_index(&en_sb_fdb,
                                "sbrec_fdb_by_dp_and_port",
                                sbrec_fdb_by_dp_and_port);

    struct northd_data *northd_data =
        engine_get_internal_data(&en_northd);
    unixctl_command_register("debug/chassis-features-list", "", 0, 0,
                             chassis_features_list,
                             &northd_data->features);
}

/* Returns true if the incremental processing ended up updating nodes. */
bool inc_proc_northd_run(struct ovsdb_idl_txn *ovnnb_txn,
                         struct ovsdb_idl_txn *ovnsb_txn,
                         struct northd_engine_context *ctx) {
    ovs_assert(ovnnb_txn && ovnsb_txn);

    int64_t start = time_msec();
    engine_init_run();

    /* Force a full recompute if instructed to, for example, after a NB/SB
     * reconnect event.  However, make sure we don't overwrite an existing
     * force-recompute request if 'recompute' is false.
     */
    if (ctx->recompute) {
        engine_set_force_recompute(ctx->recompute);
    }

    struct engine_context eng_ctx = {
        .ovnnb_idl_txn = ovnnb_txn,
        .ovnsb_idl_txn = ovnsb_txn,
    };

    engine_set_context(&eng_ctx);
    engine_run(true);

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

    int64_t now = time_msec();
    /* Postpone the next run by length of current run with maximum capped
     * by "northd-backoff-interval-ms" interval. */
    ctx->next_run_ms = now + MIN(now - start, ctx->backoff_ms);

    return engine_has_updated();
}

void inc_proc_northd_cleanup(void)
{
    engine_cleanup();
    engine_set_context(NULL);
}

bool
inc_proc_northd_can_run(struct northd_engine_context *ctx)
{
    if (ctx->recompute || time_msec() >= ctx->next_run_ms ||
        ctx->nb_idl_duration_ms >= IDL_LOOP_MAX_DURATION_MS ||
        ctx->sb_idl_duration_ms >= IDL_LOOP_MAX_DURATION_MS) {
        return true;
    }

    poll_timer_wait_until(ctx->next_run_ms);
    return false;
}

static void
chassis_features_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
                      const char *argv[] OVS_UNUSED, void *features_)
{
    struct chassis_features *features = features_;
    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_format(&ds, "ct_no_masked_label:    %s\n",
                  features->ct_no_masked_label ? "true" : "false");
    ds_put_format(&ds, "ct_lb_related:         %s\n",
                  features->ct_lb_related ? "true" : "false");
    ds_put_format(&ds, "mac_binding_timestamp: %s\n",
                  features->mac_binding_timestamp ? "true" : "false");
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}
