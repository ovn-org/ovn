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

#include "lib/inc-proc-eng.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "inc-proc-ic.h"
#include "en-ic.h"
#include "en-dp-enum.h"
#include "en-gateway.h"
#include "en-ts.h"
#include "en-tr.h"
#include "en-port-binding.h"
#include "en-route.h"
#include "en-service-monitor.h"
#include "en-address-set.h"
#include "ovn-util.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(inc_proc_ic);

#define NB_NODES \
    NB_NODE(nb_global, "nb_global") \
    NB_NODE(logical_router_static_route, "logical_router_static_route") \
    NB_NODE(logical_router, "logical_router") \
    NB_NODE(logical_router_port, "logical_router_port") \
    NB_NODE(logical_switch, "logical_switch") \
    NB_NODE(logical_switch_port, "logical_switch_port") \
    NB_NODE(load_balancer, "load_balancer") \
    NB_NODE(load_balancer_group, "load_balancer_group") \
    NB_NODE(address_set, "address_set")

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
    SB_NODE(encap, "encap") \
    SB_NODE(datapath_binding, "datapath_binding") \
    SB_NODE(port_binding, "port_binding") \
    SB_NODE(service_monitor, "service_monitor") \
    SB_NODE(learned_route, "learned_route") \
    SB_NODE(address_set, "address_set")

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

#define ICNB_NODES \
    ICNB_NODE(ic_nb_global, "ic_nb_global") \
    ICNB_NODE(transit_switch, "transit_switch") \
    ICNB_NODE(transit_router, "transit_router") \
    ICNB_NODE(transit_router_port, "transit_router_port")

    enum icnb_engine_node {
#define ICNB_NODE(NAME, NAME_STR) ICNB_##NAME,
    ICNB_NODES
#undef ICNB_NODE
    };

/* Define engine node functions for nodes that represent ICNB tables
 *
 * en_icnb_<TABLE_NAME>_run()
 * en_icnb_<TABLE_NAME>_init()
 * en_icnb_<TABLE_NAME>_cleanup()
 */
#define ICNB_NODE(NAME, NAME_STR) ENGINE_FUNC_ICNB(NAME);
    ICNB_NODES
#undef ICNB_NODE

/* Note: the ic_sb_global table is intentionally not modeled as an engine input
 * node.  It only carries IC-SB sequence numbers, which are written by
 * update_sequence_numbers() in the main loop (outside the engine) and are not
 * read by any subsystem node. */
#define ICSB_NODES \
    ICSB_NODE(availability_zone, "availability_zone") \
    ICSB_NODE(service_monitor, "service_monitor") \
    ICSB_NODE(route, "route") \
    ICSB_NODE(datapath_binding, "datapath_binding") \
    ICSB_NODE(encap, "encap") \
    ICSB_NODE(gateway, "gateway") \
    ICSB_NODE(port_binding, "port_binding") \
    ICSB_NODE(address_set, "address_set")

    enum icsb_engine_node {
#define ICSB_NODE(NAME, NAME_STR) ICSB_##NAME,
    ICSB_NODES
#undef ICSB_NODE
    };

/* Define engine node functions for nodes that represent ICSB tables
 *
 * en_icsb_<TABLE_NAME>_run()
 * en_icsb_<TABLE_NAME>_init()
 * en_icsb_<TABLE_NAME>_cleanup()
 */
#define ICSB_NODE(NAME, NAME_STR) ENGINE_FUNC_ICSB(NAME);
    ICSB_NODES
#undef ICSB_NODE

/* Define engine nodes for NB, SB, ICNB and ICSB tables
 *
 * struct engine_node en_nb_<TABLE_NAME>
 * struct engine_node en_sb_<TABLE_NAME>
 * struct engine_node en_icnb_<TABLE_NAME>
 * struct engine_node en_icsb_<TABLE_NAME>
 *
 * Define nodes as static to avoid sparse errors.
 */
#define NB_NODE(NAME, NAME_STR) static ENGINE_NODE_NB(NAME);
    NB_NODES
#undef NB_NODE

#define SB_NODE(NAME, NAME_STR) static ENGINE_NODE_SB(NAME);
    SB_NODES
#undef SB_NODE

#define ICNB_NODE(NAME, NAME_STR) static ENGINE_NODE_ICNB(NAME);
    ICNB_NODES
#undef ICNB_NODE

#define ICSB_NODE(NAME, NAME_STR) static ENGINE_NODE_ICSB(NAME);
    ICSB_NODES
#undef ICSB_NODE

/* Define engine nodes for other nodes. They should be defined as static to
 * avoid sparse errors. */
static ENGINE_NODE(dp_enum);
static ENGINE_NODE(gateway);
static ENGINE_NODE(ts);
static ENGINE_NODE(tr);
static ENGINE_NODE(port_binding);
static ENGINE_NODE(route);
static ENGINE_NODE(service_monitor);
static ENGINE_NODE(address_set);
static ENGINE_NODE(ic);

void inc_proc_ic_init(struct ovsdb_idl_loop *nb,
                      struct ovsdb_idl_loop *sb,
                      struct ovsdb_idl_loop *icnb,
                      struct ovsdb_idl_loop *icsb)
{
    /* Define relationships between nodes where the first argument is dependent
     * on the second argument.
     *
     * Each subsystem node below depends on the table input nodes it reads, so
     * the engine only re-runs a subsystem when one of its inputs changed.  No
     * change handlers are wired yet: every dependency uses a NULL handler, so
     * any tracked change to an input triggers a full recompute of just that
     * subsystem (run() method).  This preserves the previous behavior while
     * splitting the monolithic ovn_db_run() into independently-gated nodes.
     * Change handlers are added incrementally in a later step. */

    /* en_dp_enum: enumerate IC-SB datapath bindings (tunnel-key allocator and
     * transit switch/router datapath maps shared by en_ts and en_tr).
     *
     * en_ts and en_tr allocate datapath tunnel keys from the shared
     * 'dp_tnlids' set owned by this node, mutating it during their run.  To
     * keep that allocator correct, en_dp_enum must rebuild it from scratch in
     * the same iteration as any allocation.  It therefore depends not only on
     * the IC-SB datapath bindings themselves, but also on every input that can
     * cause en_ts/en_tr to allocate a key: a new transit switch or router, or
     * a change of vxlan_mode (which forces a tunnel-key refresh). */
    engine_add_input(&en_dp_enum, &en_icsb_datapath_binding, NULL);
    engine_add_input(&en_dp_enum, &en_icnb_transit_switch, NULL);
    engine_add_input(&en_dp_enum, &en_icnb_transit_router, NULL);
    engine_add_input(&en_dp_enum, &en_icnb_ic_nb_global, NULL);

    /* en_gateway: sync gateways/chassis between SB and IC-SB. */
    engine_add_input(&en_gateway, &en_icsb_availability_zone, NULL);
    engine_add_input(&en_gateway, &en_icsb_gateway, NULL);
    engine_add_input(&en_gateway, &en_icsb_encap, NULL);
    engine_add_input(&en_gateway, &en_sb_chassis, NULL);
    engine_add_input(&en_gateway, &en_sb_encap, NULL);

    /* en_ts: sync transit switches to NB and IC-SB datapath bindings. */
    engine_add_input(&en_ts, &en_dp_enum, NULL);
    engine_add_input(&en_ts, &en_icnb_ic_nb_global, NULL);
    engine_add_input(&en_ts, &en_icnb_transit_switch, NULL);
    engine_add_input(&en_ts, &en_nb_logical_switch, NULL);
    engine_add_input(&en_ts, &en_icsb_encap, NULL);

    /* en_tr: sync transit routers to NB and IC-SB datapath bindings. */
    engine_add_input(&en_tr, &en_dp_enum, NULL);
    engine_add_input(&en_tr, &en_icnb_transit_router, NULL);
    engine_add_input(&en_tr, &en_nb_logical_router, NULL);

    /* en_port_binding: sync cross-AZ port bindings. */
    engine_add_input(&en_port_binding, &en_icsb_availability_zone, NULL);
    engine_add_input(&en_port_binding, &en_icsb_port_binding, NULL);
    engine_add_input(&en_port_binding, &en_icnb_transit_switch, NULL);
    engine_add_input(&en_port_binding, &en_icnb_transit_router, NULL);
    engine_add_input(&en_port_binding, &en_icnb_transit_router_port, NULL);
    engine_add_input(&en_port_binding, &en_nb_logical_switch, NULL);
    engine_add_input(&en_port_binding, &en_nb_logical_switch_port, NULL);
    engine_add_input(&en_port_binding, &en_nb_logical_router, NULL);
    engine_add_input(&en_port_binding, &en_nb_logical_router_port, NULL);
    engine_add_input(&en_port_binding, &en_sb_port_binding, NULL);
    engine_add_input(&en_port_binding, &en_sb_chassis, NULL);

    /* en_route: advertise/learn cross-AZ routes. */
    engine_add_input(&en_route, &en_icsb_availability_zone, NULL);
    engine_add_input(&en_route, &en_icsb_port_binding, NULL);
    engine_add_input(&en_route, &en_icsb_route, NULL);
    engine_add_input(&en_route, &en_icnb_transit_switch, NULL);
    engine_add_input(&en_route, &en_nb_nb_global, NULL);
    engine_add_input(&en_route, &en_nb_logical_router, NULL);
    engine_add_input(&en_route, &en_nb_logical_router_port, NULL);
    engine_add_input(&en_route, &en_nb_logical_router_static_route, NULL);
    engine_add_input(&en_route, &en_nb_logical_switch_port, NULL);
    engine_add_input(&en_route, &en_nb_load_balancer, NULL);
    engine_add_input(&en_route, &en_nb_load_balancer_group, NULL);
    engine_add_input(&en_route, &en_sb_datapath_binding, NULL);
    engine_add_input(&en_route, &en_sb_learned_route, NULL);

    /* en_service_monitor: sync load-balancer health checks across AZs. */
    engine_add_input(&en_service_monitor, &en_icsb_availability_zone, NULL);
    engine_add_input(&en_service_monitor, &en_icsb_service_monitor, NULL);
    engine_add_input(&en_service_monitor, &en_sb_sb_global, NULL);
    engine_add_input(&en_service_monitor, &en_sb_service_monitor, NULL);
    engine_add_input(&en_service_monitor, &en_sb_port_binding, NULL);

    /* en_address_set: advertise/learn address sets across AZs. */
    engine_add_input(&en_address_set, &en_icsb_availability_zone, NULL);
    engine_add_input(&en_address_set, &en_nb_nb_global, NULL);
    engine_add_input(&en_address_set, &en_nb_address_set, NULL);
    engine_add_input(&en_address_set, &en_sb_address_set, NULL);
    engine_add_input(&en_address_set, &en_icsb_address_set, NULL);

    /* en_ic: output node aggregating all subsystems.  Order matches the
     * previous ovn_db_run() call order; in particular en_ts is added before
     * en_tr so they allocate datapath tunnel keys from the shared en_dp_enum
     * allocator in the same order as before. */
    engine_add_input(&en_ic, &en_gateway, NULL);
    engine_add_input(&en_ic, &en_ts, NULL);
    engine_add_input(&en_ic, &en_tr, NULL);
    engine_add_input(&en_ic, &en_port_binding, NULL);
    engine_add_input(&en_ic, &en_route, NULL);
    engine_add_input(&en_ic, &en_service_monitor, NULL);
    engine_add_input(&en_ic, &en_address_set, NULL);

    struct engine_arg engine_arg = {
        .nb_idl = nb->idl,
        .sb_idl = sb->idl,
        .icnb_idl = icnb->idl,
        .icsb_idl = icsb->idl,
    };

    engine_init(&en_ic, &engine_arg);
}

/* Returns true if the incremental processing ended up updating nodes. */
bool
inc_proc_ic_run(struct ic_context *ctx,
                struct ic_engine_context *ic_eng_ctx)
{
    ovs_assert(ctx->ovnnb_txn && ctx->ovnsb_txn &&
               ctx->ovninb_txn && ctx->ovnisb_unlocked_txn);

    int64_t start = time_msec();
    engine_init_run();

    struct engine_context eng_ctx = {
        .client_ctx = ctx,
    };

    engine_set_context(&eng_ctx);
    engine_run(true);

    if (!engine_has_run()) {
        if (engine_need_run()) {
            VLOG_DBG("engine did not run, force recompute next time.");
            engine_set_force_recompute_immediate();
        } else {
            VLOG_DBG("engine did not run, and it was not needed");
        }
    } else if (engine_canceled()) {
        VLOG_DBG("engine was canceled, force recompute next time.");
        engine_set_force_recompute_immediate();
    } else {
        engine_clear_force_recompute();
    }

    int64_t now = time_msec();
    /* Postpone the next run by length of current run with maximum capped
     * by "northd-backoff-interval-ms" interval. */
    ic_eng_ctx->next_run_ms = now + MIN(now - start, ic_eng_ctx->backoff_ms);

    return engine_has_updated();
}

void
inc_proc_ic_cleanup(void)
{
    engine_cleanup();
    engine_set_context(NULL);
}

bool
inc_proc_ic_can_run(struct ic_engine_context *ctx)
{
    if (engine_get_force_recompute() || time_msec() >= ctx->next_run_ms ||
        ctx->nb_idl_duration_ms >= IDL_LOOP_MAX_DURATION_MS ||
        ctx->sb_idl_duration_ms >= IDL_LOOP_MAX_DURATION_MS ||
        ctx->inb_idl_duration_ms >= IDL_LOOP_MAX_DURATION_MS ||
        ctx->isb_idl_duration_ms >= IDL_LOOP_MAX_DURATION_MS ||
        ctx->isb_unlock_idl_duration_ms >= IDL_LOOP_MAX_DURATION_MS) {
        return true;
    }

    poll_timer_wait_until(ctx->next_run_ms);
    return false;
}
