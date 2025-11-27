/*
 * Copyright (c) 2018 eBay Inc.
 *
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

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovsdb-idl.h"
#include "inc-proc-eng.h"
#include "timeval.h"
#include "unixctl.h"
#include "vec.h"
#include "sset.h"

VLOG_DEFINE_THIS_MODULE(inc_proc_eng);

static bool engine_force_recompute = false;
static bool engine_run_canceled = false;
static const struct engine_context *engine_context;

static struct vector engine_nodes =
    VECTOR_EMPTY_INITIALIZER(struct engine_node *);

static const char *engine_node_state_name[EN_STATE_MAX] = {
    [EN_STALE]     = "Stale",
    [EN_UPDATED]   = "Updated",
    [EN_UNCHANGED] = "Unchanged",
    [EN_CANCELED]   = "Canceled",
};

static long long engine_compute_log_timeout_msec = 500;

static void
engine_recompute(struct engine_node *node, bool allowed,
                 const char *reason_fmt, ...) OVS_PRINTF_FORMAT(3, 4);

void
engine_set_force_recompute(void)
{
    engine_force_recompute = true;
}

void
engine_set_force_recompute_immediate(void)
{
    engine_force_recompute = true;
    poll_immediate_wake();
}

void
engine_clear_force_recompute(void)
{
    engine_force_recompute = false;
}

bool
engine_get_force_recompute(void)
{
    return engine_force_recompute;
}

const struct engine_context *
engine_get_context(void)
{
    return engine_context;
}

void
engine_set_context(const struct engine_context *ctx)
{
    engine_context = ctx;
}

/* Builds the topologically sorted 'sorted_nodes' array starting from
 * 'node'.
 */
static void
engine_topo_sort(struct engine_node *node, struct vector *sorted_nodes)
{
    /* It's not so efficient to walk the array of already sorted nodes but
     * we know that sorting is done only once at startup so it's ok for now.
     */
    struct engine_node *sorted_node;
    VECTOR_FOR_EACH (sorted_nodes, sorted_node) {
        if (sorted_node == node) {
            return;
        }
    }

    for (size_t i = 0; i < node->n_inputs; i++) {
        engine_topo_sort(node->inputs[i].node, sorted_nodes);
    }

    vector_push(sorted_nodes, &node);
}

static void
engine_clear_stats(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *arg OVS_UNUSED)
{
    struct engine_node *node;
    VECTOR_FOR_EACH (&engine_nodes, node) {
        memset(&node->stats, 0, sizeof node->stats);
    }
    unixctl_command_reply(conn, NULL);
}

static void
engine_dump_stats(struct unixctl_conn *conn, int argc,
                  const char *argv[], void *arg OVS_UNUSED)
{
    struct ds dump = DS_EMPTY_INITIALIZER;
    const char *dump_eng_node_name = (argc > 1 ? argv[1] : NULL);
    const char *dump_stat_type = (argc > 2 ? argv[2] : NULL);

    struct engine_node *node;
    VECTOR_FOR_EACH (&engine_nodes, node) {
        if (dump_eng_node_name && strcmp(node->name, dump_eng_node_name)) {
            continue;
        }

        if (!dump_stat_type) {
            ds_put_format(&dump,
                         "Node: %s\n"
                         "- recompute: %12"PRIu64"\n"
                         "- compute:   %12"PRIu64"\n"
                         "- cancel:    %12"PRIu64"\n",
                         node->name, node->stats.recompute,
                         node->stats.compute, node->stats.cancel);
        } else {
            if (!strcmp(dump_stat_type, "recompute")) {
                ds_put_format(&dump, "%"PRIu64, node->stats.recompute);
            } else if (!strcmp(dump_stat_type, "compute")) {
                ds_put_format(&dump, "%"PRIu64, node->stats.compute);
            } else if (!strcmp(dump_stat_type, "cancel")) {
                ds_put_format(&dump, "%"PRIu64, node->stats.cancel);
            } else {
                ds_put_format(&dump, "Invalid stat type : %s", dump_stat_type);
            }
        }

        if (dump_eng_node_name) {
            break;
        }
    }

    unixctl_command_reply(conn, ds_cstr(&dump));

    ds_destroy(&dump);
}

static void
engine_trigger_recompute_cmd(struct unixctl_conn *conn, int argc OVS_UNUSED,
                             const char *argv[] OVS_UNUSED,
                             void *arg OVS_UNUSED)
{
    engine_trigger_recompute();
    unixctl_command_reply(conn, NULL);
}

static void
engine_set_log_timeout_cmd(struct unixctl_conn *conn, int argc OVS_UNUSED,
                           const char *argv[], void *arg OVS_UNUSED)
{

    unsigned int timeout;
    if (!str_to_uint(argv[1], 10, &timeout)) {
        unixctl_command_reply_error(conn, "unsigned integer required");
        return;
    }
    engine_compute_log_timeout_msec = timeout;
    unixctl_command_reply(conn, NULL);
}

static void
engine_get_compute_failure_info(struct engine_node *node)
{
    VLOG_DBG("Node \"%s\" is missing compute failure debug info.", node->name);
}

void
engine_init(struct engine_node *node, struct engine_arg *arg)
{
    engine_topo_sort(node, &engine_nodes);

    struct engine_node *sorted_node;
    VECTOR_FOR_EACH (&engine_nodes, sorted_node) {
        if (sorted_node->init) {
            sorted_node->data = sorted_node->init(sorted_node, arg);
        } else {
            sorted_node->data = NULL;
        }
        if (!sorted_node->get_compute_failure_info) {
            /* Provide default get_compute_failure_info implementation. */
            sorted_node->get_compute_failure_info =
                engine_get_compute_failure_info;
        }
    }

    unixctl_command_register("inc-engine/show-stats", "", 0, 2,
                             engine_dump_stats, NULL);
    unixctl_command_register("inc-engine/clear-stats", "", 0, 0,
                             engine_clear_stats, NULL);
    unixctl_command_register("inc-engine/recompute", "", 0, 0,
                             engine_trigger_recompute_cmd, NULL);
    unixctl_command_register("inc-engine/compute-log-timeout", "", 1, 1,
                             engine_set_log_timeout_cmd, NULL);
}

void
engine_cleanup(void)
{
    struct engine_node *node;
    VECTOR_FOR_EACH (&engine_nodes, node) {
        if (node->clear_tracked_data) {
            node->clear_tracked_data(node->data);
        }

        if (node->cleanup) {
            node->cleanup(node->data);
        }
        free(node->data);
    }
    vector_destroy(&engine_nodes);
}

struct engine_node *
engine_get_input(const char *input_name, struct engine_node *node)
{
    size_t i;
    for (i = 0; i < node->n_inputs; i++) {
        if (!strcmp(node->inputs[i].node->name, input_name)) {
            return node->inputs[i].node;
        }
    }
    OVS_NOT_REACHED();
    return NULL;
}

void *
engine_get_input_data(const char *input_name, struct engine_node *node)
{
    struct engine_node *input_node = engine_get_input(input_name, node);
    return engine_get_data(input_node);
}

void
engine_add_input_impl(struct engine_node *node, struct engine_node *input,
                      enum engine_input_handler_result (*change_handler)
                          (struct engine_node *, void *),
                      const char *change_handler_name)
{
    ovs_assert(node->n_inputs < ENGINE_MAX_INPUT);
    node->inputs[node->n_inputs].node = input;
    node->inputs[node->n_inputs].change_handler = change_handler;
    node->inputs[node->n_inputs].change_handler_name = change_handler_name;
    node->n_inputs ++;
}

void
engine_add_input_with_compute_debug_impl(
        struct engine_node *node, struct engine_node *input,
        enum engine_input_handler_result (*change_handler)
            (struct engine_node *, void *),
        void (*get_compute_failure_info)(struct engine_node *),
        const char *change_handler_name)
{
    engine_add_input_impl(node, input, change_handler, change_handler_name);
    node->get_compute_failure_info = get_compute_failure_info;
}

struct ovsdb_idl_index *
engine_ovsdb_node_get_index(struct engine_node *node, const char *name)
{
    struct ed_type_ovsdb_table *ed = node->data;
    for (size_t i = 0; i < ed->n_indexes; i++) {
        if (!strcmp(ed->indexes[i].name, name)) {
            return ed->indexes[i].index;
        }
    }
    OVS_NOT_REACHED();
    return NULL;
}

void
engine_ovsdb_node_add_index(struct engine_node *node, const char *name,
                            struct ovsdb_idl_index *index)
{
    struct ed_type_ovsdb_table *ed = node->data;
    ovs_assert(ed->n_indexes < ENGINE_MAX_OVSDB_INDEX);

    ed->indexes[ed->n_indexes].name = name;
    ed->indexes[ed->n_indexes].index = index;
    ed->n_indexes ++;
}

static void
engine_set_node_state(struct engine_node *node,
                      enum engine_node_state state,
                      const char *reason_fmt, ...)
{
    if (node->state == state) {
        return;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        va_list args;
        va_start(args, reason_fmt);
        char *reason = xvasprintf(reason_fmt, args);
        VLOG_DBG("node: %s, old_state %s, new_state %s, reason: %s.",
                 node->name, engine_node_state_name[node->state],
                 engine_node_state_name[state], reason);
        va_end(args);
        free(reason);
    }

    node->state = state;
}

static bool
engine_node_valid(struct engine_node *node)
{
    if (node->state == EN_UPDATED || node->state == EN_UNCHANGED) {
        return true;
    }

    if (node->is_valid) {
        return node->is_valid(node);
    }
    return false;
}

bool
engine_node_changed(struct engine_node *node)
{
    return node->state == EN_UPDATED;
}

bool
engine_has_run(void)
{
    struct engine_node *node;
    VECTOR_FOR_EACH (&engine_nodes, node) {
        if (node->state != EN_STALE) {
            return true;
        }
    }
    return false;
}

bool
engine_has_updated(void)
{
    struct engine_node *node;
    VECTOR_FOR_EACH (&engine_nodes, node) {
        if (node->state == EN_UPDATED) {
            return true;
        }
    }
    return false;
}

bool
engine_canceled(void)
{
    return engine_run_canceled;
}

void *
engine_get_data(struct engine_node *node)
{
    if (engine_node_valid(node)) {
        return node->data;
    }
    return NULL;
}

void *
engine_get_internal_data(struct engine_node *node)
{
    return node->data;
}

void
engine_init_run(void)
{
    VLOG_DBG("Initializing new run");
    struct engine_node *node;
    VECTOR_FOR_EACH (&engine_nodes, node) {
        engine_set_node_state(node, EN_STALE, "engine_init_run");

        if (node->clear_tracked_data) {
            node->clear_tracked_data(node->data);
        }
    }
}

/* Do a full recompute (or at least try). If we're not allowed then
 * mark the node as "canceled".
 */
static void
engine_recompute(struct engine_node *node, bool allowed,
                 const char *reason_fmt, ...)
{
    char *reason = NULL;
    va_list reason_args;

    va_start(reason_args, reason_fmt);
    reason = xvasprintf(reason_fmt, reason_args);
    va_end(reason_args);

    if (node->sb_write && !allowed) {
        VLOG_DBG("node: %s, recompute (%s) canceled", node->name, reason);
        engine_set_node_state(node, EN_CANCELED, "recompute not allowed");
        goto done;
    }

    /* Clear tracked data before calling run() so that partially tracked data
     * from some of the change handler executions are cleared. */
    if (node->clear_tracked_data) {
        node->clear_tracked_data(node->data);
    }

    /* Run the node handler which might change state. */
    long long int now = time_msec();
    engine_set_node_state(node, node->run(node, node->data),
                          "recompute run() result");
    node->stats.recompute++;
    long long int delta_time = time_msec() - now;
    if (delta_time > engine_compute_log_timeout_msec) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(20, 10);
        VLOG_INFO_RL(&rl, "node: %s, recompute (%s) took %lldms", node->name,
                     reason, delta_time);
    } else {
        VLOG_DBG("node: %s, recompute (%s) took %lldms", node->name, reason,
                 delta_time);
    }
done:
    free(reason);
}

/* Return true if the node could be computed, false otherwise. */
static bool
engine_compute(struct engine_node *node, bool recompute_allowed)
{
    for (size_t i = 0; i < node->n_inputs; i++) {
        struct engine_node *input_node = node->inputs[i].node;

        /* If the input node data changed call its change handler. */
        if (input_node->state == EN_UPDATED) {
            /* If the input change can't be handled incrementally, run
             * the node handler.
             */
            long long int now = time_msec();
            enum engine_input_handler_result handled;
            handled = node->inputs[i].change_handler(node, node->data);
            long long int delta_time = time_msec() - now;
            if (delta_time > engine_compute_log_timeout_msec) {
                static struct vlog_rate_limit rl =
                    VLOG_RATE_LIMIT_INIT(20, 10);
                VLOG_INFO_RL(&rl, "node: %s, handler for input %s took %lldms",
                             node->name, input_node->name, delta_time);
            } else {
                VLOG_DBG("node: %s, handler for input %s took %lldms",
                         node->name, input_node->name, delta_time);
            }
            if (handled == EN_UNHANDLED) {
                input_node->get_compute_failure_info(input_node);
                engine_recompute(node, recompute_allowed,
                                 "failed handler for input %s",
                                 input_node->name);
                return (node->state != EN_CANCELED);
            } else if (!engine_node_changed(node)) {
                /* We only want to update the state if the node is unchanged.
                 * Otherwise, handlers might change the state from EN_UPDATED
                 * back to EN_UNCHANGED.
                 */
                engine_set_node_state(node, (enum engine_node_state) handled,
                                      "input %s updated", input_node->name);
            }
        }
    }
    node->stats.compute++;

    return true;
}

static void
engine_run_node(struct engine_node *node, bool recompute_allowed)
{
    if (!node->n_inputs) {
        /* Run the node handler which might change state. */
        engine_set_node_state(node, node->run(node, node->data),
                              "run() result due to having no inputs");
        node->stats.recompute++;
        return;
    }

    if (engine_force_recompute) {
        engine_recompute(node, recompute_allowed, "forced");
        return;
    }

    /* If any of the inputs updated data but there is no change_handler, then
     * recompute the current node too.
     */
    bool need_compute = false;
    for (size_t i = 0; i < node->n_inputs; i++) {
        struct engine_node *input_node = node->inputs[i].node;
        if (input_node->state == EN_UPDATED) {
            need_compute = true;

            /* Trigger a recompute if we don't have a change handler. */
            if (!node->inputs[i].change_handler) {
                engine_recompute(node, recompute_allowed,
                                 "missing handler for input %s",
                                 input_node->name);
                input_node->get_compute_failure_info(input_node);
                return;
            }
        }
    }

    if (need_compute) {
        /* If we couldn't compute the node we either canceled or triggered
         * a full recompute. In any case, stop processing.
         */
        if (!engine_compute(node, recompute_allowed)) {
            return;
        }
    }

    /* If we reached this point, either the node was updated or its state is
     * still valid.
     */
    if (!engine_node_changed(node)) {
        engine_set_node_state(node, EN_UNCHANGED, "no change detected");
    }
}

void
engine_run(bool recompute_allowed)
{
    /* If the last run was canceled skip the incremental run because a
     * recompute is needed first.
     */
    if (!recompute_allowed && engine_run_canceled) {
        return;
    }

    struct ovsdb_idl_txn *sb_txn = engine_get_context()->ovnsb_idl_txn;

    engine_run_canceled = false;
    struct engine_node *node;
    VECTOR_FOR_EACH (&engine_nodes, node) {
        ovsdb_idl_txn_assert_read_only(sb_txn, !node->sb_write);
        engine_run_node(node, recompute_allowed);
        ovsdb_idl_txn_assert_read_only(sb_txn, false);

        if (node->state == EN_CANCELED) {
            node->stats.cancel++;
            engine_run_canceled = true;
            return;
        }
    }
}

bool
engine_need_run(void)
{
    struct engine_node *node;
    VECTOR_FOR_EACH (&engine_nodes, node) {
        /* Check only leaf nodes for updates. */
        if (node->n_inputs) {
            continue;
        }

        engine_set_node_state(node, node->run(node, node->data),
                              "checking if engine needs to be run");
        node->stats.recompute++;
        VLOG_DBG("input node: %s, state: %s", node->name,
                 engine_node_state_name[node->state]);
        if (node->state == EN_UPDATED) {
            return true;
        }
    }
    return false;
}

void
engine_trigger_recompute(void)
{
    VLOG_INFO("User triggered force recompute.");
    engine_set_force_recompute_immediate();
}

static void
engine_dump_node(struct engine_node *node, struct sset *visited_nodes)
{
    if (sset_contains(visited_nodes, node->name)) {
        return;
    }
    sset_add(visited_nodes, node->name);

    printf("\t%s [style=filled, shape=box, fillcolor=white, "
           "label=\"%s\"];\n",
           node->name, node->name);
    for (size_t i = 0; i < node->n_inputs; i++) {
        const char *label = node->inputs[i].change_handler
                            ? node->inputs[i].change_handler_name
                            : NULL;

        printf("\t%s -> %s [label=\"%s\"];\n",
               node->inputs[i].node->name, node->name,
               label ? label : "");

        engine_dump_node(node->inputs[i].node, visited_nodes);
    }
}

void
engine_dump_graph(const char *node_name)
{
    printf("digraph \"Incremental-Processing-Engine\" {\n");
    printf("\trankdir=LR;\n");

    struct sset visited_nodes = SSET_INITIALIZER(&visited_nodes);
    struct engine_node *node;
    VECTOR_FOR_EACH (&engine_nodes, node) {
        if (node_name && strcmp(node->name, node_name)) {
            continue;
        }

        engine_dump_node(node, &visited_nodes);

        if (node_name) {
            break;
        }
    }

    sset_destroy(&visited_nodes);
    printf("}\n");
}
