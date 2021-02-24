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
#include "openvswitch/vlog.h"
#include "inc-proc-eng.h"
#include "unixctl.h"

VLOG_DEFINE_THIS_MODULE(inc_proc_eng);

static bool engine_force_recompute = false;
static bool engine_run_aborted = false;
static const struct engine_context *engine_context;

static struct engine_node **engine_nodes;
static size_t engine_n_nodes;

static const char *engine_node_state_name[EN_STATE_MAX] = {
    [EN_STALE]     = "Stale",
    [EN_UPDATED]   = "Updated",
    [EN_UNCHANGED] = "Unchanged",
    [EN_ABORTED]   = "Aborted",
};

void
engine_set_force_recompute(bool val)
{
    engine_force_recompute = val;
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
static struct engine_node **
engine_topo_sort(struct engine_node *node, struct engine_node **sorted_nodes,
                 size_t *n_count, size_t *n_size)
{
    /* It's not so efficient to walk the array of already sorted nodes but
     * we know that sorting is done only once at startup so it's ok for now.
     */
    for (size_t i = 0; i < *n_count; i++) {
        if (sorted_nodes[i] == node) {
            return sorted_nodes;
        }
    }

    for (size_t i = 0; i < node->n_inputs; i++) {
        sorted_nodes = engine_topo_sort(node->inputs[i].node, sorted_nodes,
                                        n_count, n_size);
    }
    if (*n_count == *n_size) {
        sorted_nodes = x2nrealloc(sorted_nodes, n_size, sizeof *sorted_nodes);
    }
    sorted_nodes[(*n_count)] = node;
    (*n_count)++;
    return sorted_nodes;
}

/* Return the array of topologically sorted nodes when starting from
 * 'node'. Stores the number of nodes in 'n_count'.
 */
static struct engine_node **
engine_get_nodes(struct engine_node *node, size_t *n_count)
{
    size_t n_size = 0;

    *n_count = 0;
    return engine_topo_sort(node, NULL, n_count, &n_size);
}

static void
engine_clear_stats(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *arg OVS_UNUSED)
{
    for (size_t i = 0; i < engine_n_nodes; i++) {
        struct engine_node *node = engine_nodes[i];

        memset(&node->stats, 0, sizeof node->stats);
    }
    unixctl_command_reply(conn, NULL);
}

static void
engine_dump_stats(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *arg OVS_UNUSED)
{
    struct ds dump = DS_EMPTY_INITIALIZER;

    for (size_t i = 0; i < engine_n_nodes; i++) {
        struct engine_node *node = engine_nodes[i];

        ds_put_format(&dump,
                      "Node: %s\n"
                      "- recompute: %12"PRIu64"\n"
                      "- compute:   %12"PRIu64"\n"
                      "- abort:     %12"PRIu64"\n",
                      node->name, node->stats.recompute,
                      node->stats.compute, node->stats.abort);
    }
    unixctl_command_reply(conn, ds_cstr(&dump));

    ds_destroy(&dump);
}

void
engine_init(struct engine_node *node, struct engine_arg *arg)
{
    engine_nodes = engine_get_nodes(node, &engine_n_nodes);

    for (size_t i = 0; i < engine_n_nodes; i++) {
        if (engine_nodes[i]->init) {
            engine_nodes[i]->data =
                engine_nodes[i]->init(engine_nodes[i], arg);
        } else {
            engine_nodes[i]->data = NULL;
        }
    }

    unixctl_command_register("inc-engine/show-stats", "", 0, 0,
                             engine_dump_stats, NULL);
    unixctl_command_register("inc-engine/clear-stats", "", 0, 0,
                             engine_clear_stats, NULL);
}

void
engine_cleanup(void)
{
    for (size_t i = 0; i < engine_n_nodes; i++) {
        if (engine_nodes[i]->clear_tracked_data) {
            engine_nodes[i]->clear_tracked_data(engine_nodes[i]->data);
        }

        if (engine_nodes[i]->cleanup) {
            engine_nodes[i]->cleanup(engine_nodes[i]->data);
        }
        free(engine_nodes[i]->data);
    }
    free(engine_nodes);
    engine_nodes = NULL;
    engine_n_nodes = 0;
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
engine_add_input(struct engine_node *node, struct engine_node *input,
                 bool (*change_handler)(struct engine_node *, void *))
{
    ovs_assert(node->n_inputs < ENGINE_MAX_INPUT);
    node->inputs[node->n_inputs].node = input;
    node->inputs[node->n_inputs].change_handler = change_handler;
    node->n_inputs ++;
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

void
engine_set_node_state_at(struct engine_node *node,
                         enum engine_node_state state,
                         const char *where)
{
    if (node->state == state) {
        return;
    }

    VLOG_DBG("%s: node: %s, old_state %s, new_state %s",
             where, node->name,
             engine_node_state_name[node->state],
             engine_node_state_name[state]);

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
    for (size_t i = 0; i < engine_n_nodes; i++) {
        if (engine_nodes[i]->state != EN_STALE) {
            return true;
        }
    }
    return false;
}

bool
engine_aborted(void)
{
    return engine_run_aborted;
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
    for (size_t i = 0; i < engine_n_nodes; i++) {
        engine_set_node_state(engine_nodes[i], EN_STALE);

        if (engine_nodes[i]->clear_tracked_data) {
            engine_nodes[i]->clear_tracked_data(engine_nodes[i]->data);
        }
    }
}

/* Do a full recompute (or at least try). If we're not allowed then
 * mark the node as "aborted".
 */
static void
engine_recompute(struct engine_node *node, bool forced, bool allowed)
{
    VLOG_DBG("node: %s, recompute (%s)", node->name,
             forced ? "forced" : "triggered");

    if (!allowed) {
        VLOG_DBG("node: %s, recompute aborted", node->name);
        engine_set_node_state(node, EN_ABORTED);
        return;
    }

    /* Run the node handler which might change state. */
    node->run(node, node->data);
    node->stats.recompute++;
}

/* Return true if the node could be computed, false otherwise. */
static bool
engine_compute(struct engine_node *node, bool recompute_allowed)
{
    for (size_t i = 0; i < node->n_inputs; i++) {
        /* If the input node data changed call its change handler. */
        if (node->inputs[i].node->state == EN_UPDATED) {
            VLOG_DBG("node: %s, handle change for input %s",
                     node->name, node->inputs[i].node->name);

            /* If the input change can't be handled incrementally, run
             * the node handler.
             */
            if (!node->inputs[i].change_handler(node, node->data)) {
                VLOG_DBG("node: %s, can't handle change for input %s, "
                         "fall back to recompute",
                         node->name, node->inputs[i].node->name);
                engine_recompute(node, false, recompute_allowed);
                return (node->state != EN_ABORTED);
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
        node->run(node, node->data);
        node->stats.recompute++;
        return;
    }

    if (engine_force_recompute) {
        engine_recompute(node, true, recompute_allowed);
        return;
    }

    /* If any of the inputs updated data but there is no change_handler, then
     * recompute the current node too.
     */
    bool need_compute = false;
    for (size_t i = 0; i < node->n_inputs; i++) {
        if (node->inputs[i].node->state == EN_UPDATED) {
            need_compute = true;

            /* Trigger a recompute if we don't have a change handler. */
            if (!node->inputs[i].change_handler) {
                engine_recompute(node, false, recompute_allowed);
                return;
            }
        }
    }

    if (need_compute) {
        /* If we couldn't compute the node we either aborted or triggered
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
        engine_set_node_state(node, EN_UNCHANGED);
    }
}

void
engine_run(bool recompute_allowed)
{
    /* If the last run was aborted skip the incremental run because a
     * recompute is needed first.
     */
    if (!recompute_allowed && engine_run_aborted) {
        return;
    }

    engine_run_aborted = false;
    for (size_t i = 0; i < engine_n_nodes; i++) {
        engine_run_node(engine_nodes[i], recompute_allowed);

        if (engine_nodes[i]->state == EN_ABORTED) {
            engine_nodes[i]->stats.abort++;
            engine_run_aborted = true;
            return;
        }
    }
}

bool
engine_need_run(void)
{
    for (size_t i = 0; i < engine_n_nodes; i++) {
        /* Check only leaf nodes for updates. */
        if (engine_nodes[i]->n_inputs) {
            continue;
        }

        engine_nodes[i]->run(engine_nodes[i], engine_nodes[i]->data);
        engine_nodes[i]->stats.recompute++;
        VLOG_DBG("input node: %s, state: %s", engine_nodes[i]->name,
                 engine_node_state_name[engine_nodes[i]->state]);
        if (engine_nodes[i]->state == EN_UPDATED) {
            return true;
        }
    }
    return false;
}
