/* Copyright (c) 2022, Red Hat, Inc.
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

#include "lib/inc-proc-eng.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/timeval.h"
#include "northd/mac-binding-aging.h"
#include "northd/northd.h"
#include "openvswitch/hmap.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(mac_binding_aging);

#define AGING_BULK_REMOVAL_DELAY_MSEC 5000

struct aging_waker {
    bool should_schedule;
    long long next_wake_msec;
};

static void
aging_waker_schedule_next_wake(struct aging_waker *waker, int64_t next_wake_ms)
{
    waker->should_schedule = false;

    if (next_wake_ms < INT64_MAX) {
        waker->should_schedule = true;
        waker->next_wake_msec = time_msec() + next_wake_ms;
        poll_timer_wait_until(waker->next_wake_msec);
    }
}

struct aging_context {
    int64_t next_wake_ms;
    int64_t time_wall_now;
    uint32_t removal_limit;
    uint32_t n_removed;
    uint64_t threshold;
};

static struct aging_context
aging_context_init(uint32_t removal_limit)
{
    struct aging_context ctx = {
           .next_wake_ms = INT64_MAX,
           .time_wall_now = time_wall_msec(),
           .removal_limit = removal_limit,
           .n_removed = 0,
           .threshold = 0,
    };
    return ctx;
}

static void
aging_context_set_threshold(struct aging_context *ctx, uint64_t threshold)
{
    ctx->threshold = threshold;
}

static bool
aging_context_is_at_limit(struct aging_context *ctx)
{
    return ctx->removal_limit && ctx->n_removed == ctx->removal_limit;
}

static bool
aging_context_handle_timestamp(struct aging_context *ctx, int64_t timestamp)
{
    int64_t elapsed = ctx->time_wall_now - timestamp;
    if (elapsed < 0) {
        return false;
    }

    if (elapsed >= ctx->threshold) {
        ctx->n_removed++;
        return true;
    }

    ctx->next_wake_ms = MIN(ctx->next_wake_ms, (ctx->threshold - elapsed));
    return false;
}

static uint32_t
get_removal_limit(struct engine_node *node, const char *name)
{
    const struct nbrec_nb_global_table *nb_global_table =
            EN_OVSDB_GET(engine_get_input("NB_nb_global", node));
    const struct nbrec_nb_global *nb =
            nbrec_nb_global_table_first(nb_global_table);
    if (!nb) {
        return 0;
    }

    return smap_get_uint(&nb->options, name, 0);
}

static void
mac_binding_aging_run_for_datapath(const struct sbrec_datapath_binding *dp,
                                   struct ovsdb_idl_index *mb_by_datapath,
                                   struct aging_context *ctx)
{
    if (!ctx->threshold) {
        return;
    }

    struct sbrec_mac_binding *mb_index_row =
        sbrec_mac_binding_index_init_row(mb_by_datapath);
    sbrec_mac_binding_index_set_datapath(mb_index_row, dp);

    const struct sbrec_mac_binding *mb;
    SBREC_MAC_BINDING_FOR_EACH_EQUAL (mb, mb_index_row, mb_by_datapath) {
        if (aging_context_handle_timestamp(ctx, mb->timestamp)) {
            sbrec_mac_binding_delete(mb);
            if (aging_context_is_at_limit(ctx)) {
                break;
            }
        }
    }
    sbrec_mac_binding_index_destroy_row(mb_index_row);
}

void
en_mac_binding_aging_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    struct aging_waker *waker =
        engine_get_input_data("mac_binding_aging_waker", node);

    if (!eng_ctx->ovnsb_idl_txn ||
        !northd_data->features.mac_binding_timestamp ||
        time_msec() < waker->next_wake_msec) {
        return;
    }

    uint32_t limit = get_removal_limit(node, "mac_binding_removal_limit");
    struct aging_context ctx = aging_context_init(limit);

    struct ovsdb_idl_index *sbrec_mac_binding_by_datapath =
        engine_ovsdb_node_get_index(engine_get_input("SB_mac_binding", node),
                                    "sbrec_mac_binding_by_datapath");

    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &northd_data->lr_datapaths.datapaths) {
        ovs_assert(od->nbr);

        if (!od->sb) {
            continue;
        }

        uint64_t threshold = smap_get_uint(&od->nbr->options,
                                           "mac_binding_age_threshold", 0);
        aging_context_set_threshold(&ctx, threshold * 1000);

        mac_binding_aging_run_for_datapath(od->sb,
                                           sbrec_mac_binding_by_datapath,
                                           &ctx);
        if (aging_context_is_at_limit(&ctx)) {
            /* Schedule the next run after specified delay. */
            ctx.next_wake_ms = AGING_BULK_REMOVAL_DELAY_MSEC;
            break;
        }
    }

    aging_waker_schedule_next_wake(waker, ctx.next_wake_ms);

    engine_set_node_state(node, EN_UPDATED);
}

void *
en_mac_binding_aging_init(struct engine_node *node OVS_UNUSED,
                          struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_mac_binding_aging_cleanup(void *data OVS_UNUSED)
{
}

/* The waker node is an input node, but the data about when to wake up
 * the aging node are populated by the aging node.
 * The reason being that engine periodically runs input nodes to check
 * if we there are updates, so it could process the other nodes, however
 * the waker cannot be dependent on other node because it wouldn't be
 * input node anymore. */
void
en_mac_binding_aging_waker_run(struct engine_node *node, void *data)
{
    struct aging_waker *waker = data;

    engine_set_node_state(node, EN_UNCHANGED);

    if (!waker->should_schedule) {
        return;
    }

    if (time_msec() >= waker->next_wake_msec) {
        waker->should_schedule = false;
        engine_set_node_state(node, EN_UPDATED);
        return;
    }

    poll_timer_wait_until(waker->next_wake_msec);
}

void *
en_mac_binding_aging_waker_init(struct engine_node *node OVS_UNUSED,
                                struct engine_arg *arg OVS_UNUSED)
{
    struct aging_waker *waker = xmalloc(sizeof *waker);

    waker->should_schedule = false;
    waker->next_wake_msec = 0;

    return waker;
}

void
en_mac_binding_aging_waker_cleanup(void *data OVS_UNUSED)
{
}
