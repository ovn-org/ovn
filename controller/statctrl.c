/* Copyright (c) 2023, Red Hat, Inc.
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

#include "byte-order.h"
#include "dirs.h"
#include "latch.h"
#include "lflow.h"
#include "mac_cache.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/rconn.h"
#include "openvswitch/vlog.h"
#include "ovn/logical-fields.h"
#include "ovs-thread.h"
#include "seq.h"
#include "socket-util.h"
#include "statctrl.h"

VLOG_DEFINE_THIS_MODULE(statctrl);

enum stat_type {
    STATS_MAC_BINDING = 0,
    STATS_FDB,
    STATS_MAX,
};

struct stats_node {
    /* The statistics request. */
    struct  ofputil_flow_stats_request request;
    /* xid of the last statistics request. */
    ovs_be32 xid;
    /* Timestamp when the next request should happen. */
    int64_t next_request_timestamp;
    /* Request delay in ms. */
    uint64_t request_delay;
    /* List of processed statistics. */
    struct ovs_list stats_list;
    /* Function to clean up the node.
     * This function runs in main thread. */
    void (*destroy)(struct ovs_list *stats_list);
    /* Function to process the response and store it in the list.
     * This function runs in statctrl thread locked behind mutex. */
    void (*process_flow_stats)(struct ovs_list *stats_list,
                               struct ofputil_flow_stats *ofp_stats);
    /* Function to process the parsed stats.
     * This function runs in main thread locked behind mutex. */
    void (*run)(struct ovs_list *stats_list, uint64_t *req_delay, void *data);
};

#define STATS_NODE(NAME, REQUEST, DESTROY, PROCESS, RUN)                   \
    statctrl_ctx.nodes[STATS_##NAME] = (struct stats_node) {               \
        .request = REQUEST,                                                \
        .xid = 0,                                                          \
        .next_request_timestamp = INT64_MAX,                               \
        .request_delay = 0,                                                \
        .stats_list =                                                      \
            OVS_LIST_INITIALIZER(                                          \
                &statctrl_ctx.nodes[STATS_##NAME].stats_list),             \
        .destroy = DESTROY,                                                \
        .process_flow_stats = PROCESS,                                     \
        .run = RUN                                                         \
    };

struct statctrl_ctx {
    char *br_int;

    pthread_t thread;
    struct latch exit_latch;

    struct seq *thread_seq;
    struct seq *main_seq;

    struct stats_node nodes[STATS_MAX];
};

static struct statctrl_ctx statctrl_ctx;
static struct ovs_mutex mutex;

static void *statctrl_thread_handler(void *arg);
static void statctrl_rconn_setup(struct rconn *swconn, char *conn_target)
    OVS_REQUIRES(mutex);
static void statctrl_handle_rconn_msg(struct rconn *swconn,
                                      struct statctrl_ctx *ctx,
                                      struct ofpbuf *msg);
static enum stat_type statctrl_get_stat_type(struct statctrl_ctx *ctx,
                                             const struct ofp_header *oh);
static void statctrl_decode_statistics_reply(struct stats_node *node,
                                             struct ofpbuf *msg)
    OVS_REQUIRES(mutex);
static void statctrl_send_request(struct rconn *swconn,
                                  struct statctrl_ctx *ctx)
    OVS_REQUIRES(mutex);
static void statctrl_notify_main_thread(struct statctrl_ctx *ctx);
static void statctrl_set_conn_target(const char *br_int_name)
    OVS_REQUIRES(mutex);
static void statctrl_wait_next_request(struct statctrl_ctx *ctx)
    OVS_REQUIRES(mutex);
static bool statctrl_update_next_request_timestamp(struct stats_node *node,
                                                   long long now,
                                                   uint64_t prev_delay)
    OVS_REQUIRES(mutex);

void
statctrl_init(void)
{
    statctrl_ctx.br_int = NULL;
    latch_init(&statctrl_ctx.exit_latch);
    ovs_mutex_init(&mutex);
    statctrl_ctx.thread_seq = seq_create();
    statctrl_ctx.main_seq = seq_create();

    /* Definition of all stat nodes. */
    struct ofputil_flow_stats_request mac_binding_request = {
            .cookie = htonll(0),
            .cookie_mask = htonll(0),
            .out_port = OFPP_ANY,
            .out_group = OFPG_ANY,
            .table_id = OFTABLE_MAC_CACHE_USE,
    };
    STATS_NODE(MAC_BINDING, mac_binding_request, mac_cache_stats_destroy,
               mac_cache_mb_stats_process_flow_stats, mac_cache_mb_stats_run);

    struct ofputil_flow_stats_request fdb_request = {
            .cookie = htonll(0),
            .cookie_mask = htonll(0),
            .out_port = OFPP_ANY,
            .out_group = OFPG_ANY,
            .table_id = OFTABLE_LOOKUP_FDB,
    };
    STATS_NODE(FDB, fdb_request, mac_cache_stats_destroy,
               mac_cache_fdb_stats_process_flow_stats,
               mac_cache_fdb_stats_run);

    statctrl_ctx.thread = ovs_thread_create("ovn_statctrl",
                                            statctrl_thread_handler,
                                            &statctrl_ctx);
}

void
statctrl_run(struct ovsdb_idl_txn *ovnsb_idl_txn,
             struct mac_cache_data *mac_cache_data)
{
    if (!ovnsb_idl_txn) {
        return;
    }

    void *node_data[STATS_MAX] = {mac_cache_data, mac_cache_data};

    bool schedule_updated = false;
    long long now = time_msec();

    ovs_mutex_lock(&mutex);
    for (size_t i = 0; i < STATS_MAX; i++) {
        struct stats_node *node = &statctrl_ctx.nodes[i];
        uint64_t prev_delay = node->request_delay;

        node->run(&node->stats_list, &node->request_delay, node_data[i]);

        schedule_updated |=
                statctrl_update_next_request_timestamp(node, now, prev_delay);
    }
    ovs_mutex_unlock(&mutex);

    if (schedule_updated) {
        seq_change(statctrl_ctx.thread_seq);
    }
}

void
statctrl_update(const char *br_int_name)
{
    ovs_mutex_lock(&mutex);
    statctrl_set_conn_target(br_int_name);
    ovs_mutex_unlock(&mutex);
}

void
statctrl_wait(struct ovsdb_idl_txn *ovnsb_idl_txn)
{
    if (!ovnsb_idl_txn) {
        return;
    }

    ovs_mutex_lock(&mutex);
    for (size_t i = 0; i < STATS_MAX; i++) {
        struct stats_node *node = &statctrl_ctx.nodes[i];
        if (!ovs_list_is_empty(&node->stats_list)) {
            poll_immediate_wake();
        }
    }
    int64_t new_seq = seq_read(statctrl_ctx.main_seq);
    seq_wait(statctrl_ctx.main_seq, new_seq);
    ovs_mutex_unlock(&mutex);
}

void
statctrl_destroy(void)
{
    latch_set(&statctrl_ctx.exit_latch);
    pthread_join(statctrl_ctx.thread, NULL);
    latch_destroy(&statctrl_ctx.exit_latch);
    free(statctrl_ctx.br_int);
    seq_destroy(statctrl_ctx.thread_seq);
    seq_destroy(statctrl_ctx.main_seq);

    for (size_t i = 0; i < STATS_MAX; i++) {
        struct stats_node *node = &statctrl_ctx.nodes[i];
        node->destroy(&node->stats_list);
    }
}

static void *
statctrl_thread_handler(void *arg)
{
    struct statctrl_ctx *ctx = arg;

    /* OpenFlow connection to the switch. */
    struct rconn *swconn = rconn_create(0, 0, DSCP_DEFAULT,
                                        1 << OFP15_VERSION);

    while (!latch_is_set(&ctx->exit_latch)) {
        ovs_mutex_lock(&mutex);
        statctrl_rconn_setup(swconn, ctx->br_int);
        ovs_mutex_unlock(&mutex);

        rconn_run(swconn);
        uint64_t new_seq = seq_read(ctx->thread_seq);

        if (rconn_is_connected(swconn)) {
            for (int i = 0; i < 100; i++) {
                struct ofpbuf *msg = rconn_recv(swconn);

                if (!msg) {
                    break;
                }

                statctrl_handle_rconn_msg(swconn, ctx, msg);
                ofpbuf_delete(msg);
            }

            ovs_mutex_lock(&mutex);
            statctrl_send_request(swconn, ctx);
            ovs_mutex_unlock(&mutex);
        }

        statctrl_notify_main_thread(ctx);
        rconn_run_wait(swconn);
        rconn_recv_wait(swconn);
        ovs_mutex_lock(&mutex);
        statctrl_wait_next_request(ctx);
        ovs_mutex_unlock(&mutex);
        seq_wait(ctx->thread_seq, new_seq);
        latch_wait(&ctx->exit_latch);

        poll_block();
    }

    rconn_destroy(swconn);
    return NULL;
}

static void
statctrl_rconn_setup(struct rconn *swconn, char *br_int)
    OVS_REQUIRES(mutex)
{
    if (!br_int) {
        rconn_disconnect(swconn);
        return;
    }

    char *conn_target = xasprintf("unix:%s/%s.mgmt", ovs_rundir(), br_int);

    if (strcmp(conn_target, rconn_get_target(swconn))) {
        VLOG_INFO("%s: connecting to switch", conn_target);
        rconn_connect(swconn, conn_target, conn_target);
    }

    free(conn_target);
}

static void
statctrl_handle_rconn_msg(struct rconn *swconn, struct statctrl_ctx *ctx,
                          struct ofpbuf *msg)
{
    enum ofptype type;
    const struct ofp_header *oh = msg->data;

    ofptype_decode(&type, oh);

    if (type == OFPTYPE_ECHO_REQUEST) {
        rconn_send(swconn, ofputil_encode_echo_reply(oh), NULL);
    } else if (type == OFPTYPE_FLOW_STATS_REPLY) {
        enum stat_type stype = statctrl_get_stat_type(ctx, oh);
        if (stype == STATS_MAX) {
            return;
        }

        ovs_mutex_lock(&mutex);
        statctrl_decode_statistics_reply(&ctx->nodes[stype], msg);
        ovs_mutex_unlock(&mutex);
    } else {
        if (VLOG_IS_DBG_ENABLED()) {

            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

            char *s = ofp_to_string(oh, ntohs(oh->length), NULL, NULL, 2);

            VLOG_DBG_RL(&rl, "OpenFlow packet ignored: %s", s);
            free(s);
        }
    }
}

static enum stat_type
statctrl_get_stat_type(struct statctrl_ctx *ctx, const struct ofp_header *oh)
{
    for (size_t i = 0; i < STATS_MAX; i++) {
        if (ctx->nodes[i].xid == oh->xid) {
            return i;
        }
    }
    return STATS_MAX;
}

static void
statctrl_decode_statistics_reply(struct stats_node *node, struct ofpbuf *msg)
    OVS_REQUIRES(mutex)
{
    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 0);

    while (true) {
        struct ofputil_flow_stats fs;

        int error = ofputil_decode_flow_stats_reply(&fs, msg, true, &ofpacts);
        if (error == EOF) {
            break;
        } else if (error) {
            VLOG_DBG("Couldn't parse stat reply: %s", ofperr_to_string(error));
            break;
        }

        node->process_flow_stats(&node->stats_list, &fs);
    }

    ofpbuf_uninit(&ofpacts);
}

static void
statctrl_send_request(struct rconn *swconn, struct statctrl_ctx *ctx)
    OVS_REQUIRES(mutex)
{
    long long now = time_msec();
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);

    for (size_t i = 0; i < STATS_MAX; i++) {
        struct stats_node *node = &ctx->nodes[i];

        if (now < node->next_request_timestamp) {
            continue;
        }

        struct ofpbuf *msg =
                ofputil_encode_flow_stats_request(&node->request, proto);
        node->xid = ((struct ofp_header *) msg->data)->xid;

        statctrl_update_next_request_timestamp(node, now, 0);

        rconn_send(swconn, msg, NULL);
    }
}

static void
statctrl_notify_main_thread(struct statctrl_ctx *ctx)
{
    for (size_t i = 0; i < STATS_MAX; i++) {
        if (!ovs_list_is_empty(&ctx->nodes[i].stats_list)) {
            seq_change(ctx->main_seq);
            return;
        }
    }
}

static void
statctrl_set_conn_target(const char *br_int_name)
    OVS_REQUIRES(mutex)
{
    if (!br_int_name) {
        return;
    }


    if (!statctrl_ctx.br_int || strcmp(statctrl_ctx.br_int, br_int_name)) {
        free(statctrl_ctx.br_int);
        statctrl_ctx.br_int = xstrdup(br_int_name);
        /* Notify statctrl thread that integration bridge is set/changed. */
        seq_change(statctrl_ctx.thread_seq);
    }
}

static void
statctrl_wait_next_request(struct statctrl_ctx *ctx)
    OVS_REQUIRES(mutex)
{
    for (size_t i = 0; i < STATS_MAX; i++) {
        int64_t timestamp = ctx->nodes[i].next_request_timestamp;
        if (timestamp < INT64_MAX) {
            poll_timer_wait_until(timestamp);
        }
    }
}

static bool
statctrl_update_next_request_timestamp(struct stats_node *node,
                                       long long now, uint64_t prev_delay)
{
    if (!node->request_delay) {
        node->next_request_timestamp = INT64_MAX;
        return false;
    }

    int64_t timestamp = prev_delay ? node->next_request_timestamp : now;
    node->next_request_timestamp =
            timestamp + node->request_delay - prev_delay;

    return timestamp != node->next_request_timestamp;
}
