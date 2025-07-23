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

/* OVS includes. */
#include "bitmap.h"
#include "byte-order.h"
#include "dirs.h"
#include "dp-packet.h"
#include "flow.h"
#include "hash.h"
#include "hindex.h"
#include "lib/socket-util.h"
#include "lib/util.h"
#include "lib/vswitch-idl.h"
#include "openflow/openflow.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-bundle.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-group.h"
#include "openvswitch/ofp-match.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-meter.h"
#include "openvswitch/ofp-packet.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/rconn.h"

/* OVN includes. */
#include "br-flow-mgr.h"
#include "en-bridge-data.h"
#include "br-ofctrl.h"
#include "lib/ovn-util.h"
#include "lib/ovn-br-idl.h"

VLOG_DEFINE_THIS_MODULE(brofctrl);

/* TODO:  This file borrows a lot of code from controller/ofctrl.c.
 *        Move the generic ofctrl handling to lib/ofctrl.c and use
 *        it in br-controller/br-ofctrl.c and controller/ofctrl.c
 */

/* Connection state machine. */
#define STATES                                  \
    STATE(S_NEW)                                \
    STATE(S_WAIT_BEFORE_CLEAR)                  \
    STATE(S_CLEAR_FLOWS)                        \
    STATE(S_UPDATE_FLOWS)

enum br_ofctrl_state {
#define STATE(NAME) NAME,
    STATES
#undef STATE
};

/* An in-flight update to the switch's flow table.
 *
 * When we receive a barrier reply from the switch with the given 'xid', we
 * know that the switch is caught up to the requested sequence number
 * 'req_cfg' (and make that available to the client via
 * br_ofctrl_get_cur_cfg(), so that it can store it into external state. */
struct br_ofctrl_flow_update {
    struct ovs_list list_node;  /* In 'flow_updates'. */
    ovs_be32 xid;               /* OpenFlow transaction ID for barrier. */
    uint64_t req_cfg;           /* Requested sequence number. */
};

struct br_ofctrl {
    struct hmap_node hmap_node;
    char *bridge; /* key. */

    /* OpenFlow connection to the switch. */
    struct rconn *swconn;
    int probe_interval;
    char *conn_target;

    unsigned int wait_before_clear_time;
    /* The time when the state S_WAIT_BEFORE_CLEAR should complete.
     * If the timer is not started yet, it is set to 0. */
    long long int wait_before_clear_expire;

    /* Currently in-flight updates. */
    struct ovs_list flow_updates;

    /* req_cfg of latest committed flow update. */
    uint64_t cur_cfg;
    uint64_t old_req_cfg;
    bool skipped_last_time;

    /* Indicates if we just went through the S_CLEAR_FLOWS state, which means
     * we need to perform a one time deletion for all the existing flows,
     * groups and meters. This can happen during initialization or OpenFlow
     * reconnection (e.g. after OVS restart). */
    bool br_ofctrl_initial_clear;

    /* Last seen sequence number for 'swconn'.  When this differs from
     * rconn_get_connection_seqno(rconn), 'swconn' has reconnected. */
    unsigned int seqno;

    /* Counter for in-flight OpenFlow messages on 'swconn'.  We only send a new
     * round of flow table modifications to the switch when the counter falls
     * to zero, to avoid unbounded buffering. */
    struct rconn_packet_counter *tx_counter;

    /* Current state. */
    enum br_ofctrl_state state;
};

static struct hmap br_ofctrls = HMAP_INITIALIZER(&br_ofctrls);

static struct br_ofctrl *br_ofctrl_get(const char *bridge);
static void br_ofctrl_put(struct br_ofctrl *br_ofctrl, uint64_t req_cfg,
                          bool lflows_changed, bool pflows_changed);
static void br_ofctrl_destroy(struct br_ofctrl *);
static ovs_be32 queue_msg(struct br_ofctrl *, struct ofpbuf *);
static struct br_ofctrl_flow_update *br_ofctrl_flow_update_from_list_node(
    const struct ovs_list *);
static bool br_ofctrl_run__(struct br_ofctrl *);
static bool br_ofctrl_has_backlog(struct br_ofctrl *);
static bool br_ofctrl_can_put(struct br_ofctrl *);

void
br_ofctrls_init(void)
{

}

void
br_ofctrls_destroy(void)
{
    struct br_ofctrl *br_ofctrl;
    HMAP_FOR_EACH_POP (br_ofctrl, hmap_node, &br_ofctrls) {
        br_ofctrl_destroy(br_ofctrl);
    }

    hmap_destroy(&br_ofctrls);
}

void
br_ofctrls_add_or_update_bridge(struct ovn_bridge *br)
{
    ovs_assert(br->ovs_br);

    struct br_ofctrl *br_ofctrl = br_ofctrl_get(br->db_br->name);

    if (!br_ofctrl) {
        br_ofctrl = xzalloc(sizeof *br_ofctrl);
        br_ofctrl->bridge = xstrdup(br->db_br->name);
        br_ofctrl->swconn = rconn_create(0, 0, DSCP_DEFAULT,
                                         1 << OFP15_VERSION);
        br_ofctrl->tx_counter = rconn_packet_counter_create();
        ovs_list_init(&br_ofctrl->flow_updates);

        hmap_insert(&br_ofctrls, &br_ofctrl->hmap_node,
                    hash_string(br_ofctrl->bridge, 0));
    } else {
        free(br_ofctrl->conn_target);
    }

    br_ofctrl->probe_interval = br->probe_interval;
    br_ofctrl->conn_target = xstrdup(br->conn_target);
    br_ofctrl->wait_before_clear_time = br->wait_before_clear_time;
}

void
br_ofctrls_remove_bridge(const char *bridge)
{
    struct br_ofctrl *br_ofctrl = br_ofctrl_get(bridge);
    if (br_ofctrl) {
        hmap_remove(&br_ofctrls, &br_ofctrl->hmap_node);
        br_ofctrl_destroy(br_ofctrl);
    }
}

void
br_ofctrls_get_bridges(struct sset *managed_bridges)
{
    struct br_ofctrl *br_ofctrl;
    HMAP_FOR_EACH (br_ofctrl, hmap_node, &br_ofctrls) {
        sset_add(managed_bridges, br_ofctrl->bridge);
    }
}

/* Runs the OpenFlow state machine against each bridge in the br_ofctrls hmap,
 * which is local to the hypervisor on which we are running.
 *
 * Returns 'true' if an OpenFlow reconnect happened for any of the bridge;
 * 'false' otherwise.
 */
bool
br_ofctrls_run(void)
{
    bool reconnected = false;

    struct br_ofctrl *br_ofctrl;
    HMAP_FOR_EACH (br_ofctrl, hmap_node, &br_ofctrls) {
        reconnected |= br_ofctrl_run__(br_ofctrl);
    }

    return reconnected;
}

/* Programs the flow table on the switch, if possible, by the flows
 * added to the br-flow-mgr.
 *
 * This should be called after br_ofctrls_run() within the main loop. */
void
br_ofctrls_put(uint64_t req_cfg, bool lflows_changed, bool pflows_changed)
{
    struct br_ofctrl *br_ofctrl;
    HMAP_FOR_EACH (br_ofctrl, hmap_node, &br_ofctrls) {
        br_ofctrl_put(br_ofctrl, req_cfg, lflows_changed, pflows_changed);
    }
}

void
br_ofctrls_wait(void)
{
    struct br_ofctrl *br_ofctrl;
    HMAP_FOR_EACH (br_ofctrl, hmap_node, &br_ofctrls) {
        rconn_run_wait(br_ofctrl->swconn);
        rconn_recv_wait(br_ofctrl->swconn);
    }
}

uint64_t
br_ofctrl_get_cur_cfg(void)
{
    uint64_t of_cur_cfg = UINT64_MAX;
    struct br_ofctrl *br_ofctrl;
    HMAP_FOR_EACH (br_ofctrl, hmap_node, &br_ofctrls) {
        of_cur_cfg = MIN(of_cur_cfg, br_ofctrl->cur_cfg);
    }

    return of_cur_cfg;
}

/* Static functions. */

static void
br_ofctrl_destroy(struct br_ofctrl *br_ofctrl)
{
    rconn_destroy(br_ofctrl->swconn);
    rconn_packet_counter_destroy(br_ofctrl->tx_counter);
    free(br_ofctrl->bridge);
    free(br_ofctrl);
}

static struct br_ofctrl *
br_ofctrl_get(const char *bridge)
{
    struct br_ofctrl *br_ofctrl;
    uint32_t hash = hash_string(bridge, 0);
    HMAP_FOR_EACH_WITH_HASH (br_ofctrl, hmap_node, hash, &br_ofctrls) {
        if (!strcmp(br_ofctrl->bridge, bridge)) {
            return br_ofctrl;
        }
    }

    return NULL;
}

static ovs_be32
queue_msg(struct br_ofctrl *br_ofctrl, struct ofpbuf *msg)
{
    const struct ofp_header *oh = msg->data;
    ovs_be32 xid_ = oh->xid;
    rconn_send(br_ofctrl->swconn, msg, br_ofctrl->tx_counter);
    return xid_;
}

static void
log_openflow_rl(struct vlog_rate_limit *rl, enum vlog_level level,
                const struct ofp_header *oh, const char *title)
{
    if (!vlog_should_drop(&this_module, level, rl)) {
        char *s = ofp_to_string(oh, ntohs(oh->length), NULL, NULL, 2);
        vlog(&this_module, level, "%s: %s", title, s);
        free(s);
    }
}

static struct br_ofctrl_flow_update *
br_ofctrl_flow_update_from_list_node(const struct ovs_list *list_node)
{
    return CONTAINER_OF(list_node, struct br_ofctrl_flow_update, list_node);
}

/* br_ofctrl state machine functions. */

static void
br_ofctrl_recv(struct br_ofctrl *br_ofctrl, const struct ofp_header *oh,
            enum ofptype type)
{
    if (type == OFPTYPE_ECHO_REQUEST) {
        queue_msg(br_ofctrl, ofputil_encode_echo_reply(oh));
    } else if (type == OFPTYPE_ERROR) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);
        log_openflow_rl(&rl, VLL_INFO, oh, "OpenFlow error");
        rconn_reconnect(br_ofctrl->swconn);
    } else {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);
        log_openflow_rl(&rl, VLL_DBG, oh, "OpenFlow packet ignored");
    }
}


/* S_NEW, for a new connection.
 *
 */

static void
run_S_NEW(struct br_ofctrl *br_ofctrl)
{
    br_ofctrl->state = S_WAIT_BEFORE_CLEAR;
}

static void
recv_S_NEW(struct br_ofctrl *br_ofctrl OVS_UNUSED,
           const struct ofp_header *oh OVS_UNUSED,
           enum ofptype type OVS_UNUSED)
{
    OVS_NOT_REACHED();
}

/* S_WAIT_BEFORE_CLEAR, we are almost ready to set up flows, but just wait for
 * a while until the initial flow compute to complete before we clear the
 * existing flows in OVS, so that we won't end up with an empty flow table,
 * which may cause data plane down time. */
static void
run_S_WAIT_BEFORE_CLEAR(struct br_ofctrl *br_ofctrl)
{
    if (!br_ofctrl->wait_before_clear_time ||
        (br_ofctrl->wait_before_clear_expire &&
         time_msec() >= br_ofctrl->wait_before_clear_expire)) {
        br_ofctrl->state = S_CLEAR_FLOWS;
        return;
    }

    if (!br_ofctrl->wait_before_clear_expire) {
        /* Start the timer. */
        br_ofctrl->wait_before_clear_expire =
            time_msec() + br_ofctrl->wait_before_clear_time;
    }
    poll_timer_wait_until(br_ofctrl->wait_before_clear_expire);
}

static void
recv_S_WAIT_BEFORE_CLEAR(struct br_ofctrl *br_ofctrl,
                         const struct ofp_header *oh, enum ofptype type)
{
    br_ofctrl_recv(br_ofctrl, oh, type);
}

/* Sends an OFPT_TABLE_MOD to clear all flows, then transitions to
 * S_UPDATE_FLOWS. */

static void
run_S_CLEAR_FLOWS(struct br_ofctrl *br_ofctrl)
{
    VLOG_DBG("clearing all flows for bridge %s", br_ofctrl->bridge);

    /* Set the flag so that the ofctrl_run() can clear the existing flows,
     * groups and meters. We clear them in ofctrl_run() right before the new
     * ones are installed to avoid data plane downtime. */
    br_ofctrl->br_ofctrl_initial_clear = true;

    /* Clear installed_flows, to match the state of the switch. */
    br_flow_flush_oflows(br_ofctrl->bridge);

    /* All flow updates are irrelevant now. */
    struct br_ofctrl_flow_update *fup;
    LIST_FOR_EACH_SAFE (fup, list_node, &br_ofctrl->flow_updates) {
        ovs_list_remove(&fup->list_node);
        free(fup);
    }

    br_ofctrl->state = S_UPDATE_FLOWS;

    /* Give a chance for the main loop to call br_ofctrl_put() in case there
     * were pending flows waiting ofctrl state change to S_UPDATE_FLOWS. */
    poll_immediate_wake();
}

static void
recv_S_CLEAR_FLOWS(struct br_ofctrl *br_ofctrl,
                   const struct ofp_header *oh, enum ofptype type)
{
    br_ofctrl_recv(br_ofctrl, oh, type);
}

/* S_UPDATE_FLOWS, for maintaining the flow table over time.
 *
 * Compare the installed flows to the ones we want.  Send OFPT_FLOW_MOD as
 * necessary.
 *
 * This is a terminal state.  We only transition out of it if the connection
 * drops. */

static void
run_S_UPDATE_FLOWS(struct br_ofctrl *br_ofctrl OVS_UNUSED)
{
    /* Nothing to do here.
     *
     * Being in this state enables br_ofctrl_put() to work, however. */
}

static void
br_flow_updates_handle_barrier_reply(struct br_ofctrl *br_ofctrl,
                                     const struct ofp_header *oh)
{
    if (ovs_list_is_empty(&br_ofctrl->flow_updates)) {
        return;
    }

    struct br_ofctrl_flow_update *fup = br_ofctrl_flow_update_from_list_node(
        ovs_list_front(&br_ofctrl->flow_updates));
    if (fup->xid == oh->xid) {
        if (fup->req_cfg >= br_ofctrl->cur_cfg) {
            br_ofctrl->cur_cfg = fup->req_cfg;
        }
        ovs_list_remove(&fup->list_node);
        free(fup);
    }
}

static void
recv_S_UPDATE_FLOWS(struct br_ofctrl *br_ofctrl,
                    const struct ofp_header *oh, enum ofptype type)
{
    if (type == OFPTYPE_BARRIER_REPLY) {
        br_flow_updates_handle_barrier_reply(br_ofctrl, oh);
    } else {
        br_ofctrl_recv(br_ofctrl, oh, type);
    }
}

static bool
br_ofctrl_run__(struct br_ofctrl *br_ofctrl)
{
    struct rconn *swconn = br_ofctrl->swconn;

    ovn_update_swconn_at(swconn, br_ofctrl->conn_target,
                         br_ofctrl->probe_interval, "br_ofctrl");
    rconn_run(swconn);

    if (!rconn_is_connected(swconn)) {
        return false;
    }

    bool reconnected = false;

    if (br_ofctrl->seqno != rconn_get_connection_seqno(swconn)) {
        br_ofctrl->seqno = rconn_get_connection_seqno(swconn);
        reconnected = true;
        br_ofctrl->state = S_NEW;
    }

    bool progress = true;
    for (int i = 0; progress && i < 50; i++) {
        /* Allow the state machine to run. */
        enum br_ofctrl_state old_state = br_ofctrl->state;
        switch (br_ofctrl->state) {
#define STATE(NAME) case NAME: run_##NAME(br_ofctrl); break;
            STATES
#undef STATE
        default:
            OVS_NOT_REACHED();
        }

        /* Try to process a received packet. */
        struct ofpbuf *msg = rconn_recv(swconn);
        if (msg) {
            const struct ofp_header *oh = msg->data;
            enum ofptype type;
            enum ofperr error;

            error = ofptype_decode(&type, oh);
            if (!error) {
                switch (br_ofctrl->state) {
#define STATE(NAME) case NAME: recv_##NAME(br_ofctrl, oh, type); break;
                    STATES
#undef STATE
                default:
                    OVS_NOT_REACHED();
                }
            } else {
                char *s = ofp_to_string(oh, ntohs(oh->length), NULL, NULL, 1);
                VLOG_WARN("could not decode OpenFlow message (%s): %s",
                          ofperr_to_string(error), s);
                free(s);
            }

            ofpbuf_delete(msg);
        }

        /* If we did some work, plan to go around again. */
        progress = old_state != br_ofctrl->state || msg;
    }
    if (progress) {
        /* We bailed out to limit the amount of work we do in one go, to allow
         * other code a chance to run.  We were still making progress at that
         * point, so ensure that we come back again without waiting. */
        poll_immediate_wake();
    }

    return reconnected;
}

static bool
br_ofctrl_has_backlog(struct br_ofctrl *br_ofctrl)
{
    if (rconn_packet_counter_n_packets(br_ofctrl->tx_counter)
        || rconn_get_version(br_ofctrl->swconn) < 0) {
        return true;
    }
    return false;
}

/* The flow table can be updated if the connection to the switch is up and
 * in the correct state and not backlogged with existing flow_mods.  (Our
 * criteria for being backlogged appear very conservative, but the socket
 * between ovn-controller and OVS provides some buffering.) */
static bool
br_ofctrl_can_put(struct br_ofctrl *br_ofctrl)
{
    if (br_ofctrl->state != S_UPDATE_FLOWS
        || br_ofctrl_has_backlog(br_ofctrl)) {
        return false;
    }
    return true;
}

static struct ofpbuf *
encode_flow_mod(struct ofputil_flow_mod *fm)
{
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_ANY;
    fm->out_group = OFPG_ANY;
    return ofputil_encode_flow_mod(fm, OFPUTIL_P_OF15_OXM);
}

static struct ofpbuf *
encode_bundle_add(struct ofpbuf *msg, struct ofputil_bundle_ctrl_msg *bc)
{
    struct ofputil_bundle_add_msg bam = {
        .bundle_id = bc->bundle_id,
        .flags     = bc->flags,
        .msg       = msg->data,
    };
    return ofputil_encode_bundle_add(OFP15_VERSION, &bam);
}

static bool
add_flow_mod(struct ofputil_flow_mod *fm,
             struct ofputil_bundle_ctrl_msg *bc,
             struct ovs_list *msgs)
{
    struct ofpbuf *msg = encode_flow_mod(fm);
    struct ofpbuf *bundle_msg = encode_bundle_add(msg, bc);

    uint32_t flow_mod_len = msg->size;
    uint32_t bundle_len = bundle_msg->size;

    ofpbuf_delete(msg);

    if (flow_mod_len > UINT16_MAX || bundle_len > UINT16_MAX) {
        ofpbuf_delete(bundle_msg);

        return false;
    }

    ovs_list_push_back(msgs, &bundle_msg->list_node);
    return true;
}

static void
br_ofctrl_put(struct br_ofctrl *br_ofctrl, uint64_t req_cfg,
              bool lflows_changed, bool pflows_changed)
{
    bool need_put = false;

    if (lflows_changed || pflows_changed || br_ofctrl->skipped_last_time ||
        br_ofctrl->br_ofctrl_initial_clear) {
        need_put = true;
        br_ofctrl->old_req_cfg = req_cfg;
    } else if (req_cfg != br_ofctrl->old_req_cfg) {
        /* req_cfg changed since last br_ofctrl_put() call */
        if (br_ofctrl->cur_cfg == br_ofctrl->old_req_cfg) {
            /* If there are no updates pending, we were up-to-date already,
             * update with the new req_cfg.
             */
            if (ovs_list_is_empty(&br_ofctrl->flow_updates)) {
                br_ofctrl->cur_cfg = req_cfg;
                br_ofctrl->old_req_cfg = req_cfg;
            }
        } else {
            need_put = true;
            br_ofctrl->old_req_cfg = req_cfg;
        }
    }

    if (!need_put) {
        VLOG_DBG("br_ofctrl_put not needed for bridge %s", br_ofctrl->bridge);
        return;
    }

    /* OpenFlow messages to send to the switch to bring it up-to-date. */
    struct ovs_list msgs = OVS_LIST_INITIALIZER(&msgs);

    if (!br_ofctrl_can_put(br_ofctrl)) {
        VLOG_DBG("br_ofctrl_put can't be performed for bridge %s",
                 br_ofctrl->bridge);

        br_ofctrl->skipped_last_time = true;
        return;
    }

    /* Add all flow updates into a bundle. */
    static int bundle_id = 0;
    struct ofputil_bundle_ctrl_msg bc = {
        .bundle_id = bundle_id++,
        .flags     = OFPBF_ORDERED | OFPBF_ATOMIC,
    };
    struct ofpbuf *bundle_open, *bundle_commit;

    /* Open a new bundle. */
    bc.type = OFPBCT_OPEN_REQUEST;
    bundle_open = ofputil_encode_bundle_ctrl_request(OFP15_VERSION, &bc);
    ovs_list_push_back(&msgs, &bundle_open->list_node);

    if (br_ofctrl->br_ofctrl_initial_clear) {
        /* Send a flow_mod to delete all flows. */
        struct ofputil_flow_mod fm = {
            .table_id = OFPTT_ALL,
            .command = OFPFC_DELETE,
        };
        minimatch_init_catchall(&fm.match);
        add_flow_mod(&fm, &bc, &msgs);
        minimatch_destroy(&fm.match);

        br_ofctrl->br_ofctrl_initial_clear = false;
    }

    br_flow_populate_oflow_msgs(br_ofctrl->bridge, &msgs);

    if (ovs_list_back(&msgs) == &bundle_open->list_node) {
        /* No flow updates.  Removing the bundle open request. */
        ovs_list_pop_back(&msgs);
        ofpbuf_delete(bundle_open);
    } else {
        /* Committing the bundle. */
        bc.type = OFPBCT_COMMIT_REQUEST;
        bundle_commit = ofputil_encode_bundle_ctrl_request(OFP15_VERSION, &bc);
        ovs_list_push_back(&msgs, &bundle_commit->list_node);
    }

    if (!ovs_list_is_empty(&msgs)) {
        /* Add a barrier to the list of messages. */
        struct ofpbuf *barrier = ofputil_encode_barrier_request(OFP15_VERSION);
        const struct ofp_header *oh = barrier->data;
        ovs_be32 xid_ = oh->xid;
        ovs_list_push_back(&msgs, &barrier->list_node);

        /* Queue the messages. */
        struct ofpbuf *msg;
        LIST_FOR_EACH_POP (msg, list_node, &msgs) {
            queue_msg(br_ofctrl, msg);
        }

        /* Track the flow update. */
        struct br_ofctrl_flow_update *fup;
        LIST_FOR_EACH_REVERSE_SAFE (fup, list_node, &br_ofctrl->flow_updates) {
            if (req_cfg < fup->req_cfg) {
                /* This br_ofctrl_flow_update is for a configuration later than
                 * 'req_cfg'.  This should not normally happen, because it
                 * means that the local seqno decreased and it should normally
                 * be monotonically increasing. */
                VLOG_WARN("req_cfg regressed from %"PRId64" to %"PRId64,
                          fup->req_cfg, req_cfg);
                ovs_list_remove(&fup->list_node);
                free(fup);
            } else if (req_cfg == fup->req_cfg) {
                /* This br_ofctrl_flow_update is for the same configuration as
                 * 'req_cfg'.  Probably, some change to the physical topology
                 * means that we had to revise the OpenFlow flow table even
                 * though the logical topology did not change.  Update fp->xid,
                 * so that we don't send a notification that we're up-to-date
                 * until we're really caught up. */
                VLOG_DBG("advanced xid target for req_cfg=%"PRId64, req_cfg);
                fup->xid = xid_;

                return;
            } else {
                break;
            }
        }

        /* Add a flow update. */
        fup = xmalloc(sizeof *fup);
        ovs_list_push_back(&br_ofctrl->flow_updates, &fup->list_node);
        fup->xid = xid_;
        fup->req_cfg = req_cfg;
    } else if (!ovs_list_is_empty(&br_ofctrl->flow_updates)) {
        /* Getting up-to-date with 'req_cfg' didn't require any extra flow
         * table changes, so whenever we get up-to-date with the most recent
         * flow table update, we're also up-to-date with 'req_cfg'. */
        struct br_ofctrl_flow_update *fup =
            br_ofctrl_flow_update_from_list_node(
                ovs_list_back(&br_ofctrl->flow_updates));
        fup->req_cfg = req_cfg;
    } else {
        /* We were completely up-to-date before and still are. */
        br_ofctrl->cur_cfg = req_cfg;
    }
}
