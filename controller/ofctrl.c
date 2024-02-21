/* Copyright (c) 2015, 2016, 2017 Nicira, Inc.
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
#include "bitmap.h"
#include "byte-order.h"
#include "coverage.h"
#include "dirs.h"
#include "dp-packet.h"
#include "flow.h"
#include "hash.h"
#include "hindex.h"
#include "lflow.h"
#include "ofctrl.h"
#include "openflow/openflow.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-bundle.h"
#include "openvswitch/ofp-ct.h"
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
#include "ovn-controller.h"
#include "ovn/actions.h"
#include "lib/extend-table.h"
#include "lib/lb.h"
#include "openvswitch/poll-loop.h"
#include "physical.h"
#include "openvswitch/rconn.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(ofctrl);

COVERAGE_DEFINE(ofctrl_msg_too_long);

/* An OpenFlow flow. */
struct ovn_flow {
    /* Key. */
    uint8_t table_id;
    uint16_t priority;
    struct minimatch match;

    /* Hash. */
    uint32_t hash;

    /* Data. */
    struct ofpact *ofpacts;
    size_t ofpacts_len;
    uint64_t cookie;
    uint32_t ctrl_meter_id; /* Meter to be used for controller actions. */
};

/* A desired flow, in struct ovn_desired_flow_table, calculated by the
 * incremental processing engine.
 * - They are added/removed incrementally when I-P engine is able to process
 *   the changes incrementally, or
 * - Completely cleared and recomputed by I-P engine when recompute happens.
 *
 * Links are maintained between desired flows and SB data. The relationship
 * is M to N. The struct sb_flow_ref is used to link a pair of desired flow
 * and SB UUID. The below diagram depicts the data structure.
 *
 *                   SB UUIDs
 *                 +-----+-----+-----+-----+-----+-----+-----+
 *                 |     |     |     |     |     |     |     |
 *                 +--+--+--+--+--+--+-----+--+--+--+--+--+--+
 *                    |     |     |           |     |     |
 *  Desired Flows     |     |     |           |     |     |
 *     +----+       +-+-+   |   +-+-+         |   +-+-+   |
 *     |    +-------+   +-------+   +-------------+   |   |
 *     +----+       +---+   |   +-+-+         |   +---+   |
 *     |    |               |     |           |           |
 *     +----+               |     |         +-+-+         |
 *     |    +-------------------------------+   |         |
 *     +----+             +---+   |         +---+         |
 *     |    +-------------+   |   |                       |
 *     +----+             +---+   |                       |
 *     |    |                     |                       |
 *     +----+                   +-+-+                   +-+-+
 *     |    +-------------------+   +-------------------+   |
 *     +----+                   +---+                   +---+
 *     |    |
 *     +----+
 *
 * The links are updated whenever there is a change in desired flows, which is
 * usually triggered by a SB data change in I-P engine.
 *
 * ** Tracking **
 *
 * A desired flow can be tracked - listed in ovn_desired_flow_table's
 * tracked_flows.
 *
 * Tracked flows is initially empty, and stays empty after the first run of I-P
 * engine when installed flows are initially populated. After that, flow
 * changes are tracked when I-P engine incrementally computes flow changes.
 * Tracked flows are then processed and removed completely in ofctrl_put.
 * ("processed" means OpenFlow change messages are composed and sent/queued to
 * OVS, which ensures flows in OVS is always in sync (eventually) with the
 * installed flows table).
 *
 * In case of full recompute of I-P engine, tracked flows are not
 * added/removed, and ofctrl_put will not rely on tracked flows. (It is I-P
 * engine's responsibility to ensure the tracked flows are cleared before
 * recompute).
 *
 * Tracked flows can be preserved across multiple I-P engine runs - if in some
 * iterations ofctrl_put() is skipped. Tracked flows are cleared only when it
 * is consumed or when flow recompute happens.
 *
 * The "change_tracked" member of desired flow table maintains the status of
 * whether flow changes are tracked or not. It is always set to true when
 * ofctrl_put is completed, and transition to false whenever
 * ovn_desired_flow_table_clear is called.
 *
 * NOTE: A tracked flow is just a reference to a desired flow, instead of a new
 * copy. When a desired flow is removed and tracked, it is removed from the
 * match_flow_table and uuid_flow_table indexes, and added to the tracked_flows
 * list, marking is_deleted = true, but not immediately destroyed. It is
 * destroyed when the tracking is processed for installed flow updates.
 */
struct desired_flow {
    struct ovn_flow flow;
    struct hmap_node match_hmap_node; /* For match based hashing. */
    struct ovs_list list_node; /* For handling lists of flows. */

    /* A list of struct sb_flow_ref nodes, which references this flow. (There
     * are cases that multiple SB entities share the same desired OpenFlow
     * flow, e.g. when conjunction is used.) */
    struct ovs_list references;

    /* The corresponding flow in installed table. */
    struct installed_flow *installed_flow;

    /* Node in installed_flow.desired_refs list. */
    struct ovs_list installed_ref_list_node;

    /* For tracking. */
    struct ovs_list track_list_node; /* node in ovn_desired_flow_table's
                                      * tracked_flows list. */
    bool is_deleted; /* If the tracked flow is deleted. */
};

struct sb_to_flow {
    struct hmap_node hmap_node; /* Node in
                                   ovn_desired_flow_table.uuid_flow_table. */
    struct uuid sb_uuid;
    struct ovs_list flows; /* A list of struct sb_flow_ref nodes that
                                      are referenced by the sb_uuid. */
    struct ovs_list addrsets; /* A list of struct sb_addrset_ref. */
};

struct sb_flow_ref {
    struct ovs_list sb_list; /* Node in desired_flow.references. */
    struct ovs_list flow_list; /* Node in sb_to_flow.flows. */
    struct ovs_list as_ip_flow_list; /* Node in as_ip_to_flow_node.flows. */
    struct desired_flow *flow;
    struct uuid sb_uuid;
};

struct sb_addrset_ref {
    struct ovs_list list_node; /* List node in sb_to_flow.addrsets. */
    char *name; /* Name of the address set. */
    struct hmap as_ip_to_flow_map; /* map from IPs in the address set to flows.
                                      Each node is as_ip_to_flow_node. */
};

struct as_ip_to_flow_node {
    struct hmap_node hmap_node; /* Node in sb_addrset_ref.as_ip_to_flow_map. */
    struct in6_addr as_ip;
    struct in6_addr as_mask;

    /* A list of struct sb_flow_ref. A single IP in an address set can be
     * used by multiple flows.  e.g., in match:
     * ip.src == $as1 && ip.dst == $as1. */
    struct ovs_list flows;
};

/* An installed flow, in static variable installed_lflows/installed_pflows.
 *
 * Installed flows are updated in ofctrl_put for maintaining the flow
 * installation to OVS. They are updated according to desired flows: either by
 * processing the tracked desired flow changes, or by comparing desired flows
 * with currently installed flows when tracked desired flows changes are not
 * available.
 *
 * In addition, when ofctrl state machine enters S_CLEAR, the installed flows
 * will be cleared. (This happens in initialization phase and also when
 * ovs-vswitchd is disconnected/reconnected).
 *
 * Links are maintained between installed flows and desired flows. The
 * relationship is 1 to N. A link is added when a flow addition is processed.
 * A link is removed when a flow deletion is processed, the desired flow
 * table is cleared, or the installed flow table is cleared.
 *
 * To ensure predictable behavior, the list of desired flows is maintained
 * partially sorted in the following way (from least restrictive to most
 * restrictive wrt. match):
 * - allow flows without action conjunction.
 * - drop flows without action conjunction.
 * - a single flow with action conjunction.
 *
 * The first desired_flow in the list is the active one, the one that is
 * actually installed.
 */
struct installed_flow {
    struct ovn_flow flow;
    struct hmap_node match_hmap_node; /* For match based hashing. */

    /* A list of desired ovn_flow nodes (linked by
     * desired_flow.installed_ref_list_node), which reference this installed
     * flow.  (There are cases that multiple desired flows reference the same
     * installed flow, e.g. when there are conflict/duplicated ACLs that
     * generates same match conditions). */
    struct ovs_list desired_refs;
};

/* Global ofctrl memory usage specific statistics, all in bytes. */
struct ofctrl_mem_stats {
    uint64_t sb_flow_ref_usage;
    uint64_t desired_flow_usage;
    uint64_t installed_flow_usage;
    uint64_t oflow_update_usage;
};

static struct ofctrl_mem_stats mem_stats;

typedef bool
(*desired_flow_match_cb)(const struct desired_flow *candidate,
                         const void *arg);
static struct desired_flow *desired_flow_alloc(
    uint8_t table_id,
    uint16_t priority,
    uint64_t cookie,
    const struct match *match,
    const struct ofpbuf *actions,
    uint32_t meter_id);
static size_t desired_flow_size(const struct desired_flow *);
static struct desired_flow *desired_flow_lookup(
    struct ovn_desired_flow_table *,
    const struct ovn_flow *target);
static struct desired_flow *desired_flow_lookup_check_uuid(
    struct ovn_desired_flow_table *,
    const struct ovn_flow *target,
    const struct uuid *);
static struct desired_flow *desired_flow_lookup_conjunctive(
    struct ovn_desired_flow_table *,
    const struct ovn_flow *target);
static void desired_flow_destroy(struct desired_flow *);

static struct installed_flow *installed_flow_lookup(
    const struct ovn_flow *target, struct hmap *installed_flows);
static void installed_flow_destroy(struct installed_flow *);
static struct installed_flow *installed_flow_dup(struct desired_flow *);
static size_t installed_flow_size(const struct installed_flow *);
static struct desired_flow *installed_flow_get_active(struct installed_flow *);

static uint32_t ovn_flow_match_hash(const struct ovn_flow *);
static char *ovn_flow_to_string(const struct ovn_flow *);
static void ovn_flow_log(const struct ovn_flow *, const char *action);

static void remove_flows_from_sb_to_flow(struct ovn_desired_flow_table *,
                                         struct sb_to_flow *,
                                         const char *log_msg,
                                         struct uuidset *flood_remove_nodes);

/* OpenFlow connection to the switch. */
static struct rconn *swconn;

/* Symbol table for OVN expressions. */
static struct shash symtab;

/* Last seen sequence number for 'swconn'.  When this differs from
 * rconn_get_connection_seqno(rconn), 'swconn' has reconnected. */
static unsigned int seqno;

/* Connection state machine. */
#define STATES                                  \
    STATE(S_NEW)                                \
    STATE(S_TLV_TABLE_REQUESTED)                \
    STATE(S_TLV_TABLE_MOD_SENT)                 \
    STATE(S_WAIT_BEFORE_CLEAR)                  \
    STATE(S_CLEAR_FLOWS)                        \
    STATE(S_UPDATE_FLOWS)
enum ofctrl_state {
#define STATE(NAME) NAME,
    STATES
#undef STATE
};

/* An in-flight update to the switch's flow table.
 *
 * When we receive a barrier reply from the switch with the given 'xid', we
 * know that the switch is caught up to the requested sequence number
 * 'req_cfg' (and make that available to the client via ofctrl_get_cur_cfg(),
 * so that it can store it into external state, e.g., our Chassis record's
 * nb_cfg column). */
struct ofctrl_flow_update {
    struct ovs_list list_node;  /* In 'flow_updates'. */
    ovs_be32 xid;               /* OpenFlow transaction ID for barrier. */
    uint64_t req_cfg;           /* Requested sequence number. */
};

static struct ofctrl_flow_update *
ofctrl_flow_update_from_list_node(const struct ovs_list *list_node)
{
    return CONTAINER_OF(list_node, struct ofctrl_flow_update, list_node);
}

static size_t
ofctrl_flow_update_size(const struct ofctrl_flow_update *fup)
{
    return sizeof *fup;
}

/* Currently in-flight updates. */
static struct ovs_list flow_updates;

/* req_cfg of latest committed flow update. */
static uint64_t cur_cfg;

/* Current state. */
static enum ofctrl_state state;

/* The time (ms) to stay in the state S_WAIT_BEFORE_CLEAR. Read from
 * external_ids: ovn-ofctrl-wait-before-clear. */
static unsigned int wait_before_clear_time = 0;

/* The time when the state S_WAIT_BEFORE_CLEAR should complete.
 * If the timer is not started yet, it is set to 0. */
static long long int wait_before_clear_expire = 0;

/* Transaction IDs for messages in flight to the switch. */
static ovs_be32 xid, xid2;

/* Counter for in-flight OpenFlow messages on 'swconn'.  We only send a new
 * round of flow table modifications to the switch when the counter falls to
 * zero, to avoid unbounded buffering. */
static struct rconn_packet_counter *tx_counter;

/* Flow table of "struct ovn_flow"s, that holds the logical flow table
 * currently installed in the switch. */
static struct hmap installed_lflows;
/* Flow table of "struct ovn_flow"s, that holds the physical flow table
 * currently installed in the switch. */
static struct hmap installed_pflows;

/* A reference to the group_table. */
static struct ovn_extend_table *groups;

/* A reference to the meter_table. */
static struct ovn_extend_table *meters;

/* Installed meter bands. */
struct meter_band_data {
    int64_t burst_size;
    int64_t rate;
};

struct meter_band_entry {
    struct meter_band_data *bands;
    size_t n_bands;
};

static struct shash meter_bands;

static void ofctrl_meter_bands_destroy(void);
static void ofctrl_meter_bands_clear(void);

/* MFF_* field ID for our Geneve option.  In S_TLV_TABLE_MOD_SENT, this is
 * the option we requested (we don't know whether we obtained it yet).  In
 * S_CLEAR_FLOWS or S_UPDATE_FLOWS, this is really the option we have. */
static enum mf_field_id mff_ovn_geneve;

/* Indicates if we just went through the S_CLEAR_FLOWS state, which means we
 * need to perform a one time deletion for all the existing flows, groups and
 * meters. This can happen during initialization or OpenFlow reconnection
 * (e.g. after OVS restart). */
static bool ofctrl_initial_clear;

static ovs_be32 queue_msg(struct ofpbuf *);

static struct ofpbuf *encode_flow_mod(struct ofputil_flow_mod *);

static struct ofpbuf *encode_group_mod(const struct ofputil_group_mod *);

static struct ofpbuf *encode_meter_mod(const struct ofputil_meter_mod *);

static void ovn_installed_flow_table_clear(void);
static void ovn_installed_flow_table_destroy(void);


static void ofctrl_recv(const struct ofp_header *, enum ofptype);

void
ofctrl_init(struct ovn_extend_table *group_table,
            struct ovn_extend_table *meter_table,
            int inactivity_probe_interval)
{
    swconn = rconn_create(inactivity_probe_interval, 0,
                          DSCP_DEFAULT, 1 << OFP15_VERSION);
    tx_counter = rconn_packet_counter_create();
    hmap_init(&installed_lflows);
    hmap_init(&installed_pflows);
    ovs_list_init(&flow_updates);
    ovn_init_symtab(&symtab);
    groups = group_table;
    meters = meter_table;
    shash_init(&meter_bands);
}

/* S_NEW, for a new connection.
 *
 * Sends NXT_TLV_TABLE_REQUEST and transitions to
 * S_TLV_TABLE_REQUESTED. */

static void
run_S_NEW(void)
{
    struct ofpbuf *buf = ofpraw_alloc(OFPRAW_NXT_TLV_TABLE_REQUEST,
                                      rconn_get_version(swconn), 0);
    xid = queue_msg(buf);
    state = S_TLV_TABLE_REQUESTED;
}

static void
recv_S_NEW(const struct ofp_header *oh OVS_UNUSED,
           enum ofptype type OVS_UNUSED,
           struct shash *pending_ct_zones OVS_UNUSED)
{
    OVS_NOT_REACHED();
}

/* S_TLV_TABLE_REQUESTED, when NXT_TLV_TABLE_REQUEST has been sent
 * and we're waiting for a reply.
 *
 * If we receive an NXT_TLV_TABLE_REPLY:
 *
 *     - If it contains our tunnel metadata option, assign its field ID to
 *       mff_ovn_geneve and transition to S_WAIT_BEFORE_CLEAR.
 *
 *     - Otherwise, if there is an unused tunnel metadata field ID, send
 *       NXT_TLV_TABLE_MOD and OFPT_BARRIER_REQUEST, and transition to
 *       S_TLV_TABLE_MOD_SENT.
 *
 *     - Otherwise, log an error, disable Geneve, and transition to
 *       S_WAIT_BEFORE_CLEAR.
 *
 * If we receive an OFPT_ERROR:
 *
 *     - Log an error, disable Geneve, and transition to S_WAIT_BEFORE_CLEAR.
 */

static void
run_S_TLV_TABLE_REQUESTED(void)
{
}

static bool
process_tlv_table_reply(const struct ofputil_tlv_table_reply *reply)
{
    const struct ofputil_tlv_map *map;
    uint64_t md_free = UINT64_MAX;
    BUILD_ASSERT(TUN_METADATA_NUM_OPTS == 64);

    LIST_FOR_EACH (map, list_node, &reply->mappings) {
        if (map->option_class == OVN_GENEVE_CLASS
            && map->option_type == OVN_GENEVE_TYPE
            && map->option_len == OVN_GENEVE_LEN) {
            if (map->index >= TUN_METADATA_NUM_OPTS) {
                VLOG_ERR("desired Geneve tunnel option 0x%"PRIx16","
                         "%"PRIu8",%"PRIu8" already in use with "
                         "unsupported index %"PRIu16,
                         map->option_class, map->option_type,
                         map->option_len, map->index);
                return false;
            } else {
                mff_ovn_geneve = MFF_TUN_METADATA0 + map->index;
                state = S_WAIT_BEFORE_CLEAR;
                return true;
            }
        }

        if (map->index < TUN_METADATA_NUM_OPTS) {
            md_free &= ~(UINT64_C(1) << map->index);
        }
    }

    VLOG_DBG("OVN Geneve option not found");
    if (!md_free) {
        VLOG_ERR("no Geneve options free for use by OVN");
        return false;
    }

    unsigned int index = rightmost_1bit_idx(md_free);
    mff_ovn_geneve = MFF_TUN_METADATA0 + index;
    struct ofputil_tlv_map tm;
    tm.option_class = OVN_GENEVE_CLASS;
    tm.option_type = OVN_GENEVE_TYPE;
    tm.option_len = OVN_GENEVE_LEN;
    tm.index = index;

    struct ofputil_tlv_table_mod ttm;
    ttm.command = NXTTMC_ADD;
    ovs_list_init(&ttm.mappings);
    ovs_list_push_back(&ttm.mappings, &tm.list_node);

    xid = queue_msg(ofputil_encode_tlv_table_mod(OFP15_VERSION, &ttm));
    xid2 = queue_msg(ofputil_encode_barrier_request(OFP15_VERSION));
    state = S_TLV_TABLE_MOD_SENT;

    return true;
}

static void
recv_S_TLV_TABLE_REQUESTED(const struct ofp_header *oh, enum ofptype type,
                           struct shash *pending_ct_zones OVS_UNUSED)
{
    if (oh->xid != xid) {
        ofctrl_recv(oh, type);
        return;
    } else if (type == OFPTYPE_NXT_TLV_TABLE_REPLY) {
        struct ofputil_tlv_table_reply reply;
        enum ofperr error = ofputil_decode_tlv_table_reply(oh, &reply);
        if (!error) {
            bool ok = process_tlv_table_reply(&reply);
            ofputil_uninit_tlv_table(&reply.mappings);
            if (ok) {
                return;
            }
        } else {
            VLOG_ERR("failed to decode TLV table request (%s)",
                     ofperr_to_string(error));
        }
    } else if (type == OFPTYPE_ERROR) {
        VLOG_ERR("switch refused to allocate Geneve option (%s)",
                 ofperr_to_string(ofperr_decode_msg(oh, NULL)));
    } else {
        char *s = ofp_to_string(oh, ntohs(oh->length), NULL, NULL, 1);
        VLOG_ERR("unexpected reply to TLV table request (%s)", s);
        free(s);
    }

    /* Error path. */
    mff_ovn_geneve = 0;
    state = S_WAIT_BEFORE_CLEAR;
}

/* S_TLV_TABLE_MOD_SENT, when NXT_TLV_TABLE_MOD and OFPT_BARRIER_REQUEST
 * have been sent and we're waiting for a reply to one or the other.
 *
 * If we receive an OFPT_ERROR:
 *
 *     - If the error is NXTTMFC_ALREADY_MAPPED or NXTTMFC_DUP_ENTRY, we
 *       raced with some other controller.  Transition to S_NEW.
 *
 *     - Otherwise, log an error, disable Geneve, and transition to
 *       S_WAIT_BEFORE_CLEAR.
 *
 * If we receive OFPT_BARRIER_REPLY:
 *
 *     - Set the tunnel metadata field ID to the one that we requested.
 *       Transition to S_WAIT_BEFORE_CLEAR.
 */

static void
run_S_TLV_TABLE_MOD_SENT(void)
{
}

static void
recv_S_TLV_TABLE_MOD_SENT(const struct ofp_header *oh, enum ofptype type,
                          struct shash *pending_ct_zones OVS_UNUSED)
{
    if (oh->xid != xid && oh->xid != xid2) {
        ofctrl_recv(oh, type);
    } else if (oh->xid == xid2 && type == OFPTYPE_BARRIER_REPLY) {
        state = S_WAIT_BEFORE_CLEAR;
    } else if (oh->xid == xid && type == OFPTYPE_ERROR) {
        enum ofperr error = ofperr_decode_msg(oh, NULL);
        if (error == OFPERR_NXTTMFC_ALREADY_MAPPED ||
            error == OFPERR_NXTTMFC_DUP_ENTRY) {
            VLOG_INFO("raced with another controller adding "
                      "Geneve option (%s); trying again",
                      ofperr_to_string(error));
            state = S_NEW;
        } else {
            VLOG_ERR("error adding Geneve option (%s)",
                     ofperr_to_string(error));
            goto error;
        }
    } else {
        char *s = ofp_to_string(oh, ntohs(oh->length), NULL, NULL, 1);
        VLOG_ERR("unexpected reply to Geneve option allocation request (%s)",
                 s);
        free(s);
        goto error;
    }
    return;

error:
    state = S_WAIT_BEFORE_CLEAR;
}

/* S_WAIT_BEFORE_CLEAR, we are almost ready to set up flows, but just wait for
 * a while until the initial flow compute to complete before we clear the
 * existing flows in OVS, so that we won't end up with an empty flow table,
 * which may cause data plane down time. */
static void
run_S_WAIT_BEFORE_CLEAR(void)
{
    if (!wait_before_clear_time ||
        (wait_before_clear_expire &&
         time_msec() >= wait_before_clear_expire)) {
        state = S_CLEAR_FLOWS;
        return;
    }

    if (!wait_before_clear_expire) {
        /* Start the timer. */
        wait_before_clear_expire = time_msec() + wait_before_clear_time;
    }
    poll_timer_wait_until(wait_before_clear_expire);
}

static void
recv_S_WAIT_BEFORE_CLEAR(const struct ofp_header *oh, enum ofptype type,
                         struct shash *pending_ct_zones OVS_UNUSED)
{
    ofctrl_recv(oh, type);
}

/* S_CLEAR_FLOWS, after we've established a Geneve metadata field ID and it's
 * time to set up some flows.
 *
 * Sends an OFPT_TABLE_MOD to clear all flows, then transitions to
 * S_UPDATE_FLOWS. */

static void
run_S_CLEAR_FLOWS(void)
{
    VLOG_DBG("clearing all flows");

    /* Set the flag so that the ofctrl_run() can clear the existing flows,
     * groups and meters. We clear them in ofctrl_run() right before the new
     * ones are installed to avoid data plane downtime. */
    ofctrl_initial_clear = true;

    /* Clear installed_flows, to match the state of the switch. */
    ovn_installed_flow_table_clear();

    /* Clear existing groups, to match the state of the switch. */
    if (groups) {
        ovn_extend_table_clear(groups, true);
    }

    /* Clear existing meters, to match the state of the switch. */
    if (meters) {
        ovn_extend_table_clear(meters, true);
        ofctrl_meter_bands_clear();
    }

    /* All flow updates are irrelevant now. */
    struct ofctrl_flow_update *fup;
    LIST_FOR_EACH_SAFE (fup, list_node, &flow_updates) {
        mem_stats.oflow_update_usage -= ofctrl_flow_update_size(fup);
        ovs_list_remove(&fup->list_node);
        free(fup);
    }

    state = S_UPDATE_FLOWS;

    /* Give a chance for the main loop to call ofctrl_put() in case there were
     * pending flows waiting ofctrl state change to S_UPDATE_FLOWS. */
    poll_immediate_wake();
}

static void
recv_S_CLEAR_FLOWS(const struct ofp_header *oh, enum ofptype type,
                   struct shash *pending_ct_zones OVS_UNUSED)
{
    ofctrl_recv(oh, type);
}

/* S_UPDATE_FLOWS, for maintaining the flow table over time.
 *
 * Compare the installed flows to the ones we want.  Send OFPT_FLOW_MOD as
 * necessary.
 *
 * This is a terminal state.  We only transition out of it if the connection
 * drops. */

static void
run_S_UPDATE_FLOWS(void)
{
    /* Nothing to do here.
     *
     * Being in this state enables ofctrl_put() to work, however. */
}

static void
recv_S_UPDATE_FLOWS(const struct ofp_header *oh, enum ofptype type,
                    struct shash *pending_ct_zones)
{
    if (type == OFPTYPE_BARRIER_REPLY && !ovs_list_is_empty(&flow_updates)) {
        struct ofctrl_flow_update *fup = ofctrl_flow_update_from_list_node(
            ovs_list_front(&flow_updates));
        if (fup->xid == oh->xid) {
            if (fup->req_cfg >= cur_cfg) {
                cur_cfg = fup->req_cfg;
            }
            mem_stats.oflow_update_usage -= ofctrl_flow_update_size(fup);
            ovs_list_remove(&fup->list_node);
            free(fup);
        }

        /* If the barrier xid is associated with an outstanding conntrack
         * flush, the flush succeeded.  Move the pending ct zone entry
         * to the next stage. */
        struct shash_node *iter;
        SHASH_FOR_EACH(iter, pending_ct_zones) {
            struct ct_zone_pending_entry *ctzpe = iter->data;
            if (ctzpe->state == CT_ZONE_OF_SENT && ctzpe->of_xid == oh->xid) {
                ctzpe->state = CT_ZONE_DB_QUEUED;
            }
        }
    } else {
        ofctrl_recv(oh, type);
    }
}


enum mf_field_id
ofctrl_get_mf_field_id(void)
{
    if (!rconn_is_connected(swconn)) {
        return 0;
    }
    return (state == S_WAIT_BEFORE_CLEAR
            || state == S_CLEAR_FLOWS
            || state == S_UPDATE_FLOWS
            ? mff_ovn_geneve : 0);
}

/* Runs the OpenFlow state machine against 'br_int', which is local to the
 * hypervisor on which we are running.  Attempts to negotiate a Geneve option
 * field for class OVN_GENEVE_CLASS, type OVN_GENEVE_TYPE.
 *
 * Returns 'true' if an OpenFlow reconnect happened; 'false' otherwise.
 */
bool
ofctrl_run(const struct ovsrec_bridge *br_int,
           const struct ovsrec_open_vswitch_table *ovs_table,
           struct shash *pending_ct_zones)
{
    char *target = xasprintf("unix:%s/%s.mgmt", ovs_rundir(), br_int->name);
    bool reconnected = false;

    if (strcmp(target, rconn_get_target(swconn))) {
        VLOG_INFO("%s: connecting to switch", target);
        rconn_connect(swconn, target, target);
    }
    free(target);

    rconn_run(swconn);

    if (!rconn_is_connected(swconn) || !pending_ct_zones) {
        return reconnected;
    }

    if (seqno != rconn_get_connection_seqno(swconn)) {
        seqno = rconn_get_connection_seqno(swconn);
        reconnected = true;
        state = S_NEW;

        /* Reset the state of any outstanding ct flushes to resend them. */
        struct shash_node *iter;
        SHASH_FOR_EACH(iter, pending_ct_zones) {
            struct ct_zone_pending_entry *ctzpe = iter->data;
            if (ctzpe->state == CT_ZONE_OF_SENT) {
                ctzpe->state = CT_ZONE_OF_QUEUED;
            }
        }
    }
    const struct ovsrec_open_vswitch *cfg =
        ovsrec_open_vswitch_table_first(ovs_table);
    ovs_assert(cfg);
    unsigned int _wait_before_clear_time =
        smap_get_uint(&cfg->external_ids, "ovn-ofctrl-wait-before-clear", 0);
    if (_wait_before_clear_time != wait_before_clear_time) {
        VLOG_INFO("ofctrl-wait-before-clear is now %u ms (was %u ms)",
                  _wait_before_clear_time, wait_before_clear_time);
        wait_before_clear_time = _wait_before_clear_time;
    }

    bool progress = true;
    for (int i = 0; progress && i < 50; i++) {
        /* Allow the state machine to run. */
        enum ofctrl_state old_state = state;
        switch (state) {
#define STATE(NAME) case NAME: run_##NAME(); break;
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
                switch (state) {
#define STATE(NAME) case NAME: recv_##NAME(oh, type, pending_ct_zones); break;
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
        progress = old_state != state || msg;
    }
    if (progress) {
        /* We bailed out to limit the amount of work we do in one go, to allow
         * other code a chance to run.  We were still making progress at that
         * point, so ensure that we come back again without waiting. */
        poll_immediate_wake();
    }

    return reconnected;
}

void
ofctrl_wait(void)
{
    rconn_run_wait(swconn);
    rconn_recv_wait(swconn);
}

void
ofctrl_destroy(void)
{
    rconn_destroy(swconn);
    ovn_installed_flow_table_destroy();
    rconn_packet_counter_destroy(tx_counter);
    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
    ofctrl_meter_bands_destroy();
}

uint64_t
ofctrl_get_cur_cfg(void)
{
    return cur_cfg;
}

static ovs_be32
queue_msg(struct ofpbuf *msg)
{
    const struct ofp_header *oh = msg->data;
    ovs_be32 xid_ = oh->xid;
    rconn_send(swconn, msg, tx_counter);
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

static void
ofctrl_recv(const struct ofp_header *oh, enum ofptype type)
{
    if (type == OFPTYPE_ECHO_REQUEST) {
        queue_msg(ofputil_encode_echo_reply(oh));
    } else if (type == OFPTYPE_ERROR) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);
        log_openflow_rl(&rl, VLL_INFO, oh, "OpenFlow error");
        rconn_reconnect(swconn);
    } else {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);
        log_openflow_rl(&rl, VLL_DBG, oh, "OpenFlow packet ignored");
    }
}

static bool
flow_action_has_drop(const struct ovn_flow *f)
{
    return f->ofpacts_len == 0;
}

static bool
flow_action_has_conj(const struct ovn_flow *f)
{
    const struct ofpact *a = NULL;

    OFPACT_FOR_EACH (a, f->ofpacts, f->ofpacts_len) {
        if (a->type == OFPACT_CONJUNCTION) {
            return true;
        }
    }
    return false;
}

static bool
flow_action_has_allow(const struct ovn_flow *f)
{
    return !flow_action_has_drop(f) && !flow_action_has_conj(f);
}

/* Returns true if flow 'a' is preferred over flow 'b'. */
static bool
flow_is_preferred(const struct ovn_flow *a, const struct ovn_flow *b)
{
    if (flow_action_has_allow(b)) {
        return false;
    }
    if (flow_action_has_allow(a)) {
        return true;
    }
    if (flow_action_has_drop(b)) {
        return false;
    }
    if (flow_action_has_drop(a)) {
        return true;
    }

    /* Flows 'a' and 'b' should never both have action conjunction. */
    OVS_NOT_REACHED();
}

/* Adds the desired flow to the list of desired flows that have same match
 * conditions as the installed flow.
 *
 * It is caller's responsibility to make sure the link between the pair didn't
 * exist before.
 *
 * Returns true if the newly added desired flow is selected to be the active
 * one.
 */
static bool
link_installed_to_desired(struct installed_flow *i, struct desired_flow *d)
{
    struct desired_flow *f;

    /* Find first 'f' such that 'd' is preferred over 'f'.  If no such desired
     * flow exists then 'f' will point after the last element of the list.
     */
    LIST_FOR_EACH (f, installed_ref_list_node, &i->desired_refs) {
        if (flow_is_preferred(&d->flow, &f->flow)) {
            break;
        }
    }
    if (!f) {
        ovs_list_insert(&i->desired_refs, &d->installed_ref_list_node);
    } else {
        ovs_list_insert(&f->installed_ref_list_node,
                        &d->installed_ref_list_node);
    }
    d->installed_flow = i;
    return installed_flow_get_active(i) == d;
}

/* Replaces 'old_desired' with 'new_desired' in the list of desired flows
 * that have same match conditions as the installed flow.
 */
static void
replace_installed_to_desired(struct installed_flow *i,
                             struct desired_flow *old_desired,
                             struct desired_flow *new_desired)
{
    ovs_assert(old_desired->installed_flow == i);
    ovs_list_replace(&new_desired->installed_ref_list_node,
                     &old_desired->installed_ref_list_node);
    old_desired->installed_flow = NULL;
    new_desired->installed_flow = i;
}

/* Removes the desired flow from the list of desired flows that have the same
 * match conditions as the installed flow.
 *
 * Returns true if the desired flow was the previously active flow.
 */
static bool
unlink_installed_to_desired(struct installed_flow *i, struct desired_flow *d)
{
    struct desired_flow *old_active = installed_flow_get_active(i);

    ovs_assert(d && d->installed_flow == i);
    ovs_list_remove(&d->installed_ref_list_node);
    d->installed_flow = NULL;
    return old_active == d;
}

static void
unlink_all_refs_for_installed_flow(struct installed_flow *i)
{
    struct desired_flow *d;
    LIST_FOR_EACH_SAFE (d, installed_ref_list_node, &i->desired_refs) {
        unlink_installed_to_desired(i, d);
    }
}

static void
track_flow_add_or_modify(struct ovn_desired_flow_table *flow_table,
                         struct desired_flow *f)
{
    if (!flow_table->change_tracked) {
        return;
    }

    /* If same node (flow adding/modifying) was tracked, remove it from
     * tracking first. */
    if (!ovs_list_is_empty(&f->track_list_node)) {
        ovs_list_remove(&f->track_list_node);
    }
    f->is_deleted = false;
    ovs_list_push_back(&flow_table->tracked_flows, &f->track_list_node);

}

static void
track_flow_del(struct ovn_desired_flow_table *flow_table,
               struct desired_flow *f)
{
    if (!flow_table->change_tracked) {
        return;
    }
    /* If same node (flow adding/modifying) was tracked, remove it from
     * tracking first. */
    if (!ovs_list_is_empty(&f->track_list_node)) {
        ovs_list_remove(&f->track_list_node);
        if (!f->installed_flow) {
            /* If it is not installed yet, simply destroy it. */
            desired_flow_destroy(f);
            return;
        }
    }
    f->is_deleted = true;
    ovs_list_push_back(&flow_table->tracked_flows, &f->track_list_node);
}

/* When a desired flow is being removed, depending on "change_tracked", this
 * function either unlinks a desired flow from installed flow and destroy it,
 * or do nothing but track it. */
static void
track_or_destroy_for_flow_del(struct ovn_desired_flow_table *flow_table,
                              struct desired_flow *f)
{
    if (flow_table->change_tracked) {
        track_flow_del(flow_table, f);
    } else {
        if (f->installed_flow) {
            unlink_installed_to_desired(f->installed_flow, f);
        }
        desired_flow_destroy(f);
    }
}

static size_t
sb_flow_ref_size(const struct sb_flow_ref *sfr)
{
    return sizeof *sfr;
}

static size_t
sb_to_flow_size(const struct sb_to_flow *stf)
{
    return sizeof *stf;
}

static size_t
sb_addrset_ref_size(const struct sb_addrset_ref *sar)
{
    return sizeof *sar + strlen(sar->name) + 1;
}

static struct sb_to_flow *
sb_to_flow_find(struct hmap *uuid_flow_table, const struct uuid *sb_uuid)
{
    struct sb_to_flow *stf;
    HMAP_FOR_EACH_WITH_HASH (stf, hmap_node, uuid_hash(sb_uuid),
                            uuid_flow_table) {
        if (uuid_equals(sb_uuid, &stf->sb_uuid)) {
            return stf;
        }
    }
    return NULL;
}

static struct as_ip_to_flow_node *
as_ip_to_flow_find(struct hmap *as_ip_to_flow_map,
                   const struct in6_addr *as_ip,
                   const struct in6_addr *as_mask)
{
    uint32_t hash = hash_bytes(as_ip, sizeof *as_ip, 0);

    struct as_ip_to_flow_node *itfn;
    HMAP_FOR_EACH_WITH_HASH (itfn, hmap_node, hash, as_ip_to_flow_map) {
        if (ipv6_addr_equals(&itfn->as_ip, as_ip)
            && ipv6_addr_equals(&itfn->as_mask, as_mask)) {
            return itfn;
        }
    }
    return NULL;
}

static void
link_flow_to_sb(struct ovn_desired_flow_table *flow_table,
                struct desired_flow *f, const struct uuid *sb_uuid,
                const struct addrset_info *as_info)
{
    struct sb_flow_ref *sfr = xmalloc(sizeof *sfr);
    mem_stats.sb_flow_ref_usage += sb_flow_ref_size(sfr);
    sfr->flow = f;
    sfr->sb_uuid = *sb_uuid;
    ovs_list_insert(&f->references, &sfr->sb_list);
    struct sb_to_flow *stf = sb_to_flow_find(&flow_table->uuid_flow_table,
                                             sb_uuid);
    if (!stf) {
        stf = xmalloc(sizeof *stf);
        mem_stats.sb_flow_ref_usage += sb_to_flow_size(stf);
        stf->sb_uuid = *sb_uuid;
        ovs_list_init(&stf->flows);
        ovs_list_init(&stf->addrsets);
        hmap_insert(&flow_table->uuid_flow_table, &stf->hmap_node,
                    uuid_hash(sb_uuid));
    }
    ovs_list_insert(&stf->flows, &sfr->flow_list);

    if (!as_info) {
        ovs_list_init(&sfr->as_ip_flow_list);
        return;
    }

    /* link flow to address_set + ip */
    struct sb_addrset_ref *sar;
    bool found = false;
    LIST_FOR_EACH (sar, list_node, &stf->addrsets) {
        if (!strcmp(sar->name, as_info->name)) {
            found = true;
            break;
        }
    }
    if (!found) {
        sar = xmalloc(sizeof *sar);
        sar->name = xstrdup(as_info->name);
        mem_stats.sb_flow_ref_usage += sb_addrset_ref_size(sar);
        hmap_init(&sar->as_ip_to_flow_map);
        ovs_list_insert(&stf->addrsets, &sar->list_node);
    }

    struct as_ip_to_flow_node * itfn =
        as_ip_to_flow_find(&sar->as_ip_to_flow_map, &as_info->ip,
                           &as_info->mask);
    if (!itfn) {
        itfn = xmalloc(sizeof *itfn);
        mem_stats.sb_flow_ref_usage += sizeof *itfn;
        itfn->as_ip = as_info->ip;
        itfn->as_mask = as_info->mask;
        ovs_list_init(&itfn->flows);
        uint32_t hash = hash_bytes(&as_info->ip, sizeof as_info->ip, 0);
        hmap_insert(&sar->as_ip_to_flow_map, &itfn->hmap_node, hash);
    }

    ovs_list_insert(&itfn->flows, &sfr->as_ip_flow_list);
}

/* Flow table interfaces to the rest of ovn-controller. */

/* Adds a flow to 'desired_flows' with the specified 'match' and 'actions' to
 * the OpenFlow table numbered 'table_id' with the given 'priority', OpenFlow
 * 'cookie' and 'meter_id'. The caller retains ownership of 'match' and
 * 'actions'.
 *
 * The flow is also linked to the sb_uuid that generates it.
 *
 * This just assembles the desired flow table in memory.  Nothing is actually
 * sent to the switch until a later call to ofctrl_put().
 *
 * The caller should initialize its own hmap to hold the flows. */
void
ofctrl_check_and_add_flow_metered(struct ovn_desired_flow_table *flow_table,
                                  uint8_t table_id, uint16_t priority,
                                  uint64_t cookie,
                                  const struct match *match,
                                  const struct ofpbuf *actions,
                                  const struct uuid *sb_uuid,
                                  uint32_t meter_id,
                                  const struct addrset_info *as_info,
                                  bool log_duplicate_flow)
{
    struct desired_flow *f = desired_flow_alloc(table_id, priority, cookie,
                                                match, actions,
                                                meter_id);

    if (desired_flow_lookup_check_uuid(flow_table, &f->flow, sb_uuid)) {
        if (log_duplicate_flow) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
            if (!VLOG_DROP_DBG(&rl)) {
                char *s = ovn_flow_to_string(&f->flow);
                VLOG_DBG("dropping duplicate flow: %s", s);
                free(s);
            }
        }
        desired_flow_destroy(f);
        return;
    }

    hmap_insert(&flow_table->match_flow_table, &f->match_hmap_node,
                f->flow.hash);
    link_flow_to_sb(flow_table, f, sb_uuid, as_info);
    track_flow_add_or_modify(flow_table, f);
    ovn_flow_log(&f->flow, "ofctrl_add_flow");
}

void
ofctrl_add_flow(struct ovn_desired_flow_table *desired_flows,
                uint8_t table_id, uint16_t priority, uint64_t cookie,
                const struct match *match, const struct ofpbuf *actions,
                const struct uuid *sb_uuid)
{
    ofctrl_add_flow_metered(desired_flows, table_id, priority, cookie,
                            match, actions, sb_uuid, NX_CTLR_NO_METER, NULL);
}

void
ofctrl_add_flow_metered(struct ovn_desired_flow_table *desired_flows,
                        uint8_t table_id, uint16_t priority, uint64_t cookie,
                        const struct match *match,
                        const struct ofpbuf *actions,
                        const struct uuid *sb_uuid, uint32_t meter_id,
                        const struct addrset_info *as_info)
{
    ofctrl_check_and_add_flow_metered(desired_flows, table_id, priority,
                                      cookie, match, actions, sb_uuid,
                                      meter_id, as_info, true);
}

struct ofpact_ref {
    struct hmap_node hmap_node;
    struct ofpact *ofpact;
};

static struct ofpact_ref *
ofpact_ref_find(const struct hmap *refs, const struct ofpact *ofpact)
{
    uint32_t hash = hash_bytes(ofpact, ofpact->len, 0);

    struct ofpact_ref *ref;
    HMAP_FOR_EACH_WITH_HASH (ref, hmap_node, hash, refs) {
        if (ofpacts_equal(ref->ofpact, ref->ofpact->len,
                          ofpact, ofpact->len)) {
            return ref;
        }
    }

    return NULL;
}

static void
ofpact_refs_destroy(struct hmap *refs)
{
    struct ofpact_ref *ref;
    HMAP_FOR_EACH_POP (ref, hmap_node, refs) {
        free(ref);
    }
    hmap_destroy(refs);
}

/* Either add a new flow, or append actions on an existing flow. If the
 * flow existed, a new link will also be created between the new sb_uuid
 * and the existing flow. */
void
ofctrl_add_or_append_flow(struct ovn_desired_flow_table *desired_flows,
                          uint8_t table_id, uint16_t priority, uint64_t cookie,
                          const struct match *match,
                          const struct ofpbuf *actions,
                          const struct uuid *sb_uuid,
                          uint32_t meter_id,
                          const struct addrset_info *as_info)
{
    struct desired_flow *existing;
    struct desired_flow *f;

    f = desired_flow_alloc(table_id, priority, cookie, match, actions,
                           meter_id);
    existing = desired_flow_lookup_conjunctive(desired_flows, &f->flow);
    if (existing) {
        struct hmap existing_conj = HMAP_INITIALIZER(&existing_conj);

        struct ofpact *ofpact;
        OFPACT_FOR_EACH (ofpact, existing->flow.ofpacts,
                         existing->flow.ofpacts_len) {
            if (ofpact->type != OFPACT_CONJUNCTION) {
                continue;
            }

            struct ofpact_ref *ref = xmalloc(sizeof *ref);
            ref->ofpact = ofpact;
            uint32_t hash = hash_bytes(ofpact, ofpact->len, 0);
            hmap_insert(&existing_conj, &ref->hmap_node, hash);
        }

        /* There's already a flow with this particular match and action
         * 'conjunction'. Append the action to that flow rather than
         * adding a new flow.
         */
        uint64_t compound_stub[64 / 8];
        struct ofpbuf compound;
        ofpbuf_use_stub(&compound, compound_stub, sizeof(compound_stub));
        ofpbuf_put(&compound, existing->flow.ofpacts,
                   existing->flow.ofpacts_len);

        OFPACT_FOR_EACH (ofpact, f->flow.ofpacts, f->flow.ofpacts_len) {
            if (ofpact->type != OFPACT_CONJUNCTION ||
                !ofpact_ref_find(&existing_conj, ofpact)) {
                ofpbuf_put(&compound, ofpact, OFPACT_ALIGN(ofpact->len));
            }
        }

        ofpact_refs_destroy(&existing_conj);

        mem_stats.desired_flow_usage -= desired_flow_size(existing);
        free(existing->flow.ofpacts);
        existing->flow.ofpacts = xmemdup(compound.data, compound.size);
        existing->flow.ofpacts_len = compound.size;
        mem_stats.desired_flow_usage += desired_flow_size(existing);

        ofpbuf_uninit(&compound);
        desired_flow_destroy(f);
        f = existing;

        /* Since the flow now shared by more than one SB lflows, don't track
         * it with address set ips. So remove any existed as_info tracking, and
         * then add the new sb link without as_info.
         *
         * XXX: this may still be tracked if the flow is shared by different
         * lflows, but we need to remove the related conjunction from the
         * actions properly when handle addrset ip deletion, instead of simply
         * delete the flow. */
        struct sb_flow_ref *sfr;
        LIST_FOR_EACH (sfr, sb_list, &f->references) {
            ovs_list_remove(&sfr->as_ip_flow_list);
            ovs_list_init(&sfr->as_ip_flow_list);
        }
        link_flow_to_sb(desired_flows, f, sb_uuid, NULL);
    } else {
        hmap_insert(&desired_flows->match_flow_table, &f->match_hmap_node,
                    f->flow.hash);
        link_flow_to_sb(desired_flows, f, sb_uuid, as_info);
    }
    track_flow_add_or_modify(desired_flows, f);

    if (existing) {
        ovn_flow_log(&f->flow, "ofctrl_add_or_append_flow (append)");
    } else {
        ovn_flow_log(&f->flow, "ofctrl_add_or_append_flow (add)");
    }
}

void
ofctrl_remove_flows(struct ovn_desired_flow_table *flow_table,
                    const struct uuid *sb_uuid)
{
    struct sb_to_flow *stf = sb_to_flow_find(&flow_table->uuid_flow_table,
                                             sb_uuid);
    if (stf) {
        remove_flows_from_sb_to_flow(flow_table, stf, "ofctrl_remove_flow",
                                     NULL);
    }

    /* remove any related group and meter info */
    ovn_extend_table_remove_desired(groups, sb_uuid);
    ovn_extend_table_remove_desired(meters, sb_uuid);
}

static void
flood_remove_flows_for_sb_uuid(struct ovn_desired_flow_table *flow_table,
                               const struct uuid *sb_uuid,
                               struct uuidset *flood_remove_nodes)
{
    struct sb_to_flow *stf = sb_to_flow_find(&flow_table->uuid_flow_table,
                                             sb_uuid);
    if (!stf) {
        return;
    }

    remove_flows_from_sb_to_flow(flow_table, stf, "flood remove",
                                 flood_remove_nodes);
}

void
ofctrl_flood_remove_flows(struct ovn_desired_flow_table *flow_table,
                          struct uuidset *flood_remove_nodes)
{
    /* flood_remove_flows_for_sb_uuid() will modify the 'flood_remove_nodes'
     * hash map by inserting new items, so we can't use it for iteration.
     * Copying the sb_uuids into an array. */
    struct uuid *sb_uuids = uuidset_array(flood_remove_nodes);
    size_t n = uuidset_count(flood_remove_nodes);

    for (size_t i = 0; i < n; i++) {
        flood_remove_flows_for_sb_uuid(flow_table, &sb_uuids[i],
                                       flood_remove_nodes);
    }
    free(sb_uuids);

    /* remove any related group and meter info */
    struct uuidset_node *ofrn;
    UUIDSET_FOR_EACH (ofrn, flood_remove_nodes) {
        ovn_extend_table_remove_desired(groups, &ofrn->uuid);
        ovn_extend_table_remove_desired(meters, &ofrn->uuid);
    }
}

/* Remove desired flows related to the specified 'addrset_info' for the
 * 'lflow_uuid'. Returns true if it can be processed completely, otherwise
 * returns false, which would trigger a reprocessing of the lflow of
 * 'lflow_uuid'. The expected_count is checked against the actual flows
 * deleted, and if it doesn't match, return false, too. */
bool
ofctrl_remove_flows_for_as_ip(struct ovn_desired_flow_table *flow_table,
                              const struct uuid *lflow_uuid,
                              const struct addrset_info *as_info,
                              size_t expected_count)
{
    struct sb_to_flow *stf = sb_to_flow_find(&flow_table->uuid_flow_table,
                                             lflow_uuid);
    if (!stf) {
        /* No such flow, nothing needs to be done. */
        return true;
    }

    struct sb_addrset_ref *sar;
    bool found = false;
    LIST_FOR_EACH (sar, list_node, &stf->addrsets) {
        if (!strcmp(sar->name, as_info->name)) {
            found = true;
            break;
        }
    }
    if (!found) {
        /* No address set tracking infomation found, can't perform the
         * deletion. */
        return false;
    }

    struct as_ip_to_flow_node *itfn =
        as_ip_to_flow_find(&sar->as_ip_to_flow_map, &as_info->ip,
                           &as_info->mask);
    if (!itfn) {
        /* This ip wasn't tracked, probably because it maps to a flow that has
         * compound conjunction actions for the same ip from multiple address
         * sets. */
        return false;
    }
    struct sb_flow_ref *sfr;
    size_t count = 0;
    LIST_FOR_EACH_SAFE (sfr, as_ip_flow_list, &itfn->flows) {
        /* If the desired flow is referenced by multiple sb lflows, it
         * shouldn't have been indexed by address set. */
        ovs_assert(ovs_list_is_short(&sfr->sb_list));

        ovs_list_remove(&sfr->sb_list);
        ovs_list_remove(&sfr->flow_list);
        ovs_list_remove(&sfr->as_ip_flow_list);

        struct desired_flow *f = sfr->flow;
        mem_stats.sb_flow_ref_usage -= sb_flow_ref_size(sfr);
        free(sfr);

        ovs_assert(ovs_list_is_empty(&f->list_node));
        ovs_assert(ovs_list_is_empty(&f->references));
        ovn_flow_log(&f->flow, "remove_flows_for_as_ip");
        hmap_remove(&flow_table->match_flow_table,
                    &f->match_hmap_node);
        track_or_destroy_for_flow_del(flow_table, f);
        count++;
    }

    hmap_remove(&sar->as_ip_to_flow_map, &itfn->hmap_node);
    mem_stats.sb_flow_ref_usage -= sizeof *itfn;
    free(itfn);
    return (count == expected_count);
}

/* Remove ovn_flows for the given "sb_to_flow" node in the uuid_flow_table.
 * Optionally log the message for each flow that is acturally removed, if
 * log_msg is not NULL. */
static void
remove_flows_from_sb_to_flow(struct ovn_desired_flow_table *flow_table,
                             struct sb_to_flow *stf,
                             const char *log_msg,
                             struct uuidset *flood_remove_nodes)
{
    /* ovn_flows that have other references and waiting to be removed. */
    struct ovs_list to_be_removed = OVS_LIST_INITIALIZER(&to_be_removed);

    /* Traverse all flows for the given sb_uuid. */
    struct sb_flow_ref *sfr;
    LIST_FOR_EACH_SAFE (sfr, flow_list, &stf->flows) {
        ovs_list_remove(&sfr->sb_list);
        ovs_list_remove(&sfr->flow_list);
        ovs_list_remove(&sfr->as_ip_flow_list);
        struct desired_flow *f = sfr->flow;
        mem_stats.sb_flow_ref_usage -= sb_flow_ref_size(sfr);
        free(sfr);

        ovs_assert(ovs_list_is_empty(&f->list_node));
        if (ovs_list_is_empty(&f->references)) {
            if (log_msg) {
                ovn_flow_log(&f->flow, log_msg);
            }
            hmap_remove(&flow_table->match_flow_table,
                        &f->match_hmap_node);
            track_or_destroy_for_flow_del(flow_table, f);
        } else if (flood_remove_nodes) {
            ovs_list_insert(&to_be_removed, &f->list_node);
        }
    }

    struct sb_addrset_ref *sar;
    LIST_FOR_EACH_SAFE (sar, list_node, &stf->addrsets) {
        ovs_list_remove(&sar->list_node);
        struct as_ip_to_flow_node *itfn;
        HMAP_FOR_EACH_SAFE (itfn, hmap_node, &sar->as_ip_to_flow_map) {
            hmap_remove(&sar->as_ip_to_flow_map, &itfn->hmap_node);
            ovs_assert(ovs_list_is_empty(&itfn->flows));
            mem_stats.sb_flow_ref_usage -= sizeof *itfn;
            free(itfn);
        }
        hmap_destroy(&sar->as_ip_to_flow_map);
        mem_stats.sb_flow_ref_usage -= sb_addrset_ref_size(sar);
        free(sar->name);
        free(sar);
    }

    hmap_remove(&flow_table->uuid_flow_table, &stf->hmap_node);
    mem_stats.sb_flow_ref_usage -= sb_to_flow_size(stf);
    free(stf);

    /* Traverse other referencing sb_uuids for the flows in the to_be_removed
     * list. */

    /* Detach the items in f->references from the sfr.flow_list lists,
     * so that recursive calls will not mess up the sfr.sb_list list. */
    struct desired_flow *f;
    LIST_FOR_EACH (f, list_node, &to_be_removed) {
        ovs_assert(!ovs_list_is_empty(&f->references));
        LIST_FOR_EACH (sfr, sb_list, &f->references) {
            ovs_list_remove(&sfr->flow_list);
            ovs_list_remove(&sfr->as_ip_flow_list);
        }
    }
    LIST_FOR_EACH_SAFE (f, list_node, &to_be_removed) {
        LIST_FOR_EACH_SAFE (sfr, sb_list, &f->references) {
            if (!uuidset_find(flood_remove_nodes, &sfr->sb_uuid)) {
                uuidset_insert(flood_remove_nodes, &sfr->sb_uuid);
                flood_remove_flows_for_sb_uuid(flow_table, &sfr->sb_uuid,
                                               flood_remove_nodes);
            }
            ovs_list_remove(&sfr->sb_list);
            mem_stats.sb_flow_ref_usage -= sb_flow_ref_size(sfr);
            free(sfr);
        }
        ovs_list_remove(&f->list_node);
        if (log_msg) {
            ovn_flow_log(&f->flow, log_msg);
        }
        hmap_remove(&flow_table->match_flow_table,
                    &f->match_hmap_node);
        track_or_destroy_for_flow_del(flow_table, f);
    }
}

/* flow operations. */

static void
ovn_flow_init(struct ovn_flow *f, uint8_t table_id, uint16_t priority,
              uint64_t cookie, const struct match *match,
              const struct ofpbuf *actions, uint32_t meter_id)
{
    f->table_id = table_id;
    f->priority = priority;
    minimatch_init(&f->match, match);
    f->ofpacts = xmemdup(actions->data, actions->size);
    f->ofpacts_len = actions->size;
    f->hash = ovn_flow_match_hash(f);
    f->cookie = cookie;
    f->ctrl_meter_id = meter_id;
}

static size_t
desired_flow_size(const struct desired_flow *f)
{
    return sizeof *f + f->flow.ofpacts_len;
}

static struct desired_flow *
desired_flow_alloc(uint8_t table_id, uint16_t priority, uint64_t cookie,
                   const struct match *match, const struct ofpbuf *actions,
                   uint32_t meter_id)
{
    struct desired_flow *f = xmalloc(sizeof *f);
    ovs_list_init(&f->references);
    ovs_list_init(&f->list_node);
    ovs_list_init(&f->installed_ref_list_node);
    ovs_list_init(&f->track_list_node);
    f->installed_flow = NULL;
    f->is_deleted = false;
    ovn_flow_init(&f->flow, table_id, priority, cookie, match, actions,
                  meter_id);

    mem_stats.desired_flow_usage += desired_flow_size(f);
    return f;
}

/* Returns a hash of the match key in 'f'. */
static uint32_t
ovn_flow_match_hash(const struct ovn_flow *f)
{
    return hash_2words((f->table_id << 16) | f->priority,
                       minimatch_hash(&f->match, 0));
}

static size_t
installed_flow_size(const struct installed_flow *f)
{
    return sizeof *f + f->flow.ofpacts_len;
}

/* Duplicate a desired flow to an installed flow. */
static struct installed_flow *
installed_flow_dup(struct desired_flow *src)
{
    struct installed_flow *dst = xmalloc(sizeof *dst);
    ovs_list_init(&dst->desired_refs);
    dst->flow.table_id = src->flow.table_id;
    dst->flow.priority = src->flow.priority;
    minimatch_clone(&dst->flow.match, &src->flow.match);
    dst->flow.ofpacts = xmemdup(src->flow.ofpacts, src->flow.ofpacts_len);
    dst->flow.ofpacts_len = src->flow.ofpacts_len;
    dst->flow.hash = src->flow.hash;
    dst->flow.cookie = src->flow.cookie;
    dst->flow.ctrl_meter_id = src->flow.ctrl_meter_id;
    mem_stats.installed_flow_usage += installed_flow_size(dst);
    return dst;
}

static struct desired_flow *
installed_flow_get_active(struct installed_flow *f)
{
    if (!ovs_list_is_empty(&f->desired_refs)) {
        return CONTAINER_OF(ovs_list_front(&f->desired_refs),
                            struct desired_flow,
                            installed_ref_list_node);
    }
    return NULL;
}

static struct desired_flow *
desired_flow_lookup__(struct ovn_desired_flow_table *flow_table,
                      const struct ovn_flow *target,
                      desired_flow_match_cb match_cb,
                      const void *arg)
{
    struct desired_flow *d;
    HMAP_FOR_EACH_WITH_HASH (d, match_hmap_node, target->hash,
                             &flow_table->match_flow_table) {
        struct ovn_flow *f = &d->flow;
        if (f->table_id == target->table_id
            && f->priority == target->priority
            && f->ctrl_meter_id == target->ctrl_meter_id
            && minimatch_equal(&f->match, &target->match)) {

            if (!match_cb || match_cb(d, arg)) {
                return d;
            }
        }
    }
    return NULL;
}

/* Finds and returns a desired_flow in 'flow_table' whose key is identical to
 * 'target''s key, or NULL if there is none.
 */
static struct desired_flow *
desired_flow_lookup(struct ovn_desired_flow_table *flow_table,
                    const struct ovn_flow *target)
{
    return desired_flow_lookup__(flow_table, target, NULL, NULL);
}

static bool
flow_lookup_match_uuid_cb(const struct desired_flow *candidate,
                          const void *arg)
{
    const struct uuid *sb_uuid = arg;
    struct sb_flow_ref *sfr;

    LIST_FOR_EACH (sfr, sb_list, &candidate->references) {
        if (uuid_equals(sb_uuid, &sfr->sb_uuid)) {
            return true;
        }
    }
    return false;
}

/* Finds and returns a desired_flow in 'flow_table' whose key is identical to
 * 'target''s key, or NULL if there is none.
 *
 * The function will also check if the found flow is referenced by the
 * 'sb_uuid'.
 */
static struct desired_flow *
desired_flow_lookup_check_uuid(struct ovn_desired_flow_table *flow_table,
                            const struct ovn_flow *target,
                            const struct uuid *sb_uuid)
{
    return desired_flow_lookup__(flow_table, target, flow_lookup_match_uuid_cb,
                                 sb_uuid);
}

static bool
flow_lookup_match_conj_cb(const struct desired_flow *candidate,
                          const void *arg OVS_UNUSED)
{
    return flow_action_has_conj(&candidate->flow);
}

/* Finds and returns a desired_flow in 'flow_table' whose key is identical to
 * 'target''s key, or NULL if there is none.
 *
 * The function will only return a matching flow if it contains action
 * 'conjunction'.
 */
static struct desired_flow *
desired_flow_lookup_conjunctive(struct ovn_desired_flow_table *flow_table,
                                const struct ovn_flow *target)
{
    return desired_flow_lookup__(flow_table, target, flow_lookup_match_conj_cb,
                                 NULL);
}

/* Finds and returns an installed_flow in installed_flows whose key is
 * identical to 'target''s key, or NULL if there is none. */
static struct installed_flow *
installed_flow_lookup(const struct ovn_flow *target,
                      struct hmap *installed_flows)
{
    struct installed_flow *i;
    HMAP_FOR_EACH_WITH_HASH (i, match_hmap_node, target->hash,
                             installed_flows) {
        struct ovn_flow *f = &i->flow;
        if (f->table_id == target->table_id
            && f->priority == target->priority
            && minimatch_equal(&f->match, &target->match)) {
            return i;
        }
    }
    return NULL;
}

static char *
ovn_flow_to_string(const struct ovn_flow *f)
{
    struct ds s = DS_EMPTY_INITIALIZER;

    ds_put_format(&s, "cookie=%"PRIx64", ", f->cookie);
    ds_put_format(&s, "table_id=%"PRIu8", ", f->table_id);
    ds_put_format(&s, "priority=%"PRIu16", ", f->priority);
    minimatch_format(&f->match, NULL, NULL, &s, OFP_DEFAULT_PRIORITY);
    ds_put_cstr(&s, ", actions=");
    struct ofpact_format_params fp = { .s = &s };
    ofpacts_format(f->ofpacts, f->ofpacts_len, &fp);
    return ds_steal_cstr(&s);
}

static void
ovn_flow_log(const struct ovn_flow *f, const char *action)
{
    if (VLOG_IS_DBG_ENABLED()) {
        char *s = ovn_flow_to_string(f);
        VLOG_DBG("%s flow: %s", action, s);
        free(s);
    }
}

static void
ovn_flow_log_size_err(const struct ovn_flow *f)
{
    COVERAGE_INC(ofctrl_msg_too_long);

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

    char *s = ovn_flow_to_string(f);
    VLOG_ERR_RL(&rl, "The FLOW_MOD message is too big: %s", s);
    free(s);
}

static void
ovn_flow_uninit(struct ovn_flow *f)
{
    minimatch_destroy(&f->match);
    free(f->ofpacts);
}

static void
desired_flow_destroy(struct desired_flow *f)
{
    if (f) {
        ovs_assert(ovs_list_is_empty(&f->references));
        ovs_assert(!f->installed_flow);
        mem_stats.desired_flow_usage -= desired_flow_size(f);
        ovn_flow_uninit(&f->flow);
        free(f);
    }
}

static void
installed_flow_destroy(struct installed_flow *f)
{
    if (f) {
        ovs_assert(!installed_flow_get_active(f));
        mem_stats.installed_flow_usage -= installed_flow_size(f);
        ovn_flow_uninit(&f->flow);
        free(f);
    }
}

/* Desired flow table operations. */
void
ovn_desired_flow_table_init(struct ovn_desired_flow_table *flow_table)
{
    hmap_init(&flow_table->match_flow_table);
    hmap_init(&flow_table->uuid_flow_table);
    ovs_list_init(&flow_table->tracked_flows);
    flow_table->change_tracked = false;
}

void
ovn_desired_flow_table_clear(struct ovn_desired_flow_table *flow_table)
{
    flow_table->change_tracked = false;

    struct desired_flow *f;
    LIST_FOR_EACH_SAFE (f, track_list_node, &flow_table->tracked_flows) {
        ovs_list_remove(&f->track_list_node);
        if (f->is_deleted) {
            if (f->installed_flow) {
                unlink_installed_to_desired(f->installed_flow, f);
            }
            desired_flow_destroy(f);
        }
    }

    struct sb_to_flow *stf;
    HMAP_FOR_EACH_SAFE (stf, hmap_node, &flow_table->uuid_flow_table) {
        remove_flows_from_sb_to_flow(flow_table, stf, NULL, NULL);
    }
}

void
ovn_desired_flow_table_destroy(struct ovn_desired_flow_table *flow_table)
{
    ovn_desired_flow_table_clear(flow_table);
    hmap_destroy(&flow_table->match_flow_table);
    hmap_destroy(&flow_table->uuid_flow_table);
}


/* Installed flow table operations. */
static void
ovn_installed_flow_table_clear(void)
{
    struct installed_flow *f;
    HMAP_FOR_EACH_SAFE (f, match_hmap_node, &installed_lflows) {
        hmap_remove(&installed_lflows, &f->match_hmap_node);
        unlink_all_refs_for_installed_flow(f);
        installed_flow_destroy(f);
    }

    HMAP_FOR_EACH_SAFE (f, match_hmap_node, &installed_pflows) {
        hmap_remove(&installed_pflows, &f->match_hmap_node);
        unlink_all_refs_for_installed_flow(f);
        installed_flow_destroy(f);
    }
}

static void
ovn_installed_flow_table_destroy(void)
{
    ovn_installed_flow_table_clear();
    hmap_destroy(&installed_lflows);
    hmap_destroy(&installed_pflows);
}

/* Flow table update. */

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

/* group_table. */

static struct ofpbuf *
encode_group_mod(const struct ofputil_group_mod *gm)
{
    return ofputil_encode_group_mod(OFP15_VERSION, gm, NULL, -1);
}

static void
add_group_mod(struct ofputil_group_mod *gm,
              struct ofputil_bundle_ctrl_msg *bc,
              struct ovs_list *msgs)
{
    struct ofpbuf *msg = encode_group_mod(gm);
    if ((msg->size + sizeof(struct ofp14_bundle_ctrl_msg)) <= UINT16_MAX) {
        struct ofpbuf *bundle_msg = encode_bundle_add(msg, bc);
        ofpbuf_delete(msg);
        ovs_list_push_back(msgs, &bundle_msg->list_node);
        return;
    }

    /* This group mod request is too large to fit in a single OF message
     * since the header can only specify a 16-bit size. We need to break
     * this into multiple group_mod requests.
     */

    /* Pull the first bucket. All buckets are approximately the same length
     * since they contain near-identical actions. Using its length can give
     * us a good approximation of how many buckets we can fit in a single
     * OF message.
     */
    ofpraw_pull_assert(msg);
    struct ofp15_group_mod *ogm = ofpbuf_pull(msg, sizeof(*ogm));
    struct ofp15_bucket *of_bucket = ofpbuf_pull(msg, sizeof(*of_bucket));
    uint16_t bucket_size = ntohs(of_bucket->len);

    ofpbuf_delete(msg);

    /* Dividing by 2 here ensures that just in case there are variations in
     * the size of the buckets, we will not put too many in our new group_mod
     * message.
     */
    size_t max_buckets = ((UINT16_MAX - sizeof *ogm -
                           sizeof(struct ofp14_bundle_ctrl_msg)) / bucket_size)
                         / 2;

    ovs_assert(max_buckets < ovs_list_size(&gm->buckets));

    uint16_t command = OFPGC15_INSERT_BUCKET;
    if (gm->command == OFPGC15_DELETE ||
        gm->command == OFPGC15_REMOVE_BUCKET) {
        command = OFPGC15_REMOVE_BUCKET;
    }
    struct ofputil_group_mod split = {
        .command = command,
        .type = gm->type,
        .group_id = gm->group_id,
        .command_bucket_id = OFPG15_BUCKET_LAST,
    };
    ovs_list_init(&split.buckets);

    size_t i = 0;
    struct ofputil_bucket *bucket;
    LIST_FOR_EACH (bucket, list_node, &gm->buckets) {
        if (i++ < max_buckets) {
            continue;
        }
        break;
    }

    ovs_list_splice(&split.buckets, &bucket->list_node, &gm->buckets);

    struct ofpbuf *orig = encode_group_mod(gm);
    struct ofpbuf *bundle_msg = encode_bundle_add(orig, bc);
    ofpbuf_delete(orig);
    ovs_list_push_back(msgs, &bundle_msg->list_node);

    /* We call this recursively just in case our new
     * INSERT_BUCKET/REMOVE_BUCKET group_mod is still too
     * large for an OF message. This will allow for it to
     * be broken into pieces, too.
     */
    add_group_mod(&split, bc, msgs);
    ofputil_uninit_group_mod(&split);
}


static struct ofpbuf *
encode_meter_mod(const struct ofputil_meter_mod *mm)
{
    return ofputil_encode_meter_mod(OFP15_VERSION, mm);
}

static void
add_meter_mod(const struct ofputil_meter_mod *mm, struct ovs_list *msgs)
{
    struct ofpbuf *msg = encode_meter_mod(mm);
    ovs_list_push_back(msgs, &msg->list_node);
}

static void
add_ct_flush_zone(uint16_t zone_id, struct ovs_list *msgs)
{
    struct ofpbuf *msg = ofpraw_alloc(OFPRAW_NXT_CT_FLUSH_ZONE,
                                      rconn_get_version(swconn), 0);
    struct nx_zone_id *nzi = ofpbuf_put_zeros(msg, sizeof *nzi);
    nzi->zone_id = htons(zone_id);

    ovs_list_push_back(msgs, &msg->list_node);
}

static void
add_meter_string(struct ovn_extend_table_info *m_desired,
                 struct ovs_list *msgs)
{
    /* Create and install new meter. */
    struct ofputil_meter_mod mm;
    enum ofputil_protocol usable_protocols;
    char *meter_string = xasprintf("meter=%"PRIu32",%s",
                                   m_desired->table_id,
                                   &m_desired->name[52]);
    char *error = parse_ofp_meter_mod_str(&mm, meter_string, OFPMC13_ADD,
                                          &usable_protocols);
    if (!error) {
        add_meter_mod(&mm, msgs);
        free(mm.meter.bands);
    } else {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_ERR_RL(&rl, "new meter %s %s", error, meter_string);
        free(error);
    }
    free(meter_string);
}

static void
update_ovs_meter(struct ovn_extend_table_info *entry,
                 const struct sbrec_meter *sb_meter, int cmd,
                 struct ovs_list *msgs)
{

    struct ofputil_meter_mod mm;
    mm.command = cmd;
    mm.meter.meter_id = entry->table_id;
    mm.meter.flags = OFPMF13_STATS;

    if (!strcmp(sb_meter->unit, "pktps")) {
        mm.meter.flags |= OFPMF13_PKTPS;
    } else {
        mm.meter.flags |= OFPMF13_KBPS;
    }

    mm.meter.n_bands = sb_meter->n_bands;
    mm.meter.bands = xcalloc(mm.meter.n_bands, sizeof *mm.meter.bands);

    for (size_t i = 0; i < sb_meter->n_bands; i++) {
        struct sbrec_meter_band *sb_band = sb_meter->bands[i];
        struct ofputil_meter_band *mm_band = &mm.meter.bands[i];

        if (!strcmp(sb_band->action, "drop")) {
            mm_band->type = OFPMBT13_DROP;
        }

        mm_band->prec_level = 0;
        mm_band->rate = sb_band->rate;
        mm_band->burst_size = sb_band->burst_size;

        if (mm_band->burst_size) {
            mm.meter.flags |= OFPMF13_BURST;
        }
    }

    add_meter_mod(&mm, msgs);
    free(mm.meter.bands);
}

static void
ofctrl_meter_bands_clear(void)
{
    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &meter_bands) {
        struct meter_band_entry *mb = node->data;
        shash_delete(&meter_bands, node);
        free(mb->bands);
        free(mb);
    }
}

static void
ofctrl_meter_bands_destroy(void)
{
    ofctrl_meter_bands_clear();
    shash_destroy(&meter_bands);
}

static bool
ofctrl_meter_bands_is_equal(const struct sbrec_meter *sb_meter,
                            struct meter_band_entry *mb)
{
    if (mb->n_bands != sb_meter->n_bands) {
        return false;
    }

    for (int i = 0; i < sb_meter->n_bands; i++) {
        int j;
        for (j = 0; j < mb->n_bands; j++) {
            if (sb_meter->bands[i]->rate == mb->bands[j].rate &&
                sb_meter->bands[i]->burst_size == mb->bands[j].burst_size) {
                break;
            }
        }
        if (j == mb->n_bands) {
            return false;
        }
    }
    return true;
}

static void
ofctrl_meter_bands_alloc(const struct sbrec_meter *sb_meter,
                         struct ovn_extend_table_info *entry,
                         struct ovs_list *msgs)
{
    struct meter_band_entry *mb = mb = xzalloc(sizeof *mb);
    mb->n_bands = sb_meter->n_bands;
    mb->bands = xcalloc(mb->n_bands, sizeof *mb->bands);
    for (int i = 0; i < sb_meter->n_bands; i++) {
        mb->bands[i].rate = sb_meter->bands[i]->rate;
        mb->bands[i].burst_size = sb_meter->bands[i]->burst_size;
    }
    shash_add(&meter_bands, entry->name, mb);
    update_ovs_meter(entry, sb_meter, OFPMC13_ADD, msgs);
}

static void
ofctrl_meter_bands_update(const struct sbrec_meter *sb_meter,
                          struct ovn_extend_table_info *entry,
                          struct ovs_list *msgs)
{
    struct meter_band_entry *mb =
        shash_find_data(&meter_bands, entry->name);
    if (!mb) {
        ofctrl_meter_bands_alloc(sb_meter, entry, msgs);
        return;
    }

    if (ofctrl_meter_bands_is_equal(sb_meter, mb)) {
        return;
    }

    free(mb->bands);
    mb->n_bands = sb_meter->n_bands;
    mb->bands = xcalloc(mb->n_bands, sizeof *mb->bands);
    for (int i = 0; i < sb_meter->n_bands; i++) {
        mb->bands[i].rate = sb_meter->bands[i]->rate;
        mb->bands[i].burst_size = sb_meter->bands[i]->burst_size;
    }

    update_ovs_meter(entry, sb_meter, OFPMC13_MODIFY, msgs);
}

static void
ofctrl_meter_bands_erase(struct ovn_extend_table_info *entry,
                         struct ovs_list *msgs)
{
    struct meter_band_entry *mb =
        shash_find_and_delete(&meter_bands, entry->name);
    if (mb) {
        /* Delete the meter. */
        struct ofputil_meter_mod mm = {
            .command = OFPMC13_DELETE,
            .meter = { .meter_id = entry->table_id },
        };
        add_meter_mod(&mm, msgs);

        free(mb->bands);
        free(mb);
    }
}

static const struct sbrec_meter *
sb_meter_lookup_by_name(struct ovsdb_idl_index *sbrec_meter_by_name,
                        const char *name)
{
    const struct sbrec_meter *sb_meter;
    struct sbrec_meter *index_row;

    index_row = sbrec_meter_index_init_row(sbrec_meter_by_name);
    sbrec_meter_index_set_name(index_row, name);
    sb_meter = sbrec_meter_index_find(sbrec_meter_by_name, index_row);
    sbrec_meter_index_destroy_row(index_row);

    return sb_meter;
}

static void
ofctrl_meter_bands_sync(struct ovn_extend_table_info *m_existing,
                        struct ovsdb_idl_index *sbrec_meter_by_name,
                        struct ovs_list *msgs)
{
    const struct sbrec_meter *sb_meter;

    sb_meter = sb_meter_lookup_by_name(sbrec_meter_by_name, m_existing->name);
    if (sb_meter) {
        /* OFPMC13_ADD or OFPMC13_MODIFY */
        ofctrl_meter_bands_update(sb_meter, m_existing, msgs);
    } else {
        /* OFPMC13_DELETE */
        ofctrl_meter_bands_erase(m_existing, msgs);
    }
}

static void
add_meter(struct ovn_extend_table_info *m_desired,
          struct ovsdb_idl_index *sbrec_meter_by_name,
          struct ovs_list *msgs)
{
    const struct sbrec_meter *sb_meter;

    sb_meter = sb_meter_lookup_by_name(sbrec_meter_by_name, m_desired->name);
    if (!sb_meter) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_ERR_RL(&rl, "could not find meter named \"%s\"", m_desired->name);
        return;
    }

    ofctrl_meter_bands_alloc(sb_meter, m_desired, msgs);
}

static void
installed_flow_add(struct ovn_flow *d,
                   struct ofputil_bundle_ctrl_msg *bc,
                   struct ovs_list *msgs)
{
    /* Send flow_mod to add flow. */
    struct ofputil_flow_mod fm = {
        .match = d->match,
        .priority = d->priority,
        .table_id = d->table_id,
        .ofpacts = d->ofpacts,
        .ofpacts_len = d->ofpacts_len,
        .new_cookie = htonll(d->cookie),
        .command = OFPFC_ADD,
    };

    if (!add_flow_mod(&fm, bc, msgs)) {
        ovn_flow_log_size_err(d);
    }
}

static void
installed_flow_mod(struct ovn_flow *i, struct ovn_flow *d,
                   struct ofputil_bundle_ctrl_msg *bc,
                   struct ovs_list *msgs)
{
    /* Update actions in installed flow. */
    struct ofputil_flow_mod fm = {
        .match = i->match,
        .priority = i->priority,
        .table_id = i->table_id,
        .ofpacts = d->ofpacts,
        .ofpacts_len = d->ofpacts_len,
        .command = OFPFC_MODIFY_STRICT,
    };
    /* Update cookie if it is changed. */
    if (i->cookie != d->cookie) {
        fm.modify_cookie = true;
        fm.new_cookie = htonll(d->cookie);
        /* Use OFPFC_ADD so that cookie can be updated. */
        fm.command = OFPFC_ADD;
    }
    bool result = add_flow_mod(&fm, bc, msgs);

    /* Replace 'i''s actions and cookie by 'd''s. */
    mem_stats.installed_flow_usage -= i->ofpacts_len - d->ofpacts_len;
    free(i->ofpacts);
    i->ofpacts = xmemdup(d->ofpacts, d->ofpacts_len);
    i->ofpacts_len = d->ofpacts_len;
    i->cookie = d->cookie;

    if (!result) {
        ovn_flow_log_size_err(i);
    }
}

static void
installed_flow_del(struct ovn_flow *i,
                   struct ofputil_bundle_ctrl_msg *bc,
                   struct ovs_list *msgs)
{
    struct ofputil_flow_mod fm = {
        .match = i->match,
        .priority = i->priority,
        .table_id = i->table_id,
        .command = OFPFC_DELETE_STRICT,
    };

    if (!add_flow_mod(&fm, bc, msgs)) {
        ovn_flow_log_size_err(i);
    }
}

static void
update_installed_flows_by_compare(struct ovn_desired_flow_table *flow_table,
                                  struct ofputil_bundle_ctrl_msg *bc,
                                  struct hmap *installed_flows,
                                  struct ovs_list *msgs)
{
    ovs_assert(ovs_list_is_empty(&flow_table->tracked_flows));
    /* Iterate through all of the installed flows.  If any of them are no
     * longer desired, delete them; if any of them should have different
     * actions, update them. */
    struct installed_flow *i;
    HMAP_FOR_EACH_SAFE (i, match_hmap_node, installed_flows) {
        unlink_all_refs_for_installed_flow(i);
        struct desired_flow *d = desired_flow_lookup(flow_table, &i->flow);
        if (!d) {
            /* Installed flow is no longer desirable.  Delete it from the
             * switch and from installed_flows. */
            installed_flow_del(&i->flow, bc, msgs);
            ovn_flow_log(&i->flow, "removing installed");

            hmap_remove(installed_flows, &i->match_hmap_node);
            installed_flow_destroy(i);
        } else {
            if (!ofpacts_equal(i->flow.ofpacts, i->flow.ofpacts_len,
                               d->flow.ofpacts, d->flow.ofpacts_len) ||
                i->flow.cookie != d->flow.cookie) {
                installed_flow_mod(&i->flow, &d->flow, bc, msgs);
                ovn_flow_log(&i->flow, "updating installed");
            }
            link_installed_to_desired(i, d);

        }
    }

    /* Iterate through the desired flows and add those that aren't found
     * in the installed flow table. */
    struct desired_flow *d;
    HMAP_FOR_EACH (d, match_hmap_node, &flow_table->match_flow_table) {
        i = installed_flow_lookup(&d->flow, installed_flows);
        if (!i) {
            ovn_flow_log(&d->flow, "adding installed");
            installed_flow_add(&d->flow, bc, msgs);

            /* Copy 'd' from 'flow_table' to installed_flows. */
            i = installed_flow_dup(d);
            hmap_insert(installed_flows, &i->match_hmap_node, i->flow.hash);
            link_installed_to_desired(i, d);
        } else if (!d->installed_flow) {
            /* This is a desired_flow that conflicts with one installed
             * previously but not linked yet.  However, if this flow becomes
             * active, e.g., it is less restrictive than the previous active
             * flow then modify the installed flow.
             */
            if (link_installed_to_desired(i, d)) {
                installed_flow_mod(&i->flow, &d->flow, bc, msgs);
                ovn_flow_log(&i->flow, "updating installed (conflict)");
            }
        }
    }
}

/* Finds and returns a desired_flow in 'deleted_flows' that is exactly the
 * same as 'target', including cookie and actions.
 */
static struct desired_flow *
deleted_flow_lookup(struct hmap *deleted_flows, struct ovn_flow *target)
{
    struct desired_flow *d;
    HMAP_FOR_EACH_WITH_HASH (d, match_hmap_node, target->hash,
                             deleted_flows) {
        struct ovn_flow *f = &d->flow;
        if (f->table_id == target->table_id
            && f->priority == target->priority
            && minimatch_equal(&f->match, &target->match)
            && f->cookie == target->cookie
            && ofpacts_equal(f->ofpacts, f->ofpacts_len, target->ofpacts,
                             target->ofpacts_len)) {
            /* del_f must have been installed, otherwise it should have
             * been removed during track_flow_del. */
            ovs_assert(d->installed_flow);

            /* Now we also need to make sure the desired flow being
             * added/updated has exact same action and cookie as the installed
             * flow of d. Otherwise, don't merge them, so that the
             * installed flow can be updated later. */
            struct ovn_flow *f_i = &d->installed_flow->flow;
            if (f_i->cookie == target->cookie
                && ofpacts_equal(f_i->ofpacts, f_i->ofpacts_len,
                                 target->ofpacts, target->ofpacts_len)) {
                return d;
            }
        }
    }
    return NULL;
}

/* This function scans the tracked flow changes in the order and merges "add"
 * or "update" after "deleted" operations for exactly same flow (priority,
 * table, match, action and cookie), to avoid unnecessary OF messages being
 * sent to OVS. */
static void
merge_tracked_flows(struct ovn_desired_flow_table *flow_table)
{
    struct hmap deleted_flows = HMAP_INITIALIZER(&deleted_flows);
    struct desired_flow *f;
    LIST_FOR_EACH_SAFE (f, track_list_node,
                        &flow_table->tracked_flows) {
        if (f->is_deleted) {
            /* reuse f->match_hmap_node field since it is already removed from
             * the desired flow table's match index. */
            hmap_insert(&deleted_flows, &f->match_hmap_node,
                        f->flow.hash);
        } else {
            struct desired_flow *del_f = deleted_flow_lookup(&deleted_flows,
                                                             &f->flow);
            if (!del_f) {
                continue;
            }

            if (!f->installed_flow) {
                /* f is not installed yet. */
                replace_installed_to_desired(del_f->installed_flow, del_f, f);
            } else {
                /* f has been installed before, and now was updated to exact
                 * the same flow as del_f. */
                ovs_assert(f->installed_flow == del_f->installed_flow);
                unlink_installed_to_desired(del_f->installed_flow, del_f);
            }
            hmap_remove(&deleted_flows, &del_f->match_hmap_node);
            ovs_list_remove(&del_f->track_list_node);
            desired_flow_destroy(del_f);

            ovs_list_remove(&f->track_list_node);
            ovs_list_init(&f->track_list_node);
        }
    }
    HMAP_FOR_EACH_SAFE (f, match_hmap_node, &deleted_flows) {
        hmap_remove(&deleted_flows, &f->match_hmap_node);
    }
    hmap_destroy(&deleted_flows);
}

static void
update_installed_flows_by_track(struct ovn_desired_flow_table *flow_table,
                                struct ofputil_bundle_ctrl_msg *bc,
                                struct hmap *installed_flows,
                                struct ovs_list *msgs)
{
    merge_tracked_flows(flow_table);
    struct desired_flow *f;
    LIST_FOR_EACH_SAFE (f, track_list_node,
                        &flow_table->tracked_flows) {
        ovs_list_remove(&f->track_list_node);
        if (f->is_deleted) {
            /* The desired flow was deleted */
            if (f->installed_flow) {
                struct installed_flow *i = f->installed_flow;
                bool was_active = unlink_installed_to_desired(i, f);
                struct desired_flow *d = installed_flow_get_active(i);

                if (!d) {
                    installed_flow_del(&i->flow, bc, msgs);
                    ovn_flow_log(&i->flow, "removing installed (tracked)");

                    hmap_remove(installed_flows, &i->match_hmap_node);
                    installed_flow_destroy(i);
                } else if (was_active) {
                    /* There are other desired flow(s) referencing this
                     * installed flow, so update the OVS flow for the new
                     * active flow (at least the cookie will be different,
                     * even if the actions are the same). */
                    installed_flow_mod(&i->flow, &d->flow, bc, msgs);
                    ovn_flow_log(&i->flow, "updating installed (tracked)");
                }
            }
            desired_flow_destroy(f);
        } else {
            /* The desired flow was added or modified. */
            struct installed_flow *i = installed_flow_lookup(&f->flow,
                                                             installed_flows);
            if (!i) {
                /* Adding a new flow. */
                installed_flow_add(&f->flow, bc, msgs);
                ovn_flow_log(&f->flow, "adding installed (tracked)");

                /* Copy 'f' from 'flow_table' to installed_flows. */
                struct installed_flow *new_node = installed_flow_dup(f);
                hmap_insert(installed_flows, &new_node->match_hmap_node,
                            new_node->flow.hash);
                link_installed_to_desired(new_node, f);
            } else if (installed_flow_get_active(i) == f) {
                /* The installed flow is installed for f, but f has change
                 * tracked, so it must have been modified. */
                installed_flow_mod(&i->flow, &f->flow, bc, msgs);
                ovn_flow_log(&i->flow, "updating installed (tracked)");
            } else if (!f->installed_flow) {
                /* Adding a new flow that conflicts with an existing installed
                 * flow, so add it to the link.  If this flow becomes active,
                 * e.g., it is less restrictive than the previous active flow
                 * then modify the installed flow.
                 */
                if (link_installed_to_desired(i, f)) {
                    installed_flow_mod(&i->flow, &f->flow, bc, msgs);
                    ovn_flow_log(&i->flow,
                                 "updating installed (tracked conflict)");
                }
            }
            /* The track_list_node emptyness is used to check if the node is
             * already added to track list, so initialize it again here. */
            ovs_list_init(&f->track_list_node);
        }
    }
}

static void
add_ct_flush_tuple(const struct ovn_lb_5tuple *tuple,
                   struct ovs_list *msgs)
{
    if (VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_cstr(&ds, "Flushing CT for 5-tuple: vip=");
        ipv6_format_mapped(&tuple->vip_ip, &ds);
        ds_put_format(&ds, ":%"PRIu16", backend=", tuple->vip_port);
        ipv6_format_mapped(&tuple->backend_ip, &ds);
        ds_put_format(&ds, ":%"PRIu16", protocol=%"PRIu8,
                      tuple->backend_port, tuple->proto);
        VLOG_DBG("%s", ds_cstr(&ds));

        ds_destroy(&ds);
    }

    struct ofp_ct_match match = {
        .ip_proto = tuple->proto,
        .tuple_orig.dst = tuple->vip_ip,
        .tuple_orig.dst_port = htons(tuple->vip_port),
        .tuple_reply.src = tuple->backend_ip,
        .tuple_reply.src_port = htons(tuple->backend_port),
    };

    struct ofpbuf *msg = ofp_ct_match_encode(&match, NULL, OFP15_VERSION);
    ovs_list_push_back(msgs, &msg->list_node);
}

bool
ofctrl_has_backlog(void)
{
    if (rconn_packet_counter_n_packets(tx_counter)
        || rconn_get_version(swconn) < 0) {
        return true;
    }
    return false;
}

/* The flow table can be updated if the connection to the switch is up and
 * in the correct state and not backlogged with existing flow_mods.  (Our
 * criteria for being backlogged appear very conservative, but the socket
 * between ovn-controller and OVS provides some buffering.) */
static bool
ofctrl_can_put(void)
{
    if (state != S_UPDATE_FLOWS
        || ofctrl_has_backlog()) {
        return false;
    }
    return true;
}

/* Replaces the flow table on the switch, if possible, by the flows added
 * with ofctrl_add_flow().
 *
 * Replaces the group table and meter table on the switch, if possible,
 * by the contents of '->desired'.
 *
 * Sends conntrack flush messages to each zone in 'pending_ct_zones' that
 * is in the CT_ZONE_OF_QUEUED state and then moves the zone into the
 * CT_ZONE_OF_SENT state.
 *
 * This should be called after ofctrl_run() within the main loop. */
void
ofctrl_put(struct ovn_desired_flow_table *lflow_table,
           struct ovn_desired_flow_table *pflow_table,
           struct shash *pending_ct_zones,
           struct hmap *pending_lb_tuples,
           struct ovsdb_idl_index *sbrec_meter_by_name,
           uint64_t req_cfg,
           bool lflows_changed,
           bool pflows_changed)
{
    static bool skipped_last_time = false;
    static uint64_t old_req_cfg = 0;
    bool need_put = false;
    if (lflows_changed || pflows_changed || skipped_last_time ||
        ofctrl_initial_clear) {
        need_put = true;
        old_req_cfg = req_cfg;
    } else if (req_cfg != old_req_cfg) {
        /* req_cfg changed since last ofctrl_put() call */
        if (cur_cfg == old_req_cfg) {
            /* If there are no updates pending, we were up-to-date already,
             * update with the new req_cfg.
             */
            if (ovs_list_is_empty(&flow_updates)) {
                cur_cfg = req_cfg;
                old_req_cfg = req_cfg;
            }
        } else {
            need_put = true;
            old_req_cfg = req_cfg;
        }
    }

    if (!need_put) {
        VLOG_DBG("ofctrl_put not needed");
        return;
    }
    if (!ofctrl_can_put()) {
        VLOG_DBG("ofctrl_put can't be performed");
        skipped_last_time = true;
        return;
    }

    /* OpenFlow messages to send to the switch to bring it up-to-date. */
    struct ovs_list msgs = OVS_LIST_INITIALIZER(&msgs);

    /* Iterate through ct zones that need to be flushed. */
    struct shash_node *iter;
    SHASH_FOR_EACH(iter, pending_ct_zones) {
        struct ct_zone_pending_entry *ctzpe = iter->data;
        if (ctzpe->state == CT_ZONE_OF_QUEUED) {
            add_ct_flush_zone(ctzpe->zone, &msgs);
            ctzpe->state = CT_ZONE_OF_SENT;
            ctzpe->of_xid = 0;
        }
    }

    if (ofctrl_initial_clear) {
        /* Send a meter_mod to delete all meters.
         * XXX: Ideally, we should include the meter deletion and
         * reinstallation in the same bundle just like for flows and groups,
         * for minimum data plane interruption. However, OVS doesn't support
         * METER_MOD in bundle yet. */
        struct ofputil_meter_mod mm;
        memset(&mm, 0, sizeof mm);
        mm.command = OFPMC13_DELETE;
        mm.meter.meter_id = OFPM13_ALL;
        add_meter_mod(&mm, &msgs);
    }

    /* Iterate through all the desired meters. If there are new ones,
     * add them to the switch. */
    struct ovn_extend_table_info *m_desired;
    HMAP_FOR_EACH (m_desired, hmap_node, &meters->desired) {
        struct ovn_extend_table_info *m_existing =
            ovn_extend_table_lookup(&meters->existing, m_desired);
        if (!m_existing) {
            if (!strncmp(m_desired->name, "__string: ", 10)) {
                /* The "set-meter" action creates a meter entry name that
                 * describes the meter itself. */
                add_meter_string(m_desired, &msgs);
            } else {
                add_meter(m_desired, sbrec_meter_by_name, &msgs);
            }
        } else {
            ofctrl_meter_bands_sync(m_existing, sbrec_meter_by_name, &msgs);
        }
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

    if (ofctrl_initial_clear) {
        /* Send a flow_mod to delete all flows. */
        struct ofputil_flow_mod fm = {
            .table_id = OFPTT_ALL,
            .command = OFPFC_DELETE,
        };
        minimatch_init_catchall(&fm.match);
        add_flow_mod(&fm, &bc, &msgs);
        minimatch_destroy(&fm.match);

        /* Send a group_mod to delete all groups. */
        struct ofputil_group_mod gm;
        memset(&gm, 0, sizeof gm);
        gm.command = OFPGC11_DELETE;
        gm.group_id = OFPG_ALL;
        gm.command_bucket_id = OFPG15_BUCKET_ALL;
        ovs_list_init(&gm.buckets);
        add_group_mod(&gm, &bc, &msgs);
        ofputil_uninit_group_mod(&gm);

        ofctrl_initial_clear = false;
    }

    /* Iterate through all the desired groups. If there are new ones,
     * add them to the switch. */
    struct ovn_extend_table_info *desired;
    EXTEND_TABLE_FOR_EACH_UNINSTALLED (desired, groups) {
        /* Create and install new group. */
        struct ofputil_group_mod gm;
        enum ofputil_protocol usable_protocols;
        char *group_string = xasprintf("group_id=%"PRIu32",%s",
                                       desired->table_id,
                                       desired->name);
        char *error = parse_ofp_group_mod_str(&gm, OFPGC15_ADD, group_string,
                                              NULL, NULL, &usable_protocols);
        if (!error) {
            add_group_mod(&gm, &bc, &msgs);
        } else {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_ERR_RL(&rl, "new group %s %s", error, group_string);
            free(error);
        }
        free(group_string);
        ofputil_uninit_group_mod(&gm);
    }

    /* If skipped last time, then process the flow table
     * (tracked) flows even if lflows_changed is not set.
     * Same for pflows_changed. */
    if (lflows_changed || skipped_last_time) {
        if (lflow_table->change_tracked) {
            update_installed_flows_by_track(lflow_table, &bc,
                                            &installed_lflows,
                                            &msgs);
        } else {
            update_installed_flows_by_compare(lflow_table, &bc,
                                              &installed_lflows,
                                              &msgs);
        }
    }

    if (pflows_changed || skipped_last_time) {
        if (pflow_table->change_tracked) {
            update_installed_flows_by_track(pflow_table, &bc,
                                            &installed_pflows,
                                            &msgs);
        } else {
            update_installed_flows_by_compare(pflow_table, &bc,
                                              &installed_pflows,
                                              &msgs);
        }
    }

    skipped_last_time = false;

    /* Iterate through the installed groups from previous runs. If they
     * are not needed delete them. */
    struct ovn_extend_table_info *installed;
    EXTEND_TABLE_FOR_EACH_INSTALLED (installed, groups) {
        /* Delete the group. */
        struct ofputil_group_mod gm;
        enum ofputil_protocol usable_protocols;
        char *group_string = xasprintf("group_id=%"PRIu32"",
                                       installed->table_id);
        char *error = parse_ofp_group_mod_str(&gm, OFPGC15_DELETE,
                                              group_string, NULL, NULL,
                                              &usable_protocols);
        if (!error) {
            add_group_mod(&gm, &bc, &msgs);
        } else {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_ERR_RL(&rl, "Error deleting group %d: %s",
                        installed->table_id, error);
            free(error);
        }
        free(group_string);
        ofputil_uninit_group_mod(&gm);
        ovn_extend_table_remove_existing(groups, installed);
    }

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

    /* Sync the contents of groups->desired to groups->existing. */
    ovn_extend_table_sync(groups);

    /* Iterate through the installed meters from previous runs. If they
     * are not needed delete them. */
    struct ovn_extend_table_info *m_installed;
    EXTEND_TABLE_FOR_EACH_INSTALLED (m_installed, meters) {
        /* Delete the meter. */
        ofctrl_meter_bands_erase(m_installed, &msgs);
        if (!strncmp(m_installed->name, "__string: ", 10)) {
            struct ofputil_meter_mod mm = {
                .command = OFPMC13_DELETE,
                .meter = { .meter_id = m_installed->table_id },
            };
            add_meter_mod(&mm, &msgs);
        }
        ovn_extend_table_remove_existing(meters, m_installed);
    }

    /* Sync the contents of meters->desired to meters->existing. */
    ovn_extend_table_sync(meters);

    if (ovs_feature_is_supported(OVS_CT_TUPLE_FLUSH_SUPPORT)) {
        struct ovn_lb_5tuple *tuple;
        HMAP_FOR_EACH_POP (tuple, hmap_node, pending_lb_tuples) {
            add_ct_flush_tuple(tuple, &msgs);
            free(tuple);
        }
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
            queue_msg(msg);
        }

        /* Store the barrier's xid with any newly sent ct flushes. */
        SHASH_FOR_EACH(iter, pending_ct_zones) {
            struct ct_zone_pending_entry *ctzpe = iter->data;
            if (ctzpe->state == CT_ZONE_OF_SENT && !ctzpe->of_xid) {
                ctzpe->of_xid = xid_;
            }
        }

        /* Track the flow update. */
        struct ofctrl_flow_update *fup;
        LIST_FOR_EACH_REVERSE_SAFE (fup, list_node, &flow_updates) {
            if (req_cfg < fup->req_cfg) {
                /* This ofctrl_flow_update is for a configuration later than
                 * 'req_cfg'.  This should not normally happen, because it
                 * means that the local seqno decreased and it should normally
                 * be monotonically increasing. */
                VLOG_WARN("req_cfg regressed from %"PRId64" to %"PRId64,
                          fup->req_cfg, req_cfg);
                mem_stats.oflow_update_usage -= ofctrl_flow_update_size(fup);
                ovs_list_remove(&fup->list_node);
                free(fup);
            } else if (req_cfg == fup->req_cfg) {
                /* This ofctrl_flow_update is for the same configuration as
                 * 'req_cfg'.  Probably, some change to the physical topology
                 * means that we had to revise the OpenFlow flow table even
                 * though the logical topology did not change.  Update fp->xid,
                 * so that we don't send a notification that we're up-to-date
                 * until we're really caught up. */
                VLOG_DBG("advanced xid target for req_cfg=%"PRId64, req_cfg);
                fup->xid = xid_;
                goto done;
            } else {
                break;
            }
        }

        /* Add a flow update. */
        fup = xmalloc(sizeof *fup);
        ovs_list_push_back(&flow_updates, &fup->list_node);
        fup->xid = xid_;
        fup->req_cfg = req_cfg;
        mem_stats.oflow_update_usage += ofctrl_flow_update_size(fup);
    done:;
    } else if (!ovs_list_is_empty(&flow_updates)) {
        /* Getting up-to-date with 'req_cfg' didn't require any extra flow
         * table changes, so whenever we get up-to-date with the most recent
         * flow table update, we're also up-to-date with 'req_cfg'. */
        struct ofctrl_flow_update *fup = ofctrl_flow_update_from_list_node(
            ovs_list_back(&flow_updates));
        fup->req_cfg = req_cfg;
    } else {
        /* We were completely up-to-date before and still are. */
        cur_cfg = req_cfg;
    }

    lflow_table->change_tracked = true;
    ovs_assert(ovs_list_is_empty(&lflow_table->tracked_flows));

    pflow_table->change_tracked = true;
    ovs_assert(ovs_list_is_empty(&pflow_table->tracked_flows));
}

/* Looks up the logical port with the name 'port_name' in 'br_int_'.  If
 * found, returns true and sets '*portp' to the OpenFlow port number
 * assigned to the port.  Otherwise, returns false. */
static bool
ofctrl_lookup_port(const void *br_int_, const char *port_name,
                   unsigned int *portp)
{
    const struct ovsrec_bridge *br_int = br_int_;

    for (int i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_int->ports[i];
        for (int j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec = port_rec->interfaces[j];
            const char *iface_id = smap_get(&iface_rec->external_ids,
                                            "iface-id");

            if (iface_id && !strcmp(iface_id, port_name)) {
                if (!iface_rec->n_ofport) {
                    continue;
                }

                int64_t ofport = iface_rec->ofport[0];
                if (ofport < 1 || ofport > ofp_to_u16(OFPP_MAX)) {
                    continue;
                }
                *portp = ofport;
                return true;
            }
        }
    }

    return false;
}

/* Generates a packet described by 'flow_s' in the syntax of an OVN
 * logical expression and injects it into 'br_int'.  The flow
 * description must contain an ingress logical port that is present on
 * 'br_int'.
 *
 * Returns NULL if successful, otherwise an error message that the caller
 * must free(). */
char *
ofctrl_inject_pkt(const struct ovsrec_bridge *br_int, const char *flow_s,
                  const struct shash *addr_sets,
                  const struct shash *port_groups,
                  const struct smap *template_vars)
{
    int version = rconn_get_version(swconn);
    if (version < 0) {
        return xstrdup("OpenFlow channel not ready.");
    }

    struct flow uflow;
    struct lex_str flow_exp_s = lexer_parse_template_string(flow_s,
                                                            template_vars,
                                                            NULL);
    char *error = expr_parse_microflow(lex_str_get(&flow_exp_s), &symtab,
                                       addr_sets, port_groups,
                                       ofctrl_lookup_port, br_int, &uflow);
    lex_str_free(&flow_exp_s);
    if (error) {
        return error;
    }

    /* The physical OpenFlow port was stored in the logical ingress
     * port, so put it in the correct location for a flow structure. */
    uflow.in_port.ofp_port = u16_to_ofp(uflow.regs[MFF_LOG_INPORT - MFF_REG0]);
    uflow.regs[MFF_LOG_INPORT - MFF_REG0] = 0;

    if (!uflow.in_port.ofp_port) {
        return xstrdup("ingress port not found on hypervisor.");
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    flow_compose(&packet, &uflow, NULL, 64);

    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_IN_PORT;
    resubmit->table_id = 0;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, uflow.in_port.ofp_port);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);

    return NULL;
}

bool
ofctrl_is_connected(void)
{
    return rconn_is_connected(swconn);
}

void
ofctrl_set_probe_interval(int probe_interval)
{
    if (swconn) {
        rconn_set_probe_interval(swconn, probe_interval);
    }
}

void
ofctrl_get_memory_usage(struct simap *usage)
{
    simap_increase(usage, "ofctrl_sb_flow_ref_usage-KB",
                   ROUND_UP(mem_stats.sb_flow_ref_usage, 1024) / 1024);
    simap_increase(usage, "ofctrl_desired_flow_usage-KB",
                   ROUND_UP(mem_stats.desired_flow_usage, 1024) / 1024);
    simap_increase(usage, "ofctrl_installed_flow_usage-KB",
                   ROUND_UP(mem_stats.installed_flow_usage, 1024) / 1024);
    simap_increase(usage, "oflow_update_usage-KB",
                   ROUND_UP(mem_stats.oflow_update_usage, 1024) / 1024);
    simap_increase(usage, "ofctrl_rconn_packet_counter-KB",
                   ROUND_UP(rconn_packet_counter_n_bytes(tx_counter), 1024)
                   / 1024);
}
