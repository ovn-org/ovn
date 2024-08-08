/* Copyright (c) 2021, Red Hat, Inc.
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
#include <stdint.h>
#include <stdlib.h>

#include "lib/util.h"
#include "lib/dirs.h"
#include "socket-util.h"
#include "lib/vswitch-idl.h"
#include "odp-netlink.h"
#include "openvswitch/vlog.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/rconn.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-bundle.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-meter.h"
#include "openvswitch/ofp-group.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/rconn.h"
#include "ovn/features.h"
#include "controller/ofctrl.h"
#include "ovn-util.h"

VLOG_DEFINE_THIS_MODULE(features);

/* Parses 'cap_name' from 'ovs_capabilities' and returns whether the
 * type of capability is supported or not. */
typedef bool ovs_feature_parse_func(const struct smap *ovs_capabilities,
                                    const char *cap_name);

struct ovs_feature {
    enum ovs_feature_value value;
    const char *name;
    ovs_feature_parse_func *parse;
};

struct ovs_openflow_feature {
    enum ovs_feature_value value;
    const char *name;
    bool queued;
    ovs_be32 xid;
    ovs_be32 barrier_xid;
    void (*send_request)(struct ovs_openflow_feature *feature);
    bool (*handle_response)(struct ovs_openflow_feature *feature,
                            enum ofptype type, const struct ofp_header *oh);
    bool (*handle_barrier)(struct ovs_openflow_feature *feature);
};

static bool
bool_parser(const struct smap *ovs_capabilities, const char *cap_name)
{
    return smap_get_bool(ovs_capabilities, cap_name, false);
}

static bool
dp_hash_l4_sym_support_parser(const struct smap *ovs_capabilities,
                              const char *cap_name OVS_UNUSED)
{
    int max_hash_alg = smap_get_int(ovs_capabilities, "max_hash_alg", 0);

    return max_hash_alg == OVS_HASH_ALG_SYM_L4;
}

static struct ovs_feature all_ovs_features[] = {
    {
        .value = OVS_CT_ZERO_SNAT_SUPPORT,
        .name = "ct_zero_snat",
        .parse = bool_parser,
    },
    {
        .value = OVS_CT_TUPLE_FLUSH_SUPPORT,
        .name = "ct_flush",
        .parse = bool_parser,
    },
    {
        .value = OVS_DP_HASH_L4_SYM_SUPPORT,
        .name = "dp_hash_l4_sym_support",
        .parse = dp_hash_l4_sym_support_parser,
    },
};

/* A bitmap of OVS features that have been detected as 'supported'. */
static uint32_t supported_ovs_features;


/* Currently discovered set of features. */
static struct ofputil_meter_features ovs_meter_features;
static struct ofputil_group_features ovs_group_features;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 10);

/* ovs-vswitchd connection. */
static struct rconn *swconn;
static uint32_t conn_seq_no;

static void
log_unexpected_reply(struct ovs_openflow_feature *feature,
                     const struct ofp_header *oh)
{
    if (VLOG_IS_WARN_ENABLED()) {
        char *s = ofp_to_string(oh, ntohs(oh->length), NULL, NULL, 2);
        VLOG_WARN_RL(&rl, "OVS Feature: %s, unexpected reply: %s",
                     feature->name, s);
        free(s);
    }
}

static bool
default_barrier_response_handle(struct ovs_openflow_feature *feature)
{
    VLOG_WARN_RL(&rl, "OVS Feature: %s, didn't receive any reply",
                 feature->name);
    return supported_ovs_features & feature->value;
}

static void
meter_features_send_request(struct ovs_openflow_feature *feature)
{
    struct ofpbuf *msg = ofpraw_alloc(OFPRAW_OFPST13_METER_FEATURES_REQUEST,
                                      rconn_get_version(swconn), 0);
    feature->xid = ((struct ofp_header *) msg->data)->xid;
    rconn_send(swconn, msg, NULL);
}

static bool
meter_features_handle_response(struct ovs_openflow_feature *feature,
                               enum ofptype type, const struct ofp_header *oh)
{
    if (type != OFPTYPE_METER_FEATURES_STATS_REPLY) {
        log_unexpected_reply(feature, oh);
        return supported_ovs_features & feature->value;
    }

    struct ofputil_meter_features features;
    ofputil_decode_meter_features(oh, &features);

    if (memcmp(&ovs_meter_features, &features, sizeof features)) {
        ovs_meter_features = features;
        return ovs_meter_features.max_meters;
    }

    return supported_ovs_features & feature->value;
}

static void
group_features_send_request(struct ovs_openflow_feature *feature)
{
    struct ofpbuf *msg =
            ofputil_encode_group_features_request(rconn_get_version(swconn));
    feature->xid = ((struct ofp_header *) msg->data)->xid;
    rconn_send(swconn, msg, NULL);
}

static bool
group_features_handle_response(struct ovs_openflow_feature *feature,
                               enum ofptype type, const struct ofp_header *oh)
{
    if (type != OFPTYPE_GROUP_FEATURES_STATS_REPLY) {
        log_unexpected_reply(feature, oh);
        return supported_ovs_features & feature->value;
    }

    struct ofputil_group_features features;
    ofputil_decode_group_features_reply(oh, &features);

    if (memcmp(&ovs_group_features, &features, sizeof features)) {
        ovs_group_features = features;
        return ovs_group_features.max_groups[OFPGT11_SELECT];
    }

    return supported_ovs_features & feature->value;
}

static void
sample_with_reg_send_request(struct ovs_openflow_feature *feature)
{
    struct ofputil_bundle_ctrl_msg ctrl = {
        .bundle_id = 0,
        .flags     = OFPBF_ORDERED | OFPBF_ATOMIC,
        .type      = OFPBCT_OPEN_REQUEST,
    };
    rconn_send(swconn,
               ofputil_encode_bundle_ctrl_request(OFP15_VERSION, &ctrl), NULL);

    uint8_t actions_stub[64];
    struct ofpbuf actions;
    ofpbuf_use_stub(&actions, actions_stub, sizeof(actions_stub));

    struct mf_subfield subfield = {
        .field = mf_from_id(MFF_REG0),
        .n_bits = 32,
        .ofs = 0
    };

    struct ofpact_sample *sample = ofpact_put_SAMPLE(&actions);
    sample->probability = UINT16_MAX;
    sample->collector_set_id = 0;
    sample->obs_domain_src = subfield;
    sample->obs_point_src = subfield;
    sample->sampling_port = OFPP_NONE;

    struct ofputil_flow_mod fm = {
        .priority = 0,
        .table_id = 0,
        .ofpacts = actions.data,
        .ofpacts_len = actions.size,
        .command = OFPFC_ADD,
        .new_cookie = htonll(0),
        .buffer_id = UINT32_MAX,
        .out_port = OFPP_ANY,
        .out_group = OFPG_ANY,
    };

    struct match match;
    match_init_catchall(&match);
    minimatch_init(&fm.match, &match);

    struct ofpbuf *fm_msg = ofputil_encode_flow_mod(&fm, OFPUTIL_P_OF15_OXM);

    struct ofputil_bundle_add_msg bam = {
        .bundle_id = ctrl.bundle_id,
        .flags = ctrl.flags,
        .msg = fm_msg->data,
    };
    struct ofpbuf *msg = ofputil_encode_bundle_add(OFP15_VERSION, &bam);

    feature->xid = ((struct ofp_header *) msg->data)->xid;
    rconn_send(swconn, msg, NULL);

    ctrl.type = OFPBCT_DISCARD_REQUEST;
    rconn_send(swconn,
               ofputil_encode_bundle_ctrl_request(OFP15_VERSION, &ctrl), NULL);

    minimatch_destroy(&fm.match);
    ofpbuf_delete(fm_msg);
}

static bool
sample_with_reg_handle_response(struct ovs_openflow_feature *feature,
                                enum ofptype type, const struct ofp_header *oh)
{
    if (type != OFPTYPE_ERROR) {
        log_unexpected_reply(feature, oh);
    }

    return false;
}

static bool
sample_with_reg_handle_barrier(struct ovs_openflow_feature *feature OVS_UNUSED)
{
    return true;
}

static struct ovs_openflow_feature all_openflow_features[] = {
        {
            .value = OVS_DP_METER_SUPPORT,
            .name = "meter_support",
            .send_request = meter_features_send_request,
            .handle_response = meter_features_handle_response,
            .handle_barrier = default_barrier_response_handle,
        },
        {
            .value = OVS_OF_GROUP_SUPPORT,
            .name = "group_support",
            .send_request = group_features_send_request,
            .handle_response = group_features_handle_response,
            .handle_barrier = default_barrier_response_handle,
        },
        {
            .value = OVS_SAMPLE_REG_SUPPORT,
            .name = "sample_action_with_registers",
            .send_request = sample_with_reg_send_request,
            .handle_response = sample_with_reg_handle_response,
            .handle_barrier = sample_with_reg_handle_barrier,
        }
};

static bool
handle_feature_state_update(bool new_state, enum ovs_feature_value value,
                            const char *name)
{
    bool updated = false;

    bool old_state = supported_ovs_features & value;
    if (new_state != old_state) {
        updated = true;
        if (new_state) {
            supported_ovs_features |= value;
        } else {
            supported_ovs_features &= ~value;
        }
        VLOG_INFO_RL(&rl, "OVS Feature: %s, state: %s", name,
                     new_state ? "supported" : "not supported");
    }

    return updated;
}

static bool
features_handle_rconn_msg(struct ofpbuf *msg)
{
    const struct ofp_header *oh = msg->data;

    enum ofptype type;
    ofptype_decode(&type, oh);

    if (type == OFPTYPE_ECHO_REQUEST) {
        rconn_send(swconn, ofputil_encode_echo_reply(oh), NULL);
        return false;
    }

    for (size_t i = 0; i < ARRAY_SIZE(all_openflow_features); i++) {
        struct ovs_openflow_feature *feature = &all_openflow_features[i];

        bool new_state;
        if (feature->queued && feature->xid == oh->xid) {
            new_state = feature->handle_response(feature, type, oh);
        } else if (feature->queued && feature->barrier_xid == oh->xid) {
            new_state = feature->handle_barrier(feature);
        } else {
            continue;
        }

        feature->queued = false;
        return handle_feature_state_update(new_state, feature->value,
                                           feature->name);
    }

    if (VLOG_IS_DBG_ENABLED()) {
        char *s = ofp_to_string(oh, ntohs(oh->length), NULL, NULL, 2);
        VLOG_DBG_RL(&rl, "OpenFlow packet ignored: %s", s);
        free(s);
    }

    return false;
}

static bool
ovs_feature_is_valid(enum ovs_feature_value feature)
{
    switch (feature) {
    case OVS_CT_ZERO_SNAT_SUPPORT:
    case OVS_DP_METER_SUPPORT:
    case OVS_CT_TUPLE_FLUSH_SUPPORT:
    case OVS_DP_HASH_L4_SYM_SUPPORT:
    case OVS_OF_GROUP_SUPPORT:
    case OVS_SAMPLE_REG_SUPPORT:
        return true;
    default:
        return false;
    }
}

bool
ovs_feature_is_supported(enum ovs_feature_value feature)
{
    ovs_assert(ovs_feature_is_valid(feature));
    return supported_ovs_features & feature;
}


static bool
ovs_feature_get_openflow_cap(void)
{
    rconn_run(swconn);
    if (!rconn_is_connected(swconn)) {
        rconn_run_wait(swconn);
        rconn_recv_wait(swconn);
        return false;
    }

    /* send new requests just after reconnect. */
    if (conn_seq_no != rconn_get_connection_seqno(swconn)) {
        for (size_t i = 0; i < ARRAY_SIZE(all_openflow_features); i++) {
            struct ovs_openflow_feature *feature = &all_openflow_features[i];

            feature->queued = true;
            feature->send_request(feature);

            struct ofpbuf *msg =
                    ofputil_encode_barrier_request(rconn_get_version(swconn));
            feature->barrier_xid = ((struct ofp_header *) msg->data)->xid;
            rconn_send(swconn, msg, NULL);
        }
    }
    conn_seq_no = rconn_get_connection_seqno(swconn);

    bool ret = false;
    for (int i = 0; i < 50; i++) {
        struct ofpbuf *msg = rconn_recv(swconn);
        if (!msg) {
            break;
        }

        ret |= features_handle_rconn_msg(msg);
        ofpbuf_delete(msg);
    }
    rconn_run_wait(swconn);
    rconn_recv_wait(swconn);

    return ret;
}

void
ovs_feature_support_destroy(void)
{
    rconn_destroy(swconn);
    swconn = NULL;
}

/* Returns 'true' if the set of tracked OVS features has been updated. */
bool
ovs_feature_support_run(const struct smap *ovs_capabilities,
                        const char *conn_target, int probe_interval)
{
    static struct smap empty_caps = SMAP_INITIALIZER(&empty_caps);

    if (!ovs_capabilities) {
        ovs_capabilities = &empty_caps;
    }

    if (!swconn) {
        swconn = rconn_create(0, 0, DSCP_DEFAULT, 1 << OFP15_VERSION);
    }
    ovn_update_swconn_at(swconn, conn_target, probe_interval, "features");

    bool updated = ovs_feature_get_openflow_cap();

    for (size_t i = 0; i < ARRAY_SIZE(all_ovs_features); i++) {
        struct ovs_feature *feature = &all_ovs_features[i];
        bool new_value = feature->parse(ovs_capabilities, feature->name);
        updated |= handle_feature_state_update(new_value, feature->value,
                                               feature->name);
    }
    return updated;
}

bool
ovs_feature_set_discovered(void)
{
    /* The supported feature set has been discovered if we're connected
     * to OVS and it replied to all our feature request messages. */
    bool replied_to_all = true;
    for (size_t i = 0; i < ARRAY_SIZE(all_openflow_features); i++) {
        struct ovs_openflow_feature *feature = &all_openflow_features[i];
        replied_to_all &= !feature->queued;
    }

    return swconn && rconn_is_connected(swconn) && replied_to_all;
}

/* Returns the number of meters the OVS datapath supports. */
uint32_t
ovs_feature_max_meters_get(void)
{
    return ovs_meter_features.max_meters;
}

/* Returns the number of select groups the OVS datapath supports. */
uint32_t
ovs_feature_max_select_groups_get(void)
{
    return ovs_group_features.max_groups[OFPGT11_SELECT];
}
