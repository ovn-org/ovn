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
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-meter.h"
#include "openvswitch/ofp-group.h"
#include "openvswitch/ofp-util.h"
#include "ovn/features.h"

VLOG_DEFINE_THIS_MODULE(features);

#define FEATURES_DEFAULT_PROBE_INTERVAL_SEC 5

/* Parses 'cap_name' from 'ovs_capabilities' and returns whether the
 * type of capability is supported or not. */
typedef bool ovs_feature_parse_func(const struct smap *ovs_capabilities,
                                    const char *cap_name);

struct ovs_feature {
    enum ovs_feature_value value;
    const char *name;
    ovs_feature_parse_func *parse;
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

/* Last set of received feature replies. */
static struct ofputil_meter_features ovs_meter_features_reply;
static struct ofputil_group_features ovs_group_features_reply;

/* Currently discovered set of features. */
static struct ofputil_meter_features ovs_meter_features;
static struct ofputil_group_features ovs_group_features;

/* Number of features replies still expected to receive for the requests
 * we sent already. */
static uint32_t n_features_reply_expected;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

/* ovs-vswitchd connection. */
static struct rconn *swconn;
static uint32_t conn_seq_no;

static bool
ovs_feature_is_valid(enum ovs_feature_value feature)
{
    switch (feature) {
    case OVS_CT_ZERO_SNAT_SUPPORT:
    case OVS_DP_METER_SUPPORT:
    case OVS_CT_TUPLE_FLUSH_SUPPORT:
    case OVS_DP_HASH_L4_SYM_SUPPORT:
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

static void
ovs_feature_rconn_setup(const char *br_name)
{
    if (!swconn) {
        swconn = rconn_create(FEATURES_DEFAULT_PROBE_INTERVAL_SEC, 0,
                              DSCP_DEFAULT, 1 << OFP15_VERSION);
    }

    if (!rconn_is_connected(swconn)) {
        char *target = xasprintf("unix:%s/%s.mgmt", ovs_rundir(), br_name);
        if (strcmp(target, rconn_get_target(swconn))) {
            VLOG_INFO("%s: connecting to switch", target);
            rconn_connect(swconn, target, target);
        }
        free(target);
    }
    rconn_set_probe_interval(swconn, FEATURES_DEFAULT_PROBE_INTERVAL_SEC);
}

static bool
ovs_feature_get_openflow_cap(const char *br_name)
{
    struct ofpbuf *msg;

    if (!br_name) {
        return false;
    }

    ovs_feature_rconn_setup(br_name);

    rconn_run(swconn);
    if (!rconn_is_connected(swconn)) {
        rconn_run_wait(swconn);
        rconn_recv_wait(swconn);
        return false;
    }

    /* send new requests just after reconnect. */
    if (conn_seq_no != rconn_get_connection_seqno(swconn)) {
        n_features_reply_expected = 0;

        /* Dump OpenFlow switch meter capabilities. */
        msg = ofpraw_alloc(OFPRAW_OFPST13_METER_FEATURES_REQUEST,
                           rconn_get_version(swconn), 0);
        rconn_send(swconn, msg, NULL);
        n_features_reply_expected++;
        /* Dump OpenFlow switch group capabilities. */
        msg = ofputil_encode_group_features_request(rconn_get_version(swconn));
        rconn_send(swconn, msg, NULL);
        n_features_reply_expected++;
    }
    conn_seq_no = rconn_get_connection_seqno(swconn);

    bool ret = false;
    for (int i = 0; i < 50; i++) {
        msg = rconn_recv(swconn);
        if (!msg) {
            break;
        }

        const struct ofp_header *oh = msg->data;
        enum ofptype type;
        ofptype_decode(&type, oh);

        if (type == OFPTYPE_METER_FEATURES_STATS_REPLY) {
            ofputil_decode_meter_features(oh, &ovs_meter_features_reply);
            ovs_assert(n_features_reply_expected);
            n_features_reply_expected--;
        } else if (type == OFPTYPE_GROUP_FEATURES_STATS_REPLY) {
            ofputil_decode_group_features_reply(oh, &ovs_group_features_reply);
            ovs_assert(n_features_reply_expected);
            n_features_reply_expected--;
        } else if (type == OFPTYPE_ECHO_REQUEST) {
            rconn_send(swconn, ofputil_encode_echo_reply(oh), NULL);
        }
        ofpbuf_delete(msg);
    }
    rconn_run_wait(swconn);
    rconn_recv_wait(swconn);

    /* If all feature replies were received, update the set of supported
     * features. */
    if (!n_features_reply_expected) {
        if (memcmp(&ovs_meter_features, &ovs_meter_features_reply,
                   sizeof ovs_meter_features_reply)) {
            ovs_meter_features = ovs_meter_features_reply;
            if (ovs_meter_features.max_meters) {
                supported_ovs_features |= OVS_DP_METER_SUPPORT;
            } else {
                supported_ovs_features &= ~OVS_DP_METER_SUPPORT;
            }
            ret = true;
        }
        if (memcmp(&ovs_group_features, &ovs_group_features_reply,
                   sizeof ovs_group_features_reply)) {
            ovs_group_features = ovs_group_features_reply;
            ret = true;
        }
    }

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
                        const char *br_name)
{
    static struct smap empty_caps = SMAP_INITIALIZER(&empty_caps);
    bool updated = false;

    if (!ovs_capabilities) {
        ovs_capabilities = &empty_caps;
    }

    if (ovs_feature_get_openflow_cap(br_name)) {
        updated = true;
    }

    for (size_t i = 0; i < ARRAY_SIZE(all_ovs_features); i++) {
        struct ovs_feature *feature = &all_ovs_features[i];
        bool old_state = supported_ovs_features & feature->value;
        bool new_state = feature->parse(ovs_capabilities, feature->name);
        if (new_state != old_state) {
            updated = true;
            if (new_state) {
                supported_ovs_features |= feature->value;
            } else {
                supported_ovs_features &= ~feature->value;
            }
            VLOG_INFO_RL(&rl, "OVS Feature: %s, state: %s", feature->name,
                         new_state ? "supported" : "not supported");
        }
    }
    return updated;
}

bool
ovs_feature_set_discovered(void)
{
    /* The supported feature set has been discovered if we're connected
     * to OVS and it replied to all our feature request messages. */
    return swconn && rconn_is_connected(swconn) &&
           n_features_reply_expected == 0;
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
