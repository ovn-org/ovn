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

#include <stdlib.h>
#include <stdio.h>

#include "debug.h"
#include "bitmap.h"
#include "dirs.h"
#include "ipam.h"
#include "openvswitch/dynamic-string.h"
#include "hash.h"
#include "hmapx.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "ovn/lex.h"
#include "lib/chassis-index.h"
#include "lib/ip-mcast-index.h"
#include "lib/static-mac-binding-index.h"
#include "lib/copp.h"
#include "lib/mcast-group-index.h"
#include "lib/ovn-l7.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/lb.h"
#include "memory.h"
#include "northd.h"
#include "lib/ovn-parallel-hmap.h"
#include "ovn/actions.h"
#include "ovn/features.h"
#include "ovn/logical-fields.h"
#include "packets.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "svec.h"
#include "stopwatch.h"
#include "lib/stopwatch-names.h"
#include "stream.h"
#include "timeval.h"
#include "util.h"
#include "uuid.h"
#include "ovs-thread.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(northd);

static bool controller_event_en;
static bool lflow_hash_lock_initialized = false;

static bool check_lsp_is_up;

static bool install_ls_lb_from_router;

/* MAC allocated for service monitor usage. Just one mac is allocated
 * for this purpose and ovn-controller's on each chassis will make use
 * of this mac when sending out the packets to monitor the services
 * defined in Service_Monitor Southbound table. Since these packets
 * all locally handled, having just one mac is good enough. */
static char svc_monitor_mac[ETH_ADDR_STRLEN + 1];
static struct eth_addr svc_monitor_mac_ea;

/* If this option is 'true' northd will make use of ct.inv match fields.
 * Otherwise, it will avoid using it.  The default is true. */
static bool use_ct_inv_match = true;

/* If this option is 'true' northd will implicitly add a lowest-priority
 * drop rule in the ACL stage of logical switches that have at least one
 * ACL.
 */
static bool default_acl_drop;

#define MAX_OVN_TAGS 4096

/* Pipeline stages. */

/* The two purposes for which ovn-northd uses OVN logical datapaths. */
enum ovn_datapath_type {
    DP_SWITCH,                  /* OVN logical switch. */
    DP_ROUTER                   /* OVN logical router. */
};

/* Returns an "enum ovn_stage" built from the arguments.
 *
 * (It's better to use ovn_stage_build() for type-safety reasons, but inline
 * functions can't be used in enums or switch cases.) */
#define OVN_STAGE_BUILD(DP_TYPE, PIPELINE, TABLE) \
    (((DP_TYPE) << 9) | ((PIPELINE) << 8) | (TABLE))

/* A stage within an OVN logical switch or router.
 *
 * An "enum ovn_stage" indicates whether the stage is part of a logical switch
 * or router, whether the stage is part of the ingress or egress pipeline, and
 * the table within that pipeline.  The first three components are combined to
 * form the stage's full name, e.g. S_SWITCH_IN_PORT_SEC_L2,
 * S_ROUTER_OUT_DELIVERY. */
enum ovn_stage {
#define PIPELINE_STAGES                                                   \
    /* Logical switch ingress stages. */                                  \
    PIPELINE_STAGE(SWITCH, IN,  CHECK_PORT_SEC, 0, "ls_in_check_port_sec")   \
    PIPELINE_STAGE(SWITCH, IN,  APPLY_PORT_SEC, 1, "ls_in_apply_port_sec")   \
    PIPELINE_STAGE(SWITCH, IN,  LOOKUP_FDB ,    2, "ls_in_lookup_fdb")    \
    PIPELINE_STAGE(SWITCH, IN,  PUT_FDB,        3, "ls_in_put_fdb")       \
    PIPELINE_STAGE(SWITCH, IN,  PRE_ACL,        4, "ls_in_pre_acl")       \
    PIPELINE_STAGE(SWITCH, IN,  PRE_LB,         5, "ls_in_pre_lb")        \
    PIPELINE_STAGE(SWITCH, IN,  PRE_STATEFUL,   6, "ls_in_pre_stateful")  \
    PIPELINE_STAGE(SWITCH, IN,  ACL_HINT,       7, "ls_in_acl_hint")      \
    PIPELINE_STAGE(SWITCH, IN,  ACL,            8, "ls_in_acl")           \
    PIPELINE_STAGE(SWITCH, IN,  QOS_MARK,       9, "ls_in_qos_mark")      \
    PIPELINE_STAGE(SWITCH, IN,  QOS_METER,     10, "ls_in_qos_meter")     \
    PIPELINE_STAGE(SWITCH, IN,  LB_AFF_CHECK,  11, "ls_in_lb_aff_check")  \
    PIPELINE_STAGE(SWITCH, IN,  LB,            12, "ls_in_lb")            \
    PIPELINE_STAGE(SWITCH, IN,  LB_AFF_LEARN,  13, "ls_in_lb_aff_learn")  \
    PIPELINE_STAGE(SWITCH, IN,  ACL_AFTER_LB,  14, "ls_in_acl_after_lb")  \
    PIPELINE_STAGE(SWITCH, IN,  STATEFUL,      15, "ls_in_stateful")      \
    PIPELINE_STAGE(SWITCH, IN,  PRE_HAIRPIN,   16, "ls_in_pre_hairpin")   \
    PIPELINE_STAGE(SWITCH, IN,  NAT_HAIRPIN,   17, "ls_in_nat_hairpin")   \
    PIPELINE_STAGE(SWITCH, IN,  HAIRPIN,       18, "ls_in_hairpin")       \
    PIPELINE_STAGE(SWITCH, IN,  ARP_ND_RSP,    19, "ls_in_arp_rsp")       \
    PIPELINE_STAGE(SWITCH, IN,  DHCP_OPTIONS,  20, "ls_in_dhcp_options")  \
    PIPELINE_STAGE(SWITCH, IN,  DHCP_RESPONSE, 21, "ls_in_dhcp_response") \
    PIPELINE_STAGE(SWITCH, IN,  DNS_LOOKUP,    22, "ls_in_dns_lookup")    \
    PIPELINE_STAGE(SWITCH, IN,  DNS_RESPONSE,  23, "ls_in_dns_response")  \
    PIPELINE_STAGE(SWITCH, IN,  EXTERNAL_PORT, 24, "ls_in_external_port") \
    PIPELINE_STAGE(SWITCH, IN,  L2_LKUP,       25, "ls_in_l2_lkup")       \
    PIPELINE_STAGE(SWITCH, IN,  L2_UNKNOWN,    26, "ls_in_l2_unknown")    \
                                                                          \
    /* Logical switch egress stages. */                                   \
    PIPELINE_STAGE(SWITCH, OUT, PRE_LB,       0, "ls_out_pre_lb")         \
    PIPELINE_STAGE(SWITCH, OUT, PRE_ACL,      1, "ls_out_pre_acl")        \
    PIPELINE_STAGE(SWITCH, OUT, PRE_STATEFUL, 2, "ls_out_pre_stateful")   \
    PIPELINE_STAGE(SWITCH, OUT, ACL_HINT,     3, "ls_out_acl_hint")       \
    PIPELINE_STAGE(SWITCH, OUT, ACL,          4, "ls_out_acl")            \
    PIPELINE_STAGE(SWITCH, OUT, QOS_MARK,     5, "ls_out_qos_mark")       \
    PIPELINE_STAGE(SWITCH, OUT, QOS_METER,    6, "ls_out_qos_meter")      \
    PIPELINE_STAGE(SWITCH, OUT, STATEFUL,     7, "ls_out_stateful")       \
    PIPELINE_STAGE(SWITCH, OUT, CHECK_PORT_SEC,  8, "ls_out_check_port_sec") \
    PIPELINE_STAGE(SWITCH, OUT, APPLY_PORT_SEC,  9, "ls_out_apply_port_sec") \
                                                                      \
    /* Logical router ingress stages. */                              \
    PIPELINE_STAGE(ROUTER, IN,  ADMISSION,       0, "lr_in_admission")    \
    PIPELINE_STAGE(ROUTER, IN,  LOOKUP_NEIGHBOR, 1, "lr_in_lookup_neighbor") \
    PIPELINE_STAGE(ROUTER, IN,  LEARN_NEIGHBOR,  2, "lr_in_learn_neighbor") \
    PIPELINE_STAGE(ROUTER, IN,  IP_INPUT,        3, "lr_in_ip_input")     \
    PIPELINE_STAGE(ROUTER, IN,  UNSNAT,          4, "lr_in_unsnat")       \
    PIPELINE_STAGE(ROUTER, IN,  DEFRAG,          5, "lr_in_defrag")       \
    PIPELINE_STAGE(ROUTER, IN,  LB_AFF_CHECK,    6, "lr_in_lb_aff_check") \
    PIPELINE_STAGE(ROUTER, IN,  DNAT,            7, "lr_in_dnat")         \
    PIPELINE_STAGE(ROUTER, IN,  LB_AFF_LEARN,    8, "lr_in_lb_aff_learn") \
    PIPELINE_STAGE(ROUTER, IN,  ECMP_STATEFUL,   9, "lr_in_ecmp_stateful") \
    PIPELINE_STAGE(ROUTER, IN,  ND_RA_OPTIONS,   10, "lr_in_nd_ra_options") \
    PIPELINE_STAGE(ROUTER, IN,  ND_RA_RESPONSE,  11, "lr_in_nd_ra_response") \
    PIPELINE_STAGE(ROUTER, IN,  IP_ROUTING_PRE,  12, "lr_in_ip_routing_pre")  \
    PIPELINE_STAGE(ROUTER, IN,  IP_ROUTING,      13, "lr_in_ip_routing")      \
    PIPELINE_STAGE(ROUTER, IN,  IP_ROUTING_ECMP, 14, "lr_in_ip_routing_ecmp") \
    PIPELINE_STAGE(ROUTER, IN,  POLICY,          15, "lr_in_policy")          \
    PIPELINE_STAGE(ROUTER, IN,  POLICY_ECMP,     16, "lr_in_policy_ecmp")     \
    PIPELINE_STAGE(ROUTER, IN,  ARP_RESOLVE,     17, "lr_in_arp_resolve")     \
    PIPELINE_STAGE(ROUTER, IN,  CHK_PKT_LEN,     18, "lr_in_chk_pkt_len")     \
    PIPELINE_STAGE(ROUTER, IN,  LARGER_PKTS,     19, "lr_in_larger_pkts")     \
    PIPELINE_STAGE(ROUTER, IN,  GW_REDIRECT,     20, "lr_in_gw_redirect")     \
    PIPELINE_STAGE(ROUTER, IN,  ARP_REQUEST,     21, "lr_in_arp_request")     \
                                                                      \
    /* Logical router egress stages. */                               \
    PIPELINE_STAGE(ROUTER, OUT, CHECK_DNAT_LOCAL,   0,                       \
                   "lr_out_chk_dnat_local")                                  \
    PIPELINE_STAGE(ROUTER, OUT, UNDNAT,             1, "lr_out_undnat")      \
    PIPELINE_STAGE(ROUTER, OUT, POST_UNDNAT,        2, "lr_out_post_undnat") \
    PIPELINE_STAGE(ROUTER, OUT, SNAT,               3, "lr_out_snat")        \
    PIPELINE_STAGE(ROUTER, OUT, POST_SNAT,          4, "lr_out_post_snat")   \
    PIPELINE_STAGE(ROUTER, OUT, EGR_LOOP,           5, "lr_out_egr_loop")    \
    PIPELINE_STAGE(ROUTER, OUT, DELIVERY,           6, "lr_out_delivery")

#define PIPELINE_STAGE(DP_TYPE, PIPELINE, STAGE, TABLE, NAME)   \
    S_##DP_TYPE##_##PIPELINE##_##STAGE                          \
        = OVN_STAGE_BUILD(DP_##DP_TYPE, P_##PIPELINE, TABLE),
    PIPELINE_STAGES
#undef PIPELINE_STAGE
};

/* Due to various hard-coded priorities need to implement ACLs, the
 * northbound database supports a smaller range of ACL priorities than
 * are available to logical flows.  This value is added to an ACL
 * priority to determine the ACL's logical flow priority. */
#define OVN_ACL_PRI_OFFSET 1000

/* Register definitions specific to switches. */
#define REGBIT_CONNTRACK_DEFRAG   "reg0[0]"
#define REGBIT_CONNTRACK_COMMIT   "reg0[1]"
#define REGBIT_CONNTRACK_NAT      "reg0[2]"
#define REGBIT_DHCP_OPTS_RESULT   "reg0[3]"
#define REGBIT_DNS_LOOKUP_RESULT  "reg0[4]"
#define REGBIT_ND_RA_OPTS_RESULT  "reg0[5]"
#define REGBIT_HAIRPIN            "reg0[6]"
#define REGBIT_ACL_HINT_ALLOW_NEW "reg0[7]"
#define REGBIT_ACL_HINT_ALLOW     "reg0[8]"
#define REGBIT_ACL_HINT_DROP      "reg0[9]"
#define REGBIT_ACL_HINT_BLOCK     "reg0[10]"
#define REGBIT_LKUP_FDB           "reg0[11]"
#define REGBIT_HAIRPIN_REPLY      "reg0[12]"
#define REGBIT_ACL_LABEL          "reg0[13]"
#define REGBIT_FROM_RAMP          "reg0[14]"
#define REGBIT_PORT_SEC_DROP      "reg0[15]"

#define REG_ORIG_DIP_IPV4         "reg1"
#define REG_ORIG_DIP_IPV6         "xxreg1"
#define REG_ORIG_TP_DPORT         "reg2[0..15]"

/* Register used to store backend ipv6 address
 * for load balancer affinity. */
#define REG_LB_L2_AFF_BACKEND_IP6 "xxreg0"

/* Register definitions for switches and routers. */

/* Register used to store backend ipv4 address
 * for load balancer affinity. */
#define REG_LB_AFF_BACKEND_IP4  "reg4"
#define REG_LB_AFF_MATCH_PORT   "reg8[0..15]"

/* Indicate that this packet has been recirculated using egress
 * loopback.  This allows certain checks to be bypassed, such as a
 * logical router dropping packets with source IP address equals
 * one of the logical router's own IP addresses. */
#define REGBIT_EGRESS_LOOPBACK  "reg9[0]"
/* Register to store the result of check_pkt_larger action. */
#define REGBIT_PKT_LARGER        "reg9[1]"
#define REGBIT_LOOKUP_NEIGHBOR_RESULT "reg9[2]"
#define REGBIT_LOOKUP_NEIGHBOR_IP_RESULT "reg9[3]"
#define REGBIT_DST_NAT_IP_LOCAL "reg9[4]"
#define REGBIT_KNOWN_ECMP_NH    "reg9[5]"
#define REGBIT_KNOWN_LB_SESSION "reg9[6]"

/* Register to store the eth address associated to a router port for packets
 * received in S_ROUTER_IN_ADMISSION.
 */
#define REG_INPORT_ETH_ADDR "xreg0[0..47]"

/* Register for ECMP bucket selection. */
#define REG_ECMP_GROUP_ID       "reg8[0..15]"
#define REG_ECMP_MEMBER_ID      "reg8[16..31]"

/* Registers used for routing. */
#define REG_NEXT_HOP_IPV4 "reg0"
#define REG_NEXT_HOP_IPV6 "xxreg0"
#define REG_SRC_IPV4 "reg1"
#define REG_SRC_IPV6 "xxreg1"
#define REG_ROUTE_TABLE_ID "reg7"

/* Register used to store backend ipv6 address
 * for load balancer affinity. */
#define REG_LB_L3_AFF_BACKEND_IP6  "xxreg1"

#define REG_ORIG_TP_DPORT_ROUTER   "reg9[16..31]"

/* Register used for setting a label for ACLs in a Logical Switch. */
#define REG_LABEL "reg3"

/* Register used for temporarily store ECMP eth.src to avoid masked ct_label
 * access. It doesn't really occupy registers because the content of the
 * register is saved to stack and then restored in the same flow.
 * Note: the bits must match ct_label.ecmp_reply_eth defined in
 * logical-fields.c */
#define REG_ECMP_ETH_FULL "xxreg1"
#define REG_ECMP_ETH_FIELD REG_ECMP_ETH_FULL "[" \
    OVN_CT_STR(OVN_CT_ECMP_ETH_1ST_BIT) \
    ".." \
    OVN_CT_STR(OVN_CT_ECMP_ETH_END_BIT) "]"

#define FLAGBIT_NOT_VXLAN "flags[1] == 0"

/*
 * OVS register usage:
 *
 * Logical Switch pipeline:
 * +----+----------------------------------------------+---+-----------------------------------+
 * | R0 |     REGBIT_{CONNTRACK/DHCP/DNS}              |   |                                   |
 * |    |     REGBIT_{HAIRPIN/HAIRPIN_REPLY}           |   |                                   |
 * |    | REGBIT_ACL_HINT_{ALLOW_NEW/ALLOW/DROP/BLOCK} |   |                                   |
 * |    |     REGBIT_ACL_LABEL                         | X |                                   |
 * +----+----------------------------------------------+ X |                                   |
 * | R5 |                   UNUSED                     | X |       LB_L2_AFF_BACKEND_IP6       |
 * | R1 |         ORIG_DIP_IPV4 (>= IN_PRE_STATEFUL)   | R |                                   |
 * +----+----------------------------------------------+ E |                                   |
 * | R2 |         ORIG_TP_DPORT (>= IN_PRE_STATEFUL)   | G |                                   |
 * +----+----------------------------------------------+ 0 |                                   |
 * | R3 |                  ACL LABEL                   |   |                                   |
 * +----+----------------------------------------------+---+-----------------------------------+
 * | R4 |            REG_LB_AFF_BACKEND_IP4            |   |                                   |
 * +----+----------------------------------------------+ X |                                   |
 * | R5 |                   UNUSED                     | X | ORIG_DIP_IPV6(>= IN_PRE_STATEFUL) |
 * +----+----------------------------------------------+ R |                                   |
 * | R6 |                   UNUSED                     | E |                                   |
 * +----+----------------------------------------------+ G |                                   |
 * | R7 |                   UNUSED                     | 1 |                                   |
 * +----+----------------------------------------------+---+-----------------------------------+
 * | R8 |              LB_AFF_MATCH_PORT               |
 * +----+----------------------------------------------+
 * | R9 |                   UNUSED                     |
 * +----+----------------------------------------------+
 *
 * Logical Router pipeline:
 * +-----+---------------------------+---+-----------------+---+------------------------------------+
 * | R0  | REGBIT_ND_RA_OPTS_RESULT  |   |                 |   |                                    |
 * |     |   (= IN_ND_RA_OPTIONS)    | X |                 |   |                                    |
 * |     |      NEXT_HOP_IPV4        | R |                 |   |                                    |
 * |     |      (>= IP_INPUT)        | E | INPORT_ETH_ADDR | X |                                    |
 * +-----+---------------------------+ G |   (< IP_INPUT)  | X |                                    |
 * | R1  |   SRC_IPV4 for ARP-REQ    | 0 |                 | R |                                    |
 * |     |      (>= IP_INPUT)        |   |                 | E |     NEXT_HOP_IPV6 (>= DEFRAG )     |
 * +-----+---------------------------+---+-----------------+ G |                                    |
 * | R2  |        UNUSED             | X |                 | 0 |                                    |
 * |     |                           | R |                 |   |                                    |
 * +-----+---------------------------+ E |     UNUSED      |   |                                    |
 * | R3  |        UNUSED             | G |                 |   |                                    |
 * |     |                           | 1 |                 |   |                                    |
 * +-----+---------------------------+---+-----------------+---+------------------------------------+
 * | R4  |  REG_LB_AFF_BACKEND_IP4   | X |                 |   |                                    |
 * |     |                           | R |                 |   |                                    |
 * +-----+---------------------------+ E |     UNUSED      | X |                                    |
 * | R5  |        UNUSED             | G |                 | X |                                    |
 * |     |                           | 2 |                 | R |        LB_L3_AFF_BACKEND_IP6       |
 * +-----+---------------------------+---+-----------------+ E |           (<= IN_DNAT)             |
 * | R6  |        UNUSED             | X |                 | G |                                    |
 * |     |                           | R |                 | 1 |                                    |
 * +-----+---------------------------+ E |     UNUSED      |   |                                    |
 * | R7  |      ROUTE_TABLE_ID       | G |                 |   |                                    |
 * |     | (>= IN_IP_ROUTING_PRE &&  | 3 |                 |   |                                    |
 * |     |  <= IN_IP_ROUTING)        |   |                 |   |                                    |
 * +-----+---------------------------+---+-----------------+---+------------------------------------+
 * | R8  |     ECMP_GROUP_ID         |   |                 |
 * |     |     ECMP_MEMBER_ID        |   |                 |
 * |     |    LB_AFF_MATCH_PORT      | X |                 |
 * +-----+---------------------------+ R |                 |
 * |     | REGBIT_{                  | E |                 |
 * |     |   EGRESS_LOOPBACK/        | G |     UNUSED      |
 * | R9  |   PKT_LARGER/             | 4 |                 |
 * |     |   LOOKUP_NEIGHBOR_RESULT/ |   |                 |
 * |     |   SKIP_LOOKUP_NEIGHBOR/   |   |                 |
 * |     |   KNOWN_ECMP_NH}          |   |                 |
 * |     |                           |   |                 |
 * |     | REG_ORIG_TP_DPORT_ROUTER  |   |                 |
 * |     |                           |   |                 |
 * +-----+---------------------------+---+-----------------+
 *
 */

/*
 * Route offsets implement logic to prioritize traffic for routes with
 * same ip_prefix values:
 *  -  connected route overrides static one;
 *  -  static route overrides connected route. */
#define ROUTE_PRIO_OFFSET_MULTIPLIER 3
#define ROUTE_PRIO_OFFSET_STATIC 1
#define ROUTE_PRIO_OFFSET_CONNECTED 2

/* Returns an "enum ovn_stage" built from the arguments. */
static enum ovn_stage
ovn_stage_build(enum ovn_datapath_type dp_type, enum ovn_pipeline pipeline,
                uint8_t table)
{
    return OVN_STAGE_BUILD(dp_type, pipeline, table);
}

/* Returns the pipeline to which 'stage' belongs. */
static enum ovn_pipeline
ovn_stage_get_pipeline(enum ovn_stage stage)
{
    return (stage >> 8) & 1;
}

/* Returns the pipeline name to which 'stage' belongs. */
static const char *
ovn_stage_get_pipeline_name(enum ovn_stage stage)
{
    return ovn_stage_get_pipeline(stage) == P_IN ? "ingress" : "egress";
}

/* Returns the table to which 'stage' belongs. */
static uint8_t
ovn_stage_get_table(enum ovn_stage stage)
{
    return stage & 0xff;
}

/* Returns a string name for 'stage'. */
static const char *
ovn_stage_to_str(enum ovn_stage stage)
{
    switch (stage) {
#define PIPELINE_STAGE(DP_TYPE, PIPELINE, STAGE, TABLE, NAME)       \
        case S_##DP_TYPE##_##PIPELINE##_##STAGE: return NAME;
    PIPELINE_STAGES
#undef PIPELINE_STAGE
        default: return "<unknown>";
    }
}

/* Returns the type of the datapath to which a flow with the given 'stage' may
 * be added. */
static enum ovn_datapath_type
ovn_stage_to_datapath_type(enum ovn_stage stage)
{
    switch (stage) {
#define PIPELINE_STAGE(DP_TYPE, PIPELINE, STAGE, TABLE, NAME)       \
        case S_##DP_TYPE##_##PIPELINE##_##STAGE: return DP_##DP_TYPE;
    PIPELINE_STAGES
#undef PIPELINE_STAGE
    default: OVS_NOT_REACHED();
    }
}

static void
build_chassis_features(const struct northd_input *input_data,
                       struct chassis_features *chassis_features)
{
    const struct sbrec_chassis *chassis;

    SBREC_CHASSIS_TABLE_FOR_EACH (chassis, input_data->sbrec_chassis) {
        bool ct_no_masked_label =
            smap_get_bool(&chassis->other_config,
                          OVN_FEATURE_CT_NO_MASKED_LABEL,
                          false);
        if (!ct_no_masked_label && chassis_features->ct_no_masked_label) {
            chassis_features->ct_no_masked_label = false;
        }

        bool mac_binding_timestamp =
            smap_get_bool(&chassis->other_config,
                          OVN_FEATURE_MAC_BINDING_TIMESTAMP,
                          false);
        if (!mac_binding_timestamp &&
            chassis_features->mac_binding_timestamp) {
            chassis_features->mac_binding_timestamp = false;
        }
    }
}

struct ovn_chassis_qdisc_queues {
    struct hmap_node key_node;
    uint32_t queue_id;
    struct uuid chassis_uuid;
};

static uint32_t
hash_chassis_queue(const struct uuid *chassis_uuid, uint32_t queue_id)
{
    return hash_2words(uuid_hash(chassis_uuid), queue_id);
}

static void
destroy_chassis_queues(struct hmap *set)
{
    struct ovn_chassis_qdisc_queues *node;
    HMAP_FOR_EACH_POP (node, key_node, set) {
        free(node);
    }
    hmap_destroy(set);
}

static void
add_chassis_queue(struct hmap *set, const struct uuid *chassis_uuid,
                  uint32_t queue_id)
{
    struct ovn_chassis_qdisc_queues *node = xmalloc(sizeof *node);
    node->queue_id = queue_id;
    node->chassis_uuid = *chassis_uuid;
    hmap_insert(set, &node->key_node,
                hash_chassis_queue(chassis_uuid, queue_id));
}

static bool
chassis_queueid_in_use(const struct hmap *set, const struct uuid *chassis_uuid,
                       uint32_t queue_id)
{
    const struct ovn_chassis_qdisc_queues *node;
    HMAP_FOR_EACH_WITH_HASH (node, key_node,
                             hash_chassis_queue(chassis_uuid, queue_id), set) {
        if (uuid_equals(chassis_uuid, &node->chassis_uuid)
            && node->queue_id == queue_id) {
            return true;
        }
    }
    return false;
}

static uint32_t
allocate_chassis_queueid(struct hmap *set, const struct uuid *uuid, char *name)
{
    if (!uuid) {
        return 0;
    }

    for (uint32_t queue_id = QDISC_MIN_QUEUE_ID + 1;
         queue_id <= QDISC_MAX_QUEUE_ID;
         queue_id++) {
        if (!chassis_queueid_in_use(set, uuid, queue_id)) {
            add_chassis_queue(set, uuid, queue_id);
            return queue_id;
        }
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    VLOG_WARN_RL(&rl, "all %s queue ids exhausted", name);
    return 0;
}

static void
free_chassis_queueid(struct hmap *set, const struct uuid *uuid,
                     uint32_t queue_id)
{
    if (!uuid) {
        return;
    }

    struct ovn_chassis_qdisc_queues *node;
    HMAP_FOR_EACH_WITH_HASH (node, key_node,
                             hash_chassis_queue(uuid, queue_id), set) {
        if (uuid_equals(uuid, &node->chassis_uuid)
            && node->queue_id == queue_id) {
            hmap_remove(set, &node->key_node);
            free(node);
            break;
        }
    }
}

static inline bool
port_has_qos_params(const struct smap *opts)
{
    return (smap_get(opts, "qos_max_rate") ||
            smap_get(opts, "qos_burst"));
}


static void
init_mcast_port_info(struct mcast_port_info *mcast_info,
                     const struct nbrec_logical_switch_port *nbsp,
                     const struct nbrec_logical_router_port *nbrp)
{
    if (nbsp) {
        mcast_info->flood =
            smap_get_bool(&nbsp->options, "mcast_flood", false);
        mcast_info->flood_reports =
            smap_get_bool(&nbsp->options, "mcast_flood_reports",
                          false);
    } else if (nbrp) {
        /* We don't process multicast reports in any special way on logical
         * routers so just treat them as regular multicast traffic.
         */
        mcast_info->flood =
            smap_get_bool(&nbrp->options, "mcast_flood", false);
        mcast_info->flood_reports = mcast_info->flood;
    }
}

static uint32_t
ovn_mcast_group_allocate_key(struct mcast_info *mcast_info)
{
    return ovn_allocate_tnlid(&mcast_info->group_tnlids, "multicast group",
                              OVN_MIN_IP_MULTICAST, OVN_MAX_IP_MULTICAST,
                              &mcast_info->group_tnlid_hint);
}

/* Contains a NAT entry with the external addresses pre-parsed. */
struct ovn_nat {
    const struct nbrec_nat *nb;
    struct lport_addresses ext_addrs;
    struct ovs_list ext_addr_list_node; /* Linkage in the per-external IP
                                         * list of nat entries. Currently
                                         * only used for SNAT.
                                         */
};

/* Stores the list of SNAT entries referencing a unique SNAT IP address.
 * The 'snat_entries' list will be empty if the SNAT IP is used only for
 * dnat_force_snat_ip or lb_force_snat_ip.
 */
struct ovn_snat_ip {
    struct ovs_list snat_entries;
};

static bool
get_force_snat_ip(struct ovn_datapath *od, const char *key_type,
                  struct lport_addresses *laddrs);

/* Returns true if a 'nat_entry' is valid, i.e.:
 * - parsing was successful.
 * - the string yielded exactly one IPv4 address or exactly one IPv6 address.
 */
static bool
nat_entry_is_valid(const struct ovn_nat *nat_entry)
{
    const struct lport_addresses *ext_addrs = &nat_entry->ext_addrs;

    return (ext_addrs->n_ipv4_addrs == 1 && ext_addrs->n_ipv6_addrs == 0) ||
        (ext_addrs->n_ipv4_addrs == 0 && ext_addrs->n_ipv6_addrs == 1);
}

static bool
nat_entry_is_v6(const struct ovn_nat *nat_entry)
{
    return nat_entry->ext_addrs.n_ipv6_addrs > 0;
}

static void
snat_ip_add(struct ovn_datapath *od, const char *ip, struct ovn_nat *nat_entry)
{
    struct ovn_snat_ip *snat_ip = shash_find_data(&od->snat_ips, ip);

    if (!snat_ip) {
        snat_ip = xzalloc(sizeof *snat_ip);
        ovs_list_init(&snat_ip->snat_entries);
        shash_add(&od->snat_ips, ip, snat_ip);
    }

    if (nat_entry) {
        ovs_list_push_back(&snat_ip->snat_entries,
                           &nat_entry->ext_addr_list_node);
    }
}

static void
init_nat_entries(struct ovn_datapath *od)
{
    if (!od->nbr) {
        return;
    }

    shash_init(&od->snat_ips);
    if (get_force_snat_ip(od, "dnat", &od->dnat_force_snat_addrs)) {
        if (od->dnat_force_snat_addrs.n_ipv4_addrs) {
            snat_ip_add(od, od->dnat_force_snat_addrs.ipv4_addrs[0].addr_s,
                        NULL);
        }
        if (od->dnat_force_snat_addrs.n_ipv6_addrs) {
            snat_ip_add(od, od->dnat_force_snat_addrs.ipv6_addrs[0].addr_s,
                        NULL);
        }
    }

    /* Check if 'lb_force_snat_ip' is configured with 'router_ip'. */
    const char *lb_force_snat =
        smap_get(&od->nbr->options, "lb_force_snat_ip");
    if (lb_force_snat && !strcmp(lb_force_snat, "router_ip")
            && smap_get(&od->nbr->options, "chassis")) {
        /* Set it to true only if its gateway router and
         * options:lb_force_snat_ip=router_ip. */
        od->lb_force_snat_router_ip = true;
    } else {
        od->lb_force_snat_router_ip = false;

        /* Check if 'lb_force_snat_ip' is configured with a set of
         * IP address(es). */
        if (get_force_snat_ip(od, "lb", &od->lb_force_snat_addrs)) {
            if (od->lb_force_snat_addrs.n_ipv4_addrs) {
                snat_ip_add(od, od->lb_force_snat_addrs.ipv4_addrs[0].addr_s,
                            NULL);
            }
            if (od->lb_force_snat_addrs.n_ipv6_addrs) {
                snat_ip_add(od, od->lb_force_snat_addrs.ipv6_addrs[0].addr_s,
                            NULL);
            }
        }
    }

    if (!od->nbr->n_nat) {
        return;
    }

    od->nat_entries = xmalloc(od->nbr->n_nat * sizeof *od->nat_entries);

    for (size_t i = 0; i < od->nbr->n_nat; i++) {
        const struct nbrec_nat *nat = od->nbr->nat[i];
        struct ovn_nat *nat_entry = &od->nat_entries[i];

        nat_entry->nb = nat;
        if (!extract_ip_addresses(nat->external_ip,
                                  &nat_entry->ext_addrs) ||
                !nat_entry_is_valid(nat_entry)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

            VLOG_WARN_RL(&rl,
                         "Bad ip address %s in nat configuration "
                         "for router %s", nat->external_ip, od->nbr->name);
            continue;
        }

        /* If this is a SNAT rule add the IP to the set of unique SNAT IPs. */
        if (!strcmp(nat->type, "snat")) {
            if (!nat_entry_is_v6(nat_entry)) {
                snat_ip_add(od, nat_entry->ext_addrs.ipv4_addrs[0].addr_s,
                            nat_entry);
            } else {
                snat_ip_add(od, nat_entry->ext_addrs.ipv6_addrs[0].addr_s,
                            nat_entry);
            }
        }

        if (!strcmp(nat->type, "dnat_and_snat")
            && nat->logical_port && nat->external_mac) {
            od->has_distributed_nat = true;
        }
    }
    od->n_nat_entries = od->nbr->n_nat;
}

static void
destroy_nat_entries(struct ovn_datapath *od)
{
    if (!od->nbr) {
        return;
    }

    shash_destroy_free_data(&od->snat_ips);
    destroy_lport_addresses(&od->dnat_force_snat_addrs);
    destroy_lport_addresses(&od->lb_force_snat_addrs);

    for (size_t i = 0; i < od->n_nat_entries; i++) {
        destroy_lport_addresses(&od->nat_entries[i].ext_addrs);
    }
}

static void
init_router_external_ips(struct ovn_datapath *od)
{
    if (!od->nbr) {
        return;
    }

    sset_init(&od->external_ips);
    for (size_t i = 0; i < od->nbr->n_nat; i++) {
        sset_add(&od->external_ips, od->nbr->nat[i]->external_ip);
    }
}

static void
destroy_router_external_ips(struct ovn_datapath *od)
{
    if (!od->nbr) {
        return;
    }

    sset_destroy(&od->external_ips);
}

static bool
lb_has_vip(const struct nbrec_load_balancer *lb)
{
    return !smap_is_empty(&lb->vips);
}

static bool
lb_group_has_vip(const struct nbrec_load_balancer_group *lb_group)
{
    for (size_t i = 0; i < lb_group->n_load_balancer; i++) {
        if (lb_has_vip(lb_group->load_balancer[i])) {
            return true;
        }
    }
    return false;
}

static bool
ls_has_lb_vip(struct ovn_datapath *od)
{
    for (size_t i = 0; i < od->nbs->n_load_balancer; i++) {
        if (lb_has_vip(od->nbs->load_balancer[i])) {
            return true;
        }
    }

    for (size_t i = 0; i < od->nbs->n_load_balancer_group; i++) {
        if (lb_group_has_vip(od->nbs->load_balancer_group[i])) {
            return true;
        }
    }
    return false;
}

static bool
lr_has_lb_vip(struct ovn_datapath *od)
{
    for (size_t i = 0; i < od->nbr->n_load_balancer; i++) {
        if (lb_has_vip(od->nbr->load_balancer[i])) {
            return true;
        }
    }

    for (size_t i = 0; i < od->nbr->n_load_balancer_group; i++) {
        if (lb_group_has_vip(od->nbr->load_balancer_group[i])) {
            return true;
        }
    }
    return false;
}

static void
init_lb_for_datapath(struct ovn_datapath *od)
{
    if (od->nbs) {
        od->has_lb_vip = ls_has_lb_vip(od);
    } else {
        od->has_lb_vip = lr_has_lb_vip(od);
    }
}

static void
destroy_lb_for_datapath(struct ovn_datapath *od)
{
    ovn_lb_ip_set_destroy(od->lb_ips);
    od->lb_ips = NULL;

    if (!od->nbs && !od->nbr) {
        return;
    }
}

/* A group of logical router datapaths which are connected - either
 * directly or indirectly.
 * Each logical router can belong to only one group. */
struct lrouter_group {
    struct ovn_datapath **router_dps;
    int n_router_dps;
    /* Set of ha_chassis_groups which are associated with the router dps. */
    struct sset ha_chassis_groups;
};

static struct ovn_datapath *
ovn_datapath_create(struct hmap *datapaths, const struct uuid *key,
                    const struct nbrec_logical_switch *nbs,
                    const struct nbrec_logical_router *nbr,
                    const struct sbrec_datapath_binding *sb)
{
    struct ovn_datapath *od = xzalloc(sizeof *od);
    od->key = *key;
    od->sb = sb;
    od->nbs = nbs;
    od->nbr = nbr;
    hmap_init(&od->port_tnlids);
    hmap_init(&od->nb_pgs);
    od->port_key_hint = 0;
    hmap_insert(datapaths, &od->key_node, uuid_hash(&od->key));
    od->lr_group = NULL;
    ovs_list_init(&od->port_list);
    return od;
}

static void ovn_ls_port_group_destroy(struct hmap *nb_pgs);
static void destroy_mcast_info_for_datapath(struct ovn_datapath *od);

static void
ovn_datapath_destroy(struct hmap *datapaths, struct ovn_datapath *od)
{
    if (od) {
        /* Don't remove od->list.  It is used within build_datapaths() as a
         * private list and once we've exited that function it is not safe to
         * use it. */
        hmap_remove(datapaths, &od->key_node);
        ovn_destroy_tnlids(&od->port_tnlids);
        destroy_ipam_info(&od->ipam_info);
        free(od->router_ports);
        free(od->ls_peers);
        destroy_nat_entries(od);
        destroy_router_external_ips(od);
        destroy_lb_for_datapath(od);
        free(od->nat_entries);
        free(od->localnet_ports);
        free(od->l3dgw_ports);
        ovn_ls_port_group_destroy(&od->nb_pgs);
        destroy_mcast_info_for_datapath(od);

        free(od);
    }
}

/* Returns 'od''s datapath type. */
static enum ovn_datapath_type
ovn_datapath_get_type(const struct ovn_datapath *od)
{
    return od->nbs ? DP_SWITCH : DP_ROUTER;
}

static struct ovn_datapath *
ovn_datapath_find(const struct hmap *datapaths,
                  const struct uuid *uuid)
{
    struct ovn_datapath *od;

    HMAP_FOR_EACH_WITH_HASH (od, key_node, uuid_hash(uuid), datapaths) {
        if (uuid_equals(uuid, &od->key)) {
            return od;
        }
    }
    return NULL;
}

static struct ovn_datapath *
ovn_datapath_find_by_key(struct hmap *datapaths, uint32_t dp_key)
{
    struct ovn_datapath *od;

    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (od->tunnel_key == dp_key) {
            return od;
        }
    }

    return NULL;
}

static bool
ovn_datapath_is_stale(const struct ovn_datapath *od)
{
    return !od->nbr && !od->nbs;
}

static struct ovn_datapath *
ovn_datapath_from_sbrec(const struct hmap *datapaths,
                        const struct sbrec_datapath_binding *sb)
{
    struct uuid key;

    if (!smap_get_uuid(&sb->external_ids, "logical-switch", &key) &&
        !smap_get_uuid(&sb->external_ids, "logical-router", &key)) {
        return NULL;
    }
    struct ovn_datapath *od = ovn_datapath_find(datapaths, &key);
    if (od && (od->sb == sb)) {
        return od;
    }

    return NULL;
}

static void
ovn_datapath_add_router_port(struct ovn_datapath *od, struct ovn_port *op)
{
    if (od->n_router_ports == od->n_allocated_router_ports) {
        od->router_ports = x2nrealloc(od->router_ports,
                                      &od->n_allocated_router_ports,
                                      sizeof *od->router_ports);
    }
    od->router_ports[od->n_router_ports++] = op;
}

static void
ovn_datapath_add_ls_peer(struct ovn_datapath *od, struct ovn_datapath *peer)
{
    if (od->n_ls_peers == od->n_allocated_ls_peers) {
        od->ls_peers = x2nrealloc(od->ls_peers, &od->n_allocated_ls_peers,
                                  sizeof *od->ls_peers);
    }
    od->ls_peers[od->n_ls_peers++] = peer;
}

static bool
lrouter_is_enabled(const struct nbrec_logical_router *lrouter)
{
    return !lrouter->enabled || *lrouter->enabled;
}

static void
init_ipam_info_for_datapath(struct ovn_datapath *od)
{
    if (!od->nbs) {
        return;
    }

    char uuid_s[UUID_LEN + 1];
    sprintf(uuid_s, UUID_FMT, UUID_ARGS(&od->key));
    init_ipam_info(&od->ipam_info, &od->nbs->other_config, uuid_s);
}

static void
init_mcast_info_for_router_datapath(struct ovn_datapath *od)
{
    struct mcast_router_info *mcast_rtr_info = &od->mcast_info.rtr;

    mcast_rtr_info->relay = smap_get_bool(&od->nbr->options, "mcast_relay",
                                          false);
}

static void
init_mcast_info_for_switch_datapath(struct ovn_datapath *od)
{
    struct mcast_switch_info *mcast_sw_info = &od->mcast_info.sw;

    mcast_sw_info->enabled =
        smap_get_bool(&od->nbs->other_config, "mcast_snoop", false);
    mcast_sw_info->querier =
        smap_get_bool(&od->nbs->other_config, "mcast_querier", true);
    mcast_sw_info->flood_unregistered =
        smap_get_bool(&od->nbs->other_config, "mcast_flood_unregistered",
                      false);

    mcast_sw_info->table_size =
        smap_get_ullong(&od->nbs->other_config, "mcast_table_size",
                        OVN_MCAST_DEFAULT_MAX_ENTRIES);

    uint32_t idle_timeout =
        smap_get_ullong(&od->nbs->other_config, "mcast_idle_timeout",
                        OVN_MCAST_DEFAULT_IDLE_TIMEOUT_S);
    if (idle_timeout < OVN_MCAST_MIN_IDLE_TIMEOUT_S) {
        idle_timeout = OVN_MCAST_MIN_IDLE_TIMEOUT_S;
    } else if (idle_timeout > OVN_MCAST_MAX_IDLE_TIMEOUT_S) {
        idle_timeout = OVN_MCAST_MAX_IDLE_TIMEOUT_S;
    }
    mcast_sw_info->idle_timeout = idle_timeout;

    uint32_t query_interval =
        smap_get_ullong(&od->nbs->other_config, "mcast_query_interval",
                        mcast_sw_info->idle_timeout / 2);
    if (query_interval < OVN_MCAST_MIN_QUERY_INTERVAL_S) {
        query_interval = OVN_MCAST_MIN_QUERY_INTERVAL_S;
    } else if (query_interval > OVN_MCAST_MAX_QUERY_INTERVAL_S) {
        query_interval = OVN_MCAST_MAX_QUERY_INTERVAL_S;
    }
    mcast_sw_info->query_interval = query_interval;

    mcast_sw_info->eth_src =
        nullable_xstrdup(smap_get(&od->nbs->other_config, "mcast_eth_src"));
    mcast_sw_info->ipv4_src =
        nullable_xstrdup(smap_get(&od->nbs->other_config, "mcast_ip4_src"));
    mcast_sw_info->ipv6_src =
        nullable_xstrdup(smap_get(&od->nbs->other_config, "mcast_ip6_src"));

    mcast_sw_info->query_max_response =
        smap_get_ullong(&od->nbs->other_config, "mcast_query_max_response",
                        OVN_MCAST_DEFAULT_QUERY_MAX_RESPONSE_S);
}

static void
init_mcast_flow_count(struct ovn_datapath *od)
{
    if (od->nbr) {
        return;
    }

    struct mcast_switch_info *mcast_sw_info = &od->mcast_info.sw;
    mcast_sw_info->active_v4_flows = ATOMIC_VAR_INIT(0);
    mcast_sw_info->active_v6_flows = ATOMIC_VAR_INIT(0);
}

static void
init_mcast_info_for_datapath(struct ovn_datapath *od)
{
    if (!od->nbr && !od->nbs) {
        return;
    }

    hmap_init(&od->mcast_info.group_tnlids);
    od->mcast_info.group_tnlid_hint = OVN_MIN_IP_MULTICAST;
    ovs_list_init(&od->mcast_info.groups);

    if (od->nbs) {
        init_mcast_info_for_switch_datapath(od);
    } else {
        init_mcast_info_for_router_datapath(od);
    }
}

static void
destroy_mcast_info_for_switch_datapath(struct ovn_datapath *od)
{
    struct mcast_switch_info *mcast_sw_info = &od->mcast_info.sw;

    free(mcast_sw_info->eth_src);
    free(mcast_sw_info->ipv4_src);
    free(mcast_sw_info->ipv6_src);
}

static void
destroy_mcast_info_for_datapath(struct ovn_datapath *od)
{
    if (!od->nbr && !od->nbs) {
        return;
    }

    if (od->nbs) {
        destroy_mcast_info_for_switch_datapath(od);
    }

    ovn_destroy_tnlids(&od->mcast_info.group_tnlids);
}

static void
store_mcast_info_for_switch_datapath(const struct sbrec_ip_multicast *sb,
                                     struct ovn_datapath *od)
{
    struct mcast_switch_info *mcast_sw_info = &od->mcast_info.sw;

    sbrec_ip_multicast_set_datapath(sb, od->sb);
    sbrec_ip_multicast_set_enabled(sb, &mcast_sw_info->enabled, 1);
    sbrec_ip_multicast_set_querier(sb, &mcast_sw_info->querier, 1);
    sbrec_ip_multicast_set_table_size(sb, &mcast_sw_info->table_size, 1);
    sbrec_ip_multicast_set_idle_timeout(sb, &mcast_sw_info->idle_timeout, 1);
    sbrec_ip_multicast_set_query_interval(sb,
                                          &mcast_sw_info->query_interval, 1);
    sbrec_ip_multicast_set_query_max_resp(sb,
                                          &mcast_sw_info->query_max_response,
                                          1);

    if (mcast_sw_info->eth_src) {
        sbrec_ip_multicast_set_eth_src(sb, mcast_sw_info->eth_src);
    }

    if (mcast_sw_info->ipv4_src) {
        sbrec_ip_multicast_set_ip4_src(sb, mcast_sw_info->ipv4_src);
    }

    if (mcast_sw_info->ipv6_src) {
        sbrec_ip_multicast_set_ip6_src(sb, mcast_sw_info->ipv6_src);
    }
}

static void
ovn_datapath_update_external_ids(struct ovn_datapath *od)
{
    /* Get the logical-switch or logical-router UUID to set in
     * external-ids. */
    char uuid_s[UUID_LEN + 1];
    sprintf(uuid_s, UUID_FMT, UUID_ARGS(&od->key));
    const char *key = od->nbs ? "logical-switch" : "logical-router";

    /* Get names to set in external-ids. */
    const char *name = od->nbs ? od->nbs->name : od->nbr->name;
    const char *name2 = (od->nbs
                         ? smap_get(&od->nbs->external_ids,
                                    "neutron:network_name")
                         : smap_get(&od->nbr->external_ids,
                                    "neutron:router_name"));

    /* Set external-ids. */
    struct smap ids = SMAP_INITIALIZER(&ids);
    smap_add(&ids, key, uuid_s);
    smap_add(&ids, "name", name);
    if (name2 && name2[0]) {
        smap_add(&ids, "name2", name2);
    }

    /* Set interconn-ts. */
    if (od->nbs) {
        const char *ts = smap_get(&od->nbs->other_config, "interconn-ts");
        if (ts) {
            smap_add(&ids, "interconn-ts", ts);
        }
    }

    /* Set snat-ct-zone */
    if (od->nbr) {
        int nat_default_ct = smap_get_int(&od->nbr->options,
                                           "snat-ct-zone", -1);
        if (nat_default_ct >= 0) {
            smap_add_format(&ids, "snat-ct-zone", "%d", nat_default_ct);
        }

        bool learn_from_arp_request =
            smap_get_bool(&od->nbr->options, "always_learn_from_arp_request",
                          true);
        if (!learn_from_arp_request) {
            smap_add(&ids, "always_learn_from_arp_request", "false");
        }
    }

    sbrec_datapath_binding_set_external_ids(od->sb, &ids);
    smap_destroy(&ids);
}

static void
join_datapaths(struct northd_input *input_data,
               struct ovsdb_idl_txn *ovnsb_txn,
               struct hmap *datapaths, struct ovs_list *sb_only,
               struct ovs_list *nb_only, struct ovs_list *both,
               struct ovs_list *lr_list)
{
    ovs_list_init(sb_only);
    ovs_list_init(nb_only);
    ovs_list_init(both);

    const struct sbrec_datapath_binding *sb;
    SBREC_DATAPATH_BINDING_TABLE_FOR_EACH_SAFE (sb,
                            input_data->sbrec_datapath_binding_table) {
        struct uuid key;
        if (!smap_get_uuid(&sb->external_ids, "logical-switch", &key) &&
            !smap_get_uuid(&sb->external_ids, "logical-router", &key)) {
            ovsdb_idl_txn_add_comment(
                ovnsb_txn,
                "deleting Datapath_Binding "UUID_FMT" that lacks "
                "external-ids:logical-switch and "
                "external-ids:logical-router",
                UUID_ARGS(&sb->header_.uuid));
            sbrec_datapath_binding_delete(sb);
            continue;
        }

        if (ovn_datapath_find(datapaths, &key)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(
                &rl, "deleting Datapath_Binding "UUID_FMT" with "
                "duplicate external-ids:logical-switch/router "UUID_FMT,
                UUID_ARGS(&sb->header_.uuid), UUID_ARGS(&key));
            sbrec_datapath_binding_delete(sb);
            continue;
        }

        struct ovn_datapath *od = ovn_datapath_create(datapaths, &key,
                                                      NULL, NULL, sb);
        ovs_list_push_back(sb_only, &od->list);
    }

    const struct nbrec_logical_switch *nbs;
    NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH (nbs,
                              input_data->nbrec_logical_switch) {
        struct ovn_datapath *od = ovn_datapath_find(datapaths,
                                                    &nbs->header_.uuid);
        if (od) {
            od->nbs = nbs;
            ovs_list_remove(&od->list);
            ovs_list_push_back(both, &od->list);
            ovn_datapath_update_external_ids(od);
        } else {
            od = ovn_datapath_create(datapaths, &nbs->header_.uuid,
                                     nbs, NULL, NULL);
            ovs_list_push_back(nb_only, &od->list);
        }

        init_ipam_info_for_datapath(od);
        init_mcast_info_for_datapath(od);
        init_lb_for_datapath(od);
    }

    const struct nbrec_logical_router *nbr;
    NBREC_LOGICAL_ROUTER_TABLE_FOR_EACH (nbr,
                               input_data->nbrec_logical_router) {
        if (!lrouter_is_enabled(nbr)) {
            continue;
        }

        struct ovn_datapath *od = ovn_datapath_find(datapaths,
                                                    &nbr->header_.uuid);
        if (od) {
            if (!od->nbs) {
                od->nbr = nbr;
                ovs_list_remove(&od->list);
                ovs_list_push_back(both, &od->list);
                ovn_datapath_update_external_ids(od);
            } else {
                /* Can't happen! */
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl,
                             "duplicate UUID "UUID_FMT" in OVN_Northbound",
                             UUID_ARGS(&nbr->header_.uuid));
                continue;
            }
        } else {
            od = ovn_datapath_create(datapaths, &nbr->header_.uuid,
                                     NULL, nbr, NULL);
            ovs_list_push_back(nb_only, &od->list);
        }
        init_mcast_info_for_datapath(od);
        init_nat_entries(od);
        init_router_external_ips(od);
        init_lb_for_datapath(od);
        if (smap_get(&od->nbr->options, "chassis")) {
            od->is_gw_router = true;
        }
        ovs_list_push_back(lr_list, &od->lr_list);
    }
}

static bool
is_vxlan_mode(struct northd_input *input_data)
{
    const struct sbrec_chassis *chassis;
    SBREC_CHASSIS_TABLE_FOR_EACH (chassis, input_data->sbrec_chassis) {
        for (int i = 0; i < chassis->n_encaps; i++) {
            if (!strcmp(chassis->encaps[i]->type, "vxlan")) {
                return true;
            }
        }
    }
    return false;
}

static uint32_t
get_ovn_max_dp_key_local(struct northd_input *input_data)
{
    if (is_vxlan_mode(input_data)) {
        /* OVN_MAX_DP_GLOBAL_NUM doesn't apply for vxlan mode. */
        return OVN_MAX_DP_VXLAN_KEY;
    }
    return OVN_MAX_DP_KEY - OVN_MAX_DP_GLOBAL_NUM;
}

static void
ovn_datapath_allocate_key(struct northd_input *input_data,
                          struct hmap *datapaths, struct hmap *dp_tnlids,
                          struct ovn_datapath *od, uint32_t *hint)
{
    if (!od->tunnel_key) {
        od->tunnel_key = ovn_allocate_tnlid(dp_tnlids, "datapath",
                                    OVN_MIN_DP_KEY_LOCAL,
                                    get_ovn_max_dp_key_local(input_data),
                                    hint);
        if (!od->tunnel_key) {
            if (od->sb) {
                sbrec_datapath_binding_delete(od->sb);
            }
            ovs_list_remove(&od->list);
            ovn_datapath_destroy(datapaths, od);
        }
    }
}

static void
ovn_datapath_assign_requested_tnl_id(struct northd_input *input_data,
                                     struct hmap *dp_tnlids,
                                     struct ovn_datapath *od)
{
    const struct smap *other_config = (od->nbs
                                       ? &od->nbs->other_config
                                       : &od->nbr->options);
    uint32_t tunnel_key = smap_get_int(other_config, "requested-tnl-key", 0);
    if (tunnel_key) {
        const char *interconn_ts = smap_get(other_config, "interconn-ts");
        if (!interconn_ts && is_vxlan_mode(input_data) &&
            tunnel_key >= 1 << 12) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Tunnel key %"PRIu32" for datapath %s is "
                         "incompatible with VXLAN", tunnel_key,
                         od->nbs ? od->nbs->name : od->nbr->name);
            return;
        }
        if (ovn_add_tnlid(dp_tnlids, tunnel_key)) {
            od->tunnel_key = tunnel_key;
        } else {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Logical %s %s requests same tunnel key "
                         "%"PRIu32" as another logical switch or router",
                         od->nbs ? "switch" : "router",
                         od->nbs ? od->nbs->name : od->nbr->name, tunnel_key);
        }
    }
}

/* Array of all datapaths, with 'od->index' being their index in the array. */
static struct ovn_datapath **datapaths_array = NULL;
static size_t n_datapaths = 0; /* Size of the 'datapaths_array'. */

/* Updates the southbound Datapath_Binding table so that it contains the
 * logical switches and routers specified by the northbound database.
 *
 * Initializes 'datapaths' to contain a "struct ovn_datapath" for every logical
 * switch and router. */
static void
build_datapaths(struct northd_input *input_data,
                struct ovsdb_idl_txn *ovnsb_txn,
                struct hmap *datapaths,
                struct ovs_list *lr_list)
{
    struct ovs_list sb_only, nb_only, both;

    join_datapaths(input_data, ovnsb_txn,
                   datapaths, &sb_only, &nb_only, &both, lr_list);

    /* Assign explicitly requested tunnel ids first. */
    struct hmap dp_tnlids = HMAP_INITIALIZER(&dp_tnlids);
    struct ovn_datapath *od;
    LIST_FOR_EACH (od, list, &both) {
        ovn_datapath_assign_requested_tnl_id(input_data, &dp_tnlids, od);
    }
    LIST_FOR_EACH (od, list, &nb_only) {
        ovn_datapath_assign_requested_tnl_id(input_data, &dp_tnlids, od);
    }

    /* Keep nonconflicting tunnel IDs that are already assigned. */
    LIST_FOR_EACH (od, list, &both) {
        if (!od->tunnel_key && ovn_add_tnlid(&dp_tnlids, od->sb->tunnel_key)) {
            od->tunnel_key = od->sb->tunnel_key;
        }
    }

    /* Assign new tunnel ids where needed. */
    uint32_t hint = 0;
    LIST_FOR_EACH_SAFE (od, list, &both) {
        ovn_datapath_allocate_key(input_data,
                                  datapaths, &dp_tnlids, od, &hint);
    }
    LIST_FOR_EACH_SAFE (od, list, &nb_only) {
        ovn_datapath_allocate_key(input_data,
                                  datapaths, &dp_tnlids, od, &hint);
    }

    /* Sync tunnel ids from nb to sb. */
    LIST_FOR_EACH (od, list, &both) {
        if (od->sb->tunnel_key != od->tunnel_key) {
            sbrec_datapath_binding_set_tunnel_key(od->sb, od->tunnel_key);
        }
        ovn_datapath_update_external_ids(od);
    }
    LIST_FOR_EACH (od, list, &nb_only) {
        od->sb = sbrec_datapath_binding_insert(ovnsb_txn);
        ovn_datapath_update_external_ids(od);
        sbrec_datapath_binding_set_tunnel_key(od->sb, od->tunnel_key);
    }
    ovn_destroy_tnlids(&dp_tnlids);

    /* Delete southbound records without northbound matches. */
    LIST_FOR_EACH_SAFE (od, list, &sb_only) {
        ovs_list_remove(&od->list);
        sbrec_datapath_binding_delete(od->sb);
        ovn_datapath_destroy(datapaths, od);
    }

    /* Assign unique sequential indexes to all datapaths.  These are not
     * visible outside of the northd loop, so, unlike the tunnel keys, it
     * doesn't matter if they are different on every iteration. */
    size_t index = 0;

    n_datapaths = hmap_count(datapaths);
    datapaths_array = xrealloc(datapaths_array,
                               n_datapaths * sizeof *datapaths_array);
    HMAP_FOR_EACH (od, key_node, datapaths) {
        od->index = index;
        datapaths_array[index++] = od;
    }
}

/* Structure representing logical router port
 * routable addresses. This includes DNAT and Load Balancer
 * addresses. This structure will only be filled in if the
 * router port is a gateway router port. Otherwise, all pointers
 * will be NULL and n_addrs will be 0.
 */
struct ovn_port_routable_addresses {
    /* The parsed routable addresses */
    struct lport_addresses *laddrs;
    /* Number of items in the laddrs array */
    size_t n_addrs;
};

/* A logical switch port or logical router port.
 *
 * In steady state, an ovn_port points to a northbound Logical_Switch_Port
 * record (via 'nbsp') *or* a Logical_Router_Port record (via 'nbrp'), and to a
 * southbound Port_Binding record (via 'sb').  As the state of the system
 * changes, join_logical_ports() may determine that there is a new LSP or LRP
 * that has no corresponding Port_Binding record (in which case build_ports())
 * will create the missing Port_Binding) or that a Port_Binding record exists
 * that has no coresponding LSP (in which case build_ports() will delete the
 * spurious Port_Binding).  Thus, after build_ports() runs, any given ovn_port
 * will have 'sb' nonnull, and 'nbsp' xor 'nbrp' nonnull.
 *
 * Ordinarily there is only one ovn_port that points to a given LSP or LRP (but
 * distributed gateway ports point a "derived" ovn_port to a duplicate LRP).
 */
struct ovn_port {
    /* Port name aka key.
     *
     * This is ordinarily the same as nbsp->name or nbrp->name and
     * sb->logical_port.  (A distributed gateway port creates a "derived"
     * ovn_port with key "cr-%s" % nbrp->name.) */
    struct hmap_node key_node;  /* Index on 'key'. */
    char *key;                  /* nbsp->name, nbrp->name, sb->logical_port. */
    char *json_key;             /* 'key', quoted for use in JSON. */

    const struct sbrec_port_binding *sb;         /* May be NULL. */

    uint32_t tunnel_key;

    /* Logical switch port data. */
    const struct nbrec_logical_switch_port *nbsp; /* May be NULL. */

    struct lport_addresses *lsp_addrs;  /* Logical switch port addresses. */
    unsigned int n_lsp_addrs;

    struct lport_addresses *ps_addrs;   /* Port security addresses. */
    unsigned int n_ps_addrs;

    /* Logical router port data. */
    const struct nbrec_logical_router_port *nbrp; /* May be NULL. */

    struct lport_addresses lrp_networks;

    struct ovn_port_routable_addresses routables;

    /* Logical port multicast data. */
    struct mcast_port_info mcast_info;

    /* At most one of l3dgw_port and cr_port can be not NULL. */

    /* This is set to a distributed gateway port if and only if this ovn_port
     * is "derived" from it. Otherwise this is set to NULL. The derived
     * ovn_port represents the instance of distributed gateway port on the
     * gateway chassis.*/
    struct ovn_port *l3dgw_port;

    /* This is set to the "derived" chassis-redirect port of this port if and
     * only if this port is a distributed gateway port. Otherwise this is set
     * to NULL. */
    struct ovn_port *cr_port;

    bool has_unknown; /* If the addresses have 'unknown' defined. */

    bool has_bfd;

    /* The port's peer:
     *
     *     - A switch port S of type "router" has a router port R as a peer,
     *       and R in turn has S has its peer.
     *
     *     - Two connected logical router ports have each other as peer.
     *
     *     - Other kinds of ports have no peer. */
    struct ovn_port *peer;

    struct ovn_datapath *od;

    struct ovs_list list;       /* In list of similar records. */

    struct ovs_list dp_node;
};

static bool
is_l3dgw_port(const struct ovn_port *op)
{
    return op->cr_port;
}

static bool
is_cr_port(const struct ovn_port *op)
{
    return op->l3dgw_port;
}

static void
destroy_routable_addresses(struct ovn_port_routable_addresses *ra)
{
    for (size_t i = 0; i < ra->n_addrs; i++) {
        destroy_lport_addresses(&ra->laddrs[i]);
    }
    free(ra->laddrs);
}

static char **get_nat_addresses(const struct ovn_port *op, size_t *n,
                                bool routable_only, bool include_lb_ips);

static void
assign_routable_addresses(struct ovn_port *op)
{
    size_t n;
    char **nats = get_nat_addresses(op, &n, true, true);

    if (!nats) {
        return;
    }

    struct lport_addresses *laddrs = xcalloc(n, sizeof(*laddrs));
    size_t n_addrs = 0;
    for (size_t i = 0; i < n; i++) {
        int ofs;
        if (!extract_addresses(nats[i], &laddrs[n_addrs], &ofs)) {
            free(nats[i]);
            continue;
        }
        n_addrs++;
        free(nats[i]);
    }
    free(nats);

    /* Everything seems to have worked out */
    op->routables.laddrs = laddrs;
    op->routables.n_addrs = n_addrs;
}


static void
ovn_port_set_nb(struct ovn_port *op,
                const struct nbrec_logical_switch_port *nbsp,
                const struct nbrec_logical_router_port *nbrp)
{
    op->nbsp = nbsp;
    op->nbrp = nbrp;
    init_mcast_port_info(&op->mcast_info, op->nbsp, op->nbrp);
}

static struct ovn_port *
ovn_port_create(struct hmap *ports, const char *key,
                const struct nbrec_logical_switch_port *nbsp,
                const struct nbrec_logical_router_port *nbrp,
                const struct sbrec_port_binding *sb)
{
    struct ovn_port *op = xzalloc(sizeof *op);

    struct ds json_key = DS_EMPTY_INITIALIZER;
    json_string_escape(key, &json_key);
    op->json_key = ds_steal_cstr(&json_key);

    op->key = xstrdup(key);
    op->sb = sb;
    ovn_port_set_nb(op, nbsp, nbrp);
    op->l3dgw_port = op->cr_port = NULL;
    hmap_insert(ports, &op->key_node, hash_string(op->key, 0));
    return op;
}

static void
ovn_port_destroy(struct hmap *ports, struct ovn_port *port)
{
    if (port) {
        /* Don't remove port->list.  It is used within build_ports() as a
         * private list and once we've exited that function it is not safe to
         * use it. */
        hmap_remove(ports, &port->key_node);

        for (int i = 0; i < port->n_lsp_addrs; i++) {
            destroy_lport_addresses(&port->lsp_addrs[i]);
        }
        free(port->lsp_addrs);

        for (int i = 0; i < port->n_ps_addrs; i++) {
            destroy_lport_addresses(&port->ps_addrs[i]);
        }
        free(port->ps_addrs);

        destroy_routable_addresses(&port->routables);

        destroy_lport_addresses(&port->lrp_networks);
        free(port->json_key);
        free(port->key);
        free(port);
    }
}

/* Returns the ovn_port that matches 'name'.  If 'prefer_bound' is true and
 * multiple ports share the same name, gives precendence to ports bound to
 * an ovn_datapath.
 */
static struct ovn_port *
ovn_port_find__(const struct hmap *ports, const char *name,
                bool prefer_bound)
{
    struct ovn_port *matched_op = NULL;
    struct ovn_port *op;

    HMAP_FOR_EACH_WITH_HASH (op, key_node, hash_string(name, 0), ports) {
        if (!strcmp(op->key, name)) {
            matched_op = op;
            if (!prefer_bound || op->od) {
                return op;
            }
        }
    }
    return matched_op;
}

static struct ovn_port *
ovn_port_find(const struct hmap *ports, const char *name)
{
    return ovn_port_find__(ports, name, false);
}

static struct ovn_port *
ovn_port_find_bound(const struct hmap *ports, const char *name)
{
    return ovn_port_find__(ports, name, true);
}

/* Returns true if the logical switch port 'enabled' column is empty or
 * set to true.  Otherwise, returns false. */
static bool
lsp_is_enabled(const struct nbrec_logical_switch_port *lsp)
{
    return !lsp->n_enabled || *lsp->enabled;
}

/* Returns true only if the logical switch port 'up' column is set to true.
 * Otherwise, if the column is not set or set to false, returns false. */
static bool
lsp_is_up(const struct nbrec_logical_switch_port *lsp)
{
    return lsp->n_up && *lsp->up;
}

static bool
lsp_is_external(const struct nbrec_logical_switch_port *nbsp)
{
    return !strcmp(nbsp->type, "external");
}

static bool
lsp_is_router(const struct nbrec_logical_switch_port *nbsp)
{
    return !strcmp(nbsp->type, "router");
}

static bool
lsp_is_remote(const struct nbrec_logical_switch_port *nbsp)
{
    return !strcmp(nbsp->type, "remote");
}

static bool
lsp_is_localnet(const struct nbrec_logical_switch_port *nbsp)
{
    return !strcmp(nbsp->type, "localnet");
}

static bool
lsp_is_vtep(const struct nbrec_logical_switch_port *nbsp)
{
    return !strcmp(nbsp->type, "vtep");
}

static bool
localnet_can_learn_mac(const struct nbrec_logical_switch_port *nbsp)
{
    return smap_get_bool(&nbsp->options, "localnet_learn_fdb", false);
}

static bool
lsp_is_type_changed(const struct sbrec_port_binding *sb,
                const struct nbrec_logical_switch_port *nbsp,
                bool *update_sbrec)
{
    *update_sbrec = false;
    if (!sb || !nbsp) {
        return false;
    }

    if (!sb->type[0] && !nbsp->type[0]) {
        /* Two "VIF's" interface make sure both have parent_port
         * set or both have parent_port unset, otherwisre they are
         * different ports type.
         */
        if ((!sb->parent_port && nbsp->parent_name) ||
                        (sb->parent_port && !nbsp->parent_name)) {
            *update_sbrec = true;
            return true;
        } else {
            return false;
        }
    }

    /* Cover cases where port changed to/from virtual port */
    if (!strcmp(sb->type, "virtual") ||
                !strcmp(nbsp->type, "virtual")) {
        *update_sbrec = true;
    }

    /* Both lports are not "VIF's" it is safe to use strcmp. */
    if (sb->type[0] && nbsp->type[0]) {
        return strcmp(sb->type, nbsp->type);
    }

    return true;
}

static bool
lrport_is_enabled(const struct nbrec_logical_router_port *lrport)
{
    return !lrport->enabled || *lrport->enabled;
}

static struct ovn_port *
ovn_port_get_peer(const struct hmap *ports, struct ovn_port *op)
{
    if (!op->nbsp || !lsp_is_router(op->nbsp) || op->l3dgw_port) {
        return NULL;
    }

    if (op->peer) {
        return op->peer;
    }

    const char *peer_name = smap_get(&op->nbsp->options, "router-port");
    if (!peer_name) {
        return NULL;
    }

    return ovn_port_find(ports, peer_name);
}

static void
ipam_insert_ip_for_datapath(struct ovn_datapath *od, uint32_t ip)
{
    if (!od) {
        return;
    }

    ipam_insert_ip(&od->ipam_info, ip);
}

static void
ipam_insert_lsp_addresses(struct ovn_datapath *od, struct ovn_port *op,
                          char *address)
{
    if (!od || !op || !address || !strcmp(address, "unknown")
        || !strcmp(address, "router") || is_dynamic_lsp_address(address)) {
        return;
    }

    struct lport_addresses laddrs;
    if (!extract_lsp_addresses(address, &laddrs)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "Extract addresses failed.");
        return;
    }
    ipam_insert_mac(&laddrs.ea, true);

    /* IP is only added to IPAM if the switch's subnet option
     * is set, whereas MAC is always added to MACAM. */
    if (!od->ipam_info.allocated_ipv4s) {
        destroy_lport_addresses(&laddrs);
        return;
    }

    for (size_t j = 0; j < laddrs.n_ipv4_addrs; j++) {
        uint32_t ip = ntohl(laddrs.ipv4_addrs[j].addr);
        ipam_insert_ip_for_datapath(od, ip);
    }

    destroy_lport_addresses(&laddrs);
}

static void
ipam_add_port_addresses(struct ovn_datapath *od, struct ovn_port *op)
{
    if (!od || !op) {
        return;
    }

    if (op->nbsp) {
        /* Add all the port's addresses to address data structures. */
        for (size_t i = 0; i < op->nbsp->n_addresses; i++) {
            ipam_insert_lsp_addresses(od, op, op->nbsp->addresses[i]);
        }
    } else if (op->nbrp) {
        struct lport_addresses lrp_networks;
        if (!extract_lrp_networks(op->nbrp, &lrp_networks)) {
            static struct vlog_rate_limit rl
                = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Extract addresses failed.");
            return;
        }
        ipam_insert_mac(&lrp_networks.ea, true);

        if (!op->peer || !op->peer->nbsp || !op->peer->od || !op->peer->od->nbs
            || !smap_get(&op->peer->od->nbs->other_config, "subnet")) {
            destroy_lport_addresses(&lrp_networks);
            return;
        }

        for (size_t i = 0; i < lrp_networks.n_ipv4_addrs; i++) {
            uint32_t ip = ntohl(lrp_networks.ipv4_addrs[i].addr);
            /* If the router has the first IP address of the subnet, don't add
             * it to IPAM. We already added this when we initialized IPAM for
             * the datapath. This will just result in an erroneous message
             * about a duplicate IP address.
             */
            if (ip != op->peer->od->ipam_info.start_ipv4) {
                ipam_insert_ip_for_datapath(op->peer->od, ip);
            }
        }

        destroy_lport_addresses(&lrp_networks);
    }
}

static const char *find_lrp_member_ip(const struct ovn_port *op,
                                      const char *ip_s);

/* Returns true if the given router port 'op' (assumed to be a distributed
 * gateway port) is the relevant DGP where the NAT rule of the router needs to
 * be applied. */
static bool
is_nat_gateway_port(const struct nbrec_nat *nat, const struct ovn_port *op)
{
    if (op->od->n_l3dgw_ports > 1
        && ((!nat->gateway_port && !find_lrp_member_ip(op, nat->external_ip))
            || (nat->gateway_port && nat->gateway_port != op->nbrp))) {
        return false;
    }
    return true;
}

enum dynamic_update_type {
    NONE,    /* No change to the address */
    REMOVE,  /* Address is no longer dynamic */
    STATIC,  /* Use static address (MAC only) */
    DYNAMIC, /* Assign a new dynamic address */
};

struct dynamic_address_update {
    struct ovs_list node;       /* In build_ipam()'s list of updates. */

    struct ovn_datapath *od;
    struct ovn_port *op;

    struct lport_addresses current_addresses;
    struct eth_addr static_mac;
    ovs_be32 static_ip;
    struct in6_addr static_ipv6;
    enum dynamic_update_type mac;
    enum dynamic_update_type ipv4;
    enum dynamic_update_type ipv6;
};

static enum dynamic_update_type
dynamic_mac_changed(const char *lsp_addresses,
                    struct dynamic_address_update *update)
{
   struct eth_addr ea;

   if (ovs_scan(lsp_addresses, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(ea))) {
       if (eth_addr_equals(ea, update->current_addresses.ea)) {
           return NONE;
       } else {
           /* MAC is still static, but it has changed */
           update->static_mac = ea;
           return STATIC;
       }
   }

   uint64_t mac64 = eth_addr_to_uint64(update->current_addresses.ea);
   uint64_t prefix = eth_addr_to_uint64(get_mac_prefix());

   if ((mac64 ^ prefix) >> 24) {
       return DYNAMIC;
   } else {
       return NONE;
   }
}

static enum dynamic_update_type
dynamic_ip4_changed(const char *lsp_addrs,
                    struct dynamic_address_update *update)
{
    const struct ipam_info *ipam = &update->op->od->ipam_info;
    const struct lport_addresses *cur_addresses = &update->current_addresses;
    bool dynamic_ip4 = ipam->allocated_ipv4s != NULL;

    if (!dynamic_ip4) {
        if (update->current_addresses.n_ipv4_addrs) {
            return REMOVE;
        } else {
            return NONE;
        }
    }

    if (!cur_addresses->n_ipv4_addrs) {
        /* IPv4 was previously static but now is dynamic */
        return DYNAMIC;
    }

    uint32_t ip4 = ntohl(cur_addresses->ipv4_addrs[0].addr);
    if (ip4 < ipam->start_ipv4) {
        return DYNAMIC;
    }

    uint32_t index = ip4 - ipam->start_ipv4;
    if (index >= ipam->total_ipv4s - 1 ||
        bitmap_is_set(ipam->allocated_ipv4s, index)) {
        /* Previously assigned dynamic IPv4 address can no longer be used.
         * It's either outside the subnet, conflicts with an excluded IP,
         * or conflicts with a statically-assigned address on the switch
         */
        return DYNAMIC;
    } else {
        char ipv6_s[IPV6_SCAN_LEN + 1];
        ovs_be32 new_ip;
        int n = 0;

        if ((ovs_scan(lsp_addrs, "dynamic "IP_SCAN_FMT"%n",
                     IP_SCAN_ARGS(&new_ip), &n)
             && lsp_addrs[n] == '\0') ||
            (ovs_scan(lsp_addrs, "dynamic "IP_SCAN_FMT" "IPV6_SCAN_FMT"%n",
                      IP_SCAN_ARGS(&new_ip), ipv6_s, &n)
             && lsp_addrs[n] == '\0')) {
            index = ntohl(new_ip) - ipam->start_ipv4;
            if (ntohl(new_ip) < ipam->start_ipv4 ||
                index > ipam->total_ipv4s ||
                bitmap_is_set(ipam->allocated_ipv4s, index)) {
                /* new static ip is not valid */
                return DYNAMIC;
            } else if (cur_addresses->ipv4_addrs[0].addr != new_ip) {
                update->ipv4 = STATIC;
                update->static_ip = new_ip;
                return STATIC;
            }
        }
        return NONE;
    }
}

static enum dynamic_update_type
dynamic_ip6_changed(const char *lsp_addrs,
                    struct dynamic_address_update *update)
{
    bool dynamic_ip6 = update->op->od->ipam_info.ipv6_prefix_set;
    struct eth_addr ea;

    if (!dynamic_ip6) {
        if (update->current_addresses.n_ipv6_addrs) {
            /* IPv6 was dynamic but now is not */
            return REMOVE;
        } else {
            /* IPv6 has never been dynamic */
            return NONE;
        }
    }

    if (!update->current_addresses.n_ipv6_addrs ||
        ovs_scan(lsp_addrs, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(ea))) {
        /* IPv6 was previously static but now is dynamic */
        return DYNAMIC;
    }

    const struct lport_addresses *cur_addresses;
    char ipv6_s[IPV6_SCAN_LEN + 1];
    ovs_be32 new_ip;
    int n = 0;

    if ((ovs_scan(lsp_addrs, "dynamic "IPV6_SCAN_FMT"%n",
                  ipv6_s, &n) && lsp_addrs[n] == '\0') ||
        (ovs_scan(lsp_addrs, "dynamic "IP_SCAN_FMT" "IPV6_SCAN_FMT"%n",
                  IP_SCAN_ARGS(&new_ip), ipv6_s, &n)
         && lsp_addrs[n] == '\0')) {
        struct in6_addr ipv6;

        if (!ipv6_parse(ipv6_s, &ipv6)) {
            return DYNAMIC;
        }

        struct in6_addr masked = ipv6_addr_bitand(&ipv6,
                &update->op->od->ipam_info.ipv6_prefix);
        if (!IN6_ARE_ADDR_EQUAL(&masked,
                                &update->op->od->ipam_info.ipv6_prefix)) {
            return DYNAMIC;
        }

        cur_addresses = &update->current_addresses;

        if (!IN6_ARE_ADDR_EQUAL(&cur_addresses->ipv6_addrs[0].addr,
                                &ipv6)) {
            update->static_ipv6 = ipv6;
            return STATIC;
        }
    } else if (update->mac != NONE) {
        return DYNAMIC;
    }

    return NONE;
}

/* Check previously assigned dynamic addresses for validity. This will
 * check if the assigned addresses need to change.
 *
 * Returns true if any changes to dynamic addresses are required
 */
static bool
dynamic_addresses_check_for_updates(const char *lsp_addrs,
                                    struct dynamic_address_update *update)
{
    update->mac = dynamic_mac_changed(lsp_addrs, update);
    update->ipv4 = dynamic_ip4_changed(lsp_addrs, update);
    update->ipv6 = dynamic_ip6_changed(lsp_addrs, update);
    if (update->mac == NONE &&
        update->ipv4 == NONE &&
        update->ipv6 == NONE) {
        return false;
    } else {
        return true;
    }
}

/* For addresses that do not need to be updated, go ahead and insert them
 * into IPAM. This way, their addresses will be claimed and cannot be assigned
 * elsewhere later.
 */
static void
update_unchanged_dynamic_addresses(struct dynamic_address_update *update)
{
    if (update->mac == NONE) {
        ipam_insert_mac(&update->current_addresses.ea, false);
    }
    if (update->ipv4 == NONE && update->current_addresses.n_ipv4_addrs) {
        ipam_insert_ip_for_datapath(update->op->od,
                       ntohl(update->current_addresses.ipv4_addrs[0].addr));
    }
}

static void
set_lsp_dynamic_addresses(const char *dynamic_addresses, struct ovn_port *op)
{
    extract_lsp_addresses(dynamic_addresses, &op->lsp_addrs[op->n_lsp_addrs]);
    op->n_lsp_addrs++;
}

/* Determines which components (MAC, IPv4, and IPv6) of dynamic
 * addresses need to be assigned. This is used exclusively for
 * ports that do not have dynamic addresses already assigned.
 */
static void
set_dynamic_updates(const char *addrspec,
                    struct dynamic_address_update *update)
{
    bool has_ipv4 = false, has_ipv6 = false;
    char ipv6_s[IPV6_SCAN_LEN + 1];
    struct eth_addr mac;
    ovs_be32 ip;
    int n = 0;
    if (ovs_scan(addrspec, ETH_ADDR_SCAN_FMT" dynamic%n",
                 ETH_ADDR_SCAN_ARGS(mac), &n)
        && addrspec[n] == '\0') {
        update->mac = STATIC;
        update->static_mac = mac;
    } else {
        update->mac = DYNAMIC;
    }

    if ((ovs_scan(addrspec, "dynamic "IP_SCAN_FMT"%n",
                 IP_SCAN_ARGS(&ip), &n) && addrspec[n] == '\0')) {
        has_ipv4 = true;
    } else if ((ovs_scan(addrspec, "dynamic "IPV6_SCAN_FMT"%n",
                         ipv6_s, &n) && addrspec[n] == '\0')) {
        has_ipv6 = true;
    } else if ((ovs_scan(addrspec, "dynamic "IP_SCAN_FMT" "IPV6_SCAN_FMT"%n",
                         IP_SCAN_ARGS(&ip), ipv6_s, &n)
               && addrspec[n] == '\0')) {
        has_ipv4 = has_ipv6 = true;
    }

    if (has_ipv4) {
        update->ipv4 = STATIC;
        update->static_ip = ip;
    } else if (update->op->od->ipam_info.allocated_ipv4s) {
        update->ipv4 = DYNAMIC;
    } else {
        update->ipv4 = NONE;
    }

    if (has_ipv6 && ipv6_parse(ipv6_s, &update->static_ipv6)) {
        update->ipv6 = STATIC;
    } else if (update->op->od->ipam_info.ipv6_prefix_set) {
        update->ipv6 = DYNAMIC;
    } else {
        update->ipv6 = NONE;
    }
}

static void
update_dynamic_addresses(struct dynamic_address_update *update)
{
    ovs_be32 ip4 = 0;
    switch (update->ipv4) {
    case NONE:
        if (update->current_addresses.n_ipv4_addrs) {
            ip4 = update->current_addresses.ipv4_addrs[0].addr;
        }
        break;
    case REMOVE:
        break;
    case STATIC:
        ip4 = update->static_ip;
        break;
    case DYNAMIC:
        ip4 = htonl(ipam_get_unused_ip(&update->od->ipam_info));
        VLOG_INFO("Assigned dynamic IPv4 address '"IP_FMT"' to port '%s'",
                  IP_ARGS(ip4), update->op->nbsp->name);
    }

    struct eth_addr mac;
    switch (update->mac) {
    case NONE:
        mac = update->current_addresses.ea;
        break;
    case REMOVE:
        OVS_NOT_REACHED();
    case STATIC:
        mac = update->static_mac;
        break;
    case DYNAMIC:
        eth_addr_from_uint64(ipam_get_unused_mac(ip4), &mac);
        VLOG_INFO("Assigned dynamic MAC address '"ETH_ADDR_FMT"' to port '%s'",
                  ETH_ADDR_ARGS(mac), update->op->nbsp->name);
        break;
    }

    struct in6_addr ip6 = in6addr_any;
    switch (update->ipv6) {
    case NONE:
        if (update->current_addresses.n_ipv6_addrs) {
            ip6 = update->current_addresses.ipv6_addrs[0].addr;
        }
        break;
    case REMOVE:
        break;
    case STATIC:
        ip6 = update->static_ipv6;
        break;
    case DYNAMIC:
        in6_generate_eui64(mac, &update->od->ipam_info.ipv6_prefix, &ip6);
        struct ds ip6_ds = DS_EMPTY_INITIALIZER;
        ipv6_format_addr(&ip6, &ip6_ds);
        VLOG_INFO("Assigned dynamic IPv6 address '%s' to port '%s'",
                  ip6_ds.string, update->op->nbsp->name);
        ds_destroy(&ip6_ds);
        break;
    }

    struct ds new_addr = DS_EMPTY_INITIALIZER;
    ds_put_format(&new_addr, ETH_ADDR_FMT, ETH_ADDR_ARGS(mac));
    ipam_insert_mac(&mac, true);

    if (ip4) {
        ipam_insert_ip_for_datapath(update->od, ntohl(ip4));
        ds_put_format(&new_addr, " "IP_FMT, IP_ARGS(ip4));
    }
    if (!IN6_ARE_ADDR_EQUAL(&ip6, &in6addr_any)) {
        char ip6_s[INET6_ADDRSTRLEN + 1];
        ipv6_string_mapped(ip6_s, &ip6);
        ds_put_format(&new_addr, " %s", ip6_s);
    }
    nbrec_logical_switch_port_set_dynamic_addresses(update->op->nbsp,
                                                    ds_cstr(&new_addr));
    set_lsp_dynamic_addresses(ds_cstr(&new_addr), update->op);
    ds_destroy(&new_addr);
}

static void
build_ipam(struct hmap *datapaths, struct hmap *ports)
{
    /* IPAM generally stands for IP address management.  In non-virtualized
     * world, MAC addresses come with the hardware.  But, with virtualized
     * workloads, they need to be assigned and managed.  This function
     * does both IP address management (ipam) and MAC address management
     * (macam). */

    /* If the switch's other_config:subnet is set, allocate new addresses for
     * ports that have the "dynamic" keyword in their addresses column. */
    struct ovn_datapath *od;
    struct ovs_list updates;

    ovs_list_init(&updates);
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbs) {
            continue;
        }

        for (size_t i = 0; i < od->nbs->n_ports; i++) {
            const struct nbrec_logical_switch_port *nbsp = od->nbs->ports[i];

            if (!od->ipam_info.allocated_ipv4s &&
                !od->ipam_info.ipv6_prefix_set &&
                !od->ipam_info.mac_only) {
                if (nbsp->dynamic_addresses) {
                    nbrec_logical_switch_port_set_dynamic_addresses(nbsp,
                                                                    NULL);
                }
                continue;
            }

            struct ovn_port *op = ovn_port_find(ports, nbsp->name);
            if (!op || op->nbsp != nbsp || op->peer) {
                /* Do not allocate addresses for logical switch ports that
                 * have a peer. */
                continue;
            }

            int num_dynamic_addresses = 0;
            for (size_t j = 0; j < nbsp->n_addresses; j++) {
                if (!is_dynamic_lsp_address(nbsp->addresses[j])) {
                    continue;
                }
                if (num_dynamic_addresses) {
                    static struct vlog_rate_limit rl
                        = VLOG_RATE_LIMIT_INIT(1, 1);
                    VLOG_WARN_RL(&rl, "More than one dynamic address "
                                 "configured for logical switch port '%s'",
                                 nbsp->name);
                    continue;
                }
                num_dynamic_addresses++;
                struct dynamic_address_update *update
                    = xzalloc(sizeof *update);
                update->op = op;
                update->od = od;
                if (nbsp->dynamic_addresses) {
                    bool any_changed;
                    extract_lsp_addresses(nbsp->dynamic_addresses,
                                          &update->current_addresses);
                    any_changed = dynamic_addresses_check_for_updates(
                        nbsp->addresses[j], update);
                    update_unchanged_dynamic_addresses(update);
                    if (any_changed) {
                        ovs_list_push_back(&updates, &update->node);
                    } else {
                        /* No changes to dynamic addresses */
                        set_lsp_dynamic_addresses(nbsp->dynamic_addresses, op);
                        destroy_lport_addresses(&update->current_addresses);
                        free(update);
                    }
                } else {
                    set_dynamic_updates(nbsp->addresses[j], update);
                    ovs_list_push_back(&updates, &update->node);
                }
            }

            if (!num_dynamic_addresses && nbsp->dynamic_addresses) {
                nbrec_logical_switch_port_set_dynamic_addresses(nbsp, NULL);
            }
        }

    }

    /* After retaining all unchanged dynamic addresses, now assign
     * new ones.
     */
    struct dynamic_address_update *update;
    LIST_FOR_EACH_POP (update, node, &updates) {
        update_dynamic_addresses(update);
        destroy_lport_addresses(&update->current_addresses);
        free(update);
    }
}

/* Tag allocation for nested containers.
 *
 * For a logical switch port with 'parent_name' and a request to allocate tags,
 * keeps a track of all allocated tags. */
struct tag_alloc_node {
    struct hmap_node hmap_node;
    char *parent_name;
    unsigned long *allocated_tags;  /* A bitmap to track allocated tags. */
};

static void
tag_alloc_destroy(struct hmap *tag_alloc_table)
{
    struct tag_alloc_node *node;
    HMAP_FOR_EACH_POP (node, hmap_node, tag_alloc_table) {
        bitmap_free(node->allocated_tags);
        free(node->parent_name);
        free(node);
    }
    hmap_destroy(tag_alloc_table);
}

static struct tag_alloc_node *
tag_alloc_get_node(struct hmap *tag_alloc_table, const char *parent_name)
{
    /* If a node for the 'parent_name' exists, return it. */
    struct tag_alloc_node *tag_alloc_node;
    HMAP_FOR_EACH_WITH_HASH (tag_alloc_node, hmap_node,
                             hash_string(parent_name, 0),
                             tag_alloc_table) {
        if (!strcmp(tag_alloc_node->parent_name, parent_name)) {
            return tag_alloc_node;
        }
    }

    /* Create a new node. */
    tag_alloc_node = xmalloc(sizeof *tag_alloc_node);
    tag_alloc_node->parent_name = xstrdup(parent_name);
    tag_alloc_node->allocated_tags = bitmap_allocate(MAX_OVN_TAGS);
    /* Tag 0 is invalid for nested containers. */
    bitmap_set1(tag_alloc_node->allocated_tags, 0);
    hmap_insert(tag_alloc_table, &tag_alloc_node->hmap_node,
                hash_string(parent_name, 0));

    return tag_alloc_node;
}

static void
tag_alloc_add_existing_tags(struct hmap *tag_alloc_table,
                            const struct nbrec_logical_switch_port *nbsp)
{
    /* Add the tags of already existing nested containers.  If there is no
     * 'nbsp->parent_name' or no 'nbsp->tag' set, there is nothing to do. */
    if (!nbsp->parent_name || !nbsp->parent_name[0] || !nbsp->tag) {
        return;
    }

    struct tag_alloc_node *tag_alloc_node;
    tag_alloc_node = tag_alloc_get_node(tag_alloc_table, nbsp->parent_name);
    bitmap_set1(tag_alloc_node->allocated_tags, *nbsp->tag);
}

static void
tag_alloc_create_new_tag(struct hmap *tag_alloc_table,
                         const struct nbrec_logical_switch_port *nbsp)
{
    if (!nbsp->tag_request) {
        return;
    }

    if (nbsp->parent_name && nbsp->parent_name[0]
        && *nbsp->tag_request == 0) {
        /* For nested containers that need allocation, do the allocation. */

        if (nbsp->tag) {
            /* This has already been allocated. */
            return;
        }

        struct tag_alloc_node *tag_alloc_node;
        int64_t tag;
        tag_alloc_node = tag_alloc_get_node(tag_alloc_table,
                                            nbsp->parent_name);
        tag = bitmap_scan(tag_alloc_node->allocated_tags, 0, 1, MAX_OVN_TAGS);
        if (tag == MAX_OVN_TAGS) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_ERR_RL(&rl, "out of vlans for logical switch ports with "
                        "parent %s", nbsp->parent_name);
            return;
        }
        bitmap_set1(tag_alloc_node->allocated_tags, tag);
        nbrec_logical_switch_port_set_tag(nbsp, &tag, 1);
    } else if (*nbsp->tag_request != 0) {
        /* For everything else, copy the contents of 'tag_request' to 'tag'. */
        nbrec_logical_switch_port_set_tag(nbsp, nbsp->tag_request, 1);
    }
}


static void
join_logical_ports(struct northd_input *input_data,
                   struct hmap *datapaths, struct hmap *ports,
                   struct hmap *chassis_qdisc_queues,
                   struct hmap *tag_alloc_table, struct ovs_list *sb_only,
                   struct ovs_list *nb_only, struct ovs_list *both)
{
    ovs_list_init(sb_only);
    ovs_list_init(nb_only);
    ovs_list_init(both);

    const struct sbrec_port_binding *sb;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (sb,
                                 input_data->sbrec_port_binding_table) {
        struct ovn_port *op = ovn_port_create(ports, sb->logical_port,
                                              NULL, NULL, sb);
        ovs_list_push_back(sb_only, &op->list);
    }

    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (od->nbs) {
            size_t n_allocated_localnet_ports = 0;
            for (size_t i = 0; i < od->nbs->n_ports; i++) {
                const struct nbrec_logical_switch_port *nbsp
                    = od->nbs->ports[i];
                struct ovn_port *op = ovn_port_find_bound(ports, nbsp->name);
                if (op && (op->od || op->nbsp || op->nbrp)) {
                    static struct vlog_rate_limit rl
                        = VLOG_RATE_LIMIT_INIT(5, 1);
                    VLOG_WARN_RL(&rl, "duplicate logical port %s", nbsp->name);
                    continue;
                } else if (op && (!op->sb || op->sb->datapath == od->sb)) {
                    /*
                     * Handle cases where lport type was explicitly changed
                     * in the NBDB, in such cases:
                     * 1. remove the current sbrec of the affected lport from
                     *    the port_binding table.
                     *
                     * 2. create a new sbrec with the same logical_port as the
                     *    deleted lport and add it to the nb_only list which
                     *    will make the northd handle this lport as a new
                     *    created one and recompute everything that is needed
                     *    for this lport.
                     *
                     * This change will affect container/virtual lport type
                     * changes only for now, this change is needed in
                     * contaier/virtual lport cases to avoid port type
                     * conflicts in the ovn-controller when the user clears
                     * the parent_port field in the container lport or updated
                     * the lport type.
                     *
                     */
                    bool update_sbrec = false;
                    if (op->sb && lsp_is_type_changed(op->sb, nbsp,
                                                      &update_sbrec)
                                   && update_sbrec) {
                        ovs_list_remove(&op->list);
                        sbrec_port_binding_delete(op->sb);
                        ovn_port_destroy(ports, op);
                        op = ovn_port_create(ports, nbsp->name, nbsp,
                                             NULL, NULL);
                        ovs_list_push_back(nb_only, &op->list);
                    } else {
                        ovn_port_set_nb(op, nbsp, NULL);
                        ovs_list_remove(&op->list);

                        uint32_t queue_id = smap_get_int(&op->sb->options,
                                                         "qdisc_queue_id", 0);
                        if (queue_id && op->sb->chassis) {
                            add_chassis_queue(
                                 chassis_qdisc_queues,
                                 &op->sb->chassis->header_.uuid,
                                 queue_id);
                        }

                        ovs_list_push_back(both, &op->list);

                        /* This port exists due to a SB binding, but should
                         * not have been initialized fully. */
                        ovs_assert(!op->n_lsp_addrs && !op->n_ps_addrs);
                    }
                } else {
                    op = ovn_port_create(ports, nbsp->name, nbsp, NULL, NULL);
                    ovs_list_push_back(nb_only, &op->list);
                }

                if (lsp_is_localnet(nbsp)) {
                   if (od->n_localnet_ports >= n_allocated_localnet_ports) {
                       od->localnet_ports = x2nrealloc(
                           od->localnet_ports, &n_allocated_localnet_ports,
                           sizeof *od->localnet_ports);
                   }
                   od->localnet_ports[od->n_localnet_ports++] = op;
                }

                if (lsp_is_vtep(nbsp)) {
                    od->has_vtep_lports = true;
                }

                op->lsp_addrs
                    = xmalloc(sizeof *op->lsp_addrs * nbsp->n_addresses);
                for (size_t j = 0; j < nbsp->n_addresses; j++) {
                    if (!strcmp(nbsp->addresses[j], "unknown")) {
                        op->has_unknown = true;
                        continue;
                    }
                    if (!strcmp(nbsp->addresses[j], "router")) {
                        continue;
                    }
                    if (is_dynamic_lsp_address(nbsp->addresses[j])) {
                        continue;
                    } else if (!extract_lsp_addresses(nbsp->addresses[j],
                                           &op->lsp_addrs[op->n_lsp_addrs])) {
                        static struct vlog_rate_limit rl
                            = VLOG_RATE_LIMIT_INIT(1, 1);
                        VLOG_INFO_RL(&rl, "invalid syntax '%s' in logical "
                                          "switch port addresses. No MAC "
                                          "address found",
                                          op->nbsp->addresses[j]);
                        continue;
                    }
                    op->n_lsp_addrs++;
                }

                op->ps_addrs
                    = xmalloc(sizeof *op->ps_addrs * nbsp->n_port_security);
                for (size_t j = 0; j < nbsp->n_port_security; j++) {
                    if (!extract_lsp_addresses(nbsp->port_security[j],
                                               &op->ps_addrs[op->n_ps_addrs])) {
                        static struct vlog_rate_limit rl
                            = VLOG_RATE_LIMIT_INIT(1, 1);
                        VLOG_INFO_RL(&rl, "invalid syntax '%s' in port "
                                          "security. No MAC address found",
                                          op->nbsp->port_security[j]);
                        continue;
                    }
                    op->n_ps_addrs++;
                }

                op->od = od;
                ovs_list_push_back(&od->port_list, &op->dp_node);
                tag_alloc_add_existing_tags(tag_alloc_table, nbsp);
            }
        } else {
            size_t n_allocated_l3dgw_ports = 0;
            for (size_t i = 0; i < od->nbr->n_ports; i++) {
                const struct nbrec_logical_router_port *nbrp
                    = od->nbr->ports[i];

                struct lport_addresses lrp_networks;
                if (!extract_lrp_networks(nbrp, &lrp_networks)) {
                    static struct vlog_rate_limit rl
                        = VLOG_RATE_LIMIT_INIT(5, 1);
                    VLOG_WARN_RL(&rl, "bad 'mac' %s", nbrp->mac);
                    continue;
                }

                if (!lrp_networks.n_ipv4_addrs && !lrp_networks.n_ipv6_addrs) {
                    continue;
                }

                struct ovn_port *op = ovn_port_find_bound(ports, nbrp->name);
                if (op && (op->od || op->nbsp || op->nbrp)) {
                    static struct vlog_rate_limit rl
                        = VLOG_RATE_LIMIT_INIT(5, 1);
                    VLOG_WARN_RL(&rl, "duplicate logical router port %s",
                                 nbrp->name);
                    destroy_lport_addresses(&lrp_networks);
                    continue;
                } else if (op && (!op->sb || op->sb->datapath == od->sb)) {
                    ovn_port_set_nb(op, NULL, nbrp);
                    ovs_list_remove(&op->list);
                    ovs_list_push_back(both, &op->list);

                    /* This port exists but should not have been
                     * initialized fully. */
                    ovs_assert(!op->lrp_networks.n_ipv4_addrs
                               && !op->lrp_networks.n_ipv6_addrs);
                } else {
                    op = ovn_port_create(ports, nbrp->name, NULL, nbrp, NULL);
                    ovs_list_push_back(nb_only, &op->list);
                }

                op->lrp_networks = lrp_networks;
                op->od = od;
                ovs_list_push_back(&od->port_list, &op->dp_node);

                if (!od->redirect_bridged) {
                    const char *redirect_type =
                        smap_get(&nbrp->options, "redirect-type");
                    od->redirect_bridged =
                        redirect_type && !strcasecmp(redirect_type, "bridged");
                }

                if (op->nbrp->ha_chassis_group ||
                    op->nbrp->n_gateway_chassis) {
                    /* Additional "derived" ovn_port crp represents the
                     * instance of op on the gateway chassis. */
                    const char *gw_chassis = smap_get(&op->od->nbr->options,
                                                   "chassis");
                    if (gw_chassis) {
                        static struct vlog_rate_limit rl
                            = VLOG_RATE_LIMIT_INIT(1, 1);
                        VLOG_WARN_RL(&rl, "Bad configuration: distributed "
                                     "gateway port configured on port %s "
                                     "on L3 gateway router", nbrp->name);
                        continue;
                    }

                    char *redirect_name =
                        ovn_chassis_redirect_name(nbrp->name);
                    struct ovn_port *crp = ovn_port_find(ports, redirect_name);
                    if (crp && crp->sb && crp->sb->datapath == od->sb) {
                        ovn_port_set_nb(crp, NULL, nbrp);
                        ovs_list_remove(&crp->list);
                        ovs_list_push_back(both, &crp->list);
                    } else {
                        crp = ovn_port_create(ports, redirect_name,
                                              NULL, nbrp, NULL);
                        ovs_list_push_back(nb_only, &crp->list);
                    }
                    crp->l3dgw_port = op;
                    op->cr_port = crp;
                    crp->od = od;
                    free(redirect_name);

                    /* Add to l3dgw_ports in od, for later use during flow
                     * creation. */
                    if (od->n_l3dgw_ports == n_allocated_l3dgw_ports) {
                        od->l3dgw_ports = x2nrealloc(od->l3dgw_ports,
                                                     &n_allocated_l3dgw_ports,
                                                     sizeof *od->l3dgw_ports);
                    }
                    od->l3dgw_ports[od->n_l3dgw_ports++] = op;

                    assign_routable_addresses(op);
                }
            }
        }
    }

    /* Connect logical router ports, and logical switch ports of type "router",
     * to their peers. */
    struct ovn_port *op;
    HMAP_FOR_EACH (op, key_node, ports) {
        if (op->nbsp && lsp_is_router(op->nbsp) && !op->l3dgw_port) {
            struct ovn_port *peer = ovn_port_get_peer(ports, op);
            if (!peer || !peer->nbrp) {
                continue;
            }

            ovn_datapath_add_router_port(op->od, op);
            ovn_datapath_add_ls_peer(peer->od, op->od);
            peer->peer = op;
            op->peer = peer;

            /* Fill op->lsp_addrs for op->nbsp->addresses[] with
             * contents "router", which was skipped in the loop above. */
            for (size_t j = 0; j < op->nbsp->n_addresses; j++) {
                if (!strcmp(op->nbsp->addresses[j], "router")) {
                    if (extract_lrp_networks(peer->nbrp,
                                            &op->lsp_addrs[op->n_lsp_addrs])) {
                        op->n_lsp_addrs++;
                    }
                    break;
                }
            }

            /* If the router is multicast enabled then set relay on the switch
             * datapath.
             */
            if (peer->od && peer->od->mcast_info.rtr.relay) {
                op->od->mcast_info.sw.flood_relay = true;
            }
        } else if (op->nbrp && op->nbrp->peer && !op->l3dgw_port) {
            struct ovn_port *peer = ovn_port_find(ports, op->nbrp->peer);
            if (peer) {
                if (peer->nbrp) {
                    op->peer = peer;
                } else if (peer->nbsp) {
                    /* An ovn_port for a switch port of type "router" does have
                     * a router port as its peer (see the case above for
                     * "router" ports), but this is set via options:router-port
                     * in Logical_Switch_Port and does not involve the
                     * Logical_Router_Port's 'peer' column. */
                    static struct vlog_rate_limit rl =
                            VLOG_RATE_LIMIT_INIT(5, 1);
                    VLOG_WARN_RL(&rl, "Bad configuration: The peer of router "
                                 "port %s is a switch port", op->key);
                }
            }
        }
    }

    /* Wait until all ports have been connected to add to IPAM since
     * it relies on proper peers to be set
     */
    HMAP_FOR_EACH (op, key_node, ports) {
        ipam_add_port_addresses(op->od, op);
    }
}

/* Returns an array of strings, each consisting of a MAC address followed
 * by one or more IP addresses, and if the port is a distributed gateway
 * port, followed by 'is_chassis_resident("LPORT_NAME")', where the
 * LPORT_NAME is the name of the L3 redirect port or the name of the
 * logical_port specified in a NAT rule. These strings include the
 * external IP addresses of NAT rules defined on that router whose
 * gateway_port is router port 'op', and all of the IP addresses used in
 * load balancer VIPs defined on that router.
 *
 * The caller must free each of the n returned strings with free(),
 * and must free the returned array when it is no longer needed. */
static char **
get_nat_addresses(const struct ovn_port *op, size_t *n, bool routable_only,
                  bool include_lb_ips)
{
    size_t n_nats = 0;
    struct eth_addr mac;
    if (!op || !op->nbrp || !op->od || !op->od->nbr
        || (!op->od->nbr->n_nat && !op->od->has_lb_vip)
        || !eth_addr_from_string(op->nbrp->mac, &mac)) {
        *n = n_nats;
        return NULL;
    }

    struct ds c_addresses = DS_EMPTY_INITIALIZER;
    ds_put_format(&c_addresses, ETH_ADDR_FMT, ETH_ADDR_ARGS(mac));
    bool central_ip_address = false;

    char **addresses;
    addresses = xmalloc(sizeof *addresses * (op->od->nbr->n_nat + 1));

    /* Get NAT IP addresses. */
    for (size_t i = 0; i < op->od->nbr->n_nat; i++) {
        const struct nbrec_nat *nat = op->od->nbr->nat[i];
        ovs_be32 ip, mask;

        if (routable_only &&
            (!strcmp(nat->type, "snat") ||
             !smap_get_bool(&nat->options, "add_route", false))) {
            continue;
        }

        char *error = ip_parse_masked(nat->external_ip, &ip, &mask);
        if (error || mask != OVS_BE32_MAX) {
            free(error);
            continue;
        }

        /* Not including external IP of NAT rules whose gateway_port is
         * not 'op'. */
        if (!is_nat_gateway_port(nat, op)) {
            continue;
        }

        /* Determine whether this NAT rule satisfies the conditions for
         * distributed NAT processing. */
        if (op->od->n_l3dgw_ports && !strcmp(nat->type, "dnat_and_snat")
            && nat->logical_port && nat->external_mac) {
            /* Distributed NAT rule. */
            if (eth_addr_from_string(nat->external_mac, &mac)) {
                struct ds address = DS_EMPTY_INITIALIZER;
                ds_put_format(&address, ETH_ADDR_FMT, ETH_ADDR_ARGS(mac));
                ds_put_format(&address, " %s", nat->external_ip);
                ds_put_format(&address, " is_chassis_resident(\"%s\")",
                              nat->logical_port);
                addresses[n_nats++] = ds_steal_cstr(&address);
            }
        } else {
            /* Centralized NAT rule, either on gateway router or distributed
             * router.
             * Check if external_ip is same as router ip. If so, then there
             * is no need to add this to the nat_addresses. The router IPs
             * will be added separately. */
            bool is_router_ip = false;
            for (size_t j = 0; j < op->lrp_networks.n_ipv4_addrs; j++) {
                if (!strcmp(nat->external_ip,
                            op->lrp_networks.ipv4_addrs[j].addr_s)) {
                    is_router_ip = true;
                    break;
                }
            }
            if (!is_router_ip) {
                for (size_t j = 0; j < op->lrp_networks.n_ipv6_addrs; j++) {
                    if (!strcmp(nat->external_ip,
                                op->lrp_networks.ipv6_addrs[j].addr_s)) {
                        is_router_ip = true;
                        break;
                    }
                }
            }

            if (!is_router_ip) {
                ds_put_format(&c_addresses, " %s", nat->external_ip);
                central_ip_address = true;
            }
        }
    }

    if (include_lb_ips) {
        const char *ip_address;
        if (routable_only) {
            SSET_FOR_EACH (ip_address, &op->od->lb_ips->ips_v4_routable) {
                ds_put_format(&c_addresses, " %s", ip_address);
                central_ip_address = true;
            }
            SSET_FOR_EACH (ip_address, &op->od->lb_ips->ips_v6_routable) {
                ds_put_format(&c_addresses, " %s", ip_address);
                central_ip_address = true;
            }
        } else {
            SSET_FOR_EACH (ip_address, &op->od->lb_ips->ips_v4) {
                ds_put_format(&c_addresses, " %s", ip_address);
                central_ip_address = true;
            }
            SSET_FOR_EACH (ip_address, &op->od->lb_ips->ips_v6) {
                ds_put_format(&c_addresses, " %s", ip_address);
                central_ip_address = true;
            }
        }
    }

    if (central_ip_address) {
        /* Gratuitous ARP for centralized NAT rules on distributed gateway
         * ports should be restricted to the gateway chassis. */
        if (is_l3dgw_port(op)) {
            ds_put_format(&c_addresses, " is_chassis_resident(%s)",
                          op->cr_port->json_key);
        }

        addresses[n_nats++] = ds_steal_cstr(&c_addresses);
    }

    *n = n_nats;
    ds_destroy(&c_addresses);

    return addresses;
}

static bool
sbpb_gw_chassis_needs_update(
    const struct sbrec_port_binding *pb,
    const struct nbrec_logical_router_port *lrp,
    struct ovsdb_idl_index *sbrec_chassis_by_name)
{
    if (!lrp || !pb) {
        return false;
    }

    if (lrp->n_gateway_chassis && !pb->ha_chassis_group) {
        /* If there are gateway chassis in the NB DB, but there is
         * no corresponding HA chassis group in SB DB we need to
         * create the HA chassis group in SB DB for this lrp. */
        return true;
    }

    if (strcmp(pb->ha_chassis_group->name, lrp->name)) {
        /* Name doesn't match. */
        return true;
    }

    if (lrp->n_gateway_chassis != pb->ha_chassis_group->n_ha_chassis) {
        return true;
    }

    for (size_t i = 0; i < lrp->n_gateway_chassis; i++) {
        struct nbrec_gateway_chassis *nbgw_ch = lrp->gateway_chassis[i];
        bool found = false;
        for (size_t j = 0; j < pb->ha_chassis_group->n_ha_chassis; j++) {
            struct sbrec_ha_chassis *sbha_ch =
                pb->ha_chassis_group->ha_chassis[j];
            const char *chassis_name = smap_get(&sbha_ch->external_ids,
                                                "chassis-name");
            if (!chassis_name) {
                return true;
            }

            if (strcmp(chassis_name, nbgw_ch->chassis_name)) {
                continue;
            }

            found = true;

            if (nbgw_ch->priority != sbha_ch->priority) {
                return true;
            }

            if (sbha_ch->chassis &&
                strcmp(nbgw_ch->chassis_name, sbha_ch->chassis->name)) {
                /* sbha_ch->chassis's name is different from the one
                 * in sbha_ch->external_ids:chassis-name. */
                return true;
            }

            if (!sbha_ch->chassis &&
                chassis_lookup_by_name(sbrec_chassis_by_name,
                                       nbgw_ch->chassis_name)) {
                /* sbha_ch->chassis is NULL, but the chassis is
                 * present in Chassis table. */
                return true;
            }
        }

        if (!found) {
            return true;
        }
    }

    /* No need to update SB DB. Its in sync. */
    return false;
}

static struct sbrec_ha_chassis *
create_sb_ha_chassis(struct ovsdb_idl_txn *ovnsb_txn,
                     const struct sbrec_chassis *chassis,
                     const char *chassis_name, int priority)
{
    struct sbrec_ha_chassis *sb_ha_chassis =
        sbrec_ha_chassis_insert(ovnsb_txn);
    sbrec_ha_chassis_set_chassis(sb_ha_chassis, chassis);
    sbrec_ha_chassis_set_priority(sb_ha_chassis, priority);
    /* Store the chassis_name in external_ids. If the chassis
     * entry doesn't exist in the Chassis table then we can
     * figure out the chassis to which this ha_chassis
     * maps to. */
    const struct smap external_ids =
        SMAP_CONST1(&external_ids, "chassis-name", chassis_name);
    sbrec_ha_chassis_set_external_ids(sb_ha_chassis, &external_ids);
    return sb_ha_chassis;
}

static bool
chassis_group_list_changed(
    const struct nbrec_ha_chassis_group *nb_ha_grp,
    const struct sbrec_ha_chassis_group *sb_ha_grp,
    struct ovsdb_idl_index *sbrec_chassis_by_name)
{
    if (nb_ha_grp->n_ha_chassis != sb_ha_grp->n_ha_chassis) {
        return true;
    }

    struct shash nb_ha_chassis_list = SHASH_INITIALIZER(&nb_ha_chassis_list);
    for (size_t i = 0; i < nb_ha_grp->n_ha_chassis; i++) {
        shash_add(&nb_ha_chassis_list,
                  nb_ha_grp->ha_chassis[i]->chassis_name,
                  nb_ha_grp->ha_chassis[i]);
    }

    bool changed = false;
    const struct sbrec_ha_chassis *sb_ha_chassis;
    const struct nbrec_ha_chassis *nb_ha_chassis;
    for (size_t i = 0; i < sb_ha_grp->n_ha_chassis; i++) {
        sb_ha_chassis = sb_ha_grp->ha_chassis[i];
        const char *chassis_name = smap_get(&sb_ha_chassis->external_ids,
                                            "chassis-name");

        if (!chassis_name) {
            changed = true;
            break;
        }

        nb_ha_chassis = shash_find_and_delete(&nb_ha_chassis_list,
                                              chassis_name);
        if (!nb_ha_chassis ||
            nb_ha_chassis->priority != sb_ha_chassis->priority) {
            changed = true;
            break;
        }

        if (sb_ha_chassis->chassis &&
            strcmp(sb_ha_chassis->chassis->name, chassis_name)) {
            /* sb_ha_chassis->chassis's name is different from the one
             * in sb_ha_chassis->external_ids:chassis-name. */
            changed = true;
            break;
        }

        if (!sb_ha_chassis->chassis &&
            chassis_lookup_by_name(sbrec_chassis_by_name,
                                   chassis_name)) {
            /* sb_ha_chassis->chassis is NULL, but the chassis is
             * present in Chassis table. */
            changed = true;
            break;
        }
    }

    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &nb_ha_chassis_list) {
        shash_delete(&nb_ha_chassis_list, node);
        changed = true;
    }
    shash_destroy(&nb_ha_chassis_list);

    return changed;
}

static void
sync_ha_chassis_group_for_sbpb(struct northd_input *input_data,
                               struct ovsdb_idl_txn *ovnsb_txn,
                               const struct nbrec_ha_chassis_group *nb_ha_grp,
                               struct ovsdb_idl_index *sbrec_chassis_by_name,
                               const struct sbrec_port_binding *pb)
{
    bool new_sb_chassis_group = false;
    const struct sbrec_ha_chassis_group *sb_ha_grp =
        ha_chassis_group_lookup_by_name(
            input_data->sbrec_ha_chassis_grp_by_name, nb_ha_grp->name);

    if (!sb_ha_grp) {
        sb_ha_grp = sbrec_ha_chassis_group_insert(ovnsb_txn);
        sbrec_ha_chassis_group_set_name(sb_ha_grp, nb_ha_grp->name);
        new_sb_chassis_group = true;
    }

    if (new_sb_chassis_group ||
        chassis_group_list_changed(nb_ha_grp, sb_ha_grp,
                                   sbrec_chassis_by_name)) {
        struct sbrec_ha_chassis **sb_ha_chassis = NULL;
        size_t n_ha_chassis = nb_ha_grp->n_ha_chassis;
        sb_ha_chassis = xcalloc(n_ha_chassis, sizeof *sb_ha_chassis);
        for (size_t i = 0; i < nb_ha_grp->n_ha_chassis; i++) {
            const struct nbrec_ha_chassis *nb_ha_chassis
                = nb_ha_grp->ha_chassis[i];
            const struct sbrec_chassis *chassis =
                chassis_lookup_by_name(sbrec_chassis_by_name,
                                       nb_ha_chassis->chassis_name);
            sb_ha_chassis[i] = sbrec_ha_chassis_insert(ovnsb_txn);
            /* It's perfectly ok if the chassis is NULL. This could
             * happen when ovn-controller exits and removes its row
             * from the chassis table in OVN SB DB. */
            sbrec_ha_chassis_set_chassis(sb_ha_chassis[i], chassis);
            sbrec_ha_chassis_set_priority(sb_ha_chassis[i],
                                          nb_ha_chassis->priority);
            const struct smap external_ids =
                SMAP_CONST1(&external_ids, "chassis-name",
                            nb_ha_chassis->chassis_name);
            sbrec_ha_chassis_set_external_ids(sb_ha_chassis[i], &external_ids);
        }
        sbrec_ha_chassis_group_set_ha_chassis(sb_ha_grp, sb_ha_chassis,
                                              n_ha_chassis);
        free(sb_ha_chassis);
    }

    sbrec_port_binding_set_ha_chassis_group(pb, sb_ha_grp);
}

/* This functions translates the gw chassis on the nb database
 * to HA chassis group in the sb database entries.
 */
static void
copy_gw_chassis_from_nbrp_to_sbpb(
        struct northd_input *input_data,
        struct ovsdb_idl_txn *ovnsb_txn,
        struct ovsdb_idl_index *sbrec_chassis_by_name,
        const struct nbrec_logical_router_port *lrp,
        const struct sbrec_port_binding *port_binding)
{

    /* Make use of the new HA chassis group table to support HA
     * for the distributed gateway router port. */
    const struct sbrec_ha_chassis_group *sb_ha_chassis_group =
        ha_chassis_group_lookup_by_name(
            input_data->sbrec_ha_chassis_grp_by_name, lrp->name);
    if (!sb_ha_chassis_group) {
        sb_ha_chassis_group = sbrec_ha_chassis_group_insert(ovnsb_txn);
        sbrec_ha_chassis_group_set_name(sb_ha_chassis_group, lrp->name);
    }

    struct sbrec_ha_chassis **sb_ha_chassis = xcalloc(lrp->n_gateway_chassis,
                                                      sizeof *sb_ha_chassis);
    size_t n_sb_ha_ch = 0;
    for (size_t n = 0; n < lrp->n_gateway_chassis; n++) {
        struct nbrec_gateway_chassis *lrp_gwc = lrp->gateway_chassis[n];
        if (!lrp_gwc->chassis_name) {
            continue;
        }

        const struct sbrec_chassis *chassis =
            chassis_lookup_by_name(sbrec_chassis_by_name,
                                   lrp_gwc->chassis_name);

        sb_ha_chassis[n_sb_ha_ch] =
            create_sb_ha_chassis(ovnsb_txn, chassis, lrp_gwc->chassis_name,
                                 lrp_gwc->priority);
        n_sb_ha_ch++;
    }

    sbrec_ha_chassis_group_set_ha_chassis(sb_ha_chassis_group,
                                          sb_ha_chassis, n_sb_ha_ch);
    sbrec_port_binding_set_ha_chassis_group(port_binding, sb_ha_chassis_group);
    free(sb_ha_chassis);
}

static const char*
op_get_name(const struct ovn_port *op)
{
    ovs_assert(op->nbsp || op->nbrp);
    const char *name = op->nbsp ? op->nbsp->name
                                : op->nbrp->name;
    return name;
}

static void
ovn_update_ipv6_prefix(struct hmap *ports)
{
    const struct ovn_port *op;
    HMAP_FOR_EACH (op, key_node, ports) {
        if (!op->nbrp) {
            continue;
        }

        if (!smap_get_bool(&op->nbrp->options, "prefix", false)) {
            continue;
        }

        char prefix[IPV6_SCAN_LEN + 6];
        unsigned aid;
        const char *ipv6_pd_list = smap_get(&op->sb->options,
                                            "ipv6_ra_pd_list");
        if (!ipv6_pd_list ||
            !ovs_scan(ipv6_pd_list, "%u:%s", &aid, prefix)) {
            continue;
        }

        const char *prefix_ptr = prefix;
        nbrec_logical_router_port_set_ipv6_prefix(op->nbrp, &prefix_ptr, 1);
    }
}

static const struct sbrec_chassis *
chassis_lookup(struct ovsdb_idl_index *sbrec_chassis_by_name,
               struct ovsdb_idl_index *sbrec_chassis_by_hostname,
               const char *name_or_hostname)
{
    const struct sbrec_chassis *chassis; /* May be NULL. */
    chassis = chassis_lookup_by_name(sbrec_chassis_by_name,
                                     name_or_hostname);
    return chassis ? chassis : chassis_lookup_by_hostname(
                    sbrec_chassis_by_hostname, name_or_hostname);
}

static void
ovn_port_update_sbrec_chassis(
        struct ovsdb_idl_index *sbrec_chassis_by_name,
        struct ovsdb_idl_index *sbrec_chassis_by_hostname,
        const struct ovn_port *op)
{
    const char *requested_chassis; /* May be NULL. */

    size_t n_requested_chassis = 0;
    struct sbrec_chassis **requested_chassis_sb = xcalloc(
        n_requested_chassis, sizeof *requested_chassis_sb);

    requested_chassis = smap_get(&op->nbsp->options,
                                 "requested-chassis");
    if (requested_chassis) {
        char *tokstr = xstrdup(requested_chassis);
        char *save_ptr = NULL;
        char *chassis;
        for (chassis = strtok_r(tokstr, ",", &save_ptr); chassis != NULL;
             chassis = strtok_r(NULL, ",", &save_ptr)) {
            const struct sbrec_chassis *chassis_sb = chassis_lookup(
                sbrec_chassis_by_name, sbrec_chassis_by_hostname, chassis);
            if (chassis_sb) {
                requested_chassis_sb = xrealloc(
                    requested_chassis_sb,
                    ++n_requested_chassis * (sizeof *requested_chassis_sb));
                requested_chassis_sb[n_requested_chassis - 1] = (
                    (struct sbrec_chassis *) chassis_sb);
            } else {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(
                    1, 1);
                VLOG_WARN_RL(
                    &rl,
                    "Unknown chassis '%s' set in "
                    "options:requested-chassis on LSP '%s'.",
                    chassis, op->nbsp->name);
            }
        }
        free(tokstr);
    }

    if (n_requested_chassis > 0) {
        sbrec_port_binding_set_requested_chassis(op->sb,
                                                 *requested_chassis_sb);
    } else {
        sbrec_port_binding_set_requested_chassis(op->sb, NULL);
    }
    if (n_requested_chassis > 1) {
        sbrec_port_binding_set_requested_additional_chassis(
            op->sb, &requested_chassis_sb[1], n_requested_chassis - 1);
    } else {
        sbrec_port_binding_set_requested_additional_chassis(op->sb, NULL, 0);
    }
    free(requested_chassis_sb);
}

static void
check_and_do_sb_mirror_deletion(const struct ovn_port *op)
{
    size_t i = 0;
    struct shash nb_mirror_rules = SHASH_INITIALIZER(&nb_mirror_rules);

    for (i = 0; i < op->nbsp->n_mirror_rules; i++) {
        shash_add(&nb_mirror_rules,
                  op->nbsp->mirror_rules[i]->name,
                  op->nbsp->mirror_rules[i]);
    }

    for (i = 0; i < op->sb->n_mirror_rules; i++) {
        if (!shash_find(&nb_mirror_rules,
                        op->sb->mirror_rules[i]->name)) {
            /* Delete from SB since its not present in NB*/
            sbrec_port_binding_update_mirror_rules_delvalue(op->sb,
                                             op->sb->mirror_rules[i]);
        }
    }

    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, &nb_mirror_rules) {
        shash_delete(&nb_mirror_rules, node);
    }
    shash_destroy(&nb_mirror_rules);
}

static void
check_and_do_sb_mirror_addition(struct northd_input *input_data,
                                const struct ovn_port *op)
{
    for (size_t i = 0; i < op->nbsp->n_mirror_rules; i++) {
        const struct sbrec_mirror *sb_mirror;
        SBREC_MIRROR_TABLE_FOR_EACH (sb_mirror,
                                     input_data->sbrec_mirror_table) {
            if (!strcmp(sb_mirror->name,
                        op->nbsp->mirror_rules[i]->name)) {
                /* Add the value to SB */
                sbrec_port_binding_update_mirror_rules_addvalue(op->sb,
                                                                sb_mirror);
            }
        }
    }
}

static void
sbrec_port_binding_update_mirror_rules(struct northd_input *input_data,
                                       const struct ovn_port *op)
{
    check_and_do_sb_mirror_deletion(op);
    check_and_do_sb_mirror_addition(input_data, op);
}

static void
ovn_port_update_sbrec(struct northd_input *input_data,
                      struct ovsdb_idl_txn *ovnsb_txn,
                      struct ovsdb_idl_index *sbrec_chassis_by_name,
                      struct ovsdb_idl_index *sbrec_chassis_by_hostname,
                      const struct ovn_port *op,
                      struct hmap *chassis_qdisc_queues,
                      struct sset *active_ha_chassis_grps)
{
    sbrec_port_binding_set_datapath(op->sb, op->od->sb);
    if (op->nbrp) {
        /* If the router is for l3 gateway, it resides on a chassis
         * and its port type is "l3gateway". */
        const char *chassis_name = smap_get(&op->od->nbr->options, "chassis");
        if (is_cr_port(op)) {
            sbrec_port_binding_set_type(op->sb, "chassisredirect");
        } else if (chassis_name) {
            sbrec_port_binding_set_type(op->sb, "l3gateway");
        } else {
            sbrec_port_binding_set_type(op->sb, "patch");
        }

        struct smap new;
        smap_init(&new);
        if (is_cr_port(op)) {
            const char *redirect_type = smap_get(&op->nbrp->options,
                                                 "redirect-type");

            if (op->nbrp->ha_chassis_group) {
                if (op->nbrp->n_gateway_chassis) {
                    static struct vlog_rate_limit rl
                        = VLOG_RATE_LIMIT_INIT(1, 1);
                    VLOG_WARN_RL(&rl, "Both ha_chassis_group and "
                                 "gateway_chassis configured on port %s; "
                                 "ignoring the latter.", op->nbrp->name);
                }

                /* HA Chassis group is set. Ignore 'gateway_chassis'. */
                sync_ha_chassis_group_for_sbpb(input_data, ovnsb_txn,
                                               op->nbrp->ha_chassis_group,
                                               sbrec_chassis_by_name, op->sb);
                sset_add(active_ha_chassis_grps,
                         op->nbrp->ha_chassis_group->name);
            } else if (op->nbrp->n_gateway_chassis) {
                /* Legacy gateway_chassis support.
                 * Create ha_chassis_group for the Northbound gateway_chassis
                 * associated with the lrp. */
                if (sbpb_gw_chassis_needs_update(op->sb, op->nbrp,
                                                 sbrec_chassis_by_name)) {
                    copy_gw_chassis_from_nbrp_to_sbpb(input_data,
                                                      ovnsb_txn,
                                                      sbrec_chassis_by_name,
                                                      op->nbrp, op->sb);
                }

                sset_add(active_ha_chassis_grps, op->nbrp->name);
            } else {
                /* Nothing is set. Clear ha_chassis_group  from pb. */
                if (op->sb->ha_chassis_group) {
                    sbrec_port_binding_set_ha_chassis_group(op->sb, NULL);
                }
            }

            if (op->sb->n_gateway_chassis) {
                /* Delete the legacy gateway_chassis from the pb. */
                sbrec_port_binding_set_gateway_chassis(op->sb, NULL, 0);
            }
            smap_add(&new, "distributed-port", op->nbrp->name);

            bool always_redirect = !op->od->has_distributed_nat;
            if (redirect_type) {
                smap_add(&new, "redirect-type", redirect_type);
                /* XXX Why can't we enable always-redirect when redirect-type
                 * is bridged? */
                if (!strcmp(redirect_type, "bridged")) {
                    always_redirect = false;
                }
            }

            if (always_redirect) {
                smap_add(&new, "always-redirect", "true");
            }
        } else {
            if (op->peer) {
                smap_add(&new, "peer", op->peer->key);
                if (op->nbrp->ha_chassis_group ||
                    op->nbrp->n_gateway_chassis) {
                    char *redirect_name =
                        ovn_chassis_redirect_name(op->nbrp->name);
                    smap_add(&new, "chassis-redirect-port", redirect_name);
                    free(redirect_name);
                }
            }
            if (chassis_name) {
                smap_add(&new, "l3gateway-chassis", chassis_name);
            }
        }

        const char *ipv6_pd_list = smap_get(&op->sb->options,
                                            "ipv6_ra_pd_list");
        if (ipv6_pd_list) {
            smap_add(&new, "ipv6_ra_pd_list", ipv6_pd_list);
        }

        sbrec_port_binding_set_options(op->sb, &new);
        smap_destroy(&new);

        sbrec_port_binding_set_parent_port(op->sb, NULL);
        sbrec_port_binding_set_tag(op->sb, NULL, 0);

        struct ds s = DS_EMPTY_INITIALIZER;
        ds_put_cstr(&s, op->nbrp->mac);
        for (int i = 0; i < op->nbrp->n_networks; ++i) {
            ds_put_format(&s, " %s", op->nbrp->networks[i]);
        }
        const char *addresses = ds_cstr(&s);
        sbrec_port_binding_set_mac(op->sb, &addresses, 1);
        ds_destroy(&s);

        sbrec_port_binding_set_external_ids(op->sb, &op->nbrp->external_ids);

        sbrec_port_binding_set_nat_addresses(op->sb, NULL, 0);
    } else {
        if (!lsp_is_router(op->nbsp)) {
            uint32_t queue_id = smap_get_int(
                    &op->sb->options, "qdisc_queue_id", 0);
            bool has_qos = port_has_qos_params(&op->nbsp->options);
            const struct uuid *uuid = NULL;
            struct smap options;
            char *name = "";

            if (lsp_is_localnet(op->nbsp)) {
                uuid = &op->sb->header_.uuid;
                name = "localnet";
            } else if (op->sb->chassis) {
                uuid = &op->sb->chassis->header_.uuid;
                name = op->sb->chassis->name;
            }

            if (has_qos && !queue_id) {
                queue_id = allocate_chassis_queueid(chassis_qdisc_queues,
                                                    uuid, name);
            } else if (!has_qos && queue_id) {
                free_chassis_queueid(chassis_qdisc_queues, uuid, queue_id);
                queue_id = 0;
            }

            smap_clone(&options, &op->nbsp->options);
            if (queue_id) {
                smap_add_format(&options,
                                "qdisc_queue_id", "%d", queue_id);
            }

            if (smap_get_bool(&op->od->nbs->other_config, "vlan-passthru", false)) {
                smap_add(&options, "vlan-passthru", "true");
            }

            /* Retain activated chassis flags. */
            if (op->sb->requested_additional_chassis) {
                const char *activated_str = smap_get(
                    &op->sb->options, "additional-chassis-activated");
                if (activated_str) {
                    smap_add(&options, "additional-chassis-activated",
                             activated_str);
                }
            }

            sbrec_port_binding_set_options(op->sb, &options);
            smap_destroy(&options);
            if (ovn_is_known_nb_lsp_type(op->nbsp->type)) {
                sbrec_port_binding_set_type(op->sb, op->nbsp->type);
            } else {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(
                    &rl, "Unknown port type '%s' set on logical switch '%s'.",
                    op->nbsp->type, op->nbsp->name);
            }

            sbrec_port_binding_set_nat_addresses(op->sb, NULL, 0);

            if (!strcmp(op->nbsp->type, "external")) {
                if (op->nbsp->ha_chassis_group) {
                    sync_ha_chassis_group_for_sbpb(
                        input_data,
                        ovnsb_txn, op->nbsp->ha_chassis_group,
                        sbrec_chassis_by_name, op->sb);
                    sset_add(active_ha_chassis_grps,
                             op->nbsp->ha_chassis_group->name);
                } else {
                    sbrec_port_binding_set_ha_chassis_group(op->sb, NULL);
                }
            } else if (op->sb->ha_chassis_group) {
                /* Clear the port bindings ha_chassis_group if the type is
                 * not external and if this column is set.  This can happen
                 * when an external port is reset to type normal and
                 * ha_chassis_group cleared in the same transaction. */
                sbrec_port_binding_set_ha_chassis_group(op->sb, NULL);
            }

            ovn_port_update_sbrec_chassis(sbrec_chassis_by_name,
                                          sbrec_chassis_by_hostname, op);
        } else {
            const char *chassis = NULL;
            if (op->peer && op->peer->od && op->peer->od->nbr) {
                chassis = smap_get(&op->peer->od->nbr->options, "chassis");
            }

            /* A switch port connected to a gateway router is also of
             * type "l3gateway". */
            if (chassis) {
                sbrec_port_binding_set_type(op->sb, "l3gateway");
            } else {
                sbrec_port_binding_set_type(op->sb, "patch");
            }

            const char *router_port = smap_get(&op->nbsp->options,
                                               "router-port");
            if (router_port || chassis) {
                struct smap new;
                smap_init(&new);
                if (router_port) {
                    smap_add(&new, "peer", router_port);
                }
                if (chassis) {
                    smap_add(&new, "l3gateway-chassis", chassis);
                }
                sbrec_port_binding_set_options(op->sb, &new);
                smap_destroy(&new);
            } else {
                sbrec_port_binding_set_options(op->sb, NULL);
            }
            const char *nat_addresses = smap_get(&op->nbsp->options,
                                           "nat-addresses");
            size_t n_nats = 0;
            char **nats = NULL;
            bool l3dgw_ports = op->peer && op->peer->od &&
                               op->peer->od->n_l3dgw_ports;
            if (nat_addresses && !strcmp(nat_addresses, "router")) {
                if (op->peer && op->peer->od
                    && (chassis || op->peer->od->n_l3dgw_ports)) {
                    bool exclude_lb_vips = smap_get_bool(&op->nbsp->options,
                            "exclude-lb-vips-from-garp", false);
                    nats = get_nat_addresses(op->peer, &n_nats, false,
                                             !exclude_lb_vips);
                }
            } else if (nat_addresses && (chassis || l3dgw_ports)) {
                struct lport_addresses laddrs;
                if (!extract_lsp_addresses(nat_addresses, &laddrs)) {
                    static struct vlog_rate_limit rl =
                        VLOG_RATE_LIMIT_INIT(1, 1);
                    VLOG_WARN_RL(&rl, "Error extracting nat-addresses.");
                } else {
                    destroy_lport_addresses(&laddrs);
                    n_nats = 1;
                    nats = xcalloc(1, sizeof *nats);
                    struct ds nat_addr = DS_EMPTY_INITIALIZER;
                    ds_put_format(&nat_addr, "%s", nat_addresses);
                    if (l3dgw_ports) {
                        const struct ovn_port *l3dgw_port = (
                            is_l3dgw_port(op->peer)
                            ? op->peer
                            : op->peer->od->l3dgw_ports[0]);
                        ds_put_format(&nat_addr, " is_chassis_resident(%s)",
                            l3dgw_port->cr_port->json_key);
                    }
                    nats[0] = xstrdup(ds_cstr(&nat_addr));
                    ds_destroy(&nat_addr);
                }
            }

            /* Add the router mac and IPv4 addresses to
             * Port_Binding.nat_addresses so that GARP is sent for these
             * IPs by the ovn-controller on which the distributed gateway
             * router port resides if:
             *
             * -  op->peer has 'reside-on-redirect-chassis' set and the
             *    the logical router datapath has distributed router port.
             *
             * -  op->peer is distributed gateway router port.
             *
             * -  op->peer's router is a gateway router and op has a localnet
             *    port.
             *
             * Note: Port_Binding.nat_addresses column is also used for
             * sending the GARPs for the router port IPs.
             * */
            bool add_router_port_garp = false;
            if (op->peer && op->peer->nbrp && op->peer->od->n_l3dgw_ports) {
                if (is_l3dgw_port(op->peer)) {
                    add_router_port_garp = true;
                } else if (smap_get_bool(&op->peer->nbrp->options,
                               "reside-on-redirect-chassis", false)) {
                    if (op->peer->od->n_l3dgw_ports == 1) {
                        add_router_port_garp = true;
                    } else {
                        static struct vlog_rate_limit rl =
                            VLOG_RATE_LIMIT_INIT(1, 1);
                        VLOG_WARN_RL(&rl, "\"reside-on-redirect-chassis\" is "
                                     "set on logical router port %s, which "
                                     "is on logical router %s, which has %"
                                     PRIuSIZE" distributed gateway ports. This"
                                     "option can only be used when there is "
                                     "a single distributed gateway port.",
                                     op->peer->key, op->peer->od->nbr->name,
                                     op->peer->od->n_l3dgw_ports);
                    }
                }
            } else if (chassis && op->od->n_localnet_ports) {
                add_router_port_garp = true;
            }

            if (add_router_port_garp) {
                struct ds garp_info = DS_EMPTY_INITIALIZER;
                ds_put_format(&garp_info, "%s", op->peer->lrp_networks.ea_s);

                for (size_t i = 0; i < op->peer->lrp_networks.n_ipv4_addrs;
                     i++) {
                    ds_put_format(&garp_info, " %s",
                                  op->peer->lrp_networks.ipv4_addrs[i].addr_s);
                }

                if (op->peer->od->n_l3dgw_ports) {
                    const struct ovn_port *l3dgw_port = (
                        is_l3dgw_port(op->peer)
                        ? op->peer
                        : op->peer->od->l3dgw_ports[0]);
                    ds_put_format(&garp_info, " is_chassis_resident(%s)",
                                  l3dgw_port->cr_port->json_key);
                }

                n_nats++;
                nats = xrealloc(nats, (n_nats * sizeof *nats));
                nats[n_nats - 1] = ds_steal_cstr(&garp_info);
                ds_destroy(&garp_info);
            }
            sbrec_port_binding_set_nat_addresses(op->sb,
                                                 (const char **) nats, n_nats);
            for (size_t i = 0; i < n_nats; i++) {
                free(nats[i]);
            }
            free(nats);
        }

        sbrec_port_binding_set_parent_port(op->sb, op->nbsp->parent_name);
        sbrec_port_binding_set_tag(op->sb, op->nbsp->tag, op->nbsp->n_tag);
        sbrec_port_binding_set_mac(op->sb, (const char **) op->nbsp->addresses,
                                   op->nbsp->n_addresses);
        sbrec_port_binding_set_port_security(
            op->sb, (const char **) op->nbsp->port_security,
            op->nbsp->n_port_security);

        struct smap ids = SMAP_INITIALIZER(&ids);
        smap_clone(&ids, &op->nbsp->external_ids);
        const char *name = smap_get(&ids, "neutron:port_name");
        if (name && name[0]) {
            smap_add(&ids, "name", name);
        }
        sbrec_port_binding_set_external_ids(op->sb, &ids);
        smap_destroy(&ids);

        if (!op->nbsp->n_mirror_rules) {
            /* Nothing is set. Clear mirror_rules from pb. */
            sbrec_port_binding_set_mirror_rules(op->sb, NULL, 0);
        } else {
            /* Check if SB DB update needed */
            sbrec_port_binding_update_mirror_rules(input_data, op);
        }

    }
    if (op->tunnel_key != op->sb->tunnel_key) {
        sbrec_port_binding_set_tunnel_key(op->sb, op->tunnel_key);
    }

    /* ovn-controller will update 'Port_Binding.up' only if it was explicitly
     * set to 'false'.
     */
    if (!op->sb->n_up) {
        bool up = false;
        sbrec_port_binding_set_up(op->sb, &up, 1);
    }
}

/* Remove mac_binding entries that refer to logical_ports which are
 * deleted. */
static void
cleanup_mac_bindings(struct northd_input *input_data,
                     struct hmap *datapaths,
                     struct hmap *ports)
{
    const struct sbrec_mac_binding *b;
    SBREC_MAC_BINDING_TABLE_FOR_EACH_SAFE (b,
                             input_data->sbrec_mac_binding_table) {
        const struct ovn_datapath *od =
            ovn_datapath_from_sbrec(datapaths, b->datapath);

        if (!od || ovn_datapath_is_stale(od) ||
                !ovn_port_find(ports, b->logical_port)) {
            sbrec_mac_binding_delete(b);
        }
    }
}

static void
cleanup_sb_ha_chassis_groups(struct northd_input *input_data,
                             struct sset *active_ha_chassis_groups)
{
    const struct sbrec_ha_chassis_group *b;
    SBREC_HA_CHASSIS_GROUP_TABLE_FOR_EACH_SAFE (b,
                                input_data->sbrec_ha_chassis_group_table) {
        if (!sset_contains(active_ha_chassis_groups, b->name)) {
            sbrec_ha_chassis_group_delete(b);
        }
    }
}

static void
cleanup_stale_fdb_entries(struct northd_input *input_data,
                          struct hmap *datapaths)
{
    const struct sbrec_fdb *fdb_e;
    SBREC_FDB_TABLE_FOR_EACH_SAFE (fdb_e,
                         input_data->sbrec_fdb_table) {
        bool delete = true;
        struct ovn_datapath *od
            = ovn_datapath_find_by_key(datapaths, fdb_e->dp_key);
        if (od) {
            if (ovn_tnlid_present(&od->port_tnlids, fdb_e->port_key)) {
                delete = false;
            }
        }

        if (delete) {
            sbrec_fdb_delete(fdb_e);
        }
    }
}

struct service_monitor_info {
    struct hmap_node hmap_node;
    const struct sbrec_service_monitor *sbrec_mon;
    bool required;
};


static struct service_monitor_info *
create_or_get_service_mon(struct ovsdb_idl_txn *ovnsb_txn,
                          struct hmap *monitor_map,
                          const char *ip, const char *logical_port,
                          uint16_t service_port, const char *protocol)
{
    uint32_t hash = service_port;
    hash = hash_string(ip, hash);
    hash = hash_string(logical_port, hash);
    struct service_monitor_info *mon_info;

    HMAP_FOR_EACH_WITH_HASH (mon_info, hmap_node, hash, monitor_map) {
        if (mon_info->sbrec_mon->port == service_port &&
            !strcmp(mon_info->sbrec_mon->ip, ip) &&
            !strcmp(mon_info->sbrec_mon->protocol, protocol) &&
            !strcmp(mon_info->sbrec_mon->logical_port, logical_port)) {
            return mon_info;
        }
    }

    struct sbrec_service_monitor *sbrec_mon =
        sbrec_service_monitor_insert(ovnsb_txn);
    sbrec_service_monitor_set_ip(sbrec_mon, ip);
    sbrec_service_monitor_set_port(sbrec_mon, service_port);
    sbrec_service_monitor_set_logical_port(sbrec_mon, logical_port);
    sbrec_service_monitor_set_protocol(sbrec_mon, protocol);
    mon_info = xzalloc(sizeof *mon_info);
    mon_info->sbrec_mon = sbrec_mon;
    hmap_insert(monitor_map, &mon_info->hmap_node, hash);
    return mon_info;
}

static void
ovn_lb_svc_create(struct ovsdb_idl_txn *ovnsb_txn, struct ovn_northd_lb *lb,
                  struct hmap *monitor_map, struct hmap *ports)
{
    if (lb->template) {
        return;
    }

    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_lb_vip *lb_vip = &lb->vips[i];
        struct ovn_northd_lb_vip *lb_vip_nb = &lb->vips_nb[i];

        for (size_t j = 0; j < lb_vip->n_backends; j++) {
            struct ovn_lb_backend *backend = &lb_vip->backends[j];
            struct ovn_northd_lb_backend *backend_nb =
                &lb_vip_nb->backends_nb[j];

            struct ovn_port *op = NULL;
            char *svc_mon_src_ip = NULL;
            const char *s = smap_get(&lb->nlb->ip_port_mappings,
                                     backend->ip_str);
            if (s) {
                char *port_name = xstrdup(s);
                char *p = strstr(port_name, ":");
                if (p) {
                    *p = 0;
                    p++;
                    op = ovn_port_find(ports, port_name);
                    svc_mon_src_ip = xstrdup(p);
                }
                free(port_name);
            }

            backend_nb->op = op;
            backend_nb->svc_mon_src_ip = svc_mon_src_ip;

            if (!lb_vip_nb->lb_health_check || !op || !svc_mon_src_ip ||
                !lsp_is_enabled(op->nbsp)) {
                continue;
            }

            const char *protocol = lb->nlb->protocol;
            if (!protocol || !protocol[0]) {
                protocol = "tcp";
            }
            backend_nb->health_check = true;
            struct service_monitor_info *mon_info =
                create_or_get_service_mon(ovnsb_txn, monitor_map,
                                          backend->ip_str,
                                          backend_nb->op->nbsp->name,
                                          backend->port,
                                          protocol);
            ovs_assert(mon_info);
            sbrec_service_monitor_set_options(
                mon_info->sbrec_mon, &lb_vip_nb->lb_health_check->options);
            struct eth_addr ea;
            if (!mon_info->sbrec_mon->src_mac ||
                !eth_addr_from_string(mon_info->sbrec_mon->src_mac, &ea) ||
                !eth_addr_equals(ea, svc_monitor_mac_ea)) {
                sbrec_service_monitor_set_src_mac(mon_info->sbrec_mon,
                                                  svc_monitor_mac);
            }

            if (!mon_info->sbrec_mon->src_ip ||
                strcmp(mon_info->sbrec_mon->src_ip,
                       backend_nb->svc_mon_src_ip)) {
                sbrec_service_monitor_set_src_ip(
                    mon_info->sbrec_mon,
                    backend_nb->svc_mon_src_ip);
            }

            if ((!op->sb->n_up || !op->sb->up[0])
                && mon_info->sbrec_mon->status
                && !strcmp(mon_info->sbrec_mon->status, "online")) {
                sbrec_service_monitor_set_status(mon_info->sbrec_mon,
                                                 "offline");
            }

            backend_nb->sbrec_monitor = mon_info->sbrec_mon;
            mon_info->required = true;
        }
    }
}

static bool
build_lb_vip_actions(struct ovn_lb_vip *lb_vip,
                     struct ovn_northd_lb_vip *lb_vip_nb,
                     struct ds *action, char *selection_fields,
                     bool ls_dp, bool ct_lb_mark)
{
    const char *ct_lb_action = ct_lb_mark ? "ct_lb_mark" : "ct_lb";
    bool skip_hash_fields = false, reject = false;

    if (lb_vip_nb->lb_health_check) {
        ds_put_format(action, "%s(backends=", ct_lb_action);

        size_t n_active_backends = 0;
        for (size_t i = 0; i < lb_vip->n_backends; i++) {
            struct ovn_lb_backend *backend = &lb_vip->backends[i];
            struct ovn_northd_lb_backend *backend_nb =
                &lb_vip_nb->backends_nb[i];
            if (!backend_nb->health_check ||
                (backend_nb->health_check && backend_nb->sbrec_monitor &&
                 backend_nb->sbrec_monitor->status &&
                 strcmp(backend_nb->sbrec_monitor->status, "online"))) {
                continue;
            }

            n_active_backends++;
            ds_put_format(action, "%s:%"PRIu16",",
                          backend->ip_str, backend->port);
        }

        if (!n_active_backends) {
            if (!lb_vip->empty_backend_rej) {
                ds_clear(action);
                ds_put_cstr(action, debug_drop_action());
                skip_hash_fields = true;
            } else {
                reject = true;
            }
        } else {
            ds_chomp(action, ',');
            ds_put_cstr(action, ");");
        }
    } else if (lb_vip->empty_backend_rej && !lb_vip->n_backends) {
        reject = true;
    } else {
        ds_put_format(action, "%s(backends=%s);", ct_lb_action,
                      lb_vip_nb->backend_ips);
    }

    if (reject) {
        int stage = ls_dp ? ovn_stage_get_table(S_SWITCH_OUT_QOS_MARK)
                          : ovn_stage_get_table(S_ROUTER_OUT_SNAT);
        ds_clear(action);
        ds_put_format(action, "reg0 = 0; reject { outport <-> inport; "
                      "next(pipeline=egress,table=%d);};", stage);
    } else if (!skip_hash_fields && selection_fields && selection_fields[0]) {
        ds_chomp(action, ';');
        ds_chomp(action, ')');
        ds_put_format(action, "; hash_fields=\"%s\");", selection_fields);
    }
    return reject;
}

static void
build_lrouter_lb_ips(struct ovn_lb_ip_set *lb_ips,
                     const struct ovn_northd_lb *lb)
{
    const char *ip_address;

    SSET_FOR_EACH (ip_address, &lb->ips_v4) {
        sset_add(&lb_ips->ips_v4, ip_address);
        if (lb->routable) {
            sset_add(&lb_ips->ips_v4_routable, ip_address);
        }
    }
    SSET_FOR_EACH (ip_address, &lb->ips_v6) {
        sset_add(&lb_ips->ips_v6, ip_address);
        if (lb->routable) {
            sset_add(&lb_ips->ips_v6_routable, ip_address);
        }
    }
}

static void
build_lbs(struct northd_input *input_data, struct hmap *datapaths,
          struct hmap *lbs, struct hmap *lb_groups)
{
    const struct nbrec_load_balancer_group *nbrec_lb_group;
    struct ovn_lb_group *lb_group;
    struct ovn_northd_lb *lb;

    hmap_init(lbs);
    hmap_init(lb_groups);

    const struct nbrec_load_balancer *nbrec_lb;
    NBREC_LOAD_BALANCER_TABLE_FOR_EACH (nbrec_lb,
                               input_data->nbrec_load_balancer_table) {
        struct ovn_northd_lb *lb_nb = ovn_northd_lb_create(nbrec_lb);
        hmap_insert(lbs, &lb_nb->hmap_node,
                    uuid_hash(&nbrec_lb->header_.uuid));
    }

    NBREC_LOAD_BALANCER_GROUP_TABLE_FOR_EACH (nbrec_lb_group,
                               input_data->nbrec_load_balancer_group_table) {
        lb_group = ovn_lb_group_create(nbrec_lb_group, lbs,
                                       hmap_count(datapaths));

        for (size_t i = 0; i < lb_group->n_lbs; i++) {
            build_lrouter_lb_ips(lb_group->lb_ips, lb_group->lbs[i]);
        }

        hmap_insert(lb_groups, &lb_group->hmap_node,
                    uuid_hash(&lb_group->uuid));
    }

    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbs) {
            continue;
        }

        for (size_t i = 0; i < od->nbs->n_load_balancer; i++) {
            const struct uuid *lb_uuid =
                &od->nbs->load_balancer[i]->header_.uuid;
            lb = ovn_northd_lb_find(lbs, lb_uuid);
            ovn_northd_lb_add_ls(lb, 1, &od);
        }

        for (size_t i = 0; i < od->nbs->n_load_balancer_group; i++) {
            nbrec_lb_group = od->nbs->load_balancer_group[i];
            lb_group = ovn_lb_group_find(lb_groups,
                                         &nbrec_lb_group->header_.uuid);
            ovn_lb_group_add_ls(lb_group, 1, &od);
        }
    }

    HMAP_FOR_EACH (lb_group, hmap_node, lb_groups) {
        for (size_t j = 0; j < lb_group->n_lbs; j++) {
            ovn_northd_lb_add_ls(lb_group->lbs[j], lb_group->n_ls,
                                 lb_group->ls);
        }
    }

    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbr) {
            continue;
        }

        /* Checking load balancer groups first, starting from the largest one,
         * to more efficiently copy IP sets. */
        size_t largest_group = 0;

        for (size_t i = 1; i < od->nbr->n_load_balancer_group; i++) {
            if (od->nbr->load_balancer_group[i]->n_load_balancer >
                od->nbr->load_balancer_group[largest_group]->n_load_balancer) {
                largest_group = i;
            }
        }

        for (size_t i = 0; i < od->nbr->n_load_balancer_group; i++) {
            size_t idx = (i + largest_group) % od->nbr->n_load_balancer_group;

            nbrec_lb_group = od->nbr->load_balancer_group[idx];
            lb_group = ovn_lb_group_find(lb_groups,
                                         &nbrec_lb_group->header_.uuid);
            ovn_lb_group_add_lr(lb_group, od);

            if (!od->lb_ips) {
                od->lb_ips = ovn_lb_ip_set_clone(lb_group->lb_ips);
            } else {
                for (size_t j = 0; j < lb_group->n_lbs; j++) {
                    build_lrouter_lb_ips(od->lb_ips, lb_group->lbs[j]);
                }
            }
        }

        if (!od->lb_ips) {
            od->lb_ips = ovn_lb_ip_set_create();
        }

        for (size_t i = 0; i < od->nbr->n_load_balancer; i++) {
            const struct uuid *lb_uuid =
                &od->nbr->load_balancer[i]->header_.uuid;
            lb = ovn_northd_lb_find(lbs, lb_uuid);
            ovn_northd_lb_add_lr(lb, 1, &od);
            build_lrouter_lb_ips(od->lb_ips, lb);
        }
    }

    HMAP_FOR_EACH (lb_group, hmap_node, lb_groups) {
        for (size_t j = 0; j < lb_group->n_lbs; j++) {
            ovn_northd_lb_add_lr(lb_group->lbs[j], lb_group->n_lr,
                                 lb_group->lr);
        }
    }
}

static void
build_lb_svcs(struct northd_input *input_data,
              struct ovsdb_idl_txn *ovnsb_txn,
              struct hmap *ports,
              struct hmap *lbs)
{
    struct hmap monitor_map = HMAP_INITIALIZER(&monitor_map);

    const struct sbrec_service_monitor *sbrec_mon;
    SBREC_SERVICE_MONITOR_TABLE_FOR_EACH (sbrec_mon,
                            input_data->sbrec_service_monitor_table) {
        uint32_t hash = sbrec_mon->port;
        hash = hash_string(sbrec_mon->ip, hash);
        hash = hash_string(sbrec_mon->logical_port, hash);
        struct service_monitor_info *mon_info = xzalloc(sizeof *mon_info);
        mon_info->sbrec_mon = sbrec_mon;
        mon_info->required = false;
        hmap_insert(&monitor_map, &mon_info->hmap_node, hash);
    }

    struct ovn_northd_lb *lb;
    HMAP_FOR_EACH (lb, hmap_node, lbs) {
        ovn_lb_svc_create(ovnsb_txn, lb, &monitor_map, ports);
    }

    struct service_monitor_info *mon_info;
    HMAP_FOR_EACH_POP (mon_info, hmap_node, &monitor_map) {
        if (!mon_info->required) {
            sbrec_service_monitor_delete(mon_info->sbrec_mon);
        }

        free(mon_info);
    }
    hmap_destroy(&monitor_map);
}

static bool lrouter_port_ipv4_reachable(const struct ovn_port *op,
                                        ovs_be32 addr);
static bool lrouter_port_ipv6_reachable(const struct ovn_port *op,
                                        const struct in6_addr *addr);
static void
build_lrouter_lb_reachable_ips(struct ovn_datapath *od,
                               const struct ovn_northd_lb *lb)
{
    /* If configured to not reply to any neighbor requests for all VIPs
     * return early.
     */
    if (lb->neigh_mode == LB_NEIGH_RESPOND_NONE) {
        return;
    }

    /* If configured to reply to neighbor requests for all VIPs force them
     * all to be considered "reachable".
     */
    if (lb->neigh_mode == LB_NEIGH_RESPOND_ALL) {
        for (size_t i = 0; i < lb->n_vips; i++) {
            if (lb->vips[i].address_family == AF_INET) {
                sset_add(&od->lb_ips->ips_v4_reachable, lb->vips[i].vip_str);
            } else {
                sset_add(&od->lb_ips->ips_v6_reachable, lb->vips[i].vip_str);
            }
        }
        return;
    }

    /* Otherwise, a VIP is reachable if there's at least one router
     * subnet that includes it.
     */
    ovs_assert(lb->neigh_mode == LB_NEIGH_RESPOND_REACHABLE);
    for (size_t i = 0; i < lb->n_vips; i++) {
        if (lb->vips[i].address_family == AF_INET) {
            ovs_be32 vip_ip4 = in6_addr_get_mapped_ipv4(&lb->vips[i].vip);
            struct ovn_port *op;

            LIST_FOR_EACH (op, dp_node, &od->port_list) {
                if (lrouter_port_ipv4_reachable(op, vip_ip4)) {
                    sset_add(&od->lb_ips->ips_v4_reachable,
                             lb->vips[i].vip_str);
                    break;
                }
            }
        } else {
            struct ovn_port *op;

            LIST_FOR_EACH (op, dp_node, &od->port_list) {
                if (lrouter_port_ipv6_reachable(op, &lb->vips[i].vip)) {
                    sset_add(&od->lb_ips->ips_v6_reachable,
                             lb->vips[i].vip_str);
                    break;
                }
            }
        }
    }
}

static void
build_lrouter_lbs_check(const struct hmap *datapaths)
{
    struct ovn_datapath *od;

    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbr) {
            continue;
        }

        if (od->has_lb_vip && od->n_l3dgw_ports > 1
                && !smap_get(&od->nbr->options, "chassis")) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Load-balancers are configured on logical "
                         "router %s, which has %"PRIuSIZE" distributed "
                         "gateway ports. Load-balancer is not supported "
                         "yet when there is more than one distributed "
                         "gateway port on the router.",
                         od->nbr->name, od->n_l3dgw_ports);
        }
    }
}

static void
build_lrouter_lbs_reachable_ips(struct hmap *datapaths, struct hmap *lbs,
                                struct hmap *lb_groups)
{
    struct ovn_datapath *od;

    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbr) {
            continue;
        }

        for (size_t i = 0; i < od->nbr->n_load_balancer; i++) {
            struct ovn_northd_lb *lb =
                ovn_northd_lb_find(lbs,
                                   &od->nbr->load_balancer[i]->header_.uuid);
            build_lrouter_lb_reachable_ips(od, lb);
        }

        for (size_t i = 0; i < od->nbr->n_load_balancer_group; i++) {
            const struct nbrec_load_balancer_group *nbrec_lb_group =
                od->nbr->load_balancer_group[i];
            struct ovn_lb_group *lb_group;

            lb_group = ovn_lb_group_find(lb_groups,
                                         &nbrec_lb_group->header_.uuid);
            for (size_t j = 0; j < lb_group->n_lbs; j++) {
                build_lrouter_lb_reachable_ips(od, lb_group->lbs[j]);
            }
        }
    }
}

static void
build_lswitch_lbs_from_lrouter(struct hmap *lbs, struct hmap *lb_groups)
{
    if (!install_ls_lb_from_router) {
        return;
    }

    struct ovn_northd_lb *lb;
    HMAP_FOR_EACH (lb, hmap_node, lbs) {
        for (size_t i = 0; i < lb->n_nb_lr; i++) {
            struct ovn_datapath *od = lb->nb_lr[i];
            ovn_northd_lb_add_ls(lb, od->n_ls_peers, od->ls_peers);
        }
    }

    struct ovn_lb_group *lb_group;
    HMAP_FOR_EACH (lb_group, hmap_node, lb_groups) {
        for (size_t i = 0; i < lb_group->n_lr; i++) {
            struct ovn_datapath *od = lb_group->lr[i];
            ovn_lb_group_add_ls(lb_group, od->n_ls_peers, od->ls_peers);
            for (size_t j = 0; j < lb_group->n_lbs; j++) {
                ovn_northd_lb_add_ls(lb_group->lbs[j], od->n_ls_peers,
                                     od->ls_peers);
            }
        }
    }
}

/* This must be called after all ports have been processed, i.e., after
 * build_ports() because the reachability check requires the router ports
 * networks to have been parsed.
 */
static void
build_lb_port_related_data(struct hmap *datapaths, struct hmap *ports,
                           struct hmap *lbs, struct hmap *lb_groups,
                           struct northd_input *input_data,
                           struct ovsdb_idl_txn *ovnsb_txn)
{
    build_lrouter_lbs_check(datapaths);
    build_lrouter_lbs_reachable_ips(datapaths, lbs, lb_groups);
    build_lb_svcs(input_data, ovnsb_txn, ports, lbs);
    build_lswitch_lbs_from_lrouter(lbs, lb_groups);
}


struct ovn_dp_group {
    unsigned long *bitmap;
    struct sbrec_logical_dp_group *dp_group;
    struct hmap_node node;
};

static struct ovn_dp_group *
ovn_dp_group_find(const struct hmap *dp_groups,
                  const unsigned long *dpg_bitmap, uint32_t hash)
{
    struct ovn_dp_group *dpg;

    HMAP_FOR_EACH_WITH_HASH (dpg, node, hash, dp_groups) {
        if (bitmap_equal(dpg->bitmap, dpg_bitmap, n_datapaths)) {
            return dpg;
        }
    }
    return NULL;
}

static struct sbrec_logical_dp_group *
ovn_sb_insert_logical_dp_group(struct ovsdb_idl_txn *ovnsb_txn,
                               const unsigned long *dpg_bitmap)
{
    struct sbrec_logical_dp_group *dp_group;
    const struct sbrec_datapath_binding **sb;
    size_t n = 0, index;

    sb = xmalloc(bitmap_count1(dpg_bitmap, n_datapaths) * sizeof *sb);
    BITMAP_FOR_EACH_1 (index, n_datapaths, dpg_bitmap) {
        sb[n++] = datapaths_array[index]->sb;
    }
    dp_group = sbrec_logical_dp_group_insert(ovnsb_txn);
    sbrec_logical_dp_group_set_datapaths(
        dp_group, (struct sbrec_datapath_binding **) sb, n);
    free(sb);

    return dp_group;
}

/* Syncs relevant load balancers (applied to logical switches) to the
 * Southbound database.
 */
static void
sync_lbs(struct northd_input *input_data, struct ovsdb_idl_txn *ovnsb_txn,
         struct hmap *datapaths, struct hmap *lbs)
{
    struct hmap dp_groups = HMAP_INITIALIZER(&dp_groups);
    struct ovn_northd_lb *lb;

    /* Delete any stale SB load balancer rows and collect existing valid
     * datapath groups. */
    struct hmapx existing_sb_dp_groups =
        HMAPX_INITIALIZER(&existing_sb_dp_groups);
    struct hmapx existing_lbs = HMAPX_INITIALIZER(&existing_lbs);
    const struct sbrec_load_balancer *sbrec_lb;
    SBREC_LOAD_BALANCER_TABLE_FOR_EACH_SAFE (sbrec_lb,
                            input_data->sbrec_load_balancer_table) {
        const char *nb_lb_uuid = smap_get(&sbrec_lb->external_ids, "lb_id");
        struct uuid lb_uuid;
        if (!nb_lb_uuid || !uuid_from_string(&lb_uuid, nb_lb_uuid)) {
            sbrec_load_balancer_delete(sbrec_lb);
            continue;
        }

        /* Delete any SB load balancer entries that refer to NB load balancers
         * that don't exist anymore or are not applied to switches anymore.
         *
         * There is also a special case in which duplicate LBs might be created
         * in the SB, e.g., due to the fact that OVSDB only ensures
         * "at-least-once" consistency for clustered database tables that
         * are not indexed in any way.
         */
        lb = ovn_northd_lb_find(lbs, &lb_uuid);
        if (!lb || !lb->n_nb_ls || !hmapx_add(&existing_lbs, lb)) {
            sbrec_load_balancer_delete(sbrec_lb);
            continue;
        }

        lb->slb = sbrec_lb;

        /* Collect the datapath group. */
        struct sbrec_logical_dp_group *dp_group = sbrec_lb->datapath_group;

        if (!dp_group || !hmapx_add(&existing_sb_dp_groups, dp_group)) {
            continue;
        }

        struct ovn_dp_group *dpg = xzalloc(sizeof *dpg);
        size_t i, n = 0;

        dpg->bitmap = bitmap_allocate(n_datapaths);
        for (i = 0; i < dp_group->n_datapaths; i++) {
            struct ovn_datapath *datapath_od;

            datapath_od = ovn_datapath_from_sbrec(datapaths,
                                                  dp_group->datapaths[i]);
            if (!datapath_od || ovn_datapath_is_stale(datapath_od)) {
                break;
            }
            bitmap_set1(dpg->bitmap, datapath_od->index);
            n++;
        }
        if (i == dp_group->n_datapaths) {
            uint32_t hash = hash_int(n, 0);

            if (!ovn_dp_group_find(&dp_groups, dpg->bitmap, hash)) {
                dpg->dp_group = dp_group;
                hmap_insert(&dp_groups, &dpg->node, hash);
                continue;
            }
        }
        bitmap_free(dpg->bitmap);
        free(dpg);
    }
    hmapx_destroy(&existing_lbs);
    hmapx_destroy(&existing_sb_dp_groups);

    /* Create SB Load balancer records if not present and sync
     * the SB load balancer columns. */
    HMAP_FOR_EACH (lb, hmap_node, lbs) {

        if (!lb->n_nb_ls) {
            continue;
        }

        /* Store the fact that northd provides the original (destination IP +
         * transport port) tuple.
         */
        struct smap options;
        smap_clone(&options, &lb->nlb->options);
        smap_replace(&options, "hairpin_orig_tuple", "true");

        if (!lb->slb) {
            sbrec_lb = sbrec_load_balancer_insert(ovnsb_txn);
            lb->slb = sbrec_lb;
            char *lb_id = xasprintf(
                UUID_FMT, UUID_ARGS(&lb->nlb->header_.uuid));
            const struct smap external_ids =
                SMAP_CONST1(&external_ids, "lb_id", lb_id);
            sbrec_load_balancer_set_external_ids(sbrec_lb, &external_ids);
            free(lb_id);
        }

        /* Find datapath group for this load balancer. */
        unsigned long *lb_dps_bitmap;
        struct ovn_dp_group *dpg;
        uint32_t hash;

        lb_dps_bitmap = bitmap_allocate(n_datapaths);
        for (size_t i = 0; i < lb->n_nb_ls; i++) {
            bitmap_set1(lb_dps_bitmap, lb->nb_ls[i]->index);
        }

        hash = hash_int(bitmap_count1(lb_dps_bitmap, n_datapaths), 0);
        dpg = ovn_dp_group_find(&dp_groups, lb_dps_bitmap, hash);
        if (!dpg) {
            dpg = xzalloc(sizeof *dpg);
            dpg->dp_group = ovn_sb_insert_logical_dp_group(ovnsb_txn,
                                                           lb_dps_bitmap);
            dpg->bitmap = bitmap_clone(lb_dps_bitmap, n_datapaths);
            hmap_insert(&dp_groups, &dpg->node, hash);
        }
        bitmap_free(lb_dps_bitmap);

        /* Update columns. */
        sbrec_load_balancer_set_name(lb->slb, lb->nlb->name);
        sbrec_load_balancer_set_vips(lb->slb, &lb->nlb->vips);
        sbrec_load_balancer_set_protocol(lb->slb, lb->nlb->protocol);
        sbrec_load_balancer_set_datapath_group(lb->slb, dpg->dp_group);
        sbrec_load_balancer_set_options(lb->slb, &options);
        /* Clearing 'datapaths' column, since 'dp_group' is in use. */
        sbrec_load_balancer_set_datapaths(lb->slb, NULL, 0);
        smap_destroy(&options);
    }

    struct ovn_dp_group *dpg;
    HMAP_FOR_EACH_POP (dpg, node, &dp_groups) {
        bitmap_free(dpg->bitmap);
        free(dpg);
    }
    hmap_destroy(&dp_groups);

    /* Datapath_Binding.load_balancers is not used anymore, it's still in the
     * schema for compatibility reasons.  Reset it to empty, just in case.
     */
    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbs) {
            continue;
        }

        if (od->sb->n_load_balancers) {
            sbrec_datapath_binding_set_load_balancers(od->sb, NULL, 0);
        }
    }
}

static bool
ovn_port_add_tnlid(struct ovn_port *op, uint32_t tunnel_key)
{
    bool added = ovn_add_tnlid(&op->od->port_tnlids, tunnel_key);
    if (added) {
        op->tunnel_key = tunnel_key;
        if (tunnel_key > op->od->port_key_hint) {
            op->od->port_key_hint = tunnel_key;
        }
    }
    return added;
}

static void
ovn_port_assign_requested_tnl_id(struct northd_input *input_data,
                                 struct ovn_port *op)
{
    const struct smap *options = (op->nbsp
                                  ? &op->nbsp->options
                                  : &op->nbrp->options);
    uint32_t tunnel_key = smap_get_int(options, "requested-tnl-key", 0);
    if (tunnel_key) {
        if (is_vxlan_mode(input_data) &&
                tunnel_key >= OVN_VXLAN_MIN_MULTICAST) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Tunnel key %"PRIu32" for port %s "
                         "is incompatible with VXLAN",
                         tunnel_key, op_get_name(op));
            return;
        }
        if (!ovn_port_add_tnlid(op, tunnel_key)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Logical %s port %s requests same tunnel key "
                         "%"PRIu32" as another LSP or LRP",
                         op->nbsp ? "switch" : "router",
                         op_get_name(op), tunnel_key);
        }
    }
}

static void
ovn_port_allocate_key(struct northd_input *input_data,
                      struct hmap *ports,
                      struct ovn_port *op)
{
    if (!op->tunnel_key) {
        uint8_t key_bits = is_vxlan_mode(input_data)? 12 : 16;
        op->tunnel_key = ovn_allocate_tnlid(&op->od->port_tnlids, "port",
                                            1, (1u << (key_bits - 1)) - 1,
                                            &op->od->port_key_hint);
        if (!op->tunnel_key) {
            if (op->sb) {
                sbrec_port_binding_delete(op->sb);
            }
            ovs_list_remove(&op->list);
            ovn_port_destroy(ports, op);
        }
    }
}

/* Updates the southbound Port_Binding table so that it contains the logical
 * switch ports specified by the northbound database.
 *
 * Initializes 'ports' to contain a "struct ovn_port" for every logical port,
 * using the "struct ovn_datapath"s in 'datapaths' to look up logical
 * datapaths. */
static void
build_ports(struct northd_input *input_data,
            struct ovsdb_idl_txn *ovnsb_txn,
            struct ovsdb_idl_index *sbrec_chassis_by_name,
            struct ovsdb_idl_index *sbrec_chassis_by_hostname,
            struct hmap *datapaths, struct hmap *ports)
{
    struct ovs_list sb_only, nb_only, both;
    struct hmap tag_alloc_table = HMAP_INITIALIZER(&tag_alloc_table);
    struct hmap chassis_qdisc_queues = HMAP_INITIALIZER(&chassis_qdisc_queues);

    /* sset which stores the set of ha chassis group names used. */
    struct sset active_ha_chassis_grps =
        SSET_INITIALIZER(&active_ha_chassis_grps);

    join_logical_ports(input_data,
                       datapaths, ports, &chassis_qdisc_queues,
                       &tag_alloc_table, &sb_only, &nb_only, &both);

    /* Purge stale Mac_Bindings if ports are deleted. */
    bool remove_mac_bindings = !ovs_list_is_empty(&sb_only);

    /* Assign explicitly requested tunnel ids first. */
    struct ovn_port *op;
    LIST_FOR_EACH (op, list, &both) {
        ovn_port_assign_requested_tnl_id(input_data, op);
    }
    LIST_FOR_EACH (op, list, &nb_only) {
        ovn_port_assign_requested_tnl_id(input_data, op);
    }

    /* Keep nonconflicting tunnel IDs that are already assigned. */
    LIST_FOR_EACH (op, list, &both) {
        if (!op->tunnel_key) {
            ovn_port_add_tnlid(op, op->sb->tunnel_key);
        }
    }

    /* Assign new tunnel ids where needed. */
    LIST_FOR_EACH_SAFE (op, list, &both) {
        ovn_port_allocate_key(input_data, ports, op);
    }
    LIST_FOR_EACH_SAFE (op, list, &nb_only) {
        ovn_port_allocate_key(input_data, ports, op);
    }

    /* For logical ports that are in both databases, update the southbound
     * record based on northbound data.
     * For logical ports that are in NB database, do any tag allocation
     * needed. */
    LIST_FOR_EACH_SAFE (op, list, &both) {
        /* When reusing stale Port_Bindings, make sure that stale
         * Mac_Bindings are purged.
         */
        if (op->od->sb != op->sb->datapath) {
            remove_mac_bindings = true;
        }
        if (op->nbsp) {
            tag_alloc_create_new_tag(&tag_alloc_table, op->nbsp);
        }
        ovn_port_update_sbrec(input_data,
                              ovnsb_txn, sbrec_chassis_by_name,
                              sbrec_chassis_by_hostname,
                              op, &chassis_qdisc_queues,
                              &active_ha_chassis_grps);
    }

    /* Add southbound record for each unmatched northbound record. */
    LIST_FOR_EACH_SAFE (op, list, &nb_only) {
        op->sb = sbrec_port_binding_insert(ovnsb_txn);
        ovn_port_update_sbrec(input_data,
                              ovnsb_txn, sbrec_chassis_by_name,
                              sbrec_chassis_by_hostname, op,
                              &chassis_qdisc_queues,
                              &active_ha_chassis_grps);
        sbrec_port_binding_set_logical_port(op->sb, op->key);
    }

    /* Delete southbound records without northbound matches. */
    if (!ovs_list_is_empty(&sb_only)) {
        LIST_FOR_EACH_SAFE (op, list, &sb_only) {
            ovs_list_remove(&op->list);
            sbrec_port_binding_delete(op->sb);
            ovn_port_destroy(ports, op);
        }
    }
    if (remove_mac_bindings) {
        cleanup_mac_bindings(input_data, datapaths, ports);
    }

    tag_alloc_destroy(&tag_alloc_table);
    destroy_chassis_queues(&chassis_qdisc_queues);
    cleanup_sb_ha_chassis_groups(input_data, &active_ha_chassis_grps);
    sset_destroy(&active_ha_chassis_grps);
}

struct multicast_group {
    const char *name;
    uint16_t key;               /* OVN_MIN_MULTICAST...OVN_MAX_MULTICAST. */
};

#define MC_FLOOD "_MC_flood"
static const struct multicast_group mc_flood =
    { MC_FLOOD, OVN_MCAST_FLOOD_TUNNEL_KEY };

#define MC_MROUTER_FLOOD "_MC_mrouter_flood"
static const struct multicast_group mc_mrouter_flood =
    { MC_MROUTER_FLOOD, OVN_MCAST_MROUTER_FLOOD_TUNNEL_KEY };

#define MC_STATIC "_MC_static"
static const struct multicast_group mc_static =
    { MC_STATIC, OVN_MCAST_STATIC_TUNNEL_KEY };

#define MC_UNKNOWN "_MC_unknown"
static const struct multicast_group mc_unknown =
    { MC_UNKNOWN, OVN_MCAST_UNKNOWN_TUNNEL_KEY };

#define MC_FLOOD_L2 "_MC_flood_l2"
static const struct multicast_group mc_flood_l2 =
    { MC_FLOOD_L2, OVN_MCAST_FLOOD_L2_TUNNEL_KEY };

static bool
multicast_group_equal(const struct multicast_group *a,
                      const struct multicast_group *b)
{
    return !strcmp(a->name, b->name) && a->key == b->key;
}

/* Multicast group entry. */
struct ovn_multicast {
    struct hmap_node hmap_node; /* Index on 'datapath' and 'key'. */
    struct ovn_datapath *datapath;
    const struct multicast_group *group;

    struct ovn_port **ports;
    size_t n_ports, allocated_ports;
};

static uint32_t
ovn_multicast_hash(const struct ovn_datapath *datapath,
                   const struct multicast_group *group)
{
    return hash_pointer(datapath, group->key);
}

static struct ovn_multicast *
ovn_multicast_find(struct hmap *mcgroups, struct ovn_datapath *datapath,
                   const struct multicast_group *group)
{
    struct ovn_multicast *mc;

    HMAP_FOR_EACH_WITH_HASH (mc, hmap_node,
                             ovn_multicast_hash(datapath, group), mcgroups) {
        if (mc->datapath == datapath
            && multicast_group_equal(mc->group, group)) {
            return mc;
        }
    }
    return NULL;
}

static void
ovn_multicast_add_ports(struct hmap *mcgroups, struct ovn_datapath *od,
                        const struct multicast_group *group,
                        struct ovn_port **ports, size_t n_ports)
{
    struct ovn_multicast *mc = ovn_multicast_find(mcgroups, od, group);
    if (!mc) {
        mc = xmalloc(sizeof *mc);
        hmap_insert(mcgroups, &mc->hmap_node, ovn_multicast_hash(od, group));
        mc->datapath = od;
        mc->group = group;
        mc->n_ports = 0;
        mc->allocated_ports = 4;
        mc->ports = xmalloc(mc->allocated_ports * sizeof *mc->ports);
    }

    size_t n_ports_total = mc->n_ports + n_ports;

    if (n_ports_total > 2 * mc->allocated_ports) {
        mc->allocated_ports = n_ports_total;
        mc->ports = xrealloc(mc->ports,
                             mc->allocated_ports * sizeof *mc->ports);
    } else if (n_ports_total > mc->allocated_ports) {
        mc->ports = x2nrealloc(mc->ports, &mc->allocated_ports,
                               sizeof *mc->ports);
    }

    memcpy(&mc->ports[mc->n_ports], &ports[0], n_ports * sizeof *ports);
    mc->n_ports += n_ports;
}

static void
ovn_multicast_add(struct hmap *mcgroups, const struct multicast_group *group,
                  struct ovn_port *port)
{
    /* Store the chassis redirect port otherwise traffic will not be tunneled
     * properly.
     */
    if (port->cr_port) {
        port = port->cr_port;
    }
    ovn_multicast_add_ports(mcgroups, port->od, group, &port, 1);
}

static void
ovn_multicast_destroy(struct hmap *mcgroups, struct ovn_multicast *mc)
{
    if (mc) {
        hmap_remove(mcgroups, &mc->hmap_node);
        free(mc->ports);
        free(mc);
    }
}

static void
ovn_multicast_update_sbrec(const struct ovn_multicast *mc,
                           const struct sbrec_multicast_group *sb)
{
    struct sbrec_port_binding **ports = xmalloc(mc->n_ports * sizeof *ports);
    for (size_t i = 0; i < mc->n_ports; i++) {
        ports[i] = CONST_CAST(struct sbrec_port_binding *, mc->ports[i]->sb);
    }
    sbrec_multicast_group_set_ports(sb, ports, mc->n_ports);
    free(ports);
}

/*
 * IGMP group entry (1:1 mapping to SB database).
 */
struct ovn_igmp_group_entry {
    struct ovs_list list_node; /* Linkage in the list of entries. */
    size_t n_ports;
    struct ovn_port **ports;
};

/*
 * IGMP group entry (aggregate of all entries from the SB database
 * corresponding to the multicast group).
 */
struct ovn_igmp_group {
    struct hmap_node hmap_node; /* Index on 'datapath' and 'address'. */
    struct ovs_list list_node;  /* Linkage in the per-dp igmp group list. */

    struct ovn_datapath *datapath;
    struct in6_addr address; /* Multicast IPv6-mapped-IPv4 or IPv4 address. */
    struct multicast_group mcgroup;

    struct ovs_list entries; /* List of SB entries for this group. */
};

static uint32_t
ovn_igmp_group_hash(const struct ovn_datapath *datapath,
                    const struct in6_addr *address)
{
    return hash_pointer(datapath, hash_bytes(address, sizeof *address, 0));
}

static struct ovn_igmp_group *
ovn_igmp_group_find(struct hmap *igmp_groups,
                    const struct ovn_datapath *datapath,
                    const struct in6_addr *address)
{
    struct ovn_igmp_group *group;

    HMAP_FOR_EACH_WITH_HASH (group, hmap_node,
                             ovn_igmp_group_hash(datapath, address),
                             igmp_groups) {
        if (group->datapath == datapath &&
                ipv6_addr_equals(&group->address, address)) {
            return group;
        }
    }
    return NULL;
}

static struct ovn_igmp_group *
ovn_igmp_group_add(struct lflow_input *input_data,
                   struct hmap *igmp_groups,
                   struct ovn_datapath *datapath,
                   const struct in6_addr *address,
                   const char *address_s)
{
    struct ovn_igmp_group *igmp_group =
        ovn_igmp_group_find(igmp_groups, datapath, address);

    if (!igmp_group) {
        igmp_group = xmalloc(sizeof *igmp_group);

        const struct sbrec_multicast_group *mcgroup =
            mcast_group_lookup(input_data->sbrec_mcast_group_by_name_dp,
                               address_s,
                               datapath->sb);

        igmp_group->datapath = datapath;
        igmp_group->address = *address;
        if (mcgroup) {
            igmp_group->mcgroup.key = mcgroup->tunnel_key;
            ovn_add_tnlid(&datapath->mcast_info.group_tnlids,
                          mcgroup->tunnel_key);
        } else {
            igmp_group->mcgroup.key = 0;
        }
        igmp_group->mcgroup.name = address_s;
        ovs_list_init(&igmp_group->entries);

        hmap_insert(igmp_groups, &igmp_group->hmap_node,
                    ovn_igmp_group_hash(datapath, address));
        ovs_list_push_back(&datapath->mcast_info.groups,
                           &igmp_group->list_node);
    }

    return igmp_group;
}

static bool
ovn_igmp_group_get_address(const struct sbrec_igmp_group *sb_igmp_group,
                           struct in6_addr *address)
{
    ovs_be32 ipv4;

    if (ip_parse(sb_igmp_group->address, &ipv4)) {
        *address = in6_addr_mapped_ipv4(ipv4);
        return true;
    }
    if (!ipv6_parse(sb_igmp_group->address, address)) {
        return false;
    }
    return true;
}

static struct ovn_port **
ovn_igmp_group_get_ports(const struct sbrec_igmp_group *sb_igmp_group,
                         size_t *n_ports, const struct hmap *ovn_ports)
{
    struct ovn_port **ports = NULL;

     *n_ports = 0;
     for (size_t i = 0; i < sb_igmp_group->n_ports; i++) {
        struct ovn_port *port =
            ovn_port_find(ovn_ports, sb_igmp_group->ports[i]->logical_port);

        if (!port) {
            continue;
        }

        /* If this is already a flood port skip it for the group. */
        if (port->mcast_info.flood) {
            continue;
        }

        /* If this is already a port of a router on which relay is enabled,
         * skip it for the group. Traffic is flooded there anyway.
         */
        if (port->peer && port->peer->od &&
                port->peer->od->mcast_info.rtr.relay) {
            continue;
        }

        if (ports == NULL) {
            ports = xmalloc(sb_igmp_group->n_ports * sizeof *ports);
        }

        ports[(*n_ports)] = port;
        (*n_ports)++;
    }

    return ports;
}

static void
ovn_igmp_group_add_entry(struct ovn_igmp_group *igmp_group,
                         struct ovn_port **ports, size_t n_ports)
{
    struct ovn_igmp_group_entry *entry = xmalloc(sizeof *entry);

    entry->ports = ports;
    entry->n_ports = n_ports;
    ovs_list_push_back(&igmp_group->entries, &entry->list_node);
}

static void
ovn_igmp_group_destroy_entry(struct ovn_igmp_group_entry *entry)
{
    free(entry->ports);
}

static bool
ovn_igmp_group_allocate_id(struct ovn_igmp_group *igmp_group)
{
    if (igmp_group->mcgroup.key == 0) {
        struct mcast_info *mcast_info = &igmp_group->datapath->mcast_info;
        igmp_group->mcgroup.key = ovn_mcast_group_allocate_key(mcast_info);
    }

    if (igmp_group->mcgroup.key == 0) {
        return false;
    }

    return true;
}

static void
ovn_igmp_mrouter_aggregate_ports(struct ovn_igmp_group *igmp_group,
                                 struct hmap *mcast_groups)
{
    struct ovn_igmp_group_entry *entry;

    LIST_FOR_EACH_POP (entry, list_node, &igmp_group->entries) {
        ovn_multicast_add_ports(mcast_groups, igmp_group->datapath,
                                &mc_mrouter_flood, entry->ports,
                                entry->n_ports);

        ovn_igmp_group_destroy_entry(entry);
        free(entry);
    }
}

static void
ovn_igmp_group_aggregate_ports(struct ovn_igmp_group *igmp_group,
                               struct hmap *mcast_groups)
{
    struct ovn_igmp_group_entry *entry;

    LIST_FOR_EACH_POP (entry, list_node, &igmp_group->entries) {
        ovn_multicast_add_ports(mcast_groups, igmp_group->datapath,
                                &igmp_group->mcgroup, entry->ports,
                                entry->n_ports);

        ovn_igmp_group_destroy_entry(entry);
        free(entry);
    }

    if (igmp_group->datapath->n_localnet_ports) {
        ovn_multicast_add_ports(mcast_groups, igmp_group->datapath,
                                &igmp_group->mcgroup,
                                igmp_group->datapath->localnet_ports,
                                igmp_group->datapath->n_localnet_ports);
    }
}

static void
ovn_igmp_group_destroy(struct hmap *igmp_groups,
                       struct ovn_igmp_group *igmp_group)
{
    if (igmp_group) {
        struct ovn_igmp_group_entry *entry;

        LIST_FOR_EACH_POP (entry, list_node, &igmp_group->entries) {
            ovn_igmp_group_destroy_entry(entry);
            free(entry);
        }
        hmap_remove(igmp_groups, &igmp_group->hmap_node);
        ovs_list_remove(&igmp_group->list_node);
        free(igmp_group);
    }
}

/* Logical flow generation.
 *
 * This code generates the Logical_Flow table in the southbound database, as a
 * function of most of the northbound database.
 */

struct ovn_lflow {
    struct hmap_node hmap_node;

    struct ovn_datapath *od;     /* 'logical_datapath' in SB schema.  */
    struct ovs_mutex dpg_lock;   /* Lock guarding access to 'dpg_bitmap' */
    unsigned long *dpg_bitmap;   /* Bitmap of all datapaths by their 'index'.*/
    enum ovn_stage stage;
    uint16_t priority;
    char *match;
    char *actions;
    char *io_port;
    char *stage_hint;
    char *ctrl_meter;
    struct ovn_dp_group *dpg;    /* Link to unique Sb datapath group. */
    const char *where;
};

static void ovn_lflow_destroy(struct hmap *lflows, struct ovn_lflow *lflow);
static struct ovn_lflow *ovn_lflow_find(const struct hmap *lflows,
                                        const struct ovn_datapath *od,
                                        enum ovn_stage stage,
                                        uint16_t priority, const char *match,
                                        const char *actions,
                                        const char *ctrl_meter, uint32_t hash);

static char *
ovn_lflow_hint(const struct ovsdb_idl_row *row)
{
    if (!row) {
        return NULL;
    }
    return xasprintf("%08x", row->uuid.parts[0]);
}

static bool
ovn_lflow_equal(const struct ovn_lflow *a, const struct ovn_datapath *od,
                enum ovn_stage stage, uint16_t priority, const char *match,
                const char *actions, const char *ctrl_meter)
{
    return (a->od == od
            && a->stage == stage
            && a->priority == priority
            && !strcmp(a->match, match)
            && !strcmp(a->actions, actions)
            && nullable_string_is_equal(a->ctrl_meter, ctrl_meter));
}

enum {
    STATE_NULL,               /* parallelization is off */
    STATE_INIT_HASH_SIZES,    /* parallelization is on; hashes sizing needed */
    STATE_USE_PARALLELIZATION /* parallelization is on */
};
static int parallelization_state = STATE_NULL;

static void
ovn_lflow_init(struct ovn_lflow *lflow, struct ovn_datapath *od,
               enum ovn_stage stage, uint16_t priority,
               char *match, char *actions, char *io_port, char *ctrl_meter,
               char *stage_hint, const char *where)
{
    lflow->dpg_bitmap = bitmap_allocate(n_datapaths);
    lflow->od = od;
    lflow->stage = stage;
    lflow->priority = priority;
    lflow->match = match;
    lflow->actions = actions;
    lflow->io_port = io_port;
    lflow->stage_hint = stage_hint;
    lflow->ctrl_meter = ctrl_meter;
    lflow->dpg = NULL;
    lflow->where = where;
    if (parallelization_state != STATE_NULL) {
        ovs_mutex_init(&lflow->dpg_lock);
    }
}

static bool
ovn_dp_group_add_with_reference(struct ovn_lflow *lflow_ref,
                                struct ovn_datapath *od)
                                OVS_NO_THREAD_SAFETY_ANALYSIS
{
    if (!lflow_ref) {
        return false;
    }

    if (parallelization_state == STATE_USE_PARALLELIZATION) {
        ovs_mutex_lock(&lflow_ref->dpg_lock);
        bitmap_set1(lflow_ref->dpg_bitmap, od->index);
        ovs_mutex_unlock(&lflow_ref->dpg_lock);
    } else {
        bitmap_set1(lflow_ref->dpg_bitmap, od->index);
    }

    return true;
}

/* The lflow_hash_lock is a mutex array that protects updates to the shared
 * lflow table across threads when parallel lflow build and dp-group are both
 * enabled. To avoid high contention between threads, a big array of mutexes
 * are used instead of just one. This is possible because when parallel build
 * is used we only use hmap_insert_fast() to update the hmap, which would not
 * touch the bucket array but only the list in a single bucket. We only need to
 * make sure that when adding lflows to the same hash bucket, the same lock is
 * used, so that no two threads can add to the bucket at the same time.  It is
 * ok that the same lock is used to protect multiple buckets, so a fixed sized
 * mutex array is used instead of 1-1 mapping to the hash buckets. This
 * simplies the implementation while effectively reduces lock contention
 * because the chance that different threads contending the same lock amongst
 * the big number of locks is very low. */
#define LFLOW_HASH_LOCK_MASK 0xFFFF
static struct ovs_mutex lflow_hash_locks[LFLOW_HASH_LOCK_MASK + 1];

static void
lflow_hash_lock_init(void)
{
    if (!lflow_hash_lock_initialized) {
        for (size_t i = 0; i < LFLOW_HASH_LOCK_MASK + 1; i++) {
            ovs_mutex_init(&lflow_hash_locks[i]);
        }
        lflow_hash_lock_initialized = true;
    }
}

static void
lflow_hash_lock_destroy(void)
{
    if (lflow_hash_lock_initialized) {
        for (size_t i = 0; i < LFLOW_HASH_LOCK_MASK + 1; i++) {
            ovs_mutex_destroy(&lflow_hash_locks[i]);
        }
    }
    lflow_hash_lock_initialized = false;
}

/* This thread-local var is used for parallel lflow building when dp-groups is
 * enabled. It maintains the number of lflows inserted by the current thread to
 * the shared lflow hmap in the current iteration. It is needed because the
 * lflow_hash_lock cannot protect current update of the hmap's size (hmap->n)
 * by different threads.
 *
 * When all threads complete the tasks of an iteration, the counters of all the
 * threads are collected to fix the lflow hmap's size (by the function
 * fix_flow_map_size()).
 * */
static thread_local size_t thread_lflow_counter = 0;

/* Adds a row with the specified contents to the Logical_Flow table.
 * Version to use when hash bucket locking is NOT required.
 */
static struct ovn_lflow *
do_ovn_lflow_add(struct hmap *lflow_map, struct ovn_datapath *od,
                 uint32_t hash, enum ovn_stage stage, uint16_t priority,
                 const char *match, const char *actions, const char *io_port,
                 const struct ovsdb_idl_row *stage_hint,
                 const char *where, const char *ctrl_meter)
{

    struct ovn_lflow *old_lflow;
    struct ovn_lflow *lflow;

    old_lflow = ovn_lflow_find(lflow_map, NULL, stage, priority, match,
                               actions, ctrl_meter, hash);
    if (old_lflow) {
        ovn_dp_group_add_with_reference(old_lflow, od);
        return old_lflow;
    }

    lflow = xmalloc(sizeof *lflow);
    /* While adding new logical flows we're not setting single datapath, but
     * collecting a group.  'od' will be updated later for all flows with only
     * one datapath in a group, so it could be hashed correctly. */
    ovn_lflow_init(lflow, NULL, stage, priority,
                   xstrdup(match), xstrdup(actions),
                   io_port ? xstrdup(io_port) : NULL,
                   nullable_xstrdup(ctrl_meter),
                   ovn_lflow_hint(stage_hint), where);
    bitmap_set1(lflow->dpg_bitmap, od->index);
    if (parallelization_state != STATE_USE_PARALLELIZATION) {
        hmap_insert(lflow_map, &lflow->hmap_node, hash);
    } else {
        hmap_insert_fast(lflow_map, &lflow->hmap_node, hash);
        thread_lflow_counter++;
    }
    return lflow;
}

/* Adds a row with the specified contents to the Logical_Flow table.
 * Version to use when hash bucket locking IS required.
 */
static struct ovn_lflow *
do_ovn_lflow_add_pd(struct hmap *lflow_map, struct ovn_datapath *od,
                    uint32_t hash, enum ovn_stage stage, uint16_t priority,
                    const char *match, const char *actions,
                    const char *io_port,
                    const struct ovsdb_idl_row *stage_hint,
                    const char *where, const char *ctrl_meter)
{

    struct ovn_lflow *lflow;
    struct ovs_mutex *hash_lock =
        &lflow_hash_locks[hash & lflow_map->mask & LFLOW_HASH_LOCK_MASK];

    ovs_mutex_lock(hash_lock);
    lflow = do_ovn_lflow_add(lflow_map, od, hash, stage, priority, match,
                             actions, io_port, stage_hint, where, ctrl_meter);
    ovs_mutex_unlock(hash_lock);
    return lflow;
}

static struct ovn_lflow *
ovn_lflow_add_at_with_hash(struct hmap *lflow_map, struct ovn_datapath *od,
                           enum ovn_stage stage, uint16_t priority,
                           const char *match, const char *actions,
                           const char *io_port, const char *ctrl_meter,
                           const struct ovsdb_idl_row *stage_hint,
                           const char *where, uint32_t hash)
{
    struct ovn_lflow *lflow;

    ovs_assert(ovn_stage_to_datapath_type(stage) == ovn_datapath_get_type(od));
    if (parallelization_state == STATE_USE_PARALLELIZATION) {
        lflow = do_ovn_lflow_add_pd(lflow_map, od, hash, stage, priority,
                                    match, actions, io_port, stage_hint, where,
                                    ctrl_meter);
    } else {
        lflow = do_ovn_lflow_add(lflow_map, od, hash, stage, priority, match,
                         actions, io_port, stage_hint, where, ctrl_meter);
    }
    return lflow;
}

/* Adds a row with the specified contents to the Logical_Flow table. */
static void
ovn_lflow_add_at(struct hmap *lflow_map, struct ovn_datapath *od,
                 enum ovn_stage stage, uint16_t priority,
                 const char *match, const char *actions, const char *io_port,
                 const char *ctrl_meter,
                 const struct ovsdb_idl_row *stage_hint, const char *where)
{
    uint32_t hash;

    hash = ovn_logical_flow_hash(ovn_stage_get_table(stage),
                                 ovn_stage_get_pipeline(stage),
                                 priority, match,
                                 actions);
    ovn_lflow_add_at_with_hash(lflow_map, od, stage, priority, match, actions,
                               io_port, ctrl_meter, stage_hint, where, hash);
}

static void
__ovn_lflow_add_default_drop(struct hmap *lflow_map,
                             struct ovn_datapath *od,
                             enum ovn_stage stage,
                             const char *where)
{
        ovn_lflow_add_at(lflow_map, od, stage, 0, "1", debug_drop_action(),
                         NULL, NULL, NULL, where );
}

/* Adds a row with the specified contents to the Logical_Flow table. */
#define ovn_lflow_add_with_hint__(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, \
                                  ACTIONS, IN_OUT_PORT, CTRL_METER, \
                                  STAGE_HINT) \
    ovn_lflow_add_at(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, ACTIONS, \
                     IN_OUT_PORT, CTRL_METER, STAGE_HINT, OVS_SOURCE_LOCATOR)

#define ovn_lflow_add_with_hint(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, \
                                ACTIONS, STAGE_HINT) \
    ovn_lflow_add_at(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, ACTIONS, \
                     NULL, NULL, STAGE_HINT, OVS_SOURCE_LOCATOR)

#define ovn_lflow_add_default_drop(LFLOW_MAP, OD, STAGE)                    \
    __ovn_lflow_add_default_drop(LFLOW_MAP, OD, STAGE, OVS_SOURCE_LOCATOR)


/* This macro is similar to ovn_lflow_add_with_hint, except that it requires
 * the IN_OUT_PORT argument, which tells the lport name that appears in the
 * MATCH, which helps ovn-controller to bypass lflows parsing when the lport is
 * not local to the chassis. The critiera of the lport to be added using this
 * argument:
 *
 * - For ingress pipeline, the lport that is used to match "inport".
 * - For egress pipeline, the lport that is used to match "outport".
 *
 * For now, only LS pipelines should use this macro.  */
#define ovn_lflow_add_with_lport_and_hint(LFLOW_MAP, OD, STAGE, PRIORITY, \
                                          MATCH, ACTIONS, IN_OUT_PORT, \
                                          STAGE_HINT) \
    ovn_lflow_add_at(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, ACTIONS, \
                     IN_OUT_PORT, NULL, STAGE_HINT, OVS_SOURCE_LOCATOR)

#define ovn_lflow_add(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, ACTIONS) \
    ovn_lflow_add_at(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, ACTIONS, \
                     NULL, NULL, NULL, OVS_SOURCE_LOCATOR)

#define ovn_lflow_metered(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, ACTIONS, \
                          CTRL_METER) \
    ovn_lflow_add_with_hint__(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, \
                              ACTIONS, NULL, CTRL_METER, NULL)

static struct ovn_lflow *
ovn_lflow_find(const struct hmap *lflows, const struct ovn_datapath *od,
               enum ovn_stage stage, uint16_t priority,
               const char *match, const char *actions, const char *ctrl_meter,
               uint32_t hash)
{
    struct ovn_lflow *lflow;
    HMAP_FOR_EACH_WITH_HASH (lflow, hmap_node, hash, lflows) {
        if (ovn_lflow_equal(lflow, od, stage, priority, match, actions,
                            ctrl_meter)) {
            return lflow;
        }
    }
    return NULL;
}

static void
ovn_lflow_destroy(struct hmap *lflows, struct ovn_lflow *lflow)
{
    if (lflow) {
        if (parallelization_state != STATE_NULL) {
            ovs_mutex_destroy(&lflow->dpg_lock);
        }
        if (lflows) {
            hmap_remove(lflows, &lflow->hmap_node);
        }
        bitmap_free(lflow->dpg_bitmap);
        free(lflow->match);
        free(lflow->actions);
        free(lflow->io_port);
        free(lflow->stage_hint);
        free(lflow->ctrl_meter);
        free(lflow);
    }
}

static bool
build_dhcpv4_action(struct ovn_port *op, ovs_be32 offer_ip,
                    struct ds *options_action, struct ds *response_action,
                    struct ds *ipv4_addr_match)
{
    if (!op->nbsp->dhcpv4_options) {
        /* CMS has disabled native DHCPv4 for this lport. */
        return false;
    }

    ovs_be32 host_ip, mask;
    char *error = ip_parse_masked(op->nbsp->dhcpv4_options->cidr, &host_ip,
                                  &mask);
    if (error || ((offer_ip ^ host_ip) & mask)) {
       /* Either
        *  - cidr defined is invalid or
        *  - the offer ip of the logical port doesn't belong to the cidr
        *    defined in the DHCPv4 options.
        *  */
        free(error);
        return false;
    }

    const char *server_ip = smap_get(
        &op->nbsp->dhcpv4_options->options, "server_id");
    const char *server_mac = smap_get(
        &op->nbsp->dhcpv4_options->options, "server_mac");
    const char *lease_time = smap_get(
        &op->nbsp->dhcpv4_options->options, "lease_time");

    if (!(server_ip && server_mac && lease_time)) {
        /* "server_id", "server_mac" and "lease_time" should be
         * present in the dhcp_options. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Required DHCPv4 options not defined for lport - %s",
                     op->json_key);
        return false;
    }

    struct smap dhcpv4_options = SMAP_INITIALIZER(&dhcpv4_options);
    smap_clone(&dhcpv4_options, &op->nbsp->dhcpv4_options->options);

    /* server_mac is not DHCPv4 option, delete it from the smap. */
    smap_remove(&dhcpv4_options, "server_mac");
    char *netmask = xasprintf(IP_FMT, IP_ARGS(mask));
    smap_add(&dhcpv4_options, "netmask", netmask);
    free(netmask);

    ds_put_format(options_action,
                  REGBIT_DHCP_OPTS_RESULT" = put_dhcp_opts(offerip = "
                  IP_FMT", ", IP_ARGS(offer_ip));

    /* Try to get hostname DHCP option from ovn_port as it can be passed there
     * instead of DHCP_Options set. Logical_Switch_Port options:hostname takes
     precedence over DHCP_Options options:hostname. */
    const char *hostname = smap_get(&op->nbsp->options, "hostname");
    if (hostname) {
        smap_replace(&dhcpv4_options, "hostname", hostname);
    }

    /* We're not using SMAP_FOR_EACH because we want a consistent order of the
     * options on different architectures (big or little endian, SSE4.2) */
    const struct smap_node **sorted_opts = smap_sort(&dhcpv4_options);
    for (size_t i = 0; i < smap_count(&dhcpv4_options); i++) {
        const struct smap_node *node = sorted_opts[i];
        ds_put_format(options_action, "%s = %s, ", node->key, node->value);
    }
    free(sorted_opts);

    ds_chomp(options_action, ' ');
    ds_chomp(options_action, ',');
    ds_put_cstr(options_action, "); next;");

    ds_put_format(response_action, "eth.dst = eth.src; eth.src = %s; "
                  "ip4.src = %s; udp.src = 67; udp.dst = 68; "
                  "outport = inport; flags.loopback = 1; output;",
                  server_mac, server_ip);

    ds_put_format(ipv4_addr_match,
                  "ip4.src == "IP_FMT" && ip4.dst == {%s, 255.255.255.255}",
                  IP_ARGS(offer_ip), server_ip);
    smap_destroy(&dhcpv4_options);
    return true;
}

static bool
build_dhcpv6_action(struct ovn_port *op, struct in6_addr *offer_ip,
                    struct ds *options_action, struct ds *response_action)
{
    if (!op->nbsp->dhcpv6_options) {
        /* CMS has disabled native DHCPv6 for this lport. */
        return false;
    }

    struct in6_addr host_ip, mask;

    char *error = ipv6_parse_masked(op->nbsp->dhcpv6_options->cidr, &host_ip,
                                        &mask);
    if (error) {
        free(error);
        return false;
    }
    struct in6_addr ip6_mask = ipv6_addr_bitxor(offer_ip, &host_ip);
    ip6_mask = ipv6_addr_bitand(&ip6_mask, &mask);
    if (!ipv6_mask_is_any(&ip6_mask)) {
        /* offer_ip doesn't belongs to the cidr defined in lport's DHCPv6
         * options.*/
        return false;
    }

    const struct smap *options_map = &op->nbsp->dhcpv6_options->options;
    /* "server_id" should be the MAC address. */
    const char *server_mac = smap_get(options_map, "server_id");
    struct eth_addr ea;
    if (!server_mac || !eth_addr_from_string(server_mac, &ea)) {
        /* "server_id" should be present in the dhcpv6_options. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "server_id not present in the DHCPv6 options"
                          " for lport %s", op->json_key);
        return false;
    }

    /* Get the link local IP of the DHCPv6 server from the server MAC. */
    struct in6_addr lla;
    in6_generate_lla(ea, &lla);

    char server_ip[INET6_ADDRSTRLEN + 1];
    ipv6_string_mapped(server_ip, &lla);

    char ia_addr[INET6_ADDRSTRLEN + 1];
    ipv6_string_mapped(ia_addr, offer_ip);

    ds_put_format(options_action,
                  REGBIT_DHCP_OPTS_RESULT" = put_dhcpv6_opts(");

    /* Check whether the dhcpv6 options should be configured as stateful.
     * Only reply with ia_addr option for dhcpv6 stateful address mode. */
    if (!smap_get_bool(options_map, "dhcpv6_stateless", false)) {
        ipv6_string_mapped(ia_addr, offer_ip);
        ds_put_format(options_action, "ia_addr = %s, ", ia_addr);
    }

    /* We're not using SMAP_FOR_EACH because we want a consistent order of the
     * options on different architectures (big or little endian, SSE4.2) */
    const struct smap_node **sorted_opts = smap_sort(options_map);
    for (size_t i = 0; i < smap_count(options_map); i++) {
        const struct smap_node *node = sorted_opts[i];
        if (strcmp(node->key, "dhcpv6_stateless")) {
            ds_put_format(options_action, "%s = %s, ", node->key, node->value);
        }
    }
    free(sorted_opts);

    ds_chomp(options_action, ' ');
    ds_chomp(options_action, ',');
    ds_put_cstr(options_action, "); next;");

    ds_put_format(response_action, "eth.dst = eth.src; eth.src = %s; "
                  "ip6.dst = ip6.src; ip6.src = %s; udp.src = 547; "
                  "udp.dst = 546; outport = inport; flags.loopback = 1; "
                  "output;",
                  server_mac, server_ip);

    return true;
}

struct ovn_port_group_ls {
    struct hmap_node key_node;  /* Index on 'key'. */
    struct uuid key;            /* nb_ls->header_.uuid. */
    struct ovn_datapath *od;

    struct ovn_port **ports; /* Ports in 'od' referrenced by the PG. */
    size_t n_ports;
    size_t n_allocated_ports;
};

struct ovn_port_group {
    struct hmap_node key_node;  /* Index on 'key'. */
    struct uuid key;            /* nb_pg->header_.uuid. */
    const struct nbrec_port_group *nb_pg;
    struct hmap nb_lswitches;   /* NB lswitches related to the port group */
};

static struct ovn_port_group_ls *
ovn_port_group_ls_add(struct ovn_port_group *pg, struct ovn_datapath *od)
{
    struct ovn_port_group_ls *pg_ls = xzalloc(sizeof *pg_ls);
    pg_ls->key = od->nbs->header_.uuid;
    pg_ls->od = od;
    hmap_insert(&pg->nb_lswitches, &pg_ls->key_node, uuid_hash(&pg_ls->key));
    return pg_ls;
}

static struct ovn_port_group_ls *
ovn_port_group_ls_find(struct ovn_port_group *pg, const struct uuid *ls_uuid)
{
    struct ovn_port_group_ls *pg_ls;

    HMAP_FOR_EACH_WITH_HASH (pg_ls, key_node, uuid_hash(ls_uuid),
                             &pg->nb_lswitches) {
        if (uuid_equals(ls_uuid, &pg_ls->key)) {
            return pg_ls;
        }
    }
    return NULL;
}

static void
ovn_port_group_ls_add_port(struct ovn_port_group_ls *pg_ls,
                           struct ovn_port *op)
{
    if (pg_ls->n_ports == pg_ls->n_allocated_ports) {
        pg_ls->ports = x2nrealloc(pg_ls->ports,
                                  &pg_ls->n_allocated_ports,
                                  sizeof *pg_ls->ports);
    }
    pg_ls->ports[pg_ls->n_ports++] = op;
}

struct ovn_ls_port_group {
    struct hmap_node key_node;  /* Index on 'key'. */
    struct uuid key;            /* nb_pg->header_.uuid. */
    const struct nbrec_port_group *nb_pg;
};

static void
ovn_ls_port_group_add(struct hmap *nb_pgs,
                      const struct nbrec_port_group *nb_pg)
{
    struct ovn_ls_port_group *ls_pg = xzalloc(sizeof *ls_pg);
    ls_pg->key = nb_pg->header_.uuid;
    ls_pg->nb_pg = nb_pg;
    hmap_insert(nb_pgs, &ls_pg->key_node, uuid_hash(&ls_pg->key));
}

static void
ovn_ls_port_group_destroy(struct hmap *nb_pgs)
{
    struct ovn_ls_port_group *ls_pg;
    HMAP_FOR_EACH_POP (ls_pg, key_node, nb_pgs) {
        free(ls_pg);
    }
    hmap_destroy(nb_pgs);
}

static void
ls_get_acl_flags(struct ovn_datapath *od)
{
    od->has_acls = false;
    od->has_stateful_acl = false;

    if (od->nbs->n_acls) {
        od->has_acls = true;

        for (size_t i = 0; i < od->nbs->n_acls; i++) {
            struct nbrec_acl *acl = od->nbs->acls[i];
            if (!strcmp(acl->action, "allow-related")) {
                od->has_stateful_acl = true;
                return;
            }
        }
    }

    struct ovn_ls_port_group *ls_pg;
    HMAP_FOR_EACH (ls_pg, key_node, &od->nb_pgs) {
        if (ls_pg->nb_pg->n_acls) {
            od->has_acls = true;

            for (size_t i = 0; i < ls_pg->nb_pg->n_acls; i++) {
                struct nbrec_acl *acl = ls_pg->nb_pg->acls[i];
                if (!strcmp(acl->action, "allow-related")) {
                    od->has_stateful_acl = true;
                    return;
                }
            }
        }
    }
}

/* Adds the logical flows in the (in/out) check port sec stage only if
 *   - the lport is disabled or
 *   - lport is of type vtep - to skip the ingress pipeline.
 *   - lport has qdisc queue id is configured.
 *
 * For all the other logical ports,  generic flow added in
 * build_lswitch_lflows_admission_control() handles the port security.
 */
static void
build_lswitch_port_sec_op(struct ovn_port *op, struct hmap *lflows,
                                struct ds *actions, struct ds *match)
{
    if (!op->nbsp) {
        return;
    }

    if (lsp_is_external(op->nbsp)) {
        return;
    }

    ds_clear(match);
    ds_clear(actions);
    ds_put_format(match, "inport == %s", op->json_key);
    if (!lsp_is_enabled(op->nbsp)) {
        /* Drop packets from disabled logical ports. */
        ovn_lflow_add_with_lport_and_hint(
            lflows, op->od, S_SWITCH_IN_CHECK_PORT_SEC,
            100, ds_cstr(match), REGBIT_PORT_SEC_DROP" = 1; next;",
            op->key, &op->nbsp->header_);

        ds_clear(match);
        ds_put_format(match, "outport == %s", op->json_key);
        ovn_lflow_add_with_lport_and_hint(
            lflows, op->od, S_SWITCH_IN_L2_UNKNOWN, 50, ds_cstr(match),
            "drop;", op->key, &op->nbsp->header_);
        return;
    }

    const char *queue_id = smap_get(&op->sb->options, "qdisc_queue_id");
    if (queue_id) {
        ds_put_format(actions, "set_queue(%s); ", queue_id);
    }

    if (lsp_is_vtep(op->nbsp)) {
        ds_put_format(actions, REGBIT_FROM_RAMP" = 1; ");
        ds_put_format(actions, "next(pipeline=ingress, table=%d);",
                      ovn_stage_get_table(S_SWITCH_IN_HAIRPIN));
        ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                          S_SWITCH_IN_CHECK_PORT_SEC, 70,
                                          ds_cstr(match), ds_cstr(actions),
                                          op->key, &op->nbsp->header_);
    } else if (queue_id) {
        ds_put_cstr(actions,
                    REGBIT_PORT_SEC_DROP" = check_in_port_sec(); next;");
        ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                          S_SWITCH_IN_CHECK_PORT_SEC, 70,
                                          ds_cstr(match), ds_cstr(actions),
                                          op->key, &op->nbsp->header_);

        if (lsp_is_localnet(op->nbsp)) {
            ds_clear(match);
            ds_clear(actions);
            ds_put_format(match, "outport == %s", op->json_key);
            ds_put_format(actions, "set_queue(%s); output;", queue_id);
            ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                            S_SWITCH_OUT_APPLY_PORT_SEC, 100,
                                            ds_cstr(match), ds_cstr(actions),
                                            op->key, &op->nbsp->header_);
        }
    }
}

static void
build_lswitch_learn_fdb_op(
        struct ovn_port *op, struct hmap *lflows,
        struct ds *actions, struct ds *match)
{
    if (!op->nbsp) {
        return;
    }

    if (!op->n_ps_addrs && op->has_unknown && (!strcmp(op->nbsp->type, "") ||
        (lsp_is_localnet(op->nbsp) && localnet_can_learn_mac(op->nbsp)))) {
        ds_clear(match);
        ds_clear(actions);
        ds_put_format(match, "inport == %s", op->json_key);
        ds_put_format(actions, REGBIT_LKUP_FDB
                      " = lookup_fdb(inport, eth.src); next;");
        ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                          S_SWITCH_IN_LOOKUP_FDB, 100,
                                          ds_cstr(match), ds_cstr(actions),
                                          op->key, &op->nbsp->header_);

        ds_put_cstr(match, " && "REGBIT_LKUP_FDB" == 0");
        ds_clear(actions);
        ds_put_cstr(actions, "put_fdb(inport, eth.src); next;");
        ovn_lflow_add_with_lport_and_hint(lflows, op->od, S_SWITCH_IN_PUT_FDB,
                                          100, ds_cstr(match),
                                          ds_cstr(actions), op->key,
                                          &op->nbsp->header_);
    }
}

static void
build_lswitch_learn_fdb_od(
        struct ovn_datapath *od, struct hmap *lflows)
{

    if (od->nbs) {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_LOOKUP_FDB, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_IN_PUT_FDB, 0, "1", "next;");
    }
}

/* Egress tables 8: Egress port security - IP (priority 0)
 * Egress table 9: Egress port security L2 - multicast/broadcast
 *                 (priority 100). */
static void
build_lswitch_output_port_sec_od(struct ovn_datapath *od,
                              struct hmap *lflows)
{
    if (od->nbs) {
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_CHECK_PORT_SEC, 100,
                      "eth.mcast", REGBIT_PORT_SEC_DROP" = 0; next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_CHECK_PORT_SEC, 0, "1",
                      REGBIT_PORT_SEC_DROP" = check_out_port_sec(); next;");

        ovn_lflow_add(lflows, od, S_SWITCH_OUT_APPLY_PORT_SEC, 50,
                      REGBIT_PORT_SEC_DROP" == 1", "drop;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_APPLY_PORT_SEC, 0,
                      "1", "output;");

    }
}

static void
skip_port_from_conntrack(struct ovn_datapath *od, struct ovn_port *op,
                         enum ovn_stage in_stage, enum ovn_stage out_stage,
                         uint16_t priority, struct hmap *lflows)
{
    /* Can't use ct() for router ports. Consider the following configuration:
     * lp1(10.0.0.2) on hostA--ls1--lr0--ls2--lp2(10.0.1.2) on hostB, For a
     * ping from lp1 to lp2, First, the response will go through ct() with a
     * zone for lp2 in the ls2 ingress pipeline on hostB.  That ct zone knows
     * about this connection. Next, it goes through ct() with the zone for the
     * router port in the egress pipeline of ls2 on hostB.  This zone does not
     * know about the connection, as the icmp request went through the logical
     * router on hostA, not hostB. This would only work with distributed
     * conntrack state across all chassis. */
    struct ds match_in = DS_EMPTY_INITIALIZER;
    struct ds match_out = DS_EMPTY_INITIALIZER;

    ds_put_format(&match_in, "ip && inport == %s", op->json_key);
    ds_put_format(&match_out, "ip && outport == %s", op->json_key);
    ovn_lflow_add_with_lport_and_hint(lflows, od, in_stage, priority,
                                      ds_cstr(&match_in), "next;", op->key,
                                      &op->nbsp->header_);
    ovn_lflow_add_with_lport_and_hint(lflows, od, out_stage, priority,
                                      ds_cstr(&match_out), "next;", op->key,
                                      &op->nbsp->header_);

    ds_destroy(&match_in);
    ds_destroy(&match_out);
}

static void
build_stateless_filter(struct ovn_datapath *od,
                       const struct nbrec_acl *acl,
                       struct hmap *lflows)
{
    if (!strcmp(acl->direction, "from-lport")) {
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_PRE_ACL,
                                acl->priority + OVN_ACL_PRI_OFFSET,
                                acl->match,
                                "next;",
                                &acl->header_);
    } else {
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_OUT_PRE_ACL,
                                acl->priority + OVN_ACL_PRI_OFFSET,
                                acl->match,
                                "next;",
                                &acl->header_);
    }
}

static void
build_stateless_filters(struct ovn_datapath *od,
                        const struct hmap *port_groups,
                        struct hmap *lflows)
{
    for (size_t i = 0; i < od->nbs->n_acls; i++) {
        const struct nbrec_acl *acl = od->nbs->acls[i];
        if (!strcmp(acl->action, "allow-stateless")) {
            build_stateless_filter(od, acl, lflows);
        }
    }

    struct ovn_port_group *pg;
    HMAP_FOR_EACH (pg, key_node, port_groups) {
        if (ovn_port_group_ls_find(pg, &od->nbs->header_.uuid)) {
            for (size_t i = 0; i < pg->nb_pg->n_acls; i++) {
                const struct nbrec_acl *acl = pg->nb_pg->acls[i];
                if (!strcmp(acl->action, "allow-stateless")) {
                    build_stateless_filter(od, acl, lflows);
                }
            }
        }
    }
}

static void
build_pre_acls(struct ovn_datapath *od, const struct hmap *port_groups,
               struct hmap *lflows)
{
    /* Ingress and Egress Pre-ACL Table (Priority 0): Packets are
     * allowed by default. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_ACL, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_ACL, 0, "1", "next;");

    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_ACL, 110,
                  "eth.dst == $svc_monitor_mac", "next;");

    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_ACL, 110,
                  "eth.src == $svc_monitor_mac", "next;");

    /* If there are any stateful ACL rules in this datapath, we may
     * send IP packets for some (allow) filters through the conntrack action,
     * which handles defragmentation, in order to match L4 headers. */
    if (od->has_stateful_acl) {
        for (size_t i = 0; i < od->n_router_ports; i++) {
            skip_port_from_conntrack(od, od->router_ports[i],
                                     S_SWITCH_IN_PRE_ACL, S_SWITCH_OUT_PRE_ACL,
                                     110, lflows);
        }
        for (size_t i = 0; i < od->n_localnet_ports; i++) {
            skip_port_from_conntrack(od, od->localnet_ports[i],
                                     S_SWITCH_IN_PRE_ACL, S_SWITCH_OUT_PRE_ACL,
                                     110, lflows);
        }

        /* stateless filters always take precedence over stateful ACLs. */
        build_stateless_filters(od, port_groups, lflows);

        /* Ingress and Egress Pre-ACL Table (Priority 110).
         *
         * Not to do conntrack on ND and ICMP destination
         * unreachable packets. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_ACL, 110,
                      "nd || nd_rs || nd_ra || mldv1 || mldv2 || "
                      "(udp && udp.src == 546 && udp.dst == 547)", "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_ACL, 110,
                      "nd || nd_rs || nd_ra || mldv1 || mldv2 || "
                      "(udp && udp.src == 546 && udp.dst == 547)", "next;");

        /* Do not send multicast packets to conntrack. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_ACL, 110, "eth.mcast",
                      "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_ACL, 110, "eth.mcast",
                      "next;");

        /* Ingress and Egress Pre-ACL Table (Priority 100).
         *
         * Regardless of whether the ACL is "from-lport" or "to-lport",
         * we need rules in both the ingress and egress table, because
         * the return traffic needs to be followed.
         *
         * 'REGBIT_CONNTRACK_DEFRAG' is set to let the pre-stateful table send
         * it to conntrack for tracking and defragmentation. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_ACL, 100, "ip",
                      REGBIT_CONNTRACK_DEFRAG" = 1; next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_ACL, 100, "ip",
                      REGBIT_CONNTRACK_DEFRAG" = 1; next;");
    }
}

/*
 * Returns true if logical switch is configured with DNS records, false
 * otherwise.
 */
static bool
ls_has_dns_records(const struct nbrec_logical_switch *nbs)
{
    for (size_t i = 0; i < nbs->n_dns_records; i++) {
        if (!smap_is_empty(&nbs->dns_records[i]->records)) {
            return true;
        }
    }

    return false;
}

static bool
build_empty_lb_event_flow(struct ovn_lb_vip *lb_vip,
                          const struct ovn_northd_lb *lb,
                          struct ds *match, struct ds *action)
{
    bool controller_event = lb->controller_event ||
                            controller_event_en; /* deprecated */
    if (!controller_event || lb_vip->n_backends ||
        lb_vip->empty_backend_rej) {
        return false;
    }

    ds_clear(action);
    ds_clear(match);

    bool ipv4 = lb_vip->address_family == AF_INET;

    ds_put_format(match, "ip%s.dst == %s && %s",
                  ipv4 ? "4": "6", lb_vip->vip_str, lb->proto);

    char *vip = lb_vip->vip_str;
    if (lb_vip->port_str) {
        ds_put_format(match, " && %s.dst == %s", lb->proto, lb_vip->port_str);
        vip = xasprintf("%s%s%s:%s", ipv4 ? "" : "[", lb_vip->vip_str,
                        ipv4 ? "" : "]", lb_vip->port_str);
    }

    ds_put_format(action,
                  "trigger_event(event = \"%s\", "
                  "vip = \"%s\", "
                  "protocol = \"%s\", "
                  "load_balancer = \"" UUID_FMT "\");",
                  event_to_string(OVN_EVENT_EMPTY_LB_BACKENDS),
                  vip, lb->proto,
                  UUID_ARGS(&lb->nlb->header_.uuid));
    if (lb_vip->port_str) {
        free(vip);
    }
    return true;
}

static void
build_interconn_mcast_snoop_flows(struct ovn_datapath *od,
                                  const struct shash *meter_groups,
                                  struct hmap *lflows)
{
    struct mcast_switch_info *mcast_sw_info = &od->mcast_info.sw;
    if (!mcast_sw_info->enabled
        || !smap_get(&od->nbs->other_config, "interconn-ts")) {
        return;
    }

    struct ovn_port *op;

    LIST_FOR_EACH (op, dp_node, &od->port_list) {
        if (!lsp_is_remote(op->nbsp)) {
            continue;
        }
        /* Punt IGMP traffic to controller. */
        char *match = xasprintf("inport == %s && igmp", op->json_key);
        ovn_lflow_metered(lflows, od, S_SWITCH_OUT_PRE_LB, 120, match,
                          "clone { igmp; }; next;",
                          copp_meter_get(COPP_IGMP, od->nbs->copp,
                                         meter_groups));
        free(match);

        /* Punt MLD traffic to controller. */
        match = xasprintf("inport == %s && (mldv1 || mldv2)", op->json_key);
        ovn_lflow_metered(lflows, od, S_SWITCH_OUT_PRE_LB, 120, match,
                          "clone { igmp; }; next;",
                          copp_meter_get(COPP_IGMP, od->nbs->copp,
                                         meter_groups));
        free(match);
    }
}

static void
build_pre_lb(struct ovn_datapath *od, const struct shash *meter_groups,
             struct hmap *lflows)
{
    /* Handle IGMP/MLD packets crossing AZs. */
    build_interconn_mcast_snoop_flows(od, meter_groups, lflows);

    /* Do not send multicast packets to conntrack */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_LB, 110, "eth.mcast", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_LB, 110, "eth.mcast", "next;");

    /* Do not send ND packets to conntrack */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_LB, 110,
                  "nd || nd_rs || nd_ra || mldv1 || mldv2",
                  "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_LB, 110,
                  "nd || nd_rs || nd_ra || mldv1 || mldv2",
                  "next;");

    /* Do not send service monitor packets to conntrack. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_LB, 110,
                  "eth.dst == $svc_monitor_mac", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_LB, 110,
                  "eth.src == $svc_monitor_mac", "next;");

    /* Allow all packets to go to next tables by default. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_LB, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_LB, 0, "1", "next;");

    for (size_t i = 0; i < od->n_router_ports; i++) {
        skip_port_from_conntrack(od, od->router_ports[i],
                                 S_SWITCH_IN_PRE_LB, S_SWITCH_OUT_PRE_LB,
                                 110, lflows);
    }
    for (size_t i = 0; i < od->n_localnet_ports; i++) {
        skip_port_from_conntrack(od, od->localnet_ports[i],
                                 S_SWITCH_IN_PRE_LB, S_SWITCH_OUT_PRE_LB,
                                 110, lflows);
    }

    /* 'REGBIT_CONNTRACK_NAT' is set to let the pre-stateful table send
     * packet to conntrack for defragmentation and possibly for unNATting.
     *
     * Send all the packets to conntrack in the ingress pipeline if the
     * logical switch has a load balancer with VIP configured. Earlier
     * we used to set the REGBIT_CONNTRACK_DEFRAG flag in the ingress
     * pipeline if the IP destination matches the VIP. But this causes
     * few issues when a logical switch has no ACLs configured with
     * allow-related.
     * To understand the issue, lets a take a TCP load balancer -
     * 10.0.0.10:80=10.0.0.3:80.
     * If a logical port - p1 with IP - 10.0.0.5 opens a TCP connection
     * with the VIP - 10.0.0.10, then the packet in the ingress pipeline
     * of 'p1' is sent to the p1's conntrack zone id and the packet is
     * load balanced to the backend - 10.0.0.3. For the reply packet from
     * the backend lport, it is not sent to the conntrack of backend
     * lport's zone id. This is fine as long as the packet is valid.
     * Suppose the backend lport sends an invalid TCP packet (like
     * incorrect sequence number), the packet gets * delivered to the
     * lport 'p1' without unDNATing the packet to the VIP - 10.0.0.10.
     * And this causes the connection to be reset by the lport p1's VIF.
     *
     * We can't fix this issue by adding a logical flow to drop ct.inv
     * packets in the egress pipeline since it will drop all other
     * connections not destined to the load balancers.
     *
     * To fix this issue, we send all the packets to the conntrack in the
     * ingress pipeline if a load balancer is configured. We can now
     * add a lflow to drop ct.inv packets.
     */
    if (od->has_lb_vip) {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_LB,
                      100, "ip", REGBIT_CONNTRACK_NAT" = 1; next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_LB,
                      100, "ip", REGBIT_CONNTRACK_NAT" = 1; next;");
    }
}

static void
build_pre_stateful(struct ovn_datapath *od,
                   const struct chassis_features *features,
                   struct hmap *lflows)
{
    /* Ingress and Egress pre-stateful Table (Priority 0): Packets are
     * allowed by default. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_STATEFUL, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_STATEFUL, 0, "1", "next;");

    /* Note: priority-120 flows are added in build_lb_rules_pre_stateful(). */

    const char *ct_lb_action = features->ct_no_masked_label
                               ? "ct_lb_mark;"
                               : "ct_lb;";

    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_STATEFUL, 110,
                  REGBIT_CONNTRACK_NAT" == 1", ct_lb_action);

    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_STATEFUL, 110,
                  REGBIT_CONNTRACK_NAT" == 1", ct_lb_action);

    /* If REGBIT_CONNTRACK_DEFRAG is set as 1, then the packets should be
     * sent to conntrack for tracking and defragmentation. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_STATEFUL, 100,
                  REGBIT_CONNTRACK_DEFRAG" == 1", "ct_next;");

    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_STATEFUL, 100,
                  REGBIT_CONNTRACK_DEFRAG" == 1", "ct_next;");

}

static void
build_acl_hints(struct ovn_datapath *od,
                const struct chassis_features *features,
                struct hmap *lflows)
{
    /* This stage builds hints for the IN/OUT_ACL stage. Based on various
     * combinations of ct flags packets may hit only a subset of the logical
     * flows in the IN/OUT_ACL stage.
     *
     * Populating ACL hints first and storing them in registers simplifies
     * the logical flow match expressions in the IN/OUT_ACL stage and
     * generates less openflows.
     *
     * Certain combinations of ct flags might be valid matches for multiple
     * types of ACL logical flows (e.g., allow/drop). In such cases hints
     * corresponding to all potential matches are set.
     */

    enum ovn_stage stages[] = {
        S_SWITCH_IN_ACL_HINT,
        S_SWITCH_OUT_ACL_HINT,
    };

    for (size_t i = 0; i < ARRAY_SIZE(stages); i++) {
        enum ovn_stage stage = stages[i];
        const char *match;

        /* In any case, advance to the next stage. */
        if (!od->has_acls && !od->has_lb_vip) {
            ovn_lflow_add(lflows, od, stage, UINT16_MAX, "1", "next;");
        } else {
            ovn_lflow_add(lflows, od, stage, 0, "1", "next;");
        }

        if (!od->has_stateful_acl && !od->has_lb_vip) {
            continue;
        }

        /* New, not already established connections, may hit either allow
         * or drop ACLs. For allow ACLs, the connection must also be committed
         * to conntrack so we set REGBIT_ACL_HINT_ALLOW_NEW.
         */
        ovn_lflow_add(lflows, od, stage, 7, "ct.new && !ct.est",
                      REGBIT_ACL_HINT_ALLOW_NEW " = 1; "
                      REGBIT_ACL_HINT_DROP " = 1; "
                      "next;");

        /* Already established connections in the "request" direction that
         * are already marked as "blocked" may hit either:
         * - allow ACLs for connections that were previously allowed by a
         *   policy that was deleted and is being readded now. In this case
         *   the connection should be recommitted so we set
         *   REGBIT_ACL_HINT_ALLOW_NEW.
         * - drop ACLs.
         */
        match = features->ct_no_masked_label
                ? "!ct.new && ct.est && !ct.rpl && ct_mark.blocked == 1"
                : "!ct.new && ct.est && !ct.rpl && ct_label.blocked == 1";
        ovn_lflow_add(lflows, od, stage, 6, match,
                      REGBIT_ACL_HINT_ALLOW_NEW " = 1; "
                      REGBIT_ACL_HINT_DROP " = 1; "
                      "next;");

        /* Not tracked traffic can either be allowed or dropped. */
        ovn_lflow_add(lflows, od, stage, 5, "!ct.trk",
                      REGBIT_ACL_HINT_ALLOW " = 1; "
                      REGBIT_ACL_HINT_DROP " = 1; "
                      "next;");

        /* Already established connections in the "request" direction may hit
         * either:
         * - allow ACLs in which case the traffic should be allowed so we set
         *   REGBIT_ACL_HINT_ALLOW.
         * - drop ACLs in which case the traffic should be blocked and the
         *   connection must be committed with ct_mark.blocked set so we set
         *   REGBIT_ACL_HINT_BLOCK.
         */
        match = features->ct_no_masked_label
                ? "!ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0"
                : "!ct.new && ct.est && !ct.rpl && ct_label.blocked == 0";
        ovn_lflow_add(lflows, od, stage, 4, match,
                      REGBIT_ACL_HINT_ALLOW " = 1; "
                      REGBIT_ACL_HINT_BLOCK " = 1; "
                      "next;");

        /* Not established or established and already blocked connections may
         * hit drop ACLs.
         */
        ovn_lflow_add(lflows, od, stage, 3, "!ct.est",
                      REGBIT_ACL_HINT_DROP " = 1; "
                      "next;");
        match = features->ct_no_masked_label
                ? "ct.est && ct_mark.blocked == 1"
                : "ct.est && ct_label.blocked == 1";
        ovn_lflow_add(lflows, od, stage, 2, match,
                      REGBIT_ACL_HINT_DROP " = 1; "
                      "next;");

        /* Established connections that were previously allowed might hit
         * drop ACLs in which case the connection must be committed with
         * ct_mark.blocked set.
         */
        match = features->ct_no_masked_label
                ? "ct.est && ct_mark.blocked == 0"
                : "ct.est && ct_label.blocked == 0";
        ovn_lflow_add(lflows, od, stage, 1, match,
                      REGBIT_ACL_HINT_BLOCK " = 1; "
                      "next;");
    }
}

static const struct nbrec_meter*
fair_meter_lookup_by_name(const struct shash *meter_groups,
                          const char *meter_name)
{
    const struct nbrec_meter *nb_meter =
        meter_name ? shash_find_data(meter_groups, meter_name) : NULL;
    if (nb_meter) {
        return (nb_meter->fair && *nb_meter->fair) ? nb_meter : NULL;
    }
    return NULL;
}

static char*
alloc_acl_log_unique_meter_name(const struct nbrec_acl *acl)
{
    return xasprintf("%s__" UUID_FMT,
                     acl->meter, UUID_ARGS(&acl->header_.uuid));
}

static void
build_acl_log_meter(struct ds *actions, const struct nbrec_acl *acl,
                    const struct shash *meter_groups)
{
    if (!acl->meter) {
        return;
    }

    /* If ACL log meter uses a fair meter, use unique Meter name. */
    if (fair_meter_lookup_by_name(meter_groups, acl->meter)) {
        char *meter_name = alloc_acl_log_unique_meter_name(acl);
        ds_put_format(actions, "meter=\"%s\", ", meter_name);
        free(meter_name);
    } else {
        ds_put_format(actions, "meter=\"%s\", ", acl->meter);
    }
}

static void
build_acl_log(struct ds *actions, const struct nbrec_acl *acl,
              const struct shash *meter_groups)
{
    if (!acl->log) {
        return;
    }

    ds_put_cstr(actions, "log(");

    if (acl->name) {
        ds_put_format(actions, "name=\"%s\", ", acl->name);
    }

    /* If a severity level isn't specified, default to "info". */
    if (acl->severity) {
        ds_put_format(actions, "severity=%s, ", acl->severity);
    } else {
        ds_put_format(actions, "severity=info, ");
    }

    if (!strcmp(acl->action, "drop")) {
        ds_put_cstr(actions, "verdict=drop, ");
    } else if (!strcmp(acl->action, "reject")) {
        ds_put_cstr(actions, "verdict=reject, ");
    } else if (!strcmp(acl->action, "allow")
        || !strcmp(acl->action, "allow-related")
        || !strcmp(acl->action, "allow-stateless")) {
        ds_put_cstr(actions, "verdict=allow, ");
    }

    build_acl_log_meter(actions, acl, meter_groups);

    ds_chomp(actions, ' ');
    ds_chomp(actions, ',');
    ds_put_cstr(actions, "); ");
}

static void
build_reject_acl_rules(struct ovn_datapath *od, struct hmap *lflows,
                       enum ovn_stage stage, struct nbrec_acl *acl,
                       struct ds *extra_match, struct ds *extra_actions,
                       const struct ovsdb_idl_row *stage_hint,
                       const struct shash *meter_groups)
{
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;
    bool ingress = (ovn_stage_get_pipeline(stage) == P_IN);

    char *next_action =
        xasprintf("next(pipeline=%s,table=%d);",
                  ingress ? "egress": "ingress",
                  ingress ? ovn_stage_get_table(S_SWITCH_OUT_QOS_MARK)
                          : ovn_stage_get_table(S_SWITCH_IN_L2_LKUP));

    build_acl_log(&actions, acl, meter_groups);
    if (extra_match->length > 0) {
        ds_put_format(&match, "(%s) && ", extra_match->string);
    }
    ds_put_cstr(&match, acl->match);

    if (extra_actions->length > 0) {
        ds_put_format(&actions, "%s ", extra_actions->string);
    }

    ds_put_format(&actions, "reg0 = 0; "
                  "reject { "
                  "/* eth.dst <-> eth.src; ip.dst <-> ip.src; is implicit. */ "
                  "outport <-> inport; %s };", next_action);
    ovn_lflow_add_with_hint__(lflows, od, stage,
                              acl->priority + OVN_ACL_PRI_OFFSET,
                              ds_cstr(&match), ds_cstr(&actions), NULL,
                              copp_meter_get(COPP_REJECT, od->nbs->copp,
                                             meter_groups),
                              stage_hint);

    free(next_action);
    ds_destroy(&match);
    ds_destroy(&actions);
}

static void
consider_acl(struct hmap *lflows, struct ovn_datapath *od,
             struct nbrec_acl *acl, bool has_stateful, bool ct_masked_mark,
             const struct shash *meter_groups, struct ds *match,
             struct ds *actions)
{
    const char *ct_blocked_match = ct_masked_mark
                                   ? "ct_mark.blocked"
                                   : "ct_label.blocked";
    bool ingress = !strcmp(acl->direction, "from-lport") ? true :false;
    enum ovn_stage stage;

    if (ingress && smap_get_bool(&acl->options, "apply-after-lb", false)) {
        stage = S_SWITCH_IN_ACL_AFTER_LB;
    } else if (ingress) {
        stage = S_SWITCH_IN_ACL;
    } else {
        stage = S_SWITCH_OUT_ACL;
    }

    if (!strcmp(acl->action, "allow-stateless")) {
        ds_clear(actions);
        build_acl_log(actions, acl, meter_groups);
        ds_put_cstr(actions, "next;");
        ovn_lflow_add_with_hint(lflows, od, stage,
                                acl->priority + OVN_ACL_PRI_OFFSET,
                                acl->match, ds_cstr(actions),
                                &acl->header_);
    } else if (!strcmp(acl->action, "allow")
        || !strcmp(acl->action, "allow-related")) {
        /* If there are any stateful flows, we must even commit "allow"
         * actions.  This is because, while the initiater's
         * direction may not have any stateful rules, the server's
         * may and then its return traffic would not have an
         * associated conntrack entry and would return "+invalid". */
        if (!has_stateful) {
            ds_clear(actions);
            build_acl_log(actions, acl, meter_groups);
            ds_put_cstr(actions, "next;");
            ovn_lflow_add_with_hint(lflows, od, stage,
                                    acl->priority + OVN_ACL_PRI_OFFSET,
                                    acl->match, ds_cstr(actions),
                                    &acl->header_);
        } else {
            /* Commit the connection tracking entry if it's a new
             * connection that matches this ACL.  After this commit,
             * the reply traffic is allowed by a flow we create at
             * priority 65535, defined earlier.
             *
             * It's also possible that a known connection was marked for
             * deletion after a policy was deleted, but the policy was
             * re-added while that connection is still known.  We catch
             * that case here and un-set ct_mark.blocked (which will be done
             * by ct_commit in the "stateful" stage) to indicate that the
             * connection should be allowed to resume.
             */
            ds_clear(match);
            ds_clear(actions);
            ds_put_format(match, REGBIT_ACL_HINT_ALLOW_NEW " == 1 && (%s)",
                          acl->match);

            ds_put_cstr(actions, REGBIT_CONNTRACK_COMMIT" = 1; ");
            if (acl->label) {
                ds_put_format(actions, REGBIT_ACL_LABEL" = 1; "
                              REG_LABEL" = %"PRId64"; ", acl->label);
            }
            build_acl_log(actions, acl, meter_groups);
            ds_put_cstr(actions, "next;");
            ovn_lflow_add_with_hint(lflows, od, stage,
                                    acl->priority + OVN_ACL_PRI_OFFSET,
                                    ds_cstr(match),
                                    ds_cstr(actions),
                                    &acl->header_);

            /* Match on traffic in the request direction for an established
             * connection tracking entry that has not been marked for
             * deletion. We use this to ensure that this
             * connection is still allowed by the currently defined
             * policy. Match untracked packets too.
             * Commit the connection only if the ACL has a label. This is done
             * to update the connection tracking entry label in case the ACL
             * allowing the connection changes. */
            ds_clear(match);
            ds_clear(actions);
            ds_put_format(match, REGBIT_ACL_HINT_ALLOW " == 1 && (%s)",
                          acl->match);
            if (acl->label) {
                ds_put_cstr(actions, REGBIT_CONNTRACK_COMMIT" = 1; ");
                ds_put_format(actions, REGBIT_ACL_LABEL" = 1; "
                              REG_LABEL" = %"PRId64"; ", acl->label);
            }
            build_acl_log(actions, acl, meter_groups);
            ds_put_cstr(actions, "next;");
            ovn_lflow_add_with_hint(lflows, od, stage,
                                    acl->priority + OVN_ACL_PRI_OFFSET,
                                    ds_cstr(match), ds_cstr(actions),
                                    &acl->header_);

            /* Related and reply traffic are universally allowed by priority
             * 65532 flows created in build_acls(). If logging is enabled on
             * the ACL, then we need to ensure that the related and reply
             * traffic is logged, so we install a slightly higher-priority
             * flow that matches the ACL, allows the traffic, and logs it.
             *
             * Note: Matching the ct_label.label may prevent OVS flow HW
             * offloading to work for some NICs because masked-access of
             * ct_label is not supported on those NICs due to HW
             * limitations. In such case the user may choose to avoid using the
             * "log-related" option.
             */
            bool log_related = smap_get_bool(&acl->options, "log-related",
                                             false);
            if (acl->log && acl->label && log_related) {
                /* Related/reply flows need to be set on the opposite pipeline
                 * from where the ACL itself is set.
                 */
                enum ovn_stage log_related_stage = ingress ?
                    S_SWITCH_OUT_ACL :
                    S_SWITCH_IN_ACL;
                ds_clear(match);
                ds_clear(actions);

                ds_put_format(match, "ct.est && !ct.rel && !ct.new%s && "
                              "ct.rpl && %s == 0 && "
                              "ct_label.label == %" PRId64,
                              use_ct_inv_match ? " && !ct.inv" : "",
                              ct_blocked_match, acl->label);
                build_acl_log(actions, acl, meter_groups);
                ds_put_cstr(actions, "next;");
                ovn_lflow_add_with_hint(lflows, od, log_related_stage,
                                        UINT16_MAX - 2,
                                        ds_cstr(match), ds_cstr(actions),
                                        &acl->header_);

                ds_clear(match);
                ds_put_format(match, "!ct.est && ct.rel && !ct.new%s && "
                                     "%s == 0 && "
                                     "ct_label.label == %" PRId64,
                                     use_ct_inv_match ? " && !ct.inv" : "",
                                     ct_blocked_match, acl->label);
                ovn_lflow_add_with_hint(lflows, od, log_related_stage,
                                        UINT16_MAX - 2,
                                        ds_cstr(match), ds_cstr(actions),
                                        &acl->header_);
            }

        }
    } else if (!strcmp(acl->action, "drop")
               || !strcmp(acl->action, "reject")) {
        /* The implementation of "drop" differs if stateful ACLs are in
         * use for this datapath.  In that case, the actions differ
         * depending on whether the connection was previously committed
         * to the connection tracker with ct_commit. */
        if (has_stateful) {
            /* If the packet is not tracked or not part of an established
             * connection, then we can simply reject/drop it. */
            ds_clear(match);
            ds_clear(actions);
            ds_put_cstr(match, REGBIT_ACL_HINT_DROP " == 1");
            if (!strcmp(acl->action, "reject")) {
                build_reject_acl_rules(od, lflows, stage, acl, match,
                                       actions, &acl->header_, meter_groups);
            } else {
                ds_put_format(match, " && (%s)", acl->match);
                build_acl_log(actions, acl, meter_groups);
                ds_put_cstr(actions, debug_implicit_drop_action());
                ovn_lflow_add_with_hint(lflows, od, stage,
                                        acl->priority + OVN_ACL_PRI_OFFSET,
                                        ds_cstr(match), ds_cstr(actions),
                                        &acl->header_);
            }
            /* For an existing connection without ct_mark.blocked set, we've
             * encountered a policy change. ACLs previously allowed
             * this connection and we committed the connection tracking
             * entry.  Current policy says that we should drop this
             * connection.  First, we set ct_mark.blocked to indicate
             * that this connection is set for deletion.  By not
             * specifying "next;", we implicitly drop the packet after
             * updating conntrack state.  We would normally defer
             * ct_commit() to the "stateful" stage, but since we're
             * rejecting/dropping the packet, we go ahead and do it here.
             */
            ds_clear(match);
            ds_clear(actions);
            ds_put_cstr(match, REGBIT_ACL_HINT_BLOCK " == 1");
            ds_put_format(actions, "ct_commit { %s = 1; }; ",
                          ct_blocked_match);
            if (!strcmp(acl->action, "reject")) {
                build_reject_acl_rules(od, lflows, stage, acl, match,
                                       actions, &acl->header_, meter_groups);
            } else {
                ds_put_format(match, " && (%s)", acl->match);
                build_acl_log(actions, acl, meter_groups);
                ds_put_cstr(actions, debug_implicit_drop_action());
                ovn_lflow_add_with_hint(lflows, od, stage,
                                        acl->priority + OVN_ACL_PRI_OFFSET,
                                        ds_cstr(match), ds_cstr(actions),
                                        &acl->header_);
            }
        } else {
            /* There are no stateful ACLs in use on this datapath,
             * so a "reject/drop" ACL is simply the "reject/drop"
             * logical flow action in all cases. */
            ds_clear(match);
            ds_clear(actions);
            if (!strcmp(acl->action, "reject")) {
                build_reject_acl_rules(od, lflows, stage, acl, match,
                                       actions, &acl->header_, meter_groups);
            } else {
                build_acl_log(actions, acl, meter_groups);
                ds_put_cstr(actions, debug_implicit_drop_action());
                ovn_lflow_add_with_hint(lflows, od, stage,
                                        acl->priority + OVN_ACL_PRI_OFFSET,
                                        acl->match, ds_cstr(actions),
                                        &acl->header_);
            }
        }
    }
}

static struct ovn_port_group *
ovn_port_group_create(struct hmap *pgs,
                      const struct nbrec_port_group *nb_pg)
{
    struct ovn_port_group *pg = xzalloc(sizeof *pg);
    pg->key = nb_pg->header_.uuid;
    pg->nb_pg = nb_pg;
    hmap_init(&pg->nb_lswitches);
    hmap_insert(pgs, &pg->key_node, uuid_hash(&pg->key));
    return pg;
}

static void
ovn_port_group_destroy(struct hmap *pgs, struct ovn_port_group *pg)
{
    if (pg) {
        hmap_remove(pgs, &pg->key_node);
        struct ovn_port_group_ls *ls;
        HMAP_FOR_EACH_POP (ls, key_node, &pg->nb_lswitches) {
            free(ls->ports);
            free(ls);
        }
        hmap_destroy(&pg->nb_lswitches);
        free(pg);
    }
}

static void
copy_ra_to_sb(struct ovn_port *op, const char *address_mode);

static void
ovn_update_ipv6_options(struct hmap *ports)
{
    struct ovn_port *op;
    HMAP_FOR_EACH (op, key_node, ports) {
        if (!op->nbrp || op->nbrp->peer || !op->peer) {
            continue;
        }

        if (!op->lrp_networks.n_ipv6_addrs) {
            continue;
        }

        struct smap options;
        smap_clone(&options, &op->sb->options);

        /* enable IPv6 prefix delegation */
        bool prefix_delegation = smap_get_bool(&op->nbrp->options,
                                           "prefix_delegation", false);
        if (!lrport_is_enabled(op->nbrp)) {
            prefix_delegation = false;
        }
        if (smap_get_bool(&options, "ipv6_prefix_delegation",
                          false) != prefix_delegation) {
            smap_add(&options, "ipv6_prefix_delegation",
                     prefix_delegation ? "true" : "false");
        }

        bool ipv6_prefix = smap_get_bool(&op->nbrp->options,
                                     "prefix", false);
        if (!lrport_is_enabled(op->nbrp)) {
            ipv6_prefix = false;
        }
        if (smap_get_bool(&options, "ipv6_prefix", false) != ipv6_prefix) {
            smap_add(&options, "ipv6_prefix",
                     ipv6_prefix ? "true" : "false");
        }
        sbrec_port_binding_set_options(op->sb, &options);

        smap_destroy(&options);

        const char *address_mode = smap_get(
            &op->nbrp->ipv6_ra_configs, "address_mode");

        if (!address_mode) {
            continue;
        }
        if (strcmp(address_mode, "slaac") &&
            strcmp(address_mode, "dhcpv6_stateful") &&
            strcmp(address_mode, "dhcpv6_stateless")) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "Invalid address mode [%s] defined",
                         address_mode);
            continue;
        }

        if (smap_get_bool(&op->nbrp->ipv6_ra_configs, "send_periodic",
                          false)) {
            copy_ra_to_sb(op, address_mode);
        }
    }
}

static void
build_port_group_lswitches(struct northd_input *input_data,
                           struct hmap *pgs,
                           struct hmap *ports)
{
    hmap_init(pgs);

    const struct nbrec_port_group *nb_pg;
    NBREC_PORT_GROUP_TABLE_FOR_EACH (nb_pg,
                                  input_data->nbrec_port_group_table) {
        struct ovn_port_group *pg = ovn_port_group_create(pgs, nb_pg);
        for (size_t i = 0; i < nb_pg->n_ports; i++) {
            struct ovn_port *op = ovn_port_find(ports, nb_pg->ports[i]->name);
            if (!op) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_ERR_RL(&rl, "lport %s in port group %s not found.",
                            nb_pg->ports[i]->name,
                            nb_pg->name);
                continue;
            }

            if (!op->od->nbs) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "lport %s in port group %s has no lswitch.",
                             nb_pg->ports[i]->name,
                             nb_pg->name);
                continue;
            }

            struct ovn_port_group_ls *pg_ls =
                ovn_port_group_ls_find(pg, &op->od->nbs->header_.uuid);
            if (!pg_ls) {
                pg_ls = ovn_port_group_ls_add(pg, op->od);
                ovn_ls_port_group_add(&op->od->nb_pgs, nb_pg);
            }
            ovn_port_group_ls_add_port(pg_ls, op);
        }
    }
}

static void
build_acls(struct ovn_datapath *od, const struct chassis_features *features,
           struct hmap *lflows, const struct hmap *port_groups,
           const struct shash *meter_groups)
{
    const char *default_acl_action = default_acl_drop ? "drop;" : "next;";
    bool has_stateful = od->has_stateful_acl || od->has_lb_vip;
    const char *ct_blocked_match = features->ct_no_masked_label
                                   ? "ct_mark.blocked"
                                   : "ct_label.blocked";
    struct ds match   = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    /* Ingress and Egress ACL Table (Priority 0): Packets are allowed by
     * default.  If the logical switch has no ACLs or no load balancers,
     * then add 65535-priority flow to advance the packet to next
     * stage.
     *
     * A related rule at priority 1 is added below if there
     * are any stateful ACLs in this datapath. */
    if (!od->has_acls) {
        if (!od->has_lb_vip) {
            ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, UINT16_MAX, "1",
                          "next;");
            ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, UINT16_MAX, "1",
                          "next;");
        } else {
            ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, 0, "1", "next;");
            ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, 0, "1", "next;");
        }
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_AFTER_LB, 0, "1", "next;");
    } else {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, 0, "1",
                      default_acl_action);
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, 0, "1",
                      default_acl_action);
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_AFTER_LB, 0, "1",
                      default_acl_action);
    }


    if (has_stateful) {
        /* Ingress and Egress ACL Table (Priority 1).
         *
         * By default, traffic is allowed (if default_acl_drop is 'false') or
         * dropped (if default_acl_drop is 'true').  This is partially
         * handled by the Priority 0 ACL flows added earlier, but we also
         * need to commit IP flows.  This is because, while the initiater's
         * direction may not have any stateful rules, the server's may
         * and then its return traffic would not have an associated
         * conntrack entry and would return "+invalid".
         *
         * We use "ct_commit" for a connection that is not already known
         * by the connection tracker.  Once a connection is committed,
         * subsequent packets will hit the flow at priority 0 that just
         * uses "next;"
         *
         * We also check for established connections that have ct_mark.blocked
         * set on them.  That's a connection that was disallowed, but is
         * now allowed by policy again since it hit this default-allow flow.
         * We need to set ct_mark.blocked=0 to let the connection continue,
         * which will be done by ct_commit() in the "stateful" stage.
         * Subsequent packets will hit the flow at priority 0 that just
         * uses "next;". */
        ds_clear(&match);
        ds_put_format(&match, "ip && ct.est && %s == 1", ct_blocked_match);
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, 1,
                      ds_cstr(&match),
                      REGBIT_CONNTRACK_COMMIT" = 1; next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, 1,
                      ds_cstr(&match),
                      REGBIT_CONNTRACK_COMMIT" = 1; next;");

        default_acl_action = default_acl_drop
                             ? "drop;"
                             : REGBIT_CONNTRACK_COMMIT" = 1; next;";
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, 1, "ip && !ct.est",
                      default_acl_action);
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, 1, "ip && !ct.est",
                      default_acl_action);

        /* Ingress and Egress ACL Table (Priority 65532).
         *
         * Always drop traffic that's in an invalid state.  Also drop
         * reply direction packets for connections that have been marked
         * for deletion (ct_mark.blocked is set).
         *
         * This is enforced at a higher priority than ACLs can be defined. */
        ds_clear(&match);
        ds_put_format(&match, "%s(ct.est && ct.rpl && %s == 1)",
                      use_ct_inv_match ? "ct.inv || " : "",
                      ct_blocked_match);
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, UINT16_MAX - 3,
                      ds_cstr(&match), debug_drop_action());
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, UINT16_MAX - 3,
                      ds_cstr(&match),  debug_drop_action());

        /* Ingress and Egress ACL Table (Priority 65535 - 3).
         *
         * Allow reply traffic that is part of an established
         * conntrack entry that has not been marked for deletion
         * (ct_mark.blocked).  We only match traffic in the
         * reply direction because we want traffic in the request
         * direction to hit the currently defined policy from ACLs.
         *
         * This is enforced at a higher priority than ACLs can be defined. */
        ds_clear(&match);
        ds_put_format(&match, "ct.est && !ct.rel && !ct.new%s && "
                      "ct.rpl && %s == 0",
                      use_ct_inv_match ? " && !ct.inv" : "",
                      ct_blocked_match);
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, UINT16_MAX - 3,
                      ds_cstr(&match), REGBIT_ACL_HINT_DROP" = 0; "
                      REGBIT_ACL_HINT_BLOCK" = 0; next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, UINT16_MAX - 3,
                      ds_cstr(&match), "next;");

        /* Ingress and Egress ACL Table (Priority 65535).
         *
         * Allow traffic that is related to an existing conntrack entry that
         * has not been marked for deletion (ct_mark.blocked). At the same
         * time apply NAT on this traffic.
         *
         * This is enforced at a higher priority than ACLs can be defined.
         *
         * NOTE: This does not support related data sessions (eg,
         * a dynamically negotiated FTP data channel), but will allow
         * related traffic such as an ICMP Port Unreachable through
         * that's generated from a non-listening UDP port.  */
        ds_clear(&match);
        ds_put_format(&match, "!ct.est && ct.rel && !ct.new%s && %s == 0",
                      use_ct_inv_match ? " && !ct.inv" : "",
                      ct_blocked_match);
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, UINT16_MAX - 3,
                      ds_cstr(&match), "ct_commit_nat;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, UINT16_MAX - 3,
                      ds_cstr(&match), "ct_commit_nat;");

        /* Ingress and Egress ACL Table (Priority 65532).
         *
         * Not to do conntrack on ND packets. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, UINT16_MAX - 3,
                      "nd || nd_ra || nd_rs || mldv1 || mldv2", "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, UINT16_MAX - 3,
                      "nd || nd_ra || nd_rs || mldv1 || mldv2", "next;");
    }

    /* Ingress or Egress ACL Table (Various priorities). */
    for (size_t i = 0; i < od->nbs->n_acls; i++) {
        struct nbrec_acl *acl = od->nbs->acls[i];
        consider_acl(lflows, od, acl, has_stateful,
                     features->ct_no_masked_label,
                     meter_groups, &match, &actions);
    }
    struct ovn_port_group *pg;
    HMAP_FOR_EACH (pg, key_node, port_groups) {
        if (ovn_port_group_ls_find(pg, &od->nbs->header_.uuid)) {
            for (size_t i = 0; i < pg->nb_pg->n_acls; i++) {
                consider_acl(lflows, od, pg->nb_pg->acls[i], has_stateful,
                             features->ct_no_masked_label,
                             meter_groups, &match, &actions);
            }
        }
    }

    /* Add 34000 priority flow to allow DHCP reply from ovn-controller to all
     * logical ports of the datapath if the CMS has configured DHCPv4 options.
     * */
    for (size_t i = 0; i < od->nbs->n_ports; i++) {
        if (lsp_is_external(od->nbs->ports[i])) {
            continue;
        }

        if (od->nbs->ports[i]->dhcpv4_options) {
            const char *server_id = smap_get(
                &od->nbs->ports[i]->dhcpv4_options->options, "server_id");
            const char *server_mac = smap_get(
                &od->nbs->ports[i]->dhcpv4_options->options, "server_mac");
            const char *lease_time = smap_get(
                &od->nbs->ports[i]->dhcpv4_options->options, "lease_time");
            if (server_id && server_mac && lease_time) {
                const char *dhcp_actions =
                    has_stateful ? "ct_commit; next;" : "next;";
                ds_clear(&match);
                ds_put_format(&match, "outport == \"%s\" && eth.src == %s "
                              "&& ip4.src == %s && udp && udp.src == 67 "
                              "&& udp.dst == 68", od->nbs->ports[i]->name,
                              server_mac, server_id);
                ovn_lflow_add_with_lport_and_hint(
                    lflows, od, S_SWITCH_OUT_ACL, 34000, ds_cstr(&match),
                    dhcp_actions, od->nbs->ports[i]->name,
                    &od->nbs->ports[i]->dhcpv4_options->header_);
            }
        }

        if (od->nbs->ports[i]->dhcpv6_options) {
            const char *server_mac = smap_get(
                &od->nbs->ports[i]->dhcpv6_options->options, "server_id");
            struct eth_addr ea;
            if (server_mac && eth_addr_from_string(server_mac, &ea)) {
                /* Get the link local IP of the DHCPv6 server from the
                 * server MAC. */
                struct in6_addr lla;
                in6_generate_lla(ea, &lla);

                char server_ip[INET6_ADDRSTRLEN + 1];
                ipv6_string_mapped(server_ip, &lla);

                const char *dhcp6_actions = has_stateful ? "ct_commit; next;" :
                    "next;";
                ds_clear(&match);
                ds_put_format(&match, "outport == \"%s\" && eth.src == %s "
                              "&& ip6.src == %s && udp && udp.src == 547 "
                              "&& udp.dst == 546", od->nbs->ports[i]->name,
                              server_mac, server_ip);
                ovn_lflow_add_with_lport_and_hint(
                    lflows, od, S_SWITCH_OUT_ACL, 34000, ds_cstr(&match),
                    dhcp6_actions, od->nbs->ports[i]->name,
                    &od->nbs->ports[i]->dhcpv6_options->header_);
            }
        }
    }

    /* Add a 34000 priority flow to advance the DNS reply from ovn-controller,
     * if the CMS has configured DNS records for the datapath.
     */
    if (ls_has_dns_records(od->nbs)) {
        const char *dns_actions = has_stateful ? "ct_commit; next;" : "next;";
        ovn_lflow_add(
            lflows, od, S_SWITCH_OUT_ACL, 34000, "udp.src == 53",
            dns_actions);
    }

    if (od->has_acls || od->has_lb_vip) {
        /* Add a 34000 priority flow to advance the service monitor reply
        * packets to skip applying ingress ACLs. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, 34000,
                    "eth.dst == $svc_monitor_mac", "next;");

        /* Add a 34000 priority flow to advance the service monitor packets
        * generated by ovn-controller to skip applying egress ACLs. */
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, 34000,
                    "eth.src == $svc_monitor_mac", "next;");
    }

    ds_destroy(&match);
    ds_destroy(&actions);
}

static void
build_qos(struct ovn_datapath *od, struct hmap *lflows) {
    struct ds action = DS_EMPTY_INITIALIZER;

    ovn_lflow_add(lflows, od, S_SWITCH_IN_QOS_MARK, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_QOS_MARK, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_IN_QOS_METER, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_QOS_METER, 0, "1", "next;");

    for (size_t i = 0; i < od->nbs->n_qos_rules; i++) {
        struct nbrec_qos *qos = od->nbs->qos_rules[i];
        bool ingress = !strcmp(qos->direction, "from-lport") ? true :false;
        enum ovn_stage stage = ingress ? S_SWITCH_IN_QOS_MARK : S_SWITCH_OUT_QOS_MARK;
        int64_t rate = 0;
        int64_t burst = 0;

        for (size_t j = 0; j < qos->n_action; j++) {
            if (!strcmp(qos->key_action[j], "dscp")) {
                ds_clear(&action);
                ds_put_format(&action, "ip.dscp = %"PRId64"; next;",
                              qos->value_action[j]);
                ovn_lflow_add_with_hint(lflows, od, stage,
                                        qos->priority,
                                        qos->match, ds_cstr(&action),
                                        &qos->header_);
            }
        }

        for (size_t n = 0; n < qos->n_bandwidth; n++) {
            if (!strcmp(qos->key_bandwidth[n], "rate")) {
                rate = qos->value_bandwidth[n];
            } else if (!strcmp(qos->key_bandwidth[n], "burst")) {
                burst = qos->value_bandwidth[n];
            }
        }
        if (rate) {
            stage = ingress ? S_SWITCH_IN_QOS_METER : S_SWITCH_OUT_QOS_METER;
            ds_clear(&action);
            if (burst) {
                ds_put_format(&action,
                              "set_meter(%"PRId64", %"PRId64"); next;",
                              rate, burst);
            } else {
                ds_put_format(&action,
                              "set_meter(%"PRId64"); next;",
                              rate);
            }

            /* Ingress and Egress QoS Meter Table.
             *
             * We limit the bandwidth of this flow by adding a meter table.
             */
            ovn_lflow_add_with_hint(lflows, od, stage,
                                    qos->priority,
                                    qos->match, ds_cstr(&action),
                                    &qos->header_);
        }
    }
    ds_destroy(&action);
}

static void
build_lb_rules_pre_stateful(struct hmap *lflows, struct ovn_northd_lb *lb,
                            bool ct_lb_mark, struct ds *match,
                            struct ds *action)
{
    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_lb_vip *lb_vip = &lb->vips[i];
        ds_clear(action);
        ds_clear(match);
        const char *ip_match = NULL;

        /* Store the original destination IP to be used when generating
         * hairpin flows.
         */
        if (lb->vips[i].address_family == AF_INET) {
            ip_match = "ip4";
            ds_put_format(action, REG_ORIG_DIP_IPV4 " = %s; ",
                          lb_vip->vip_str);
        } else {
            ip_match = "ip6";
            ds_put_format(action, REG_ORIG_DIP_IPV6 " = %s; ",
                          lb_vip->vip_str);
        }

        const char *proto = NULL;
        if (lb_vip->port_str) {
            proto = "tcp";
            if (lb->nlb->protocol) {
                if (!strcmp(lb->nlb->protocol, "udp")) {
                    proto = "udp";
                } else if (!strcmp(lb->nlb->protocol, "sctp")) {
                    proto = "sctp";
                }
            }

            /* Store the original destination port to be used when generating
             * hairpin flows.
             */
            ds_put_format(action, REG_ORIG_TP_DPORT " = %s; ",
                          lb_vip->port_str);
        }
        ds_put_format(action, "%s;", ct_lb_mark ? "ct_lb_mark" : "ct_lb");

        ds_put_format(match, "%s.dst == %s", ip_match, lb_vip->vip_str);
        if (lb_vip->port_str) {
            ds_put_format(match, " && %s.dst == %s", proto, lb_vip->port_str);
        }

        struct ovn_lflow *lflow_ref = NULL;
        uint32_t hash = ovn_logical_flow_hash(
                ovn_stage_get_table(S_SWITCH_IN_PRE_STATEFUL),
                ovn_stage_get_pipeline(S_SWITCH_IN_PRE_STATEFUL), 120,
                ds_cstr(match), ds_cstr(action));

        for (size_t j = 0; j < lb->n_nb_ls; j++) {
            struct ovn_datapath *od = lb->nb_ls[j];

            if (!ovn_dp_group_add_with_reference(lflow_ref, od)) {
                lflow_ref = ovn_lflow_add_at_with_hash(
                        lflows, od, S_SWITCH_IN_PRE_STATEFUL, 120,
                        ds_cstr(match), ds_cstr(action),
                        NULL, NULL, &lb->nlb->header_,
                        OVS_SOURCE_LOCATOR, hash);
            }
        }
    }
}

/* Builds the logical router flows related to load balancer affinity.
 * For a LB configured with 'vip=V:VP' and backends 'B1:BP1,B2:BP2' and
 * affinity timeout set to T, it generates the following logical flows:
 * - load balancing affinity check:
 *   table=lr_in_lb_aff_check, priority=100
 *      match=(new_lb_match)
 *      action=(REGBIT_KNOWN_LB_SESSION = chk_lb_aff(); next;)
 *
 * - load balancing:
 *   table=lr_in_dnat, priority=150
 *      match=(REGBIT_KNOWN_LB_SESSION == 1 && ct.new && ip4
 *             && REG_LB_AFF_BACKEND_IP4 == B1 && REG_LB_AFF_MATCH_PORT == BP1)
 *      action=(REG_NEXT_HOP_IPV4 = V; lb_action;
 *              ct_lb_mark(backends=B1:BP1);)
 *   table=lr_in_dnat, priority=150
 *      match=(REGBIT_KNOWN_LB_SESSION == 1 && ct.new && ip4
 *             && REG_LB_AFF_BACKEND_IP4 == B2 && REG_LB_AFF_MATCH_PORT == BP2)
 *      action=(REG_NEXT_HOP_IPV4 = V; lb_action;
 *              ct_lb_mark(backends=B2:BP2);)
 *
 * - load balancing affinity learn:
 *   table=lr_in_lb_aff_learn, priority=100
 *      match=(REGBIT_KNOWN_LB_SESSION == 0
 *             && ct.new && ip4
 *             && REG_NEXT_HOP_IPV4 == V && REG_ORIG_TP_DPORT_ROUTER = VP
 *             && ip4.dst == B1 && tcp.dst == BP1)
 *      action=(commit_lb_aff(vip = "V:VP", backend = "B1:BP1",
 *                            proto = tcp, timeout = T));
 *   table=lr_in_lb_aff_learn, priority=100
 *      match=(REGBIT_KNOWN_LB_SESSION == 0
 *             && ct.new && ip4
 *             && REG_NEXT_HOP_IPV4 == V && REG_ORIG_TP_DPORT_ROUTER = VP
 *             && ip4.dst == B2 && tcp.dst == BP2)
 *      action=(commit_lb_aff(vip = "V:VP", backend = "B2:BP2",
 *                            proto = tcp, timeout = T));
 *
 */
static void
build_lb_affinity_lr_flows(struct hmap *lflows, struct ovn_northd_lb *lb,
                           struct ovn_lb_vip *lb_vip, char *new_lb_match,
                           char *lb_action, struct ovn_datapath **dplist,
                           int n_dplist)
{
    if (!lb->affinity_timeout) {
        return;
    }

    static char *aff_check = REGBIT_KNOWN_LB_SESSION" = chk_lb_aff(); next;";
    struct ovn_lflow *lflow_ref_aff_check = NULL;
    /* Check if we have already a enstablished connection for this
     * tuple and we are in affinity timeslot. */
    uint32_t hash_aff_check = ovn_logical_flow_hash(
            ovn_stage_get_table(S_ROUTER_IN_LB_AFF_CHECK),
            ovn_stage_get_pipeline(S_ROUTER_IN_LB_AFF_CHECK), 100,
            new_lb_match, aff_check);

    for (size_t i = 0; i < n_dplist; i++) {
        if (!ovn_dp_group_add_with_reference(lflow_ref_aff_check, dplist[i])) {
            lflow_ref_aff_check = ovn_lflow_add_at_with_hash(
                    lflows, dplist[i], S_ROUTER_IN_LB_AFF_CHECK, 100,
                    new_lb_match, aff_check, NULL, NULL, &lb->nlb->header_,
                    OVS_SOURCE_LOCATOR, hash_aff_check);
        }
    }

    struct ds aff_action = DS_EMPTY_INITIALIZER;
    struct ds aff_action_learn = DS_EMPTY_INITIALIZER;
    struct ds aff_match = DS_EMPTY_INITIALIZER;
    struct ds aff_match_learn = DS_EMPTY_INITIALIZER;

    bool ipv6 = !IN6_IS_ADDR_V4MAPPED(&lb_vip->vip);
    const char *ip_match = ipv6 ? "ip6" : "ip4";

    const char *reg_vip = ipv6 ? REG_NEXT_HOP_IPV6 : REG_NEXT_HOP_IPV4;
    const char *reg_backend =
        ipv6 ? REG_LB_L3_AFF_BACKEND_IP6 : REG_LB_AFF_BACKEND_IP4;

    /* Prepare common part of affinity LB and affinity learn action. */
    ds_put_format(&aff_action, "%s = %s; ", reg_vip, lb_vip->vip_str);
    ds_put_cstr(&aff_action_learn, "commit_lb_aff(vip = \"");

    if (lb_vip->vip_port) {
        ds_put_format(&aff_action_learn, ipv6 ? "[%s]:%"PRIu16 : "%s:%"PRIu16,
                      lb_vip->vip_str, lb_vip->vip_port);
    } else {
        ds_put_cstr(&aff_action_learn, lb_vip->vip_str);
    }

    if (lb_action) {
        ds_put_cstr(&aff_action, lb_action);
    }
    ds_put_cstr(&aff_action, "ct_lb_mark(backends=");
    ds_put_cstr(&aff_action_learn, "\", backend = \"");

    /* Prepare common part of affinity learn match. */
    if (lb_vip->vip_port) {
        ds_put_format(&aff_match_learn, REGBIT_KNOWN_LB_SESSION" == 0 && "
                      "ct.new && %s && %s == %s && "
                      REG_ORIG_TP_DPORT_ROUTER" == %"PRIu16" && "
                      "%s.dst == ", ip_match, reg_vip, lb_vip->vip_str,
                      lb_vip->vip_port, ip_match);
    } else {
        ds_put_format(&aff_match_learn, REGBIT_KNOWN_LB_SESSION" == 0 && "
                      "ct.new && %s && %s == %s && %s.dst == ", ip_match,
                      reg_vip, lb_vip->vip_str, ip_match);
    }

    /* Prepare common part of affinity match. */
    ds_put_format(&aff_match, REGBIT_KNOWN_LB_SESSION" == 1 && "
                  "ct.new && %s && %s == ", ip_match, reg_backend);

    /* Store the common part length. */
    size_t aff_action_len = aff_action.length;
    size_t aff_action_learn_len = aff_action_learn.length;
    size_t aff_match_len = aff_match.length;
    size_t aff_match_learn_len = aff_match_learn.length;


    for (size_t i = 0; i < lb_vip->n_backends; i++) {
        struct ovn_lb_backend *backend = &lb_vip->backends[i];

        ds_put_cstr(&aff_match_learn, backend->ip_str);
        ds_put_cstr(&aff_match, backend->ip_str);

        if (backend->port) {
            ds_put_format(&aff_action, ipv6 ? "[%s]:%d" : "%s:%d",
                          backend->ip_str, backend->port);
            ds_put_format(&aff_action_learn, ipv6 ? "[%s]:%d" : "%s:%d",
                          backend->ip_str, backend->port);

            ds_put_format(&aff_match_learn, " && %s.dst == %d",
                          lb->proto, backend->port);
            ds_put_format(&aff_match, " && "REG_LB_AFF_MATCH_PORT" == %d",
                          backend->port);
        } else {
            ds_put_cstr(&aff_action, backend->ip_str);
            ds_put_cstr(&aff_action_learn, backend->ip_str);
        }

        ds_put_cstr(&aff_action, ");");
        ds_put_char(&aff_action_learn, '"');

        if (lb_vip->vip_port) {
            ds_put_format(&aff_action_learn, ", proto = %s", lb->proto);
        }

        ds_put_format(&aff_action_learn, ", timeout = %d); /* drop */",
                      lb->affinity_timeout);

        struct ovn_lflow *lflow_ref_aff_learn = NULL;
        uint32_t hash_aff_learn = ovn_logical_flow_hash(
                ovn_stage_get_table(S_ROUTER_IN_LB_AFF_LEARN),
                ovn_stage_get_pipeline(S_ROUTER_IN_LB_AFF_LEARN),
                100, ds_cstr(&aff_match_learn), ds_cstr(&aff_action_learn));

        struct ovn_lflow *lflow_ref_aff_lb = NULL;
        uint32_t hash_aff_lb = ovn_logical_flow_hash(
                ovn_stage_get_table(S_ROUTER_IN_DNAT),
                ovn_stage_get_pipeline(S_ROUTER_IN_DNAT),
                150, ds_cstr(&aff_match), ds_cstr(&aff_action));

        for (size_t j = 0; j < n_dplist; j++) {
            /* Forward to OFTABLE_CHK_LB_AFFINITY table to store flow tuple. */
            if (!ovn_dp_group_add_with_reference(lflow_ref_aff_learn,
                                                 dplist[j])) {
                lflow_ref_aff_learn = ovn_lflow_add_at_with_hash(
                        lflows, dplist[j], S_ROUTER_IN_LB_AFF_LEARN, 100,
                        ds_cstr(&aff_match_learn), ds_cstr(&aff_action_learn),
                        NULL, NULL, &lb->nlb->header_, OVS_SOURCE_LOCATOR,
                        hash_aff_learn);
            }
            /* Use already selected backend within affinity timeslot. */
            if (!ovn_dp_group_add_with_reference(lflow_ref_aff_lb,
                                                 dplist[j])) {
                lflow_ref_aff_lb = ovn_lflow_add_at_with_hash(
                    lflows, dplist[j], S_ROUTER_IN_DNAT, 150,
                    ds_cstr(&aff_match), ds_cstr(&aff_action), NULL, NULL,
                    &lb->nlb->header_, OVS_SOURCE_LOCATOR,
                    hash_aff_lb);
            }
        }

        ds_truncate(&aff_action, aff_action_len);
        ds_truncate(&aff_action_learn, aff_action_learn_len);
        ds_truncate(&aff_match, aff_match_len);
        ds_truncate(&aff_match_learn, aff_match_learn_len);
    }

    ds_destroy(&aff_action);
    ds_destroy(&aff_action_learn);
    ds_destroy(&aff_match);
    ds_destroy(&aff_match_learn);
}

/* Builds the logical switch flows related to load balancer affinity.
 * For a LB configured with 'vip=V:VP' and backends 'B1:BP1,B2:BP2' and
 * affinity timeout set to T, it generates the following logical flows:
 * - load balancing affinity check:
 *   table=ls_in_lb_aff_check, priority=100
 *      match=(ct.new && ip4
 *             && REG_ORIG_DIP_IPV4 == V && REG_ORIG_TP_DPORT == VP)
 *      action=(REGBIT_KNOWN_LB_SESSION = chk_lb_aff(); next;)
 *
 * - load balancing:
 *   table=ls_in_lb, priority=150
 *      match=(REGBIT_KNOWN_LB_SESSION == 1 && ct.new && ip4
 *             && REG_LB_AFF_BACKEND_IP4 == B1 && REG_LB_AFF_MATCH_PORT == BP1)
 *      action=(REGBIT_CONNTRACK_COMMIT = 0;
 *              REG_ORIG_DIP_IPV4 = V; REG_ORIG_TP_DPORT = VP;
 *              ct_lb_mark(backends=B1:BP1);)
 *   table=ls_in_lb, priority=150
 *      match=(REGBIT_KNOWN_LB_SESSION == 1 && ct.new && ip4
 *             && REG_LB_AFF_BACKEND_IP4 == B2 && REG_LB_AFF_MATCH_PORT == BP2)
 *      action=(REGBIT_CONNTRACK_COMMIT = 0;
 *              REG_ORIG_DIP_IPV4 = V;
 *              REG_ORIG_TP_DPORT = VP;
 *              ct_lb_mark(backends=B1:BP2);)
 *
 * - load balancing affinity learn:
 *   table=ls_in_lb_aff_learn, priority=100
 *      match=(REGBIT_KNOWN_LB_SESSION == 0
 *             && ct.new && ip4
 *             && REG_ORIG_DIP_IPV4 == V && REG_ORIG_TP_DPORT == VP
 *             && ip4.dst == B1 && tcp.dst == BP1)
 *      action=(commit_lb_aff(vip = "V:VP", backend = "B1:BP1",
 *                            proto = tcp, timeout = T));
 *   table=ls_in_lb_aff_learn, priority=100
 *      match=(REGBIT_KNOWN_LB_SESSION == 0
 *             && ct.new && ip4
 *             && REG_ORIG_DIP_IPV4 == V && REG_ORIG_TP_DPORT == VP
 *             && ip4.dst == B2 && tcp.dst == BP2)
 *      action=(commit_lb_aff(vip = "V:VP", backend = "B2:BP2",
 *                            proto = tcp, timeout = T));
 *
 */
static void
build_lb_affinity_ls_flows(struct hmap *lflows, struct ovn_northd_lb *lb,
                           struct ovn_lb_vip *lb_vip)
{
    if (!lb->affinity_timeout) {
        return;
    }

    struct ds new_lb_match = DS_EMPTY_INITIALIZER;
    if (IN6_IS_ADDR_V4MAPPED(&lb_vip->vip)) {
        ds_put_format(&new_lb_match,
                      "ct.new && ip4 && "REG_ORIG_DIP_IPV4 " == %s",
                      lb_vip->vip_str);
    } else {
        ds_put_format(&new_lb_match,
                      "ct.new && ip6 && "REG_ORIG_DIP_IPV6 " == %s",
                      lb_vip->vip_str);
    }

    if (lb_vip->vip_port) {
        ds_put_format(&new_lb_match, " && "REG_ORIG_TP_DPORT " == %"PRIu16,
                      lb_vip->vip_port);
    }

    static char *aff_check = REGBIT_KNOWN_LB_SESSION" = chk_lb_aff(); next;";
    struct ovn_lflow *lflow_ref_aff_check = NULL;
    /* Check if we have already a enstablished connection for this
     * tuple and we are in affinity timeslot. */
    uint32_t hash_aff_check = ovn_logical_flow_hash(
            ovn_stage_get_table(S_SWITCH_IN_LB_AFF_CHECK),
            ovn_stage_get_pipeline(S_SWITCH_IN_LB_AFF_CHECK), 100,
            ds_cstr(&new_lb_match), aff_check);

    for (size_t i = 0; i < lb->n_nb_ls; i++) {
        if (!ovn_dp_group_add_with_reference(lflow_ref_aff_check,
                                             lb->nb_ls[i])) {
            lflow_ref_aff_check = ovn_lflow_add_at_with_hash(
                    lflows, lb->nb_ls[i], S_SWITCH_IN_LB_AFF_CHECK, 100,
                    ds_cstr(&new_lb_match), aff_check, NULL, NULL,
                    &lb->nlb->header_, OVS_SOURCE_LOCATOR, hash_aff_check);
        }
    }
    ds_destroy(&new_lb_match);

    struct ds aff_action = DS_EMPTY_INITIALIZER;
    struct ds aff_action_learn = DS_EMPTY_INITIALIZER;
    struct ds aff_match = DS_EMPTY_INITIALIZER;
    struct ds aff_match_learn = DS_EMPTY_INITIALIZER;

    bool ipv6 = !IN6_IS_ADDR_V4MAPPED(&lb_vip->vip);
    const char *ip_match = ipv6 ? "ip6" : "ip4";

    const char *reg_vip = ipv6 ? REG_ORIG_DIP_IPV6 : REG_ORIG_DIP_IPV4;
    const char *reg_backend =
        ipv6 ? REG_LB_L2_AFF_BACKEND_IP6 : REG_LB_AFF_BACKEND_IP4;

    /* Prepare common part of affinity LB and affinity learn action. */
    ds_put_format(&aff_action, REGBIT_CONNTRACK_COMMIT" = 0; %s = %s; ",
                  reg_vip, lb_vip->vip_str);
    ds_put_cstr(&aff_action_learn, "commit_lb_aff(vip = \"");

    if (lb_vip->vip_port) {
        ds_put_format(&aff_action, REG_ORIG_TP_DPORT" = %"PRIu16"; ",
                      lb_vip->vip_port);
        ds_put_format(&aff_action_learn, ipv6 ? "[%s]:%"PRIu16 : "%s:%"PRIu16,
                      lb_vip->vip_str, lb_vip->vip_port);
    } else {
        ds_put_cstr(&aff_action_learn, lb_vip->vip_str);
    }

    ds_put_cstr(&aff_action, "ct_lb_mark(backends=");
    ds_put_cstr(&aff_action_learn, "\", backend = \"");

    /* Prepare common part of affinity learn match. */
    if (lb_vip->vip_port) {
        ds_put_format(&aff_match_learn, REGBIT_KNOWN_LB_SESSION" == 0 && "
                      "ct.new && %s && %s == %s && "
                      REG_ORIG_TP_DPORT" == %"PRIu16" && %s.dst == ",
                      ip_match, reg_vip, lb_vip->vip_str,
                      lb_vip->vip_port, ip_match);
    } else {
        ds_put_format(&aff_match_learn, REGBIT_KNOWN_LB_SESSION" == 0 && "
                      "ct.new && %s && %s == %s && %s.dst == ",
                      ip_match, reg_vip, lb_vip->vip_str, ip_match);
    }

    /* Prepare common part of affinity match. */
    ds_put_format(&aff_match, REGBIT_KNOWN_LB_SESSION" == 1 && "
                  "ct.new && %s && %s == ", ip_match, reg_backend);

    /* Store the common part length. */
    size_t aff_action_len = aff_action.length;
    size_t aff_action_learn_len = aff_action_learn.length;
    size_t aff_match_len = aff_match.length;
    size_t aff_match_learn_len = aff_match_learn.length;

    for (size_t i = 0; i < lb_vip->n_backends; i++) {
        struct ovn_lb_backend *backend = &lb_vip->backends[i];

        ds_put_cstr(&aff_match_learn, backend->ip_str);
        ds_put_cstr(&aff_match, backend->ip_str);

        if (backend->port) {
            ds_put_format(&aff_action, ipv6 ? "[%s]:%d" : "%s:%d",
                          backend->ip_str, backend->port);
            ds_put_format(&aff_action_learn, ipv6 ? "[%s]:%d" : "%s:%d",
                          backend->ip_str, backend->port);

            ds_put_format(&aff_match_learn, " && %s.dst == %d",
                          lb->proto, backend->port);
            ds_put_format(&aff_match, " && "REG_LB_AFF_MATCH_PORT" == %d",
                          backend->port);
        } else {
            ds_put_cstr(&aff_action, backend->ip_str);
            ds_put_cstr(&aff_action_learn, backend->ip_str);
        }

        ds_put_cstr(&aff_action, ");");
        ds_put_char(&aff_action_learn, '"');

        if (lb_vip->vip_port) {
            ds_put_format(&aff_action_learn, ", proto = %s", lb->proto);
        }

        ds_put_format(&aff_action_learn, ", timeout = %d); /* drop */",
                      lb->affinity_timeout);

        struct ovn_lflow *lflow_ref_aff_learn = NULL;
        uint32_t hash_aff_learn = ovn_logical_flow_hash(
                ovn_stage_get_table(S_SWITCH_IN_LB_AFF_LEARN),
                ovn_stage_get_pipeline(S_SWITCH_IN_LB_AFF_LEARN),
                100, ds_cstr(&aff_match_learn), ds_cstr(&aff_action_learn));

        struct ovn_lflow *lflow_ref_aff_lb = NULL;
        uint32_t hash_aff_lb = ovn_logical_flow_hash(
                ovn_stage_get_table(S_SWITCH_IN_LB),
                ovn_stage_get_pipeline(S_SWITCH_IN_LB),
                150, ds_cstr(&aff_match), ds_cstr(&aff_action));

        for (size_t j = 0; j < lb->n_nb_ls; j++) {
            /* Forward to OFTABLE_CHK_LB_AFFINITY table to store flow tuple. */
            if (!ovn_dp_group_add_with_reference(lflow_ref_aff_learn,
                                                 lb->nb_ls[j])) {
                lflow_ref_aff_learn = ovn_lflow_add_at_with_hash(
                        lflows, lb->nb_ls[j], S_SWITCH_IN_LB_AFF_LEARN, 100,
                        ds_cstr(&aff_match_learn), ds_cstr(&aff_action_learn),
                        NULL, NULL, &lb->nlb->header_, OVS_SOURCE_LOCATOR,
                        hash_aff_learn);
            }
            /* Use already selected backend within affinity timeslot. */
            if (!ovn_dp_group_add_with_reference(lflow_ref_aff_lb,
                                                 lb->nb_ls[j])) {
                lflow_ref_aff_lb = ovn_lflow_add_at_with_hash(
                    lflows, lb->nb_ls[j], S_SWITCH_IN_LB, 150,
                    ds_cstr(&aff_match), ds_cstr(&aff_action), NULL, NULL,
                    &lb->nlb->header_, OVS_SOURCE_LOCATOR,
                    hash_aff_lb);
            }
        }

        ds_truncate(&aff_action, aff_action_len);
        ds_truncate(&aff_action_learn, aff_action_learn_len);
        ds_truncate(&aff_match, aff_match_len);
        ds_truncate(&aff_match_learn, aff_match_learn_len);
    }

    ds_destroy(&aff_action);
    ds_destroy(&aff_action_learn);
    ds_destroy(&aff_match);
    ds_destroy(&aff_match_learn);
}

static void
build_lb_affinity_default_flows(struct ovn_datapath *od, struct hmap *lflows)
{
    if (od->nbs) {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_LB_AFF_CHECK, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_IN_LB_AFF_LEARN, 0, "1", "next;");
    }
    if (od->nbr) {
        ovn_lflow_add(lflows, od, S_ROUTER_IN_LB_AFF_CHECK, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_LB_AFF_LEARN, 0, "1", "next;");
    }
}

static void
build_lb_rules(struct hmap *lflows, struct ovn_northd_lb *lb, bool ct_lb_mark,
               struct ds *match, struct ds *action,
               const struct shash *meter_groups)
{
    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_lb_vip *lb_vip = &lb->vips[i];
        struct ovn_northd_lb_vip *lb_vip_nb = &lb->vips_nb[i];
        const char *ip_match = NULL;
        if (lb_vip->address_family == AF_INET) {
            ip_match = "ip4";
        } else {
            ip_match = "ip6";
        }

        ds_clear(action);
        ds_clear(match);

        /* Make sure that we clear the REGBIT_CONNTRACK_COMMIT flag.  Otherwise
         * the load balanced packet will be committed again in
         * S_SWITCH_IN_STATEFUL. */
        ds_put_format(action, REGBIT_CONNTRACK_COMMIT" = 0; ");

        /* New connections in Ingress table. */
        const char *meter = NULL;
        bool reject = build_lb_vip_actions(lb_vip, lb_vip_nb, action,
                                           lb->selection_fields, true,
                                           ct_lb_mark);

        ds_put_format(match, "ct.new && %s.dst == %s", ip_match,
                      lb_vip->vip_str);
        int priority = 110;
        if (lb_vip->port_str) {
            ds_put_format(match, " && %s.dst == %s", lb->proto,
                          lb_vip->port_str);
            priority = 120;
        }

        build_lb_affinity_ls_flows(lflows, lb, lb_vip);

        struct ovn_lflow *lflow_ref = NULL;
        uint32_t hash = ovn_logical_flow_hash(
                ovn_stage_get_table(S_SWITCH_IN_LB),
                ovn_stage_get_pipeline(S_SWITCH_IN_LB), priority,
                ds_cstr(match), ds_cstr(action));

        for (size_t j = 0; j < lb->n_nb_ls; j++) {
            struct ovn_datapath *od = lb->nb_ls[j];

            if (reject) {
                meter = copp_meter_get(COPP_REJECT, od->nbs->copp,
                                       meter_groups);
            }
            if (meter || !ovn_dp_group_add_with_reference(lflow_ref, od)) {
                struct ovn_lflow *lflow = ovn_lflow_add_at_with_hash(
                        lflows, od, S_SWITCH_IN_LB, priority,
                        ds_cstr(match), ds_cstr(action),
                        NULL, meter, &lb->nlb->header_,
                        OVS_SOURCE_LOCATOR, hash);
                lflow_ref = meter ? NULL : lflow;
            }
        }
    }
}

static void
build_stateful(struct ovn_datapath *od,
               const struct chassis_features *features,
               struct hmap *lflows)
{
    const char *ct_block_action = features->ct_no_masked_label
                                  ? "ct_mark.blocked"
                                  : "ct_label.blocked";
    struct ds actions = DS_EMPTY_INITIALIZER;

    /* Ingress LB, Ingress and Egress stateful Table (Priority 0): Packets are
     * allowed by default. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_LB, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_IN_STATEFUL, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_STATEFUL, 0, "1", "next;");

    /* If REGBIT_CONNTRACK_COMMIT is set as 1 and
     * REGBIT_CONNTRACK_SET_LABEL is set to 1, then the packets should be
     * committed to conntrack.
     * We always set ct_mark.blocked to 0 here as
     * any packet that makes it this far is part of a connection we
     * want to allow to continue. */
    ds_put_format(&actions, "ct_commit { %s = 0; "
                            "ct_label.label = " REG_LABEL "; }; next;",
                  ct_block_action);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_STATEFUL, 100,
                  REGBIT_CONNTRACK_COMMIT" == 1 && "
                  REGBIT_ACL_LABEL" == 1",
                  ds_cstr(&actions));
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_STATEFUL, 100,
                  REGBIT_CONNTRACK_COMMIT" == 1 && "
                  REGBIT_ACL_LABEL" == 1",
                  ds_cstr(&actions));

    /* If REGBIT_CONNTRACK_COMMIT is set as 1, then the packets should be
     * committed to conntrack. We always set ct_mark.blocked to 0 here as
     * any packet that makes it this far is part of a connection we
     * want to allow to continue. */
    ds_clear(&actions);
    ds_put_format(&actions, "ct_commit { %s = 0; }; next;", ct_block_action);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_STATEFUL, 100,
                  REGBIT_CONNTRACK_COMMIT" == 1 && "
                  REGBIT_ACL_LABEL" == 0",
                  ds_cstr(&actions));
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_STATEFUL, 100,
                  REGBIT_CONNTRACK_COMMIT" == 1 && "
                  REGBIT_ACL_LABEL" == 0",
                  ds_cstr(&actions));
    ds_destroy(&actions);
}

static void
build_lb_hairpin(struct ovn_datapath *od, struct hmap *lflows)
{
    /* Ingress Pre-Hairpin/Nat-Hairpin/Hairpin tabled (Priority 0).
     * Packets that don't need hairpinning should continue processing.
     */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_HAIRPIN, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_IN_NAT_HAIRPIN, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_IN_HAIRPIN, 0, "1", "next;");

    if (od->has_lb_vip) {
        /* Check if the packet needs to be hairpinned.
         * Set REGBIT_HAIRPIN in the original direction and
         * REGBIT_HAIRPIN_REPLY in the reply direction.
         */
        ovn_lflow_add_with_hint(
            lflows, od, S_SWITCH_IN_PRE_HAIRPIN, 100, "ip && ct.trk",
            REGBIT_HAIRPIN " = chk_lb_hairpin(); "
            REGBIT_HAIRPIN_REPLY " = chk_lb_hairpin_reply(); "
            "next;",
            &od->nbs->header_);

        /* If packet needs to be hairpinned, snat the src ip with the VIP
         * for new sessions. */
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_NAT_HAIRPIN, 100,
                                "ip && ct.new && ct.trk"
                                " && "REGBIT_HAIRPIN " == 1",
                                "ct_snat_to_vip; next;",
                                &od->nbs->header_);

        /* If packet needs to be hairpinned, for established sessions there
         * should already be an SNAT conntrack entry.
         */
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_NAT_HAIRPIN, 100,
                                "ip && ct.est && ct.trk"
                                " && "REGBIT_HAIRPIN " == 1",
                                "ct_snat;",
                                &od->nbs->header_);

        /* For the reply of hairpinned traffic, snat the src ip to the VIP. */
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_NAT_HAIRPIN, 90,
                                "ip && "REGBIT_HAIRPIN_REPLY " == 1",
                                "ct_snat;",
                                &od->nbs->header_);

        /* Ingress Hairpin table.
        * - Priority 1: Packets that were SNAT-ed for hairpinning should be
        *   looped back (i.e., swap ETH addresses and send back on inport).
        */
        ovn_lflow_add(
            lflows, od, S_SWITCH_IN_HAIRPIN, 1,
            "("REGBIT_HAIRPIN " == 1 || " REGBIT_HAIRPIN_REPLY " == 1)",
            "eth.dst <-> eth.src; outport = inport; flags.loopback = 1; "
            "output;");
    }
}

static void
build_vtep_hairpin(struct ovn_datapath *od, struct hmap *lflows)
{
    /* Ingress Pre-ARP flows for VTEP hairpining traffic. Priority 1000:
     * Packets that received from non-VTEP ports should continue processing. */

    char *action = xasprintf("next(pipeline=ingress, table=%d);",
                             ovn_stage_get_table(S_SWITCH_IN_L2_LKUP));
    /* send all traffic from VTEP directly to L2LKP table. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_HAIRPIN, 1000,
                  REGBIT_FROM_RAMP" == 1", action);
    free(action);

    struct ds match = DS_EMPTY_INITIALIZER;
    size_t n_ports = od->n_router_ports;
    bool dp_has_l3dgw_ports = false;
    for (int i = 0; i < n_ports; i++) {
        if (is_l3dgw_port(od->router_ports[i]->peer)) {
            ds_put_format(&match, "%sis_chassis_resident(%s)%s",
                          i == 0 ? REGBIT_FROM_RAMP" == 1 && (" : "",
                          od->router_ports[i]->peer->cr_port->json_key,
                          i < n_ports - 1 ? " || " : ")");
            dp_has_l3dgw_ports = true;
        }
    }

    /* Ingress pre-arp flow for traffic from VTEP (ramp) switch.
    * Priority 2000: Packets, that were received from VTEP (ramp) switch and
    * router ports of current datapath are l3dgw ports and they reside on
    * current chassis, should be passed to next table for ARP/ND hairpin
    * processing.
    */
    if (dp_has_l3dgw_ports) {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_HAIRPIN, 2000, ds_cstr(&match),
                      "next;");
    }
    ds_destroy(&match);
}

/* Build logical flows for the forwarding groups */
static void
build_fwd_group_lflows(struct ovn_datapath *od, struct hmap *lflows)
{

    if (!(!od->nbs || !od->nbs->n_forwarding_groups)) {
        struct ds match = DS_EMPTY_INITIALIZER;
        struct ds actions = DS_EMPTY_INITIALIZER;
        struct ds group_ports = DS_EMPTY_INITIALIZER;

        for (int i = 0; i < od->nbs->n_forwarding_groups; ++i) {
            const struct nbrec_forwarding_group *fwd_group = NULL;
            fwd_group = od->nbs->forwarding_groups[i];
            if (!fwd_group->n_child_port) {
                continue;
            }

            /* ARP responder for the forwarding group's virtual IP */
            ds_put_format(&match, "arp.tpa == %s && arp.op == 1",
                          fwd_group->vip);
            ds_put_format(&actions,
                "eth.dst = eth.src; "
                "eth.src = %s; "
                "arp.op = 2; /* ARP reply */ "
                "arp.tha = arp.sha; "
                "arp.sha = %s; "
                "arp.tpa = arp.spa; "
                "arp.spa = %s; "
                "outport = inport; "
                "flags.loopback = 1; "
                "output;",
                fwd_group->vmac, fwd_group->vmac, fwd_group->vip);

            ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_ARP_ND_RSP, 50,
                                    ds_cstr(&match), ds_cstr(&actions),
                                    &fwd_group->header_);

            /* L2 lookup for the forwarding group's virtual MAC */
            ds_clear(&match);
            ds_put_format(&match, "eth.dst == %s", fwd_group->vmac);

            /* Create a comma separated string of child ports */
            ds_clear(&group_ports);
            if (fwd_group->liveness) {
                ds_put_cstr(&group_ports, "liveness=\"true\",");
            }
            ds_put_cstr(&group_ports, "childports=");
            for (i = 0; i < (fwd_group->n_child_port - 1); ++i) {
                ds_put_format(&group_ports, "\"%s\",",
                             fwd_group->child_port[i]);
            }
            ds_put_format(&group_ports, "\"%s\"",
                          fwd_group->child_port[fwd_group->n_child_port - 1]);

            ds_clear(&actions);
            ds_put_format(&actions, "fwd_group(%s);", ds_cstr(&group_ports));
            ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_L2_LKUP, 50,
                                    ds_cstr(&match), ds_cstr(&actions),
                                    &fwd_group->header_);
        }

        ds_destroy(&match);
        ds_destroy(&actions);
        ds_destroy(&group_ports);
    }
}

static void
build_lrouter_groups__(struct hmap *ports, struct ovn_datapath *od)
{
    ovs_assert((od && od->nbr && od->lr_group));

    /* For logical router with distributed gateway ports. If it
     * has HA_Chassis_Group associated to it in SB DB, then store the
     * ha chassis group name. */
    for (size_t i = 0; i < od->n_l3dgw_ports; i++) {
        struct ovn_port *crp = od->l3dgw_ports[i]->cr_port;
        if (crp->sb->ha_chassis_group &&
            crp->sb->ha_chassis_group->n_ha_chassis > 1) {
            sset_add(&od->lr_group->ha_chassis_groups,
                     crp->sb->ha_chassis_group->name);
        }
    }

    for (size_t i = 0; i < od->nbr->n_ports; i++) {
        struct ovn_port *router_port =
            ovn_port_find(ports, od->nbr->ports[i]->name);

        if (!router_port || !router_port->peer) {
            continue;
        }

        /* Get the peer logical switch/logical router datapath. */
        struct ovn_datapath *peer_dp = router_port->peer->od;
        if (peer_dp->nbr) {
            if (!peer_dp->lr_group) {
                peer_dp->lr_group = od->lr_group;
                od->lr_group->router_dps[od->lr_group->n_router_dps++]
                    = peer_dp;
                build_lrouter_groups__(ports, peer_dp);
            }
        } else {
            for (size_t j = 0; j < peer_dp->n_router_ports; j++) {
                if (!peer_dp->router_ports[j]->peer) {
                    /* If there is no peer port connecting to the
                    * router port, ignore it. */
                    continue;
                }

                struct ovn_datapath *router_dp;
                router_dp = peer_dp->router_ports[j]->peer->od;
                if (router_dp == od) {
                    continue;
                }

                if (router_dp->lr_group == od->lr_group) {
                    /* 'router_dp' and 'od' already belong to the same
                    * lrouter group. Nothing to be done. */
                    continue;
                }

                router_dp->lr_group = od->lr_group;
                od->lr_group->router_dps[od->lr_group->n_router_dps++]
                    = router_dp;
                build_lrouter_groups__(ports, router_dp);
            }
        }
    }
}

/* Adds each logical router into a logical router group. All the
 * logical routers which belong to a group are connected to
 * each other either directly or indirectly (via transit logical switches
 * in between).
 *
 * Suppose if 'lr_list' has lr0, lr1, lr2, lr3, lr4, lr5
 * and the topology is like
 *  sw0 <-> lr0 <-> sw1 <-> lr1 <->sw2 <-> lr2
 *  sw3 <-> lr3 <-> lr4 <-> sw5
 *  sw6 <-> lr5 <-> sw7
 * Then 3 groups are created.
 * Group 1 -> lr0, lr1 and lr2
 *            lr0, lr1 and lr2's ovn_datapath->lr_group will point to this
 *            group. This means sw0's logical ports can send packets to sw2's
 *            logical ports if proper static route's are added.
 * Group 2 -> lr3 and lr4
 *            lr3 and lr4's ovn_datapath->lr_group will point to this group.
 * Group 3 -> lr5
 *
 * Each logical router can belong to only one group.
 */
static void
build_lrouter_groups(struct hmap *ports, struct ovs_list *lr_list)
{
    struct ovn_datapath *od;
    size_t n_router_dps = ovs_list_size(lr_list);

    LIST_FOR_EACH (od, lr_list, lr_list) {
        if (!od->lr_group) {
            od->lr_group = xzalloc(sizeof *od->lr_group);
            /* Each logical router group can have max
             * 'n_router_dps'. So allocate enough memory. */
            od->lr_group->router_dps = xcalloc(sizeof *od, n_router_dps);
            od->lr_group->router_dps[0] = od;
            od->lr_group->n_router_dps = 1;
            sset_init(&od->lr_group->ha_chassis_groups);
            build_lrouter_groups__(ports, od);
        }
    }
}

/*
 * Ingress table 24: Flows that flood self originated ARP/RARP/ND packets in
 * the switching domain.
 */
static void
build_lswitch_rport_arp_req_self_orig_flow(struct ovn_port *op,
                                           uint32_t priority,
                                           struct ovn_datapath *od,
                                           struct hmap *lflows)
{
    struct sset all_eth_addrs = SSET_INITIALIZER(&all_eth_addrs);
    struct ds eth_src = DS_EMPTY_INITIALIZER;
    struct ds match = DS_EMPTY_INITIALIZER;

    sset_add(&all_eth_addrs, op->lrp_networks.ea_s);

    for (size_t i = 0; i < op->od->nbr->n_nat; i++) {
        struct ovn_nat *nat_entry = &op->od->nat_entries[i];
        const struct nbrec_nat *nat = nat_entry->nb;

        if (!nat_entry_is_valid(nat_entry)) {
            continue;
        }

        if (!strcmp(nat->type, "snat")) {
            continue;
        }

        if (!nat->external_mac) {
            continue;
        }
        sset_add(&all_eth_addrs, nat->external_mac);
    }

    /* Self originated ARP requests/RARP/ND need to be flooded to the L2 domain
     * (except on router ports).  Determine that packets are self originated
     * by also matching on source MAC. Matching on ingress port is not
     * reliable in case this is a VLAN-backed network.
     * Priority: 75.
     */
    const char *eth_addr;

    ds_put_cstr(&eth_src, "{");
    SSET_FOR_EACH (eth_addr, &all_eth_addrs) {
        ds_put_format(&eth_src, "%s, ", eth_addr);
    }
    ds_chomp(&eth_src, ' ');
    ds_chomp(&eth_src, ',');
    ds_put_cstr(&eth_src, "}");

    ds_put_format(&match,
                  "eth.src == %s && (arp.op == 1 || rarp.op == 3 || nd_ns)",
                  ds_cstr(&eth_src));
    ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, priority, ds_cstr(&match),
                  "outport = \""MC_FLOOD_L2"\"; output;");

    sset_destroy(&all_eth_addrs);
    ds_destroy(&eth_src);
    ds_destroy(&match);
}

static void
arp_nd_ns_match(const char *ips, int addr_family, struct ds *match)
{
    /* Packets received from VXLAN tunnels have already been through the
     * router pipeline so we should skip them. Normally this is done by the
     * multicast_group implementation (VXLAN packets skip table 32 which
     * delivers to patch ports) but we're bypassing multicast_groups.
     */
    ds_put_cstr(match, FLAGBIT_NOT_VXLAN " && ");

    if (addr_family == AF_INET) {
        ds_put_format(match, "arp.op == 1 && arp.tpa == %s", ips);
    } else {
        ds_put_format(match, "nd_ns && nd.target == %s", ips);
    }
}

/* Returns 'true' if the IPv4 'addr' is on the same subnet with one of the
 * IPs configured on the router port.
 */
static bool
lrouter_port_ipv4_reachable(const struct ovn_port *op, ovs_be32 addr)
{
    for (size_t i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
        struct ipv4_netaddr *op_addr = &op->lrp_networks.ipv4_addrs[i];

        if ((addr & op_addr->mask) == op_addr->network) {
            return true;
        }
    }
    return false;
}

/* Returns 'true' if the IPv6 'addr' is on the same subnet with one of the
 * IPs configured on the router port.
 */
static bool
lrouter_port_ipv6_reachable(const struct ovn_port *op,
                            const struct in6_addr *addr)
{
    for (size_t i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
        struct ipv6_netaddr *op_addr = &op->lrp_networks.ipv6_addrs[i];

        struct in6_addr nat_addr6_masked =
            ipv6_addr_bitand(addr, &op_addr->mask);

        if (ipv6_addr_equals(&nat_addr6_masked, &op_addr->network)) {
            return true;
        }
    }
    return false;
}

/*
 * Ingress table 24: Flows that forward ARP/ND requests only to the routers
 * that own the addresses. Other ARP/ND packets are still flooded in the
 * switching domain as regular broadcast.
 */
static void
build_lswitch_rport_arp_req_flow(const char *ips,
    int addr_family, struct ovn_port *patch_op, struct ovn_datapath *od,
    uint32_t priority, struct hmap *lflows,
    const struct ovsdb_idl_row *stage_hint)
{
    struct ds match   = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    arp_nd_ns_match(ips, addr_family, &match);

    /* Send a the packet to the router pipeline.  If the switch has non-router
     * ports then flood it there as well.
     */
    if (od->n_router_ports != od->nbs->n_ports) {
        ds_put_format(&actions, "clone {outport = %s; output; }; "
                                "outport = \""MC_FLOOD_L2"\"; output;",
                      patch_op->json_key);
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_L2_LKUP,
                                priority, ds_cstr(&match),
                                ds_cstr(&actions), stage_hint);
    } else {
        ds_put_format(&actions, "outport = %s; output;", patch_op->json_key);
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_L2_LKUP, priority,
                                ds_cstr(&match), ds_cstr(&actions),
                                stage_hint);
    }

    ds_destroy(&match);
    ds_destroy(&actions);
}

/*
 * Ingress table 24: Flows that forward ARP/ND requests only to the routers
 * that own the addresses.
 * Priorities:
 * - 80: self originated GARPs that need to follow regular processing.
 * - 75: ARP requests to router owned IPs (interface IP/LB/NAT).
 */
static void
build_lswitch_rport_arp_req_flows(struct ovn_port *op,
                                  struct ovn_datapath *sw_od,
                                  struct ovn_port *sw_op,
                                  struct hmap *lflows,
                                  const struct ovsdb_idl_row *stage_hint)
{
    if (!op || !op->nbrp) {
        return;
    }

    if (!lrport_is_enabled(op->nbrp)) {
        return;
    }

    /* Forward ARP requests for owned IP addresses (L3, VIP, NAT) only to this
     * router port.
     * Priority: 80.
     */

    const char *ip_addr;
    SSET_FOR_EACH (ip_addr, &op->od->lb_ips->ips_v4) {
        ovs_be32 ipv4_addr;

        /* Check if the ovn port has a network configured on which we could
         * expect ARP requests for the LB VIP.
         */
        if (ip_parse(ip_addr, &ipv4_addr) &&
            lrouter_port_ipv4_reachable(op, ipv4_addr)) {
            build_lswitch_rport_arp_req_flow(
                ip_addr, AF_INET, sw_op, sw_od, 80, lflows,
                stage_hint);
        }
    }
    SSET_FOR_EACH (ip_addr, &op->od->lb_ips->ips_v6) {
        struct in6_addr ipv6_addr;

        /* Check if the ovn port has a network configured on which we could
         * expect NS requests for the LB VIP.
         */
        if (ipv6_parse(ip_addr, &ipv6_addr) &&
            lrouter_port_ipv6_reachable(op, &ipv6_addr)) {
            build_lswitch_rport_arp_req_flow(
                ip_addr, AF_INET6, sw_op, sw_od, 80, lflows,
                stage_hint);
        }
    }

    for (size_t i = 0; i < op->od->nbr->n_nat; i++) {
        struct ovn_nat *nat_entry = &op->od->nat_entries[i];
        const struct nbrec_nat *nat = nat_entry->nb;

        if (!nat_entry_is_valid(nat_entry)) {
            continue;
        }

        if (!strcmp(nat->type, "snat")) {
            continue;
        }

        /* Check if the ovn port has a network configured on which we could
         * expect ARP requests/NS for the DNAT external_ip.
         */
        if (nat_entry_is_v6(nat_entry)) {
            if (!sset_contains(&op->od->lb_ips->ips_v6, nat->external_ip)) {
                build_lswitch_rport_arp_req_flow(
                    nat->external_ip, AF_INET6, sw_op, sw_od, 80, lflows,
                    stage_hint);
            }
        } else {
            if (!sset_contains(&op->od->lb_ips->ips_v4, nat->external_ip)) {
                build_lswitch_rport_arp_req_flow(
                    nat->external_ip, AF_INET, sw_op, sw_od, 80, lflows,
                    stage_hint);
            }
        }
    }

    for (size_t i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
        build_lswitch_rport_arp_req_flow(
            op->lrp_networks.ipv4_addrs[i].addr_s, AF_INET, sw_op, sw_od, 80,
            lflows, stage_hint);
    }
    for (size_t i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
        build_lswitch_rport_arp_req_flow(
            op->lrp_networks.ipv6_addrs[i].addr_s, AF_INET6, sw_op, sw_od, 80,
            lflows, stage_hint);
    }

    /* Self originated ARP requests/RARP/ND need to be flooded as usual.
     *
     * However, if the switch doesn't have any non-router ports we shouldn't
     * even try to flood.
     *
     * Priority: 75.
     */
    if (sw_od->n_router_ports != sw_od->nbs->n_ports) {
        build_lswitch_rport_arp_req_self_orig_flow(op, 75, sw_od, lflows);
    }
}

static void
build_dhcpv4_options_flows(struct ovn_port *op,
                           struct lport_addresses *lsp_addrs,
                           struct ovn_port *inport, bool is_external,
                           const struct shash *meter_groups,
                           struct hmap *lflows)
{
    struct ds match = DS_EMPTY_INITIALIZER;

    for (size_t j = 0; j < lsp_addrs->n_ipv4_addrs; j++) {
        struct ds options_action = DS_EMPTY_INITIALIZER;
        struct ds response_action = DS_EMPTY_INITIALIZER;
        struct ds ipv4_addr_match = DS_EMPTY_INITIALIZER;
        if (build_dhcpv4_action(
                op, lsp_addrs->ipv4_addrs[j].addr,
                &options_action, &response_action, &ipv4_addr_match)) {
            ds_clear(&match);
            ds_put_format(
                &match, "inport == %s && eth.src == %s && "
                "ip4.src == 0.0.0.0 && ip4.dst == 255.255.255.255 && "
                "udp.src == 68 && udp.dst == 67",
                inport->json_key, lsp_addrs->ea_s);

            if (is_external) {
                ds_put_format(&match, " && is_chassis_resident(%s)",
                              op->json_key);
            }

            ovn_lflow_add_with_hint__(lflows, op->od,
                                      S_SWITCH_IN_DHCP_OPTIONS, 100,
                                      ds_cstr(&match),
                                      ds_cstr(&options_action),
                                      inport->key,
                                      copp_meter_get(COPP_DHCPV4_OPTS,
                                                     op->od->nbs->copp,
                                                     meter_groups),
                                      &op->nbsp->dhcpv4_options->header_);
            ds_clear(&match);
            /* Allow ip4.src = OFFER_IP and
             * ip4.dst = {SERVER_IP, 255.255.255.255} for the below
             * cases
             *  -  When the client wants to renew the IP by sending
             *     the DHCPREQUEST to the server ip.
             *  -  When the client wants to renew the IP by
             *     broadcasting the DHCPREQUEST.
             */
            ds_put_format(
                &match, "inport == %s && eth.src == %s && "
                "%s && udp.src == 68 && udp.dst == 67",
                inport->json_key, lsp_addrs->ea_s, ds_cstr(&ipv4_addr_match));

            if (is_external) {
                ds_put_format(&match, " && is_chassis_resident(%s)",
                              op->json_key);
            }

            ovn_lflow_add_with_hint__(lflows, op->od,
                                      S_SWITCH_IN_DHCP_OPTIONS, 100,
                                      ds_cstr(&match),
                                      ds_cstr(&options_action),
                                      inport->key,
                                      copp_meter_get(COPP_DHCPV4_OPTS,
                                                     op->od->nbs->copp,
                                                     meter_groups),
                                      &op->nbsp->dhcpv4_options->header_);
            ds_clear(&match);

            /* If REGBIT_DHCP_OPTS_RESULT is set, it means the
             * put_dhcp_opts action is successful. */
            ds_put_format(
                &match, "inport == %s && eth.src == %s && "
                "ip4 && udp.src == 68 && udp.dst == 67"
                " && "REGBIT_DHCP_OPTS_RESULT,
                inport->json_key, lsp_addrs->ea_s);

            if (is_external) {
                ds_put_format(&match, " && is_chassis_resident(%s)",
                              op->json_key);
            }

            ovn_lflow_add_with_lport_and_hint(
                lflows, op->od, S_SWITCH_IN_DHCP_RESPONSE, 100,
                ds_cstr(&match), ds_cstr(&response_action), inport->key,
                &op->nbsp->dhcpv4_options->header_);
            ds_destroy(&options_action);
            ds_destroy(&response_action);
            ds_destroy(&ipv4_addr_match);
            break;
        }
    }
    ds_destroy(&match);
}

static void
build_dhcpv6_options_flows(struct ovn_port *op,
                           struct lport_addresses *lsp_addrs,
                           struct ovn_port *inport, bool is_external,
                           const struct shash *meter_groups,
                           struct hmap *lflows)
{
    struct ds match = DS_EMPTY_INITIALIZER;

    for (size_t j = 0; j < lsp_addrs->n_ipv6_addrs; j++) {
        struct ds options_action = DS_EMPTY_INITIALIZER;
        struct ds response_action = DS_EMPTY_INITIALIZER;
        if (build_dhcpv6_action(
                op, &lsp_addrs->ipv6_addrs[j].addr,
                &options_action, &response_action)) {
            ds_clear(&match);
            ds_put_format(
                &match, "inport == %s && eth.src == %s"
                " && ip6.dst == ff02::1:2 && udp.src == 546 &&"
                " udp.dst == 547",
                inport->json_key, lsp_addrs->ea_s);

            if (is_external) {
                ds_put_format(&match, " && is_chassis_resident(%s)",
                              op->json_key);
            }

            ovn_lflow_add_with_hint__(lflows, op->od,
                                      S_SWITCH_IN_DHCP_OPTIONS, 100,
                                      ds_cstr(&match),
                                      ds_cstr(&options_action),
                                      inport->key,
                                      copp_meter_get(COPP_DHCPV6_OPTS,
                                                     op->od->nbs->copp,
                                                     meter_groups),
                                      &op->nbsp->dhcpv6_options->header_);

            /* If REGBIT_DHCP_OPTS_RESULT is set to 1, it means the
             * put_dhcpv6_opts action is successful */
            ds_put_cstr(&match, " && "REGBIT_DHCP_OPTS_RESULT);
            ovn_lflow_add_with_lport_and_hint(
                lflows, op->od, S_SWITCH_IN_DHCP_RESPONSE, 100,
                ds_cstr(&match), ds_cstr(&response_action), inport->key,
                &op->nbsp->dhcpv6_options->header_);
            ds_destroy(&options_action);
            ds_destroy(&response_action);
            break;
        }
    }
    ds_destroy(&match);
}

static void
build_drop_arp_nd_flows_for_unbound_router_ports(struct ovn_port *op,
                                                 const struct ovn_port *port,
                                                 struct hmap *lflows)
{
    struct ds match = DS_EMPTY_INITIALIZER;

    for (size_t i = 0; i < op->n_lsp_addrs; i++) {
        for (size_t j = 0; j < op->od->n_router_ports; j++) {
            struct ovn_port *rp = op->od->router_ports[j];
            for (size_t k = 0; k < rp->n_lsp_addrs; k++) {
                for (size_t l = 0; l < rp->lsp_addrs[k].n_ipv4_addrs; l++) {
                    ds_clear(&match);
                    ds_put_format(
                        &match, "inport == %s && eth.src == %s"
                        " && !is_chassis_resident(%s)"
                        " && arp.tpa == %s && arp.op == 1",
                        port->json_key,
                        op->lsp_addrs[i].ea_s, op->json_key,
                        rp->lsp_addrs[k].ipv4_addrs[l].addr_s);
                    ovn_lflow_add_with_lport_and_hint(
                        lflows, op->od, S_SWITCH_IN_EXTERNAL_PORT, 100,
                        ds_cstr(&match),  debug_drop_action(), port->key,
                        &op->nbsp->header_);
                }
                for (size_t l = 0; l < rp->lsp_addrs[k].n_ipv6_addrs; l++) {
                    ds_clear(&match);
                    ds_put_format(
                        &match, "inport == %s && eth.src == %s"
                        " && !is_chassis_resident(%s)"
                        " && nd_ns && ip6.dst == {%s, %s} && nd.target == %s",
                        port->json_key,
                        op->lsp_addrs[i].ea_s, op->json_key,
                        rp->lsp_addrs[k].ipv6_addrs[l].addr_s,
                        rp->lsp_addrs[k].ipv6_addrs[l].sn_addr_s,
                        rp->lsp_addrs[k].ipv6_addrs[l].addr_s);
                    ovn_lflow_add_with_lport_and_hint(
                        lflows, op->od, S_SWITCH_IN_EXTERNAL_PORT, 100,
                        ds_cstr(&match), debug_drop_action(), port->key,
                        &op->nbsp->header_);
                }

                ds_clear(&match);
                ds_put_format(
                    &match, "inport == %s && eth.src == %s"
                    " && eth.dst == %s"
                    " && !is_chassis_resident(%s)",
                    port->json_key,
                    op->lsp_addrs[i].ea_s, rp->lsp_addrs[k].ea_s,
                    op->json_key);
                ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                                  S_SWITCH_IN_EXTERNAL_PORT,
                                                  100, ds_cstr(&match),
                                                  debug_drop_action(),
                                                  port->key,
                                                  &op->nbsp->header_);
            }
        }
    }
    ds_destroy(&match);
}

static bool
is_vlan_transparent(const struct ovn_datapath *od)
{
    return smap_get_bool(&od->nbs->other_config, "vlan-passthru", false);
}

static void
build_lswitch_flows(const struct hmap *datapaths,
                    struct hmap *lflows)
{
    /* This flow table structure is documented in ovn-northd(8), so please
     * update ovn-northd.8.xml if you change anything. */

    struct ovn_datapath *od;

    /* Ingress table 25: Destination lookup for unknown MACs (priority 0). */
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbs) {
            continue;
        }

        ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, 0, "1",
                      "outport = get_fdb(eth.dst); next;");

        if (od->has_unknown) {
            ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_UNKNOWN, 50,
                          "outport == \"none\"",
                          "outport = \""MC_UNKNOWN "\"; output;");
        } else {
            ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_UNKNOWN, 50,
                          "outport == \"none\"",  debug_drop_action());
        }
        ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_UNKNOWN, 0, "1",
                      "output;");
    }

}

/* Build pre-ACL and ACL tables for both ingress and egress.
 * Ingress tables 3 through 10.  Egress tables 0 through 7. */
static void
build_lswitch_lflows_pre_acl_and_acl(struct ovn_datapath *od,
                                     const struct hmap *port_groups,
                                     const struct chassis_features *features,
                                     struct hmap *lflows,
                                     const struct shash *meter_groups)
{
    if (od->nbs) {
        ls_get_acl_flags(od);

        build_pre_acls(od, port_groups, lflows);
        build_pre_lb(od, meter_groups, lflows);
        build_pre_stateful(od, features, lflows);
        build_acl_hints(od, features, lflows);
        build_acls(od, features, lflows, port_groups, meter_groups);
        build_qos(od, lflows);
        build_stateful(od, features, lflows);
        build_lb_hairpin(od, lflows);
        build_vtep_hairpin(od, lflows);
    }
}

/* Logical switch ingress table 0: Admission control framework (priority
 * 100). */
static void
build_lswitch_lflows_admission_control(struct ovn_datapath *od,
                                       struct hmap *lflows)
{
    if (od->nbs) {
        /* Logical VLANs not supported. */
        if (!is_vlan_transparent(od)) {
            /* Block logical VLANs. */
            ovn_lflow_add(lflows, od, S_SWITCH_IN_CHECK_PORT_SEC, 100,
                          "vlan.present", debug_drop_action());
        }

        /* Broadcast/multicast source address is invalid. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_CHECK_PORT_SEC, 100,
                      "eth.src[40]", debug_drop_action());

        ovn_lflow_add(lflows, od, S_SWITCH_IN_CHECK_PORT_SEC, 50, "1",
                      REGBIT_PORT_SEC_DROP" = check_in_port_sec(); next;");

        ovn_lflow_add(lflows, od, S_SWITCH_IN_APPLY_PORT_SEC, 50,
                      REGBIT_PORT_SEC_DROP" == 1", debug_drop_action());

        ovn_lflow_add(lflows, od, S_SWITCH_IN_APPLY_PORT_SEC, 0, "1", "next;");
    }
}

/* Ingress table 18: ARP/ND responder, skip requests coming from localnet
 * ports. (priority 100); see ovn-northd.8.xml for the rationale. */

static void
build_lswitch_arp_nd_responder_skip_local(struct ovn_port *op,
                                          struct hmap *lflows,
                                          struct ds *match)
{
    if (op->nbsp && lsp_is_localnet(op->nbsp)) {
        ds_clear(match);
        ds_put_format(match, "inport == %s", op->json_key);
        ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                          S_SWITCH_IN_ARP_ND_RSP, 100,
                                          ds_cstr(match), "next;", op->key,
                                          &op->nbsp->header_);
    }
}

/* Ingress table 18: ARP/ND responder, reply for known IPs.
 * (priority 50). */
static void
build_lswitch_arp_nd_responder_known_ips(struct ovn_port *op,
                                         struct hmap *lflows,
                                         const struct hmap *ports,
                                         const struct shash *meter_groups,
                                         struct ds *actions,
                                         struct ds *match)
{
    if (op->nbsp) {
        if (!strcmp(op->nbsp->type, "virtual")) {
            /* Handle
             *  - GARPs for virtual ip which belongs to a logical port
             *    of type 'virtual' and bind that port.
             *
             *  - ARP reply from the virtual ip which belongs to a logical
             *    port of type 'virtual' and bind that port.
             *
             *  - IPv6 Neighbor Solicitations requests that targets virtual
             *    ip which belongs to a logical port of type 'virtual' and
             *    bind that port.
             *
             *  - IPv6 unsolicited Neighbor Advertisements that targets
             *    ip which belongs to a logical port of type 'virtual'
             *    and bind that port.
             * */
            struct in6_addr ip;

            const char *virtual_ip = smap_get(&op->nbsp->options,
                                              "virtual-ip");
            const char *virtual_parents = smap_get(&op->nbsp->options,
                                                   "virtual-parents");
            if (!virtual_ip || !virtual_parents) {
                return;
            }

            bool is_ipv4 = strchr(virtual_ip, '.') ? true : false;
            if (is_ipv4) {
                ovs_be32 ipv4;
                if (!ip_parse(virtual_ip, &ipv4)) {
                     return;
                }
            } else {
                if (!ipv6_parse(virtual_ip, &ip)) {
                     return;
                }
            }

            char *tokstr = xstrdup(virtual_parents);
            char *save_ptr = NULL;
            char *vparent;
            for (vparent = strtok_r(tokstr, ",", &save_ptr); vparent != NULL;
                 vparent = strtok_r(NULL, ",", &save_ptr)) {
                struct ovn_port *vp = ovn_port_find(ports, vparent);
                if (!vp || vp->od != op->od) {
                    /* vparent name should be valid and it should belong
                     * to the same logical switch. */
                    continue;
                }

                if (is_ipv4) {
                    ds_clear(match);
                    ds_put_format(match, "inport == \"%s\" && "
                            "((arp.op == 1 && arp.spa == %s && "
                            "arp.tpa == %s) || (arp.op == 2 && "
                            "arp.spa == %s))",
                            vparent, virtual_ip, virtual_ip,
                            virtual_ip);
                } else {
                    struct ipv6_netaddr na;
                    /* Find VIP multicast group */
                    in6_addr_solicited_node(&na.sn_addr, &ip);
                    inet_ntop(AF_INET6, &na.sn_addr, na.sn_addr_s,
                              sizeof na.sn_addr_s);

                    ds_clear(match);
                    ds_put_format(match, "inport == \"%s\" && "
                            "((nd_ns && ip6.dst == {%s, %s} && "
                            "nd.target == %s) ||"
                            "(nd_na && nd.target == %s))",
                            vparent,
                            virtual_ip,
                            na.sn_addr_s,
                            virtual_ip,
                            virtual_ip);
                }

                ds_clear(actions);
                ds_put_format(actions,
                    "bind_vport(%s, inport); "
                    "next;",
                    op->json_key);
                ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                                  S_SWITCH_IN_ARP_ND_RSP, 100,
                                                  ds_cstr(match),
                                                  ds_cstr(actions), vparent,
                                                  &vp->nbsp->header_);
            }

            free(tokstr);
        } else {
            /*
             * Add ARP/ND reply flows if either the
             *  - port is up and it doesn't have 'unknown' address defined or
             *  - port type is router or
             *  - port type is localport
             */
            if (check_lsp_is_up &&
                !lsp_is_up(op->nbsp) && !lsp_is_router(op->nbsp) &&
                strcmp(op->nbsp->type, "localport")) {
                return;
            }

            if (lsp_is_external(op->nbsp) || op->has_unknown) {
                return;
            }

            if (is_vlan_transparent(op->od)) {
                return;
            }

            for (size_t i = 0; i < op->n_lsp_addrs; i++) {
                for (size_t j = 0; j < op->lsp_addrs[i].n_ipv4_addrs; j++) {
                    ds_clear(match);
                    ds_put_format(match, "arp.tpa == %s && arp.op == 1",
                                op->lsp_addrs[i].ipv4_addrs[j].addr_s);
                    ds_clear(actions);
                    ds_put_format(actions,
                        "eth.dst = eth.src; "
                        "eth.src = %s; "
                        "arp.op = 2; /* ARP reply */ "
                        "arp.tha = arp.sha; "
                        "arp.sha = %s; "
                        "arp.tpa = arp.spa; "
                        "arp.spa = %s; "
                        "outport = inport; "
                        "flags.loopback = 1; "
                        "output;",
                        op->lsp_addrs[i].ea_s, op->lsp_addrs[i].ea_s,
                        op->lsp_addrs[i].ipv4_addrs[j].addr_s);
                    ovn_lflow_add_with_hint(lflows, op->od,
                                            S_SWITCH_IN_ARP_ND_RSP, 50,
                                            ds_cstr(match),
                                            ds_cstr(actions),
                                            &op->nbsp->header_);

                    /* Do not reply to an ARP request from the port that owns
                     * the address (otherwise a DHCP client that ARPs to check
                     * for a duplicate address will fail).  Instead, forward
                     * it the usual way.
                     *
                     * (Another alternative would be to simply drop the packet.
                     * If everything is working as it is configured, then this
                     * would produce equivalent results, since no one should
                     * reply to the request.  But ARPing for one's own IP
                     * address is intended to detect situations where the
                     * network is not working as configured, so dropping the
                     * request would frustrate that intent.) */
                    ds_put_format(match, " && inport == %s", op->json_key);
                    ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                                      S_SWITCH_IN_ARP_ND_RSP,
                                                      100, ds_cstr(match),
                                                      "next;", op->key,
                                                      &op->nbsp->header_);
                }

                /* For ND solicitations, we need to listen for both the
                 * unicast IPv6 address and its all-nodes multicast address,
                 * but always respond with the unicast IPv6 address. */
                for (size_t j = 0; j < op->lsp_addrs[i].n_ipv6_addrs; j++) {
                    ds_clear(match);
                    ds_put_format(match,
                            "nd_ns && ip6.dst == {%s, %s} && nd.target == %s",
                            op->lsp_addrs[i].ipv6_addrs[j].addr_s,
                            op->lsp_addrs[i].ipv6_addrs[j].sn_addr_s,
                            op->lsp_addrs[i].ipv6_addrs[j].addr_s);

                    ds_clear(actions);
                    ds_put_format(actions,
                            "%s { "
                            "eth.src = %s; "
                            "ip6.src = %s; "
                            "nd.target = %s; "
                            "nd.tll = %s; "
                            "outport = inport; "
                            "flags.loopback = 1; "
                            "output; "
                            "};",
                            lsp_is_router(op->nbsp) ? "nd_na_router" : "nd_na",
                            op->lsp_addrs[i].ea_s,
                            op->lsp_addrs[i].ipv6_addrs[j].addr_s,
                            op->lsp_addrs[i].ipv6_addrs[j].addr_s,
                            op->lsp_addrs[i].ea_s);
                    ovn_lflow_add_with_hint__(lflows, op->od,
                                              S_SWITCH_IN_ARP_ND_RSP, 50,
                                              ds_cstr(match),
                                              ds_cstr(actions),
                                              NULL,
                                              copp_meter_get(COPP_ND_NA,
                                                  op->od->nbs->copp,
                                                  meter_groups),
                                              &op->nbsp->header_);

                    /* Do not reply to a solicitation from the port that owns
                     * the address (otherwise DAD detection will fail). */
                    ds_put_format(match, " && inport == %s", op->json_key);
                    ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                                      S_SWITCH_IN_ARP_ND_RSP,
                                                      100, ds_cstr(match),
                                                      "next;", op->key,
                                                      &op->nbsp->header_);
                }
            }
        }

        if (op->peer) {
            const char *arp_proxy = smap_get(&op->nbsp->options,"arp_proxy");

            struct lport_addresses proxy_arp_addrs;
            int i = 0;

            /* Add responses for ARP proxies. */
            if (arp_proxy && extract_ip_addresses(arp_proxy,
                                                  &proxy_arp_addrs) &&
                proxy_arp_addrs.n_ipv4_addrs) {
                /* Match rule on all proxy ARP IPs. */
                ds_clear(match);
                ds_put_cstr(match, "arp.op == 1 && arp.tpa == {");

                for (i = 0; i < proxy_arp_addrs.n_ipv4_addrs; i++) {
                    ds_put_format(match, "%s,",
                                  proxy_arp_addrs.ipv4_addrs[i].addr_s);
                }

                ds_chomp(match, ',');
                ds_put_cstr(match, "}");
                destroy_lport_addresses(&proxy_arp_addrs);

                ds_clear(actions);
                ds_put_format(actions,
                    "eth.dst = eth.src; "
                    "eth.src = %s; "
                    "arp.op = 2; /* ARP reply */ "
                    "arp.tha = arp.sha; "
                    "arp.sha = %s; "
                    "arp.tpa <-> arp.spa; "
                    "outport = inport; "
                    "flags.loopback = 1; "
                    "output;",
                    op->peer->lrp_networks.ea_s,
                    op->peer->lrp_networks.ea_s);

                ovn_lflow_add_with_hint(lflows, op->od, S_SWITCH_IN_ARP_ND_RSP,
                    50, ds_cstr(match), ds_cstr(actions), &op->nbsp->header_);
            }
        }
    }
}

/* Ingress table 18: ARP/ND responder, by default goto next.
 * (priority 0)*/
static void
build_lswitch_arp_nd_responder_default(struct ovn_datapath *od,
                                       struct hmap *lflows)
{
    if (od->nbs) {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ARP_ND_RSP, 0, "1", "next;");
    }
}

/* Ingress table 18: ARP/ND responder for service monitor source ip.
 * (priority 110)*/
static void
build_lswitch_arp_nd_service_monitor(struct ovn_northd_lb *lb,
                                     struct hmap *lflows,
                                     struct ds *actions,
                                     struct ds *match)
{
    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_northd_lb_vip *lb_vip_nb = &lb->vips_nb[i];
        if (!lb_vip_nb->lb_health_check) {
            continue;
        }

        for (size_t j = 0; j < lb_vip_nb->n_backends; j++) {
            struct ovn_northd_lb_backend *backend_nb =
                &lb_vip_nb->backends_nb[j];
            if (!backend_nb->op || !backend_nb->svc_mon_src_ip) {
                continue;
            }

            ds_clear(match);
            ds_put_format(match, "arp.tpa == %s && arp.op == 1",
                          backend_nb->svc_mon_src_ip);
            ds_clear(actions);
            ds_put_format(actions,
                "eth.dst = eth.src; "
                "eth.src = %s; "
                "arp.op = 2; /* ARP reply */ "
                "arp.tha = arp.sha; "
                "arp.sha = %s; "
                "arp.tpa = arp.spa; "
                "arp.spa = %s; "
                "outport = inport; "
                "flags.loopback = 1; "
                "output;",
                svc_monitor_mac, svc_monitor_mac,
                backend_nb->svc_mon_src_ip);
            ovn_lflow_add_with_hint(lflows,
                                    backend_nb->op->od,
                                    S_SWITCH_IN_ARP_ND_RSP, 110,
                                    ds_cstr(match), ds_cstr(actions),
                                    &lb->nlb->header_);
        }
    }
}


/* Logical switch ingress table 19 and 20: DHCP options and response
 * priority 100 flows. */
static void
build_lswitch_dhcp_options_and_response(struct ovn_port *op,
                                        struct hmap *lflows,
                                        const struct shash *meter_groups)
{
    if (op->nbsp) {
        if (!lsp_is_enabled(op->nbsp) || lsp_is_router(op->nbsp)) {
            /* Don't add the DHCP flows if the port is not enabled or if the
             * port is a router port. */
            return;
        }

        if (!op->nbsp->dhcpv4_options && !op->nbsp->dhcpv6_options) {
            /* CMS has disabled both native DHCPv4 and DHCPv6 for this lport.
             */
            return;
        }

        bool is_external = lsp_is_external(op->nbsp);
        if (is_external && (!op->od->n_localnet_ports ||
                            !op->nbsp->ha_chassis_group)) {
            /* If it's an external port and there are no localnet ports
             * and if it doesn't belong to an HA chassis group ignore it. */
            return;
        }

        for (size_t i = 0; i < op->n_lsp_addrs; i++) {
            if (is_external) {
                for (size_t j = 0; j < op->od->n_localnet_ports; j++) {
                    build_dhcpv4_options_flows(
                        op, &op->lsp_addrs[i],
                        op->od->localnet_ports[j], is_external,
                        meter_groups, lflows);
                    build_dhcpv6_options_flows(
                        op, &op->lsp_addrs[i],
                        op->od->localnet_ports[j], is_external,
                        meter_groups, lflows);
                }
            } else {
                build_dhcpv4_options_flows(op, &op->lsp_addrs[i], op,
                                           is_external, meter_groups,
                                           lflows);
                build_dhcpv6_options_flows(op, &op->lsp_addrs[i], op,
                                           is_external, meter_groups,
                                           lflows);
            }
        }
    }
}

/* Ingress table 19 and 20: DHCP options and response, by default goto
 * next. (priority 0).
 * Ingress table 21 and 22: DNS lookup and response, by default goto next.
 * (priority 0).
 * Ingress table 23 - External port handling, by default goto next.
 * (priority 0). */
static void
build_lswitch_dhcp_and_dns_defaults(struct ovn_datapath *od,
                                        struct hmap *lflows)
{
    if (od->nbs) {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_DHCP_OPTIONS, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_IN_DHCP_RESPONSE, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_IN_DNS_LOOKUP, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_IN_DNS_RESPONSE, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_IN_EXTERNAL_PORT, 0, "1", "next;");
    }
}

/* Logical switch ingress table 21 and 22: DNS lookup and response
* priority 100 flows.
*/
static void
build_lswitch_dns_lookup_and_response(struct ovn_datapath *od,
                                      struct hmap *lflows,
                                      const struct shash *meter_groups)
{
    if (od->nbs && ls_has_dns_records(od->nbs)) {
        ovn_lflow_metered(lflows, od, S_SWITCH_IN_DNS_LOOKUP, 100,
                          "udp.dst == 53",
                          REGBIT_DNS_LOOKUP_RESULT" = dns_lookup(); next;",
                          copp_meter_get(COPP_DNS, od->nbs->copp,
                                         meter_groups));
        const char *dns_action = "eth.dst <-> eth.src; ip4.src <-> ip4.dst; "
                      "udp.dst = udp.src; udp.src = 53; outport = inport; "
                      "flags.loopback = 1; output;";
        const char *dns_match = "udp.dst == 53 && "REGBIT_DNS_LOOKUP_RESULT;
        ovn_lflow_add(lflows, od, S_SWITCH_IN_DNS_RESPONSE, 100,
                      dns_match, dns_action);
        dns_action = "eth.dst <-> eth.src; ip6.src <-> ip6.dst; "
                      "udp.dst = udp.src; udp.src = 53; outport = inport; "
                      "flags.loopback = 1; output;";
        ovn_lflow_add(lflows, od, S_SWITCH_IN_DNS_RESPONSE, 100,
                      dns_match, dns_action);
    }
}

/* Table 23: External port. Drop ARP request for router ips from
 * external ports  on chassis not binding those ports.
 * This makes the router pipeline to be run only on the chassis
 * binding the external ports. */
static void
build_lswitch_external_port(struct ovn_port *op,
                            struct hmap *lflows)
{
    if (op->nbsp && lsp_is_external(op->nbsp)) {

        for (size_t i = 0; i < op->od->n_localnet_ports; i++) {
            build_drop_arp_nd_flows_for_unbound_router_ports(
                op, op->od->localnet_ports[i], lflows);
        }
    }
}

/* Ingress table 24: Destination lookup, broadcast and multicast handling
 * (priority 70 - 100). */
static void
build_lswitch_destination_lookup_bmcast(struct ovn_datapath *od,
                                        struct hmap *lflows,
                                        struct ds *actions,
                                        const struct shash *meter_groups)
{
    if (od->nbs) {

        ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, 110,
                      "eth.dst == $svc_monitor_mac",
                      "handle_svc_check(inport);");

        struct mcast_switch_info *mcast_sw_info = &od->mcast_info.sw;

        if (mcast_sw_info->enabled) {
            ds_clear(actions);
            ds_put_cstr(actions, "igmp;");
            /* Punt IGMP traffic to controller. */
            ovn_lflow_metered(lflows, od, S_SWITCH_IN_L2_LKUP, 100,
                              "igmp", ds_cstr(actions),
                              copp_meter_get(COPP_IGMP, od->nbs->copp,
                                             meter_groups));

            /* Punt MLD traffic to controller. */
            ovn_lflow_metered(lflows, od, S_SWITCH_IN_L2_LKUP, 100,
                              "mldv1 || mldv2", ds_cstr(actions),
                              copp_meter_get(COPP_IGMP, od->nbs->copp,
                                             meter_groups));

            /* Flood all IP multicast traffic destined to 224.0.0.X to all
             * ports - RFC 4541, section 2.1.2, item 2.
             */
            ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, 85,
                          "ip4.mcast && ip4.dst == 224.0.0.0/24",
                          "outport = \""MC_FLOOD_L2"\"; output;");

            /* Flood all IPv6 multicast traffic destined to reserved
             * multicast IPs (RFC 4291, 2.7.1).
             */
            ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, 85,
                          "ip6.mcast_flood",
                          "outport = \""MC_FLOOD"\"; output;");

            /* Forward uregistered IP multicast to routers with relay enabled
             * and to any ports configured to flood IP multicast traffic.
             * If configured to flood unregistered traffic this will be
             * handled by the L2 multicast flow.
             */
            if (!mcast_sw_info->flood_unregistered) {
                ds_clear(actions);

                if (mcast_sw_info->flood_relay) {
                    ds_put_cstr(actions,
                                "clone { "
                                    "outport = \""MC_MROUTER_FLOOD"\"; "
                                    "output; "
                                "}; ");
                }

                if (mcast_sw_info->flood_static) {
                    ds_put_cstr(actions, "outport =\""MC_STATIC"\"; output;");
                }

                /* Explicitly drop the traffic if relay or static flooding
                 * is not configured.
                 */
                if (!mcast_sw_info->flood_relay &&
                        !mcast_sw_info->flood_static) {
                    ds_put_cstr(actions, debug_drop_action());
                }

                ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, 80,
                              "ip4.mcast || ip6.mcast",
                              ds_cstr(actions));
            }
        }

        ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, 70, "eth.mcast",
                      "outport = \""MC_FLOOD"\"; output;");
    }
}


/* Ingress table 24: Add IP multicast flows learnt from IGMP/MLD
 * (priority 90). */
static void
build_lswitch_ip_mcast_igmp_mld(struct ovn_igmp_group *igmp_group,
                                struct hmap *lflows,
                                struct ds *actions,
                                struct ds *match)
{
    uint64_t dummy;

    if (igmp_group->datapath) {

        ds_clear(match);
        ds_clear(actions);

        struct mcast_switch_info *mcast_sw_info =
            &igmp_group->datapath->mcast_info.sw;
        uint64_t table_size = mcast_sw_info->table_size;

        if (IN6_IS_ADDR_V4MAPPED(&igmp_group->address)) {
            /* RFC 4541, section 2.1.2, item 2: Skip groups in the 224.0.0.X
             * range.
             */
            ovs_be32 group_address =
                in6_addr_get_mapped_ipv4(&igmp_group->address);
            if (ip_is_local_multicast(group_address)) {
                return;
            }
            if (atomic_compare_exchange_strong(
                        &mcast_sw_info->active_v4_flows, &table_size,
                        mcast_sw_info->table_size)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

                VLOG_INFO_RL(&rl, "Too many active mcast flows: %"PRIu64,
                             mcast_sw_info->active_v4_flows);
                return;
            }
            atomic_add(&mcast_sw_info->active_v4_flows, 1, &dummy);
            ds_put_format(match, "eth.mcast && ip4 && ip4.dst == %s ",
                          igmp_group->mcgroup.name);
        } else {
            /* RFC 4291, section 2.7.1: Skip groups that correspond to all
             * hosts.
             */
            if (ipv6_is_all_hosts(&igmp_group->address)) {
                return;
            }
            if (atomic_compare_exchange_strong(
                        &mcast_sw_info->active_v6_flows, &table_size,
                        mcast_sw_info->table_size)) {
                return;
            }
            atomic_add(&mcast_sw_info->active_v6_flows, 1, &dummy);
            ds_put_format(match, "eth.mcast && ip6 && ip6.dst == %s ",
                          igmp_group->mcgroup.name);
        }

        /* Also flood traffic to all multicast routers with relay enabled. */
        if (mcast_sw_info->flood_relay) {
            ds_put_cstr(actions,
                        "clone { "
                            "outport = \""MC_MROUTER_FLOOD "\"; "
                            "output; "
                        "};");
        }
        if (mcast_sw_info->flood_static) {
            ds_put_cstr(actions,
                        "clone { "
                            "outport =\""MC_STATIC"\"; "
                            "output; "
                        "};");
        }
        ds_put_format(actions, "outport = \"%s\"; output; ",
                      igmp_group->mcgroup.name);

        ovn_lflow_add(lflows, igmp_group->datapath, S_SWITCH_IN_L2_LKUP,
                      90, ds_cstr(match), ds_cstr(actions));
    }
}

static struct ovs_mutex mcgroup_mutex = OVS_MUTEX_INITIALIZER;

/* Ingress table 24: Destination lookup, unicast handling (priority 50), */
static void
build_lswitch_ip_unicast_lookup(struct ovn_port *op,
                                struct hmap *lflows,
                                struct hmap *mcgroups,
                                struct ds *actions,
                                struct ds *match)
{
    if (op->nbsp && (!lsp_is_external(op->nbsp))) {

        /* For ports connected to logical routers add flows to bypass the
         * broadcast flooding of ARP/ND requests in table 19. We direct the
         * requests only to the router port that owns the IP address.
         */
        if (lsp_is_router(op->nbsp)) {
            build_lswitch_rport_arp_req_flows(op->peer, op->od, op, lflows,
                                              &op->nbsp->header_);
        }

        for (size_t i = 0; i < op->nbsp->n_addresses; i++) {
            /* Addresses are owned by the logical port.
             * Ethernet address followed by zero or more IPv4
             * or IPv6 addresses (or both). */
            struct eth_addr mac;
            bool lsp_enabled = lsp_is_enabled(op->nbsp);
            char *action = lsp_enabled ? "outport = %s; output;" : "drop;";
            if (ovs_scan(op->nbsp->addresses[i],
                        ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))) {
                ds_clear(match);
                ds_put_format(match, "eth.dst == "ETH_ADDR_FMT,
                              ETH_ADDR_ARGS(mac));

                ds_clear(actions);
                ds_put_format(actions, action, op->json_key);
                ovn_lflow_add_with_hint(lflows, op->od, S_SWITCH_IN_L2_LKUP,
                                        50, ds_cstr(match),
                                        ds_cstr(actions),
                                        &op->nbsp->header_);
            } else if (!strcmp(op->nbsp->addresses[i], "unknown")) {
                if (lsp_enabled) {
                    ovs_mutex_lock(&mcgroup_mutex);
                    ovn_multicast_add(mcgroups, &mc_unknown, op);
                    ovs_mutex_unlock(&mcgroup_mutex);
                    op->od->has_unknown = true;
                }
            } else if (is_dynamic_lsp_address(op->nbsp->addresses[i])) {
                if (!op->nbsp->dynamic_addresses
                    || !ovs_scan(op->nbsp->dynamic_addresses,
                            ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))) {
                    continue;
                }
                ds_clear(match);
                ds_put_format(match, "eth.dst == "ETH_ADDR_FMT,
                              ETH_ADDR_ARGS(mac));

                ds_clear(actions);
                ds_put_format(actions, action, op->json_key);
                ovn_lflow_add_with_hint(lflows, op->od, S_SWITCH_IN_L2_LKUP,
                                        50, ds_cstr(match),
                                        ds_cstr(actions),
                                        &op->nbsp->header_);
            } else if (!strcmp(op->nbsp->addresses[i], "router")) {
                if (!op->peer || !op->peer->nbrp
                    || !ovs_scan(op->peer->nbrp->mac,
                            ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))) {
                    continue;
                }
                ds_clear(match);
                ds_put_format(match, "eth.dst == "ETH_ADDR_FMT,
                              ETH_ADDR_ARGS(mac));
                if (op->peer->od->n_l3dgw_ports
                    && op->od->n_localnet_ports) {
                    bool add_chassis_resident_check = false;
                    const char *json_key;
                    if (is_l3dgw_port(op->peer)) {
                        /* The peer of this port represents a distributed
                         * gateway port. The destination lookup flow for the
                         * router's distributed gateway port MAC address should
                         * only be programmed on the gateway chassis. */
                        add_chassis_resident_check = true;
                        json_key = op->peer->cr_port->json_key;
                    } else {
                        /* Check if the option 'reside-on-redirect-chassis'
                         * is set to true on the peer port. If set to true
                         * and if the logical switch has a localnet port, it
                         * means the router pipeline for the packets from
                         * this logical switch should be run on the chassis
                         * hosting the gateway port.
                         */
                        add_chassis_resident_check = smap_get_bool(
                            &op->peer->nbrp->options,
                            "reside-on-redirect-chassis", false) &&
                            op->peer->od->n_l3dgw_ports == 1;
                        json_key =
                            op->peer->od->l3dgw_ports[0]->cr_port->json_key;
                    }

                    if (add_chassis_resident_check) {
                        ds_put_format(match, " && is_chassis_resident(%s)",
                                      json_key);
                    }
                }

                ds_clear(actions);
                ds_put_format(actions, action, op->json_key);
                ovn_lflow_add_with_hint(lflows, op->od,
                                        S_SWITCH_IN_L2_LKUP, 50,
                                        ds_cstr(match), ds_cstr(actions),
                                        &op->nbsp->header_);

                /* Add ethernet addresses specified in NAT rules on
                 * distributed logical routers. */
                if (is_l3dgw_port(op->peer)) {
                    for (int j = 0; j < op->peer->od->nbr->n_nat; j++) {
                        const struct nbrec_nat *nat
                                                  = op->peer->od->nbr->nat[j];
                        if (!strcmp(nat->type, "dnat_and_snat")
                            && nat->logical_port && nat->external_mac
                            && eth_addr_from_string(nat->external_mac, &mac)) {

                            ds_clear(match);
                            ds_put_format(match, "eth.dst == "ETH_ADDR_FMT
                                          " && is_chassis_resident(\"%s\")",
                                          ETH_ADDR_ARGS(mac),
                                          nat->logical_port);

                            ds_clear(actions);
                            ds_put_format(actions, action, op->json_key);
                            ovn_lflow_add_with_hint(lflows, op->od,
                                                    S_SWITCH_IN_L2_LKUP, 50,
                                                    ds_cstr(match),
                                                    ds_cstr(actions),
                                                    &op->nbsp->header_);
                        }
                    }
                }
            } else {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

                VLOG_INFO_RL(&rl,
                             "%s: invalid syntax '%s' in addresses column",
                             op->nbsp->name, op->nbsp->addresses[i]);
            }
        }
    }
}

struct bfd_entry {
    struct hmap_node hmap_node;

    const struct sbrec_bfd *sb_bt;

    bool ref;
};

static struct bfd_entry *
bfd_port_lookup(const struct hmap *bfd_map, const char *logical_port,
                const char *dst_ip)
{
    struct bfd_entry *bfd_e;
    uint32_t hash;

    hash = hash_string(dst_ip, 0);
    hash = hash_string(logical_port, hash);
    HMAP_FOR_EACH_WITH_HASH (bfd_e, hmap_node, hash, bfd_map) {
        if (!strcmp(bfd_e->sb_bt->logical_port, logical_port) &&
            !strcmp(bfd_e->sb_bt->dst_ip, dst_ip)) {
            return bfd_e;
        }
    }
    return NULL;
}

void
bfd_cleanup_connections(struct lflow_input *input_data,
                        struct hmap *bfd_map)
{
    const struct nbrec_bfd *nb_bt;
    struct bfd_entry *bfd_e;

    NBREC_BFD_TABLE_FOR_EACH (nb_bt, input_data->nbrec_bfd_table) {
        bfd_e = bfd_port_lookup(bfd_map, nb_bt->logical_port, nb_bt->dst_ip);
        if (!bfd_e) {
            continue;
        }

        if (!bfd_e->ref && strcmp(nb_bt->status, "admin_down")) {
            /* no user for this bfd connection */
            nbrec_bfd_set_status(nb_bt, "admin_down");
        }
    }

    HMAP_FOR_EACH_POP (bfd_e, hmap_node, bfd_map) {
        free(bfd_e);
    }
}

#define BFD_DEF_MINTX       1000 /* 1s */
#define BFD_DEF_MINRX       1000 /* 1s */
#define BFD_DEF_DETECT_MULT 5

static void
build_bfd_update_sb_conf(const struct nbrec_bfd *nb_bt,
                         const struct sbrec_bfd *sb_bt)
{
    if (strcmp(nb_bt->dst_ip, sb_bt->dst_ip)) {
        sbrec_bfd_set_dst_ip(sb_bt, nb_bt->dst_ip);
    }

    if (strcmp(nb_bt->logical_port, sb_bt->logical_port)) {
        sbrec_bfd_set_logical_port(sb_bt, nb_bt->logical_port);
    }

    if (strcmp(nb_bt->status, sb_bt->status)) {
        sbrec_bfd_set_status(sb_bt, nb_bt->status);
    }

    int detect_mult = nb_bt->n_detect_mult ? nb_bt->detect_mult[0]
                                           : BFD_DEF_DETECT_MULT;
    if (detect_mult != sb_bt->detect_mult) {
        sbrec_bfd_set_detect_mult(sb_bt, detect_mult);
    }

    int min_tx = nb_bt->n_min_tx ? nb_bt->min_tx[0] : BFD_DEF_MINTX;
    if (min_tx != sb_bt->min_tx) {
        sbrec_bfd_set_min_tx(sb_bt, min_tx);
    }

    int min_rx = nb_bt->n_min_rx ? nb_bt->min_rx[0] : BFD_DEF_MINRX;
    if (min_rx != sb_bt->min_rx) {
        sbrec_bfd_set_min_rx(sb_bt, min_rx);
    }
}

/* RFC 5881 section 4
 * The source port MUST be in the range 49152 through 65535.
 * The same UDP source port number MUST be used for all BFD
 * Control packets associated with a particular session.
 * The source port number SHOULD be unique among all BFD
 * sessions on the system
 */
#define BFD_UDP_SRC_PORT_START  49152
#define BFD_UDP_SRC_PORT_LEN    (65535 - BFD_UDP_SRC_PORT_START)

static int bfd_get_unused_port(unsigned long *bfd_src_ports)
{
    int port;

    port = bitmap_scan(bfd_src_ports, 0, 0, BFD_UDP_SRC_PORT_LEN);
    if (port == BFD_UDP_SRC_PORT_LEN) {
        return -ENOSPC;
    }
    bitmap_set1(bfd_src_ports, port);

    return port + BFD_UDP_SRC_PORT_START;
}

void
build_bfd_table(struct lflow_input *input_data,
                struct ovsdb_idl_txn *ovnsb_txn,
                struct hmap *bfd_connections, struct hmap *ports)
{
    struct hmap sb_only = HMAP_INITIALIZER(&sb_only);
    const struct sbrec_bfd *sb_bt;
    unsigned long *bfd_src_ports;
    struct bfd_entry *bfd_e;
    uint32_t hash;

    bfd_src_ports = bitmap_allocate(BFD_UDP_SRC_PORT_LEN);

    SBREC_BFD_TABLE_FOR_EACH (sb_bt, input_data->sbrec_bfd_table) {
        bfd_e = xmalloc(sizeof *bfd_e);
        bfd_e->sb_bt = sb_bt;
        hash = hash_string(sb_bt->dst_ip, 0);
        hash = hash_string(sb_bt->logical_port, hash);
        hmap_insert(&sb_only, &bfd_e->hmap_node, hash);
        bitmap_set1(bfd_src_ports, sb_bt->src_port - BFD_UDP_SRC_PORT_START);
    }

    const struct nbrec_bfd *nb_bt;
    NBREC_BFD_TABLE_FOR_EACH (nb_bt, input_data->nbrec_bfd_table) {
        if (!nb_bt->status) {
            /* default state is admin_down */
            nbrec_bfd_set_status(nb_bt, "admin_down");
        }

        bfd_e = bfd_port_lookup(&sb_only, nb_bt->logical_port, nb_bt->dst_ip);
        if (!bfd_e) {
            int udp_src = bfd_get_unused_port(bfd_src_ports);
            if (udp_src < 0) {
                continue;
            }

            sb_bt = sbrec_bfd_insert(ovnsb_txn);
            sbrec_bfd_set_logical_port(sb_bt, nb_bt->logical_port);
            sbrec_bfd_set_dst_ip(sb_bt, nb_bt->dst_ip);
            sbrec_bfd_set_disc(sb_bt, 1 + random_uint32());
            sbrec_bfd_set_src_port(sb_bt, udp_src);
            sbrec_bfd_set_status(sb_bt, nb_bt->status);

            int min_tx = nb_bt->n_min_tx ? nb_bt->min_tx[0] : BFD_DEF_MINTX;
            sbrec_bfd_set_min_tx(sb_bt, min_tx);
            int min_rx = nb_bt->n_min_rx ? nb_bt->min_rx[0] : BFD_DEF_MINRX;
            sbrec_bfd_set_min_rx(sb_bt, min_rx);
            int d_mult = nb_bt->n_detect_mult ? nb_bt->detect_mult[0]
                                              : BFD_DEF_DETECT_MULT;
            sbrec_bfd_set_detect_mult(sb_bt, d_mult);
        } else {
            if (strcmp(bfd_e->sb_bt->status, nb_bt->status)) {
                if (!strcmp(nb_bt->status, "admin_down") ||
                    !strcmp(bfd_e->sb_bt->status, "admin_down")) {
                    sbrec_bfd_set_status(bfd_e->sb_bt, nb_bt->status);
                } else {
                    nbrec_bfd_set_status(nb_bt, bfd_e->sb_bt->status);
                }
            }
            build_bfd_update_sb_conf(nb_bt, bfd_e->sb_bt);

            hmap_remove(&sb_only, &bfd_e->hmap_node);
            bfd_e->ref = false;
            hash = hash_string(bfd_e->sb_bt->dst_ip, 0);
            hash = hash_string(bfd_e->sb_bt->logical_port, hash);
            hmap_insert(bfd_connections, &bfd_e->hmap_node, hash);
        }

        struct ovn_port *op = ovn_port_find(ports, nb_bt->logical_port);
        if (op) {
            op->has_bfd = true;
        }
    }

    HMAP_FOR_EACH_POP (bfd_e, hmap_node, &sb_only) {
        struct ovn_port *op = ovn_port_find(ports, bfd_e->sb_bt->logical_port);
        if (op) {
            op->has_bfd = false;
        }
        sbrec_bfd_delete(bfd_e->sb_bt);
        free(bfd_e);
    }
    hmap_destroy(&sb_only);

    bitmap_free(bfd_src_ports);
}

/* Returns a string of the IP address of the router port 'op' that
 * overlaps with 'ip_s".  If one is not found, returns NULL.
 *
 * The caller must not free the returned string. */
static const char *
find_lrp_member_ip(const struct ovn_port *op, const char *ip_s)
{
    return find_lport_address(&op->lrp_networks, ip_s);
}

static struct ovn_port*
get_outport_for_routing_policy_nexthop(struct ovn_datapath *od,
                                       const struct hmap *ports,
                                       int priority, const char *nexthop)
{
    if (nexthop == NULL) {
        return NULL;
    }

    /* Find the router port matching the next hop. */
    for (int i = 0; i < od->nbr->n_ports; i++) {
       struct nbrec_logical_router_port *lrp = od->nbr->ports[i];

       struct ovn_port *out_port = ovn_port_find(ports, lrp->name);
       if (out_port && find_lrp_member_ip(out_port, nexthop)) {
           return out_port;
       }
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
    VLOG_WARN_RL(&rl, "No path for routing policy priority %d; next hop %s",
                 priority, nexthop);
    return NULL;
}

static void
build_routing_policy_flow(struct hmap *lflows, struct ovn_datapath *od,
                          const struct hmap *ports,
                          const struct nbrec_logical_router_policy *rule,
                          const struct ovsdb_idl_row *stage_hint)
{
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    if (!strcmp(rule->action, "reroute")) {
        ovs_assert(rule->n_nexthops <= 1);

        char *nexthop =
            (rule->n_nexthops == 1 ? rule->nexthops[0] : rule->nexthop);
        struct ovn_port *out_port = get_outport_for_routing_policy_nexthop(
             od, ports, rule->priority, nexthop);
        if (!out_port) {
            return;
        }

        const char *lrp_addr_s = find_lrp_member_ip(out_port, nexthop);
        if (!lrp_addr_s) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "lrp_addr not found for routing policy "
                         " priority %"PRId64" nexthop %s",
                         rule->priority, nexthop);
            return;
        }
        uint32_t pkt_mark = ovn_smap_get_uint(&rule->options, "pkt_mark", 0);
        if (pkt_mark) {
            ds_put_format(&actions, "pkt.mark = %u; ", pkt_mark);
        }

        bool is_ipv4 = strchr(nexthop, '.') ? true : false;
        ds_put_format(&actions, "%s = %s; "
                      "%s = %s; "
                      "eth.src = %s; "
                      "outport = %s; "
                      "flags.loopback = 1; "
                      REG_ECMP_GROUP_ID" = 0; "
                      "next;",
                      is_ipv4 ? REG_NEXT_HOP_IPV4 : REG_NEXT_HOP_IPV6,
                      nexthop,
                      is_ipv4 ? REG_SRC_IPV4 : REG_SRC_IPV6,
                      lrp_addr_s,
                      out_port->lrp_networks.ea_s,
                      out_port->json_key);

    } else if (!strcmp(rule->action, "drop")) {
        ds_put_cstr(&actions, debug_drop_action());
    } else if (!strcmp(rule->action, "allow")) {
        uint32_t pkt_mark = ovn_smap_get_uint(&rule->options, "pkt_mark", 0);
        if (pkt_mark) {
            ds_put_format(&actions, "pkt.mark = %u; ", pkt_mark);
        }
        ds_put_cstr(&actions, REG_ECMP_GROUP_ID" = 0; next;");
    }
    ds_put_format(&match, "%s", rule->match);

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_POLICY, rule->priority,
                            ds_cstr(&match), ds_cstr(&actions), stage_hint);
    ds_destroy(&match);
    ds_destroy(&actions);
}

static void
build_ecmp_routing_policy_flows(struct hmap *lflows, struct ovn_datapath *od,
                                const struct hmap *ports,
                                const struct nbrec_logical_router_policy *rule,
                                uint16_t ecmp_group_id)
{
    ovs_assert(rule->n_nexthops > 1);

    bool nexthops_is_ipv4 = true;

    /* Check that all the nexthops belong to the same addr family before
     * adding logical flows. */
    for (uint16_t i = 0; i < rule->n_nexthops; i++) {
        bool is_ipv4 = strchr(rule->nexthops[i], '.') ? true : false;

        if (i == 0) {
            nexthops_is_ipv4 = is_ipv4;
        }

        if (is_ipv4 != nexthops_is_ipv4) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "nexthop [%s] of the router policy with "
                         "the match [%s] do not belong to the same address "
                         "family as other next hops",
                         rule->nexthops[i], rule->match);
            return;
        }
    }

    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    for (size_t i = 0; i < rule->n_nexthops; i++) {
        struct ovn_port *out_port = get_outport_for_routing_policy_nexthop(
             od, ports, rule->priority, rule->nexthops[i]);
        if (!out_port) {
            goto cleanup;
        }

        const char *lrp_addr_s =
            find_lrp_member_ip(out_port, rule->nexthops[i]);
        if (!lrp_addr_s) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "lrp_addr not found for routing policy "
                            " priority %"PRId64" nexthop %s",
                            rule->priority, rule->nexthops[i]);
            goto cleanup;
        }

        ds_clear(&actions);
        uint32_t pkt_mark = ovn_smap_get_uint(&rule->options, "pkt_mark", 0);
        if (pkt_mark) {
            ds_put_format(&actions, "pkt.mark = %u; ", pkt_mark);
        }

        bool is_ipv4 = strchr(rule->nexthops[i], '.') ? true : false;

        ds_put_format(&actions, "%s = %s; "
                      "%s = %s; "
                      "eth.src = %s; "
                      "outport = %s; "
                      "flags.loopback = 1; "
                      "next;",
                      is_ipv4 ? REG_NEXT_HOP_IPV4 : REG_NEXT_HOP_IPV6,
                      rule->nexthops[i],
                      is_ipv4 ? REG_SRC_IPV4 : REG_SRC_IPV6,
                      lrp_addr_s,
                      out_port->lrp_networks.ea_s,
                      out_port->json_key);

        ds_clear(&match);
        ds_put_format(&match, REG_ECMP_GROUP_ID" == %"PRIu16" && "
                      REG_ECMP_MEMBER_ID" == %"PRIuSIZE,
                      ecmp_group_id, i + 1);
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_POLICY_ECMP,
                                100, ds_cstr(&match),
                                ds_cstr(&actions), &rule->header_);
    }

    ds_clear(&actions);
    ds_put_format(&actions, "%s = %"PRIu16
                  "; %s = select(", REG_ECMP_GROUP_ID, ecmp_group_id,
                  REG_ECMP_MEMBER_ID);

    for (size_t i = 0; i < rule->n_nexthops; i++) {
        if (i > 0) {
            ds_put_cstr(&actions, ", ");
        }

        ds_put_format(&actions, "%"PRIuSIZE, i + 1);
    }
    ds_put_cstr(&actions, ");");
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_POLICY,
                            rule->priority, rule->match,
                            ds_cstr(&actions), &rule->header_);

cleanup:
    ds_destroy(&match);
    ds_destroy(&actions);
}

static uint32_t
route_table_add(struct simap *route_tables, const char *route_table_name)
{
    /* route table ids start from 1 */
    uint32_t rtb_id = simap_count(route_tables) + 1;

    if (rtb_id == UINT16_MAX) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "too many route tables for Logical Router.");
        return 0;
    }

    if (!simap_put(route_tables, route_table_name, rtb_id)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Route table id unexpectedly appeared");
    }

    return rtb_id;
}

static uint32_t
get_route_table_id(struct simap *route_tables, const char *route_table_name)
{
    if (!route_table_name || !strlen(route_table_name)) {
        return 0;
    }

    uint32_t rtb_id = simap_get(route_tables, route_table_name);
    if (!rtb_id) {
        rtb_id = route_table_add(route_tables, route_table_name);
    }

    return rtb_id;
}

static void
build_route_table_lflow(struct ovn_datapath *od, struct hmap *lflows,
                        struct nbrec_logical_router_port *lrp,
                        struct simap *route_tables)
{
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    const char *route_table_name = smap_get(&lrp->options, "route_table");
    uint32_t rtb_id = get_route_table_id(route_tables, route_table_name);
    if (!rtb_id) {
        return;
    }

    ds_put_format(&match, "inport == \"%s\"", lrp->name);
    ds_put_format(&actions, "%s = %d; next;",
                  REG_ROUTE_TABLE_ID, rtb_id);

    ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING_PRE, 100,
                  ds_cstr(&match), ds_cstr(&actions));

    ds_destroy(&match);
    ds_destroy(&actions);
}

struct parsed_route {
    struct ovs_list list_node;
    struct in6_addr prefix;
    unsigned int plen;
    bool is_src_route;
    uint32_t route_table_id;
    uint32_t hash;
    const struct nbrec_logical_router_static_route *route;
    bool ecmp_symmetric_reply;
    bool is_discard_route;
};

static uint32_t
route_hash(struct parsed_route *route)
{
    return hash_bytes(&route->prefix, sizeof route->prefix,
                      (uint32_t)route->plen);
}

static struct ovs_mutex bfd_lock = OVS_MUTEX_INITIALIZER;

static bool
find_static_route_outport(struct ovn_datapath *od, const struct hmap *ports,
    const struct nbrec_logical_router_static_route *route, bool is_ipv4,
    const char **p_lrp_addr_s, struct ovn_port **p_out_port);

/* Parse and validate the route. Return the parsed route if successful.
 * Otherwise return NULL. */
static struct parsed_route *
parsed_routes_add(struct ovn_datapath *od, const struct hmap *ports,
                  struct ovs_list *routes, struct simap *route_tables,
                  const struct nbrec_logical_router_static_route *route,
                  const struct hmap *bfd_connections)
{
    /* Verify that the next hop is an IP address with an all-ones mask. */
    struct in6_addr nexthop;
    unsigned int plen;
    bool is_discard_route = !strcmp(route->nexthop, "discard");
    bool valid_nexthop = strlen(route->nexthop) && !is_discard_route;
    if (valid_nexthop) {
        if (!ip46_parse_cidr(route->nexthop, &nexthop, &plen)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad 'nexthop' %s in static route "
                         UUID_FMT, route->nexthop,
                         UUID_ARGS(&route->header_.uuid));
            return NULL;
        }
        if ((IN6_IS_ADDR_V4MAPPED(&nexthop) && plen != 32) ||
            (!IN6_IS_ADDR_V4MAPPED(&nexthop) && plen != 128)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad next hop mask %s in static route "
                         UUID_FMT, route->nexthop,
                         UUID_ARGS(&route->header_.uuid));
            return NULL;
        }
    }

    /* Parse ip_prefix */
    struct in6_addr prefix;
    if (!ip46_parse_cidr(route->ip_prefix, &prefix, &plen)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad 'ip_prefix' %s in static route "
                     UUID_FMT, route->ip_prefix,
                     UUID_ARGS(&route->header_.uuid));
        return NULL;
    }

    /* Verify that ip_prefix and nexthop have same address familiy. */
    if (valid_nexthop) {
        if (IN6_IS_ADDR_V4MAPPED(&prefix) != IN6_IS_ADDR_V4MAPPED(&nexthop)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Address family doesn't match between 'ip_prefix'"
                         " %s and 'nexthop' %s in static route "UUID_FMT,
                         route->ip_prefix, route->nexthop,
                         UUID_ARGS(&route->header_.uuid));
            return NULL;
        }
    }

    /* Verify that ip_prefix and nexthop are on the same network. */
    if (!is_discard_route &&
        !find_static_route_outport(od, ports, route,
                                   IN6_IS_ADDR_V4MAPPED(&prefix),
                                   NULL, NULL)) {
        return NULL;
    }

    const struct nbrec_bfd *nb_bt = route->bfd;
    if (nb_bt && !strcmp(nb_bt->dst_ip, route->nexthop)) {
        struct bfd_entry *bfd_e;

        bfd_e = bfd_port_lookup(bfd_connections, nb_bt->logical_port,
                                nb_bt->dst_ip);
        ovs_mutex_lock(&bfd_lock);
        if (bfd_e) {
            bfd_e->ref = true;
        }

        if (!strcmp(nb_bt->status, "admin_down")) {
            nbrec_bfd_set_status(nb_bt, "down");
        }

        if (!strcmp(nb_bt->status, "down")) {
            ovs_mutex_unlock(&bfd_lock);
            return NULL;
        }
        ovs_mutex_unlock(&bfd_lock);
    }

    struct parsed_route *pr = xzalloc(sizeof *pr);
    pr->prefix = prefix;
    pr->plen = plen;
    pr->route_table_id = get_route_table_id(route_tables, route->route_table);
    pr->is_src_route = (route->policy && !strcmp(route->policy,
                                                 "src-ip"));
    pr->hash = route_hash(pr);
    pr->route = route;
    pr->ecmp_symmetric_reply = smap_get_bool(&route->options,
                                             "ecmp_symmetric_reply", false);
    pr->is_discard_route = is_discard_route;
    ovs_list_insert(routes, &pr->list_node);
    return pr;
}

static void
parsed_routes_destroy(struct ovs_list *routes)
{
    struct parsed_route *pr;
    LIST_FOR_EACH_SAFE (pr, list_node, routes) {
        ovs_list_remove(&pr->list_node);
        free(pr);
    }
}

struct ecmp_route_list_node {
    struct ovs_list list_node;
    uint16_t id; /* starts from 1 */
    const struct parsed_route *route;
};

struct ecmp_groups_node {
    struct hmap_node hmap_node; /* In ecmp_groups */
    uint16_t id; /* starts from 1 */
    struct in6_addr prefix;
    unsigned int plen;
    bool is_src_route;
    const char *origin;
    uint32_t route_table_id;
    uint16_t route_count;
    struct ovs_list route_list; /* Contains ecmp_route_list_node */
};

static void
ecmp_groups_add_route(struct ecmp_groups_node *group,
                      const struct parsed_route *route)
{
    if (group->route_count == UINT16_MAX) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "too many routes in a single ecmp group.");
        return;
    }

    struct ecmp_route_list_node *er = xmalloc(sizeof *er);
    er->route = route;
    er->id = ++group->route_count;
    ovs_list_insert(&group->route_list, &er->list_node);
}

static struct ecmp_groups_node *
ecmp_groups_add(struct hmap *ecmp_groups,
                const struct parsed_route *route)
{
    if (hmap_count(ecmp_groups) == UINT16_MAX) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "too many ecmp groups.");
        return NULL;
    }

    struct ecmp_groups_node *eg = xzalloc(sizeof *eg);
    hmap_insert(ecmp_groups, &eg->hmap_node, route->hash);

    eg->id = hmap_count(ecmp_groups);
    eg->prefix = route->prefix;
    eg->plen = route->plen;
    eg->is_src_route = route->is_src_route;
    eg->origin = smap_get_def(&route->route->options, "origin", "");
    eg->route_table_id = route->route_table_id;
    ovs_list_init(&eg->route_list);
    ecmp_groups_add_route(eg, route);

    return eg;
}

static struct ecmp_groups_node *
ecmp_groups_find(struct hmap *ecmp_groups, struct parsed_route *route)
{
    struct ecmp_groups_node *eg;
    HMAP_FOR_EACH_WITH_HASH (eg, hmap_node, route->hash, ecmp_groups) {
        if (ipv6_addr_equals(&eg->prefix, &route->prefix) &&
            eg->plen == route->plen &&
            eg->is_src_route == route->is_src_route &&
            eg->route_table_id == route->route_table_id) {
            return eg;
        }
    }
    return NULL;
}

static void
ecmp_groups_destroy(struct hmap *ecmp_groups)
{
    struct ecmp_groups_node *eg;
    HMAP_FOR_EACH_SAFE (eg, hmap_node, ecmp_groups) {
        struct ecmp_route_list_node *er;
        LIST_FOR_EACH_SAFE (er, list_node, &eg->route_list) {
            ovs_list_remove(&er->list_node);
            free(er);
        }
        hmap_remove(ecmp_groups, &eg->hmap_node);
        free(eg);
    }
    hmap_destroy(ecmp_groups);
}

struct unique_routes_node {
    struct hmap_node hmap_node;
    const struct parsed_route *route;
};

static void
unique_routes_add(struct hmap *unique_routes,
                  const struct parsed_route *route)
{
    struct unique_routes_node *ur = xmalloc(sizeof *ur);
    ur->route = route;
    hmap_insert(unique_routes, &ur->hmap_node, route->hash);
}

/* Remove the unique_routes_node from the hmap, and return the parsed_route
 * pointed by the removed node. */
static const struct parsed_route *
unique_routes_remove(struct hmap *unique_routes,
                     const struct parsed_route *route)
{
    struct unique_routes_node *ur;
    HMAP_FOR_EACH_WITH_HASH (ur, hmap_node, route->hash, unique_routes) {
        if (ipv6_addr_equals(&route->prefix, &ur->route->prefix) &&
            route->plen == ur->route->plen &&
            route->is_src_route == ur->route->is_src_route &&
            route->route_table_id == ur->route->route_table_id) {
            hmap_remove(unique_routes, &ur->hmap_node);
            const struct parsed_route *existed_route = ur->route;
            free(ur);
            return existed_route;
        }
    }
    return NULL;
}

static void
unique_routes_destroy(struct hmap *unique_routes)
{
    struct unique_routes_node *ur;
    HMAP_FOR_EACH_SAFE (ur, hmap_node, unique_routes) {
        hmap_remove(unique_routes, &ur->hmap_node);
        free(ur);
    }
    hmap_destroy(unique_routes);
}

static char *
build_route_prefix_s(const struct in6_addr *prefix, unsigned int plen)
{
    char *prefix_s;
    if (IN6_IS_ADDR_V4MAPPED(prefix)) {
        prefix_s = xasprintf(IP_FMT, IP_ARGS(in6_addr_get_mapped_ipv4(prefix) &
                                             be32_prefix_mask(plen)));
    } else {
        struct in6_addr mask = ipv6_create_mask(plen);
        struct in6_addr network = ipv6_addr_bitand(prefix, &mask);
        prefix_s = xmalloc(INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &network, prefix_s, INET6_ADDRSTRLEN);
    }
    return prefix_s;
}

static void
build_route_match(const struct ovn_port *op_inport, uint32_t rtb_id,
                  const char *network_s, int plen, bool is_src_route,
                  bool is_ipv4, struct ds *match, uint16_t *priority, int ofs)
{
    const char *dir;
    /* The priority here is calculated to implement longest-prefix-match
     * routing. */
    if (is_src_route) {
        dir = "src";
        ofs = 0;
    } else {
        dir = "dst";
    }

    *priority = (plen * ROUTE_PRIO_OFFSET_MULTIPLIER) + ofs;

    if (op_inport) {
        ds_put_format(match, "inport == %s && ", op_inport->json_key);
    }
    if (rtb_id || ofs == ROUTE_PRIO_OFFSET_STATIC) {
        ds_put_format(match, "%s == %d && ", REG_ROUTE_TABLE_ID, rtb_id);
    }
    ds_put_format(match, "ip%s.%s == %s/%d", is_ipv4 ? "4" : "6", dir,
                  network_s, plen);
}

/* Output: p_lrp_addr_s and p_out_port. */
static bool
find_static_route_outport(struct ovn_datapath *od, const struct hmap *ports,
    const struct nbrec_logical_router_static_route *route, bool is_ipv4,
    const char **p_lrp_addr_s, struct ovn_port **p_out_port)
{
    const char *lrp_addr_s = NULL;
    struct ovn_port *out_port = NULL;
    if (route->output_port) {
        out_port = ovn_port_find(ports, route->output_port);
        if (!out_port) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Bad out port %s for static route %s",
                         route->output_port, route->ip_prefix);
            return false;
        }
        if (strlen(route->nexthop)) {
            lrp_addr_s = find_lrp_member_ip(out_port, route->nexthop);
        }
        if (!lrp_addr_s) {
            /* There are no IP networks configured on the router's port via
             * which 'route->nexthop' is theoretically reachable.  But since
             * 'out_port' has been specified, we honor it by trying to reach
             * 'route->nexthop' via the first IP address of 'out_port'.
             * (There are cases, e.g in GCE, where each VM gets a /32 IP
             * address and the default gateway is still reachable from it.) */
            if (is_ipv4) {
                if (out_port->lrp_networks.n_ipv4_addrs) {
                    lrp_addr_s = out_port->lrp_networks.ipv4_addrs[0].addr_s;
                }
            } else {
                if (out_port->lrp_networks.n_ipv6_addrs) {
                    lrp_addr_s = out_port->lrp_networks.ipv6_addrs[0].addr_s;
                }
            }
        }
    } else {
        /* output_port is not specified, find the
         * router port matching the next hop. */
        int i;
        for (i = 0; i < od->nbr->n_ports; i++) {
            struct nbrec_logical_router_port *lrp = od->nbr->ports[i];
            out_port = ovn_port_find(ports, lrp->name);
            if (!out_port) {
                /* This should not happen. */
                continue;
            }

            if (strlen(route->nexthop)) {
                lrp_addr_s = find_lrp_member_ip(out_port, route->nexthop);
            }
            if (lrp_addr_s) {
                break;
            }
        }
    }
    if (!out_port || !lrp_addr_s) {
        /* There is no matched out port. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "No path for static route %s; next hop %s",
                     route->ip_prefix, route->nexthop);
        return false;
    }
    if (p_out_port) {
        *p_out_port = out_port;
    }
    if (p_lrp_addr_s) {
        *p_lrp_addr_s = lrp_addr_s;
    }

    return true;
}

static void
add_ecmp_symmetric_reply_flows(struct hmap *lflows,
                               struct ovn_datapath *od,
                               bool ct_masked_mark,
                               const char *port_ip,
                               struct ovn_port *out_port,
                               const struct parsed_route *route,
                               struct ds *route_match)
{
    const struct nbrec_logical_router_static_route *st_route = route->route;
    struct ds base_match = DS_EMPTY_INITIALIZER;
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;
    struct ds ecmp_reply = DS_EMPTY_INITIALIZER;
    char *cidr = normalize_v46_prefix(&route->prefix, route->plen);
    const char *ct_ecmp_reply_port_match = ct_masked_mark
                                           ? "ct_mark.ecmp_reply_port"
                                           : "ct_label.ecmp_reply_port";

    /* If symmetric ECMP replies are enabled, then packets that arrive over
     * an ECMP route need to go through conntrack.
     */
    ds_put_format(&base_match, "inport == %s && ip%s.%s == %s",
                  out_port->json_key,
                  IN6_IS_ADDR_V4MAPPED(&route->prefix) ? "4" : "6",
                  route->is_src_route ? "dst" : "src",
                  cidr);
    free(cidr);
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DEFRAG, 100,
            ds_cstr(&base_match),
            REGBIT_KNOWN_ECMP_NH" = chk_ecmp_nh_mac(); ct_next;",
            &st_route->header_);

    /* And packets that go out over an ECMP route need conntrack */
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DEFRAG, 100,
            ds_cstr(route_match),
            REGBIT_KNOWN_ECMP_NH" = chk_ecmp_nh(); ct_next;",
            &st_route->header_);

    /* Save src eth and inport in ct_label for packets that arrive over
     * an ECMP route.
     *
     * NOTE: we purposely are not clearing match before this
     * ds_put_cstr() call. The previous contents are needed.
     */
    ds_put_format(&match, "%s && (ct.new && !ct.est) && tcp",
                  ds_cstr(&base_match));
    ds_put_format(&actions,
            "ct_commit { ct_label.ecmp_reply_eth = eth.src; "
            " %s = %" PRId64 ";}; "
            "commit_ecmp_nh(ipv6 = %s, proto = tcp); next;",
            ct_ecmp_reply_port_match, out_port->sb->tunnel_key,
            IN6_IS_ADDR_V4MAPPED(&route->prefix) ? "false" : "true");
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_ECMP_STATEFUL, 100,
                            ds_cstr(&match), ds_cstr(&actions),
                            &st_route->header_);
    ds_clear(&match);
    ds_put_format(&match, "%s && (ct.new && !ct.est) && udp",
                  ds_cstr(&base_match));
    ds_clear(&actions);
    ds_put_format(&actions,
            "ct_commit { ct_label.ecmp_reply_eth = eth.src; "
            " %s = %" PRId64 ";}; "
            "commit_ecmp_nh(ipv6 = %s, proto = udp); next;",
            ct_ecmp_reply_port_match, out_port->sb->tunnel_key,
            IN6_IS_ADDR_V4MAPPED(&route->prefix) ? "false" : "true");
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_ECMP_STATEFUL, 100,
                            ds_cstr(&match), ds_cstr(&actions),
                            &st_route->header_);
    ds_clear(&match);
    ds_put_format(&match, "%s && (ct.new && !ct.est) && sctp",
                  ds_cstr(&base_match));
    ds_clear(&actions);
    ds_put_format(&actions,
            "ct_commit { ct_label.ecmp_reply_eth = eth.src; "
            " %s = %" PRId64 ";}; "
            "commit_ecmp_nh(ipv6 = %s, proto = sctp); next;",
            ct_ecmp_reply_port_match, out_port->sb->tunnel_key,
            IN6_IS_ADDR_V4MAPPED(&route->prefix) ? "false" : "true");
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_ECMP_STATEFUL, 100,
                            ds_cstr(&match), ds_cstr(&actions),
                            &st_route->header_);

    ds_clear(&match);
    ds_put_format(&match,
            "%s && (!ct.rpl && ct.est) && tcp && "REGBIT_KNOWN_ECMP_NH" == 0",
            ds_cstr(&base_match));
    ds_clear(&actions);
    ds_put_format(&actions,
            "ct_commit { ct_label.ecmp_reply_eth = eth.src; "
            " %s = %" PRId64 ";}; "
            "commit_ecmp_nh(ipv6 = %s, proto = tcp); next;",
            ct_ecmp_reply_port_match, out_port->sb->tunnel_key,
            IN6_IS_ADDR_V4MAPPED(&route->prefix) ? "false" : "true");
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_ECMP_STATEFUL, 100,
                            ds_cstr(&match), ds_cstr(&actions),
                            &st_route->header_);

    ds_clear(&match);
    ds_put_format(&match,
            "%s && (!ct.rpl && ct.est) && udp && "REGBIT_KNOWN_ECMP_NH" == 0",
            ds_cstr(&base_match));
    ds_clear(&actions);
    ds_put_format(&actions,
            "ct_commit { ct_label.ecmp_reply_eth = eth.src; "
            " %s = %" PRId64 ";}; "
            "commit_ecmp_nh(ipv6 = %s, proto = udp); next;",
            ct_ecmp_reply_port_match, out_port->sb->tunnel_key,
            IN6_IS_ADDR_V4MAPPED(&route->prefix) ? "false" : "true");
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_ECMP_STATEFUL, 100,
                            ds_cstr(&match), ds_cstr(&actions),
                            &st_route->header_);
    ds_clear(&match);
    ds_put_format(&match,
            "%s && (!ct.rpl && ct.est) && sctp && "REGBIT_KNOWN_ECMP_NH" == 0",
            ds_cstr(&base_match));
    ds_clear(&actions);
    ds_put_format(&actions,
            "ct_commit { ct_label.ecmp_reply_eth = eth.src; "
            " %s = %" PRId64 ";}; "
            "commit_ecmp_nh(ipv6 = %s, proto = sctp); next;",
            ct_ecmp_reply_port_match, out_port->sb->tunnel_key,
            IN6_IS_ADDR_V4MAPPED(&route->prefix) ? "false" : "true");
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_ECMP_STATEFUL, 100,
                            ds_cstr(&match), ds_cstr(&actions),
                            &st_route->header_);

    /* Bypass ECMP selection if we already have ct_label information
     * for where to route the packet.
     */
    ds_put_format(&ecmp_reply,
                  "ct.rpl && "REGBIT_KNOWN_ECMP_NH" == 1 && %s == %"PRId64,
                  ct_ecmp_reply_port_match, out_port->sb->tunnel_key);
    ds_clear(&match);
    ds_put_format(&match, "%s && %s", ds_cstr(&ecmp_reply),
                  ds_cstr(route_match));
    ds_clear(&actions);
    ds_put_format(&actions, "ip.ttl--; flags.loopback = 1; "
                  "eth.src = %s; %sreg1 = %s; outport = %s; next;",
                  out_port->lrp_networks.ea_s,
                  IN6_IS_ADDR_V4MAPPED(&route->prefix) ? "" : "xx",
                  port_ip, out_port->json_key);
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_IP_ROUTING, 10300,
                           ds_cstr(&match), ds_cstr(&actions),
                           &st_route->header_);

    /* Egress reply traffic for symmetric ECMP routes skips router policies. */
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_POLICY, 65535,
                            ds_cstr(&ecmp_reply), "next;",
                            &st_route->header_);

    /* Use REG_ECMP_ETH_FULL to pass the eth field from ct_label to eth.dst to
     * avoid masked access to ct_label. Otherwise it may prevent OVS flow
     * HW offloading to work for some NICs because masked-access of ct_label is
     * not supported on those NICs due to HW limitations.
     *
     * Use push/pop to save the value of the register before using it and
     * restore it immediately afterwards, so that the use of the register is
     * temporary and doesn't interfere with other stages. */
    const char *action = "push(" REG_ECMP_ETH_FULL "); "
                         REG_ECMP_ETH_FULL " = ct_label;"
                         " eth.dst = " REG_ECMP_ETH_FIELD ";"
                         " pop(" REG_ECMP_ETH_FULL "); next;";
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_ARP_RESOLVE,
                            200, ds_cstr(&ecmp_reply),
                            action, &st_route->header_);

    ds_destroy(&base_match);
    ds_destroy(&match);
    ds_destroy(&actions);
    ds_destroy(&ecmp_reply);
}

static void
build_ecmp_route_flow(struct hmap *lflows, struct ovn_datapath *od,
                      bool ct_masked_mark, const struct hmap *ports,
                      struct ecmp_groups_node *eg)

{
    bool is_ipv4 = IN6_IS_ADDR_V4MAPPED(&eg->prefix);
    uint16_t priority;
    struct ecmp_route_list_node *er;
    struct ds route_match = DS_EMPTY_INITIALIZER;

    char *prefix_s = build_route_prefix_s(&eg->prefix, eg->plen);
    int ofs = !strcmp(eg->origin, ROUTE_ORIGIN_CONNECTED) ?
        ROUTE_PRIO_OFFSET_CONNECTED: ROUTE_PRIO_OFFSET_STATIC;
    build_route_match(NULL, eg->route_table_id, prefix_s, eg->plen,
                      eg->is_src_route, is_ipv4, &route_match, &priority, ofs);
    free(prefix_s);

    struct ds actions = DS_EMPTY_INITIALIZER;
    ds_put_format(&actions, "ip.ttl--; flags.loopback = 1; %s = %"PRIu16
                  "; %s = select(", REG_ECMP_GROUP_ID, eg->id,
                  REG_ECMP_MEMBER_ID);

    bool is_first = true;
    LIST_FOR_EACH (er, list_node, &eg->route_list) {
        if (is_first) {
            is_first = false;
        } else {
            ds_put_cstr(&actions, ", ");
        }
        ds_put_format(&actions, "%"PRIu16, er->id);
    }

    ds_put_cstr(&actions, ");");

    ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, priority,
                  ds_cstr(&route_match), ds_cstr(&actions));

    /* Add per member flow */
    struct ds match = DS_EMPTY_INITIALIZER;
    struct sset visited_ports = SSET_INITIALIZER(&visited_ports);
    LIST_FOR_EACH (er, list_node, &eg->route_list) {
        const struct parsed_route *route_ = er->route;
        const struct nbrec_logical_router_static_route *route = route_->route;
        /* Find the outgoing port. */
        const char *lrp_addr_s = NULL;
        struct ovn_port *out_port = NULL;
        if (!find_static_route_outport(od, ports, route, is_ipv4, &lrp_addr_s,
                                       &out_port)) {
            continue;
        }
        /* Symmetric ECMP reply is only usable on gateway routers.
         * It is NOT usable on distributed routers with a gateway port.
         */
        if (smap_get(&od->nbr->options, "chassis") &&
            route_->ecmp_symmetric_reply && sset_add(&visited_ports,
                                                     out_port->key)) {
            add_ecmp_symmetric_reply_flows(lflows, od, ct_masked_mark,
                                           lrp_addr_s, out_port,
                                           route_, &route_match);
        }
        ds_clear(&match);
        ds_put_format(&match, REG_ECMP_GROUP_ID" == %"PRIu16" && "
                      REG_ECMP_MEMBER_ID" == %"PRIu16,
                      eg->id, er->id);
        ds_clear(&actions);
        ds_put_format(&actions, "%s = %s; "
                      "%s = %s; "
                      "eth.src = %s; "
                      "outport = %s; "
                      "next;",
                      is_ipv4 ? REG_NEXT_HOP_IPV4 : REG_NEXT_HOP_IPV6,
                      route->nexthop,
                      is_ipv4 ? REG_SRC_IPV4 : REG_SRC_IPV6,
                      lrp_addr_s,
                      out_port->lrp_networks.ea_s,
                      out_port->json_key);
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_IP_ROUTING_ECMP, 100,
                                ds_cstr(&match), ds_cstr(&actions),
                                &route->header_);
    }
    sset_destroy(&visited_ports);
    ds_destroy(&match);
    ds_destroy(&route_match);
    ds_destroy(&actions);
}

static void
add_route(struct hmap *lflows, struct ovn_datapath *od,
          const struct ovn_port *op, const char *lrp_addr_s,
          const char *network_s, int plen, const char *gateway,
          bool is_src_route, const uint32_t rtb_id,
          const struct ovsdb_idl_row *stage_hint, bool is_discard_route,
          int ofs)
{
    bool is_ipv4 = strchr(network_s, '.') ? true : false;
    struct ds match = DS_EMPTY_INITIALIZER;
    uint16_t priority;
    const struct ovn_port *op_inport = NULL;

    /* IPv6 link-local addresses must be scoped to the local router port. */
    if (!is_ipv4) {
        struct in6_addr network;
        ovs_assert(ipv6_parse(network_s, &network));
        if (in6_is_lla(&network)) {
            op_inport = op;
        }
    }
    build_route_match(op_inport, rtb_id, network_s, plen, is_src_route,
                      is_ipv4, &match, &priority, ofs);

    struct ds common_actions = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;
    if (is_discard_route) {
        ds_put_cstr(&actions, debug_drop_action());
    } else {
        ds_put_format(&common_actions, REG_ECMP_GROUP_ID" = 0; %s = ",
                      is_ipv4 ? REG_NEXT_HOP_IPV4 : REG_NEXT_HOP_IPV6);
        if (gateway && strlen(gateway)) {
            ds_put_cstr(&common_actions, gateway);
        } else {
            ds_put_format(&common_actions, "ip%s.dst", is_ipv4 ? "4" : "6");
        }
        ds_put_format(&common_actions, "; "
                      "%s = %s; "
                      "eth.src = %s; "
                      "outport = %s; "
                      "flags.loopback = 1; "
                      "next;",
                      is_ipv4 ? REG_SRC_IPV4 : REG_SRC_IPV6,
                      lrp_addr_s,
                      op->lrp_networks.ea_s,
                      op->json_key);
        ds_put_format(&actions, "ip.ttl--; %s", ds_cstr(&common_actions));
    }

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_IP_ROUTING, priority,
                            ds_cstr(&match), ds_cstr(&actions),
                            stage_hint);
    if (op && op->has_bfd) {
        ds_put_format(&match, " && udp.dst == 3784");
        ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_ROUTING,
                                priority + 1, ds_cstr(&match),
                                ds_cstr(&common_actions), stage_hint);
    }
    ds_destroy(&match);
    ds_destroy(&common_actions);
    ds_destroy(&actions);
}

static void
build_static_route_flow(struct hmap *lflows, struct ovn_datapath *od,
                        const struct hmap *ports,
                        const struct parsed_route *route_)
{
    const char *lrp_addr_s = NULL;
    struct ovn_port *out_port = NULL;

    const struct nbrec_logical_router_static_route *route = route_->route;

    /* Find the outgoing port. */
    if (!route_->is_discard_route) {
        if (!find_static_route_outport(od, ports, route,
                                       IN6_IS_ADDR_V4MAPPED(&route_->prefix),
                                       &lrp_addr_s, &out_port)) {
            return;
        }
    }

    int ofs = !strcmp(smap_get_def(&route->options, "origin", ""),
                      ROUTE_ORIGIN_CONNECTED) ? ROUTE_PRIO_OFFSET_CONNECTED
                                              : ROUTE_PRIO_OFFSET_STATIC;

    char *prefix_s = build_route_prefix_s(&route_->prefix, route_->plen);
    add_route(lflows, route_->is_discard_route ? od : out_port->od, out_port,
              lrp_addr_s, prefix_s, route_->plen, route->nexthop,
              route_->is_src_route, route_->route_table_id, &route->header_,
              route_->is_discard_route, ofs);

    free(prefix_s);
}

static void
op_put_v4_networks(struct ds *ds, const struct ovn_port *op, bool add_bcast)
{
    if (!add_bcast && op->lrp_networks.n_ipv4_addrs == 1) {
        ds_put_format(ds, "%s", op->lrp_networks.ipv4_addrs[0].addr_s);
        return;
    }

    ds_put_cstr(ds, "{");
    for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
        ds_put_format(ds, "%s, ", op->lrp_networks.ipv4_addrs[i].addr_s);
        if (add_bcast) {
            ds_put_format(ds, "%s, ", op->lrp_networks.ipv4_addrs[i].bcast_s);
        }
    }
    ds_chomp(ds, ' ');
    ds_chomp(ds, ',');
    ds_put_cstr(ds, "}");
}

static void
op_put_v6_networks(struct ds *ds, const struct ovn_port *op)
{
    if (op->lrp_networks.n_ipv6_addrs == 1) {
        ds_put_format(ds, "%s", op->lrp_networks.ipv6_addrs[0].addr_s);
        return;
    }

    ds_put_cstr(ds, "{");
    for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
        ds_put_format(ds, "%s, ", op->lrp_networks.ipv6_addrs[i].addr_s);
    }
    ds_chomp(ds, ' ');
    ds_chomp(ds, ',');
    ds_put_cstr(ds, "}");
}

static bool
get_force_snat_ip(struct ovn_datapath *od, const char *key_type,
                  struct lport_addresses *laddrs)
{
    char *key = xasprintf("%s_force_snat_ip", key_type);
    const char *addresses = smap_get(&od->nbr->options, key);
    free(key);

    if (!addresses) {
        return false;
    }

    if (!extract_ip_address(addresses, laddrs)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad ip %s in options of router "UUID_FMT"",
                     addresses, UUID_ARGS(&od->key));
        return false;
    }

    return true;
}

static void
build_gw_lrouter_nat_flows_for_lb(struct ovn_northd_lb *lb,
                                  struct ovn_datapath **dplist, int n_dplist,
                                  bool reject, char *new_match,
                                  char *new_action, char *est_match,
                                  char *est_action, struct hmap *lflows,
                                  int prio, const struct shash *meter_groups)
{
    if (!n_dplist) {
        return;
    }

    struct ovn_lflow *lflow_ref_new = NULL, *lflow_ref_est = NULL;
    uint32_t hash_new = ovn_logical_flow_hash(
            ovn_stage_get_table(S_ROUTER_IN_DNAT),
            ovn_stage_get_pipeline(S_ROUTER_IN_DNAT),
            prio, new_match, new_action);
    uint32_t hash_est = ovn_logical_flow_hash(
            ovn_stage_get_table(S_ROUTER_IN_DNAT),
            ovn_stage_get_pipeline(S_ROUTER_IN_DNAT),
            prio, est_match, est_action);

    for (size_t i = 0; i < n_dplist; i++) {
        struct ovn_datapath *od = dplist[i];
        const char *meter = NULL;

        if (reject) {
            meter = copp_meter_get(COPP_REJECT, od->nbr->copp, meter_groups);
        }
        if (meter || !ovn_dp_group_add_with_reference(lflow_ref_new, od)) {
            struct ovn_lflow *lflow = ovn_lflow_add_at_with_hash(lflows, od,
                    S_ROUTER_IN_DNAT, prio, new_match, new_action,
                    NULL, meter, &lb->nlb->header_, OVS_SOURCE_LOCATOR,
                    hash_new);
            lflow_ref_new = meter ? NULL : lflow;
        }

        if (!ovn_dp_group_add_with_reference(lflow_ref_est, od)) {
            lflow_ref_est = ovn_lflow_add_at_with_hash(lflows, od,
                    S_ROUTER_IN_DNAT, prio, est_match, est_action,
                    NULL, NULL, &lb->nlb->header_,
                    OVS_SOURCE_LOCATOR, hash_est);
        }
    }
}

static void
build_lrouter_nat_flows_for_lb(struct ovn_lb_vip *lb_vip,
                               struct ovn_northd_lb *lb,
                               struct ovn_northd_lb_vip *vips_nb,
                               struct hmap *lflows,
                               struct ds *match, struct ds *action,
                               const struct shash *meter_groups,
                               bool ct_lb_mark)
{
    const char *ct_natted = ct_lb_mark ? "ct_mark.natted" : "ct_label.natted";
    char *skip_snat_new_action = NULL;
    char *skip_snat_est_action = NULL;
    char *new_match;
    char *est_match;

    ds_clear(match);
    ds_clear(action);

    bool reject = build_lb_vip_actions(lb_vip, vips_nb, action,
                                       lb->selection_fields, false,
                                       ct_lb_mark);

    /* Higher priority rules are added for load-balancing in DNAT
     * table.  For every match (on a VIP[:port]), we add two flows.
     * One flow is for specific matching on ct.new with an action
     * of "ct_lb_mark($targets);". The other flow is for ct.est with
     * an action of "next;".
     */
    if (lb_vip->address_family == AF_INET) {
        ds_put_format(match, "ip4 && "REG_NEXT_HOP_IPV4" == %s",
                      lb_vip->vip_str);
    } else {
        ds_put_format(match, "ip6 && "REG_NEXT_HOP_IPV6" == %s",
                      lb_vip->vip_str);
    }

    if (lb->skip_snat) {
        skip_snat_new_action = xasprintf("flags.skip_snat_for_lb = 1; %s",
                                         ds_cstr(action));
        skip_snat_est_action = xasprintf("flags.skip_snat_for_lb = 1; "
                                         "next;");
    }

    int prio = 110;
    if (lb_vip->port_str) {
        prio = 120;
        new_match = xasprintf("ct.new && !ct.rel && %s && %s && "
                              REG_ORIG_TP_DPORT_ROUTER" == %s",
                              ds_cstr(match), lb->proto, lb_vip->port_str);
        est_match = xasprintf("ct.est && !ct.rel && %s && %s && "
                              REG_ORIG_TP_DPORT_ROUTER" == %s && %s == 1",
                              ds_cstr(match), lb->proto, lb_vip->port_str,
                              ct_natted);
    } else {
        new_match = xasprintf("ct.new && !ct.rel && %s", ds_cstr(match));
        est_match = xasprintf("ct.est && !ct.rel && %s && %s == 1",
                          ds_cstr(match), ct_natted);
    }

    const char *ip_match = NULL;
    if (lb_vip->address_family == AF_INET) {
        ip_match = "ip4";
    } else {
        ip_match = "ip6";
    }

    /* Add logical flows to UNDNAT the load balanced reverse traffic in
     * the router egress pipleine stage - S_ROUTER_OUT_UNDNAT if the logical
     * router has a gateway router port associated.
     */
    struct ds undnat_match = DS_EMPTY_INITIALIZER;
    ds_put_format(&undnat_match, "%s && (", ip_match);

    for (size_t i = 0; i < lb_vip->n_backends; i++) {
        struct ovn_lb_backend *backend = &lb_vip->backends[i];
        ds_put_format(&undnat_match, "(%s.src == %s", ip_match,
                      backend->ip_str);

        if (backend->port_str) {
            ds_put_format(&undnat_match, " && %s.src == %s) || ",
                          lb->proto, backend->port_str);
        } else {
            ds_put_cstr(&undnat_match, ") || ");
        }
    }
    ds_chomp(&undnat_match, ' ');
    ds_chomp(&undnat_match, '|');
    ds_chomp(&undnat_match, '|');
    ds_chomp(&undnat_match, ' ');

    struct ds unsnat_match = DS_EMPTY_INITIALIZER;
    ds_put_format(&unsnat_match, "%s && %s.dst == %s && %s",
                  ip_match, ip_match, lb_vip->vip_str, lb->proto);
    if (lb_vip->port_str) {
        ds_put_format(&unsnat_match, " && %s.dst == %s", lb->proto,
                      lb_vip->port_str);
    }

    struct ovn_datapath **gw_router_skip_snat =
        xcalloc(lb->n_nb_lr, sizeof *gw_router_skip_snat);
    int n_gw_router_skip_snat = 0;

    struct ovn_datapath **gw_router_force_snat =
        xcalloc(lb->n_nb_lr, sizeof *gw_router_force_snat);
    int n_gw_router_force_snat = 0;

    struct ovn_datapath **gw_router =
        xcalloc(lb->n_nb_lr, sizeof *gw_router);
    int n_gw_router = 0;

    struct ovn_datapath **distributed_router =
        xcalloc(lb->n_nb_lr, sizeof *distributed_router);
    int n_distributed_router = 0;

    struct ovn_datapath **lb_aff_force_snat_router =
        xcalloc(lb->n_nb_lr, sizeof *lb_aff_force_snat_router);
    int n_lb_aff_force_snat_router = 0;

    struct ovn_datapath **lb_aff_router =
        xcalloc(lb->n_nb_lr, sizeof *lb_aff_router);
    int n_lb_aff_router = 0;

    /* Group gw router since we do not have datapath dependency in
     * lflow generation for them.
     */
    for (size_t i = 0; i < lb->n_nb_lr; i++) {
        struct ovn_datapath *od = lb->nb_lr[i];
        if (!od->n_l3dgw_ports) {
            if (lb->skip_snat) {
                gw_router_skip_snat[n_gw_router_skip_snat++] = od;
            } else if (!lport_addresses_is_empty(&od->lb_force_snat_addrs) ||
                       od->lb_force_snat_router_ip) {
                gw_router_force_snat[n_gw_router_force_snat++] = od;
            } else {
                gw_router[n_gw_router++] = od;
            }
        } else {
            distributed_router[n_distributed_router++] = od;
        }

        if (!lport_addresses_is_empty(&od->lb_force_snat_addrs) ||
            od->lb_force_snat_router_ip) {
            lb_aff_force_snat_router[n_lb_aff_force_snat_router++] = od;
        } else {
            lb_aff_router[n_lb_aff_router++] = od;
        }

        if (sset_contains(&od->external_ips, lb_vip->vip_str)) {
            /* The load balancer vip is also present in the NAT entries.
             * So add a high priority lflow to advance the the packet
             * destined to the vip (and the vip port if defined)
             * in the S_ROUTER_IN_UNSNAT stage.
             * There seems to be an issue with ovs-vswitchd. When the new
             * connection packet destined for the lb vip is received,
             * it is dnat'ed in the S_ROUTER_IN_DNAT stage in the dnat
             * conntrack zone. For the next packet, if it goes through
             * unsnat stage, the conntrack flags are not set properly, and
             * it doesn't hit the established state flows in
             * S_ROUTER_IN_DNAT stage. */
             ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_UNSNAT, 120,
                                     ds_cstr(&unsnat_match), "next;",
                                     &lb->nlb->header_);
        }
    }

    /* GW router logic */
    build_gw_lrouter_nat_flows_for_lb(lb, gw_router_skip_snat,
            n_gw_router_skip_snat, reject, new_match,
            skip_snat_new_action, est_match,
            skip_snat_est_action, lflows, prio, meter_groups);

    char *new_actions = xasprintf("flags.force_snat_for_lb = 1; %s",
                                  ds_cstr(action));
    build_gw_lrouter_nat_flows_for_lb(lb, gw_router_force_snat,
            n_gw_router_force_snat, reject, new_match,
            new_actions, est_match,
            "flags.force_snat_for_lb = 1; next;",
            lflows, prio, meter_groups);

    /* LB affinity flows for datapaths where CMS has specified
     * force_snat_for_lb floag option.
     */
    build_lb_affinity_lr_flows(lflows, lb, lb_vip, new_match,
                               "flags.force_snat_for_lb = 1; ",
                               lb_aff_force_snat_router,
                               n_lb_aff_force_snat_router);

    build_gw_lrouter_nat_flows_for_lb(lb, gw_router, n_gw_router,
            reject, new_match, ds_cstr(action), est_match,
            "next;", lflows, prio, meter_groups);

    /* LB affinity flows for datapaths where CMS has specified
     * skip_snat_for_lb floag option or regular datapaths.
     */
    char *lb_aff_action =
        lb->skip_snat ? "flags.skip_snat_for_lb = 1; " : NULL;
    build_lb_affinity_lr_flows(lflows, lb, lb_vip, new_match, lb_aff_action,
                               lb_aff_router, n_lb_aff_router);

    /* Distributed router logic */
    for (size_t i = 0; i < n_distributed_router; i++) {
        struct ovn_datapath *od = distributed_router[i];
        char *new_match_p = new_match;
        char *est_match_p = est_match;
        const char *meter = NULL;
        bool is_dp_lb_force_snat =
            !lport_addresses_is_empty(&od->lb_force_snat_addrs) ||
            od->lb_force_snat_router_ip;

        if (reject) {
            meter = copp_meter_get(COPP_REJECT, od->nbr->copp, meter_groups);
        }

        if (lb_vip->n_backends || !lb_vip->empty_backend_rej) {
            new_match_p = xasprintf("%s && is_chassis_resident(%s)",
                                    new_match,
                                    od->l3dgw_ports[0]->cr_port->json_key);
            est_match_p = xasprintf("%s && is_chassis_resident(%s)",
                                    est_match,
                                    od->l3dgw_ports[0]->cr_port->json_key);
        }

        if (lb->skip_snat) {
            ovn_lflow_add_with_hint__(lflows, od, S_ROUTER_IN_DNAT, prio,
                                      new_match_p, skip_snat_new_action,
                                      NULL, meter, &lb->nlb->header_);
            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DNAT, prio,
                                    est_match_p, skip_snat_est_action,
                                    &lb->nlb->header_);
        } else if (is_dp_lb_force_snat) {
            ovn_lflow_add_with_hint__(lflows, od, S_ROUTER_IN_DNAT, prio,
                                      new_match_p, new_actions, NULL,
                                      meter, &lb->nlb->header_);
            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DNAT, prio,
                                    est_match_p,
                                    "flags.force_snat_for_lb = 1; next;",
                                    &lb->nlb->header_);
        } else {
            ovn_lflow_add_with_hint__(lflows, od, S_ROUTER_IN_DNAT, prio,
                                      new_match_p, ds_cstr(action), NULL,
                                      meter, &lb->nlb->header_);
            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DNAT, prio,
                                    est_match_p, "next;",
                                    &lb->nlb->header_);
        }

        if (new_match_p != new_match) {
            free(new_match_p);
        }
        if (est_match_p != est_match) {
            free(est_match_p);
        }

        if (!lb_vip->n_backends) {
            continue;
        }

        char *undnat_match_p = xasprintf(
            "%s) && outport == %s && is_chassis_resident(%s)",
            ds_cstr(&undnat_match),
            od->l3dgw_ports[0]->json_key,
            od->l3dgw_ports[0]->cr_port->json_key);
        if (lb->skip_snat) {
            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_UNDNAT, 120,
                                    undnat_match_p, skip_snat_est_action,
                                    &lb->nlb->header_);
        } else if (is_dp_lb_force_snat) {
            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_UNDNAT, 120,
                                    undnat_match_p,
                                    "flags.force_snat_for_lb = 1; next;",
                                    &lb->nlb->header_);
        } else {
            ovn_lflow_add_with_hint(
                lflows, od, S_ROUTER_OUT_UNDNAT, 120, undnat_match_p,
                od->is_gw_router ? "ct_dnat;" : "ct_dnat_in_czone;",
                &lb->nlb->header_);
        }
        free(undnat_match_p);
    }

    ds_destroy(&unsnat_match);
    ds_destroy(&undnat_match);

    free(skip_snat_new_action);
    free(skip_snat_est_action);
    free(est_match);
    free(new_match);
    free(new_actions);

    free(gw_router_force_snat);
    free(gw_router_skip_snat);
    free(distributed_router);
    free(lb_aff_force_snat_router);
    free(lb_aff_router);
    free(gw_router);
}

static void
build_lswitch_flows_for_lb(struct ovn_northd_lb *lb, struct hmap *lflows,
                           const struct shash *meter_groups,
                           const struct chassis_features *features,
                           struct ds *match, struct ds *action)
{
    if (!lb->n_nb_ls) {
        return;
    }

    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_lb_vip *lb_vip = &lb->vips[i];

        /* pre-stateful lb */
        if (!build_empty_lb_event_flow(lb_vip, lb, match, action)) {
            continue;
        }
        for (size_t j = 0; j < lb->n_nb_ls; j++) {
            struct ovn_datapath *od = lb->nb_ls[j];
            ovn_lflow_add_with_hint__(lflows, od,
                                      S_SWITCH_IN_PRE_LB, 130, ds_cstr(match),
                                      ds_cstr(action),
                                      NULL,
                                      copp_meter_get(COPP_EVENT_ELB,
                                                     od->nbs->copp,
                                                     meter_groups),
                                      &lb->nlb->header_);
        }
        /* Ignore L4 port information in the key because fragmented packets
         * may not have L4 information.  The pre-stateful table will send
         * the packet through ct() action to de-fragment. In stateful
         * table, we will eventually look at L4 information. */
    }

    /* stateful lb
     * Load balancing rules for new connections get committed to conntrack
     * table.  So even if REGBIT_CONNTRACK_COMMIT is set in a previous table
     * a higher priority rule for load balancing below also commits the
     * connection, so it is okay if we do not hit the above match on
     * REGBIT_CONNTRACK_COMMIT. */
    build_lb_rules_pre_stateful(lflows, lb, features->ct_no_masked_label,
                                match, action);
    build_lb_rules(lflows, lb, features->ct_no_masked_label,
                   match, action, meter_groups);
}

/* If there are any load balancing rules, we should send the packet to
 * conntrack for defragmentation and tracking.  This helps with two things.
 *
 * 1. With tracking, we can send only new connections to pick a DNAT ip address
 *    from a group.
 * 2. If there are L4 ports in load balancing rules, we need the
 *    defragmentation to match on L4 ports.
 */
static void
build_lrouter_defrag_flows_for_lb(struct ovn_northd_lb *lb,
                                  struct hmap *lflows,
                                  struct ds *match)
{
    if (!lb->n_nb_lr) {
        return;
    }

    struct ds defrag_actions = DS_EMPTY_INITIALIZER;
    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_lb_vip *lb_vip = &lb->vips[i];
        int prio = 100;

        ds_clear(&defrag_actions);
        ds_clear(match);

        if (lb_vip->address_family == AF_INET) {
            ds_put_format(match, "ip && ip4.dst == %s", lb_vip->vip_str);
            ds_put_format(&defrag_actions, REG_NEXT_HOP_IPV4" = %s; ",
                          lb_vip->vip_str);
        } else {
            ds_put_format(match, "ip && ip6.dst == %s", lb_vip->vip_str);
            ds_put_format(&defrag_actions, REG_NEXT_HOP_IPV6" = %s; ",
                          lb_vip->vip_str);
        }

        if (lb_vip->port_str) {
            ds_put_format(match, " && %s", lb->proto);
            prio = 110;

            ds_put_format(&defrag_actions, REG_ORIG_TP_DPORT_ROUTER
                          " = %s.dst; ", lb->proto);
        }

        ds_put_format(&defrag_actions, "ct_dnat;");

        struct ovn_lflow *lflow_ref = NULL;
        uint32_t hash = ovn_logical_flow_hash(
                ovn_stage_get_table(S_ROUTER_IN_DEFRAG),
                ovn_stage_get_pipeline(S_ROUTER_IN_DEFRAG), prio,
                ds_cstr(match), ds_cstr(&defrag_actions));
        for (size_t j = 0; j < lb->n_nb_lr; j++) {
            struct ovn_datapath *od = lb->nb_lr[j];
            if (ovn_dp_group_add_with_reference(lflow_ref, od)) {
                continue;
            }
            lflow_ref = ovn_lflow_add_at_with_hash(lflows, od,
                                    S_ROUTER_IN_DEFRAG, prio,
                                    ds_cstr(match), ds_cstr(&defrag_actions),
                                    NULL, NULL, &lb->nlb->header_,
                                    OVS_SOURCE_LOCATOR, hash);
        }
    }
    ds_destroy(&defrag_actions);
}

static void
build_lrouter_flows_for_lb(struct ovn_northd_lb *lb, struct hmap *lflows,
                           const struct shash *meter_groups,
                           const struct chassis_features *features,
                           struct ds *match, struct ds *action)
{
    if (!lb->n_nb_lr) {
        return;
    }

    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_lb_vip *lb_vip = &lb->vips[i];

        build_lrouter_nat_flows_for_lb(lb_vip, lb, &lb->vips_nb[i],
                                       lflows, match, action, meter_groups,
                                       features->ct_no_masked_label);

        if (!build_empty_lb_event_flow(lb_vip, lb, match, action)) {
            continue;
        }
        for (size_t j = 0; j < lb->n_nb_lr; j++) {
            struct ovn_datapath *od = lb->nb_lr[j];
            ovn_lflow_add_with_hint__(lflows, od, S_ROUTER_IN_DNAT,
                                      130, ds_cstr(match), ds_cstr(action),
                                      NULL,
                                      copp_meter_get(COPP_EVENT_ELB,
                                                     od->nbr->copp,
                                                     meter_groups),
                                      &lb->nlb->header_);
        }
    }

    if (lb->skip_snat) {
        for (size_t i = 0; i < lb->n_nb_lr; i++) {
            ovn_lflow_add(lflows, lb->nb_lr[i], S_ROUTER_OUT_SNAT, 120,
                          "flags.skip_snat_for_lb == 1 && ip", "next;");
        }
    }
}

#define ND_RA_MAX_INTERVAL_MAX 1800
#define ND_RA_MAX_INTERVAL_MIN 4

#define ND_RA_MIN_INTERVAL_MAX(max) ((max) * 3 / 4)
#define ND_RA_MIN_INTERVAL_MIN 3

static void
copy_ra_to_sb(struct ovn_port *op, const char *address_mode)
{
    struct smap options;
    smap_clone(&options, &op->sb->options);

    smap_add(&options, "ipv6_ra_send_periodic", "true");
    smap_add(&options, "ipv6_ra_address_mode", address_mode);

    int max_interval = smap_get_int(&op->nbrp->ipv6_ra_configs,
            "max_interval", ND_RA_MAX_INTERVAL_DEFAULT);
    if (max_interval > ND_RA_MAX_INTERVAL_MAX) {
        max_interval = ND_RA_MAX_INTERVAL_MAX;
    }
    if (max_interval < ND_RA_MAX_INTERVAL_MIN) {
        max_interval = ND_RA_MAX_INTERVAL_MIN;
    }
    smap_add_format(&options, "ipv6_ra_max_interval", "%d", max_interval);

    int min_interval = smap_get_int(&op->nbrp->ipv6_ra_configs,
            "min_interval", nd_ra_min_interval_default(max_interval));
    if (min_interval > ND_RA_MIN_INTERVAL_MAX(max_interval)) {
        min_interval = ND_RA_MIN_INTERVAL_MAX(max_interval);
    }
    if (min_interval < ND_RA_MIN_INTERVAL_MIN) {
        min_interval = ND_RA_MIN_INTERVAL_MIN;
    }
    smap_add_format(&options, "ipv6_ra_min_interval", "%d", min_interval);

    int mtu = smap_get_int(&op->nbrp->ipv6_ra_configs, "mtu", ND_MTU_DEFAULT);
    /* RFC 2460 requires the MTU for IPv6 to be at least 1280 */
    if (mtu && mtu >= 1280) {
        smap_add_format(&options, "ipv6_ra_mtu", "%d", mtu);
    }

    struct ds s = DS_EMPTY_INITIALIZER;
    for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; ++i) {
        struct ipv6_netaddr *addrs = &op->lrp_networks.ipv6_addrs[i];
        if (in6_is_lla(&addrs->network)) {
            smap_add(&options, "ipv6_ra_src_addr", addrs->addr_s);
            continue;
        }
        ds_put_format(&s, "%s/%u ", addrs->network_s, addrs->plen);
    }

    const char *ra_pd_list = smap_get(&op->sb->options, "ipv6_ra_pd_list");
    if (ra_pd_list) {
        ds_put_cstr(&s, ra_pd_list);
    }
    /* Remove trailing space */
    ds_chomp(&s, ' ');
    smap_add(&options, "ipv6_ra_prefixes", ds_cstr(&s));
    ds_destroy(&s);

    const char *rdnss = smap_get(&op->nbrp->ipv6_ra_configs, "rdnss");
    if (rdnss) {
        smap_add(&options, "ipv6_ra_rdnss", rdnss);
    }
    const char *dnssl = smap_get(&op->nbrp->ipv6_ra_configs, "dnssl");
    if (dnssl) {
        smap_add(&options, "ipv6_ra_dnssl", dnssl);
    }

    smap_add(&options, "ipv6_ra_src_eth", op->lrp_networks.ea_s);

    const char *prf = smap_get(&op->nbrp->ipv6_ra_configs,
                               "router_preference");
    if (!prf || (strcmp(prf, "HIGH") && strcmp(prf, "LOW"))) {
        smap_add(&options, "ipv6_ra_prf", "MEDIUM");
    } else {
        smap_add(&options, "ipv6_ra_prf", prf);
    }

    const char *route_info = smap_get(&op->nbrp->ipv6_ra_configs,
                                      "route_info");
    if (route_info) {
        smap_add(&options, "ipv6_ra_route_info", route_info);
    }

    sbrec_port_binding_set_options(op->sb, &options);
    smap_destroy(&options);
}

static inline bool
lrouter_nat_is_stateless(const struct nbrec_nat *nat)
{
    const char *stateless = smap_get(&nat->options, "stateless");

    if (stateless && !strcmp(stateless, "true")) {
        return true;
    }

    return false;
}

/* Handles the match criteria and actions in logical flow
 * based on external ip based NAT rule filter.
 *
 * For ALLOWED_EXT_IPs, we will add an additional match criteria
 * of comparing ip*.src/dst with the allowed external ip address set.
 *
 * For EXEMPTED_EXT_IPs, we will have an additional logical flow
 * where we compare ip*.src/dst with the exempted external ip address set
 * and action says "next" instead of ct*.
 */
static inline void
lrouter_nat_add_ext_ip_match(struct ovn_datapath *od,
                             struct hmap *lflows, struct ds *match,
                             const struct nbrec_nat *nat,
                             bool is_v6, bool is_src, int cidr_bits)
{
    struct nbrec_address_set *allowed_ext_ips = nat->allowed_ext_ips;
    struct nbrec_address_set *exempted_ext_ips = nat->exempted_ext_ips;

    ovs_assert(allowed_ext_ips || exempted_ext_ips);

    if (allowed_ext_ips) {
        ds_put_format(match, " && ip%s.%s == $%s",
                      is_v6 ? "6" : "4",
                      is_src ? "src" : "dst",
                      allowed_ext_ips->name);
    } else if (exempted_ext_ips) {
        struct ds match_exempt = DS_EMPTY_INITIALIZER;
        enum ovn_stage stage = is_src ? S_ROUTER_IN_DNAT : S_ROUTER_OUT_SNAT;
        uint16_t priority;

        /* Priority of logical flows corresponding to exempted_ext_ips is
         * +2 of the corresponding regular NAT rule.
         * For example, if we have following NAT rule and we associate
         * exempted external ips to it:
         * "ovn-nbctl lr-nat-add router dnat_and_snat 10.15.24.139 50.0.0.11"
         *
         * And now we associate exempted external ip address set to it.
         * Now corresponding to above rule we will have following logical
         * flows:
         * lr_out_snat...priority=163, match=(..ip4.dst == $exempt_range),
         *                             action=(next;)
         * lr_out_snat...priority=161, match=(..), action=(ct_snat(....);)
         *
         */
        if (is_src) {
            /* S_ROUTER_IN_DNAT uses priority 100 */
            priority = 100 + 2;
        } else {
            /* S_ROUTER_OUT_SNAT uses priority (mask + 1 + 128 + 1) */
            priority = cidr_bits + 3;

            if (!od->is_gw_router) {
                priority += 128;
           }
        }

        ds_clone(&match_exempt, match);
        ds_put_format(&match_exempt, " && ip%s.%s == $%s",
                      is_v6 ? "6" : "4",
                      is_src ? "src" : "dst",
                      exempted_ext_ips->name);

        ovn_lflow_add_with_hint(lflows, od, stage, priority,
                                ds_cstr(&match_exempt), "next;",
                                &nat->header_);
        ds_destroy(&match_exempt);
    }
}

/* Builds the logical flow that replies to ARP requests for an 'ip_address'
 * owned by the router. The flow is inserted in table S_ROUTER_IN_IP_INPUT
 * with the given priority.
 */
static void
build_lrouter_arp_flow(struct ovn_datapath *od, struct ovn_port *op,
                       const char *ip_address, const char *eth_addr,
                       struct ds *extra_match, bool drop, uint16_t priority,
                       const struct ovsdb_idl_row *hint,
                       struct hmap *lflows)
{
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    if (op) {
        ds_put_format(&match, "inport == %s && ", op->json_key);
    }

    ds_put_format(&match, "arp.op == 1 && arp.tpa == %s", ip_address);

    if (extra_match && ds_last(extra_match) != EOF) {
        ds_put_format(&match, " && %s", ds_cstr(extra_match));
    }
    if (drop) {
        ds_put_cstr(&actions, debug_drop_action());
    } else {
        ds_put_format(&actions,
                      "eth.dst = eth.src; "
                      "eth.src = %s; "
                      "arp.op = 2; /* ARP reply */ "
                      "arp.tha = arp.sha; "
                      "arp.sha = %s; "
                      "arp.tpa <-> arp.spa; "
                      "outport = inport; "
                      "flags.loopback = 1; "
                      "output;",
                      eth_addr,
                      eth_addr);
    }

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_IP_INPUT, priority,
                            ds_cstr(&match), ds_cstr(&actions), hint);

    ds_destroy(&match);
    ds_destroy(&actions);
}

/* Builds the logical flow that replies to NS requests for an 'ip_address'
 * owned by the router. The flow is inserted in table S_ROUTER_IN_IP_INPUT
 * with the given priority. If 'sn_ip_address' is non-NULL, requests are
 * restricted only to packets with IP destination 'ip_address' or
 * 'sn_ip_address'.
 */
static void
build_lrouter_nd_flow(struct ovn_datapath *od, struct ovn_port *op,
                      const char *action, const char *ip_address,
                      const char *sn_ip_address, const char *eth_addr,
                      struct ds *extra_match, bool drop, uint16_t priority,
                      const struct ovsdb_idl_row *hint,
                      struct hmap *lflows, const struct shash *meter_groups)
{
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    if (op) {
        ds_put_format(&match, "inport == %s && ", op->json_key);
    }

    if (sn_ip_address) {
        ds_put_format(&match, "ip6.dst == {%s, %s} && ",
                      ip_address, sn_ip_address);
    }

    ds_put_format(&match, "nd_ns && nd.target == %s", ip_address);

    if (extra_match && ds_last(extra_match) != EOF) {
        ds_put_format(&match, " && %s", ds_cstr(extra_match));
    }

    if (drop) {
        ds_put_cstr(&actions, debug_drop_action());
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_IP_INPUT, priority,
                                ds_cstr(&match), ds_cstr(&actions), hint);
    } else {
        ds_put_format(&actions,
                      "%s { "
                        "eth.src = %s; "
                        "ip6.src = nd.target; "
                        "nd.tll = %s; "
                        "outport = inport; "
                        "flags.loopback = 1; "
                        "output; "
                      "};",
                      action,
                      eth_addr,
                      eth_addr);
        ovn_lflow_add_with_hint__(lflows, od, S_ROUTER_IN_IP_INPUT, priority,
                                  ds_cstr(&match), ds_cstr(&actions), NULL,
                                  copp_meter_get(COPP_ND_NA, od->nbr->copp,
                                                 meter_groups),
                                  hint);
    }

    ds_destroy(&match);
    ds_destroy(&actions);
}

static void
build_lrouter_nat_arp_nd_flow(struct ovn_datapath *od,
                              struct ovn_nat *nat_entry,
                              struct hmap *lflows,
                              const struct shash *meter_groups)
{
    struct lport_addresses *ext_addrs = &nat_entry->ext_addrs;
    const struct nbrec_nat *nat = nat_entry->nb;

    if (nat_entry_is_v6(nat_entry)) {
        build_lrouter_nd_flow(od, NULL, "nd_na",
                              ext_addrs->ipv6_addrs[0].addr_s,
                              ext_addrs->ipv6_addrs[0].sn_addr_s,
                              REG_INPORT_ETH_ADDR, NULL, false, 90,
                              &nat->header_, lflows, meter_groups);
    } else {
        build_lrouter_arp_flow(od, NULL,
                               ext_addrs->ipv4_addrs[0].addr_s,
                               REG_INPORT_ETH_ADDR, NULL, false, 90,
                               &nat->header_, lflows);
    }
}

static void
build_lrouter_port_nat_arp_nd_flow(struct ovn_port *op,
                                   struct ovn_nat *nat_entry,
                                   struct hmap *lflows,
                                   const struct shash *meter_groups)
{
    struct lport_addresses *ext_addrs = &nat_entry->ext_addrs;
    const struct nbrec_nat *nat = nat_entry->nb;
    struct ds match = DS_EMPTY_INITIALIZER;

    /* ARP/ND should be sent from distributed gateway port where the NAT rule
     * will be applied. */
    if (!is_nat_gateway_port(nat, op)) {
        return;
    }

    /* Mac address to use when replying to ARP/NS. */
    const char *mac_s = REG_INPORT_ETH_ADDR;
    struct eth_addr mac;

    if (nat->external_mac &&
        eth_addr_from_string(nat->external_mac, &mac)
        && nat->logical_port) {
        /* distributed NAT case, use nat->external_mac */
        mac_s = nat->external_mac;
        /* Traffic with eth.src = nat->external_mac should only be
         * sent from the chassis where nat->logical_port is
         * resident, so that upstream MAC learning points to the
         * correct chassis.  Also need to avoid generation of
         * multiple ARP responses from different chassis. */
        ds_put_format(&match, "is_chassis_resident(\"%s\")",
                      nat->logical_port);
    } else {
        mac_s = REG_INPORT_ETH_ADDR;
        /* Traffic with eth.src = l3dgw_port->lrp_networks.ea_s
         * should only be sent from the gateway chassis, so that
         * upstream MAC learning points to the gateway chassis.
         * Also need to avoid generation of multiple ARP responses
         * from different chassis. */
        ovs_assert(is_l3dgw_port(op));
        ds_put_format(&match, "is_chassis_resident(%s)",
                      op->cr_port->json_key);
    }

    /* Respond to ARP/NS requests on the chassis that binds the gw
     * port. Drop the ARP/NS requests on other chassis.
     */
    if (nat_entry_is_v6(nat_entry)) {
        build_lrouter_nd_flow(op->od, op, "nd_na",
                              ext_addrs->ipv6_addrs[0].addr_s,
                              ext_addrs->ipv6_addrs[0].sn_addr_s,
                              mac_s, &match, false, 92,
                              &nat->header_, lflows, meter_groups);
        build_lrouter_nd_flow(op->od, op, "nd_na",
                              ext_addrs->ipv6_addrs[0].addr_s,
                              ext_addrs->ipv6_addrs[0].sn_addr_s,
                              mac_s, NULL, true, 91,
                              &nat->header_, lflows, meter_groups);
    } else {
        build_lrouter_arp_flow(op->od, op,
                               ext_addrs->ipv4_addrs[0].addr_s,
                               mac_s, &match, false, 92,
                               &nat->header_, lflows);
        build_lrouter_arp_flow(op->od, op,
                               ext_addrs->ipv4_addrs[0].addr_s,
                               mac_s, NULL, true, 91,
                               &nat->header_, lflows);
    }

    ds_destroy(&match);
}

static void
build_lrouter_drop_own_dest(struct ovn_port *op, enum ovn_stage stage,
                            uint16_t priority, bool drop_snat_ip,
                            struct hmap *lflows)
{
    struct ds match_ips = DS_EMPTY_INITIALIZER;

    if (op->lrp_networks.n_ipv4_addrs) {
        for (size_t i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            const char *ip = op->lrp_networks.ipv4_addrs[i].addr_s;

            bool router_ip_in_snat_ips = !!shash_find(&op->od->snat_ips, ip);
            bool router_ip_in_lb_ips =
                    !!sset_find(&op->od->lb_ips->ips_v4, ip);
            bool drop_router_ip = (drop_snat_ip == (router_ip_in_snat_ips ||
                                                    router_ip_in_lb_ips));

            if (drop_router_ip) {
                ds_put_format(&match_ips, "%s, ", ip);
            }
        }

        if (ds_last(&match_ips) != EOF) {
            ds_chomp(&match_ips, ' ');
            ds_chomp(&match_ips, ',');

            char *match = xasprintf("ip4.dst == {%s}", ds_cstr(&match_ips));
            ovn_lflow_add_with_hint(lflows, op->od, stage, priority,
                                    match, debug_drop_action(),
                                    &op->nbrp->header_);
            free(match);
        }
    }

    if (op->lrp_networks.n_ipv6_addrs) {
        ds_clear(&match_ips);

        for (size_t i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
            const char *ip = op->lrp_networks.ipv6_addrs[i].addr_s;

            bool router_ip_in_snat_ips = !!shash_find(&op->od->snat_ips, ip);
            bool router_ip_in_lb_ips =
                    !!sset_find(&op->od->lb_ips->ips_v6, ip);
            bool drop_router_ip = (drop_snat_ip == (router_ip_in_snat_ips ||
                                                    router_ip_in_lb_ips));

            if (drop_router_ip) {
                ds_put_format(&match_ips, "%s, ", ip);
            }
        }

        if (ds_last(&match_ips) != EOF) {
            ds_chomp(&match_ips, ' ');
            ds_chomp(&match_ips, ',');

            char *match = xasprintf("ip6.dst == {%s}", ds_cstr(&match_ips));
            ovn_lflow_add_with_hint(lflows, op->od, stage, priority,
                                    match, debug_drop_action(),
                                    &op->nbrp->header_);
            free(match);
        }
    }
    ds_destroy(&match_ips);
}

static void
build_lrouter_force_snat_flows(struct hmap *lflows, struct ovn_datapath *od,
                               const char *ip_version, const char *ip_addr,
                               const char *context)
{
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;
    ds_put_format(&match, "ip%s && ip%s.dst == %s",
                  ip_version, ip_version, ip_addr);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_UNSNAT, 110,
                  ds_cstr(&match), "ct_snat;");

    /* Higher priority rules to force SNAT with the IP addresses
     * configured in the Gateway router.  This only takes effect
     * when the packet has already been DNATed or load balanced once. */
    ds_clear(&match);
    ds_put_format(&match, "flags.force_snat_for_%s == 1 && ip%s",
                  context, ip_version);
    ds_put_format(&actions, "ct_snat(%s);", ip_addr);
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_SNAT, 100,
                  ds_cstr(&match), ds_cstr(&actions));

    ds_destroy(&match);
    ds_destroy(&actions);
}

static void
build_lrouter_force_snat_flows_op(struct ovn_port *op,
                                  struct hmap *lflows,
                                  struct ds *match, struct ds *actions)
{
    if (!op->nbrp || !op->peer || !op->od->lb_force_snat_router_ip) {
        return;
    }

    if (op->lrp_networks.n_ipv4_addrs) {
        ds_clear(match);
        ds_clear(actions);

        ds_put_format(match, "inport == %s && ip4.dst == %s",
                      op->json_key, op->lrp_networks.ipv4_addrs[0].addr_s);
        ovn_lflow_add(lflows, op->od, S_ROUTER_IN_UNSNAT, 110,
                      ds_cstr(match), "ct_snat;");

        ds_clear(match);

        /* Higher priority rules to force SNAT with the router port ip.
         * This only takes effect when the packet has already been
         * load balanced once. */
        ds_put_format(match, "flags.force_snat_for_lb == 1 && ip4 && "
                      "outport == %s", op->json_key);
        ds_put_format(actions, "ct_snat(%s);",
                      op->lrp_networks.ipv4_addrs[0].addr_s);
        ovn_lflow_add(lflows, op->od, S_ROUTER_OUT_SNAT, 110,
                      ds_cstr(match), ds_cstr(actions));
        if (op->lrp_networks.n_ipv4_addrs > 1) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "Logical router port %s is configured with "
                              "multiple IPv4 addresses.  Only the first "
                              "IP [%s] is considered as SNAT for load "
                              "balancer", op->json_key,
                              op->lrp_networks.ipv4_addrs[0].addr_s);
        }
    }

    /* op->lrp_networks.ipv6_addrs will always have LLA and that will be
     * last in the list. So add the flows only if n_ipv6_addrs > 1. */
    if (op->lrp_networks.n_ipv6_addrs > 1) {
        ds_clear(match);
        ds_clear(actions);

        ds_put_format(match, "inport == %s && ip6.dst == %s",
                      op->json_key, op->lrp_networks.ipv6_addrs[0].addr_s);
        ovn_lflow_add(lflows, op->od, S_ROUTER_IN_UNSNAT, 110,
                      ds_cstr(match), "ct_snat;");

        ds_clear(match);

        /* Higher priority rules to force SNAT with the router port ip.
         * This only takes effect when the packet has already been
         * load balanced once. */
        ds_put_format(match, "flags.force_snat_for_lb == 1 && ip6 && "
                      "outport == %s", op->json_key);
        ds_put_format(actions, "ct_snat(%s);",
                      op->lrp_networks.ipv6_addrs[0].addr_s);
        ovn_lflow_add(lflows, op->od, S_ROUTER_OUT_SNAT, 110,
                      ds_cstr(match), ds_cstr(actions));
        if (op->lrp_networks.n_ipv6_addrs > 2) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "Logical router port %s is configured with "
                              "multiple IPv6 addresses.  Only the first "
                              "IP [%s] is considered as SNAT for load "
                              "balancer", op->json_key,
                              op->lrp_networks.ipv6_addrs[0].addr_s);
        }
    }
}

static void
build_lrouter_bfd_flows(struct hmap *lflows, struct ovn_port *op,
                        const struct shash *meter_groups)
{
    if (!op->has_bfd) {
        return;
    }

    struct ds ip_list = DS_EMPTY_INITIALIZER;
    struct ds match = DS_EMPTY_INITIALIZER;

    if (op->lrp_networks.n_ipv4_addrs) {
        op_put_v4_networks(&ip_list, op, false);
        ds_put_format(&match, "ip4.src == %s && udp.dst == 3784",
                      ds_cstr(&ip_list));
        ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT, 110,
                                ds_cstr(&match), "next; ",
                                &op->nbrp->header_);
        ds_clear(&match);
        ds_put_format(&match, "ip4.dst == %s && udp.dst == 3784",
                      ds_cstr(&ip_list));
        ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT, 110,
                                  ds_cstr(&match), "handle_bfd_msg(); ", NULL,
                                  copp_meter_get(COPP_BFD, op->od->nbr->copp,
                                                 meter_groups),
                                  &op->nbrp->header_);
    }
    if (op->lrp_networks.n_ipv6_addrs) {
        ds_clear(&ip_list);
        ds_clear(&match);

        op_put_v6_networks(&ip_list, op);
        ds_put_format(&match, "ip6.src == %s && udp.dst == 3784",
                      ds_cstr(&ip_list));
        ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT, 110,
                                ds_cstr(&match), "next; ",
                                &op->nbrp->header_);
        ds_clear(&match);
        ds_put_format(&match, "ip6.dst == %s && udp.dst == 3784",
                      ds_cstr(&ip_list));
        ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT, 110,
                                  ds_cstr(&match), "handle_bfd_msg(); ", NULL,
                                  copp_meter_get(COPP_BFD, op->od->nbr->copp,
                                                 meter_groups),
                                  &op->nbrp->header_);
    }

    ds_destroy(&ip_list);
    ds_destroy(&match);
}

/* Logical router ingress Table 0: L2 Admission Control
 * Generic admission control flows (without inport check).
 */
static void
build_adm_ctrl_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows)
{
    if (od->nbr) {
        /* Logical VLANs not supported.
         * Broadcast/multicast source address is invalid. */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_ADMISSION, 100,
                      "vlan.present || eth.src[40]", debug_drop_action());

        /* Default action for L2 security is to drop. */
        ovn_lflow_add_default_drop(lflows, od, S_ROUTER_IN_ADMISSION);
    }
}

static int
build_gateway_get_l2_hdr_size(struct ovn_port *op)
{
    struct ovn_port *peer = op->peer;

    if (peer && peer->od && peer->od->nbs) {
        /* Check if vlans are enabled on a localnet port running the logical
         * switch connected to this logical router.
         */
        for (size_t i = 0; i < peer->od->n_localnet_ports; i++) {
            struct ovn_port *localnet_port = peer->od->localnet_ports[i];
            const struct nbrec_logical_switch_port *nbsp = localnet_port->nbsp;

            if (nbsp && nbsp->n_tag_request > 0) {
                return VLAN_ETH_HEADER_LEN;
            }
        }
    }

    return ETH_HEADER_LEN;
}

/* All 'gateway_mtu' and 'gateway_mtu_bypass' flows should be built with this
 * function.
 */
static void OVS_PRINTF_FORMAT(9, 10)
build_gateway_mtu_flow(struct hmap *lflows, struct ovn_port *op,
                       enum ovn_stage stage, uint16_t prio_low,
                       uint16_t prio_high, struct ds *match,
                       struct ds *actions, const struct ovsdb_idl_row *hint,
                       const char *extra_actions_fmt, ...)
{
    int gw_mtu = smap_get_int(&op->nbrp->options, "gateway_mtu", 0);

    va_list extra_actions_args;
    va_start(extra_actions_args, extra_actions_fmt);

    ds_clear(actions);
    if (gw_mtu > 0) {
        int l2_hdr_size = build_gateway_get_l2_hdr_size(op);
        ds_put_format(actions, REGBIT_PKT_LARGER" = check_pkt_larger(%d); ",
                      gw_mtu + l2_hdr_size);
    }

    ds_put_format_valist(actions, extra_actions_fmt, extra_actions_args);
    ovn_lflow_add_with_hint(lflows, op->od, stage, prio_low,
                            ds_cstr(match), ds_cstr(actions),
                            hint);

    if (gw_mtu > 0) {
        const char *gw_mtu_bypass = smap_get(&op->nbrp->options,
                                             "gateway_mtu_bypass");
        if (gw_mtu_bypass) {
            ds_clear(actions);
            ds_put_format_valist(actions, extra_actions_fmt,
                                 extra_actions_args);
            ds_put_format(match, " && (%s)", gw_mtu_bypass);
            ovn_lflow_add_with_hint(lflows, op->od, stage, prio_high,
                                    ds_cstr(match), ds_cstr(actions),
                                    hint);
        }
    }
    va_end(extra_actions_args);
}

static bool
consider_l3dwg_port_is_centralized(struct ovn_port *op)
{
    if (op->peer && op->peer->od->has_vtep_lports) {
        return false;
    }

    if (is_l3dgw_port(op)) {
        /* Traffic with eth.dst = l3dgw_port->lrp_networks.ea_s
         * should only be received on the gateway chassis. */
        return true;
    }

    return false;
}

/* Logical router ingress Table 0: L2 Admission Control
 * This table drops packets that the router shouldn’t see at all based
 * on their Ethernet headers.
 */
static void
build_adm_ctrl_flows_for_lrouter_port(
        struct ovn_port *op, struct hmap *lflows,
        struct ds *match, struct ds *actions)
{
    if (op->nbrp) {
        if (!lrport_is_enabled(op->nbrp)) {
            /* Drop packets from disabled logical ports (since logical flow
             * tables are default-drop). */
            return;
        }

        if (is_cr_port(op)) {
            /* No ingress packets should be received on a chassisredirect
             * port. */
            return;
        }

        /* Store the ethernet address of the port receiving the packet.
         * This will save us from having to match on inport further down in
         * the pipeline.
         */
        ds_clear(match);
        ds_put_format(match, "eth.mcast && inport == %s", op->json_key);
        build_gateway_mtu_flow(lflows, op, S_ROUTER_IN_ADMISSION, 50, 55,
                               match, actions, &op->nbrp->header_,
                               REG_INPORT_ETH_ADDR " = %s; next;",
                               op->lrp_networks.ea_s);

        ds_clear(match);
        ds_put_format(match, "eth.dst == %s && inport == %s",
                      op->lrp_networks.ea_s, op->json_key);
        if (consider_l3dwg_port_is_centralized(op)) {
            ds_put_format(match, " && is_chassis_resident(%s)",
                          op->cr_port->json_key);
        }
        build_gateway_mtu_flow(lflows, op, S_ROUTER_IN_ADMISSION, 50, 55,
                               match, actions, &op->nbrp->header_,
                               REG_INPORT_ETH_ADDR " = %s; next;",
                               op->lrp_networks.ea_s);
    }
}


/* Logical router ingress Table 1 and 2: Neighbor lookup and learning
 * lflows for logical routers. */
static void
build_neigh_learning_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows,
        struct ds *match, struct ds *actions,
        const struct shash *meter_groups)
{
    if (od->nbr) {

        /* Learn MAC bindings from ARP/IPv6 ND.
         *
         * For ARP packets, table LOOKUP_NEIGHBOR does a lookup for the
         * (arp.spa, arp.sha) in the mac binding table using the 'lookup_arp'
         * action and stores the result in REGBIT_LOOKUP_NEIGHBOR_RESULT bit.
         * If "always_learn_from_arp_request" is set to false, it will also
         * lookup for the (arp.spa) in the mac binding table using the
         * "lookup_arp_ip" action for ARP request packets, and stores the
         * result in REGBIT_LOOKUP_NEIGHBOR_IP_RESULT bit; or set that bit
         * to "1" directly for ARP response packets.
         *
         * For IPv6 ND NA packets, table LOOKUP_NEIGHBOR does a lookup
         * for the (nd.target, nd.tll) in the mac binding table using the
         * 'lookup_nd' action and stores the result in
         * REGBIT_LOOKUP_NEIGHBOR_RESULT bit. If
         * "always_learn_from_arp_request" is set to false,
         * REGBIT_LOOKUP_NEIGHBOR_IP_RESULT bit is set.
         *
         * For IPv6 ND NS packets, table LOOKUP_NEIGHBOR does a lookup
         * for the (ip6.src, nd.sll) in the mac binding table using the
         * 'lookup_nd' action and stores the result in
         * REGBIT_LOOKUP_NEIGHBOR_RESULT bit. If
         * "always_learn_from_arp_request" is set to false, it will also lookup
         * for the (ip6.src) in the mac binding table using the "lookup_nd_ip"
         * action and stores the result in REGBIT_LOOKUP_NEIGHBOR_IP_RESULT
         * bit.
         *
         * Table LEARN_NEIGHBOR learns the mac-binding using the action
         * - 'put_arp/put_nd'. Learning mac-binding is skipped if
         *   REGBIT_LOOKUP_NEIGHBOR_RESULT bit is set or
         *   REGBIT_LOOKUP_NEIGHBOR_IP_RESULT is not set.
         *
         * */

        /* Flows for LOOKUP_NEIGHBOR. */
        bool learn_from_arp_request = smap_get_bool(&od->nbr->options,
            "always_learn_from_arp_request", true);
        ds_clear(actions);
        ds_put_format(actions, REGBIT_LOOKUP_NEIGHBOR_RESULT
                      " = lookup_arp(inport, arp.spa, arp.sha); %snext;",
                      learn_from_arp_request ? "" :
                      REGBIT_LOOKUP_NEIGHBOR_IP_RESULT" = 1; ");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_LOOKUP_NEIGHBOR, 100,
                      "arp.op == 2", ds_cstr(actions));

        ds_clear(actions);
        ds_put_format(actions, REGBIT_LOOKUP_NEIGHBOR_RESULT
                      " = lookup_nd(inport, nd.target, nd.tll); %snext;",
                      learn_from_arp_request ? "" :
                      REGBIT_LOOKUP_NEIGHBOR_IP_RESULT" = 1; ");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_LOOKUP_NEIGHBOR, 100, "nd_na",
                      ds_cstr(actions));

        ds_clear(actions);
        ds_put_format(actions, REGBIT_LOOKUP_NEIGHBOR_RESULT
                      " = lookup_nd(inport, ip6.src, nd.sll); %snext;",
                      learn_from_arp_request ? "" :
                      REGBIT_LOOKUP_NEIGHBOR_IP_RESULT
                      " = lookup_nd_ip(inport, ip6.src); ");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_LOOKUP_NEIGHBOR, 100, "nd_ns",
                      ds_cstr(actions));

        /* For other packet types, we can skip neighbor learning.
         * So set REGBIT_LOOKUP_NEIGHBOR_RESULT to 1. */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_LOOKUP_NEIGHBOR, 0, "1",
                      REGBIT_LOOKUP_NEIGHBOR_RESULT" = 1; next;");

        /* Flows for LEARN_NEIGHBOR. */
        /* Skip Neighbor learning if not required. */
        ds_clear(match);
        ds_put_format(match, REGBIT_LOOKUP_NEIGHBOR_RESULT" == 1%s",
                      learn_from_arp_request ? "" :
                      " || "REGBIT_LOOKUP_NEIGHBOR_IP_RESULT" == 0");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 100,
                      ds_cstr(match), "next;");

        ovn_lflow_metered(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                          "arp", "put_arp(inport, arp.spa, arp.sha); next;",
                          copp_meter_get(COPP_ARP, od->nbr->copp,
                                         meter_groups));

        ovn_lflow_add(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 95,
                      "nd_ns && (ip6.src == 0 || nd.sll == 0)", "next;");

        ovn_lflow_metered(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 95,
                          "nd_na && nd.tll == 0",
                          "put_nd(inport, nd.target, eth.src); next;",
                          copp_meter_get(COPP_ND_NA, od->nbr->copp,
                                         meter_groups));

        ovn_lflow_metered(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                          "nd_na", "put_nd(inport, nd.target, nd.tll); next;",
                          copp_meter_get(COPP_ND_NA, od->nbr->copp,
                                         meter_groups));

        ovn_lflow_metered(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                          "nd_ns", "put_nd(inport, ip6.src, nd.sll); next;",
                          copp_meter_get(COPP_ND_NS, od->nbr->copp,
                                         meter_groups));

        ovn_lflow_add_default_drop(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR);
    }

}

/* Logical router ingress Table 1: Neighbor lookup lflows
 * for logical router ports. */
static void
build_neigh_learning_flows_for_lrouter_port(
        struct ovn_port *op, struct hmap *lflows,
        struct ds *match, struct ds *actions)
{
    if (op->nbrp) {

        bool learn_from_arp_request = smap_get_bool(&op->od->nbr->options,
            "always_learn_from_arp_request", true);

        /* Check if we need to learn mac-binding from ARP requests. */
        for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            if (!learn_from_arp_request) {
                /* ARP request to this address should always get learned,
                 * so add a priority-110 flow to set
                 * REGBIT_LOOKUP_NEIGHBOR_IP_RESULT to 1. */
                ds_clear(match);
                ds_put_format(match,
                              "inport == %s && arp.spa == %s/%u && "
                              "arp.tpa == %s && arp.op == 1",
                              op->json_key,
                              op->lrp_networks.ipv4_addrs[i].network_s,
                              op->lrp_networks.ipv4_addrs[i].plen,
                              op->lrp_networks.ipv4_addrs[i].addr_s);
                if (is_l3dgw_port(op)) {
                    ds_put_format(match, " && is_chassis_resident(%s)",
                                  op->cr_port->json_key);
                }
                const char *actions_s = REGBIT_LOOKUP_NEIGHBOR_RESULT
                                  " = lookup_arp(inport, arp.spa, arp.sha); "
                                  REGBIT_LOOKUP_NEIGHBOR_IP_RESULT" = 1;"
                                  " next;";
                ovn_lflow_add_with_hint(lflows, op->od,
                                        S_ROUTER_IN_LOOKUP_NEIGHBOR, 110,
                                        ds_cstr(match), actions_s,
                                        &op->nbrp->header_);
            }
            ds_clear(match);
            ds_put_format(match,
                          "inport == %s && arp.spa == %s/%u && arp.op == 1",
                          op->json_key,
                          op->lrp_networks.ipv4_addrs[i].network_s,
                          op->lrp_networks.ipv4_addrs[i].plen);
            if (is_l3dgw_port(op)) {
                ds_put_format(match, " && is_chassis_resident(%s)",
                              op->cr_port->json_key);
            }
            ds_clear(actions);
            ds_put_format(actions, REGBIT_LOOKUP_NEIGHBOR_RESULT
                          " = lookup_arp(inport, arp.spa, arp.sha); %snext;",
                          learn_from_arp_request ? "" :
                          REGBIT_LOOKUP_NEIGHBOR_IP_RESULT
                          " = lookup_arp_ip(inport, arp.spa); ");
            ovn_lflow_add_with_hint(lflows, op->od,
                                    S_ROUTER_IN_LOOKUP_NEIGHBOR, 100,
                                    ds_cstr(match), ds_cstr(actions),
                                    &op->nbrp->header_);
        }
    }
}

/* Logical router ingress table ND_RA_OPTIONS & ND_RA_RESPONSE: IPv6 Router
 * Adv (RA) options and response. */
static void
build_ND_RA_flows_for_lrouter_port(
        struct ovn_port *op, struct hmap *lflows,
        struct ds *match, struct ds *actions,
        const struct shash *meter_groups)
{
    if (!op->nbrp || op->nbrp->peer || !op->peer) {
        return;
    }

    if (!op->lrp_networks.n_ipv6_addrs) {
        return;
    }

    const char *address_mode = smap_get(
        &op->nbrp->ipv6_ra_configs, "address_mode");

    if (!address_mode) {
        return;
    }
    if (strcmp(address_mode, "slaac") &&
        strcmp(address_mode, "dhcpv6_stateful") &&
        strcmp(address_mode, "dhcpv6_stateless")) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Invalid address mode [%s] defined",
                     address_mode);
        return;
    }

    ds_clear(match);
    ds_put_format(match, "inport == %s && ip6.dst == ff02::2 && nd_rs",
                          op->json_key);
    ds_clear(actions);

    const char *mtu_s = smap_get(
        &op->nbrp->ipv6_ra_configs, "mtu");

    /* As per RFC 2460, 1280 is minimum IPv6 MTU. */
    uint32_t mtu = (mtu_s && atoi(mtu_s) >= 1280) ? atoi(mtu_s) : 0;

    ds_put_format(actions, REGBIT_ND_RA_OPTS_RESULT" = put_nd_ra_opts("
                  "addr_mode = \"%s\", slla = %s",
                  address_mode, op->lrp_networks.ea_s);
    if (mtu > 0) {
        ds_put_format(actions, ", mtu = %u", mtu);
    }

    const char *prf = smap_get_def(
        &op->nbrp->ipv6_ra_configs, "router_preference", "MEDIUM");
    if (strcmp(prf, "MEDIUM")) {
        ds_put_format(actions, ", router_preference = \"%s\"", prf);
    }

    const char *ra_rdnss = smap_get(&op->nbrp->ipv6_ra_configs, "rdnss");
    if (ra_rdnss) {
        ds_put_format(actions, ", rdnss = %s", ra_rdnss);
    }

    const char *ra_dnssl = smap_get(&op->nbrp->ipv6_ra_configs, "dnssl");
    if (ra_dnssl) {
        ds_put_format(actions, ", dnssl = \"%s\"", ra_dnssl);
    }

    const char *route_info = smap_get(&op->nbrp->ipv6_ra_configs,
                                      "route_info");
    if (route_info) {
        ds_put_format(actions, ", route_info = \"%s\"", route_info);
    }

    bool add_rs_response_flow = false;

    for (size_t i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
        if (in6_is_lla(&op->lrp_networks.ipv6_addrs[i].network)) {
            continue;
        }

        ds_put_format(actions, ", prefix = %s/%u",
                      op->lrp_networks.ipv6_addrs[i].network_s,
                      op->lrp_networks.ipv6_addrs[i].plen);

        add_rs_response_flow = true;
    }

    if (add_rs_response_flow) {
        ds_put_cstr(actions, "); next;");
        ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_ND_RA_OPTIONS,
                                  50, ds_cstr(match), ds_cstr(actions), NULL,
                                  copp_meter_get(COPP_ND_RA_OPTS,
                                                 op->od->nbr->copp,
                                                 meter_groups),
                                  &op->nbrp->header_);
        ds_clear(actions);
        ds_clear(match);
        ds_put_format(match, "inport == %s && ip6.dst == ff02::2 && "
                      "nd_ra && "REGBIT_ND_RA_OPTS_RESULT, op->json_key);

        char ip6_str[INET6_ADDRSTRLEN + 1];
        struct in6_addr lla;
        in6_generate_lla(op->lrp_networks.ea, &lla);
        memset(ip6_str, 0, sizeof(ip6_str));
        ipv6_string_mapped(ip6_str, &lla);
        ds_put_format(actions, "eth.dst = eth.src; eth.src = %s; "
                      "ip6.dst = ip6.src; ip6.src = %s; "
                      "outport = inport; flags.loopback = 1; "
                      "output;",
                      op->lrp_networks.ea_s, ip6_str);
        ovn_lflow_add_with_hint(lflows, op->od,
                                S_ROUTER_IN_ND_RA_RESPONSE, 50,
                                ds_cstr(match), ds_cstr(actions),
                                &op->nbrp->header_);
    }
}

/* Logical router ingress table ND_RA_OPTIONS & ND_RA_RESPONSE: RS
 * responder, by default goto next. (priority 0). */
static void
build_ND_RA_flows_for_lrouter(struct ovn_datapath *od, struct hmap *lflows)
{
    if (od->nbr) {
        ovn_lflow_add(lflows, od, S_ROUTER_IN_ND_RA_OPTIONS, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_ND_RA_RESPONSE, 0, "1", "next;");
    }
}

/* Logical router ingress table IP_ROUTING_PRE:
 * by default goto next. (priority 0). */
static void
build_ip_routing_pre_flows_for_lrouter(struct ovn_datapath *od,
                                       struct hmap *lflows)
{
    if (od->nbr) {
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING_PRE, 0, "1",
                      REG_ROUTE_TABLE_ID" = 0; next;");
    }
}

/* Logical router ingress table IP_ROUTING : IP Routing.
 *
 * A packet that arrives at this table is an IP packet that should be
 * routed to the address in 'ip[46].dst'.
 *
 * For regular routes without ECMP, table IP_ROUTING sets outport to the
 * correct output port, eth.src to the output port's MAC address, and
 * REG_NEXT_HOP_IPV4/REG_NEXT_HOP_IPV6 to the next-hop IP address
 * (leaving 'ip[46].dst', the packet’s final destination, unchanged), and
 * advances to the next table.
 *
 * For ECMP routes, i.e. multiple routes with same policy and prefix, table
 * IP_ROUTING remembers ECMP group id and selects a member id, and advances
 * to table IP_ROUTING_ECMP, which sets outport, eth.src and
 * REG_NEXT_HOP_IPV4/REG_NEXT_HOP_IPV6 for the selected ECMP member.
 */
static void
build_ip_routing_flows_for_lrouter_port(
        struct ovn_port *op, const struct hmap *ports, struct hmap *lflows)
{
    if (op->nbrp) {

        for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            add_route(lflows, op->od, op, op->lrp_networks.ipv4_addrs[i].addr_s,
                      op->lrp_networks.ipv4_addrs[i].network_s,
                      op->lrp_networks.ipv4_addrs[i].plen, NULL, false, 0,
                      &op->nbrp->header_, false, ROUTE_PRIO_OFFSET_CONNECTED);
        }

        for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
            add_route(lflows, op->od, op, op->lrp_networks.ipv6_addrs[i].addr_s,
                      op->lrp_networks.ipv6_addrs[i].network_s,
                      op->lrp_networks.ipv6_addrs[i].plen, NULL, false, 0,
                      &op->nbrp->header_, false, ROUTE_PRIO_OFFSET_CONNECTED);
        }
    } else if (lsp_is_router(op->nbsp)) {
        struct ovn_port *peer = ovn_port_get_peer(ports, op);
        if (!peer || !peer->nbrp || !peer->lrp_networks.n_ipv4_addrs) {
            return;
        }

        for (int i = 0; i < op->od->n_router_ports; i++) {
            struct ovn_port *router_port = ovn_port_get_peer(
                    ports, op->od->router_ports[i]);
            if (!router_port || !router_port->nbrp || router_port == peer) {
                continue;
            }

            struct ovn_port_routable_addresses *ra = &router_port->routables;
            for (size_t j = 0; j < ra->n_addrs; j++) {
                struct lport_addresses *laddrs = &ra->laddrs[j];
                for (size_t k = 0; k < laddrs->n_ipv4_addrs; k++) {
                    add_route(lflows, peer->od, peer,
                              peer->lrp_networks.ipv4_addrs[0].addr_s,
                              laddrs->ipv4_addrs[k].network_s,
                              laddrs->ipv4_addrs[k].plen, NULL, false, 0,
                              &peer->nbrp->header_, false,
                              ROUTE_PRIO_OFFSET_CONNECTED);
                }
            }
        }
    }
}

static void
build_static_route_flows_for_lrouter(
        struct ovn_datapath *od, const struct chassis_features *features,
        struct hmap *lflows, const struct hmap *ports,
        const struct hmap *bfd_connections)
{
    if (od->nbr) {
        ovn_lflow_add_default_drop(lflows, od, S_ROUTER_IN_IP_ROUTING_ECMP);
        ovn_lflow_add_default_drop(lflows, od, S_ROUTER_IN_IP_ROUTING);
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING_ECMP, 150,
                      REG_ECMP_GROUP_ID" == 0", "next;");

        struct hmap ecmp_groups = HMAP_INITIALIZER(&ecmp_groups);
        struct hmap unique_routes = HMAP_INITIALIZER(&unique_routes);
        struct ovs_list parsed_routes = OVS_LIST_INITIALIZER(&parsed_routes);
        struct simap route_tables = SIMAP_INITIALIZER(&route_tables);
        struct ecmp_groups_node *group;

        for (int i = 0; i < od->nbr->n_ports; i++) {
            build_route_table_lflow(od, lflows, od->nbr->ports[i],
                                    &route_tables);
        }

        for (int i = 0; i < od->nbr->n_static_routes; i++) {
            struct parsed_route *route =
                parsed_routes_add(od, ports, &parsed_routes, &route_tables,
                                  od->nbr->static_routes[i], bfd_connections);
            if (!route) {
                continue;
            }
            group = ecmp_groups_find(&ecmp_groups, route);
            if (group) {
                ecmp_groups_add_route(group, route);
            } else {
                const struct parsed_route *existed_route =
                    unique_routes_remove(&unique_routes, route);
                if (existed_route) {
                    group = ecmp_groups_add(&ecmp_groups, existed_route);
                    if (group) {
                        ecmp_groups_add_route(group, route);
                    }
                } else {
                    unique_routes_add(&unique_routes, route);
                }
            }
        }
        HMAP_FOR_EACH (group, hmap_node, &ecmp_groups) {
            /* add a flow in IP_ROUTING, and one flow for each member in
             * IP_ROUTING_ECMP. */
            build_ecmp_route_flow(lflows, od, features->ct_no_masked_label,
                                  ports, group);
        }
        const struct unique_routes_node *ur;
        HMAP_FOR_EACH (ur, hmap_node, &unique_routes) {
            build_static_route_flow(lflows, od, ports, ur->route);
        }
        ecmp_groups_destroy(&ecmp_groups);
        unique_routes_destroy(&unique_routes);
        parsed_routes_destroy(&parsed_routes);
        simap_destroy(&route_tables);
    }
}

/* IP Multicast lookup. Here we set the output port, adjust TTL and
 * advance to next table (priority 500).
 */
static void
build_mcast_lookup_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows,
        struct ds *match, struct ds *actions)
{
    if (od->nbr) {

        /* Drop IPv6 multicast traffic that shouldn't be forwarded,
         * i.e., router solicitation and router advertisement.
         */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10550,
                      "nd_rs || nd_ra", debug_drop_action());
        if (!od->mcast_info.rtr.relay) {
            return;
        }

        struct ovn_igmp_group *igmp_group;

        LIST_FOR_EACH (igmp_group, list_node, &od->mcast_info.groups) {
            ds_clear(match);
            ds_clear(actions);
            if (IN6_IS_ADDR_V4MAPPED(&igmp_group->address)) {
                ds_put_format(match, "ip4 && ip4.dst == %s ",
                            igmp_group->mcgroup.name);
            } else {
                ds_put_format(match, "ip6 && ip6.dst == %s ",
                            igmp_group->mcgroup.name);
            }
            if (od->mcast_info.rtr.flood_static) {
                ds_put_cstr(actions,
                            "clone { "
                                "outport = \""MC_STATIC"\"; "
                                "ip.ttl--; "
                                "next; "
                            "};");
            }
            ds_put_format(actions, "outport = \"%s\"; ip.ttl--; next;",
                          igmp_group->mcgroup.name);
            ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10500,
                          ds_cstr(match), ds_cstr(actions));
        }

        /* If needed, flood unregistered multicast on statically configured
         * ports. Otherwise drop any multicast traffic.
         */
        if (od->mcast_info.rtr.flood_static) {
            /* MLD and IGMP packets that need to be flooded statically
             * should be flooded without decrementing TTL (it's always
             * 1).  To prevent packets looping for ever (to some extent),
             * drop IGMP/MLD packets that are received from the router's
             * own mac addresses.
             */
            struct ovn_port *op;
            LIST_FOR_EACH (op, dp_node, &od->port_list) {
                ds_clear(match);
                ds_put_format(match, "eth.src == %s && igmp",
                              op->lrp_networks.ea_s);
                ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10550,
                              ds_cstr(match), debug_drop_action());

                ds_clear(match);
                ds_put_format(match, "eth.src == %s && (mldv1 || mldv2)",
                              op->lrp_networks.ea_s);
                ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10550,
                              ds_cstr(match), debug_drop_action());
            }

            ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10460,
                          "igmp",
                          "clone { "
                                "outport = \""MC_STATIC"\"; "
                                "next; "
                          "};");
            ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10460,
                          "mldv1 || mldv2",
                          "clone { "
                                "outport = \""MC_STATIC"\"; "
                                "next; "
                          "};");
            ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10450,
                          "ip4.mcast || ip6.mcast",
                          "clone { "
                                "outport = \""MC_STATIC"\"; "
                                "ip.ttl--; "
                                "next; "
                          "};");
        } else {
            ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10450,
                          "ip4.mcast || ip6.mcast", debug_drop_action());
        }
    }
}

/* Logical router ingress table POLICY: Policy.
 *
 * A packet that arrives at this table is an IP packet that should be
 * permitted/denied/rerouted to the address in the rule's nexthop.
 * This table sets outport to the correct out_port,
 * eth.src to the output port's MAC address,
 * and REG_NEXT_HOP_IPV4/REG_NEXT_HOP_IPV6 to the next-hop IP address
 * (leaving 'ip[46].dst', the packet’s final destination, unchanged), and
 * advances to the next table for ARP/ND resolution. */
static void
build_ingress_policy_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows,
        const struct hmap *ports)
{
    if (od->nbr) {
        /* This is a catch-all rule. It has the lowest priority (0)
         * does a match-all("1") and pass-through (next) */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_POLICY, 0, "1",
                      REG_ECMP_GROUP_ID" = 0; next;");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_POLICY_ECMP, 150,
                      REG_ECMP_GROUP_ID" == 0", "next;");
        ovn_lflow_add_default_drop(lflows, od, S_ROUTER_IN_POLICY_ECMP);

        /* Convert routing policies to flows. */
        uint16_t ecmp_group_id = 1;
        for (int i = 0; i < od->nbr->n_policies; i++) {
            const struct nbrec_logical_router_policy *rule
                = od->nbr->policies[i];
            bool is_ecmp_reroute =
                (!strcmp(rule->action, "reroute") && rule->n_nexthops > 1);

            if (is_ecmp_reroute) {
                build_ecmp_routing_policy_flows(lflows, od, ports, rule,
                                                ecmp_group_id);
                ecmp_group_id++;
            } else {
                build_routing_policy_flow(lflows, od, ports, rule,
                                          &rule->header_);
            }
        }
    }
}

/* Local router ingress table ARP_RESOLVE: ARP Resolution. */
static void
build_arp_resolve_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows)
{
    if (od->nbr) {
        /* Multicast packets already have the outport set so just advance to
         * next table (priority 500). */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_ARP_RESOLVE, 500,
                      "ip4.mcast || ip6.mcast", "next;");

        ovn_lflow_add(lflows, od, S_ROUTER_IN_ARP_RESOLVE, 1, "ip4",
                      "get_arp(outport, " REG_NEXT_HOP_IPV4 "); next;");

        ovn_lflow_add(lflows, od, S_ROUTER_IN_ARP_RESOLVE, 1, "ip6",
                      "get_nd(outport, " REG_NEXT_HOP_IPV6 "); next;");

        ovn_lflow_add_default_drop(lflows, od, S_ROUTER_IN_ARP_RESOLVE);
    }
}

static void
routable_addresses_to_lflows(struct hmap *lflows, struct ovn_port *router_port,
                             struct ovn_port *peer, struct ds *match,
                             struct ds *actions)
{
    struct ovn_port_routable_addresses *ra = &router_port->routables;
    if (!ra->n_addrs) {
        return;
    }

    for (size_t i = 0; i < ra->n_addrs; i++) {
        ds_clear(match);
        ds_put_format(match, "outport == %s && "REG_NEXT_HOP_IPV4" == {",
                      peer->json_key);
        bool first = true;
        for (size_t j = 0; j < ra->laddrs[i].n_ipv4_addrs; j++) {
            if (!first) {
                ds_put_cstr(match, ", ");
            }
            ds_put_cstr(match, ra->laddrs[i].ipv4_addrs[j].addr_s);
            first = false;
        }
        ds_put_cstr(match, "}");

        ds_clear(actions);
        ds_put_format(actions, "eth.dst = %s; next;", ra->laddrs[i].ea_s);
        ovn_lflow_add(lflows, peer->od, S_ROUTER_IN_ARP_RESOLVE, 100,
                      ds_cstr(match), ds_cstr(actions));
    }
}

/* Local router ingress table ARP_RESOLVE: ARP Resolution.
 *
 * Any unicast packet that reaches this table is an IP packet whose
 * next-hop IP address is in REG_NEXT_HOP_IPV4/REG_NEXT_HOP_IPV6
 * (ip4.dst/ipv6.dst is the final destination).
 * This table resolves the IP address in
 * REG_NEXT_HOP_IPV4/REG_NEXT_HOP_IPV6 into an output port in outport and
 * an Ethernet address in eth.dst.
 */
static void
build_arp_resolve_flows_for_lrouter_port(
        struct ovn_port *op, struct hmap *lflows,
        const struct hmap *ports,
        struct ds *match, struct ds *actions)
{
    if (op->nbsp && !lsp_is_enabled(op->nbsp)) {
        return;
    }

    if (op->nbrp) {
        /* This is a logical router port. If next-hop IP address in
         * REG_NEXT_HOP_IPV4/REG_NEXT_HOP_IPV6 matches IP address of this
         * router port, then the packet is intended to eventually be sent
         * to this logical port. Set the destination mac address using
         * this port's mac address.
         *
         * The packet is still in peer's logical pipeline. So the match
         * should be on peer's outport. */
        if (op->peer && op->nbrp->peer) {
            if (op->lrp_networks.n_ipv4_addrs) {
                ds_clear(match);
                ds_put_format(match, "outport == %s && "
                              REG_NEXT_HOP_IPV4 "== ",
                              op->peer->json_key);
                op_put_v4_networks(match, op, false);

                ds_clear(actions);
                ds_put_format(actions, "eth.dst = %s; next;",
                              op->lrp_networks.ea_s);
                ovn_lflow_add_with_hint(lflows, op->peer->od,
                                        S_ROUTER_IN_ARP_RESOLVE, 100,
                                        ds_cstr(match), ds_cstr(actions),
                                        &op->nbrp->header_);
            }

            if (op->lrp_networks.n_ipv6_addrs) {
                ds_clear(match);
                ds_put_format(match, "outport == %s && "
                              REG_NEXT_HOP_IPV6 " == ",
                              op->peer->json_key);
                op_put_v6_networks(match, op);

                ds_clear(actions);
                ds_put_format(actions, "eth.dst = %s; next;",
                              op->lrp_networks.ea_s);
                ovn_lflow_add_with_hint(lflows, op->peer->od,
                                        S_ROUTER_IN_ARP_RESOLVE, 100,
                                        ds_cstr(match), ds_cstr(actions),
                                        &op->nbrp->header_);
            }
        }

        if (is_l3dgw_port(op)) {
            const char *redirect_type = smap_get(&op->nbrp->options,
                                                 "redirect-type");
            if (redirect_type && !strcasecmp(redirect_type, "bridged")) {
                /* Packet is on a non gateway chassis and
                 * has an unresolved ARP on a network behind gateway
                 * chassis attached router port. Since, redirect type
                 * is "bridged", instead of calling "get_arp"
                 * on this node, we will redirect the packet to gateway
                 * chassis, by setting destination mac router port mac.*/
                ds_clear(match);
                ds_put_format(match, "outport == %s && "
                              "!is_chassis_resident(%s)", op->json_key,
                              op->cr_port->json_key);
                ds_clear(actions);
                ds_put_format(actions, "eth.dst = %s; next;",
                              op->lrp_networks.ea_s);

                ovn_lflow_add_with_hint(lflows, op->od,
                                        S_ROUTER_IN_ARP_RESOLVE, 50,
                                        ds_cstr(match), ds_cstr(actions),
                                        &op->nbrp->header_);
            }
        }

        /* Drop IP traffic destined to router owned IPs. Part of it is dropped
         * in stage "lr_in_ip_input" but traffic that could have been unSNATed
         * but didn't match any existing session might still end up here.
         *
         * Priority 2.
         */
        build_lrouter_drop_own_dest(op, S_ROUTER_IN_ARP_RESOLVE, 2, true,
                                    lflows);
    } else if (op->od->n_router_ports && !lsp_is_router(op->nbsp)
               && strcmp(op->nbsp->type, "virtual")) {
        /* This is a logical switch port that backs a VM or a container.
         * Extract its addresses. For each of the address, go through all
         * the router ports attached to the switch (to which this port
         * connects) and if the address in question is reachable from the
         * router port, add an ARP/ND entry in that router's pipeline. */

        for (size_t i = 0; i < op->n_lsp_addrs; i++) {
            const char *ea_s = op->lsp_addrs[i].ea_s;
            for (size_t j = 0; j < op->lsp_addrs[i].n_ipv4_addrs; j++) {
                const char *ip_s = op->lsp_addrs[i].ipv4_addrs[j].addr_s;
                for (size_t k = 0; k < op->od->n_router_ports; k++) {
                    /* Get the Logical_Router_Port that the
                     * Logical_Switch_Port is connected to, as
                     * 'peer'. */
                    struct ovn_port *peer = ovn_port_get_peer(
                            ports, op->od->router_ports[k]);
                    if (!peer || !peer->nbrp) {
                        continue;
                    }

                    if (!find_lrp_member_ip(peer, ip_s)) {
                        continue;
                    }

                    ds_clear(match);
                    ds_put_format(match, "outport == %s && "
                                  REG_NEXT_HOP_IPV4 " == %s",
                                  peer->json_key, ip_s);

                    ds_clear(actions);
                    ds_put_format(actions, "eth.dst = %s; next;", ea_s);
                    ovn_lflow_add_with_hint(lflows, peer->od,
                                            S_ROUTER_IN_ARP_RESOLVE, 100,
                                            ds_cstr(match),
                                            ds_cstr(actions),
                                            &op->nbsp->header_);
                }
            }

            for (size_t j = 0; j < op->lsp_addrs[i].n_ipv6_addrs; j++) {
                const char *ip_s = op->lsp_addrs[i].ipv6_addrs[j].addr_s;
                for (size_t k = 0; k < op->od->n_router_ports; k++) {
                    /* Get the Logical_Router_Port that the
                     * Logical_Switch_Port is connected to, as
                     * 'peer'. */
                    struct ovn_port *peer = ovn_port_get_peer(
                            ports, op->od->router_ports[k]);
                    if (!peer || !peer->nbrp) {
                        continue;
                    }

                    if (!find_lrp_member_ip(peer, ip_s)) {
                        continue;
                    }

                    ds_clear(match);
                    ds_put_format(match, "outport == %s && "
                                  REG_NEXT_HOP_IPV6 " == %s",
                                  peer->json_key, ip_s);

                    ds_clear(actions);
                    ds_put_format(actions, "eth.dst = %s; next;", ea_s);
                    ovn_lflow_add_with_hint(lflows, peer->od,
                                            S_ROUTER_IN_ARP_RESOLVE, 100,
                                            ds_cstr(match),
                                            ds_cstr(actions),
                                            &op->nbsp->header_);
                }
            }
        }
    } else if (op->od->n_router_ports && !lsp_is_router(op->nbsp)
               && !strcmp(op->nbsp->type, "virtual")) {
        /* This is a virtual port. Add ARP replies for the virtual ip with
         * the mac of the present active virtual parent.
         * If the logical port doesn't have virtual parent set in
         * Port_Binding table, then add the flow to set eth.dst to
         * 00:00:00:00:00:00 and advance to next table so that ARP is
         * resolved by router pipeline using the arp{} action.
         * The MAC_Binding entry for the virtual ip might be invalid. */

        const char *vip = smap_get(&op->nbsp->options,
                                   "virtual-ip");
        const char *virtual_parents = smap_get(&op->nbsp->options,
                                               "virtual-parents");

        if (!vip || !virtual_parents || !op->sb) {
            return;
        }

        bool is_ipv4 = strchr(vip, '.') ? true : false;
        if (is_ipv4) {
            ovs_be32 ipv4;
            if (!ip_parse(vip, &ipv4)) {
                 return;
            }
        } else {
            struct in6_addr ipv6;
            if (!ipv6_parse(vip, &ipv6)) {
                 return;
            }
        }

        if (!op->sb->virtual_parent || !op->sb->virtual_parent[0] ||
            !op->sb->chassis) {
            /* The virtual port is not claimed yet. */
            for (size_t i = 0; i < op->od->n_router_ports; i++) {
                struct ovn_port *peer = ovn_port_get_peer(
                        ports, op->od->router_ports[i]);
                if (!peer || !peer->nbrp) {
                    continue;
                }

                if (find_lrp_member_ip(peer, vip)) {
                    ds_clear(match);
                    ds_put_format(
                        match, "outport == %s && " "%s == %s", peer->json_key,
                        is_ipv4 ? REG_NEXT_HOP_IPV4 : REG_NEXT_HOP_IPV6, vip);

                    const char *arp_actions =
                                  "eth.dst = 00:00:00:00:00:00; next;";
                    ovn_lflow_add_with_hint(lflows, peer->od,
                                            S_ROUTER_IN_ARP_RESOLVE, 100,
                                            ds_cstr(match),
                                            arp_actions,
                                            &op->nbsp->header_);
                    break;
                }
            }
        } else {
            struct ovn_port *vp =
                ovn_port_find(ports, op->sb->virtual_parent);
            if (!vp || !vp->nbsp) {
                return;
            }

            for (size_t i = 0; i < vp->n_lsp_addrs; i++) {
                bool found_vip_network = false;
                const char *ea_s = vp->lsp_addrs[i].ea_s;
                for (size_t j = 0; j < vp->od->n_router_ports; j++) {
                    /* Get the Logical_Router_Port that the
                    * Logical_Switch_Port is connected to, as
                    * 'peer'. */
                    struct ovn_port *peer =
                        ovn_port_get_peer(ports, vp->od->router_ports[j]);
                    if (!peer || !peer->nbrp) {
                        continue;
                    }

                    if (!find_lrp_member_ip(peer, vip)) {
                        continue;
                    }

                    ds_clear(match);
                    ds_put_format(
                        match, "outport == %s && " "%s == %s", peer->json_key,
                        is_ipv4 ? REG_NEXT_HOP_IPV4 : REG_NEXT_HOP_IPV6, vip);

                    ds_clear(actions);
                    ds_put_format(actions, "eth.dst = %s; next;", ea_s);
                    ovn_lflow_add_with_hint(lflows, peer->od,
                                            S_ROUTER_IN_ARP_RESOLVE, 100,
                                            ds_cstr(match),
                                            ds_cstr(actions),
                                            &op->nbsp->header_);
                    found_vip_network = true;
                    break;
                }

                if (found_vip_network) {
                    break;
                }
            }
        }
    } else if (lsp_is_router(op->nbsp)) {
        /* This is a logical switch port that connects to a router. */

        /* The peer of this switch port is the router port for which
         * we need to add logical flows such that it can resolve
         * ARP entries for all the other router ports connected to
         * the switch in question. */
        struct ovn_port *peer = ovn_port_get_peer(ports, op);
        if (!peer || !peer->nbrp) {
            return;
        }

        if (peer->od->nbr &&
            smap_get_bool(&peer->od->nbr->options,
                          "dynamic_neigh_routers", false)) {
            return;
        }

        for (size_t i = 0; i < op->od->n_router_ports; i++) {
            const char *router_port_name = smap_get(
                                &op->od->router_ports[i]->nbsp->options,
                                "router-port");
            struct ovn_port *router_port = ovn_port_find(ports,
                                                         router_port_name);
            if (!router_port || !router_port->nbrp) {
                continue;
            }

            /* Skip the router port under consideration. */
            if (router_port == peer) {
               continue;
            }

            if (router_port->lrp_networks.n_ipv4_addrs) {
                ds_clear(match);
                ds_put_format(match, "outport == %s && "
                              REG_NEXT_HOP_IPV4 " == ",
                              peer->json_key);
                op_put_v4_networks(match, router_port, false);

                ds_clear(actions);
                ds_put_format(actions, "eth.dst = %s; next;",
                                          router_port->lrp_networks.ea_s);
                ovn_lflow_add_with_hint(lflows, peer->od,
                                        S_ROUTER_IN_ARP_RESOLVE, 100,
                                        ds_cstr(match), ds_cstr(actions),
                                        &op->nbsp->header_);
            }

            if (router_port->lrp_networks.n_ipv6_addrs) {
                ds_clear(match);
                ds_put_format(match, "outport == %s && "
                              REG_NEXT_HOP_IPV6 " == ",
                              peer->json_key);
                op_put_v6_networks(match, router_port);

                ds_clear(actions);
                ds_put_format(actions, "eth.dst = %s; next;",
                              router_port->lrp_networks.ea_s);
                ovn_lflow_add_with_hint(lflows, peer->od,
                                        S_ROUTER_IN_ARP_RESOLVE, 100,
                                        ds_cstr(match), ds_cstr(actions),
                                        &op->nbsp->header_);
            }

            if (smap_get(&peer->od->nbr->options, "chassis")
                || peer->cr_port) {
                routable_addresses_to_lflows(lflows, router_port, peer,
                                             match, actions);
            }
        }
    }

}

static void
build_icmperr_pkt_big_flows(struct ovn_port *op, int mtu, struct hmap *lflows,
                            const struct shash *meter_groups, struct ds *match,
                            struct ds *actions, enum ovn_stage stage,
                            struct ovn_port *outport)
{
    char *outport_match = outport ? xasprintf("outport == %s && ",
                                              outport->json_key)
                                  : NULL;

    if (op->lrp_networks.ipv4_addrs) {
        ds_clear(match);
        ds_put_format(match, "inport == %s && %sip4 && "REGBIT_PKT_LARGER
                      " && "REGBIT_EGRESS_LOOPBACK" == 0", op->json_key,
                      outport ? outport_match : "");

        ds_clear(actions);
        /* Set icmp4.frag_mtu to gw_mtu */
        ds_put_format(actions,
            "icmp4_error {"
            REGBIT_EGRESS_LOOPBACK" = 1; "
            REGBIT_PKT_LARGER" = 0; "
            "eth.dst = %s; "
            "ip4.dst = ip4.src; "
            "ip4.src = %s; "
            "ip.ttl = 255; "
            "icmp4.type = 3; /* Destination Unreachable. */ "
            "icmp4.code = 4; /* Frag Needed and DF was Set. */ "
            "icmp4.frag_mtu = %d; "
            "next(pipeline=ingress, table=%d); };",
            op->lrp_networks.ea_s,
            op->lrp_networks.ipv4_addrs[0].addr_s,
            mtu, ovn_stage_get_table(S_ROUTER_IN_ADMISSION));
        ovn_lflow_add_with_hint__(lflows, op->od, stage, 150,
                                  ds_cstr(match), ds_cstr(actions),
                                  NULL,
                                  copp_meter_get(
                                        COPP_ICMP4_ERR,
                                        op->od->nbr->copp,
                                        meter_groups),
                                  &op->nbrp->header_);
    }

    if (op->lrp_networks.ipv6_addrs) {
        ds_clear(match);
        ds_put_format(match, "inport == %s && %sip6 && "REGBIT_PKT_LARGER
                      " && "REGBIT_EGRESS_LOOPBACK" == 0", op->json_key,
                      outport ? outport_match : "");

        ds_clear(actions);
        /* Set icmp6.frag_mtu to gw_mtu */
        ds_put_format(actions,
            "icmp6_error {"
            REGBIT_EGRESS_LOOPBACK" = 1; "
            REGBIT_PKT_LARGER" = 0; "
            "eth.dst = %s; "
            "ip6.dst = ip6.src; "
            "ip6.src = %s; "
            "ip.ttl = 255; "
            "icmp6.type = 2; /* Packet Too Big. */ "
            "icmp6.code = 0; "
            "icmp6.frag_mtu = %d; "
            "next(pipeline=ingress, table=%d); };",
            op->lrp_networks.ea_s,
            op->lrp_networks.ipv6_addrs[0].addr_s,
            mtu, ovn_stage_get_table(S_ROUTER_IN_ADMISSION));
        ovn_lflow_add_with_hint__(lflows, op->od, stage, 150,
                                  ds_cstr(match), ds_cstr(actions),
                                  NULL,
                                  copp_meter_get(
                                        COPP_ICMP6_ERR,
                                        op->od->nbr->copp,
                                        meter_groups),
                                  &op->nbrp->header_);
    }
    free(outport_match);
}

static void
build_check_pkt_len_flows_for_lrp(struct ovn_port *op,
                                  struct hmap *lflows,
                                  const struct hmap *ports,
                                  const struct shash *meter_groups,
                                  struct ds *match,
                                  struct ds *actions)
{
    int gw_mtu = smap_get_int(&op->nbrp->options, "gateway_mtu", 0);
    if (gw_mtu <= 0) {
        return;
    }

    ds_clear(match);
    ds_put_format(match, "outport == %s", op->json_key);
    build_gateway_mtu_flow(lflows, op, S_ROUTER_IN_CHK_PKT_LEN, 50, 55,
                           match, actions, &op->nbrp->header_, "next;");

    /* ingress traffic */
    build_icmperr_pkt_big_flows(op, gw_mtu, lflows, meter_groups,
                                match, actions, S_ROUTER_IN_IP_INPUT,
                                NULL);

    for (size_t i = 0; i < op->od->nbr->n_ports; i++) {
        struct ovn_port *rp = ovn_port_find(ports,
                                            op->od->nbr->ports[i]->name);
        if (!rp || rp == op) {
            continue;
        }

        /* egress traffic */
        build_icmperr_pkt_big_flows(rp, gw_mtu, lflows, meter_groups,
                                    match, actions, S_ROUTER_IN_LARGER_PKTS,
                                    op);
    }
}

/* Local router ingress table CHK_PKT_LEN: Check packet length.
 *
 * Any IPv4 packet with outport set to the distributed gateway
 * router port, check the packet length and store the result in the
 * 'REGBIT_PKT_LARGER' register bit.
 *
 * Local router ingress table LARGER_PKTS: Handle larger packets.
 *
 * Any IPv4 packet with outport set to the distributed gateway
 * router port and the 'REGBIT_PKT_LARGER' register bit is set,
 * generate ICMPv4 packet with type 3 (Destination Unreachable) and
 * code 4 (Fragmentation needed).
 * */
static void
build_check_pkt_len_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows,
        const struct hmap *ports,
        struct ds *match, struct ds *actions,
        const struct shash *meter_groups)
{
    if (!od->nbr) {
        return;
    }

    /* Packets are allowed by default. */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_CHK_PKT_LEN, 0, "1",
                  "next;");
    ovn_lflow_add(lflows, od, S_ROUTER_IN_LARGER_PKTS, 0, "1",
                  "next;");

    for (size_t i = 0; i < od->nbr->n_ports; i++) {
        struct ovn_port *rp = ovn_port_find(ports,
                                            od->nbr->ports[i]->name);
        if (!rp || !rp->nbrp) {
            continue;
        }
        build_check_pkt_len_flows_for_lrp(rp, lflows, ports, meter_groups,
                                          match, actions);
    }
}

/* Logical router ingress table GW_REDIRECT: Gateway redirect. */
static void
build_gateway_redirect_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows,
        struct ds *match, struct ds *actions)
{
    if (!od->nbr) {
        return;
    }
    for (size_t i = 0; i < od->n_l3dgw_ports; i++) {
        const struct ovsdb_idl_row *stage_hint = NULL;
        bool add_def_flow = true;

        if (od->l3dgw_ports[i]->nbrp) {
            stage_hint = &od->l3dgw_ports[i]->nbrp->header_;
        }

        /* For traffic with outport == l3dgw_port, if the
         * packet did not match any higher priority redirect
         * rule, then the traffic is redirected to the central
         * instance of the l3dgw_port. */
        ds_clear(match);
        ds_put_format(match, "outport == %s",
                      od->l3dgw_ports[i]->json_key);
        ds_clear(actions);
        ds_put_format(actions, "outport = %s; next;",
                      od->l3dgw_ports[i]->cr_port->json_key);
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_GW_REDIRECT, 50,
                                ds_cstr(match), ds_cstr(actions),
                                stage_hint);
        for (int j = 0; j < od->n_nat_entries; j++) {
            const struct ovn_nat *nat = &od->nat_entries[j];

            if (!lrouter_nat_is_stateless(nat->nb) ||
                strcmp(nat->nb->type, "dnat_and_snat") ||
                (!nat->nb->allowed_ext_ips && !nat->nb->exempted_ext_ips)) {
                continue;
            }

            struct ds match_ext = DS_EMPTY_INITIALIZER;
            struct nbrec_address_set  *as = nat->nb->allowed_ext_ips
                ? nat->nb->allowed_ext_ips : nat->nb->exempted_ext_ips;
            ds_put_format(&match_ext, "%s && ip%s.src == $%s",
                          ds_cstr(match), nat_entry_is_v6(nat) ? "6" : "4",
                          as->name);

            if (nat->nb->allowed_ext_ips) {
                ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_GW_REDIRECT,
                                        75, ds_cstr(&match_ext),
                                        ds_cstr(actions), stage_hint);
                if (add_def_flow) {
                    ds_clear(&match_ext);
                    ds_put_format(&match_ext, "ip && ip%s.dst == %s",
                                  nat_entry_is_v6(nat) ? "6" : "4",
                                  nat->nb->external_ip);
                    ovn_lflow_add(lflows, od, S_ROUTER_IN_GW_REDIRECT, 70,
                                  ds_cstr(&match_ext), "drop;");
                    add_def_flow = false;
                }
            } else if (nat->nb->exempted_ext_ips) {
                ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_GW_REDIRECT,
                                        75, ds_cstr(&match_ext), "drop;",
                                        stage_hint);
            }
            ds_destroy(&match_ext);
        }
    }

    /* Packets are allowed by default. */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_GW_REDIRECT, 0, "1", "next;");
}

/* Local router ingress table ARP_REQUEST: ARP request.
 *
 * In the common case where the Ethernet destination has been resolved,
 * this table outputs the packet (priority 0).  Otherwise, it composes
 * and sends an ARP/IPv6 NA request (priority 100). */
static void
build_arp_request_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows,
        struct ds *match, struct ds *actions,
        const struct shash *meter_groups)
{
    if (od->nbr) {
        for (int i = 0; i < od->nbr->n_static_routes; i++) {
            const struct nbrec_logical_router_static_route *route;

            route = od->nbr->static_routes[i];
            struct in6_addr gw_ip6;
            unsigned int plen;
            char *error = ipv6_parse_cidr(route->nexthop, &gw_ip6, &plen);
            if (error || plen != 128) {
                free(error);
                continue;
            }

            ds_clear(match);
            ds_put_format(match, "eth.dst == 00:00:00:00:00:00 && "
                          "ip6 && " REG_NEXT_HOP_IPV6 " == %s",
                          route->nexthop);
            struct in6_addr sn_addr;
            struct eth_addr eth_dst;
            in6_addr_solicited_node(&sn_addr, &gw_ip6);
            ipv6_multicast_to_ethernet(&eth_dst, &sn_addr);

            char sn_addr_s[INET6_ADDRSTRLEN + 1];
            ipv6_string_mapped(sn_addr_s, &sn_addr);

            ds_clear(actions);
            ds_put_format(actions,
                          "nd_ns { "
                          "eth.dst = "ETH_ADDR_FMT"; "
                          "ip6.dst = %s; "
                          "nd.target = %s; "
                          "output; "
                          "};", ETH_ADDR_ARGS(eth_dst), sn_addr_s,
                          route->nexthop);

            ovn_lflow_add_with_hint__(lflows, od, S_ROUTER_IN_ARP_REQUEST, 200,
                                      ds_cstr(match), ds_cstr(actions), NULL,
                                      copp_meter_get(COPP_ND_NS_RESOLVE,
                                                     od->nbr->copp,
                                                     meter_groups),
                                      &route->header_);
        }

        ovn_lflow_metered(lflows, od, S_ROUTER_IN_ARP_REQUEST, 100,
                          "eth.dst == 00:00:00:00:00:00 && ip4",
                          "arp { "
                          "eth.dst = ff:ff:ff:ff:ff:ff; "
                          "arp.spa = " REG_SRC_IPV4 "; "
                          "arp.tpa = " REG_NEXT_HOP_IPV4 "; "
                          "arp.op = 1; " /* ARP request */
                          "output; "
                          "};",
                          copp_meter_get(COPP_ARP_RESOLVE, od->nbr->copp,
                                         meter_groups));
        ovn_lflow_metered(lflows, od, S_ROUTER_IN_ARP_REQUEST, 100,
                          "eth.dst == 00:00:00:00:00:00 && ip6",
                          "nd_ns { "
                          "nd.target = " REG_NEXT_HOP_IPV6 "; "
                          "output; "
                          "};",
                          copp_meter_get(COPP_ND_NS_RESOLVE, od->nbr->copp,
                                         meter_groups));
        ovn_lflow_add(lflows, od, S_ROUTER_IN_ARP_REQUEST, 0, "1", "output;");
    }
}

/* Logical router egress table DELIVERY: Delivery (priority 100-110).
 *
 * Priority 100 rules deliver packets to enabled logical ports.
 * Priority 110 rules match multicast packets and update the source
 * mac before delivering to enabled logical ports. IP multicast traffic
 * bypasses S_ROUTER_IN_IP_ROUTING route lookups.
 */
static void
build_egress_delivery_flows_for_lrouter_port(
        struct ovn_port *op, struct hmap *lflows,
        struct ds *match, struct ds *actions)
{
    if (op->nbrp) {
        if (!lrport_is_enabled(op->nbrp)) {
            /* Drop packets to disabled logical ports (since logical flow
             * tables are default-drop). */
            return;
        }

        if (is_cr_port(op)) {
            /* No egress packets should be processed in the context of
             * a chassisredirect port.  The chassisredirect port should
             * be replaced by the l3dgw port in the local output
             * pipeline stage before egress processing. */
            return;
        }

        /* If multicast relay is enabled then also adjust source mac for IP
         * multicast traffic.
         */
        if (op->od->mcast_info.rtr.relay) {
            ds_clear(match);
            ds_clear(actions);
            ds_put_format(match, "(ip4.mcast || ip6.mcast) && outport == %s",
                          op->json_key);
            ds_put_format(actions, "eth.src = %s; output;",
                          op->lrp_networks.ea_s);
            ovn_lflow_add(lflows, op->od, S_ROUTER_OUT_DELIVERY, 110,
                          ds_cstr(match), ds_cstr(actions));
        }

        ds_clear(match);
        ds_put_format(match, "outport == %s", op->json_key);
        ovn_lflow_add(lflows, op->od, S_ROUTER_OUT_DELIVERY, 100,
                      ds_cstr(match), "output;");

        ovn_lflow_add_default_drop(lflows, op->od, S_ROUTER_OUT_DELIVERY);
    }

}

static void
build_misc_local_traffic_drop_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows)
{
    if (od->nbr) {
        /* Allow IGMP and MLD packets (with TTL = 1) if the router is
         * configured to flood them statically on some ports.
         */
        if (od->mcast_info.rtr.flood_static) {
            ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 120,
                          "igmp && ip.ttl == 1", "next;");
            ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 120,
                          "(mldv1 || mldv2) && ip.ttl == 1", "next;");
        }

        /* L3 admission control: drop multicast and broadcast source, localhost
         * source or destination, and zero network source or destination
         * (priority 100). */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 100,
                      "ip4.src_mcast ||"
                      "ip4.src == 255.255.255.255 || "
                      "ip4.src == 127.0.0.0/8 || "
                      "ip4.dst == 127.0.0.0/8 || "
                      "ip4.src == 0.0.0.0/8 || "
                      "ip4.dst == 0.0.0.0/8",
                      debug_drop_action());

        /* Drop ARP packets (priority 85). ARP request packets for router's own
         * IPs are handled with priority-90 flows.
         * Drop IPv6 ND packets (priority 85). ND NA packets for router's own
         * IPs are handled with priority-90 flows.
         */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 85,
                      "arp || nd", debug_drop_action());

        /* Allow IPv6 multicast traffic that's supposed to reach the
         * router pipeline (e.g., router solicitations).
         */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 84, "nd_rs || nd_ra",
                      "next;");

        /* Drop other reserved multicast. */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 83,
                      "ip6.mcast_rsvd", debug_drop_action());

        /* Allow other multicast if relay enabled (priority 82). */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 82,
                      "ip4.mcast || ip6.mcast",
                      (od->mcast_info.rtr.relay ? "next;" :
                                                  debug_drop_action()));

        /* Drop Ethernet local broadcast.  By definition this traffic should
         * not be forwarded.*/
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 50,
                      "eth.bcast", debug_drop_action());

        /* TTL discard */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 30,
                      "ip4 && ip.ttl == {0, 1}", debug_drop_action());

        /* Pass other traffic not already handled to the next table for
         * routing. */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 0, "1", "next;");
    }
}

static void
build_dhcpv6_reply_flows_for_lrouter_port(
        struct ovn_port *op, struct hmap *lflows,
        struct ds *match)
{
    if (op->nbrp && (!op->l3dgw_port)) {
        for (size_t i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
            ds_clear(match);
            ds_put_format(match, "ip6.dst == %s && udp.src == 547 &&"
                          " udp.dst == 546",
                          op->lrp_networks.ipv6_addrs[i].addr_s);
            ovn_lflow_add(lflows, op->od, S_ROUTER_IN_IP_INPUT, 100,
                          ds_cstr(match),
                          "reg0 = 0; handle_dhcpv6_reply;");
        }
    }

}

static void
build_ipv6_input_flows_for_lrouter_port(
        struct ovn_port *op, struct hmap *lflows,
        struct ds *match, struct ds *actions,
        const struct shash *meter_groups)
{
    if (op->nbrp && !is_cr_port(op)) {
        /* No ingress packets are accepted on a chassisredirect
         * port, so no need to program flows for that port. */
        if (op->lrp_networks.n_ipv6_addrs) {
            /* ICMPv6 echo reply.  These flows reply to echo requests
             * received for the router's IP address. */
            ds_clear(match);
            ds_put_cstr(match, "ip6.dst == ");
            op_put_v6_networks(match, op);
            ds_put_cstr(match, " && icmp6.type == 128 && icmp6.code == 0");

            const char *lrp_actions =
                        "ip6.dst <-> ip6.src; "
                        "ip.ttl = 255; "
                        "icmp6.type = 129; "
                        "flags.loopback = 1; "
                        "next; ";
            ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT, 90,
                                    ds_cstr(match), lrp_actions,
                                    &op->nbrp->header_);
        }

        /* ND reply.  These flows reply to ND solicitations for the
         * router's own IP address. */
        for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
            ds_clear(match);
            if (is_l3dgw_port(op)) {
                /* Traffic with eth.src = l3dgw_port->lrp_networks.ea_s
                 * should only be sent from the gateway chassi, so that
                 * upstream MAC learning points to the gateway chassis.
                 * Also need to avoid generation of multiple ND replies
                 * from different chassis. */
                ds_put_format(match, "is_chassis_resident(%s)",
                              op->cr_port->json_key);
            }

            build_lrouter_nd_flow(op->od, op, "nd_na_router",
                                  op->lrp_networks.ipv6_addrs[i].addr_s,
                                  op->lrp_networks.ipv6_addrs[i].sn_addr_s,
                                  REG_INPORT_ETH_ADDR, match, false, 90,
                                  &op->nbrp->header_, lflows, meter_groups);
        }

        /* UDP/TCP/SCTP port unreachable */
        if (!op->od->is_gw_router && !op->od->n_l3dgw_ports) {
            for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
                ds_clear(match);
                ds_put_format(match,
                              "ip6 && ip6.dst == %s && !ip.later_frag && tcp",
                              op->lrp_networks.ipv6_addrs[i].addr_s);
                const char *action = "tcp_reset {"
                                     "eth.dst <-> eth.src; "
                                     "ip6.dst <-> ip6.src; "
                                     "next; };";
                ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                          80, ds_cstr(match), action, NULL,
                                          copp_meter_get(
                                              COPP_TCP_RESET,
                                              op->od->nbr->copp,
                                              meter_groups),
                                          &op->nbrp->header_);

                ds_clear(match);
                ds_put_format(match,
                              "ip6 && ip6.dst == %s && !ip.later_frag && sctp",
                              op->lrp_networks.ipv6_addrs[i].addr_s);
                action = "sctp_abort {"
                         "eth.dst <-> eth.src; "
                         "ip6.dst <-> ip6.src; "
                         "next; };";
                ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                          80, ds_cstr(match), action, NULL,
                                          copp_meter_get(
                                              COPP_TCP_RESET,
                                              op->od->nbr->copp,
                                              meter_groups),
                                          &op->nbrp->header_);

                ds_clear(match);
                ds_put_format(match,
                              "ip6 && ip6.dst == %s && !ip.later_frag && udp",
                              op->lrp_networks.ipv6_addrs[i].addr_s);
                action = "icmp6 {"
                         "eth.dst <-> eth.src; "
                         "ip6.dst <-> ip6.src; "
                         "ip.ttl = 255; "
                         "icmp6.type = 1; "
                         "icmp6.code = 4; "
                         "next; };";
                ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                          80, ds_cstr(match), action, NULL,
                                          copp_meter_get(
                                              COPP_ICMP6_ERR,
                                              op->od->nbr->copp,
                                              meter_groups),
                                          &op->nbrp->header_);

                ds_clear(match);
                ds_put_format(match,
                              "ip6 && ip6.dst == %s && !ip.later_frag",
                              op->lrp_networks.ipv6_addrs[i].addr_s);
                action = "icmp6 {"
                         "eth.dst <-> eth.src; "
                         "ip6.dst <-> ip6.src; "
                         "ip.ttl = 255; "
                         "icmp6.type = 1; "
                         "icmp6.code = 3; "
                         "next; };";
                ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                          70, ds_cstr(match), action, NULL,
                                          copp_meter_get(
                                              COPP_ICMP6_ERR,
                                              op->od->nbr->copp,
                                              meter_groups),
                                          &op->nbrp->header_);
            }
        }

        /* ICMPv6 time exceeded */
        struct ds ip_ds = DS_EMPTY_INITIALIZER;
        for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
            /* skip link-local address */
            if (in6_is_lla(&op->lrp_networks.ipv6_addrs[i].network)) {
                continue;
            }

            ds_clear(match);
            ds_clear(actions);
            ds_clear(&ip_ds);
            if (is_l3dgw_port(op)) {
                ds_put_cstr(&ip_ds, "ip6.dst <-> ip6.src");
            } else {
                ds_put_format(&ip_ds, "ip6.dst = ip6.src; ip6.src = %s",
                              op->lrp_networks.ipv6_addrs[i].addr_s);
            }
            ds_put_format(match,
                          "inport == %s && ip6 && "
                          "ip6.src == %s/%d && "
                          "ip.ttl == {0, 1} && !ip.later_frag",
                          op->json_key,
                          op->lrp_networks.ipv6_addrs[i].network_s,
                          op->lrp_networks.ipv6_addrs[i].plen);
            ds_put_format(actions,
                          "icmp6 {"
                          "eth.dst <-> eth.src; "
                          "%s ; ip.ttl = 254; "
                          "icmp6.type = 3; /* Time exceeded */ "
                          "icmp6.code = 0; /* TTL exceeded in transit */ "
                          "outport = %s; flags.loopback = 1; output; };",
                          ds_cstr(&ip_ds), op->json_key);
            ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                    100, ds_cstr(match), ds_cstr(actions), NULL,
                    copp_meter_get(COPP_ICMP6_ERR, op->od->nbr->copp,
                                   meter_groups),
                    &op->nbrp->header_);
        }
        ds_destroy(&ip_ds);
    }

}

static void
build_lrouter_arp_nd_for_datapath(struct ovn_datapath *od,
                                  struct hmap *lflows,
                                  const struct shash *meter_groups)
{
    if (od->nbr) {

        /* Priority-90-92 flows handle ARP requests and ND packets. Most are
         * per logical port but DNAT addresses can be handled per datapath
         * for non gateway router ports.
         *
         * Priority 91 and 92 flows are added for each gateway router
         * port to handle the special cases. In case we get the packet
         * on a regular port, just reply with the port's ETH address.
         */
        for (int i = 0; i < od->nbr->n_nat; i++) {
            struct ovn_nat *nat_entry = &od->nat_entries[i];

            /* Skip entries we failed to parse. */
            if (!nat_entry_is_valid(nat_entry)) {
                continue;
            }

            /* Skip SNAT entries for now, we handle unique SNAT IPs separately
             * below.
             */
            if (!strcmp(nat_entry->nb->type, "snat")) {
                continue;
            }
            build_lrouter_nat_arp_nd_flow(od, nat_entry, lflows, meter_groups);
        }

        /* Now handle SNAT entries too, one per unique SNAT IP. */
        struct shash_node *snat_snode;
        SHASH_FOR_EACH (snat_snode, &od->snat_ips) {
            struct ovn_snat_ip *snat_ip = snat_snode->data;

            if (ovs_list_is_empty(&snat_ip->snat_entries)) {
                continue;
            }

            struct ovn_nat *nat_entry =
                CONTAINER_OF(ovs_list_front(&snat_ip->snat_entries),
                             struct ovn_nat, ext_addr_list_node);
            build_lrouter_nat_arp_nd_flow(od, nat_entry, lflows, meter_groups);
        }
    }
}

/* Logical router ingress table 3: IP Input for IPv4. */
static void
build_lrouter_ipv4_ip_input(struct ovn_port *op,
                            struct hmap *lflows,
                            struct ds *match, struct ds *actions,
                            const struct shash *meter_groups)
{
    /* No ingress packets are accepted on a chassisredirect
     * port, so no need to program flows for that port. */
    if (op->nbrp && !is_cr_port(op)) {
        if (op->lrp_networks.n_ipv4_addrs) {
            /* L3 admission control: drop packets that originate from an
             * IPv4 address owned by the router or a broadcast address
             * known to the router (priority 100). */
            ds_clear(match);
            ds_put_cstr(match, "ip4.src == ");
            op_put_v4_networks(match, op, true);
            ds_put_cstr(match, " && "REGBIT_EGRESS_LOOPBACK" == 0");
            ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT, 100,
                                    ds_cstr(match), debug_drop_action(),
                                    &op->nbrp->header_);

            /* ICMP echo reply.  These flows reply to ICMP echo requests
             * received for the router's IP address. Since packets only
             * get here as part of the logical router datapath, the inport
             * (i.e. the incoming locally attached net) does not matter.
             * The ip.ttl also does not matter (RFC1812 section 4.2.2.9) */
            ds_clear(match);
            ds_put_cstr(match, "ip4.dst == ");
            op_put_v4_networks(match, op, false);
            ds_put_cstr(match, " && icmp4.type == 8 && icmp4.code == 0");

            const char * icmp_actions = "ip4.dst <-> ip4.src; "
                          "ip.ttl = 255; "
                          "icmp4.type = 0; "
                          "flags.loopback = 1; "
                          "next; ";
            ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT, 90,
                                    ds_cstr(match), icmp_actions,
                                    &op->nbrp->header_);
        }

        /* BFD msg handling */
        build_lrouter_bfd_flows(lflows, op, meter_groups);

        /* ICMP time exceeded */
        struct ds ip_ds = DS_EMPTY_INITIALIZER;
        for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            ds_clear(match);
            ds_clear(actions);
            ds_clear(&ip_ds);
            if (is_l3dgw_port(op)) {
                ds_put_cstr(&ip_ds, "ip4.dst <-> ip4.src");
            } else {
                ds_put_format(&ip_ds, "ip4.dst = ip4.src; ip4.src = %s",
                              op->lrp_networks.ipv4_addrs[i].addr_s);
            }
            ds_put_format(match,
                          "inport == %s && ip4 && "
                          "ip.ttl == {0, 1} && !ip.later_frag", op->json_key);
            ds_put_format(actions,
                          "icmp4 {"
                          "eth.dst <-> eth.src; "
                          "icmp4.type = 11; /* Time exceeded */ "
                          "icmp4.code = 0; /* TTL exceeded in transit */ "
                          "%s ; ip.ttl = 254; "
                          "outport = %s; flags.loopback = 1; output; };",
                          ds_cstr(&ip_ds), op->json_key);
            ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                    100, ds_cstr(match), ds_cstr(actions), NULL,
                    copp_meter_get(COPP_ICMP4_ERR, op->od->nbr->copp,
                                   meter_groups),
                    &op->nbrp->header_);

        }
        ds_destroy(&ip_ds);

        /* ARP reply.  These flows reply to ARP requests for the router's own
         * IP address. */
        for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            ds_clear(match);
            ds_put_format(match, "arp.spa == %s/%u",
                          op->lrp_networks.ipv4_addrs[i].network_s,
                          op->lrp_networks.ipv4_addrs[i].plen);

            if (op->od->n_l3dgw_ports && op->peer
                && op->peer->od->n_localnet_ports) {
                bool add_chassis_resident_check = false;
                const char *json_key;
                if (is_l3dgw_port(op)) {
                    /* Traffic with eth.src = l3dgw_port->lrp_networks.ea_s
                     * should only be sent from the gateway chassis, so that
                     * upstream MAC learning points to the gateway chassis.
                     * Also need to avoid generation of multiple ARP responses
                     * from different chassis. */
                    add_chassis_resident_check = true;
                    json_key = op->cr_port->json_key;
                } else {
                    /* Check if the option 'reside-on-redirect-chassis'
                     * is set to true on the router port. If set to true
                     * and if peer's logical switch has a localnet port, it
                     * means the router pipeline for the packets from
                     * peer's logical switch is be run on the chassis
                     * hosting the gateway port and it should reply to the
                     * ARP requests for the router port IPs.
                     */
                    add_chassis_resident_check = smap_get_bool(
                        &op->nbrp->options,
                        "reside-on-redirect-chassis", false) &&
                        op->od->n_l3dgw_ports == 1;
                    json_key = op->od->l3dgw_ports[0]->cr_port->json_key;
                }

                if (add_chassis_resident_check) {
                    ds_put_format(match, " && is_chassis_resident(%s)",
                                  json_key);
                }
            }

            build_lrouter_arp_flow(op->od, op,
                                   op->lrp_networks.ipv4_addrs[i].addr_s,
                                   REG_INPORT_ETH_ADDR, match, false, 90,
                                   &op->nbrp->header_, lflows);
        }

        if (sset_count(&op->od->lb_ips->ips_v4_reachable)) {
            ds_clear(match);
            if (is_l3dgw_port(op)) {
                ds_put_format(match, "is_chassis_resident(%s)",
                              op->cr_port->json_key);
            }

            /* Create a single ARP rule for all IPs that are used as VIPs. */
            char *lb_ips_v4_as = lr_lb_address_set_ref(op->od->tunnel_key,
                                                       AF_INET);
            build_lrouter_arp_flow(op->od, op, lb_ips_v4_as,
                                   REG_INPORT_ETH_ADDR,
                                   match, false, 90, NULL, lflows);
            free(lb_ips_v4_as);
        }

        if (sset_count(&op->od->lb_ips->ips_v6_reachable)) {
            ds_clear(match);

            if (is_l3dgw_port(op)) {
                ds_put_format(match, "is_chassis_resident(%s)",
                              op->cr_port->json_key);
            }

            /* Create a single ND rule for all IPs that are used as VIPs. */
            char *lb_ips_v6_as = lr_lb_address_set_ref(op->od->tunnel_key,
                                                       AF_INET6);
            build_lrouter_nd_flow(op->od, op, "nd_na", lb_ips_v6_as, NULL,
                                  REG_INPORT_ETH_ADDR, match, false, 90,
                                  NULL, lflows, meter_groups);
            free(lb_ips_v6_as);
        }

        if (!op->od->is_gw_router && !op->od->n_l3dgw_ports) {
            /* UDP/TCP/SCTP port unreachable. */
            for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
                ds_clear(match);
                ds_put_format(match,
                              "ip4 && ip4.dst == %s && !ip.later_frag && udp",
                              op->lrp_networks.ipv4_addrs[i].addr_s);
                const char *action = "icmp4 {"
                                     "eth.dst <-> eth.src; "
                                     "ip4.dst <-> ip4.src; "
                                     "ip.ttl = 255; "
                                     "icmp4.type = 3; "
                                     "icmp4.code = 3; "
                                     "next; };";
                ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                          80, ds_cstr(match), action, NULL,
                                          copp_meter_get(
                                              COPP_ICMP4_ERR,
                                              op->od->nbr->copp,
                                              meter_groups),
                                          &op->nbrp->header_);

                ds_clear(match);
                ds_put_format(match,
                              "ip4 && ip4.dst == %s && !ip.later_frag && tcp",
                              op->lrp_networks.ipv4_addrs[i].addr_s);
                action = "tcp_reset {"
                         "eth.dst <-> eth.src; "
                         "ip4.dst <-> ip4.src; "
                         "next; };";
                ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                          80, ds_cstr(match), action, NULL,
                                          copp_meter_get(
                                              COPP_TCP_RESET,
                                              op->od->nbr->copp,
                                              meter_groups),
                                          &op->nbrp->header_);

                ds_clear(match);
                ds_put_format(match,
                              "ip4 && ip4.dst == %s && !ip.later_frag && sctp",
                              op->lrp_networks.ipv4_addrs[i].addr_s);
                action = "sctp_abort {"
                         "eth.dst <-> eth.src; "
                         "ip4.dst <-> ip4.src; "
                         "next; };";
                ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                          80, ds_cstr(match), action, NULL,
                                          copp_meter_get(
                                              COPP_TCP_RESET,
                                              op->od->nbr->copp,
                                              meter_groups),
                                          &op->nbrp->header_);

                ds_clear(match);
                ds_put_format(match,
                              "ip4 && ip4.dst == %s && !ip.later_frag",
                              op->lrp_networks.ipv4_addrs[i].addr_s);
                action = "icmp4 {"
                         "eth.dst <-> eth.src; "
                         "ip4.dst <-> ip4.src; "
                         "ip.ttl = 255; "
                         "icmp4.type = 3; "
                         "icmp4.code = 2; "
                         "next; };";
                ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                          70, ds_cstr(match), action, NULL,
                                          copp_meter_get(
                                              COPP_ICMP4_ERR,
                                              op->od->nbr->copp,
                                              meter_groups),
                                          &op->nbrp->header_);
            }
        }

        /* Drop IP traffic destined to router owned IPs except if the IP is
         * also a SNAT IP. Those are dropped later, in stage
         * "lr_in_arp_resolve", if unSNAT was unsuccessful.
         *
         * If op->od->lb_force_snat_router_ip is true, it means the IP of the
         * router port is also SNAT IP.
         *
         * Priority 60.
         */
        if (!op->od->lb_force_snat_router_ip) {
            build_lrouter_drop_own_dest(op, S_ROUTER_IN_IP_INPUT, 60, false,
                                        lflows);
        }
        /* ARP / ND handling for external IP addresses.
         *
         * DNAT and SNAT IP addresses are external IP addresses that need ARP
         * handling.
         *
         * These are already taken care globally, per router. The only
         * exception is on the l3dgw_port where we might need to use a
         * different ETH address.
         */
        if (!is_l3dgw_port(op)) {
            return;
        }

        for (size_t i = 0; i < op->od->nbr->n_nat; i++) {
            struct ovn_nat *nat_entry = &op->od->nat_entries[i];

            /* Skip entries we failed to parse. */
            if (!nat_entry_is_valid(nat_entry)) {
                continue;
            }

            /* Skip SNAT entries for now, we handle unique SNAT IPs separately
             * below.
             */
            if (!strcmp(nat_entry->nb->type, "snat")) {
                continue;
            }
            build_lrouter_port_nat_arp_nd_flow(op, nat_entry, lflows,
                                               meter_groups);
        }

        /* Now handle SNAT entries too, one per unique SNAT IP. */
        struct shash_node *snat_snode;
        SHASH_FOR_EACH (snat_snode, &op->od->snat_ips) {
            struct ovn_snat_ip *snat_ip = snat_snode->data;

            if (ovs_list_is_empty(&snat_ip->snat_entries)) {
                continue;
            }

            struct ovn_nat *nat_entry =
                CONTAINER_OF(ovs_list_front(&snat_ip->snat_entries),
                             struct ovn_nat, ext_addr_list_node);
            build_lrouter_port_nat_arp_nd_flow(op, nat_entry, lflows,
                                               meter_groups);
        }
    }
}

static void
build_lrouter_in_unsnat_flow(struct hmap *lflows, struct ovn_datapath *od,
                             const struct nbrec_nat *nat, struct ds *match,
                             struct ds *actions, bool distributed, bool is_v6,
                             struct ovn_port *l3dgw_port)
{
    /* Ingress UNSNAT table: It is for already established connections'
    * reverse traffic. i.e., SNAT has already been done in egress
    * pipeline and now the packet has entered the ingress pipeline as
    * part of a reply. We undo the SNAT here.
    *
    * Undoing SNAT has to happen before DNAT processing.  This is
    * because when the packet was DNATed in ingress pipeline, it did
    * not know about the possibility of eventual additional SNAT in
    * egress pipeline. */
    if (strcmp(nat->type, "snat") && strcmp(nat->type, "dnat_and_snat")) {
        return;
    }

    bool stateless = lrouter_nat_is_stateless(nat);
    if (od->is_gw_router) {
        ds_clear(match);
        ds_clear(actions);
        ds_put_format(match, "ip && ip%s.dst == %s",
                      is_v6 ? "6" : "4", nat->external_ip);
        if (!strcmp(nat->type, "dnat_and_snat") && stateless) {
            ds_put_format(actions, "next;");
        } else {
            ds_put_cstr(actions, "ct_snat;");
        }

        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_UNSNAT,
                                90, ds_cstr(match), ds_cstr(actions),
                                &nat->header_);
    } else {
        /* Distributed router. */

        /* Traffic received on l3dgw_port is subject to NAT. */
        ds_clear(match);
        ds_clear(actions);
        ds_put_format(match, "ip && ip%s.dst == %s && inport == %s && "
                      "flags.loopback == 0", is_v6 ? "6" : "4",
                      nat->external_ip, l3dgw_port->json_key);
        if (!distributed && od->n_l3dgw_ports) {
            /* Flows for NAT rules that are centralized are only
            * programmed on the gateway chassis. */
            ds_put_format(match, " && is_chassis_resident(%s)",
                          l3dgw_port->cr_port->json_key);
        }

        if (!strcmp(nat->type, "dnat_and_snat") && stateless) {
            ds_put_format(actions, "next;");
        } else {
            ds_put_cstr(actions, "ct_snat_in_czone;");
        }

        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_UNSNAT,
                                100, ds_cstr(match), ds_cstr(actions),
                                &nat->header_);

        if (!stateless) {
            ds_clear(match);
            ds_clear(actions);
            ds_put_format(match, "ip && ip%s.dst == %s && inport == %s && "
                          "flags.loopback == 1 && flags.use_snat_zone == 1",
                          is_v6 ? "6" : "4", nat->external_ip,
                          l3dgw_port->json_key);
            if (!distributed && od->n_l3dgw_ports) {
                /* Flows for NAT rules that are centralized are only
                * programmed on the gateway chassis. */
                ds_put_format(match, " && is_chassis_resident(%s)",
                            l3dgw_port->cr_port->json_key);
            }
            ds_put_cstr(actions, "ct_snat;");
            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_UNSNAT,
                                    100, ds_cstr(match), ds_cstr(actions),
                                    &nat->header_);
        }
    }
}

static void
build_lrouter_in_dnat_flow(struct hmap *lflows, struct ovn_datapath *od,
                           const struct nbrec_nat *nat, struct ds *match,
                           struct ds *actions, bool distributed,
                           int cidr_bits, bool is_v6,
                           struct ovn_port *l3dgw_port)
{
    /* Ingress DNAT table: Packets enter the pipeline with destination
    * IP address that needs to be DNATted from a external IP address
    * to a logical IP address. */
    if (!strcmp(nat->type, "dnat") || !strcmp(nat->type, "dnat_and_snat")) {
        bool stateless = lrouter_nat_is_stateless(nat);

        if (od->is_gw_router) {
            /* Packet when it goes from the initiator to destination.
             * We need to set flags.loopback because the router can
             * send the packet back through the same interface. */
            ds_clear(match);
            ds_put_format(match, "ip && ip%s.dst == %s",
                          is_v6 ? "6" : "4", nat->external_ip);
            ds_clear(actions);
            if (nat->allowed_ext_ips || nat->exempted_ext_ips) {
                lrouter_nat_add_ext_ip_match(od, lflows, match, nat,
                                             is_v6, true, cidr_bits);
            }

            if (!lport_addresses_is_empty(&od->dnat_force_snat_addrs)) {
                /* Indicate to the future tables that a DNAT has taken
                 * place and a force SNAT needs to be done in the
                 * Egress SNAT table. */
                ds_put_format(actions, "flags.force_snat_for_dnat = 1; ");
            }

            if (!strcmp(nat->type, "dnat_and_snat") && stateless) {
                ds_put_format(actions, "flags.loopback = 1; "
                              "ip%s.dst=%s; next;",
                              is_v6 ? "6" : "4", nat->logical_ip);
            } else {
                ds_put_format(actions, "flags.loopback = 1; ct_dnat(%s",
                              nat->logical_ip);

                if (nat->external_port_range[0]) {
                    ds_put_format(actions, ",%s", nat->external_port_range);
                }
                ds_put_format(actions, ");");
            }

            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DNAT, 100,
                                    ds_cstr(match), ds_cstr(actions),
                                    &nat->header_);
        } else {
            /* Distributed router. */

            /* Traffic received on l3dgw_port is subject to NAT. */
            ds_clear(match);
            ds_put_format(match, "ip && ip%s.dst == %s && inport == %s",
                          is_v6 ? "6" : "4", nat->external_ip,
                          l3dgw_port->json_key);
            if (!distributed && od->n_l3dgw_ports) {
                /* Flows for NAT rules that are centralized are only
                * programmed on the gateway chassis. */
                ds_put_format(match, " && is_chassis_resident(%s)",
                              l3dgw_port->cr_port->json_key);
            }
            ds_clear(actions);
            if (nat->allowed_ext_ips || nat->exempted_ext_ips) {
                lrouter_nat_add_ext_ip_match(od, lflows, match, nat,
                                             is_v6, true, cidr_bits);
            }

            if (!strcmp(nat->type, "dnat_and_snat") && stateless) {
                ds_put_format(actions, "ip%s.dst=%s; next;",
                              is_v6 ? "6" : "4", nat->logical_ip);
            } else {
                ds_put_format(actions, "ct_dnat_in_czone(%s", nat->logical_ip);
                if (nat->external_port_range[0]) {
                    ds_put_format(actions, ",%s", nat->external_port_range);
                }
                ds_put_format(actions, ");");
            }

            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DNAT, 100,
                                    ds_cstr(match), ds_cstr(actions),
                                    &nat->header_);
        }
    }
}

static void
build_lrouter_out_undnat_flow(struct hmap *lflows, struct ovn_datapath *od,
                              const struct nbrec_nat *nat, struct ds *match,
                              struct ds *actions, bool distributed,
                              struct eth_addr mac, bool is_v6,
                              struct ovn_port *l3dgw_port)
{
    /* Egress UNDNAT table: It is for already established connections'
    * reverse traffic. i.e., DNAT has already been done in ingress
    * pipeline and now the packet has entered the egress pipeline as
    * part of a reply. We undo the DNAT here.
    *
    * Note that this only applies for NAT on a distributed router.
    */
    if (!od->n_l3dgw_ports ||
        (strcmp(nat->type, "dnat") && strcmp(nat->type, "dnat_and_snat"))) {
        return;
    }

    ds_clear(match);
    ds_put_format(match, "ip && ip%s.src == %s && outport == %s",
                  is_v6 ? "6" : "4", nat->logical_ip,
                  l3dgw_port->json_key);
    if (!distributed && od->n_l3dgw_ports) {
        /* Flows for NAT rules that are centralized are only
        * programmed on the gateway chassis. */
        ds_put_format(match, " && is_chassis_resident(%s)",
                      l3dgw_port->cr_port->json_key);
    }
    ds_clear(actions);
    if (distributed) {
        ds_put_format(actions, "eth.src = "ETH_ADDR_FMT"; ",
                      ETH_ADDR_ARGS(mac));
    }

    if (!strcmp(nat->type, "dnat_and_snat") &&
        lrouter_nat_is_stateless(nat)) {
        ds_put_format(actions, "next;");
    } else {
        ds_put_format(actions,
                      od->is_gw_router ? "ct_dnat;" : "ct_dnat_in_czone;");
    }

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_UNDNAT, 100,
                            ds_cstr(match), ds_cstr(actions),
                            &nat->header_);
}

static void
build_lrouter_out_is_dnat_local(struct hmap *lflows, struct ovn_datapath *od,
                                const struct nbrec_nat *nat, struct ds *match,
                                struct ds *actions, bool distributed,
                                bool is_v6, struct ovn_port *l3dgw_port)
{
    /* Note that this only applies for NAT on a distributed router.
     */
    if (!od->n_l3dgw_ports) {
        return;
    }

    ds_clear(match);
    ds_put_format(match, "ip && ip%s.dst == %s && ",
                  is_v6 ? "6" : "4", nat->external_ip);
    if (distributed) {
        ds_put_format(match, "is_chassis_resident(\"%s\")", nat->logical_port);
    } else {
        ds_put_format(match, "is_chassis_resident(%s)",
                      l3dgw_port->cr_port->json_key);
    }

    ds_clear(actions);
    ds_put_cstr(actions, REGBIT_DST_NAT_IP_LOCAL" = 1; next;");

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_CHECK_DNAT_LOCAL,
                            50, ds_cstr(match), ds_cstr(actions),
                            &nat->header_);
}

static void
build_lrouter_out_snat_flow(struct hmap *lflows, struct ovn_datapath *od,
                            const struct nbrec_nat *nat, struct ds *match,
                            struct ds *actions, bool distributed,
                            struct eth_addr mac, int cidr_bits, bool is_v6,
                            struct ovn_port *l3dgw_port)
{
    /* Egress SNAT table: Packets enter the egress pipeline with
    * source ip address that needs to be SNATted to a external ip
    * address. */
    if (strcmp(nat->type, "snat") && strcmp(nat->type, "dnat_and_snat")) {
        return;
    }

    bool stateless = lrouter_nat_is_stateless(nat);
    if (od->is_gw_router) {
        ds_clear(match);
        ds_put_format(match, "ip && ip%s.src == %s",
                      is_v6 ? "6" : "4", nat->logical_ip);
        ds_clear(actions);

        if (nat->allowed_ext_ips || nat->exempted_ext_ips) {
            lrouter_nat_add_ext_ip_match(od, lflows, match, nat,
                                         is_v6, false, cidr_bits);
        }

        if (!strcmp(nat->type, "dnat_and_snat") && stateless) {
            ds_put_format(actions, "ip%s.src=%s; next;",
                          is_v6 ? "6" : "4", nat->external_ip);
        } else {
            ds_put_format(match, " && (!ct.trk || !ct.rpl)");
            ds_put_format(actions, "ct_snat(%s", nat->external_ip);

            if (nat->external_port_range[0]) {
                ds_put_format(actions, ",%s",
                              nat->external_port_range);
            }
            ds_put_format(actions, ");");
        }

        /* The priority here is calculated such that the
        * nat->logical_ip with the longest mask gets a higher
        * priority. */
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_SNAT,
                                cidr_bits + 1, ds_cstr(match),
                                ds_cstr(actions), &nat->header_);
    } else {
        uint16_t priority = cidr_bits + 1;

        /* Distributed router. */
        ds_clear(match);
        ds_put_format(match, "ip && ip%s.src == %s && outport == %s",
                      is_v6 ? "6" : "4", nat->logical_ip,
                      l3dgw_port->json_key);
        if (od->n_l3dgw_ports) {
            if (distributed) {
                ovs_assert(nat->logical_port);
                priority += 128;
                ds_put_format(match, " && is_chassis_resident(\"%s\")",
                              nat->logical_port);
            } else {
                /* Flows for NAT rules that are centralized are only
                * programmed on the gateway chassis. */
                priority += 128;
                ds_put_format(match, " && is_chassis_resident(%s)",
                              l3dgw_port->cr_port->json_key);
            }
        }
        ds_clear(actions);

        if (nat->allowed_ext_ips || nat->exempted_ext_ips) {
            lrouter_nat_add_ext_ip_match(od, lflows, match, nat,
                                         is_v6, false, cidr_bits);
        }

        if (distributed) {
            ds_put_format(actions, "eth.src = "ETH_ADDR_FMT"; ",
                          ETH_ADDR_ARGS(mac));
        }

        if (!strcmp(nat->type, "dnat_and_snat") && stateless) {
            ds_put_format(actions, "ip%s.src=%s; next;",
                          is_v6 ? "6" : "4", nat->external_ip);
        } else {
            ds_put_format(actions, "ct_snat_in_czone(%s",
                        nat->external_ip);
            if (nat->external_port_range[0]) {
                ds_put_format(actions, ",%s", nat->external_port_range);
            }
            ds_put_format(actions, ");");
        }

        /* The priority here is calculated such that the
        * nat->logical_ip with the longest mask gets a higher
        * priority. */
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_SNAT,
                                priority, ds_cstr(match),
                                ds_cstr(actions), &nat->header_);

        if (!stateless) {
            ds_put_cstr(match, " && "REGBIT_DST_NAT_IP_LOCAL" == 1");
            ds_clear(actions);
            if (distributed) {
                ds_put_format(actions, "eth.src = "ETH_ADDR_FMT"; ",
                              ETH_ADDR_ARGS(mac));
            }
            ds_put_format(actions,  REGBIT_DST_NAT_IP_LOCAL" = 0; ct_snat(%s",
                          nat->external_ip);
            if (nat->external_port_range[0]) {
                ds_put_format(actions, ",%s", nat->external_port_range);
            }
            ds_put_format(actions, ");");
            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_SNAT,
                                    priority + 1, ds_cstr(match),
                                    ds_cstr(actions), &nat->header_);
        }
    }
}

static void
build_lrouter_ingress_nat_check_pkt_len(struct hmap *lflows,
                                        const struct nbrec_nat *nat,
                                        struct ovn_datapath *od, bool is_v6,
                                        struct ds *match, struct ds *actions,
                                        int mtu, struct ovn_port *l3dgw_port,
                                        const struct shash *meter_groups)
{
        ds_clear(match);
        ds_put_format(match, "inport == %s && "REGBIT_PKT_LARGER
                      " && "REGBIT_EGRESS_LOOPBACK" == 0",
                      l3dgw_port->json_key);

        ds_clear(actions);
        if (!is_v6) {
            ds_put_format(match, " && ip4 && ip4.dst == %s", nat->external_ip);
            /* Set icmp4.frag_mtu to gw_mtu */
            ds_put_format(actions,
                "icmp4_error {"
                REGBIT_EGRESS_LOOPBACK" = 1; "
                REGBIT_PKT_LARGER" = 0; "
                "eth.dst = eth.src; "
                "eth.src = %s; "
                "ip4.dst = ip4.src; "
                "ip4.src = %s; "
                "ip.ttl = 254; "
                "icmp4.type = 3; /* Destination Unreachable. */ "
                "icmp4.code = 4; /* Frag Needed and DF was Set. */ "
                "icmp4.frag_mtu = %d; "
                "outport = %s; flags.loopback = 1; output; };",
                nat->external_mac,
                nat->external_ip,
                mtu, l3dgw_port->json_key);
            ovn_lflow_add_with_hint__(lflows, od, S_ROUTER_IN_IP_INPUT, 160,
                                      ds_cstr(match), ds_cstr(actions),
                                      NULL,
                                      copp_meter_get(
                                            COPP_ICMP4_ERR,
                                            od->nbr->copp,
                                            meter_groups),
                                      &nat->header_);
        } else {
            ds_put_format(match, " && ip6 && ip6.dst == %s", nat->external_ip);
            /* Set icmp6.frag_mtu to gw_mtu */
            ds_put_format(actions,
                "icmp6_error {"
                REGBIT_EGRESS_LOOPBACK" = 1; "
                REGBIT_PKT_LARGER" = 0; "
                "eth.dst = eth.src; "
                "eth.src = %s; "
                "ip6.dst = ip6.src; "
                "ip6.src = %s; "
                "ip.ttl = 254; "
                "icmp6.type = 2; /* Packet Too Big. */ "
                "icmp6.code = 0; "
                "icmp6.frag_mtu = %d; "
                "outport = %s; flags.loopback = 1; output; };",
                nat->external_mac,
                nat->external_ip,
                mtu, l3dgw_port->json_key);
            ovn_lflow_add_with_hint__(lflows, od, S_ROUTER_IN_IP_INPUT, 160,
                                      ds_cstr(match), ds_cstr(actions),
                                      NULL,
                                      copp_meter_get(
                                            COPP_ICMP6_ERR,
                                            od->nbr->copp,
                                            meter_groups),
                                      &nat->header_);
        }
}

static void
build_lrouter_ingress_flow(struct hmap *lflows, struct ovn_datapath *od,
                           const struct nbrec_nat *nat, struct ds *match,
                           struct ds *actions, struct eth_addr mac,
                           bool distributed, bool is_v6,
                           struct ovn_port *l3dgw_port,
                           const struct shash *meter_groups)
{
    if (od->n_l3dgw_ports && !strcmp(nat->type, "snat")) {
        ds_clear(match);
        ds_put_format(
            match, "inport == %s && %s == %s",
            l3dgw_port->json_key,
            is_v6 ? "ip6.src" : "ip4.src", nat->external_ip);
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_IP_INPUT,
                                120, ds_cstr(match), "next;",
                                &nat->header_);
    }
    /* Logical router ingress table 0:
    * For NAT on a distributed router, add rules allowing
    * ingress traffic with eth.dst matching nat->external_mac
    * on the l3dgw_port instance where nat->logical_port is
    * resident. */
    if (distributed) {
        /* Store the ethernet address of the port receiving the packet.
        * This will save us from having to match on inport further
        * down in the pipeline.
        */
        int gw_mtu = smap_get_int(&l3dgw_port->nbrp->options,
                                  "gateway_mtu", 0);
        ds_clear(match);
        ds_put_format(match,
                      "eth.dst == "ETH_ADDR_FMT" && inport == %s"
                      " && is_chassis_resident(\"%s\")",
                      ETH_ADDR_ARGS(mac),
                      l3dgw_port->json_key,
                      nat->logical_port);
        build_gateway_mtu_flow(lflows, l3dgw_port,
                               S_ROUTER_IN_ADMISSION, 50, 55,
                               match, actions, &nat->header_,
                               REG_INPORT_ETH_ADDR " = %s; next;",
                               l3dgw_port->lrp_networks.ea_s);
        if (gw_mtu) {
            build_lrouter_ingress_nat_check_pkt_len(lflows, nat, od, is_v6,
                                                    match, actions, gw_mtu,
                                                    l3dgw_port, meter_groups);
        }
    }
}

static int
lrouter_check_nat_entry(struct ovn_datapath *od, const struct nbrec_nat *nat,
                        const struct hmap *ports, ovs_be32 *mask,
                        bool *is_v6, int *cidr_bits, struct eth_addr *mac,
                        bool *distributed, struct ovn_port **nat_l3dgw_port)
{
    struct in6_addr ipv6, mask_v6, v6_exact = IN6ADDR_EXACT_INIT;
    ovs_be32 ip;

    if (nat->allowed_ext_ips && nat->exempted_ext_ips) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "NAT rule: "UUID_FMT" not applied, since "
                    "both allowed and exempt external ips set",
                    UUID_ARGS(&(nat->header_.uuid)));
        return -EINVAL;
    }

    char *error = ip_parse_masked(nat->external_ip, &ip, mask);
    *is_v6 = false;

    if (error || *mask != OVS_BE32_MAX) {
        free(error);
        error = ipv6_parse_masked(nat->external_ip, &ipv6, &mask_v6);
        if (error || memcmp(&mask_v6, &v6_exact, sizeof(mask_v6))) {
            /* Invalid for both IPv4 and IPv6 */
            static struct vlog_rate_limit rl =
                VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad external ip %s for nat",
                        nat->external_ip);
            free(error);
            return -EINVAL;
        }
        /* It was an invalid IPv4 address, but valid IPv6.
        * Treat the rest of the handling of this NAT rule
        * as IPv6. */
        *is_v6 = true;
    }

    /* Validate gateway_port of NAT rule. */
    *nat_l3dgw_port = NULL;
    if (nat->gateway_port == NULL) {
        if (od->n_l3dgw_ports == 1) {
            *nat_l3dgw_port = od->l3dgw_ports[0];
        } else if (od->n_l3dgw_ports > 1) {
            /* Find the DGP reachable for the NAT external IP. */
            for (size_t i = 0; i < od->n_l3dgw_ports; i++) {
               if (find_lrp_member_ip(od->l3dgw_ports[i], nat->external_ip)) {
                   *nat_l3dgw_port = od->l3dgw_ports[i];
                   break;
               }
            }
            if (*nat_l3dgw_port == NULL) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "Unable to determine gateway_port for NAT "
                             "with external_ip: %s configured on logical "
                             "router: %s with multiple distributed gateway "
                             "ports", nat->external_ip, od->nbr->name);
                return -EINVAL;
            }
        }
    } else {
        *nat_l3dgw_port = ovn_port_find(ports, nat->gateway_port->name);

        if (!(*nat_l3dgw_port) || (*nat_l3dgw_port)->od != od ||
            !is_l3dgw_port(*nat_l3dgw_port)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "gateway_port: %s of NAT configured on "
                         "logical router: %s is not a valid distributed "
                         "gateway port on that router",
                         nat->gateway_port->name, od->nbr->name);
            return -EINVAL;
        }
    }

    /* Check the validity of nat->logical_ip. 'logical_ip' can
    * be a subnet when the type is "snat". */
    if (*is_v6) {
        error = ipv6_parse_masked(nat->logical_ip, &ipv6, &mask_v6);
        *cidr_bits = ipv6_count_cidr_bits(&mask_v6);
    } else {
        error = ip_parse_masked(nat->logical_ip, &ip, mask);
        *cidr_bits = ip_count_cidr_bits(*mask);
    }
    if (!strcmp(nat->type, "snat")) {
        if (error) {
            /* Invalid for both IPv4 and IPv6 */
            static struct vlog_rate_limit rl =
                VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad ip network or ip %s for snat "
                        "in router "UUID_FMT"",
                        nat->logical_ip, UUID_ARGS(&od->key));
            free(error);
            return -EINVAL;
        }
    } else {
        if (error || (*is_v6 == false && *mask != OVS_BE32_MAX)
            || (*is_v6 && memcmp(&mask_v6, &v6_exact,
                                sizeof mask_v6))) {
            /* Invalid for both IPv4 and IPv6 */
            static struct vlog_rate_limit rl =
                VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad ip %s for dnat in router "
                ""UUID_FMT"", nat->logical_ip, UUID_ARGS(&od->key));
            free(error);
            return -EINVAL;
        }
    }

    /* For distributed router NAT, determine whether this NAT rule
     * satisfies the conditions for distributed NAT processing. */
    *distributed = false;
    if (od->n_l3dgw_ports && !strcmp(nat->type, "dnat_and_snat") &&
        nat->logical_port && nat->external_mac) {
        if (eth_addr_from_string(nat->external_mac, mac)) {
            *distributed = true;
        } else {
            static struct vlog_rate_limit rl =
                VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad mac %s for dnat in router "
                ""UUID_FMT"", nat->external_mac, UUID_ARGS(&od->key));
            return -EINVAL;
        }
    }

    return 0;
}

/* NAT, Defrag and load balancing. */
static void
build_lrouter_nat_defrag_and_lb(struct ovn_datapath *od, struct hmap *lflows,
                                const struct hmap *ports, struct ds *match,
                                struct ds *actions,
                                const struct shash *meter_groups,
                                bool ct_lb_mark)
{
    if (!od->nbr) {
        return;
    }

    /* Packets are allowed by default. */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_DEFRAG, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_ROUTER_IN_UNSNAT, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_CHECK_DNAT_LOCAL, 0, "1",
                  REGBIT_DST_NAT_IP_LOCAL" = 0; next;");
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_SNAT, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_UNDNAT, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_POST_UNDNAT, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_POST_SNAT, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_EGR_LOOP, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_ROUTER_IN_ECMP_STATEFUL, 0, "1", "next;");

    /* Ingress DNAT Table (Priority 50).
     *
     * Allow traffic that is related to an existing conntrack entry.
     * At the same time apply NAT for this traffic.
     *
     * NOTE: This does not support related data sessions (eg,
     * a dynamically negotiated FTP data channel), but will allow
     * related traffic such as an ICMP Port Unreachable through
     * that's generated from a non-listening UDP port.  */
    if (od->has_lb_vip) {
        ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT, 50,
                      "ct.rel && !ct.est && !ct.new", "ct_commit_nat;");
    }

    /* If the router has load balancer or DNAT rules, re-circulate every packet
     * through the DNAT zone so that packets that need to be unDNATed in the
     * reverse direction get unDNATed.
     *
     * We also commit newly initiated connections in the reply direction to the
     * DNAT zone. This ensures that these flows are tracked. If the flow was
     * not committed, it would produce ongoing datapath flows with the ct.new
     * flag set. Some NICs are unable to offload these flows.
     */
    if (od->is_gw_router && (od->nbr->n_nat || od->has_lb_vip)) {
        ovn_lflow_add(lflows, od, S_ROUTER_OUT_UNDNAT, 50,
                      "ip", "flags.loopback = 1; ct_dnat;");
        ovn_lflow_add(lflows, od, S_ROUTER_OUT_POST_UNDNAT, 50,
                      "ip && ct.new", "ct_commit { } ; next; ");
    }

    /* Send the IPv6 NS packets to next table. When ovn-controller
     * generates IPv6 NS (for the action - nd_ns{}), the injected
     * packet would go through conntrack - which is not required. */
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_SNAT, 120, "nd_ns", "next;");

    /* NAT rules are only valid on Gateway routers and routers with
     * l3dgw_ports (router has port(s) with gateway chassis
     * specified). */
    if (!od->is_gw_router && !od->n_l3dgw_ports) {
        return;
    }

    struct sset nat_entries = SSET_INITIALIZER(&nat_entries);

    bool dnat_force_snat_ip =
        !lport_addresses_is_empty(&od->dnat_force_snat_addrs);
    bool lb_force_snat_ip =
        !lport_addresses_is_empty(&od->lb_force_snat_addrs);

    for (int i = 0; i < od->nbr->n_nat; i++) {
        const struct nbrec_nat *nat = nat = od->nbr->nat[i];
        struct eth_addr mac = eth_addr_broadcast;
        bool is_v6, distributed;
        ovs_be32 mask;
        int cidr_bits;
        struct ovn_port *l3dgw_port;

        if (lrouter_check_nat_entry(od, nat, ports, &mask, &is_v6, &cidr_bits,
                                    &mac, &distributed, &l3dgw_port) < 0) {
            continue;
        }

        /* S_ROUTER_IN_UNSNAT */
        build_lrouter_in_unsnat_flow(lflows, od, nat, match, actions, distributed,
                                     is_v6, l3dgw_port);
        /* S_ROUTER_IN_DNAT */
        build_lrouter_in_dnat_flow(lflows, od, nat, match, actions, distributed,
                                   cidr_bits, is_v6, l3dgw_port);

        /* ARP resolve for NAT IPs. */
        if (od->is_gw_router) {
            /* Add the NAT external_ip to the nat_entries for
             * gateway routers. This is required for adding load balancer
             * flows.*/
            sset_add(&nat_entries, nat->external_ip);
        } else {
            if (!sset_contains(&nat_entries, nat->external_ip)) {
                ds_clear(match);
                ds_put_format(
                    match, "outport == %s && %s == %s",
                    l3dgw_port->json_key,
                    is_v6 ? REG_NEXT_HOP_IPV6 : REG_NEXT_HOP_IPV4,
                    nat->external_ip);
                ds_clear(actions);
                ds_put_format(
                    actions, "eth.dst = %s; next;",
                    distributed ? nat->external_mac :
                    l3dgw_port->lrp_networks.ea_s);
                ovn_lflow_add_with_hint(lflows, od,
                                        S_ROUTER_IN_ARP_RESOLVE,
                                        100, ds_cstr(match),
                                        ds_cstr(actions),
                                        &nat->header_);
                if (od->redirect_bridged && distributed) {
                    ds_clear(match);
                    ds_put_format(
                            match,
                            "outport == %s && ip%s.src == %s "
                            "&& is_chassis_resident(\"%s\")",
                            od->l3dgw_ports[0]->json_key,
                            is_v6 ? "6" : "4", nat->logical_ip,
                            nat->logical_port);
                    ds_clear(actions);
                    if (is_v6) {
                        ds_put_cstr(actions,
                            "get_nd(outport, " REG_NEXT_HOP_IPV6 "); next;");
                    } else {
                        ds_put_cstr(actions,
                            "get_arp(outport, " REG_NEXT_HOP_IPV4 "); next;");
                    }
                    ovn_lflow_add_with_hint(lflows, od,
                                            S_ROUTER_IN_ARP_RESOLVE, 90,
                                            ds_cstr(match), ds_cstr(actions),
                                            &nat->header_);
                }
                sset_add(&nat_entries, nat->external_ip);
            }
        }

        /* S_ROUTER_OUT_DNAT_LOCAL */
        build_lrouter_out_is_dnat_local(lflows, od, nat, match, actions,
                                        distributed, is_v6, l3dgw_port);

        /* S_ROUTER_OUT_UNDNAT */
        build_lrouter_out_undnat_flow(lflows, od, nat, match, actions, distributed,
                                      mac, is_v6, l3dgw_port);
        /* S_ROUTER_OUT_SNAT */
        build_lrouter_out_snat_flow(lflows, od, nat, match, actions, distributed,
                                    mac, cidr_bits, is_v6, l3dgw_port);

        /* S_ROUTER_IN_ADMISSION - S_ROUTER_IN_IP_INPUT */
        build_lrouter_ingress_flow(lflows, od, nat, match, actions, mac,
                                   distributed, is_v6, l3dgw_port,
                                   meter_groups);

        /* Ingress Gateway Redirect Table: For NAT on a distributed
         * router, add flows that are specific to a NAT rule.  These
         * flows indicate the presence of an applicable NAT rule that
         * can be applied in a distributed manner.
         * In particulr REG_SRC_IPV4/REG_SRC_IPV6 and eth.src are set to
         * NAT external IP and NAT external mac so the ARP request
         * generated in the following stage is sent out with proper IP/MAC
         * src addresses.
         */
        if (distributed) {
            ds_clear(match);
            ds_clear(actions);
            ds_put_format(match,
                          "ip%s.src == %s && outport == %s",
                          is_v6 ? "6" : "4", nat->logical_ip,
                          l3dgw_port->json_key);
            /* Add a rule to drop traffic from a distributed NAT if
             * the virtual port has not claimed yet becaused otherwise
             * the traffic will be centralized misconfiguring the TOR switch.
             */
            struct ovn_port *op = ovn_port_find(ports, nat->logical_port);
            if (op && op->nbsp && !strcmp(op->nbsp->type, "virtual")) {
                ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_GW_REDIRECT,
                                        80, ds_cstr(match),
                                        debug_drop_action(), &nat->header_);
            }
            ds_put_format(match, " && is_chassis_resident(\"%s\")",
                          nat->logical_port);
            ds_put_format(actions, "eth.src = %s; %s = %s; next;",
                          nat->external_mac,
                          is_v6 ? REG_SRC_IPV6 : REG_SRC_IPV4,
                          nat->external_ip);
            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_GW_REDIRECT,
                                    100, ds_cstr(match),
                                    ds_cstr(actions), &nat->header_);
        }

        /* Egress Loopback table: For NAT on a distributed router.
         * If packets in the egress pipeline on the distributed
         * gateway port have ip.dst matching a NAT external IP, then
         * loop a clone of the packet back to the beginning of the
         * ingress pipeline with inport = outport. */
        if (od->n_l3dgw_ports) {
            /* Distributed router. */
            ds_clear(match);
            ds_put_format(match, "ip%s.dst == %s && outport == %s",
                          is_v6 ? "6" : "4",
                          nat->external_ip,
                          l3dgw_port->json_key);
            if (!distributed) {
                ds_put_format(match, " && is_chassis_resident(%s)",
                              l3dgw_port->cr_port->json_key);
            } else {
                ds_put_format(match, " && is_chassis_resident(\"%s\")",
                              nat->logical_port);
            }

            ds_clear(actions);
            ds_put_format(actions,
                          "clone { ct_clear; "
                          "inport = outport; outport = \"\"; "
                          "eth.dst <-> eth.src; "
                          "flags = 0; flags.loopback = 1; "
                          "flags.use_snat_zone = "REGBIT_DST_NAT_IP_LOCAL"; ");
            for (int j = 0; j < MFF_N_LOG_REGS; j++) {
                ds_put_format(actions, "reg%d = 0; ", j);
            }
            ds_put_format(actions, REGBIT_EGRESS_LOOPBACK" = 1; "
                          "next(pipeline=ingress, table=%d); };",
                          ovn_stage_get_table(S_ROUTER_IN_ADMISSION));
            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_EGR_LOOP, 100,
                                    ds_cstr(match), ds_cstr(actions),
                                    &nat->header_);
        }
    }

    if (od->nbr->n_nat) {
        ds_clear(match);
        const char *ct_natted = ct_lb_mark ?
                                "ct_mark.natted" :
                                "ct_label.natted";
        ds_put_format(match, "ip && %s == 1", ct_natted);
        /* This flow is unique since it is in the egress pipeline but checks
         * the value of ct_label.natted, which would have been set in the
         * ingress pipeline. If a change is ever introduced that clears or
         * otherwise invalidates the ct_label between the ingress and egress
         * pipelines, then an alternative will need to be devised.
         */
        ds_clear(actions);
        ds_put_cstr(actions, REGBIT_DST_NAT_IP_LOCAL" = 1; next;");
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_CHECK_DNAT_LOCAL,
                                50, ds_cstr(match), ds_cstr(actions),
                                &od->nbr->header_);

    }

    /* Handle force SNAT options set in the gateway router. */
    if (od->is_gw_router) {
        if (dnat_force_snat_ip) {
            if (od->dnat_force_snat_addrs.n_ipv4_addrs) {
                build_lrouter_force_snat_flows(lflows, od, "4",
                    od->dnat_force_snat_addrs.ipv4_addrs[0].addr_s,
                    "dnat");
            }
            if (od->dnat_force_snat_addrs.n_ipv6_addrs) {
                build_lrouter_force_snat_flows(lflows, od, "6",
                    od->dnat_force_snat_addrs.ipv6_addrs[0].addr_s,
                    "dnat");
            }
        }
        if (lb_force_snat_ip) {
            if (od->lb_force_snat_addrs.n_ipv4_addrs) {
                build_lrouter_force_snat_flows(lflows, od, "4",
                    od->lb_force_snat_addrs.ipv4_addrs[0].addr_s, "lb");
            }
            if (od->lb_force_snat_addrs.n_ipv6_addrs) {
                build_lrouter_force_snat_flows(lflows, od, "6",
                    od->lb_force_snat_addrs.ipv6_addrs[0].addr_s, "lb");
            }
        }
    }

    sset_destroy(&nat_entries);
}



struct lswitch_flow_build_info {
    const struct hmap *datapaths;
    const struct hmap *ports;
    const struct hmap *port_groups;
    struct hmap *lflows;
    struct hmap *mcgroups;
    struct hmap *igmp_groups;
    const struct shash *meter_groups;
    const struct hmap *lbs;
    const struct hmap *bfd_connections;
    const struct chassis_features *features;
    char *svc_check_match;
    struct ds match;
    struct ds actions;
    size_t thread_lflow_counter;
};

/* Helper function to combine all lflow generation which is iterated by
 * datapath.
 *
 * When extending the function new "work data" must be added to the lsi
 * struct, not passed as an argument.
 */

static void
build_lswitch_and_lrouter_iterate_by_od(struct ovn_datapath *od,
                                        struct lswitch_flow_build_info *lsi)
{
    /* Build Logical Switch Flows. */
    build_lswitch_lflows_pre_acl_and_acl(od, lsi->port_groups,
                                         lsi->features,
                                         lsi->lflows,
                                         lsi->meter_groups);

    build_fwd_group_lflows(od, lsi->lflows);
    build_lswitch_lflows_admission_control(od, lsi->lflows);
    build_lswitch_learn_fdb_od(od, lsi->lflows);
    build_lswitch_arp_nd_responder_default(od, lsi->lflows);
    build_lswitch_dns_lookup_and_response(od, lsi->lflows, lsi->meter_groups);
    build_lswitch_dhcp_and_dns_defaults(od, lsi->lflows);
    build_lswitch_destination_lookup_bmcast(od, lsi->lflows, &lsi->actions,
                                            lsi->meter_groups);
    build_lswitch_output_port_sec_od(od, lsi->lflows);

    /* Build Logical Router Flows. */
    build_adm_ctrl_flows_for_lrouter(od, lsi->lflows);
    build_neigh_learning_flows_for_lrouter(od, lsi->lflows, &lsi->match,
                                           &lsi->actions, lsi->meter_groups);
    build_ND_RA_flows_for_lrouter(od, lsi->lflows);
    build_ip_routing_pre_flows_for_lrouter(od, lsi->lflows);
    build_static_route_flows_for_lrouter(od, lsi->features,
                                         lsi->lflows, lsi->ports,
                                         lsi->bfd_connections);
    build_mcast_lookup_flows_for_lrouter(od, lsi->lflows, &lsi->match,
                                         &lsi->actions);
    build_ingress_policy_flows_for_lrouter(od, lsi->lflows, lsi->ports);
    build_arp_resolve_flows_for_lrouter(od, lsi->lflows);
    build_check_pkt_len_flows_for_lrouter(od, lsi->lflows, lsi->ports,
                                          &lsi->match, &lsi->actions,
                                          lsi->meter_groups);
    build_gateway_redirect_flows_for_lrouter(od, lsi->lflows, &lsi->match,
                                             &lsi->actions);
    build_arp_request_flows_for_lrouter(od, lsi->lflows, &lsi->match,
                                        &lsi->actions, lsi->meter_groups);
    build_misc_local_traffic_drop_flows_for_lrouter(od, lsi->lflows);
    build_lrouter_arp_nd_for_datapath(od, lsi->lflows, lsi->meter_groups);
    build_lrouter_nat_defrag_and_lb(od, lsi->lflows, lsi->ports, &lsi->match,
                                    &lsi->actions, lsi->meter_groups,
                                    lsi->features->ct_no_masked_label);
    build_lb_affinity_default_flows(od, lsi->lflows);
}

/* Helper function to combine all lflow generation which is iterated by port.
 */
static void
build_lswitch_and_lrouter_iterate_by_op(struct ovn_port *op,
                                        struct lswitch_flow_build_info *lsi)
{
    /* Build Logical Switch Flows. */
    build_lswitch_port_sec_op(op, lsi->lflows, &lsi->actions, &lsi->match);
    build_lswitch_learn_fdb_op(op, lsi->lflows, &lsi->actions,
                               &lsi->match);
    build_lswitch_arp_nd_responder_skip_local(op, lsi->lflows,
                                              &lsi->match);
    build_lswitch_arp_nd_responder_known_ips(op, lsi->lflows,
                                             lsi->ports,
                                             lsi->meter_groups,
                                             &lsi->actions,
                                             &lsi->match);
    build_lswitch_dhcp_options_and_response(op, lsi->lflows,
                                            lsi->meter_groups);
    build_lswitch_external_port(op, lsi->lflows);
    build_lswitch_ip_unicast_lookup(op, lsi->lflows, lsi->mcgroups,
                                    &lsi->actions, &lsi->match);

    /* Build Logical Router Flows. */
    build_adm_ctrl_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                          &lsi->actions);
    build_neigh_learning_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                                &lsi->actions);
    build_ip_routing_flows_for_lrouter_port(op, lsi->ports, lsi->lflows);
    build_ND_RA_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                       &lsi->actions, lsi->meter_groups);
    build_arp_resolve_flows_for_lrouter_port(op, lsi->lflows, lsi->ports,
                                             &lsi->match, &lsi->actions);
    build_egress_delivery_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                                 &lsi->actions);
    build_dhcpv6_reply_flows_for_lrouter_port(op, lsi->lflows, &lsi->match);
    build_ipv6_input_flows_for_lrouter_port(op, lsi->lflows,
                                            &lsi->match, &lsi->actions,
                                            lsi->meter_groups);
    build_lrouter_ipv4_ip_input(op, lsi->lflows,
                                &lsi->match, &lsi->actions, lsi->meter_groups);
    build_lrouter_force_snat_flows_op(op, lsi->lflows, &lsi->match,
                                      &lsi->actions);
}

static void *
build_lflows_thread(void *arg)
{
    struct worker_control *control = (struct worker_control *) arg;
    struct lswitch_flow_build_info *lsi;

    struct ovn_datapath *od;
    struct ovn_port *op;
    struct ovn_northd_lb *lb;
    struct ovn_igmp_group *igmp_group;
    int bnum;

    while (!stop_parallel_processing()) {
        wait_for_work(control);
        lsi = (struct lswitch_flow_build_info *) control->data;
        if (stop_parallel_processing()) {
            return NULL;
        }
        thread_lflow_counter = 0;
        if (lsi) {
            /* Iterate over bucket ThreadID, ThreadID+size, ... */
            for (bnum = control->id;
                    bnum <= lsi->datapaths->mask;
                    bnum += control->pool->size)
            {
                HMAP_FOR_EACH_IN_PARALLEL (od, key_node, bnum, lsi->datapaths) {
                    if (stop_parallel_processing()) {
                        return NULL;
                    }
                    build_lswitch_and_lrouter_iterate_by_od(od, lsi);
                }
            }
            for (bnum = control->id;
                    bnum <= lsi->ports->mask;
                    bnum += control->pool->size)
            {
                HMAP_FOR_EACH_IN_PARALLEL (op, key_node, bnum, lsi->ports) {
                    if (stop_parallel_processing()) {
                        return NULL;
                    }
                    build_lswitch_and_lrouter_iterate_by_op(op, lsi);
                }
            }
            for (bnum = control->id;
                    bnum <= lsi->lbs->mask;
                    bnum += control->pool->size)
            {
                HMAP_FOR_EACH_IN_PARALLEL (lb, hmap_node, bnum, lsi->lbs) {
                    if (stop_parallel_processing()) {
                        return NULL;
                    }
                    build_lswitch_arp_nd_service_monitor(lb, lsi->lflows,
                                                         &lsi->match,
                                                         &lsi->actions);
                    build_lrouter_defrag_flows_for_lb(lb, lsi->lflows,
                                                      &lsi->match);
                    build_lrouter_flows_for_lb(lb, lsi->lflows,
                                               lsi->meter_groups,
                                               lsi->features,
                                               &lsi->match, &lsi->actions);
                    build_lswitch_flows_for_lb(lb, lsi->lflows,
                                               lsi->meter_groups,
                                               lsi->features,
                                               &lsi->match, &lsi->actions);
                }
            }
            for (bnum = control->id;
                    bnum <= lsi->igmp_groups->mask;
                    bnum += control->pool->size)
            {
                HMAP_FOR_EACH_IN_PARALLEL (
                        igmp_group, hmap_node, bnum, lsi->igmp_groups) {
                    if (stop_parallel_processing()) {
                        return NULL;
                    }
                    build_lswitch_ip_mcast_igmp_mld(igmp_group, lsi->lflows,
                                                    &lsi->match,
                                                    &lsi->actions);
                }
            }
        }
        lsi->thread_lflow_counter = thread_lflow_counter;
        post_completed_work(control);
    }
    return NULL;
}

static struct worker_pool *build_lflows_pool = NULL;

static void
noop_callback(struct worker_pool *pool OVS_UNUSED,
              void *fin_result OVS_UNUSED,
              void *result_frags OVS_UNUSED,
              size_t index OVS_UNUSED)
{
    /* Do nothing */
}

/* Fixes the hmap size (hmap->n) after parallel building the lflow_map when
 * dp-groups is enabled, because in that case all threads are updating the
 * global lflow hmap. Although the lflow_hash_lock prevents currently inserting
 * to the same hash bucket, the hmap->n is updated currently by all threads and
 * may not be accurate at the end of each iteration. This function collects the
 * thread-local lflow counters maintained by each thread and update the hmap
 * size with the aggregated value. This function must be called immediately
 * after the worker threads complete the tasks in each iteration before any
 * future operations on the lflow map. */
static void
fix_flow_map_size(struct hmap *lflow_map,
                  struct lswitch_flow_build_info *lsiv,
                  size_t n_lsiv)
{
    size_t total = 0;
    for (size_t i = 0; i < n_lsiv; i++) {
        total += lsiv[i].thread_lflow_counter;
    }
    lflow_map->n = total;
}

static void
build_lswitch_and_lrouter_flows(const struct hmap *datapaths,
                                const struct hmap *ports,
                                const struct hmap *port_groups,
                                struct hmap *lflows,
                                struct hmap *mcgroups,
                                struct hmap *igmp_groups,
                                const struct shash *meter_groups,
                                const struct hmap *lbs,
                                const struct hmap *bfd_connections,
                                const struct chassis_features *features)
{

    char *svc_check_match = xasprintf("eth.dst == %s", svc_monitor_mac);

    if (parallelization_state == STATE_USE_PARALLELIZATION) {
        struct lswitch_flow_build_info *lsiv;
        int index;

        lsiv = xcalloc(sizeof(*lsiv), build_lflows_pool->size);

        /* Set up "work chunks" for each thread to work on. */

        for (index = 0; index < build_lflows_pool->size; index++) {
            /* dp_groups are in use so we lock a shared lflows hash
             * on a per-bucket level.
             */
            lsiv[index].lflows = lflows;
            lsiv[index].datapaths = datapaths;
            lsiv[index].ports = ports;
            lsiv[index].port_groups = port_groups;
            lsiv[index].mcgroups = mcgroups;
            lsiv[index].igmp_groups = igmp_groups;
            lsiv[index].meter_groups = meter_groups;
            lsiv[index].lbs = lbs;
            lsiv[index].bfd_connections = bfd_connections;
            lsiv[index].features = features;
            lsiv[index].svc_check_match = svc_check_match;
            lsiv[index].thread_lflow_counter = 0;
            ds_init(&lsiv[index].match);
            ds_init(&lsiv[index].actions);

            build_lflows_pool->controls[index].data = &lsiv[index];
        }

        /* Run thread pool. */
        run_pool_callback(build_lflows_pool, NULL, NULL, noop_callback);
        fix_flow_map_size(lflows, lsiv, build_lflows_pool->size);

        for (index = 0; index < build_lflows_pool->size; index++) {
            ds_destroy(&lsiv[index].match);
            ds_destroy(&lsiv[index].actions);
        }
        free(lsiv);
    } else {
        struct ovn_datapath *od;
        struct ovn_port *op;
        struct ovn_northd_lb *lb;
        struct ovn_igmp_group *igmp_group;
        struct lswitch_flow_build_info lsi = {
            .datapaths = datapaths,
            .ports = ports,
            .port_groups = port_groups,
            .lflows = lflows,
            .mcgroups = mcgroups,
            .igmp_groups = igmp_groups,
            .meter_groups = meter_groups,
            .lbs = lbs,
            .bfd_connections = bfd_connections,
            .features = features,
            .svc_check_match = svc_check_match,
            .match = DS_EMPTY_INITIALIZER,
            .actions = DS_EMPTY_INITIALIZER,
        };

        /* Combined build - all lflow generation from lswitch and lrouter
         * will move here and will be reogranized by iterator type.
         */
        stopwatch_start(LFLOWS_DATAPATHS_STOPWATCH_NAME, time_msec());
        HMAP_FOR_EACH (od, key_node, datapaths) {
            build_lswitch_and_lrouter_iterate_by_od(od, &lsi);
        }
        stopwatch_stop(LFLOWS_DATAPATHS_STOPWATCH_NAME, time_msec());
        stopwatch_start(LFLOWS_PORTS_STOPWATCH_NAME, time_msec());
        HMAP_FOR_EACH (op, key_node, ports) {
            build_lswitch_and_lrouter_iterate_by_op(op, &lsi);
        }
        stopwatch_stop(LFLOWS_PORTS_STOPWATCH_NAME, time_msec());
        stopwatch_start(LFLOWS_LBS_STOPWATCH_NAME, time_msec());
        HMAP_FOR_EACH (lb, hmap_node, lbs) {
            build_lswitch_arp_nd_service_monitor(lb, lsi.lflows,
                                                 &lsi.actions,
                                                 &lsi.match);
            build_lrouter_defrag_flows_for_lb(lb, lsi.lflows, &lsi.match);
            build_lrouter_flows_for_lb(lb, lsi.lflows, lsi.meter_groups,
                                       lsi.features, &lsi.match, &lsi.actions);
            build_lswitch_flows_for_lb(lb, lsi.lflows, lsi.meter_groups,
                                       lsi.features, &lsi.match, &lsi.actions);
        }
        stopwatch_stop(LFLOWS_LBS_STOPWATCH_NAME, time_msec());
        stopwatch_start(LFLOWS_IGMP_STOPWATCH_NAME, time_msec());
        HMAP_FOR_EACH (igmp_group, hmap_node, igmp_groups) {
            build_lswitch_ip_mcast_igmp_mld(igmp_group,
                                            lsi.lflows,
                                            &lsi.actions,
                                            &lsi.match);
        }
        stopwatch_stop(LFLOWS_IGMP_STOPWATCH_NAME, time_msec());

        ds_destroy(&lsi.match);
        ds_destroy(&lsi.actions);
    }

    free(svc_check_match);
    build_lswitch_flows(datapaths, lflows);
}

static void
ovn_sb_set_lflow_logical_dp_group(
    struct ovsdb_idl_txn *ovnsb_txn,
    struct hmap *dp_groups,
    const struct sbrec_logical_flow *sbflow,
    const unsigned long *dpg_bitmap)
{
    struct ovn_dp_group *dpg;
    size_t n_ods;

    n_ods = bitmap_count1(dpg_bitmap, n_datapaths);

    if (!n_ods) {
        sbrec_logical_flow_set_logical_dp_group(sbflow, NULL);
        return;
    }

    ovs_assert(n_ods != 1);

    dpg = ovn_dp_group_find(dp_groups, dpg_bitmap, hash_int(n_ods, 0));
    ovs_assert(dpg != NULL);

    if (!dpg->dp_group) {
        dpg->dp_group = ovn_sb_insert_logical_dp_group(ovnsb_txn, dpg->bitmap);
    }
    sbrec_logical_flow_set_logical_dp_group(sbflow, dpg->dp_group);
}

static ssize_t max_seen_lflow_size = 128;

void run_update_worker_pool(int n_threads)
{
    /* If number of threads has been updated (or initially set),
     * update the worker pool. */
    if (update_worker_pool(n_threads, &build_lflows_pool,
                           build_lflows_thread) != POOL_UNCHANGED) {
        /* worker pool was updated */
        if (get_worker_pool_size() <= 1) {
            /* destroy potentially created lflow_hash_lock */
            lflow_hash_lock_destroy();
            parallelization_state = STATE_NULL;
        } else if (parallelization_state != STATE_USE_PARALLELIZATION) {
            lflow_hash_lock_init();
            parallelization_state = STATE_INIT_HASH_SIZES;
        }
    }
}

static void
build_mcast_groups(struct lflow_input *data,
                   const struct hmap *datapaths,
                   const struct hmap *ports,
                   struct hmap *mcast_groups,
                   struct hmap *igmp_groups);

/* Updates the Logical_Flow and Multicast_Group tables in the OVN_SB database,
 * constructing their contents based on the OVN_NB database. */
void build_lflows(struct lflow_input *input_data,
                  struct ovsdb_idl_txn *ovnsb_txn)
{
    struct hmap lflows;
    struct hmap mcast_groups;
    struct hmap igmp_groups;

    build_mcast_groups(input_data, input_data->datapaths, input_data->ports,
                       &mcast_groups, &igmp_groups);

    fast_hmap_size_for(&lflows, max_seen_lflow_size);

    build_lswitch_and_lrouter_flows(input_data->datapaths, input_data->ports,
                                    input_data->port_groups, &lflows,
                                    &mcast_groups, &igmp_groups,
                                    input_data->meter_groups, input_data->lbs,
                                    input_data->bfd_connections,
                                    input_data->features);

    if (parallelization_state == STATE_INIT_HASH_SIZES) {
        parallelization_state = STATE_USE_PARALLELIZATION;
    }

    /* Parallel build may result in a suboptimal hash. Resize the
     * hash to a correct size before doing lookups */

    hmap_expand(&lflows);

    if (hmap_count(&lflows) > max_seen_lflow_size) {
        max_seen_lflow_size = hmap_count(&lflows);
    }

    stopwatch_start(LFLOWS_DP_GROUPS_STOPWATCH_NAME, time_msec());
    /* Collecting all unique datapath groups. */
    struct hmap dp_groups = HMAP_INITIALIZER(&dp_groups);
    struct hmap single_dp_lflows;

    /* Single dp_flows will never grow bigger than lflows,
     * thus the two hmaps will remain the same size regardless
     * of how many elements we remove from lflows and add to
     * single_dp_lflows.
     * Note - lflows is always sized for at least 128 flows.
     */
    fast_hmap_size_for(&single_dp_lflows, max_seen_lflow_size);

    struct ovn_lflow *lflow;
    HMAP_FOR_EACH_SAFE (lflow, hmap_node, &lflows) {
        struct ovn_dp_group *dpg;
        uint32_t hash, n_ods;

        n_ods = bitmap_count1(lflow->dpg_bitmap, n_datapaths);

        ovs_assert(n_ods);

        if (n_ods == 1) {
            /* There is only one datapath, so it should be moved out of the
             * group to a single 'od'. */
            size_t index = bitmap_scan(lflow->dpg_bitmap, true, 0,
                                       n_datapaths);

            bitmap_set0(lflow->dpg_bitmap, index);
            lflow->od = datapaths_array[index];

            /* Logical flow should be re-hashed to allow lookups. */
            hash = hmap_node_hash(&lflow->hmap_node);
            /* Remove from lflows. */
            hmap_remove(&lflows, &lflow->hmap_node);
            hash = ovn_logical_flow_hash_datapath(&lflow->od->sb->header_.uuid,
                                                  hash);
            /* Add to single_dp_lflows. */
            hmap_insert_fast(&single_dp_lflows, &lflow->hmap_node, hash);
            continue;
        }

        hash = hash_int(n_ods, 0);
        dpg = ovn_dp_group_find(&dp_groups, lflow->dpg_bitmap, hash);
        if (!dpg) {
            dpg = xzalloc(sizeof *dpg);
            dpg->bitmap = bitmap_clone(lflow->dpg_bitmap, n_datapaths);
            hmap_insert(&dp_groups, &dpg->node, hash);
        }
        lflow->dpg = dpg;
    }

    /* Merge multiple and single dp hashes. */

    fast_hmap_merge(&lflows, &single_dp_lflows);

    hmap_destroy(&single_dp_lflows);

    stopwatch_stop(LFLOWS_DP_GROUPS_STOPWATCH_NAME, time_msec());
    stopwatch_start(LFLOWS_TO_SB_STOPWATCH_NAME, time_msec());

    /* Push changes to the Logical_Flow table to database. */
    const struct sbrec_logical_flow *sbflow;
    SBREC_LOGICAL_FLOW_TABLE_FOR_EACH_SAFE (sbflow,
                                     input_data->sbrec_logical_flow_table) {
        struct sbrec_logical_dp_group *dp_group = sbflow->logical_dp_group;
        struct ovn_datapath *logical_datapath_od = NULL;
        size_t i;

        /* Find one valid datapath to get the datapath type. */
        struct sbrec_datapath_binding *dp = sbflow->logical_datapath;
        if (dp) {
            logical_datapath_od = ovn_datapath_from_sbrec(
                                            input_data->datapaths, dp);
            if (logical_datapath_od
                && ovn_datapath_is_stale(logical_datapath_od)) {
                logical_datapath_od = NULL;
            }
        }
        for (i = 0; dp_group && i < dp_group->n_datapaths; i++) {
            logical_datapath_od = ovn_datapath_from_sbrec(
                             input_data->datapaths, dp_group->datapaths[i]);
            if (logical_datapath_od
                && !ovn_datapath_is_stale(logical_datapath_od)) {
                break;
            }
            logical_datapath_od = NULL;
        }

        if (!logical_datapath_od) {
            /* This lflow has no valid logical datapaths. */
            sbrec_logical_flow_delete(sbflow);
            continue;
        }

        enum ovn_pipeline pipeline
            = !strcmp(sbflow->pipeline, "ingress") ? P_IN : P_OUT;

        lflow = ovn_lflow_find(
            &lflows, dp_group ? NULL : logical_datapath_od,
            ovn_stage_build(ovn_datapath_get_type(logical_datapath_od),
                            pipeline, sbflow->table_id),
            sbflow->priority, sbflow->match, sbflow->actions,
            sbflow->controller_meter, sbflow->hash);
        if (lflow) {
            if (input_data->ovn_internal_version_changed) {
                const char *stage_name = smap_get_def(&sbflow->external_ids,
                                                  "stage-name", "");
                const char *stage_hint = smap_get_def(&sbflow->external_ids,
                                                  "stage-hint", "");
                const char *source = smap_get_def(&sbflow->external_ids,
                                                  "source", "");

                if (strcmp(stage_name, ovn_stage_to_str(lflow->stage))) {
                    sbrec_logical_flow_update_external_ids_setkey(sbflow,
                     "stage-name", ovn_stage_to_str(lflow->stage));
                }
                if (lflow->stage_hint) {
                    if (strcmp(stage_hint, lflow->stage_hint)) {
                        sbrec_logical_flow_update_external_ids_setkey(sbflow,
                        "stage-hint", lflow->stage_hint);
                    }
                }
                if (lflow->where) {
                    if (strcmp(source, lflow->where)) {
                        sbrec_logical_flow_update_external_ids_setkey(sbflow,
                        "source", lflow->where);
                    }
                }
            }

            /* This is a valid lflow.  Checking if the datapath group needs
             * updates. */
            bool update_dp_group = false;

            if ((!lflow->dpg && dp_group) || (lflow->dpg && !dp_group)) {
                /* Need to add or delete datapath group. */
                update_dp_group = true;
            } else if (!lflow->dpg && !dp_group) {
                /* No datapath group and not needed. */
            } else if (lflow->dpg->dp_group) {
                /* We know the datapath group in Sb that should be used. */
                if (lflow->dpg->dp_group != dp_group) {
                    /* Flow has different datapath group in the database.  */
                    update_dp_group = true;
                }
                /* Datapath group is already up to date. */
            } else {
                /* There is a datapath group and we need to perform
                 * a full comparison. */
                unsigned long *dpg_bitmap;
                struct ovn_datapath *od;

                dpg_bitmap = bitmap_allocate(n_datapaths);
                /* Check all logical datapaths from the group. */
                for (i = 0; i < dp_group->n_datapaths; i++) {
                    od = ovn_datapath_from_sbrec(
                            input_data->datapaths, dp_group->datapaths[i]);
                    if (!od || ovn_datapath_is_stale(od)) {
                        continue;
                    }
                    bitmap_set1(dpg_bitmap, od->index);
                }

                update_dp_group = !bitmap_equal(dpg_bitmap, lflow->dpg_bitmap,
                                                n_datapaths);
                bitmap_free(dpg_bitmap);
            }

            if (update_dp_group) {
                ovn_sb_set_lflow_logical_dp_group(ovnsb_txn, &dp_groups,
                                                  sbflow, lflow->dpg_bitmap);
            } else if (lflow->dpg && !lflow->dpg->dp_group) {
                /* Setting relation between unique datapath group and
                 * Sb DB datapath goup. */
                lflow->dpg->dp_group = dp_group;
            }

            /* This lflow updated.  Not needed anymore. */
            ovn_lflow_destroy(&lflows, lflow);
        } else {
            sbrec_logical_flow_delete(sbflow);
        }
    }

    HMAP_FOR_EACH_SAFE (lflow, hmap_node, &lflows) {
        const char *pipeline = ovn_stage_get_pipeline_name(lflow->stage);
        uint8_t table = ovn_stage_get_table(lflow->stage);

        sbflow = sbrec_logical_flow_insert(ovnsb_txn);
        if (lflow->od) {
            sbrec_logical_flow_set_logical_datapath(sbflow, lflow->od->sb);
        }
        ovn_sb_set_lflow_logical_dp_group(ovnsb_txn, &dp_groups,
                                          sbflow, lflow->dpg_bitmap);
        sbrec_logical_flow_set_pipeline(sbflow, pipeline);
        sbrec_logical_flow_set_table_id(sbflow, table);
        sbrec_logical_flow_set_priority(sbflow, lflow->priority);
        sbrec_logical_flow_set_match(sbflow, lflow->match);
        sbrec_logical_flow_set_actions(sbflow, lflow->actions);
        if (lflow->io_port) {
            struct smap tags = SMAP_INITIALIZER(&tags);
            smap_add(&tags, "in_out_port", lflow->io_port);
            sbrec_logical_flow_set_tags(sbflow, &tags);
            smap_destroy(&tags);
        }
        sbrec_logical_flow_set_controller_meter(sbflow, lflow->ctrl_meter);

        /* Trim the source locator lflow->where, which looks something like
         * "ovn/northd/northd.c:1234", down to just the part following the
         * last slash, e.g. "northd.c:1234". */
        const char *slash = strrchr(lflow->where, '/');
#if _WIN32
        const char *backslash = strrchr(lflow->where, '\\');
        if (!slash || backslash > slash) {
            slash = backslash;
        }
#endif
        const char *where = slash ? slash + 1 : lflow->where;

        struct smap ids = SMAP_INITIALIZER(&ids);
        smap_add(&ids, "stage-name", ovn_stage_to_str(lflow->stage));
        smap_add(&ids, "source", where);
        if (lflow->stage_hint) {
            smap_add(&ids, "stage-hint", lflow->stage_hint);
        }
        sbrec_logical_flow_set_external_ids(sbflow, &ids);
        smap_destroy(&ids);

        ovn_lflow_destroy(&lflows, lflow);
    }
    hmap_destroy(&lflows);

    stopwatch_stop(LFLOWS_TO_SB_STOPWATCH_NAME, time_msec());
    struct ovn_dp_group *dpg;
    HMAP_FOR_EACH_POP (dpg, node, &dp_groups) {
        bitmap_free(dpg->bitmap);
        free(dpg);
    }
    hmap_destroy(&dp_groups);

    /* Push changes to the Multicast_Group table to database. */
    const struct sbrec_multicast_group *sbmc;
    SBREC_MULTICAST_GROUP_TABLE_FOR_EACH_SAFE (sbmc,
                                input_data->sbrec_multicast_group_table) {
        struct ovn_datapath *od = ovn_datapath_from_sbrec(
                               input_data->datapaths, sbmc->datapath);

        if (!od || ovn_datapath_is_stale(od)) {
            sbrec_multicast_group_delete(sbmc);
            continue;
        }

        struct multicast_group group = { .name = sbmc->name,
                                         .key = sbmc->tunnel_key };
        struct ovn_multicast *mc = ovn_multicast_find(&mcast_groups,
                                                      od, &group);
        if (mc) {
            ovn_multicast_update_sbrec(mc, sbmc);
            ovn_multicast_destroy(&mcast_groups, mc);
        } else {
            sbrec_multicast_group_delete(sbmc);
        }
    }
    struct ovn_multicast *mc;
    HMAP_FOR_EACH_SAFE (mc, hmap_node, &mcast_groups) {
        if (!mc->datapath) {
            ovn_multicast_destroy(&mcast_groups, mc);
            continue;
        }
        sbmc = sbrec_multicast_group_insert(ovnsb_txn);
        sbrec_multicast_group_set_datapath(sbmc, mc->datapath->sb);
        sbrec_multicast_group_set_name(sbmc, mc->group->name);
        sbrec_multicast_group_set_tunnel_key(sbmc, mc->group->key);
        ovn_multicast_update_sbrec(mc, sbmc);
        ovn_multicast_destroy(&mcast_groups, mc);
    }

    struct ovn_igmp_group *igmp_group;

    HMAP_FOR_EACH_SAFE (igmp_group, hmap_node, &igmp_groups) {
        ovn_igmp_group_destroy(&igmp_groups, igmp_group);
    }

    hmap_destroy(&igmp_groups);
    hmap_destroy(&mcast_groups);
}

/* Each port group in Port_Group table in OVN_Northbound has a corresponding
 * entry in Port_Group table in OVN_Southbound. In OVN_Northbound the entries
 * contains lport uuids, while in OVN_Southbound we store the lport names.
 */
static void
sync_port_groups(struct northd_input *input_data,
                struct ovsdb_idl_txn *ovnsb_txn,
                 struct hmap *pgs)
{
    struct shash sb_port_groups = SHASH_INITIALIZER(&sb_port_groups);

    const struct sbrec_port_group *sb_port_group;
    SBREC_PORT_GROUP_TABLE_FOR_EACH (sb_port_group,
                               input_data->sbrec_port_group_table) {
        shash_add(&sb_port_groups, sb_port_group->name, sb_port_group);
    }

    struct ds sb_name = DS_EMPTY_INITIALIZER;

    struct ovn_port_group *pg;
    HMAP_FOR_EACH (pg, key_node, pgs) {

        struct ovn_port_group_ls *pg_ls;
        HMAP_FOR_EACH (pg_ls, key_node, &pg->nb_lswitches) {
            get_sb_port_group_name(pg->nb_pg->name, pg_ls->od->sb->tunnel_key,
                                   &sb_name);
            sb_port_group = shash_find_and_delete(&sb_port_groups,
                                                  ds_cstr(&sb_name));
            if (!sb_port_group) {
                sb_port_group = sbrec_port_group_insert(ovnsb_txn);
                sbrec_port_group_set_name(sb_port_group, ds_cstr(&sb_name));
            }

            const char **nb_port_names = xcalloc(pg_ls->n_ports,
                                                 sizeof *nb_port_names);
            for (size_t i = 0; i < pg_ls->n_ports; i++) {
                nb_port_names[i] = pg_ls->ports[i]->nbsp->name;
            }
            sbrec_port_group_set_ports(sb_port_group,
                                       nb_port_names,
                                       pg_ls->n_ports);
            free(nb_port_names);
        }
    }
    ds_destroy(&sb_name);

    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &sb_port_groups) {
        sbrec_port_group_delete(node->data);
        shash_delete(&sb_port_groups, node);
    }
    shash_destroy(&sb_port_groups);
}

struct band_entry {
    int64_t rate;
    int64_t burst_size;
    const char *action;
};

static int
band_cmp(const void *band1_, const void *band2_)
{
    const struct band_entry *band1p = band1_;
    const struct band_entry *band2p = band2_;

    if (band1p->rate != band2p->rate) {
        return band1p->rate > band2p->rate ? -1 : 1;
    } else if (band1p->burst_size != band2p->burst_size) {
        return band1p->burst_size > band2p->burst_size ? -1 : 1;
    } else {
        return strcmp(band1p->action, band2p->action);
    }
}

static bool
bands_need_update(const struct nbrec_meter *nb_meter,
                  const struct sbrec_meter *sb_meter)
{
    if (nb_meter->n_bands != sb_meter->n_bands) {
        return true;
    }

    /* A single band is the most common scenario, so speed up that
     * check. */
    if (nb_meter->n_bands == 1) {
        struct nbrec_meter_band *nb_band = nb_meter->bands[0];
        struct sbrec_meter_band *sb_band = sb_meter->bands[0];

        return !(nb_band->rate == sb_band->rate
                 && nb_band->burst_size == sb_band->burst_size
                 && !strcmp(sb_band->action, nb_band->action));
    }

    /* Place the Northbound entries in sorted order. */
    struct band_entry *nb_bands;
    nb_bands = xmalloc(sizeof *nb_bands * nb_meter->n_bands);
    for (size_t i = 0; i < nb_meter->n_bands; i++) {
        struct nbrec_meter_band *nb_band = nb_meter->bands[i];

        nb_bands[i].rate = nb_band->rate;
        nb_bands[i].burst_size = nb_band->burst_size;
        nb_bands[i].action = nb_band->action;
    }
    qsort(nb_bands, nb_meter->n_bands, sizeof *nb_bands, band_cmp);

    /* Place the Southbound entries in sorted order. */
    struct band_entry *sb_bands;
    sb_bands = xmalloc(sizeof *sb_bands * sb_meter->n_bands);
    for (size_t i = 0; i < sb_meter->n_bands; i++) {
        struct sbrec_meter_band *sb_band = sb_meter->bands[i];

        sb_bands[i].rate = sb_band->rate;
        sb_bands[i].burst_size = sb_band->burst_size;
        sb_bands[i].action = sb_band->action;
    }
    qsort(sb_bands, sb_meter->n_bands, sizeof *sb_bands, band_cmp);

    bool need_update = false;
    for (size_t i = 0; i < nb_meter->n_bands; i++) {
        if (nb_bands[i].rate != sb_bands[i].rate
            || nb_bands[i].burst_size != sb_bands[i].burst_size
            || strcmp(nb_bands[i].action, sb_bands[i].action)) {
            need_update = true;
            goto done;
        }
    }

done:
    free(nb_bands);
    free(sb_bands);

    return need_update;
}

static void
sync_meters_iterate_nb_meter(struct ovsdb_idl_txn *ovnsb_txn,
                             const char *meter_name,
                             const struct nbrec_meter *nb_meter,
                             struct shash *sb_meters,
                             struct sset *used_sb_meters)
{
    const struct sbrec_meter *sb_meter;
    bool new_sb_meter = false;

    sb_meter = shash_find_data(sb_meters, meter_name);
    if (!sb_meter) {
        sb_meter = sbrec_meter_insert(ovnsb_txn);
        sbrec_meter_set_name(sb_meter, meter_name);
        shash_add(sb_meters, sb_meter->name, sb_meter);
        new_sb_meter = true;
    }
    sset_add(used_sb_meters, meter_name);

    if (new_sb_meter || bands_need_update(nb_meter, sb_meter)) {
        struct sbrec_meter_band **sb_bands;
        sb_bands = xcalloc(nb_meter->n_bands, sizeof *sb_bands);
        for (size_t i = 0; i < nb_meter->n_bands; i++) {
            const struct nbrec_meter_band *nb_band = nb_meter->bands[i];

            sb_bands[i] = sbrec_meter_band_insert(ovnsb_txn);

            sbrec_meter_band_set_action(sb_bands[i], nb_band->action);
            sbrec_meter_band_set_rate(sb_bands[i], nb_band->rate);
            sbrec_meter_band_set_burst_size(sb_bands[i],
                                            nb_band->burst_size);
        }
        sbrec_meter_set_bands(sb_meter, sb_bands, nb_meter->n_bands);
        free(sb_bands);
    }

    sbrec_meter_set_unit(sb_meter, nb_meter->unit);
}

static void
sync_acl_fair_meter(struct ovsdb_idl_txn *ovnsb_txn,
                    struct shash *meter_groups,
                    const struct nbrec_acl *acl, struct shash *sb_meters,
                    struct sset *used_sb_meters)
{
    const struct nbrec_meter *nb_meter =
        fair_meter_lookup_by_name(meter_groups, acl->meter);

    if (!nb_meter) {
        return;
    }

    char *meter_name = alloc_acl_log_unique_meter_name(acl);
    sync_meters_iterate_nb_meter(ovnsb_txn, meter_name, nb_meter, sb_meters,
                                 used_sb_meters);
    free(meter_name);
}

/* Each entry in the Meter and Meter_Band tables in OVN_Northbound have
 * a corresponding entries in the Meter and Meter_Band tables in
 * OVN_Southbound. Additionally, ACL logs that use fair meters have
 * a private copy of its meter in the SB table.
 */
static void
sync_meters(struct northd_input *input_data,
            struct ovsdb_idl_txn *ovnsb_txn,
            struct shash *meter_groups)
{
    struct shash sb_meters = SHASH_INITIALIZER(&sb_meters);
    struct sset used_sb_meters = SSET_INITIALIZER(&used_sb_meters);

    const struct sbrec_meter *sb_meter;
    SBREC_METER_TABLE_FOR_EACH (sb_meter, input_data->sbrec_meter_table) {
        shash_add(&sb_meters, sb_meter->name, sb_meter);
    }

    const struct nbrec_meter *nb_meter;
    NBREC_METER_TABLE_FOR_EACH (nb_meter, input_data->nbrec_meter_table) {
        sync_meters_iterate_nb_meter(ovnsb_txn, nb_meter->name, nb_meter,
                                     &sb_meters, &used_sb_meters);
    }

    /*
     * In addition to creating Meters in the SB from the block above, check
     * and see if additional rows are needed to get ACLs logs individually
     * rate-limited.
     */
    const struct nbrec_acl *acl;
    NBREC_ACL_TABLE_FOR_EACH (acl, input_data->nbrec_acl_table) {
        sync_acl_fair_meter(ovnsb_txn, meter_groups, acl,
                            &sb_meters, &used_sb_meters);
    }

    const char *used_meter;
    SSET_FOR_EACH_SAFE (used_meter, &used_sb_meters) {
        shash_find_and_delete(&sb_meters, used_meter);
        sset_delete(&used_sb_meters, SSET_NODE_FROM_NAME(used_meter));
    }
    sset_destroy(&used_sb_meters);

    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &sb_meters) {
        sbrec_meter_delete(node->data);
        shash_delete(&sb_meters, node);
    }
    shash_destroy(&sb_meters);
}

static bool
mirror_needs_update(const struct nbrec_mirror *nb_mirror,
                    const struct sbrec_mirror *sb_mirror)
{

    if (nb_mirror->index != sb_mirror->index) {
        return true;
    } else if (strcmp(nb_mirror->sink, sb_mirror->sink)) {
        return true;
    } else if (strcmp(nb_mirror->type, sb_mirror->type)) {
        return true;
    } else if (strcmp(nb_mirror->filter, sb_mirror->filter)) {
        return true;
    }

    return false;
}

static void
sync_mirrors_iterate_nb_mirror(struct ovsdb_idl_txn *ovnsb_txn,
                               const char *mirror_name,
                               const struct nbrec_mirror *nb_mirror,
                               struct shash *sb_mirrors)
{
    const struct sbrec_mirror *sb_mirror;
    bool new_sb_mirror = false;

    sb_mirror = shash_find_data(sb_mirrors, mirror_name);
    if (!sb_mirror) {
        sb_mirror = sbrec_mirror_insert(ovnsb_txn);
        sbrec_mirror_set_name(sb_mirror, mirror_name);
        shash_add(sb_mirrors, sb_mirror->name, sb_mirror);
        new_sb_mirror = true;
    }

    if (new_sb_mirror || mirror_needs_update(nb_mirror, sb_mirror)) {
        sbrec_mirror_set_filter(sb_mirror, nb_mirror->filter);
        sbrec_mirror_set_index(sb_mirror, nb_mirror->index);
        sbrec_mirror_set_sink(sb_mirror, nb_mirror->sink);
        sbrec_mirror_set_type(sb_mirror, nb_mirror->type);
    }
}

static void
sync_mirrors(struct northd_input *input_data,
             struct ovsdb_idl_txn *ovnsb_txn)
{
    struct shash sb_mirrors = SHASH_INITIALIZER(&sb_mirrors);

    const struct sbrec_mirror *sb_mirror;
    SBREC_MIRROR_TABLE_FOR_EACH (sb_mirror, input_data->sbrec_mirror_table) {
        shash_add(&sb_mirrors, sb_mirror->name, sb_mirror);
    }

    const struct nbrec_mirror *nb_mirror;
    NBREC_MIRROR_TABLE_FOR_EACH (nb_mirror, input_data->nbrec_mirror_table) {
        sync_mirrors_iterate_nb_mirror(ovnsb_txn, nb_mirror->name, nb_mirror,
                                       &sb_mirrors);
        shash_find_and_delete(&sb_mirrors, nb_mirror->name);
    }

    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, &sb_mirrors) {
        sbrec_mirror_delete(node->data);
        shash_delete(&sb_mirrors, node);
    }
    shash_destroy(&sb_mirrors);
}

/*
 * struct 'dns_info' is used to sync the DNS records between OVN Northbound db
 * and Southbound db.
 */
struct dns_info {
    struct hmap_node hmap_node;
    const struct nbrec_dns *nb_dns; /* DNS record in the Northbound db. */
    const struct sbrec_dns *sb_dns; /* DNS record in the Southbound db. */

    /* Datapaths to which the DNS entry is associated with it. */
    const struct sbrec_datapath_binding **sbs;
    size_t n_sbs;
};

static inline struct dns_info *
get_dns_info_from_hmap(struct hmap *dns_map, struct uuid *uuid)
{
    struct dns_info *dns_info;
    size_t hash = uuid_hash(uuid);
    HMAP_FOR_EACH_WITH_HASH (dns_info, hmap_node, hash, dns_map) {
        if (uuid_equals(&dns_info->nb_dns->header_.uuid, uuid)) {
            return dns_info;
        }
    }

    return NULL;
}

static void
sync_dns_entries(struct northd_input *input_data,
                 struct ovsdb_idl_txn *ovnsb_txn,
                 struct hmap *datapaths)
{
    struct hmap dns_map = HMAP_INITIALIZER(&dns_map);
    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbs || !od->nbs->n_dns_records) {
            continue;
        }

        for (size_t i = 0; i < od->nbs->n_dns_records; i++) {
            struct dns_info *dns_info = get_dns_info_from_hmap(
                &dns_map, &od->nbs->dns_records[i]->header_.uuid);
            if (!dns_info) {
                size_t hash = uuid_hash(
                    &od->nbs->dns_records[i]->header_.uuid);
                dns_info = xzalloc(sizeof *dns_info);;
                dns_info->nb_dns = od->nbs->dns_records[i];
                hmap_insert(&dns_map, &dns_info->hmap_node, hash);
            }

            dns_info->n_sbs++;
            dns_info->sbs = xrealloc(dns_info->sbs,
                                     dns_info->n_sbs * sizeof *dns_info->sbs);
            dns_info->sbs[dns_info->n_sbs - 1] = od->sb;
        }
    }

    const struct sbrec_dns *sbrec_dns;
    SBREC_DNS_TABLE_FOR_EACH_SAFE (sbrec_dns, input_data->sbrec_dns_table) {
        const char *nb_dns_uuid = smap_get(&sbrec_dns->external_ids, "dns_id");
        struct uuid dns_uuid;
        if (!nb_dns_uuid || !uuid_from_string(&dns_uuid, nb_dns_uuid)) {
            sbrec_dns_delete(sbrec_dns);
            continue;
        }

        struct dns_info *dns_info =
            get_dns_info_from_hmap(&dns_map, &dns_uuid);
        if (dns_info) {
            dns_info->sb_dns = sbrec_dns;
        } else {
            sbrec_dns_delete(sbrec_dns);
        }
    }

    struct dns_info *dns_info;
    HMAP_FOR_EACH_POP (dns_info, hmap_node, &dns_map) {
        if (!dns_info->sb_dns) {
            sbrec_dns = sbrec_dns_insert(ovnsb_txn);
            dns_info->sb_dns = sbrec_dns;
            char *dns_id = xasprintf(
                UUID_FMT, UUID_ARGS(&dns_info->nb_dns->header_.uuid));
            const struct smap external_ids =
                SMAP_CONST1(&external_ids, "dns_id", dns_id);
            sbrec_dns_set_external_ids(sbrec_dns, &external_ids);
            free(dns_id);
        }

        /* Set the datapaths and records. If nothing has changed, then
         * this will be a no-op.
         */
        sbrec_dns_set_datapaths(
            dns_info->sb_dns,
            (struct sbrec_datapath_binding **)dns_info->sbs,
            dns_info->n_sbs);

        /* DNS lookups are case-insensitive. Convert records to lowercase so
         * we can do consistent lookups when DNS requests arrive
         */
        struct smap lower_records = SMAP_INITIALIZER(&lower_records);
        struct smap_node *node;
        SMAP_FOR_EACH (node, &dns_info->nb_dns->records) {
            smap_add_nocopy(&lower_records, xstrdup(node->key),
                            str_tolower(node->value));
        }

        sbrec_dns_set_records(dns_info->sb_dns, &lower_records);

        smap_destroy(&lower_records);
        free(dns_info->sbs);
        free(dns_info);
    }
    hmap_destroy(&dns_map);
}

static void
sync_template_vars(struct northd_input *input_data,
                   struct ovsdb_idl_txn *ovnsb_txn)
{
    struct shash nb_tvs = SHASH_INITIALIZER(&nb_tvs);

    const struct nbrec_chassis_template_var *nb_tv;
    const struct sbrec_chassis_template_var *sb_tv;

    NBREC_CHASSIS_TEMPLATE_VAR_TABLE_FOR_EACH (
            nb_tv, input_data->nbrec_chassis_template_var_table) {
        shash_add(&nb_tvs, nb_tv->chassis, nb_tv);
    }

    SBREC_CHASSIS_TEMPLATE_VAR_TABLE_FOR_EACH_SAFE (
            sb_tv, input_data->sbrec_chassis_template_var_table) {
        nb_tv = shash_find_and_delete(&nb_tvs, sb_tv->chassis);
        if (!nb_tv) {
            sbrec_chassis_template_var_delete(sb_tv);
            continue;
        }
        if (!smap_equal(&sb_tv->variables, &nb_tv->variables)) {
            sbrec_chassis_template_var_set_variables(sb_tv,
                                                     &nb_tv->variables);
        }
    }

    struct shash_node *node;
    SHASH_FOR_EACH (node, &nb_tvs) {
        nb_tv = node->data;
        sb_tv = sbrec_chassis_template_var_insert(ovnsb_txn);
        sbrec_chassis_template_var_set_chassis(sb_tv, nb_tv->chassis);
        sbrec_chassis_template_var_set_variables(sb_tv, &nb_tv->variables);
    }
    shash_destroy(&nb_tvs);
}

static void
destroy_datapaths_and_ports(struct hmap *datapaths, struct hmap *ports,
                            struct ovs_list *lr_list)
{
    struct ovn_datapath *router_dp;
    LIST_FOR_EACH_POP (router_dp, lr_list, lr_list) {
        if (router_dp->lr_group) {
            struct lrouter_group *lr_group = router_dp->lr_group;

            for (size_t i = 0; i < lr_group->n_router_dps; i++) {
                lr_group->router_dps[i]->lr_group = NULL;
            }

            free(lr_group->router_dps);
            sset_destroy(&lr_group->ha_chassis_groups);
            free(lr_group);
        }
    }

    struct ovn_datapath *dp;
    HMAP_FOR_EACH_SAFE (dp, key_node, datapaths) {
        ovn_datapath_destroy(datapaths, dp);
    }
    hmap_destroy(datapaths);

    struct ovn_port *port;
    HMAP_FOR_EACH_SAFE (port, key_node, ports) {
        ovn_port_destroy(ports, port);
    }
    hmap_destroy(ports);
}

static void
build_ip_mcast(struct northd_input *input_data,
               struct ovsdb_idl_txn *ovnsb_txn,
               struct hmap *datapaths)
{
    struct ovn_datapath *od;

    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbs) {
            continue;
        }

        const struct sbrec_ip_multicast *ip_mcast =
            ip_mcast_lookup(input_data->sbrec_ip_mcast_by_dp, od->sb);

        if (!ip_mcast) {
            ip_mcast = sbrec_ip_multicast_insert(ovnsb_txn);
        }
        store_mcast_info_for_switch_datapath(ip_mcast, od);
    }

    /* Delete southbound records without northbound matches. */
    const struct sbrec_ip_multicast *sb;

    SBREC_IP_MULTICAST_TABLE_FOR_EACH_SAFE (sb,
                                   input_data->sbrec_ip_multicast_table) {
        od = ovn_datapath_from_sbrec(datapaths, sb->datapath);
        if (!od || ovn_datapath_is_stale(od)) {
            sbrec_ip_multicast_delete(sb);
        }
    }
}

static void
build_mcast_groups(struct lflow_input *input_data,
                   const struct hmap *datapaths,
                   const struct hmap *ports,
                   struct hmap *mcast_groups,
                   struct hmap *igmp_groups)
{
    struct ovn_port *op;

    hmap_init(mcast_groups);
    hmap_init(igmp_groups);
    struct ovn_datapath *od;

    HMAP_FOR_EACH (od, key_node, datapaths) {
        init_mcast_flow_count(od);
    }

    HMAP_FOR_EACH (op, key_node, ports) {
        if (op->nbrp && lrport_is_enabled(op->nbrp)) {
            /* If this port is configured to always flood multicast traffic
             * add it to the MC_STATIC group.
             */
            if (op->mcast_info.flood) {
                ovn_multicast_add(mcast_groups, &mc_static, op);
                op->od->mcast_info.rtr.flood_static = true;
            }
        } else if (op->nbsp && lsp_is_enabled(op->nbsp)) {
            ovn_multicast_add(mcast_groups, &mc_flood, op);

            if (!lsp_is_router(op->nbsp)) {
                ovn_multicast_add(mcast_groups, &mc_flood_l2, op);
            }

            /* If this port is connected to a multicast router then add it
             * to the MC_MROUTER_FLOOD group.
             */
            if (op->od->mcast_info.sw.flood_relay && op->peer &&
                    op->peer->od && op->peer->od->mcast_info.rtr.relay) {
                ovn_multicast_add(mcast_groups, &mc_mrouter_flood, op);
            }

            /* If this port is configured to always flood multicast reports
             * add it to the MC_MROUTER_FLOOD group (all reports must be
             * flooded to statically configured or learned mrouters).
             */
            if (op->mcast_info.flood_reports) {
                ovn_multicast_add(mcast_groups, &mc_mrouter_flood, op);
                op->od->mcast_info.sw.flood_reports = true;
            }

            /* If this port is configured to always flood multicast traffic
             * add it to the MC_STATIC group.
             */
            if (op->mcast_info.flood) {
                ovn_multicast_add(mcast_groups, &mc_static, op);
                op->od->mcast_info.sw.flood_static = true;
            }
        }
    }

    const struct sbrec_igmp_group *sb_igmp;

    SBREC_IGMP_GROUP_TABLE_FOR_EACH_SAFE (sb_igmp,
                                     input_data->sbrec_igmp_group_table) {
        /* If this is a stale group (e.g., controller had crashed,
         * purge it).
         */
        if (!sb_igmp->chassis || !sb_igmp->datapath) {
            sbrec_igmp_group_delete(sb_igmp);
            continue;
        }

        /* If the datapath value is stale, purge the group. */
        od = ovn_datapath_from_sbrec(datapaths, sb_igmp->datapath);

        if (!od || ovn_datapath_is_stale(od)) {
            sbrec_igmp_group_delete(sb_igmp);
            continue;
        }

        struct in6_addr group_address;
        if (!strcmp(sb_igmp->address, OVN_IGMP_GROUP_MROUTERS)) {
            /* Use all-zeros IP to denote a group corresponding to mrouters. */
            memset(&group_address, 0, sizeof group_address);
        } else if (!ovn_igmp_group_get_address(sb_igmp, &group_address)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "invalid IGMP group address: %s",
                         sb_igmp->address);
            continue;
        }

        /* Extract the IGMP group ports from the SB entry. */
        size_t n_igmp_ports;
        struct ovn_port **igmp_ports =
            ovn_igmp_group_get_ports(sb_igmp, &n_igmp_ports, ports);

        /* It can be that all ports in the IGMP group record already have
         * mcast_flood=true and then we can skip the group completely.
         */
        if (!igmp_ports) {
            continue;
        }

        /* Add the IGMP group entry. Will also try to allocate an ID for it
         * if the multicast group already exists.
         */
        struct ovn_igmp_group *igmp_group =
            ovn_igmp_group_add(input_data, igmp_groups, od, &group_address,
                               sb_igmp->address);

        /* Add the extracted ports to the IGMP group. */
        ovn_igmp_group_add_entry(igmp_group, igmp_ports, n_igmp_ports);
    }

    /* Build IGMP groups for multicast routers with relay enabled. The router
     * IGMP groups are based on the groups learnt by their multicast enabled
     * peers.
     */
    HMAP_FOR_EACH (od, key_node, datapaths) {

        if (ovs_list_is_empty(&od->mcast_info.groups)) {
            continue;
        }

        for (size_t i = 0; i < od->n_router_ports; i++) {
            struct ovn_port *router_port = od->router_ports[i]->peer;

            /* If the router the port connects to doesn't have multicast
             * relay enabled or if it was already configured to flood
             * multicast traffic then skip it.
             */
            if (!router_port || !router_port->od ||
                    !router_port->od->mcast_info.rtr.relay ||
                    router_port->mcast_info.flood) {
                continue;
            }

            struct ovn_igmp_group *igmp_group;
            LIST_FOR_EACH (igmp_group, list_node, &od->mcast_info.groups) {
                struct in6_addr *address = &igmp_group->address;

                /* Skip mrouter entries. */
                if (!strcmp(igmp_group->mcgroup.name,
                            OVN_IGMP_GROUP_MROUTERS)) {
                    continue;
                }

                /* For IPv6 only relay routable multicast groups
                 * (RFC 4291 2.7).
                 */
                if (!IN6_IS_ADDR_V4MAPPED(address) &&
                        !ipv6_addr_is_routable_multicast(address)) {
                    continue;
                }

                struct ovn_igmp_group *igmp_group_rtr =
                    ovn_igmp_group_add(input_data,
                                       igmp_groups, router_port->od,
                                       address, igmp_group->mcgroup.name);
                struct ovn_port **router_igmp_ports =
                    xmalloc(sizeof *router_igmp_ports);
                /* Store the chassis redirect port  otherwise traffic will not
                 * be tunneled properly.
                 */
                router_igmp_ports[0] = router_port->cr_port
                                       ? router_port->cr_port
                                       : router_port;
                ovn_igmp_group_add_entry(igmp_group_rtr, router_igmp_ports, 1);
            }
        }
    }

    /* Walk the aggregated IGMP groups and allocate IDs for new entries.
     * Then store the ports in the associated multicast group.
     * Mrouter entries are also stored as IGMP groups, deal with those
     * explicitly.
     */
    struct ovn_igmp_group *igmp_group;
    HMAP_FOR_EACH_SAFE (igmp_group, hmap_node, igmp_groups) {

        /* If this is a mrouter entry just aggregate the mrouter ports
         * into the MC_MROUTER mcast_group and destroy the igmp_group;
         * no more processing needed. */
        if (!strcmp(igmp_group->mcgroup.name, OVN_IGMP_GROUP_MROUTERS)) {
            ovn_igmp_mrouter_aggregate_ports(igmp_group, mcast_groups);
            ovn_igmp_group_destroy(igmp_groups, igmp_group);
            continue;
        }

        if (!ovn_igmp_group_allocate_id(igmp_group)) {
            /* If we ran out of keys just destroy the entry. */
            ovn_igmp_group_destroy(igmp_groups, igmp_group);
            continue;
        }

        /* Aggregate the ports from all entries corresponding to this
         * group.
         */
        ovn_igmp_group_aggregate_ports(igmp_group, mcast_groups);
    }
}

static void
build_meter_groups(struct northd_input *input_data,
                   struct shash *meter_groups)
{
    const struct nbrec_meter *nb_meter;
    NBREC_METER_TABLE_FOR_EACH (nb_meter, input_data->nbrec_meter_table) {
        shash_add(meter_groups, nb_meter->name, nb_meter);
    }
}

static const struct nbrec_static_mac_binding *
static_mac_binding_by_port_ip(struct northd_input *input_data,
                       const char *logical_port, const char *ip)
{
    const struct nbrec_static_mac_binding *nb_smb = NULL;

    NBREC_STATIC_MAC_BINDING_TABLE_FOR_EACH (
        nb_smb, input_data->nbrec_static_mac_binding_table) {
        if (!strcmp(nb_smb->logical_port, logical_port) &&
            !strcmp(nb_smb->ip, ip)) {
            break;
        }
    }

    return nb_smb;
}

static void
build_static_mac_binding_table(struct northd_input *input_data,
                               struct ovsdb_idl_txn *ovnsb_txn,
                               struct hmap *ports)
{
    /* Cleanup SB Static_MAC_Binding entries which do not have corresponding
     * NB Static_MAC_Binding entries. */
    const struct nbrec_static_mac_binding *nb_smb;
    const struct sbrec_static_mac_binding *sb_smb;
    SBREC_STATIC_MAC_BINDING_TABLE_FOR_EACH_SAFE (sb_smb,
        input_data->sbrec_static_mac_binding_table) {
        nb_smb = static_mac_binding_by_port_ip(input_data,
                                               sb_smb->logical_port,
                                               sb_smb->ip);
        if (!nb_smb) {
            sbrec_static_mac_binding_delete(sb_smb);
        }
    }

    /* Create/Update SB Static_MAC_Binding entries with corresponding values
     * from NB Static_MAC_Binding entries. */
    NBREC_STATIC_MAC_BINDING_TABLE_FOR_EACH (
        nb_smb, input_data->nbrec_static_mac_binding_table) {
        struct ovn_port *op = ovn_port_find(ports, nb_smb->logical_port);
        if (op && op->nbrp) {
            struct ovn_datapath *od = op->od;
            if (od && od->sb) {
                const struct sbrec_static_mac_binding *mb =
                    static_mac_binding_lookup(
                        input_data->sbrec_static_mac_binding_by_lport_ip,
                        nb_smb->logical_port, nb_smb->ip);
                if (!mb) {
                    /* Create new entry */
                    mb = sbrec_static_mac_binding_insert(ovnsb_txn);
                    sbrec_static_mac_binding_set_logical_port(
                        mb, nb_smb->logical_port);
                    sbrec_static_mac_binding_set_ip(mb, nb_smb->ip);
                    sbrec_static_mac_binding_set_mac(mb, nb_smb->mac);
                    sbrec_static_mac_binding_set_override_dynamic_mac(mb,
                        nb_smb->override_dynamic_mac);
                    sbrec_static_mac_binding_set_datapath(mb, od->sb);
                } else {
                    /* Update existing entry if there is a change*/
                    if (strcmp(mb->mac, nb_smb->mac)) {
                        sbrec_static_mac_binding_set_mac(mb, nb_smb->mac);
                    }
                    if (mb->override_dynamic_mac !=
                        nb_smb->override_dynamic_mac) {
                        sbrec_static_mac_binding_set_override_dynamic_mac(mb,
                            nb_smb->override_dynamic_mac);
                    }
                }
            }
        }
    }
}

void
northd_init(struct northd_data *data)
{
    hmap_init(&data->datapaths);
    hmap_init(&data->ports);
    hmap_init(&data->port_groups);
    shash_init(&data->meter_groups);
    hmap_init(&data->lbs);
    hmap_init(&data->lb_groups);
    hmap_init(&data->bfd_connections);
    ovs_list_init(&data->lr_list);
    data->features = (struct chassis_features) {
        .ct_no_masked_label = true,
        .mac_binding_timestamp = true,
    };
    data->ovn_internal_version_changed = false;
}

void
northd_destroy(struct northd_data *data)
{
    struct ovn_northd_lb *lb;
    HMAP_FOR_EACH_POP (lb, hmap_node, &data->lbs) {
        ovn_northd_lb_destroy(lb);
    }
    hmap_destroy(&data->lbs);

    struct ovn_lb_group *lb_group;
    HMAP_FOR_EACH_POP (lb_group, hmap_node, &data->lb_groups) {
        ovn_lb_group_destroy(lb_group);
    }
    hmap_destroy(&data->lb_groups);

    struct ovn_port_group *pg;
    HMAP_FOR_EACH_SAFE (pg, key_node, &data->port_groups) {
        ovn_port_group_destroy(&data->port_groups, pg);
    }

    hmap_destroy(&data->port_groups);
    hmap_destroy(&data->bfd_connections);

    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &data->meter_groups) {
        shash_delete(&data->meter_groups, node);
    }
    shash_destroy(&data->meter_groups);

    /* XXX Having to explicitly clean up macam here
     * is a bit strange. We don't explicitly initialize
     * macam in this module, but this is the logical place
     * to clean it up. Ideally, more IPAM logic can be factored
     * out of ovn-northd and this can be taken care of there
     * as well.
     */
    cleanup_macam();

    destroy_datapaths_and_ports(&data->datapaths, &data->ports,
                                &data->lr_list);
    destroy_debug_config();
}

static void
ovnnb_db_run(struct northd_input *input_data,
             struct northd_data *data,
             struct ovsdb_idl_txn *ovnnb_txn,
             struct ovsdb_idl_txn *ovnsb_txn,
             struct ovsdb_idl_index *sbrec_chassis_by_name,
             struct ovsdb_idl_index *sbrec_chassis_by_hostname)
{
    if (!ovnsb_txn || !ovnnb_txn) {
        return;
    }
    stopwatch_start(BUILD_LFLOWS_CTX_STOPWATCH_NAME, time_msec());

    /* Sync ipsec configuration.
     * Copy nb_cfg from northbound to southbound database.
     * Also set up to update sb_cfg once our southbound transaction commits. */
    const struct nbrec_nb_global *nb = nbrec_nb_global_table_first(
                                       input_data->nbrec_nb_global_table);
    if (!nb) {
        nb = nbrec_nb_global_insert(ovnnb_txn);
    }

    const char *mac_addr_prefix = set_mac_prefix(smap_get(&nb->options,
                                                          "mac_prefix"));

    const char *monitor_mac = smap_get(&nb->options, "svc_monitor_mac");
    if (monitor_mac) {
        if (eth_addr_from_string(monitor_mac, &svc_monitor_mac_ea)) {
            snprintf(svc_monitor_mac, sizeof svc_monitor_mac,
                     ETH_ADDR_FMT, ETH_ADDR_ARGS(svc_monitor_mac_ea));
        } else {
            monitor_mac = NULL;
        }
    }

    struct smap options;
    smap_clone(&options, &nb->options);

    smap_replace(&options, "mac_prefix", mac_addr_prefix);

    if (!monitor_mac) {
        eth_addr_random(&svc_monitor_mac_ea);
        snprintf(svc_monitor_mac, sizeof svc_monitor_mac,
                 ETH_ADDR_FMT, ETH_ADDR_ARGS(svc_monitor_mac_ea));
        smap_replace(&options, "svc_monitor_mac", svc_monitor_mac);
    }

    char *max_tunid = xasprintf("%d", get_ovn_max_dp_key_local(input_data));
    smap_replace(&options, "max_tunid", max_tunid);
    free(max_tunid);

    char *ovn_internal_version = ovn_get_internal_version();
    if (!strcmp(ovn_internal_version,
                smap_get_def(&options, "northd_internal_version", ""))) {
        data->ovn_internal_version_changed = false;
    } else {
        smap_replace(&options, "northd_internal_version",
                     ovn_internal_version);
    }
    free(ovn_internal_version);

    if (!smap_equal(&nb->options, &options)) {
        nbrec_nb_global_verify_options(nb);
        nbrec_nb_global_set_options(nb, &options);
    }

    use_ct_inv_match = smap_get_bool(&nb->options,
                                     "use_ct_inv_match", true);

    /* deprecated, use --event instead */
    controller_event_en = smap_get_bool(&nb->options,
                                        "controller_event", false);
    check_lsp_is_up = !smap_get_bool(&nb->options,
                                     "ignore_lsp_down", true);
    default_acl_drop = smap_get_bool(&nb->options, "default_acl_drop", false);

    install_ls_lb_from_router = smap_get_bool(&nb->options,
                                              "install_ls_lb_from_router",
                                              false);

    build_chassis_features(input_data, &data->features);

    init_debug_config(nb);

    build_datapaths(input_data, ovnsb_txn, &data->datapaths, &data->lr_list);
    build_lbs(input_data, &data->datapaths, &data->lbs, &data->lb_groups);
    build_ports(input_data, ovnsb_txn, sbrec_chassis_by_name,
                sbrec_chassis_by_hostname,
                &data->datapaths, &data->ports);
    build_lb_port_related_data(&data->datapaths, &data->ports, &data->lbs,
                               &data->lb_groups, input_data, ovnsb_txn);
    build_ipam(&data->datapaths, &data->ports);
    build_port_group_lswitches(input_data, &data->port_groups, &data->ports);
    build_lrouter_groups(&data->ports, &data->lr_list);
    build_ip_mcast(input_data, ovnsb_txn, &data->datapaths);
    build_meter_groups(input_data, &data->meter_groups);
    build_static_mac_binding_table(input_data, ovnsb_txn, &data->ports);
    stopwatch_stop(BUILD_LFLOWS_CTX_STOPWATCH_NAME, time_msec());
    stopwatch_start(CLEAR_LFLOWS_CTX_STOPWATCH_NAME, time_msec());
    ovn_update_ipv6_options(&data->ports);
    ovn_update_ipv6_prefix(&data->ports);

    sync_lbs(input_data, ovnsb_txn, &data->datapaths, &data->lbs);
    sync_port_groups(input_data, ovnsb_txn, &data->port_groups);
    sync_meters(input_data, ovnsb_txn, &data->meter_groups);
    sync_mirrors(input_data, ovnsb_txn);
    sync_dns_entries(input_data, ovnsb_txn, &data->datapaths);
    sync_template_vars(input_data, ovnsb_txn);

    cleanup_stale_fdb_entries(input_data, &data->datapaths);
    stopwatch_stop(CLEAR_LFLOWS_CTX_STOPWATCH_NAME, time_msec());

    /* Set up SB_Global (depends on chassis features). */
    const struct sbrec_sb_global *sb = sbrec_sb_global_table_first(
                                       input_data->sbrec_sb_global_table);
    if (!sb) {
        sb = sbrec_sb_global_insert(ovnsb_txn);
    }
    if (nb->ipsec != sb->ipsec) {
        sbrec_sb_global_set_ipsec(sb, nb->ipsec);
    }

    /* Inform ovn-controllers whether LB flows will use ct_mark (i.e., only
     * if all chassis support it).  If not explicitly present in the database
     * the default value to be used for this option is 'true'.
     */
    if (!data->features.ct_no_masked_label) {
        smap_replace(&options, "lb_hairpin_use_ct_mark", "false");
    } else {
        smap_remove(&options, "lb_hairpin_use_ct_mark");
    }
    if (!smap_equal(&sb->options, &options)) {
        sbrec_sb_global_set_options(sb, &options);
    }
    smap_destroy(&options);
}

/* Stores the list of chassis which references an ha_chassis_group.
 */
struct ha_ref_chassis_info {
    const struct sbrec_ha_chassis_group *ha_chassis_group;
    struct sbrec_chassis **ref_chassis;
    size_t n_ref_chassis;
    size_t free_slots;
};

static void
add_to_ha_ref_chassis_info(struct ha_ref_chassis_info *ref_ch_info,
                           const struct sbrec_chassis *chassis)
{
    for (size_t j = 0; j < ref_ch_info->n_ref_chassis; j++) {
        if (ref_ch_info->ref_chassis[j] == chassis) {
           return;
        }
    }

    /* Allocate space for 3 chassis at a time. */
    if (!ref_ch_info->free_slots) {
        ref_ch_info->ref_chassis =
            xrealloc(ref_ch_info->ref_chassis,
                     sizeof *ref_ch_info->ref_chassis *
                     (ref_ch_info->n_ref_chassis + 3));
        ref_ch_info->free_slots = 3;
    }

    ref_ch_info->ref_chassis[ref_ch_info->n_ref_chassis] =
        CONST_CAST(struct sbrec_chassis *, chassis);
    ref_ch_info->n_ref_chassis++;
    ref_ch_info->free_slots--;
}

struct ha_chassis_group_node {
    struct hmap_node hmap_node;
    const struct sbrec_ha_chassis_group *ha_ch_grp;
};

static void
update_sb_ha_group_ref_chassis(struct northd_input *input_data,
                               struct shash *ha_ref_chassis_map)
{
    struct hmap ha_ch_grps = HMAP_INITIALIZER(&ha_ch_grps);
    struct ha_chassis_group_node *ha_ch_grp_node;

    /* Initialize a set of all ha_chassis_groups in SB. */
    const struct sbrec_ha_chassis_group *ha_ch_grp;
    SBREC_HA_CHASSIS_GROUP_TABLE_FOR_EACH (ha_ch_grp,
                                    input_data->sbrec_ha_chassis_group_table) {
        ha_ch_grp_node = xzalloc(sizeof *ha_ch_grp_node);
        ha_ch_grp_node->ha_ch_grp = ha_ch_grp;
        hmap_insert(&ha_ch_grps, &ha_ch_grp_node->hmap_node,
                    uuid_hash(&ha_ch_grp->header_.uuid));
    }

    /* Update each group and remove it from the set. */
    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, ha_ref_chassis_map) {
        struct ha_ref_chassis_info *ha_ref_info = node->data;
        sbrec_ha_chassis_group_set_ref_chassis(ha_ref_info->ha_chassis_group,
                                               ha_ref_info->ref_chassis,
                                               ha_ref_info->n_ref_chassis);

        /* Remove the updated group from the set. */
        HMAP_FOR_EACH_WITH_HASH (ha_ch_grp_node, hmap_node,
            uuid_hash(&ha_ref_info->ha_chassis_group->header_.uuid),
            &ha_ch_grps) {
            if (ha_ch_grp_node->ha_ch_grp == ha_ref_info->ha_chassis_group) {
                hmap_remove(&ha_ch_grps, &ha_ch_grp_node->hmap_node);
                free(ha_ch_grp_node);
                break;
            }
        }
        free(ha_ref_info->ref_chassis);
        free(ha_ref_info);
        shash_delete(ha_ref_chassis_map, node);
    }

    /* Now the rest of the groups don't have any ref-chassis, so clear the SB
     * field for those records. */
    HMAP_FOR_EACH_SAFE (ha_ch_grp_node, hmap_node, &ha_ch_grps) {
        sbrec_ha_chassis_group_set_ref_chassis(ha_ch_grp_node->ha_ch_grp,
                                               NULL, 0);
        hmap_remove(&ha_ch_grps, &ha_ch_grp_node->hmap_node);
        free(ha_ch_grp_node);
    }

    hmap_destroy(&ha_ch_grps);
}

/* This function checks if the port binding 'sb' references
 * a HA chassis group.
 * Eg. Suppose a distributed logical router port - lr0-public
 * uses an HA chassis group - hagrp1 and if hagrp1 has 3 ha
 * chassis - gw1, gw2 and gw3.
 * Or
 * If the distributed logical router port - lr0-public has
 * 3 gateway chassis - gw1, gw2 and gw3.
 * ovn-northd creates ha chassis group - hagrp1 in SB DB
 * and adds gw1, gw2 and gw3 to its ha_chassis list.
 *
 * If port binding 'sb' represents a logical switch port 'p1'
 * and its logical switch is connected to the logical router
 * 'lr0' directly or indirectly (i.e p1's logical switch is
 *  connected to a router 'lr1' and 'lr1' has a path to lr0 via
 *  transit logical switches) and 'sb' is claimed by chassis - 'c1' then
 * this function adds c1 to the list of the reference chassis
 *  - 'ref_chassis' of hagrp1.
 */
static void
build_ha_chassis_group_ref_chassis(struct northd_input *input_data,
                                   const struct sbrec_port_binding *sb,
                                   struct ovn_port *op,
                                   struct shash *ha_ref_chassis_map)
{
    struct lrouter_group *lr_group = NULL;
    for (size_t i = 0; i < op->od->n_router_ports; i++) {
        if (!op->od->router_ports[i]->peer) {
            continue;
        }

        lr_group = op->od->router_ports[i]->peer->od->lr_group;
        /* If a logical switch has multiple router ports, then
         * all the logical routers belong to the same logical
         * router group. */
        break;
    }

    if (!lr_group) {
        return;
    }

    const char *ha_group_name;
    SSET_FOR_EACH (ha_group_name, &lr_group->ha_chassis_groups) {
        const struct sbrec_ha_chassis_group *sb_ha_chassis_grp;
        sb_ha_chassis_grp = ha_chassis_group_lookup_by_name(
            input_data->sbrec_ha_chassis_grp_by_name, ha_group_name);

        if (sb_ha_chassis_grp) {
            struct ha_ref_chassis_info *ref_ch_info =
            shash_find_data(ha_ref_chassis_map, sb_ha_chassis_grp->name);
            ovs_assert(ref_ch_info);
            add_to_ha_ref_chassis_info(ref_ch_info, sb->chassis);
        }
    }
}

/* Handle changes to the 'chassis' column of the 'Port_Binding' table.  When
 * this column is not empty, it means we need to set the corresponding logical
 * port as 'up' in the northbound DB. */
static void
handle_port_binding_changes(struct northd_input *input_data,
                            struct ovsdb_idl_txn *ovnsb_txn,
                            struct hmap *ports,
                            struct shash *ha_ref_chassis_map)
{
    const struct sbrec_port_binding *sb;
    bool build_ha_chassis_ref = false;
    if (ovnsb_txn) {
        const struct sbrec_ha_chassis_group *ha_ch_grp;
        SBREC_HA_CHASSIS_GROUP_TABLE_FOR_EACH (ha_ch_grp,
                                    input_data->sbrec_ha_chassis_group_table) {
            if (ha_ch_grp->n_ha_chassis > 1) {
                struct ha_ref_chassis_info *ref_ch_info =
                    xzalloc(sizeof *ref_ch_info);
                ref_ch_info->ha_chassis_group = ha_ch_grp;
                build_ha_chassis_ref = true;
                shash_add(ha_ref_chassis_map, ha_ch_grp->name, ref_ch_info);
            }
        }
    }

    SBREC_PORT_BINDING_TABLE_FOR_EACH (sb,
                                       input_data->sbrec_port_binding_table) {
        struct ovn_port *op = ovn_port_find(ports, sb->logical_port);

        if (!op || !op->nbsp) {
            /* The logical port doesn't exist for this port binding.  This can
             * happen under normal circumstances when ovn-northd hasn't gotten
             * around to pruning the Port_Binding yet. */
            continue;
        }

        bool up = false;

        if (lsp_is_router(op->nbsp)) {
            up = true;
        } else if (sb->chassis) {
            up = smap_get_bool(&sb->chassis->other_config,
                               OVN_FEATURE_PORT_UP_NOTIF, false)
                 ? sb->n_up && sb->up[0]
                 : true;
        }

        if (!op->nbsp->up || *op->nbsp->up != up) {
            nbrec_logical_switch_port_set_up(op->nbsp, &up, 1);
        }

        if (build_ha_chassis_ref && ovnsb_txn && sb->chassis) {
            /* Check and add the chassis which has claimed this 'sb'
             * to the ha chassis group's ref_chassis if required. */
            build_ha_chassis_group_ref_chassis(input_data, sb, op,
                                               ha_ref_chassis_map);
        }
    }
}

/* Handle a fairly small set of changes in the southbound database. */
static void
ovnsb_db_run(struct northd_input *input_data,
             struct ovsdb_idl_txn *ovnnb_txn,
             struct ovsdb_idl_txn *ovnsb_txn,
             struct hmap *ports)
{
    if (!ovnnb_txn ||
        !ovsdb_idl_has_ever_connected(ovsdb_idl_txn_get_idl(ovnsb_txn))) {
        return;
    }

    struct shash ha_ref_chassis_map = SHASH_INITIALIZER(&ha_ref_chassis_map);
    handle_port_binding_changes(input_data,
                                ovnsb_txn, ports, &ha_ref_chassis_map);
    if (ovnsb_txn) {
        update_sb_ha_group_ref_chassis(input_data,
                                       &ha_ref_chassis_map);
    }
    shash_destroy(&ha_ref_chassis_map);
}

void northd_run(struct northd_input *input_data,
                struct northd_data *data,
                struct ovsdb_idl_txn *ovnnb_txn,
                struct ovsdb_idl_txn *ovnsb_txn)
{
    stopwatch_start(OVNNB_DB_RUN_STOPWATCH_NAME, time_msec());
    ovnnb_db_run(input_data, data, ovnnb_txn, ovnsb_txn,
                 input_data->sbrec_chassis_by_name,
                 input_data->sbrec_chassis_by_hostname);
    stopwatch_stop(OVNNB_DB_RUN_STOPWATCH_NAME, time_msec());
    stopwatch_start(OVNSB_DB_RUN_STOPWATCH_NAME, time_msec());
    ovnsb_db_run(input_data, ovnnb_txn, ovnsb_txn, &data->ports);
    stopwatch_stop(OVNSB_DB_RUN_STOPWATCH_NAME, time_msec());
}

const char *
northd_get_svc_monitor_mac(void)
{
    return svc_monitor_mac;
}
