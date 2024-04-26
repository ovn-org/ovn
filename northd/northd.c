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

#include "aging.h"
#include "debug.h"
#include "bitmap.h"
#include "coverage.h"
#include "dirs.h"
#include "en-meters.h"
#include "en-port-group.h"
#include "ipam.h"
#include "openvswitch/dynamic-string.h"
#include "hash.h"
#include "hmapx.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "ovn/lex.h"
#include "lb.h"
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
#include "lflow-mgr.h"
#include "memory.h"
#include "northd.h"
#include "en-global-config.h"
#include "en-lb-data.h"
#include "en-lr-nat.h"
#include "en-lr-stateful.h"
#include "en-ls-stateful.h"
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


static bool check_lsp_is_up;

static bool install_ls_lb_from_router;

/* Use common zone for SNAT and DNAT if this option is set to "true". */
static bool use_common_zone = false;

/* If this option is 'true' northd will make use of ct.inv match fields.
 * Otherwise, it will avoid using it.  The default is true. */
static bool use_ct_inv_match = true;

/* If this option is 'true' northd will implicitly add a lowest-priority
 * drop rule in the ACL stage of logical switches that have at least one
 * ACL.
 */
static bool default_acl_drop;

#define MAX_OVN_TAGS 4096


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
#define REGBIT_ACL_STATELESS      "reg0[16]"
#define REGBIT_ACL_HINT_ALLOW_REL "reg0[17]"

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

/* Registers for ACL evaluation */
#define REGBIT_ACL_VERDICT_ALLOW "reg8[16]"
#define REGBIT_ACL_VERDICT_DROP "reg8[17]"
#define REGBIT_ACL_VERDICT_REJECT "reg8[18]"
#define REG_ACL_TIER "reg8[30..31]"

/* Indicate that this packet has been recirculated using egress
 * loopback.  This allows certain checks to be bypassed, such as a
 * logical router dropping packets with source IP address equals
 * one of the logical router's own IP addresses. */
#define REGBIT_EGRESS_LOOPBACK  "reg9[0]"
/* Register to store the result of check_pkt_larger action. */
/* This register is also used by ovn-controller in
 * OFTABLE_OUTPUT_LARGE_PKT_DETECT table, for a similar goal. */
#define REGBIT_PKT_LARGER        "reg9[1]"
#define REGBIT_LOOKUP_NEIGHBOR_RESULT "reg9[2]"
#define REGBIT_LOOKUP_NEIGHBOR_IP_RESULT "reg9[3]"
#define REGBIT_DST_NAT_IP_LOCAL "reg9[4]"
#define REGBIT_KNOWN_LB_SESSION "reg9[6]"
#define REGBIT_DHCP_RELAY_REQ_CHK "reg9[7]"
#define REGBIT_DHCP_RELAY_RESP_CHK "reg9[8]"

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
#define REG_DHCP_RELAY_DIP_IPV4 "reg2"
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
 * |    |     REGBIT_ACL_{LABEL/STATELESS}             | X |                                   |
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
 * | R2     REG_DHCP_RELAY_DIP_IPV4  | X |                 | 0 |                                    |
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
 * |     |REGBIT_DHCP_RELAY_REQ_CHK/ |   |                 |
 * |     |REGBIT_DHCP_RELAY_RESP_CHK}|   |                 |
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

/* Returns the type of the datapath to which a flow with the given 'stage' may
 * be added. */
enum ovn_datapath_type
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

static uint32_t
allocate_queueid(unsigned long *queue_id_bitmap)
{
    uint32_t queue_id = bitmap_scan(queue_id_bitmap, 0, 1,
                                    QDISC_MAX_QUEUE_ID + 1);
    if (queue_id == QDISC_MAX_QUEUE_ID + 1) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "all queue ids exhausted");
        return 0;
    }
    bitmap_set1(queue_id_bitmap, queue_id);

    return queue_id;
}

static inline bool
port_has_qos_params(const struct smap *opts)
{
    return (smap_get(opts, "qos_max_rate") || smap_get(opts, "qos_min_rate") ||
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
ls_has_lb_vip(const struct ovn_datapath *od)
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
lr_has_lb_vip(const struct ovn_datapath *od)
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

bool
od_has_lb_vip(const struct ovn_datapath *od)
{
    if (od->nbs) {
        return ls_has_lb_vip(od);
    } else {
        return lr_has_lb_vip(od);
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
    /* Temporary storage for chassis references while computing HA groups. */
    struct hmapx tmp_ha_ref_chassis;
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
    od->port_key_hint = 0;
    hmap_insert(datapaths, &od->key_node, uuid_hash(&od->key));
    od->lr_group = NULL;
    hmap_init(&od->ports);
    sset_init(&od->router_ips);
    return od;
}

static void destroy_mcast_info_for_datapath(struct ovn_datapath *od);

static void
destroy_ports_for_datapath(struct ovn_datapath *od)
{
    ovs_assert(hmap_is_empty(&od->ports));
    hmap_destroy(&od->ports);
}

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
        free(od->localnet_ports);
        free(od->l3dgw_ports);
        destroy_mcast_info_for_datapath(od);
        destroy_ports_for_datapath(od);
        sset_destroy(&od->router_ips);
        free(od);
    }
}

static struct ovn_datapath *
ovn_datapath_find_(const struct hmap *datapaths,
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

const struct ovn_datapath *
ovn_datapath_find(const struct hmap *datapaths,
                  const struct uuid *uuid)
{
    return ovn_datapath_find_(datapaths, uuid);
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

struct ovn_datapath *
ovn_datapath_from_sbrec(const struct hmap *ls_datapaths,
                        const struct hmap *lr_datapaths,
                        const struct sbrec_datapath_binding *sb)
{
    struct uuid key;
    const struct hmap *dps;

    if (smap_get_uuid(&sb->external_ids, "logical-switch", &key)) {
        dps = ls_datapaths;
    } else if (smap_get_uuid(&sb->external_ids, "logical-router", &key)) {
        dps = lr_datapaths;
    } else {
        return NULL;
    }
    if (!dps) {
        return NULL;
    }
    struct ovn_datapath *od = ovn_datapath_find_(dps, &key);
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
    ovs_assert(od->nbs);

    struct mcast_switch_info *mcast_sw_info = &od->mcast_info.sw;
    atomic_init(&mcast_sw_info->active_v4_flows, 0);
    atomic_init(&mcast_sw_info->active_v6_flows, 0);
}

static void
init_mcast_info_for_datapath(struct ovn_datapath *od)
{
    if (!od->nbr && !od->nbs) {
        return;
    }

    hmap_init(&od->mcast_info.group_tnlids);
    /* allocations start from hint + 1 */
    od->mcast_info.group_tnlid_hint = OVN_MIN_IP_MULTICAST - 1;
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

        uint32_t age_threshold = smap_get_uint(&od->nbs->other_config,
                                               "fdb_age_threshold", 0);
        if (age_threshold) {
            smap_add_format(&ids, "fdb_age_threshold",
                            "%u", age_threshold);
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

        /* For timestamp refreshing, the smallest threshold of the option is
         * set to SB to make sure all entries are refreshed in time.
         * XXX: This approach simplifies processing in ovn-controller, but it
         * may be enhanced, if necessary, to parse the complete CIDR-based
         * threshold configurations to SB to reduce unnecessary refreshes. */
        uint32_t age_threshold = min_mac_binding_age_threshold(
                                       smap_get(&od->nbr->options,
                                               "mac_binding_age_threshold"));
        if (age_threshold) {
            smap_add_format(&ids, "mac_binding_age_threshold",
                            "%u", age_threshold);
        }
    }

    sbrec_datapath_binding_set_external_ids(od->sb, &ids);
    smap_destroy(&ids);
}

static void
join_datapaths(const struct nbrec_logical_switch_table *nbrec_ls_table,
               const struct nbrec_logical_router_table *nbrec_lr_table,
               const struct sbrec_datapath_binding_table *sbrec_dp_table,
               struct ovsdb_idl_txn *ovnsb_txn,
               struct hmap *datapaths, struct ovs_list *sb_only,
               struct ovs_list *nb_only, struct ovs_list *both,
               struct ovs_list *lr_list)
{
    ovs_list_init(sb_only);
    ovs_list_init(nb_only);
    ovs_list_init(both);

    const struct sbrec_datapath_binding *sb;
    SBREC_DATAPATH_BINDING_TABLE_FOR_EACH_SAFE (sb, sbrec_dp_table) {
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

        if (ovn_datapath_find_(datapaths, &key)) {
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
    NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH (nbs, nbrec_ls_table) {
        struct ovn_datapath *od = ovn_datapath_find_(datapaths,
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
    }

    const struct nbrec_logical_router *nbr;
    NBREC_LOGICAL_ROUTER_TABLE_FOR_EACH (nbr, nbrec_lr_table) {
        if (!lrouter_is_enabled(nbr)) {
            continue;
        }

        struct ovn_datapath *od = ovn_datapath_find_(datapaths,
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
        if (smap_get(&od->nbr->options, "chassis")) {
            od->is_gw_router = true;
        }
        ovs_list_push_back(lr_list, &od->lr_list);
    }
}

static bool
is_vxlan_mode(const struct sbrec_chassis_table *sbrec_chassis_table)
{
    const struct sbrec_chassis *chassis;
    SBREC_CHASSIS_TABLE_FOR_EACH (chassis, sbrec_chassis_table) {
        for (int i = 0; i < chassis->n_encaps; i++) {
            if (!strcmp(chassis->encaps[i]->type, "vxlan")) {
                return true;
            }
        }
    }
    return false;
}

uint32_t
get_ovn_max_dp_key_local(const struct sbrec_chassis_table *sbrec_chassis_table)
{
    if (is_vxlan_mode(sbrec_chassis_table)) {
        /* OVN_MAX_DP_GLOBAL_NUM doesn't apply for vxlan mode. */
        return OVN_MAX_DP_VXLAN_KEY;
    }
    return OVN_MAX_DP_KEY - OVN_MAX_DP_GLOBAL_NUM;
}

static void
ovn_datapath_allocate_key(const struct sbrec_chassis_table *sbrec_ch_table,
                          struct hmap *datapaths, struct hmap *dp_tnlids,
                          struct ovn_datapath *od, uint32_t *hint)
{
    if (!od->tunnel_key) {
        od->tunnel_key = ovn_allocate_tnlid(dp_tnlids, "datapath",
                                    OVN_MIN_DP_KEY_LOCAL,
                                    get_ovn_max_dp_key_local(sbrec_ch_table),
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
ovn_datapath_assign_requested_tnl_id(
    const struct sbrec_chassis_table *sbrec_chassis_table,
    struct hmap *dp_tnlids, struct ovn_datapath *od)
{
    const struct smap *other_config = (od->nbs
                                       ? &od->nbs->other_config
                                       : &od->nbr->options);
    uint32_t tunnel_key = smap_get_int(other_config, "requested-tnl-key", 0);
    if (tunnel_key) {
        const char *interconn_ts = smap_get(other_config, "interconn-ts");
        if (!interconn_ts && is_vxlan_mode(sbrec_chassis_table) &&
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

static void
ods_build_array_index(struct ovn_datapaths *datapaths)
{
    /* Assign unique sequential indexes to all datapaths.  These are not
     * visible outside of the northd loop, so, unlike the tunnel keys, it
     * doesn't matter if they are different on every iteration. */
    size_t index = 0;

    datapaths->array = xrealloc(datapaths->array,
                            ods_size(datapaths) * sizeof *datapaths->array);

    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &datapaths->datapaths) {
        od->index = index;
        datapaths->array[index++] = od;
        od->datapaths = datapaths;
    }
}

/* Updates the southbound Datapath_Binding table so that it contains the
 * logical switches and routers specified by the northbound database.
 *
 * Initializes 'datapaths' to contain a "struct ovn_datapath" for every logical
 * switch and router. */
static void
build_datapaths(struct ovsdb_idl_txn *ovnsb_txn,
                const struct nbrec_logical_switch_table *nbrec_ls_table,
                const struct nbrec_logical_router_table *nbrec_lr_table,
                const struct sbrec_datapath_binding_table *sbrec_dp_table,
                const struct sbrec_chassis_table *sbrec_chassis_table,
                struct ovn_datapaths *ls_datapaths,
                struct ovn_datapaths *lr_datapaths,
                struct ovs_list *lr_list)
{
    struct ovs_list sb_only, nb_only, both;

    struct hmap *datapaths = &ls_datapaths->datapaths;
    join_datapaths(nbrec_ls_table, nbrec_lr_table, sbrec_dp_table, ovnsb_txn,
                   datapaths, &sb_only, &nb_only, &both, lr_list);

    /* Assign explicitly requested tunnel ids first. */
    struct hmap dp_tnlids = HMAP_INITIALIZER(&dp_tnlids);
    struct ovn_datapath *od;
    LIST_FOR_EACH (od, list, &both) {
        ovn_datapath_assign_requested_tnl_id(sbrec_chassis_table, &dp_tnlids,
                                             od);
    }
    LIST_FOR_EACH (od, list, &nb_only) {
        ovn_datapath_assign_requested_tnl_id(sbrec_chassis_table, &dp_tnlids,
                                             od); }

    /* Keep nonconflicting tunnel IDs that are already assigned. */
    LIST_FOR_EACH (od, list, &both) {
        if (!od->tunnel_key && ovn_add_tnlid(&dp_tnlids, od->sb->tunnel_key)) {
            od->tunnel_key = od->sb->tunnel_key;
        }
    }

    /* Assign new tunnel ids where needed. */
    uint32_t hint = 0;
    LIST_FOR_EACH_SAFE (od, list, &both) {
        ovn_datapath_allocate_key(sbrec_chassis_table,
                                  datapaths, &dp_tnlids, od, &hint);
    }
    LIST_FOR_EACH_SAFE (od, list, &nb_only) {
        ovn_datapath_allocate_key(sbrec_chassis_table,
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

    /* Move lr datapaths to lr_datapaths, and ls datapaths will
     * remain in datapaths/ls_datapaths. */
    HMAP_FOR_EACH_SAFE (od, key_node, datapaths) {
        if (!od->nbr) {
            ovs_assert(od->nbs);
            continue;
        }
        hmap_remove(datapaths, &od->key_node);
        hmap_insert(&lr_datapaths->datapaths, &od->key_node,
                    od->key_node.hash);
    }

    ods_build_array_index(ls_datapaths);
    ods_build_array_index(lr_datapaths);
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

static bool lsp_can_be_inc_processed(const struct nbrec_logical_switch_port *);

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
                                bool routable_only, bool include_lb_ips,
                                const struct lr_stateful_record *);

static struct ovn_port_routable_addresses
get_op_routable_addresses(struct ovn_port *op,
                          const struct lr_stateful_record *lr_stateful_rec)
{
    size_t n;
    char **nats = get_nat_addresses(op, &n, true, true, lr_stateful_rec);

    if (!nats) {
        return (struct ovn_port_routable_addresses) {
            .laddrs = NULL,
            .n_addrs = 0,
        };
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

    if (!n_addrs) {
        free(laddrs);
        laddrs = NULL;
    }

    return (struct ovn_port_routable_addresses) {
        .laddrs = laddrs,
        .n_addrs = n_addrs,
    };
}


static void
ovn_port_set_nb(struct ovn_port *op,
                const struct nbrec_logical_switch_port *nbsp,
                const struct nbrec_logical_router_port *nbrp)
{
    op->nbsp = nbsp;
    if (nbsp) {
        op->lsp_can_be_inc_processed = lsp_can_be_inc_processed(nbsp);
    }
    op->nbrp = nbrp;
    init_mcast_port_info(&op->mcast_info, op->nbsp, op->nbrp);
}

static bool lsp_is_router(const struct nbrec_logical_switch_port *nbsp);

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

    op->lflow_ref = lflow_ref_create();
    op->stateful_lflow_ref = lflow_ref_create();

    return op;
}

static void
ovn_port_cleanup(struct ovn_port *port)
{
    if (port->tunnel_key) {
        ovs_assert(port->od);
        ovn_free_tnlid(&port->od->port_tnlids, port->tunnel_key);
    }
    for (int i = 0; i < port->n_lsp_addrs; i++) {
        destroy_lport_addresses(&port->lsp_addrs[i]);
    }
    free(port->lsp_addrs);
    port->n_lsp_addrs = 0;
    port->lsp_addrs = NULL;

    if (port->peer) {
        port->peer->peer = NULL;
    }

    for (int i = 0; i < port->n_ps_addrs; i++) {
        destroy_lport_addresses(&port->ps_addrs[i]);
    }
    free(port->ps_addrs);
    port->ps_addrs = NULL;
    port->n_ps_addrs = 0;

    destroy_lport_addresses(&port->lrp_networks);
    destroy_lport_addresses(&port->proxy_arp_addrs);
}

static void
ovn_port_destroy_orphan(struct ovn_port *port)
{
    ovn_port_cleanup(port);
    free(port->json_key);
    free(port->key);
    lflow_ref_destroy(port->lflow_ref);
    lflow_ref_destroy(port->stateful_lflow_ref);

    free(port);
}

static void
ovn_port_destroy(struct hmap *ports, struct ovn_port *port)
{
    if (port) {
        /* Don't remove port->list. The node should be removed from such lists
         * before calling this function. */
        hmap_remove(ports, &port->key_node);
        if (port->od && !port->l3dgw_port) {
            hmap_remove(&port->od->ports, &port->dp_node);
        }
        ovn_port_destroy_orphan(port);
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

static bool
lsp_is_clone_to_unknown(const struct nbrec_logical_switch_port *nbsp)
{
    if (!nbsp->type[0]) {
        /* Check this option only for VIF logical port. */
        const char *pkt_clone_type = smap_get(&nbsp->options,
                                              "pkt_clone_type");
        if (pkt_clone_type && !strcasecmp(pkt_clone_type, "mc_unknown")) {
            return true;
        }
    }
    return false;
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
lsp_disable_arp_nd_rsp(const struct nbrec_logical_switch_port *nbsp)
{
    return smap_get_bool(&nbsp->options, "disable_arp_nd_rsp", false);
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
ovn_port_get_peer(const struct hmap *lr_ports, struct ovn_port *op)
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

    return ovn_port_find(lr_ports, peer_name);
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
ipam_insert_lsp_addresses(struct ovn_datapath *od,
                          struct lport_addresses *laddrs)
{
    ipam_insert_mac(&laddrs->ea, true);

    /* IP is only added to IPAM if the switch's subnet option
     * is set, whereas MAC is always added to MACAM. */
    if (!od->ipam_info.allocated_ipv4s) {
        return;
    }

    for (size_t j = 0; j < laddrs->n_ipv4_addrs; j++) {
        uint32_t ip = ntohl(laddrs->ipv4_addrs[j].addr);
        ipam_insert_ip_for_datapath(od, ip);
    }
}

static void
ipam_add_port_addresses(struct ovn_datapath *od, struct ovn_port *op)
{
    if (!od || !op) {
        return;
    }

    if (op->n_lsp_non_router_addrs) {
        /* Add all the port's addresses to address data structures. */
        for (size_t i = 0; i < op->n_lsp_non_router_addrs; i++) {
            ipam_insert_lsp_addresses(od, &op->lsp_addrs[i]);
        }
    } else if (op->lrp_networks.ea_s[0]) {
        ipam_insert_mac(&op->lrp_networks.ea, true);

        if (!op->peer || !op->peer->nbsp || !op->peer->od || !op->peer->od->nbs
            || !smap_get(&op->peer->od->nbs->other_config, "subnet")) {
            return;
        }

        for (size_t i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            uint32_t ip = ntohl(op->lrp_networks.ipv4_addrs[i].addr);
            /* If the router has the first IP address of the subnet, don't add
             * it to IPAM. We already added this when we initialized IPAM for
             * the datapath. This will just result in an erroneous message
             * about a duplicate IP address.
             */
            if (ip != op->peer->od->ipam_info.start_ipv4) {
                ipam_insert_ip_for_datapath(op->peer->od, ip);
            }
        }
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
build_ipam(struct hmap *ls_datapaths, struct hmap *ls_ports)
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
    HMAP_FOR_EACH (od, key_node, ls_datapaths) {
        ovs_assert(od->nbs);

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

            struct ovn_port *op = ovn_port_find(ls_ports, nbsp->name);
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
parse_lsp_addrs(struct ovn_port *op)
{
    const struct nbrec_logical_switch_port *nbsp = op->nbsp;
    ovs_assert(nbsp);
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
    op->n_lsp_non_router_addrs = op->n_lsp_addrs;

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
}

static void
join_logical_ports(const struct sbrec_port_binding_table *sbrec_pb_table,
                   struct hmap *ls_datapaths, struct hmap *lr_datapaths,
                   struct hmap *ports, unsigned long *queue_id_bitmap,
                   struct hmap *tag_alloc_table, struct ovs_list *sb_only,
                   struct ovs_list *nb_only, struct ovs_list *both)
{
    ovs_list_init(sb_only);
    ovs_list_init(nb_only);
    ovs_list_init(both);

    const struct sbrec_port_binding *sb;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (sb, sbrec_pb_table) {
        struct ovn_port *op = ovn_port_create(ports, sb->logical_port,
                                              NULL, NULL, sb);
        ovs_list_push_back(sb_only, &op->list);
    }

    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, ls_datapaths) {
        ovs_assert(od->nbs);
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
                    if (queue_id) {
                        bitmap_set1(queue_id_bitmap, queue_id);
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

            parse_lsp_addrs(op);

            op->od = od;
            if (op->has_unknown) {
                od->has_unknown = true;
            }
            hmap_insert(&od->ports, &op->dp_node,
                        hmap_node_hash(&op->key_node));
            tag_alloc_add_existing_tags(tag_alloc_table, nbsp);
        }
    }
    HMAP_FOR_EACH (od, key_node, lr_datapaths) {
        ovs_assert(od->nbr);
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

            for (size_t j = 0; j < op->lrp_networks.n_ipv4_addrs; j++) {
                sset_add(&op->od->router_ips,
                         op->lrp_networks.ipv4_addrs[j].addr_s);
            }
            for (size_t j = 0; j < op->lrp_networks.n_ipv6_addrs; j++) {
                /* Exclude the LLA. */
                if (!in6_is_lla(&op->lrp_networks.ipv6_addrs[j].addr)) {
                    sset_add(&op->od->router_ips,
                             op->lrp_networks.ipv6_addrs[j].addr_s);
                }
            }

            hmap_insert(&od->ports, &op->dp_node,
                        hmap_node_hash(&op->key_node));

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

            /* For LSP of router type arp proxy can be activated so
             * it needs to be parsed
             * either takes "MAC IP1 IP2" or "IP1 IP2"
             */
            const char *arp_proxy = smap_get(&op->nbsp->options,"arp_proxy");
            int ofs = 0;
            if (arp_proxy) {
                if (extract_addresses(arp_proxy, &op->proxy_arp_addrs, &ofs) ||
                    extract_ip_addresses(arp_proxy, &op->proxy_arp_addrs)) {
                    op->od->has_arp_proxy_port = true;
                } else {
                    static struct vlog_rate_limit rl =
                        VLOG_RATE_LIMIT_INIT(1, 5);
                    VLOG_WARN_RL(&rl,
                        "Invalid arp_proxy option: '%s' at lsp '%s'",
                        arp_proxy, op->nbsp->name);
                }
            }

            /* Only used for the router type LSP whose peer is l3dgw_port */
            if (op->peer && is_l3dgw_port(op->peer)) {
                op->enable_router_port_acl = smap_get_bool(
                    &op->nbsp->options, "enable_router_port_acl", false);
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
                  bool include_lb_ips,
                  const struct lr_stateful_record *lr_stateful_rec)
{
    size_t n_nats = 0;
    struct eth_addr mac;
    if (!op || !op->nbrp || !op->od || !op->od->nbr
        || (!op->od->nbr->n_nat
            && !lr_stateful_rec_has_lb_vip(lr_stateful_rec))
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

    if (include_lb_ips && lr_stateful_rec) {
        const char *ip_address;
        if (routable_only) {
            SSET_FOR_EACH (ip_address,
                           &lr_stateful_rec->lb_ips->ips_v4_routable) {
                ds_put_format(&c_addresses, " %s", ip_address);
                central_ip_address = true;
            }
            SSET_FOR_EACH (ip_address,
                           &lr_stateful_rec->lb_ips->ips_v6_routable) {
                ds_put_format(&c_addresses, " %s", ip_address);
                central_ip_address = true;
            }
        } else {
            SSET_FOR_EACH (ip_address, &lr_stateful_rec->lb_ips->ips_v4) {
                ds_put_format(&c_addresses, " %s", ip_address);
                central_ip_address = true;
            }
            SSET_FOR_EACH (ip_address, &lr_stateful_rec->lb_ips->ips_v6) {
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
sync_ha_chassis_group_for_sbpb(
    struct ovsdb_idl_txn *ovnsb_txn,
    struct ovsdb_idl_index *sbrec_chassis_by_name,
    struct ovsdb_idl_index *sbrec_ha_chassis_grp_by_name,
    const struct nbrec_ha_chassis_group *nb_ha_grp,
    const struct sbrec_port_binding *pb)
{
    bool new_sb_chassis_group = false;
    const struct sbrec_ha_chassis_group *sb_ha_grp =
        ha_chassis_group_lookup_by_name(
            sbrec_ha_chassis_grp_by_name, nb_ha_grp->name);

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
        struct ovsdb_idl_txn *ovnsb_txn,
        struct ovsdb_idl_index *sbrec_chassis_by_name,
        struct ovsdb_idl_index *sbrec_ha_chassis_grp_by_name,
        const struct nbrec_logical_router_port *lrp,
        const struct sbrec_port_binding *port_binding)
{

    /* Make use of the new HA chassis group table to support HA
     * for the distributed gateway router port. */
    const struct sbrec_ha_chassis_group *sb_ha_chassis_group =
        ha_chassis_group_lookup_by_name(
            sbrec_ha_chassis_grp_by_name, lrp->name);
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
ovn_update_ipv6_prefix(struct hmap *lr_ports)
{
    const struct ovn_port *op;
    HMAP_FOR_EACH (op, key_node, lr_ports) {
        ovs_assert(op->nbrp);

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
check_and_do_sb_mirror_addition(
    const struct sbrec_mirror_table *sbrec_mirror_table,
    const struct ovn_port *op)
{
    for (size_t i = 0; i < op->nbsp->n_mirror_rules; i++) {
        const struct sbrec_mirror *sb_mirror;
        SBREC_MIRROR_TABLE_FOR_EACH (sb_mirror,
                                     sbrec_mirror_table) {
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
sbrec_port_binding_update_mirror_rules(
    const struct sbrec_mirror_table *sbrec_mirror_table,
    const struct ovn_port *op)
{
    check_and_do_sb_mirror_deletion(op);
    check_and_do_sb_mirror_addition(sbrec_mirror_table, op);
}

/* Return true if given ovn_port has peer and this peer's ovn_datapath
 * has_vtep_lports set to true. False otherwise. */
static bool
l3dgw_port_has_associated_vtep_lports(const struct ovn_port *op)
{
    return op->peer && op->peer->od->has_vtep_lports;
}

static void
ovn_port_update_sbrec(struct ovsdb_idl_txn *ovnsb_txn,
                      struct ovsdb_idl_index *sbrec_chassis_by_name,
                      struct ovsdb_idl_index *sbrec_chassis_by_hostname,
                      struct ovsdb_idl_index *sbrec_ha_chassis_grp_by_name,
                      const struct sbrec_mirror_table *sbrec_mirror_table,
                      const struct ovn_port *op,
                      unsigned long *queue_id_bitmap,
                      struct sset *active_ha_chassis_grps)
{
    sbrec_port_binding_set_datapath(op->sb, op->od->sb);
    if (op->nbrp) {
        /* Note: SB port binding options for router ports are set in
         * sync_pbs(). */

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

        if (is_cr_port(op)) {
            ovs_assert(sbrec_chassis_by_name);
            ovs_assert(sbrec_chassis_by_hostname);
            ovs_assert(sbrec_ha_chassis_grp_by_name);
            ovs_assert(active_ha_chassis_grps);

            if (op->nbrp->ha_chassis_group) {
                if (op->nbrp->n_gateway_chassis) {
                    static struct vlog_rate_limit rl
                        = VLOG_RATE_LIMIT_INIT(1, 1);
                    VLOG_WARN_RL(&rl, "Both ha_chassis_group and "
                                 "gateway_chassis configured on port %s; "
                                 "ignoring the latter.", op->nbrp->name);
                }

                /* HA Chassis group is set. Ignore 'gateway_chassis'. */
                sync_ha_chassis_group_for_sbpb(ovnsb_txn,
                                               sbrec_chassis_by_name,
                                               sbrec_ha_chassis_grp_by_name,
                                               op->nbrp->ha_chassis_group,
                                               op->sb);
                sset_add(active_ha_chassis_grps,
                         op->nbrp->ha_chassis_group->name);
            } else if (op->nbrp->n_gateway_chassis) {
                /* Legacy gateway_chassis support.
                 * Create ha_chassis_group for the Northbound gateway_chassis
                 * associated with the lrp. */
                if (sbpb_gw_chassis_needs_update(op->sb, op->nbrp,
                                                 sbrec_chassis_by_name)) {
                    copy_gw_chassis_from_nbrp_to_sbpb(
                        ovnsb_txn, sbrec_chassis_by_name,
                        sbrec_ha_chassis_grp_by_name, op->nbrp, op->sb);
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
        }

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
    } else {
        if (!lsp_is_router(op->nbsp)) {
            uint32_t queue_id = smap_get_int(
                    &op->sb->options, "qdisc_queue_id", 0);
            bool has_qos = port_has_qos_params(&op->nbsp->options);
            struct smap options;

            if (has_qos && !queue_id) {
                ovs_assert(queue_id_bitmap);
                queue_id = allocate_queueid(queue_id_bitmap);
            } else if (!has_qos && queue_id) {
                ovs_assert(queue_id_bitmap);
                bitmap_set0(queue_id_bitmap, queue_id);
                queue_id = 0;
            }

            smap_clone(&options, &op->nbsp->options);

            if (queue_id) {
                if (op->od->n_localnet_ports) {
                    struct ovn_port *port = op->od->localnet_ports[0];
                    const char *physical_network = smap_get(
                            &port->nbsp->options, "network_name");
                    if (physical_network) {
                        smap_add(&options, "qos_physical_network",
                                 physical_network);
                    }
                }
                smap_add_format(&options,
                                "qdisc_queue_id", "%d", queue_id);
            }

            if (smap_get_bool(&op->od->nbs->other_config, "vlan-passthru", false)) {
                smap_add(&options, "vlan-passthru", "true");
            }

            ovn_port_update_sbrec_chassis(sbrec_chassis_by_name,
                                          sbrec_chassis_by_hostname, op);

            /* Retain activated chassis flags. */
            if (op->sb->requested_additional_chassis) {
                const char *activated_str = smap_get(
                    &op->sb->options, "additional-chassis-activated");
                if (activated_str) {
                    smap_add(&options, "additional-chassis-activated",
                             activated_str);
                }
            }

            if (lsp_is_remote(op->nbsp)) {
                /* ovn-northd is supposed to set port_binding for remote ports
                 * if requested chassis is marked as remote. */
                if (op->sb->requested_chassis &&
                    smap_get_bool(&op->sb->requested_chassis->other_config,
                                  "is-remote", false)) {
                    sbrec_port_binding_set_chassis(op->sb,
                                                   op->sb->requested_chassis);
                    smap_add(&options, "is-remote-nb-bound", "true");
                } else if (smap_get_bool(&op->sb->options,
                                         "is-remote-nb-bound", false)) {
                    sbrec_port_binding_set_chassis(op->sb, NULL);
                    smap_add(&options, "is-remote-nb-bound", "false");
                }
            } else if (op->sb->chassis &&
                       smap_get_bool(&op->sb->chassis->other_config,
                                     "is-remote", false)) {
                /* Its not a remote port but if the chassis is set and if its a
                 * remote chassis then clear it. */
                sbrec_port_binding_set_chassis(op->sb, NULL);
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
                ovs_assert(sbrec_chassis_by_name);
                ovs_assert(sbrec_chassis_by_hostname);
                ovs_assert(sbrec_ha_chassis_grp_by_name);
                ovs_assert(active_ha_chassis_grps);
                if (op->nbsp->ha_chassis_group) {
                    sync_ha_chassis_group_for_sbpb(
                        ovnsb_txn, sbrec_chassis_by_name,
                        sbrec_ha_chassis_grp_by_name,
                        op->nbsp->ha_chassis_group,
                        op->sb);
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
        } else {
            if (op->sb->chassis &&
                smap_get_bool(&op->sb->chassis->other_config,
                              "is-remote", false)) {
                sbrec_port_binding_set_chassis(op->sb, NULL);
            }

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
            sbrec_port_binding_update_mirror_rules(sbrec_mirror_table, op);
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
cleanup_mac_bindings(
    const struct sbrec_mac_binding_table *sbrec_mac_binding_table,
    struct hmap *lr_datapaths, struct hmap *lr_ports)
{
    const struct sbrec_mac_binding *b;
    SBREC_MAC_BINDING_TABLE_FOR_EACH_SAFE (b, sbrec_mac_binding_table) {
        const struct ovn_datapath *od =
            ovn_datapath_from_sbrec(NULL, lr_datapaths, b->datapath);

        if (!od || ovn_datapath_is_stale(od) ||
                !ovn_port_find(lr_ports, b->logical_port)) {
            sbrec_mac_binding_delete(b);
        }
    }
}

static void
cleanup_sb_ha_chassis_groups(
    const struct sbrec_ha_chassis_group_table *sbrec_ha_chassis_group_table,
    struct sset *active_ha_chassis_groups)
{
    const struct sbrec_ha_chassis_group *b;
    SBREC_HA_CHASSIS_GROUP_TABLE_FOR_EACH_SAFE (b,
                                sbrec_ha_chassis_group_table) {
        if (!sset_contains(active_ha_chassis_groups, b->name)) {
            sbrec_ha_chassis_group_delete(b);
        }
    }
}

static void
cleanup_stale_fdb_entries(const struct sbrec_fdb_table *sbrec_fdb_table,
                          struct hmap *ls_datapaths)
{
    const struct sbrec_fdb *fdb_e;
    SBREC_FDB_TABLE_FOR_EACH_SAFE (fdb_e, sbrec_fdb_table) {
        bool delete = true;
        struct ovn_datapath *od
            = ovn_datapath_find_by_key(ls_datapaths, fdb_e->dp_key);
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

static void
delete_fdb_entry(struct ovsdb_idl_index *sbrec_fdb_by_dp_and_port,
                 uint32_t dp_key, uint32_t port_key)
{
    struct sbrec_fdb *target =
        sbrec_fdb_index_init_row(sbrec_fdb_by_dp_and_port);
    sbrec_fdb_index_set_dp_key(target, dp_key);
    sbrec_fdb_index_set_port_key(target, port_key);

    struct sbrec_fdb *fdb_e = sbrec_fdb_index_find(sbrec_fdb_by_dp_and_port,
                                                   target);
    sbrec_fdb_index_destroy_row(target);

    if (fdb_e) {
        sbrec_fdb_delete(fdb_e);
    }
}

struct service_monitor_info {
    struct hmap_node hmap_node;
    const struct sbrec_service_monitor *sbrec_mon;
    bool required;
};


static struct service_monitor_info *
get_service_mon(const struct hmap *monitor_map,
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

    return NULL;
}

static struct service_monitor_info *
create_or_get_service_mon(struct ovsdb_idl_txn *ovnsb_txn,
                          struct hmap *monitor_map,
                          const char *ip, const char *logical_port,
                          uint16_t service_port, const char *protocol,
                          const char *chassis_name)
{
    struct service_monitor_info *mon_info =
        get_service_mon(monitor_map, ip, logical_port, service_port,
                        protocol);

    if (mon_info) {
        if (chassis_name && strcmp(mon_info->sbrec_mon->chassis_name,
                                   chassis_name)) {
            sbrec_service_monitor_set_chassis_name(mon_info->sbrec_mon,
                                                   chassis_name);
        }
        return mon_info;
    }

    /* get_service_mon() also calculates the hash the same way. */
    uint32_t hash = service_port;
    hash = hash_string(ip, hash);
    hash = hash_string(logical_port, hash);

    struct sbrec_service_monitor *sbrec_mon =
        sbrec_service_monitor_insert(ovnsb_txn);
    sbrec_service_monitor_set_ip(sbrec_mon, ip);
    sbrec_service_monitor_set_port(sbrec_mon, service_port);
    sbrec_service_monitor_set_logical_port(sbrec_mon, logical_port);
    sbrec_service_monitor_set_protocol(sbrec_mon, protocol);
    if (chassis_name) {
        sbrec_service_monitor_set_chassis_name(sbrec_mon, chassis_name);
    }
    mon_info = xzalloc(sizeof *mon_info);
    mon_info->sbrec_mon = sbrec_mon;
    hmap_insert(monitor_map, &mon_info->hmap_node, hash);
    return mon_info;
}

static void
ovn_lb_svc_create(struct ovsdb_idl_txn *ovnsb_txn,
                  const struct ovn_northd_lb *lb,
                  const char *svc_monitor_mac,
                  const struct eth_addr *svc_monitor_mac_ea,
                  struct hmap *monitor_map, struct hmap *ls_ports,
                  struct sset *svc_monitor_lsps)
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

            if (!backend_nb->health_check) {
                continue;
            }

            sset_add(svc_monitor_lsps, backend_nb->logical_port);
            struct ovn_port *op = ovn_port_find(ls_ports,
                                                backend_nb->logical_port);

            if (!op || !lsp_is_enabled(op->nbsp)) {
                continue;
            }

            const char *protocol = lb->nlb->protocol;
            if (!protocol || !protocol[0]) {
                protocol = "tcp";
            }

            const char *chassis_name = NULL;
            if (op->sb && op->sb->chassis) {
                chassis_name = op->sb->chassis->name;
            }

            struct service_monitor_info *mon_info =
                create_or_get_service_mon(ovnsb_txn, monitor_map,
                                          backend->ip_str,
                                          backend_nb->logical_port,
                                          backend->port,
                                          protocol,
                                          chassis_name);
            ovs_assert(mon_info);
            sbrec_service_monitor_set_options(
                mon_info->sbrec_mon, &lb_vip_nb->lb_health_check->options);
            struct eth_addr ea;
            if (!mon_info->sbrec_mon->src_mac ||
                !eth_addr_from_string(mon_info->sbrec_mon->src_mac, &ea) ||
                !eth_addr_equals(ea, *svc_monitor_mac_ea)) {
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

            mon_info->required = true;
        }
    }
}

static bool
build_lb_vip_actions(const struct ovn_northd_lb *lb,
                     const struct ovn_lb_vip *lb_vip,
                     const struct ovn_northd_lb_vip *lb_vip_nb,
                     struct ds *action, char *selection_fields,
                     struct ds *skip_snat_action,
                     struct ds *force_snat_action,
                     bool ls_dp, const struct chassis_features *features,
                     const struct hmap *svc_monitor_map)
{
    const char *ct_lb_action =
        features->ct_no_masked_label ? "ct_lb_mark" : "ct_lb";
    bool reject = !lb_vip->n_backends && lb_vip->empty_backend_rej;
    bool drop = !lb_vip->n_backends && !lb_vip->empty_backend_rej;

    if (lb_vip_nb->lb_health_check) {
        ds_put_format(action, "%s(backends=", ct_lb_action);

        size_t n_active_backends = 0;
        for (size_t i = 0; i < lb_vip->n_backends; i++) {
            struct ovn_lb_backend *backend = &lb_vip->backends[i];
            struct ovn_northd_lb_backend *backend_nb =
                &lb_vip_nb->backends_nb[i];

            if (!backend_nb->health_check) {
                continue;
            }

            const char *protocol = lb->nlb->protocol;
            if (!protocol || !protocol[0]) {
                protocol = "tcp";
            }

            struct service_monitor_info *mon_info = get_service_mon(
                svc_monitor_map, backend->ip_str, backend_nb->logical_port,
                backend->port, protocol);

            if (!mon_info) {
                continue;
            }

            ovs_assert(mon_info->sbrec_mon);
            if (mon_info->sbrec_mon->status &&
                    strcmp(mon_info->sbrec_mon->status, "online")) {
                continue;
            }

            n_active_backends++;
            bool ipv6 = !IN6_IS_ADDR_V4MAPPED(&backend->ip);
            ds_put_format(action, ipv6 ? "[%s]:%"PRIu16"," : "%s:%"PRIu16",",
                          backend->ip_str, backend->port);
        }
        ds_chomp(action, ',');

        drop = !n_active_backends && !lb_vip->empty_backend_rej;
        reject = !n_active_backends && lb_vip->empty_backend_rej;
    } else {
        ds_put_format(action, "%s(backends=%s", ct_lb_action,
                      lb_vip_nb->backend_ips);
    }

    if (reject) {
        int stage = ls_dp ? ovn_stage_get_table(S_SWITCH_OUT_QOS)
                          : ovn_stage_get_table(S_ROUTER_OUT_SNAT);
        ds_clear(action);
        ds_put_format(action, "reg0 = 0; reject { outport <-> inport; "
                              "next(pipeline=egress,table=%d);};", stage);
    } else if (drop) {
        ds_clear(action);
        ds_put_cstr(action, debug_drop_action());
    } else if (selection_fields && selection_fields[0]) {
        ds_put_format(action, "; hash_fields=\"%s\"", selection_fields);
    }

    bool is_lb_action = !(reject || drop);
    const char *enclose = is_lb_action ? ");" : "";

    if (!ls_dp) {
        ds_put_format(skip_snat_action, "flags.skip_snat_for_lb = 1; %s%s",
                      ds_cstr(action),
                      is_lb_action ? "; skip_snat);" : enclose);
        ds_put_format(force_snat_action, "flags.force_snat_for_lb = 1; %s%s",
                      ds_cstr(action),
                      is_lb_action ? "; force_snat);" : enclose);
    }

    ds_put_cstr(action, enclose);

    return reject;
}

static void
build_lb_datapaths(const struct hmap *lbs, const struct hmap *lb_groups,
                   struct ovn_datapaths *ls_datapaths,
                   struct ovn_datapaths *lr_datapaths,
                   struct hmap *lb_datapaths_map,
                   struct hmap *lb_group_datapaths_map)
{
    const struct nbrec_load_balancer_group *nbrec_lb_group;
    struct ovn_lb_group_datapaths *lb_group_dps;
    const struct ovn_lb_group *lb_group;
    struct ovn_lb_datapaths *lb_dps;
    const struct ovn_northd_lb *lb;

    hmap_init(lb_datapaths_map);
    hmap_init(lb_group_datapaths_map);

    HMAP_FOR_EACH (lb, hmap_node, lbs) {
        lb_dps = ovn_lb_datapaths_create(lb, ods_size(ls_datapaths),
                                         ods_size(lr_datapaths));
        hmap_insert(lb_datapaths_map, &lb_dps->hmap_node,
                    uuid_hash(&lb->nlb->header_.uuid));
    }

    HMAP_FOR_EACH (lb_group, hmap_node, lb_groups) {
        lb_group_dps = ovn_lb_group_datapaths_create(
            lb_group, ods_size(ls_datapaths), ods_size(lr_datapaths));
        hmap_insert(lb_group_datapaths_map, &lb_group_dps->hmap_node,
                    uuid_hash(&lb_group->uuid));
    }

    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &ls_datapaths->datapaths) {
        if (!od->nbs) {
            continue;
        }

        for (size_t i = 0; i < od->nbs->n_load_balancer; i++) {
            const struct uuid *lb_uuid =
                &od->nbs->load_balancer[i]->header_.uuid;
            lb_dps = ovn_lb_datapaths_find(lb_datapaths_map, lb_uuid);
            ovs_assert(lb_dps);
            ovn_lb_datapaths_add_ls(lb_dps, 1, &od);
        }

        for (size_t i = 0; i < od->nbs->n_load_balancer_group; i++) {
            nbrec_lb_group = od->nbs->load_balancer_group[i];
            const struct uuid *lb_group_uuid = &nbrec_lb_group->header_.uuid;
            lb_group_dps =
                ovn_lb_group_datapaths_find(lb_group_datapaths_map,
                                            lb_group_uuid);
            ovs_assert(lb_group_dps);
            ovn_lb_group_datapaths_add_ls(lb_group_dps, 1, &od);
        }
    }

    HMAP_FOR_EACH (od, key_node, &lr_datapaths->datapaths) {
        ovs_assert(od->nbr);

        for (size_t i = 0; i < od->nbr->n_load_balancer_group; i++) {
            nbrec_lb_group = od->nbr->load_balancer_group[i];
            const struct uuid *lb_group_uuid = &nbrec_lb_group->header_.uuid;

            lb_group_dps =
                ovn_lb_group_datapaths_find(lb_group_datapaths_map,
                                            lb_group_uuid);
            ovs_assert(lb_group_dps);
            ovn_lb_group_datapaths_add_lr(lb_group_dps, od);
        }

        for (size_t i = 0; i < od->nbr->n_load_balancer; i++) {
            const struct uuid *lb_uuid =
                &od->nbr->load_balancer[i]->header_.uuid;
            lb_dps = ovn_lb_datapaths_find(lb_datapaths_map, lb_uuid);
            ovs_assert(lb_dps);
            ovn_lb_datapaths_add_lr(lb_dps, 1, &od);
        }
    }

    HMAP_FOR_EACH (lb_group_dps, hmap_node, lb_group_datapaths_map) {
        for (size_t j = 0; j < lb_group_dps->lb_group->n_lbs; j++) {
            const struct uuid *lb_uuid =
                &lb_group_dps->lb_group->lbs[j]->nlb->header_.uuid;
            lb_dps = ovn_lb_datapaths_find(lb_datapaths_map, lb_uuid);
            ovs_assert(lb_dps);
            ovn_lb_datapaths_add_ls(lb_dps, lb_group_dps->n_ls,
                                    lb_group_dps->ls);
            ovn_lb_datapaths_add_lr(lb_dps, lb_group_dps->n_lr,
                                    lb_group_dps->lr);
        }
    }
}

static void
build_lb_svcs(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_service_monitor_table *sbrec_service_monitor_table,
    const char *svc_monitor_mac,
    const struct eth_addr *svc_monitor_mac_ea,
    struct hmap *ls_ports, struct hmap *lb_dps_map,
    struct sset *svc_monitor_lsps,
    struct hmap *svc_monitor_map)
{
    const struct sbrec_service_monitor *sbrec_mon;
    SBREC_SERVICE_MONITOR_TABLE_FOR_EACH (sbrec_mon,
                            sbrec_service_monitor_table) {
        uint32_t hash = sbrec_mon->port;
        hash = hash_string(sbrec_mon->ip, hash);
        hash = hash_string(sbrec_mon->logical_port, hash);
        struct service_monitor_info *mon_info = xzalloc(sizeof *mon_info);
        mon_info->sbrec_mon = sbrec_mon;
        mon_info->required = false;
        hmap_insert(svc_monitor_map, &mon_info->hmap_node, hash);
    }

    struct ovn_lb_datapaths *lb_dps;
    HMAP_FOR_EACH (lb_dps, hmap_node, lb_dps_map) {
        ovn_lb_svc_create(ovnsb_txn, lb_dps->lb, svc_monitor_mac,
                          svc_monitor_mac_ea, svc_monitor_map, ls_ports,
                          svc_monitor_lsps);
    }

    struct service_monitor_info *mon_info;
    HMAP_FOR_EACH_SAFE (mon_info, hmap_node, svc_monitor_map) {
        if (!mon_info->required) {
            sbrec_service_monitor_delete(mon_info->sbrec_mon);
            hmap_remove(svc_monitor_map, &mon_info->hmap_node);
            free(mon_info);
        }
    }
}

static void
build_lswitch_lbs_from_lrouter(struct ovn_datapaths *lr_datapaths,
                               struct hmap *lb_dps_map,
                               struct hmap *lb_group_dps_map)
{
    if (!install_ls_lb_from_router) {
        return;
    }

    struct ovn_lb_datapaths *lb_dps;
    size_t index;

    HMAP_FOR_EACH (lb_dps, hmap_node, lb_dps_map) {
        BITMAP_FOR_EACH_1 (index, ods_size(lr_datapaths), lb_dps->nb_lr_map) {
            struct ovn_datapath *od = lr_datapaths->array[index];
            ovn_lb_datapaths_add_ls(lb_dps, od->n_ls_peers, od->ls_peers);
        }
    }

    struct ovn_lb_group_datapaths *lb_group_dps;
    HMAP_FOR_EACH (lb_group_dps, hmap_node, lb_group_dps_map) {
        for (size_t i = 0; i < lb_group_dps->n_lr; i++) {
            struct ovn_datapath *od = lb_group_dps->lr[i];
            ovn_lb_group_datapaths_add_ls(lb_group_dps, od->n_ls_peers,
                                          od->ls_peers);
            for (size_t j = 0; j < lb_group_dps->lb_group->n_lbs; j++) {
                const struct uuid *lb_uuid =
                    &lb_group_dps->lb_group->lbs[j]->nlb->header_.uuid;
                lb_dps = ovn_lb_datapaths_find(lb_dps_map, lb_uuid);
                ovs_assert(lb_dps);
                ovn_lb_datapaths_add_ls(lb_dps, od->n_ls_peers, od->ls_peers);
            }
        }
    }
}

static void
build_lb_count_dps(struct hmap *lb_dps_map,
                   size_t n_ls_datapaths,
                   size_t n_lr_datapaths)
{
    struct ovn_lb_datapaths *lb_dps;

    HMAP_FOR_EACH (lb_dps, hmap_node, lb_dps_map) {
        lb_dps->n_nb_lr = bitmap_count1(lb_dps->nb_lr_map, n_lr_datapaths);
        lb_dps->n_nb_ls = bitmap_count1(lb_dps->nb_ls_map, n_ls_datapaths);
    }
}

/* This must be called after all ports have been processed, i.e., after
 * build_ports() because the reachability check requires the router ports
 * networks to have been parsed.
 */
static void
build_lb_port_related_data(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_service_monitor_table *sbrec_service_monitor_table,
    const char *svc_monitor_mac,
    const struct eth_addr *svc_monitor_mac_ea,
    struct ovn_datapaths *lr_datapaths, struct hmap *ls_ports,
    struct hmap *lb_dps_map, struct hmap *lb_group_dps_map,
    struct sset *svc_monitor_lsps,
    struct hmap *svc_monitor_map)
{
    build_lb_svcs(ovnsb_txn, sbrec_service_monitor_table, svc_monitor_mac,
                  svc_monitor_mac_ea, ls_ports, lb_dps_map,
                  svc_monitor_lsps, svc_monitor_map);
    build_lswitch_lbs_from_lrouter(lr_datapaths, lb_dps_map, lb_group_dps_map);
}

/* Syncs the SB port binding for the ovn_port 'op' of a logical switch port.
 * Caller should make sure that the OVN SB IDL txn is not NULL.  Presently it
 * only syncs the nat column of port binding corresponding to the 'op->nbsp' */
static void
sync_pb_for_lsp(struct ovn_port *op,
                const struct lr_stateful_table *lr_stateful_table)
{
    ovs_assert(op->nbsp);

    if (lsp_is_router(op->nbsp)) {
        const char *chassis = NULL;
        if (op->peer && op->peer->od && op->peer->od->nbr) {
            chassis = smap_get(&op->peer->od->nbr->options, "chassis");
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
                bool include_lb_vips = !smap_get_bool(&op->nbsp->options,
                        "exclude-lb-vips-from-garp", false);

                const struct lr_stateful_record *lr_stateful_rec = NULL;

                if (include_lb_vips) {
                    lr_stateful_rec = lr_stateful_table_find_by_index(
                        lr_stateful_table, op->peer->od->index);
                }
                nats = get_nat_addresses(op->peer, &n_nats, false,
                                         include_lb_vips, lr_stateful_rec);
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
    } else {
        sbrec_port_binding_set_nat_addresses(op->sb, NULL, 0);
    }
}

/* Syncs the SB port binding for the ovn_port 'op' of a logical router port.
 * Caller should make sure that the OVN SB IDL txn is not NULL.  Presently it
 * only sets the port binding options column for the router ports */
static void
sync_pb_for_lrp(struct ovn_port *op,
                const struct lr_stateful_table *lr_stateful_table)
{
    ovs_assert(op->nbrp);

    struct smap new;
    smap_init(&new);

    const char *chassis_name = smap_get(&op->od->nbr->options, "chassis");
    if (is_cr_port(op)) {
        const struct lr_stateful_record *lr_stateful_rec =
            lr_stateful_table_find_by_index(lr_stateful_table, op->od->index);
        ovs_assert(lr_stateful_rec);

        smap_add(&new, "distributed-port", op->nbrp->name);

        bool always_redirect =
            !lr_stateful_rec->lrnat_rec->has_distributed_nat &&
            !l3dgw_port_has_associated_vtep_lports(op->l3dgw_port);

        const char *redirect_type = smap_get(&op->nbrp->options,
                                            "redirect-type");
        if (redirect_type) {
            smap_add(&new, "redirect-type", redirect_type);
            /* Note: Why can't we enable always-redirect when redirect-type
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

    const char *ipv6_pd_list = smap_get(&op->sb->options, "ipv6_ra_pd_list");
    if (ipv6_pd_list) {
        smap_add(&new, "ipv6_ra_pd_list", ipv6_pd_list);
    }

    sbrec_port_binding_set_options(op->sb, &new);
    smap_destroy(&new);
}

static void ovn_update_ipv6_options(struct hmap *lr_ports);
static void ovn_update_ipv6_opt_for_op(struct ovn_port *op);

/* Sync the SB Port bindings which needs to be updated.
 * Presently it syncs the nat column of port bindings corresponding to
 * the logical switch ports. */
void
sync_pbs(struct ovsdb_idl_txn *ovnsb_idl_txn, struct hmap *ls_ports,
         struct hmap *lr_ports,
         const struct lr_stateful_table *lr_stateful_table)
{
    ovs_assert(ovnsb_idl_txn);

    struct ovn_port *op;
    HMAP_FOR_EACH (op, key_node, ls_ports) {
        sync_pb_for_lsp(op, lr_stateful_table);
    }

    HMAP_FOR_EACH (op, key_node, lr_ports) {
        sync_pb_for_lrp(op, lr_stateful_table);
    }

    ovn_update_ipv6_options(lr_ports);
}

/* Sync the SB Port bindings for the added and updated logical switch ports
 * of the tracked northd engine data. */
bool
sync_pbs_for_northd_changed_ovn_ports(
    struct tracked_ovn_ports *trk_ovn_ports,
    const struct lr_stateful_table *lr_stateful_table)
{
    struct hmapx_node *hmapx_node;

    HMAPX_FOR_EACH (hmapx_node, &trk_ovn_ports->created) {
        sync_pb_for_lsp(hmapx_node->data, lr_stateful_table);
    }

    HMAPX_FOR_EACH (hmapx_node, &trk_ovn_ports->updated) {
        sync_pb_for_lsp(hmapx_node->data, lr_stateful_table);
    }

    return true;
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

/* Returns false if the requested key is confict with another allocated key, so
 * that the I-P engine can fallback to recompute if needed; otherwise return
 * true (even if the key is not allocated). */
static bool
ovn_port_assign_requested_tnl_id(
    const struct sbrec_chassis_table *sbrec_chassis_table, struct ovn_port *op)
{
    const struct smap *options = (op->nbsp
                                  ? &op->nbsp->options
                                  : &op->nbrp->options);
    uint32_t tunnel_key = smap_get_int(options, "requested-tnl-key", 0);
    if (tunnel_key) {
        if (is_vxlan_mode(sbrec_chassis_table) &&
                tunnel_key >= OVN_VXLAN_MIN_MULTICAST) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Tunnel key %"PRIu32" for port %s "
                         "is incompatible with VXLAN",
                         tunnel_key, op_get_name(op));
            return true;
        }
        if (!ovn_port_add_tnlid(op, tunnel_key)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Logical %s port %s requests same tunnel key "
                         "%"PRIu32" as another LSP or LRP",
                         op->nbsp ? "switch" : "router",
                         op_get_name(op), tunnel_key);
            return false;
        }
    }
    return true;
}

static bool
ovn_port_allocate_key(const struct sbrec_chassis_table *sbrec_chassis_table,
                      struct ovn_port *op)
{
    if (!op->tunnel_key) {
        uint8_t key_bits = is_vxlan_mode(sbrec_chassis_table)? 12 : 16;
        op->tunnel_key = ovn_allocate_tnlid(&op->od->port_tnlids, "port",
                                            1, (1u << (key_bits - 1)) - 1,
                                            &op->od->port_key_hint);
        if (!op->tunnel_key) {
            return false;
        }
    }
    return true;
}

/* Updates the southbound Port_Binding table so that it contains the logical
 * switch ports specified by the northbound database.
 *
 * Initializes 'ports' to contain a "struct ovn_port" for every logical port,
 * using the "struct ovn_datapath"s in 'datapaths' to look up logical
 * datapaths. */
static void
build_ports(struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_port_binding_table *sbrec_port_binding_table,
    const struct sbrec_chassis_table *sbrec_chassis_table,
    const struct sbrec_mirror_table *sbrec_mirror_table,
    const struct sbrec_mac_binding_table *sbrec_mac_binding_table,
    const struct sbrec_ha_chassis_group_table *sbrec_ha_chassis_group_table,
    struct ovsdb_idl_index *sbrec_chassis_by_name,
    struct ovsdb_idl_index *sbrec_chassis_by_hostname,
    struct ovsdb_idl_index *sbrec_ha_chassis_grp_by_name,
    struct hmap *ls_datapaths, struct hmap *lr_datapaths,
    struct hmap *ls_ports, struct hmap *lr_ports)
{
    struct ovs_list sb_only, nb_only, both;
    /* XXX: Add tag_alloc_table and queue_id_bitmap as part of northd_data
     * to improve I-P. */
    struct hmap tag_alloc_table = HMAP_INITIALIZER(&tag_alloc_table);
    unsigned long *queue_id_bitmap = bitmap_allocate(QDISC_MAX_QUEUE_ID + 1);
    bitmap_set1(queue_id_bitmap, 0);

    /* sset which stores the set of ha chassis group names used. */
    struct sset active_ha_chassis_grps =
        SSET_INITIALIZER(&active_ha_chassis_grps);

    /* Borrow ls_ports for joining NB and SB for both LSPs and LRPs.
     * We will split them later. */
    struct hmap *ports = ls_ports;
    join_logical_ports(sbrec_port_binding_table, ls_datapaths, lr_datapaths,
                       ports, queue_id_bitmap,
                       &tag_alloc_table, &sb_only, &nb_only, &both);

    /* Purge stale Mac_Bindings if ports are deleted. */
    bool remove_mac_bindings = !ovs_list_is_empty(&sb_only);

    /* Assign explicitly requested tunnel ids first. */
    struct ovn_port *op;
    LIST_FOR_EACH (op, list, &both) {
        ovn_port_assign_requested_tnl_id(sbrec_chassis_table, op);
    }
    LIST_FOR_EACH (op, list, &nb_only) {
        ovn_port_assign_requested_tnl_id(sbrec_chassis_table, op);
    }

    /* Keep nonconflicting tunnel IDs that are already assigned. */
    LIST_FOR_EACH (op, list, &both) {
        if (!op->tunnel_key) {
            ovn_port_add_tnlid(op, op->sb->tunnel_key);
        }
    }

    /* Assign new tunnel ids where needed. */
    LIST_FOR_EACH_SAFE (op, list, &both) {
        if (!ovn_port_allocate_key(sbrec_chassis_table, op)) {
            sbrec_port_binding_delete(op->sb);
            ovs_list_remove(&op->list);
            ovn_port_destroy(ports, op);
        }
    }
    LIST_FOR_EACH_SAFE (op, list, &nb_only) {
        if (!ovn_port_allocate_key(sbrec_chassis_table, op)) {
            ovs_list_remove(&op->list);
            ovn_port_destroy(ports, op);
        }
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
        ovn_port_update_sbrec(ovnsb_txn, sbrec_chassis_by_name,
                              sbrec_chassis_by_hostname,
                              sbrec_ha_chassis_grp_by_name,
                              sbrec_mirror_table,
                              op, queue_id_bitmap,
                              &active_ha_chassis_grps);
        ovs_list_remove(&op->list);
    }

    /* Add southbound record for each unmatched northbound record. */
    LIST_FOR_EACH_SAFE (op, list, &nb_only) {
        op->sb = sbrec_port_binding_insert(ovnsb_txn);
        ovn_port_update_sbrec(ovnsb_txn, sbrec_chassis_by_name,
                              sbrec_chassis_by_hostname,
                              sbrec_ha_chassis_grp_by_name,
                              sbrec_mirror_table,
                              op, queue_id_bitmap,
                              &active_ha_chassis_grps);
        sbrec_port_binding_set_logical_port(op->sb, op->key);
        ovs_list_remove(&op->list);
    }

    /* Delete southbound records without northbound matches. */
    if (!ovs_list_is_empty(&sb_only)) {
        LIST_FOR_EACH_SAFE (op, list, &sb_only) {
            ovs_list_remove(&op->list);
            sbrec_port_binding_delete(op->sb);
            ovn_port_destroy(ports, op);
        }
    }

    /* Move logical router ports to lr_ports, and logical switch ports will
     * remain in ports/ls_ports. */
    HMAP_FOR_EACH_SAFE (op, key_node, ports) {
        if (!op->nbrp) {
            continue;
        }
        hmap_remove(ports, &op->key_node);
        hmap_insert(lr_ports, &op->key_node, op->key_node.hash);
    }

    if (remove_mac_bindings) {
        cleanup_mac_bindings(sbrec_mac_binding_table, lr_datapaths, lr_ports);
    }

    tag_alloc_destroy(&tag_alloc_table);
    bitmap_free(queue_id_bitmap);
    cleanup_sb_ha_chassis_groups(sbrec_ha_chassis_group_table,
                                 &active_ha_chassis_grps);
    sset_destroy(&active_ha_chassis_grps);
}

static void
destroy_tracked_ovn_ports(struct tracked_ovn_ports *trk_ovn_ports)
{
    struct hmapx_node *hmapx_node;
    HMAPX_FOR_EACH_SAFE (hmapx_node, &trk_ovn_ports->deleted) {
        ovn_port_destroy_orphan(hmapx_node->data);
        hmapx_delete(&trk_ovn_ports->deleted, hmapx_node);
    }

    hmapx_clear(&trk_ovn_ports->created);
    hmapx_clear(&trk_ovn_ports->updated);
}

static void
destroy_tracked_lbs(struct tracked_lbs *trk_lbs)
{
    struct hmapx_node *hmapx_node;
    HMAPX_FOR_EACH_SAFE (hmapx_node, &trk_lbs->deleted) {
        ovn_lb_datapaths_destroy(hmapx_node->data);
        hmapx_delete(&trk_lbs->deleted, hmapx_node);
    }

    hmapx_clear(&trk_lbs->crupdated);
}

static void
add_op_to_northd_tracked_ports(struct hmapx *tracked_ovn_ports,
                               struct ovn_port *op)
{
    hmapx_add(tracked_ovn_ports, op);
}

void
destroy_northd_data_tracked_changes(struct northd_data *nd)
{
    struct northd_tracked_data *trk_changes = &nd->trk_data;
    destroy_tracked_ovn_ports(&trk_changes->trk_lsps);
    destroy_tracked_lbs(&trk_changes->trk_lbs);
    hmapx_clear(&trk_changes->trk_nat_lrs);
    hmapx_clear(&trk_changes->ls_with_changed_lbs);
    hmapx_clear(&trk_changes->ls_with_changed_acls);
    trk_changes->type = NORTHD_TRACKED_NONE;
}

static void
init_northd_tracked_data(struct northd_data *nd)
{
    struct northd_tracked_data *trk_data = &nd->trk_data;
    trk_data->type = NORTHD_TRACKED_NONE;
    hmapx_init(&trk_data->trk_lsps.created);
    hmapx_init(&trk_data->trk_lsps.updated);
    hmapx_init(&trk_data->trk_lsps.deleted);
    hmapx_init(&trk_data->trk_lbs.crupdated);
    hmapx_init(&trk_data->trk_lbs.deleted);
    hmapx_init(&trk_data->trk_nat_lrs);
    hmapx_init(&trk_data->ls_with_changed_lbs);
    hmapx_init(&trk_data->ls_with_changed_acls);
}

static void
destroy_northd_tracked_data(struct northd_data *nd)
{
    struct northd_tracked_data *trk_data = &nd->trk_data;
    trk_data->type = NORTHD_TRACKED_NONE;
    hmapx_destroy(&trk_data->trk_lsps.created);
    hmapx_destroy(&trk_data->trk_lsps.updated);
    hmapx_destroy(&trk_data->trk_lsps.deleted);
    hmapx_destroy(&trk_data->trk_lbs.crupdated);
    hmapx_destroy(&trk_data->trk_lbs.deleted);
    hmapx_destroy(&trk_data->trk_nat_lrs);
    hmapx_destroy(&trk_data->ls_with_changed_lbs);
    hmapx_destroy(&trk_data->ls_with_changed_acls);
}

/* Check if a changed LSP can be handled incrementally within the I-P engine
 * node en_northd.
 */
static bool
lsp_can_be_inc_processed(const struct nbrec_logical_switch_port *nbsp)
{
    /* Support only normal VIF for now. */
    if (nbsp->type[0]) {
        return false;
    }

    /* Tag allocation is not supported for now. */
    if ((nbsp->parent_name && nbsp->parent_name[0]) || nbsp->tag ||
        nbsp->tag_request) {
        return false;
    }

    /* Port with qos settings is not supported for now (need special handling
     * for qdisc_queue_id sync). */
    if (port_has_qos_params(&nbsp->options)) {
        return false;
    }

    for (size_t j = 0; j < nbsp->n_addresses; j++) {
        /* Dynamic address handling is not supported for now. */
        if (is_dynamic_lsp_address(nbsp->addresses[j])) {
            return false;
        }
        /* "unknown" address handling is not supported for now.  XXX: Need to
         * handle od->has_unknown change and track it when the first LSP with
         * 'unknown' is added or when the last one is removed. */
        if (!strcmp(nbsp->addresses[j], "unknown")) {
            return false;
        }
    }

    return true;
}

static bool
ls_port_has_changed(const struct nbrec_logical_switch_port *new)
{
    /* XXX: Need a better OVSDB IDL interface for this check. */
    return (nbrec_logical_switch_port_row_get_seqno(new,
                                OVSDB_IDL_CHANGE_MODIFY) > 0);
}

static struct ovn_port *
ovn_port_find_in_datapath(struct ovn_datapath *od,
                          const struct nbrec_logical_switch_port *nbsp)
{
    struct ovn_port *op;
    HMAP_FOR_EACH_WITH_HASH (op, dp_node, hash_string(nbsp->name, 0),
                             &od->ports) {
        if (!strcmp(op->key, nbsp->name) && op->nbsp == nbsp) {
            return op;
        }
    }
    return NULL;
}

static bool
ls_port_init(struct ovn_port *op, struct ovsdb_idl_txn *ovnsb_txn,
             struct ovn_datapath *od,
             const struct sbrec_port_binding *sb,
             const struct sbrec_mirror_table *sbrec_mirror_table,
             const struct sbrec_chassis_table *sbrec_chassis_table,
             struct ovsdb_idl_index *sbrec_chassis_by_name,
             struct ovsdb_idl_index *sbrec_chassis_by_hostname)
{
    op->od = od;
    parse_lsp_addrs(op);
    /* Assign explicitly requested tunnel ids first. */
    if (!ovn_port_assign_requested_tnl_id(sbrec_chassis_table, op)) {
        return false;
    }
    /* Keep nonconflicting tunnel IDs that are already assigned. */
    if (sb) {
        if (!op->tunnel_key) {
            ovn_port_add_tnlid(op, sb->tunnel_key);
        }
    }
    /* Assign new tunnel ids where needed. */
    if (!ovn_port_allocate_key(sbrec_chassis_table, op)) {
        return false;
    }
    /* Create new binding, if needed. */
    if (sb) {
        op->sb = sb;
    } else {
        /* XXX: the new SB port_binding will change in IDL, so need to handle
         * SB port_binding updates incrementally to achieve end-to-end
         * incremental processing. */
        op->sb = sbrec_port_binding_insert(ovnsb_txn);
        sbrec_port_binding_set_logical_port(op->sb, op->key);
    }
    ovn_port_update_sbrec(ovnsb_txn, sbrec_chassis_by_name,
                          sbrec_chassis_by_hostname, NULL, sbrec_mirror_table,
                          op, NULL, NULL);
    return true;
}

static struct ovn_port *
ls_port_create(struct ovsdb_idl_txn *ovnsb_txn, struct hmap *ls_ports,
               const char *key, const struct nbrec_logical_switch_port *nbsp,
               struct ovn_datapath *od, const struct sbrec_port_binding *sb,
               const struct sbrec_mirror_table *sbrec_mirror_table,
               const struct sbrec_chassis_table *sbrec_chassis_table,
               struct ovsdb_idl_index *sbrec_chassis_by_name,
               struct ovsdb_idl_index *sbrec_chassis_by_hostname)
{
    struct ovn_port *op = ovn_port_create(ls_ports, key, nbsp, NULL,
                                          NULL);
    hmap_insert(&od->ports, &op->dp_node, hmap_node_hash(&op->key_node));
    if (!ls_port_init(op, ovnsb_txn, od, sb,
                      sbrec_mirror_table, sbrec_chassis_table,
                      sbrec_chassis_by_name, sbrec_chassis_by_hostname)) {
        ovn_port_destroy(ls_ports, op);
        return NULL;
    }

    return op;
}

static bool
ls_port_reinit(struct ovn_port *op, struct ovsdb_idl_txn *ovnsb_txn,
                const struct nbrec_logical_switch_port *nbsp,
                const struct nbrec_logical_router_port *nbrp,
                struct ovn_datapath *od,
                const struct sbrec_port_binding *sb,
                const struct sbrec_mirror_table *sbrec_mirror_table,
                const struct sbrec_chassis_table *sbrec_chassis_table,
                struct ovsdb_idl_index *sbrec_chassis_by_name,
                struct ovsdb_idl_index *sbrec_chassis_by_hostname)
{
    ovn_port_cleanup(op);
    op->sb = sb;
    ovn_port_set_nb(op, nbsp, nbrp);
    op->l3dgw_port = op->cr_port = NULL;
    return ls_port_init(op, ovnsb_txn, od, sb,
                        sbrec_mirror_table, sbrec_chassis_table,
                        sbrec_chassis_by_name, sbrec_chassis_by_hostname);
}

/* Returns true if the logical switch has changes which can be
 * incrementally handled.
 * Presently supports i-p for the below changes:
 *    - logical switch ports.
 *    - load balancers.
 *    - load balancer groups.
 *    - ACLs
 */
static bool
ls_changes_can_be_handled(
    const struct nbrec_logical_switch *ls)
{
    /* Check if the columns are changed in this row. */
    enum nbrec_logical_switch_column_id col;
    for (col = 0; col < NBREC_LOGICAL_SWITCH_N_COLUMNS; col++) {
        if (nbrec_logical_switch_is_updated(ls, col)) {
            if (col == NBREC_LOGICAL_SWITCH_COL_ACLS ||
                col == NBREC_LOGICAL_SWITCH_COL_PORTS ||
                col == NBREC_LOGICAL_SWITCH_COL_LOAD_BALANCER ||
                col == NBREC_LOGICAL_SWITCH_COL_LOAD_BALANCER_GROUP) {
                continue;
            }
            return false;
        }
    }

    /* Check if the referenced rows are changed.
       XXX: Need a better OVSDB IDL interface for this check. */
    if (ls->copp && nbrec_copp_row_get_seqno(ls->copp,
                                OVSDB_IDL_CHANGE_MODIFY) > 0) {
        return false;
    }
    for (size_t i = 0; i < ls->n_dns_records; i++) {
        if (nbrec_dns_row_get_seqno(ls->dns_records[i],
                                OVSDB_IDL_CHANGE_MODIFY) > 0) {
            return false;
        }
    }
    for (size_t i = 0; i < ls->n_forwarding_groups; i++) {
        if (nbrec_forwarding_group_row_get_seqno(ls->forwarding_groups[i],
                                OVSDB_IDL_CHANGE_MODIFY) > 0) {
            return false;
        }
    }
    for (size_t i = 0; i < ls->n_qos_rules; i++) {
        if (nbrec_qos_row_get_seqno(ls->qos_rules[i],
                                OVSDB_IDL_CHANGE_MODIFY) > 0) {
            return false;
        }
    }
    return true;
}

static bool
check_lsp_changes_other_than_up(const struct nbrec_logical_switch_port *nbsp)
{
    /* Check if the columns are changed in this row. */
    enum nbrec_logical_switch_port_column_id col;
    for (col = 0; col < NBREC_LOGICAL_SWITCH_PORT_N_COLUMNS; col++) {
        if (nbrec_logical_switch_port_is_updated(nbsp, col) &&
            col != NBREC_LOGICAL_SWITCH_PORT_COL_UP) {
            return true;
        }
    }

    /* Check if the referenced rows are changed.
       XXX: Need a better OVSDB IDL interface for this check. */
    if (nbsp->dhcpv4_options &&
        nbrec_dhcp_options_row_get_seqno(nbsp->dhcpv4_options,
                                         OVSDB_IDL_CHANGE_MODIFY) > 0) {
        return true;
    }
    if (nbsp->dhcpv6_options &&
        nbrec_dhcp_options_row_get_seqno(nbsp->dhcpv6_options,
                                         OVSDB_IDL_CHANGE_MODIFY) > 0) {
        return true;
    }
    if (nbsp->ha_chassis_group &&
        nbrec_ha_chassis_group_row_get_seqno(nbsp->ha_chassis_group,
                                             OVSDB_IDL_CHANGE_MODIFY) > 0) {
        return true;
    }
    for (size_t i = 0; i < nbsp->n_mirror_rules; i++) {
        if (nbrec_mirror_row_get_seqno(nbsp->mirror_rules[i],
                                       OVSDB_IDL_CHANGE_MODIFY) > 0) {
            return true;
        }
    }
    return false;
}

/* Handles logical switch port changes of a changed logical switch.
 * Returns false, if any logical port can't be incrementally handled.
 */
static bool
ls_handle_lsp_changes(struct ovsdb_idl_txn *ovnsb_idl_txn,
                      const struct nbrec_logical_switch *changed_ls,
                      const struct northd_input *ni,
                      struct northd_data *nd,
                      struct ovn_datapath *od,
                      struct tracked_ovn_ports *trk_lsps)
{
    bool ls_ports_changed = false;
    if (!nbrec_logical_switch_is_updated(changed_ls,
                                         NBREC_LOGICAL_SWITCH_COL_PORTS)) {

        for (size_t i = 0; i < changed_ls->n_ports; i++) {
            if (nbrec_logical_switch_port_row_get_seqno(
                changed_ls->ports[i], OVSDB_IDL_CHANGE_MODIFY) > 0) {
                ls_ports_changed = true;
                break;
            }
        }
    } else {
        ls_ports_changed = true;
    }

    if (!ls_ports_changed) {
        return true;
    }

    bool ls_had_only_router_ports = (od->n_router_ports
            && (od->n_router_ports == hmap_count(&od->ports)));

    struct ovn_port *op;
    HMAP_FOR_EACH (op, dp_node, &od->ports) {
        op->visited = false;
    }

    /* Compare the individual ports in the old and new Logical Switches */
    for (size_t j = 0; j < changed_ls->n_ports; ++j) {
        struct nbrec_logical_switch_port *new_nbsp = changed_ls->ports[j];
        op = ovn_port_find_in_datapath(od, new_nbsp);

        if (!op) {
            if (!lsp_can_be_inc_processed(new_nbsp)) {
                goto fail;
            }
            op = ls_port_create(ovnsb_idl_txn, &nd->ls_ports,
                                new_nbsp->name, new_nbsp, od, NULL,
                                ni->sbrec_mirror_table,
                                ni->sbrec_chassis_table,
                                ni->sbrec_chassis_by_name,
                                ni->sbrec_chassis_by_hostname);
            if (!op) {
                goto fail;
            }
            add_op_to_northd_tracked_ports(&trk_lsps->created, op);
        } else if (ls_port_has_changed(new_nbsp)) {
            /* Existing port updated */
            bool temp = false;
            if (lsp_is_type_changed(op->sb, new_nbsp, &temp) ||
                !op->lsp_can_be_inc_processed ||
                !lsp_can_be_inc_processed(new_nbsp)) {
                goto fail;
            }
            const struct sbrec_port_binding *sb = op->sb;
            if (sset_contains(&nd->svc_monitor_lsps, new_nbsp->name)) {
                /* This port is used for svc monitor, which may be impacted
                 * by this change. Fallback to recompute. */
                goto fail;
            }
            if (!check_lsp_is_up &&
                !check_lsp_changes_other_than_up(new_nbsp)) {
                /* If the only change is the "up" column while the
                 * "ignore_lsp_down" is set to true, just ignore this
                 * change. */
                op->visited = true;
                continue;
            }
            if (!ls_port_reinit(op, ovnsb_idl_txn,
                                new_nbsp, NULL,
                                od, sb, ni->sbrec_mirror_table,
                                ni->sbrec_chassis_table,
                                ni->sbrec_chassis_by_name,
                                ni->sbrec_chassis_by_hostname)) {
                if (sb) {
                    sbrec_port_binding_delete(sb);
                }
                ovn_port_destroy(&nd->ls_ports, op);
                goto fail;
            }
            add_op_to_northd_tracked_ports(&trk_lsps->updated, op);
        }
        op->visited = true;
    }

    /* Check for deleted ports */
    HMAP_FOR_EACH_SAFE (op, dp_node, &od->ports) {
        if (!op->visited) {
            if (!op->lsp_can_be_inc_processed) {
                goto fail;
            }
            if (sset_contains(&nd->svc_monitor_lsps, op->key)) {
                /* This port was used for svc monitor, which may be
                 * impacted by this deletion. Fallback to recompute. */
                goto fail;
            }
            add_op_to_northd_tracked_ports(&trk_lsps->deleted, op);
            hmap_remove(&nd->ls_ports, &op->key_node);
            hmap_remove(&od->ports, &op->dp_node);
            sbrec_port_binding_delete(op->sb);
            delete_fdb_entry(ni->sbrec_fdb_by_dp_and_port, od->tunnel_key,
                                op->tunnel_key);
        }
    }

    bool ls_has_only_router_ports = (od->n_router_ports
            && (od->n_router_ports == hmap_count(&od->ports)));

    /* There are lflows related to router ports that depend on whether
     * there are switch ports on the logical switch (see
     * build_lswitch_rport_arp_req_flow() for more details). Check if this
     * dependency has changed and if it has, then add the router ports
     * to the tracked 'updated' ovn ports so that lflow engine can
     * regenerate lflows for these router ports. */
    if (ls_had_only_router_ports != ls_has_only_router_ports) {
        for (size_t i = 0; i < od->n_router_ports; i++) {
            op = od->router_ports[i];
            add_op_to_northd_tracked_ports(&trk_lsps->updated, op);
        }
    }

    return true;

fail:
    destroy_tracked_ovn_ports(trk_lsps);
    return false;
}

static bool
is_acls_seqno_changed(struct nbrec_acl **nb_acls, size_t n_nb_acls)
{
    for (size_t i = 0; i < n_nb_acls; i++) {
        if (nbrec_acl_row_get_seqno(nb_acls[i],
                                    OVSDB_IDL_CHANGE_MODIFY) > 0) {
            return true;
        }
    }

    return false;
}

static bool
is_ls_acls_changed(const struct nbrec_logical_switch *nbs) {
    return (nbrec_logical_switch_is_updated(nbs, NBREC_LOGICAL_SWITCH_COL_ACLS)
            || is_acls_seqno_changed(nbs->acls, nbs->n_acls));
}

/* Return true if changes are handled incrementally, false otherwise.
 * When there are any changes, try to track what's exactly changed and set
 * northd_data->trk_data accordingly.
 *
 * Note: Changes to load balancer and load balancer groups associated with
 * the logical switches are handled separately in the lb_data change handlers.
 * */
bool
northd_handle_ls_changes(struct ovsdb_idl_txn *ovnsb_idl_txn,
                         const struct northd_input *ni,
                         struct northd_data *nd)
{
    const struct nbrec_logical_switch *changed_ls;
    struct northd_tracked_data *trk_data = &nd->trk_data;

    NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH_TRACKED (changed_ls,
                                             ni->nbrec_logical_switch_table) {
        if (nbrec_logical_switch_is_new(changed_ls) ||
            nbrec_logical_switch_is_deleted(changed_ls)) {
            goto fail;
        }
        struct ovn_datapath *od = ovn_datapath_find_(
                                    &nd->ls_datapaths.datapaths,
                                    &changed_ls->header_.uuid);
        if (!od) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Internal error: a tracked updated LS doesn't "
                         "exist in ls_datapaths: "UUID_FMT,
                         UUID_ARGS(&changed_ls->header_.uuid));
            goto fail;
        }

        /* Check if the ls changes can be handled or not. */
        if (!ls_changes_can_be_handled(changed_ls)) {
            goto fail;
        }

        if (!ls_handle_lsp_changes(ovnsb_idl_txn, changed_ls,
                                   ni, nd, od, &trk_data->trk_lsps)) {
            goto fail;
        }

        if (is_ls_acls_changed(changed_ls)) {
            hmapx_add(&trk_data->ls_with_changed_acls, od);
        }
    }

    if (!hmapx_is_empty(&trk_data->trk_lsps.created)
        || !hmapx_is_empty(&trk_data->trk_lsps.updated)
        || !hmapx_is_empty(&trk_data->trk_lsps.deleted)) {
        trk_data->type |= NORTHD_TRACKED_PORTS;
    }

    if (!hmapx_is_empty(&trk_data->ls_with_changed_acls)) {
        trk_data->type |= NORTHD_TRACKED_LS_ACLS;
    }

    return true;

fail:
    destroy_northd_data_tracked_changes(nd);
    return false;
}

/* Returns true if the logical router has changes which can be
 * incrementally handled.
 * Presently supports i-p for the below changes:
 *    - load balancers and load balancer groups.
 *    - NAT changes
 */
static bool
lr_changes_can_be_handled(const struct nbrec_logical_router *lr)
{
    /* We can't do I-P processing when the router is disabled. */
    if (!lrouter_is_enabled(lr)) {
        return false;
    }

    /* Check if the columns are changed in this row. */
    enum nbrec_logical_router_column_id col;
    for (col = 0; col < NBREC_LOGICAL_ROUTER_N_COLUMNS; col++) {
        if (nbrec_logical_router_is_updated(lr, col)) {
            if (col == NBREC_LOGICAL_ROUTER_COL_LOAD_BALANCER
                || col == NBREC_LOGICAL_ROUTER_COL_LOAD_BALANCER_GROUP
                || col == NBREC_LOGICAL_ROUTER_COL_NAT) {
                continue;
            }
            return false;
        }
    }

    /* Check if the referenced rows are changed.
       XXX: Need a better OVSDB IDL interface for this check. */
    for (size_t i = 0; i < lr->n_ports; i++) {
        if (nbrec_logical_router_port_row_get_seqno(lr->ports[i],
                                OVSDB_IDL_CHANGE_MODIFY) > 0) {
            return false;
        }
    }
    if (lr->copp && nbrec_copp_row_get_seqno(lr->copp,
                                OVSDB_IDL_CHANGE_MODIFY) > 0) {
        return false;
    }
    for (size_t i = 0; i < lr->n_policies; i++) {
        if (nbrec_logical_router_policy_row_get_seqno(lr->policies[i],
                                OVSDB_IDL_CHANGE_MODIFY) > 0) {
            return false;
        }
    }
    for (size_t i = 0; i < lr->n_static_routes; i++) {
        if (nbrec_logical_router_static_route_row_get_seqno(
            lr->static_routes[i], OVSDB_IDL_CHANGE_MODIFY) > 0) {
            return false;
        }
    }
    return true;
}

static bool
is_lr_nats_seqno_changed(const struct nbrec_logical_router *nbr)
{
    for (size_t i = 0; i < nbr->n_nat; i++) {
        if (nbrec_nat_row_get_seqno(nbr->nat[i],
                                    OVSDB_IDL_CHANGE_MODIFY) > 0) {
            return true;
        }
    }

    return false;
}

static bool
is_lr_nats_changed(const struct nbrec_logical_router *nbr) {
    return (nbrec_logical_router_is_updated(nbr,
                                            NBREC_LOGICAL_ROUTER_COL_NAT)
            || nbrec_logical_router_is_updated(
                nbr, NBREC_LOGICAL_ROUTER_COL_OPTIONS)
            || is_lr_nats_seqno_changed(nbr));
}

/* Return true if changes are handled incrementally, false otherwise.
 *
 * Note: Changes to load balancer and load balancer groups associated with
 * the logical routers are handled separately in the lb_data change
 * handler -  northd_handle_lb_data_changes().
 * */
bool
northd_handle_lr_changes(const struct northd_input *ni,
                         struct northd_data *nd)
{
    const struct nbrec_logical_router *changed_lr;

    NBREC_LOGICAL_ROUTER_TABLE_FOR_EACH_TRACKED (changed_lr,
                                             ni->nbrec_logical_router_table) {
        if (nbrec_logical_router_is_new(changed_lr) ||
            nbrec_logical_router_is_deleted(changed_lr)) {
            goto fail;
        }

        /* Presently only able to handle load balancer,
         * load balancer group changes and NAT changes. */
        if (!lr_changes_can_be_handled(changed_lr)) {
            goto fail;
        }

        if (is_lr_nats_changed(changed_lr)) {
            struct ovn_datapath *od = ovn_datapath_find_(
                                    &nd->lr_datapaths.datapaths,
                                    &changed_lr->header_.uuid);

            if (!od) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "Internal error: a tracked updated LR "
                            "doesn't exist in lr_datapaths: "UUID_FMT,
                            UUID_ARGS(&changed_lr->header_.uuid));
                goto fail;
            }

            hmapx_add(&nd->trk_data.trk_nat_lrs, od);
        }
    }

    if (!hmapx_is_empty(&nd->trk_data.trk_nat_lrs)) {
        nd->trk_data.type |= NORTHD_TRACKED_LR_NATS;
    }

    return true;
fail:
    destroy_northd_data_tracked_changes(nd);
    return false;
}

bool
northd_handle_sb_port_binding_changes(
    const struct sbrec_port_binding_table *sbrec_port_binding_table,
    struct hmap *ls_ports, struct hmap *lr_ports)
{
    const struct sbrec_port_binding *pb;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    SBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (pb, sbrec_port_binding_table) {
        bool is_router_port = is_pb_router_type(pb);
        struct ovn_port *op = NULL;

        if (is_router_port) {
            /* A router port binding 'pb' can belong to
             *   - a logical switch port of type router or
             *   - a logical router port.
             *
             * So, first search in lr_ports hmap.  If not found, search in
             * ls_ports hmap.
             * */
            op = ovn_port_find(lr_ports, pb->logical_port);
        }

        if (!op) {
            op = ovn_port_find(ls_ports, pb->logical_port);

            if (op) {
                is_router_port = false;
            }
        }

        if (sbrec_port_binding_is_new(pb)) {
            /* Most likely the PB was created by northd and this is the
             * notification of that trasaction. So we just update the sb
             * pointer in northd data. Fallback to recompute otherwise. */
            if (!op) {
                VLOG_WARN_RL(&rl, "A port-binding for %s is created but the "
                            "%s is not found.", pb->logical_port,
                            is_router_port ? "LRP" : "LSP");
                return false;
            }
            op->sb = pb;
        } else if (sbrec_port_binding_is_deleted(pb)) {
            /* Most likely the PB was deleted by northd and this is the
             * notification of that transaction, and we can ignore in this
             * case. Fallback to recompute otherwise, to avoid dangling
             * sb idl pointers and other unexpected behavior. */
            if (op && op->sb == pb) {
                VLOG_WARN_RL(&rl, "A port-binding for %s is deleted but the "
                            "LSP/LRP still exists.", pb->logical_port);
                return false;
            }
        } else {
            /* The PB is updated.
             * For an LSP PB it is most likely because of
             * binding/unbinding to/from a chassis, and we can ignore the
             * change (updating NB "up" will be handled in the engine node
             * "sync_from_sb").
             *
             * For an LRP PB, it is most likely because of
             *   - IPv6 prefix delagation updates from ovn-controller.
             *     This update is handled in "sync_from_sb" node.
             *   - ha chassis group and this can be ignored.
             *
             * All other changes can be ignored.
             *
             * Fallback to recompute for anything unexpected. */
            if (!op) {
                VLOG_WARN_RL(&rl, "A port-binding for %s is updated but the "
                            "%s is not found.", pb->logical_port,
                            is_router_port ? "LRP" : "LSP");
                return false;
            }
            if (op->sb != pb) {
                VLOG_WARN_RL(&rl, "A port-binding for %s is updated with a new"
                             "IDL row, which is unusual.", pb->logical_port);
                return false;
            }
        }
    }
    return true;
}

/* Handler for lb_data engine changes.  It does the following
 * For every tracked 'lb' and 'lb_group'
 *  - it creates or deletes the ovn_lb_datapaths/ovn_lb_group_datapaths
 *    from the lb_datapaths hmap and lb_group_datapaths hmap.
 *
 *  - For any changes to a logical switch (in 'trk_lb_data->crupdated_ls_lbs')
 *    due to association of a load balancer (eg. ovn-nbctl ls-lb-add sw0 lb1),
 *    the logical switch datapath is added to the load balancer (represented
 *    by 'struct ovn_lb_datapaths') by calling ovn_lb_datapaths_add_ls().
 * */
bool
northd_handle_lb_data_changes(struct tracked_lb_data *trk_lb_data,
                              struct ovn_datapaths *ls_datapaths,
                              struct ovn_datapaths *lr_datapaths,
                              struct hmap *lb_datapaths_map,
                              struct hmap *lbgrp_datapaths_map,
                              struct northd_tracked_data *nd_changes)
{
    if (trk_lb_data->has_health_checks) {
        /* Fall back to recompute since a tracked load balancer
         * has health checks configured and I-P is not yet supported
         * for such load balancers. */
        return false;
    }

    /* Fall back to recompute if any load balancer was dissociated from
     * a load balancer group (but not deleted). */
    if (trk_lb_data->has_dissassoc_lbs_from_lbgrps) {
        return false;
    }

    /* Fall back to recompute if load balancer groups are deleted. */
    if (!hmapx_is_empty(&trk_lb_data->deleted_lbgrps)) {
        return false;
    }

    /* Fall back to recompute if any load balancer has been disassociated from
     * a logical switch or router. */
    if (trk_lb_data->has_dissassoc_lbs_from_od) {
        return false;
    }

    /* Fall back to recompute if any logical switch or router was deleted which
     * had load balancer or lb group association. */
    if (!hmapx_is_empty(&trk_lb_data->deleted_od_lb_data)) {
        return false;
    }

    /* Fall back to recompute if any load balancer group has been disassociated
     * from a logical switch or router. */
    if (trk_lb_data->has_dissassoc_lbgrps_from_od) {
        return false;
    }

    if (trk_lb_data->has_routable_lb) {
        return false;
    }

    struct ovn_lb_datapaths *lb_dps;
    struct ovn_northd_lb *lb;
    struct ovn_datapath *od;
    struct hmapx_node *hmapx_node;
    HMAPX_FOR_EACH (hmapx_node, &trk_lb_data->deleted_lbs) {
        lb = hmapx_node->data;
        const struct uuid *lb_uuid = &lb->nlb->header_.uuid;

        lb_dps = ovn_lb_datapaths_find(lb_datapaths_map, lb_uuid);
        ovs_assert(lb_dps);

        size_t index;
        BITMAP_FOR_EACH_1 (index, ods_size(ls_datapaths),
                           lb_dps->nb_ls_map) {
            od = ls_datapaths->array[index];

            /* Add the ls datapath to the northd tracked data. */
            hmapx_add(&nd_changes->ls_with_changed_lbs, od);
        }

        hmap_remove(lb_datapaths_map, &lb_dps->hmap_node);

        /* Add the deleted lb to the northd tracked data. */
        hmapx_add(&nd_changes->trk_lbs.deleted, lb_dps);
    }

    /* Create the 'lb_dps' if not already created for each
     * 'lb' in the trk_lb_data->crupdated_lbs. */
    struct crupdated_lb *clb;
    HMAP_FOR_EACH (clb, hmap_node, &trk_lb_data->crupdated_lbs) {
        lb = clb->lb;
        const struct uuid *lb_uuid = &lb->nlb->header_.uuid;

        lb_dps = ovn_lb_datapaths_find(lb_datapaths_map, lb_uuid);
        if (!lb_dps) {
            lb_dps = ovn_lb_datapaths_create(lb, ods_size(ls_datapaths),
                                             ods_size(lr_datapaths));
            hmap_insert(lb_datapaths_map, &lb_dps->hmap_node,
                        uuid_hash(lb_uuid));
        }

        /* Add the updated lb to the northd tracked data. */
        hmapx_add(&nd_changes->trk_lbs.crupdated, lb_dps);
    }

    struct ovn_lb_group_datapaths *lbgrp_dps;
    struct ovn_lb_group *lbgrp;
    struct crupdated_lbgrp *crupdated_lbgrp;
    HMAP_FOR_EACH (crupdated_lbgrp, hmap_node,
                   &trk_lb_data->crupdated_lbgrps) {
        lbgrp = crupdated_lbgrp->lbgrp;
        const struct uuid *lb_uuid = &lbgrp->uuid;

        lbgrp_dps = ovn_lb_group_datapaths_find(lbgrp_datapaths_map,
                                                lb_uuid);
        if (!lbgrp_dps) {
            lbgrp_dps = ovn_lb_group_datapaths_create(
                lbgrp, ods_size(ls_datapaths), ods_size(lr_datapaths));
            hmap_insert(lbgrp_datapaths_map, &lbgrp_dps->hmap_node,
                        uuid_hash(lb_uuid));
        }
    }

    struct crupdated_od_lb_data *codlb;
    LIST_FOR_EACH (codlb, list_node, &trk_lb_data->crupdated_ls_lbs) {
        od = ovn_datapath_find_(&ls_datapaths->datapaths, &codlb->od_uuid);
        ovs_assert(od);

        struct uuidset_node *uuidnode;
        UUIDSET_FOR_EACH (uuidnode, &codlb->assoc_lbs) {
            lb_dps = ovn_lb_datapaths_find(lb_datapaths_map, &uuidnode->uuid);
            ovs_assert(lb_dps);
            ovn_lb_datapaths_add_ls(lb_dps, 1, &od);

            /* Add the lb to the northd tracked data. */
            hmapx_add(&nd_changes->trk_lbs.crupdated, lb_dps);
        }

        UUIDSET_FOR_EACH (uuidnode, &codlb->assoc_lbgrps) {
            lbgrp_dps = ovn_lb_group_datapaths_find(lbgrp_datapaths_map,
                                                    &uuidnode->uuid);
            ovs_assert(lbgrp_dps);
            ovn_lb_group_datapaths_add_ls(lbgrp_dps, 1, &od);

            /* Associate all the lbs of the lbgrp to the datapath 'od' */
            for (size_t j = 0; j < lbgrp_dps->lb_group->n_lbs; j++) {
                const struct uuid *lb_uuid
                    = &lbgrp_dps->lb_group->lbs[j]->nlb->header_.uuid;
                lb_dps = ovn_lb_datapaths_find(lb_datapaths_map, lb_uuid);
                ovs_assert(lb_dps);
                ovn_lb_datapaths_add_ls(lb_dps, 1, &od);

                /* Add the lb to the northd tracked data. */
                hmapx_add(&nd_changes->trk_lbs.crupdated, lb_dps);
            }
        }

        /* Add the ls datapath to the northd tracked data. */
        hmapx_add(&nd_changes->ls_with_changed_lbs, od);
    }

    LIST_FOR_EACH (codlb, list_node, &trk_lb_data->crupdated_lr_lbs) {
        od = ovn_datapath_find_(&lr_datapaths->datapaths, &codlb->od_uuid);
        ovs_assert(od);

        struct uuidset_node *uuidnode;
        UUIDSET_FOR_EACH (uuidnode, &codlb->assoc_lbs) {
            lb_dps = ovn_lb_datapaths_find(lb_datapaths_map, &uuidnode->uuid);
            ovs_assert(lb_dps);
            ovn_lb_datapaths_add_lr(lb_dps, 1, &od);

            /* Add the lb to the northd tracked data. */
            hmapx_add(&nd_changes->trk_lbs.crupdated, lb_dps);
        }

        UUIDSET_FOR_EACH (uuidnode, &codlb->assoc_lbgrps) {
            lbgrp_dps = ovn_lb_group_datapaths_find(lbgrp_datapaths_map,
                                                    &uuidnode->uuid);
            ovs_assert(lbgrp_dps);
            ovn_lb_group_datapaths_add_lr(lbgrp_dps, od);

            /* Associate all the lbs of the lbgrp to the datapath 'od' */
            for (size_t j = 0; j < lbgrp_dps->lb_group->n_lbs; j++) {
                const struct uuid *lb_uuid
                    = &lbgrp_dps->lb_group->lbs[j]->nlb->header_.uuid;
                lb_dps = ovn_lb_datapaths_find(lb_datapaths_map, lb_uuid);
                ovs_assert(lb_dps);
                ovn_lb_datapaths_add_lr(lb_dps, 1, &od);

                /* Add the lb to the northd tracked data. */
                hmapx_add(&nd_changes->trk_lbs.crupdated, lb_dps);
            }
        }
    }

    HMAP_FOR_EACH (clb, hmap_node, &trk_lb_data->crupdated_lbs) {
        lb = clb->lb;
        const struct uuid *lb_uuid = &lb->nlb->header_.uuid;

        lb_dps = ovn_lb_datapaths_find(lb_datapaths_map, lb_uuid);
        ovs_assert(lb_dps);
        size_t index;
        BITMAP_FOR_EACH_1 (index, ods_size(ls_datapaths),
                           lb_dps->nb_ls_map) {
            od = ls_datapaths->array[index];

            /* Add the ls datapath to the northd tracked data. */
            hmapx_add(&nd_changes->ls_with_changed_lbs, od);
        }
    }

    HMAP_FOR_EACH (crupdated_lbgrp, hmap_node,
                   &trk_lb_data->crupdated_lbgrps) {
        lbgrp = crupdated_lbgrp->lbgrp;
        const struct uuid *lb_uuid = &lbgrp->uuid;

        lbgrp_dps = ovn_lb_group_datapaths_find(lbgrp_datapaths_map,
                                                lb_uuid);
        ovs_assert(lbgrp_dps);

        struct hmapx_node *hnode;
        HMAPX_FOR_EACH (hnode, &crupdated_lbgrp->assoc_lbs) {
            lb = hnode->data;
            lb_uuid = &lb->nlb->header_.uuid;
            lb_dps = ovn_lb_datapaths_find(lb_datapaths_map, lb_uuid);
            ovs_assert(lb_dps);
            for (size_t i = 0; i < lbgrp_dps->n_lr; i++) {
                od = lbgrp_dps->lr[i];
                ovn_lb_datapaths_add_lr(lb_dps, 1, &od);
            }

            for (size_t i = 0; i < lbgrp_dps->n_ls; i++) {
               od = lbgrp_dps->ls[i];
                ovn_lb_datapaths_add_ls(lb_dps, 1, &od);

                /* Add the ls datapath to the northd tracked data. */
                hmapx_add(&nd_changes->ls_with_changed_lbs, od);
            }

            /* Add the lb to the northd tracked data. */
            hmapx_add(&nd_changes->trk_lbs.crupdated, lb_dps);
        }
    }

    if (!hmapx_is_empty(&nd_changes->trk_lbs.crupdated)
        || !hmapx_is_empty(&nd_changes->trk_lbs.deleted)) {
        nd_changes->type |= NORTHD_TRACKED_LBS;
    }

    if (!hmapx_is_empty(&nd_changes->ls_with_changed_lbs)) {
        nd_changes->type |= NORTHD_TRACKED_LS_LBS;
    }

    return true;
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
ovn_igmp_group_add(struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp,
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
            mcast_group_lookup(sbrec_mcast_group_by_name_dp,
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

static struct ovn_port **
ovn_igmp_group_get_ports(const struct sbrec_igmp_group *sb_igmp_group,
                         size_t *n_ports, const struct hmap *ls_ports)
{
    struct ovn_port **ports = NULL;

     *n_ports = 0;
     for (size_t i = 0; i < sb_igmp_group->n_ports; i++) {
        struct ovn_port *port =
            ovn_port_find(ls_ports, sb_igmp_group->ports[i]->logical_port);

        if (!port || !port->nbsp) {
            continue;
        }

        /* If this is already a flood port skip it for the group. */
        if (port->mcast_info.flood) {
            continue;
        }

        /* If this is already a port of a router on which relay is enabled
         * and it's not a transit switch to router port, skip it for the
         * group.  Traffic is flooded there anyway.
         */
        if (port->peer && port->peer->od &&
                port->peer->od->mcast_info.rtr.relay &&
                !ovn_datapath_is_transit_switch(port->od)) {
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

int parallelization_state = STATE_NULL;


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
thread_local size_t thread_lflow_counter = 0;

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
                  "(ip4.src == {"IP_FMT", 0.0.0.0} "
                  "&& ip4.dst == {%s, 255.255.255.255})",
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

/* Adds the logical flows in the (in/out) check port sec stage only if
 *   - the lport is disabled or
 *   - lport is of type vtep - to skip the ingress pipeline.
 *   - lport has qdisc queue id is configured.
 *
 * For all the other logical ports,  generic flow added in
 * build_lswitch_lflows_admission_control() handles the port security.
 */
static void
build_lswitch_port_sec_op(struct ovn_port *op, struct lflow_table *lflows,
                          struct ds *actions, struct ds *match)
{
    ovs_assert(op->nbsp);

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
            op->key, &op->nbsp->header_, op->lflow_ref);

        ds_clear(match);
        ds_put_format(match, "outport == %s", op->json_key);
        ovn_lflow_add_with_lport_and_hint(
            lflows, op->od, S_SWITCH_IN_L2_UNKNOWN, 50, ds_cstr(match),
            debug_drop_action(), op->key, &op->nbsp->header_, op->lflow_ref);
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
                                          op->key, &op->nbsp->header_,
                                          op->lflow_ref);
    } else if (queue_id) {
        ds_put_cstr(actions,
                    REGBIT_PORT_SEC_DROP" = check_in_port_sec(); next;");
        ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                          S_SWITCH_IN_CHECK_PORT_SEC, 70,
                                          ds_cstr(match), ds_cstr(actions),
                                          op->key, &op->nbsp->header_,
                                          op->lflow_ref);

        if (!lsp_is_localnet(op->nbsp) && !op->od->n_localnet_ports) {
            return;
        }

        ds_clear(actions);
        ds_put_format(actions, "set_queue(%s); output;", queue_id);

        ds_clear(match);
        if (lsp_is_localnet(op->nbsp)) {
            ds_put_format(match, "outport == %s", op->json_key);
            ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                              S_SWITCH_OUT_APPLY_PORT_SEC, 100,
                                              ds_cstr(match), ds_cstr(actions),
                                              op->key, &op->nbsp->header_,
                                              op->lflow_ref);
        } else if (op->od->n_localnet_ports) {
            ds_put_format(match, "outport == %s && inport == %s",
                          op->od->localnet_ports[0]->json_key,
                          op->json_key);
            ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                    S_SWITCH_OUT_APPLY_PORT_SEC, 110,
                    ds_cstr(match), ds_cstr(actions),
                    op->od->localnet_ports[0]->key,
                    &op->od->localnet_ports[0]->nbsp->header_,
                    op->lflow_ref);
        }
    }
}

static void
build_lswitch_learn_fdb_op(
    struct ovn_port *op, struct lflow_table *lflows,
    struct ds *actions, struct ds *match)
{
    ovs_assert(op->nbsp);

    if (!op->n_ps_addrs && op->has_unknown && (!strcmp(op->nbsp->type, "") ||
        (lsp_is_localnet(op->nbsp) && localnet_can_learn_mac(op->nbsp)))) {
        ds_clear(match);
        ds_clear(actions);
        ds_put_format(match, "inport == %s", op->json_key);
        if (lsp_is_localnet(op->nbsp)) {
            ds_put_cstr(actions, "flags.localnet = 1; ");
        }
        ds_put_format(actions, REGBIT_LKUP_FDB
                      " = lookup_fdb(inport, eth.src); next;");
        ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                          S_SWITCH_IN_LOOKUP_FDB, 100,
                                          ds_cstr(match), ds_cstr(actions),
                                          op->key, &op->nbsp->header_,
                                          op->lflow_ref);

        ds_put_cstr(match, " && "REGBIT_LKUP_FDB" == 0");
        ds_clear(actions);
        ds_put_cstr(actions, "put_fdb(inport, eth.src); next;");
        ovn_lflow_add_with_lport_and_hint(lflows, op->od, S_SWITCH_IN_PUT_FDB,
                                          100, ds_cstr(match),
                                          ds_cstr(actions), op->key,
                                          &op->nbsp->header_,
                                          op->lflow_ref);
    }
}

static void
build_lswitch_learn_fdb_od(
    struct ovn_datapath *od, struct lflow_table *lflows,
    struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbs);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_LOOKUP_FDB, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PUT_FDB, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, 0, "1",
                  "outport = get_fdb(eth.dst); next;", lflow_ref);
}

/* Egress tables 8: Egress port security - IP (priority 0)
 * Egress table 9: Egress port security L2 - multicast/broadcast
 *                 (priority 100). */
static void
build_lswitch_output_port_sec_od(struct ovn_datapath *od,
                                 struct lflow_table *lflows,
                                 struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbs);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_CHECK_PORT_SEC, 100,
                  "eth.mcast", REGBIT_PORT_SEC_DROP" = 0; next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_CHECK_PORT_SEC, 0, "1",
                  REGBIT_PORT_SEC_DROP" = check_out_port_sec(); next;",
                  lflow_ref);

    ovn_lflow_add(lflows, od, S_SWITCH_OUT_APPLY_PORT_SEC, 50,
                  REGBIT_PORT_SEC_DROP" == 1", debug_drop_action(),
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_APPLY_PORT_SEC, 0,
                  "1", "output;", lflow_ref);
}

static void
skip_port_from_conntrack(const struct ovn_datapath *od, struct ovn_port *op,
                         bool has_stateful_acl, enum ovn_stage in_stage,
                         enum ovn_stage out_stage, uint16_t priority,
                         struct lflow_table *lflows,
                         struct lflow_ref *lflow_ref)
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

    const char *ingress_action = "next;";
    const char *egress_action = has_stateful_acl
                                ? "next;"
                                : "ct_clear; next;";

    char *ingress_match = xasprintf("ip && inport == %s", op->json_key);
    char *egress_match = xasprintf("ip && outport == %s", op->json_key);

    ovn_lflow_add_with_lport_and_hint(lflows, od, in_stage, priority,
                                      ingress_match, ingress_action,
                                      op->key, &op->nbsp->header_, lflow_ref);
    ovn_lflow_add_with_lport_and_hint(lflows, od, out_stage, priority,
                                      egress_match, egress_action,
                                      op->key, &op->nbsp->header_, lflow_ref);

    free(ingress_match);
    free(egress_match);
}

static void
build_stateless_filter(const struct ovn_datapath *od,
                       const struct nbrec_acl *acl,
                       struct lflow_table *lflows,
                       struct lflow_ref *lflow_ref)
{
    const char *action = REGBIT_ACL_STATELESS" = 1; next;";
    if (!strcmp(acl->direction, "from-lport")) {
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_PRE_ACL,
                                acl->priority + OVN_ACL_PRI_OFFSET,
                                acl->match,
                                action,
                                &acl->header_,
                                lflow_ref);
    } else {
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_OUT_PRE_ACL,
                                acl->priority + OVN_ACL_PRI_OFFSET,
                                acl->match,
                                action,
                                &acl->header_,
                                lflow_ref);
    }
}

static void
build_stateless_filters(const struct ovn_datapath *od,
                        const struct ls_port_group_table *ls_port_groups,
                        struct lflow_table *lflows,
                        struct lflow_ref *lflow_ref)
{
    for (size_t i = 0; i < od->nbs->n_acls; i++) {
        const struct nbrec_acl *acl = od->nbs->acls[i];
        if (!strcmp(acl->action, "allow-stateless")) {
            build_stateless_filter(od, acl, lflows, lflow_ref);
        }
    }

    const struct ls_port_group *ls_pg =
        ls_port_group_table_find(ls_port_groups, od->nbs);
    if (!ls_pg) {
        return;
    }

    const struct ls_port_group_record *ls_pg_rec;
    HMAP_FOR_EACH (ls_pg_rec, key_node, &ls_pg->nb_pgs) {
        for (size_t i = 0; i < ls_pg_rec->nb_pg->n_acls; i++) {
            const struct nbrec_acl *acl = ls_pg_rec->nb_pg->acls[i];

            if (!strcmp(acl->action, "allow-stateless")) {
                build_stateless_filter(od, acl, lflows, lflow_ref);
            }
        }
    }
}

static void
build_pre_acls(struct ovn_datapath *od, struct lflow_table *lflows,
               struct lflow_ref *lflow_ref)
{
    /* Ingress and Egress Pre-ACL Table (Priority 0): Packets are
     * allowed by default. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_ACL, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_ACL, 0, "1", "next;",
                  lflow_ref);

    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_ACL, 110,
                  "eth.dst == $svc_monitor_mac", "next;",
                  lflow_ref);

    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_ACL, 110,
                  "eth.src == $svc_monitor_mac", "next;",
                  lflow_ref);
}

static void
build_ls_stateful_rec_pre_acls(
    const struct ls_stateful_record *ls_stateful_rec,
    const struct ovn_datapath *od,
    const struct ls_port_group_table *ls_port_groups,
    struct lflow_table *lflows,
    struct lflow_ref *lflow_ref)
{
    /* If there are any stateful ACL rules in this datapath, we may
     * send IP packets for some (allow) filters through the conntrack action,
     * which handles defragmentation, in order to match L4 headers. */
    if (ls_stateful_rec->has_stateful_acl) {
        for (size_t i = 0; i < od->n_router_ports; i++) {
            struct ovn_port *op = od->router_ports[i];
            if (op->enable_router_port_acl) {
                continue;
            }
            skip_port_from_conntrack(od, op, true,
                                     S_SWITCH_IN_PRE_ACL, S_SWITCH_OUT_PRE_ACL,
                                     110, lflows, lflow_ref);
        }
        for (size_t i = 0; i < od->n_localnet_ports; i++) {
            skip_port_from_conntrack(od, od->localnet_ports[i], true,
                                     S_SWITCH_IN_PRE_ACL,
                                     S_SWITCH_OUT_PRE_ACL,
                                     110, lflows, lflow_ref);
        }

        /* stateless filters always take precedence over stateful ACLs. */
        build_stateless_filters(od, ls_port_groups, lflows, lflow_ref);

        /* Ingress and Egress Pre-ACL Table (Priority 110).
         *
         * Not to do conntrack on ND and ICMP destination
         * unreachable packets. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_ACL, 110,
                      "nd || nd_rs || nd_ra || mldv1 || mldv2 || "
                      "(udp && udp.src == 546 && udp.dst == 547)", "next;",
                      lflow_ref);
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_ACL, 110,
                      "nd || nd_rs || nd_ra || mldv1 || mldv2 || "
                      "(udp && udp.src == 546 && udp.dst == 547)", "next;",
                      lflow_ref);

        /* Do not send multicast packets to conntrack. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_ACL, 110, "eth.mcast",
                      "next;", lflow_ref);
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_ACL, 110, "eth.mcast",
                      "next;", lflow_ref);

        /* Ingress and Egress Pre-ACL Table (Priority 100).
         *
         * Regardless of whether the ACL is "from-lport" or "to-lport",
         * we need rules in both the ingress and egress table, because
         * the return traffic needs to be followed.
         *
         * 'REGBIT_CONNTRACK_DEFRAG' is set to let the pre-stateful table send
         * it to conntrack for tracking and defragmentation. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_ACL, 100, "ip",
                      REGBIT_CONNTRACK_DEFRAG" = 1; next;",
                      lflow_ref);
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_ACL, 100, "ip",
                      REGBIT_CONNTRACK_DEFRAG" = 1; next;",
                      lflow_ref);
    } else if (ls_stateful_rec->has_lb_vip) {
        /* We'll build stateless filters if there are LB rules so that
         * the stateless flows are not tracked in pre-lb. */
         build_stateless_filters(od, ls_port_groups, lflows, lflow_ref);
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
                                  struct lflow_table *lflows,
                                  struct lflow_ref *lflow_ref)
{
    struct mcast_switch_info *mcast_sw_info = &od->mcast_info.sw;
    if (!mcast_sw_info->enabled
        || !smap_get(&od->nbs->other_config, "interconn-ts")) {
        return;
    }

    struct ovn_port *op;

    HMAP_FOR_EACH (op, dp_node, &od->ports) {
        if (!lsp_is_remote(op->nbsp)) {
            continue;
        }
        /* Punt IGMP traffic to controller. */
        char *match = xasprintf("inport == %s && igmp && "
                                "flags.igmp_loopback == 0", op->json_key);
        ovn_lflow_metered(lflows, od, S_SWITCH_OUT_PRE_LB, 120, match,
                          "clone { igmp; }; next;",
                          copp_meter_get(COPP_IGMP, od->nbs->copp,
                                         meter_groups),
                          lflow_ref);
        free(match);

        /* Punt MLD traffic to controller. */
        match = xasprintf("inport == %s && (mldv1 || mldv2) && "
                          "flags.igmp_loopback == 0", op->json_key);
        ovn_lflow_metered(lflows, od, S_SWITCH_OUT_PRE_LB, 120, match,
                          "clone { igmp; }; next;",
                          copp_meter_get(COPP_IGMP, od->nbs->copp,
                                         meter_groups),
                          lflow_ref);
        free(match);
    }
}

static void
build_pre_lb(struct ovn_datapath *od, const struct shash *meter_groups,
             struct lflow_table *lflows, struct lflow_ref *lflow_ref)
{
    /* Handle IGMP/MLD packets crossing AZs. */
    build_interconn_mcast_snoop_flows(od, meter_groups, lflows, lflow_ref);

    /* Do not send multicast packets to conntrack */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_LB, 110, "eth.mcast", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_LB, 110, "eth.mcast", "next;",
                  lflow_ref);

    /* Do not send ND packets to conntrack */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_LB, 110,
                  "nd || nd_rs || nd_ra || mldv1 || mldv2",
                  "next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_LB, 110,
                  "nd || nd_rs || nd_ra || mldv1 || mldv2",
                  "next;", lflow_ref);

    /* Do not send service monitor packets to conntrack. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_LB, 110,
                  "eth.dst == $svc_monitor_mac", "next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_LB, 110,
                  "eth.src == $svc_monitor_mac", "next;", lflow_ref);

    /* Allow all packets to go to next tables by default. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_LB, 0, "1", "next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_LB, 0, "1", "next;", lflow_ref);

    /* Do not send statless flows via conntrack */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_LB, 110,
                  REGBIT_ACL_STATELESS" == 1", "next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_LB, 110,
                  REGBIT_ACL_STATELESS" == 1", "next;", lflow_ref);
}

static void
build_ls_stateful_rec_pre_lb(const struct ls_stateful_record *ls_stateful_rec,
                             const struct ovn_datapath *od,
                             struct lflow_table *lflows,
                             struct lflow_ref *lflow_ref)
{
    for (size_t i = 0; i < od->n_router_ports; i++) {
        skip_port_from_conntrack(od, od->router_ports[i],
                                 ls_stateful_rec->has_stateful_acl,
                                 S_SWITCH_IN_PRE_LB, S_SWITCH_OUT_PRE_LB,
                                 110, lflows, lflow_ref);
    }

    /* Localnet ports have no need for going through conntrack, unless
     * the logical switch has a load balancer. Then, conntrack is necessary
     * so that traffic arriving via the localnet port can be load
     * balanced.
     */
    if (!ls_stateful_rec->has_lb_vip) {
        for (size_t i = 0; i < od->n_localnet_ports; i++) {
            skip_port_from_conntrack(od, od->localnet_ports[i],
                                     ls_stateful_rec->has_stateful_acl,
                                     S_SWITCH_IN_PRE_LB, S_SWITCH_OUT_PRE_LB,
                                     110, lflows, lflow_ref);
        }
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
    if (ls_stateful_rec->has_lb_vip) {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_LB,
                      100, "ip", REGBIT_CONNTRACK_NAT" = 1; next;",
                      lflow_ref);
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_LB,
                      100, "ip", REGBIT_CONNTRACK_NAT" = 1; next;",
                      lflow_ref);
    }
}

static void
build_pre_stateful(struct ovn_datapath *od,
                   const struct chassis_features *features,
                   struct lflow_table *lflows,
                   struct lflow_ref *lflow_ref)
{
    /* Ingress and Egress pre-stateful Table (Priority 0): Packets are
     * allowed by default. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_STATEFUL, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_STATEFUL, 0, "1", "next;",
                  lflow_ref);

    /* Note: priority-120 flows are added in build_lb_rules_pre_stateful(). */

    const char *ct_lb_action = features->ct_no_masked_label
                               ? "ct_lb_mark;"
                               : "ct_lb;";

    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_STATEFUL, 110,
                  REGBIT_CONNTRACK_NAT" == 1", ct_lb_action,
                  lflow_ref);

    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_STATEFUL, 110,
                  REGBIT_CONNTRACK_NAT" == 1", ct_lb_action,
                  lflow_ref);

    /* If REGBIT_CONNTRACK_DEFRAG is set as 1, then the packets should be
     * sent to conntrack for tracking and defragmentation. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_STATEFUL, 100,
                  REGBIT_CONNTRACK_DEFRAG" == 1", "ct_next;",
                  lflow_ref);

    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_STATEFUL, 100,
                  REGBIT_CONNTRACK_DEFRAG" == 1", "ct_next;",
                  lflow_ref);

}

static void
build_acl_hints(const struct ls_stateful_record *ls_stateful_rec,
                const struct ovn_datapath *od,
                const struct chassis_features *features,
                struct lflow_table *lflows,
                struct lflow_ref *lflow_ref)
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
        if (!ls_stateful_rec->has_acls && !ls_stateful_rec->has_lb_vip) {
            ovn_lflow_add(lflows, od, stage, UINT16_MAX, "1", "next;",
                          lflow_ref);
        } else {
            ovn_lflow_add(lflows, od, stage, 0, "1", "next;", lflow_ref);
        }

        if (!ls_stateful_rec->has_stateful_acl
            && !ls_stateful_rec->has_lb_vip) {
            continue;
        }

        /* New, not already established connections, may hit either allow
         * or drop ACLs. For allow ACLs, the connection must also be committed
         * to conntrack so we set REGBIT_ACL_HINT_ALLOW_NEW.
         */
        ovn_lflow_add(lflows, od, stage, 7, "ct.new && !ct.est",
                      REGBIT_ACL_HINT_ALLOW_NEW " = 1; "
                      REGBIT_ACL_HINT_DROP " = 1; "
                      "next;", lflow_ref);

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
                      "next;", lflow_ref);

        /* Not tracked traffic can either be allowed or dropped. */
        ovn_lflow_add(lflows, od, stage, 5, "!ct.trk",
                      REGBIT_ACL_HINT_ALLOW " = 1; "
                      REGBIT_ACL_HINT_DROP " = 1; "
                      "next;", lflow_ref);

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
                      "next;", lflow_ref);

        /* Not established or established and already blocked connections may
         * hit drop ACLs.
         */
        ovn_lflow_add(lflows, od, stage, 3, "!ct.est",
                      REGBIT_ACL_HINT_DROP " = 1; "
                      "next;", lflow_ref);
        match = features->ct_no_masked_label
                ? "ct.est && ct_mark.blocked == 1"
                : "ct.est && ct_label.blocked == 1";
        ovn_lflow_add(lflows, od, stage, 2, match,
                      REGBIT_ACL_HINT_DROP " = 1; "
                      "next;", lflow_ref);

        /* Established connections that were previously allowed might hit
         * drop ACLs in which case the connection must be committed with
         * ct_mark.blocked set.
         */
        match = features->ct_no_masked_label
                ? "ct.est && ct_mark.blocked == 0"
                : "ct.est && ct_label.blocked == 0";
        ovn_lflow_add(lflows, od, stage, 1, match,
                      REGBIT_ACL_HINT_BLOCK " = 1; "
                      "next;", lflow_ref);
    }
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
    } else if (!strcmp(acl->action, "pass")) {
        ds_put_cstr(actions, "verdict=pass, ");
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
consider_acl(struct lflow_table *lflows, const struct ovn_datapath *od,
             const struct nbrec_acl *acl, bool has_stateful,
             bool ct_masked_mark, const struct shash *meter_groups,
             uint64_t max_acl_tier, struct ds *match, struct ds *actions,
             struct lflow_ref *lflow_ref)
{
    const char *ct_blocked_match = ct_masked_mark
                                   ? "ct_mark.blocked"
                                   : "ct_label.blocked";
    bool ingress = !strcmp(acl->direction, "from-lport") ? true :false;
    enum ovn_stage stage;

    if (ingress && smap_get_bool(&acl->options, "apply-after-lb", false)) {
        stage = S_SWITCH_IN_ACL_AFTER_LB_EVAL;
    } else if (ingress) {
        stage = S_SWITCH_IN_ACL_EVAL;
    } else {
        stage = S_SWITCH_OUT_ACL_EVAL;
    }

    const char *verdict;
    if (!strcmp(acl->action, "drop")) {
        verdict = REGBIT_ACL_VERDICT_DROP " = 1; ";
    } else if (!strcmp(acl->action, "reject")) {
        verdict = REGBIT_ACL_VERDICT_REJECT " = 1; ";
    } else if (!strcmp(acl->action, "pass")) {
        verdict = "";
    } else {
        verdict = REGBIT_ACL_VERDICT_ALLOW " = 1; ";
    }

    ds_clear(actions);
    /* All ACLs will have the same actions as a basis. */
    build_acl_log(actions, acl, meter_groups);
    ds_put_cstr(actions, verdict);
    size_t log_verdict_len = actions->length;
    uint16_t priority = acl->priority + OVN_ACL_PRI_OFFSET;

    /* All ACLS will start by matching on their respective tier. */
    size_t match_tier_len = 0;
    ds_clear(match);
    if (max_acl_tier) {
        ds_put_format(match, REG_ACL_TIER " == %"PRId64" && ", acl->tier);
        match_tier_len = match->length;
    }

    if (!has_stateful
        || !strcmp(acl->action, "pass")
        || !strcmp(acl->action, "allow-stateless")) {
        ds_put_cstr(actions, "next;");
        ds_put_format(match, "(%s)", acl->match);
        ovn_lflow_add_with_hint(lflows, od, stage, priority,
                                ds_cstr(match), ds_cstr(actions),
                                &acl->header_, lflow_ref);
        return;
    }

    if (!strcmp(acl->action, "allow")
        || !strcmp(acl->action, "allow-related")) {
        /* If there are any stateful flows, we must even commit "allow"
         * actions.  This is because, while the initiater's
         * direction may not have any stateful rules, the server's
         * may and then its return traffic would not have an
         * associated conntrack entry and would return "+invalid". */

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
        ds_truncate(match, match_tier_len);
        ds_put_format(match, REGBIT_ACL_HINT_ALLOW_NEW " == 1 && (%s)",
                      acl->match);

        ds_truncate(actions, log_verdict_len);
        ds_put_cstr(actions, REGBIT_CONNTRACK_COMMIT" = 1; ");
        if (acl->label) {
            ds_put_format(actions, REGBIT_ACL_LABEL" = 1; "
                          REG_LABEL" = %"PRId64"; ", acl->label);
        }
        ds_put_cstr(actions, "next;");
        ovn_lflow_add_with_hint(lflows, od, stage, priority,
                                ds_cstr(match), ds_cstr(actions),
                                &acl->header_, lflow_ref);

        /* Match on traffic in the request direction for an established
         * connection tracking entry that has not been marked for
         * deletion. We use this to ensure that this
         * connection is still allowed by the currently defined
         * policy. Match untracked packets too.
         * Commit the connection only if the ACL has a label. This is done
         * to update the connection tracking entry label in case the ACL
         * allowing the connection changes. */
        ds_truncate(match, match_tier_len);
        ds_truncate(actions, log_verdict_len);
        ds_put_format(match, REGBIT_ACL_HINT_ALLOW " == 1 && (%s)",
                      acl->match);
        if (acl->label) {
            ds_put_cstr(actions, REGBIT_CONNTRACK_COMMIT" = 1; ");
            ds_put_format(actions, REGBIT_ACL_LABEL" = 1; "
                          REG_LABEL" = %"PRId64"; ", acl->label);
        }
        ds_put_cstr(actions, "next;");
        ovn_lflow_add_with_hint(lflows, od, stage, priority,
                                ds_cstr(match), ds_cstr(actions),
                                &acl->header_, lflow_ref);
    } else if (!strcmp(acl->action, "drop")
               || !strcmp(acl->action, "reject")) {
        /* The implementation of "drop" differs if stateful ACLs are in
         * use for this datapath.  In that case, the actions differ
         * depending on whether the connection was previously committed
         * to the connection tracker with ct_commit. */
        /* If the packet is not tracked or not part of an established
         * connection, then we can simply reject/drop it. */
        ds_truncate(match, match_tier_len);
        ds_put_cstr(match, REGBIT_ACL_HINT_DROP " == 1");
        ds_put_format(match, " && (%s)", acl->match);

        ds_truncate(actions, log_verdict_len);
        ds_put_cstr(actions, "next;");
        ovn_lflow_add_with_hint(lflows, od, stage, priority,
                                ds_cstr(match), ds_cstr(actions),
                                &acl->header_, lflow_ref);
        /* For an existing connection without ct_mark.blocked set, we've
         * encountered a policy change. ACLs previously allowed
         * this connection and we committed the connection tracking
         * entry.  Current policy says that we should drop this
         * connection.  First, we set ct_mark.blocked to indicate
         * that this connection is set for deletion.  By not
         * specifying "next;", we implicitly drop the packet after
         * updating conntrack state.  We would normally defer
         * ct_commit to the "stateful" stage, but since we're
         * rejecting/dropping the packet, we go ahead and do it here.
         */
        ds_truncate(match, match_tier_len);
        ds_put_cstr(match, REGBIT_ACL_HINT_BLOCK " == 1");
        ds_put_format(match, " && (%s)", acl->match);

        ds_truncate(actions, log_verdict_len);
        ds_put_format(actions, "ct_commit { %s = 1; }; next;",
                      ct_blocked_match);
        ovn_lflow_add_with_hint(lflows, od, stage, priority,
                                ds_cstr(match), ds_cstr(actions),
                                &acl->header_, lflow_ref);
    }
}

static void
copy_ra_to_sb(struct ovn_port *op, const char *address_mode);

static void
ovn_update_ipv6_opt_for_op(struct ovn_port *op)
{
    ovs_assert(op->nbrp);

    if (op->nbrp->peer || !op->peer) {
        return;
    }

    if (!op->lrp_networks.n_ipv6_addrs) {
        return;
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

    bool ipv6_prefix = smap_get_bool(&op->nbrp->options, "prefix", false);
    if (!lrport_is_enabled(op->nbrp)) {
        ipv6_prefix = false;
    }
    if (smap_get_bool(&options, "ipv6_prefix", false) != ipv6_prefix) {
        smap_add(&options, "ipv6_prefix", ipv6_prefix ? "true" : "false");
    }
    sbrec_port_binding_set_options(op->sb, &options);

    smap_destroy(&options);

    const char *address_mode = smap_get(&op->nbrp->ipv6_ra_configs,
                                        "address_mode");

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

    if (smap_get_bool(&op->nbrp->ipv6_ra_configs, "send_periodic", false)) {
        copy_ra_to_sb(op, address_mode);
    }
}

static void
ovn_update_ipv6_options(struct hmap *lr_ports)
{
    struct ovn_port *op;
    HMAP_FOR_EACH (op, key_node, lr_ports) {
        ovn_update_ipv6_opt_for_op(op);
    }
}

#define IPV6_CT_OMIT_MATCH "nd || nd_ra || nd_rs || mldv1 || mldv2"

static void
build_acl_action_lflows(const struct ls_stateful_record *ls_stateful_rec,
                        const struct ovn_datapath *od,
                        struct lflow_table *lflows,
                        const char *default_acl_action,
                        const struct shash *meter_groups,
                        struct ds *match,
                        struct ds *actions,
                        struct lflow_ref *lflow_ref)
{
    enum ovn_stage stages [] = {
        S_SWITCH_IN_ACL_ACTION,
        S_SWITCH_IN_ACL_AFTER_LB_ACTION,
        S_SWITCH_OUT_ACL_ACTION,
    };

    ds_clear(actions);
    ds_put_cstr(actions, REGBIT_ACL_VERDICT_ALLOW " = 0; "
                        REGBIT_ACL_VERDICT_DROP " = 0; "
                        REGBIT_ACL_VERDICT_REJECT " = 0; ");
    if (ls_stateful_rec->max_acl_tier) {
        ds_put_cstr(actions, REG_ACL_TIER " = 0; ");
    }

    size_t verdict_len = actions->length;

    for (size_t i = 0; i < ARRAY_SIZE(stages); i++) {
        enum ovn_stage stage = stages[i];
        if (!ls_stateful_rec->has_acls) {
            ovn_lflow_add(lflows, od, stage, 0, "1", "next;", lflow_ref);
            continue;
        }
        ds_truncate(actions, verdict_len);
        ds_put_cstr(actions, "next;");
        ovn_lflow_add(lflows, od, stage, 1000,
                      REGBIT_ACL_VERDICT_ALLOW " == 1", ds_cstr(actions),
                      lflow_ref);
        ds_truncate(actions, verdict_len);
        ds_put_cstr(actions, debug_implicit_drop_action());
        ovn_lflow_add(lflows, od, stage, 1000,
                      REGBIT_ACL_VERDICT_DROP " == 1",
                      ds_cstr(actions),
                      lflow_ref);
        bool ingress = ovn_stage_get_pipeline(stage) == P_IN;

        ds_truncate(actions, verdict_len);
        ds_put_format(
            actions, "reg0 = 0; "
            "reject { "
            "/* eth.dst <-> eth.src; ip.dst <-> ip.src; is implicit. */ "
            "outport <-> inport; next(pipeline=%s,table=%d); };",
            ingress ? "egress" : "ingress",
            ingress ? ovn_stage_get_table(S_SWITCH_OUT_QOS)
                : ovn_stage_get_table(S_SWITCH_IN_L2_LKUP));

        ovn_lflow_metered(lflows, od, stage, 1000,
                          REGBIT_ACL_VERDICT_REJECT " == 1", ds_cstr(actions),
                          copp_meter_get(COPP_REJECT, od->nbs->copp,
                          meter_groups), lflow_ref);

        ds_truncate(actions, verdict_len);
        ds_put_cstr(actions, default_acl_action);
        ovn_lflow_add(lflows, od, stage, 0, "1", ds_cstr(actions), lflow_ref);

        struct ds tier_actions = DS_EMPTY_INITIALIZER;
        for (size_t j = 0; j < ls_stateful_rec->max_acl_tier; j++) {
            ds_clear(match);
            ds_put_format(match, REG_ACL_TIER " == %"PRIuSIZE, j);
            ds_clear(&tier_actions);
            ds_put_format(&tier_actions, REG_ACL_TIER " = %"PRIuSIZE"; "
                          "next(pipeline=%s,table=%d);",
                          j + 1, ingress ? "ingress" : "egress",
                          ovn_stage_get_table(stage) - 1);
            ovn_lflow_add(lflows, od, stage, 500, ds_cstr(match),
                         ds_cstr(&tier_actions), lflow_ref);
        }
        ds_destroy(&tier_actions);
    }
}

static void
build_acl_log_related_flows(const struct ovn_datapath *od,
                            struct lflow_table *lflows,
                            const struct nbrec_acl *acl, bool has_stateful,
                            bool ct_masked_mark,
                            const struct shash *meter_groups,
                            struct ds *match, struct ds *actions,
                            struct lflow_ref *lflow_ref)
{
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
    const char *ct_blocked_match = ct_masked_mark
                                   ? "ct_mark.blocked"
                                   : "ct_label.blocked";
    bool ingress = !strcmp(acl->direction, "from-lport") ? true :false;
    bool log_related = smap_get_bool(&acl->options, "log-related",
                                     false);

    if (!strcmp(acl->action, "allow-stateless") || !has_stateful) {
        /* Not stateful */
        return;
    }

    if (strcmp(acl->action, "allow") && strcmp(acl->action, "allow-related")) {
        /* Not an allow ACL */
        return;
    }

    if (!acl->log || !acl->label || !log_related) {
        /* Missing requirements for logging related ACLs */
        return;
    }

    ds_clear(actions);
    build_acl_log(actions, acl, meter_groups);
    ds_put_cstr(actions, REGBIT_ACL_VERDICT_ALLOW" = 1; next;");
    /* Related/reply flows need to be set on the opposite pipeline
     * from where the ACL itself is set.
     */
    enum ovn_stage log_related_stage = ingress ?
        S_SWITCH_OUT_ACL_EVAL :
        S_SWITCH_IN_ACL_EVAL;
    ds_clear(match);
    ds_put_format(match, "ct.est && !ct.rel && !ct.new%s && "
                  "ct.rpl && %s == 0 && "
                  "ct_label.label == %" PRId64,
                  use_ct_inv_match ? " && !ct.inv" : "",
                  ct_blocked_match, acl->label);
    ovn_lflow_add_with_hint(lflows, od, log_related_stage,
                            UINT16_MAX - 2,
                            ds_cstr(match), ds_cstr(actions),
                            &acl->header_, lflow_ref);

    ds_clear(match);
    ds_put_format(match, "!ct.est && ct.rel && !ct.new%s && "
                         "%s == 0 && "
                         "ct_label.label == %" PRId64,
                         use_ct_inv_match ? " && !ct.inv" : "",
                         ct_blocked_match, acl->label);
    ovn_lflow_add_with_hint(lflows, od, log_related_stage,
                            UINT16_MAX - 2,
                            ds_cstr(match), ds_cstr(actions),
                            &acl->header_, lflow_ref);
}

static void
build_acls(const struct ls_stateful_record *ls_stateful_rec,
           const struct ovn_datapath *od,
           const struct chassis_features *features,
           struct lflow_table *lflows,
           const struct ls_port_group_table *ls_port_groups,
           const struct shash *meter_groups,
           struct lflow_ref *lflow_ref)
{
    const char *default_acl_action = default_acl_drop
                                     ? debug_implicit_drop_action()
                                     : "next;";
    bool has_stateful = (ls_stateful_rec->has_stateful_acl
                         || ls_stateful_rec->has_lb_vip);
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
    if (!ls_stateful_rec->has_acls) {
        if (!ls_stateful_rec->has_lb_vip) {
            ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_EVAL, UINT16_MAX, "1",
                          "next;", lflow_ref);
            ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL_EVAL, UINT16_MAX, "1",
                          "next;", lflow_ref);
        } else {
            ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_EVAL, 0, "1", "next;",
                          lflow_ref);
            ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL_EVAL, 0, "1", "next;",
                          lflow_ref);
        }
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_AFTER_LB_EVAL, 0, "1",
                      "next;", lflow_ref);
    } else {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_EVAL, 0, "1", "next;",
                      lflow_ref);
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL_EVAL, 0, "1", "next;",
                      lflow_ref);
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_AFTER_LB_EVAL, 0, "1",
                      "next;", lflow_ref);
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
         * which will be done by ct_commit in the "stateful" stage.
         * Subsequent packets will hit the flow at priority 0 that just
         * uses "next;". */
        ds_clear(&match);
        ds_put_format(&match, "ip && ct.est && %s == 1", ct_blocked_match);
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_EVAL, 1,
                      ds_cstr(&match),
                      REGBIT_CONNTRACK_COMMIT" = 1; "
                      REGBIT_ACL_VERDICT_ALLOW" = 1; next;",
                      lflow_ref);
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL_EVAL, 1,
                      ds_cstr(&match),
                      REGBIT_CONNTRACK_COMMIT" = 1; "
                      REGBIT_ACL_VERDICT_ALLOW" = 1; next;",
                      lflow_ref);

        const char *next_action = default_acl_drop
                             ? "next;"
                             : REGBIT_CONNTRACK_COMMIT" = 1; next;";
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_EVAL, 1, "ip && !ct.est",
                      next_action, lflow_ref);
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL_EVAL, 1, "ip && !ct.est",
                      next_action, lflow_ref);

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
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_EVAL, UINT16_MAX - 3,
                      ds_cstr(&match), REGBIT_ACL_VERDICT_DROP " = 1; next;",
                      lflow_ref);
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL_EVAL, UINT16_MAX - 3,
                      ds_cstr(&match), REGBIT_ACL_VERDICT_DROP " = 1; next;",
                      lflow_ref);

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
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_EVAL, UINT16_MAX - 3,
                      ds_cstr(&match), REGBIT_ACL_HINT_DROP" = 0; "
                      REGBIT_ACL_HINT_BLOCK" = 0; "
                      REGBIT_ACL_HINT_ALLOW_REL" = 1; "
                      REGBIT_ACL_VERDICT_ALLOW" = 1; next;",
                      lflow_ref);
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL_EVAL, UINT16_MAX - 3,
                      ds_cstr(&match),
                      REGBIT_ACL_VERDICT_ALLOW " = 1; next;",
                      lflow_ref);

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
        const char *ct_in_acl_action =
            features->ct_lb_related
            ? REGBIT_ACL_HINT_ALLOW_REL" = 1; "
              REGBIT_ACL_VERDICT_ALLOW" = 1; ct_commit_nat;"
            : REGBIT_ACL_HINT_ALLOW_REL" = 1; "
              REGBIT_ACL_VERDICT_ALLOW" = 1; next;";
        const char *ct_out_acl_action =
            features->ct_lb_related
            ? REGBIT_ACL_VERDICT_ALLOW" = 1; ct_commit_nat;"
            : REGBIT_ACL_VERDICT_ALLOW" = 1; next;";
        ds_clear(&match);
        ds_put_format(&match, "!ct.est && ct.rel && !ct.new%s && %s == 0",
                      use_ct_inv_match ? " && !ct.inv" : "",
                      ct_blocked_match);
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_EVAL, UINT16_MAX - 3,
                      ds_cstr(&match), ct_in_acl_action, lflow_ref);
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL_EVAL, UINT16_MAX - 3,
                      ds_cstr(&match), ct_out_acl_action, lflow_ref);
        /* Reply and related traffic matched by an "allow-related" ACL
         * should be allowed in the ls_in_acl_after_lb stage too. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_AFTER_LB_EVAL,
                      UINT16_MAX - 3,
                      REGBIT_ACL_HINT_ALLOW_REL" == 1",
                      REGBIT_ACL_VERDICT_ALLOW " = 1; next;",
                      lflow_ref);
    }

    /* Ingress and Egress ACL Table (Priority 65532).
     *
     * Always allow service IPv6 protocols regardless of other ACLs defined.
     *
     * Also, don't send them to conntrack because session tracking
     * for these protocols is not working properly:
     * https://bugzilla.kernel.org/show_bug.cgi?id=11797. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_EVAL, UINT16_MAX - 3,
                  IPV6_CT_OMIT_MATCH,
                  REGBIT_ACL_VERDICT_ALLOW " = 1; next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL_EVAL, UINT16_MAX - 3,
                  IPV6_CT_OMIT_MATCH,
                  REGBIT_ACL_VERDICT_ALLOW " = 1; next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_AFTER_LB_EVAL, UINT16_MAX - 3,
                  IPV6_CT_OMIT_MATCH,
                  REGBIT_ACL_VERDICT_ALLOW " = 1; next;",
                  lflow_ref);

    /* Ingress or Egress ACL Table (Various priorities). */
    for (size_t i = 0; i < od->nbs->n_acls; i++) {
        struct nbrec_acl *acl = od->nbs->acls[i];
        build_acl_log_related_flows(od, lflows, acl, has_stateful,
                                    features->ct_no_masked_label,
                                    meter_groups, &match, &actions,
                                    lflow_ref);
        consider_acl(lflows, od, acl, has_stateful,
                     features->ct_no_masked_label,
                     meter_groups, ls_stateful_rec->max_acl_tier,
                     &match, &actions, lflow_ref);
    }

    const struct ls_port_group *ls_pg =
        ls_port_group_table_find(ls_port_groups, od->nbs);
    if (ls_pg) {
        const struct ls_port_group_record *ls_pg_rec;
        HMAP_FOR_EACH (ls_pg_rec, key_node, &ls_pg->nb_pgs) {
            for (size_t i = 0; i < ls_pg_rec->nb_pg->n_acls; i++) {
                const struct nbrec_acl *acl = ls_pg_rec->nb_pg->acls[i];

                build_acl_log_related_flows(od, lflows, acl, has_stateful,
                                            features->ct_no_masked_label,
                                            meter_groups, &match, &actions,
                                            lflow_ref);
                consider_acl(lflows, od, acl, has_stateful,
                             features->ct_no_masked_label,
                             meter_groups, ls_stateful_rec->max_acl_tier,
                             &match, &actions, lflow_ref);
            }
        }
    }

    /* Add a 34000 priority flow to advance the DNS reply from ovn-controller,
     * if the CMS has configured DNS records for the datapath.
     */
    if (ls_has_dns_records(od->nbs)) {
        const char *dns_actions =
            has_stateful ? REGBIT_ACL_VERDICT_ALLOW" = 1; "
                           "ct_commit; next;"
                         : REGBIT_ACL_VERDICT_ALLOW" = 1; next;";
        ovn_lflow_add(
            lflows, od, S_SWITCH_OUT_ACL_EVAL, 34000, "udp.src == 53",
            dns_actions, lflow_ref);
    }

    if (ls_stateful_rec->has_acls || ls_stateful_rec->has_lb_vip) {
        /* Add a 34000 priority flow to advance the service monitor reply
        * packets to skip applying ingress ACLs. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL_EVAL, 34000,
                    "eth.dst == $svc_monitor_mac",
                    REGBIT_ACL_VERDICT_ALLOW" = 1; next;",
                    lflow_ref);

        /* Add a 34000 priority flow to advance the service monitor packets
        * generated by ovn-controller to skip applying egress ACLs. */
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL_EVAL, 34000,
                    "eth.src == $svc_monitor_mac",
                    REGBIT_ACL_VERDICT_ALLOW" = 1; next;",
                    lflow_ref);
    }

    build_acl_action_lflows(ls_stateful_rec, od, lflows, default_acl_action,
                            meter_groups, &match, &actions, lflow_ref);

    ds_destroy(&match);
    ds_destroy(&actions);
}

#define QOS_MAX_DSCP 63

static void
build_qos(struct ovn_datapath *od, struct lflow_table *lflows,
          struct lflow_ref *lflow_ref) {
    struct ds action = DS_EMPTY_INITIALIZER;

    ovn_lflow_add(lflows, od, S_SWITCH_IN_QOS, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_QOS, 0, "1", "next;",
                  lflow_ref);

    for (size_t i = 0; i < od->nbs->n_qos_rules; i++) {
        struct nbrec_qos *qos = od->nbs->qos_rules[i];
        bool ingress = !strcmp(qos->direction, "from-lport") ? true :false;
        enum ovn_stage stage = ingress ? S_SWITCH_IN_QOS : S_SWITCH_OUT_QOS;
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        int64_t rate = 0;
        int64_t burst = 0;

        ds_clear(&action);
        for (size_t n = 0; n < qos->n_bandwidth; n++) {
            if (!strcmp(qos->key_bandwidth[n], "rate")) {
                rate = qos->value_bandwidth[n];
            } else if (!strcmp(qos->key_bandwidth[n], "burst")) {
                burst = qos->value_bandwidth[n];
            }
        }
        if (rate) {
            stage = ingress ? S_SWITCH_IN_QOS : S_SWITCH_OUT_QOS;
            if (burst) {
                ds_put_format(&action,
                              "set_meter(%"PRId64", %"PRId64"); ",
                              rate, burst);
            } else {
                ds_put_format(&action,
                              "set_meter(%"PRId64"); ",
                              rate);
            }
        }
        for (size_t j = 0; j < qos->n_action; j++) {
            if (!strcmp(qos->key_action[j], "dscp")) {
                if (qos->value_action[j] > QOS_MAX_DSCP) {
                    VLOG_WARN_RL(&rl, "Bad 'dscp' value %"PRId64" in qos "
                                      UUID_FMT, qos->value_action[j],
                                      UUID_ARGS(&qos->header_.uuid));
                    continue;
                }

                ds_put_format(&action, "ip.dscp = %"PRId64"; ",
                              qos->value_action[j]);
            } else if (!strcmp(qos->key_action[j], "mark")) {
                ds_put_format(&action, "pkt.mark = %"PRId64"; ",
                              qos->value_action[j]);
            }
        }
            ds_put_cstr(&action, "next;");
            ovn_lflow_add_with_hint(lflows, od, stage,
                                    qos->priority,
                                    qos->match, ds_cstr(&action),
                                    &qos->header_, lflow_ref);
    }
    ds_destroy(&action);
}

static void
build_lb_rules_pre_stateful(struct lflow_table *lflows,
                            struct ovn_lb_datapaths *lb_dps,
                            bool ct_lb_mark,
                            const struct ovn_datapaths *ls_datapaths,
                            struct ds *match, struct ds *action)
{
    if (!lb_dps->n_nb_ls) {
        return;
    }

    const struct ovn_northd_lb *lb = lb_dps->lb;
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

        ds_put_format(match, REGBIT_CONNTRACK_NAT" == 1 && %s.dst == %s",
                      ip_match, lb_vip->vip_str);
        if (lb_vip->port_str) {
            ds_put_format(match, " && %s.dst == %s", proto, lb_vip->port_str);
        }

        ovn_lflow_add_with_dp_group(
            lflows, lb_dps->nb_ls_map, ods_size(ls_datapaths),
            S_SWITCH_IN_PRE_STATEFUL, 120, ds_cstr(match), ds_cstr(action),
            &lb->nlb->header_, lb_dps->lflow_ref);
    }
}

/* Builds the logical router flows related to load balancer affinity.
 * For a LB configured with 'vip=V:VP' and backends 'B1:BP1,B2:BP2' and
 * affinity timeout set to T, it generates the following logical flows:
 * - load balancing affinity check:
 *   table=lr_in_lb_aff_check, priority=100
 *      match=(new_lb_match)
 *      action=(REG_NEXT_HOP_IPV4 = ip4.dst;
 *              REG_ORIG_TP_DPORT_ROUTER = tcp.dst;
 *              REGBIT_KNOWN_LB_SESSION = chk_lb_aff(); next;)
 *
 * - load balancing:
 *   table=lr_in_dnat, priority=150
 *      match=(REGBIT_KNOWN_LB_SESSION == 1 && ct.new && ip4.dst == V
 *             && REG_LB_AFF_BACKEND_IP4 == B1 && REG_LB_AFF_MATCH_PORT == BP1)
 *      action=(REG_NEXT_HOP_IPV4 = V; lb_action;
 *              ct_lb_mark(backends=B1:BP1; ct_flag);)
 *   table=lr_in_dnat, priority=150
 *      match=(REGBIT_KNOWN_LB_SESSION == 1 && ct.new && ip4.dst == V
 *             && REG_LB_AFF_BACKEND_IP4 == B2 && REG_LB_AFF_MATCH_PORT == BP2)
 *      action=(REG_NEXT_HOP_IPV4 = V; lb_action;
 *              ct_lb_mark(backends=B2:BP2; ct_flag);)
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
build_lb_affinity_lr_flows(struct lflow_table *lflows,
                           const struct ovn_northd_lb *lb,
                           struct ovn_lb_vip *lb_vip, char *new_lb_match,
                           char *lb_action, const unsigned long *dp_bitmap,
                           const struct ovn_datapaths *lr_datapaths,
                           struct lflow_ref *lflow_ref)
{
    if (!lb->affinity_timeout ||
        bitmap_is_all_zeros(dp_bitmap, ods_size(lr_datapaths))) {
        return;
    }

    struct ds aff_action = DS_EMPTY_INITIALIZER;
    struct ds aff_action_learn = DS_EMPTY_INITIALIZER;
    struct ds aff_match = DS_EMPTY_INITIALIZER;
    struct ds aff_match_learn = DS_EMPTY_INITIALIZER;
    struct ds aff_check_action = DS_EMPTY_INITIALIZER;

    bool ipv6 = !IN6_IS_ADDR_V4MAPPED(&lb_vip->vip);
    const char *ip_match = ipv6 ? "ip6" : "ip4";

    const char *reg_vip = ipv6 ? REG_NEXT_HOP_IPV6 : REG_NEXT_HOP_IPV4;
    const char *reg_backend =
        ipv6 ? REG_LB_L3_AFF_BACKEND_IP6 : REG_LB_AFF_BACKEND_IP4;
    const char *ct_flag = NULL;
    if (lb_action && !strcmp(lb_action, "flags.skip_snat_for_lb = 1; ")) {
        ct_flag = "; skip_snat";
    } else if (lb_action &&
               !strcmp(lb_action, "flags.force_snat_for_lb = 1; ")) {
        ct_flag = "; force_snat";
    }

    /* Create affinity check flow. */
    ds_put_format(&aff_check_action, "%s = %s.dst; ", reg_vip, ip_match);

    if (lb_vip->port_str) {
        ds_put_format(&aff_check_action, REG_ORIG_TP_DPORT_ROUTER" = %s.dst; ",
                      lb->proto);
    }
    ds_put_cstr(&aff_check_action, REGBIT_KNOWN_LB_SESSION
                " = chk_lb_aff(); next;");

    ovn_lflow_add_with_dp_group(
        lflows, dp_bitmap, ods_size(lr_datapaths), S_ROUTER_IN_LB_AFF_CHECK,
        100, new_lb_match, ds_cstr(&aff_check_action), &lb->nlb->header_,
        lflow_ref);

    /* Prepare common part of affinity LB and affinity learn action. */
    ds_put_format(&aff_action, "%s = %s; ", reg_vip, lb_vip->vip_str);
    ds_put_cstr(&aff_action_learn, "commit_lb_aff(vip = \"");

    if (lb_vip->port_str) {
        ds_put_format(&aff_action_learn, ipv6 ? "[%s]:%s" : "%s:%s",
                      lb_vip->vip_str, lb_vip->port_str);
    } else {
        ds_put_cstr(&aff_action_learn, lb_vip->vip_str);
    }

    if (lb_action) {
        ds_put_cstr(&aff_action, lb_action);
    }
    ds_put_cstr(&aff_action, "ct_lb_mark(backends=");
    ds_put_cstr(&aff_action_learn, "\", backend = \"");

    /* Prepare common part of affinity learn match. */
    if (lb_vip->port_str) {
        ds_put_format(&aff_match_learn, REGBIT_KNOWN_LB_SESSION" == 0 && "
                      "ct.new && %s && %s == %s && "
                      REG_ORIG_TP_DPORT_ROUTER" == %s && "
                      "%s.dst == ", ip_match, reg_vip, lb_vip->vip_str,
                      lb_vip->port_str, ip_match);
    } else {
        ds_put_format(&aff_match_learn, REGBIT_KNOWN_LB_SESSION" == 0 && "
                      "ct.new && %s && %s == %s && %s.dst == ", ip_match,
                      reg_vip, lb_vip->vip_str, ip_match);
    }

    /* Prepare common part of affinity match. */
    ds_put_format(&aff_match, REGBIT_KNOWN_LB_SESSION" == 1 && "
                  "ct.new && %s.dst == %s && %s == ", ip_match,
                  lb_vip->vip_str, reg_backend);

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

        if (ct_flag) {
            ds_put_cstr(&aff_action, ct_flag);
        }

        ds_put_cstr(&aff_action, ");");
        ds_put_char(&aff_action_learn, '"');

        if (lb_vip->port_str) {
            ds_put_format(&aff_action_learn, ", proto = %s", lb->proto);
        }

        ds_put_format(&aff_action_learn, ", timeout = %d); /* drop */",
                      lb->affinity_timeout);

        /* Forward to OFTABLE_CHK_LB_AFFINITY table to store flow tuple. */
        ovn_lflow_add_with_dp_group(
            lflows, dp_bitmap, ods_size(lr_datapaths),
            S_ROUTER_IN_LB_AFF_LEARN, 100, ds_cstr(&aff_match_learn),
            ds_cstr(&aff_action_learn), &lb->nlb->header_,
            lflow_ref);

        /* Use already selected backend within affinity timeslot. */
        ovn_lflow_add_with_dp_group(
            lflows, dp_bitmap, ods_size(lr_datapaths), S_ROUTER_IN_DNAT, 150,
            ds_cstr(&aff_match), ds_cstr(&aff_action), &lb->nlb->header_,
            lflow_ref);

        ds_truncate(&aff_action, aff_action_len);
        ds_truncate(&aff_action_learn, aff_action_learn_len);
        ds_truncate(&aff_match, aff_match_len);
        ds_truncate(&aff_match_learn, aff_match_learn_len);
    }

    ds_destroy(&aff_action);
    ds_destroy(&aff_action_learn);
    ds_destroy(&aff_match);
    ds_destroy(&aff_match_learn);
    ds_destroy(&aff_check_action);
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
 *      match=(REGBIT_KNOWN_LB_SESSION == 1 && ct.new && ip4.dst == V
 *             && REG_LB_AFF_BACKEND_IP4 == B1 && REG_LB_AFF_MATCH_PORT == BP1)
 *      action=(REGBIT_CONNTRACK_COMMIT = 0;
 *              REG_ORIG_DIP_IPV4 = V; REG_ORIG_TP_DPORT = VP;
 *              ct_lb_mark(backends=B1:BP1);)
 *   table=ls_in_lb, priority=150
 *      match=(REGBIT_KNOWN_LB_SESSION == 1 && ct.new && ip4.dst == V
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
build_lb_affinity_ls_flows(struct lflow_table *lflows,
                           struct ovn_lb_datapaths *lb_dps,
                           struct ovn_lb_vip *lb_vip,
                           const struct ovn_datapaths *ls_datapaths,
                           struct lflow_ref *lflow_ref)
{
    if (!lb_dps->lb->affinity_timeout || !lb_dps->n_nb_ls) {
        return;
    }

    const struct ovn_northd_lb *lb = lb_dps->lb;
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

    if (lb_vip->port_str) {
        ds_put_format(&new_lb_match, " && "REG_ORIG_TP_DPORT " == %s",
                      lb_vip->port_str);
    }

    static char *aff_check = REGBIT_KNOWN_LB_SESSION" = chk_lb_aff(); next;";

    ovn_lflow_add_with_dp_group(
        lflows, lb_dps->nb_ls_map, ods_size(ls_datapaths),
        S_SWITCH_IN_LB_AFF_CHECK, 100, ds_cstr(&new_lb_match), aff_check,
        &lb_dps->lb->nlb->header_, lflow_ref);
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

    if (lb_vip->port_str) {
        ds_put_format(&aff_action, REG_ORIG_TP_DPORT" = %s; ",
                      lb_vip->port_str);
        ds_put_format(&aff_action_learn, ipv6 ? "[%s]:%s" : "%s:%s",
                      lb_vip->vip_str, lb_vip->port_str);
    } else {
        ds_put_cstr(&aff_action_learn, lb_vip->vip_str);
    }

    ds_put_cstr(&aff_action, "ct_lb_mark(backends=");
    ds_put_cstr(&aff_action_learn, "\", backend = \"");

    /* Prepare common part of affinity learn match. */
    if (lb_vip->port_str) {
        ds_put_format(&aff_match_learn, REGBIT_KNOWN_LB_SESSION" == 0 && "
                      "ct.new && %s && %s == %s && "
                      REG_ORIG_TP_DPORT" == %s && %s.dst == ",
                      ip_match, reg_vip, lb_vip->vip_str,
                      lb_vip->port_str, ip_match);
    } else {
        ds_put_format(&aff_match_learn, REGBIT_KNOWN_LB_SESSION" == 0 && "
                      "ct.new && %s && %s == %s && %s.dst == ",
                      ip_match, reg_vip, lb_vip->vip_str, ip_match);
    }

    /* Prepare common part of affinity match. */
    ds_put_format(&aff_match, REGBIT_KNOWN_LB_SESSION" == 1 && "
                  "ct.new && %s.dst == %s && %s == ", ip_match,
                  lb_vip->vip_str, reg_backend);

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

        if (lb_vip->port_str) {
            ds_put_format(&aff_action_learn, ", proto = %s", lb->proto);
        }

        ds_put_format(&aff_action_learn, ", timeout = %d); /* drop */",
                      lb->affinity_timeout);

        /* Forward to OFTABLE_CHK_LB_AFFINITY table to store flow tuple. */
        ovn_lflow_add_with_dp_group(
            lflows, lb_dps->nb_ls_map, ods_size(ls_datapaths),
            S_SWITCH_IN_LB_AFF_LEARN, 100, ds_cstr(&aff_match_learn),
            ds_cstr(&aff_action_learn), &lb->nlb->header_,
            lflow_ref);

        /* Use already selected backend within affinity timeslot. */
        ovn_lflow_add_with_dp_group(
            lflows, lb_dps->nb_ls_map, ods_size(ls_datapaths),
            S_SWITCH_IN_LB, 150, ds_cstr(&aff_match), ds_cstr(&aff_action),
            &lb->nlb->header_, lflow_ref);

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
build_lswitch_lb_affinity_default_flows(struct ovn_datapath *od,
                                        struct lflow_table *lflows,
                                        struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbs);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_LB_AFF_CHECK, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_LB_AFF_LEARN, 0, "1", "next;",
                  lflow_ref);
}

static void
build_lrouter_lb_affinity_default_flows(struct ovn_datapath *od,
                                        struct lflow_table *lflows,
                                        struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_LB_AFF_CHECK, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_LB_AFF_LEARN, 0, "1", "next;",
                  lflow_ref);
}

static void
build_lb_rules(struct lflow_table *lflows, struct ovn_lb_datapaths *lb_dps,
               const struct ovn_datapaths *ls_datapaths,
               const struct chassis_features *features, struct ds *match,
               struct ds *action, const struct shash *meter_groups,
               const struct hmap *svc_monitor_map)
{
    const struct ovn_northd_lb *lb = lb_dps->lb;
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
        bool reject = build_lb_vip_actions(lb, lb_vip, lb_vip_nb, action,
                                           lb->selection_fields,
                                           NULL, NULL, true, features,
                                           svc_monitor_map);

        ds_put_format(match, "ct.new && %s.dst == %s", ip_match,
                      lb_vip->vip_str);
        int priority = 110;
        if (lb_vip->port_str) {
            ds_put_format(match, " && %s.dst == %s", lb->proto,
                          lb_vip->port_str);
            priority = 120;
        }

        build_lb_affinity_ls_flows(lflows, lb_dps, lb_vip, ls_datapaths,
                                   lb_dps->lflow_ref);

        unsigned long *dp_non_meter = NULL;
        bool build_non_meter = false;
        if (reject) {
            size_t index;

            dp_non_meter = bitmap_clone(lb_dps->nb_ls_map,
                                        ods_size(ls_datapaths));
            BITMAP_FOR_EACH_1 (index, ods_size(ls_datapaths),
                               lb_dps->nb_ls_map) {
                struct ovn_datapath *od = ls_datapaths->array[index];

                meter = copp_meter_get(COPP_REJECT, od->nbs->copp,
                                       meter_groups);
                if (!meter) {
                    build_non_meter = true;
                    continue;
                }
                bitmap_set0(dp_non_meter, index);
                ovn_lflow_add_with_hint__(
                        lflows, od, S_SWITCH_IN_LB, priority,
                        ds_cstr(match), ds_cstr(action),
                        NULL, meter, &lb->nlb->header_,
                        lb_dps->lflow_ref);
            }
        }
        if (!reject || build_non_meter) {
            ovn_lflow_add_with_dp_group(
                lflows, dp_non_meter ? dp_non_meter : lb_dps->nb_ls_map,
                ods_size(ls_datapaths), S_SWITCH_IN_LB, priority,
                ds_cstr(match), ds_cstr(action), &lb->nlb->header_,
                lb_dps->lflow_ref);
        }
        bitmap_free(dp_non_meter);
    }
}

static void
build_stateful(struct ovn_datapath *od,
               const struct chassis_features *features,
               struct lflow_table *lflows,
               struct lflow_ref *lflow_ref)
{
    const char *ct_block_action = features->ct_no_masked_label
                                  ? "ct_mark.blocked"
                                  : "ct_label.blocked";
    struct ds actions = DS_EMPTY_INITIALIZER;

    /* Ingress LB, Ingress and Egress stateful Table (Priority 0): Packets are
     * allowed by default. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_LB, 0, "1", "next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_STATEFUL, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_STATEFUL, 0, "1", "next;",
                  lflow_ref);

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
                  ds_cstr(&actions),
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_STATEFUL, 100,
                  REGBIT_CONNTRACK_COMMIT" == 1 && "
                  REGBIT_ACL_LABEL" == 1",
                  ds_cstr(&actions),
                  lflow_ref);

    /* If REGBIT_CONNTRACK_COMMIT is set as 1, then the packets should be
     * committed to conntrack. We always set ct_mark.blocked to 0 here as
     * any packet that makes it this far is part of a connection we
     * want to allow to continue. */
    ds_clear(&actions);
    ds_put_format(&actions, "ct_commit { %s = 0; }; next;", ct_block_action);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_STATEFUL, 100,
                  REGBIT_CONNTRACK_COMMIT" == 1 && "
                  REGBIT_ACL_LABEL" == 0",
                  ds_cstr(&actions),
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_STATEFUL, 100,
                  REGBIT_CONNTRACK_COMMIT" == 1 && "
                  REGBIT_ACL_LABEL" == 0",
                  ds_cstr(&actions),
                  lflow_ref);
    ds_destroy(&actions);
}

static void
build_lb_hairpin(const struct ls_stateful_record *ls_stateful_rec,
                 const struct ovn_datapath *od,
                 struct lflow_table *lflows,
                 struct lflow_ref *lflow_ref)
{
    /* Ingress Pre-Hairpin/Nat-Hairpin/Hairpin tabled (Priority 0).
     * Packets that don't need hairpinning should continue processing.
     */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_HAIRPIN, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_NAT_HAIRPIN, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_HAIRPIN, 0, "1", "next;",
                  lflow_ref);

    if (ls_stateful_rec->has_lb_vip) {
        /* Check if the packet needs to be hairpinned.
         * Set REGBIT_HAIRPIN in the original direction and
         * REGBIT_HAIRPIN_REPLY in the reply direction.
         */
        ovn_lflow_add_with_hint(
            lflows, od, S_SWITCH_IN_PRE_HAIRPIN, 100, "ip && ct.trk",
            REGBIT_HAIRPIN " = chk_lb_hairpin(); "
            REGBIT_HAIRPIN_REPLY " = chk_lb_hairpin_reply(); "
            "next;",
            &od->nbs->header_,
            lflow_ref);

        /* If packet needs to be hairpinned, snat the src ip with the VIP
         * for new sessions. */
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_NAT_HAIRPIN, 100,
                                "ip && ct.new && ct.trk"
                                " && "REGBIT_HAIRPIN " == 1",
                                "ct_snat_to_vip; next;",
                                &od->nbs->header_,
                                lflow_ref);

        /* If packet needs to be hairpinned, for established sessions there
         * should already be an SNAT conntrack entry.
         */
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_NAT_HAIRPIN, 100,
                                "ip && ct.est && ct.trk"
                                " && "REGBIT_HAIRPIN " == 1",
                                "ct_snat;",
                                &od->nbs->header_,
                                lflow_ref);

        /* For the reply of hairpinned traffic, snat the src ip to the VIP. */
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_NAT_HAIRPIN, 90,
                                "ip && "REGBIT_HAIRPIN_REPLY " == 1",
                                "ct_snat;",
                                &od->nbs->header_,
                                lflow_ref);

        /* Ingress Hairpin table.
        * - Priority 1: Packets that were SNAT-ed for hairpinning should be
        *   looped back (i.e., swap ETH addresses and send back on inport).
        */
        ovn_lflow_add(
            lflows, od, S_SWITCH_IN_HAIRPIN, 1,
            "("REGBIT_HAIRPIN " == 1 || " REGBIT_HAIRPIN_REPLY " == 1)",
            "eth.dst <-> eth.src; outport = inport; flags.loopback = 1; "
            "output;", lflow_ref);
    }
}

static void
build_vtep_hairpin(struct ovn_datapath *od, struct lflow_table *lflows,
                   struct lflow_ref *lflow_ref)
{
    if (!od->has_vtep_lports) {
        /* There is no need in these flows if datapath has no vtep lports. */
        return;
    }

    /* Ingress Pre-ARP flows for VTEP hairpining traffic. Priority 1000:
     * Packets received from VTEP ports must go directly to L2LKP table.
     */
    char *action = xasprintf("next(pipeline=ingress, table=%d);",
                             ovn_stage_get_table(S_SWITCH_IN_L2_LKUP));
    ovn_lflow_add(lflows, od, S_SWITCH_IN_HAIRPIN, 1000,
                  REGBIT_FROM_RAMP" == 1", action, lflow_ref);
    free(action);

    /* Ingress pre-arp flow for traffic from VTEP (ramp) switch.
    * Priority 2000: Packets, that were received from VTEP (ramp) switch and
    * router ports of current datapath are l3dgw ports and they reside on
    * current chassis, should be passed to next table for ARP/ND hairpin
    * processing. */
    struct ds match = DS_EMPTY_INITIALIZER;
    for (int i = 0; i < od->n_router_ports; i++) {
        struct ovn_port *op = od->router_ports[i]->peer;
        if (is_l3dgw_port(op)) {
            ds_clear(&match);
            ds_put_format(&match,
                          REGBIT_FROM_RAMP" == 1 && is_chassis_resident(%s)",
                          op->cr_port->json_key);
            ovn_lflow_add(lflows, od, S_SWITCH_IN_HAIRPIN, 2000,
                          ds_cstr(&match), "next;", lflow_ref);
        }
    }

    /* ARP/Neighbor Solicitation requests must skip ls_in_arp_rsp table for
     * packets arrived from HW VTEP (ramp) switch.
     * Neighbor resolution for router ports is done in logical router ingress
     * pipeline.  ARP resolution for vif lports is done directly by vif ports.
     */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_ARP_ND_RSP, 65535,
                  REGBIT_FROM_RAMP" == 1 && (arp || nd_ns)",
                  "flags.loopback = 1; next;", lflow_ref);

    ds_destroy(&match);
}

/* Build logical flows for the forwarding groups */
static void
build_fwd_group_lflows(struct ovn_datapath *od, struct lflow_table *lflows,
                       struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbs);
    if (!od->nbs->n_forwarding_groups) {
        return;
    }
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
                                &fwd_group->header_, lflow_ref);

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
                                &fwd_group->header_, lflow_ref);
    }

    ds_destroy(&match);
    ds_destroy(&actions);
    ds_destroy(&group_ports);
}

static void
build_lrouter_groups__(struct hmap *lr_ports, struct ovn_datapath *od)
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
            ovn_port_find(lr_ports, od->nbr->ports[i]->name);

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
                build_lrouter_groups__(lr_ports, peer_dp);
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
                build_lrouter_groups__(lr_ports, router_dp);
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
build_lrouter_groups(struct hmap *lr_ports, struct ovs_list *lr_list)
{
    struct ovn_datapath *od;
    size_t n_router_dps = ovs_list_size(lr_list);

    LIST_FOR_EACH (od, lr_list, lr_list) {
        if (!od->lr_group) {
            od->lr_group = xzalloc(sizeof *od->lr_group);
            /* Each logical router group can have max
             * 'n_router_dps'. So allocate enough memory. */
            od->lr_group->router_dps =
                xcalloc(n_router_dps, sizeof *od->lr_group->router_dps);
            od->lr_group->router_dps[0] = od;
            od->lr_group->n_router_dps = 1;
            sset_init(&od->lr_group->ha_chassis_groups);
            hmapx_init(&od->lr_group->tmp_ha_ref_chassis);
            build_lrouter_groups__(lr_ports, od);
        }
    }
}

/*
 * Ingress table 25: Flows that flood self originated ARP/RARP/ND packets in
 * the switching domain.
 */
static void
build_lswitch_rport_arp_req_self_orig_flow(struct ovn_port *op,
                                        uint32_t priority,
                                        const struct ovn_datapath *od,
                                        const struct lr_nat_record *lrnat_rec,
                                        struct lflow_table *lflows,
                                        struct lflow_ref *lflow_ref)
{
    struct ds eth_src = DS_EMPTY_INITIALIZER;
    struct ds match = DS_EMPTY_INITIALIZER;

    /* Self originated ARP requests/RARP/ND need to be flooded to the L2 domain
     * (except on router ports).  Determine that packets are self originated
     * by also matching on source MAC. Matching on ingress port is not
     * reliable in case this is a VLAN-backed network.
     * Priority: 75.
     */
    const char *eth_addr;

    ds_put_format(&eth_src, "{%s, ", op->lrp_networks.ea_s);
    SSET_FOR_EACH (eth_addr, &lrnat_rec->external_macs) {
        ds_put_format(&eth_src, "%s, ", eth_addr);
    }
    ds_chomp(&eth_src, ' ');
    ds_chomp(&eth_src, ',');
    ds_put_cstr(&eth_src, "}");

    ds_put_format(&match,
                  "eth.src == %s && (arp.op == 1 || rarp.op == 3 || nd_ns)",
                  ds_cstr(&eth_src));
    ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, priority, ds_cstr(&match),
                  "outport = \""MC_FLOOD_L2"\"; output;", lflow_ref);

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
bool
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
bool
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
 * Ingress table 25: Flows that forward ARP/ND requests only to the routers
 * that own the addresses. Other ARP/ND packets are still flooded in the
 * switching domain as regular broadcast.
 */
static void
build_lswitch_rport_arp_req_flow(
    const char *ips, int addr_family, struct ovn_port *patch_op,
    const struct ovn_datapath *od, uint32_t priority,
    struct lflow_table *lflows, const struct ovsdb_idl_row *stage_hint,
    struct lflow_ref *lflow_ref)
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
                                ds_cstr(&actions), stage_hint,
                                lflow_ref);
    } else {
        ds_put_format(&actions, "outport = %s; output;", patch_op->json_key);
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_L2_LKUP,
                                priority, ds_cstr(&match),
                                ds_cstr(&actions),
                                stage_hint,
                                lflow_ref);
    }

    ds_destroy(&match);
    ds_destroy(&actions);
}

/*
 * Ingress table 25: Flows that forward ARP/ND requests only to the routers
 * that own the addresses.
 * Priorities:
 * - 80: self originated GARPs that need to follow regular processing.
 * - 75: ARP requests to router owned IPs (interface IP/LB/NAT).
 */
static void
build_lswitch_rport_arp_req_flows(struct ovn_port *op,
                                  struct ovn_datapath *sw_od,
                                  struct ovn_port *sw_op,
                                  struct lflow_table *lflows,
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
    for (size_t i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
        build_lswitch_rport_arp_req_flow(
            op->lrp_networks.ipv4_addrs[i].addr_s, AF_INET, sw_op, sw_od, 80,
            lflows, stage_hint, sw_op->lflow_ref);
    }
    for (size_t i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
        build_lswitch_rport_arp_req_flow(
            op->lrp_networks.ipv6_addrs[i].addr_s, AF_INET6, sw_op, sw_od, 80,
            lflows, stage_hint, sw_op->lflow_ref);
    }
}

/*
 * Ingress table 25: Flows that forward ARP/ND requests only to the routers
 * that own the addresses.
 * Priorities:
 * - 80: self originated GARPs that need to follow regular processing.
 * - 75: ARP requests to router owned IPs (interface IP/LB/NAT).
 */
static void
build_lswitch_rport_arp_req_flows_for_lbnats(
    struct ovn_port *op, const struct lr_stateful_record *lr_stateful_rec,
    const struct ovn_datapath *sw_od, struct ovn_port *sw_op,
    struct lflow_table *lflows, const struct ovsdb_idl_row *stage_hint,
    struct lflow_ref *lflow_ref)
{
    if (!op || !op->nbrp) {
        return;
    }

    if (!lrport_is_enabled(op->nbrp)) {
        return;
    }

    ovs_assert(uuid_equals(&op->od->nbr->header_.uuid,
                           &lr_stateful_rec->nbr_uuid));

    /* Forward ARP requests for owned IP addresses (L3, VIP, NAT) only to this
     * router port.
     * Priority: 80.
     */
    if (op->od->nbr->n_load_balancer || op->od->nbr->n_load_balancer_group) {
        const char *ip_addr;
        SSET_FOR_EACH (ip_addr, &lr_stateful_rec->lb_ips->ips_v4_reachable) {
            ovs_be32 ipv4_addr;

            /* Check if the ovn port has a network configured on which we could
             * expect ARP requests for the LB VIP.
             */
            if (ip_parse(ip_addr, &ipv4_addr) &&
                lrouter_port_ipv4_reachable(op, ipv4_addr)) {
                build_lswitch_rport_arp_req_flow(
                    ip_addr, AF_INET, sw_op, sw_od, 80, lflows,
                    stage_hint, lflow_ref);
            }
        }
        SSET_FOR_EACH (ip_addr, &lr_stateful_rec->lb_ips->ips_v6_reachable) {
            struct in6_addr ipv6_addr;

            /* Check if the ovn port has a network configured on which we could
             * expect NS requests for the LB VIP.
             */
            if (ipv6_parse(ip_addr, &ipv6_addr) &&
                lrouter_port_ipv6_reachable(op, &ipv6_addr)) {
                build_lswitch_rport_arp_req_flow(
                    ip_addr, AF_INET6, sw_op, sw_od, 80, lflows,
                    stage_hint, lflow_ref);
            }
        }
    }

    /* Self originated ARP requests/RARP/ND need to be flooded as usual.
     *
     * However, if the switch doesn't have any non-router ports we shouldn't
     * even try to flood.
     *
     * Priority: 75.
     */
    if (sw_od->n_router_ports != sw_od->nbs->n_ports) {
        build_lswitch_rport_arp_req_self_orig_flow(op, 75, sw_od,
                                                   lr_stateful_rec->lrnat_rec,
                                                   lflows, lflow_ref);
    }

    for (size_t i = 0; i < lr_stateful_rec->lrnat_rec->n_nat_entries; i++) {
        struct ovn_nat *nat_entry =
            &lr_stateful_rec->lrnat_rec->nat_entries[i];
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
            if (!sset_contains(&lr_stateful_rec->lb_ips->ips_v6,
                               nat->external_ip)) {
                build_lswitch_rport_arp_req_flow(
                    nat->external_ip, AF_INET6, sw_op, sw_od, 80, lflows,
                    stage_hint, lflow_ref);
            }
        } else {
            if (!sset_contains(&lr_stateful_rec->lb_ips->ips_v4,
                               nat->external_ip)) {
                build_lswitch_rport_arp_req_flow(
                    nat->external_ip, AF_INET, sw_op, sw_od, 80, lflows,
                    stage_hint, lflow_ref);
            }
        }
    }

    struct shash_node *snat_snode;
    SHASH_FOR_EACH (snat_snode, &lr_stateful_rec->lrnat_rec->snat_ips) {
        struct ovn_snat_ip *snat_ip = snat_snode->data;

        if (ovs_list_is_empty(&snat_ip->snat_entries)) {
            continue;
        }

        struct ovn_nat *nat_entry =
            CONTAINER_OF(ovs_list_front(&snat_ip->snat_entries),
                         struct ovn_nat, ext_addr_list_node);
        if (nat_entry->is_router_ip) {
            /* If its a router ip, then there is no need to add the ARP
             * request forwarder flows as it will be added by
             * build_lswitch_rport_arp_req_flows(). */
            continue;
        }

        const struct nbrec_nat *nat = nat_entry->nb;

        /* Check if the ovn port has a network configured on which we could
         * expect ARP requests/NS for the SNAT external_ip.
         */
        if (nat_entry_is_v6(nat_entry)) {
            if (!sset_contains(&lr_stateful_rec->lb_ips->ips_v6,
                               nat->external_ip)) {
                build_lswitch_rport_arp_req_flow(
                    nat->external_ip, AF_INET6, sw_op, sw_od, 80, lflows,
                    stage_hint, lflow_ref);
            }
        } else {
            if (!sset_contains(&lr_stateful_rec->lb_ips->ips_v4,
                               nat->external_ip)) {
                build_lswitch_rport_arp_req_flow(
                    nat->external_ip, AF_INET, sw_op, sw_od, 80, lflows,
                    stage_hint, lflow_ref);
            }
        }
    }
}

static void
build_dhcpv4_options_flows(struct ovn_port *op,
                           struct lport_addresses *lsp_addrs,
                           struct ovn_port *inport, bool is_external,
                           const struct shash *meter_groups,
                           struct lflow_table *lflows,
                           struct lflow_ref *lflow_ref)
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
                                      &op->nbsp->dhcpv4_options->header_,
                                      lflow_ref);
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
                &op->nbsp->dhcpv4_options->header_,
                lflow_ref);
            ds_destroy(&options_action);
            ds_destroy(&response_action);
            ds_destroy(&ipv4_addr_match);

            /* Add 34000 priority flow to allow DHCP reply from ovn-controller
             * to the ogical port of the datapath if the CMS has configured
             * DHCPv4 options.
             * */
            if (!is_external) {
                const char *server_id = smap_get(
                    &op->nbsp->dhcpv4_options->options, "server_id");
                const char *server_mac = smap_get(
                    &op->nbsp->dhcpv4_options->options, "server_mac");
                const char *lease_time = smap_get(
                    &op->nbsp->dhcpv4_options->options, "lease_time");
                ovs_assert(server_id && server_mac && lease_time);
                const char *dhcp_actions =
                    REGBIT_ACL_VERDICT_ALLOW" = 1; next;";
                ds_clear(&match);
                ds_put_format(&match, "outport == %s && eth.src == %s "
                              "&& ip4.src == %s && udp && udp.src == 67 "
                              "&& udp.dst == 68",op->json_key,
                              server_mac, server_id);
                ovn_lflow_add_with_lport_and_hint(
                    lflows, op->od, S_SWITCH_OUT_ACL_EVAL, 34000,
                    ds_cstr(&match),dhcp_actions, op->key,
                    &op->nbsp->dhcpv4_options->header_,
                    lflow_ref);
            }
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
                           struct lflow_table *lflows,
                           struct lflow_ref *lflow_ref)
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
                                      &op->nbsp->dhcpv6_options->header_,
                                      lflow_ref);

            /* If REGBIT_DHCP_OPTS_RESULT is set to 1, it means the
             * put_dhcpv6_opts action is successful */
            ds_put_cstr(&match, " && "REGBIT_DHCP_OPTS_RESULT);
            ovn_lflow_add_with_lport_and_hint(
                lflows, op->od, S_SWITCH_IN_DHCP_RESPONSE, 100,
                ds_cstr(&match), ds_cstr(&response_action), inport->key,
                &op->nbsp->dhcpv6_options->header_, lflow_ref);
            ds_destroy(&options_action);
            ds_destroy(&response_action);

            /* Add 34000 priority flow to allow DHCP reply from ovn-controller
             * to the ogical port of the datapath if the CMS has configured
             * DHCPv6 options.
             * */
            if (!is_external) {
                const char *server_mac = smap_get(
                    &op->nbsp->dhcpv6_options->options, "server_id");
                struct eth_addr ea;
                ovs_assert(server_mac &&
                           eth_addr_from_string(server_mac, &ea));
                /* Get the link local IP of the DHCPv6 server from the
                * server MAC. */
                struct in6_addr lla;
                in6_generate_lla(ea, &lla);

                char server_ip[INET6_ADDRSTRLEN + 1];
                ipv6_string_mapped(server_ip, &lla);

                const char *dhcp6_actions =
                    REGBIT_ACL_VERDICT_ALLOW" = 1; next;";
                ds_clear(&match);
                ds_put_format(&match, "outport == %s && eth.src == %s "
                              "&& ip6.src == %s && udp && udp.src == 547 "
                              "&& udp.dst == 546", op->json_key,
                              server_mac, server_ip);
                ovn_lflow_add_with_lport_and_hint(
                    lflows, op->od, S_SWITCH_OUT_ACL_EVAL, 34000,
                    ds_cstr(&match),dhcp6_actions, op->key,
                    &op->nbsp->dhcpv6_options->header_,
                    lflow_ref);
            }
            break;
        }
    }
    ds_destroy(&match);
}

static const char *
ls_dhcp_relay_port(const struct ovn_datapath *od)
{
    return smap_get(&od->nbs->other_config, "dhcp_relay_port");
}

static void
build_lswitch_dhcp_relay_flows(struct ovn_port *op,
                               const struct hmap *ls_ports,
                               struct lflow_table *lflows,
                               struct ds *match,
                               struct ds *actions)
{
    if (op->nbrp || !op->nbsp) {
        return;
    }

    /* consider only ports attached to VMs */
    if (strcmp(op->nbsp->type, "")) {
        return;
    }

    if (!op->od || !op->od->n_router_ports || !op->od->nbs) {
        return;
    }

    /* configure dhcp relay flows only when peer router  has
     * relay config enabled */
    const char *dhcp_relay_port = ls_dhcp_relay_port(op->od);
    if (!dhcp_relay_port) {
        return;
    }

    struct ovn_port *sp = ovn_port_find(ls_ports, dhcp_relay_port);

    if (!sp || !sp->nbsp || !sp->peer) {
        return;
    }

    struct ovn_port *rp = sp->peer;
    if (!rp || !rp->nbrp || !rp->nbrp->dhcp_relay || rp->peer != sp) {
        return;
    }

    char *server_ip_str = NULL;
    uint16_t port;
    int addr_family;
    struct in6_addr server_ip;
    struct nbrec_dhcp_relay *dhcp_relay = rp->nbrp->dhcp_relay;

    if (!ip_address_and_port_from_lb_key(dhcp_relay->servers, &server_ip_str,
                                         &server_ip, &port, &addr_family)) {
        return;
    }

    if (server_ip_str == NULL) {
        return;
    }

    ds_clear(match);
    ds_clear(actions);

    ds_put_format(
        match, "inport == %s && eth.src == %s && "
        "ip4.src == 0.0.0.0 && ip4.dst == 255.255.255.255 && "
        "udp.src == 68 && udp.dst == 67",
        op->json_key, op->lsp_addrs[0].ea_s);
    ds_put_format(actions,
                  "eth.dst = %s; outport = %s; next; /* DHCP_RELAY_REQ */",
                  rp->lrp_networks.ea_s,sp->json_key);
    ovn_lflow_add_with_hint__(lflows, op->od,
                              S_SWITCH_IN_L2_LKUP, 100,
                              ds_cstr(match),
                              ds_cstr(actions),
                              op->key,
                              NULL,
                              &op->nbsp->header_,
                              op->lflow_ref);
    ds_clear(match);
    ds_clear(actions);
    free(server_ip_str);
}

static void
build_drop_arp_nd_flows_for_unbound_router_ports(struct ovn_port *op,
                                                 const struct ovn_port *port,
                                                 struct lflow_table *lflows,
                                                 struct lflow_ref *lflow_ref)
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
                        &op->nbsp->header_, lflow_ref);
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
                        &op->nbsp->header_, lflow_ref);
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
                                                  &op->nbsp->header_,
                                                  lflow_ref);
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
build_lswitch_lflows_l2_unknown(struct ovn_datapath *od,
                                struct lflow_table *lflows,
                                struct lflow_ref *lflow_ref)
{
    /* Ingress table 25/26: Destination lookup for unknown MACs. */
    if (od->has_unknown) {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_UNKNOWN, 50,
                      "outport == \"none\"",
                      "outport = \""MC_UNKNOWN "\"; output;",
                      lflow_ref);
    } else {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_UNKNOWN, 50,
                      "outport == \"none\"",  debug_drop_action(),
                      lflow_ref);
    }
    ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_UNKNOWN, 0, "1",
                  "output;", lflow_ref);
}

/* Build pre-ACL and ACL tables for both ingress and egress.
 * Ingress tables 3 through 10.  Egress tables 0 through 7. */
static void
build_lswitch_lflows_pre_acl_and_acl(
    struct ovn_datapath *od,
    const struct chassis_features *features,
    struct lflow_table *lflows,
    const struct shash *meter_groups,
    struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbs);
    build_pre_acls(od, lflows, lflow_ref);
    build_pre_lb(od, meter_groups, lflows, lflow_ref);
    build_pre_stateful(od, features, lflows, lflow_ref);
    build_qos(od, lflows, lflow_ref);
    build_stateful(od, features, lflows, lflow_ref);
    build_vtep_hairpin(od, lflows, lflow_ref);
}

/* Logical switch ingress table 0: Admission control framework (priority
 * 100). */
static void
build_lswitch_lflows_admission_control(struct ovn_datapath *od,
                                       struct lflow_table *lflows,
                                       struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbs);

    /* Default action for recirculated ICMP error 'packet too big'. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_CHECK_PORT_SEC, 110,
                  "((ip4 && icmp4.type == 3 && icmp4.code == 4) ||"
                  " (ip6 && icmp6.type == 2 && icmp6.code == 0)) &&"
                  " flags.tunnel_rx == 1", debug_drop_action(), lflow_ref);

    /* Logical VLANs not supported. */
    if (!is_vlan_transparent(od)) {
        /* Block logical VLANs. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_CHECK_PORT_SEC, 100,
                      "vlan.present", debug_drop_action(),
                      lflow_ref);
    }

    /* Broadcast/multicast source address is invalid. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_CHECK_PORT_SEC, 100,
                  "eth.src[40]", debug_drop_action(),
                  lflow_ref);

    ovn_lflow_add(lflows, od, S_SWITCH_IN_CHECK_PORT_SEC, 50, "1",
                  REGBIT_PORT_SEC_DROP" = check_in_port_sec(); next;",
                  lflow_ref);

    ovn_lflow_add(lflows, od, S_SWITCH_IN_APPLY_PORT_SEC, 50,
                  REGBIT_PORT_SEC_DROP" == 1", debug_drop_action(),
                  lflow_ref);

    ovn_lflow_add(lflows, od, S_SWITCH_IN_APPLY_PORT_SEC, 0, "1", "next;",
                  lflow_ref);
}

/* Ingress table 19: ARP/ND responder, skip requests coming from localnet
 * ports. (priority 100); see ovn-northd.8.xml for the rationale. */

static void
build_lswitch_arp_nd_responder_skip_local(struct ovn_port *op,
                                          struct lflow_table *lflows,
                                          struct ds *match)
{
    ovs_assert(op->nbsp);
    if (!lsp_is_localnet(op->nbsp) || op->od->has_arp_proxy_port) {
        return;
    }
    ds_clear(match);
    ds_put_format(match, "inport == %s", op->json_key);
    ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                      S_SWITCH_IN_ARP_ND_RSP, 100,
                                      ds_cstr(match), "next;", op->key,
                                      &op->nbsp->header_, op->lflow_ref);
}

/* Ingress table 19: ARP/ND responder, reply for known IPs.
 * (priority 50). */
static void
build_lswitch_arp_nd_responder_known_ips(struct ovn_port *op,
                                         struct lflow_table *lflows,
                                         const struct hmap *ls_ports,
                                         const struct shash *meter_groups,
                                         struct ds *actions,
                                         struct ds *match)
{
    ovs_assert(op->nbsp);
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

        if (!ip46_parse(virtual_ip, &ip)) {
            return;
        }

        char *tokstr = xstrdup(virtual_parents);
        char *save_ptr = NULL;
        char *vparent;
        for (vparent = strtok_r(tokstr, ",", &save_ptr); vparent != NULL;
             vparent = strtok_r(NULL, ",", &save_ptr)) {
            struct ovn_port *vp = ovn_port_find(ls_ports, vparent);
            if (!vp || vp->od != op->od) {
                /* vparent name should be valid and it should belong
                 * to the same logical switch. */
                continue;
            }

            if (!addr_is_ipv6(virtual_ip)) {
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
                                              &vp->nbsp->header_,
                                              op->lflow_ref);
        }

        free(tokstr);
    } else {
        /*
         * Add ARP/ND reply flows if either the
         *  - port is up and it doesn't have 'unknown' address defined or it
         *    doesn't have the option disable_arp_nd_rsp=true.
         *  - port type is router or
         *  - port type is localport
         */
        if (check_lsp_is_up &&
            !lsp_is_up(op->nbsp) && !lsp_is_router(op->nbsp) &&
            strcmp(op->nbsp->type, "localport")) {
            return;
        }

        if (lsp_is_external(op->nbsp) || op->has_unknown ||
           (!op->nbsp->type[0] && lsp_disable_arp_nd_rsp(op->nbsp))) {
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
                                        &op->nbsp->header_,
                                        op->lflow_ref);

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
                                                  &op->nbsp->header_,
                                                  op->lflow_ref);
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
                                          &op->nbsp->header_,
                                          op->lflow_ref);

                /* Do not reply to a solicitation from the port that owns
                 * the address (otherwise DAD detection will fail). */
                ds_put_format(match, " && inport == %s", op->json_key);
                ovn_lflow_add_with_lport_and_hint(lflows, op->od,
                                                  S_SWITCH_IN_ARP_ND_RSP,
                                                  100, ds_cstr(match),
                                                  "next;", op->key,
                                                  &op->nbsp->header_,
                                                  op->lflow_ref);
            }
        }
    }
    if (op->proxy_arp_addrs.n_ipv4_addrs ||
        op->proxy_arp_addrs.n_ipv6_addrs) {
        /* Select the mac address to answer the proxy ARP/NDP */
        char *ea_s = NULL;
        if (!eth_addr_is_zero(op->proxy_arp_addrs.ea)) {
            ea_s = op->proxy_arp_addrs.ea_s;
        } else if (op->peer) {
            ea_s = op->peer->lrp_networks.ea_s;
        } else {
            return;
        }

        int i = 0;
        /* Add IPv4 responses for ARP proxies. */
        if (op->proxy_arp_addrs.n_ipv4_addrs) {
            /* Match rule on all proxy ARP IPs. */
            ds_clear(match);
            ds_put_cstr(match, "arp.op == 1 && arp.tpa == {");

            for (i = 0; i < op->proxy_arp_addrs.n_ipv4_addrs; i++) {
                ds_put_format(match, "%s/%u,",
                              op->proxy_arp_addrs.ipv4_addrs[i].addr_s,
                              op->proxy_arp_addrs.ipv4_addrs[i].plen);
            }

            ds_chomp(match, ',');
            ds_put_cstr(match, "}");

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
                ea_s,
                ea_s);

            ovn_lflow_add_with_hint(lflows, op->od,
                                    S_SWITCH_IN_ARP_ND_RSP,
                                    30, ds_cstr(match),
                                    ds_cstr(actions),
                                    &op->nbsp->header_,
                                    op->lflow_ref);
        }

        /* Add IPv6 NDP responses.
         * For ND solicitations, we need to listen for both the
         * unicast IPv6 address and its all-nodes multicast address,
         * but always respond with the unicast IPv6 address. */
        if (op->proxy_arp_addrs.n_ipv6_addrs) {
            struct ds ip6_dst_match = DS_EMPTY_INITIALIZER;
            struct ds nd_target_match = DS_EMPTY_INITIALIZER;
            for (size_t j = 0; j < op->proxy_arp_addrs.n_ipv6_addrs; j++) {
                ds_put_format(&ip6_dst_match, "%s/%u, %s/%u, ",
                        op->proxy_arp_addrs.ipv6_addrs[j].addr_s,
                        op->proxy_arp_addrs.ipv6_addrs[j].plen,
                        op->proxy_arp_addrs.ipv6_addrs[j].sn_addr_s,
                        op->proxy_arp_addrs.ipv6_addrs[j].plen);
                ds_put_format(&nd_target_match, "%s/%u, ",
                        op->proxy_arp_addrs.ipv6_addrs[j].addr_s,
                        op->proxy_arp_addrs.ipv6_addrs[j].plen);
            }
            ds_truncate(&ip6_dst_match, ip6_dst_match.length - 2);
            ds_truncate(&nd_target_match, nd_target_match.length - 2);
            ds_clear(match);
            ds_put_format(match,
                          "nd_ns "
                          "&& ip6.dst == { %s } "
                          "&& nd.target == { %s }",
                          ds_cstr(&ip6_dst_match),
                          ds_cstr(&nd_target_match));
            ds_clear(actions);
            ds_put_format(actions,
                    "%s { "
                    "eth.src = %s; "
                    "ip6.src = nd.target; "
                    "nd.target = nd.target; "
                    "nd.tll = %s; "
                    "outport = inport; "
                    "flags.loopback = 1; "
                    "output; "
                    "};",
                    lsp_is_router(op->nbsp) ? "nd_na_router" : "nd_na",
                    ea_s,
                    ea_s);
            ovn_lflow_add_with_hint__(lflows, op->od,
                                      S_SWITCH_IN_ARP_ND_RSP, 30,
                                      ds_cstr(match),
                                      ds_cstr(actions),
                                      NULL,
                                      copp_meter_get(COPP_ND_NA,
                                        op->od->nbs->copp,
                                        meter_groups),
                                      &op->nbsp->header_,
                                      op->lflow_ref);
            ds_destroy(&ip6_dst_match);
            ds_destroy(&nd_target_match);
        }
    }
}

/* Ingress table 19: ARP/ND responder, by default goto next.
 * (priority 0)*/
static void
build_lswitch_arp_nd_responder_default(struct ovn_datapath *od,
                                       struct lflow_table *lflows,
                                       struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbs);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_ARP_ND_RSP, 0, "1", "next;",
                  lflow_ref);
}

/* Ingress table 19: ARP/ND responder for service monitor source ip.
 * (priority 110)*/
static void
build_lswitch_arp_nd_service_monitor(const struct ovn_lb_datapaths *lb_dps,
                                     const struct hmap *ls_ports,
                                     const char *svc_monitor_mac,
                                     struct lflow_table *lflows,
                                     struct ds *actions,
                                     struct ds *match)
{
    const struct ovn_northd_lb *lb = lb_dps->lb;
    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_northd_lb_vip *lb_vip_nb = &lb->vips_nb[i];
        if (!lb_vip_nb->lb_health_check) {
            continue;
        }

        struct ovn_lb_vip *lb_vip = &lb->vips[i];
        for (size_t j = 0; j < lb_vip_nb->n_backends; j++) {
            struct ovn_northd_lb_backend *backend_nb =
                &lb_vip_nb->backends_nb[j];

            if (!backend_nb->health_check) {
                continue;
            }

            struct ovn_port *op = ovn_port_find(ls_ports,
                                                backend_nb->logical_port);
            if (!op || !backend_nb->svc_mon_src_ip) {
                continue;
            }

            ds_clear(match);
            ds_clear(actions);
            if (IN6_IS_ADDR_V4MAPPED(&lb_vip->vip)) {
                ds_put_format(match, "arp.tpa == %s && arp.op == 1",
                              backend_nb->svc_mon_src_ip);
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
            } else {
                ds_put_format(match, "nd_ns && nd.target == %s",
                              backend_nb->svc_mon_src_ip);
                ds_put_format(actions,
                        "nd_na { "
                        "eth.dst = eth.src; "
                        "eth.src = %s; "
                        "ip6.src = %s; "
                        "nd.target = %s; "
                        "nd.tll = %s; "
                        "outport = inport; "
                        "flags.loopback = 1; "
                        "output; "
                        "};",
                        svc_monitor_mac,
                        backend_nb->svc_mon_src_ip,
                        backend_nb->svc_mon_src_ip,
                        svc_monitor_mac);
            }
            ovn_lflow_add_with_hint(lflows,
                                    op->od,
                                    S_SWITCH_IN_ARP_ND_RSP, 110,
                                    ds_cstr(match), ds_cstr(actions),
                                    &lb->nlb->header_,
                                    lb_dps->lflow_ref);
        }
    }
}


/* Logical switch ingress table 20 and 21: DHCP options and response
 * priority 100 flows. */
static void
build_lswitch_dhcp_options_and_response(struct ovn_port *op,
                                        struct lflow_table *lflows,
                                        const struct shash *meter_groups)
{
    ovs_assert(op->nbsp);
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

    if (op->od && op->od->nbs
        && ls_dhcp_relay_port(op->od)) {
        /* Don't add the DHCP server flows if DHCP Relay is enabled on the
         * logical switch. */
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
                    meter_groups, lflows, op->lflow_ref);
                build_dhcpv6_options_flows(
                    op, &op->lsp_addrs[i],
                    op->od->localnet_ports[j], is_external,
                    meter_groups, lflows, op->lflow_ref);
            }
        } else {
            build_dhcpv4_options_flows(op, &op->lsp_addrs[i], op,
                                       is_external, meter_groups,
                                       lflows, op->lflow_ref);
            build_dhcpv6_options_flows(op, &op->lsp_addrs[i], op,
                                       is_external, meter_groups,
                                       lflows, op->lflow_ref);
        }
    }
}

/* Ingress table 20 and 21: DHCP options and response, by default goto
 * next. (priority 0).
 * Ingress table 22 and 23: DNS lookup and response, by default goto next.
 * (priority 0).
 * Ingress table 24 - External port handling, by default goto next.
 * (priority 0). */
static void
build_lswitch_dhcp_and_dns_defaults(struct ovn_datapath *od,
                                    struct lflow_table *lflows,
                                    struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbs);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_DHCP_OPTIONS, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_DHCP_RESPONSE, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_DNS_LOOKUP, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_DNS_RESPONSE, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_SWITCH_IN_EXTERNAL_PORT, 0, "1", "next;",
                  lflow_ref);
}

/* Logical switch ingress table 22 and 23: DNS lookup and response
* priority 100 flows.
*/
static void
build_lswitch_dns_lookup_and_response(struct ovn_datapath *od,
                                      struct lflow_table *lflows,
                                      const struct shash *meter_groups,
                                      struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbs);
    if (!ls_has_dns_records(od->nbs)) {
        return;
    }
    ovn_lflow_metered(lflows, od, S_SWITCH_IN_DNS_LOOKUP, 100,
                      "udp.dst == 53",
                      REGBIT_DNS_LOOKUP_RESULT" = dns_lookup(); next;",
                      copp_meter_get(COPP_DNS, od->nbs->copp,
                                     meter_groups), lflow_ref);
    const char *dns_action = "eth.dst <-> eth.src; ip4.src <-> ip4.dst; "
                  "udp.dst = udp.src; udp.src = 53; outport = inport; "
                  "flags.loopback = 1; output;";
    const char *dns_match = "udp.dst == 53 && "REGBIT_DNS_LOOKUP_RESULT;
    ovn_lflow_add(lflows, od, S_SWITCH_IN_DNS_RESPONSE, 100,
                  dns_match, dns_action, lflow_ref);
    dns_action = "eth.dst <-> eth.src; ip6.src <-> ip6.dst; "
                  "udp.dst = udp.src; udp.src = 53; outport = inport; "
                  "flags.loopback = 1; output;";
    ovn_lflow_add(lflows, od, S_SWITCH_IN_DNS_RESPONSE, 100,
                  dns_match, dns_action, lflow_ref);
}

/* Table 24: External port. Drop ARP request for router ips from
 * external ports  on chassis not binding those ports.
 * This makes the router pipeline to be run only on the chassis
 * binding the external ports. */
static void
build_lswitch_external_port(struct ovn_port *op,
                            struct lflow_table *lflows)
{
    ovs_assert(op->nbsp);
    if (!lsp_is_external(op->nbsp)) {
        return;
    }
    for (size_t i = 0; i < op->od->n_localnet_ports; i++) {
        build_drop_arp_nd_flows_for_unbound_router_ports(
            op, op->od->localnet_ports[i], lflows,
            op->lflow_ref);
    }
}

/* Ingress table 25: Destination lookup, broadcast and multicast handling
 * (priority 70 - 100). */
static void
build_lswitch_destination_lookup_bmcast(struct ovn_datapath *od,
                                        struct lflow_table *lflows,
                                        struct ds *actions,
                                        const struct shash *meter_groups,
                                        struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbs);

    ovn_lflow_metered(lflows, od, S_SWITCH_IN_L2_LKUP, 110,
                      "eth.dst == $svc_monitor_mac && (tcp || icmp || icmp6)",
                      "handle_svc_check(inport);",
                      copp_meter_get(COPP_SVC_MONITOR, od->nbs->copp,
                                     meter_groups), lflow_ref);

    struct mcast_switch_info *mcast_sw_info = &od->mcast_info.sw;

    if (mcast_sw_info->enabled) {
        ds_clear(actions);
        ds_put_cstr(actions, "igmp;");
        /* Punt IGMP traffic to controller. */
        ovn_lflow_metered(lflows, od, S_SWITCH_IN_L2_LKUP, 100,
                          "flags.igmp_loopback == 0 && igmp", ds_cstr(actions),
                          copp_meter_get(COPP_IGMP, od->nbs->copp,
                                         meter_groups),
                          lflow_ref);

        /* Punt MLD traffic to controller. */
        ovn_lflow_metered(lflows, od, S_SWITCH_IN_L2_LKUP, 100,
                          "flags.igmp_loopback == 0 && (mldv1 || mldv2)",
                          ds_cstr(actions),
                          copp_meter_get(COPP_IGMP, od->nbs->copp,
                                         meter_groups),
                          lflow_ref);

        /* Flood all IP multicast traffic destined to 224.0.0.X to all
         * ports - RFC 4541, section 2.1.2, item 2.
         */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, 85,
                      "ip4.mcast && ip4.dst == 224.0.0.0/24",
                      "outport = \""MC_FLOOD_L2"\"; output;",
                      lflow_ref);

        /* Flood all IPv6 multicast traffic destined to reserved
         * multicast IPs (RFC 4291, 2.7.1).
         */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, 85,
                      "ip6.mcast_flood",
                      "outport = \""MC_FLOOD"\"; output;",
                      lflow_ref);

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
                          ds_cstr(actions), lflow_ref);
        }
    }

    if (!smap_get_bool(&od->nbs->other_config,
                       "broadcast-arps-to-all-routers", true)) {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, 72,
                      "eth.mcast && (arp.op == 1 || nd_ns)",
                      "outport = \""MC_FLOOD_L2"\"; output;",
                      lflow_ref);
    }

    ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, 70, "eth.mcast",
                  "outport = \""MC_FLOOD"\"; output;", lflow_ref);
}


/* Ingress table 27: Add IP multicast flows learnt from IGMP/MLD
 * (priority 90).
 *
 * OR, for transit switches:
 *
 * Add IP multicast flows learnt from IGMP/MLD to forward traffic
 * explicitly to the ports that are part of the IGMP/MLD group,
 * and ignore MROUTER Ports.
 * (priority 90).
 */
static void
build_lswitch_ip_mcast_igmp_mld(struct ovn_igmp_group *igmp_group,
                                struct lflow_table *lflows,
                                struct ds *actions,
                                struct ds *match)
{
    uint64_t dummy;

    if (igmp_group->datapath) {

        ds_clear(match);
        ds_clear(actions);

        bool transit_switch =
            ovn_datapath_is_transit_switch(igmp_group->datapath);

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
             * hosts, all link-local routers and all site routers.
             */
            if (ipv6_is_all_hosts(&igmp_group->address) ||
                ipv6_is_all_router(&igmp_group->address) ||
                ipv6_is_all_site_router(&igmp_group->address)) {
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
        if (mcast_sw_info->flood_relay && !transit_switch) {
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
                      90, ds_cstr(match), ds_cstr(actions), NULL);
    }
}

/* Ingress table 25: Destination lookup, unicast handling (priority 50), */
static void
build_lswitch_ip_unicast_lookup(struct ovn_port *op,
                                struct lflow_table *lflows,
                                struct ds *actions, struct ds *match)
{
    ovs_assert(op->nbsp);
    if (lsp_is_external(op->nbsp)) {
        return;
    }

    /* For ports connected to logical routers add flows to bypass the
     * broadcast flooding of ARP/ND requests in table 19. We direct the
     * requests only to the router port that owns the IP address.
     */
    if (lsp_is_router(op->nbsp)) {
        build_lswitch_rport_arp_req_flows(op->peer, op->od, op, lflows,
                                          &op->nbsp->header_);
    }

    bool lsp_clone_to_unknown = lsp_is_clone_to_unknown(op->nbsp);

    for (size_t i = 0; i < op->nbsp->n_addresses; i++) {
        /* Addresses are owned by the logical port.
         * Ethernet address followed by zero or more IPv4
         * or IPv6 addresses (or both). */
        struct eth_addr mac;
        bool lsp_enabled = lsp_is_enabled(op->nbsp);
        const char *action = lsp_enabled
                             ? ((lsp_clone_to_unknown && op->od->has_unknown)
                                ? "clone {outport = %s; output; };"
                                  "outport = \""MC_UNKNOWN "\"; output;"
                                : "outport = %s; output;")
                             : debug_drop_action();

        if (ovs_scan(op->nbsp->addresses[i],
                    ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))) {
            ds_clear(match);
            ds_put_format(match, "eth.dst == "ETH_ADDR_FMT,
                          ETH_ADDR_ARGS(mac));

            ds_clear(actions);
            ds_put_format(actions, action, op->json_key);
            ovn_lflow_add_with_hint(lflows, op->od,
                                    S_SWITCH_IN_L2_LKUP,
                                    50, ds_cstr(match),
                                    ds_cstr(actions),
                                    &op->nbsp->header_,
                                    op->lflow_ref);
        } else if (!strcmp(op->nbsp->addresses[i], "unknown")) {
            continue;
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
            ovn_lflow_add_with_hint(lflows, op->od,
                                    S_SWITCH_IN_L2_LKUP,
                                    50, ds_cstr(match),
                                    ds_cstr(actions),
                                    &op->nbsp->header_,
                                    op->lflow_ref);
        } else if (!strcmp(op->nbsp->addresses[i], "router")) {
            if (!op->peer || !op->peer->nbrp
                || !ovs_scan(op->peer->nbrp->mac,
                        ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))) {
                continue;
            }
            ds_clear(match);
            ds_put_cstr(match, "eth.dst == ");
            if (!eth_addr_is_zero(op->proxy_arp_addrs.ea)) {
                ds_put_format(match,
                              "{ %s, "ETH_ADDR_FMT" }",
                              op->proxy_arp_addrs.ea_s,
                              ETH_ADDR_ARGS(mac));
            } else {
                ds_put_format(match, ETH_ADDR_FMT, ETH_ADDR_ARGS(mac));
            }
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
                                    &op->nbsp->header_,
                                    op->lflow_ref);
        } else {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

            VLOG_INFO_RL(&rl,
                         "%s: invalid syntax '%s' in addresses column",
                         op->nbsp->name, op->nbsp->addresses[i]);
        }
    }
}

/* Ingress table 25: Destination lookup, unicast handling (priority 50), */
static void
build_lswitch_ip_unicast_lookup_for_nats(
    struct ovn_port *op, const struct lr_stateful_record *lr_stateful_rec,
    struct lflow_table *lflows, struct ds *match, struct ds *actions,
    struct lflow_ref *lflow_ref)
{
    ovs_assert(op->nbsp);

    if (!op->peer || !is_l3dgw_port(op->peer)) {
        return;
    }

    /* Make sure the lr_stateful_rec belongs to the peer port's
     * logical router. */
    ovs_assert(uuid_equals(&op->peer->od->nbr->header_.uuid,
                           &lr_stateful_rec->nbr_uuid));

    const char *action = lsp_is_enabled(op->nbsp) ?
                         "outport = %s; output;" :
                         debug_drop_action();
    struct eth_addr mac;

    /* Add ethernet addresses specified in NAT rules on
     * distributed logical routers. */
    for (size_t i = 0; i < lr_stateful_rec->lrnat_rec->n_nat_entries; i++) {
        const struct ovn_nat *nat =
            &lr_stateful_rec->lrnat_rec->nat_entries[i];

        if (!strcmp(nat->nb->type, "dnat_and_snat")
            && nat->nb->logical_port && nat->nb->external_mac
            && eth_addr_from_string(nat->nb->external_mac, &mac)) {

            ds_clear(match);
            ds_put_format(match, "eth.dst == "ETH_ADDR_FMT
                                 " && is_chassis_resident(\"%s\")",
                          ETH_ADDR_ARGS(mac),
                          nat->nb->logical_port);

            ds_clear(actions);
            ds_put_format(actions, action, op->json_key);
            ovn_lflow_add_with_hint(lflows, op->od,
                                    S_SWITCH_IN_L2_LKUP, 50,
                                    ds_cstr(match),
                                    ds_cstr(actions),
                                    &op->nbsp->header_,
                                    lflow_ref);
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
bfd_cleanup_connections(const struct nbrec_bfd_table *nbrec_bfd_table,
                        struct hmap *bfd_map)
{
    const struct nbrec_bfd *nb_bt;
    struct bfd_entry *bfd_e;

    NBREC_BFD_TABLE_FOR_EACH (nb_bt, nbrec_bfd_table) {
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
build_bfd_table(struct ovsdb_idl_txn *ovnsb_txn,
                const struct nbrec_bfd_table *nbrec_bfd_table,
                const struct sbrec_bfd_table *sbrec_bfd_table,
                const struct hmap *lr_ports, struct hmap *bfd_connections)
{
    struct hmap sb_only = HMAP_INITIALIZER(&sb_only);
    const struct sbrec_bfd *sb_bt;
    unsigned long *bfd_src_ports;
    struct bfd_entry *bfd_e;
    uint32_t hash;

    bfd_src_ports = bitmap_allocate(BFD_UDP_SRC_PORT_LEN);

    SBREC_BFD_TABLE_FOR_EACH (sb_bt, sbrec_bfd_table) {
        bfd_e = xmalloc(sizeof *bfd_e);
        bfd_e->sb_bt = sb_bt;
        hash = hash_string(sb_bt->dst_ip, 0);
        hash = hash_string(sb_bt->logical_port, hash);
        hmap_insert(&sb_only, &bfd_e->hmap_node, hash);
        bitmap_set1(bfd_src_ports, sb_bt->src_port - BFD_UDP_SRC_PORT_START);
    }

    const struct nbrec_bfd *nb_bt;
    NBREC_BFD_TABLE_FOR_EACH (nb_bt, nbrec_bfd_table) {
        if (!nb_bt->status) {
            /* default state is admin_down */
            nbrec_bfd_set_status(nb_bt, "admin_down");
        }

        struct ovn_port *op = ovn_port_find(lr_ports, nb_bt->logical_port);
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
            if (op && op->sb && op->sb->chassis) {
                sbrec_bfd_set_chassis_name(sb_bt, op->sb->chassis->name);
            }

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
            if (op && op->sb && op->sb->chassis &&
                strcmp(op->sb->chassis->name, bfd_e->sb_bt->chassis_name)) {
                sbrec_bfd_set_chassis_name(bfd_e->sb_bt,
                                           op->sb->chassis->name);
            }

            hmap_remove(&sb_only, &bfd_e->hmap_node);
            bfd_e->ref = false;
            hash = hash_string(bfd_e->sb_bt->dst_ip, 0);
            hash = hash_string(bfd_e->sb_bt->logical_port, hash);
            hmap_insert(bfd_connections, &bfd_e->hmap_node, hash);
        }

        if (op) {
            op->has_bfd = true;
        }
    }

    HMAP_FOR_EACH_POP (bfd_e, hmap_node, &sb_only) {
        struct ovn_port *op = ovn_port_find(lr_ports,
                                            bfd_e->sb_bt->logical_port);
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
                                       const struct hmap *lr_ports,
                                       int priority, const char *nexthop)
{
    if (nexthop == NULL) {
        return NULL;
    }

    /* Find the router port matching the next hop. */
    for (int i = 0; i < od->nbr->n_ports; i++) {
       struct nbrec_logical_router_port *lrp = od->nbr->ports[i];

       struct ovn_port *out_port = ovn_port_find(lr_ports, lrp->name);
       if (out_port && find_lrp_member_ip(out_port, nexthop)) {
           return out_port;
       }
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
    VLOG_WARN_RL(&rl, "No path for routing policy priority %d; next hop %s",
                 priority, nexthop);
    return NULL;
}

static struct ovs_mutex bfd_lock = OVS_MUTEX_INITIALIZER;

static bool check_bfd_state(
        const struct nbrec_logical_router_policy *rule,
        const struct hmap *bfd_connections,
        struct ovn_port *out_port,
        const char *nexthop)
{
    struct in6_addr nexthop_v6;
    bool is_nexthop_v6 = ipv6_parse(nexthop, &nexthop_v6);
    bool ret = true;

    for (size_t i = 0; i < rule->n_bfd_sessions; i++) {
        /* Check if there is a BFD session associated to the reroute
         * policy. */
        const struct nbrec_bfd *nb_bt = rule->bfd_sessions[i];
        struct in6_addr dst_ipv6;
        bool is_dst_v6 = ipv6_parse(nb_bt->dst_ip, &dst_ipv6);

        if (is_nexthop_v6 ^ is_dst_v6) {
            continue;
        }

        if ((is_nexthop_v6 && !ipv6_addr_equals(&nexthop_v6, &dst_ipv6)) ||
            strcmp(nb_bt->dst_ip, nexthop)) {
            continue;
        }

        if (strcmp(nb_bt->logical_port, out_port->key)) {
            continue;
        }

        struct bfd_entry *bfd_e = bfd_port_lookup(bfd_connections,
                                                  nb_bt->logical_port,
                                                  nb_bt->dst_ip);
        ovs_mutex_lock(&bfd_lock);
        if (bfd_e) {
            bfd_e->ref = true;
        }

        if (!strcmp(nb_bt->status, "admin_down")) {
            nbrec_bfd_set_status(nb_bt, "down");
        }

        ret = strcmp(nb_bt->status, "down");
        ovs_mutex_unlock(&bfd_lock);
        break;
    }

    return ret;
}

static void
build_routing_policy_flow(struct lflow_table *lflows, struct ovn_datapath *od,
                          const struct hmap *lr_ports,
                          const struct nbrec_logical_router_policy *rule,
                          const struct hmap *bfd_connections,
                          const struct ovsdb_idl_row *stage_hint,
                          struct lflow_ref *lflow_ref)
{
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    if (!strcmp(rule->action, "reroute")) {
        ovs_assert(rule->n_nexthops <= 1);

        char *nexthop =
            (rule->n_nexthops == 1 ? rule->nexthops[0] : rule->nexthop);
        struct ovn_port *out_port = get_outport_for_routing_policy_nexthop(
             od, lr_ports, rule->priority, nexthop);
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

        if (!check_bfd_state(rule, bfd_connections, out_port, nexthop)) {
            return;
        }

        uint32_t pkt_mark = smap_get_uint(&rule->options, "pkt_mark", 0);
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
        uint32_t pkt_mark = smap_get_uint(&rule->options, "pkt_mark", 0);
        if (pkt_mark) {
            ds_put_format(&actions, "pkt.mark = %u; ", pkt_mark);
        }
        ds_put_cstr(&actions, REG_ECMP_GROUP_ID" = 0; next;");
    }
    ds_put_format(&match, "%s", rule->match);

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_POLICY, rule->priority,
                            ds_cstr(&match), ds_cstr(&actions), stage_hint,
                            lflow_ref);
    ds_destroy(&match);
    ds_destroy(&actions);
}

static void
build_ecmp_routing_policy_flows(struct lflow_table *lflows,
                                struct ovn_datapath *od,
                                const struct hmap *lr_ports,
                                const struct nbrec_logical_router_policy *rule,
                                const struct hmap *bfd_connections,
                                uint16_t ecmp_group_id,
                                struct lflow_ref *lflow_ref)
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

    size_t *valid_nexthops = xcalloc(rule->n_nexthops, sizeof *valid_nexthops);
    size_t n_valid_nexthops = 0;

    for (size_t i = 0; i < rule->n_nexthops; i++) {
        struct ovn_port *out_port = get_outport_for_routing_policy_nexthop(
             od, lr_ports, rule->priority, rule->nexthops[i]);
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

        if (!check_bfd_state(rule, bfd_connections, out_port,
                             rule->nexthops[i])) {
            continue;
        }

        valid_nexthops[n_valid_nexthops++] = i + 1;

        ds_clear(&actions);
        uint32_t pkt_mark = smap_get_uint(&rule->options, "pkt_mark", 0);
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
                                ds_cstr(&actions), &rule->header_,
                                lflow_ref);
    }

    if (!n_valid_nexthops) {
        goto cleanup;
    }

    ds_clear(&actions);
    if (n_valid_nexthops > 1) {
        ds_put_format(&actions, "%s = %"PRIu16
                      "; %s = select(", REG_ECMP_GROUP_ID, ecmp_group_id,
                      REG_ECMP_MEMBER_ID);

        for (size_t i = 0; i < n_valid_nexthops; i++) {
            if (i > 0) {
                ds_put_cstr(&actions, ", ");
            }

            ds_put_format(&actions, "%"PRIuSIZE, valid_nexthops[i]);
        }
        ds_put_cstr(&actions, ");");
    } else {
        ds_put_format(&actions, "%s = %"PRIu16
                      "; %s = %"PRIuSIZE"; next;", REG_ECMP_GROUP_ID,
                      ecmp_group_id, REG_ECMP_MEMBER_ID,
                      valid_nexthops[0]);
    }
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_POLICY,
                            rule->priority, rule->match,
                            ds_cstr(&actions), &rule->header_,
                            lflow_ref);

cleanup:
    free(valid_nexthops);
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
    if (!route_table_name || !route_table_name[0]) {
        return 0;
    }

    uint32_t rtb_id = simap_get(route_tables, route_table_name);
    if (!rtb_id) {
        rtb_id = route_table_add(route_tables, route_table_name);
    }

    return rtb_id;
}

static void
build_route_table_lflow(struct ovn_datapath *od, struct lflow_table *lflows,
                        struct nbrec_logical_router_port *lrp,
                        struct simap *route_tables,
                        struct lflow_ref *lflow_ref)
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
                  ds_cstr(&match), ds_cstr(&actions), lflow_ref);

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

static bool
find_static_route_outport(struct ovn_datapath *od, const struct hmap *lr_ports,
    const struct nbrec_logical_router_static_route *route, bool is_ipv4,
    const char **p_lrp_addr_s, struct ovn_port **p_out_port);

/* Parse and validate the route. Return the parsed route if successful.
 * Otherwise return NULL. */
static struct parsed_route *
parsed_routes_add(struct ovn_datapath *od, const struct hmap *lr_ports,
                  struct ovs_list *routes, struct simap *route_tables,
                  const struct nbrec_logical_router_static_route *route,
                  const struct hmap *bfd_connections)
{
    /* Verify that the next hop is an IP address with an all-ones mask. */
    struct in6_addr nexthop;
    unsigned int plen;
    bool is_discard_route = !strcmp(route->nexthop, "discard");
    bool valid_nexthop = route->nexthop[0] && !is_discard_route;
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
        !find_static_route_outport(od, lr_ports, route,
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
find_static_route_outport(struct ovn_datapath *od, const struct hmap *lr_ports,
    const struct nbrec_logical_router_static_route *route, bool is_ipv4,
    const char **p_lrp_addr_s, struct ovn_port **p_out_port)
{
    const char *lrp_addr_s = NULL;
    struct ovn_port *out_port = NULL;
    if (route->output_port) {
        out_port = ovn_port_find(lr_ports, route->output_port);
        if (!out_port) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Bad out port %s for static route %s",
                         route->output_port, route->ip_prefix);
            return false;
        }
        if (route->nexthop[0]) {
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
            out_port = ovn_port_find(lr_ports, lrp->name);
            if (!out_port) {
                /* This should not happen. */
                continue;
            }

            if (route->nexthop[0]) {
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
add_ecmp_symmetric_reply_flows(struct lflow_table *lflows,
                               struct ovn_datapath *od,
                               bool ct_masked_mark,
                               const char *port_ip,
                               struct ovn_port *out_port,
                               const struct parsed_route *route,
                               struct ds *route_match,
                               struct lflow_ref *lflow_ref)
{
    const struct nbrec_logical_router_static_route *st_route = route->route;
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
    ds_put_format(&match, "inport == %s && ip%s.%s == %s",
                  out_port->json_key,
                  IN6_IS_ADDR_V4MAPPED(&route->prefix) ? "4" : "6",
                  route->is_src_route ? "dst" : "src",
                  cidr);
    free(cidr);
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DEFRAG, 100,
                             ds_cstr(&match), "ct_next;",
                             &st_route->header_, lflow_ref);

    /* And packets that go out over an ECMP route need conntrack */
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DEFRAG, 100,
                             ds_cstr(route_match), "ct_next;",
                             &st_route->header_, lflow_ref);

    /* Save src eth and inport in ct_label for packets that arrive over
     * an ECMP route.
     *
     * NOTE: we purposely are not clearing match before this
     * ds_put_cstr() call. The previous contents are needed.
     */
    ds_put_cstr(&match, " && !ct.rpl && (ct.new || ct.est)");
    ds_put_format(&actions,
            "ct_commit { ct_label.ecmp_reply_eth = eth.src; "
            " %s = %" PRId64 ";}; "
            "next;",
            ct_ecmp_reply_port_match, out_port->sb->tunnel_key);
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_ECMP_STATEFUL, 100,
                            ds_cstr(&match), ds_cstr(&actions),
                            &st_route->header_,
                            lflow_ref);

    /* Bypass ECMP selection if we already have ct_label information
     * for where to route the packet.
     */
    ds_put_format(&ecmp_reply,
                  "ct.rpl && %s == %"PRId64,
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
                           &st_route->header_,
                           lflow_ref);

    /* Egress reply traffic for symmetric ECMP routes skips router policies. */
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_POLICY, 65535,
                            ds_cstr(&ecmp_reply), "next;",
                            &st_route->header_,
                            lflow_ref);

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
                            action, &st_route->header_,
                            lflow_ref);

    ds_destroy(&match);
    ds_destroy(&actions);
    ds_destroy(&ecmp_reply);
}

static void
build_ecmp_route_flow(struct lflow_table *lflows, struct ovn_datapath *od,
                      bool ct_masked_mark, const struct hmap *lr_ports,
                      struct ecmp_groups_node *eg,
                      struct lflow_ref *lflow_ref)

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
                  ds_cstr(&route_match), ds_cstr(&actions),
                  lflow_ref);

    /* Add per member flow */
    struct ds match = DS_EMPTY_INITIALIZER;
    struct sset visited_ports = SSET_INITIALIZER(&visited_ports);
    LIST_FOR_EACH (er, list_node, &eg->route_list) {
        const struct parsed_route *route_ = er->route;
        const struct nbrec_logical_router_static_route *route = route_->route;
        /* Find the outgoing port. */
        const char *lrp_addr_s = NULL;
        struct ovn_port *out_port = NULL;
        if (!find_static_route_outport(od, lr_ports, route, is_ipv4,
                                       &lrp_addr_s, &out_port)) {
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
                                           route_, &route_match,
                                           lflow_ref);
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
                                &route->header_, lflow_ref);
    }
    sset_destroy(&visited_ports);
    ds_destroy(&match);
    ds_destroy(&route_match);
    ds_destroy(&actions);
}

static void
add_route(struct lflow_table *lflows, struct ovn_datapath *od,
          const struct ovn_port *op, const char *lrp_addr_s,
          const char *network_s, int plen, const char *gateway,
          bool is_src_route, const uint32_t rtb_id,
          const struct ovsdb_idl_row *stage_hint, bool is_discard_route,
          int ofs, struct lflow_ref *lflow_ref)
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
        if (gateway && gateway[0]) {
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

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_IP_ROUTING,
                            priority, ds_cstr(&match),
                            ds_cstr(&actions), stage_hint,
                            lflow_ref);
    if (op && op->has_bfd) {
        ds_put_format(&match, " && udp.dst == 3784");
        ovn_lflow_add_with_hint(lflows, op->od,
                                S_ROUTER_IN_IP_ROUTING,
                                priority + 1, ds_cstr(&match),
                                ds_cstr(&common_actions),\
                                stage_hint, lflow_ref);
    }
    ds_destroy(&match);
    ds_destroy(&common_actions);
    ds_destroy(&actions);
}

static void
build_static_route_flow(struct lflow_table *lflows, struct ovn_datapath *od,
                        const struct hmap *lr_ports,
                        const struct parsed_route *route_,
                        struct lflow_ref *lflow_ref)
{
    const char *lrp_addr_s = NULL;
    struct ovn_port *out_port = NULL;

    const struct nbrec_logical_router_static_route *route = route_->route;

    /* Find the outgoing port. */
    if (!route_->is_discard_route) {
        if (!find_static_route_outport(od, lr_ports, route,
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
              route_->is_discard_route, ofs, lflow_ref);

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


enum lrouter_nat_lb_flow_type {
    LROUTER_NAT_LB_FLOW_NORMAL = 0,
    LROUTER_NAT_LB_FLOW_SKIP_SNAT,
    LROUTER_NAT_LB_FLOW_FORCE_SNAT,
    LROUTER_NAT_LB_FLOW_MAX,
};

struct lrouter_nat_lb_flows_ctx {
    const char *new_action[LROUTER_NAT_LB_FLOW_MAX];

    struct ds *new_match;
    struct ds *undnat_match;
    struct ds *gw_redir_action;

    struct ovn_lb_vip *lb_vip;
    const struct ovn_northd_lb *lb;
    bool reject;

    int prio;

    struct lflow_table *lflows;
    const struct shash *meter_groups;
};

static inline bool
lrouter_use_common_zone(const struct ovn_datapath *od)
{
    return !od->is_gw_router && use_common_zone;
}

static void
build_distr_lrouter_nat_flows_for_lb(struct lrouter_nat_lb_flows_ctx *ctx,
                                     enum lrouter_nat_lb_flow_type type,
                                     struct ovn_datapath *od,
                                     struct lflow_ref *lflow_ref)
{
    struct ovn_port *dgp = od->l3dgw_ports[0];

    const char *undnat_action;

    switch (type) {
    case LROUTER_NAT_LB_FLOW_FORCE_SNAT:
        undnat_action = "flags.force_snat_for_lb = 1; next;";
        break;
    case LROUTER_NAT_LB_FLOW_SKIP_SNAT:
        undnat_action = "flags.skip_snat_for_lb = 1; next;";
        break;
    case LROUTER_NAT_LB_FLOW_NORMAL:
    case LROUTER_NAT_LB_FLOW_MAX:
        undnat_action = lrouter_use_common_zone(od)
                        ? "ct_dnat_in_czone;"
                        : "ct_dnat;";
        break;
    }

    /* Store the match lengths, so we can reuse the ds buffer. */
    size_t new_match_len = ctx->new_match->length;
    size_t undnat_match_len = ctx->undnat_match->length;


    const char *meter = NULL;

    if (ctx->reject) {
        meter = copp_meter_get(COPP_REJECT, od->nbr->copp, ctx->meter_groups);
    }

    if (ctx->lb_vip->n_backends || !ctx->lb_vip->empty_backend_rej) {
        ds_put_format(ctx->new_match, " && is_chassis_resident(%s)",
                      od->l3dgw_ports[0]->cr_port->json_key);
    }

    ovn_lflow_add_with_hint__(ctx->lflows, od, S_ROUTER_IN_DNAT, ctx->prio,
                              ds_cstr(ctx->new_match), ctx->new_action[type],
                              NULL, meter, &ctx->lb->nlb->header_,
                              lflow_ref);

    ds_truncate(ctx->new_match, new_match_len);

    if (!ctx->lb_vip->n_backends) {
        return;
    }

    /* We need to centralize the LB traffic to properly perform
     * the undnat stage.
     */
    ds_put_format(ctx->undnat_match, ") && outport == %s", dgp->json_key);
    ds_clear(ctx->gw_redir_action);
    ds_put_format(ctx->gw_redir_action, "outport = %s; next;",
                  dgp->cr_port->json_key);

    ovn_lflow_add_with_hint(ctx->lflows, od, S_ROUTER_IN_GW_REDIRECT,
                            200, ds_cstr(ctx->undnat_match),
                            ds_cstr(ctx->gw_redir_action),
                            &ctx->lb->nlb->header_,
                            lflow_ref);
    ds_truncate(ctx->undnat_match, undnat_match_len);

    ds_put_format(ctx->undnat_match, ") && (inport == %s || outport == %s)"
                  " && is_chassis_resident(%s)", dgp->json_key, dgp->json_key,
                  dgp->cr_port->json_key);
    ovn_lflow_add_with_hint(ctx->lflows, od, S_ROUTER_OUT_UNDNAT, 120,
                            ds_cstr(ctx->undnat_match), undnat_action,
                            &ctx->lb->nlb->header_,
                            lflow_ref);
    ds_truncate(ctx->undnat_match, undnat_match_len);
}

static void
build_gw_lrouter_nat_flows_for_lb(struct lrouter_nat_lb_flows_ctx *ctx,
                                  enum lrouter_nat_lb_flow_type type,
                                  const struct ovn_datapaths *lr_datapaths,
                                  const unsigned long *dp_bitmap,
                                  struct lflow_ref *lflow_ref)
{
    unsigned long *dp_non_meter = NULL;
    bool build_non_meter = false;
    size_t index;
    size_t bitmap_len = ods_size(lr_datapaths);

    if (bitmap_is_all_zeros(dp_bitmap, bitmap_len)) {
        return;
    }

    if (ctx->reject) {
        dp_non_meter = bitmap_clone(dp_bitmap, bitmap_len);
        BITMAP_FOR_EACH_1 (index, bitmap_len, dp_bitmap) {
            struct ovn_datapath *od = lr_datapaths->array[index];
            const char *meter;

            meter = copp_meter_get(COPP_REJECT, od->nbr->copp,
                                   ctx->meter_groups);
            if (!meter) {
                build_non_meter = true;
                continue;
            }
            bitmap_set0(dp_non_meter, index);
            ovn_lflow_add_with_hint__(ctx->lflows, od, S_ROUTER_IN_DNAT,
                    ctx->prio, ds_cstr(ctx->new_match), ctx->new_action[type],
                    NULL, meter, &ctx->lb->nlb->header_, lflow_ref);
        }
    }
    if (!ctx->reject || build_non_meter) {
        ovn_lflow_add_with_dp_group(ctx->lflows,
            dp_non_meter ? dp_non_meter : dp_bitmap, ods_size(lr_datapaths),
            S_ROUTER_IN_DNAT, ctx->prio, ds_cstr(ctx->new_match),
            ctx->new_action[type], &ctx->lb->nlb->header_, lflow_ref);
    }
    bitmap_free(dp_non_meter);
}

static void
build_lrouter_nat_flows_for_lb(
    struct ovn_lb_vip *lb_vip,
    struct ovn_lb_datapaths *lb_dps,
    struct ovn_northd_lb_vip *vips_nb,
    const struct ovn_datapaths *lr_datapaths,
    const struct lr_stateful_table *lr_stateful_table,
    struct lflow_table *lflows,
    struct ds *match, struct ds *action,
    const struct shash *meter_groups,
    const struct chassis_features *features,
    const struct hmap *svc_monitor_map)
{
    const struct ovn_northd_lb *lb = lb_dps->lb;
    bool ipv4 = lb_vip->address_family == AF_INET;
    const char *ip_match = ipv4 ? "ip4" : "ip6";
    char *aff_action[LROUTER_NAT_LB_FLOW_MAX] = {
        [LROUTER_NAT_LB_FLOW_SKIP_SNAT]  = "flags.skip_snat_for_lb = 1; ",
        [LROUTER_NAT_LB_FLOW_FORCE_SNAT] = "flags.force_snat_for_lb = 1; ",
    };

    int prio = 110;

    struct ds skip_snat_act = DS_EMPTY_INITIALIZER;
    struct ds force_snat_act = DS_EMPTY_INITIALIZER;
    struct ds undnat_match = DS_EMPTY_INITIALIZER;
    struct ds gw_redir_action = DS_EMPTY_INITIALIZER;

    ds_clear(match);
    ds_clear(action);

    bool reject = build_lb_vip_actions(lb, lb_vip, vips_nb, action,
                                       lb->selection_fields, &skip_snat_act,
                                       &force_snat_act, false, features,
                                       svc_monitor_map);

    /* Higher priority rules are added for load-balancing in DNAT
     * table.  For every match (on a VIP[:port]), we add two flows.
     * One flow is for specific matching on ct.new with an action
     * of "ct_lb_mark($targets);". The other flow is for ct.est with
     * an action of "next;".
     */
    ds_put_format(match, "ct.new && !ct.rel && %s && %s.dst == %s",
                  ip_match, ip_match, lb_vip->vip_str);
    if (lb_vip->port_str) {
        prio = 120;
        ds_put_format(match, " && %s && %s.dst == %s",
                      lb->proto, lb->proto, lb_vip->port_str);
    }

    /* Add logical flows to UNDNAT the load balanced reverse traffic in
     * the router egress pipleine stage - S_ROUTER_OUT_UNDNAT if the logical
     * router has a gateway router port associated.
     */
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
    /* Remove the trailing " || ". */
    ds_truncate(&undnat_match, undnat_match.length - 4);

    struct lrouter_nat_lb_flows_ctx ctx = {
        .lb_vip = lb_vip,
        .lb = lb,
        .reject = reject,
        .prio = prio,
        .lflows = lflows,
        .meter_groups = meter_groups,
        .new_match = match,
        .undnat_match = &undnat_match,
        .gw_redir_action = &gw_redir_action,
    };

    ctx.new_action[LROUTER_NAT_LB_FLOW_NORMAL] = ds_cstr(action);
    ctx.new_action[LROUTER_NAT_LB_FLOW_SKIP_SNAT] = ds_cstr(&skip_snat_act);
    ctx.new_action[LROUTER_NAT_LB_FLOW_FORCE_SNAT] = ds_cstr(&force_snat_act);

    unsigned long *gw_dp_bitmap[LROUTER_NAT_LB_FLOW_MAX];
    unsigned long *aff_dp_bitmap[LROUTER_NAT_LB_FLOW_MAX];

    size_t bitmap_len = ods_size(lr_datapaths);
    for (size_t i = 0; i < LROUTER_NAT_LB_FLOW_MAX; i++) {
        gw_dp_bitmap[i] = bitmap_allocate(bitmap_len);
        aff_dp_bitmap[i] = bitmap_allocate(bitmap_len);
    }

    /* Group gw router since we do not have datapath dependency in
     * lflow generation for them.
     */
    size_t index;
    BITMAP_FOR_EACH_1 (index, bitmap_len, lb_dps->nb_lr_map) {
        struct ovn_datapath *od = lr_datapaths->array[index];
        enum lrouter_nat_lb_flow_type type;

        const struct lr_stateful_record *lr_stateful_rec =
            lr_stateful_table_find_by_index(lr_stateful_table, od->index);
        ovs_assert(lr_stateful_rec);

        const struct lr_nat_record *lrnat_rec = lr_stateful_rec->lrnat_rec;
        if (lb->skip_snat) {
            type = LROUTER_NAT_LB_FLOW_SKIP_SNAT;
        } else if (!lport_addresses_is_empty(&lrnat_rec->lb_force_snat_addrs)
                   || lrnat_rec->lb_force_snat_router_ip) {
            type = LROUTER_NAT_LB_FLOW_FORCE_SNAT;
        } else {
            type = LROUTER_NAT_LB_FLOW_NORMAL;
        }

        if (!od->n_l3dgw_ports) {
            bitmap_set1(gw_dp_bitmap[type], index);
        } else {
            build_distr_lrouter_nat_flows_for_lb(&ctx, type, od,
                                                 lb_dps->lflow_ref);
        }

        if (lb->affinity_timeout) {
            bitmap_set1(aff_dp_bitmap[type], index);
        }
    }

    for (size_t type = 0; type < LROUTER_NAT_LB_FLOW_MAX; type++) {
        build_gw_lrouter_nat_flows_for_lb(&ctx, type, lr_datapaths,
                                          gw_dp_bitmap[type],
                                          lb_dps->lflow_ref);
        build_lb_affinity_lr_flows(lflows, lb, lb_vip, ds_cstr(match),
                                   aff_action[type], aff_dp_bitmap[type],
                                   lr_datapaths, lb_dps->lflow_ref);
    }

    ds_destroy(&undnat_match);
    ds_destroy(&skip_snat_act);
    ds_destroy(&force_snat_act);
    ds_destroy(&gw_redir_action);

    for (size_t i = 0; i < LROUTER_NAT_LB_FLOW_MAX; i++) {
        bitmap_free(gw_dp_bitmap[i]);
        bitmap_free(aff_dp_bitmap[i]);
    }
}

static void
build_lswitch_flows_for_lb(struct ovn_lb_datapaths *lb_dps,
                           struct lflow_table *lflows,
                           const struct shash *meter_groups,
                           const struct ovn_datapaths *ls_datapaths,
                           const struct chassis_features *features,
                           const struct hmap *svc_monitor_map,
                           struct ds *match, struct ds *action)
{
    if (!lb_dps->n_nb_ls) {
        return;
    }

    const struct ovn_northd_lb *lb = lb_dps->lb;
    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_lb_vip *lb_vip = &lb->vips[i];

        /* pre-stateful lb */
        if (!build_empty_lb_event_flow(lb_vip, lb, match, action)) {
            continue;
        }

        size_t index;
        BITMAP_FOR_EACH_1 (index, ods_size(ls_datapaths), lb_dps->nb_ls_map) {
            struct ovn_datapath *od = ls_datapaths->array[index];

            ovn_lflow_add_with_hint__(lflows, od,
                                      S_SWITCH_IN_PRE_LB, 130, ds_cstr(match),
                                      ds_cstr(action),
                                      NULL,
                                      copp_meter_get(COPP_EVENT_ELB,
                                                     od->nbs->copp,
                                                     meter_groups),
                                      &lb->nlb->header_,
                                      lb_dps->lflow_ref);
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
    build_lb_rules_pre_stateful(lflows, lb_dps, features->ct_no_masked_label,
                                ls_datapaths, match, action);
    build_lb_rules(lflows, lb_dps, ls_datapaths, features, match, action,
                   meter_groups, svc_monitor_map);
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
build_lrouter_defrag_flows_for_lb(struct ovn_lb_datapaths *lb_dps,
                                  struct lflow_table *lflows,
                                  const struct ovn_datapaths *lr_datapaths,
                                  struct ds *match)
{
    if (!lb_dps->n_nb_lr) {
        return;
    }

    for (size_t i = 0; i < lb_dps->lb->n_vips; i++) {
        struct ovn_lb_vip *lb_vip = &lb_dps->lb->vips[i];
        bool ipv6 = lb_vip->address_family == AF_INET6;
        int prio = 100;

        ds_clear(match);
        ds_put_format(match, "ip && ip%c.dst == %s", ipv6 ? '6' : '4',
                      lb_vip->vip_str);

        ovn_lflow_add_with_dp_group(
            lflows, lb_dps->nb_lr_map, ods_size(lr_datapaths),
            S_ROUTER_IN_DEFRAG, prio, ds_cstr(match), "ct_dnat;",
            &lb_dps->lb->nlb->header_, lb_dps->lflow_ref);
    }
}

static void
build_lrouter_flows_for_lb(struct ovn_lb_datapaths *lb_dps,
                           struct lflow_table *lflows,
                           const struct shash *meter_groups,
                           const struct ovn_datapaths *lr_datapaths,
                           const struct lr_stateful_table *lr_stateful_table,
                           const struct chassis_features *features,
                           const struct hmap *svc_monitor_map,
                           struct ds *match, struct ds *action)
{
    size_t index;

    if (!lb_dps->n_nb_lr) {
        return;
    }

    const struct ovn_northd_lb *lb = lb_dps->lb;
    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_lb_vip *lb_vip = &lb->vips[i];

        build_lrouter_nat_flows_for_lb(lb_vip, lb_dps, &lb->vips_nb[i],
                                       lr_datapaths, lr_stateful_table, lflows,
                                       match, action, meter_groups, features,
                                       svc_monitor_map);

        if (!build_empty_lb_event_flow(lb_vip, lb, match, action)) {
            continue;
        }

        BITMAP_FOR_EACH_1 (index, ods_size(lr_datapaths), lb_dps->nb_lr_map) {
            struct ovn_datapath *od = lr_datapaths->array[index];

            ovn_lflow_add_with_hint__(lflows, od, S_ROUTER_IN_DNAT,
                                      130, ds_cstr(match), ds_cstr(action),
                                      NULL,
                                      copp_meter_get(COPP_EVENT_ELB,
                                                     od->nbr->copp,
                                                     meter_groups),
                                      &lb->nlb->header_, lb_dps->lflow_ref);
        }
    }

    if (lb->skip_snat) {
        BITMAP_FOR_EACH_1 (index, ods_size(lr_datapaths), lb_dps->nb_lr_map) {
            struct ovn_datapath *od = lr_datapaths->array[index];

            ovn_lflow_add(lflows, od, S_ROUTER_OUT_SNAT, 120,
                          "flags.skip_snat_for_lb == 1 && ip", "next;",
                          lb_dps->lflow_ref);
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

    for (size_t i = 0; i < op->nbrp->n_ipv6_prefix; i++) {
        ds_put_cstr(&s, op->nbrp->ipv6_prefix[i]);
        ds_put_char(&s, ' ');
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
lrouter_dnat_and_snat_is_stateless(const struct nbrec_nat *nat)
{
    return smap_get_bool(&nat->options, "stateless", false) &&
           !strcmp(nat->type, "dnat_and_snat");
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
lrouter_nat_add_ext_ip_match(const struct ovn_datapath *od,
                             struct lflow_table *lflows, struct ds *match,
                             const struct nbrec_nat *nat,
                             bool is_v6, bool is_src, int cidr_bits,
                             struct lflow_ref *lflow_ref)
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
                                &nat->header_, lflow_ref);
        ds_destroy(&match_exempt);
    }
}

/* Builds the logical flow that replies to ARP requests for an 'ip_address'
 * owned by the router. The flow is inserted in table S_ROUTER_IN_IP_INPUT
 * with the given priority.
 */
static void
build_lrouter_arp_flow(const struct ovn_datapath *od, struct ovn_port *op,
                       const char *ip_address, const char *eth_addr,
                       struct ds *extra_match, bool drop, uint16_t priority,
                       const struct ovsdb_idl_row *hint,
                       struct lflow_table *lflows,
                       struct lflow_ref *lflow_ref)
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
                            ds_cstr(&match), ds_cstr(&actions), hint,
                            lflow_ref);

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
build_lrouter_nd_flow(const struct ovn_datapath *od, struct ovn_port *op,
                      const char *action, const char *ip_address,
                      const char *sn_ip_address, const char *eth_addr,
                      struct ds *extra_match, bool drop, uint16_t priority,
                      const struct ovsdb_idl_row *hint,
                      struct lflow_table *lflows,
                      const struct shash *meter_groups,
                      struct lflow_ref *lflow_ref)
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
                                ds_cstr(&match), ds_cstr(&actions), hint,
                                lflow_ref);
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
                                  hint, lflow_ref);
    }

    ds_destroy(&match);
    ds_destroy(&actions);
}

static void
build_lrouter_nat_arp_nd_flow(const struct ovn_datapath *od,
                              struct ovn_nat *nat_entry,
                              struct lflow_table *lflows,
                              const struct shash *meter_groups,
                              struct lflow_ref *lflow_ref)
{
    struct lport_addresses *ext_addrs = &nat_entry->ext_addrs;
    const struct nbrec_nat *nat = nat_entry->nb;

    if (nat_entry_is_v6(nat_entry)) {
        build_lrouter_nd_flow(od, NULL, "nd_na",
                              ext_addrs->ipv6_addrs[0].addr_s,
                              ext_addrs->ipv6_addrs[0].sn_addr_s,
                              REG_INPORT_ETH_ADDR, NULL, false, 90,
                              &nat->header_, lflows, meter_groups,
                              lflow_ref);
    } else {
        build_lrouter_arp_flow(od, NULL,
                               ext_addrs->ipv4_addrs[0].addr_s,
                               REG_INPORT_ETH_ADDR, NULL, false, 90,
                               &nat->header_, lflows,
                               lflow_ref);
    }
}

static void
build_lrouter_port_nat_arp_nd_flow(struct ovn_port *op,
                                   struct ovn_nat *nat_entry,
                                   struct lflow_table *lflows,
                                   const struct shash *meter_groups,
                                   struct lflow_ref *lflow_ref)
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
                              &nat->header_, lflows, meter_groups,
                              lflow_ref);
        build_lrouter_nd_flow(op->od, op, "nd_na",
                              ext_addrs->ipv6_addrs[0].addr_s,
                              ext_addrs->ipv6_addrs[0].sn_addr_s,
                              mac_s, NULL, true, 91,
                              &nat->header_, lflows, meter_groups,
                              lflow_ref);
    } else {
        build_lrouter_arp_flow(op->od, op,
                               ext_addrs->ipv4_addrs[0].addr_s,
                               mac_s, &match, false, 92,
                               &nat->header_, lflows,
                               lflow_ref);
        build_lrouter_arp_flow(op->od, op,
                               ext_addrs->ipv4_addrs[0].addr_s,
                               mac_s, NULL, true, 91,
                               &nat->header_, lflows,
                               lflow_ref);
    }

    ds_destroy(&match);
}

static void
build_lrouter_drop_own_dest(struct ovn_port *op,
                            const struct lr_stateful_record *lr_stateful_rec,
                            enum ovn_stage stage,
                            uint16_t priority, bool drop_snat_ip,
                            struct lflow_table *lflows,
                            struct lflow_ref *lflow_ref)
{
    struct ds match_ips = DS_EMPTY_INITIALIZER;

    if (op->lrp_networks.n_ipv4_addrs) {
        for (size_t i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            const char *ip = op->lrp_networks.ipv4_addrs[i].addr_s;

            bool router_ip_in_snat_ips =
                !!shash_find(&lr_stateful_rec->lrnat_rec->snat_ips, ip);
            bool router_ip_in_lb_ips =
                !!sset_find(&lr_stateful_rec->lb_ips->ips_v4, ip);
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
                                    &op->nbrp->header_,
                                    lflow_ref);
            free(match);
        }
    }

    if (op->lrp_networks.n_ipv6_addrs) {
        ds_clear(&match_ips);

        for (size_t i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
            const char *ip = op->lrp_networks.ipv6_addrs[i].addr_s;

            bool router_ip_in_snat_ips =
                !!shash_find(&lr_stateful_rec->lrnat_rec->snat_ips, ip);
            bool router_ip_in_lb_ips =
                !!sset_find(&lr_stateful_rec->lb_ips->ips_v6, ip);
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
                                    &op->nbrp->header_,
                                    lflow_ref);
            free(match);
        }
    }
    ds_destroy(&match_ips);
}

static void
build_lrouter_force_snat_flows(struct lflow_table *lflows,
                               const struct ovn_datapath *od,
                               const char *ip_version, const char *ip_addr,
                               const char *context,
                               struct lflow_ref *lflow_ref)
{
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;
    ds_put_format(&match, "ip%s && ip%s.dst == %s",
                  ip_version, ip_version, ip_addr);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_UNSNAT, 110,
                  ds_cstr(&match), "ct_snat;", lflow_ref);

    /* Higher priority rules to force SNAT with the IP addresses
     * configured in the Gateway router.  This only takes effect
     * when the packet has already been DNATed or load balanced once. */
    ds_clear(&match);
    ds_put_format(&match, "flags.force_snat_for_%s == 1 && ip%s",
                  context, ip_version);
    ds_put_format(&actions, "ct_snat(%s);", ip_addr);
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_SNAT, 100,
                  ds_cstr(&match), ds_cstr(&actions),
                  lflow_ref);

    ds_destroy(&match);
    ds_destroy(&actions);
}

/* Following flows are used to manage traffic redirected by the kernel
 * (e.g. ICMP errors packets) that enter the cluster from the geneve ports
 */
static void
build_lrouter_icmp_packet_toobig_admin_flows(
        struct ovn_port *op, struct lflow_table *lflows,
        struct ds *match, struct ds *actions,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(op->nbrp);

    if (!is_l3dgw_port(op)) {
        return;
    }

    ds_clear(match);
    ds_put_format(match,
                  "((ip4 && icmp4.type == 3 && icmp4.code == 4) ||"
                  " (ip6 && icmp6.type == 2 && icmp6.code == 0)) &&"
                  " eth.dst == %s && !is_chassis_resident(%s) &&"
                  " flags.tunnel_rx == 1",
                  op->nbrp->mac, op->cr_port->json_key);
    ds_clear(actions);
    ds_put_format(actions, "outport <-> inport; inport = %s; next;",
                  op->json_key);
    ovn_lflow_add(lflows, op->od, S_ROUTER_IN_ADMISSION, 120,
                  ds_cstr(match), ds_cstr(actions), lflow_ref);
}

static void
build_lswitch_icmp_packet_toobig_admin_flows(
        struct ovn_port *op, struct lflow_table *lflows,
        struct ds *match, struct ds *actions)
{
    ovs_assert(op->nbsp);

    if (!lsp_is_router(op->nbsp)) {
        return;
    }

    struct ovn_port *peer = op->peer;
    if (!peer) {
        return;
    }

    ds_clear(match);
    if (peer->od->is_gw_router) {
        ds_put_format(match,
                      "((ip4 && icmp4.type == 3 && icmp4.code == 4) ||"
                      " (ip6 && icmp6.type == 2 && icmp6.code == 0)) && "
                      "eth.src == %s && outport == %s && flags.tunnel_rx == 1",
                      peer->nbrp->mac, op->json_key);
    } else {
        ds_put_format(match,
                      "((ip4 && icmp4.type == 3 && icmp4.code == 4) ||"
                      " (ip6 && icmp6.type == 2 && icmp6.code == 0)) && "
                      "eth.dst == %s && flags.tunnel_rx == 1",
                      peer->nbrp->mac);
    }
    ds_clear(actions);
    ds_put_format(actions,
                  "outport <-> inport; next(pipeline=ingress,table=%d);",
                  ovn_stage_get_table(S_SWITCH_IN_L2_LKUP));
    ovn_lflow_add(lflows, op->od, S_SWITCH_IN_CHECK_PORT_SEC, 120,
                  ds_cstr(match), ds_cstr(actions), op->lflow_ref);
}

static void
build_lrouter_force_snat_flows_op(struct ovn_port *op,
                                  const struct lr_nat_record *lrnat_rec,
                                  struct lflow_table *lflows,
                                  struct ds *match, struct ds *actions,
                                  struct lflow_ref *lflow_ref)
{
    ovs_assert(op->nbrp);
    if (!op->peer || !lrnat_rec->lb_force_snat_router_ip) {
        return;
    }

    if (op->lrp_networks.n_ipv4_addrs) {
        ds_clear(match);
        ds_clear(actions);

        ds_put_format(match, "inport == %s && ip4.dst == %s",
                      op->json_key, op->lrp_networks.ipv4_addrs[0].addr_s);
        ovn_lflow_add(lflows, op->od, S_ROUTER_IN_UNSNAT, 110,
                      ds_cstr(match), "ct_snat;", lflow_ref);

        ds_clear(match);

        /* Higher priority rules to force SNAT with the router port ip.
         * This only takes effect when the packet has already been
         * load balanced once. */
        ds_put_format(match, "flags.force_snat_for_lb == 1 && ip4 && "
                      "outport == %s", op->json_key);
        ds_put_format(actions, "ct_snat(%s);",
                      op->lrp_networks.ipv4_addrs[0].addr_s);
        ovn_lflow_add(lflows, op->od, S_ROUTER_OUT_SNAT, 110,
                      ds_cstr(match), ds_cstr(actions),
                      lflow_ref);
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
                      ds_cstr(match), "ct_snat;", lflow_ref);

        ds_clear(match);

        /* Higher priority rules to force SNAT with the router port ip.
         * This only takes effect when the packet has already been
         * load balanced once. */
        ds_put_format(match, "flags.force_snat_for_lb == 1 && ip6 && "
                      "outport == %s", op->json_key);
        ds_put_format(actions, "ct_snat(%s);",
                      op->lrp_networks.ipv6_addrs[0].addr_s);
        ovn_lflow_add(lflows, op->od, S_ROUTER_OUT_SNAT, 110,
                      ds_cstr(match), ds_cstr(actions),
                      lflow_ref);
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
build_lrouter_bfd_flows(struct lflow_table *lflows, struct ovn_port *op,
                        const struct shash *meter_groups,
                        struct lflow_ref *lflow_ref)
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
                                &op->nbrp->header_,
                                lflow_ref);
        ds_clear(&match);
        ds_put_format(&match, "ip4.dst == %s && udp.dst == 3784",
                      ds_cstr(&ip_list));
        ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT, 110,
                                  ds_cstr(&match), "handle_bfd_msg(); ", NULL,
                                  copp_meter_get(COPP_BFD, op->od->nbr->copp,
                                                 meter_groups),
                                  &op->nbrp->header_,
                                  lflow_ref);
    }
    if (op->lrp_networks.n_ipv6_addrs) {
        ds_clear(&ip_list);
        ds_clear(&match);

        op_put_v6_networks(&ip_list, op);
        ds_put_format(&match, "ip6.src == %s && udp.dst == 3784",
                      ds_cstr(&ip_list));
        ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT, 110,
                                ds_cstr(&match), "next; ",
                                &op->nbrp->header_,
                                lflow_ref);
        ds_clear(&match);
        ds_put_format(&match, "ip6.dst == %s && udp.dst == 3784",
                      ds_cstr(&ip_list));
        ovn_lflow_add_with_hint__(lflows, op->od, S_ROUTER_IN_IP_INPUT, 110,
                                  ds_cstr(&match), "handle_bfd_msg(); ", NULL,
                                  copp_meter_get(COPP_BFD, op->od->nbr->copp,
                                                 meter_groups),
                                  &op->nbrp->header_,
                                  lflow_ref);
    }

    ds_destroy(&ip_list);
    ds_destroy(&match);
}

/* Logical router ingress Table 0: L2 Admission Control
 * Generic admission control flows (without inport check).
 */
static void
build_adm_ctrl_flows_for_lrouter(
        struct ovn_datapath *od, struct lflow_table *lflows,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);

    /* Default action for recirculated ICMP error 'packet too big'. */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_ADMISSION, 110,
                  "((ip4 && icmp4.type == 3 && icmp4.code == 4) ||"
                  " (ip6 && icmp6.type == 2 && icmp6.code == 0)) &&"
                  " flags.tunnel_rx == 1", debug_drop_action(), lflow_ref);

    /* Logical VLANs not supported.
     * Broadcast/multicast source address is invalid. */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_ADMISSION, 100,
                  "vlan.present || eth.src[40]", debug_drop_action(),
                  lflow_ref);

    /* Default action for L2 security is to drop. */
    ovn_lflow_add_default_drop(lflows, od, S_ROUTER_IN_ADMISSION,
                               lflow_ref);
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

            if (!nbsp || !nbsp->tag_request) {
                continue;
            }

            if (nbsp->tag_request[0] ||
                (nbsp->parent_name && nbsp->parent_name[0])) {
                /* Valid tag. */
                return VLAN_ETH_HEADER_LEN;
            }
        }
    }

    return ETH_HEADER_LEN;
}

/* All 'gateway_mtu' and 'gateway_mtu_bypass' flows should be built with this
 * function.
 */
static void OVS_PRINTF_FORMAT(10, 11)
build_gateway_mtu_flow(struct lflow_table *lflows, struct ovn_port *op,
                       enum ovn_stage stage, uint16_t prio_low,
                       uint16_t prio_high, struct ds *match,
                       struct ds *actions, const struct ovsdb_idl_row *hint,
                       struct lflow_ref *lflow_ref,
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
                            hint, lflow_ref);

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
                                    hint, lflow_ref);
        }
    }
    va_end(extra_actions_args);
}

static bool
consider_l3dgw_port_is_centralized(struct ovn_port *op)
{
    if (l3dgw_port_has_associated_vtep_lports(op)) {
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
        struct ovn_port *op, struct lflow_table *lflows,
        struct ds *match, struct ds *actions,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(op->nbrp);

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
                           lflow_ref,
                           REG_INPORT_ETH_ADDR " = %s; next;",
                           op->lrp_networks.ea_s);

    ds_clear(match);
    ds_put_cstr(match, "eth.dst == ");
    if (op->peer && !eth_addr_is_zero(op->peer->proxy_arp_addrs.ea)) {
        ds_put_format(match,
                      "{ %s, %s }",
                      op->peer->proxy_arp_addrs.ea_s,
                      op->lrp_networks.ea_s);
    } else {
        ds_put_format(match, "%s", op->lrp_networks.ea_s);
    }
    ds_put_format(match, " && inport == %s", op->json_key);
    if (consider_l3dgw_port_is_centralized(op)) {
        ds_put_format(match, " && is_chassis_resident(%s)",
                      op->cr_port->json_key);
    }
    build_gateway_mtu_flow(lflows, op, S_ROUTER_IN_ADMISSION, 50, 55,
                           match, actions, &op->nbrp->header_,
                           lflow_ref,
                           REG_INPORT_ETH_ADDR " = %s; next;",
                           op->lrp_networks.ea_s);
}


/* Logical router ingress Table 1 and 2: Neighbor lookup and learning
 * lflows for logical routers. */
static void
build_neigh_learning_flows_for_lrouter(
        struct ovn_datapath *od, struct lflow_table *lflows,
        struct ds *match, struct ds *actions,
        const struct shash *meter_groups,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);

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
                  "arp.op == 2", ds_cstr(actions), lflow_ref);

    ds_clear(actions);
    ds_put_format(actions, REGBIT_LOOKUP_NEIGHBOR_RESULT
                  " = lookup_nd(inport, nd.target, nd.tll); %snext;",
                  learn_from_arp_request ? "" :
                  REGBIT_LOOKUP_NEIGHBOR_IP_RESULT" = 1; ");
    ovn_lflow_add(lflows, od, S_ROUTER_IN_LOOKUP_NEIGHBOR, 100, "nd_na",
                  ds_cstr(actions), lflow_ref);

    if (!learn_from_arp_request) {
        /* Add flow to skip GARP LLA if we don't know it already.
         * From RFC 2461, section 4.4, Neighbor Advertisement Message
         * Format, the Destination Address should be:
         *   For solicited advertisements, the Source Address of
         *   an invoking Neighbor Solicitation or, if the
         *   solicitation's Source Address is the unspecified
         *   address, the all-nodes multicast address. */
        ds_clear(actions);
        ds_put_format(actions, REGBIT_LOOKUP_NEIGHBOR_RESULT
                               " = lookup_nd(inport, nd.target, nd.tll); "
                               REGBIT_LOOKUP_NEIGHBOR_IP_RESULT
                               " = lookup_nd_ip(inport, nd.target); next;");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_LOOKUP_NEIGHBOR, 110,
                      "nd_na && ip6.src == fe80::/10 && ip6.dst == ff00::/8",
                      ds_cstr(actions), lflow_ref);
    }

    ds_clear(actions);
    ds_put_format(actions, REGBIT_LOOKUP_NEIGHBOR_RESULT
                  " = lookup_nd(inport, ip6.src, nd.sll); %snext;",
                  learn_from_arp_request ? "" :
                  REGBIT_LOOKUP_NEIGHBOR_IP_RESULT
                  " = lookup_nd_ip(inport, ip6.src); ");
    ovn_lflow_add(lflows, od, S_ROUTER_IN_LOOKUP_NEIGHBOR, 100, "nd_ns",
                  ds_cstr(actions), lflow_ref);

    /* For other packet types, we can skip neighbor learning.
     * So set REGBIT_LOOKUP_NEIGHBOR_RESULT to 1. */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_LOOKUP_NEIGHBOR, 0, "1",
                  REGBIT_LOOKUP_NEIGHBOR_RESULT" = 1; next;",
                  lflow_ref);

    /* Flows for LEARN_NEIGHBOR. */
    /* Skip Neighbor learning if not required. */
    ds_clear(match);
    ds_put_format(match, REGBIT_LOOKUP_NEIGHBOR_RESULT" == 1%s",
                  learn_from_arp_request ? "" :
                  " || "REGBIT_LOOKUP_NEIGHBOR_IP_RESULT" == 0");
    ovn_lflow_add(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 100,
                  ds_cstr(match), "mac_cache_use; next;",
                  lflow_ref);

    ovn_lflow_metered(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                      "arp", "put_arp(inport, arp.spa, arp.sha); next;",
                      copp_meter_get(COPP_ARP, od->nbr->copp,
                                     meter_groups),
                      lflow_ref);

    ovn_lflow_add(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 95,
                  "nd_ns && (ip6.src == 0 || nd.sll == 0)", "next;",
                  lflow_ref);

    ovn_lflow_metered(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 95,
                      "nd_na && nd.tll == 0",
                      "put_nd(inport, nd.target, eth.src); next;",
                      copp_meter_get(COPP_ND_NA, od->nbr->copp,
                                     meter_groups),
                      lflow_ref);

    ovn_lflow_metered(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                      "nd_na", "put_nd(inport, nd.target, nd.tll); next;",
                      copp_meter_get(COPP_ND_NA, od->nbr->copp,
                                     meter_groups),
                      lflow_ref);

    ovn_lflow_metered(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                      "nd_ns", "put_nd(inport, ip6.src, nd.sll); next;",
                      copp_meter_get(COPP_ND_NS, od->nbr->copp,
                                     meter_groups),
                      lflow_ref);

    ovn_lflow_add_default_drop(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR,
                               lflow_ref);
}

/* Logical router ingress Table 1: Neighbor lookup lflows
 * for logical router ports. */
static void
build_neigh_learning_flows_for_lrouter_port(
        struct ovn_port *op, struct lflow_table *lflows,
        struct ds *match, struct ds *actions,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(op->nbrp);

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
                                    &op->nbrp->header_,
                                    lflow_ref);
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
                                &op->nbrp->header_,
                                lflow_ref);
    }
}

/* Logical router ingress table ND_RA_OPTIONS & ND_RA_RESPONSE: IPv6 Router
 * Adv (RA) options and response. */
static void
build_ND_RA_flows_for_lrouter_port(
        struct ovn_port *op, struct lflow_table *lflows,
        struct ds *match, struct ds *actions,
        const struct shash *meter_groups,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(op->nbrp);
    if (op->nbrp->peer || !op->peer) {
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
                                  &op->nbrp->header_,
                                  lflow_ref);
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
                                &op->nbrp->header_,
                                lflow_ref);
    }
}

/* Logical router ingress table ND_RA_OPTIONS & ND_RA_RESPONSE: RS
 * responder, by default goto next. (priority 0). */
static void
build_ND_RA_flows_for_lrouter(struct ovn_datapath *od,
                              struct lflow_table *lflows,
                              struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_ND_RA_OPTIONS, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_ND_RA_RESPONSE, 0, "1", "next;",
                  lflow_ref);
}

/* Logical router ingress table IP_ROUTING_PRE:
 * by default goto next. (priority 0). */
static void
build_ip_routing_pre_flows_for_lrouter(struct ovn_datapath *od,
                                       struct lflow_table *lflows,
                                       struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING_PRE, 0, "1",
                  REG_ROUTE_TABLE_ID" = 0; next;", lflow_ref);
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
 *
 * This function adds routes for directly connected subnets configured on the
 * LRP 'op'.
 */
static void
build_ip_routing_flows_for_lrp(
        struct ovn_port *op, struct lflow_table *lflows,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(op->nbrp);
    for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
        add_route(lflows, op->od, op, op->lrp_networks.ipv4_addrs[i].addr_s,
                  op->lrp_networks.ipv4_addrs[i].network_s,
                  op->lrp_networks.ipv4_addrs[i].plen, NULL, false, 0,
                  &op->nbrp->header_, false, ROUTE_PRIO_OFFSET_CONNECTED,
                  lflow_ref);
    }

    for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
        add_route(lflows, op->od, op, op->lrp_networks.ipv6_addrs[i].addr_s,
                  op->lrp_networks.ipv6_addrs[i].network_s,
                  op->lrp_networks.ipv6_addrs[i].plen, NULL, false, 0,
                  &op->nbrp->header_, false, ROUTE_PRIO_OFFSET_CONNECTED,
                  lflow_ref);
    }
}

static void
build_static_route_flows_for_lrouter(
        struct ovn_datapath *od, const struct chassis_features *features,
        struct lflow_table *lflows, const struct hmap *lr_ports,
        const struct hmap *bfd_connections,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);
    ovn_lflow_add_default_drop(lflows, od, S_ROUTER_IN_IP_ROUTING_ECMP,
                               lflow_ref);
    ovn_lflow_add_default_drop(lflows, od, S_ROUTER_IN_IP_ROUTING,
                               lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING_ECMP, 150,
                  REG_ECMP_GROUP_ID" == 0", "next;",
                  lflow_ref);

    struct hmap ecmp_groups = HMAP_INITIALIZER(&ecmp_groups);
    struct hmap unique_routes = HMAP_INITIALIZER(&unique_routes);
    struct ovs_list parsed_routes = OVS_LIST_INITIALIZER(&parsed_routes);
    struct simap route_tables = SIMAP_INITIALIZER(&route_tables);
    struct ecmp_groups_node *group;

    for (int i = 0; i < od->nbr->n_ports; i++) {
        build_route_table_lflow(od, lflows, od->nbr->ports[i],
                                &route_tables, lflow_ref);
    }

    for (int i = 0; i < od->nbr->n_static_routes; i++) {
        struct parsed_route *route =
            parsed_routes_add(od, lr_ports, &parsed_routes, &route_tables,
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
                              lr_ports, group, lflow_ref);
    }
    const struct unique_routes_node *ur;
    HMAP_FOR_EACH (ur, hmap_node, &unique_routes) {
        build_static_route_flow(lflows, od, lr_ports, ur->route, lflow_ref);
    }
    ecmp_groups_destroy(&ecmp_groups);
    unique_routes_destroy(&unique_routes);
    parsed_routes_destroy(&parsed_routes);
    simap_destroy(&route_tables);
}

/* IP Multicast lookup. Here we set the output port, adjust TTL and
 * advance to next table (priority 500).
 */
static void
build_mcast_lookup_flows_for_lrouter(
        struct ovn_datapath *od, struct lflow_table *lflows,
        struct ds *match, struct ds *actions,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);

    /* Drop IPv6 multicast traffic that shouldn't be forwarded,
     * i.e., router solicitation and router advertisement.
     */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10550,
                  "nd_rs || nd_ra", debug_drop_action(),
                  lflow_ref);
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
                      ds_cstr(match), ds_cstr(actions),
                      lflow_ref);
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
        HMAP_FOR_EACH (op, dp_node, &od->ports) {
            ds_clear(match);
            ds_put_format(match, "eth.src == %s && igmp",
                          op->lrp_networks.ea_s);
            ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10550,
                          ds_cstr(match), debug_drop_action(),
                          lflow_ref);

            ds_clear(match);
            ds_put_format(match, "eth.src == %s && (mldv1 || mldv2)",
                          op->lrp_networks.ea_s);
            ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10550,
                          ds_cstr(match), debug_drop_action(),
                          lflow_ref);
        }

        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10460,
                      "igmp",
                      "clone { "
                            "outport = \""MC_STATIC"\"; "
                            "next; "
                      "};",
                      lflow_ref);
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10460,
                      "mldv1 || mldv2",
                      "clone { "
                            "outport = \""MC_STATIC"\"; "
                            "next; "
                      "};",
                      lflow_ref);
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10450,
                      "ip4.mcast || ip6.mcast",
                      "clone { "
                            "outport = \""MC_STATIC"\"; "
                            "ip.ttl--; "
                            "next; "
                      "};",
                      lflow_ref);
    } else {
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 10450,
                      "ip4.mcast || ip6.mcast", debug_drop_action(),
                      lflow_ref);
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
        struct ovn_datapath *od, struct lflow_table *lflows,
        const struct hmap *lr_ports,
        const struct hmap *bfd_connections,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);
    /* This is a catch-all rule. It has the lowest priority (0)
     * does a match-all("1") and pass-through (next) */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_POLICY, 0, "1",
                  REG_ECMP_GROUP_ID" = 0; next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_POLICY_ECMP, 150,
                  REG_ECMP_GROUP_ID" == 0", "next;",
                  lflow_ref);
    ovn_lflow_add_default_drop(lflows, od, S_ROUTER_IN_POLICY_ECMP,
                               lflow_ref);

    /* Convert routing policies to flows. */
    uint16_t ecmp_group_id = 1;
    for (int i = 0; i < od->nbr->n_policies; i++) {
        const struct nbrec_logical_router_policy *rule
            = od->nbr->policies[i];
        bool is_ecmp_reroute =
            (!strcmp(rule->action, "reroute") && rule->n_nexthops > 1);

        if (is_ecmp_reroute) {
            build_ecmp_routing_policy_flows(lflows, od, lr_ports, rule,
                                            bfd_connections, ecmp_group_id,
                                            lflow_ref);
            ecmp_group_id++;
        } else {
            build_routing_policy_flow(lflows, od, lr_ports, rule,
                                      bfd_connections, &rule->header_,
                                      lflow_ref);
        }
    }
}

/* Local router ingress table ARP_RESOLVE: ARP Resolution. */
static void
build_arp_resolve_flows_for_lrouter(
        struct ovn_datapath *od, struct lflow_table *lflows,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);
    /* Multicast packets already have the outport set so just advance to
     * next table (priority 500). */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_ARP_RESOLVE, 500,
                  "ip4.mcast || ip6.mcast", "next;",
                  lflow_ref);

    ovn_lflow_add(lflows, od, S_ROUTER_IN_ARP_RESOLVE, 1, "ip4",
                  "get_arp(outport, " REG_NEXT_HOP_IPV4 "); next;",
                  lflow_ref);

    ovn_lflow_add(lflows, od, S_ROUTER_IN_ARP_RESOLVE, 1, "ip6",
                  "get_nd(outport, " REG_NEXT_HOP_IPV6 "); next;",
                  lflow_ref);

    ovn_lflow_add_default_drop(lflows, od, S_ROUTER_IN_ARP_RESOLVE,
                               lflow_ref);
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

/* This function adds ARP resolve flows related to a LRP. */
static void
build_arp_resolve_flows_for_lrp(struct ovn_port *op,
                                struct lflow_table *lflows,
                                struct ds *match, struct ds *actions,
                                struct lflow_ref *lflow_ref)
{
    ovs_assert(op->nbrp);
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
                                    &op->nbrp->header_,
                                    lflow_ref);
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
                                    &op->nbrp->header_,
                                    lflow_ref);
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
                                    &op->nbrp->header_,
                                    lflow_ref);
        }
    }
}

/* This function adds ARP resolve flows related to a LSP. */
static void
build_arp_resolve_flows_for_lsp(
        struct ovn_port *op, struct lflow_table *lflows,
        const struct hmap *lr_ports,
        struct ds *match, struct ds *actions)
{
    ovs_assert(op->nbsp);
    if (!lsp_is_enabled(op->nbsp)) {
        return;
    }

    if (op->od->n_router_ports && !lsp_is_router(op->nbsp)
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
                            lr_ports, op->od->router_ports[k]);
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
                                            &op->nbsp->header_,
                                            op->lflow_ref);
                }
            }

            for (size_t j = 0; j < op->lsp_addrs[i].n_ipv6_addrs; j++) {
                const char *ip_s = op->lsp_addrs[i].ipv6_addrs[j].addr_s;
                for (size_t k = 0; k < op->od->n_router_ports; k++) {
                    /* Get the Logical_Router_Port that the
                     * Logical_Switch_Port is connected to, as
                     * 'peer'. */
                    struct ovn_port *peer = ovn_port_get_peer(
                            lr_ports, op->od->router_ports[k]);
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
                                            &op->nbsp->header_,
                                            op->lflow_ref);
                }
            }
        }
    } else if (lsp_is_router(op->nbsp)) {
        /* This is a logical switch port that connects to a router. */

        /* The peer of this switch port is the router port for which
         * we need to add logical flows such that it can resolve
         * ARP entries for all the other router ports connected to
         * the switch in question. */
        struct ovn_port *peer = ovn_port_get_peer(lr_ports, op);
        if (!peer || !peer->nbrp) {
            return;
        }

        if (peer->od->nbr &&
            smap_get_bool(&peer->od->nbr->options,
                          "dynamic_neigh_routers", false)) {
            return;
        }

        for (size_t i = 0; i < op->od->n_router_ports; i++) {
            struct ovn_port *router_port =
                ovn_port_get_peer(lr_ports, op->od->router_ports[i]);
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
                                        &op->nbsp->header_,
                                        op->lflow_ref);
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
                                        &op->nbsp->header_,
                                        op->lflow_ref);
            }
        }
    }
}

#define ICMP4_NEED_FRAG_FORMAT                           \
    "icmp4_error {"                                      \
    "%s"                                                 \
    REGBIT_EGRESS_LOOPBACK" = 1; "                       \
    REGBIT_PKT_LARGER" = 0; "                            \
    "eth.dst = %s; "                                     \
    "ip4.dst = ip4.src; "                                \
    "ip4.src = %s; "                                     \
    "ip.ttl = 255; "                                     \
    "icmp4.type = 3; /* Destination Unreachable. */ "    \
    "icmp4.code = 4; /* Frag Needed and DF was Set. */ " \
    "icmp4.frag_mtu = %d; "                              \
    "next(pipeline=ingress, table=%d); };"               \

#define ICMP6_NEED_FRAG_FORMAT               \
    "icmp6_error {"                          \
    "%s"                                     \
    REGBIT_EGRESS_LOOPBACK" = 1; "           \
    REGBIT_PKT_LARGER" = 0; "                \
    "eth.dst = %s; "                         \
    "ip6.dst = ip6.src; "                    \
    "ip6.src = %s; "                         \
    "ip.ttl = 255; "                         \
    "icmp6.type = 2; /* Packet Too Big. */ " \
    "icmp6.code = 0; "                       \
    "icmp6.frag_mtu = %d; "                  \
    "next(pipeline=ingress, table=%d); };"

static void
create_icmp_need_frag_lflow(const struct ovn_port *op, int mtu,
                            struct ds *actions, struct ds *match,
                            const char *meter, struct lflow_table *lflows,
                            struct lflow_ref *lflow_ref,
                            enum ovn_stage stage, uint16_t priority,
                            bool is_ipv6, const char *extra_match,
                            const char *extra_action)
{
    if ((is_ipv6 && !op->lrp_networks.ipv6_addrs) ||
        (!is_ipv6 && !op->lrp_networks.ipv4_addrs)) {
        return;
    }

    const char *ip = is_ipv6
                     ? op->lrp_networks.ipv6_addrs[0].addr_s
                     : op->lrp_networks.ipv4_addrs[0].addr_s;
    size_t match_len = match->length;

    ds_put_format(match, " && ip%c && "REGBIT_PKT_LARGER
                  " && "REGBIT_EGRESS_LOOPBACK" == 0", is_ipv6 ? '6' : '4');

    if (*extra_match) {
        ds_put_format(match, " && %s", extra_match);
    }

    ds_clear(actions);
    ds_put_format(actions,
                  is_ipv6 ? ICMP6_NEED_FRAG_FORMAT : ICMP4_NEED_FRAG_FORMAT,
                  extra_action, op->lrp_networks.ea_s, ip,
                  mtu, ovn_stage_get_table(S_ROUTER_IN_ADMISSION));

    ovn_lflow_add_with_hint__(lflows, op->od, stage, priority,
                              ds_cstr(match), ds_cstr(actions),
                              NULL, meter, &op->nbrp->header_, lflow_ref);

    ds_truncate(match, match_len);
}

static void
build_icmperr_pkt_big_flows(struct ovn_port *op, int mtu,
                            struct lflow_table *lflows,
                            const struct shash *meter_groups, struct ds *match,
                            struct ds *actions, enum ovn_stage stage,
                            struct ovn_port *outport,
                            struct lflow_ref *lflow_ref)
{
    const char *ipv4_meter = copp_meter_get(COPP_ICMP4_ERR, op->od->nbr->copp,
                                            meter_groups);
    const char *ipv6_meter = copp_meter_get(COPP_ICMP6_ERR, op->od->nbr->copp,
                                            meter_groups);

    ds_clear(match);
    ds_put_format(match, "inport == %s", op->json_key);

    if (outport) {
        ds_put_format(match, " && outport == %s", outport->json_key);

        create_icmp_need_frag_lflow(op, mtu, actions, match, ipv4_meter,
                                    lflows, lflow_ref, stage, 160, false,
                                    "ct.trk && ct.rpl && ct.dnat",
                                    "flags.icmp_snat = 1; ");
        create_icmp_need_frag_lflow(op, mtu, actions, match, ipv6_meter,
                                    lflows, lflow_ref, stage, 160, true,
                                    "ct.trk && ct.rpl && ct.dnat",
                                    "flags.icmp_snat = 1; ");
    }

    create_icmp_need_frag_lflow(op, mtu, actions, match, ipv4_meter, lflows,
                                lflow_ref, stage, 150, false, "", "");
    create_icmp_need_frag_lflow(op, mtu, actions, match, ipv6_meter, lflows,
                                lflow_ref, stage, 150, true, "", "");
}

static void
build_check_pkt_len_flows_for_lrp(struct ovn_port *op,
                                  struct lflow_table *lflows,
                                  const struct hmap *lr_ports,
                                  const struct shash *meter_groups,
                                  struct ds *match, struct ds *actions,
                                  struct lflow_ref *lflow_ref,
                                  const struct chassis_features *features)
{
    int gw_mtu = smap_get_int(&op->nbrp->options, "gateway_mtu", 0);
    if (gw_mtu <= 0) {
        return;
    }

    ds_clear(match);
    ds_put_format(match, "outport == %s", op->json_key);
    build_gateway_mtu_flow(lflows, op, S_ROUTER_IN_CHK_PKT_LEN, 50, 55,
                           match, actions, &op->nbrp->header_,
                           lflow_ref, "next;");

    /* ingress traffic */
    build_icmperr_pkt_big_flows(op, gw_mtu, lflows, meter_groups,
                                match, actions, S_ROUTER_IN_IP_INPUT,
                                NULL, lflow_ref);

    for (size_t i = 0; i < op->od->nbr->n_ports; i++) {
        struct ovn_port *rp = ovn_port_find(lr_ports,
                                            op->od->nbr->ports[i]->name);
        if (!rp || rp == op) {
            continue;
        }

        /* egress traffic */
        build_icmperr_pkt_big_flows(rp, gw_mtu, lflows, meter_groups,
                                    match, actions, S_ROUTER_IN_LARGER_PKTS,
                                    op, lflow_ref);
    }

    if (features->ct_commit_nat_v2) {
        ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_OUT_POST_SNAT, 100,
                                "icmp && flags.icmp_snat == 1",
                                "ct_commit_nat(snat);", &op->nbrp->header_,
                                lflow_ref);
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
        struct ovn_datapath *od, struct lflow_table *lflows,
        const struct hmap *lr_ports,
        struct ds *match, struct ds *actions,
        const struct shash *meter_groups,
        struct lflow_ref *lflow_ref,
        const struct chassis_features *features)
{
    ovs_assert(od->nbr);

    /* Packets are allowed by default. */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_CHK_PKT_LEN, 0, "1",
                  "next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_LARGER_PKTS, 0, "1",
                  "next;", lflow_ref);

    for (size_t i = 0; i < od->nbr->n_ports; i++) {
        struct ovn_port *rp = ovn_port_find(lr_ports,
                                            od->nbr->ports[i]->name);
        if (!rp || !rp->nbrp) {
            continue;
        }
        build_check_pkt_len_flows_for_lrp(rp, lflows, lr_ports, meter_groups,
                                          match, actions, lflow_ref, features);
    }
}

/* Logical router ingress table GW_REDIRECT: Gateway redirect. */
static void
build_gateway_redirect_flows_for_lrouter(
        struct ovn_datapath *od, struct lflow_table *lflows,
        struct ds *match, struct ds *actions,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);
    for (size_t i = 0; i < od->n_l3dgw_ports; i++) {
        if (l3dgw_port_has_associated_vtep_lports(od->l3dgw_ports[i])) {
            /* Skip adding redirect lflow for vtep-enabled l3dgw ports.
             * Traffic from hypervisor to VTEP (ramp) switch should go in
             * distributed manner. Only returning routed traffic must go
             * through centralized gateway (or ha-chassis-group).
             * This assumes that attached logical switch with vtep lport(s) has
             * no localnet port(s) for NAT. Otherwise centralized NAT will not
             * work. */
            continue;
        }

        const struct ovsdb_idl_row *stage_hint = NULL;

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
                                stage_hint, lflow_ref);
    }

    /* Packets are allowed by default. */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_GW_REDIRECT, 0, "1", "next;",
                  lflow_ref);
}

/* Logical router ingress table GW_REDIRECT: Gateway redirect. */
static void
build_lr_gateway_redirect_flows_for_nats(
        const struct ovn_datapath *od, const struct lr_nat_record *lrnat_rec,
        struct lflow_table *lflows, struct ds *match, struct ds *actions,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);
    for (size_t i = 0; i < od->n_l3dgw_ports; i++) {
        if (l3dgw_port_has_associated_vtep_lports(od->l3dgw_ports[i])) {
            /* Skip adding redirect lflow for vtep-enabled l3dgw ports.
             * Traffic from hypervisor to VTEP (ramp) switch should go in
             * distributed manner. Only returning routed traffic must go
             * through centralized gateway (or ha-chassis-group).
             * This assumes that attached logical switch with vtep lport(s) has
             * no localnet port(s) for NAT. Otherwise centralized NAT will not
             * work. */
            continue;
        }

        bool add_def_flow = true;

        for (int j = 0; j < lrnat_rec->n_nat_entries; j++) {
            const struct ovn_nat *nat = &lrnat_rec->nat_entries[j];

            if (!lrouter_dnat_and_snat_is_stateless(nat->nb) ||
                (!nat->nb->allowed_ext_ips && !nat->nb->exempted_ext_ips)) {
                continue;
            }

            const struct ovsdb_idl_row *stage_hint = NULL;

            if (od->l3dgw_ports[i]->nbrp) {
                stage_hint = &od->l3dgw_ports[i]->nbrp->header_;
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
                                        ds_cstr(actions), stage_hint,
                                        lflow_ref);
                if (add_def_flow) {
                    ds_clear(&match_ext);
                    ds_put_format(&match_ext, "ip && ip%s.dst == %s",
                                  nat_entry_is_v6(nat) ? "6" : "4",
                                  nat->nb->external_ip);
                    ovn_lflow_add(lflows, od, S_ROUTER_IN_GW_REDIRECT, 70,
                                  ds_cstr(&match_ext), debug_drop_action(),
                                  lflow_ref);
                    add_def_flow = false;
                }
            } else if (nat->nb->exempted_ext_ips) {
                ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_GW_REDIRECT,
                                        75, ds_cstr(&match_ext),
                                        debug_drop_action(),
                                        stage_hint, lflow_ref);
            }
            ds_destroy(&match_ext);
        }
    }
}

/* Local router ingress table ARP_REQUEST: ARP request.
 *
 * In the common case where the Ethernet destination has been resolved,
 * this table outputs the packet (priority 0).  Otherwise, it composes
 * and sends an ARP/IPv6 NA request (priority 100). */
static void
build_arp_request_flows_for_lrouter(
        struct ovn_datapath *od, struct lflow_table *lflows,
        struct ds *match, struct ds *actions,
        const struct shash *meter_groups,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);
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
                      "}; output;", ETH_ADDR_ARGS(eth_dst), sn_addr_s,
                      route->nexthop);

        ovn_lflow_add_with_hint__(lflows, od, S_ROUTER_IN_ARP_REQUEST, 200,
                                  ds_cstr(match), ds_cstr(actions), NULL,
                                  copp_meter_get(COPP_ND_NS_RESOLVE,
                                                 od->nbr->copp,
                                                 meter_groups),
                                  &route->header_,
                                  lflow_ref);
    }

    ovn_lflow_metered(lflows, od, S_ROUTER_IN_ARP_REQUEST, 100,
                      "eth.dst == 00:00:00:00:00:00 && ip4",
                      "arp { "
                      "eth.dst = ff:ff:ff:ff:ff:ff; "
                      "arp.spa = " REG_SRC_IPV4 "; "
                      "arp.tpa = " REG_NEXT_HOP_IPV4 "; "
                      "arp.op = 1; " /* ARP request */
                      "output; "
                      "}; output;",
                      copp_meter_get(COPP_ARP_RESOLVE, od->nbr->copp,
                                     meter_groups),
                      lflow_ref);
    ovn_lflow_metered(lflows, od, S_ROUTER_IN_ARP_REQUEST, 100,
                      "eth.dst == 00:00:00:00:00:00 && ip6",
                      "nd_ns { "
                      "nd.target = " REG_NEXT_HOP_IPV6 "; "
                      "output; "
                      "}; output;",
                      copp_meter_get(COPP_ND_NS_RESOLVE, od->nbr->copp,
                                     meter_groups),
                      lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_ARP_REQUEST, 0, "1", "output;",
                  lflow_ref);
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
        struct ovn_port *op, struct lflow_table *lflows,
        struct ds *match, struct ds *actions,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(op->nbrp);
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
                      ds_cstr(match), ds_cstr(actions),
                      lflow_ref);
    }

    ds_clear(match);
    ds_put_format(match, "outport == %s", op->json_key);
    ovn_lflow_add(lflows, op->od, S_ROUTER_OUT_DELIVERY, 100,
                  ds_cstr(match), "output;", lflow_ref);
}

static void
build_misc_local_traffic_drop_flows_for_lrouter(
        struct ovn_datapath *od, struct lflow_table *lflows,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);
    /* Allow IGMP and MLD packets (with TTL = 1) if the router is
     * configured to flood them statically on some ports.
     */
    if (od->mcast_info.rtr.flood_static) {
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 120,
                      "igmp && ip.ttl == 1", "next;",
                      lflow_ref);
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 120,
                      "(mldv1 || mldv2) && ip.ttl == 1", "next;",
                      lflow_ref);
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
                  debug_drop_action(),
                  lflow_ref);

    /* Drop ARP packets (priority 85). ARP request packets for router's own
     * IPs are handled with priority-90 flows.
     * Drop IPv6 ND packets (priority 85). ND NA packets for router's own
     * IPs are handled with priority-90 flows.
     */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 85,
                  "arp || nd", debug_drop_action(),
                  lflow_ref);

    /* Allow IPv6 multicast traffic that's supposed to reach the
     * router pipeline (e.g., router solicitations).
     */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 84, "nd_rs || nd_ra",
                  "next;", lflow_ref);

    /* Drop other reserved multicast. */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 83,
                  "ip6.mcast_rsvd", debug_drop_action(),
                  lflow_ref);

    /* Allow other multicast if relay enabled (priority 82). */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 82,
                  "ip4.mcast || ip6.mcast",
                  (od->mcast_info.rtr.relay ? "next;" :
                                              debug_drop_action()),
                  lflow_ref);

    /* Drop Ethernet local broadcast.  By definition this traffic should
     * not be forwarded.*/
    ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 50,
                  "eth.bcast", debug_drop_action(),
                  lflow_ref);

    /* Avoid ICMP time exceeded for multicast, silent drop instead.
     * See RFC1812 section 5.3.1:
     *  If the TTL is reduced to zero (or less), the packet MUST be discarded,
     *  and if the destination is NOT A MULTICAST address the router MUST send
     *  an ICMP Time Exceeded message ...
     *
     * The reason behind is that TTL has special meanings for multicast. For
     * example, TTL = 1 means restricted to the same subnet, not forwarded by
     * the router. So it is very common to see multicast packets with ttl = 1,
     * and generating ICMP for such packets is harmful from both slowpath
     * performance and functionality point of view.
     *
     * (priority-31 flows will send ICMP time exceeded) */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 32,
                  "ip.ttl == {0, 1} && !ip.later_frag && "
                  "(ip4.mcast || ip6.mcast)", debug_drop_action(),
                  lflow_ref);

    /* TTL discard */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 30,
                  "ip.ttl == {0, 1}", debug_drop_action(),
                  lflow_ref);

    /* Pass other traffic not already handled to the next table for
     * routing. */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 0, "1", "next;",
                  lflow_ref);
}

static void
build_dhcpv6_reply_flows_for_lrouter_port(
        struct ovn_port *op, struct lflow_table *lflows,
        struct ds *match,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(op->nbrp);
    if (op->l3dgw_port) {
        return;
    }
    for (size_t i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
        ds_clear(match);
        ds_put_format(match, "ip6.dst == %s && udp.src == 547 &&"
                      " udp.dst == 546",
                      op->lrp_networks.ipv6_addrs[i].addr_s);
        ovn_lflow_add(lflows, op->od, S_ROUTER_IN_IP_INPUT, 100,
                      ds_cstr(match),
                      "reg0 = 0; handle_dhcpv6_reply;",
                      lflow_ref);
    }
}

static void
build_dhcp_relay_flows_for_lrouter_port(struct ovn_port *op,
                                        struct lflow_table *lflows,
                                        struct ds *match, struct ds *actions,
                                        struct lflow_ref *lflow_ref)
{
    if (!op->nbrp || !op->nbrp->dhcp_relay) {
        return;

    }

    /* configure dhcp relay flows only when peer switch has
     * relay config enabled */
    struct ovn_port *sp = op->peer;
    if (!sp || !sp->nbsp || sp->peer != op ||
        !sp->od || !ls_dhcp_relay_port(sp->od)) {
        return;
    }

    struct nbrec_dhcp_relay *dhcp_relay = op->nbrp->dhcp_relay;
    if (!dhcp_relay->servers) {
        return;
    }

    int addr_family;
    /* currently not supporting custom port,
     * dhcp server port is always set to 67 when installing flows */
    uint16_t port;
    char *server_ip_str = NULL;
    struct in6_addr server_ip;

    if (!ip_address_and_port_from_lb_key(dhcp_relay->servers, &server_ip_str,
                                         &server_ip, &port, &addr_family)) {
        return;
    }

    if (server_ip_str == NULL) {
        return;
    }

    ds_clear(match);
    ds_clear(actions);

    ds_put_format(
        match, "inport == %s && "
        "ip4.src == 0.0.0.0 && ip4.dst == 255.255.255.255 && "
        "ip.frag == 0 && udp.src == 68 && udp.dst == 67",
        op->json_key);
    ds_put_format(actions,
                  REGBIT_DHCP_RELAY_REQ_CHK
                  " = dhcp_relay_req_chk(%s, %s);"
                  "next; /* DHCP_RELAY_REQ */",
                  op->lrp_networks.ipv4_addrs[0].addr_s, server_ip_str);

    ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT, 110,
                            ds_cstr(match), ds_cstr(actions),
                            &op->nbrp->header_, lflow_ref);

    ds_clear(match);
    ds_clear(actions);

    ds_put_format(
        match, "inport == %s && "
        "ip4.src == 0.0.0.0 && ip4.dst == 255.255.255.255 && "
        "udp.src == 68 && udp.dst == 67 && "
        REGBIT_DHCP_RELAY_REQ_CHK,
        op->json_key);
    ds_put_format(actions,
                  "ip4.src = %s; ip4.dst = %s; udp.src = 67; next; "
                  "/* DHCP_RELAY_REQ */",
                  op->lrp_networks.ipv4_addrs[0].addr_s, server_ip_str);

    ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_DHCP_RELAY_REQ, 100,
                            ds_cstr(match), ds_cstr(actions),
                            &op->nbrp->header_, lflow_ref);

    ds_clear(match);
    ds_clear(actions);

    ds_put_format(
        match, "inport == %s && "
        "ip4.src == 0.0.0.0 && ip4.dst == 255.255.255.255 && "
        "udp.src == 68 && udp.dst == 67 && "
        REGBIT_DHCP_RELAY_REQ_CHK" == 0",
        op->json_key);
    ds_put_format(actions, "drop; /* DHCP_RELAY_REQ */");

    ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_DHCP_RELAY_REQ, 1,
                            ds_cstr(match), ds_cstr(actions),
                            &op->nbrp->header_, lflow_ref);

    ds_clear(match);
    ds_clear(actions);

    ds_put_format(
        match, "ip4.src == %s && ip4.dst == %s && "
        "ip.frag == 0 && udp.src == 67 && udp.dst == 67",
        server_ip_str, op->lrp_networks.ipv4_addrs[0].addr_s);
    ds_put_format(actions, "next; /* DHCP_RELAY_RESP */");
    ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT, 110,
                            ds_cstr(match), ds_cstr(actions),
                            &op->nbrp->header_, lflow_ref);

    ds_clear(match);
    ds_clear(actions);

    ds_put_format(
        match, "ip4.src == %s && ip4.dst == %s && "
        "udp.src == 67 && udp.dst == 67",
        server_ip_str, op->lrp_networks.ipv4_addrs[0].addr_s);
    ds_put_format(actions,
          REG_DHCP_RELAY_DIP_IPV4" = ip4.dst; "
          REGBIT_DHCP_RELAY_RESP_CHK
          " = dhcp_relay_resp_chk(%s, %s); next; /* DHCP_RELAY_RESP */",
          op->lrp_networks.ipv4_addrs[0].addr_s, server_ip_str);

    ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_DHCP_RELAY_RESP_CHK,
                            100,
                            ds_cstr(match), ds_cstr(actions),
                            &op->nbrp->header_, lflow_ref);


    ds_clear(match);
    ds_clear(actions);

    ds_put_format(
        match, "ip4.src == %s && "
        REG_DHCP_RELAY_DIP_IPV4" == %s && "
        "udp.src == 67 && udp.dst == 67 && "
        REGBIT_DHCP_RELAY_RESP_CHK,
        server_ip_str, op->lrp_networks.ipv4_addrs[0].addr_s);
    ds_put_format(actions,
                  "ip4.src = %s; udp.dst = 68; "
                  "outport = %s; output; /* DHCP_RELAY_RESP */",
                  op->lrp_networks.ipv4_addrs[0].addr_s, op->json_key);
    ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_DHCP_RELAY_RESP,
                            100, ds_cstr(match), ds_cstr(actions),
                            &op->nbrp->header_, lflow_ref);

    ds_clear(match);
    ds_clear(actions);

    ds_put_format(match, "ip4.src == %s && "
                  REG_DHCP_RELAY_DIP_IPV4" == %s && "
                  "udp.src == 67 && udp.dst == 67 && "
                  REGBIT_DHCP_RELAY_RESP_CHK" == 0",
                  server_ip_str, op->lrp_networks.ipv4_addrs[0].addr_s);
    ds_put_format(actions, "drop; /* DHCP_RELAY_RESP */");
    ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_DHCP_RELAY_RESP,
                            1, ds_cstr(match), ds_cstr(actions),
                            &op->nbrp->header_, lflow_ref);
    ds_clear(match);
    ds_clear(actions);
    free(server_ip_str);
}

static void
build_ipv6_input_flows_for_lrouter_port(
        struct ovn_port *op, struct lflow_table *lflows,
        struct ds *match, struct ds *actions,
        const struct shash *meter_groups,
        struct lflow_ref *lflow_ref)
{
    ovs_assert(op->nbrp);
    if (is_cr_port(op)) {
        return;
    }
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
                                &op->nbrp->header_, lflow_ref);
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
                              &op->nbrp->header_, lflows, meter_groups,
                              lflow_ref);
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
                                      &op->nbrp->header_,
                                      lflow_ref);

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
                                      &op->nbrp->header_,
                                      lflow_ref);

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
                                      &op->nbrp->header_,
                                      lflow_ref);

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
                                      &op->nbrp->header_,
                                      lflow_ref);
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
                31, ds_cstr(match), ds_cstr(actions), NULL,
                copp_meter_get(COPP_ICMP6_ERR, op->od->nbr->copp,
                               meter_groups),
                &op->nbrp->header_, lflow_ref);
    }
    ds_destroy(&ip_ds);
}

static void
build_lrouter_arp_nd_for_datapath(const struct ovn_datapath *od,
                                  const struct lr_nat_record *lrnat_rec,
                                  struct lflow_table *lflows,
                                  const struct shash *meter_groups,
                                  struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);
    if (!od->nbr->n_nat) {
        return;
    }

    /* Priority-90-92 flows handle ARP requests and ND packets. Most are
     * per logical port but DNAT addresses can be handled per datapath
     * for non gateway router ports.
     *
     * Priority 91 and 92 flows are added for each gateway router
     * port to handle the special cases. In case we get the packet
     * on a regular port, just reply with the port's ETH address.
     */
    for (size_t i = 0; i < lrnat_rec->n_nat_entries; i++) {
        struct ovn_nat *nat_entry = &lrnat_rec->nat_entries[i];

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
        build_lrouter_nat_arp_nd_flow(od, nat_entry, lflows, meter_groups,
                                      lflow_ref);
    }

    /* Now handle SNAT entries too, one per unique SNAT IP. */
    struct shash_node *snat_snode;
    SHASH_FOR_EACH (snat_snode, &lrnat_rec->snat_ips) {
        struct ovn_snat_ip *snat_ip = snat_snode->data;

        if (ovs_list_is_empty(&snat_ip->snat_entries)) {
            continue;
        }

        struct ovn_nat *nat_entry =
            CONTAINER_OF(ovs_list_front(&snat_ip->snat_entries),
                         struct ovn_nat, ext_addr_list_node);
        build_lrouter_nat_arp_nd_flow(od, nat_entry, lflows, meter_groups,
                                      lflow_ref);
    }
}

/* Logical router ingress table 3: IP Input for IPv4. */
static void
build_lrouter_ipv4_ip_input(struct ovn_port *op,
                            struct lflow_table *lflows,
                            struct ds *match, struct ds *actions,
                            const struct shash *meter_groups,
                            struct lflow_ref *lflow_ref)
{
    ovs_assert(op->nbrp);
    /* No ingress packets are accepted on a chassisredirect
     * port, so no need to program flows for that port. */
    if (is_cr_port(op)) {
        return;
    }
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
                                &op->nbrp->header_, lflow_ref);

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
                                &op->nbrp->header_, lflow_ref);
    }

    /* BFD msg handling */
    build_lrouter_bfd_flows(lflows, op, meter_groups, lflow_ref);

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
                31, ds_cstr(match), ds_cstr(actions), NULL,
                copp_meter_get(COPP_ICMP4_ERR, op->od->nbr->copp,
                               meter_groups),
                &op->nbrp->header_, lflow_ref);

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
                               &op->nbrp->header_, lflows, lflow_ref);
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
                                      &op->nbrp->header_,
                                      lflow_ref);

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
                                      &op->nbrp->header_,
                                      lflow_ref);

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
                                      &op->nbrp->header_,
                                      lflow_ref);

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
                                      &op->nbrp->header_,
                                      lflow_ref);
        }
    }
}

/* Logical router ingress table 3: IP Input for IPv4. */
static void
build_lrouter_ipv4_ip_input_for_lbnats(
    struct ovn_port *op, struct lflow_table *lflows,
    const struct lr_stateful_record *lr_stateful_rec,
    struct ds *match, const struct shash *meter_groups,
    struct lflow_ref *lflow_ref)
{
    ovs_assert(op->nbrp);
    /* No ingress packets are accepted on a chassisredirect
     * port, so no need to program flows for that port. */
    if (is_cr_port(op)) {
        return;
    }

    if (sset_count(&lr_stateful_rec->lb_ips->ips_v4_reachable)) {
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
                               match, false, 90, NULL, lflows, lflow_ref);
        free(lb_ips_v4_as);
    }

    if (sset_count(&lr_stateful_rec->lb_ips->ips_v6_reachable)) {
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
                              NULL, lflows, meter_groups, lflow_ref);
        free(lb_ips_v6_as);
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

    for (size_t i = 0; i < lr_stateful_rec->lrnat_rec->n_nat_entries; i++) {
        struct ovn_nat *nat_entry =
            &lr_stateful_rec->lrnat_rec->nat_entries[i];

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
                                        meter_groups, lflow_ref);
    }

    /* Now handle SNAT entries too, one per unique SNAT IP. */
    struct shash_node *snat_snode;
    SHASH_FOR_EACH (snat_snode, &lr_stateful_rec->lrnat_rec->snat_ips) {
        struct ovn_snat_ip *snat_ip = snat_snode->data;

        if (ovs_list_is_empty(&snat_ip->snat_entries)) {
            continue;
        }

        struct ovn_nat *nat_entry =
            CONTAINER_OF(ovs_list_front(&snat_ip->snat_entries),
                        struct ovn_nat, ext_addr_list_node);
        build_lrouter_port_nat_arp_nd_flow(op, nat_entry, lflows,
                                        meter_groups, lflow_ref);
    }
}

static void
build_lrouter_in_unsnat_match(const struct ovn_datapath *od,
                              const struct nbrec_nat *nat, struct ds *match,
                              bool distributed_nat, bool is_v6,
                              struct ovn_port *l3dgw_port)
{
    ds_clear(match);

    ds_put_format(match, "ip && ip%c.dst == %s",
                  is_v6 ? '6' : '4', nat->external_ip);

    if (!od->is_gw_router) {
        /* Distributed router. */

        /* Traffic received on l3dgw_port is subject to NAT. */
        ds_put_format(match, " && inport == %s", l3dgw_port->json_key);

        if (!distributed_nat && od->n_l3dgw_ports) {
            /* Flows for NAT rules that are centralized are only
             * programmed on the gateway chassis. */
            ds_put_format(match, " && is_chassis_resident(%s)",
                          l3dgw_port->cr_port->json_key);
        }
    }
}

static void
build_lrouter_in_unsnat_stateless_flow(struct lflow_table *lflows,
                                       const struct ovn_datapath *od,
                                       const struct nbrec_nat *nat,
                                       struct ds *match,
                                       bool distributed_nat, bool is_v6,
                                       struct ovn_port *l3dgw_port,
                                       struct lflow_ref *lflow_ref)
{
    if (strcmp(nat->type, "snat") && strcmp(nat->type, "dnat_and_snat")) {
        return;
    }

    uint16_t priority = od->is_gw_router ? 90 : 100;

    build_lrouter_in_unsnat_match(od, nat, match, distributed_nat, is_v6,
                                  l3dgw_port);

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_UNSNAT,
                            priority, ds_cstr(match), "next;",
                            &nat->header_, lflow_ref);
}

static void
build_lrouter_in_unsnat_in_czone_flow(struct lflow_table *lflows,
                                      const struct ovn_datapath *od,
                                      const struct nbrec_nat *nat,
                                      struct ds *match, bool distributed_nat,
                                      bool is_v6, struct ovn_port *l3dgw_port,
                                      struct lflow_ref *lflow_ref)
{
    if (strcmp(nat->type, "snat") && strcmp(nat->type, "dnat_and_snat")) {
        return;
    }

    build_lrouter_in_unsnat_match(od, nat, match, distributed_nat, is_v6,
                                  l3dgw_port);

    /* We're adding two flows: one matching on "M1 && flags.loopback == 0" and
     * the second one matching on "M1 && flags.loopback == 1 && M2".
     * Reuse the common part of the match string.
     */
    size_t common_match_len = match->length;

    ds_put_cstr(match, " && flags.loopback == 0");
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_UNSNAT,
                            100, ds_cstr(match), "ct_snat_in_czone;",
                            &nat->header_, lflow_ref);

    ds_truncate(match, common_match_len);
    /* Update common zone match for the hairpin traffic. */
    ds_put_cstr(match, " && flags.loopback == 1 && flags.use_snat_zone == 1");

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_UNSNAT,
                            100, ds_cstr(match), "ct_snat;",
                            &nat->header_, lflow_ref);
}

static void
build_lrouter_in_unsnat_flow(struct lflow_table *lflows,
                             const struct ovn_datapath *od,
                             const struct nbrec_nat *nat, struct ds *match,
                             bool distributed_nat, bool is_v6,
                             struct ovn_port *l3dgw_port,
                             struct lflow_ref *lflow_ref)
{

    if (strcmp(nat->type, "snat") && strcmp(nat->type, "dnat_and_snat")) {
        return;
    }

    uint16_t priority = od->is_gw_router ? 90 : 100;

    build_lrouter_in_unsnat_match(od, nat, match, distributed_nat, is_v6,
                                  l3dgw_port);

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_UNSNAT,
                            priority, ds_cstr(match), "ct_snat;",
                            &nat->header_, lflow_ref);
}

static void
build_lrouter_in_dnat_flow(struct lflow_table *lflows,
                           const struct ovn_datapath *od,
                           const struct lr_nat_record *lrnat_rec,
                           const struct nbrec_nat *nat, struct ds *match,
                           struct ds *actions, bool distributed_nat,
                           int cidr_bits, bool is_v6,
                           struct ovn_port *l3dgw_port, bool stateless,
                           struct lflow_ref *lflow_ref)
{
    /* Ingress DNAT table: Packets enter the pipeline with destination
    * IP address that needs to be DNATted from a external IP address
    * to a logical IP address. */
    if (strcmp(nat->type, "dnat") && strcmp(nat->type, "dnat_and_snat")) {
        return;
    }

    ds_clear(match);
    ds_clear(actions);

    const char *nat_action = lrouter_use_common_zone(od)
                             ? "ct_dnat_in_czone"
                             : "ct_dnat";

    ds_put_format(match, "ip && ip%c.dst == %s", is_v6 ? '6' : '4',
                  nat->external_ip);

    if (od->is_gw_router) {
        if (!lport_addresses_is_empty(&lrnat_rec->dnat_force_snat_addrs)) {
            /* Indicate to the future tables that a DNAT has taken
             * place and a force SNAT needs to be done in the
             * Egress SNAT table. */
            ds_put_cstr(actions, "flags.force_snat_for_dnat = 1; ");
        }

        /* Packet when it goes from the initiator to destination.
        * We need to set flags.loopback because the router can
        * send the packet back through the same interface. */
        ds_put_cstr(actions, "flags.loopback = 1; ");
    } else {
        /* Distributed router. */

        /* Traffic received on l3dgw_port is subject to NAT. */
        ds_put_format(match, " && inport == %s", l3dgw_port->json_key);
        if (!distributed_nat && od->n_l3dgw_ports) {
            /* Flows for NAT rules that are centralized are only
            * programmed on the gateway chassis. */
            ds_put_format(match, " && is_chassis_resident(%s)",
                          l3dgw_port->cr_port->json_key);
        }
    }

    if (nat->allowed_ext_ips || nat->exempted_ext_ips) {
        lrouter_nat_add_ext_ip_match(od, lflows, match, nat,
                                     is_v6, true, cidr_bits,
                                     lflow_ref);
    }

    if (stateless) {
        ds_put_format(actions, "ip%c.dst=%s; next;",
                      is_v6 ? '6' : '4', nat->logical_ip);
    } else {
        ds_put_format(actions, "%s(%s", nat_action, nat->logical_ip);
        if (nat->external_port_range[0]) {
            ds_put_format(actions, ",%s", nat->external_port_range);
        }
        ds_put_format(actions, ");");
    }

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DNAT, 100,
                            ds_cstr(match), ds_cstr(actions),
                            &nat->header_, lflow_ref);
}

static void
build_lrouter_out_undnat_flow(struct lflow_table *lflows,
                              const struct ovn_datapath *od,
                              const struct nbrec_nat *nat, struct ds *match,
                              struct ds *actions, bool distributed_nat,
                              struct eth_addr mac, bool is_v6,
                              struct ovn_port *l3dgw_port, bool stateless,
                              struct lflow_ref *lflow_ref)
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
    ds_clear(actions);

    ds_put_format(match, "ip && ip%c.src == %s && outport == %s",
                  is_v6 ? '6' : '4', nat->logical_ip,
                  l3dgw_port->json_key);
    if (!distributed_nat && od->n_l3dgw_ports) {
        /* Flows for NAT rules that are centralized are only
        * programmed on the gateway chassis. */
        ds_put_format(match, " && is_chassis_resident(%s)",
                      l3dgw_port->cr_port->json_key);
    }

    if (distributed_nat) {
        ds_put_format(actions, "eth.src = "ETH_ADDR_FMT"; ",
                      ETH_ADDR_ARGS(mac));
    }

    if (stateless) {
        ds_put_format(actions, "next;");
    } else {
        ds_put_cstr(actions, lrouter_use_common_zone(od)
                    ? "ct_dnat_in_czone;"
                    : "ct_dnat;");
    }

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_UNDNAT, 100,
                            ds_cstr(match), ds_cstr(actions),
                            &nat->header_, lflow_ref);
}

static void
build_lrouter_out_is_dnat_local(struct lflow_table *lflows,
                                const struct ovn_datapath *od,
                                const struct nbrec_nat *nat, struct ds *match,
                                struct ds *actions, bool distributed_nat,
                                bool is_v6, struct ovn_port *l3dgw_port,
                                struct lflow_ref *lflow_ref)
{
    /* Note that this only applies for NAT on a distributed router.
     */
    if (!od->n_l3dgw_ports) {
        return;
    }

    ds_clear(match);
    ds_put_format(match, "ip && ip%s.dst == %s && ",
                  is_v6 ? "6" : "4", nat->external_ip);
    if (distributed_nat) {
        ds_put_format(match, "is_chassis_resident(\"%s\")", nat->logical_port);
    } else {
        ds_put_format(match, "is_chassis_resident(%s)",
                      l3dgw_port->cr_port->json_key);
    }

    ds_clear(actions);
    ds_put_cstr(actions, REGBIT_DST_NAT_IP_LOCAL" = 1; next;");

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_CHECK_DNAT_LOCAL,
                            50, ds_cstr(match), ds_cstr(actions),
                            &nat->header_, lflow_ref);
}

static void
build_lrouter_out_snat_match(struct lflow_table *lflows,
                             const struct ovn_datapath *od,
                             const struct nbrec_nat *nat,
                             struct ds *match,
                             bool distributed_nat, int cidr_bits,
                             bool is_v6,
                             struct ovn_port *l3dgw_port,
                             struct lflow_ref *lflow_ref,
                             bool is_reverse)
{
    ds_clear(match);

    ds_put_format(match, "ip && ip%c.%s == %s",
                  is_v6 ? '6' : '4',
                  is_reverse ? "dst" : "src",
                  nat->logical_ip);

    if (!od->is_gw_router) {
        /* Distributed router. */
        ds_put_format(match, " && %s == %s",
                      is_reverse ? "inport" : "outport",
                      l3dgw_port->json_key);
        if (od->n_l3dgw_ports) {
            ds_put_format(match, " && is_chassis_resident(\"%s\")",
                          distributed_nat
                          ? nat->logical_port
                          : l3dgw_port->cr_port->key);
        }
    }

    if (nat->allowed_ext_ips || nat->exempted_ext_ips) {
        lrouter_nat_add_ext_ip_match(od, lflows, match, nat,
                                     is_v6, is_reverse, cidr_bits,
                                     lflow_ref);
    }
}

static void
build_lrouter_out_snat_stateless_flow(struct lflow_table *lflows,
                                      const struct ovn_datapath *od,
                                      const struct nbrec_nat *nat,
                                      struct ds *match, struct ds *actions,
                                      bool distributed_nat,
                                      struct eth_addr mac, int cidr_bits,
                                      bool is_v6, struct ovn_port *l3dgw_port,
                                      struct lflow_ref *lflow_ref)
{
    if (strcmp(nat->type, "snat") && strcmp(nat->type, "dnat_and_snat")) {
        return;
    }

    ds_clear(actions);

    /* The priority here is calculated such that the
     * nat->logical_ip with the longest mask gets a higher
     * priority. */
    uint16_t priority = cidr_bits + 1;

    build_lrouter_out_snat_match(lflows, od, nat, match, distributed_nat,
                                 cidr_bits, is_v6, l3dgw_port, lflow_ref,
                                 false);

    if (!od->is_gw_router) {
        /* Distributed router. */
        if (od->n_l3dgw_ports) {
            priority += 128;
        }

        if (distributed_nat) {
            ds_put_format(actions, "eth.src = "ETH_ADDR_FMT"; ",
                          ETH_ADDR_ARGS(mac));
        }
    }

    ds_put_format(actions, "ip%c.src=%s; next;",
                  is_v6 ? '6' : '4', nat->external_ip);

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_SNAT,
                            priority, ds_cstr(match),
                            ds_cstr(actions), &nat->header_,
                            lflow_ref);
}

static void
build_lrouter_out_snat_in_czone_flow(struct lflow_table *lflows,
                                     const struct ovn_datapath *od,
                                     const struct nbrec_nat *nat,
                                     struct ds *match,
                                     struct ds *actions, bool distributed_nat,
                                     struct eth_addr mac, int cidr_bits,
                                     bool is_v6, struct ovn_port *l3dgw_port,
                                     struct lflow_ref *lflow_ref)
{
    if (strcmp(nat->type, "snat") && strcmp(nat->type, "dnat_and_snat")) {
        return;
    }

    ds_clear(actions);

    /* The priority here is calculated such that the
     * nat->logical_ip with the longest mask gets a higher
     * priority. */
    uint16_t priority = cidr_bits + 1;
    struct ds zone_actions = DS_EMPTY_INITIALIZER;

    build_lrouter_out_snat_match(lflows, od, nat, match, distributed_nat,
                                 cidr_bits, is_v6, l3dgw_port,
                                 lflow_ref, false);

    if (od->n_l3dgw_ports) {
        priority += 128;
    }

    if (distributed_nat) {
        ds_put_format(actions, "eth.src = "ETH_ADDR_FMT"; ",
                      ETH_ADDR_ARGS(mac));
        ds_put_format(&zone_actions, "eth.src = "ETH_ADDR_FMT"; ",
                      ETH_ADDR_ARGS(mac));
    }
    ds_put_format(match, " && (!ct.trk || !ct.rpl)");

    ds_put_cstr(&zone_actions, REGBIT_DST_NAT_IP_LOCAL" = 0; ");

    ds_put_format(actions, "ct_snat_in_czone(%s", nat->external_ip);
    ds_put_format(&zone_actions, "ct_snat(%s", nat->external_ip);

    if (nat->external_port_range[0]) {
        ds_put_format(actions, ",%s", nat->external_port_range);
        ds_put_format(&zone_actions, ",%s", nat->external_port_range);
    }

    ds_put_cstr(actions, ");");
    ds_put_cstr(&zone_actions, ");");

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_SNAT,
                            priority, ds_cstr(match),
                            ds_cstr(actions), &nat->header_,
                            lflow_ref);

    ds_put_cstr(match, " && "REGBIT_DST_NAT_IP_LOCAL" == 1");

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_SNAT,
                            priority + 1, ds_cstr(match),
                            ds_cstr(&zone_actions), &nat->header_,
                            lflow_ref);

    ds_destroy(&zone_actions);
}

static void
build_lrouter_out_snat_flow(struct lflow_table *lflows,
                            const struct ovn_datapath *od,
                            const struct nbrec_nat *nat, struct ds *match,
                            struct ds *actions, bool distributed_nat,
                            struct eth_addr mac, int cidr_bits, bool is_v6,
                            struct ovn_port *l3dgw_port,
                            struct lflow_ref *lflow_ref,
                            const struct chassis_features *features)
{
    if (strcmp(nat->type, "snat") && strcmp(nat->type, "dnat_and_snat")) {
        return;
    }

    ds_clear(actions);

    /* The priority here is calculated such that the
     * nat->logical_ip with the longest mask gets a higher
     * priority. */
    uint16_t priority = cidr_bits + 1;

    build_lrouter_out_snat_match(lflows, od, nat, match, distributed_nat,
                                 cidr_bits, is_v6, l3dgw_port, lflow_ref,
                                 false);
    size_t original_match_len = match->length;

    if (!od->is_gw_router) {
        /* Distributed router. */
        if (od->n_l3dgw_ports) {
            priority += 128;
        }

        if (distributed_nat) {
            ds_put_format(actions, "eth.src = "ETH_ADDR_FMT"; ",
                          ETH_ADDR_ARGS(mac));
        }
    }
    ds_put_cstr(match, " && (!ct.trk || !ct.rpl)");

    ds_put_format(actions, "ct_snat(%s", nat->external_ip);
    if (nat->external_port_range[0]) {
        ds_put_format(actions, ",%s", nat->external_port_range);
    }
    ds_put_format(actions, ");");

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_SNAT,
                            priority, ds_cstr(match),
                            ds_cstr(actions), &nat->header_,
                            lflow_ref);

    /* For the SNAT networks, we need to make sure that connections are
     * properly tracked so we can decide whether to perform SNAT on traffic
     * exiting the network. */
    if (features->ct_commit_to_zone && !strcmp(nat->type, "snat") &&
        !od->is_gw_router) {
        /* For traffic that comes from SNAT network, initiate CT state before
         * entering S_ROUTER_OUT_SNAT to allow matching on various CT states.
         */
        ds_truncate(match, original_match_len);
        ovn_lflow_add(lflows, od, S_ROUTER_OUT_POST_UNDNAT, 70,
                      ds_cstr(match), "ct_snat;",
                      lflow_ref);

        build_lrouter_out_snat_match(lflows, od, nat, match,
                                     distributed_nat, cidr_bits, is_v6,
                                     l3dgw_port, lflow_ref, true);

        /* New traffic that goes into SNAT network is committed to CT to avoid
         * SNAT-ing replies.*/
        ovn_lflow_add(lflows, od, S_ROUTER_OUT_SNAT, priority,
                      ds_cstr(match), "ct_snat;",
                      lflow_ref);

        ds_put_cstr(match, " && ct.new");
        ovn_lflow_add(lflows, od, S_ROUTER_OUT_POST_SNAT, priority,
                      ds_cstr(match), "ct_commit_to_zone(snat);",
                      lflow_ref);
    }
}

static void
build_lrouter_ingress_nat_check_pkt_len(struct lflow_table *lflows,
                                        const struct nbrec_nat *nat,
                                        const struct ovn_datapath *od,
                                        bool is_v6, struct ds *match,
                                        struct ds *actions, int mtu,
                                        struct ovn_port *l3dgw_port,
                                        const struct shash *meter_groups,
                                        struct lflow_ref *lflow_ref)
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
                                      &nat->header_,
                                      lflow_ref);
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
                                      &nat->header_,
                                      lflow_ref);
        }
}

static void
build_lrouter_ingress_flow(struct lflow_table *lflows,
                           const struct ovn_datapath *od,
                           const struct nbrec_nat *nat, struct ds *match,
                           struct ds *actions, struct eth_addr mac,
                           bool distributed_nat, bool is_v6,
                           struct ovn_port *l3dgw_port,
                           const struct shash *meter_groups,
                           struct lflow_ref *lflow_ref)
{
    if (od->n_l3dgw_ports && !strcmp(nat->type, "snat")) {
        ds_clear(match);
        ds_put_format(
            match, "inport == %s && %s == %s",
            l3dgw_port->json_key,
            is_v6 ? "ip6.src" : "ip4.src", nat->external_ip);
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_IP_INPUT,
                                120, ds_cstr(match), "next;",
                                &nat->header_, lflow_ref);
    }
    /* Logical router ingress table 0:
    * For NAT on a distributed router, add rules allowing
    * ingress traffic with eth.dst matching nat->external_mac
    * on the l3dgw_port instance where nat->logical_port is
    * resident. */
    if (distributed_nat) {
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
                               lflow_ref,
                               REG_INPORT_ETH_ADDR " = %s; next;",
                               l3dgw_port->lrp_networks.ea_s);
        if (gw_mtu) {
            build_lrouter_ingress_nat_check_pkt_len(lflows, nat, od, is_v6,
                                                    match, actions, gw_mtu,
                                                    l3dgw_port, meter_groups,
                                                    lflow_ref);
        }
    }
}

static int
lrouter_check_nat_entry(const struct ovn_datapath *od,
                        const struct nbrec_nat *nat,
                        const struct hmap *lr_ports, ovs_be32 *mask,
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
        *nat_l3dgw_port = ovn_port_find(lr_ports, nat->gateway_port->name);

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
static void build_lr_nat_defrag_and_lb_default_flows(
    struct ovn_datapath *od, struct lflow_table *lflows,
    struct lflow_ref *lflow_ref)
{
    ovs_assert(od->nbr);

    /* Packets are allowed by default. */
    ovn_lflow_add(lflows, od, S_ROUTER_IN_DEFRAG, 0, "1", "next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_UNSNAT, 0, "1", "next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_CHECK_DNAT_LOCAL, 0, "1",
                  REGBIT_DST_NAT_IP_LOCAL" = 0; next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_SNAT, 0, "1", "next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT, 0, "1", "next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_UNDNAT, 0, "1", "next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_POST_UNDNAT, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_POST_SNAT, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_EGR_LOOP, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_ECMP_STATEFUL, 0, "1", "next;",
                  lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_DHCP_RELAY_REQ, 0, "1",
                  "next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_DHCP_RELAY_RESP_CHK, 0, "1",
                  "next;", lflow_ref);
    ovn_lflow_add(lflows, od, S_ROUTER_IN_DHCP_RELAY_RESP, 0, "1",
                  "next;", lflow_ref);


    /* Send the IPv6 NS packets to next table. When ovn-controller
     * generates IPv6 NS (for the action - nd_ns{}), the injected
     * packet would go through conntrack - which is not required. */
    ovn_lflow_add(lflows, od, S_ROUTER_OUT_SNAT, 120, "nd_ns", "next;",
                  lflow_ref);
}

static void
build_lrouter_nat_defrag_and_lb(
    const struct lr_stateful_record *lr_stateful_rec,
    const struct ovn_datapath *od, struct lflow_table *lflows,
    const struct hmap *ls_ports, const struct hmap *lr_ports,
    struct ds *match, struct ds *actions,
    const struct shash *meter_groups,
    const struct chassis_features *features,
    struct lflow_ref *lflow_ref)
{
    const char *ct_flag_reg = features->ct_no_masked_label
                              ? "ct_mark"
                              : "ct_label";
    /* Ingress DNAT (Priority 50/70).
     *
     * Allow traffic that is related to an existing conntrack entry.
     * At the same time apply NAT for this traffic.
     *
     * NOTE: This does not support related data sessions (eg,
     * a dynamically negotiated FTP data channel), but will allow
     * related traffic such as an ICMP Port Unreachable through
     * that's generated from a non-listening UDP port.  */
    if (lr_stateful_rec->has_lb_vip && features->ct_lb_related) {
        ds_clear(match);

        ds_put_cstr(match, "ct.rel && !ct.est && !ct.new");
        size_t match_len = match->length;

        ds_put_format(match, " && %s.skip_snat == 1", ct_flag_reg);
        ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT, 70, ds_cstr(match),
                      "flags.skip_snat_for_lb = 1; ct_commit_nat;",
                      lflow_ref);

        ds_truncate(match, match_len);
        ds_put_format(match, " && %s.force_snat == 1", ct_flag_reg);
        ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT, 70, ds_cstr(match),
                      "flags.force_snat_for_lb = 1; ct_commit_nat;",
                      lflow_ref);

        ds_truncate(match, match_len);
        ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT, 50, ds_cstr(match),
                      "ct_commit_nat;", lflow_ref);
    }

    /* Ingress DNAT (Priority 50/70).
     *
     * Pass the traffic that is already established to the next table with
     * proper flags set.
     */
    if (lr_stateful_rec->has_lb_vip) {
        ds_clear(match);

        ds_put_format(match, "ct.est && !ct.rel && !ct.new && %s.natted",
                      ct_flag_reg);
        size_t match_len = match->length;

        ds_put_format(match, " && %s.skip_snat == 1", ct_flag_reg);
        ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT, 70, ds_cstr(match),
                      "flags.skip_snat_for_lb = 1; next;",
                      lflow_ref);

        ds_truncate(match, match_len);
        ds_put_format(match, " && %s.force_snat == 1", ct_flag_reg);
        ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT, 70, ds_cstr(match),
                      "flags.force_snat_for_lb = 1; next;",
                      lflow_ref);

        ds_truncate(match, match_len);
        ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT, 50, ds_cstr(match),
                      "next;", lflow_ref);
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
    if (od->is_gw_router && (od->nbr->n_nat || lr_stateful_rec->has_lb_vip)) {
        /* Do not send ND or ICMP packets to connection tracking. */
        ovn_lflow_add(lflows, od, S_ROUTER_OUT_UNDNAT, 100,
                      "nd || nd_rs || nd_ra", "next;",
                      lflow_ref);
        ovn_lflow_add(lflows, od, S_ROUTER_OUT_UNDNAT, 50,
                      "ip", "flags.loopback = 1; ct_dnat;",
                      lflow_ref);
        ovn_lflow_add(lflows, od, S_ROUTER_OUT_POST_UNDNAT, 50,
                      "ip && ct.new", "ct_commit { } ; next; ",
                      lflow_ref);
    }

    /* NAT rules are only valid on Gateway routers and routers with
     * l3dgw_ports (router has port(s) with gateway chassis
     * specified). */
    if (!od->is_gw_router && !od->n_l3dgw_ports) {
        return;
    }

    struct sset nat_entries = SSET_INITIALIZER(&nat_entries);
    const struct lr_nat_record *lrnat_rec = lr_stateful_rec->lrnat_rec;
    ovs_assert(lrnat_rec);

    bool dnat_force_snat_ip =
        !lport_addresses_is_empty(&lrnat_rec->dnat_force_snat_addrs);
    bool lb_force_snat_ip =
        !lport_addresses_is_empty(&lrnat_rec->lb_force_snat_addrs);

    for (size_t i = 0; i < lrnat_rec->n_nat_entries; i++) {
        struct ovn_nat *nat_entry = &lrnat_rec->nat_entries[i];
        const struct nbrec_nat *nat = nat_entry->nb;
        struct eth_addr mac = eth_addr_broadcast;
        bool is_v6, distributed_nat;
        ovs_be32 mask;
        int cidr_bits;
        struct ovn_port *l3dgw_port;

        bool stateless = lrouter_dnat_and_snat_is_stateless(nat);

        if (lrouter_check_nat_entry(od, nat, lr_ports, &mask, &is_v6,
                                    &cidr_bits,
                                    &mac, &distributed_nat, &l3dgw_port) < 0) {
            continue;
        }

        /* S_ROUTER_IN_UNSNAT
         * Ingress UNSNAT table: It is for already established connections'
         * reverse traffic. i.e., SNAT has already been done in egress
         * pipeline and now the packet has entered the ingress pipeline as
         * part of a reply. We undo the SNAT here.
         *
         * Undoing SNAT has to happen before DNAT processing.  This is
         * because when the packet was DNATed in ingress pipeline, it did
         * not know about the possibility of eventual additional SNAT in
         * egress pipeline. */
        if (stateless) {
            build_lrouter_in_unsnat_stateless_flow(lflows, od, nat, match,
                                                   distributed_nat, is_v6,
                                                   l3dgw_port, lflow_ref);
        } else if (lrouter_use_common_zone(od)) {
            build_lrouter_in_unsnat_in_czone_flow(lflows, od, nat, match,
                                                  distributed_nat, is_v6,
                                                  l3dgw_port, lflow_ref);
        } else {
            build_lrouter_in_unsnat_flow(lflows, od, nat, match,
                                         distributed_nat, is_v6, l3dgw_port,
                                         lflow_ref);
        }
        /* S_ROUTER_IN_DNAT */
        build_lrouter_in_dnat_flow(lflows, od, lrnat_rec, nat, match, actions,
                                   distributed_nat, cidr_bits, is_v6,
                                   l3dgw_port, stateless, lflow_ref);

        /* ARP resolve for NAT IPs. */
        if (!od->is_gw_router) {
            if (!sset_contains(&nat_entries, nat->external_ip)) {
                /* Drop packets coming in from external that still has
                 * destination IP equals to the NAT external IP, to avoid loop.
                 * The packets must have gone through DNAT/unSNAT stage but
                 * failed to convert the destination. */
                ds_clear(match);
                ds_put_format(
                    match, "inport == %s && outport == %s && ip%s.dst == %s",
                    l3dgw_port->json_key, l3dgw_port->json_key,
                    is_v6 ? "6" : "4", nat->external_ip);
                ovn_lflow_add_with_hint(lflows, od,
                                        S_ROUTER_IN_ARP_RESOLVE,
                                        150, ds_cstr(match),
                                        debug_drop_action(),
                                        &nat->header_,
                                        lflow_ref);
                /* Now for packets coming from other (downlink) LRPs, allow ARP
                 * resolve for the NAT IP, so that such packets can be
                 * forwarded for E/W NAT. */
                ds_clear(match);
                ds_put_format(
                    match, "outport == %s && %s == %s",
                    l3dgw_port->json_key,
                    is_v6 ? REG_NEXT_HOP_IPV6 : REG_NEXT_HOP_IPV4,
                    nat->external_ip);
                ds_clear(actions);
                ds_put_format(
                    actions, "eth.dst = %s; next;",
                    distributed_nat ? nat->external_mac :
                    l3dgw_port->lrp_networks.ea_s);
                ovn_lflow_add_with_hint(lflows, od,
                                        S_ROUTER_IN_ARP_RESOLVE,
                                        100, ds_cstr(match),
                                        ds_cstr(actions),
                                        &nat->header_,
                                        lflow_ref);
                if (od->redirect_bridged && distributed_nat) {
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
                                            &nat->header_,
                                            lflow_ref);
                }
                sset_add(&nat_entries, nat->external_ip);
            }
        }

        if (use_common_zone) {
            /* S_ROUTER_OUT_DNAT_LOCAL */
            build_lrouter_out_is_dnat_local(lflows, od, nat, match, actions,
                                            distributed_nat, is_v6,
                                            l3dgw_port, lflow_ref);
        }

        /* S_ROUTER_OUT_UNDNAT */
        build_lrouter_out_undnat_flow(lflows, od, nat, match, actions,
                                      distributed_nat, mac, is_v6, l3dgw_port,
                                      stateless, lflow_ref);
        /* S_ROUTER_OUT_SNAT
         * Egress SNAT table: Packets enter the egress pipeline with
         * source ip address that needs to be SNATted to a external ip
         * address. */
        if (stateless) {
            build_lrouter_out_snat_stateless_flow(lflows, od, nat, match,
                                                  actions, distributed_nat,
                                                  mac, cidr_bits, is_v6,
                                                  l3dgw_port, lflow_ref);
        } else if (lrouter_use_common_zone(od)) {
            build_lrouter_out_snat_in_czone_flow(lflows, od, nat, match,
                                                 actions, distributed_nat, mac,
                                                 cidr_bits, is_v6, l3dgw_port,
                                                 lflow_ref);
        } else {
            build_lrouter_out_snat_flow(lflows, od, nat, match, actions,
                                        distributed_nat, mac, cidr_bits, is_v6,
                                        l3dgw_port, lflow_ref, features);
        }

        /* S_ROUTER_IN_ADMISSION - S_ROUTER_IN_IP_INPUT */
        build_lrouter_ingress_flow(lflows, od, nat, match, actions, mac,
                                   distributed_nat, is_v6, l3dgw_port,
                                   meter_groups, lflow_ref);

        /* Ingress Gateway Redirect Table: For NAT on a distributed
         * router, add flows that are specific to a NAT rule.  These
         * flows indicate the presence of an applicable NAT rule that
         * can be applied in a distributed manner.
         * In particulr REG_SRC_IPV4/REG_SRC_IPV6 and eth.src are set to
         * NAT external IP and NAT external mac so the ARP request
         * generated in the following stage is sent out with proper IP/MAC
         * src addresses.
         */
        if (distributed_nat) {
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
            struct ovn_port *op = ovn_port_find(ls_ports,
                                                nat->logical_port);
            if (op && op->nbsp && !strcmp(op->nbsp->type, "virtual")) {
                ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_GW_REDIRECT,
                                        80, ds_cstr(match),
                                        debug_drop_action(), &nat->header_,
                                        lflow_ref);
            }
            ds_put_format(match, " && is_chassis_resident(\"%s\")",
                          nat->logical_port);
            ds_put_format(actions, "eth.src = %s; %s = %s; next;",
                          nat->external_mac,
                          is_v6 ? REG_SRC_IPV6 : REG_SRC_IPV4,
                          nat->external_ip);
            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_GW_REDIRECT,
                                    100, ds_cstr(match),
                                    ds_cstr(actions), &nat->header_,
                                    lflow_ref);
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
            if (!distributed_nat) {
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
                          "flags = 0; flags.loopback = 1; ");
            if (use_common_zone) {
                ds_put_cstr(actions, "flags.use_snat_zone = "
                            REGBIT_DST_NAT_IP_LOCAL"; ");
            }
            for (int j = 0; j < MFF_N_LOG_REGS; j++) {
                ds_put_format(actions, "reg%d = 0; ", j);
            }
            ds_put_format(actions, REGBIT_EGRESS_LOOPBACK" = 1; "
                          "next(pipeline=ingress, table=%d); };",
                          ovn_stage_get_table(S_ROUTER_IN_ADMISSION));
            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_EGR_LOOP, 100,
                                    ds_cstr(match), ds_cstr(actions),
                                    &nat->header_, lflow_ref);
        }
    }

    if (use_common_zone && od->nbr->n_nat) {
        ds_clear(match);
        const char *ct_natted = features->ct_no_masked_label ?
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
                                &od->nbr->header_, lflow_ref);

    }

    /* Handle force SNAT options set in the gateway router. */
    if (od->is_gw_router) {
        if (dnat_force_snat_ip) {
            if (lrnat_rec->dnat_force_snat_addrs.n_ipv4_addrs) {
                build_lrouter_force_snat_flows(lflows, od, "4",
                    lrnat_rec->dnat_force_snat_addrs.ipv4_addrs[0].addr_s,
                    "dnat", lflow_ref);
            }
            if (lrnat_rec->dnat_force_snat_addrs.n_ipv6_addrs) {
                build_lrouter_force_snat_flows(lflows, od, "6",
                    lrnat_rec->dnat_force_snat_addrs.ipv6_addrs[0].addr_s,
                    "dnat", lflow_ref);
            }
        }
        if (lb_force_snat_ip) {
            if (lrnat_rec->lb_force_snat_addrs.n_ipv4_addrs) {
                build_lrouter_force_snat_flows(lflows, od, "4",
                    lrnat_rec->lb_force_snat_addrs.ipv4_addrs[0].addr_s, "lb",
                    lflow_ref);
            }
            if (lrnat_rec->lb_force_snat_addrs.n_ipv6_addrs) {
                build_lrouter_force_snat_flows(lflows, od, "6",
                    lrnat_rec->lb_force_snat_addrs.ipv6_addrs[0].addr_s, "lb",
                    lflow_ref);
            }
        }
    }

    sset_destroy(&nat_entries);
}

static void
build_lsp_lflows_for_lbnats(struct ovn_port *lsp,
                            const struct lr_stateful_record *lr_stateful_rec,
                            struct lflow_table *lflows,
                            struct ds *match,
                            struct ds *actions,
                            struct lflow_ref *lflow_ref)
{
    ovs_assert(lsp->nbsp);
    ovs_assert(lsp->peer);
    build_lswitch_rport_arp_req_flows_for_lbnats(
        lsp->peer, lr_stateful_rec, lsp->od, lsp,
        lflows, &lsp->nbsp->header_, lflow_ref);
    build_lswitch_ip_unicast_lookup_for_nats(lsp, lr_stateful_rec, lflows,
                                             match, actions, lflow_ref);
}

/* Logical router ingress table IP_ROUTING : IP Routing.
 *
 * Adds the LRP 'lrp's routable addresses (addresses which can be routed via
 * the LRP's datapath) as routable flows into the other router datapaths
 * which are connected to the LRP's peer's logical switch.
 *
 * i.e If logical switch sw0 is conencted to the routers R0, R1 and R2,
 * and if LRP of R0 has routable addresses (IP1 and IP2), then it adds
 * the routes to reach these IPs in the R1 and R2's datapaths.
 *
 * This function also adds the ARP resolve flows for these addresses
 * (IP1 and IP2) in the ARP_RESOLVE table of R1 and R2.
 * */
static void
build_routable_flows_for_router_port(
    struct ovn_port *lrp, const struct lr_stateful_record *lr_stateful_rec,
    struct lflow_table *lflows,
    struct ds *match,
    struct ds *actions)
{
    ovs_assert(lrp->nbrp && uuid_equals(&lrp->od->nbr->header_.uuid,
                                        &lr_stateful_rec->nbr_uuid));

    struct ovn_port *lsp_peer = lrp->peer;
    if (!lsp_peer || !lsp_peer->nbsp) {
        return;
    }

    struct ovn_datapath *peer_ls = lsp_peer->od;
    ovs_assert(peer_ls->nbs);

    struct ovn_port_routable_addresses ra =
        get_op_routable_addresses(lrp, lr_stateful_rec);

    struct ovn_port *router_port;

    for (size_t i = 0; i < peer_ls->n_router_ports; i++) {
        router_port = peer_ls->router_ports[i]->peer;

        if (router_port == lrp) {
            continue;
        }

        if (lrp->nbrp->ha_chassis_group ||
                lrp->nbrp->n_gateway_chassis || lrp->od->is_gw_router) {
            for (size_t j = 0; j < ra.n_addrs; j++) {
                struct lport_addresses *laddrs = &ra.laddrs[j];
                for (size_t k = 0; k < laddrs->n_ipv4_addrs; k++) {
                    add_route(lflows, router_port->od, router_port,
                              router_port->lrp_networks.ipv4_addrs[0].addr_s,
                              laddrs->ipv4_addrs[k].network_s,
                              laddrs->ipv4_addrs[k].plen, NULL, false, 0,
                              &router_port->nbrp->header_, false,
                              ROUTE_PRIO_OFFSET_CONNECTED,
                              lrp->stateful_lflow_ref);
                }
            }
        }

        bool dynamic_neigh_router =
            smap_get_bool(&router_port->od->nbr->options,
                          "dynamic_neigh_routers", false);

        if (!dynamic_neigh_router &&
            (router_port->od->is_gw_router || router_port->cr_port)) {

            for (size_t k = 0; k < ra.n_addrs; k++) {
                ds_clear(match);
                ds_put_format(match, "outport == %s && "
                              REG_NEXT_HOP_IPV4" == {",
                              router_port->json_key);
                bool first = true;
                for (size_t j = 0; j < ra.laddrs[k].n_ipv4_addrs; j++) {
                    if (!first) {
                        ds_put_cstr(match, ", ");
                    }
                    ds_put_cstr(match, ra.laddrs[k].ipv4_addrs[j].addr_s);
                    first = false;
                }
                ds_put_cstr(match, "}");

                ds_clear(actions);
                ds_put_format(actions, "eth.dst = %s; next;",
                              ra.laddrs[k].ea_s);
                ovn_lflow_add(lflows, router_port->od, S_ROUTER_IN_ARP_RESOLVE,
                              100, ds_cstr(match), ds_cstr(actions),
                              lrp->stateful_lflow_ref);
            }
        }
    }

    destroy_routable_addresses(&ra);
}

static void
build_lbnat_lflows_iterate_by_lsp(
    struct ovn_port *op, const struct lr_stateful_table *lr_stateful_table,
    struct ds *match, struct ds *actions, struct lflow_table *lflows)
{
    ovs_assert(op->nbsp);

    if (!lsp_is_router(op->nbsp) || !op->peer) {
        return;
    }

    const struct lr_stateful_record *lr_stateful_rec;
    lr_stateful_rec = lr_stateful_table_find_by_index(lr_stateful_table,
                                                      op->peer->od->index);
    ovs_assert(lr_stateful_rec);

    build_lsp_lflows_for_lbnats(op, lr_stateful_rec,
                                lflows,match, actions,
                                op->stateful_lflow_ref);
}

static void
build_lrp_lflows_for_lbnats(struct ovn_port *op,
                            const struct lr_stateful_record *lr_stateful_rec,
                            const struct shash *meter_groups,
                            struct ds *match, struct ds *actions,
                            struct lflow_table *lflows)
{
    ovs_assert(op->nbrp && uuid_equals(&op->od->nbr->header_.uuid,
                                       &lr_stateful_rec->nbr_uuid));

    /* Drop IP traffic destined to router owned IPs except if the IP is
     * also a SNAT IP. Those are dropped later, in stage
     * "lr_in_arp_resolve", if unSNAT was unsuccessful.
     *
     * If lrnat_rec->lb_force_snat_router_ip is true, it means the IP of the
     * router port is also SNAT IP.
     *
     * Priority 60.
     */
    if (!lr_stateful_rec->lrnat_rec->lb_force_snat_router_ip) {
        build_lrouter_drop_own_dest(op, lr_stateful_rec,
                                    S_ROUTER_IN_IP_INPUT, 60, false, lflows,
                                    op->stateful_lflow_ref);
    }

    /* Drop IP traffic destined to router owned IPs. Part of it is dropped
     * in stage "lr_in_ip_input" but traffic that could have been unSNATed
     * but didn't match any existing session might still end up here.
     *
     * Priority 2.
     */
    build_lrouter_drop_own_dest(op, lr_stateful_rec,
                                S_ROUTER_IN_ARP_RESOLVE, 2, true,
                                lflows, op->stateful_lflow_ref);

    build_lrouter_ipv4_ip_input_for_lbnats(op, lflows, lr_stateful_rec,
                                           match, meter_groups,
                                           op->stateful_lflow_ref);
    build_lrouter_force_snat_flows_op(op, lr_stateful_rec->lrnat_rec, lflows,
                                      match, actions, op->stateful_lflow_ref);
}

/* Builds the load balancer and NAT related flows for the router port 'op'.
 * It uses the op->stateful_lflow_ref for lflow referencing.
 */
static void
build_lbnat_lflows_iterate_by_lrp(
    struct ovn_port *op, const struct lr_stateful_table *lr_stateful_table,
    const struct shash *meter_groups, struct ds *match,
    struct ds *actions, struct lflow_table *lflows)
{
    ovs_assert(op->nbrp);

    const struct lr_stateful_record *lr_stateful_rec;
    lr_stateful_rec = lr_stateful_table_find_by_index(lr_stateful_table,
                                                      op->od->index);
    ovs_assert(lr_stateful_rec);

    build_lrp_lflows_for_lbnats(op, lr_stateful_rec, meter_groups, match,
                                actions, lflows);

    build_routable_flows_for_router_port(op, lr_stateful_rec, lflows, match,
                                         actions);
}

static void
build_lr_stateful_flows(const struct lr_stateful_record *lr_stateful_rec,
                        const struct ovn_datapaths *lr_datapaths,
                        struct lflow_table *lflows,
                        const struct hmap *ls_ports,
                        const struct hmap *lr_ports,
                        struct ds *match,
                        struct ds *actions,
                        const struct shash *meter_groups,
                        const struct chassis_features *features)
{
    const struct ovn_datapath *od =
        ovn_datapaths_find_by_index(lr_datapaths, lr_stateful_rec->lr_index);
    ovs_assert(od->nbr);
    ovs_assert(uuid_equals(&od->nbr->header_.uuid,
                           &lr_stateful_rec->nbr_uuid));
    build_lrouter_nat_defrag_and_lb(lr_stateful_rec, od, lflows, ls_ports,
                                    lr_ports, match, actions, meter_groups,
                                    features, lr_stateful_rec->lflow_ref);
    build_lr_gateway_redirect_flows_for_nats(od, lr_stateful_rec->lrnat_rec,
                                             lflows, match, actions,
                                             lr_stateful_rec->lflow_ref);
    build_lrouter_arp_nd_for_datapath(od, lr_stateful_rec->lrnat_rec,
                                      lflows, meter_groups,
                                      lr_stateful_rec->lflow_ref);
}

static void
build_ls_stateful_flows(const struct ls_stateful_record *ls_stateful_rec,
                        const struct ovn_datapath *od,
                        const struct ls_port_group_table *ls_pgs,
                        const struct chassis_features *features,
                        const struct shash *meter_groups,
                        struct lflow_table *lflows)
{
    build_ls_stateful_rec_pre_acls(ls_stateful_rec, od, ls_pgs, lflows,
                                   ls_stateful_rec->lflow_ref);
    build_ls_stateful_rec_pre_lb(ls_stateful_rec, od, lflows,
                                 ls_stateful_rec->lflow_ref);
    build_acl_hints(ls_stateful_rec, od, features, lflows,
                    ls_stateful_rec->lflow_ref);
    build_acls(ls_stateful_rec, od, features, lflows, ls_pgs,
               meter_groups, ls_stateful_rec->lflow_ref);
    build_lb_hairpin(ls_stateful_rec, od, lflows, ls_stateful_rec->lflow_ref);
}

struct lswitch_flow_build_info {
    const struct ovn_datapaths *ls_datapaths;
    const struct ovn_datapaths *lr_datapaths;
    const struct hmap *ls_ports;
    const struct hmap *lr_ports;
    const struct ls_port_group_table *ls_port_groups;
    const struct lr_stateful_table *lr_stateful_table;
    const struct ls_stateful_table *ls_stateful_table;
    struct lflow_table *lflows;
    struct hmap *igmp_groups;
    const struct shash *meter_groups;
    const struct hmap *lb_dps_map;
    const struct hmap *svc_monitor_map;
    const struct hmap *bfd_connections;
    const struct chassis_features *features;
    char *svc_check_match;
    struct ds match;
    struct ds actions;
    size_t thread_lflow_counter;
    const char *svc_monitor_mac;
};

/* Helper function to combine all lflow generation which is iterated by
 * logical switch datapath.
 *
 * When extending the function new "work data" must be added to the lsi
 * struct, not passed as an argument.
 */
static void
build_lswitch_and_lrouter_iterate_by_ls(struct ovn_datapath *od,
                                        struct lswitch_flow_build_info *lsi)
{
    ovs_assert(od->nbs);
    build_lswitch_lflows_pre_acl_and_acl(od, lsi->features, lsi->lflows,
                                         lsi->meter_groups, NULL);

    build_fwd_group_lflows(od, lsi->lflows, NULL);
    build_lswitch_lflows_admission_control(od, lsi->lflows, NULL);
    build_lswitch_learn_fdb_od(od, lsi->lflows, NULL);
    build_lswitch_arp_nd_responder_default(od, lsi->lflows, NULL);
    build_lswitch_dns_lookup_and_response(od, lsi->lflows, lsi->meter_groups,
                                          NULL);
    build_lswitch_dhcp_and_dns_defaults(od, lsi->lflows, NULL);
    build_lswitch_destination_lookup_bmcast(od, lsi->lflows, &lsi->actions,
                                            lsi->meter_groups, NULL);
    build_lswitch_output_port_sec_od(od, lsi->lflows, NULL);
    build_lswitch_lb_affinity_default_flows(od, lsi->lflows, NULL);
    build_lswitch_lflows_l2_unknown(od, lsi->lflows, NULL);
}

/* Helper function to combine all lflow generation which is iterated by
 * logical router datapath.
 */
static void
build_lswitch_and_lrouter_iterate_by_lr(struct ovn_datapath *od,
                                        struct lswitch_flow_build_info *lsi)
{
    ovs_assert(od->nbr);
    build_adm_ctrl_flows_for_lrouter(od, lsi->lflows, NULL);
    build_neigh_learning_flows_for_lrouter(od, lsi->lflows, &lsi->match,
                                           &lsi->actions,
                                           lsi->meter_groups, NULL);
    build_ND_RA_flows_for_lrouter(od, lsi->lflows, NULL);
    build_ip_routing_pre_flows_for_lrouter(od, lsi->lflows, NULL);
    build_static_route_flows_for_lrouter(od, lsi->features,
                                         lsi->lflows, lsi->lr_ports,
                                         lsi->bfd_connections,
                                         NULL);
    build_mcast_lookup_flows_for_lrouter(od, lsi->lflows, &lsi->match,
                                         &lsi->actions, NULL);
    build_ingress_policy_flows_for_lrouter(od, lsi->lflows, lsi->lr_ports,
                                           lsi->bfd_connections, NULL);
    build_arp_resolve_flows_for_lrouter(od, lsi->lflows, NULL);
    build_check_pkt_len_flows_for_lrouter(od, lsi->lflows, lsi->lr_ports,
                                          &lsi->match, &lsi->actions,
                                          lsi->meter_groups, NULL,
                                          lsi->features);
    build_gateway_redirect_flows_for_lrouter(od, lsi->lflows, &lsi->match,
                                             &lsi->actions, NULL);
    build_arp_request_flows_for_lrouter(od, lsi->lflows, &lsi->match,
                                        &lsi->actions,
                                        lsi->meter_groups,
                                        NULL);
    build_misc_local_traffic_drop_flows_for_lrouter(od, lsi->lflows, NULL);

    build_lr_nat_defrag_and_lb_default_flows(od, lsi->lflows, NULL);
    build_lrouter_lb_affinity_default_flows(od, lsi->lflows, NULL);

    /* Default drop rule in lr_out_delivery stage.  See
     * build_egress_delivery_flows_for_lrouter_port() which adds a rule
     * for each router port. */
    ovn_lflow_add_default_drop(lsi->lflows, od, S_ROUTER_OUT_DELIVERY, NULL);
}

/* Helper function to combine all lflow generation which is iterated by logical
 * switch port.
 */
static void
build_lswitch_and_lrouter_iterate_by_lsp(struct ovn_port *op,
                                         const struct hmap *ls_ports,
                                         const struct hmap *lr_ports,
                                         const struct shash *meter_groups,
                                         struct ds *match,
                                         struct ds *actions,
                                         struct lflow_table *lflows)
{
    ovs_assert(op->nbsp);

    /* Build Logical Switch Flows. */
    build_lswitch_port_sec_op(op, lflows, actions, match);
    build_lswitch_learn_fdb_op(op, lflows, actions, match);
    build_lswitch_arp_nd_responder_skip_local(op, lflows, match);
    build_lswitch_arp_nd_responder_known_ips(op, lflows, ls_ports,
                                             meter_groups, actions, match);
    build_lswitch_dhcp_options_and_response(op, lflows, meter_groups);
    build_lswitch_external_port(op, lflows);
    build_lswitch_icmp_packet_toobig_admin_flows(op, lflows, match, actions);
    build_lswitch_ip_unicast_lookup(op, lflows, actions,
                                    match);
    build_lswitch_dhcp_relay_flows(op, ls_ports, lflows, match, actions);

    /* Build Logical Router Flows. */
    build_arp_resolve_flows_for_lsp(op, lflows, lr_ports, match, actions);
}

/* Helper function to combine all lflow generation which is iterated by logical
 * router port. All the flows built in this function are Logical Router flows.
 */
static void
build_lswitch_and_lrouter_iterate_by_lrp(struct ovn_port *op,
                                         struct lswitch_flow_build_info *lsi)
{
    ovs_assert(op->nbrp);

    build_adm_ctrl_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                          &lsi->actions, op->lflow_ref);
    build_neigh_learning_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                                &lsi->actions, op->lflow_ref);
    build_ip_routing_flows_for_lrp(op, lsi->lflows, op->lflow_ref);
    build_ND_RA_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                       &lsi->actions, lsi->meter_groups,
                                       op->lflow_ref);
    build_arp_resolve_flows_for_lrp(op, lsi->lflows,
                                    &lsi->match, &lsi->actions, op->lflow_ref);
    build_egress_delivery_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                                 &lsi->actions,
                                                 op->lflow_ref);
    build_dhcpv6_reply_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                              op->lflow_ref);
    build_dhcp_relay_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                            &lsi->actions, op->lflow_ref);
    build_ipv6_input_flows_for_lrouter_port(op, lsi->lflows,
                                            &lsi->match, &lsi->actions,
                                            lsi->meter_groups,
                                            op->lflow_ref);
    build_lrouter_ipv4_ip_input(op, lsi->lflows, &lsi->match, &lsi->actions,
                                lsi->meter_groups, op->lflow_ref);
    build_lrouter_icmp_packet_toobig_admin_flows(op, lsi->lflows, &lsi->match,
                                                 &lsi->actions, op->lflow_ref);
}

static void *
build_lflows_thread(void *arg)
{
    struct worker_control *control = (struct worker_control *) arg;
    const struct lr_stateful_record *lr_stateful_rec;
    const struct ls_stateful_record *ls_stateful_rec;
    struct lswitch_flow_build_info *lsi;
    struct ovn_igmp_group *igmp_group;
    struct ovn_lb_datapaths *lb_dps;
    struct ovn_datapath *od;
    struct ovn_port *op;
    int bnum;

    /* Note:  lflow_ref is not thread safe.  Ensure that
     *    - op->lflow_ref
     *    - lb_dps->lflow_ref
     *    - lr_stateful_rec->lflow_ref
     *    - ls_stateful_rec->lflow_ref
     * are not accessed by multiple threads at the same time. */
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
                    bnum <= lsi->ls_datapaths->datapaths.mask;
                    bnum += control->pool->size)
            {
                HMAP_FOR_EACH_IN_PARALLEL (od, key_node, bnum,
                                           &lsi->ls_datapaths->datapaths) {
                    if (stop_parallel_processing()) {
                        return NULL;
                    }
                    build_lswitch_and_lrouter_iterate_by_ls(od, lsi);
                }
            }
            for (bnum = control->id;
                    bnum <= lsi->lr_datapaths->datapaths.mask;
                    bnum += control->pool->size)
            {
                HMAP_FOR_EACH_IN_PARALLEL (od, key_node, bnum,
                                           &lsi->lr_datapaths->datapaths) {
                    if (stop_parallel_processing()) {
                        return NULL;
                    }
                    build_lswitch_and_lrouter_iterate_by_lr(od, lsi);
                }
            }
            for (bnum = control->id;
                    bnum <= lsi->ls_ports->mask;
                    bnum += control->pool->size)
            {
                HMAP_FOR_EACH_IN_PARALLEL (op, key_node, bnum,
                                           lsi->ls_ports) {
                    if (stop_parallel_processing()) {
                        return NULL;
                    }
                    build_lswitch_and_lrouter_iterate_by_lsp(op, lsi->ls_ports,
                                                             lsi->lr_ports,
                                                             lsi->meter_groups,
                                                             &lsi->match,
                                                             &lsi->actions,
                                                             lsi->lflows);
                    build_lbnat_lflows_iterate_by_lsp(
                        op, lsi->lr_stateful_table, &lsi->match,
                        &lsi->actions, lsi->lflows);
                }
            }
            for (bnum = control->id;
                    bnum <= lsi->lr_ports->mask;
                    bnum += control->pool->size)
            {
                HMAP_FOR_EACH_IN_PARALLEL (op, key_node, bnum,
                                           lsi->lr_ports) {
                    if (stop_parallel_processing()) {
                        return NULL;
                    }
                    build_lswitch_and_lrouter_iterate_by_lrp(op, lsi);
                    build_lbnat_lflows_iterate_by_lrp(
                        op, lsi->lr_stateful_table, lsi->meter_groups,
                        &lsi->match, &lsi->actions, lsi->lflows);
                }
            }
            for (bnum = control->id;
                    bnum <= lsi->lb_dps_map->mask;
                    bnum += control->pool->size)
            {
                HMAP_FOR_EACH_IN_PARALLEL (lb_dps, hmap_node, bnum,
                                           lsi->lb_dps_map) {
                    if (stop_parallel_processing()) {
                        return NULL;
                    }
                    build_lswitch_arp_nd_service_monitor(lb_dps,
                                                         lsi->ls_ports,
                                                         lsi->svc_monitor_mac,
                                                         lsi->lflows,
                                                         &lsi->match,
                                                         &lsi->actions);
                    build_lrouter_defrag_flows_for_lb(lb_dps, lsi->lflows,
                                                      lsi->lr_datapaths,
                                                      &lsi->match);
                    build_lrouter_flows_for_lb(lb_dps, lsi->lflows,
                                               lsi->meter_groups,
                                               lsi->lr_datapaths,
                                               lsi->lr_stateful_table,
                                               lsi->features,
                                               lsi->svc_monitor_map,
                                               &lsi->match, &lsi->actions);
                    build_lswitch_flows_for_lb(lb_dps, lsi->lflows,
                                               lsi->meter_groups,
                                               lsi->ls_datapaths,
                                               lsi->features,
                                               lsi->svc_monitor_map,
                                               &lsi->match, &lsi->actions);
                }
            }
            for (bnum = control->id;
                    bnum <= lsi->lr_stateful_table->entries.mask;
                    bnum += control->pool->size)
            {
                LR_STATEFUL_TABLE_FOR_EACH_IN_P (lr_stateful_rec, bnum,
                                                 lsi->lr_stateful_table) {
                    if (stop_parallel_processing()) {
                        return NULL;
                    }
                    build_lr_stateful_flows(lr_stateful_rec, lsi->lr_datapaths,
                                            lsi->lflows, lsi->ls_ports,
                                            lsi->lr_ports, &lsi->match,
                                            &lsi->actions,
                                            lsi->meter_groups,
                                            lsi->features);
                }
            }

            for (bnum = control->id;
                    bnum <= lsi->ls_stateful_table->entries.mask;
                    bnum += control->pool->size)
            {
                LS_STATEFUL_TABLE_FOR_EACH_IN_P (ls_stateful_rec, bnum,
                                                 lsi->ls_stateful_table) {
                    od = ovn_datapaths_find_by_index(
                        lsi->ls_datapaths, ls_stateful_rec->ls_index);
                    /* Make sure that ls_stateful_rec and od belong to the
                     * same NB Logical switch. */
                    ovs_assert(uuid_equals(&ls_stateful_rec->nbs_uuid,
                                           &od->nbs->header_.uuid));
                    build_ls_stateful_flows(ls_stateful_rec, od,
                                            lsi->ls_port_groups,
                                            lsi->features, lsi->meter_groups,
                                            lsi->lflows);
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

/* Fixes the hmap size (hmap->n) after parallel building the lflow_table when
 * dp-groups is enabled, because in that case all threads are updating the
 * global lflow hmap. Although the lflow_hash_lock prevents currently inserting
 * to the same hash bucket, the hmap->n is updated currently by all threads and
 * may not be accurate at the end of each iteration. This function collects the
 * thread-local lflow counters maintained by each thread and update the hmap
 * size with the aggregated value. This function must be called immediately
 * after the worker threads complete the tasks in each iteration before any
 * future operations on the lflow map. */
static void
fix_flow_table_size(struct lflow_table *lflow_table,
                  struct lswitch_flow_build_info *lsiv,
                  size_t n_lsiv)
{
    size_t total = 0;
    for (size_t i = 0; i < n_lsiv; i++) {
        total += lsiv[i].thread_lflow_counter;
    }
    lflow_table_set_size(lflow_table, total);
}

static void
build_lswitch_and_lrouter_flows(
    const struct ovn_datapaths *ls_datapaths,
    const struct ovn_datapaths *lr_datapaths,
    const struct hmap *ls_ports,
    const struct hmap *lr_ports,
    const struct ls_port_group_table *ls_pgs,
    const struct lr_stateful_table *lr_stateful_table,
    const struct ls_stateful_table *ls_stateful_table,
    struct lflow_table *lflows,
    struct hmap *igmp_groups,
    const struct shash *meter_groups,
    const struct hmap *lb_dps_map,
    const struct hmap *svc_monitor_map,
    const struct hmap *bfd_connections,
    const struct chassis_features *features,
    const char *svc_monitor_mac)
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
            lsiv[index].ls_datapaths = ls_datapaths;
            lsiv[index].lr_datapaths = lr_datapaths;
            lsiv[index].ls_ports = ls_ports;
            lsiv[index].lr_ports = lr_ports;
            lsiv[index].ls_port_groups = ls_pgs;
            lsiv[index].lr_stateful_table = lr_stateful_table;
            lsiv[index].ls_stateful_table = ls_stateful_table;
            lsiv[index].igmp_groups = igmp_groups;
            lsiv[index].meter_groups = meter_groups;
            lsiv[index].lb_dps_map = lb_dps_map;
            lsiv[index].svc_monitor_map = svc_monitor_map;
            lsiv[index].bfd_connections = bfd_connections;
            lsiv[index].features = features;
            lsiv[index].svc_check_match = svc_check_match;
            lsiv[index].thread_lflow_counter = 0;
            lsiv[index].svc_monitor_mac = svc_monitor_mac;
            ds_init(&lsiv[index].match);
            ds_init(&lsiv[index].actions);

            build_lflows_pool->controls[index].data = &lsiv[index];
        }

        /* Run thread pool. */
        run_pool_callback(build_lflows_pool, NULL, NULL, noop_callback);
        fix_flow_table_size(lflows, lsiv, build_lflows_pool->size);

        for (index = 0; index < build_lflows_pool->size; index++) {
            ds_destroy(&lsiv[index].match);
            ds_destroy(&lsiv[index].actions);
        }
        free(lsiv);
    } else {
        const struct lr_stateful_record *lr_stateful_rec;
        const struct ls_stateful_record *ls_stateful_rec;
        struct ovn_igmp_group *igmp_group;
        struct ovn_lb_datapaths *lb_dps;
        struct ovn_datapath *od;
        struct ovn_port *op;

        struct lswitch_flow_build_info lsi = {
            .ls_datapaths = ls_datapaths,
            .lr_datapaths = lr_datapaths,
            .ls_ports = ls_ports,
            .lr_ports = lr_ports,
            .ls_port_groups = ls_pgs,
            .lr_stateful_table = lr_stateful_table,
            .ls_stateful_table = ls_stateful_table,
            .lflows = lflows,
            .igmp_groups = igmp_groups,
            .meter_groups = meter_groups,
            .lb_dps_map = lb_dps_map,
            .svc_monitor_map = svc_monitor_map,
            .bfd_connections = bfd_connections,
            .features = features,
            .svc_check_match = svc_check_match,
            .svc_monitor_mac = svc_monitor_mac,
            .match = DS_EMPTY_INITIALIZER,
            .actions = DS_EMPTY_INITIALIZER,
        };

        /* Combined build - all lflow generation from lswitch and lrouter
         * will move here and will be reogranized by iterator type.
         */
        stopwatch_start(LFLOWS_DATAPATHS_STOPWATCH_NAME, time_msec());
        HMAP_FOR_EACH (od, key_node, &ls_datapaths->datapaths) {
            build_lswitch_and_lrouter_iterate_by_ls(od, &lsi);
        }
        HMAP_FOR_EACH (od, key_node, &lr_datapaths->datapaths) {
            build_lswitch_and_lrouter_iterate_by_lr(od, &lsi);
        }
        stopwatch_stop(LFLOWS_DATAPATHS_STOPWATCH_NAME, time_msec());
        stopwatch_start(LFLOWS_PORTS_STOPWATCH_NAME, time_msec());
        HMAP_FOR_EACH (op, key_node, ls_ports) {
            build_lswitch_and_lrouter_iterate_by_lsp(op, lsi.ls_ports,
                                                     lsi.lr_ports,
                                                     lsi.meter_groups,
                                                     &lsi.match,
                                                     &lsi.actions,
                                                     lsi.lflows);
            build_lbnat_lflows_iterate_by_lsp(op, lsi.lr_stateful_table,
                                              &lsi.match,
                                              &lsi.actions, lsi.lflows);
        }
        HMAP_FOR_EACH (op, key_node, lr_ports) {
            build_lswitch_and_lrouter_iterate_by_lrp(op, &lsi);
            build_lbnat_lflows_iterate_by_lrp(op, lsi.lr_stateful_table,
                                              lsi.meter_groups,
                                              &lsi.match,
                                              &lsi.actions,
                                              lsi.lflows);
        }
        stopwatch_stop(LFLOWS_PORTS_STOPWATCH_NAME, time_msec());
        stopwatch_start(LFLOWS_LBS_STOPWATCH_NAME, time_msec());
        HMAP_FOR_EACH (lb_dps, hmap_node, lb_dps_map) {
            build_lswitch_arp_nd_service_monitor(lb_dps, lsi.ls_ports,
                                                 lsi.svc_monitor_mac,
                                                 lsi.lflows, &lsi.actions,
                                                 &lsi.match);
            build_lrouter_defrag_flows_for_lb(lb_dps, lsi.lflows,
                                              lsi.lr_datapaths, &lsi.match);
            build_lrouter_flows_for_lb(lb_dps, lsi.lflows, lsi.meter_groups,
                                       lsi.lr_datapaths, lsi.lr_stateful_table,
                                       lsi.features, lsi.svc_monitor_map,
                                       &lsi.match, &lsi.actions);
            build_lswitch_flows_for_lb(lb_dps, lsi.lflows, lsi.meter_groups,
                                       lsi.ls_datapaths, lsi.features,
                                       lsi.svc_monitor_map,
                                       &lsi.match, &lsi.actions);
        }
        stopwatch_stop(LFLOWS_LBS_STOPWATCH_NAME, time_msec());
        stopwatch_start(LFLOWS_LR_STATEFUL_STOPWATCH_NAME, time_msec());
        LR_STATEFUL_TABLE_FOR_EACH (lr_stateful_rec, lr_stateful_table) {
            build_lr_stateful_flows(lr_stateful_rec, lsi.lr_datapaths,
                                    lsi.lflows, lsi.ls_ports, lsi.lr_ports,
                                    &lsi.match, &lsi.actions,
                                    lsi.meter_groups, lsi.features);
        }
        stopwatch_stop(LFLOWS_LR_STATEFUL_STOPWATCH_NAME, time_msec());
        stopwatch_start(LFLOWS_LS_STATEFUL_STOPWATCH_NAME, time_msec());
        LS_STATEFUL_TABLE_FOR_EACH (ls_stateful_rec, ls_stateful_table) {
            od = ovn_datapaths_find_by_index(lsi.ls_datapaths,
                                             ls_stateful_rec->ls_index);
            /* Make sure that ls_stateful_rec and od belong to the
             * same NB Logical switch. */
            ovs_assert(uuid_equals(&ls_stateful_rec->nbs_uuid,
                                   &od->nbs->header_.uuid));
            build_ls_stateful_flows(ls_stateful_rec, od, lsi.ls_port_groups,
                                    lsi.features, lsi.meter_groups,
                                    lsi.lflows);
        }
        stopwatch_stop(LFLOWS_LS_STATEFUL_STOPWATCH_NAME, time_msec());
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
}

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
build_mcast_groups(const struct sbrec_igmp_group_table *sbrec_igmp_group_table,
                   struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp,
                   const struct ovn_datapaths *ls_datapaths,
                   const struct hmap *ls_ports,
                   const struct hmap *lr_ports,
                   struct hmap *mcast_groups,
                   struct hmap *igmp_groups);

static struct sbrec_multicast_group *
create_sb_multicast_group(struct ovsdb_idl_txn *ovnsb_txn,
                          const struct sbrec_datapath_binding *dp,
                          const char *name,
                          int64_t tunnel_key)
{
    struct sbrec_multicast_group *sbmc =
        sbrec_multicast_group_insert(ovnsb_txn);
    sbrec_multicast_group_set_datapath(sbmc, dp);
    sbrec_multicast_group_set_name(sbmc, name);
    sbrec_multicast_group_set_tunnel_key(sbmc, tunnel_key);
    return sbmc;
}

/* Updates the Logical_Flow and Multicast_Group tables in the OVN_SB database,
 * constructing their contents based on the OVN_NB database. */
void build_lflows(struct ovsdb_idl_txn *ovnsb_txn,
                  struct lflow_input *input_data,
                  struct lflow_table *lflows)
{
    struct hmap mcast_groups;
    struct hmap igmp_groups;

    build_mcast_groups(input_data->sbrec_igmp_group_table,
                       input_data->sbrec_mcast_group_by_name_dp,
                       input_data->ls_datapaths,
                       input_data->ls_ports, input_data->lr_ports,
                       &mcast_groups, &igmp_groups);

    build_lswitch_and_lrouter_flows(input_data->ls_datapaths,
                                    input_data->lr_datapaths,
                                    input_data->ls_ports,
                                    input_data->lr_ports,
                                    input_data->ls_port_groups,
                                    input_data->lr_stateful_table,
                                    input_data->ls_stateful_table,
                                    lflows,
                                    &igmp_groups,
                                    input_data->meter_groups,
                                    input_data->lb_datapaths_map,
                                    input_data->svc_monitor_map,
                                    input_data->bfd_connections,
                                    input_data->features,
                                    input_data->svc_monitor_mac);

    if (parallelization_state == STATE_INIT_HASH_SIZES) {
        parallelization_state = STATE_USE_PARALLELIZATION;
    }

    /* Parallel build may result in a suboptimal hash. Resize the
     * lflow map to a correct size before doing lookups */
    lflow_table_expand(lflows);
    
    stopwatch_start(LFLOWS_TO_SB_STOPWATCH_NAME, time_msec());
    lflow_table_sync_to_sb(lflows, ovnsb_txn, input_data->ls_datapaths,
                           input_data->lr_datapaths,
                           input_data->ovn_internal_version_changed,
                           input_data->sbrec_logical_flow_table,
                           input_data->sbrec_logical_dp_group_table);

    stopwatch_stop(LFLOWS_TO_SB_STOPWATCH_NAME, time_msec());

    /* Push changes to the Multicast_Group table to database. */
    const struct sbrec_multicast_group *sbmc;
    SBREC_MULTICAST_GROUP_TABLE_FOR_EACH_SAFE (
            sbmc, input_data->sbrec_multicast_group_table) {
        struct ovn_datapath *od = ovn_datapath_from_sbrec(
            &input_data->ls_datapaths->datapaths,
            &input_data->lr_datapaths->datapaths,
            sbmc->datapath);

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
        sbmc = create_sb_multicast_group(ovnsb_txn, mc->datapath->sb,
                                         mc->group->name, mc->group->key);
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

void
lflow_reset_northd_refs(struct lflow_input *lflow_input)
{
    const struct lr_stateful_record *lr_stateful_rec;
    struct ls_stateful_record *ls_stateful_rec;
    struct ovn_lb_datapaths *lb_dps;
    struct ovn_port *op;

    LR_STATEFUL_TABLE_FOR_EACH (lr_stateful_rec,
                                lflow_input->lr_stateful_table) {
        lflow_ref_clear(lr_stateful_rec->lflow_ref);
    }

    LS_STATEFUL_TABLE_FOR_EACH (ls_stateful_rec,
                                lflow_input->ls_stateful_table) {
        lflow_ref_clear(ls_stateful_rec->lflow_ref);
    }

    HMAP_FOR_EACH (op, key_node, lflow_input->ls_ports) {
        lflow_ref_clear(op->lflow_ref);
        lflow_ref_clear(op->stateful_lflow_ref);
    }

    HMAP_FOR_EACH (op, key_node, lflow_input->lr_ports) {
        lflow_ref_clear(op->lflow_ref);
        lflow_ref_clear(op->stateful_lflow_ref);
    }

    HMAP_FOR_EACH (lb_dps, hmap_node, lflow_input->lb_datapaths_map) {
        lflow_ref_clear(lb_dps->lflow_ref);
    }
}

bool
lflow_handle_northd_port_changes(struct ovsdb_idl_txn *ovnsb_txn,
                                 struct tracked_ovn_ports *trk_lsps,
                                 struct lflow_input *lflow_input,
                                 struct lflow_table *lflows)
{
    struct hmapx_node *hmapx_node;
    struct ovn_port *op;

    HMAPX_FOR_EACH (hmapx_node, &trk_lsps->deleted) {
        op = hmapx_node->data;
        /* Make sure 'op' is an lsp and not lrp. */
        ovs_assert(op->nbsp);
        bool handled = lflow_ref_resync_flows(
            op->lflow_ref, lflows, ovnsb_txn, lflow_input->ls_datapaths,
            lflow_input->lr_datapaths,
            lflow_input->ovn_internal_version_changed,
            lflow_input->sbrec_logical_flow_table,
            lflow_input->sbrec_logical_dp_group_table);
        if (!handled) {
            return false;
        }
        /* No need to update SB multicast groups, thanks to weak
         * references. */
    }

    HMAPX_FOR_EACH (hmapx_node, &trk_lsps->updated) {
        op = hmapx_node->data;
        /* Make sure 'op' is an lsp and not lrp. */
        ovs_assert(op->nbsp);
        /* Clear old lflows. */
        lflow_ref_unlink_lflows(op->lflow_ref);

        /* Generate new lflows. */
        struct ds match = DS_EMPTY_INITIALIZER;
        struct ds actions = DS_EMPTY_INITIALIZER;
        build_lswitch_and_lrouter_iterate_by_lsp(op, lflow_input->ls_ports,
                                                 lflow_input->lr_ports,
                                                 lflow_input->meter_groups,
                                                 &match, &actions,
                                                 lflows);
        /* Sync the new flows to SB. */
        bool handled = lflow_ref_sync_lflows(
            op->lflow_ref, lflows, ovnsb_txn, lflow_input->ls_datapaths,
            lflow_input->lr_datapaths,
            lflow_input->ovn_internal_version_changed,
            lflow_input->sbrec_logical_flow_table,
            lflow_input->sbrec_logical_dp_group_table);
        if (handled) {
            /* Now regenerate the stateful lflows for 'op' */
            /* Clear old lflows. */
            lflow_ref_unlink_lflows(op->stateful_lflow_ref);
            build_lbnat_lflows_iterate_by_lsp(op,
                                              lflow_input->lr_stateful_table,
                                              &match, &actions, lflows);
            handled = lflow_ref_sync_lflows(
                op->stateful_lflow_ref, lflows, ovnsb_txn,
                lflow_input->ls_datapaths,
                lflow_input->lr_datapaths,
                lflow_input->ovn_internal_version_changed,
                lflow_input->sbrec_logical_flow_table,
                lflow_input->sbrec_logical_dp_group_table);
        }

        ds_destroy(&match);
        ds_destroy(&actions);

        if (!handled) {
            return false;
        }

        /* SB port_binding is not deleted, so don't update SB multicast
         * groups. */
    }

    HMAPX_FOR_EACH (hmapx_node, &trk_lsps->created) {
        op = hmapx_node->data;
        /* Make sure 'op' is an lsp and not lrp. */
        ovs_assert(op->nbsp);

        const struct sbrec_multicast_group *sbmc_flood =
            mcast_group_lookup(lflow_input->sbrec_mcast_group_by_name_dp,
                               MC_FLOOD, op->od->sb);
        const struct sbrec_multicast_group *sbmc_flood_l2 =
            mcast_group_lookup(lflow_input->sbrec_mcast_group_by_name_dp,
                               MC_FLOOD_L2, op->od->sb);
        const struct sbrec_multicast_group *sbmc_unknown =
            mcast_group_lookup(lflow_input->sbrec_mcast_group_by_name_dp,
                               MC_UNKNOWN, op->od->sb);

        struct ds match = DS_EMPTY_INITIALIZER;
        struct ds actions = DS_EMPTY_INITIALIZER;
        build_lswitch_and_lrouter_iterate_by_lsp(op, lflow_input->ls_ports,
                                                 lflow_input->lr_ports,
                                                 lflow_input->meter_groups,
                                                 &match, &actions, lflows);

        /* Sync the newly added flows to SB. */
        bool handled = lflow_ref_sync_lflows(
            op->lflow_ref, lflows, ovnsb_txn, lflow_input->ls_datapaths,
            lflow_input->lr_datapaths,
            lflow_input->ovn_internal_version_changed,
            lflow_input->sbrec_logical_flow_table,
            lflow_input->sbrec_logical_dp_group_table);
        if (handled) {
            /* Now generate the stateful lflows for 'op' */
            build_lbnat_lflows_iterate_by_lsp(op,
                                              lflow_input->lr_stateful_table,
                                              &match, &actions, lflows);
            handled = lflow_ref_sync_lflows(
                op->stateful_lflow_ref, lflows, ovnsb_txn,
                lflow_input->ls_datapaths,
                lflow_input->lr_datapaths,
                lflow_input->ovn_internal_version_changed,
                lflow_input->sbrec_logical_flow_table,
                lflow_input->sbrec_logical_dp_group_table);
        }

        ds_destroy(&match);
        ds_destroy(&actions);

        if (!handled) {
            return false;
        }

        /* Update SB multicast groups for the new port. */
        if (!sbmc_flood) {
            sbmc_flood = create_sb_multicast_group(ovnsb_txn,
                op->od->sb, MC_FLOOD, OVN_MCAST_FLOOD_TUNNEL_KEY);
        }
        sbrec_multicast_group_update_ports_addvalue(sbmc_flood, op->sb);

        if (!sbmc_flood_l2) {
            sbmc_flood_l2 = create_sb_multicast_group(ovnsb_txn,
                op->od->sb, MC_FLOOD_L2,
                OVN_MCAST_FLOOD_L2_TUNNEL_KEY);
        }
        sbrec_multicast_group_update_ports_addvalue(sbmc_flood_l2, op->sb);

        if (op->has_unknown) {
            if (!sbmc_unknown) {
                sbmc_unknown = create_sb_multicast_group(ovnsb_txn,
                    op->od->sb, MC_UNKNOWN,
                    OVN_MCAST_UNKNOWN_TUNNEL_KEY);
            }
            sbrec_multicast_group_update_ports_addvalue(sbmc_unknown,
                                                        op->sb);
        }
    }

    return true;
}

bool
lflow_handle_northd_lb_changes(struct ovsdb_idl_txn *ovnsb_txn,
                               struct tracked_lbs *trk_lbs,
                               struct lflow_input *lflow_input,
                               struct lflow_table *lflows)
{
    struct ovn_lb_datapaths *lb_dps;
    struct hmapx_node *hmapx_node;
    HMAPX_FOR_EACH (hmapx_node, &trk_lbs->deleted) {
        lb_dps = hmapx_node->data;

        lflow_ref_resync_flows(
            lb_dps->lflow_ref, lflows, ovnsb_txn, lflow_input->ls_datapaths,
            lflow_input->lr_datapaths,
            lflow_input->ovn_internal_version_changed,
            lflow_input->sbrec_logical_flow_table,
            lflow_input->sbrec_logical_dp_group_table);
    }

    HMAPX_FOR_EACH (hmapx_node, &trk_lbs->crupdated) {
        lb_dps = hmapx_node->data;

        /* unlink old lflows. */
        lflow_ref_unlink_lflows(lb_dps->lflow_ref);

        /* Generate new lflows. */
        struct ds match = DS_EMPTY_INITIALIZER;
        struct ds actions = DS_EMPTY_INITIALIZER;

        build_lswitch_arp_nd_service_monitor(lb_dps, lflow_input->ls_ports,
                                             lflow_input->svc_monitor_mac,
                                             lflows, &actions,
                                             &match);
        build_lrouter_defrag_flows_for_lb(lb_dps, lflows,
                                          lflow_input->lr_datapaths, &match);
        build_lrouter_flows_for_lb(lb_dps, lflows,
                                   lflow_input->meter_groups,
                                   lflow_input->lr_datapaths,
                                   lflow_input->lr_stateful_table,
                                   lflow_input->features,
                                   lflow_input->svc_monitor_map,
                                   &match, &actions);
        build_lswitch_flows_for_lb(lb_dps, lflows,
                                   lflow_input->meter_groups,
                                   lflow_input->ls_datapaths,
                                   lflow_input->features,
                                   lflow_input->svc_monitor_map,
                                   &match, &actions);

        ds_destroy(&match);
        ds_destroy(&actions);

        /* Sync the new flows to SB. */
        bool handled = lflow_ref_sync_lflows(
            lb_dps->lflow_ref, lflows, ovnsb_txn, lflow_input->ls_datapaths,
            lflow_input->lr_datapaths,
            lflow_input->ovn_internal_version_changed,
            lflow_input->sbrec_logical_flow_table,
            lflow_input->sbrec_logical_dp_group_table);
        if (!handled) {
            return false;
        }
    }

    return true;
}

bool
lflow_handle_lr_stateful_changes(struct ovsdb_idl_txn *ovnsb_txn,
                                struct lr_stateful_tracked_data *trk_data,
                                struct lflow_input *lflow_input,
                                struct lflow_table *lflows)
{
    struct lr_stateful_record *lr_stateful_rec;
    struct ds actions = DS_EMPTY_INITIALIZER;
    struct ds match = DS_EMPTY_INITIALIZER;
    struct hmapx_node *hmapx_node;
    bool handled = true;

    HMAPX_FOR_EACH (hmapx_node, &trk_data->crupdated) {
        lr_stateful_rec = hmapx_node->data;
        /* Unlink old lflows. */
        lflow_ref_unlink_lflows(lr_stateful_rec->lflow_ref);

        /* Generate new lflows. */
        build_lr_stateful_flows(lr_stateful_rec, lflow_input->lr_datapaths,
                                lflows, lflow_input->ls_ports,
                                lflow_input->lr_ports, &match, &actions,
                                lflow_input->meter_groups,
                                lflow_input->features);

        /* Sync the new flows to SB. */
        handled = lflow_ref_sync_lflows(
            lr_stateful_rec->lflow_ref, lflows, ovnsb_txn,
            lflow_input->ls_datapaths, lflow_input->lr_datapaths,
            lflow_input->ovn_internal_version_changed,
            lflow_input->sbrec_logical_flow_table,
            lflow_input->sbrec_logical_dp_group_table);
        if (!handled) {
            goto exit;
        }

        const struct ovn_datapath *od =
            ovn_datapaths_find_by_index(lflow_input->lr_datapaths,
                                        lr_stateful_rec->lr_index);
        struct ovn_port *op;
        HMAP_FOR_EACH (op, dp_node, &od->ports) {
            lflow_ref_unlink_lflows(op->stateful_lflow_ref);

            build_lbnat_lflows_iterate_by_lrp(op,
                                              lflow_input->lr_stateful_table,
                                              lflow_input->meter_groups,
                                              &match, &actions,
                                              lflows);

            handled = lflow_ref_sync_lflows(
                op->stateful_lflow_ref, lflows, ovnsb_txn,
                lflow_input->ls_datapaths, lflow_input->lr_datapaths,
                lflow_input->ovn_internal_version_changed,
                lflow_input->sbrec_logical_flow_table,
                lflow_input->sbrec_logical_dp_group_table);
            if (!handled) {
                goto exit;
            }

            if (op->peer && op->peer->nbsp) {
                lflow_ref_unlink_lflows(op->peer->stateful_lflow_ref);

                build_lbnat_lflows_iterate_by_lsp(
                    op->peer, lflow_input->lr_stateful_table, &match, &actions,
                    lflows);

                handled = lflow_ref_sync_lflows(
                    op->peer->stateful_lflow_ref, lflows, ovnsb_txn,
                    lflow_input->ls_datapaths, lflow_input->lr_datapaths,
                    lflow_input->ovn_internal_version_changed,
                    lflow_input->sbrec_logical_flow_table,
                    lflow_input->sbrec_logical_dp_group_table);
                if (!handled) {
                    goto exit;
                }
            }
        }
    }

exit:
    ds_destroy(&match);
    ds_destroy(&actions);

    return handled;
}

bool
lflow_handle_ls_stateful_changes(struct ovsdb_idl_txn *ovnsb_txn,
                                struct ls_stateful_tracked_data *trk_data,
                                struct lflow_input *lflow_input,
                                struct lflow_table *lflows)
{
    struct hmapx_node *hmapx_node;

    HMAPX_FOR_EACH (hmapx_node, &trk_data->crupdated) {
        struct ls_stateful_record *ls_stateful_rec = hmapx_node->data;
        const struct ovn_datapath *od =
            ovn_datapaths_find_by_index(lflow_input->ls_datapaths,
                                        ls_stateful_rec->ls_index);
        ovs_assert(od->nbs && uuid_equals(&od->nbs->header_.uuid,
                                          &ls_stateful_rec->nbs_uuid));

        lflow_ref_unlink_lflows(ls_stateful_rec->lflow_ref);

        /* Generate new lflows. */
        build_ls_stateful_flows(ls_stateful_rec, od,
                                lflow_input->ls_port_groups,
                                lflow_input->features,
                                lflow_input->meter_groups,
                                lflows);

        /* Sync the new flows to SB. */
        bool handled = lflow_ref_sync_lflows(
            ls_stateful_rec->lflow_ref, lflows, ovnsb_txn,
            lflow_input->ls_datapaths,
            lflow_input->lr_datapaths,
            lflow_input->ovn_internal_version_changed,
            lflow_input->sbrec_logical_flow_table,
            lflow_input->sbrec_logical_dp_group_table);
        if (!handled) {
            return false;
        }
    }

    return true;
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
sync_mirrors(struct ovsdb_idl_txn *ovnsb_txn,
             const struct nbrec_mirror_table *nbrec_mirror_table,
             const struct sbrec_mirror_table *sbrec_mirror_table)
{
    struct shash sb_mirrors = SHASH_INITIALIZER(&sb_mirrors);

    const struct sbrec_mirror *sb_mirror;
    SBREC_MIRROR_TABLE_FOR_EACH (sb_mirror, sbrec_mirror_table) {
        shash_add(&sb_mirrors, sb_mirror->name, sb_mirror);
    }

    const struct nbrec_mirror *nb_mirror;
    NBREC_MIRROR_TABLE_FOR_EACH (nb_mirror, nbrec_mirror_table) {
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
sync_dns_entries(struct ovsdb_idl_txn *ovnsb_txn,
                 const struct sbrec_dns_table *sbrec_dns_table,
                 struct hmap *ls_datapaths)
{
    struct hmap dns_map = HMAP_INITIALIZER(&dns_map);
    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, ls_datapaths) {
        ovs_assert(od->nbs);
        if (!od->nbs->n_dns_records) {
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
    SBREC_DNS_TABLE_FOR_EACH_SAFE (sbrec_dns, sbrec_dns_table) {
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

        /* Copy DNS options to SB*/
        struct smap options = SMAP_INITIALIZER(&options);
        if (!smap_is_empty(&dns_info->sb_dns->options)) {
            smap_clone(&options, &dns_info->sb_dns->options);
        }

        bool ovn_owned = smap_get_bool(&dns_info->nb_dns->options,
                                       "ovn-owned", false);
        smap_replace(&options, "ovn-owned",
                 ovn_owned? "true" : "false");
        sbrec_dns_set_options(dns_info->sb_dns, &options);
        smap_destroy(&options);

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
sync_template_vars(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct nbrec_chassis_template_var_table *nbrec_ch_template_var_table,
    const struct sbrec_chassis_template_var_table *sbrec_ch_template_var_table)
{
    struct shash nb_tvs = SHASH_INITIALIZER(&nb_tvs);

    const struct nbrec_chassis_template_var *nb_tv;
    const struct sbrec_chassis_template_var *sb_tv;

    NBREC_CHASSIS_TEMPLATE_VAR_TABLE_FOR_EACH (
            nb_tv, nbrec_ch_template_var_table) {
        shash_add(&nb_tvs, nb_tv->chassis, nb_tv);
    }

    SBREC_CHASSIS_TEMPLATE_VAR_TABLE_FOR_EACH_SAFE (
            sb_tv, sbrec_ch_template_var_table) {
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
build_ip_mcast(struct ovsdb_idl_txn *ovnsb_txn,
               const struct sbrec_ip_multicast_table *sbrec_ip_multicast_table,
               struct ovsdb_idl_index *sbrec_ip_mcast_by_dp,
               struct hmap *ls_datapaths)
{
    struct ovn_datapath *od;

    HMAP_FOR_EACH (od, key_node, ls_datapaths) {
        ovs_assert(od->nbs);

        const struct sbrec_ip_multicast *ip_mcast =
            ip_mcast_lookup(sbrec_ip_mcast_by_dp, od->sb);

        if (!ip_mcast) {
            ip_mcast = sbrec_ip_multicast_insert(ovnsb_txn);
        }
        store_mcast_info_for_switch_datapath(ip_mcast, od);
    }

    /* Delete southbound records without northbound matches. */
    const struct sbrec_ip_multicast *sb;

    SBREC_IP_MULTICAST_TABLE_FOR_EACH_SAFE (sb, sbrec_ip_multicast_table) {
        od = ovn_datapath_from_sbrec(ls_datapaths, NULL, sb->datapath);
        if (!od || ovn_datapath_is_stale(od)) {
            sbrec_ip_multicast_delete(sb);
        }
    }
}

static void
build_mcast_groups(const struct sbrec_igmp_group_table *sbrec_igmp_group_table,
                   struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp,
                   const struct ovn_datapaths *ls_datapaths,
                   const struct hmap *ls_ports,
                   const struct hmap *lr_ports,
                   struct hmap *mcast_groups,
                   struct hmap *igmp_groups)
{
    struct ovn_port *op;

    hmap_init(mcast_groups);
    hmap_init(igmp_groups);
    struct ovn_datapath *od;

    HMAP_FOR_EACH (od, key_node, &ls_datapaths->datapaths) {
        init_mcast_flow_count(od);
    }

    HMAP_FOR_EACH (op, key_node, lr_ports) {
        if (lrport_is_enabled(op->nbrp)) {
            /* If this port is configured to always flood multicast traffic
             * add it to the MC_STATIC group.
             */
            if (op->mcast_info.flood) {
                ovn_multicast_add(mcast_groups, &mc_static, op);
                op->od->mcast_info.rtr.flood_static = true;
            }
        }
    }

    HMAP_FOR_EACH (op, key_node, ls_ports) {
        if (lsp_is_enabled(op->nbsp)) {
            ovn_multicast_add(mcast_groups, &mc_flood, op);

            if (!lsp_is_router(op->nbsp)) {
                ovn_multicast_add(mcast_groups, &mc_flood_l2, op);
            }

            if (op->has_unknown) {
                ovn_multicast_add(mcast_groups, &mc_unknown, op);
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

    SBREC_IGMP_GROUP_TABLE_FOR_EACH_SAFE (sb_igmp, sbrec_igmp_group_table) {
        /* If this is a stale group (e.g., controller had crashed,
         * purge it).
         */
        if (!sb_igmp->chassis || !sb_igmp->datapath) {
            sbrec_igmp_group_delete(sb_igmp);
            continue;
        }

        /* If the datapath value is stale, purge the group. */
        od = ovn_datapath_from_sbrec(&ls_datapaths->datapaths, NULL,
                                     sb_igmp->datapath);

        if (!od || ovn_datapath_is_stale(od)) {
            sbrec_igmp_group_delete(sb_igmp);
            continue;
        }

        struct in6_addr group_address;
        if (!strcmp(sb_igmp->address, OVN_IGMP_GROUP_MROUTERS)) {
            /* Use all-zeros IP to denote a group corresponding to mrouters. */
            memset(&group_address, 0, sizeof group_address);
        } else if (!ip46_parse(sb_igmp->address, &group_address)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "invalid IGMP group address: %s",
                         sb_igmp->address);
            continue;
        }

        /* Extract the IGMP group ports from the SB entry. */
        size_t n_igmp_ports;
        struct ovn_port **igmp_ports =
            ovn_igmp_group_get_ports(sb_igmp, &n_igmp_ports, ls_ports);

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
            ovn_igmp_group_add(sbrec_mcast_group_by_name_dp, igmp_groups, od,
                               &group_address, sb_igmp->address);

        /* Add the extracted ports to the IGMP group. */
        ovn_igmp_group_add_entry(igmp_group, igmp_ports, n_igmp_ports);
    }

    /* Build IGMP groups for multicast routers with relay enabled. The router
     * IGMP groups are based on the groups learnt by their multicast enabled
     * peers.
     */
    HMAP_FOR_EACH (od, key_node, &ls_datapaths->datapaths) {

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
                    ovn_igmp_group_add(sbrec_mcast_group_by_name_dp,
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

static const struct nbrec_static_mac_binding *
static_mac_binding_by_port_ip(
    const struct nbrec_static_mac_binding_table *nbrec_static_mb_table,
    const char *logical_port, const char *ip)
{
    const struct nbrec_static_mac_binding *nb_smb = NULL;

    NBREC_STATIC_MAC_BINDING_TABLE_FOR_EACH (nb_smb, nbrec_static_mb_table) {
        if (!strcmp(nb_smb->logical_port, logical_port) &&
            !strcmp(nb_smb->ip, ip)) {
            break;
        }
    }

    return nb_smb;
}

static void
build_static_mac_binding_table(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct nbrec_static_mac_binding_table *nbrec_static_mb_table,
    const struct sbrec_static_mac_binding_table *sbrec_static_mb_table,
    struct ovsdb_idl_index *sbrec_static_mac_binding_by_lport_ip,
    struct hmap *lr_ports)
{
    /* Cleanup SB Static_MAC_Binding entries which do not have corresponding
     * NB Static_MAC_Binding entries. */
    const struct nbrec_static_mac_binding *nb_smb;
    const struct sbrec_static_mac_binding *sb_smb;
    SBREC_STATIC_MAC_BINDING_TABLE_FOR_EACH_SAFE (sb_smb,
        sbrec_static_mb_table) {
        nb_smb = static_mac_binding_by_port_ip(nbrec_static_mb_table,
                                               sb_smb->logical_port,
                                               sb_smb->ip);
        if (!nb_smb) {
            sbrec_static_mac_binding_delete(sb_smb);
        }
    }

    /* Create/Update SB Static_MAC_Binding entries with corresponding values
     * from NB Static_MAC_Binding entries. */
    NBREC_STATIC_MAC_BINDING_TABLE_FOR_EACH (
        nb_smb, nbrec_static_mb_table) {
        struct ovn_port *op = ovn_port_find(lr_ports, nb_smb->logical_port);
        if (op && op->nbrp) {
            struct ovn_datapath *od = op->od;
            if (od && od->sb) {
                const struct sbrec_static_mac_binding *mb =
                    static_mac_binding_lookup(
                        sbrec_static_mac_binding_by_lport_ip,
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

static void
ovn_datapaths_init(struct ovn_datapaths *datapaths)
{
    hmap_init(&datapaths->datapaths);
    datapaths->array = NULL;
}

static void
ovn_datapaths_destroy(struct ovn_datapaths *datapaths)
{
    struct ovn_datapath *dp;
    HMAP_FOR_EACH_SAFE (dp, key_node, &datapaths->datapaths) {
        ovn_datapath_destroy(&datapaths->datapaths, dp);
    }
    hmap_destroy(&datapaths->datapaths);

    free(datapaths->array);
    datapaths->array = NULL;
}

static void
destroy_datapaths_and_ports(struct ovn_datapaths *ls_datapaths,
                            struct ovn_datapaths *lr_datapaths,
                            struct hmap *ls_ports, struct hmap *lr_ports,
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
            hmapx_destroy(&lr_group->tmp_ha_ref_chassis);
            free(lr_group);
        }
    }

    struct ovn_port *port;
    HMAP_FOR_EACH_SAFE (port, key_node, ls_ports) {
        ovn_port_destroy(ls_ports, port);
    }
    hmap_destroy(ls_ports);

    HMAP_FOR_EACH_SAFE (port, key_node, lr_ports) {
        ovn_port_destroy(lr_ports, port);
    }
    hmap_destroy(lr_ports);

    ovn_datapaths_destroy(ls_datapaths);
    ovn_datapaths_destroy(lr_datapaths);
}

void
northd_init(struct northd_data *data)
{
    ovn_datapaths_init(&data->ls_datapaths);
    ovn_datapaths_init(&data->lr_datapaths);
    hmap_init(&data->ls_ports);
    hmap_init(&data->lr_ports);
    hmap_init(&data->lb_datapaths_map);
    hmap_init(&data->lb_group_datapaths_map);
    ovs_list_init(&data->lr_list);
    sset_init(&data->svc_monitor_lsps);
    hmap_init(&data->svc_monitor_map);
    init_northd_tracked_data(data);
}

void
northd_destroy(struct northd_data *data)
{
    struct ovn_lb_datapaths *lb_dps;
    HMAP_FOR_EACH_POP (lb_dps, hmap_node, &data->lb_datapaths_map) {
        ovn_lb_datapaths_destroy(lb_dps);
    }
    hmap_destroy(&data->lb_datapaths_map);

    struct ovn_lb_group_datapaths *lb_group_dps;
    HMAP_FOR_EACH_POP (lb_group_dps, hmap_node,
                       &data->lb_group_datapaths_map) {
        ovn_lb_group_datapaths_destroy(lb_group_dps);
    }
    hmap_destroy(&data->lb_group_datapaths_map);

    struct service_monitor_info *mon_info;
    HMAP_FOR_EACH_POP (mon_info, hmap_node, &data->svc_monitor_map) {
        free(mon_info);
    }
    hmap_destroy(&data->svc_monitor_map);

    /* XXX Having to explicitly clean up macam here
     * is a bit strange. We don't explicitly initialize
     * macam in this module, but this is the logical place
     * to clean it up. Ideally, more IPAM logic can be factored
     * out of ovn-northd and this can be taken care of there
     * as well.
     */
    cleanup_macam();

    destroy_datapaths_and_ports(&data->ls_datapaths, &data->lr_datapaths,
                                &data->ls_ports, &data->lr_ports,
                                &data->lr_list);

    sset_destroy(&data->svc_monitor_lsps);
    destroy_northd_tracked_data(data);
}

void
ovnnb_db_run(struct northd_input *input_data,
             struct northd_data *data,
             struct ovsdb_idl_txn *ovnnb_txn,
             struct ovsdb_idl_txn *ovnsb_txn)
{
    if (!ovnsb_txn || !ovnnb_txn) {
        return;
    }
    stopwatch_start(BUILD_LFLOWS_CTX_STOPWATCH_NAME, time_msec());

    use_ct_inv_match = smap_get_bool(input_data->nb_options,
                                     "use_ct_inv_match", true);

    /* deprecated, use --event instead */
    controller_event_en = smap_get_bool(input_data->nb_options,
                                        "controller_event", false);
    check_lsp_is_up = !smap_get_bool(input_data->nb_options,
                                     "ignore_lsp_down", true);
    default_acl_drop = smap_get_bool(input_data->nb_options,
                                     "default_acl_drop", false);

    install_ls_lb_from_router = smap_get_bool(input_data->nb_options,
                                              "install_ls_lb_from_router",
                                              false);
    use_common_zone = smap_get_bool(input_data->nb_options, "use_common_zone",
                                    false);

    build_datapaths(ovnsb_txn,
                    input_data->nbrec_logical_switch_table,
                    input_data->nbrec_logical_router_table,
                    input_data->sbrec_datapath_binding_table,
                    input_data->sbrec_chassis_table,
                    &data->ls_datapaths,
                    &data->lr_datapaths, &data->lr_list);
    build_lb_datapaths(input_data->lbs, input_data->lbgrps,
                       &data->ls_datapaths, &data->lr_datapaths,
                       &data->lb_datapaths_map, &data->lb_group_datapaths_map);
    build_ports(ovnsb_txn,
                input_data->sbrec_port_binding_table,
                input_data->sbrec_chassis_table,
                input_data->sbrec_mirror_table,
                input_data->sbrec_mac_binding_table,
                input_data->sbrec_ha_chassis_group_table,
                input_data->sbrec_chassis_by_name,
                input_data->sbrec_chassis_by_hostname,
                input_data->sbrec_ha_chassis_grp_by_name,
                &data->ls_datapaths.datapaths, &data->lr_datapaths.datapaths,
                &data->ls_ports, &data->lr_ports);
    build_lb_port_related_data(ovnsb_txn,
                               input_data->sbrec_service_monitor_table,
                               input_data->svc_monitor_mac,
                               &input_data->svc_monitor_mac_ea,
                               &data->lr_datapaths, &data->ls_ports,
                               &data->lb_datapaths_map,
                               &data->lb_group_datapaths_map,
                               &data->svc_monitor_lsps,
                               &data->svc_monitor_map);
    build_lb_count_dps(&data->lb_datapaths_map,
                       ods_size(&data->ls_datapaths),
                       ods_size(&data->lr_datapaths));
    build_ipam(&data->ls_datapaths.datapaths, &data->ls_ports);
    build_lrouter_groups(&data->lr_ports, &data->lr_list);
    build_ip_mcast(ovnsb_txn, input_data->sbrec_ip_multicast_table,
                   input_data->sbrec_ip_mcast_by_dp,
                   &data->ls_datapaths.datapaths);
    build_static_mac_binding_table(ovnsb_txn,
        input_data->nbrec_static_mac_binding_table,
        input_data->sbrec_static_mac_binding_table,
        input_data->sbrec_static_mac_binding_by_lport_ip,
        &data->lr_ports);
    stopwatch_stop(BUILD_LFLOWS_CTX_STOPWATCH_NAME, time_msec());
    stopwatch_start(CLEAR_LFLOWS_CTX_STOPWATCH_NAME, time_msec());

    sync_mirrors(ovnsb_txn, input_data->nbrec_mirror_table,
                 input_data->sbrec_mirror_table);
    sync_dns_entries(ovnsb_txn, input_data->sbrec_dns_table,
                     &data->ls_datapaths.datapaths);
    sync_template_vars(ovnsb_txn, input_data->nbrec_chassis_template_var_table,
                       input_data->sbrec_chassis_template_var_table);

    cleanup_stale_fdb_entries(input_data->sbrec_fdb_table,
                              &data->ls_datapaths.datapaths);
    stopwatch_stop(CLEAR_LFLOWS_CTX_STOPWATCH_NAME, time_msec());

}

/* Stores the set of chassis which references an ha_chassis_group.
 */
struct ha_ref_chassis_info {
    const struct sbrec_ha_chassis_group *ha_chassis_group;
    struct hmapx ref_chassis;
};

static void
add_to_ha_ref_chassis_info(struct ha_ref_chassis_info *ref_ch_info,
                           const struct hmapx *chassis)
{
    if (!hmapx_count(&ref_ch_info->ref_chassis)) {
        hmapx_destroy(&ref_ch_info->ref_chassis);
        hmapx_clone(&ref_ch_info->ref_chassis, chassis);
    } else {
        struct hmapx_node *node;

        HMAPX_FOR_EACH (node, chassis) {
            hmapx_add(&ref_ch_info->ref_chassis, node->data);
        }
    }
}

struct ha_chassis_group_node {
    struct hmap_node hmap_node;
    const struct sbrec_ha_chassis_group *ha_ch_grp;
};

static void
update_sb_ha_group_ref_chassis(
    const struct sbrec_ha_chassis_group_table *sb_ha_ch_grp_table,
    struct shash *ha_ref_chassis_map)
{
    struct hmap ha_ch_grps = HMAP_INITIALIZER(&ha_ch_grps);
    struct ha_chassis_group_node *ha_ch_grp_node;

    /* Initialize a set of all ha_chassis_groups in SB. */
    const struct sbrec_ha_chassis_group *ha_ch_grp;
    SBREC_HA_CHASSIS_GROUP_TABLE_FOR_EACH (ha_ch_grp, sb_ha_ch_grp_table) {
        ha_ch_grp_node = xzalloc(sizeof *ha_ch_grp_node);
        ha_ch_grp_node->ha_ch_grp = ha_ch_grp;
        hmap_insert(&ha_ch_grps, &ha_ch_grp_node->hmap_node,
                    uuid_hash(&ha_ch_grp->header_.uuid));
    }

    /* Update each group and remove it from the set. */
    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, ha_ref_chassis_map) {
        struct ha_ref_chassis_info *ha_ref_info = node->data;
        size_t n = hmapx_count(&ha_ref_info->ref_chassis);
        struct sbrec_chassis **ref_chassis;
        struct hmapx_node *chassis_node;

        ref_chassis = xmalloc(n * sizeof *ref_chassis);

        n = 0;
        HMAPX_FOR_EACH (chassis_node, &ha_ref_info->ref_chassis) {
            ref_chassis[n++] = chassis_node->data;
        }

        sbrec_ha_chassis_group_set_ref_chassis(ha_ref_info->ha_chassis_group,
                                               ref_chassis, n);
        free(ref_chassis);

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
        hmapx_destroy(&ha_ref_info->ref_chassis);
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

/* This function and the next function build_ha_chassis_group_ref_chassis
 * build the reference chassis 'ref_chassis' for each HA chassis group.
 *
 * Suppose a distributed logical router port - lr0-public uses an HA chassis
 * group - hagrp1 and if hagrp1 has 3 ha chassis - gw1, gw2 and gw3.
 * Or
 * If the distributed logical router port - lr0-public has 3 gateway chassis -
 * gw1, gw2 and gw3.
 *
 * ovn-northd creates ha chassis group - hagrp1 in SB DB and adds gw1, gw2 and
 * gw3 to its ha_chassis list.
 *
 * If port binding 'sb' represents a logical switch port 'p1' and its logical
 * switch is connected to the logical router 'lr0' directly or indirectly (i.e
 * p1's logical switch is connected to a router 'lr1' and 'lr1' has a path to
 * lr0 via transit logical switches) and 'sb' is claimed by chassis - 'c1' then
 * this function adds c1 to the 'tmp_ha_ref_chassis' of lr_group, and later the
 * function build_ha_chassis_group_ref_chassis will add these chassis to the
 * list of the reference chassis - 'ref_chassis' of hagrp1.
 */
static void
collect_lr_groups_for_ha_chassis_groups(const struct sbrec_port_binding *sb,
                                        struct ovn_port *op,
                                        struct hmapx *lr_groups)
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

    if (!lr_group || sset_is_empty(&lr_group->ha_chassis_groups)) {
        return;
    }

    hmapx_add(lr_groups, lr_group);
    hmapx_add(&lr_group->tmp_ha_ref_chassis, sb->chassis);
}

static void
build_ha_chassis_group_ref_chassis(struct hmapx *lr_groups,
                                   struct shash *ha_ref_chassis_map)
{
    struct hmapx_node *node;

    HMAPX_FOR_EACH (node, lr_groups) {
        struct lrouter_group *lr_group = node->data;
        const char *ha_group_name;

        SSET_FOR_EACH (ha_group_name, &lr_group->ha_chassis_groups) {
            struct ha_ref_chassis_info *ref_ch_info =
                shash_find_data(ha_ref_chassis_map, ha_group_name);
            ovs_assert(ref_ch_info);

            add_to_ha_ref_chassis_info(ref_ch_info,
                                       &lr_group->tmp_ha_ref_chassis);
        }

        hmapx_destroy(&lr_group->tmp_ha_ref_chassis);
        hmapx_init(&lr_group->tmp_ha_ref_chassis);
    }
}

/* Set the "hosting-chassis" status in the NBDB logical_router_port
 * table indicating which chassis the distributed port is bond to. */
static void
handle_cr_port_binding_changes(const struct sbrec_port_binding *sb,
                struct ovn_port *orp)
{
    const struct nbrec_logical_router_port *nbrec_lrp = orp->l3dgw_port->nbrp;

    if (sb->chassis) {
        nbrec_logical_router_port_update_status_setkey(nbrec_lrp,
                                                       "hosting-chassis",
                                                       sb->chassis->name);
    } else if (smap_get(&nbrec_lrp->status, "hosting-chassis")) {
        nbrec_logical_router_port_update_status_delkey(nbrec_lrp,
                                                       "hosting-chassis");
    }
}

/* Handle changes to the 'chassis' column of the 'Port_Binding' table.  When
 * this column is not empty, it means we need to set the corresponding logical
 * port as 'up' in the northbound DB. */
static void
handle_port_binding_changes(struct ovsdb_idl_txn *ovnsb_txn,
                const struct sbrec_port_binding_table *sb_pb_table,
                const struct sbrec_ha_chassis_group_table *sb_ha_ch_grp_table,
                struct hmap *ls_ports,
                struct hmap *lr_ports,
                struct shash *ha_ref_chassis_map)
{
    struct hmapx lr_groups = HMAPX_INITIALIZER(&lr_groups);
    const struct sbrec_port_binding *sb;
    bool build_ha_chassis_ref = false;

    if (ovnsb_txn) {
        const struct sbrec_ha_chassis_group *ha_ch_grp;
        SBREC_HA_CHASSIS_GROUP_TABLE_FOR_EACH (ha_ch_grp, sb_ha_ch_grp_table) {
            if (ha_ch_grp->n_ha_chassis > 1) {
                struct ha_ref_chassis_info *ref_ch_info;

                ref_ch_info = xzalloc(sizeof *ref_ch_info);
                ref_ch_info->ha_chassis_group = ha_ch_grp;
                hmapx_init(&ref_ch_info->ref_chassis);
                build_ha_chassis_ref = true;
                shash_add(ha_ref_chassis_map, ha_ch_grp->name, ref_ch_info);
            }
        }
    }

    SBREC_PORT_BINDING_TABLE_FOR_EACH (sb, sb_pb_table) {

        struct ovn_port *orp = ovn_port_find(lr_ports, sb->logical_port);

        if (orp && is_cr_port(orp)) {
            handle_cr_port_binding_changes(sb, orp);
            continue;
        }

        struct ovn_port *op = ovn_port_find(ls_ports, sb->logical_port);

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

        /* ovn-controller will update 'Port_Binding.up' only if it was
         * explicitly set to 'false'.
         */
        if (!op->sb->n_up) {
            up = false;
            sbrec_port_binding_set_up(op->sb, &up, 1);
        }

        if (build_ha_chassis_ref && ovnsb_txn && sb->chassis) {
            /* Check and collect the chassis which has claimed this 'sb'
             * in relation to LR groups. */
            collect_lr_groups_for_ha_chassis_groups(sb, op, &lr_groups);
        }
    }

    /* Update ha chassis group's ref_chassis if required. */
    build_ha_chassis_group_ref_chassis(&lr_groups, ha_ref_chassis_map);
    hmapx_destroy(&lr_groups);
}

/* Handle a fairly small set of changes in the southbound database. */
void
ovnsb_db_run(struct ovsdb_idl_txn *ovnnb_txn,
             struct ovsdb_idl_txn *ovnsb_txn,
             const struct sbrec_port_binding_table *sb_pb_table,
             const struct sbrec_ha_chassis_group_table *sb_ha_ch_grp_table,
             struct hmap *ls_ports,
             struct hmap *lr_ports)
{
    if (!ovnnb_txn ||
        !ovsdb_idl_has_ever_connected(ovsdb_idl_txn_get_idl(ovnsb_txn))) {
        return;
    }

    struct shash ha_ref_chassis_map = SHASH_INITIALIZER(&ha_ref_chassis_map);
    handle_port_binding_changes(ovnsb_txn, sb_pb_table, sb_ha_ch_grp_table,
                                ls_ports, lr_ports, &ha_ref_chassis_map);
    if (ovnsb_txn) {
        update_sb_ha_group_ref_chassis(sb_ha_ch_grp_table,
                                       &ha_ref_chassis_map);
    }
    shash_destroy(&ha_ref_chassis_map);

    ovn_update_ipv6_prefix(lr_ports);
}

const struct ovn_datapath *
northd_get_datapath_for_port(const struct hmap *ls_ports,
                             const char *port_name)
{
    const struct ovn_port *op = ovn_port_find(ls_ports, port_name);

    return op ? op->od : NULL;
}
