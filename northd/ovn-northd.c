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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "bitmap.h"
#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "ipam.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "hmapx.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "ovn/lex.h"
#include "lib/chassis-index.h"
#include "lib/ip-mcast-index.h"
#include "lib/mcast-group-index.h"
#include "lib/ovn-l7.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/lb.h"
#include "memory.h"
#include "ovn/actions.h"
#include "ovn/features.h"
#include "ovn/logical-fields.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "svec.h"
#include "stream.h"
#include "stream-ssl.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovn_northd);

static unixctl_cb_func ovn_northd_exit;
static unixctl_cb_func ovn_northd_pause;
static unixctl_cb_func ovn_northd_resume;
static unixctl_cb_func ovn_northd_is_paused;
static unixctl_cb_func ovn_northd_status;
static unixctl_cb_func cluster_state_reset_cmd;

struct northd_context {
    struct ovsdb_idl *ovnnb_idl;
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl_txn *ovnnb_txn;
    struct ovsdb_idl_txn *ovnsb_txn;
    struct ovsdb_idl_index *sbrec_chassis_by_name;
    struct ovsdb_idl_index *sbrec_ha_chassis_grp_by_name;
    struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp;
    struct ovsdb_idl_index *sbrec_ip_mcast_by_dp;
};

struct northd_state {
    bool had_lock;
    bool paused;
};

static const char *ovnnb_db;
static const char *ovnsb_db;
static const char *unixctl_path;

static bool controller_event_en;

static bool check_lsp_is_up;

/* MAC allocated for service monitor usage. Just one mac is allocated
 * for this purpose and ovn-controller's on each chassis will make use
 * of this mac when sending out the packets to monitor the services
 * defined in Service_Monitor Southbound table. Since these packets
 * all locally handled, having just one mac is good enough. */
static char svc_monitor_mac[ETH_ADDR_STRLEN + 1];
static struct eth_addr svc_monitor_mac_ea;

/* Default probe interval for NB and SB DB connections. */
#define DEFAULT_PROBE_INTERVAL_MSEC 5000
static int northd_probe_interval_nb = 0;
static int northd_probe_interval_sb = 0;

#define MAX_OVN_TAGS 4096

/* Pipeline stages. */

/* The two pipelines in an OVN logical flow table. */
enum ovn_pipeline {
    P_IN,                       /* Ingress pipeline. */
    P_OUT                       /* Egress pipeline. */
};

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
    PIPELINE_STAGE(SWITCH, IN,  PORT_SEC_L2,    0, "ls_in_port_sec_l2")   \
    PIPELINE_STAGE(SWITCH, IN,  PORT_SEC_IP,    1, "ls_in_port_sec_ip")   \
    PIPELINE_STAGE(SWITCH, IN,  PORT_SEC_ND,    2, "ls_in_port_sec_nd")   \
    PIPELINE_STAGE(SWITCH, IN,  PRE_ACL,        3, "ls_in_pre_acl")       \
    PIPELINE_STAGE(SWITCH, IN,  PRE_LB,         4, "ls_in_pre_lb")        \
    PIPELINE_STAGE(SWITCH, IN,  PRE_STATEFUL,   5, "ls_in_pre_stateful")  \
    PIPELINE_STAGE(SWITCH, IN,  ACL_HINT,       6, "ls_in_acl_hint")      \
    PIPELINE_STAGE(SWITCH, IN,  ACL,            7, "ls_in_acl")           \
    PIPELINE_STAGE(SWITCH, IN,  QOS_MARK,       8, "ls_in_qos_mark")      \
    PIPELINE_STAGE(SWITCH, IN,  QOS_METER,      9, "ls_in_qos_meter")     \
    PIPELINE_STAGE(SWITCH, IN,  LB,            10, "ls_in_lb")            \
    PIPELINE_STAGE(SWITCH, IN,  STATEFUL,      11, "ls_in_stateful")      \
    PIPELINE_STAGE(SWITCH, IN,  PRE_HAIRPIN,   12, "ls_in_pre_hairpin")   \
    PIPELINE_STAGE(SWITCH, IN,  NAT_HAIRPIN,   13, "ls_in_nat_hairpin")       \
    PIPELINE_STAGE(SWITCH, IN,  HAIRPIN,       14, "ls_in_hairpin")       \
    PIPELINE_STAGE(SWITCH, IN,  ARP_ND_RSP,    15, "ls_in_arp_rsp")       \
    PIPELINE_STAGE(SWITCH, IN,  DHCP_OPTIONS,  16, "ls_in_dhcp_options")  \
    PIPELINE_STAGE(SWITCH, IN,  DHCP_RESPONSE, 17, "ls_in_dhcp_response") \
    PIPELINE_STAGE(SWITCH, IN,  DNS_LOOKUP,    18, "ls_in_dns_lookup")    \
    PIPELINE_STAGE(SWITCH, IN,  DNS_RESPONSE,  19, "ls_in_dns_response")  \
    PIPELINE_STAGE(SWITCH, IN,  EXTERNAL_PORT, 20, "ls_in_external_port") \
    PIPELINE_STAGE(SWITCH, IN,  L2_LKUP,       21, "ls_in_l2_lkup")       \
                                                                          \
    /* Logical switch egress stages. */                                   \
    PIPELINE_STAGE(SWITCH, OUT, PRE_LB,       0, "ls_out_pre_lb")         \
    PIPELINE_STAGE(SWITCH, OUT, PRE_ACL,      1, "ls_out_pre_acl")        \
    PIPELINE_STAGE(SWITCH, OUT, PRE_STATEFUL, 2, "ls_out_pre_stateful")   \
    PIPELINE_STAGE(SWITCH, OUT, LB,           3, "ls_out_lb")             \
    PIPELINE_STAGE(SWITCH, OUT, ACL_HINT,     4, "ls_out_acl_hint")       \
    PIPELINE_STAGE(SWITCH, OUT, ACL,          5, "ls_out_acl")            \
    PIPELINE_STAGE(SWITCH, OUT, QOS_MARK,     6, "ls_out_qos_mark")       \
    PIPELINE_STAGE(SWITCH, OUT, QOS_METER,    7, "ls_out_qos_meter")      \
    PIPELINE_STAGE(SWITCH, OUT, STATEFUL,     8, "ls_out_stateful")       \
    PIPELINE_STAGE(SWITCH, OUT, PORT_SEC_IP,  9, "ls_out_port_sec_ip")    \
    PIPELINE_STAGE(SWITCH, OUT, PORT_SEC_L2, 10, "ls_out_port_sec_l2")    \
                                                                      \
    /* Logical router ingress stages. */                              \
    PIPELINE_STAGE(ROUTER, IN,  ADMISSION,       0, "lr_in_admission")    \
    PIPELINE_STAGE(ROUTER, IN,  LOOKUP_NEIGHBOR, 1, "lr_in_lookup_neighbor") \
    PIPELINE_STAGE(ROUTER, IN,  LEARN_NEIGHBOR,  2, "lr_in_learn_neighbor") \
    PIPELINE_STAGE(ROUTER, IN,  IP_INPUT,        3, "lr_in_ip_input")     \
    PIPELINE_STAGE(ROUTER, IN,  DEFRAG,          4, "lr_in_defrag")       \
    PIPELINE_STAGE(ROUTER, IN,  UNSNAT,          5, "lr_in_unsnat")       \
    PIPELINE_STAGE(ROUTER, IN,  DNAT,            6, "lr_in_dnat")         \
    PIPELINE_STAGE(ROUTER, IN,  ECMP_STATEFUL,   7, "lr_in_ecmp_stateful") \
    PIPELINE_STAGE(ROUTER, IN,  ND_RA_OPTIONS,   8, "lr_in_nd_ra_options") \
    PIPELINE_STAGE(ROUTER, IN,  ND_RA_RESPONSE,  9, "lr_in_nd_ra_response") \
    PIPELINE_STAGE(ROUTER, IN,  IP_ROUTING,      10, "lr_in_ip_routing")   \
    PIPELINE_STAGE(ROUTER, IN,  IP_ROUTING_ECMP, 11, "lr_in_ip_routing_ecmp") \
    PIPELINE_STAGE(ROUTER, IN,  POLICY,          12, "lr_in_policy")       \
    PIPELINE_STAGE(ROUTER, IN,  POLICY_ECMP,     13, "lr_in_policy_ecmp")  \
    PIPELINE_STAGE(ROUTER, IN,  ARP_RESOLVE,     14, "lr_in_arp_resolve")  \
    PIPELINE_STAGE(ROUTER, IN,  CHK_PKT_LEN   ,  15, "lr_in_chk_pkt_len")  \
    PIPELINE_STAGE(ROUTER, IN,  LARGER_PKTS,     16, "lr_in_larger_pkts")  \
    PIPELINE_STAGE(ROUTER, IN,  GW_REDIRECT,     17, "lr_in_gw_redirect")  \
    PIPELINE_STAGE(ROUTER, IN,  ARP_REQUEST,     18, "lr_in_arp_request")  \
                                                                      \
    /* Logical router egress stages. */                               \
    PIPELINE_STAGE(ROUTER, OUT, UNDNAT,    0, "lr_out_undnat")        \
    PIPELINE_STAGE(ROUTER, OUT, SNAT,      1, "lr_out_snat")          \
    PIPELINE_STAGE(ROUTER, OUT, EGR_LOOP,  2, "lr_out_egr_loop")      \
    PIPELINE_STAGE(ROUTER, OUT, DELIVERY,  3, "lr_out_delivery")

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

/* Register definitions for switches and routers. */

/* Indicate that this packet has been recirculated using egress
 * loopback.  This allows certain checks to be bypassed, such as a
 * logical router dropping packets with source IP address equals
 * one of the logical router's own IP addresses. */
#define REGBIT_EGRESS_LOOPBACK  "reg9[0]"
/* Register to store the result of check_pkt_larger action. */
#define REGBIT_PKT_LARGER        "reg9[1]"
#define REGBIT_LOOKUP_NEIGHBOR_RESULT "reg9[2]"
#define REGBIT_LOOKUP_NEIGHBOR_IP_RESULT "reg9[3]"

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

#define FLAGBIT_NOT_VXLAN "flags[1] == 0"

/*
 * OVS register usage:
 *
 * Logical Switch pipeline:
 * +---------+----------------------------------------------+
 * | R0      |     REGBIT_{CONNTRACK/DHCP/DNS/HAIRPIN}      |
 * |         | REGBIT_ACL_HINT_{ALLOW_NEW/ALLOW/DROP/BLOCK} |
 * +---------+----------------------------------------------+
 * | R1 - R9 |                   UNUSED                     |
 * +---------+----------------------------------------------+
 *
 * Logical Router pipeline:
 * +-----+--------------------------+---+-----------------+---+---------------+
 * | R0  | REGBIT_ND_RA_OPTS_RESULT |   |                 |   |               |
 * |     |   (= IN_ND_RA_OPTIONS)   | X |                 |   |               |
 * |     |      NEXT_HOP_IPV4       | R |                 |   |               |
 * |     |      (>= IP_INPUT)       | E | INPORT_ETH_ADDR | X |               |
 * +-----+--------------------------+ G |   (< IP_INPUT)  | X |               |
 * | R1  |   SRC_IPV4 for ARP-REQ   | 0 |                 | R |               |
 * |     |      (>= IP_INPUT)       |   |                 | E | NEXT_HOP_IPV6 |
 * +-----+--------------------------+---+-----------------+ G | (>= IP_INPUT) |
 * | R2  |        UNUSED            | X |                 | 0 |               |
 * |     |                          | R |                 |   |               |
 * +-----+--------------------------+ E |     UNUSED      |   |               |
 * | R3  |        UNUSED            | G |                 |   |               |
 * |     |                          | 1 |                 |   |               |
 * +-----+--------------------------+---+-----------------+---+---------------+
 * | R4  |        UNUSED            | X |                 |   |               |
 * |     |                          | R |                 |   |               |
 * +-----+--------------------------+ E |     UNUSED      | X |               |
 * | R5  |        UNUSED            | G |                 | X |               |
 * |     |                          | 2 |                 | R |SRC_IPV6 for NS|
 * +-----+--------------------------+---+-----------------+ E | (>= IP_INPUT) |
 * | R6  |        UNUSED            | X |                 | G |               |
 * |     |                          | R |                 | 1 |               |
 * +-----+--------------------------+ E |     UNUSED      |   |               |
 * | R7  |        UNUSED            | G |                 |   |               |
 * |     |                          | 3 |                 |   |               |
 * +-----+--------------------------+---+-----------------+---+---------------+
 * | R8  |     ECMP_GROUP_ID        |   |                 |
 * |     |     ECMP_MEMBER_ID       | X |                 |
 * +-----+--------------------------+ R |                 |
 * |     | REGBIT_{                 | E |                 |
 * |     |   EGRESS_LOOPBACK/       | G |     UNUSED      |
 * | R9  |   PKT_LARGER/            | 4 |                 |
 * |     |   LOOKUP_NEIGHBOR_RESULT/|   |                 |
 * |     |   SKIP_LOOKUP_NEIGHBOR}  |   |                 |
 * +-----+--------------------------+---+-----------------+
 *
 */

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
usage(void)
{
    printf("\
%s: OVN northbound management daemon\n\
usage: %s [OPTIONS]\n\
\n\
Options:\n\
  --ovnnb-db=DATABASE       connect to ovn-nb database at DATABASE\n\
                            (default: %s)\n\
  --ovnsb-db=DATABASE       connect to ovn-sb database at DATABASE\n\
                            (default: %s)\n\
  --unixctl=SOCKET          override default control socket name\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_nb_db(), default_sb_db());
    daemon_usage();
    vlog_usage();
    stream_usage("database", true, true, false);
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


/*
 * Multicast snooping and querier per datapath configuration.
 */
struct mcast_switch_info {

    bool enabled;               /* True if snooping enabled. */
    bool querier;               /* True if querier enabled. */
    bool flood_unregistered;    /* True if unregistered multicast should be
                                 * flooded.
                                 */
    bool flood_relay;           /* True if the switch is connected to a
                                 * multicast router and unregistered multicast
                                 * should be flooded to the mrouter. Only
                                 * applicable if flood_unregistered == false.
                                 */
    bool flood_reports;         /* True if the switch has at least one port
                                 * configured to flood reports.
                                 */
    bool flood_static;          /* True if the switch has at least one port
                                 * configured to flood traffic.
                                 */
    int64_t table_size;         /* Max number of IP multicast groups. */
    int64_t idle_timeout;       /* Timeout after which an idle group is
                                 * flushed.
                                 */
    int64_t query_interval;     /* Interval between multicast queries. */
    char *eth_src;              /* ETH src address of the queries. */
    char *ipv4_src;             /* IPv4 src address of the queries. */
    char *ipv6_src;             /* IPv6 src address of the queries. */

    int64_t query_max_response; /* Expected time after which reports should
                                 * be received for queries that were sent out.
                                 */

    uint32_t active_v4_flows;   /* Current number of active IPv4 multicast
                                 * flows.
                                 */
    uint32_t active_v6_flows;   /* Current number of active IPv6 multicast
                                 * flows.
                                 */
};

struct mcast_router_info {
    bool relay;        /* True if the router should relay IP multicast. */
    bool flood_static; /* True if the router has at least one port configured
                        * to flood traffic.
                        */
};

struct mcast_info {

    struct hmap group_tnlids;  /* Group tunnel IDs in use on this DP. */
    uint32_t group_tnlid_hint; /* Hint for allocating next group tunnel ID. */
    struct ovs_list groups;    /* List of groups learnt on this DP. */

    union {
        struct mcast_switch_info sw;  /* Switch specific multicast info. */
        struct mcast_router_info rtr; /* Router specific multicast info. */
    };
};

struct mcast_port_info {
    bool flood;         /* True if the port should flood IP multicast traffic
                         * regardless if it's registered or not. */
    bool flood_reports; /* True if the port should flood IP multicast reports
                         * (e.g., IGMP join/leave). */
};

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

/* The 'key' comes from nbs->header_.uuid or nbr->header_.uuid or
 * sb->external_ids:logical-switch. */
struct ovn_datapath {
    struct hmap_node key_node;  /* Index on 'key'. */
    struct uuid key;            /* (nbs/nbr)->header_.uuid. */

    const struct nbrec_logical_switch *nbs;  /* May be NULL. */
    const struct nbrec_logical_router *nbr;  /* May be NULL. */
    const struct sbrec_datapath_binding *sb; /* May be NULL. */

    struct ovs_list list;       /* In list of similar records. */

    uint32_t tunnel_key;

    /* Logical switch data. */
    struct ovn_port **router_ports;
    size_t n_router_ports;

    struct hmap port_tnlids;
    uint32_t port_key_hint;

    bool has_stateful_acl;
    bool has_lb_vip;
    bool has_unknown;

    /* IPAM data. */
    struct ipam_info ipam_info;

    /* Multicast data. */
    struct mcast_info mcast_info;

    /* OVN northd only needs to know about the logical router gateway port for
     * NAT on a distributed router.  This "distributed gateway port" is
     * populated only when there is a gateway chassis specified for one of
     * the ports on the logical router.  Otherwise this will be NULL. */
    struct ovn_port *l3dgw_port;
    /* The "derived" OVN port representing the instance of l3dgw_port on
     * the gateway chassis. */
    struct ovn_port *l3redirect_port;

    /* NAT entries configured on the router. */
    struct ovn_nat *nat_entries;

    /* SNAT IPs owned by the router (shash of 'struct ovn_snat_ip'). */
    struct shash snat_ips;

    struct lport_addresses dnat_force_snat_addrs;
    struct lport_addresses lb_force_snat_addrs;

    struct ovn_port **localnet_ports;
    size_t n_localnet_ports;

    struct ovs_list lr_list; /* In list of logical router datapaths. */
    /* The logical router group to which this datapath belongs.
     * Valid only if it is logical router datapath. NULL otherwise. */
    struct lrouter_group *lr_group;

    /* Port groups related to the datapath, used only when nbs is NOT NULL. */
    struct hmap nb_pgs;
};

static bool ls_has_stateful_acl(struct ovn_datapath *od);
static bool ls_has_lb_vip(struct ovn_datapath *od);

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
    }
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

    for (size_t i = 0; i < od->nbr->n_nat; i++) {
        destroy_lport_addresses(&od->nat_entries[i].ext_addrs);
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
        destroy_nat_entries(od);
        free(od->nat_entries);
        free(od->localnet_ports);
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
ovn_datapath_find(struct hmap *datapaths, const struct uuid *uuid)
{
    struct ovn_datapath *od;

    HMAP_FOR_EACH_WITH_HASH (od, key_node, uuid_hash(uuid), datapaths) {
        if (uuid_equals(uuid, &od->key)) {
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
ovn_datapath_from_sbrec(struct hmap *datapaths,
                        const struct sbrec_datapath_binding *sb)
{
    struct uuid key;

    if (!smap_get_uuid(&sb->external_ids, "logical-switch", &key) &&
        !smap_get_uuid(&sb->external_ids, "logical-router", &key)) {
        return NULL;
    }
    return ovn_datapath_find(datapaths, &key);
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

    mcast_sw_info->active_v4_flows = 0;
    mcast_sw_info->active_v6_flows = 0;
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
join_datapaths(struct northd_context *ctx, struct hmap *datapaths,
               struct ovs_list *sb_only, struct ovs_list *nb_only,
               struct ovs_list *both, struct ovs_list *lr_list)
{
    ovs_list_init(sb_only);
    ovs_list_init(nb_only);
    ovs_list_init(both);

    const struct sbrec_datapath_binding *sb, *sb_next;
    SBREC_DATAPATH_BINDING_FOR_EACH_SAFE (sb, sb_next, ctx->ovnsb_idl) {
        struct uuid key;
        if (!smap_get_uuid(&sb->external_ids, "logical-switch", &key) &&
            !smap_get_uuid(&sb->external_ids, "logical-router", &key)) {
            ovsdb_idl_txn_add_comment(
                ctx->ovnsb_txn,
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
    NBREC_LOGICAL_SWITCH_FOR_EACH (nbs, ctx->ovnnb_idl) {
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
    }

    const struct nbrec_logical_router *nbr;
    NBREC_LOGICAL_ROUTER_FOR_EACH (nbr, ctx->ovnnb_idl) {
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
        ovs_list_push_back(lr_list, &od->lr_list);
    }
}

static bool
is_vxlan_mode(struct ovsdb_idl *ovnsb_idl)
{
    const struct sbrec_chassis *chassis;
    SBREC_CHASSIS_FOR_EACH (chassis, ovnsb_idl) {
        for (int i = 0; i < chassis->n_encaps; i++) {
            if (!strcmp(chassis->encaps[i]->type, "vxlan")) {
                return true;
            }
        }
    }
    return false;
}

static uint32_t
get_ovn_max_dp_key_local(struct northd_context *ctx)
{
    if (is_vxlan_mode(ctx->ovnsb_idl)) {
        /* OVN_MAX_DP_GLOBAL_NUM doesn't apply for vxlan mode. */
        return OVN_MAX_DP_VXLAN_KEY;
    }
    return OVN_MAX_DP_KEY - OVN_MAX_DP_GLOBAL_NUM;
}

static void
ovn_datapath_allocate_key(struct northd_context *ctx,
                          struct hmap *datapaths, struct hmap *dp_tnlids,
                          struct ovn_datapath *od, uint32_t *hint)
{
    if (!od->tunnel_key) {
        od->tunnel_key = ovn_allocate_tnlid(dp_tnlids, "datapath",
                                            OVN_MIN_DP_KEY_LOCAL,
                                            get_ovn_max_dp_key_local(ctx),
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
ovn_datapath_assign_requested_tnl_id(struct hmap *dp_tnlids,
                                     struct ovn_datapath *od)
{
    const struct smap *other_config = (od->nbs
                                       ? &od->nbs->other_config
                                       : &od->nbr->options);
    uint32_t tunnel_key = smap_get_int(other_config, "requested-tnl-key", 0);
    if (tunnel_key) {
        if (ovn_add_tnlid(dp_tnlids, tunnel_key)) {
            od->tunnel_key = tunnel_key;
        } else {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Logical %s %s requests same tunnel key "
                         "%"PRIu32" as another logical switch or router",
                         od->nbs ? "switch" : "router", od->nbs->name,
                         tunnel_key);
        }
    }
}

/* Updates the southbound Datapath_Binding table so that it contains the
 * logical switches and routers specified by the northbound database.
 *
 * Initializes 'datapaths' to contain a "struct ovn_datapath" for every logical
 * switch and router. */
static void
build_datapaths(struct northd_context *ctx, struct hmap *datapaths,
                struct ovs_list *lr_list)
{
    struct ovs_list sb_only, nb_only, both;

    join_datapaths(ctx, datapaths, &sb_only, &nb_only, &both, lr_list);

    /* Assign explicitly requested tunnel ids first. */
    struct hmap dp_tnlids = HMAP_INITIALIZER(&dp_tnlids);
    struct ovn_datapath *od, *next;
    LIST_FOR_EACH (od, list, &both) {
        ovn_datapath_assign_requested_tnl_id(&dp_tnlids, od);
    }
    LIST_FOR_EACH (od, list, &nb_only) {
        ovn_datapath_assign_requested_tnl_id(&dp_tnlids, od);
    }

    /* Keep nonconflicting tunnel IDs that are already assigned. */
    LIST_FOR_EACH (od, list, &both) {
        if (!od->tunnel_key && ovn_add_tnlid(&dp_tnlids, od->sb->tunnel_key)) {
            od->tunnel_key = od->sb->tunnel_key;
        }
    }

    /* Assign new tunnel ids where needed. */
    uint32_t hint = 0;
    LIST_FOR_EACH_SAFE (od, next, list, &both) {
        ovn_datapath_allocate_key(ctx, datapaths, &dp_tnlids, od, &hint);
    }
    LIST_FOR_EACH_SAFE (od, next, list, &nb_only) {
        ovn_datapath_allocate_key(ctx, datapaths, &dp_tnlids, od, &hint);
    }

    /* Sync tunnel ids from nb to sb. */
    LIST_FOR_EACH (od, list, &both) {
        if (od->sb->tunnel_key != od->tunnel_key) {
            sbrec_datapath_binding_set_tunnel_key(od->sb, od->tunnel_key);
        }
        ovn_datapath_update_external_ids(od);
    }
    LIST_FOR_EACH (od, list, &nb_only) {
        od->sb = sbrec_datapath_binding_insert(ctx->ovnsb_txn);
        ovn_datapath_update_external_ids(od);
        sbrec_datapath_binding_set_tunnel_key(od->sb, od->tunnel_key);
    }
    ovn_destroy_tnlids(&dp_tnlids);

    /* Delete southbound records without northbound matches. */
    LIST_FOR_EACH_SAFE (od, next, list, &sb_only) {
        ovs_list_remove(&od->list);
        sbrec_datapath_binding_delete(od->sb);
        ovn_datapath_destroy(datapaths, od);
    }
}

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

    /* Logical port multicast data. */
    struct mcast_port_info mcast_info;

    /* This is ordinarily false.  It is true if and only if this ovn_port is
     * derived from a chassis-redirect port. */
    bool derived;

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
};

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
    op->derived = false;
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
lrport_is_enabled(const struct nbrec_logical_router_port *lrport)
{
    return !lrport->enabled || *lrport->enabled;
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
join_logical_ports(struct northd_context *ctx,
                   struct hmap *datapaths, struct hmap *ports,
                   struct hmap *chassis_qdisc_queues,
                   struct hmap *tag_alloc_table, struct ovs_list *sb_only,
                   struct ovs_list *nb_only, struct ovs_list *both)
{
    ovs_list_init(sb_only);
    ovs_list_init(nb_only);
    ovs_list_init(both);

    const struct sbrec_port_binding *sb;
    SBREC_PORT_BINDING_FOR_EACH (sb, ctx->ovnsb_idl) {
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
                    ovn_port_set_nb(op, nbsp, NULL);
                    ovs_list_remove(&op->list);

                    uint32_t queue_id = smap_get_int(&op->sb->options,
                                                     "qdisc_queue_id", 0);
                    if (queue_id && op->sb->chassis) {
                        add_chassis_queue(
                             chassis_qdisc_queues, &op->sb->chassis->header_.uuid,
                             queue_id);
                    }

                    ovs_list_push_back(both, &op->list);

                    /* This port exists due to a SB binding, but should
                     * not have been initialized fully. */
                    ovs_assert(!op->n_lsp_addrs && !op->n_ps_addrs);
                } else {
                    op = ovn_port_create(ports, nbsp->name, nbsp, NULL, NULL);
                    ovs_list_push_back(nb_only, &op->list);
                }

                if (!strcmp(nbsp->type, "localnet")) {
                   if (od->n_localnet_ports >= n_allocated_localnet_ports) {
                       od->localnet_ports = x2nrealloc(
                           od->localnet_ports, &n_allocated_localnet_ports,
                           sizeof *od->localnet_ports);
                   }
                   od->localnet_ports[od->n_localnet_ports++] = op;
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
                tag_alloc_add_existing_tags(tag_alloc_table, nbsp);
            }
        } else {
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
                    if (od->l3dgw_port || od->l3redirect_port) {
                        static struct vlog_rate_limit rl
                            = VLOG_RATE_LIMIT_INIT(1, 1);
                        VLOG_WARN_RL(&rl, "Bad configuration: multiple "
                                     "distributed gateway ports on logical "
                                     "router %s", od->nbr->name);
                        continue;
                    }

                    char *redirect_name =
                        ovn_chassis_redirect_name(nbrp->name);
                    struct ovn_port *crp = ovn_port_find(ports, redirect_name);
                    if (crp && crp->sb && crp->sb->datapath == od->sb) {
                        crp->derived = true;
                        ovn_port_set_nb(crp, NULL, nbrp);
                        ovs_list_remove(&crp->list);
                        ovs_list_push_back(both, &crp->list);
                    } else {
                        crp = ovn_port_create(ports, redirect_name,
                                              NULL, nbrp, NULL);
                        crp->derived = true;
                        ovs_list_push_back(nb_only, &crp->list);
                    }
                    crp->od = od;
                    free(redirect_name);

                    /* Set l3dgw_port and l3redirect_port in od, for later
                     * use during flow creation. */
                    od->l3dgw_port = op;
                    od->l3redirect_port = crp;
                }
            }
        }
    }

    /* Connect logical router ports, and logical switch ports of type "router",
     * to their peers. */
    struct ovn_port *op;
    HMAP_FOR_EACH (op, key_node, ports) {
        if (op->nbsp && lsp_is_router(op->nbsp) && !op->derived) {
            const char *peer_name = smap_get(&op->nbsp->options, "router-port");
            if (!peer_name) {
                continue;
            }

            struct ovn_port *peer = ovn_port_find(ports, peer_name);
            if (!peer || !peer->nbrp) {
                continue;
            }

            peer->peer = op;
            op->peer = peer;
            op->od->router_ports = xrealloc(
                op->od->router_ports,
                sizeof *op->od->router_ports * (op->od->n_router_ports + 1));
            op->od->router_ports[op->od->n_router_ports++] = op;

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
        } else if (op->nbrp && op->nbrp->peer && !op->derived) {
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

static void
get_router_load_balancer_ips(const struct ovn_datapath *od,
                             struct sset *all_ips_v4, struct sset *all_ips_v6)
{
    if (!od->nbr) {
        return;
    }

    for (int i = 0; i < od->nbr->n_load_balancer; i++) {
        struct nbrec_load_balancer *lb = od->nbr->load_balancer[i];
        struct smap *vips = &lb->vips;
        struct smap_node *node;

        SMAP_FOR_EACH (node, vips) {
            /* node->key contains IP:port or just IP. */
            char *ip_address;
            uint16_t port;
            int addr_family;

            if (!ip_address_and_port_from_lb_key(node->key, &ip_address, &port,
                                                 &addr_family)) {
                continue;
            }

            struct sset *all_ips;
            if (addr_family == AF_INET) {
                all_ips = all_ips_v4;
            } else {
                all_ips = all_ips_v6;
            }

            if (!sset_contains(all_ips, ip_address)) {
                sset_add(all_ips, ip_address);
            }

            free(ip_address);
        }
    }
}

/* Returns an array of strings, each consisting of a MAC address followed
 * by one or more IP addresses, and if the port is a distributed gateway
 * port, followed by 'is_chassis_resident("LPORT_NAME")', where the
 * LPORT_NAME is the name of the L3 redirect port or the name of the
 * logical_port specified in a NAT rule.  These strings include the
 * external IP addresses of all NAT rules defined on that router, and all
 * of the IP addresses used in load balancer VIPs defined on that router.
 *
 * The caller must free each of the n returned strings with free(),
 * and must free the returned array when it is no longer needed. */
static char **
get_nat_addresses(const struct ovn_port *op, size_t *n)
{
    size_t n_nats = 0;
    struct eth_addr mac;
    if (!op->nbrp || !op->od || !op->od->nbr
        || (!op->od->nbr->n_nat && !op->od->nbr->n_load_balancer)
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

        char *error = ip_parse_masked(nat->external_ip, &ip, &mask);
        if (error || mask != OVS_BE32_MAX) {
            free(error);
            continue;
        }

        /* Determine whether this NAT rule satisfies the conditions for
         * distributed NAT processing. */
        if (op->od->l3redirect_port && !strcmp(nat->type, "dnat_and_snat")
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

    /* Two sets to hold all load-balancer vips. */
    struct sset all_ips_v4 = SSET_INITIALIZER(&all_ips_v4);
    struct sset all_ips_v6 = SSET_INITIALIZER(&all_ips_v6);
    get_router_load_balancer_ips(op->od, &all_ips_v4, &all_ips_v6);

    const char *ip_address;
    SSET_FOR_EACH (ip_address, &all_ips_v4) {
        ds_put_format(&c_addresses, " %s", ip_address);
        central_ip_address = true;
    }
    SSET_FOR_EACH (ip_address, &all_ips_v6) {
        ds_put_format(&c_addresses, " %s", ip_address);
        central_ip_address = true;
    }
    sset_destroy(&all_ips_v4);
    sset_destroy(&all_ips_v6);

    if (central_ip_address) {
        /* Gratuitous ARP for centralized NAT rules on distributed gateway
         * ports should be restricted to the gateway chassis. */
        if (op->od->l3redirect_port) {
            ds_put_format(&c_addresses, " is_chassis_resident(%s)",
                          op->od->l3redirect_port->json_key);
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
create_sb_ha_chassis(struct northd_context *ctx,
                     const struct sbrec_chassis *chassis,
                     const char *chassis_name, int priority)
{
    struct sbrec_ha_chassis *sb_ha_chassis =
        sbrec_ha_chassis_insert(ctx->ovnsb_txn);
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

    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, &nb_ha_chassis_list) {
        shash_delete(&nb_ha_chassis_list, node);
        changed = true;
    }
    shash_destroy(&nb_ha_chassis_list);

    return changed;
}

static void
sync_ha_chassis_group_for_sbpb(struct northd_context *ctx,
                               const struct nbrec_ha_chassis_group *nb_ha_grp,
                               struct ovsdb_idl_index *sbrec_chassis_by_name,
                               const struct sbrec_port_binding *pb)
{
    bool new_sb_chassis_group = false;
    const struct sbrec_ha_chassis_group *sb_ha_grp =
        ha_chassis_group_lookup_by_name(
            ctx->sbrec_ha_chassis_grp_by_name, nb_ha_grp->name);

    if (!sb_ha_grp) {
        sb_ha_grp = sbrec_ha_chassis_group_insert(ctx->ovnsb_txn);
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
            sb_ha_chassis[i] = sbrec_ha_chassis_insert(ctx->ovnsb_txn);
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
        struct northd_context *ctx,
        struct ovsdb_idl_index *sbrec_chassis_by_name,
        const struct nbrec_logical_router_port *lrp,
        const struct sbrec_port_binding *port_binding)
{

    /* Make use of the new HA chassis group table to support HA
     * for the distributed gateway router port. */
    const struct sbrec_ha_chassis_group *sb_ha_chassis_group =
        ha_chassis_group_lookup_by_name(
            ctx->sbrec_ha_chassis_grp_by_name, lrp->name);
    if (!sb_ha_chassis_group) {
        sb_ha_chassis_group = sbrec_ha_chassis_group_insert(ctx->ovnsb_txn);
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
            create_sb_ha_chassis(ctx, chassis, lrp_gwc->chassis_name,
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

static void
ovn_port_update_sbrec(struct northd_context *ctx,
                      struct ovsdb_idl_index *sbrec_chassis_by_name,
                      const struct ovn_port *op,
                      struct hmap *chassis_qdisc_queues,
                      struct sset *active_ha_chassis_grps)
{
    sbrec_port_binding_set_datapath(op->sb, op->od->sb);
    if (op->nbrp) {
        /* If the router is for l3 gateway, it resides on a chassis
         * and its port type is "l3gateway". */
        const char *chassis_name = smap_get(&op->od->nbr->options, "chassis");
        if (op->derived) {
            sbrec_port_binding_set_type(op->sb, "chassisredirect");
        } else if (chassis_name) {
            sbrec_port_binding_set_type(op->sb, "l3gateway");
        } else {
            sbrec_port_binding_set_type(op->sb, "patch");
        }

        struct smap new;
        smap_init(&new);
        if (op->derived) {
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
                sync_ha_chassis_group_for_sbpb(ctx, op->nbrp->ha_chassis_group,
                                               sbrec_chassis_by_name, op->sb);
                sset_add(active_ha_chassis_grps,
                         op->nbrp->ha_chassis_group->name);
            } else if (op->nbrp->n_gateway_chassis) {
                /* Legacy gateway_chassis support.
                 * Create ha_chassis_group for the Northbound gateway_chassis
                 * associated with the lrp. */
                if (sbpb_gw_chassis_needs_update(op->sb, op->nbrp,
                                                 sbrec_chassis_by_name)) {
                    copy_gw_chassis_from_nbrp_to_sbpb(ctx,
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
            if (redirect_type) {
                smap_add(&new, "redirect-type", redirect_type);
            }
        } else {
            if (op->peer) {
                smap_add(&new, "peer", op->peer->key);
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

        struct smap ids = SMAP_INITIALIZER(&ids);
        sbrec_port_binding_set_external_ids(op->sb, &ids);

        sbrec_port_binding_set_nat_addresses(op->sb, NULL, 0);
    } else {
        if (!lsp_is_router(op->nbsp)) {
            uint32_t queue_id = smap_get_int(
                    &op->sb->options, "qdisc_queue_id", 0);
            bool has_qos = port_has_qos_params(&op->nbsp->options);
            const struct uuid *uuid = NULL;
            struct smap options;
            char *name = "";

            if (!strcmp(op->nbsp->type, "localnet")) {
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
                        ctx, op->nbsp->ha_chassis_group,
                        sbrec_chassis_by_name, op->sb);
                    sset_add(active_ha_chassis_grps,
                             op->nbsp->ha_chassis_group->name);
                } else {
                    sbrec_port_binding_set_ha_chassis_group(op->sb, NULL);
                }
            }
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
            if (nat_addresses && !strcmp(nat_addresses, "router")) {
                if (op->peer && op->peer->od
                    && (chassis || op->peer->od->l3redirect_port)) {
                    nats = get_nat_addresses(op->peer, &n_nats);
                }
            /* Only accept manual specification of ethernet address
             * followed by IPv4 addresses on type "l3gateway" ports. */
            } else if (nat_addresses && chassis) {
                struct lport_addresses laddrs;
                if (!extract_lsp_addresses(nat_addresses, &laddrs)) {
                    static struct vlog_rate_limit rl =
                        VLOG_RATE_LIMIT_INIT(1, 1);
                    VLOG_WARN_RL(&rl, "Error extracting nat-addresses.");
                } else {
                    destroy_lport_addresses(&laddrs);
                    n_nats = 1;
                    nats = xcalloc(1, sizeof *nats);
                    nats[0] = xstrdup(nat_addresses);
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
            if (op->peer && op->peer->nbrp && op->peer->od->l3dgw_port &&
                op->peer->od->l3redirect_port &&
                (smap_get_bool(&op->peer->nbrp->options,
                              "reside-on-redirect-chassis", false) ||
                op->peer == op->peer->od->l3dgw_port)) {
                add_router_port_garp = true;
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

                if (op->peer->od->l3redirect_port) {
                    ds_put_format(&garp_info, " is_chassis_resident(%s)",
                                  op->peer->od->l3redirect_port->json_key);
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

        struct smap ids = SMAP_INITIALIZER(&ids);
        smap_clone(&ids, &op->nbsp->external_ids);
        const char *name = smap_get(&ids, "neutron:port_name");
        if (name && name[0]) {
            smap_add(&ids, "name", name);
        }
        sbrec_port_binding_set_external_ids(op->sb, &ids);
        smap_destroy(&ids);
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
cleanup_mac_bindings(struct northd_context *ctx, struct hmap *datapaths,
                     struct hmap *ports)
{
    const struct sbrec_mac_binding *b, *n;
    SBREC_MAC_BINDING_FOR_EACH_SAFE (b, n, ctx->ovnsb_idl) {
        const struct ovn_datapath *od =
            ovn_datapath_from_sbrec(datapaths, b->datapath);

        if (!od || ovn_datapath_is_stale(od) ||
                !ovn_port_find(ports, b->logical_port)) {
            sbrec_mac_binding_delete(b);
        }
    }
}

static void
cleanup_sb_ha_chassis_groups(struct northd_context *ctx,
                             struct sset *active_ha_chassis_groups)
{
    const struct sbrec_ha_chassis_group *b, *n;
    SBREC_HA_CHASSIS_GROUP_FOR_EACH_SAFE (b, n, ctx->ovnsb_idl) {
        if (!sset_contains(active_ha_chassis_groups, b->name)) {
            sbrec_ha_chassis_group_delete(b);
        }
    }
}

struct service_monitor_info {
    struct hmap_node hmap_node;
    const struct sbrec_service_monitor *sbrec_mon;
    bool required;
};


static struct service_monitor_info *
create_or_get_service_mon(struct northd_context *ctx,
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
        sbrec_service_monitor_insert(ctx->ovnsb_txn);
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
ovn_lb_svc_create(struct northd_context *ctx, struct ovn_northd_lb *lb,
                  struct hmap *monitor_map)
{
    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_lb_vip *lb_vip = &lb->vips[i];
        struct ovn_northd_lb_vip *lb_vip_nb = &lb->vips_nb[i];

        if (!lb_vip_nb->lb_health_check) {
            continue;
        }

        for (size_t j = 0; j < lb_vip->n_backends; j++) {
            struct ovn_lb_backend *backend = &lb_vip->backends[j];
            struct ovn_northd_lb_backend *backend_nb =
                &lb_vip_nb->backends_nb[j];

            if (backend_nb->op && backend_nb->svc_mon_src_ip) {
                const char *protocol = lb->nlb->protocol;
                if (!protocol || !protocol[0]) {
                    protocol = "tcp";
                }
                backend_nb->health_check = true;
                struct service_monitor_info *mon_info =
                    create_or_get_service_mon(ctx, monitor_map,
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

                backend_nb->sbrec_monitor = mon_info->sbrec_mon;
                mon_info->required = true;
            }
        }
    }
}

static
void build_lb_vip_actions(struct ovn_lb_vip *lb_vip,
                          struct ovn_northd_lb_vip *lb_vip_nb,
                          struct ds *action, char *selection_fields,
                          bool ls_dp)
{
    bool skip_hash_fields = false, reject = false;

    if (lb_vip_nb->lb_health_check) {
        ds_put_cstr(action, "ct_lb(backends=");

        size_t n_active_backends = 0;
        for (size_t i = 0; i < lb_vip->n_backends; i++) {
            struct ovn_lb_backend *backend = &lb_vip->backends[i];
            struct ovn_northd_lb_backend *backend_nb =
                &lb_vip_nb->backends_nb[i];
            if (backend_nb->health_check && backend_nb->sbrec_monitor &&
                backend_nb->sbrec_monitor->status &&
                strcmp(backend_nb->sbrec_monitor->status, "online")) {
                continue;
            }

            n_active_backends++;
            ds_put_format(action, "%s:%"PRIu16",",
                          backend->ip_str, backend->port);
        }

        if (!n_active_backends) {
            if (!lb_vip->empty_backend_rej) {
                ds_clear(action);
                ds_put_cstr(action, "drop;");
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
        ds_put_format(action, "ct_lb(backends=%s);", lb_vip_nb->backend_ips);
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
}

static void
build_ovn_lbs(struct northd_context *ctx, struct hmap *datapaths,
              struct hmap *ports, struct hmap *lbs)
{
    hmap_init(lbs);
    struct hmap monitor_map = HMAP_INITIALIZER(&monitor_map);

    const struct sbrec_service_monitor *sbrec_mon;
    SBREC_SERVICE_MONITOR_FOR_EACH (sbrec_mon, ctx->ovnsb_idl) {
        uint32_t hash = sbrec_mon->port;
        hash = hash_string(sbrec_mon->ip, hash);
        hash = hash_string(sbrec_mon->logical_port, hash);
        struct service_monitor_info *mon_info = xzalloc(sizeof *mon_info);
        mon_info->sbrec_mon = sbrec_mon;
        mon_info->required = false;
        hmap_insert(&monitor_map, &mon_info->hmap_node, hash);
    }

    const struct nbrec_load_balancer *nbrec_lb;
    NBREC_LOAD_BALANCER_FOR_EACH (nbrec_lb, ctx->ovnnb_idl) {
        struct ovn_northd_lb *lb =
            ovn_northd_lb_create(nbrec_lb, ports, (void *)ovn_port_find);
        hmap_insert(lbs, &lb->hmap_node, uuid_hash(&nbrec_lb->header_.uuid));
    }

    struct ovn_northd_lb *lb;
    HMAP_FOR_EACH (lb, hmap_node, lbs) {
        ovn_lb_svc_create(ctx, lb, &monitor_map);
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

            ovn_northd_lb_add_datapath(lb, od->sb);
        }
    }

    /* Delete any stale SB load balancer rows. */
    const struct sbrec_load_balancer *sbrec_lb, *next;
    SBREC_LOAD_BALANCER_FOR_EACH_SAFE (sbrec_lb, next, ctx->ovnsb_idl) {
        const char *nb_lb_uuid = smap_get(&sbrec_lb->external_ids, "lb_id");
        struct uuid lb_uuid;
        if (!nb_lb_uuid || !uuid_from_string(&lb_uuid, nb_lb_uuid)) {
            sbrec_load_balancer_delete(sbrec_lb);
            continue;
        }

        lb = ovn_northd_lb_find(lbs, &lb_uuid);
        if (lb && lb->n_dps) {
            lb->slb = sbrec_lb;
        } else {
            sbrec_load_balancer_delete(sbrec_lb);
        }
    }

    /* Create SB Load balancer records if not present and sync
     * the SB load balancer columns. */
    HMAP_FOR_EACH (lb, hmap_node, lbs) {
        if (!lb->n_dps) {
            continue;
        }

        if (!lb->slb) {
            sbrec_lb = sbrec_load_balancer_insert(ctx->ovnsb_txn);
            lb->slb = sbrec_lb;
            char *lb_id = xasprintf(
                UUID_FMT, UUID_ARGS(&lb->nlb->header_.uuid));
            const struct smap external_ids =
                SMAP_CONST1(&external_ids, "lb_id", lb_id);
            sbrec_load_balancer_set_external_ids(sbrec_lb, &external_ids);
            free(lb_id);
        }
        sbrec_load_balancer_set_name(lb->slb, lb->nlb->name);
        sbrec_load_balancer_set_vips(lb->slb, &lb->nlb->vips);
        sbrec_load_balancer_set_protocol(lb->slb, lb->nlb->protocol);
        sbrec_load_balancer_set_options(lb->slb, &lb->nlb->options);
        sbrec_load_balancer_set_datapaths(
            lb->slb, (struct sbrec_datapath_binding **)lb->dps,
            lb->n_dps);
    }

    /* Set the list of associated load balanacers to a logical switch
     * datapath binding in the SB DB. */
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbs) {
            continue;
        }

        const struct sbrec_load_balancer **sbrec_lbs =
            xmalloc(od->nbs->n_load_balancer * sizeof *sbrec_lbs);
        for (size_t i = 0; i < od->nbs->n_load_balancer; i++) {
            const struct uuid *lb_uuid =
                &od->nbs->load_balancer[i]->header_.uuid;
            lb = ovn_northd_lb_find(lbs, lb_uuid);
            sbrec_lbs[i] = lb->slb;
        }

        sbrec_datapath_binding_set_load_balancers(
            od->sb, (struct sbrec_load_balancer **)sbrec_lbs,
            od->nbs->n_load_balancer);
        free(sbrec_lbs);
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
ovn_port_assign_requested_tnl_id(struct ovn_port *op)
{
    const struct smap *options = (op->nbsp
                                  ? &op->nbsp->options
                                  : &op->nbrp->options);
    uint32_t tunnel_key = smap_get_int(options, "requested-tnl-key", 0);
    if (tunnel_key && !ovn_port_add_tnlid(op, tunnel_key)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "Logical %s port %s requests same tunnel key "
                     "%"PRIu32" as another LSP or LRP",
                     op->nbsp ? "switch" : "router",
                     op_get_name(op), tunnel_key);
    }
}

static void
ovn_port_allocate_key(struct hmap *ports, struct ovn_port *op)
{
    if (!op->tunnel_key) {
        op->tunnel_key = ovn_allocate_tnlid(&op->od->port_tnlids, "port",
                                            1, (1u << 15) - 1,
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
build_ports(struct northd_context *ctx,
            struct ovsdb_idl_index *sbrec_chassis_by_name,
            struct hmap *datapaths, struct hmap *ports)
{
    struct ovs_list sb_only, nb_only, both;
    struct hmap tag_alloc_table = HMAP_INITIALIZER(&tag_alloc_table);
    struct hmap chassis_qdisc_queues = HMAP_INITIALIZER(&chassis_qdisc_queues);

    /* sset which stores the set of ha chassis group names used. */
    struct sset active_ha_chassis_grps =
        SSET_INITIALIZER(&active_ha_chassis_grps);

    join_logical_ports(ctx, datapaths, ports, &chassis_qdisc_queues,
                       &tag_alloc_table, &sb_only, &nb_only, &both);

    /* Purge stale Mac_Bindings if ports are deleted. */
    bool remove_mac_bindings = !ovs_list_is_empty(&sb_only);

    /* Assign explicitly requested tunnel ids first. */
    struct ovn_port *op, *next;
    LIST_FOR_EACH (op, list, &both) {
        ovn_port_assign_requested_tnl_id(op);
    }
    LIST_FOR_EACH (op, list, &nb_only) {
        ovn_port_assign_requested_tnl_id(op);
    }

    /* Keep nonconflicting tunnel IDs that are already assigned. */
    LIST_FOR_EACH (op, list, &both) {
        if (!op->tunnel_key) {
            ovn_port_add_tnlid(op, op->sb->tunnel_key);
        }
    }

    /* Assign new tunnel ids where needed. */
    LIST_FOR_EACH_SAFE (op, next, list, &both) {
        ovn_port_allocate_key(ports, op);
    }
    LIST_FOR_EACH_SAFE (op, next, list, &nb_only) {
        ovn_port_allocate_key(ports, op);
    }

    /* For logical ports that are in both databases, update the southbound
     * record based on northbound data.
     * For logical ports that are in NB database, do any tag allocation
     * needed. */
    LIST_FOR_EACH_SAFE (op, next, list, &both) {
        /* When reusing stale Port_Bindings, make sure that stale
         * Mac_Bindings are purged.
         */
        if (op->od->sb != op->sb->datapath) {
            remove_mac_bindings = true;
        }
        if (op->nbsp) {
            tag_alloc_create_new_tag(&tag_alloc_table, op->nbsp);
        }
        ovn_port_update_sbrec(ctx, sbrec_chassis_by_name,
                              op, &chassis_qdisc_queues,
                              &active_ha_chassis_grps);
    }

    /* Add southbound record for each unmatched northbound record. */
    LIST_FOR_EACH_SAFE (op, next, list, &nb_only) {
        op->sb = sbrec_port_binding_insert(ctx->ovnsb_txn);
        ovn_port_update_sbrec(ctx, sbrec_chassis_by_name, op,
                              &chassis_qdisc_queues,
                              &active_ha_chassis_grps);
        sbrec_port_binding_set_logical_port(op->sb, op->key);
    }

    /* Delete southbound records without northbound matches. */
    if (!ovs_list_is_empty(&sb_only)) {
        LIST_FOR_EACH_SAFE (op, next, list, &sb_only) {
            ovs_list_remove(&op->list);
            sbrec_port_binding_delete(op->sb);
            ovn_port_destroy(ports, op);
        }
    }
    if (remove_mac_bindings) {
        cleanup_mac_bindings(ctx, datapaths, ports);
    }

    tag_alloc_destroy(&tag_alloc_table);
    destroy_chassis_queues(&chassis_qdisc_queues);
    cleanup_sb_ha_chassis_groups(ctx, &active_ha_chassis_grps);
    sset_destroy(&active_ha_chassis_grps);
}

/* XXX: The 'ovn_lflow_add_unique*()' functions should be used for logical
 *      flows using a multicast group.
 *      See the comment on 'ovn_lflow_add_unique()' for details. */
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

#define MC_MROUTER_STATIC "_MC_mrouter_static"
static const struct multicast_group mc_mrouter_static =
    { MC_MROUTER_STATIC, OVN_MCAST_MROUTER_STATIC_TUNNEL_KEY };

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
ovn_igmp_group_add(struct northd_context *ctx, struct hmap *igmp_groups,
                   struct ovn_datapath *datapath,
                   const struct in6_addr *address,
                   const char *address_s)
{
    struct ovn_igmp_group *igmp_group =
        ovn_igmp_group_find(igmp_groups, datapath, address);

    if (!igmp_group) {
        igmp_group = xmalloc(sizeof *igmp_group);

        const struct sbrec_multicast_group *mcgroup =
            mcast_group_lookup(ctx->sbrec_mcast_group_by_name_dp, address_s,
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
                         size_t *n_ports, struct hmap *ovn_ports)
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
    struct hmapx od_group;       /* Hash map of 'struct ovn_datapath *'. */
    enum ovn_stage stage;
    uint16_t priority;
    char *match;
    char *actions;
    char *stage_hint;
    const char *where;
};

static void ovn_lflow_destroy(struct hmap *lflows, struct ovn_lflow *lflow);
static struct ovn_lflow * ovn_lflow_find_by_lflow(const struct hmap *,
                                                  const struct ovn_lflow *,
                                                  uint32_t hash);

static uint32_t
ovn_lflow_hash(const struct ovn_lflow *lflow)
{
    return ovn_logical_flow_hash(ovn_stage_get_table(lflow->stage),
                                 ovn_stage_get_pipeline_name(lflow->stage),
                                 lflow->priority, lflow->match,
                                 lflow->actions);
}

static char *
ovn_lflow_hint(const struct ovsdb_idl_row *row)
{
    if (!row) {
        return NULL;
    }
    return xasprintf("%08x", row->uuid.parts[0]);
}

static bool
ovn_lflow_equal(const struct ovn_lflow *a, const struct ovn_lflow *b)
{
    return (a->od == b->od
            && a->stage == b->stage
            && a->priority == b->priority
            && !strcmp(a->match, b->match)
            && !strcmp(a->actions, b->actions));
}

static void
ovn_lflow_init(struct ovn_lflow *lflow, struct ovn_datapath *od,
               enum ovn_stage stage, uint16_t priority,
               char *match, char *actions, char *stage_hint,
               const char *where)
{
    hmapx_init(&lflow->od_group);
    lflow->od = od;
    lflow->stage = stage;
    lflow->priority = priority;
    lflow->match = match;
    lflow->actions = actions;
    lflow->stage_hint = stage_hint;
    lflow->where = where;
}

/* If this option is 'true' northd will combine logical flows that differs by
 * logical datapath only by creating a datapah group. */
static bool use_logical_dp_groups = false;

/* Adds a row with the specified contents to the Logical_Flow table. */
static void
ovn_lflow_add_at(struct hmap *lflow_map, struct ovn_datapath *od,
                 enum ovn_stage stage, uint16_t priority,
                 const char *match, const char *actions, bool shared,
                 const struct ovsdb_idl_row *stage_hint, const char *where)
{
    ovs_assert(ovn_stage_to_datapath_type(stage) == ovn_datapath_get_type(od));

    struct ovn_lflow *old_lflow, *lflow;
    uint32_t hash;

    lflow = xmalloc(sizeof *lflow);
    /* While adding new logical flows we're not setting single datapath, but
     * collecting a group.  'od' will be updated later for all flows with only
     * one datapath in a group, so it could be hashed correctly. */
    ovn_lflow_init(lflow, NULL, stage, priority,
                   xstrdup(match), xstrdup(actions),
                   ovn_lflow_hint(stage_hint), where);

    hash = ovn_lflow_hash(lflow);
    if (shared && use_logical_dp_groups) {
        old_lflow = ovn_lflow_find_by_lflow(lflow_map, lflow, hash);
        if (old_lflow) {
            ovn_lflow_destroy(NULL, lflow);
            hmapx_add(&old_lflow->od_group, od);
            return;
        }
    }

    hmapx_add(&lflow->od_group, od);
    hmap_insert(lflow_map, &lflow->hmap_node, hash);
}

/* Adds a row with the specified contents to the Logical_Flow table. */
#define ovn_lflow_add_with_hint(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, \
                                ACTIONS, STAGE_HINT) \
    ovn_lflow_add_at(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, ACTIONS, true, \
                     STAGE_HINT, OVS_SOURCE_LOCATOR)

#define ovn_lflow_add(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, ACTIONS) \
    ovn_lflow_add_at(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, ACTIONS, true, \
                     NULL, OVS_SOURCE_LOCATOR)

/* Adds a row with the specified contents to the Logical_Flow table.
 * Combining of this logical flow with already existing ones, e.g., by using
 * Logical Datapath Groups, is forbidden.
 *
 * XXX: ovn-controller assumes that a logical flow using multicast group always
 *      comes after or in the same database update with the corresponding
 *      multicast group.  That will not be the case with datapath groups.
 *      For this reason, the 'ovn_lflow_add_unique*()' functions should be used
 *      for such logical flows.
 */
#define ovn_lflow_add_unique_with_hint(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, \
                                       ACTIONS, STAGE_HINT) \
    ovn_lflow_add_at(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, ACTIONS, false, \
                     STAGE_HINT, OVS_SOURCE_LOCATOR)

#define ovn_lflow_add_unique(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, ACTIONS) \
    ovn_lflow_add_at(LFLOW_MAP, OD, STAGE, PRIORITY, MATCH, ACTIONS, false, \
                     NULL, OVS_SOURCE_LOCATOR)

static struct ovn_lflow *
ovn_lflow_find(struct hmap *lflows, struct ovn_datapath *od,
               enum ovn_stage stage, uint16_t priority,
               const char *match, const char *actions, uint32_t hash)
{
    struct ovn_lflow target;
    ovn_lflow_init(&target, od, stage, priority,
                   CONST_CAST(char *, match), CONST_CAST(char *, actions),
                   NULL, NULL);

    return ovn_lflow_find_by_lflow(lflows, &target, hash);
}

static void
ovn_lflow_destroy(struct hmap *lflows, struct ovn_lflow *lflow)
{
    if (lflow) {
        if (lflows) {
            hmap_remove(lflows, &lflow->hmap_node);
        }
        hmapx_destroy(&lflow->od_group);
        free(lflow->match);
        free(lflow->actions);
        free(lflow->stage_hint);
        free(lflow);
    }
}

static struct ovn_lflow *
ovn_lflow_find_by_lflow(const struct hmap *lflows,
                        const struct ovn_lflow *target, uint32_t hash)
{
    struct ovn_lflow *lflow;
    HMAP_FOR_EACH_WITH_HASH (lflow, hmap_node, hash, lflows) {
        if (ovn_lflow_equal(lflow, target)) {
            return lflow;
        }
    }
    return NULL;
}

/* Appends port security constraints on L2 address field 'eth_addr_field'
 * (e.g. "eth.src" or "eth.dst") to 'match'.  'ps_addrs', with 'n_ps_addrs'
 * elements, is the collection of port_security constraints from an
 * OVN_NB Logical_Switch_Port row generated by extract_lsp_addresses(). */
static void
build_port_security_l2(const char *eth_addr_field,
                       struct lport_addresses *ps_addrs,
                       unsigned int n_ps_addrs,
                       struct ds *match)
{
    if (!n_ps_addrs) {
        return;
    }

    ds_put_format(match, " && %s == {", eth_addr_field);

    for (size_t i = 0; i < n_ps_addrs; i++) {
        ds_put_format(match, "%s ", ps_addrs[i].ea_s);
    }
    ds_chomp(match, ' ');
    ds_put_cstr(match, "}");
}

static void
build_port_security_ipv6_nd_flow(
    struct ds *match, struct eth_addr ea, struct ipv6_netaddr *ipv6_addrs,
    int n_ipv6_addrs)
{
    ds_put_format(match, " && ip6 && nd && ((nd.sll == "ETH_ADDR_FMT" || "
                  "nd.sll == "ETH_ADDR_FMT") || ((nd.tll == "ETH_ADDR_FMT" || "
                  "nd.tll == "ETH_ADDR_FMT")", ETH_ADDR_ARGS(eth_addr_zero),
                  ETH_ADDR_ARGS(ea), ETH_ADDR_ARGS(eth_addr_zero),
                  ETH_ADDR_ARGS(ea));
    if (!n_ipv6_addrs) {
        ds_put_cstr(match, "))");
        return;
    }

    char ip6_str[INET6_ADDRSTRLEN + 1];
    struct in6_addr lla;
    in6_generate_lla(ea, &lla);
    memset(ip6_str, 0, sizeof(ip6_str));
    ipv6_string_mapped(ip6_str, &lla);
    ds_put_format(match, " && (nd.target == %s", ip6_str);

    for (size_t i = 0; i < n_ipv6_addrs; i++) {
        /* When the netmask is applied, if the host portion is
         * non-zero, the host can only use the specified
         * address in the nd.target.  If zero, the host is allowed
         * to use any address in the subnet.
         */
        if (ipv6_addrs[i].plen == 128
            || !ipv6_addr_is_host_zero(&ipv6_addrs[i].addr,
                                       &ipv6_addrs[i].mask)) {
            ds_put_format(match, " || nd.target == %s", ipv6_addrs[i].addr_s);
        } else {
            ds_put_format(match, " || nd.target == %s/%d",
                          ipv6_addrs[i].network_s, ipv6_addrs[i].plen);
        }
    }

    ds_put_format(match, ")))");
}

static void
build_port_security_ipv6_flow(
    enum ovn_pipeline pipeline, struct ds *match, struct eth_addr ea,
    struct ipv6_netaddr *ipv6_addrs, int n_ipv6_addrs)
{
    char ip6_str[INET6_ADDRSTRLEN + 1];

    ds_put_format(match, " && %s == {",
                  pipeline == P_IN ? "ip6.src" : "ip6.dst");

    /* Allow link-local address. */
    struct in6_addr lla;
    in6_generate_lla(ea, &lla);
    ipv6_string_mapped(ip6_str, &lla);
    ds_put_format(match, "%s, ", ip6_str);

    /* Allow ip6.dst=ff00::/8 for multicast packets */
    if (pipeline == P_OUT) {
        ds_put_cstr(match, "ff00::/8, ");
    }
    for (size_t i = 0; i < n_ipv6_addrs; i++) {
        /* When the netmask is applied, if the host portion is
         * non-zero, the host can only use the specified
         * address.  If zero, the host is allowed to use any
         * address in the subnet.
         */
        if (ipv6_addrs[i].plen == 128
            || !ipv6_addr_is_host_zero(&ipv6_addrs[i].addr,
                                       &ipv6_addrs[i].mask)) {
            ds_put_format(match, "%s, ", ipv6_addrs[i].addr_s);
        } else {
            ds_put_format(match, "%s/%d, ", ipv6_addrs[i].network_s,
                          ipv6_addrs[i].plen);
        }
    }
    /* Replace ", " by "}". */
    ds_chomp(match, ' ');
    ds_chomp(match, ',');
    ds_put_cstr(match, "}");
}

/**
 * Build port security constraints on ARP and IPv6 ND fields
 * and add logical flows to S_SWITCH_IN_PORT_SEC_ND stage.
 *
 * For each port security of the logical port, following
 * logical flows are added
 *   - If the port security has no IP (both IPv4 and IPv6) or
 *     if it has IPv4 address(es)
 *      - Priority 90 flow to allow ARP packets for known MAC addresses
 *        in the eth.src and arp.spa fields. If the port security
 *        has IPv4 addresses, allow known IPv4 addresses in the arp.tpa field.
 *
 *   - If the port security has no IP (both IPv4 and IPv6) or
 *     if it has IPv6 address(es)
 *     - Priority 90 flow to allow IPv6 ND packets for known MAC addresses
 *       in the eth.src and nd.sll/nd.tll fields. If the port security
 *       has IPv6 addresses, allow known IPv6 addresses in the nd.target field
 *       for IPv6 Neighbor Advertisement packet.
 *
 *   - Priority 80 flow to drop ARP and IPv6 ND packets.
 */
static void
build_port_security_nd(struct ovn_port *op, struct hmap *lflows,
                       const struct ovsdb_idl_row *stage_hint)
{
    struct ds match = DS_EMPTY_INITIALIZER;

    for (size_t i = 0; i < op->n_ps_addrs; i++) {
        struct lport_addresses *ps = &op->ps_addrs[i];

        bool no_ip = !(ps->n_ipv4_addrs || ps->n_ipv6_addrs);

        ds_clear(&match);
        if (ps->n_ipv4_addrs || no_ip) {
            ds_put_format(&match,
                          "inport == %s && eth.src == %s && arp.sha == %s",
                          op->json_key, ps->ea_s, ps->ea_s);

            if (ps->n_ipv4_addrs) {
                ds_put_cstr(&match, " && arp.spa == {");
                for (size_t j = 0; j < ps->n_ipv4_addrs; j++) {
                    /* When the netmask is applied, if the host portion is
                     * non-zero, the host can only use the specified
                     * address in the arp.spa.  If zero, the host is allowed
                     * to use any address in the subnet. */
                    if (ps->ipv4_addrs[j].plen == 32
                        || ps->ipv4_addrs[j].addr & ~ps->ipv4_addrs[j].mask) {
                        ds_put_cstr(&match, ps->ipv4_addrs[j].addr_s);
                    } else {
                        ds_put_format(&match, "%s/%d",
                                      ps->ipv4_addrs[j].network_s,
                                      ps->ipv4_addrs[j].plen);
                    }
                    ds_put_cstr(&match, ", ");
                }
                ds_chomp(&match, ' ');
                ds_chomp(&match, ',');
                ds_put_cstr(&match, "}");
            }
            ovn_lflow_add_with_hint(lflows, op->od, S_SWITCH_IN_PORT_SEC_ND,
                                    90, ds_cstr(&match), "next;", stage_hint);
        }

        if (ps->n_ipv6_addrs || no_ip) {
            ds_clear(&match);
            ds_put_format(&match, "inport == %s && eth.src == %s",
                          op->json_key, ps->ea_s);
            build_port_security_ipv6_nd_flow(&match, ps->ea, ps->ipv6_addrs,
                                             ps->n_ipv6_addrs);
            ovn_lflow_add_with_hint(lflows, op->od, S_SWITCH_IN_PORT_SEC_ND,
                                    90, ds_cstr(&match), "next;", stage_hint);
        }
    }

    ds_clear(&match);
    ds_put_format(&match, "inport == %s && (arp || nd)", op->json_key);
    ovn_lflow_add_with_hint(lflows, op->od, S_SWITCH_IN_PORT_SEC_ND, 80,
                            ds_cstr(&match), "drop;", stage_hint);
    ds_destroy(&match);
}

/**
 * Build port security constraints on IPv4 and IPv6 src and dst fields
 * and add logical flows to S_SWITCH_(IN/OUT)_PORT_SEC_IP stage.
 *
 * For each port security of the logical port, following
 * logical flows are added
 *   - If the port security has IPv4 addresses,
 *     - Priority 90 flow to allow IPv4 packets for known IPv4 addresses
 *
 *   - If the port security has IPv6 addresses,
 *     - Priority 90 flow to allow IPv6 packets for known IPv6 addresses
 *
 *   - If the port security has IPv4 addresses or IPv6 addresses or both
 *     - Priority 80 flow to drop all IPv4 and IPv6 traffic
 */
static void
build_port_security_ip(enum ovn_pipeline pipeline, struct ovn_port *op,
                       struct hmap *lflows,
                       const struct ovsdb_idl_row *stage_hint)
{
    char *port_direction;
    enum ovn_stage stage;
    if (pipeline == P_IN) {
        port_direction = "inport";
        stage = S_SWITCH_IN_PORT_SEC_IP;
    } else {
        port_direction = "outport";
        stage = S_SWITCH_OUT_PORT_SEC_IP;
    }

    for (size_t i = 0; i < op->n_ps_addrs; i++) {
        struct lport_addresses *ps = &op->ps_addrs[i];

        if (!(ps->n_ipv4_addrs || ps->n_ipv6_addrs)) {
            continue;
        }

        if (ps->n_ipv4_addrs) {
            struct ds match = DS_EMPTY_INITIALIZER;
            if (pipeline == P_IN) {
                /* Permit use of the unspecified address for DHCP discovery */
                struct ds dhcp_match = DS_EMPTY_INITIALIZER;
                ds_put_format(&dhcp_match, "inport == %s"
                              " && eth.src == %s"
                              " && ip4.src == 0.0.0.0"
                              " && ip4.dst == 255.255.255.255"
                              " && udp.src == 68 && udp.dst == 67",
                              op->json_key, ps->ea_s);
                ovn_lflow_add_with_hint(lflows, op->od, stage, 90,
                                        ds_cstr(&dhcp_match), "next;",
                                        stage_hint);
                ds_destroy(&dhcp_match);
                ds_put_format(&match, "inport == %s && eth.src == %s"
                              " && ip4.src == {", op->json_key,
                              ps->ea_s);
            } else {
                ds_put_format(&match, "outport == %s && eth.dst == %s"
                              " && ip4.dst == {255.255.255.255, 224.0.0.0/4, ",
                              op->json_key, ps->ea_s);
            }

            for (int j = 0; j < ps->n_ipv4_addrs; j++) {
                ovs_be32 mask = ps->ipv4_addrs[j].mask;
                /* When the netmask is applied, if the host portion is
                 * non-zero, the host can only use the specified
                 * address.  If zero, the host is allowed to use any
                 * address in the subnet.
                 */
                if (ps->ipv4_addrs[j].plen == 32
                    || ps->ipv4_addrs[j].addr & ~mask) {
                    ds_put_format(&match, "%s", ps->ipv4_addrs[j].addr_s);
                    if (pipeline == P_OUT && ps->ipv4_addrs[j].plen != 32) {
                        /* Host is also allowed to receive packets to the
                         * broadcast address in the specified subnet. */
                        ds_put_format(&match, ", %s",
                                      ps->ipv4_addrs[j].bcast_s);
                    }
                } else {
                    /* host portion is zero */
                    ds_put_format(&match, "%s/%d", ps->ipv4_addrs[j].network_s,
                                  ps->ipv4_addrs[j].plen);
                }
                ds_put_cstr(&match, ", ");
            }

            /* Replace ", " by "}". */
            ds_chomp(&match, ' ');
            ds_chomp(&match, ',');
            ds_put_cstr(&match, "}");
            ovn_lflow_add_with_hint(lflows, op->od, stage, 90,
                                    ds_cstr(&match), "next;",
                                    stage_hint);
            ds_destroy(&match);
        }

        if (ps->n_ipv6_addrs) {
            struct ds match = DS_EMPTY_INITIALIZER;
            if (pipeline == P_IN) {
                /* Permit use of unspecified address for duplicate address
                 * detection */
                struct ds dad_match = DS_EMPTY_INITIALIZER;
                ds_put_format(&dad_match, "inport == %s"
                              " && eth.src == %s"
                              " && ip6.src == ::"
                              " && ip6.dst == ff02::/16"
                              " && icmp6.type == {131, 135, 143}", op->json_key,
                              ps->ea_s);
                ovn_lflow_add_with_hint(lflows, op->od, stage, 90,
                                        ds_cstr(&dad_match), "next;",
                                        stage_hint);
                ds_destroy(&dad_match);
            }
            ds_put_format(&match, "%s == %s && %s == %s",
                          port_direction, op->json_key,
                          pipeline == P_IN ? "eth.src" : "eth.dst", ps->ea_s);
            build_port_security_ipv6_flow(pipeline, &match, ps->ea,
                                          ps->ipv6_addrs, ps->n_ipv6_addrs);
            ovn_lflow_add_with_hint(lflows, op->od, stage, 90,
                                    ds_cstr(&match), "next;",
                                    stage_hint);
            ds_destroy(&match);
        }

        char *match = xasprintf("%s == %s && %s == %s && ip",
                                port_direction, op->json_key,
                                pipeline == P_IN ? "eth.src" : "eth.dst",
                                ps->ea_s);
        ovn_lflow_add_with_hint(lflows, op->od, stage, 80, match, "drop;",
                                stage_hint);
        free(match);
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

static bool
ls_has_stateful_acl(struct ovn_datapath *od)
{
    for (size_t i = 0; i < od->nbs->n_acls; i++) {
        struct nbrec_acl *acl = od->nbs->acls[i];
        if (!strcmp(acl->action, "allow-related")) {
            return true;
        }
    }

    struct ovn_ls_port_group *ls_pg;
    HMAP_FOR_EACH (ls_pg, key_node, &od->nb_pgs) {
        for (size_t i = 0; i < ls_pg->nb_pg->n_acls; i++) {
            struct nbrec_acl *acl = ls_pg->nb_pg->acls[i];
            if (!strcmp(acl->action, "allow-related")) {
                return true;
            }
        }
    }

    return false;
}

/* Logical switch ingress table 0: Ingress port security - L2
 *  (priority 50).
 *  Ingress table 1: Ingress port security - IP (priority 90 and 80)
 *  Ingress table 2: Ingress port security - ND (priority 90 and 80)
 */
static void
build_lswitch_input_port_sec_op(
        struct ovn_port *op, struct hmap *lflows,
        struct ds *actions, struct ds *match)
{

    if (!op->nbsp) {
        return;
    }

    if (!lsp_is_enabled(op->nbsp)) {
        /* Drop packets from disabled logical ports (since logical flow
         * tables are default-drop). */
        return;
    }

    if (lsp_is_external(op->nbsp)) {
        return;
    }

    ds_clear(match);
    ds_clear(actions);
    ds_put_format(match, "inport == %s", op->json_key);
    build_port_security_l2("eth.src", op->ps_addrs, op->n_ps_addrs,
                           match);

    const char *queue_id = smap_get(&op->sb->options, "qdisc_queue_id");
    if (queue_id) {
        ds_put_format(actions, "set_queue(%s); ", queue_id);
    }
    ds_put_cstr(actions, "next;");
    ovn_lflow_add_with_hint(lflows, op->od, S_SWITCH_IN_PORT_SEC_L2, 50,
                            ds_cstr(match), ds_cstr(actions),
                            &op->nbsp->header_);

    if (op->nbsp->n_port_security) {
        build_port_security_ip(P_IN, op, lflows, &op->nbsp->header_);
        build_port_security_nd(op, lflows, &op->nbsp->header_);
    }
}

/* Ingress table 1 and 2: Port security - IP and ND, by default
 * goto next. (priority 0)
 */
static void
build_lswitch_input_port_sec_od(
        struct ovn_datapath *od, struct hmap *lflows)
{

    if (od->nbs) {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_PORT_SEC_ND, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_IN_PORT_SEC_IP, 0, "1", "next;");
    }
}

/* Egress table 8: Egress port security - IP (priorities 90 and 80)
 * if port security enabled.
 *
 * Egress table 9: Egress port security - L2 (priorities 50 and 150).
 *
 * Priority 50 rules implement port security for enabled logical port.
 *
 * Priority 150 rules drop packets to disabled logical ports, so that
 * they don't even receive multicast or broadcast packets.
 */
static void
build_lswitch_output_port_sec_op(struct ovn_port *op,
                                 struct hmap *lflows,
                                 struct ds *match,
                                 struct ds *actions)
{

    if (op->nbsp && (!lsp_is_external(op->nbsp))) {

        ds_clear(actions);
        ds_clear(match);

        ds_put_format(match, "outport == %s", op->json_key);
        if (lsp_is_enabled(op->nbsp)) {
            build_port_security_l2("eth.dst", op->ps_addrs, op->n_ps_addrs,
                                   match);

            if (!strcmp(op->nbsp->type, "localnet")) {
                const char *queue_id = smap_get(&op->sb->options,
                                                "qdisc_queue_id");
                if (queue_id) {
                    ds_put_format(actions, "set_queue(%s); ", queue_id);
                }
            }
            ds_put_cstr(actions, "output;");
            ovn_lflow_add_with_hint(lflows, op->od, S_SWITCH_OUT_PORT_SEC_L2,
                                    50, ds_cstr(match), ds_cstr(actions),
                                    &op->nbsp->header_);
        } else {
            ovn_lflow_add_with_hint(lflows, op->od, S_SWITCH_OUT_PORT_SEC_L2,
                                    150, ds_cstr(match), "drop;",
                                    &op->nbsp->header_);
        }

        if (op->nbsp->n_port_security) {
            build_port_security_ip(P_OUT, op, lflows, &op->nbsp->header_);
        }
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
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_PORT_SEC_IP, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_PORT_SEC_L2, 100, "eth.mcast",
                      "output;");
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
    ovn_lflow_add_with_hint(lflows, od, in_stage, priority,
                            ds_cstr(&match_in), "next;",
                            &op->nbsp->header_);
    ovn_lflow_add_with_hint(lflows, od, out_stage, priority,
                            ds_cstr(&match_out), "next;",
                            &op->nbsp->header_);

    ds_destroy(&match_in);
    ds_destroy(&match_out);
}

static void
build_pre_acls(struct ovn_datapath *od, struct hmap *lflows)
{
    /* Ingress and Egress Pre-ACL Table (Priority 0): Packets are
     * allowed by default. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_ACL, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_ACL, 0, "1", "next;");

    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_ACL, 110,
                  "eth.dst == $svc_monitor_mac", "next;");

    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_ACL, 110,
                  "eth.src == $svc_monitor_mac", "next;");

    /* If there are any stateful ACL rules in this datapath, we must
     * send all IP packets through the conntrack action, which handles
     * defragmentation, in order to match L4 headers. */
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

static void
build_empty_lb_event_flow(struct ovn_datapath *od, struct hmap *lflows,
                          struct ovn_lb_vip *lb_vip,
                          struct nbrec_load_balancer *lb,
                          int pl, struct shash *meter_groups)
{
    bool controller_event = smap_get_bool(&lb->options, "event", false) ||
                            controller_event_en; /* deprecated */
    if (!controller_event || lb_vip->n_backends ||
        lb_vip->empty_backend_rej) {
        return;
    }

    bool ipv4 = IN6_IS_ADDR_V4MAPPED(&lb_vip->vip);
    struct ds match = DS_EMPTY_INITIALIZER;
    char *meter = "", *action;

    if (meter_groups && shash_find(meter_groups, "event-elb")) {
        meter = "event-elb";
    }

    ds_put_format(&match, "ip%s.dst == %s && %s",
                  ipv4 ? "4": "6", lb_vip->vip_str, lb->protocol);

    char *vip = lb_vip->vip_str;
    if (lb_vip->vip_port) {
        ds_put_format(&match, " && %s.dst == %u", lb->protocol,
                      lb_vip->vip_port);
        vip = xasprintf("%s%s%s:%u", ipv4 ? "" : "[", lb_vip->vip_str,
                        ipv4 ? "" : "]", lb_vip->vip_port);
    }

    action = xasprintf("trigger_event(event = \"%s\", "
                       "meter = \"%s\", vip = \"%s\", "
                       "protocol = \"%s\", "
                       "load_balancer = \"" UUID_FMT "\");",
                       event_to_string(OVN_EVENT_EMPTY_LB_BACKENDS),
                       meter, vip, lb->protocol,
                       UUID_ARGS(&lb->header_.uuid));
    ovn_lflow_add_with_hint(lflows, od, pl, 130, ds_cstr(&match), action,
                            &lb->header_);
    ds_destroy(&match);
    if (lb_vip->vip_port) {
        free(vip);
    }
    free(action);
}

static bool
ls_has_lb_vip(struct ovn_datapath *od)
{
    for (int i = 0; i < od->nbs->n_load_balancer; i++) {
        struct nbrec_load_balancer *nb_lb = od->nbs->load_balancer[i];
        if (!smap_is_empty(&nb_lb->vips)) {
            return true;
        }
    }

    return false;
}

static void
build_pre_lb(struct ovn_datapath *od, struct hmap *lflows,
             struct shash *meter_groups, struct hmap *lbs)
{
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

    bool vip_configured = false;
    for (int i = 0; i < od->nbs->n_load_balancer; i++) {
        struct nbrec_load_balancer *nb_lb = od->nbs->load_balancer[i];
        struct ovn_northd_lb *lb =
            ovn_northd_lb_find(lbs, &nb_lb->header_.uuid);
        ovs_assert(lb);

        for (size_t j = 0; j < lb->n_vips; j++) {
            struct ovn_lb_vip *lb_vip = &lb->vips[j];
            build_empty_lb_event_flow(od, lflows, lb_vip, nb_lb,
                                      S_SWITCH_IN_PRE_LB, meter_groups);

            /* Ignore L4 port information in the key because fragmented packets
             * may not have L4 information.  The pre-stateful table will send
             * the packet through ct() action to de-fragment. In stateful
             * table, we will eventually look at L4 information. */
        }

        vip_configured = (vip_configured || lb->n_vips);
    }

    /* 'REGBIT_CONNTRACK_DEFRAG' is set to let the pre-stateful table send
     * packet to conntrack for defragmentation.
     *
     * Send all the packets to conntrack in the ingress pipeline if the
     * logical switch has a load balancer with VIP configured. Earlier
     * we used to set the REGBIT_CONNTRACK_DEFRAG flag in the ingress pipeline
     * if the IP destination matches the VIP. But this causes few issues when
     * a logical switch has no ACLs configured with allow-related.
     * To understand the issue, lets a take a TCP load balancer -
     * 10.0.0.10:80=10.0.0.3:80.
     * If a logical port - p1 with IP - 10.0.0.5 opens a TCP connection with
     * the VIP - 10.0.0.10, then the packet in the ingress pipeline of 'p1'
     * is sent to the p1's conntrack zone id and the packet is load balanced
     * to the backend - 10.0.0.3. For the reply packet from the backend lport,
     * it is not sent to the conntrack of backend lport's zone id. This is fine
     * as long as the packet is valid. Suppose the backend lport sends an
     *  invalid TCP packet (like incorrect sequence number), the packet gets
     * delivered to the lport 'p1' without unDNATing the packet to the
     * VIP - 10.0.0.10. And this causes the connection to be reset by the
     * lport p1's VIF.
     *
     * We can't fix this issue by adding a logical flow to drop ct.inv packets
     * in the egress pipeline since it will drop all other connections not
     * destined to the load balancers.
     *
     * To fix this issue, we send all the packets to the conntrack in the
     * ingress pipeline if a load balancer is configured. We can now
     * add a lflow to drop ct.inv packets.
     */
    if (vip_configured) {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_LB,
                      100, "ip", REGBIT_CONNTRACK_DEFRAG" = 1; next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_LB,
                      100, "ip", REGBIT_CONNTRACK_DEFRAG" = 1; next;");
    }
}

static void
build_pre_stateful(struct ovn_datapath *od, struct hmap *lflows)
{
    /* Ingress and Egress pre-stateful Table (Priority 0): Packets are
     * allowed by default. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_STATEFUL, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_STATEFUL, 0, "1", "next;");

    /* If REGBIT_CONNTRACK_DEFRAG is set as 1, then the packets should be
     * sent to conntrack for tracking and defragmentation. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_STATEFUL, 100,
                  REGBIT_CONNTRACK_DEFRAG" == 1", "ct_next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_STATEFUL, 100,
                  REGBIT_CONNTRACK_DEFRAG" == 1", "ct_next;");
}

static void
build_acl_hints(struct ovn_datapath *od, struct hmap *lflows)
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

        /* In any case, advance to the next stage. */
        ovn_lflow_add(lflows, od, stage, 0, "1", "next;");

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
        ovn_lflow_add(lflows, od, stage, 6,
                      "!ct.new && ct.est && !ct.rpl && ct_label.blocked == 1",
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
         *   connection must be committed with ct_label.blocked set so we set
         *   REGBIT_ACL_HINT_BLOCK.
         */
        ovn_lflow_add(lflows, od, stage, 4,
                      "!ct.new && ct.est && !ct.rpl && ct_label.blocked == 0",
                      REGBIT_ACL_HINT_ALLOW " = 1; "
                      REGBIT_ACL_HINT_BLOCK " = 1; "
                      "next;");

        /* Not established or established and already blocked connections may
         * hit drop ACLs.
         */
        ovn_lflow_add(lflows, od, stage, 3, "!ct.est",
                      REGBIT_ACL_HINT_DROP " = 1; "
                      "next;");
        ovn_lflow_add(lflows, od, stage, 2, "ct.est && ct_label.blocked == 1",
                      REGBIT_ACL_HINT_DROP " = 1; "
                      "next;");

        /* Established connections that were previously allowed might hit
         * drop ACLs in which case the connection must be committed with
         * ct_label.blocked set.
         */
        ovn_lflow_add(lflows, od, stage, 1, "ct.est && ct_label.blocked == 0",
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
        || !strcmp(acl->action, "allow-related")) {
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
    bool ingress = (stage == S_SWITCH_IN_ACL);

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
    ovn_lflow_add_with_hint(lflows, od, stage,
                            acl->priority + OVN_ACL_PRI_OFFSET,
                            ds_cstr(&match), ds_cstr(&actions), stage_hint);

    free(next_action);
    ds_destroy(&match);
    ds_destroy(&actions);
}

static void
consider_acl(struct hmap *lflows, struct ovn_datapath *od,
             struct nbrec_acl *acl, bool has_stateful,
             const struct shash *meter_groups)
{
    bool ingress = !strcmp(acl->direction, "from-lport") ? true :false;
    enum ovn_stage stage = ingress ? S_SWITCH_IN_ACL : S_SWITCH_OUT_ACL;

    if (!strcmp(acl->action, "allow")
        || !strcmp(acl->action, "allow-related")) {
        /* If there are any stateful flows, we must even commit "allow"
         * actions.  This is because, while the initiater's
         * direction may not have any stateful rules, the server's
         * may and then its return traffic would not have an
         * associated conntrack entry and would return "+invalid". */
        if (!has_stateful) {
            struct ds actions = DS_EMPTY_INITIALIZER;
            build_acl_log(&actions, acl, meter_groups);
            ds_put_cstr(&actions, "next;");
            ovn_lflow_add_with_hint(lflows, od, stage,
                                    acl->priority + OVN_ACL_PRI_OFFSET,
                                    acl->match, ds_cstr(&actions),
                                    &acl->header_);
            ds_destroy(&actions);
        } else {
            struct ds match = DS_EMPTY_INITIALIZER;
            struct ds actions = DS_EMPTY_INITIALIZER;

            /* Commit the connection tracking entry if it's a new
             * connection that matches this ACL.  After this commit,
             * the reply traffic is allowed by a flow we create at
             * priority 65535, defined earlier.
             *
             * It's also possible that a known connection was marked for
             * deletion after a policy was deleted, but the policy was
             * re-added while that connection is still known.  We catch
             * that case here and un-set ct_label.blocked (which will be done
             * by ct_commit in the "stateful" stage) to indicate that the
             * connection should be allowed to resume.
             */
            ds_put_format(&match, REGBIT_ACL_HINT_ALLOW_NEW " == 1 && (%s)",
                          acl->match);
            ds_put_cstr(&actions, REGBIT_CONNTRACK_COMMIT" = 1; ");
            build_acl_log(&actions, acl, meter_groups);
            ds_put_cstr(&actions, "next;");
            ovn_lflow_add_with_hint(lflows, od, stage,
                                    acl->priority + OVN_ACL_PRI_OFFSET,
                                    ds_cstr(&match),
                                    ds_cstr(&actions),
                                    &acl->header_);

            /* Match on traffic in the request direction for an established
             * connection tracking entry that has not been marked for
             * deletion.  There is no need to commit here, so we can just
             * proceed to the next table. We use this to ensure that this
             * connection is still allowed by the currently defined
             * policy. Match untracked packets too. */
            ds_clear(&match);
            ds_clear(&actions);
            ds_put_format(&match, REGBIT_ACL_HINT_ALLOW " == 1 && (%s)",
                          acl->match);

            build_acl_log(&actions, acl, meter_groups);
            ds_put_cstr(&actions, "next;");
            ovn_lflow_add_with_hint(lflows, od, stage,
                                    acl->priority + OVN_ACL_PRI_OFFSET,
                                    ds_cstr(&match), ds_cstr(&actions),
                                    &acl->header_);

            ds_destroy(&match);
            ds_destroy(&actions);
        }
    } else if (!strcmp(acl->action, "drop")
               || !strcmp(acl->action, "reject")) {
        struct ds match = DS_EMPTY_INITIALIZER;
        struct ds actions = DS_EMPTY_INITIALIZER;

        /* The implementation of "drop" differs if stateful ACLs are in
         * use for this datapath.  In that case, the actions differ
         * depending on whether the connection was previously committed
         * to the connection tracker with ct_commit. */
        if (has_stateful) {
            /* If the packet is not tracked or not part of an established
             * connection, then we can simply reject/drop it. */
            ds_put_cstr(&match, REGBIT_ACL_HINT_DROP " == 1");
            if (!strcmp(acl->action, "reject")) {
                build_reject_acl_rules(od, lflows, stage, acl, &match,
                                       &actions, &acl->header_, meter_groups);
            } else {
                ds_put_format(&match, " && (%s)", acl->match);
                build_acl_log(&actions, acl, meter_groups);
                ds_put_cstr(&actions, "/* drop */");
                ovn_lflow_add_with_hint(lflows, od, stage,
                                        acl->priority + OVN_ACL_PRI_OFFSET,
                                        ds_cstr(&match), ds_cstr(&actions),
                                        &acl->header_);
            }
            /* For an existing connection without ct_label set, we've
             * encountered a policy change. ACLs previously allowed
             * this connection and we committed the connection tracking
             * entry.  Current policy says that we should drop this
             * connection.  First, we set bit 0 of ct_label to indicate
             * that this connection is set for deletion.  By not
             * specifying "next;", we implicitly drop the packet after
             * updating conntrack state.  We would normally defer
             * ct_commit() to the "stateful" stage, but since we're
             * rejecting/dropping the packet, we go ahead and do it here.
             */
            ds_clear(&match);
            ds_clear(&actions);
            ds_put_cstr(&match, REGBIT_ACL_HINT_BLOCK " == 1");
            ds_put_cstr(&actions, "ct_commit { ct_label.blocked = 1; }; ");
            if (!strcmp(acl->action, "reject")) {
                build_reject_acl_rules(od, lflows, stage, acl, &match,
                                       &actions, &acl->header_, meter_groups);
            } else {
                ds_put_format(&match, " && (%s)", acl->match);
                build_acl_log(&actions, acl, meter_groups);
                ds_put_cstr(&actions, "/* drop */");
                ovn_lflow_add_with_hint(lflows, od, stage,
                                        acl->priority + OVN_ACL_PRI_OFFSET,
                                        ds_cstr(&match), ds_cstr(&actions),
                                        &acl->header_);
            }
        } else {
            /* There are no stateful ACLs in use on this datapath,
             * so a "reject/drop" ACL is simply the "reject/drop"
             * logical flow action in all cases. */
            if (!strcmp(acl->action, "reject")) {
                build_reject_acl_rules(od, lflows, stage, acl, &match,
                                       &actions, &acl->header_, meter_groups);
            } else {
                build_acl_log(&actions, acl, meter_groups);
                ds_put_cstr(&actions, "/* drop */");
                ovn_lflow_add_with_hint(lflows, od, stage,
                                        acl->priority + OVN_ACL_PRI_OFFSET,
                                        acl->match, ds_cstr(&actions),
                                        &acl->header_);
            }
        }
        ds_destroy(&match);
        ds_destroy(&actions);
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
build_port_group_lswitches(struct northd_context *ctx, struct hmap *pgs,
                           struct hmap *ports)
{
    hmap_init(pgs);

    const struct nbrec_port_group *nb_pg;
    NBREC_PORT_GROUP_FOR_EACH (nb_pg, ctx->ovnnb_idl) {
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
build_acls(struct ovn_datapath *od, struct hmap *lflows,
           struct hmap *port_groups, const struct shash *meter_groups)
{
    bool has_stateful = od->has_stateful_acl || od->has_lb_vip;

    /* Ingress and Egress ACL Table (Priority 0): Packets are allowed by
     * default.  A related rule at priority 1 is added below if there
     * are any stateful ACLs in this datapath. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, 0, "1", "next;");

    if (has_stateful) {
        /* Ingress and Egress ACL Table (Priority 1).
         *
         * By default, traffic is allowed.  This is partially handled by
         * the Priority 0 ACL flows added earlier, but we also need to
         * commit IP flows.  This is because, while the initiater's
         * direction may not have any stateful rules, the server's may
         * and then its return traffic would not have an associated
         * conntrack entry and would return "+invalid".
         *
         * We use "ct_commit" for a connection that is not already known
         * by the connection tracker.  Once a connection is committed,
         * subsequent packets will hit the flow at priority 0 that just
         * uses "next;"
         *
         * We also check for established connections that have ct_label.blocked
         * set on them.  That's a connection that was disallowed, but is
         * now allowed by policy again since it hit this default-allow flow.
         * We need to set ct_label.blocked=0 to let the connection continue,
         * which will be done by ct_commit() in the "stateful" stage.
         * Subsequent packets will hit the flow at priority 0 that just
         * uses "next;". */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, 1,
                      "ip && (!ct.est || (ct.est && ct_label.blocked == 1))",
                       REGBIT_CONNTRACK_COMMIT" = 1; next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, 1,
                      "ip && (!ct.est || (ct.est && ct_label.blocked == 1))",
                       REGBIT_CONNTRACK_COMMIT" = 1; next;");

        /* Ingress and Egress ACL Table (Priority 65535).
         *
         * Always drop traffic that's in an invalid state.  Also drop
         * reply direction packets for connections that have been marked
         * for deletion (bit 0 of ct_label is set).
         *
         * This is enforced at a higher priority than ACLs can be defined. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, UINT16_MAX,
                      "ct.inv || (ct.est && ct.rpl && ct_label.blocked == 1)",
                      "drop;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, UINT16_MAX,
                      "ct.inv || (ct.est && ct.rpl && ct_label.blocked == 1)",
                      "drop;");

        /* Ingress and Egress ACL Table (Priority 65535).
         *
         * Allow reply traffic that is part of an established
         * conntrack entry that has not been marked for deletion
         * (bit 0 of ct_label).  We only match traffic in the
         * reply direction because we want traffic in the request
         * direction to hit the currently defined policy from ACLs.
         *
         * This is enforced at a higher priority than ACLs can be defined. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, UINT16_MAX,
                      "ct.est && !ct.rel && !ct.new && !ct.inv "
                      "&& ct.rpl && ct_label.blocked == 0",
                      "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, UINT16_MAX,
                      "ct.est && !ct.rel && !ct.new && !ct.inv "
                      "&& ct.rpl && ct_label.blocked == 0",
                      "next;");

        /* Ingress and Egress ACL Table (Priority 65535).
         *
         * Allow traffic that is related to an existing conntrack entry that
         * has not been marked for deletion (bit 0 of ct_label).
         *
         * This is enforced at a higher priority than ACLs can be defined.
         *
         * NOTE: This does not support related data sessions (eg,
         * a dynamically negotiated FTP data channel), but will allow
         * related traffic such as an ICMP Port Unreachable through
         * that's generated from a non-listening UDP port.  */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, UINT16_MAX,
                      "!ct.est && ct.rel && !ct.new && !ct.inv "
                      "&& ct_label.blocked == 0",
                      "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, UINT16_MAX,
                      "!ct.est && ct.rel && !ct.new && !ct.inv "
                      "&& ct_label.blocked == 0",
                      "next;");

        /* Ingress and Egress ACL Table (Priority 65535).
         *
         * Not to do conntrack on ND packets. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, UINT16_MAX,
                      "nd || nd_ra || nd_rs || mldv1 || mldv2", "next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, UINT16_MAX,
                      "nd || nd_ra || nd_rs || mldv1 || mldv2", "next;");
    }

    /* Ingress or Egress ACL Table (Various priorities). */
    for (size_t i = 0; i < od->nbs->n_acls; i++) {
        struct nbrec_acl *acl = od->nbs->acls[i];
        consider_acl(lflows, od, acl, has_stateful, meter_groups);
    }
    struct ovn_port_group *pg;
    HMAP_FOR_EACH (pg, key_node, port_groups) {
        if (ovn_port_group_ls_find(pg, &od->nbs->header_.uuid)) {
            for (size_t i = 0; i < pg->nb_pg->n_acls; i++) {
                consider_acl(lflows, od, pg->nb_pg->acls[i], has_stateful,
                             meter_groups);
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
                struct ds match = DS_EMPTY_INITIALIZER;
                const char *actions =
                    has_stateful ? "ct_commit; next;" : "next;";
                ds_put_format(&match, "outport == \"%s\" && eth.src == %s "
                              "&& ip4.src == %s && udp && udp.src == 67 "
                              "&& udp.dst == 68", od->nbs->ports[i]->name,
                              server_mac, server_id);
                ovn_lflow_add_with_hint(
                    lflows, od, S_SWITCH_OUT_ACL, 34000, ds_cstr(&match),
                    actions, &od->nbs->ports[i]->dhcpv4_options->header_);
                ds_destroy(&match);
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

                struct ds match = DS_EMPTY_INITIALIZER;
                const char *actions = has_stateful ? "ct_commit; next;" :
                    "next;";
                ds_put_format(&match, "outport == \"%s\" && eth.src == %s "
                              "&& ip6.src == %s && udp && udp.src == 547 "
                              "&& udp.dst == 546", od->nbs->ports[i]->name,
                              server_mac, server_ip);
                ovn_lflow_add_with_hint(
                    lflows, od, S_SWITCH_OUT_ACL, 34000, ds_cstr(&match),
                    actions, &od->nbs->ports[i]->dhcpv6_options->header_);
                ds_destroy(&match);
            }
        }
    }

    /* Add a 34000 priority flow to advance the DNS reply from ovn-controller,
     * if the CMS has configured DNS records for the datapath.
     */
    if (ls_has_dns_records(od->nbs)) {
        const char *actions = has_stateful ? "ct_commit; next;" : "next;";
        ovn_lflow_add(
            lflows, od, S_SWITCH_OUT_ACL, 34000, "udp.src == 53",
            actions);
    }

    /* Add a 34000 priority flow to advance the service monitor reply
     * packets to skip applying ingress ACLs. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_ACL, 34000,
                  "eth.dst == $svc_monitor_mac", "next;");

    /* Add a 34000 priority flow to advance the service monitor packets
     * generated by ovn-controller to skip applying egress ACLs. */
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_ACL, 34000,
                  "eth.src == $svc_monitor_mac", "next;");
}

static void
build_qos(struct ovn_datapath *od, struct hmap *lflows) {
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
                struct ds dscp_action = DS_EMPTY_INITIALIZER;

                ds_put_format(&dscp_action, "ip.dscp = %"PRId64"; next;",
                              qos->value_action[j]);
                ovn_lflow_add_with_hint(lflows, od, stage,
                                        qos->priority,
                                        qos->match, ds_cstr(&dscp_action),
                                        &qos->header_);
                ds_destroy(&dscp_action);
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
            struct ds meter_action = DS_EMPTY_INITIALIZER;
            stage = ingress ? S_SWITCH_IN_QOS_METER : S_SWITCH_OUT_QOS_METER;
            if (burst) {
                ds_put_format(&meter_action,
                              "set_meter(%"PRId64", %"PRId64"); next;",
                              rate, burst);
            } else {
                ds_put_format(&meter_action,
                              "set_meter(%"PRId64"); next;",
                              rate);
            }

            /* Ingress and Egress QoS Meter Table.
             *
             * We limit the bandwidth of this flow by adding a meter table.
             */
            ovn_lflow_add_with_hint(lflows, od, stage,
                                    qos->priority,
                                    qos->match, ds_cstr(&meter_action),
                                    &qos->header_);
            ds_destroy(&meter_action);
        }
    }
}

static void
build_lb(struct ovn_datapath *od, struct hmap *lflows)
{
    /* Ingress and Egress LB Table (Priority 0): Packets are allowed by
     * default.  */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_LB, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_LB, 0, "1", "next;");

    if (od->nbs->n_load_balancer) {
        for (size_t i = 0; i < od->n_router_ports; i++) {
            skip_port_from_conntrack(od, od->router_ports[i],
                                     S_SWITCH_IN_LB, S_SWITCH_OUT_LB,
                                     UINT16_MAX, lflows);
        }
    }

    if (od->has_lb_vip) {
        /* Ingress and Egress LB Table (Priority 65534).
         *
         * Send established traffic through conntrack for just NAT. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_LB, UINT16_MAX - 1,
                      "ct.est && !ct.rel && !ct.new && !ct.inv && "
                      "ct_label.natted == 1",
                      REGBIT_CONNTRACK_NAT" = 1; next;");
        ovn_lflow_add(lflows, od, S_SWITCH_OUT_LB, UINT16_MAX - 1,
                      "ct.est && !ct.rel && !ct.new && !ct.inv && "
                      "ct_label.natted == 1",
                      REGBIT_CONNTRACK_NAT" = 1; next;");
    }
}

static void
build_lb_rules(struct ovn_datapath *od, struct hmap *lflows,
               struct ovn_northd_lb *lb)
{
    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_lb_vip *lb_vip = &lb->vips[i];
        struct ovn_northd_lb_vip *lb_vip_nb = &lb->vips_nb[i];

        const char *ip_match = NULL;
        if (IN6_IS_ADDR_V4MAPPED(&lb_vip->vip)) {
            ip_match = "ip4";
        } else {
            ip_match = "ip6";
        }

        const char *proto = NULL;
        if (lb_vip->vip_port) {
            proto = "tcp";
            if (lb->nlb->protocol) {
                if (!strcmp(lb->nlb->protocol, "udp")) {
                    proto = "udp";
                } else if (!strcmp(lb->nlb->protocol, "sctp")) {
                    proto = "sctp";
                }
            }
        }

        /* New connections in Ingress table. */
        struct ds action = DS_EMPTY_INITIALIZER;
        build_lb_vip_actions(lb_vip, lb_vip_nb, &action,
                             lb->selection_fields, true);

        struct ds match = DS_EMPTY_INITIALIZER;
        ds_put_format(&match, "ct.new && %s.dst == %s", ip_match,
                      lb_vip->vip_str);
        if (lb_vip->vip_port) {
            ds_put_format(&match, " && %s.dst == %d", proto, lb_vip->vip_port);
            ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_STATEFUL, 120,
                                    ds_cstr(&match), ds_cstr(&action),
                                    &lb->nlb->header_);
        } else {
            ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_STATEFUL, 110,
                                    ds_cstr(&match), ds_cstr(&action),
                                    &lb->nlb->header_);
        }

        ds_destroy(&match);
        ds_destroy(&action);
    }
}

static void
build_stateful(struct ovn_datapath *od, struct hmap *lflows, struct hmap *lbs)
{
    /* Ingress and Egress stateful Table (Priority 0): Packets are
     * allowed by default. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_STATEFUL, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_STATEFUL, 0, "1", "next;");

    /* If REGBIT_CONNTRACK_COMMIT is set as 1, then the packets should be
     * committed to conntrack. We always set ct_label.blocked to 0 here as
     * any packet that makes it this far is part of a connection we
     * want to allow to continue. */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_STATEFUL, 100,
                  REGBIT_CONNTRACK_COMMIT" == 1",
                  "ct_commit { ct_label.blocked = 0; }; next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_STATEFUL, 100,
                  REGBIT_CONNTRACK_COMMIT" == 1",
                  "ct_commit { ct_label.blocked = 0; }; next;");

    /* If REGBIT_CONNTRACK_NAT is set as 1, then packets should just be sent
     * through nat (without committing).
     *
     * REGBIT_CONNTRACK_COMMIT is set for new connections and
     * REGBIT_CONNTRACK_NAT is set for established connections. So they
     * don't overlap.
     */
    ovn_lflow_add(lflows, od, S_SWITCH_IN_STATEFUL, 100,
                  REGBIT_CONNTRACK_NAT" == 1", "ct_lb;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_STATEFUL, 100,
                  REGBIT_CONNTRACK_NAT" == 1", "ct_lb;");

    /* Load balancing rules for new connections get committed to conntrack
     * table.  So even if REGBIT_CONNTRACK_COMMIT is set in a previous table
     * a higher priority rule for load balancing below also commits the
     * connection, so it is okay if we do not hit the above match on
     * REGBIT_CONNTRACK_COMMIT. */
    for (int i = 0; i < od->nbs->n_load_balancer; i++) {
        struct ovn_northd_lb *lb =
            ovn_northd_lb_find(lbs, &od->nbs->load_balancer[i]->header_.uuid);

        ovs_assert(lb);
        build_lb_rules(od, lflows, lb);
    }
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
        /* Check if the packet needs to be hairpinned. */
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_PRE_HAIRPIN, 100,
                                "ip && ct.trk && ct.dnat",
                                REGBIT_HAIRPIN " = chk_lb_hairpin(); next;",
                                &od->nbs->header_);

        /* Check if the packet is a reply of hairpinned traffic. */
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_PRE_HAIRPIN, 90, "ip",
                                REGBIT_HAIRPIN " = chk_lb_hairpin_reply(); "
                                "next;", &od->nbs->header_);

        /* If packet needs to be hairpinned, snat the src ip with the VIP. */
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_NAT_HAIRPIN, 100,
                                "ip && (ct.new || ct.est) && ct.trk && ct.dnat"
                                " && "REGBIT_HAIRPIN " == 1",
                                "ct_snat_to_vip; next;",
                                &od->nbs->header_);

        /* For the reply of hairpinned traffic, snat the src ip to the VIP. */
        ovn_lflow_add_with_hint(lflows, od, S_SWITCH_IN_NAT_HAIRPIN, 90,
                                "ip && "REGBIT_HAIRPIN " == 1", "ct_snat;",
                                &od->nbs->header_);

        /* Ingress Hairpin table.
        * - Priority 1: Packets that were SNAT-ed for hairpinning should be
        *   looped back (i.e., swap ETH addresses and send back on inport).
        */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_HAIRPIN, 1,
                      REGBIT_HAIRPIN " == 1",
                      "eth.dst <-> eth.src;"
                      "outport = inport;"
                      "flags.loopback = 1;"
                      "output;");
    }
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

    if (od->l3dgw_port && od->l3redirect_port) {
        /* It's a logical router with gateway port. If it
         * has HA_Chassis_Group associated to it in SB DB, then store the
         * ha chassis group name. */
        if (od->l3redirect_port->sb->ha_chassis_group) {
            sset_add(&od->lr_group->ha_chassis_groups,
                     od->l3redirect_port->sb->ha_chassis_group->name);
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
 * Ingress table 19: Flows that flood self originated ARP/ND packets in the
 * switching domain.
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

        /* Check if the ovn port has a network configured on which we could
         * expect ARP requests/NS for the DNAT external_ip.
         */
        if (nat_entry_is_v6(nat_entry)) {
            struct in6_addr *addr = &nat_entry->ext_addrs.ipv6_addrs[0].addr;

            if (!lrouter_port_ipv6_reachable(op, addr)) {
                continue;
            }
        } else {
            ovs_be32 addr = nat_entry->ext_addrs.ipv4_addrs[0].addr;

            if (!lrouter_port_ipv4_reachable(op, addr)) {
                continue;
            }
        }
        sset_add(&all_eth_addrs, nat->external_mac);
    }

    /* Self originated ARP requests/ND need to be flooded to the L2 domain
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

    ds_put_format(&match, "eth.src == %s && (arp.op == 1 || nd_ns)",
                  ds_cstr(&eth_src));
    ovn_lflow_add_unique(lflows, od, S_SWITCH_IN_L2_LKUP, priority,
                         ds_cstr(&match),
                         "outport = \""MC_FLOOD_L2"\"; output;");

    sset_destroy(&all_eth_addrs);
    ds_destroy(&eth_src);
    ds_destroy(&match);
}

/*
 * Ingress table 19: Flows that forward ARP/ND requests only to the routers
 * that own the addresses. Other ARP/ND packets are still flooded in the
 * switching domain as regular broadcast.
 */
static void
build_lswitch_rport_arp_req_flow_for_ip(struct sset *ips,
                                        int addr_family,
                                        struct ovn_port *patch_op,
                                        struct ovn_datapath *od,
                                        uint32_t priority,
                                        struct hmap *lflows,
                                        const struct ovsdb_idl_row *stage_hint)
{
    struct ds match   = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    /* Packets received from VXLAN tunnels have already been through the
     * router pipeline so we should skip them. Normally this is done by the
     * multicast_group implementation (VXLAN packets skip table 32 which
     * delivers to patch ports) but we're bypassing multicast_groups.
     */
    ds_put_cstr(&match, FLAGBIT_NOT_VXLAN " && ");

    if (addr_family == AF_INET) {
        ds_put_cstr(&match, "arp.op == 1 && arp.tpa == { ");
    } else {
        ds_put_cstr(&match, "nd_ns && nd.target == { ");
    }

    const char *ip_address;
    SSET_FOR_EACH (ip_address, ips) {
        ds_put_format(&match, "%s, ", ip_address);
    }

    ds_chomp(&match, ' ');
    ds_chomp(&match, ',');
    ds_put_cstr(&match, "}");

    /* Send a the packet to the router pipeline.  If the switch has non-router
     * ports then flood it there as well.
     */
    if (od->n_router_ports != od->nbs->n_ports) {
        ds_put_format(&actions, "clone {outport = %s; output; }; "
                                "outport = \""MC_FLOOD_L2"\"; output;",
                      patch_op->json_key);
        ovn_lflow_add_unique_with_hint(lflows, od, S_SWITCH_IN_L2_LKUP,
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
 * Ingress table 19: Flows that forward ARP/ND requests only to the routers
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
    struct sset all_ips_v4 = SSET_INITIALIZER(&all_ips_v4);
    struct sset all_ips_v6 = SSET_INITIALIZER(&all_ips_v6);

    get_router_load_balancer_ips(op->od, &all_ips_v4, &all_ips_v6);

    const char *ip_addr;
    const char *ip_addr_next;
    SSET_FOR_EACH_SAFE (ip_addr, ip_addr_next, &all_ips_v4) {
        ovs_be32 ipv4_addr;

        /* Check if the ovn port has a network configured on which we could
         * expect ARP requests for the LB VIP.
         */
        if (ip_parse(ip_addr, &ipv4_addr) &&
                lrouter_port_ipv4_reachable(op, ipv4_addr)) {
            continue;
        }

        sset_delete(&all_ips_v4, SSET_NODE_FROM_NAME(ip_addr));
    }
    SSET_FOR_EACH_SAFE (ip_addr, ip_addr_next, &all_ips_v6) {
        struct in6_addr ipv6_addr;

        /* Check if the ovn port has a network configured on which we could
         * expect NS requests for the LB VIP.
         */
        if (ipv6_parse(ip_addr, &ipv6_addr) &&
                lrouter_port_ipv6_reachable(op, &ipv6_addr)) {
            continue;
        }

        sset_delete(&all_ips_v6, SSET_NODE_FROM_NAME(ip_addr));
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
            struct in6_addr *addr = &nat_entry->ext_addrs.ipv6_addrs[0].addr;

            if (lrouter_port_ipv6_reachable(op, addr)) {
                sset_add(&all_ips_v6, nat->external_ip);
            }
        } else {
            ovs_be32 addr = nat_entry->ext_addrs.ipv4_addrs[0].addr;

            if (lrouter_port_ipv4_reachable(op, addr)) {
                sset_add(&all_ips_v4, nat->external_ip);
            }
        }
    }

    for (size_t i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
        sset_add(&all_ips_v4, op->lrp_networks.ipv4_addrs[i].addr_s);
    }
    for (size_t i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
        sset_add(&all_ips_v6, op->lrp_networks.ipv6_addrs[i].addr_s);
    }

    if (!sset_is_empty(&all_ips_v4)) {
        build_lswitch_rport_arp_req_flow_for_ip(&all_ips_v4, AF_INET, sw_op,
                                                sw_od, 80, lflows,
                                                stage_hint);
    }
    if (!sset_is_empty(&all_ips_v6)) {
        build_lswitch_rport_arp_req_flow_for_ip(&all_ips_v6, AF_INET6, sw_op,
                                                sw_od, 80, lflows,
                                                stage_hint);
    }

    sset_destroy(&all_ips_v4);
    sset_destroy(&all_ips_v6);

    /* Self originated ARP requests/ND need to be flooded as usual.
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
                           const char *json_key, bool is_external,
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
                json_key, lsp_addrs->ea_s);

            if (is_external) {
                ds_put_format(&match, " && is_chassis_resident(%s)",
                              op->json_key);
            }

            ovn_lflow_add_with_hint(lflows, op->od,
                                    S_SWITCH_IN_DHCP_OPTIONS, 100,
                                    ds_cstr(&match),
                                    ds_cstr(&options_action),
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
                json_key, lsp_addrs->ea_s, ds_cstr(&ipv4_addr_match));

            if (is_external) {
                ds_put_format(&match, " && is_chassis_resident(%s)",
                              op->json_key);
            }

            ovn_lflow_add_with_hint(lflows, op->od,
                                    S_SWITCH_IN_DHCP_OPTIONS, 100,
                                    ds_cstr(&match),
                                    ds_cstr(&options_action),
                                    &op->nbsp->dhcpv4_options->header_);
            ds_clear(&match);

            /* If REGBIT_DHCP_OPTS_RESULT is set, it means the
             * put_dhcp_opts action is successful. */
            ds_put_format(
                &match, "inport == %s && eth.src == %s && "
                "ip4 && udp.src == 68 && udp.dst == 67"
                " && "REGBIT_DHCP_OPTS_RESULT,
                json_key, lsp_addrs->ea_s);

            if (is_external) {
                ds_put_format(&match, " && is_chassis_resident(%s)",
                              op->json_key);
            }

            ovn_lflow_add_with_hint(lflows, op->od,
                                    S_SWITCH_IN_DHCP_RESPONSE, 100,
                                    ds_cstr(&match),
                                    ds_cstr(&response_action),
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
                           const char *json_key, bool is_external,
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
                json_key, lsp_addrs->ea_s);

            if (is_external) {
                ds_put_format(&match, " && is_chassis_resident(%s)",
                              op->json_key);
            }

            ovn_lflow_add_with_hint(lflows, op->od,
                                    S_SWITCH_IN_DHCP_OPTIONS, 100,
                                    ds_cstr(&match),
                                    ds_cstr(&options_action),
                                    &op->nbsp->dhcpv6_options->header_);

            /* If REGBIT_DHCP_OPTS_RESULT is set to 1, it means the
             * put_dhcpv6_opts action is successful */
            ds_put_cstr(&match, " && "REGBIT_DHCP_OPTS_RESULT);
            ovn_lflow_add_with_hint(lflows, op->od,
                                    S_SWITCH_IN_DHCP_RESPONSE, 100,
                                    ds_cstr(&match),
                                    ds_cstr(&response_action),
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
                    ovn_lflow_add_with_hint(lflows, op->od,
                                            S_SWITCH_IN_EXTERNAL_PORT,
                                            100, ds_cstr(&match), "drop;",
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
                    ovn_lflow_add_with_hint(lflows, op->od,
                                            S_SWITCH_IN_EXTERNAL_PORT, 100,
                                            ds_cstr(&match), "drop;",
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
                ovn_lflow_add_with_hint(lflows, op->od,
                                        S_SWITCH_IN_EXTERNAL_PORT,
                                        100, ds_cstr(&match), "drop;",
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
build_lswitch_flows(struct hmap *datapaths, struct hmap *lflows)
{
    /* This flow table structure is documented in ovn-northd(8), so please
     * update ovn-northd.8.xml if you change anything. */

    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;
    struct ovn_datapath *od;

    /* Ingress table 19: Destination lookup for unknown MACs (priority 0). */
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbs) {
            continue;
        }

        if (od->has_unknown) {
            ovn_lflow_add_unique(lflows, od, S_SWITCH_IN_L2_LKUP, 0, "1",
                                 "outport = \""MC_UNKNOWN"\"; output;");
        }
    }

    ds_destroy(&match);
    ds_destroy(&actions);
}

/* Build pre-ACL and ACL tables for both ingress and egress.
 * Ingress tables 3 through 10.  Egress tables 0 through 7. */
static void
build_lswitch_lflows_pre_acl_and_acl(struct ovn_datapath *od,
                                     struct hmap *port_groups,
                                     struct hmap *lflows,
                                     struct shash *meter_groups,
                                     struct hmap *lbs)
{
    if (od->nbs) {
        od->has_stateful_acl = ls_has_stateful_acl(od);
        od->has_lb_vip = ls_has_lb_vip(od);

        build_pre_acls(od, lflows);
        build_pre_lb(od, lflows, meter_groups, lbs);
        build_pre_stateful(od, lflows);
        build_acl_hints(od, lflows);
        build_acls(od, lflows, port_groups, meter_groups);
        build_qos(od, lflows);
        build_lb(od, lflows);
        build_stateful(od, lflows, lbs);
        build_lb_hairpin(od, lflows);
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
            ovn_lflow_add(lflows, od, S_SWITCH_IN_PORT_SEC_L2, 100,
                          "vlan.present", "drop;");
        }

        /* Broadcast/multicast source address is invalid. */
        ovn_lflow_add(lflows, od, S_SWITCH_IN_PORT_SEC_L2, 100, "eth.src[40]",
                      "drop;");

        /* Port security flows have priority 50
         * (see build_lswitch_input_port_sec()) and will continue
         * to the next table if packet source is acceptable. */
    }
}

/* Ingress table 13: ARP/ND responder, skip requests coming from localnet
 * and vtep ports. (priority 100); see ovn-northd.8.xml for the
 * rationale. */

static void
build_lswitch_arp_nd_responder_skip_local(struct ovn_port *op,
                                          struct hmap *lflows,
                                          struct ds *match)
{
    if (op->nbsp) {
        if ((!strcmp(op->nbsp->type, "localnet")) ||
            (!strcmp(op->nbsp->type, "vtep"))) {
            ds_clear(match);
            ds_put_format(match, "inport == %s", op->json_key);
            ovn_lflow_add_with_hint(lflows, op->od, S_SWITCH_IN_ARP_ND_RSP,
                                    100, ds_cstr(match), "next;",
                                    &op->nbsp->header_);
        }
    }
}

/* Ingress table 13: ARP/ND responder, reply for known IPs.
 * (priority 50). */
static void
build_lswitch_arp_nd_responder_known_ips(struct ovn_port *op,
                                         struct hmap *lflows,
                                         struct hmap *ports,
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
             * */
            ovs_be32 ip;
            const char *virtual_ip = smap_get(&op->nbsp->options,
                                              "virtual-ip");
            const char *virtual_parents = smap_get(&op->nbsp->options,
                                                   "virtual-parents");
            if (!virtual_ip || !virtual_parents ||
                !ip_parse(virtual_ip, &ip)) {
                return;
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

                ds_clear(match);
                ds_put_format(match, "inport == \"%s\" && "
                              "((arp.op == 1 && arp.spa == %s && "
                              "arp.tpa == %s) || (arp.op == 2 && "
                              "arp.spa == %s))",
                              vparent, virtual_ip, virtual_ip,
                              virtual_ip);
                ds_clear(actions);
                ds_put_format(actions,
                    "bind_vport(%s, inport); "
                    "next;",
                    op->json_key);
                ovn_lflow_add_with_hint(lflows, op->od,
                                        S_SWITCH_IN_ARP_ND_RSP, 100,
                                        ds_cstr(match), ds_cstr(actions),
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
                    ovn_lflow_add_with_hint(lflows, op->od,
                                            S_SWITCH_IN_ARP_ND_RSP, 100,
                                            ds_cstr(match), "next;",
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
                    ovn_lflow_add_with_hint(lflows, op->od,
                                            S_SWITCH_IN_ARP_ND_RSP, 50,
                                            ds_cstr(match),
                                            ds_cstr(actions),
                                            &op->nbsp->header_);

                    /* Do not reply to a solicitation from the port that owns
                     * the address (otherwise DAD detection will fail). */
                    ds_put_format(match, " && inport == %s", op->json_key);
                    ovn_lflow_add_with_hint(lflows, op->od,
                                            S_SWITCH_IN_ARP_ND_RSP, 100,
                                            ds_cstr(match), "next;",
                                            &op->nbsp->header_);
                }
            }
        }
    }
}

/* Ingress table 13: ARP/ND responder, by default goto next.
 * (priority 0)*/
static void
build_lswitch_arp_nd_responder_default(struct ovn_datapath *od,
                                       struct hmap *lflows)
{
    if (od->nbs) {
        ovn_lflow_add(lflows, od, S_SWITCH_IN_ARP_ND_RSP, 0, "1", "next;");
    }
}

/* Ingress table 13: ARP/ND responder for service monitor source ip.
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


/* Logical switch ingress table 14 and 15: DHCP options and response
 * priority 100 flows. */
static void
build_lswitch_dhcp_options_and_response(struct ovn_port *op,
                                        struct hmap *lflows)
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
                        op->od->localnet_ports[j]->json_key, is_external,
                        lflows);
                    build_dhcpv6_options_flows(
                        op, &op->lsp_addrs[i],
                        op->od->localnet_ports[j]->json_key, is_external,
                        lflows);
                }
            } else {
                build_dhcpv4_options_flows(op, &op->lsp_addrs[i], op->json_key,
                                           is_external, lflows);
                build_dhcpv6_options_flows(op, &op->lsp_addrs[i], op->json_key,
                                           is_external, lflows);
            }
        }
    }
}

/* Ingress table 14 and 15: DHCP options and response, by default goto
 * next. (priority 0).
 * Ingress table 16 and 17: DNS lookup and response, by default goto next.
 * (priority 0).
 * Ingress table 18 - External port handling, by default goto next.
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

/* Logical switch ingress table 17 and 18: DNS lookup and response
* priority 100 flows.
*/
static void
build_lswitch_dns_lookup_and_response(struct ovn_datapath *od,
                                      struct hmap *lflows)
{
    if (od->nbs && ls_has_dns_records(od->nbs)) {

        ovn_lflow_add(lflows, od, S_SWITCH_IN_DNS_LOOKUP, 100,
                      "udp.dst == 53",
                      REGBIT_DNS_LOOKUP_RESULT" = dns_lookup(); next;");
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

/* Table 18: External port. Drop ARP request for router ips from
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

/* Ingress table 19: Destination lookup, broadcast and multicast handling
 * (priority 70 - 100). */
static void
build_lswitch_destination_lookup_bmcast(struct ovn_datapath *od,
                                        struct hmap *lflows,
                                        struct ds *actions)
{
    if (od->nbs) {

        ovn_lflow_add(lflows, od, S_SWITCH_IN_L2_LKUP, 110,
                      "eth.dst == $svc_monitor_mac",
                      "handle_svc_check(inport);");

        struct mcast_switch_info *mcast_sw_info = &od->mcast_info.sw;

        if (mcast_sw_info->enabled) {
            ds_clear(actions);
            if (mcast_sw_info->flood_reports) {
                ds_put_cstr(actions,
                            "clone { "
                                "outport = \""MC_MROUTER_STATIC"\"; "
                                "output; "
                            "};");
            }
            ds_put_cstr(actions, "igmp;");
            /* Punt IGMP traffic to controller. */
            ovn_lflow_add_unique(lflows, od, S_SWITCH_IN_L2_LKUP, 100,
                                 "ip4 && ip.proto == 2", ds_cstr(actions));

            /* Punt MLD traffic to controller. */
            ovn_lflow_add_unique(lflows, od, S_SWITCH_IN_L2_LKUP, 100,
                                 "mldv1 || mldv2", ds_cstr(actions));

            /* Flood all IP multicast traffic destined to 224.0.0.X to all
             * ports - RFC 4541, section 2.1.2, item 2.
             */
            ovn_lflow_add_unique(lflows, od, S_SWITCH_IN_L2_LKUP, 85,
                                 "ip4.mcast && ip4.dst == 224.0.0.0/24",
                                 "outport = \""MC_FLOOD"\"; output;");

            /* Flood all IPv6 multicast traffic destined to reserved
             * multicast IPs (RFC 4291, 2.7.1).
             */
            ovn_lflow_add_unique(lflows, od, S_SWITCH_IN_L2_LKUP, 85,
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
                    ds_put_cstr(actions, "drop;");
                }

                ovn_lflow_add_unique(lflows, od, S_SWITCH_IN_L2_LKUP, 80,
                                     "ip4.mcast || ip6.mcast",
                                     ds_cstr(actions));
            }
        }

        ovn_lflow_add_unique(lflows, od, S_SWITCH_IN_L2_LKUP, 70, "eth.mcast",
                             "outport = \""MC_FLOOD"\"; output;");
    }
}


/* Ingress table 19: Add IP multicast flows learnt from IGMP/MLD
 * (priority 90). */
static void
build_lswitch_ip_mcast_igmp_mld(struct ovn_igmp_group *igmp_group,
                                struct hmap *lflows,
                                struct ds *actions,
                                struct ds *match)
{
    if (igmp_group->datapath) {

        ds_clear(match);
        ds_clear(actions);

        struct mcast_switch_info *mcast_sw_info =
            &igmp_group->datapath->mcast_info.sw;

        if (IN6_IS_ADDR_V4MAPPED(&igmp_group->address)) {
            /* RFC 4541, section 2.1.2, item 2: Skip groups in the 224.0.0.X
             * range.
             */
            ovs_be32 group_address =
                in6_addr_get_mapped_ipv4(&igmp_group->address);
            if (ip_is_local_multicast(group_address)) {
                return;
            }

            if (mcast_sw_info->active_v4_flows >= mcast_sw_info->table_size) {
                return;
            }
            mcast_sw_info->active_v4_flows++;
            ds_put_format(match, "eth.mcast && ip4 && ip4.dst == %s ",
                          igmp_group->mcgroup.name);
        } else {
            /* RFC 4291, section 2.7.1: Skip groups that correspond to all
             * hosts.
             */
            if (ipv6_is_all_hosts(&igmp_group->address)) {
                return;
            }
            if (mcast_sw_info->active_v6_flows >= mcast_sw_info->table_size) {
                return;
            }
            mcast_sw_info->active_v6_flows++;
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

        ovn_lflow_add_unique(lflows, igmp_group->datapath, S_SWITCH_IN_L2_LKUP,
                             90, ds_cstr(match), ds_cstr(actions));
    }
}

/* Ingress table 19: Destination lookup, unicast handling (priority 50), */
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
            if (ovs_scan(op->nbsp->addresses[i],
                        ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))) {
                ds_clear(match);
                ds_put_format(match, "eth.dst == "ETH_ADDR_FMT,
                              ETH_ADDR_ARGS(mac));

                ds_clear(actions);
                ds_put_format(actions, "outport = %s; output;", op->json_key);
                ovn_lflow_add_with_hint(lflows, op->od, S_SWITCH_IN_L2_LKUP,
                                        50, ds_cstr(match),
                                        ds_cstr(actions),
                                        &op->nbsp->header_);
            } else if (!strcmp(op->nbsp->addresses[i], "unknown")) {
                if (lsp_is_enabled(op->nbsp)) {
                    ovn_multicast_add(mcgroups, &mc_unknown, op);
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
                ds_put_format(actions, "outport = %s; output;", op->json_key);
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
                if (op->peer->od->l3dgw_port
                    && op->peer->od->l3redirect_port
                    && op->od->n_localnet_ports) {
                    bool add_chassis_resident_check = false;
                    if (op->peer == op->peer->od->l3dgw_port) {
                        /* The peer of this port represents a distributed
                         * gateway port. The destination lookup flow for the
                         * router's distributed gateway port MAC address should
                         * only be programmed on the gateway chassis. */
                        add_chassis_resident_check = true;
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
                            "reside-on-redirect-chassis", false);
                    }

                    if (add_chassis_resident_check) {
                        ds_put_format(match, " && is_chassis_resident(%s)",
                                      op->peer->od->l3redirect_port->json_key);
                    }
                }

                ds_clear(actions);
                ds_put_format(actions, "outport = %s; output;", op->json_key);
                ovn_lflow_add_with_hint(lflows, op->od,
                                        S_SWITCH_IN_L2_LKUP, 50,
                                        ds_cstr(match), ds_cstr(actions),
                                        &op->nbsp->header_);

                /* Add ethernet addresses specified in NAT rules on
                 * distributed logical routers. */
                if (op->peer->od->l3dgw_port
                    && op->peer == op->peer->od->l3dgw_port) {
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
                            ds_put_format(actions, "outport = %s; output;",
                                          op->json_key);
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
bfd_port_lookup(struct hmap *bfd_map, const char *logical_port,
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

static void
bfd_cleanup_connections(struct northd_context *ctx, struct hmap *bfd_map)
{
    const struct nbrec_bfd *nb_bt;
    struct bfd_entry *bfd_e;

    NBREC_BFD_FOR_EACH (nb_bt, ctx->ovnnb_idl) {
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

static void
build_bfd_table(struct northd_context *ctx, struct hmap *bfd_connections,
                struct hmap *ports)
{
    struct hmap sb_only = HMAP_INITIALIZER(&sb_only);
    const struct sbrec_bfd *sb_bt;
    unsigned long *bfd_src_ports;
    struct bfd_entry *bfd_e;
    uint32_t hash;

    bfd_src_ports = bitmap_allocate(BFD_UDP_SRC_PORT_LEN);

    SBREC_BFD_FOR_EACH (sb_bt, ctx->ovnsb_idl) {
        bfd_e = xmalloc(sizeof *bfd_e);
        bfd_e->sb_bt = sb_bt;
        hash = hash_string(sb_bt->dst_ip, 0);
        hash = hash_string(sb_bt->logical_port, hash);
        hmap_insert(&sb_only, &bfd_e->hmap_node, hash);
        bitmap_set1(bfd_src_ports, sb_bt->src_port - BFD_UDP_SRC_PORT_START);
    }

    const struct nbrec_bfd *nb_bt;
    NBREC_BFD_FOR_EACH (nb_bt, ctx->ovnnb_idl) {
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

            sb_bt = sbrec_bfd_insert(ctx->ovnsb_txn);
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
        } else if (strcmp(bfd_e->sb_bt->status, nb_bt->status)) {
            if (!strcmp(nb_bt->status, "admin_down") ||
                !strcmp(bfd_e->sb_bt->status, "admin_down")) {
                sbrec_bfd_set_status(bfd_e->sb_bt, nb_bt->status);
            } else {
                nbrec_bfd_set_status(nb_bt, bfd_e->sb_bt->status);
            }
        }
        if (bfd_e) {
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
    bool is_ipv4 = strchr(ip_s, '.') ? true : false;

    if (is_ipv4) {
        ovs_be32 ip;

        if (!ip_parse(ip_s, &ip)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad ip address %s", ip_s);
            return NULL;
        }

        for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            const struct ipv4_netaddr *na = &op->lrp_networks.ipv4_addrs[i];

            if (!((na->network ^ ip) & na->mask)) {
                /* There should be only 1 interface that matches the
                 * supplied IP.  Otherwise, it's a configuration error,
                 * because subnets of a router's interfaces should NOT
                 * overlap. */
                return na->addr_s;
            }
        }
    } else {
        struct in6_addr ip6;

        if (!ipv6_parse(ip_s, &ip6)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad ipv6 address %s", ip_s);
            return NULL;
        }

        for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
            const struct ipv6_netaddr *na = &op->lrp_networks.ipv6_addrs[i];
            struct in6_addr xor_addr = ipv6_addr_bitxor(&na->network, &ip6);
            struct in6_addr and_addr = ipv6_addr_bitand(&xor_addr, &na->mask);

            if (ipv6_is_zero(&and_addr)) {
                /* There should be only 1 interface that matches the
                 * supplied IP.  Otherwise, it's a configuration error,
                 * because subnets of a router's interfaces should NOT
                 * overlap. */
                return na->addr_s;
            }
        }
    }

    return NULL;
}

static struct ovn_port*
get_outport_for_routing_policy_nexthop(struct ovn_datapath *od,
                                       struct hmap *ports,
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
                          struct hmap *ports,
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
        ds_put_cstr(&actions, "drop;");
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
                                struct hmap *ports,
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

struct parsed_route {
    struct ovs_list list_node;
    struct in6_addr prefix;
    unsigned int plen;
    bool is_src_route;
    uint32_t hash;
    const struct nbrec_logical_router_static_route *route;
    bool ecmp_symmetric_reply;
};

static uint32_t
route_hash(struct parsed_route *route)
{
    return hash_bytes(&route->prefix, sizeof route->prefix,
                      (uint32_t)route->plen);
}

/* Parse and validate the route. Return the parsed route if successful.
 * Otherwise return NULL. */
static struct parsed_route *
parsed_routes_add(struct ovs_list *routes,
                  const struct nbrec_logical_router_static_route *route,
                  struct hmap *bfd_connections)
{
    /* Verify that the next hop is an IP address with an all-ones mask. */
    struct in6_addr nexthop;
    unsigned int plen;
    if (!ip46_parse_cidr(route->nexthop, &nexthop, &plen)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad 'nexthop' %s in static route"
                     UUID_FMT, route->nexthop,
                     UUID_ARGS(&route->header_.uuid));
        return NULL;
    }
    if ((IN6_IS_ADDR_V4MAPPED(&nexthop) && plen != 32) ||
        (!IN6_IS_ADDR_V4MAPPED(&nexthop) && plen != 128)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad next hop mask %s in static route"
                     UUID_FMT, route->nexthop,
                     UUID_ARGS(&route->header_.uuid));
        return NULL;
    }

    /* Parse ip_prefix */
    struct in6_addr prefix;
    if (!ip46_parse_cidr(route->ip_prefix, &prefix, &plen)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad 'ip_prefix' %s in static route"
                     UUID_FMT, route->ip_prefix,
                     UUID_ARGS(&route->header_.uuid));
        return NULL;
    }

    /* Verify that ip_prefix and nexthop have same address familiy. */
    if (IN6_IS_ADDR_V4MAPPED(&prefix) != IN6_IS_ADDR_V4MAPPED(&nexthop)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Address family doesn't match between 'ip_prefix' %s"
                     " and 'nexthop' %s in static route"UUID_FMT,
                     route->ip_prefix, route->nexthop,
                     UUID_ARGS(&route->header_.uuid));
        return NULL;
    }

    const struct nbrec_bfd *nb_bt = route->bfd;
    if (nb_bt && !strcmp(nb_bt->dst_ip, route->nexthop)) {
        struct bfd_entry *bfd_e;

        bfd_e = bfd_port_lookup(bfd_connections, nb_bt->logical_port,
                                nb_bt->dst_ip);
        if (bfd_e) {
            bfd_e->ref = true;
        }

        if (!strcmp(nb_bt->status, "admin_down")) {
            nbrec_bfd_set_status(nb_bt, "down");
        }

        if (!strcmp(nb_bt->status, "down")) {
            return NULL;
        }
    }

    struct parsed_route *pr = xzalloc(sizeof *pr);
    pr->prefix = prefix;
    pr->plen = plen;
    pr->is_src_route = (route->policy && !strcmp(route->policy,
                                                 "src-ip"));
    pr->hash = route_hash(pr);
    pr->route = route;
    pr->ecmp_symmetric_reply = smap_get_bool(&route->options,
                                             "ecmp_symmetric_reply", false);
    ovs_list_insert(routes, &pr->list_node);
    return pr;
}

static void
parsed_routes_destroy(struct ovs_list *routes)
{
    struct parsed_route *pr, *next;
    LIST_FOR_EACH_SAFE (pr, next, list_node, routes) {
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
            eg->is_src_route == route->is_src_route) {
            return eg;
        }
    }
    return NULL;
}

static void
ecmp_groups_destroy(struct hmap *ecmp_groups)
{
    struct ecmp_groups_node *eg, *next;
    HMAP_FOR_EACH_SAFE (eg, next, hmap_node, ecmp_groups) {
        struct ecmp_route_list_node *er, *er_next;
        LIST_FOR_EACH_SAFE (er, er_next, list_node, &eg->route_list) {
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
            route->is_src_route == ur->route->is_src_route) {
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
    struct unique_routes_node *ur, *next;
    HMAP_FOR_EACH_SAFE (ur, next, hmap_node, unique_routes) {
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
build_route_match(const struct ovn_port *op_inport, const char *network_s,
                  int plen, bool is_src_route, bool is_ipv4, struct ds *match,
                  uint16_t *priority)
{
    const char *dir;
    /* The priority here is calculated to implement longest-prefix-match
     * routing. */
    if (is_src_route) {
        dir = "src";
        *priority = plen * 2;
    } else {
        dir = "dst";
        *priority = (plen * 2) + 1;
    }

    if (op_inport) {
        ds_put_format(match, "inport == %s && ", op_inport->json_key);
    }
    ds_put_format(match, "ip%s.%s == %s/%d", is_ipv4 ? "4" : "6", dir,
                  network_s, plen);
}

/* Output: p_lrp_addr_s and p_out_port. */
static bool
find_static_route_outport(struct ovn_datapath *od, struct hmap *ports,
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
        lrp_addr_s = find_lrp_member_ip(out_port, route->nexthop);
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

            lrp_addr_s = find_lrp_member_ip(out_port, route->nexthop);
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
    *p_out_port = out_port;
    *p_lrp_addr_s = lrp_addr_s;

    return true;
}

static void
add_ecmp_symmetric_reply_flows(struct hmap *lflows,
                               struct ovn_datapath *od,
                               const char *port_ip,
                               struct ovn_port *out_port,
                               const struct parsed_route *route,
                               struct ds *route_match)
{
    const struct nbrec_logical_router_static_route *st_route = route->route;
    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;
    struct ds ecmp_reply = DS_EMPTY_INITIALIZER;
    char *cidr = normalize_v46_prefix(&route->prefix, route->plen);

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
                            &st_route->header_);

    /* And packets that go out over an ECMP route need conntrack */
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DEFRAG, 100,
                            ds_cstr(route_match), "ct_next;",
                            &st_route->header_);

    /* Save src eth and inport in ct_label for packets that arrive over
     * an ECMP route.
     *
     * NOTE: we purposely are not clearing match before this
     * ds_put_cstr() call. The previous contents are needed.
     */
    ds_put_cstr(&match, " && (ct.new && !ct.est)");

    ds_put_format(&actions, "ct_commit { ct_label.ecmp_reply_eth = eth.src;"
                  " ct_label.ecmp_reply_port = %" PRId64 ";}; next;",
                  out_port->sb->tunnel_key);
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_ECMP_STATEFUL, 100,
                            ds_cstr(&match), ds_cstr(&actions),
                            &st_route->header_);

    /* Bypass ECMP selection if we already have ct_label information
     * for where to route the packet.
     */
    ds_put_format(&ecmp_reply, "ct.rpl && ct_label.ecmp_reply_port == %"
                  PRId64, out_port->sb->tunnel_key);
    ds_clear(&match);
    ds_put_format(&match, "%s && %s", ds_cstr(&ecmp_reply),
                  ds_cstr(route_match));
    ds_clear(&actions);
    ds_put_format(&actions, "ip.ttl--; flags.loopback = 1; "
                  "eth.src = %s; %sreg1 = %s; outport = %s; next;",
                  out_port->lrp_networks.ea_s,
                  IN6_IS_ADDR_V4MAPPED(&route->prefix) ? "" : "xx",
                  port_ip, out_port->json_key);
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_IP_ROUTING, 100,
                           ds_cstr(&match), ds_cstr(&actions),
                           &st_route->header_);

    /* Egress reply traffic for symmetric ECMP routes skips router policies. */
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_POLICY, 65535,
                            ds_cstr(&ecmp_reply), "next;",
                            &st_route->header_);

    const char *action = "eth.dst = ct_label.ecmp_reply_eth; next;";
    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_ARP_RESOLVE,
                            200, ds_cstr(&ecmp_reply),
                            action, &st_route->header_);

    ds_destroy(&match);
    ds_destroy(&actions);
    ds_destroy(&ecmp_reply);
}

static void
build_ecmp_route_flow(struct hmap *lflows, struct ovn_datapath *od,
                      struct hmap *ports, struct ecmp_groups_node *eg)

{
    bool is_ipv4 = IN6_IS_ADDR_V4MAPPED(&eg->prefix);
    uint16_t priority;
    struct ecmp_route_list_node *er;
    struct ds route_match = DS_EMPTY_INITIALIZER;

    char *prefix_s = build_route_prefix_s(&eg->prefix, eg->plen);
    build_route_match(NULL, prefix_s, eg->plen, eg->is_src_route, is_ipv4,
                      &route_match, &priority);
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
            add_ecmp_symmetric_reply_flows(lflows, od, lrp_addr_s, out_port,
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
add_route(struct hmap *lflows, const struct ovn_port *op,
          const char *lrp_addr_s, const char *network_s, int plen,
          const char *gateway, bool is_src_route,
          const struct ovsdb_idl_row *stage_hint)
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
    build_route_match(op_inport, network_s, plen, is_src_route, is_ipv4,
                      &match, &priority);

    struct ds common_actions = DS_EMPTY_INITIALIZER;
    ds_put_format(&common_actions, REG_ECMP_GROUP_ID" = 0; %s = ",
                  is_ipv4 ? REG_NEXT_HOP_IPV4 : REG_NEXT_HOP_IPV6);
    if (gateway) {
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
    struct ds actions = DS_EMPTY_INITIALIZER;
    ds_put_format(&actions, "ip.ttl--; %s", ds_cstr(&common_actions));

    ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_ROUTING, priority,
                            ds_cstr(&match), ds_cstr(&actions),
                            stage_hint);
    if (op->has_bfd) {
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
                        struct hmap *ports,
                        const struct parsed_route *route_)
{
    const char *lrp_addr_s = NULL;
    struct ovn_port *out_port = NULL;

    const struct nbrec_logical_router_static_route *route = route_->route;

    /* Find the outgoing port. */
    if (!find_static_route_outport(od, ports, route,
                                   IN6_IS_ADDR_V4MAPPED(&route_->prefix),
                                   &lrp_addr_s, &out_port)) {
        return;
    }

    char *prefix_s = build_route_prefix_s(&route_->prefix, route_->plen);
    add_route(lflows, out_port, lrp_addr_s, prefix_s, route_->plen,
              route->nexthop, route_->is_src_route,
              &route->header_);

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
add_router_lb_flow(struct hmap *lflows, struct ovn_datapath *od,
                   struct ds *match, struct ds *actions, int priority,
                   bool lb_force_snat_ip, struct ovn_lb_vip *lb_vip,
                   const char *proto, struct nbrec_load_balancer *lb,
                   struct shash *meter_groups, struct sset *nat_entries)
{
    build_empty_lb_event_flow(od, lflows, lb_vip, lb, S_ROUTER_IN_DNAT,
                              meter_groups);

    /* A match and actions for new connections. */
    char *new_match = xasprintf("ct.new && %s", ds_cstr(match));
    if (lb_force_snat_ip) {
        char *new_actions = xasprintf("flags.force_snat_for_lb = 1; %s",
                                      ds_cstr(actions));
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DNAT, priority,
                                new_match, new_actions, &lb->header_);
        free(new_actions);
    } else {
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DNAT, priority,
                                new_match, ds_cstr(actions), &lb->header_);
    }

    /* A match and actions for established connections. */
    char *est_match = xasprintf("ct.est && %s", ds_cstr(match));
    if (lb_force_snat_ip) {
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DNAT, priority,
                                est_match,
                                "flags.force_snat_for_lb = 1; ct_dnat;",
                                &lb->header_);
    } else {
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DNAT, priority,
                                est_match, "ct_dnat;", &lb->header_);
    }

    free(new_match);
    free(est_match);

    const char *ip_match = NULL;
    if (IN6_IS_ADDR_V4MAPPED(&lb_vip->vip)) {
        ip_match = "ip4";
    } else {
        ip_match = "ip6";
    }

    if (sset_contains(nat_entries, lb_vip->vip_str)) {
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
        struct ds unsnat_match = DS_EMPTY_INITIALIZER;
        ds_put_format(&unsnat_match, "%s && %s.dst == %s && %s",
                      ip_match, ip_match, lb_vip->vip_str, proto);
        if (lb_vip->vip_port) {
            ds_put_format(&unsnat_match, " && %s.dst == %d", proto,
                          lb_vip->vip_port);
        }

        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_UNSNAT, 120,
                                ds_cstr(&unsnat_match), "next;", &lb->header_);

        ds_destroy(&unsnat_match);
    }

    if (!od->l3dgw_port || !od->l3redirect_port || !lb_vip->n_backends) {
        return;
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

        if (backend->port) {
            ds_put_format(&undnat_match, " && %s.src == %d) || ",
                          proto, backend->port);
        } else {
            ds_put_cstr(&undnat_match, ") || ");
        }
    }

    ds_chomp(&undnat_match, ' ');
    ds_chomp(&undnat_match, '|');
    ds_chomp(&undnat_match, '|');
    ds_chomp(&undnat_match, ' ');
    ds_put_format(&undnat_match, ") && outport == %s && "
                 "is_chassis_resident(%s)", od->l3dgw_port->json_key,
                 od->l3redirect_port->json_key);
    if (lb_force_snat_ip) {
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_UNDNAT, 120,
                                ds_cstr(&undnat_match),
                                "flags.force_snat_for_lb = 1; ct_dnat;",
                                &lb->header_);
    } else {
        ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_UNDNAT, 120,
                                ds_cstr(&undnat_match), "ct_dnat;",
                                &lb->header_);
    }

    ds_destroy(&undnat_match);
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
                             bool is_v6, bool is_src, ovs_be32 mask)
{
    struct nbrec_address_set *allowed_ext_ips = nat->allowed_ext_ips;
    struct nbrec_address_set *exempted_ext_ips = nat->exempted_ext_ips;
    bool is_gw_router = !od->l3dgw_port;

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
         * +1 of the corresponding regulr NAT rule.
         * For example, if we have following NAT rule and we associate
         * exempted external ips to it:
         * "ovn-nbctl lr-nat-add router dnat_and_snat 10.15.24.139 50.0.0.11"
         *
         * And now we associate exempted external ip address set to it.
         * Now corresponding to above rule we will have following logical
         * flows:
         * lr_out_snat...priority=162, match=(..ip4.dst == $exempt_range),
         *                             action=(next;)
         * lr_out_snat...priority=161, match=(..), action=(ct_snat(....);)
         *
         */
        if (is_src) {
            /* S_ROUTER_IN_DNAT uses priority 100 */
            priority = 100 + 1;
        } else {
            /* S_ROUTER_OUT_SNAT uses priority (mask + 1 + 128 + 1) */
            priority = count_1bits(ntohl(mask)) + 2;

            if (!is_gw_router) {
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
        ds_put_format(&actions, "drop;");
    } else {
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
                      eth_addr,
                      eth_addr,
                      ip_address);
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
                      struct hmap *lflows)
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
        ds_put_format(&actions, "drop;");
    } else {
        ds_put_format(&actions,
                      "%s { "
                        "eth.src = %s; "
                        "ip6.src = %s; "
                        "nd.target = %s; "
                        "nd.tll = %s; "
                        "outport = inport; "
                        "flags.loopback = 1; "
                        "output; "
                      "};",
                      action,
                      eth_addr,
                      ip_address,
                      ip_address,
                      eth_addr);
    }

    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_IP_INPUT, priority,
                            ds_cstr(&match), ds_cstr(&actions), hint);

    ds_destroy(&match);
    ds_destroy(&actions);
}

static void
build_lrouter_nat_arp_nd_flow(struct ovn_datapath *od,
                              struct ovn_nat *nat_entry,
                              struct hmap *lflows)
{
    struct lport_addresses *ext_addrs = &nat_entry->ext_addrs;
    const struct nbrec_nat *nat = nat_entry->nb;

    if (nat_entry_is_v6(nat_entry)) {
        build_lrouter_nd_flow(od, NULL, "nd_na",
                              ext_addrs->ipv6_addrs[0].addr_s,
                              ext_addrs->ipv6_addrs[0].sn_addr_s,
                              REG_INPORT_ETH_ADDR, NULL, false, 90,
                              &nat->header_, lflows);
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
                                   struct hmap *lflows)
{
    struct lport_addresses *ext_addrs = &nat_entry->ext_addrs;
    const struct nbrec_nat *nat = nat_entry->nb;
    struct ds match = DS_EMPTY_INITIALIZER;

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
        if (op->od->l3redirect_port) {
            ds_put_format(&match, "is_chassis_resident(%s)",
                          op->od->l3redirect_port->json_key);
        }
    }

    /* Respond to ARP/NS requests on the chassis that binds the gw
     * port. Drop the ARP/NS requests on other chassis.
     */
    if (nat_entry_is_v6(nat_entry)) {
        build_lrouter_nd_flow(op->od, op, "nd_na",
                              ext_addrs->ipv6_addrs[0].addr_s,
                              ext_addrs->ipv6_addrs[0].sn_addr_s,
                              mac_s, &match, false, 92,
                              &nat->header_, lflows);
        build_lrouter_nd_flow(op->od, op, "nd_na",
                              ext_addrs->ipv6_addrs[0].addr_s,
                              ext_addrs->ipv6_addrs[0].sn_addr_s,
                              mac_s, NULL, true, 91,
                              &nat->header_, lflows);
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
            bool drop_router_ip = (drop_snat_ip == router_ip_in_snat_ips);

            if (drop_router_ip) {
                ds_put_format(&match_ips, "%s, ", ip);
            }
        }

        if (ds_last(&match_ips) != EOF) {
            ds_chomp(&match_ips, ' ');
            ds_chomp(&match_ips, ',');

            char *match = xasprintf("ip4.dst == {%s}", ds_cstr(&match_ips));
            ovn_lflow_add_with_hint(lflows, op->od, stage, priority,
                                    match, "drop;",
                                    &op->nbrp->header_);
            free(match);
        }
    }

    if (op->lrp_networks.n_ipv6_addrs) {
        ds_clear(&match_ips);

        for (size_t i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
            const char *ip = op->lrp_networks.ipv6_addrs[i].addr_s;

            bool router_ip_in_snat_ips = !!shash_find(&op->od->snat_ips, ip);
            bool drop_router_ip = (drop_snat_ip == router_ip_in_snat_ips);

            if (drop_router_ip) {
                ds_put_format(&match_ips, "%s, ", ip);
            }
        }

        if (ds_last(&match_ips) != EOF) {
            ds_chomp(&match_ips, ' ');
            ds_chomp(&match_ips, ',');

            char *match = xasprintf("ip6.dst == {%s}", ds_cstr(&match_ips));
            ovn_lflow_add_with_hint(lflows, op->od, stage, priority,
                                    match, "drop;",
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
build_lrouter_bfd_flows(struct hmap *lflows, struct ovn_port *op)
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
        ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT, 110,
                                ds_cstr(&match), "handle_bfd_msg(); ",
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
        ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT, 110,
                                ds_cstr(&match), "handle_bfd_msg(); ",
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
                      "vlan.present || eth.src[40]", "drop;");
    }
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

        if (op->derived) {
            /* No ingress packets should be received on a chassisredirect
             * port. */
            return;
        }

        /* Store the ethernet address of the port receiving the packet.
         * This will save us from having to match on inport further down in
         * the pipeline.
         */
        ds_clear(actions);
        ds_put_format(actions, REG_INPORT_ETH_ADDR " = %s; next;",
                      op->lrp_networks.ea_s);

        ds_clear(match);
        ds_put_format(match, "eth.mcast && inport == %s", op->json_key);
        ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_ADMISSION, 50,
                                ds_cstr(match), ds_cstr(actions),
                                &op->nbrp->header_);

        ds_clear(match);
        ds_put_format(match, "eth.dst == %s && inport == %s",
                      op->lrp_networks.ea_s, op->json_key);
        if (op->od->l3dgw_port && op == op->od->l3dgw_port
            && op->od->l3redirect_port) {
            /* Traffic with eth.dst = l3dgw_port->lrp_networks.ea_s
             * should only be received on the gateway chassis. */
            ds_put_format(match, " && is_chassis_resident(%s)",
                          op->od->l3redirect_port->json_key);
        }
        ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_ADMISSION, 50,
                                ds_cstr(match),  ds_cstr(actions),
                                &op->nbrp->header_);
    }
}


/* Logical router ingress Table 1 and 2: Neighbor lookup and learning
 * lflows for logical routers. */
static void
build_neigh_learning_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows,
        struct ds *match, struct ds *actions)
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

        ovn_lflow_add(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                      "arp", "put_arp(inport, arp.spa, arp.sha); next;");

        ovn_lflow_add(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                      "nd_na", "put_nd(inport, nd.target, nd.tll); next;");

        ovn_lflow_add(lflows, od, S_ROUTER_IN_LEARN_NEIGHBOR, 90,
                      "nd_ns", "put_nd(inport, ip6.src, nd.sll); next;");
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
                if (op->od->l3dgw_port && op == op->od->l3dgw_port
                    && op->od->l3redirect_port) {
                    ds_put_format(match, " && is_chassis_resident(%s)",
                                  op->od->l3redirect_port->json_key);
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
            if (op->od->l3dgw_port && op == op->od->l3dgw_port
                && op->od->l3redirect_port) {
                ds_put_format(match, " && is_chassis_resident(%s)",
                              op->od->l3redirect_port->json_key);
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
        struct ds *match, struct ds *actions)
{
    if (!op->nbrp || op->nbrp->peer || !op->peer) {
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
    smap_add(&options, "ipv6_prefix_delegation",
             prefix_delegation ? "true" : "false");

    bool ipv6_prefix = smap_get_bool(&op->nbrp->options,
                                     "prefix", false);
    if (!lrport_is_enabled(op->nbrp)) {
        ipv6_prefix = false;
    }
    smap_add(&options, "ipv6_prefix",
             ipv6_prefix ? "true" : "false");
    sbrec_port_binding_set_options(op->sb, &options);

    smap_destroy(&options);

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

    if (smap_get_bool(&op->nbrp->ipv6_ra_configs, "send_periodic",
                      false)) {
        copy_ra_to_sb(op, address_mode);
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
        ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_ND_RA_OPTIONS,
                                50, ds_cstr(match), ds_cstr(actions),
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
        struct ovn_port *op, struct hmap *lflows)
{
    if (op->nbrp) {

        for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            add_route(lflows, op, op->lrp_networks.ipv4_addrs[i].addr_s,
                      op->lrp_networks.ipv4_addrs[i].network_s,
                      op->lrp_networks.ipv4_addrs[i].plen, NULL, false,
                      &op->nbrp->header_);
        }

        for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
            add_route(lflows, op, op->lrp_networks.ipv6_addrs[i].addr_s,
                      op->lrp_networks.ipv6_addrs[i].network_s,
                      op->lrp_networks.ipv6_addrs[i].plen, NULL, false,
                      &op->nbrp->header_);
        }
    }
}

static void
build_static_route_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows,
        struct hmap *ports, struct hmap *bfd_connections)
{
    if (od->nbr) {
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING_ECMP, 150,
                      REG_ECMP_GROUP_ID" == 0", "next;");

        struct hmap ecmp_groups = HMAP_INITIALIZER(&ecmp_groups);
        struct hmap unique_routes = HMAP_INITIALIZER(&unique_routes);
        struct ovs_list parsed_routes = OVS_LIST_INITIALIZER(&parsed_routes);
        struct ecmp_groups_node *group;
        for (int i = 0; i < od->nbr->n_static_routes; i++) {
            struct parsed_route *route =
                parsed_routes_add(&parsed_routes, od->nbr->static_routes[i],
                                  bfd_connections);
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
            build_ecmp_route_flow(lflows, od, ports, group);
        }
        const struct unique_routes_node *ur;
        HMAP_FOR_EACH (ur, hmap_node, &unique_routes) {
            build_static_route_flow(lflows, od, ports, ur->route);
        }
        ecmp_groups_destroy(&ecmp_groups);
        unique_routes_destroy(&unique_routes);
        parsed_routes_destroy(&parsed_routes);
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
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 550,
                      "nd_rs || nd_ra", "drop;");
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
            ovn_lflow_add_unique(lflows, od, S_ROUTER_IN_IP_ROUTING, 500,
                                 ds_cstr(match), ds_cstr(actions));
        }

        /* If needed, flood unregistered multicast on statically configured
         * ports. Otherwise drop any multicast traffic.
         */
        if (od->mcast_info.rtr.flood_static) {
            ovn_lflow_add_unique(lflows, od, S_ROUTER_IN_IP_ROUTING, 450,
                          "ip4.mcast || ip6.mcast",
                          "clone { "
                                "outport = \""MC_STATIC"\"; "
                                "ip.ttl--; "
                                "next; "
                          "};");
        } else {
            ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_ROUTING, 450,
                          "ip4.mcast || ip6.mcast", "drop;");
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
        struct hmap *ports)
{
    if (od->nbr) {
        /* This is a catch-all rule. It has the lowest priority (0)
         * does a match-all("1") and pass-through (next) */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_POLICY, 0, "1",
                      REG_ECMP_GROUP_ID" = 0; next;");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_POLICY_ECMP, 150,
                      REG_ECMP_GROUP_ID" == 0", "next;");

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

        ovn_lflow_add(lflows, od, S_ROUTER_IN_ARP_RESOLVE, 0, "ip4",
                      "get_arp(outport, " REG_NEXT_HOP_IPV4 "); next;");

        ovn_lflow_add(lflows, od, S_ROUTER_IN_ARP_RESOLVE, 0, "ip6",
                      "get_nd(outport, " REG_NEXT_HOP_IPV6 "); next;");
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
        struct hmap *ports,
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

        if (!op->derived && op->od->l3redirect_port) {
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
                              op->od->l3redirect_port->json_key);
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
         * Priority 1.
         */
        build_lrouter_drop_own_dest(op, S_ROUTER_IN_ARP_RESOLVE, 1, true,
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
                    const char *peer_name = smap_get(
                        &op->od->router_ports[k]->nbsp->options,
                        "router-port");
                    if (!peer_name) {
                        continue;
                    }

                    struct ovn_port *peer = ovn_port_find(ports, peer_name);
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
                    const char *peer_name = smap_get(
                        &op->od->router_ports[k]->nbsp->options,
                        "router-port");
                    if (!peer_name) {
                        continue;
                    }

                    struct ovn_port *peer = ovn_port_find(ports, peer_name);
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
        ovs_be32 ip;

        const char *vip = smap_get(&op->nbsp->options,
                                   "virtual-ip");
        const char *virtual_parents = smap_get(&op->nbsp->options,
                                               "virtual-parents");
        if (!vip || !virtual_parents ||
            !ip_parse(vip, &ip) || !op->sb) {
            return;
        }

        if (!op->sb->virtual_parent || !op->sb->virtual_parent[0] ||
            !op->sb->chassis) {
            /* The virtual port is not claimed yet. */
            for (size_t i = 0; i < op->od->n_router_ports; i++) {
                const char *peer_name = smap_get(
                    &op->od->router_ports[i]->nbsp->options,
                    "router-port");
                if (!peer_name) {
                    continue;
                }

                struct ovn_port *peer = ovn_port_find(ports, peer_name);
                if (!peer || !peer->nbrp) {
                    continue;
                }

                if (find_lrp_member_ip(peer, vip)) {
                    ds_clear(match);
                    ds_put_format(match, "outport == %s && "
                                  REG_NEXT_HOP_IPV4 " == %s",
                                  peer->json_key, vip);

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
                    const char *peer_name = smap_get(
                        &vp->od->router_ports[j]->nbsp->options,
                        "router-port");
                    if (!peer_name) {
                        continue;
                    }

                    struct ovn_port *peer =
                        ovn_port_find(ports, peer_name);
                    if (!peer || !peer->nbrp) {
                        continue;
                    }

                    if (!find_lrp_member_ip(peer, vip)) {
                        continue;
                    }

                    ds_clear(match);
                    ds_put_format(match, "outport == %s && "
                                  REG_NEXT_HOP_IPV4 " == %s",
                                  peer->json_key, vip);

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

        const char *peer_name = smap_get(&op->nbsp->options,
                                         "router-port");
        if (!peer_name) {
            return;
        }

        struct ovn_port *peer = ovn_port_find(ports, peer_name);
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
        }
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
        struct hmap *ports,
        struct ds *match, struct ds *actions)
{
    if (od->nbr) {

        /* Packets are allowed by default. */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_CHK_PKT_LEN, 0, "1",
                      "next;");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_LARGER_PKTS, 0, "1",
                      "next;");

        if (od->l3dgw_port && od->l3redirect_port) {
            int gw_mtu = 0;
            if (od->l3dgw_port->nbrp) {
                 gw_mtu = smap_get_int(&od->l3dgw_port->nbrp->options,
                                       "gateway_mtu", 0);
            }
            /* Add the flows only if gateway_mtu is configured. */
            if (gw_mtu <= 0) {
                return;
            }

            ds_clear(match);
            ds_put_format(match, "outport == %s", od->l3dgw_port->json_key);

            ds_clear(actions);
            ds_put_format(actions,
                          REGBIT_PKT_LARGER" = check_pkt_larger(%d);"
                          " next;", gw_mtu + VLAN_ETH_HEADER_LEN);
            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_CHK_PKT_LEN, 50,
                                    ds_cstr(match), ds_cstr(actions),
                                    &od->l3dgw_port->nbrp->header_);

            for (size_t i = 0; i < od->nbr->n_ports; i++) {
                struct ovn_port *rp = ovn_port_find(ports,
                                                    od->nbr->ports[i]->name);
                if (!rp || rp == od->l3dgw_port) {
                    continue;
                }

                if (rp->lrp_networks.ipv4_addrs) {
                    ds_clear(match);
                    ds_put_format(match, "inport == %s && outport == %s"
                                  " && ip4 && "REGBIT_PKT_LARGER,
                                  rp->json_key, od->l3dgw_port->json_key);

                    ds_clear(actions);
                    /* Set icmp4.frag_mtu to gw_mtu */
                    ds_put_format(actions,
                        "icmp4_error {"
                        REGBIT_EGRESS_LOOPBACK" = 1; "
                        "eth.dst = %s; "
                        "ip4.dst = ip4.src; "
                        "ip4.src = %s; "
                        "ip.ttl = 255; "
                        "icmp4.type = 3; /* Destination Unreachable. */ "
                        "icmp4.code = 4; /* Frag Needed and DF was Set. */ "
                        "icmp4.frag_mtu = %d; "
                        "next(pipeline=ingress, table=%d); };",
                        rp->lrp_networks.ea_s,
                        rp->lrp_networks.ipv4_addrs[0].addr_s,
                        gw_mtu,
                        ovn_stage_get_table(S_ROUTER_IN_ADMISSION));
                    ovn_lflow_add_with_hint(lflows, od,
                                            S_ROUTER_IN_LARGER_PKTS, 50,
                                            ds_cstr(match), ds_cstr(actions),
                                            &rp->nbrp->header_);
                }

                if (rp->lrp_networks.ipv6_addrs) {
                    ds_clear(match);
                    ds_put_format(match, "inport == %s && outport == %s"
                                  " && ip6 && "REGBIT_PKT_LARGER,
                                  rp->json_key, od->l3dgw_port->json_key);

                    ds_clear(actions);
                    /* Set icmp6.frag_mtu to gw_mtu */
                    ds_put_format(actions,
                        "icmp6_error {"
                        REGBIT_EGRESS_LOOPBACK" = 1; "
                        "eth.dst = %s; "
                        "ip6.dst = ip6.src; "
                        "ip6.src = %s; "
                        "ip.ttl = 255; "
                        "icmp6.type = 2; /* Packet Too Big. */ "
                        "icmp6.code = 0; "
                        "icmp6.frag_mtu = %d; "
                        "next(pipeline=ingress, table=%d); };",
                        rp->lrp_networks.ea_s,
                        rp->lrp_networks.ipv6_addrs[0].addr_s,
                        gw_mtu,
                        ovn_stage_get_table(S_ROUTER_IN_ADMISSION));
                    ovn_lflow_add_with_hint(lflows, od,
                                            S_ROUTER_IN_LARGER_PKTS, 50,
                                            ds_cstr(match), ds_cstr(actions),
                                            &rp->nbrp->header_);
                }
            }
        }
    }
}

/* Logical router ingress table GW_REDIRECT: Gateway redirect.
 *
 * For traffic with outport equal to the l3dgw_port
 * on a distributed router, this table redirects a subset
 * of the traffic to the l3redirect_port which represents
 * the central instance of the l3dgw_port.
 */
static void
build_gateway_redirect_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows,
        struct ds *match, struct ds *actions)
{
    if (od->nbr) {
        if (od->l3dgw_port && od->l3redirect_port) {
            const struct ovsdb_idl_row *stage_hint = NULL;

            if (od->l3dgw_port->nbrp) {
                stage_hint = &od->l3dgw_port->nbrp->header_;
            }

            /* For traffic with outport == l3dgw_port, if the
             * packet did not match any higher priority redirect
             * rule, then the traffic is redirected to the central
             * instance of the l3dgw_port. */
            ds_clear(match);
            ds_put_format(match, "outport == %s",
                          od->l3dgw_port->json_key);
            ds_clear(actions);
            ds_put_format(actions, "outport = %s; next;",
                          od->l3redirect_port->json_key);
            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_GW_REDIRECT, 50,
                                    ds_cstr(match), ds_cstr(actions),
                                    stage_hint);
        }

        /* Packets are allowed by default. */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_GW_REDIRECT, 0, "1", "next;");
    }
}

/* Local router ingress table ARP_REQUEST: ARP request.
 *
 * In the common case where the Ethernet destination has been resolved,
 * this table outputs the packet (priority 0).  Otherwise, it composes
 * and sends an ARP/IPv6 NA request (priority 100). */
static void
build_arp_request_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows,
        struct ds *match, struct ds *actions)
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

            ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_ARP_REQUEST, 200,
                                    ds_cstr(match), ds_cstr(actions),
                                    &route->header_);
        }

        ovn_lflow_add(lflows, od, S_ROUTER_IN_ARP_REQUEST, 100,
                      "eth.dst == 00:00:00:00:00:00 && ip4",
                      "arp { "
                      "eth.dst = ff:ff:ff:ff:ff:ff; "
                      "arp.spa = " REG_SRC_IPV4 "; "
                      "arp.tpa = " REG_NEXT_HOP_IPV4 "; "
                      "arp.op = 1; " /* ARP request */
                      "output; "
                      "};");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_ARP_REQUEST, 100,
                      "eth.dst == 00:00:00:00:00:00 && ip6",
                      "nd_ns { "
                      "nd.target = " REG_NEXT_HOP_IPV6 "; "
                      "output; "
                      "};");
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

        if (op->derived) {
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
    }

}

static void
build_misc_local_traffic_drop_flows_for_lrouter(
        struct ovn_datapath *od, struct hmap *lflows)
{
    if (od->nbr) {
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
                      "drop;");

        /* Drop ARP packets (priority 85). ARP request packets for router's own
         * IPs are handled with priority-90 flows.
         * Drop IPv6 ND packets (priority 85). ND NA packets for router's own
         * IPs are handled with priority-90 flows.
         */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 85,
                      "arp || nd", "drop;");

        /* Allow IPv6 multicast traffic that's supposed to reach the
         * router pipeline (e.g., router solicitations).
         */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 84, "nd_rs || nd_ra",
                      "next;");

        /* Drop other reserved multicast. */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 83,
                      "ip6.mcast_rsvd", "drop;");

        /* Allow other multicast if relay enabled (priority 82). */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 82,
                      "ip4.mcast || ip6.mcast",
                      od->mcast_info.rtr.relay ? "next;" : "drop;");

        /* Drop Ethernet local broadcast.  By definition this traffic should
         * not be forwarded.*/
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 50,
                      "eth.bcast", "drop;");

        /* TTL discard */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_IP_INPUT, 30,
                      "ip4 && ip.ttl == {0, 1}", "drop;");

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
    if (op->nbrp && (!op->derived)) {
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
        struct ds *match, struct ds *actions)
{
    if (op->nbrp && (!op->derived)) {
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
            if (op->od->l3dgw_port && op == op->od->l3dgw_port
                && op->od->l3redirect_port) {
                /* Traffic with eth.src = l3dgw_port->lrp_networks.ea_s
                 * should only be sent from the gateway chassi, so that
                 * upstream MAC learning points to the gateway chassis.
                 * Also need to avoid generation of multiple ND replies
                 * from different chassis. */
                ds_put_format(match, "is_chassis_resident(%s)",
                              op->od->l3redirect_port->json_key);
            }

            build_lrouter_nd_flow(op->od, op, "nd_na_router",
                                  op->lrp_networks.ipv6_addrs[i].addr_s,
                                  op->lrp_networks.ipv6_addrs[i].sn_addr_s,
                                  REG_INPORT_ETH_ADDR, match, false, 90,
                                  &op->nbrp->header_, lflows);
        }

        /* UDP/TCP/SCTP port unreachable */
        if (!smap_get(&op->od->nbr->options, "chassis")
            && !op->od->l3dgw_port) {
            for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
                ds_clear(match);
                ds_put_format(match,
                              "ip6 && ip6.dst == %s && !ip.later_frag && tcp",
                              op->lrp_networks.ipv6_addrs[i].addr_s);
                const char *action = "tcp_reset {"
                                     "eth.dst <-> eth.src; "
                                     "ip6.dst <-> ip6.src; "
                                     "next; };";
                ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                        80, ds_cstr(match), action,
                                        &op->nbrp->header_);

                ds_clear(match);
                ds_put_format(match,
                              "ip6 && ip6.dst == %s && !ip.later_frag && sctp",
                              op->lrp_networks.ipv6_addrs[i].addr_s);
                action = "sctp_abort {"
                         "eth.dst <-> eth.src; "
                         "ip6.dst <-> ip6.src; "
                         "next; };";
                ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                        80, ds_cstr(match), action,
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
                ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                        80, ds_cstr(match), action,
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
                ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                        70, ds_cstr(match), action,
                                        &op->nbrp->header_);
            }
        }

        /* ICMPv6 time exceeded */
        for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
            /* skip link-local address */
            if (in6_is_lla(&op->lrp_networks.ipv6_addrs[i].network)) {
                continue;
            }

            ds_clear(match);
            ds_clear(actions);

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
                          "ip6.dst = ip6.src; "
                          "ip6.src = %s; "
                          "ip.ttl = 255; "
                          "icmp6.type = 3; /* Time exceeded */ "
                          "icmp6.code = 0; /* TTL exceeded in transit */ "
                          "next; };",
                          op->lrp_networks.ipv6_addrs[i].addr_s);
            ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT, 40,
                                    ds_cstr(match), ds_cstr(actions),
                                    &op->nbrp->header_);
        }
    }

}

static void
build_lrouter_arp_nd_for_datapath(struct ovn_datapath *od,
                                  struct hmap *lflows)
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
            build_lrouter_nat_arp_nd_flow(od, nat_entry, lflows);
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
            build_lrouter_nat_arp_nd_flow(od, nat_entry, lflows);
        }
    }
}

/* Logical router ingress table 3: IP Input for IPv4. */
static void
build_lrouter_ipv4_ip_input(struct ovn_port *op,
                            struct hmap *lflows,
                            struct ds *match, struct ds *actions)
{
    /* No ingress packets are accepted on a chassisredirect
     * port, so no need to program flows for that port. */
    if (op->nbrp && (!op->derived)) {
        if (op->lrp_networks.n_ipv4_addrs) {
            /* L3 admission control: drop packets that originate from an
             * IPv4 address owned by the router or a broadcast address
             * known to the router (priority 100). */
            ds_clear(match);
            ds_put_cstr(match, "ip4.src == ");
            op_put_v4_networks(match, op, true);
            ds_put_cstr(match, " && "REGBIT_EGRESS_LOOPBACK" == 0");
            ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT, 100,
                                    ds_cstr(match), "drop;",
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
        build_lrouter_bfd_flows(lflows, op);

        /* ICMP time exceeded */
        for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            ds_clear(match);
            ds_clear(actions);

            ds_put_format(match,
                          "inport == %s && ip4 && "
                          "ip.ttl == {0, 1} && !ip.later_frag", op->json_key);
            ds_put_format(actions,
                          "icmp4 {"
                          "eth.dst <-> eth.src; "
                          "icmp4.type = 11; /* Time exceeded */ "
                          "icmp4.code = 0; /* TTL exceeded in transit */ "
                          "ip4.dst = ip4.src; "
                          "ip4.src = %s; "
                          "ip.ttl = 255; "
                          "next; };",
                          op->lrp_networks.ipv4_addrs[i].addr_s);
            ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT, 40,
                                    ds_cstr(match), ds_cstr(actions),
                                    &op->nbrp->header_);
        }

        /* ARP reply.  These flows reply to ARP requests for the router's own
         * IP address. */
        for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            ds_clear(match);
            ds_put_format(match, "arp.spa == %s/%u",
                          op->lrp_networks.ipv4_addrs[i].network_s,
                          op->lrp_networks.ipv4_addrs[i].plen);

            if (op->od->l3dgw_port && op->od->l3redirect_port && op->peer
                && op->peer->od->n_localnet_ports) {
                bool add_chassis_resident_check = false;
                if (op == op->od->l3dgw_port) {
                    /* Traffic with eth.src = l3dgw_port->lrp_networks.ea_s
                     * should only be sent from the gateway chassis, so that
                     * upstream MAC learning points to the gateway chassis.
                     * Also need to avoid generation of multiple ARP responses
                     * from different chassis. */
                    add_chassis_resident_check = true;
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
                        "reside-on-redirect-chassis", false);
                }

                if (add_chassis_resident_check) {
                    ds_put_format(match, " && is_chassis_resident(%s)",
                                  op->od->l3redirect_port->json_key);
                }
            }

            build_lrouter_arp_flow(op->od, op,
                                   op->lrp_networks.ipv4_addrs[i].addr_s,
                                   REG_INPORT_ETH_ADDR, match, false, 90,
                                   &op->nbrp->header_, lflows);
        }

        /* A set to hold all load-balancer vips that need ARP responses. */
        struct sset all_ips_v4 = SSET_INITIALIZER(&all_ips_v4);
        struct sset all_ips_v6 = SSET_INITIALIZER(&all_ips_v6);
        get_router_load_balancer_ips(op->od, &all_ips_v4, &all_ips_v6);

        const char *ip_address;
        SSET_FOR_EACH (ip_address, &all_ips_v4) {
            ds_clear(match);
            if (op == op->od->l3dgw_port) {
                ds_put_format(match, "is_chassis_resident(%s)",
                              op->od->l3redirect_port->json_key);
            }

            build_lrouter_arp_flow(op->od, op,
                                   ip_address, REG_INPORT_ETH_ADDR,
                                   match, false, 90, NULL, lflows);
        }

        SSET_FOR_EACH (ip_address, &all_ips_v6) {
            ds_clear(match);
            if (op == op->od->l3dgw_port) {
                ds_put_format(match, "is_chassis_resident(%s)",
                              op->od->l3redirect_port->json_key);
            }

            build_lrouter_nd_flow(op->od, op, "nd_na",
                                  ip_address, NULL, REG_INPORT_ETH_ADDR,
                                  match, false, 90, NULL, lflows);
        }

        sset_destroy(&all_ips_v4);
        sset_destroy(&all_ips_v6);

        if (!smap_get(&op->od->nbr->options, "chassis")
            && !op->od->l3dgw_port) {
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
                ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                        80, ds_cstr(match), action,
                                        &op->nbrp->header_);

                ds_clear(match);
                ds_put_format(match,
                              "ip4 && ip4.dst == %s && !ip.later_frag && tcp",
                              op->lrp_networks.ipv4_addrs[i].addr_s);
                action = "tcp_reset {"
                         "eth.dst <-> eth.src; "
                         "ip4.dst <-> ip4.src; "
                         "next; };";
                ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                        80, ds_cstr(match), action,
                                        &op->nbrp->header_);

                ds_clear(match);
                ds_put_format(match,
                              "ip4 && ip4.dst == %s && !ip.later_frag && sctp",
                              op->lrp_networks.ipv4_addrs[i].addr_s);
                action = "sctp_abort {"
                         "eth.dst <-> eth.src; "
                         "ip4.dst <-> ip4.src; "
                         "next; };";
                ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                        80, ds_cstr(match), action,
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
                ovn_lflow_add_with_hint(lflows, op->od, S_ROUTER_IN_IP_INPUT,
                                        70, ds_cstr(match), action,
                                        &op->nbrp->header_);
            }
        }

        /* Drop IP traffic destined to router owned IPs except if the IP is
         * also a SNAT IP. Those are dropped later, in stage
         * "lr_in_arp_resolve", if unSNAT was unsuccessful.
         *
         * Priority 60.
         */
        build_lrouter_drop_own_dest(op, S_ROUTER_IN_IP_INPUT, 60, false,
                                    lflows);

        /* ARP / ND handling for external IP addresses.
         *
         * DNAT and SNAT IP addresses are external IP addresses that need ARP
         * handling.
         *
         * These are already taken care globally, per router. The only
         * exception is on the l3dgw_port where we might need to use a
         * different ETH address.
         */
        if (op != op->od->l3dgw_port) {
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
            build_lrouter_port_nat_arp_nd_flow(op, nat_entry, lflows);
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
            build_lrouter_port_nat_arp_nd_flow(op, nat_entry, lflows);
        }
    }
}

/* NAT, Defrag and load balancing. */
static void
build_lrouter_nat_defrag_and_lb(struct ovn_datapath *od,
                                struct hmap *lflows,
                                struct shash *meter_groups,
                                struct hmap *lbs,
                                struct ds *match, struct ds *actions)
{
    if (od->nbr) {

        /* Packets are allowed by default. */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_DEFRAG, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_UNSNAT, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_ROUTER_OUT_SNAT, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_ROUTER_OUT_UNDNAT, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_ROUTER_OUT_EGR_LOOP, 0, "1", "next;");
        ovn_lflow_add(lflows, od, S_ROUTER_IN_ECMP_STATEFUL, 0, "1", "next;");

        /* Send the IPv6 NS packets to next table. When ovn-controller
         * generates IPv6 NS (for the action - nd_ns{}), the injected
         * packet would go through conntrack - which is not required. */
        ovn_lflow_add(lflows, od, S_ROUTER_OUT_SNAT, 120, "nd_ns", "next;");

        /* NAT rules are only valid on Gateway routers and routers with
         * l3dgw_port (router has a port with gateway chassis
         * specified). */
        if (!smap_get(&od->nbr->options, "chassis") && !od->l3dgw_port) {
            return;
        }

        struct sset nat_entries = SSET_INITIALIZER(&nat_entries);

        bool dnat_force_snat_ip =
            !lport_addresses_is_empty(&od->dnat_force_snat_addrs);
        bool lb_force_snat_ip =
            !lport_addresses_is_empty(&od->lb_force_snat_addrs);

        for (int i = 0; i < od->nbr->n_nat; i++) {
            const struct nbrec_nat *nat;

            nat = od->nbr->nat[i];

            ovs_be32 ip, mask;
            struct in6_addr ipv6, mask_v6, v6_exact = IN6ADDR_EXACT_INIT;
            bool is_v6 = false;
            bool stateless = lrouter_nat_is_stateless(nat);
            struct nbrec_address_set *allowed_ext_ips =
                                      nat->allowed_ext_ips;
            struct nbrec_address_set *exempted_ext_ips =
                                      nat->exempted_ext_ips;

            if (allowed_ext_ips && exempted_ext_ips) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "NAT rule: "UUID_FMT" not applied, since "
                             "both allowed and exempt external ips set",
                             UUID_ARGS(&(nat->header_.uuid)));
                continue;
            }

            char *error = ip_parse_masked(nat->external_ip, &ip, &mask);
            if (error || mask != OVS_BE32_MAX) {
                free(error);
                error = ipv6_parse_masked(nat->external_ip, &ipv6, &mask_v6);
                if (error || memcmp(&mask_v6, &v6_exact, sizeof(mask_v6))) {
                    /* Invalid for both IPv4 and IPv6 */
                    static struct vlog_rate_limit rl =
                        VLOG_RATE_LIMIT_INIT(5, 1);
                    VLOG_WARN_RL(&rl, "bad external ip %s for nat",
                                 nat->external_ip);
                    free(error);
                    continue;
                }
                /* It was an invalid IPv4 address, but valid IPv6.
                 * Treat the rest of the handling of this NAT rule
                 * as IPv6. */
                is_v6 = true;
            }

            /* Check the validity of nat->logical_ip. 'logical_ip' can
             * be a subnet when the type is "snat". */
            int cidr_bits;
            if (is_v6) {
                error = ipv6_parse_masked(nat->logical_ip, &ipv6, &mask_v6);
                cidr_bits = ipv6_count_cidr_bits(&mask_v6);
            } else {
                error = ip_parse_masked(nat->logical_ip, &ip, &mask);
                cidr_bits = ip_count_cidr_bits(mask);
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
                    continue;
                }
            } else {
                if (error || (!is_v6 && mask != OVS_BE32_MAX)
                    || (is_v6 && memcmp(&mask_v6, &v6_exact,
                                        sizeof mask_v6))) {
                    /* Invalid for both IPv4 and IPv6 */
                    static struct vlog_rate_limit rl =
                        VLOG_RATE_LIMIT_INIT(5, 1);
                    VLOG_WARN_RL(&rl, "bad ip %s for dnat in router "
                        ""UUID_FMT"", nat->logical_ip, UUID_ARGS(&od->key));
                    free(error);
                    continue;
                }
            }

            /* For distributed router NAT, determine whether this NAT rule
             * satisfies the conditions for distributed NAT processing. */
            bool distributed = false;
            struct eth_addr mac;
            if (od->l3dgw_port && !strcmp(nat->type, "dnat_and_snat") &&
                nat->logical_port && nat->external_mac) {
                if (eth_addr_from_string(nat->external_mac, &mac)) {
                    distributed = true;
                } else {
                    static struct vlog_rate_limit rl =
                        VLOG_RATE_LIMIT_INIT(5, 1);
                    VLOG_WARN_RL(&rl, "bad mac %s for dnat in router "
                        ""UUID_FMT"", nat->external_mac, UUID_ARGS(&od->key));
                    continue;
                }
            }

            /* Ingress UNSNAT table: It is for already established connections'
             * reverse traffic. i.e., SNAT has already been done in egress
             * pipeline and now the packet has entered the ingress pipeline as
             * part of a reply. We undo the SNAT here.
             *
             * Undoing SNAT has to happen before DNAT processing.  This is
             * because when the packet was DNATed in ingress pipeline, it did
             * not know about the possibility of eventual additional SNAT in
             * egress pipeline. */
            if (!strcmp(nat->type, "snat")
                || !strcmp(nat->type, "dnat_and_snat")) {
                if (!od->l3dgw_port) {
                    /* Gateway router. */
                    ds_clear(match);
                    ds_clear(actions);
                    ds_put_format(match, "ip && ip%s.dst == %s",
                                  is_v6 ? "6" : "4",
                                  nat->external_ip);
                    if (!strcmp(nat->type, "dnat_and_snat") && stateless) {
                       ds_put_format(actions, "ip%s.dst=%s; next;",
                                     is_v6 ? "6" : "4", nat->logical_ip);
                    } else {
                       ds_put_cstr(actions, "ct_snat;");
                    }

                    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_UNSNAT,
                                            90, ds_cstr(match),
                                            ds_cstr(actions),
                                            &nat->header_);
                } else {
                    /* Distributed router. */

                    /* Traffic received on l3dgw_port is subject to NAT. */
                    ds_clear(match);
                    ds_clear(actions);
                    ds_put_format(match, "ip && ip%s.dst == %s"
                                          " && inport == %s",
                                  is_v6 ? "6" : "4",
                                  nat->external_ip,
                                  od->l3dgw_port->json_key);
                    if (!distributed && od->l3redirect_port) {
                        /* Flows for NAT rules that are centralized are only
                         * programmed on the gateway chassis. */
                        ds_put_format(match, " && is_chassis_resident(%s)",
                                      od->l3redirect_port->json_key);
                    }

                    if (!strcmp(nat->type, "dnat_and_snat") && stateless) {
                        ds_put_format(actions, "ip%s.dst=%s; next;",
                                      is_v6 ? "6" : "4", nat->logical_ip);
                    } else {
                        ds_put_cstr(actions, "ct_snat;");
                    }

                    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_UNSNAT,
                                            100,
                                            ds_cstr(match), ds_cstr(actions),
                                            &nat->header_);
                }
            }

            /* Ingress DNAT table: Packets enter the pipeline with destination
             * IP address that needs to be DNATted from a external IP address
             * to a logical IP address. */
            if (!strcmp(nat->type, "dnat")
                || !strcmp(nat->type, "dnat_and_snat")) {
                if (!od->l3dgw_port) {
                    /* Gateway router. */
                    /* Packet when it goes from the initiator to destination.
                     * We need to set flags.loopback because the router can
                     * send the packet back through the same interface. */
                    ds_clear(match);
                    ds_put_format(match, "ip && ip%s.dst == %s",
                                  is_v6 ? "6" : "4",
                                  nat->external_ip);
                    ds_clear(actions);
                    if (allowed_ext_ips || exempted_ext_ips) {
                        lrouter_nat_add_ext_ip_match(od, lflows, match, nat,
                                                     is_v6, true, mask);
                    }

                    if (dnat_force_snat_ip) {
                        /* Indicate to the future tables that a DNAT has taken
                         * place and a force SNAT needs to be done in the
                         * Egress SNAT table. */
                        ds_put_format(actions,
                                      "flags.force_snat_for_dnat = 1; ");
                    }

                    if (!strcmp(nat->type, "dnat_and_snat") && stateless) {
                        ds_put_format(actions, "flags.loopback = 1; "
                                      "ip%s.dst=%s; next;",
                                      is_v6 ? "6" : "4", nat->logical_ip);
                    } else {
                        ds_put_format(actions, "flags.loopback = 1; "
                                      "ct_dnat(%s", nat->logical_ip);

                        if (nat->external_port_range[0]) {
                            ds_put_format(actions, ",%s",
                                          nat->external_port_range);
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
                    ds_put_format(match, "ip && ip%s.dst == %s"
                                          " && inport == %s",
                                  is_v6 ? "6" : "4",
                                  nat->external_ip,
                                  od->l3dgw_port->json_key);
                    if (!distributed && od->l3redirect_port) {
                        /* Flows for NAT rules that are centralized are only
                         * programmed on the gateway chassis. */
                        ds_put_format(match, " && is_chassis_resident(%s)",
                                      od->l3redirect_port->json_key);
                    }
                    ds_clear(actions);
                    if (allowed_ext_ips || exempted_ext_ips) {
                        lrouter_nat_add_ext_ip_match(od, lflows, match, nat,
                                                     is_v6, true, mask);
                    }

                    if (!strcmp(nat->type, "dnat_and_snat") && stateless) {
                        ds_put_format(actions, "ip%s.dst=%s; next;",
                                      is_v6 ? "6" : "4", nat->logical_ip);
                    } else {
                        ds_put_format(actions, "ct_dnat(%s", nat->logical_ip);
                        if (nat->external_port_range[0]) {
                            ds_put_format(actions, ",%s",
                                          nat->external_port_range);
                        }
                        ds_put_format(actions, ");");
                    }

                    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DNAT, 100,
                                            ds_cstr(match), ds_cstr(actions),
                                            &nat->header_);
                }
            }

            /* ARP resolve for NAT IPs. */
            if (od->l3dgw_port) {
                if (!strcmp(nat->type, "snat")) {
                    ds_clear(match);
                    ds_put_format(
                        match, "inport == %s && %s == %s",
                        od->l3dgw_port->json_key,
                        is_v6 ? "ip6.src" : "ip4.src", nat->external_ip);
                    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_IP_INPUT,
                                            120, ds_cstr(match), "next;",
                                            &nat->header_);
                }

                if (!sset_contains(&nat_entries, nat->external_ip)) {
                    ds_clear(match);
                    ds_put_format(
                        match, "outport == %s && %s == %s",
                        od->l3dgw_port->json_key,
                        is_v6 ? REG_NEXT_HOP_IPV6 : REG_NEXT_HOP_IPV4,
                        nat->external_ip);
                    ds_clear(actions);
                    ds_put_format(
                        actions, "eth.dst = %s; next;",
                        distributed ? nat->external_mac :
                        od->l3dgw_port->lrp_networks.ea_s);
                    ovn_lflow_add_with_hint(lflows, od,
                                            S_ROUTER_IN_ARP_RESOLVE,
                                            100, ds_cstr(match),
                                            ds_cstr(actions),
                                            &nat->header_);
                    sset_add(&nat_entries, nat->external_ip);
                }
            } else {
                /* Add the NAT external_ip to the nat_entries even for
                 * gateway routers. This is required for adding load balancer
                 * flows.*/
                sset_add(&nat_entries, nat->external_ip);
            }

            /* Egress UNDNAT table: It is for already established connections'
             * reverse traffic. i.e., DNAT has already been done in ingress
             * pipeline and now the packet has entered the egress pipeline as
             * part of a reply. We undo the DNAT here.
             *
             * Note that this only applies for NAT on a distributed router.
             * Undo DNAT on a gateway router is done in the ingress DNAT
             * pipeline stage. */
            if (od->l3dgw_port && (!strcmp(nat->type, "dnat")
                || !strcmp(nat->type, "dnat_and_snat"))) {
                ds_clear(match);
                ds_put_format(match, "ip && ip%s.src == %s"
                                      " && outport == %s",
                              is_v6 ? "6" : "4",
                              nat->logical_ip,
                              od->l3dgw_port->json_key);
                if (!distributed && od->l3redirect_port) {
                    /* Flows for NAT rules that are centralized are only
                     * programmed on the gateway chassis. */
                    ds_put_format(match, " && is_chassis_resident(%s)",
                                  od->l3redirect_port->json_key);
                }
                ds_clear(actions);
                if (distributed) {
                    ds_put_format(actions, "eth.src = "ETH_ADDR_FMT"; ",
                                  ETH_ADDR_ARGS(mac));
                }

                if (!strcmp(nat->type, "dnat_and_snat") && stateless) {
                    ds_put_format(actions, "ip%s.src=%s; next;",
                                  is_v6 ? "6" : "4", nat->external_ip);
                } else {
                    ds_put_format(actions, "ct_dnat;");
                }

                ovn_lflow_add_with_hint(lflows, od, S_ROUTER_OUT_UNDNAT, 100,
                                        ds_cstr(match), ds_cstr(actions),
                                        &nat->header_);
            }

            /* Egress SNAT table: Packets enter the egress pipeline with
             * source ip address that needs to be SNATted to a external ip
             * address. */
            if (!strcmp(nat->type, "snat")
                || !strcmp(nat->type, "dnat_and_snat")) {
                if (!od->l3dgw_port) {
                    /* Gateway router. */
                    ds_clear(match);
                    ds_put_format(match, "ip && ip%s.src == %s",
                                  is_v6 ? "6" : "4",
                                  nat->logical_ip);
                    ds_clear(actions);

                    if (allowed_ext_ips || exempted_ext_ips) {
                        lrouter_nat_add_ext_ip_match(od, lflows, match, nat,
                                                     is_v6, false, mask);
                    }

                    if (!strcmp(nat->type, "dnat_and_snat") && stateless) {
                        ds_put_format(actions, "ip%s.src=%s; next;",
                                      is_v6 ? "6" : "4", nat->external_ip);
                    } else {
                        ds_put_format(actions, "ct_snat(%s",
                                      nat->external_ip);

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
                                            cidr_bits + 1,
                                            ds_cstr(match), ds_cstr(actions),
                                            &nat->header_);
                } else {
                    uint16_t priority = cidr_bits + 1;

                    /* Distributed router. */
                    ds_clear(match);
                    ds_put_format(match, "ip && ip%s.src == %s"
                                          " && outport == %s",
                                  is_v6 ? "6" : "4",
                                  nat->logical_ip,
                                  od->l3dgw_port->json_key);
                    if (!distributed && od->l3redirect_port) {
                        /* Flows for NAT rules that are centralized are only
                         * programmed on the gateway chassis. */
                        priority += 128;
                        ds_put_format(match, " && is_chassis_resident(%s)",
                                      od->l3redirect_port->json_key);
                    }
                    ds_clear(actions);

                    if (allowed_ext_ips || exempted_ext_ips) {
                        lrouter_nat_add_ext_ip_match(od, lflows, match, nat,
                                                     is_v6, false, mask);
                    }

                    if (distributed) {
                        ds_put_format(actions, "eth.src = "ETH_ADDR_FMT"; ",
                                      ETH_ADDR_ARGS(mac));
                    }

                    if (!strcmp(nat->type, "dnat_and_snat") && stateless) {
                        ds_put_format(actions, "ip%s.src=%s; next;",
                                      is_v6 ? "6" : "4", nat->external_ip);
                    } else {
                        ds_put_format(actions, "ct_snat(%s",
                                      nat->external_ip);
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
                                            priority, ds_cstr(match),
                                            ds_cstr(actions),
                                            &nat->header_);
                }
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
                ds_clear(actions);
                ds_put_format(actions, REG_INPORT_ETH_ADDR " = %s; next;",
                              od->l3dgw_port->lrp_networks.ea_s);

                ds_clear(match);
                ds_put_format(match,
                              "eth.dst == "ETH_ADDR_FMT" && inport == %s"
                              " && is_chassis_resident(\"%s\")",
                              ETH_ADDR_ARGS(mac),
                              od->l3dgw_port->json_key,
                              nat->logical_port);
                ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_ADMISSION, 50,
                                        ds_cstr(match), ds_cstr(actions),
                                        &nat->header_);
            }

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
                              "ip%s.src == %s && outport == %s && "
                              "is_chassis_resident(\"%s\")",
                              is_v6 ? "6" : "4", nat->logical_ip,
                              od->l3dgw_port->json_key, nat->logical_port);
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
            if (od->l3dgw_port) {
                /* Distributed router. */
                ds_clear(match);
                ds_put_format(match, "ip%s.dst == %s && outport == %s",
                              is_v6 ? "6" : "4",
                              nat->external_ip,
                              od->l3dgw_port->json_key);
                if (!distributed) {
                    ds_put_format(match, " && is_chassis_resident(%s)",
                                  od->l3redirect_port->json_key);
                } else {
                    ds_put_format(match, " && is_chassis_resident(\"%s\")",
                                  nat->logical_port);
                }

                ds_clear(actions);
                ds_put_format(actions,
                              "clone { ct_clear; "
                              "inport = outport; outport = \"\"; "
                              "flags = 0; flags.loopback = 1; ");
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

        /* Handle force SNAT options set in the gateway router. */
        if (!od->l3dgw_port) {
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

            /* For gateway router, re-circulate every packet through
            * the DNAT zone.  This helps with the following.
            *
            * Any packet that needs to be unDNATed in the reverse
            * direction gets unDNATed. Ideally this could be done in
            * the egress pipeline. But since the gateway router
            * does not have any feature that depends on the source
            * ip address being external IP address for IP routing,
            * we can do it here, saving a future re-circulation. */
            ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT, 50,
                          "ip", "flags.loopback = 1; ct_dnat;");
        }

        /* Load balancing and packet defrag are only valid on
         * Gateway routers or router with gateway port. */
        if (!smap_get(&od->nbr->options, "chassis") && !od->l3dgw_port) {
            sset_destroy(&nat_entries);
            return;
        }

        /* A set to hold all ips that need defragmentation and tracking. */
        struct sset all_ips = SSET_INITIALIZER(&all_ips);

        for (int i = 0; i < od->nbr->n_load_balancer; i++) {
            struct nbrec_load_balancer *nb_lb = od->nbr->load_balancer[i];
            struct ovn_northd_lb *lb =
                ovn_northd_lb_find(lbs, &nb_lb->header_.uuid);
            ovs_assert(lb);

            for (size_t j = 0; j < lb->n_vips; j++) {
                struct ovn_lb_vip *lb_vip = &lb->vips[j];
                struct ovn_northd_lb_vip *lb_vip_nb = &lb->vips_nb[j];
                ds_clear(actions);
                build_lb_vip_actions(lb_vip, lb_vip_nb, actions,
                                     lb->selection_fields, false);

                if (!sset_contains(&all_ips, lb_vip->vip_str)) {
                    sset_add(&all_ips, lb_vip->vip_str);
                    /* If there are any load balancing rules, we should send
                     * the packet to conntrack for defragmentation and
                     * tracking.  This helps with two things.
                     *
                     * 1. With tracking, we can send only new connections to
                     *    pick a DNAT ip address from a group.
                     * 2. If there are L4 ports in load balancing rules, we
                     *    need the defragmentation to match on L4 ports. */
                    ds_clear(match);
                    if (IN6_IS_ADDR_V4MAPPED(&lb_vip->vip)) {
                        ds_put_format(match, "ip && ip4.dst == %s",
                                      lb_vip->vip_str);
                    } else {
                        ds_put_format(match, "ip && ip6.dst == %s",
                                      lb_vip->vip_str);
                    }
                    ovn_lflow_add_with_hint(lflows, od, S_ROUTER_IN_DEFRAG,
                                            100, ds_cstr(match), "ct_next;",
                                            &nb_lb->header_);
                }

                /* Higher priority rules are added for load-balancing in DNAT
                 * table.  For every match (on a VIP[:port]), we add two flows
                 * via add_router_lb_flow().  One flow is for specific matching
                 * on ct.new with an action of "ct_lb($targets);".  The other
                 * flow is for ct.est with an action of "ct_dnat;". */
                ds_clear(match);
                if (IN6_IS_ADDR_V4MAPPED(&lb_vip->vip)) {
                    ds_put_format(match, "ip && ip4.dst == %s",
                                  lb_vip->vip_str);
                } else {
                    ds_put_format(match, "ip && ip6.dst == %s",
                                  lb_vip->vip_str);
                }

                int prio = 110;
                bool is_udp = nullable_string_is_equal(nb_lb->protocol, "udp");
                bool is_sctp = nullable_string_is_equal(nb_lb->protocol,
                                                        "sctp");
                const char *proto = is_udp ? "udp" : is_sctp ? "sctp" : "tcp";

                if (lb_vip->vip_port) {
                    ds_put_format(match, " && %s && %s.dst == %d", proto,
                                  proto, lb_vip->vip_port);
                    prio = 120;
                }

                if (od->l3redirect_port &&
                    (lb_vip->n_backends || !lb_vip->empty_backend_rej)) {
                    ds_put_format(match, " && is_chassis_resident(%s)",
                                  od->l3redirect_port->json_key);
                }
                add_router_lb_flow(lflows, od, match, actions, prio,
                                   lb_force_snat_ip, lb_vip, proto,
                                   nb_lb, meter_groups, &nat_entries);
            }
        }
        sset_destroy(&all_ips);
        sset_destroy(&nat_entries);
    }
}



struct lswitch_flow_build_info {
    struct hmap *datapaths;
    struct hmap *ports;
    struct hmap *port_groups;
    struct hmap *lflows;
    struct hmap *mcgroups;
    struct hmap *igmp_groups;
    struct shash *meter_groups;
    struct hmap *lbs;
    struct hmap *bfd_connections;
    char *svc_check_match;
    struct ds match;
    struct ds actions;
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
    build_lswitch_lflows_pre_acl_and_acl(od, lsi->port_groups, lsi->lflows,
                                         lsi->meter_groups, lsi->lbs);

    build_fwd_group_lflows(od, lsi->lflows);
    build_lswitch_lflows_admission_control(od, lsi->lflows);
    build_lswitch_input_port_sec_od(od, lsi->lflows);
    build_lswitch_arp_nd_responder_default(od, lsi->lflows);
    build_lswitch_dns_lookup_and_response(od, lsi->lflows);
    build_lswitch_dhcp_and_dns_defaults(od, lsi->lflows);
    build_lswitch_destination_lookup_bmcast(od, lsi->lflows, &lsi->actions);
    build_lswitch_output_port_sec_od(od, lsi->lflows);

    /* Build Logical Router Flows. */
    build_adm_ctrl_flows_for_lrouter(od, lsi->lflows);
    build_neigh_learning_flows_for_lrouter(od, lsi->lflows, &lsi->match,
                                           &lsi->actions);
    build_ND_RA_flows_for_lrouter(od, lsi->lflows);
    build_static_route_flows_for_lrouter(od, lsi->lflows, lsi->ports,
                                         lsi->bfd_connections);
    build_mcast_lookup_flows_for_lrouter(od, lsi->lflows, &lsi->match,
                                         &lsi->actions);
    build_ingress_policy_flows_for_lrouter(od, lsi->lflows, lsi->ports);
    build_arp_resolve_flows_for_lrouter(od, lsi->lflows);
    build_check_pkt_len_flows_for_lrouter(od, lsi->lflows, lsi->ports,
                                          &lsi->match, &lsi->actions);
    build_gateway_redirect_flows_for_lrouter(od, lsi->lflows, &lsi->match,
                                             &lsi->actions);
    build_arp_request_flows_for_lrouter(od, lsi->lflows, &lsi->match,
                                        &lsi->actions);
    build_misc_local_traffic_drop_flows_for_lrouter(od, lsi->lflows);
    build_lrouter_arp_nd_for_datapath(od, lsi->lflows);
    build_lrouter_nat_defrag_and_lb(od, lsi->lflows, lsi->meter_groups,
                                    lsi->lbs, &lsi->match, &lsi->actions);
}

/* Helper function to combine all lflow generation which is iterated by port.
 */

static void
build_lswitch_and_lrouter_iterate_by_op(struct ovn_port *op,
                                        struct lswitch_flow_build_info *lsi)
{
    /* Build Logical Switch Flows. */
    build_lswitch_input_port_sec_op(op, lsi->lflows, &lsi->actions,
                                    &lsi->match);
    build_lswitch_arp_nd_responder_skip_local(op, lsi->lflows,
                                              &lsi->match);
    build_lswitch_arp_nd_responder_known_ips(op, lsi->lflows,
                                             lsi->ports,
                                             &lsi->actions,
                                             &lsi->match);
    build_lswitch_dhcp_options_and_response(op,lsi->lflows);
    build_lswitch_external_port(op, lsi->lflows);
    build_lswitch_ip_unicast_lookup(op, lsi->lflows, lsi->mcgroups,
                                    &lsi->actions, &lsi->match);
    build_lswitch_output_port_sec_op(op, lsi->lflows,
                                     &lsi->actions, &lsi->match);

    /* Build Logical Router Flows. */
    build_adm_ctrl_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                          &lsi->actions);
    build_neigh_learning_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                                &lsi->actions);
    build_ip_routing_flows_for_lrouter_port(op, lsi->lflows);
    build_ND_RA_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                       &lsi->actions);
    build_arp_resolve_flows_for_lrouter_port(op, lsi->lflows, lsi->ports,
                                             &lsi->match, &lsi->actions);
    build_egress_delivery_flows_for_lrouter_port(op, lsi->lflows, &lsi->match,
                                                 &lsi->actions);
    build_dhcpv6_reply_flows_for_lrouter_port(op, lsi->lflows, &lsi->match);
    build_ipv6_input_flows_for_lrouter_port(op, lsi->lflows,
                                            &lsi->match, &lsi->actions);
    build_lrouter_ipv4_ip_input(op, lsi->lflows,
                                &lsi->match, &lsi->actions);
}

static void
build_lswitch_and_lrouter_flows(struct hmap *datapaths, struct hmap *ports,
                                struct hmap *port_groups, struct hmap *lflows,
                                struct hmap *mcgroups,
                                struct hmap *igmp_groups,
                                struct shash *meter_groups, struct hmap *lbs,
                                struct hmap *bfd_connections)
{
    struct ovn_datapath *od;
    struct ovn_port *op;
    struct ovn_northd_lb *lb;
    struct ovn_igmp_group *igmp_group;

    char *svc_check_match = xasprintf("eth.dst == %s", svc_monitor_mac);

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
        .svc_check_match = svc_check_match,
        .match = DS_EMPTY_INITIALIZER,
        .actions = DS_EMPTY_INITIALIZER,
    };

    /* Combined build - all lflow generation from lswitch and lrouter
     * will move here and will be reogranized by iterator type.
     */
    HMAP_FOR_EACH (od, key_node, datapaths) {
        build_lswitch_and_lrouter_iterate_by_od(od, &lsi);
    }
    HMAP_FOR_EACH (op, key_node, ports) {
        build_lswitch_and_lrouter_iterate_by_op(op, &lsi);
    }
    HMAP_FOR_EACH (lb, hmap_node, lbs) {
        build_lswitch_arp_nd_service_monitor(lb, lsi.lflows,
                                             &lsi.actions,
                                             &lsi.match);
    }
    HMAP_FOR_EACH (igmp_group, hmap_node, igmp_groups) {
        build_lswitch_ip_mcast_igmp_mld(igmp_group,
                                        lsi.lflows,
                                        &lsi.actions,
                                        &lsi.match);
    }
    free(svc_check_match);

    ds_destroy(&lsi.match);
    ds_destroy(&lsi.actions);

    build_lswitch_flows(datapaths, lflows);
}

struct ovn_dp_group {
    struct hmapx map;
    struct sbrec_logical_dp_group *dp_group;
    struct hmap_node node;
};

static struct ovn_dp_group *
ovn_dp_group_find(const struct hmap *dp_groups,
                  const struct hmapx *od, uint32_t hash)
{
    struct ovn_dp_group *dpg;

    HMAP_FOR_EACH_WITH_HASH (dpg, node, hash, dp_groups) {
        if (hmapx_equals(&dpg->map, od)) {
            return dpg;
        }
    }
    return NULL;
}

static struct sbrec_logical_dp_group *
ovn_sb_insert_logical_dp_group(struct northd_context *ctx,
                                     const struct hmapx *od)
{
    struct sbrec_logical_dp_group *dp_group;
    const struct sbrec_datapath_binding **sb;
    const struct hmapx_node *node;
    int n = 0;

    sb = xmalloc(hmapx_count(od) * sizeof *sb);
    HMAPX_FOR_EACH (node, od) {
        sb[n++] = ((struct ovn_datapath *) node->data)->sb;
    }
    dp_group = sbrec_logical_dp_group_insert(ctx->ovnsb_txn);
    sbrec_logical_dp_group_set_datapaths(
        dp_group, (struct sbrec_datapath_binding **) sb, n);
    free(sb);

    return dp_group;
}

static void
ovn_sb_set_lflow_logical_dp_group(
    struct northd_context *ctx,
    struct hmap *dp_groups,
    const struct sbrec_logical_flow *sbflow,
    const struct hmapx *od_group)
{
    struct ovn_dp_group *dpg;

    if (!hmapx_count(od_group)) {
        sbrec_logical_flow_set_logical_dp_group(sbflow, NULL);
        return;
    }

    ovs_assert(hmapx_count(od_group) != 1);

    dpg = ovn_dp_group_find(dp_groups, od_group,
                            hash_int(hmapx_count(od_group), 0));
    ovs_assert(dpg != NULL);

    if (!dpg->dp_group) {
        dpg->dp_group = ovn_sb_insert_logical_dp_group(ctx, &dpg->map);
    }
    sbrec_logical_flow_set_logical_dp_group(sbflow, dpg->dp_group);
}

/* Updates the Logical_Flow and Multicast_Group tables in the OVN_SB database,
 * constructing their contents based on the OVN_NB database. */
static void
build_lflows(struct northd_context *ctx, struct hmap *datapaths,
             struct hmap *ports, struct hmap *port_groups,
             struct hmap *mcgroups, struct hmap *igmp_groups,
             struct shash *meter_groups,
             struct hmap *lbs, struct hmap *bfd_connections)
{
    struct hmap lflows = HMAP_INITIALIZER(&lflows);

    build_lswitch_and_lrouter_flows(datapaths, ports,
                                    port_groups, &lflows, mcgroups,
                                    igmp_groups, meter_groups, lbs,
                                    bfd_connections);

    /* Collecting all unique datapath groups. */
    struct hmap dp_groups = HMAP_INITIALIZER(&dp_groups);
    struct hmapx single_dp_lflows = HMAPX_INITIALIZER(&single_dp_lflows);
    struct ovn_lflow *lflow;
    HMAP_FOR_EACH (lflow, hmap_node, &lflows) {
        uint32_t hash = hash_int(hmapx_count(&lflow->od_group), 0);
        struct ovn_dp_group *dpg;

        ovs_assert(hmapx_count(&lflow->od_group));

        if (hmapx_count(&lflow->od_group) == 1) {
            /* There is only one datapath, so it should be moved out of the
             * group to a single 'od'. */
            const struct hmapx_node *node;
            HMAPX_FOR_EACH (node, &lflow->od_group) {
                lflow->od = node->data;
                break;
            }
            hmapx_clear(&lflow->od_group);
            /* Logical flow should be re-hashed later to allow lookups. */
            hmapx_add(&single_dp_lflows, lflow);
            continue;
        }

        dpg = ovn_dp_group_find(&dp_groups, &lflow->od_group, hash);
        if (!dpg) {
            dpg = xzalloc(sizeof *dpg);
            hmapx_clone(&dpg->map, &lflow->od_group);
            hmap_insert(&dp_groups, &dpg->node, hash);
        }
    }

    /* Adding datapath to the flow hash for logical flows that have only one,
     * so they could be found by the southbound db record. */
    const struct hmapx_node *node;
    uint32_t hash;
    HMAPX_FOR_EACH (node, &single_dp_lflows) {
        lflow = node->data;
        hash = hmap_node_hash(&lflow->hmap_node);
        hmap_remove(&lflows, &lflow->hmap_node);
        hash = ovn_logical_flow_hash_datapath(&lflow->od->sb->header_.uuid,
                                              hash);
        hmap_insert(&lflows, &lflow->hmap_node, hash);
    }
    hmapx_destroy(&single_dp_lflows);

    /* Push changes to the Logical_Flow table to database. */
    const struct sbrec_logical_flow *sbflow, *next_sbflow;
    SBREC_LOGICAL_FLOW_FOR_EACH_SAFE (sbflow, next_sbflow, ctx->ovnsb_idl) {
        struct sbrec_logical_dp_group *dp_group = sbflow->logical_dp_group;
        struct ovn_datapath **od, *logical_datapath_od = NULL;
        int n_datapaths = 0;
        size_t i;

        od = xmalloc((dp_group ? dp_group->n_datapaths + 1 : 1) * sizeof *od);
        /* Check all logical datapaths from the group. */
        for (i = 0; dp_group && i < dp_group->n_datapaths; i++) {
            od[n_datapaths] = ovn_datapath_from_sbrec(datapaths,
                                                      dp_group->datapaths[i]);
            if (!od[n_datapaths] || ovn_datapath_is_stale(od[n_datapaths])) {
                continue;
            }
            n_datapaths++;
        }

        struct sbrec_datapath_binding *dp = sbflow->logical_datapath;
        if (dp) {
            logical_datapath_od = ovn_datapath_from_sbrec(datapaths, dp);
            if (logical_datapath_od
                && ovn_datapath_is_stale(logical_datapath_od)) {
                logical_datapath_od = NULL;
            }
        }

        if (!n_datapaths && !logical_datapath_od) {
            /* This lflow has no valid logical datapaths. */
            sbrec_logical_flow_delete(sbflow);
            free(od);
            continue;
        }

        enum ovn_pipeline pipeline
            = !strcmp(sbflow->pipeline, "ingress") ? P_IN : P_OUT;
        enum ovn_datapath_type dp_type;

        if (n_datapaths) {
            dp_type = od[0]->nbs ? DP_SWITCH : DP_ROUTER;
        } else {
            dp_type = logical_datapath_od->nbs ? DP_SWITCH : DP_ROUTER;
        }
        lflow = ovn_lflow_find(
            &lflows, logical_datapath_od,
            ovn_stage_build(dp_type, pipeline, sbflow->table_id),
            sbflow->priority, sbflow->match, sbflow->actions, sbflow->hash);
        if (lflow) {
            /* This is a valid lflow.  Checking if the datapath group needs
             * updates. */
            bool update_dp_group = false;

            if (n_datapaths != hmapx_count(&lflow->od_group)) {
                update_dp_group = true;
            } else {
                for (i = 0; i < n_datapaths; i++) {
                    if (od[i] && !hmapx_contains(&lflow->od_group, od[i])) {
                        update_dp_group = true;
                        break;
                    }
                }
            }

            if (update_dp_group) {
                ovn_sb_set_lflow_logical_dp_group(ctx, &dp_groups,
                                                  sbflow, &lflow->od_group);
            }
            /* This lflow updated.  Not needed anymore. */
            ovn_lflow_destroy(&lflows, lflow);
        } else {
            sbrec_logical_flow_delete(sbflow);
        }
        free(od);
    }

    struct ovn_lflow *next_lflow;
    HMAP_FOR_EACH_SAFE (lflow, next_lflow, hmap_node, &lflows) {
        const char *pipeline = ovn_stage_get_pipeline_name(lflow->stage);
        uint8_t table = ovn_stage_get_table(lflow->stage);

        sbflow = sbrec_logical_flow_insert(ctx->ovnsb_txn);
        if (lflow->od) {
            sbrec_logical_flow_set_logical_datapath(sbflow, lflow->od->sb);
        }
        ovn_sb_set_lflow_logical_dp_group(ctx, &dp_groups,
                                          sbflow, &lflow->od_group);
        sbrec_logical_flow_set_pipeline(sbflow, pipeline);
        sbrec_logical_flow_set_table_id(sbflow, table);
        sbrec_logical_flow_set_priority(sbflow, lflow->priority);
        sbrec_logical_flow_set_match(sbflow, lflow->match);
        sbrec_logical_flow_set_actions(sbflow, lflow->actions);

        /* Trim the source locator lflow->where, which looks something like
         * "ovn/northd/ovn-northd.c:1234", down to just the part following the
         * last slash, e.g. "ovn-northd.c:1234". */
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

    struct ovn_dp_group *dpg;
    HMAP_FOR_EACH_POP (dpg, node, &dp_groups) {
        hmapx_destroy(&dpg->map);
        free(dpg);
    }
    hmap_destroy(&dp_groups);

    /* Push changes to the Multicast_Group table to database. */
    const struct sbrec_multicast_group *sbmc, *next_sbmc;
    SBREC_MULTICAST_GROUP_FOR_EACH_SAFE (sbmc, next_sbmc, ctx->ovnsb_idl) {
        struct ovn_datapath *od = ovn_datapath_from_sbrec(datapaths,
                                                          sbmc->datapath);

        if (!od || ovn_datapath_is_stale(od)) {
            sbrec_multicast_group_delete(sbmc);
            continue;
        }

        struct multicast_group group = { .name = sbmc->name,
                                         .key = sbmc->tunnel_key };
        struct ovn_multicast *mc = ovn_multicast_find(mcgroups, od, &group);
        if (mc) {
            ovn_multicast_update_sbrec(mc, sbmc);
            ovn_multicast_destroy(mcgroups, mc);
        } else {
            sbrec_multicast_group_delete(sbmc);
        }
    }
    struct ovn_multicast *mc, *next_mc;
    HMAP_FOR_EACH_SAFE (mc, next_mc, hmap_node, mcgroups) {
        if (!mc->datapath) {
            ovn_multicast_destroy(mcgroups, mc);
            continue;
        }
        sbmc = sbrec_multicast_group_insert(ctx->ovnsb_txn);
        sbrec_multicast_group_set_datapath(sbmc, mc->datapath->sb);
        sbrec_multicast_group_set_name(sbmc, mc->group->name);
        sbrec_multicast_group_set_tunnel_key(sbmc, mc->group->key);
        ovn_multicast_update_sbrec(mc, sbmc);
        ovn_multicast_destroy(mcgroups, mc);
    }
}

static void
sync_address_set(struct northd_context *ctx, const char *name,
                 const char **addrs, size_t n_addrs,
                 struct shash *sb_address_sets)
{
    const struct sbrec_address_set *sb_address_set;
    sb_address_set = shash_find_and_delete(sb_address_sets,
                                           name);
    if (!sb_address_set) {
        sb_address_set = sbrec_address_set_insert(ctx->ovnsb_txn);
        sbrec_address_set_set_name(sb_address_set, name);
    }

    sbrec_address_set_set_addresses(sb_address_set,
                                    addrs, n_addrs);
}

/* OVN_Southbound Address_Set table contains same records as in north
 * bound, plus the records generated from Port_Group table in north bound.
 *
 * There are 2 records generated from each port group, one for IPv4, and
 * one for IPv6, named in the format: <port group name>_ip4 and
 * <port group name>_ip6 respectively. MAC addresses are ignored.
 *
 * We always update OVN_Southbound to match the Address_Set and Port_Group
 * in OVN_Northbound, so that the address sets used in Logical_Flows in
 * OVN_Southbound is checked against the proper set.*/
static void
sync_address_sets(struct northd_context *ctx)
{
    struct shash sb_address_sets = SHASH_INITIALIZER(&sb_address_sets);

    const struct sbrec_address_set *sb_address_set;
    SBREC_ADDRESS_SET_FOR_EACH (sb_address_set, ctx->ovnsb_idl) {
        shash_add(&sb_address_sets, sb_address_set->name, sb_address_set);
    }

    /* Service monitor MAC. */
    const char *svc_monitor_macp = svc_monitor_mac;
    sync_address_set(ctx, "svc_monitor_mac", &svc_monitor_macp, 1,
                     &sb_address_sets);

    /* sync port group generated address sets first */
    const struct nbrec_port_group *nb_port_group;
    NBREC_PORT_GROUP_FOR_EACH (nb_port_group, ctx->ovnnb_idl) {
        struct svec ipv4_addrs = SVEC_EMPTY_INITIALIZER;
        struct svec ipv6_addrs = SVEC_EMPTY_INITIALIZER;
        for (size_t i = 0; i < nb_port_group->n_ports; i++) {
            for (size_t j = 0; j < nb_port_group->ports[i]->n_addresses; j++) {
                const char *addrs = nb_port_group->ports[i]->addresses[j];
                if (!is_dynamic_lsp_address(addrs)) {
                    split_addresses(addrs, &ipv4_addrs, &ipv6_addrs);
                }
            }
            if (nb_port_group->ports[i]->dynamic_addresses) {
                split_addresses(nb_port_group->ports[i]->dynamic_addresses,
                                &ipv4_addrs, &ipv6_addrs);
            }
        }
        char *ipv4_addrs_name = xasprintf("%s_ip4", nb_port_group->name);
        char *ipv6_addrs_name = xasprintf("%s_ip6", nb_port_group->name);
        sync_address_set(ctx, ipv4_addrs_name,
                         /* "char **" is not compatible with "const char **" */
                         (const char **)ipv4_addrs.names,
                         ipv4_addrs.n, &sb_address_sets);
        sync_address_set(ctx, ipv6_addrs_name,
                         /* "char **" is not compatible with "const char **" */
                         (const char **)ipv6_addrs.names,
                         ipv6_addrs.n, &sb_address_sets);
        free(ipv4_addrs_name);
        free(ipv6_addrs_name);
        svec_destroy(&ipv4_addrs);
        svec_destroy(&ipv6_addrs);
    }

    /* sync user defined address sets, which may overwrite port group
     * generated address sets if same name is used */
    const struct nbrec_address_set *nb_address_set;
    NBREC_ADDRESS_SET_FOR_EACH (nb_address_set, ctx->ovnnb_idl) {
        sync_address_set(ctx, nb_address_set->name,
            /* "char **" is not compatible with "const char **" */
            (const char **)nb_address_set->addresses,
            nb_address_set->n_addresses, &sb_address_sets);
    }

    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, &sb_address_sets) {
        sbrec_address_set_delete(node->data);
        shash_delete(&sb_address_sets, node);
    }
    shash_destroy(&sb_address_sets);
}

/* Each port group in Port_Group table in OVN_Northbound has a corresponding
 * entry in Port_Group table in OVN_Southbound. In OVN_Northbound the entries
 * contains lport uuids, while in OVN_Southbound we store the lport names.
 */
static void
sync_port_groups(struct northd_context *ctx, struct hmap *pgs)
{
    struct shash sb_port_groups = SHASH_INITIALIZER(&sb_port_groups);

    const struct sbrec_port_group *sb_port_group;
    SBREC_PORT_GROUP_FOR_EACH (sb_port_group, ctx->ovnsb_idl) {
        shash_add(&sb_port_groups, sb_port_group->name, sb_port_group);
    }

    struct ds sb_name = DS_EMPTY_INITIALIZER;

    struct ovn_port_group *pg;
    HMAP_FOR_EACH (pg, key_node, pgs) {

        struct ovn_port_group_ls *pg_ls;
        HMAP_FOR_EACH (pg_ls, key_node, &pg->nb_lswitches) {
            ds_clear(&sb_name);
            get_sb_port_group_name(pg->nb_pg->name, pg_ls->od->sb->tunnel_key,
                                   &sb_name);
            sb_port_group = shash_find_and_delete(&sb_port_groups,
                                                  ds_cstr(&sb_name));
            if (!sb_port_group) {
                sb_port_group = sbrec_port_group_insert(ctx->ovnsb_txn);
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

    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, &sb_port_groups) {
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
sync_meters_iterate_nb_meter(struct northd_context *ctx,
                             const char *meter_name,
                             const struct nbrec_meter *nb_meter,
                             struct shash *sb_meters,
                             struct sset *used_sb_meters)
{
    const struct sbrec_meter *sb_meter;
    bool new_sb_meter = false;

    sb_meter = shash_find_data(sb_meters, meter_name);
    if (!sb_meter) {
        sb_meter = sbrec_meter_insert(ctx->ovnsb_txn);
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

            sb_bands[i] = sbrec_meter_band_insert(ctx->ovnsb_txn);

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
sync_acl_fair_meter(struct northd_context *ctx, struct shash *meter_groups,
                    const struct nbrec_acl *acl, struct shash *sb_meters,
                    struct sset *used_sb_meters)
{
    const struct nbrec_meter *nb_meter =
        fair_meter_lookup_by_name(meter_groups, acl->meter);

    if (!nb_meter) {
        return;
    }

    char *meter_name = alloc_acl_log_unique_meter_name(acl);
    sync_meters_iterate_nb_meter(ctx, meter_name, nb_meter, sb_meters,
                                 used_sb_meters);
    free(meter_name);
}

/* Each entry in the Meter and Meter_Band tables in OVN_Northbound have
 * a corresponding entries in the Meter and Meter_Band tables in
 * OVN_Southbound. Additionally, ACL logs that use fair meters have
 * a private copy of its meter in the SB table.
 */
static void
sync_meters(struct northd_context *ctx, struct shash *meter_groups)
{
    struct shash sb_meters = SHASH_INITIALIZER(&sb_meters);
    struct sset used_sb_meters = SSET_INITIALIZER(&used_sb_meters);

    const struct sbrec_meter *sb_meter;
    SBREC_METER_FOR_EACH (sb_meter, ctx->ovnsb_idl) {
        shash_add(&sb_meters, sb_meter->name, sb_meter);
    }

    const struct nbrec_meter *nb_meter;
    NBREC_METER_FOR_EACH (nb_meter, ctx->ovnnb_idl) {
        sync_meters_iterate_nb_meter(ctx, nb_meter->name, nb_meter,
                                     &sb_meters, &used_sb_meters);
    }

    /*
     * In addition to creating Meters in the SB from the block above, check
     * and see if additional rows are needed to get ACLs logs individually
     * rate-limited.
     */
    const struct nbrec_acl *acl;
    NBREC_ACL_FOR_EACH (acl, ctx->ovnnb_idl) {
        sync_acl_fair_meter(ctx, meter_groups, acl,
                            &sb_meters, &used_sb_meters);
    }

    const char *used_meter;
    const char *used_meter_next;
    SSET_FOR_EACH_SAFE (used_meter, used_meter_next, &used_sb_meters) {
        shash_find_and_delete(&sb_meters, used_meter);
        sset_delete(&used_sb_meters, SSET_NODE_FROM_NAME(used_meter));
    }
    sset_destroy(&used_sb_meters);

    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, &sb_meters) {
        sbrec_meter_delete(node->data);
        shash_delete(&sb_meters, node);
    }
    shash_destroy(&sb_meters);
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
sync_dns_entries(struct northd_context *ctx, struct hmap *datapaths)
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

    const struct sbrec_dns *sbrec_dns, *next;
    SBREC_DNS_FOR_EACH_SAFE (sbrec_dns, next, ctx->ovnsb_idl) {
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
            sbrec_dns = sbrec_dns_insert(ctx->ovnsb_txn);
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

    struct ovn_datapath *dp, *next_dp;
    HMAP_FOR_EACH_SAFE (dp, next_dp, key_node, datapaths) {
        ovn_datapath_destroy(datapaths, dp);
    }
    hmap_destroy(datapaths);

    struct ovn_port *port, *next_port;
    HMAP_FOR_EACH_SAFE (port, next_port, key_node, ports) {
        ovn_port_destroy(ports, port);
    }
    hmap_destroy(ports);
}

static void
build_ip_mcast(struct northd_context *ctx, struct hmap *datapaths)
{
    struct ovn_datapath *od;

    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbs) {
            continue;
        }

        const struct sbrec_ip_multicast *ip_mcast =
            ip_mcast_lookup(ctx->sbrec_ip_mcast_by_dp, od->sb);

        if (!ip_mcast) {
            ip_mcast = sbrec_ip_multicast_insert(ctx->ovnsb_txn);
        }
        store_mcast_info_for_switch_datapath(ip_mcast, od);
    }

    /* Delete southbound records without northbound matches. */
    const struct sbrec_ip_multicast *sb, *sb_next;

    SBREC_IP_MULTICAST_FOR_EACH_SAFE (sb, sb_next, ctx->ovnsb_idl) {
        od = ovn_datapath_from_sbrec(datapaths, sb->datapath);
        if (!od || ovn_datapath_is_stale(od)) {
            sbrec_ip_multicast_delete(sb);
        }
    }
}

static void
build_mcast_groups(struct northd_context *ctx,
                   struct hmap *datapaths, struct hmap *ports,
                   struct hmap *mcast_groups,
                   struct hmap *igmp_groups)
{
    struct ovn_port *op;

    hmap_init(mcast_groups);
    hmap_init(igmp_groups);

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
             * add it to the MC_MROUTER_STATIC group.
             */
            if (op->mcast_info.flood_reports) {
                ovn_multicast_add(mcast_groups, &mc_mrouter_static, op);
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

    const struct sbrec_igmp_group *sb_igmp, *sb_igmp_next;

    SBREC_IGMP_GROUP_FOR_EACH_SAFE (sb_igmp, sb_igmp_next, ctx->ovnsb_idl) {
        /* If this is a stale group (e.g., controller had crashed,
         * purge it).
         */
        if (!sb_igmp->chassis || !sb_igmp->datapath) {
            sbrec_igmp_group_delete(sb_igmp);
            continue;
        }

        /* If the datapath value is stale, purge the group. */
        struct ovn_datapath *od =
            ovn_datapath_from_sbrec(datapaths, sb_igmp->datapath);

        if (!od || ovn_datapath_is_stale(od)) {
            sbrec_igmp_group_delete(sb_igmp);
            continue;
        }

        struct in6_addr group_address;
        if (!ovn_igmp_group_get_address(sb_igmp, &group_address)) {
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
            ovn_igmp_group_add(ctx, igmp_groups, od, &group_address,
                               sb_igmp->address);

        /* Add the extracted ports to the IGMP group. */
        ovn_igmp_group_add_entry(igmp_group, igmp_ports, n_igmp_ports);
    }

    /* Build IGMP groups for multicast routers with relay enabled. The router
     * IGMP groups are based on the groups learnt by their multicast enabled
     * peers.
     */
    struct ovn_datapath *od;
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

                /* For IPv6 only relay routable multicast groups
                 * (RFC 4291 2.7).
                 */
                if (!IN6_IS_ADDR_V4MAPPED(address) &&
                        !ipv6_addr_is_routable_multicast(address)) {
                    continue;
                }

                struct ovn_igmp_group *igmp_group_rtr =
                    ovn_igmp_group_add(ctx, igmp_groups, router_port->od,
                                       address, igmp_group->mcgroup.name);
                struct ovn_port **router_igmp_ports =
                    xmalloc(sizeof *router_igmp_ports);
                router_igmp_ports[0] = router_port;
                ovn_igmp_group_add_entry(igmp_group_rtr, router_igmp_ports, 1);
            }
        }
    }

    /* Walk the aggregated IGMP groups and allocate IDs for new entries.
     * Then store the ports in the associated multicast group.
     */
    struct ovn_igmp_group *igmp_group, *igmp_group_next;
    HMAP_FOR_EACH_SAFE (igmp_group, igmp_group_next, hmap_node, igmp_groups) {

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
build_meter_groups(struct northd_context *ctx,
                   struct shash *meter_groups)
{
    const struct nbrec_meter *nb_meter;
    NBREC_METER_FOR_EACH (nb_meter, ctx->ovnnb_idl) {
        shash_add(meter_groups, nb_meter->name, nb_meter);
    }
}

static int
get_probe_interval(const char *db, const struct nbrec_nb_global *nb)
{
    int default_interval = (db && !stream_or_pstream_needs_probes(db)
                            ? 0 : DEFAULT_PROBE_INTERVAL_MSEC);
    int interval = smap_get_int(&nb->options,
                                "northd_probe_interval", default_interval);

    if (interval > 0 && interval < 1000) {
        interval = 1000;
    }
    return interval;
}

static void
ovnnb_db_run(struct northd_context *ctx,
             struct ovsdb_idl_index *sbrec_chassis_by_name,
             struct ovsdb_idl_loop *sb_loop,
             struct hmap *datapaths, struct hmap *ports,
             struct ovs_list *lr_list,
             int64_t loop_start_time,
             const char *ovn_internal_version)
{
    if (!ctx->ovnsb_txn || !ctx->ovnnb_txn) {
        return;
    }
    struct hmap port_groups;
    struct hmap mcast_groups;
    struct hmap igmp_groups;
    struct shash meter_groups = SHASH_INITIALIZER(&meter_groups);
    struct hmap lbs;
    struct hmap bfd_connections = HMAP_INITIALIZER(&bfd_connections);

    /* Sync ipsec configuration.
     * Copy nb_cfg from northbound to southbound database.
     * Also set up to update sb_cfg once our southbound transaction commits. */
    const struct nbrec_nb_global *nb = nbrec_nb_global_first(ctx->ovnnb_idl);
    if (!nb) {
        nb = nbrec_nb_global_insert(ctx->ovnnb_txn);
    }
    const struct sbrec_sb_global *sb = sbrec_sb_global_first(ctx->ovnsb_idl);
    if (!sb) {
        sb = sbrec_sb_global_insert(ctx->ovnsb_txn);
    }
    if (nb->ipsec != sb->ipsec) {
        sbrec_sb_global_set_ipsec(sb, nb->ipsec);
    }
    if (nb->nb_cfg != sb->nb_cfg) {
        sbrec_sb_global_set_nb_cfg(sb, nb->nb_cfg);
        nbrec_nb_global_set_nb_cfg_timestamp(nb, loop_start_time);
    }
    sbrec_sb_global_set_options(sb, &nb->options);
    sb_loop->next_cfg = nb->nb_cfg;

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

    smap_add(&options, "mac_prefix", mac_addr_prefix);

    if (!monitor_mac) {
        eth_addr_random(&svc_monitor_mac_ea);
        snprintf(svc_monitor_mac, sizeof svc_monitor_mac,
                 ETH_ADDR_FMT, ETH_ADDR_ARGS(svc_monitor_mac_ea));
        smap_replace(&options, "svc_monitor_mac", svc_monitor_mac);
    }

    char *max_tunid = xasprintf("%d", get_ovn_max_dp_key_local(ctx));
    smap_replace(&options, "max_tunid", max_tunid);
    free(max_tunid);

    smap_replace(&options, "northd_internal_version", ovn_internal_version);

    nbrec_nb_global_verify_options(nb);
    nbrec_nb_global_set_options(nb, &options);

    smap_destroy(&options);

    /* Update the probe interval. */
    northd_probe_interval_nb = get_probe_interval(ovnnb_db, nb);
    northd_probe_interval_sb = get_probe_interval(ovnsb_db, nb);

    use_logical_dp_groups = smap_get_bool(&nb->options,
                                          "use_logical_dp_groups", false);
    /* deprecated, use --event instead */
    controller_event_en = smap_get_bool(&nb->options,
                                        "controller_event", false);
    check_lsp_is_up = !smap_get_bool(&nb->options,
                                     "ignore_lsp_down", false);

    build_datapaths(ctx, datapaths, lr_list);
    build_ports(ctx, sbrec_chassis_by_name, datapaths, ports);
    build_ovn_lbs(ctx, datapaths, ports, &lbs);
    build_ipam(datapaths, ports);
    build_port_group_lswitches(ctx, &port_groups, ports);
    build_lrouter_groups(ports, lr_list);
    build_ip_mcast(ctx, datapaths);
    build_mcast_groups(ctx, datapaths, ports, &mcast_groups, &igmp_groups);
    build_meter_groups(ctx, &meter_groups);
    build_bfd_table(ctx, &bfd_connections, ports);
    build_lflows(ctx, datapaths, ports, &port_groups, &mcast_groups,
                 &igmp_groups, &meter_groups, &lbs, &bfd_connections);
    ovn_update_ipv6_prefix(ports);

    sync_address_sets(ctx);
    sync_port_groups(ctx, &port_groups);
    sync_meters(ctx, &meter_groups);
    sync_dns_entries(ctx, datapaths);

    struct ovn_northd_lb *lb;
    HMAP_FOR_EACH_POP (lb, hmap_node, &lbs) {
        ovn_northd_lb_destroy(lb);
    }
    hmap_destroy(&lbs);

    struct ovn_igmp_group *igmp_group, *next_igmp_group;

    HMAP_FOR_EACH_SAFE (igmp_group, next_igmp_group, hmap_node, &igmp_groups) {
        ovn_igmp_group_destroy(&igmp_groups, igmp_group);
    }

    struct ovn_port_group *pg, *next_pg;
    HMAP_FOR_EACH_SAFE (pg, next_pg, key_node, &port_groups) {
        ovn_port_group_destroy(&port_groups, pg);
    }

    bfd_cleanup_connections(ctx, &bfd_connections);

    hmap_destroy(&igmp_groups);
    hmap_destroy(&mcast_groups);
    hmap_destroy(&port_groups);
    hmap_destroy(&bfd_connections);

    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, &meter_groups) {
        shash_delete(&meter_groups, node);
    }
    shash_destroy(&meter_groups);

    /* XXX Having to explicitly clean up macam here
     * is a bit strange. We don't explicitly initialize
     * macam in this module, but this is the logical place
     * to clean it up. Ideally, more IPAM logic can be factored
     * out of ovn-northd and this can be taken care of there
     * as well.
     */
    cleanup_macam();
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

static void
update_sb_ha_group_ref_chassis(struct shash *ha_ref_chassis_map)
{
    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, ha_ref_chassis_map) {
        struct ha_ref_chassis_info *ha_ref_info = node->data;
        sbrec_ha_chassis_group_set_ref_chassis(ha_ref_info->ha_chassis_group,
                                               ha_ref_info->ref_chassis,
                                               ha_ref_info->n_ref_chassis);
        free(ha_ref_info->ref_chassis);
        free(ha_ref_info);
        shash_delete(ha_ref_chassis_map, node);
    }
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
build_ha_chassis_group_ref_chassis(struct northd_context *ctx,
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
            ctx->sbrec_ha_chassis_grp_by_name, ha_group_name);

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
handle_port_binding_changes(struct northd_context *ctx, struct hmap *ports,
                            struct shash *ha_ref_chassis_map)
{
    const struct sbrec_port_binding *sb;
    bool build_ha_chassis_ref = false;
    if (ctx->ovnsb_txn) {
        const struct sbrec_ha_chassis_group *ha_ch_grp;
        SBREC_HA_CHASSIS_GROUP_FOR_EACH (ha_ch_grp, ctx->ovnsb_idl) {
            struct ha_ref_chassis_info *ref_ch_info =
                xzalloc(sizeof *ref_ch_info);
            ref_ch_info->ha_chassis_group = ha_ch_grp;
            build_ha_chassis_ref = true;
            shash_add(ha_ref_chassis_map, ha_ch_grp->name, ref_ch_info);
        }
    }

    SBREC_PORT_BINDING_FOR_EACH(sb, ctx->ovnsb_idl) {
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

        if (build_ha_chassis_ref && ctx->ovnsb_txn && sb->chassis) {
            /* Check and add the chassis which has claimed this 'sb'
             * to the ha chassis group's ref_chassis if required. */
            build_ha_chassis_group_ref_chassis(ctx, sb, op,
                                               ha_ref_chassis_map);
        }
    }
}

static struct gen_opts_map supported_dhcp_opts[] = {
    OFFERIP,
    DHCP_OPT_NETMASK,
    DHCP_OPT_ROUTER,
    DHCP_OPT_DNS_SERVER,
    DHCP_OPT_LOG_SERVER,
    DHCP_OPT_LPR_SERVER,
    DHCP_OPT_SWAP_SERVER,
    DHCP_OPT_POLICY_FILTER,
    DHCP_OPT_ROUTER_SOLICITATION,
    DHCP_OPT_NIS_SERVER,
    DHCP_OPT_NTP_SERVER,
    DHCP_OPT_SERVER_ID,
    DHCP_OPT_TFTP_SERVER,
    DHCP_OPT_CLASSLESS_STATIC_ROUTE,
    DHCP_OPT_MS_CLASSLESS_STATIC_ROUTE,
    DHCP_OPT_IP_FORWARD_ENABLE,
    DHCP_OPT_ROUTER_DISCOVERY,
    DHCP_OPT_ETHERNET_ENCAP,
    DHCP_OPT_DEFAULT_TTL,
    DHCP_OPT_TCP_TTL,
    DHCP_OPT_MTU,
    DHCP_OPT_LEASE_TIME,
    DHCP_OPT_T1,
    DHCP_OPT_T2,
    DHCP_OPT_WPAD,
    DHCP_OPT_BOOTFILE,
    DHCP_OPT_PATH_PREFIX,
    DHCP_OPT_TFTP_SERVER_ADDRESS,
    DHCP_OPT_DOMAIN_NAME,
    DHCP_OPT_ARP_CACHE_TIMEOUT,
    DHCP_OPT_TCP_KEEPALIVE_INTERVAL,
    DHCP_OPT_DOMAIN_SEARCH_LIST,
    DHCP_OPT_BOOTFILE_ALT,
    DHCP_OPT_BROADCAST_ADDRESS,
    DHCP_OPT_NETBIOS_NAME_SERVER,
    DHCP_OPT_NETBIOS_NODE_TYPE,
};

static struct gen_opts_map supported_dhcpv6_opts[] = {
    DHCPV6_OPT_IA_ADDR,
    DHCPV6_OPT_SERVER_ID,
    DHCPV6_OPT_DOMAIN_SEARCH,
    DHCPV6_OPT_DNS_SERVER
};

static void
check_and_add_supported_dhcp_opts_to_sb_db(struct northd_context *ctx)
{
    struct hmap dhcp_opts_to_add = HMAP_INITIALIZER(&dhcp_opts_to_add);
    for (size_t i = 0; (i < sizeof(supported_dhcp_opts) /
                            sizeof(supported_dhcp_opts[0])); i++) {
        hmap_insert(&dhcp_opts_to_add, &supported_dhcp_opts[i].hmap_node,
                    dhcp_opt_hash(supported_dhcp_opts[i].name));
    }

    const struct sbrec_dhcp_options *opt_row, *opt_row_next;
    SBREC_DHCP_OPTIONS_FOR_EACH_SAFE(opt_row, opt_row_next, ctx->ovnsb_idl) {
        struct gen_opts_map *dhcp_opt =
            dhcp_opts_find(&dhcp_opts_to_add, opt_row->name);
        if (dhcp_opt) {
            if (!strcmp(dhcp_opt->type, opt_row->type) &&
                 dhcp_opt->code == opt_row->code) {
                hmap_remove(&dhcp_opts_to_add, &dhcp_opt->hmap_node);
            } else {
                sbrec_dhcp_options_delete(opt_row);
            }
        } else {
            sbrec_dhcp_options_delete(opt_row);
        }
    }

    struct gen_opts_map *opt;
    HMAP_FOR_EACH (opt, hmap_node, &dhcp_opts_to_add) {
        struct sbrec_dhcp_options *sbrec_dhcp_option =
            sbrec_dhcp_options_insert(ctx->ovnsb_txn);
        sbrec_dhcp_options_set_name(sbrec_dhcp_option, opt->name);
        sbrec_dhcp_options_set_code(sbrec_dhcp_option, opt->code);
        sbrec_dhcp_options_set_type(sbrec_dhcp_option, opt->type);
    }

    hmap_destroy(&dhcp_opts_to_add);
}

static void
check_and_add_supported_dhcpv6_opts_to_sb_db(struct northd_context *ctx)
{
    struct hmap dhcpv6_opts_to_add = HMAP_INITIALIZER(&dhcpv6_opts_to_add);
    for (size_t i = 0; (i < sizeof(supported_dhcpv6_opts) /
                            sizeof(supported_dhcpv6_opts[0])); i++) {
        hmap_insert(&dhcpv6_opts_to_add, &supported_dhcpv6_opts[i].hmap_node,
                    dhcp_opt_hash(supported_dhcpv6_opts[i].name));
    }

    const struct sbrec_dhcpv6_options *opt_row, *opt_row_next;
    SBREC_DHCPV6_OPTIONS_FOR_EACH_SAFE(opt_row, opt_row_next, ctx->ovnsb_idl) {
        struct gen_opts_map *dhcp_opt =
            dhcp_opts_find(&dhcpv6_opts_to_add, opt_row->name);
        if (dhcp_opt) {
            hmap_remove(&dhcpv6_opts_to_add, &dhcp_opt->hmap_node);
        } else {
            sbrec_dhcpv6_options_delete(opt_row);
        }
    }

    struct gen_opts_map *opt;
    HMAP_FOR_EACH(opt, hmap_node, &dhcpv6_opts_to_add) {
        struct sbrec_dhcpv6_options *sbrec_dhcpv6_option =
            sbrec_dhcpv6_options_insert(ctx->ovnsb_txn);
        sbrec_dhcpv6_options_set_name(sbrec_dhcpv6_option, opt->name);
        sbrec_dhcpv6_options_set_code(sbrec_dhcpv6_option, opt->code);
        sbrec_dhcpv6_options_set_type(sbrec_dhcpv6_option, opt->type);
    }

    hmap_destroy(&dhcpv6_opts_to_add);
}

static const char *rbac_chassis_auth[] =
    {"name"};
static const char *rbac_chassis_update[] =
    {"nb_cfg", "external_ids", "encaps", "vtep_logical_switches",
     "other_config"};

static const char *rbac_chassis_private_auth[] =
    {"name"};
static const char *rbac_chassis_private_update[] =
    {"nb_cfg", "nb_cfg_timestamp", "chassis", "external_ids"};

static const char *rbac_encap_auth[] =
    {"chassis_name"};
static const char *rbac_encap_update[] =
    {"type", "options", "ip"};

static const char *rbac_port_binding_auth[] =
    {""};
static const char *rbac_port_binding_update[] =
    {"chassis", "up"};

static const char *rbac_mac_binding_auth[] =
    {""};
static const char *rbac_mac_binding_update[] =
    {"logical_port", "ip", "mac", "datapath"};

static const char *rbac_svc_monitor_auth[] =
    {""};
static const char *rbac_svc_monitor_auth_update[] =
    {"status"};

static struct rbac_perm_cfg {
    const char *table;
    const char **auth;
    int n_auth;
    bool insdel;
    const char **update;
    int n_update;
    const struct sbrec_rbac_permission *row;
} rbac_perm_cfg[] = {
    {
        .table = "Chassis",
        .auth = rbac_chassis_auth,
        .n_auth = ARRAY_SIZE(rbac_chassis_auth),
        .insdel = true,
        .update = rbac_chassis_update,
        .n_update = ARRAY_SIZE(rbac_chassis_update),
        .row = NULL
    },{
        .table = "Chassis_Private",
        .auth = rbac_chassis_private_auth,
        .n_auth = ARRAY_SIZE(rbac_chassis_private_auth),
        .insdel = true,
        .update = rbac_chassis_private_update,
        .n_update = ARRAY_SIZE(rbac_chassis_private_update),
        .row = NULL
    },{
        .table = "Encap",
        .auth = rbac_encap_auth,
        .n_auth = ARRAY_SIZE(rbac_encap_auth),
        .insdel = true,
        .update = rbac_encap_update,
        .n_update = ARRAY_SIZE(rbac_encap_update),
        .row = NULL
    },{
        .table = "Port_Binding",
        .auth = rbac_port_binding_auth,
        .n_auth = ARRAY_SIZE(rbac_port_binding_auth),
        .insdel = false,
        .update = rbac_port_binding_update,
        .n_update = ARRAY_SIZE(rbac_port_binding_update),
        .row = NULL
    },{
        .table = "MAC_Binding",
        .auth = rbac_mac_binding_auth,
        .n_auth = ARRAY_SIZE(rbac_mac_binding_auth),
        .insdel = true,
        .update = rbac_mac_binding_update,
        .n_update = ARRAY_SIZE(rbac_mac_binding_update),
        .row = NULL
    },{
        .table = "Service_Monitor",
        .auth = rbac_svc_monitor_auth,
        .n_auth = ARRAY_SIZE(rbac_svc_monitor_auth),
        .insdel = false,
        .update = rbac_svc_monitor_auth_update,
        .n_update = ARRAY_SIZE(rbac_svc_monitor_auth_update),
        .row = NULL
    },{
        .table = NULL,
        .auth = NULL,
        .n_auth = 0,
        .insdel = false,
        .update = NULL,
        .n_update = 0,
        .row = NULL
    }
};

static bool
ovn_rbac_validate_perm(const struct sbrec_rbac_permission *perm)
{
    struct rbac_perm_cfg *pcfg;
    int i, j, n_found;

    for (pcfg = rbac_perm_cfg; pcfg->table; pcfg++) {
        if (!strcmp(perm->table, pcfg->table)) {
            break;
        }
    }
    if (!pcfg->table) {
        return false;
    }
    if (perm->n_authorization != pcfg->n_auth ||
        perm->n_update != pcfg->n_update) {
        return false;
    }
    if (perm->insert_delete != pcfg->insdel) {
        return false;
    }
    /* verify perm->authorization vs. pcfg->auth */
    n_found = 0;
    for (i = 0; i < pcfg->n_auth; i++) {
        for (j = 0; j < perm->n_authorization; j++) {
            if (!strcmp(pcfg->auth[i], perm->authorization[j])) {
                n_found++;
                break;
            }
        }
    }
    if (n_found != pcfg->n_auth) {
        return false;
    }

    /* verify perm->update vs. pcfg->update */
    n_found = 0;
    for (i = 0; i < pcfg->n_update; i++) {
        for (j = 0; j < perm->n_update; j++) {
            if (!strcmp(pcfg->update[i], perm->update[j])) {
                n_found++;
                break;
            }
        }
    }
    if (n_found != pcfg->n_update) {
        return false;
    }

    /* Success, db state matches expected state */
    pcfg->row = perm;
    return true;
}

static void
ovn_rbac_create_perm(struct rbac_perm_cfg *pcfg,
                     struct northd_context *ctx,
                     const struct sbrec_rbac_role *rbac_role)
{
    struct sbrec_rbac_permission *rbac_perm;

    rbac_perm = sbrec_rbac_permission_insert(ctx->ovnsb_txn);
    sbrec_rbac_permission_set_table(rbac_perm, pcfg->table);
    sbrec_rbac_permission_set_authorization(rbac_perm,
                                            pcfg->auth,
                                            pcfg->n_auth);
    sbrec_rbac_permission_set_insert_delete(rbac_perm, pcfg->insdel);
    sbrec_rbac_permission_set_update(rbac_perm,
                                     pcfg->update,
                                     pcfg->n_update);
    sbrec_rbac_role_update_permissions_setkey(rbac_role, pcfg->table,
                                              rbac_perm);
}

static void
check_and_update_rbac(struct northd_context *ctx)
{
    const struct sbrec_rbac_role *rbac_role = NULL;
    const struct sbrec_rbac_permission *perm_row, *perm_next;
    const struct sbrec_rbac_role *role_row, *role_row_next;
    struct rbac_perm_cfg *pcfg;

    for (pcfg = rbac_perm_cfg; pcfg->table; pcfg++) {
        pcfg->row = NULL;
    }

    SBREC_RBAC_PERMISSION_FOR_EACH_SAFE (perm_row, perm_next, ctx->ovnsb_idl) {
        if (!ovn_rbac_validate_perm(perm_row)) {
            sbrec_rbac_permission_delete(perm_row);
        }
    }
    SBREC_RBAC_ROLE_FOR_EACH_SAFE (role_row, role_row_next, ctx->ovnsb_idl) {
        if (strcmp(role_row->name, "ovn-controller")) {
            sbrec_rbac_role_delete(role_row);
        } else {
            rbac_role = role_row;
        }
    }

    if (!rbac_role) {
        rbac_role = sbrec_rbac_role_insert(ctx->ovnsb_txn);
        sbrec_rbac_role_set_name(rbac_role, "ovn-controller");
    }

    for (pcfg = rbac_perm_cfg; pcfg->table; pcfg++) {
        if (!pcfg->row) {
            ovn_rbac_create_perm(pcfg, ctx, rbac_role);
        }
    }
}

/* Updates the sb_cfg and hv_cfg columns in the northbound NB_Global table. */
static void
update_northbound_cfg(struct northd_context *ctx,
                      struct ovsdb_idl_loop *sb_loop,
                      int64_t loop_start_time)
{
    /* Update northbound sb_cfg if appropriate. */
    const struct nbrec_nb_global *nbg = nbrec_nb_global_first(ctx->ovnnb_idl);
    int64_t sb_cfg = sb_loop->cur_cfg;
    if (nbg && sb_cfg && nbg->sb_cfg != sb_cfg) {
        nbrec_nb_global_set_sb_cfg(nbg, sb_cfg);
        nbrec_nb_global_set_sb_cfg_timestamp(nbg, loop_start_time);
    }

    /* Update northbound hv_cfg if appropriate. */
    if (nbg) {
        /* Find minimum nb_cfg among all chassis. */
        const struct sbrec_chassis_private *chassis_priv;
        int64_t hv_cfg = nbg->nb_cfg;
        int64_t hv_cfg_ts = 0;
        SBREC_CHASSIS_PRIVATE_FOR_EACH (chassis_priv, ctx->ovnsb_idl) {
            const struct sbrec_chassis *chassis = chassis_priv->chassis;
            if (chassis) {
                if (smap_get_bool(&chassis->other_config,
                                  "is-remote", false)) {
                    /* Skip remote chassises. */
                    continue;
                }
            } else {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "Chassis does not exist for "
                             "Chassis_Private record, name: %s",
                             chassis_priv->name);
            }

            if (chassis_priv->nb_cfg < hv_cfg) {
                hv_cfg = chassis_priv->nb_cfg;
                hv_cfg_ts = chassis_priv->nb_cfg_timestamp;
            } else if (chassis_priv->nb_cfg == hv_cfg &&
                       chassis_priv->nb_cfg_timestamp > hv_cfg_ts) {
                hv_cfg_ts = chassis_priv->nb_cfg_timestamp;
            }
        }

        /* Update hv_cfg. */
        if (nbg->hv_cfg != hv_cfg) {
            nbrec_nb_global_set_hv_cfg(nbg, hv_cfg);
            nbrec_nb_global_set_hv_cfg_timestamp(nbg, hv_cfg_ts);
        }
    }
}

/* Handle a fairly small set of changes in the southbound database. */
static void
ovnsb_db_run(struct northd_context *ctx,
             struct ovsdb_idl_loop *sb_loop,
             struct hmap *ports,
             int64_t loop_start_time)
{
    if (!ctx->ovnnb_txn || !ovsdb_idl_has_ever_connected(ctx->ovnsb_idl)) {
        return;
    }

    struct shash ha_ref_chassis_map = SHASH_INITIALIZER(&ha_ref_chassis_map);
    handle_port_binding_changes(ctx, ports, &ha_ref_chassis_map);
    update_northbound_cfg(ctx, sb_loop, loop_start_time);
    if (ctx->ovnsb_txn) {
        update_sb_ha_group_ref_chassis(&ha_ref_chassis_map);
    }
    shash_destroy(&ha_ref_chassis_map);
}

static void
ovn_db_run(struct northd_context *ctx,
           struct ovsdb_idl_index *sbrec_chassis_by_name,
           struct ovsdb_idl_loop *ovnsb_idl_loop,
           const char *ovn_internal_version)
{
    struct hmap datapaths, ports;
    struct ovs_list lr_list;
    ovs_list_init(&lr_list);
    hmap_init(&datapaths);
    hmap_init(&ports);

    int64_t start_time = time_wall_msec();
    ovnnb_db_run(ctx, sbrec_chassis_by_name, ovnsb_idl_loop,
                 &datapaths, &ports, &lr_list, start_time,
                 ovn_internal_version);
    ovnsb_db_run(ctx, ovnsb_idl_loop, &ports, start_time);
    destroy_datapaths_and_ports(&datapaths, &ports, &lr_list);
}

static void
parse_options(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum {
        OVN_DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"ovnsb-db", required_argument, NULL, 'd'},
        {"ovnnb-db", required_argument, NULL, 'D'},
        {"unixctl", required_argument, NULL, 'u'},
        {"help", no_argument, NULL, 'h'},
        {"options", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        OVN_DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        OVN_DAEMON_OPTION_HANDLERS;
        VLOG_OPTION_HANDLERS;
        STREAM_SSL_OPTION_HANDLERS;

        case 'd':
            ovnsb_db = optarg;
            break;

        case 'D':
            ovnnb_db = optarg;
            break;

        case 'u':
            unixctl_path = optarg;
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'V':
            ovn_print_version(0, 0);
            exit(EXIT_SUCCESS);

        default:
            break;
        }
    }

    if (!ovnsb_db || !ovnsb_db[0]) {
        ovnsb_db = default_sb_db();
    }

    if (!ovnnb_db || !ovnnb_db[0]) {
        ovnnb_db = default_nb_db();
    }

    free(short_options);
}

static void
add_column_noalert(struct ovsdb_idl *idl,
                   const struct ovsdb_idl_column *column)
{
    ovsdb_idl_add_column(idl, column);
    ovsdb_idl_omit_alert(idl, column);
}

int
main(int argc, char *argv[])
{
    int res = EXIT_SUCCESS;
    struct unixctl_server *unixctl;
    int retval;
    bool exiting;
    struct northd_state state;

    fatal_ignore_sigpipe();
    ovs_cmdl_proctitle_init(argc, argv);
    ovn_set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);

    daemonize_start(false);

    char *abs_unixctl_path = get_abs_unix_ctl_path(unixctl_path);
    retval = unixctl_server_create(abs_unixctl_path, &unixctl);
    free(abs_unixctl_path);

    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_northd_exit, &exiting);
    unixctl_command_register("pause", "", 0, 0, ovn_northd_pause, &state);
    unixctl_command_register("resume", "", 0, 0, ovn_northd_resume, &state);
    unixctl_command_register("is-paused", "", 0, 0, ovn_northd_is_paused,
                             &state);
    unixctl_command_register("status", "", 0, 0, ovn_northd_status, &state);

    bool reset_ovnsb_idl_min_index = false;
    unixctl_command_register("sb-cluster-state-reset", "", 0, 0,
                             cluster_state_reset_cmd,
                             &reset_ovnsb_idl_min_index);

    bool reset_ovnnb_idl_min_index = false;
    unixctl_command_register("nb-cluster-state-reset", "", 0, 0,
                             cluster_state_reset_cmd,
                             &reset_ovnnb_idl_min_index);

    daemonize_complete();

    /* We want to detect (almost) all changes to the ovn-nb db. */
    struct ovsdb_idl_loop ovnnb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnnb_db, &nbrec_idl_class, true, true));
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl,
                         &nbrec_nb_global_col_nb_cfg_timestamp);
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl, &nbrec_nb_global_col_sb_cfg);
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl,
                         &nbrec_nb_global_col_sb_cfg_timestamp);
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl, &nbrec_nb_global_col_hv_cfg);
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl,
                         &nbrec_nb_global_col_hv_cfg_timestamp);

    unixctl_command_register("nb-connection-status", "", 0, 0,
                             ovn_conn_show, ovnnb_idl_loop.idl);

    /* We want to detect only selected changes to the ovn-sb db. */
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnsb_db, &sbrec_idl_class, false, true));

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_sb_global);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_sb_global_col_nb_cfg);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_sb_global_col_options);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_sb_global_col_ipsec);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_logical_flow);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_logical_flow_col_logical_datapath);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_logical_flow_col_logical_dp_group);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_logical_flow_col_pipeline);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_logical_flow_col_table_id);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_logical_flow_col_priority);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_logical_flow_col_match);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_logical_flow_col_actions);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl,
                        &sbrec_table_logical_dp_group);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_logical_dp_group_col_datapaths);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_multicast_group);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_multicast_group_col_datapath);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_multicast_group_col_tunnel_key);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_multicast_group_col_name);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_multicast_group_col_ports);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_datapath_binding);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_datapath_binding_col_tunnel_key);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_datapath_binding_col_load_balancers);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_datapath_binding_col_external_ids);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_port_binding);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_binding_col_datapath);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_port_binding_col_logical_port);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_port_binding_col_tunnel_key);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_port_binding_col_parent_port);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_binding_col_tag);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_binding_col_type);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_binding_col_options);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_binding_col_mac);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_port_binding_col_nat_addresses);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_port_binding_col_chassis);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_port_binding_col_gateway_chassis);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_port_binding_col_ha_chassis_group);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_port_binding_col_virtual_parent);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_port_binding_col_up);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_gateway_chassis_col_chassis);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_gateway_chassis_col_name);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_gateway_chassis_col_priority);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_gateway_chassis_col_external_ids);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_gateway_chassis_col_options);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_port_binding_col_external_ids);
    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_mac_binding);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_mac_binding_col_datapath);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_mac_binding_col_ip);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_mac_binding_col_mac);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_mac_binding_col_logical_port);
    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_dhcp_options);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dhcp_options_col_code);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dhcp_options_col_type);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dhcp_options_col_name);
    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_dhcpv6_options);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dhcpv6_options_col_code);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dhcpv6_options_col_type);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dhcpv6_options_col_name);
    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_address_set);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_address_set_col_name);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_address_set_col_addresses);
    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_port_group);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_group_col_name);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_group_col_ports);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_dns);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dns_col_datapaths);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dns_col_records);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dns_col_external_ids);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_rbac_role);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_rbac_role_col_name);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_rbac_role_col_permissions);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_rbac_permission);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_rbac_permission_col_table);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_rbac_permission_col_authorization);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_rbac_permission_col_insert_delete);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_rbac_permission_col_update);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_meter);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_meter_col_name);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_meter_col_unit);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_meter_col_bands);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_meter_band);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_meter_band_col_action);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_meter_band_col_rate);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_meter_band_col_burst_size);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_chassis);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_chassis_col_name);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_chassis_col_other_config);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_chassis_col_encaps);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_encap);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_encap_col_type);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_chassis_private);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_chassis_private_col_name);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_chassis_private_col_chassis);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_chassis_private_col_nb_cfg);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_chassis_private_col_nb_cfg_timestamp);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_ha_chassis);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ha_chassis_col_chassis);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ha_chassis_col_priority);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ha_chassis_col_external_ids);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_ha_chassis_group);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ha_chassis_group_col_name);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ha_chassis_group_col_ha_chassis);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ha_chassis_group_col_external_ids);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ha_chassis_group_col_ref_chassis);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_igmp_group);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_igmp_group_col_address);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_igmp_group_col_datapath);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_igmp_group_col_chassis);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_igmp_group_col_ports);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_ip_multicast);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ip_multicast_col_datapath);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ip_multicast_col_enabled);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ip_multicast_col_querier);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ip_multicast_col_eth_src);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ip_multicast_col_ip4_src);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ip_multicast_col_ip6_src);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ip_multicast_col_table_size);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ip_multicast_col_idle_timeout);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ip_multicast_col_query_interval);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_ip_multicast_col_query_max_resp);
    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_service_monitor);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_service_monitor_col_ip);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_service_monitor_col_logical_port);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_service_monitor_col_port);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_service_monitor_col_options);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_service_monitor_col_status);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_service_monitor_col_protocol);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_service_monitor_col_src_mac);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_service_monitor_col_src_ip);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_service_monitor_col_external_ids);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_load_balancer);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_load_balancer_col_datapaths);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_load_balancer_col_name);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_load_balancer_col_vips);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_load_balancer_col_protocol);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_load_balancer_col_options);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_load_balancer_col_external_ids);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_bfd);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_bfd_col_logical_port);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_bfd_col_dst_ip);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_bfd_col_status);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_bfd_col_min_tx);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_bfd_col_min_rx);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_bfd_col_detect_mult);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_bfd_col_disc);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_bfd_col_src_port);

    struct ovsdb_idl_index *sbrec_chassis_by_name
        = chassis_index_create(ovnsb_idl_loop.idl);

    struct ovsdb_idl_index *sbrec_ha_chassis_grp_by_name
        = ha_chassis_group_index_create(ovnsb_idl_loop.idl);

    struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp
        = mcast_group_index_create(ovnsb_idl_loop.idl);

    struct ovsdb_idl_index *sbrec_ip_mcast_by_dp
        = ip_mcast_index_create(ovnsb_idl_loop.idl);

    unixctl_command_register("sb-connection-status", "", 0, 0,
                             ovn_conn_show, ovnsb_idl_loop.idl);

    char *ovn_internal_version = ovn_get_internal_version();
    VLOG_INFO("OVN internal version is : [%s]", ovn_internal_version);

    /* Main loop. */
    exiting = false;
    state.had_lock = false;
    state.paused = false;
    while (!exiting) {
        memory_run();
        if (memory_should_report()) {
            struct simap usage = SIMAP_INITIALIZER(&usage);

            /* Nothing special to report yet. */
            memory_report(&usage);
            simap_destroy(&usage);
        }

        if (!state.paused) {
            if (!ovsdb_idl_has_lock(ovnsb_idl_loop.idl) &&
                !ovsdb_idl_is_lock_contended(ovnsb_idl_loop.idl))
            {
                /* Ensure that only a single ovn-northd is active in the
                 * deployment by acquiring a lock called "ovn_northd" on the
                 * southbound database and then only performing DB transactions
                 * if the lock is held.
                 */
                ovsdb_idl_set_lock(ovnsb_idl_loop.idl, "ovn_northd");
            }

            struct northd_context ctx = {
                .ovnnb_idl = ovnnb_idl_loop.idl,
                .ovnnb_txn = ovsdb_idl_loop_run(&ovnnb_idl_loop),
                .ovnsb_idl = ovnsb_idl_loop.idl,
                .ovnsb_txn = ovsdb_idl_loop_run(&ovnsb_idl_loop),
                .sbrec_chassis_by_name = sbrec_chassis_by_name,
                .sbrec_ha_chassis_grp_by_name = sbrec_ha_chassis_grp_by_name,
                .sbrec_mcast_group_by_name_dp = sbrec_mcast_group_by_name_dp,
                .sbrec_ip_mcast_by_dp = sbrec_ip_mcast_by_dp,
            };

            if (!state.had_lock && ovsdb_idl_has_lock(ovnsb_idl_loop.idl)) {
                VLOG_INFO("ovn-northd lock acquired. "
                        "This ovn-northd instance is now active.");
                state.had_lock = true;
            } else if (state.had_lock &&
                       !ovsdb_idl_has_lock(ovnsb_idl_loop.idl))
            {
                VLOG_INFO("ovn-northd lock lost. "
                        "This ovn-northd instance is now on standby.");
                state.had_lock = false;
            }

            if (ovsdb_idl_has_lock(ovnsb_idl_loop.idl)) {
                ovn_db_run(&ctx, sbrec_chassis_by_name, &ovnsb_idl_loop,
                           ovn_internal_version);
                if (ctx.ovnsb_txn) {
                    check_and_add_supported_dhcp_opts_to_sb_db(&ctx);
                    check_and_add_supported_dhcpv6_opts_to_sb_db(&ctx);
                    check_and_update_rbac(&ctx);
                }
            }

            ovsdb_idl_loop_commit_and_wait(&ovnnb_idl_loop);
            ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);
        } else {
            /* ovn-northd is paused
             *    - we still want to handle any db updates and update the
             *      local IDL. Otherwise, when it is resumed, the local IDL
             *      copy will be out of sync.
             *    - but we don't want to create any txns.
             * */
            if (ovsdb_idl_has_lock(ovnsb_idl_loop.idl) ||
                ovsdb_idl_is_lock_contended(ovnsb_idl_loop.idl))
            {
                /* make sure we don't hold the lock while paused */
                VLOG_INFO("This ovn-northd instance is now paused.");
                ovsdb_idl_set_lock(ovnsb_idl_loop.idl, NULL);
                state.had_lock = false;
            }

            ovsdb_idl_run(ovnnb_idl_loop.idl);
            ovsdb_idl_run(ovnsb_idl_loop.idl);
            ovsdb_idl_wait(ovnnb_idl_loop.idl);
            ovsdb_idl_wait(ovnsb_idl_loop.idl);
        }

        unixctl_server_run(unixctl);
        unixctl_server_wait(unixctl);
        memory_wait();
        if (exiting) {
            poll_immediate_wake();
        }


        ovsdb_idl_set_probe_interval(ovnnb_idl_loop.idl,
                                     northd_probe_interval_nb);
        ovsdb_idl_set_probe_interval(ovnsb_idl_loop.idl,
                                     northd_probe_interval_sb);

        if (reset_ovnsb_idl_min_index) {
            VLOG_INFO("Resetting southbound database cluster state");
            ovsdb_idl_reset_min_index(ovnsb_idl_loop.idl);
            reset_ovnsb_idl_min_index = false;
        }

        if (reset_ovnnb_idl_min_index) {
            VLOG_INFO("Resetting northbound database cluster state");
            ovsdb_idl_reset_min_index(ovnnb_idl_loop.idl);
            reset_ovnnb_idl_min_index = false;
        }

        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
    }


    free(ovn_internal_version);
    unixctl_server_destroy(unixctl);
    ovsdb_idl_loop_destroy(&ovnnb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);
    service_stop();

    exit(res);
}

static void
ovn_northd_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_northd_pause(struct unixctl_conn *conn, int argc OVS_UNUSED,
                const char *argv[] OVS_UNUSED, void *state_)
{
    struct northd_state  *state = state_;
    state->paused = true;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_northd_resume(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *state_)
{
    struct northd_state *state = state_;
    state->paused = false;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_northd_is_paused(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *state_)
{
    struct northd_state *state = state_;
    if (state->paused) {
        unixctl_command_reply(conn, "true");
    } else {
        unixctl_command_reply(conn, "false");
    }
}

static void
ovn_northd_status(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *state_)
{
    struct northd_state *state = state_;
    char *status;

    if (state->paused) {
        status = "paused";
    } else {
        status = state->had_lock ? "active" : "standby";
    }

    /*
     * Use a labelled formatted output so we can add more to the status command
     * later without breaking any consuming scripts
     */
    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "Status: %s\n", status);
    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}

static void
cluster_state_reset_cmd(struct unixctl_conn *conn, int argc OVS_UNUSED,
               const char *argv[] OVS_UNUSED, void *idl_reset_)
{
    bool *idl_reset = idl_reset_;

    *idl_reset = true;
    poll_immediate_wake();
    unixctl_command_reply(conn, NULL);
}
