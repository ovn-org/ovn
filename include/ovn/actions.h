/*
 * Copyright (c) 2015, 2016, 2017 Nicira, Inc.
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

#ifndef OVN_ACTIONS_H
#define OVN_ACTIONS_H 1

#include <stdbool.h>
#include <stdint.h>
#include "compiler.h"
#include "expr.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/uuid.h"
#include "util.h"
#include "ovn/features.h"

struct expr;
struct lexer;
struct ofpbuf;
struct shash;
struct simap;
struct ovn_extend_table;
struct collector_set_ids;

/* List of OVN logical actions.
 *
 * This macro is used directly only internally by this header and its
 * corresponding .c file, but the list is still of interest to developers.
 *
 * Each OVNACT invocation has the following parameters:
 *
 * 1. <ENUM>, used below in the enum definition of OVNACT_<ENUM>, and
 *    elsewhere.
 *
 * 2. <STRUCT> corresponding to a structure "struct <STRUCT>", that must be a
 *    defined below.  This structure must be an abstract definition of the
 *    action.  Its first member must have type "struct ovnact" and name
 *    "ovnact".  The structure must have a fixed length, that is, it may not
 *    end with a flexible array member.
 *
 * These OVNACTS are used to generate the OVN internal version.   See
 * ovn_get_internal_version() in lib/ovn-util.c.  If any OVNACT is updated,
 * increment the OVN_INTERNAL_MINOR_VER macro in lib/ovn-util.c.
 */
#define OVNACTS                                       \
    OVNACT(OUTPUT,            ovnact_null)            \
    OVNACT(NEXT,              ovnact_next)            \
    OVNACT(LOAD,              ovnact_load)            \
    OVNACT(MOVE,              ovnact_move)            \
    OVNACT(PUSH,              ovnact_push_pop)        \
    OVNACT(POP,               ovnact_push_pop)        \
    OVNACT(EXCHANGE,          ovnact_move)            \
    OVNACT(DEC_TTL,           ovnact_null)            \
    OVNACT(CT_NEXT,           ovnact_ct_next)         \
    OVNACT(CT_COMMIT_V1,      ovnact_ct_commit_v1)    \
    OVNACT(CT_COMMIT_V2,      ovnact_nest)            \
    OVNACT(CT_DNAT,           ovnact_ct_nat)          \
    OVNACT(CT_SNAT,           ovnact_ct_nat)          \
    OVNACT(CT_DNAT_IN_CZONE,  ovnact_ct_nat)          \
    OVNACT(CT_SNAT_IN_CZONE,  ovnact_ct_nat)          \
    OVNACT(CT_LB,             ovnact_ct_lb)           \
    OVNACT(CT_LB_MARK,        ovnact_ct_lb)           \
    OVNACT(SELECT,            ovnact_select)          \
    OVNACT(CT_CLEAR,          ovnact_null)            \
    OVNACT(CT_COMMIT_NAT,     ovnact_ct_nat)          \
    OVNACT(CLONE,             ovnact_nest)            \
    OVNACT(ARP,               ovnact_nest)            \
    OVNACT(ICMP4,             ovnact_nest)            \
    OVNACT(ICMP4_ERROR,       ovnact_nest)            \
    OVNACT(ICMP6,             ovnact_nest)            \
    OVNACT(IGMP,              ovnact_null)            \
    OVNACT(TCP_RESET,         ovnact_nest)            \
    OVNACT(ND_NA,             ovnact_nest)            \
    OVNACT(ND_NA_ROUTER,      ovnact_nest)            \
    OVNACT(GET_ARP,           ovnact_get_mac_bind)    \
    OVNACT(PUT_ARP,           ovnact_put_mac_bind)    \
    OVNACT(LOOKUP_ARP,        ovnact_lookup_mac_bind) \
    OVNACT(LOOKUP_ARP_IP,     ovnact_lookup_mac_bind_ip) \
    OVNACT(GET_ND,            ovnact_get_mac_bind)    \
    OVNACT(PUT_ND,            ovnact_put_mac_bind)    \
    OVNACT(LOOKUP_ND,         ovnact_lookup_mac_bind) \
    OVNACT(LOOKUP_ND_IP,      ovnact_lookup_mac_bind_ip) \
    OVNACT(PUT_DHCPV4_OPTS,   ovnact_put_opts)        \
    OVNACT(PUT_DHCPV6_OPTS,   ovnact_put_opts)        \
    OVNACT(SET_QUEUE,         ovnact_set_queue)       \
    OVNACT(DNS_LOOKUP,        ovnact_result)          \
    OVNACT(LOG,               ovnact_log)             \
    OVNACT(PUT_ND_RA_OPTS,    ovnact_put_opts)        \
    OVNACT(ND_NS,             ovnact_nest)            \
    OVNACT(SET_METER,         ovnact_set_meter)       \
    OVNACT(OVNFIELD_LOAD,     ovnact_load)            \
    OVNACT(CHECK_PKT_LARGER,  ovnact_check_pkt_larger) \
    OVNACT(TRIGGER_EVENT,     ovnact_controller_event) \
    OVNACT(BIND_VPORT,        ovnact_bind_vport)       \
    OVNACT(HANDLE_SVC_CHECK,  ovnact_handle_svc_check) \
    OVNACT(FWD_GROUP,         ovnact_fwd_group)       \
    OVNACT(DHCP6_REPLY,       ovnact_null)            \
    OVNACT(ICMP6_ERROR,       ovnact_nest)            \
    OVNACT(REJECT,            ovnact_nest)            \
    OVNACT(CHK_LB_HAIRPIN,    ovnact_result)          \
    OVNACT(CHK_LB_HAIRPIN_REPLY, ovnact_result)       \
    OVNACT(CT_SNAT_TO_VIP,    ovnact_null)            \
    OVNACT(BFD_MSG,           ovnact_null)            \
    OVNACT(SCTP_ABORT,        ovnact_nest)            \
    OVNACT(PUT_FDB,           ovnact_put_fdb)         \
    OVNACT(GET_FDB,           ovnact_get_fdb)         \
    OVNACT(LOOKUP_FDB,        ovnact_lookup_fdb)      \
    OVNACT(CHECK_IN_PORT_SEC,  ovnact_result)         \
    OVNACT(CHECK_OUT_PORT_SEC, ovnact_result)         \
    OVNACT(COMMIT_ECMP_NH,    ovnact_commit_ecmp_nh)  \
    OVNACT(CHK_ECMP_NH_MAC,   ovnact_result)          \
    OVNACT(CHK_ECMP_NH,       ovnact_result)          \
    OVNACT(COMMIT_LB_AFF,     ovnact_commit_lb_aff)   \
    OVNACT(CHK_LB_AFF,        ovnact_result)          \
    OVNACT(SAMPLE,            ovnact_sample)          \
    OVNACT(MAC_CACHE_USE,     ovnact_null)            \

/* enum ovnact_type, with a member OVNACT_<ENUM> for each action. */
enum OVS_PACKED_ENUM ovnact_type {
#define OVNACT(ENUM, STRUCT) OVNACT_##ENUM,
    OVNACTS
#undef OVNACT
};

/* Define N_OVNACTS to the number of types of ovnacts. */
enum {
#define OVNACT(ENUM, STRUCT) + 1
    N_OVNACTS = OVNACTS
#undef OVNACT
};

/* Header for an action.
 *
 * Each action is a structure "struct ovnact_*" that begins with "struct
 * ovnact", usually followed by other data that describes the action.  Actions
 * are padded out to a multiple of OVNACT_ALIGNTO bytes in length.
 */
struct ovnact {
    /* We want the space advantage of an 8-bit type here on every
     * implementation, without giving up the advantage of having a useful type
     * on implementations that support packed enums. */
#ifdef HAVE_PACKED_ENUM
    enum ovnact_type type;      /* OVNACT_*. */
#else
    uint8_t type;               /* OVNACT_* */
#endif
    uint8_t pad;                /* Pad to multiple of 16 bits. */

    uint16_t len;               /* Length of the action, in bytes, including
                                 * struct ovnact, excluding padding. */
};
BUILD_ASSERT_DECL(sizeof(struct ovnact) == 4);

/* Alignment. */
#define OVNACT_ALIGNTO 8
#define OVNACT_ALIGN(SIZE) ROUND_UP(SIZE, OVNACT_ALIGNTO)

/* Returns the ovnact following 'ovnact'. */
static inline struct ovnact *
ovnact_next(const struct ovnact *ovnact)
{
    return (void *) ((uint8_t *) ovnact + OVNACT_ALIGN(ovnact->len));
}

struct ovnact *ovnact_next_flattened(const struct ovnact *);

static inline struct ovnact *
ovnact_end(const struct ovnact *ovnacts, size_t ovnacts_len)
{
    return (void *) ((uint8_t *) ovnacts + ovnacts_len);
}

/* Assigns POS to each ovnact, in turn, in the OVNACTS_LEN bytes of ovnacts
 * starting at OVNACTS. */
#define OVNACT_FOR_EACH(POS, OVNACTS, OVNACTS_LEN)                      \
    for ((POS) = (OVNACTS); (POS) < ovnact_end(OVNACTS, OVNACTS_LEN);  \
         (POS) = ovnact_next(POS))

static inline int
ovnacts_count(const struct ovnact *ovnacts, size_t ovnacts_len)
{
    uint8_t n_ovnacts = 0;
    if (ovnacts) {
        const struct ovnact *a;

        OVNACT_FOR_EACH (a, ovnacts, ovnacts_len) {
            n_ovnacts++;
        }
    }
    return n_ovnacts;
}

/* Action structure for each OVNACT_*. */

/* Action structure for actions that do not have any extra data beyond the
 * action type. */
struct ovnact_null {
    struct ovnact ovnact;
};

/* Logical pipeline in which a set of actions is executed. */
enum ovnact_pipeline {
    OVNACT_P_INGRESS,
    OVNACT_P_EGRESS,
};

/* OVNACT_NEXT. */
struct ovnact_next {
    struct ovnact ovnact;

    /* Arguments. */
    uint8_t ltable;                /* Logical table ID of next table. */
    enum ovnact_pipeline pipeline; /* Pipeline of next table. */

    /* Information about the flow that the action is in.  This does not affect
     * behavior, since the implementation of "next" doesn't depend on the
     * source table or pipeline.  It does affect how ovnacts_format() prints
     * the action. */
    uint8_t src_ltable;                /* Logical table ID of source table. */
    enum ovnact_pipeline src_pipeline; /* Pipeline of source table. */
};

/* OVNACT_LOAD. */
struct ovnact_load {
    struct ovnact ovnact;
    struct expr_field dst;
    union expr_constant imm;
};

/* OVNACT_MOVE, OVNACT_EXCHANGE. */
struct ovnact_move {
    struct ovnact ovnact;
    struct expr_field lhs;
    struct expr_field rhs;
};

/* OVNACT_PUSH, OVNACT_POP. */
struct ovnact_push_pop {
    struct ovnact ovnact;
    struct expr_field field;
};

/* OVNACT_CT_NEXT. */
struct ovnact_ct_next {
    struct ovnact ovnact;
    uint8_t ltable;                /* Logical table ID of next table. */
};

/* OVNACT_CT_COMMIT_V1. */
struct ovnact_ct_commit_v1 {
    struct ovnact ovnact;
    uint32_t ct_mark, ct_mark_mask;
    ovs_be128 ct_label, ct_label_mask;
};

/* Type of NAT used for the particular action.
 * UNSPEC translates to applying NAT that works for both directions. */
enum ovnact_ct_nat_type {
    OVNACT_CT_NAT_SRC,
    OVNACT_CT_NAT_DEST,
    OVNACT_CT_NAT_UNSPEC,
};

/* OVNACT_CT_DNAT, OVNACT_CT_SNAT, OVNACT_CT_COMMIT_NAT. */
struct ovnact_ct_nat {
    struct ovnact ovnact;
    int family;
    union {
        struct in6_addr ipv6;
        ovs_be32 ipv4;
    };

    struct {
       bool exists;
       uint16_t port_lo;
       uint16_t port_hi;
    } port_range;

    enum ovnact_ct_nat_type type;

    bool commit;                /* Explicit commit action. */

    uint8_t ltable;             /* Logical table ID of next table. */
};

enum ovnact_ct_lb_flag {
    OVNACT_CT_LB_FLAG_NONE,
    OVNACT_CT_LB_FLAG_SKIP_SNAT,
    OVNACT_CT_LB_FLAG_FORCE_SNAT,
};

struct ovnact_ct_lb_dst {
    int family;
    union {
        struct in6_addr ipv6;
        ovs_be32 ipv4;
    };
    uint16_t port;
};

/* OVNACT_CT_LB/OVNACT_CT_LB_MARK. */
struct ovnact_ct_lb {
    struct ovnact ovnact;
    struct ovnact_ct_lb_dst *dsts;
    size_t n_dsts;
    uint8_t ltable;             /* Logical table ID of next table. */
    char *hash_fields;
    enum ovnact_ct_lb_flag ct_flag;
};

struct ovnact_select_dst {
    uint16_t id;
    uint16_t weight;
};

/* OVNACT_SELECT. */
struct ovnact_select {
    struct ovnact ovnact;
    struct ovnact_select_dst *dsts;
    size_t n_dsts;
    uint8_t ltable;             /* Logical table ID of next table. */
    struct expr_field res_field;
};

/* OVNACT_ARP, OVNACT_ND_NA, OVNACT_CLONE. */
struct ovnact_nest {
    struct ovnact ovnact;
    struct ovnact *nested;
    size_t nested_len;
};

/* OVNACT_GET_ARP, OVNACT_GET_ND. */
struct ovnact_get_mac_bind {
    struct ovnact ovnact;
    struct expr_field port;     /* Logical port name. */
    struct expr_field ip;       /* 32-bit or 128-bit IP address. */
};

/* OVNACT_PUT_ARP, ONVACT_PUT_ND. */
struct ovnact_put_mac_bind {
    struct ovnact ovnact;
    struct expr_field port;     /* Logical port name. */
    struct expr_field ip;       /* 32-bit or 128-bit IP address. */
    struct expr_field mac;      /* 48-bit Ethernet address. */
};

/* OVNACT_LOOKUP_ARP, OVNACT_LOOKUP_ND. */
struct ovnact_lookup_mac_bind {
    struct ovnact ovnact;
    struct expr_field dst;      /* 1-bit destination field. */
    struct expr_field port;     /* Logical port name. */
    struct expr_field ip;       /* 32-bit or 128-bit IP address. */
    struct expr_field mac;      /* 48-bit Ethernet address. */
};

/* OVNACT_LOOKUP_ARP_IP, OVNACT_LOOKUP_ND_IP. */
struct ovnact_lookup_mac_bind_ip {
    struct ovnact ovnact;
    struct expr_field dst;      /* 1-bit destination field. */
    struct expr_field port;     /* Logical port name. */
    struct expr_field ip;       /* 32-bit or 128-bit IP address. */
};

struct ovnact_gen_option {
    const struct gen_opts_map *option;
    struct expr_constant_set value;
};

/* OVNACT_PUT_DHCPV4_OPTS, OVNACT_PUT_DHCPV6_OPTS. */
struct ovnact_put_opts {
    struct ovnact ovnact;
    struct expr_field dst;      /* 1-bit destination field. */
    struct ovnact_gen_option *options;
    size_t n_options;
};

/* Valid arguments to SET_QUEUE action.
 *
 * QDISC_MIN_QUEUE_ID is the default queue, so user-defined queues should
 * start at QDISC_MIN_QUEUE_ID+1. */
#define QDISC_MIN_QUEUE_ID  0
#define QDISC_MAX_QUEUE_ID  0xf000

/* OVNACT_SET_QUEUE. */
struct ovnact_set_queue {
    struct ovnact ovnact;
    uint16_t queue_id;
};

/* OVNACT_DNS_LOOKUP, OVNACT_CHK_LB_HAIRPIN, OVNACT_CHK_LB_HAIRPIN_REPLY. */
struct ovnact_result {
    struct ovnact ovnact;
    struct expr_field dst;      /* 1-bit destination field. */
};

/* OVNACT_LOG. */
struct ovnact_log {
    struct ovnact ovnact;
    uint8_t verdict;            /* One of LOG_VERDICT_*. */
    uint8_t severity;           /* One of LOG_SEVERITY_*. */
    char *name;
    char *meter;
};

/* OVNACT_SET_METER. */
struct ovnact_set_meter {
    struct ovnact ovnact;
    uint64_t rate;                   /* rate field, in kbps. */
    uint64_t burst;                  /* burst rate field, in kbps. */
};

/* OVNACT_CHECK_IP_PKT_LARGER. */
struct ovnact_check_pkt_larger {
    struct ovnact ovnact;
    uint16_t pkt_len;
    struct expr_field dst;      /* 1-bit destination field. */
};

/* OVNACT_EVENT. */
struct ovnact_controller_event {
    struct ovnact ovnact;
    int event_type;   /* controller event type */
    struct ovnact_gen_option *options;
    size_t n_options;
};

/* OVNACT_BIND_VPORT. */
struct ovnact_bind_vport {
    struct ovnact ovnact;
    char *vport;
    struct expr_field vport_parent;     /* Logical virtual port's port name. */
};

/* OVNACT_HANDLE_SVC_CHECK. */
struct ovnact_handle_svc_check {
    struct ovnact ovnact;
    struct expr_field port;     /* Logical port name. */
};

/* OVNACT_FWD_GROUP. */
struct ovnact_fwd_group {
    struct ovnact ovnact;
    bool liveness;
    char **child_ports;       /* Logical ports */
    size_t n_child_ports;
    uint8_t ltable;           /* Logical table ID of next table. */
};

/* OVNACT_PUT_FDB. */
struct ovnact_put_fdb {
    struct ovnact ovnact;
    struct expr_field port;     /* Logical port name. */
    struct expr_field mac;      /* 48-bit Ethernet address. */
};

/* OVNACT_GET_FDB. */
struct ovnact_get_fdb {
    struct ovnact ovnact;
    struct expr_field mac;     /* 48-bit Ethernet address. */
    struct expr_field dst;     /* 32-bit destination field. */
};

/* OVNACT_LOOKUP_FDB. */
struct ovnact_lookup_fdb {
    struct ovnact ovnact;
    struct expr_field mac;     /* 48-bit Ethernet address. */
    struct expr_field port;    /* Logical port name. */
    struct expr_field dst;     /* 1-bit destination field. */
};

/* OVNACT_SAMPLE */
struct ovnact_sample {
    struct ovnact ovnact;
    uint16_t probability;       /* probability over UINT16_MAX. */
    uint8_t obs_domain_id;      /* most significant byte of the
                                   observation domain id. The other 24 bits
                                   will come from the datapath's tunnel key. */
    uint32_t collector_set_id;  /* colector_set_id. */
    uint32_t obs_point_id;      /* observation point id. */
    bool use_cookie;            /* use cookie as obs_point_id */
};

/* OVNACT_COMMIT_ECMP_NH. */
struct ovnact_commit_ecmp_nh {
    struct ovnact ovnact;
    bool ipv6;
    uint8_t proto;
};

/* OVNACT_COMMIT_LB_AFF. */
struct ovnact_commit_lb_aff {
    struct ovnact ovnact;

    struct in6_addr vip;
    uint16_t vip_port;
    uint8_t proto;

    struct in6_addr backend;
    uint16_t backend_port;

    uint16_t timeout;
};

/* Internal use by the helpers below. */
void ovnact_init(struct ovnact *, enum ovnact_type, size_t len);
void *ovnact_put(struct ofpbuf *, enum ovnact_type, size_t len);

/* For each OVNACT_<ENUM> with a corresponding struct <STRUCT>, this defines
 * the following commonly useful functions:
 *
 *   struct <STRUCT> *ovnact_put_<ENUM>(struct ofpbuf *ovnacts);
 *
 *     Appends a new 'ovnact', of length OVNACT_<ENUM>_SIZE, to 'ovnacts',
 *     initializes it with ovnact_init_<ENUM>(), and returns it.  Also sets
 *     'ovnacts->header' to the returned action.
 *
 *   struct <STRUCT> *ovnact_get_<ENUM>(const struct ovnact *ovnact);
 *
 *     Returns 'ovnact' cast to "struct <STRUCT> *".  'ovnact->type' must be
 *     OVNACT_<ENUM>.
 *
 * as well as the following more rarely useful definitions:
 *
 *   void ovnact_init_<ENUM>(struct <STRUCT> *ovnact);
 *
 *     Initializes the parts of 'ovnact' that identify it as having type
 *     OVNACT_<ENUM> and length OVNACT_<ENUM>_SIZE and zeros the rest.
 *
 *   <ENUM>_SIZE
 *
 *     The size of the action structure, that is, sizeof(struct <STRUCT>)
 *     rounded up to a multiple of OVNACT_ALIGNTO.
 */
#define OVNACT(ENUM, STRUCT)                                            \
    BUILD_ASSERT_DECL(offsetof(struct STRUCT, ovnact) == 0);            \
                                                                        \
    enum { OVNACT_##ENUM##_SIZE = OVNACT_ALIGN(sizeof(struct STRUCT)) }; \
                                                                        \
    static inline struct STRUCT *                                       \
    ovnact_get_##ENUM(const struct ovnact *ovnact)                      \
    {                                                                   \
        ovs_assert(ovnact->type == OVNACT_##ENUM);                      \
        return ALIGNED_CAST(struct STRUCT *, ovnact);                   \
    }                                                                   \
                                                                        \
    static inline struct STRUCT *                                       \
    ovnact_put_##ENUM(struct ofpbuf *ovnacts)                           \
    {                                                                   \
        return ovnact_put(ovnacts, OVNACT_##ENUM,                       \
                          OVNACT_##ENUM##_SIZE);                        \
    }                                                                   \
                                                                        \
    static inline void                                                  \
    ovnact_init_##ENUM(struct STRUCT *ovnact)                           \
    {                                                                   \
        ovnact_init(&ovnact->ovnact, OVNACT_##ENUM,                     \
                    OVNACT_##ENUM##_SIZE);                              \
    }
OVNACTS
#undef OVNACT

enum action_opcode {
    /* "arp { ...actions... }".
     *
     * The actions, in OpenFlow 1.3 format, follow the action_header.
     */
    ACTION_OPCODE_ARP,

    /* "put_arp(port, ip, mac)"
     *
     * Arguments are passed through the packet metadata and data, as follows:
     *
     *     MFF_REG0 = ip
     *     MFF_LOG_INPORT = port
     *     MFF_ETH_SRC = mac
     */
    ACTION_OPCODE_PUT_ARP,

    /* "result = put_dhcp_opts(offer_ip, option, ...)".
     *
     * Arguments follow the action_header, in this format:
     *   - A 32-bit or 64-bit OXM header designating the result field.
     *   - A 32-bit integer specifying a bit offset within the result field.
     *   - The 32-bit DHCP offer IP.
     *   - Any number of DHCP options.
     */
    ACTION_OPCODE_PUT_DHCP_OPTS,

    /* "nd_na { ...actions... }".
     *
     * The actions, in OpenFlow 1.3 format, follow the action_header.
     */
    ACTION_OPCODE_ND_NA,

    /* "put_nd(port, ip6, mac)"
     *
     * Arguments are passed through the packet metadata and data, as follows:
     *
     *     MFF_XXREG0 = ip6
     *     MFF_LOG_INPORT = port
     *     MFF_ETH_SRC = mac
     */
    ACTION_OPCODE_PUT_ND,

    /* "result = put_dhcpv6_opts(option, ...)".
     *
     * Arguments follow the action_header, in this format:
     *   - A 32-bit or 64-bit OXM header designating the result field.
     *   - A 32-bit integer specifying a bit offset within the result field.
     *   - Any number of DHCPv6 options.
     */
    ACTION_OPCODE_PUT_DHCPV6_OPTS,

    /* "result = dns_lookup()".
     * Arguments follow the action_header, in this format:
     *   - A 32-bit or 64-bit OXM header designating the result field.
     *   - A 32-bit integer specifying a bit offset within the result field.
     *
     */
    ACTION_OPCODE_DNS_LOOKUP,

    /* "log(arguments)".
     *
     * Arguments are as follows:
     *   - An 8-bit verdict.
     *   - An 8-bit severity.
     *   - A variable length string containing the name.
     */
    ACTION_OPCODE_LOG,

    /* "result = put_nd_ra_opts(option, ...)".
     * Arguments follow the action_header, in this format:
     *   - A 32-bit or 64-bit OXM header designating the result field.
     *   - A 32-bit integer specifying a bit offset within the result field.
     *   - Any number of ICMPv6 options.
     */
    ACTION_OPCODE_PUT_ND_RA_OPTS,

    /* "nd_ns { ...actions... }".
     *
     * The actions, in OpenFlow 1.3 format, follow the action_header.
     */
    ACTION_OPCODE_ND_NS,

    /* "icmp4 { ...actions... } and icmp6 { ...actions... }".
     *
     * The actions, in OpenFlow 1.3 format, follow the action_header.
     */
    ACTION_OPCODE_ICMP,

    /* "tcp_reset { ...actions... }".
     *
     * The actions, in OpenFlow 1.3 format, follow the action_header.
     */
    ACTION_OPCODE_TCP_RESET,

    /* "nd_na_router { ...actions... }" with rso flag 'ND_RSO_ROUTER' set.
        *
        * The actions, in OpenFlow 1.3 format, follow the action_header.
        */
    ACTION_OPCODE_ND_NA_ROUTER,

     /* MTU value (to put in the icmp4 header field - frag_mtu) follow the
     * action header. */
    ACTION_OPCODE_PUT_ICMP4_FRAG_MTU,

    /* "icmp4_error { ...actions... }".
     *
     * The actions, in OpenFlow 1.3 format, follow the action_header.
     */
    ACTION_OPCODE_ICMP4_ERROR,

    /* "trigger_event (event_type)" */
    ACTION_OPCODE_EVENT,

    /* "igmp".
     *
     * Snoop IGMP, learn the multicast participants
     */
    ACTION_OPCODE_IGMP,

    /* "bind_vport(vport, vport_parent)".
     *
     *   'vport' follows the action_header, in the format - 32-bit field.
     *   'vport_parent' is passed through the packet metadata as
     *    MFF_LOG_INPORT.
     */
    ACTION_OPCODE_BIND_VPORT,

    /* "handle_svc_check(port)"."
     *
     * Arguments are passed through the packet metadata and data, as follows:
     *
     *     MFF_LOG_INPORT = port
     */
    ACTION_OPCODE_HANDLE_SVC_CHECK,
    /* handle_dhcpv6_reply { ...actions ...}."
     *
     *  The actions, in OpenFlow 1.3 format, follow the action_header.
     */
    ACTION_OPCODE_DHCP6_SERVER,

    /* "icmp6_error { ...actions... }".
     *
     * The actions, in OpenFlow 1.3 format, follow the action_header.
     */
    ACTION_OPCODE_ICMP6_ERROR,

    /* MTU value (to put in the icmp6 header field - frag_mtu) follow the
     * action header. */
    ACTION_OPCODE_PUT_ICMP6_FRAG_MTU,

    /* "reject { ...actions... }".
     *
     * The actions, in OpenFlow 1.3 format, follow the action_header.
     */
    ACTION_OPCODE_REJECT,

    /* handle_bfd_msg { ...actions ...}."
     *
     *  The actions, in OpenFlow 1.3 format, follow the action_header.
     */
    ACTION_OPCODE_BFD_MSG,

    /* "sctp_abort { ...actions... }".
     *
     * The actions, in OpenFlow 1.3 format, follow the action_header.
     */
    ACTION_OPCODE_SCTP_ABORT,

    /* put_fdb(inport, eth.src).
     */
    ACTION_OPCODE_PUT_FDB,

    /* activation_strategy_rarp() */
    ACTION_OPCODE_ACTIVATION_STRATEGY_RARP,

    /* multicast group split buffer action. */
    ACTION_OPCODE_MG_SPLIT_BUF,
};

/* Header. */
struct action_header {
    ovs_be32 opcode;            /* One of ACTION_OPCODE_* */
    uint8_t pad[4];
};
BUILD_ASSERT_DECL(sizeof(struct action_header) == 8);

struct ovnact_parse_params {
    /* A table of "struct expr_symbol"s to support (as one would provide to
     * expr_parse()). */
    const struct shash *symtab;

    /* hmap of 'struct gen_opts_map' to support 'put_dhcp_opts' action */
    const struct hmap *dhcp_opts;

    /* hmap of 'struct gen_opts_map'  to support 'put_dhcpv6_opts' action */
    const struct hmap *dhcpv6_opts;

    /* hmap of 'struct gen_opts_map' to support 'put_nd_ra_opts' action */
    const struct hmap *nd_ra_opts;

    /* Array of hmap of 'struct gen_opts_map' to support 'trigger_event'
     * action */
    const struct controller_event_options *controller_event_opts;

    /* Each OVN flow exists in a logical table within a logical pipeline.
     * These parameters express this context for a set of OVN actions being
     * parsed:
     *
     *     - 'n_tables' is the number of tables in the logical ingress and
     *        egress pipelines, that is, "next" may specify a table less than
     *        or equal to 'n_tables'.  If 'n_tables' is 0 then "next" is
     *        disallowed entirely.
     *
     *     - 'cur_ltable' is the logical table of the current flow, within
     *       'pipeline'.  If cur_ltable + 1 < n_tables, then this defines the
     *       default table that "next" will jump to.
     *
     *     - 'pipeline' is the logical pipeline.  It is the default pipeline to
     *       which 'next' will jump.  If 'pipeline' is OVNACT_P_EGRESS, then
     *       'next' will also be able to jump into the ingress pipeline, but
     *       the reverse is not true. */
    enum ovnact_pipeline pipeline; /* Logical pipeline. */
    uint8_t n_tables;              /* Number of logical flow tables. */
    uint8_t cur_ltable;            /* 0 <= cur_ltable < n_tables. */
};

bool ovnacts_parse(struct lexer *, const struct ovnact_parse_params *,
                    struct ofpbuf *ovnacts, struct expr **prereqsp);
char *ovnacts_parse_string(const char *s, const struct ovnact_parse_params *,
                           struct ofpbuf *ovnacts, struct expr **prereqsp)
    OVS_WARN_UNUSED_RESULT;

void ovnacts_format(const struct ovnact[], size_t ovnacts_len, struct ds *);

struct ovnact_encode_params {
    /* Looks up logical port 'port_name'.  If found, stores its port number in
     * '*portp' and returns true; otherwise, returns false. */
    bool (*lookup_port)(const void *aux, const char *port_name,
                        unsigned int *portp);

    /* Looks up tunnel port to a chassis by its port name.  If found, stores
     * its openflow port number in '*ofport' and returns true;
     * otherwise, returns false. */
    bool (*tunnel_ofport)(const void *aux, const char *port_name,
                          ofp_port_t *ofport);

    const void *aux;

    /* 'true' if the flow is for a switch. */
    bool is_switch;

    /* A struct to figure out the group_id for group actions. */
    struct ovn_extend_table *group_table;

    /* A struct to figure out the meter_id for meter actions. */
    struct ovn_extend_table *meter_table;

    /* A struct to lookup Flow_Sample_Collector_Set ids */
    const struct flow_collector_ids *collector_ids;

    /* The logical flow uuid that drove this action. */
    struct uuid lflow_uuid;

    /* The datapath key. */
    uint32_t dp_key;

    /* OVN maps each logical flow table (ltable), one-to-one, onto a physical
     * OpenFlow flow table (ptable).  A number of parameters describe this
     * mapping and data related to flow tables:
     *
     *     - 'pipeline' is the logical pipeline in which the actions are
     *       executing.
     *
     *     - 'ingress_ptable' is the OpenFlow table that corresponds to OVN
     *       ingress table 0.
     *
     *     - 'egress_ptable' is the OpenFlow table that corresponds to OVN
     *       egress table 0.
     *
     *     - 'output_ptable' should be the OpenFlow table to which the logical
     *       "output" action will resubmit.
     *
     *     - 'mac_bind_ptable' should be the OpenFlow table used to track MAC
     *       bindings. */
    enum ovnact_pipeline pipeline; /* Logical pipeline. */
    uint8_t ingress_ptable;     /* First OpenFlow ingress table. */
    uint8_t egress_ptable;      /* First OpenFlow egress table. */
    uint8_t output_ptable;      /* OpenFlow table for 'output' to resubmit. */
    uint8_t mac_bind_ptable;    /* OpenFlow table for 'get_arp'/'get_nd' to
                                   resubmit. */
    uint8_t mac_lookup_ptable;  /* OpenFlow table for
                                   'lookup_arp'/'lookup_nd' to resubmit. */
    uint8_t lb_hairpin_ptable;  /* OpenFlow table for
                                 * 'chk_lb_hairpin' to resubmit. */
    uint8_t lb_hairpin_reply_ptable;  /* OpenFlow table for
                                       * 'chk_lb_hairpin_reply' to resubmit. */
    uint8_t ct_snat_vip_ptable;  /* OpenFlow table for
                                  * 'ct_snat_to_vip' to resubmit. */
    uint8_t fdb_ptable; /* OpenFlow table for
                         * 'get_fdb' to resubmit. */
    uint8_t fdb_lookup_ptable; /* OpenFlow table for
                                * 'lookup_fdb' to resubmit. */
    uint8_t in_port_sec_ptable; /* OpenFlow table for
                                * 'check_in_port_sec' to resubmit. */
    uint8_t out_port_sec_ptable; /* OpenFlow table for
                                * 'check_out_port_sec' to resubmit. */
    uint32_t ctrl_meter_id;     /* Meter to be used if the resulting flow
                                   sends packets to controller. */
    uint32_t common_nat_ct_zone; /* When performing NAT in a common CT zone,
                                    this determines which CT zone to use */
    uint32_t mac_cache_use_table; /* OpenFlow table for 'mac_cache_use'
                                   * to resubmit. */
};

void ovnacts_encode(const struct ovnact[], size_t ovnacts_len,
                    const struct ovnact_encode_params *,
                    struct ofpbuf *ofpacts);

void ovnacts_free(struct ovnact[], size_t ovnacts_len);
char *ovnact_op_to_string(uint32_t);
int encode_ra_dnssl_opt(char *data, char *buf, int buf_len);

size_t encode_start_controller_op(enum action_opcode opcode, bool pause,
                                  uint32_t meter_id, struct ofpbuf *ofpacts);
void encode_finish_controller_op(size_t ofs, struct ofpbuf *ofpacts);
void encode_controller_op(enum action_opcode opcode, uint32_t meter_id,
                          struct ofpbuf *ofpacts);

#endif /* ovn/actions.h */
