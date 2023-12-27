/* Copyright (c) 2016, 2017 Nicira, Inc.
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

#include "openvswitch/shash.h"
#include "ovn/expr.h"
#include "ovn/logical-fields.h"
#include "ovs-thread.h"
#include "packets.h"

/* Silence a warning. */
extern const struct ovn_field ovn_fields[OVN_FIELD_N_IDS];

const struct ovn_field ovn_fields[OVN_FIELD_N_IDS] = {
    {
        OVN_ICMP4_FRAG_MTU,
        "icmp4.frag_mtu",
        2, 16,
    }, {
        OVN_ICMP6_FRAG_MTU,
        "icmp6.frag_mtu",
        4, 32,
    },
};

static struct shash ovnfield_by_name;

static void
add_subregister(const char *name,
                const char *parent_name, int parent_idx,
                int width, int idx,
                struct shash *symtab)
{
    int lsb = width * idx;
    int msb = lsb + (width - 1);
    char *expansion = xasprintf("%s%d[%d..%d]",
                                parent_name, parent_idx, lsb, msb);
    expr_symtab_add_subfield(symtab, name, NULL, expansion);
    free(expansion);
}

static void
add_ct_bit(const char *name, int index, struct shash *symtab)
{
    char *expansion = xasprintf("ct_state[%d]", index);
    const char *prereqs = index == CS_TRACKED_BIT ? NULL : "ct.trk";
    expr_symtab_add_subfield(symtab, name, prereqs, expansion);
    free(expansion);
}

void
ovn_init_symtab(struct shash *symtab)
{
    shash_init(symtab);

    /* Reserve a pair of registers for the logical inport and outport.  A full
     * 32-bit register each is bigger than we need, but the expression code
     * doesn't yet support string fields that occupy less than a full OXM. */
    expr_symtab_add_string(symtab, "inport", MFF_LOG_INPORT, NULL);
    expr_symtab_add_string(symtab, "outport", MFF_LOG_OUTPORT, NULL);

    /* Logical registers:
     *     128-bit xxregs
     *     64-bit xregs
     *     32-bit regs
     *
     * The expression language doesn't handle overlapping fields properly
     * unless they're formally defined as subfields.  It's a little awkward. */
    for (int xxi = 0; xxi < MFF_N_LOG_REGS / 4; xxi++) {
        char *xxname = xasprintf("xxreg%d", xxi);
        expr_symtab_add_field(symtab, xxname, MFF_XXREG0 + xxi, NULL, false);
        free(xxname);
    }
    for (int xi = 0; xi < MFF_N_LOG_REGS / 2; xi++) {
        char *xname = xasprintf("xreg%d", xi);
        int xxi = xi / 2;
        if (xxi < MFF_N_LOG_REGS / 4) {
            add_subregister(xname, "xxreg", xxi, 64, 1 - xi % 2, symtab);
        } else {
            expr_symtab_add_field(symtab, xname, MFF_XREG0 + xi, NULL, false);
        }
        free(xname);
    }
    for (int i = 0; i < MFF_N_LOG_REGS; i++) {
        char *name = xasprintf("reg%d", i);
        int xxi = i / 4;
        int xi = i / 2;
        if (xxi < MFF_N_LOG_REGS / 4) {
            add_subregister(name, "xxreg", xxi, 32, 3 - i % 4, symtab);
        } else if (xi < MFF_N_LOG_REGS / 2) {
            add_subregister(name, "xreg", xi, 32, 1 - i % 2, symtab);
        } else {
            expr_symtab_add_field(symtab, name, MFF_REG0 + i, NULL, false);
        }
        free(name);
    }

    /* Flags used in logical to physical transformation. */
    expr_symtab_add_field(symtab, "flags", MFF_LOG_FLAGS, NULL, false);
    char flags_str[16];
    snprintf(flags_str, sizeof flags_str, "flags[%d]", MLF_ALLOW_LOOPBACK_BIT);
    expr_symtab_add_subfield(symtab, "flags.loopback", NULL, flags_str);
    snprintf(flags_str, sizeof flags_str, "flags[%d]",
             MLF_FORCE_SNAT_FOR_DNAT_BIT);
    expr_symtab_add_subfield(symtab, "flags.force_snat_for_dnat", NULL,
                             flags_str);
    snprintf(flags_str, sizeof flags_str, "flags[%d]",
             MLF_FORCE_SNAT_FOR_LB_BIT);
    expr_symtab_add_subfield(symtab, "flags.force_snat_for_lb", NULL,
                             flags_str);
    snprintf(flags_str, sizeof flags_str, "flags[%d]",
             MLF_SKIP_SNAT_FOR_LB_BIT);
    expr_symtab_add_subfield(symtab, "flags.skip_snat_for_lb", NULL,
                             flags_str);
    snprintf(flags_str, sizeof flags_str, "flags[%d]",
             MLF_USE_SNAT_ZONE);
    expr_symtab_add_subfield(symtab, "flags.use_snat_zone", NULL,
                             flags_str);
    snprintf(flags_str, sizeof flags_str, "flags[%d]",
             MLF_LOCALNET_BIT);
    expr_symtab_add_subfield(symtab, "flags.localnet", NULL,
                             flags_str);

    /* Connection tracking state. */
    expr_symtab_add_field_scoped(symtab, "ct_mark", MFF_CT_MARK, NULL, false,
                                 WR_CT_COMMIT);
    expr_symtab_add_subfield_scoped(symtab, "ct_mark.blocked", NULL,
                                    "ct_mark["
                                        OVN_CT_STR(OVN_CT_BLOCKED_BIT)
                                    "]",
                                    WR_CT_COMMIT);
    expr_symtab_add_subfield_scoped(symtab, "ct_mark.natted", NULL,
                                    "ct_mark["
                                        OVN_CT_STR(OVN_CT_NATTED_BIT)
                                    "]",
                                    WR_CT_COMMIT);
    expr_symtab_add_subfield_scoped(symtab, "ct_mark.ecmp_reply_port", NULL,
                                    "ct_mark[16..31]", WR_CT_COMMIT);
    expr_symtab_add_subfield_scoped(symtab, "ct_mark.skip_snat", NULL,
                                    "ct_mark["
                                    OVN_CT_STR(OVN_CT_LB_SKIP_SNAT_BIT)
                                    "]",
                                    WR_CT_COMMIT);
    expr_symtab_add_subfield_scoped(symtab, "ct_mark.force_snat", NULL,
                                    "ct_mark["
                                    OVN_CT_STR(OVN_CT_LB_FORCE_SNAT_BIT)
                                    "]",
                                    WR_CT_COMMIT);

    expr_symtab_add_field_scoped(symtab, "ct_label", MFF_CT_LABEL, NULL,
                                 false, WR_CT_COMMIT);
    expr_symtab_add_subfield_scoped(symtab, "ct_label.blocked", NULL,
                                    "ct_label["
                                        OVN_CT_STR(OVN_CT_BLOCKED_BIT)
                                    "]",
                                    WR_CT_COMMIT);
    expr_symtab_add_subfield_scoped(symtab, "ct_label.natted", NULL,
                                    "ct_label["
                                        OVN_CT_STR(OVN_CT_NATTED_BIT)
                                    "]",
                                    WR_CT_COMMIT);
    expr_symtab_add_subfield_scoped(symtab, "ct_label.ecmp_reply_eth", NULL,
                                    "ct_label["
                                    OVN_CT_STR(OVN_CT_ECMP_ETH_1ST_BIT) ".."
                                    OVN_CT_STR(OVN_CT_ECMP_ETH_END_BIT) "]",
                                    WR_CT_COMMIT);
    expr_symtab_add_subfield_scoped(symtab, "ct_label.ecmp_reply_port", NULL,
                                    "ct_label[80..95]", WR_CT_COMMIT);
    expr_symtab_add_subfield_scoped(symtab, "ct_label.label", NULL,
                                    "ct_label[96..127]", WR_CT_COMMIT);
    expr_symtab_add_subfield_scoped(symtab, "ct_label.skip_snat", NULL,
                                    "ct_label["
                                    OVN_CT_STR(OVN_CT_LB_SKIP_SNAT_BIT)
                                    "]",
                                    WR_CT_COMMIT);
    expr_symtab_add_subfield_scoped(symtab, "ct_label.force_snat", NULL,
                                    "ct_label["
                                    OVN_CT_STR(OVN_CT_LB_FORCE_SNAT_BIT)
                                    "]",
                                    WR_CT_COMMIT);

    expr_symtab_add_field(symtab, "ct_state", MFF_CT_STATE, NULL, false);

#define CS_STATE(ENUM, INDEX, NAME) \
    add_ct_bit("ct."NAME, CS_##ENUM##_BIT, symtab);
    CS_STATES
#undef CS_STATE

    /* Data fields. */
    expr_symtab_add_field(symtab, "eth.src", MFF_ETH_SRC, NULL, false);
    expr_symtab_add_field(symtab, "eth.dst", MFF_ETH_DST, NULL, false);
    expr_symtab_add_field(symtab, "eth.type", MFF_ETH_TYPE, NULL, true);
    expr_symtab_add_predicate(symtab, "eth.bcast",
                              "eth.dst == ff:ff:ff:ff:ff:ff");
    expr_symtab_add_subfield(symtab, "eth.mcast", NULL, "eth.dst[40]");
    expr_symtab_add_predicate(symtab, "eth.mcastv6",
                              "eth.dst[32..47] == 0x3333");

    expr_symtab_add_field(symtab, "vlan.tci", MFF_VLAN_TCI, NULL, false);
    expr_symtab_add_predicate(symtab, "vlan.present", "vlan.tci[12]");
    expr_symtab_add_subfield(symtab, "vlan.pcp", "vlan.present",
                             "vlan.tci[13..15]");
    expr_symtab_add_subfield(symtab, "vlan.vid", "vlan.present",
                             "vlan.tci[0..11]");

    expr_symtab_add_predicate(symtab, "ip4", "eth.type == 0x800");
    expr_symtab_add_predicate(symtab, "ip6", "eth.type == 0x86dd");
    expr_symtab_add_predicate(symtab, "ip", "ip4 || ip6");
    expr_symtab_add_field(symtab, "ip.proto", MFF_IP_PROTO, "ip", true);
    expr_symtab_add_field(symtab, "ip.dscp", MFF_IP_DSCP_SHIFTED, "ip", false);
    expr_symtab_add_field(symtab, "ip.ecn", MFF_IP_ECN, "ip", false);
    expr_symtab_add_field(symtab, "ip.ttl", MFF_IP_TTL, "ip", false);

    expr_symtab_add_field(symtab, "ip4.src", MFF_IPV4_SRC, "ip4", false);
    expr_symtab_add_field(symtab, "ip4.dst", MFF_IPV4_DST, "ip4", false);
    expr_symtab_add_predicate(symtab, "ip4.src_mcast",
                              "ip4.src[28..31] == 0xe");
    expr_symtab_add_predicate(symtab, "ip4.mcast",
                              "eth.mcast && ip4.dst[28..31] == 0xe");

    expr_symtab_add_predicate(symtab, "icmp4", "ip4 && ip.proto == 1");
    expr_symtab_add_field(symtab, "icmp4.type", MFF_ICMPV4_TYPE, "icmp4",
              false);
    expr_symtab_add_field(symtab, "icmp4.code", MFF_ICMPV4_CODE, "icmp4",
              false);

    expr_symtab_add_predicate(symtab, "igmp", "ip4 && ip.proto == 2");

    expr_symtab_add_field(symtab, "ip6.src", MFF_IPV6_SRC, "ip6", false);
    expr_symtab_add_field(symtab, "ip6.dst", MFF_IPV6_DST, "ip6", false);
    expr_symtab_add_field(symtab, "ip6.label", MFF_IPV6_LABEL, "ip6", false);

    /* Predefined IPv6 multicast groups (RFC 4291, 2.7.1). */
    expr_symtab_add_predicate(symtab, "ip6.mcast_rsvd",
                              "ip6.dst[116..127] == 0xff0 && "
                              "ip6.dst[0..111] == 0x0");
    expr_symtab_add_predicate(symtab, "ip6.mcast_all_nodes",
                              "ip6.dst == ff01::1 || ip6.dst == ff02::1");
    expr_symtab_add_predicate(symtab, "ip6.mcast_all_rtrs",
                              "ip6.dst == ff01::2 || ip6.dst == ff02::2 || "
                              "ip6.dst == ff05::2");
    expr_symtab_add_predicate(symtab, "ip6.mcast_sol_node",
                              "ip6.dst == ff02::1:ff00:0000/104");
    expr_symtab_add_predicate(symtab, "ip6.mcast_flood",
                              "eth.mcastv6 && "
                              "(ip6.mcast_rsvd || "
                              "ip6.mcast_all_nodes || "
                              "ip6.mcast_all_rtrs || "
                              "ip6.mcast_sol_node)");

    expr_symtab_add_predicate(symtab, "ip6.mcast",
                              "eth.mcastv6 && ip6.dst[120..127] == 0xff");

    expr_symtab_add_predicate(symtab, "icmp6", "ip6 && ip.proto == 58");
    expr_symtab_add_field(symtab, "icmp6.type", MFF_ICMPV6_TYPE, "icmp6",
                          true);
    expr_symtab_add_field(symtab, "icmp6.code", MFF_ICMPV6_CODE, "icmp6",
                          true);

    expr_symtab_add_predicate(symtab, "icmp", "icmp4 || icmp6");

    expr_symtab_add_field(symtab, "ip.frag", MFF_IP_FRAG, "ip", false);
    expr_symtab_add_predicate(symtab, "ip.is_frag", "ip.frag[0]");
    expr_symtab_add_predicate(symtab, "ip.later_frag", "ip.frag[1]");
    expr_symtab_add_predicate(symtab, "ip.first_frag",
                              "ip.is_frag && !ip.later_frag");

    expr_symtab_add_predicate(symtab, "arp", "eth.type == 0x806");
    expr_symtab_add_field(symtab, "arp.op", MFF_ARP_OP, "arp", false);
    expr_symtab_add_field(symtab, "arp.spa", MFF_ARP_SPA, "arp", false);
    expr_symtab_add_field(symtab, "arp.sha", MFF_ARP_SHA, "arp", false);
    expr_symtab_add_field(symtab, "arp.tpa", MFF_ARP_TPA, "arp", false);
    expr_symtab_add_field(symtab, "arp.tha", MFF_ARP_THA, "arp", false);

    /* RARPs use the same layout as arp packets -> use the same field_id */
    expr_symtab_add_predicate(symtab, "rarp", "eth.type == 0x8035");
    expr_symtab_add_field(symtab, "rarp.op", MFF_ARP_OP, "rarp", false);
    expr_symtab_add_field(symtab, "rarp.spa", MFF_ARP_SPA, "rarp", false);
    expr_symtab_add_field(symtab, "rarp.sha", MFF_ARP_SHA, "rarp", false);
    expr_symtab_add_field(symtab, "rarp.tpa", MFF_ARP_TPA, "rarp", false);
    expr_symtab_add_field(symtab, "rarp.tha", MFF_ARP_THA, "rarp", false);

    expr_symtab_add_predicate(symtab, "nd",
              "icmp6.type == {135, 136} && icmp6.code == 0 && ip.ttl == 255");
    expr_symtab_add_predicate(symtab, "nd_ns",
              "icmp6.type == 135 && icmp6.code == 0 && ip.ttl == 255");
    expr_symtab_add_predicate(symtab, "nd_na",
              "icmp6.type == 136 && icmp6.code == 0 && ip.ttl == 255");
    expr_symtab_add_predicate(symtab, "nd_rs",
              "icmp6.type == 133 && icmp6.code == 0 && ip.ttl == 255");
    expr_symtab_add_predicate(symtab, "nd_ra",
              "icmp6.type == 134 && icmp6.code == 0 && ip.ttl == 255");
    expr_symtab_add_field(symtab, "nd.target", MFF_ND_TARGET, "nd", false);
    expr_symtab_add_field(symtab, "nd.sll", MFF_ND_SLL, "nd_ns", false);
    expr_symtab_add_field(symtab, "nd.tll", MFF_ND_TLL, "nd_na", false);

    /* MLDv1 packets use link-local source addresses
     * (RFC 2710 and RFC 3810).
     */
    expr_symtab_add_predicate(symtab, "mldv1",
                              "ip6.src == fe80::/10 && "
                              "icmp6.type == {130, 131, 132}");
    /* MLDv2 packets are sent to ff02::16 (RFC 3810, 5.2.14) */
    expr_symtab_add_predicate(symtab, "mldv2",
                              "ip6.dst == ff02::16 && icmp6.type == 143");

    expr_symtab_add_predicate(symtab, "tcp", "ip.proto == 6");
    expr_symtab_add_field(symtab, "tcp.src", MFF_TCP_SRC, "tcp", false);
    expr_symtab_add_field(symtab, "tcp.dst", MFF_TCP_DST, "tcp", false);
    expr_symtab_add_field(symtab, "tcp.flags", MFF_TCP_FLAGS, "tcp", false);

    expr_symtab_add_predicate(symtab, "udp", "ip.proto == 17");
    expr_symtab_add_field(symtab, "udp.src", MFF_UDP_SRC, "udp", false);
    expr_symtab_add_field(symtab, "udp.dst", MFF_UDP_DST, "udp", false);

    expr_symtab_add_predicate(symtab, "sctp", "ip.proto == 132");
    expr_symtab_add_field(symtab, "sctp.src", MFF_SCTP_SRC, "sctp", false);
    expr_symtab_add_field(symtab, "sctp.dst", MFF_SCTP_DST, "sctp", false);

    expr_symtab_add_field(symtab, "pkt.mark", MFF_PKT_MARK, NULL, false);

    expr_symtab_add_ovn_field(symtab, "icmp4.frag_mtu", OVN_ICMP4_FRAG_MTU);
    expr_symtab_add_ovn_field(symtab, "icmp6.frag_mtu", OVN_ICMP6_FRAG_MTU);
}

const char *
event_to_string(enum ovn_controller_event event)
{
    switch (event) {
    case OVN_EVENT_EMPTY_LB_BACKENDS:
        return "empty_lb_backends";
    case OVN_EVENT_MAX:
    default:
        return "";
    }
}

int
string_to_event(const char *s)
{
    if (!strcmp(s, "empty_lb_backends")) {
        return OVN_EVENT_EMPTY_LB_BACKENDS;
    }
    return -1;
}

static void
ovn_destroy_ovnfields(void)
{
    shash_destroy(&ovnfield_by_name);
}

static void
ovn_do_init_ovnfields(void)
{
    shash_init(&ovnfield_by_name);
    for (int i = 0; i < OVN_FIELD_N_IDS; i++) {
       const struct ovn_field *of = &ovn_fields[i];
       ovs_assert(of->id == i); /* Fields must be in the enum order. */
       shash_add_once(&ovnfield_by_name, of->name, of);
    }
    atexit(ovn_destroy_ovnfields);
}

static void
ovn_init_ovnfields(void)
{
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, ovn_do_init_ovnfields);
}

const struct ovn_field *
ovn_field_from_name(const char *name)
{
    ovn_init_ovnfields();

    return shash_find_data(&ovnfield_by_name, name);
}
