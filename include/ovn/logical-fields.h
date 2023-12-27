/* Copyright (c) 2015, 2016 Nicira, Inc.
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

#ifndef OVN_LOGICAL_FIELDS_H
#define OVN_LOGICAL_FIELDS_H 1

#include "openvswitch/meta-flow.h"
#include "openvswitch/util.h"

struct shash;

enum ovn_controller_event {
    OVN_EVENT_EMPTY_LB_BACKENDS = 0,
    OVN_EVENT_MAX,
};

/* Logical fields.
 *
 * These values are documented in ovn-architecture(7), please update the
 * documentation if you change any of them. */
#define MFF_LOG_DATAPATH MFF_METADATA /* Logical datapath (64 bits). */
#define MFF_LOG_FLAGS      MFF_REG10  /* One of MLF_* (32 bits). */
#define MFF_LOG_DNAT_ZONE  MFF_REG11  /* conntrack dnat zone for gateway router
                                       * (32 bits). */
#define MFF_LOG_SNAT_ZONE  MFF_REG12  /* conntrack snat zone for gateway router
                                       * (32 bits). */
#define MFF_LOG_CT_ZONE    MFF_REG13  /* Logical conntrack zone for lports
                                       * (32 bits). */
#define MFF_LOG_INPORT     MFF_REG14  /* Logical input port (32 bits). */
#define MFF_LOG_OUTPORT    MFF_REG15  /* Logical output port (32 bits). */

/* Logical registers.
 *
 * Make sure these don't overlap with the logical fields! */
#define MFF_LOG_REG0             MFF_REG0
#define MFF_LOG_LB_ORIG_DIP_IPV4 MFF_REG1
#define MFF_LOG_LB_ORIG_TP_DPORT MFF_REG2

#define MFF_LOG_XXREG0           MFF_XXREG0
#define MFF_LOG_LB_ORIG_DIP_IPV6 MFF_XXREG1

#define MFF_N_LOG_REGS 10

#define MFF_LOG_LB_AFF_MATCH_IP4_ADDR       MFF_REG4
#define MFF_LOG_LB_AFF_MATCH_LS_IP6_ADDR    MFF_XXREG0
#define MFF_LOG_LB_AFF_MATCH_LR_IP6_ADDR    MFF_XXREG1
#define MFF_LOG_LB_AFF_MATCH_PORT           MFF_REG8

void ovn_init_symtab(struct shash *symtab);

/* MFF_LOG_FLAGS_REG bit assignments */
enum mff_log_flags_bits {
    MLF_ALLOW_LOOPBACK_BIT = 0,
    MLF_RCV_FROM_RAMP_BIT = 1,
    MLF_FORCE_SNAT_FOR_DNAT_BIT = 2,
    MLF_FORCE_SNAT_FOR_LB_BIT = 3,
    MLF_LOCAL_ONLY_BIT = 4,
    MLF_NESTED_CONTAINER_BIT = 5,
    MLF_LOOKUP_MAC_BIT = 6,
    MLF_LOOKUP_LB_HAIRPIN_BIT = 7,
    MLF_LOOKUP_FDB_BIT = 8,
    MLF_SKIP_SNAT_FOR_LB_BIT = 9,
    MLF_LOCALPORT_BIT = 10,
    MLF_USE_SNAT_ZONE = 11,
    MLF_CHECK_PORT_SEC_BIT = 12,
    MLF_LOOKUP_COMMIT_ECMP_NH_BIT = 13,
    MLF_USE_LB_AFF_SESSION_BIT = 14,
    MLF_LOCALNET_BIT = 15,
};

/* MFF_LOG_FLAGS_REG flag assignments */
enum mff_log_flags {
    /* Allow outputting back to inport. */
    MLF_ALLOW_LOOPBACK = (1 << MLF_ALLOW_LOOPBACK_BIT),

    /* Indicate that a packet was received from a ramp switch to compensate for
     * the lack of egress port information available in ramp switch
     * encapsulation.  Egress port information is available for Geneve, STT and
     * regular VXLAN tunnel types. */
    MLF_RCV_FROM_RAMP = (1 << MLF_RCV_FROM_RAMP_BIT),

    /* Indicate that a packet needs a force SNAT in the gateway router when
     * DNAT has taken place. */
    MLF_FORCE_SNAT_FOR_DNAT = (1 << MLF_FORCE_SNAT_FOR_DNAT_BIT),

    /* Indicate that a packet needs a force SNAT in the gateway router when
     * load-balancing has taken place. */
    MLF_FORCE_SNAT_FOR_LB = (1 << MLF_FORCE_SNAT_FOR_LB_BIT),

    /* Indicate that a packet that should be distributed across multiple
     * hypervisors should instead only be output to local targets
     */
    MLF_LOCAL_ONLY = (1 << MLF_LOCAL_ONLY_BIT),

    /* Indicate that a packet was received from a nested container. */
    MLF_NESTED_CONTAINER = (1 << MLF_NESTED_CONTAINER_BIT),

    /* Indicate that the lookup in the mac binding table was successful. */
    MLF_LOOKUP_MAC = (1 << MLF_LOOKUP_MAC_BIT),

    MLF_LOOKUP_LB_HAIRPIN = (1 << MLF_LOOKUP_LB_HAIRPIN_BIT),

    /* Indicate that the lookup in the fdb table was successful. */
    MLF_LOOKUP_FDB = (1 << MLF_LOOKUP_FDB_BIT),

    /* Indicate that a packet must not SNAT in the gateway router when
     * load-balancing has taken place. */
    MLF_SKIP_SNAT_FOR_LB = (1 << MLF_SKIP_SNAT_FOR_LB_BIT),

    /* Indicate the packet has been received from a localport */
    MLF_LOCALPORT = (1 << MLF_LOCALPORT_BIT),

    MLF_LOOKUP_COMMIT_ECMP_NH = (1 << MLF_LOOKUP_COMMIT_ECMP_NH_BIT),

    MLF_USE_LB_AFF_SESSION = (1 << MLF_USE_LB_AFF_SESSION_BIT),

    /* Indicate that the port is localnet. */
    MLF_LOCALNET = (1 << MLF_LOCALNET_BIT),

};

/* OVN logical fields
 * ===================
 * These are the fields which OVN supports modifying which gets translated
 * to OFFlow controller action.
 *
 * OpenvSwitch doesn't support modifying these fields yet. If a field is
 * supported later by OpenvSwitch, it can be deleted from here.
 */

enum ovn_field_id {
    /*
     * Name: "icmp4.frag_mtu" -
     * Type: be16
     * Description: Sets the low-order 16 bits of the ICMP4 header field
     * (that is labelled "unused" in the ICMP specification) of the ICMP4
     * packet as per the RFC 1191.
     */
    OVN_ICMP4_FRAG_MTU,
    /*
     * Name: "icmp6.frag_mtu" -
     * Type: be32
     * Description: Sets the first 32 bits of the ICMPv6 body to the MTU of
     * next-hop link (RFC 4443)
     */
    OVN_ICMP6_FRAG_MTU,

    OVN_FIELD_N_IDS
};

struct ovn_field {
    enum ovn_field_id id;
    const char *name;
    unsigned int n_bytes;       /* Width of the field in bytes. */
    unsigned int n_bits;        /* Number of significant bits in field. */
};

static inline const struct ovn_field *
ovn_field_from_id(enum ovn_field_id id)
{
    extern const struct ovn_field ovn_fields[OVN_FIELD_N_IDS];
    ovs_assert((unsigned int) id < OVN_FIELD_N_IDS);
    return &ovn_fields[id];
}

const char *event_to_string(enum ovn_controller_event event);
int string_to_event(const char *s);
const struct ovn_field *ovn_field_from_name(const char *name);

/* OVN CT label values
 * ===================
 * These are specific ct.label bit values OVN uses to track different types
 * of traffic.
 */

#define OVN_CT_BLOCKED_BIT 0
#define OVN_CT_NATTED_BIT  1
#define OVN_CT_LB_SKIP_SNAT_BIT 2
#define OVN_CT_LB_FORCE_SNAT_BIT 3

#define OVN_CT_BLOCKED 1
#define OVN_CT_NATTED  2
#define OVN_CT_LB_SKIP_SNAT 4
#define OVN_CT_LB_FORCE_SNAT 8

#define OVN_CT_ECMP_ETH_1ST_BIT 32
#define OVN_CT_ECMP_ETH_END_BIT 79

#define OVN_CT_STR(LABEL_VALUE) OVS_STRINGIZE(LABEL_VALUE)
#define OVN_CT_MASKED_STR(LABEL_VALUE) \
    OVS_STRINGIZE(LABEL_VALUE) "/" OVS_STRINGIZE(LABEL_VALUE)

#define OVN_CT_LABEL_STR(LABEL_VALUE) "ct_label[" OVN_CT_STR(LABEL_VALUE) "]"

#endif /* ovn/lib/logical-fields.h */
