/*
 * Copyright (c) 2016 Red Hat, Inc.
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

#ifndef OVN_L7_H
#define OVN_L7_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include "csum.h"
#include "dp-packet.h"
#include "openvswitch/hmap.h"
#include "hash.h"
#include "ovn/logical-fields.h"

#define BFD_PACKET_LEN  24
#define BFD_DEST_PORT   3784
#define BFD_VERSION     1
#define BFD_DEFAULT_SRC_IP 0xA9FE0101 /* 169.254.1.1 */
#define BFD_DEFAULT_DST_IP 0xA9FE0100 /* 169.254.1.0 */

struct bfd_msg {
    uint8_t vers_diag;
    uint8_t flags;
    uint8_t mult;
    uint8_t length;
    ovs_be32 my_disc;
    ovs_be32 your_disc;
    ovs_be32 min_tx;
    ovs_be32 min_rx;
    ovs_be32 min_rx_echo;
};
BUILD_ASSERT_DECL(BFD_PACKET_LEN == sizeof(struct bfd_msg));

#define DNS_QUERY_TYPE_A        0x01
#define DNS_QUERY_TYPE_AAAA     0x1c
#define DNS_QUERY_TYPE_ANY      0xff
#define DNS_QUERY_TYPE_PTR      0x0c

#define DNS_CLASS_IN            0x01
#define DNS_DEFAULT_RR_TTL      3600

/* Generic options map which is used to store dhcpv4 opts and dhcpv6 opts. */
struct gen_opts_map {
    struct hmap_node hmap_node;
    char *name;
    char *type;
    size_t code;
};

#define DOMAIN_NAME_MAX_LEN 255
#define DHCP_BROADCAST_FLAG 0x8000

/* These are not defined in ovs/lib/dhcp.h and hence defined here with
 * OVN_DHCP_OPT_CODE_<opt_name>.
 */
#define OVN_DHCP_OPT_CODE_NETMASK      1
#define OVN_DHCP_OPT_CODE_LEASE_TIME   51
#define OVN_DHCP_OPT_CODE_T1           58
#define OVN_DHCP_OPT_CODE_T2           59

#define DHCP_OPTION(NAME, CODE, TYPE) \
    {.name = NAME, .code = CODE, .type = TYPE}

#define OFFERIP              DHCP_OPTION("offerip", 0, "ipv4")
#define DHCP_OPT_NETMASK     DHCP_OPTION("netmask", 1, "ipv4")
#define DHCP_OPT_ROUTER      DHCP_OPTION("router", 3, "ipv4")
#define DHCP_OPT_DNS_SERVER  DHCP_OPTION("dns_server", 6, "ipv4")
#define DHCP_OPT_LOG_SERVER  DHCP_OPTION("log_server", 7, "ipv4")
#define DHCP_OPT_LPR_SERVER  DHCP_OPTION("lpr_server", 9, "ipv4")
#define DHCP_OPT_HOSTNAME    DHCP_OPTION("hostname", 12, "str")
#define DHCP_OPT_DOMAIN_NAME DHCP_OPTION("domain_name", 15, "str")
#define DHCP_OPT_SWAP_SERVER DHCP_OPTION("swap_server", 16, "ipv4")

#define DHCP_OPT_POLICY_FILTER \
    DHCP_OPTION("policy_filter", 21, "ipv4")

#define DHCP_OPT_ROUTER_SOLICITATION \
    DHCP_OPTION("router_solicitation", 32, "ipv4")

#define DHCP_OPT_NIS_SERVER  DHCP_OPTION("nis_server", 41, "ipv4")
#define DHCP_OPT_NTP_SERVER  DHCP_OPTION("ntp_server", 42, "ipv4")
#define DHCP_OPT_SERVER_ID   DHCP_OPTION("server_id", 54, "ipv4")
#define DHCP_OPT_TFTP_SERVER DHCP_OPTION("tftp_server", 66, "host_id")

#define DHCP_OPT_CLASSLESS_STATIC_ROUTE \
    DHCP_OPTION("classless_static_route", 121, "static_routes")
#define DHCP_OPT_MS_CLASSLESS_STATIC_ROUTE \
    DHCP_OPTION("ms_classless_static_route", 249, "static_routes")

#define DHCP_OPT_IP_FORWARD_ENABLE DHCP_OPTION("ip_forward_enable", 19, "bool")
#define DHCP_OPT_ROUTER_DISCOVERY DHCP_OPTION("router_discovery", 31, "bool")
#define DHCP_OPT_ETHERNET_ENCAP DHCP_OPTION("ethernet_encap", 36, "bool")

#define DHCP_OPT_DEFAULT_TTL DHCP_OPTION("default_ttl", 23, "uint8")

#define DHCP_OPT_TCP_TTL  DHCP_OPTION("tcp_ttl", 37, "uint8")
#define DHCP_OPT_MTU      DHCP_OPTION("mtu", 26, "uint16")
#define DHCP_OPT_LEASE_TIME DHCP_OPTION("lease_time", 51, "uint32")
#define DHCP_OPT_T1 DHCP_OPTION("T1", 58, "uint32")
#define DHCP_OPT_T2 DHCP_OPTION("T2", 59, "uint32")

#define DHCP_OPT_BOOTFILE DHCP_OPTION("bootfile_name", 67, "str")
#define DHCP_OPT_WPAD DHCP_OPTION("wpad", 252, "str")
#define DHCP_OPT_PATH_PREFIX DHCP_OPTION("path_prefix", 210, "str")
#define DHCP_OPT_TFTP_SERVER_ADDRESS \
    DHCP_OPTION("tftp_server_address", 150, "ipv4")
#define DHCP_OPT_DOMAIN_SEARCH_LIST \
    DHCP_OPTION("domain_search_list", 119, "domains")

#define DHCP_OPT_BROADCAST_ADDRESS \
    DHCP_OPTION("broadcast_address", 28, "ipv4")

#define DHCP_OPT_NETBIOS_NAME_SERVER \
    DHCP_OPTION("netbios_name_server", 44, "ipv4")
#define DHCP_OPT_NETBIOS_NODE_TYPE \
    DHCP_OPTION("netbios_node_type", 46, "uint8")

#define DHCP_OPT_BOOTFILE_CODE 67

/* Use unused 254 option for iPXE bootfile_name_alt userdata DHCP option.
 * This option code is replaced by 67 when sending the DHCP reply.
 */
#define DHCP_OPT_BOOTFILE_ALT_CODE 254
#define DHCP_OPT_BOOTFILE_ALT DHCP_OPTION("bootfile_name_alt", \
                                          DHCP_OPT_BOOTFILE_ALT_CODE, "str")

#define DHCP_OPT_ETHERBOOT	175

#define DHCP_OPT_ARP_CACHE_TIMEOUT \
    DHCP_OPTION("arp_cache_timeout", 35, "uint32")
#define DHCP_OPT_TCP_KEEPALIVE_INTERVAL \
    DHCP_OPTION("tcp_keepalive_interval", 38, "uint32")

static inline uint32_t
gen_opt_hash(char *opt_name)
{
    return hash_string(opt_name, 0);
}

static inline uint32_t
dhcp_opt_hash(char *opt_name)
{
    return gen_opt_hash(opt_name);
}

static inline struct gen_opts_map *
gen_opts_find(const struct hmap *gen_opts, char *opt_name)
{
    struct gen_opts_map *gen_opt;
    HMAP_FOR_EACH_WITH_HASH (gen_opt, hmap_node, gen_opt_hash(opt_name),
                             gen_opts) {
        if (!strcmp(gen_opt->name, opt_name)) {
            return gen_opt;
        }
    }

    return NULL;
}

static inline struct gen_opts_map *
dhcp_opts_find(const struct hmap *dhcp_opts, char *opt_name)
{
    return gen_opts_find(dhcp_opts, opt_name);
}

static inline void
gen_opt_add(struct hmap *gen_opts, char *opt_name, size_t code, char *type)
{
    struct gen_opts_map *gen_opt = xzalloc(sizeof *gen_opt);
    gen_opt->name = xstrdup(opt_name);
    gen_opt->code = code;
    gen_opt->type = xstrdup(type);
    hmap_insert(gen_opts, &gen_opt->hmap_node, gen_opt_hash(opt_name));
}

static inline void
dhcp_opt_add(struct hmap *dhcp_opts, char *opt_name, size_t code, char *type)
{
    gen_opt_add(dhcp_opts, opt_name, code, type);
}

static inline void
gen_opts_destroy(struct hmap *gen_opts)
{
    struct gen_opts_map *gen_opt;
    HMAP_FOR_EACH_POP (gen_opt, hmap_node, gen_opts) {
        free(gen_opt->name);
        free(gen_opt->type);
        free(gen_opt);
    }
    hmap_destroy(gen_opts);
}

static inline void
dhcp_opts_destroy(struct hmap *dhcp_opts)
{
    gen_opts_destroy(dhcp_opts);
}

OVS_PACKED(
struct dhcp_opt_header {
    uint8_t code;
    uint8_t len;
});

#define DHCP_OPT_PAYLOAD(hdr) \
    (void *)((char *)hdr + sizeof(struct dhcp_opt_header))

/* Used in the OpenFlow PACKET_IN userdata */
struct dhcp_opt6_header {
    ovs_be16 opt_code;
    ovs_be16 size;
};

/* These are not defined in ovs/lib/dhcp.h, hence defining here. */
#define OVN_DHCP_MSG_DECLINE        4
#define OVN_DHCP_MSG_RELEASE        7
#define OVN_DHCP_MSG_INFORM         8

/* Supported DHCPv6 Message Types */
#define DHCPV6_MSG_TYPE_SOLICIT     1
#define DHCPV6_MSG_TYPE_ADVT        2
#define DHCPV6_MSG_TYPE_REQUEST     3
#define DHCPV6_MSG_TYPE_CONFIRM     4
#define DHCPV6_MSG_TYPE_RENEW       5
#define DHCPV6_MSG_TYPE_REBIND      6

#define DHCPV6_MSG_TYPE_REPLY       7
#define DHCPV6_MSG_TYPE_DECLINE     9
#define DHCPV6_MSG_TYPE_INFO_REQ    11


/* DHCPv6 Option codes */
#define DHCPV6_OPT_CLIENT_ID_CODE        1
#define DHCPV6_OPT_SERVER_ID_CODE        2
#define DHCPV6_OPT_IA_NA_CODE            3
#define DHCPV6_OPT_IA_ADDR_CODE          5
#define DHCPV6_OPT_STATUS_CODE           13
#define DHCPV6_OPT_DNS_SERVER_CODE       23
#define DHCPV6_OPT_DOMAIN_SEARCH_CODE    24
#define DHCPV6_OPT_IA_PD                 25
#define DHCPV6_OPT_IA_PREFIX             26

#define DHCPV6_OPT_SERVER_ID \
    DHCP_OPTION("server_id", DHCPV6_OPT_SERVER_ID_CODE, "mac")

#define DHCPV6_OPT_IA_ADDR  \
    DHCP_OPTION("ia_addr", DHCPV6_OPT_IA_ADDR_CODE, "ipv6")

#define DHCPV6_OPT_DNS_SERVER  \
    DHCP_OPTION("dns_server", DHCPV6_OPT_DNS_SERVER_CODE, "ipv6")

#define DHCPV6_OPT_DOMAIN_SEARCH \
    DHCP_OPTION("domain_search", DHCPV6_OPT_DOMAIN_SEARCH_CODE, "str")

OVS_PACKED(
struct dhcpv6_opt_header {
    ovs_be16 code;
    ovs_be16 len;
});

OVS_PACKED(
struct dhcpv6_opt_server_id {
    struct dhcpv6_opt_header opt;
    ovs_be16 duid_type;
    ovs_be16 hw_type;
    struct eth_addr mac;
});


OVS_PACKED(
struct dhcpv6_opt_ia_addr {
    struct dhcpv6_opt_header opt;
    struct in6_addr ipv6;
    ovs_be32 t1;
    ovs_be32 t2;
});

OVS_PACKED(
struct dhcpv6_opt_ia_na {
    struct dhcpv6_opt_header opt;
    ovs_be32 iaid;
    ovs_be32 t1;
    ovs_be32 t2;
});

/* RDNSS option RFC 6106 */
#define ND_RDNSS_OPT_LEN    8
#define ND_OPT_RDNSS        25
struct nd_rdnss_opt {
    uint8_t type;         /* ND_OPT_RDNSS. */
    uint8_t len;          /* >= 3. */
    ovs_be16 reserved;    /* Always 0. */
    ovs_16aligned_be32 lifetime;
};
BUILD_ASSERT_DECL(ND_RDNSS_OPT_LEN == sizeof(struct nd_rdnss_opt));

/* DNSSL option RFC 6106 */
#define ND_OPT_DNSSL        31
#define ND_DNSSL_OPT_LEN    8
struct ovs_nd_dnssl {
    u_int8_t type;  /* ND_OPT_DNSSL */
    u_int8_t len;   /* >= 2 */
    ovs_be16 reserved;
    ovs_16aligned_be32 lifetime;
};
BUILD_ASSERT_DECL(ND_DNSSL_OPT_LEN == sizeof(struct ovs_nd_dnssl));

/* Route Information option RFC 4191 */
#define ND_OPT_ROUTE_INFO_TYPE   24
#define ND_ROUTE_INFO_OPT_LEN    8
struct ovs_nd_route_info {
    u_int8_t type;  /* ND_OPT_ROUTE_INFO_TYPE */
    u_int8_t len;   /* 1, 2 or 3 */
    u_int8_t prefix_len;
    u_int8_t flags;
    ovs_be32 route_lifetime;
};
BUILD_ASSERT_DECL(ND_ROUTE_INFO_OPT_LEN == sizeof(struct ovs_nd_route_info));

OVS_PACKED(
struct dhcpv6_opt_ia_prefix {
    struct dhcpv6_opt_header opt;
    ovs_be32 plife_time;
    ovs_be32 vlife_time;
    uint8_t plen;
    struct in6_addr ipv6;
});

OVS_PACKED(
struct dhcpv6_opt_status {
    struct dhcpv6_opt_header opt;
    ovs_be16 status_code;
    uint8_t msg[];
});

#define DHCPV6_DUID_LL      3
#define DHCPV6_HW_TYPE_ETH  1

#define DHCPV6_OPT_PAYLOAD(opt) \
    (void *)((char *)opt + sizeof(struct dhcpv6_opt_header))

static inline struct gen_opts_map *
nd_ra_opts_find(const struct hmap *nd_ra_opts, char *opt_name)
{
    return gen_opts_find(nd_ra_opts, opt_name);
}

static inline void
nd_ra_opt_add(struct hmap *nd_ra_opts, char *opt_name, size_t code,
               char *type)
{
    gen_opt_add(nd_ra_opts, opt_name, code, type);
}

static inline void
nd_ra_opts_destroy(struct hmap *nd_ra_opts)
{
    gen_opts_destroy(nd_ra_opts);
}


#define ND_RA_FLAG_ADDR_MODE    0
/* all small numbers seems to be all already taken but nothing guarantees this
 * code will not be assigned by IANA to another option */
#define ND_RA_FLAG_PRF          255


/* Default values of various IPv6 Neighbor Discovery protocol options and
 * flags. See RFC 4861 for more information.
 * */
#define IPV6_ND_RA_FLAG_MANAGED_ADDR_CONFIG         0x80
#define IPV6_ND_RA_FLAG_OTHER_ADDR_CONFIG           0x40

#define IPV6_ND_RA_CUR_HOP_LIMIT                    255
#define IPV6_ND_RA_LIFETIME                         0xffff
#define IPV6_ND_RA_REACHABLE_TIME                   0
#define IPV6_ND_RA_RETRANSMIT_TIMER                 0

#define IPV6_ND_RA_OPT_PREFIX_ON_LINK               0x80
#define IPV6_ND_RA_OPT_PREFIX_AUTONOMOUS            0x40
#define IPV6_ND_RA_OPT_PREFIX_VALID_LIFETIME        0xffffffff
#define IPV6_ND_RA_OPT_PREFIX_PREFERRED_LIFETIME    0xffffffff

#define IPV6_ND_RA_OPT_PRF_NORMAL                   0x00
#define IPV6_ND_RA_OPT_PRF_HIGH                     0x08
#define IPV6_ND_RA_OPT_PRF_LOW                      0x18
#define IPV6_ND_RA_OPT_PRF_RESET_MASK               0xe7

static inline void
nd_ra_opts_init(struct hmap *nd_ra_opts)
{
    nd_ra_opt_add(nd_ra_opts, "addr_mode", ND_RA_FLAG_ADDR_MODE, "str");
    nd_ra_opt_add(nd_ra_opts, "router_preference", ND_RA_FLAG_PRF, "str");
    nd_ra_opt_add(nd_ra_opts, "slla", ND_OPT_SOURCE_LINKADDR, "mac");
    nd_ra_opt_add(nd_ra_opts, "prefix", ND_OPT_PREFIX_INFORMATION, "ipv6");
    nd_ra_opt_add(nd_ra_opts, "mtu", ND_OPT_MTU, "uint32");
}

#define EMPTY_LB_VIP           1
#define EMPTY_LB_PROTOCOL      2
#define EMPTY_LB_LOAD_BALANCER 3

/* Used in the OpenFlow PACKET_IN userdata */
struct controller_event_opt_header {
    ovs_be16 opt_code;
    ovs_be16 size;
};

struct controller_event_options {
    struct hmap event_opts[OVN_EVENT_MAX];
};

static inline void
controller_event_opt_add(struct controller_event_options *event_opts,
                         enum ovn_controller_event event_type, char *opt_name,
                         size_t opt_code, char *opt_type)
{
    gen_opt_add(&event_opts->event_opts[event_type], opt_name, opt_code,
                opt_type);
}

static inline void
controller_event_opts_init(struct controller_event_options *opts)
{
    for (size_t i = 0; i < OVN_EVENT_MAX; i++) {
        hmap_init(&opts->event_opts[i]);
    }
    controller_event_opt_add(opts, OVN_EVENT_EMPTY_LB_BACKENDS, "vip",
                             EMPTY_LB_VIP, "str");
    controller_event_opt_add(opts, OVN_EVENT_EMPTY_LB_BACKENDS, "protocol",
                             EMPTY_LB_PROTOCOL, "str");
    controller_event_opt_add(opts, OVN_EVENT_EMPTY_LB_BACKENDS,
                             "load_balancer", EMPTY_LB_LOAD_BALANCER, "str");
}

static inline void
controller_event_opts_destroy(struct controller_event_options *opts)
{
    for (size_t i = 0; i < OVN_EVENT_MAX; i++) {
        gen_opts_destroy(&opts->event_opts[i]);
    }
}

bool ipv6_addr_is_routable_multicast(const struct in6_addr *);

static inline bool
ipv6_addr_is_host_zero(const struct in6_addr *prefix,
                       const struct in6_addr *mask)
{
    /* host-bits-non-zero <=> (prefix ^ mask) & prefix. */
    struct in6_addr tmp = ipv6_addr_bitxor(prefix, mask);

    tmp = ipv6_addr_bitand(&tmp, prefix);
    return ipv6_is_zero(&tmp);
}

#define IPV6_EXT_HEADER_LEN 8
struct ipv6_ext_header {
    uint8_t ip6_nxt_proto;
    uint8_t len;
    uint8_t values[6];
};
BUILD_ASSERT_DECL(IPV6_EXT_HEADER_LEN == sizeof(struct ipv6_ext_header));

/* Sets the IPv6 extension header fields (next proto and length) and
 * copies the first max 6 values to the header. Returns the number of values
 * copied to the header.
 */
static inline size_t
packet_set_ipv6_ext_header(struct ipv6_ext_header *ext_hdr, uint8_t ip_proto,
                           uint8_t ext_len, const uint8_t *values,
                           size_t n_values)
{
    ext_hdr->ip6_nxt_proto = ip_proto;
    ext_hdr->len = (ext_len >= 8 ? ext_len - 8 : 0);
    if (OVS_UNLIKELY(n_values > 6)) {
        n_values = 6;
    }
    memcpy(&ext_hdr->values, values, n_values);
    return n_values;
}

#define MLD_QUERY_HEADER_LEN 28
struct mld_query_header {
    uint8_t type;
    uint8_t code;
    ovs_be16 csum;
    ovs_be16 max_resp;
    ovs_be16 rsvd;
    struct in6_addr group;
    uint8_t srs_qrv;
    uint8_t qqic;
    ovs_be16 nsrcs;
};
BUILD_ASSERT_DECL(MLD_QUERY_HEADER_LEN == sizeof(struct mld_query_header));

/* Sets the MLD type to MLD_QUERY and populates the MLD query header
 * 'packet'. 'packet' must be a valid MLD query packet with its l4
 * offset properly populated.
 */
static inline void
packet_set_mld_query(struct dp_packet *packet, uint16_t max_resp,
                     const struct in6_addr *group,
                     bool srs, uint8_t qrv, uint8_t qqic)
{
    struct mld_query_header *mqh = dp_packet_l4(packet);
    mqh->type = MLD_QUERY;
    mqh->code = 0;
    mqh->max_resp = htons(max_resp);
    mqh->rsvd = 0;
    memcpy(&mqh->group, group, sizeof mqh->group);

    /* See RFC 3810 5.1.8. */
    if (qrv > 7) {
        qrv = 0;
    }

    mqh->srs_qrv = (srs << 3 | qrv);
    mqh->qqic = qqic;
    mqh->nsrcs = 0;

    struct ovs_16aligned_ip6_hdr *nh6 = dp_packet_l3(packet);
    mqh->csum = 0;
    mqh->csum = packet_csum_upperlayer6(nh6, mqh, IPPROTO_ICMPV6, sizeof *mqh);
}

#endif /* OVN_L7_H */
