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


#ifndef OVN_UTIL_H
#define OVN_UTIL_H 1

#include "lib/packets.h"

struct nbrec_logical_router_port;
struct sbrec_logical_flow;
struct uuid;
struct eth_addr;
struct sbrec_port_binding;
struct sbrec_datapath_binding;

struct ipv4_netaddr {
    ovs_be32 addr;            /* 192.168.10.123 */
    ovs_be32 mask;            /* 255.255.255.0 */
    ovs_be32 network;         /* 192.168.10.0 */
    unsigned int plen;        /* CIDR Prefix: 24. */

    char addr_s[INET_ADDRSTRLEN + 1];     /* "192.168.10.123" */
    char network_s[INET_ADDRSTRLEN + 1];  /* "192.168.10.0" */
    char bcast_s[INET_ADDRSTRLEN + 1];    /* "192.168.10.255" */
};

struct ipv6_netaddr {
    struct in6_addr addr;     /* fc00::1 */
    struct in6_addr mask;     /* ffff:ffff:ffff:ffff:: */
    struct in6_addr sn_addr;  /* ff02:1:ff00::1 */
    struct in6_addr network;  /* fc00:: */
    unsigned int plen;        /* CIDR Prefix: 64 */

    char addr_s[INET6_ADDRSTRLEN + 1];    /* "fc00::1" */
    char sn_addr_s[INET6_ADDRSTRLEN + 1]; /* "ff02:1:ff00::1" */
    char network_s[INET6_ADDRSTRLEN + 1]; /* "fc00::" */
};

struct lport_addresses {
    char ea_s[ETH_ADDR_STRLEN + 1];
    struct eth_addr ea;
    size_t n_ipv4_addrs;
    struct ipv4_netaddr *ipv4_addrs;
    size_t n_ipv6_addrs;
    struct ipv6_netaddr *ipv6_addrs;
};

bool is_dynamic_lsp_address(const char *address);
bool extract_addresses(const char *address, struct lport_addresses *,
                       int *ofs);
bool extract_lsp_addresses(const char *address, struct lport_addresses *);
bool extract_ip_addresses(const char *address, struct lport_addresses *);
bool extract_lrp_networks(const struct nbrec_logical_router_port *,
                          struct lport_addresses *);
bool extract_sbrec_binding_first_mac(const struct sbrec_port_binding *binding,
                                     struct eth_addr *ea);

void destroy_lport_addresses(struct lport_addresses *);

char *alloc_nat_zone_key(const struct uuid *key, const char *type);

const char *default_nb_db(void);
const char *default_sb_db(void);
const char *default_ic_nb_db(void);
const char *default_ic_sb_db(void);
char *get_abs_unix_ctl_path(void);

struct ovsdb_idl_table_class;
const char *db_table_usage(struct ds *tables,
                           const struct ovsdb_idl_table_class *class,
                           int n_tables);

bool ovn_is_known_nb_lsp_type(const char *type);

uint32_t sbrec_logical_flow_hash(const struct sbrec_logical_flow *);
uint32_t ovn_logical_flow_hash(const struct uuid *logical_datapath,
                               uint8_t table_id, const char *pipeline,
                               uint16_t priority,
                               const char *match, const char *actions);
bool datapath_is_switch(const struct sbrec_datapath_binding *);

#define OVN_MAX_DP_KEY ((1u << 24) - 1)
#define OVN_MAX_DP_GLOBAL_NUM ((1u << 16) - 1)
#define OVN_MIN_DP_KEY_LOCAL 1
#define OVN_MAX_DP_KEY_LOCAL (OVN_MAX_DP_KEY - OVN_MAX_DP_GLOBAL_NUM)
#define OVN_MIN_DP_KEY_GLOBAL (OVN_MAX_DP_KEY_LOCAL + 1)
#define OVN_MAX_DP_KEY_GLOBAL OVN_MAX_DP_KEY
struct hmap;
void ovn_destroy_tnlids(struct hmap *tnlids);
void ovn_add_tnlid(struct hmap *set, uint32_t tnlid);
uint32_t ovn_allocate_tnlid(struct hmap *set, const char *name, uint32_t min,
                            uint32_t max, uint32_t *hint);
#endif
