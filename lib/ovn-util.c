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

#include "ovn-util.h"

#include <ctype.h>
#include <unistd.h>

#include "daemon.h"
#include "include/ovn/actions.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/vlog.h"
#include "lib/vswitch-idl.h"
#include "ovn-dirs.h"
#include "ovn-nb-idl.h"
#include "ovn-sb-idl.h"
#include "ovsdb-idl.h"
#include "socket-util.h"
#include "stream.h"
#include "svec.h"
#include "unixctl.h"

VLOG_DEFINE_THIS_MODULE(ovn_util);

#define DEFAULT_PROBE_INTERVAL_MSEC 5000

void ovn_conn_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *idl_)
{
    const struct ovsdb_idl *idl = idl_;

    unixctl_command_reply(
        conn,
        ovsdb_idl_is_connected(idl) ? "connected": "not connected");
}

/* Set inactivity probe interval for 'idl' and 'remote' to 'interval'.
 * If 'interval' < 0 (no preference from daemon settings), set it to 5000ms;
 * if 'remote' needs probing, disable otherwise.
 * 'interval' value of 0 disables probing.
 */
void set_idl_probe_interval(struct ovsdb_idl *idl, const char *remote,
                            int interval)
{
    if (interval < 0) {
        interval = (remote && !stream_or_pstream_needs_probes(remote)
                    ? 0 : DEFAULT_PROBE_INTERVAL_MSEC);
    } else if (interval > 0 && interval < 1000) {
        interval = 1000;
    }

    ovsdb_idl_set_probe_interval(idl, interval);
}

static void
add_ipv4_netaddr(struct lport_addresses *laddrs, ovs_be32 addr,
                 unsigned int plen)
{
    laddrs->n_ipv4_addrs++;
    laddrs->ipv4_addrs = xrealloc(laddrs->ipv4_addrs,
        laddrs->n_ipv4_addrs * sizeof *laddrs->ipv4_addrs);

    struct ipv4_netaddr *na = &laddrs->ipv4_addrs[laddrs->n_ipv4_addrs - 1];

    na->addr = addr;
    na->mask = be32_prefix_mask(plen);
    na->network = addr & na->mask;
    na->plen = plen;

    ovs_be32 bcast = addr | ~na->mask;
    inet_ntop(AF_INET, &addr, na->addr_s, sizeof na->addr_s);
    inet_ntop(AF_INET, &na->network, na->network_s, sizeof na->network_s);
    inet_ntop(AF_INET, &bcast, na->bcast_s, sizeof na->bcast_s);
}

static void
add_ipv6_netaddr(struct lport_addresses *laddrs, struct in6_addr addr,
                 unsigned int plen)
{
    laddrs->n_ipv6_addrs++;
    laddrs->ipv6_addrs = xrealloc(laddrs->ipv6_addrs,
        laddrs->n_ipv6_addrs * sizeof *laddrs->ipv6_addrs);

    struct ipv6_netaddr *na = &laddrs->ipv6_addrs[laddrs->n_ipv6_addrs - 1];

    memcpy(&na->addr, &addr, sizeof na->addr);
    na->mask = ipv6_create_mask(plen);
    na->network = ipv6_addr_bitand(&addr, &na->mask);
    na->plen = plen;
    in6_addr_solicited_node(&na->sn_addr, &addr);

    inet_ntop(AF_INET6, &addr, na->addr_s, sizeof na->addr_s);
    inet_ntop(AF_INET6, &na->sn_addr, na->sn_addr_s, sizeof na->sn_addr_s);
    inet_ntop(AF_INET6, &na->network, na->network_s, sizeof na->network_s);
}

/* Returns true if specified address specifies a dynamic address,
 * supporting the following formats:
 *
 *    "dynamic":
 *        Both MAC and IP are to be allocated dynamically.
 *
 *    "xx:xx:xx:xx:xx:xx dynamic":
 *        Use specified MAC address, but allocate an IP address
 *        dynamically.
 *
 *    "dynamic x.x.x.x":
 *        Use specified IP address, but allocate a MAC address
 *        dynamically.
 */
bool
is_dynamic_lsp_address(const char *address)
{
    char ipv6_s[IPV6_SCAN_LEN + 1];
    struct eth_addr ea;
    ovs_be32 ip;
    int n = 0;

    if (!strncmp(address, "dynamic", 7)) {
        n = 7;
        if (!address[n]) {
            /* "dynamic" */
            return true;
        }
        if (ovs_scan_len(address, &n, " "IP_SCAN_FMT, IP_SCAN_ARGS(&ip))
            && !address[n]) {
            /* "dynamic x.x.x.x" */
            return true;
        }
        if (ovs_scan_len(address, &n, " "IPV6_SCAN_FMT, ipv6_s)
            && !address[n]) {
            /* Either "dynamic xxxx::xxxx" or "dynamic x.x.x.x xxxx::xxxx". */
            return true;
        }
        return false;
    }

    if (ovs_scan_len(address, &n, ETH_ADDR_SCAN_FMT" dynamic",
                     ETH_ADDR_SCAN_ARGS(ea)) && !address[n]) {
        /* "xx:xx:xx:xx:xx:xx dynamic" */
        return true;
    }

    return false;
}

static bool
parse_and_store_addresses(const char *address, struct lport_addresses *laddrs,
                          int *ofs, bool extract_eth_addr)
{
    memset(laddrs, 0, sizeof *laddrs);

    const char *buf = address;
    const char *const start = buf;
    int buf_index = 0;

    if (extract_eth_addr) {
        if (!ovs_scan_len(buf, &buf_index, ETH_ADDR_SCAN_FMT,
                          ETH_ADDR_SCAN_ARGS(laddrs->ea))) {
            laddrs->ea = eth_addr_zero;
            *ofs = 0;
            return false;
        }

        snprintf(laddrs->ea_s, sizeof laddrs->ea_s, ETH_ADDR_FMT,
                 ETH_ADDR_ARGS(laddrs->ea));
    }

    ovs_be32 ip4;
    struct in6_addr ip6;
    unsigned int plen;
    char *error;

    /* Loop through the buffer and extract the IPv4/IPv6 addresses
     * and store in the 'laddrs'. Break the loop if invalid data is found.
     */
    buf += buf_index;
    while (*buf != '\0') {
        buf_index = 0;
        error = ip_parse_cidr_len(buf, &buf_index, &ip4, &plen);
        if (!error) {
            add_ipv4_netaddr(laddrs, ip4, plen);
            buf += buf_index;
            continue;
        }
        free(error);
        error = ipv6_parse_cidr_len(buf, &buf_index, &ip6, &plen);
        if (!error) {
            add_ipv6_netaddr(laddrs, ip6, plen);
        } else {
            free(error);
            break;
        }
        buf += buf_index;
    }

    *ofs = buf - start;
    return true;
}

/* Extracts the mac, IPv4 and IPv6 addresses from * 'address' which
 * should be of the format "MAC [IP1 IP2 ..] .." where IPn should be a
 * valid IPv4 or IPv6 address and stores them in the 'ipv4_addrs' and
 * 'ipv6_addrs' fields of 'laddrs'.  There may be additional content in
 * 'address' after "MAC [IP1 IP2 .. ]".  The value of 'ofs' that is
 * returned indicates the offset where that additional content begins.
 *
 * Returns true if at least 'MAC' is found in 'address', false otherwise.
 *
 * The caller must call destroy_lport_addresses(). */
bool
extract_addresses(const char *address, struct lport_addresses *laddrs,
                  int *ofs)
{
    return parse_and_store_addresses(address, laddrs, ofs, true);
}

/* Extracts the mac, IPv4 and IPv6 addresses from * 'address' which
 * should be of the format 'MAC [IP1 IP2 ..]" where IPn should be a
 * valid IPv4 or IPv6 address and stores them in the 'ipv4_addrs' and
 * 'ipv6_addrs' fields of 'laddrs'.
 *
 * Return true if at least 'MAC' is found in 'address', false otherwise.
 *
 * The caller must call destroy_lport_addresses(). */
bool
extract_lsp_addresses(const char *address, struct lport_addresses *laddrs)
{
    int ofs;
    bool success = extract_addresses(address, laddrs, &ofs);

    if (success && address[ofs]) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl, "invalid syntax '%s' in address", address);
    }

    return success;
}

/* Extracts the IPv4 and IPv6 addresses from * 'address' which
 * should be of the format 'IP1 IP2 .." where IPn should be a
 * valid IPv4 or IPv6 address and stores them in the 'ipv4_addrs' and
 * 'ipv6_addrs' fields of 'laddrs'.
 *
 * Return true if at least one IP address is found in 'address',
 * false otherwise.
 *
 * The caller must call destroy_lport_addresses(). */
bool
extract_ip_addresses(const char *address, struct lport_addresses *laddrs)
{
    int ofs;
    if (parse_and_store_addresses(address, laddrs, &ofs, false)) {
        return (laddrs->n_ipv4_addrs || laddrs->n_ipv6_addrs);
    }

    return false;
}

/* Extracts at most one IPv4 and at most one IPv6 address from 'address'
 * which should be of the format 'IP1 [IP2]'.
 *
 * Return true if at most one IPv4 address and at most one IPv6 address
 * is found in 'address'.  IPs must be host IPs, i.e., no unmasked bits.
 *
 * The caller must call destroy_lport_addresses().
 */
bool extract_ip_address(const char *address, struct lport_addresses *laddrs)
{
    if (!extract_ip_addresses(address, laddrs) ||
            laddrs->n_ipv4_addrs > 1 ||
            laddrs->n_ipv6_addrs > 1 ||
            (laddrs->n_ipv4_addrs && laddrs->ipv4_addrs[0].plen != 32) ||
            (laddrs->n_ipv6_addrs && laddrs->ipv6_addrs[0].plen != 128)) {
        destroy_lport_addresses(laddrs);
        return false;
    }
    return true;
}

/* Extracts the mac, IPv4 and IPv6 addresses from the
 * "nbrec_logical_router_port" parameter 'lrp'.  Stores the IPv4 and
 * IPv6 addresses in the 'ipv4_addrs' and 'ipv6_addrs' fields of
 * 'laddrs', respectively.  In addition, a link local IPv6 address
 * based on the 'mac' member of 'lrp' is added to the 'ipv6_addrs'
 * field.
 *
 * Return true if a valid 'mac' address is found in 'lrp', false otherwise.
 *
 * The caller must call destroy_lport_addresses(). */
bool
extract_lrp_networks(const struct nbrec_logical_router_port *lrp,
                     struct lport_addresses *laddrs)
{
    return extract_lrp_networks__(lrp->mac, lrp->networks, lrp->n_networks,
                                  laddrs);
}

/* Separate out the body of 'extract_lrp_networks()' for use from DDlog,
 * which does not know the 'nbrec_logical_router_port' type. */
bool
extract_lrp_networks__(char *mac, char **networks, size_t n_networks,
                       struct lport_addresses *laddrs)
{
    memset(laddrs, 0, sizeof *laddrs);

    if (!eth_addr_from_string(mac, &laddrs->ea)) {
        laddrs->ea = eth_addr_zero;
        return false;
    }
    snprintf(laddrs->ea_s, sizeof laddrs->ea_s, ETH_ADDR_FMT,
             ETH_ADDR_ARGS(laddrs->ea));

    for (int i = 0; i < n_networks; i++) {
        ovs_be32 ip4;
        struct in6_addr ip6;
        unsigned int plen;
        char *error;

        error = ip_parse_cidr(networks[i], &ip4, &plen);
        if (!error) {
            if (!ip4) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "bad 'networks' %s", networks[i]);
                continue;
            }

            add_ipv4_netaddr(laddrs, ip4, plen);
            continue;
        }
        free(error);

        error = ipv6_parse_cidr(networks[i], &ip6, &plen);
        if (!error) {
            add_ipv6_netaddr(laddrs, ip6, plen);
        } else {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_INFO_RL(&rl, "invalid syntax '%s' in networks",
                         networks[i]);
            free(error);
        }
    }

    /* Always add the IPv6 link local address. */
    struct in6_addr lla;
    in6_generate_lla(laddrs->ea, &lla);
    add_ipv6_netaddr(laddrs, lla, 64);

    return true;
}

bool
extract_sbrec_binding_first_mac(const struct sbrec_port_binding *binding,
                                struct eth_addr *ea)
{
    char *save_ptr = NULL;
    bool ret = false;

    if (!binding->n_mac) {
        return ret;
    }

    char *tokstr = xstrdup(binding->mac[0]);

    for (char *token = strtok_r(tokstr, " ", &save_ptr);
         token != NULL;
         token = strtok_r(NULL, " ", &save_ptr)) {

        /* Return the first chassis mac. */
        char *err_str = str_to_mac(token, ea);
        if (err_str) {
            free(err_str);
            continue;
        }

        ret = true;
        break;
    }

    free(tokstr);
    return ret;
}

bool
lport_addresses_is_empty(struct lport_addresses *laddrs)
{
    return !laddrs->n_ipv4_addrs && !laddrs->n_ipv6_addrs;
}

void
destroy_lport_addresses(struct lport_addresses *laddrs)
{
    free(laddrs->ipv4_addrs);
    free(laddrs->ipv6_addrs);
}

/* Returns a string of the IP address of 'laddrs' that overlaps with 'ip_s'.
 * If one is not found, returns NULL.
 *
 * The caller must not free the returned string. */
const char *
find_lport_address(const struct lport_addresses *laddrs, const char *ip_s)
{
    bool is_ipv4 = strchr(ip_s, '.') ? true : false;

    if (is_ipv4) {
        ovs_be32 ip;

        if (!ip_parse(ip_s, &ip)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad ip address %s", ip_s);
            return NULL;
        }

        for (int i = 0; i < laddrs->n_ipv4_addrs; i++) {
            const struct ipv4_netaddr *na = &laddrs->ipv4_addrs[i];

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

        for (int i = 0; i < laddrs->n_ipv6_addrs; i++) {
            const struct ipv6_netaddr *na = &laddrs->ipv6_addrs[i];
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

/* Go through 'addresses' and add found IPv4 addresses to 'ipv4_addrs' and
 * IPv6 addresses to 'ipv6_addrs'. */
void
split_addresses(const char *addresses, struct svec *ipv4_addrs,
                struct svec *ipv6_addrs)
{
    struct lport_addresses laddrs;
    extract_lsp_addresses(addresses, &laddrs);
    for (size_t k = 0; k < laddrs.n_ipv4_addrs; k++) {
        svec_add(ipv4_addrs, laddrs.ipv4_addrs[k].addr_s);
    }
    for (size_t k = 0; k < laddrs.n_ipv6_addrs; k++) {
        svec_add(ipv6_addrs, laddrs.ipv6_addrs[k].addr_s);
    }
    destroy_lport_addresses(&laddrs);
}

/* Allocates a key for NAT conntrack zone allocation for a provided
 * 'key' record and a 'type'.
 *
 * It is the caller's responsibility to free the allocated memory. */
char *
alloc_nat_zone_key(const char *name, const char *type)
{
    return xasprintf("%s_%s", name, type);
}

const char *
default_nb_db(void)
{
    static char *def;
    if (!def) {
        def = getenv("OVN_NB_DB");
        if (!def) {
            def = xasprintf("unix:%s/ovnnb_db.sock", ovn_rundir());
        }
    }
    return def;
}

const char *
default_sb_db(void)
{
    static char *def;
    if (!def) {
        def = getenv("OVN_SB_DB");
        if (!def) {
            def = xasprintf("unix:%s/ovnsb_db.sock", ovn_rundir());
        }
    }
    return def;
}

const char *
default_ic_nb_db(void)
{
    static char *def;
    if (!def) {
        def = getenv("OVN_IC_NB_DB");
        if (!def) {
            def = xasprintf("unix:%s/ovn_ic_nb_db.sock", ovn_rundir());
        }
    }
    return def;
}

const char *
default_ic_sb_db(void)
{
    static char *def;
    if (!def) {
        def = getenv("OVN_IC_SB_DB");
        if (!def) {
            def = xasprintf("unix:%s/ovn_ic_sb_db.sock", ovn_rundir());
        }
    }
    return def;
}

char *
get_abs_unix_ctl_path(const char *path)
{
#ifdef _WIN32
    enum { WINDOWS = 1 };
#else
    enum { WINDOWS = 0 };
#endif

    long int pid = getpid();
    char *abs_path
        = (path ? abs_file_name(ovn_rundir(), path)
           : WINDOWS ? xasprintf("%s/%s.ctl", ovn_rundir(), program_name)
           : xasprintf("%s/%s.%ld.ctl", ovn_rundir(), program_name, pid));
    return abs_path;
}

void
ovn_set_pidfile(const char *name)
{
    char *pidfile_name = NULL;

#ifndef _WIN32
    pidfile_name = name ? abs_file_name(ovn_rundir(), name)
                        : xasprintf("%s/%s.pid", ovn_rundir(), program_name);
#else
    if (name) {
        if (strchr(name, ':')) {
            pidfile_name = xstrdup(name);
        } else {
            pidfile_name = xasprintf("%s/%s", ovn_rundir(), name);
        }
    } else {
        pidfile_name = xasprintf("%s/%s.pid", ovn_rundir(), program_name);
    }
#endif

    /* Call openvswitch lib function. */
    set_pidfile(pidfile_name);
    free(pidfile_name);
}

/* l3gateway, chassisredirect, and patch
 * are not in this list since they are
 * only set in the SB DB by northd
 */
static const char *OVN_NB_LSP_TYPES[] = {
    "l2gateway",
    "localnet",
    "localport",
    "router",
    "vtep",
    "external",
    "virtual",
    "remote",
};

bool
ovn_is_known_nb_lsp_type(const char *type)
{
    int i;

    if (!type || !type[0]) {
        return true;
    }

    for (i = 0; i < ARRAY_SIZE(OVN_NB_LSP_TYPES); ++i) {
        if (!strcmp(OVN_NB_LSP_TYPES[i], type)) {
            return true;
        }
    }

    return false;
}

static enum ovn_pipeline
ovn_pipeline_from_name(const char *pipeline)
{
    return pipeline[0] == 'i' ? P_IN : P_OUT;
}

uint32_t
sbrec_logical_flow_hash(const struct sbrec_logical_flow *lf)
{
    const struct sbrec_datapath_binding *ld = lf->logical_datapath;
    uint32_t hash = ovn_logical_flow_hash(lf->table_id,
                                          ovn_pipeline_from_name(lf->pipeline),
                                          lf->priority, lf->match,
                                          lf->actions);

    return ld ? ovn_logical_flow_hash_datapath(&ld->header_.uuid, hash) : hash;
}

uint32_t
ovn_logical_flow_hash(uint8_t table_id, enum ovn_pipeline pipeline,
                      uint16_t priority,
                      const char *match, const char *actions)
{
    size_t hash = hash_2words((table_id << 16) | priority, pipeline);
    hash = hash_string(match, hash);
    return hash_string(actions, hash);
}

uint32_t
ovn_logical_flow_hash_datapath(const struct uuid *logical_datapath,
                               uint32_t hash)
{
    return hash_add(hash, uuid_hash(logical_datapath));
}


struct tnlid_node {
    struct hmap_node hmap_node;
    uint32_t tnlid;
};

void
ovn_destroy_tnlids(struct hmap *tnlids)
{
    struct tnlid_node *node;
    HMAP_FOR_EACH_POP (node, hmap_node, tnlids) {
        free(node);
    }
    hmap_destroy(tnlids);
}

/* Returns true if 'tnlid' is present in the hmap 'tnlids'. */
bool
ovn_tnlid_present(struct hmap *tnlids, uint32_t tnlid)
{
    uint32_t hash = hash_int(tnlid, 0);
    struct tnlid_node *node;
    HMAP_FOR_EACH_IN_BUCKET (node, hmap_node, hash, tnlids) {
        if (node->tnlid == tnlid) {
            return true;
        }
    }

    return false;
}

bool
ovn_add_tnlid(struct hmap *set, uint32_t tnlid)
{
    if (ovn_tnlid_present(set, tnlid)) {
        return false;
    }

    uint32_t hash = hash_int(tnlid, 0);
    struct tnlid_node *node = xmalloc(sizeof *node);
    hmap_insert(set, &node->hmap_node, hash);
    node->tnlid = tnlid;
    return true;
}

static uint32_t
next_tnlid(uint32_t tnlid, uint32_t min, uint32_t max)
{
    return tnlid + 1 <= max ? tnlid + 1 : min;
}

uint32_t
ovn_allocate_tnlid(struct hmap *set, const char *name, uint32_t min,
                   uint32_t max, uint32_t *hint)
{
    for (uint32_t tnlid = next_tnlid(*hint, min, max); tnlid != *hint;
         tnlid = next_tnlid(tnlid, min, max)) {
        if (ovn_add_tnlid(set, tnlid)) {
            *hint = tnlid;
            return tnlid;
        }
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    VLOG_WARN_RL(&rl, "all %s tunnel ids exhausted", name);
    return 0;
}

bool
ovn_free_tnlid(struct hmap *tnlids, uint32_t tnlid)
{
    uint32_t hash = hash_int(tnlid, 0);
    struct tnlid_node *node;
    HMAP_FOR_EACH_IN_BUCKET (node, hmap_node, hash, tnlids) {
        if (node->tnlid == tnlid) {
            hmap_remove(tnlids, &node->hmap_node);
            free(node);
            return true;
        }
    }
    return false;
}

char *
ovn_chassis_redirect_name(const char *port_name)
{
    return xasprintf("cr-%s", port_name);
}

bool
ip46_parse_cidr(const char *str, struct in6_addr *prefix, unsigned int *plen)
{
    ovs_be32 ipv4;
    char *error = ip_parse_cidr(str, &ipv4, plen);

    if (!error) {
        in6_addr_set_mapped_ipv4(prefix, ipv4);
        return true;
    }
    free(error);
    error = ipv6_parse_cidr(str, prefix, plen);
    if (!error) {
        return true;
    }
    free(error);
    return false;
}

bool
ip46_parse(const char *ip_str, struct in6_addr *ip)
{
    ovs_be32 ipv4;
    if (ip_parse(ip_str, &ipv4)) {
        *ip = in6_addr_mapped_ipv4(ipv4);
        return true;
    }

    return ipv6_parse(ip_str, ip);
}

/* The caller must free the returned string. */
char *
normalize_ipv4_prefix(ovs_be32 ipv4, unsigned int plen)
{
    ovs_be32 network = ipv4 & be32_prefix_mask(plen);
    if (plen == 32) {
        return xasprintf(IP_FMT, IP_ARGS(network));
    } else {
        return xasprintf(IP_FMT "/%d", IP_ARGS(network), plen);
    }
}

/* The caller must free the returned string. */
char *
normalize_ipv6_prefix(const struct in6_addr *ipv6, unsigned int plen)
{
    char network_s[INET6_ADDRSTRLEN];

    struct in6_addr mask = ipv6_create_mask(plen);
    struct in6_addr network = ipv6_addr_bitand(ipv6, &mask);

    inet_ntop(AF_INET6, &network, network_s, INET6_ADDRSTRLEN);
    if (plen == 128) {
        return xasprintf("%s", network_s);
    } else {
        return xasprintf("%s/%d", network_s, plen);
    }
}

char *
normalize_v46_prefix(const struct in6_addr *prefix, unsigned int plen)
{
    if (IN6_IS_ADDR_V4MAPPED(prefix)) {
        return normalize_ipv4_prefix(in6_addr_get_mapped_ipv4(prefix), plen);
    } else {
        return normalize_ipv6_prefix(prefix, plen);
    }
}

char *
str_tolower(const char *orig)
{
    char *copy = xmalloc(strlen(orig) + 1);
    char *p = copy;

    while (*orig) {
        *p++ = tolower(*orig++);
    }
    *p = '\0';

    return copy;
}

/* This is a wrapper function which get the value associated with 'key' in
 * 'smap' and converts it to an unsigned int. If 'key' is not in 'smap' or a
 * valid unsigned integer can't be parsed from it's value, returns 'def'.
 *
 * Note: Remove this function once OpenvSwitch library (lib/smap.h) has this
 * helper function.
 */
unsigned int
ovn_smap_get_uint(const struct smap *smap, const char *key, unsigned int def)
{
    const char *value = smap_get(smap, key);
    unsigned int u_value;

    if (!value || !str_to_uint(value, 10, &u_value)) {
        return def;
    }

    return u_value;
}

/* For a 'key' of the form "IP:port" or just "IP", sets 'port',
 * 'ip_address' and 'ip' ('struct in6_addr' IPv6 or IPv4 mapped address).
 * The caller must free() the memory allocated for 'ip_address'.
 * Returns true if parsing of 'key' was successful, false otherwise.
 */
bool
ip_address_and_port_from_lb_key(const char *key, char **ip_address,
                                struct in6_addr *ip, uint16_t *port,
                                int *addr_family)
{
    struct sockaddr_storage ss;
    if (!inet_parse_active(key, 0, &ss, false, NULL)) {
        *ip_address = NULL;
        memset(ip, 0, sizeof(*ip));
        *port = 0;
        *addr_family = 0;
        return false;
    }

    struct ds s = DS_EMPTY_INITIALIZER;
    ss_format_address_nobracks(&ss, &s);
    *ip_address = ds_steal_cstr(&s);
    *ip = ss_get_address(&ss);
    *port = ss_get_port(&ss);
    *addr_family = ss.ss_family;
    return true;
}

/* Increment this for any logical flow changes, if an existing OVN action is
 * modified or a stage is added to a logical pipeline.
 *
 * This value is also used to handle some backward compatibility during
 * upgrading. It should never decrease or rewind. */
#define OVN_INTERNAL_MINOR_VER 6

/* Returns the OVN version. The caller must free the returned value. */
char *
ovn_get_internal_version(void)
{
    return xasprintf("%s-%s-%d.%d", OVN_PACKAGE_VERSION,
                     sbrec_get_db_version(),
                     N_OVNACTS, OVN_INTERNAL_MINOR_VER);
}

#ifdef DDLOG
/* Callbacks used by the ddlog northd code to print warnings and errors. */
void
ddlog_warn(const char *msg)
{
    VLOG_WARN("%s", msg);
}

void
ddlog_err(const char *msg)
{
    VLOG_ERR("%s", msg);
}
#endif

uint32_t
get_tunnel_type(const char *name)
{
    if (!strcmp(name, "geneve")) {
        return GENEVE;
    } else if (!strcmp(name, "stt")) {
        return STT;
    } else if (!strcmp(name, "vxlan")) {
        return VXLAN;
    }

    return 0;
}

const struct ovsrec_bridge *
get_bridge(const struct ovsrec_bridge_table *bridge_table, const char *br_name)
{
    const struct ovsrec_bridge *br;
    OVSREC_BRIDGE_TABLE_FOR_EACH (br, bridge_table) {
        if (!strcmp(br->name, br_name)) {
            return br;
        }
    }
    return NULL;
}

#define DAEMON_STARTUP_DELAY_SEED 20
#define DAEMON_STARTUP_DELAY_MS   10000

static int64_t startup_ts;
static int startup_delay = DAEMON_STARTUP_DELAY_SEED;

/* Used by debug command only, for tests. */
static bool ignore_startup_delay = false;

OVS_CONSTRUCTOR(startup_ts_initializer) {
    startup_ts = time_wall_msec();
}

int64_t
daemon_startup_ts(void)
{
    return startup_ts;
}

void
daemon_started_recently_countdown(void)
{
    if (startup_delay > 0) {
        startup_delay--;
    }
}

void
daemon_started_recently_ignore(void)
{
    ignore_startup_delay = true;
}

bool
daemon_started_recently(void)
{
    if (ignore_startup_delay) {
        return false;
    }

    VLOG_DBG("startup_delay: %d, startup_ts: %"PRId64, startup_delay,
             startup_ts);

    /* Ensure that at least an amount of updates has been handled. */
    if (startup_delay) {
        return true;
    }

    /* Ensure that at least an amount of time has passed. */
    return time_wall_msec() - startup_ts <= DAEMON_STARTUP_DELAY_MS;
}

/* Builds a unique address set compatible name ([a-zA-Z_.][a-zA-Z_.0-9]*)
 * for the router's load balancer VIP address set, combining the logical
 * router's datapath tunnel key and address family.
 *
 * Also prefixes the name with 'prefix'.
 */
static char *
lr_lb_address_set_name_(uint32_t lr_tunnel_key, const char *prefix,
                        int addr_family)
{
    return xasprintf("%s_rtr_lb_%"PRIu32"_ip%s", prefix, lr_tunnel_key,
                     addr_family == AF_INET ? "4" : "6");
}

/* Builds the router's load balancer VIP address set name. */
char *
lr_lb_address_set_name(uint32_t lr_tunnel_key, int addr_family)
{
    return lr_lb_address_set_name_(lr_tunnel_key, "", addr_family);
}

/* Builds a string that refers to the the router's load balancer VIP address
 * set name, that is: $<address_set_name>.
 */
char *
lr_lb_address_set_ref(uint32_t lr_tunnel_key, int addr_family)
{
    return lr_lb_address_set_name_(lr_tunnel_key, "$", addr_family);
}

static char *
chassis_option_key(const char *option_key, const char *chassis_id)
{
    if (!chassis_id) {
        return xasprintf("%s", option_key);
    }
    return xasprintf("%s-%s", option_key, chassis_id);
}

const char *
get_chassis_external_id_value(const struct smap *external_ids,
                              const char *chassis_id,
                              const char *option_key,
                              const char *def)
{
    char *chassis_key = chassis_option_key(option_key, chassis_id);
    const char *ret =
        smap_get_def(external_ids, chassis_key,
                     smap_get_def(external_ids, option_key, def));
    free(chassis_key);
    return ret;
}

int
get_chassis_external_id_value_int(const struct smap *external_ids,
                                  const char *chassis_id,
                                  const char *option_key,
                                  int def)
{
    char *chassis_key = chassis_option_key(option_key, chassis_id);
    int ret =
        smap_get_int(external_ids, chassis_key,
                     smap_get_int(external_ids, option_key, def));
    free(chassis_key);
    return ret;
}

unsigned int
get_chassis_external_id_value_uint(const struct smap *external_ids,
                                   const char *chassis_id,
                                   const char *option_key,
                                   unsigned int def)
{
    char *chassis_key = chassis_option_key(option_key, chassis_id);
    unsigned int ret =
        smap_get_uint(external_ids, chassis_key,
                      smap_get_uint(external_ids, option_key, def));
    free(chassis_key);
    return ret;
}

unsigned long long int
get_chassis_external_id_value_ullong(const struct smap *external_ids,
                                     const char *chassis_id,
                                     const char *option_key,
                                     unsigned long long int def)
{
    char *chassis_key = chassis_option_key(option_key, chassis_id);
    unsigned long long int ret =
        smap_get_ullong(external_ids, chassis_key,
                        smap_get_ullong(external_ids, option_key, def));
    free(chassis_key);
    return ret;
}

bool
get_chassis_external_id_value_bool(const struct smap *external_ids,
                                   const char *chassis_id,
                                   const char *option_key,
                                   bool def)
{
    char *chassis_key = chassis_option_key(option_key, chassis_id);
    bool ret =
        smap_get_bool(external_ids, chassis_key,
                      smap_get_bool(external_ids, option_key, def));
    free(chassis_key);
    return ret;
}

void flow_collector_ids_init(struct flow_collector_ids *ids)
{
    ovs_list_init(&ids->list);
}

void flow_collector_ids_init_from_table(struct flow_collector_ids *ids,
    const struct ovsrec_flow_sample_collector_set_table *table)
{
    flow_collector_ids_init(ids);
    const struct ovsrec_flow_sample_collector_set *ovs_collector_set;
    OVSREC_FLOW_SAMPLE_COLLECTOR_SET_TABLE_FOR_EACH (ovs_collector_set,
                                                    table) {
        flow_collector_ids_add(ids, ovs_collector_set->id);
    }
}

void flow_collector_ids_add(struct flow_collector_ids *ids,
                            uint64_t id)
{
    struct flow_collector_id *collector = xzalloc(sizeof *collector);
    collector->id = id;
    ovs_list_push_back(&ids->list, &collector->node);
}

bool flow_collector_ids_lookup(const struct flow_collector_ids *ids,
                               uint32_t id)
{
    struct flow_collector_id *collector;
    LIST_FOR_EACH (collector, node, &ids->list) {
        if (collector->id == id) {
          return true;
        }
    }
    return false;
}

void flow_collector_ids_destroy(struct flow_collector_ids *ids)
{
    struct flow_collector_id *collector;
    LIST_FOR_EACH_SAFE (collector, node, &ids->list) {
        ovs_list_remove(&collector->node);
        free(collector);
    }
}

void flow_collector_ids_clear(struct flow_collector_ids *ids)
{
    flow_collector_ids_destroy(ids);
    flow_collector_ids_init(ids);
}

char *
encode_fqdn_string(const char *fqdn, size_t *len)
{

    size_t domain_len = strlen(fqdn);
    *len = domain_len + 2;
    char *encoded = xzalloc(*len);

    int8_t label_len = 0;
    for (size_t i = 0; i < domain_len; i++) {
        if (fqdn[i] == '.') {
            encoded[i - label_len] = label_len;
            label_len = 0;
        } else {
            encoded[i + 1] = fqdn[i];
            label_len++;
        }
    }

    /* This is required for the last label if it doesn't end with '.' */
    if (label_len) {
        encoded[domain_len - label_len] = label_len;
    }

    return encoded;
}

static bool
is_lport_vif(const struct sbrec_port_binding *pb)
{
    return !pb->type[0];
}

enum en_lport_type
get_lport_type(const struct sbrec_port_binding *pb)
{
    if (is_lport_vif(pb)) {
        if (pb->parent_port && pb->parent_port[0]) {
            return LP_CONTAINER;
        }
        return LP_VIF;
    } else if (!strcmp(pb->type, "patch")) {
        return LP_PATCH;
    } else if (!strcmp(pb->type, "chassisredirect")) {
        return LP_CHASSISREDIRECT;
    } else if (!strcmp(pb->type, "l3gateway")) {
        return LP_L3GATEWAY;
    } else if (!strcmp(pb->type, "localnet")) {
        return LP_LOCALNET;
    } else if (!strcmp(pb->type, "localport")) {
        return LP_LOCALPORT;
    } else if (!strcmp(pb->type, "l2gateway")) {
        return LP_L2GATEWAY;
    } else if (!strcmp(pb->type, "virtual")) {
        return LP_VIRTUAL;
    } else if (!strcmp(pb->type, "external")) {
        return LP_EXTERNAL;
    } else if (!strcmp(pb->type, "remote")) {
        return LP_REMOTE;
    } else if (!strcmp(pb->type, "vtep")) {
        return LP_VTEP;
    }

    return LP_UNKNOWN;
}

char *
get_lport_type_str(enum en_lport_type lport_type)
{
    switch (lport_type) {
    case LP_VIF:
        return "VIF";
    case LP_CONTAINER:
        return "CONTAINER";
    case LP_VIRTUAL:
        return "VIRTUAL";
    case LP_PATCH:
        return "PATCH";
    case LP_CHASSISREDIRECT:
        return "CHASSISREDIRECT";
    case LP_L3GATEWAY:
        return "L3GATEWAY";
    case LP_LOCALNET:
        return "LOCALNET";
    case LP_LOCALPORT:
        return "LOCALPORT";
    case LP_L2GATEWAY:
        return "L2GATEWAY";
    case LP_EXTERNAL:
        return "EXTERNAL";
    case LP_REMOTE:
        return "REMOTE";
    case LP_VTEP:
        return "VTEP";
    case LP_UNKNOWN:
        return "UNKNOWN";
    }

    OVS_NOT_REACHED();
}

bool
is_pb_router_type(const struct sbrec_port_binding *pb)
{
    enum en_lport_type lport_type = get_lport_type(pb);

    switch (lport_type) {
    case LP_PATCH:
    case LP_CHASSISREDIRECT:
    case LP_L3GATEWAY:
    case LP_L2GATEWAY:
        return true;

    case LP_VIF:
    case LP_CONTAINER:
    case LP_VIRTUAL:
    case LP_LOCALNET:
    case LP_LOCALPORT:
    case LP_REMOTE:
    case LP_VTEP:
    case LP_EXTERNAL:
    case LP_UNKNOWN:
        return false;
    }

    return false;
}

void
sorted_array_apply_diff(const struct sorted_array *a1,
                        const struct sorted_array *a2,
                        void (*apply_callback)(const void *arg,
                                               const char *item,
                                               bool add),
                        const void *arg)
{
    size_t idx1, idx2;

    for (idx1 = idx2 = 0; idx1 < a1->n && idx2 < a2->n;) {
        int cmp = strcmp(a1->arr[idx1], a2->arr[idx2]);
        if (cmp < 0) {
            apply_callback(arg, a1->arr[idx1], true);
            idx1++;
        } else if (cmp > 0) {
            apply_callback(arg, a2->arr[idx2], false);
            idx2++;
        } else {
            idx1++;
            idx2++;
        }
    }

    for (; idx1 < a1->n; idx1++) {
        apply_callback(arg, a1->arr[idx1], true);
    }

    for (; idx2 < a2->n; idx2++) {
        apply_callback(arg, a2->arr[idx2], false);
    }
}

/* Call for the unixctl command that will store the connection and
 * set the appropriate conditions. */
void
ovn_exit_command_callback(struct unixctl_conn *conn, int argc,
                          const char *argv[], void *exit_args_)
{
    struct ovn_exit_args *exit_args = exit_args_;

    exit_args->n_conns++;
    exit_args->conns = xrealloc(exit_args->conns,
                                exit_args->n_conns * sizeof *exit_args->conns);

    exit_args->exiting = true;
    exit_args->conns[exit_args->n_conns - 1] = conn;

    if (!exit_args->restart) {
        exit_args->restart = argc == 2 && !strcmp(argv[1], "--restart");
    }
}

/* Reply to all waiting unixctl connections and free the connection array.
 * This function should be called after the heaviest cleanup has finished. */
void
ovn_exit_args_finish(struct ovn_exit_args *exit_args)
{
    for (size_t i = 0; i < exit_args->n_conns; i++) {
        unixctl_command_reply(exit_args->conns[i], NULL);
    }
    free(exit_args->conns);
}
