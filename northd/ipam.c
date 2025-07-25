#include <config.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "ipam.h"
#include "northd.h"
#include "ovn/lex.h"

#include "smap.h"
#include "packets.h"
#include "bitmap.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ipam)

static void init_ipam_ipv6_prefix(const char *ipv6_prefix,
                                  struct ipam_info *info);
static void init_ipam_ipv4(const char *subnet_str,
                           const char *exclude_ip_list,
                           struct ipam_info *info);
static bool ipam_is_duplicate_mac(struct eth_addr *ea, uint64_t mac64,
                                  bool warn);

static void ipam_insert_ip_for_datapath(struct ovn_datapath *, uint32_t, bool);

static void ipam_insert_lsp_addresses(struct ovn_datapath *,
                                      struct lport_addresses *);

static enum dynamic_update_type dynamic_mac_changed(const char *,
    struct dynamic_address_update *);

static enum dynamic_update_type dynamic_ip4_changed(const char *,
    struct dynamic_address_update *);

static enum dynamic_update_type dynamic_ip6_changed(const char *,
    struct dynamic_address_update *);

static bool dynamic_addresses_check_for_updates(const char *,
    struct dynamic_address_update *);

static void update_unchanged_dynamic_addresses(
    struct dynamic_address_update *);

static void set_lsp_dynamic_addresses(const char *,
                                      struct ovn_port *);

static void set_dynamic_updates(const char *,
                                struct dynamic_address_update *);

void
init_ipam_info(struct ipam_info *info, const struct smap *config, const char *id)
{
    const char *subnet_str = smap_get(config, "subnet");
    const char *ipv6_prefix = smap_get(config, "ipv6_prefix");
    const char *exclude_ips = smap_get(config, "exclude_ips");

    info->id = xstrdup(id ? id : "<unknown>");

    init_ipam_ipv4(subnet_str, exclude_ips, info);
    init_ipam_ipv6_prefix(ipv6_prefix, info);

    if (!subnet_str && !ipv6_prefix) {
        info->mac_only = smap_get_bool(config, "mac_only", false);
    }
}

void
init_ipam_info_for_datapath(struct ovn_datapath *od)
{
    if (!od->nbs || od->ipam_info_initialized) {
        return;
    }

    char uuid_s[UUID_LEN + 1];
    sprintf(uuid_s, UUID_FMT, UUID_ARGS(&od->key));
    init_ipam_info(&od->ipam_info, &od->nbs->other_config, uuid_s);
    od->ipam_info_initialized = true;
}

void
destroy_ipam_info(struct ipam_info *info)
{
    bitmap_free(info->allocated_ipv4s);
    free(CONST_CAST(char *, info->id));
}

bool
ipam_insert_ip(struct ipam_info *info, uint32_t ip, bool dynamic)
{
    if (!info->allocated_ipv4s) {
        return true;
    }

    if (ip >= info->start_ipv4 &&
        ip < (info->start_ipv4 + info->total_ipv4s)) {
        if (dynamic && bitmap_is_set(info->allocated_ipv4s,
                                     ip - info->start_ipv4)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "%s: Duplicate IP set: " IP_FMT,
                         info->id, IP_ARGS(htonl(ip)));
            return false;
        }
        bitmap_set1(info->allocated_ipv4s,
                    ip - info->start_ipv4);
    }
    return true;
}

static void
ipam_insert_ip_for_datapath(struct ovn_datapath *od, uint32_t ip,
                            bool dynamic)
{
    if (!od) {
        return;
    }

    ipam_insert_ip(&od->ipam_info, ip, dynamic);
}

uint32_t
ipam_get_unused_ip(struct ipam_info *info)
{
    if (!info->allocated_ipv4s) {
        return 0;
    }

    size_t new_ip_index = bitmap_scan(info->allocated_ipv4s, 0, 0,
                                      info->total_ipv4s - 1);
    if (new_ip_index == info->total_ipv4s - 1) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "%s: Subnet address space has been exhausted.",
                     info->id);
        return 0;
    }

    return info->start_ipv4 + new_ip_index;
}

/* MAC address management (macam) table of "struct eth_addr"s, that holds the
 * MAC addresses allocated by the OVN ipam module. */
static struct hmap macam = HMAP_INITIALIZER(&macam);

struct macam_node {
    struct hmap_node hmap_node;
    struct eth_addr mac_addr; /* Allocated MAC address. */
};

#define MAC_ADDR_SPACE 0xffffff
static struct eth_addr mac_prefix;
static char mac_prefix_str[18];

void
ipam_insert_mac(struct eth_addr *ea, bool check)
{
    if (!ea) {
        return;
    }

    uint64_t mac64 = eth_addr_to_uint64(*ea);
    uint64_t prefix = eth_addr_to_uint64(mac_prefix);

    /* If the new MAC was not assigned by this address management system or
     * check is true and the new MAC is a duplicate, do not insert it into the
     * macam hmap. */
    if (((mac64 ^ prefix) >> 24)
        || (check && ipam_is_duplicate_mac(ea, mac64, true))) {
        return;
    }

    struct macam_node *new_macam_node = xmalloc(sizeof *new_macam_node);
    new_macam_node->mac_addr = *ea;
    hmap_insert(&macam, &new_macam_node->hmap_node, hash_uint64(mac64));
}

uint64_t
ipam_get_unused_mac(ovs_be32 ip)
{
    uint32_t mac_addr_suffix, i, base_addr = ntohl(ip) & MAC_ADDR_SPACE;
    struct eth_addr mac;
    uint64_t mac64;

    for (i = 0; i < MAC_ADDR_SPACE - 1; i++) {
        /* The tentative MAC's suffix will be in the interval (1, 0xfffffe). */
        mac_addr_suffix = ((base_addr + i) % (MAC_ADDR_SPACE - 1)) + 1;
        mac64 =  eth_addr_to_uint64(mac_prefix) | mac_addr_suffix;
        eth_addr_from_uint64(mac64, &mac);
        if (!ipam_is_duplicate_mac(&mac, mac64, false)) {
            break;
        }
    }

    if (i == MAC_ADDR_SPACE) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "MAC address space exhausted.");
        mac64 = 0;
    }

    return mac64;
}

void
cleanup_macam(void)
{
    struct macam_node *node;
    HMAP_FOR_EACH_POP (node, hmap_node, &macam) {
        free(node);
    }
}

struct eth_addr
get_mac_prefix(void)
{
    return mac_prefix;
}

const char *
set_mac_prefix(const char *prefix)
{
    mac_prefix = eth_addr_zero;
    if (prefix) {
        struct eth_addr addr;

        memset(&addr, 0, sizeof addr);
        if (ovs_scan(prefix, "%"SCNx8":%"SCNx8":%"SCNx8,
                     &addr.ea[0], &addr.ea[1], &addr.ea[2])) {
            mac_prefix = addr;
        }
    }

    if (eth_addr_equals(mac_prefix, eth_addr_zero)) {
        eth_addr_random(&mac_prefix);
        memset(&mac_prefix.ea[3], 0, 3);
    }

    snprintf(mac_prefix_str, sizeof(mac_prefix_str),
             "%02"PRIx8":%02"PRIx8":%02"PRIx8,
             mac_prefix.ea[0], mac_prefix.ea[1], mac_prefix.ea[2]);

    return mac_prefix_str;
}

static void
init_ipam_ipv6_prefix(const char *ipv6_prefix, struct ipam_info *info)
{
    info->ipv6_prefix_set = false;
    info->ipv6_prefix = in6addr_any;

    if (!ipv6_prefix) {
        return;
    }

    /* XXX Since we only accept /64 addresses, why do we even bother
     * with accepting and trying to analyze a user-provided mask?
     */
    if (strchr(ipv6_prefix, '/')) {
        /* If a prefix length was specified, it must be 64. */
        struct in6_addr mask;
        char *error
            = ipv6_parse_masked(ipv6_prefix,
                                &info->ipv6_prefix, &mask);
        if (error) {
            static struct vlog_rate_limit rl
                = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "%s: bad 'ipv6_prefix' %s: %s",
                         info->id, ipv6_prefix, error);
            free(error);
        } else {
            if (ipv6_count_cidr_bits(&mask) == 64) {
                info->ipv6_prefix_set = true;
            } else {
                static struct vlog_rate_limit rl
                    = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "%s: bad 'ipv6_prefix' %s: must be /64",
                             info->id, ipv6_prefix);
            }
        }
    } else {
        info->ipv6_prefix_set = ipv6_parse(
            ipv6_prefix, &info->ipv6_prefix);
        if (!info->ipv6_prefix_set) {
            static struct vlog_rate_limit rl
                = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "%s: bad 'ipv6_prefix' %s", info->id,
                         ipv6_prefix);
        }
    }

    if (info->ipv6_prefix_set) {
        /* Make sure nothing past first 64 bits are set */
        struct in6_addr mask = ipv6_create_mask(64);
        info->ipv6_prefix = ipv6_addr_bitand(&info->ipv6_prefix, &mask);
    }
}

static void
init_ipam_ipv4(const char *subnet_str, const char *exclude_ip_list,
               struct ipam_info *info)
{
    info->start_ipv4 = 0;
    info->total_ipv4s = 0;
    info->allocated_ipv4s = NULL;

    if (!subnet_str) {
        return;
    }

    ovs_be32 subnet, mask;
    char *error = ip_parse_masked(subnet_str, &subnet, &mask);
    if (error || mask == OVS_BE32_MAX || !ip_is_cidr(mask)) {
        static struct vlog_rate_limit rl
            = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "%s: bad 'subnet' %s", info->id, subnet_str);
        free(error);
        return;
    }

    info->start_ipv4 = ntohl(subnet & mask) + 1;
    info->total_ipv4s = ~ntohl(mask);
    info->allocated_ipv4s =
        bitmap_allocate(info->total_ipv4s);

    /* Mark first IP as taken */
    bitmap_set1(info->allocated_ipv4s, 0);

    if (!exclude_ip_list) {
        return;
    }

    struct lexer lexer;
    lexer_init(&lexer, exclude_ip_list);
    /* exclude_ip_list could be in the format -
    *  "10.0.0.4 10.0.0.10 10.0.0.20..10.0.0.50 10.0.0.100..10.0.0.110".
    */
    lexer_get(&lexer);
    while (lexer.token.type != LEX_T_END) {
        if (lexer.token.type != LEX_T_INTEGER) {
            lexer_syntax_error(&lexer, "expecting address");
            break;
        }
        uint32_t start = ntohl(lexer.token.value.ipv4);
        lexer_get(&lexer);

        uint32_t end = start + 1;
        if (lexer_match(&lexer, LEX_T_ELLIPSIS)) {
            if (lexer.token.type != LEX_T_INTEGER) {
                lexer_syntax_error(&lexer, "expecting address range");
                break;
            }
            end = ntohl(lexer.token.value.ipv4) + 1;
            lexer_get(&lexer);
        }

        /* Clamp start...end to fit the subnet. */
        start = MAX(info->start_ipv4, start);
        end = MIN(info->start_ipv4 + info->total_ipv4s, end);
        if (end > start) {
            bitmap_set_multiple(info->allocated_ipv4s,
                                start - info->start_ipv4,
                                end - start, 1);
        } else {
            lexer_error(&lexer, "excluded addresses not in subnet");
        }
    }
    if (lexer.error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "%s: bad exclude_ips (%s)", info->id, lexer.error);
    }
    lexer_destroy(&lexer);
}

static bool
ipam_is_duplicate_mac(struct eth_addr *ea, uint64_t mac64, bool warn)
{
    struct macam_node *macam_node;
    HMAP_FOR_EACH_WITH_HASH (macam_node, hmap_node, hash_uint64(mac64),
                             &macam) {
        if (eth_addr_equals(*ea, macam_node->mac_addr)) {
            if (warn) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "Duplicate MAC set: "ETH_ADDR_FMT,
                             ETH_ADDR_ARGS(macam_node->mac_addr));
            }
            return true;
        }
    }
    return false;
}

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
                       ntohl(update->current_addresses.ipv4_addrs[0].addr),
                       true);
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

void
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
        ipam_insert_ip_for_datapath(update->od, ntohl(ip4), true);
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


void
update_ipam_ls(struct ovn_datapath *od, struct vector *updates,
               bool recompute)
{
    ovs_assert(od);
    ovs_assert(od->nbs);
    ovs_assert(updates);

    struct ovn_port *op;
    HMAP_FOR_EACH (op, dp_node, &od->ports) {
        const struct nbrec_logical_switch_port *nbsp = op->nbsp;
        ovs_assert(nbsp);

        if (!od->ipam_info.allocated_ipv4s &&
            !od->ipam_info.ipv6_prefix_set &&
            !od->ipam_info.mac_only) {
            if (nbsp->dynamic_addresses) {
                nbrec_logical_switch_port_set_dynamic_addresses(nbsp,
                                                                NULL);
            }
            continue;
        }

        bool has_dynamic_address = false;
        for (size_t j = 0; j < nbsp->n_addresses; j++) {
            if (!is_dynamic_lsp_address(nbsp->addresses[j])) {
                continue;
            }
            if (has_dynamic_address) {
                static struct vlog_rate_limit rl
                    = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "More than one dynamic address "
                             "configured for logical switch port '%s'",
                             nbsp->name);
                continue;
            }
            has_dynamic_address = true;
            struct dynamic_address_update update = {
                .op = op,
                .od = od,
            };
            init_lport_addresses(&update.current_addresses);
            if (nbsp->dynamic_addresses) {
                bool any_changed;
                extract_lsp_addresses(nbsp->dynamic_addresses,
                                      &update.current_addresses);
                any_changed = dynamic_addresses_check_for_updates(
                    nbsp->addresses[j], &update);
                update_unchanged_dynamic_addresses(&update);
                if (any_changed) {
                    vector_push(updates, &update);
                } else {
                    /* No changes to dynamic addresses */
                    if (recompute) {
                        set_lsp_dynamic_addresses(nbsp->dynamic_addresses, op);
                    }
                    destroy_lport_addresses(&update.current_addresses);
                }
            } else {
                set_dynamic_updates(nbsp->addresses[j], &update);
                vector_push(updates, &update);
            }
        }

        if (!has_dynamic_address && nbsp->dynamic_addresses) {
            nbrec_logical_switch_port_set_dynamic_addresses(nbsp, NULL);
        }
    }
}

void
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
                ipam_insert_ip_for_datapath(op->peer->od, ip, false);
            }
        }
    }
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
        ipam_insert_ip_for_datapath(od, ip, false);
    }
}
