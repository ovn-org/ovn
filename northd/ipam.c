#include <config.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "ipam.h"
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
destroy_ipam_info(struct ipam_info *info)
{
    bitmap_free(info->allocated_ipv4s);
    free((char *) info->id);
}

bool
ipam_insert_ip(struct ipam_info *info, uint32_t ip)
{
    if (!info->allocated_ipv4s) {
        return true;
    }

    if (ip >= info->start_ipv4 &&
        ip < (info->start_ipv4 + info->total_ipv4s)) {
        if (bitmap_is_set(info->allocated_ipv4s,
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

