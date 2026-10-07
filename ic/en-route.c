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

#include "en-az.h"
#include "en-route.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "ovn-ic.h"
#include "ovsdb-idl.h"
#include "smap.h"
#include "vec.h"
#include "sset.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(en_ic_route);

struct ic_route_info {
    struct hmap_node node;
    struct in6_addr prefix;
    unsigned int plen;
    struct in6_addr nexthop;
    const char *origin;
    const char *route_table;
    const char *route_tag;
    bool override_connected;
    struct uuid ic_route_uuid;

    const struct nbrec_logical_router *nb_lr;

    /* One of nb_route, nb_lrp, nb_lb is set and the other ones must be NULL.
     * - For a route that is learned from IC-SB, or a static route that is
     *   generated from a route that is configured in NB, the "nb_route"
     *   is set.
     * - For a route that is generated from a direct-connect subnet of
     *   a logical router port, the "nb_lrp" is set.
     * - For a route that is generated from a load-balancer vip of
     *   a logical router, the "nb_lb" is set. */
    const struct nbrec_logical_router_static_route *nb_route;
    const struct nbrec_logical_router_port *nb_lrp;
    const struct nbrec_load_balancer *nb_lb;
};

struct ic_router_info {
    struct hmap_node node;
    const struct nbrec_logical_router *lr; /* key of hmap */
    struct vector isb_pbs; /* Vector of const struct icsbrec_port_binding *. */
    struct hmap routes_learned;
};

static const struct sbrec_datapath_binding *
find_sb_dp_by_nb_uuid(struct ovsdb_idl_index *sbrec_datapath_binding,
                      const struct uuid *nb_uuid)
{
    const struct sbrec_datapath_binding *key =
        sbrec_datapath_binding_index_init_row(sbrec_datapath_binding);

    sbrec_datapath_binding_set_nb_uuid(key, nb_uuid, 1);

    const struct sbrec_datapath_binding *dp =
        sbrec_datapath_binding_index_find(sbrec_datapath_binding, key);
    sbrec_datapath_binding_index_destroy_row(key);

    return dp;
}

static inline bool
get_override_connected(const struct smap *options)
{
    return smap_get_bool(options, ROUTE_OVERRIDE_CONNECTED, false);
}

static uint32_t
ic_route_hash(const struct in6_addr *prefix, unsigned int plen,
              const struct in6_addr *nexthop, const char *origin,
              const char *route_table,
              const struct uuid *ic_route_uuid,
              bool override_connected)
{
    uint32_t basis = ic_route_uuid ? uuid_hash(ic_route_uuid) : 0;
    basis = hash_bytes(prefix, sizeof *prefix, basis);
    basis = hash_int((uint32_t) plen, basis);
    basis = hash_string(origin, basis);
    basis = hash_string(route_table, basis);
    basis = hash_boolean(override_connected, basis);
    return hash_bytes(nexthop, sizeof *nexthop, basis);
}

static struct ic_route_info *
ic_route_find(struct hmap *routes, const struct in6_addr *prefix,
              unsigned int plen, const struct in6_addr *nexthop,
              const char *origin, const char *route_table,
              const struct uuid *ic_route_uuid,
              bool override_connected, uint32_t hash)
{
    struct ic_route_info *r;
    if (!hash) {
        hash = ic_route_hash(prefix, plen, nexthop, origin, route_table,
                             ic_route_uuid, override_connected);
    }
    HMAP_FOR_EACH_WITH_HASH (r, node, hash, routes) {
        if (ipv6_addr_equals(&r->prefix, prefix) &&
            r->plen == plen &&
            r->override_connected == override_connected &&
            ipv6_addr_equals(&r->nexthop, nexthop) &&
            !strcmp(r->origin, origin) &&
            !strcmp(r->route_table ? r->route_table : "", route_table) &&
            (!ic_route_uuid || uuid_equals(&r->ic_route_uuid,
                                           ic_route_uuid))) {
            return r;
        }
    }
    return NULL;
}

static struct ic_router_info *
ic_router_find(struct hmap *ic_lrs, const struct nbrec_logical_router *lr)
{
    struct ic_router_info *ic_lr;
    HMAP_FOR_EACH_WITH_HASH (ic_lr, node, uuid_hash(&lr->header_.uuid),
                             ic_lrs) {
        if (ic_lr->lr == lr) {
           return ic_lr;
        }
    }
    return NULL;
}

static bool
parse_route(const char *s_prefix, const char *s_nexthop,
            struct in6_addr *prefix, unsigned int *plen,
            struct in6_addr *nexthop, bool reject_lla)
{
    if (!ip46_parse_cidr(s_prefix, prefix, plen)) {
        return false;
    }

    unsigned int nlen;
    if (strcmp(s_nexthop, "discard") &&
        !ip46_parse_cidr(s_nexthop, nexthop, &nlen)) {
        return false;
    }

    /* Reject routes with a link-local next hop only on the learn path: a
     * link-local next hop is not useful as a local static route.  On the
     * advertise path it must be accepted, because advertised connected IPv6
     * routes legitimately use the router port's link-local address as next
     * hop (see get_nexthop_from_lport_addresses()); rejecting them there
     * would make advertise_routes() delete and re-create the same route on
     * every run. */
    return !reject_lla || !in6_is_lla(nexthop);
}

/* Return false if can't be added due to bad format. */
static bool
add_to_routes_learned(struct hmap *routes_learned,
                      const struct nbrec_logical_router_static_route *nb_route,
                      const struct nbrec_logical_router *nb_lr,
                      const struct uuid *ic_route_uuid)
{
    struct in6_addr prefix, nexthop;
    unsigned int plen;
    if (!parse_route(nb_route->ip_prefix, nb_route->nexthop,
                     &prefix, &plen, &nexthop, true)) {
        return false;
    }
    const char *origin = smap_get_def(&nb_route->options, "origin", "");
    bool override_connected = get_override_connected(&nb_route->options);

    uint32_t hash = ic_route_hash(&prefix, plen, &nexthop, origin,
                                  nb_route->route_table, ic_route_uuid,
                                  override_connected);
    if (ic_route_find(routes_learned, &prefix, plen, &nexthop, origin,
                      nb_route->route_table, ic_route_uuid,
                      override_connected, hash)) {
        /* Route was added to learned on previous iteration. */
        return true;
    }

    struct ic_route_info *ic_route = xzalloc(sizeof *ic_route);
    ic_route->prefix = prefix;
    ic_route->plen = plen;
    ic_route->nexthop = nexthop;
    ic_route->nb_route = nb_route;
    ic_route->origin = origin;
    ic_route->route_table = nb_route->route_table;
    ic_route->nb_lr = nb_lr;
    ic_route->ic_route_uuid = *ic_route_uuid;
    ic_route->override_connected = override_connected;
    hmap_insert(routes_learned, &ic_route->node, hash);

    return true;
}

/* Returns true if IPv4 prefixes of 'nb_lr' should be advertised with the
 * interconnect port's IPv6 address as next hop ("IPv4 over IPv6").
 * The option is read from the Logical_Router and may be overridden on the
 * transit Logical_Router_Port.
 */
static bool
route_ipv4_next_hop_ipv6(const struct nbrec_logical_router *nb_lr,
                         const struct nbrec_logical_router_port *ts_lrp)
{
    const char *opt_name = "ic-route-ipv4-next-hop-ipv6";
    bool lr_opt = smap_get_bool(&nb_lr->options, opt_name, false);

    return ts_lrp ? smap_get_bool(&ts_lrp->options, opt_name, lr_opt) : lr_opt;
}

static bool
get_nexthop_from_lport_addresses(bool is_v4_prefix,
                                 const struct lport_addresses *laddr,
                                 bool ipv4_next_hop_ipv6,
                                 struct in6_addr *nexthop)
{
    /* For an IPv4 prefix, pick an IPv4 next hop by default.  When
     * 'ipv4_next_hop_ipv6' is enabled and the interconnect port has an IPv6
     * address, advertise the IPv4 prefix with that IPv6 address as next hop
     * instead ("IPv4 over IPv6"). */
    if (is_v4_prefix && !(ipv4_next_hop_ipv6 && laddr->n_ipv6_addrs)) {
        if (!laddr->n_ipv4_addrs) {
            return false;
        }
        in6_addr_set_mapped_ipv4(nexthop, laddr->ipv4_addrs[0].addr);
        return true;
    }

    /* ipv6 */
    if (laddr->n_ipv6_addrs) {
        *nexthop = laddr->ipv6_addrs[0].addr;
        return true;
    }

    return false;
}

static bool
prefix_is_filtered(struct in6_addr *prefix,
                   unsigned int plen,
                   const struct nbrec_logical_router *nb_lr,
                   const struct nbrec_logical_router_port *ts_lrp,
                   bool is_advertisement)
{
    struct ds filter_list = DS_EMPTY_INITIALIZER;
    const char *filter_direction = is_advertisement ? "ic-route-filter-adv" :
                                                      "ic-route-filter-learn";
    if (ts_lrp) {
        const char *lrp_route_filter = smap_get(&ts_lrp->options,
                                                filter_direction);
        if (lrp_route_filter) {
            ds_put_format(&filter_list, "%s,", lrp_route_filter);
        }
    }
    const char *lr_route_filter = smap_get(&nb_lr->options,
                                           filter_direction);
    if (lr_route_filter) {
        ds_put_format(&filter_list, "%s,", lr_route_filter);
    }

    struct sset prefix_set = SSET_INITIALIZER(&prefix_set);
    sset_from_delimited_string(&prefix_set, ds_cstr(&filter_list), ",");

    bool matched = true;
    if (!sset_is_empty(&prefix_set)) {
        matched = find_prefix_in_set(prefix, plen, &prefix_set,
                                     filter_direction);
    }

    ds_destroy(&filter_list);
    sset_destroy(&prefix_set);
    return matched;
}

static bool
prefix_is_deny_filtered(struct in6_addr *prefix,
                        unsigned int plen,
                        const struct smap *nb_options,
                        const struct nbrec_logical_router *nb_lr,
                        const struct nbrec_logical_router_port *ts_lrp,
                        bool is_advertisement)
{
    struct ds deny_list = DS_EMPTY_INITIALIZER;
    const char *deny_key = is_advertisement ? "ic-route-deny-adv" :
                                              "ic-route-deny-learn";

    if (ts_lrp) {
        const char *lrp_deny_filter = smap_get(&ts_lrp->options, deny_key);
        if (lrp_deny_filter) {
            ds_put_format(&deny_list, "%s,", lrp_deny_filter);
        }
    }

    if (nb_lr) {
        const char *lr_deny_filter = smap_get(&nb_lr->options, deny_key);
        if (lr_deny_filter) {
            ds_put_format(&deny_list, "%s,", lr_deny_filter);
        }
    }

    if (nb_options) {
        const char *global_deny = smap_get(nb_options, "ic-route-denylist");
        if (!global_deny || !global_deny[0]) {
            global_deny = smap_get(nb_options, "ic-route-blacklist");
        }
        if (global_deny && global_deny[0]) {
            ds_put_format(&deny_list, "%s,", global_deny);
        }
    }

    struct sset prefix_set = SSET_INITIALIZER(&prefix_set);
    sset_from_delimited_string(&prefix_set, ds_cstr(&deny_list), ",");

    bool denied = false;
    if (!sset_is_empty(&prefix_set)) {
        denied = find_prefix_in_set(prefix, plen, &prefix_set, deny_key);
    }

    ds_destroy(&deny_list);
    sset_destroy(&prefix_set);
    return denied;
}

static bool
route_need_advertise(const char *policy,
                     struct in6_addr *prefix,
                     unsigned int plen,
                     const struct smap *nb_options,
                     const struct nbrec_logical_router *nb_lr,
                     const struct nbrec_logical_router_port *ts_lrp)
{
    if (!smap_get_bool(nb_options, "ic-route-adv", false)) {
        return false;
    }

    if (plen == 0 &&
        !smap_get_bool(nb_options, "ic-route-adv-default", false)) {
        return false;
    }

    if (policy && !strcmp(policy, "src-ip")) {
        return false;
    }

    if (prefix_is_link_local(prefix, plen)) {
        return false;
    }

    if (prefix_is_deny_filtered(prefix, plen, nb_options,
                                nb_lr, ts_lrp, true)) {
        return false;
    }

    if (!prefix_is_filtered(prefix, plen, nb_lr, ts_lrp, true)) {
        return false;
    }

    return true;
}

static void
add_to_routes_ad(struct hmap *routes_ad, const struct in6_addr prefix,
                 unsigned int plen, const struct in6_addr nexthop,
                 const char *origin, const char *route_table,
                 const struct nbrec_logical_router_port *nb_lrp,
                 const struct nbrec_logical_router_static_route *nb_route,
                 const struct nbrec_logical_router *nb_lr,
                 const struct nbrec_load_balancer *nb_lb,
                 const char *route_tag, bool override_connected)
{
    ovs_assert(nb_route || nb_lrp || nb_lb || nb_lr);

    if (route_table == NULL) {
        route_table = "";
    }

    uint hash = ic_route_hash(&prefix, plen, &nexthop, origin,
                              route_table, NULL, override_connected);

    if (!ic_route_find(routes_ad, &prefix, plen, &nexthop, origin, route_table,
                       NULL, override_connected, hash)) {
        struct ic_route_info *ic_route = xzalloc(sizeof *ic_route);
        ic_route->prefix = prefix;
        ic_route->plen = plen;
        ic_route->nexthop = nexthop;
        ic_route->nb_route = nb_route;
        ic_route->origin = origin;
        ic_route->route_table = route_table;
        ic_route->nb_lrp = nb_lrp;
        ic_route->nb_lr = nb_lr;
        ic_route->nb_lb = nb_lb;
        ic_route->route_tag = route_tag;
        ic_route->override_connected = override_connected;
        hmap_insert(routes_ad, &ic_route->node, hash);
    } else {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        const char *msg_fmt = "Duplicate %s route advertisement was "
                              "suppressed! NB %s uuid: "UUID_FMT;
        if (nb_route) {
            VLOG_WARN_RL(&rl, msg_fmt, origin, "route",
                         UUID_ARGS(&nb_route->header_.uuid));
        } else if (nb_lb) {
            VLOG_WARN_RL(&rl, msg_fmt, origin, "loadbalancer",
                         UUID_ARGS(&nb_lb->header_.uuid));
        } else if (nb_lrp) {
            VLOG_WARN_RL(&rl, msg_fmt, origin, "lrp",
                         UUID_ARGS(&nb_lrp->header_.uuid));
        } else {
            VLOG_WARN_RL(&rl, msg_fmt, origin, "lr",
                UUID_ARGS(&nb_lr->header_.uuid));
        }
    }
}

static void
add_static_to_routes_ad(
    struct hmap *routes_ad,
    const struct nbrec_logical_router_static_route *nb_route,
    const struct nbrec_logical_router *nb_lr,
    const struct lport_addresses *nexthop_addresses,
    const struct smap *nb_options,
    const char *route_tag,
    const struct nbrec_logical_router_port *ts_lrp)
{
    struct in6_addr prefix, nexthop;
    unsigned int plen;
    bool override_connected = get_override_connected(&nb_route->options);

    if (!parse_route(nb_route->ip_prefix, nb_route->nexthop,
                     &prefix, &plen, &nexthop, true)) {
        return;
    }

    if (!route_need_advertise(nb_route->policy, &prefix, plen, nb_options,
                              nb_lr, ts_lrp)) {
        return;
    }

    if (!get_nexthop_from_lport_addresses(IN6_IS_ADDR_V4MAPPED(&prefix),
                                          nexthop_addresses,
                                          route_ipv4_next_hop_ipv6(nb_lr,
                                                                   ts_lrp),
                                          &nexthop)) {
        return;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        ds_put_format(&msg, "Advertising static route: %s -> %s, ic nexthop: ",
                      nb_route->ip_prefix, nb_route->nexthop);
        ipv6_format_mapped(&nexthop, &msg);
        ds_put_format(&msg, ", route_table: %s", nb_route->route_table[0]
                                                 ? nb_route->route_table
                                                 : "<main>");

        VLOG_DBG("%s", ds_cstr(&msg));
        ds_destroy(&msg);
    }

    add_to_routes_ad(routes_ad, prefix, plen, nexthop, ROUTE_ORIGIN_STATIC,
                     nb_route->route_table, NULL, nb_route, nb_lr,
                     NULL, route_tag, override_connected);
}

static void
add_network_to_routes_ad(struct hmap *routes_ad, const char *network,
                         const struct nbrec_logical_router_port *nb_lrp,
                         const struct lport_addresses *nexthop_addresses,
                         const struct smap *nb_options,
                         const struct nbrec_logical_router *nb_lr,
                         const struct nbrec_logical_router_port *ts_lrp,
                         const char *route_tag,
                         const char *ts_route_table,
                         bool is_src_dynamic)
{
    struct in6_addr prefix, nexthop;
    unsigned int plen;
    if (!ip46_parse_cidr(network, &prefix, &plen)) {
        return;
    }

    if (!route_need_advertise(NULL, &prefix, plen, nb_options,
                              nb_lr, ts_lrp)) {
        if (VLOG_IS_DBG_ENABLED()) {
            struct ds msg = DS_EMPTY_INITIALIZER;
            ds_put_format(&msg, "Route ad: skip network %s", network);
            if (nb_lrp) {
                ds_put_format(&msg, " of lrp %s", nb_lrp->name);
            }
            ds_put_format(&msg, ".");
            VLOG_DBG("%s", ds_cstr(&msg));
            ds_destroy(&msg);
        }
        return;
    }

    if (!get_nexthop_from_lport_addresses(IN6_IS_ADDR_V4MAPPED(&prefix),
                                          nexthop_addresses,
                                          route_ipv4_next_hop_ipv6(nb_lr,
                                                                   ts_lrp),
                                          &nexthop)) {
        return;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        ds_put_format(&msg, "Adding direct network route to <main> routing "
                      "table: %s", network);

        if (nb_lrp) {
            ds_put_format(&msg, " of lrp %s,", nb_lrp->name);
        }
        ds_put_format(&msg, " nexthop ");
        ipv6_format_mapped(&nexthop, &msg);

        VLOG_DBG("%s", ds_cstr(&msg));
        ds_destroy(&msg);
    }

    /* Create additional route to local and remote networks that have
     * common route table name with port attached to transit switch having
     * same route table name.
     * As a result, traffic that is processed within such route table and is
     * routed cross az will select port attached to transit switch specially
     * allocated to process traffic within that route table.
     */

    if (*ts_route_table) {
        add_to_routes_ad(routes_ad, prefix, plen, nexthop,
                         ROUTE_ORIGIN_CONNECTED, ts_route_table,
                         nb_lrp, NULL, nb_lr, NULL, route_tag, true);
    }

    const char *origin = is_src_dynamic ? ROUTE_ORIGIN_CONNECTED_DYNAMIC :
                                          ROUTE_ORIGIN_CONNECTED;
    /* directly-connected routes go to <main> route table */
    add_to_routes_ad(routes_ad, prefix, plen, nexthop, origin,
                     NULL, nb_lrp, NULL, nb_lr, NULL, route_tag, false);
}

static void
add_lb_vip_to_routes_ad(struct hmap *routes_ad, const char *vip_key,
                        const struct nbrec_load_balancer *nb_lb,
                        const struct lport_addresses *nexthop_addresses,
                        const struct smap *nb_options,
                        const struct nbrec_logical_router *nb_lr,
                        const char *route_tag,
                        const struct nbrec_logical_router_port *ts_lrp)
{
    char *vip_str = NULL;
    struct in6_addr vip_ip, nexthop;
    uint16_t vip_port;
    int addr_family;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

    if (!ip_address_and_port_from_lb_key(vip_key, &vip_str, &vip_ip,
                                         &vip_port, &addr_family)) {
        VLOG_WARN_RL(&rl, "Route ad: Parsing failed for lb vip %s", vip_key);
        return;
    }
    if (vip_str == NULL) {
        return;
    }
    unsigned int plen = (addr_family == AF_INET) ? 32 : 128;
    if (!route_need_advertise(NULL, &vip_ip, plen, nb_options,
                              nb_lr, ts_lrp)) {
        VLOG_DBG("Route ad: skip lb vip %s.", vip_key);
        goto out;
    }
    if (!get_nexthop_from_lport_addresses(IN6_IS_ADDR_V4MAPPED(&vip_ip),
                                          nexthop_addresses,
                                          route_ipv4_next_hop_ipv6(nb_lr,
                                                                   ts_lrp),
                                          &nexthop)) {
        VLOG_DBG("Route ad: failed to get nexthop for lb vip %s", vip_key);
        goto out;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        ds_put_format(&msg, "Adding lb vip route to <main> routing "
                      "table: %s, nexthop ", vip_str);
        ipv6_format_mapped(&nexthop, &msg);

        VLOG_DBG("%s", ds_cstr(&msg));
        ds_destroy(&msg);
    }

    /* Lb vip routes go to <main> route table */
    add_to_routes_ad(routes_ad, vip_ip, plen, nexthop, ROUTE_ORIGIN_LB,
                     NULL, NULL, NULL, nb_lr, nb_lb, route_tag, false);
out:
    free(vip_str);
}

static bool
route_has_local_gw(const struct nbrec_logical_router *lr,
                   const char *route_table, const char *ip_prefix) {

    const struct nbrec_logical_router_static_route *route;
    for (int i = 0; i < lr->n_static_routes; i++) {
        route = lr->static_routes[i];
        if (!smap_get(&route->external_ids, "ic-learned-route") &&
            !strcmp(route->route_table, route_table) &&
            !strcmp(route->ip_prefix, ip_prefix)) {
            return true;
        }
    }
    return false;
}

static bool
lrp_has_neighbor_in_ts(const struct nbrec_logical_router_port *lrp,
                       struct in6_addr *nexthop)
{
    if (!lrp || !nexthop) {
        return false;
    }

    struct lport_addresses lrp_networks;
    if (!extract_lrp_networks(lrp, &lrp_networks)) {
        destroy_lport_addresses(&lrp_networks);
        return false;
    }

    if (IN6_IS_ADDR_V4MAPPED(nexthop)) {
        ovs_be32 neigh_prefix_v4 = in6_addr_get_mapped_ipv4(nexthop);
        for (size_t i = 0; i < lrp_networks.n_ipv4_addrs; i++) {
            struct ipv4_netaddr address = lrp_networks.ipv4_addrs[i];
            if (address.network == (neigh_prefix_v4 & address.mask)) {
                destroy_lport_addresses(&lrp_networks);
                return true;
            }
        }
    } else {
        for (size_t i = 0; i < lrp_networks.n_ipv6_addrs; i++) {
            struct ipv6_netaddr address = lrp_networks.ipv6_addrs[i];
            struct in6_addr neigh_prefix = ipv6_addr_bitand(nexthop,
                                                            &address.mask);
            if (ipv6_addr_equals(&address.network, &neigh_prefix)) {
                destroy_lport_addresses(&lrp_networks);
                return true;
            }
        }
    }

    destroy_lport_addresses(&lrp_networks);
    return false;
}

static bool
route_matches_local_lb(const struct nbrec_load_balancer *nb_lb,
                       const char *ip_prefix)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
    struct in6_addr prefix;
    unsigned int plen;

    if (!ip46_parse_cidr(ip_prefix, &prefix, &plen)) {
        return false;
    }

    struct smap_node *node;
    SMAP_FOR_EACH (node, &nb_lb->vips) {
        char *vip_str = NULL;
        struct in6_addr vip_ip;
        uint16_t vip_port;
        int addr_family;
        if (ip_address_and_port_from_lb_key(node->key, &vip_str,
                                            &vip_ip, &vip_port,
                                            &addr_family)) {
            if (IN6_IS_ADDR_V4MAPPED(&prefix) && addr_family == AF_INET) {
                ovs_be32 vip = in6_addr_get_mapped_ipv4(&vip_ip);
                ovs_be32 mask = be32_prefix_mask(plen);

                if ((vip & mask) == in6_addr_get_mapped_ipv4(&prefix)) {
                    free(vip_str);
                    return true;
                }
            } else if (!IN6_IS_ADDR_V4MAPPED(&prefix)
                       && addr_family == AF_INET6) {
                struct in6_addr mask = ipv6_create_mask(plen);
                struct in6_addr vip_prefix = ipv6_addr_bitand(&vip_ip, &mask);
                if (ipv6_addr_equals(&prefix, &vip_prefix)) {
                    free(vip_str);
                    return true;
                }
            }
            free(vip_str);
        } else {
            VLOG_WARN_RL(&rl,
                         "Route learn: Parsing failed for local lb vip %s",
                         node->key);
        }
    }
    return false;
}

static bool
route_need_learn(struct ic_context *ctx,
                 const struct nbrec_logical_router *lr,
                 const struct icsbrec_route *isb_route,
                 struct in6_addr *prefix, unsigned int plen,
                 const struct smap *nb_options,
                 const struct nbrec_logical_router_port *ts_lrp,
                 struct in6_addr *nexthop)
{
    if (!smap_get_bool(nb_options, "ic-route-learn", false)) {
        return false;
    }

    if (plen == 0 &&
        !smap_get_bool(nb_options, "ic-route-learn-default", false)) {
        return false;
    }

    if (!strcmp(isb_route->origin, ROUTE_ORIGIN_LB) &&
        !smap_get_bool(nb_options, "ic-route-learn-lb", false)) {
        return false;
    }

    if (!lrouter_is_enabled(lr)) {
        return false;
    }

    if (prefix_is_link_local(prefix, plen)) {
        return false;
    }

    if (prefix_is_deny_filtered(prefix, plen, nb_options, lr, ts_lrp, false)) {
        return false;
    }

    if (!prefix_is_filtered(prefix, plen, lr, ts_lrp, false)) {
        return false;
    }

    if (route_has_local_gw(lr, isb_route->route_table, isb_route->ip_prefix)) {
        VLOG_DBG("Skip learning %s (rtb:%s) route, as we've got one with "
                 "local GW", isb_route->ip_prefix, isb_route->route_table);
        return false;
    }

    if (!lrp_has_neighbor_in_ts(ts_lrp, nexthop)) {
        return false;
    }

    for (size_t i = 0; i < lr->n_load_balancer; i++) {
        if (route_matches_local_lb(lr->load_balancer[i],
                                   isb_route->ip_prefix)) {
            VLOG_DBG("Skip learning %s (rtb:%s) route, as we've got local"
                     " LB with matching VIP", isb_route->ip_prefix,
                     isb_route->route_table);
            return false;
        }
    }
    for (size_t i = 0; i < lr->n_load_balancer_group; i++) {
        const struct nbrec_load_balancer_group *nb_lbg =
            lr->load_balancer_group[i];
        for (size_t j = 0; j < nb_lbg->n_load_balancer; j++) {
            if (route_matches_local_lb(nb_lbg->load_balancer[j],
                                       isb_route->ip_prefix)) {
                VLOG_DBG("Skip learning %s (rtb:%s) route, as we've got local"
                         " LB with matching VIP", isb_route->ip_prefix,
                         isb_route->route_table);
                return false;
            }
        }
    }

    const struct sbrec_datapath_binding *dp =
        find_sb_dp_by_nb_uuid(ctx->sbrec_datapath_binding_by_nb_uuid,
                              &lr->header_.uuid);
    if (!dp) {
        return true;
    }

    struct sbrec_learned_route *filter = sbrec_learned_route_index_init_row(
        ctx->sbrec_learned_route_by_datapath);
    sbrec_learned_route_index_set_datapath(filter, dp);
    struct sbrec_learned_route *sb_route;
    SBREC_LEARNED_ROUTE_FOR_EACH_EQUAL (sb_route, filter,
                                        ctx->sbrec_learned_route_by_datapath) {
        if (!strcmp(isb_route->ip_prefix, sb_route->ip_prefix)) {
            sbrec_learned_route_index_destroy_row(filter);
                VLOG_DBG("Skip learning %s (rtb:%s) route, as we've got"
                         " dynamic routing learned", isb_route->ip_prefix,
                         isb_route->route_table);
            return false;
        }
    }
    sbrec_learned_route_index_destroy_row(filter);

    return true;
}

static const char *
get_lrp_name_by_ts_port_name(struct ic_context *ctx, const char *ts_port_name)
{
    const struct nbrec_logical_switch_port *nb_lsp;

    nb_lsp = get_lsp_by_ts_port_name(ctx, ts_port_name);
    if (!nb_lsp) {
        return NULL;
    }

    return smap_get(&nb_lsp->options, "router-port");
}

static const struct nbrec_logical_router_port *
find_lrp_of_nexthop(struct ic_context *ctx,
                    const struct icsbrec_route *isb_route)
{
    const struct nbrec_logical_router_port *lrp;
    const struct nbrec_logical_switch *ls;
    ls = find_ts_in_nb(ctx, isb_route->transit_switch);
    if (!ls) {
        return NULL;
    }

    struct in6_addr nexthop;
    if (!ip46_parse(isb_route->nexthop, &nexthop)) {
        return NULL;
    }

    for (size_t i = 0; i < ls->n_ports; i++) {
        char *lsp_name = ls->ports[i]->name;
        const char *lrp_name = get_lrp_name_by_ts_port_name(ctx,
                                                            lsp_name);
        if (!lrp_name) {
            continue;
        }

        lrp = get_lrp_by_lrp_name(ctx, lrp_name);
        if (!lrp) {
            continue;
        }

        struct lport_addresses lrp_networks;
        if (!extract_lrp_networks(lrp, &lrp_networks)) {
            destroy_lport_addresses(&lrp_networks);
            continue;
        }

        if (IN6_IS_ADDR_V4MAPPED(&nexthop)) {
            ovs_be32 nexthop_v4 = in6_addr_get_mapped_ipv4(&nexthop);
            for (size_t i_v4 = 0; i_v4  < lrp_networks.n_ipv4_addrs; i_v4++) {
                struct ipv4_netaddr address = lrp_networks.ipv4_addrs[i_v4];
                if (address.addr == nexthop_v4) {
                    destroy_lport_addresses(&lrp_networks);
                    return lrp;
                }
            }
        } else {
            for (size_t i_v6 = 0; i_v6 < lrp_networks.n_ipv6_addrs; i_v6++) {
                struct ipv6_netaddr address = lrp_networks.ipv6_addrs[i_v6];
                struct in6_addr nexthop_v6 = ipv6_addr_bitand(&nexthop,
                                                              &address.mask);
                if (ipv6_addr_equals(&address.network, &nexthop_v6)) {
                    destroy_lport_addresses(&lrp_networks);
                    return lrp;
                }
            }
        }
        destroy_lport_addresses(&lrp_networks);
    }

    return NULL;
}

static bool
lrp_is_ts_port(struct ic_context *ctx, struct ic_router_info *ic_lr,
               const char *lrp_name)
{
    const struct icsbrec_port_binding *isb_pb;
    const char *ts_lrp_name;
    VECTOR_FOR_EACH (&ic_lr->isb_pbs, isb_pb) {
        ts_lrp_name = get_lrp_name_by_ts_port_name(ctx, isb_pb->logical_port);
        if (ts_lrp_name && !strcmp(ts_lrp_name, lrp_name)) {
            return true;
        }
    }
    return false;
}

#define IC_ROUTE_LEARN_TAG_RULES "ic-route-learn-tag-rules"
#define IC_ROUTE_LEARN_TAG_ALLOW "allow:"
#define IC_ROUTE_LEARN_TAG_BLOCK "block:"
#define IC_ROUTE_FILTER_TAG "ic-route-filter-tag"

/* Route tag rules of a TS LRP, as configured through its
 * "ic-route-learn-tag-rules" option. */
struct route_learn_tag_rules {
    const char *config;     /* Option value, for logging purposes. */
    bool configured;        /* False if the option is unset or invalid, in
                             * which case no route is filtered. */
    bool allow;             /* True: only routes tagged with one of 'tags' are
                             * learned.  False: routes tagged with one of
                             * 'tags' are not learned. */
    struct sset tags;
};

/* Initializes 'rules' from the "ic-route-learn-tag-rules" option of 'lrp',
 * which may be NULL.  The option value must be either
 * "allow:<comma-separated-tags>" or "block:<comma-separated-tags>"; any other
 * value is logged and ignored.  Route tags cannot contain commas. */
static void
route_learn_tag_rules_init(struct route_learn_tag_rules *rules,
                           const struct nbrec_logical_router_port *lrp)
{
    static struct vlog_rate_limit bad_value_rl = VLOG_RATE_LIMIT_INIT(5, 1);
    static struct vlog_rate_limit no_tag_rl = VLOG_RATE_LIMIT_INIT(5, 1);
    const char *tags = "";

    rules->config = lrp ? smap_get(&lrp->options, IC_ROUTE_LEARN_TAG_RULES)
                        : NULL;
    rules->configured = false;
    rules->allow = false;

    if (rules->config) {
        if (!strncmp(rules->config, IC_ROUTE_LEARN_TAG_ALLOW,
                     strlen(IC_ROUTE_LEARN_TAG_ALLOW))) {
            tags = rules->config + strlen(IC_ROUTE_LEARN_TAG_ALLOW);
            rules->allow = true;
            rules->configured = true;
        } else if (!strncmp(rules->config, IC_ROUTE_LEARN_TAG_BLOCK,
                            strlen(IC_ROUTE_LEARN_TAG_BLOCK))) {
            tags = rules->config + strlen(IC_ROUTE_LEARN_TAG_BLOCK);
            rules->configured = true;
        } else {
            VLOG_WARN_RL(&bad_value_rl,
                         "Ignoring invalid %s value [%s] of logical "
                         "router port %s: expected \"%s<tags>\" or "
                         "\"%s<tags>\".", IC_ROUTE_LEARN_TAG_RULES,
                         rules->config, lrp->name,
                         IC_ROUTE_LEARN_TAG_ALLOW, IC_ROUTE_LEARN_TAG_BLOCK);
        }
    }

    sset_from_delimited_string(&rules->tags, tags, ",");

    if (rules->configured && sset_is_empty(&rules->tags)) {
        VLOG_WARN_RL(&no_tag_rl,
                     "Ignoring %s value [%s] of logical router port %s: "
                     "no route tag specified.", IC_ROUTE_LEARN_TAG_RULES,
                     rules->config, lrp->name);
        rules->configured = false;
    }
}

static void
route_learn_tag_rules_destroy(struct route_learn_tag_rules *rules)
{
    sset_destroy(&rules->tags);
}

/* Returns true if a route tagged with 'route_tag' (NULL if the route
 * carries no tag) can be learned according to 'rules'. */
static bool
route_learn_tag_rules_allow(const struct route_learn_tag_rules *rules,
                            const char *route_tag)
{
    if (!rules->configured) {
        return true;
    }

    bool listed = route_tag && sset_contains(&rules->tags, route_tag);
    return rules->allow ? listed : !listed;
}

/* A NULL 'ts_scope' means "all transit switches" (full recompute); a non-NULL
 * scope restricts processing to the transit switches whose names it
 * contains. */
static bool
route_ts_in_scope(const struct sset *ts_scope, const char *ts_name)
{
    return !ts_scope || sset_contains(ts_scope, ts_name);
}

static void
sync_learned_routes(struct ic_context *ctx,
                    const struct icsbrec_availability_zone *runned_az,
                    struct ic_router_info *ic_lr,
                    const struct sset *ts_scope)
{
    ovs_assert(ctx->ovnnb_txn);
    const struct icsbrec_route *isb_route, *isb_route_key;

    const struct nbrec_nb_global *nb_global =
        nbrec_nb_global_first(ctx->ovnnb_idl);
    ovs_assert(nb_global);

    const char *lrp_name, *ts_route_table, *route_filter_tag;
    const struct icsbrec_port_binding *isb_pb;
    const struct nbrec_logical_router_port *lrp;
    VECTOR_FOR_EACH (&ic_lr->isb_pbs, isb_pb) {
        if (!route_ts_in_scope(ts_scope, isb_pb->transit_switch)) {
            continue;
        }
        if (!strcmp(isb_pb->address, "")) {
            continue;
        }
        lrp_name = get_lrp_name_by_ts_port_name(ctx, isb_pb->logical_port);
        lrp = lrp_name ? get_lrp_by_lrp_name(ctx, lrp_name) : NULL;
        if (lrp) {
            ts_route_table = smap_get_def(&lrp->options, "route_table", "");
            route_filter_tag = smap_get_def(&lrp->options,
                                            IC_ROUTE_FILTER_TAG, "");
        } else {
            ts_route_table = "";
            route_filter_tag = "";
        }

        struct route_learn_tag_rules learn_tag_rules;
        route_learn_tag_rules_init(&learn_tag_rules, lrp);

        if (route_filter_tag[0]) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            if (learn_tag_rules.configured) {
                VLOG_WARN_RL(&rl, "The deprecated %s option of logical router "
                             "port %s is ignored as %s is also configured.",
                             IC_ROUTE_FILTER_TAG, lrp->name,
                             IC_ROUTE_LEARN_TAG_RULES);
            } else {
                VLOG_WARN_RL(&rl, "The %s option of logical router port %s is "
                             "deprecated and will be removed in the 28.09 "
                             "release; use %s instead.", IC_ROUTE_FILTER_TAG,
                             lrp->name, IC_ROUTE_LEARN_TAG_RULES);
            }
        }

        isb_route_key = icsbrec_route_index_init_row(ctx->icsbrec_route_by_ts);
        icsbrec_route_index_set_transit_switch(isb_route_key,
                                               isb_pb->transit_switch);

        ICSBREC_ROUTE_FOR_EACH_EQUAL (isb_route, isb_route_key,
                                      ctx->icsbrec_route_by_ts) {
            /* Filters ICSB routes, skipping those that either belong to
             * current logical router or are legacy routes from the current
             * availability zone (without lr-id).
             */
            const char *lr_id = smap_get(&isb_route->external_ids, "lr-id");
            struct uuid lr_uuid;
            if (lr_id) {
                if (!uuid_from_string(&lr_uuid, lr_id)
                    || uuid_equals(&ic_lr->lr->header_.uuid, &lr_uuid)) {
                    continue;
                }
            } else if (isb_route->availability_zone == runned_az) {
                continue;
            }

            const char *isb_route_tag = smap_get(&isb_route->external_ids,
                                                 "ic-route-tag");
            /* The deprecated filter tag is honored only when the route learn
             * tag rules are not in effect. */
            if (!learn_tag_rules.configured && isb_route_tag &&
                !strcmp(isb_route_tag, route_filter_tag)) {
                VLOG_DBG("Skip learning route %s -> %s as its route tag "
                         "[%s] is filtered by the filter tag [%s] of TS LRP",
                         isb_route->ip_prefix, isb_route->nexthop,
                         isb_route_tag, route_filter_tag);
                continue;
            }

            if (!route_learn_tag_rules_allow(&learn_tag_rules,
                                             isb_route_tag)) {
                VLOG_DBG("Skip learning route %s -> %s as its route tag "
                         "[%s] is filtered by the %s [%s] of TS LRP",
                         isb_route->ip_prefix, isb_route->nexthop,
                         isb_route_tag ? isb_route_tag : "",
                         IC_ROUTE_LEARN_TAG_RULES, learn_tag_rules.config);
                continue;
            }

            if (isb_route->route_table[0] &&
                strcmp(isb_route->route_table, ts_route_table)) {
                if (VLOG_IS_DBG_ENABLED()) {
                    VLOG_DBG("Skip learning static route %s -> %s as either "
                             "its route table %s != %s of TS port or ",
                             isb_route->ip_prefix, isb_route->nexthop,
                             isb_route->route_table, ts_route_table);
                }
                continue;
            }

            struct in6_addr prefix, nexthop;
            unsigned int plen;
            if (!parse_route(isb_route->ip_prefix, isb_route->nexthop,
                             &prefix, &plen, &nexthop, true)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "Bad route format in IC-SB: %s -> %s. "
                             "Ignored.", isb_route->ip_prefix,
                             isb_route->nexthop);
                continue;
            }
            if (!route_need_learn(ctx, ic_lr->lr, isb_route, &prefix, plen,
                                  &nb_global->options, lrp, &nexthop)) {
                continue;
            }

            bool override_connected =
                get_override_connected(&isb_route->options);
            struct ic_route_info *route_learned
                = ic_route_find(&ic_lr->routes_learned, &prefix, plen,
                                &nexthop, isb_route->origin,
                                isb_route->route_table,
                                &isb_route->header_.uuid,
                                override_connected, 0);

            if (route_learned) {
                hmap_remove(&ic_lr->routes_learned, &route_learned->node);
                free(route_learned);
            } else {
                /* Create the missing route in NB. */
                const struct nbrec_logical_router_static_route *nb_route =
                    nbrec_logical_router_static_route_insert(ctx->ovnnb_txn);
                nbrec_logical_router_static_route_set_ip_prefix(nb_route,
                    isb_route->ip_prefix);
                nbrec_logical_router_static_route_set_nexthop(nb_route,
                    isb_route->nexthop);
                char *uuid_s = xasprintf(UUID_FMT,
                                         UUID_ARGS(&isb_route->header_.uuid));
                nbrec_logical_router_static_route_set_route_table(nb_route,
                    isb_route->route_table);
                nbrec_logical_router_static_route_update_external_ids_setkey(
                    nb_route, "ic-learned-route", uuid_s);
                nbrec_logical_router_static_route_update_options_setkey(
                    nb_route, "origin", isb_route->origin);
                free(uuid_s);
                if (override_connected) {
                    nbrec_logical_router_static_route_update_options_setkey(
                        nb_route, ROUTE_OVERRIDE_CONNECTED, "true");
                }
                nbrec_logical_router_update_static_routes_addvalue(ic_lr->lr,
                    nb_route);
            }
        }
        icsbrec_route_index_destroy_row(isb_route_key);
        route_learn_tag_rules_destroy(&learn_tag_rules);
    }

    /* Delete extra learned routes. */
    struct ic_route_info *route_learned;
    HMAP_FOR_EACH_SAFE (route_learned, node, &ic_lr->routes_learned) {
        VLOG_DBG("Delete route %s -> %s that is not in IC-SB from NB.",
                 route_learned->nb_route->ip_prefix,
                 route_learned->nb_route->nexthop);
        nbrec_logical_router_update_static_routes_delvalue(
            ic_lr->lr, route_learned->nb_route);
        hmap_remove(&ic_lr->routes_learned, &route_learned->node);
        free(route_learned);
    }
}

static void
ad_route_sync_external_ids(const struct ic_route_info *route_adv,
                           const struct icsbrec_route *isb_route)
{
    struct uuid isb_ext_id, nb_id, isb_ext_lr_id, lr_id;
    const char *route_tag;
    smap_get_uuid(&isb_route->external_ids, "nb-id", &isb_ext_id);
    smap_get_uuid(&isb_route->external_ids, "lr-id", &isb_ext_lr_id);
    nb_id = route_adv->nb_lb ? route_adv->nb_lb->header_.uuid :
            route_adv->nb_route ? route_adv->nb_route->header_.uuid :
            route_adv->nb_lrp ? route_adv->nb_lrp->header_.uuid :
            route_adv->nb_lr->header_.uuid;

    lr_id = route_adv->nb_lr->header_.uuid;
    if (!uuid_equals(&isb_ext_id, &nb_id)) {
        char *uuid_s = xasprintf(UUID_FMT, UUID_ARGS(&nb_id));
        icsbrec_route_update_external_ids_setkey(isb_route, "nb-id",
                                                 uuid_s);
        free(uuid_s);
    }
    if (!uuid_equals(&isb_ext_lr_id, &lr_id)) {
        char *uuid_s = xasprintf(UUID_FMT, UUID_ARGS(&lr_id));
        icsbrec_route_update_external_ids_setkey(isb_route, "lr-id",
                                                 uuid_s);
        free(uuid_s);
    }
    if (strcmp(route_adv->route_tag, "")) {
        icsbrec_route_update_external_ids_setkey(isb_route, "ic-route-tag",
                                                 route_adv->route_tag);
    } else {
        route_tag = smap_get(&isb_route->external_ids, "ic-route-tag");
        if (route_tag) {
            icsbrec_route_update_external_ids_delkey(isb_route,
                                                     "ic-route-tag");
        }
    }
}

/* Sync routes from routes_ad to IC-SB. */
static void
advertise_routes(struct ic_context *ctx,
                 const struct icsbrec_availability_zone *az,
                 const char *ts_name,
                 struct hmap *routes_ad)
{
    ovs_assert(ctx->ovnisb_unlocked_txn);
    const struct icsbrec_route *isb_route;
    const struct icsbrec_route *isb_route_key =
        icsbrec_route_index_init_row(ctx->icsbrec_route_by_ts_az);
    icsbrec_route_index_set_transit_switch(isb_route_key, ts_name);
    icsbrec_route_index_set_availability_zone(isb_route_key, az);

    ICSBREC_ROUTE_FOR_EACH_EQUAL (isb_route, isb_route_key,
                                  ctx->icsbrec_route_by_ts_az) {
        struct in6_addr prefix, nexthop;
        unsigned int plen;

        if (!parse_route(isb_route->ip_prefix, isb_route->nexthop,
                         &prefix, &plen, &nexthop, false)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Bad route format in IC-SB: %s -> %s. "
                         "Delete it.",
                         isb_route->ip_prefix, isb_route->nexthop);
            icsbrec_route_delete(isb_route);
            continue;
        }
        bool override_connected = get_override_connected(&isb_route->options);
        struct ic_route_info *route_adv =
            ic_route_find(routes_ad, &prefix, plen, &nexthop,
                          isb_route->origin, isb_route->route_table,
                          NULL, override_connected, 0);
        if (!route_adv) {
            /* Delete the extra route from IC-SB. */
            VLOG_DBG("Delete route %s -> %s from IC-SB, which is not found"
                     " in local routes to be advertised.",
                     isb_route->ip_prefix, isb_route->nexthop);
            icsbrec_route_delete(isb_route);
        } else {
            ad_route_sync_external_ids(route_adv, isb_route);

            hmap_remove(routes_ad, &route_adv->node);
            free(route_adv);
        }
    }
    icsbrec_route_index_destroy_row(isb_route_key);

    struct ds prefix = DS_EMPTY_INITIALIZER;

    /* Create the missing routes in IC-SB */
    struct ic_route_info *route_adv;
    HMAP_FOR_EACH_SAFE (route_adv, node, routes_ad) {
        ds_clear(&prefix);
        ipv6_format_mapped(&route_adv->prefix, &prefix);
        ds_put_format(&prefix, "/%d", route_adv->plen);
        char *nexthop_s = normalize_v46(&route_adv->nexthop);

        isb_route = icsbrec_route_insert(ctx->ovnisb_unlocked_txn);
        icsbrec_route_set_transit_switch(isb_route, ts_name);
        icsbrec_route_set_availability_zone(isb_route, az);
        icsbrec_route_set_ip_prefix(isb_route, ds_cstr(&prefix));
        icsbrec_route_set_nexthop(isb_route, nexthop_s);
        icsbrec_route_set_origin(isb_route, route_adv->origin);
        icsbrec_route_set_route_table(isb_route, route_adv->route_table
                                                 ? route_adv->route_table
                                                 : "");
        if (route_adv->override_connected) {
            icsbrec_route_update_options_setkey(isb_route,
                ROUTE_OVERRIDE_CONNECTED, "true");
        }
        free(nexthop_s);

        ad_route_sync_external_ids(route_adv, isb_route);

        hmap_remove(routes_ad, &route_adv->node);
        free(route_adv);
    }

    ds_destroy(&prefix);
}

static void
collect_learned_routes(struct ic_context *ctx,
                       struct ic_router_info *ic_lr,
                       const struct sset *ts_scope)
{
    const struct nbrec_logical_router *lr = ic_lr->lr;

    /* Check static routes of the LR and collect learned routes */
    for (int i = 0; i < lr->n_static_routes; i++) {
        const struct nbrec_logical_router_static_route *nb_route
            = lr->static_routes[i];
        struct uuid isb_uuid;
        if (smap_get_uuid(&nb_route->external_ids, "ic-learned-route",
                          &isb_uuid)) {
            /* It is a learned route.  As in build_ts_routes_to_adv(), under a
             * restricted transit switch scope do not collect a learned route
             * whose originating IC-SB route still exists on an out-of-scope
             * transit switch: sync_learned_routes() deletes whatever is left
             * in routes_learned, so collecting it here would wrongly delete
             * another transit switch's route.  This is the fallback path,
             * taken when the router has no in-scope port binding with valid
             * addresses (e.g. a router attached only to out-of-scope transit
             * switches); without this guard a scoped sync of one transit
             * switch wipes the learned routes of every other one. */
            if (ts_scope) {
                const struct icsbrec_route *isb_route =
                    icsbrec_route_get_for_uuid(ctx->ovnisb_unlocked_idl,
                                               &isb_uuid);
                if (isb_route &&
                    !route_ts_in_scope(ts_scope, isb_route->transit_switch)) {
                    continue;
                }
            }
            if (!add_to_routes_learned(&ic_lr->routes_learned, nb_route, lr,
                                       &isb_uuid)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "Bad format of learned route in NB: "
                             "%s -> %s. Delete it.", nb_route->ip_prefix,
                             nb_route->nexthop);
                nbrec_logical_router_update_static_routes_delvalue(lr,
                    nb_route);
            }
        }
    }
}

static void
build_ts_routes_to_adv(struct ic_context *ctx,
                       struct ic_router_info *ic_lr,
                       struct hmap *routes_ad,
                       struct lport_addresses *ts_port_addrs,
                       const struct nbrec_nb_global *nb_global,
                       const char *ts_route_table,
                       const char *route_tag,
                       const struct nbrec_logical_router_port *ts_lrp,
                       const struct sset *ts_scope)
{
    const struct nbrec_logical_router *lr = ic_lr->lr;

    /* Check static routes of the LR */
    for (int i = 0; i < lr->n_static_routes; i++) {
        const struct nbrec_logical_router_static_route *nb_route
            = lr->static_routes[i];
        struct uuid isb_uuid;
        if (smap_get_uuid(&nb_route->external_ids, "ic-learned-route",
                          &isb_uuid)) {
            /* It is a learned route.  When processing a restricted transit
             * switch scope, don't track a learned route whose originating
             * IC-SB route still exists on an out-of-scope transit switch:
             * sync_learned_routes() deletes whatever is left in
             * routes_learned, so tracking it here would wrongly delete another
             * TS's route.  A
             * learned route whose source IC-SB route is gone (e.g. it was
             * withdrawn and re-advertised under a new UUID) IS tracked, so it
             * gets cleaned up as a stale leftover instead of leaking as a
             * duplicate. */
            if (ts_scope) {
                const struct icsbrec_route *isb_route =
                    icsbrec_route_get_for_uuid(ctx->ovnisb_unlocked_idl,
                                               &isb_uuid);
                if (isb_route &&
                    !route_ts_in_scope(ts_scope, isb_route->transit_switch)) {
                    continue;
                }
            }
            if (!add_to_routes_learned(&ic_lr->routes_learned, nb_route, lr,
                                       &isb_uuid)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "Bad format of learned route in NB: "
                             "%s -> %s. Delete it.", nb_route->ip_prefix,
                             nb_route->nexthop);
                nbrec_logical_router_update_static_routes_delvalue(lr,
                    nb_route);
            }
        } else if (!strcmp(ts_route_table, nb_route->route_table)) {
            /* It may be a route to be advertised */
            add_static_to_routes_ad(routes_ad, nb_route, lr, ts_port_addrs,
                                    &nb_global->options, route_tag, ts_lrp);
        }
    }

    /* Check directly-connected subnets of the LR */
    for (int i = 0; i < lr->n_ports; i++) {
        const struct nbrec_logical_router_port *lrp = lr->ports[i];
        if (!lrp_is_ts_port(ctx, ic_lr, lrp->name)) {
            for (int j = 0; j < lrp->n_networks; j++) {
                add_network_to_routes_ad(routes_ad, lrp->networks[j], lrp,
                                         ts_port_addrs,
                                         &nb_global->options,
                                         lr, ts_lrp, route_tag,
                                         ts_route_table, false);
            }
        } else {
            /* The router port of the TS port is ignored. */
            VLOG_DBG("Skip advertising direct route of lrp %s (TS port)",
                     lrp->name);
        }
    }

    /* Check loadbalancers associated with the LR */
    if (smap_get_bool(&nb_global->options, "ic-route-adv-lb", false)) {
        for (size_t i = 0; i < lr->n_load_balancer; i++) {
            const struct nbrec_load_balancer *nb_lb = lr->load_balancer[i];
            struct smap_node *node;
            SMAP_FOR_EACH (node, &nb_lb->vips) {
                add_lb_vip_to_routes_ad(routes_ad, node->key, nb_lb,
                                        ts_port_addrs,
                                        &nb_global->options,
                                        lr, route_tag, ts_lrp);
            }
        }

        for (size_t i = 0; i < lr->n_load_balancer_group; i++) {
            const struct nbrec_load_balancer_group *nb_lbg =
                lr->load_balancer_group[i];
            for (size_t j = 0; j < nb_lbg->n_load_balancer; j++) {
                const struct nbrec_load_balancer *nb_lb =
                    nb_lbg->load_balancer[j];
                struct smap_node *node;
                SMAP_FOR_EACH (node, &nb_lb->vips) {
                    add_lb_vip_to_routes_ad(routes_ad, node->key, nb_lb,
                                            ts_port_addrs,
                                            &nb_global->options,
                                            lr, route_tag, ts_lrp);
                }
            }
        }
    }

    const struct sbrec_datapath_binding *dp =
        find_sb_dp_by_nb_uuid(ctx->sbrec_datapath_binding_by_nb_uuid,
                              &lr->header_.uuid);
    if (!dp) {
        return;
    }

    struct sbrec_learned_route *filter = sbrec_learned_route_index_init_row(
        ctx->sbrec_learned_route_by_datapath);
    sbrec_learned_route_index_set_datapath(filter, dp);
    struct sbrec_learned_route *sb_route;
    SBREC_LEARNED_ROUTE_FOR_EACH_EQUAL (sb_route, filter,
                                        ctx->sbrec_learned_route_by_datapath) {
        add_network_to_routes_ad(routes_ad, sb_route->ip_prefix, NULL,
                                 ts_port_addrs,
                                 &nb_global->options,
                                 lr, ts_lrp, route_tag, ts_route_table, true);
    }
    sbrec_learned_route_index_destroy_row(filter);
}

static void
collect_lr_routes(struct ic_context *ctx,
                  struct ic_router_info *ic_lr,
                  struct shash *routes_ad_by_ts,
                  const struct sset *ts_scope)
{
    const struct nbrec_nb_global *nb_global =
        nbrec_nb_global_first(ctx->ovnnb_idl);
    ovs_assert(nb_global);

    const struct icsbrec_port_binding *isb_pb;
    const char *lrp_name, *ts_name, *route_table, *route_tag;
    struct lport_addresses ts_port_addrs;
    const struct icnbrec_transit_switch *key;
    const struct nbrec_logical_router_port *lrp;

    struct hmap *routes_ad;
    const struct icnbrec_transit_switch *t_sw;
    bool routes_built = false;
    VECTOR_FOR_EACH (&ic_lr->isb_pbs, isb_pb) {
        key = icnbrec_transit_switch_index_init_row(
            ctx->icnbrec_transit_switch_by_name);
        icnbrec_transit_switch_index_set_name(key, isb_pb->transit_switch);
        t_sw = icnbrec_transit_switch_index_find(
             ctx->icnbrec_transit_switch_by_name, key);
        icnbrec_transit_switch_index_destroy_row(key);
        if (!t_sw) {
            continue;
        }
        ts_name = t_sw->name;
        if (!route_ts_in_scope(ts_scope, ts_name)) {
            continue;
        }
        routes_ad = shash_find_data(routes_ad_by_ts, ts_name);
        if (!routes_ad) {
            routes_ad = xzalloc(sizeof *routes_ad);
            hmap_init(routes_ad);
            shash_add(routes_ad_by_ts, ts_name, routes_ad);
        }

        if (!lrouter_is_enabled(ic_lr->lr)) {
            continue;
        }

        if (!extract_lsp_addresses(isb_pb->address, &ts_port_addrs)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(&rl, "Route sync ignores port %s on ts %s for router"
                         " %s because the addresses are invalid.",
                         isb_pb->logical_port, isb_pb->transit_switch,
                         ic_lr->lr->name);
            continue;
        }
        lrp_name = get_lrp_name_by_ts_port_name(ctx, isb_pb->logical_port);
        lrp = lrp_name ? get_lrp_by_lrp_name(ctx, lrp_name) : NULL;
        if (lrp) {
            route_table = smap_get_def(&lrp->options, "route_table", "");
            route_tag = smap_get_def(&lrp->options, "ic-route-tag", "");
        } else {
            route_table = "";
            route_tag = "";
        }
        routes_built = true;
        build_ts_routes_to_adv(ctx, ic_lr, routes_ad, &ts_port_addrs,
                               nb_global, route_table, route_tag, lrp,
                               ts_scope);
        destroy_lport_addresses(&ts_port_addrs);
    }
    /* If no port binding had valid addresses (e.g. LR disabled
     * and PB address cleared simultaneously), collect learned routes so
     * they can be deleted by sync_learned_routes(). */
    if (!routes_built) {
        collect_learned_routes(ctx, ic_lr, ts_scope);
    }
}

/* Deletes 'isb_route' if it is orphaned: its transit switch no longer exists,
 * or no local LRP matches its nexthop. */
static void
delete_orphan_ic_route(struct ic_context *ctx,
                       const struct icsbrec_route *isb_route)
{
    const struct icnbrec_transit_switch *t_sw_key =
        icnbrec_transit_switch_index_init_row(
            ctx->icnbrec_transit_switch_by_name);
    icnbrec_transit_switch_index_set_name(t_sw_key, isb_route->transit_switch);
    const struct icnbrec_transit_switch *t_sw =
        icnbrec_transit_switch_index_find(ctx->icnbrec_transit_switch_by_name,
                                          t_sw_key);
    icnbrec_transit_switch_index_destroy_row(t_sw_key);

    if (!t_sw || !find_lrp_of_nexthop(ctx, isb_route)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_INFO_RL(&rl, "Deleting orphan ICDB:Route: %s->%s (%s, rtb:%s,"
                     " transit switch: %s)", isb_route->ip_prefix,
                     isb_route->nexthop, isb_route->origin,
                     isb_route->route_table, isb_route->transit_switch);
        icsbrec_route_delete(isb_route);
    }
}

static void
delete_orphan_ic_routes(struct ic_context *ctx,
                         const struct icsbrec_availability_zone *az,
                         const struct sset *ts_scope)
{
    const struct icsbrec_route *isb_route, *isb_route_key;

    if (ts_scope) {
        /* Scoped: walk only the routes on the in-scope transit switches, via
         * the (transit_switch, availability_zone) index - O
         * (routes-on-scoped-TS) instead of O(all routes advertised by the
         * AZ). */
        const char *ts_name;
        SSET_FOR_EACH (ts_name, ts_scope) {
            isb_route_key =
                icsbrec_route_index_init_row(ctx->icsbrec_route_by_ts_az);
            icsbrec_route_index_set_transit_switch(isb_route_key, ts_name);
            icsbrec_route_index_set_availability_zone(isb_route_key, az);
            ICSBREC_ROUTE_FOR_EACH_EQUAL (isb_route, isb_route_key,
                                          ctx->icsbrec_route_by_ts_az) {
                delete_orphan_ic_route(ctx, isb_route);
            }
            icsbrec_route_index_destroy_row(isb_route_key);
        }
        return;
    }

    /* Full scope: every route advertised by this AZ. */
    isb_route_key = icsbrec_route_index_init_row(ctx->icsbrec_route_by_az);
    icsbrec_route_index_set_availability_zone(isb_route_key, az);
    ICSBREC_ROUTE_FOR_EACH_EQUAL (isb_route, isb_route_key,
                                  ctx->icsbrec_route_by_az) {
        delete_orphan_ic_route(ctx, isb_route);
    }
    icsbrec_route_index_destroy_row(isb_route_key);
}

/* Synchronizes advertised and learned routes.  When 'ts_scope' is NULL every
 * transit switch in the AZ is reconciled (full recompute).  When 'ts_scope' is
 * non-NULL, only the transit switches it names are reconciled, together with
 * every local logical router attached to them.  Scoping by transit switch
 * keeps advertise_routes() correct: it deletes any IC-SB route on a (transit
 * switch, AZ) pair that is not in the locally computed set, so a reconciled
 * transit switch must include the routes of all local routers attached to
 * it. */
static void
route_sync_scope(struct ic_context *ctx,
                 const struct icsbrec_availability_zone *runned_az,
                 const struct sset *ts_scope)
{
    if (!ctx->ovnisb_unlocked_txn || !ctx->ovnnb_txn || !ctx->ovnsb_txn) {
        return;
    }

    if (ts_scope && sset_is_empty(ts_scope)) {
        return;
    }

    delete_orphan_ic_routes(ctx, runned_az, ts_scope);

    /* Under a restricted scope, collect only the logical routers attached to
     * an in-scope transit switch.  Their 'router-id's are gathered from the
     * IC-SB port bindings of the in-scope transit switches
     * (icsbrec_port_binding_by_ts_az, O(ports-on-scoped-TS)); every other
     * router is skipped in the collection loop below before any expensive
     * lookup.  This keeps route_sync_scope's cost proportional to the scope
     * instead of to the whole AZ, while still building each in-scope router's
     * FULL port set (the by-AZ walk visits all its ports), which the
     * connected-route logic requires.  Collecting a superset of routers would
     * only be wasteful, never wrong; collecting a subset could make
     * advertise_routes() wrongly delete an in-scope TS route, so the set is
     * built from every port binding on the in-scope transit switches. */
    struct sset scope_lr_ids = SSET_INITIALIZER(&scope_lr_ids);
    if (ts_scope) {
        const char *ts_name;
        SSET_FOR_EACH (ts_name, ts_scope) {
            const struct icsbrec_port_binding *pb_ts_key =
                icsbrec_port_binding_index_init_row(
                    ctx->icsbrec_port_binding_by_ts_az);
            icsbrec_port_binding_index_set_transit_switch(pb_ts_key, ts_name);
            icsbrec_port_binding_index_set_availability_zone(pb_ts_key,
                runned_az);
            const struct icsbrec_port_binding *pb;
            ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, pb_ts_key,
                ctx->icsbrec_port_binding_by_ts_az) {
                const char *lr_id = smap_get(&pb->external_ids, "router-id");
                if (lr_id) {
                    sset_add(&scope_lr_ids, lr_id);
                }
            }
            icsbrec_port_binding_index_destroy_row(pb_ts_key);
        }
    }

    struct hmap ic_lrs = HMAP_INITIALIZER(&ic_lrs);
    const struct icsbrec_port_binding *isb_pb;
    const struct icsbrec_port_binding *isb_pb_key =
        icsbrec_port_binding_index_init_row(ctx->icsbrec_port_binding_by_az);
    icsbrec_port_binding_index_set_availability_zone(isb_pb_key,
        runned_az);

    /* Each port on TS maps to a logical router, which is stored in the
     * external_ids:router-id of the IC SB port_binding record.
     * Here we build info for interconnected Logical Router:
     * collect IC Port Binding to process routes sync later on. */
    ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
                                         ctx->icsbrec_port_binding_by_az)
    {
        /* Scoped sync: skip routers not attached to any in-scope transit
         * switch before doing any expensive lookup. */
        if (ts_scope) {
            const char *lr_id = smap_get(&isb_pb->external_ids, "router-id");
            if (!lr_id || !sset_contains(&scope_lr_ids, lr_id)) {
                continue;
            }
        }

        /* Build the full per-router port set regardless of scope: the
         * connected route logic (lrp_is_ts_port) needs to recognise every one
         * of a router's transit-switch ports, not just the in-scope ones,
         * otherwise an out-of-scope TS port's subnet would be wrongly
         * advertised.  The scope is applied later, per transit switch, in
         * collect_lr_routes() and sync_learned_routes(). */
        if (ic_pb_get_type(isb_pb) == IC_ROUTER_PORT) {
            continue;
        }
        const struct nbrec_logical_switch_port *nb_lsp;

        nb_lsp = get_lsp_by_ts_port_name(ctx, isb_pb->logical_port);
        if (!nb_lsp) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_DBG_RL(&rl,
                        "IC-SB Port_Binding '%s' on ts '%s': "
                        "NB LSP not found, skipping route collection.",
                        isb_pb->logical_port, isb_pb->transit_switch);
            continue;
        }

        if (!strcmp(nb_lsp->type, "switch") || !strcmp(nb_lsp->type, "")) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_DBG_RL(&rl,
                        "IC-SB Port_Binding '%s' on ts '%s' corresponds to a "
                        "switch port, not considering for route collection.",
                        isb_pb->logical_port, isb_pb->transit_switch);
            continue;
        }

        const char *ts_lrp_name =
            get_lrp_name_by_ts_port_name(ctx, isb_pb->logical_port);
        if (!ts_lrp_name) {
            if (!strcmp(isb_pb->type, "transit-switch-port")) {
                continue;
            }
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Route sync ignores port %s on ts %s because "
                         "logical router port is not found in NB. Deleting it",
                         isb_pb->logical_port, isb_pb->transit_switch);
            icsbrec_port_binding_delete(isb_pb);
            continue;
        }

        struct uuid lr_uuid;
        if (!smap_get_uuid(&isb_pb->external_ids, "router-id", &lr_uuid)) {
            VLOG_DBG("IC-SB Port_Binding %s doesn't have "
                     "external_ids:router-id set.", isb_pb->logical_port);
            continue;
        }

        const struct nbrec_logical_router *lr
            = nbrec_logical_router_get_for_uuid(ctx->ovnnb_idl, &lr_uuid);
        if (!lr) {
            continue;
        }

        struct ic_router_info *ic_lr = ic_router_find(&ic_lrs, lr);
        if (!ic_lr) {
            ic_lr = xzalloc(sizeof *ic_lr);
            ic_lr->lr = lr;
            ic_lr->isb_pbs =
                VECTOR_EMPTY_INITIALIZER(const struct icsbrec_port_binding *);
            hmap_init(&ic_lr->routes_learned);
            hmap_insert(&ic_lrs, &ic_lr->node, uuid_hash(&lr->header_.uuid));
        }
        vector_push(&ic_lr->isb_pbs, &isb_pb);
    }
    icsbrec_port_binding_index_destroy_row(isb_pb_key);

    struct ic_router_info *ic_lr;
    struct shash routes_ad_by_ts = SHASH_INITIALIZER(&routes_ad_by_ts);
    HMAP_FOR_EACH_SAFE (ic_lr, node, &ic_lrs) {
        collect_lr_routes(ctx, ic_lr, &routes_ad_by_ts, ts_scope);
        sync_learned_routes(ctx, runned_az, ic_lr, ts_scope);
        vector_destroy(&ic_lr->isb_pbs);
        hmap_destroy(&ic_lr->routes_learned);
        hmap_remove(&ic_lrs, &ic_lr->node);
        free(ic_lr);
    }
    struct shash_node *node;
    SHASH_FOR_EACH (node, &routes_ad_by_ts) {
        advertise_routes(ctx, runned_az, node->name, node->data);
        hmap_destroy(node->data);
    }
    shash_destroy_free_data(&routes_ad_by_ts);
    hmap_destroy(&ic_lrs);
    sset_destroy(&scope_lr_ids);
}

static void
route_run(struct ic_context *ctx,
          const struct icsbrec_availability_zone *runned_az)
{
    route_sync_scope(ctx, runned_az, NULL);
}

/* Builds 'lr_ts_map': a map from the canonical UUID string of each NB logical
 * router interconnected in this AZ to a 'struct sset *' of the transit-switch
 * names it is attached to.  Used by the en_route change handlers to translate
 * a changed NB/SB row into the set of transit switches that must be
 * reconciled.
 * Destroy with route_lr_ts_map_destroy(). */
static void
route_lr_ts_map_init(struct ic_context *ctx,
                     const struct icsbrec_availability_zone *runned_az,
                     struct shash *lr_ts_map)
{
    shash_init(lr_ts_map);

    if (!runned_az) {
        return;
    }

    const struct icsbrec_port_binding *isb_pb;
    const struct icsbrec_port_binding *isb_pb_key =
        icsbrec_port_binding_index_init_row(ctx->icsbrec_port_binding_by_az);
    icsbrec_port_binding_index_set_availability_zone(isb_pb_key,
                                                     runned_az);
    ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
                                         ctx->icsbrec_port_binding_by_az) {
        const char *lr_id = smap_get(&isb_pb->external_ids, "router-id");
        if (!lr_id) {
            continue;
        }
        struct sset *ts_set = shash_find_data(lr_ts_map, lr_id);
        if (!ts_set) {
            ts_set = xmalloc(sizeof *ts_set);
            sset_init(ts_set);
            shash_add(lr_ts_map, lr_id, ts_set);
        }
        sset_add(ts_set, isb_pb->transit_switch);
    }
    icsbrec_port_binding_index_destroy_row(isb_pb_key);
}

static void
route_lr_ts_map_destroy(struct shash *lr_ts_map)
{
    struct shash_node *node;
    SHASH_FOR_EACH (node, lr_ts_map) {
        sset_destroy(node->data);
        free(node->data);
    }
    shash_destroy(lr_ts_map);
}

/* en_route tracked data.  'synced_ts' holds the transit switches already
 * reconciled by route_sync_scope() during the current engine run.  Because
 * several en_route input handlers can fire in one iteration and each maps its
 * change to a transit-switch scope, the same TS could be synced more than once
 * per iteration.  A repeat sync is not only redundant - it duplicates learned
 * routes: the NB static routes inserted by the first sync are not yet visible
 * on the logical router's static_routes column within the same transaction, so
 * sync_learned_routes() would re-insert them.  The engine clears this set at
 * the start of every engine run (engine_init_run -> clear_tracked_data). */
struct ed_type_route {
    struct sset synced_ts;
    /* Snapshot of the NB Global 'options' keys that gate route processing
     * (the 'ic-route-*' set listed in route_nb_global_opt_keys), taken at the
     * end of the last en_route_run().  The NB Global handler compares the live
     * options against this snapshot so that churn on unrelated keys - such as
     * ovn-northd's 'max_tunid'/'mac_prefix'/'northd_internal_version'
     * bookkeeping - does not force a full route recompute.  Persistent across
     * runs (not cleared by clear_tracked_data). */
    struct smap nb_global_opts;
};

/* NB Global 'options' keys read by route processing (see route_need_advertise,
 * route_need_learn and prefix_is_deny_filtered in ovn-ic.c).  A change to any
 * of these alters the global advertise/learn gates of every transit switch, so
 * it warrants a full route recompute; a change to any other 'options' key does
 * not concern route processing. */
static const char *route_nb_global_opt_keys[] = {
    "ic-route-adv",
    "ic-route-adv-default",
    "ic-route-adv-lb",
    "ic-route-learn",
    "ic-route-learn-default",
    "ic-route-learn-lb",
    "ic-route-denylist",
    "ic-route-blacklist",
};

/* Fills 'snap' with the route-relevant NB Global 'options' keys (those in
 * route_nb_global_opt_keys that are set) from the current NB Global row. */
static void
route_snapshot_nb_global_opts(struct engine_node *node, struct smap *snap)
{
    smap_clear(snap);
    const struct nbrec_nb_global_table *tbl =
        EN_OVSDB_GET(engine_get_input("NB_nb_global", node));
    const struct nbrec_nb_global *nb_global =
        nbrec_nb_global_table_first(tbl);
    if (!nb_global) {
        return;
    }
    for (size_t i = 0; i < ARRAY_SIZE(route_nb_global_opt_keys); i++) {
        const char *key = route_nb_global_opt_keys[i];
        const char *val = smap_get(&nb_global->options, key);
        if (val) {
            smap_add(snap, key, val);
        }
    }
}

enum engine_node_state
en_route_run(struct engine_node *node, void *data_)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    struct ed_type_route *data = data_;
    const struct ed_type_az *az = engine_get_input_data("az", node);

    /* runned_az is resolved by the upstream en_az node.  Without an AZ there
     * is nothing to sync (mirrors the previous main-loop gating). */
    if (!az->runned_az) {
        return EN_UNCHANGED;
    }

    route_run(ctx, az->runned_az);

    /* Refresh the snapshot of route-relevant NB Global options so the
     * NB Global handler can detect a real gate change on the next iteration.
     */
    route_snapshot_nb_global_opts(node, &data->nb_global_opts);

    return EN_UPDATED;
}

/* Returns the ic_context, or NULL when there is no availability zone yet (in
 * which case the caller should report EN_HANDLED_UNCHANGED: there is nothing
 * for the route engine to do). */
static struct ic_context *
route_handler_ctx(struct engine_node *node,
                  const struct icsbrec_availability_zone **runned_az)
{
    struct ic_context *ctx = engine_get_context()->client_ctx;
    const struct ed_type_az *az = engine_get_input_data("az", node);
    *runned_az = az->runned_az;
    return az->runned_az ? ctx : NULL;
}

/* The route handlers translate a changed input row into the set of transit
 * switches that must be reconciled, then call route_sync_scope() on that set
 * instead of forcing a full recompute.  Reconciling per transit switch keeps
 * both directions correct: advertise_routes() reconciles all local routers
 * attached to a transit switch at once, and sync_learned_routes() reconciles a
 * router against the IC-SB routes of the transit switches in scope. */

/* Unions the transit-switch names that the interconnected logical router
 * 'lr_uuid' attaches to (per 'lr_ts_map') into 'affected'. */
static void
route_scope_add_lr_uuid(struct shash *lr_ts_map, const struct uuid *lr_uuid,
                        struct sset *affected)
{
    char *uuid_s = xasprintf(UUID_FMT, UUID_ARGS(lr_uuid));
    const struct sset *ts_set = shash_find_data(lr_ts_map, uuid_s);
    free(uuid_s);
    if (!ts_set) {
        return;
    }
    const char *ts_name;
    SSET_FOR_EACH (ts_name, ts_set) {
        sset_add(affected, ts_name);
    }
}

typedef bool (*route_lr_match_fn)(const struct nbrec_logical_router *lr,
                                  const void *aux);

/* For each interconnected logical router (per 'lr_ts_map') whose NB row
 * matches 'match', unions its transit-switch names into 'affected'.  Used when
 * the changed row (an LRP, a static route, a load balancer) does not itself
 * name a router, so the owning router is found by membership. */
static void
route_scope_add_matching_lrs(struct ic_context *ctx, struct shash *lr_ts_map,
                             route_lr_match_fn match, const void *aux,
                             struct sset *affected)
{
    struct shash_node *node;
    SHASH_FOR_EACH (node, lr_ts_map) {
        struct uuid lr_uuid;
        if (!uuid_from_string(&lr_uuid, node->name)) {
            continue;
        }
        const struct nbrec_logical_router *lr =
            nbrec_logical_router_get_for_uuid(ctx->ovnnb_idl, &lr_uuid);
        if (!lr || !match(lr, aux)) {
            continue;
        }
        const struct sset *ts_set = node->data;
        const char *ts_name;
        SSET_FOR_EACH (ts_name, ts_set) {
            sset_add(affected, ts_name);
        }
    }
}

static bool
lr_has_port(const struct nbrec_logical_router *lr, const void *aux)
{
    const struct nbrec_logical_router_port *lrp = aux;
    for (size_t i = 0; i < lr->n_ports; i++) {
        if (lr->ports[i] == lrp) {
            return true;
        }
    }
    return false;
}

static bool
lr_has_static_route(const struct nbrec_logical_router *lr, const void *aux)
{
    const struct nbrec_logical_router_static_route *sr = aux;
    for (size_t i = 0; i < lr->n_static_routes; i++) {
        if (lr->static_routes[i] == sr) {
            return true;
        }
    }
    return false;
}

static bool
lr_uses_lb(const struct nbrec_logical_router *lr, const void *aux)
{
    const struct nbrec_load_balancer *lb = aux;
    for (size_t i = 0; i < lr->n_load_balancer; i++) {
        if (lr->load_balancer[i] == lb) {
            return true;
        }
    }
    for (size_t i = 0; i < lr->n_load_balancer_group; i++) {
        const struct nbrec_load_balancer_group *lbg =
            lr->load_balancer_group[i];
        for (size_t j = 0; j < lbg->n_load_balancer; j++) {
            if (lbg->load_balancer[j] == lb) {
                return true;
            }
        }
    }
    return false;
}

static bool
lr_uses_lbg(const struct nbrec_logical_router *lr, const void *aux)
{
    const struct nbrec_load_balancer_group *lbg = aux;
    for (size_t i = 0; i < lr->n_load_balancer_group; i++) {
        if (lr->load_balancer_group[i] == lbg) {
            return true;
        }
    }
    return false;
}

/* Runs the scoped route sync for the transit switches in 'affected' and maps
 * it to an engine result.  'updated' is set when the caller already applied a
 * direct NB change.  When there is work to do but the transactions needed by
 * route_sync_scope() are not available yet, returns EN_UNHANDLED so the change
 * is retried (rather than silently dropped). */
static enum engine_input_handler_result
route_scope_finish(struct ic_context *ctx,
                   const struct icsbrec_availability_zone *runned_az,
                   struct sset *affected, bool updated,
                   void *node_data)
{
    struct ed_type_route *rt = node_data;

    /* Drop transit switches already reconciled earlier in this engine run:
     * route_sync_scope() fully reconciles a TS, so a repeat sync is redundant
     * and would duplicate learned routes (see 'synced_ts'). */
    const char *ts_name;
    SSET_FOR_EACH_SAFE (ts_name, affected) {
        if (sset_contains(&rt->synced_ts, ts_name)) {
            sset_find_and_delete(affected, ts_name);
        }
    }

    if (!sset_is_empty(affected)) {
        if (!ctx->ovnisb_unlocked_txn || !ctx->ovnnb_txn || !ctx->ovnsb_txn) {
            return EN_UNHANDLED;
        }
        SSET_FOR_EACH (ts_name, affected) {
            sset_add(&rt->synced_ts, ts_name);
        }
        route_sync_scope(ctx, runned_az, affected);
        updated = true;
    }
    return updated ? EN_HANDLED_UPDATED : EN_HANDLED_UNCHANGED;
}

/* NB Global: only the 'options' smap holds the route gates
 * (ic-route-adv/-learn/-denylist...).  Other columns (connections, ssl,
 * external_ids) do not affect route processing, and neither do options keys
 * outside route_nb_global_opt_keys - in particular ovn-northd routinely bumps
 * unrelated keys such as 'max_tunid', 'mac_prefix' and
 * 'northd_internal_version'.  Compare the live route gates against the
 * snapshot taken on the last run: a change to any of them affects the global
 * filters of every transit switch, so it falls back to a full recompute;
 * otherwise the options change is irrelevant to routes and is handled as
 * a no-op. */
enum engine_input_handler_result
route_nb_nb_global_handler(struct engine_node *node, void *data_)
{
    const struct ed_type_az *az = engine_get_input_data("az", node);
    if (!az->runned_az) {
        return EN_HANDLED_UNCHANGED;
    }

    struct ed_type_route *data = data_;
    struct smap cur = SMAP_INITIALIZER(&cur);
    route_snapshot_nb_global_opts(node, &cur);

    bool changed = !smap_equal(&cur, &data->nb_global_opts);
    smap_destroy(&data->nb_global_opts);
    smap_clone(&data->nb_global_opts, &cur);
    smap_destroy(&cur);

    return changed ? EN_UNHANDLED : EN_HANDLED_UNCHANGED;
}

/* Returns the IC-NB transit switch named 'name', or NULL. */
static const struct icnbrec_transit_switch *
route_find_ts_in_icnb(struct ic_context *ctx, const char *name)
{
    const struct icnbrec_transit_switch *key =
        icnbrec_transit_switch_index_init_row(
            ctx->icnbrec_transit_switch_by_name);
    icnbrec_transit_switch_index_set_name(key, name);
    const struct icnbrec_transit_switch *ts =
        icnbrec_transit_switch_index_find(ctx->icnbrec_transit_switch_by_name,
                                          key);
    icnbrec_transit_switch_index_destroy_row(key);
    return ts;
}

/* NB Logical_Switch: only transit-switch mirrors (other_config:interconn-ts)
 * are read by route_run (via find_ts_in_nb()/find_lrp_of_nexthop()).  A change
 * to such a switch's name, ports or other_config needs the corresponding
 * transit switch re-synced; any other logical switch (tenant churn) is
 * irrelevant. */
enum engine_input_handler_result
route_nb_logical_switch_handler(struct engine_node *node,
                                void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = route_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct nbrec_logical_switch_table *tbl =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));
    struct sset affected = SSET_INITIALIZER(&affected);
    const struct nbrec_logical_switch *ls;
    NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH_TRACKED (ls, tbl) {
        bool oc_updated = ovsdb_idl_track_is_updated(&ls->header_,
                              &nbrec_logical_switch_col_other_config);
        const char *ts_name = smap_get(&ls->other_config, "interconn-ts");

        /* The tracked row only carries the new other_config, so a switch that
         * just stopped mirroring a transit switch - or that now mirrors a
         * different one - no longer names the transit switch that has to be
         * re-synced.  A mirror is always created named after its transit
         * switch (ts_sync_one()), so fall back to the switch name to find the
         * transit switch it used to mirror. */
        if (oc_updated && (!ts_name || strcmp(ts_name, ls->name))
            && route_find_ts_in_icnb(ctx, ls->name)) {
            sset_add(&affected, ls->name);
        }

        if (!ts_name) {
            continue;
        }
        if (nbrec_logical_switch_is_new(ls) ||
            nbrec_logical_switch_is_deleted(ls) ||
            oc_updated ||
            ovsdb_idl_track_is_updated(&ls->header_,
                                       &nbrec_logical_switch_col_name) ||
            ovsdb_idl_track_is_updated(&ls->header_,
                                       &nbrec_logical_switch_col_ports)) {
            sset_add(&affected, ts_name);
        }
    }

    enum engine_input_handler_result ret =
        route_scope_finish(ctx, runned_az, &affected, false, data);
    sset_destroy(&affected);
    return ret;
}

/* NB Logical_Router: a new router, or a change to options, ports,
 * load_balancer or load_balancer_group affects which routes the router
 * advertises.  Scope to the transit switches the router attaches to.  A change
 * limited to the static_routes column is delegated to the static-route handler
 * (which co-fires in the same iteration).  A router deletion can no longer be
 * mapped to its transit switches (its IC-SB port bindings are being removed),
 * so it falls back to a full recompute. */
enum engine_input_handler_result
route_nb_logical_router_handler(struct engine_node *node,
                                void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = route_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct nbrec_logical_router_table *tbl =
        EN_OVSDB_GET(engine_get_input("NB_logical_router", node));
    struct shash lr_ts_map;
    route_lr_ts_map_init(ctx, runned_az, &lr_ts_map);
    struct sset affected = SSET_INITIALIZER(&affected);
    bool unhandled = false;

    const struct nbrec_logical_router *lr;
    NBREC_LOGICAL_ROUTER_TABLE_FOR_EACH_TRACKED (lr, tbl) {
        if (nbrec_logical_router_is_deleted(lr)) {
            unhandled = true;
            break;
        }
        if (nbrec_logical_router_is_new(lr) ||
            ovsdb_idl_track_is_updated(&lr->header_,
                                       &nbrec_logical_router_col_options) ||
            ovsdb_idl_track_is_updated(&lr->header_,
                                       &nbrec_logical_router_col_enabled) ||
            ovsdb_idl_track_is_updated(&lr->header_,
                                       &nbrec_logical_router_col_ports) ||
            ovsdb_idl_track_is_updated(
                &lr->header_, &nbrec_logical_router_col_load_balancer) ||
            ovsdb_idl_track_is_updated(
                &lr->header_,
                &nbrec_logical_router_col_load_balancer_group)) {
            route_scope_add_lr_uuid(&lr_ts_map, &lr->header_.uuid, &affected);
        }
    }

    enum engine_input_handler_result ret =
        unhandled ? EN_UNHANDLED
                  : route_scope_finish(ctx, runned_az, &affected, false, data);
    sset_destroy(&affected);
    route_lr_ts_map_destroy(&lr_ts_map);
    return ret;
}

/* NB Logical_Router_Port: networks and options (route_table, ic-route-tag,
 * ic-route-learn-tag-rules, and the deprecated ic-route-filter-tag) affect
 * connected-route advertising and learning for the owning router.  Port
 * creation/deletion changes the router's 'ports' column and is handled by
 * route_nb_logical_router_handler; here only column updates to an existing
 * port need to be scoped to the owning router. */
enum engine_input_handler_result
route_nb_logical_router_port_handler(struct engine_node *node,
                                     void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = route_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct nbrec_logical_router_port_table *tbl =
        EN_OVSDB_GET(engine_get_input("NB_logical_router_port", node));
    struct shash lr_ts_map;
    route_lr_ts_map_init(ctx, runned_az, &lr_ts_map);
    struct sset affected = SSET_INITIALIZER(&affected);

    const struct nbrec_logical_router_port *lrp;
    NBREC_LOGICAL_ROUTER_PORT_TABLE_FOR_EACH_TRACKED (lrp, tbl) {
        if (nbrec_logical_router_port_is_new(lrp) ||
            nbrec_logical_router_port_is_deleted(lrp)) {
            continue;
        }
        route_scope_add_matching_lrs(ctx, &lr_ts_map, lr_has_port, lrp,
                                     &affected);
    }

    enum engine_input_handler_result ret =
        route_scope_finish(ctx, runned_az, &affected, false, data);
    sset_destroy(&affected);
    route_lr_ts_map_destroy(&lr_ts_map);
    return ret;
}

/* NB Logical_Router_Static_Route: routes this engine created when learning
 * remote routes carry external_ids:ic-learned-route, so their own
 * create/update/delete events must be ignored (otherwise the engine ping-pongs
 * on its own write-backs).  A user-authored static route may need
 * (re)advertising on the transit switches of its owning router.  A deletion
 * can no longer be mapped to its owner (it was removed from the router's
 * static_routes column), so it falls back to a full recompute. */
enum engine_input_handler_result
route_nb_logical_router_static_route_handler(struct engine_node *node,
                                             void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = route_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct nbrec_logical_router_static_route_table *tbl =
        EN_OVSDB_GET(engine_get_input("NB_logical_router_static_route", node));
    struct shash lr_ts_map;
    route_lr_ts_map_init(ctx, runned_az, &lr_ts_map);
    struct sset affected = SSET_INITIALIZER(&affected);
    bool unhandled = false;

    const struct nbrec_logical_router_static_route *sr;
    NBREC_LOGICAL_ROUTER_STATIC_ROUTE_TABLE_FOR_EACH_TRACKED (sr, tbl) {
        if (smap_get(&sr->external_ids, "ic-learned-route")) {
            /* Our own learned-route write-back: ignore. */
            continue;
        }
        if (nbrec_logical_router_static_route_is_deleted(sr)) {
            unhandled = true;
            break;
        }
        /* User route - may need (re)advertising on its router's TSes. */
        route_scope_add_matching_lrs(ctx, &lr_ts_map, lr_has_static_route, sr,
                                     &affected);
    }

    enum engine_input_handler_result ret =
        unhandled ? EN_UNHANDLED
                  : route_scope_finish(ctx, runned_az, &affected, false, data);
    sset_destroy(&affected);
    route_lr_ts_map_destroy(&lr_ts_map);
    return ret;
}

/* NB Logical_Switch_Port: route_run reads a transit-switch-mirror port's
 * 'type' and 'options:router-port' (via get_lsp_by_ts_port_name() and
 * find_lrp_of_nexthop()) to map IC-SB port bindings to their owning logical
 * router and to resolve learned-route nexthops.  A column change on such a
 * port reconciles its transit switch; ports that do not belong to a
 * transit-switch mirror (ordinary tenant ports) are irrelevant.  Port
 * creation/deletion changes the mirror's 'ports' column and is handled by
 * route_nb_logical_switch_handler. */
enum engine_input_handler_result
route_nb_logical_switch_port_handler(struct engine_node *node,
                                     void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = route_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct nbrec_logical_switch_port_table *tbl =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch_port", node));
    struct sset affected = SSET_INITIALIZER(&affected);
    struct shash lsp_ts_map;
    port_binding_lsp_ts_map_init(ctx, &lsp_ts_map);
    const struct nbrec_logical_switch_port *lsp;
    NBREC_LOGICAL_SWITCH_PORT_TABLE_FOR_EACH_TRACKED (lsp, tbl) {
        if (nbrec_logical_switch_port_is_new(lsp) ||
            nbrec_logical_switch_port_is_deleted(lsp)) {
            continue;
        }
        port_binding_collect_lsp_ts(&lsp_ts_map, lsp, &affected);
    }
    shash_destroy(&lsp_ts_map);

    enum engine_input_handler_result ret =
        route_scope_finish(ctx, runned_az, &affected, false, data);
    sset_destroy(&affected);
    return ret;
}

/* NB Load_Balancer: when ic-route-adv-lb is set, VIPs of LBs attached to a
 * router (directly or via a load-balancer group) are advertised.  A VIP change
 * on an already-referenced LB does not touch the router's columns, so scope to
 * the routers that use this LB.  LB deletion changes the router's
 * load_balancer column and is handled by route_nb_logical_router_handler. */
enum engine_input_handler_result
route_nb_load_balancer_handler(struct engine_node *node, void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = route_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct nbrec_load_balancer_table *tbl =
        EN_OVSDB_GET(engine_get_input("NB_load_balancer", node));
    struct shash lr_ts_map;
    route_lr_ts_map_init(ctx, runned_az, &lr_ts_map);
    struct sset affected = SSET_INITIALIZER(&affected);

    const struct nbrec_load_balancer *lb;
    NBREC_LOAD_BALANCER_TABLE_FOR_EACH_TRACKED (lb, tbl) {
        if (nbrec_load_balancer_is_deleted(lb)) {
            continue;
        }
        route_scope_add_matching_lrs(ctx, &lr_ts_map, lr_uses_lb, lb,
                                     &affected);
    }

    enum engine_input_handler_result ret =
        route_scope_finish(ctx, runned_az, &affected, false, data);
    sset_destroy(&affected);
    route_lr_ts_map_destroy(&lr_ts_map);
    return ret;
}

/* NB Load_Balancer_Group: a membership change affects routers that reference
 * the group.  Group removal changes the router's load_balancer_group column
 * and is handled by route_nb_logical_router_handler. */
enum engine_input_handler_result
route_nb_load_balancer_group_handler(struct engine_node *node,
                                     void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = route_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct nbrec_load_balancer_group_table *tbl =
        EN_OVSDB_GET(engine_get_input("NB_load_balancer_group", node));
    struct shash lr_ts_map;
    route_lr_ts_map_init(ctx, runned_az, &lr_ts_map);
    struct sset affected = SSET_INITIALIZER(&affected);

    const struct nbrec_load_balancer_group *lbg;
    NBREC_LOAD_BALANCER_GROUP_TABLE_FOR_EACH_TRACKED (lbg, tbl) {
        if (nbrec_load_balancer_group_is_deleted(lbg)) {
            continue;
        }
        route_scope_add_matching_lrs(ctx, &lr_ts_map, lr_uses_lbg, lbg,
                                     &affected);
    }

    enum engine_input_handler_result ret =
        route_scope_finish(ctx, runned_az, &affected, false, data);
    sset_destroy(&affected);
    route_lr_ts_map_destroy(&lr_ts_map);
    return ret;
}

/* Removes the engine-created NB static routes that learned 'isb_route'
 * (matched by external_ids:ic-learned-route == isb_route's UUID), detaching
 * them from their logical routers.  Every local router attached to the route's
 * transit switch learns it, so each one holds its own copy and all of them are
 * removed.  Returns true if any was found and removed.
 *
 * Only a local router attached to the withdrawn route's transit switch can
 * hold the learned NB route, so the candidate routers are looked up via the
 * (transit_switch, availability_zone) index rather than scanning every logical
 * router in the AZ (which is O(routers) per withdrawal).  The withdrawal of a
 * remote route does not remove the local router's port binding, so the router
 * is still present on the transit switch here; a transit-switch teardown that
 * removes the port binding is reconciled by the recompute paths instead. */
static bool
route_remove_learned_nb_route(
    struct ic_context *ctx,
    const struct icsbrec_availability_zone *runned_az,
    const struct icsbrec_route *isb_route)
{
    char *uuid_s = xasprintf(UUID_FMT, UUID_ARGS(&isb_route->header_.uuid));
    bool removed = false;

    struct sset lr_ids = SSET_INITIALIZER(&lr_ids);
    const struct icsbrec_port_binding *pb_key =
       icsbrec_port_binding_index_init_row(ctx->icsbrec_port_binding_by_ts_az);
    icsbrec_port_binding_index_set_transit_switch(pb_key,
                                                  isb_route->transit_switch);
    icsbrec_port_binding_index_set_availability_zone(pb_key, runned_az);
    const struct icsbrec_port_binding *pb;
    ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, pb_key,
                                         ctx->icsbrec_port_binding_by_ts_az) {
        const char *lr_id = smap_get(&pb->external_ids, "router-id");
        if (lr_id) {
            sset_add(&lr_ids, lr_id);
        }
    }
    icsbrec_port_binding_index_destroy_row(pb_key);

    const char *lr_id;
    SSET_FOR_EACH (lr_id, &lr_ids) {
        struct uuid lr_uuid;
        if (!uuid_from_string(&lr_uuid, lr_id)) {
            continue;
        }
        const struct nbrec_logical_router *lr =
            nbrec_logical_router_get_for_uuid(ctx->ovnnb_idl, &lr_uuid);
        if (!lr) {
            continue;
        }
        for (size_t i = 0; i < lr->n_static_routes; i++) {
            const struct nbrec_logical_router_static_route *sr =
                lr->static_routes[i];
            const char *learned =
                smap_get(&sr->external_ids, "ic-learned-route");
            if (learned && !strcmp(learned, uuid_s)) {
                nbrec_logical_router_update_static_routes_delvalue(lr, sr);
                removed = true;
                break;
            }
        }
    }

    sset_destroy(&lr_ids);
    free(uuid_s);
    return removed;
}

/* IC-SB Route: the most impactful input.  Each relevant change is scoped to
 * the route's transit switch.  See the per-case comments. */
enum engine_input_handler_result
route_icsb_route_handler(struct engine_node *node, void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = route_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct icsbrec_route_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICSB_route", node));
    struct sset affected = SSET_INITIALIZER(&affected);
    const struct icsbrec_route *isb_route;
    bool updated = false;

    ICSBREC_ROUTE_TABLE_FOR_EACH_TRACKED (isb_route, tbl) {
        bool ours = isb_route->availability_zone == runned_az;

        if (icsbrec_route_is_deleted(isb_route)) {
            if (ours) {
                /* A route advertised from this AZ was removed: re-advertise
                 * and let same-AZ learners un-learn, scoped to its TS. */
                sset_add(&affected, isb_route->transit_switch);
            } else {
                /* A remote route we had learned is gone: drop the matching NB
                 * static route directly. */
                if (!ctx->ovnnb_txn) {
                    sset_destroy(&affected);
                    return EN_UNHANDLED;
                }
                if (route_remove_learned_nb_route(ctx, runned_az, isb_route)) {
                    updated = true;
                }
            }
        } else if (icsbrec_route_is_new(isb_route)) {
            /* A new route needs the full router context to decide learning
             * (route_need_learn / NB Global options / filters), but only for
             * routers attached to its transit switch. */
            sset_add(&affected, isb_route->transit_switch);
        } else if (!ours) {
            /* A remote route changed.  Re-sync its TS only when a column that
             * route learning actually reads changed: the
             * prefix/nexthop/origin/route_table/transit_switch/AZ, the
             * ic-route-tag in external_ids used by learn filters, or the
             * connected-route override in options.  The IDL routinely reports
             * a tracked row as updated even when no column value changed
             * (e.g. a no-op write echoed back on a monitor update); at scale
             * every AZ's route sync surfaces every other AZ's routes as such
             * no-op changes, so re-syncing unconditionally would reconcile
             * every transit switch on every change (O(number of interconnected
             * routes)). */
            if (ovsdb_idl_track_is_updated(&isb_route->header_,
                                           &icsbrec_route_col_ip_prefix) ||
                ovsdb_idl_track_is_updated(&isb_route->header_,
                                           &icsbrec_route_col_nexthop) ||
                ovsdb_idl_track_is_updated(&isb_route->header_,
                                           &icsbrec_route_col_origin) ||
                ovsdb_idl_track_is_updated(&isb_route->header_,
                                           &icsbrec_route_col_route_table) ||
                ovsdb_idl_track_is_updated(&isb_route->header_,
                                        &icsbrec_route_col_transit_switch) ||
                ovsdb_idl_track_is_updated(&isb_route->header_,
                                        &icsbrec_route_col_availability_zone)
                || ovsdb_idl_track_is_updated(&isb_route->header_,
                                        &icsbrec_route_col_external_ids) ||
                ovsdb_idl_track_is_updated(&isb_route->header_,
                                           &icsbrec_route_col_options)) {
                sset_add(&affected, isb_route->transit_switch);
            }
        } else {
            /* Our own route changed.  A core-field change can affect what
             * other local routers learn; an external_ids/options-only change
             * is our own advertise write-back (ad_route_sync_external_ids),
             * whose triggering NB change already drove a sync - ignore it to
             * avoid a feedback recompute. */
            if (ovsdb_idl_track_is_updated(&isb_route->header_,
                                           &icsbrec_route_col_ip_prefix) ||
                ovsdb_idl_track_is_updated(&isb_route->header_,
                                           &icsbrec_route_col_nexthop) ||
                ovsdb_idl_track_is_updated(&isb_route->header_,
                                           &icsbrec_route_col_origin) ||
                ovsdb_idl_track_is_updated(&isb_route->header_,
                                           &icsbrec_route_col_route_table) ||
                ovsdb_idl_track_is_updated(&isb_route->header_,
                                           &icsbrec_route_col_transit_switch)
                || ovsdb_idl_track_is_updated(
                    &isb_route->header_,
                    &icsbrec_route_col_availability_zone)) {
                sset_add(&affected, isb_route->transit_switch);
            }
        }
    }

    enum engine_input_handler_result ret =
        route_scope_finish(ctx, runned_az, &affected, updated, data);
    sset_destroy(&affected);
    return ret;
}

/* IC-SB Port_Binding: route_run maps a port binding to its NB logical router
 * via external_ids:router-id and reads logical_port/transit_switch/
 * availability_zone/address/type.  A change to any of those (or a new/deleted
 * binding) needs its transit switch re-synced; tunnel_key/gateway/nb_ic_uuid/
 * encap are not read by route_run. */
enum engine_input_handler_result
route_icsb_port_binding_handler(struct engine_node *node,
                                void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = route_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct icsbrec_port_binding_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICSB_port_binding", node));
    struct sset affected = SSET_INITIALIZER(&affected);
    const struct icsbrec_port_binding *isb_pb;
    ICSBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (isb_pb, tbl) {
        if (icsbrec_port_binding_is_new(isb_pb) ||
            icsbrec_port_binding_is_deleted(isb_pb) ||
            ovsdb_idl_track_is_updated(
                &isb_pb->header_, &icsbrec_port_binding_col_logical_port) ||
            ovsdb_idl_track_is_updated(
                &isb_pb->header_, &icsbrec_port_binding_col_transit_switch) ||
            ovsdb_idl_track_is_updated(
                &isb_pb->header_,
                &icsbrec_port_binding_col_availability_zone) ||
            ovsdb_idl_track_is_updated(&isb_pb->header_,
                                       &icsbrec_port_binding_col_address) ||
            ovsdb_idl_track_is_updated(&isb_pb->header_,
                                       &icsbrec_port_binding_col_type) ||
            ovsdb_idl_track_is_updated(
                &isb_pb->header_, &icsbrec_port_binding_col_external_ids)) {
            sset_add(&affected, isb_pb->transit_switch);
        }
    }

    enum engine_input_handler_result ret =
        route_scope_finish(ctx, runned_az, &affected, false, data);
    sset_destroy(&affected);
    return ret;
}

/* IC-NB Transit_Switch: route_run keys advertise/learn off the transit switch
 * name.  A new or deleted transit switch is scoped to its own name; a rename
 * cannot be scoped (the old name is no longer available) and falls back to a
 * full recompute.  Its other_config/external_ids are not read. */
enum engine_input_handler_result
route_icnb_transit_switch_handler(struct engine_node *node,
                                  void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = route_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct icnbrec_transit_switch_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_switch", node));
    struct sset affected = SSET_INITIALIZER(&affected);
    bool unhandled = false;
    const struct icnbrec_transit_switch *ts;
    ICNBREC_TRANSIT_SWITCH_TABLE_FOR_EACH_TRACKED (ts, tbl) {
        if (icnbrec_transit_switch_is_new(ts) ||
            icnbrec_transit_switch_is_deleted(ts)) {
            sset_add(&affected, ts->name);
        } else if (ovsdb_idl_track_is_updated(
                       &ts->header_, &icnbrec_transit_switch_col_name)) {
            unhandled = true;
            break;
        }
    }

    enum engine_input_handler_result ret =
        unhandled ? EN_UNHANDLED
                  : route_scope_finish(ctx, runned_az, &affected, false, data);
    sset_destroy(&affected);
    return ret;
}

/* SB Datapath_Binding: build_ts_routes_to_adv() maps a logical router to its
 * SB datapath (via nb_uuid) to read its SB learned routes.  A datapath created
 * or removed for an interconnected router changes that lookup, so scope to
 * that router's transit switches. */
enum engine_input_handler_result
route_sb_datapath_binding_handler(struct engine_node *node,
                                  void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = route_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct sbrec_datapath_binding_table *tbl =
        EN_OVSDB_GET(engine_get_input("SB_datapath_binding", node));
    struct shash lr_ts_map;
    route_lr_ts_map_init(ctx, runned_az, &lr_ts_map);
    struct sset affected = SSET_INITIALIZER(&affected);

    const struct sbrec_datapath_binding *dp;
    SBREC_DATAPATH_BINDING_TABLE_FOR_EACH_TRACKED (dp, tbl) {
        if (!sbrec_datapath_binding_is_new(dp) &&
            !sbrec_datapath_binding_is_deleted(dp) &&
            !ovsdb_idl_track_is_updated(
                &dp->header_, &sbrec_datapath_binding_col_nb_uuid)) {
            continue;
        }
        if (dp->n_nb_uuid < 1) {
            continue;
        }
        route_scope_add_lr_uuid(&lr_ts_map, &dp->nb_uuid[0], &affected);
    }

    enum engine_input_handler_result ret =
        route_scope_finish(ctx, runned_az, &affected, false, data);
    sset_destroy(&affected);
    route_lr_ts_map_destroy(&lr_ts_map);
    return ret;
}

/* SB Learned_Route: dynamic (e.g. BGP-learned) routes on a router's datapath
 * are advertised by build_ts_routes_to_adv().  Scope a change to the transit
 * switches of the interconnected router owning the route's datapath. */
enum engine_input_handler_result
route_sb_learned_route_handler(struct engine_node *node, void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = route_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct sbrec_learned_route_table *tbl =
        EN_OVSDB_GET(engine_get_input("SB_learned_route", node));
    struct shash lr_ts_map;
    route_lr_ts_map_init(ctx, runned_az, &lr_ts_map);
    struct sset affected = SSET_INITIALIZER(&affected);

    const struct sbrec_learned_route *sb_route;
    SBREC_LEARNED_ROUTE_TABLE_FOR_EACH_TRACKED (sb_route, tbl) {
        const struct sbrec_datapath_binding *dp = sb_route->datapath;
        if (!dp || dp->n_nb_uuid < 1) {
            continue;
        }
        route_scope_add_lr_uuid(&lr_ts_map, &dp->nb_uuid[0], &affected);
    }

    enum engine_input_handler_result ret =
        route_scope_finish(ctx, runned_az, &affected, false, data);
    sset_destroy(&affected);
    route_lr_ts_map_destroy(&lr_ts_map);
    return ret;
}

void *
en_route_init(struct engine_node *node OVS_UNUSED,
              struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_route *data = xzalloc(sizeof *data);
    sset_init(&data->synced_ts);
    smap_init(&data->nb_global_opts);
    return data;
}

void
en_route_clear_tracked_data(void *data_)
{
    struct ed_type_route *data = data_;
    sset_clear(&data->synced_ts);
}

void
en_route_cleanup(void *data_)
{
    struct ed_type_route *data = data_;
    sset_destroy(&data->synced_ts);
    smap_destroy(&data->nb_global_opts);
}
