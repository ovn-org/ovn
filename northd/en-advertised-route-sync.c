/*
 * Copyright (c) 2025, STACKIT GmbH & Co. KG
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

#include "stopwatch.h"
#include "northd.h"

#include "en-advertised-route-sync.h"
#include "en-lr-nat.h"
#include "en-lr-stateful.h"
#include "lb.h"
#include "lib/stopwatch-names.h"
#include "openvswitch/hmap.h"
#include "ovn-util.h"

struct ar_entry {
    struct hmap_node hmap_node;

    const struct ovn_datapath *od;       /* Datapath the route is
                                          * advertised on. */
    const struct ovn_port *op;           /* Port the route is advertised
                                          * on. */
    char *ip_prefix;
    const struct ovn_port *tracked_port; /* If set, the port whose chassis
                                          * advertises this route with a
                                          * higher priority. */
    enum route_source source;
};

/* Add a new entries to the to-be-advertised routes.
 * Takes ownership of ip_prefix. */
static struct ar_entry *
ar_entry_add_nocopy(struct hmap *routes, const struct ovn_datapath *od,
                    const struct ovn_port *op, char *ip_prefix,
                    const struct ovn_port *tracked_port,
                    enum route_source source)
{
    struct ar_entry *route_e = xzalloc(sizeof *route_e);

    route_e->od = od;
    route_e->op = op;
    route_e->ip_prefix = ip_prefix;
    route_e->tracked_port = tracked_port;
    route_e->source = source;
    uint32_t hash = uuid_hash(&od->sdp->sb_dp->header_.uuid);
    hash = hash_string(op->sb->logical_port, hash);
    hash = hash_string(ip_prefix, hash);
    hmap_insert(routes, &route_e->hmap_node, hash);

    return route_e;
}

/* Add a new entries to the to-be-advertised routes.
 * Makes a copy of ip_prefix. */
static struct ar_entry *
ar_entry_add(struct hmap *routes, const struct ovn_datapath *od,
             const struct ovn_port *op, const char *ip_prefix,
             const struct ovn_port *tracked_port,
             enum route_source source)
{
    return ar_entry_add_nocopy(routes, od, op, xstrdup(ip_prefix),
                               tracked_port, source);
}

static struct ar_entry *
ar_entry_find(struct hmap *route_map,
              const struct sbrec_datapath_binding *sb_db,
              const struct sbrec_port_binding *logical_port,
              const char *ip_prefix,
              const struct sbrec_port_binding *tracked_port)
{
    struct ar_entry *route_e;
    uint32_t hash;

    hash = uuid_hash(&sb_db->header_.uuid);
    hash = hash_string(logical_port->logical_port, hash);
    hash = hash_string(ip_prefix, hash);

    HMAP_FOR_EACH_WITH_HASH (route_e, hmap_node, hash, route_map) {
        if (!uuid_equals(&sb_db->header_.uuid,
                         &route_e->od->sdp->sb_dp->header_.uuid)) {
            continue;
        }
        if (!uuid_equals(&logical_port->header_.uuid,
                         &route_e->op->sb->header_.uuid)) {
            continue;
        }
        if (strcmp(ip_prefix, route_e->ip_prefix)) {
            continue;
        }

        if (tracked_port) {
            if (!route_e->tracked_port ||
                    tracked_port != route_e->tracked_port->sb) {
                continue;
            }
        }

        return route_e;
    }

    return NULL;
}

static void
ar_entry_free(struct ar_entry *route_e)
{
    free(route_e->ip_prefix);
    free(route_e);
}

static void
advertised_route_table_sync(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_advertised_route_table *sbrec_advertised_route_table,
    const struct hmap *routes,
    const struct hmap *dynamic_routes,
    struct advertised_route_sync_data *data);

enum engine_input_handler_result
advertised_route_sync_lr_stateful_change_handler(struct engine_node *node,
                                                 void *data_)
{
    /* We only actually use lr_stateful data if we expose individual host
     * routes. In this case we for now just recompute.
     * */
    struct ed_type_lr_stateful *lr_stateful_data =
        engine_get_input_data("lr_stateful", node);
    struct advertised_route_sync_data *data = data_;

    struct hmapx_node *hmapx_node;
    const struct lr_stateful_record *lr_stateful_rec;
    HMAPX_FOR_EACH (hmapx_node, &lr_stateful_data->trk_data.crupdated) {
        lr_stateful_rec = hmapx_node->data;
        if (uuidset_contains(&data->nb_lr,
                             &lr_stateful_rec->nbr_uuid)) {
            return EN_UNHANDLED;
        }
    }

    return EN_HANDLED_UNCHANGED;
}

enum engine_input_handler_result
advertised_route_sync_northd_change_handler(struct engine_node *node,
                                            void *data_)
{
    struct advertised_route_sync_data *data = data_;
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_has_tracked_data(&northd_data->trk_data)) {
        return EN_UNHANDLED;
    }

    /* We indirectly use northd_data->ls_ports if we announce host routes.
     * For now we just recompute on any change to lsps that are relevant to us.
     */
    struct hmapx_node *hmapx_node;
    const struct ovn_port *op;
    HMAPX_FOR_EACH (hmapx_node, &northd_data->trk_data.trk_lsps.created) {
        op = hmapx_node->data;
        if (uuidset_contains(&data->nb_ls,
                             &op->od->nbs->header_.uuid)) {
            return EN_UNHANDLED;
        }
    }
    HMAPX_FOR_EACH (hmapx_node, &northd_data->trk_data.trk_lsps.updated) {
        op = hmapx_node->data;
        if (uuidset_contains(&data->nb_ls,
                             &op->od->nbs->header_.uuid)) {
            return EN_UNHANDLED;
        }
    }
    HMAPX_FOR_EACH (hmapx_node, &northd_data->trk_data.trk_lsps.deleted) {
        op = hmapx_node->data;
        if (uuidset_contains(&data->nb_ls,
                             &op->od->nbs->header_.uuid)) {
            return EN_UNHANDLED;
        }
    }

    return EN_HANDLED_UNCHANGED;
}

static void
routes_sync_init(struct advertised_route_sync_data *data)
{
    uuidset_init(&data->nb_lr);
    uuidset_init(&data->nb_ls);
}

static void
routes_sync_clear(struct advertised_route_sync_data *data)
{
    uuidset_clear(&data->nb_lr);
    uuidset_clear(&data->nb_ls);
}

static void
routes_sync_destroy(struct advertised_route_sync_data *data)
{
    uuidset_destroy(&data->nb_lr);
    uuidset_destroy(&data->nb_ls);
}

void *
en_advertised_route_sync_init(struct engine_node *node OVS_UNUSED,
                              struct engine_arg *arg OVS_UNUSED)
{
    struct advertised_route_sync_data *data = xzalloc(sizeof *data);
    routes_sync_init(data);
    return data;
}

void
en_advertised_route_sync_cleanup(void *data OVS_UNUSED)
{
    routes_sync_destroy(data);
}

enum engine_node_state
en_advertised_route_sync_run(struct engine_node *node, void *data OVS_UNUSED)
{
    routes_sync_clear(data);

    struct advertised_route_sync_data *routes_sync_data = data;
    struct routes_data *routes_data
        = engine_get_input_data("routes", node);
    struct dynamic_routes_data *dynamic_routes_data
        = engine_get_input_data("dynamic_routes", node);
    const struct engine_context *eng_ctx = engine_get_context();
    const struct sbrec_advertised_route_table *sbrec_advertised_route_table =
        EN_OVSDB_GET(engine_get_input("SB_advertised_route", node));

    stopwatch_start(ADVERTISED_ROUTE_SYNC_RUN_STOPWATCH_NAME, time_msec());

    advertised_route_table_sync(eng_ctx->ovnsb_idl_txn,
                                sbrec_advertised_route_table,
                                &routes_data->parsed_routes,
                                &dynamic_routes_data->routes,
                                routes_sync_data);

    stopwatch_stop(ADVERTISED_ROUTE_SYNC_RUN_STOPWATCH_NAME, time_msec());
    return EN_UPDATED;
}

/* This function adds a new route for each entry in lr_nat record
 * to "routes". Logical port of the route is set to "advertising_op" and
 * tracked port is set to NAT's distributed gw port. If NAT doesn't have
 * DGP (for example if it's set on gateway router), no tracked port will
 * be set.*/
static void
build_nat_route_for_port(const struct ovn_port *advertising_op,
                         const struct lr_nat_record *lr_nat,
                         const struct hmap *ls_ports,
                         struct hmap *routes)
{
    const struct ovn_datapath *advertising_od = advertising_op->od;

    for (size_t i = 0; i < lr_nat->n_nat_entries; i++) {
        const struct ovn_nat *nat = &lr_nat->nat_entries[i];
        if (!nat->is_valid) {
            continue;
        }

        const struct ovn_port *tracked_port =
            nat->is_distributed
            ? ovn_port_find(ls_ports, nat->nb->logical_port)
            : nat->l3dgw_port;

        if (!ar_entry_find(routes, advertising_od->sdp->sb_dp,
                           advertising_op->sb,
                           nat->nb->external_ip,
                           tracked_port ? tracked_port->sb : NULL)) {
            ar_entry_add(routes, advertising_od, advertising_op,
                         nat->nb->external_ip, tracked_port,
                         ROUTE_SOURCE_NAT);
        }
    }
}

/* Generate routes for NAT external IPs in lr_nat, for each ovn port
 * in "od" that has enabled redistribution of NAT adresses.*/
static void
build_nat_routes(const struct ovn_datapath *od,
                 const struct lr_nat_record *lr_nat,
                 const struct hmap *ls_ports,
                 struct hmap *routes)
{
    const struct ovn_port *op;
    HMAP_FOR_EACH (op, dp_node, &od->ports) {
        if (!drr_mode_NAT_is_set(op->dynamic_routing_redistribute)) {
            continue;
        }

        build_nat_route_for_port(op, lr_nat, ls_ports, routes);
    }
}

/* Similar to build_nat_routes, this function generates routes for nat records
 * in neighboring routers. For each ovn port in "od" that has enabled
 * redistribution of NAT adresses, look up their neighbors (either directly
 * connected routers, or routers connected through common LS) and advertise
 * thier external NAT IPs too.*/
static void
build_nat_connected_routes(
    const struct ovn_datapath *od,
    const struct lr_stateful_table *lr_stateful_table,
    const struct hmap *ls_ports,
    struct hmap *routes)
{
    const struct ovn_port *op;
    HMAP_FOR_EACH (op, dp_node, &od->ports) {
        if (!drr_mode_NAT_is_set(op->dynamic_routing_redistribute)) {
            continue;
        }

        if (!op->peer) {
            continue;
        }

        struct ovn_datapath *peer_od = op->peer->od;
        ovs_assert(peer_od->nbs || peer_od->nbr);

        /* This is a directly connected LR peer. */
        if (peer_od->nbr) {
            const struct lr_stateful_record *peer_lr_stateful =
                lr_stateful_table_find_by_uuid(lr_stateful_table,
                                                 peer_od->key);
            if (!peer_lr_stateful) {
                continue;
            }

            /* Advertise peer's NAT routes via the local port too. */
            build_nat_route_for_port(op, peer_lr_stateful->lrnat_rec,
                                     ls_ports, routes);
            continue;
        }

        /* This peer is LSP, we need to check all connected router ports
         * for NAT.*/
        const struct ovn_port *rp;
        VECTOR_FOR_EACH (&peer_od->router_ports, rp) {
            if (rp->peer == op) {
                /* Skip advertising router. */
                continue;
            }

            const struct lr_stateful_record *peer_lr_stateful =
                lr_stateful_table_find_by_uuid(lr_stateful_table,
                                                rp->peer->od->key);
            if (!peer_lr_stateful) {
                continue;
            }

            /* Advertise peer's NAT routes via the local port too. */
            build_nat_route_for_port(op, peer_lr_stateful->lrnat_rec,
                                     ls_ports, routes);
        }
    }
}

/* This function adds a new route for each IP in lb_ips to "routes".*/
static void
build_lb_route_for_port(const struct ovn_port *advertising_op,
                        const struct ovn_port *tracked_port,
                        const struct ovn_lb_ip_set *lb_ips,
                        struct hmap *routes)
{
    const struct ovn_datapath *advertising_od = advertising_op->od;

    const char *ip_address;
    SSET_FOR_EACH (ip_address, &lb_ips->ips_v4) {
        ar_entry_add(routes, advertising_od, advertising_op,
                     ip_address, tracked_port, ROUTE_SOURCE_LB);
    }
    SSET_FOR_EACH (ip_address, &lb_ips->ips_v6) {
        ar_entry_add(routes, advertising_od, advertising_op,
                     ip_address, tracked_port, ROUTE_SOURCE_LB);
    }
}

/* Similar to build_lb_routes, this function generates routes for LB VIPs
 * of neighboring routers. For each ovn port in "od" that has enabled
 * redistribution of LB VIPs, look up their neighbors (either directly
 * routers, or routers connected through common LS) and advertise their
 * LB VIPs too.*/
static void
build_lb_connected_routes(const struct ovn_datapath *od,
                          const struct lr_stateful_table *lr_stateful_table,
                          struct hmap *routes)
{
    const struct ovn_port *op;
    HMAP_FOR_EACH (op, dp_node, &od->ports) {
        if (!drr_mode_LB_is_set(op->dynamic_routing_redistribute)) {
            continue;
        }

        if (!op->peer) {
            continue;
        }

        struct ovn_datapath *peer_od = op->peer->od;
        ovs_assert(peer_od->nbs || peer_od->nbr);

        const struct lr_stateful_record *lr_stateful_rec;
        /* This is directly connected LR peer. */
        if (peer_od->nbr) {
            lr_stateful_rec = lr_stateful_table_find_by_uuid(
                lr_stateful_table, peer_od->key);
            build_lb_route_for_port(op, op->peer, lr_stateful_rec->lb_ips,
                                    routes);
            continue;
        }

        /* This peer is LSP, we need to check all connected router ports for
         * LBs.*/
        struct ovn_port *rp;
        VECTOR_FOR_EACH (&peer_od->router_ports, rp) {
            if (rp->peer == op) {
                /* no need to check for LBs on ovn_port that initiated this
                 * function.*/
                continue;
            }
            lr_stateful_rec = lr_stateful_table_find_by_uuid(
                lr_stateful_table, rp->peer->od->key);

            build_lb_route_for_port(op, rp->peer, lr_stateful_rec->lb_ips,
                                    routes);
        }
    }
}

static void
build_lb_routes(const struct ovn_datapath *od,
                const struct ovn_lb_ip_set *lb_ips,
                struct hmap *routes)
{
    const struct ovn_port *op;
    HMAP_FOR_EACH (op, dp_node, &od->ports) {
        if (!drr_mode_LB_is_set(op->dynamic_routing_redistribute)) {
            continue;
        }

        /* Traffic processed by a load balancer is:
         * - handled by the chassis where a gateway router is bound
         * OR
         * - always redirected to a distributed gateway router port
         *
         * Advertise the LB IPs via all 'op' if this is a gateway router or
         * throuh all DGPs of this distributed router otherwise. */

        if (od->is_gw_router) {
            build_lb_route_for_port(op, NULL, lb_ips, routes);
        } else {
            struct ovn_port *dgp;
            VECTOR_FOR_EACH (&od->l3dgw_ports, dgp) {
                build_lb_route_for_port(op, dgp, lb_ips, routes);
            }
        }
    }
}

void *
en_dynamic_routes_init(struct engine_node *node OVS_UNUSED,
                       struct engine_arg *arg OVS_UNUSED)
{
    struct dynamic_routes_data *data = xmalloc(sizeof *data);
    *data = (struct dynamic_routes_data) {
        .routes = HMAP_INITIALIZER(&data->routes),
    };

    return data;
}

static void
en_dynamic_routes_clear(struct dynamic_routes_data *data)
{
    struct ar_entry *ar;
    HMAP_FOR_EACH_POP (ar, hmap_node, &data->routes) {
        ar_entry_free(ar);
    }
}
void
en_dynamic_routes_cleanup(void *data_)
{
    struct dynamic_routes_data *data = data_;

    en_dynamic_routes_clear(data);
    hmap_destroy(&data->routes);
}

enum engine_node_state
en_dynamic_routes_run(struct engine_node *node, void *data)
{
    struct dynamic_routes_data *dynamic_routes_data = data;
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    struct ed_type_lr_stateful *lr_stateful_data =
        engine_get_input_data("lr_stateful", node);

    en_dynamic_routes_clear(data);

    stopwatch_start(DYNAMIC_ROUTES_RUN_STOPWATCH_NAME, time_msec());
    const struct lr_stateful_record *lr_stateful_rec;
    HMAP_FOR_EACH (lr_stateful_rec, key_node,
                   &lr_stateful_data->table.entries) {
        const struct ovn_datapath *od =
            ovn_datapaths_find_by_index(&northd_data->lr_datapaths,
                                        lr_stateful_rec->lr_index);
        if (!od->dynamic_routing) {
            continue;
        }
        build_nat_routes(od, lr_stateful_rec->lrnat_rec,
                         &northd_data->ls_ports,
                         &dynamic_routes_data->routes);
        build_nat_connected_routes(od, &lr_stateful_data->table,
                                   &northd_data->ls_ports,
                                   &dynamic_routes_data->routes);

        build_lb_routes(od, lr_stateful_rec->lb_ips,
                        &dynamic_routes_data->routes);
        build_lb_connected_routes(od, &lr_stateful_data->table,
                                  &dynamic_routes_data->routes);
    }
    stopwatch_stop(DYNAMIC_ROUTES_RUN_STOPWATCH_NAME, time_msec());
    return EN_UPDATED;
}

static void
publish_lport_addresses(struct hmap *sync_routes,
                        const struct ovn_datapath *od,
                        const struct ovn_port *logical_port,
                        const struct lport_addresses *addresses,
                        const struct ovn_port *tracking_port)
{
    for (size_t i = 0; i < addresses->n_ipv4_addrs; i++) {
        const struct ipv4_netaddr *addr = &addresses->ipv4_addrs[i];
        ar_entry_add(sync_routes, od, logical_port, addr->addr_s,
                     tracking_port, ROUTE_SOURCE_CONNECTED);
    }
    for (size_t i = 0; i < addresses->n_ipv6_addrs; i++) {
        if (in6_is_lla(&addresses->ipv6_addrs[i].network)) {
            continue;
        }
        const struct ipv6_netaddr *addr = &addresses->ipv6_addrs[i];
        ar_entry_add(sync_routes, od, logical_port, addr->addr_s,
                     tracking_port, ROUTE_SOURCE_CONNECTED);
    }
}

/* Collect all IP addresses connected to the out_port of a route.
 * This traverses all LSPs on the LS connected to the out_port. */
static void
publish_host_routes(struct hmap *sync_routes,
                    const struct ovn_datapath *advertising_od,
                    const struct ovn_port *advertising_op,
                    struct advertised_route_sync_data *data)
{
    if (!advertising_op->peer) {
        return;
    }

    struct ovn_datapath *peer_od = advertising_op->peer->od;
    if (!peer_od->nbs && !peer_od->nbr) {
        return;
    }

    if (peer_od->nbr) {
        /* This is a LRP directly connected to another LRP. */
        const struct ovn_port *lrp = advertising_op->peer;
        publish_lport_addresses(sync_routes, advertising_od,
                                advertising_op, &lrp->lrp_networks, lrp);
        return;
    }

    /* We need to track the LS we are publishing routes from, so that we can
     * recompute when any port on there changes. */
    uuidset_insert(&data->nb_ls, &peer_od->nbs->header_.uuid);

    struct ovn_port *port;
    HMAP_FOR_EACH (port, dp_node, &peer_od->ports) {
        if (port->peer && port->peer->nbrp) {
            /* This is a LSP connected to an LRP */
            const struct ovn_port *lrp = port->peer;
            publish_lport_addresses(sync_routes, advertising_od,
                                    advertising_op, &lrp->lrp_networks, lrp);
        } else {
            /* This is just a plain LSP */
            for (size_t i = 0; i < port->n_lsp_addrs; i++) {
                publish_lport_addresses(sync_routes, advertising_od,
                                        advertising_op,
                                        &port->lsp_addrs[i],
                                        port);
            }
        }
    }
}

static bool
should_advertise_route(const struct uuidset *host_route_lrps,
                       const struct ovn_datapath *advertising_od,
                       const struct ovn_port *advertising_op,
                       enum route_source source)
{
    if (!advertising_od->dynamic_routing) {
        return false;
    }

    enum dynamic_routing_redistribute_mode drr =
        advertising_op->dynamic_routing_redistribute;

    switch (source) {
    case ROUTE_SOURCE_CONNECTED:
        if (!drr_mode_CONNECTED_is_set(drr)) {
            return false;
        }

        /* If we advertise host routes, we only need to do so once per
         * LRP. */
        const struct uuid *lrp_uuid = &advertising_op->nbrp->header_.uuid;
        if (drr_mode_CONNECTED_AS_HOST_is_set(drr) &&
                uuidset_contains(host_route_lrps, lrp_uuid)) {
            return false;
        }
        return true;
    case ROUTE_SOURCE_STATIC:
        return drr_mode_STATIC_is_set(drr);
    case ROUTE_SOURCE_NAT:
        return drr_mode_NAT_is_set(drr);
    case ROUTE_SOURCE_LB:
        return drr_mode_LB_is_set(drr);
    case ROUTE_SOURCE_LEARNED:
        OVS_NOT_REACHED();
    default:
        OVS_NOT_REACHED();
    }
}

/* Returns true if the connected route was advertised as a set of host routes
 * (/32 for IPv4 and /128 for IPv6), one for each individual IP known to be
 * reachable in the connected route's subnet.  Returns false otherwise. */
static bool
advertise_routes_as_host_prefix(
    struct advertised_route_sync_data *data,
    struct uuidset *host_route_lrps,
    struct hmap *sync_routes,
    const struct ovn_datapath *advertising_od,
    const struct ovn_port *advertising_op,
    enum route_source source
)
{
    if (source != ROUTE_SOURCE_CONNECTED) {
        return false;
    }

    enum dynamic_routing_redistribute_mode drr =
        advertising_op->dynamic_routing_redistribute;
    if (!drr_mode_CONNECTED_AS_HOST_is_set(drr)) {
        return false;
    }

    uuidset_insert(host_route_lrps, &advertising_op->nbrp->header_.uuid);
    publish_host_routes(sync_routes, advertising_od, advertising_op, data);
    return true;
}

/* Track datapaths (routers/switches) whose changes should trigger
 * the set of advertised routes.  That includes NAT and LB related
 * advertised routes. */
static void
advertise_route_track_od(struct advertised_route_sync_data *data,
                         const struct ovn_datapath *advertising_od,
                         const struct ovn_port *tracked_op,
                         enum route_source source)
{
    switch (source) {
    case ROUTE_SOURCE_NAT:
        /* If NAT route tracks port on a different DP than the one that
         * advertises the route, we need to watch for changes on that DP as
         * well. */
        if (tracked_op && tracked_op->od != advertising_od) {
            if (tracked_op->od->nbr) {
                uuidset_insert(&data->nb_lr,
                               &tracked_op->od->nbr->header_.uuid);
            } else if (tracked_op->od->nbs) {
                uuidset_insert(&data->nb_ls,
                               &tracked_op->od->nbs->header_.uuid);
            }
        }
        break;
    case ROUTE_SOURCE_LB:
        /* If LB route tracks port on a different DP than the one that
         * advertises the route, we need to watch for changes on that DP as
         * well. */
        if (tracked_op && tracked_op->od != advertising_od) {
            uuidset_insert(&data->nb_lr,
                           &tracked_op->od->nbr->header_.uuid);
        }
        break;
    case ROUTE_SOURCE_CONNECTED:
    case ROUTE_SOURCE_STATIC:
        break;
    case ROUTE_SOURCE_LEARNED:
        OVS_NOT_REACHED();
    default:
        OVS_NOT_REACHED();
    }
}

static void
advertised_route_table_sync(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_advertised_route_table *sbrec_advertised_route_table,
    const struct hmap *routes,
    const struct hmap *dynamic_routes,
    struct advertised_route_sync_data *data)
{
    struct hmap sync_routes = HMAP_INITIALIZER(&sync_routes);
    struct uuidset host_route_lrps = UUIDSET_INITIALIZER(&host_route_lrps);

    /* First build the set of non-dynamic routes that need sync-ing. */
    const struct parsed_route *route;
    HMAP_FOR_EACH (route, key_node, routes) {
        if (route->is_discard_route) {
            continue;
        }

        if (!should_advertise_route(&host_route_lrps, route->od,
                                    route->out_port, route->source)) {
            continue;
        }

        if (advertise_routes_as_host_prefix(data, &host_route_lrps,
                                            &sync_routes, route->od,
                                            route->out_port,
                                            route->source)) {
            continue;
        }

        if (prefix_is_link_local(&route->prefix, route->plen)) {
            continue;
        }

        advertise_route_track_od(data, route->od, route->tracked_port,
                                 route->source);

        const struct sbrec_port_binding *tracked_port =
            route->tracked_port ? route->tracked_port->sb : NULL;
        char *ip_prefix = normalize_v46_prefix(&route->prefix, route->plen);
        if (ar_entry_find(&sync_routes, route->od->sdp->sb_dp,
                          route->out_port->sb, ip_prefix,
                          tracked_port)) {
            free(ip_prefix);
            continue;
        }
        ar_entry_add_nocopy(&sync_routes, route->od, route->out_port,
                            ip_prefix,
                            route->tracked_port,
                            route->source);
    }

    /* Then add the set of dynamic routes that need sync-ing. */
    struct ar_entry *route_e;
    HMAP_FOR_EACH (route_e, hmap_node, dynamic_routes) {
        if (!should_advertise_route(&host_route_lrps, route_e->od, route_e->op,
                                    route_e->source)) {
            continue;
        }

        advertise_route_track_od(data, route_e->od, route_e->tracked_port,
                                 route_e->source);

        const struct sbrec_port_binding *tracked_pb =
            route_e->tracked_port ? route_e->tracked_port->sb : NULL;
        if (ar_entry_find(&sync_routes, route_e->od->sdp->sb_dp,
                          route_e->op->sb,
                          route_e->ip_prefix, tracked_pb)) {
            /* We could already have advertised route entry for LRP IP that
             * corresponds to "snat" when "connected-as-host" is combined
             * with "nat". Skip it. */
            continue;
        }
        ar_entry_add(&sync_routes, route_e->od, route_e->op,
                     route_e->ip_prefix, route_e->tracked_port,
                     route_e->source);
    }
    uuidset_destroy(&host_route_lrps);

    const struct sbrec_advertised_route *sb_route;
    SBREC_ADVERTISED_ROUTE_TABLE_FOR_EACH_SAFE (sb_route,
                                                sbrec_advertised_route_table) {
        route_e = ar_entry_find(&sync_routes, sb_route->datapath,
                                sb_route->logical_port, sb_route->ip_prefix,
                                sb_route->tracked_port);
        if (!route_e) {
            sbrec_advertised_route_delete(sb_route);
            continue;
        }

        if (route_e->tracked_port && !sb_route->tracked_port) {
            sbrec_advertised_route_set_tracked_port(
                sb_route, route_e->tracked_port->sb);
        }
        hmap_remove(&sync_routes, &route_e->hmap_node);
        ar_entry_free(route_e);
    }

    HMAP_FOR_EACH_POP (route_e, hmap_node, &sync_routes) {
        const struct sbrec_advertised_route *sr =
            sbrec_advertised_route_insert(ovnsb_txn);
        sbrec_advertised_route_set_datapath(sr, route_e->od->sdp->sb_dp);
        sbrec_advertised_route_set_logical_port(sr, route_e->op->sb);
        sbrec_advertised_route_set_ip_prefix(sr, route_e->ip_prefix);
        if (route_e->tracked_port) {
            sbrec_advertised_route_set_tracked_port(sr,
                                                    route_e->tracked_port->sb);
        }
        ar_entry_free(route_e);
    }

    hmap_destroy(&sync_routes);
}

struct advertised_mac_binding {
    struct hmap_node hmap_node;

    const struct sbrec_datapath_binding *dp;
    const struct sbrec_port_binding *sb;

    char *ip;
    char *mac;
};

static bool
evpn_ip_redistribution_enabled(const struct ovn_datapath *od)
{
    if (!od->has_evpn_vni) {
        return false;
    }

    const char *redistribute = smap_get(&od->nbs->other_config,
                                        "dynamic-routing-redistribute");
    return redistribute && !strcmp(redistribute, "ip");
}

static uint32_t
advertised_mac_binding_get_hash(const struct sbrec_datapath_binding *dp,
                                const struct sbrec_port_binding *sb,
                                const char *ip, const char *mac)
{
    uint32_t hash = uuid_hash(&dp->header_.uuid);
    hash = hash_string(sb->logical_port, hash);
    hash = hash_string(ip, hash);
    hash = hash_string(mac, hash);

    return hash;
}

static struct advertised_mac_binding *
advertised_mac_binding_entry_find(struct hmap *map,
                                  const struct sbrec_datapath_binding *dp,
                                  const struct sbrec_port_binding *sb,
                                  const char *ip, const char *mac)
{
    uint32_t hash = advertised_mac_binding_get_hash(dp, sb, ip, mac);
    struct advertised_mac_binding *e;
    HMAP_FOR_EACH_WITH_HASH (e, hmap_node, hash, map) {
        if (uuid_equals(&sb->header_.uuid, &e->sb->header_.uuid) &&
            uuid_equals(&dp->header_.uuid, &e->dp->header_.uuid) &&
            !strcmp(e->ip, ip) && !strcmp(e->mac, mac)) {
            return e;
        }
    }

    return NULL;
}

static void
advertised_mac_binding_entry_add(struct hmap *map,
                                 const struct sbrec_datapath_binding *dp,
                                 const struct sbrec_port_binding *sb,
                                 const char *ip, const char *mac)
{
    struct advertised_mac_binding *e = xmalloc(sizeof *e);
    e->ip = xstrdup(ip);
    e->mac = xstrdup(mac);
    e->sb = sb;
    e->dp = dp;

    uint32_t hash = advertised_mac_binding_get_hash(dp, sb, ip, mac);
    hmap_insert(map, &e->hmap_node, hash);
}

static void
advertised_mac_binding_entry_destroy(struct advertised_mac_binding *e)
{
    free(e->ip);
    free(e->mac);
    free(e);
}

static void
advertised_mac_binding_add(struct hmap *map,
                           const struct sbrec_datapath_binding *dp,
                           const struct sbrec_port_binding *sb,
                           struct lport_addresses *addr)
{
    if (!addr) {
        return;
    }

    for (size_t i = 0; i < addr->n_ipv4_addrs; i++) {
        if (!advertised_mac_binding_entry_find(map, dp, sb,
                                               addr->ipv4_addrs[i].addr_s,
                                               addr->ea_s)) {
            advertised_mac_binding_entry_add(map, dp, sb,
                                             addr->ipv4_addrs[i].addr_s,
                                             addr->ea_s);
        }
    }

    for (size_t i = 0; i < addr->n_ipv6_addrs; i++) {
        if (prefix_is_link_local(&addr->ipv6_addrs[i].addr, 128)) {
            continue;
        }

        if (!advertised_mac_binding_entry_find(map, dp, sb,
                                               addr->ipv6_addrs[i].addr_s,
                                               addr->ea_s)) {
            advertised_mac_binding_entry_add(map, dp, sb,
                                             addr->ipv6_addrs[i].addr_s,
                                             addr->ea_s);
        }
    }
}

static void
build_advertised_mac_binding(const struct ovn_datapath *od, struct hmap *map)
{
    ovs_assert(od->nbs);

    if (!evpn_ip_redistribution_enabled(od)) {
        return;
    }

    struct ovn_port *op;
    HMAP_FOR_EACH (op, dp_node, &od->ports) {
        if (!op->sb) {
            continue;
        }

        if (lsp_is_router(op->nbsp) && op->peer) {
            advertised_mac_binding_add(map, od->sdp->sb_dp, op->sb,
                                       &op->peer->lrp_networks);
        }

        if (!strcmp(op->nbsp->type, "")) { /* LSP */
            advertised_mac_binding_add(map, od->sdp->sb_dp, op->sb,
                                       op->lsp_addrs);
        }
    }
}

void *
en_advertised_mac_binding_sync_init(struct engine_node *node OVS_UNUSED,
                                    struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

enum engine_node_state
en_advertised_mac_binding_sync_run(struct engine_node *node,
                                   void *data OVS_UNUSED)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    const struct sbrec_advertised_mac_binding_table *sbrec_adv_mb_table =
        EN_OVSDB_GET(engine_get_input("SB_advertised_mac_binding", node));
    const struct engine_context *eng_ctx = engine_get_context();

    struct hmap advertised_mac_binding_map =
        HMAP_INITIALIZER(&advertised_mac_binding_map);

    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &northd_data->ls_datapaths.datapaths) {
        build_advertised_mac_binding(od, &advertised_mac_binding_map);
    }

    struct advertised_mac_binding *e;
    const struct sbrec_advertised_mac_binding *sb_adv_mb;
    SBREC_ADVERTISED_MAC_BINDING_TABLE_FOR_EACH_SAFE (sb_adv_mb,
                                          sbrec_adv_mb_table) {
        e = advertised_mac_binding_entry_find(&advertised_mac_binding_map,
                                              sb_adv_mb->datapath,
                                              sb_adv_mb->logical_port,
                                              sb_adv_mb->ip, sb_adv_mb->mac);
        if (!e) {
            sbrec_advertised_mac_binding_delete(sb_adv_mb);
        } else {
            hmap_remove(&advertised_mac_binding_map, &e->hmap_node);
            advertised_mac_binding_entry_destroy(e);
        }
    }

    HMAP_FOR_EACH_POP (e, hmap_node, &advertised_mac_binding_map) {
        sb_adv_mb =
            sbrec_advertised_mac_binding_insert(eng_ctx->ovnsb_idl_txn);
        sbrec_advertised_mac_binding_set_datapath(sb_adv_mb, e->sb->datapath);
        sbrec_advertised_mac_binding_set_logical_port(sb_adv_mb, e->sb);
        sbrec_advertised_mac_binding_set_ip(sb_adv_mb, e->ip);
        sbrec_advertised_mac_binding_set_mac(sb_adv_mb, e->mac);
        advertised_mac_binding_entry_destroy(e);
    }

    hmap_destroy(&advertised_mac_binding_map);

    return EN_UPDATED;
}

void
en_advertised_mac_binding_sync_cleanup(void *data OVS_UNUSED)
{
}

enum engine_input_handler_result
northd_output_advertised_mac_binding_sync_handler(
    struct engine_node *node OVS_UNUSED, void *data OVS_UNUSED)
{
    return EN_HANDLED_UPDATED;
}
