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

static void
advertised_route_table_sync(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_advertised_route_table *sbrec_advertised_route_table,
    const struct lr_stateful_table *lr_stateful_table,
    const struct hmap *routes,
    const struct hmap *dynamic_routes,
    struct advertised_route_sync_data *data);

bool
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
            return false;
        }
    }

    return true;
}

bool
advertised_route_sync_northd_change_handler(struct engine_node *node,
                                            void *data_)
{
    struct advertised_route_sync_data *data = data_;
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_has_tracked_data(&northd_data->trk_data)) {
        return false;
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
            return false;
        }
    }
    HMAPX_FOR_EACH (hmapx_node, &northd_data->trk_data.trk_lsps.updated) {
        op = hmapx_node->data;
        if (uuidset_contains(&data->nb_ls,
                             &op->od->nbs->header_.uuid)) {
            return false;
        }
    }
    HMAPX_FOR_EACH (hmapx_node, &northd_data->trk_data.trk_lsps.deleted) {
        op = hmapx_node->data;
        if (uuidset_contains(&data->nb_ls,
                             &op->od->nbs->header_.uuid)) {
            return false;
        }
    }

    return true;
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

void
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
    struct ed_type_lr_stateful *lr_stateful_data =
        engine_get_input_data("lr_stateful", node);

    stopwatch_start(ADVERTISED_ROUTE_SYNC_RUN_STOPWATCH_NAME, time_msec());

    advertised_route_table_sync(eng_ctx->ovnsb_idl_txn,
                                sbrec_advertised_route_table,
                                &lr_stateful_data->table,
                                &routes_data->parsed_routes,
                                &dynamic_routes_data->parsed_routes,
                                routes_sync_data);

    stopwatch_stop(ADVERTISED_ROUTE_SYNC_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}

/* This function adds new parsed route for each entry in lr_nat record
 * to "routes". Logical port of the route is set to "advertising_op" and
 * tracked port is set to NAT's distributed gw port. If NAT doesn't have
 * DGP (for example if it's set on gateway router), no tracked port will
 * be set.*/
static void
build_nat_parsed_route_for_port(const struct ovn_port *advertising_op,
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

        int plen = nat_entry_is_v6(nat) ? 128 : 32;
        struct in6_addr prefix;
        ip46_parse(nat->nb->external_ip, &prefix);

        const struct ovn_port *tracked_port =
            nat->is_distributed
            ? ovn_port_find(ls_ports, nat->nb->logical_port)
            : nat->l3dgw_port;
        parsed_route_add(advertising_od, NULL, &prefix, plen, false,
                         nat->nb->external_ip, advertising_op, 0, false,
                         false, NULL, ROUTE_SOURCE_NAT, &nat->nb->header_,
                         tracked_port, routes);
    }
}

/* Generate parsed routes for NAT external IPs in lr_nat, for each ovn port
 * in "od" that has enabled redistribution of NAT adresses.*/
static void
build_nat_parsed_routes(const struct ovn_datapath *od,
                        const struct lr_nat_record *lr_nat,
                        const struct hmap *ls_ports,
                        struct hmap *routes)
{
    const struct ovn_port *op;
    HMAP_FOR_EACH (op, dp_node, &od->ports) {
        if (!drr_mode_NAT_is_set(op->dynamic_routing_redistribute)) {
            continue;
        }

        build_nat_parsed_route_for_port(op, lr_nat, ls_ports, routes);
    }
}

/* Similar to build_nat_parsed_routes, this function generates parsed routes
 * for nat records in neighboring routers. For each ovn port in "od" that has
 * enabled redistribution of NAT adresses, look up their neighbors (either
 * directly routers, or routers connected through common LS) and advertise
 * thier external NAT IPs too.*/
static void
build_nat_connected_parsed_routes(
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

        const struct ovn_port *peer_port = NULL;
        /* This is a directly connected LR peer. */
        if (peer_od->nbr) {
            peer_port = op->peer;

            const struct lr_stateful_record *peer_lr_stateful =
                lr_stateful_table_find_by_index(lr_stateful_table,
                                                 peer_od->index);
            if (!peer_lr_stateful) {
                continue;
            }

            /* Advertise peer's NAT routes via the local port too. */
            build_nat_parsed_route_for_port(op, peer_lr_stateful->lrnat_rec,
                                            ls_ports, routes);
            return;
        }

        /* This peer is LSP, we need to check all connected router ports
         * for NAT.*/
        for (size_t i = 0; i < peer_od->n_router_ports; i++) {
            peer_port = peer_od->router_ports[i]->peer;
            if (peer_port == op) {
                /* Skip advertising router. */
                continue;
            }

            const struct lr_stateful_record *peer_lr_stateful =
                lr_stateful_table_find_by_index(lr_stateful_table,
                                                peer_port->od->index);
            if (!peer_lr_stateful) {
                continue;
            }

            /* Advertise peer's NAT routes via the local port too. */
            build_nat_parsed_route_for_port(op, peer_lr_stateful->lrnat_rec,
                                            ls_ports, routes);
        }
    }
}

/* This function adds new parsed route for each IP in lb_ips to "routes".*/
static void
build_lb_parsed_route_for_port(const struct ovn_port *advertising_op,
                               const struct ovn_port *tracked_port,
                               const struct ovn_lb_ip_set *lb_ips,
                               struct hmap *routes)
{
    const struct ovn_datapath *advertising_od = advertising_op->od;

    const char *ip_address;
    SSET_FOR_EACH (ip_address, &lb_ips->ips_v4) {
        struct in6_addr prefix;
        ip46_parse(ip_address, &prefix);
        parsed_route_add(advertising_od, NULL, &prefix, 32, false,
                         ip_address, advertising_op, 0, false, false,
                         NULL, ROUTE_SOURCE_LB, &advertising_op->nbrp->header_,
                         tracked_port, routes);
    }
    SSET_FOR_EACH (ip_address, &lb_ips->ips_v6) {
        struct in6_addr prefix;
        ip46_parse(ip_address, &prefix);
        parsed_route_add(advertising_od, NULL, &prefix, 128, false,
                         ip_address, advertising_op, 0, false, false,
                         NULL, ROUTE_SOURCE_LB, &advertising_op->nbrp->header_,
                         tracked_port, routes);
    }
}

/* Similar to build_lb_parsed_routes, this function generates parsed routes
 * for LB VIPs of neighboring routers. For each ovn port in "od" that has
 * enabled redistribution of LB VIPs, look up their neighbors (either
 * directly routers, or routers connected through common LS) and advertise
 * thier LB VIPs too.*/
static void
build_lb_connected_parsed_routes(
        const struct ovn_datapath *od,
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
        const struct ovn_port *peer_port = NULL;
        /* This is directly connected LR peer. */
        if (peer_od->nbr) {
            lr_stateful_rec = lr_stateful_table_find_by_index(
                lr_stateful_table, peer_od->index);
            peer_port = op->peer;
            build_lb_parsed_route_for_port(op, peer_port,
                                           lr_stateful_rec->lb_ips, routes);
            return;
        }

        /* This peer is LSP, we need to check all connected router ports for
         * LBs.*/
        for (size_t i = 0; i < peer_od->n_router_ports; i++) {
            peer_port = peer_od->router_ports[i]->peer;
            if (peer_port == op) {
                /* no need to check for LBs on ovn_port that initiated this
                 * function.*/
                continue;
            }
            lr_stateful_rec = lr_stateful_table_find_by_index(
                lr_stateful_table, peer_port->od->index);

            build_lb_parsed_route_for_port(op, peer_port,
                                           lr_stateful_rec->lb_ips, routes);
        }
    }
}

static void
build_lb_parsed_routes(const struct ovn_datapath *od,
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
        struct ovn_port *op_ = NULL;
        size_t n_tracked_ports = !od->is_gw_router ? od->n_l3dgw_ports : 1;
        struct ovn_port **tracked_ports = !od->is_gw_router
                                          ? od->l3dgw_ports
                                          : &op_;

        for (size_t i = 0; i < n_tracked_ports; i++) {
            build_lb_parsed_route_for_port(op, tracked_ports[i], lb_ips,
                                           routes);
        }
    }
}

void *
en_dynamic_routes_init(struct engine_node *node OVS_UNUSED,
                       struct engine_arg *arg OVS_UNUSED)
{
    struct dynamic_routes_data *data = xmalloc(sizeof *data);
    *data = (struct dynamic_routes_data) {
        .parsed_routes = HMAP_INITIALIZER(&data->parsed_routes),
    };

    return data;
}

static void
en_dynamic_routes_clear(struct dynamic_routes_data *data)
{
    struct parsed_route *r;
    HMAP_FOR_EACH_POP (r, key_node, &data->parsed_routes) {
        parsed_route_free(r);
    }
}
void
en_dynamic_routes_cleanup(void *data_)
{
    struct dynamic_routes_data *data = data_;

    en_dynamic_routes_clear(data);
    hmap_destroy(&data->parsed_routes);
}

void
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
        build_nat_parsed_routes(od, lr_stateful_rec->lrnat_rec,
                                &northd_data->ls_ports,
                                &dynamic_routes_data->parsed_routes);
        build_nat_connected_parsed_routes(od, &lr_stateful_data->table,
                                          &northd_data->ls_ports,
                                          &dynamic_routes_data->parsed_routes);

        build_lb_parsed_routes(od, lr_stateful_rec->lb_ips,
                               &dynamic_routes_data->parsed_routes);
        build_lb_connected_parsed_routes(od, &lr_stateful_data->table,
                                         &dynamic_routes_data->parsed_routes);
    }
    stopwatch_stop(DYNAMIC_ROUTES_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}

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
};

/* Add a new entries to the to-be-advertised routes.
 * Takes ownership of ip_prefix. */
static struct ar_entry *
ar_entry_add(struct hmap *routes, const struct ovn_datapath *od,
             const struct ovn_port *op, char *ip_prefix,
             const struct ovn_port *tracked_port)
{
    struct ar_entry *route_e = xzalloc(sizeof *route_e);

    route_e->od = od;
    route_e->op = op;
    route_e->ip_prefix = ip_prefix;
    route_e->tracked_port = tracked_port;
    uint32_t hash = uuid_hash(&od->sb->header_.uuid);
    hash = hash_string(op->sb->logical_port, hash);
    hash = hash_string(ip_prefix, hash);
    hmap_insert(routes, &route_e->hmap_node, hash);

    return route_e;
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
                         &route_e->od->sb->header_.uuid)) {
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
publish_lport_addresses(struct hmap *sync_routes,
                        const struct ovn_datapath *od,
                        const struct ovn_port *logical_port,
                        const struct lport_addresses *addresses,
                        const struct ovn_port *tracking_port)
{
    for (size_t i = 0; i < addresses->n_ipv4_addrs; i++) {
        const struct ipv4_netaddr *addr = &addresses->ipv4_addrs[i];
        ar_entry_add(sync_routes, od, logical_port, xstrdup(addr->addr_s),
                     tracking_port);
    }
    for (size_t i = 0; i < addresses->n_ipv6_addrs; i++) {
        if (in6_is_lla(&addresses->ipv6_addrs[i].network)) {
            continue;
        }
        const struct ipv6_netaddr *addr = &addresses->ipv6_addrs[i];
        ar_entry_add(sync_routes, od, logical_port, xstrdup(addr->addr_s),
                      tracking_port);
    }
}

/* Collect all IP addresses connected via this LRP. */
static void
publish_host_routes_lrp(struct hmap *sync_routes,
                        const struct lr_stateful_table *lr_stateful_table,
                        const struct ovn_datapath *advertising_od,
                        const struct ovn_port *advertising_op,
                        struct advertised_route_sync_data *data,
                        const struct ovn_port *lrp)
{
    /* This is a LSP connected to an LRP */
    const struct lport_addresses *addresses = &lrp->lrp_networks;
    publish_lport_addresses(sync_routes, advertising_od,
                            advertising_op, addresses, lrp);

    const struct lr_stateful_record *lr_stateful_rec;
    lr_stateful_rec =
        lr_stateful_table_find_by_index(lr_stateful_table, lrp->od->index);
    /* We also need to track this LR as we need to recompute when
     * any of its IPs change. */
    uuidset_insert(&data->nb_lr, &lr_stateful_rec->nbr_uuid);
    struct ovn_port_routable_addresses addrs =
        get_op_addresses(lrp, lr_stateful_rec, false);
    for (size_t i = 0; i < addrs.n_addrs; i++) {
        publish_lport_addresses(sync_routes, advertising_od,
                                advertising_op, &addrs.laddrs[i], lrp);
    }
    destroy_routable_addresses(&addrs);
}

/* Collect all IP addresses connected to the out_port of a route.
 * This traverses all LSPs on the LS connected to the out_port. */
static void
publish_host_routes(struct hmap *sync_routes,
                    const struct lr_stateful_table *lr_stateful_table,
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
        publish_host_routes_lrp(sync_routes, lr_stateful_table, advertising_od,
                                advertising_op, data, advertising_op->peer);
        return;
    }

    /* We need to track the LS we are publishing routes from, so that we can
     * recompute when any port on there changes. */
    uuidset_insert(&data->nb_ls, &peer_od->nbs->header_.uuid);

    struct ovn_port *port;
    HMAP_FOR_EACH (port, dp_node, &peer_od->ports) {
        if (port->peer && port->peer->nbrp) {
            /* This is a LSP connected to an LRP */
            publish_host_routes_lrp(sync_routes, lr_stateful_table,
                                    advertising_od, advertising_op,
                                    data, port->peer);
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

static void
advertised_route_table_sync_route_add(
    const struct lr_stateful_table *lr_stateful_table,
    struct advertised_route_sync_data *data,
    struct uuidset *host_route_lrps,
    struct hmap *sync_routes,
    const struct parsed_route *route)
{
    if (route->is_discard_route) {
        return;
    }
    if (prefix_is_link_local(&route->prefix, route->plen)) {
        return;
    }
    if (!route->od->dynamic_routing) {
        return;
    }

    enum dynamic_routing_redistribute_mode drr =
        route->out_port->dynamic_routing_redistribute;
    if (route->source == ROUTE_SOURCE_CONNECTED) {
        if (!drr_mode_CONNECTED_is_set(drr)) {
            return;
        }
        /* If we advertise host routes, we only need to do so once per
         * LRP. */
        const struct uuid *lrp_uuid = &route->out_port->nbrp->header_.uuid;
        if (drr_mode_CONNECTED_AS_HOST_is_set(drr) &&
            !uuidset_contains(host_route_lrps, lrp_uuid)) {
            uuidset_insert(host_route_lrps, lrp_uuid);
            publish_host_routes(sync_routes, lr_stateful_table,
                                route->od, route->out_port,
                                data);
            return;
        }
    }
    if (route->source == ROUTE_SOURCE_STATIC && !drr_mode_STATIC_is_set(drr)) {
        return;
    }
    if (route->source == ROUTE_SOURCE_NAT) {
        if (!drr_mode_NAT_is_set(drr)) {
            return;
        }
        /* If NAT route tracks port on a different DP than the one that
         * advertises the route, we need to watch for changes on that DP as
         * well. */
        if (route->tracked_port && route->tracked_port->od != route->od) {
            if (route->tracked_port->od->nbr) {
                uuidset_insert(&data->nb_lr,
                               &route->tracked_port->od->nbr->header_.uuid);
            } else if (route->tracked_port->od->nbs) {
                uuidset_insert(&data->nb_ls,
                               &route->tracked_port->od->nbs->header_.uuid);
            }
        }
    }
    if (route->source == ROUTE_SOURCE_LB) {
        if (!drr_mode_LB_is_set(drr)) {
            return;
        }
        /* If LB route tracks port on a different DP than the one that
         * advertises the route, we need to watch for changes on that DP as
         * well. */
        if (route->tracked_port && route->tracked_port->od != route->od) {
            uuidset_insert(&data->nb_lr,
                           &route->tracked_port->od->nbr->header_.uuid);
        }
    }

    char *ip_prefix = normalize_v46_prefix(&route->prefix, route->plen);
    ar_entry_add(sync_routes, route->od, route->out_port, ip_prefix,
                 route->tracked_port);
}

static void
advertised_route_table_sync(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_advertised_route_table *sbrec_advertised_route_table,
    const struct lr_stateful_table *lr_stateful_table,
    const struct hmap *routes,
    const struct hmap *dynamic_routes,
    struct advertised_route_sync_data *data)
{
    struct hmap sync_routes = HMAP_INITIALIZER(&sync_routes);
    struct uuidset host_route_lrps = UUIDSET_INITIALIZER(&host_route_lrps);
    const struct parsed_route *route;

    struct ar_entry *route_e;

    /* First build the set of non-dynamic routes that need sync-ing. */
    HMAP_FOR_EACH (route, key_node, routes) {
        advertised_route_table_sync_route_add(lr_stateful_table,
                                              data, &host_route_lrps,
                                              &sync_routes,
                                              route);
    }
    /* Then add the set of dynamic routes that need sync-ing. */
    HMAP_FOR_EACH (route, key_node, dynamic_routes) {
        advertised_route_table_sync_route_add(lr_stateful_table,
                                              data, &host_route_lrps,
                                              &sync_routes,
                                              route);
    }
    uuidset_destroy(&host_route_lrps);

    const struct sbrec_advertised_route *sb_route;
    SBREC_ADVERTISED_ROUTE_TABLE_FOR_EACH_SAFE (sb_route,
                                                sbrec_advertised_route_table) {
        route_e = ar_entry_find(&sync_routes, sb_route->datapath,
                                sb_route->logical_port, sb_route->ip_prefix,
                                sb_route->tracked_port);
        if (route_e) {
          hmap_remove(&sync_routes, &route_e->hmap_node);
          ar_entry_free(route_e);
        } else {
          sbrec_advertised_route_delete(sb_route);
        }
    }

    HMAP_FOR_EACH_POP (route_e, hmap_node, &sync_routes) {
        const struct sbrec_advertised_route *sr =
            sbrec_advertised_route_insert(ovnsb_txn);
        sbrec_advertised_route_set_datapath(sr, route_e->od->sb);
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

