/*
 * Copyright (c) 2025 Canonical, Ltd.
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

#include <errno.h>
#include <net/if.h>
#include <stdbool.h>

#include "hmapx.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "openvswitch/list.h"

#include "lib/ovn-sb-idl.h"

#include "binding.h"
#include "ha-chassis.h"
#include "local_data.h"
#include "nexthop-exchange.h"
#include "route.h"
#include "route-exchange.h"
#include "route-exchange-netlink.h"

VLOG_DEFINE_THIS_MODULE(route_exchange);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

struct maintained_route_table_entry {
    struct hmap_node node;
    uint32_t table_id;
};

/* What route_exchange knows about one kernel routing table it syncs. */
struct route_table_state {
    struct hmap_node node;
    uint32_t table_id;
    /* Routes of the table OVN learns from (struct re_nl_cached_route). */
    struct hmap learned_routes;
};

struct route_exchange_state {
    /* Contains 'struct route_table_state', by table id. */
    struct hmap tables;
};

static struct hmap _maintained_route_tables =
    HMAP_INITIALIZER(&_maintained_route_tables);
static struct sset _maintained_vrfs = SSET_INITIALIZER(&_maintained_vrfs);

struct route_entry {
    struct hmap_node hmap_node;

    const struct sbrec_learned_route *sb_route;
    bool stale;
};

static uint32_t
maintained_route_table_hash(uint32_t table_id)
{
    return hash_int(table_id, 0);
}

static bool
maintained_route_table_contains(uint32_t table_id)
{
    uint32_t hash = maintained_route_table_hash(table_id);
    struct maintained_route_table_entry *mrt;
    HMAP_FOR_EACH_WITH_HASH (mrt, node, hash,
                             &_maintained_route_tables) {
        if (mrt->table_id == table_id) {
            return true;
        }
    }
    return false;
}

static void
maintained_route_table_add(uint32_t table_id)
{
    if (maintained_route_table_contains(table_id)) {
        return;
    }
    uint32_t hash = maintained_route_table_hash(table_id);
    struct maintained_route_table_entry *mrt = xmalloc(sizeof *mrt);
    mrt->table_id = table_id;
    hmap_insert(&_maintained_route_tables, &mrt->node, hash);
}

static struct route_table_state *
route_table_state_find(const struct route_exchange_state *state,
                       uint32_t table_id)
{
    struct route_table_state *rt;
    HMAP_FOR_EACH_WITH_HASH (rt, node, maintained_route_table_hash(table_id),
                             &state->tables) {
        if (rt->table_id == table_id) {
            return rt;
        }
    }

    return NULL;
}

static struct route_table_state *
route_table_state_get(struct route_exchange_state *state, uint32_t table_id)
{
    struct route_table_state *rt = route_table_state_find(state, table_id);
    if (rt) {
        return rt;
    }

    rt = xmalloc(sizeof *rt);
    rt->table_id = table_id;
    hmap_init(&rt->learned_routes);
    hmap_insert(&state->tables, &rt->node,
                maintained_route_table_hash(table_id));

    return rt;
}

static void
route_table_state_destroy(struct route_exchange_state *state,
                          struct route_table_state *rt)
{
    hmap_remove(&state->tables, &rt->node);
    re_nl_cached_routes_clear(&rt->learned_routes);
    hmap_destroy(&rt->learned_routes);
    free(rt);
}

struct route_exchange_state *
route_exchange_state_create(void)
{
    struct route_exchange_state *state = xmalloc(sizeof *state);

    hmap_init(&state->tables);
    return state;
}

void
route_exchange_state_destroy(struct route_exchange_state *state)
{
    struct route_table_state *rt;
    HMAP_FOR_EACH_SAFE (rt, node, &state->tables) {
        route_table_state_destroy(state, rt);
    }

    hmap_destroy(&state->tables);
    free(state);
}

static struct route_entry *
route_add_entry(struct hmap *routes,
                const struct sbrec_learned_route *sb_route,
                bool stale)
{
    struct route_entry *route_e = xmalloc(sizeof *route_e);
    *route_e = (struct route_entry) {
        .sb_route = sb_route,
        .stale = stale,
    };

    uint32_t hash = uuid_hash(&sb_route->datapath->header_.uuid);
    hash = hash_string(sb_route->logical_port->logical_port, hash);
    hash = hash_string(sb_route->ip_prefix, hash);

    hmap_insert(routes, &route_e->hmap_node, hash);
    return route_e;
}

static struct route_entry *
route_lookup(struct hmap *route_map,
             const struct sbrec_datapath_binding *sb_db,
             const struct sbrec_port_binding *logical_port,
             const char *ip_prefix, const char *nexthop)
{
    struct route_entry *route_e;
    uint32_t hash;

    hash = uuid_hash(&sb_db->header_.uuid);
    hash = hash_string(logical_port->logical_port, hash);
    hash = hash_string(ip_prefix, hash);

    HMAP_FOR_EACH_WITH_HASH (route_e, hmap_node, hash, route_map) {
        if (route_e->sb_route->datapath != sb_db) {
            continue;
        }
        if (route_e->sb_route->logical_port != logical_port) {
            continue;
        }
        if (strcmp(route_e->sb_route->ip_prefix, ip_prefix)) {
            continue;
        }
        if (strcmp(route_e->sb_route->nexthop, nexthop)) {
            continue;
        }

        return route_e;
    }

    return NULL;
}

static void
sb_sync_learned_routes(const struct vector *learned_routes,
                       const struct sbrec_datapath_binding *datapath,
                       const struct smap *bound_ports,
                       struct ovsdb_idl_txn *ovnsb_idl_txn,
                       struct ovsdb_idl_index *sbrec_port_binding_by_name,
                       struct ovsdb_idl_index *sbrec_learned_route_by_datapath,
                       bool *sb_changes_pending,
                       const struct sbrec_chassis *chassis)
{
    struct hmap sync_routes = HMAP_INITIALIZER(&sync_routes);
    const struct sbrec_learned_route *sb_route;
    struct hmapx lrp_with_dr_port_name =
        HMAPX_INITIALIZER(&lrp_with_dr_port_name);

    struct sbrec_learned_route *filter =
        sbrec_learned_route_index_init_row(sbrec_learned_route_by_datapath);
    sbrec_learned_route_index_set_datapath(filter, datapath);
    SBREC_LEARNED_ROUTE_FOR_EACH_EQUAL (sb_route, filter,
                                        sbrec_learned_route_by_datapath) {
        const struct sbrec_port_binding *cr_pb =
            lport_get_cr_port(sbrec_port_binding_by_name,
                              sb_route->logical_port, NULL);
        struct route_entry *route_e = NULL;

        /* Collect the set of unique logical ports we learned routes on. The
         * (potentially expensive) dynamic-routing-port-name lookups are
         * postponed until after the loop so that they are performed once per
         * logical port instead of once per learned route. */
        hmapx_add(&lrp_with_dr_port_name,
                  CONST_CAST(void *, sb_route->logical_port));

        if (sb_route->logical_port->chassis == chassis ||
            (cr_pb && cr_pb->chassis == chassis)) {
            route_e = route_add_entry(&sync_routes, sb_route, false);
        }

        /* If the port is not local we don't care about it.
         * Some other ovn-controller will handle it.
         * We may not use smap_get since the value might be validly NULL. */
        if (!smap_get_node(bound_ports,
                           sb_route->logical_port->logical_port)) {
            continue;
        }
        if (route_e) {
            route_e->stale = true;
            continue;
        }
        route_add_entry(&sync_routes, sb_route, true);
    }
    sbrec_learned_route_index_destroy_row(filter);

    /* Drop the logical ports that don't have a dynamic-routing-port-name set,
     * either directly or via their distributed gateway port. */
    struct hmapx_node *lrp_node;
    HMAPX_FOR_EACH_SAFE (lrp_node, &lrp_with_dr_port_name) {
        const struct sbrec_port_binding *lrp = lrp_node->data;
        const struct sbrec_port_binding *cr_pb =
            lport_get_cr_port(sbrec_port_binding_by_name, lrp, NULL);
        const char *dynamic_routing_port_name =
            smap_get(&lrp->options, "dynamic-routing-port-name");
        if (!dynamic_routing_port_name && cr_pb) {
            dynamic_routing_port_name =
                smap_get(&cr_pb->options, "dynamic-routing-port-name");
        }
        if (!dynamic_routing_port_name) {
            hmapx_delete(&lrp_with_dr_port_name, lrp_node);
        }
    }

    if (!hmapx_is_empty(&lrp_with_dr_port_name)) {
        struct route_entry *route_e;
        HMAP_FOR_EACH (route_e, hmap_node, &sync_routes) {
            if (!hmapx_contains(&lrp_with_dr_port_name,
                                route_e->sb_route->logical_port)) {
                route_e->stale = true;
            }
        }
    }
    hmapx_destroy(&lrp_with_dr_port_name);

    struct re_nl_received_route_node *learned_route;
    VECTOR_FOR_EACH_PTR (learned_routes, learned_route) {
        char *ip_prefix = normalize_v46_prefix(&learned_route->prefix,
                                               learned_route->plen);
        char *nexthop = normalize_v46(&learned_route->nexthop);

        struct smap_node *port_node;
        SMAP_FOR_EACH (port_node, bound_ports) {
            /* The user specified an ifname, but we learned it on a different
             * port. */
            if (port_node->value && strcmp(port_node->value,
                                           learned_route->ifname)) {
                continue;
            }

            const struct sbrec_port_binding *logical_port =
                lport_lookup_by_name(sbrec_port_binding_by_name,
                                     port_node->key);
            if (!logical_port) {
                continue;
            }

            bool no_learning = smap_get_bool(&logical_port->options,
                                             "dynamic-routing-no-learning",
                                             false);
            if (no_learning) {
                continue;
            }

            struct route_entry *route_e =
                route_lookup(&sync_routes, datapath,
                             logical_port, ip_prefix, nexthop);
            if (route_e) {
                route_e->stale = false;
            } else {
                if (!ovnsb_idl_txn) {
                    *sb_changes_pending = true;
                    continue;
                }
                sb_route = sbrec_learned_route_insert(ovnsb_idl_txn);
                sbrec_learned_route_set_datapath(sb_route, datapath);
                sbrec_learned_route_set_logical_port(sb_route, logical_port);
                sbrec_learned_route_set_ip_prefix(sb_route, ip_prefix);
                sbrec_learned_route_set_nexthop(sb_route, nexthop);

                route_add_entry(&sync_routes, sb_route, false);
            }
        }
        free(ip_prefix);
        free(nexthop);
    }

    struct route_entry *route_e;
    HMAP_FOR_EACH_POP (route_e, hmap_node, &sync_routes) {
        if (route_e->stale) {
            sbrec_learned_route_delete(route_e->sb_route);
        }
        free(route_e);
    }
    hmap_destroy(&sync_routes);
}

/* Last route_exchange netlink operation. */
static int route_exchange_nl_status;

#define CLEAR_ROUTE_EXCHANGE_NL_STATUS() \
    do {                                 \
        route_exchange_nl_status = 0;    \
    } while (0)

#define SET_ROUTE_EXCHANGE_NL_STATUS(error)     \
    do {                                        \
        if (!route_exchange_nl_status) {        \
            route_exchange_nl_status = (error); \
            if (error) {                        \
                poll_immediate_wake();          \
            }                                   \
        }                                       \
    } while (0)

struct advertised_routes_entry {
    struct hmap_node node;

    /* Contains "struct advertise_datapath_entry *" for all datapaths that
     * advertise routes on this routing table. Multiple datapaths may share a
     * single table when they use the same dynamic-routing-vrf-id. */
    struct hmapx datapaths;
    uint32_t table_id;
};

/* Records that 'ad' distributes routes into the table 'table_id', creating the
 * entry for the table in 'advertised_routes' if it is the first datapath to do
 * so. */
static void
advertised_routes_add(struct hmap *advertised_routes,
                      const struct advertise_datapath_entry *ad,
                      uint32_t table_id)
{
    struct advertised_routes_entry *entry = NULL;
    uint32_t hash = maintained_route_table_hash(table_id);
    HMAP_FOR_EACH_WITH_HASH (entry, node, hash, advertised_routes) {
        if (entry->table_id == table_id) {
            break;
        }
    }

    if (entry == NULL) {
        entry = xmalloc(sizeof *entry);
        *entry = (struct advertised_routes_entry) {
            .datapaths = HMAPX_INITIALIZER(&entry->datapaths),
            .table_id = table_id,
        };
        hmap_insert(advertised_routes, &entry->node, hash);
    }

    hmapx_add(&entry->datapaths, CONST_CAST(void *, ad));
}

/* Collects the route tables of all datapaths in 'datapaths' ('struct
 * advertise_datapath_entry *') into 'route_tables', so that a routing table
 * shared by several of them is synced as a single authoritative set. */
static void
advertised_routes_tables(const struct hmapx *datapaths,
                         struct vector *route_tables)
{
    struct hmapx_node *dp_node;
    HMAPX_FOR_EACH (dp_node, datapaths) {
        const struct advertise_datapath_entry *adpe = dp_node->data;
        const struct hmap *routes = &adpe->routes;

        vector_push(route_tables, &routes);
    }
}

static struct advertised_routes_entry *
advertised_routes_find(const struct hmap *advertised_routes, uint32_t table_id)
{
    struct advertised_routes_entry *arte;
    HMAP_FOR_EACH_WITH_HASH (arte, node,
                             maintained_route_table_hash(table_id),
                             advertised_routes) {
        if (arte->table_id == table_id) {
            return arte;
        }
    }

    return NULL;
}

/* Maps every routing table OVN distributes routes into to the datapaths that
 * do so. */
static void
advertised_routes_build(struct hmap *advertised_routes,
                        const struct hmap *announce_routes)
{
    const struct advertise_datapath_entry *ad;
    HMAP_FOR_EACH (ad, node, announce_routes) {
        uint32_t table_id = route_get_table_id(ad->db);

        if (TABLE_ID_VALID(table_id)) {
            advertised_routes_add(advertised_routes, ad, table_id);
        }
    }
}

static void
advertised_routes_destroy(struct hmap *advertised_routes)
{
    struct advertised_routes_entry *arte;
    HMAP_FOR_EACH_POP (arte, node, advertised_routes) {
        hmapx_destroy(&arte->datapaths);
        free(arte);
    }
    hmap_destroy(advertised_routes);
}

/* Turns the routes OVN learns from the table 'rt' into Learned_Route rows of
 * every datapath in 'datapaths' ('struct advertise_datapath_entry *'). */
static void
route_table_resolve_and_sync(
    struct route_table_state *rt, const struct hmapx *datapaths,
    const struct route_exchange_ctx_in *r_ctx_in,
    struct route_exchange_ctx_out *r_ctx_out)
{
    struct vector received_routes =
        VECTOR_EMPTY_INITIALIZER(struct re_nl_received_route_node);

    const struct re_nl_cached_route *cr;
    HMAP_FOR_EACH (cr, node, &rt->learned_routes) {
        re_nl_resolve_route(cr->msg, &received_routes);
    }

    struct hmapx_node *dp_node;
    HMAPX_FOR_EACH (dp_node, datapaths) {
        const struct advertise_datapath_entry *adpe = dp_node->data;

        sb_sync_learned_routes(&received_routes, adpe->db,
                               &adpe->bound_ports,
                               r_ctx_in->ovnsb_idl_txn,
                               r_ctx_in->sbrec_port_binding_by_name,
                               r_ctx_in->sbrec_learned_route_by_datapath,
                               &r_ctx_out->sb_changes_pending,
                               r_ctx_in->chassis);
    }

    vector_destroy(&received_routes);
}

/* Redoes the Learned_Route rows of every table in 'changed_tables' ('struct
 * route_table_state'). */
static enum route_exchange_handled
resync_changed_tables(const struct hmapx *changed_tables,
                      const struct route_exchange_ctx_in *r_ctx_in,
                      struct route_exchange_ctx_out *r_ctx_out)
{
    if (hmapx_is_empty(changed_tables)) {
        return ROUTE_EXCHANGE_UNCHANGED;
    }

    if (!r_ctx_in->ovnsb_idl_txn) {
        /* Without a transaction we could only record that there are changes
         * left to write, which a full run does better. */
        return ROUTE_EXCHANGE_UNHANDLED;
    }

    struct hmap advertised_routes = HMAP_INITIALIZER(&advertised_routes);
    enum route_exchange_handled handled = ROUTE_EXCHANGE_UPDATED;

    advertised_routes_build(&advertised_routes, r_ctx_in->announce_routes);

    struct hmapx_node *hn;
    HMAPX_FOR_EACH (hn, changed_tables) {
        struct route_table_state *rt = hn->data;
        const struct advertised_routes_entry *arte =
            advertised_routes_find(&advertised_routes, rt->table_id);

        if (!arte) {
            /* The datapaths distributing routes into the table are not the
             * ones it was synced for. */
            handled = ROUTE_EXCHANGE_UNHANDLED;
            break;
        }

        route_table_resolve_and_sync(rt, &arte->datapaths, r_ctx_in,
                                     r_ctx_out);
    }

    advertised_routes_destroy(&advertised_routes);

    return handled;
}

enum route_exchange_handled
route_exchange_handle_route_changes(
    struct route_exchange_state *state,
    const struct route_exchange_ctx_in *r_ctx_in,
    struct route_exchange_ctx_out *r_ctx_out,
    const struct vector *changed_routes)
{
    struct hmapx changed_tables = HMAPX_INITIALIZER(&changed_tables);
    enum route_exchange_handled handled;

    const struct ovn_route_msg *msg;
    VECTOR_FOR_EACH (changed_routes, msg) {
        struct route_table_state *rt =
            route_table_state_find(state, msg->table_id);
        if (!rt) {
            /* A table we have not read, so we do not know the rest of it
             * either. */
            handled = ROUTE_EXCHANGE_UNHANDLED;
            goto out;
        }

        if (re_nl_cached_routes_apply(&rt->learned_routes, msg)) {
            hmapx_add(&changed_tables, rt);
        }
    }

    handled = resync_changed_tables(&changed_tables, r_ctx_in, r_ctx_out);

out:
    hmapx_destroy(&changed_tables);

    return handled;
}

void
route_exchange_run(struct route_exchange_state *state,
                   const struct route_exchange_ctx_in *r_ctx_in,
                   struct route_exchange_ctx_out *r_ctx_out)
{
    struct hmap advertised_routes = HMAP_INITIALIZER(&advertised_routes);
    struct sset old_maintained_vrfs = SSET_INITIALIZER(&old_maintained_vrfs);
    sset_swap(&_maintained_vrfs, &old_maintained_vrfs);
    struct hmap old_maintained_route_table =
        HMAP_INITIALIZER(&old_maintained_route_table);
    hmap_swap(&_maintained_route_tables, &old_maintained_route_table);
    int error;

    CLEAR_ROUTE_EXCHANGE_NL_STATUS();
    const struct advertise_datapath_entry *ad;
    HMAP_FOR_EACH (ad, node, r_ctx_in->announce_routes) {
        uint32_t table_id = route_get_table_id(ad->db);
        if (!TABLE_ID_VALID(table_id)) {
            VLOG_WARN_RL(&rl, "Unable to sync routes for datapath "UUID_FMT": "
                         "invalid table id: %"PRIu32,
                         UUID_ARGS(&ad->db->header_.uuid), table_id);
            continue;
        }

        if (ad->maintain_vrf) {
            if (!sset_contains(&old_maintained_vrfs, ad->vrf_name)) {
                error = re_nl_create_vrf(ad->vrf_name, table_id);
                if (error && error != EEXIST) {
                    VLOG_WARN_RL(&rl,
                                 "Unable to create VRF %s for datapath "
                                 UUID_FMT": %s.", ad->vrf_name,
                                 UUID_ARGS(&ad->db->header_.uuid),
                                 ovs_strerror(error));
                    SET_ROUTE_EXCHANGE_NL_STATUS(error);
                    continue;
                }
            }
            sset_add(&_maintained_vrfs, ad->vrf_name);
        } else {
            /* A previous maintain-vrf flag was removed. We should therefore
             * also not delete it even if we created it previously. */
            sset_find_and_delete(&_maintained_vrfs, ad->vrf_name);
            sset_find_and_delete(&old_maintained_vrfs, ad->vrf_name);
        }

        advertised_routes_add(&advertised_routes, ad, table_id);
    }

    struct advertised_routes_entry *arte;
    HMAP_FOR_EACH (arte, node, &advertised_routes) {
        maintained_route_table_add(arte->table_id);

        struct route_table_state *rt = route_table_state_get(state,
                                                             arte->table_id);
        struct vector route_tables =
            VECTOR_EMPTY_INITIALIZER(const struct hmap *);
        advertised_routes_tables(&arte->datapaths, &route_tables);

        error = re_nl_sync_routes(arte->table_id, &route_tables,
                                  &rt->learned_routes);
        SET_ROUTE_EXCHANGE_NL_STATUS(error);
        vector_destroy(&route_tables);

        route_table_resolve_and_sync(rt, &arte->datapaths, r_ctx_in,
                                     r_ctx_out);
        vector_push(r_ctx_out->route_table_watches, &arte->table_id);
    }

    /* Forget the tables we do not sync anymore. */
    struct route_table_state *rt;
    HMAP_FOR_EACH_SAFE (rt, node, &state->tables) {
        if (!advertised_routes_find(&advertised_routes, rt->table_id)) {
            route_table_state_destroy(state, rt);
        }
    }

    /* Remove routes in tables previously maintained by us. */
    struct maintained_route_table_entry *mrt;
    HMAP_FOR_EACH_POP (mrt, node, &old_maintained_route_table) {
        if (!maintained_route_table_contains(mrt->table_id)) {
            error = re_nl_cleanup_routes(mrt->table_id);
            if (error) {
                /* If netlink transaction fails, we will retry next time. */
                maintained_route_table_add(mrt->table_id);
                SET_ROUTE_EXCHANGE_NL_STATUS(error);
            }
        }
        free(mrt);
    }
    hmap_destroy(&old_maintained_route_table);

    /* Remove VRFs previously maintained by us not found in the above loop. */
    const char *vrf_name;
    SSET_FOR_EACH_SAFE (vrf_name, &old_maintained_vrfs) {
        if (!sset_contains(&_maintained_vrfs, vrf_name)) {
            error = re_nl_delete_vrf(vrf_name);
            if (error && error != ENODEV) {
                /* If netlink transaction fails, we will retry next time. */
                sset_add(&_maintained_vrfs, vrf_name);
                SET_ROUTE_EXCHANGE_NL_STATUS(error);
            }
        }
        sset_delete(&old_maintained_vrfs, SSET_NODE_FROM_NAME(vrf_name));
    }
    sset_destroy(&old_maintained_vrfs);
    advertised_routes_destroy(&advertised_routes);
}

void
route_exchange_cleanup_vrfs(void)
{
    struct maintained_route_table_entry *mrt;
    HMAP_FOR_EACH (mrt, node, &_maintained_route_tables) {
        re_nl_cleanup_routes(mrt->table_id);
    }

    const char *vrf_name;
    SSET_FOR_EACH (vrf_name, &_maintained_vrfs) {
        re_nl_delete_vrf(vrf_name);
    }
}

void
route_exchange_destroy(void)
{
    struct maintained_route_table_entry *mrt;
    HMAP_FOR_EACH_POP (mrt, node, &_maintained_route_tables) {
        free(mrt);
    }

    const char *vrf_name;
    SSET_FOR_EACH_SAFE (vrf_name, &_maintained_vrfs) {
        sset_delete(&_maintained_vrfs, SSET_NODE_FROM_NAME(vrf_name));
    }

    sset_destroy(&_maintained_vrfs);
    hmap_destroy(&_maintained_route_tables);
}

int
route_exchange_status_run(void)
{
    return route_exchange_nl_status;
}
