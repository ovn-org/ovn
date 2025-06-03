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

#include "openvswitch/vlog.h"
#include "openvswitch/list.h"

#include "lib/ovn-sb-idl.h"

#include "binding.h"
#include "ha-chassis.h"
#include "local_data.h"
#include "route.h"
#include "route-table-notify.h"
#include "route-exchange.h"
#include "route-exchange-netlink.h"

VLOG_DEFINE_THIS_MODULE(route_exchange);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

struct maintained_route_table_entry {
    struct hmap_node node;
    uint32_t table_id;
};

static struct hmap _maintained_route_tables =
    HMAP_INITIALIZER(&_maintained_route_tables);
static struct sset _maintained_vrfs = SSET_INITIALIZER(&_maintained_vrfs);

struct route_entry {
    struct hmap_node hmap_node;

    const struct sbrec_learned_route *sb_route;
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

static void
route_add_entry(struct hmap *routes,
                  const struct sbrec_learned_route *sb_route)
{
    struct route_entry *route_e = xmalloc(sizeof *route_e);
    route_e->sb_route = sb_route;

    uint32_t hash = uuid_hash(&sb_route->datapath->header_.uuid);
    hash = hash_string(sb_route->logical_port->logical_port, hash);
    hash = hash_string(sb_route->ip_prefix, hash);

    hmap_insert(routes, &route_e->hmap_node, hash);
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
                       struct ovsdb_idl_index *sbrec_learned_route_by_datapath)
{
    struct hmap sync_routes = HMAP_INITIALIZER(&sync_routes);
    const struct sbrec_learned_route *sb_route;
    struct route_entry *route_e;

    struct sbrec_learned_route *filter =
        sbrec_learned_route_index_init_row(sbrec_learned_route_by_datapath);
    sbrec_learned_route_index_set_datapath(filter, datapath);
    SBREC_LEARNED_ROUTE_FOR_EACH_EQUAL (sb_route, filter,
                                        sbrec_learned_route_by_datapath) {
        /* If the port is not local we don't care about it.
         * Some other ovn-controller will handle it.
         * We may not use smap_get since the value might be validly NULL. */
        if (!smap_get_node(bound_ports,
                           sb_route->logical_port->logical_port)) {
            continue;
        }
        route_add_entry(&sync_routes, sb_route);
    }
    sbrec_learned_route_index_destroy_row(filter);

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
            route_e = route_lookup(&sync_routes, datapath,
                                   logical_port, ip_prefix, nexthop);
            if (route_e) {
                hmap_remove(&sync_routes, &route_e->hmap_node);
                free(route_e);
            } else {
                sb_route = sbrec_learned_route_insert(ovnsb_idl_txn);
                sbrec_learned_route_set_datapath(sb_route, datapath);
                sbrec_learned_route_set_logical_port(sb_route, logical_port);
                sbrec_learned_route_set_ip_prefix(sb_route, ip_prefix);
                sbrec_learned_route_set_nexthop(sb_route, nexthop);
            }
        }
        free(ip_prefix);
        free(nexthop);
    }

    HMAP_FOR_EACH_POP (route_e, hmap_node, &sync_routes) {
        sbrec_learned_route_delete(route_e->sb_route);
        free(route_e);
    }
    hmap_destroy(&sync_routes);
}

void
route_exchange_run(const struct route_exchange_ctx_in *r_ctx_in,
                   struct route_exchange_ctx_out *r_ctx_out)
{
    struct sset old_maintained_vrfs = SSET_INITIALIZER(&old_maintained_vrfs);
    sset_swap(&_maintained_vrfs, &old_maintained_vrfs);
    struct hmap old_maintained_route_table =
        HMAP_INITIALIZER(&old_maintained_route_table);
    hmap_swap(&_maintained_route_tables, &old_maintained_route_table);
    int error;

    const struct advertise_datapath_entry *ad;
    HMAP_FOR_EACH (ad, node, r_ctx_in->announce_routes) {
        uint32_t table_id = ad->db->tunnel_key;

        if (ad->maintain_vrf) {
            if (!sset_contains(&old_maintained_vrfs, ad->vrf_name)) {
                error = re_nl_create_vrf(ad->vrf_name, table_id);
                if (error && error != EEXIST) {
                    VLOG_WARN_RL(&rl,
                                 "Unable to create VRF %s for datapath "
                                 "%"PRIi32": %s.",
                                 ad->vrf_name, table_id,
                                 ovs_strerror(error));
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

        maintained_route_table_add(table_id);

        struct vector received_routes =
            VECTOR_EMPTY_INITIALIZER(struct re_nl_received_route_node);

        re_nl_sync_routes(ad->db->tunnel_key, &ad->routes,
                          &received_routes, ad->db);

        sb_sync_learned_routes(&received_routes, ad->db,
                               &ad->bound_ports, r_ctx_in->ovnsb_idl_txn,
                               r_ctx_in->sbrec_port_binding_by_name,
                               r_ctx_in->sbrec_learned_route_by_datapath);

        route_table_add_watch_request(&r_ctx_out->route_table_watches,
                                      table_id);

        vector_destroy(&received_routes);
    }

    /* Remove routes in tables previously maintained by us. */
    struct maintained_route_table_entry *mrt;
    HMAP_FOR_EACH_POP (mrt, node, &old_maintained_route_table) {
        if (!maintained_route_table_contains(mrt->table_id)) {
            error = re_nl_cleanup_routes(mrt->table_id);
            if (error) {
                /* If netlink transaction fails, we will retry next time. */
                maintained_route_table_add(mrt->table_id);
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
            if (error) {
                /* If netlink transaction fails, we will retry next time. */
                sset_add(&_maintained_vrfs, vrf_name);
            }
        }
        sset_delete(&old_maintained_vrfs, SSET_NODE_FROM_NAME(vrf_name));
    }
    sset_destroy(&old_maintained_vrfs);
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
