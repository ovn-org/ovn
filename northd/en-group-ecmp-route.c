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
#include <stdbool.h>

#include "openvswitch/vlog.h"
#include "stopwatch.h"
#include "northd.h"

#include "en-group-ecmp-route.h"
#include "en-learned-route-sync.h"
#include "lib/stopwatch-names.h"
#include "openvswitch/hmap.h"

VLOG_DEFINE_THIS_MODULE(en_group_ecmp_route);

static void
unique_routes_destroy(struct hmap *unique_routes);

static void
ecmp_groups_destroy(struct hmap *ecmp_groups)
{
    struct ecmp_groups_node *eg;
    HMAP_FOR_EACH_SAFE (eg, hmap_node, ecmp_groups) {
        struct ecmp_route_list_node *er;
        LIST_FOR_EACH_SAFE (er, list_node, &eg->route_list) {
            ovs_list_remove(&er->list_node);
            free(er);
        }
        hmap_remove(ecmp_groups, &eg->hmap_node);
        sset_destroy(&eg->selection_fields);
        free(eg);
    }
    hmap_destroy(ecmp_groups);
}

static void
group_ecmp_route_clear(struct group_ecmp_route_data *data)
{
    struct group_ecmp_datapath *n;
    HMAP_FOR_EACH_POP (n, hmap_node, &data->datapaths) {
        unique_routes_destroy(&n->unique_routes);
        ecmp_groups_destroy(&n->ecmp_groups);
        free(n);
    }
}

static void
group_ecmp_route_init(struct group_ecmp_route_data *data)
{
    hmap_init(&data->datapaths);
}

void *en_group_ecmp_route_init(struct engine_node *node OVS_UNUSED,
                               struct engine_arg *arg OVS_UNUSED)
{
    struct group_ecmp_route_data *data = xmalloc(sizeof *data);
    group_ecmp_route_init(data);
    return data;
}

void en_group_ecmp_route_cleanup(void *_data)
{
    struct group_ecmp_route_data *data = _data;
    group_ecmp_route_clear(data);
    hmap_destroy(&data->datapaths);
}

void
en_group_ecmp_route_clear_tracked_data(void *data OVS_UNUSED)
{
}

struct group_ecmp_datapath *
group_ecmp_datapath_lookup(const struct group_ecmp_route_data *data,
                           const struct ovn_datapath *od)
{
    struct group_ecmp_datapath *n;
    size_t hash = uuid_hash(&od->key);
    HMAP_FOR_EACH_WITH_HASH (n, hmap_node, hash, &data->datapaths) {
        if (n->od == od) {
            return n;
        }
    }
    return NULL;
}

static struct group_ecmp_datapath *
group_ecmp_datapath_add(struct group_ecmp_route_data *data,
                        const struct ovn_datapath *od)
{
    struct group_ecmp_datapath *n = group_ecmp_datapath_lookup(data, od);
    if (n) {
        return n;
    }

    size_t hash = uuid_hash(&od->key);
    n = xmalloc(sizeof *n);
    n->od = od;
    hmap_init(&n->ecmp_groups);
    hmap_init(&n->unique_routes);
    hmap_insert(&data->datapaths, &n->hmap_node, hash);
    return n;
}

static void
unique_routes_add(struct group_ecmp_datapath *gn,
                  const struct parsed_route *route)
{
    struct unique_routes_node *ur = xmalloc(sizeof *ur);
    ur->route = route;
    hmap_insert(&gn->unique_routes, &ur->hmap_node, route->hash);
}

static void
unique_routes_destroy(struct hmap *unique_routes)
{
    struct unique_routes_node *ur;
    HMAP_FOR_EACH_SAFE (ur, hmap_node, unique_routes) {
        hmap_remove(unique_routes, &ur->hmap_node);
        free(ur);
    }
    hmap_destroy(unique_routes);
}

/* Remove the unique_routes_node from the group, and return the parsed_route
 * pointed by the removed node. */
static const struct parsed_route *
unique_routes_remove(struct group_ecmp_datapath *gn,
                     const struct parsed_route *route)
{
    struct unique_routes_node *ur;
    HMAP_FOR_EACH_WITH_HASH (ur, hmap_node, route->hash, &gn->unique_routes) {
        if (ipv6_addr_equals(&route->prefix, &ur->route->prefix) &&
            route->plen == ur->route->plen &&
            route->is_src_route == ur->route->is_src_route &&
            route->source == ur->route->source &&
            route->route_table_id == ur->route->route_table_id) {
            hmap_remove(&gn->unique_routes, &ur->hmap_node);
            const struct parsed_route *existed_route = ur->route;
            free(ur);
            return existed_route;
        }
    }
    return NULL;
}

static void
ecmp_groups_add_route(struct ecmp_groups_node *group,
                      const struct parsed_route *route)
{
    if (group->route_count == UINT16_MAX) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "too many routes in a single ecmp group.");
        return;
    }

    struct ecmp_route_list_node *er = xmalloc(sizeof *er);
    er->route = route;
    er->id = ++group->route_count;

    if (group->route_count == 1) {
        sset_clone(&group->selection_fields, &route->ecmp_selection_fields);
    } else {
        sset_intersect(&group->selection_fields,
                       &route->ecmp_selection_fields);
    }

    ovs_list_insert(&group->route_list, &er->list_node);
}

static struct ecmp_groups_node *
ecmp_groups_add(struct group_ecmp_datapath *gn,
                const struct parsed_route *route)
{
    if (hmap_count(&gn->ecmp_groups) == UINT16_MAX) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "too many ecmp groups.");
        return NULL;
    }

    struct ecmp_groups_node *eg = xzalloc(sizeof *eg);
    hmap_insert(&gn->ecmp_groups, &eg->hmap_node, route->hash);

    eg->id = hmap_count(&gn->ecmp_groups);
    eg->prefix = route->prefix;
    eg->plen = route->plen;
    eg->is_src_route = route->is_src_route;
    eg->source = route->source;
    eg->route_table_id = route->route_table_id;
    sset_init(&eg->selection_fields);
    ovs_list_init(&eg->route_list);
    ecmp_groups_add_route(eg, route);

    return eg;
}

static struct ecmp_groups_node *
ecmp_groups_find(struct group_ecmp_datapath *gn,
                 const struct parsed_route *route)
{
    struct ecmp_groups_node *eg;
    HMAP_FOR_EACH_WITH_HASH (eg, hmap_node, route->hash, &gn->ecmp_groups) {
        if (ipv6_addr_equals(&eg->prefix, &route->prefix) &&
            eg->plen == route->plen &&
            eg->is_src_route == route->is_src_route &&
            eg->route_table_id == route->route_table_id &&
            eg->source == route->source) {
            return eg;
        }
    }
    return NULL;
}

static void
add_route(struct group_ecmp_route_data *data, const struct parsed_route *pr)
{
    struct group_ecmp_datapath *gn = group_ecmp_datapath_add(data, pr->od);

    if (pr->source == ROUTE_SOURCE_CONNECTED) {
        unique_routes_add(gn, pr);
        return;
    }

    struct ecmp_groups_node *group = ecmp_groups_find(gn, pr);
    if (group) {
        ecmp_groups_add_route(group, pr);
    } else {
        const struct parsed_route *existed_route =
            unique_routes_remove(gn, pr);
        if (existed_route) {
            group = ecmp_groups_add(gn, existed_route);
            if (group) {
                ecmp_groups_add_route(group, pr);
            }
        } else if (pr->ecmp_symmetric_reply) {
            /* Traffic for symmetric reply routes has to be conntracked
             * even if there is only one next-hop, in case another next-hop
             * is added later. */
            ecmp_groups_add(gn, pr);
        } else {
            unique_routes_add(gn, pr);
        }
    }
}

static void
group_ecmp_route(struct group_ecmp_route_data *data,
                 const struct routes_data *routes_data,
                 const struct learned_route_sync_data *learned_route_data)
{
    const struct parsed_route *pr;
    HMAP_FOR_EACH (pr, key_node, &routes_data->parsed_routes) {
        add_route(data, pr);
    }

    HMAP_FOR_EACH (pr, key_node, &learned_route_data->parsed_routes) {
        add_route(data, pr);
    }
}

void en_group_ecmp_route_run(struct engine_node *node, void *_data)
{
    struct group_ecmp_route_data *data = _data;
    group_ecmp_route_clear(data);

    struct routes_data *routes_data
        = engine_get_input_data("routes", node);
    struct learned_route_sync_data *learned_route_data
        = engine_get_input_data("learned_route_sync", node);

    stopwatch_start(GROUP_ECMP_ROUTE_RUN_STOPWATCH_NAME, time_msec());

    group_ecmp_route(data, routes_data, learned_route_data);

    stopwatch_stop(GROUP_ECMP_ROUTE_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}
