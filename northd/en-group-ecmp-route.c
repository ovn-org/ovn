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

#include "northd/lflow-mgr.h"
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
ecmp_groups_node_free(struct ecmp_groups_node *eg)
{
    if (!eg) {
        return;
    }

    struct ecmp_route_list_node *er;
    LIST_FOR_EACH_SAFE (er, list_node, &eg->route_list) {
        ovs_list_remove(&er->list_node);
        free(er);
    }
    sset_destroy(&eg->selection_fields);
    free(eg);
}

static void
ecmp_groups_destroy(struct hmap *ecmp_groups)
{
    struct ecmp_groups_node *eg;
    HMAP_FOR_EACH_SAFE (eg, hmap_node, ecmp_groups) {
        hmap_remove(ecmp_groups, &eg->hmap_node);
        ecmp_groups_node_free(eg);
    }
    hmap_destroy(ecmp_groups);
}

static void
group_node_free(struct group_ecmp_datapath *n)
{
    if (!n) {
        return;
    }

    unique_routes_destroy(&n->unique_routes);
    ecmp_groups_destroy(&n->ecmp_groups);
    lflow_ref_destroy(n->lflow_ref);
    free(n);
}

static void
group_ecmp_route_clear_tracked(struct group_ecmp_route_data *data)
{
    data->tracked = false;
    hmapx_clear(&data->trk_data.crupdated_datapath_routes);

    struct hmapx_node *hmapx_node;
    HMAPX_FOR_EACH (hmapx_node, &data->trk_data.deleted_datapath_routes) {
        group_node_free(hmapx_node->data);
    }
    hmapx_clear(&data->trk_data.deleted_datapath_routes);
}

static void
group_ecmp_route_clear(struct group_ecmp_route_data *data)
{
    struct group_ecmp_datapath *n;
    HMAP_FOR_EACH_POP (n, hmap_node, &data->datapaths) {
        group_node_free(n);
    }
    group_ecmp_route_clear_tracked(data);
}

static void
group_ecmp_route_init(struct group_ecmp_route_data *data)
{
    hmap_init(&data->datapaths);
    hmapx_init(&data->trk_data.crupdated_datapath_routes);
    hmapx_init(&data->trk_data.deleted_datapath_routes);
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
    hmapx_destroy(&data->trk_data.crupdated_datapath_routes);
    hmapx_destroy(&data->trk_data.deleted_datapath_routes);
}

void
en_group_ecmp_route_clear_tracked_data(void *data OVS_UNUSED)
{
    group_ecmp_route_clear_tracked(data);
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
    size_t hash = uuid_hash(&od->key);
    struct group_ecmp_datapath *n = xmalloc(sizeof *n);
    n->od = od;
    n->lflow_ref = lflow_ref_create();
    hmap_init(&n->ecmp_groups);
    hmap_init(&n->unique_routes);
    hmap_insert(&data->datapaths, &n->hmap_node, hash);
    return n;
}

static struct group_ecmp_datapath *
group_ecmp_datapath_lookup_or_add(struct group_ecmp_route_data *data,
                                  const struct ovn_datapath *od)
{
    struct group_ecmp_datapath *n = group_ecmp_datapath_lookup(data, od);
    if (n) {
        return n;
    }

    return group_ecmp_datapath_add(data, od);
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

/* Removes a route from an ecmp group. If the ecmp group should persist
 * afterwards you must call ecmp_groups_update_ids before any further
 * insertions. */
static const struct parsed_route *
ecmp_groups_remove_route(struct ecmp_groups_node *group,
                         const struct parsed_route *pr)
{
    struct ecmp_route_list_node *er;
    LIST_FOR_EACH (er, list_node, &group->route_list) {
        if (er->route == pr) {
            const struct parsed_route *found_route = er->route;
            ovs_list_remove(&er->list_node);
            free(er);
            return found_route;
        }
    }

    return NULL;
}

static void
ecmp_group_update_ids(struct ecmp_groups_node *group)
{
    struct ecmp_route_list_node *er;
    size_t i = 0;
    LIST_FOR_EACH (er, list_node, &group->route_list) {
        er->id = i;
        i++;
    }
    group->route_count = i;
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

static bool
ecmp_group_has_symmetric_reply(struct ecmp_groups_node *eg)
{
    struct ecmp_route_list_node *er;
    LIST_FOR_EACH (er, list_node, &eg->route_list) {
        if (er->route->ecmp_symmetric_reply) {
            return true;
        }
    }
    return false;
}

static void
add_route(struct group_ecmp_datapath *gn, const struct parsed_route *pr)
{
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
    struct group_ecmp_datapath *gn;
    const struct parsed_route *pr;
    HMAP_FOR_EACH (pr, key_node, &routes_data->parsed_routes) {
        gn = group_ecmp_datapath_lookup_or_add(data, pr->od);
        add_route(gn, pr);
    }

    HMAP_FOR_EACH (pr, key_node, &learned_route_data->parsed_routes) {
        gn = group_ecmp_datapath_lookup_or_add(data, pr->od);
        add_route(gn, pr);
    }
}

void
en_group_ecmp_route_run(struct engine_node *node, void *_data)
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

static void
handle_added_route(struct group_ecmp_route_data *data,
                   const struct parsed_route *pr,
                   struct hmapx *updated_routes)
{
    struct group_ecmp_datapath *node = group_ecmp_datapath_lookup(data,
                                                                  pr->od);

    if (!node) {
        node = group_ecmp_datapath_add(data, pr->od);
    }

    hmapx_add(updated_routes, node);
    add_route(node, pr);
}

static bool
handle_deleted_route(struct group_ecmp_route_data *data,
                     const struct parsed_route *pr,
                     struct hmapx *updated_routes)
{
    struct group_ecmp_datapath *node = group_ecmp_datapath_lookup(data,
                                                                  pr->od);
    if (!node) {
        /* This should not happen since we should know the datapath. */
        return false;
    }

    const struct parsed_route *existing = unique_routes_remove(node, pr);
    if (!existing) {
        /* The route must be part of an ecmp group. */
        if (pr->source == ROUTE_SOURCE_CONNECTED) {
            /* Connected routes are never part of an ecmp group.
             * We should recompute. */
            return false;
        }

        struct ecmp_groups_node *eg = ecmp_groups_find(node, pr);
        if (!eg) {
            /* We neither found the route as unique nor as ecmp group.
             * We should recompute. */
            return false;
        }

        size_t ecmp_members = ovs_list_size(&eg->route_list);
        if (ecmp_members == 1) {
            /* The route is the only ecmp member, we remove the whole group. */
            hmap_remove(&node->ecmp_groups, &eg->hmap_node);
            ecmp_groups_node_free(eg);
        } else if (ecmp_members == 2) {
            /* There is only one other member. If it does not have
             * ecmp_symmetric_reply configured, we convert it to a
             * unique route. Otherwise it stays an ecmp group with just one
             * member. */
            ecmp_groups_remove_route(eg, pr);
            if (ecmp_group_has_symmetric_reply(eg)) {
                ecmp_group_update_ids(eg);
            } else {
                struct ecmp_route_list_node *er = CONTAINER_OF(
                    ovs_list_front(&eg->route_list),
                    struct ecmp_route_list_node, list_node);
                unique_routes_add(node, er->route);
                hmap_remove(&node->ecmp_groups, &eg->hmap_node);
                ecmp_groups_node_free(eg);
            }
        } else {
            /* We can just remove the member from the group. We need to update
             * the indices of all routes so that future insertions directly
             * have a new index. */
            ecmp_groups_remove_route(eg, pr);
            ecmp_group_update_ids(eg);
        }
    }

    hmapx_add(updated_routes, node);
    return true;
}

bool
group_ecmp_route_learned_route_change_handler(struct engine_node *eng_node,
                                              void *_data)
{
    struct group_ecmp_route_data *data = _data;
    struct learned_route_sync_data *learned_route_data
        = engine_get_input_data("learned_route_sync", eng_node);

    if (!learned_route_data->tracked) {
        data->tracked = false;
        return false;
    }

    data->tracked = true;

    struct hmapx updated_routes = HMAPX_INITIALIZER(&updated_routes);

    const struct hmapx_node *hmapx_node;
    const struct parsed_route *pr;
    HMAPX_FOR_EACH (hmapx_node,
                    &learned_route_data->trk_data.trk_deleted_parsed_route) {
        pr = hmapx_node->data;
        if (!handle_deleted_route(data, pr, &updated_routes)) {
            hmapx_destroy(&updated_routes);
            return false;
        }
    }

    HMAPX_FOR_EACH (hmapx_node,
                    &learned_route_data->trk_data.trk_created_parsed_route) {
        pr = hmapx_node->data;
        handle_added_route(data, pr, &updated_routes);
    }

    /* Now we need to group the route_nodes based on if there are any routes
     * left. */
    HMAPX_FOR_EACH (hmapx_node, &updated_routes) {
        struct group_ecmp_datapath *node = hmapx_node->data;
        if (hmap_is_empty(&node->unique_routes) &&
                hmap_is_empty(&node->ecmp_groups)) {
            hmapx_add(&data->trk_data.deleted_datapath_routes, node);
            hmap_remove(&data->datapaths, &node->hmap_node);
        } else {
            hmapx_add(&data->trk_data.crupdated_datapath_routes, node);
        }
    }

    hmapx_destroy(&updated_routes);

    if (!(hmapx_is_empty(&data->trk_data.crupdated_datapath_routes) &&
          hmapx_is_empty(&data->trk_data.deleted_datapath_routes))) {
        engine_set_node_state(eng_node, EN_UPDATED);
    }
    return true;
}
