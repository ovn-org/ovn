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

#include "en-learned-route-sync.h"
#include "lib/stopwatch-names.h"
#include "openvswitch/hmap.h"
#include "ovn-util.h"

VLOG_DEFINE_THIS_MODULE(en_learned_route_sync);

static void
routes_table_sync(
    const struct sbrec_learned_route_table *sbrec_learned_route_table,
    const struct hmap *lr_ports,
    const struct ovn_datapaths *lr_datapaths,
    struct hmap *parsed_routes_out);

enum engine_input_handler_result
learned_route_sync_northd_change_handler(struct engine_node *node,
                                         void *data_ OVS_UNUSED)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_has_tracked_data(&northd_data->trk_data)) {
        return EN_UNHANDLED;
    }

    /* This node uses the below data from the en_northd engine node.
     * See (lr_stateful_get_input_data())
     *   1. northd_data->lr_datapaths
     *   2. northd_data->lr_ports
     *      This data gets updated when a logical router or logical router port
     *      is created or deleted.
     *      Northd engine node presently falls back to full recompute when
     *      this happens and so does this node.
     *      Note: When we add I-P to the created/deleted logical routers or
     *      logical router ports, we need to revisit this handler.
     */

    return EN_HANDLED_UNCHANGED;
}

static void
routes_sync_clear_tracked(struct learned_route_sync_data *data)
{
    hmapx_clear(&data->trk_data.trk_created_parsed_route);
    struct hmapx_node *hmapx_node;
    HMAPX_FOR_EACH_SAFE (hmapx_node,
                         &data->trk_data.trk_deleted_parsed_route) {
        parsed_route_free(hmapx_node->data);
        hmapx_delete(&data->trk_data.trk_deleted_parsed_route, hmapx_node);
    }
    data->tracked = false;
}

static void
routes_sync_clear(struct learned_route_sync_data *data)
{
    struct parsed_route *r;
    HMAP_FOR_EACH_POP (r, key_node, &data->parsed_routes) {
        parsed_route_free(r);
    }
    routes_sync_clear_tracked(data);
}

static void
routes_sync_init(struct learned_route_sync_data *data)
{
    hmap_init(&data->parsed_routes);
    hmapx_init(&data->trk_data.trk_created_parsed_route);
    hmapx_init(&data->trk_data.trk_deleted_parsed_route);
    data->tracked = false;
}

static void
routes_sync_destroy(struct learned_route_sync_data *data)
{
    routes_sync_clear(data);
    hmap_destroy(&data->parsed_routes);
    hmapx_destroy(&data->trk_data.trk_created_parsed_route);
    hmapx_destroy(&data->trk_data.trk_deleted_parsed_route);
}

void *
en_learned_route_sync_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct learned_route_sync_data *data = xzalloc(sizeof *data);
    routes_sync_init(data);
    return data;
}

void
en_learned_route_sync_cleanup(void *data)
{
    routes_sync_destroy(data);
}

void
en_learned_route_sync_clear_tracked_data(void *data)
{
    routes_sync_clear_tracked(data);
}

enum engine_node_state
en_learned_route_sync_run(struct engine_node *node, void *data)
{
    routes_sync_clear(data);

    struct learned_route_sync_data *routes_sync_data = data;
    const struct sbrec_learned_route_table *sbrec_learned_route_table =
        EN_OVSDB_GET(engine_get_input("SB_learned_route", node));
    struct northd_data *northd_data = engine_get_input_data("northd", node);

    stopwatch_start(LEARNED_ROUTE_SYNC_RUN_STOPWATCH_NAME, time_msec());

    routes_table_sync(sbrec_learned_route_table,
                      &northd_data->lr_ports,
                      &northd_data->lr_datapaths,
                      &routes_sync_data->parsed_routes);

    stopwatch_stop(LEARNED_ROUTE_SYNC_RUN_STOPWATCH_NAME, time_msec());
    return EN_UPDATED;
}


static struct parsed_route *
parse_route_from_sbrec_route(struct hmap *parsed_routes_out,
                             const struct hmap *lr_ports,
                             const struct hmap *lr_datapaths,
                             const struct sbrec_learned_route *route)
{
    const struct ovn_datapath *od = ovn_datapath_from_sbrec(
        NULL, lr_datapaths, route->datapath);

    if (!od || ovn_datapath_is_stale(od)) {
        return NULL;
    }

    /* Verify that the next hop is an IP address with an all-ones mask. */
    struct in6_addr *nexthop = xmalloc(sizeof *nexthop);
    unsigned int plen;
    if (!ip46_parse_cidr(route->nexthop, nexthop, &plen)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad 'nexthop' %s in learned route "
                     UUID_FMT, route->nexthop,
                     UUID_ARGS(&route->header_.uuid));
        free(nexthop);
        return NULL;
    }
    if ((IN6_IS_ADDR_V4MAPPED(nexthop) && plen != 32) ||
        (!IN6_IS_ADDR_V4MAPPED(nexthop) && plen != 128)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad next hop mask %s in learned route "
                     UUID_FMT, route->nexthop,
                     UUID_ARGS(&route->header_.uuid));
        free(nexthop);
        return NULL;
    }

    /* Parse ip_prefix */
    struct in6_addr prefix;
    if (!ip46_parse_cidr(route->ip_prefix, &prefix, &plen)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad 'ip_prefix' %s in learned route "
                     UUID_FMT, route->ip_prefix,
                     UUID_ARGS(&route->header_.uuid));
        free(nexthop);
        return NULL;
    }

    /* Verify that ip_prefix and nexthop are on the same network. */
    const char *lrp_addr_s = NULL;
    struct ovn_port *out_port = NULL;
    if (!find_route_outport(lr_ports, route->logical_port->logical_port,
                            "static route", route->ip_prefix, route->nexthop,
                            IN6_IS_ADDR_V4MAPPED(&prefix),
                            false,
                            &out_port, &lrp_addr_s)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "could not find output port %s for learned route "
                     UUID_FMT, route->logical_port->logical_port,
                     UUID_ARGS(&route->header_.uuid));
        free(nexthop);
        return NULL;
    }

    return parsed_route_add(od, nexthop, &prefix, plen, false, lrp_addr_s,
                            out_port, 0, false, false, NULL,
                            ROUTE_SOURCE_LEARNED, &route->header_, NULL,
                            parsed_routes_out);
}

static void
routes_table_sync(
    const struct sbrec_learned_route_table *sbrec_learned_route_table,
    const struct hmap *lr_ports,
    const struct ovn_datapaths *lr_datapaths,
    struct hmap *parsed_routes_out)
{
    const struct sbrec_learned_route *sb_route;
    SBREC_LEARNED_ROUTE_TABLE_FOR_EACH_SAFE (sb_route,
                                             sbrec_learned_route_table) {
        struct ovn_port *op =
            ovn_port_find(lr_ports, sb_route->logical_port->logical_port);
        if (!op || op->sb != sb_route->logical_port || !op->od ||
            !op->od->dynamic_routing) {
            sbrec_learned_route_delete(sb_route);
            continue;
        }
        parse_route_from_sbrec_route(parsed_routes_out, lr_ports,
                                     &lr_datapaths->datapaths,
                                     sb_route);

    }
}

static struct parsed_route *
find_learned_route(const struct sbrec_learned_route *learned_route,
                   const struct ovn_datapaths *lr_datapaths,
                   const struct hmap *routes)
{
    const struct ovn_datapath *od = ovn_datapath_from_sbrec(
        NULL, &lr_datapaths->datapaths, learned_route->datapath);
    if (!od) {
        return NULL;
    }
    return parsed_route_lookup_by_source(od, ROUTE_SOURCE_LEARNED,
                                         &learned_route->header_, routes);
}

enum engine_input_handler_result
learned_route_sync_sb_learned_route_change_handler(struct engine_node *node,
                                                   void *data_)
{
    struct learned_route_sync_data *data = data_;
    data->tracked = true;

    const struct sbrec_learned_route_table *sbrec_learned_route_table =
        EN_OVSDB_GET(engine_get_input("SB_learned_route", node));
    struct northd_data *northd_data = engine_get_input_data("northd", node);

    const struct sbrec_learned_route *changed_route;
    SBREC_LEARNED_ROUTE_TABLE_FOR_EACH_TRACKED (changed_route,
                                                sbrec_learned_route_table) {
        if (sbrec_learned_route_is_new(changed_route) &&
            sbrec_learned_route_is_deleted(changed_route)) {
            continue;
        }

        if (sbrec_learned_route_is_new(changed_route)) {
            struct parsed_route *route = parse_route_from_sbrec_route(
                &data->parsed_routes, &northd_data->lr_ports,
                &northd_data->lr_datapaths.datapaths, changed_route);
            if (route) {
                hmapx_add(&data->trk_data.trk_created_parsed_route, route);
                continue;
            }
        }

        if (sbrec_learned_route_is_deleted(changed_route)) {
            struct parsed_route *route = find_learned_route(
                changed_route, &northd_data->lr_datapaths,
                &data->parsed_routes);
            if (!route) {
                goto fail;
            }
            hmap_remove(&data->parsed_routes, &route->key_node);
            hmapx_add(&data->trk_data.trk_deleted_parsed_route, route);
            continue;
        }

        /* The learned routes should never be updated, so we just fail the
         * handler here if that happens. */
        goto fail;
    }

    if (!hmapx_is_empty(&data->trk_data.trk_created_parsed_route) ||
        !hmapx_is_empty(&data->trk_data.trk_deleted_parsed_route)) {
        return EN_HANDLED_UPDATED;
    }

    return EN_HANDLED_UNCHANGED;

fail:
    routes_sync_clear_tracked(data);
    return EN_UNHANDLED;
}
