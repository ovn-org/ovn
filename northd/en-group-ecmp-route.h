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
#ifndef EN_GROUP_ECMP_ROUTE_H
#define EN_GROUP_ECMP_ROUTE_H 1

#include "lib/inc-proc-eng.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "northd/northd.h"
#include <netinet/in.h>

struct ecmp_route_list_node {
    struct ovs_list list_node;
    uint16_t id; /* starts from 1 */
    const struct parsed_route *route;
};

struct ecmp_groups_node {
    struct hmap_node hmap_node; /* In ecmp_groups */
    uint16_t id; /* starts from 1 */
    struct in6_addr prefix;
    unsigned int plen;
    bool is_src_route;
    enum route_source source;
    uint32_t route_table_id;
    uint16_t route_count;
    struct ovs_list route_list; /* Contains ecmp_route_list_node */
    struct sset selection_fields;
};

struct unique_routes_node {
    struct hmap_node hmap_node;
    const struct parsed_route *route;
};

/* Each 'group_ecmp_datapath' represents all routes relevant for that single
 * datapath grouped by ecmp and unique routes. */
struct group_ecmp_datapath {
    struct hmap_node hmap_node;

    /* The datapath for which this node is relevant. */
    const struct ovn_datapath *od;

    /* The lflow ref for all routes of this datapath. */
    struct lflow_ref *lflow_ref;

    /* Contains all routes that are part of an ecmp group.
     * Contains struct ecmp_groups_node. */
    struct hmap ecmp_groups;

    /* Contains all routes that are not part of an ecmp group.
     * Contains struct unique_routes_node. */
    struct hmap unique_routes;
};

struct group_ecmp_route_tracked_data {
    /* Contains references to group_ecmp_route_node. Each of the referenced
     * datapaths contains at least one route. */
    struct hmapx crupdated_datapath_routes;

    /* Contains references to group_ecmp_route_node. Each of the referenced
     * datapath previously had some routes. The datapath now no longer
     * contains any route.*/
    struct hmapx deleted_datapath_routes;
};

struct group_ecmp_route_data {
    /* Contains struct group_ecmp_route_node. */
    struct hmap datapaths;

    /* 'tracked' is set to true if there is information available for
     * incremental processing. If true then 'trk_data' is valid. */
    bool tracked;
    struct group_ecmp_route_tracked_data trk_data;
};

void *en_group_ecmp_route_init(struct engine_node *, struct engine_arg *);
void en_group_ecmp_route_cleanup(void *data);
void en_group_ecmp_route_clear_tracked_data(void *data);
void en_group_ecmp_route_run(struct engine_node *, void *data);

bool group_ecmp_route_learned_route_change_handler(struct engine_node *,
                                                   void *data);

struct group_ecmp_datapath *group_ecmp_datapath_lookup(
    const struct group_ecmp_route_data *data,
    const struct ovn_datapath *od);

#endif /* EN_GROUP_ECMP_ROUTE_H */
