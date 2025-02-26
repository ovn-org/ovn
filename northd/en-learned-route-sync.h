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
#ifndef EN_LEARNED_ROUTE_SYNC_H
#define EN_LEARNED_ROUTE_SYNC_H 1

#include "lib/inc-proc-eng.h"
#include "openvswitch/hmap.h"
#include "hmapx.h"

/* Track what's changed in the learned routes engine node.
 * For now only tracks changed learned routes. */
struct learned_routes_tracked_data {
    /* Tracked created routes based on sb_learned_routes.
     * hmapx node is 'struct parsed_route *'. */
    struct hmapx trk_created_parsed_route;

    /* Tracked deleted routes based on sb_learned_routes.
     * hmapx node is 'struct parsed_route *'. */
    struct hmapx trk_deleted_parsed_route;
};

struct learned_route_sync_data {
    struct hmap parsed_routes;

    /* 'tracked' is set to true if there is information available for
     * incremental processing. If true then trk_data is valid. */
    bool tracked;
    struct learned_routes_tracked_data trk_data;
};

bool learned_route_sync_northd_change_handler(struct engine_node *,
                                              void *data);
bool learned_route_sync_sb_learned_route_change_handler(struct engine_node *,
                                                        void *data);
void *en_learned_route_sync_init(struct engine_node *, struct engine_arg *);
void en_learned_route_sync_cleanup(void *data);
void en_learned_route_sync_clear_tracked_data(void *data);
void en_learned_route_sync_run(struct engine_node *, void *data);

#endif /* EN_LEARNED_ROUTE_SYNC_H */
