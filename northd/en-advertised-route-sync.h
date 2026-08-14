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
#ifndef EN_ADVERTISED_ROUTE_SYNC_H
#define EN_ADVERTISED_ROUTE_SYNC_H 1

#include "lib/inc-proc-eng.h"
#include "lib/uuidset.h"
#include "openvswitch/hmap.h"
#include "hmapx.h"

/* Track what changed in the dynamic_routes engine node's parsed_routes.
 * All hmapx node data are pointers to struct parsed_route. */
struct dynamic_routes_tracked_data {
    struct hmapx trk_created_parsed_routes;
    struct hmapx trk_deleted_parsed_routes;
};

struct dynamic_routes_data {
    /* Stores struct ar_entry, one for each dynamic route. Fed only to
     * en_advertised_route_sync (SB Advertised_Route table). */
    struct hmap routes;
    /* Stores struct parsed_route, one per VIP/NAT-external IP whose
     * advertisement was synthesized from a *connected-neighbour* LR (i.e.
     * dynamic-routing-redistribute=lb/nat for an LRP whose peer LS hosts
     * another LR that owns the LB/NAT). Without these the advertising LR
     * would claim reachability for a prefix it had no local forwarding
     * route to. Fed to en_group_ecmp_route alongside en_routes and
     * en_learned_route_sync. */
    struct hmap parsed_routes;
    /* Holds the previous parsed routes while parsed_routes is rebuilt.
     * Routes that remain here after the rebuild are owned by
     * trk_deleted_parsed_routes until its tracked data is cleared. */
    struct hmap old_parsed_routes;
    /* Contains the uuids of all NB Logical Routers where we used a
     * lr_stateful_record during computation. */
    struct uuidset nb_lr;
    /* Contains the uuids of all NB Logical Switches where we rely on port
     * changes for host routes. */
    struct uuidset nb_ls;

    /* 'tracked' is set to true if there is information available for
     * incremental processing. If true then trk_data is valid. */
    bool tracked;
    struct dynamic_routes_tracked_data trk_data;
};

void *en_advertised_route_sync_init(struct engine_node *, struct engine_arg *);
void en_advertised_route_sync_cleanup(void *data);
enum engine_node_state en_advertised_route_sync_run(struct engine_node *,
                                                    void *data);

void *en_dynamic_routes_init(struct engine_node *, struct engine_arg *);
void en_dynamic_routes_cleanup(void *data);
enum engine_node_state en_dynamic_routes_run(struct engine_node *, void *data);
enum engine_input_handler_result
dynamic_routes_northd_change_handler(struct engine_node *node, void *data_);
enum engine_input_handler_result
dynamic_routes_lr_stateful_change_handler(struct engine_node *node,
                                          void *data_);

void *en_advertised_mac_binding_sync_init(struct engine_node *,
                                          struct engine_arg *);
void en_advertised_mac_binding_sync_cleanup(void *data);
enum engine_node_state
en_advertised_mac_binding_sync_run(struct engine_node *, void *data);
enum engine_input_handler_result
northd_output_advertised_mac_binding_sync_handler(struct engine_node *,
                                                  void *data);
enum engine_input_handler_result
advertised_mac_binding_sync_northd_change_handler(struct engine_node *node,
                                                  void *data);
#endif /* EN_ADVERTISED_ROUTE_SYNC_H */
