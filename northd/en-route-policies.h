/*
 * Copyright (c) 2026, Red Hat, Inc.
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

#ifndef EN_ROUTE_POLICIES_H
#define EN_ROUTE_POLICIES_H

#include "inc-proc-eng.h"

#include "lib/simap.h"
#include "openvswitch/hmap.h"

/* Represents the data associated with an instance of a northbound
 * Logical Router Policy for a particular Logical Router.
 */
struct route_policy {
    struct hmap_node key_node;
    const struct nbrec_logical_router_policy *rule;
    size_t n_valid_nexthops;
    char **valid_nexthops;
    uint32_t chain_id;
    uint32_t jump_chain_id;
};

/* Global route policy data exported by en-route-policies. */
struct route_policies_data {
    struct hmap route_policies;
    struct hmap bfd_active_connections;
    struct simap chain_ids;
};

void en_route_policies_cleanup(void *data);
enum engine_input_handler_result
route_policies_northd_change_handler(struct engine_node *node,
                                     void *data OVS_UNUSED);
enum engine_input_handler_result
route_policies_datapath_synced_logical_router_handler(struct engine_node *node,
                                                      void *data OVS_UNUSED);
enum engine_node_state en_route_policies_run(struct engine_node *node,
                                             void *data);
void *en_route_policies_init(struct engine_node *node OVS_UNUSED,
                             struct engine_arg *arg OVS_UNUSED);

#endif /* EN_ROUTE_POLICIES_H */
