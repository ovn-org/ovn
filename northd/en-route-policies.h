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

#include <netinet/in.h>
#include <arpa/inet.h>

#include "inc-proc-eng.h"

#include "lib/simap.h"
#include "openvswitch/hmap.h"
#include "vec.h"
#include "uuidset.h"
#include "sparse-array.h"

/* Each instance of this represents a nexthop for a router
 * policy with "reroute" action. The fields are used for
 * building the associated logical flows later.
 */
struct route_policy_nexthop {
    const char *nexthop_addr;
    char src_addr[INET6_ADDRSTRLEN];
    const char *outport_key;
};

/* Represents the data associated with an instance of a northbound
 * Logical Router Policy for a particular Logical Router.
 */
struct route_policy {
    struct hmap_node key_node;
    const struct nbrec_logical_router_policy *rule;
    struct vector valid_nexthops; /* struct route_policy_nexthop */
    uint32_t chain_id;
    uint32_t jump_chain_id;
    /* If the policy is ECMP, then this is the group ID for the policy.
     * If the policy is not ECMP, then this is 0.
     */
    uint32_t ecmp_group_id;
};

struct datapath_route_policies {
    struct simap chain_ids;
    struct hmap route_policies;
    struct hmap ecmp_group_ids;
    uint32_t dp_index;
    struct lflow_ref *lflow_ref;
};

struct datapath_bfd_active_connections {
    struct uuidset active_connections;
};

/* Global route policy data exported by en-route-policies. */
struct route_policies_data {
    /* Each entry is a struct datapath_route_policies pointer */
    struct sparse_array dp_route_policies;
    struct sparse_array dp_bfd_active_connections;
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
