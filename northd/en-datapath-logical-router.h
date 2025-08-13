/*
 * Copyright (c) 2025, Red Hat, Inc.
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

#ifndef EN_DATAPATH_LOGICAL_ROUTER_H
#define EN_DATAPATH_LOGICAL_ROUTER_H

#include "lib/inc-proc-eng.h"
#include "openvswitch/hmap.h"

void *en_datapath_logical_router_init(struct engine_node *,
                                      struct engine_arg *);

enum engine_node_state en_datapath_logical_router_run(struct engine_node *,
                                                      void *data);
void en_datapath_logical_router_clear_tracked_data(void *data);
void en_datapath_logical_router_cleanup(void *data);

struct ovn_synced_logical_router {
    struct hmap_node hmap_node;
    const struct nbrec_logical_router *nb;
    const struct sbrec_datapath_binding *sb;
};

struct ovn_synced_logical_router_map {
    struct hmap synced_routers;
};

void *en_datapath_synced_logical_router_init(struct engine_node *,
                                             struct engine_arg *);

enum engine_node_state en_datapath_synced_logical_router_run(
    struct engine_node *, void *data);

void en_datapath_synced_logical_router_cleanup(void *data);

enum engine_input_handler_result
en_datapath_logical_router_logical_router_handler(struct engine_node *,
                                                  void *);

#endif /* EN_DATAPATH_LOGICAL_ROUTER_H */
