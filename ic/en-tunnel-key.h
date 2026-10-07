/*
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

#ifndef EN_IC_TUNNEL_KEY_H
#define EN_IC_TUNNEL_KEY_H 1

#include "lib/inc-proc-eng.h"
#include "openvswitch/hmap.h"

/* Data maintained by the "tunnel_key" engine node: the set of datapath tunnel
 * keys currently in use by IC-SB Datapath_Bindings.  This node is the single
 * owner of datapath tunnel-key allocation: it runs after en_ts and en_tr
 * (which only maintain the AZ NB Logical_Switch/Router mirrors) and
 * reconciles every transit switch/router's IC-SB Datapath_Binding, allocating
 * a globally unique tunnel key for each new one.  Concentrating allocation in
 * one node keeps the keys unique across both datapath types without any node
 * mutating another node's data. */
struct ed_type_tunnel_key {
    /* Set of tunnel keys already in use by IC-SB Datapath_Bindings.  Holds
     * 'struct tnlid_node *' entries owned by this node. */
    struct hmap dp_tnlids;
};

enum engine_node_state en_tunnel_key_run(struct engine_node *node, void *data);
void *en_tunnel_key_init(struct engine_node *node, struct engine_arg *arg);
void en_tunnel_key_cleanup(void *data);

/* Scoped incremental handlers: create/refresh/GC the IC-SB Datapath_Binding of
 * only the transit switches/routers whose IC-NB row or IC-SB binding changed,
 * without a full recompute. */
enum engine_input_handler_result
en_tunnel_key_icnb_transit_switch_handler(struct engine_node *node,
                                          void *data);
enum engine_input_handler_result
en_tunnel_key_icnb_transit_router_handler(struct engine_node *node,
                                          void *data);
enum engine_input_handler_result
en_tunnel_key_icsb_datapath_binding_handler(struct engine_node *node,
                                            void *data);

/* Shared change handler for the IC-NB Global input of nodes that only care
 * about its 'options' (e.g. vxlan_mode), not the nb_ic_cfg/sb_ic_cfg
 * sequence numbers that the sequence-number protocol bumps on every change.
 * Named without a node prefix because it is shared by en_tunnel_key and
 * en_ts. */
enum engine_input_handler_result
ic_nb_global_options_handler(struct engine_node *node, void *data);

#endif /* EN_IC_TUNNEL_KEY_H */
