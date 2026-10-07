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

#ifndef EN_IC_PORT_BINDING_H
#define EN_IC_PORT_BINDING_H 1

#include "lib/inc-proc-eng.h"

enum engine_node_state en_port_binding_run(struct engine_node *node,
                                           void *data);
void *en_port_binding_init(struct engine_node *node, struct engine_arg *arg);
void en_port_binding_clear_tracked_data(void *data);
void en_port_binding_cleanup(void *data);

enum engine_input_handler_result
port_binding_icnb_transit_switch_handler(struct engine_node *node, void *data);
enum engine_input_handler_result
port_binding_icnb_transit_router_handler(struct engine_node *node, void *data);
enum engine_input_handler_result
port_binding_icnb_transit_router_port_handler(struct engine_node *node,
                                              void *data);
enum engine_input_handler_result
port_binding_icnb_transit_switch_port_handler(struct engine_node *node,
                                              void *data);
enum engine_input_handler_result
port_binding_icsb_port_binding_handler(struct engine_node *node, void *data);
enum engine_input_handler_result
port_binding_nb_logical_switch_handler(struct engine_node *node, void *data);
enum engine_input_handler_result
port_binding_nb_logical_switch_port_handler(struct engine_node *node,
                                            void *data);
enum engine_input_handler_result
port_binding_nb_logical_router_handler(struct engine_node *node, void *data);
enum engine_input_handler_result
port_binding_nb_logical_router_port_handler(struct engine_node *node,
                                            void *data);
enum engine_input_handler_result
port_binding_sb_port_binding_handler(struct engine_node *node, void *data);
enum engine_input_handler_result
port_binding_sb_chassis_handler(struct engine_node *node, void *data);

#endif /* EN_IC_PORT_BINDING_H */
