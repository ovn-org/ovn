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

#ifndef EN_DP_GROUP_H
#define EN_DP_GROUP_H 1

#include "lib/inc-proc-eng.h"

void *en_dp_group_init(struct engine_node *node, struct engine_arg *arg);
enum engine_node_state en_dp_group_run(struct engine_node *node, void *data);
void en_dp_group_cleanup(void *data);
enum engine_input_handler_result
dp_group_lflow_handler(struct engine_node *node, void *data);

#endif /* EN_DP_GROUP_H */
