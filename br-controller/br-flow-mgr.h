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

#ifndef BR_FLOW_MGR_H
#define BR_FLOW_MGR_H 1

#include <stdio.h>

/* OVS includes. */
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"

/* OVN includes. */

struct match;
struct ofpbuf;
struct uuid;

#define DP_FLOW_TABLE_GLOBAL_KEY 0

void br_flow_tables_init(void);
void br_flow_tables_destroy(void);

struct br_flow_table *br_flow_table_alloc(const char *bridge);
struct br_flow_table *br_flow_table_get(const char *bridge);
void br_flow_table_destroy(const char *bridge);

void br_flow_switch_logical_oflow_tables(void);
void br_flow_switch_logical_oflow_table(const char *bridge);
void br_flow_switch_physical_oflow_tables(void);
void br_flow_switch_physical_oflow_table(const char *bridge);

void br_flow_add_logical_oflow(const char *bridge, uint8_t table_id,
                               uint16_t priority, uint64_t cookie,
                               const struct match *match,
                               const struct ofpbuf *actions,
                               const struct uuid *flow_uuid);
void br_flow_add_physical_oflow(const char *bridge, uint8_t table_id,
                                uint16_t priority, uint64_t cookie,
                                const struct match *match,
                                const struct ofpbuf *actions,
                                const struct uuid *flow_uuid);

void br_flow_remove_logical_oflows_all(const struct uuid *flow_uuid);
void br_flow_remove_logical_oflows(const char *bridge,
                                   const struct uuid *flow_uuid);
void br_flow_remove_physical_oflows(const char *bridge,
                                    const struct uuid *flow_uuid);
void br_flow_flush_oflows(const char *bridge);
void br_flow_flush_all_oflows(void);

void br_flow_populate_oflow_msgs(const char *bridge, struct ovs_list *msgs);

#endif /* BR_FLOW_MGR_H */
