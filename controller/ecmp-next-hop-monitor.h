/* Copyright (c) 2025, Red Hat, Inc.
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

#ifndef OVN_ECMP_NEXT_HOP_MONITOR_H
#define OVN_ECMP_NEXT_HOP_MONITOR_H

void ecmp_nexthop_init(void);
void ecmp_nexthop_destroy(void);
bool ecmp_nexthop_monitor_run(const struct sbrec_ecmp_nexthop_table *,
                              const struct hmap *local_datapaths,
                              const struct shash *current_ct_zones,
                              const struct rconn *swconn,
                              struct ovs_list *msgs);
#endif /* OVN_ECMP_NEXT_HOP_MONITOR_H */
