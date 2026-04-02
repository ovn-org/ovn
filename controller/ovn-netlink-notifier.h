/* Copyright (c) 2026, Red Hat, Inc.
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

#ifndef OVN_NETLINK_NOTIFIER_H
#define OVN_NETLINK_NOTIFIER_H 1

#include <stdbool.h>

struct vector;

enum ovn_netlink_notifier_type {
    OVN_NL_NOTIFIER_ROUTE_V4,
    OVN_NL_NOTIFIER_ROUTE_V6,
    OVN_NL_NOTIFIER_NEIGHBOR,
    OVN_NL_NOTIFIER_NEXTHOP,
    OVN_NL_NOTIFIER_MAX,
};

void ovn_netlink_update_notifier(enum ovn_netlink_notifier_type type,
                                 bool enabled);
struct vector *ovn_netlink_get_msgs(enum ovn_netlink_notifier_type type);
void ovn_netlink_notifier_flush(enum ovn_netlink_notifier_type type);
void ovn_netlink_notifiers_run(void);
void ovn_netlink_notifiers_wait(void);
void ovn_netlink_notifiers_destroy(void);

#endif /* OVN_NETLINK_NOTIFIER_H */
