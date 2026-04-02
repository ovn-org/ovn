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

#ifndef NEXTHOP_EXCHANGE_H
#define NEXTHOP_EXCHANGE_H 1

#include <netinet/in.h>
#include <stdint.h>

#include "openvswitch/hmap.h"

struct ds;
struct ofpbuf;

struct nexthop_grp_entry {
    /* The id of the nexthop gateway. */
    uint32_t id;
    /* The weight of the entry. */
    uint16_t weight;
    /* The pointer to the gateway entry. */
    struct nexthop_entry *gateway;
};

struct nexthop_entry {
    struct hmap_node hmap_node;
    /* The id of the nexthop. */
    uint32_t id;
    /* Nexthop IP address, zeroed in case of group entry. */
    struct in6_addr addr;
    /* Number of group entries, "0" in case of gateway entry. */
    size_t n_grps;
    /* Array of group entries. */
    struct nexthop_grp_entry grps[];
};

/* A digested version of a nexthop message sent down by the kernel to indicate
 * that a nexthop entry has changed. */
struct nh_table_msg {
    /* E.g. RTM_NEWNEXTHOP, RTM_DELNEXTHOP. */
    uint16_t nlmsg_type;
    /* The inner entry. */
    struct nexthop_entry *nhe;
};

void nexthops_sync(struct hmap *nexthops);
void nexthop_entry_format(struct ds *ds, const struct nexthop_entry *nhe);
int nh_table_parse(struct ofpbuf *, struct nh_table_msg *change);

#endif /* NEXTHOP_EXCHANGE_H */
