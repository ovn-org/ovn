/*
 * Copyright (c) 2025 Canonical, Ltd.
 * Copyright (c) 2025, STACKIT GmbH & Co. KG
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

#ifndef ROUTE_EXCHANGE_NETLINK_H
#define ROUTE_EXCHANGE_NETLINK_H 1

#include <stdint.h>
#include <netinet/in.h>
#include <net/if.h>

/* The following definition should be available in Linux 6.15 and might be
 * missing if we have older headers. */
#ifndef RTPROT_OVN
#define RTPROT_OVN 84
#endif

struct in6_addr;
struct hmap;
struct vector;

struct re_nl_received_route_node {
    const struct sbrec_datapath_binding *db;
    struct in6_addr prefix;
    unsigned int plen;
    struct in6_addr nexthop;
    /* Adding 1 to this to be sure we actually have a terminating '\0' */
    char ifname[IFNAMSIZ + 1];
};

int re_nl_create_vrf(const char *ifname, uint32_t table_id);
int re_nl_delete_vrf(const char *ifname);

int re_nl_add_route(uint32_t table_id, const struct in6_addr *dst,
                    unsigned int plen, unsigned int priority);
int re_nl_delete_route(uint32_t table_id, const struct in6_addr *dst,
                       unsigned int plen, unsigned int priority);

int re_nl_sync_routes(uint32_t table_id, const struct hmap *routes,
                      struct vector *learned_routes,
                      const struct sbrec_datapath_binding *db);

int re_nl_cleanup_routes(uint32_t table_id);

#endif /* route-exchange-netlink.h */
