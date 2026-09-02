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

#ifndef ROUTE_EXCHANGE_H
#define ROUTE_EXCHANGE_H 1

#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>

#include "openvswitch/hmap.h"
#include "util.h"

/* One of the next hops of a route as reported by the kernel. */
struct ovn_route_nexthop {
    struct in6_addr addr;
    /* Adding 1 to this to be sure we actually have a terminating '\0' */
    char ifname[IFNAMSIZ + 1];
};

/* A digested version of a route message sent down by the kernel to indicate
 * that a route has changed.  Unlike 'struct route_data', which points into
 * itself to describe the next hops, this is self contained, so it stays valid
 * after the message it was built from is gone. */
struct ovn_route_msg {
    /* E.g. RTM_NEWROUTE, RTM_DELROUTE. */
    uint16_t nlmsg_type;
    /* Routing table the route belongs to. */
    uint32_t table_id;
    /* Prefix the route is for. */
    struct in6_addr prefix;
    unsigned int plen;
    /* Routing protocol that installed the route, e.g. RTPROT_BGP. */
    unsigned char protocol;
    /* Metric of the route.  The kernel allows several routes for one prefix
     * that differ only by this, so it is part of a route's identity. */
    uint32_t priority;
    /* Number of next hops described by the route itself. */
    size_t n_nexthops;
    struct ovn_route_nexthop nexthops[];
};

static inline size_t
ovn_route_msg_size(const struct ovn_route_msg *msg)
{
    return sizeof *msg + msg->n_nexthops * sizeof msg->nexthops[0];
}

static inline struct ovn_route_msg *
ovn_route_msg_clone(const struct ovn_route_msg *msg)
{
    return xmemdup(msg, ovn_route_msg_size(msg));
}

struct route_exchange_ctx_in {
    struct ovsdb_idl_txn *ovnsb_idl_txn;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    struct ovsdb_idl_index *sbrec_learned_route_by_datapath;
    const struct sbrec_chassis *chassis;

    /* Contains struct advertise_datapath_entry */
    const struct hmap *announce_routes;
};

struct route_exchange_ctx_out {
    struct vector *route_table_watches;
    bool sb_changes_pending;
};

void route_exchange_run(const struct route_exchange_ctx_in *,
                        struct route_exchange_ctx_out *);
void route_exchange_cleanup_vrfs(void);
void route_exchange_destroy(void);

int route_exchange_status_run(void);

#endif /* ROUTE_EXCHANGE_H */
