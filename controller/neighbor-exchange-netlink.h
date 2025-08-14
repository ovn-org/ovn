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

#ifndef NEIGHBOR_EXCHANGE_NETLINK_H
#define NEIGHBOR_EXCHANGE_NETLINK_H 1

#include <netinet/in.h>
#include <stdint.h>

#include "openvswitch/hmap.h"
#include "openvswitch/ofpbuf.h"

#include "vec.h"

struct ne_nl_received_neigh {
    int32_t if_index;
    uint8_t  family;        /* AF_INET/AF_INET6/AF_BRIDGE. */

    struct eth_addr lladdr; /* Interface index where the neigh is learnt on. */
    struct in6_addr addr;   /* In case of 'dst' entries non-zero;
                             * all zero otherwise. */
    uint16_t vlan;          /* Parsed from NDA_VLAN. */
    uint16_t port;          /* UDP port, e.g., for VXLAN,
                             * parsed from NDA_PORT. */
    uint16_t state;         /* A value out of NUD_*,
                             * from linux/neighbour.h. */
    uint8_t  flags;         /* A combination of NTF_* flags,
                             * from linux/neighbour.h. */
    uint8_t  type;          /* A value out of 'rtm_type' from linux/rtnetlink.h
                             * e.g., RTN_UNICAST, RTN_MULTICAST. */
};

/* A digested version of a neigh message sent down by the kernel to indicate
 * that a neigh entry has changed. */
struct ne_table_msg {
    uint16_t nlmsg_type;            /* E.g. RTM_NEWNEIGH, RTM_DELNEIGH. */
    struct ne_nl_received_neigh nd; /* Data parsed from this message. */
};

int ne_nl_sync_neigh(uint8_t family, int32_t if_index,
                     const struct hmap *neighbors,
                     struct vector *learned_neighbors);

bool ne_is_ovn_owned(const struct ne_nl_received_neigh *nd);

int ne_table_parse(struct ofpbuf *, void *change);

#endif /* NEIGHBOR_EXCHANGE_NETLINK_H */
