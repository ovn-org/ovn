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

#ifndef NEIGHBOR_H
#define NEIGHBOR_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdint.h>

#include "lib/sset.h"
#include "openvswitch/hmap.h"

#include "vec.h"

/* XXX: AF_BRIDGE doesn't seem to be defined on some systems, e.g., OSX. */
#ifndef AF_BRIDGE
#define AF_BRIDGE AF_UNSPEC
#endif

enum neighbor_family {
    NEIGH_AF_INET = AF_INET,
    NEIGH_AF_INET6 = AF_INET6,
    NEIGH_AF_BRIDGE = AF_BRIDGE,
};

struct neighbor_ctx_in {
    /* Contains 'struct local_datapath'. */
    const struct hmap *local_datapaths;
};

struct neighbor_ctx_out {
    /* Contains struct neighbor_interface_monitor pointers. */
    struct vector *monitored_interfaces;
};

enum neighbor_interface_type {
    NEIGH_IFACE_BRIDGE,
    NEIGH_IFACE_VXLAN,
    NEIGH_IFACE_LOOPBACK,
};

struct neighbor_interface_monitor {
    enum neighbor_family family;
    char if_name[IFNAMSIZ + 1];
    enum neighbor_interface_type type;
    uint32_t vni;

    /* Contains struct advertise_neighbor_entry - the entries that OVN
     * advertises on this interface. */
    struct hmap announced_neighbors;
};

struct advertise_neighbor_entry {
    struct hmap_node node;

    struct eth_addr lladdr;
    struct in6_addr addr;   /* In case of 'dst' entries non-zero;
                             * all zero otherwise. */
};

uint32_t advertise_neigh_hash(const struct eth_addr *,
                              const struct in6_addr *);
struct advertise_neighbor_entry *advertise_neigh_find(
    const struct hmap *neighbors, struct eth_addr mac,
    const struct in6_addr *ip);
void neighbor_run(struct neighbor_ctx_in *, struct neighbor_ctx_out *);
void neighbor_cleanup(struct vector *monitored_interfaces);

#endif /* NEIGHBOR_H */
