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

#include <config.h>

#include "lib/hash.h"
#include "lib/packets.h"
#include "lib/sset.h"

#include "neighbor.h"

static void neighbor_interface_monitor_destroy(
    struct neighbor_interface_monitor *);

uint32_t
advertise_neigh_hash(const struct eth_addr *eth, const struct in6_addr *ip)
{
    return hash_bytes(ip, sizeof *ip, hash_bytes(eth, sizeof *eth, 0));
}

struct advertise_neighbor_entry *
advertise_neigh_find(const struct hmap *neighbors, struct eth_addr mac,
                     const struct in6_addr *ip)
{
    uint32_t hash = advertise_neigh_hash(&mac, ip);

    struct advertise_neighbor_entry *ne;
    HMAP_FOR_EACH_WITH_HASH (ne, node, hash, neighbors) {
        if (eth_addr_equals(ne->lladdr, mac) &&
            ipv6_addr_equals(&ne->addr, ip)) {
            return ne;
        }
    }

    return NULL;
}

void
neighbor_run(struct neighbor_ctx_in *n_ctx_in OVS_UNUSED,
             struct neighbor_ctx_out *n_ctx_out OVS_UNUSED)
{
    /* XXX: Not implemented yet. */
}

void
neighbor_cleanup(struct vector *monitored_interfaces)
{
    struct neighbor_interface_monitor *nim;
    VECTOR_FOR_EACH (monitored_interfaces, nim) {
        neighbor_interface_monitor_destroy(nim);
    }
    vector_clear(monitored_interfaces);
}

static void
neighbor_interface_monitor_destroy(struct neighbor_interface_monitor *nim)
{
    struct advertise_neighbor_entry *an;

    HMAP_FOR_EACH_POP (an, node, &nim->announced_neighbors) {
        free(an);
    }
    hmap_destroy(&nim->announced_neighbors);
    free(nim);
}
