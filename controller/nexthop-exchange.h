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

#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "hash.h"
#include "openvswitch/hmap.h"
#include "util.h"

struct ds;
struct ofpbuf;
struct vector;

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
    /* Output interface, empty string if the nexthop does not have one.
     * Adding 1 to this to be sure we actually have a terminating '\0'. */
    char ifname[IFNAMSIZ + 1];
    /* True if the nexthop discards the traffic sent to it. */
    bool is_blackhole;
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

/* Member of a set of kernel nexthop object ids. */
struct nexthop_id_node {
    struct hmap_node hmap_node;
    uint32_t id;
};

/* Adds 'id' to the set 'ids' if it is not there yet. */
static inline void
nexthop_ids_add(struct hmap *ids, uint32_t id)
{
    uint32_t hash = hash_int(id, 0);

    struct nexthop_id_node *node;
    HMAP_FOR_EACH_WITH_HASH (node, hmap_node, hash, ids) {
        if (node->id == id) {
            return;
        }
    }

    node = xmalloc(sizeof *node);
    node->id = id;
    hmap_insert(ids, &node->hmap_node, hash);
}

static inline bool
nexthop_ids_contains(const struct hmap *ids, uint32_t id)
{
    const struct nexthop_id_node *node;
    HMAP_FOR_EACH_WITH_HASH (node, hmap_node, hash_int(id, 0), ids) {
        if (node->id == id) {
            return true;
        }
    }

    return false;
}

static inline void
nexthop_ids_clear(struct hmap *ids)
{
    struct nexthop_id_node *node;
    HMAP_FOR_EACH_POP (node, hmap_node, ids) {
        free(node);
    }
}

void nexthops_sync(struct hmap *nexthops);
void nexthop_entry_format(struct ds *ds, const struct nexthop_entry *nhe);
struct nexthop_entry *nexthop_entry_find(const struct hmap *nexthops,
                                         uint32_t id);
int nh_table_parse(struct ofpbuf *, struct nh_table_msg *change);
bool nexthops_handle_changes(struct hmap *nexthops, struct vector *msgs);
void nexthops_destroy(struct hmap *nexthops);

#endif /* NEXTHOP_EXCHANGE_H */
