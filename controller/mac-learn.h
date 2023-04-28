/*
 * Copyright (c) 2020 Red Hat, Inc.
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

#ifndef OVN_MAC_LEARN_H
#define OVN_MAC_LEARN_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include "openvswitch/hmap.h"

struct mac_binding {
    struct hmap_node hmap_node; /* In a hmap. */

    /* Key. */
    uint32_t dp_key;
    uint32_t port_key; /* Port from where this mac_binding is learnt. */
    struct in6_addr ip;

    /* Value. */
    struct eth_addr mac;

    /* Absolute time (in ms) when a user specific timeout expires for
     * this entry. */
    long long timeout_at_ms;
};

struct mac_bindings_map {
    struct hmap map;
    /* Maximum capacity of the associated map. "0" means unlimited. */
    size_t max_size;
};

void ovn_mac_bindings_map_init(struct mac_bindings_map *mac_bindings,
                               size_t max_size);
void ovn_mac_bindings_map_destroy(struct mac_bindings_map *mac_bindings);
void ovn_mac_bindings_map_wait(struct mac_bindings_map *mac_bindings);
void ovn_mac_binding_remove(struct mac_binding *mb,
                            struct mac_bindings_map *mac_bindings);
bool ovn_mac_binding_timed_out(const struct mac_binding *mb,
                               long long now);

struct mac_binding *ovn_mac_binding_add(struct mac_bindings_map *mac_bindings,
                                        uint32_t dp_key, uint32_t port_key,
                                        struct in6_addr *ip,
                                        struct eth_addr mac,
                                        uint32_t timeout_ms);
size_t keys_ip_hash(uint32_t dp_key, uint32_t port_key, struct in6_addr *ip);
struct mac_binding *
ovn_mac_binding_find(const struct mac_bindings_map *mac_bindings,
                     uint32_t dp_key, uint32_t port_key, struct in6_addr *ip,
                     size_t hash);


struct fdb_entry {
    struct hmap_node hmap_node; /* In a hmap. */

    /* Key. */
    uint32_t dp_key;
    struct eth_addr mac;

    /* value. */
    uint32_t port_key;
};

void ovn_fdb_init(struct hmap *fdbs);
void ovn_fdbs_flush(struct hmap *fdbs);
void ovn_fdbs_destroy(struct hmap *fdbs);

struct fdb_entry *ovn_fdb_add(struct hmap *fdbs,
                                uint32_t dp_key, struct eth_addr mac,
                                uint32_t port_key);

#endif /* OVN_MAC_LEARN_H */
