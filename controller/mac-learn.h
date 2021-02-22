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
};

void ovn_mac_bindings_init(struct hmap *mac_bindings);
void ovn_mac_bindings_flush(struct hmap *mac_bindings);
void ovn_mac_bindings_destroy(struct hmap *mac_bindings);

struct mac_binding *ovn_mac_binding_add(struct hmap *mac_bindings,
                                        uint32_t dp_key, uint32_t port_key,
                                        struct in6_addr *ip,
                                        struct eth_addr mac);



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
