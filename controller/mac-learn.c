/* Copyright (c) 2020, Red Hat, Inc.
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

#include "mac-learn.h"

/* OpenvSwitch lib includes. */
#include "openvswitch/vlog.h"
#include "lib/smap.h"

VLOG_DEFINE_THIS_MODULE(mac_learn);

#define MAX_MAC_BINDINGS 1000

static size_t mac_binding_hash(uint32_t dp_key, uint32_t port_key,
                               struct in6_addr *);
static struct mac_binding *mac_binding_find(struct hmap *mac_bindings,
                                            uint32_t dp_key,
                                            uint32_t port_key,
                                            struct in6_addr *ip, size_t hash);

void
ovn_mac_bindings_init(struct hmap *mac_bindings)
{
    hmap_init(mac_bindings);
}

void
ovn_mac_bindings_flush(struct hmap *mac_bindings)
{
    struct mac_binding *mb;
    HMAP_FOR_EACH_POP (mb, hmap_node, mac_bindings) {
        free(mb);
    }
}

void
ovn_mac_bindings_destroy(struct hmap *mac_bindings)
{
    ovn_mac_bindings_flush(mac_bindings);
    hmap_destroy(mac_bindings);
}

struct mac_binding *
ovn_mac_binding_add(struct hmap *mac_bindings, uint32_t dp_key,
                    uint32_t port_key, struct in6_addr *ip,
                    struct eth_addr mac)
{
    uint32_t hash = mac_binding_hash(dp_key, port_key, ip);

    struct mac_binding *mb =
        mac_binding_find(mac_bindings, dp_key, port_key, ip, hash);
    if (!mb) {
        if (hmap_count(mac_bindings) >= MAX_MAC_BINDINGS) {
            return NULL;
        }

        mb = xmalloc(sizeof *mb);
        mb->dp_key = dp_key;
        mb->port_key = port_key;
        mb->ip = *ip;
        hmap_insert(mac_bindings, &mb->hmap_node, hash);
    }
    mb->mac = mac;

    return mb;
}

static size_t
mac_binding_hash(uint32_t dp_key, uint32_t port_key, struct in6_addr *ip)
{
    return hash_bytes(ip, sizeof *ip, hash_2words(dp_key, port_key));
}

static struct mac_binding *
mac_binding_find(struct hmap *mac_bindings, uint32_t dp_key,
                   uint32_t port_key, struct in6_addr *ip, size_t hash)
{
    struct mac_binding *mb;
    HMAP_FOR_EACH_WITH_HASH (mb, hmap_node, hash, mac_bindings) {
        if (mb->dp_key == dp_key && mb->port_key == port_key &&
            IN6_ARE_ADDR_EQUAL(&mb->ip, ip)) {
            return mb;
        }
    }

    return NULL;
}
