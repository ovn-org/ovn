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
#include "lib/packets.h"
#include "lib/smap.h"

VLOG_DEFINE_THIS_MODULE(mac_learn);

#define MAX_MAC_BINDINGS 1000
#define MAX_FDB_ENTRIES  1000

static size_t mac_binding_hash(uint32_t dp_key, uint32_t port_key,
                               struct in6_addr *);
static struct mac_binding *mac_binding_find(struct hmap *mac_bindings,
                                            uint32_t dp_key,
                                            uint32_t port_key,
                                            struct in6_addr *ip, size_t hash);
static size_t fdb_entry_hash(uint32_t dp_key, struct eth_addr *);

static struct fdb_entry *fdb_entry_find(struct hmap *fdbs, uint32_t dp_key,
                                        struct eth_addr *mac, size_t hash);

/* mac_binding functions. */
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

/* fdb functions. */
void
ovn_fdb_init(struct hmap *fdbs)
{
    hmap_init(fdbs);
}

void
ovn_fdbs_flush(struct hmap *fdbs)
{
    struct fdb_entry *fdb_e;
    HMAP_FOR_EACH_POP (fdb_e, hmap_node, fdbs) {
        free(fdb_e);
    }
}

void
ovn_fdbs_destroy(struct hmap *fdbs)
{
   ovn_fdbs_flush(fdbs);
   hmap_destroy(fdbs);
}

struct fdb_entry *
ovn_fdb_add(struct hmap *fdbs, uint32_t dp_key, struct eth_addr mac,
            uint32_t port_key)
{
    uint32_t hash = fdb_entry_hash(dp_key, &mac);

    struct fdb_entry *fdb_e =
        fdb_entry_find(fdbs, dp_key, &mac, hash);
    if (!fdb_e) {
        if (hmap_count(fdbs) >= MAX_FDB_ENTRIES) {
            return NULL;
        }

        fdb_e = xzalloc(sizeof *fdb_e);
        fdb_e->dp_key = dp_key;
        fdb_e->mac = mac;
        hmap_insert(fdbs, &fdb_e->hmap_node, hash);
    }
    fdb_e->port_key = port_key;

    return fdb_e;

}

/* mac_binding related static functions. */

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

/* fdb related static functions. */

static size_t
fdb_entry_hash(uint32_t dp_key, struct eth_addr *mac)
{
    uint64_t mac64 = eth_addr_to_uint64(*mac);
    return hash_2words(dp_key, hash_uint64(mac64));
}

static struct fdb_entry *
fdb_entry_find(struct hmap *fdbs, uint32_t dp_key,
               struct eth_addr *mac, size_t hash)
{
    struct fdb_entry *fdb_e;
    HMAP_FOR_EACH_WITH_HASH (fdb_e, hmap_node, hash, fdbs) {
        if (fdb_e->dp_key == dp_key && eth_addr_equals(fdb_e->mac, *mac)) {
            return fdb_e;
        }
    }

    return NULL;
}
