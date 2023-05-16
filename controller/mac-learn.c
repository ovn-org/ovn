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
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "lib/packets.h"
#include "lib/smap.h"
#include "lib/timeval.h"
#include "lport.h"
#include "ovn-sb-idl.h"

VLOG_DEFINE_THIS_MODULE(mac_learn);

#define MAX_FDB_ENTRIES             1000
#define MAX_BUFFERED_PACKETS        1000
#define BUFFER_QUEUE_DEPTH          4
#define BUFFERED_PACKETS_TIMEOUT_MS 10000
#define BUFFERED_PACKETS_LOOKUP_MS  100

static size_t keys_ip_hash(uint32_t dp_key, uint32_t port_key,
                           struct in6_addr *ip);
static struct mac_binding *mac_binding_find(const struct mac_bindings_map
                                            *mac_bindings, uint32_t dp_key,
                                            uint32_t port_key,
                                            struct in6_addr *ip, size_t hash);
static size_t fdb_entry_hash(uint32_t dp_key, struct eth_addr *);

static struct fdb_entry *fdb_entry_find(struct hmap *fdbs, uint32_t dp_key,
                                        struct eth_addr *mac, size_t hash);
static struct buffered_packets *
buffered_packets_find(struct buffered_packets_ctx *ctx, uint64_t dp_key,
                      uint64_t port_key, struct in6_addr *ip, uint32_t hash);
static void ovn_buffered_packets_remove(struct buffered_packets_ctx *ctx,
                                        struct buffered_packets *bp);
static void
buffered_packets_db_lookup(struct buffered_packets *bp,
                           struct ds *ip, struct eth_addr *mac,
                           struct ovsdb_idl_index *sbrec_pb_by_key,
                           struct ovsdb_idl_index *sbrec_dp_by_key,
                           struct ovsdb_idl_index *sbrec_pb_by_name,
                           struct ovsdb_idl_index *sbrec_mb_by_lport_ip);

/* mac_binding functions. */
void
ovn_mac_bindings_map_init(struct mac_bindings_map *mac_bindings,
                          size_t max_size)
{
    mac_bindings->max_size = max_size;
    hmap_init(&mac_bindings->map);
}

void
ovn_mac_bindings_map_destroy(struct mac_bindings_map *mac_bindings)
{
    struct mac_binding *mb;

    HMAP_FOR_EACH_POP (mb, hmap_node, &mac_bindings->map) {
        free(mb);
    }
    hmap_destroy(&mac_bindings->map);
}

struct mac_binding *
ovn_mac_binding_add(struct mac_bindings_map *mac_bindings, uint32_t dp_key,
                    uint32_t port_key, struct in6_addr *ip,
                    struct eth_addr mac, uint32_t timeout_ms)
{
    uint32_t hash = keys_ip_hash(dp_key, port_key, ip);

    struct mac_binding *mb =
        mac_binding_find(mac_bindings, dp_key, port_key, ip, hash);
    size_t max_size = mac_bindings->max_size;
    if (!mb) {
        if (max_size && hmap_count(&mac_bindings->map) >= max_size) {
            return NULL;
        }
        mb = xmalloc(sizeof *mb);
        mb->dp_key = dp_key;
        mb->port_key = port_key;
        mb->ip = *ip;
        mb->timeout_at_ms = time_msec() + timeout_ms;
        hmap_insert(&mac_bindings->map, &mb->hmap_node, hash);
    }
    mb->mac = mac;

    return mb;
}

/* This is called from ovn-controller main context */
void
ovn_mac_bindings_map_wait(struct mac_bindings_map *mac_bindings)
{
    if (hmap_is_empty(&mac_bindings->map)) {
        return;
    }

    struct mac_binding *mb;

    HMAP_FOR_EACH (mb, hmap_node, &mac_bindings->map) {
        poll_timer_wait_until(mb->timeout_at_ms);
    }
}

void
ovn_mac_binding_remove(struct mac_binding *mb,
                       struct mac_bindings_map *mac_bindings)
{
    hmap_remove(&mac_bindings->map, &mb->hmap_node);
    free(mb);
}

bool
ovn_mac_binding_timed_out(const struct mac_binding *mb, long long now)
{
    return now >= mb->timeout_at_ms;
}

const struct sbrec_mac_binding *
ovn_mac_binding_lookup(struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                       const char *logical_port, const char *ip)
{
    struct sbrec_mac_binding *mb =
        sbrec_mac_binding_index_init_row(sbrec_mac_binding_by_lport_ip);
    sbrec_mac_binding_index_set_logical_port(mb, logical_port);
    sbrec_mac_binding_index_set_ip(mb, ip);

    const struct sbrec_mac_binding *retval =
        sbrec_mac_binding_index_find(sbrec_mac_binding_by_lport_ip, mb);

    sbrec_mac_binding_index_destroy_row(mb);

    return retval;
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

/* packet buffering functions */

struct packet_data *
ovn_packet_data_create(struct ofpbuf ofpacts,
                       const struct dp_packet *original_packet)
{
    struct packet_data *pd = xmalloc(sizeof *pd);

    pd->ofpacts = ofpacts;
    /* clone the packet to send it later with correct L2 address */
    pd->p = dp_packet_clone_data(dp_packet_data(original_packet),
                                 dp_packet_size(original_packet));

    return pd;
}


void
ovn_packet_data_destroy(struct packet_data *pd)
{
    dp_packet_delete(pd->p);
    ofpbuf_uninit(&pd->ofpacts);
    free(pd);
}

struct buffered_packets *
ovn_buffered_packets_add(struct buffered_packets_ctx *ctx, uint64_t dp_key,
                         uint64_t port_key, struct in6_addr ip)
{
    struct buffered_packets *bp;

    uint32_t hash = keys_ip_hash(dp_key, port_key, &ip);

    bp = buffered_packets_find(ctx, dp_key, port_key, &ip, hash);
    if (!bp) {
        if (hmap_count(&ctx->buffered_packets) >= MAX_BUFFERED_PACKETS) {
            return NULL;
        }

        bp = xmalloc(sizeof *bp);
        hmap_insert(&ctx->buffered_packets, &bp->hmap_node, hash);
        bp->ip = ip;
        bp->dp_key = dp_key;
        bp->port_key = port_key;
        /* Schedule the freshly added buffered packet to do lookup
         * immediately. */
        bp->lookup_at_ms = 0;
        ovs_list_init(&bp->queue);
    }

    bp->expire_at_ms = time_msec() + BUFFERED_PACKETS_TIMEOUT_MS;

    return bp;
}

void
ovn_buffered_packets_packet_data_enqueue(struct buffered_packets *bp,
                                         struct packet_data *pd)
{
    if (ovs_list_size(&bp->queue) == BUFFER_QUEUE_DEPTH) {
        struct packet_data *p = CONTAINER_OF(ovs_list_pop_front(&bp->queue),
                                             struct packet_data, node);

        ovn_packet_data_destroy(p);
    }
    ovs_list_push_back(&bp->queue, &pd->node);
}

void
ovn_buffered_packets_ctx_run(struct buffered_packets_ctx *ctx,
                             const struct mac_bindings_map *recent_mbs,
                             struct ovsdb_idl_index *sbrec_pb_by_key,
                             struct ovsdb_idl_index *sbrec_dp_by_key,
                             struct ovsdb_idl_index *sbrec_pb_by_name,
                             struct ovsdb_idl_index *sbrec_mb_by_lport_ip)
{
    struct ds ip = DS_EMPTY_INITIALIZER;
    long long now = time_msec();

    struct buffered_packets *bp;

    HMAP_FOR_EACH_SAFE (bp, hmap_node, &ctx->buffered_packets) {
        struct eth_addr mac = eth_addr_zero;
        /* Remove expired buffered packets. */
        if (now > bp->expire_at_ms) {
            ovn_buffered_packets_remove(ctx, bp);
            continue;
        }

        uint32_t hash = keys_ip_hash(bp->dp_key, bp->port_key, &bp->ip);
        struct mac_binding *mb = mac_binding_find(recent_mbs, bp->dp_key,
                                                  bp->port_key, &bp->ip, hash);

        if (mb) {
            mac = mb->mac;
        } else if (now >= bp->lookup_at_ms) {
            /* Check if we can do a full lookup. */
            buffered_packets_db_lookup(bp, &ip, &mac, sbrec_pb_by_key,
                                       sbrec_dp_by_key, sbrec_pb_by_name,
                                       sbrec_mb_by_lport_ip);
            /* Schedule next lookup even if we found the MAC address,
             * if the address was found this struct will be deleted anyway. */
            bp->lookup_at_ms = now + BUFFERED_PACKETS_LOOKUP_MS;
        }

        if (eth_addr_is_zero(mac)) {
            continue;
        }

        struct packet_data *pd;
        LIST_FOR_EACH_POP (pd, node, &bp->queue) {
            struct eth_header *eth = dp_packet_data(pd->p);
            eth->eth_dst = mac;

            ovs_list_push_back(&ctx->ready_packets_data, &pd->node);
        }

        ovn_buffered_packets_remove(ctx, bp);
    }

    ds_destroy(&ip);
}

bool
ovn_buffered_packets_ctx_is_ready_to_send(struct buffered_packets_ctx *ctx)
{
    return !ovs_list_is_empty(&ctx->ready_packets_data);
}

bool
ovn_buffered_packets_ctx_has_packets(struct buffered_packets_ctx *ctx)
{
    return !hmap_is_empty(&ctx->buffered_packets);
}

void
ovn_buffered_packets_ctx_init(struct buffered_packets_ctx *ctx)
{
    hmap_init(&ctx->buffered_packets);
    ovs_list_init(&ctx->ready_packets_data);
}

void
ovn_buffered_packets_ctx_destroy(struct buffered_packets_ctx *ctx)
{
    struct packet_data *pd;
    LIST_FOR_EACH_POP (pd, node, &ctx->ready_packets_data) {
        ovn_packet_data_destroy(pd);
    }

    struct buffered_packets *bp;
    HMAP_FOR_EACH_SAFE (bp, hmap_node, &ctx->buffered_packets) {
        ovn_buffered_packets_remove(ctx, bp);
    }
    hmap_destroy(&ctx->buffered_packets);
}

/* mac_binding related static functions. */
static size_t
keys_ip_hash(uint32_t dp_key, uint32_t port_key, struct in6_addr *ip)
{
    return hash_bytes(ip, sizeof *ip, hash_2words(dp_key, port_key));
}

static struct mac_binding *
mac_binding_find(const struct mac_bindings_map *mac_bindings,
                 uint32_t dp_key, uint32_t port_key, struct in6_addr *ip,
                 size_t hash)
{
    struct mac_binding *mb;

    HMAP_FOR_EACH_WITH_HASH (mb, hmap_node, hash, &mac_bindings->map) {
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

/* packet buffering static functions. */
static struct buffered_packets *
buffered_packets_find(struct buffered_packets_ctx *ctx, uint64_t dp_key,
                      uint64_t port_key, struct in6_addr *ip, uint32_t hash)
{
    struct buffered_packets *mb;

    HMAP_FOR_EACH_WITH_HASH (mb, hmap_node, hash, &ctx->buffered_packets) {
        if (mb->dp_key == dp_key && mb->port_key == port_key &&
            IN6_ARE_ADDR_EQUAL(&mb->ip, ip)) {
            return mb;
        }
    }

    return NULL;
}

static void
ovn_buffered_packets_remove(struct buffered_packets_ctx *ctx,
                            struct buffered_packets *bp)
{
    struct packet_data *pd;

    LIST_FOR_EACH_POP (pd, node, &bp->queue) {
        ovn_packet_data_destroy(pd);
    }

    hmap_remove(&ctx->buffered_packets, &bp->hmap_node);
    free(bp);
}

static void
buffered_packets_db_lookup(struct buffered_packets *bp, struct ds *ip,
                           struct eth_addr *mac,
                           struct ovsdb_idl_index *sbrec_pb_by_key,
                           struct ovsdb_idl_index *sbrec_dp_by_key,
                           struct ovsdb_idl_index *sbrec_pb_by_name,
                           struct ovsdb_idl_index *sbrec_mb_by_lport_ip)
{
    const struct sbrec_port_binding *pb = lport_lookup_by_key(sbrec_dp_by_key,
                                                              sbrec_pb_by_key,
                                                              bp->dp_key,
                                                              bp->port_key);
    if (!pb) {
        return;
    }

    if (!strcmp(pb->type, "chassisredirect")) {
        const char *dgp_name =
            smap_get_def(&pb->options, "distributed-port", "");
        pb = lport_lookup_by_name(sbrec_pb_by_name, dgp_name);
        if (!pb) {
            return;
        }
    }

    ipv6_format_mapped(&bp->ip, ip);
    const struct sbrec_mac_binding *smb =
        ovn_mac_binding_lookup(sbrec_mb_by_lport_ip, pb->logical_port,
                               ds_cstr_ro(ip));
    ds_clear(ip);

    if (!smb) {
        return;
    }

    eth_addr_from_string(smb->mac, mac);
}
