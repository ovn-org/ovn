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

#include "dp-packet.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/ofpbuf.h"

struct ovsdb_idl_index;

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
const struct sbrec_mac_binding *
ovn_mac_binding_lookup(struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                       const char *logical_port, const char *ip);


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


struct packet_data {
    struct ovs_list node;

    struct ofpbuf ofpacts;
    struct dp_packet *p;
};

struct buffered_packets {
    struct hmap_node hmap_node;

    struct in6_addr ip;
    uint64_t dp_key;
    uint64_t port_key;

    /* Queue of packet_data associated with this struct. */
    struct ovs_list queue;

    /* Timestamp in ms when the buffered packet should expire. */
    long long int expire_at_ms;

    /* Timestamp in ms when the buffered packet should do full SB lookup.*/
    long long int lookup_at_ms;
};

struct buffered_packets_ctx {
    /* Map of all buffered packets waiting for the MAC address. */
    struct hmap buffered_packets;
    /* List of packet data that are ready to be sent. */
    struct ovs_list ready_packets_data;
};

struct packet_data *
ovn_packet_data_create(struct ofpbuf ofpacts,
                       const struct dp_packet *original_packet);
void ovn_packet_data_destroy(struct packet_data *pd);
struct buffered_packets *
ovn_buffered_packets_add(struct buffered_packets_ctx *ctx, uint64_t dp_key,
                         uint64_t port_key, struct in6_addr ip);
void ovn_buffered_packets_packet_data_enqueue(struct buffered_packets *bp,
                                              struct packet_data *pd);
void
ovn_buffered_packets_ctx_run(struct buffered_packets_ctx *ctx,
                             const struct mac_bindings_map *recent_mbs,
                             struct ovsdb_idl_index *sbrec_pb_by_key,
                             struct ovsdb_idl_index *sbrec_dp_by_key,
                             struct ovsdb_idl_index *sbrec_pb_by_name,
                             struct ovsdb_idl_index *sbrec_mb_by_lport_ip);
void ovn_buffered_packets_ctx_init(struct buffered_packets_ctx *ctx);
void ovn_buffered_packets_ctx_destroy(struct buffered_packets_ctx *ctx);
bool
ovn_buffered_packets_ctx_is_ready_to_send(struct buffered_packets_ctx *ctx);
bool ovn_buffered_packets_ctx_has_packets(struct buffered_packets_ctx *ctx);

#endif /* OVN_MAC_LEARN_H */
