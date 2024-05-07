/* Copyright (c) 2023, Red Hat, Inc.
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

#ifndef OVN_MAC_CACHE_H
#define OVN_MAC_CACHE_H

#include <stdint.h>

#include "dp-packet.h"
#include "openvswitch/hmap.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-packet.h"
#include "ovn-sb-idl.h"

struct ovsdb_idl_index;

struct mac_cache_data {
    /* 'struct mac_cache_threshold' by datapath's tunnel_key. */
    struct hmap thresholds;
    /* 'struct mac_cache_mac_binding' by 'struct mac_cache_mb_data' that are
     * local and have threshold > 0. */
    struct hmap mac_bindings;
    /* 'struct mac_cache_fdb' by 'struct mac_cache_fdb_data' that are
     * local and have threshold > 0. */
    struct hmap fdbs;
};

struct mac_cache_threshold {
    struct hmap_node hmap_node;
    /* Datapath tunnel key. */
    uint32_t dp_key;
    /* Aging threshold in ms. */
    uint64_t value;
    /* Statistics dump period. */
    uint64_t dump_period;
};

struct mac_binding_data {
    /* Keys. */
    uint32_t port_key;
    uint32_t dp_key;
    struct in6_addr ip;
    /* Value. */
    struct eth_addr mac;
};

struct mac_binding {
    struct hmap_node hmap_node;
    /* Common data to identify MAC binding. */
    struct mac_binding_data data;
    /* Reference to the SB MAC binding record (Might be NULL). */
    const struct sbrec_mac_binding *sbrec_mb;
    /* User specified timestamp (in ms) */
    long long timestamp;
};

struct fdb_data {
    /* Keys. */
    uint32_t dp_key;
    struct eth_addr mac;
    /* Value. */
    uint32_t port_key;
};

struct fdb {
    struct hmap_node hmap_node;
    /* Common data to identify FDB. */
    struct fdb_data data;
    /* Reference to the SB FDB record. */
    const struct sbrec_fdb *sbrec_fdb;
};

struct bp_packet_data {
    struct ovs_list node;

    struct ofpbuf *continuation;
    struct ofputil_packet_in pin;
};

struct buffered_packets {
    struct hmap_node hmap_node;

    struct mac_binding_data mb_data;

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

/* Thresholds. */
void mac_cache_threshold_add(struct mac_cache_data *data,
                             const struct sbrec_datapath_binding *dp);
void mac_cache_threshold_replace(struct mac_cache_data *data,
                                 const struct sbrec_datapath_binding *dp,
                                 const struct hmap *local_datapaths);
struct mac_cache_threshold *
mac_cache_threshold_find(struct mac_cache_data *data, uint32_t dp_key);
void mac_cache_thresholds_sync(struct mac_cache_data *data,
                               const struct hmap *local_datapaths);
void mac_cache_thresholds_clear(struct mac_cache_data *data);

/* MAC binding. */
struct mac_binding *mac_binding_add(struct hmap *map,
                                    struct mac_binding_data mb_data,
                                    long long timestamp);

void mac_binding_remove(struct hmap *map, struct mac_binding *mb);

struct mac_binding *mac_binding_find(const struct hmap *map,
                                     const struct mac_binding_data *mb_data);

bool mac_binding_data_from_sbrec(struct mac_binding_data *data,
                                 const struct sbrec_mac_binding *mb,
                                 struct ovsdb_idl_index *sbrec_pb_by_name);

void mac_bindings_clear(struct hmap *map);

bool sb_mac_binding_updated(const struct sbrec_mac_binding *mb);

const struct sbrec_mac_binding *
mac_binding_lookup(struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                   const char *logical_port, const char *ip);

/* FDB. */
struct fdb *fdb_add(struct hmap *map, struct fdb_data fdb_data);

void fdb_remove(struct hmap *map, struct fdb *fdb);

bool fdb_data_from_sbrec(struct fdb_data *data, const struct sbrec_fdb *fdb);

struct fdb *fdb_find(const struct hmap *map, const struct fdb_data *fdb_data);

bool sb_fdb_updated(const struct sbrec_fdb *fdb);

void fdbs_clear(struct hmap *map);

/* MAC binding stat processing. */
void
mac_binding_stats_process_flow_stats(struct ovs_list *stats_list,
                                     struct ofputil_flow_stats *ofp_stats);

void mac_binding_stats_run(struct ovs_list *stats_list, uint64_t *req_delay,
                           void *data);

/* FDB stat processing. */
void fdb_stats_process_flow_stats(struct ovs_list *stats_list,
                                  struct ofputil_flow_stats *ofp_stats);

void fdb_stats_run(struct ovs_list *stats_list, uint64_t *req_delay,
                   void *data);

void mac_cache_stats_destroy(struct ovs_list *stats_list);

/* Packet buffering. */
struct bp_packet_data *
bp_packet_data_create(const struct ofputil_packet_in *pin,
                      const struct ofpbuf *continuation);

void bp_packet_data_destroy(struct bp_packet_data *pd);

struct buffered_packets *
buffered_packets_add(struct buffered_packets_ctx *ctx,
                     struct mac_binding_data mb_data);

void buffered_packets_packet_data_enqueue(struct buffered_packets *bp,
                                          struct bp_packet_data *pd);

void buffered_packets_ctx_run(struct buffered_packets_ctx *ctx,
                              const struct hmap *recent_mbs,
                              struct ovsdb_idl_index *sbrec_pb_by_key,
                              struct ovsdb_idl_index *sbrec_dp_by_key,
                              struct ovsdb_idl_index *sbrec_pb_by_name,
                              struct ovsdb_idl_index *sbrec_mb_by_lport_ip);

void buffered_packets_ctx_init(struct buffered_packets_ctx *ctx);

void buffered_packets_ctx_destroy(struct buffered_packets_ctx *ctx);

bool buffered_packets_ctx_is_ready_to_send(struct buffered_packets_ctx *ctx);

bool buffered_packets_ctx_has_packets(struct buffered_packets_ctx *ctx);

#endif /* controller/mac-cache.h */
