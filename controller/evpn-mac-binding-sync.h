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

#ifndef EVPN_MAC_BINDING_SYNC_H
#define EVPN_MAC_BINDING_SYNC_H 1

#include "openvswitch/hmap.h"
#include "openvswitch/uuid.h"
#include "uuidset.h"

struct mac_cache_data;
struct ovsdb_idl_index;
struct ovsdb_idl_txn;
struct sbrec_mac_binding_table;
struct sbrec_shared_mac_binding_table;

/* Tracks a MAC_Binding or Shared_MAC_Binding row written by EVPN sync. */
struct evpn_mb_synced_entry {
    struct hmap_node hmap_node;
    char *logical_port;                  /* Router port name, if private. */
    struct uuid scope_uuid;              /* Scope UUID, if shared. */
    bool shared;
    char *ip;                            /* Normalized IP string. */
    struct uuid mb_uuid;                 /* UUID of the SB binding row. */
    bool stale;                          /* Marked true at start of sync,
                                          * cleared when still desired. */
};

/* Persistent state for the en_evpn_mac_binding_sync engine node. */
struct ed_type_evpn_mac_binding_sync {
    /* Contains 'struct evpn_mb_synced_entry'.  Tracks private
     * (logical_port, ip) and shared (scope, ip) pairs written to SB. */
    struct hmap synced_entries;

    /* Contains LSP UUIDs belonging to synced entries peers. */
    struct uuidset lsp_peers;

    /* True when an SB write was skipped because ovnsb_idl_txn was NULL. */
    bool sb_changes_pending;
};

/* Timer that periodically wakes the sync node so it can refresh
 * timestamps on SB MAC_Binding rows it owns. */
struct evpn_mb_sync_waker {
    bool should_schedule;         /* Whether a wake is pending. */
    long long next_wake_msec;     /* Absolute time of next wake. */
};

void evpn_mac_binding_sync_run(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
    struct ovsdb_idl_index *shared_mac_binding_by_scope_ip,
    const struct sbrec_mac_binding_table *mb_table,
    const struct sbrec_shared_mac_binding_table *shared_mb_table,
    const struct hmap *local_datapaths,
    const struct hmap *evpn_arps,
    struct mac_cache_data *mac_cache_data,
    struct ed_type_evpn_mac_binding_sync *data,
    struct evpn_mb_sync_waker *waker);

void evpn_mac_binding_sync_init(struct ed_type_evpn_mac_binding_sync *);
void evpn_mac_binding_sync_cleanup(struct ed_type_evpn_mac_binding_sync *);

#endif /* EVPN_MAC_BINDING_SYNC_H */
