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

#include <config.h>

#include "openvswitch/poll-loop.h"
#include "packets.h"
#include "timeval.h"

#include "evpn-arp.h"
#include "evpn-mac-binding-sync.h"
#include "lib/mac-binding-index.h"
#include "local_data.h"
#include "mac-cache.h"
#include "ovn-sb-idl.h"
#include "ovn-util.h"
#include "vec.h"

/* Hash a (logical_port, ip) pair. */
static uint32_t
evpn_mb_hash(const char *logical_port, const char *ip)
{
    uint32_t hash = hash_string(logical_port, 0);
    return hash_string(ip, hash);
}

static struct evpn_mb_synced_entry *
evpn_mb_synced_find(const struct hmap *synced, const char *logical_port,
                    const char *ip)
{
    uint32_t hash = evpn_mb_hash(logical_port, ip);

    struct evpn_mb_synced_entry *entry;
    HMAP_FOR_EACH_WITH_HASH (entry, hmap_node, hash, synced) {
        if (!strcmp(entry->logical_port, logical_port) &&
            !strcmp(entry->ip, ip)) {
            return entry;
        }
    }

    return NULL;
}

static struct evpn_mb_synced_entry *
evpn_mb_synced_add(struct hmap *synced, const char *logical_port,
                   const char *ip)
{
    struct evpn_mb_synced_entry *entry = xmalloc(sizeof *entry);
    *entry = (struct evpn_mb_synced_entry) {
        .logical_port = xstrdup(logical_port),
        .ip = xstrdup(ip),
    };
    hmap_insert(synced, &entry->hmap_node, evpn_mb_hash(logical_port, ip));
    return entry;
}

static void
evpn_mb_synced_remove(struct hmap *synced, struct evpn_mb_synced_entry *entry)
{
    hmap_remove(synced, &entry->hmap_node);
    free(entry->logical_port);
    free(entry->ip);
    free(entry);
}

/* Schedule the waker to fire after 'delay_ms' milliseconds. */
static void
evpn_mb_sync_waker_schedule(struct evpn_mb_sync_waker *waker,
                            int64_t delay_ms)
{
    if (delay_ms < INT64_MAX) {
        waker->should_schedule = true;
        waker->next_wake_msec = time_msec() + delay_ms;
        poll_timer_wait_until(waker->next_wake_msec);
    }
}

/* Sync a single EVPN ARP entry to the SB MAC_Binding table for one
 * router port.  Caller must ensure 'ovnsb_idl_txn' is valid.
 * Returns the remaining time (in ms) until the next timestamp
 * refresh is needed, or INT64_MAX if none. */
static int64_t
sync_evpn_mb_for_router_port(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
    const struct sbrec_mac_binding_table *mb_table,
    const struct sbrec_port_binding *router_pb,
    const struct evpn_arp *arp,
    struct mac_cache_data *mac_cache_data,
    struct ed_type_evpn_mac_binding_sync *data,
    long long timewall_now)
{
    char *ip_s = normalize_v46(&arp->ip);
    struct evpn_mb_synced_entry *existing =
        evpn_mb_synced_find(&data->synced_entries,
                            router_pb->logical_port, ip_s);

    const struct sbrec_mac_binding *sb_mb = existing
        ? sbrec_mac_binding_table_get_for_uuid(mb_table, &existing->mb_uuid)
        : NULL;

    /* Insert or update the SB MAC_Binding row. */
    const struct sbrec_mac_binding *b =
        mac_binding_add_to_sb(ovnsb_idl_txn,
                              sbrec_mac_binding_by_lport_ip,
                              router_pb->logical_port,
                              router_pb->datapath,
                              arp->mac, ip_s, false,
                              sb_mb);

    if (!existing) {
        existing = evpn_mb_synced_add(&data->synced_entries,
                                      router_pb->logical_port, ip_s);
    }

    free(ip_s);
    existing->mb_uuid = b->header_.uuid;
    existing->stale = false;

    /* Refresh timestamp to prevent aging. */
    struct mac_cache_threshold *threshold =
        mac_cache_threshold_find(mac_cache_data,
                                 router_pb->datapath->tunnel_key);
    if (!threshold) {
        return INT64_MAX;
    }

    uint64_t since_updated = timewall_now - b->timestamp;
    if (since_updated >= threshold->cooldown_period) {
        sbrec_mac_binding_set_timestamp(b, timewall_now);
        return threshold->cooldown_period;
    }

    return threshold->cooldown_period - since_updated;
}

void
evpn_mac_binding_sync_run(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
    const struct sbrec_mac_binding_table *mb_table,
    const struct hmap *local_datapaths,
    const struct hmap *evpn_arps,
    struct mac_cache_data *mac_cache_data,
    struct ed_type_evpn_mac_binding_sync *data,
    struct evpn_mb_sync_waker *waker)
{
    if (!ovnsb_idl_txn) {
        data->sb_changes_pending = true;
        return;
    }

    long long timewall_now = time_wall_msec();
    int64_t min_next_refresh_ms = INT64_MAX;

    /* Mark all synced entries as stale.  SB row pointers are resolved
     * lazily by UUID only where needed (insert/update, timestamp
     * refresh, delete), avoiding a per-entry index lookup here. */
    struct evpn_mb_synced_entry *synced_entry;
    HMAP_FOR_EACH (synced_entry, hmap_node, &data->synced_entries) {
        synced_entry->stale = true;
    }

    /* Walk current EVPN ARPs and sync to SB. */
    const struct evpn_arp *arp;
    HMAP_FOR_EACH (arp, hmap_node, evpn_arps) {
        const struct peer_ports *peers;
        VECTOR_FOR_EACH_PTR (&arp->ldp->peer_ports, peers) {
            const struct sbrec_port_binding *remote_pb = peers->remote;
            struct local_datapath *peer_ld =
                get_local_datapath(local_datapaths,
                                   remote_pb->datapath->tunnel_key);
            if (!peer_ld || peer_ld->is_switch) {
                continue;
            }

            int64_t remaining =
                sync_evpn_mb_for_router_port(ovnsb_idl_txn,
                                             sbrec_mac_binding_by_lport_ip,
                                             mb_table,
                                             remote_pb, arp,
                                             mac_cache_data, data,
                                             timewall_now);
            if (remaining < min_next_refresh_ms) {
                min_next_refresh_ms = remaining;
            }
        }
    }

    /* Delete stale entries from SB. */
    HMAP_FOR_EACH_SAFE (synced_entry, hmap_node, &data->synced_entries) {
        if (!synced_entry->stale) {
            continue;
        }

        const struct sbrec_mac_binding *sb_mb =
            sbrec_mac_binding_table_get_for_uuid(
                mb_table, &synced_entry->mb_uuid);
        if (sb_mb) {
            sbrec_mac_binding_delete(sb_mb);
        }

        evpn_mb_synced_remove(&data->synced_entries, synced_entry);
    }

    /* Schedule the waker for the next timestamp refresh. */
    if (min_next_refresh_ms < INT64_MAX) {
        evpn_mb_sync_waker_schedule(waker, min_next_refresh_ms);
    }
}

void
evpn_mac_binding_sync_init(struct ed_type_evpn_mac_binding_sync *data)
{
    hmap_init(&data->synced_entries);
    data->sb_changes_pending = false;
}

void
evpn_mac_binding_sync_cleanup(struct ed_type_evpn_mac_binding_sync *data)
{
    struct evpn_mb_synced_entry *entry;
    HMAP_FOR_EACH_POP (entry, hmap_node, &data->synced_entries) {
        free(entry->logical_port);
        free(entry->ip);
        free(entry);
    }
    hmap_destroy(&data->synced_entries);
}
