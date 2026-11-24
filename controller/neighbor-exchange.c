/* Copyright (c) 2025, Red Hat, Inc.
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

#include <linux/neighbour.h>

#include "host-if-monitor.h"
#include "neighbor.h"
#include "neighbor-exchange.h"
#include "neighbor-exchange-netlink.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovn-util.h"
#include "packets.h"
#include "timeval.h"
#include "vec.h"
#include "unixctl.h"

VLOG_DEFINE_THIS_MODULE(neighbor_exchange);

static uint32_t evpn_remote_vtep_hash(const struct in6_addr *ip,
                                      uint16_t port, uint32_t vni);
static void evpn_remote_vtep_add(struct hmap *remote_vteps, struct in6_addr ip,
                                 uint16_t port, uint32_t vni);
static struct evpn_remote_vtep *evpn_remote_vtep_find(
    const struct hmap *remote_vteps, const struct in6_addr *ip,
    uint16_t port, uint32_t vni);
static void evpn_static_entry_add(struct hmap *static_entries,
                                  struct eth_addr mac, struct in6_addr ip,
                                  uint32_t vni, uint32_t nh_id);
static struct evpn_static_entry *evpn_static_entry_find(
    const struct hmap *static_entries, struct eth_addr mac,
    struct in6_addr ip, uint32_t vni, uint32_t nh_id);
static uint32_t evpn_static_entry_hash(const struct eth_addr *mac,
                                       const struct in6_addr *ip,
                                       uint32_t vni, uint32_t nh_id);

/* Retry failed Netlink operations at most once per second in the absence
 * of other engine inputs. */
static long long int neighbor_exchange_retry_at;

struct neighbor_snapshot {
    struct hmap_node node;
    uint64_t link_generation;
    enum neighbor_family family;
    enum neighbor_interface_type type;
    uint32_t vni;
    struct vector learned;
    bool seen;
};

static struct neighbor_snapshot *
neighbor_snapshot_get(struct hmap *snapshots,
                      const struct neighbor_interface_monitor *nim,
                      uint64_t link_generation)
{
    uint32_t hash = hash_3words(nim->family, nim->type, nim->vni);
    hash = hash_uint64_basis(link_generation, hash);
    struct neighbor_snapshot *snapshot;
    HMAP_FOR_EACH_WITH_HASH (snapshot, node, hash, snapshots) {
        if (snapshot->link_generation == link_generation
            && snapshot->family == nim->family && snapshot->type == nim->type
            && snapshot->vni == nim->vni) {
            return snapshot;
        }
    }

    snapshot = xmalloc(sizeof *snapshot);
    *snapshot = (struct neighbor_snapshot) {
        .link_generation = link_generation,
        .family = nim->family,
        .type = nim->type,
        .vni = nim->vni,
        .learned = VECTOR_EMPTY_INITIALIZER(struct ne_nl_received_neigh),
    };
    hmap_insert(snapshots, &snapshot->node, hash);
    return snapshot;
}

static void
neighbor_snapshot_destroy(struct neighbor_snapshot *snapshot)
{
    vector_destroy(&snapshot->learned);
    free(snapshot);
}

void
neighbor_exchange_snapshots_clear(struct hmap *snapshots)
{
    struct neighbor_snapshot *snapshot;
    HMAP_FOR_EACH_POP (snapshot, node, snapshots) {
        neighbor_snapshot_destroy(snapshot);
    }
}

void
neighbor_exchange_run(const struct neighbor_exchange_ctx_in *n_ctx_in,
                      struct neighbor_exchange_ctx_out *n_ctx_out)
{
    struct neighbor_interface_monitor *nim;

    struct sset if_names = SSET_INITIALIZER(&if_names);
    VECTOR_FOR_EACH (n_ctx_in->monitored_interfaces, nim) {
        sset_add(&if_names, nim->if_name);
    }
    host_if_monitor_update_watches(&if_names);
    sset_destroy(&if_names);

    evpn_remote_vteps_clear(n_ctx_out->remote_vteps);
    evpn_static_entries_clear(n_ctx_out->static_fdbs);
    evpn_static_entries_clear(n_ctx_out->static_arps);
    vector_clear(n_ctx_out->neighbor_table_watches);

    bool retry = false;
    VECTOR_FOR_EACH (n_ctx_in->monitored_interfaces, nim) {
        struct host_if_monitor_link link =
            host_if_monitor_get_link(nim->if_name);
        if (!link.if_index) {
            continue;
        }

        struct vector received_neighbors =
            VECTOR_EMPTY_INITIALIZER(struct ne_nl_received_neigh);
        bool dump_failed;
        int error = ne_nl_sync_neigh(nim->family, link.if_index, nim->type,
                                    &nim->announced_neighbors,
                                    &received_neighbors, &dump_failed);
        retry |= error != 0;

        struct neighbor_snapshot *snapshot =
            neighbor_snapshot_get(n_ctx_out->snapshots, nim, link.generation);
        snapshot->seen = true;
        /* A successful empty dump supersedes the previous observations.
         * Add/delete errors still leave us with a usable dump. */
        if (!dump_failed) {
            vector_destroy(&snapshot->learned);
            snapshot->learned = vector_steal(&received_neighbors);
        }
        vector_destroy(&received_neighbors);

        struct ne_nl_received_neigh *ne;
        switch (nim->type) {
        case NEIGH_IFACE_BRIDGE:
            VECTOR_FOR_EACH_PTR (&snapshot->learned, ne) {
                if (ne_is_valid_static_arp(ne)) {
                    if (!evpn_static_entry_find(n_ctx_out->static_arps,
                                                ne->lladdr, ne->addr,
                                                nim->vni, 0)) {
                        evpn_static_entry_add(n_ctx_out->static_arps,
                                              ne->lladdr, ne->addr,
                                              nim->vni, 0);
                    }
                }
            }
            break;
        case NEIGH_IFACE_VXLAN:
            VECTOR_FOR_EACH_PTR (&snapshot->learned, ne) {
                if (ne_is_valid_remote_vtep(ne)) {
                    uint16_t port = ne->port ? ne->port : DEFAULT_VXLAN_PORT;
                    if (!evpn_remote_vtep_find(n_ctx_out->remote_vteps,
                                               &ne->addr, port, nim->vni)) {
                        evpn_remote_vtep_add(n_ctx_out->remote_vteps, ne->addr,
                                             port, nim->vni);
                    }
                }

                if (ne_is_valid_static_fdb(ne)) {
                    if (!evpn_static_entry_find(n_ctx_out->static_fdbs,
                                                ne->lladdr, ne->addr,
                                                nim->vni, ne->nh_id)) {
                        evpn_static_entry_add(n_ctx_out->static_fdbs,
                                              ne->lladdr, ne->addr,
                                              nim->vni, ne->nh_id);
                    }
                }
            }
            break;
        case NEIGH_IFACE_LOOPBACK:
            /* No learning from the loopback interface required. */
            break;
        case NEIGH_IFACE_UNSPECIFIED:
            OVS_NOT_REACHED();
        }

        vector_push(n_ctx_out->neighbor_table_watches, &link.if_index);
    }

    struct neighbor_snapshot *snapshot;
    HMAP_FOR_EACH_SAFE (snapshot, node, n_ctx_out->snapshots) {
        if (!snapshot->seen) {
            hmap_remove(n_ctx_out->snapshots, &snapshot->node);
            neighbor_snapshot_destroy(snapshot);
        } else {
            snapshot->seen = false;
        }
    }

    neighbor_exchange_retry_at = retry ? time_msec() + 1000 : 0;
    if (retry) {
        poll_timer_wait_until(neighbor_exchange_retry_at);
    }
}

bool
neighbor_exchange_retry_due(void)
{
    if (!neighbor_exchange_retry_at) {
        return false;
    }
    if (time_msec() >= neighbor_exchange_retry_at) {
        return true;
    }
    poll_timer_wait_until(neighbor_exchange_retry_at);
    return false;
}

void
evpn_remote_vteps_clear(struct hmap *remote_vteps)
{
    struct evpn_remote_vtep *vtep;
    HMAP_FOR_EACH_POP (vtep, hmap_node, remote_vteps) {
        free(vtep);
    }
}

void
evpn_remote_vtep_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
                      const char *argv[] OVS_UNUSED, void *data_)
{
    struct hmap *remote_vteps = data_;
    struct ds ds = DS_EMPTY_INITIALIZER;

    struct evpn_remote_vtep *vtep;
    HMAP_FOR_EACH (vtep, hmap_node, remote_vteps) {
        ds_put_cstr(&ds, "IP: ");
        ipv6_format_mapped(&vtep->ip, &ds);
        ds_put_format(&ds, ", port: %"PRIu16", vni: %"PRIu32"\n",
                      vtep->port, vtep->vni);
    }

    unixctl_command_reply(conn, ds_cstr_ro(&ds));
    ds_destroy(&ds);
}

void
evpn_static_entries_clear(struct hmap *static_entries)
{
    struct evpn_static_entry *e;
    HMAP_FOR_EACH_POP (e, hmap_node, static_entries) {
        free(e);
    }
}

static void
evpn_remote_vtep_add(struct hmap *remote_vteps, struct in6_addr ip,
                     uint16_t port, uint32_t vni)
{
    struct evpn_remote_vtep *vtep = xmalloc(sizeof *vtep);
    *vtep = (struct evpn_remote_vtep) {
        .ip = ip,
        .port = port,
        .vni = vni,
    };

    hmap_insert(remote_vteps, &vtep->hmap_node,
                evpn_remote_vtep_hash(&ip, port, vni));
}

static struct evpn_remote_vtep *
evpn_remote_vtep_find(const struct hmap *remote_vteps,
                      const struct in6_addr *ip,
                      uint16_t port, uint32_t vni)
{
    uint32_t hash = evpn_remote_vtep_hash(ip, port, vni);

    struct evpn_remote_vtep *vtep;
    HMAP_FOR_EACH_WITH_HASH (vtep, hmap_node, hash, remote_vteps) {
        if (ipv6_addr_equals(&vtep->ip, ip) &&
            vtep->port == port && vtep->vni == vni) {
            return vtep;
        }
    }

    return NULL;
}

static uint32_t
evpn_remote_vtep_hash(const struct in6_addr *ip, uint16_t port,
                      uint32_t vni)
{
    uint32_t hash = 0;
    hash = hash_add_in6_addr(hash, ip);
    hash = hash_add(hash, port);
    hash = hash_add(hash, vni);

    return hash_finish(hash, 14);
}

static void
evpn_static_entry_add(struct hmap *static_entries, struct eth_addr mac,
                      struct in6_addr ip, uint32_t vni, uint32_t nh_id)
{
    struct evpn_static_entry *e = xmalloc(sizeof *e);
    *e = (struct evpn_static_entry) {
        .mac = mac,
        .ip = ip,
        .vni = vni,
        .nh_id = nh_id,
    };

    hmap_insert(static_entries, &e->hmap_node,
                evpn_static_entry_hash(&mac, &ip, vni, nh_id));
}

static struct evpn_static_entry *
evpn_static_entry_find(const struct hmap *static_entries, struct eth_addr mac,
                       struct in6_addr ip, uint32_t vni, uint32_t nh_id)
{
    uint32_t hash = evpn_static_entry_hash(&mac, &ip, vni, nh_id);

    struct evpn_static_entry *e;
    HMAP_FOR_EACH_WITH_HASH (e, hmap_node, hash, static_entries) {
        if (eth_addr_equals(e->mac, mac) &&
            ipv6_addr_equals(&e->ip, &ip) &&
            e->vni == vni &&
            e->nh_id == nh_id) {
            return e;
        }
    }

    return NULL;
}

static uint32_t
evpn_static_entry_hash(const struct eth_addr *mac, const struct in6_addr *ip,
                       uint32_t vni, uint32_t nh_id)
{
    uint32_t hash = 0;
    hash = hash_bytes(mac, sizeof *mac, hash);
    hash = hash_add_in6_addr(hash, ip);
    hash = hash_add(hash, vni);
    hash = hash_add(hash, nh_id);

    return hash_finish(hash, 30);
}
