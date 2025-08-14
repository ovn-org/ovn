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
#include "neighbor-table-notify.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovn-util.h"
#include "packets.h"
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


/* Last neighbor_exchange netlink operation. */
static int neighbor_exchange_nl_status;

#define CLEAR_NEIGHBOR_EXCHANGE_NL_STATUS() \
    do {                                    \
        neighbor_exchange_nl_status = 0;    \
    } while (0)

#define SET_NEIGHBOR_EXCHANGE_NL_STATUS(error)     \
    do {                                           \
        if (!neighbor_exchange_nl_status) {        \
            neighbor_exchange_nl_status = (error); \
            if (error) {                           \
                poll_immediate_wake();             \
            }                                      \
        }                                          \
    } while (0)

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

    CLEAR_NEIGHBOR_EXCHANGE_NL_STATUS();
    VECTOR_FOR_EACH (n_ctx_in->monitored_interfaces, nim) {
        int32_t if_index = host_if_monitor_ifname_toindex(nim->if_name);

        if (!if_index) {
            continue;
        }

        struct vector received_neighbors =
            VECTOR_EMPTY_INITIALIZER(struct ne_nl_received_neigh);
        SET_NEIGHBOR_EXCHANGE_NL_STATUS(
            ne_nl_sync_neigh(nim->family, if_index, &nim->announced_neighbors,
                             &received_neighbors)
        );

        if (nim->type == NEIGH_IFACE_VXLAN) {
            struct ne_nl_received_neigh *ne;
            VECTOR_FOR_EACH_PTR (&received_neighbors, ne) {
                if (ne_is_valid_remote_vtep(ne)) {
                    uint16_t port = ne->port ? ne->port : DEFAULT_VXLAN_PORT;
                    if (!evpn_remote_vtep_find(n_ctx_out->remote_vteps,
                                               &ne->addr, port, nim->vni)) {
                        evpn_remote_vtep_add(n_ctx_out->remote_vteps, ne->addr,
                                             port, nim->vni);
                    }
                }
            }
        }

        neighbor_table_add_watch_request(&n_ctx_out->neighbor_table_watches,
                                         if_index, nim->if_name);
        vector_destroy(&received_neighbors);
    }
}

int
neighbor_exchange_status_run(void)
{
    return neighbor_exchange_nl_status;
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
