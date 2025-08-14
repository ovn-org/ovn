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

#include "lib/hash.h"
#include "lib/packets.h"
#include "lib/sset.h"
#include "local_data.h"
#include "lport.h"
#include "ovn-sb-idl.h"

#include "neighbor.h"

static const char *neighbor_interface_prefixes[] = {
    [NEIGH_IFACE_BRIDGE] = "br-",
    [NEIGH_IFACE_VXLAN] = "vxlan-",
    [NEIGH_IFACE_LOOPBACK] = "lo-",
};

static void neighbor_interface_monitor_destroy(
    struct neighbor_interface_monitor *);
static bool neighbor_interface_with_vni_exists(
    struct vector *monitored_interfaces,
    uint32_t vni);
static struct neighbor_interface_monitor *
neighbor_interface_monitor_alloc(enum neighbor_family family,
                                 enum neighbor_interface_type type,
                                 uint32_t vni);
static void neighbor_collect_mac_to_advertise(
    const struct neighbor_ctx_in *, struct hmap *neighbors,
    struct sset *advertised_pbs, const struct sbrec_datapath_binding *);
static const struct sbrec_port_binding *neighbor_get_relevant_port_binding(
    struct ovsdb_idl_index *sbrec_pb_by_name,
    const struct sbrec_port_binding *);
static void advertise_neigh_add(struct hmap *neighbors, struct eth_addr mac,
                                struct in6_addr ip);

uint32_t
advertise_neigh_hash(const struct eth_addr *eth, const struct in6_addr *ip)
{
    return hash_bytes(ip, sizeof *ip, hash_bytes(eth, sizeof *eth, 0));
}

struct advertise_neighbor_entry *
advertise_neigh_find(const struct hmap *neighbors, struct eth_addr mac,
                     const struct in6_addr *ip)
{
    uint32_t hash = advertise_neigh_hash(&mac, ip);

    struct advertise_neighbor_entry *ne;
    HMAP_FOR_EACH_WITH_HASH (ne, node, hash, neighbors) {
        if (eth_addr_equals(ne->lladdr, mac) &&
            ipv6_addr_equals(&ne->addr, ip)) {
            return ne;
        }
    }

    return NULL;
}

void
neighbor_run(struct neighbor_ctx_in *n_ctx_in,
             struct neighbor_ctx_out *n_ctx_out)
{
    struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, n_ctx_in->local_datapaths) {
        if (!ld->is_switch) {
            continue;
        }

        int64_t vni = ovn_smap_get_llong(&ld->datapath->external_ids,
                                         "dynamic-routing-vni", -1);
        if (!ovn_is_valid_vni(vni)) {
            continue;
        }

        if (neighbor_interface_with_vni_exists(n_ctx_out->monitored_interfaces,
                                               vni)) {
            continue;
        }

        struct neighbor_interface_monitor *vxlan =
            neighbor_interface_monitor_alloc(NEIGH_AF_BRIDGE,
                                             NEIGH_IFACE_VXLAN, vni);
        vector_push(n_ctx_out->monitored_interfaces, &vxlan);

        struct neighbor_interface_monitor *lo =
            neighbor_interface_monitor_alloc(NEIGH_AF_BRIDGE,
                                             NEIGH_IFACE_LOOPBACK, vni);
        vector_push(n_ctx_out->monitored_interfaces, &lo);

        struct neighbor_interface_monitor *br_v4 =
            neighbor_interface_monitor_alloc(NEIGH_AF_INET,
                                             NEIGH_IFACE_BRIDGE, vni);
        vector_push(n_ctx_out->monitored_interfaces, &br_v4);

        struct neighbor_interface_monitor *br_v6 =
            neighbor_interface_monitor_alloc(NEIGH_AF_INET6,
                                             NEIGH_IFACE_BRIDGE, vni);
        vector_push(n_ctx_out->monitored_interfaces, &br_v6);

        const char *redistribute = smap_get(&ld->datapath->external_ids,
                                            "dynamic-routing-redistribute");
        if (!redistribute || strcmp(redistribute, "fdb")) {
            continue;
        }

        neighbor_collect_mac_to_advertise(n_ctx_in, &lo->announced_neighbors,
                                          n_ctx_out->advertised_pbs,
                                          ld->datapath);
    }
}

void
neighbor_cleanup(struct vector *monitored_interfaces)
{
    struct neighbor_interface_monitor *nim;
    VECTOR_FOR_EACH (monitored_interfaces, nim) {
        neighbor_interface_monitor_destroy(nim);
    }
    vector_clear(monitored_interfaces);
}

bool
neighbor_is_relevant_port_updated(struct ovsdb_idl_index *sbrec_pb_by_name,
                                  const struct sbrec_chassis *chassis,
                                  struct sset *advertised_pbs,
                                  const struct tracked_lport *lport)
{
    if (lport->tracked_type == TRACKED_RESOURCE_REMOVED &&
        sset_contains(advertised_pbs, lport->pb->logical_port)) {
        return true;
    }

    if (lport->tracked_type != TRACKED_RESOURCE_NEW) {
        return false;
    }

    const struct sbrec_port_binding *pb =
        neighbor_get_relevant_port_binding(sbrec_pb_by_name, lport->pb);
    return lport_pb_is_chassis_resident(chassis, pb);
}

static void
neighbor_interface_monitor_destroy(struct neighbor_interface_monitor *nim)
{
    struct advertise_neighbor_entry *an;

    HMAP_FOR_EACH_POP (an, node, &nim->announced_neighbors) {
        free(an);
    }
    hmap_destroy(&nim->announced_neighbors);
    free(nim);
}

static bool
neighbor_interface_with_vni_exists(struct vector *monitored_interfaces,
                                   uint32_t vni)
{
    const struct neighbor_interface_monitor *nim;
    VECTOR_FOR_EACH (monitored_interfaces, nim) {
        if (nim->vni == vni) {
            return true;
        }
    }

    return false;
}

static struct neighbor_interface_monitor *
neighbor_interface_monitor_alloc(enum neighbor_family family,
                                 enum neighbor_interface_type type,
                                 uint32_t vni)
{
    struct neighbor_interface_monitor *nim = xmalloc(sizeof *nim);
    *nim = (struct neighbor_interface_monitor) {
        .family = family,
        .announced_neighbors = HMAP_INITIALIZER(&nim->announced_neighbors),
        .type = type,
        .vni = vni,
    };
    snprintf(nim->if_name, sizeof nim->if_name, "%s%"PRIu32,
             neighbor_interface_prefixes[type], vni);
    return nim;
}

static void
neighbor_collect_mac_to_advertise(const struct neighbor_ctx_in *n_ctx_in,
                                  struct hmap *neighbors,
                                  struct sset *advertised_pbs,
                                  const struct sbrec_datapath_binding *dp)
{
    struct sbrec_port_binding *target =
        sbrec_port_binding_index_init_row(n_ctx_in->sbrec_pb_by_dp);
    sbrec_port_binding_index_set_datapath(target, dp);

    const struct sbrec_port_binding *dp_pb;
    SBREC_PORT_BINDING_FOR_EACH_EQUAL (dp_pb, target,
                                       n_ctx_in->sbrec_pb_by_dp) {
        const struct sbrec_port_binding *pb =
            neighbor_get_relevant_port_binding(n_ctx_in->sbrec_pb_by_name,
                                               dp_pb);
        if (!lport_pb_is_chassis_resident(n_ctx_in->chassis, pb)) {
            continue;
        }

        for (size_t i = 0; i < pb->n_mac; i++) {
            struct lport_addresses addresses;
            if (!extract_lsp_addresses(pb->mac[i], &addresses)) {
                continue;
            }

            if (!advertise_neigh_find(neighbors, addresses.ea, &in6addr_any)) {
                advertise_neigh_add(neighbors, addresses.ea, in6addr_any);
            }

            destroy_lport_addresses(&addresses);
        }

        sset_add(advertised_pbs, pb->logical_port);
    }

    sbrec_port_binding_index_destroy_row(target);
}

static const struct sbrec_port_binding *
neighbor_get_relevant_port_binding(struct ovsdb_idl_index *sbrec_pb_by_name,
                                   const struct sbrec_port_binding *pb)
{
    enum en_lport_type type = get_lport_type(pb);
    if (type == LP_VIF || type == LP_VIRTUAL || type == LP_CONTAINER) {
        return pb;
    }

    if (type == LP_L3GATEWAY) {
        return lport_get_peer(pb, sbrec_pb_by_name);
    }

    if (type == LP_PATCH) {
        const struct sbrec_port_binding *peer =
            lport_get_peer(pb, sbrec_pb_by_name);
        if (!peer) {
            return NULL;
        }

        return lport_get_cr_port(sbrec_pb_by_name, peer, NULL);
    }

    return NULL;
}

static void
advertise_neigh_add(struct hmap *neighbors, struct eth_addr mac,
                    struct in6_addr ip)
{
    struct advertise_neighbor_entry *ne = xmalloc(sizeof *ne);
    *ne = (struct advertise_neighbor_entry) {
        .lladdr = mac,
        .addr = ip,
    };

    hmap_insert(neighbors, &ne->node, advertise_neigh_hash(&mac, &ip));
}
