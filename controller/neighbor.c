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
#include "openvswitch/ofp-parse.h"
#include "openvswitch/vlog.h"
#include "ovn-sb-idl.h"

#include "neighbor.h"

VLOG_DEFINE_THIS_MODULE(neighbor);

static const char *neighbor_interface_prefixes[] = {
    [NEIGH_IFACE_BRIDGE] = "br-",
    [NEIGH_IFACE_VXLAN] = "vxlan-",
    [NEIGH_IFACE_LOOPBACK] = "lo-",
};

static const char *neighbor_opt_name[] = {
    [NEIGH_IFACE_BRIDGE] = "dynamic-routing-bridge-ifname",
    [NEIGH_IFACE_VXLAN] = "dynamic-routing-vxlan-ifname",
    [NEIGH_IFACE_LOOPBACK] = "dynamic-routing-advertise-ifname",
};

static void neighbor_interface_monitor_destroy(
    struct neighbor_interface_monitor *);
static bool neighbor_interface_with_vni_exists(
    struct vector *monitored_interfaces,
    uint32_t vni);
static struct neighbor_interface_monitor *
neighbor_interface_monitor_alloc(enum neighbor_family family,
                                 enum neighbor_interface_type type,
                                 uint32_t vni, const char *if_name);
static void neighbor_collect_mac_to_advertise(
    const struct neighbor_ctx_in *, struct hmap *neighbors,
    struct sset *advertised_pbs, const struct sbrec_datapath_binding *);
static void neighbor_collect_ip_mac_to_advertise(
    const struct neighbor_ctx_in *,
    struct hmap *neighbors_v4, struct hmap *neighbors_v6,
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

static void
neigh_parse_device_name(struct sset *device_names, struct local_datapath *ld,
                        enum neighbor_interface_type type, uint32_t vni)
{
    const char *names = smap_get_def(&ld->datapath->external_ids,
                                     neighbor_opt_name[type], "");
    sset_from_delimited_string(device_names, names, ",");
    if (sset_is_empty(device_names)) {
        /* Default device name if not specified. */
        char if_name[IFNAMSIZ + 1];
        snprintf(if_name, sizeof if_name, "%s%"PRIu32,
                 neighbor_interface_prefixes[type], vni);
        sset_add(device_names, if_name);
    }
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

        struct sset device_names;
        neigh_parse_device_name(&device_names, ld, NEIGH_IFACE_VXLAN, vni);
        const char *name;
        SSET_FOR_EACH (name, &device_names) {
            struct neighbor_interface_monitor *vxlan =
                neighbor_interface_monitor_alloc(NEIGH_AF_BRIDGE,
                                                 NEIGH_IFACE_VXLAN, vni, name);
            vector_push(n_ctx_out->monitored_interfaces, &vxlan);
        }
        sset_destroy(&device_names);

        neigh_parse_device_name(&device_names, ld, NEIGH_IFACE_LOOPBACK, vni);
        if (sset_count(&device_names) > 1) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "Datapath "UUID_FMT" too many names provided "
                              "for loopback device",
                         UUID_ARGS(&ld->datapath->header_.uuid));
        }
        struct neighbor_interface_monitor *lo =
            neighbor_interface_monitor_alloc(NEIGH_AF_BRIDGE,
                                             NEIGH_IFACE_LOOPBACK, vni,
                                             SSET_FIRST(&device_names));
        vector_push(n_ctx_out->monitored_interfaces, &lo);
        sset_destroy(&device_names);

        neigh_parse_device_name(&device_names, ld, NEIGH_IFACE_BRIDGE, vni);
        if (sset_count(&device_names) > 1) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "Datapath "UUID_FMT" too many names provided "
                              "for bridge device",
                         UUID_ARGS(&ld->datapath->header_.uuid));
        }
        struct neighbor_interface_monitor *br_v4 =
            neighbor_interface_monitor_alloc(NEIGH_AF_INET,
                                             NEIGH_IFACE_BRIDGE, vni,
                                             SSET_FIRST(&device_names));
        vector_push(n_ctx_out->monitored_interfaces, &br_v4);

        struct neighbor_interface_monitor *br_v6 =
            neighbor_interface_monitor_alloc(NEIGH_AF_INET6,
                                             NEIGH_IFACE_BRIDGE, vni,
                                             SSET_FIRST(&device_names));
        vector_push(n_ctx_out->monitored_interfaces, &br_v6);
        sset_destroy(&device_names);

        enum neigh_redistribute_mode mode =
            parse_neigh_dynamic_redistribute(&ld->datapath->external_ids);
        if (nrm_mode_FDB_is_set(mode)) {
            neighbor_collect_mac_to_advertise(n_ctx_in,
                                              &lo->announced_neighbors,
                                              n_ctx_out->advertised_pbs,
                                              ld->datapath);
        }
        if (nrm_mode_IP_is_set(mode)) {
            neighbor_collect_ip_mac_to_advertise(n_ctx_in,
                                                 &br_v4->announced_neighbors,
                                                 &br_v6->announced_neighbors,
                                                 n_ctx_out->advertised_pbs,
                                                 ld->datapath);
        }

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
                                 uint32_t vni, const char *if_name)
{
    struct neighbor_interface_monitor *nim = xmalloc(sizeof *nim);
    *nim = (struct neighbor_interface_monitor) {
        .family = family,
        .announced_neighbors = HMAP_INITIALIZER(&nim->announced_neighbors),
        .type = type,
        .vni = vni,
    };
    snprintf(nim->if_name, sizeof nim->if_name, "%s", if_name);

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

static void
neighbor_collect_ip_mac_to_advertise(
        const struct neighbor_ctx_in *n_ctx_in,
        struct hmap *neighbors_v4,
        struct hmap *neighbors_v6,
        struct sset *advertised_pbs,
        const struct sbrec_datapath_binding *dp)
{
    struct sbrec_advertised_mac_binding *target =
        sbrec_advertised_mac_binding_index_init_row(
                n_ctx_in->sbrec_amb_by_dp);
    sbrec_advertised_mac_binding_index_set_datapath(target, dp);

    const struct sbrec_advertised_mac_binding *adv_mb;
    SBREC_ADVERTISED_MAC_BINDING_FOR_EACH_EQUAL (adv_mb, target,
                                                 n_ctx_in->sbrec_amb_by_dp) {
        const struct sbrec_port_binding *pb =
            neighbor_get_relevant_port_binding(n_ctx_in->sbrec_pb_by_name,
                                               adv_mb->logical_port);
        if (!lport_pb_is_chassis_resident(n_ctx_in->chassis, pb)) {
            continue;
        }

        struct in6_addr ip;
        if (!ip46_parse(adv_mb->ip, &ip)) {
            continue;
        }

        struct eth_addr ea;
        char *err = str_to_mac(adv_mb->mac, &ea);
        if (err) {
            free(err);
            continue;
        }

        struct hmap *neighbors = IN6_IS_ADDR_V4MAPPED(&ip)
                                 ? neighbors_v4 : neighbors_v6;
        if (!advertise_neigh_find(neighbors, ea, &ip)) {
            advertise_neigh_add(neighbors, ea, ip);
        }
        sset_add(advertised_pbs, pb->logical_port);
    }

    sbrec_advertised_mac_binding_index_destroy_row(target);
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
