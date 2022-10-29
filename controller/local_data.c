/* Copyright (c) 2021, Red Hat, Inc.
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

/* OVS includes. */
#include "include/openvswitch/json.h"
#include "lib/hmapx.h"
#include "lib/flow.h"
#include "lib/util.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "encaps.h"
#include "ha-chassis.h"
#include "lport.h"
#include "lib/ovn-util.h"
#include "lib/ovn-sb-idl.h"
#include "local_data.h"
#include "lport.h"

VLOG_DEFINE_THIS_MODULE(ldata);

static struct local_datapath *add_local_datapath__(
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    int depth, const struct sbrec_datapath_binding *,
    const struct sbrec_chassis *, struct hmap *local_datapaths,
    struct hmap *tracked_datapaths);
static void local_datapath_peer_port_add(
    struct local_datapath *, const struct sbrec_port_binding *local,
    const struct sbrec_port_binding *remote);

static struct tracked_datapath *tracked_datapath_create(
    const struct sbrec_datapath_binding *dp,
    enum en_tracked_resource_type tracked_type,
    struct hmap *tracked_datapaths);

static bool datapath_is_switch(const struct sbrec_datapath_binding *);
static bool datapath_is_transit_switch(const struct sbrec_datapath_binding *);

static uint64_t local_datapath_usage;

struct local_datapath *
get_local_datapath(const struct hmap *local_datapaths, uint32_t tunnel_key)
{
    struct hmap_node *node = hmap_first_with_hash(local_datapaths, tunnel_key);
    return (node
            ? CONTAINER_OF(node, struct local_datapath, hmap_node)
            : NULL);
}

struct local_datapath *
local_datapath_alloc(const struct sbrec_datapath_binding *dp)
{
    struct local_datapath *ld = xzalloc(sizeof *ld);
    ld->datapath = dp;
    ld->is_switch = datapath_is_switch(dp);
    ld->is_transit_switch = datapath_is_transit_switch(dp);
    shash_init(&ld->external_ports);
    shash_init(&ld->multichassis_ports);
    /* memory accounting - common part. */
    local_datapath_usage += sizeof *ld;

    return ld;
}

void
local_datapaths_destroy(struct hmap *local_datapaths)
{
    struct local_datapath *ld;
    HMAP_FOR_EACH_POP (ld, hmap_node, local_datapaths) {
        local_datapath_destroy(ld);
    }

    hmap_destroy(local_datapaths);
}

void
local_datapath_destroy(struct local_datapath *ld)
{
    /* memory accounting. */
    struct shash_node *node;
    SHASH_FOR_EACH (node, &ld->external_ports) {
        local_datapath_usage -= strlen(node->name);
    }
    SHASH_FOR_EACH (node, &ld->multichassis_ports) {
        local_datapath_usage -= strlen(node->name);
    }
    local_datapath_usage -= (shash_count(&ld->external_ports)
                             * sizeof *node);
    local_datapath_usage -= (shash_count(&ld->multichassis_ports)
                             * sizeof *node);
    local_datapath_usage -= sizeof *ld;
    local_datapath_usage -=
        ld->n_allocated_peer_ports * sizeof *ld->peer_ports;

    free(ld->peer_ports);
    shash_destroy(&ld->external_ports);
    shash_destroy(&ld->multichassis_ports);
    free(ld);
}

/* Checks if pb is running on local gw router or pb is a patch port
 * and the peer datapath should be added to local datapaths. */
bool
need_add_peer_to_local(
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct sbrec_port_binding *pb,
    const struct sbrec_chassis *chassis)
{
    /* This port is running on local gw router. */
    if (!strcmp(pb->type, "l3gateway") && pb->chassis == chassis) {
        return true;
    }

    /* If it is not a patch port, no peer to add. */
    if (strcmp(pb->type, "patch")) {
        return false;
    }

    /* If it is a regular patch port, it is fully distributed, add the peer. */
    const char *crp = smap_get(&pb->options, "chassis-redirect-port");
    if (!crp) {
        return true;
    }

    /* A DGP, find its chassis-redirect-port pb. */
    const struct sbrec_port_binding *pb_crp =
        lport_lookup_by_name(sbrec_port_binding_by_name, crp);
    if (!pb_crp) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        VLOG_WARN_RL(&rl, "Chassis-redirect-port %s for DGP %s is not found.",
                     pb->logical_port, crp);
        return false;
    }

    /* Check if it is configured as "always-redirect". If not, then we will
     * need to add the peer to local for distributed processing. */
    if (!smap_get_bool(&pb_crp->options, "always-redirect", false)) {
        return true;
    }

    /* Check if its chassis-redirect-port is local. If yes, then we need to add
     * the peer to local, which could be the localnet network, which doesn't
     * have other chances to be added to local datapaths if there is no VIF
     * bindings. */
    if (pb_crp->ha_chassis_group) {
        return ha_chassis_group_contains(pb_crp->ha_chassis_group, chassis);
    }
    return false;
}

void
add_local_datapath(struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                   struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                   struct ovsdb_idl_index *sbrec_port_binding_by_name,
                   const struct sbrec_datapath_binding *dp,
                   const struct sbrec_chassis *chassis,
                   struct hmap *local_datapaths,
                   struct hmap *tracked_datapaths)
{
    add_local_datapath__(sbrec_datapath_binding_by_key,
                         sbrec_port_binding_by_datapath,
                         sbrec_port_binding_by_name, 0,
                         dp, chassis, local_datapaths,
                         tracked_datapaths);
}

void
add_local_datapath_peer_port(
    const struct sbrec_port_binding *pb,
    const struct sbrec_chassis *chassis,
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    struct local_datapath *ld,
    struct hmap *local_datapaths,
    struct hmap *tracked_datapaths)
{
    const struct sbrec_port_binding *peer;
    peer = lport_get_peer(pb, sbrec_port_binding_by_name);

    if (!peer) {
        return;
    }

    local_datapath_peer_port_add(ld, pb, peer);

    struct local_datapath *peer_ld =
        get_local_datapath(local_datapaths,
                           peer->datapath->tunnel_key);
    if (!peer_ld) {
        add_local_datapath__(sbrec_datapath_binding_by_key,
                             sbrec_port_binding_by_datapath,
                             sbrec_port_binding_by_name, 1,
                             peer->datapath, chassis, local_datapaths,
                             tracked_datapaths);
        return;
    }

    local_datapath_peer_port_add(peer_ld, peer, pb);
}

void
remove_local_datapath_peer_port(const struct sbrec_port_binding *pb,
                                struct local_datapath *ld,
                                struct hmap *local_datapaths)
{
    size_t i = 0;
    for (i = 0; i < ld->n_peer_ports; i++) {
        if (ld->peer_ports[i].local == pb) {
            break;
        }
    }

    if (i == ld->n_peer_ports) {
        return;
    }

    const struct sbrec_port_binding *peer = ld->peer_ports[i].remote;

    /* Possible improvement: We can shrink the allocated peer ports
     * if (ld->n_peer_ports < ld->n_allocated_peer_ports / 2).
     */
    ld->peer_ports[i].local = ld->peer_ports[ld->n_peer_ports - 1].local;
    ld->peer_ports[i].remote = ld->peer_ports[ld->n_peer_ports - 1].remote;
    ld->n_peer_ports--;

    struct local_datapath *peer_ld =
        get_local_datapath(local_datapaths, peer->datapath->tunnel_key);
    if (peer_ld) {
        /* Remove the peer port from the peer datapath. The peer
         * datapath also tries to remove its peer lport, but that would
         * be no-op. */
        remove_local_datapath_peer_port(peer, peer_ld, local_datapaths);
    }
}

void
add_local_datapath_external_port(struct local_datapath *ld,
                                 char *logical_port, const void *data)
{
    if (!shash_replace(&ld->external_ports, logical_port, data)) {
        local_datapath_usage += sizeof(struct shash_node) +
                                strlen(logical_port);
    }
}

void
remove_local_datapath_external_port(struct local_datapath *ld,
                                    char *logical_port)
{
    if (shash_find_and_delete(&ld->external_ports, logical_port)) {
        local_datapath_usage -= sizeof(struct shash_node) +
                                strlen(logical_port);
    }
}

void
add_local_datapath_multichassis_port(struct local_datapath *ld,
                                     char *logical_port, const void *data)
{
    if (!shash_replace(&ld->multichassis_ports, logical_port, data)) {
        local_datapath_usage += sizeof(struct shash_node) +
                                strlen(logical_port);
    }
}

void
remove_local_datapath_multichassis_port(struct local_datapath *ld,
                                        char *logical_port)
{
    if (shash_find_and_delete(&ld->multichassis_ports, logical_port)) {
        local_datapath_usage -= sizeof(struct shash_node) +
                                strlen(logical_port);
    }
}

void
local_datapath_memory_usage(struct simap *usage)
{
    simap_increase(usage, "local_datapath_usage-KB",
                   ROUND_UP(local_datapath_usage, 1024) / 1024);
}

/* track datapath functions. */
struct tracked_datapath *
tracked_datapath_add(const struct sbrec_datapath_binding *dp,
                     enum en_tracked_resource_type tracked_type,
                     struct hmap *tracked_datapaths)
{
    struct tracked_datapath *t_dp =
        tracked_datapath_find(tracked_datapaths, dp);
    if (!t_dp) {
        t_dp = tracked_datapath_create(dp, tracked_type, tracked_datapaths);
    } else {
        t_dp->tracked_type = tracked_type;
    }

    return t_dp;
}

struct tracked_datapath *
tracked_datapath_find(struct hmap *tracked_datapaths,
                      const struct sbrec_datapath_binding *dp)
{
    struct tracked_datapath *t_dp;
    size_t hash = uuid_hash(&dp->header_.uuid);
    HMAP_FOR_EACH_WITH_HASH (t_dp, node, hash, tracked_datapaths) {
        if (uuid_equals(&t_dp->dp->header_.uuid, &dp->header_.uuid)) {
            return t_dp;
        }
    }

    return NULL;
}

void
tracked_datapath_lport_add(const struct sbrec_port_binding *pb,
                           enum en_tracked_resource_type tracked_type,
                           struct hmap *tracked_datapaths)
{
    struct tracked_datapath *tracked_dp =
        tracked_datapath_find(tracked_datapaths, pb->datapath);
    if (!tracked_dp) {
        tracked_dp = tracked_datapath_create(pb->datapath,
                                             TRACKED_RESOURCE_UPDATED,
                                             tracked_datapaths);
    }

    /* Check if the lport is already present or not.
     * If it is already present, then just update the 'pb' field. */
    struct tracked_lport *lport =
        shash_find_data(&tracked_dp->lports, pb->logical_port);

    if (!lport) {
        lport = xmalloc(sizeof *lport);
        shash_add(&tracked_dp->lports, pb->logical_port, lport);
    }

    lport->pb = pb;
    lport->tracked_type = tracked_type;
}

void
tracked_datapaths_destroy(struct hmap *tracked_datapaths)
{
    struct tracked_datapath *t_dp;
    HMAP_FOR_EACH_POP (t_dp, node, tracked_datapaths) {
        shash_destroy_free_data(&t_dp->lports);
        free(t_dp);
    }

    hmap_destroy(tracked_datapaths);
}

/* Iterates the br_int ports and build the simap of patch to ofports
 * and chassis tunnels. */
void
local_nonvif_data_run(const struct ovsrec_bridge *br_int,
                      const struct sbrec_chassis *chassis_rec,
                      struct simap *patch_ofports,
                      struct hmap *chassis_tunnels)
{
    for (int i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_int->ports[i];
        if (!strcmp(port_rec->name, br_int->name)) {
            continue;
        }

        const char *tunnel_id = smap_get(&port_rec->external_ids,
                                         "ovn-chassis-id");
        if (tunnel_id && encaps_tunnel_id_match(tunnel_id,
                                                chassis_rec->name,
                                                NULL)) {
            continue;
        }

        const char *localnet = smap_get(&port_rec->external_ids,
                                        "ovn-localnet-port");
        const char *l2gateway = smap_get(&port_rec->external_ids,
                                        "ovn-l2gateway-port");

        for (int j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec = port_rec->interfaces[j];

            /* Get OpenFlow port number. */
            if (!iface_rec->n_ofport) {
                continue;
            }
            int64_t ofport = iface_rec->ofport[0];
            if (ofport < 1 || ofport > ofp_to_u16(OFPP_MAX)) {
                continue;
            }

            bool is_patch = !strcmp(iface_rec->type, "patch");
            if (is_patch && localnet) {
                simap_put(patch_ofports, localnet, ofport);
                break;
            } else if (is_patch && l2gateway) {
                /* L2 gateway patch ports can be handled just like VIFs. */
                simap_put(patch_ofports, l2gateway, ofport);
                break;
            } else if (tunnel_id) {
                enum chassis_tunnel_type tunnel_type;
                if (!strcmp(iface_rec->type, "geneve")) {
                    tunnel_type = GENEVE;
                } else if (!strcmp(iface_rec->type, "stt")) {
                    tunnel_type = STT;
                } else if (!strcmp(iface_rec->type, "vxlan")) {
                    tunnel_type = VXLAN;
                } else {
                    continue;
                }

                /* We split the tunnel_id to get the chassis-id
                 * and hash the tunnel list on the chassis-id. The
                 * reason to use the chassis-id alone is because
                 * there might be cases (multicast, gateway chassis)
                 * where we need to tunnel to the chassis, but won't
                 * have the encap-ip specifically.
                 */
                char *hash_id = NULL;
                char *ip = NULL;

                if (!encaps_tunnel_id_parse(tunnel_id, &hash_id, &ip)) {
                    continue;
                }
                struct chassis_tunnel *tun = xmalloc(sizeof *tun);
                hmap_insert(chassis_tunnels, &tun->hmap_node,
                            hash_string(hash_id, 0));
                tun->chassis_id = xstrdup(tunnel_id);
                tun->ofport = u16_to_ofp(ofport);
                tun->type = tunnel_type;

                free(hash_id);
                free(ip);
                break;
            }
        }
    }
}

bool
local_nonvif_data_handle_ovs_iface_changes(
    const struct ovsrec_interface_table *iface_table)
{
    const struct ovsrec_interface *iface_rec;
    OVSREC_INTERFACE_TABLE_FOR_EACH_TRACKED (iface_rec, iface_table) {
        if (!strcmp(iface_rec->type, "geneve") ||
            !strcmp(iface_rec->type, "patch") ||
            !strcmp(iface_rec->type, "vxlan") ||
            !strcmp(iface_rec->type, "stt")) {
            return false;
        }
    }

    return true;
}

bool
get_chassis_tunnel_ofport(const struct hmap *chassis_tunnels,
                          const char *chassis_name, char *encap_ip,
                          ofp_port_t *ofport)
{
    struct chassis_tunnel *tun = NULL;
    tun = chassis_tunnel_find(chassis_tunnels, chassis_name, encap_ip);
    if (!tun) {
        return false;
    }

    *ofport = tun->ofport;
    return true;
}


void
chassis_tunnels_destroy(struct hmap *chassis_tunnels)
{
    struct chassis_tunnel *tun;
    HMAP_FOR_EACH_POP (tun, hmap_node, chassis_tunnels) {
        free(tun->chassis_id);
        free(tun);
    }
    hmap_destroy(chassis_tunnels);
}


/*
 * This function looks up the list of tunnel ports (provided by
 * ovn-chassis-id ports) and returns the tunnel for the given chassid-id and
 * encap-ip. The ovn-chassis-id is formed using the chassis-id and encap-ip.
 * The list is hashed using the chassis-id. If the encap-ip is not specified,
 * it means we'll just return a tunnel for that chassis-id, i.e. we just check
 * for chassis-id and if there is a match, we'll return the tunnel.
 * If encap-ip is also provided we use both chassis-id and encap-ip to do
 * a more specific lookup.
 */
struct chassis_tunnel *
chassis_tunnel_find(const struct hmap *chassis_tunnels, const char *chassis_id,
                    char *encap_ip)
{
    /*
     * If the specific encap_ip is given, look for the chassisid_ip entry,
     * else return the 1st found entry for the chassis.
     */
    struct chassis_tunnel *tun = NULL;
    HMAP_FOR_EACH_WITH_HASH (tun, hmap_node, hash_string(chassis_id, 0),
                             chassis_tunnels) {
        if (encaps_tunnel_id_match(tun->chassis_id, chassis_id, encap_ip)) {
            return tun;
        }
    }
    return NULL;
}

/* static functions. */
static struct local_datapath *
add_local_datapath__(struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                     struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                     struct ovsdb_idl_index *sbrec_port_binding_by_name,
                     int depth, const struct sbrec_datapath_binding *dp,
                     const struct sbrec_chassis *chassis,
                     struct hmap *local_datapaths,
                     struct hmap *tracked_datapaths)
{
    uint32_t dp_key = dp->tunnel_key;
    struct local_datapath *ld = get_local_datapath(local_datapaths, dp_key);
    if (ld) {
        return ld;
    }

    ld = local_datapath_alloc(dp);
    hmap_insert(local_datapaths, &ld->hmap_node, dp_key);
    ld->datapath = dp;

    if (tracked_datapaths) {
        tracked_datapath_add(ld->datapath, TRACKED_RESOURCE_NEW,
                             tracked_datapaths);
    }

    if (depth >= 100) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "datapaths nested too deep");
        return ld;
    }

    struct sbrec_port_binding *target =
        sbrec_port_binding_index_init_row(sbrec_port_binding_by_datapath);
    sbrec_port_binding_index_set_datapath(target, dp);

    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, target,
                                       sbrec_port_binding_by_datapath) {
        if (!strcmp(pb->type, "patch") || !strcmp(pb->type, "l3gateway")) {
            const char *peer_name = smap_get(&pb->options, "peer");
            if (peer_name) {
                const struct sbrec_port_binding *peer;

                peer = lport_lookup_by_name(sbrec_port_binding_by_name,
                                            peer_name);

                if (peer && peer->datapath) {
                    if (need_add_peer_to_local(
                            sbrec_port_binding_by_name, pb, chassis)) {
                        struct local_datapath *peer_ld =
                            add_local_datapath__(sbrec_datapath_binding_by_key,
                                             sbrec_port_binding_by_datapath,
                                             sbrec_port_binding_by_name,
                                             depth + 1, peer->datapath,
                                             chassis, local_datapaths,
                                             tracked_datapaths);
                        local_datapath_peer_port_add(peer_ld, peer, pb);
                        local_datapath_peer_port_add(ld, pb, peer);
                    }
                }
            }
        }
    }
    sbrec_port_binding_index_destroy_row(target);
    return ld;
}

static struct tracked_datapath *
tracked_datapath_create(const struct sbrec_datapath_binding *dp,
                        enum en_tracked_resource_type tracked_type,
                        struct hmap *tracked_datapaths)
{
    struct tracked_datapath *t_dp = xzalloc(sizeof *t_dp);
    t_dp->dp = dp;
    t_dp->tracked_type = tracked_type;
    shash_init(&t_dp->lports);
    hmap_insert(tracked_datapaths, &t_dp->node, uuid_hash(&dp->header_.uuid));
    return t_dp;
}

static void
local_datapath_peer_port_add(struct local_datapath *ld,
                             const struct sbrec_port_binding *local,
                             const struct sbrec_port_binding *remote)
{
    for (size_t i = 0; i < ld->n_peer_ports; i++) {
        if (ld->peer_ports[i].local == local) {
            return;
        }
    }
    ld->n_peer_ports++;
    if (ld->n_peer_ports > ld->n_allocated_peer_ports) {
        size_t old_n_ports = ld->n_allocated_peer_ports;
        ld->peer_ports =
            x2nrealloc(ld->peer_ports,
                       &ld->n_allocated_peer_ports,
                       sizeof *ld->peer_ports);
        local_datapath_usage +=
            (ld->n_allocated_peer_ports - old_n_ports) *
            sizeof *ld->peer_ports;
    }
    ld->peer_ports[ld->n_peer_ports - 1].local = local;
    ld->peer_ports[ld->n_peer_ports - 1].remote = remote;
}

static bool
datapath_is_switch(const struct sbrec_datapath_binding *ldp)
{
    return smap_get(&ldp->external_ids, "logical-switch") != NULL;
}

static bool
datapath_is_transit_switch(const struct sbrec_datapath_binding *ldp)
{
    return smap_get(&ldp->external_ids, "interconn-ts") != NULL;
}
