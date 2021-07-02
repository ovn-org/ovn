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
#include "lib/util.h"
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "lib/ovn-util.h"
#include "lib/ovn-sb-idl.h"
#include "local_data.h"
#include "lport.h"

VLOG_DEFINE_THIS_MODULE(ldata);

static void add_local_datapath__(
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    int depth, const struct sbrec_datapath_binding *,
    struct hmap *local_datapaths, struct hmap *tracked_datapaths);

static struct tracked_datapath *tracked_datapath_create(
    const struct sbrec_datapath_binding *dp,
    enum en_tracked_resource_type tracked_type,
    struct hmap *tracked_datapaths);

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
    shash_init(&ld->external_ports);
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
    free(ld->peer_ports);
    shash_destroy(&ld->external_ports);
    free(ld);
}

void
add_local_datapath(struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                   struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                   struct ovsdb_idl_index *sbrec_port_binding_by_name,
                   const struct sbrec_datapath_binding *dp,
                   struct hmap *local_datapaths,
                   struct hmap *tracked_datapaths)
{
    add_local_datapath__(sbrec_datapath_binding_by_key,
                         sbrec_port_binding_by_datapath,
                         sbrec_port_binding_by_name, 0,
                         dp, local_datapaths,
                         tracked_datapaths);
}

void
add_local_datapath_peer_port(
    const struct sbrec_port_binding *pb,
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

    bool present = false;
    for (size_t i = 0; i < ld->n_peer_ports; i++) {
        if (ld->peer_ports[i].local == pb) {
            present = true;
            break;
        }
    }

    if (!present) {
        ld->n_peer_ports++;
        if (ld->n_peer_ports > ld->n_allocated_peer_ports) {
            ld->peer_ports =
                x2nrealloc(ld->peer_ports,
                           &ld->n_allocated_peer_ports,
                           sizeof *ld->peer_ports);
        }
        ld->peer_ports[ld->n_peer_ports - 1].local = pb;
        ld->peer_ports[ld->n_peer_ports - 1].remote = peer;
    }

    struct local_datapath *peer_ld =
        get_local_datapath(local_datapaths,
                           peer->datapath->tunnel_key);
    if (!peer_ld) {
        add_local_datapath__(sbrec_datapath_binding_by_key,
                             sbrec_port_binding_by_datapath,
                             sbrec_port_binding_by_name, 1,
                             peer->datapath, local_datapaths,
                             tracked_datapaths);
        return;
    }

    for (size_t i = 0; i < peer_ld->n_peer_ports; i++) {
        if (peer_ld->peer_ports[i].local == peer) {
            return;
        }
    }

    peer_ld->n_peer_ports++;
    if (peer_ld->n_peer_ports > peer_ld->n_allocated_peer_ports) {
        peer_ld->peer_ports =
            x2nrealloc(peer_ld->peer_ports,
                        &peer_ld->n_allocated_peer_ports,
                        sizeof *peer_ld->peer_ports);
    }
    peer_ld->peer_ports[peer_ld->n_peer_ports - 1].local = peer;
    peer_ld->peer_ports[peer_ld->n_peer_ports - 1].remote = pb;
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

/* static functions. */
static void
add_local_datapath__(struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                     struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                     struct ovsdb_idl_index *sbrec_port_binding_by_name,
                     int depth, const struct sbrec_datapath_binding *dp,
                     struct hmap *local_datapaths,
                     struct hmap *tracked_datapaths)
{
    uint32_t dp_key = dp->tunnel_key;
    struct local_datapath *ld = get_local_datapath(local_datapaths, dp_key);
    if (ld) {
        return;
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
        return;
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
                    if (!strcmp(pb->type, "patch")) {
                        /* Add the datapath to local datapath only for patch
                         * ports. For l3gateway ports, since gateway router
                         * resides on one chassis, we don't need to add.
                         * Otherwise, all other chassis might create patch
                         * ports between br-int and the provider bridge. */
                        add_local_datapath__(sbrec_datapath_binding_by_key,
                                             sbrec_port_binding_by_datapath,
                                             sbrec_port_binding_by_name,
                                             depth + 1, peer->datapath,
                                             local_datapaths,
                                             tracked_datapaths);
                    }
                    ld->n_peer_ports++;
                    if (ld->n_peer_ports > ld->n_allocated_peer_ports) {
                        ld->peer_ports =
                            x2nrealloc(ld->peer_ports,
                                       &ld->n_allocated_peer_ports,
                                       sizeof *ld->peer_ports);
                    }
                    ld->peer_ports[ld->n_peer_ports - 1].local = pb;
                    ld->peer_ports[ld->n_peer_ports - 1].remote = peer;
                }
            }
        }
    }
    sbrec_port_binding_index_destroy_row(target);
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
