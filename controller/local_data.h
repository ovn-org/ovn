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

#ifndef LOCAL_DATA_H
#define LOCAL_DATA_H 1

/* OVS includes. */
#include "include/openvswitch/shash.h"
#include "lib/smap.h"
#include "lib/simap.h"

/* OVN includes. */
#include "lib/ovn-util.h"

struct sbrec_datapath_binding;
struct sbrec_port_binding;
struct sbrec_chassis;
struct ovsdb_idl_index;
struct ovsrec_bridge;
struct ovsrec_interface_table;

/* A logical datapath that has some relevance to this hypervisor.  A logical
 * datapath D is relevant to hypervisor H if:
 *
 *     - Some VIF or l2gateway or l3gateway port in D is located on H.
 *
 *     - D is reachable over a series of hops across patch ports, starting from
 *       a datapath relevant to H.
 *
 * The 'hmap_node''s hash value is 'datapath->tunnel_key'. */
struct local_datapath {
    struct hmap_node hmap_node;
    const struct sbrec_datapath_binding *datapath;
    bool is_switch;

    /* The localnet port in this datapath, if any (at most one is allowed). */
    const struct sbrec_port_binding *localnet_port;

    struct {
        const struct sbrec_port_binding *local;
        const struct sbrec_port_binding *remote;
    } *peer_ports;

    size_t n_peer_ports;
    size_t n_allocated_peer_ports;

    struct shash external_ports;
};

struct local_datapath *local_datapath_alloc(
    const struct sbrec_datapath_binding *);
struct local_datapath *get_local_datapath(const struct hmap *,
                                          uint32_t tunnel_key);
bool
need_add_patch_peer_to_local(
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct sbrec_port_binding *,
    const struct sbrec_chassis *);
void add_local_datapath(
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct sbrec_datapath_binding *,
    const struct sbrec_chassis *,
    struct hmap *local_datapaths,
    struct hmap *tracked_datapaths);

void local_datapaths_destroy(struct hmap *local_datapaths);
void local_datapath_destroy(struct local_datapath *ld);
void add_local_datapath_peer_port(
    const struct sbrec_port_binding *,
    const struct sbrec_chassis *,
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    struct local_datapath *,
    struct hmap *local_datapaths,
    struct hmap *tracked_datapaths);

void remove_local_datapath_peer_port(const struct sbrec_port_binding *pb,
                                     struct local_datapath *ld,
                                     struct hmap *local_datapaths);

enum en_tracked_resource_type {
    TRACKED_RESOURCE_NEW,
    TRACKED_RESOURCE_REMOVED,
    TRACKED_RESOURCE_UPDATED
};

/* Represents a tracked logical port. */
struct tracked_lport {
    const struct sbrec_port_binding *pb;
    enum en_tracked_resource_type tracked_type;
};

/* Represent a tracked datapath. */
struct tracked_datapath {
    struct hmap_node node;
    const struct sbrec_datapath_binding *dp;
    enum en_tracked_resource_type tracked_type;
    struct shash lports; /* shash of struct tracked_binding_lport. */
};

struct tracked_datapath * tracked_datapath_add(
    const struct sbrec_datapath_binding *, enum en_tracked_resource_type,
    struct hmap *tracked_datapaths);
struct tracked_datapath *tracked_datapath_find(
    struct hmap *tracked_datapaths, const struct sbrec_datapath_binding *);
void tracked_datapath_lport_add(const struct sbrec_port_binding *,
                                enum en_tracked_resource_type,
                                struct hmap *tracked_datapaths);
void tracked_datapaths_destroy(struct hmap *tracked_datapaths);

/* Maps from a chassis to the OpenFlow port number of the tunnel that can be
 * used to reach that chassis. */
struct chassis_tunnel {
    struct hmap_node hmap_node;
    char *chassis_id;
    ofp_port_t ofport;
    enum chassis_tunnel_type type;
};

void local_nonvif_data_run(const struct ovsrec_bridge *br_int,
                           const struct sbrec_chassis *,
                           struct simap *patch_ofports,
                           struct hmap *chassis_tunnels);

bool local_nonvif_data_handle_ovs_iface_changes(
    const struct ovsrec_interface_table *);

struct chassis_tunnel *chassis_tunnel_find(const struct hmap *chassis_tunnels,
                                           const char *chassis_id,
                                           char *encap_ip);

bool get_chassis_tunnel_ofport(const struct hmap *chassis_tunnels,
                               const char *chassis_name, char *encap_ip,
                               ofp_port_t *ofport);

void chassis_tunnels_destroy(struct hmap *chassis_tunnels);

#endif /* controller/local_data.h */
