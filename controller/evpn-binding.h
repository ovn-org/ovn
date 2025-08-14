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

#ifndef EVPN_BINDING_H
#define EVPN_BINDING_H 1

#include <stdint.h>

#include "hmapx.h"
#include "openvswitch/hmap.h"
#include "uuidset.h"

struct ovsrec_bridge;
struct unixctl_conn;

struct evpn_binding_ctx_in {
    const struct ovsrec_bridge *br_int;
    /* Contains 'struct local_datapath'. */
    const struct hmap *local_datapaths;
    /* Contains 'struct evpn_remote_vtep'. */
    const struct hmap *remote_vteps;
};

struct evpn_binding_ctx_out {
    /* Contains 'struct evpn_binding'. */
    struct hmap *bindings;
    /* Contains pointers to 'struct evpn_binding'. */
    struct hmapx *updated_bindings;
    /* Contains 'flow_uuid' from removed 'struct evpn_binding'. */
    struct uuidset *removed_bindings;
    /* Contains 'struct evpn_multicast_group'. */
    struct hmap *multicast_groups;
    /* Contains pointers to 'struct evpn_multicast_group'. */
    struct hmapx *updated_multicast_groups;
    /* Contains 'flow_uuid' from removed 'struct evpn_multicast_group'. */
    struct uuidset *removed_multicast_groups;
    /* Contains 'struct tnlid_node". */
    struct hmap *tunnel_keys;
};

struct evpn_binding {
    struct hmap_node hmap_node;
    /* UUID used to identify physical flows related to this binding. */
    struct uuid flow_uuid;
    /* IP address of the remote VTEP. */
    struct in6_addr remote_ip;
    uint32_t vni;
    /* Local tunnel key to identify the binding. */
    uint32_t binding_key;

    ofp_port_t tunnel_ofport;
    uint32_t dp_key;
};

struct evpn_multicast_group {
    struct hmap_node hmap_node;
    /* UUID used to identify physical flows related to this mutlicast group. */
    struct uuid flow_uuid;
    /* Contains pointers to 'struct evpn_bindings'. */
    struct hmapx bindings;
    uint32_t vni;
};

void evpn_binding_run(const struct evpn_binding_ctx_in *,
                      struct evpn_binding_ctx_out *);
struct evpn_binding *evpn_binding_find(const struct hmap *evpn_bindings,
                                       const struct in6_addr *remote_ip,
                                       uint32_t vni);
void evpn_bindings_destroy(struct hmap *bindings);
void evpn_vtep_binding_list(struct unixctl_conn *conn, int argc,
                             const char *argv[], void *data_);
void evpn_multicast_groups_destroy(struct hmap *multicast_groups);
void evpn_multicast_group_list(struct unixctl_conn *conn, int argc,
                                const char *argv[], void *data_);

#endif /* EVPN_BINDING_H */
