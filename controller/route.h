/*
 * Copyright (c) 2025, Canonical, Ltd.
 * Copyright (c) 2025, STACKIT GmbH & Co. KG
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

#ifndef ROUTE_H
#define ROUTE_H 1

#include <stdbool.h>
#include <netinet/in.h>
#include <net/if.h>
#include "openvswitch/hmap.h"
#include "sset.h"
#include "smap.h"

struct hmap;
struct ovsdb_idl_index;
struct sbrec_chassis;
struct sbrec_port_binding;

struct route_ctx_in {
    const struct sbrec_advertised_route_table *advertised_route_table;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    const struct sbrec_chassis *chassis;
    const char *dynamic_routing_port_mapping;
    const struct sset *active_tunnels;
    const struct hmap *local_datapaths;
    struct shash *local_bindings;
};

struct route_ctx_out {
    struct hmap *tracked_re_datapaths;

    /* Contains the tracked_ports that in the last run were bound locally. */
    struct sset *tracked_ports_local;

    /* Contains the tracked_ports that in the last run were not bound
     * locally. */
    struct sset *tracked_ports_remote;

    /* Contains struct advertise_datapath_entry */
    struct hmap *announce_routes;
};

struct advertise_datapath_entry {
    struct hmap_node node;

    const struct sbrec_datapath_binding *db;
    bool maintain_vrf;
    char vrf_name[IFNAMSIZ + 1];
    struct hmap routes;

    /* The name of the port bindings locally bound for this datapath and
     * running route exchange logic.
     * The key is the port name and the value is the ifname if set. This may
     * be empty if the all ports specified dynamic-routing-port-name, but no
     * such referenced port is local. In this case we should only advertise
     * routes but not learn them. */
    struct smap bound_ports;
};

struct advertise_route_entry {
    struct hmap_node node;
    struct in6_addr addr;
    unsigned int plen;
    unsigned int priority;
};

const struct sbrec_port_binding *route_exchange_find_port(
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct sbrec_chassis *chassis,
    const struct sset *active_tunnels,
    const struct sbrec_port_binding *pb);
bool route_exchange_relevant_port(const struct sbrec_port_binding *);
uint32_t advertise_route_hash(const struct in6_addr *dst, unsigned int plen);
void route_run(struct route_ctx_in *, struct route_ctx_out *);
void route_cleanup(struct hmap *announce_routes);

#endif /* ROUTE_H */
