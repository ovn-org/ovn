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
#include "openvswitch/hmap.h"
#include "sset.h"

struct hmap;
struct ovsdb_idl_index;
struct sbrec_chassis;
struct sbrec_port_binding;

struct route_ctx_in {
    const struct sbrec_advertised_route_table *advertised_route_table;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    const struct sbrec_chassis *chassis;
    const struct sset *active_tunnels;
    const struct hmap *local_datapaths;
    const struct sset *local_lports;
};

struct route_ctx_out {
    struct hmap *tracked_re_datapaths;

    /* Contains struct advertise_datapath_entry */
    struct hmap *announce_routes;
};

struct advertise_datapath_entry {
    struct hmap_node node;

    const struct sbrec_datapath_binding *db;
    bool maintain_vrf;
    struct hmap routes;

    /* The name of the port bindings locally bound for this datapath and
     * running route exchange logic. */
    struct sset bound_ports;
};

struct advertise_route_entry {
    struct hmap_node node;
    struct in6_addr addr;
    unsigned int plen;
};

bool route_exchange_relevant_port(const struct sbrec_port_binding *);
uint32_t advertise_route_hash(const struct in6_addr *dst, unsigned int plen);
void route_run(struct route_ctx_in *, struct route_ctx_out *);
void route_cleanup(struct hmap *announce_routes);

#endif /* ROUTE_H */
