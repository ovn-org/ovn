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

#ifndef NEIGHBOR_EXCHANGE_H
#define NEIGHBOR_EXCHANGE_H 1

#include <netinet/in.h>

#include "openvswitch/hmap.h"

#define DEFAULT_VXLAN_PORT 4789

struct unixctl_conn;

struct neighbor_exchange_ctx_in {
    /* Contains struct neighbor_interface_monitor pointers. */
    const struct vector *monitored_interfaces;
};

struct neighbor_exchange_ctx_out {
    /* Contains struct neighbor_table_watch_request. */
    struct hmap neighbor_table_watches;
    /* Contains 'struct evpn_remote_vtep'. */
    struct hmap *remote_vteps;
    /* Contains 'struct evpn_static_fdb'. */
    struct hmap *static_fdbs;
};

struct evpn_remote_vtep {
    struct hmap_node hmap_node;
    /* IP address of the remote tunnel. */
    struct in6_addr ip;
    /* Destination port of the remote tunnel. */
    uint16_t port;
    /* VNI of the VTEP. */
    uint32_t vni;
};

struct evpn_static_fdb {
    struct hmap_node hmap_node;
    /* MAC address of the remote workload. */
    struct eth_addr mac;
    /* Destination ip of the remote tunnel. */
    struct in6_addr ip;
    /* VNI of the VTEP. */
    uint32_t vni;
};

void neighbor_exchange_run(const struct neighbor_exchange_ctx_in *,
                           struct neighbor_exchange_ctx_out *);
int neighbor_exchange_status_run(void);
void evpn_remote_vteps_clear(struct hmap *remote_vteps);
void evpn_remote_vtep_list(struct unixctl_conn *, int argc,
                           const char *argv[], void *data_);
void evpn_static_fdbs_clear(struct hmap *static_fdbs);

#endif  /* NEIGHBOR_EXCHANGE_H */
