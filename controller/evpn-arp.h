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

#ifndef EVPN_ARP_H
#define EVPN_ARP_H 1

#include <stdint.h>

#include "hmapx.h"
#include "local_data.h"
#include "neighbor-of.h"
#include "openvswitch/hmap.h"
#include "uuidset.h"

struct unixctl_conn;

struct evpn_arp_ctx_in {
    /* Contains 'struct evpn_datapath'. */
    const struct hmap *datapaths;
    /* Contains 'struct evpn_static_entry' one for each ARP. */
    const struct hmap *static_arps;
};

struct evpn_arp_ctx_out {
    /* Contains 'struct evpn_arp'. */
    struct hmap *arps;
    /* Contains pointers to 'struct evpn_binding'. */
    struct hmapx *updated_arps;
    /* Contains 'flow_uuid' from removed 'struct evpn_binding'. */
    struct uuidset *removed_arps;
};

struct evpn_arp {
    struct hmap_node hmap_node;
    /* UUID used to identify physical flows related to this ARP entry. */
    struct uuid flow_uuid;
    /* MAC address of the remote workload. */
    struct eth_addr mac;
    /* IP address of the remote workload. */
    struct in6_addr ip;
    uint32_t vni;
    /* Logical datapath of the switch this was learned on. */
    const struct local_datapath *ldp;
    /* Priority to use for this ARP entry at OpenFlow level. */
    enum neigh_of_rule_prio priority;
};

void evpn_arp_run(const struct evpn_arp_ctx_in *, struct evpn_arp_ctx_out *);
void evpn_arps_destroy(struct hmap *arps);
void evpn_arp_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *data_);

#endif /* EVPN_ARP_H */
