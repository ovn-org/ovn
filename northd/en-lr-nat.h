/*
 * Copyright (c) 2024, Red Hat, Inc.
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
#ifndef EN_LR_NAT_H
#define EN_LR_NAT_H 1

#include <stdint.h>

/* OVS includes. */
#include "lib/hmapx.h"
#include "openvswitch/hmap.h"
#include "sset.h"

/* OVN includes. */
#include "lib/inc-proc-eng.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"

enum ovn_nat_type {
    SNAT,
    DNAT,
    DNAT_AND_SNAT,
};

/* Contains a NAT entry with the external addresses pre-parsed. */
struct ovn_nat {
    const struct nbrec_nat *nb;
    struct lport_addresses ext_addrs; /* Parsed NB.NAT.external_ip. */
    struct eth_addr mac;              /* Parsed NB.NAT.external_mac. */
    int logical_ip_cidr_bits;         /* Parsed NB.NATlogical_ip prefix len. */
    struct ovs_list ext_addr_list_node; /* Linkage in the per-external IP
                                         * list of nat entries. Currently
                                         * only used for SNAT.
                                         */
    bool is_router_ip; /* Indicates if the NAT external_ip is also one of
                        * router's lrp ip.  Can be 'true' only for SNAT. */

    struct ovn_port *l3dgw_port; /* If non-NULL, the distributed gateway port
                                  * this NAT will use.  NULL for gateway
                                  * routers. */
    bool is_distributed;         /* True if this NAT record is fully
                                  * distributed. */
    bool is_valid; /* True if the configuration of this entry is valid. */
    enum ovn_nat_type type;
};

/* Stores the list of SNAT entries referencing a unique SNAT IP address.
 * The 'snat_entries' list will be empty if the SNAT IP is used only for
 * dnat_force_snat_ip or lb_force_snat_ip.
 */
struct ovn_snat_ip {
    struct ovs_list snat_entries;
};

struct lr_nat_record {
    struct hmap_node key_node;  /* Index on 'nbr->header_.uuid'. */

    /* UUID of the NB Logical Router. */
    struct uuid nbr_uuid;

    /* Unique id of the logical router.  Note : This id is assigned
     * by the northd engine node for each logical router. */
    size_t lr_index;

    struct ovn_nat *nat_entries;
    size_t n_nat_entries;

    bool has_distributed_nat;

    /* Set of nat external ips on the router. */
    struct sset external_ips;

    /* Set of nat external macs on the router. */
    struct sset external_macs;

    /* SNAT IPs owned by the router (shash of 'struct ovn_snat_ip'). */
    struct shash snat_ips;

    struct lport_addresses dnat_force_snat_addrs;
    struct lport_addresses lb_force_snat_addrs;
    bool lb_force_snat_router_ip;
};

struct lr_nat_tracked_data {
    /* Created or updated logical router with NAT data. */
    struct hmapx crupdated;
};

struct lr_nat_table {
    struct hmap entries; /* Stores struct lr_nat_record. */

    /* The array index of each element in 'entries'. */
    struct lr_nat_record **array;
};

const struct lr_nat_record * lr_nat_table_find_by_index(
    const struct lr_nat_table *, size_t od_index);

#define LR_NAT_TABLE_FOR_EACH(LR_NAT_REC, TABLE) \
    HMAP_FOR_EACH (LR_NAT_REC, key_node, &(TABLE)->entries)

struct ed_type_lr_nat_data {
    struct lr_nat_table lr_nats;

    struct lr_nat_tracked_data trk_data;
};

void *en_lr_nat_init(struct engine_node *, struct engine_arg *);
void en_lr_nat_cleanup(void *data);
void en_lr_nat_clear_tracked_data(void *data);
enum engine_node_state en_lr_nat_run(struct engine_node *, void *data);

enum engine_input_handler_result lr_nat_northd_handler(struct engine_node *,
                                                       void *data);

static inline bool
nat_entry_is_v6(const struct ovn_nat *nat_entry)
{
    return nat_entry->ext_addrs.n_ipv6_addrs > 0;
}

static inline bool
lr_nat_has_tracked_data(struct lr_nat_tracked_data *trk_data) {
    return !hmapx_is_empty(&trk_data->crupdated);
}

#endif /* EN_LR_NAT_H */
