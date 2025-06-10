/*
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

#include "vswitch-idl.h"
#ifndef GARP_RARP_H
#define GARP_RARP_H 1

#include "cmap.h"
#include "sset.h"
#include "openvswitch/types.h"

/* Contains a single mac and ip address that should be announced. */
struct garp_rarp_node {
    struct cmap_node cmap_node;
    struct eth_addr ea;          /* Ethernet address of port. */
    ovs_be32 ipv4;               /* Ipv4 address of port. */
    atomic_llong announce_time;  /* Next announcement in ms.
                                  * If LLONG_MAX there should be no
                                  * annoucement. */
    atomic_int backoff;          /* Backoff timeout for the next
                                  * announcement (in msecs). */
    uint32_t dp_key;             /* Datapath used to output this GARP. */
    uint32_t port_key;           /* Port to inject the GARP into. */
    bool stale;                  /* Used during sync to remove stale
                                  * information. */
};

/* Contains all required data for pinctrl to actually send garps. */
struct garp_rarp_data {
    struct cmap data;

    long long int max_timeout;
    bool continuous;
};

struct garp_rarp_ctx_in {
    struct ovsdb_idl_txn *ovnsb_idl_txn;
    const struct ovsrec_open_vswitch *cfg;
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip;
    const struct sbrec_ecmp_nexthop_table *ecmp_nh_table;
    const struct sbrec_chassis *chassis;
    const struct hmap *local_datapaths;
    const struct sset *active_tunnels;
    struct ed_type_garp_rarp *data;
};

struct ed_type_garp_rarp {
    /* non_local_lports and local_lports are used in the incremental handlers
     * to trigger updates if such a port changes. */
    struct sset non_local_lports; /* lports that we did not consider because
                                     they where not local. */
    struct sset local_lports; /* lports where we did consider the addresses
                                 because they where local. */
};

void garp_rarp_run(struct garp_rarp_ctx_in *);
void garp_rarp_node_free(struct garp_rarp_node *);
const struct garp_rarp_data *garp_rarp_get_data(void);
bool garp_rarp_data_changed(void);

struct ed_type_garp_rarp *garp_rarp_init(void);
void garp_rarp_cleanup(struct ed_type_garp_rarp *);

#endif /* GARP_RARP_H */
