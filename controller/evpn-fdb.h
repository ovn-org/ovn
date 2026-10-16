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

#ifndef EVPN_FDB_H
#define EVPN_FDB_H 1

#include <stdint.h>

#include "hmapx.h"
#include "openvswitch/hmap.h"
#include "uuidset.h"
#include "vec.h"

struct unixctl_conn;

struct evpn_fdb_ctx_in {
    /* Contains 'struct evpn_binding'. */
    const struct hmap *bindings;
    /* Contains 'struct evpn_static_entry', one for each FDB. */
    const struct hmap *static_fdbs;
    /* Contains 'struct nexthop_entry'. */
    const struct hmap *nexthops;
    /* Contains 'struct evpn_datapath'. */
    const struct hmap *datapaths;
};

struct evpn_fdb_ctx_out {
    /* Contains 'struct evpn_fdb'. */
    struct hmap *fdbs;
    /* Contains pointers to 'struct evpn_fdb'. */
    struct hmapx *updated_fdbs;
    /* Contains 'flow_uuid' from removed 'struct evpn_fdb'. */
    struct uuidset *removed_fdbs;
};

struct evpn_fdb_path {
    uint32_t binding_key;
    /* Nexthop weight from the kernel nexthop group.
     * 0 for single-path entries (no ECMP). */
    uint16_t weight;
    /* Must be zero; memcmp-based equality depends on it. */
    uint16_t pad;
};

struct evpn_fdb {
    struct hmap_node hmap_node;
    /* UUID used to identify physical flows related to this FDB. */
    struct uuid flow_uuid;
    /* MAC address of the remote workload. */
    struct eth_addr mac;
    uint32_t vni;
    uint32_t dp_key;
    /* Contains 'struct evpn_fdb_path', one per ECMP path.
     * For single-path entries len == 1. */
    struct vector paths;
    /* Fields of the ECMP select group for selection_method=hash, NULL for
     * selection_method=dp_hash. */
    char *hash_fields;
};

void evpn_fdb_run(const struct evpn_fdb_ctx_in *, struct evpn_fdb_ctx_out *);
void evpn_fdbs_destroy(struct hmap *fdbs);
void evpn_fdb_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *data_);

#endif /* EVPN_FDB_H */
