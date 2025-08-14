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

struct unixctl_conn;

struct evpn_fdb_ctx_in {
    /* Contains 'struct evpn_binding'. */
    const struct hmap *bindings;
    /* Contains 'struct evpn_static_fdb'. */
    const struct hmap *static_fdbs;
};

struct evpn_fdb_ctx_out {
    /* Contains 'struct evpn_fdb'. */
    struct hmap *fdbs;
    /* Contains pointers to 'struct evpn_binding'. */
    struct hmapx *updated_fdbs;
    /* Contains 'flow_uuid' from removed 'struct evpn_binding'. */
    struct uuidset *removed_fdbs;
};

struct evpn_fdb {
    struct hmap_node hmap_node;
    /* UUID used to identify physical flows related to this FDB. */
    struct uuid flow_uuid;
    /* IP address of the remote VTEP. */
    struct eth_addr mac;
    /* Local tunnel key to identify the binding. */
    uint32_t binding_key;
    uint32_t dp_key;
};

void evpn_fdb_run(const struct evpn_fdb_ctx_in *, struct evpn_fdb_ctx_out *);
void evpn_fdbs_destroy(struct hmap *fdbs);
void evpn_fdb_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *data_);

#endif /* EVPN_FDB_H */
