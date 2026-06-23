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

#include <config.h>

#include <string.h>

#include "evpn-binding.h"
#include "local_data.h"
#include "neighbor-exchange.h"
#include "nexthop-exchange.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovn-sb-idl.h"
#include "packets.h"
#include "unixctl.h"

#include "evpn-fdb.h"

VLOG_DEFINE_THIS_MODULE(evpn_fdb);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

static struct evpn_fdb *evpn_fdb_add(struct hmap *evpn_fdbs, struct eth_addr,
                                     uint32_t vni);
static struct evpn_fdb *evpn_fdb_find(const struct hmap *evpn_fdbs,
                                      struct eth_addr, uint32_t vni);
static uint32_t evpn_fdb_hash(const struct eth_addr *mac, uint32_t vni);

static int
evpn_fdb_path_cmp(const void *a, const void *b)
{
    const struct evpn_fdb_path *pa = a;
    const struct evpn_fdb_path *pb = b;

    if (pa->binding_key != pb->binding_key) {
        return pa->binding_key < pb->binding_key ? -1 : 1;
    }

    if (pa->weight != pb->weight) {
        return pa->weight < pb->weight ? -1 : 1;
    }

    return 0;
}

/* Build a sorted vector of paths for 'static_fdb'.
 * For single-path entries (nh_id == 0), looks up a single binding by IP.
 * For ECMP entries (nh_id != 0), resolves the nexthop group and collects
 * one path per gateway, preserving nexthop weights. */
static void
evpn_fdb_resolve_paths(const struct evpn_fdb_ctx_in *f_ctx_in,
                       const struct evpn_static_entry *static_fdb,
                       struct vector *paths)
{
    if (!static_fdb->nh_id) {
        /* Single-path: direct VTEP IP. */
        const struct evpn_binding *binding =
            evpn_binding_find(f_ctx_in->bindings, &static_fdb->ip,
                              static_fdb->vni);
        if (!binding) {
            return;
        }
        struct evpn_fdb_path path = {
            .binding_key = binding->binding_key,
            .weight = 0,
        };
        vector_push(paths, &path);
        return;
    }

    /* ECMP: resolve nexthop group to multiple paths. */
    const struct nexthop_entry *nhe =
        nexthop_entry_find(f_ctx_in->nexthops, static_fdb->nh_id);
    if (!nhe) {
        VLOG_WARN_RL(&rl, "Couldn't find nexthop %"PRIu32" for "
                     ETH_ADDR_FMT" MAC address.",
                     static_fdb->nh_id, ETH_ADDR_ARGS(static_fdb->mac));
        return;
    }

    if (!nhe->n_grps) {
        VLOG_WARN_RL(&rl, "Nexthop %"PRIu32" for "
                     ETH_ADDR_FMT" MAC address is not a group.",
                     static_fdb->nh_id, ETH_ADDR_ARGS(static_fdb->mac));
        return;
    }

    for (size_t i = 0; i < nhe->n_grps; i++) {
        const struct nexthop_grp_entry *grp = &nhe->grps[i];
        if (!grp->gateway) {
            continue;
        }

        const struct evpn_binding *binding =
            evpn_binding_find(f_ctx_in->bindings, &grp->gateway->addr,
                              static_fdb->vni);
        if (!binding) {
            VLOG_WARN_RL(&rl, "Couldn't find EVPN binding for nexthop "
                         "group member %"PRIu32" (gateway id %"PRIu32").",
                         static_fdb->nh_id, grp->id);
            continue;
        }

        struct evpn_fdb_path path = {
            .binding_key = binding->binding_key,
            .weight = grp->weight,
        };
        vector_push(paths, &path);
    }

    /* Sort so that memcmp-based comparison is deterministic. */
    vector_qsort(paths, evpn_fdb_path_cmp);
}

/* Returns true if the paths in 'fdb' match the contents of 'paths'.
 * Caller must ensure 'paths' is non-empty (memcmp with NULL is UB). */
static bool
evpn_fdb_paths_equal(const struct evpn_fdb *fdb,
                     const struct vector *paths)
{
    return vector_len(&fdb->paths) == vector_len(paths)
           && !memcmp(vector_get_array(&fdb->paths),
                      vector_get_array(paths),
                      vector_len(paths) * sizeof(struct evpn_fdb_path));
}

void
evpn_fdb_run(const struct evpn_fdb_ctx_in *f_ctx_in,
             struct evpn_fdb_ctx_out *f_ctx_out)
{
    struct hmapx stale_fdbs = HMAPX_INITIALIZER(&stale_fdbs);

    struct evpn_fdb *fdb;
    HMAP_FOR_EACH (fdb, hmap_node, f_ctx_out->fdbs) {
        hmapx_add(&stale_fdbs, fdb);
    }

    struct vector paths = VECTOR_EMPTY_INITIALIZER(struct evpn_fdb_path);

    const struct evpn_static_entry *static_fdb;
    HMAP_FOR_EACH (static_fdb, hmap_node, f_ctx_in->static_fdbs) {
        vector_clear(&paths);

        evpn_fdb_resolve_paths(f_ctx_in, static_fdb, &paths);
        if (vector_is_empty(&paths)) {
            VLOG_WARN_RL(&rl, "Couldn't resolve EVPN bindings for "
                         ETH_ADDR_FMT" MAC address.",
                         ETH_ADDR_ARGS(static_fdb->mac));
            continue;
        }

        const struct evpn_datapath *edp =
            evpn_datapath_find(f_ctx_in->datapaths, static_fdb->vni);
        if (!edp) {
            VLOG_WARN_RL(&rl, "Couldn't find EVPN datapath for VNI %"PRIu32
                         " ("ETH_ADDR_FMT" MAC address).",
                         static_fdb->vni, ETH_ADDR_ARGS(static_fdb->mac));
            continue;
        }
        uint32_t dp_key = edp->ldp->datapath->tunnel_key;

        fdb = evpn_fdb_find(f_ctx_out->fdbs, static_fdb->mac, static_fdb->vni);
        if (!fdb) {
            fdb = evpn_fdb_add(f_ctx_out->fdbs, static_fdb->mac,
                               static_fdb->vni);
        }

        bool updated = false;
        if (!evpn_fdb_paths_equal(fdb, &paths)) {
            vector_clear(&fdb->paths);
            vector_push_array(&fdb->paths,
                              vector_get_array(&paths),
                              vector_len(&paths));
            updated = true;
        }

        if (fdb->dp_key != dp_key) {
            fdb->dp_key = dp_key;
            updated = true;
        }

        if (updated) {
            hmapx_add(f_ctx_out->updated_fdbs, fdb);
        }

        hmapx_find_and_delete(&stale_fdbs, fdb);
    }

    vector_destroy(&paths);

    struct hmapx_node *node;
    HMAPX_FOR_EACH (node, &stale_fdbs) {
        fdb = node->data;

        uuidset_insert(f_ctx_out->removed_fdbs, &fdb->flow_uuid);
        hmap_remove(f_ctx_out->fdbs, &fdb->hmap_node);
        vector_destroy(&fdb->paths);
        free(fdb);
    }

    hmapx_destroy(&stale_fdbs);
}

void
evpn_fdbs_destroy(struct hmap *fdbs)
{
    struct evpn_fdb *fdb;
    HMAP_FOR_EACH_POP (fdb, hmap_node, fdbs) {
        vector_destroy(&fdb->paths);
        free(fdb);
    }
    hmap_destroy(fdbs);
}

void
evpn_fdb_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[] OVS_UNUSED, void *data_)
{
    struct hmap *fdbs = data_;
    struct ds ds = DS_EMPTY_INITIALIZER;

    const struct evpn_fdb *fdb;
    HMAP_FOR_EACH (fdb, hmap_node, fdbs) {
        ds_put_format(&ds, "UUID: "UUID_FMT", MAC: "ETH_ADDR_FMT", "
                      "vni: %"PRIu32", ", UUID_ARGS(&fdb->flow_uuid),
                      ETH_ADDR_ARGS(fdb->mac), fdb->vni);

        if (vector_len(&fdb->paths) == 1) {
            struct evpn_fdb_path path =
                vector_get(&fdb->paths, 0, struct evpn_fdb_path);
            ds_put_format(&ds, "binding_key: %#"PRIx32", dp_key: %"PRIu32"\n",
                          path.binding_key, fdb->dp_key);
        } else {
            ds_put_format(&ds, "dp_key: %"PRIu32", paths: [", fdb->dp_key);
            for (size_t i = 0; i < vector_len(&fdb->paths); i++) {
                if (i) {
                    ds_put_cstr(&ds, ", ");
                }
                struct evpn_fdb_path path =
                    vector_get(&fdb->paths, i, struct evpn_fdb_path);
                ds_put_format(&ds, "{key=%#"PRIx32", weight=%"PRIu16"}",
                              path.binding_key, path.weight);
            }
            ds_put_cstr(&ds, "]\n");
        }
    }

    unixctl_command_reply(conn, ds_cstr_ro(&ds));
    ds_destroy(&ds);
}

static struct evpn_fdb *
evpn_fdb_add(struct hmap *evpn_fdbs, struct eth_addr mac, uint32_t vni)
{
    struct evpn_fdb *fdb = xmalloc(sizeof *fdb);
    *fdb = (struct evpn_fdb) {
        .flow_uuid = uuid_random(),
        .mac = mac,
        .vni = vni,
        .paths = VECTOR_EMPTY_INITIALIZER(struct evpn_fdb_path),
    };

    uint32_t hash = evpn_fdb_hash(&mac, vni);
    hmap_insert(evpn_fdbs, &fdb->hmap_node, hash);

    return fdb;
}

static struct evpn_fdb *
evpn_fdb_find(const struct hmap *evpn_fdbs, struct eth_addr mac, uint32_t vni)
{
    uint32_t hash = evpn_fdb_hash(&mac, vni);

    struct evpn_fdb *fdb;
    HMAP_FOR_EACH_WITH_HASH (fdb, hmap_node, hash, evpn_fdbs) {
        if (eth_addr_equals(fdb->mac, mac) &&
            fdb->vni == vni) {
            return fdb;
        }
    }

    return NULL;
}

static uint32_t
evpn_fdb_hash(const struct eth_addr *mac, uint32_t vni)
{
    uint32_t hash = 0;
    hash = hash_bytes(mac, sizeof *mac, hash);
    hash = hash_add(hash, vni);

    return hash_finish(hash, 10);
}
