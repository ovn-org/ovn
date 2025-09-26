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

#include "evpn-binding.h"
#include "neighbor-exchange.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "unixctl.h"

#include "evpn-fdb.h"

VLOG_DEFINE_THIS_MODULE(evpn_fdb);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

static struct evpn_fdb *evpn_fdb_add(struct hmap *evpn_fdbs, struct eth_addr);
static struct evpn_fdb *evpn_fdb_find(const struct hmap *evpn_fdbs,
                                      struct eth_addr);

void
evpn_fdb_run(const struct evpn_fdb_ctx_in *f_ctx_in,
             struct evpn_fdb_ctx_out *f_ctx_out)
{
    struct hmapx stale_fdbs = HMAPX_INITIALIZER(&stale_fdbs);

    struct evpn_fdb *fdb;
    HMAP_FOR_EACH (fdb, hmap_node, f_ctx_out->fdbs) {
        hmapx_add(&stale_fdbs, fdb);
    }

    const struct evpn_static_entry *static_fdb;
    HMAP_FOR_EACH (static_fdb, hmap_node, f_ctx_in->static_fdbs) {
        const struct evpn_binding *binding =
            evpn_binding_find(f_ctx_in->bindings, &static_fdb->ip,
                              static_fdb->vni);
        if (!binding) {
            VLOG_WARN_RL(&rl, "Couldn't find EVPN binding for "ETH_ADDR_FMT" "
                         "MAC address.", ETH_ADDR_ARGS(static_fdb->mac));
            continue;
        }

        fdb = evpn_fdb_find(f_ctx_out->fdbs, static_fdb->mac);
        if (!fdb) {
            fdb = evpn_fdb_add(f_ctx_out->fdbs, static_fdb->mac);
        }

        bool updated = false;
        if (fdb->binding_key != binding->binding_key) {
            fdb->binding_key = binding->binding_key;
            updated = true;
        }

        if (fdb->dp_key != binding->dp_key) {
            fdb->dp_key = binding->dp_key;
            updated = true;
        }

        if (updated) {
            hmapx_add(f_ctx_out->updated_fdbs, fdb);
        }

        hmapx_find_and_delete(&stale_fdbs, fdb);
    }

    struct hmapx_node *node;
    HMAPX_FOR_EACH (node, &stale_fdbs) {
        fdb = node->data;

        uuidset_insert(f_ctx_out->removed_fdbs, &fdb->flow_uuid);
        hmap_remove(f_ctx_out->fdbs, &fdb->hmap_node);
        free(fdb);
    }

    hmapx_destroy(&stale_fdbs);
}

void
evpn_fdbs_destroy(struct hmap *fdbs)
{
    struct evpn_fdb *fdb;
    HMAP_FOR_EACH_POP (fdb, hmap_node, fdbs) {
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
                      "binding_key: %#"PRIx32", dp_key: %"PRIu32"\n",
                      UUID_ARGS(&fdb->flow_uuid), ETH_ADDR_ARGS(fdb->mac),
                      fdb->binding_key, fdb->dp_key);
    }

    unixctl_command_reply(conn, ds_cstr_ro(&ds));
    ds_destroy(&ds);
}

static struct evpn_fdb *
evpn_fdb_add(struct hmap *evpn_fdbs, struct eth_addr mac)
{
    struct evpn_fdb *fdb = xmalloc(sizeof *fdb);
    *fdb = (struct evpn_fdb) {
        .flow_uuid = uuid_random(),
        .mac = mac,
        .binding_key = 0,
        .dp_key = 0,
    };

    uint32_t hash = hash_bytes(&mac, sizeof mac, 0);
    hmap_insert(evpn_fdbs, &fdb->hmap_node, hash);

    return fdb;
}

static struct evpn_fdb *
evpn_fdb_find(const struct hmap *evpn_fdbs, struct eth_addr mac)
{
    uint32_t hash = hash_bytes(&mac, sizeof mac, 0);

    struct evpn_fdb *fdb;
    HMAP_FOR_EACH_WITH_HASH (fdb, hmap_node, hash, evpn_fdbs) {
        if (eth_addr_equals(fdb->mac, mac)) {
            return fdb;
        }
    }

    return NULL;
}
