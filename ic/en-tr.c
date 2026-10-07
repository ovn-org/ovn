/*
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

#include "en-az.h"
#include "en-tr.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-nb-idl.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovn-ic.h"
#include "ovsdb-idl.h"
#include "smap.h"
#include "util.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(en_ic_tr);

/* Builds 'isb_tr_dps': the committed IC-SB transit-router Datapath_Bindings
 * keyed by NB IC UUID string.  Read-only; used to copy each committed tunnel
 * key into its NB Logical_Router mirror's options:requested-tnl-key.  This is
 * en_tr's own local data, rebuilt each run and never mutated by another node.
 */
static void
collect_tr_datapaths(struct ic_context *ctx, struct shash *isb_tr_dps)
{
    shash_init(isb_tr_dps);

    const struct icsbrec_datapath_binding *isb_dp;
    ICSBREC_DATAPATH_BINDING_FOR_EACH (isb_dp, ctx->ovnisb_idl) {
        if (ic_dp_get_type(isb_dp) == IC_ROUTER) {
            if (!isb_dp->nb_ic_uuid) {
                /* Not inserted by ovn-ic: nothing to reconcile. */
                continue;
            }
            char *uuid_str = uuid_to_string(isb_dp->nb_ic_uuid);
            shash_add(isb_tr_dps, uuid_str, isb_dp);
            free(uuid_str);
        }
    }
}

/* Syncs transit routers to their AZ NB Logical_Router mirrors: creates the
 * mirror if missing, and copies each committed IC-SB Datapath_Binding tunnel
 * key into options:requested-tnl-key.  IC-SB Datapath_Binding creation/keying/
 * GC is owned by en_tunnel_key. */
static void
tr_run(struct ic_context *ctx, struct shash *isb_tr_dps)
{
    if (!ctx->ovnnb_txn) {
        return;
    }

    const struct nbrec_logical_router *lr;
    struct shash nb_tres = SHASH_INITIALIZER(&nb_tres);
    NBREC_LOGICAL_ROUTER_FOR_EACH (lr, ctx->ovnnb_idl) {
        const char *tr_name = smap_get(&lr->options, "interconn-tr");
        if (tr_name) {
            shash_add(&nb_tres, tr_name, lr);
        }
    }

    const struct icnbrec_transit_router *tr;
    ICNBREC_TRANSIT_ROUTER_FOR_EACH (tr, ctx->ovninb_idl) {
        lr = shash_find_and_delete(&nb_tres, tr->name);
        if (!lr) {
            lr = nbrec_logical_router_insert(ctx->ovnnb_txn);
            nbrec_logical_router_set_name(lr, tr->name);
            nbrec_logical_router_update_options_setkey(
                lr, "interconn-tr", tr->name);
        }
        char *uuid_str = uuid_to_string(&tr->header_.uuid);
        const struct icsbrec_datapath_binding *isb_dp =
            shash_find_data(isb_tr_dps, uuid_str);
        free(uuid_str);

        if (isb_dp) {
            char *tnl_key_str = xasprintf("%"PRId64, isb_dp->tunnel_key);
            nbrec_logical_router_update_options_setkey(
                lr, "requested-tnl-key", tnl_key_str);
            free(tnl_key_str);
        }
    }

    struct shash_node *node;
    SHASH_FOR_EACH (node, &nb_tres) {
        nbrec_logical_router_delete(node->data);
    }
    shash_destroy(&nb_tres);
}

enum engine_node_state
en_tr_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    const struct ed_type_az *az = engine_get_input_data("az", node);

    /* runned_az is resolved by the upstream en_az node.  Without an AZ there
     * is nothing to sync (mirrors the previous main-loop gating). */
    if (!az->runned_az) {
        return EN_UNCHANGED;
    }

    struct shash isb_tr_dps;
    collect_tr_datapaths(ctx, &isb_tr_dps);
    tr_run(ctx, &isb_tr_dps);
    shash_destroy(&isb_tr_dps);

    return EN_UPDATED;
}

void *
en_tr_init(struct engine_node *node OVS_UNUSED,
           struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_tr_cleanup(void *data OVS_UNUSED)
{
}
