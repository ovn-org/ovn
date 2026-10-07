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

#include "en-tunnel-key.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-util.h"
#include "openvswitch/hmap.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovn-ic.h"
#include "ovsdb-idl.h"
#include "smap.h"
#include "sset.h"
#include "util.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(en_ic_tunnel_key);

/* Returns true if 'key' falls in the global VXLAN datapath tunnel-key range.
*/
static bool
dp_key_in_vxlan_range(int64_t key)
{
    return key >= OVN_MIN_DP_VXLAN_KEY_GLOBAL &&
           key <= OVN_MAX_DP_VXLAN_KEY_GLOBAL;
}

/* Rebuilds the tunnel-key allocator 'data->dp_tnlids' and, in 'isb_ts_dps'
 * (keyed by transit-switch name) / 'isb_tr_dps' (keyed by NB IC UUID string),
 * every committed IC-SB Datapath_Binding.  Read from the locked IC-SB IDL,
 * which is the same IDL this node writes to and reads back from, so no
 * locked/unlocked bridging is needed: the tracked changes (from the unlocked
 * IDL) are used only to scope which entities to reconcile, never to mutate
 * state directly. */
static void
tunnel_key_build_state(struct ic_context *ctx, struct ed_type_tunnel_key *data,
                       struct shash *isb_ts_dps, struct shash *isb_tr_dps)
{
    ovn_destroy_tnlids(&data->dp_tnlids);
    hmap_init(&data->dp_tnlids);
    shash_init(isb_ts_dps);
    shash_init(isb_tr_dps);

    const struct icsbrec_datapath_binding *isb_dp;
    ICSBREC_DATAPATH_BINDING_FOR_EACH (isb_dp, ctx->ovnisb_idl) {
        ovn_add_tnlid(&data->dp_tnlids, isb_dp->tunnel_key);
        if (ic_dp_get_type(isb_dp) == IC_ROUTER) {
            if (!isb_dp->nb_ic_uuid) {
                /* Not inserted by ovn-ic: nothing to reconcile. */
                continue;
            }
            char *uuid_str = uuid_to_string(isb_dp->nb_ic_uuid);
            shash_add(isb_tr_dps, uuid_str, isb_dp);
            free(uuid_str);
        } else {
            shash_add(isb_ts_dps, isb_dp->transit_switch, isb_dp);
        }
    }
}

/* Publishes 'dp_key' to the AZ NB Logical_Switch mirror of transit switch
 * 'ts_name' ('nb_ts_mirrors', keyed by name), when the mirror exists. */
static void
tunnel_key_publish_ts_mirror(struct shash *nb_ts_mirrors, const char *ts_name,
                             int64_t dp_key)
{
    const struct nbrec_logical_switch *ls =
        shash_find_data(nb_ts_mirrors, ts_name);
    if (!ls) {
        return;
    }

    char *tnl_key_str = xasprintf("%"PRId64, dp_key);
    nbrec_logical_switch_update_other_config_setkey(ls, "requested-tnl-key",
                                                    tnl_key_str);
    free(tnl_key_str);
}

/* Reconciles one transit switch 'ts's IC-SB Datapath_Binding: creates it (with
 * a fresh globally-unique tunnel key) when 'isb_dp' is NULL, reallocates its
 * key if the encap (VXLAN) mode changed its range, and back-fills the type /
 * nb_ic_uuid columns.  Whenever a key is allocated - on creation and on
 * reallocation alike - it is published to the AZ NB Logical_Switch mirror in
 * this same iteration.  Leaving the mirror to a later run is not safe: the
 * committed key only reaches en_ts on a following engine run, and nothing
 * guarantees one happens after the IC-SB transaction lands, so the mirror can
 * keep a key from the wrong range indefinitely. */
static void
tunnel_key_reconcile_ts(struct ic_context *ctx,
                        struct ed_type_tunnel_key *data,
                        const struct icnbrec_transit_switch *ts,
                        const struct icsbrec_datapath_binding *isb_dp,
                        struct shash *nb_ts_mirrors, bool vxlan_mode)
{
    if (!isb_dp) {
        int64_t dp_key = allocate_dp_key(&data->dp_tnlids, vxlan_mode,
                                         "transit switch datapath");
        if (!dp_key) {
            return;
        }
        struct icsbrec_datapath_binding *new_dp =
            icsbrec_datapath_binding_insert(ctx->ovnisb_txn);
        icsbrec_datapath_binding_set_transit_switch(new_dp, ts->name);
        icsbrec_datapath_binding_set_tunnel_key(new_dp, dp_key);
        icsbrec_datapath_binding_set_type(new_dp, "transit-switch");
        icsbrec_datapath_binding_set_nb_ic_uuid(new_dp, &ts->header_.uuid, 1);

        tunnel_key_publish_ts_mirror(nb_ts_mirrors, ts->name, dp_key);
        return;
    }

    if (dp_key_in_vxlan_range(isb_dp->tunnel_key) != vxlan_mode) {
        int64_t dp_key = allocate_dp_key(&data->dp_tnlids, vxlan_mode,
                                         "transit switch datapath");
        if (dp_key) {
            icsbrec_datapath_binding_set_tunnel_key(isb_dp, dp_key);
            tunnel_key_publish_ts_mirror(nb_ts_mirrors, ts->name, dp_key);
        }
    }
    if (!isb_dp->type) {
        icsbrec_datapath_binding_set_type(isb_dp, "transit-switch");
    }
    if (!isb_dp->nb_ic_uuid) {
        icsbrec_datapath_binding_set_nb_ic_uuid(isb_dp, &ts->header_.uuid, 1);
    }
}

/* Reconciles one transit router 'tr's IC-SB Datapath_Binding: creates it (with
 * a fresh globally-unique tunnel key, always from the non-VXLAN range) when
 * 'isb_dp' is NULL.  Its key reaches the NB Logical_Router mirror on a
 * follow-up iteration (en_tr copies the committed key back). */
static void
tunnel_key_reconcile_tr(struct ic_context *ctx,
                        struct ed_type_tunnel_key *data,
                        const struct icnbrec_transit_router *tr,
                        const struct icsbrec_datapath_binding *isb_dp)
{
    if (isb_dp) {
        return;
    }

    int64_t dp_key = allocate_dp_key(&data->dp_tnlids, false,
                                     "transit router datapath");
    if (!dp_key) {
        return;
    }
    struct icsbrec_datapath_binding *new_dp =
        icsbrec_datapath_binding_insert(ctx->ovnisb_txn);
    icsbrec_datapath_binding_set_tunnel_key(new_dp, dp_key);
    icsbrec_datapath_binding_set_nb_ic_uuid(new_dp, &tr->header_.uuid, 1);
    icsbrec_datapath_binding_set_type(new_dp, "transit-router");
}

/* Builds 'nb_ts_mirrors' (keyed by transit-switch name) from the AZ NB
 * Logical_Switch mirrors.  A table walk (not the by-name index) is used so it
 * sees the mirrors en_ts just inserted in this transaction, which lets a
 * brand-new binding publish its key to the mirror in the same iteration. */
static void
tunnel_key_collect_nb_mirrors(struct ic_context *ctx,
                              struct shash *nb_ts_mirrors)
{
    shash_init(nb_ts_mirrors);
    if (!ctx->ovnnb_txn) {
        return;
    }
    const struct nbrec_logical_switch *ls;
    NBREC_LOGICAL_SWITCH_FOR_EACH (ls, ctx->ovnnb_idl) {
        const char *ts_name = smap_get(&ls->other_config, "interconn-ts");
        if (ts_name && !shash_find(nb_ts_mirrors, ts_name)) {
            shash_add(nb_ts_mirrors, ts_name,
                      CONST_CAST(struct nbrec_logical_switch *, ls));
        }
    }
}

enum engine_node_state
en_tunnel_key_run(struct engine_node *node OVS_UNUSED, void *data_)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    struct ed_type_tunnel_key *data = data_;

    struct shash isb_ts_dps, isb_tr_dps;
    tunnel_key_build_state(ctx, data, &isb_ts_dps, &isb_tr_dps);

    /* The IC-SB Datapath_Binding table is the leader's to write; only touch it
     * (create/refresh/delete) while holding the IC-SB lock. */
    if (ctx->ovnisb_txn && is_az_leader(ctx->ovnisb_txn)) {
        bool vxlan_mode = ic_ts_compute_vxlan_mode(ctx);
        struct shash nb_ts_mirrors;
        tunnel_key_collect_nb_mirrors(ctx, &nb_ts_mirrors);

        const struct icnbrec_transit_switch *ts;
        ICNBREC_TRANSIT_SWITCH_FOR_EACH (ts, ctx->ovninb_idl) {
            const struct icsbrec_datapath_binding *isb_dp =
                shash_find_and_delete(&isb_ts_dps, ts->name);
            tunnel_key_reconcile_ts(ctx, data, ts, isb_dp, &nb_ts_mirrors,
                                    vxlan_mode);
        }

        const struct icnbrec_transit_router *tr;
        ICNBREC_TRANSIT_ROUTER_FOR_EACH (tr, ctx->ovninb_idl) {
            char *uuid_str = uuid_to_string(&tr->header_.uuid);
            const struct icsbrec_datapath_binding *isb_dp =
                shash_find_and_delete(&isb_tr_dps, uuid_str);
            free(uuid_str);
            tunnel_key_reconcile_tr(ctx, data, tr, isb_dp);
        }

        /* Delete IC-SB Datapath_Bindings whose IC-NB entity is gone. */
        struct shash_node *sn;
        SHASH_FOR_EACH (sn, &isb_ts_dps) {
            icsbrec_datapath_binding_delete(sn->data);
        }
        SHASH_FOR_EACH (sn, &isb_tr_dps) {
            icsbrec_datapath_binding_delete(sn->data);
        }

        shash_destroy(&nb_ts_mirrors);
    }

    shash_destroy(&isb_ts_dps);
    shash_destroy(&isb_tr_dps);

    return EN_UPDATED;
}

/* Reconciles only the transit switches named in 'ts_scope' and the transit
 * routers whose NB IC UUID string is in 'tr_scope': creates a missing binding,
 * refreshes a mis-ranged key, and deletes a binding whose IC-NB entity is
 * gone. Returns EN_UNHANDLED (forcing a recompute) when the IC-SB
 * lock/transaction needed to write the binding is not available yet. */
static enum engine_input_handler_result
tunnel_key_sync_scope(struct ic_context *ctx, struct ed_type_tunnel_key *data,
                      struct sset *ts_scope, struct sset *tr_scope)
{
    if (sset_is_empty(ts_scope) && sset_is_empty(tr_scope)) {
        return EN_HANDLED_UNCHANGED;
    }
    if (!ctx->ovnisb_txn || !is_az_leader(ctx->ovnisb_txn)) {
        return EN_UNHANDLED;
    }

    bool vxlan_mode = ic_ts_compute_vxlan_mode(ctx);
    struct shash isb_ts_dps, isb_tr_dps;
    tunnel_key_build_state(ctx, data, &isb_ts_dps, &isb_tr_dps);
    struct shash nb_ts_mirrors;
    tunnel_key_collect_nb_mirrors(ctx, &nb_ts_mirrors);

    /* IC-NB Transit_Switch has no generated get_for_name(); map name -> row so
     * an in-scope transit switch can be looked up. */
    struct shash icnb_ts = SHASH_INITIALIZER(&icnb_ts);
    if (!sset_is_empty(ts_scope)) {
        const struct icnbrec_transit_switch *ts;
        ICNBREC_TRANSIT_SWITCH_FOR_EACH (ts, ctx->ovninb_idl) {
            if (!shash_find(&icnb_ts, ts->name)) {
                shash_add(&icnb_ts, ts->name,
                          CONST_CAST(struct icnbrec_transit_switch *, ts));
            }
        }
    }

    const char *name;
    SSET_FOR_EACH (name, ts_scope) {
        const struct icnbrec_transit_switch *ts =
            shash_find_data(&icnb_ts, name);
        const struct icsbrec_datapath_binding *isb_dp =
            shash_find_data(&isb_ts_dps, name);
        if (ts) {
            tunnel_key_reconcile_ts(ctx, data, ts, isb_dp, &nb_ts_mirrors,
                                    vxlan_mode);
        } else if (isb_dp) {
            icsbrec_datapath_binding_delete(isb_dp);
        }
    }
    shash_destroy(&icnb_ts);

    const char *uuid_str;
    SSET_FOR_EACH (uuid_str, tr_scope) {
        struct uuid tr_uuid;
        if (!uuid_from_string(&tr_uuid, uuid_str)) {
            continue;
        }
        const struct icnbrec_transit_router *tr =
            icnbrec_transit_router_get_for_uuid(ctx->ovninb_idl, &tr_uuid);
        const struct icsbrec_datapath_binding *isb_dp =
            shash_find_data(&isb_tr_dps, uuid_str);
        if (tr) {
            tunnel_key_reconcile_tr(ctx, data, tr, isb_dp);
        } else if (isb_dp) {
            icsbrec_datapath_binding_delete(isb_dp);
        }
    }

    shash_destroy(&nb_ts_mirrors);
    shash_destroy(&isb_ts_dps);
    shash_destroy(&isb_tr_dps);

    return EN_HANDLED_UPDATED;
}

/* IC-NB Transit_Switch: a new transit switch needs its IC-SB Datapath_Binding
 * created; a deleted one needs it garbage-collected.  Both are scoped by name
 * and reconciled without a full recompute.  A rename cannot be scoped (the
 * tracked row only carries the new name, so the binding keyed by the old one
 * would leak) and falls back to a full recompute. */
enum engine_input_handler_result
en_tunnel_key_icnb_transit_switch_handler(struct engine_node *node,
                                          void *data_)
{
    struct ed_type_tunnel_key *data = data_;
    struct ic_context *ctx = engine_get_context()->client_ctx;
    const struct icnbrec_transit_switch_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_switch", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    struct sset tr_scope = SSET_INITIALIZER(&tr_scope);
    bool unhandled = false;
    const struct icnbrec_transit_switch *ts;
    ICNBREC_TRANSIT_SWITCH_TABLE_FOR_EACH_TRACKED (ts, tbl) {
        if (!icnbrec_transit_switch_is_new(ts) &&
            !icnbrec_transit_switch_is_deleted(ts) &&
            ovsdb_idl_track_is_updated(&ts->header_,
                                       &icnbrec_transit_switch_col_name)) {
            unhandled = true;
            break;
        }
        sset_add(&ts_scope, ts->name);
    }

    enum engine_input_handler_result ret =
        unhandled ? EN_UNHANDLED
                  : tunnel_key_sync_scope(ctx, data, &ts_scope, &tr_scope);
    sset_destroy(&ts_scope);
    sset_destroy(&tr_scope);
    return ret;
}

/* IC-NB Transit_Router: analogous to the transit-switch handler, scoped by the
 * transit router's NB IC UUID (the binding key). */
enum engine_input_handler_result
en_tunnel_key_icnb_transit_router_handler(struct engine_node *node,
                                          void *data_)
{
    struct ed_type_tunnel_key *data = data_;
    struct ic_context *ctx = engine_get_context()->client_ctx;
    const struct icnbrec_transit_router_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_router", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    struct sset tr_scope = SSET_INITIALIZER(&tr_scope);
    const struct icnbrec_transit_router *tr;
    ICNBREC_TRANSIT_ROUTER_TABLE_FOR_EACH_TRACKED (tr, tbl) {
        char *uuid_str = uuid_to_string(&tr->header_.uuid);
        sset_add(&tr_scope, uuid_str);
        free(uuid_str);
    }

    enum engine_input_handler_result ret =
        tunnel_key_sync_scope(ctx, data, &ts_scope, &tr_scope);
    sset_destroy(&ts_scope);
    sset_destroy(&tr_scope);
    return ret;
}

/* IC-SB Datapath_Binding: react only to a binding *deletion* by re-creating it
 * for the still-present IC-NB entity (self-healing after an out-of-band
 * delete).  Inserts and modifies are this node's own writes (or already
 * consistent), so they are a no-op here - the requested-tnl-key follow-up is
 * driven by en_ts/en_tr's own handlers on this same table. */
enum engine_input_handler_result
en_tunnel_key_icsb_datapath_binding_handler(struct engine_node *node,
                                            void *data_)
{
    struct ed_type_tunnel_key *data = data_;
    struct ic_context *ctx = engine_get_context()->client_ctx;
    const struct icsbrec_datapath_binding_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICSB_datapath_binding", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    struct sset tr_scope = SSET_INITIALIZER(&tr_scope);
    const struct icsbrec_datapath_binding *isb_dp;
    ICSBREC_DATAPATH_BINDING_TABLE_FOR_EACH_TRACKED (isb_dp, tbl) {
        if (!icsbrec_datapath_binding_is_deleted(isb_dp)) {
            continue;
        }
        if (ic_dp_get_type(isb_dp) == IC_ROUTER) {
            if (!isb_dp->nb_ic_uuid) {
                /* Not inserted by ovn-ic: nothing to reconcile. */
                continue;
            }
            char *uuid_str = uuid_to_string(isb_dp->nb_ic_uuid);
            sset_add(&tr_scope, uuid_str);
            free(uuid_str);
        } else {
            sset_add(&ts_scope, isb_dp->transit_switch);
        }
    }

    enum engine_input_handler_result ret =
        tunnel_key_sync_scope(ctx, data, &ts_scope, &tr_scope);
    sset_destroy(&ts_scope);
    sset_destroy(&tr_scope);
    return ret;
}

/* Shared change handler for the IC-NB Global input: ignores
 * nb_ic_cfg/sb_ic_cfg sequence-number-only changes, and forces a recompute
 * only when the row is created/deleted or its 'options' (e.g. vxlan_mode)
 * change. */
enum engine_input_handler_result
ic_nb_global_options_handler(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct icnbrec_ic_nb_global_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICNB_ic_nb_global", node));
    const struct icnbrec_ic_nb_global *icnb;

    ICNBREC_IC_NB_GLOBAL_TABLE_FOR_EACH_TRACKED (icnb, tbl) {
        if (icnbrec_ic_nb_global_is_new(icnb) ||
            icnbrec_ic_nb_global_is_deleted(icnb) ||
            ovsdb_idl_track_is_updated(&icnb->header_,
                                       &icnbrec_ic_nb_global_col_options)) {
            return EN_UNHANDLED;
        }
    }

    return EN_HANDLED_UNCHANGED;
}

void *
en_tunnel_key_init(struct engine_node *node OVS_UNUSED,
                   struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_tunnel_key *data = xzalloc(sizeof *data);

    hmap_init(&data->dp_tnlids);

    return data;
}

void
en_tunnel_key_cleanup(void *data_)
{
    struct ed_type_tunnel_key *data = data_;

    ovn_destroy_tnlids(&data->dp_tnlids);
}
