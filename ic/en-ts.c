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
#include "en-ts.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-nb-idl.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovsdb-idl.h"
#include "smap.h"
#include "sset.h"
#include "ovn-ic.h"

VLOG_DEFINE_THIS_MODULE(en_ic_ts);

/* Builds 'isb_ts_dps': the committed IC-SB transit-switch Datapath_Bindings
 * keyed by transit-switch name.  Read-only; ts_sync_scope() copies each
 * committed tunnel key into its NB mirror's requested-tnl-key.  This is
 * en_ts's own local data, rebuilt each run and never mutated by another
 * node. */
static void
collect_ts_datapaths(struct ic_context *ctx, struct shash *isb_ts_dps)
{
    shash_init(isb_ts_dps);

    const struct icsbrec_datapath_binding *isb_dp;
    ICSBREC_DATAPATH_BINDING_FOR_EACH (isb_dp, ctx->ovnisb_idl) {
        if (ic_dp_get_type(isb_dp) == IC_SWITCH) {
            shash_add(isb_ts_dps, isb_dp->transit_switch, isb_dp);
        }
    }
}

enum engine_node_state
en_ts_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    const struct ed_type_az *az = engine_get_input_data("az", node);

    /* runned_az is resolved by the upstream en_az node.  Without an AZ there
     * is nothing to sync (mirrors the previous main-loop gating). */
    if (!az->runned_az) {
        return EN_UNCHANGED;
    }

    struct shash isb_ts_dps;
    collect_ts_datapaths(ctx, &isb_ts_dps);
    ts_sync_scope(ctx, &isb_ts_dps, NULL);
    shash_destroy(&isb_ts_dps);

    return EN_UPDATED;
}

/* Returns the ic_context, or NULL when there is no availability zone yet (in
 * which case the caller should report EN_HANDLED_UNCHANGED). */
static struct ic_context *
ts_handler_ctx(struct engine_node *node)
{
    struct ic_context *ctx = engine_get_context()->client_ctx;
    const struct ed_type_az *az = engine_get_input_data("az", node);
    return az->runned_az ? ctx : NULL;
}

/* Runs the scoped NB-mirror sync for the collected transit-switch scope and
 * maps it to an engine result.  ts_sync_scope() gates the NB mirror on the
 * ovnnb_txn it needs, exactly as the full recompute does. */
static enum engine_input_handler_result
ts_scope_finish(struct ic_context *ctx, struct sset *ts_scope)
{
    if (sset_is_empty(ts_scope)) {
        return EN_HANDLED_UNCHANGED;
    }

    struct shash isb_ts_dps;
    collect_ts_datapaths(ctx, &isb_ts_dps);
    ts_sync_scope(ctx, &isb_ts_dps, ts_scope);
    shash_destroy(&isb_ts_dps);

    return EN_HANDLED_UPDATED;
}

/* IC-NB Transit_Switch: a new/deleted transit switch must have its NB mirror
 * reconciled.  A deletion is honoured via the scoped GC in ts_sync_scope()
 * (the deleted row's name stays in scope but is absent from IC-NB, so its
 * mirror leftover is removed).  A rename cannot be scoped (the tracked row
 * only carries the new name, so the mirror of the old one would leak) and
 * falls back to a full recompute. */
enum engine_input_handler_result
en_ts_icnb_transit_switch_handler(struct engine_node *node,
                                  void *data OVS_UNUSED)
{
    struct ic_context *ctx = ts_handler_ctx(node);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct icnbrec_transit_switch_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_switch", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
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
        unhandled ? EN_UNHANDLED : ts_scope_finish(ctx, &ts_scope);
    sset_destroy(&ts_scope);
    return ret;
}

/* Only transit-switch mirror logical switches (other_config:interconn-ts)
 * affect en_ts.  A change to such a logical switch reconciles that transit
 * switch (re-creating the mirror if it was deleted externally); any other
 * logical switch is irrelevant to en_ts, so its change is a no-op, avoiding a
 * recompute on unrelated NB Logical_Switch updates. */
enum engine_input_handler_result
en_ts_nb_logical_switch_handler(struct engine_node *node,
                                void *data OVS_UNUSED)
{
    struct ic_context *ctx = ts_handler_ctx(node);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct nbrec_logical_switch_table *tbl =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    const struct nbrec_logical_switch *ls;
    NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH_TRACKED (ls, tbl) {
        const char *ts_name = smap_get(&ls->other_config, "interconn-ts");
        if (ts_name) {
            sset_add(&ts_scope, ts_name);
        }
    }

    enum engine_input_handler_result ret = ts_scope_finish(ctx, &ts_scope);
    sset_destroy(&ts_scope);
    return ret;
}

/* IC-SB Datapath_Binding: when a transit switch's datapath tunnel key is
 * (re)assigned by en_tunnel_key, the NB Logical_Switch mirror's
 * other_config:requested-tnl-key must be updated to the committed value.  This
 * is what synchronizes the key after a global tunnel-key refresh (an IC-NB
 * vxlan_mode change reallocates the datapath key into the VXLAN range in
 * IC-SB, but the NB value only catches up on a follow-up iteration).
 *
 * Only transit-switch bindings have an NB mirror; transit routers (IC_ROUTER)
 * are irrelevant.  Deletions are ignored: a transit switch removal is
 * reconciled through en_ts_icnb_transit_switch_handler and the scoped GC in
 * ts_sync_scope().
 *
 * Newly *inserted* bindings are also ignored, on purpose.  en_tunnel_key
 * inserts the binding and already publishes its freshly-allocated key to the
 * mirror in the same iteration; reacting to that insert here would re-sync the
 * transit switch while its mirror (if just created by
 * en_ts_icnb_transit_switch_handler) is still uncommitted - find_ts_in_nb()'s
 * index does not see the txn-local insert, so a duplicate NB Logical_Switch
 * would be created.  Here we only react to a tunnel-key *modify* on an
 * already-existing binding (the vxlan refresh), whose mirror already
 * exists. */
enum engine_input_handler_result
en_ts_icsb_datapath_binding_handler(struct engine_node *node,
                                    void *data OVS_UNUSED)
{
    struct ic_context *ctx = ts_handler_ctx(node);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct icsbrec_datapath_binding_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICSB_datapath_binding", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    const struct icsbrec_datapath_binding *isb_dp;
    ICSBREC_DATAPATH_BINDING_TABLE_FOR_EACH_TRACKED (isb_dp, tbl) {
        if (icsbrec_datapath_binding_is_deleted(isb_dp) ||
            icsbrec_datapath_binding_is_new(isb_dp) ||
            ic_dp_get_type(isb_dp) != IC_SWITCH) {
            continue;
        }
        if (ovsdb_idl_track_is_updated(&isb_dp->header_,
                    &icsbrec_datapath_binding_col_tunnel_key)) {
            sset_add(&ts_scope, isb_dp->transit_switch);
        }
    }

    enum engine_input_handler_result ret = ts_scope_finish(ctx, &ts_scope);
    sset_destroy(&ts_scope);
    return ret;
}

void *
en_ts_init(struct engine_node *node OVS_UNUSED,
           struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_ts_cleanup(void *data OVS_UNUSED)
{
}
