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
