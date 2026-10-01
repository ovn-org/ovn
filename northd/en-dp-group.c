/*
 * Copyright (c) 2026, Red Hat, Inc.
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

#include "en-datapath-sync.h"
#include "en-dp-group.h"
#include "en-global-config.h"
#include "en-lflow.h"
#include "lflow-mgr.h"
#include "lib/inc-proc-eng.h"
#include "lib/stopwatch-names.h"
#include "northd.h"
#include "openvswitch/vlog.h"
#include "stopwatch.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(en_dp_group);

void *
en_dp_group_init(struct engine_node *node OVS_UNUSED,
                 struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

static void
dp_group_sync_to_sb(struct engine_node *node,
                    struct lflow_data *lflow_data)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct all_synced_datapaths *all_dps =
        engine_get_input_data("datapath_sync", node);
    struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);

    const struct sbrec_logical_flow_table *sb_flow_table =
        EN_OVSDB_GET(engine_get_input("SB_logical_flow", node));
    const struct sbrec_logical_dp_group_table *sb_dpgrp_table =
        EN_OVSDB_GET(engine_get_input("SB_logical_dp_group", node));

    stopwatch_start(LFLOWS_TO_SB_STOPWATCH_NAME, time_msec());
    lflow_table_sync_to_sb(lflow_data->lflow_table,
                           eng_ctx->ovnsb_idl_txn,
                           all_dps->synced_dps,
                           global_config->ovn_internal_version_changed,
                           sb_flow_table, sb_dpgrp_table);
    stopwatch_stop(LFLOWS_TO_SB_STOPWATCH_NAME, time_msec());
}

enum engine_node_state
en_dp_group_run(struct engine_node *node,
                void *data OVS_UNUSED)
{
    struct lflow_data *lflow_data = engine_get_input_data("lflow", node);

    dp_group_sync_to_sb(node, lflow_data);
    return EN_UPDATED;
}

enum engine_input_handler_result
dp_group_lflow_handler(struct engine_node *node,
                       void *data OVS_UNUSED)
{
    struct lflow_data *lflow_data = engine_get_input_data("lflow", node);

    const struct engine_context *eng_ctx = engine_get_context();
    struct all_synced_datapaths *all_dps =
        engine_get_input_data("datapath_sync", node);

    const struct sbrec_logical_flow_table *sb_flow_table =
        EN_OVSDB_GET(engine_get_input("SB_logical_flow", node));
    const struct sbrec_logical_dp_group_table *sb_dpgrp_table =
        EN_OVSDB_GET(engine_get_input("SB_logical_dp_group", node));

    struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);

    if (hmapx_is_empty(&lflow_data->trk_data.dirty_lflow_refs) ||
        lflow_data->trk_data.needs_full_sync) {

        dp_group_sync_to_sb(node, lflow_data);
        return EN_HANDLED_UPDATED;
    }

    struct hmapx_node *hmapx_node;
    HMAPX_FOR_EACH (hmapx_node, &lflow_data->trk_data.dirty_lflow_refs) {
        struct lflow_ref *ref = hmapx_node->data;
        if (!lflow_ref_sync_lflows(ref, lflow_data->lflow_table,
                                   eng_ctx->ovnsb_idl_txn,
                                   all_dps->synced_dps,
                                   global_config->ovn_internal_version_changed,
                                   sb_flow_table, sb_dpgrp_table)) {
            return EN_UNHANDLED;
        }
    }
    return EN_HANDLED_UPDATED;
}

void
en_dp_group_cleanup(void *data OVS_UNUSED)
{
}
