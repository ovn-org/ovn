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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "openvswitch/util.h"

#include "en-sync-from-sb.h"
#include "include/ovn/expr.h"
#include "lib/inc-proc-eng.h"
#include "lib/lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "stopwatch.h"
#include "lib/stopwatch-names.h"
#include "timeval.h"
#include "northd.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(en_sync_from_sb);

void *
en_sync_from_sb_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_sync_from_sb_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct northd_data *nd = engine_get_input_data("northd", node);

    const struct sbrec_port_binding_table *sb_pb_table =
        EN_OVSDB_GET(engine_get_input("SB_port_binding", node));
    const struct sbrec_ha_chassis_group_table *sb_ha_ch_grp_table =
        EN_OVSDB_GET(engine_get_input("SB_ha_chassis_group", node));
    struct ovsdb_idl_index *sb_ha_ch_grp_by_name =
        engine_ovsdb_node_get_index(
            engine_get_input("SB_ha_chassis_group", node),
            "sbrec_ha_chassis_grp_by_name");
    stopwatch_start(OVNSB_DB_RUN_STOPWATCH_NAME, time_msec());
    ovnsb_db_run(eng_ctx->ovnnb_idl_txn, eng_ctx->ovnsb_idl_txn,
                 sb_pb_table, sb_ha_ch_grp_table, sb_ha_ch_grp_by_name,
                 &nd->ls_ports);
    stopwatch_stop(OVNSB_DB_RUN_STOPWATCH_NAME, time_msec());
}

bool
sync_from_sb_northd_handler(struct engine_node *node,
                            void *data OVS_UNUSED)
{
    struct northd_data *nd = engine_get_input_data("northd", node);
    if (nd->change_tracked) {
        /* There are only NB LSP related changes and the only field this node
         * cares about is the "up" column, which is considered write-only to
         * this node, so it is safe to ignore the change. (The real change
         * matters to this node is always from the SB DB.) */
        return true;
    }
    return false;
}

void
en_sync_from_sb_cleanup(void *data OVS_UNUSED)
{

}
