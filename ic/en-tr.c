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

#include "en-dp-enum.h"
#include "en-tr.h"
#include "lib/inc-proc-eng.h"
#include "openvswitch/vlog.h"
#include "ovn-ic.h"

VLOG_DEFINE_THIS_MODULE(en_ic_tr);

enum engine_node_state
en_tr_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    struct ed_type_dp_enum *dp = engine_get_input_data("dp_enum", node);

    tr_run(ctx, &dp->dp_tnlids, &dp->isb_tr_dps);

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
