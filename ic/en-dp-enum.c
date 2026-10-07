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
#include "lib/inc-proc-eng.h"
#include "lib/ovn-util.h"
#include "openvswitch/hmap.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovn-ic.h"

VLOG_DEFINE_THIS_MODULE(en_ic_dp_enum);

enum engine_node_state
en_dp_enum_run(struct engine_node *node OVS_UNUSED, void *data_)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    struct ed_type_dp_enum *data = data_;

    /* Clear the previous iteration's state and rebuild from the current IC-SB
     * datapath bindings. */
    ovn_destroy_tnlids(&data->dp_tnlids);
    hmap_init(&data->dp_tnlids);
    shash_clear(&data->isb_ts_dps);
    shash_clear(&data->isb_tr_dps);

    enumerate_datapaths(ctx, &data->dp_tnlids, &data->isb_ts_dps,
                        &data->isb_tr_dps);

    return EN_UPDATED;
}

void *
en_dp_enum_init(struct engine_node *node OVS_UNUSED,
                struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_dp_enum *data = xzalloc(sizeof *data);

    hmap_init(&data->dp_tnlids);
    shash_init(&data->isb_ts_dps);
    shash_init(&data->isb_tr_dps);

    return data;
}

void
en_dp_enum_cleanup(void *data_)
{
    struct ed_type_dp_enum *data = data_;

    ovn_destroy_tnlids(&data->dp_tnlids);
    shash_destroy(&data->isb_ts_dps);
    shash_destroy(&data->isb_tr_dps);
}
