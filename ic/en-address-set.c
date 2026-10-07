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

#include "en-address-set.h"
#include "en-az.h"
#include "lib/inc-proc-eng.h"
#include "openvswitch/vlog.h"
#include "ovn-ic.h"

VLOG_DEFINE_THIS_MODULE(en_ic_address_set);

enum engine_node_state
en_address_set_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    const struct ed_type_az *az = engine_get_input_data("az", node);

    /* runned_az is resolved by the upstream en_az node.  Without an AZ there
     * is nothing to sync; this also mirrors the previous main-loop gating and
     * avoids running address_set_run() before the NB Global row exists (en_az
     * leaves runned_az NULL until then, and address_set_run() asserts on a
     * NULL NB Global). */
    if (!az->runned_az) {
        return EN_UNCHANGED;
    }

    address_set_run(ctx, az->runned_az);

    return EN_UPDATED;
}

void *
en_address_set_init(struct engine_node *node OVS_UNUSED,
                    struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_address_set_cleanup(void *data OVS_UNUSED)
{
}
