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

#include "en-route.h"
#include "lib/inc-proc-eng.h"
#include "openvswitch/vlog.h"
#include "ovn-ic.h"

VLOG_DEFINE_THIS_MODULE(en_ic_route);

enum engine_node_state
en_route_run(struct engine_node *node OVS_UNUSED, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;

    route_run(ctx);

    return EN_UPDATED;
}

void *
en_route_init(struct engine_node *node OVS_UNUSED,
              struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_route_cleanup(void *data OVS_UNUSED)
{
}
