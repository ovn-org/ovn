/* Copyright (c) 2025, Red Hat, Inc.
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

#include "neighbor-exchange.h"

void
neighbor_exchange_run(const struct neighbor_exchange_ctx_in *ctx_in OVS_UNUSED,
                      struct neighbor_exchange_ctx_out *ctx_out OVS_UNUSED)
{
}

int
neighbor_exchange_status_run(void)
{
    return 0;
}

void
evpn_remote_vteps_clear(struct hmap *remote_vteps OVS_UNUSED)
{
}

void
evpn_remote_vtep_list(struct unixctl_conn *conn OVS_UNUSED,
                      int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
                      void *data_ OVS_UNUSED)
{
}
