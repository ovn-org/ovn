/*
 * Copyright (c) 2025 Canonical, Ltd.
 * Copyright (c) 2025, STACKIT GmbH & Co. KG
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

#include "openvswitch/compiler.h"
#include "route-exchange.h"

void
route_exchange_run(const struct route_exchange_ctx_in *r_ctx_in OVS_UNUSED,
                   struct route_exchange_ctx_out *r_ctx_out OVS_UNUSED)
{
}

void
route_exchange_cleanup_vrfs(void)
{
}

void
route_exchange_destroy(void)
{
}

int route_exchange_status_run(void)
{
    return 0;
}
