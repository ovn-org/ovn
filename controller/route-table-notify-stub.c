/*
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

#include <stdbool.h>

#include "openvswitch/compiler.h"
#include "route-table-notify.h"

bool
route_table_notify_run(void)
{
    return false;
}

void
route_table_notify_wait(void)
{
}

void
route_table_add_watch_request(struct hmap *route_table_watches OVS_UNUSED,
                              uint32_t table_id OVS_UNUSED)
{
}

void
route_table_watch_request_cleanup(struct hmap *route_table_watches OVS_UNUSED)
{
}

void
route_table_notify_update_watches(
    const struct hmap *route_table_watches OVS_UNUSED)
{
}

void
route_table_notify_destroy(void)
{
}
