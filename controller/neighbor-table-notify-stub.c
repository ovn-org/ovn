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

#include <stdbool.h>

#include "openvswitch/compiler.h"
#include "neighbor-table-notify.h"

bool
neighbor_table_notify_run(void)
{
    return false;
}

void
neighbor_table_notify_wait(void)
{
}

void
neighbor_table_add_watch_request(
    struct hmap *neighbor_table_watches OVS_UNUSED,
    int32_t if_index OVS_UNUSED,
    const char *if_name OVS_UNUSED)
{
}

void
neighbor_table_watch_request_cleanup(
    struct hmap *neighbor_table_watches OVS_UNUSED)
{
}

void
neighbor_table_notify_update_watches(
    const struct hmap *neighbor_table_watches OVS_UNUSED)
{
}

void
neighbor_table_notify_destroy(void)
{
}
