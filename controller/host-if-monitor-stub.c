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
#include "host-if-monitor.h"

void
host_if_monitor_wait(void)
{
}

bool
host_if_monitor_run(void)
{
    return false;
}

void
host_if_monitor_update_watches(const struct sset *if_names OVS_UNUSED)
{
}

int32_t
host_if_monitor_ifname_toindex(const char *if_name OVS_UNUSED)
{
    return 0;
}
