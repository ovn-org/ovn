/* Copyright (c) 2025, STACKIT GmbH & Co. KG
 * Copyright (c) 2026, Red Hat, Inc.
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
#include <stddef.h>

#include "openvswitch/compiler.h"
#include "ovn-netlink-notifier.h"
#include "vec.h"

static struct vector empty = VECTOR_EMPTY_INITIALIZER(uint8_t);

void
ovn_netlink_update_notifier(enum ovn_netlink_notifier_type type OVS_UNUSED,
                            bool enabled OVS_UNUSED)
{
}

struct vector *
ovn_netlink_get_msgs(enum ovn_netlink_notifier_type type OVS_UNUSED)
{
    return &empty;
}

void
ovn_netlink_notifier_flush(enum ovn_netlink_notifier_type type OVS_UNUSED)
{
}

void
ovn_netlink_notifiers_run(void)
{
}

void
ovn_netlink_notifiers_wait(void)
{
}

void
ovn_netlink_notifiers_destroy(void)
{
}
