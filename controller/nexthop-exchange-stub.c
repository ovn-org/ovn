/* Copyright (c) 2026, Red Hat, Inc.
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

#include "lib/netlink.h"
#include "openvswitch/hmap.h"
#include "openvswitch/ofpbuf.h"

#include "nexthop-exchange.h"

/* Populates 'nexthops' with all nexthop entries
 * (struct nexthop_entry) with fdb flag set that exist in the table. */
void
nexthops_sync(struct hmap *nexthops OVS_UNUSED)
{
}

void
nexthop_entry_format(struct ds *ds OVS_UNUSED,
                     const struct nexthop_entry *nhe OVS_UNUSED)
{
}

int
nh_table_parse(struct ofpbuf *buf OVS_UNUSED,
               struct nh_table_msg *change OVS_UNUSED)
{
    return 0;
}
