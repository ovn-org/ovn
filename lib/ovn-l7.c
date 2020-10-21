/*
 * Copyright (c) 2020 Red Hat.
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

#include "ovn-l7.h"

bool
ipv6_addr_is_routable_multicast(const struct in6_addr *ip)
{
    if (!ipv6_addr_is_multicast(ip)) {
        return false;
    }

    /* Check multicast group scope, RFC 4291, 2.7. */
    switch (ip->s6_addr[1] & 0x0F) {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x0F:
        return false;
    default:
        return true;
    }
}
