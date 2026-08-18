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

#ifndef NEIGHBOR_OF_H
#define NEIGHBOR_OF_H 1

#include "ovn-sb-idl.h"
#include "openvswitch/uuid.h"
#include "ofctrl.h"

/* Priorities of ovn-controller generated flows for various types of MAC
 * Bindings.  EVPN-learned MAC bindings are written to the SB MAC_Binding
 * table and consumed through the normal lflow pipeline at the same
 * priority as dynamic entries.  The EVPN ARP lookup side table (table 113)
 * uses the dynamic priority as well.  Valid preference orders based on
 * the SB.Static_MAC_Binding.override_dynamic_mac value are:
 *
 * - static-mac-binding < dynamic-mac-binding (+ EVPN)
 * - dynamic-mac-binding (+ EVPN) < static-mac-binding
 */
enum neigh_of_rule_prio {
    NEIGH_OF_STATIC_MAC_BINDING_LOW_PRIO  = 50,
    NEIGH_OF_DYNAMIC_MAC_BINDING_PRIO     = 100,
    NEIGH_OF_STATIC_MAC_BINDING_HIGH_PRIO = 150,
};

void
consider_neighbor_flow(const struct sbrec_port_binding *,
                       const struct uuid *neighbor_uuid,
                       const struct in6_addr *, struct eth_addr,
                       struct ovn_desired_flow_table *,
                       enum neigh_of_rule_prio priority,
                       bool needs_usage_tracking);

#endif  /* NEIGHBOR_OF_H */
