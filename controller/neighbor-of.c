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

#include "lflow.h"
#include "neighbor-of.h"
#include "openvswitch/match.h"
#include "ovn/logical-fields.h"

void
consider_neighbor_flow(const struct sbrec_port_binding *pb,
                       const struct uuid *neighbor_uuid,
                       const struct in6_addr *ip, struct eth_addr mac,
                       struct ovn_desired_flow_table *flow_table,
                       enum neigh_of_rule_prio priority,
                       bool needs_usage_tracking)
{
    struct match get_arp_match = MATCH_CATCHALL_INITIALIZER;
    struct match lookup_arp_match = MATCH_CATCHALL_INITIALIZER;
    struct match mb_cache_use_match = MATCH_CATCHALL_INITIALIZER;
    struct match lookup_arp_for_stats_match = MATCH_CATCHALL_INITIALIZER;

    match_set_dl_src(&lookup_arp_match, mac);
    match_set_metadata(&lookup_arp_match, htonll(pb->datapath->tunnel_key));
    match_set_reg(&lookup_arp_match, MFF_LOG_INPORT - MFF_REG0,
                  pb->tunnel_key);

    if (IN6_IS_ADDR_V4MAPPED(ip)) {
        ovs_be32 ip_addr = in6_addr_get_mapped_ipv4(ip);
        match_set_reg(&get_arp_match, 0, ntohl(ip_addr));

        match_set_dl_type(&lookup_arp_match, htons(ETH_TYPE_ARP));
        lookup_arp_for_stats_match = lookup_arp_match;

        match_set_reg(&lookup_arp_match, 0, ntohl(ip_addr));

        match_set_dl_type(&mb_cache_use_match, htons(ETH_TYPE_IP));
        match_set_nw_src(&mb_cache_use_match, ip_addr);

        match_set_arp_opcode_masked(&lookup_arp_for_stats_match, 2, 0xff);
        match_set_arp_spa_masked(&lookup_arp_for_stats_match, ip_addr,
                                 htonl(0xffffffff));
    } else {
        ovs_be128 value;
        memcpy(&value, ip, sizeof(value));
        match_set_xxreg(&get_arp_match, 1, ntoh128(value));

        match_set_dl_type(&lookup_arp_match, htons(ETH_TYPE_IPV6));
        match_set_nw_proto(&lookup_arp_match, 58);
        match_set_icmp_code(&lookup_arp_match, 0);

        match_set_xxreg(&lookup_arp_match, 0, ntoh128(value));

        match_set_dl_type(&mb_cache_use_match, htons(ETH_TYPE_IPV6));
        match_set_ipv6_src(&mb_cache_use_match, ip);
    }

    match_set_metadata(&get_arp_match, htonll(pb->datapath->tunnel_key));
    match_set_reg(&get_arp_match, MFF_LOG_OUTPORT - MFF_REG0, pb->tunnel_key);

    match_set_dl_src(&mb_cache_use_match, mac);
    match_set_reg(&mb_cache_use_match, MFF_LOG_INPORT - MFF_REG0,
                  pb->tunnel_key);
    match_set_metadata(&mb_cache_use_match, htonll(pb->datapath->tunnel_key));

    uint64_t stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);
    put_load_bytes(mac.ea, sizeof mac.ea, MFF_ETH_DST, 0, 48,
                   &ofpacts);
    put_load(1, MFF_LOG_FLAGS, MLF_LOOKUP_MAC_BIT, 1, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_MAC_BINDING, priority,
                    neighbor_uuid->parts[0],
                    &get_arp_match, &ofpacts,
                    neighbor_uuid);

    ofpbuf_clear(&ofpacts);
    put_load(1, MFF_LOG_FLAGS, MLF_LOOKUP_MAC_BIT, 1, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_MAC_LOOKUP, priority,
                    neighbor_uuid->parts[0],
                    &lookup_arp_match, &ofpacts,
                    neighbor_uuid);

    if (needs_usage_tracking) {
        ofpbuf_clear(&ofpacts);
        if (IN6_IS_ADDR_V4MAPPED(ip)) {
            ofctrl_add_flow(flow_table, OFTABLE_MAC_CACHE_USE, priority,
                            neighbor_uuid->parts[0],
                            &lookup_arp_for_stats_match,
                            &ofpacts, neighbor_uuid);
        }
        ofctrl_add_flow(flow_table, OFTABLE_MAC_CACHE_USE, priority,
                        neighbor_uuid->parts[0], &mb_cache_use_match,
                        &ofpacts, neighbor_uuid);
    }

    ofpbuf_uninit(&ofpacts);
}
