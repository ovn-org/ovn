/*
 * Copyright (c) 2025, Red Hat, Inc.
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

#ifndef OVN_EN_MULTICAST_H
#define OVN_EN_MULTICAST_H

#include <stdint.h>

/* OVS includes. */
#include "openvswitch/hmap.h"

/* OVN includes. */
#include "lib/ovn-sb-idl.h"
#include "northd.h"

#define MC_FLOOD "_MC_flood"
#define MC_MROUTER_FLOOD "_MC_mrouter_flood"
#define MC_STATIC "_MC_static"
#define MC_UNKNOWN "_MC_unknown"
#define MC_FLOOD_L2 "_MC_flood_l2"

struct multicast_group {
    const char *name;
    uint16_t key;               /* OVN_MIN_MULTICAST...OVN_MAX_MULTICAST. */
};

/* Multicast group entry. */
struct ovn_multicast {
    struct hmap_node hmap_node; /* Index on 'datapath' and 'key'. */
    struct ovn_datapath *datapath;
    const struct multicast_group *group;

    struct ovn_port **ports;
    size_t n_ports, allocated_ports;
};

/*
 * IGMP group entry (1:1 mapping to SB database).
 */
struct ovn_igmp_group_entry {
    struct ovs_list list_node; /* Linkage in the list of entries. */
    size_t n_ports;
    struct ovn_port **ports;
};

/*
 * IGMP group entry (aggregate of all entries from the SB database
 * corresponding to the multicast group).
 */
struct ovn_igmp_group {
    struct hmap_node hmap_node; /* Index on 'datapath' and 'address'. */
    struct ovs_list list_node;  /* Linkage in the per-dp igmp group list. */

    struct ovn_datapath *datapath;
    struct in6_addr address; /* Multicast IPv6-mapped-IPv4 or IPv4 address. */
    struct multicast_group mcgroup;

    struct ovs_list entries; /* List of SB entries for this group. */
};

void build_mcast_groups(
    const struct sbrec_igmp_group_table *sbrec_igmp_group_table,
    struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp,
    const struct hmap *ls_datapaths,
    const struct hmap *ls_ports,
    const struct hmap *lr_ports,
    struct hmap *mcast_groups,
    struct hmap *igmp_groups);
void sync_multicast_groups_to_sb(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_multicast_group_table *sbrec_multicast_group_table,
    const struct hmap * ls_datapaths, const struct hmap *lr_datapaths,
    struct hmap *mcast_groups);
void ovn_igmp_groups_destroy(struct hmap *igmp_groups);
struct sbrec_multicast_group *create_sb_multicast_group(
    struct ovsdb_idl_txn *ovnsb_txn, const struct sbrec_datapath_binding *,
    const char *name, int64_t tunnel_key);

#endif /* OVN_EN_MULTICAST_H */
