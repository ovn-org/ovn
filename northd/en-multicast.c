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

#include <config.h>

/* OVS includes. */
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "en-multicast.h"
#include "lib/ip-mcast-index.h"
#include "lib/mcast-group-index.h"
#include "lib/ovn-l7.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "northd.h"

VLOG_DEFINE_THIS_MODULE(en_multicast);

static const struct multicast_group mc_flood =
    { MC_FLOOD, OVN_MCAST_FLOOD_TUNNEL_KEY };

static const struct multicast_group mc_mrouter_flood =
    { MC_MROUTER_FLOOD, OVN_MCAST_MROUTER_FLOOD_TUNNEL_KEY };

static const struct multicast_group mc_static =
    { MC_STATIC, OVN_MCAST_STATIC_TUNNEL_KEY };

static const struct multicast_group mc_unknown =
    { MC_UNKNOWN, OVN_MCAST_UNKNOWN_TUNNEL_KEY };

static const struct multicast_group mc_flood_l2 =
    { MC_FLOOD_L2, OVN_MCAST_FLOOD_L2_TUNNEL_KEY };

static bool multicast_group_equal(const struct multicast_group *,
                                  const struct multicast_group *);
static uint32_t ovn_multicast_hash(const struct ovn_datapath *,
                                   const struct multicast_group *);
static struct ovn_multicast *ovn_multicast_find(
    struct hmap *mcgroups, struct ovn_datapath *,
    const struct multicast_group *);
static void ovn_multicast_add_ports(struct hmap *mcgroups,
                                    struct ovn_datapath *,
                                    const struct multicast_group *,
                                    struct ovn_port **ports, size_t n_ports);
static void ovn_multicast_add(struct hmap *mcgroups,
                              const struct multicast_group *,
                              struct ovn_port *);
static void ovn_multicast_destroy(struct hmap *mcgroups,
                                  struct ovn_multicast *);
static void ovn_multicast_update_sbrec(const struct ovn_multicast *,
                                       const struct sbrec_multicast_group *);

static uint32_t ovn_igmp_group_hash(const struct ovn_datapath *,
                                    const struct in6_addr *);
static struct ovn_igmp_group * ovn_igmp_group_find(struct hmap *igmp_groups,
                                                   const struct ovn_datapath *,
                                                   const struct in6_addr *);
static struct ovn_igmp_group *ovn_igmp_group_add(
    struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp,
    struct hmap *igmp_groups, struct ovn_datapath *,
    const struct in6_addr *, const char *address_s);
static struct ovn_port **ovn_igmp_group_get_ports(
    const struct sbrec_igmp_group *, size_t *n_ports,
    const struct hmap *ls_ports);
static void ovn_igmp_group_add_entry(struct ovn_igmp_group *,
                                     struct ovn_port **ports, size_t n_ports);
static void ovn_igmp_group_destroy_entry(struct ovn_igmp_group_entry *);
static bool ovn_igmp_group_allocate_id(struct ovn_igmp_group *);
static void ovn_igmp_mrouter_aggregate_ports(struct ovn_igmp_group *,
                                             struct hmap *mcast_groups);
static void ovn_igmp_group_aggregate_ports(struct ovn_igmp_group *,
                                           struct hmap *mcast_groups);
static void ovn_igmp_group_destroy(struct hmap *igmp_groups,
                                   struct ovn_igmp_group *);

void
build_mcast_groups(const struct sbrec_igmp_group_table *sbrec_igmp_group_table,
                   struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp,
                   const struct hmap *ls_datapaths,
                   const struct hmap *ls_ports,
                   const struct hmap *lr_ports,
                   struct hmap *mcast_groups,
                   struct hmap *igmp_groups)
{
    struct ovn_datapath *od;
    struct ovn_port *op;

    hmap_init(mcast_groups);
    hmap_init(igmp_groups);

    HMAP_FOR_EACH (op, key_node, lr_ports) {
        if (lrport_is_enabled(op->nbrp)) {
            /* If this port is configured to always flood multicast traffic
             * add it to the MC_STATIC group.
             */
            if (op->mcast_info.flood) {
                ovn_multicast_add(mcast_groups, &mc_static, op);
                op->od->mcast_info.rtr.flood_static = true;
            }
        }
    }

    HMAP_FOR_EACH (op, key_node, ls_ports) {
        if (lsp_is_enabled(op->nbsp)) {
            ovn_multicast_add(mcast_groups, &mc_flood, op);

            if (!lsp_is_router(op->nbsp)) {
                ovn_multicast_add(mcast_groups, &mc_flood_l2, op);
            }

            if (op->has_unknown) {
                ovn_multicast_add(mcast_groups, &mc_unknown, op);
            }

            /* If this port is connected to a multicast router then add it
             * to the MC_MROUTER_FLOOD group.
             */
            if (op->od->mcast_info.sw.flood_relay && op->peer &&
                op->peer->od && op->peer->od->mcast_info.rtr.relay) {
                ovn_multicast_add(mcast_groups, &mc_mrouter_flood, op);
            }

            /* If this port is configured to always flood multicast reports
             * add it to the MC_MROUTER_FLOOD group (all reports must be
             * flooded to statically configured or learned mrouters).
             */
            if (op->mcast_info.flood_reports) {
                ovn_multicast_add(mcast_groups, &mc_mrouter_flood, op);
                op->od->mcast_info.sw.flood_reports = true;
            }

            /* If this port is configured to always flood multicast traffic
             * add it to the MC_STATIC group.
             */
            if (op->mcast_info.flood) {
                ovn_multicast_add(mcast_groups, &mc_static, op);
                op->od->mcast_info.sw.flood_static = true;
            }
        }
    }

    const struct sbrec_igmp_group *sb_igmp;

    SBREC_IGMP_GROUP_TABLE_FOR_EACH_SAFE (sb_igmp, sbrec_igmp_group_table) {
        /* If this is a stale group (e.g., controller had crashed,
         * purge it).
         */
        if (!sb_igmp->chassis || !sb_igmp->datapath) {
            sbrec_igmp_group_delete(sb_igmp);
            continue;
        }

        /* If the datapath value is stale, purge the group. */
        od = ovn_datapath_from_sbrec(ls_datapaths, NULL,
                                     sb_igmp->datapath);

        if (!od || ovn_datapath_is_stale(od)) {
            sbrec_igmp_group_delete(sb_igmp);
            continue;
        }

        struct in6_addr group_address;
        if (!strcmp(sb_igmp->address, OVN_IGMP_GROUP_MROUTERS)) {
            /* Use all-zeros IP to denote a group corresponding to mrouters. */
            memset(&group_address, 0, sizeof group_address);
        } else if (!ip46_parse(sb_igmp->address, &group_address)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "invalid IGMP group address: %s",
                         sb_igmp->address);
            continue;
        }

        /* Extract the IGMP group ports from the SB entry. */
        size_t n_igmp_ports;
        struct ovn_port **igmp_ports =
            ovn_igmp_group_get_ports(sb_igmp, &n_igmp_ports, ls_ports);

        /* It can be that all ports in the IGMP group record already have
         * mcast_flood=true and then we can skip the group completely.
         */
        if (!igmp_ports) {
            continue;
        }

        /* Add the IGMP group entry. Will also try to allocate an ID for it
         * if the multicast group already exists.
         */
        struct ovn_igmp_group *igmp_group =
            ovn_igmp_group_add(sbrec_mcast_group_by_name_dp, igmp_groups, od,
                               &group_address, sb_igmp->address);

        /* Add the extracted ports to the IGMP group. */
        ovn_igmp_group_add_entry(igmp_group, igmp_ports, n_igmp_ports);
    }

    /* Build IGMP groups for multicast routers with relay enabled. The router
     * IGMP groups are based on the groups learnt by their multicast enabled
     * peers.
     */
    HMAP_FOR_EACH (od, key_node, ls_datapaths) {

        if (ovs_list_is_empty(&od->mcast_info.groups)) {
            continue;
        }

        for (size_t i = 0; i < od->n_router_ports; i++) {
            struct ovn_port *router_port = od->router_ports[i]->peer;

            /* If the router the port connects to doesn't have multicast
             * relay enabled or if it was already configured to flood
             * multicast traffic then skip it.
             */
            if (!router_port || !router_port->od ||
                !router_port->od->mcast_info.rtr.relay ||
                router_port->mcast_info.flood) {
                continue;
            }

            struct ovn_igmp_group *igmp_group;
            LIST_FOR_EACH (igmp_group, list_node, &od->mcast_info.groups) {
                struct in6_addr *address = &igmp_group->address;

                /* Skip mrouter entries. */
                if (!strcmp(igmp_group->mcgroup.name,
                            OVN_IGMP_GROUP_MROUTERS)) {
                    continue;
                }

                /* For IPv6 only relay routable multicast groups
                 * (RFC 4291 2.7).
                 */
                if (!IN6_IS_ADDR_V4MAPPED(address) &&
                    !ipv6_addr_is_routable_multicast(address)) {
                    continue;
                }

                struct ovn_igmp_group *igmp_group_rtr =
                    ovn_igmp_group_add(sbrec_mcast_group_by_name_dp,
                                       igmp_groups, router_port->od,
                                       address, igmp_group->mcgroup.name);
                struct ovn_port **router_igmp_ports =
                    xmalloc(sizeof *router_igmp_ports);
                /* Store the chassis redirect port  otherwise traffic will not
                 * be tunneled properly.
                 */
                router_igmp_ports[0] = router_port->cr_port
                                       ? router_port->cr_port
                                       : router_port;
                ovn_igmp_group_add_entry(igmp_group_rtr, router_igmp_ports, 1);
            }
        }
    }

    /* Walk the aggregated IGMP groups and allocate IDs for new entries.
     * Then store the ports in the associated multicast group.
     * Mrouter entries are also stored as IGMP groups, deal with those
     * explicitly.
     */
    struct ovn_igmp_group *igmp_group;
    HMAP_FOR_EACH_SAFE (igmp_group, hmap_node, igmp_groups) {

        /* If this is a mrouter entry just aggregate the mrouter ports
         * into the MC_MROUTER mcast_group and destroy the igmp_group;
         * no more processing needed. */
        if (!strcmp(igmp_group->mcgroup.name, OVN_IGMP_GROUP_MROUTERS)) {
            ovn_igmp_mrouter_aggregate_ports(igmp_group, mcast_groups);
            ovn_igmp_group_destroy(igmp_groups, igmp_group);
            continue;
        }

        if (!ovn_igmp_group_allocate_id(igmp_group)) {
            /* If we ran out of keys just destroy the entry. */
            ovn_igmp_group_destroy(igmp_groups, igmp_group);
            continue;
        }

        /* Aggregate the ports from all entries corresponding to this
         * group.
         */
        ovn_igmp_group_aggregate_ports(igmp_group, mcast_groups);
    }
}

void
sync_multicast_groups_to_sb(
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_multicast_group_table *sbrec_multicast_group_table,
    const struct hmap * ls_datapaths, const struct hmap *lr_datapaths,
    struct hmap *mcast_groups)
{
    /* Push changes to the Multicast_Group table to database. */
    const struct sbrec_multicast_group *sbmc;
    SBREC_MULTICAST_GROUP_TABLE_FOR_EACH_SAFE (
        sbmc, sbrec_multicast_group_table) {
        struct ovn_datapath *od = ovn_datapath_from_sbrec(ls_datapaths,
                                                          lr_datapaths,
                                                          sbmc->datapath);

        if (!od || ovn_datapath_is_stale(od)) {
            sbrec_multicast_group_delete(sbmc);
            continue;
        }

        struct multicast_group group = { .name = sbmc->name,
            .key = sbmc->tunnel_key };
        struct ovn_multicast *mc = ovn_multicast_find(mcast_groups,
                                                      od, &group);
        if (mc) {
            ovn_multicast_update_sbrec(mc, sbmc);
            ovn_multicast_destroy(mcast_groups, mc);
        } else {
            sbrec_multicast_group_delete(sbmc);
        }
    }
    struct ovn_multicast *mc;
    HMAP_FOR_EACH_SAFE (mc, hmap_node, mcast_groups) {
        if (!mc->datapath) {
            ovn_multicast_destroy(mcast_groups, mc);
            continue;
        }
        sbmc = create_sb_multicast_group(ovnsb_txn, mc->datapath->sb,
                                         mc->group->name, mc->group->key);
        ovn_multicast_update_sbrec(mc, sbmc);
        ovn_multicast_destroy(mcast_groups, mc);
    }

    hmap_destroy(mcast_groups);
}

void
ovn_igmp_groups_destroy(struct hmap *igmp_groups)
{
    struct ovn_igmp_group *igmp_group;
    HMAP_FOR_EACH_SAFE (igmp_group, hmap_node, igmp_groups) {
        ovn_igmp_group_destroy(igmp_groups, igmp_group);
    }
    hmap_destroy(igmp_groups);
}

struct sbrec_multicast_group *
create_sb_multicast_group(struct ovsdb_idl_txn *ovnsb_txn,
                          const struct sbrec_datapath_binding *dp,
                          const char *name,
                          int64_t tunnel_key)
{
    struct sbrec_multicast_group *sbmc =
        sbrec_multicast_group_insert(ovnsb_txn);
    sbrec_multicast_group_set_datapath(sbmc, dp);
    sbrec_multicast_group_set_name(sbmc, name);
    sbrec_multicast_group_set_tunnel_key(sbmc, tunnel_key);
    return sbmc;
}


static bool
multicast_group_equal(const struct multicast_group *a,
                      const struct multicast_group *b)
{
    return !strcmp(a->name, b->name) && a->key == b->key;
}


static uint32_t
ovn_multicast_hash(const struct ovn_datapath *datapath,
                   const struct multicast_group *group)
{
    return hash_pointer(datapath, group->key);
}

static struct ovn_multicast *
ovn_multicast_find(struct hmap *mcgroups, struct ovn_datapath *datapath,
                   const struct multicast_group *group)
{
    struct ovn_multicast *mc;

    HMAP_FOR_EACH_WITH_HASH (mc, hmap_node,
                             ovn_multicast_hash(datapath, group), mcgroups) {
        if (mc->datapath == datapath
            && multicast_group_equal(mc->group, group)) {
            return mc;
        }
    }
    return NULL;
}

static void
ovn_multicast_add_ports(struct hmap *mcgroups, struct ovn_datapath *od,
                        const struct multicast_group *group,
                        struct ovn_port **ports, size_t n_ports)
{
    struct ovn_multicast *mc = ovn_multicast_find(mcgroups, od, group);
    if (!mc) {
        mc = xmalloc(sizeof *mc);
        hmap_insert(mcgroups, &mc->hmap_node, ovn_multicast_hash(od, group));
        mc->datapath = od;
        mc->group = group;
        mc->n_ports = 0;
        mc->allocated_ports = 4;
        mc->ports = xmalloc(mc->allocated_ports * sizeof *mc->ports);
    }

    size_t n_ports_total = mc->n_ports + n_ports;

    if (n_ports_total > 2 * mc->allocated_ports) {
        mc->allocated_ports = n_ports_total;
        mc->ports = xrealloc(mc->ports,
                             mc->allocated_ports * sizeof *mc->ports);
    } else if (n_ports_total > mc->allocated_ports) {
        mc->ports = x2nrealloc(mc->ports, &mc->allocated_ports,
                               sizeof *mc->ports);
    }

    memcpy(&mc->ports[mc->n_ports], &ports[0], n_ports * sizeof *ports);
    mc->n_ports += n_ports;
}

static void
ovn_multicast_add(struct hmap *mcgroups, const struct multicast_group *group,
                  struct ovn_port *port)
{
    /* Store the chassis redirect port otherwise traffic will not be tunneled
     * properly.
     */
    if (port->cr_port) {
        port = port->cr_port;
    }
    ovn_multicast_add_ports(mcgroups, port->od, group, &port, 1);
}

static void
ovn_multicast_destroy(struct hmap *mcgroups, struct ovn_multicast *mc)
{
    if (mc) {
        hmap_remove(mcgroups, &mc->hmap_node);
        free(mc->ports);
        free(mc);
    }
}

static void
ovn_multicast_update_sbrec(const struct ovn_multicast *mc,
                           const struct sbrec_multicast_group *sb)
{
    struct sbrec_port_binding **ports = xmalloc(mc->n_ports * sizeof *ports);
    for (size_t i = 0; i < mc->n_ports; i++) {
        ports[i] = CONST_CAST(struct sbrec_port_binding *, mc->ports[i]->sb);
    }
    sbrec_multicast_group_set_ports(sb, ports, mc->n_ports);
    free(ports);
}

static uint32_t
ovn_igmp_group_hash(const struct ovn_datapath *datapath,
                    const struct in6_addr *address)
{
    return hash_pointer(datapath, hash_bytes(address, sizeof *address, 0));
}

static struct ovn_igmp_group *
ovn_igmp_group_find(struct hmap *igmp_groups,
                    const struct ovn_datapath *datapath,
                    const struct in6_addr *address)
{
    struct ovn_igmp_group *group;

    HMAP_FOR_EACH_WITH_HASH (group, hmap_node,
                             ovn_igmp_group_hash(datapath, address),
                             igmp_groups) {
        if (group->datapath == datapath &&
            ipv6_addr_equals(&group->address, address)) {
            return group;
        }
    }
    return NULL;
}

static struct ovn_igmp_group *
ovn_igmp_group_add(struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp,
                   struct hmap *igmp_groups,
                   struct ovn_datapath *datapath,
                   const struct in6_addr *address,
                   const char *address_s)
{
    struct ovn_igmp_group *igmp_group =
        ovn_igmp_group_find(igmp_groups, datapath, address);

    if (!igmp_group) {
        igmp_group = xmalloc(sizeof *igmp_group);

        const struct sbrec_multicast_group *mcgroup =
            mcast_group_lookup(sbrec_mcast_group_by_name_dp,
                               address_s,
                               datapath->sb);

        igmp_group->datapath = datapath;
        igmp_group->address = *address;
        if (mcgroup) {
            igmp_group->mcgroup.key = mcgroup->tunnel_key;
            ovn_add_tnlid(&datapath->mcast_info.group_tnlids,
                          mcgroup->tunnel_key);
        } else {
            igmp_group->mcgroup.key = 0;
        }
        igmp_group->mcgroup.name = address_s;
        ovs_list_init(&igmp_group->entries);

        hmap_insert(igmp_groups, &igmp_group->hmap_node,
                    ovn_igmp_group_hash(datapath, address));
        ovs_list_push_back(&datapath->mcast_info.groups,
                           &igmp_group->list_node);
    }

    return igmp_group;
}

static struct ovn_port **
ovn_igmp_group_get_ports(const struct sbrec_igmp_group *sb_igmp_group,
                         size_t *n_ports, const struct hmap *ls_ports)
{
    struct ovn_port **ports = NULL;

    *n_ports = 0;
    for (size_t i = 0; i < sb_igmp_group->n_ports; i++) {
        struct ovn_port *port =
            ovn_port_find(ls_ports, sb_igmp_group->ports[i]->logical_port);

        if (!port || !port->nbsp) {
            continue;
        }

        /* If this is already a flood port skip it for the group. */
        if (port->mcast_info.flood) {
            continue;
        }

        /* If this is already a port of a router on which relay is enabled,
         * skip it for the group. Traffic is flooded there anyway.
         */
        if (port->peer && port->peer->od &&
            port->peer->od->mcast_info.rtr.relay) {
            continue;
        }

        if (ports == NULL) {
            ports = xmalloc(sb_igmp_group->n_ports * sizeof *ports);
        }

        ports[(*n_ports)] = port;
        (*n_ports)++;
    }

    return ports;
}

static void
ovn_igmp_group_add_entry(struct ovn_igmp_group *igmp_group,
                         struct ovn_port **ports, size_t n_ports)
{
    struct ovn_igmp_group_entry *entry = xmalloc(sizeof *entry);

    entry->ports = ports;
    entry->n_ports = n_ports;
    ovs_list_push_back(&igmp_group->entries, &entry->list_node);
}

static void
ovn_igmp_group_destroy_entry(struct ovn_igmp_group_entry *entry)
{
    free(entry->ports);
}

static bool
ovn_igmp_group_allocate_id(struct ovn_igmp_group *igmp_group)
{
    if (igmp_group->mcgroup.key == 0) {
        struct hmap *tnlids = &igmp_group->datapath->mcast_info.group_tnlids;
        uint32_t tnlid_hint =
            igmp_group->datapath->mcast_info.group_tnlid_hint;
        igmp_group->mcgroup.key = ovn_allocate_tnlid(tnlids, "multicast group",
                                                     OVN_MIN_IP_MULTICAST,
                                                     OVN_MAX_IP_MULTICAST,
                                                     &tnlid_hint);
    }

    if (igmp_group->mcgroup.key == 0) {
        return false;
    }

    return true;
}

static void
ovn_igmp_mrouter_aggregate_ports(struct ovn_igmp_group *igmp_group,
                                 struct hmap *mcast_groups)
{
    struct ovn_igmp_group_entry *entry;

    LIST_FOR_EACH_POP (entry, list_node, &igmp_group->entries) {
        ovn_multicast_add_ports(mcast_groups, igmp_group->datapath,
                                &mc_mrouter_flood, entry->ports,
                                entry->n_ports);

        ovn_igmp_group_destroy_entry(entry);
        free(entry);
    }
}

static void
ovn_igmp_group_aggregate_ports(struct ovn_igmp_group *igmp_group,
                               struct hmap *mcast_groups)
{
    struct ovn_igmp_group_entry *entry;

    LIST_FOR_EACH_POP (entry, list_node, &igmp_group->entries) {
        ovn_multicast_add_ports(mcast_groups, igmp_group->datapath,
                                &igmp_group->mcgroup, entry->ports,
                                entry->n_ports);

        ovn_igmp_group_destroy_entry(entry);
        free(entry);
    }

    if (igmp_group->datapath->n_localnet_ports) {
        ovn_multicast_add_ports(mcast_groups, igmp_group->datapath,
                                &igmp_group->mcgroup,
                                igmp_group->datapath->localnet_ports,
                                igmp_group->datapath->n_localnet_ports);
    }
}

static void
ovn_igmp_group_destroy(struct hmap *igmp_groups,
                       struct ovn_igmp_group *igmp_group)
{
    if (igmp_group) {
        struct ovn_igmp_group_entry *entry;

        LIST_FOR_EACH_POP (entry, list_node, &igmp_group->entries) {
            ovn_igmp_group_destroy_entry(entry);
            free(entry);
        }
        hmap_remove(igmp_groups, &igmp_group->hmap_node);
        ovs_list_remove(&igmp_group->list_node);
        free(igmp_group);
    }
}
