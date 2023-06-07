/*
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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "lib/svec.h"
#include "openvswitch/util.h"

#include "en-sync-sb.h"
#include "lib/inc-proc-eng.h"
#include "lib/lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "northd.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(en_sync_to_sb);

/* This is just a type wrapper to enforce that it has to be sorted. */
struct sorted_addresses {
    const char **arr;
    size_t n;
};


static void sync_addr_set(struct ovsdb_idl_txn *ovnsb_txn, const char *name,
                          struct sorted_addresses *addresses,
                          struct shash *sb_address_sets);
static void sync_addr_sets(struct ovsdb_idl_txn *ovnsb_txn,
                           const struct nbrec_address_set_table *,
                           const struct nbrec_port_group_table *,
                           const struct sbrec_address_set_table *,
                           const struct ovn_datapaths *lr_datapaths);
static const struct sbrec_address_set *sb_address_set_lookup_by_name(
    struct ovsdb_idl_index *, const char *name);
static void update_sb_addr_set(struct sorted_addresses *,
                               const struct sbrec_address_set *);
static void build_port_group_address_set(const struct nbrec_port_group *,
                                         struct svec *ipv4_addrs,
                                         struct svec *ipv6_addrs);
static struct sorted_addresses
sorted_addresses_from_nbrec(const struct nbrec_address_set *nb_as);
static struct sorted_addresses
sorted_addresses_from_svec(struct svec *addresses);
static struct sorted_addresses
sorted_addresses_from_sset(struct sset *addresses);

void *
en_sync_to_sb_init(struct engine_node *node OVS_UNUSED,
                struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_sync_to_sb_run(struct engine_node *node, void *data OVS_UNUSED)
{
    engine_set_node_state(node, EN_UPDATED);
}

void
en_sync_to_sb_cleanup(void *data OVS_UNUSED)
{

}

void *
en_sync_to_sb_addr_set_init(struct engine_node *node OVS_UNUSED,
                            struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_sync_to_sb_addr_set_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct nbrec_address_set_table *nb_address_set_table =
        EN_OVSDB_GET(engine_get_input("NB_address_set", node));
    const struct nbrec_port_group_table *nb_port_group_table =
        EN_OVSDB_GET(engine_get_input("NB_port_group", node));
    const struct sbrec_address_set_table *sb_address_set_table =
        EN_OVSDB_GET(engine_get_input("SB_address_set", node));

    const struct engine_context *eng_ctx = engine_get_context();
    struct northd_data *northd_data = engine_get_input_data("northd", node);

    sync_addr_sets(eng_ctx->ovnsb_idl_txn, nb_address_set_table,
                   nb_port_group_table, sb_address_set_table,
                   &northd_data->lr_datapaths);

    engine_set_node_state(node, EN_UPDATED);
}

void
en_sync_to_sb_addr_set_cleanup(void *data OVS_UNUSED)
{

}

bool
sync_to_sb_addr_set_nb_address_set_handler(struct engine_node *node,
                                           void *data OVS_UNUSED)
{
    const struct nbrec_address_set_table *nb_address_set_table =
        EN_OVSDB_GET(engine_get_input("NB_address_set", node));

    /* Return false if an address set is created or deleted.
     * Handle I-P for only updated address sets. */
    const struct nbrec_address_set *nb_addr_set;
    NBREC_ADDRESS_SET_TABLE_FOR_EACH_TRACKED (nb_addr_set,
                                              nb_address_set_table) {
        if (nbrec_address_set_is_new(nb_addr_set) ||
                nbrec_address_set_is_deleted(nb_addr_set)) {
            return false;
        }
    }

    struct ovsdb_idl_index *sbrec_address_set_by_name =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_address_set", node),
                "sbrec_address_set_by_name");

    NBREC_ADDRESS_SET_TABLE_FOR_EACH_TRACKED (nb_addr_set,
                                              nb_address_set_table) {
        const struct sbrec_address_set *sb_addr_set =
            sb_address_set_lookup_by_name(sbrec_address_set_by_name,
                                          nb_addr_set->name);
        if (!sb_addr_set) {
            return false;
        }
        struct sorted_addresses addrs =
                sorted_addresses_from_nbrec(nb_addr_set);
        update_sb_addr_set(&addrs, sb_addr_set);
    }

    return true;
}

bool
sync_to_sb_addr_set_nb_port_group_handler(struct engine_node *node,
                                          void *data OVS_UNUSED)
{
    const struct nbrec_port_group *nb_pg;
    const struct nbrec_port_group_table *nb_port_group_table =
        EN_OVSDB_GET(engine_get_input("NB_port_group", node));
    NBREC_PORT_GROUP_TABLE_FOR_EACH_TRACKED (nb_pg, nb_port_group_table) {
        if (nbrec_port_group_is_new(nb_pg) ||
                nbrec_port_group_is_deleted(nb_pg)) {
            return false;
        }
    }

    struct ovsdb_idl_index *sbrec_address_set_by_name =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_address_set", node),
                "sbrec_address_set_by_name");
    NBREC_PORT_GROUP_TABLE_FOR_EACH_TRACKED (nb_pg, nb_port_group_table) {
        char *ipv4_addrs_name = xasprintf("%s_ip4", nb_pg->name);
        const struct sbrec_address_set *sb_addr_set_v4 =
            sb_address_set_lookup_by_name(sbrec_address_set_by_name,
                                          ipv4_addrs_name);
        if (!sb_addr_set_v4) {
            free(ipv4_addrs_name);
            return false;
        }
        char *ipv6_addrs_name = xasprintf("%s_ip6", nb_pg->name);
        const struct sbrec_address_set *sb_addr_set_v6 =
            sb_address_set_lookup_by_name(sbrec_address_set_by_name,
                                          ipv6_addrs_name);
        if (!sb_addr_set_v6) {
            free(ipv4_addrs_name);
            free(ipv6_addrs_name);
            return false;
        }

        struct svec ipv4_addrs = SVEC_EMPTY_INITIALIZER;
        struct svec ipv6_addrs = SVEC_EMPTY_INITIALIZER;
        build_port_group_address_set(nb_pg, &ipv4_addrs, &ipv6_addrs);

        struct sorted_addresses ipv4_addrs_sorted =
                sorted_addresses_from_svec(&ipv4_addrs);
        struct sorted_addresses ipv6_addrs_sorted =
                sorted_addresses_from_svec(&ipv6_addrs);

        update_sb_addr_set(&ipv4_addrs_sorted, sb_addr_set_v4);
        update_sb_addr_set(&ipv6_addrs_sorted, sb_addr_set_v6);

        free(ipv4_addrs_name);
        free(ipv6_addrs_name);
        svec_destroy(&ipv4_addrs);
        svec_destroy(&ipv6_addrs);
    }

    return true;
}

/* static functions. */
static void
sync_addr_set(struct ovsdb_idl_txn *ovnsb_txn, const char *name,
              struct sorted_addresses *addresses,
              struct shash *sb_address_sets)
{
    const struct sbrec_address_set *sb_address_set;
    sb_address_set = shash_find_and_delete(sb_address_sets,
                                           name);
    if (!sb_address_set) {
        sb_address_set = sbrec_address_set_insert(ovnsb_txn);
        sbrec_address_set_set_name(sb_address_set, name);
        sbrec_address_set_set_addresses(sb_address_set, addresses->arr,
                                        addresses->n);
    } else {
        update_sb_addr_set(addresses, sb_address_set);
    }
}

/* OVN_Southbound Address_Set table contains same records as in north
 * bound, plus
 *   - the records generated from Port_Group table in north bound.
 *
 *     There are 2 records generated from each port group, one for IPv4, and
 *     one for IPv6, named in the format: <port group name>_ip4 and
 *    <port group name>_ip6 respectively. MAC addresses are ignored.
 *
 *   - the records generated for the load balancer VIP addresses which are
 *     routable from each logical router.
 *
 * We always update OVN_Southbound to match the Address_Set and Port_Group
 * in OVN_Northbound, so that the address sets used in Logical_Flows in
 * OVN_Southbound is checked against the proper set.*/
static void
sync_addr_sets(struct ovsdb_idl_txn *ovnsb_txn,
               const struct nbrec_address_set_table *nb_address_set_table,
               const struct nbrec_port_group_table *nb_port_group_table,
               const struct sbrec_address_set_table *sb_address_set_table,
               const struct ovn_datapaths *lr_datapaths)
{
    struct shash sb_address_sets = SHASH_INITIALIZER(&sb_address_sets);

    const struct sbrec_address_set *sb_address_set;
    SBREC_ADDRESS_SET_TABLE_FOR_EACH (sb_address_set,
                                      sb_address_set_table) {
        shash_add(&sb_address_sets, sb_address_set->name, sb_address_set);
    }

    /* Service monitor MAC. */
    const char *svc_monitor_macp = northd_get_svc_monitor_mac();
    struct sorted_addresses svc = {
            .arr = &svc_monitor_macp,
            .n = 1,
    };
    sync_addr_set(ovnsb_txn, "svc_monitor_mac", &svc, &sb_address_sets);

    /* sync port group generated address sets first */
    const struct nbrec_port_group *nb_port_group;
    NBREC_PORT_GROUP_TABLE_FOR_EACH (nb_port_group,
                                     nb_port_group_table) {
        struct svec ipv4_addrs = SVEC_EMPTY_INITIALIZER;
        struct svec ipv6_addrs = SVEC_EMPTY_INITIALIZER;
        build_port_group_address_set(nb_port_group, &ipv4_addrs, &ipv6_addrs);
        char *ipv4_addrs_name = xasprintf("%s_ip4", nb_port_group->name);
        char *ipv6_addrs_name = xasprintf("%s_ip6", nb_port_group->name);

        struct sorted_addresses ipv4_addrs_sorted =
                sorted_addresses_from_svec(&ipv4_addrs);
        struct sorted_addresses ipv6_addrs_sorted =
                sorted_addresses_from_svec(&ipv6_addrs);

        sync_addr_set(ovnsb_txn, ipv4_addrs_name,
                      &ipv4_addrs_sorted, &sb_address_sets);
        sync_addr_set(ovnsb_txn, ipv6_addrs_name,
                      &ipv6_addrs_sorted, &sb_address_sets);
        free(ipv4_addrs_name);
        free(ipv6_addrs_name);
        svec_destroy(&ipv4_addrs);
        svec_destroy(&ipv6_addrs);
    }

    /* Sync router load balancer VIP generated address sets. */
    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &lr_datapaths->datapaths) {
        ovs_assert(od->nbr);

        if (sset_count(&od->lb_ips->ips_v4_reachable)) {
            char *ipv4_addrs_name = lr_lb_address_set_name(od->tunnel_key,
                                                           AF_INET);

            struct sorted_addresses ipv4_addrs_sorted =
                    sorted_addresses_from_sset(&od->lb_ips->ips_v4_reachable);

            sync_addr_set(ovnsb_txn, ipv4_addrs_name,
                          &ipv4_addrs_sorted, &sb_address_sets);
            free(ipv4_addrs_sorted.arr);
            free(ipv4_addrs_name);
        }

        if (sset_count(&od->lb_ips->ips_v6_reachable)) {
            char *ipv6_addrs_name = lr_lb_address_set_name(od->tunnel_key,
                                                           AF_INET6);
            struct sorted_addresses ipv6_addrs_sorted =
                    sorted_addresses_from_sset(&od->lb_ips->ips_v6_reachable);

            sync_addr_set(ovnsb_txn, ipv6_addrs_name,
                          &ipv6_addrs_sorted, &sb_address_sets);
            free(ipv6_addrs_sorted.arr);
            free(ipv6_addrs_name);
        }
    }

    /* sync user defined address sets, which may overwrite port group
     * generated address sets if same name is used */
    const struct nbrec_address_set *nb_address_set;
    NBREC_ADDRESS_SET_TABLE_FOR_EACH (nb_address_set,
                                      nb_address_set_table) {
        struct sorted_addresses addrs =
                sorted_addresses_from_nbrec(nb_address_set);
        sync_addr_set(ovnsb_txn, nb_address_set->name,
                      &addrs, &sb_address_sets);
    }

    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &sb_address_sets) {
        sbrec_address_set_delete(node->data);
        shash_delete(&sb_address_sets, node);
    }
    shash_destroy(&sb_address_sets);
}

static void
update_sb_addr_set(struct sorted_addresses *nb_addresses,
                   const struct sbrec_address_set *sb_as)
{
    size_t nb_index, sb_index;

    const char **nb_arr = nb_addresses->arr;
    char **sb_arr = sb_as->addresses;
    size_t nb_n = nb_addresses->n;
    size_t sb_n = sb_as->n_addresses;

    for (nb_index = sb_index = 0; nb_index < nb_n && sb_index < sb_n;) {
        int cmp = strcmp(nb_arr[nb_index], sb_arr[sb_index]);
        if (cmp < 0) {
            sbrec_address_set_update_addresses_addvalue(sb_as,
                                                        nb_arr[nb_index]);
            nb_index++;
        } else if (cmp > 0) {
            sbrec_address_set_update_addresses_delvalue(sb_as,
                                                        sb_arr[sb_index]);
            sb_index++;
        } else {
            nb_index++;
            sb_index++;
        }
    }

    for (; nb_index < nb_n; nb_index++) {
        sbrec_address_set_update_addresses_addvalue(sb_as, nb_arr[nb_index]);
    }

    for (; sb_index < sb_n; sb_index++) {
        sbrec_address_set_update_addresses_delvalue(sb_as, sb_arr[sb_index]);
    }
}

static void
build_port_group_address_set(const struct nbrec_port_group *nb_port_group,
                             struct svec *ipv4_addrs,
                             struct svec *ipv6_addrs)
{
    for (size_t i = 0; i < nb_port_group->n_ports; i++) {
        for (size_t j = 0; j < nb_port_group->ports[i]->n_addresses; j++) {
            const char *addrs = nb_port_group->ports[i]->addresses[j];
            if (!is_dynamic_lsp_address(addrs)) {
                split_addresses(addrs, ipv4_addrs, ipv6_addrs);
            }
        }
        if (nb_port_group->ports[i]->dynamic_addresses) {
            split_addresses(nb_port_group->ports[i]->dynamic_addresses,
                            ipv4_addrs, ipv6_addrs);
        }
    }
}

/* Finds and returns the address set with the given 'name', or NULL if no such
 * address set exists. */
static const struct sbrec_address_set *
sb_address_set_lookup_by_name(struct ovsdb_idl_index *sbrec_addr_set_by_name,
                              const char *name)
{
    struct sbrec_address_set *target = sbrec_address_set_index_init_row(
        sbrec_addr_set_by_name);
    sbrec_address_set_index_set_name(target, name);

    struct sbrec_address_set *retval = sbrec_address_set_index_find(
        sbrec_addr_set_by_name, target);

    sbrec_address_set_index_destroy_row(target);

    return retval;
}

static struct sorted_addresses
sorted_addresses_from_nbrec(const struct nbrec_address_set *nb_as)
{
    /* The DB is already sorted. */
    return (struct sorted_addresses) {
        .arr = (const char **) nb_as->addresses,
        .n = nb_as->n_addresses,
    };
}

static struct sorted_addresses
sorted_addresses_from_svec(struct svec *addresses)
{
    svec_sort(addresses);
    return (struct sorted_addresses) {
        .arr = (const char **) addresses->names,
        .n = addresses->n,
    };
}

static struct sorted_addresses
sorted_addresses_from_sset(struct sset *addresses)
{
    return (struct sorted_addresses) {
        .arr = sset_sort(addresses),
        .n = sset_count(addresses),
    };
}
