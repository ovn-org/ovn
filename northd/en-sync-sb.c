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

static void sync_addr_set(struct ovsdb_idl_txn *ovnsb_txn, const char *name,
                          struct sorted_array *addresses,
                          struct shash *sb_address_sets);
static void sync_addr_sets(struct ovsdb_idl_txn *ovnsb_txn,
                           const struct nbrec_address_set_table *,
                           const struct nbrec_port_group_table *,
                           const struct sbrec_address_set_table *,
                           const struct ovn_datapaths *lr_datapaths);
static const struct sbrec_address_set *sb_address_set_lookup_by_name(
    struct ovsdb_idl_index *, const char *name);
static void update_sb_addr_set(struct sorted_array *,
                               const struct sbrec_address_set *);
static void build_port_group_address_set(const struct nbrec_port_group *,
                                         struct svec *ipv4_addrs,
                                         struct svec *ipv6_addrs);

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
        struct sorted_array addrs =
            sorted_array_from_dbrec(nb_addr_set, addresses);
        update_sb_addr_set(&addrs, sb_addr_set);
        sorted_array_destroy(&addrs);
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

        struct sorted_array ipv4_addrs_sorted =
                sorted_array_from_svec(&ipv4_addrs);
        struct sorted_array ipv6_addrs_sorted =
                sorted_array_from_svec(&ipv6_addrs);

        update_sb_addr_set(&ipv4_addrs_sorted, sb_addr_set_v4);
        update_sb_addr_set(&ipv6_addrs_sorted, sb_addr_set_v6);

        sorted_array_destroy(&ipv4_addrs_sorted);
        sorted_array_destroy(&ipv6_addrs_sorted);
        svec_destroy(&ipv4_addrs);
        svec_destroy(&ipv6_addrs);
        free(ipv4_addrs_name);
        free(ipv6_addrs_name);
    }

    return true;
}

/* sync_to_sb_lb engine node functions.
 * This engine node syncs the SB load balancers.
 */
void *
en_sync_to_sb_lb_init(struct engine_node *node OVS_UNUSED,
                      struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_sync_to_sb_lb_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct sbrec_load_balancer_table *sb_load_balancer_table =
        EN_OVSDB_GET(engine_get_input("SB_load_balancer", node));
    const struct engine_context *eng_ctx = engine_get_context();
    struct northd_data *northd_data = engine_get_input_data("northd", node);

    sync_lbs(eng_ctx->ovnsb_idl_txn, sb_load_balancer_table,
             &northd_data->ls_datapaths, &northd_data->lb_datapaths_map);
    engine_set_node_state(node, EN_UPDATED);
}

void
en_sync_to_sb_lb_cleanup(void *data OVS_UNUSED)
{

}

bool
sync_to_sb_lb_northd_handler(struct engine_node *node, void *data OVS_UNUSED)
{
    struct northd_data *nd = engine_get_input_data("northd", node);
    if (nd->change_tracked) {
        /* There are only NB LSP related changes and these can be safely
         * ignore and returned true.  However in case the northd engine
         * tracking data includes other changes, we need to do additional
         * checks before safely ignoring. */
        return true;
    }
    return false;
}

/* static functions. */
static void
sync_addr_set(struct ovsdb_idl_txn *ovnsb_txn, const char *name,
              struct sorted_array *addresses,
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
    struct sorted_array svc = sorted_array_create(&svc_monitor_macp, 1, false);
    sync_addr_set(ovnsb_txn, "svc_monitor_mac", &svc, &sb_address_sets);
    sorted_array_destroy(&svc);

    /* sync port group generated address sets first */
    const struct nbrec_port_group *nb_port_group;
    NBREC_PORT_GROUP_TABLE_FOR_EACH (nb_port_group,
                                     nb_port_group_table) {
        struct svec ipv4_addrs = SVEC_EMPTY_INITIALIZER;
        struct svec ipv6_addrs = SVEC_EMPTY_INITIALIZER;
        build_port_group_address_set(nb_port_group, &ipv4_addrs, &ipv6_addrs);
        char *ipv4_addrs_name = xasprintf("%s_ip4", nb_port_group->name);
        char *ipv6_addrs_name = xasprintf("%s_ip6", nb_port_group->name);

        struct sorted_array ipv4_addrs_sorted =
                sorted_array_from_svec(&ipv4_addrs);
        struct sorted_array ipv6_addrs_sorted =
                sorted_array_from_svec(&ipv6_addrs);

        sync_addr_set(ovnsb_txn, ipv4_addrs_name,
                      &ipv4_addrs_sorted, &sb_address_sets);
        sync_addr_set(ovnsb_txn, ipv6_addrs_name,
                      &ipv6_addrs_sorted, &sb_address_sets);
        sorted_array_destroy(&ipv4_addrs_sorted);
        sorted_array_destroy(&ipv6_addrs_sorted);
        svec_destroy(&ipv4_addrs);
        svec_destroy(&ipv6_addrs);
        free(ipv4_addrs_name);
        free(ipv6_addrs_name);
    }

    /* Sync router load balancer VIP generated address sets. */
    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &lr_datapaths->datapaths) {
        ovs_assert(od->nbr);

        if (sset_count(&od->lb_ips->ips_v4_reachable)) {
            char *ipv4_addrs_name = lr_lb_address_set_name(od->tunnel_key,
                                                           AF_INET);

            struct sorted_array ipv4_addrs_sorted =
                    sorted_array_from_sset(&od->lb_ips->ips_v4_reachable);

            sync_addr_set(ovnsb_txn, ipv4_addrs_name,
                          &ipv4_addrs_sorted, &sb_address_sets);
            sorted_array_destroy(&ipv4_addrs_sorted);
            free(ipv4_addrs_name);
        }

        if (sset_count(&od->lb_ips->ips_v6_reachable)) {
            char *ipv6_addrs_name = lr_lb_address_set_name(od->tunnel_key,
                                                           AF_INET6);
            struct sorted_array ipv6_addrs_sorted =
                    sorted_array_from_sset(&od->lb_ips->ips_v6_reachable);

            sync_addr_set(ovnsb_txn, ipv6_addrs_name,
                          &ipv6_addrs_sorted, &sb_address_sets);
            sorted_array_destroy(&ipv6_addrs_sorted);
            free(ipv6_addrs_name);
        }
    }

    /* sync user defined address sets, which may overwrite port group
     * generated address sets if same name is used */
    const struct nbrec_address_set *nb_address_set;
    NBREC_ADDRESS_SET_TABLE_FOR_EACH (nb_address_set,
                                      nb_address_set_table) {
        struct sorted_array addrs =
                sorted_array_from_dbrec(nb_address_set, addresses);
        sync_addr_set(ovnsb_txn, nb_address_set->name,
                      &addrs, &sb_address_sets);
        sorted_array_destroy(&addrs);
    }

    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &sb_address_sets) {
        sbrec_address_set_delete(node->data);
        shash_delete(&sb_address_sets, node);
    }
    shash_destroy(&sb_address_sets);
}

static void
sb_addr_set_apply_diff(const void *arg, const char *item, bool add)
{
    const struct sbrec_address_set *as = arg;
    if (add) {
        sbrec_address_set_update_addresses_addvalue(as, item);
    } else {
        sbrec_address_set_update_addresses_delvalue(as, item);
    }
}

static void
update_sb_addr_set(struct sorted_array *nb_addresses,
                   const struct sbrec_address_set *sb_as)
{
    struct sorted_array sb_addresses =
        sorted_array_from_dbrec(sb_as, addresses);
    sorted_array_apply_diff(nb_addresses, &sb_addresses,
                            sb_addr_set_apply_diff, sb_as);
    sorted_array_destroy(&sb_addresses);
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
