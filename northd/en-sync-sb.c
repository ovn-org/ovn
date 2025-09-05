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

/* OVS includes. */
#include "lib/svec.h"
#include "openvswitch/util.h"

/* OVN includes. */
#include "en-lr-nat.h"
#include "en-global-config.h"
#include "en-lr-stateful.h"
#include "en-sync-sb.h"
#include "lb.h"
#include "lib/inc-proc-eng.h"
#include "lib/lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "lflow-mgr.h"
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
                           const struct lr_stateful_table *,
                           const struct ovn_datapaths *,
                           const char *svc_monitor_macp);
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

enum engine_node_state
en_sync_to_sb_run(struct engine_node *node OVS_UNUSED, void *data OVS_UNUSED)
{
    return EN_UPDATED;
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

enum engine_node_state
en_sync_to_sb_addr_set_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct nbrec_address_set_table *nb_address_set_table =
        EN_OVSDB_GET(engine_get_input("NB_address_set", node));
    const struct nbrec_port_group_table *nb_port_group_table =
        EN_OVSDB_GET(engine_get_input("NB_port_group", node));
    const struct sbrec_address_set_table *sb_address_set_table =
        EN_OVSDB_GET(engine_get_input("SB_address_set", node));

    const struct engine_context *eng_ctx = engine_get_context();
    const struct ed_type_lr_stateful *lr_stateful_data =
        engine_get_input_data("lr_stateful", node);
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);
    sync_addr_sets(eng_ctx->ovnsb_idl_txn, nb_address_set_table,
                   nb_port_group_table, sb_address_set_table,
                   &lr_stateful_data->table,
                   &northd_data->lr_datapaths,
                   global_config->svc_monitor_mac);

    return EN_UPDATED;
}

void
en_sync_to_sb_addr_set_cleanup(void *data OVS_UNUSED)
{

}

enum engine_input_handler_result
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
            return EN_UNHANDLED;
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
            return EN_UNHANDLED;
        }
        struct sorted_array addrs =
            sorted_array_from_dbrec(nb_addr_set, addresses);
        update_sb_addr_set(&addrs, sb_addr_set);
        sorted_array_destroy(&addrs);
    }

    return EN_HANDLED_UNCHANGED;
}

enum engine_input_handler_result
sync_to_sb_addr_set_nb_port_group_handler(struct engine_node *node,
                                          void *data OVS_UNUSED)
{
    const struct nbrec_port_group *nb_pg;
    const struct nbrec_port_group_table *nb_port_group_table =
        EN_OVSDB_GET(engine_get_input("NB_port_group", node));
    NBREC_PORT_GROUP_TABLE_FOR_EACH_TRACKED (nb_pg, nb_port_group_table) {
        if (nbrec_port_group_is_new(nb_pg) ||
                nbrec_port_group_is_deleted(nb_pg)) {
            return EN_UNHANDLED;
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
            return EN_UNHANDLED;
        }
        char *ipv6_addrs_name = xasprintf("%s_ip6", nb_pg->name);
        const struct sbrec_address_set *sb_addr_set_v6 =
            sb_address_set_lookup_by_name(sbrec_address_set_by_name,
                                          ipv6_addrs_name);
        if (!sb_addr_set_v6) {
            free(ipv4_addrs_name);
            free(ipv6_addrs_name);
            return EN_UNHANDLED;
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

    return EN_HANDLED_UNCHANGED;
}

/* sync_to_sb_lb engine node functions.
 * This engine node syncs the SB load balancers.
 */
struct sb_lb_record {
    struct hmap_node key_node;  /* Index on 'nblb->header_.uuid'. */

    struct ovn_lb_datapaths *lb_dps;
    const struct sbrec_load_balancer *sbrec_lb;
    struct ovn_dp_group *ls_dpg;
    struct ovn_dp_group *lr_dpg;
};

struct sb_lb_table {
    struct hmap entries; /* Stores struct sb_lb_record. */
    struct hmap ls_dp_groups;
    struct hmap lr_dp_groups;
};

struct ed_type_sync_to_sb_lb_data {
    struct sb_lb_table sb_lbs;
};

static void sb_lb_table_init(struct sb_lb_table *);
static void sb_lb_table_clear(struct sb_lb_table *);
static void sb_lb_table_destroy(struct sb_lb_table *);

static struct sb_lb_record *sb_lb_table_find(struct hmap *sb_lbs,
                                             const struct uuid *);
static void sb_lb_table_build_and_sync(struct sb_lb_table *,
                                struct ovsdb_idl_txn *ovnsb_txn,
                                const struct sbrec_load_balancer_table *,
                                const struct sbrec_logical_dp_group_table *,
                                struct hmap *lb_dps_map,
                                struct ovn_datapaths *ls_datapaths,
                                struct ovn_datapaths *lr_datapaths,
                                struct chassis_features *);
static bool sync_sb_lb_record(struct sb_lb_record *,
                              const struct sbrec_load_balancer *,
                              const struct sbrec_logical_dp_group_table *,
                              struct sb_lb_table *,
                              struct ovsdb_idl_txn *ovnsb_txn,
                              struct ovn_datapaths *ls_datapaths,
                              struct ovn_datapaths *lr_datapaths,
                              struct chassis_features *);
static bool sync_changed_lbs(struct sb_lb_table *,
                             struct ovsdb_idl_txn *ovnsb_txn,
                             const struct sbrec_load_balancer_table *,
                             const struct sbrec_logical_dp_group_table *,
                             struct tracked_lbs *,
                             struct ovn_datapaths *ls_datapaths,
                             struct ovn_datapaths *lr_datapaths,
                             struct chassis_features *);

void *
en_sync_to_sb_lb_init(struct engine_node *node OVS_UNUSED,
                      struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_sync_to_sb_lb_data *data = xzalloc(sizeof *data);
    sb_lb_table_init(&data->sb_lbs);

    return data;
}

enum engine_node_state
en_sync_to_sb_lb_run(struct engine_node *node, void *data_)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    const struct sbrec_load_balancer_table *sb_load_balancer_table =
        EN_OVSDB_GET(engine_get_input("SB_load_balancer", node));
    const struct sbrec_logical_dp_group_table *sb_dpgrp_table =
        EN_OVSDB_GET(engine_get_input("SB_logical_dp_group", node));
    struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);
    const struct engine_context *eng_ctx = engine_get_context();
    struct ed_type_sync_to_sb_lb_data *data = data_;

    sb_lb_table_clear(&data->sb_lbs);
    sb_lb_table_build_and_sync(&data->sb_lbs, eng_ctx->ovnsb_idl_txn,
                               sb_load_balancer_table,
                               sb_dpgrp_table,
                               &northd_data->lb_datapaths_map,
                               &northd_data->ls_datapaths,
                               &northd_data->lr_datapaths,
                               &global_config->features);

    return EN_UPDATED;
}

void
en_sync_to_sb_lb_cleanup(void *data_)
{
    struct ed_type_sync_to_sb_lb_data *data = data_;
    sb_lb_table_destroy(&data->sb_lbs);
}

enum engine_input_handler_result
sync_to_sb_lb_northd_handler(struct engine_node *node, void *data_)
{
    struct northd_data *nd = engine_get_input_data("northd", node);

    if (!northd_has_tracked_data(&nd->trk_data)) {
        /* Return false if no tracking data. */
        return EN_UNHANDLED;
    }

    if (!northd_has_lbs_in_tracked_data(&nd->trk_data)) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct engine_context *eng_ctx = engine_get_context();
    const struct sbrec_logical_dp_group_table *sb_dpgrp_table =
        EN_OVSDB_GET(engine_get_input("SB_logical_dp_group", node));
    const struct sbrec_load_balancer_table *sb_lb_table =
        EN_OVSDB_GET(engine_get_input("SB_load_balancer", node));
    struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);
    struct ed_type_sync_to_sb_lb_data *data = data_;

    if (!sync_changed_lbs(&data->sb_lbs, eng_ctx->ovnsb_idl_txn, sb_lb_table,
                          sb_dpgrp_table, &nd->trk_data.trk_lbs,
                          &nd->ls_datapaths, &nd->lr_datapaths,
                          &global_config->features)) {
        return EN_UNHANDLED;
    }

    return EN_HANDLED_UPDATED;
}

enum engine_input_handler_result
sync_to_sb_lb_sb_load_balancer(struct engine_node *node, void *data_)
{
    const struct sbrec_load_balancer_table *sb_lb_table =
        EN_OVSDB_GET(engine_get_input("SB_load_balancer", node));
    struct ed_type_sync_to_sb_lb_data *data = data_;

    /* The only reason to handle SB.Load_Balancer updates is to detect
     * spurious records being created in clustered databases due to
     * lack of indexing on the SB.Load_Balancer table.  All other changes
     * are valid and performed by northd, the only write-client for
     * this table. */
    const struct sbrec_load_balancer *sb_lb;
    SBREC_LOAD_BALANCER_TABLE_FOR_EACH_TRACKED (sb_lb, sb_lb_table) {
        if (!sbrec_load_balancer_is_new(sb_lb)) {
            continue;
        }

        if (!sb_lb_table_find(&data->sb_lbs.entries, &sb_lb->header_.uuid)) {
            return EN_UNHANDLED;
        }
    }
    return EN_HANDLED_UNCHANGED;
}

/* sync_to_sb_pb engine node functions.
 * This engine node syncs the SB Port Bindings (partly).
 * en_northd engine create the SB Port binding rows and
 * updates most of the columns.
 * This engine node updates the port binding columns which
 * needs to be updated after northd engine is run.
 */

void *
en_sync_to_sb_pb_init(struct engine_node *node OVS_UNUSED,
                      struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

enum engine_node_state
en_sync_to_sb_pb_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    struct ed_type_lr_stateful *lr_stateful_data =
        engine_get_input_data("lr_stateful", node);

    sync_pbs(eng_ctx->ovnsb_idl_txn, &northd_data->ls_ports,
             &northd_data->lr_ports,
             &lr_stateful_data->table);
    return EN_UPDATED;
}

void
en_sync_to_sb_pb_cleanup(void *data OVS_UNUSED)
{

}

enum engine_input_handler_result
sync_to_sb_pb_northd_handler(struct engine_node *node, void *data OVS_UNUSED)
{
    struct northd_data *nd = engine_get_input_data("northd", node);
    if (!northd_has_tracked_data(&nd->trk_data) ||
            northd_has_lbs_in_tracked_data(&nd->trk_data)) {
        /* Return false if no tracking data or if lbs changed. */
        return EN_UNHANDLED;
    }

    struct ed_type_lr_stateful *lr_stateful_data =
        engine_get_input_data("lr_stateful", node);

    if (!sync_pbs_for_northd_changed_ovn_ports(&nd->trk_data.trk_lsps,
                                               &lr_stateful_data->table)) {
        return EN_UNHANDLED;
    }

    return EN_HANDLED_UPDATED;
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
               const struct lr_stateful_table *lr_statefuls,
               const struct ovn_datapaths *lr_datapaths,
               const char *svc_monitor_macp)
{
    struct shash sb_address_sets = SHASH_INITIALIZER(&sb_address_sets);

    const struct sbrec_address_set *sb_address_set;
    SBREC_ADDRESS_SET_TABLE_FOR_EACH (sb_address_set,
                                      sb_address_set_table) {
        shash_add(&sb_address_sets, sb_address_set->name, sb_address_set);
    }

    /* Service monitor MAC. */
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
    const struct lr_stateful_record *lr_stateful_rec;
    LR_STATEFUL_TABLE_FOR_EACH (lr_stateful_rec, lr_statefuls) {
        const struct ovn_datapath *od =
            ovn_datapaths_find_by_index(lr_datapaths,
                                        lr_stateful_rec->lr_index);
        if (sset_count(&lr_stateful_rec->lb_ips->ips_v4_reachable)) {
            char *ipv4_addrs_name =
                lr_lb_address_set_name(od->tunnel_key, AF_INET);

            struct sorted_array ipv4_addrs_sorted = sorted_array_from_sset(
                &lr_stateful_rec->lb_ips->ips_v4_reachable);

            sync_addr_set(ovnsb_txn, ipv4_addrs_name,
                          &ipv4_addrs_sorted, &sb_address_sets);
            sorted_array_destroy(&ipv4_addrs_sorted);
            free(ipv4_addrs_name);
        }

        if (sset_count(&lr_stateful_rec->lb_ips->ips_v6_reachable)) {
            char *ipv6_addrs_name =
                lr_lb_address_set_name(od->tunnel_key, AF_INET6);
            struct sorted_array ipv6_addrs_sorted = sorted_array_from_sset(
                &lr_stateful_rec->lb_ips->ips_v6_reachable);

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

/* static functions related to sync_to_sb_lb */

static void
sb_lb_table_init(struct sb_lb_table *sb_lbs)
{
    hmap_init(&sb_lbs->entries);
    ovn_dp_groups_init(&sb_lbs->ls_dp_groups);
    ovn_dp_groups_init(&sb_lbs->lr_dp_groups);
}

static void
sb_lb_table_clear(struct sb_lb_table *sb_lbs)
{
    struct sb_lb_record *sb_lb;
    HMAP_FOR_EACH_POP (sb_lb, key_node, &sb_lbs->entries) {
        free(sb_lb);
    }

    ovn_dp_groups_clear(&sb_lbs->ls_dp_groups);
    ovn_dp_groups_clear(&sb_lbs->lr_dp_groups);
}

static void
sb_lb_table_destroy(struct sb_lb_table *sb_lbs)
{
    sb_lb_table_clear(sb_lbs);
    hmap_destroy(&sb_lbs->entries);
    ovn_dp_groups_destroy(&sb_lbs->ls_dp_groups);
    ovn_dp_groups_destroy(&sb_lbs->lr_dp_groups);
}

static struct sb_lb_record *
sb_lb_table_find(struct hmap *sb_lbs, const struct uuid *lb_uuid)
{
    struct sb_lb_record *sb_lb;
    HMAP_FOR_EACH_WITH_HASH (sb_lb, key_node, uuid_hash(lb_uuid),
                             sb_lbs) {
        if (uuid_equals(&sb_lb->lb_dps->lb->nlb->header_.uuid, lb_uuid)) {
            return sb_lb;
        }
    }

    return NULL;
}

static void
sb_lb_table_build_and_sync(
    struct sb_lb_table *sb_lbs, struct ovsdb_idl_txn *ovnsb_txn,
    const struct sbrec_load_balancer_table *sb_lb_table,
    const struct sbrec_logical_dp_group_table *sb_dpgrp_table,
    struct hmap *lb_dps_map, struct ovn_datapaths *ls_datapaths,
    struct ovn_datapaths *lr_datapaths,
    struct chassis_features *chassis_features)
{
    struct hmap tmp_sb_lbs = HMAP_INITIALIZER(&tmp_sb_lbs);
    struct ovn_lb_datapaths *lb_dps;
    struct sb_lb_record *sb_lb;

    HMAP_FOR_EACH (lb_dps, hmap_node, lb_dps_map) {
        if (dynamic_bitmap_is_empty(&lb_dps->nb_ls_map) &&
            dynamic_bitmap_is_empty(&lb_dps->nb_lr_map)) {
            continue;
        }

        sb_lb = xzalloc(sizeof *sb_lb);
        sb_lb->lb_dps = lb_dps;
        hmap_insert(&tmp_sb_lbs, &sb_lb->key_node,
                    uuid_hash(&lb_dps->lb->nlb->header_.uuid));
    }

    const struct sbrec_load_balancer *sbrec_lb;
    SBREC_LOAD_BALANCER_TABLE_FOR_EACH_SAFE (sbrec_lb,
                                             sb_lb_table) {
        sb_lb = sb_lb_table_find(&tmp_sb_lbs, &sbrec_lb->header_.uuid);
        if (sb_lb) {
            sb_lb->sbrec_lb = sbrec_lb;
            bool success = sync_sb_lb_record(sb_lb, sbrec_lb, sb_dpgrp_table,
                                             sb_lbs, ovnsb_txn, ls_datapaths,
                                             lr_datapaths, chassis_features);
            /* Since we are rebuilding and syncing,  sync_sb_lb_record should
             * not return false. */
            ovs_assert(success);

            hmap_remove(&tmp_sb_lbs, &sb_lb->key_node);
            hmap_insert(&sb_lbs->entries, &sb_lb->key_node,
                        uuid_hash(&sb_lb->lb_dps->lb->nlb->header_.uuid));
        } else {
            sbrec_load_balancer_delete(sbrec_lb);
        }
    }

    HMAP_FOR_EACH_POP (sb_lb, key_node, &tmp_sb_lbs) {
        bool success = sync_sb_lb_record(sb_lb, NULL, sb_dpgrp_table, sb_lbs,
                                         ovnsb_txn, ls_datapaths, lr_datapaths,
                                         chassis_features);
        /* Since we are rebuilding and syncing,  sync_sb_lb_record should not
         * return false. */
        ovs_assert(success);

        hmap_insert(&sb_lbs->entries, &sb_lb->key_node,
                    uuid_hash(&sb_lb->lb_dps->lb->nlb->header_.uuid));
    }

    hmap_destroy(&tmp_sb_lbs);
}

static bool
sync_sb_lb_record(struct sb_lb_record *sb_lb,
                  const struct sbrec_load_balancer *sbrec_lb,
                  const struct sbrec_logical_dp_group_table *sb_dpgrp_table,
                  struct sb_lb_table *sb_lbs,
                  struct ovsdb_idl_txn *ovnsb_txn,
                  struct ovn_datapaths *ls_datapaths,
                  struct ovn_datapaths *lr_datapaths,
                  struct chassis_features *chassis_features)
{
    struct sbrec_logical_dp_group *sbrec_ls_dp_group = NULL;
    struct sbrec_logical_dp_group *sbrec_lr_dp_group = NULL;
    const struct ovn_lb_datapaths *lb_dps;
    struct ovn_dp_group *pre_sync_ls_dpg;
    struct ovn_dp_group *pre_sync_lr_dpg;

    lb_dps = sb_lb->lb_dps;
    pre_sync_ls_dpg = sb_lb->ls_dpg;
    pre_sync_lr_dpg = sb_lb->lr_dpg;

    if (!sbrec_lb) {
        const struct uuid *nb_uuid = &lb_dps->lb->nlb->header_.uuid;
        sbrec_lb = sbrec_load_balancer_insert_persist_uuid(ovnsb_txn, nb_uuid);
    } else {
        sbrec_ls_dp_group =
            chassis_features->ls_dpg_column
            ? sbrec_lb->ls_datapath_group
            : sbrec_lb->datapath_group; /* deprecated */

        sbrec_lr_dp_group = sbrec_lb->lr_datapath_group;
    }

    if (!dynamic_bitmap_is_empty(&lb_dps->nb_ls_map)) {
        sb_lb->ls_dpg = ovn_dp_group_get(&sb_lbs->ls_dp_groups,
                                         lb_dps->nb_ls_map.n_elems,
                                         lb_dps->nb_ls_map.map,
                                         ods_size(ls_datapaths));
        if (sb_lb->ls_dpg) {
            /* Update the dpg's sb dp_group. */
            sb_lb->ls_dpg->dp_group =
                sbrec_logical_dp_group_table_get_for_uuid(sb_dpgrp_table,
                                                    &sb_lb->ls_dpg->dpg_uuid);
            if (!sb_lb->ls_dpg->dp_group) {
                /* Ideally this should not happen.  But it can still happen
                 * due to 2 reasons:
                 * 1. There is a bug in the dp_group management.  We should
                 *    perhaps assert here.
                 * 2. A User or CMS may delete the logical_dp_groups in SB DB
                 *    or clear the SB:Load_balancer.ls_datapath_group column
                 *    (intentionally or accidentally)
                 *
                 * Because of (2) it is better to return false instead of
                 * assert,so that we recover from th inconsistent SB DB.
                 */
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "SB Load balancer [%s]'s ls_dp_group column "
                            "is not set (which is unexpected).  It should "
                            "have been referencing the dp group ["UUID_FMT"]",
                            sb_lb->lb_dps->lb->nlb->name,
                            UUID_ARGS(&sb_lb->ls_dpg->dpg_uuid));
                return false;
            }
        } else {
            sb_lb->ls_dpg = ovn_dp_group_create(
                ovnsb_txn, &sb_lbs->ls_dp_groups, sbrec_ls_dp_group,
                lb_dps->nb_ls_map.n_elems, lb_dps->nb_ls_map.map,
                ods_size(ls_datapaths), true,
                ls_datapaths, lr_datapaths);
        }

        if (chassis_features->ls_dpg_column) {
            sbrec_load_balancer_set_ls_datapath_group(sbrec_lb,
                                                      sb_lb->ls_dpg->dp_group);
            sbrec_load_balancer_set_datapath_group(sbrec_lb, NULL);
        } else {
            /* datapath_group column is deprecated. */
            sbrec_load_balancer_set_ls_datapath_group(sbrec_lb, NULL);
            sbrec_load_balancer_set_datapath_group(sbrec_lb,
                                                   sb_lb->ls_dpg->dp_group);

        }
    } else {
        sbrec_load_balancer_set_ls_datapath_group(sbrec_lb, NULL);
        sbrec_load_balancer_set_datapath_group(sbrec_lb, NULL);
    }


    if (!dynamic_bitmap_is_empty(&lb_dps->nb_lr_map)) {
        sb_lb->lr_dpg = ovn_dp_group_get(&sb_lbs->lr_dp_groups,
                                         lb_dps->nb_lr_map.n_elems,
                                         lb_dps->nb_lr_map.map,
                                         ods_size(lr_datapaths));
        if (sb_lb->lr_dpg) {
            /* Update the dpg's sb dp_group. */
            sb_lb->lr_dpg->dp_group =
                sbrec_logical_dp_group_table_get_for_uuid(sb_dpgrp_table,
                                                    &sb_lb->lr_dpg->dpg_uuid);
            if (!sb_lb->lr_dpg->dp_group) {
                /* Ideally this should not happen.  But it can still happen
                 * due to 2 reasons:
                 * 1. There is a bug in the dp_group management.  We should
                 *    perhaps assert here.
                 * 2. A User or CMS may delete the logical_dp_groups in SB DB
                 *    or clear the SB:Load_balancer.lr_datapath_group column
                 *    (intentionally or accidentally)
                 *
                 * Because of (2) it is better to return false instead of
                 * assert,so that we recover from th inconsistent SB DB.
                 */
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "SB Load balancer [%s]'s lr_dp_group column "
                            "is not set (which is unexpected).  It should "
                            "have been referencing the dp group ["UUID_FMT"]",
                            sb_lb->lb_dps->lb->nlb->name,
                            UUID_ARGS(&sb_lb->lr_dpg->dpg_uuid));
                return false;
            }
        } else {
            sb_lb->lr_dpg = ovn_dp_group_create(
                ovnsb_txn, &sb_lbs->lr_dp_groups, sbrec_lr_dp_group,
                lb_dps->nb_lr_map.n_elems, lb_dps->nb_lr_map.map,
                ods_size(lr_datapaths), false,
                ls_datapaths, lr_datapaths);
        }

        sbrec_load_balancer_set_lr_datapath_group(sbrec_lb,
                                                  sb_lb->lr_dpg->dp_group);
    } else {
        sbrec_load_balancer_set_lr_datapath_group(sbrec_lb, NULL);
    }

    if (pre_sync_ls_dpg != sb_lb->ls_dpg) {
        if (sb_lb->ls_dpg) {
            inc_ovn_dp_group_ref(sb_lb->ls_dpg);
        }
        if (pre_sync_ls_dpg) {
            dec_ovn_dp_group_ref(&sb_lbs->ls_dp_groups, pre_sync_ls_dpg);
        }
    }

    if (pre_sync_lr_dpg != sb_lb->lr_dpg) {
        if (sb_lb->lr_dpg) {
            inc_ovn_dp_group_ref(sb_lb->lr_dpg);
        }
        if (pre_sync_lr_dpg) {
            dec_ovn_dp_group_ref(&sb_lbs->lr_dp_groups, pre_sync_lr_dpg);
        }
    }

    /* Update columns. */
    sbrec_load_balancer_set_name(sbrec_lb, lb_dps->lb->nlb->name);
    sbrec_load_balancer_set_vips(sbrec_lb,
                                 ovn_northd_lb_get_vips(lb_dps->lb));
    sbrec_load_balancer_set_protocol(sbrec_lb, lb_dps->lb->nlb->protocol);
    sbrec_load_balancer_set_options(sbrec_lb, &lb_dps->lb->nlb->options);
    /* Clearing 'datapaths' column, since 'dp_group' is in use. */
    sbrec_load_balancer_set_datapaths(sbrec_lb, NULL, 0);

    return true;
}

static bool
sync_changed_lbs(struct sb_lb_table *sb_lbs,
                 struct ovsdb_idl_txn *ovnsb_txn,
                 const struct sbrec_load_balancer_table *sb_lb_table,
                 const struct sbrec_logical_dp_group_table *sb_dpgrp_table,
                 struct tracked_lbs *trk_lbs,
                 struct ovn_datapaths *ls_datapaths,
                 struct ovn_datapaths *lr_datapaths,
                 struct chassis_features *chassis_features)
{
    struct ovn_lb_datapaths *lb_dps;
    struct hmapx_node *hmapx_node;
    struct sb_lb_record *sb_lb;

    HMAPX_FOR_EACH (hmapx_node, &trk_lbs->deleted) {
        lb_dps = hmapx_node->data;
        const struct uuid *nb_uuid = &lb_dps->lb->nlb->header_.uuid;
        sb_lb = sb_lb_table_find(&sb_lbs->entries, nb_uuid);
        if (sb_lb) {
            const struct sbrec_load_balancer *sbrec_lb =
                sbrec_load_balancer_table_get_for_uuid(sb_lb_table, nb_uuid);
            if (sbrec_lb) {
                sbrec_load_balancer_delete(sbrec_lb);
            }

            hmap_remove(&sb_lbs->entries, &sb_lb->key_node);
            free(sb_lb);
        }
    }

    HMAPX_FOR_EACH (hmapx_node, &trk_lbs->crupdated) {
        lb_dps = hmapx_node->data;
        const struct uuid *nb_uuid = &lb_dps->lb->nlb->header_.uuid;

        sb_lb = sb_lb_table_find(&sb_lbs->entries, nb_uuid);

        if (!sb_lb &&
            dynamic_bitmap_is_empty(&lb_dps->nb_ls_map) &&
            dynamic_bitmap_is_empty(&lb_dps->nb_lr_map)) {
            continue;
        }

        if (!sb_lb) {
            sb_lb = xzalloc(sizeof *sb_lb);
            sb_lb->lb_dps = lb_dps;
            hmap_insert(&sb_lbs->entries, &sb_lb->key_node,
                        uuid_hash(nb_uuid));
        } else {
            sb_lb->sbrec_lb =
                sbrec_load_balancer_table_get_for_uuid(sb_lb_table, nb_uuid);
        }

        if (sb_lb &&
            dynamic_bitmap_is_empty(&lb_dps->nb_ls_map) &&
            dynamic_bitmap_is_empty(&lb_dps->nb_lr_map)) {
            const struct sbrec_load_balancer *sbrec_lb =
                sbrec_load_balancer_table_get_for_uuid(sb_lb_table, nb_uuid);
            if (sbrec_lb) {
                sbrec_load_balancer_delete(sbrec_lb);
            }

            hmap_remove(&sb_lbs->entries, &sb_lb->key_node);
            free(sb_lb);
        }

        if (!sync_sb_lb_record(sb_lb, sb_lb->sbrec_lb, sb_dpgrp_table, sb_lbs,
                               ovnsb_txn, ls_datapaths, lr_datapaths,
                               chassis_features)) {
            return false;
        }
    }

    return true;
}
