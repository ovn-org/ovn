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
                          const char **addrs, size_t n_addrs,
                          struct shash *sb_address_sets);
static void sync_addr_sets(const struct nbrec_address_set_table *,
                           const struct nbrec_port_group_table *,
                           const struct sbrec_address_set_table *,
                           struct ovsdb_idl_txn *ovnsb_txn,
                           struct hmap *datapaths);

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

    sync_addr_sets(nb_address_set_table, nb_port_group_table,
                   sb_address_set_table, eng_ctx->ovnsb_idl_txn,
                   &northd_data->datapaths);

    engine_set_node_state(node, EN_UPDATED);
}

void
en_sync_to_sb_addr_set_cleanup(void *data OVS_UNUSED)
{

}

/* static functions. */
static void
sync_addr_set(struct ovsdb_idl_txn *ovnsb_txn, const char *name,
              const char **addrs, size_t n_addrs,
              struct shash *sb_address_sets)
{
    const struct sbrec_address_set *sb_address_set;
    sb_address_set = shash_find_and_delete(sb_address_sets,
                                           name);
    if (!sb_address_set) {
        sb_address_set = sbrec_address_set_insert(ovnsb_txn);
        sbrec_address_set_set_name(sb_address_set, name);
    }

    sbrec_address_set_set_addresses(sb_address_set,
                                    addrs, n_addrs);
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
sync_addr_sets(const struct nbrec_address_set_table *nb_address_set_table,
               const struct nbrec_port_group_table *nb_port_group_table,
               const struct sbrec_address_set_table *sb_address_set_table,
               struct ovsdb_idl_txn *ovnsb_txn, struct hmap *datapaths)
{
    struct shash sb_address_sets = SHASH_INITIALIZER(&sb_address_sets);

    const struct sbrec_address_set *sb_address_set;
    SBREC_ADDRESS_SET_TABLE_FOR_EACH (sb_address_set,
                                      sb_address_set_table) {
        shash_add(&sb_address_sets, sb_address_set->name, sb_address_set);
    }

    /* Service monitor MAC. */
    const char *svc_monitor_macp = northd_get_svc_monitor_mac();
    sync_addr_set(ovnsb_txn, "svc_monitor_mac", &svc_monitor_macp, 1,
                     &sb_address_sets);

    /* sync port group generated address sets first */
    const struct nbrec_port_group *nb_port_group;
    NBREC_PORT_GROUP_TABLE_FOR_EACH (nb_port_group,
                                     nb_port_group_table) {
        struct svec ipv4_addrs = SVEC_EMPTY_INITIALIZER;
        struct svec ipv6_addrs = SVEC_EMPTY_INITIALIZER;
        for (size_t i = 0; i < nb_port_group->n_ports; i++) {
            for (size_t j = 0; j < nb_port_group->ports[i]->n_addresses; j++) {
                const char *addrs = nb_port_group->ports[i]->addresses[j];
                if (!is_dynamic_lsp_address(addrs)) {
                    split_addresses(addrs, &ipv4_addrs, &ipv6_addrs);
                }
            }
            if (nb_port_group->ports[i]->dynamic_addresses) {
                split_addresses(nb_port_group->ports[i]->dynamic_addresses,
                                &ipv4_addrs, &ipv6_addrs);
            }
        }
        char *ipv4_addrs_name = xasprintf("%s_ip4", nb_port_group->name);
        char *ipv6_addrs_name = xasprintf("%s_ip6", nb_port_group->name);
        sync_addr_set(ovnsb_txn, ipv4_addrs_name,
                      /* "char **" is not compatible with "const char **" */
                      (const char **) ipv4_addrs.names,
                      ipv4_addrs.n, &sb_address_sets);
        sync_addr_set(ovnsb_txn, ipv6_addrs_name,
                      /* "char **" is not compatible with "const char **" */
                      (const char **) ipv6_addrs.names,
                      ipv6_addrs.n, &sb_address_sets);
        free(ipv4_addrs_name);
        free(ipv6_addrs_name);
        svec_destroy(&ipv4_addrs);
        svec_destroy(&ipv6_addrs);
    }

    /* Sync router load balancer VIP generated address sets. */
    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbr) {
            continue;
        }

        if (sset_count(&od->lb_ips->ips_v4_reachable)) {
            char *ipv4_addrs_name = lr_lb_address_set_name(od->tunnel_key,
                                                           AF_INET);
            const char **ipv4_addrs =
                sset_array(&od->lb_ips->ips_v4_reachable);

            sync_addr_set(ovnsb_txn, ipv4_addrs_name, ipv4_addrs,
                          sset_count(&od->lb_ips->ips_v4_reachable),
                          &sb_address_sets);
            free(ipv4_addrs_name);
            free(ipv4_addrs);
        }

        if (sset_count(&od->lb_ips->ips_v6_reachable)) {
            char *ipv6_addrs_name = lr_lb_address_set_name(od->tunnel_key,
                                                           AF_INET6);
            const char **ipv6_addrs =
                sset_array(&od->lb_ips->ips_v6_reachable);

            sync_addr_set(ovnsb_txn, ipv6_addrs_name, ipv6_addrs,
                          sset_count(&od->lb_ips->ips_v6_reachable),
                          &sb_address_sets);
            free(ipv6_addrs_name);
            free(ipv6_addrs);
        }
    }

    /* sync user defined address sets, which may overwrite port group
     * generated address sets if same name is used */
    const struct nbrec_address_set *nb_address_set;
    NBREC_ADDRESS_SET_TABLE_FOR_EACH (nb_address_set,
                                      nb_address_set_table) {
        sync_addr_set(ovnsb_txn, nb_address_set->name,
            /* "char **" is not compatible with "const char **" */
            (const char **) nb_address_set->addresses,
            nb_address_set->n_addresses, &sb_address_sets);
    }

    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &sb_address_sets) {
        sbrec_address_set_delete(node->data);
        shash_delete(&sb_address_sets, node);
    }
    shash_destroy(&sb_address_sets);
}
