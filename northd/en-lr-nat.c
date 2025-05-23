/*
 * Copyright (c) 2024, Red Hat, Inc.
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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

/* OVS includes */
#include "include/openvswitch/hmap.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"
#include "stopwatch.h"

/* OVN includes */
#include "en-lr-nat.h"
#include "lib/inc-proc-eng.h"
#include "lib/lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"
#include "northd.h"

VLOG_DEFINE_THIS_MODULE(en_lr_nat);

/* Static function declarations. */
static void lr_nat_table_init(struct lr_nat_table *);
static void lr_nat_table_clear(struct lr_nat_table *);
static void lr_nat_table_destroy(struct lr_nat_table *);
static void lr_nat_table_build(struct lr_nat_table *,
                               const struct ovn_datapaths *lr_datapaths,
                               const struct hmap *lr_ports);
static struct lr_nat_record *lr_nat_table_find_by_index_(
    const struct lr_nat_table *, size_t od_index);

static struct lr_nat_record *lr_nat_record_create(struct lr_nat_table *,
                                                  const struct ovn_datapath *,
                                                  const struct hmap *lr_ports);
static void lr_nat_record_init(struct lr_nat_record *,
                               const struct ovn_datapath *,
                               const struct hmap *lr_ports);
static void lr_nat_record_clear(struct lr_nat_record *);
static void lr_nat_record_reinit(struct lr_nat_record *,
                                 const struct ovn_datapath *,
                                 const struct hmap *lr_ports);
static void lr_nat_record_destroy(struct lr_nat_record *);

static bool get_force_snat_ip(const struct ovn_datapath *,
                              const char *key_type,
                              struct lport_addresses *);

static void snat_ip_add(struct lr_nat_record *, const char *ip,
                        struct ovn_nat *);

const struct lr_nat_record *
lr_nat_table_find_by_index(const struct lr_nat_table *table,
                           size_t od_index)
{
    return lr_nat_table_find_by_index_(table, od_index);
}

/* 'lr_nat' engine node manages the NB logical router NAT data.
 */
void *
en_lr_nat_init(struct engine_node *node OVS_UNUSED,
               struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_lr_nat_data *data = xzalloc(sizeof *data);
    lr_nat_table_init(&data->lr_nats);
    hmapx_init(&data->trk_data.crupdated);
    return data;
}

void
en_lr_nat_cleanup(void *data_)
{
    struct ed_type_lr_nat_data *data = (struct ed_type_lr_nat_data *) data_;
    lr_nat_table_destroy(&data->lr_nats);
    hmapx_destroy(&data->trk_data.crupdated);
}

void
en_lr_nat_clear_tracked_data(void *data_)
{
    struct ed_type_lr_nat_data *data = (struct ed_type_lr_nat_data *) data_;
    hmapx_clear(&data->trk_data.crupdated);
}

enum engine_node_state
en_lr_nat_run(struct engine_node *node, void *data_)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    struct ed_type_lr_nat_data *data = data_;

    stopwatch_start(LR_NAT_RUN_STOPWATCH_NAME, time_msec());
    lr_nat_table_clear(&data->lr_nats);
    lr_nat_table_build(&data->lr_nats, &northd_data->lr_datapaths,
                       &northd_data->lr_ports);

    stopwatch_stop(LR_NAT_RUN_STOPWATCH_NAME, time_msec());
    return EN_UPDATED;
}

/* Handler functions. */
enum engine_input_handler_result
lr_nat_northd_handler(struct engine_node *node, void *data_)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_has_tracked_data(&northd_data->trk_data)) {
        return EN_UNHANDLED;
    }

    if (!northd_has_lr_nats_in_tracked_data(&northd_data->trk_data)) {
        return EN_HANDLED_UNCHANGED;
    }

    struct ed_type_lr_nat_data *data = data_;
    struct lr_nat_record *lrnat_rec;
    const struct ovn_datapath *od;
    struct hmapx_node *hmapx_node;

    HMAPX_FOR_EACH (hmapx_node, &northd_data->trk_data.trk_nat_lrs) {
        od = hmapx_node->data;
        lrnat_rec = lr_nat_table_find_by_index_(&data->lr_nats, od->index);
        ovs_assert(lrnat_rec);
        lr_nat_record_reinit(lrnat_rec, od, &northd_data->lr_ports);

        /* Add the lrnet rec to the tracking data. */
        hmapx_add(&data->trk_data.crupdated, lrnat_rec);
    }

    if (lr_nat_has_tracked_data(&data->trk_data)) {
        return EN_HANDLED_UPDATED;
    }

    return EN_HANDLED_UNCHANGED;
}

/* static functions. */
static void
lr_nat_table_init(struct lr_nat_table *table)
{
    *table = (struct lr_nat_table) {
        .entries = HMAP_INITIALIZER(&table->entries),
    };
}

static void
lr_nat_table_clear(struct lr_nat_table *table)
{
    struct lr_nat_record *lrnat_rec;
    HMAP_FOR_EACH_POP (lrnat_rec, key_node, &table->entries) {
        lr_nat_record_destroy(lrnat_rec);
    }

    free(table->array);
    table->array = NULL;
}

static void
lr_nat_table_build(struct lr_nat_table *table,
                   const struct ovn_datapaths *lr_datapaths,
                   const struct hmap *lr_ports)
{
    table->array = xrealloc(table->array,
                            ods_size(lr_datapaths) * sizeof *table->array);

    const struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &lr_datapaths->datapaths) {
        lr_nat_record_create(table, od, lr_ports);
    }
}

static void
lr_nat_table_destroy(struct lr_nat_table *table)
{
    lr_nat_table_clear(table);
    hmap_destroy(&table->entries);
}

struct lr_nat_record *
lr_nat_table_find_by_index_(const struct lr_nat_table *table,
                            size_t od_index)
{
    ovs_assert(od_index <= hmap_count(&table->entries));

    return table->array[od_index];
}

static struct lr_nat_record *
lr_nat_record_create(struct lr_nat_table *table,
                     const struct ovn_datapath *od,
                     const struct hmap *lr_ports)
{
    ovs_assert(od->nbr);

    struct lr_nat_record *lrnat_rec = xzalloc(sizeof *lrnat_rec);
    lr_nat_record_init(lrnat_rec, od, lr_ports);

    hmap_insert(&table->entries, &lrnat_rec->key_node,
                uuid_hash(&od->nbr->header_.uuid));
    table->array[od->index] = lrnat_rec;
    return lrnat_rec;
}

/* Returns true if a 'nat_entry' is valid, i.e.:
 * - parsing was successful.
 * - the string yielded exactly one IPv4 address or exactly one IPv6 address.
 */
static bool
lr_nat_entry_ext_addrs_valid(const struct ovn_nat *nat_entry)
{
    const struct lport_addresses *ext_addrs = &nat_entry->ext_addrs;

    return (ext_addrs->n_ipv4_addrs == 1 && ext_addrs->n_ipv6_addrs == 0) ||
        (ext_addrs->n_ipv4_addrs == 0 && ext_addrs->n_ipv6_addrs == 1);
}

/* Populates 'nat_entry->logical_ip_cidr_bits'.  SNAT rules can have
 * subnets as logical IPs.  Their prefix length is used to generate
 * NAT priority (LPM). */
static bool
lr_nat_entry_set_logical_ip_cidr_bits(const struct ovn_datapath *od,
                                      struct ovn_nat *nat_entry)
{
    struct in6_addr ipv6, mask_v6, v6_exact = IN6ADDR_EXACT_INIT;
    const struct nbrec_nat *nat = nat_entry->nb;
    bool is_v6 = nat_entry_is_v6(nat_entry);
    ovs_be32 ip, mask;
    char *error = NULL;
    if (is_v6) {
        error = ipv6_parse_masked(nat->logical_ip, &ipv6, &mask_v6);
        nat_entry->logical_ip_cidr_bits = ipv6_count_cidr_bits(&mask_v6);
    } else {
        error = ip_parse_masked(nat->logical_ip, &ip, &mask);
        nat_entry->logical_ip_cidr_bits = ip_count_cidr_bits(mask);
    }
    if (nat_entry->type == SNAT) {
        if (error) {
            /* Invalid for both IPv4 and IPv6 */
            static struct vlog_rate_limit rl =
                VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad ip network or ip %s for snat "
                              "in router " UUID_FMT,
                        nat->logical_ip, UUID_ARGS(&od->key));
            free(error);
            return false;
        }
    } else {
        if (error || (!is_v6 && mask != OVS_BE32_MAX)
            || (is_v6 && memcmp(&mask_v6, &v6_exact, sizeof mask_v6))) {
            /* Invalid for both IPv4 and IPv6 */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad ip %s for dnat in router "
                              UUID_FMT,
                         nat->logical_ip, UUID_ARGS(&od->key));
            free(error);
            return false;
        }
    }
    return true;
}

/* Populates 'nat_entry->l3dgw_port' with the corresponding DGW port
 * (distributed gateway port) for the NAT entry, if any.  Sets
 * 'nat_entry->is_distributed' to true if the NAT entry is fully
 * distributed, that is, dnat_and_snat with valid DGW port and mac set.
 * It sets 'nat_entry->is_distributed' to false otherwise.
 *
 * Returns false on failure to find an adequate DGW port.
 * Returns true otherwise.
 *  */
static bool
lr_nat_entry_set_dgw_port(const struct ovn_datapath *od,
                          struct ovn_nat *nat_entry,
                          const struct hmap *lr_ports)
{
    const struct nbrec_nat *nat = nat_entry->nb;

    /* Validate gateway_port of NAT rule. */
    nat_entry->l3dgw_port = NULL;
    if (nat->gateway_port == NULL) {
        if (vector_len(&od->l3dgw_ports) == 1) {
            nat_entry->l3dgw_port = vector_get(&od->l3dgw_ports, 0,
                                               struct ovn_port *);
        } else if (vector_len(&od->l3dgw_ports) > 1) {
            /* Find the DGP reachable for the NAT external IP. */
            struct ovn_port *dgp;
            VECTOR_FOR_EACH (&od->l3dgw_ports, dgp) {
               if (lrp_find_member_ip(dgp, nat->external_ip)) {
                   nat_entry->l3dgw_port = dgp;
                   break;
               }
            }
            if (nat_entry->l3dgw_port == NULL) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "Unable to determine gateway_port for NAT "
                             "with external_ip: %s configured on logical "
                             "router: %s with multiple distributed gateway "
                             "ports", nat->external_ip, od->nbr->name);
                return false;
            }
        }
    } else {
        nat_entry->l3dgw_port =
            ovn_port_find(lr_ports, nat->gateway_port->name);

        if (!nat_entry->l3dgw_port || nat_entry->l3dgw_port->od != od ||
            !lrp_is_l3dgw(nat_entry->l3dgw_port)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "gateway_port: %s of NAT configured on "
                         "logical router: %s is not a valid distributed "
                         "gateway port on that router",
                         nat->gateway_port->name, od->nbr->name);
            return false;
        }
    }

    /* For distributed router NAT, determine whether this NAT rule
     * satisfies the conditions for distributed NAT processing. */
    nat_entry->is_distributed = false;

    /* NAT cannnot be distributed if the DGP's peer
     * has a chassisredirect port (as the routing is centralized
     * on the gateway chassis for the DGP's networks/subnets.)
     */
    struct ovn_port *l3dgw_port = nat_entry->l3dgw_port;
    if (l3dgw_port && l3dgw_port->peer && l3dgw_port->peer->cr_port) {
        return true;
    }

    if (!vector_is_empty(&od->l3dgw_ports) &&
        nat_entry->type == DNAT_AND_SNAT &&
        nat->logical_port && nat->external_mac) {
            nat_entry->is_distributed = true;
    }

    return true;
}

static void
lr_nat_record_init(struct lr_nat_record *lrnat_rec,
                   const struct ovn_datapath *od,
                   const struct hmap *lr_ports)
{
    lrnat_rec->lr_index = od->index;
    lrnat_rec->nbr_uuid = od->nbr->header_.uuid;

    shash_init(&lrnat_rec->snat_ips);
    sset_init(&lrnat_rec->external_ips);
    for (size_t i = 0; i < od->nbr->n_nat; i++) {
        sset_add(&lrnat_rec->external_ips, od->nbr->nat[i]->external_ip);
    }

    sset_init(&lrnat_rec->external_macs);
    lrnat_rec->has_distributed_nat = false;

    if (get_force_snat_ip(od, "dnat",
                          &lrnat_rec->dnat_force_snat_addrs)) {
        if (lrnat_rec->dnat_force_snat_addrs.n_ipv4_addrs) {
            snat_ip_add(lrnat_rec,
                        lrnat_rec->dnat_force_snat_addrs.ipv4_addrs[0].addr_s,
                        NULL);
        }
        if (lrnat_rec->dnat_force_snat_addrs.n_ipv6_addrs) {
            snat_ip_add(lrnat_rec,
                        lrnat_rec->dnat_force_snat_addrs.ipv6_addrs[0].addr_s,
                        NULL);
        }
    } else {
        init_lport_addresses(&lrnat_rec->dnat_force_snat_addrs);
    }

    /* Check if 'lb_force_snat_ip' is configured with 'router_ip'. */
    const char *lb_force_snat =
        smap_get(&od->nbr->options, "lb_force_snat_ip");
    if (lb_force_snat && !strcmp(lb_force_snat, "router_ip")
            && smap_get(&od->nbr->options, "chassis")) {

        /* Set it to true only if its gateway router and
         * options:lb_force_snat_ip=router_ip. */
        lrnat_rec->lb_force_snat_router_ip = true;
    } else {
        lrnat_rec->lb_force_snat_router_ip = false;

        /* Check if 'lb_force_snat_ip' is configured with a set of
         * IP address(es). */
        if (get_force_snat_ip(od, "lb",
                              &lrnat_rec->lb_force_snat_addrs)) {
            if (lrnat_rec->lb_force_snat_addrs.n_ipv4_addrs) {
                snat_ip_add(lrnat_rec,
                        lrnat_rec->lb_force_snat_addrs.ipv4_addrs[0].addr_s,
                        NULL);
            }
            if (lrnat_rec->lb_force_snat_addrs.n_ipv6_addrs) {
                snat_ip_add(lrnat_rec,
                        lrnat_rec->lb_force_snat_addrs.ipv6_addrs[0].addr_s,
                        NULL);
            }
        } else {
            init_lport_addresses(&lrnat_rec->lb_force_snat_addrs);
        }
    }

    if (!od->nbr->n_nat) {
        lrnat_rec->nat_entries = NULL;
        lrnat_rec->n_nat_entries = 0;
        return;
    }

    lrnat_rec->nat_entries =
        xmalloc(od->nbr->n_nat * sizeof *lrnat_rec->nat_entries);

    for (size_t i = 0; i < od->nbr->n_nat; i++) {
        const struct nbrec_nat *nat = od->nbr->nat[i];
        struct ovn_nat *nat_entry = &lrnat_rec->nat_entries[i];

        nat_entry->nb = nat;
        nat_entry->is_router_ip = false;
        nat_entry->is_valid = true;

        if (!strcmp(nat->type, "snat")) {
            nat_entry->type = SNAT;
        } else if (!strcmp(nat->type, "dnat_and_snat")) {
            nat_entry->type = DNAT_AND_SNAT;
        } else {
            nat_entry->type = DNAT;
        }

        if (!extract_ip_addresses(nat->external_ip, &nat_entry->ext_addrs)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

            VLOG_WARN_RL(&rl, "Failed to extract ip address %s "
                              "in nat configuration for router %s",
                         nat->external_ip, od->nbr->name);
            nat_entry->is_valid = false;
            continue;
        }

        if (nat->external_mac && !eth_addr_from_string(nat->external_mac,
                                                       &nat_entry->mac)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad mac %s for dnat in router "
                         ""UUID_FMT"", nat->external_mac, UUID_ARGS(&od->key));
            nat_entry->is_valid = false;
            continue;
        }

        if (!lr_nat_entry_ext_addrs_valid(nat_entry)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

            VLOG_WARN_RL(&rl, "Invalid ip address %s in nat configuration "
                              "for router %s",
                         nat->external_ip, od->nbr->name);
            nat_entry->is_valid = false;
            continue;
        }

        if (nat->allowed_ext_ips && nat->exempted_ext_ips) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "NAT rule: " UUID_FMT " not applied, since "
                              "both allowed and exempt external ips set",
                        UUID_ARGS(&(nat->header_.uuid)));
            nat_entry->is_valid = false;
            continue;
        }

        /* Set nat_entry->logical_ip_cidr_bits (SNAT logical_ip can be
         * a subnet). */
        if (!lr_nat_entry_set_logical_ip_cidr_bits(od, nat_entry)) {
            nat_entry->is_valid = false;
            continue;
        }

        /* Set nat_entry->l3dgw_port and nat_entry->is_distributed. */
        if (!lr_nat_entry_set_dgw_port(od, nat_entry, lr_ports)) {
            nat_entry->is_valid = false;
            continue;
        }

        /* If this is a SNAT rule add the IP to the set of unique SNAT IPs. */
        if (!strcmp(nat->type, "snat")) {
            if (sset_contains(&od->router_ips, nat->external_ip)) {
                nat_entry->is_router_ip = true;
            }

            if (!nat_entry_is_v6(nat_entry)) {
                snat_ip_add(lrnat_rec,
                            nat_entry->ext_addrs.ipv4_addrs[0].addr_s,
                            nat_entry);
            } else {
                snat_ip_add(lrnat_rec,
                            nat_entry->ext_addrs.ipv6_addrs[0].addr_s,
                            nat_entry);
            }
        } else {
            if (!strcmp(nat->type, "dnat_and_snat")) {
                if (nat->logical_port && nat->external_mac) {
                    lrnat_rec->has_distributed_nat = true;
                }
            }

            if (nat->external_mac) {
                sset_add(&lrnat_rec->external_macs, nat->external_mac);
            }
        }
    }
    lrnat_rec->n_nat_entries = od->nbr->n_nat;
}

static void
lr_nat_record_clear(struct lr_nat_record *lrnat_rec)
{
    shash_destroy_free_data(&lrnat_rec->snat_ips);
    destroy_lport_addresses(&lrnat_rec->dnat_force_snat_addrs);
    destroy_lport_addresses(&lrnat_rec->lb_force_snat_addrs);

    for (size_t i = 0; i < lrnat_rec->n_nat_entries; i++) {
        destroy_lport_addresses(&lrnat_rec->nat_entries[i].ext_addrs);
    }

    free(lrnat_rec->nat_entries);
    sset_destroy(&lrnat_rec->external_ips);
    sset_destroy(&lrnat_rec->external_macs);
}

static void
lr_nat_record_reinit(struct lr_nat_record *lrnat_rec,
                     const struct ovn_datapath *od,
                     const struct hmap *lr_ports)
{
    lr_nat_record_clear(lrnat_rec);
    lr_nat_record_init(lrnat_rec, od, lr_ports);
}

static void
lr_nat_record_destroy(struct lr_nat_record *lrnat_rec)
{
    lr_nat_record_clear(lrnat_rec);
    free(lrnat_rec);
}

static void
snat_ip_add(struct lr_nat_record *lrnat_rec, const char *ip,
            struct ovn_nat *nat_entry)
{
    struct ovn_snat_ip *snat_ip = shash_find_data(&lrnat_rec->snat_ips, ip);

    if (!snat_ip) {
        snat_ip = xzalloc(sizeof *snat_ip);
        ovs_list_init(&snat_ip->snat_entries);
        shash_add(&lrnat_rec->snat_ips, ip, snat_ip);
    }

    if (nat_entry) {
        ovs_list_push_back(&snat_ip->snat_entries,
                           &nat_entry->ext_addr_list_node);
    }
}

static bool
get_force_snat_ip(const struct ovn_datapath *od, const char *key_type,
                  struct lport_addresses *laddrs)
{
    char *key = xasprintf("%s_force_snat_ip", key_type);
    const char *addresses = smap_get(&od->nbr->options, key);
    free(key);

    if (!addresses) {
        return false;
    }

    if (!extract_ip_address(addresses, laddrs)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad ip %s in options of router "UUID_FMT"",
                     addresses, UUID_ARGS(&od->nbr->header_.uuid));
        return false;
    }

    return true;
}
