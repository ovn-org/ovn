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
                               const struct ovn_datapaths *lr_datapaths);
static struct lr_nat_record *lr_nat_table_find_by_index_(
    const struct lr_nat_table *, size_t od_index);

static struct lr_nat_record *lr_nat_record_create(
    struct lr_nat_table *, const struct ovn_datapath *);
static void lr_nat_record_init(struct lr_nat_record *,
                               const struct ovn_datapath *);
static void lr_nat_record_clear(struct lr_nat_record *);
static void lr_nat_record_reinit(struct lr_nat_record *,
                                 const struct ovn_datapath *);
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

void
en_lr_nat_run(struct engine_node *node, void *data_)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    struct ed_type_lr_nat_data *data = data_;

    stopwatch_start(LR_NAT_RUN_STOPWATCH_NAME, time_msec());
    lr_nat_table_clear(&data->lr_nats);
    lr_nat_table_build(&data->lr_nats, &northd_data->lr_datapaths);

    stopwatch_stop(LR_NAT_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}

/* Handler functions. */
bool
lr_nat_northd_handler(struct engine_node *node, void *data_)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_has_tracked_data(&northd_data->trk_data)) {
        return false;
    }

    if (!northd_has_lr_nats_in_tracked_data(&northd_data->trk_data)) {
        return true;
    }

    struct ed_type_lr_nat_data *data = data_;
    struct lr_nat_record *lrnat_rec;
    const struct ovn_datapath *od;
    struct hmapx_node *hmapx_node;

    HMAPX_FOR_EACH (hmapx_node, &northd_data->trk_data.trk_nat_lrs) {
        od = hmapx_node->data;
        lrnat_rec = lr_nat_table_find_by_index_(&data->lr_nats, od->index);
        ovs_assert(lrnat_rec);
        lr_nat_record_reinit(lrnat_rec, od);

        /* Add the lrnet rec to the tracking data. */
        hmapx_add(&data->trk_data.crupdated, lrnat_rec);
    }

    if (lr_nat_has_tracked_data(&data->trk_data)) {
        engine_set_node_state(node, EN_UPDATED);
    }

    return true;
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
                   const struct ovn_datapaths *lr_datapaths)
{
    table->array = xrealloc(table->array,
                            ods_size(lr_datapaths) * sizeof *table->array);

    const struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &lr_datapaths->datapaths) {
        lr_nat_record_create(table, od);
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
                     const struct ovn_datapath *od)
{
    ovs_assert(od->nbr);

    struct lr_nat_record *lrnat_rec = xzalloc(sizeof *lrnat_rec);
    lr_nat_record_init(lrnat_rec, od);

    hmap_insert(&table->entries, &lrnat_rec->key_node,
                uuid_hash(&od->nbr->header_.uuid));
    table->array[od->index] = lrnat_rec;
    return lrnat_rec;
}

static void
lr_nat_record_init(struct lr_nat_record *lrnat_rec,
                   const struct ovn_datapath *od)
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

        if (!extract_ip_addresses(nat->external_ip,
                                  &nat_entry->ext_addrs) ||
                !nat_entry_is_valid(nat_entry)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

            VLOG_WARN_RL(&rl,
                         "Bad ip address %s in nat configuration "
                         "for router %s", nat->external_ip,
                         od->nbr->name);
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
            if (!strcmp(nat->type, "dnat_and_snat")
                    && nat->logical_port && nat->external_mac) {
                lrnat_rec->has_distributed_nat = true;
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
                     const struct ovn_datapath *od)
{
    lr_nat_record_clear(lrnat_rec);
    lr_nat_record_init(lrnat_rec, od);
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
