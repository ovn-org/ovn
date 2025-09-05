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
#include "lib/bitmap.h"
#include "lib/socket-util.h"
#include "lib/uuidset.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"
#include "stopwatch.h"

/* OVN includes */
#include "en-lb-data.h"
#include "en-ls-stateful.h"
#include "en-port-group.h"
#include "lib/inc-proc-eng.h"
#include "lib/lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"
#include "lflow-mgr.h"
#include "northd.h"

VLOG_DEFINE_THIS_MODULE(en_ls_stateful);

/* Static function declarations. */
static void ls_stateful_table_init(struct ls_stateful_table *);
static void ls_stateful_table_clear(struct ls_stateful_table *);
static void ls_stateful_table_destroy(struct ls_stateful_table *);
static struct ls_stateful_record *ls_stateful_table_find_(
    const struct ls_stateful_table *, const struct nbrec_logical_switch *);
static void ls_stateful_table_build(struct ls_stateful_table *,
                                    const struct ovn_datapaths *ls_datapaths,
                                    const struct ls_port_group_table *);

static struct ls_stateful_input ls_stateful_get_input_data(
    struct engine_node *);

static struct ls_stateful_record *ls_stateful_record_create(
    struct ls_stateful_table *,
    const struct ovn_datapath *,
    const struct ls_port_group_table *);
static void ls_stateful_record_destroy(struct ls_stateful_record *);
static void ls_stateful_record_init(
    struct ls_stateful_record *,
    const struct ovn_datapath *,
    const struct ls_port_group_table *);
static bool ls_has_lb_vip(const struct ovn_datapath *);
static void ls_stateful_record_set_acls(
    struct ls_stateful_record *, const struct nbrec_logical_switch *,
    const struct ls_port_group_table *);
static void ls_stateful_record_set_acls_(struct ls_stateful_record *,
                                         struct nbrec_acl **, size_t n_acls);
static struct ls_stateful_input ls_stateful_get_input_data(
    struct engine_node *);

struct ls_stateful_input {
    const struct ls_port_group_table *ls_port_groups;
    const struct ovn_datapaths *ls_datapaths;
};

/* public functions. */
void *
en_ls_stateful_init(struct engine_node *node OVS_UNUSED,
                    struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_ls_stateful *data = xzalloc(sizeof *data);
    ls_stateful_table_init(&data->table);
    hmapx_init(&data->trk_data.crupdated);
    hmapx_init(&data->trk_data.deleted);
    return data;
}

void
en_ls_stateful_cleanup(void *data_)
{
    struct ed_type_ls_stateful *data = data_;
    ls_stateful_table_destroy(&data->table);
    hmapx_destroy(&data->trk_data.crupdated);

    struct hmapx_node *n;
    HMAPX_FOR_EACH_SAFE (n, &data->trk_data.deleted) {
        ls_stateful_record_destroy(n->data);
        hmapx_delete(&data->trk_data.deleted, n);
    }
    hmapx_destroy(&data->trk_data.deleted);
}

void
en_ls_stateful_clear_tracked_data(void *data_)
{
    struct ed_type_ls_stateful *data = data_;
    hmapx_clear(&data->trk_data.crupdated);

    struct hmapx_node *n;
    HMAPX_FOR_EACH_SAFE (n, &data->trk_data.deleted) {
        ls_stateful_record_destroy(n->data);
        hmapx_delete(&data->trk_data.deleted, n);
    }
    hmapx_clear(&data->trk_data.deleted);
}

enum engine_node_state
en_ls_stateful_run(struct engine_node *node, void *data_)
{
    struct ls_stateful_input input_data = ls_stateful_get_input_data(node);
    struct ed_type_ls_stateful *data = data_;

    stopwatch_start(LS_STATEFUL_RUN_STOPWATCH_NAME, time_msec());

    ls_stateful_table_clear(&data->table);
    ls_stateful_table_build(&data->table, input_data.ls_datapaths,
                          input_data.ls_port_groups);

    stopwatch_stop(LS_STATEFUL_RUN_STOPWATCH_NAME, time_msec());
    return EN_UPDATED;
}

/* Handler functions. */
enum engine_input_handler_result
ls_stateful_northd_handler(struct engine_node *node, void *data_)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_has_tracked_data(&northd_data->trk_data)) {
        return EN_UNHANDLED;
    }

    if (!northd_has_ls_lbs_in_tracked_data(&northd_data->trk_data) &&
        !northd_has_ls_acls_in_tracked_data(&northd_data->trk_data) &&
        !northd_has_lswitches_in_tracked_data(&northd_data->trk_data)) {
        return EN_HANDLED_UNCHANGED;
    }

    struct northd_tracked_data *nd_changes = &northd_data->trk_data;
    struct ls_stateful_input input_data = ls_stateful_get_input_data(node);
    struct ed_type_ls_stateful *data = data_;
    struct hmapx_node *hmapx_node;

    HMAPX_FOR_EACH (hmapx_node, &nd_changes->trk_switches.crupdated) {
        const struct ovn_datapath *od = hmapx_node->data;

        if (!ls_stateful_table_find_(&data->table, od->nbs)) {
            ls_stateful_record_create(&data->table, od,
                                      input_data.ls_port_groups);
        }
    }

    HMAPX_FOR_EACH (hmapx_node, &nd_changes->ls_with_changed_lbs) {
        const struct ovn_datapath *od = hmapx_node->data;

        struct ls_stateful_record *ls_stateful_rec =
            ls_stateful_table_find_(&data->table, od->nbs);
        ovs_assert(ls_stateful_rec);
        ls_stateful_rec->has_lb_vip = ls_has_lb_vip(od);

        /* Add the ls_stateful_rec to the tracking data. */
        hmapx_add(&data->trk_data.crupdated, ls_stateful_rec);
    }

    HMAPX_FOR_EACH (hmapx_node, &nd_changes->ls_with_changed_acls) {
        const struct ovn_datapath *od = hmapx_node->data;

        struct ls_stateful_record *ls_stateful_rec =
            ls_stateful_table_find_(&data->table, od->nbs);
        ovs_assert(ls_stateful_rec);
        /* Ensure that only one handler per engine run calls
         * ls_stateful_record_set_acls on the same ls_stateful_rec by
         * calling it only when the ls_stateful_rec is added to the hmapx. */
        if (hmapx_add(&data->trk_data.crupdated, ls_stateful_rec)) {
            ls_stateful_record_set_acls(ls_stateful_rec, od->nbs,
                                         input_data.ls_port_groups);
        }
    }

    HMAPX_FOR_EACH (hmapx_node, &nd_changes->trk_switches.deleted) {
        const struct ovn_datapath *od = hmapx_node->data;
        struct ls_stateful_record *ls_stateful_rec =
            ls_stateful_table_find_(&data->table, od->nbs);

        if (ls_stateful_rec &&
            !ovn_datapath_find(&northd_data->ls_datapaths.datapaths,
                               &od->nbs->header_.uuid)) {
            hmap_remove(&data->table.entries, &ls_stateful_rec->key_node);
            /* Add the ls_stateful_rec to the tracking data. */
            hmapx_add(&data->trk_data.deleted, ls_stateful_rec);
        }
    }

    if (ls_stateful_has_tracked_data(&data->trk_data)) {
        return EN_HANDLED_UPDATED;
    }

    return EN_HANDLED_UNCHANGED;
}

enum engine_input_handler_result
ls_stateful_port_group_handler(struct engine_node *node, void *data_)
{
    struct port_group_data *pg_data =
        engine_get_input_data("port_group", node);

    struct ed_type_ls_stateful *data = data_;
    struct hmapx_node *hmap_node;
    HMAPX_FOR_EACH (hmap_node, &pg_data->ls_port_groups_sets_changed) {
        const struct nbrec_logical_switch *nbs = hmap_node->data;
        struct ls_stateful_record *ls_stateful_rec =
            ls_stateful_table_find_(&data->table, nbs);
        /* Ensure that only one handler per engine run calls
         * ls_stateful_record_set_acls on the same ls_stateful_rec by
         * calling it only when the ls_stateful_rec is added to the hmapx.*/
        if (ls_stateful_rec && hmapx_add(&data->trk_data.crupdated,
                                         ls_stateful_rec)) {
            ls_stateful_record_set_acls(ls_stateful_rec,
                                        nbs,
                                        &pg_data->ls_port_groups);
        }
    }

    if (ls_stateful_has_tracked_data(&data->trk_data)) {
        return EN_HANDLED_UPDATED;
    }
    return EN_HANDLED_UNCHANGED;
}

enum engine_input_handler_result
ls_stateful_acl_handler(struct engine_node *node, void *data_)
{
    struct ed_type_ls_stateful *data = data_;
    const struct nbrec_acl_table *nbrec_acl_table =
        EN_OVSDB_GET(engine_get_input("NB_acl", node));

    const struct nbrec_acl *acl;
    NBREC_ACL_TABLE_FOR_EACH_TRACKED (acl, nbrec_acl_table) {
        /* The creation and deletion is handled in relation to LS/PG rather
         * than the ACL itself. */
        if (nbrec_acl_is_new(acl) || nbrec_acl_is_deleted(acl)) {
            continue;
        }

        struct ls_stateful_record *ls_stateful_rec;
        LS_STATEFUL_TABLE_FOR_EACH (ls_stateful_rec, &data->table) {
            if (uuidset_contains(&ls_stateful_rec->related_acls,
                                 &acl->header_.uuid)) {
                hmapx_add(&data->trk_data.crupdated, ls_stateful_rec);
            }
        }
    }

    if (ls_stateful_has_tracked_data(&data->trk_data)) {
        return EN_HANDLED_UPDATED;
    }
    return EN_HANDLED_UNCHANGED;
}

/* static functions. */
static void
ls_stateful_table_init(struct ls_stateful_table *table)
{
    *table = (struct ls_stateful_table) {
        .entries = HMAP_INITIALIZER(&table->entries),
    };
}

static void
ls_stateful_table_destroy(struct ls_stateful_table *table)
{
    ls_stateful_table_clear(table);
    hmap_destroy(&table->entries);
}

static void
ls_stateful_table_clear(struct ls_stateful_table *table)
{
    struct ls_stateful_record *ls_stateful_rec;
    HMAP_FOR_EACH_POP (ls_stateful_rec, key_node, &table->entries) {
        ls_stateful_record_destroy(ls_stateful_rec);
    }
}

static void
ls_stateful_table_build(struct ls_stateful_table *table,
                        const struct ovn_datapaths *ls_datapaths,
                        const struct ls_port_group_table *ls_pgs)
{
    const struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &ls_datapaths->datapaths) {
        ls_stateful_record_create(table, od, ls_pgs);
    }
}

static struct ls_stateful_record *
ls_stateful_table_find_(const struct ls_stateful_table *table,
                        const struct nbrec_logical_switch *nbs)
{
    struct ls_stateful_record *ls_stateful_rec;

    HMAP_FOR_EACH_WITH_HASH (ls_stateful_rec, key_node,
                             uuid_hash(&nbs->header_.uuid), &table->entries) {
        if (uuid_equals(&ls_stateful_rec->nbs_uuid, &nbs->header_.uuid)) {
            return ls_stateful_rec;
        }
    }
    return NULL;
}

static struct ls_stateful_record *
ls_stateful_record_create(struct ls_stateful_table *table,
                          const struct ovn_datapath *od,
                          const struct ls_port_group_table *ls_pgs)
{
    struct ls_stateful_record *ls_stateful_rec =
        xzalloc(sizeof *ls_stateful_rec);
    ls_stateful_rec->ls_index = od->index;
    ls_stateful_rec->nbs_uuid = od->nbs->header_.uuid;
    uuidset_init(&ls_stateful_rec->related_acls);
    ls_stateful_record_init(ls_stateful_rec, od, ls_pgs);
    ls_stateful_rec->lflow_ref = lflow_ref_create();

    hmap_insert(&table->entries, &ls_stateful_rec->key_node,
                uuid_hash(&od->nbs->header_.uuid));

    return ls_stateful_rec;
}

static void
ls_stateful_record_destroy(struct ls_stateful_record *ls_stateful_rec)
{
    uuidset_destroy(&ls_stateful_rec->related_acls);
    lflow_ref_destroy(ls_stateful_rec->lflow_ref);
    free(ls_stateful_rec);
}

static void
ls_stateful_record_init(struct ls_stateful_record *ls_stateful_rec,
                      const struct ovn_datapath *od,
                      const struct ls_port_group_table *ls_pgs)
{
    ls_stateful_rec->has_lb_vip = ls_has_lb_vip(od);
    ls_stateful_record_set_acls(ls_stateful_rec, od->nbs, ls_pgs);
}

static bool
lb_has_vip(const struct nbrec_load_balancer *lb)
{
    return !smap_is_empty(&lb->vips);
}

static bool
lb_group_has_vip(const struct nbrec_load_balancer_group *lb_group)
{
    for (size_t i = 0; i < lb_group->n_load_balancer; i++) {
        if (lb_has_vip(lb_group->load_balancer[i])) {
            return true;
        }
    }
    return false;
}

static bool
ls_has_lb_vip(const struct ovn_datapath *od)
{
    for (size_t i = 0; i < od->nbs->n_load_balancer; i++) {
        if (lb_has_vip(od->nbs->load_balancer[i])) {
            return true;
        }
    }

    for (size_t i = 0; i < od->nbs->n_load_balancer_group; i++) {
        if (lb_group_has_vip(od->nbs->load_balancer_group[i])) {
            return true;
        }
    }
    return false;
}

static void
ls_stateful_record_set_acls(struct ls_stateful_record *ls_stateful_rec,
                            const struct nbrec_logical_switch *nbs,
                            const struct ls_port_group_table *ls_pgs)
{
    ls_stateful_rec->has_stateful_acl = false;
    memset(&ls_stateful_rec->max_acl_tier, 0,
           sizeof ls_stateful_rec->max_acl_tier);
    ls_stateful_rec->has_acls = false;
    uuidset_clear(&ls_stateful_rec->related_acls);

    ls_stateful_record_set_acls_(ls_stateful_rec, nbs->acls,
                                 nbs->n_acls);

    struct ls_port_group *ls_pg = ls_port_group_table_find(ls_pgs, nbs);
    if (!ls_pg) {
        return;
    }

    const struct ls_port_group_record *ls_pg_rec;
    HMAP_FOR_EACH (ls_pg_rec, key_node, &ls_pg->nb_pgs) {
        ls_stateful_record_set_acls_(ls_stateful_rec, ls_pg_rec->nb_pg->acls,
                                     ls_pg_rec->nb_pg->n_acls);
    }
}

static void
update_ls_max_acl_tier(struct ls_stateful_record *ls_stateful_rec,
                       const struct nbrec_acl *acl)
{
    if (!acl->tier) {
        return;
    }

    uint64_t *tier;

    if (!strcmp(acl->direction, "from-lport")) {
        if (smap_get_bool(&acl->options, "apply-after-lb", false)) {
            tier = &ls_stateful_rec->max_acl_tier.ingress_post_lb;
        } else {
            tier = &ls_stateful_rec->max_acl_tier.ingress_pre_lb;
        }
    } else {
        tier = &ls_stateful_rec->max_acl_tier.egress;
    }

    *tier = MAX(*tier, acl->tier);
}

static void
ls_stateful_record_set_acls_(struct ls_stateful_record *ls_stateful_rec,
                             struct nbrec_acl **acls, size_t n_acls)
{
    if (!n_acls) {
        return;
    }

    ls_stateful_rec->has_acls = true;
    for (size_t i = 0; i < n_acls; i++) {
        const struct nbrec_acl *acl = acls[i];
        update_ls_max_acl_tier(ls_stateful_rec, acl);
        uuidset_insert(&ls_stateful_rec->related_acls, &acl->header_.uuid);
        if (!ls_stateful_rec->has_stateful_acl
                && !strcmp(acl->action, "allow-related")) {
            ls_stateful_rec->has_stateful_acl = true;
        }
    }
}

static struct ls_stateful_input
ls_stateful_get_input_data(struct engine_node *node)
{
    const struct northd_data *northd_data =
        engine_get_input_data("northd", node);
    const struct port_group_data *pg_data =
        engine_get_input_data("port_group", node);

    return (struct ls_stateful_input) {
        .ls_port_groups = &pg_data->ls_port_groups,
        .ls_datapaths = &northd_data->ls_datapaths,
    };
}
