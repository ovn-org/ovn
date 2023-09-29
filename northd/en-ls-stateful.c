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
    const struct ls_port_group *,
    const struct ls_port_group_table *);
static void ls_stateful_record_reinit(
    struct ls_stateful_record *,
    const struct ovn_datapath *,
    const struct ls_port_group *,
    const struct ls_port_group_table *);
static bool ls_has_lb_vip(const struct ovn_datapath *);
static void ls_stateful_record_set_acl_flags(
    struct ls_stateful_record *, const struct ovn_datapath *,
    const struct ls_port_group *, const struct ls_port_group_table *);
static bool ls_stateful_record_set_acl_flags_(struct ls_stateful_record *,
                                              struct nbrec_acl **,
                                              size_t n_acls);
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
    return data;
}

void
en_ls_stateful_cleanup(void *data_)
{
    struct ed_type_ls_stateful *data = data_;
    ls_stateful_table_destroy(&data->table);
    hmapx_destroy(&data->trk_data.crupdated);
}

void
en_ls_stateful_clear_tracked_data(void *data_)
{
    struct ed_type_ls_stateful *data = data_;
    hmapx_clear(&data->trk_data.crupdated);
}

void
en_ls_stateful_run(struct engine_node *node, void *data_)
{
    struct ls_stateful_input input_data = ls_stateful_get_input_data(node);
    struct ed_type_ls_stateful *data = data_;

    stopwatch_start(LS_STATEFUL_RUN_STOPWATCH_NAME, time_msec());

    ls_stateful_table_clear(&data->table);
    ls_stateful_table_build(&data->table, input_data.ls_datapaths,
                          input_data.ls_port_groups);

    stopwatch_stop(LS_STATEFUL_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}

/* Handler functions. */
bool
ls_stateful_northd_handler(struct engine_node *node, void *data_)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_has_tracked_data(&northd_data->trk_data)) {
        return false;
    }

    if (!northd_has_ls_lbs_in_tracked_data(&northd_data->trk_data) &&
        !northd_has_ls_acls_in_tracked_data(&northd_data->trk_data)) {
        return true;
    }

    struct northd_tracked_data *nd_changes = &northd_data->trk_data;
    struct ls_stateful_input input_data = ls_stateful_get_input_data(node);
    struct ed_type_ls_stateful *data = data_;
    struct hmapx_node *hmapx_node;

    struct hmapx changed_stateful_od = HMAPX_INITIALIZER(&changed_stateful_od);
    HMAPX_FOR_EACH (hmapx_node, &nd_changes->ls_with_changed_lbs) {
        hmapx_add(&changed_stateful_od, hmapx_node->data);
    }

    HMAPX_FOR_EACH (hmapx_node, &nd_changes->ls_with_changed_acls) {
        hmapx_add(&changed_stateful_od, hmapx_node->data);
    }

    HMAPX_FOR_EACH (hmapx_node, &changed_stateful_od) {
        const struct ovn_datapath *od = hmapx_node->data;

        struct ls_stateful_record *ls_stateful_rec = ls_stateful_table_find_(
            &data->table, od->nbs);
        ovs_assert(ls_stateful_rec);
        ls_stateful_record_reinit(ls_stateful_rec, od, NULL,
                                  input_data.ls_port_groups);

        /* Add the ls_stateful_rec to the tracking data. */
        hmapx_add(&data->trk_data.crupdated, ls_stateful_rec);
    }

    if (ls_stateful_has_tracked_data(&data->trk_data)) {
        engine_set_node_state(node, EN_UPDATED);
    }

    hmapx_destroy(&changed_stateful_od);

    return true;
}

bool
ls_stateful_port_group_handler(struct engine_node *node, void *data_)
{
    struct port_group_data *pg_data =
        engine_get_input_data("port_group", node);

    if (pg_data->ls_port_groups_sets_changed) {
        return false;
    }

    /* port_group engine node doesn't provide the tracking data yet.
     * Loop through all the ls port groups and update the ls_stateful_rec.
     * This is still better than returning false. */
    struct ls_stateful_input input_data = ls_stateful_get_input_data(node);
    struct ed_type_ls_stateful *data = data_;
    const struct ls_port_group *ls_pg;

    LS_PORT_GROUP_TABLE_FOR_EACH (ls_pg, input_data.ls_port_groups) {
        struct ls_stateful_record *ls_stateful_rec =
            ls_stateful_table_find_(&data->table, ls_pg->nbs);
        ovs_assert(ls_stateful_rec);
        const struct ovn_datapath *od =
            ovn_datapaths_find_by_index(input_data.ls_datapaths,
                                        ls_stateful_rec->ls_index);
        bool had_stateful_acl = ls_stateful_rec->has_stateful_acl;
        uint64_t max_acl_tier = ls_stateful_rec->max_acl_tier;
        bool had_acls = ls_stateful_rec->has_acls;
        bool modified = false;

        ls_stateful_record_reinit(ls_stateful_rec, od, ls_pg,
                                  input_data.ls_port_groups);

        if ((had_stateful_acl != ls_stateful_rec->has_stateful_acl)
            || (had_acls != ls_stateful_rec->has_acls)
            || max_acl_tier != ls_stateful_rec->max_acl_tier) {
            modified = true;
        }

        if (modified) {
            /* Add the ls_stateful_rec to the tracking data. */
            hmapx_add(&data->trk_data.crupdated, ls_stateful_rec);
        }
    }

    if (ls_stateful_has_tracked_data(&data->trk_data)) {
        engine_set_node_state(node, EN_UPDATED);
    }
    return true;
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
    ls_stateful_record_init(ls_stateful_rec, od, NULL, ls_pgs);

    hmap_insert(&table->entries, &ls_stateful_rec->key_node,
                uuid_hash(&od->nbs->header_.uuid));

    return ls_stateful_rec;
}

static void
ls_stateful_record_destroy(struct ls_stateful_record *ls_stateful_rec)
{
    free(ls_stateful_rec);
}

static void
ls_stateful_record_init(struct ls_stateful_record *ls_stateful_rec,
                        const struct ovn_datapath *od,
                        const struct ls_port_group *ls_pg,
                        const struct ls_port_group_table *ls_pgs)
{
    ls_stateful_rec->has_lb_vip = ls_has_lb_vip(od);
    ls_stateful_record_set_acl_flags(ls_stateful_rec, od, ls_pg, ls_pgs);
}

static void
ls_stateful_record_reinit(struct ls_stateful_record *ls_stateful_rec,
                          const struct ovn_datapath *od,
                          const struct ls_port_group *ls_pg,
                          const struct ls_port_group_table *ls_pgs)
{
    ls_stateful_record_init(ls_stateful_rec, od, ls_pg, ls_pgs);
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
ls_stateful_record_set_acl_flags(struct ls_stateful_record *ls_stateful_rec,
                                 const struct ovn_datapath *od,
                                 const struct ls_port_group *ls_pg,
                                 const struct ls_port_group_table *ls_pgs)
{
    ls_stateful_rec->has_stateful_acl = false;
    ls_stateful_rec->max_acl_tier = 0;
    ls_stateful_rec->has_acls = false;

    if (ls_stateful_record_set_acl_flags_(ls_stateful_rec, od->nbs->acls,
                                          od->nbs->n_acls)) {
        return;
    }

    if (!ls_pg) {
        ls_pg = ls_port_group_table_find(ls_pgs, od->nbs);
    }

    if (!ls_pg) {
        return;
    }

    const struct ls_port_group_record *ls_pg_rec;
    HMAP_FOR_EACH (ls_pg_rec, key_node, &ls_pg->nb_pgs) {
        if (ls_stateful_record_set_acl_flags_(ls_stateful_rec,
                                              ls_pg_rec->nb_pg->acls,
                                              ls_pg_rec->nb_pg->n_acls)) {
            return;
        }
    }
}

static bool
ls_stateful_record_set_acl_flags_(struct ls_stateful_record *ls_stateful_rec,
                                  struct nbrec_acl **acls,
                                  size_t n_acls)
{
    /* A true return indicates that there are no possible ACL flags
     * left to set on ls_stateful record. A false return indicates that
     * further ACLs should be explored in case more flags need to be
     * set on ls_stateful record.
     */
    if (!n_acls) {
        return false;
    }

    ls_stateful_rec->has_acls = true;
    for (size_t i = 0; i < n_acls; i++) {
        const struct nbrec_acl *acl = acls[i];
        if (acl->tier > ls_stateful_rec->max_acl_tier) {
            ls_stateful_rec->max_acl_tier = acl->tier;
        }
        if (!ls_stateful_rec->has_stateful_acl
                && !strcmp(acl->action, "allow-related")) {
            ls_stateful_rec->has_stateful_acl = true;
        }
        if (ls_stateful_rec->has_stateful_acl &&
            ls_stateful_rec->max_acl_tier ==
                nbrec_acl_col_tier.type.value.integer.max) {
            return true;
        }
    }

    return false;
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
