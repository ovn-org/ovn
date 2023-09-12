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

/* OVS includes */
#include "include/openvswitch/hmap.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"

/* OVN includes */
#include "en-lb-data.h"
#include "lib/inc-proc-eng.h"
#include "lib/lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "northd.h"

VLOG_DEFINE_THIS_MODULE(en_lb_data);

static void lb_data_init(struct ed_type_lb_data *);
static void lb_data_destroy(struct ed_type_lb_data *);
static void build_lbs(const struct nbrec_load_balancer_table *,
                      const struct nbrec_load_balancer_group_table *,
                      struct hmap *lbs, struct hmap *lb_groups);
static struct ovn_lb_group *create_lb_group(
    const struct nbrec_load_balancer_group *, struct hmap *lbs,
    struct hmap *lb_groups);
static void destroy_tracked_data(struct ed_type_lb_data *);
static void add_crupdated_lb_to_tracked_data(struct ovn_northd_lb *,
                                                    struct tracked_lb_data *,
                                                    bool health_checks);
static void add_deleted_lb_to_tracked_data(struct ovn_northd_lb *,
                                                  struct tracked_lb_data *,
                                                  bool health_checks);
static struct crupdated_lbgrp *
    add_crupdated_lbgrp_to_tracked_data(struct ovn_lb_group *,
                                           struct tracked_lb_data *);
static void add_deleted_lbgrp_to_tracked_data(
    struct ovn_lb_group *, struct tracked_lb_data *);

/* 'lb_data' engine node manages the NB load balancers and load balancer
 * groups.  For each NB LB, it creates 'struct ovn_northd_lb' and
 * for each NB LB group, it creates 'struct ovn_lb_group' and stores in
 * the respective hmaps in it's data (ed_type_lb_data).
 */
void *
en_lb_data_init(struct engine_node *node OVS_UNUSED,
                       struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_lb_data *data = xzalloc(sizeof *data);
    lb_data_init(data);
    return data;
}

void
en_lb_data_run(struct engine_node *node, void *data)
{
    struct ed_type_lb_data *lb_data = (struct ed_type_lb_data *) data;
    lb_data_destroy(lb_data);
    lb_data_init(lb_data);

    const struct nbrec_load_balancer_table *nb_lb_table =
        EN_OVSDB_GET(engine_get_input("NB_load_balancer", node));
    const struct nbrec_load_balancer_group_table *nb_lbg_table =
        EN_OVSDB_GET(engine_get_input("NB_load_balancer_group", node));

    lb_data->tracked = false;
    build_lbs(nb_lb_table, nb_lbg_table, &lb_data->lbs, &lb_data->lbgrps);
    engine_set_node_state(node, EN_UPDATED);
}

void
en_lb_data_cleanup(void *data)
{
    struct ed_type_lb_data *lb_data = (struct ed_type_lb_data *) data;
    lb_data_destroy(lb_data);
}

void
en_lb_data_clear_tracked_data(void *data)
{
    struct ed_type_lb_data *lb_data = (struct ed_type_lb_data *) data;
    destroy_tracked_data(lb_data);
}


/* Handler functions. */
bool
lb_data_load_balancer_handler(struct engine_node *node, void *data)
{
    const struct nbrec_load_balancer_table *nb_lb_table =
        EN_OVSDB_GET(engine_get_input("NB_load_balancer", node));

    struct ed_type_lb_data *lb_data = (struct ed_type_lb_data *) data;

    lb_data->tracked = true;
    struct tracked_lb_data *trk_lb_data = &lb_data->tracked_lb_data;

    const struct nbrec_load_balancer *tracked_lb;
    NBREC_LOAD_BALANCER_TABLE_FOR_EACH_TRACKED (tracked_lb, nb_lb_table) {
        struct ovn_northd_lb *lb;
        if (nbrec_load_balancer_is_new(tracked_lb)) {
            /* New load balancer. */
            lb = ovn_northd_lb_create(tracked_lb);
            hmap_insert(&lb_data->lbs, &lb->hmap_node,
                        uuid_hash(&tracked_lb->header_.uuid));
            add_crupdated_lb_to_tracked_data(lb, trk_lb_data,
                                             lb->health_checks);
        } else if (nbrec_load_balancer_is_deleted(tracked_lb)) {
            lb = ovn_northd_lb_find(&lb_data->lbs,
                                    &tracked_lb->header_.uuid);
            ovs_assert(lb);
            hmap_remove(&lb_data->lbs, &lb->hmap_node);
            add_deleted_lb_to_tracked_data(lb, trk_lb_data,
                                           lb->health_checks);
        } else {
            /* Load balancer updated. */
            lb = ovn_northd_lb_find(&lb_data->lbs,
                                    &tracked_lb->header_.uuid);
            ovs_assert(lb);
            bool health_checks = lb->health_checks;
            ovn_northd_lb_reinit(lb, tracked_lb);
            health_checks |= lb->health_checks;
            add_crupdated_lb_to_tracked_data(lb, trk_lb_data, health_checks);
        }
    }

    engine_set_node_state(node, EN_UPDATED);
    return true;
}

bool
lb_data_load_balancer_group_handler(struct engine_node *node, void *data)
{
    struct ed_type_lb_data *lb_data = (struct ed_type_lb_data *) data;
    const struct nbrec_load_balancer_group_table *nb_lbg_table =
        EN_OVSDB_GET(engine_get_input("NB_load_balancer_group", node));

    lb_data->tracked = true;
    struct tracked_lb_data *trk_lb_data = &lb_data->tracked_lb_data;
    const struct nbrec_load_balancer_group *tracked_lb_group;
    NBREC_LOAD_BALANCER_GROUP_TABLE_FOR_EACH_TRACKED (tracked_lb_group,
                                                      nb_lbg_table) {
        if (nbrec_load_balancer_group_is_new(tracked_lb_group)) {
            struct ovn_lb_group *lb_group =
                create_lb_group(tracked_lb_group, &lb_data->lbs,
                                &lb_data->lbgrps);
            struct crupdated_lbgrp *clbg =
                add_crupdated_lbgrp_to_tracked_data(lb_group, trk_lb_data);
            for (size_t i = 0; i < lb_group->n_lbs; i++) {
                hmapx_add(&clbg->assoc_lbs, lb_group->lbs[i]);
            }
        } else if (nbrec_load_balancer_group_is_deleted(tracked_lb_group)) {
            struct ovn_lb_group *lb_group;
            lb_group = ovn_lb_group_find(&lb_data->lbgrps,
                                         &tracked_lb_group->header_.uuid);
            ovs_assert(lb_group);
            hmap_remove(&lb_data->lbgrps, &lb_group->hmap_node);
            add_deleted_lbgrp_to_tracked_data(lb_group, trk_lb_data);
        } else {

            struct ovn_lb_group *lb_group;
            lb_group = ovn_lb_group_find(&lb_data->lbgrps,
                                         &tracked_lb_group->header_.uuid);
            ovs_assert(lb_group);

            /* Determine the lbs which are added or deleted for this
             * lb group and add them to tracked data.
             * Eg.  If an lb group lbg1 before the update had [lb1, lb2, lb3]
             *      And in the update, lb2 was removed and lb4 got added, then
             *      add lb2 and lb4 to the trk_lb_data->crupdated_lbs. */
            struct hmapx pre_update_lbs = HMAPX_INITIALIZER(&pre_update_lbs);
            for (size_t i = 0; i < lb_group->n_lbs; i++) {
                hmapx_add(&pre_update_lbs, lb_group->lbs[i]);
            }
            ovn_lb_group_reinit(lb_group, tracked_lb_group, &lb_data->lbs);
            for (size_t i = 0; i < lb_group->n_lbs; i++) {
                build_lrouter_lb_ips(lb_group->lb_ips, lb_group->lbs[i]);
            }

            struct crupdated_lbgrp *clbg =
                add_crupdated_lbgrp_to_tracked_data(lb_group, trk_lb_data);

            for (size_t i = 0; i < lb_group->n_lbs; i++) {
                struct ovn_northd_lb *lb = lb_group->lbs[i];
                struct hmapx_node *hmapx_node = hmapx_find(&pre_update_lbs,
                                                           lb);
                if (!hmapx_node) {
                    hmapx_add(&clbg->assoc_lbs, lb);
                } else {
                    hmapx_delete(&pre_update_lbs, hmapx_node);
                }
            }

            struct hmapx_node *hmapx_node;
            HMAPX_FOR_EACH_SAFE (hmapx_node, &pre_update_lbs) {
                struct ovn_northd_lb *lb = hmapx_node->data;
                /* Check if the pre updated lb is actually deleted or
                 * just disassociated from the lb group. If it's just
                 * disassociated, then set 'has_dissassoc_lbs_from_lb_grops' to
                 * true.  Later if required we can add this 'lb' to an hmapx of
                 * disassociated_lbs. */
                if (!hmapx_find(&trk_lb_data->deleted_lbs, lb)) {
                    trk_lb_data->has_dissassoc_lbs_from_lbgrps = true;
                }
                hmapx_delete(&pre_update_lbs, hmapx_node);
            }
            hmapx_destroy(&pre_update_lbs);
        }
    }

    engine_set_node_state(node, EN_UPDATED);
    return true;
}

/* static functions. */
static void
lb_data_init(struct ed_type_lb_data *lb_data)
{
    hmap_init(&lb_data->lbs);
    hmap_init(&lb_data->lbgrps);

    struct tracked_lb_data *trk_lb_data = &lb_data->tracked_lb_data;
    hmap_init(&trk_lb_data->crupdated_lbs);
    hmapx_init(&trk_lb_data->deleted_lbs);
    hmap_init(&trk_lb_data->crupdated_lbgrps);
    hmapx_init(&trk_lb_data->deleted_lbgrps);
}

static void
lb_data_destroy(struct ed_type_lb_data *lb_data)
{
    struct ovn_northd_lb *lb;
    HMAP_FOR_EACH_POP (lb, hmap_node, &lb_data->lbs) {
        ovn_northd_lb_destroy(lb);
    }
    hmap_destroy(&lb_data->lbs);

    struct ovn_lb_group *lb_group;
    HMAP_FOR_EACH_POP (lb_group, hmap_node, &lb_data->lbgrps) {
        ovn_lb_group_destroy(lb_group);
    }
    hmap_destroy(&lb_data->lbgrps);

    destroy_tracked_data(lb_data);
    hmap_destroy(&lb_data->tracked_lb_data.crupdated_lbs);
    hmapx_destroy(&lb_data->tracked_lb_data.deleted_lbs);
    hmapx_destroy(&lb_data->tracked_lb_data.deleted_lbgrps);
    hmap_destroy(&lb_data->tracked_lb_data.crupdated_lbgrps);
}

static void
build_lbs(const struct nbrec_load_balancer_table *nbrec_load_balancer_table,
          const struct nbrec_load_balancer_group_table *nbrec_lb_group_table,
          struct hmap *lbs, struct hmap *lb_groups)
{
    const struct nbrec_load_balancer *nbrec_lb;
    NBREC_LOAD_BALANCER_TABLE_FOR_EACH (nbrec_lb, nbrec_load_balancer_table) {
        struct ovn_northd_lb *lb_nb = ovn_northd_lb_create(nbrec_lb);
        hmap_insert(lbs, &lb_nb->hmap_node,
                    uuid_hash(&nbrec_lb->header_.uuid));
    }

    const struct nbrec_load_balancer_group *nbrec_lb_group;
    NBREC_LOAD_BALANCER_GROUP_TABLE_FOR_EACH (nbrec_lb_group,
                                              nbrec_lb_group_table) {
        create_lb_group(nbrec_lb_group, lbs, lb_groups);
    }
}

static struct ovn_lb_group *
create_lb_group(const struct nbrec_load_balancer_group *nbrec_lb_group,
                struct hmap *lbs, struct hmap *lb_groups)
{
    struct ovn_lb_group *lb_group = ovn_lb_group_create(nbrec_lb_group, lbs);

    for (size_t i = 0; i < lb_group->n_lbs; i++) {
        build_lrouter_lb_ips(lb_group->lb_ips, lb_group->lbs[i]);
    }

    hmap_insert(lb_groups, &lb_group->hmap_node,
                uuid_hash(&lb_group->uuid));

    return lb_group;
}

static void
destroy_tracked_data(struct ed_type_lb_data *lb_data)
{
    lb_data->tracked = false;
    lb_data->tracked_lb_data.has_health_checks = false;
    lb_data->tracked_lb_data.has_dissassoc_lbs_from_lbgrps = false;

    struct hmapx_node *node;
    HMAPX_FOR_EACH_SAFE (node, &lb_data->tracked_lb_data.deleted_lbs) {
        ovn_northd_lb_destroy(node->data);
        hmapx_delete(&lb_data->tracked_lb_data.deleted_lbs, node);
    }

    HMAPX_FOR_EACH_SAFE (node, &lb_data->tracked_lb_data.deleted_lbgrps) {
        ovn_lb_group_destroy(node->data);
        hmapx_delete(&lb_data->tracked_lb_data.deleted_lbgrps, node);
    }

    struct crupdated_lb *clb;
    HMAP_FOR_EACH_POP (clb, hmap_node,
                       &lb_data->tracked_lb_data.crupdated_lbs) {
        free(clb);
    }

    struct crupdated_lbgrp *crupdated_lbg;
    HMAP_FOR_EACH_POP (crupdated_lbg, hmap_node,
                       &lb_data->tracked_lb_data.crupdated_lbgrps) {
        hmapx_destroy(&crupdated_lbg->assoc_lbs);
        free(crupdated_lbg);
    }
}

static void
add_crupdated_lb_to_tracked_data(struct ovn_northd_lb *lb,
                                 struct tracked_lb_data *tracked_lb_data,
                                 bool health_checks)
{
    struct crupdated_lb *clb = xzalloc(sizeof *clb);
    clb->lb = lb;
    hmap_insert(&tracked_lb_data->crupdated_lbs, &clb->hmap_node,
                uuid_hash(&lb->nlb->header_.uuid));
    if (health_checks) {
        tracked_lb_data->has_health_checks = true;
    }
}

static void
add_deleted_lb_to_tracked_data(struct ovn_northd_lb *lb,
                               struct tracked_lb_data *tracked_lb_data,
                               bool health_checks)
{
    hmapx_add(&tracked_lb_data->deleted_lbs, lb);
    if (health_checks) {
        tracked_lb_data->has_health_checks = true;
    }
}

static struct crupdated_lbgrp *
add_crupdated_lbgrp_to_tracked_data(struct ovn_lb_group *lbgrp,
                                       struct tracked_lb_data *tracked_lb_data)
{
    struct crupdated_lbgrp *clbg = xzalloc(sizeof *clbg);
    clbg->lbgrp = lbgrp;
    hmapx_init(&clbg->assoc_lbs);
    hmap_insert(&tracked_lb_data->crupdated_lbgrps, &clbg->hmap_node,
                uuid_hash(&lbgrp->uuid));
    return clbg;
}

static void
add_deleted_lbgrp_to_tracked_data(struct ovn_lb_group *lbg,
                                     struct tracked_lb_data *tracked_lb_data)
{
    hmapx_add(&tracked_lb_data->deleted_lbgrps, lbg);
}
