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
#include "lb.h"
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
static void build_od_lb_map(const struct nbrec_logical_switch_table *,
                            const struct nbrec_logical_router_table *,
                            struct hmap *ls_lb_map, struct hmap *lr_lb_map);
static struct od_lb_data *find_od_lb_data(struct hmap *od_lb_map,
                                          const struct uuid *od_uuid);
static void destroy_od_lb_data(struct od_lb_data *od_lb_data);
static struct od_lb_data *create_od_lb_data(struct hmap *od_lb_map,
                                            const struct uuid *od_uuid);
static void handle_od_lb_changes(struct nbrec_load_balancer **,
                                 size_t n_nbrec_lbs,
                                 struct od_lb_data *od_lb_data,
                                 struct ed_type_lb_data *lb_data,
                                 struct crupdated_od_lb_data *);
static void handle_od_lbgrp_changes(struct nbrec_load_balancer_group **,
                                    size_t n_nbrec_lbs,
                                    struct od_lb_data *,
                                    struct ed_type_lb_data *lb_data,
                                    struct crupdated_od_lb_data *);

static struct ovn_lb_group *create_lb_group(
    const struct nbrec_load_balancer_group *, struct hmap *lbs,
    struct hmap *lb_groups);
static void destroy_tracked_data(struct ed_type_lb_data *);
static struct crupdated_lb *add_crupdated_lb_to_tracked_data(
    struct ovn_northd_lb *, struct tracked_lb_data *, bool health_checks);
static void add_deleted_lb_to_tracked_data(struct ovn_northd_lb *,
                                                  struct tracked_lb_data *,
                                                  bool health_checks);
static struct crupdated_lbgrp *
    add_crupdated_lbgrp_to_tracked_data(struct ovn_lb_group *,
                                           struct tracked_lb_data *);
static void add_deleted_lbgrp_to_tracked_data(
    struct ovn_lb_group *, struct tracked_lb_data *);
static bool is_ls_lbs_changed(const struct nbrec_logical_switch *nbs);
static bool is_ls_lbgrps_changed(const struct nbrec_logical_switch *nbs);
static bool is_lr_lbs_changed(const struct nbrec_logical_router *);
static bool is_lr_lbgrps_changed(const struct nbrec_logical_router *);

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
    const struct nbrec_logical_switch_table *nb_ls_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));
    const struct nbrec_logical_router_table *nb_lr_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_router", node));

    lb_data->tracked = false;
    build_lbs(nb_lb_table, nb_lbg_table, &lb_data->lbs, &lb_data->lbgrps);
    build_od_lb_map(nb_ls_table, nb_lr_table, &lb_data->ls_lb_map,
                    &lb_data->lr_lb_map);

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
        /* "New" + "Deleted" is a no-op. */
        if (nbrec_load_balancer_is_new(tracked_lb)
            && nbrec_load_balancer_is_deleted(tracked_lb)) {
            continue;
        }

        struct ovn_northd_lb *lb;
        if (nbrec_load_balancer_is_new(tracked_lb)) {
            /* New load balancer. */
            lb = ovn_northd_lb_create(tracked_lb);
            hmap_insert(&lb_data->lbs, &lb->hmap_node,
                        uuid_hash(&tracked_lb->header_.uuid));
            add_crupdated_lb_to_tracked_data(lb, trk_lb_data,
                                             lb->health_checks);
            trk_lb_data->has_routable_lb |= lb->routable;
            continue;
        }

        /* Protect against "spurious" deletes reported by the IDL. */
        lb = ovn_northd_lb_find(&lb_data->lbs, &tracked_lb->header_.uuid);
        if (!lb) {
            continue;
        }

        if (nbrec_load_balancer_is_deleted(tracked_lb)) {
            hmap_remove(&lb_data->lbs, &lb->hmap_node);
            add_deleted_lb_to_tracked_data(lb, trk_lb_data,
                                           lb->health_checks);
            trk_lb_data->has_routable_lb |= lb->routable;
        } else {
            /* Load balancer updated. */
            bool health_checks = lb->health_checks;
            struct sset old_ips_v4 = SSET_INITIALIZER(&old_ips_v4);
            struct sset old_ips_v6 = SSET_INITIALIZER(&old_ips_v6);
            sset_swap(&lb->ips_v4, &old_ips_v4);
            sset_swap(&lb->ips_v6, &old_ips_v6);
            ovn_northd_lb_reinit(lb, tracked_lb);
            health_checks |= lb->health_checks;
            struct crupdated_lb *clb = add_crupdated_lb_to_tracked_data(
                lb, trk_lb_data, health_checks);
            trk_lb_data->has_routable_lb |= lb->routable;

            /* Determine the inserted and deleted vips and store them in
             * the tracked data. */
            const char *vip;
            SSET_FOR_EACH (vip, &lb->ips_v4) {
                if (!sset_find_and_delete(&old_ips_v4, vip)) {
                    sset_add(&clb->inserted_vips_v4, vip);
                }
            }

            sset_swap(&old_ips_v4, &clb->deleted_vips_v4);

            SSET_FOR_EACH (vip, &lb->ips_v6) {
                if (!sset_find_and_delete(&old_ips_v6, vip)) {
                    sset_add(&clb->inserted_vips_v6, vip);
                }
            }

            sset_swap(&old_ips_v6, &clb->deleted_vips_v6);

            sset_destroy(&old_ips_v4);
            sset_destroy(&old_ips_v6);
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
        /* "New" + "Deleted" is a no-op. */
        if (nbrec_load_balancer_group_is_new(tracked_lb_group)
            && nbrec_load_balancer_group_is_deleted(tracked_lb_group)) {
            continue;
        }

        if (nbrec_load_balancer_group_is_new(tracked_lb_group)) {
            struct ovn_lb_group *lb_group =
                create_lb_group(tracked_lb_group, &lb_data->lbs,
                                &lb_data->lbgrps);
            struct crupdated_lbgrp *clbg =
                add_crupdated_lbgrp_to_tracked_data(lb_group, trk_lb_data);
            for (size_t i = 0; i < lb_group->n_lbs; i++) {
                hmapx_add(&clbg->assoc_lbs, lb_group->lbs[i]);
            }

            trk_lb_data->has_routable_lb |= lb_group->has_routable_lb;
            continue;
        }

        /* Protect against "spurious" deletes reported by the IDL. */
        struct ovn_lb_group *lb_group;
        lb_group = ovn_lb_group_find(&lb_data->lbgrps,
                                     &tracked_lb_group->header_.uuid);
        if (!lb_group) {
            continue;
        }

        if (nbrec_load_balancer_group_is_deleted(tracked_lb_group)) {
            hmap_remove(&lb_data->lbgrps, &lb_group->hmap_node);
            add_deleted_lbgrp_to_tracked_data(lb_group, trk_lb_data);
            trk_lb_data->has_routable_lb |= lb_group->has_routable_lb;
        } else {
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

            trk_lb_data->has_routable_lb |= lb_group->has_routable_lb;
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

bool
lb_data_logical_switch_handler(struct engine_node *node, void *data)
{
    struct ed_type_lb_data *lb_data = (struct ed_type_lb_data *) data;
    const struct nbrec_logical_switch_table *nb_ls_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));

    struct tracked_lb_data *trk_lb_data = &lb_data->tracked_lb_data;
    lb_data->tracked = true;

    bool changed = false;
    const struct nbrec_logical_switch *nbs;
    NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH_TRACKED (nbs, nb_ls_table) {
        if (nbrec_logical_switch_is_deleted(nbs)) {
            struct od_lb_data *od_lb_data =
                find_od_lb_data(&lb_data->ls_lb_map, &nbs->header_.uuid);
            if (od_lb_data) {
                hmap_remove(&lb_data->ls_lb_map, &od_lb_data->hmap_node);
                hmapx_add(&trk_lb_data->deleted_od_lb_data, od_lb_data);
            }
        } else {
            bool ls_lbs_changed = is_ls_lbs_changed(nbs);
            bool ls_lbgrps_changed = is_ls_lbgrps_changed(nbs);
            if (!ls_lbs_changed && !ls_lbgrps_changed) {
                continue;
            }
            changed = true;
            struct crupdated_od_lb_data *codlb = xzalloc(sizeof *codlb);
            codlb->od_uuid = nbs->header_.uuid;
            uuidset_init(&codlb->assoc_lbs);
            uuidset_init(&codlb->assoc_lbgrps);

            struct od_lb_data *od_lb_data =
                find_od_lb_data(&lb_data->ls_lb_map, &nbs->header_.uuid);
            if (!od_lb_data) {
                od_lb_data = create_od_lb_data(&lb_data->ls_lb_map,
                                                &nbs->header_.uuid);
            }

            if (ls_lbs_changed) {
                handle_od_lb_changes(nbs->load_balancer, nbs->n_load_balancer,
                                     od_lb_data, lb_data, codlb);
            }

            if (ls_lbgrps_changed) {
                handle_od_lbgrp_changes(nbs->load_balancer_group,
                                        nbs->n_load_balancer_group,
                                        od_lb_data, lb_data, codlb);
            }

            ovs_list_insert(&trk_lb_data->crupdated_ls_lbs, &codlb->list_node);
        }
    }

    if (changed) {
        engine_set_node_state(node, EN_UPDATED);
    }
    return true;
}

bool
lb_data_logical_router_handler(struct engine_node *node, void *data)
{
    struct ed_type_lb_data *lb_data = (struct ed_type_lb_data *) data;
    const struct nbrec_logical_router_table *nbrec_lr_table =
        EN_OVSDB_GET(engine_get_input("NB_logical_router", node));

    struct tracked_lb_data *trk_lb_data = &lb_data->tracked_lb_data;
    lb_data->tracked = true;

    bool changed = false;
    const struct nbrec_logical_router *nbr;
    NBREC_LOGICAL_ROUTER_TABLE_FOR_EACH_TRACKED (nbr, nbrec_lr_table) {
        if (nbrec_logical_router_is_deleted(nbr)) {
            struct od_lb_data *od_lb_data =
                find_od_lb_data(&lb_data->lr_lb_map, &nbr->header_.uuid);
            if (od_lb_data) {
                hmap_remove(&lb_data->lr_lb_map, &od_lb_data->hmap_node);
                hmapx_add(&trk_lb_data->deleted_od_lb_data, od_lb_data);
            }
        } else {
            bool lr_lbs_changed = is_lr_lbs_changed(nbr);
            bool lr_lbgrps_changed = is_lr_lbgrps_changed(nbr);
            if (!lr_lbs_changed && !lr_lbgrps_changed) {
                continue;
            }
            changed = true;
            struct crupdated_od_lb_data *codlb = xzalloc(sizeof *codlb);
            codlb->od_uuid = nbr->header_.uuid;
            uuidset_init(&codlb->assoc_lbs);
            uuidset_init(&codlb->assoc_lbgrps);

            struct od_lb_data *od_lb_data =
                find_od_lb_data(&lb_data->lr_lb_map, &nbr->header_.uuid);
            if (!od_lb_data) {
                od_lb_data = create_od_lb_data(&lb_data->lr_lb_map,
                                                &nbr->header_.uuid);
            }

            if (lr_lbs_changed) {
                handle_od_lb_changes(nbr->load_balancer, nbr->n_load_balancer,
                                     od_lb_data, lb_data, codlb);
            }

            if (lr_lbgrps_changed) {
                handle_od_lbgrp_changes(nbr->load_balancer_group,
                                        nbr->n_load_balancer_group,
                                        od_lb_data, lb_data, codlb);
            }

            ovs_list_insert(&trk_lb_data->crupdated_lr_lbs, &codlb->list_node);
        }
    }

    if (changed) {
        engine_set_node_state(node, EN_UPDATED);
    }
    return true;
}

/* static functions. */
static void
lb_data_init(struct ed_type_lb_data *lb_data)
{
    hmap_init(&lb_data->lbs);
    hmap_init(&lb_data->lbgrps);
    hmap_init(&lb_data->ls_lb_map);
    hmap_init(&lb_data->lr_lb_map);

    struct tracked_lb_data *trk_lb_data = &lb_data->tracked_lb_data;
    hmap_init(&trk_lb_data->crupdated_lbs);
    hmapx_init(&trk_lb_data->deleted_lbs);
    hmap_init(&trk_lb_data->crupdated_lbgrps);
    hmapx_init(&trk_lb_data->deleted_lbgrps);
    ovs_list_init(&trk_lb_data->crupdated_ls_lbs);
    ovs_list_init(&trk_lb_data->crupdated_lr_lbs);
    hmapx_init(&trk_lb_data->deleted_od_lb_data);
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

    struct od_lb_data *od_lb_data;
    HMAP_FOR_EACH_POP (od_lb_data, hmap_node, &lb_data->ls_lb_map) {
        destroy_od_lb_data(od_lb_data);
    }
    hmap_destroy(&lb_data->ls_lb_map);

    HMAP_FOR_EACH_POP (od_lb_data, hmap_node, &lb_data->lr_lb_map) {
        destroy_od_lb_data(od_lb_data);
    }
    hmap_destroy(&lb_data->lr_lb_map);

    destroy_tracked_data(lb_data);
    hmap_destroy(&lb_data->tracked_lb_data.crupdated_lbs);
    hmapx_destroy(&lb_data->tracked_lb_data.deleted_lbs);
    hmapx_destroy(&lb_data->tracked_lb_data.deleted_lbgrps);
    hmap_destroy(&lb_data->tracked_lb_data.crupdated_lbgrps);
    hmapx_destroy(&lb_data->tracked_lb_data.deleted_od_lb_data);
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
build_od_lb_map(const struct nbrec_logical_switch_table *nbrec_ls_table,
                const struct nbrec_logical_router_table *nbrec_lr_table,
                struct hmap *ls_lb_map, struct hmap *lr_lb_map)
{
    const struct nbrec_logical_switch *nbrec_ls;
    NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH (nbrec_ls, nbrec_ls_table) {
        if (!nbrec_ls->n_load_balancer && !nbrec_ls->n_load_balancer_group) {
            continue;
        }

        struct od_lb_data *ls_lb_data =
            create_od_lb_data(ls_lb_map, &nbrec_ls->header_.uuid);
        for (size_t i = 0; i < nbrec_ls->n_load_balancer; i++) {
            uuidset_insert(ls_lb_data->lbs,
                           &nbrec_ls->load_balancer[i]->header_.uuid);
        }
        for (size_t i = 0; i < nbrec_ls->n_load_balancer_group; i++) {
            uuidset_insert(ls_lb_data->lbgrps,
                           &nbrec_ls->load_balancer_group[i]->header_.uuid);
        }
    }

    const struct nbrec_logical_router *nbrec_lr;
    NBREC_LOGICAL_ROUTER_TABLE_FOR_EACH (nbrec_lr, nbrec_lr_table) {
        if (!nbrec_lr->n_load_balancer && !nbrec_lr->n_load_balancer_group) {
            continue;
        }

        struct od_lb_data *lr_lb_data =
            create_od_lb_data(lr_lb_map, &nbrec_lr->header_.uuid);
        for (size_t i = 0; i < nbrec_lr->n_load_balancer; i++) {
            uuidset_insert(lr_lb_data->lbs,
                           &nbrec_lr->load_balancer[i]->header_.uuid);
        }
        for (size_t i = 0; i < nbrec_lr->n_load_balancer_group; i++) {
            uuidset_insert(lr_lb_data->lbgrps,
                           &nbrec_lr->load_balancer_group[i]->header_.uuid);
        }
    }
}

static struct od_lb_data *
create_od_lb_data(struct hmap *od_lb_map, const struct uuid *od_uuid)
{
    struct od_lb_data *od_lb_data = xzalloc(sizeof *od_lb_data);
    od_lb_data->od_uuid = *od_uuid;
    od_lb_data->lbs = xzalloc(sizeof *od_lb_data->lbs);
    od_lb_data->lbgrps = xzalloc(sizeof *od_lb_data->lbgrps);
    uuidset_init(od_lb_data->lbs);
    uuidset_init(od_lb_data->lbgrps);

    hmap_insert(od_lb_map, &od_lb_data->hmap_node,
                uuid_hash(&od_lb_data->od_uuid));
    return od_lb_data;
}

static struct od_lb_data *
find_od_lb_data(struct hmap *od_lb_map, const struct uuid *od_uuid)
{
    struct od_lb_data *od_lb_data;
    HMAP_FOR_EACH_WITH_HASH (od_lb_data, hmap_node, uuid_hash(od_uuid),
                             od_lb_map) {
        if (uuid_equals(&od_lb_data->od_uuid, od_uuid)) {
            return od_lb_data;
        }
    }

    return NULL;
}

static void
destroy_od_lb_data(struct od_lb_data *od_lb_data)
{
    uuidset_destroy(od_lb_data->lbs);
    uuidset_destroy(od_lb_data->lbgrps);
    free(od_lb_data->lbs);
    free(od_lb_data->lbgrps);
    free(od_lb_data);
}

static void
handle_od_lb_changes(struct nbrec_load_balancer **nbrec_lbs,
                     size_t n_nbrec_lbs, struct od_lb_data *od_lb_data,
                     struct ed_type_lb_data *lb_data,
                     struct crupdated_od_lb_data *codlb)
{
    struct tracked_lb_data *trk_lb_data = &lb_data->tracked_lb_data;
    struct uuidset *pre_lb_uuids = od_lb_data->lbs;
    od_lb_data->lbs = xzalloc(sizeof *od_lb_data->lbs);
    uuidset_init(od_lb_data->lbs);

    for (size_t i = 0; i < n_nbrec_lbs; i++) {
        const struct uuid *lb_uuid = &nbrec_lbs[i]->header_.uuid;
        uuidset_insert(od_lb_data->lbs, lb_uuid);

        struct uuidset_node *unode = uuidset_find(pre_lb_uuids, lb_uuid);

        if (!unode || (nbrec_load_balancer_row_get_seqno(
                nbrec_lbs[i], OVSDB_IDL_CHANGE_MODIFY) > 0)) {
            /* Add this lb to the tracked data. */
            uuidset_insert(&codlb->assoc_lbs, lb_uuid);

            if (!trk_lb_data->has_routable_lb) {
                struct ovn_northd_lb *lb = ovn_northd_lb_find(&lb_data->lbs,
                                                              lb_uuid);
                ovs_assert(lb);
                trk_lb_data->has_routable_lb |= lb->routable;
            }
        }

        if (unode) {
            uuidset_delete(pre_lb_uuids, unode);
        }
    }

    if (!uuidset_is_empty(pre_lb_uuids)) {
        trk_lb_data->has_dissassoc_lbs_from_od = true;
    }

    uuidset_destroy(pre_lb_uuids);
    free(pre_lb_uuids);
}

static void
handle_od_lbgrp_changes(struct nbrec_load_balancer_group **nbrec_lbgrps,
                        size_t n_nbrec_lbgrps, struct od_lb_data *od_lb_data,
                        struct ed_type_lb_data *lb_data,
                        struct crupdated_od_lb_data *codlb)
{
    struct tracked_lb_data *trk_lb_data = &lb_data->tracked_lb_data;
    struct uuidset *pre_lbgrp_uuids = od_lb_data->lbgrps;
    od_lb_data->lbgrps = xzalloc(sizeof *od_lb_data->lbgrps);
    uuidset_init(od_lb_data->lbgrps);
    for (size_t i = 0; i < n_nbrec_lbgrps; i++) {
        const struct uuid *lbgrp_uuid = &nbrec_lbgrps[i]->header_.uuid;
        uuidset_insert(od_lb_data->lbgrps, lbgrp_uuid);

        if (!uuidset_find_and_delete(pre_lbgrp_uuids, lbgrp_uuid)) {
            /* Add this lb group to the tracked data. */
            uuidset_insert(&codlb->assoc_lbgrps, lbgrp_uuid);

            if (!trk_lb_data->has_routable_lb) {
                struct ovn_lb_group *lbgrp =
                    ovn_lb_group_find(&lb_data->lbgrps, lbgrp_uuid);
                ovs_assert(lbgrp);
                trk_lb_data->has_routable_lb |= lbgrp->has_routable_lb;
            }
        }
    }

    if (!uuidset_is_empty(pre_lbgrp_uuids)) {
        trk_lb_data->has_dissassoc_lbgrps_from_od = true;
    }

    uuidset_destroy(pre_lbgrp_uuids);
    free(pre_lbgrp_uuids);
}

static void
destroy_tracked_data(struct ed_type_lb_data *lb_data)
{
    lb_data->tracked = false;
    lb_data->tracked_lb_data.has_health_checks = false;
    lb_data->tracked_lb_data.has_dissassoc_lbs_from_lbgrps = false;
    lb_data->tracked_lb_data.has_dissassoc_lbs_from_od = false;
    lb_data->tracked_lb_data.has_dissassoc_lbgrps_from_od = false;
    lb_data->tracked_lb_data.has_routable_lb = false;

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
        sset_destroy(&clb->inserted_vips_v4);
        sset_destroy(&clb->inserted_vips_v6);
        sset_destroy(&clb->deleted_vips_v4);
        sset_destroy(&clb->deleted_vips_v6);
        free(clb);
    }

    struct crupdated_lbgrp *crupdated_lbg;
    HMAP_FOR_EACH_POP (crupdated_lbg, hmap_node,
                       &lb_data->tracked_lb_data.crupdated_lbgrps) {
        hmapx_destroy(&crupdated_lbg->assoc_lbs);
        free(crupdated_lbg);
    }

    struct crupdated_od_lb_data *codlb;
    LIST_FOR_EACH_SAFE (codlb, list_node,
                        &lb_data->tracked_lb_data.crupdated_ls_lbs) {
        ovs_list_remove(&codlb->list_node);
        uuidset_destroy(&codlb->assoc_lbs);
        uuidset_destroy(&codlb->assoc_lbgrps);
        free(codlb);
    }

    LIST_FOR_EACH_SAFE (codlb, list_node,
                        &lb_data->tracked_lb_data.crupdated_lr_lbs) {
        ovs_list_remove(&codlb->list_node);
        uuidset_destroy(&codlb->assoc_lbs);
        uuidset_destroy(&codlb->assoc_lbgrps);
        free(codlb);
    }

    HMAPX_FOR_EACH_SAFE (node, &lb_data->tracked_lb_data.deleted_od_lb_data) {
        destroy_od_lb_data(node->data);
        hmapx_delete(&lb_data->tracked_lb_data.deleted_od_lb_data, node);
    }
}

static struct crupdated_lb *
add_crupdated_lb_to_tracked_data(struct ovn_northd_lb *lb,
                                 struct tracked_lb_data *tracked_lb_data,
                                 bool health_checks)
{
    struct crupdated_lb *clb = xzalloc(sizeof *clb);
    clb->lb = lb;
    hmap_insert(&tracked_lb_data->crupdated_lbs, &clb->hmap_node,
                uuid_hash(&lb->nlb->header_.uuid));
    sset_init(&clb->inserted_vips_v4);
    sset_init(&clb->inserted_vips_v6);
    sset_init(&clb->deleted_vips_v4);
    sset_init(&clb->deleted_vips_v6);
    if (health_checks) {
        tracked_lb_data->has_health_checks = true;
    }

    return clb;
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

static bool
is_ls_lbs_changed(const struct nbrec_logical_switch *nbs) {
    return ((nbrec_logical_switch_is_new(nbs) && nbs->n_load_balancer)
            ||  nbrec_logical_switch_is_updated(nbs,
                        NBREC_LOGICAL_SWITCH_COL_LOAD_BALANCER));
}

static bool
is_ls_lbgrps_changed(const struct nbrec_logical_switch *nbs) {
    return ((nbrec_logical_switch_is_new(nbs) && nbs->n_load_balancer_group)
            ||  nbrec_logical_switch_is_updated(nbs,
                        NBREC_LOGICAL_SWITCH_COL_LOAD_BALANCER_GROUP));
}

static bool
is_lr_lbs_changed(const struct nbrec_logical_router *nbr) {
    return ((nbrec_logical_router_is_new(nbr) && nbr->n_load_balancer)
            ||  nbrec_logical_router_is_updated(nbr,
                        NBREC_LOGICAL_ROUTER_COL_LOAD_BALANCER));
}

static bool
is_lr_lbgrps_changed(const struct nbrec_logical_router *nbr) {
    return ((nbrec_logical_router_is_new(nbr) && nbr->n_load_balancer_group)
            ||  nbrec_logical_router_is_updated(nbr,
                        NBREC_LOGICAL_ROUTER_COL_LOAD_BALANCER_GROUP));
}
