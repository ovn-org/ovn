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

    build_lbs(nb_lb_table, nb_lbg_table, &lb_data->lbs, &lb_data->lb_groups);
    engine_set_node_state(node, EN_UPDATED);
}

void
en_lb_data_cleanup(void *data)
{
    struct ed_type_lb_data *lb_data = (struct ed_type_lb_data *) data;
    lb_data_destroy(lb_data);
}

/* static functions. */
static void
lb_data_init(struct ed_type_lb_data *lb_data)
{
    hmap_init(&lb_data->lbs);
    hmap_init(&lb_data->lb_groups);
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
    HMAP_FOR_EACH_POP (lb_group, hmap_node, &lb_data->lb_groups) {
        ovn_lb_group_destroy(lb_group);
    }
    hmap_destroy(&lb_data->lb_groups);
}

static void
build_lbs(const struct nbrec_load_balancer_table *nbrec_load_balancer_table,
          const struct nbrec_load_balancer_group_table *nbrec_lb_group_table,
          struct hmap *lbs, struct hmap *lb_groups)
{
    struct ovn_lb_group *lb_group;
    struct ovn_northd_lb *lb_nb;

    const struct nbrec_load_balancer *nbrec_lb;
    NBREC_LOAD_BALANCER_TABLE_FOR_EACH (nbrec_lb, nbrec_load_balancer_table) {
        lb_nb = ovn_northd_lb_create(nbrec_lb);
        hmap_insert(lbs, &lb_nb->hmap_node,
                    uuid_hash(&nbrec_lb->header_.uuid));
    }

    const struct nbrec_load_balancer_group *nbrec_lb_group;
    NBREC_LOAD_BALANCER_GROUP_TABLE_FOR_EACH (nbrec_lb_group,
                                              nbrec_lb_group_table) {
        lb_group = ovn_lb_group_create(nbrec_lb_group, lbs);

        for (size_t i = 0; i < lb_group->n_lbs; i++) {
            build_lrouter_lb_ips(lb_group->lb_ips, lb_group->lbs[i]);
        }

        hmap_insert(lb_groups, &lb_group->hmap_node,
                    uuid_hash(&lb_group->uuid));
    }
}
