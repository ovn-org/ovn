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
#include "lib/coverage.h"
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "br-flow-mgr.h"
#include "en-lflow.h"
#include "en-bridge-data.h"
#include "include/ovn/actions.h"
#include "lib/inc-proc-eng.h"
#include "lib/lflow-conj-ids.h"
#include "lib/ovn-br-idl.h"

VLOG_DEFINE_THIS_MODULE(en_lflow);

COVERAGE_DEFINE(lflow_run);

/* TODO:  This file borrows a lot of code from controller/lflow.c.
 *        Move the generic logical flow processing logic to lib/lflow.c
 *        and use it in br-controller/lflow.c and controller/lflow.c
 */

struct lflow_output_persistent_data {
    struct shash symtab;
};

struct ed_type_lflow_output_data {
    /* conjunction ID usage information of lflows */
    struct conj_ids conj_ids;

    /* Data which is persistent and not cleared during
     * full recompute. */
    struct lflow_output_persistent_data pd;
};

struct lflow_ctx_in {
    struct shash *ovn_bridges;
    struct shash *symtab;
    struct ovnbrrec_logical_flow_table *brrec_lflow_table;
};

struct lflow_ctx_out {
    struct conj_ids *conj_ids;
};

struct lookup_port_aux {
    const struct ovnbrrec_logical_flow *lflow;
    const struct ovn_bridge *br;
};

static struct expr *convert_match_to_expr(
    const struct ovnbrrec_logical_flow *lflow, struct expr **prereqs,
    struct shash *symtab);
static void init_lflow_ctx(struct engine_node *node,
                           struct ed_type_bridge_data *,
                           struct ed_type_lflow_output_data *,
                           struct lflow_ctx_in *,
                           struct lflow_ctx_out *);
static void lflow_run(struct lflow_ctx_in *,
                      struct lflow_ctx_out *);
static bool lookup_port_cb(const void *aux_, const char *port_name,
                           unsigned int *portp);
static void consider_logical_flow(const struct ovnbrrec_logical_flow *,
                                  const struct ovn_bridge *,
                                  struct lflow_ctx_in *,
                                  struct lflow_ctx_out *);
static void add_matches_to_flow_table(const struct ovnbrrec_logical_flow *,
                                      const struct ovn_bridge *,
                                      struct hmap *matches,
                                      uint8_t ptable,
                                      uint8_t output_ptable,
                                      struct ofpbuf *ovnacts);

void *en_lflow_output_init(struct engine_node *node OVS_UNUSED,
                           struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_lflow_output_data *lflow_data = xzalloc(sizeof *lflow_data);
    ovn_init_symtab(&lflow_data->pd.symtab);
    lflow_conj_ids_init(&lflow_data->conj_ids);

    return lflow_data;
}

void en_lflow_output_cleanup(void *data_)
{
    struct ed_type_lflow_output_data *lflow_data = data_;
    lflow_conj_ids_destroy(&lflow_data->conj_ids);
    expr_symtab_destroy(&lflow_data->pd.symtab);
    shash_destroy(&lflow_data->pd.symtab);
}

enum engine_node_state
en_lflow_output_run(struct engine_node *node OVS_UNUSED, void *data_)
{
    struct ed_type_lflow_output_data *lflow_data = data_;
    struct ed_type_bridge_data *bridge_data =
        engine_get_input_data("bridge_data", node);

    lflow_conj_ids_clear(&lflow_data->conj_ids);
    br_flow_switch_logical_oflow_tables();

    struct lflow_ctx_in l_ctx_in;
    struct lflow_ctx_out l_ctx_out;

    init_lflow_ctx(node, bridge_data, lflow_data, &l_ctx_in, &l_ctx_out);
    lflow_run(&l_ctx_in, &l_ctx_out);

    return EN_UPDATED;
}

/* Static functions. */

static void
init_lflow_ctx(struct engine_node *node,
               struct ed_type_bridge_data *bridge_data,
               struct ed_type_lflow_output_data *lflow_data,
               struct lflow_ctx_in *l_ctx_in,
               struct lflow_ctx_out *l_ctx_out)
{
    struct ovnbrrec_logical_flow_table *lflow_table =
        (struct ovnbrrec_logical_flow_table *) EN_OVSDB_GET(
            engine_get_input("BR_logical_flow", node));

    l_ctx_in->ovn_bridges = &bridge_data->bridges;
    l_ctx_in->brrec_lflow_table = lflow_table;
    l_ctx_in->symtab = &lflow_data->pd.symtab;
    l_ctx_out->conj_ids = &lflow_data->conj_ids;
}

static void
lflow_run(struct lflow_ctx_in *l_ctx_in, struct lflow_ctx_out *l_ctx_out)
{
    COVERAGE_INC(lflow_run);

    const struct ovnbrrec_logical_flow *lflow;
    OVNBRREC_LOGICAL_FLOW_TABLE_FOR_EACH (lflow, l_ctx_in->brrec_lflow_table) {
        struct ovn_bridge *br = shash_find_data(l_ctx_in->ovn_bridges,
                                               lflow->bridge->name);
        if (!br) {
            continue;
        }

        consider_logical_flow(lflow, br, l_ctx_in, l_ctx_out);
    }
}

static void
consider_logical_flow(const struct ovnbrrec_logical_flow *lflow,
                      const struct ovn_bridge *br,
                      struct lflow_ctx_in *l_ctx_in,
                      struct lflow_ctx_out *l_ctx_out)
{
    uint64_t ovnacts_stub[1024 / 8];
    struct ofpbuf ovnacts = OFPBUF_STUB_INITIALIZER(ovnacts_stub);
    struct expr *prereqs = NULL;

    struct ovnact_parse_params pp = {
        .symtab = l_ctx_in->symtab,
        .pipeline = OVNACT_P_INGRESS,
        .n_tables = 255,
        .cur_ltable = lflow->table_id,
    };

    char *error = ovnacts_parse_string(lflow->actions, &pp,
                                       &ovnacts, &prereqs);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "error parsing actions \"%s\": %s",
                     lflow->actions, error);
        free(error);
    }

    struct hmap *matches = NULL;
    struct expr *expr = NULL;

    expr = convert_match_to_expr(lflow, &prereqs, l_ctx_in->symtab);
    if (!expr) {
        goto done;
    }

    expr = expr_normalize(expr);

    uint32_t start_conj_id = 0;
    uint32_t n_conjs = 0;

    struct lookup_port_aux aux = {
        .lflow = lflow,
        .br = br,
    };

    matches = xmalloc(sizeof *matches);
    n_conjs = expr_to_matches(expr, lookup_port_cb, &aux, matches);
    if (n_conjs) {
        start_conj_id = lflow_conj_ids_alloc(l_ctx_out->conj_ids,
                                             &lflow->header_.uuid,
                                             &br->key, n_conjs);
        if (!start_conj_id) {
            VLOG_ERR("32-bit conjunction ids exhausted!");
            goto done;
        }

        expr_matches_prepare(matches, start_conj_id - 1);
    }

    if (hmap_is_empty(matches)) {
        VLOG_DBG("lflow "UUID_FMT" matches are empty, skip",
                    UUID_ARGS(&lflow->header_.uuid));
        goto done;
    }

    uint8_t ptable = BR_OFTABLE_LOG_INGRESS_PIPELINE + lflow->table_id;

    add_matches_to_flow_table(lflow, br, matches, ptable,
                              BR_OFTABLE_SAVE_INPORT,
                              &ovnacts);

done:
    expr_destroy(expr);
    expr_destroy(prereqs);
    ovnacts_free(ovnacts.data, ovnacts.size);
    ofpbuf_uninit(&ovnacts);
    expr_matches_destroy(matches);
    free(matches);
}

/* Converts the match and returns the simplified expr tree.
 *
 * The caller should evaluate the conditions and normalize the expr tree.
 * If parsing is successful, '*prereqs' is also consumed.
 */
static struct expr *
convert_match_to_expr(const struct ovnbrrec_logical_flow *lflow,
                      struct expr **prereqs,
                      struct shash *symtab)
{
    char *error = NULL;

    struct expr *e = expr_parse_string(lflow->match, symtab, NULL, NULL, NULL,
                                       NULL, 0, &error);
    if (!error) {
        if (*prereqs) {
            e = expr_combine(EXPR_T_AND, e, *prereqs);
            *prereqs = NULL;
        }
        e = expr_annotate(e, symtab, &error);
    }
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "error parsing match \"%s\": %s",
                    lflow->match, error);
        free(error);
        return NULL;
    }

    return expr_simplify(e);
}

static bool
lookup_port_cb(const void *aux_, const char *port_name, unsigned int *portp)
{
    if (!strcmp(port_name, "none")) {
        *portp = 0;
        return true;
    }

    const struct lookup_port_aux *aux = aux_;
    *portp = simap_get(&aux->br->ovs_ifaces, port_name);

    return *portp > 0;
}

static void
add_matches_to_flow_table(const struct ovnbrrec_logical_flow *lflow,
                          const struct ovn_bridge *br,
                          struct hmap *matches, uint8_t ptable,
                          uint8_t output_ptable, struct ofpbuf *ovnacts)
{
    struct lookup_port_aux aux = {
        .lflow = lflow,
        .br = br,
    };

    /* Encode OVN logical actions into OpenFlow. */
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    struct ovnact_encode_params ep = {
        .lookup_port = lookup_port_cb,
        .aux = &aux,
        .is_switch = true,
        .lflow_uuid = lflow->header_.uuid,

        .pipeline = OVNACT_P_INGRESS,
        .ingress_ptable = BR_OFTABLE_LOG_INGRESS_PIPELINE,
        .egress_ptable = 0,
        .output_ptable = output_ptable,
    };
    ovnacts_encode(ovnacts->data, ovnacts->size, &ep, &ofpacts);

    struct expr_match *m;
    HMAP_FOR_EACH (m, hmap_node, matches) {
        if (vector_is_empty(&m->conjunctions)) {
            br_flow_add_logical_oflow(br->db_br->name, ptable,
                                      lflow->priority,
                                      lflow->header_.uuid.parts[0],
                                      &m->match, &ofpacts,
                                      &lflow->header_.uuid);
        } else {
            uint64_t conj_stubs[64 / 8];
            struct ofpbuf conj;

            ofpbuf_use_stub(&conj, conj_stubs, sizeof conj_stubs);
            const struct cls_conjunction *src;
            VECTOR_FOR_EACH_PTR (&m->conjunctions, src) {
                struct ofpact_conjunction *dst = ofpact_put_CONJUNCTION(&conj);
                dst->id = src->id;
                dst->clause = src->clause;
                dst->n_clauses = src->n_clauses;
            }

            br_flow_add_logical_oflow(br->db_br->name, ptable,
                                      lflow->priority,
                                      lflow->header_.uuid.parts[0],
                                      &m->match, &conj,
                                      &lflow->header_.uuid);
            ofpbuf_uninit(&conj);
        }
    }

    ofpbuf_uninit(&ofpacts);
}
