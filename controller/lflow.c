/* Copyright (c) 2015, 2016, 2017 Nicira, Inc.
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
#include "binding.h"
#include "lflow.h"
#include "coverage.h"
#include "ha-chassis.h"
#include "lflow-cache.h"
#include "local_data.h"
#include "lport.h"
#include "ofctrl.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovn-controller.h"
#include "ovn/actions.h"
#include "ovn/expr.h"
#include "lib/lb.h"
#include "lib/ovn-l7.h"
#include "lib/ovn-sb-idl.h"
#include "lib/extend-table.h"
#include "lib/uuidset.h"
#include "packets.h"
#include "physical.h"
#include "simap.h"
#include "sset.h"

VLOG_DEFINE_THIS_MODULE(lflow);

COVERAGE_DEFINE(lflow_run);
COVERAGE_DEFINE(consider_logical_flow);

/* Symbol table. */

/* Contains "struct expr_symbol"s for fields supported by OVN lflows. */
static struct shash symtab;

void
lflow_init(void)
{
    ovn_init_symtab(&symtab);
}

struct lookup_port_aux {
    struct ovsdb_idl_index *sbrec_multicast_group_by_name_datapath;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    const struct sbrec_datapath_binding *dp;
    const struct sbrec_logical_flow *lflow;
    struct objdep_mgr *deps_mgr;
    const struct hmap *chassis_tunnels;
};

struct condition_aux {
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    const struct sbrec_datapath_binding *dp;
    const struct sbrec_chassis *chassis;
    const struct sset *active_tunnels;
    const struct sbrec_logical_flow *lflow;
    /* Resource reference to store the port name referenced
     * in is_chassis_resident() to the object (logical flow). */
    struct objdep_mgr *deps_mgr;
};

static struct expr *
convert_match_to_expr(const struct sbrec_logical_flow *,
                      const struct local_datapath *ldp,
                      struct expr **prereqs, const struct shash *addr_sets,
                      const struct shash *port_groups,
                      const struct smap *template_vars,
                      struct sset *template_vars_ref,
                      struct objdep_mgr *, bool *pg_addr_set_ref);
static void
add_matches_to_flow_table(const struct sbrec_logical_flow *,
                          const struct local_datapath *,
                          struct hmap *matches, uint8_t ptable,
                          uint8_t output_ptable, struct ofpbuf *ovnacts,
                          bool ingress, struct lflow_ctx_in *,
                          struct lflow_ctx_out *);
static void
consider_logical_flow(const struct sbrec_logical_flow *lflow,
                      bool is_recompute,
                      struct lflow_ctx_in *l_ctx_in,
                      struct lflow_ctx_out *l_ctx_out);

static void
consider_lb_hairpin_flows(const struct ovn_controller_lb *lb,
                          const struct hmap *local_datapaths,
                          bool use_ct_mark,
                          struct ovn_desired_flow_table *flow_table);

static void add_port_sec_flows(const struct shash *binding_lports,
                               const struct sbrec_chassis *,
                               struct ovn_desired_flow_table *);
static void consider_port_sec_flows(const struct sbrec_port_binding *pb,
                                    struct ovn_desired_flow_table *);

static bool
lookup_port_cb(const void *aux_, const char *port_name, unsigned int *portp)
{
    if (!strcmp(port_name, "none")) {
        *portp = 0;
        return true;
    }

    const struct lookup_port_aux *aux = aux_;

    /* Store the name that used to lookup the lport to lflow reference, so that
     * in the future when the lport's port binding changes, the logical flow
     * that references this lport can be reprocessed. */
    objdep_mgr_add(aux->deps_mgr, OBJDEP_TYPE_PORTBINDING, port_name,
                   &aux->lflow->header_.uuid);

    const struct sbrec_port_binding *pb
        = lport_lookup_by_name(aux->sbrec_port_binding_by_name, port_name);
    if (pb && pb->datapath == aux->dp) {
        *portp = pb->tunnel_key;
        return true;
    }

    /* Store the key (DP + name) that used to lookup the multicast group to
     * lflow reference, so that in the future when the multicast group's
     * existance (found/not found) changes, the logical flow that references
     * this multicast group can be reprocessed. */
    struct ds mg_key = DS_EMPTY_INITIALIZER;
    get_mc_group_key(port_name, aux->dp->tunnel_key, &mg_key);
    objdep_mgr_add(aux->deps_mgr, OBJDEP_TYPE_MC_GROUP, ds_cstr(&mg_key),
                   &aux->lflow->header_.uuid);
    ds_destroy(&mg_key);

    const struct sbrec_multicast_group *mg = mcgroup_lookup_by_dp_name(
        aux->sbrec_multicast_group_by_name_datapath, aux->dp, port_name);
    if (mg) {
        *portp = mg->tunnel_key;
        return true;
    }

    return false;
}

/* Given the OVN port name, get its openflow port */
static bool
tunnel_ofport_cb(const void *aux_, const char *port_name, ofp_port_t *ofport)
{
    const struct lookup_port_aux *aux = aux_;

    const struct sbrec_port_binding *pb
        = lport_lookup_by_name(aux->sbrec_port_binding_by_name, port_name);
    if (!pb || (pb->datapath != aux->dp) || !pb->chassis) {
        return false;
    }

    if (!get_chassis_tunnel_ofport(aux->chassis_tunnels, pb->chassis->name,
                                   NULL, ofport)) {
        return false;
    }

    return true;
}

static bool
is_chassis_resident_cb(const void *c_aux_, const char *port_name)
{
    const struct condition_aux *c_aux = c_aux_;

    /* Store the port name that used to lookup the lport to object reference,
     * so that in the future when the lport's port-binding changes the logical
     * flow that references this lport can be reprocessed. */
    objdep_mgr_add(c_aux->deps_mgr, OBJDEP_TYPE_PORTBINDING, port_name,
                   &c_aux->lflow->header_.uuid);

    const struct sbrec_port_binding *pb
        = lport_lookup_by_name(c_aux->sbrec_port_binding_by_name, port_name);
    if (!pb) {
        return false;
    }

    if (strcmp(pb->type, "chassisredirect")) {
        /* for non-chassisredirect ports */
        return pb->chassis && pb->chassis == c_aux->chassis;
    } else {
        if (ha_chassis_group_contains(pb->ha_chassis_group,
                                      c_aux->chassis)) {
            bool active = ha_chassis_group_is_active(pb->ha_chassis_group,
                                                     c_aux->active_tunnels,
                                                     c_aux->chassis);
            return active;
        }
        return false;
    }
}

/* Adds the logical flows from the Logical_Flow table to flow tables. */
static void
add_logical_flows(struct lflow_ctx_in *l_ctx_in,
                  struct lflow_ctx_out *l_ctx_out)
{
    const struct sbrec_logical_flow *lflow;
    SBREC_LOGICAL_FLOW_TABLE_FOR_EACH (lflow, l_ctx_in->logical_flow_table) {
        consider_logical_flow(lflow, true, l_ctx_in, l_ctx_out);
    }
}

bool
lflow_handle_changed_flows(struct lflow_ctx_in *l_ctx_in,
                           struct lflow_ctx_out *l_ctx_out)
{
    bool ret = true;
    const struct sbrec_logical_flow *lflow;

    /* Flood remove the flows for all the tracked lflows.  Its possible that
     * lflow_add_flows_for_datapath() may have been called before calling
     * this function. */
    struct uuidset flood_remove_nodes =
        UUIDSET_INITIALIZER(&flood_remove_nodes);
    SBREC_LOGICAL_FLOW_TABLE_FOR_EACH_TRACKED (lflow,
                                               l_ctx_in->logical_flow_table) {
        if (uuidset_find(l_ctx_out->objs_processed, &lflow->header_.uuid)) {
            VLOG_DBG("lflow "UUID_FMT"has been processed, skip.",
                     UUID_ARGS(&lflow->header_.uuid));
            continue;
        }
        VLOG_DBG("delete lflow "UUID_FMT, UUID_ARGS(&lflow->header_.uuid));
        uuidset_insert(&flood_remove_nodes, &lflow->header_.uuid);
        if (!sbrec_logical_flow_is_new(lflow)) {
            if (lflow_cache_is_enabled(l_ctx_out->lflow_cache)) {
                lflow_cache_delete(l_ctx_out->lflow_cache,
                                   &lflow->header_.uuid);
            }
        }
    }
    ofctrl_flood_remove_flows(l_ctx_out->flow_table, &flood_remove_nodes);

    struct uuidset_node *ofrn;
    UUIDSET_FOR_EACH (ofrn, &flood_remove_nodes) {
        /* Delete entries from lflow resource reference. */
        objdep_mgr_remove_obj(l_ctx_out->lflow_deps_mgr, &ofrn->uuid);
        /* Delete conj_ids owned by the lflow. */
        lflow_conj_ids_free(l_ctx_out->conj_ids, &ofrn->uuid);
        /* Reprocessing the lflow if the sb record is not deleted. */
        lflow = sbrec_logical_flow_table_get_for_uuid(
            l_ctx_in->logical_flow_table, &ofrn->uuid);
        if (lflow) {
            VLOG_DBG("re-add lflow "UUID_FMT,
                     UUID_ARGS(&lflow->header_.uuid));

            /* For the extra lflows that need to be reprocessed because of the
             * flood remove, remove it from objs_processed. */
            struct uuidset_node *unode =
                uuidset_find(l_ctx_out->objs_processed,
                             &lflow->header_.uuid);
            if (unode) {
                VLOG_DBG("lflow "UUID_FMT"has been processed, now reprocess.",
                         UUID_ARGS(&lflow->header_.uuid));
                uuidset_delete(l_ctx_out->objs_processed, unode);
            }

            consider_logical_flow(lflow, false, l_ctx_in, l_ctx_out);
        }
    }
    uuidset_destroy(&flood_remove_nodes);

    return ret;
}

static bool
as_info_from_expr_const(const char *as_name, const union expr_constant *c,
                        struct addrset_info *as_info)
{
    as_info->name = as_name;
    as_info->ip = c->value.ipv6;
    if (c->masked) {
        as_info->mask = c->mask.ipv6;
    } else {
        /* Generate mask so that it is the same as what's added for
         * expr->cmp.mask. See make_cmp__() in expr.c. */
        union mf_subvalue mask;
        memset(&mask, 0, sizeof mask);
        if (c->format == LEX_F_IPV4) {
            mask.ipv4 = be32_prefix_mask(32);
        } else if (c->format == LEX_F_IPV6) {
            mask.ipv6 = ipv6_create_mask(128);
        } else if (c->format == LEX_F_ETHERNET) {
            mask.mac = eth_addr_exact;
        } else {
            /* Not an address */
            return false;
        }
        as_info->mask = mask.ipv6;
    }
    return true;
}

static void
store_lflow_template_refs(struct objdep_mgr *lflow_deps_mgr,
                          const struct sset *template_vars_ref,
                          const struct sbrec_logical_flow *lflow)
{
    const char *tv_name;
    SSET_FOR_EACH (tv_name, template_vars_ref) {
        objdep_mgr_add(lflow_deps_mgr, OBJDEP_TYPE_TEMPLATE, tv_name,
                       &lflow->header_.uuid);
    }
}

static bool
lflow_parse_actions(const struct sbrec_logical_flow *lflow,
                    const struct lflow_ctx_in *l_ctx_in,
                    struct sset *template_vars_ref,
                    struct ofpbuf *ovnacts_out,
                    struct expr **prereqs_out)
{
    bool ingress = !strcmp(lflow->pipeline, "ingress");
    struct ovnact_parse_params pp = {
        .symtab = &symtab,
        .dhcp_opts = l_ctx_in->dhcp_opts,
        .dhcpv6_opts = l_ctx_in->dhcpv6_opts,
        .nd_ra_opts = l_ctx_in->nd_ra_opts,
        .controller_event_opts = l_ctx_in->controller_event_opts,

        .pipeline = ingress ? OVNACT_P_INGRESS : OVNACT_P_EGRESS,
        .n_tables = LOG_PIPELINE_LEN,
        .cur_ltable = lflow->table_id,
    };

    struct lex_str actions_s =
        lexer_parse_template_string(lflow->actions, l_ctx_in->template_vars,
                                    template_vars_ref);
    char *error = ovnacts_parse_string(lex_str_get(&actions_s), &pp,
                                       ovnacts_out, prereqs_out);
    lex_str_free(&actions_s);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "error parsing actions \"%s\": %s",
                     lflow->actions, error);
        free(error);
        return false;
    }
    return true;
}

/* Parses the lflow regarding the changed address set 'as_name', and generates
 * ovs flows for the newly added addresses in 'as_diff_added' only. It is
 * similar to consider_logical_flow__, with the below differences:
 *
 * - It has one more arg 'as_ref_count' to deduce how many flows are expected
 *   to be added.
 * - It uses a small fake address set that contains only the added addresses
 *   to replace the original address set temporarily and restores it after
 *   parsing.
 * - It doesn't check or touch lflow-cache, because lflow-cache is disabled
 *   when address-sets/port-groups are used.
 * - It doesn't check non-local lports because it should have been checked
 *   when the lflow is initially parsed, and if it is non-local and skipped
 *   then it wouldn't have the address set parsed and referenced.
 *
 * Because of these differences, it is just cleaner to keep it as a separate
 * function. */
static bool
consider_lflow_for_added_as_ips__(
                        const struct sbrec_logical_flow *lflow,
                        const struct sbrec_datapath_binding *dp,
                        const char *as_name,
                        size_t as_ref_count,
                        const struct expr_constant_set *as_diff_added,
                        struct lflow_ctx_in *l_ctx_in,
                        struct lflow_ctx_out *l_ctx_out)
{
    bool handled = true;
    struct local_datapath *ldp = get_local_datapath(l_ctx_in->local_datapaths,
                                                    dp->tunnel_key);
    if (!ldp) {
        VLOG_DBG("Skip lflow "UUID_FMT" for non-local datapath %"PRId64,
                 UUID_ARGS(&lflow->header_.uuid), dp->tunnel_key);
        return true;
    }

    /* Determine translation of logical table IDs to physical table IDs. */
    bool ingress = !strcmp(lflow->pipeline, "ingress");

    /* Determine translation of logical table IDs to physical table IDs. */
    uint8_t first_ptable = (ingress
                            ? OFTABLE_LOG_INGRESS_PIPELINE
                            : OFTABLE_LOG_EGRESS_PIPELINE);
    uint8_t ptable = first_ptable + lflow->table_id;
    uint8_t output_ptable = (ingress
                             ? OFTABLE_OUTPUT_INIT
                             : OFTABLE_SAVE_INPORT);

    uint64_t ovnacts_stub[1024 / 8];
    struct ofpbuf ovnacts = OFPBUF_STUB_INITIALIZER(ovnacts_stub);
    struct sset template_vars_ref = SSET_INITIALIZER(&template_vars_ref);
    struct expr *prereqs = NULL;

    if (!lflow_parse_actions(lflow, l_ctx_in, &template_vars_ref,
                             &ovnacts, &prereqs)) {
        ovnacts_free(ovnacts.data, ovnacts.size);
        ofpbuf_uninit(&ovnacts);
        store_lflow_template_refs(l_ctx_out->lflow_deps_mgr,
                                  &template_vars_ref, lflow);
        sset_destroy(&template_vars_ref);
        return true;
    }

    struct lookup_port_aux aux = {
        .sbrec_multicast_group_by_name_datapath
            = l_ctx_in->sbrec_multicast_group_by_name_datapath,
        .sbrec_port_binding_by_name = l_ctx_in->sbrec_port_binding_by_name,
        .dp = dp,
        .lflow = lflow,
        .deps_mgr = l_ctx_out->lflow_deps_mgr,
    };
    struct condition_aux cond_aux = {
        .sbrec_port_binding_by_name = l_ctx_in->sbrec_port_binding_by_name,
        .dp = dp,
        .chassis = l_ctx_in->chassis,
        .active_tunnels = l_ctx_in->active_tunnels,
        .lflow = lflow,
        .deps_mgr = l_ctx_out->lflow_deps_mgr,
    };

    struct hmap matches = HMAP_INITIALIZER(&matches);
    const struct expr_constant_set *fake_as = as_diff_added;
    struct expr_constant_set *new_fake_as = NULL;
    struct in6_addr dummy_ip;
    bool has_dummy_ip = false;
    ovs_assert(as_diff_added->n_values);

    /* When there is only 1 element, we append a dummy address and create a
     * fake address set with 2 elements, so that the lflow parsing would
     * generate exactly the same format of flows as it would when parsing with
     * the original address set. */
    if (as_diff_added->n_values == 1) {
        new_fake_as = xzalloc(sizeof *new_fake_as);
        new_fake_as->values = xzalloc(sizeof *new_fake_as->values * 2);
        new_fake_as->n_values = 2;
        new_fake_as->values[0] = new_fake_as->values[1] =
            as_diff_added->values[0];
        /* Make a dummy ip that is different from the real one. */
        new_fake_as->values[1].value.u8_val++;
        dummy_ip = new_fake_as->values[1].value.ipv6;
        has_dummy_ip = true;
        fake_as = new_fake_as;
    }

    /* Temporarily replace the address set in addr_sets with the fake_as, so
     * that the cost of lflow parsing is related to the delta but not the
     * original size of the address set. It is possible that there are other
     * address sets used by this logical flow and their size can be big. In
     * such case the parsing cost is still high. In practice, big address
     * sets are likely to be updated more frequently that small address sets,
     * so this approach should still be effective overall.
     *
     * XXX: if necessary, we can optimize this by checking all the address set
     * references in this lflow, and replace all the "big" address sets with a
     * small faked one. */
    struct expr_constant_set *real_as =
        shash_replace((struct shash *)l_ctx_in->addr_sets, as_name, fake_as);
    /* We are here because of the address set update, so it must be found. */
    ovs_assert(real_as);

    struct expr *expr = convert_match_to_expr(lflow, ldp, &prereqs,
                                              l_ctx_in->addr_sets,
                                              l_ctx_in->port_groups,
                                              l_ctx_in->template_vars,
                                              &template_vars_ref,
                                              l_ctx_out->lflow_deps_mgr, NULL);
    shash_replace((struct shash *)l_ctx_in->addr_sets, as_name, real_as);
    if (new_fake_as) {
        expr_constant_set_destroy(new_fake_as);
        free(new_fake_as);
    }
    if (!expr) {
        goto done;
    }

    expr = expr_evaluate_condition(expr, is_chassis_resident_cb,
                                   &cond_aux);
    expr = expr_normalize(expr);

    uint32_t start_conj_id = 0;
    uint32_t n_conjs = 0;
    n_conjs = expr_to_matches(expr, lookup_port_cb, &aux, &matches);
    if (hmap_is_empty(&matches)) {
        VLOG_DBG("lflow "UUID_FMT" matches are empty, skip",
                 UUID_ARGS(&lflow->header_.uuid));
        goto done;
    }

    /* Discard the matches unrelated to the added addresses in the AS
     * 'as_name'. */
    struct expr_match *m;
    HMAP_FOR_EACH_SAFE (m, hmap_node, &matches) {
        if (!m->as_name || strcmp(m->as_name, as_name) ||
            (has_dummy_ip && !memcmp(&m->as_ip, &dummy_ip, sizeof dummy_ip))) {
            hmap_remove(&matches, &m->hmap_node);
            expr_match_destroy(m);
            continue;
        }
    }

    /* The number of matches generated by the new addresses should match the
     * number of items in the as_diff_added and the reference count of the AS
     * in this lflow. Otherwise, it means we hit some complex/corner cases that
     * the generated matches can't be mapped from the items in the
     * as_diff_added. So we need to fall back to reprocessing the lflow.
     */
    if (hmap_count(&matches) != as_ref_count * as_diff_added->n_values) {
        VLOG_DBG("lflow "UUID_FMT", addrset %s: Generated flows count "
                 "(%"PRIuSIZE") " "doesn't match added addresses count "
                 "(%"PRIuSIZE") and ref_count (%"PRIuSIZE"). "
                 "Need reprocessing.",
                 UUID_ARGS(&lflow->header_.uuid), as_name,
                 hmap_count(&matches), as_diff_added->n_values, as_ref_count);
        handled = false;
        goto done;
    }
    if (n_conjs) {
        start_conj_id = lflow_conj_ids_find(l_ctx_out->conj_ids,
                                            &lflow->header_.uuid,
                                            &dp->header_.uuid);
        if (!start_conj_id) {
            VLOG_DBG("lflow "UUID_FMT" didn't have conjunctions. "
                     "Need reprocessing", UUID_ARGS(&lflow->header_.uuid));
            handled = false;
            goto done;
        }
        expr_matches_prepare(&matches, start_conj_id - 1);
    }
    add_matches_to_flow_table(lflow, ldp, &matches, ptable, output_ptable,
                              &ovnacts, ingress, l_ctx_in, l_ctx_out);
done:
    expr_destroy(prereqs);
    ovnacts_free(ovnacts.data, ovnacts.size);
    ofpbuf_uninit(&ovnacts);
    expr_destroy(expr);
    expr_matches_destroy(&matches);

    store_lflow_template_refs(l_ctx_out->lflow_deps_mgr,
                              &template_vars_ref, lflow);
    sset_destroy(&template_vars_ref);

    return handled;
}

static bool
consider_lflow_for_added_as_ips(
                        const struct sbrec_logical_flow *lflow,
                        const char *as_name,
                        size_t as_ref_count,
                        const struct expr_constant_set *as_diff_added,
                        struct lflow_ctx_in *l_ctx_in,
                        struct lflow_ctx_out *l_ctx_out)
{
    const struct sbrec_logical_dp_group *dp_group = lflow->logical_dp_group;
    const struct sbrec_datapath_binding *dp = lflow->logical_datapath;

    if (!dp_group && !dp) {
        VLOG_DBG("lflow "UUID_FMT" has no datapath binding, skip",
                 UUID_ARGS(&lflow->header_.uuid));
        return true;
    }
    ovs_assert(!dp_group || !dp);

    if (dp) {
        return consider_lflow_for_added_as_ips__(lflow, dp, as_name,
                                                 as_ref_count, as_diff_added,
                                                 l_ctx_in, l_ctx_out);
    }
    for (size_t i = 0; dp_group && i < dp_group->n_datapaths; i++) {
        if (!consider_lflow_for_added_as_ips__(lflow, dp_group->datapaths[i],
                                               as_name, as_ref_count,
                                               as_diff_added, l_ctx_in,
                                               l_ctx_out)) {
            return false;
        }
    }
    return true;
}

/* Check if an address set update can be handled without reprocessing the
 * lflow. */
static bool
as_update_can_be_handled(const char *as_name, struct addr_set_diff *as_diff,
                         struct lflow_ctx_in *l_ctx_in)
{
    struct expr_constant_set *as = shash_find_data(l_ctx_in->addr_sets,
                                                   as_name);
    ovs_assert(as);
    size_t n_added = as_diff->added ? as_diff->added->n_values : 0;
    size_t n_deleted = as_diff->deleted ? as_diff->deleted->n_values : 0;
    size_t old_as_size = as->n_values + n_deleted - n_added;

    /* If the change may impact n_conj, i.e. the template of the flows would
     * change, we must reprocess the lflow. */
    if (old_as_size <= 1 || as->n_values <= 1) {
        return false;
    }

    /* If the size of the diff is too big, reprocessing may be more
     * efficient than incrementally processing the diffs.  */
    if ((n_added + n_deleted) >= as->n_values) {
        return false;
    }

    return true;
}

/* Handles address set update incrementally - processes only the diff
 * (added/deleted) addresses in the address set. If it cannot handle the update
 * incrementally, returns false, so that the caller will trigger reprocessing
 * for the lflow.
 *
 * The reasons that the function returns false are:
 *
 * - The size of the address set changed to/from 0 or 1, which means the
 *   'template' of the lflow translation is changed. In this case reprocessing
 *   doesn't impact performance because the size of the address set is already
 *   very small.
 *
 * - The size of the change is equal or bigger than the new size. In this case
 *   it doesn't make sense to incrementally processing the changes because
 *   reprocessing can be faster.
 *
 * - When the address set information couldn't be properly tracked during lflow
 *   parsing. The typical cases are:
 *
 *      - The relational operator to the address set is not '=='. In this case
 *        there is no 1-1 mapping between the addresses and the flows
 *        generated.
 *
 *      - The sub expression of the address set is combined with other sub-
 *        expressions/constants, usually because of disjunctions between
 *        sub-expressions/constants, e.g.:
 *
 *          ip.src == $as1 || ip.dst == $as2
 *          ip.src == {$as1, $as2}
 *          ip.src == {$as1, ip1}
 *
 *        All these could have been split into separate lflows.
 *
 *      - Conjunctions overlapping between lflows, which can be caused by
 *        overlapping address sets or same address set used by multiple lflows
 *        that could have been combined. e.g.:
 *
 *          lflow1: ip.src == $as1 && tcp.dst == {p1, p2}
 *          lflow2: ip.src == $as1 && tcp.dst == {p3, p4}
 *
 *        It could have been combined as:
 *
 *          ip.src == $as1 && tcp.dst == {p1, p2, p3, p4}
 *
 *        Note: addresses additions still can be processed incrementally in
 *        this case, although deletions cannot.
 */
bool
lflow_handle_addr_set_update(const char *as_name,
                             struct addr_set_diff *as_diff,
                             struct lflow_ctx_in *l_ctx_in,
                             struct lflow_ctx_out *l_ctx_out,
                             bool *changed)
{
    ovs_assert(as_diff->added || as_diff->deleted);
    if (!as_update_can_be_handled(as_name, as_diff, l_ctx_in)) {
        return false;
    }

    struct resource_to_objects_node *resource_node =
        objdep_mgr_find_objs(l_ctx_out->lflow_deps_mgr, OBJDEP_TYPE_ADDRSET,
                             as_name);
    if (!resource_node) {
        *changed = false;
        return true;
    }

    *changed = false;

    bool ret = true;
    struct object_to_resources_list_node *resource_list_node;
    RESOURCE_FOR_EACH_OBJ (resource_list_node, resource_node) {
        const struct uuid *obj_uuid = &resource_list_node->obj_uuid;
        if (uuidset_find(l_ctx_out->objs_processed, obj_uuid)) {
            VLOG_DBG("lflow "UUID_FMT"has been processed, skip.",
                     UUID_ARGS(obj_uuid));
            continue;
        }
        const struct sbrec_logical_flow *lflow =
            sbrec_logical_flow_table_get_for_uuid(l_ctx_in->logical_flow_table,
                                                  obj_uuid);
        if (!lflow) {
            /* lflow deletion should be handled in the corresponding input
             * handler, so we can skip here. */
            VLOG_DBG("lflow "UUID_FMT" not found while handling updates of "
                     "address set %s, skip.",
                     UUID_ARGS(obj_uuid), as_name);
            continue;
        }
        *changed = true;

        if (as_diff->deleted) {
            struct addrset_info as_info;
            for (size_t i = 0; i < as_diff->deleted->n_values; i++) {
                union expr_constant *c = &as_diff->deleted->values[i];
                if (!as_info_from_expr_const(as_name, c, &as_info)) {
                    continue;
                }
                if (!ofctrl_remove_flows_for_as_ip(
                        l_ctx_out->flow_table, obj_uuid, &as_info,
                        resource_list_node->ref_count)) {
                    ret = false;
                    goto done;
                }
            }
        }

        if (as_diff->added) {
            if (!consider_lflow_for_added_as_ips(lflow, as_name,
                                                 resource_list_node->ref_count,
                                                 as_diff->added,
                                                 l_ctx_in, l_ctx_out)) {
                ret = false;
                goto done;
            }
        }
    }

done:
    return ret;
}

bool
lflow_handle_changed_ref(enum objdep_type type, const char *res_name,
                         struct ovs_list *objs_todo,
                         const void *in_arg, void *out_arg)
{
    struct lflow_ctx_in *l_ctx_in = CONST_CAST(struct lflow_ctx_in *, in_arg);
    struct lflow_ctx_out *l_ctx_out = out_arg;

    /* Re-parse the related lflows. */
    /* Firstly, flood remove the flows from desired flow table. */
    struct object_to_resources_list_node *resource_list_node_uuid;
    struct uuidset flood_remove_nodes =
        UUIDSET_INITIALIZER(&flood_remove_nodes);
    LIST_FOR_EACH_SAFE (resource_list_node_uuid, list_node, objs_todo) {
        const struct uuid *obj_uuid = &resource_list_node_uuid->obj_uuid;
        VLOG_DBG("Reprocess lflow "UUID_FMT" for resource type: %s,"
                 " name: %s.",
                 UUID_ARGS(obj_uuid), objdep_type_name(type), res_name);
        uuidset_insert(&flood_remove_nodes, obj_uuid);
        free(resource_list_node_uuid);
    }
    ofctrl_flood_remove_flows(l_ctx_out->flow_table, &flood_remove_nodes);

    /* Secondly, for each lflow that is actually removed, reprocessing it. */
    struct uuidset_node *ofrn;
    UUIDSET_FOR_EACH (ofrn, &flood_remove_nodes) {
        objdep_mgr_remove_obj(l_ctx_out->lflow_deps_mgr, &ofrn->uuid);
        lflow_conj_ids_free(l_ctx_out->conj_ids, &ofrn->uuid);

        const struct sbrec_logical_flow *lflow =
            sbrec_logical_flow_table_get_for_uuid(l_ctx_in->logical_flow_table,
                                                  &ofrn->uuid);
        if (!lflow) {
            VLOG_DBG("lflow "UUID_FMT" not found while reprocessing for"
                     " resource type: %s, name: %s.",
                     UUID_ARGS(&ofrn->uuid),
                     objdep_type_name(type), res_name);
            continue;
        }

        /* For the extra lflows that need to be reprocessed because of the
         * flood remove, remove it from objs_processed. */
        struct uuidset_node *unode =
            uuidset_find(l_ctx_out->objs_processed, &lflow->header_.uuid);
        if (unode) {
            VLOG_DBG("lflow "UUID_FMT"has been processed, now reprocess.",
                     UUID_ARGS(&lflow->header_.uuid));
            uuidset_delete(l_ctx_out->objs_processed, unode);
        }

        consider_logical_flow(lflow, false, l_ctx_in, l_ctx_out);
    }
    uuidset_destroy(&flood_remove_nodes);
    return true;
}

static void
lflow_parse_ctrl_meter(const struct sbrec_logical_flow *lflow,
                       struct ovn_extend_table *meter_table,
                       uint32_t *meter_id)
{
    ovs_assert(meter_id);
    *meter_id = NX_CTLR_NO_METER;

    if (lflow->controller_meter) {
        *meter_id = ovn_extend_table_assign_id(meter_table,
                                               lflow->controller_meter,
                                               lflow->header_.uuid);
        if (*meter_id == EXT_TABLE_ID_INVALID) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Unable to assign id for meter: %s",
                         lflow->controller_meter);
            return;
        }
    }
}

static int
get_common_nat_zone(const struct local_datapath *ldp)
{
    /* Normally, the common NAT zone defaults to the DNAT zone. However,
     * if the "snat-ct-zone" is set on the datapath, the user is
     * expecting an explicit CT zone to be used for SNAT. If we default
     * to the DNAT zone, then it means SNAT will not use the configured
     * value. The way we get around this is to use the SNAT zone as the
     * common zone if "snat-ct-zone" is set.
     */
    if (smap_get(&ldp->datapath->external_ids, "snat-ct-zone")) {
        return MFF_LOG_SNAT_ZONE;
    } else {
        return MFF_LOG_DNAT_ZONE;
    }
}

static void
add_matches_to_flow_table(const struct sbrec_logical_flow *lflow,
                          const struct local_datapath *ldp,
                          struct hmap *matches, uint8_t ptable,
                          uint8_t output_ptable, struct ofpbuf *ovnacts,
                          bool ingress, struct lflow_ctx_in *l_ctx_in,
                          struct lflow_ctx_out *l_ctx_out)
{
    struct lookup_port_aux aux = {
        .sbrec_multicast_group_by_name_datapath
            = l_ctx_in->sbrec_multicast_group_by_name_datapath,
        .sbrec_port_binding_by_name = l_ctx_in->sbrec_port_binding_by_name,
        .dp = ldp->datapath,
        .lflow = lflow,
        .deps_mgr = l_ctx_out->lflow_deps_mgr,
        .chassis_tunnels = l_ctx_in->chassis_tunnels,
    };

    /* Parse any meter to be used if this flow should punt packets to
     * controller.
     */
    uint32_t ctrl_meter_id = NX_CTLR_NO_METER;
    lflow_parse_ctrl_meter(lflow, l_ctx_out->meter_table,
                           &ctrl_meter_id);

    /* Encode OVN logical actions into OpenFlow. */
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    struct ovnact_encode_params ep = {
        .lookup_port = lookup_port_cb,
        .tunnel_ofport = tunnel_ofport_cb,
        .aux = &aux,
        .is_switch = ldp->is_switch,
        .group_table = l_ctx_out->group_table,
        .meter_table = l_ctx_out->meter_table,
        .collector_ids = l_ctx_in->collector_ids,
        .lflow_uuid = lflow->header_.uuid,
        .dp_key = ldp->datapath->tunnel_key,

        .pipeline = ingress ? OVNACT_P_INGRESS : OVNACT_P_EGRESS,
        .ingress_ptable = OFTABLE_LOG_INGRESS_PIPELINE,
        .egress_ptable = OFTABLE_LOG_EGRESS_PIPELINE,
        .output_ptable = output_ptable,
        .mac_bind_ptable = OFTABLE_MAC_BINDING,
        .mac_lookup_ptable = OFTABLE_MAC_LOOKUP,
        .lb_hairpin_ptable = OFTABLE_CHK_LB_HAIRPIN,
        .lb_hairpin_reply_ptable = OFTABLE_CHK_LB_HAIRPIN_REPLY,
        .ct_snat_vip_ptable = OFTABLE_CT_SNAT_HAIRPIN,
        .fdb_ptable = OFTABLE_GET_FDB,
        .fdb_lookup_ptable = OFTABLE_LOOKUP_FDB,
        .in_port_sec_ptable = OFTABLE_CHK_IN_PORT_SEC,
        .out_port_sec_ptable = OFTABLE_CHK_OUT_PORT_SEC,
        .ctrl_meter_id = ctrl_meter_id,
        .common_nat_ct_zone = get_common_nat_zone(ldp),
    };
    ovnacts_encode(ovnacts->data, ovnacts->size, &ep, &ofpacts);

    struct expr_match *m;
    HMAP_FOR_EACH (m, hmap_node, matches) {
        match_set_metadata(&m->match, htonll(ldp->datapath->tunnel_key));
        if (ldp->is_switch) {
            unsigned int reg_index
                = (ingress ? MFF_LOG_INPORT : MFF_LOG_OUTPORT) - MFF_REG0;
            int64_t port_id = m->match.flow.regs[reg_index];
            if (port_id) {
                int64_t dp_id = ldp->datapath->tunnel_key;
                char buf[16];
                get_unique_lport_key(dp_id, port_id, buf, sizeof(buf));
                if (!sset_contains(l_ctx_in->related_lport_ids, buf)) {
                    VLOG_DBG("lflow "UUID_FMT
                             " port %s in match is not local, skip",
                             UUID_ARGS(&lflow->header_.uuid),
                             buf);
                    continue;
                }
            }
        }

        struct addrset_info as_info = {
            .name = m->as_name,
            .ip = m->as_ip,
            .mask = m->as_mask
        };
        if (!m->n) {
            ofctrl_add_flow_metered(l_ctx_out->flow_table, ptable,
                                    lflow->priority,
                                    lflow->header_.uuid.parts[0], &m->match,
                                    &ofpacts, &lflow->header_.uuid,
                                    ctrl_meter_id,
                                    as_info.name ? &as_info : NULL);
        } else {
            if (m->n > 1) {
                ovs_assert(!as_info.name);
            }
            uint64_t conj_stubs[64 / 8];
            struct ofpbuf conj;

            ofpbuf_use_stub(&conj, conj_stubs, sizeof conj_stubs);
            for (int i = 0; i < m->n; i++) {
                const struct cls_conjunction *src = &m->conjunctions[i];
                struct ofpact_conjunction *dst;

                dst = ofpact_put_CONJUNCTION(&conj);
                dst->id = src->id;
                dst->clause = src->clause;
                dst->n_clauses = src->n_clauses;
            }

            ofctrl_add_or_append_flow(l_ctx_out->flow_table, ptable,
                                      lflow->priority, 0,
                                      &m->match, &conj, &lflow->header_.uuid,
                                      ctrl_meter_id,
                                      as_info.name ? &as_info : NULL);
            ofpbuf_uninit(&conj);
        }
    }

    ofpbuf_uninit(&ofpacts);
}

/* Converts the match and returns the simplified expr tree.
 *
 * The caller should evaluate the conditions and normalize the expr tree.
 * If parsing is successful, '*prereqs' is also consumed.
 */
static struct expr *
convert_match_to_expr(const struct sbrec_logical_flow *lflow,
                      const struct local_datapath *ldp,
                      struct expr **prereqs,
                      const struct shash *addr_sets,
                      const struct shash *port_groups,
                      const struct smap *template_vars,
                      struct sset *template_vars_ref,
                      struct objdep_mgr *mgr,
                      bool *pg_addr_set_ref)
{
    struct shash addr_sets_ref = SHASH_INITIALIZER(&addr_sets_ref);
    struct sset port_groups_ref = SSET_INITIALIZER(&port_groups_ref);
    char *error = NULL;

    struct lex_str match_s = lexer_parse_template_string(lflow->match,
                                                         template_vars,
                                                         template_vars_ref);
    struct expr *e = expr_parse_string(lex_str_get(&match_s), &symtab,
                                       addr_sets, port_groups, &addr_sets_ref,
                                       &port_groups_ref,
                                       ldp->datapath->tunnel_key,
                                       &error);
    lex_str_free(&match_s);

    struct shash_node *addr_sets_ref_node;
    SHASH_FOR_EACH (addr_sets_ref_node, &addr_sets_ref) {
        objdep_mgr_add_with_refcount(mgr, OBJDEP_TYPE_ADDRSET,
                                     addr_sets_ref_node->name,
                                     &lflow->header_.uuid,
                                     *(size_t *) addr_sets_ref_node->data);
    }
    const char *port_group_name;
    SSET_FOR_EACH (port_group_name, &port_groups_ref) {
        objdep_mgr_add(mgr, OBJDEP_TYPE_PORTGROUP, port_group_name,
                       &lflow->header_.uuid);
    }

    if (pg_addr_set_ref) {
        *pg_addr_set_ref = (!sset_is_empty(&port_groups_ref) ||
                            !shash_is_empty(&addr_sets_ref));
    }
    shash_destroy_free_data(&addr_sets_ref);
    sset_destroy(&port_groups_ref);

    if (!error) {
        if (*prereqs) {
            e = expr_combine(EXPR_T_AND, e, *prereqs);
            *prereqs = NULL;
        }
        e = expr_annotate(e, &symtab, &error);
    }
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "error parsing match \"%s\": %s",
                    lflow->match, error);
        expr_destroy(e);
        free(error);
        return NULL;
    }

    return expr_simplify(e);
}

static void
consider_logical_flow__(const struct sbrec_logical_flow *lflow,
                        const struct sbrec_datapath_binding *dp,
                        struct lflow_ctx_in *l_ctx_in,
                        struct lflow_ctx_out *l_ctx_out)
{
    struct local_datapath *ldp = get_local_datapath(l_ctx_in->local_datapaths,
                                                    dp->tunnel_key);
    if (!ldp) {
        VLOG_DBG("Skip lflow "UUID_FMT" for non-local datapath %"PRId64,
                 UUID_ARGS(&lflow->header_.uuid), dp->tunnel_key);
        return;
    }

    const char *io_port = smap_get(&lflow->tags, "in_out_port");
    if (io_port) {
        objdep_mgr_add(l_ctx_out->lflow_deps_mgr, OBJDEP_TYPE_PORTBINDING,
                       io_port, &lflow->header_.uuid);
        const struct sbrec_port_binding *pb
            = lport_lookup_by_name(l_ctx_in->sbrec_port_binding_by_name,
                                   io_port);
        if (!pb) {
            VLOG_DBG("lflow "UUID_FMT" matches inport/outport %s that's not "
                     "found, skip", UUID_ARGS(&lflow->header_.uuid), io_port);
            return;
        }
        char buf[16];
        get_unique_lport_key(dp->tunnel_key, pb->tunnel_key, buf, sizeof buf);
        if (!sset_contains(l_ctx_in->related_lport_ids, buf)) {
            VLOG_DBG("lflow "UUID_FMT" matches inport/outport %s that's not "
                     "local, skip", UUID_ARGS(&lflow->header_.uuid), io_port);
            return;
        }
    }

    /* Determine translation of logical table IDs to physical table IDs. */
    bool ingress = !strcmp(lflow->pipeline, "ingress");

    /* Determine translation of logical table IDs to physical table IDs. */
    uint8_t first_ptable = (ingress
                            ? OFTABLE_LOG_INGRESS_PIPELINE
                            : OFTABLE_LOG_EGRESS_PIPELINE);
    uint8_t ptable = first_ptable + lflow->table_id;
    uint8_t output_ptable = (ingress
                             ? OFTABLE_OUTPUT_INIT
                             : OFTABLE_SAVE_INPORT);

    /* Parse OVN logical actions.
     *
     * XXX Deny changes to 'outport' in egress pipeline. */
    uint64_t ovnacts_stub[1024 / 8];
    struct ofpbuf ovnacts = OFPBUF_STUB_INITIALIZER(ovnacts_stub);
    struct sset template_vars_ref = SSET_INITIALIZER(&template_vars_ref);
    struct expr *prereqs = NULL;

    if (!lflow_parse_actions(lflow, l_ctx_in, &template_vars_ref,
                             &ovnacts, &prereqs)) {
        ovnacts_free(ovnacts.data, ovnacts.size);
        ofpbuf_uninit(&ovnacts);
        store_lflow_template_refs(l_ctx_out->lflow_deps_mgr,
                                  &template_vars_ref, lflow);
        sset_destroy(&template_vars_ref);
        return;
    }

    struct lookup_port_aux aux = {
        .sbrec_multicast_group_by_name_datapath
            = l_ctx_in->sbrec_multicast_group_by_name_datapath,
        .sbrec_port_binding_by_name = l_ctx_in->sbrec_port_binding_by_name,
        .dp = dp,
        .lflow = lflow,
        .deps_mgr = l_ctx_out->lflow_deps_mgr,
    };
    struct condition_aux cond_aux = {
        .sbrec_port_binding_by_name = l_ctx_in->sbrec_port_binding_by_name,
        .dp = dp,
        .chassis = l_ctx_in->chassis,
        .active_tunnels = l_ctx_in->active_tunnels,
        .lflow = lflow,
        .deps_mgr = l_ctx_out->lflow_deps_mgr,
    };

    struct lflow_cache_value *lcv =
        lflow_cache_get(l_ctx_out->lflow_cache, &lflow->header_.uuid);
    enum lflow_cache_type lcv_type =
        lcv ? lcv->type : LCACHE_T_NONE;

    struct expr *cached_expr = NULL, *expr = NULL;
    struct hmap *matches = NULL;
    size_t matches_size = 0;

    bool pg_addr_set_ref = false;

    if (lcv_type == LCACHE_T_MATCHES
        && lcv->n_conjs
        && !lflow_conj_ids_alloc_specified(l_ctx_out->conj_ids,
                                           &lflow->header_.uuid,
                                           &dp->header_.uuid,
                                           lcv->conj_id_ofs, lcv->n_conjs)) {
        /* This should happen very rarely. */
        VLOG_DBG("lflow "UUID_FMT" match cached with conjunctions, but the"
                 " cached ids are not available anymore. Drop the cache.",
                 UUID_ARGS(&lflow->header_.uuid));
        lflow_cache_delete(l_ctx_out->lflow_cache, &lflow->header_.uuid);
        lcv_type = LCACHE_T_NONE;
    }

    /* Get match expr, either from cache or from lflow match. */
    switch (lcv_type) {
    case LCACHE_T_NONE:
        expr = convert_match_to_expr(lflow, ldp, &prereqs, l_ctx_in->addr_sets,
                                     l_ctx_in->port_groups,
                                     l_ctx_in->template_vars,
                                     &template_vars_ref,
                                     l_ctx_out->lflow_deps_mgr,
                                     &pg_addr_set_ref);
        if (!expr) {
            goto done;
        }
        break;
    case LCACHE_T_EXPR:
        expr = expr_clone(lcv->expr);
        break;
    case LCACHE_T_MATCHES:
        break;
    }

    /* If caching is enabled and this is a not cached expr that doesn't refer
     * to address sets, port groups, or template variables, save it to
     * potentially cache it later.
     */
    if (lcv_type == LCACHE_T_NONE
            && lflow_cache_is_enabled(l_ctx_out->lflow_cache)
            && !pg_addr_set_ref
            && sset_is_empty(&template_vars_ref)) {
        cached_expr = expr_clone(expr);
    }

    /* Normalize expression if needed. */
    switch (lcv_type) {
    case LCACHE_T_NONE:
    case LCACHE_T_EXPR:
        expr = expr_evaluate_condition(expr, is_chassis_resident_cb,
                                       &cond_aux);
        expr = expr_normalize(expr);
        break;
    case LCACHE_T_MATCHES:
        break;
    }

    /* Get matches, either from cache or from expr computed above. */
    uint32_t start_conj_id = 0;
    uint32_t n_conjs = 0;
    switch (lcv_type) {
    case LCACHE_T_NONE:
    case LCACHE_T_EXPR:
        matches = xmalloc(sizeof *matches);
        n_conjs = expr_to_matches(expr, lookup_port_cb, &aux, matches);
        if (hmap_is_empty(matches)) {
            VLOG_DBG("lflow "UUID_FMT" matches are empty, skip",
                     UUID_ARGS(&lflow->header_.uuid));
            goto done;
        }
        if (n_conjs) {
            start_conj_id = lflow_conj_ids_alloc(l_ctx_out->conj_ids,
                                                 &lflow->header_.uuid,
                                                 &dp->header_.uuid,
                                                 n_conjs);
            if (!start_conj_id) {
                VLOG_ERR("32-bit conjunction ids exhausted!");
                goto done;
            }
            matches_size = expr_matches_prepare(matches, start_conj_id - 1);
        }
        break;
    case LCACHE_T_MATCHES:
        matches = lcv->expr_matches;
        break;
    }

    add_matches_to_flow_table(lflow, ldp, matches, ptable, output_ptable,
                              &ovnacts, ingress, l_ctx_in, l_ctx_out);

    /* Update cache if needed. */
    switch (lcv_type) {
    case LCACHE_T_NONE:
        /* Cache new entry if caching is enabled. */
        if (lflow_cache_is_enabled(l_ctx_out->lflow_cache)) {
            if (cached_expr
                && !objdep_mgr_contains_obj(l_ctx_out->lflow_deps_mgr,
                                            &lflow->header_.uuid)) {
                lflow_cache_add_matches(l_ctx_out->lflow_cache,
                                        &lflow->header_.uuid, start_conj_id,
                                        n_conjs, matches, matches_size);
                matches = NULL;
            } else if (cached_expr) {
                lflow_cache_add_expr(l_ctx_out->lflow_cache,
                                     &lflow->header_.uuid,
                                     cached_expr, expr_size(cached_expr));
                cached_expr = NULL;
            }
        }
        break;
    case LCACHE_T_EXPR:
        break;
    case LCACHE_T_MATCHES:
        /* Cached matches were used, don't destroy them. */
        matches = NULL;
        break;
    }

done:
    expr_destroy(prereqs);
    ovnacts_free(ovnacts.data, ovnacts.size);
    ofpbuf_uninit(&ovnacts);
    expr_destroy(expr);
    expr_destroy(cached_expr);
    expr_matches_destroy(matches);
    free(matches);

    store_lflow_template_refs(l_ctx_out->lflow_deps_mgr,
                              &template_vars_ref, lflow);
    sset_destroy(&template_vars_ref);
}

static void
consider_logical_flow(const struct sbrec_logical_flow *lflow,
                      bool is_recompute,
                      struct lflow_ctx_in *l_ctx_in,
                      struct lflow_ctx_out *l_ctx_out)
{
    const struct sbrec_logical_dp_group *dp_group = lflow->logical_dp_group;
    const struct sbrec_datapath_binding *dp = lflow->logical_datapath;

    if (!dp_group && !dp) {
        VLOG_DBG("lflow "UUID_FMT" has no datapath binding, skip",
                 UUID_ARGS(&lflow->header_.uuid));
        return;
    }
    ovs_assert(!dp_group || !dp);

    COVERAGE_INC(consider_logical_flow);
    if (!is_recompute) {
        ovs_assert(!uuidset_find(l_ctx_out->objs_processed,
                                 &lflow->header_.uuid));
        uuidset_insert(l_ctx_out->objs_processed, &lflow->header_.uuid);
    }

    if (dp) {
        consider_logical_flow__(lflow, dp, l_ctx_in, l_ctx_out);
        return;
    }
    for (size_t i = 0; dp_group && i < dp_group->n_datapaths; i++) {
        consider_logical_flow__(lflow, dp_group->datapaths[i],
                                l_ctx_in, l_ctx_out);
    }
}

static void
put_load(const uint8_t *data, size_t len,
         enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts,
                                                       mf_from_id(dst), NULL,
                                                       NULL);
    bitwise_copy(data, len, 0, sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(ofpact_set_field_mask(sf), sf->field->n_bytes, ofs, n_bits);
}

static void
put_load64(uint64_t value, enum mf_field_id dst, int ofs, int n_bits,
           struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts,
                                                       mf_from_id(dst), NULL,
                                                       NULL);
    ovs_be64 n_value = htonll(value);
    bitwise_copy(&n_value, 8, 0, sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(ofpact_set_field_mask(sf), sf->field->n_bytes, ofs, n_bits);
}

static void
consider_neighbor_flow(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                       const struct hmap *local_datapaths,
                       const struct sbrec_mac_binding *b,
                       const struct sbrec_static_mac_binding *smb,
                       struct ovn_desired_flow_table *flow_table,
                       uint16_t priority)
{
    if (!b && !smb) {
        return;
    }

    char *logical_port = b ? b->logical_port : smb->logical_port;
    char *ip = b ? b->ip : smb->ip;
    char *mac = b ? b->mac : smb->mac;

    const struct sbrec_port_binding *pb
        = lport_lookup_by_name(sbrec_port_binding_by_name, logical_port);
    if (!pb || !get_local_datapath(local_datapaths,
                                   pb->datapath->tunnel_key)) {
        return;
    }

    struct eth_addr mac_addr;
    if (!eth_addr_from_string(mac, &mac_addr)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad 'mac' %s", mac);
        return;
    }

    struct match get_arp_match = MATCH_CATCHALL_INITIALIZER;
    struct match lookup_arp_match = MATCH_CATCHALL_INITIALIZER;

    if (strchr(ip, '.')) {
        ovs_be32 ip_addr;
        if (!ip_parse(ip, &ip_addr)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad 'ip' %s", ip);
            return;
        }
        match_set_reg(&get_arp_match, 0, ntohl(ip_addr));
        match_set_reg(&lookup_arp_match, 0, ntohl(ip_addr));
        match_set_dl_type(&lookup_arp_match, htons(ETH_TYPE_ARP));
    } else {
        struct in6_addr ip6;
        if (!ipv6_parse(ip, &ip6)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad 'ip' %s", ip);
            return;
        }
        ovs_be128 value;
        memcpy(&value, &ip6, sizeof(value));
        match_set_xxreg(&get_arp_match, 0, ntoh128(value));

        match_set_xxreg(&lookup_arp_match, 0, ntoh128(value));
        match_set_dl_type(&lookup_arp_match, htons(ETH_TYPE_IPV6));
        match_set_nw_proto(&lookup_arp_match, 58);
        match_set_icmp_code(&lookup_arp_match, 0);
    }

    match_set_metadata(&get_arp_match, htonll(pb->datapath->tunnel_key));
    match_set_reg(&get_arp_match, MFF_LOG_OUTPORT - MFF_REG0, pb->tunnel_key);

    match_set_metadata(&lookup_arp_match, htonll(pb->datapath->tunnel_key));
    match_set_reg(&lookup_arp_match, MFF_LOG_INPORT - MFF_REG0,
                  pb->tunnel_key);

    uint64_t stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);
    uint8_t value = 1;
    put_load(mac_addr.ea, sizeof mac_addr.ea, MFF_ETH_DST, 0, 48, &ofpacts);
    put_load(&value, sizeof value, MFF_LOG_FLAGS, MLF_LOOKUP_MAC_BIT, 1,
             &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_MAC_BINDING, priority,
                    b ? b->header_.uuid.parts[0] : smb->header_.uuid.parts[0],
                    &get_arp_match, &ofpacts,
                    b ? &b->header_.uuid : &smb->header_.uuid);

    ofpbuf_clear(&ofpacts);
    put_load(&value, sizeof value, MFF_LOG_FLAGS, MLF_LOOKUP_MAC_BIT, 1,
             &ofpacts);
    match_set_dl_src(&lookup_arp_match, mac_addr);
    ofctrl_add_flow(flow_table, OFTABLE_MAC_LOOKUP, priority,
                    b ? b->header_.uuid.parts[0] : smb->header_.uuid.parts[0],
                    &lookup_arp_match, &ofpacts,
                    b ? &b->header_.uuid : &smb->header_.uuid);

    ofpbuf_uninit(&ofpacts);
}

/* Adds an OpenFlow flow to flow tables for each MAC binding in the OVN
 * southbound database. */
static void
add_neighbor_flows(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                   const struct sbrec_mac_binding_table *mac_binding_table,
                   const struct sbrec_static_mac_binding_table *smb_table,
                   const struct hmap *local_datapaths,
                   struct ovn_desired_flow_table *flow_table)
{
    /* Add flows for learnt MAC bindings */
    const struct sbrec_mac_binding *b;
    SBREC_MAC_BINDING_TABLE_FOR_EACH (b, mac_binding_table) {
        consider_neighbor_flow(sbrec_port_binding_by_name, local_datapaths,
                               b, NULL, flow_table, 100);
    }

    /* Add flows for statically configured MAC bindings */
    const struct sbrec_static_mac_binding *smb;
    SBREC_STATIC_MAC_BINDING_TABLE_FOR_EACH (smb, smb_table) {
        consider_neighbor_flow(sbrec_port_binding_by_name, local_datapaths,
                               NULL, smb, flow_table,
                               smb->override_dynamic_mac ? 150 : 50);
    }
}

/* Builds the "learn()" action to be triggered by packets initiating a
 * hairpin session.
 *
 * This will generate flows in table OFTABLE_CHK_LB_HAIRPIN_REPLY of the form:
 * - match:
 *     metadata=<orig-pkt-metadata>,ip/ipv6,ip.src=<backend>,ip.dst=<vip>
 *     nw_proto='lb_proto',tp_src_port=<backend-port>
 * - action:
 *     set MLF_LOOKUP_LB_HAIRPIN_BIT=1
 */
static void
add_lb_vip_hairpin_reply_action(struct in6_addr *vip6, ovs_be32 vip,
                                uint8_t lb_proto, bool has_l4_port,
                                uint64_t cookie, struct ofpbuf *ofpacts)
{
    struct match match = MATCH_CATCHALL_INITIALIZER;
    size_t ol_offset = ofpacts->size;
    struct ofpact_learn *ol = ofpact_put_LEARN(ofpacts);
    struct ofpact_learn_spec *ol_spec;
    unsigned int imm_bytes;
    uint8_t *src_imm;

    /* Once learned, hairpin reply flows are permanent until the VIP/backend
     * is removed.
     */
    ol->flags = NX_LEARN_F_DELETE_LEARNED;
    ol->idle_timeout = OFP_FLOW_PERMANENT;
    ol->hard_timeout = OFP_FLOW_PERMANENT;
    ol->priority = OFP_DEFAULT_PRIORITY;
    ol->table_id = OFTABLE_CHK_LB_HAIRPIN_REPLY;
    ol->cookie = htonll(cookie);

    /* Match on metadata of the packet that created the hairpin session. */
    ol_spec = ofpbuf_put_zeros(ofpacts, sizeof *ol_spec);

    ol_spec->dst.field = mf_from_id(MFF_METADATA);
    ol_spec->dst.ofs = 0;
    ol_spec->dst.n_bits = ol_spec->dst.field->n_bits;
    ol_spec->n_bits = ol_spec->dst.n_bits;
    ol_spec->dst_type = NX_LEARN_DST_MATCH;
    ol_spec->src_type = NX_LEARN_SRC_FIELD;
    ol_spec->src.field = mf_from_id(MFF_METADATA);

    /* Match on the same ETH type as the packet that created the hairpin
     * session.
     */
    ol_spec = ofpbuf_put_zeros(ofpacts, sizeof *ol_spec);
    ol_spec->dst.field = mf_from_id(MFF_ETH_TYPE);
    ol_spec->dst.ofs = 0;
    ol_spec->dst.n_bits = ol_spec->dst.field->n_bits;
    ol_spec->n_bits = ol_spec->dst.n_bits;
    ol_spec->dst_type = NX_LEARN_DST_MATCH;
    ol_spec->src_type = NX_LEARN_SRC_IMMEDIATE;
    union mf_value imm_eth_type = {
        .be16 = !vip6 ? htons(ETH_TYPE_IP) : htons(ETH_TYPE_IPV6)
    };
    mf_write_subfield_value(&ol_spec->dst, &imm_eth_type, &match);

    /* Push value last, as this may reallocate 'ol_spec'. */
    imm_bytes = DIV_ROUND_UP(ol_spec->dst.n_bits, 8);
    src_imm = ofpbuf_put_zeros(ofpacts, OFPACT_ALIGN(imm_bytes));
    memcpy(src_imm, &imm_eth_type, imm_bytes);

    /* Hairpin replies have ip.src == <backend-ip>. */
    ol_spec = ofpbuf_put_zeros(ofpacts, sizeof *ol_spec);
    if (!vip6) {
        ol_spec->dst.field = mf_from_id(MFF_IPV4_SRC);
        ol_spec->src.field = mf_from_id(MFF_IPV4_SRC);
    } else {
        ol_spec->dst.field = mf_from_id(MFF_IPV6_SRC);
        ol_spec->src.field = mf_from_id(MFF_IPV6_SRC);
    }
    ol_spec->dst.ofs = 0;
    ol_spec->dst.n_bits = ol_spec->dst.field->n_bits;
    ol_spec->n_bits = ol_spec->dst.n_bits;
    ol_spec->dst_type = NX_LEARN_DST_MATCH;
    ol_spec->src_type = NX_LEARN_SRC_FIELD;

    /* Hairpin replies have ip.dst == <vip>. */
    union mf_value imm_ip;
    ol_spec = ofpbuf_put_zeros(ofpacts, sizeof *ol_spec);
    if (!vip6) {
        ol_spec->dst.field = mf_from_id(MFF_IPV4_DST);
        imm_ip = (union mf_value) {
            .be32 = vip
        };
    } else {
        ol_spec->dst.field = mf_from_id(MFF_IPV6_DST);
        imm_ip = (union mf_value) {
            .ipv6 = *vip6
        };
    }
    ol_spec->dst.ofs = 0;
    ol_spec->dst.n_bits = ol_spec->dst.field->n_bits;
    ol_spec->n_bits = ol_spec->dst.n_bits;
    ol_spec->dst_type = NX_LEARN_DST_MATCH;
    ol_spec->src_type = NX_LEARN_SRC_IMMEDIATE;
    mf_write_subfield_value(&ol_spec->dst, &imm_ip, &match);

    /* Push value last, as this may reallocate 'ol_spec' */
    imm_bytes = DIV_ROUND_UP(ol_spec->dst.n_bits, 8);
    src_imm = ofpbuf_put_zeros(ofpacts, OFPACT_ALIGN(imm_bytes));
    memcpy(src_imm, &imm_ip, imm_bytes);

    /* Hairpin replies have the same nw_proto as packets that created the
     * session.
     */
    ol_spec = ofpbuf_put_zeros(ofpacts, sizeof *ol_spec);
    ol_spec->dst.field = mf_from_id(MFF_IP_PROTO);
    ol_spec->src.field = mf_from_id(MFF_IP_PROTO);
    ol_spec->dst.ofs = 0;
    ol_spec->dst.n_bits = ol_spec->dst.field->n_bits;
    ol_spec->n_bits = ol_spec->dst.n_bits;
    ol_spec->dst_type = NX_LEARN_DST_MATCH;

    /* Hairpin replies have source port == <backend-port>. */
    if (has_l4_port) {
        union mf_value imm_proto = {
            .u8 = lb_proto,
        };

        ol_spec->src_type = NX_LEARN_SRC_IMMEDIATE;
        mf_write_subfield_value(&ol_spec->dst, &imm_proto, &match);

        /* Push value last, as this may reallocate 'ol_spec' */
        imm_bytes = DIV_ROUND_UP(ol_spec->dst.n_bits, 8);
        src_imm = ofpbuf_put_zeros(ofpacts, OFPACT_ALIGN(imm_bytes));
        memcpy(src_imm, &imm_proto, imm_bytes);

        ol_spec = ofpbuf_put_zeros(ofpacts, sizeof *ol_spec);
        switch (lb_proto) {
        case IPPROTO_TCP:
            ol_spec->dst.field = mf_from_id(MFF_TCP_SRC);
            ol_spec->src.field = mf_from_id(MFF_TCP_DST);
            break;
        case IPPROTO_UDP:
            ol_spec->dst.field = mf_from_id(MFF_UDP_SRC);
            ol_spec->src.field = mf_from_id(MFF_UDP_DST);
            break;
        case IPPROTO_SCTP:
            ol_spec->dst.field = mf_from_id(MFF_SCTP_SRC);
            ol_spec->src.field = mf_from_id(MFF_SCTP_DST);
            break;
        default:
            OVS_NOT_REACHED();
            break;
        }
        ol_spec->dst.ofs = 0;
        ol_spec->dst.n_bits = ol_spec->dst.field->n_bits;
        ol_spec->n_bits = ol_spec->dst.n_bits;
        ol_spec->dst_type = NX_LEARN_DST_MATCH;
        ol_spec->src_type = NX_LEARN_SRC_FIELD;
    } else {
        ol_spec->src_type = NX_LEARN_SRC_FIELD;
    }

    /* Set MLF_LOOKUP_LB_HAIRPIN_BIT for hairpin replies. */
    ol_spec = ofpbuf_put_zeros(ofpacts, sizeof *ol_spec);
    ol_spec->dst.field = mf_from_id(MFF_LOG_FLAGS);
    ol_spec->dst.ofs = MLF_LOOKUP_LB_HAIRPIN_BIT;
    ol_spec->dst.n_bits = 1;
    ol_spec->n_bits = ol_spec->dst.n_bits;
    ol_spec->dst_type = NX_LEARN_DST_LOAD;
    ol_spec->src_type = NX_LEARN_SRC_IMMEDIATE;
    union mf_value imm_reg_value = {
        .u8 = 1
    };
    mf_write_subfield_value(&ol_spec->dst, &imm_reg_value, &match);

    /* Push value last, as this may reallocate 'ol_spec' */
    imm_bytes = DIV_ROUND_UP(ol_spec->dst.n_bits, 8);
    src_imm = ofpbuf_put_zeros(ofpacts, OFPACT_ALIGN(imm_bytes));
    memcpy(src_imm, &imm_reg_value, imm_bytes);

    /* Reload ol pointer since ofpacts buffer can be reallocated. */
    ol = ofpbuf_at_assert(ofpacts, ol_offset, sizeof *ol);
    ofpact_finish_LEARN(ofpacts, &ol);
}

/* Adds flows to detect hairpin sessions.
 *
 * For backwards compatibilty with older ovn-northd versions, uses
 * ct_nw_dst(), ct_ipv6_dst(), ct_tp_dst(), otherwise uses the
 * original destination tuple stored by ovn-northd.
 */
static void
add_lb_vip_hairpin_flows(const struct ovn_controller_lb *lb,
                         struct ovn_lb_vip *lb_vip,
                         struct ovn_lb_backend *lb_backend,
                         bool use_ct_mark,
                         struct ovn_desired_flow_table *flow_table)
{
    uint64_t stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);
    struct match hairpin_match = MATCH_CATCHALL_INITIALIZER;

    uint8_t value = 1;
    put_load(&value, sizeof value, MFF_LOG_FLAGS,
             MLF_LOOKUP_LB_HAIRPIN_BIT, 1, &ofpacts);

    /* Matching on ct_nw_dst()/ct_ipv6_dst()/ct_tp_dst() requires matching
     * on ct_state first.
     */
    if (!lb->hairpin_orig_tuple) {
        uint32_t ct_state = OVS_CS_F_TRACKED | OVS_CS_F_DST_NAT;
        match_set_ct_state_masked(&hairpin_match, ct_state, ct_state);
    }

    if (IN6_IS_ADDR_V4MAPPED(&lb_vip->vip)) {
        ovs_be32 bip4 = in6_addr_get_mapped_ipv4(&lb_backend->ip);
        ovs_be32 vip4 = in6_addr_get_mapped_ipv4(&lb_vip->vip);
        ovs_be32 snat_vip4 = lb->hairpin_snat_ips.n_ipv4_addrs
                        ? lb->hairpin_snat_ips.ipv4_addrs[0].addr
                        : vip4;

        match_set_dl_type(&hairpin_match, htons(ETH_TYPE_IP));
        match_set_nw_src(&hairpin_match, bip4);
        match_set_nw_dst(&hairpin_match, bip4);

        if (!lb->hairpin_orig_tuple) {
            match_set_ct_nw_dst(&hairpin_match, vip4);
        } else {
            match_set_reg(&hairpin_match,
                          MFF_LOG_LB_ORIG_DIP_IPV4 - MFF_LOG_REG0,
                          ntohl(vip4));
        }

        add_lb_vip_hairpin_reply_action(NULL, snat_vip4, lb->proto,
                                        lb_backend->port,
                                        lb->slb->header_.uuid.parts[0],
                                        &ofpacts);
    } else {
        struct in6_addr *bip6 = &lb_backend->ip;
        struct in6_addr *snat_vip6 =
            lb->hairpin_snat_ips.n_ipv6_addrs
            ? &lb->hairpin_snat_ips.ipv6_addrs[0].addr
            : &lb_vip->vip;
        match_set_dl_type(&hairpin_match, htons(ETH_TYPE_IPV6));
        match_set_ipv6_src(&hairpin_match, bip6);
        match_set_ipv6_dst(&hairpin_match, bip6);

        if (!lb->hairpin_orig_tuple) {
            match_set_ct_ipv6_dst(&hairpin_match, &lb_vip->vip);
        } else {
            ovs_be128 vip6_value;

            memcpy(&vip6_value, &lb_vip->vip, sizeof vip6_value);
            match_set_xxreg(&hairpin_match,
                            MFF_LOG_LB_ORIG_DIP_IPV6 - MFF_LOG_XXREG0,
                            ntoh128(vip6_value));
        }

        add_lb_vip_hairpin_reply_action(snat_vip6, 0, lb->proto,
                                        lb_backend->port,
                                        lb->slb->header_.uuid.parts[0],
                                        &ofpacts);
    }

    if (lb_backend->port) {
        match_set_nw_proto(&hairpin_match, lb->proto);
        match_set_tp_dst(&hairpin_match, htons(lb_backend->port));
        if (!lb->hairpin_orig_tuple) {
            match_set_ct_nw_proto(&hairpin_match, lb->proto);
            match_set_ct_tp_dst(&hairpin_match, htons(lb_vip->vip_port));
        } else {
            match_set_reg_masked(&hairpin_match,
                                 MFF_LOG_LB_ORIG_TP_DPORT - MFF_REG0,
                                 lb_vip->vip_port, UINT16_MAX);
        }
    }

    /* In the original direction, only match on traffic that was already
     * load balanced, i.e., "ct.natted == 1".  Also, it's good enough
     * to not include the datapath tunnel_key in the match when determining
     * that a packet needs to be hairpinned because the rest of the match is
     * restrictive enough:
     * - traffic must have already been load balanced.
     * - packets must have ip.src == ip.dst at this point.
     * - the destination protocol and port must be of a valid backend that
     *   has the same IP as ip.dst.
     *
     * During upgrades logical flows might still use the old way of storing
     * ct.natted in ct_label.  For backwards compatibility, only use ct_mark
     * if ovn-northd notified ovn-controller to do that.
     */
    if (use_ct_mark) {
        uint32_t lb_ct_mark = OVN_CT_NATTED;
        match_set_ct_mark_masked(&hairpin_match, lb_ct_mark, lb_ct_mark);

        ofctrl_add_flow(flow_table, OFTABLE_CHK_LB_HAIRPIN, 100,
                        lb->slb->header_.uuid.parts[0], &hairpin_match,
                        &ofpacts, &lb->slb->header_.uuid);
    } else {
        match_set_ct_mark_masked(&hairpin_match, 0, 0);
        ovs_u128 lb_ct_label = {
            .u64.lo = OVN_CT_NATTED,
        };
        match_set_ct_label_masked(&hairpin_match, lb_ct_label, lb_ct_label);

        ofctrl_add_flow(flow_table, OFTABLE_CHK_LB_HAIRPIN, 100,
                        lb->slb->header_.uuid.parts[0], &hairpin_match,
                        &ofpacts, &lb->slb->header_.uuid);
    }

    ofpbuf_uninit(&ofpacts);
}

static void
add_lb_ct_snat_hairpin_for_dp(const struct ovn_controller_lb *lb,
                              bool has_vip_port,
                              const struct sbrec_datapath_binding *datapath,
                              const struct hmap *local_datapaths,
                              struct match *dp_match,
                              struct ofpbuf *dp_acts,
                              struct ovn_desired_flow_table *flow_table)
{
    if (datapath) {
        if (!get_local_datapath(local_datapaths, datapath->tunnel_key)) {
            return;
        }
        match_set_metadata(dp_match, htonll(datapath->tunnel_key));
    }

    uint16_t priority = datapath ? 200 : 100;
    if (!has_vip_port) {
        /* If L4 ports are not specified for the current LB, we will decrease
         * the flow priority in order to not collide with other LBs with more
         * fine-grained configuration.
         */
        priority -= 10;
    }
    /* A flow added for the "hairpin_snat_ip" case will have an extra
     * datapath match, but it will also match on the less restrictive
     * general case.  Therefore, we set the priority in the
     * "hairpin_snat_ip" case to be higher than the general case. */
    ofctrl_add_flow(flow_table, OFTABLE_CT_SNAT_HAIRPIN,
                    priority, lb->slb->header_.uuid.parts[0],
                    dp_match, dp_acts, &lb->slb->header_.uuid);
}

/* Add a ct_snat flow for each VIP of the LB.  If this LB does not use
 * "hairpin_snat_ip", we can SNAT using the VIP.
 *
 * If this LB uses "hairpin_snat_ip", we can SNAT using that address, but
 * we have to add a separate flow per datapath. */
static void
add_lb_ct_snat_hairpin_vip_flow(const struct ovn_controller_lb *lb,
                                const struct ovn_lb_vip *lb_vip,
                                const struct hmap *local_datapaths,
                                struct ovn_desired_flow_table *flow_table)
{
    uint64_t stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);

    uint8_t address_family;
    if (IN6_IS_ADDR_V4MAPPED(&lb_vip->vip)) {
        address_family = AF_INET;
    } else {
        address_family = AF_INET6;
    }

    struct ofpact_conntrack *ct = ofpact_put_CT(&ofpacts);
    ct->recirc_table = NX_CT_RECIRC_NONE;
    ct->zone_src.field = mf_from_id(MFF_LOG_SNAT_ZONE);
    ct->zone_src.ofs = 0;
    ct->zone_src.n_bits = 16;
    ct->flags = NX_CT_F_COMMIT;
    ct->alg = 0;

    size_t nat_offset;
    nat_offset = ofpacts.size;
    ofpbuf_pull(&ofpacts, nat_offset);

    struct ofpact_nat *nat = ofpact_put_NAT(&ofpacts);
    nat->flags = NX_NAT_F_SRC;
    nat->range_af = address_family;

    if (nat->range_af == AF_INET) {
        nat->range.addr.ipv4.min = lb->hairpin_snat_ips.n_ipv4_addrs
                                   ? lb->hairpin_snat_ips.ipv4_addrs[0].addr
                                   : in6_addr_get_mapped_ipv4(&lb_vip->vip);
    } else {
        nat->range.addr.ipv6.min = lb->hairpin_snat_ips.n_ipv6_addrs
                                   ? lb->hairpin_snat_ips.ipv6_addrs[0].addr
                                   : lb_vip->vip;
    }
    ofpacts.header = ofpbuf_push_uninit(&ofpacts, nat_offset);
    ofpact_finish(&ofpacts, &ct->ofpact);

    struct match match = MATCH_CATCHALL_INITIALIZER;

    /* Matching on ct_nw_dst()/ct_ipv6_dst()/ct_tp_dst() requires matching
     * on ct_state first.
     */
    if (!lb->hairpin_orig_tuple) {
        uint32_t ct_state = OVS_CS_F_TRACKED | OVS_CS_F_DST_NAT;
        match_set_ct_state_masked(&match, ct_state, ct_state);
    }

    if (address_family == AF_INET) {
        ovs_be32 vip4 = in6_addr_get_mapped_ipv4(&lb_vip->vip);

        match_set_dl_type(&match, htons(ETH_TYPE_IP));

        if (!lb->hairpin_orig_tuple) {
            match_set_ct_nw_dst(&match, vip4);
        } else {
            match_set_reg(&match, MFF_LOG_LB_ORIG_DIP_IPV4 - MFF_LOG_REG0,
                          ntohl(vip4));
        }
    } else {
        match_set_dl_type(&match, htons(ETH_TYPE_IPV6));
        if (!lb->hairpin_orig_tuple) {
            match_set_ct_ipv6_dst(&match, &lb_vip->vip);
        } else {
            ovs_be128 vip6_value;

            memcpy(&vip6_value, &lb_vip->vip, sizeof vip6_value);
            match_set_xxreg(&match, MFF_LOG_LB_ORIG_DIP_IPV6 - MFF_LOG_XXREG0,
                            ntoh128(vip6_value));
        }
    }

    if (lb_vip->vip_port) {
        match_set_nw_proto(&match, lb->proto);
        if (!lb->hairpin_orig_tuple) {
            match_set_ct_nw_proto(&match, lb->proto);
            match_set_ct_tp_dst(&match, htons(lb_vip->vip_port));
        } else {
            match_set_reg_masked(&match, MFF_LOG_LB_ORIG_TP_DPORT - MFF_REG0,
                                 lb_vip->vip_port, UINT16_MAX);
        }
    }

    bool use_hairpin_snat_ip = false;
    if ((address_family == AF_INET && lb->hairpin_snat_ips.n_ipv4_addrs) ||
        (address_family == AF_INET6 && lb->hairpin_snat_ips.n_ipv6_addrs)) {
        use_hairpin_snat_ip = true;
    }

    if (!use_hairpin_snat_ip) {
        add_lb_ct_snat_hairpin_for_dp(lb, !!lb_vip->vip_port, NULL, NULL,
                                      &match, &ofpacts, flow_table);
    } else {
        for (size_t i = 0; i < lb->slb->n_datapaths; i++) {
            add_lb_ct_snat_hairpin_for_dp(lb, !!lb_vip->vip_port,
                                          lb->slb->datapaths[i],
                                          local_datapaths, &match,
                                          &ofpacts, flow_table);
        }
        if (lb->slb->datapath_group) {
            for (size_t i = 0; i < lb->slb->datapath_group->n_datapaths; i++) {
                add_lb_ct_snat_hairpin_for_dp(
                    lb, !!lb_vip->vip_port,
                    lb->slb->datapath_group->datapaths[i],
                    local_datapaths, &match, &ofpacts, flow_table);
            }
        }
    }

    ofpbuf_uninit(&ofpacts);
}

/* When a packet is sent to a LB VIP from a backend and the LB selects that
 * same backend as the target, this is a hairpin flow. The source address of
 * hairpin flows needs to be updated via SNAT so as it seems that the packet is
 * being sent from either a) the LB VIP or b) "hairpin_snat_ip" as specified in
 * the LB entry in the NBDB.
 *
 * add_lb_ct_snat_hairpin_flows() adds OpenFlow flows for each LB in order to
 * achieve this behaviour. */
static void
add_lb_ct_snat_hairpin_flows(const struct ovn_controller_lb *lb,
                             const struct hmap *local_datapaths,
                             struct ovn_desired_flow_table *flow_table)
{
    /* We must add a flow for each LB VIP. In the general case, this flow
       is added to the OFTABLE_CT_SNAT_HAIRPIN table. If it matches, we
       should SNAT using the LB VIP. We do not discriminate using the datapath
       metadata as a match field, this is because we are sure that only
       hairpin flows will reach the OFTABLE_CT_SNAT_HAIRPIN table and if
       they have, then we should SNAT using the LB VIP. This allows us to
       reduce the number of OpenFlow flows that we need to install as we only
       need to add one flow per VIP (rather than one flow per VIP for every
       datapath). This is because if two LBs have the same VIP but they are
       added on different datapaths, we would SNAT in the same way (i.e. using
       the same IP).

       There is an exception to this if "hairpin_snat_ip" has been specified.
       In this case we need to use the "hairpin_snat_ip" IP address for SNAT.
       If we consider the case in which we have two LBs with the same VIP
       added on two different datapaths. In the general case, as mentioned
       above we do not need to add an OpenFlow flow for each datapath. However,
       if one LB has specified "hairpin_snat_ip", then we need to SNAT that LB
       using the "hairpin_snat_ip" address rather than the VIP. In order to
       achieve that, we need to add a datapath metadata match.  These flows
       will match on a subset of fields of more general flows, generated for a
       case without "hairpin_snat_ip", so they need to have a higher priority.

       There is another potential exception. Consider the case in which we have
       two LBs which both have "hairpin_snat_ip" set. If these LBs have
       the same VIP and are added to the same datapath, this will result in
       unexpected behaviour. However, although this is currently an allowed
       configuration in OVN, it is a nonsense configuration as two LBs with the
       same VIP should not be added to the same datapath. */

    for (int i = 0; i < lb->n_vips; i++) {
        add_lb_ct_snat_hairpin_vip_flow(lb, &lb->vips[i], local_datapaths,
                                        flow_table);
    }
}

static void
consider_lb_hairpin_flows(const struct ovn_controller_lb *lb,
                          const struct hmap *local_datapaths,
                          bool use_ct_mark,
                          struct ovn_desired_flow_table *flow_table)
{
    for (size_t i = 0; i < lb->n_vips; i++) {
        struct ovn_lb_vip *lb_vip = &lb->vips[i];

        for (size_t j = 0; j < lb_vip->n_backends; j++) {
            struct ovn_lb_backend *lb_backend = &lb_vip->backends[j];

            add_lb_vip_hairpin_flows(lb, lb_vip, lb_backend,
                                     use_ct_mark, flow_table);
        }
    }

    add_lb_ct_snat_hairpin_flows(lb, local_datapaths, flow_table);
}

/* Adds OpenFlow flows to flow tables for each Load balancer VIPs and
 * backends to handle the load balanced hairpin traffic. */
static void
add_lb_hairpin_flows(const struct hmap *local_lbs,
                     const struct hmap *local_datapaths,
                     bool use_ct_mark,
                     struct ovn_desired_flow_table *flow_table)
{
    const struct ovn_controller_lb *lb;
    HMAP_FOR_EACH (lb, hmap_node, local_lbs) {
        consider_lb_hairpin_flows(lb, local_datapaths,
                                  use_ct_mark, flow_table);
    }
}

/* Handles neighbor changes in mac_binding table. */
void
lflow_handle_changed_mac_bindings(
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct sbrec_mac_binding_table *mac_binding_table,
    const struct hmap *local_datapaths,
    struct ovn_desired_flow_table *flow_table)
{
    const struct sbrec_mac_binding *mb;
    /* Handle deleted mac_bindings first, to avoid *duplicated flow* problem
     * when same flow needs to be added. */
    SBREC_MAC_BINDING_TABLE_FOR_EACH_TRACKED (mb, mac_binding_table) {
        /* Remove any flows that should be removed. */
        if (sbrec_mac_binding_is_deleted(mb)) {
            VLOG_DBG("handle deleted mac_binding "UUID_FMT,
                     UUID_ARGS(&mb->header_.uuid));
            ofctrl_remove_flows(flow_table, &mb->header_.uuid);
        }
    }
    SBREC_MAC_BINDING_TABLE_FOR_EACH_TRACKED (mb, mac_binding_table) {
        if (!sbrec_mac_binding_is_deleted(mb)) {
            if (!sbrec_mac_binding_is_new(mb)) {
                VLOG_DBG("handle updated mac_binding "UUID_FMT,
                         UUID_ARGS(&mb->header_.uuid));
                ofctrl_remove_flows(flow_table, &mb->header_.uuid);
            }
            VLOG_DBG("handle new mac_binding "UUID_FMT,
                     UUID_ARGS(&mb->header_.uuid));
            consider_neighbor_flow(sbrec_port_binding_by_name, local_datapaths,
                                   mb, NULL, flow_table, 100);
        }
    }
}

/* Handles changes to static_mac_binding table. */
void
lflow_handle_changed_static_mac_bindings(
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct sbrec_static_mac_binding_table *smb_table,
    const struct hmap *local_datapaths,
    struct ovn_desired_flow_table *flow_table)
{
    const struct sbrec_static_mac_binding *smb;
    SBREC_STATIC_MAC_BINDING_TABLE_FOR_EACH_TRACKED (smb, smb_table) {
        if (sbrec_static_mac_binding_is_deleted(smb)) {
            VLOG_DBG("handle deleted static_mac_binding "UUID_FMT,
                     UUID_ARGS(&smb->header_.uuid));
            ofctrl_remove_flows(flow_table, &smb->header_.uuid);
        } else {
            if (!sbrec_static_mac_binding_is_new(smb)) {
                VLOG_DBG("handle updated static_mac_binding "UUID_FMT,
                         UUID_ARGS(&smb->header_.uuid));
                ofctrl_remove_flows(flow_table, &smb->header_.uuid);
            }
            VLOG_DBG("handle new static_mac_binding "UUID_FMT,
                     UUID_ARGS(&smb->header_.uuid));
            consider_neighbor_flow(sbrec_port_binding_by_name, local_datapaths,
                                   NULL, smb, flow_table,
                                   smb->override_dynamic_mac ? 150 : 50);
        }
    }
}

static void
consider_fdb_flows(const struct sbrec_fdb *fdb,
                   const struct hmap *local_datapaths,
                   struct ovn_desired_flow_table *flow_table,
                   struct ovsdb_idl_index *sbrec_port_binding_by_key,
                   bool localnet_learn_fdb)
{
    struct local_datapath *ld = get_local_datapath(local_datapaths,
                                                   fdb->dp_key);
    if (!ld) {
        return;
    }
    const struct sbrec_port_binding *pb = lport_lookup_by_key_with_dp(
        sbrec_port_binding_by_key, ld->datapath, fdb->port_key);

    struct eth_addr mac;
    if (!eth_addr_from_string(fdb->mac, &mac)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad 'mac' %s", fdb->mac);
        return;
    }

    struct match match = MATCH_CATCHALL_INITIALIZER;
    match_set_metadata(&match, htonll(fdb->dp_key));
    match_set_dl_dst(&match, mac);

    uint64_t stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);
    put_load64(fdb->port_key, MFF_LOG_OUTPORT, 0, 32, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_GET_FDB, 100,
                    fdb->header_.uuid.parts[0], &match, &ofpacts,
                    &fdb->header_.uuid);
    ofpbuf_clear(&ofpacts);

    uint8_t value = 1;
    uint8_t is_vif =  pb ? !strcmp(pb->type, "") : 0;
    put_load(&value, sizeof value, MFF_LOG_FLAGS,
             MLF_LOOKUP_FDB_BIT, 1, &ofpacts);

    struct match lookup_match = MATCH_CATCHALL_INITIALIZER;
    match_set_metadata(&lookup_match, htonll(fdb->dp_key));
    match_set_dl_src(&lookup_match, mac);
    match_set_reg(&lookup_match, MFF_LOG_INPORT - MFF_REG0, fdb->port_key);
    ofctrl_add_flow(flow_table, OFTABLE_LOOKUP_FDB, 100,
                    fdb->header_.uuid.parts[0], &lookup_match, &ofpacts,
                    &fdb->header_.uuid);

    if (is_vif && localnet_learn_fdb) {
        struct match lookup_match_vif = MATCH_CATCHALL_INITIALIZER;
        match_set_metadata(&lookup_match_vif, htonll(fdb->dp_key));
        match_set_dl_src(&lookup_match_vif, mac);
        match_set_reg_masked(&lookup_match_vif, MFF_LOG_FLAGS - MFF_REG0,
                             MLF_LOCALNET, MLF_LOCALNET);

        ofctrl_add_flow(flow_table, OFTABLE_LOOKUP_FDB, 100,
                        fdb->header_.uuid.parts[0], &lookup_match_vif,
                        &ofpacts, &fdb->header_.uuid);
    }
    ofpbuf_uninit(&ofpacts);
}

/* Adds an OpenFlow flow to flow tables for each MAC binding in the OVN
 * southbound database. */
static void
add_fdb_flows(const struct sbrec_fdb_table *fdb_table,
              const struct hmap *local_datapaths,
              struct ovn_desired_flow_table *flow_table,
              struct ovsdb_idl_index *sbrec_port_binding_by_key,
              bool localnet_learn_fdb)
{
    const struct sbrec_fdb *fdb;
    SBREC_FDB_TABLE_FOR_EACH (fdb, fdb_table) {
        consider_fdb_flows(fdb, local_datapaths, flow_table,
                           sbrec_port_binding_by_key, localnet_learn_fdb);
    }
}


/* Translates logical flows in the Logical_Flow table in the OVN_SB database
 * into OpenFlow flows.  See ovn-architecture(7) for more information. */
void
lflow_run(struct lflow_ctx_in *l_ctx_in, struct lflow_ctx_out *l_ctx_out)
{
    COVERAGE_INC(lflow_run);

    add_logical_flows(l_ctx_in, l_ctx_out);
    add_neighbor_flows(l_ctx_in->sbrec_port_binding_by_name,
                       l_ctx_in->mac_binding_table,
                       l_ctx_in->static_mac_binding_table,
                       l_ctx_in->local_datapaths,
                       l_ctx_out->flow_table);
    add_lb_hairpin_flows(l_ctx_in->local_lbs,
                         l_ctx_in->local_datapaths,
                         l_ctx_in->lb_hairpin_use_ct_mark,
                         l_ctx_out->flow_table);
    add_fdb_flows(l_ctx_in->fdb_table, l_ctx_in->local_datapaths,
                  l_ctx_out->flow_table,
                  l_ctx_in->sbrec_port_binding_by_key,
                  l_ctx_in->localnet_learn_fdb);
    add_port_sec_flows(l_ctx_in->binding_lports, l_ctx_in->chassis,
                       l_ctx_out->flow_table);
}

/* Should be called at every ovn-controller iteration before IDL tracked
 * changes are cleared to avoid maintaining cache entries for flows that
 * don't exist anymore.
 */
void
lflow_handle_cached_flows(struct lflow_cache *lc,
                          const struct sbrec_logical_flow_table *flow_table)
{
    const struct sbrec_logical_flow *lflow;

    SBREC_LOGICAL_FLOW_TABLE_FOR_EACH_TRACKED (lflow, flow_table) {
        if (sbrec_logical_flow_is_deleted(lflow)) {
            lflow_cache_delete(lc, &lflow->header_.uuid);
        }
    }
}

void
lflow_destroy(void)
{
    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
}

bool
lflow_add_flows_for_datapath(const struct sbrec_datapath_binding *dp,
                             struct lflow_ctx_in *l_ctx_in,
                             struct lflow_ctx_out *l_ctx_out)
{
    bool handled = true;

    struct sbrec_logical_flow *lf_row = sbrec_logical_flow_index_init_row(
        l_ctx_in->sbrec_logical_flow_by_logical_datapath);
    sbrec_logical_flow_index_set_logical_datapath(lf_row, dp);

    const struct sbrec_logical_flow *lflow;
    SBREC_LOGICAL_FLOW_FOR_EACH_EQUAL (
        lflow, lf_row, l_ctx_in->sbrec_logical_flow_by_logical_datapath) {
        if (uuidset_find(l_ctx_out->objs_processed, &lflow->header_.uuid)) {
            continue;
        }
        uuidset_insert(l_ctx_out->objs_processed, &lflow->header_.uuid);
        consider_logical_flow__(lflow, dp, l_ctx_in, l_ctx_out);
    }
    sbrec_logical_flow_index_destroy_row(lf_row);

    lf_row = sbrec_logical_flow_index_init_row(
        l_ctx_in->sbrec_logical_flow_by_logical_dp_group);
    /* There are far fewer datapath groups than logical flows. */
    const struct sbrec_logical_dp_group *ldpg;
    SBREC_LOGICAL_DP_GROUP_TABLE_FOR_EACH (ldpg,
                                           l_ctx_in->logical_dp_group_table) {
        bool found = false;
        for (size_t i = 0; i < ldpg->n_datapaths; i++) {
            if (ldpg->datapaths[i] == dp) {
                found = true;
                break;
            }
        }
        if (!found) {
            continue;
        }

        sbrec_logical_flow_index_set_logical_dp_group(lf_row, ldpg);
        SBREC_LOGICAL_FLOW_FOR_EACH_EQUAL (
            lflow, lf_row, l_ctx_in->sbrec_logical_flow_by_logical_dp_group) {
            if (uuidset_find(l_ctx_out->objs_processed,
                             &lflow->header_.uuid)) {
                continue;
            }
            /* Don't call uuidset_insert() because here we process the
             * lflow only for one of the DPs in the DP group, which may be
             * incomplete. */
            consider_logical_flow__(lflow, dp, l_ctx_in, l_ctx_out);
        }
    }
    sbrec_logical_flow_index_destroy_row(lf_row);

    struct sbrec_fdb *fdb_index_row =
        sbrec_fdb_index_init_row(l_ctx_in->sbrec_fdb_by_dp_key);
    sbrec_fdb_index_set_dp_key(fdb_index_row, dp->tunnel_key);
    const struct sbrec_fdb *fdb_row;
    SBREC_FDB_FOR_EACH_EQUAL (fdb_row, fdb_index_row,
                              l_ctx_in->sbrec_fdb_by_dp_key) {
        consider_fdb_flows(fdb_row, l_ctx_in->local_datapaths,
                           l_ctx_out->flow_table,
                           l_ctx_in->sbrec_port_binding_by_key,
                           l_ctx_in->localnet_learn_fdb);
    }
    sbrec_fdb_index_destroy_row(fdb_index_row);

    struct sbrec_mac_binding *mb_index_row = sbrec_mac_binding_index_init_row(
        l_ctx_in->sbrec_mac_binding_by_datapath);
    sbrec_mac_binding_index_set_datapath(mb_index_row, dp);
    const struct sbrec_mac_binding *mb;
    SBREC_MAC_BINDING_FOR_EACH_EQUAL (
        mb, mb_index_row, l_ctx_in->sbrec_mac_binding_by_datapath) {
        consider_neighbor_flow(l_ctx_in->sbrec_port_binding_by_name,
                               l_ctx_in->local_datapaths,
                               mb, NULL, l_ctx_out->flow_table, 100);
    }
    sbrec_mac_binding_index_destroy_row(mb_index_row);

    struct sbrec_static_mac_binding *smb_index_row =
        sbrec_static_mac_binding_index_init_row(
            l_ctx_in->sbrec_static_mac_binding_by_datapath);
    sbrec_static_mac_binding_index_set_datapath(smb_index_row, dp);
    const struct sbrec_static_mac_binding *smb;
    SBREC_STATIC_MAC_BINDING_FOR_EACH_EQUAL (
        smb, smb_index_row, l_ctx_in->sbrec_static_mac_binding_by_datapath) {
        consider_neighbor_flow(l_ctx_in->sbrec_port_binding_by_name,
                               l_ctx_in->local_datapaths,
                               NULL, smb, l_ctx_out->flow_table,
                               smb->override_dynamic_mac ? 150 : 50);
    }
    sbrec_static_mac_binding_index_destroy_row(smb_index_row);

    return handled;
}

/* Handles a port-binding change that is possibly related to a lport's
 * residence status on this chassis. */
bool
lflow_handle_flows_for_lport(const struct sbrec_port_binding *pb,
                             struct lflow_ctx_in *l_ctx_in,
                             struct lflow_ctx_out *l_ctx_out)
{
    bool changed;

    if (!objdep_mgr_handle_change(l_ctx_out->lflow_deps_mgr,
                                  OBJDEP_TYPE_PORTBINDING,
                                  pb->logical_port,
                                  lflow_handle_changed_ref,
                                  l_ctx_out->objs_processed,
                                  l_ctx_in, l_ctx_out, &changed)) {
        return false;
    }

    /* Program the port security flows.
     * Note: All the port security OF rules are added using the 'uuid'
     * of the port binding.  Right now port binding 'uuid' is used in
     * the logical flow table (l_ctx_out->flow_table) only for port
     * security flows.  Later if new flows are added using the
     * port binding'uuid', then this function should handle it properly.
     */
    ofctrl_remove_flows(l_ctx_out->flow_table, &pb->header_.uuid);

    if (pb->n_port_security && shash_find(l_ctx_in->binding_lports,
                                          pb->logical_port)) {
        consider_port_sec_flows(pb, l_ctx_out->flow_table);
    }
    if (l_ctx_in->localnet_learn_fdb_changed && l_ctx_in->localnet_learn_fdb) {
        const struct sbrec_fdb *fdb;
        SBREC_FDB_TABLE_FOR_EACH (fdb, l_ctx_in->fdb_table) {
            consider_fdb_flows(fdb, l_ctx_in->local_datapaths,
                               l_ctx_out->flow_table,
                               l_ctx_in->sbrec_port_binding_by_key,
                               l_ctx_in->localnet_learn_fdb);
        }
    }
    return true;
}

/* Handles port-binding add/deletions. */
bool
lflow_handle_changed_port_bindings(struct lflow_ctx_in *l_ctx_in,
                                   struct lflow_ctx_out *l_ctx_out)
{
    bool ret = true;
    bool changed;
    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (pb,
                                               l_ctx_in->port_binding_table) {
        if (!sbrec_port_binding_is_new(pb)
            && !sbrec_port_binding_is_deleted(pb)) {
            continue;
        }
        if (!objdep_mgr_handle_change(l_ctx_out->lflow_deps_mgr,
                                      OBJDEP_TYPE_PORTBINDING,
                                      pb->logical_port,
                                      lflow_handle_changed_ref,
                                      l_ctx_out->objs_processed,
                                      l_ctx_in, l_ctx_out, &changed)) {
            ret = false;
            break;
        }
    }
    return ret;
}

bool
lflow_handle_changed_mc_groups(struct lflow_ctx_in *l_ctx_in,
                               struct lflow_ctx_out *l_ctx_out)
{
    bool ret = true;
    bool changed;
    struct ds mg_key = DS_EMPTY_INITIALIZER;
    const struct sbrec_multicast_group *mg;
    SBREC_MULTICAST_GROUP_TABLE_FOR_EACH_TRACKED (mg,
                                                  l_ctx_in->mc_group_table) {
        get_mc_group_key(mg->name, mg->datapath->tunnel_key, &mg_key);
        if (!sbrec_multicast_group_is_new(mg)
            && !sbrec_multicast_group_is_deleted(mg)) {
            continue;
        }
        if (!objdep_mgr_handle_change(l_ctx_out->lflow_deps_mgr,
                                      OBJDEP_TYPE_MC_GROUP, ds_cstr(&mg_key),
                                      lflow_handle_changed_ref,
                                      l_ctx_out->objs_processed,
                                      l_ctx_in, l_ctx_out, &changed)) {
            ret = false;
            break;
        }
    }
    ds_destroy(&mg_key);
    return ret;
}

bool
lflow_handle_changed_lbs(struct lflow_ctx_in *l_ctx_in,
                         struct lflow_ctx_out *l_ctx_out,
                         const struct uuidset *deleted_lbs,
                         const struct uuidset *updated_lbs,
                         const struct uuidset *new_lbs,
                         const struct hmap *old_lbs)
{
    const struct ovn_controller_lb *lb;

    struct uuidset_node *uuid_node;
    UUIDSET_FOR_EACH (uuid_node, deleted_lbs) {
        lb = ovn_controller_lb_find(old_lbs, &uuid_node->uuid);

        VLOG_DBG("Remove hairpin flows for deleted load balancer "UUID_FMT,
                 UUID_ARGS(&uuid_node->uuid));
        ofctrl_remove_flows(l_ctx_out->flow_table, &uuid_node->uuid);
    }

    UUIDSET_FOR_EACH (uuid_node, updated_lbs) {
        lb = ovn_controller_lb_find(l_ctx_in->local_lbs, &uuid_node->uuid);

        VLOG_DBG("Remove and add hairpin flows for updated load balancer "
                  UUID_FMT, UUID_ARGS(&uuid_node->uuid));
        ofctrl_remove_flows(l_ctx_out->flow_table, &uuid_node->uuid);
        consider_lb_hairpin_flows(lb, l_ctx_in->local_datapaths,
                                  l_ctx_in->lb_hairpin_use_ct_mark,
                                  l_ctx_out->flow_table);
    }

    UUIDSET_FOR_EACH (uuid_node, new_lbs) {
        lb = ovn_controller_lb_find(l_ctx_in->local_lbs, &uuid_node->uuid);

        VLOG_DBG("Add load balancer hairpin flows for "UUID_FMT,
                 UUID_ARGS(&uuid_node->uuid));
        consider_lb_hairpin_flows(lb, l_ctx_in->local_datapaths,
                                  l_ctx_in->lb_hairpin_use_ct_mark,
                                  l_ctx_out->flow_table);
    }

    return true;
}

bool
lflow_handle_changed_fdbs(struct lflow_ctx_in *l_ctx_in,
                         struct lflow_ctx_out *l_ctx_out)
{
    const struct sbrec_fdb *fdb;

    SBREC_FDB_TABLE_FOR_EACH_TRACKED (fdb, l_ctx_in->fdb_table) {
        if (sbrec_fdb_is_deleted(fdb)) {
            VLOG_DBG("Remove fdb flows for deleted fdb "UUID_FMT,
                     UUID_ARGS(&fdb->header_.uuid));
            ofctrl_remove_flows(l_ctx_out->flow_table, &fdb->header_.uuid);
        }
    }

    SBREC_FDB_TABLE_FOR_EACH_TRACKED (fdb, l_ctx_in->fdb_table) {
        if (sbrec_fdb_is_deleted(fdb)) {
            continue;
        }

        if (!sbrec_fdb_is_new(fdb)) {
            VLOG_DBG("Remove fdb flows for updated fdb "UUID_FMT,
                     UUID_ARGS(&fdb->header_.uuid));
            ofctrl_remove_flows(l_ctx_out->flow_table, &fdb->header_.uuid);
        }

        VLOG_DBG("Add fdb flows for fdb "UUID_FMT,
                 UUID_ARGS(&fdb->header_.uuid));
        consider_fdb_flows(fdb, l_ctx_in->local_datapaths,
                           l_ctx_out->flow_table,
                           l_ctx_in->sbrec_port_binding_by_key,
                           l_ctx_in->localnet_learn_fdb);
    }

    return true;
}

static void
add_port_sec_flows(const struct shash *binding_lports,
                   const struct sbrec_chassis *chassis,
                   struct ovn_desired_flow_table *flow_table)
{
    const struct shash_node *node;
    SHASH_FOR_EACH (node, binding_lports) {
        const struct binding_lport *b_lport = node->data;
        if (!b_lport->pb || b_lport->pb->chassis != chassis) {
            continue;
        }

        consider_port_sec_flows(b_lport->pb, flow_table);
    }
}

static void
reset_match_for_port_sec_flows(const struct sbrec_port_binding *pb,
                               enum mf_field_id reg_id, struct match *match)
{
    match_init_catchall(match);
    match_set_metadata(match, htonll(pb->datapath->tunnel_key));
    match_set_reg(match, reg_id - MFF_REG0, pb->tunnel_key);
}

static void build_port_sec_deny_action(struct ofpbuf *ofpacts)
{
    ofpbuf_clear(ofpacts);
    uint8_t value = 1;
    put_load(&value, sizeof value, MFF_LOG_FLAGS,
             MLF_CHECK_PORT_SEC_BIT, 1, ofpacts);
}

static void build_port_sec_allow_action(struct ofpbuf *ofpacts)
{
    ofpbuf_clear(ofpacts);
    uint8_t value = 0;
    put_load(&value, sizeof value, MFF_LOG_FLAGS,
             MLF_CHECK_PORT_SEC_BIT, 1, ofpacts);
}

static void build_port_sec_adv_nd_check(struct ofpbuf *ofpacts)
{
    ofpbuf_clear(ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(ofpacts);
    resubmit->in_port = OFPP_IN_PORT;
    resubmit->table_id = OFTABLE_CHK_IN_PORT_SEC_ND;
}

static void
build_in_port_sec_default_flows(const struct sbrec_port_binding *pb,
                                struct match *m, struct ofpbuf *ofpacts,
                                struct ovn_desired_flow_table *flow_table)
{
    reset_match_for_port_sec_flows(pb, MFF_LOG_INPORT, m);
    build_port_sec_deny_action(ofpacts);

    /* Add the below logical flow equivalent OF rule in 'in_port_sec' table.
     * priority: 80
     * match - "inport == pb->logical_port"
     * action - "port_sec_failed = 1;"
     * description: "Default drop all traffic from""
     */
    ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC, 80,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);

    /* ARP checking is done in the next table. So just advance
     * the arp packets to the next table.
     *
     * Add the below logical flow equivalent OF rules in 'in_port_sec' table.
     * priority: 95
     * match - "inport == pb->logical_port && arp"
     * action - "resubmit(,PORT_SEC_ND_TABLE);"
     */
    match_set_dl_type(m, htons(ETH_TYPE_ARP));
    build_port_sec_adv_nd_check(ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC, 95,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);

    /* Add the below logical flow equivalent OF rules in 'in_port_sec_nd' table
     * priority: 80
     * match - "inport == pb->logical_port && arp"
     * action - "port_sec_failed = 1;"
     * description: "Default drop all arp packets"
     * note: "Higher priority flows are added to allow the legit ARP packets."
     */
    reset_match_for_port_sec_flows(pb, MFF_LOG_INPORT, m);
    build_port_sec_deny_action(ofpacts);
    match_set_dl_type(m, htons(ETH_TYPE_ARP));
    ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC_ND, 80,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);

    /* Add the below logical flow equivalent OF rules in 'in_port_sec_nd' table
     * priority: 80
     * match - "inport == pb->logical_port && icmp6 && icmp6.code == 136"
     * action - "port_sec_failed = 1;"
     * description: "Default drop all IPv6 NA packets"
     * note: "Higher priority flows are added to allow the legit NA packets."
     */
    match_set_dl_type(m, htons(ETH_TYPE_IPV6));
    match_set_nw_proto(m, IPPROTO_ICMPV6);
    match_set_nw_ttl(m, 255);
    match_set_icmp_type(m, 136);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC_ND, 80,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);

    /* Add the below logical flow equivalent OF rules in 'in_port_sec_nd' table
     * priority: 80
     * match - "inport == pb->logical_port && icmp6 && icmp6.code == 135"
     * action - "port_sec_failed = 0;"
     * description: "Default allow all IPv6 NS packets"
     * note: This is a hack for now.  Ideally we should do default drop.
     *       There seems to be a bug in ovs-vswitchd which needs further
     *       investigation.
     *
     * Eg.  If there are below OF rules in the same table
     * (1) priority=90,icmp6,reg14=0x1,metadata=0x1,nw_ttl=255,icmp_type=135,
     *     icmp_code=0,nd_sll=fa:16:3e:94:05:98
     *     actions=load:0->NXM_NX_REG10[12]
     * (2) priority=80,icmp6,reg14=0x1,metadata=0x1,nw_ttl=255,icmp_type=135,
     *     icmp_code=0 actions=load:1->NXM_NX_REG10[12]
     *
     * An IPv6 NS packet with nd_sll = fa:16:3e:94:05:98 is matching on the
     * second prio-80 flow instead of the first one.
     */
    match_set_dl_type(m, htons(ETH_TYPE_IPV6));
    match_set_nw_proto(m, IPPROTO_ICMPV6);
    match_set_nw_ttl(m, 255);
    match_set_icmp_type(m, 135);
    build_port_sec_allow_action(ofpacts); /*TODO:  Change this to
                                           * build_port_sec_deny_action(). */
    ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC_ND, 80,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);
}

static void
build_in_port_sec_no_ip_flows(const struct sbrec_port_binding *pb,
                              struct lport_addresses *ps_addr,
                              struct match *m, struct ofpbuf *ofpacts,
                              struct ovn_desired_flow_table *flow_table)
{
    if (ps_addr->n_ipv4_addrs || ps_addr->n_ipv6_addrs) {
        return;
    }

    /* Add the below logical flow equivalent OF rules in 'in_port_sec' table.
     * priority: 90
     * match - "inport == pb->logical_port && eth.src == ps_addr.ea"
     * action - "next;"
     * description: "Advance the packet for ARP/ND check"
     */
    reset_match_for_port_sec_flows(pb, MFF_LOG_INPORT, m);
    match_set_dl_src(m, ps_addr->ea);
    build_port_sec_adv_nd_check(ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC, 90,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);
}

static void
build_in_port_sec_ip4_flows(const struct sbrec_port_binding *pb,
                           struct lport_addresses *ps_addr,
                           struct match *m, struct ofpbuf *ofpacts,
                           struct ovn_desired_flow_table *flow_table)
{
    if (!ps_addr->n_ipv4_addrs) {
        /* If no IPv4 addresses, then 'pb' is not allowed to send IPv4 traffic.
         * build_in_port_sec_default_flows() takes care of this scenario. */
        return;
    }

    /* Advance all traffic from the port security eth address for ND check. */
    build_port_sec_allow_action(ofpacts);

    /* Add the below logical flow equivalent OF rules in in_port_sec.
     * priority: 90
     * match - "inport == pb->port && eth.src == ps_addr.ea &&
     *         ip4.src == {ps_addr.ipv4_addrs}"
     * action - "port_sec_failed = 0;"
     */
    for (size_t j = 0; j < ps_addr->n_ipv4_addrs; j++) {
        reset_match_for_port_sec_flows(pb, MFF_LOG_INPORT, m);
        match_set_dl_src(m, ps_addr->ea);
        match_set_dl_type(m, htons(ETH_TYPE_IP));

        ovs_be32 mask = ps_addr->ipv4_addrs[j].mask;
        /* When the netmask is applied, if the host portion is
         * non-zero, the host can only use the specified
         * address.  If zero, the host is allowed to use any
         * address in the subnet.
         */
        if (ps_addr->ipv4_addrs[j].plen == 32 ||
                ps_addr->ipv4_addrs[j].addr & ~mask) {
            match_set_nw_src(m, ps_addr->ipv4_addrs[j].addr);
        } else {
            match_set_nw_src_masked(m, ps_addr->ipv4_addrs[j].addr, mask);
        }

        ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC, 90,
                        pb->header_.uuid.parts[0], m, ofpacts,
                        &pb->header_.uuid);
    }

    /* Add the below logical flow equivalent OF rules in in_port_sec.
     * priority: 90
     * match - "inport == pb->port && eth.src == ps_addr.ea &&
     *          ip4.src == 0.0.0.0 && ip4.dst == 255.255.255.255 &&
     *          udp.src == 67 && udp.dst == 68"
     * action - "port_sec_failed = 0;"
     * description: "Allow the DHCP requests."
     */
    reset_match_for_port_sec_flows(pb, MFF_LOG_INPORT, m);
    match_set_dl_src(m, ps_addr->ea);
    match_set_dl_type(m, htons(ETH_TYPE_IP));

    ovs_be32 ip4 = htonl(0);
    match_set_nw_src(m, ip4);
    ip4 = htonl(0xffffffff);
    match_set_nw_dst(m, ip4);
    match_set_nw_proto(m, IPPROTO_UDP);
    match_set_tp_src(m, htons(68));
    match_set_tp_dst(m, htons(67));

    ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC, 90,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);
}

/* Adds the OF rules to allow ARP packets in 'in_port_sec_nd' table. */
static void
build_in_port_sec_arp_flows(const struct sbrec_port_binding *pb,
                           struct lport_addresses *ps_addr,
                           struct match *m, struct ofpbuf *ofpacts,
                           struct ovn_desired_flow_table *flow_table)
{
    if (!ps_addr->n_ipv4_addrs && ps_addr->n_ipv6_addrs) {
        /* No ARP is allowed as only IPv6 addresses are configured. */
        return;
    }

    build_port_sec_allow_action(ofpacts);

    if (!ps_addr->n_ipv4_addrs) {
        /* No IPv4 addresses.
         * Add the below logical flow equivalent OF rules in 'in_port_sec_nd'
         * table.
         * priority: 90
         * match - "inport == pb->port && eth.src == ps_addr.ea &&
         *          arp && arp.sha == ps_addr.ea"
         * action - "port_sec_failed = 0;"
         */
        reset_match_for_port_sec_flows(pb, MFF_LOG_INPORT, m);
        match_set_dl_src(m, ps_addr->ea);
        match_set_dl_type(m, htons(ETH_TYPE_ARP));
        match_set_arp_sha(m, ps_addr->ea);
        ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC_ND, 90,
                        pb->header_.uuid.parts[0], m, ofpacts,
                        &pb->header_.uuid);
    }

    /* Add the below logical flow equivalent OF rules in 'in_port_sec_nd'
     * table.
     * priority: 90
     * match - "inport == pb->port && eth.src == ps_addr.ea &&
     *         arp && arp.sha == ps_addr.ea && arp.spa == {ps_addr.ipv4_addrs}"
     * action - "port_sec_failed = 0;"
     */
    for (size_t j = 0; j < ps_addr->n_ipv4_addrs; j++) {
        reset_match_for_port_sec_flows(pb, MFF_LOG_INPORT, m);
        match_set_dl_src(m, ps_addr->ea);
        match_set_dl_type(m, htons(ETH_TYPE_ARP));
        match_set_arp_sha(m, ps_addr->ea);

        ovs_be32 mask = ps_addr->ipv4_addrs[j].mask;
        if (ps_addr->ipv4_addrs[j].plen == 32 ||
                ps_addr->ipv4_addrs[j].addr & ~mask) {
            match_set_nw_src(m, ps_addr->ipv4_addrs[j].addr);
        } else {
            match_set_nw_src_masked(m, ps_addr->ipv4_addrs[j].addr, mask);
        }
        ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC_ND, 90,
                        pb->header_.uuid.parts[0], m, ofpacts,
                        &pb->header_.uuid);
    }
}

static void
build_in_port_sec_ip6_flows(const struct sbrec_port_binding *pb,
                           struct lport_addresses *ps_addr,
                           struct match *m, struct ofpbuf *ofpacts,
                           struct ovn_desired_flow_table *flow_table)
{
    if (!ps_addr->n_ipv6_addrs) {
        /* If no IPv6 addresses, then 'pb' is not allowed to send IPv6 traffic.
         * build_in_port_sec_default_flows() takes care of this scenario. */
        return;
    }

    /* Add the below logical flow equivalent OF rules in 'in_port_sec_nd'
     * table.
     * priority: 90
     * match - "inport == pb->port && eth.src == ps_addr.ea &&
     *         ip6.src == {ps_addr.ipv6_addrs, lla}"
     * action - "next;"
     * description - Advance the packet for Neighbor Solicit/Adv check.
     */
    build_port_sec_adv_nd_check(ofpacts);

    for (size_t j = 0; j < ps_addr->n_ipv6_addrs; j++) {
        reset_match_for_port_sec_flows(pb, MFF_LOG_INPORT, m);
        match_set_dl_src(m, ps_addr->ea);
        match_set_dl_type(m, htons(ETH_TYPE_IPV6));

        if (ps_addr->ipv6_addrs[j].plen == 128
            || !ipv6_addr_is_host_zero(&ps_addr->ipv6_addrs[j].addr,
                                        &ps_addr->ipv6_addrs[j].mask)) {
            match_set_ipv6_src(m, &ps_addr->ipv6_addrs[j].addr);
        } else {
            match_set_ipv6_src_masked(m, &ps_addr->ipv6_addrs[j].network,
                                        &ps_addr->ipv6_addrs[j].mask);
        }

        ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC, 90,
                        pb->header_.uuid.parts[0], m, ofpacts,
                        &pb->header_.uuid);
    }

    reset_match_for_port_sec_flows(pb, MFF_LOG_INPORT, m);
    match_set_dl_src(m, ps_addr->ea);
    match_set_dl_type(m, htons(ETH_TYPE_IPV6));

    struct in6_addr lla;
    in6_generate_lla(ps_addr->ea, &lla);
    match_set_ipv6_src(m, &lla);

    ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC, 90,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);

    /* Add the below logical flow equivalent OF rules in 'in_port_sec_nd'
     * table.
     * priority: 90
     * match - "inport == pb->port && eth.src == ps_addr.ea &&
     *          ip6.src == :: && ip6.dst == ff02::/16 && icmp6 &&
     *          icmp6.code == 0 && icmp6.type == {131, 143}"
     * action - "port_sec_failed = 0;"
     */
    build_port_sec_allow_action(ofpacts);
    match_set_ipv6_src(m, &in6addr_any);
    struct in6_addr ip6, mask;
    char *err = ipv6_parse_masked("ff02::/16", &ip6, &mask);
    ovs_assert(!err);

    match_set_ipv6_dst_masked(m, &ip6, &mask);
    match_set_nw_proto(m, IPPROTO_ICMPV6);
    match_set_icmp_type(m, 131);
    match_set_icmp_code(m, 0);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC, 90,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);

    match_set_icmp_type(m, 143);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC, 90,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);

    /* Add the below logical flow equivalent OF rules in 'in_port_sec_nd'
     * table.
     * priority: 90
     * match - "inport == pb->port && eth.src == ps_addr.ea &&
     *          ip6.src == :: && ip6.dst == ff02::/16 && icmp6 &&
     *          icmp6.code == 0 && icmp6.type == 135"
     * action - "next;"
     * description: "Advance the packet for Neighbor solicit check"
     */
    build_port_sec_adv_nd_check(ofpacts);
    match_set_icmp_type(m, 135);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC, 90,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);
}

/* Adds the OF rules to allow IPv6 Neigh discovery packet in
 * 'in_port_sec_nd' table. */
static void
build_in_port_sec_nd_flows(const struct sbrec_port_binding *pb,
                           struct lport_addresses *ps_addr,
                           struct match *m, struct ofpbuf *ofpacts,
                           struct ovn_desired_flow_table *flow_table)
{
    build_port_sec_allow_action(ofpacts);

    /* Add the below logical flow equivalent OF rules in 'in_port_sec_nd'
     * table.
     * priority: 90
     * match - "inport == pb->port && eth.src == ps_addr.ea &&
     *          icmp6 && icmp6.code == 135 && icmp6.type == 0 &&
     *          ip6.tll == 255 && nd.sll == {00:00:00:00:00:00, ps_addr.ea}"
     * action - "port_sec_failed = 0;"
     */
    reset_match_for_port_sec_flows(pb, MFF_LOG_INPORT, m);
    match_set_dl_type(m, htons(ETH_TYPE_IPV6));
    match_set_nw_proto(m, IPPROTO_ICMPV6);
    match_set_nw_ttl(m, 255);
    match_set_icmp_type(m, 135);
    match_set_icmp_code(m, 0);

    match_set_arp_sha(m, eth_addr_zero);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC_ND, 90,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);

    match_set_arp_sha(m, ps_addr->ea);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC_ND, 90,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);

    match_set_icmp_type(m, 136);
    match_set_icmp_code(m, 0);
    if (ps_addr->n_ipv6_addrs) {
        /* Add the below logical flow equivalent OF rules in 'in_port_sec_nd'
         * table if IPv6 addresses are configured.
         * priority: 90
         * match - "inport == pb->port && eth.src == ps_addr.ea && icmp6 &&
         *          icmp6.code == 136 && icmp6.type == 0 && ip6.tll == 255 &&
         *          nd.tll == {00:00:00:00:00:00, ps_addr.ea} &&
         *          nd.target == {ps_addr.ipv6_addrs, lla}"
         * action - "port_sec_failed = 0;"
         */
        struct in6_addr lla;
        in6_generate_lla(ps_addr->ea, &lla);
        match_set_arp_tha(m, eth_addr_zero);

        match_set_nd_target(m, &lla);
        ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC_ND, 90,
                        pb->header_.uuid.parts[0], m, ofpacts,
                        &pb->header_.uuid);
        match_set_arp_tha(m, ps_addr->ea);
        match_set_nd_target(m, &lla);
        ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC_ND, 90,
                        pb->header_.uuid.parts[0], m, ofpacts,
                        &pb->header_.uuid);

        for (size_t j = 0; j < ps_addr->n_ipv6_addrs; j++) {
            reset_match_for_port_sec_flows(pb, MFF_LOG_INPORT, m);
            match_set_dl_src(m, ps_addr->ea);
            match_set_dl_type(m, htons(ETH_TYPE_IPV6));
            match_set_nw_proto(m, IPPROTO_ICMPV6);
            match_set_icmp_type(m, 136);
            match_set_icmp_code(m, 0);
            match_set_arp_tha(m, eth_addr_zero);

            if (ps_addr->ipv6_addrs[j].plen == 128
                || !ipv6_addr_is_host_zero(&ps_addr->ipv6_addrs[j].addr,
                                            &ps_addr->ipv6_addrs[j].mask)) {
                match_set_nd_target(m, &ps_addr->ipv6_addrs[j].addr);
            } else {
                match_set_nd_target_masked(m, &ps_addr->ipv6_addrs[j].network,
                                           &ps_addr->ipv6_addrs[j].mask);
            }

            ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC_ND, 90,
                            pb->header_.uuid.parts[0], m, ofpacts,
                            &pb->header_.uuid);

            match_set_arp_tha(m, ps_addr->ea);
            ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC_ND, 90,
                            pb->header_.uuid.parts[0], m, ofpacts,
                            &pb->header_.uuid);
        }
    } else {
        /* Add the below logical flow equivalent OF rules in 'in_port_sec_nd'
         * table if no IPv6 addresses are configured.
         * priority: 90
         * match - "inport == pb->port && eth.src == ps_addr.ea && icmp6 &&
         *          icmp6.code == 136 && icmp6.type == 0 && ip6.tll == 255 &&
         *          nd.tll == {00:00:00:00:00:00, ps_addr.ea}"
         * action - "port_sec_failed = 0;"
         */
        match_set_arp_tha(m, eth_addr_zero);
        ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC_ND, 90,
                        pb->header_.uuid.parts[0], m, ofpacts,
                        &pb->header_.uuid);

        match_set_arp_tha(m, ps_addr->ea);
        ofctrl_add_flow(flow_table, OFTABLE_CHK_IN_PORT_SEC_ND, 90,
                        pb->header_.uuid.parts[0], m, ofpacts,
                        &pb->header_.uuid);
    }
}

static void
build_out_port_sec_no_ip_flows(const struct sbrec_port_binding *pb,
                               struct lport_addresses *ps_addr,
                               struct match *m, struct ofpbuf *ofpacts,
                               struct ovn_desired_flow_table *flow_table)
{
    /* Add the below logical flow equivalent OF rules in 'out_port_sec' table.
     * priority: 85
     * match - "outport == pb->logical_port && eth.dst == ps_addr.ea"
     * action - "port_sec_failed = 0;"
     * description: "Allow the packet if eth.dst matches."
     */
    reset_match_for_port_sec_flows(pb, MFF_LOG_OUTPORT, m);
    match_set_dl_dst(m, ps_addr->ea);
    build_port_sec_allow_action(ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_OUT_PORT_SEC, 85,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);
}

static void
build_out_port_sec_ip4_flows(const struct sbrec_port_binding *pb,
                            struct lport_addresses *ps_addr,
                            struct match *m, struct ofpbuf *ofpacts,
                            struct ovn_desired_flow_table *flow_table)
{
    if (!ps_addr->n_ipv4_addrs && !ps_addr->n_ipv6_addrs) {
         /* No IPv4 and no IPv6 addresses in the port security.
          * Both IPv4 and IPv6 traffic should be delivered to the
          * lport. build_out_port_sec_no_ip_flows() takes care of
          * adding the required flow(s) to allow. */
        return;
    }

    /* Add the below logical flow equivalent OF rules in 'out_port_sec' table.
     * priority: 90
     * match - "outport == pb->logical_port && eth.dst == ps_addr.ea && ip4"
     * action - "port_sec_failed = 1;"
     * description: Default drop IPv4 packets.  If IPv4 addresses are
     *              configured, then higher priority flows are added
     *              to allow specific IPv4 packets.
     */
    reset_match_for_port_sec_flows(pb, MFF_LOG_OUTPORT, m);
    match_set_dl_dst(m, ps_addr->ea);
    match_set_dl_type(m, htons(ETH_TYPE_IP));
    build_port_sec_deny_action(ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_OUT_PORT_SEC, 90,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);

    if (!ps_addr->n_ipv4_addrs) {
        return;
    }

    /* Add the below logical flow equivalent OF rules in 'out_port_sec' table.
     * priority: 95
     * match - "outport == pb->logical_port && eth.dst == ps_addr.ea &&
     *          ip4.dst == {ps_addr.ipv4_addrs, 255.255.255.255, 224.0.0.0/4},"
     * action - "port_sec_failed = 0;"
     */
    build_port_sec_allow_action(ofpacts);
    for (size_t j = 0; j < ps_addr->n_ipv4_addrs; j++) {
        reset_match_for_port_sec_flows(pb, MFF_LOG_OUTPORT, m);
        match_set_dl_dst(m, ps_addr->ea);
        match_set_dl_type(m, htons(ETH_TYPE_IP));
        ovs_be32 mask = ps_addr->ipv4_addrs[j].mask;
        if (ps_addr->ipv4_addrs[j].plen == 32
                || ps_addr->ipv4_addrs[j].addr & ~mask) {

            if (ps_addr->ipv4_addrs[j].plen != 32) {
                /* Special case to allow bcast traffic.
                 * Eg. If ps_addr is 10.0.0.4/24, then add the below flow
                 * priority: 95
                 * match - "outport == pb->logical_port &&
                 *          eth.dst == ps_addr.ea &&
                 *          ip4.dst == 10.0.0.255"
                 * action - "port_sec_failed = 0;"
                 */
                ovs_be32 bcast_addr;
                ovs_assert(ip_parse(ps_addr->ipv4_addrs[j].bcast_s,
                                    &bcast_addr));
                match_set_nw_dst(m, bcast_addr);
                ofctrl_add_flow(flow_table, OFTABLE_CHK_OUT_PORT_SEC, 95,
                                pb->header_.uuid.parts[0], m, ofpacts,
                                &pb->header_.uuid);
            }

            match_set_nw_dst(m, ps_addr->ipv4_addrs[j].addr);
        } else {
            /* host portion is zero */
            match_set_nw_dst_masked(m, ps_addr->ipv4_addrs[j].addr,
                                    mask);
        }

        ofctrl_add_flow(flow_table, OFTABLE_CHK_OUT_PORT_SEC, 95,
                        pb->header_.uuid.parts[0], m, ofpacts,
                        &pb->header_.uuid);
    }

    reset_match_for_port_sec_flows(pb, MFF_LOG_OUTPORT, m);
    match_set_dl_dst(m, ps_addr->ea);
    match_set_dl_type(m, htons(ETH_TYPE_IP));

    ovs_be32 ip4 = htonl(0xffffffff);
    match_set_nw_dst(m, ip4);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_OUT_PORT_SEC, 95,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);

    /* Allow 224.0.0.0/4 traffic. */
    ip4 = htonl(0xe0000000);
    ovs_be32 mask = htonl(0xf0000000);
    match_set_nw_dst_masked(m, ip4, mask);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_OUT_PORT_SEC, 95,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);
}

static void
build_out_port_sec_ip6_flows(const struct sbrec_port_binding *pb,
                            struct lport_addresses *ps_addr,
                            struct match *m, struct ofpbuf *ofpacts,
                            struct ovn_desired_flow_table *flow_table)
{
    if (!ps_addr->n_ipv4_addrs && !ps_addr->n_ipv6_addrs) {
        /* No IPv4 and no IPv6 addresses in the port security.
         * Both IPv4 and IPv6 traffic should be delivered to the
         * lport. build_out_port_sec_no_ip_flows() takes care of
         * adding the required flow(s) to allow. */
        return;
    }

    /* Add the below logical flow equivalent OF rules in 'out_port_sec' table.
     * priority: 90
     * match - "outport == pb->logical_port && eth.dst == ps_addr.ea && ip6"
     * action - "port_sec_failed = 1;"
     * description: Default drop IPv6 packets.  If IPv6 addresses are
     *              configured, then higher priority flows are added
     *              to allow specific IPv6 packets.
     */
    reset_match_for_port_sec_flows(pb, MFF_LOG_OUTPORT, m);
    match_set_dl_dst(m, ps_addr->ea);
    match_set_dl_type(m, htons(ETH_TYPE_IPV6));
    build_port_sec_deny_action(ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_OUT_PORT_SEC, 90,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);

    if (!ps_addr->n_ipv6_addrs) {
        return;
    }

    /* Add the below logical flow equivalent OF rules in 'out_port_sec' table.
     * priority: 95
     * match - "outport == pb->logical_port && eth.dst == ps_addr.ea &&
     *          ip6.dst == {ps_addr.ipv6_addrs, lla, ff00::/8},"
     * action - "port_sec_failed = 0;"
     */
    build_port_sec_allow_action(ofpacts);
    for (size_t j = 0; j < ps_addr->n_ipv6_addrs; j++) {
        reset_match_for_port_sec_flows(pb, MFF_LOG_OUTPORT, m);
        match_set_dl_dst(m, ps_addr->ea);
        match_set_dl_type(m, htons(ETH_TYPE_IPV6));

        if (ps_addr->ipv6_addrs[j].plen == 128
            || !ipv6_addr_is_host_zero(&ps_addr->ipv6_addrs[j].addr,
                                        &ps_addr->ipv6_addrs[j].mask)) {
            match_set_ipv6_dst(m, &ps_addr->ipv6_addrs[j].addr);
        } else {
            match_set_ipv6_dst_masked(m, &ps_addr->ipv6_addrs[j].network,
                                      &ps_addr->ipv6_addrs[j].mask);
        }

        ofctrl_add_flow(flow_table, OFTABLE_CHK_OUT_PORT_SEC, 95,
                        pb->header_.uuid.parts[0], m, ofpacts,
                        &pb->header_.uuid);
    }

    struct in6_addr lla;
    in6_generate_lla(ps_addr->ea, &lla);

    reset_match_for_port_sec_flows(pb, MFF_LOG_OUTPORT, m);
    match_set_dl_dst(m, ps_addr->ea);
    match_set_dl_type(m, htons(ETH_TYPE_IPV6));
    match_set_ipv6_dst(m, &lla);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_OUT_PORT_SEC, 95,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);

    struct in6_addr ip6, mask;
    char *err = ipv6_parse_masked("ff00::/8", &ip6, &mask);
    ovs_assert(!err);

    match_set_ipv6_dst_masked(m, &ip6, &mask);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_OUT_PORT_SEC, 95,
                    pb->header_.uuid.parts[0], m, ofpacts,
                    &pb->header_.uuid);
}

static void
consider_port_sec_flows(const struct sbrec_port_binding *pb,
                        struct ovn_desired_flow_table *flow_table)
{
    if (!pb->n_port_security) {
        return;
    }

    struct lport_addresses *ps_addrs;   /* Port security addresses. */
    size_t n_ps_addrs = 0;

    ps_addrs = xmalloc(sizeof *ps_addrs * pb->n_port_security);
    for (size_t i = 0; i < pb->n_port_security; i++) {
        if (!extract_lsp_addresses(pb->port_security[i],
                                    &ps_addrs[n_ps_addrs])) {
            static struct vlog_rate_limit rl
                = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_INFO_RL(&rl, "invalid syntax '%s' in port "
                         "security. No MAC address found",
                         pb->port_security[i]);
            continue;
        }
        n_ps_addrs++;
    }

    if (!n_ps_addrs) {
        free(ps_addrs);
        return;
    }

    struct match match = MATCH_CATCHALL_INITIALIZER;
    uint64_t stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);

    build_in_port_sec_default_flows(pb, &match, &ofpacts, flow_table);

    for (size_t i = 0; i < n_ps_addrs; i++) {
        build_in_port_sec_no_ip_flows(pb, &ps_addrs[i], &match, &ofpacts,
                                      flow_table);
        build_in_port_sec_ip4_flows(pb, &ps_addrs[i], &match, &ofpacts,
                                    flow_table);
        build_in_port_sec_arp_flows(pb, &ps_addrs[i], &match, &ofpacts,
                                    flow_table);
        build_in_port_sec_ip6_flows(pb, &ps_addrs[i], &match, &ofpacts,
                                    flow_table);
        build_in_port_sec_nd_flows(pb, &ps_addrs[i], &match, &ofpacts,
                                   flow_table);
    }

    /* Out port security. */

    /* Add the below logical flow equivalent OF rules in 'out_port_sec_nd'
     * table.
     * priority: 80
     * match - "outport == pb->logical_port"
     * action - "port_sec_failed = 1;"
     * descrption: "Drop all traffic"
     */
    reset_match_for_port_sec_flows(pb, MFF_LOG_OUTPORT, &match);
    build_port_sec_deny_action(&ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_CHK_OUT_PORT_SEC, 80,
                    pb->header_.uuid.parts[0], &match, &ofpacts,
                    &pb->header_.uuid);

    for (size_t i = 0; i < n_ps_addrs; i++) {
        build_out_port_sec_no_ip_flows(pb, &ps_addrs[i], &match, &ofpacts,
                                       flow_table);
        build_out_port_sec_ip4_flows(pb, &ps_addrs[i], &match, &ofpacts,
                                       flow_table);
        build_out_port_sec_ip6_flows(pb, &ps_addrs[i], &match, &ofpacts,
                                       flow_table);
    }

    ofpbuf_uninit(&ofpacts);
    for (size_t i = 0; i < n_ps_addrs; i++) {
        destroy_lport_addresses(&ps_addrs[i]);
    }
    free(ps_addrs);
}
