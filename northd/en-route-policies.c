/*
 * Copyright (c) 2026, Red Hat, Inc.
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

#include "en-datapath-logical-router.h"
#include "en-route-policies.h"
#include "northd.h"
#include "ovn-nb-idl.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(en_route_policies);

static struct route_policy *
route_policies_lookup(struct hmap *route_policies, size_t hash,
                      const struct nbrec_logical_router_policy *rule)
{
    struct route_policy *rp;
    HMAP_FOR_EACH_WITH_HASH (rp, key_node, hash, route_policies) {
        if (rp->rule == rule) {
            return rp;
        }
    }

    return NULL;
}

static bool
policy_chain_id(struct simap *chain_ids, const char *chain_name, uint32_t *id)
{
    if (chain_name && *chain_name) {
        *id = simap_get(chain_ids, chain_name);
        return true;
    }

    return false;
}

static void
policy_chain_add(struct simap *chain_ids, const char *chain_name)
{
    uint32_t id = simap_count(chain_ids) + 1;

    if (id == UINT16_MAX) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Too many policy chains for Logical Router.");
        return;
    }

    if (!simap_put(chain_ids, chain_name, id)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Policy chain id unexpectedly appeared");
    }
}

/* Returns true if the output port to be used for forwarding traffic through
 * this policy could be determined.  Stores a pointer to the output port
 * in 'p_output_port' and a pointer to the router IP address to be used for
 * this policy, in 'p_lrp_addr_s'. */
static bool
find_policy_outport(struct ovn_datapath *od,
                    const struct nbrec_logical_router_policy *policy,
                    const char *nexthop, bool is_ipv4,
                    const char **p_lrp_addr_s, struct ovn_port **p_out_port)
{
    if (nexthop == NULL) {
        return false;
    }

    struct ovn_port *out_port = NULL;
    const char *lrp_addr_s = NULL;

    if (policy->output_port) {
        if (!find_route_outport(od, policy->output_port->name,
                                "policy", policy->match,
                                nexthop, is_ipv4, true, &out_port,
                                &lrp_addr_s)) {
            return false;
        }
    } else {
        /* If output_port is not specified, find the router port matching
         * the next hop. */
        HMAP_FOR_EACH (out_port, dp_node, &od->ports) {
            lrp_addr_s = lrp_find_member_ip(out_port, nexthop);
            if (lrp_addr_s) {
                break;
            }
        }
    }

    if (!out_port || !lrp_addr_s) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Logical Router: %s, policy "
                          "(chain: '%s', match: '%s', priority %"PRId64"): "
                          "no path for next hop %s",
                     od->nbr->name,
                     policy->chain ? policy->chain : "<Default>",
                     policy->match, policy->priority, nexthop);
        return false;
    }
    if (p_out_port) {
        *p_out_port = out_port;
    }
    if (p_lrp_addr_s) {
        *p_lrp_addr_s = lrp_addr_s;
    }

    return true;
}

static bool
check_bfd_state(const struct nbrec_logical_router_policy *rule,
                struct ovn_port *out_port, const char *nexthop,
                const struct hmap *bfd_connections,
                struct hmap *bfd_active_connections)
{
    struct in6_addr nexthop_v6;
    bool is_nexthop_v6 = ipv6_parse(nexthop, &nexthop_v6);

    for (size_t i = 0; i < rule->n_bfd_sessions; i++) {
        /* Check if there is a BFD session associated to the reroute
         * policy. */
        const struct nbrec_bfd *nb_bt = rule->bfd_sessions[i];
        struct in6_addr dst_ipv6;
        bool is_dst_v6 = ipv6_parse(nb_bt->dst_ip, &dst_ipv6);

        if (is_nexthop_v6 ^ is_dst_v6) {
            continue;
        }

        if ((is_nexthop_v6 && !ipv6_addr_equals(&nexthop_v6, &dst_ipv6)) ||
            strcmp(nb_bt->dst_ip, nexthop)) {
            continue;
        }

        if (strcmp(nb_bt->logical_port, out_port->key)) {
            continue;
        }

        struct bfd_entry *bfd_e = bfd_port_lookup(bfd_connections,
                                                  nb_bt->logical_port,
                                                  nb_bt->dst_ip);
        if (!bfd_e) {
            continue;
        }

        /* This route policy is linked to an active bfd session. */
        struct bfd_entry *bfd_rp = bfd_port_lookup(bfd_active_connections,
                                                   nb_bt->logical_port,
                                                   nb_bt->dst_ip);
        if (!bfd_rp) {
            bfd_rp = bfd_alloc_entry(bfd_active_connections,
                                     nb_bt->logical_port, nb_bt->dst_ip,
                                     bfd_e->status);
        }

        if (!strcmp(bfd_e->status, "admin_down")) {
            bfd_set_status(bfd_rp, "down");
        }

        return strcmp(bfd_rp->status, "down");
    }

    return true;
}

static void
build_route_policies(struct ovn_datapath *od,
                     const struct hmap *bfd_connections,
                     struct hmap *route_policies,
                     struct hmap *bfd_active_connections,
                     struct simap *chain_ids)
{
    /* Create chain numeric ids for policies with chain name set */
    for (int i = 0; i < od->nbr->n_policies; i++) {
        const struct nbrec_logical_router_policy *rule = od->nbr->policies[i];
        uint32_t id;

        if (policy_chain_id(chain_ids, rule->chain, &id) && id == 0) {
            policy_chain_add(chain_ids, rule->chain);
        }
    }

    size_t hash = uuid_hash(&od->key);
    uint32_t ecmp_group_id = 1;
    for (int i = 0; i < od->nbr->n_policies; i++) {
        const struct nbrec_logical_router_policy *rule = od->nbr->policies[i];

        if (route_policies_lookup(route_policies, hash, rule)) {
            continue;
        }

        uint32_t chain_id = 0;
        uint32_t jump_chain_id = 0;

        /* Skip policy if chain name is set but id was not created above */
        if (policy_chain_id(chain_ids, rule->chain, &chain_id)
            && chain_id == 0) {
            continue;
        }

        if (!strcmp(rule->action, "jump")) {
            /* Skip policy if action is 'jump' but no target chain is set */
            if (!policy_chain_id(chain_ids, rule->jump_chain,
                                 &jump_chain_id)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl,
                         "Logical router: %s, policy action 'jump'"
                         " has empty target",
                         od->nbr->name);
                continue;
            }

            /* Skip policy if action is 'jump' but target chain name
               is not resolved to numeric id */
            if (jump_chain_id == 0) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl,
                         "Logical router: %s, policy action 'jump'"
                         " follows to non-existent chain %s",
                         od->nbr->name, rule->jump_chain);
                continue;
            }
        }

        if (simap_is_empty(chain_ids)) {
            chain_id = -1;
        }

        struct vector valid_nexthops =
            VECTOR_EMPTY_INITIALIZER(struct route_policy_nexthop);
        if (!strcmp(rule->action, "reroute")) {
            if (rule->nexthop && rule->nexthop[0]) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "Logical router: %s, policy uses deprecated"
                             " column \"nexthop\", this policy is skipped. "
                             "Please use \"nexthops\" column instead.",
                             od->nbr->name);
                continue;
            }

            if (rule->output_port && rule->n_nexthops != 1) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl,
                             "Logical router: %s, policy "
                             "(chain: '%s', match: '%s', priority %"PRId64"): "
                             "output_port only supported on non-ECMP "
                             "reroute policies",
                             od->nbr->name,
                             rule->chain ? rule->chain : "<Default>",
                             rule->match, rule->priority);
                continue;
            }

            /* Check that all the nexthops belong to the same addr family. */
            bool is_ipv4 = true;
            bool ips_match = true;
            for (size_t j = 0; j < rule->n_nexthops; j++) {
                const char *nexthop = rule->nexthops[j];
                if (!nexthop || !nexthop[0]) {
                    continue;
                }

                bool nexthop_is_ipv4 = !!strchr(nexthop, '.');

                if (j == 0) {
                    is_ipv4 = nexthop_is_ipv4;
                }

                if (nexthop_is_ipv4 != is_ipv4) {
                    static struct vlog_rate_limit rl =
                        VLOG_RATE_LIMIT_INIT(5, 1);
                    VLOG_WARN_RL(&rl, "nexthop [%s] of the router policy with "
                                 "the match [%s] does not belong to the same "
                                 "address family as other next hops",
                                 rule->nexthops[j], rule->match);
                    ips_match = false;
                    break;
                }
            }
            if (!ips_match) {
                continue;
            }

            vector_reserve(&valid_nexthops, rule->n_nexthops);
            for (size_t j = 0; j < rule->n_nexthops; j++) {
                char *nexthop = rule->nexthops[j];
                if (!nexthop || !nexthop[0]) {
                    continue;
                }

                struct ovn_port *out_port = NULL;
                const char *lrp_addr_s = NULL;

                if (!find_policy_outport(od, rule, nexthop, is_ipv4,
                                         &lrp_addr_s, &out_port)) {
                    continue;
                }
                if (!check_bfd_state(rule, out_port, nexthop,
                                     bfd_connections,
                                     bfd_active_connections)) {
                    continue;
                }
                struct route_policy_nexthop policy_nexthop = {
                    .nexthop_addr = nexthop,
                    .outport_key = out_port->nbrp->name,
                };
                strncpy(policy_nexthop.src_addr, lrp_addr_s,
                        sizeof(policy_nexthop.src_addr) - 1);
                vector_push(&valid_nexthops, &policy_nexthop);
            }

            if (vector_len(&valid_nexthops) == 0) {
                vector_destroy(&valid_nexthops);
                continue;
            }
        }

        uint32_t group = 0;
        if (vector_len(&valid_nexthops) > 1) {
            if (ecmp_group_id >= UINT16_MAX) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "Exhausted the range of ECMP group IDs for "
                             "logical router policies. Any further ECMP "
                             "routes will be skipped.");
                vector_destroy(&valid_nexthops);
                continue;
            }
            group = ecmp_group_id++;
        }
        struct route_policy *new_rp = xmalloc(sizeof *new_rp);
        *new_rp = (struct route_policy) {
            .rule = rule,
            .valid_nexthops = vector_steal(&valid_nexthops),
            .chain_id = chain_id,
            .jump_chain_id = jump_chain_id,
            .ecmp_group_id = group,
        };
        hmap_insert(route_policies, &new_rp->key_node, hash);
    }
}

static void
route_policies_init(struct route_policies_data *data)
{
    hmap_init(&data->route_policies);
    hmap_init(&data->bfd_active_connections);
}

static void
route_policies_destroy(struct route_policies_data *data)
{
    struct route_policy *rp;
    HMAP_FOR_EACH_POP (rp, key_node, &data->route_policies) {
        vector_destroy(&rp->valid_nexthops);
        free(rp);
    };
    hmap_destroy(&data->route_policies);
    bfd_destroy(&data->bfd_active_connections);
}

enum engine_node_state
en_route_policies_run(struct engine_node *node, void *data)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    struct bfd_data *bfd_data = engine_get_input_data("bfd", node);
    struct route_policies_data *route_policies_data = data;

    route_policies_destroy(data);
    route_policies_init(data);

    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &northd_data->lr_datapaths.datapaths) {
        struct simap chain_ids = SIMAP_INITIALIZER(&chain_ids);

        build_route_policies(od, &bfd_data->bfd_connections,
                             &route_policies_data->route_policies,
                             &route_policies_data->bfd_active_connections,
                             &chain_ids);
        simap_destroy(&chain_ids);
    }

    return EN_UPDATED;
}

void
*en_route_policies_init(struct engine_node *node OVS_UNUSED,
                        struct engine_arg *arg OVS_UNUSED)
{
    struct route_policies_data *data = xzalloc(sizeof *data);

    route_policies_init(data);
    return data;
}

void
en_route_policies_cleanup(void *data)
{
    route_policies_destroy(data);
}

enum engine_input_handler_result
route_policies_northd_change_handler(struct engine_node *node,
                                     void *data OVS_UNUSED)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_has_tracked_data(&northd_data->trk_data)) {
        return EN_UNHANDLED;
    }

    /* This node uses the below data from the en_northd engine node.
     * See (lr_stateful_get_input_data())
     *   1. northd_data->lr_datapaths
     *      This data gets updated when a logical router or logical router port
     *      is created or deleted.
     *      Northd engine node presently falls back to full recompute when
     *      this happens and so does this node.
     */

    return EN_HANDLED_UNCHANGED;
}

enum engine_input_handler_result
route_policies_datapath_synced_logical_router_handler(struct engine_node *node,
                                                      void *data OVS_UNUSED)
{
    const struct ovn_synced_logical_router_map *synced_lrs =
        engine_get_input_data("datapath_synced_logical_router", node);

    if (hmapx_is_empty(&synced_lrs->new) &&
        hmapx_is_empty(&synced_lrs->updated) &&
        hmapx_is_empty(&synced_lrs->deleted)) {
        return EN_UNHANDLED;
    }

    struct hmapx_node *lr_node;
    HMAPX_FOR_EACH (lr_node, &synced_lrs->deleted) {
        const struct ovn_synced_logical_router *lr = lr_node->data;
        if (lr->nb->n_policies > 0) {
            return EN_UNHANDLED;
        }
    }

    HMAPX_FOR_EACH (lr_node, &synced_lrs->new) {
        const struct ovn_synced_logical_router *lr = lr_node->data;
        if (lr->nb->n_policies > 0) {
            return EN_UNHANDLED;
        }
    }

    HMAPX_FOR_EACH (lr_node, &synced_lrs->updated) {
        const struct ovn_synced_logical_router *lr = lr_node->data;
        if (nbrec_logical_router_is_updated(
                lr->nb, NBREC_LOGICAL_ROUTER_COL_POLICIES)) {
            return EN_UNHANDLED;
        }
        for (size_t i = 0; i < lr->nb->n_policies; i++) {
            if (nbrec_logical_router_policy_row_get_seqno(lr->nb->policies[i],
                                    OVSDB_IDL_CHANGE_MODIFY) > 0) {
                return EN_UNHANDLED;
            }
        }
    }

    return EN_HANDLED_UNCHANGED;
}
