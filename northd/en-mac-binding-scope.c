/*
 * Copyright (c) 2026, NVIDIA CORPORATION.  All rights reserved.
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

#include "en-global-config.h"
#include "en-mac-binding-scope.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "northd/aging.h"
#include "northd.h"
#include "openvswitch/hmap.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(mac_binding_scope);

struct scope_constraints {
    const char *chassis;
    const struct sbrec_ha_chassis_group *ha_group;
    const char *network_name;
    const char *ethertype;
    int64_t vlan;
    bool initialized;
};

static const char *
ha_chassis_name(const struct sbrec_ha_chassis *ha_chassis)
{
    return ha_chassis->chassis
           ? ha_chassis->chassis->name
           : smap_get(&ha_chassis->external_ids, "chassis-name");
}

static bool
ha_chassis_group_is_single_chassis(
    const struct sbrec_ha_chassis_group *group, const char *chassis)
{
    const char *group_chassis = group->n_ha_chassis == 1
        ? ha_chassis_name(group->ha_chassis[0]) : NULL;
    return group_chassis && !strcmp(group_chassis, chassis);
}

static bool
ha_chassis_groups_have_same_placement(
    const struct sbrec_ha_chassis_group *a,
    const struct sbrec_ha_chassis_group *b)
{
    if (a == b) {
        return true;
    }
    if (a->n_ha_chassis != b->n_ha_chassis) {
        return false;
    }

    for (size_t i = 0; i < a->n_ha_chassis; i++) {
        const struct sbrec_ha_chassis *a_chassis = a->ha_chassis[i];
        const char *a_name = ha_chassis_name(a_chassis);
        bool found = false;

        for (size_t j = 0; j < b->n_ha_chassis; j++) {
            const struct sbrec_ha_chassis *b_chassis = b->ha_chassis[j];
            const char *b_name = ha_chassis_name(b_chassis);
            if (a_name && b_name && !strcmp(a_name, b_name) &&
                a_chassis->priority == b_chassis->priority) {
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }
    return true;
}

static bool
scope_placements_match(const struct scope_constraints *constraints,
                       const char *chassis,
                       const struct sbrec_ha_chassis_group *ha_group)
{
    if (constraints->chassis && chassis) {
        return !strcmp(constraints->chassis, chassis);
    }
    if (constraints->ha_group && ha_group) {
        return ha_chassis_groups_have_same_placement(
            constraints->ha_group, ha_group);
    }
    if (constraints->chassis && ha_group) {
        return ha_chassis_group_is_single_chassis(
            ha_group, constraints->chassis);
    }
    if (constraints->ha_group && chassis) {
        return ha_chassis_group_is_single_chassis(
            constraints->ha_group, chassis);
    }
    return false;
}

static bool
scope_member_validate(const struct ovn_port *op,
                      struct scope_constraints *constraints,
                      const char **reason)
{
    if (!op->sb || !op->peer || !op->peer->od ||
        vector_len(&op->peer->od->localnet_ports) != 1) {
        *reason = "each member must connect to one localnet port";
        return false;
    }

    const struct ovn_port *localnet = vector_get(
        &op->peer->od->localnet_ports, 0, const struct ovn_port *);
    const char *network_name = smap_get(&localnet->nbsp->options,
                                        "network_name");
    if (!network_name || !network_name[0]) {
        *reason = "the localnet port must have a network_name";
        return false;
    }

    const char *chassis = smap_get(&op->od->nbr->options, "chassis");
    const struct sbrec_ha_chassis_group *ha_group = NULL;
    if (!chassis && op->cr_port && op->cr_port->sb) {
        ha_group = op->cr_port->sb->ha_chassis_group;
    }
    if (!chassis && !ha_group) {
        *reason = "each member must have a gateway chassis placement";
        return false;
    }

    int64_t vlan = localnet->nbsp->n_tag ? localnet->nbsp->tag[0] : 0;
    const char *ethertype = smap_get_def(&localnet->nbsp->options,
                                         "ethtype", "802.1q");
    if (!constraints->initialized) {
        *constraints = (struct scope_constraints) {
            .chassis = chassis,
            .ha_group = ha_group,
            .network_name = network_name,
            .ethertype = ethertype,
            .vlan = vlan,
            .initialized = true,
        };
        return true;
    }

    if (!scope_placements_match(constraints, chassis, ha_group)) {
        *reason = "all members must share one gateway chassis placement";
        return false;
    }
    if (strcmp(constraints->network_name, network_name) ||
        constraints->vlan != vlan ||
        strcmp(constraints->ethertype, ethertype)) {
        *reason = "all members must share one physical L2 domain";
        return false;
    }
    return true;
}

static bool
scope_validate(const struct nbrec_mac_binding_scope *scope,
               const struct northd_data *northd_data,
               struct vector *members, const char **reason)
{
    if (scope->mac_binding_age_threshold &&
        !mac_binding_age_threshold_is_valid(
            scope->mac_binding_age_threshold)) {
        *reason = "the MAC binding aging threshold is invalid";
        return false;
    }

    const struct ovn_port *op;
    struct scope_constraints constraints = {0};

    HMAP_FOR_EACH (op, key_node, &northd_data->lr_ports) {
        if (!op->nbrp || op->primary_port ||
            op->nbrp->mac_binding_scope != scope) {
            continue;
        }
        vector_push(members, &op);
        if (!scope_member_validate(op, &constraints, reason)) {
            return false;
        }
    }

    if (vector_is_empty(members)) {
        *reason = "the scope has no router port members";
        return false;
    }
    return true;
}

static bool
scope_copy_to_sb(const struct nbrec_mac_binding_scope *nb_scope,
                 const struct sbrec_mac_binding_scope *sb_scope,
                 uint32_t binding_key)
{
    bool changed = strcmp(sb_scope->name, nb_scope->name) ||
                   sb_scope->binding_key != binding_key ||
                   sb_scope->n_always_learn_from_arp_request !=
                       nb_scope->n_always_learn_from_arp_request ||
                   (sb_scope->n_always_learn_from_arp_request &&
                    sb_scope->always_learn_from_arp_request[0] !=
                        nb_scope->always_learn_from_arp_request[0]) ||
                   sb_scope->n_disable_garp_rarp !=
                       nb_scope->n_disable_garp_rarp ||
                   (sb_scope->n_disable_garp_rarp &&
                    sb_scope->disable_garp_rarp[0] !=
                        nb_scope->disable_garp_rarp[0]) ||
                   !nullable_string_is_equal(
                       sb_scope->mac_binding_age_threshold,
                       nb_scope->mac_binding_age_threshold);

    sbrec_mac_binding_scope_set_name(sb_scope, nb_scope->name);
    sbrec_mac_binding_scope_set_binding_key(sb_scope, binding_key);
    sbrec_mac_binding_scope_set_always_learn_from_arp_request(
        sb_scope, nb_scope->always_learn_from_arp_request,
        nb_scope->n_always_learn_from_arp_request);
    sbrec_mac_binding_scope_set_disable_garp_rarp(
        sb_scope, nb_scope->disable_garp_rarp,
        nb_scope->n_disable_garp_rarp);
    sbrec_mac_binding_scope_set_mac_binding_age_threshold(
        sb_scope, nb_scope->mac_binding_age_threshold);

    struct smap external_ids;
    smap_clone(&external_ids, &nb_scope->external_ids);
    smap_replace_nocopy(&external_ids, "ovn-nb-id",
                        uuid_to_string(&nb_scope->header_.uuid));
    changed |= !smap_equal(&sb_scope->external_ids, &external_ids);
    sbrec_mac_binding_scope_set_external_ids(sb_scope, &external_ids);
    smap_destroy(&external_ids);
    return changed;
}

void *
en_mac_binding_scope_init(struct engine_node *node OVS_UNUSED,
                          struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

enum engine_node_state
en_mac_binding_scope_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    const struct northd_data *northd_data =
        engine_get_input_data("northd", node);
    const struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);
    const struct nbrec_mac_binding_scope_table *nb_scope_table =
        EN_OVSDB_GET(engine_get_input("NB_mac_binding_scope", node));
    const struct sbrec_mac_binding_scope_table *sb_scope_table =
        EN_OVSDB_GET(engine_get_input("SB_mac_binding_scope", node));
    if (!nbrec_mac_binding_scope_table_first(nb_scope_table) &&
        !sbrec_mac_binding_scope_table_first(sb_scope_table)) {
        return EN_UNCHANGED;
    }

    const struct sbrec_shared_mac_binding_table *shared_mb_table =
        EN_OVSDB_GET(engine_get_input("SB_shared_mac_binding", node));
    const struct sbrec_mac_binding_table *mac_binding_table =
        EN_OVSDB_GET(engine_get_input("SB_mac_binding", node));
    const struct sbrec_port_binding_table *pb_table =
        EN_OVSDB_GET(engine_get_input("SB_port_binding", node));
    bool changed = false;

    struct shash sb_scopes = SHASH_INITIALIZER(&sb_scopes);
    struct hmap binding_keys = HMAP_INITIALIZER(&binding_keys);
    struct hmapx keys_preserved = HMAPX_INITIALIZER(&keys_preserved);
    const struct sbrec_mac_binding_scope *sb_scope;
    SBREC_MAC_BINDING_SCOPE_TABLE_FOR_EACH (sb_scope, sb_scope_table) {
        const char *nb_id = smap_get(&sb_scope->external_ids, "ovn-nb-id");
        if (nb_id && !shash_find(&sb_scopes, nb_id)) {
            shash_add(&sb_scopes, nb_id, CONST_CAST(
                struct sbrec_mac_binding_scope *, sb_scope));
        } else if (nb_id) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Duplicate MAC binding scope for NB UUID %s",
                         nb_id);
        }
        if (sb_scope->binding_key > 0 &&
            sb_scope->binding_key <= OVN_MAX_DP_KEY &&
            ovn_add_tnlid(&binding_keys, sb_scope->binding_key)) {
            hmapx_add(&keys_preserved, CONST_CAST(
                struct sbrec_mac_binding_scope *, sb_scope));
        }
    }

    struct hmapx active_scopes = HMAPX_INITIALIZER(&active_scopes);
    struct hmapx active_pbs = HMAPX_INITIALIZER(&active_pbs);
    struct sset active_lports = SSET_INITIALIZER(&active_lports);
    uint32_t key_hint = 0;
    const struct nbrec_mac_binding_scope *nb_scope;
    NBREC_MAC_BINDING_SCOPE_TABLE_FOR_EACH (nb_scope, nb_scope_table) {
        struct vector members = VECTOR_EMPTY_INITIALIZER(
            const struct ovn_port *);
        const char *reason = NULL;
        bool valid = global_config->features.shared_mac_binding &&
                     scope_validate(nb_scope, northd_data, &members, &reason);
        if (!valid) {
            if (reason) {
                static struct vlog_rate_limit rl =
                    VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "Ignoring MAC binding scope '%s': %s",
                             nb_scope->name, reason);
            }
            vector_destroy(&members);
            continue;
        }

        char nb_id[UUID_LEN + 1];
        snprintf(nb_id, sizeof nb_id, UUID_FMT,
                 UUID_ARGS(&nb_scope->header_.uuid));
        sb_scope = shash_find_and_delete(&sb_scopes, nb_id);
        if (!sb_scope) {
            sb_scope = sbrec_mac_binding_scope_insert(
                eng_ctx->ovnsb_idl_txn);
            changed = true;
        }

        uint32_t key = hmapx_contains(&keys_preserved, sb_scope)
                       ? sb_scope->binding_key
                       : ovn_allocate_tnlid(&binding_keys,
                                            "MAC binding scope", 1,
                                            OVN_MAX_DP_KEY, &key_hint);
        if (!key) {
            vector_destroy(&members);
            continue;
        }

        changed |= scope_copy_to_sb(nb_scope, sb_scope, key);
        hmapx_add(&active_scopes, CONST_CAST(
            struct sbrec_mac_binding_scope *, sb_scope));

        const struct ovn_port *member;
        VECTOR_FOR_EACH (&members, member) {
            hmapx_add(&active_pbs, CONST_CAST(
                struct sbrec_port_binding *, member->sb));
            if (member->sb->mac_binding_scope != sb_scope) {
                sbrec_port_binding_set_mac_binding_scope(member->sb,
                                                         sb_scope);
                changed = true;
            }
            sset_add(&active_lports, member->key);
            if (member->cr_port && member->cr_port->sb) {
                const struct sbrec_port_binding *cr_pb = member->cr_port->sb;
                hmapx_add(&active_pbs, CONST_CAST(
                    struct sbrec_port_binding *, cr_pb));
                if (cr_pb->mac_binding_scope != sb_scope) {
                    sbrec_port_binding_set_mac_binding_scope(cr_pb,
                                                             sb_scope);
                    changed = true;
                }
            }
        }
        vector_destroy(&members);
    }

    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (pb, pb_table) {
        if (pb->mac_binding_scope && !hmapx_contains(&active_pbs, pb)) {
            sbrec_port_binding_set_mac_binding_scope(pb, NULL);
            changed = true;
        }
    }

    const struct sbrec_mac_binding *mb;
    SBREC_MAC_BINDING_TABLE_FOR_EACH (mb, mac_binding_table) {
        if (sset_contains(&active_lports, mb->logical_port)) {
            sbrec_mac_binding_delete(mb);
        }
    }

    const struct sbrec_shared_mac_binding *shared_mb;
    SBREC_SHARED_MAC_BINDING_TABLE_FOR_EACH (shared_mb, shared_mb_table) {
        if (!hmapx_contains(&active_scopes, shared_mb->scope)) {
            sbrec_shared_mac_binding_delete(shared_mb);
        }
    }
    SBREC_MAC_BINDING_SCOPE_TABLE_FOR_EACH (sb_scope, sb_scope_table) {
        if (!hmapx_contains(&active_scopes, sb_scope)) {
            sbrec_mac_binding_scope_delete(sb_scope);
            changed = true;
        }
    }

    shash_destroy(&sb_scopes);
    ovn_destroy_tnlids(&binding_keys);
    hmapx_destroy(&keys_preserved);
    hmapx_destroy(&active_scopes);
    hmapx_destroy(&active_pbs);
    sset_destroy(&active_lports);
    return changed ? EN_UPDATED : EN_UNCHANGED;
}

void
en_mac_binding_scope_cleanup(void *data OVS_UNUSED)
{
}
