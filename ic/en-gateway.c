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

#include "en-az.h"
#include "en-gateway.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "openvswitch/vlog.h"
#include "ovn-ic.h"

VLOG_DEFINE_THIS_MODULE(en_ic_gateway);

/* Returns true if any information in gw and chassis is different. */
static bool
is_gateway_data_changed(const struct icsbrec_gateway *gw,
                   const struct sbrec_chassis *chassis)
{
    if (strcmp(gw->hostname, chassis->hostname)) {
        return true;
    }

    if (gw->n_encaps != chassis->n_encaps) {
        return true;
    }

    for (size_t g = 0; g < gw->n_encaps; g++) {
        bool found = false;
        const struct icsbrec_encap *gw_encap = gw->encaps[g];
        for (size_t s = 0; s < chassis->n_encaps; s++) {
            const struct sbrec_encap *chassis_encap = chassis->encaps[s];
            if (!strcmp(gw_encap->type, chassis_encap->type) &&
                !strcmp(gw_encap->ip, chassis_encap->ip)) {
                found = true;
                if (!smap_equal(&gw_encap->options, &chassis_encap->options)) {
                    return true;
                }
                break;
            }
        }
        if (!found) {
            return true;
        }
    }

    return false;
}

static void
sync_isb_gw_to_sb(struct ic_context *ctx,
                  const struct icsbrec_gateway *gw,
                  const struct sbrec_chassis *chassis)
{
    struct smap temp_map;
    sbrec_chassis_set_hostname(chassis, gw->hostname);
    smap_clone(&temp_map, &chassis->other_config);
    smap_replace(&temp_map, "is-remote", "true");
    /* Use sbrec_chassis_set_other_config instead of
     * sbrec_chassis_update_other_config_setkey so the in-memory datum is
     * updated for reads in the same loop iteration. */
    sbrec_chassis_set_other_config(chassis, &temp_map);
    smap_destroy(&temp_map);

    /* Sync encaps used by this gateway. */
    ovs_assert(gw->n_encaps);
    struct sbrec_encap *sb_encap;
    struct sbrec_encap **sb_encaps =
        xmalloc(gw->n_encaps * sizeof *sb_encaps);
    for (size_t i = 0; i < gw->n_encaps; i++) {
        sb_encap = sbrec_encap_insert(ctx->ovnsb_txn);
        sbrec_encap_set_chassis_name(sb_encap, gw->name);
        sbrec_encap_set_ip(sb_encap, gw->encaps[i]->ip);
        sbrec_encap_set_type(sb_encap, gw->encaps[i]->type);
        sbrec_encap_set_options(sb_encap, &gw->encaps[i]->options);
        sb_encaps[i] = sb_encap;
    }
    sbrec_chassis_set_encaps(chassis, sb_encaps, gw->n_encaps);
    free(sb_encaps);
}

static void
sync_sb_gw_to_isb(struct ic_context *ctx,
                  const struct sbrec_chassis *chassis,
                  const struct icsbrec_gateway *gw)
{
    icsbrec_gateway_set_hostname(gw, chassis->hostname);

    /* Sync encaps used by this chassis. */
    ovs_assert(chassis->n_encaps);
    struct icsbrec_encap *isb_encap;
    struct icsbrec_encap **isb_encaps =
        xmalloc(chassis->n_encaps * sizeof *isb_encaps);
    for (size_t i = 0; i < chassis->n_encaps; i++) {
        isb_encap = icsbrec_encap_insert(ctx->ovnisb_unlocked_txn);
        icsbrec_encap_set_gateway_name(isb_encap,
                                      chassis->name);
        icsbrec_encap_set_ip(isb_encap, chassis->encaps[i]->ip);
        icsbrec_encap_set_type(isb_encap,
                              chassis->encaps[i]->type);
        icsbrec_encap_set_options(isb_encap,
                                 &chassis->encaps[i]->options);
        isb_encaps[i] = isb_encap;
    }
    icsbrec_gateway_set_encaps(gw, isb_encaps,
                              chassis->n_encaps);
    free(isb_encaps);
}

/* Returns true if it ran to completion, false if the IC-SB/SB transactions
 * needed to sync were not available (in which case the caller should report
 * that the node is still stale). */
static bool
gateway_run(struct ic_context *ctx,
            const struct icsbrec_availability_zone *runned_az)
{
    if (!ctx->ovnisb_unlocked_txn || !ctx->ovnsb_txn) {
        return false;
    }

    struct shash local_gws = SHASH_INITIALIZER(&local_gws);
    struct shash remote_gws = SHASH_INITIALIZER(&remote_gws);
    const struct icsbrec_gateway *gw;
    ICSBREC_GATEWAY_FOR_EACH (gw, ctx->ovnisb_unlocked_idl) {
        if (gw->availability_zone == runned_az) {
            shash_add(&local_gws, gw->name, gw);
        } else {
            shash_add(&remote_gws, gw->name, gw);
        }
    }

    const struct sbrec_chassis *chassis;
    SBREC_CHASSIS_FOR_EACH (chassis, ctx->ovnsb_idl) {
        if (smap_get_bool(&chassis->other_config, "is-interconn", false)) {
            gw = shash_find_and_delete(&local_gws, chassis->name);
            if (!gw) {
                gw = icsbrec_gateway_insert(ctx->ovnisb_unlocked_txn);
                icsbrec_gateway_set_availability_zone(gw, runned_az);
                icsbrec_gateway_set_name(gw, chassis->name);
                sync_sb_gw_to_isb(ctx, chassis, gw);
            } else if (is_gateway_data_changed(gw, chassis)) {
                sync_sb_gw_to_isb(ctx, chassis, gw);
            }
        } else if (smap_get_bool(&chassis->other_config, "is-remote", false)) {
            gw = shash_find_and_delete(&remote_gws, chassis->name);
            if (!gw) {
                sbrec_chassis_delete(chassis);
            } else if (is_gateway_data_changed(gw, chassis)) {
                sync_isb_gw_to_sb(ctx, gw, chassis);
            }
        }
    }

    /* Delete extra gateways from ISB for the local AZ */
    struct shash_node *node;
    SHASH_FOR_EACH (node, &local_gws) {
        icsbrec_gateway_delete(node->data);
    }
    shash_destroy(&local_gws);

    /* Create SB chassis for remote gateways in ISB */
    SHASH_FOR_EACH (node, &remote_gws) {
        gw = node->data;
        chassis = sbrec_chassis_insert(ctx->ovnsb_txn);
        sbrec_chassis_set_name(chassis, gw->name);
        sync_isb_gw_to_sb(ctx, gw, chassis);
    }
    shash_destroy(&remote_gws);

    return true;
}

/* Returns the IC-SB gateway named 'name' whose availability zone is (when
 * 'local') or is not (otherwise) this instance's AZ, or NULL.  There is no
 * index on Gateway by name, but the number of gateways is small. */
static const struct icsbrec_gateway *
find_gw_by_name(struct ic_context *ctx,
                const struct icsbrec_availability_zone *runned_az,
                const char *name, bool local)
{
    const struct icsbrec_gateway *gw;
    ICSBREC_GATEWAY_FOR_EACH (gw, ctx->ovnisb_unlocked_idl) {
        if ((gw->availability_zone == runned_az) == local
            && !strcmp(gw->name, name)) {
            return gw;
        }
    }
    return NULL;
}

/* Incremental handler for en_gateway's SB Chassis input.  Mirrors the
 * SB-Chassis-driven half of gateway_run() for the tracked chassis only:
 * an is-interconn chassis maintains its local IC-SB gateway, while an
 * is-remote chassis (one we created from a remote gateway) is re-synced or
 * deleted.  Returns EN_UNHANDLED to fall back to a full recompute for cases
 * that cannot be handled incrementally, and EN_HANDLED_UNCHANGED when the
 * tracked chassis required no write at all. */
static enum engine_input_handler_result
sync_gateway_handle_sb_chassis(
    struct ic_context *ctx,
    const struct icsbrec_availability_zone *runned_az,
    const struct sbrec_chassis_table *tbl)
{
    if (!ctx->ovnisb_unlocked_txn || !ctx->ovnsb_txn) {
        return EN_UNHANDLED;
    }

    bool changed = false;
    const struct sbrec_chassis *chassis;
    SBREC_CHASSIS_TABLE_FOR_EACH_TRACKED (chassis, tbl) {
        const struct icsbrec_gateway *local_gw =
            find_gw_by_name(ctx, runned_az, chassis->name, true);

        if (sbrec_chassis_is_deleted(chassis)) {
            /* The local gateway derived from this chassis (if any) is now
             * orphaned.  IC-SB Gateway is indexed uniquely by name, so a local
             * gateway with this name rules out a remote one: nothing more to
             * do for this chassis. */
            if (local_gw) {
                icsbrec_gateway_delete(local_gw);
                changed = true;
                continue;
            }
            /* If this was a remote chassis we created and the remote gateway
             * still exists, it must be recreated: leave that to a full
             * recompute. */
            if (find_gw_by_name(ctx, runned_az, chassis->name, false)) {
                return EN_UNHANDLED;
            }
            continue;
        }

        if (smap_get_bool(&chassis->other_config, "is-interconn", false)) {
            if (!local_gw) {
                local_gw = icsbrec_gateway_insert(ctx->ovnisb_unlocked_txn);
                icsbrec_gateway_set_availability_zone(local_gw,
                                                      runned_az);
                icsbrec_gateway_set_name(local_gw, chassis->name);
                sync_sb_gw_to_isb(ctx, chassis, local_gw);
                changed = true;
            } else if (is_gateway_data_changed(local_gw, chassis)) {
                sync_sb_gw_to_isb(ctx, chassis, local_gw);
                changed = true;
            }
        } else {
            /* No longer an interconn chassis: drop any local gateway derived
             * from it. */
            if (local_gw) {
                icsbrec_gateway_delete(local_gw);
                changed = true;
            }
            if (smap_get_bool(&chassis->other_config, "is-remote", false)) {
                const struct icsbrec_gateway *remote_gw =
                    find_gw_by_name(ctx, runned_az, chassis->name, false);
                if (!remote_gw) {
                    sbrec_chassis_delete(chassis);
                    changed = true;
                } else if (is_gateway_data_changed(remote_gw, chassis)) {
                    sync_isb_gw_to_sb(ctx, remote_gw, chassis);
                    changed = true;
                }
            }
        }
    }

    return changed ? EN_HANDLED_UPDATED : EN_HANDLED_UNCHANGED;
}

/* Incremental handler for en_gateway's IC-SB Gateway input.  Mirrors the
 * remote-gateway-driven half of gateway_run() for the tracked gateways only:
 * a remote gateway maintains its SB chassis mirror.  Returns EN_UNHANDLED to
 * fall back to a full recompute for cases that cannot be handled
 * incrementally, and EN_HANDLED_UNCHANGED when the tracked gateways required
 * no write at all. */
static enum engine_input_handler_result
sync_gateway_handle_icsb_gateway(
    struct ic_context *ctx,
    const struct icsbrec_availability_zone *runned_az,
    const struct icsbrec_gateway_table *tbl)
{
    if (!ctx->ovnisb_unlocked_txn || !ctx->ovnsb_txn) {
        return EN_UNHANDLED;
    }

    bool changed = false;
    const struct icsbrec_gateway *gw;
    ICSBREC_GATEWAY_TABLE_FOR_EACH_TRACKED (gw, tbl) {
        bool local = gw->availability_zone == runned_az;
        const struct sbrec_chassis *chassis = find_sb_chassis(ctx, gw->name);

        if (icsbrec_gateway_is_deleted(gw)) {
            if (!local && chassis &&
                smap_get_bool(&chassis->other_config, "is-remote", false)) {
                sbrec_chassis_delete(chassis);
                changed = true;
            }
            /* A local gateway disappearing while its interconn chassis still
             * exists needs the chassis-driven recreate path:
             * full recompute. */
            if (local && chassis &&
                smap_get_bool(&chassis->other_config, "is-interconn", false)) {
                return EN_UNHANDLED;
            }
            continue;
        }

        if (local) {
            /* Local gateways are produced from SB chassis (handled by the
             * SB Chassis handler); a create/update here is our own write. */
            continue;
        }

        /* Remote gateway: ensure a matching SB chassis exists and is synced.
         * If the only chassis with this name is a local interconn chassis,
         * this is an unexpected name collision; fall back. */
        if (chassis &&
            smap_get_bool(&chassis->other_config, "is-interconn", false)) {
            return EN_UNHANDLED;
        }
        if (!chassis) {
            chassis = sbrec_chassis_insert(ctx->ovnsb_txn);
            sbrec_chassis_set_name(chassis, gw->name);
            sync_isb_gw_to_sb(ctx, gw, chassis);
            changed = true;
        } else if (is_gateway_data_changed(gw, chassis)) {
            sync_isb_gw_to_sb(ctx, gw, chassis);
            changed = true;
        }
    }

    return changed ? EN_HANDLED_UPDATED : EN_HANDLED_UNCHANGED;
}

enum engine_node_state
en_gateway_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    const struct ed_type_az *az = engine_get_input_data("az", node);

    /* runned_az is resolved by the upstream en_az node.  Without an AZ there
     * is nothing to sync (mirrors the previous main-loop gating). */
    if (!az->runned_az) {
        return EN_UNCHANGED;
    }

    /* If the transactions needed to sync were not available, the node could
     * not be brought up to date; report it as stale so the engine retries. */
    if (!gateway_run(ctx, az->runned_az)) {
        return EN_STALE;
    }

    return EN_UPDATED;
}

enum engine_input_handler_result
en_gateway_sb_chassis_handler(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    const struct ed_type_az *az = engine_get_input_data("az", node);

    if (!az->runned_az) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct sbrec_chassis_table *tbl =
        EN_OVSDB_GET(engine_get_input("SB_chassis", node));

    return sync_gateway_handle_sb_chassis(ctx, az->runned_az, tbl);
}

enum engine_input_handler_result
en_gateway_icsb_gateway_handler(struct engine_node *node,
                                void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    const struct ed_type_az *az = engine_get_input_data("az", node);

    if (!az->runned_az) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct icsbrec_gateway_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICSB_gateway", node));

    return sync_gateway_handle_icsb_gateway(ctx, az->runned_az, tbl);
}

void *
en_gateway_init(struct engine_node *node OVS_UNUSED,
                struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_gateway_cleanup(void *data OVS_UNUSED)
{
}
