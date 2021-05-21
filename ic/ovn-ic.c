/*
 * Copyright (c) 2020 eBay Inc.
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

#include "bitmap.h"
#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "memory.h"
#include "openvswitch/poll-loop.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "stream.h"
#include "stream-ssl.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovn_ic);

static unixctl_cb_func ovn_ic_exit;
static unixctl_cb_func ovn_ic_pause;
static unixctl_cb_func ovn_ic_resume;
static unixctl_cb_func ovn_ic_is_paused;
static unixctl_cb_func ovn_ic_status;

struct ic_context {
    struct ovsdb_idl *ovnnb_idl;
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl *ovninb_idl;
    struct ovsdb_idl *ovnisb_idl;
    struct ovsdb_idl_txn *ovnnb_txn;
    struct ovsdb_idl_txn *ovnsb_txn;
    struct ovsdb_idl_txn *ovninb_txn;
    struct ovsdb_idl_txn *ovnisb_txn;
    struct ovsdb_idl_index *nbrec_ls_by_name;
    struct ovsdb_idl_index *nbrec_port_by_name;
    struct ovsdb_idl_index *sbrec_chassis_by_name;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    struct ovsdb_idl_index *icsbrec_port_binding_by_ts;
};

struct ic_state {
    bool had_lock;
    bool paused;
};

static const char *ovnnb_db;
static const char *ovnsb_db;
static const char *ovn_ic_nb_db;
static const char *ovn_ic_sb_db;
static const char *unixctl_path;

/* SSL options */
static const char *ssl_private_key_file;
static const char *ssl_certificate_file;
static const char *ssl_ca_cert_file;


static void
usage(void)
{
    printf("\
%s: OVN interconnection management daemon\n\
usage: %s [OPTIONS]\n\
\n\
Options:\n\
  --ovnnb-db=DATABASE       connect to ovn-nb database at DATABASE\n\
                            (default: %s)\n\
  --ovnsb-db=DATABASE       connect to ovn-sb database at DATABASE\n\
                            (default: %s)\n\
  --unixctl=SOCKET          override default control socket name\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_nb_db(), default_sb_db());
    daemon_usage();
    vlog_usage();
    stream_usage("database", true, true, false);
}

static const struct icsbrec_availability_zone *
az_run(struct ic_context *ctx)
{
    const struct nbrec_nb_global *nb_global =
        nbrec_nb_global_first(ctx->ovnnb_idl);

    if (!nb_global) {
        VLOG_INFO("NB Global not exist.");
        return NULL;
    }

    /* Delete old AZ if name changes.  Note: if name changed when ovn-ic
     * is not running, one has to manually delete the old AZ with:
     * "ovn-ic-sbctl destroy avail <az>". */
    static char *az_name;
    const struct icsbrec_availability_zone *az;
    if (az_name && strcmp(az_name, nb_global->name)) {
        ICSBREC_AVAILABILITY_ZONE_FOR_EACH (az, ctx->ovnisb_idl) {
            if (!strcmp(az->name, az_name)) {
                icsbrec_availability_zone_delete(az);
                break;
            }
        }
        free(az_name);
        az_name = NULL;
    }

    if (!nb_global->name[0]) {
        return NULL;
    }

    if (!az_name) {
        az_name = xstrdup(nb_global->name);
    }

    if (ctx->ovnisb_txn) {
        ovsdb_idl_txn_add_comment(ctx->ovnisb_txn, "AZ %s", az_name);
    }

    ICSBREC_AVAILABILITY_ZONE_FOR_EACH (az, ctx->ovnisb_idl) {
        if (!strcmp(az->name, az_name)) {
            return az;
        }
    }

    /* Create AZ in ISB */
    if (ctx->ovnisb_txn) {
        VLOG_INFO("Register AZ %s to interconnection DB.", az_name);
        az = icsbrec_availability_zone_insert(ctx->ovnisb_txn);
        icsbrec_availability_zone_set_name(az, az_name);
        return az;
    }
    return NULL;
}

static uint32_t
allocate_ts_dp_key(struct hmap *dp_tnlids)
{
    static uint32_t hint = OVN_MIN_DP_KEY_GLOBAL;
    return ovn_allocate_tnlid(dp_tnlids, "transit switch datapath",
                              OVN_MIN_DP_KEY_GLOBAL, OVN_MAX_DP_KEY_GLOBAL,
                              &hint);
}

static void
ts_run(struct ic_context *ctx)
{
    const struct icnbrec_transit_switch *ts;

    struct hmap dp_tnlids = HMAP_INITIALIZER(&dp_tnlids);
    struct shash isb_dps = SHASH_INITIALIZER(&isb_dps);
    const struct icsbrec_datapath_binding *isb_dp;
    ICSBREC_DATAPATH_BINDING_FOR_EACH (isb_dp, ctx->ovnisb_idl) {
        shash_add(&isb_dps, isb_dp->transit_switch, isb_dp);
        ovn_add_tnlid(&dp_tnlids, isb_dp->tunnel_key);
    }

    /* Sync INB TS to AZ NB */
    if (ctx->ovnnb_txn) {
        struct shash nb_tses = SHASH_INITIALIZER(&nb_tses);
        const struct nbrec_logical_switch *ls;

        /* Get current NB Logical_Switch with other_config:interconn-ts */
        NBREC_LOGICAL_SWITCH_FOR_EACH (ls, ctx->ovnnb_idl) {
            const char *ts_name = smap_get(&ls->other_config, "interconn-ts");
            if (ts_name) {
                shash_add(&nb_tses, ts_name, ls);
            }
        }

        /* Create/update NB Logical_Switch for each TS */
        ICNBREC_TRANSIT_SWITCH_FOR_EACH (ts, ctx->ovninb_idl) {
            ls = shash_find_and_delete(&nb_tses, ts->name);
            if (!ls) {
                ls = nbrec_logical_switch_insert(ctx->ovnnb_txn);
                nbrec_logical_switch_set_name(ls, ts->name);
                nbrec_logical_switch_update_other_config_setkey(ls,
                                                                "interconn-ts",
                                                                ts->name);
            }
            isb_dp = shash_find_data(&isb_dps, ts->name);
            if (isb_dp) {
                int64_t nb_tnl_key = smap_get_int(&ls->other_config,
                                                  "requested-tnl-key",
                                                  0);
                if (nb_tnl_key != isb_dp->tunnel_key) {
                    VLOG_DBG("Set other_config:requested-tnl-key %"PRId64
                             " for transit switch %s in NB.",
                             isb_dp->tunnel_key, ts->name);
                    char *tnl_key_str = xasprintf("%"PRId64,
                                                  isb_dp->tunnel_key);
                    nbrec_logical_switch_update_other_config_setkey(
                        ls, "requested-tnl-key", tnl_key_str);
                    free(tnl_key_str);
                }
            }
        }

        /* Delete extra NB Logical_Switch with other_config:interconn-ts */
        struct shash_node *node;
        SHASH_FOR_EACH (node, &nb_tses) {
            nbrec_logical_switch_delete(node->data);
        }
        shash_destroy(&nb_tses);
    }

    /* Sync TS between INB and ISB.  This is performed after syncing with AZ
     * SB, to avoid uncommitted ISB datapath tunnel key to be synced back to
     * AZ. */
    if (ctx->ovnisb_txn) {
        /* Create ISB Datapath_Binding */
        ICNBREC_TRANSIT_SWITCH_FOR_EACH (ts, ctx->ovninb_idl) {
            isb_dp = shash_find_and_delete(&isb_dps, ts->name);
            if (!isb_dp) {
                /* Allocate tunnel key */
                int64_t dp_key = allocate_ts_dp_key(&dp_tnlids);
                if (!dp_key) {
                    continue;
                }

                isb_dp = icsbrec_datapath_binding_insert(ctx->ovnisb_txn);
                icsbrec_datapath_binding_set_transit_switch(isb_dp, ts->name);
                icsbrec_datapath_binding_set_tunnel_key(isb_dp, dp_key);
            }
        }

        /* Delete extra ISB Datapath_Binding */
        struct shash_node *node;
        SHASH_FOR_EACH (node, &isb_dps) {
            icsbrec_datapath_binding_delete(node->data);
        }
    }
    ovn_destroy_tnlids(&dp_tnlids);
    shash_destroy(&isb_dps);
}

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

    for (int g = 0; g < gw->n_encaps; g++) {

        bool found = false;
        const struct icsbrec_encap *gw_encap = gw->encaps[g];
        for (int s = 0; s < chassis->n_encaps; s++) {
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
    sbrec_chassis_set_hostname(chassis, gw->hostname);
    sbrec_chassis_update_other_config_setkey(chassis, "is-remote", "true");
    /* TODO(lucasagomes): Continue writing the configuration to the
     * external_ids column for backward compatibility with the current
     * systems, this behavior should be removed in the future. */
    sbrec_chassis_update_external_ids_setkey(chassis, "is-remote", "true");

    /* Sync encaps used by this gateway. */
    ovs_assert(gw->n_encaps);
    struct sbrec_encap *sb_encap;
    struct sbrec_encap **sb_encaps =
        xmalloc(gw->n_encaps * sizeof *sb_encaps);
    for (int i = 0; i < gw->n_encaps; i++) {
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
    for (int i = 0; i < chassis->n_encaps; i++) {
        isb_encap = icsbrec_encap_insert(ctx->ovnisb_txn);
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

static void
gateway_run(struct ic_context *ctx, const struct icsbrec_availability_zone *az)
{
    if (!ctx->ovnisb_txn || !ctx->ovnsb_txn) {
        return;
    }

    struct shash local_gws = SHASH_INITIALIZER(&local_gws);
    struct shash remote_gws = SHASH_INITIALIZER(&remote_gws);
    const struct icsbrec_gateway *gw;
    ICSBREC_GATEWAY_FOR_EACH (gw, ctx->ovnisb_idl) {
        if (gw->availability_zone == az) {
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
                gw = icsbrec_gateway_insert(ctx->ovnisb_txn);
                icsbrec_gateway_set_availability_zone(gw, az);
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
}

static const struct nbrec_logical_switch *
find_ts_in_nb(struct ic_context *ctx, char *ts_name)
{
    const struct nbrec_logical_switch *key =
        nbrec_logical_switch_index_init_row(ctx->nbrec_ls_by_name);
    nbrec_logical_switch_index_set_name(key, ts_name);

    const struct nbrec_logical_switch *ls;
    bool found = false;
    NBREC_LOGICAL_SWITCH_FOR_EACH_EQUAL (ls, key, ctx->nbrec_ls_by_name) {
        const char *ls_ts_name = smap_get(&ls->other_config, "interconn-ts");
        if (ls_ts_name && !strcmp(ts_name, ls_ts_name)) {
            found = true;
            break;
        }
    }
    nbrec_logical_switch_index_destroy_row(key);

    if (found) {
        return ls;
    }
    return NULL;
}

static const struct sbrec_port_binding *
find_sb_pb_by_name(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                   const char *name)
{
    const struct sbrec_port_binding *key =
        sbrec_port_binding_index_init_row(sbrec_port_binding_by_name);
    sbrec_port_binding_index_set_logical_port(key, name);

    const struct sbrec_port_binding *pb =
        sbrec_port_binding_index_find(sbrec_port_binding_by_name, key);
    sbrec_port_binding_index_destroy_row(key);

    return pb;
}

static const struct sbrec_port_binding *
find_peer_port(struct ic_context *ctx,
               const struct sbrec_port_binding *sb_pb)
{
    const char *peer_name = smap_get(&sb_pb->options, "peer");
    if (!peer_name) {
        return NULL;
    }

    return find_sb_pb_by_name(ctx->sbrec_port_binding_by_name, peer_name);
}

static const struct sbrec_port_binding *
find_crp_from_lrp(struct ic_context *ctx,
                  const struct sbrec_port_binding *lrp_pb)
{
    char *crp_name = ovn_chassis_redirect_name(lrp_pb->logical_port);

    const struct sbrec_port_binding *pb =
        find_sb_pb_by_name(ctx->sbrec_port_binding_by_name, crp_name);

    free(crp_name);
    return pb;
}

static const struct sbrec_port_binding *
find_crp_for_sb_pb(struct ic_context *ctx,
                   const struct sbrec_port_binding *sb_pb)
{
    const struct sbrec_port_binding *peer = find_peer_port(ctx, sb_pb);
    if (!peer) {
        return NULL;
    }

    return find_crp_from_lrp(ctx, peer);
}

static const char *
get_lrp_address_for_sb_pb(struct ic_context *ctx,
                          const struct sbrec_port_binding *sb_pb)
{
    const struct sbrec_port_binding *peer = find_peer_port(ctx, sb_pb);
    if (!peer) {
        return NULL;
    }

    return peer->n_mac ? *peer->mac : NULL;
}

static const struct sbrec_chassis *
find_sb_chassis(struct ic_context *ctx, const char *name)
{
    const struct sbrec_chassis *key =
        sbrec_chassis_index_init_row(ctx->sbrec_chassis_by_name);
    sbrec_chassis_index_set_name(key, name);

    const struct sbrec_chassis *chassis =
        sbrec_chassis_index_find(ctx->sbrec_chassis_by_name, key);
    sbrec_chassis_index_destroy_row(key);

    return chassis;
}

static void
sync_lsp_tnl_key(const struct nbrec_logical_switch_port *lsp,
                 int64_t isb_tnl_key)
{
    int64_t tnl_key = smap_get_int(&lsp->options, "requested-tnl-key", 0);
    if (tnl_key != isb_tnl_key) {
        VLOG_DBG("Set options:requested-tnl-key %"PRId64
                 " for lsp %s in NB.", isb_tnl_key, lsp->name);
        char *tnl_key_str = xasprintf("%"PRId64, isb_tnl_key);
        nbrec_logical_switch_port_update_options_setkey(lsp,
                                                        "requested-tnl-key",
                                                        tnl_key_str);
        free(tnl_key_str);
    }

}

static bool
get_router_uuid_by_sb_pb(struct ic_context *ctx,
                         const struct sbrec_port_binding *sb_pb,
                         struct uuid *router_uuid)
{
    const struct sbrec_port_binding *router_pb = find_peer_port(ctx, sb_pb);
    if (!router_pb || !router_pb->datapath) {
        return NULL;
    }

    return smap_get_uuid(&router_pb->datapath->external_ids, "logical-router",
                         router_uuid);
}

static void
update_isb_pb_external_ids(struct ic_context *ctx,
                           const struct sbrec_port_binding *sb_pb,
                           const struct icsbrec_port_binding *isb_pb)
{
    struct uuid lr_uuid;
    if (!get_router_uuid_by_sb_pb(ctx, sb_pb, &lr_uuid)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Can't get router uuid for transit switch port %s.",
                     isb_pb->logical_port);
        return;
    }

    struct uuid current_lr_uuid;
    if (smap_get_uuid(&isb_pb->external_ids, "router-id", &current_lr_uuid) &&
        uuid_equals(&lr_uuid, &current_lr_uuid)) {
        return;
    }

    char *uuid_s = xasprintf(UUID_FMT, UUID_ARGS(&lr_uuid));
    icsbrec_port_binding_update_external_ids_setkey(isb_pb, "router-id",
                                                    uuid_s);
    free(uuid_s);
}

/* For each local port:
 *   - Sync from NB to ISB.
 *   - Sync gateway from SB to ISB.
 *   - Sync tunnel key from ISB to NB.
 */
static void
sync_local_port(struct ic_context *ctx,
                const struct icsbrec_port_binding *isb_pb,
                const struct sbrec_port_binding *sb_pb,
                const struct nbrec_logical_switch_port *lsp)
{
    /* Sync address from NB to ISB */
    const char *address = get_lrp_address_for_sb_pb(ctx, sb_pb);
    if (!address) {
        VLOG_DBG("Can't get logical router port address for logical"
                 " switch port %s", sb_pb->logical_port);
        if (isb_pb->address[0]) {
            icsbrec_port_binding_set_address(isb_pb, "");
        }
    } else {
        if (strcmp(address, isb_pb->address)) {
            icsbrec_port_binding_set_address(isb_pb, address);
        }
    }

    /* Sync gateway from SB to ISB */
    const struct sbrec_port_binding *crp = find_crp_for_sb_pb(ctx, sb_pb);
    if (crp && crp->chassis) {
        if (strcmp(crp->chassis->name, isb_pb->gateway)) {
            icsbrec_port_binding_set_gateway(isb_pb, crp->chassis->name);
        }
    } else {
        if (isb_pb->gateway[0]) {
            icsbrec_port_binding_set_gateway(isb_pb, "");
        }
    }

    /* Sync external_ids:router-id to ISB */
    update_isb_pb_external_ids(ctx, sb_pb, isb_pb);

    /* Sync back tunnel key from ISB to NB */
    sync_lsp_tnl_key(lsp, isb_pb->tunnel_key);
}

/* For each remote port:
 *   - Sync from ISB to NB
 *   - Sync gateway from ISB to SB
 */
static void
sync_remote_port(struct ic_context *ctx,
                 const struct icsbrec_port_binding *isb_pb,
                 const struct nbrec_logical_switch_port *lsp,
                 const struct sbrec_port_binding *sb_pb)
{
    /* Sync address from ISB to NB */
    if (isb_pb->address[0]) {
        if (lsp->n_addresses != 1 ||
            strcmp(isb_pb->address, lsp->addresses[0])) {
            nbrec_logical_switch_port_set_addresses(
                lsp, (const char **)&isb_pb->address, 1);
        }
    } else {
        if (lsp->n_addresses != 0) {
            nbrec_logical_switch_port_set_addresses(lsp, NULL, 0);
        }
    }

    /* Sync tunnel key from ISB to NB */
    sync_lsp_tnl_key(lsp, isb_pb->tunnel_key);

    /* Sync gateway from ISB to SB */
    if (isb_pb->gateway[0]) {
        if (!sb_pb->chassis || strcmp(sb_pb->chassis->name, isb_pb->gateway)) {
            const struct sbrec_chassis *chassis =
                find_sb_chassis(ctx, isb_pb->gateway);
            if (!chassis) {
                VLOG_DBG("Chassis %s is not found in SB, syncing from ISB "
                         "to SB skipped for logical port %s.",
                         isb_pb->gateway, lsp->name);
                return;
            }
            sbrec_port_binding_set_chassis(sb_pb, chassis);
        }
    } else {
        if (sb_pb->chassis) {
            sbrec_port_binding_set_chassis(sb_pb, NULL);
        }
    }
}

static void
create_nb_lsp(struct ic_context *ctx,
              const struct icsbrec_port_binding *isb_pb,
              const struct nbrec_logical_switch *ls)
{
    const struct nbrec_logical_switch_port *lsp =
        nbrec_logical_switch_port_insert(ctx->ovnnb_txn);
    nbrec_logical_switch_port_set_name(lsp, isb_pb->logical_port);
    nbrec_logical_switch_port_set_type(lsp, "remote");

    bool up = true;
    nbrec_logical_switch_port_set_up(lsp, &up, 1);

    if (isb_pb->address[0]) {
        nbrec_logical_switch_port_set_addresses(
            lsp, (const char **)&isb_pb->address, 1);
    }
    sync_lsp_tnl_key(lsp, isb_pb->tunnel_key);
    nbrec_logical_switch_update_ports_addvalue(ls, lsp);
}

static void
create_isb_pb(struct ic_context *ctx,
              const struct sbrec_port_binding *sb_pb,
              const struct icsbrec_availability_zone *az,
              const char *ts_name,
              uint32_t pb_tnl_key)
{
    const struct icsbrec_port_binding *isb_pb =
        icsbrec_port_binding_insert(ctx->ovnisb_txn);
    icsbrec_port_binding_set_availability_zone(isb_pb, az);
    icsbrec_port_binding_set_transit_switch(isb_pb, ts_name);
    icsbrec_port_binding_set_logical_port(isb_pb, sb_pb->logical_port);
    icsbrec_port_binding_set_tunnel_key(isb_pb, pb_tnl_key);

    const char *address = get_lrp_address_for_sb_pb(ctx, sb_pb);
    if (address) {
        icsbrec_port_binding_set_address(isb_pb, address);
    }

    const struct sbrec_port_binding *crp = find_crp_for_sb_pb(ctx, sb_pb);
    if (crp && crp->chassis) {
        icsbrec_port_binding_set_gateway(isb_pb, crp->chassis->name);
    }

    update_isb_pb_external_ids(ctx, sb_pb, isb_pb);

    /* XXX: Sync encap so that multiple encaps can be used for the same
     * gateway.  However, it is not needed for now, since we don't yet
     * support specifying encap type/ip for gateway chassis or ha-chassis
     * for logical router port in NB DB, and now encap should always be
     * empty.  The sync can be added if we add such support for gateway
     * chassis/ha-chassis in NB DB. */
}

static const struct sbrec_port_binding *
find_lsp_in_sb(struct ic_context *ctx,
               const struct nbrec_logical_switch_port *lsp)
{
    return find_sb_pb_by_name(ctx->sbrec_port_binding_by_name, lsp->name);
}

static uint32_t
allocate_port_key(struct hmap *pb_tnlids)
{
    static uint32_t hint;
    return ovn_allocate_tnlid(pb_tnlids, "transit port",
                              1, (1u << 15) - 1, &hint);
}

static void
port_binding_run(struct ic_context *ctx,
                 const struct icsbrec_availability_zone *az)
{
    if (!ctx->ovnisb_txn || !ctx->ovnnb_txn || !ctx->ovnsb_txn) {
        return;
    }

    const struct icnbrec_transit_switch *ts;
    ICNBREC_TRANSIT_SWITCH_FOR_EACH (ts, ctx->ovninb_idl) {
        const struct nbrec_logical_switch *ls = find_ts_in_nb(ctx, ts->name);
        if (!ls) {
            VLOG_DBG("Transit switch %s not found in NB.", ts->name);
            continue;
        }
        struct shash local_pbs = SHASH_INITIALIZER(&local_pbs);
        struct shash remote_pbs = SHASH_INITIALIZER(&remote_pbs);
        struct hmap pb_tnlids = HMAP_INITIALIZER(&pb_tnlids);
        const struct icsbrec_port_binding *isb_pb;
        const struct icsbrec_port_binding *isb_pb_key =
            icsbrec_port_binding_index_init_row(
                ctx->icsbrec_port_binding_by_ts);
        icsbrec_port_binding_index_set_transit_switch(isb_pb_key, ts->name);

        ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
                                            ctx->icsbrec_port_binding_by_ts) {
            if (isb_pb->availability_zone == az) {
                shash_add(&local_pbs, isb_pb->logical_port, isb_pb);
            } else {
                shash_add(&remote_pbs, isb_pb->logical_port, isb_pb);
            }
            ovn_add_tnlid(&pb_tnlids, isb_pb->tunnel_key);
        }
        icsbrec_port_binding_index_destroy_row(isb_pb_key);

        const struct nbrec_logical_switch_port *lsp;
        for (int i = 0; i < ls->n_ports; i++) {
            lsp = ls->ports[i];

            const struct sbrec_port_binding *sb_pb = find_lsp_in_sb(ctx, lsp);
            if (!strcmp(lsp->type, "router")) {
                /* The port is local. */
                if (!sb_pb) {
                    continue;
                }
                isb_pb = shash_find_and_delete(&local_pbs, lsp->name);
                if (!isb_pb) {
                    uint32_t pb_tnl_key = allocate_port_key(&pb_tnlids);
                    create_isb_pb(ctx, sb_pb, az, ts->name, pb_tnl_key);
                } else {
                    sync_local_port(ctx, isb_pb, sb_pb, lsp);
                }
            } else if (!strcmp(lsp->type, "remote")) {
                /* The port is remote. */
                isb_pb = shash_find_and_delete(&remote_pbs, lsp->name);
                if (!isb_pb) {
                    nbrec_logical_switch_update_ports_delvalue(ls, lsp);
                } else {
                    if (!sb_pb) {
                        continue;
                    }
                    sync_remote_port(ctx, isb_pb, lsp, sb_pb);
                }
            } else {
                VLOG_DBG("Ignore lsp %s on ts %s with type %s.",
                         lsp->name, ts->name, lsp->type);
            }
        }

        /* Delete extra port-binding from ISB */
        struct shash_node *node;
        SHASH_FOR_EACH (node, &local_pbs) {
            icsbrec_port_binding_delete(node->data);
        }

        /* Create lsp in NB for remote ports */
        SHASH_FOR_EACH (node, &remote_pbs) {
            create_nb_lsp(ctx, node->data, ls);
        }

        shash_destroy(&local_pbs);
        shash_destroy(&remote_pbs);
        ovn_destroy_tnlids(&pb_tnlids);
    }
}

struct ic_router_info {
    struct hmap_node node;
    const struct nbrec_logical_router *lr; /* key of hmap */
    const struct icsbrec_port_binding *isb_pb;
    struct hmap routes_learned;
};

/* Represents an interconnection route entry. */
struct ic_route_info {
    struct hmap_node node;
    struct in6_addr prefix;
    unsigned int plen;
    struct in6_addr nexthop;

    /* Either nb_route or nb_lrp is set and the other one must be NULL.
     * - For a route that is learned from IC-SB, or a static route that is
     *   generated from a route that is configured in NB, the "nb_route"
     *   is set.
     * - For a route that is generated from a direct-connect subnet of
     *   a logical router port, the "nb_lrp" is set. */
    const struct nbrec_logical_router_static_route *nb_route;
    const struct nbrec_logical_router_port *nb_lrp;
};

static uint32_t
ic_route_hash(const struct in6_addr *prefix, unsigned int plen,
              const struct in6_addr *nexthop)
{
    uint32_t basis = hash_bytes(prefix, sizeof *prefix, (uint32_t)plen);
    return hash_bytes(nexthop, sizeof *nexthop, basis);
}

static struct ic_route_info *
ic_route_find(struct hmap *routes, const struct in6_addr *prefix,
              unsigned int plen, const struct in6_addr *nexthop)
{
    struct ic_route_info *r;
    uint32_t hash = ic_route_hash(prefix, plen, nexthop);
    HMAP_FOR_EACH_WITH_HASH (r, node, hash, routes) {
        if (ipv6_addr_equals(&r->prefix, prefix) &&
            r->plen == plen &&
            ipv6_addr_equals(&r->nexthop, nexthop)) {
            return r;
        }
    }
    return NULL;
}

static struct ic_router_info *
ic_router_find(struct hmap *ic_lrs, const struct nbrec_logical_router *lr)
{
    struct ic_router_info *ic_lr;
    HMAP_FOR_EACH_WITH_HASH (ic_lr, node, uuid_hash(&lr->header_.uuid),
                             ic_lrs) {
        if (ic_lr->lr == lr) {
           return ic_lr;
        }
    }
    return NULL;
}

static bool
parse_route(const char *s_prefix, const char *s_nexthop,
            struct in6_addr *prefix, unsigned int *plen,
            struct in6_addr *nexthop)
{
    if (!ip46_parse_cidr(s_prefix, prefix, plen)) {
        return false;
    }

    unsigned int nlen;
    return ip46_parse_cidr(s_nexthop, nexthop, &nlen);
}

/* Return false if can't be added due to bad format. */
static bool
add_to_routes_learned(struct hmap *routes_learned,
                      const struct nbrec_logical_router_static_route *nb_route)
{
    struct in6_addr prefix, nexthop;
    unsigned int plen;
    if (!parse_route(nb_route->ip_prefix, nb_route->nexthop,
                     &prefix, &plen, &nexthop)) {
        return false;
    }
    struct ic_route_info *ic_route = xzalloc(sizeof *ic_route);
    ic_route->prefix = prefix;
    ic_route->plen = plen;
    ic_route->nexthop = nexthop;
    ic_route->nb_route = nb_route;
    hmap_insert(routes_learned, &ic_route->node,
                ic_route_hash(&prefix, plen, &nexthop));
    return true;
}

static bool
get_nexthop_from_lport_addresses(bool is_v4,
                                 const struct lport_addresses *laddr,
                                 struct in6_addr *nexthop)
{
    if (is_v4) {
        if (!laddr->n_ipv4_addrs) {
            return false;
        }
        in6_addr_set_mapped_ipv4(nexthop, laddr->ipv4_addrs[0].addr);
        return true;
    }

    /* ipv6 */
    if (laddr->n_ipv6_addrs) {
        *nexthop = laddr->ipv6_addrs[0].addr;
        return true;
    }

    /* ipv6 link local */
    in6_generate_lla(laddr->ea, nexthop);
    return true;
}

static bool
prefix_is_link_local(struct in6_addr *prefix, unsigned int plen)
{
    if (IN6_IS_ADDR_V4MAPPED(prefix)) {
        /* Link local range is "169.254.0.0/16". */
        if (plen < 16) {
            return false;
        }
        ovs_be32 lla;
        inet_pton(AF_INET, "169.254.0.0", &lla);
        return ((in6_addr_get_mapped_ipv4(prefix) & htonl(0xffff0000)) == lla);
    }

    /* ipv6, link local range is "fe80::/10". */
    if (plen < 10) {
        return false;
    }
    return (((prefix->s6_addr[0] & 0xff) == 0xfe) &&
            ((prefix->s6_addr[1] & 0xc0) == 0x80));
}

static bool
prefix_is_black_listed(const struct smap *nb_options,
                       struct in6_addr *prefix,
                       unsigned int plen)
{
    const char *blacklist = smap_get(nb_options, "ic-route-blacklist");
    if (!blacklist || !blacklist[0]) {
        return false;
    }
    struct in6_addr bl_prefix;
    unsigned int bl_plen;
    char *cur, *next, *start;
    next = start = xstrdup(blacklist);
    bool matched = false;
    while ((cur = strsep(&next, ",")) && *cur) {
        if (!ip46_parse_cidr(cur, &bl_prefix, &bl_plen)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Bad format in nb_global options:"
                         "ic-route-blacklist: %s. CIDR expected.", cur);
            continue;
        }

        if (IN6_IS_ADDR_V4MAPPED(&bl_prefix) != IN6_IS_ADDR_V4MAPPED(prefix)) {
            continue;
        }

        /* 192.168.0.0/16 does not belong to 192.168.0.0/17 */
        if (plen < bl_plen) {
            continue;
        }

        if (IN6_IS_ADDR_V4MAPPED(prefix)) {
            ovs_be32 bl_prefix_v4 = in6_addr_get_mapped_ipv4(&bl_prefix);
            ovs_be32 prefix_v4 = in6_addr_get_mapped_ipv4(prefix);
            ovs_be32 mask = be32_prefix_mask(bl_plen);

            if ((prefix_v4 & mask) != (bl_prefix_v4 & mask)) {
                continue;
            }
        } else {
            struct in6_addr mask = ipv6_create_mask(bl_plen);
            for (int i = 0; i < 16 && mask.s6_addr[i] != 0; i++) {
                if ((prefix->s6_addr[i] & mask.s6_addr[i])
                    != (bl_prefix.s6_addr[i] & mask.s6_addr[i])) {
                    continue;
                }
            }
        }
        matched = true;
        break;
    }
    free(start);
    return matched;
}

static bool
route_need_advertise(const char *policy,
                     struct in6_addr *prefix,
                     unsigned int plen,
                     const struct smap *nb_options)
{
    if (!smap_get_bool(nb_options, "ic-route-adv", false)) {
        return false;
    }

    if (plen == 0 &&
        !smap_get_bool(nb_options, "ic-route-adv-default", false)) {
        return false;
    }

    if (policy && !strcmp(policy, "src-ip")) {
        return false;
    }

    if (prefix_is_link_local(prefix, plen)) {
        return false;
    }

    if (prefix_is_black_listed(nb_options, prefix, plen)) {
        return false;
    }
    return true;
}

static void
add_to_routes_ad(struct hmap *routes_ad,
                 const struct nbrec_logical_router_static_route *nb_route,
                 const struct lport_addresses *nexthop_addresses,
                 const struct smap *nb_options)
{
    struct in6_addr prefix, nexthop;
    unsigned int plen;
    if (!parse_route(nb_route->ip_prefix, nb_route->nexthop,
                     &prefix, &plen, &nexthop)) {
        return;
    }

    if (!route_need_advertise(nb_route->policy, &prefix, plen, nb_options)) {
        return;
    }

    if (!get_nexthop_from_lport_addresses(IN6_IS_ADDR_V4MAPPED(&prefix),
                                          nexthop_addresses,
                                          &nexthop)) {
        return;
    }

    struct ic_route_info *ic_route = xzalloc(sizeof *ic_route);
    ic_route->prefix = prefix;
    ic_route->plen = plen;
    ic_route->nexthop = nexthop;
    ic_route->nb_route = nb_route;
    hmap_insert(routes_ad, &ic_route->node,
                ic_route_hash(&prefix, plen, &nexthop));
}

static void
add_network_to_routes_ad(struct hmap *routes_ad, const char *network,
                         const struct nbrec_logical_router_port *nb_lrp,
                         const struct lport_addresses *nexthop_addresses,
                         const struct smap *nb_options)
{
    struct in6_addr prefix, nexthop;
    unsigned int plen;
    if (!ip46_parse_cidr(network, &prefix, &plen)) {
        return;
    }

    if (!route_need_advertise(NULL, &prefix, plen, nb_options)) {
        VLOG_DBG("Route ad: skip network %s of lrp %s.",
                 network, nb_lrp->name);
        return;
    }

    if (!get_nexthop_from_lport_addresses(IN6_IS_ADDR_V4MAPPED(&prefix),
                                          nexthop_addresses,
                                          &nexthop)) {
        return;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        ds_put_format(&msg, "Route ad: direct network %s of lrp %s, nexthop ",
                      network, nb_lrp->name);

        if (IN6_IS_ADDR_V4MAPPED(&nexthop)) {
            ds_put_format(&msg, IP_FMT,
                          IP_ARGS(in6_addr_get_mapped_ipv4(&nexthop)));
        } else {
            ipv6_format_addr(&nexthop, &msg);
        }

        VLOG_DBG("%s", ds_cstr(&msg));
        ds_destroy(&msg);
    }

    struct ic_route_info *ic_route = xzalloc(sizeof *ic_route);
    ic_route->prefix = prefix;
    ic_route->plen = plen;
    ic_route->nexthop = nexthop;
    ic_route->nb_lrp = nb_lrp;
    hmap_insert(routes_ad, &ic_route->node,
                ic_route_hash(&prefix, plen, &nexthop));
}

static bool
route_need_learn(struct in6_addr *prefix,
                 unsigned int plen,
                 const struct smap *nb_options)
{
    if (!smap_get_bool(nb_options, "ic-route-learn", false)) {
        return false;
    }

    if (plen == 0 &&
        !smap_get_bool(nb_options, "ic-route-learn-default", false)) {
        return false;
    }

    if (prefix_is_link_local(prefix, plen)) {
        return false;
    }

    if (prefix_is_black_listed(nb_options, prefix, plen)) {
        return false;
    }

    return true;
}

static void
sync_learned_route(struct ic_context *ctx,
                   const struct icsbrec_availability_zone *az,
                   struct ic_router_info *ic_lr)
{
    ovs_assert(ctx->ovnnb_txn);
    const struct icsbrec_route *isb_route;
    ICSBREC_ROUTE_FOR_EACH (isb_route, ctx->ovnisb_idl) {
        if (isb_route->availability_zone == az) {
            continue;
        }
        struct in6_addr prefix, nexthop;
        unsigned int plen;
        if (!parse_route(isb_route->ip_prefix, isb_route->nexthop,
                         &prefix, &plen, &nexthop)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Bad route format in IC-SB: %s -> %s. Ignored.",
                         isb_route->ip_prefix, isb_route->nexthop);
            continue;
        }
        const struct nbrec_nb_global *nb_global =
            nbrec_nb_global_first(ctx->ovnnb_idl);
        ovs_assert(nb_global);
        if (!route_need_learn(&prefix, plen, &nb_global->options)) {
            continue;
        }
        struct ic_route_info *route_learned
            = ic_route_find(&ic_lr->routes_learned, &prefix, plen, &nexthop);
        if (route_learned) {
            /* Sync external-ids */
            struct uuid ext_id;
            smap_get_uuid(&route_learned->nb_route->external_ids,
                          "ic-learned-route", &ext_id);
            if (!uuid_equals(&ext_id, &isb_route->header_.uuid)) {
                char *uuid_s = xasprintf(UUID_FMT,
                                         UUID_ARGS(&isb_route->header_.uuid));
                nbrec_logical_router_static_route_update_external_ids_setkey(
                    route_learned->nb_route, "ic-learned-route", uuid_s);
                free(uuid_s);
            }
            hmap_remove(&ic_lr->routes_learned, &route_learned->node);
            free(route_learned);
        } else {
            /* Create the missing route in NB. */
            const struct nbrec_logical_router_static_route *nb_route =
                nbrec_logical_router_static_route_insert(ctx->ovnnb_txn);
            nbrec_logical_router_static_route_set_ip_prefix(
                nb_route, isb_route->ip_prefix);
            nbrec_logical_router_static_route_set_nexthop(
                nb_route, isb_route->nexthop);
            char *uuid_s = xasprintf(UUID_FMT,
                                     UUID_ARGS(&isb_route->header_.uuid));
            nbrec_logical_router_static_route_update_external_ids_setkey(
                nb_route, "ic-learned-route", uuid_s);
            free(uuid_s);
            nbrec_logical_router_update_static_routes_addvalue(
                ic_lr->lr, nb_route);
        }
    }
    /* Delete extra learned routes. */
    struct ic_route_info *route_learned, *next;
    HMAP_FOR_EACH_SAFE (route_learned, next, node, &ic_lr->routes_learned) {
        VLOG_DBG("Delete route %s -> %s that is not in IC-SB from NB.",
                 route_learned->nb_route->ip_prefix,
                 route_learned->nb_route->nexthop);
        nbrec_logical_router_update_static_routes_delvalue(
            ic_lr->lr, route_learned->nb_route);
        hmap_remove(&ic_lr->routes_learned, &route_learned->node);
        free(route_learned);
    }
}

static void
ad_route_sync_external_ids(const struct ic_route_info *route_adv,
                           const struct icsbrec_route *isb_route)
{
    struct uuid isb_ext_id, nb_id;
    smap_get_uuid(&isb_route->external_ids, "nb-id", &isb_ext_id);
    nb_id = route_adv->nb_route ? route_adv->nb_route->header_.uuid
                               : route_adv->nb_lrp->header_.uuid;
    if (!uuid_equals(&isb_ext_id, &nb_id)) {
        char *uuid_s = xasprintf(UUID_FMT, UUID_ARGS(&nb_id));
        icsbrec_route_update_external_ids_setkey(isb_route, "nb-id",
                                                 uuid_s);
        free(uuid_s);
    }
}

/* Sync routes from routes_ad to IC-SB. */
static void
advertise_route(struct ic_context *ctx,
                const struct icsbrec_availability_zone *az,
                const char *ts_name,
                struct hmap *routes_ad)
{
    ovs_assert(ctx->ovnisb_txn);
    const struct icsbrec_route *isb_route;
    ICSBREC_ROUTE_FOR_EACH (isb_route, ctx->ovnisb_idl) {
        if (strcmp(isb_route->transit_switch, ts_name)) {
            continue;
        }

        if (isb_route->availability_zone != az) {
            continue;
        }

        struct in6_addr prefix, nexthop;
        unsigned int plen;

        if (!parse_route(isb_route->ip_prefix, isb_route->nexthop,
                         &prefix, &plen, &nexthop)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Bad route format in IC-SB: %s -> %s. "
                         "Delete it.",
                         isb_route->ip_prefix, isb_route->nexthop);
            icsbrec_route_delete(isb_route);
            continue;
        }
        struct ic_route_info *route_adv =
            ic_route_find(routes_ad, &prefix, plen, &nexthop);
        if (!route_adv) {
            /* Delete the extra route from IC-SB. */
            VLOG_DBG("Delete route %s -> %s from IC-SB, which is not found"
                     " in local routes to be advertised.",
                     isb_route->ip_prefix, isb_route->nexthop);
            icsbrec_route_delete(isb_route);
        } else {
            ad_route_sync_external_ids(route_adv, isb_route);

            hmap_remove(routes_ad, &route_adv->node);
            free(route_adv);
        }
    }

    /* Create the missing routes in IC-SB */
    struct ic_route_info *route_adv, *next;
    HMAP_FOR_EACH_SAFE (route_adv, next, node, routes_ad) {
        isb_route = icsbrec_route_insert(ctx->ovnisb_txn);
        icsbrec_route_set_transit_switch(isb_route, ts_name);
        icsbrec_route_set_availability_zone(isb_route, az);

        char *prefix_s, *nexthop_s;
        if (IN6_IS_ADDR_V4MAPPED(&route_adv->prefix)) {
            ovs_be32 ipv4 = in6_addr_get_mapped_ipv4(&route_adv->prefix);
            ovs_be32 nh = in6_addr_get_mapped_ipv4(&route_adv->nexthop);
            prefix_s = xasprintf(IP_FMT "/%d", IP_ARGS(ipv4), route_adv->plen);
            nexthop_s = xasprintf(IP_FMT, IP_ARGS(nh));
        } else {
            char network_s[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &route_adv->prefix, network_s,
                      INET6_ADDRSTRLEN);
            prefix_s = xasprintf("%s/%d", network_s, route_adv->plen);
            inet_ntop(AF_INET6, &route_adv->nexthop, network_s,
                      INET6_ADDRSTRLEN);
            nexthop_s = xstrdup(network_s);
        }
        icsbrec_route_set_ip_prefix(isb_route, prefix_s);
        icsbrec_route_set_nexthop(isb_route, nexthop_s);
        free(prefix_s);
        free(nexthop_s);

        ad_route_sync_external_ids(route_adv, isb_route);

        hmap_remove(routes_ad, &route_adv->node);
        free(route_adv);
    }
}

static const char *
get_lrp_name_by_ts_port_name(struct ic_context *ctx,
                           const char *ts_port_name)
{
    const struct nbrec_logical_switch_port *nb_lsp;
    const struct nbrec_logical_switch_port *nb_lsp_key =
        nbrec_logical_switch_port_index_init_row(ctx->nbrec_port_by_name);
    nbrec_logical_switch_port_index_set_name(nb_lsp_key, ts_port_name);
    nb_lsp = nbrec_logical_switch_port_index_find(ctx->nbrec_port_by_name,
                                                  nb_lsp_key);
    nbrec_logical_switch_port_index_destroy_row(nb_lsp_key);

    if (!nb_lsp) {
        return NULL;
    }

    return smap_get(&nb_lsp->options, "router-port");
}

static void
route_run(struct ic_context *ctx,
          const struct icsbrec_availability_zone *az)
{
    if (!ctx->ovnisb_txn || !ctx->ovnnb_txn) {
        return;
    }

    const struct nbrec_nb_global *nb_global =
        nbrec_nb_global_first(ctx->ovnnb_idl);
    ovs_assert(nb_global);

    const struct icnbrec_transit_switch *ts;
    ICNBREC_TRANSIT_SWITCH_FOR_EACH (ts, ctx->ovninb_idl) {
        struct hmap ic_lrs = HMAP_INITIALIZER(&ic_lrs);
        struct hmap routes_ad = HMAP_INITIALIZER(&routes_ad);

        const struct icsbrec_port_binding *isb_pb;
        const struct icsbrec_port_binding *isb_pb_key =
            icsbrec_port_binding_index_init_row(
                ctx->icsbrec_port_binding_by_ts);
        icsbrec_port_binding_index_set_transit_switch(isb_pb_key, ts->name);

        /* Each port on TS maps to a logical router, which is stored in the
         * external_ids:router-id of the IC SB port_binding record. */
        ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
                                             ctx->icsbrec_port_binding_by_ts) {
            if (isb_pb->availability_zone != az) {
                continue;
            }

            const char *ts_lrp_name =
                get_lrp_name_by_ts_port_name(ctx, isb_pb->logical_port);
            if (!ts_lrp_name) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "Route sync ignores port %s on ts %s "
                             "because logical router port is not found in NB.",
                             isb_pb->logical_port, ts->name);
                continue;
            }

            struct uuid lr_uuid;
            if (!smap_get_uuid(&isb_pb->external_ids, "router-id", &lr_uuid)) {
                VLOG_DBG("IC-SB Port_Binding %s doesn't have "
                         "external_ids:router-id set.", isb_pb->logical_port);
                continue;
            }
            const struct nbrec_logical_router *lr
                = nbrec_logical_router_get_for_uuid(ctx->ovnnb_idl, &lr_uuid);
            if (!lr) {
                continue;
            }

            if (ic_router_find(&ic_lrs, lr)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_INFO_RL(&rl, "Route sync ignores port %s on ts %s for "
                             "router %s because the router has another port "
                             "connected to same ts.", isb_pb->logical_port,
                             ts->name, lr->name);
                continue;
            }

            struct lport_addresses ts_port_addrs;
            if (!extract_lsp_addresses(isb_pb->address, &ts_port_addrs)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_INFO_RL(&rl, "Route sync ignores port %s on ts %s for "
                             "router %s because the addresses are invalid.",
                             isb_pb->logical_port, ts->name, lr->name);
                continue;
            }

            struct ic_router_info *ic_lr = xzalloc(sizeof *ic_lr);
            ic_lr->lr = lr;
            ic_lr->isb_pb = isb_pb;
            hmap_init(&ic_lr->routes_learned);
            hmap_insert(&ic_lrs, &ic_lr->node, uuid_hash(&lr->header_.uuid));

            /* Check static routes of the LR */
            for (int i = 0; i < lr->n_static_routes; i++) {
                const struct nbrec_logical_router_static_route *nb_route
                    = lr->static_routes[i];
                struct uuid isb_uuid;
                if (smap_get_uuid(&nb_route->external_ids,
                                  "ic-learned-route", &isb_uuid)) {
                    /* It is a learned route */
                    if (!add_to_routes_learned(&ic_lr->routes_learned,
                                               nb_route)) {
                        static struct vlog_rate_limit rl =
                            VLOG_RATE_LIMIT_INIT(5, 1);
                        VLOG_WARN_RL(&rl, "Bad format of learned route in NB:"
                                     " %s -> %s. Delete it.",
                                     nb_route->ip_prefix, nb_route->nexthop);
                        nbrec_logical_router_update_static_routes_delvalue(
                            lr, nb_route);
                    }
                } else {
                    /* It may be a route to be advertised */
                    add_to_routes_ad(&routes_ad, nb_route, &ts_port_addrs,
                                     &nb_global->options);
                }
            }

            /* Check direct-connected subnets of the LR */
            for (int i = 0; i < lr->n_ports; i++) {
                const struct nbrec_logical_router_port *lrp = lr->ports[i];
                if (!strcmp(lrp->name, ts_lrp_name)) {
                    /* The router port of the TS port is ignored. */
                    VLOG_DBG("Route ad: skip lrp %s (TS port: %s)",
                             lrp->name, isb_pb->logical_port);
                    continue;
                }

                for (int j = 0; j < lrp->n_networks; j++) {
                    add_network_to_routes_ad(&routes_ad, lrp->networks[j],
                                             lrp, &ts_port_addrs,
                                             &nb_global->options);
                }
            }

            destroy_lport_addresses(&ts_port_addrs);
        }
        icsbrec_port_binding_index_destroy_row(isb_pb_key);

        advertise_route(ctx, az, ts->name, &routes_ad);
        hmap_destroy(&routes_ad);

        struct ic_router_info *ic_lr, *next;
        HMAP_FOR_EACH_SAFE (ic_lr, next, node, &ic_lrs) {
            sync_learned_route(ctx, az, ic_lr);
            hmap_destroy(&ic_lr->routes_learned);
            hmap_remove(&ic_lrs, &ic_lr->node);
            free(ic_lr);
        }
        hmap_destroy(&ic_lrs);
    }
}

static void
ovn_db_run(struct ic_context *ctx)
{
    const struct icsbrec_availability_zone *az = az_run(ctx);
    VLOG_DBG("Availability zone: %s", az ? az->name : "not created yet.");

    if (!az) {
        return;
    }

    ts_run(ctx);
    gateway_run(ctx, az);
    port_binding_run(ctx, az);
    route_run(ctx, az);
}

static void
parse_options(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum {
        OVN_DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"ovnsb-db", required_argument, NULL, 'd'},
        {"ovnnb-db", required_argument, NULL, 'D'},
        {"ic-sb-db", required_argument, NULL, 'i'},
        {"ic-nb-db", required_argument, NULL, 'I'},
        {"unixctl", required_argument, NULL, 'u'},
        {"help", no_argument, NULL, 'h'},
        {"options", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        OVN_DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        OVN_DAEMON_OPTION_HANDLERS;
        VLOG_OPTION_HANDLERS;

        case 'p':
            ssl_private_key_file = optarg;
            break;

        case 'c':
            ssl_certificate_file = optarg;
            break;

        case 'C':
            ssl_ca_cert_file = optarg;
            break;

        case 'd':
            ovnsb_db = optarg;
            break;

        case 'D':
            ovnnb_db = optarg;
            break;

        case 'i':
            ovn_ic_sb_db = optarg;
            break;

        case 'I':
            ovn_ic_nb_db = optarg;
            break;

        case 'u':
            unixctl_path = optarg;
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'V':
            ovn_print_version(0, 0);
            exit(EXIT_SUCCESS);

        default:
            break;
        }
    }

    if (!ovnsb_db) {
        ovnsb_db = default_sb_db();
    }

    if (!ovnnb_db) {
        ovnnb_db = default_nb_db();
    }

    if (!ovn_ic_sb_db) {
        ovn_ic_sb_db = default_ic_sb_db();
    }

    if (!ovn_ic_nb_db) {
        ovn_ic_nb_db = default_ic_nb_db();
    }

    free(short_options);
}

static void OVS_UNUSED
add_column_noalert(struct ovsdb_idl *idl,
                   const struct ovsdb_idl_column *column)
{
    ovsdb_idl_add_column(idl, column);
    ovsdb_idl_omit_alert(idl, column);
}

static void
update_ssl_config(void)
{
    if (ssl_private_key_file && ssl_certificate_file) {
        stream_ssl_set_key_and_cert(ssl_private_key_file,
                                    ssl_certificate_file);
    }
    if (ssl_ca_cert_file) {
        stream_ssl_set_ca_cert_file(ssl_ca_cert_file, false);
    }
}

int
main(int argc, char *argv[])
{
    int res = EXIT_SUCCESS;
    struct unixctl_server *unixctl;
    int retval;
    bool exiting;
    struct ic_state state;

    fatal_ignore_sigpipe();
    ovs_cmdl_proctitle_init(argc, argv);
    ovn_set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);

    daemonize_start(false);

    char *abs_unixctl_path = get_abs_unix_ctl_path(unixctl_path);
    retval = unixctl_server_create(abs_unixctl_path, &unixctl);
    free(abs_unixctl_path);

    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_ic_exit, &exiting);
    unixctl_command_register("pause", "", 0, 0, ovn_ic_pause, &state);
    unixctl_command_register("resume", "", 0, 0, ovn_ic_resume, &state);
    unixctl_command_register("is-paused", "", 0, 0, ovn_ic_is_paused, &state);
    unixctl_command_register("status", "", 0, 0, ovn_ic_status, &state);

    daemonize_complete();

    /* ovn-ic-nb db. */
    struct ovsdb_idl_loop ovninb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovn_ic_nb_db, &icnbrec_idl_class, true, true));

    /* ovn-ic-sb db. */
    struct ovsdb_idl_loop ovnisb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovn_ic_sb_db, &icsbrec_idl_class, true, true));

    /* ovn-nb db. XXX: add only needed tables and columns */
    struct ovsdb_idl_loop ovnnb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnnb_db, &nbrec_idl_class, true, true));

    /* ovn-sb db. XXX: add only needed tables and columns */
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnsb_db, &sbrec_idl_class, true, true));

    /* Create IDL indexes */
    struct ovsdb_idl_index *nbrec_ls_by_name
        = ovsdb_idl_index_create1(ovnnb_idl_loop.idl,
                                  &nbrec_logical_switch_col_name);
    struct ovsdb_idl_index *nbrec_port_by_name
        = ovsdb_idl_index_create1(ovnnb_idl_loop.idl,
                                  &nbrec_logical_switch_port_col_name);
    struct ovsdb_idl_index *sbrec_port_binding_by_name
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_port_binding_col_logical_port);
    struct ovsdb_idl_index *sbrec_chassis_by_name
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_chassis_col_name);
    struct ovsdb_idl_index *icsbrec_port_binding_by_ts
        = ovsdb_idl_index_create1(ovnisb_idl_loop.idl,
                                  &icsbrec_port_binding_col_transit_switch);

    /* Main loop. */
    exiting = false;
    state.had_lock = false;
    state.paused = false;
    while (!exiting) {
        update_ssl_config();
        memory_run();
        if (memory_should_report()) {
            struct simap usage = SIMAP_INITIALIZER(&usage);

            /* Nothing special to report yet. */
            memory_report(&usage);
            simap_destroy(&usage);
        }

        if (!state.paused) {
            if (!ovsdb_idl_has_lock(ovnsb_idl_loop.idl) &&
                !ovsdb_idl_is_lock_contended(ovnsb_idl_loop.idl))
            {
                /* Ensure that only a single ovn-ic is active in the deployment
                 * by acquiring a lock called "ovn_ic" on the southbound
                 * database and then only performing DB transactions if the
                 * lock is held. */
                ovsdb_idl_set_lock(ovnsb_idl_loop.idl, "ovn_ic");
            }

            struct ic_context ctx = {
                .ovnnb_idl = ovnnb_idl_loop.idl,
                .ovnnb_txn = ovsdb_idl_loop_run(&ovnnb_idl_loop),
                .ovnsb_idl = ovnsb_idl_loop.idl,
                .ovnsb_txn = ovsdb_idl_loop_run(&ovnsb_idl_loop),
                .ovninb_idl = ovninb_idl_loop.idl,
                .ovninb_txn = ovsdb_idl_loop_run(&ovninb_idl_loop),
                .ovnisb_idl = ovnisb_idl_loop.idl,
                .ovnisb_txn = ovsdb_idl_loop_run(&ovnisb_idl_loop),
                .nbrec_ls_by_name = nbrec_ls_by_name,
                .nbrec_port_by_name = nbrec_port_by_name,
                .sbrec_port_binding_by_name = sbrec_port_binding_by_name,
                .sbrec_chassis_by_name = sbrec_chassis_by_name,
                .icsbrec_port_binding_by_ts = icsbrec_port_binding_by_ts,
            };

            if (!state.had_lock && ovsdb_idl_has_lock(ovnsb_idl_loop.idl)) {
                VLOG_INFO("ovn-ic lock acquired. "
                        "This ovn-ic instance is now active.");
                state.had_lock = true;
            } else if (state.had_lock &&
                       !ovsdb_idl_has_lock(ovnsb_idl_loop.idl)) {
                VLOG_INFO("ovn-ic lock lost. "
                        "This ovn-ic instance is now on standby.");
                state.had_lock = false;
            }

            if (ovsdb_idl_has_lock(ovnsb_idl_loop.idl)) {
                ovn_db_run(&ctx);
            }

            ovsdb_idl_loop_commit_and_wait(&ovnnb_idl_loop);
            ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);
            ovsdb_idl_loop_commit_and_wait(&ovninb_idl_loop);
            ovsdb_idl_loop_commit_and_wait(&ovnisb_idl_loop);
        } else {
            /* ovn-ic is paused
             *    - we still want to handle any db updates and update the
             *      local IDL. Otherwise, when it is resumed, the local IDL
             *      copy will be out of sync.
             *    - but we don't want to create any txns.
             * */
            if (ovsdb_idl_has_lock(ovnsb_idl_loop.idl) ||
                ovsdb_idl_is_lock_contended(ovnsb_idl_loop.idl))
            {
                /* make sure we don't hold the lock while paused */
                VLOG_INFO("This ovn-ic instance is now paused.");
                ovsdb_idl_set_lock(ovnsb_idl_loop.idl, NULL);
                state.had_lock = false;
            }

            ovsdb_idl_run(ovnnb_idl_loop.idl);
            ovsdb_idl_run(ovnsb_idl_loop.idl);
            ovsdb_idl_run(ovninb_idl_loop.idl);
            ovsdb_idl_run(ovnisb_idl_loop.idl);
            ovsdb_idl_wait(ovnnb_idl_loop.idl);
            ovsdb_idl_wait(ovnsb_idl_loop.idl);
            ovsdb_idl_wait(ovninb_idl_loop.idl);
            ovsdb_idl_wait(ovnisb_idl_loop.idl);
        }

        unixctl_server_run(unixctl);
        unixctl_server_wait(unixctl);
        memory_wait();
        if (exiting) {
            poll_immediate_wake();
        }

        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
    }

    unixctl_server_destroy(unixctl);
    ovsdb_idl_loop_destroy(&ovnnb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);
    ovsdb_idl_loop_destroy(&ovninb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnisb_idl_loop);
    service_stop();

    exit(res);
}

static void
ovn_ic_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
            const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_ic_pause(struct unixctl_conn *conn, int argc OVS_UNUSED,
             const char *argv[] OVS_UNUSED, void *state_)
{
    struct ic_state *state = state_;
    state->paused = true;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_ic_resume(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[] OVS_UNUSED, void *state_)
{
    struct ic_state *state = state_;
    state->paused = false;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_ic_is_paused(struct unixctl_conn *conn, int argc OVS_UNUSED,
                 const char *argv[] OVS_UNUSED, void *state_)
{
    struct ic_state *state = state_;
    if (state->paused) {
        unixctl_command_reply(conn, "true");
    } else {
        unixctl_command_reply(conn, "false");
    }
}

static void
ovn_ic_status(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[] OVS_UNUSED, void *state_)
{
    struct ic_state *state = state_;
    char *status;

    if (state->paused) {
        status = "paused";
    } else {
        status = state->had_lock ? "active" : "standby";
    }

    /*
     * Use a labelled formatted output so we can add more to the status command
     * later without breaking any consuming scripts
     */
    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "Status: %s\n", status);
    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}
