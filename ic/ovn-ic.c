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
#include "ovsdb-idl.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "stream.h"
#include "stream-ssl.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"
#include "vec.h"
#include "inc-proc-ic.h"
#include "ovn-ic.h"

VLOG_DEFINE_THIS_MODULE(ovn_ic);

static unixctl_cb_func ovn_ic_exit;
static unixctl_cb_func ovn_ic_pause;
static unixctl_cb_func ovn_ic_resume;
static unixctl_cb_func ovn_ic_is_paused;
static unixctl_cb_func ovn_ic_status;

static const char *ovnnb_db;
static const char *ovnsb_db;
static const char *ovn_ic_nb_db;
static const char *ovn_ic_sb_db;
static const char *unixctl_path;

/* SSL/TLS options. */
static const char *ssl_private_key_file;
static const char *ssl_certificate_file;
static const char *ssl_ca_cert_file;

static const struct sbrec_port_binding * find_sb_pb_by_name(
    struct ovsdb_idl_index *sbrec_port_binding_by_name, const char *name);


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
  --ic-nb-db=DATABASE       connect to ovn-ic-nb database at DATABASE\n\
                            (default: %s)\n\
  --ic-sb-db=DATABASE       connect to ovn-ic-sb database at DATABASE\n\
                            (default: %s)\n\
  --unixctl=SOCKET          override default control socket name\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_nb_db(), default_sb_db(),
    default_ic_nb_db(), default_ic_sb_db());
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

    /* Update old AZ if name changes.  Note: if name changed when ovn-ic
     * is not running, one has to manually delete/update the old AZ with:
     * "ovn-ic-sbctl destroy avail <az>". */
    static char *az_name;
    const struct icsbrec_availability_zone *az;
    if (ctx->ovnisb_txn && az_name && strcmp(az_name, nb_global->name)) {
        ICSBREC_AVAILABILITY_ZONE_FOR_EACH (az, ctx->ovnisb_idl) {
            /* AZ name update locally need to update az in ISB. */
            if (nb_global->name[0] && !strcmp(az->name, az_name)) {
                icsbrec_availability_zone_set_name(az, nb_global->name);
                break;
            } else if (!nb_global->name[0] && !strcmp(az->name, az_name)) {
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
            ctx->runned_az = az;
            return az;
        }
    }

    /* Create AZ in ISB */
    if (ctx->ovnisb_txn) {
        VLOG_INFO("Register AZ %s to interconnection DB.", az_name);
        az = icsbrec_availability_zone_insert(ctx->ovnisb_txn);
        icsbrec_availability_zone_set_name(az, az_name);
        ctx->runned_az = az;
        return az;
    }
    return NULL;
}

static uint32_t
allocate_dp_key(struct hmap *dp_tnlids, bool vxlan_mode, const char *name)
{
    uint32_t hint = vxlan_mode ? OVN_MIN_DP_VXLAN_KEY_GLOBAL
                               : OVN_MIN_DP_KEY_GLOBAL;
    return ovn_allocate_tnlid(dp_tnlids, name, hint,
            vxlan_mode ? OVN_MAX_DP_VXLAN_KEY_GLOBAL : OVN_MAX_DP_KEY_GLOBAL,
            &hint);
}

static enum ic_datapath_type
ic_dp_get_type(const struct icsbrec_datapath_binding *isb_dp)
{
    if (isb_dp->type && !strcmp(isb_dp->type, "transit-router")) {
        return IC_ROUTER;
    }

    return IC_SWITCH;
}

static enum ic_port_binding_type
ic_pb_get_type(const struct icsbrec_port_binding *isb_pb)
{
    if (isb_pb->type && !strcmp(isb_pb->type, "transit-router-port")) {
        return IC_ROUTER_PORT;
    }

    return IC_SWITCH_PORT;
}

static void
enumerate_datapaths(struct ic_context *ctx, struct hmap *dp_tnlids,
                    struct shash *isb_ts_dps, struct shash *isb_tr_dps)
{
    const struct icsbrec_datapath_binding *isb_dp;
    ICSBREC_DATAPATH_BINDING_FOR_EACH (isb_dp, ctx->ovnisb_idl) {
        ovn_add_tnlid(dp_tnlids, isb_dp->tunnel_key);

        enum ic_datapath_type dp_type = ic_dp_get_type(isb_dp);
        if (dp_type == IC_ROUTER) {
            char *uuid_str = uuid_to_string(isb_dp->nb_ic_uuid);
            shash_add(isb_tr_dps, uuid_str, isb_dp);
            free(uuid_str);
        } else {
            shash_add(isb_ts_dps, isb_dp->transit_switch, isb_dp);
        }
    }
}

static void
ts_run(struct ic_context *ctx, struct hmap *dp_tnlids,
       struct shash *isb_ts_dps)
{
    const struct icnbrec_transit_switch *ts;
    bool dp_key_refresh = false;
    bool vxlan_mode = false;
    const struct icnbrec_ic_nb_global *ic_nb =
        icnbrec_ic_nb_global_first(ctx->ovninb_idl);

    if (ic_nb && smap_get_bool(&ic_nb->options, "vxlan_mode", false)) {
        const struct icsbrec_encap *encap;
        ICSBREC_ENCAP_FOR_EACH (encap, ctx->ovnisb_idl) {
            if (!strcmp(encap->type, "vxlan")) {
                vxlan_mode = true;
                break;
            }
        }
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
                nbrec_logical_switch_update_other_config_setkey(
                        ls, "ic-vxlan_mode", vxlan_mode ? "true" : "false");
            } else {
                bool _vxlan_mode = smap_get_bool(&ls->other_config,
                                                 "ic-vxlan_mode", false);
                if (_vxlan_mode != vxlan_mode) {
                    dp_key_refresh = true;
                    nbrec_logical_switch_update_other_config_setkey(
                            ls, "ic-vxlan_mode",
                            vxlan_mode ? "true" : "false");
                }
            }

            const struct icsbrec_datapath_binding *isb_dp;
            isb_dp = shash_find_data(isb_ts_dps, ts->name);
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
            const struct icsbrec_datapath_binding *isb_dp =
                shash_find_and_delete(isb_ts_dps, ts->name);
            if (!isb_dp) {
                /* Allocate tunnel key */
                int64_t dp_key = allocate_dp_key(dp_tnlids, vxlan_mode,
                                                 "transit switch datapath");
                if (!dp_key) {
                    continue;
                }

                isb_dp = icsbrec_datapath_binding_insert(ctx->ovnisb_txn);
                icsbrec_datapath_binding_set_transit_switch(isb_dp, ts->name);
                icsbrec_datapath_binding_set_tunnel_key(isb_dp, dp_key);
            } else if (dp_key_refresh) {
                /* Refresh tunnel key since encap mode has changed. */
                int64_t dp_key = allocate_dp_key(dp_tnlids, vxlan_mode,
                                                 "transit switch datapath");
                if (dp_key) {
                    icsbrec_datapath_binding_set_tunnel_key(isb_dp, dp_key);
                }
            }

            if (!isb_dp->type) {
                icsbrec_datapath_binding_set_type(isb_dp, "transit-switch");
            }

            if (!isb_dp->nb_ic_uuid) {
                icsbrec_datapath_binding_set_nb_ic_uuid(isb_dp,
                                                        &ts->header_.uuid, 1);
            }
        }

        struct shash_node *node;
        SHASH_FOR_EACH (node, isb_ts_dps) {
            icsbrec_datapath_binding_delete(node->data);
        }
    }
}

static void
tr_run(struct ic_context *ctx, struct hmap *dp_tnlids,
       struct shash *isb_tr_dps)
{
    const struct nbrec_logical_router *lr;

    if (ctx->ovnnb_txn) {
        struct shash nb_tres = SHASH_INITIALIZER(&nb_tres);
        NBREC_LOGICAL_ROUTER_FOR_EACH (lr, ctx->ovnnb_idl) {
            const char *tr_name = smap_get(&lr->options, "interconn-tr");
            if (tr_name) {
                shash_add(&nb_tres, tr_name, lr);
            }
        }

        const struct icnbrec_transit_router *tr;
        ICNBREC_TRANSIT_ROUTER_FOR_EACH (tr, ctx->ovninb_idl) {
            lr = shash_find_and_delete(&nb_tres, tr->name);
            if (!lr) {
                lr = nbrec_logical_router_insert(ctx->ovnnb_txn);
                nbrec_logical_router_set_name(lr, tr->name);
                nbrec_logical_router_update_options_setkey(
                    lr, "interconn-tr", tr->name);
            }
            char *uuid_str = uuid_to_string(&tr->header_.uuid);
            struct icsbrec_datapath_binding *isb_dp = shash_find_data(
                isb_tr_dps, uuid_str);
            free(uuid_str);

            if (isb_dp) {
                char *tnl_key_str = xasprintf("%"PRId64, isb_dp->tunnel_key);
                nbrec_logical_router_update_options_setkey(
                    lr, "requested-tnl-key", tnl_key_str);
                free(tnl_key_str);
            }
        }

        struct shash_node *node;
        SHASH_FOR_EACH (node, &nb_tres) {
            nbrec_logical_router_delete(node->data);
        }
        shash_destroy(&nb_tres);
    }

    /* Sync TR between INB and ISB.  This is performed after syncing with AZ
     * SB, to avoid uncommitted ISB datapath tunnel key to be synced back to
     * AZ. */
    if (ctx->ovnisb_txn) {
        /* Create ISB Datapath_Binding */
        const struct icnbrec_transit_router *tr;
        ICNBREC_TRANSIT_ROUTER_FOR_EACH (tr, ctx->ovninb_idl) {
            char *uuid_str = uuid_to_string(&tr->header_.uuid);
            struct icsbrec_datapath_binding *isb_dp =
                shash_find_and_delete(isb_tr_dps, uuid_str);
            free(uuid_str);

            if (!isb_dp) {
                int dp_key = allocate_dp_key(dp_tnlids, false,
                                             "transit router datapath");
                if (!dp_key) {
                    continue;
                }

                isb_dp = icsbrec_datapath_binding_insert(ctx->ovnisb_txn);
                icsbrec_datapath_binding_set_tunnel_key(isb_dp, dp_key);
                icsbrec_datapath_binding_set_nb_ic_uuid(isb_dp,
                                                        &tr->header_.uuid, 1);
                icsbrec_datapath_binding_set_type(isb_dp, "transit-router");
            }
        }

        struct shash_node *node;
        SHASH_FOR_EACH (node, isb_tr_dps) {
            icsbrec_datapath_binding_delete(node->data);
        }
    }
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
gateway_run(struct ic_context *ctx)
{
    if (!ctx->ovnisb_txn || !ctx->ovnsb_txn) {
        return;
    }

    struct shash local_gws = SHASH_INITIALIZER(&local_gws);
    struct shash remote_gws = SHASH_INITIALIZER(&remote_gws);
    const struct icsbrec_gateway *gw;
    ICSBREC_GATEWAY_FOR_EACH (gw, ctx->ovnisb_idl) {
        if (gw->availability_zone == ctx->runned_az) {
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
                icsbrec_gateway_set_availability_zone(gw, ctx->runned_az);
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

static const struct nbrec_logical_router *
find_tr_in_nb(struct ic_context *ctx, char *tr_name)
{
    const struct nbrec_logical_router *key =
        nbrec_logical_router_index_init_row(ctx->nbrec_lr_by_name);
    nbrec_logical_router_index_set_name(key, tr_name);

    const struct nbrec_logical_router *lr;
    bool found = false;
    NBREC_LOGICAL_ROUTER_FOR_EACH_EQUAL (lr, key, ctx->nbrec_lr_by_name) {
        if (smap_get(&lr->options, "interconn-tr")) {
            found = true;
            break;
        }
    }

    nbrec_logical_router_index_destroy_row(key);
    if (found) {
        return lr;
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

static const struct sbrec_datapath_binding *
find_sb_dp_by_nb_uuid(struct ovsdb_idl_index *sbrec_datapath_binding,
                      const struct uuid *nb_uuid)
{
    const struct sbrec_datapath_binding *key =
        sbrec_datapath_binding_index_init_row(sbrec_datapath_binding);

    sbrec_datapath_binding_set_nb_uuid(key, nb_uuid, 1);

    const struct sbrec_datapath_binding *dp =
        sbrec_datapath_binding_index_find(sbrec_datapath_binding, key);
    sbrec_datapath_binding_index_destroy_row(key);

    return dp;
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

static const struct nbrec_logical_switch_port *
get_lsp_by_ts_port_name(struct ic_context *ctx, const char *ts_port_name)
{
    const struct nbrec_logical_switch_port *lsp, *key;

    key = nbrec_logical_switch_port_index_init_row(ctx->nbrec_port_by_name);
    nbrec_logical_switch_port_index_set_name(key, ts_port_name);
    lsp = nbrec_logical_switch_port_index_find(ctx->nbrec_port_by_name, key);
    nbrec_logical_switch_port_index_destroy_row(key);

    return lsp;
}

static const char *
get_lp_address_for_sb_pb(struct ic_context *ctx,
                         const struct sbrec_port_binding *sb_pb)
{
    const struct nbrec_logical_switch_port *nb_lsp;

    nb_lsp = get_lsp_by_ts_port_name(ctx, sb_pb->logical_port);
    if (!strcmp(nb_lsp->type, "switch")) {
        /* Switches always have implicit "unknown" address, and IC-SB port
         * binding can only have one address specified. */
        return "unknown";
    }

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

static inline void
sync_lrp_tnl_key(const struct nbrec_logical_router_port *lrp,
                 int64_t isb_tnl_key)
{
    int64_t tnl_key = smap_get_int(&lrp->options, "requested-tnl-key", 0);
    if (tnl_key != isb_tnl_key) {
        VLOG_DBG("Set options:requested-tnl-key %" PRId64 " for lrp %s in NB.",
                 isb_tnl_key, lrp->name);
        char *tnl_key_str = xasprintf("%"PRId64, isb_tnl_key);
        nbrec_logical_router_port_update_options_setkey(
            lrp, "requested-tnl-key", tnl_key_str);
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

    return datapath_get_nb_uuid(router_pb->datapath, router_uuid);
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
    const char *address = get_lp_address_for_sb_pb(ctx, sb_pb);
    if (!address) {
        VLOG_DBG("Can't get router/switch port address for logical"
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
    } else if (!strcmp(lsp->type, "switch") && sb_pb->chassis) {
        if (strcmp(sb_pb->chassis->name, isb_pb->gateway)) {
            icsbrec_port_binding_set_gateway(isb_pb, sb_pb->chassis->name);
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

    /* Skip port binding if it is already requested by the CMS. */
    if (smap_get(&lsp->options, "requested-chassis")) {
        return;
    }

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

/* For each remote port:
 *   - Sync from ISB to NB
 */
static void
sync_router_port(const struct icsbrec_port_binding *isb_pb,
                 const struct icnbrec_transit_router_port *trp,
                 const struct nbrec_logical_router_port *lrp)
{
    /* Sync from ICNB to NB */
    if (trp->chassis[0]) {
        const char *chassis_name =
            smap_get_def(&lrp->options, "requested-chassis", "");
        if (strcmp(trp->chassis, chassis_name)) {
            nbrec_logical_router_port_update_options_setkey(
                lrp, "requested-chassis", trp->chassis);
        }
    } else {
        nbrec_logical_router_port_update_options_delkey(
            lrp, "requested-chassis");
    }

    if (strcmp(trp->mac, lrp->mac)) {
        nbrec_logical_router_port_set_mac(lrp, trp->mac);
    }

    bool sync_networks = false;
    if (trp->n_networks != lrp->n_networks) {
        sync_networks = true;
    } else {
        for (size_t i = 0; i < trp->n_networks; i++) {
            if (strcmp(trp->networks[i], lrp->networks[i])) {
                sync_networks |= true;
                break;
            }
        }
    }

    if (sync_networks) {
        nbrec_logical_router_port_set_networks(
            lrp, (const char **) trp->networks, trp->n_networks);
    }

    /* Sync tunnel key from ISB to NB */
    sync_lrp_tnl_key(lrp, isb_pb->tunnel_key);
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

static uint32_t
allocate_port_key(struct hmap *pb_tnlids)
{
    static uint32_t hint;
    return ovn_allocate_tnlid(pb_tnlids, "transit port",
                              1, (1u << 15) - 1, &hint);
}

static const struct icsbrec_port_binding *
create_isb_pb(struct ic_context *ctx, const char *logical_port,
              const struct icsbrec_availability_zone *az, const char *ts_name,
              const struct uuid *nb_ic_uuid, const char *type,
              struct hmap *pb_tnlids)
{
    uint32_t pb_tnl_key = allocate_port_key(pb_tnlids);
    if (!pb_tnl_key) {
        return NULL;
    }

    const struct icsbrec_port_binding *isb_pb =
        icsbrec_port_binding_insert(ctx->ovnisb_txn);
    icsbrec_port_binding_set_availability_zone(isb_pb, az);
    icsbrec_port_binding_set_transit_switch(isb_pb, ts_name);
    icsbrec_port_binding_set_logical_port(isb_pb, logical_port);
    icsbrec_port_binding_set_tunnel_key(isb_pb, pb_tnl_key);
    icsbrec_port_binding_set_nb_ic_uuid(isb_pb, nb_ic_uuid, 1);
    icsbrec_port_binding_set_type(isb_pb, type);
    return isb_pb;
}

static const struct nbrec_logical_router_port *
get_lrp_by_lrp_name(struct ic_context *ctx, const char *lrp_name)
{
    const struct nbrec_logical_router_port *lrp;
    const struct nbrec_logical_router_port *lrp_key =
        nbrec_logical_router_port_index_init_row(ctx->nbrec_lrp_by_name);
    nbrec_logical_router_port_index_set_name(lrp_key, lrp_name);
    lrp =
        nbrec_logical_router_port_index_find(ctx->nbrec_lrp_by_name, lrp_key);
    nbrec_logical_router_port_index_destroy_row(lrp_key);

    return lrp;
}

static bool
trp_is_remote(struct ic_context *ctx, const char *chassis_name)
{
    if (chassis_name) {
        const struct sbrec_chassis *chassis =
            find_sb_chassis(ctx, chassis_name);
        if (chassis) {
            return smap_get_bool(&chassis->other_config, "is-remote", false);
        } else {
            return true;
        }
    }

    return false;
}

static struct nbrec_logical_router_port *
lrp_create(struct ic_context *ctx, const struct nbrec_logical_router *lr,
           const struct icnbrec_transit_router_port *trp)
{
    struct nbrec_logical_router_port *lrp =
        nbrec_logical_router_port_insert(ctx->ovnnb_txn);
    nbrec_logical_router_port_set_name(lrp, trp->name);

    nbrec_logical_router_port_update_options_setkey(lrp, "interconn-tr",
                                                    trp->name);
    nbrec_logical_router_update_ports_addvalue(lr, lrp);
    return lrp;
}

static void
sync_ts_isb_pb(struct ic_context *ctx, const struct sbrec_port_binding *sb_pb,
               const struct icsbrec_port_binding *isb_pb)
{
    const char *address = get_lp_address_for_sb_pb(ctx, sb_pb);
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

static void
port_binding_run(struct ic_context *ctx)
{
    if (!ctx->ovnisb_txn || !ctx->ovnnb_txn || !ctx->ovnsb_txn) {
        return;
    }

    struct shash switch_all_local_pbs =
        SHASH_INITIALIZER(&switch_all_local_pbs);
    struct shash router_all_local_pbs =
        SHASH_INITIALIZER(&router_all_local_pbs);
    struct hmap pb_tnlids = HMAP_INITIALIZER(&pb_tnlids);
    struct shash_node *node;

    const struct icsbrec_port_binding *isb_pb;
    const struct icsbrec_port_binding *isb_pb_key =
        icsbrec_port_binding_index_init_row(ctx->icsbrec_port_binding_by_az);
    icsbrec_port_binding_index_set_availability_zone(isb_pb_key,
                                                     ctx->runned_az);

    ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
                                         ctx->icsbrec_port_binding_by_az) {
        ic_pb_get_type(isb_pb) != IC_ROUTER_PORT
            ? shash_add(&switch_all_local_pbs, isb_pb->logical_port, isb_pb)
            : shash_add(&router_all_local_pbs, isb_pb->logical_port, isb_pb);

        ovn_add_tnlid(&pb_tnlids, isb_pb->tunnel_key);
    }
    icsbrec_port_binding_index_destroy_row(isb_pb_key);

    const struct sbrec_port_binding *sb_pb;
    const struct icnbrec_transit_switch *ts;
    ICNBREC_TRANSIT_SWITCH_FOR_EACH (ts, ctx->ovninb_idl) {
        const struct nbrec_logical_switch *ls = find_ts_in_nb(ctx, ts->name);
        if (!ls) {
            VLOG_DBG("Transit switch %s not found in NB.", ts->name);
            continue;
        }
        struct shash local_pbs = SHASH_INITIALIZER(&local_pbs);
        struct shash remote_pbs = SHASH_INITIALIZER(&remote_pbs);

        isb_pb_key = icsbrec_port_binding_index_init_row(
            ctx->icsbrec_port_binding_by_ts);
        icsbrec_port_binding_index_set_transit_switch(isb_pb_key, ts->name);

        ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
                                             ctx->icsbrec_port_binding_by_ts) {
            if (isb_pb->availability_zone == ctx->runned_az) {
                shash_add(&local_pbs, isb_pb->logical_port, isb_pb);
                shash_find_and_delete(&switch_all_local_pbs,
                                      isb_pb->logical_port);
            } else {
                shash_add(&remote_pbs, isb_pb->logical_port, isb_pb);
            }
        }
        icsbrec_port_binding_index_destroy_row(isb_pb_key);

        const struct nbrec_logical_switch_port *lsp;
        for (int i = 0; i < ls->n_ports; i++) {
            lsp = ls->ports[i];

            if (!strcmp(lsp->type, "router")
                || !strcmp(lsp->type, "switch")) {
                /* The port is local. */
                sb_pb = find_lsp_in_sb(ctx, lsp);
                if (!sb_pb) {
                    continue;
                }
                isb_pb = shash_find_and_delete(&local_pbs, lsp->name);
                if (!isb_pb) {
                    isb_pb = create_isb_pb(
                        ctx, sb_pb->logical_port, ctx->runned_az, ts->name,
                        &ts->header_.uuid, "transit-switch-port", &pb_tnlids);
                    sync_ts_isb_pb(ctx, sb_pb, isb_pb);
                } else {
                    sync_local_port(ctx, isb_pb, sb_pb, lsp);
                }

                if (isb_pb->type) {
                    icsbrec_port_binding_set_type(isb_pb,
                                                  "transit-switch-port");
                }

                if (isb_pb->nb_ic_uuid) {
                    icsbrec_port_binding_set_nb_ic_uuid(isb_pb,
                                                        &ts->header_.uuid, 1);
                }
            } else if (!strcmp(lsp->type, "remote")) {
                /* The port is remote. */
                isb_pb = shash_find_and_delete(&remote_pbs, lsp->name);
                if (!isb_pb) {
                    nbrec_logical_switch_update_ports_delvalue(ls, lsp);
                } else {
                    sb_pb = find_lsp_in_sb(ctx, lsp);
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
        SHASH_FOR_EACH (node, &local_pbs) {
            icsbrec_port_binding_delete(node->data);
        }

        /* Create lsp in NB for remote ports */
        SHASH_FOR_EACH (node, &remote_pbs) {
            create_nb_lsp(ctx, node->data, ls);
        }

        shash_destroy(&local_pbs);
        shash_destroy(&remote_pbs);
    }

    SHASH_FOR_EACH (node, &switch_all_local_pbs) {
        icsbrec_port_binding_delete(node->data);
    }
    shash_destroy(&switch_all_local_pbs);

    const struct icnbrec_transit_router *tr;
    ICNBREC_TRANSIT_ROUTER_FOR_EACH (tr, ctx->ovninb_idl) {
        const struct nbrec_logical_router *lr = find_tr_in_nb(ctx, tr->name);
        if (!lr) {
            VLOG_DBG("Transit router %s not found in NB.", tr->name);
            continue;
        }

        struct shash nb_ports = SHASH_INITIALIZER(&nb_ports);
        struct shash local_pbs = SHASH_INITIALIZER(&local_pbs);
        struct shash remote_pbs = SHASH_INITIALIZER(&remote_pbs);

        for (size_t i = 0; i < lr->n_ports; i++) {
            const struct nbrec_logical_router_port *lrp = lr->ports[i];
            if (smap_get_def(&lrp->options, "interconn-tr", NULL)) {
                shash_add(&nb_ports, lrp->name, lrp);
            }
        }

        isb_pb_key = icsbrec_port_binding_index_init_row(
            ctx->icsbrec_port_binding_by_ts);
        icsbrec_port_binding_index_set_transit_switch(isb_pb_key, tr->name);

        ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
                                             ctx->icsbrec_port_binding_by_ts) {
            if (isb_pb->availability_zone == ctx->runned_az) {
                shash_add(&local_pbs, isb_pb->logical_port, isb_pb);
                shash_find_and_delete(&router_all_local_pbs,
                                      isb_pb->logical_port);
            } else {
                shash_add(&remote_pbs, isb_pb->logical_port, isb_pb);
            }
        }
        icsbrec_port_binding_index_destroy_row(isb_pb_key);

        for (size_t i = 0; i < tr->n_ports; i++) {
            const struct icnbrec_transit_router_port *trp = tr->ports[i];

            if (trp_is_remote(ctx, trp->chassis)) {
                isb_pb = shash_find_and_delete(&remote_pbs, trp->name);
            } else {
                isb_pb = shash_find_and_delete(&local_pbs, trp->name);
                if (!isb_pb) {
                    isb_pb = create_isb_pb(ctx, trp->name, ctx->runned_az,
                                           tr->name, &tr->header_.uuid,
                                           "transit-router-port", &pb_tnlids);
                    icsbrec_port_binding_set_address(isb_pb, trp->mac);
                }
            }

            /* Don't allow remote ports to create NB LRP until ICSB entry is
             * created in the appropriate AZ. */
            if (isb_pb) {
                const struct nbrec_logical_router_port *lrp =
                    shash_find_and_delete(&nb_ports, trp->name);
                if (!lrp) {
                    lrp = lrp_create(ctx, lr, trp);
                }

                sync_router_port(isb_pb, trp, lrp);
            }
        }

        SHASH_FOR_EACH(node, &nb_ports) {
            nbrec_logical_router_port_delete(node->data);
            nbrec_logical_router_update_ports_delvalue(lr, node->data);
        }

        shash_destroy(&nb_ports);
        shash_destroy(&local_pbs);
        shash_destroy(&remote_pbs);
    }

    SHASH_FOR_EACH (node, &router_all_local_pbs) {
        icsbrec_port_binding_delete(node->data);
    }

    ovn_destroy_tnlids(&pb_tnlids);
    shash_destroy(&router_all_local_pbs);
}

struct ic_router_info {
    struct hmap_node node;
    const struct nbrec_logical_router *lr; /* key of hmap */
    struct vector isb_pbs; /* Vector of const struct icsbrec_port_binding *. */
    struct hmap routes_learned;
};

/* Represents an interconnection route entry. */
struct ic_route_info {
    struct hmap_node node;
    struct in6_addr prefix;
    unsigned int plen;
    struct in6_addr nexthop;
    const char *origin;
    const char *route_table;
    const char *route_tag;

    const struct nbrec_logical_router *nb_lr;

    /* One of nb_route, nb_lrp, nb_lb is set and the other ones must be NULL.
     * - For a route that is learned from IC-SB, or a static route that is
     *   generated from a route that is configured in NB, the "nb_route"
     *   is set.
     * - For a route that is generated from a direct-connect subnet of
     *   a logical router port, the "nb_lrp" is set.
     * - For a route that is generated from a load-balancer vip of
     *   a logical router, the "nb_lb" is set. */
    const struct nbrec_logical_router_static_route *nb_route;
    const struct nbrec_logical_router_port *nb_lrp;
    const struct nbrec_load_balancer *nb_lb;
};

static uint32_t
ic_route_hash(const struct in6_addr *prefix, unsigned int plen,
              const struct in6_addr *nexthop, const char *origin,
              const char *route_table)
{
    uint32_t basis = hash_bytes(prefix, sizeof *prefix, (uint32_t)plen);
    basis = hash_string(origin, basis);
    basis = hash_string(route_table, basis);
    return hash_bytes(nexthop, sizeof *nexthop, basis);
}

static struct ic_route_info *
ic_route_find(struct hmap *routes, const struct in6_addr *prefix,
              unsigned int plen, const struct in6_addr *nexthop,
              const char *origin, const char *route_table, uint32_t hash)
{
    struct ic_route_info *r;
    if (!hash) {
        hash = ic_route_hash(prefix, plen, nexthop, origin, route_table);
    }
    HMAP_FOR_EACH_WITH_HASH (r, node, hash, routes) {
        if (ipv6_addr_equals(&r->prefix, prefix) &&
            r->plen == plen &&
            ipv6_addr_equals(&r->nexthop, nexthop) &&
            !strcmp(r->origin, origin) &&
            !strcmp(r->route_table ? r->route_table : "", route_table)) {
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
    if (strcmp(s_nexthop, "discard") &&
        !ip46_parse_cidr(s_nexthop, nexthop, &nlen)) {
        return false;
    }

    /* Do not learn routes with link-local next hop. */
    return !in6_is_lla(nexthop);
}

/* Return false if can't be added due to bad format. */
static bool
add_to_routes_learned(struct hmap *routes_learned,
                      const struct nbrec_logical_router_static_route *nb_route,
                      const struct nbrec_logical_router *nb_lr)
{
    struct in6_addr prefix, nexthop;
    unsigned int plen;
    if (!parse_route(nb_route->ip_prefix, nb_route->nexthop,
                     &prefix, &plen, &nexthop)) {
        return false;
    }
    const char *origin = smap_get_def(&nb_route->options, "origin", "");
    if (ic_route_find(routes_learned, &prefix, plen, &nexthop, origin,
                      nb_route->route_table, 0)) {
        /* Route was added to learned on previous iteration. */
        return true;
    }

    struct ic_route_info *ic_route = xzalloc(sizeof *ic_route);
    ic_route->prefix = prefix;
    ic_route->plen = plen;
    ic_route->nexthop = nexthop;
    ic_route->nb_route = nb_route;
    ic_route->origin = origin;
    ic_route->route_table = nb_route->route_table;
    ic_route->nb_lr = nb_lr;
    hmap_insert(routes_learned, &ic_route->node,
                ic_route_hash(&prefix, plen, &nexthop, origin,
                              nb_route->route_table));
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
prefix_is_filtered(struct in6_addr *prefix,
                   unsigned int plen,
                   const struct nbrec_logical_router *nb_lr,
                   const struct nbrec_logical_router_port *ts_lrp,
                   bool is_advertisement)
{
    struct ds filter_list = DS_EMPTY_INITIALIZER;
    const char *filter_direction = is_advertisement ? "ic-route-filter-adv" :
                                                      "ic-route-filter-learn";
    if (ts_lrp) {
        const char *lrp_route_filter = smap_get(&ts_lrp->options,
                                                filter_direction);
        if (lrp_route_filter) {
            ds_put_format(&filter_list, "%s,", lrp_route_filter);
        }
    }
    const char *lr_route_filter = smap_get(&nb_lr->options,
                                           filter_direction);
    if (lr_route_filter) {
        ds_put_format(&filter_list, "%s,", lr_route_filter);
    }

    struct sset prefix_set = SSET_INITIALIZER(&prefix_set);
    sset_from_delimited_string(&prefix_set, ds_cstr(&filter_list), ",");

    bool matched = true;
    if (!sset_is_empty(&prefix_set)) {
        matched = find_prefix_in_set(prefix, plen, &prefix_set,
                                     filter_direction);
    }

    ds_destroy(&filter_list);
    sset_destroy(&prefix_set);
    return matched;
}

static bool
prefix_is_deny_filtered(struct in6_addr *prefix,
                        unsigned int plen,
                        const struct smap *nb_options,
                        const struct nbrec_logical_router *nb_lr,
                        const struct nbrec_logical_router_port *ts_lrp,
                        bool is_advertisement)
{
    struct ds deny_list = DS_EMPTY_INITIALIZER;
    const char *deny_key = is_advertisement ? "ic-route-deny-adv" :
                                              "ic-route-deny-learn";

    if (ts_lrp) {
        const char *lrp_deny_filter = smap_get(&ts_lrp->options, deny_key);
        if (lrp_deny_filter) {
            ds_put_format(&deny_list, "%s,", lrp_deny_filter);
        }
    }

    if (nb_lr) {
        const char *lr_deny_filter = smap_get(&nb_lr->options, deny_key);
        if (lr_deny_filter) {
            ds_put_format(&deny_list, "%s,", lr_deny_filter);
        }
    }

    if (nb_options) {
        const char *global_deny = smap_get(nb_options, "ic-route-denylist");
        if (!global_deny || !global_deny[0]) {
            global_deny = smap_get(nb_options, "ic-route-blacklist");
        }
        if (global_deny && global_deny[0]) {
            ds_put_format(&deny_list, "%s,", global_deny);
        }
    }

    struct sset prefix_set = SSET_INITIALIZER(&prefix_set);
    sset_from_delimited_string(&prefix_set, ds_cstr(&deny_list), ",");

    bool denied = false;
    if (!sset_is_empty(&prefix_set)) {
        denied = find_prefix_in_set(prefix, plen, &prefix_set, deny_key);
    }

    ds_destroy(&deny_list);
    sset_destroy(&prefix_set);
    return denied;
}

static bool
route_need_advertise(const char *policy,
                     struct in6_addr *prefix,
                     unsigned int plen,
                     const struct smap *nb_options,
                     const struct nbrec_logical_router *nb_lr,
                     const struct nbrec_logical_router_port *ts_lrp)
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

    if (prefix_is_deny_filtered(prefix, plen, nb_options,
                                nb_lr, ts_lrp, true)) {
        return false;
    }

    if (!prefix_is_filtered(prefix, plen, nb_lr, ts_lrp, true)) {
        return false;
    }

    return true;
}

static void
add_to_routes_ad(struct hmap *routes_ad, const struct in6_addr prefix,
                 unsigned int plen, const struct in6_addr nexthop,
                 const char *origin, const char *route_table,
                 const struct nbrec_logical_router_port *nb_lrp,
                 const struct nbrec_logical_router_static_route *nb_route,
                 const struct nbrec_logical_router *nb_lr,
                 const struct nbrec_load_balancer *nb_lb,
                 const char *route_tag)
{
    ovs_assert(nb_route || nb_lrp || nb_lb || nb_lr);

    if (route_table == NULL) {
        route_table = "";
    }

    uint hash = ic_route_hash(&prefix, plen, &nexthop, origin, route_table);

    if (!ic_route_find(routes_ad, &prefix, plen, &nexthop, origin, route_table,
                       hash)) {
        struct ic_route_info *ic_route = xzalloc(sizeof *ic_route);
        ic_route->prefix = prefix;
        ic_route->plen = plen;
        ic_route->nexthop = nexthop;
        ic_route->nb_route = nb_route;
        ic_route->origin = origin;
        ic_route->route_table = route_table;
        ic_route->nb_lrp = nb_lrp;
        ic_route->nb_lr = nb_lr;
        ic_route->nb_lb = nb_lb;
        ic_route->route_tag = route_tag;
        hmap_insert(routes_ad, &ic_route->node, hash);
    } else {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        const char *msg_fmt = "Duplicate %s route advertisement was "
                              "suppressed! NB %s uuid: "UUID_FMT;
        if (nb_route) {
            VLOG_WARN_RL(&rl, msg_fmt, origin, "route",
                         UUID_ARGS(&nb_route->header_.uuid));
        } else if (nb_lb) {
            VLOG_WARN_RL(&rl, msg_fmt, origin, "loadbalancer",
                         UUID_ARGS(&nb_lb->header_.uuid));
        } else if (nb_lrp) {
            VLOG_WARN_RL(&rl, msg_fmt, origin, "lrp",
                         UUID_ARGS(&nb_lrp->header_.uuid));
        } else {
            VLOG_WARN_RL(&rl, msg_fmt, origin, "lr",
                UUID_ARGS(&nb_lr->header_.uuid));
        }
    }
}

static void
add_static_to_routes_ad(
    struct hmap *routes_ad,
    const struct nbrec_logical_router_static_route *nb_route,
    const struct nbrec_logical_router *nb_lr,
    const struct lport_addresses *nexthop_addresses,
    const struct smap *nb_options,
    const char *route_tag,
    const struct nbrec_logical_router_port *ts_lrp)
{
    struct in6_addr prefix, nexthop;
    unsigned int plen;
    if (!parse_route(nb_route->ip_prefix, nb_route->nexthop,
                     &prefix, &plen, &nexthop)) {
        return;
    }

    if (!route_need_advertise(nb_route->policy, &prefix, plen, nb_options,
                              nb_lr, ts_lrp)) {
        return;
    }

    if (!get_nexthop_from_lport_addresses(IN6_IS_ADDR_V4MAPPED(&prefix),
                                          nexthop_addresses,
                                          &nexthop)) {
        return;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        ds_put_format(&msg, "Advertising static route: %s -> %s, ic nexthop: ",
                      nb_route->ip_prefix, nb_route->nexthop);

        if (IN6_IS_ADDR_V4MAPPED(&nexthop)) {
            ds_put_format(&msg, IP_FMT,
                          IP_ARGS(in6_addr_get_mapped_ipv4(&nexthop)));
        } else {
            ipv6_format_addr(&nexthop, &msg);
        }

        ds_put_format(&msg, ", route_table: %s", nb_route->route_table[0]
                                                 ? nb_route->route_table
                                                 : "<main>");

        VLOG_DBG("%s", ds_cstr(&msg));
        ds_destroy(&msg);
    }

    add_to_routes_ad(routes_ad, prefix, plen, nexthop, ROUTE_ORIGIN_STATIC,
                     nb_route->route_table, NULL, nb_route, nb_lr,
                     NULL, route_tag);
}

static void
add_network_to_routes_ad(struct hmap *routes_ad, const char *network,
                         const struct nbrec_logical_router_port *nb_lrp,
                         const struct lport_addresses *nexthop_addresses,
                         const struct smap *nb_options,
                         const struct nbrec_logical_router *nb_lr,
                         const char *route_tag,
                         const struct nbrec_logical_router_port *ts_lrp)
{
    struct in6_addr prefix, nexthop;
    unsigned int plen;
    if (!ip46_parse_cidr(network, &prefix, &plen)) {
        return;
    }

    if (!route_need_advertise(NULL, &prefix, plen, nb_options,
                              nb_lr, ts_lrp)) {
        if (VLOG_IS_DBG_ENABLED()) {
            struct ds msg = DS_EMPTY_INITIALIZER;
            ds_put_format(&msg, "Route ad: skip network %s", network);
            if (nb_lrp) {
                ds_put_format(&msg, " of lrp %s", nb_lrp->name);
            }
            ds_put_format(&msg, ".");
            VLOG_DBG("%s", ds_cstr(&msg));
            ds_destroy(&msg);
        }
        return;
    }

    if (!get_nexthop_from_lport_addresses(IN6_IS_ADDR_V4MAPPED(&prefix),
                                          nexthop_addresses,
                                          &nexthop)) {
        return;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        ds_put_format(&msg, "Adding direct network route to <main> routing "
                      "table: %s", network);

        if (nb_lrp) {
            ds_put_format(&msg, " of lrp %s,", nb_lrp->name);
        }
        ds_put_format(&msg, " nexthop ");
        if (IN6_IS_ADDR_V4MAPPED(&nexthop)) {
            ds_put_format(&msg, IP_FMT,
                          IP_ARGS(in6_addr_get_mapped_ipv4(&nexthop)));
        } else {
            ipv6_format_addr(&nexthop, &msg);
        }

        VLOG_DBG("%s", ds_cstr(&msg));
        ds_destroy(&msg);
    }

    /* directly-connected routes go to <main> route table */
    add_to_routes_ad(routes_ad, prefix, plen, nexthop, ROUTE_ORIGIN_CONNECTED,
                     NULL, nb_lrp, NULL, nb_lr, NULL, route_tag);
}

static void
add_lb_vip_to_routes_ad(struct hmap *routes_ad, const char *vip_key,
                        const struct nbrec_load_balancer *nb_lb,
                        const struct lport_addresses *nexthop_addresses,
                        const struct smap *nb_options,
                        const struct nbrec_logical_router *nb_lr,
                        const char *route_tag,
                        const struct nbrec_logical_router_port *ts_lrp)
{
    char *vip_str = NULL;
    struct in6_addr vip_ip, nexthop;
    uint16_t vip_port;
    int addr_family;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

    if (!ip_address_and_port_from_lb_key(vip_key, &vip_str, &vip_ip,
                                         &vip_port, &addr_family)) {
        VLOG_WARN_RL(&rl, "Route ad: Parsing failed for lb vip %s", vip_key);
        return;
    }
    if (vip_str == NULL) {
        return;
    }
    unsigned int plen = (addr_family == AF_INET) ? 32 : 128;
    if (!route_need_advertise(NULL, &vip_ip, plen, nb_options,
                              nb_lr, ts_lrp)) {
        VLOG_DBG("Route ad: skip lb vip %s.", vip_key);
        goto out;
    }
    if (!get_nexthop_from_lport_addresses(IN6_IS_ADDR_V4MAPPED(&vip_ip),
                                          nexthop_addresses,
                                          &nexthop)) {
        VLOG_WARN_RL(&rl, "Route ad: failed to get nexthop for lb vip");
        goto out;
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        ds_put_format(&msg, "Adding lb vip route to <main> routing "
                      "table: %s, nexthop ", vip_str);

        if (IN6_IS_ADDR_V4MAPPED(&nexthop)) {
            ds_put_format(&msg, IP_FMT,
                          IP_ARGS(in6_addr_get_mapped_ipv4(&nexthop)));
        } else {
            ipv6_format_addr(&nexthop, &msg);
        }

        VLOG_DBG("%s", ds_cstr(&msg));
        ds_destroy(&msg);
    }

    /* Lb vip routes go to <main> route table */
    add_to_routes_ad(routes_ad, vip_ip, plen, nexthop, ROUTE_ORIGIN_LB,
                     NULL, NULL, NULL, nb_lr, nb_lb, route_tag);
out:
    free(vip_str);
}

static bool
route_has_local_gw(const struct nbrec_logical_router *lr,
                   const char *route_table, const char *ip_prefix) {

    const struct nbrec_logical_router_static_route *route;
    for (int i = 0; i < lr->n_static_routes; i++) {
        route = lr->static_routes[i];
        if (!smap_get(&route->external_ids, "ic-learned-route") &&
            !strcmp(route->route_table, route_table) &&
            !strcmp(route->ip_prefix, ip_prefix)) {
            return true;
        }
    }
    return false;
}

static bool
lrp_has_neighbor_in_ts(const struct nbrec_logical_router_port *lrp,
                       struct in6_addr *nexthop)
{
    if (!lrp || !nexthop) {
        return false;
    }

    struct lport_addresses lrp_networks;
    if (!extract_lrp_networks(lrp, &lrp_networks)) {
        destroy_lport_addresses(&lrp_networks);
        return false;
    }

    if (IN6_IS_ADDR_V4MAPPED(nexthop)) {
        ovs_be32 neigh_prefix_v4 = in6_addr_get_mapped_ipv4(nexthop);
        for (size_t i = 0; i < lrp_networks.n_ipv4_addrs; i++) {
            struct ipv4_netaddr address = lrp_networks.ipv4_addrs[i];
            if (address.network == (neigh_prefix_v4 & address.mask)) {
                destroy_lport_addresses(&lrp_networks);
                return true;
            }
        }
    } else {
        for (size_t i = 0; i < lrp_networks.n_ipv6_addrs; i++) {
            struct ipv6_netaddr address = lrp_networks.ipv6_addrs[i];
            struct in6_addr neigh_prefix = ipv6_addr_bitand(nexthop,
                                                            &address.mask);
            if (ipv6_addr_equals(&address.network, &neigh_prefix)) {
                destroy_lport_addresses(&lrp_networks);
                return true;
            }
        }
    }

    destroy_lport_addresses(&lrp_networks);
    return false;
}

static bool
route_matches_local_lb(const struct nbrec_load_balancer *nb_lb,
                       const char *ip_prefix)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
    struct in6_addr prefix;
    unsigned int plen;

    if (!ip46_parse_cidr(ip_prefix, &prefix, &plen)) {
        return false;
    }

    struct smap_node *node;
    SMAP_FOR_EACH (node, &nb_lb->vips) {
        char *vip_str = NULL;
        struct in6_addr vip_ip;
        uint16_t vip_port;
        int addr_family;
        if (ip_address_and_port_from_lb_key(node->key, &vip_str,
                                            &vip_ip, &vip_port,
                                            &addr_family)) {
            if (IN6_IS_ADDR_V4MAPPED(&prefix) && addr_family == AF_INET) {
                ovs_be32 vip = in6_addr_get_mapped_ipv4(&vip_ip);
                ovs_be32 mask = be32_prefix_mask(plen);

                if ((vip & mask) == in6_addr_get_mapped_ipv4(&prefix)) {
                    free(vip_str);
                    return true;
                }
            } else if (!IN6_IS_ADDR_V4MAPPED(&prefix)
                       && addr_family == AF_INET6) {
                struct in6_addr mask = ipv6_create_mask(plen);
                struct in6_addr vip_prefix = ipv6_addr_bitand(&vip_ip, &mask);
                if (ipv6_addr_equals(&prefix, &vip_prefix)) {
                    free(vip_str);
                    return true;
                }
            }
            free(vip_str);
        } else {
            VLOG_WARN_RL(&rl,
                         "Route learn: Parsing failed for local lb vip %s",
                         node->key);
        }
    }
    return false;
}

static bool
route_need_learn(struct ic_context *ctx,
                 const struct nbrec_logical_router *lr,
                 const struct icsbrec_route *isb_route,
                 struct in6_addr *prefix, unsigned int plen,
                 const struct smap *nb_options,
                 const struct nbrec_logical_router_port *ts_lrp,
                 struct in6_addr *nexthop)
{
    if (!smap_get_bool(nb_options, "ic-route-learn", false)) {
        return false;
    }

    if (plen == 0 &&
        !smap_get_bool(nb_options, "ic-route-learn-default", false)) {
        return false;
    }

    if (!strcmp(isb_route->origin, ROUTE_ORIGIN_LB) &&
        !smap_get_bool(nb_options, "ic-route-learn-lb", false)) {
        return false;
    }

    if (!lrouter_is_enabled(lr)) {
        return false;
    }

    if (prefix_is_link_local(prefix, plen)) {
        return false;
    }

    if (prefix_is_deny_filtered(prefix, plen, nb_options, lr, ts_lrp, false)) {
        return false;
    }

    if (!prefix_is_filtered(prefix, plen, lr, ts_lrp, false)) {
        return false;
    }

    if (route_has_local_gw(lr, isb_route->route_table, isb_route->ip_prefix)) {
        VLOG_DBG("Skip learning %s (rtb:%s) route, as we've got one with "
                 "local GW", isb_route->ip_prefix, isb_route->route_table);
        return false;
    }

    if (!lrp_has_neighbor_in_ts(ts_lrp, nexthop)) {
        return false;
    }

    for (size_t i = 0; i < lr->n_load_balancer; i++) {
        if (route_matches_local_lb(lr->load_balancer[i],
                                   isb_route->ip_prefix)) {
            VLOG_DBG("Skip learning %s (rtb:%s) route, as we've got local"
                     " LB with matching VIP", isb_route->ip_prefix,
                     isb_route->route_table);
            return false;
        }
    }
    for (size_t i = 0; i < lr->n_load_balancer_group; i++) {
        const struct nbrec_load_balancer_group *nb_lbg =
            lr->load_balancer_group[i];
        for (size_t j = 0; j < nb_lbg->n_load_balancer; j++) {
            if (route_matches_local_lb(nb_lbg->load_balancer[j],
                                       isb_route->ip_prefix)) {
                VLOG_DBG("Skip learning %s (rtb:%s) route, as we've got local"
                         " LB with matching VIP", isb_route->ip_prefix,
                         isb_route->route_table);
                return false;
            }
        }
    }

    const struct sbrec_datapath_binding *dp =
        find_sb_dp_by_nb_uuid(ctx->sbrec_datapath_binding_by_nb_uuid,
                              &lr->header_.uuid);
    if (!dp) {
        return true;
    }


    struct sbrec_learned_route *filter = sbrec_learned_route_index_init_row(
        ctx->sbrec_learned_route_by_datapath);
    sbrec_learned_route_index_set_datapath(filter, dp);
    struct sbrec_learned_route *sb_route;
    SBREC_LEARNED_ROUTE_FOR_EACH_EQUAL (sb_route, filter,
                                        ctx->sbrec_learned_route_by_datapath) {
        if (!strcmp(isb_route->ip_prefix, sb_route->ip_prefix)) {
            sbrec_learned_route_index_destroy_row(filter);
                VLOG_DBG("Skip learning %s (rtb:%s) route, as we've got"
                         " dynamic routing learned", isb_route->ip_prefix,
                         isb_route->route_table);
            return false;
        }
    }
    sbrec_learned_route_index_destroy_row(filter);

    return true;
}

static const char *
get_lrp_name_by_ts_port_name(struct ic_context *ctx, const char *ts_port_name)
{
    const struct nbrec_logical_switch_port *nb_lsp;

    nb_lsp = get_lsp_by_ts_port_name(ctx, ts_port_name);
    if (!nb_lsp) {
        return NULL;
    }

    return smap_get(&nb_lsp->options, "router-port");
}

static const struct nbrec_logical_router_port *
find_lrp_of_nexthop(struct ic_context *ctx,
                    const struct icsbrec_route *isb_route)
{
    const struct nbrec_logical_router_port *lrp;
    const struct nbrec_logical_switch *ls;
    ls = find_ts_in_nb(ctx, isb_route->transit_switch);
    if (!ls) {
        return NULL;
    }

    struct in6_addr nexthop;
    if (!ip46_parse(isb_route->nexthop, &nexthop)) {
        return NULL;
    }

    for (size_t i = 0; i < ls->n_ports; i++) {
        char *lsp_name = ls->ports[i]->name;
        const char *lrp_name = get_lrp_name_by_ts_port_name(ctx,
                                                            lsp_name);
        if (!lrp_name) {
            continue;
        }

        lrp = get_lrp_by_lrp_name(ctx, lrp_name);
        if (!lrp) {
            continue;
        }

        struct lport_addresses lrp_networks;
        if (!extract_lrp_networks(lrp, &lrp_networks)) {
            destroy_lport_addresses(&lrp_networks);
            continue;
        }

        if (IN6_IS_ADDR_V4MAPPED(&nexthop)) {
            ovs_be32 nexthop_v4 = in6_addr_get_mapped_ipv4(&nexthop);
            for (size_t i_v4 = 0; i_v4  < lrp_networks.n_ipv4_addrs; i_v4++) {
                struct ipv4_netaddr address = lrp_networks.ipv4_addrs[i_v4];
                if (address.addr == nexthop_v4) {
                    destroy_lport_addresses(&lrp_networks);
                    return lrp;
                }
            }
        } else {
            for (size_t i_v6 = 0; i_v6 < lrp_networks.n_ipv6_addrs; i_v6++) {
                struct ipv6_netaddr address = lrp_networks.ipv6_addrs[i_v6];
                struct in6_addr nexthop_v6 = ipv6_addr_bitand(&nexthop,
                                                              &address.mask);
                if (ipv6_addr_equals(&address.network, &nexthop_v6)) {
                    destroy_lport_addresses(&lrp_networks);
                    return lrp;
                }
            }
        }
        destroy_lport_addresses(&lrp_networks);
    }

    return NULL;
}

static bool
lrp_is_ts_port(struct ic_context *ctx, struct ic_router_info *ic_lr,
               const char *lrp_name)
{
    const struct icsbrec_port_binding *isb_pb;
    const char *ts_lrp_name;
    VECTOR_FOR_EACH (&ic_lr->isb_pbs, isb_pb) {
        ts_lrp_name = get_lrp_name_by_ts_port_name(ctx, isb_pb->logical_port);
        if (!strcmp(ts_lrp_name, lrp_name)) {
            return true;
        }
    }
    return false;
}

static void
sync_learned_routes(struct ic_context *ctx,
                    struct ic_router_info *ic_lr)
{
    ovs_assert(ctx->ovnnb_txn);
    const struct icsbrec_route *isb_route, *isb_route_key;

    const struct nbrec_nb_global *nb_global =
        nbrec_nb_global_first(ctx->ovnnb_idl);
    ovs_assert(nb_global);

    const char *lrp_name, *ts_route_table, *route_filter_tag;
    const struct icsbrec_port_binding *isb_pb;
    const struct nbrec_logical_router_port *lrp;
    VECTOR_FOR_EACH (&ic_lr->isb_pbs, isb_pb) {
        if (!strcmp(isb_pb->address, "")) {
            continue;
        }
        lrp_name = get_lrp_name_by_ts_port_name(ctx, isb_pb->logical_port);
        lrp = get_lrp_by_lrp_name(ctx, lrp_name);
        if (lrp) {
            ts_route_table = smap_get_def(&lrp->options, "route_table", "");
            route_filter_tag = smap_get_def(&lrp->options,
                                            "ic-route-filter-tag", "");
        } else {
            ts_route_table = "";
            route_filter_tag = "";
        }

        isb_route_key = icsbrec_route_index_init_row(ctx->icsbrec_route_by_ts);
        icsbrec_route_index_set_transit_switch(isb_route_key,
                                               isb_pb->transit_switch);

        ICSBREC_ROUTE_FOR_EACH_EQUAL (isb_route, isb_route_key,
                                      ctx->icsbrec_route_by_ts) {
            /* Filters ICSB routes, skipping those that either belong to
             * current logical router or are legacy routes from the current
             * availability zone (withoud lr-id).
             */
            const char *lr_id = smap_get(&isb_route->external_ids, "lr-id");
            struct uuid lr_uuid;
            if (lr_id) {
                if (!uuid_from_string(&lr_uuid, lr_id)
                    || uuid_equals(&ic_lr->lr->header_.uuid, &lr_uuid)) {
                    continue;
                }
            } else if (isb_route->availability_zone == ctx->runned_az) {
                continue;
            }

            const char *isb_route_tag = smap_get(&isb_route->external_ids,
                                                 "ic-route-tag");
            if (isb_route_tag  && !strcmp(isb_route_tag, route_filter_tag)) {
                VLOG_DBG("Skip learning route %s -> %s as its route tag "
                         "[%s] is filtered by the filter tag [%s] of TS LRP ",
                         isb_route->ip_prefix, isb_route->nexthop,
                         isb_route_tag, route_filter_tag);
                continue;
            }

            if (isb_route->route_table[0] &&
                strcmp(isb_route->route_table, ts_route_table)) {
                if (VLOG_IS_DBG_ENABLED()) {
                    VLOG_DBG("Skip learning static route %s -> %s as either "
                             "its route table %s != %s of TS port or ",
                             isb_route->ip_prefix, isb_route->nexthop,
                             isb_route->route_table, ts_route_table);
                }
                continue;
            }

            struct in6_addr prefix, nexthop;
            unsigned int plen;
            if (!parse_route(isb_route->ip_prefix, isb_route->nexthop,
                             &prefix, &plen, &nexthop)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "Bad route format in IC-SB: %s -> %s. "
                             "Ignored.", isb_route->ip_prefix,
                             isb_route->nexthop);
                continue;
            }
            if (!route_need_learn(ctx, ic_lr->lr, isb_route, &prefix, plen,
                                  &nb_global->options, lrp, &nexthop)) {
                continue;
            }

            struct ic_route_info *route_learned
                = ic_route_find(&ic_lr->routes_learned, &prefix, plen,
                                &nexthop, isb_route->origin,
                                isb_route->route_table, 0);
            if (route_learned) {
                /* Sync external-ids */
                struct uuid ext_id;
                smap_get_uuid(&route_learned->nb_route->external_ids,
                              "ic-learned-route", &ext_id);
                if (!uuid_equals(&ext_id, &isb_route->header_.uuid)) {
                    char *uuid_s =
                        xasprintf(UUID_FMT,
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
                nbrec_logical_router_static_route_set_ip_prefix(nb_route,
                    isb_route->ip_prefix);
                nbrec_logical_router_static_route_set_nexthop(nb_route,
                    isb_route->nexthop);
                char *uuid_s = xasprintf(UUID_FMT,
                                         UUID_ARGS(&isb_route->header_.uuid));
                nbrec_logical_router_static_route_set_route_table(nb_route,
                    isb_route->route_table);
                nbrec_logical_router_static_route_update_external_ids_setkey(
                    nb_route, "ic-learned-route", uuid_s);
                nbrec_logical_router_static_route_update_options_setkey(
                    nb_route, "origin", isb_route->origin);
                free(uuid_s);
                nbrec_logical_router_update_static_routes_addvalue(ic_lr->lr,
                    nb_route);
            }
        }
        icsbrec_route_index_destroy_row(isb_route_key);
    }

    /* Delete extra learned routes. */
    struct ic_route_info *route_learned;
    HMAP_FOR_EACH_SAFE (route_learned, node, &ic_lr->routes_learned) {
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
    struct uuid isb_ext_id, nb_id, isb_ext_lr_id, lr_id;
    const char *route_tag;
    smap_get_uuid(&isb_route->external_ids, "nb-id", &isb_ext_id);
    smap_get_uuid(&isb_route->external_ids, "lr-id", &isb_ext_lr_id);
    nb_id = route_adv->nb_lb ? route_adv->nb_lb->header_.uuid :
            route_adv->nb_route ? route_adv->nb_route->header_.uuid :
            route_adv->nb_lrp ? route_adv->nb_lrp->header_.uuid :
            route_adv->nb_lr->header_.uuid;

    lr_id = route_adv->nb_lr->header_.uuid;
    if (!uuid_equals(&isb_ext_id, &nb_id)) {
        char *uuid_s = xasprintf(UUID_FMT, UUID_ARGS(&nb_id));
        icsbrec_route_update_external_ids_setkey(isb_route, "nb-id",
                                                 uuid_s);
        free(uuid_s);
    }
    if (!uuid_equals(&isb_ext_lr_id, &lr_id)) {
        char *uuid_s = xasprintf(UUID_FMT, UUID_ARGS(&lr_id));
        icsbrec_route_update_external_ids_setkey(isb_route, "lr-id",
                                                 uuid_s);
        free(uuid_s);
    }
    if (strcmp(route_adv->route_tag, "")) {
        icsbrec_route_update_external_ids_setkey(isb_route, "ic-route-tag",
                                                 route_adv->route_tag);
    } else {
        route_tag = smap_get(&isb_route->external_ids, "ic-route-tag");
        if (route_tag) {
            icsbrec_route_update_external_ids_delkey(isb_route,
                                                     "ic-route-tag");
        }
    }
}

/* Sync routes from routes_ad to IC-SB. */
static void
advertise_routes(struct ic_context *ctx,
                 const struct icsbrec_availability_zone *az,
                 const char *ts_name,
                 struct hmap *routes_ad)
{
    ovs_assert(ctx->ovnisb_txn);
    const struct icsbrec_route *isb_route;
    const struct icsbrec_route *isb_route_key =
        icsbrec_route_index_init_row(ctx->icsbrec_route_by_ts_az);
    icsbrec_route_index_set_transit_switch(isb_route_key, ts_name);
    icsbrec_route_index_set_availability_zone(isb_route_key, az);

    ICSBREC_ROUTE_FOR_EACH_EQUAL (isb_route, isb_route_key,
                                  ctx->icsbrec_route_by_ts_az) {
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
            ic_route_find(routes_ad, &prefix, plen, &nexthop,
                          isb_route->origin, isb_route->route_table, 0);
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
    icsbrec_route_index_destroy_row(isb_route_key);

    /* Create the missing routes in IC-SB */
    struct ic_route_info *route_adv;
    HMAP_FOR_EACH_SAFE (route_adv, node, routes_ad) {
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
        icsbrec_route_set_origin(isb_route, route_adv->origin);
        icsbrec_route_set_route_table(isb_route, route_adv->route_table
                                                 ? route_adv->route_table
                                                 : "");
        free(prefix_s);
        free(nexthop_s);

        ad_route_sync_external_ids(route_adv, isb_route);

        hmap_remove(routes_ad, &route_adv->node);
        free(route_adv);
    }
}

static void
build_ts_routes_to_adv(struct ic_context *ctx,
                       struct ic_router_info *ic_lr,
                       struct hmap *routes_ad,
                       struct lport_addresses *ts_port_addrs,
                       const struct nbrec_nb_global *nb_global,
                       const char *ts_route_table,
                       const char *route_tag,
                       const struct nbrec_logical_router_port *ts_lrp)
{
    const struct nbrec_logical_router *lr = ic_lr->lr;

    /* Check static routes of the LR */
    for (int i = 0; i < lr->n_static_routes; i++) {
        const struct nbrec_logical_router_static_route *nb_route
            = lr->static_routes[i];
        struct uuid isb_uuid;
        if (smap_get_uuid(&nb_route->external_ids, "ic-learned-route",
                          &isb_uuid)) {
            /* It is a learned route */
            if (!add_to_routes_learned(&ic_lr->routes_learned, nb_route, lr)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "Bad format of learned route in NB: "
                             "%s -> %s. Delete it.", nb_route->ip_prefix,
                             nb_route->nexthop);
                nbrec_logical_router_update_static_routes_delvalue(lr,
                    nb_route);
            }
        } else if (!strcmp(ts_route_table, nb_route->route_table)) {
            /* It may be a route to be advertised */
            add_static_to_routes_ad(routes_ad, nb_route, lr, ts_port_addrs,
                                    &nb_global->options, route_tag, ts_lrp);
        }
    }

    /* Check directly-connected subnets of the LR */
    for (int i = 0; i < lr->n_ports; i++) {
        const struct nbrec_logical_router_port *lrp = lr->ports[i];
        if (!lrp_is_ts_port(ctx, ic_lr, lrp->name)) {
            for (int j = 0; j < lrp->n_networks; j++) {
                add_network_to_routes_ad(routes_ad, lrp->networks[j], lrp,
                                         ts_port_addrs,
                                         &nb_global->options,
                                         lr, route_tag, ts_lrp);
            }
        } else {
            /* The router port of the TS port is ignored. */
            VLOG_DBG("Skip advertising direct route of lrp %s (TS port)",
                     lrp->name);
        }
    }

    /* Check loadbalancers associated with the LR */
    if (smap_get_bool(&nb_global->options, "ic-route-adv-lb", false)) {
        for (size_t i = 0; i < lr->n_load_balancer; i++) {
            const struct nbrec_load_balancer *nb_lb = lr->load_balancer[i];
            struct smap_node *node;
            SMAP_FOR_EACH (node, &nb_lb->vips) {
                add_lb_vip_to_routes_ad(routes_ad, node->key, nb_lb,
                                        ts_port_addrs,
                                        &nb_global->options,
                                        lr, route_tag, ts_lrp);
            }
        }

        for (size_t i = 0; i < lr->n_load_balancer_group; i++) {
            const struct nbrec_load_balancer_group *nb_lbg =
                lr->load_balancer_group[i];
            for (size_t j = 0; j < nb_lbg->n_load_balancer; j++) {
                const struct nbrec_load_balancer *nb_lb =
                    nb_lbg->load_balancer[j];
                struct smap_node *node;
                SMAP_FOR_EACH (node, &nb_lb->vips) {
                    add_lb_vip_to_routes_ad(routes_ad, node->key, nb_lb,
                                            ts_port_addrs,
                                            &nb_global->options,
                                            lr, route_tag, ts_lrp);
                }
            }
        }
    }

    const struct sbrec_datapath_binding *dp =
        find_sb_dp_by_nb_uuid(ctx->sbrec_datapath_binding_by_nb_uuid,
                              &lr->header_.uuid);
    if (!dp) {
        return;
    }

    struct sbrec_learned_route *filter = sbrec_learned_route_index_init_row(
        ctx->sbrec_learned_route_by_datapath);
    sbrec_learned_route_index_set_datapath(filter, dp);
    struct sbrec_learned_route *sb_route;
    SBREC_LEARNED_ROUTE_FOR_EACH_EQUAL (sb_route, filter,
                                        ctx->sbrec_learned_route_by_datapath) {
        add_network_to_routes_ad(routes_ad, sb_route->ip_prefix, NULL,
                                 ts_port_addrs,
                                 &nb_global->options,
                                 lr, route_tag, ts_lrp);
    }
    sbrec_learned_route_index_destroy_row(filter);
}

static void
collect_lr_routes(struct ic_context *ctx,
                  struct ic_router_info *ic_lr,
                  struct shash *routes_ad_by_ts)
{
    const struct nbrec_nb_global *nb_global =
        nbrec_nb_global_first(ctx->ovnnb_idl);
    ovs_assert(nb_global);

    const struct icsbrec_port_binding *isb_pb;
    const char *lrp_name, *ts_name, *route_table, *route_tag;
    struct lport_addresses ts_port_addrs;
    const struct icnbrec_transit_switch *key;
    const struct nbrec_logical_router_port *lrp;

    struct hmap *routes_ad;
    const struct icnbrec_transit_switch *t_sw;
    VECTOR_FOR_EACH (&ic_lr->isb_pbs, isb_pb) {
        key = icnbrec_transit_switch_index_init_row(
            ctx->icnbrec_transit_switch_by_name);
        icnbrec_transit_switch_index_set_name(key, isb_pb->transit_switch);
        t_sw = icnbrec_transit_switch_index_find(
             ctx->icnbrec_transit_switch_by_name, key);
        icnbrec_transit_switch_index_destroy_row(key);
        if (!t_sw) {
            continue;
        }
        ts_name = t_sw->name;
        routes_ad = shash_find_data(routes_ad_by_ts, ts_name);
        if (!routes_ad) {
            routes_ad = xzalloc(sizeof *routes_ad);
            hmap_init(routes_ad);
            shash_add(routes_ad_by_ts, ts_name, routes_ad);
        }

        if (!extract_lsp_addresses(isb_pb->address, &ts_port_addrs)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(&rl, "Route sync ignores port %s on ts %s for router"
                         " %s because the addresses are invalid.",
                         isb_pb->logical_port, isb_pb->transit_switch,
                         ic_lr->lr->name);
            continue;
        }
        lrp_name = get_lrp_name_by_ts_port_name(ctx, isb_pb->logical_port);
        lrp = get_lrp_by_lrp_name(ctx, lrp_name);
        if (lrp) {
            route_table = smap_get_def(&lrp->options, "route_table", "");
            route_tag = smap_get_def(&lrp->options, "ic-route-tag", "");
        } else {
            route_table = "";
            route_tag = "";
        }
        build_ts_routes_to_adv(ctx, ic_lr, routes_ad, &ts_port_addrs,
                               nb_global, route_table, route_tag, lrp);
        destroy_lport_addresses(&ts_port_addrs);
    }
}

static void
delete_orphan_ic_routes(struct ic_context *ctx,
                         const struct icsbrec_availability_zone *az)
{
    const struct icsbrec_route *isb_route, *isb_route_key =
        icsbrec_route_index_init_row(ctx->icsbrec_route_by_az);
    icsbrec_route_index_set_availability_zone(isb_route_key, az);

    const struct icnbrec_transit_switch *t_sw, *t_sw_key;

    ICSBREC_ROUTE_FOR_EACH_EQUAL (isb_route, isb_route_key,
                                  ctx->icsbrec_route_by_az)
    {
        t_sw_key = icnbrec_transit_switch_index_init_row(
            ctx->icnbrec_transit_switch_by_name);
        icnbrec_transit_switch_index_set_name(t_sw_key,
            isb_route->transit_switch);
        t_sw = icnbrec_transit_switch_index_find(
            ctx->icnbrec_transit_switch_by_name, t_sw_key);
        icnbrec_transit_switch_index_destroy_row(t_sw_key);

        if (!t_sw || !find_lrp_of_nexthop(ctx, isb_route)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(&rl, "Deleting orphan ICDB:Route: %s->%s (%s, rtb:%s,"
                         " transit switch: %s)", isb_route->ip_prefix,
                         isb_route->nexthop, isb_route->origin,
                         isb_route->route_table, isb_route->transit_switch);
            icsbrec_route_delete(isb_route);
        }
    }
    icsbrec_route_index_destroy_row(isb_route_key);
}

static void
route_run(struct ic_context *ctx)
{
    if (!ctx->ovnisb_txn || !ctx->ovnnb_txn || !ctx->ovnsb_txn) {
        return;
    }

    delete_orphan_ic_routes(ctx, ctx->runned_az);

    struct hmap ic_lrs = HMAP_INITIALIZER(&ic_lrs);
    const struct icsbrec_port_binding *isb_pb;
    const struct icsbrec_port_binding *isb_pb_key =
        icsbrec_port_binding_index_init_row(ctx->icsbrec_port_binding_by_az);
    icsbrec_port_binding_index_set_availability_zone(isb_pb_key,
        ctx->runned_az);

    /* Each port on TS maps to a logical router, which is stored in the
     * external_ids:router-id of the IC SB port_binding record.
     * Here we build info for interconnected Logical Router:
     * collect IC Port Binding to process routes sync later on. */
    ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
                                         ctx->icsbrec_port_binding_by_az)
    {
        if (ic_pb_get_type(isb_pb) == IC_ROUTER_PORT) {
            continue;
        }
        const struct nbrec_logical_switch_port *nb_lsp;

        nb_lsp = get_lsp_by_ts_port_name(ctx, isb_pb->logical_port);
        if (!strcmp(nb_lsp->type, "switch")) {
            VLOG_DBG("IC-SB Port_Binding '%s' on ts '%s' corresponds to a "
                     "switch port, not considering for route collection.",
                     isb_pb->logical_port, isb_pb->transit_switch);
            continue;
        }

        const char *ts_lrp_name =
            get_lrp_name_by_ts_port_name(ctx, isb_pb->logical_port);
        if (!ts_lrp_name) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Route sync ignores port %s on ts %s because "
                         "logical router port is not found in NB. Deleting it",
                         isb_pb->logical_port, isb_pb->transit_switch);
            icsbrec_port_binding_delete(isb_pb);
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

        struct ic_router_info *ic_lr = ic_router_find(&ic_lrs, lr);
        if (!ic_lr) {
            ic_lr = xzalloc(sizeof *ic_lr);
            ic_lr->lr = lr;
            ic_lr->isb_pbs =
                VECTOR_EMPTY_INITIALIZER(const struct icsbrec_port_binding *);
            hmap_init(&ic_lr->routes_learned);
            hmap_insert(&ic_lrs, &ic_lr->node, uuid_hash(&lr->header_.uuid));
        }
        vector_push(&ic_lr->isb_pbs, &isb_pb);
    }
    icsbrec_port_binding_index_destroy_row(isb_pb_key);

    struct ic_router_info *ic_lr;
    struct shash routes_ad_by_ts = SHASH_INITIALIZER(&routes_ad_by_ts);
    HMAP_FOR_EACH_SAFE (ic_lr, node, &ic_lrs) {
        collect_lr_routes(ctx, ic_lr, &routes_ad_by_ts);
        sync_learned_routes(ctx, ic_lr);
        vector_destroy(&ic_lr->isb_pbs);
        hmap_destroy(&ic_lr->routes_learned);
        hmap_remove(&ic_lrs, &ic_lr->node);
        free(ic_lr);
    }
    struct shash_node *node;
    SHASH_FOR_EACH (node, &routes_ad_by_ts) {
        advertise_routes(ctx, ctx->runned_az, node->name, node->data);
        hmap_destroy(node->data);
    }
    shash_destroy_free_data(&routes_ad_by_ts);
    hmap_destroy(&ic_lrs);
}

/*
 * Data structures and functions related to
 * synchronize health checks for load balancers
 * between availability zones.
 */
struct sync_service_monitor_data {
    /* Map of service monitors to be pushed to other AZs. */
    struct hmap pushed_svcs_map;
    /* Map of service monitors synced from other AZs to our. */
    struct hmap synced_svcs_map;
    /* Map of local service monitors in the ICSBDB. */
    struct hmap local_ic_svcs_map;
    /* Map of local service monitors in SBDB. */
    struct hmap local_sb_svcs_map;
    /* MAC address used for service monitor.  */
    char *prpg_svc_monitor_mac;
};

struct service_monitor_info {
    struct hmap_node hmap_node;
    union {
        const struct sbrec_service_monitor *sb_rec;
        const struct icsbrec_service_monitor *ic_rec;
    } db_rec;
    /* Destination availability zone name. */
    char *dst_az_name;
    /* Source availability zone name. */
    char *src_az_name;
    /* Chassis name associated with monitor logical port. */
    char *chassis_name;
};

static void
create_service_monitor_info(struct hmap *svc_map,
                            const void *db_rec,
                            const struct uuid *uuid,
                            const char *src_az_name,
                            const char *target_az_name,
                            const char *chassis_name,
                            bool ic_rec)
{
    struct service_monitor_info *svc_mon = xzalloc(sizeof(*svc_mon));
    size_t hash = uuid_hash(uuid);

    if (ic_rec) {
        svc_mon->db_rec.ic_rec =
            (const struct icsbrec_service_monitor *) db_rec;
    } else {
        svc_mon->db_rec.sb_rec =
            (const struct sbrec_service_monitor *) db_rec;
    }

    svc_mon->dst_az_name = target_az_name ? xstrdup(target_az_name) : NULL;
    svc_mon->chassis_name = chassis_name ? xstrdup(chassis_name) : NULL;
    svc_mon->src_az_name = xstrdup(src_az_name);

    hmap_insert(svc_map, &svc_mon->hmap_node, hash);
}

static void
destroy_service_monitor_info(struct service_monitor_info *svc_mon)
{
    free(svc_mon->src_az_name);
    free(svc_mon->dst_az_name);
    free(svc_mon->chassis_name);
    free(svc_mon);
}

static void
refresh_sb_record_cache(struct hmap *svc_mon_map,
                        const struct sbrec_service_monitor *lookup_rec)
{
    size_t hash = uuid_hash(&lookup_rec->header_.uuid);
    struct service_monitor_info *svc_mon;

    HMAP_FOR_EACH_WITH_HASH (svc_mon, hmap_node, hash, svc_mon_map) {
        ovs_assert(svc_mon->db_rec.sb_rec);
        if (svc_mon->db_rec.sb_rec == lookup_rec) {
            hmap_remove(svc_mon_map, &svc_mon->hmap_node);
            destroy_service_monitor_info(svc_mon);
            return;
        }
    }
}

static void
refresh_ic_record_cache(struct hmap *svc_mon_map,
                        const struct icsbrec_service_monitor *lookup_rec)
{
    size_t hash = uuid_hash(&lookup_rec->header_.uuid);
    struct service_monitor_info *svc_mon;

    HMAP_FOR_EACH_WITH_HASH (svc_mon, hmap_node, hash, svc_mon_map) {
        ovs_assert(svc_mon->db_rec.ic_rec);
        if (svc_mon->db_rec.ic_rec == lookup_rec) {
            hmap_remove(svc_mon_map, &svc_mon->hmap_node);
            destroy_service_monitor_info(svc_mon);
            return;
        }
    }
}

static void
remove_unused_ic_records(struct hmap *local_ic_svcs_map)
{
    struct service_monitor_info *svc_mon;
    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, local_ic_svcs_map) {
        icsbrec_service_monitor_delete(svc_mon->db_rec.ic_rec);
        destroy_service_monitor_info(svc_mon);
    }

    hmap_destroy(local_ic_svcs_map);
}

static void
remove_unused_sb_records(struct hmap *local_sb_svcs_map)
{
    struct service_monitor_info *svc_mon;
    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, local_sb_svcs_map) {
        sbrec_service_monitor_delete(svc_mon->db_rec.sb_rec);
        destroy_service_monitor_info(svc_mon);
    }

    hmap_destroy(local_sb_svcs_map);
}

static void
create_pushed_svcs_mon(struct ic_context *ctx,
                       struct hmap *pushed_svcs_map)
{
    struct sbrec_service_monitor *key =
        sbrec_service_monitor_index_init_row(
            ctx->sbrec_service_monitor_by_remote_type);

    sbrec_service_monitor_index_set_remote(key, true);

    const struct sbrec_service_monitor *sb_rec;
    SBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (sb_rec, key,
        ctx->sbrec_service_monitor_by_remote_type) {
        const char *target_az_name = smap_get(&sb_rec->options,
                                              "az-name");
        if (!target_az_name) {
            continue;
        }
        create_service_monitor_info(pushed_svcs_map, sb_rec,
                                    &sb_rec->header_.uuid,
                                    ctx->runned_az->name, target_az_name,
                                    NULL, false);
    }

    sbrec_service_monitor_index_destroy_row(key);
}

static void
create_synced_svcs_mon(struct ic_context *ctx,
                       struct hmap *synced_svcs_map)
{
    struct icsbrec_service_monitor *key =
        icsbrec_service_monitor_index_init_row(
          ctx->icsbrec_service_monitor_by_target_az);

    icsbrec_service_monitor_index_set_target_availability_zone(
        key, ctx->runned_az->name);

    const struct icsbrec_service_monitor *ic_rec;
    ICSBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (ic_rec, key,
        ctx->icsbrec_service_monitor_by_target_az) {

        const struct sbrec_port_binding *pb =
            find_sb_pb_by_name(ctx->sbrec_port_binding_by_name,
                               ic_rec->logical_port);

        if (!pb || !pb->up) {
            continue;
        }

        const char *chassis_name = pb->chassis ? pb->chassis->name : NULL;
        create_service_monitor_info(synced_svcs_map, ic_rec,
                                    &ic_rec->header_.uuid,
                                    ctx->runned_az->name,
                                    NULL, chassis_name, true);
    }

    icsbrec_service_monitor_index_destroy_row(key);
}

static void
create_local_ic_svcs_map(struct ic_context *ctx,
                         struct hmap *owned_svc_map)
{
    struct icsbrec_service_monitor *key =
        icsbrec_service_monitor_index_init_row(
          ctx->icsbrec_service_monitor_by_source_az);

    icsbrec_service_monitor_index_set_source_availability_zone(
        key, ctx->runned_az->name);

    const struct icsbrec_service_monitor *ic_rec;
    ICSBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (ic_rec, key,
        ctx->icsbrec_service_monitor_by_source_az) {
        create_service_monitor_info(owned_svc_map, ic_rec,
                                    &ic_rec->header_.uuid,
                                    ctx->runned_az->name, NULL,
                                    NULL, true);
    }

    icsbrec_service_monitor_index_destroy_row(key);
}

static void
create_local_sb_svcs_map(struct ic_context *ctx,
                         struct hmap *owned_svc_map)
{
    struct sbrec_service_monitor *key =
        sbrec_service_monitor_index_init_row(
          ctx->sbrec_service_monitor_by_ic_learned);

    sbrec_service_monitor_index_set_ic_learned(
        key, true);

    const struct sbrec_service_monitor *sb_rec;
    SBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (sb_rec, key,
        ctx->sbrec_service_monitor_by_ic_learned) {
        create_service_monitor_info(owned_svc_map, sb_rec,
                                    &sb_rec->header_.uuid,
                                    ctx->runned_az->name, NULL,
                                    NULL, false);
    }

    sbrec_service_monitor_index_destroy_row(key);
}

static const struct sbrec_service_monitor *
lookup_sb_svc_rec(struct ic_context *ctx,
                  const struct service_monitor_info *svc_mon)
{
    const struct icsbrec_service_monitor *db_rec =
        svc_mon->db_rec.ic_rec;
    struct sbrec_service_monitor *key =
        sbrec_service_monitor_index_init_row(
            ctx->sbrec_service_monitor_by_remote_type_logical_port);

    sbrec_service_monitor_index_set_remote(key, false);
    sbrec_service_monitor_index_set_logical_port(key, db_rec->logical_port);

    const struct sbrec_service_monitor *sb_rec;
    SBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (sb_rec, key,
        ctx->sbrec_service_monitor_by_remote_type_logical_port) {
        if (db_rec->port == sb_rec->port &&
            ((db_rec->type && sb_rec->type &&
              !strcmp(db_rec->type, sb_rec->type)) ||
             (!db_rec->type && !sb_rec->type)) &&
            !strcmp(db_rec->ip, sb_rec->ip) &&
            !strcmp(db_rec->src_ip, sb_rec->src_ip) &&
            !strcmp(db_rec->protocol, sb_rec->protocol)) {
            sbrec_service_monitor_index_destroy_row(key);
            return sb_rec;
        }
    }

    sbrec_service_monitor_index_destroy_row(key);

    return NULL;
}

static const struct icsbrec_service_monitor *
lookup_icsb_svc_rec(struct ic_context *ctx,
                    const struct service_monitor_info *svc_mon)
{
    const struct sbrec_service_monitor *db_rec =
       svc_mon->db_rec.sb_rec;
    struct icsbrec_service_monitor *key =
        icsbrec_service_monitor_index_init_row(
        ctx->icsbrec_service_monitor_by_target_az_logical_port);

    ovs_assert(svc_mon->dst_az_name);
    icsbrec_service_monitor_index_set_target_availability_zone(
        key, svc_mon->dst_az_name);

    icsbrec_service_monitor_index_set_logical_port(
        key, db_rec->logical_port);

    const struct icsbrec_service_monitor *ic_rec;
    ICSBREC_SERVICE_MONITOR_FOR_EACH_EQUAL (ic_rec, key,
        ctx->icsbrec_service_monitor_by_target_az_logical_port) {
        if (db_rec->port == ic_rec->port &&
            ((db_rec->type && ic_rec->type &&
              !strcmp(db_rec->type, ic_rec->type)) ||
             (!db_rec->type && !ic_rec->type)) &&
            !strcmp(db_rec->ip, ic_rec->ip) &&
            !strcmp(db_rec->src_ip, ic_rec->src_ip) &&
            !strcmp(db_rec->protocol, ic_rec->protocol) &&
            !strcmp(db_rec->logical_port, ic_rec->logical_port)) {
            icsbrec_service_monitor_index_destroy_row(key);
            return ic_rec;
        }
    }

    icsbrec_service_monitor_index_destroy_row(key);

    return NULL;
}

static void
create_service_monitor_data(struct ic_context *ctx,
                            struct sync_service_monitor_data *sync_data)
{
    const struct sbrec_sb_global *ic_sb = sbrec_sb_global_first(
                                                ctx->ovnsb_idl);
    const char *svc_monitor_mac = smap_get(&ic_sb->options,
                                           "svc_monitor_mac");

    if (!svc_monitor_mac) {
        return;
    }

    sync_data->prpg_svc_monitor_mac = xstrdup(svc_monitor_mac);
    create_pushed_svcs_mon(ctx, &sync_data->pushed_svcs_map);
    create_synced_svcs_mon(ctx, &sync_data->synced_svcs_map);
    create_local_ic_svcs_map(ctx, &sync_data->local_ic_svcs_map);
    create_local_sb_svcs_map(ctx, &sync_data->local_sb_svcs_map);
}

static void
destroy_service_monitor_data(struct sync_service_monitor_data *sync_data)
{
    struct service_monitor_info *svc_mon;
    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &sync_data->pushed_svcs_map) {
        destroy_service_monitor_info(svc_mon);
    }

    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &sync_data->synced_svcs_map) {
        destroy_service_monitor_info(svc_mon);
    }

    hmap_destroy(&sync_data->pushed_svcs_map);
    hmap_destroy(&sync_data->synced_svcs_map);
    free(sync_data->prpg_svc_monitor_mac);
}

static void
sync_service_monitor(struct ic_context *ctx)
{
    if (!ctx->ovnisb_txn || !ctx->ovnsb_txn) {
        return;
    }

    struct sync_service_monitor_data sync_data;
    memset(&sync_data, 0, sizeof(sync_data));
    hmap_init(&sync_data.pushed_svcs_map);
    hmap_init(&sync_data.synced_svcs_map);
    hmap_init(&sync_data.local_ic_svcs_map);
    hmap_init(&sync_data.local_sb_svcs_map);

    create_service_monitor_data(ctx, &sync_data);

    struct service_monitor_info *svc_mon;
    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &sync_data.pushed_svcs_map) {
        const struct sbrec_service_monitor *db_rec = svc_mon->db_rec.sb_rec;
        const struct icsbrec_service_monitor *ic_rec =
            lookup_icsb_svc_rec(ctx, svc_mon);

        if (ic_rec) {
            sbrec_service_monitor_set_status(db_rec, ic_rec->status);
        } else {
            ic_rec = icsbrec_service_monitor_insert(ctx->ovnisb_txn);
            icsbrec_service_monitor_set_type(ic_rec, db_rec->type);
            icsbrec_service_monitor_set_ip(ic_rec, db_rec->ip);
            icsbrec_service_monitor_set_port(ic_rec, db_rec->port);
            icsbrec_service_monitor_set_src_ip(ic_rec, db_rec->src_ip);
            icsbrec_service_monitor_set_src_mac(ic_rec,
                sync_data.prpg_svc_monitor_mac);
            icsbrec_service_monitor_set_protocol(ic_rec, db_rec->protocol);
            icsbrec_service_monitor_set_logical_port(ic_rec,
                db_rec->logical_port);
            icsbrec_service_monitor_set_target_availability_zone(ic_rec,
                svc_mon->dst_az_name);
            icsbrec_service_monitor_set_source_availability_zone(ic_rec,
                svc_mon->src_az_name);
        }

        /* Always update options because they change from NB. */
        icsbrec_service_monitor_set_options(ic_rec, &db_rec->options);
        refresh_ic_record_cache(&sync_data.local_ic_svcs_map, ic_rec);
    }

    HMAP_FOR_EACH_SAFE (svc_mon, hmap_node, &sync_data.synced_svcs_map) {
        const struct icsbrec_service_monitor *db_rec =
            svc_mon->db_rec.ic_rec;
        const struct sbrec_service_monitor *sb_rec =
            lookup_sb_svc_rec(ctx, svc_mon);

        if (sb_rec) {
            icsbrec_service_monitor_set_status(svc_mon->db_rec.ic_rec,
                                               sb_rec->status);
        } else {
            sb_rec = sbrec_service_monitor_insert(ctx->ovnsb_txn);
            sbrec_service_monitor_set_type(sb_rec, db_rec->type);
            sbrec_service_monitor_set_ip(sb_rec, db_rec->ip);
            sbrec_service_monitor_set_port(sb_rec, db_rec->port);
            sbrec_service_monitor_set_src_ip(sb_rec, db_rec->src_ip);
            /* Set svc_monitor_mac from local SBDB. */
            sbrec_service_monitor_set_src_mac(sb_rec,
                sync_data.prpg_svc_monitor_mac);
            sbrec_service_monitor_set_protocol(sb_rec,
                db_rec->protocol);
            sbrec_service_monitor_set_logical_port(sb_rec,
                db_rec->logical_port);
            sbrec_service_monitor_set_remote(sb_rec, false);
            sbrec_service_monitor_set_ic_learned(sb_rec, true);
        }

        /* Always update options since they may change via
         * NB configuration. Also update chassis_name if
         * the port has been reassigned to a different chassis.
         */
        if (svc_mon->chassis_name) {
            sbrec_service_monitor_set_chassis_name(sb_rec,
                svc_mon->chassis_name);
        }
        sbrec_service_monitor_set_options(sb_rec, &db_rec->options);
        refresh_sb_record_cache(&sync_data.local_sb_svcs_map, sb_rec);
    }

    /* Delete local created records that are no longer used. */
    remove_unused_ic_records(&sync_data.local_ic_svcs_map);
    remove_unused_sb_records(&sync_data.local_sb_svcs_map);

    destroy_service_monitor_data(&sync_data);
}

/*
 * This function implements a sequence number protocol that can be used by
 * the INB end user to verify that ISB is synced with all the changes that
 * are done be the user/AZs-controllers:
 *
 * Since we have multiple IC instances running in different regions
 * we can't rely on one of them to update the ISB and sync that update
 * to INB since other ICs can make changes in parallel.
 * So to have a sequence number protocol working properly we must
 * make sure that all the IC instances are synced with the ISB first
 * and then update the INB.
 *
 * To guarantee that all instances are synced with ISB first, each IC
 * will do the following steps:
 *
 * 1. when local ovn-ic sees that INB:nb_ic_cfg has updated we will set
 *    the ic_sb_loop->next_cfg to match the INB:nb_ic_cfg and increment
 *    the value of AZ:nb_ic_cfg and wait until we get confirmation from
 *    the server.
 *
 * 2. once this IC instance changes for ISB are committed successfully
 *    (next loop), the value of cur_cfg will be updated to match
 *    the INB:nb_ic_cfg that indicate that our local instance is up to date
 *    and no more changes need to be done for ISB.
 *
 * 3. validate that the AZ:nb_ic_cfg to match the INB:nb_ic_cfg.
 *
 * 4. Go through all the AZs and check if all have the same value of
 *    AZ:nb_ic_cfg that means all the AZs are done with ISB changes and ISB are
 *    up to date with INB, so we can set the values of ISB:nb_ic_cfg to
 *    INB:nb_ic_cfg and INB:sb_ic_cfg to INB:nb_ic_cfg.
 */
static void
update_sequence_numbers(struct ic_context *ctx,
                        struct ovsdb_idl_loop *ic_sb_loop)
{
    if (!ctx->ovnisb_txn || !ctx->ovninb_txn) {
        return;
    }

    const struct icnbrec_ic_nb_global *ic_nb = icnbrec_ic_nb_global_first(
                                               ctx->ovninb_idl);
    if (!ic_nb) {
        ic_nb = icnbrec_ic_nb_global_insert(ctx->ovninb_txn);
    }
    const struct icsbrec_ic_sb_global *ic_sb = icsbrec_ic_sb_global_first(
                                               ctx->ovnisb_idl);
    if (!ic_sb) {
        ic_sb = icsbrec_ic_sb_global_insert(ctx->ovnisb_txn);
    }

    if ((ic_nb->nb_ic_cfg != ic_sb->nb_ic_cfg) &&
                          (ic_nb->nb_ic_cfg != ctx->runned_az->nb_ic_cfg)) {
        /* Deal with potential overflows. */
        if (ctx->runned_az->nb_ic_cfg == INT64_MAX) {
            icsbrec_availability_zone_set_nb_ic_cfg(ctx->runned_az, 0);
        }
        ic_sb_loop->next_cfg = ic_nb->nb_ic_cfg;
        ovsdb_idl_txn_increment(ctx->ovnisb_txn, &ctx->runned_az->header_,
            &icsbrec_availability_zone_col_nb_ic_cfg, true);
        return;
    }

    /* handle cases where accidentally AZ:ic_nb_cfg exceeds
     * the INB:ic_nb_cfg.
     */
    if (ctx->runned_az->nb_ic_cfg != ic_sb_loop->cur_cfg) {
        icsbrec_availability_zone_set_nb_ic_cfg(ctx->runned_az,
                                                ic_sb_loop->cur_cfg);
        return;
    }

    const struct icsbrec_availability_zone *other_az;
    ICSBREC_AVAILABILITY_ZONE_FOR_EACH (other_az, ctx->ovnisb_idl) {
        if (other_az->nb_ic_cfg != ctx->runned_az->nb_ic_cfg) {
            return;
        }
    }
    /* All the AZs are updated successfully, update SB/NB counter. */
    if (ic_nb->nb_ic_cfg != ic_sb->nb_ic_cfg) {
        icsbrec_ic_sb_global_set_nb_ic_cfg(ic_sb, ctx->runned_az->nb_ic_cfg);
        icnbrec_ic_nb_global_set_sb_ic_cfg(ic_nb, ctx->runned_az->nb_ic_cfg);
    }
}

static void
inc_proc_graph_dump(const char *end_node)
{
    struct ovsdb_idl_loop ovnnb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&nbrec_idl_class, true));
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&sbrec_idl_class, true));
    struct ovsdb_idl_loop ovninb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&icnbrec_idl_class, true));
    struct ovsdb_idl_loop ovnisb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&icsbrec_idl_class, true));

    inc_proc_ic_init(&ovnnb_idl_loop, &ovnsb_idl_loop,
                     &ovninb_idl_loop, &ovnisb_idl_loop);
    engine_dump_graph(end_node);

    ovsdb_idl_loop_destroy(&ovnnb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);
    ovsdb_idl_loop_destroy(&ovninb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnisb_idl_loop);
}

void
ovn_db_run(struct ic_context *ctx)
{
    struct hmap dp_tnlids = HMAP_INITIALIZER(&dp_tnlids);
    struct shash isb_ts_dps = SHASH_INITIALIZER(&isb_ts_dps);
    struct shash isb_tr_dps = SHASH_INITIALIZER(&isb_tr_dps);

    gateway_run(ctx);
    enumerate_datapaths(ctx, &dp_tnlids, &isb_ts_dps, &isb_tr_dps);
    ts_run(ctx, &dp_tnlids, &isb_ts_dps);
    tr_run(ctx, &dp_tnlids, &isb_tr_dps);
    port_binding_run(ctx);
    route_run(ctx);
    sync_service_monitor(ctx);

    ovn_destroy_tnlids(&dp_tnlids);
    shash_destroy(&isb_ts_dps);
    shash_destroy(&isb_tr_dps);
}

static void
parse_options(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum {
        OVN_DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
        OPT_DUMP_INC_PROC_GRAPH,
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
        {"dump-inc-proc-graph", optional_argument, NULL,
         OPT_DUMP_INC_PROC_GRAPH},
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

        case OPT_SSL_PROTOCOLS:
            stream_ssl_set_protocols(optarg);
            break;

        case OPT_SSL_CIPHERS:
            stream_ssl_set_ciphers(optarg);
            break;

        case OPT_SSL_CIPHERSUITES:
            stream_ssl_set_ciphersuites(optarg);
            break;

        case OPT_SSL_SERVER_NAME:
            stream_ssl_set_server_name(optarg);
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

        /* --dump-inc-proc-graph[=<i-p-node>]: Whether to dump the I-P engine
         * graph representation in DOT format to stdout.  Optionally only up
         * to <i-p-node>.
         */
        case OPT_DUMP_INC_PROC_GRAPH:
            inc_proc_graph_dump(optarg);
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

static void
update_idl_probe_interval(struct ovsdb_idl *ovn_sb_idl,
                          struct ovsdb_idl *ovn_nb_idl,
                          struct ovsdb_idl *ovn_icsb_idl,
                          struct ovsdb_idl *ovn_icnb_idl)
{
    const struct nbrec_nb_global *nb = nbrec_nb_global_first(ovn_nb_idl);
    int interval = -1;
    if (nb) {
        interval = smap_get_int(&nb->options, "ic_probe_interval", interval);
    }
    set_idl_probe_interval(ovn_sb_idl, ovnsb_db, interval);
    set_idl_probe_interval(ovn_nb_idl, ovnnb_db, interval);

    const struct icnbrec_ic_nb_global *icnb =
        icnbrec_ic_nb_global_first(ovn_icnb_idl);
    int ic_interval = -1;
    if (icnb) {
        ic_interval = smap_get_int(&icnb->options, "ic_probe_interval",
                                   ic_interval);
    }
    set_idl_probe_interval(ovn_icsb_idl, ovn_ic_sb_db, ic_interval);
    set_idl_probe_interval(ovn_icnb_idl, ovn_ic_nb_db, ic_interval);
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

    daemonize_start(false, false);

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
    ovsdb_idl_track_add_all(ovninb_idl_loop.idl);

    /* ovn-ic-sb db. */
    struct ovsdb_idl_loop ovnisb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovn_ic_sb_db, &icsbrec_idl_class, true, true));
    ovsdb_idl_track_add_all(ovnisb_idl_loop.idl);

    /* ovn-nb db. */
    struct ovsdb_idl_loop ovnnb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnnb_db, &nbrec_idl_class, false, true));

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_nb_global);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_nb_global_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_nb_global_col_options);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl,
                        &nbrec_table_logical_router_static_route);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_route_table);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_ip_prefix);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_nexthop);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_external_ids);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_options);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_policy);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_logical_router);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_static_routes);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_ports);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_options);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_external_ids);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_enabled);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_load_balancer);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_load_balancer_group);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_logical_router_port);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_mac);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_networks);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_external_ids);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_options);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_logical_switch);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_col_ports);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_col_other_config);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_col_external_ids);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_logical_switch_port);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_addresses);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_options);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_type);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_up);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_addresses);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_enabled);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_external_ids);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_load_balancer);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_load_balancer_col_vips);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_load_balancer_group);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_load_balancer_group_col_load_balancer);

    /* ovn-sb db. */
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnsb_db, &sbrec_idl_class, false, true));

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_sb_global);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_sb_global_col_options);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_chassis);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_chassis_col_encaps);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_chassis_col_name);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_chassis_col_hostname);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_chassis_col_other_config);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_encap);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_encap_col_chassis_name);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_encap_col_type);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_encap_col_ip);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_encap_col_options);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_datapath_binding);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_datapath_binding_col_type);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_datapath_binding_col_external_ids);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_datapath_binding_col_nb_uuid);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_port_binding);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_datapath);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_mac);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_options);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_logical_port);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_external_ids);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_chassis);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_up);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_service_monitor);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_chassis_name);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_external_ids);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_type);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_ip);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_logical_port);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_port);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_protocol);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_src_ip);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_src_mac);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_remote);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_ic_learned);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_status);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_options);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_learned_route);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_learned_route_col_ip_prefix);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_learned_route_col_datapath);
    /* Create IDL indexes */
    struct ovsdb_idl_index *nbrec_ls_by_name
        = ovsdb_idl_index_create1(ovnnb_idl_loop.idl,
                                  &nbrec_logical_switch_col_name);
    struct ovsdb_idl_index *nbrec_lr_by_name = ovsdb_idl_index_create1(
        ovnnb_idl_loop.idl, &nbrec_logical_router_col_name);
    struct ovsdb_idl_index *nbrec_port_by_name
        = ovsdb_idl_index_create1(ovnnb_idl_loop.idl,
                                  &nbrec_logical_switch_port_col_name);
    struct ovsdb_idl_index *nbrec_lrp_by_name
        = ovsdb_idl_index_create1(ovnnb_idl_loop.idl,
                                  &nbrec_logical_router_port_col_name);
    struct ovsdb_idl_index *sbrec_port_binding_by_name
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_port_binding_col_logical_port);
    struct ovsdb_idl_index *sbrec_datapath_binding_by_nb_uuid
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_datapath_binding_col_nb_uuid);
    struct ovsdb_idl_index *sbrec_chassis_by_name
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_chassis_col_name);

    struct ovsdb_idl_index *sbrec_learned_route_by_datapath
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_learned_route_col_datapath);

    struct ovsdb_idl_index *sbrec_service_monitor_by_remote_type
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_service_monitor_col_remote);

    struct ovsdb_idl_index *sbrec_service_monitor_by_ic_learned
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_service_monitor_col_ic_learned);

    struct ovsdb_idl_index *sbrec_service_monitor_by_remote_type_logical_port
        = ovsdb_idl_index_create2(ovnsb_idl_loop.idl,
                                  &sbrec_service_monitor_col_remote,
                                  &sbrec_service_monitor_col_logical_port);

    struct ovsdb_idl_index *icnbrec_transit_switch_by_name
        = ovsdb_idl_index_create1(ovninb_idl_loop.idl,
                                  &icnbrec_transit_switch_col_name);

    struct ovsdb_idl_index *icsbrec_port_binding_by_az
        = ovsdb_idl_index_create1(ovnisb_idl_loop.idl,
                                  &icsbrec_port_binding_col_availability_zone);

    struct ovsdb_idl_index *icsbrec_port_binding_by_ts
        = ovsdb_idl_index_create1(ovnisb_idl_loop.idl,
                                  &icsbrec_port_binding_col_transit_switch);

    struct ovsdb_idl_index *icsbrec_port_binding_by_ts_az
        = ovsdb_idl_index_create2(ovnisb_idl_loop.idl,
                                  &icsbrec_port_binding_col_transit_switch,
                                  &icsbrec_port_binding_col_availability_zone);

    struct ovsdb_idl_index *icsbrec_route_by_az
        = ovsdb_idl_index_create1(ovnisb_idl_loop.idl,
                                  &icsbrec_route_col_availability_zone);

    struct ovsdb_idl_index *icsbrec_route_by_ts
        = ovsdb_idl_index_create1(ovnisb_idl_loop.idl,
                                  &icsbrec_route_col_transit_switch);

    struct ovsdb_idl_index *icsbrec_route_by_ts_az
        = ovsdb_idl_index_create2(ovnisb_idl_loop.idl,
                                  &icsbrec_route_col_transit_switch,
                                  &icsbrec_route_col_availability_zone);

    struct ovsdb_idl_index *icsbrec_service_monitor_by_source_az
        = ovsdb_idl_index_create1(ovnisb_idl_loop.idl,
            &icsbrec_service_monitor_col_source_availability_zone);

    struct ovsdb_idl_index *icsbrec_service_monitor_by_target_az
        = ovsdb_idl_index_create1(ovnisb_idl_loop.idl,
            &icsbrec_service_monitor_col_target_availability_zone);

    struct ovsdb_idl_index *icsbrec_service_monitor_by_target_az_logical_port
        = ovsdb_idl_index_create2(ovnisb_idl_loop.idl,
            &icsbrec_service_monitor_col_target_availability_zone,
            &icsbrec_service_monitor_col_logical_port);

    unixctl_command_register("nb-connection-status", "", 0, 0,
                             ovn_conn_show, ovnnb_idl_loop.idl);
    unixctl_command_register("sb-connection-status", "", 0, 0,
                             ovn_conn_show, ovnsb_idl_loop.idl);
    unixctl_command_register("ic-nb-connection-status", "", 0, 0,
                             ovn_conn_show, ovninb_idl_loop.idl);
    unixctl_command_register("ic-sb-connection-status", "", 0, 0,
                             ovn_conn_show, ovnisb_idl_loop.idl);

    /* Initialize incremental processing engine for ovn-northd */
    inc_proc_ic_init(&ovnnb_idl_loop, &ovnsb_idl_loop,
                     &ovninb_idl_loop, &ovnisb_idl_loop);

    unsigned int ovnnb_cond_seqno = UINT_MAX;
    unsigned int ovnsb_cond_seqno = UINT_MAX;
    unsigned int ovninb_cond_seqno = UINT_MAX;
    unsigned int ovnisb_cond_seqno = UINT_MAX;

    /* Main loop. */
    struct ic_engine_context  eng_ctx = {0};

    exiting = false;
    state.had_lock = false;
    state.paused = false;

    while (!exiting) {
        update_ssl_config();
        update_idl_probe_interval(ovnsb_idl_loop.idl, ovnnb_idl_loop.idl,
                                  ovnisb_idl_loop.idl, ovninb_idl_loop.idl);
        memory_run();
        if (memory_should_report()) {
            struct simap usage = SIMAP_INITIALIZER(&usage);

            /* Nothing special to report yet. */
            memory_report(&usage);
            simap_destroy(&usage);
        }

        bool clear_idl_track = true;
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

            struct ovsdb_idl_txn *ovnnb_txn =
                run_idl_loop(&ovnnb_idl_loop, "OVN_Northbound",
                             &eng_ctx.nb_idl_duration_ms);
            unsigned int new_ovnnb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovnnb_idl_loop.idl);
            if (new_ovnnb_cond_seqno != ovnnb_cond_seqno) {
                if (!new_ovnnb_cond_seqno) {
                    VLOG_INFO("OVN NB IDL reconnected, force recompute.");
                    inc_proc_ic_force_recompute();
                }
                ovnnb_cond_seqno = new_ovnnb_cond_seqno;
            }

            struct ovsdb_idl_txn *ovnsb_txn =
                run_idl_loop(&ovnsb_idl_loop, "OVN_Southbound",
                             &eng_ctx.sb_idl_duration_ms);
            unsigned int new_ovnsb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovnsb_idl_loop.idl);
            if (new_ovnsb_cond_seqno != ovnsb_cond_seqno) {
                if (!new_ovnsb_cond_seqno) {
                    VLOG_INFO("OVN SB IDL reconnected, force recompute.");
                    inc_proc_ic_force_recompute();
                }
                ovnsb_cond_seqno = new_ovnsb_cond_seqno;
            }

            struct ovsdb_idl_txn *ovninb_txn =
                run_idl_loop(&ovninb_idl_loop, "OVN_IC_Northbound",
                             &eng_ctx.inb_idl_duration_ms);
            unsigned int new_ovninb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovninb_idl_loop.idl);
            if (new_ovninb_cond_seqno != ovninb_cond_seqno) {
                if (!new_ovninb_cond_seqno) {
                    VLOG_INFO("OVN INB IDL reconnected, force recompute.");
                    inc_proc_ic_force_recompute();
                }
                ovninb_cond_seqno = new_ovninb_cond_seqno;
            }

            struct ovsdb_idl_txn *ovnisb_txn =
                run_idl_loop(&ovnisb_idl_loop, "OVN_IC_Southbound",
                             &eng_ctx.isb_idl_duration_ms);
            unsigned int new_ovnisb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovnisb_idl_loop.idl);
            if (new_ovnisb_cond_seqno != ovnisb_cond_seqno) {
                if (!new_ovnisb_cond_seqno) {
                    VLOG_INFO("OVN ISB IDL reconnected, force recompute.");
                    inc_proc_ic_force_recompute();
                }
                ovnisb_cond_seqno = new_ovnisb_cond_seqno;
            }

            struct ic_context ctx = {
                .ovnnb_idl = ovnnb_idl_loop.idl,
                .ovnnb_txn = ovnnb_txn,
                .ovnsb_idl = ovnsb_idl_loop.idl,
                .ovnsb_txn = ovnsb_txn,
                .ovninb_idl = ovninb_idl_loop.idl,
                .ovninb_txn = ovninb_txn,
                .ovnisb_idl = ovnisb_idl_loop.idl,
                .ovnisb_txn = ovnisb_txn,
                .nbrec_ls_by_name = nbrec_ls_by_name,
                .nbrec_lr_by_name = nbrec_lr_by_name,
                .nbrec_lrp_by_name = nbrec_lrp_by_name,
                .nbrec_port_by_name = nbrec_port_by_name,
                .sbrec_port_binding_by_name = sbrec_port_binding_by_name,
                .sbrec_datapath_binding_by_nb_uuid =
                    sbrec_datapath_binding_by_nb_uuid,
                .sbrec_chassis_by_name = sbrec_chassis_by_name,
                .sbrec_learned_route_by_datapath =
                  sbrec_learned_route_by_datapath,
                .sbrec_service_monitor_by_remote_type =
                    sbrec_service_monitor_by_remote_type,
                .sbrec_service_monitor_by_ic_learned =
                    sbrec_service_monitor_by_ic_learned,
                .sbrec_service_monitor_by_remote_type_logical_port =
                    sbrec_service_monitor_by_remote_type_logical_port,
                .icnbrec_transit_switch_by_name =
                    icnbrec_transit_switch_by_name,
                .icsbrec_port_binding_by_az = icsbrec_port_binding_by_az,
                .icsbrec_port_binding_by_ts = icsbrec_port_binding_by_ts,
                .icsbrec_port_binding_by_ts_az = icsbrec_port_binding_by_ts_az,
                .icsbrec_route_by_az = icsbrec_route_by_az,
                .icsbrec_route_by_ts = icsbrec_route_by_ts,
                .icsbrec_route_by_ts_az = icsbrec_route_by_ts_az,
                .icsbrec_service_monitor_by_source_az =
                    icsbrec_service_monitor_by_source_az,
                .icsbrec_service_monitor_by_target_az =
                    icsbrec_service_monitor_by_target_az,
                .icsbrec_service_monitor_by_target_az_logical_port =
                    icsbrec_service_monitor_by_target_az_logical_port,
            };

            if (!state.had_lock && ovsdb_idl_has_lock(ctx.ovnsb_idl)) {
                VLOG_INFO("ovn-ic lock acquired. "
                            "This ovn-ic instance is now active.");
                state.had_lock = true;
            } else if (state.had_lock &&
                       !ovsdb_idl_has_lock(ctx.ovnsb_idl)) {
                VLOG_INFO("ovn-ic lock lost. "
                            "This ovn-ic instance is now on standby.");
                state.had_lock = false;
            }

            if (ovsdb_idl_has_lock(ctx.ovnsb_idl) &&
                ovsdb_idl_has_ever_connected(ctx.ovnnb_idl) &&
                ovsdb_idl_has_ever_connected(ctx.ovnsb_idl) &&
                ovsdb_idl_has_ever_connected(ctx.ovninb_idl) &&
                ovsdb_idl_has_ever_connected(ctx.ovnisb_idl)) {
                if (ctx.ovnnb_txn && ctx.ovnsb_txn && ctx.ovninb_txn &&
                    ctx.ovnisb_txn && inc_proc_ic_can_run(&eng_ctx)) {
                    ctx.runned_az = az_run(&ctx);
                    VLOG_DBG("Availability zone: %s", ctx.runned_az ?
                             ctx.runned_az->name : "not created yet.");
                    if (ctx.runned_az) {
                        (void) inc_proc_ic_run(&ctx, &eng_ctx);
                        update_sequence_numbers(&ctx, &ovnisb_idl_loop);
                    }
                } else if (!inc_proc_ic_get_force_recompute()) {
                    clear_idl_track = false;
                }
                /* If there are any errors, we force a full recompute in order
                 * to ensure we handle all changes. */
                if (!ovsdb_idl_loop_commit_and_wait(&ovnnb_idl_loop)) {
                    VLOG_INFO("OVNNB commit failed, "
                                "force recompute next time.");
                    inc_proc_ic_force_recompute_immediate();
                }

                if (!ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop)) {
                    VLOG_INFO("OVNSB commit failed, "
                                "force recompute next time.");
                    inc_proc_ic_force_recompute_immediate();
                }

                if (!ovsdb_idl_loop_commit_and_wait(&ovninb_idl_loop)) {
                    VLOG_INFO("OVNINB commit failed, "
                                "force recompute next time.");
                    inc_proc_ic_force_recompute_immediate();
                }

                if (!ovsdb_idl_loop_commit_and_wait(&ovnisb_idl_loop)) {
                    VLOG_INFO("OVNISB commit failed, "
                                "force recompute next time.");
                    inc_proc_ic_force_recompute_immediate();
                }
            } else {
                /* Make sure we send any pending requests, e.g., lock. */
                int rc1 = ovsdb_idl_loop_commit_and_wait(&ovnnb_idl_loop);
                int rc2 = ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);
                int rc3 = ovsdb_idl_loop_commit_and_wait(&ovninb_idl_loop);
                int rc4 = ovsdb_idl_loop_commit_and_wait(&ovnisb_idl_loop);
                if (!rc1 || !rc2 || !rc3 || !rc4) {
                    VLOG_DBG(" a transaction failed in: %s %s %s %s",
                            !rc1 ? "nb" : "", !rc2 ? "sb" : "",
                            !rc3 ? "ic_nb" : "", !rc4 ? "ic_sb" : "");
                    /* A transaction failed. Wake up immediately to give
                    * opportunity to send the proper transaction
                    */
                }
                /* Force a full recompute next time we become active. */
                inc_proc_ic_force_recompute();
            }
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

            /* Force a full recompute next time we become active. */
            inc_proc_ic_force_recompute_immediate();
        }

        if (clear_idl_track) {
            ovsdb_idl_track_clear(ovnnb_idl_loop.idl);
            ovsdb_idl_track_clear(ovnsb_idl_loop.idl);
            ovsdb_idl_track_clear(ovninb_idl_loop.idl);
            ovsdb_idl_track_clear(ovnisb_idl_loop.idl);
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
    inc_proc_ic_cleanup();

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
    poll_immediate_wake();
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
