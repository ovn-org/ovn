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
#include "openvswitch/poll-loop.h"
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

        /* Create NB Logical_Switch for each TS */
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
        if (smap_get_bool(&chassis->external_ids, "is-interconn", false)) {
            gw = shash_find_and_delete(&local_gws, chassis->name);
            if (!gw) {
                gw = icsbrec_gateway_insert(ctx->ovnisb_txn);
                icsbrec_gateway_set_availability_zone(gw, az);
                icsbrec_gateway_set_name(gw, chassis->name);
                sync_sb_gw_to_isb(ctx, chassis, gw);
            } else if (is_gateway_data_changed(gw, chassis)) {
                sync_sb_gw_to_isb(ctx, chassis, gw);
            }
        } else if (smap_get_bool(&chassis->external_ids, "is-remote", false)) {
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
}

static void
parse_options(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum {
        DAEMON_OPTION_ENUMS,
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
        DAEMON_LONG_OPTIONS,
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
        DAEMON_OPTION_HANDLERS;
        VLOG_OPTION_HANDLERS;
        STREAM_SSL_OPTION_HANDLERS;

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
            ovs_print_version(0, 0);
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
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);

    daemonize_start(false);

    if (!unixctl_path) {
        char *abs_unixctl_path = get_abs_unix_ctl_path();
        retval = unixctl_server_create(abs_unixctl_path, &unixctl);
        free(abs_unixctl_path);
    } else {
        retval = unixctl_server_create(unixctl_path, &unixctl);
    }

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

    /* Main loop. */
    exiting = false;
    state.had_lock = false;
    state.paused = false;
    while (!exiting) {
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
