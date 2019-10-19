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

static void
ovn_db_run(struct ic_context *ctx)
{
    const struct icsbrec_availability_zone *az = az_run(ctx);
    VLOG_DBG("Availability zone: %s", az ? az->name : "not created yet.");
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
