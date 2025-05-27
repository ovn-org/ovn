/* Copyright (c) 2025 Crusoe Energy Systems LLC
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

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

/* OVS includes. */
#include "lib/command-line.h"
#include "lib/daemon.h"
#include "lib/dirs.h"
#include "lib/fatal-signal.h"
#include "lib/stream.h"
#include "lib/stream-ssl.h"
#include "lib/vswitch-idl.h"
#include "lib/unixctl.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"


/* OVN includes. */
#include "en-bridge-data.h"
#include "en-lflow.h"
#include "lib/ovn-br-idl.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-util.h"

VLOG_DEFINE_THIS_MODULE(main);

static char *parse_options(int argc, char *argv[]);
OVS_NO_RETURN static void usage(void);

/* SSL/TLS options. */
static const char *ssl_private_key_file;
static const char *ssl_certificate_file;
static const char *ssl_ca_cert_file;

/* --unixctl-path: Path to use for unixctl server socket. */
static char *unixctl_path;

#define BRCTL_NODES \
    BRCTL_NODE(br_global) \
    BRCTL_NODE(bridge) \
    BRCTL_NODE(logical_flow)

enum brctl_engine_node {
#define BRCTL_NODE(NAME) BRCTL_##NAME,
    BRCTL_NODES
#undef BRCTL_NODE
};

#define BRCTL_NODE(NAME) ENGINE_FUNC_BR(NAME);
    BRCTL_NODES
#undef BRCTL_NODE

#define OVS_NODES \
    OVS_NODE(open_vswitch) \
    OVS_NODE(bridge) \
    OVS_NODE(port) \
    OVS_NODE(interface)

enum ovs_engine_node {
#define OVS_NODE(NAME) OVS_##NAME,
    OVS_NODES
#undef OVS_NODE
};

#define OVS_NODE(NAME) ENGINE_FUNC_OVS(NAME);
    OVS_NODES
#undef OVS_NODE

/* Engine static functions. */
static void *
en_br_controller_output_init(struct engine_node *node OVS_UNUSED,
                             struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

static void
en_br_controller_output_cleanup(void *data OVS_UNUSED)
{

}

static enum engine_node_state
en_br_controller_output_run(struct engine_node *node OVS_UNUSED,
                            void *data OVS_UNUSED)
{
    return EN_UPDATED;
}

/* Static function declarations. */
static void ctrl_register_ovs_idl(struct ovsdb_idl *ovs_idl);
static void update_br_db(struct ovsdb_idl *ovs_idl,
                         struct ovsdb_idl *ovn_br_idl);

int
main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct unixctl_server *unixctl;
    struct ovn_exit_args exit_args = {0};
    int retval;

    ovs_cmdl_proctitle_init(argc, argv);
    ovn_set_program_name(argv[0]);
    service_start(&argc, &argv);
    char *ovs_remote = parse_options(argc, argv);
    fatal_ignore_sigpipe();

    daemonize_start(true, false);

    char *abs_unixctl_path = get_abs_unix_ctl_path(unixctl_path);
    retval = unixctl_server_create(abs_unixctl_path, &unixctl);
    free(abs_unixctl_path);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 1, ovn_exit_command_callback,
                             &exit_args);

    daemonize_complete();

    /* Connect to OVS OVSDB instance. */
    struct ovsdb_idl_loop ovs_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovs_remote, &ovsrec_idl_class, false, true));
    ctrl_register_ovs_idl(ovs_idl_loop.idl);

    ovsdb_idl_get_initial_snapshot(ovs_idl_loop.idl);

    /* Configure OVN bridge database. */
    struct ovsdb_idl_loop ovnbr_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&ovnbrrec_idl_class, true));
    ovsdb_idl_set_leader_only(ovnbr_idl_loop.idl, false);

    ovsdb_idl_track_add_all(ovnbr_idl_loop.idl);

    unixctl_command_register("connection-status", "", 0, 0,
                             ovn_conn_show, ovnbr_idl_loop.idl);

    /* We don't want to monitor Connection table at all. So omit all the
     * columns. */
    ovsdb_idl_omit(ovnbr_idl_loop.idl, &ovnbrrec_connection_col_external_ids);
    ovsdb_idl_omit(ovnbr_idl_loop.idl,
                   &ovnbrrec_connection_col_inactivity_probe);
    ovsdb_idl_omit(ovnbr_idl_loop.idl, &ovnbrrec_connection_col_is_connected);
    ovsdb_idl_omit(ovnbr_idl_loop.idl, &ovnbrrec_connection_col_max_backoff);
    ovsdb_idl_omit(ovnbr_idl_loop.idl, &ovnbrrec_connection_col_other_config);
    ovsdb_idl_omit(ovnbr_idl_loop.idl, &ovnbrrec_connection_col_status);
    ovsdb_idl_omit(ovnbr_idl_loop.idl, &ovnbrrec_connection_col_target);

    /* Define inc-proc-engine nodes. */
    ENGINE_NODE(bridge_data);
    ENGINE_NODE(lflow_output);
    ENGINE_NODE(br_controller_output);

#define BRCTL_NODE(NAME) ENGINE_NODE_BR(NAME);
    BRCTL_NODES
#undef BRCTL_NODE

#define OVS_NODE(NAME) ENGINE_NODE_OVS(NAME);
    OVS_NODES
#undef OVS_NODE

    engine_add_input(&en_bridge_data, &en_ovs_open_vswitch, NULL);
    engine_add_input(&en_bridge_data, &en_ovs_bridge, NULL);
    engine_add_input(&en_bridge_data, &en_ovs_port, NULL);
    engine_add_input(&en_bridge_data, &en_ovs_interface, NULL);

    engine_add_input(&en_bridge_data, &en_ovnbr_br_global, NULL);
    engine_add_input(&en_bridge_data, &en_ovnbr_bridge, NULL);

    engine_add_input(&en_lflow_output, &en_bridge_data, NULL);
    engine_add_input(&en_lflow_output, &en_ovnbr_logical_flow, NULL);
    engine_add_input(&en_br_controller_output, &en_lflow_output, NULL);

    struct engine_arg engine_arg = {
        .ovs_idl = ovs_idl_loop.idl,
        .ovnbr_idl = ovnbr_idl_loop.idl,
    };
    engine_init(&en_br_controller_output, &engine_arg);

    unsigned int ovs_cond_seqno = UINT_MAX;
    unsigned int ovnbr_cond_seqno = UINT_MAX;

    /* Main loop. */
    while (!exit_args.exiting) {
        engine_init_run();

        struct ovsdb_idl_txn *ovs_idl_txn = ovsdb_idl_loop_run(&ovs_idl_loop);
        unsigned int new_ovs_cond_seqno
            = ovsdb_idl_get_condition_seqno(ovs_idl_loop.idl);
        if (new_ovs_cond_seqno != ovs_cond_seqno) {
            if (!new_ovs_cond_seqno) {
                VLOG_INFO("OVS IDL reconnected, force recompute.");
                engine_set_force_recompute();
            }
            ovs_cond_seqno = new_ovs_cond_seqno;
        }

        update_br_db(ovs_idl_loop.idl, ovnbr_idl_loop.idl);
        struct ovsdb_idl_txn *ovnbr_idl_txn
            = ovsdb_idl_loop_run(&ovnbr_idl_loop);
        unsigned int new_ovnbr_cond_seqno
            = ovsdb_idl_get_condition_seqno(ovnbr_idl_loop.idl);
        if (new_ovnbr_cond_seqno != ovnbr_cond_seqno) {
            if (!new_ovnbr_cond_seqno) {
                VLOG_INFO("OVNBR IDL reconnected, force recompute.");
                engine_set_force_recompute();
            }
            ovnbr_cond_seqno = new_ovnbr_cond_seqno;
        }

        struct engine_context eng_ctx = {
            .ovs_idl_txn = ovs_idl_txn,
            .ovnbr_idl_txn = ovnbr_idl_txn,
        };

        engine_set_context(&eng_ctx);

        const struct ovsrec_open_vswitch_table *ovs_table =
            ovsrec_open_vswitch_table_get(ovs_idl_loop.idl);
        const struct ovsrec_open_vswitch *cfg =
            ovsrec_open_vswitch_table_first(ovs_table);

        if (ovsdb_idl_has_ever_connected(ovnbr_idl_loop.idl) && cfg) {
            engine_run(true);
        }

        unixctl_server_run(unixctl);

        unixctl_server_wait(unixctl);
        if (exit_args.exiting) {
            poll_immediate_wake();
        }

        ovsdb_idl_loop_commit_and_wait(&ovs_idl_loop);
        ovsdb_idl_loop_commit_and_wait(&ovnbr_idl_loop);
        ovsdb_idl_track_clear(ovnbr_idl_loop.idl);
        ovsdb_idl_track_clear(ovs_idl_loop.idl);

        poll_block();
        if (should_service_stop()) {
            exit_args.exiting = true;
        }
    }

    engine_set_context(NULL);
    engine_cleanup();

    free(ovs_remote);
    ovn_exit_args_finish(&exit_args);
    unixctl_server_destroy(unixctl);
    service_stop();
    exit(0);
}

/* static functions. */
static char *
parse_options(int argc, char *argv[])
{
    enum {
        OPT_PEER_CA_CERT = UCHAR_MAX + 1,
        OPT_BOOTSTRAP_CA_CERT,
        VLOG_OPTION_ENUMS,
        OVN_DAEMON_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };

    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {"unixctl", required_argument, NULL, 'u'},
        VLOG_LONG_OPTIONS,
        OVN_DAEMON_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        {NULL, 0, NULL, 0}
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(OFP15_VERSION, OFP15_VERSION);
            printf("OVN BR DB Schema %s\n", ovnbrrec_get_db_version());
            exit(EXIT_SUCCESS);

        case 'u':
            unixctl_path = optarg;
            break;

        VLOG_OPTION_HANDLERS
        OVN_DAEMON_OPTION_HANDLERS

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

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            ovs_abort(0, "Invalid option.");
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    char *ovs_remote = NULL;
    if (argc == 0) {
        ovs_remote = xasprintf("unix:%s/db.sock", ovs_rundir());
    } else if (argc == 1) {
        ovs_remote = xstrdup(argv[0]);
    } else {
        VLOG_FATAL("exactly zero or one non-option argument required; "
                   "use --help for usage");
    }
    return ovs_remote;
}

static void
usage(void)
{
    printf("%s: OVN bridge controller\n"
           "usage %s [OPTIONS] [OVS-DATABASE]\n"
           "where OVS-DATABASE is a socket on which the OVS OVSDB server "
           "is listening.\n",
           program_name, program_name);
    stream_usage("OVS-DATABASE", true, false, true);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -u, --unixctl=SOCKET    set control socket name\n"
           "  -n                      custom chassis name\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}

static void
ctrl_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    /* We do not monitor all tables by default, so modules must register
     * their interest explicitly.
     * When the same column is monitored in different modes by different
     * modules, there is a chance that "track" flag added by
     * ovsdb_idl_track_add_column by one module being overwritten by a
     * following ovsdb_idl_add_column by another module. Before this is fixed
     * in OVSDB IDL, we need to be careful about the order so that the "track"
     * calls are after the "non-track" calls. */
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_other_config);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_bridges);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_datapaths);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_external_ids);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_external_ids);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_interfaces);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_external_ids);
}

/* Retrieves the pointer to the OVN Bridge Controller database from 'ovs_idl'
 * and updates 'brdb_idl' with that pointer. */
static void
update_br_db(struct ovsdb_idl *ovs_idl, struct ovsdb_idl *ovnbr_idl)
{
    const struct ovsrec_open_vswitch *cfg = ovsrec_open_vswitch_first(ovs_idl);
    if (!cfg) {
        return;
    }

    const char *remote = smap_get(&cfg->external_ids, "ovn-br-remote");
    ovsdb_idl_set_remote(ovnbr_idl, remote, true);
}
