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

#include "ovn-dbctl.h"

#include <getopt.h>

#include "command-line.h"
#include "daemon.h"
#include "db-ctl-base.h"
#include "fatal-signal.h"
#include "jsonrpc.h"
#include "memory.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovn-util.h"
#include "ovsdb-idl.h"
#include "process.h"
#include "simap.h"
#include "stream-ssl.h"
#include "svec.h"
#include "table.h"
#include "timer.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ovn_dbctl);

/* --db: The database server to contact. */
static const char *db;

/* --oneline: Write each command's output as a single line? */
static bool oneline;

/* --dry-run: Do not commit any changes. */
static bool dry_run;

/* SSL options */
static const char *ssl_private_key_file;
static const char *ssl_certificate_file;
static const char *ssl_ca_cert_file;

/* --wait=TYPE: Wait for configuration change to take effect? */
static enum nbctl_wait_type wait_type = NBCTL_WAIT_NONE;

static bool print_wait_time = false;

/* --timeout: Time to wait for a connection to 'db'. */
static unsigned int timeout;

/* Format for table output. */
static struct table_style table_style = TABLE_STYLE_DEFAULT;

/* The IDL we're using and the current transaction, if any.  This is for use by
 * ovn_dbctl_exit() only, to allow it to clean up.  Other code should use its
 * context arguments. */
static struct ovsdb_idl *the_idl;
static struct ovsdb_idl_txn *the_idl_txn;

/* --leader-only, --no-leader-only: Only accept the leader in a cluster. */
static int leader_only = true;

/* --shuffle-remotes, --no-shuffle-remotes: Shuffle the order of remotes that
 * are specified in the connetion method string. */
static int shuffle_remotes = true;

/* --unixctl-path: Path to use for unixctl server socket, for daemon mode. */
static char *unixctl_path;

static unixctl_cb_func server_cmd_exit;
static unixctl_cb_func server_cmd_run;

static struct option *get_all_options(void);
static bool has_option(const struct ovs_cmdl_parsed_option *, size_t n,
                       int option);
static void dbctl_client(const struct ovn_dbctl_options *dbctl_options,
                         const char *socket_name,
                         const struct ovs_cmdl_parsed_option *, size_t n,
                         int argc, char *argv[]);
static bool will_detach(const struct ovs_cmdl_parsed_option *, size_t n);
static void apply_options_direct(const struct ovn_dbctl_options *dbctl_options,
                                 const struct ovs_cmdl_parsed_option *,
                                 size_t n, struct shash *local_options);
static char * OVS_WARN_UNUSED_RESULT run_prerequisites(
    const struct ovn_dbctl_options *dbctl_options,
    struct ctl_command[], size_t n_commands, struct ovsdb_idl *);
static char * OVS_WARN_UNUSED_RESULT do_dbctl(
    const struct ovn_dbctl_options *dbctl_options,
    const char *args, struct ctl_command *, size_t n,
    struct ovsdb_idl *, const struct timer *, bool *retry);
static char * OVS_WARN_UNUSED_RESULT main_loop(
    const struct ovn_dbctl_options *, const char *args,
    struct ctl_command *commands, size_t n_commands,
    struct ovsdb_idl *idl, const struct timer *);
static void server_loop(const struct ovn_dbctl_options *dbctl_options,
                        struct ovsdb_idl *idl, int argc, char *argv[]);
static void ovn_dbctl_exit(int status);

int
ovn_dbctl_main(int argc, char *argv[],
               const struct ovn_dbctl_options *dbctl_options)
{
    struct ovsdb_idl *idl;
    struct shash local_options;

    ovn_set_program_name(argv[0]);
    fatal_ignore_sigpipe();
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels_from_string_assert("reconnect:warn");

    ctl_init__(dbctl_options->idl_class,
               dbctl_options->tables,
               dbctl_options->cmd_show_table,
               ovn_dbctl_exit);
    ctl_register_commands(dbctl_options->commands);

    /* Check if options are set via env var. */
    char **argv_ = ovs_cmdl_env_parse_all(
        &argc, argv, getenv(dbctl_options->options_env_var_name));

    /* This utility has three operation modes:
     *
     *    - Direct: Executes commands by contacting ovsdb-server directly.
     *
     *    - Server: Runs in the background as a daemon waiting for requests
     *      from a process running in client mode.
     *
     *    - Client: Executes commands by passing them to a process running in
     *      the server mode.
     *
     * At this point we don't know what mode we're running in.  The mode partly
     * depends on the command line.  So, for now we transform the command line
     * into a parsed form, and figure out what to do with it later.
     */
    struct ovs_cmdl_parsed_option *parsed_options;
    size_t n_parsed_options;
    char *error_s = ovs_cmdl_parse_all(argc, argv_, get_all_options(),
                                       &parsed_options, &n_parsed_options);
    if (error_s) {
        ctl_fatal("%s", error_s);
    }

    /* Now figure out the operation mode:
     *
     *    - A --detach option implies server mode.
     *
     *    - An OVN_??_DAEMON environment variable implies client mode.
     *
     *    - Otherwise, we're in direct mode. */
    const char *socket_name = (unixctl_path ? unixctl_path
                               : getenv(dbctl_options->daemon_env_var_name));
    if (((socket_name && socket_name[0])
         || has_option(parsed_options, n_parsed_options, 'u'))
        && !will_detach(parsed_options, n_parsed_options)) {
        dbctl_client(dbctl_options, socket_name,
                     parsed_options, n_parsed_options, argc, argv_);
    }

    /* Parse command line. */
    shash_init(&local_options);
    apply_options_direct(dbctl_options,
                         parsed_options, n_parsed_options, &local_options);
    free(parsed_options);

    bool daemon_mode = false;
    if (get_detach()) {
        if (argc != optind) {
            ctl_fatal("non-option arguments not supported with --detach "
                      "(use --help for help)");
        }
        daemon_mode = true;
    }
    /* Initialize IDL. */
    idl = the_idl = ovsdb_idl_create_unconnected(dbctl_options->idl_class,
                                                 daemon_mode);
    ovsdb_idl_set_shuffle_remotes(idl, shuffle_remotes);
    /* "retry" is true iff in daemon mode. */
    ovsdb_idl_set_remote(idl, db, daemon_mode);
    ovsdb_idl_set_leader_only(idl, leader_only);

    if (daemon_mode) {
        server_loop(dbctl_options, idl, argc, argv_);
    } else {
        struct ctl_command *commands;
        size_t n_commands;
        char *error;

        error = ctl_parse_commands(argc - optind, argv_ + optind,
                                   &local_options, &commands, &n_commands);
        if (error) {
            ctl_fatal("%s", error);
        }

        char *args = process_escape_args(argv_);
        VLOG(ctl_might_write_to_db(commands, n_commands) ? VLL_INFO : VLL_DBG,
             "Called as %s", args);

        ctl_timeout_setup(timeout);

        error = run_prerequisites(dbctl_options, commands, n_commands, idl);
        if (error) {
            goto cleanup;
        }

        error = main_loop(dbctl_options, args, commands, n_commands, idl, NULL);

cleanup:
        free(args);

        struct ctl_command *c;
        for (c = commands; c < &commands[n_commands]; c++) {
            ds_destroy(&c->output);
            table_destroy(c->table);
            free(c->table);
            shash_destroy_free_data(&c->options);
        }
        free(commands);
        if (error) {
            ctl_fatal("%s", error);
        }
    }

    ovsdb_idl_destroy(idl);
    idl = the_idl = NULL;

    for (int i = 0; i < argc; i++) {
        free(argv_[i]);
    }
    free(argv_);
    exit(EXIT_SUCCESS);
}

static char *
main_loop(const struct ovn_dbctl_options *dbctl_options,
          const char *args, struct ctl_command *commands, size_t n_commands,
          struct ovsdb_idl *idl, const struct timer *wait_timeout)
{
    unsigned int seqno;
    bool idl_ready;

    /* Execute the commands.
     *
     * 'seqno' is the database sequence number for which we last tried to
     * execute our transaction.  There's no point in trying to commit more than
     * once for any given sequence number, because if the transaction fails
     * it's because the database changed and we need to obtain an up-to-date
     * view of the database before we try the transaction again. */
    seqno = ovsdb_idl_get_seqno(idl);

    /* IDL might have already obtained the database copy during previous
     * invocation. If so, we can't expect the sequence number to change before
     * we issue any new requests. */
    idl_ready = ovsdb_idl_has_ever_connected(idl);
    for (;;) {
        ovsdb_idl_run(idl);
        if (!ovsdb_idl_is_alive(idl)) {
            int retval = ovsdb_idl_get_last_error(idl);
            ctl_fatal("%s: database connection failed (%s)",
                      db, ovs_retval_to_string(retval));
        }

        if (idl_ready || seqno != ovsdb_idl_get_seqno(idl)) {
            idl_ready = false;
            seqno = ovsdb_idl_get_seqno(idl);

            bool retry;
            char *error = do_dbctl(dbctl_options,
                                   args, commands, n_commands, idl,
                                   wait_timeout, &retry);
            if (error) {
                return error;
            }
            if (!retry) {
                return NULL;
            }
        }

        if (seqno == ovsdb_idl_get_seqno(idl)) {
            ovsdb_idl_wait(idl);
            poll_block();
        }
    }

    return NULL;
}

/* All options that affect the main loop and are not external. */
#define MAIN_LOOP_OPTION_ENUMS                  \
        OPT_NO_WAIT,                            \
        OPT_WAIT,                               \
        OPT_PRINT_WAIT_TIME,                    \
        OPT_DRY_RUN,                            \
        OPT_ONELINE

#define MAIN_LOOP_LONG_OPTIONS                                          \
        {"no-wait", no_argument, NULL, OPT_NO_WAIT},                    \
        {"wait", required_argument, NULL, OPT_WAIT},                    \
        {"print-wait-time", no_argument, NULL, OPT_PRINT_WAIT_TIME},    \
        {"dry-run", no_argument, NULL, OPT_DRY_RUN},                    \
        {"oneline", no_argument, NULL, OPT_ONELINE},                    \
        {"timeout", required_argument, NULL, 't'}

enum {
    OPT_DB = UCHAR_MAX + 1,
    OPT_NO_SYSLOG,
    OPT_LOCAL,
    OPT_COMMANDS,
    OPT_OPTIONS,
    OPT_LEADER_ONLY,
    OPT_NO_LEADER_ONLY,
    OPT_SHUFFLE_REMOTES,
    OPT_NO_SHUFFLE_REMOTES,
    OPT_BOOTSTRAP_CA_CERT,
    MAIN_LOOP_OPTION_ENUMS,
    OVN_DAEMON_OPTION_ENUMS,
    VLOG_OPTION_ENUMS,
    TABLE_OPTION_ENUMS,
    SSL_OPTION_ENUMS,
};

static char * OVS_WARN_UNUSED_RESULT
handle_main_loop_option(const struct ovn_dbctl_options *dbctl_options,
                        int opt, const char *arg, bool *handled)
{
    ovs_assert(handled);
    *handled = true;

    switch (opt) {
    case OPT_ONELINE:
        oneline = true;
        break;

    case OPT_NO_WAIT:
        if (!dbctl_options->allow_wait) {
            return xstrdup("--no-wait not supported");
        }
        wait_type = NBCTL_WAIT_NONE;
        break;

    case OPT_WAIT:
        if (!dbctl_options->allow_wait) {
            return xstrdup("--wait not supported");
        } else if (!strcmp(arg, "none")) {
            wait_type = NBCTL_WAIT_NONE;
        } else if (!strcmp(arg, "sb")) {
            wait_type = NBCTL_WAIT_SB;
        } else if (!strcmp(arg, "hv")) {
            wait_type = NBCTL_WAIT_HV;
        } else {
            return xstrdup("argument to --wait must be "
                           "\"none\", \"sb\", or \"hv\"");
        }
        break;

    case OPT_PRINT_WAIT_TIME:
        if (!dbctl_options->allow_wait) {
            return xstrdup("--print-wait-time not supported");
        }
        print_wait_time = true;
        break;

    case OPT_DRY_RUN:
        dry_run = true;
        break;

    case 't':
        if (!str_to_uint(arg, 10, &timeout) || !timeout) {
            return xasprintf("value %s on -t or --timeout is invalid", arg);
        }
        break;

    default:
        *handled = false;
        break;
    }

    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
build_short_options(const struct option *long_options, bool print_errors)
{
    char *tmp, *short_options;

    tmp = ovs_cmdl_long_options_to_short_options(long_options);
    short_options = xasprintf("+%s%s", print_errors ? "" : ":", tmp);
    free(tmp);

    return short_options;
}

static struct option * OVS_WARN_UNUSED_RESULT
append_command_options(const struct option *options, int opt_val)
{
    struct option *o;
    size_t n_allocated;
    size_t n_existing;
    int i;

    for (i = 0; options[i].name; i++) {
        ;
    }
    n_allocated = i + 1;
    n_existing = i;

    /* We want to parse both global and command-specific options here, but
     * getopt_long() isn't too convenient for the job.  We copy our global
     * options into a dynamic array, then append all of the command-specific
     * options. */
    o = xmemdup(options, n_allocated * sizeof *options);
    ctl_add_cmd_options(&o, &n_existing, &n_allocated, opt_val);

    return o;
}

static struct option *
get_all_options(void)
{
    static const struct option global_long_options[] = {
        {"db", required_argument, NULL, OPT_DB},
        {"no-syslog", no_argument, NULL, OPT_NO_SYSLOG},
        {"help", no_argument, NULL, 'h'},
        {"commands", no_argument, NULL, OPT_COMMANDS},
        {"options", no_argument, NULL, OPT_OPTIONS},
        {"leader-only", no_argument, NULL, OPT_LEADER_ONLY},
        {"no-leader-only", no_argument, NULL, OPT_NO_LEADER_ONLY},
        {"shuffle-remotes", no_argument, NULL, OPT_SHUFFLE_REMOTES},
        {"no-shuffle-remotes", no_argument, NULL, OPT_NO_SHUFFLE_REMOTES},
        {"version", no_argument, NULL, 'V'},
        {"unixctl", required_argument, NULL, 'u'},
        MAIN_LOOP_LONG_OPTIONS,
        OVN_DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        TABLE_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };

    static struct option *options;
    if (!options) {
        options = append_command_options(global_long_options, OPT_LOCAL);
    }

    return options;
}

static bool
has_option(const struct ovs_cmdl_parsed_option *parsed_options, size_t n,
           int option)
{
    for (const struct ovs_cmdl_parsed_option *po = parsed_options;
         po < &parsed_options[n]; po++) {
        if (po->o->val == option) {
            return true;
        }
    }
    return false;
}

static bool
will_detach(const struct ovs_cmdl_parsed_option *parsed_options, size_t n)
{
    return has_option(parsed_options, n, OVN_OPT_DETACH);
}

static char * OVS_WARN_UNUSED_RESULT
add_local_option(const char *name, const char *arg,
                 struct shash *local_options)
{
    char *full_name = xasprintf("--%s", name);
    if (shash_find(local_options, full_name)) {
        char *error = xasprintf("'%s' option specified multiple times",
                                full_name);
        free(full_name);
        return error;
    }
    shash_add_nocopy(local_options, full_name, nullable_xstrdup(arg));
    return NULL;
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
apply_options_direct(const struct ovn_dbctl_options *dbctl_options,
                     const struct ovs_cmdl_parsed_option *parsed_options,
                     size_t n, struct shash *local_options)
{
    for (const struct ovs_cmdl_parsed_option *po = parsed_options;
         po < &parsed_options[n]; po++) {
        bool handled;
        char *error = handle_main_loop_option(dbctl_options,
                                              po->o->val, po->arg, &handled);
        if (error) {
            ctl_fatal("%s", error);
        }
        if (handled) {
            continue;
        }

        optarg = po->arg;
        switch (po->o->val) {
        case OPT_DB:
            db = po->arg;
            break;

        case OPT_NO_SYSLOG:
            vlog_set_levels(&this_module, VLF_SYSLOG, VLL_WARN);
            break;

        case OPT_LOCAL:
            error = add_local_option(po->o->name, po->arg, local_options);
            if (error) {
                ctl_fatal("%s", error);
            }
            break;

        case 'h':
            dbctl_options->usage();
            exit(EXIT_SUCCESS);

        case OPT_COMMANDS:
            ctl_print_commands();
            /* fall through */

        case OPT_OPTIONS:
            ctl_print_options(get_all_options());
            /* fall through */

        case OPT_LEADER_ONLY:
            leader_only = true;
            break;

        case OPT_NO_LEADER_ONLY:
            leader_only = false;
            break;

        case OPT_SHUFFLE_REMOTES:
            shuffle_remotes = true;
            break;

        case OPT_NO_SHUFFLE_REMOTES:
            shuffle_remotes = false;
            break;

        case 'u':
            unixctl_path = optarg;
            break;

        case 'V':
            ovn_print_version(0, 0);
            printf("DB Schema %s\n", dbctl_options->db_version);
            exit(EXIT_SUCCESS);

        OVN_DAEMON_OPTION_HANDLERS
        VLOG_OPTION_HANDLERS
        TABLE_OPTION_HANDLERS(&table_style)

        case 'p':
            ssl_private_key_file = optarg;
            break;

        case 'c':
            ssl_certificate_file = optarg;
            break;

        case 'C':
            ssl_ca_cert_file = optarg;
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(po->arg, true);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            OVS_NOT_REACHED();

        case 0:
            break;
        }
    }

    if (!db) {
        db = dbctl_options->default_db;
    }
    update_ssl_config();
}

static char *
run_prerequisites(const struct ovn_dbctl_options *dbctl_options,
                  struct ctl_command *commands, size_t n_commands,
                  struct ovsdb_idl *idl)
{
    dbctl_options->add_base_prerequisites(idl, wait_type);

    for (struct ctl_command *c = commands; c < &commands[n_commands]; c++) {
        if (c->syntax->prerequisites) {
            struct ctl_context ctx;

            ds_init(&c->output);
            c->table = NULL;

            ctl_context_init(&ctx, c, idl, NULL, NULL, NULL);
            (c->syntax->prerequisites)(&ctx);
            if (ctx.error) {
                char *error = xstrdup(ctx.error);
                ctl_context_done(&ctx, c);
                return error;
            }
            ctl_context_done(&ctx, c);

            ovs_assert(!c->output.string);
            ovs_assert(!c->table);
        }
    }

    return NULL;
}

static void
oneline_format(struct ds *lines, struct ds *s)
{
    size_t j;

    ds_chomp(lines, '\n');
    for (j = 0; j < lines->length; j++) {
        int ch = lines->string[j];
        switch (ch) {
        case '\n':
            ds_put_cstr(s, "\\n");
            break;

        case '\\':
            ds_put_cstr(s, "\\\\");
            break;

        default:
            ds_put_char(s, ch);
        }
    }
    ds_put_char(s, '\n');
}

static void
oneline_print(struct ds *lines)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    oneline_format(lines, &s);
    fputs(ds_cstr(&s), stdout);
    ds_destroy(&s);
}

static char *
do_dbctl(const struct ovn_dbctl_options *dbctl_options,
         const char *args, struct ctl_command *commands, size_t n_commands,
         struct ovsdb_idl *idl, const struct timer *wait_timeout, bool *retry)
{
    struct ovsdb_idl_txn *txn;
    enum ovsdb_idl_txn_status status;
    struct ovsdb_symbol_table *symtab;
    struct ctl_command *c;
    struct shash_node *node;
    char *error = NULL;

    ovs_assert(retry);

    txn = the_idl_txn = ovsdb_idl_txn_create(idl);
    if (dry_run) {
        ovsdb_idl_txn_set_dry_run(txn);
    }

    ovsdb_idl_txn_add_comment(txn, "%s: %s", program_name, args);

    dbctl_options->pre_execute(idl, txn, wait_type);

    symtab = ovsdb_symbol_table_create();
    for (c = commands; c < &commands[n_commands]; c++) {
        ds_init(&c->output);
        c->table = NULL;
    }
    struct ctl_context *ctx = dbctl_options->ctx_create();
    ctl_context_init(ctx, NULL, idl, txn, symtab, NULL);
    for (c = commands; c < &commands[n_commands]; c++) {
        ctl_context_init_command(ctx, c);
        if (c->syntax->run) {
            (c->syntax->run)(ctx);
        }
        if (ctx->error) {
            error = xstrdup(ctx->error);
            ctl_context_done(ctx, c);
            goto out_error;
        }
        ctl_context_done_command(ctx, c);

        if (ctx->try_again) {
            ctl_context_done(ctx, NULL);
            goto try_again;
        }
    }
    ctl_context_done(ctx, NULL);

    SHASH_FOR_EACH (node, &symtab->sh) {
        struct ovsdb_symbol *symbol = node->data;
        if (!symbol->created) {
            error = xasprintf("row id \"%s\" is referenced but never created "
                              "(e.g. with \"-- --id=%s create ...\")",
                              node->name, node->name);
            goto out_error;
        }
        if (!symbol->strong_ref) {
            if (!symbol->weak_ref) {
                VLOG_WARN("row id \"%s\" was created but no reference to it "
                          "was inserted, so it will not actually appear in "
                          "the database", node->name);
            } else {
                VLOG_WARN("row id \"%s\" was created but only a weak "
                          "reference to it was inserted, so it will not "
                          "actually appear in the database", node->name);
            }
        }
    }

    long long int start_time = time_wall_msec();
    status = ovsdb_idl_txn_commit_block(txn);
    if (status == TXN_UNCHANGED || status == TXN_SUCCESS) {
        for (c = commands; c < &commands[n_commands]; c++) {
            if (c->syntax->postprocess) {
                ctl_context_init(ctx, c, idl, txn, symtab, NULL);
                (c->syntax->postprocess)(ctx);
                if (ctx->error) {
                    error = xstrdup(ctx->error);
                    ctl_context_done(ctx, c);
                    goto out_error;
                }
                ctl_context_done(ctx, c);
            }
        }
    }

    switch (status) {
    case TXN_UNCOMMITTED:
    case TXN_INCOMPLETE:
        OVS_NOT_REACHED();

    case TXN_ABORTED:
        /* Should not happen--we never call ovsdb_idl_txn_abort(). */
        error = xstrdup("transaction aborted");
        goto out_error;

    case TXN_UNCHANGED:
    case TXN_SUCCESS:
        break;

    case TXN_TRY_AGAIN:
        goto try_again;

    case TXN_ERROR:
        error = xasprintf("transaction error: %s",
                          ovsdb_idl_txn_get_error(txn));
        goto out_error;

    case TXN_NOT_LOCKED:
        /* Should not happen--we never call ovsdb_idl_set_lock(). */
        error = xstrdup("database not locked");
        goto out_error;

    default:
        OVS_NOT_REACHED();
    }

    for (c = commands; c < &commands[n_commands]; c++) {
        struct ds *ds = &c->output;

        if (c->table) {
            table_print(c->table, &table_style);
        } else if (oneline) {
            oneline_print(ds);
        } else {
            fputs(ds_cstr(ds), stdout);
        }
    }

    if (dbctl_options->post_execute) {
        error = dbctl_options->post_execute(idl, txn, status, wait_type,
                                            wait_timeout, start_time,
                                            print_wait_time);
        if (error) {
            goto out_error;
        }
    }

    dbctl_options->ctx_destroy(ctx);
    ovsdb_symbol_table_destroy(symtab);
    ovsdb_idl_txn_destroy(txn);
    the_idl_txn = NULL;

    *retry = false;
    return NULL;

try_again:
    /* Our transaction needs to be rerun, or a prerequisite was not met.  Free
     * resources and return so that the caller can try again. */
    *retry = true;

out_error:
    ovsdb_idl_txn_abort(txn);
    ovsdb_idl_txn_destroy(txn);
    the_idl_txn = NULL;

    dbctl_options->ctx_destroy(ctx);
    ovsdb_symbol_table_destroy(symtab);
    return error;
}

/* Frees the current transaction and the underlying IDL and then calls
 * exit(status).
 *
 * Freeing the transaction and the IDL is not strictly necessary, but it makes
 * for a clean memory leak report from valgrind in the normal case.  That makes
 * it easier to notice real memory leaks. */
static void
ovn_dbctl_exit(int status)
{
    if (the_idl_txn) {
        ovsdb_idl_txn_abort(the_idl_txn);
        ovsdb_idl_txn_destroy(the_idl_txn);
    }
    ovsdb_idl_destroy(the_idl);
    exit(status);
}

/* Server implementation. */

#undef ctl_fatal

static const struct option *
find_option_by_value(const struct option *options, int value)
{
    const struct option *o;

    for (o = options; o->name; o++) {
        if (o->val == value) {
            return o;
        }
    }
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
server_parse_options(const struct ovn_dbctl_options *dbctl_options,
                     int argc, char *argv[], struct shash *local_options,
                     int *n_options_p)
{
    static const struct option global_long_options[] = {
        VLOG_LONG_OPTIONS,
        MAIN_LOOP_LONG_OPTIONS,
        TABLE_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    const int n_global_long_options = ARRAY_SIZE(global_long_options) - 1;
    char *short_options;
    struct option *options;
    char *error = NULL;

    ovs_assert(n_options_p);

    short_options = build_short_options(global_long_options, false);
    options = append_command_options(global_long_options, OPT_LOCAL);

    optind = 0;
    opterr = 0;
    for (;;) {
        int idx;
        int c;

        c = getopt_long(argc, argv, short_options, options, &idx);
        if (c == -1) {
            break;
        }

        bool handled;
        error = handle_main_loop_option(dbctl_options, c, optarg, &handled);
        if (error) {
            goto out;
        }
        if (handled) {
            continue;
        }

        switch (c) {
        case OPT_LOCAL:
            error = add_local_option(options[idx].name, optarg, local_options);
            if (error) {
                goto out;
            }
            break;

        VLOG_OPTION_HANDLERS
        TABLE_OPTION_HANDLERS(&table_style)

        case '?':
            if (find_option_by_value(options, optopt)) {
                error = xasprintf("option '%s' doesn't allow an argument",
                                  argv[optind - 1]);
            } else if (optopt) {
                error = xasprintf("unrecognized option '%c'", optopt);
            } else {
                error = xasprintf("unrecognized option '%s'", argv[optind - 1]);
            }
            goto out;
            break;

        case ':':
            error = xasprintf("option '%s' requires an argument",
                              argv[optind - 1]);
            goto out;
            break;

        case 0:
            break;

        default:
            error = xasprintf("unhandled option '%c'", c);
            goto out;
            break;
        }
    }
    *n_options_p = optind;

out:
    for (int i = n_global_long_options; options[i].name; i++) {
        free(CONST_CAST(char *, options[i].name));
    }
    free(options);
    free(short_options);

    return error;
}

static void
server_cmd_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}

struct server_cmd_run_ctx {
    struct ovsdb_idl *idl;
    const struct ovn_dbctl_options *dbctl_options;
};

static void
server_cmd_run(struct unixctl_conn *conn, int argc, const char **argv_,
               void *ctx_)
{
    struct server_cmd_run_ctx *ctx = ctx_;
    struct ovsdb_idl *idl = ctx->idl;
    const struct ovn_dbctl_options *dbctl_options = ctx->dbctl_options;

    struct ctl_command *commands = NULL;
    struct shash local_options;
    size_t n_commands = 0;
    int n_options = 0;
    char *error = NULL;

    /* Copy args so that getopt() can permute them. Leave last entry NULL. */
    char **argv = xcalloc(argc + 1, sizeof *argv);
    for (int i = 0; i < argc; i++) {
        argv[i] = xstrdup(argv_[i]);
    }

    /* Reset global state. */
    oneline = false;
    dry_run = false;
    wait_type = NBCTL_WAIT_NONE;
    timeout = 0;
    table_style = table_style_default;

    /* Parse commands & options. */
    char *args = process_escape_args(argv);
    shash_init(&local_options);
    error = server_parse_options(dbctl_options,
                                 argc, argv, &local_options, &n_options);
    if (error) {
        unixctl_command_reply_error(conn, error);
        goto out;
    }
    error = ctl_parse_commands(argc - n_options, argv + n_options,
                               &local_options, &commands, &n_commands);
    if (error) {
        unixctl_command_reply_error(conn, error);
        goto out;
    }
    VLOG(ctl_might_write_to_db(commands, n_commands) ? VLL_INFO : VLL_DBG,
         "Running command %s", args);

    struct timer *wait_timeout = NULL;
    struct timer wait_timeout_;
    if (timeout) {
        wait_timeout = &wait_timeout_;
        timer_set_duration(wait_timeout, timeout * 1000);
    }

    error = run_prerequisites(dbctl_options, commands, n_commands, idl);
    if (error) {
        unixctl_command_reply_error(conn, error);
        goto out;
    }
    error = main_loop(dbctl_options, args, commands, n_commands, idl, wait_timeout);
    if (error) {
        unixctl_command_reply_error(conn, error);
        goto out;
    }

    struct ds output = DS_EMPTY_INITIALIZER;
    table_format_reset();
    for (struct ctl_command *c = commands; c < &commands[n_commands]; c++) {
        if (c->table) {
            table_format(c->table, &table_style, &output);
        } else if (oneline) {
            oneline_format(&c->output, &output);
        } else {
            ds_put_cstr(&output, ds_cstr_ro(&c->output));
        }
    }
    unixctl_command_reply(conn, ds_cstr_ro(&output));
    ds_destroy(&output);

out:
    free(error);

    struct ctl_command *c;
    for (c = commands; c < &commands[n_commands]; c++) {
        ds_destroy(&c->output);
        table_destroy(c->table);
        free(c->table);
        shash_destroy_free_data(&c->options);
    }
    free(commands);
    shash_destroy_free_data(&local_options);
    free(args);
    for (int i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
}

static void
server_loop(const struct ovn_dbctl_options *dbctl_options,
            struct ovsdb_idl *idl, int argc, char *argv[])
{
    struct unixctl_server *server = NULL;
    bool exiting = false;

    service_start(&argc, &argv);
    daemonize_start(false);

    char *abs_unixctl_path = get_abs_unix_ctl_path(unixctl_path);
    int error = unixctl_server_create(abs_unixctl_path, &server);
    free(abs_unixctl_path);

    if (error) {
        ctl_fatal("failed to create unixctl server (%s)",
                  ovs_retval_to_string(error));
    }
    puts(unixctl_server_get_path(server));
    fflush(stdout);

    struct server_cmd_run_ctx server_cmd_run_ctx = {
        .idl = idl,
        .dbctl_options = dbctl_options
    };
    unixctl_command_register("run", "", 0, INT_MAX, server_cmd_run,
                             &server_cmd_run_ctx);
    unixctl_command_register("exit", "", 0, 0, server_cmd_exit, &exiting);

    for (;;) {
        update_ssl_config();
        memory_run();
        if (memory_should_report()) {
            struct simap usage = SIMAP_INITIALIZER(&usage);

            /* Nothing special to report yet. */
            memory_report(&usage);
            simap_destroy(&usage);
        }

        ovsdb_idl_run(idl);
        if (!ovsdb_idl_is_alive(idl)) {
            int retval = ovsdb_idl_get_last_error(idl);
            ctl_fatal("%s: database connection failed (%s)",
                      db, ovs_retval_to_string(retval));
        }

        if (ovsdb_idl_has_ever_connected(idl)) {
            daemonize_complete();
        }
        unixctl_server_run(server);

        if (exiting) {
            break;
        }

        memory_wait();
        ovsdb_idl_wait(idl);
        unixctl_server_wait(server);
        poll_block();
    }

    unixctl_server_destroy(server);
}

static void
dbctl_client(const struct ovn_dbctl_options *dbctl_options,
             const char *socket_name,
             const struct ovs_cmdl_parsed_option *parsed_options, size_t n,
             int argc, char *argv[])
{
    struct svec args = SVEC_EMPTY_INITIALIZER;

    for (const struct ovs_cmdl_parsed_option *po = parsed_options;
         po < &parsed_options[n]; po++) {
        optarg = po->arg;
        switch (po->o->val) {
        case OPT_DB:
            VLOG_WARN("not using %s daemon because of %s option",
                      program_name, po->o->name);
            svec_destroy(&args);
            return;

        case OPT_NO_SYSLOG:
            vlog_set_levels(&this_module, VLF_SYSLOG, VLL_WARN);
            break;

        case 'h':
            dbctl_options->usage();
            exit(EXIT_SUCCESS);

        case OPT_COMMANDS:
            ctl_print_commands();
            /* fall through */

        case OPT_OPTIONS:
            ctl_print_options(get_all_options());
            /* fall through */

        case OPT_LEADER_ONLY:
        case OPT_NO_LEADER_ONLY:
        case OPT_SHUFFLE_REMOTES:
        case OPT_NO_SHUFFLE_REMOTES:
        case OPT_BOOTSTRAP_CA_CERT:
        STREAM_SSL_CASES
        OVN_DAEMON_OPTION_CASES
            VLOG_INFO("using %s daemon, ignoring %s option",
                      program_name, po->o->name);
            break;

        case 'u':
            socket_name = optarg;
            break;

        case 'V':
            ovs_print_version(0, 0);
            printf("DB Schema %s\n", dbctl_options->db_version);
            exit(EXIT_SUCCESS);

        case 't':
            if (!str_to_uint(po->arg, 10, &timeout) || !timeout) {
                ctl_fatal("value %s on -t or --timeout is invalid", po->arg);
            }
            break;

        VLOG_OPTION_HANDLERS

        case OPT_LOCAL:
        default:
            if (po->arg) {
                svec_add_nocopy(&args,
                                xasprintf("--%s=%s", po->o->name, po->arg));
            } else {
                svec_add_nocopy(&args, xasprintf("--%s", po->o->name));
            }
            break;
        }
    }

    ovs_assert(socket_name && socket_name[0]);

    svec_add(&args, "--");
    for (int i = optind; i < argc; i++) {
        svec_add(&args, argv[i]);
    }

    ctl_timeout_setup(timeout);

    struct jsonrpc *client;
    int error = unixctl_client_create(socket_name, &client);
    if (error) {
        ctl_fatal("%s: could not connect to %s daemon (%s); "
                  "unset %s to avoid using daemon",
                  socket_name, program_name, ovs_strerror(error),
                  dbctl_options->daemon_env_var_name);
    }

    char *cmd_result;
    char *cmd_error;
    error = unixctl_client_transact(client, "run",
                                    args.n, args.names,
                                    &cmd_result, &cmd_error);
    if (error) {
        ctl_fatal("%s: transaction error (%s)",
                  socket_name, ovs_strerror(error));
    }
    svec_destroy(&args);

    int exit_status;
    if (cmd_error) {
        exit_status = EXIT_FAILURE;
        fprintf(stderr, "%s: %s", program_name, cmd_error);
    } else {
        exit_status = EXIT_SUCCESS;
        fputs(cmd_result, stdout);
    }
    free(cmd_result);
    free(cmd_error);
    jsonrpc_close(client);
    for (int i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
    exit(exit_status);
}
