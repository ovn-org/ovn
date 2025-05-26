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

#include <getopt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

/* OVS includes. */
#include "command-line.h"
#include "daemon.h"
#include "db-ctl-base.h"
#include "dirs.h"
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "lib/ovn-br-idl.h"
#include "lib/ovn-dirs.h"
#include "lib/ovn-util.h"
#include "lib/vec.h"
#include "ovn-dbctl.h"

VLOG_DEFINE_THIS_MODULE(brctl);

static char * OVS_WARN_UNUSED_RESULT br_by_name_or_uuid(
    struct ctl_context *ctx, const char *id, bool must_exist,
    const struct ovnbrrec_bridge **br_p);

static void
brctl_add_base_prerequisites(struct ovsdb_idl *idl,
                             enum nbctl_wait_type wait_type OVS_UNUSED)
{
    ovsdb_idl_add_table(idl, &ovnbrrec_table_br_global);
}

static void
brctl_pre_execute(struct ovsdb_idl *idl, struct ovsdb_idl_txn *txn,
                  enum nbctl_wait_type wait_type OVS_UNUSED)
{
    const struct ovnbrrec_br_global *br = ovnbrrec_br_global_first(idl);
    if (!br) {
        br = ovnbrrec_br_global_insert(txn);
    }
}

static int
get_inactivity_probe(struct ovsdb_idl *idl)
{
    const struct ovnbrrec_br_global *pr = ovnbrrec_br_global_first(idl);
    int interval = DEFAULT_UTILS_PROBE_INTERVAL_MSEC;

    if (pr) {
        interval = smap_get_int(&pr->options, "brctl_probe_interval",
                                interval);
    }

    return interval;
}

/* ovn-brctl specific context.  Inherits the 'struct ctl_context' as base. */
struct brctl_context {
    struct ctl_context base;
};

static struct ctl_context *
brctl_ctx_create(void)
{
    struct brctl_context *prctx = xmalloc(sizeof *prctx);

    return &prctx->base;
}

static void
brctl_ctx_destroy(struct ctl_context *ctx)
{
    free(ctx);
}

static void
print_br(const struct ovnbrrec_bridge *br, struct ds *s)
{
    ds_put_format(s, "bridge "UUID_FMT" (%s)\n",
                  UUID_ARGS(&br->header_.uuid), br->name);
}

static void
brctl_init(struct ctl_context *ctx OVS_UNUSED)
{
}

static void
brctl_pre_show(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &ovnbrrec_bridge_col_name);
    ovsdb_idl_add_column(ctx->idl, &ovnbrrec_bridge_col_options);
    ovsdb_idl_add_column(ctx->idl, &ovnbrrec_bridge_col_external_ids);
}

static const struct ctl_table_class tables[OVNBRREC_N_TABLES] = {
    [OVNBRREC_TABLE_BRIDGE].row_ids[0]
    = {&ovnbrrec_bridge_col_name, NULL, NULL},

    [OVNBRREC_TABLE_CONNECTION].row_ids[0]
    = {&ovnbrrec_connection_col_target, NULL, NULL},
};

static void
brctl_show(struct ctl_context *ctx)
{
    const struct ovnbrrec_bridge *br;

    if (ctx->argc == 2) {
        char *error = br_by_name_or_uuid(ctx, ctx->argv[1], true, &br);
        if (error) {
            ctx->error = error;
            return;
        }

        print_br(br, &ctx->output);
    } else {
        OVNBRREC_BRIDGE_FOR_EACH (br, ctx->idl) {
            print_br(br, &ctx->output);
        }
    }
}

static void
pre_get_info(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &ovnbrrec_bridge_col_name);
    ovsdb_idl_add_column(ctx->idl, &ovnbrrec_bridge_col_options);
    ovsdb_idl_add_column(ctx->idl, &ovnbrrec_bridge_col_external_ids);

    ovsdb_idl_add_column(ctx->idl, &ovnbrrec_logical_flow_col_actions);
    ovsdb_idl_add_column(ctx->idl, &ovnbrrec_logical_flow_col_bridge);
    ovsdb_idl_add_column(ctx->idl, &ovnbrrec_logical_flow_col_match);
    ovsdb_idl_add_column(ctx->idl, &ovnbrrec_logical_flow_col_priority);
    ovsdb_idl_add_column(ctx->idl, &ovnbrrec_logical_flow_col_table_id);
    ovsdb_idl_add_column(ctx->idl, &ovnbrrec_logical_flow_col_external_ids);
}

struct brctl_lflow {
    const struct ovnbrrec_logical_flow *lflow;
    const struct ovnbrrec_bridge *br;
};

static int
brctl_lflow_cmp(const void *a_, const void *b_)
{
    const struct brctl_lflow *a_ctl_lflow = a_;
    const struct brctl_lflow *b_ctl_lflow = b_;

    const struct ovnbrrec_logical_flow *a = a_ctl_lflow->lflow;
    const struct ovnbrrec_logical_flow *b = b_ctl_lflow->lflow;

    const struct ovnbrrec_bridge *abr = a_ctl_lflow->br;
    const struct ovnbrrec_bridge *bbr = b_ctl_lflow->br;
    const char *a_name = abr->name;
    const char *b_name = bbr->name;
    int cmp = strcmp(a_name, b_name);
    if (cmp) {
        return cmp;
    }

    cmp = uuid_compare_3way(&abr->header_.uuid, &bbr->header_.uuid);
    if (cmp) {
        return cmp;
    }

    cmp = (a->table_id > b->table_id ? 1
           : a->table_id < b->table_id ? -1
           : a->priority > b->priority ? -1
           : a->priority < b->priority ? 1
           : strcmp(a->match, b->match));
    return cmp ? cmp : strcmp(a->actions, b->actions);
}

static void
brctl_lflow_add(struct vector *lflows,
                const struct ovnbrrec_logical_flow *lflow,
                const struct ovnbrrec_bridge *br)
{
    struct brctl_lflow brctl_lflow = (struct brctl_lflow) {
        .lflow = lflow,
        .br = br,
    };
    vector_push(lflows, &brctl_lflow);
}

static void
print_uuid_part(const struct uuid *uuid, bool do_print, struct ds *s)
{
    if (!do_print) {
        return;
    }
    ds_put_format(s, "uuid=0x%08"PRIx32", ", uuid->parts[0]);
}

static void
print_bridge_prompt(const struct ovnbrrec_bridge *br,
                    const struct uuid *uuid, struct ds *s) {
        ds_put_format(s, "Bridge: %s", br->name);
        ds_put_format(s, " ("UUID_FMT")\n",
                      UUID_ARGS(uuid));
}

static char * OVS_WARN_UNUSED_RESULT
parse_priority(const char *arg, int64_t *priority_p)
{
    /* Validate priority. */
    int64_t priority;
    if (!ovs_scan(arg, "%"SCNd64, &priority)
        || priority < 0 || priority > 32767) {
        /* Priority_p could be uninitialized as no valid priority was
         * input, initialize it to a valid value of 0 before returning */
        *priority_p = 0;
        return xasprintf("%s: priority must in range 0...32767", arg);
    }
    *priority_p = priority;
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
parse_table_id(const char *arg, int64_t *table_p)
{
    /* Validate table id. */
    int64_t table;
    if (!ovs_scan(arg, "%"SCNd64, &table)
        || table < 0 || table > 55) {
        /* table_p could be uninitialized as no valid table id was
         * input, initialize it to a valid value of 0 before returning */
        *table_p = 0;
        return xasprintf("%s: table must in range 0...55", arg);
    }
    *table_p = table;
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
br_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist,
                   const struct ovnbrrec_bridge **br_p)
{
    const struct ovsdb_idl_row *row = NULL;

    char *error = ctl_get_row(ctx, &ovnbrrec_table_bridge,
                              id, must_exist, &row);
    *br_p = (const struct ovnbrrec_bridge *) row;
    return error;
}

static void
cmd_br_add(struct ctl_context *ctx)
{
    const struct ovnbrrec_bridge *bridge = NULL;

    char *error = br_by_name_or_uuid(ctx, ctx->argv[1], false, &bridge);
    if (error) {
        ctl_error(ctx, "%s", error);
        free(error);
        return;
    }

    if (bridge) {
        ctl_error(ctx, "Bridge %s already exists", ctx->argv[1]);
    }

    bridge = ovnbrrec_bridge_insert(ctx->txn);
    ovnbrrec_bridge_set_name(bridge, ctx->argv[1]);
}

static void
cmd_br_del(struct ctl_context *ctx)
{
    const struct ovnbrrec_bridge *bridge = NULL;

    char *error = br_by_name_or_uuid(ctx, ctx->argv[1], true, &bridge);
    if (error) {
        ctl_error(ctx, "%s", error);
        free(error);
        return;
    }

    ovnbrrec_bridge_delete(bridge);
}

static void
cmd_lflow_list(struct ctl_context *ctx)
{
    struct vector lflows = VECTOR_EMPTY_INITIALIZER(struct brctl_lflow);
    const struct ovnbrrec_bridge *bridge = NULL;

    if (ctx->argc > 1) {
        char *error = br_by_name_or_uuid(ctx, ctx->argv[1], false, &bridge);
        if (error) {
            ctl_error(ctx, "%s", error);
            free(error);
            return;
        }

        if (bridge) {
            ctx->argc--;
            ctx->argv++;
        }
    }

    const struct ovnbrrec_logical_flow *lflow;
    OVNBRREC_LOGICAL_FLOW_FOR_EACH (lflow, ctx->idl) {
        if (bridge && lflow->bridge != bridge) {
            continue;
        }

        brctl_lflow_add(&lflows, lflow, lflow->bridge);
    }

    vector_qsort(&lflows, brctl_lflow_cmp);

    bool print_uuid = shash_find(&ctx->options, "--uuid") != NULL;

    const struct brctl_lflow *curr, *prev = NULL;
    VECTOR_FOR_EACH_PTR (&lflows, curr) {
        /* Figure out whether to print this particular flow.  By default, we
         * print all flows, but if any UUIDs were listed on the command line
         * then we only print the matching ones. */
        bool include;
        if (ctx->argc > 1) {
            include = false;
            for (size_t j = 1; j < ctx->argc; j++) {
                if (is_partial_uuid_match(&curr->lflow->header_.uuid,
                                          ctx->argv[j])) {
                    include = true;
                    break;
                }
            }
        } else {
            include = true;
        }
        if (!include) {
            continue;
        }

        /* Print a header line for this datapath or pipeline, if we haven't
         * already done so. */
        if (!prev || prev->br != curr->br) {
               print_bridge_prompt(curr->br, &curr->br->header_.uuid,
                                     &ctx->output);
        }

        /* Print the flow. */
        ds_put_cstr(&ctx->output, "  ");
        print_uuid_part(&curr->lflow->header_.uuid, print_uuid, &ctx->output);
        ds_put_format(&ctx->output,
                      "table=%-2"PRId64", priority=%-5"PRId64
                      ", match=(%s), action=(%s)\n",
                      curr->lflow->table_id,
                      curr->lflow->priority, curr->lflow->match,
                      curr->lflow->actions);
        prev = curr;
    }

    vector_destroy(&lflows);
}

static void
cmd_lflow_add(struct ctl_context *ctx)
{
    const struct ovnbrrec_bridge *bridge = NULL;

    char *error = br_by_name_or_uuid(ctx, ctx->argv[1], true, &bridge);
    if (error) {
        ctl_error(ctx, "%s", error);
        free(error);
        return;
    }

    int64_t table_id;
    error = parse_table_id(ctx->argv[2], &table_id);
    if (error) {
        ctx->error = error;
        return;
    }

    int64_t priority;
    error = parse_priority(ctx->argv[3], &priority);
    if (error) {
        ctx->error = error;
        return;
    }

    struct ovnbrrec_logical_flow *lflow =
        ovnbrrec_logical_flow_insert(ctx->txn);
    ovnbrrec_logical_flow_set_bridge(lflow, bridge);
    ovnbrrec_logical_flow_set_table_id(lflow, table_id);
    ovnbrrec_logical_flow_set_priority(lflow, priority);
    ovnbrrec_logical_flow_set_match(lflow, ctx->argv[4]);
    ovnbrrec_logical_flow_set_actions(lflow, ctx->argv[5]);
}

static void
cmd_lflow_del(struct ctl_context *ctx)
{
    const struct ovnbrrec_logical_flow *lflow;
    const struct ovsdb_idl_row *row;

    char *error = ctl_get_row(ctx, &ovnbrrec_table_logical_flow,
                              ctx->argv[1], true, &row);
    if (error) {
        ctl_error(ctx, "%s", error);
        free(error);
        return;
    }

    lflow = (const struct ovnbrrec_logical_flow *) row;
    ovnbrrec_logical_flow_delete(lflow);
}

static void
cmd_lflows_del(struct ctl_context *ctx)
{
    const struct ovnbrrec_bridge *bridge = NULL;

    if (ctx->argc > 1) {
        char *error = br_by_name_or_uuid(ctx, ctx->argv[1], true, &bridge);
        if (error) {
            ctl_error(ctx, "%s", error);
            free(error);
            return;
        }
    }

    const struct ovnbrrec_logical_flow *lflow;
    OVNBRREC_LOGICAL_FLOW_FOR_EACH_SAFE (lflow, ctx->idl) {
        if (!bridge || lflow->bridge == bridge) {
            ovnbrrec_logical_flow_delete(lflow);
        }
    }
}

static const struct ctl_command_syntax brctl_commands[] = {
    { "init", 0, 0, "", NULL, brctl_init, NULL, "", RW },
    { "show", 0, 1, "[BRIDGE]", brctl_pre_show, brctl_show, NULL, "", RO },

    /* Bridge commands. */
    {"add-br", 1, 1, "BRIDGE", pre_get_info, cmd_br_add, NULL,
     "", RW},
    {"del-br", 1, 1, "BRIDGE", pre_get_info, cmd_br_del, NULL,
     "", RW},

    /* Logical flow commands */
    {"lflow-list", 0, INT_MAX, "[BRIDGE] [LFLOW...]",
     pre_get_info, cmd_lflow_list, NULL,
     "--uuid,--ovs?,--stats,--vflows?", RO},
    {"dump-flows", 0, INT_MAX, "[DATAPATH] [LFLOW...]",
     pre_get_info, cmd_lflow_list, NULL,
     "--uuid,--ovs?,--stats,--vflows?",
     RO}, /* Friendly alias for lflow-list */
    {"add-flow", 5, 5, "BRIDGE TABLE PRIORITY MATCH ACTION",
     pre_get_info, cmd_lflow_add, NULL,
     "", RW},
     {"del-flow", 1, 1, "UUID", pre_get_info, cmd_lflow_del, NULL,
     "", RW},
     {"del-flows", 0, 1, "[BRIDGE]", pre_get_info, cmd_lflows_del, NULL,
     "", RW},
     {NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, RO},
};

static void
brctl_usage(void)
{
    printf("\
%s: OVN Provider DB management utility\n\
usage: %s [OPTIONS] COMMAND [ARG...]\n\
\n\
General commands:\n\
  init                      initialize the database\n\
  show                      print overview of database contents\n\
\n\
Logical flow commands:\n\
  lflow-list  [BRIDGE] [LFLOW...] list logical flows for BRIDGE\n\
  dump-flows  [BRIDGE] [LFLOW...] alias for lflow-list\n\
\n\
\n\n", program_name, program_name);
}

int
main(int argc, char *argv[])
{
    struct ovn_dbctl_options dbctl_options = {
        .db_version = ovnbrrec_get_db_version(),
        .default_db = default_br_db(),
        .allow_wait = false,

        .options_env_var_name = "OVN_brctl_OPTIONS",
        .daemon_env_var_name = "OVN_PR_DAEMON",

        .idl_class = &ovnbrrec_idl_class,
        .tables = tables,
        .cmd_show_table = NULL,
        .commands = brctl_commands,

        .usage = brctl_usage,
        .add_base_prerequisites = brctl_add_base_prerequisites,
        .pre_execute = brctl_pre_execute,
        .post_execute = NULL,
        .get_inactivity_probe = get_inactivity_probe,

        .ctx_create = brctl_ctx_create,
        .ctx_destroy = brctl_ctx_destroy,
    };

    return ovn_dbctl_main(argc, argv, &dbctl_options);
}
