/*
 * Copyright (c) 2015, 2016, 2017 Nicira, Inc.
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

#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "colors.h"
#include "command-line.h"
#include "compiler.h"
#include "db-ctl-base.h"
#include "daemon.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "jsonrpc.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/shash.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "memory.h"
#include "ovn-dbctl.h"
#include "ovsdb-data.h"
#include "ovsdb-idl.h"
#include "openvswitch/poll-loop.h"
#include "process.h"
#include "simap.h"
#include "sset.h"
#include "stream-ssl.h"
#include "stream.h"
#include "table.h"
#include "timer.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "svec.h"

VLOG_DEFINE_THIS_MODULE(sbctl);

static void
sbctl_add_base_prerequisites(struct ovsdb_idl *idl,
                             enum nbctl_wait_type wait_type OVS_UNUSED)
{
    ovsdb_idl_add_table(idl, &sbrec_table_sb_global);
}

static void
sbctl_pre_execute(struct ovsdb_idl *idl, struct ovsdb_idl_txn *txn,
                  enum nbctl_wait_type wait_type OVS_UNUSED)
{
    const struct sbrec_sb_global *sb = sbrec_sb_global_first(idl);
    if (!sb) {
        /* XXX add verification that table is empty */
        sb = sbrec_sb_global_insert(txn);
    }
}

static void
sbctl_usage(void)
{
    printf("\
%s: OVN southbound DB management utility\n\
\n\
usage: %s [OPTIONS] COMMAND [ARG...]\n\
\n\
General commands:\n\
  show                        print overview of database contents\n\
\n\
Chassis commands:\n\
  chassis-add CHASSIS ENCAP-TYPE ENCAP-IP  create a new chassis named\n\
                                           CHASSIS with ENCAP-TYPE tunnels\n\
                                           and ENCAP-IP\n\
  chassis-del CHASSIS         delete CHASSIS and all of its encaps\n\
                              and gateway_ports\n\
\n\
Port binding commands:\n\
  lsp-bind PORT CHASSIS       bind logical port PORT to CHASSIS\n\
  lsp-unbind PORT             reset the port binding of logical port PORT\n\
\n\
Logical flow commands:\n\
  lflow-list [DATAPATH] [LFLOW...] List logical flows for DATAPATH\n\
  dump-flows [DATAPATH] [LFLOW...] Alias for lflow-list\n\
\n\
Connection commands:\n\
  get-connection             print the connections\n\
  del-connection             delete the connections\n\
  [--inactivity-probe=MSECS]\n\
  set-connection TARGET...   set the list of connections to TARGET...\n\
\n\
SSL commands:\n\
  get-ssl                     print the SSL configuration\n\
  del-ssl                     delete the SSL configuration\n\
  set-ssl PRIV-KEY CERT CA-CERT [SSL-PROTOS [SSL-CIPHERS]] \
set the SSL configuration\n\
\n\
%s\
%s\
\n\
Options:\n\
  --db=DATABASE               connect to DATABASE\n\
                              (default: %s)\n\
  --no-leader-only            accept any cluster member, not just the leader\n\
  -t, --timeout=SECS          wait at most SECS seconds\n\
  --dry-run                   do not commit changes to database\n\
  --oneline                   print exactly one line of output per command\n",
           program_name, program_name, ctl_get_db_cmd_usage(),
           ctl_list_db_tables_usage(), default_sb_db());
    table_usage();
    vlog_usage();
    printf("\
  --no-syslog             equivalent to --verbose=sbctl:syslog:warn\n");
    printf("\n\
Other options:\n\
  -h, --help                  display this help message\n\
  -V, --version               display version information\n");
    stream_usage("database", true, true, true);
    exit(EXIT_SUCCESS);
}

/* One should not use ctl_fatal() within commands because it will kill the
 * daemon if we're in daemon mode.  Use ctl_error() instead and return
 * gracefully.  */
#define ctl_fatal dont_use_ctl_fatal_use_ctl_error_and_return

/* ovs-sbctl specific context.  Inherits the 'struct ctl_context' as base. */
struct sbctl_context {
    struct ctl_context base;

    /* A cache of the contents of the database.
     *
     * A command that needs to use any of this information must first call
     * sbctl_context_populate_cache().  A command that changes anything that
     * could invalidate the cache must either call
     * sbctl_context_invalidate_cache() or manually update the cache to
     * maintain its correctness. */
    bool cache_valid;
    /* Maps from chassis name to struct sbctl_chassis. */
    struct shash chassis;
    /* Maps from lport name to struct sbctl_port_binding. */
    struct shash port_bindings;
};

/* Casts 'base' into 'struct sbctl_context'. */
static struct sbctl_context *
sbctl_context_cast(struct ctl_context *base)
{
    return CONTAINER_OF(base, struct sbctl_context, base);
}

struct sbctl_chassis {
    const struct sbrec_chassis *ch_cfg;
};

struct sbctl_port_binding {
    const struct sbrec_port_binding *bd_cfg;
};

static void
sbctl_context_invalidate_cache(struct ctl_context *ctx)
{
    struct sbctl_context *sbctl_ctx = sbctl_context_cast(ctx);

    if (!sbctl_ctx->cache_valid) {
        return;
    }
    sbctl_ctx->cache_valid = false;
    shash_destroy_free_data(&sbctl_ctx->chassis);
    shash_destroy_free_data(&sbctl_ctx->port_bindings);
}

/* Casts 'base' into 'struct sbctl_context' and initializes it if needed. */
static struct sbctl_context *
sbctl_context_get(struct ctl_context *ctx)
{
    struct sbctl_context *sbctl_ctx
        = CONTAINER_OF(ctx, struct sbctl_context, base);
    if (sbctl_ctx->cache_valid) {
        return sbctl_ctx;
    }

    const struct sbrec_chassis *chassis_rec;
    const struct sbrec_port_binding *port_binding_rec;
    struct sset chassis, port_bindings;

    sbctl_ctx->cache_valid = true;
    shash_init(&sbctl_ctx->chassis);
    shash_init(&sbctl_ctx->port_bindings);
    sset_init(&chassis);
    SBREC_CHASSIS_FOR_EACH(chassis_rec, ctx->idl) {
        struct sbctl_chassis *ch;

        if (!sset_add(&chassis, chassis_rec->name)) {
            VLOG_WARN("database contains duplicate chassis name (%s)",
                      chassis_rec->name);
            continue;
        }

        ch = xmalloc(sizeof *ch);
        ch->ch_cfg = chassis_rec;
        shash_add(&sbctl_ctx->chassis, chassis_rec->name, ch);
    }
    sset_destroy(&chassis);

    sset_init(&port_bindings);
    SBREC_PORT_BINDING_FOR_EACH(port_binding_rec, ctx->idl) {
        struct sbctl_port_binding *bd;

        if (!sset_add(&port_bindings, port_binding_rec->logical_port)) {
            VLOG_WARN("database contains duplicate port binding for logical "
                      "port (%s)",
                      port_binding_rec->logical_port);
            continue;
        }

        bd = xmalloc(sizeof *bd);
        bd->bd_cfg = port_binding_rec;
        shash_add(&sbctl_ctx->port_bindings, port_binding_rec->logical_port,
                  bd);
    }
    sset_destroy(&port_bindings);

    return sbctl_ctx;
}

static struct ctl_context *
sbctl_ctx_create(void)
{
    struct sbctl_context *sbctx = xmalloc(sizeof *sbctx);
    *sbctx = (struct sbctl_context) {
        .cache_valid = false,
    };
    return &sbctx->base;
}

static void
sbctl_ctx_destroy(struct ctl_context *ctx)
{
    sbctl_context_invalidate_cache(ctx);
    free(ctx);
}

static struct sbctl_chassis *
find_chassis(struct ctl_context *ctx, const char *name, bool must_exist)
{
    struct sbctl_context *sbctl_ctx = sbctl_context_get(ctx);
    struct sbctl_chassis *sbctl_ch = shash_find_data(&sbctl_ctx->chassis,
                                                     name);
    if (must_exist && !sbctl_ch) {
        ctl_error(ctx, "no chassis named %s", name);
    }

    return sbctl_ch;
}

static struct sbctl_port_binding *
find_port_binding(struct ctl_context *ctx, const char *name, bool must_exist)
{
    struct sbctl_context *sbctl_ctx = sbctl_context_get(ctx);
    struct sbctl_port_binding *bd = shash_find_data(&sbctl_ctx->port_bindings,
                                                    name);
    if (must_exist && !bd) {
        ctl_error(&sbctl_ctx->base, "no port named %s", name);
    }

    return bd;
}

static void
pre_get_info(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &sbrec_chassis_col_name);
    ovsdb_idl_add_column(ctx->idl, &sbrec_chassis_col_encaps);

    ovsdb_idl_add_column(ctx->idl, &sbrec_encap_col_type);
    ovsdb_idl_add_column(ctx->idl, &sbrec_encap_col_ip);

    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_logical_port);
    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_tunnel_key);
    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_chassis);
    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_datapath);
    ovsdb_idl_add_column(ctx->idl, &sbrec_port_binding_col_up);

    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_logical_datapath);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_logical_dp_group);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_pipeline);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_actions);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_priority);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_table_id);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_match);
    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_flow_col_external_ids);

    ovsdb_idl_add_column(ctx->idl, &sbrec_logical_dp_group_col_datapaths);

    ovsdb_idl_add_column(ctx->idl, &sbrec_datapath_binding_col_external_ids);

    ovsdb_idl_add_column(ctx->idl, &sbrec_ip_multicast_col_datapath);
    ovsdb_idl_add_column(ctx->idl, &sbrec_ip_multicast_col_seq_no);

    ovsdb_idl_add_column(ctx->idl, &sbrec_multicast_group_col_name);
    ovsdb_idl_add_column(ctx->idl, &sbrec_multicast_group_col_datapath);
    ovsdb_idl_add_column(ctx->idl, &sbrec_multicast_group_col_tunnel_key);
    ovsdb_idl_add_column(ctx->idl, &sbrec_multicast_group_col_ports);

    ovsdb_idl_add_column(ctx->idl, &sbrec_mac_binding_col_datapath);
    ovsdb_idl_add_column(ctx->idl, &sbrec_mac_binding_col_logical_port);
    ovsdb_idl_add_column(ctx->idl, &sbrec_mac_binding_col_ip);
    ovsdb_idl_add_column(ctx->idl, &sbrec_mac_binding_col_mac);

    ovsdb_idl_add_column(ctx->idl, &sbrec_load_balancer_col_datapaths);
    ovsdb_idl_add_column(ctx->idl, &sbrec_load_balancer_col_vips);
    ovsdb_idl_add_column(ctx->idl, &sbrec_load_balancer_col_name);
    ovsdb_idl_add_column(ctx->idl, &sbrec_load_balancer_col_protocol);
}

static struct cmd_show_table cmd_show_tables[] = {
    {&sbrec_table_chassis,
     &sbrec_chassis_col_name,
     {&sbrec_chassis_col_hostname,
      &sbrec_chassis_col_encaps,
      NULL},
     {&sbrec_table_port_binding,
      &sbrec_port_binding_col_logical_port,
      &sbrec_port_binding_col_chassis}},

    {&sbrec_table_encap,
     &sbrec_encap_col_type,
     {&sbrec_encap_col_ip,
      &sbrec_encap_col_options,
      NULL},
     {NULL, NULL, NULL}},

    {NULL, NULL, {NULL, NULL, NULL}, {NULL, NULL, NULL}},
};

static void
sbctl_init(struct ctl_context *ctx OVS_UNUSED)
{
}

static void
cmd_chassis_add(struct ctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    const char *ch_name, *encap_types, *encap_ip;

    ch_name = ctx->argv[1];
    encap_types = ctx->argv[2];
    encap_ip = ctx->argv[3];

    if (find_chassis(ctx, ch_name, false)) {
        if (may_exist) {
            return;
        }
    }

    struct sbctl_context *sbctl_ctx = sbctl_context_get(ctx);
    if (shash_find(&sbctl_ctx->chassis, ch_name)) {
        if (!may_exist) {
            ctl_error(ctx, "cannot create a chassis named %s because a "
                      "chassis named %s already exists", ch_name, ch_name);
        }
        return;
    }

    struct sset encap_set;
    sset_from_delimited_string(&encap_set, encap_types, ",");

    size_t n_encaps = sset_count(&encap_set);
    struct sbrec_encap **encaps = xmalloc(n_encaps * sizeof *encaps);
    const struct smap options = SMAP_CONST1(&options, "csum", "true");
    const char *encap_type;
    int i = 0;
    SSET_FOR_EACH (encap_type, &encap_set){
        encaps[i] = sbrec_encap_insert(ctx->txn);

        sbrec_encap_set_type(encaps[i], encap_type);
        sbrec_encap_set_ip(encaps[i], encap_ip);
        sbrec_encap_set_options(encaps[i], &options);
        sbrec_encap_set_chassis_name(encaps[i], ch_name);
        i++;
    }
    sset_destroy(&encap_set);

    struct sbrec_chassis *ch = sbrec_chassis_insert(ctx->txn);
    sbrec_chassis_set_name(ch, ch_name);
    sbrec_chassis_set_encaps(ch, encaps, n_encaps);
    free(encaps);

    sbctl_context_invalidate_cache(ctx);
}

static void
cmd_chassis_del(struct ctl_context *ctx)
{
    struct sbctl_context *sbctl_ctx = sbctl_context_cast(ctx);
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct sbctl_chassis *sbctl_ch;

    sbctl_ch = find_chassis(ctx, ctx->argv[1], must_exist);
    if (sbctl_ch) {
        if (sbctl_ch->ch_cfg) {
            size_t i;

            for (i = 0; i < sbctl_ch->ch_cfg->n_encaps; i++) {
                sbrec_encap_delete(sbctl_ch->ch_cfg->encaps[i]);
            }
            sbrec_chassis_delete(sbctl_ch->ch_cfg);
        }
        shash_find_and_delete(&sbctl_ctx->chassis, ctx->argv[1]);
        free(sbctl_ch);
    }
}

static void
cmd_lsp_bind(struct ctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    struct sbctl_chassis *sbctl_ch;
    struct sbctl_port_binding *sbctl_bd;
    char *lport_name, *ch_name;
    bool up = true;

    /* port_binding must exist, chassis must exist! */
    lport_name = ctx->argv[1];
    ch_name = ctx->argv[2];

    sbctl_bd = find_port_binding(ctx, lport_name, true);
    if (!sbctl_bd) {
        return;
    }
    sbctl_ch = find_chassis(ctx, ch_name, true);
    if (!sbctl_ch) {
        return;
    }

    if (sbctl_bd->bd_cfg->chassis) {
        if (!may_exist || sbctl_bd->bd_cfg->chassis != sbctl_ch->ch_cfg) {
            ctl_error(ctx, "lport (%s) has already been binded to chassis (%s)",
                      lport_name, sbctl_bd->bd_cfg->chassis->name);
        }
        return;
    }
    sbrec_port_binding_set_chassis(sbctl_bd->bd_cfg, sbctl_ch->ch_cfg);
    sbrec_port_binding_set_up(sbctl_bd->bd_cfg, &up, 1);
    sbctl_context_invalidate_cache(ctx);
}

static void
cmd_lsp_unbind(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct sbctl_port_binding *sbctl_bd;
    char *lport_name;

    lport_name = ctx->argv[1];
    sbctl_bd = find_port_binding(ctx, lport_name, must_exist);
    if (sbctl_bd) {
        sbrec_port_binding_set_chassis(sbctl_bd->bd_cfg, NULL);
        sbrec_port_binding_set_up(sbctl_bd->bd_cfg, NULL, 0);
    }
}

enum {
    PL_INGRESS,
    PL_EGRESS,
};

/* Help ensure we catch any future pipeline values */
static int
pipeline_encode(const char *pl)
{
    if (!strcmp(pl, "ingress")) {
        return PL_INGRESS;
    } else if (!strcmp(pl, "egress")) {
        return PL_EGRESS;
    }

    OVS_NOT_REACHED();
}

struct sbctl_lflow {
    const struct sbrec_logical_flow *lflow;
    const struct sbrec_datapath_binding *dp;
};

static int
sbctl_lflow_cmp(const void *a_, const void *b_)
{
    const struct sbctl_lflow *a_ctl_lflow = a_;
    const struct sbctl_lflow *b_ctl_lflow = b_;

    const struct sbrec_logical_flow *a = a_ctl_lflow->lflow;
    const struct sbrec_logical_flow *b = b_ctl_lflow->lflow;

    const struct sbrec_datapath_binding *adb = a_ctl_lflow->dp;
    const struct sbrec_datapath_binding *bdb = b_ctl_lflow->dp;
    const char *a_name = smap_get_def(&adb->external_ids, "name", "");
    const char *b_name = smap_get_def(&bdb->external_ids, "name", "");
    int cmp = strcmp(a_name, b_name);
    if (cmp) {
        return cmp;
    }

    cmp = uuid_compare_3way(&adb->header_.uuid, &bdb->header_.uuid);
    if (cmp) {
        return cmp;
    }

    int a_pipeline = pipeline_encode(a->pipeline);
    int b_pipeline = pipeline_encode(b->pipeline);
    cmp = (a_pipeline > b_pipeline ? 1
           : a_pipeline < b_pipeline ? -1
           : a->table_id > b->table_id ? 1
           : a->table_id < b->table_id ? -1
           : a->priority > b->priority ? -1
           : a->priority < b->priority ? 1
           : strcmp(a->match, b->match));
    return cmp ? cmp : strcmp(a->actions, b->actions);
}

static bool
is_uuid_with_prefix(const char *uuid)
{
     return uuid[0] == '0' && (uuid[1] == 'x' || uuid[1] == 'X');
}

static bool
parse_partial_uuid(char *s)
{
    /* Accept a full or partial UUID. */
    if (uuid_is_partial_string(s)) {
        return true;
    }

    /* Accept a full or partial UUID prefixed by 0x, since "ovs-ofctl
     * dump-flows" prints cookies prefixed by 0x. */
    if (is_uuid_with_prefix(s) && uuid_is_partial_string(s + 2)) {
        return true;
    }

    /* Not a (partial) UUID. */
    return false;
}

static const char *
strip_leading_zero(const char *s)
{
    return s + strspn(s, "0");
}

static bool
is_partial_uuid_match(const struct uuid *uuid, const char *match)
{
    char uuid_s[UUID_LEN + 1];
    snprintf(uuid_s, sizeof uuid_s, UUID_FMT, UUID_ARGS(uuid));

    /* We strip leading zeros because we want to accept cookie values derived
     * from UUIDs, and cookie values are printed without leading zeros because
     * they're just numbers. */
    const char *s1 = strip_leading_zero(uuid_s);
    const char *s2 = match;
    if (is_uuid_with_prefix(s2)) {
        s2 = s2 + 2;
    }
    s2 = strip_leading_zero(s2);
    return !strncmp(s1, s2, strlen(s2));
}

static char *
default_ovs(void)
{
    return xasprintf("unix:%s/br-int.mgmt", ovs_rundir());
}

static struct vconn *
sbctl_open_vconn(struct shash *options)
{
    struct shash_node *ovs = shash_find(options, "--ovs");
    if (!ovs) {
        return NULL;
    }

    char *remote = ovs->data ? xstrdup(ovs->data) : default_ovs();
    struct vconn *vconn;
    int retval = vconn_open_block(remote, 1 << OFP15_VERSION, 0, -1, &vconn);
    if (retval) {
        VLOG_WARN("%s: connection failed (%s)", remote, ovs_strerror(retval));
    }
    free(remote);
    return vconn;
}

static void
sbctl_dump_openflow(struct vconn *vconn, const struct uuid *uuid, bool stats,
                    struct ds *s)
{
    struct ofputil_flow_stats_request fsr = {
        .cookie = htonll(uuid->parts[0]),
        .cookie_mask = OVS_BE64_MAX,
        .out_port = OFPP_ANY,
        .out_group = OFPG_ANY,
        .table_id = OFPTT_ALL,
    };

    struct ofputil_flow_stats *fses;
    size_t n_fses;
    int error = vconn_dump_flows(vconn, &fsr, OFPUTIL_P_OF15_OXM,
                                 &fses, &n_fses);
    if (error) {
        VLOG_WARN("%s: error obtaining flow stats (%s)",
                  vconn_get_name(vconn), ovs_strerror(error));
        return;
    }

    if (n_fses) {
        for (size_t i = 0; i < n_fses; i++) {
            const struct ofputil_flow_stats *fs = &fses[i];

            ds_put_cstr(s, "    ");
            if (stats) {
                ofputil_flow_stats_format(s, fs, NULL, NULL, true);
            } else {
                ds_put_format(s, "%stable=%s%"PRIu8" ",
                              colors.special, colors.end, fs->table_id);
                match_format(&fs->match, NULL, s, OFP_DEFAULT_PRIORITY);
                if (ds_last(s) != ' ') {
                    ds_put_char(s, ' ');
                }

                ds_put_format(s, "%sactions=%s", colors.actions, colors.end);
                struct ofpact_format_params fp = { .s = s };
                ofpacts_format(fs->ofpacts, fs->ofpacts_len, &fp);
            }
            ds_put_char(s, '\n');
        }
    }

    for (size_t i = 0; i < n_fses; i++) {
        free(CONST_CAST(struct ofpact *, fses[i].ofpacts));
    }
    free(fses);
}

static void
print_datapath_name(const struct sbrec_datapath_binding *dp, struct ds *s)
{
    const struct smap *ids = &dp->external_ids;
    const char *name = smap_get(ids, "name");
    const char *name2 = smap_get(ids, "name2");
    if (name && name2) {
        ds_put_format(s, "\"%s\" aka \"%s\"", name, name2);
    } else if (name || name2) {
        ds_put_format(s, "\"%s\"", name ? name : name2);
    }
}

static void
print_vflow_datapath_name(const struct sbrec_datapath_binding *dp,
                          bool do_print, struct ds *s)
{
    if (!do_print) {
        return;
    }
    ds_put_cstr(s, "datapath=");
    print_datapath_name(dp, s);
    ds_put_cstr(s, ", ");
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
cmd_lflow_list_port_bindings(struct ctl_context *ctx, struct vconn *vconn,
                             const struct sbrec_datapath_binding *datapath,
                             bool stats, bool print_uuid)
{
    const struct sbrec_port_binding *pb;
    const struct sbrec_port_binding *pb_prev = NULL;
    SBREC_PORT_BINDING_FOR_EACH (pb, ctx->idl) {

        if (datapath && pb->datapath != datapath) {
            continue;
        }

        if (!pb_prev) {
            ds_put_cstr(&ctx->output, "\nPort Bindings:\n");
        }

        ds_put_cstr(&ctx->output, "  ");
        print_uuid_part(&pb->header_.uuid, print_uuid, &ctx->output);
        print_vflow_datapath_name(pb->datapath, !datapath, &ctx->output);
        ds_put_format(&ctx->output,
                      "logical_port=%s, tunnel_key=%-5"PRId64"\n",
                      pb->logical_port, pb->tunnel_key);
        if (vconn) {
            sbctl_dump_openflow(vconn, &pb->header_.uuid, stats, &ctx->output);
        }

        pb_prev = pb;
    }
}

static void
cmd_lflow_list_mac_bindings(struct ctl_context *ctx, struct vconn *vconn,
                            const struct sbrec_datapath_binding *datapath,
                            bool stats, bool print_uuid)
{
    const struct sbrec_mac_binding *mb;
    const struct sbrec_mac_binding *mb_prev = NULL;
    SBREC_MAC_BINDING_FOR_EACH (mb, ctx->idl) {
        if (datapath && mb->datapath != datapath) {
            continue;
        }

        if (!mb_prev) {
            ds_put_cstr(&ctx->output, "\nMAC Bindings:\n");
        }

        ds_put_cstr(&ctx->output, "  ");
        print_uuid_part(&mb->header_.uuid, print_uuid, &ctx->output);
        print_vflow_datapath_name(mb->datapath, !datapath, &ctx->output);

        ds_put_format(&ctx->output, "logical_port=%s, ip=%s, mac=%s\n",
               mb->logical_port, mb->ip, mb->mac);
        if (vconn) {
            sbctl_dump_openflow(vconn, &mb->header_.uuid, stats, &ctx->output);
        }

        mb_prev = mb;
    }
}

static void
cmd_lflow_list_mc_groups(struct ctl_context *ctx, struct vconn *vconn,
                         const struct sbrec_datapath_binding *datapath,
                         bool stats, bool print_uuid)
{
    const struct sbrec_multicast_group *mc;
    const struct sbrec_multicast_group *mc_prev = NULL;
    SBREC_MULTICAST_GROUP_FOR_EACH (mc, ctx->idl) {
        if (datapath && mc->datapath != datapath) {
            continue;
        }

        if (!mc_prev) {
            ds_put_cstr(&ctx->output, "\nMC Groups:\n");
        }

        ds_put_cstr(&ctx->output, "  ");
        print_uuid_part(&mc->header_.uuid, print_uuid, &ctx->output);
        print_vflow_datapath_name(mc->datapath, !datapath, &ctx->output);

        ds_put_format(&ctx->output, "name=%s, tunnel_key=%-5"PRId64", ports=(",
                      mc->name, mc->tunnel_key);
        for (size_t i = 0; i < mc->n_ports; i++) {
            ds_put_cstr(&ctx->output, mc->ports[i]->logical_port);
            if (i != mc->n_ports - 1) {
                ds_put_cstr(&ctx->output, ", ");
            }
        }
        ds_put_cstr(&ctx->output, ")\n");

        if (vconn) {
            sbctl_dump_openflow(vconn, &mc->header_.uuid, stats, &ctx->output);
        }

        mc_prev = mc;
    }
}

static void
cmd_lflow_list_chassis(struct ctl_context *ctx, struct vconn *vconn,
                       bool stats, bool print_uuid)
{
    const struct sbrec_chassis *chassis;
    const struct sbrec_chassis *chassis_prev = NULL;
    SBREC_CHASSIS_FOR_EACH (chassis, ctx->idl) {
        if (!chassis_prev) {
            ds_put_cstr(&ctx->output, "\nChassis:\n");
        }

        ds_put_cstr(&ctx->output, "  ");
        print_uuid_part(&chassis->header_.uuid, print_uuid, &ctx->output);

        ds_put_format(&ctx->output, "name=%s\n", chassis->name);
        if (vconn) {
            sbctl_dump_openflow(vconn, &chassis->header_.uuid, stats,
                                &ctx->output);
        }

        chassis_prev = chassis;
    }
}

static void
cmd_lflow_list_load_balancers(struct ctl_context *ctx, struct vconn *vconn,
                              const struct sbrec_datapath_binding *datapath,
                              bool stats, bool print_uuid)
{
    const struct sbrec_load_balancer *lb;
    const struct sbrec_load_balancer *lb_prev = NULL;
    SBREC_LOAD_BALANCER_FOR_EACH (lb, ctx->idl) {
        bool dp_found = false;
        if (datapath) {
            size_t i;
            for (i = 0; i < lb->n_datapaths; i++) {
                if (datapath == lb->datapaths[i]) {
                    dp_found = true;
                    break;
                }
            }
            if (!dp_found) {
                continue;
            }
        }

        if (!lb_prev) {
            ds_put_cstr(&ctx->output, "\nLoad Balancers:\n");
        }

        ds_put_cstr(&ctx->output, "  ");
        print_uuid_part(&lb->header_.uuid, print_uuid, &ctx->output);
        ds_put_format(&ctx->output, "name=\"%s\", protocol=\"%s\", ",
                      lb->name, lb->protocol);
        if (!dp_found) {
            for (size_t i = 0; i < lb->n_datapaths; i++) {
                print_vflow_datapath_name(lb->datapaths[i], true,
                                          &ctx->output);
            }
        }

        ds_put_cstr(&ctx->output, "\n  vips:\n");
        struct smap_node *node;
        SMAP_FOR_EACH (node, &lb->vips) {
            ds_put_format(&ctx->output, "    %s = %s\n",
                          node->key, node->value);
        }
        ds_put_cstr(&ctx->output, "\n");

        if (vconn) {
            sbctl_dump_openflow(vconn, &lb->header_.uuid, stats, &ctx->output);
        }

        lb_prev = lb;
    }
}

static bool
datapath_group_contains_datapath(const struct sbrec_logical_dp_group *g,
                                 const struct sbrec_datapath_binding *dp)
{
    if (!g || !dp) {
        return false;
    }
    for (size_t i = 0; i < g->n_datapaths; i++) {
        if (g->datapaths[i] == dp) {
            return true;
        }
    }
    return false;
}

static void
sbctl_lflow_add(struct sbctl_lflow **lflows,
                size_t *n_flows, size_t *n_capacity,
                const struct sbrec_logical_flow *lflow,
                const struct sbrec_datapath_binding *dp)
{
    if (*n_flows == *n_capacity) {
        *lflows = x2nrealloc(*lflows, n_capacity, sizeof **lflows);
    }
    (*lflows)[*n_flows].lflow = lflow;
    (*lflows)[*n_flows].dp = dp;
    (*n_flows)++;
}

static void
cmd_lflow_list(struct ctl_context *ctx)
{
    const struct sbrec_datapath_binding *datapath = NULL;
    if (ctx->argc > 1) {
        const struct ovsdb_idl_row *row;
        char *error = ctl_get_row(ctx, &sbrec_table_datapath_binding,
                                  ctx->argv[1], false, &row);
        if (error) {
            ctl_error(ctx, "%s", error);
            free(error);
            return;
        }

        datapath = (const struct sbrec_datapath_binding *)row;
        if (datapath) {
            ctx->argc--;
            ctx->argv++;
        }
    }

    for (size_t i = 1; i < ctx->argc; i++) {
        if (!parse_partial_uuid(ctx->argv[i])) {
            ctl_error(ctx, "%s is not a UUID or the beginning of a UUID",
                      ctx->argv[i]);
            return;
        }
    }

    struct vconn *vconn = sbctl_open_vconn(&ctx->options);
    bool stats = shash_find(&ctx->options, "--stats") != NULL;

    struct sbctl_lflow *lflows = NULL;
    size_t n_flows = 0;
    size_t n_capacity = 0;
    const struct sbrec_logical_flow *lflow;
    const struct sbrec_logical_dp_group *dp_group;
    SBREC_LOGICAL_FLOW_FOR_EACH (lflow, ctx->idl) {
        if (datapath
            && lflow->logical_datapath != datapath
            && !datapath_group_contains_datapath(lflow->logical_dp_group,
                                                 datapath)) {
            continue;
        }
        if (datapath) {
            sbctl_lflow_add(&lflows, &n_flows, &n_capacity, lflow, datapath);
            continue;
        }
        if (lflow->logical_datapath) {
            sbctl_lflow_add(&lflows, &n_flows, &n_capacity,
                            lflow, lflow->logical_datapath);
        }
        dp_group = lflow->logical_dp_group;
        for (size_t i = 0; dp_group && i < dp_group->n_datapaths; i++) {
            sbctl_lflow_add(&lflows, &n_flows, &n_capacity,
                            lflow, dp_group->datapaths[i]);
        }
    }

    if (n_flows) {
        qsort(lflows, n_flows, sizeof *lflows, sbctl_lflow_cmp);
    }

    bool print_uuid = shash_find(&ctx->options, "--uuid") != NULL;

    const struct sbctl_lflow *curr, *prev = NULL;
    for (size_t i = 0; i < n_flows; i++) {
        curr = &lflows[i];

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
        if (!prev
            || prev->dp != curr->dp
            || strcmp(prev->lflow->pipeline, curr->lflow->pipeline)) {
            ds_put_cstr(&ctx->output, "Datapath: ");
            print_datapath_name(curr->dp, &ctx->output);
            ds_put_format(&ctx->output, " ("UUID_FMT")  Pipeline: %s\n",
                          UUID_ARGS(&curr->dp->header_.uuid),
                          curr->lflow->pipeline);
        }

        /* Print the flow. */
        ds_put_cstr(&ctx->output, "  ");
        print_uuid_part(&curr->lflow->header_.uuid, print_uuid, &ctx->output);
        ds_put_format(&ctx->output,
                      "table=%-2"PRId64"(%-19s), priority=%-5"PRId64
                      ", match=(%s), action=(%s)\n",
                      curr->lflow->table_id,
                      smap_get_def(&curr->lflow->external_ids,
                                   "stage-name", ""),
                      curr->lflow->priority, curr->lflow->match,
                      curr->lflow->actions);
        if (vconn) {
            sbctl_dump_openflow(vconn, &curr->lflow->header_.uuid, stats,
                                &ctx->output);
        }
        prev = curr;
    }

    bool vflows = shash_find(&ctx->options, "--vflows") != NULL;
    if (vflows) {
        cmd_lflow_list_port_bindings(ctx, vconn, datapath, stats, print_uuid);
        cmd_lflow_list_mac_bindings(ctx, vconn, datapath, stats, print_uuid);
        cmd_lflow_list_mc_groups(ctx, vconn, datapath, stats, print_uuid);
        cmd_lflow_list_chassis(ctx, vconn, stats, print_uuid);
        cmd_lflow_list_load_balancers(ctx, vconn, datapath, stats, print_uuid);
    }

    vconn_close(vconn);
    free(lflows);
}

static void
sbctl_ip_mcast_flush_switch(struct ctl_context *ctx,
                            const struct sbrec_datapath_binding *dp)
{
    const struct sbrec_ip_multicast *ip_mcast;

    /* Lookup the corresponding IP_Multicast entry. */
    SBREC_IP_MULTICAST_FOR_EACH (ip_mcast, ctx->idl) {
        if (ip_mcast->datapath != dp) {
            continue;
        }

        sbrec_ip_multicast_set_seq_no(ip_mcast, ip_mcast->seq_no + 1);
    }
}

static void
sbctl_ip_mcast_flush(struct ctl_context *ctx)
{
    const struct sbrec_datapath_binding *dp;

    if (ctx->argc > 2) {
        return;
    }

    if (ctx->argc == 2) {
        const struct ovsdb_idl_row *row;
        char *error = ctl_get_row(ctx, &sbrec_table_datapath_binding,
                                  ctx->argv[1], false, &row);
        if (error) {
            ctl_error(ctx, "%s", error);
            free(error);
            return;
        }

        dp = (const struct sbrec_datapath_binding *)row;
        if (!dp) {
            ctl_error(ctx, "%s is not a valid datapath", ctx->argv[1]);
            return;
        }

        sbctl_ip_mcast_flush_switch(ctx, dp);
    } else {
        SBREC_DATAPATH_BINDING_FOR_EACH (dp, ctx->idl) {
            sbctl_ip_mcast_flush_switch(ctx, dp);
        }
    }
}

static void
verify_connections(struct ctl_context *ctx)
{
    const struct sbrec_sb_global *sb_global = sbrec_sb_global_first(ctx->idl);
    const struct sbrec_connection *conn;

    sbrec_sb_global_verify_connections(sb_global);

    SBREC_CONNECTION_FOR_EACH(conn, ctx->idl) {
        sbrec_connection_verify_target(conn);
    }
}

static void
pre_connection(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &sbrec_sb_global_col_connections);
    ovsdb_idl_add_column(ctx->idl, &sbrec_connection_col_target);
    ovsdb_idl_add_column(ctx->idl, &sbrec_connection_col_read_only);
    ovsdb_idl_add_column(ctx->idl, &sbrec_connection_col_role);
    ovsdb_idl_add_column(ctx->idl, &sbrec_connection_col_inactivity_probe);
}

static void
cmd_get_connection(struct ctl_context *ctx)
{
    const struct sbrec_connection *conn;
    struct svec targets;
    size_t i;

    verify_connections(ctx);

    /* Print the targets in sorted order for reproducibility. */
    svec_init(&targets);

    SBREC_CONNECTION_FOR_EACH(conn, ctx->idl) {
        char *s;

        s = xasprintf("%s role=\"%s\" %s",
                      conn->read_only ? "read-only" : "read-write",
                      conn->role,
                      conn->target);
        svec_add(&targets, s);
        free(s);
    }

    svec_sort_unique(&targets);
    for (i = 0; i < targets.n; i++) {
        ds_put_format(&ctx->output, "%s\n", targets.names[i]);
    }
    svec_destroy(&targets);
}

static void
delete_connections(struct ctl_context *ctx)
{
    const struct sbrec_sb_global *sb_global = sbrec_sb_global_first(ctx->idl);
    const struct sbrec_connection *conn, *next;

    /* Delete Manager rows pointed to by 'connection_options' column. */
    SBREC_CONNECTION_FOR_EACH_SAFE(conn, next, ctx->idl) {
        sbrec_connection_delete(conn);
    }

    /* Delete 'Manager' row refs in 'manager_options' column. */
    sbrec_sb_global_set_connections(sb_global, NULL, 0);
}

static void
cmd_del_connection(struct ctl_context *ctx)
{
    verify_connections(ctx);
    delete_connections(ctx);
}

static void
insert_connections(struct ctl_context *ctx, char *targets[], size_t n)
{
    const struct sbrec_sb_global *sb_global = sbrec_sb_global_first(ctx->idl);
    struct sbrec_connection **connections;
    size_t i, conns=0;
    bool read_only = false;
    char *role = "";
    const char *inactivity_probe = shash_find_data(&ctx->options,
                                                   "--inactivity-probe");

    /* Insert each connection in a new row in Connection table. */
    connections = xmalloc(n * sizeof *connections);
    for (i = 0; i < n; i++) {
        if (!strcmp(targets[i], "read-only")) {
            read_only = true;
            continue;
        } else if (!strcmp(targets[i], "read-write")) {
            read_only = false;
            continue;
        } else if (!strncmp(targets[i], "role=", 5)) {
            role = targets[i] + 5;
            continue;
        } else if (stream_verify_name(targets[i]) &&
                   pstream_verify_name(targets[i])) {
            VLOG_WARN("target type \"%s\" is possibly erroneous", targets[i]);
        }

        connections[conns] = sbrec_connection_insert(ctx->txn);
        sbrec_connection_set_target(connections[conns], targets[i]);
        sbrec_connection_set_read_only(connections[conns], read_only);
        sbrec_connection_set_role(connections[conns], role);
        if (inactivity_probe) {
            int64_t msecs = atoll(inactivity_probe);
            sbrec_connection_set_inactivity_probe(connections[conns],
                                                  &msecs, 1);
        }
        conns++;
    }

    /* Store uuids of new connection rows in 'connection' column. */
    sbrec_sb_global_set_connections(sb_global, connections, conns);
    free(connections);
}

static void
cmd_set_connection(struct ctl_context *ctx)
{
    const size_t n = ctx->argc - 1;

    verify_connections(ctx);
    delete_connections(ctx);
    insert_connections(ctx, &ctx->argv[1], n);
}

static void
pre_cmd_get_ssl(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &sbrec_sb_global_col_ssl);

    ovsdb_idl_add_column(ctx->idl, &sbrec_ssl_col_private_key);
    ovsdb_idl_add_column(ctx->idl, &sbrec_ssl_col_certificate);
    ovsdb_idl_add_column(ctx->idl, &sbrec_ssl_col_ca_cert);
    ovsdb_idl_add_column(ctx->idl, &sbrec_ssl_col_bootstrap_ca_cert);
}

static void
cmd_get_ssl(struct ctl_context *ctx)
{
    const struct sbrec_sb_global *sb_global = sbrec_sb_global_first(ctx->idl);
    const struct sbrec_ssl *ssl = sbrec_ssl_first(ctx->idl);

    sbrec_sb_global_verify_ssl(sb_global);
    if (ssl) {
        sbrec_ssl_verify_private_key(ssl);
        sbrec_ssl_verify_certificate(ssl);
        sbrec_ssl_verify_ca_cert(ssl);
        sbrec_ssl_verify_bootstrap_ca_cert(ssl);

        ds_put_format(&ctx->output, "Private key: %s\n", ssl->private_key);
        ds_put_format(&ctx->output, "Certificate: %s\n", ssl->certificate);
        ds_put_format(&ctx->output, "CA Certificate: %s\n", ssl->ca_cert);
        ds_put_format(&ctx->output, "Bootstrap: %s\n",
                ssl->bootstrap_ca_cert ? "true" : "false");
    }
}

static void
pre_cmd_del_ssl(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &sbrec_sb_global_col_ssl);
}

static void
cmd_del_ssl(struct ctl_context *ctx)
{
    const struct sbrec_sb_global *sb_global = sbrec_sb_global_first(ctx->idl);
    const struct sbrec_ssl *ssl = sbrec_ssl_first(ctx->idl);

    if (ssl) {
        sbrec_sb_global_verify_ssl(sb_global);
        sbrec_ssl_delete(ssl);
        sbrec_sb_global_set_ssl(sb_global, NULL);
    }
}

static void
pre_cmd_set_ssl(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &sbrec_sb_global_col_ssl);
}

static void
cmd_set_ssl(struct ctl_context *ctx)
{
    bool bootstrap = shash_find(&ctx->options, "--bootstrap");
    const struct sbrec_sb_global *sb_global = sbrec_sb_global_first(ctx->idl);
    const struct sbrec_ssl *ssl = sbrec_ssl_first(ctx->idl);

    sbrec_sb_global_verify_ssl(sb_global);
    if (ssl) {
        sbrec_ssl_delete(ssl);
    }
    ssl = sbrec_ssl_insert(ctx->txn);

    sbrec_ssl_set_private_key(ssl, ctx->argv[1]);
    sbrec_ssl_set_certificate(ssl, ctx->argv[2]);
    sbrec_ssl_set_ca_cert(ssl, ctx->argv[3]);

    sbrec_ssl_set_bootstrap_ca_cert(ssl, bootstrap);

    if (ctx->argc == 5) {
        sbrec_ssl_set_ssl_protocols(ssl, ctx->argv[4]);
    } else if (ctx->argc == 6) {
        sbrec_ssl_set_ssl_protocols(ssl, ctx->argv[4]);
        sbrec_ssl_set_ssl_ciphers(ssl, ctx->argv[5]);
    }

    sbrec_sb_global_set_ssl(sb_global, ssl);
}


static const struct ctl_table_class tables[SBREC_N_TABLES] = {
    [SBREC_TABLE_CHASSIS].row_ids[0] = {&sbrec_chassis_col_name, NULL, NULL},

    [SBREC_TABLE_CHASSIS_PRIVATE].row_ids[0]
    = {&sbrec_chassis_private_col_name, NULL, NULL},

    [SBREC_TABLE_DATAPATH_BINDING].row_ids
     = {{&sbrec_datapath_binding_col_external_ids, "name", NULL},
        {&sbrec_datapath_binding_col_external_ids, "name2", NULL},
        {&sbrec_datapath_binding_col_external_ids, "logical-switch", NULL},
        {&sbrec_datapath_binding_col_external_ids, "logical-router", NULL}},

    [SBREC_TABLE_PORT_BINDING].row_ids
     = {{&sbrec_port_binding_col_logical_port, NULL, NULL},
        {&sbrec_port_binding_col_external_ids, "name", NULL}},

    [SBREC_TABLE_MAC_BINDING].row_ids[0] =
    {&sbrec_mac_binding_col_logical_port, NULL, NULL},

    [SBREC_TABLE_ADDRESS_SET].row_ids[0]
    = {&sbrec_address_set_col_name, NULL, NULL},

    [SBREC_TABLE_PORT_GROUP].row_ids[0]
    = {&sbrec_port_group_col_name, NULL, NULL},

    [SBREC_TABLE_HA_CHASSIS_GROUP].row_ids[0]
    = {&sbrec_ha_chassis_group_col_name, NULL, NULL},

    [SBREC_TABLE_HA_CHASSIS].row_ids[0]
    = {&sbrec_ha_chassis_col_chassis, NULL, NULL},

    [SBREC_TABLE_METER].row_ids[0]
    = {&sbrec_meter_col_name, NULL, NULL},

    [SBREC_TABLE_SERVICE_MONITOR].row_ids[0]
    = {&sbrec_service_monitor_col_logical_port, NULL, NULL},

    [SBREC_TABLE_DHCP_OPTIONS].row_ids[0]
    = {&sbrec_dhcp_options_col_name, NULL, NULL},

    [SBREC_TABLE_DHCPV6_OPTIONS].row_ids[0]
    = {&sbrec_dhcpv6_options_col_name, NULL, NULL},

    [SBREC_TABLE_CONNECTION].row_ids[0]
    = {&sbrec_connection_col_target, NULL, NULL},

    [SBREC_TABLE_RBAC_ROLE].row_ids[0]
    = {&sbrec_rbac_role_col_name, NULL, NULL},

    [SBREC_TABLE_RBAC_PERMISSION].row_ids[0]
    = {&sbrec_rbac_permission_col_table, NULL, NULL},

    [SBREC_TABLE_GATEWAY_CHASSIS].row_ids[0]
    = {&sbrec_gateway_chassis_col_name, NULL, NULL},

    [SBREC_TABLE_LOAD_BALANCER].row_ids[0]
    = {&sbrec_load_balancer_col_name, NULL, NULL},
};

static const struct ctl_command_syntax sbctl_commands[] = {
    { "init", 0, 0, "", NULL, sbctl_init, NULL, "", RW },

    /* Chassis commands. */
    {"chassis-add", 3, 3, "CHASSIS ENCAP-TYPE ENCAP-IP", pre_get_info,
     cmd_chassis_add, NULL, "--may-exist", RW},
    {"chassis-del", 1, 1, "CHASSIS", pre_get_info, cmd_chassis_del, NULL,
     "--if-exists", RW},

    /* Port binding commands. */
    {"lsp-bind", 2, 2, "PORT CHASSIS", pre_get_info, cmd_lsp_bind, NULL,
     "--may-exist", RW},
    {"lsp-unbind", 1, 1, "PORT", pre_get_info, cmd_lsp_unbind, NULL,
     "--if-exists", RW},

    /* Logical flow commands */
    {"lflow-list", 0, INT_MAX, "[DATAPATH] [LFLOW...]",
     pre_get_info, cmd_lflow_list, NULL,
     "--uuid,--ovs?,--stats,--vflows?", RO},
    {"dump-flows", 0, INT_MAX, "[DATAPATH] [LFLOW...]",
     pre_get_info, cmd_lflow_list, NULL,
     "--uuid,--ovs?,--stats,--vflows?",
     RO}, /* Friendly alias for lflow-list */

    /* IP multicast commands. */
    {"ip-multicast-flush", 0, 1, "SWITCH",
     pre_get_info, sbctl_ip_mcast_flush, NULL, "", RW },

    /* Connection commands. */
    {"get-connection", 0, 0, "", pre_connection, cmd_get_connection, NULL, "", RO},
    {"del-connection", 0, 0, "", pre_connection, cmd_del_connection, NULL, "", RW},
    {"set-connection", 1, INT_MAX, "TARGET...", pre_connection, cmd_set_connection,
     NULL, "--inactivity-probe=", RW},

    /* SSL commands. */
    {"get-ssl", 0, 0, "", pre_cmd_get_ssl, cmd_get_ssl, NULL, "", RO},
    {"del-ssl", 0, 0, "", pre_cmd_del_ssl, cmd_del_ssl, NULL, "", RW},
    {"set-ssl", 3, 5,
        "PRIVATE-KEY CERTIFICATE CA-CERT [SSL-PROTOS [SSL-CIPHERS]]",
        pre_cmd_set_ssl, cmd_set_ssl, NULL, "--bootstrap", RW},

    {NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, RO},
};

int
main(int argc, char *argv[])
{
    struct ovn_dbctl_options dbctl_options = {
        .db_version = sbrec_get_db_version(),
        .default_db = default_sb_db(),
        .allow_wait = false,

        .options_env_var_name = "OVN_SBCTL_OPTIONS",
        .daemon_env_var_name = "OVN_SB_DAEMON",

        .idl_class = &sbrec_idl_class,
        .tables = tables,
        .cmd_show_table = cmd_show_tables,
        .commands = sbctl_commands,

        .usage = sbctl_usage,
        .add_base_prerequisites = sbctl_add_base_prerequisites,
        .pre_execute = sbctl_pre_execute,
        .post_execute = NULL,

        .ctx_create = sbctl_ctx_create,
        .ctx_destroy = sbctl_ctx_destroy,
    };

    return ovn_dbctl_main(argc, argv, &dbctl_options);
}

