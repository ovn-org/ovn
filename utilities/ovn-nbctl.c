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

#include "command-line.h"
#include "daemon.h"
#include "db-ctl-base.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "jsonrpc.h"
#include "openvswitch/json.h"
#include "lib/acl-log.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-util.h"
#include "memory.h"
#include "ovn-dbctl.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "process.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "stream.h"
#include "stream-ssl.h"
#include "svec.h"
#include "table.h"
#include "timeval.h"
#include "timer.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(nbctl);

/* Should we wait (if specified by 'wait_type') even if the commands don't
 * change the database at all? */
static bool force_wait = false;

static void
nbctl_add_base_prerequisites(struct ovsdb_idl *idl,
                             enum nbctl_wait_type wait_type)
{
    force_wait = false;

    ovsdb_idl_add_table(idl, &nbrec_table_nb_global);
    if (wait_type != NBCTL_WAIT_NONE) {
        ovsdb_idl_add_column(idl, &nbrec_nb_global_col_sb_cfg);
        ovsdb_idl_add_column(idl, &nbrec_nb_global_col_sb_cfg_timestamp);
        if (wait_type == NBCTL_WAIT_HV) {
            ovsdb_idl_add_column(idl, &nbrec_nb_global_col_hv_cfg);
            ovsdb_idl_add_column(idl, &nbrec_nb_global_col_hv_cfg_timestamp);
        }
    }
}

static void
nbctl_pre_execute(struct ovsdb_idl *idl, struct ovsdb_idl_txn *txn,
                  enum nbctl_wait_type wait_type)
{
    const struct nbrec_nb_global *nb = nbrec_nb_global_first(idl);
    if (!nb) {
        /* XXX add verification that table is empty */
        nb = nbrec_nb_global_insert(txn);
    }

    /* Deal with potential overflows. */
    if (nb->nb_cfg == LLONG_MAX) {
        nbrec_nb_global_set_nb_cfg(nb, 0);
    }

    if (wait_type != NBCTL_WAIT_NONE) {
        ovsdb_idl_txn_increment(txn, &nb->header_, &nbrec_nb_global_col_nb_cfg,
                                force_wait);
    }
}

static char *
nbctl_post_execute(struct ovsdb_idl *idl, struct ovsdb_idl_txn *txn,
                   enum ovsdb_idl_txn_status status,
                   enum nbctl_wait_type wait_type,
                   const struct timer *wait_timeout, long long int start_time,
                   bool print_wait_time)
{
    if (wait_type == NBCTL_WAIT_NONE) {
        if (force_wait) {
            VLOG_INFO("\"sync\" command has no effect without --wait");
        }
        return NULL;
    }
    if (status == TXN_UNCHANGED) {
        return NULL;
    }

    ovs_assert(status == TXN_SUCCESS);
    int64_t next_cfg = ovsdb_idl_txn_get_increment_new_value(txn);
    ovsdb_idl_enable_reconnect(idl);
    for (;;) {
        ovsdb_idl_run(idl);

        const struct nbrec_nb_global *nb;
        NBREC_NB_GLOBAL_FOR_EACH (nb, idl) {
            int64_t cur_cfg = (wait_type == NBCTL_WAIT_SB
                               ? nb->sb_cfg
                               : MIN(nb->sb_cfg, nb->hv_cfg));
            if (cur_cfg >= next_cfg) {
                if (print_wait_time) {
                    printf("Time spent on processing nb_cfg %"PRId64":\n",
                           next_cfg);

                    long long int nb_timestamp = nb->nb_cfg_timestamp;
                    long long int sb_timestamp = nb->sb_cfg_timestamp;
                    long long int hv_timestamp = nb->hv_cfg_timestamp;
                    printf("\tovn-northd delay before processing:"
                           "\t%lldms\n", nb_timestamp - start_time);
                    printf("\tovn-northd completion:"
                           "\t\t\t%lldms\n", sb_timestamp - start_time);
                    if (wait_type == NBCTL_WAIT_HV) {
                        printf("\tovn-controller(s) completion:"
                               "\t\t%lldms\n", hv_timestamp - start_time);
                    }
                }
                return NULL;
            }
        }
        ovsdb_idl_wait(idl);
        if (wait_timeout) {
            timer_wait(wait_timeout);
        }
        poll_block();
        if (wait_timeout && timer_expired(wait_timeout)) {
            return xstrdup("timeout expired");
        }
    }
}

static char * OVS_WARN_UNUSED_RESULT dhcp_options_get(
    struct ctl_context *ctx, const char *id, bool must_exist,
    const struct nbrec_dhcp_options **);

/* A context for keeping track of which switch/router certain ports are
 * connected to.
 *
 * It is required to track changes that we did within current set of commands
 * because partial updates of sets in database are not reflected in the idl
 * until transaction is committed and updates received from the server. */
struct nbctl_context {
    struct ctl_context base;

    bool context_valid;
    struct shash lsp_to_ls_map;
    struct shash lrp_to_lr_map;
};

static struct ctl_context *
nbctl_ctx_create(void)
{
    struct nbctl_context *nbctx = xmalloc(sizeof *nbctx);
    *nbctx = (struct nbctl_context) {
        .context_valid = false,
        .lsp_to_ls_map = SHASH_INITIALIZER(&nbctx->lsp_to_ls_map),
        .lrp_to_lr_map = SHASH_INITIALIZER(&nbctx->lrp_to_lr_map),
    };
    return &nbctx->base;
}

static void
nbctl_ctx_destroy(struct ctl_context *base)
{
    struct nbctl_context *nbctx
        = CONTAINER_OF(base, struct nbctl_context, base);
    nbctx->context_valid = false;
    shash_destroy(&nbctx->lsp_to_ls_map);
    shash_destroy(&nbctx->lrp_to_lr_map);
    free(nbctx);
}

static void
nbctl_pre_context(struct ctl_context *base)
{
    ovsdb_idl_add_column(base->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(base->idl, &nbrec_logical_switch_col_ports);

    ovsdb_idl_add_column(base->idl, &nbrec_logical_switch_port_col_name);

    ovsdb_idl_add_column(base->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(base->idl, &nbrec_logical_router_col_ports);

    ovsdb_idl_add_column(base->idl, &nbrec_logical_router_port_col_name);
}

/* Casts 'base' into 'struct nbctl_context' and initializes it if needed. */
static struct nbctl_context *
nbctl_context_get(struct ctl_context *base)
{
    struct nbctl_context *nbctx
        = CONTAINER_OF(base, struct nbctl_context, base);
    if (nbctx->context_valid) {
        return nbctx;
    }

    const struct nbrec_logical_switch *ls;
    NBREC_LOGICAL_SWITCH_FOR_EACH (ls, base->idl) {
        for (size_t i = 0; i < ls->n_ports; i++) {
            shash_add_once(&nbctx->lsp_to_ls_map, ls->ports[i]->name, ls);
        }
    }

    const struct nbrec_logical_router *lr;
    NBREC_LOGICAL_ROUTER_FOR_EACH (lr, base->idl) {
        for (size_t i = 0; i < lr->n_ports; i++) {
            shash_add_once(&nbctx->lrp_to_lr_map, lr->ports[i]->name, lr);
        }
    }

    nbctx->context_valid = true;
    return nbctx;
}

static void
nbctl_usage(void)
{
    printf("\
%s: OVN northbound DB management utility\n\
usage: %s [OPTIONS] COMMAND [ARG...]\n\
\n\
General commands:\n\
  init                      initialize the database\n\
  show                      print overview of database contents\n\
  show SWITCH               print overview of database contents for SWITCH\n\
  show ROUTER               print overview of database contents for ROUTER\n\
\n\
Logical switch commands:\n\
  ls-add [SWITCH]           create a logical switch named SWITCH\n\
  ls-del SWITCH             delete SWITCH and all its ports\n\
  ls-list                   print the names of all logical switches\n\
\n\
ACL commands:\n\
  [--type={switch | port-group}] [--log] [--severity=SEVERITY] [--name=NAME] [--may-exist]\n\
  acl-add {SWITCH | PORTGROUP} DIRECTION PRIORITY MATCH ACTION\n\
                            add an ACL to SWITCH/PORTGROUP\n\
  [--type={switch | port-group}]\n\
  acl-del {SWITCH | PORTGROUP} [DIRECTION [PRIORITY MATCH]]\n\
                            remove ACLs from SWITCH/PORTGROUP\n\
  [--type={switch | port-group}]\n\
  acl-list {SWITCH | PORTGROUP}\n\
                            print ACLs for SWITCH\n\
\n\
QoS commands:\n\
  qos-add SWITCH DIRECTION PRIORITY MATCH [rate=RATE [burst=BURST]] [dscp=DSCP]\n\
                            add an QoS rule to SWITCH\n\
  qos-del SWITCH [{DIRECTION | UUID} [PRIORITY MATCH]]\n\
                            remove QoS rules from SWITCH\n\
  qos-list SWITCH           print QoS rules for SWITCH\n\
\n\
Meter commands:\n\
  [--fair]\n\
  meter-add NAME ACTION RATE UNIT [BURST]\n\
                            add a meter\n\
  meter-del [NAME]          remove meters\n\
  meter-list                print meters\n\
\n\
Logical switch port commands:\n\
  lsp-add SWITCH PORT       add logical port PORT on SWITCH\n\
  lsp-add SWITCH PORT PARENT TAG\n\
                            add logical port PORT on SWITCH with PARENT\n\
                            on TAG\n\
  lsp-del PORT              delete PORT from its attached switch\n\
  lsp-list SWITCH           print the names of all logical ports on SWITCH\n\
  lsp-get-parent PORT       get the parent of PORT if set\n\
  lsp-get-tag PORT          get the PORT's tag if set\n\
  lsp-set-addresses PORT [ADDRESS]...\n\
                            set MAC or MAC+IP addresses for PORT.\n\
  lsp-get-addresses PORT    get a list of MAC or MAC+IP addresses on PORT\n\
  lsp-set-port-security PORT [ADDRS]...\n\
                            set port security addresses for PORT.\n\
  lsp-get-port-security PORT    get PORT's port security addresses\n\
  lsp-get-up PORT           get state of PORT ('up' or 'down')\n\
  lsp-set-enabled PORT STATE\n\
                            set administrative state PORT\n\
                            ('enabled' or 'disabled')\n\
  lsp-get-enabled PORT      get administrative state PORT\n\
                            ('enabled' or 'disabled')\n\
  lsp-set-type PORT TYPE    set the type for PORT\n\
  lsp-get-type PORT         get the type for PORT\n\
  lsp-set-options PORT KEY=VALUE [KEY=VALUE]...\n\
                            set options related to the type of PORT\n\
  lsp-get-options PORT      get the type specific options for PORT\n\
  lsp-set-dhcpv4-options PORT [DHCP_OPTIONS_UUID]\n\
                            set dhcpv4 options for PORT\n\
  lsp-get-dhcpv4-options PORT  get the dhcpv4 options for PORT\n\
  lsp-set-dhcpv6-options PORT [DHCP_OPTIONS_UUID]\n\
                            set dhcpv6 options for PORT\n\
  lsp-get-dhcpv6-options PORT  get the dhcpv6 options for PORT\n\
  lsp-get-ls PORT           get the logical switch which the port belongs to\n\
\n\
Forwarding group commands:\n\
  [--liveness]\n\
  fwd-group-add GROUP SWITCH VIP VMAC PORTS...\n\
                            add a forwarding group on SWITCH\n\
  fwd-group-del GROUP       delete a forwarding group\n\
  fwd-group-list [SWITCH]   print forwarding groups\n\
\n\
Logical router commands:\n\
  lr-add [ROUTER]           create a logical router named ROUTER\n\
  lr-del ROUTER             delete ROUTER and all its ports\n\
  lr-list                   print the names of all logical routers\n\
\n\
Logical router port commands:\n\
  lrp-add ROUTER PORT MAC NETWORK... [peer=PEER]\n\
                            add logical port PORT on ROUTER\n\
  lrp-set-gateway-chassis PORT CHASSIS [PRIORITY]\n\
                            set gateway chassis for port PORT\n\
  lrp-del-gateway-chassis PORT CHASSIS\n\
                            delete gateway chassis from port PORT\n\
  lrp-get-gateway-chassis PORT\n\
                            print the names of all gateway chassis on PORT\n\
                            with PRIORITY\n\
  lrp-del PORT              delete PORT from its attached router\n\
  lrp-list ROUTER           print the names of all ports on ROUTER\n\
  lrp-set-enabled PORT STATE\n\
                            set administrative state PORT\n\
                            ('enabled' or 'disabled')\n\
  lrp-get-enabled PORT      get administrative state PORT\n\
                            ('enabled' or 'disabled')\n\
  lrp-set-redirect-type PORT TYPE\n\
                            set whether redirected packet to gateway chassis\n\
                            of PORT will be encapsulated or not\n\
                            ('overlay' or 'bridged')\n\
  lrp-get-redirect-type PORT\n\
                            get whether redirected packet to gateway chassis\n\
                            of PORT will be encapsulated or not\n\
                            ('overlay' or 'bridged')\n\
\n\
Route commands:\n\
  [--policy=POLICY] [--ecmp] [--ecmp-symmetric-reply] lr-route-add ROUTER \n\
                            PREFIX NEXTHOP [PORT]\n\
                            add a route to ROUTER\n\
  [--policy=POLICY] lr-route-del ROUTER [PREFIX [NEXTHOP [PORT]]]\n\
                            remove routes from ROUTER\n\
  lr-route-list ROUTER      print routes for ROUTER\n\
\n\
Policy commands:\n\
  lr-policy-add ROUTER PRIORITY MATCH ACTION [NEXTHOP,[NEXTHOP,...]] \
[OPTIONS KEY=VALUE ...] \n\
                            add a policy to router\n\
  lr-policy-del ROUTER [{PRIORITY | UUID} [MATCH]]\n\
                            remove policies from ROUTER\n\
  lr-policy-list ROUTER     print policies for ROUTER\n\
\n\
NAT commands:\n\
  [--stateless]\n\
  [--portrange]\n\
  lr-nat-add ROUTER TYPE EXTERNAL_IP LOGICAL_IP [LOGICAL_PORT EXTERNAL_MAC]\n\
                            [EXTERNAL_PORT_RANGE]\n\
                            add a NAT to ROUTER\n\
  lr-nat-del ROUTER [TYPE [IP]]\n\
                            remove NATs from ROUTER\n\
  lr-nat-list ROUTER        print NATs for ROUTER\n\
\n\
LB commands:\n\
  lb-add LB VIP[:PORT] IP[:PORT]... [PROTOCOL]\n\
                            create a load-balancer or add a VIP to an\n\
                            existing load balancer\n\
  lb-del LB [VIP]           remove a load-balancer or just the VIP from\n\
                            the load balancer\n\
  lb-list [LB]              print load-balancers\n\
  lr-lb-add ROUTER LB       add a load-balancer to ROUTER\n\
  lr-lb-del ROUTER [LB]     remove load-balancers from ROUTER\n\
  lr-lb-list ROUTER         print load-balancers\n\
  ls-lb-add SWITCH LB       add a load-balancer to SWITCH\n\
  ls-lb-del SWITCH [LB]     remove load-balancers from SWITCH\n\
  ls-lb-list SWITCH         print load-balancers\n\
\n\
DHCP Options commands:\n\
  dhcp-options-create CIDR [EXTERNAL_IDS]\n\
                           create a DHCP options row with CIDR\n\
  dhcp-options-del DHCP_OPTIONS_UUID\n\
                           delete DHCP_OPTIONS_UUID\n\
  dhcp-options-list        \n\
                           lists the DHCP_Options rows\n\
  dhcp-options-set-options DHCP_OPTIONS_UUID  KEY=VALUE [KEY=VALUE]...\n\
                           set DHCP options for DHCP_OPTIONS_UUID\n\
  dhcp-options-get-options DHCO_OPTIONS_UUID \n\
                           displays the DHCP options for DHCP_OPTIONS_UUID\n\
\n\
Connection commands:\n\
  get-connection             print the connections\n\
  del-connection             delete the connections\n\
  [--inactivity-probe=MSECS]\n\
  set-connection TARGET...   set the list of connections to TARGET...\n\
\n\n",program_name, program_name);
    printf("\
SSL commands:\n\
  get-ssl                     print the SSL configuration\n\
  del-ssl                     delete the SSL configuration\n\
  set-ssl PRIV-KEY CERT CA-CERT [SSL-PROTOS [SSL-CIPHERS]] \
set the SSL configuration\n\
Port group commands:\n\
  pg-add PG [PORTS]           Create port group PG with optional PORTS\n\
  pg-set-ports PG PORTS       Set PORTS on port group PG\n\
  pg-del PG                   Delete port group PG\n\
HA chassis group commands:\n\
  ha-chassis-group-add GRP  Create an HA chassis group GRP\n\
  ha-chassis-group-del GRP  Delete the HA chassis group GRP\n\
  ha-chassis-group-list     List the HA chassis groups\n\
  ha-chassis-group-add-chassis GRP CHASSIS [PRIORITY] Adds an HA\
chassis with optional PRIORITY to the HA chassis group GRP\n\
  ha-chassis-group-remove-chassis GRP CHASSIS Removes the HA chassis\
CHASSIS from the HA chassis group GRP\n\
\n\
%s\
%s\
\n\
Synchronization command (use with --wait=sb|hv):\n\
  sync                     wait even for earlier changes to take effect\n\
\n\
Options:\n\
  --db=DATABASE               connect to DATABASE\n\
                              (default: %s)\n\
  --no-wait, --wait=none      do not wait for OVN reconfiguration (default)\n\
  --no-leader-only            accept any cluster member, not just the leader\n\
  --no-shuffle-remotes        do not shuffle the order of remotes\n\
  --wait=sb                   wait for southbound database update\n\
  --wait=hv                   wait for all chassis to catch up\n\
  --print-wait-time           print time spent on waiting\n\
  -t, --timeout=SECS          wait at most SECS seconds\n\
  --dry-run                   do not commit changes to database\n\
  --oneline                   print exactly one line of output per command\n",
           ctl_get_db_cmd_usage(),
           ctl_list_db_tables_usage(), default_nb_db());
    table_usage();
    daemon_usage();
    vlog_usage();
    printf("\
  --no-syslog             equivalent to --verbose=nbctl:syslog:warn\n");
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

/* Find a logical router given its id. */
static char * OVS_WARN_UNUSED_RESULT
lr_by_name_or_uuid(struct ctl_context *ctx, const char *id,
                   bool must_exist, const struct nbrec_logical_router **lr_p)
{
    const struct nbrec_logical_router *lr = NULL;
    bool is_uuid = false;
    struct uuid lr_uuid;

    *lr_p = NULL;
    if (uuid_from_string(&lr_uuid, id)) {
        is_uuid = true;
        lr = nbrec_logical_router_get_for_uuid(ctx->idl, &lr_uuid);
    }

    if (!lr) {
        const struct nbrec_logical_router *iter;

        NBREC_LOGICAL_ROUTER_FOR_EACH(iter, ctx->idl) {
            if (strcmp(iter->name, id)) {
                continue;
            }
            if (lr) {
                return xasprintf("Multiple logical routers named '%s'.  "
                                 "Use a UUID.", id);
            }
            lr = iter;
        }
    }

    if (!lr && must_exist) {
        return xasprintf("%s: router %s not found",
                         id, is_uuid ? "UUID" : "name");
    }

    *lr_p = lr;
    return NULL;
}

/* Find an Address Set given its id. */
static char * OVS_WARN_UNUSED_RESULT
address_set_by_name_or_uuid(struct ctl_context *ctx,
                            const char *id, bool must_exist,
                            const struct nbrec_address_set **addr_set_p)
{
    const struct nbrec_address_set *addr_set = NULL;
    bool is_uuid = false;
    struct uuid addr_set_uuid;

    *addr_set_p = NULL;
    if (uuid_from_string(&addr_set_uuid, id)) {
        is_uuid = true;
        addr_set = nbrec_address_set_get_for_uuid(ctx->idl, &addr_set_uuid);
    }

    if (!addr_set) {
        const struct nbrec_address_set *iter;

        NBREC_ADDRESS_SET_FOR_EACH (iter, ctx->idl) {
            if (strcmp(iter->name, id)) {
                continue;
            }
            if (addr_set) {
                return xasprintf("Multiple Address Sets named '%s'.  "
                                 "Use a UUID.", id);
            }
            addr_set = iter;
        }
    }

    if (!addr_set && must_exist) {
        return xasprintf("%s: Address Set %s not found",
                         id, is_uuid ? "UUID" : "name");
    }

    *addr_set_p = addr_set;
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
ls_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist,
                   const struct nbrec_logical_switch **ls_p)
{
    const struct nbrec_logical_switch *ls = NULL;
    *ls_p = NULL;

    struct uuid ls_uuid;
    bool is_uuid = uuid_from_string(&ls_uuid, id);
    if (is_uuid) {
        ls = nbrec_logical_switch_get_for_uuid(ctx->idl, &ls_uuid);
    }

    if (!ls) {
        const struct nbrec_logical_switch *iter;

        NBREC_LOGICAL_SWITCH_FOR_EACH(iter, ctx->idl) {
            if (strcmp(iter->name, id)) {
                continue;
            }
            if (ls) {
                return xasprintf("Multiple logical switches named '%s'.  "
                                 "Use a UUID.", id);
            }
            ls = iter;
        }
    }

    if (!ls && must_exist) {
        return xasprintf("%s: switch %s not found",
                         id, is_uuid ? "UUID" : "name");
    }

    *ls_p = ls;
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
lb_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist,
                   const struct nbrec_load_balancer **lb_p)
{
    const struct nbrec_load_balancer *lb = NULL;

    struct uuid lb_uuid;
    bool is_uuid = uuid_from_string(&lb_uuid, id);
    if (is_uuid) {
        lb = nbrec_load_balancer_get_for_uuid(ctx->idl, &lb_uuid);
    }

    if (!lb) {
        const struct nbrec_load_balancer *iter;

        NBREC_LOAD_BALANCER_FOR_EACH(iter, ctx->idl) {
            if (strcmp(iter->name, id)) {
                continue;
            }
            if (lb) {
                return xasprintf("Multiple load balancers named '%s'.  "
                                 "Use a UUID.", id);
            }
            lb = iter;
        }
    }

    if (!lb && must_exist) {
        return xasprintf("%s: load balancer %s not found", id,
                         is_uuid ? "UUID" : "name");
    }

    if (lb_p) {
        *lb_p = lb;
    }
    return NULL;
}

static char * OVS_WARN_UNUSED_RESULT
pg_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist,
                   const struct nbrec_port_group **pg_p)
{
    const struct nbrec_port_group *pg = NULL;
    *pg_p = NULL;

    struct uuid pg_uuid;
    bool is_uuid = uuid_from_string(&pg_uuid, id);
    if (is_uuid) {
        pg = nbrec_port_group_get_for_uuid(ctx->idl, &pg_uuid);
    }

    if (!pg) {
        const struct nbrec_port_group *iter;

        NBREC_PORT_GROUP_FOR_EACH (iter, ctx->idl) {
            if (!strcmp(iter->name, id)) {
                pg = iter;
                break;
            }
        }
    }

    if (!pg && must_exist) {
        return xasprintf("%s: port group %s not found", id,
                         is_uuid ? "UUID" : "name");
    }

    *pg_p = pg;
    return NULL;
}

static void
print_alias(const struct smap *external_ids, const char *key, struct ds *s)
{
    const char *alias = smap_get(external_ids, key);
    if (alias && alias[0]) {
        ds_put_format(s, " (aka %s)", alias);
    }
}

/* gateway_chassis ordering
 *  */
static int
compare_chassis_prio_(const void *gc1_, const void *gc2_)
{
    const struct nbrec_gateway_chassis *const *gc1p = gc1_;
    const struct nbrec_gateway_chassis *const *gc2p = gc2_;
    const struct nbrec_gateway_chassis *gc1 = *gc1p;
    const struct nbrec_gateway_chassis *gc2 = *gc2p;

    int prio_diff = gc2->priority - gc1->priority;
    if (!prio_diff) {
        return strcmp(gc2->name, gc1->name);
    }
    return prio_diff;
}

static const struct nbrec_gateway_chassis **
get_ordered_gw_chassis_prio_list(const struct nbrec_logical_router_port *lrp)
{
    const struct nbrec_gateway_chassis **gcs;
    int i;

    gcs = xmalloc(sizeof *gcs * lrp->n_gateway_chassis);
    for (i = 0; i < lrp->n_gateway_chassis; i++) {
        gcs[i] = lrp->gateway_chassis[i];
    }

    qsort(gcs, lrp->n_gateway_chassis, sizeof *gcs, compare_chassis_prio_);
    return gcs;
}

/* Given pointer to logical router, this routine prints the router
 * information.  */
static void
print_lr(const struct nbrec_logical_router *lr, struct ds *s)
{
    ds_put_format(s, "router "UUID_FMT" (%s)",
                  UUID_ARGS(&lr->header_.uuid), lr->name);
    print_alias(&lr->external_ids, "neutron:router_name", s);
    ds_put_char(s, '\n');

    for (size_t i = 0; i < lr->n_ports; i++) {
        const struct nbrec_logical_router_port *lrp = lr->ports[i];
        ds_put_format(s, "    port %s\n", lrp->name);
        if (lrp->mac) {
            ds_put_cstr(s, "        mac: ");
            ds_put_format(s, "\"%s\"\n", lrp->mac);
        }
        if (lrp->n_networks) {
            ds_put_cstr(s, "        networks: [");
            for (size_t j = 0; j < lrp->n_networks; j++) {
                ds_put_format(s, "%s\"%s\"",
                        j == 0 ? "" : ", ",
                        lrp->networks[j]);
            }
            ds_put_cstr(s, "]\n");
        }

        if (lrp->n_gateway_chassis) {
            const struct nbrec_gateway_chassis **gcs;

            gcs = get_ordered_gw_chassis_prio_list(lrp);
            ds_put_cstr(s, "        gateway chassis: [");
            for (size_t j = 0; j < lrp->n_gateway_chassis; j++) {
                const struct nbrec_gateway_chassis *gc = gcs[j];
                ds_put_format(s, "%s ", gc->chassis_name);
            }
            ds_chomp(s, ' ');
            ds_put_cstr(s, "]\n");
            free(gcs);
        }
    }

    for (size_t i = 0; i < lr->n_nat; i++) {
        const struct nbrec_nat *nat = lr->nat[i];
        ds_put_format(s, "    nat "UUID_FMT"\n",
                  UUID_ARGS(&nat->header_.uuid));
        ds_put_cstr(s, "        external ip: ");
        ds_put_format(s, "\"%s\"\n", nat->external_ip);
        if (nat->external_port_range[0]) {
          ds_put_cstr(s, "        external port(s): ");
          ds_put_format(s, "\"%s\"\n", nat->external_port_range);
        }
        ds_put_cstr(s, "        logical ip: ");
        ds_put_format(s, "\"%s\"\n", nat->logical_ip);
        ds_put_cstr(s, "        type: ");
        ds_put_format(s, "\"%s\"\n", nat->type);
    }
}

static void
print_ls(const struct nbrec_logical_switch *ls, struct ds *s)
{
    ds_put_format(s, "switch "UUID_FMT" (%s)",
                  UUID_ARGS(&ls->header_.uuid), ls->name);
    print_alias(&ls->external_ids, "neutron:network_name", s);
    ds_put_char(s, '\n');

    for (size_t i = 0; i < ls->n_ports; i++) {
        const struct nbrec_logical_switch_port *lsp = ls->ports[i];

        ds_put_format(s, "    port %s", lsp->name);
        print_alias(&lsp->external_ids, "neutron:port_name", s);
        ds_put_char(s, '\n');

        if (lsp->type[0]) {
            ds_put_format(s, "        type: %s\n", lsp->type);
        }
        if (lsp->parent_name) {
            ds_put_format(s, "        parent: %s\n", lsp->parent_name);
        }
        if (lsp->n_tag) {
            ds_put_format(s, "        tag: %"PRIu64"\n", lsp->tag[0]);
        }

        /* Print the addresses, but not if there's just a single "router"
         * address because that's just clutter. */
        if (lsp->n_addresses
            && !(lsp->n_addresses == 1
                 && !strcmp(lsp->addresses[0], "router"))) {
            ds_put_cstr(s, "        addresses: [");
            for (size_t j = 0; j < lsp->n_addresses; j++) {
                ds_put_format(s, "%s\"%s\"",
                        j == 0 ? "" : ", ",
                        lsp->addresses[j]);
            }
            ds_put_cstr(s, "]\n");
        }

        const char *router_port = smap_get(&lsp->options, "router-port");
        if (router_port) {
            ds_put_format(s, "        router-port: %s\n", router_port);
        }
    }
}

static void
nbctl_init(struct ctl_context *ctx OVS_UNUSED)
{
}

static void
nbctl_pre_sync(struct ctl_context *base OVS_UNUSED)
{
    force_wait = true;
}

static void
nbctl_sync(struct ctl_context *ctx OVS_UNUSED)
{
}

static void
nbctl_pre_show(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_external_ids);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_ports);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_external_ids);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_type);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_parent_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_tag);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_addresses);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_options);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_external_ids);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_ports);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_nat);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_mac);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_networks);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_gateway_chassis);

    ovsdb_idl_add_column(ctx->idl, &nbrec_gateway_chassis_col_chassis_name);

    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_external_ip);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_external_port_range);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_logical_ip);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_type);
}

static void
nbctl_show(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;

    if (ctx->argc == 2) {
        char *error = ls_by_name_or_uuid(ctx, ctx->argv[1], false, &ls);
        if (error) {
            ctx->error = error;
            return;
        }
        if (ls) {
            print_ls(ls, &ctx->output);
        }
    } else {
        NBREC_LOGICAL_SWITCH_FOR_EACH(ls, ctx->idl) {
            print_ls(ls, &ctx->output);
        }
    }
    const struct nbrec_logical_router *lr;

    if (ctx->argc == 2) {
        char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], false, &lr);
        if (error) {
            ctx->error = error;
            return;
        }
        if (lr) {
            print_lr(lr, &ctx->output);
        }
    } else {
        NBREC_LOGICAL_ROUTER_FOR_EACH(lr, ctx->idl) {
            print_lr(lr, &ctx->output);
        }
    }
}

static void
nbctl_pre_ls_add(struct ctl_context *ctx)
{
    nbctl_pre_context(ctx);
}

static void
nbctl_ls_add(struct ctl_context *ctx)
{
    const char *ls_name = ctx->argc == 2 ? ctx->argv[1] : NULL;

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    bool add_duplicate = shash_find(&ctx->options, "--add-duplicate") != NULL;
    if (may_exist && add_duplicate) {
        ctl_error(ctx, "--may-exist and --add-duplicate may not be used "
                  "together");
        return;
    }

    if (ls_name) {
        if (!add_duplicate) {
            const struct nbrec_logical_switch *ls;
            NBREC_LOGICAL_SWITCH_FOR_EACH (ls, ctx->idl) {
                if (!strcmp(ls->name, ls_name)) {
                    if (may_exist) {
                        return;
                    }
                    ctl_error(ctx, "%s: a switch with this name already "
                              "exists", ls_name);
                    return;
                }
            }
        }
    } else if (may_exist) {
        ctl_error(ctx, "--may-exist requires specifying a name");
        return;
    } else if (add_duplicate) {
        ctl_error(ctx, "--add-duplicate requires specifying a name");
        return;
    }

    struct nbrec_logical_switch *ls;
    ls = nbrec_logical_switch_insert(ctx->txn);
    if (ls_name) {
        nbrec_logical_switch_set_name(ls, ls_name);
    }
}

static void
nbctl_pre_ls_del(struct ctl_context *ctx)
{
    nbctl_pre_context(ctx);
}

static void
nbctl_ls_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct nbctl_context *nbctx = nbctl_context_get(ctx);
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *ls = NULL;

    char *error = ls_by_name_or_uuid(ctx, id, must_exist, &ls);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!ls) {
        return;
    }

    /* Updating runtime cache. */
    for (size_t i = 0; i < ls->n_ports; i++) {
        shash_find_and_delete(&nbctx->lsp_to_ls_map, ls->ports[i]->name);
    }

    nbrec_logical_switch_delete(ls);
}

static void
nbctl_pre_ls_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
}

static void
nbctl_ls_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    struct smap switches;

    smap_init(&switches);
    NBREC_LOGICAL_SWITCH_FOR_EACH(ls, ctx->idl) {
        smap_add_format(&switches, ls->name, UUID_FMT " (%s)",
                        UUID_ARGS(&ls->header_.uuid), ls->name);
    }
    const struct smap_node **nodes = smap_sort(&switches);
    for (size_t i = 0; i < smap_count(&switches); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&switches);
    free(nodes);
}

static char * OVS_WARN_UNUSED_RESULT
lsp_by_name_or_uuid(struct ctl_context *ctx, const char *id,
                    bool must_exist,
                    const struct nbrec_logical_switch_port **lsp_p)
{
    const struct nbrec_logical_switch_port *lsp = NULL;
    *lsp_p = NULL;

    struct uuid lsp_uuid;
    bool is_uuid = uuid_from_string(&lsp_uuid, id);
    if (is_uuid) {
        lsp = nbrec_logical_switch_port_get_for_uuid(ctx->idl, &lsp_uuid);
    }

    if (!lsp) {
        NBREC_LOGICAL_SWITCH_PORT_FOR_EACH(lsp, ctx->idl) {
            if (!strcmp(lsp->name, id)) {
                break;
            }
        }
    }

    if (!lsp && must_exist) {
        return xasprintf("%s: port %s not found",
                         id, is_uuid ? "UUID" : "name");
    }

    *lsp_p = lsp;
    return NULL;
}

/* Returns the logical switch that contains 'lsp'. */
static char * OVS_WARN_UNUSED_RESULT
lsp_to_ls(struct ctl_context *ctx,
          const struct nbrec_logical_switch_port *lsp,
          const struct nbrec_logical_switch **ls_p)
{
    struct nbctl_context *nbctx = nbctl_context_get(ctx);
    const struct nbrec_logical_switch *ls;
    *ls_p = NULL;

    ls = shash_find_data(&nbctx->lsp_to_ls_map, lsp->name);
    if (ls) {
        *ls_p = ls;
        return NULL;
    }
    /* Can't happen because of the database schema */
    return xasprintf("logical port %s is not part of any logical switch",
                     lsp->name);
}

static const char *
ls_get_name(const struct nbrec_logical_switch *ls,
                 char uuid_s[UUID_LEN + 1], size_t uuid_s_size)
{
    if (ls->name[0]) {
        return ls->name;
    }
    snprintf(uuid_s, uuid_s_size, UUID_FMT, UUID_ARGS(&ls->header_.uuid));
    return uuid_s;
}

static void
nbctl_pre_lsp_add(struct ctl_context *ctx)
{
    nbctl_pre_context(ctx);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_ports);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_parent_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_tag_request);
}

static void
nbctl_lsp_add(struct ctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    struct nbctl_context *nbctx = nbctl_context_get(ctx);

    const struct nbrec_logical_switch *ls = NULL;
    char *error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    const char *parent_name;
    int64_t tag;
    if (ctx->argc == 3) {
        parent_name = NULL;
        tag = -1;
    } else if (ctx->argc == 5) {
        /* Validate tag. */
        parent_name = ctx->argv[3];
        if (!ovs_scan(ctx->argv[4], "%"SCNd64, &tag)
            || tag < 0 || tag > 4095) {
            ctl_error(ctx, "%s: invalid tag (must be in range 0 to 4095)",
                      ctx->argv[4]);
            return;
        }
    } else {
        ctl_error(ctx, "lsp-add with parent must also specify a tag");
        return;
    }

    const char *lsp_name = ctx->argv[2];
    const struct nbrec_logical_switch_port *lsp;
    error = lsp_by_name_or_uuid(ctx, lsp_name, false, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (lsp) {
        if (!may_exist) {
            ctl_error(ctx, "%s: a port with this name already exists",
                      lsp_name);
            return;
        }

        const struct nbrec_logical_switch *lsw;
        error = lsp_to_ls(ctx, lsp, &lsw);
        if (error) {
            ctx->error = error;
            return;
        }
        if (lsw != ls) {
            char uuid_s[UUID_LEN + 1];
            ctl_error(ctx, "%s: port already exists but in switch %s",
                      lsp_name, ls_get_name(lsw, uuid_s, sizeof uuid_s));
            return;
        }

        if (parent_name) {
            if (!lsp->parent_name) {
                ctl_error(ctx, "%s: port already exists but has no parent",
                          lsp_name);
                return;
            } else if (strcmp(parent_name, lsp->parent_name)) {
                ctl_error(ctx, "%s: port already exists with different parent "
                          "%s", lsp_name, lsp->parent_name);
                return;
            }

            if (!lsp->n_tag_request) {
                ctl_error(ctx, "%s: port already exists but has no "
                          "tag_request", lsp_name);
                return;
            } else if (lsp->tag_request[0] != tag) {
                ctl_error(ctx, "%s: port already exists with different "
                          "tag_request %"PRId64, lsp_name,
                          lsp->tag_request[0]);
                return;
            }
        } else {
            if (lsp->parent_name) {
                ctl_error(ctx, "%s: port already exists but has parent %s",
                          lsp_name, lsp->parent_name);
                return;
            }
        }

        return;
    }

    /* Create the logical port. */
    lsp = nbrec_logical_switch_port_insert(ctx->txn);
    nbrec_logical_switch_port_set_name(lsp, lsp_name);
    if (tag >= 0) {
        nbrec_logical_switch_port_set_parent_name(lsp, parent_name);
        nbrec_logical_switch_port_set_tag_request(lsp, &tag, 1);
    }

    /* Insert the logical port into the logical switch. */
    nbrec_logical_switch_update_ports_addvalue(ls, lsp);

    /* Updating runtime cache. */
    shash_add(&nbctx->lsp_to_ls_map, lsp_name, ls);
}

static void
nbctl_pre_lsp_del(struct ctl_context *ctx)
{
    nbctl_pre_context(ctx);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_ports);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
}

/* Removes logical switch port 'lsp' from the logical switch 'ls'. */
static void
remove_lsp(struct ctl_context *ctx,
           const struct nbrec_logical_switch *ls,
           const struct nbrec_logical_switch_port *lsp)
{
    struct nbctl_context *nbctx = nbctl_context_get(ctx);

    /* Updating runtime cache. */
    shash_find_and_delete(&nbctx->lsp_to_ls_map, lsp->name);

    /* First remove 'lsp' from the array of ports.  This is what will
     * actually cause the logical port to be deleted when the transaction is
     * sent to the database server (due to garbage collection). */
    nbrec_logical_switch_update_ports_delvalue(ls, lsp);

    /* Delete 'lsp' from the IDL.  This won't have a real effect on the
     * database server (the IDL will suppress it in fact) but it means that it
     * won't show up when we iterate with NBREC_LOGICAL_SWITCH_PORT_FOR_EACH
     * later. */
    nbrec_logical_switch_port_delete(lsp);
}

static void
nbctl_lsp_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, ctx->argv[1], must_exist, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lsp) {
        return;
    }

    /* Find the switch that contains 'lsp', then delete it. */
    const struct nbrec_logical_switch *ls;

    error = lsp_to_ls(ctx, lsp, &ls);
    if (error) {
        ctx->error = error;
        return;
    }
    remove_lsp(ctx, ls, lsp);
}

static void
nbctl_pre_lsp_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_ports);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
}

static void
nbctl_lsp_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch *ls;
    struct smap lsps;
    size_t i;

    char *error = ls_by_name_or_uuid(ctx, id, true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    smap_init(&lsps);
    for (i = 0; i < ls->n_ports; i++) {
        const struct nbrec_logical_switch_port *lsp = ls->ports[i];
        smap_add_format(&lsps, lsp->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lsp->header_.uuid), lsp->name);
    }
    const struct smap_node **nodes = smap_sort(&lsps);
    for (i = 0; i < smap_count(&lsps); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lsps);
    free(nodes);
}

static void
nbctl_pre_lsp_get_parent(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_parent_name);
}

static void
nbctl_lsp_get_parent(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, ctx->argv[1], true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (lsp->parent_name) {
        ds_put_format(&ctx->output, "%s\n", lsp->parent_name);
    }
}

static void
nbctl_pre_lsp_get_tag(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_tag);
}

static void
nbctl_lsp_get_tag(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, ctx->argv[1], true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (lsp->n_tag > 0) {
        ds_put_format(&ctx->output, "%"PRId64"\n", lsp->tag[0]);
    }
}

static void
nbctl_pre_lsp_set_addresses(struct ctl_context *ctx)
{
    nbctl_pre_context(ctx);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_ports);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_addresses);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_switch_port_col_dynamic_addresses);
}

static char *
lsp_contains_duplicate_ip(struct lport_addresses *laddrs1,
                          struct lport_addresses *laddrs2,
                          const struct nbrec_logical_switch_port *lsp_test)
{
    for (size_t i = 0; i < laddrs1->n_ipv4_addrs; i++) {
        for (size_t j = 0; j < laddrs2->n_ipv4_addrs; j++) {
            if (laddrs1->ipv4_addrs[i].addr == laddrs2->ipv4_addrs[j].addr) {
                return xasprintf("duplicate IPv4 address '%s' found on "
                                 "logical switch port '%s'",
                                 laddrs1->ipv4_addrs[i].addr_s,
                                 lsp_test->name);
            }
        }
    }

    for (size_t i = 0; i < laddrs1->n_ipv6_addrs; i++) {
        for (size_t j = 0; j < laddrs2->n_ipv6_addrs; j++) {
            if (IN6_ARE_ADDR_EQUAL(&laddrs1->ipv6_addrs[i].addr,
                                   &laddrs2->ipv6_addrs[j].addr)) {
                return xasprintf("duplicate IPv6 address '%s' found on "
                                 "logical switch port '%s'",
                                 laddrs1->ipv6_addrs[i].addr_s,
                                 lsp_test->name);
            }
        }
    }

    return NULL;
}

static char *
lsp_contains_duplicates(const struct nbrec_logical_switch *ls,
                        const struct nbrec_logical_switch_port *lsp,
                        const char *address)
{
    struct lport_addresses laddrs;
    if (!extract_lsp_addresses(address, &laddrs)) {
        return NULL;
    }

    char *sub_error = NULL;
    for (size_t i = 0; i < ls->n_ports; i++) {
        struct nbrec_logical_switch_port *lsp_test = ls->ports[i];
        if (lsp_test == lsp) {
            continue;
        }
        for (size_t j = 0; j < lsp_test->n_addresses; j++) {
            struct lport_addresses laddrs_test;
            char *addr = lsp_test->addresses[j];
            if (is_dynamic_lsp_address(addr) && lsp_test->dynamic_addresses) {
                addr = lsp_test->dynamic_addresses;
            }
            if (extract_lsp_addresses(addr, &laddrs_test)) {
                sub_error = lsp_contains_duplicate_ip(&laddrs, &laddrs_test,
                                                      lsp_test);
                destroy_lport_addresses(&laddrs_test);
                if (sub_error) {
                    goto err_out;
                }
            }
        }
    }

err_out: ;
    char *error = NULL;
    if (sub_error) {
        error = xasprintf("Error on switch %s: %s", ls->name, sub_error);
        free(sub_error);
    }
    destroy_lport_addresses(&laddrs);
    return error;
}

static void
nbctl_lsp_set_addresses(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }

    const struct nbrec_logical_switch *ls;
    error = lsp_to_ls(ctx, lsp, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    int i;
    for (i = 2; i < ctx->argc; i++) {
        char ipv6_s[IPV6_SCAN_LEN + 1];
        struct eth_addr ea;
        ovs_be32 ip;

        if (strcmp(ctx->argv[i], "unknown") && strcmp(ctx->argv[i], "dynamic")
            && strcmp(ctx->argv[i], "router")
            && !ovs_scan(ctx->argv[i], ETH_ADDR_SCAN_FMT,
                         ETH_ADDR_SCAN_ARGS(ea))
            && !ovs_scan(ctx->argv[i], "dynamic "IPV6_SCAN_FMT, ipv6_s)
            && !ovs_scan(ctx->argv[i], "dynamic "IP_SCAN_FMT,
                         IP_SCAN_ARGS(&ip))) {
            ctl_error(ctx, "%s: Invalid address format. See ovn-nb(5). "
                      "Hint: An Ethernet address must be "
                      "listed before an IP address, together as a single "
                      "argument.", ctx->argv[i]);
            return;
        }

        error = lsp_contains_duplicates(ls, lsp, ctx->argv[i]);
        if (error) {
            ctl_error(ctx, "%s", error);
            free(error);
            return;
        }
    }

    nbrec_logical_switch_port_set_addresses(lsp,
            (const char **) ctx->argv + 2, ctx->argc - 2);
}

static void
nbctl_pre_lsp_get_addresses(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_addresses);
}

static void
nbctl_lsp_get_addresses(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;
    struct svec addresses;
    const char *mac;
    size_t i;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }

    svec_init(&addresses);
    for (i = 0; i < lsp->n_addresses; i++) {
        svec_add(&addresses, lsp->addresses[i]);
    }
    svec_sort(&addresses);
    SVEC_FOR_EACH(i, mac, &addresses) {
        ds_put_format(&ctx->output, "%s\n", mac);
    }
    svec_destroy(&addresses);
}

static void
nbctl_pre_lsp_port_security(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_switch_port_col_port_security);
}

static void
nbctl_lsp_set_port_security(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    nbrec_logical_switch_port_set_port_security(lsp,
            (const char **) ctx->argv + 2, ctx->argc - 2);
}

static void
nbctl_lsp_get_port_security(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;
    struct svec addrs;
    const char *addr;
    size_t i;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    svec_init(&addrs);
    for (i = 0; i < lsp->n_port_security; i++) {
        svec_add(&addrs, lsp->port_security[i]);
    }
    svec_sort(&addrs);
    SVEC_FOR_EACH(i, addr, &addrs) {
        ds_put_format(&ctx->output, "%s\n", addr);
    }
    svec_destroy(&addrs);
}

static void
nbctl_pre_lsp_get_up(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_up);
}

static void
nbctl_lsp_get_up(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    ds_put_format(&ctx->output,
                  "%s\n", (lsp->up && *lsp->up) ? "up" : "down");
}

static void
nbctl_pre_lsp_enabled(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_enabled);
}

static char * OVS_WARN_UNUSED_RESULT
parse_enabled(const char *state, bool *enabled_p)
{
    ovs_assert(enabled_p);

    if (!strcasecmp(state, "enabled")) {
        *enabled_p = true;
    } else if (!strcasecmp(state, "disabled")) {
        *enabled_p = false;
    } else {
        return xasprintf("%s: state must be \"enabled\" or \"disabled\"",
                         state);
    }
    return NULL;
}

static void
nbctl_lsp_set_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *state = ctx->argv[2];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    bool enabled;
    error = parse_enabled(state, &enabled);
    if (error) {
        ctx->error = error;
        return;
    }
    nbrec_logical_switch_port_set_enabled(lsp, &enabled, 1);
}

static void
nbctl_lsp_get_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    ds_put_format(&ctx->output, "%s\n",
                  !lsp->enabled || *lsp->enabled ? "enabled" : "disabled");
}

static void
nbctl_pre_lsp_type(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_type);
}

static void
nbctl_lsp_set_type(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *type = ctx->argv[2];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (ovn_is_known_nb_lsp_type(type)) {
        nbrec_logical_switch_port_set_type(lsp, type);
    } else {
        ctl_error(ctx, "Logical switch port type '%s' is unrecognized. "
                  "Not setting type.", type);
        return;
    }
}

static void
nbctl_lsp_get_type(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    ds_put_format(&ctx->output, "%s\n", lsp->type);
}

static void
nbctl_pre_lsp_options(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_options);
}

static void
nbctl_lsp_set_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;
    size_t i;
    struct smap options = SMAP_INITIALIZER(&options);

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    for (i = 2; i < ctx->argc; i++) {
        char *key, *value;
        value = xstrdup(ctx->argv[i]);
        key = strsep(&value, "=");
        if (value) {
            smap_add(&options, key, value);
        }
        free(key);
    }

    nbrec_logical_switch_port_set_options(lsp, &options);

    smap_destroy(&options);
}

static void
nbctl_lsp_get_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;
    struct smap_node *node;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    SMAP_FOR_EACH(node, &lsp->options) {
        ds_put_format(&ctx->output, "%s=%s\n", node->key, node->value);
    }
}

static void
nbctl_pre_lsp_dhcpv4_options(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_switch_port_col_dhcpv4_options);

    ovsdb_idl_add_column(ctx->idl, &nbrec_dhcp_options_col_cidr);
}

static void
nbctl_lsp_set_dhcpv4_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    const struct nbrec_dhcp_options *dhcp_opt = NULL;
    if (ctx->argc == 3 ) {
        error = dhcp_options_get(ctx, ctx->argv[2], true, &dhcp_opt);
        if (error) {
            ctx->error = error;
            return;
        }
    }

    if (dhcp_opt) {
        ovs_be32 ip;
        unsigned int plen;
        error = ip_parse_cidr(dhcp_opt->cidr, &ip, &plen);
        if (error){
            free(error);
            ctl_error(ctx, "DHCP options cidr '%s' is not IPv4",
                      dhcp_opt->cidr);
            return;
        }
    }
    nbrec_logical_switch_port_set_dhcpv4_options(lsp, dhcp_opt);
}

static void
nbctl_pre_lsp_dhcpv6_options(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_switch_port_col_dhcpv6_options);

    ovsdb_idl_add_column(ctx->idl, &nbrec_dhcp_options_col_cidr);
}

static void
nbctl_lsp_set_dhcpv6_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    const struct nbrec_dhcp_options *dhcp_opt = NULL;
    if (ctx->argc == 3) {
        error = dhcp_options_get(ctx, ctx->argv[2], true, &dhcp_opt);
        if (error) {
            ctx->error = error;
            return;
        }
    }

    if (dhcp_opt) {
        struct in6_addr ip;
        unsigned int plen;
        error = ipv6_parse_cidr(dhcp_opt->cidr, &ip, &plen);
        if (error) {
            free(error);
            ctl_error(ctx, "DHCP options cidr '%s' is not IPv6",
                      dhcp_opt->cidr);
            return;
        }
    }
    nbrec_logical_switch_port_set_dhcpv6_options(lsp, dhcp_opt);
}

static void
nbctl_lsp_get_dhcpv4_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (lsp->dhcpv4_options) {
        ds_put_format(&ctx->output, UUID_FMT " (%s)\n",
                      UUID_ARGS(&lsp->dhcpv4_options->header_.uuid),
                      lsp->dhcpv4_options->cidr);
    }
}

static void
nbctl_lsp_get_dhcpv6_options(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (lsp->dhcpv6_options) {
        ds_put_format(&ctx->output, UUID_FMT " (%s)\n",
                      UUID_ARGS(&lsp->dhcpv6_options->header_.uuid),
                      lsp->dhcpv6_options->cidr);
    }
}

static void
nbctl_pre_lsp_get_ls(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_ports);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
}

static void
nbctl_lsp_get_ls(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_switch_port *lsp = NULL;

    char *error = lsp_by_name_or_uuid(ctx, id, true, &lsp);
    if (error) {
        ctx->error = error;
        return;
    }

    const struct nbrec_logical_switch *ls;
    NBREC_LOGICAL_SWITCH_FOR_EACH(ls, ctx->idl) {
        for (size_t i = 0; i < ls->n_ports; i++) {
            if (ls->ports[i] == lsp) {
                ds_put_format(&ctx->output, UUID_FMT " (%s)\n",
                      UUID_ARGS(&ls->header_.uuid), ls->name);
                break;
            }
        }
    }
}

enum {
    DIR_FROM_LPORT,
    DIR_TO_LPORT
};

static int
dir_encode(const char *dir)
{
    if (!strcmp(dir, "from-lport")) {
        return DIR_FROM_LPORT;
    } else if (!strcmp(dir, "to-lport")) {
        return DIR_TO_LPORT;
    }

    OVS_NOT_REACHED();
}

static int
acl_cmp(const void *acl1_, const void *acl2_)
{
    const struct nbrec_acl *const *acl1p = acl1_;
    const struct nbrec_acl *const *acl2p = acl2_;
    const struct nbrec_acl *acl1 = *acl1p;
    const struct nbrec_acl *acl2 = *acl2p;

    int dir1 = dir_encode(acl1->direction);
    int dir2 = dir_encode(acl2->direction);

    if (dir1 != dir2) {
        return dir1 < dir2 ? -1 : 1;
    } else if (acl1->priority != acl2->priority) {
        return acl1->priority > acl2->priority ? -1 : 1;
    } else {
        return strcmp(acl1->match, acl2->match);
    }
}

static char * OVS_WARN_UNUSED_RESULT
acl_cmd_get_pg_or_ls(struct ctl_context *ctx,
                     const struct nbrec_logical_switch **ls,
                     const struct nbrec_port_group **pg)
{
    const char *opt_type = shash_find_data(&ctx->options, "--type");
    char *error;

    if (!opt_type) {
        error = pg_by_name_or_uuid(ctx, ctx->argv[1], false, pg);
        if (error) {
            return error;
        }
        error = ls_by_name_or_uuid(ctx, ctx->argv[1], false, ls);
        if (error) {
            return error;
        }
        if (*pg && *ls) {
            return xasprintf("Same name '%s' exists in both port-groups and "
                             "logical switches. Specify --type=port-group or "
                             "switch, or use a UUID.", ctx->argv[1]);
        }
        if (!*pg && !*ls) {
            return xasprintf("'%s' is not found for port-group or switch.",
                             ctx->argv[1]);
        }
    } else if (!strcmp(opt_type, "port-group")) {
        error = pg_by_name_or_uuid(ctx, ctx->argv[1], true, pg);
        if (error) {
            return error;
        }
        *ls = NULL;
    } else if (!strcmp(opt_type, "switch")) {
        error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, ls);
        if (error) {
            return error;
        }
        *pg = NULL;
    } else {
        return xasprintf("Invalid value '%s' for option --type", opt_type);
    }

    return NULL;
}

static void
nbctl_acl_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls = NULL;
    const struct nbrec_port_group *pg = NULL;
    const struct nbrec_acl **acls;
    size_t i;

    char *error = acl_cmd_get_pg_or_ls(ctx, &ls, &pg);
    if (error) {
        ctx->error = error;
        return;
    }

    size_t n_acls = pg ? pg->n_acls : ls->n_acls;
    struct nbrec_acl **nb_acls = pg ? pg->acls : ls->acls;

    acls = xmalloc(sizeof *acls * n_acls);
    for (i = 0; i < n_acls; i++) {
        acls[i] = nb_acls[i];
    }

    qsort(acls, n_acls, sizeof *acls, acl_cmp);

    for (i = 0; i < n_acls; i++) {
        const struct nbrec_acl *acl = acls[i];
        ds_put_format(&ctx->output, "%10s %5"PRId64" (%s) %s",
                      acl->direction, acl->priority, acl->match,
                      acl->action);
        if (acl->log) {
            ds_put_cstr(&ctx->output, " log(");
            if (acl->name) {
                ds_put_format(&ctx->output, "name=%s,", acl->name);
            }
            if (acl->severity) {
                ds_put_format(&ctx->output, "severity=%s,", acl->severity);
            }
            if (acl->meter) {
                ds_put_format(&ctx->output, "meter=\"%s\",", acl->meter);
            }
            ds_chomp(&ctx->output, ',');
            ds_put_cstr(&ctx->output, ")");
        }
        ds_put_cstr(&ctx->output, "\n");
    }

    free(acls);
}

static int
qos_cmp(const void *qos1_, const void *qos2_)
{
    const struct nbrec_qos *const *qos1p = qos1_;
    const struct nbrec_qos *const *qos2p = qos2_;
    const struct nbrec_qos *qos1 = *qos1p;
    const struct nbrec_qos *qos2 = *qos2p;

    int dir1 = dir_encode(qos1->direction);
    int dir2 = dir_encode(qos2->direction);

    if (dir1 != dir2) {
        return dir1 < dir2 ? -1 : 1;
    } else if (qos1->priority != qos2->priority) {
        return qos1->priority > qos2->priority ? -1 : 1;
    } else {
        return strcmp(qos1->match, qos2->match);
    }
}

static char * OVS_WARN_UNUSED_RESULT
parse_direction(const char *arg, const char **direction_p)
{
    /* Validate direction.  Only require the first letter. */
    if (arg[0] == 't') {
        *direction_p = "to-lport";
    } else if (arg[0] == 'f') {
        *direction_p = "from-lport";
    } else {
        *direction_p = NULL;
        return xasprintf("%s: direction must be \"to-lport\" or "
                         "\"from-lport\"", arg);
    }
    return NULL;
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

static void
nbctl_pre_acl(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_port_group_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_port_group_col_acls);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_acls);

    ovsdb_idl_add_column(ctx->idl, &nbrec_acl_col_direction);
    ovsdb_idl_add_column(ctx->idl, &nbrec_acl_col_priority);
    ovsdb_idl_add_column(ctx->idl, &nbrec_acl_col_match);
}

static void
nbctl_pre_acl_list(struct ctl_context *ctx)
{
    nbctl_pre_acl(ctx);

    ovsdb_idl_add_column(ctx->idl, &nbrec_acl_col_action);
    ovsdb_idl_add_column(ctx->idl, &nbrec_acl_col_log);
    ovsdb_idl_add_column(ctx->idl, &nbrec_acl_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_acl_col_severity);
    ovsdb_idl_add_column(ctx->idl, &nbrec_acl_col_meter);
}

static void
nbctl_acl_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls = NULL;
    const struct nbrec_port_group *pg = NULL;
    const char *action = ctx->argv[5];

    char *error = acl_cmd_get_pg_or_ls(ctx, &ls, &pg);
    if (error) {
        ctx->error = error;
        return;
    }

    const char *direction;
    error = parse_direction(ctx->argv[2], &direction);
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

    /* Validate action. */
    if (strcmp(action, "allow") && strcmp(action, "allow-related")
        && strcmp(action, "allow-stateless") && strcmp(action, "drop")
        && strcmp(action, "reject")) {
        ctl_error(ctx, "%s: action must be one of \"allow\", "
                  "\"allow-related\", \"allow-stateless\", \"drop\", "
                  "and \"reject\"", action);
        return;
    }

    /* Create the acl. */
    struct nbrec_acl *acl = nbrec_acl_insert(ctx->txn);
    nbrec_acl_set_priority(acl, priority);
    nbrec_acl_set_direction(acl, direction);
    nbrec_acl_set_match(acl, ctx->argv[4]);
    nbrec_acl_set_action(acl, action);

    /* Logging options. */
    bool log = shash_find(&ctx->options, "--log") != NULL;
    const char *severity = shash_find_data(&ctx->options, "--severity");
    const char *name = shash_find_data(&ctx->options, "--name");
    const char *meter = shash_find_data(&ctx->options, "--meter");
    if (log || severity || name || meter) {
        nbrec_acl_set_log(acl, true);
    }
    if (severity) {
        if (log_severity_from_string(severity) == UINT8_MAX) {
            ctl_error(ctx, "bad severity: %s", severity);
            return;
        }
        nbrec_acl_set_severity(acl, severity);
    }
    if (name) {
        nbrec_acl_set_name(acl, name);
    }
    if (meter) {
        nbrec_acl_set_meter(acl, meter);
    }

    /* Check if same acl already exists for the ls/portgroup */
    size_t n_acls = pg ? pg->n_acls : ls->n_acls;
    struct nbrec_acl **acls = pg ? pg->acls : ls->acls;
    for (size_t i = 0; i < n_acls; i++) {
        if (!acl_cmp(&acls[i], &acl)) {
            bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
            if (!may_exist) {
                ctl_error(ctx, "Same ACL already existed on the ls %s.",
                          ctx->argv[1]);
                return;
            }
            return;
        }
    }

    /* Insert the acl into the logical switch/port group. */
    if (pg) {
        nbrec_port_group_update_acls_addvalue(pg, acl);
    } else {
        nbrec_logical_switch_update_acls_addvalue(ls, acl);
    }
}

static void
nbctl_acl_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls = NULL;
    const struct nbrec_port_group *pg = NULL;

    char *error = acl_cmd_get_pg_or_ls(ctx, &ls, &pg);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 2) {
        /* If direction, priority, and match are not specified, delete
         * all ACLs. */
        if (pg) {
            nbrec_port_group_verify_acls(pg);
            nbrec_port_group_set_acls(pg, NULL, 0);
        } else {
            nbrec_logical_switch_verify_acls(ls);
            nbrec_logical_switch_set_acls(ls, NULL, 0);
        }
        return;
    }

    const char *direction;
    error = parse_direction(ctx->argv[2], &direction);
    if (error) {
        ctx->error = error;
        return;
    }

    size_t n_acls = pg ? pg->n_acls : ls->n_acls;
    struct nbrec_acl **acls = pg ? pg->acls : ls->acls;
    /* If priority and match are not specified, delete all ACLs with the
     * specified direction. */
    if (ctx->argc == 3) {
        for (size_t i = 0; i < n_acls; i++) {
            if (!strcmp(direction, acls[i]->direction)) {
                if (pg) {
                    nbrec_port_group_update_acls_delvalue(pg, acls[i]);
                } else {
                    nbrec_logical_switch_update_acls_delvalue(ls, acls[i]);
                }
            }
        }
        return;
    }

    int64_t priority;
    error = parse_priority(ctx->argv[3], &priority);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 4) {
        ctl_error(ctx, "cannot specify priority without match");
        return;
    }

    /* Remove the matching rule. */
    for (size_t i = 0; i < n_acls; i++) {
        struct nbrec_acl *acl = acls[i];

        if (priority == acl->priority && !strcmp(ctx->argv[4], acl->match) &&
             !strcmp(direction, acl->direction)) {
            if (pg) {
                nbrec_port_group_update_acls_delvalue(pg, acl);
            } else {
                nbrec_logical_switch_update_acls_delvalue(ls, acl);
            }
            return;
        }
    }
}

static void
nbctl_pre_qos_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_qos_rules);

    ovsdb_idl_add_column(ctx->idl, &nbrec_qos_col_direction);
    ovsdb_idl_add_column(ctx->idl, &nbrec_qos_col_priority);
    ovsdb_idl_add_column(ctx->idl, &nbrec_qos_col_match);
    ovsdb_idl_add_column(ctx->idl, &nbrec_qos_col_bandwidth);
    ovsdb_idl_add_column(ctx->idl, &nbrec_qos_col_action);
}

static void
nbctl_qos_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    const struct nbrec_qos **qos_rules;
    size_t i;

    char *error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    qos_rules = xmalloc(sizeof *qos_rules * ls->n_qos_rules);
    for (i = 0; i < ls->n_qos_rules; i++) {
        qos_rules[i] = ls->qos_rules[i];
    }

    qsort(qos_rules, ls->n_qos_rules, sizeof *qos_rules, qos_cmp);

    for (i = 0; i < ls->n_qos_rules; i++) {
        const struct nbrec_qos *qos_rule = qos_rules[i];
        ds_put_format(&ctx->output, "%10s %5"PRId64" (%s)",
                      qos_rule->direction, qos_rule->priority,
                      qos_rule->match);
        for (size_t j = 0; j < qos_rule->n_bandwidth; j++) {
            if (!strcmp(qos_rule->key_bandwidth[j], "rate")) {
                ds_put_format(&ctx->output, " rate=%"PRId64"",
                              qos_rule->value_bandwidth[j]);
            }
        }
        for (size_t j = 0; j < qos_rule->n_bandwidth; j++) {
            if (!strcmp(qos_rule->key_bandwidth[j], "burst")) {
                ds_put_format(&ctx->output, " burst=%"PRId64"",
                              qos_rule->value_bandwidth[j]);
            }
        }
        for (size_t j = 0; j < qos_rule->n_action; j++) {
            if (!strcmp(qos_rule->key_action[j], "dscp")) {
                ds_put_format(&ctx->output, " dscp=%"PRId64"",
                              qos_rule->value_action[j]);
            }
        }
        ds_put_cstr(&ctx->output, "\n");
    }

    free(qos_rules);
}

static void
nbctl_pre_qos_add(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_qos_rules);

    ovsdb_idl_add_column(ctx->idl, &nbrec_qos_col_direction);
    ovsdb_idl_add_column(ctx->idl, &nbrec_qos_col_priority);
    ovsdb_idl_add_column(ctx->idl, &nbrec_qos_col_match);
}

static void
nbctl_qos_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    const char *direction;
    int64_t priority;
    int64_t dscp = -1;
    int64_t rate = 0;
    int64_t burst = 0;
    char *error;

    error = parse_direction(ctx->argv[2], &direction);
    if (error) {
        ctx->error = error;
        return;
    }
    error = parse_priority(ctx->argv[3], &priority);
    if (error) {
        ctx->error = error;
        return;
    }
    error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    for (int i = 5; i < ctx->argc; i++) {
        if (!strncmp(ctx->argv[i], "dscp=", 5)) {
            if (!ovs_scan(ctx->argv[i] + 5, "%"SCNd64, &dscp)
                || dscp < 0 || dscp > 63) {
                ctl_error(ctx, "%s: dscp must be in the range 0...63",
                          ctx->argv[i] + 5);
                return;
            }
        }
        else if (!strncmp(ctx->argv[i], "rate=", 5)) {
            if (!ovs_scan(ctx->argv[i] + 5, "%"SCNd64, &rate)
                || rate < 1 || rate > UINT32_MAX) {
                ctl_error(ctx, "%s: rate must be in the range 1...4294967295",
                          ctx->argv[i] + 5);
                return;
            }
        }
        else if (!strncmp(ctx->argv[i], "burst=", 6)) {
            if (!ovs_scan(ctx->argv[i] + 6, "%"SCNd64, &burst)
                || burst < 1 || burst > UINT32_MAX) {
                ctl_error(ctx, "%s: burst must be in the range 1...4294967295",
                          ctx->argv[i] + 6);
                return;
            }
        } else {
            ctl_error(ctx, "%s: supported arguments are \"dscp=\", \"rate=\", "
                      "and \"burst=\"", ctx->argv[i]);
            return;
        }
    }

    /* Validate rate and dscp. */
    if (-1 == dscp && !rate) {
        ctl_error(ctx, "Either \"rate\" and/or \"dscp\" must be specified");
        return;
    }

    /* Create the qos. */
    struct nbrec_qos *qos = nbrec_qos_insert(ctx->txn);
    nbrec_qos_set_priority(qos, priority);
    nbrec_qos_set_direction(qos, direction);
    nbrec_qos_set_match(qos, ctx->argv[4]);
    if (-1 != dscp) {
        const char *dscp_key = "dscp";
        nbrec_qos_set_action(qos, &dscp_key, &dscp, 1);
    }
    if (rate) {
        const char *bandwidth_key[2] = {"rate", "burst"};
        const int64_t bandwidth_value[2] = {rate, burst};
        size_t n_bandwidth = 1;
        if (burst) {
            n_bandwidth = 2;
        }
        nbrec_qos_set_bandwidth(qos, bandwidth_key, bandwidth_value,
                                n_bandwidth);
    }

    /* Check if same qos rule already exists for the ls */
    for (size_t i = 0; i < ls->n_qos_rules; i++) {
        if (!qos_cmp(&ls->qos_rules[i], &qos)) {
            bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
            if (!may_exist) {
                ctl_error(ctx, "Same qos already existed on the ls %s.",
                          ctx->argv[1]);
                return;
            }
            return;
        }
    }

    /* Insert the qos rule the logical switch. */
    nbrec_logical_switch_update_qos_rules_addvalue(ls, qos);
}

static void
nbctl_pre_qos_del(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_qos_rules);

    ovsdb_idl_add_column(ctx->idl, &nbrec_qos_col_direction);
    ovsdb_idl_add_column(ctx->idl, &nbrec_qos_col_priority);
    ovsdb_idl_add_column(ctx->idl, &nbrec_qos_col_match);
}

static void
nbctl_qos_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    char *error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 2) {
        /* If direction, priority, and match are not specified, delete
         * all QoS rules. */
        nbrec_logical_switch_verify_qos_rules(ls);
        nbrec_logical_switch_set_qos_rules(ls, NULL, 0);
        return;
    }

    const char *direction;
    const struct uuid *qos_rule_uuid = NULL;
    struct uuid uuid_from_cmd;
    if (uuid_from_string(&uuid_from_cmd, ctx->argv[2])) {
        qos_rule_uuid = &uuid_from_cmd;
    } else {
        error = parse_direction(ctx->argv[2], &direction);
        if (error) {
            ctx->error = error;
            return;
        }
    }

    /* If uuid was specified, delete qos_rule with the
     * specified uuid. */
    if (ctx->argc == 3) {
        size_t i;

        if (qos_rule_uuid) {
            for (i = 0; i < ls->n_qos_rules; i++) {
                if (uuid_equals(qos_rule_uuid,
                                &(ls->qos_rules[i]->header_.uuid))) {
                    nbrec_logical_switch_update_qos_rules_delvalue(
                        ls, ls->qos_rules[i]);
                    break;
                }
            }
            if (i == ls->n_qos_rules) {
                ctl_error(ctx, "uuid is not found");
            }

        /* If priority and match are not specified, delete all qos_rules
         * with the specified direction. */
        } else {
            for (i = 0; i < ls->n_qos_rules; i++) {
                if (!strcmp(direction, ls->qos_rules[i]->direction)) {
                    nbrec_logical_switch_update_qos_rules_delvalue(
                        ls, ls->qos_rules[i]);
                }
            }
        }
        return;
    }

    if (qos_rule_uuid) {
        ctl_error(ctx, "uuid must be the only argument");
        return;
    }

    int64_t priority;
    error = parse_priority(ctx->argv[3], &priority);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 4) {
        ctl_error(ctx, "cannot specify priority without match");
        return;
    }

    /* Remove the matching rule. */
    for (size_t i = 0; i < ls->n_qos_rules; i++) {
        struct nbrec_qos *qos = ls->qos_rules[i];

        if (priority == qos->priority && !strcmp(ctx->argv[4], qos->match) &&
             !strcmp(direction, qos->direction)) {
            nbrec_logical_switch_update_qos_rules_delvalue(ls, qos);
            return;
        }
    }
}

static int
meter_cmp(const void *meter1_, const void *meter2_)
{
    struct nbrec_meter *const *meter1p = meter1_;
    struct nbrec_meter *const *meter2p = meter2_;
    const struct nbrec_meter *meter1 = *meter1p;
    const struct nbrec_meter *meter2 = *meter2p;

    return strcmp(meter1->name, meter2->name);
}

static void
nbctl_pre_meter_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_meter_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_meter_col_fair);
    ovsdb_idl_add_column(ctx->idl, &nbrec_meter_col_bands);
    ovsdb_idl_add_column(ctx->idl, &nbrec_meter_col_unit);

    ovsdb_idl_add_column(ctx->idl, &nbrec_meter_band_col_action);
    ovsdb_idl_add_column(ctx->idl, &nbrec_meter_band_col_rate);
    ovsdb_idl_add_column(ctx->idl, &nbrec_meter_band_col_burst_size);
}

static void
nbctl_meter_list(struct ctl_context *ctx)
{
    const struct nbrec_meter **meters = NULL;
    const struct nbrec_meter *meter;
    size_t n_capacity = 0;
    size_t n_meters = 0;

    NBREC_METER_FOR_EACH (meter, ctx->idl) {
        if (n_meters == n_capacity) {
            meters = x2nrealloc(meters, &n_capacity, sizeof *meters);
        }

        meters[n_meters] = meter;
        n_meters++;
    }

    if (n_meters) {
        qsort(meters, n_meters, sizeof *meters, meter_cmp);
    }

    for (size_t i = 0; i < n_meters; i++) {
        meter = meters[i];
        ds_put_format(&ctx->output, "%s:", meter->name);
        if (meter->fair) {
            ds_put_format(&ctx->output, " (%s)",
                          *meter->fair ? "fair" : "shared");
        }
        ds_put_format(&ctx->output, " bands:\n");

        for (size_t j = 0; j < meter->n_bands; j++) {
            const struct nbrec_meter_band *band = meter->bands[j];

            ds_put_format(&ctx->output, "  %s: %"PRId64" %s",
                          band->action, band->rate, meter->unit);
            if (band->burst_size) {
                ds_put_format(&ctx->output, ", %"PRId64" %s burst",
                              band->burst_size,
                              !strcmp(meter->unit, "kbps") ? "kb" : "packet" );
            }
        }

        ds_put_cstr(&ctx->output, "\n");
    }

    free(meters);
}

static void
nbctl_pre_meter_add(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_meter_col_name);
}

static void
nbctl_meter_add(struct ctl_context *ctx)
{
    const struct nbrec_meter *meter;

    const char *name = ctx->argv[1];
    NBREC_METER_FOR_EACH (meter, ctx->idl) {
        if (!strcmp(meter->name, name)) {
            ctl_error(ctx, "meter with name \"%s\" already exists", name);
            return;
        }
    }

    if (!strncmp(name, "__", 2)) {
        ctl_error(ctx, "meter names that begin with \"__\" are reserved");
        return;
    }

    const char *action = ctx->argv[2];
    if (strcmp(action, "drop")) {
        ctl_error(ctx, "action must be \"drop\"");
        return;
    }

    int64_t rate;
    if (!ovs_scan(ctx->argv[3], "%"SCNd64, &rate)
        || rate < 1 || rate > UINT32_MAX) {
        ctl_error(ctx, "rate must be in the range 1...4294967295");
        return;
    }

    const char *unit = ctx->argv[4];
    if (strcmp(unit, "kbps") && strcmp(unit, "pktps")) {
        ctl_error(ctx, "unit must be \"kbps\" or \"pktps\"");
        return;
    }

    int64_t burst = 0;
    if (ctx->argc > 5) {
        if (!ovs_scan(ctx->argv[5], "%"SCNd64, &burst)
            || burst < 0 || burst > UINT32_MAX) {
            ctl_error(ctx, "burst must be in the range 0...4294967295");
            return;
        }
    }

    /* Create the band.  We only support adding a single band. */
    struct nbrec_meter_band *band = nbrec_meter_band_insert(ctx->txn);
    nbrec_meter_band_set_action(band, action);
    nbrec_meter_band_set_rate(band, rate);
    nbrec_meter_band_set_burst_size(band, burst);

    /* Create the meter. */
    meter = nbrec_meter_insert(ctx->txn);
    nbrec_meter_set_name(meter, name);
    nbrec_meter_set_unit(meter, unit);
    nbrec_meter_set_bands(meter, &band, 1);

    /* Fair option */
    bool fair = shash_find(&ctx->options, "--fair") != NULL;
    if (fair) {
        nbrec_meter_set_fair(meter, &fair, 1);
    }
}

static void
nbctl_pre_meter_del(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_meter_col_name);
}

static void
nbctl_meter_del(struct ctl_context *ctx)
{
    const struct nbrec_meter *meter, *next;

    /* If a name is not specified, delete all meters. */
    if (ctx->argc == 1) {
        NBREC_METER_FOR_EACH_SAFE (meter, next, ctx->idl) {
            nbrec_meter_delete(meter);
        }
        return;
    }

    /* Remove the matching meter. */
    NBREC_METER_FOR_EACH (meter, ctx->idl) {
        if (strcmp(ctx->argv[1], meter->name)) {
            continue;
        }

        nbrec_meter_delete(meter);
        return;
    }
}

static void
nbctl_pre_lb_add(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_protocol);
    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_vips);
}

static void
nbctl_lb_add(struct ctl_context *ctx)
{
    const char *lb_name = ctx->argv[1];
    const char *lb_vip = ctx->argv[2];
    char *lb_ips = ctx->argv[3];

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    bool add_duplicate = shash_find(&ctx->options, "--add-duplicate") != NULL;
    bool empty_backend_rej = shash_find(&ctx->options, "--reject") != NULL;
    bool empty_backend_event = shash_find(&ctx->options, "--event") != NULL;

    if (empty_backend_event && empty_backend_rej) {
            ctl_error(ctx,
                      "--reject and --event can't specified at the same time");
            return;
    }

    const char *lb_proto;
    bool is_update_proto = false;

    if (ctx->argc == 4) {
        /* Default protocol. */
        lb_proto = "tcp";
    } else {
        /* Validate protocol. */
        lb_proto = ctx->argv[4];
        is_update_proto = true;
        if (strcmp(lb_proto, "tcp") &&
            strcmp(lb_proto, "udp") &&
            strcmp(lb_proto, "sctp")) {
            ctl_error(ctx, "%s: protocol must be one of \"tcp\", \"udp\", "
                      " or \"sctp\".", lb_proto);
            return;
        }
    }

    struct sockaddr_storage ss_vip;
    if (!inet_parse_active(lb_vip, 0, &ss_vip, false)) {
        ctl_error(ctx, "%s: should be an IP address (or an IP address "
                  "and a port number with : as a separator).", lb_vip);
        return;
    }

    struct ds lb_vip_normalized_ds = DS_EMPTY_INITIALIZER;
    uint16_t lb_vip_port = ss_get_port(&ss_vip);
    if (lb_vip_port) {
        ss_format_address(&ss_vip, &lb_vip_normalized_ds);
        ds_put_format(&lb_vip_normalized_ds, ":%d", lb_vip_port);
    } else {
        ss_format_address_nobracks(&ss_vip, &lb_vip_normalized_ds);
    }
    const char *lb_vip_normalized = ds_cstr(&lb_vip_normalized_ds);

    if (!lb_vip_port && is_update_proto) {
        ds_destroy(&lb_vip_normalized_ds);
        ctl_error(ctx, "Protocol is unnecessary when no port of vip "
                  "is given.");
        return;
    }

    char *token = NULL, *save_ptr = NULL;
    struct ds lb_ips_new = DS_EMPTY_INITIALIZER;
    for (token = strtok_r(lb_ips, ",", &save_ptr);
            token != NULL; token = strtok_r(NULL, ",", &save_ptr)) {
        struct sockaddr_storage ss_dst;

        if (lb_vip_port) {
            if (!inet_parse_active(token, -1, &ss_dst, false)) {
                ctl_error(ctx, "%s: should be an IP address and a port "
                          "number with : as a separator.", token);
                goto out;
            }
        } else {
            if (!inet_parse_address(token, &ss_dst)) {
                ctl_error(ctx, "%s: should be an IP address.", token);
                goto out;
            }
        }

        if (ss_vip.ss_family != ss_dst.ss_family) {
            ctl_error(ctx, "%s: IP address family is different from VIP %s.",
                      token, lb_vip_normalized);
            goto out;
        }
        ds_put_format(&lb_ips_new, "%s%s",
                lb_ips_new.length ? "," : "", token);
    }

    const struct nbrec_load_balancer *lb = NULL;
    if (!add_duplicate) {
        char *error = lb_by_name_or_uuid(ctx, lb_name, false, &lb);
        if (error) {
            ctx->error = error;
            goto out;
        }
        if (lb) {
            if (smap_get(&lb->vips, lb_vip_normalized)) {
                if (!may_exist) {
                    ctl_error(ctx, "%s: a load balancer with this vip (%s) "
                              "already exists", lb_name, lb_vip_normalized);
                    goto out;
                }
                /* Update the vips. */
                smap_replace(CONST_CAST(struct smap *, &lb->vips),
                        lb_vip_normalized, ds_cstr(&lb_ips_new));
            } else {
                /* Add the new vips. */
                smap_add(CONST_CAST(struct smap *, &lb->vips),
                        lb_vip_normalized, ds_cstr(&lb_ips_new));
            }

            /* Update the load balancer. */
            if (is_update_proto) {
                nbrec_load_balancer_verify_protocol(lb);
                nbrec_load_balancer_set_protocol(lb, lb_proto);
            }
            nbrec_load_balancer_verify_vips(lb);
            nbrec_load_balancer_set_vips(lb, &lb->vips);
            goto out;
        }
    }

    /* Create the load balancer. */
    lb = nbrec_load_balancer_insert(ctx->txn);
    nbrec_load_balancer_set_name(lb, lb_name);
    nbrec_load_balancer_set_protocol(lb, lb_proto);
    smap_add(CONST_CAST(struct smap *, &lb->vips),
            lb_vip_normalized, ds_cstr(&lb_ips_new));
    nbrec_load_balancer_set_vips(lb, &lb->vips);
    if (empty_backend_rej) {
        const struct smap options = SMAP_CONST1(&options, "reject", "true");
        nbrec_load_balancer_set_options(lb, &options);
    }
    if (empty_backend_event) {
        const struct smap options = SMAP_CONST1(&options, "event", "true");
        nbrec_load_balancer_set_options(lb, &options);
    }
out:
    ds_destroy(&lb_ips_new);

    ds_destroy(&lb_vip_normalized_ds);
}

static void
nbctl_pre_lb_del(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_vips);
}

static void
nbctl_lb_del(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_load_balancer *lb = NULL;
    bool must_exist = !shash_find(&ctx->options, "--if-exists");

    char *error = lb_by_name_or_uuid(ctx, id, false, &lb);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lb) {
        return;
    }

    if (ctx->argc == 3) {
        const char *lb_vip = ctx->argv[2];
        if (smap_get(&lb->vips, lb_vip)) {
            smap_remove(CONST_CAST(struct smap *, &lb->vips), lb_vip);
            if (smap_is_empty(&lb->vips)) {
                nbrec_load_balancer_delete(lb);
                return;
            }

            /* Delete the vip of the load balancer. */
            nbrec_load_balancer_verify_vips(lb);
            nbrec_load_balancer_set_vips(lb, &lb->vips);
            return;
        }
        if (must_exist) {
            ctl_error(ctx, "vip %s is not part of the load balancer.",
                      lb_vip);
            return;
        }
        return;
    }
    nbrec_load_balancer_delete(lb);
}

static void
nbctl_pre_lb_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_protocol);
    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_vips);
}

static void
lb_info_add_smap(const struct nbrec_load_balancer *lb,
                 struct smap *lbs, int vip_width)
{
    const struct smap_node **nodes = smap_sort(&lb->vips);
    if (nodes) {
        struct ds val = DS_EMPTY_INITIALIZER;
        for (int i = 0; i < smap_count(&lb->vips); i++) {
            const struct smap_node *node = nodes[i];

            struct sockaddr_storage ss;
            if (!inet_parse_active(node->key, 0, &ss, false)) {
                continue;
            }

            char *protocol = ss_get_port(&ss) ? lb->protocol : "tcp";
            i == 0 ? ds_put_format(&val,
                        UUID_FMT "    %-20.16s%-11.7s%-*.*s%s",
                        UUID_ARGS(&lb->header_.uuid),
                        lb->name, protocol,
                        vip_width + 4, vip_width,
                        node->key, node->value)
                   : ds_put_format(&val, "\n%60s%-11.7s%-*.*s%s",
                        "", protocol,
                        vip_width + 4, vip_width,
                        node->key, node->value);
        }

        smap_add_nocopy(lbs, xasprintf("%-20.16s", lb->name),
                        ds_steal_cstr(&val));
        free(nodes);
    }
}

static void
lb_info_print(struct ctl_context *ctx, struct smap *lbs, int vip_width)
{
    const struct smap_node **nodes = smap_sort(lbs);
    if (nodes) {
        ds_put_format(&ctx->output, "%-40.36s%-20.16s%-11.7s%-*.*s%s\n",
                "UUID", "LB", "PROTO", vip_width + 4, vip_width, "VIP", "IPs");
        for (size_t i = 0; i < smap_count(lbs); i++) {
            const struct smap_node *node = nodes[i];
            ds_put_format(&ctx->output, "%s\n", node->value);
        }

        free(nodes);
    }
}

static int
lb_get_max_vip_length(const struct nbrec_load_balancer *lb, int vip_width)
{
    const struct smap_node *node;
    int max_length = vip_width;

    SMAP_FOR_EACH (node, &lb->vips) {
        size_t keylen = strlen(node->key);
        if (max_length < keylen) {
            max_length = keylen;
        }
    }

    return max_length;
}

static void
lb_info_list_all(struct ctl_context *ctx,
                 const char *lb_name, bool lb_check)
{
    const struct nbrec_load_balancer *lb;
    struct smap lbs = SMAP_INITIALIZER(&lbs);
    int vip_width = 0;

    NBREC_LOAD_BALANCER_FOR_EACH (lb, ctx->idl) {
        if (lb_check && strcmp(lb->name, lb_name)) {
            continue;
        }
        vip_width = lb_get_max_vip_length(lb, vip_width);
    }

    NBREC_LOAD_BALANCER_FOR_EACH(lb, ctx->idl) {
        if (lb_check && strcmp(lb->name, lb_name)) {
            continue;
        }
        lb_info_add_smap(lb, &lbs, vip_width);
    }

    lb_info_print(ctx, &lbs, vip_width);
    smap_destroy(&lbs);
}

static void
nbctl_lb_list(struct ctl_context *ctx)
{
    if (ctx->argc == 1) {
        lb_info_list_all(ctx, NULL, false);
    } else if (ctx->argc == 2) {
        lb_info_list_all(ctx, ctx->argv[1], true);
    }
}

static void
nbctl_pre_lr_lb_add(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_load_balancer);

    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_name);
}

static void
nbctl_lr_lb_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr = NULL;
    const struct nbrec_load_balancer *new_lb;

    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }
    error = lb_by_name_or_uuid(ctx, ctx->argv[2], true, &new_lb);
    if (error) {
        ctx->error = error;
        return;
    }

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    for (int i = 0; i < lr->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = lr->load_balancer[i];

        if (uuid_equals(&new_lb->header_.uuid, &lb->header_.uuid)) {
            if (may_exist) {
                return;
            }
            ctl_error(ctx, UUID_FMT " : a load balancer with this UUID "
                      "already exists", UUID_ARGS(&lb->header_.uuid));
            return;
        }
    }

    /* Insert the load balancer into the logical router. */
    nbrec_logical_router_update_load_balancer_addvalue(lr, new_lb);
}

static void
nbctl_pre_lr_lb_del(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_load_balancer);

    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_name);
}

static void
nbctl_lr_lb_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    const struct nbrec_load_balancer *del_lb;
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 2) {
        /* If load-balancer is not specified, remove
         * all load-balancers from the logical router. */
        nbrec_logical_router_verify_load_balancer(lr);
        nbrec_logical_router_set_load_balancer(lr, NULL, 0);
        return;
    }

    error = lb_by_name_or_uuid(ctx, ctx->argv[2], true, &del_lb);
    if (error) {
        ctx->error = error;
        return;
    }
    for (size_t i = 0; i < lr->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = lr->load_balancer[i];

        if (uuid_equals(&del_lb->header_.uuid, &lb->header_.uuid)) {
            /* Remove the matching rule. */
            nbrec_logical_router_update_load_balancer_delvalue(lr, lb);
            return;
        }
    }

    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    if (must_exist) {
        ctl_error(ctx, "load balancer %s is not part of any logical router.",
                  del_lb->name);
        return;
    }
}

static void
nbctl_pre_lr_lb_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_load_balancer);

    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_protocol);
    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_vips);
}

static void
nbctl_lr_lb_list(struct ctl_context *ctx)
{
    const char *lr_name = ctx->argv[1];
    const struct nbrec_logical_router *lr;
    struct smap lbs = SMAP_INITIALIZER(&lbs);
    int vip_width = 0;

    char *error = lr_by_name_or_uuid(ctx, lr_name, true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }
    for (int i = 0; i < lr->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = lr->load_balancer[i];
        vip_width = lb_get_max_vip_length(lb, vip_width);
    }
    for (int i = 0; i < lr->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = lr->load_balancer[i];
        lb_info_add_smap(lb, &lbs, vip_width);
    }

    lb_info_print(ctx, &lbs, vip_width);
    smap_destroy(&lbs);
}

static void
nbctl_pre_ls_lb_add(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_load_balancer);

    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_name);
}

static void
nbctl_ls_lb_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls = NULL;
    const struct nbrec_load_balancer *new_lb;

    char *error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }
    error = lb_by_name_or_uuid(ctx, ctx->argv[2], true, &new_lb);
    if (error) {
        ctx->error = error;
        return;
    }

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    for (int i = 0; i < ls->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = ls->load_balancer[i];

        if (uuid_equals(&new_lb->header_.uuid, &lb->header_.uuid)) {
            if (may_exist) {
                return;
            }
            ctl_error(ctx, UUID_FMT " : a load balancer with this UUID "
                      "already exists", UUID_ARGS(&lb->header_.uuid));
            return;
        }
    }

    /* Insert the load balancer into the logical switch. */
    nbrec_logical_switch_update_load_balancer_addvalue(ls, new_lb);
}

static void
nbctl_pre_ls_lb_del(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_load_balancer);

    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_name);
}

static void
nbctl_ls_lb_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_switch *ls;
    const struct nbrec_load_balancer *del_lb;
    char *error = ls_by_name_or_uuid(ctx, ctx->argv[1], true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 2) {
        /* If load-balancer is not specified, remove
         * all load-balancers from the logical switch. */
        nbrec_logical_switch_verify_load_balancer(ls);
        nbrec_logical_switch_set_load_balancer(ls, NULL, 0);
        return;
    }

    error = lb_by_name_or_uuid(ctx, ctx->argv[2], true, &del_lb);
    if (error) {
        ctx->error = error;
        return;
    }
    for (size_t i = 0; i < ls->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = ls->load_balancer[i];

        if (uuid_equals(&del_lb->header_.uuid, &lb->header_.uuid)) {
            /* Remove the matching rule. */
            nbrec_logical_switch_update_load_balancer_delvalue(ls, lb);
            return;
        }
    }

    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    if (must_exist) {
        ctl_error(ctx, "load balancer %s is not part of any logical switch.",
                  del_lb->name);
        return;
    }
}

static void
nbctl_pre_ls_lb_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_load_balancer);

    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_protocol);
    ovsdb_idl_add_column(ctx->idl, &nbrec_load_balancer_col_vips);
}

static void
nbctl_ls_lb_list(struct ctl_context *ctx)
{
    const char *ls_name = ctx->argv[1];
    const struct nbrec_logical_switch *ls;
    struct smap lbs = SMAP_INITIALIZER(&lbs);
    int vip_width = 0;

    char *error = ls_by_name_or_uuid(ctx, ls_name, true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }
    for (int i = 0; i < ls->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = ls->load_balancer[i];
        vip_width = lb_get_max_vip_length(lb, vip_width);
    }
    for (int i = 0; i < ls->n_load_balancer; i++) {
        const struct nbrec_load_balancer *lb
            = ls->load_balancer[i];
        lb_info_add_smap(lb, &lbs, vip_width);
    }

    lb_info_print(ctx, &lbs, vip_width);
    smap_destroy(&lbs);
}

static void
nbctl_pre_lr_add(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
}

static void
nbctl_lr_add(struct ctl_context *ctx)
{
    const char *lr_name = ctx->argc == 2 ? ctx->argv[1] : NULL;

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    bool add_duplicate = shash_find(&ctx->options, "--add-duplicate") != NULL;
    if (may_exist && add_duplicate) {
        ctl_error(ctx, "--may-exist and --add-duplicate may not be used "
                  "together");
        return;
    }

    if (lr_name) {
        if (!add_duplicate) {
            const struct nbrec_logical_router *lr;
            NBREC_LOGICAL_ROUTER_FOR_EACH (lr, ctx->idl) {
                if (!strcmp(lr->name, lr_name)) {
                    if (may_exist) {
                        return;
                    }
                    ctl_error(ctx, "%s: a router with this name already "
                              "exists", lr_name);
                    return;
                }
            }
        }
    } else if (may_exist) {
        ctl_error(ctx, "--may-exist requires specifying a name");
        return;
    } else if (add_duplicate) {
        ctl_error(ctx, "--add-duplicate requires specifying a name");
        return;
    }

    struct nbrec_logical_router *lr;
    lr = nbrec_logical_router_insert(ctx->txn);
    if (lr_name) {
        nbrec_logical_router_set_name(lr, lr_name);
    }
}

static void
nbctl_pre_lr_del(struct ctl_context *ctx)
{
    nbctl_pre_context(ctx);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
}

static void
nbctl_lr_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    struct nbctl_context *nbctx = nbctl_context_get(ctx);
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router *lr = NULL;

    char *error = lr_by_name_or_uuid(ctx, id, must_exist, &lr);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lr) {
        return;
    }

    /* Updating runtime cache. */
    for (size_t i = 0; i < lr->n_ports; i++) {
        shash_find_and_delete(&nbctx->lrp_to_lr_map, lr->ports[i]->name);
    }

    nbrec_logical_router_delete(lr);
}

static void
nbctl_pre_lr_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
}

static void
nbctl_lr_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    struct smap lrs;

    smap_init(&lrs);
    NBREC_LOGICAL_ROUTER_FOR_EACH(lr, ctx->idl) {
        smap_add_format(&lrs, lr->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lr->header_.uuid), lr->name);
    }
    const struct smap_node **nodes = smap_sort(&lrs);
    for (size_t i = 0; i < smap_count(&lrs); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lrs);
    free(nodes);
}

static char *
dhcp_options_get(struct ctl_context *ctx, const char *id, bool must_exist,
                 const struct nbrec_dhcp_options **dhcp_opts_p)
{
    struct uuid dhcp_opts_uuid;
    const struct nbrec_dhcp_options *dhcp_opts = NULL;
    if (uuid_from_string(&dhcp_opts_uuid, id)) {
        dhcp_opts = nbrec_dhcp_options_get_for_uuid(ctx->idl, &dhcp_opts_uuid);
    }

    *dhcp_opts_p = dhcp_opts;
    if (!dhcp_opts && must_exist) {
        return xasprintf("%s: dhcp options UUID not found", id);
    }

    return NULL;
}

static void
nbctl_dhcp_options_create(struct ctl_context *ctx)
{
    /* Validate the cidr */
    ovs_be32 ip;
    unsigned int plen;
    char *error = ip_parse_cidr(ctx->argv[1], &ip, &plen);
    if (error){
        /* check if its IPv6 cidr */
        free(error);
        struct in6_addr ipv6;
        error = ipv6_parse_cidr(ctx->argv[1], &ipv6, &plen);
        if (error) {
            free(error);
            ctl_error(ctx, "Invalid cidr format '%s'", ctx->argv[1]);
            return;
        }
    }

    struct nbrec_dhcp_options *dhcp_opts = nbrec_dhcp_options_insert(ctx->txn);
    nbrec_dhcp_options_set_cidr(dhcp_opts, ctx->argv[1]);

    struct smap ext_ids = SMAP_INITIALIZER(&ext_ids);
    for (size_t i = 2; i < ctx->argc; i++) {
        char *key, *value;
        value = xstrdup(ctx->argv[i]);
        key = strsep(&value, "=");
        if (value) {
            smap_add(&ext_ids, key, value);
        }
        free(key);
    }

    nbrec_dhcp_options_set_external_ids(dhcp_opts, &ext_ids);
    smap_destroy(&ext_ids);
}

static void
nbctl_pre_dhcp_options_options(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_dhcp_options_col_options);
}

static void
nbctl_dhcp_options_set_options(struct ctl_context *ctx)
{
    const struct nbrec_dhcp_options *dhcp_opts;
    char *error = dhcp_options_get(ctx, ctx->argv[1], true, &dhcp_opts);
    if (error) {
        ctx->error = error;
        return;
    }

    struct smap dhcp_options = SMAP_INITIALIZER(&dhcp_options);
    for (size_t i = 2; i < ctx->argc; i++) {
        char *key, *value;
        value = xstrdup(ctx->argv[i]);
        key = strsep(&value, "=");
        if (value) {
            smap_add(&dhcp_options, key, value);
        }
        free(key);
    }

    nbrec_dhcp_options_set_options(dhcp_opts, &dhcp_options);
    smap_destroy(&dhcp_options);
}

static void
nbctl_dhcp_options_get_options(struct ctl_context *ctx)
{
    const struct nbrec_dhcp_options *dhcp_opts;
    char *error = dhcp_options_get(ctx, ctx->argv[1], true, &dhcp_opts);
    if (error) {
        ctx->error = error;
        return;
    }

    struct smap_node *node;
    SMAP_FOR_EACH(node, &dhcp_opts->options) {
        ds_put_format(&ctx->output, "%s=%s\n", node->key, node->value);
    }
}

static void
nbctl_pre_dhcp_options_del(struct ctl_context *ctx)
{
    ovsdb_idl_add_table(ctx->idl, &nbrec_table_dhcp_options);
}

static void
nbctl_dhcp_options_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const char *id = ctx->argv[1];
    const struct nbrec_dhcp_options *dhcp_opts;

    char *error = dhcp_options_get(ctx, id, must_exist, &dhcp_opts);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!dhcp_opts) {
        return;
    }

    nbrec_dhcp_options_delete(dhcp_opts);
}

static void
nbctl_pre_dhcp_options_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_dhcp_options_col_cidr);
}

static void
nbctl_dhcp_options_list(struct ctl_context *ctx)
{
    const struct nbrec_dhcp_options *dhcp_opts;
    struct smap dhcp_options;

    smap_init(&dhcp_options);
    NBREC_DHCP_OPTIONS_FOR_EACH(dhcp_opts, ctx->idl) {
        smap_add_format(&dhcp_options, dhcp_opts->cidr, UUID_FMT,
                        UUID_ARGS(&dhcp_opts->header_.uuid));
    }
    const struct smap_node **nodes = smap_sort(&dhcp_options);
    for (size_t i = 0; i < smap_count(&dhcp_options); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&dhcp_options);
    free(nodes);
}

static char *
normalize_ipv4_prefix_str(const char *orig_prefix)
{
    unsigned int plen;
    ovs_be32 ipv4;
    char *error;

    error = ip_parse_cidr(orig_prefix, &ipv4, &plen);
    if (error) {
        free(error);
        return NULL;
    }
    return normalize_ipv4_prefix(ipv4, plen);
}

static char *
normalize_ipv6_prefix_str(const char *orig_prefix)
{
    unsigned int plen;
    struct in6_addr ipv6;
    char *error;

    error = ipv6_parse_cidr(orig_prefix, &ipv6, &plen);
    if (error) {
        free(error);
        return NULL;
    }
    return normalize_ipv6_prefix(&ipv6, plen);
}

/* The caller must free the returned string. */
static char *
normalize_prefix_str(const char *orig_prefix)
{
    char *ret;

    ret = normalize_ipv4_prefix_str(orig_prefix);
    if (!ret) {
        ret = normalize_ipv6_prefix_str(orig_prefix);
    }
    return ret;
}

static char *
normalize_ipv4_addr_str(const char *orig_addr)
{
    ovs_be32 ipv4;

    if (!ip_parse(orig_addr, &ipv4)) {
        return NULL;
    }

    return normalize_ipv4_prefix(ipv4, 32);
}

static char *
normalize_ipv6_addr_str(const char *orig_addr)
{
    struct in6_addr ipv6;

    if (!ipv6_parse(orig_addr, &ipv6)) {
        return NULL;
    }

    return normalize_ipv6_prefix(&ipv6, 128);
}

/* Similar to normalize_prefix_str but must be an un-masked address.
 * The caller must free the returned string. */
OVS_UNUSED static char *
normalize_addr_str(const char *orig_addr)
{
    char *ret;

    ret = normalize_ipv4_addr_str(orig_addr);
    if (!ret) {
        ret = normalize_ipv6_addr_str(orig_addr);
    }
    return ret;
}

static void
nbctl_pre_lr_policy_add(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_policies);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_policy_col_priority);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_policy_col_match);
}

static void
nbctl_lr_policy_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    int64_t priority = 0;
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }
    error = parse_priority(ctx->argv[2], &priority);
    if (error) {
        ctx->error = error;
        return;
    }
    const char *action = ctx->argv[4];
    size_t n_nexthops = 0;
    char **nexthops = NULL;

    bool reroute = false;
    /* Validate action. */
    if (strcmp(action, "allow") && strcmp(action, "drop")
        && strcmp(action, "reroute")) {
        ctl_error(ctx, "%s: action must be one of \"allow\", \"drop\", "
                  "and \"reroute\"", action);
        return;
    }
    if (!strcmp(action, "reroute")) {
        if (ctx->argc < 6) {
            ctl_error(ctx, "Nexthop is required when action is reroute.");
            return;
        }
        reroute = true;
    }

    /* Check if same routing policy already exists.
     * A policy is uniquely identified by priority and match */
    bool may_exist = !!shash_find(&ctx->options, "--may-exist");
    size_t i;
    for (i = 0; i < lr->n_policies; i++) {
        const struct nbrec_logical_router_policy *policy = lr->policies[i];
        if (policy->priority == priority &&
            !strcmp(policy->match, ctx->argv[3])) {
            if (!may_exist) {
                ctl_error(ctx, "Same routing policy already existed on the "
                          "logical router %s.", ctx->argv[1]);
            }
            return;
        }
    }

    if (reroute) {
        char *nexthops_arg = xstrdup(ctx->argv[5]);
        char *save_ptr, *next_hop, *token;

        n_nexthops = 0;
        size_t n_allocs = 0;

        bool nexthops_is_ipv4 = true;
        for (token = strtok_r(nexthops_arg, ",", &save_ptr);
            token != NULL; token = strtok_r(NULL, ",", &save_ptr)) {
            next_hop = normalize_addr_str(token);

            if (!next_hop) {
                ctl_error(ctx, "bad next hop argument: %s", ctx->argv[5]);
                free(nexthops_arg);
                for (i = 0; i < n_nexthops; i++) {
                    free(nexthops[i]);
                }
                free(nexthops);
                return;
            }
            if (n_nexthops == n_allocs) {
                nexthops = x2nrealloc(nexthops, &n_allocs, sizeof *nexthops);
            }

            bool is_ipv4 = strchr(next_hop, '.') ? true : false;
            if (n_nexthops == 0) {
                nexthops_is_ipv4 = is_ipv4;
            }

            if (is_ipv4 != nexthops_is_ipv4) {
                ctl_error(ctx, "bad next hops argument, not in the same "
                          "addr family : %s", ctx->argv[5]);
                free(nexthops_arg);
                free(next_hop);
                for (i = 0; i < n_nexthops; i++) {
                    free(nexthops[i]);
                }
                free(nexthops);
                return;
            }
            nexthops[n_nexthops] = next_hop;
            n_nexthops++;
        }

        free(nexthops_arg);
    }

    struct nbrec_logical_router_policy *policy;
    policy = nbrec_logical_router_policy_insert(ctx->txn);
    nbrec_logical_router_policy_set_priority(policy, priority);
    nbrec_logical_router_policy_set_match(policy, ctx->argv[3]);
    nbrec_logical_router_policy_set_action(policy, action);
    if (reroute) {
        nbrec_logical_router_policy_set_nexthops(
            policy, (const char **)nexthops, n_nexthops);
    }

    /* Parse the options. */
    struct smap options = SMAP_INITIALIZER(&options);
    for (i = reroute ? 6 : 5; i < ctx->argc; i++) {
        char *key, *value;
        value = xstrdup(ctx->argv[i]);
        key = strsep(&value, "=");
        if (value && value[0]) {
            smap_add(&options, key, value);
        } else {
            ctl_error(ctx, "No value specified for the option : %s", key);
            smap_destroy(&options);
            free(key);
            for (i = 0; i < n_nexthops; i++) {
                free(nexthops[i]);
            }
            free(nexthops);
            return;
        }
        free(key);
    }
    nbrec_logical_router_policy_set_options(policy, &options);
    smap_destroy(&options);

    nbrec_logical_router_update_policies_addvalue(lr, policy);

    for (i = 0; i < n_nexthops; i++) {
        free(nexthops[i]);
    }
    free(nexthops);
}

static void
nbctl_pre_lr_policy_del(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_policies);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_policy_col_priority);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_policy_col_match);
}

static void
nbctl_lr_policy_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    int64_t priority = 0;
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 2) {
        /* If a priority is not specified, delete all policies. */
        nbrec_logical_router_set_policies(lr, NULL, 0);
        return;
    }

    const struct uuid *lr_policy_uuid = NULL;
    struct uuid uuid_from_cmd;
    if (uuid_from_string(&uuid_from_cmd, ctx->argv[2])) {
        lr_policy_uuid = &uuid_from_cmd;
    } else {
        error = parse_priority(ctx->argv[2], &priority);
        if (error) {
            ctx->error = error;
            return;
        }
    }
    /* If uuid was specified, delete routing policy with the
     * specified uuid. */
    if (ctx->argc == 3) {
        size_t i;

        if (lr_policy_uuid) {
            for (i = 0; i < lr->n_policies; i++) {
                if (uuid_equals(lr_policy_uuid,
                                &(lr->policies[i]->header_.uuid))) {
                    nbrec_logical_router_update_policies_delvalue(
                        lr, lr->policies[i]);
                    break;
                }
            }
            if (i == lr->n_policies) {
                if (!shash_find(&ctx->options, "--if-exists")) {
                    ctl_error(ctx, "Logical router policy uuid is not found.");
                }
                return;
            }

        /* If match is not specified, delete all routing policies with the
         * specified priority. */
        } else {
            for (i = 0; i < lr->n_policies; i++) {
                if (priority == lr->policies[i]->priority) {
                    nbrec_logical_router_update_policies_delvalue(
                        lr, lr->policies[i]);
                }
            }
        }
        return;
    }

    /* Delete policy that has the same priority and match string */
    for (int i = 0; i < lr->n_policies; i++) {
        struct nbrec_logical_router_policy *routing_policy = lr->policies[i];
        if (priority == routing_policy->priority &&
            !strcmp(ctx->argv[3], routing_policy->match)) {
            nbrec_logical_router_update_policies_delvalue(lr, routing_policy);
            return;
        }
    }
}

 struct routing_policy {
    int priority;
    char *match;
    const struct nbrec_logical_router_policy *policy;
};

static int
routing_policy_cmp(const void *policy1_, const void *policy2_)
{
    const struct routing_policy *policy1p = policy1_;
    const struct routing_policy *policy2p = policy2_;
    if (policy1p->priority != policy2p->priority) {
        return policy1p->priority > policy2p->priority ? -1 : 1;
    } else {
        return strcmp(policy1p->match, policy2p->match);
    }
}

static void
print_routing_policy(const struct nbrec_logical_router_policy *policy,
                     struct ds *s)
{
    if (policy->n_nexthops) {
        ds_put_format(s, "%10"PRId64" %50s %15s", policy->priority,
                      policy->match, policy->action);
        for (int i = 0; i < policy->n_nexthops; i++) {
            char *next_hop = normalize_prefix_str(policy->nexthops[i]);
            char *fmt = i ? ", %s" : " %25s";
            ds_put_format(s, fmt, next_hop);
            free(next_hop);
        }
    } else {
        ds_put_format(s, "%10"PRId64" %50s %15s", policy->priority,
                      policy->match, policy->action);
    }

    if (!smap_is_empty(&policy->options)) {
        ds_put_format(s, "%15s", "");
        struct smap_node *node;
        SMAP_FOR_EACH (node, &policy->options) {
            ds_put_format(s, "%s=%s,", node->key, node->value);
        }
        ds_chomp(s, ',');
    }

    ds_put_char(s, '\n');
}

static void
nbctl_pre_lr_policy_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_policies);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_policy_col_priority);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_policy_col_match);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_policy_col_nexthops);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_policy_col_action);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_policy_col_options);
}

static void
nbctl_lr_policy_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    struct routing_policy *policies;
    size_t n_policies = 0;
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }
    policies = xmalloc(sizeof *policies * lr->n_policies);
    for (int i = 0; i < lr->n_policies; i++) {
        const struct nbrec_logical_router_policy *policy
            = lr->policies[i];
        policies[n_policies].priority = policy->priority;
        policies[n_policies].match = policy->match;
        policies[n_policies].policy = policy;
        n_policies++;
    }
    qsort(policies, n_policies, sizeof *policies, routing_policy_cmp);
    if (n_policies) {
        ds_put_cstr(&ctx->output, "Routing Policies\n");
    }
    for (int i = 0; i < n_policies; i++) {
        print_routing_policy(policies[i].policy, &ctx->output);
    }
    free(policies);
}

static struct nbrec_logical_router_static_route *
nbctl_lr_get_route(const struct nbrec_logical_router *lr, char *prefix,
                   char *next_hop, bool is_src_route, bool ecmp)
{
    for (int i = 0; i < lr->n_static_routes; i++) {
        struct nbrec_logical_router_static_route *route = lr->static_routes[i];

        /* Compare route policy. */
        char *nb_policy = route->policy;
        bool nb_is_src_route = false;
        if (nb_policy && !strcmp(nb_policy, "src-ip")) {
                nb_is_src_route = true;
        }
        if (is_src_route != nb_is_src_route) {
            continue;
        }

        /* Compare route prefix. */
        char *rt_prefix = normalize_prefix_str(route->ip_prefix);
        if (!rt_prefix) {
            /* Ignore existing prefix we couldn't parse. */
            continue;
        }

        if (strcmp(rt_prefix, prefix)) {
            free(rt_prefix);
            continue;
        }

        if (ecmp && strcmp(next_hop, route->nexthop)) {
            free(rt_prefix);
            continue;
        }

        free(rt_prefix);
        return route;
    }
    return NULL;
}

static void
nbctl_pre_lr_route_add(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_static_routes);

    ovsdb_idl_add_column(ctx->idl, &nbrec_bfd_col_dst_ip);

    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_ip_prefix);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_nexthop);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_output_port);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_policy);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_bfd);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_options);
}

static void
nbctl_lr_route_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr = NULL;
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }
    char *prefix = NULL, *next_hop = NULL;

    const char *policy = shash_find_data(&ctx->options, "--policy");
    bool is_src_route = false;

    if (policy) {
        if (!strcmp(policy, "src-ip")) {
            is_src_route = true;
        } else if (strcmp(policy, "dst-ip")) {
            ctl_error(ctx, "bad policy: %s", policy);
            return;
        }
    }

    bool v6_prefix = false;
    prefix = normalize_ipv4_prefix_str(ctx->argv[2]);
    if (!prefix) {
        prefix = normalize_ipv6_prefix_str(ctx->argv[2]);
        v6_prefix = true;
    }
    if (!prefix) {
        ctl_error(ctx, "bad prefix argument: %s", ctx->argv[2]);
        return;
    }

    bool is_discard_route = !strcmp(ctx->argv[3], "discard");
    if (is_discard_route) {
        next_hop = xasprintf("discard");
    } else {
        next_hop = v6_prefix
            ? normalize_ipv6_addr_str(ctx->argv[3])
            : normalize_ipv4_addr_str(ctx->argv[3]);
        if (!next_hop) {
            ctl_error(ctx, "bad %s nexthop argument: %s",
                      v6_prefix ? "IPv6" : "IPv4", ctx->argv[3]);
            goto cleanup;
        }
    }

    struct shash_node *bfd = shash_find(&ctx->options, "--bfd");
    const struct nbrec_bfd *nb_bt = NULL;
    if (bfd) {
        if (bfd->data) {
            struct uuid bfd_uuid;
            if (uuid_from_string(&bfd_uuid, bfd->data)) {
                nb_bt = nbrec_bfd_get_for_uuid(ctx->idl, &bfd_uuid);
            }
            if (!nb_bt) {
                ctl_error(ctx, "no entry found in the BFD table");
                goto cleanup;
            }
        } else {
            const struct nbrec_bfd *iter;
            NBREC_BFD_FOR_EACH (iter, ctx->idl) {
                if (!strcmp(iter->dst_ip, next_hop)) {
                    nb_bt = iter;
                    break;
                }
            }
        }
    }

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    bool ecmp_symmetric_reply = shash_find(&ctx->options,
                                           "--ecmp-symmetric-reply") != NULL;
    bool ecmp = shash_find(&ctx->options, "--ecmp") != NULL ||
                ecmp_symmetric_reply;
    struct nbrec_logical_router_static_route *route =
        nbctl_lr_get_route(lr, prefix, next_hop, is_src_route, ecmp);

    /* Validations for nexthop = "discard" */
    if (is_discard_route) {
        if (ecmp) {
            ctl_error(ctx, "ecmp is not valid for discard routes.");
            goto cleanup;
        }
        if (bfd) {
            ctl_error(ctx, "bfd dst_ip cannot be discard.");
            goto cleanup;
        }
        if (ctx->argc == 5) {
            if (is_discard_route) {
                ctl_error(ctx, "outport is not valid for discard routes.");
                goto cleanup;
            }
        }
    }

    if (!ecmp) {
        if (route) {
            if (!may_exist) {
                ctl_error(ctx, "duplicate prefix: %s (policy: %s). Use option"
                          " --ecmp to allow this for ECMP routing.",
                          prefix, is_src_route ? "src-ip" : "dst-ip");
                goto cleanup;
            }

            /* Update the next hop for an existing route. */
            nbrec_logical_router_verify_static_routes(lr);
            nbrec_logical_router_static_route_verify_ip_prefix(route);
            nbrec_logical_router_static_route_verify_nexthop(route);
            nbrec_logical_router_static_route_set_ip_prefix(route, prefix);
            nbrec_logical_router_static_route_set_nexthop(route, next_hop);
            if (ctx->argc == 5) {
                nbrec_logical_router_static_route_set_output_port(
                    route, ctx->argv[4]);
            }
            if (policy) {
                 nbrec_logical_router_static_route_set_policy(route, policy);
            }
            if (bfd) {
                if (!nb_bt) {
                    if (ctx->argc != 5) {
                        ctl_error(ctx, "insert entry in the BFD table failed");
                        goto cleanup;
                    }
                    nb_bt = nbrec_bfd_insert(ctx->txn);
                    nbrec_bfd_set_dst_ip(nb_bt, next_hop);
                    nbrec_bfd_set_logical_port(nb_bt, ctx->argv[4]);
                }
                nbrec_logical_router_static_route_set_bfd(route, nb_bt);
            }
            goto cleanup;
        }
    } else if (route) {
        if (!may_exist) {
            ctl_error(ctx, "duplicate nexthop for the same ECMP route");
        }
        goto cleanup;
    }

    struct nbrec_logical_router_static_route *discard_route =
        nbctl_lr_get_route(lr, prefix, "discard", is_src_route, true);
    if (discard_route) {
        ctl_error(ctx, "discard nexthop for the same ECMP route exists.");
        goto cleanup;
    }

    route = nbrec_logical_router_static_route_insert(ctx->txn);
    nbrec_logical_router_static_route_set_ip_prefix(route, prefix);
    nbrec_logical_router_static_route_set_nexthop(route, next_hop);
    if (ctx->argc == 5) {
        nbrec_logical_router_static_route_set_output_port(route, ctx->argv[4]);
    }
    if (policy) {
        nbrec_logical_router_static_route_set_policy(route, policy);
    }

    if (ecmp_symmetric_reply) {
        const struct smap options = SMAP_CONST1(&options,
                                                "ecmp_symmetric_reply",
                                                "true");
        nbrec_logical_router_static_route_set_options(route, &options);
    }

    nbrec_logical_router_update_static_routes_addvalue(lr, route);
    if (bfd) {
        if (!nb_bt) {
            if (ctx->argc != 5) {
                ctl_error(ctx, "insert entry in the BFD table failed");
                goto cleanup;
            }
            nb_bt = nbrec_bfd_insert(ctx->txn);
            nbrec_bfd_set_dst_ip(nb_bt, next_hop);
            nbrec_bfd_set_logical_port(nb_bt, ctx->argv[4]);
        }
        nbrec_logical_router_static_route_set_bfd(route, nb_bt);
    }

cleanup:
    free(next_hop);
    free(prefix);
}

static void
nbctl_pre_lr_route_del(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_static_routes);

    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_policy);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_ip_prefix);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_nexthop);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_output_port);

}

static void
nbctl_lr_route_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    const char *policy = shash_find_data(&ctx->options, "--policy");
    bool is_src_route = false;
    if (policy) {
        if (!strcmp(policy, "src-ip")) {
            is_src_route = true;
        } else if (strcmp(policy, "dst-ip")) {
            ctl_error(ctx, "bad policy: %s", policy);
            return;
        }
    }

    if (ctx->argc == 2 && !policy) {
        /* If neither prefix nor policy is specified, delete all routes. */
        nbrec_logical_router_set_static_routes(lr, NULL, 0);
        return;
    }

    char *prefix = NULL;
    if (ctx->argc >= 3) {
        prefix = normalize_prefix_str(ctx->argv[2]);
        if (!prefix) {
            ctl_error(ctx, "bad prefix argument: %s", ctx->argv[2]);
            return;
        }
    }

    char *nexthop = NULL;
    if (ctx->argc >= 4) {
        if (!strcmp(ctx->argv[3], "discard")) {
            nexthop = xasprintf("discard");
        } else {
            nexthop = normalize_prefix_str(ctx->argv[3]);
            if (!nexthop) {
                ctl_error(ctx, "bad nexthop argument: %s", ctx->argv[3]);
                return;
            }
        }
    }

    char *output_port = NULL;
    if (ctx->argc == 5) {
        output_port = ctx->argv[4];
    }

    size_t n_removed = 0;
    for (size_t i = 0; i < lr->n_static_routes; i++) {
        /* Compare route policy, if specified. */
        if (policy) {
            char *nb_policy = lr->static_routes[i]->policy;
            bool nb_is_src_route = false;
            if (nb_policy && !strcmp(nb_policy, "src-ip")) {
                    nb_is_src_route = true;
            }
            if (is_src_route != nb_is_src_route) {
                continue;
            }
        }

        /* Compare route prefix, if specified. */
        if (prefix) {
            char *rt_prefix =
                normalize_prefix_str(lr->static_routes[i]->ip_prefix);
            if (!rt_prefix) {
                /* Ignore existing prefix we couldn't parse. */
                continue;
            }

            int ret = strcmp(prefix, rt_prefix);
            free(rt_prefix);
            if (ret) {
                continue;
            }
        }

        /* Compare nexthop, if specified. */
        if (nexthop) {
            char *rt_nexthop = !strcmp(lr->static_routes[i]->nexthop, "discard")
                ? xasprintf("discard")
                : normalize_prefix_str(lr->static_routes[i]->nexthop);
            if (!rt_nexthop) {
                /* Ignore existing nexthop we couldn't parse. */
                continue;
            }
            int ret = strcmp(nexthop, rt_nexthop);
            free(rt_nexthop);
            if (ret) {
                continue;
            }
        }

        /* Compare output_port, if specified. */
        if (output_port) {
            char *rt_output_port = lr->static_routes[i]->output_port;
            if (!rt_output_port || strcmp(output_port, rt_output_port)) {
                continue;
            }
        }

        /* Everything matched. Removing. */
        nbrec_logical_router_update_static_routes_delvalue(
            lr, lr->static_routes[i]);
        n_removed++;
    }

    if (!n_removed && !shash_find(&ctx->options, "--if-exists")) {
        ctl_error(ctx, "no matching route: policy '%s', prefix '%s', nexthop "
                  "'%s', output_port '%s'.",
                  policy ? policy : "any",
                  prefix,
                  nexthop ? nexthop : "any",
                  output_port ? output_port : "any");
    }

    free(prefix);
    free(nexthop);
}

static bool
is_valid_port_range(const char *port_range)
{
    int range_lo_int, range_hi_int;
    bool ret = false;

    if (!port_range) {
        return false;
    }

    char *save_ptr = NULL;
    char *tokstr = xstrdup(port_range);
    char *range_lo = strtok_r(tokstr, "-", &save_ptr);
    if (!range_lo) {
        goto done;
    }
    range_lo_int = strtol(range_lo, NULL, 10);
    if (errno == EINVAL || range_lo_int <= 0) {
        goto done;
    }

    if (!strchr(port_range, '-')) {
        ret = true;
        goto done;
    }

    char *range_hi = strtok_r(NULL, "-", &save_ptr);
    if (!range_hi) {
        goto done;
    }
    range_hi_int = strtol(range_hi, NULL, 10);
    if (errno == EINVAL) {
        goto done;
    }

    /* Check that there is nothing after range_hi. */
    if (strtok_r(NULL, "", &save_ptr)) {
        goto done;
    }

    if (range_lo_int >= range_hi_int) {
        goto done;
    }

    if (range_hi_int > 65535) {
        goto done;
    }

    ret = true;

done:
    free(tokstr);
    return ret;
}

static void
nbctl_pre_lr_nat_add(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_nat);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);

    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_external_ip);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_logical_ip);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_type);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_logical_port);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_external_mac);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_options);
}

static void
nbctl_lr_nat_add(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr = NULL;
    const char *nat_type = ctx->argv[2];
    const char *external_ip = ctx->argv[3];
    const char *logical_ip = ctx->argv[4];
    char *new_logical_ip = NULL;
    char *new_external_ip = NULL;
    bool is_portrange = shash_find(&ctx->options, "--portrange") != NULL;

    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    if (strcmp(nat_type, "dnat") && strcmp(nat_type, "snat")
            && strcmp(nat_type, "dnat_and_snat")) {
        ctl_error(ctx, "%s: type must be one of \"dnat\", \"snat\" and "
                  "\"dnat_and_snat\".", nat_type);
        return;
    }

    bool is_v6 = false;

    new_external_ip = normalize_ipv4_addr_str(external_ip);
    if (!new_external_ip) {
        new_external_ip = normalize_ipv6_addr_str(external_ip);
        is_v6 = true;
    }
    if (!new_external_ip) {
        ctl_error(ctx, "%s: Not a valid IPv4 or IPv6 address.",
                  external_ip);
        return;
    }

    if (strcmp("snat", nat_type)) {
        new_logical_ip = is_v6
            ? normalize_ipv6_addr_str(logical_ip)
            : normalize_ipv4_addr_str(logical_ip);
        if (!new_logical_ip) {
            ctl_error(ctx, "%s: Not a valid %s address.", logical_ip,
                      is_v6 ? "IPv6" : "IPv4");
        }
    } else {
        new_logical_ip = is_v6
            ? normalize_ipv6_prefix_str(logical_ip)
            : normalize_ipv4_prefix_str(logical_ip);
        if (!new_logical_ip) {
            ctl_error(ctx, "%s: should be an %s address or network.",
                      logical_ip, is_v6 ? "IPv6" : "IPv4");
        }
    }

    if (!new_logical_ip) {
        goto cleanup;
    }

    const char *logical_port = NULL;
    const char *external_mac = NULL;
    const char *port_range = NULL;

    if (ctx->argc == 6) {
        if (!is_portrange) {
            ctl_error(ctx, "lr-nat-add with logical_port "
                      "must also specify external_mac.");
            goto cleanup;
        }
        port_range = ctx->argv[5];
        if (!is_valid_port_range(port_range)) {
            ctl_error(ctx, "invalid port range %s.", port_range);
            goto cleanup;
        }

    } else if (ctx->argc >= 7) {
        if (strcmp(nat_type, "dnat_and_snat")) {
            ctl_error(ctx, "logical_port and external_mac are only valid when "
                      "type is \"dnat_and_snat\".");
            goto cleanup;
        }

        if (ctx->argc == 7 && is_portrange) {
            ctl_error(ctx, "lr-nat-add with logical_port "
                      "must also specify external_mac.");
            goto cleanup;
        }

        logical_port = ctx->argv[5];
        const struct nbrec_logical_switch_port *lsp;
        error = lsp_by_name_or_uuid(ctx, logical_port, true, &lsp);
        if (error) {
            ctx->error = error;
            goto cleanup;
        }

        external_mac = ctx->argv[6];
        struct eth_addr ea;
        if (!eth_addr_from_string(external_mac, &ea)) {
            ctl_error(ctx, "invalid mac address %s.", external_mac);
            goto cleanup;
        }

        if (ctx->argc > 7) {
            port_range = ctx->argv[7];
            if (!is_valid_port_range(port_range)) {
                ctl_error(ctx, "invalid port range %s.", port_range);
                goto cleanup;
            }
        }

    } else {
        port_range = NULL;
        logical_port = NULL;
        external_mac = NULL;
    }

    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    bool stateless = shash_find(&ctx->options, "--stateless") != NULL;

    if (strcmp(nat_type, "dnat_and_snat") && stateless) {
        ctl_error(ctx, "stateless is not applicable to dnat or snat types");
        goto cleanup;
    }

    int is_snat = !strcmp("snat", nat_type);
    for (size_t i = 0; i < lr->n_nat; i++) {
        const struct nbrec_nat *nat = lr->nat[i];

        char *old_external_ip;
        char *old_logical_ip;
        bool should_return = false;
        old_external_ip = normalize_prefix_str(nat->external_ip);
        if (!old_external_ip) {
            continue;
        }
        old_logical_ip = normalize_prefix_str(nat->logical_ip);
        if (!old_logical_ip) {
            free(old_external_ip);
            continue;
        }

        if (!strcmp(nat_type, nat->type)) {
            if (!strcmp(is_snat ? new_logical_ip : new_external_ip,
                        is_snat ? old_logical_ip : old_external_ip)) {
                if (!strcmp(is_snat ? new_external_ip : new_logical_ip,
                            is_snat ? old_external_ip : old_logical_ip)) {
                        if (may_exist) {
                            nbrec_nat_verify_logical_port(nat);
                            nbrec_nat_verify_external_mac(nat);
                            nbrec_nat_set_logical_port(nat, logical_port);
                            nbrec_nat_set_external_mac(nat, external_mac);
                            should_return = true;
                        } else {
                            ctl_error(ctx, "%s, %s: a NAT with this "
                                      "external_ip and logical_ip already "
                                      "exists", new_external_ip,
                                      new_logical_ip);
                            should_return = true;
                        }
                } else {
                    ctl_error(ctx, "a NAT with this type (%s) and %s (%s) "
                              "already exists",
                              nat_type,
                              is_snat ? "logical_ip" : "external_ip",
                              is_snat ? new_logical_ip : new_external_ip);
                    should_return = true;
                }
            }
        }
        if (!strcmp(nat_type, "dnat_and_snat") ||
            !strcmp(nat->type, "dnat_and_snat")) {

            if (!strcmp(old_external_ip, new_external_ip)) {
                struct smap nat_options = SMAP_INITIALIZER(&nat_options);
                if (!strcmp(smap_get(&nat->options, "stateless"),
                            "true") || stateless) {
                    ctl_error(ctx, "%s, %s: External ip cannot be shared "
                              "across stateless and stateful NATs",
                              new_external_ip, new_logical_ip);
                }
            }
        }
        free(old_external_ip);
        free(old_logical_ip);
        if (should_return) {
            goto cleanup;
        }
    }

    /* Create the NAT. */
    struct smap nat_options = SMAP_INITIALIZER(&nat_options);
    struct nbrec_nat *nat = nbrec_nat_insert(ctx->txn);
    nbrec_nat_set_type(nat, nat_type);
    nbrec_nat_set_external_ip(nat, external_ip);
    nbrec_nat_set_logical_ip(nat, new_logical_ip);
    if (logical_port && external_mac) {
        nbrec_nat_set_logical_port(nat, logical_port);
        nbrec_nat_set_external_mac(nat, external_mac);
    }

    if (port_range) {
        nbrec_nat_set_external_port_range(nat, port_range);
    }

    smap_add(&nat_options, "stateless", stateless ? "true":"false");
    nbrec_nat_set_options(nat, &nat_options);

    smap_destroy(&nat_options);

    /* Insert the NAT into the logical router. */
    nbrec_logical_router_update_nat_addvalue(lr, nat);

cleanup:
    free(new_logical_ip);
    free(new_external_ip);
}

static void
nbctl_pre_lr_nat_del(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_nat);

    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_type);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_logical_ip);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_external_ip);
}

static void
nbctl_lr_nat_del(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr = NULL;
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    if (ctx->argc == 2) {
        /* If type, external_ip and logical_ip are not specified, delete
         * all NATs. */
        nbrec_logical_router_verify_nat(lr);
        nbrec_logical_router_set_nat(lr, NULL, 0);
        return;
    }

    const char *nat_type = ctx->argv[2];
    if (strcmp(nat_type, "dnat") && strcmp(nat_type, "snat")
            && strcmp(nat_type, "dnat_and_snat")) {
        ctl_error(ctx, "%s: type must be one of \"dnat\", \"snat\" and "
                  "\"dnat_and_snat\".", nat_type);
        return;
    }

    if (ctx->argc == 3) {
        /*Deletes all NATs with the specified type. */
        for (size_t i = 0; i < lr->n_nat; i++) {
            if (!strcmp(nat_type, lr->nat[i]->type)) {
                nbrec_logical_router_update_nat_delvalue(lr, lr->nat[i]);
            }
        }
        return;
    }

    char *nat_ip = normalize_prefix_str(ctx->argv[3]);
    if (!nat_ip) {
        ctl_error(ctx, "%s: Invalid IP address or CIDR", ctx->argv[3]);
        return;
    }

    int is_snat = !strcmp("snat", nat_type);
    /* Remove the matching NAT. */
    for (size_t i = 0; i < lr->n_nat; i++) {
        struct nbrec_nat *nat = lr->nat[i];
        bool should_return = false;
        char *old_ip = normalize_prefix_str(is_snat
                                            ? nat->logical_ip
                                            : nat->external_ip);
        if (!old_ip) {
            continue;
        }
        if (!strcmp(nat_type, nat->type) && !strcmp(nat_ip, old_ip)) {
            nbrec_logical_router_update_nat_delvalue(lr, nat);
            should_return = true;
        }
        free(old_ip);
        if (should_return) {
            goto cleanup;
        }
    }

    if (must_exist) {
        ctl_error(ctx, "no matching NAT with the type (%s) and %s (%s)",
                  nat_type, is_snat ? "logical_ip" : "external_ip", nat_ip);
    }

cleanup:
    free(nat_ip);
}

static void
nbctl_pre_lr_nat_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_nat);

    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_type);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_external_ip);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_external_port_range);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_logical_ip);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_external_mac);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_logical_port);
}

static void
nbctl_lr_nat_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    struct smap lr_nats = SMAP_INITIALIZER(&lr_nats);
    for (size_t i = 0; i < lr->n_nat; i++) {
        const struct nbrec_nat *nat = lr->nat[i];
        char *key = xasprintf("%-17.13s%s", nat->type, nat->external_ip);
        if (nat->external_mac && nat->logical_port) {
            smap_add_format(&lr_nats, key, "%-17.13s%-22.18s%-21.17s%s",
                            nat->external_port_range,
                            nat->logical_ip, nat->external_mac,
                            nat->logical_port);
        } else {
            smap_add_format(&lr_nats, key, "%-17.13s%s",
                            nat->external_port_range,
                            nat->logical_ip);
        }
        free(key);
    }

    const struct smap_node **nodes = smap_sort(&lr_nats);
    if (nodes) {
        ds_put_format(&ctx->output,
                "%-17.13s%-19.15s%-17.13s%-22.18s%-21.17s%s\n",
                "TYPE", "EXTERNAL_IP", "EXTERNAL_PORT", "LOGICAL_IP",
                "EXTERNAL_MAC", "LOGICAL_PORT");
        for (size_t i = 0; i < smap_count(&lr_nats); i++) {
            const struct smap_node *node = nodes[i];
            ds_put_format(&ctx->output, "%-36.32s%s\n",
                    node->key, node->value);
        }
        free(nodes);
    }
    smap_destroy(&lr_nats);
}

static void
nbctl_pre_lr_nat_set_ext_ips(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_nat);

    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_logical_ip);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_external_ip);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_type);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_exempted_ext_ips);
    ovsdb_idl_add_column(ctx->idl, &nbrec_nat_col_allowed_ext_ips);

    ovsdb_idl_add_column(ctx->idl, &nbrec_address_set_col_name);
}

static void
nbctl_lr_nat_set_ext_ips(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr = NULL;
    const struct nbrec_address_set *addr_set = NULL;
    bool is_exempted = shash_find(&ctx->options, "--is-exempted");
    bool nat_found = false;

    if (ctx->argc < 5) {
        ctl_error(ctx, "Incomplete input, Required arguments are: "
                  "ROUTER TYPE IP ADDRESS_SET");
        return;
    }

    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    const char *nat_type = ctx->argv[2];
    if (strcmp(nat_type, "dnat") && strcmp(nat_type, "snat")
            && strcmp(nat_type, "dnat_and_snat")) {
        ctl_error(ctx, "%s: type must be one of \"dnat\", \"snat\" and "
                  "\"dnat_and_snat\".", nat_type);
        return;
    }

    error = address_set_by_name_or_uuid(ctx, ctx->argv[4], true, &addr_set);
    if (error) {
        ctx->error = error;
        return;
    }

    char *nat_ip = normalize_prefix_str(ctx->argv[3]);
    if (!nat_ip) {
        ctl_error(ctx, "%s: Invalid IP address or CIDR", ctx->argv[3]);
        return;
    }

    int is_snat = !strcmp("snat", nat_type);

    /* Update the matching NAT. */
    for (size_t i = 0; i < lr->n_nat; i++) {
        struct nbrec_nat *nat = lr->nat[i];
        char *old_ip = normalize_prefix_str(is_snat
                                            ? nat->logical_ip
                                            : nat->external_ip);

        if (!old_ip) {
            continue;
        }

        if (!strcmp(nat_type, nat->type) && !strcmp(nat_ip, old_ip)) {
            nat_found = true;
            nbrec_logical_router_verify_nat(lr);
            if (is_exempted) {
                nbrec_nat_set_exempted_ext_ips(nat, addr_set);
            } else {
                nbrec_nat_set_allowed_ext_ips(nat, addr_set);
            }
            free(nat_ip);
            free(old_ip);
            return;
        }
        free(old_ip);
    }

    if (!nat_found) {
        ctl_error(ctx, "%s: Could not locate nat rule for: %s.",
                  nat_type, nat_ip);
    }

    free(nat_ip);
}


static char * OVS_WARN_UNUSED_RESULT
lrp_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist,
                    const struct nbrec_logical_router_port **lrp_p)
{
    const struct nbrec_logical_router_port *lrp = NULL;
    *lrp_p = NULL;

    struct uuid lrp_uuid;
    bool is_uuid = uuid_from_string(&lrp_uuid, id);
    if (is_uuid) {
        lrp = nbrec_logical_router_port_get_for_uuid(ctx->idl, &lrp_uuid);
    }

    if (!lrp) {
        NBREC_LOGICAL_ROUTER_PORT_FOR_EACH(lrp, ctx->idl) {
            if (!strcmp(lrp->name, id)) {
                break;
            }
        }
    }

    if (!lrp && must_exist) {
        return xasprintf("%s: port %s not found",
                         id, is_uuid ? "UUID" : "name");
    }

    *lrp_p = lrp;
    return NULL;
}

/* Returns the logical router that contains 'lrp'. */
static char * OVS_WARN_UNUSED_RESULT
lrp_to_lr(struct ctl_context *ctx,
          const struct nbrec_logical_router_port *lrp,
          const struct nbrec_logical_router **lr_p)
{
    struct nbctl_context *nbctx = nbctl_context_get(ctx);
    const struct nbrec_logical_router *lr;
    *lr_p = NULL;

    lr = shash_find_data(&nbctx->lrp_to_lr_map, lrp->name);
    if (lr) {
        *lr_p = lr;
        return NULL;
    }

    /* Can't happen because of the database schema */
    return xasprintf("port %s is not part of any logical router",
                     lrp->name);
}

static const char *
lr_get_name(const struct nbrec_logical_router *lr, char uuid_s[UUID_LEN + 1],
            size_t uuid_s_size)
{
    if (lr->name[0]) {
        return lr->name;
    }
    snprintf(uuid_s, uuid_s_size, UUID_FMT, UUID_ARGS(&lr->header_.uuid));
    return uuid_s;
}

static char * OVS_WARN_UNUSED_RESULT
gc_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist,
                   const struct nbrec_gateway_chassis **gc_p)
{
    const struct nbrec_gateway_chassis *gc = NULL;
    *gc_p = NULL;

    struct uuid gc_uuid;
    bool is_uuid = uuid_from_string(&gc_uuid, id);
    if (is_uuid) {
        gc = nbrec_gateway_chassis_get_for_uuid(ctx->idl, &gc_uuid);
    }

    if (!gc) {
        NBREC_GATEWAY_CHASSIS_FOR_EACH (gc, ctx->idl) {
            if (!strcmp(gc->name, id)) {
                break;
            }
        }
    }

    if (!gc && must_exist) {
        return xasprintf("%s: gateway chassis %s not found", id,
                         is_uuid ? "UUID" : "name");
    }

    *gc_p = gc;
    return NULL;
}

static void
nbctl_pre_lrp_set_gateway_chassis(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_name);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_port_col_gateway_chassis);

    ovsdb_idl_add_column(ctx->idl, &nbrec_gateway_chassis_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_gateway_chassis_col_priority);
}

static void
nbctl_lrp_set_gateway_chassis(struct ctl_context *ctx)
{
    char *gc_name;
    int64_t priority = 0;
    const char *lrp_name = ctx->argv[1];
    const struct nbrec_logical_router_port *lrp = NULL;
    char *error = lrp_by_name_or_uuid(ctx, lrp_name, true, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lrp) {
        ctl_error(ctx, "router port %s is required", lrp_name);
        return;
    }

    const char *chassis_name = ctx->argv[2];
    if (ctx->argv[3]) {
        error = parse_priority(ctx->argv[3], &priority);
        if (error) {
            ctx->error = error;
            return;
        }
    }

    gc_name = xasprintf("%s-%s", lrp_name, chassis_name);
    const struct nbrec_gateway_chassis *existing_gc;
    error = gc_by_name_or_uuid(ctx, gc_name, false, &existing_gc);
    if (error) {
        ctx->error = error;
        free(gc_name);
        return;
    }
    if (existing_gc) {
        nbrec_gateway_chassis_set_priority(existing_gc, priority);
        free(gc_name);
        return;
    }

    /* Create the logical gateway chassis. */
    struct nbrec_gateway_chassis *gc
        = nbrec_gateway_chassis_insert(ctx->txn);
    nbrec_gateway_chassis_set_name(gc, gc_name);
    nbrec_gateway_chassis_set_chassis_name(gc, chassis_name);
    nbrec_gateway_chassis_set_priority(gc, priority);

    /* Insert the logical gateway chassis into the logical router port. */
    nbrec_logical_router_port_update_gateway_chassis_addvalue(lrp, gc);
    free(gc_name);
}

static void
nbctl_pre_lrp_del_gateway_chassis(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_name);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_port_col_gateway_chassis);

    ovsdb_idl_add_column(ctx->idl, &nbrec_gateway_chassis_col_chassis_name);
}

/* Removes logical router port 'lrp->gateway_chassis[idx]'. */
static void
remove_gc(const struct nbrec_logical_router_port *lrp, size_t idx)
{
    const struct nbrec_gateway_chassis *gc = lrp->gateway_chassis[idx];

    if (lrp->n_gateway_chassis == 1) {
        nbrec_logical_router_port_set_gateway_chassis(lrp, NULL, 0);
    } else {
        /* First remove 'gc' from the array of gateway_chassis.  This is what
         * will actually cause the gateway chassis to be deleted when the
         * transaction is sent to the database server (due to garbage
         * collection). */
        nbrec_logical_router_port_update_gateway_chassis_delvalue(lrp, gc);
    }

    /* Delete 'gc' from the IDL.  This won't have a real effect on
     * the database server (the IDL will suppress it in fact) but it
     * means that it won't show up when we iterate with
     * NBREC_GATEWAY_CHASSIS_FOR_EACH later. */
    nbrec_gateway_chassis_delete(gc);
}

static void
nbctl_lrp_del_gateway_chassis(struct ctl_context *ctx)
{
    const struct nbrec_logical_router_port *lrp = NULL;
    char *error = lrp_by_name_or_uuid(ctx, ctx->argv[1], true, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lrp) {
        return;
    }
    /* Find the lrp that contains 'gc', then delete it. */
    const char *chassis_name = ctx->argv[2];
    for (size_t i = 0; i < lrp->n_gateway_chassis; i++) {
        if (!strncmp(lrp->gateway_chassis[i]->chassis_name,
                    chassis_name,
                    strlen(lrp->gateway_chassis[i]->chassis_name))) {
            remove_gc(lrp, i);
            return;
        }
    }

    /* Can't happen because of the database schema. */
    ctl_error(ctx, "chassis %s is not added to logical port %s",
              chassis_name, ctx->argv[1]);
}

static void
nbctl_pre_lrp_get_gateway_chassis(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_name);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_port_col_gateway_chassis);

    ovsdb_idl_add_column(ctx->idl, &nbrec_gateway_chassis_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_gateway_chassis_col_priority);
}

/* Print a list of gateway chassis. */
static void
nbctl_lrp_get_gateway_chassis(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router_port *lrp = NULL;
    const struct nbrec_gateway_chassis **gcs;
    size_t i;

    char *error = lrp_by_name_or_uuid(ctx, id, true, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    gcs = get_ordered_gw_chassis_prio_list(lrp);

    for (i = 0; i < lrp->n_gateway_chassis; i++) {
        const struct nbrec_gateway_chassis *gc = gcs[i];
        ds_put_format(&ctx->output, "%s %5"PRId64"\n",
                      gc->name, gc->priority);
    }

    free(gcs);
}

static struct sset *
lrp_network_sset(const char **networks, int n_networks)
{
    struct sset *network_set = xzalloc(sizeof *network_set);
    sset_init(network_set);
    for (int i = 0; i < n_networks; i++) {
        char *norm = normalize_prefix_str(networks[i]);
        if (!norm) {
            sset_destroy(network_set);
            free(network_set);
            return NULL;
        }
        sset_add_and_free(network_set, norm);
    }
    return network_set;
}

static void
nbctl_pre_lrp_add(struct ctl_context *ctx)
{
    nbctl_pre_context(ctx);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_ports);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_networks);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_mac);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_peer);
}

static void
nbctl_lrp_add(struct ctl_context *ctx)
{
    bool may_exist = shash_find(&ctx->options, "--may-exist") != NULL;
    struct nbctl_context *nbctx = nbctl_context_get(ctx);

    const struct nbrec_logical_router *lr = NULL;
    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    const char *lrp_name = ctx->argv[2];
    const char *mac = ctx->argv[3];
    const char **networks = (const char **) &ctx->argv[4];

    int n_networks = ctx->argc - 4;
    for (int i = 4; i < ctx->argc; i++) {
        if (strchr(ctx->argv[i], '=')) {
            n_networks = i - 4;
            break;
        }
    }

    if (!n_networks) {
        ctl_error(ctx, "%s: router port requires specifying a network",
                  lrp_name);
        return;
    }

    char **settings = (char **) &ctx->argv[n_networks + 4];
    int n_settings = ctx->argc - 4 - n_networks;

    struct eth_addr ea;
    if (!eth_addr_from_string(mac, &ea)) {
        ctl_error(ctx, "%s: invalid mac address %s", lrp_name, mac);
        return;
    }

    const struct nbrec_logical_router_port *lrp;
    error = lrp_by_name_or_uuid(ctx, lrp_name, false, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (lrp) {
        if (!may_exist) {
            ctl_error(ctx, "%s: a port with this name already exists",
                      lrp_name);
            return;
        }

        const struct nbrec_logical_router *bound_lr;
        error = lrp_to_lr(ctx, lrp, &bound_lr);
        if (error) {
            ctx->error = error;
            return;
        }
        if (bound_lr != lr) {
            char uuid_s[UUID_LEN + 1];
            ctl_error(ctx, "%s: port already exists but in router %s",
                      lrp_name, lr_get_name(bound_lr, uuid_s, sizeof uuid_s));
            return;
        }

        struct eth_addr lrp_ea;
        eth_addr_from_string(lrp->mac, &lrp_ea);
        if (!eth_addr_equals(ea, lrp_ea)) {
            ctl_error(ctx, "%s: port already exists with mac %s", lrp_name,
                      lrp->mac);
            return;
        }

        struct sset *new_networks = lrp_network_sset(networks, n_networks);
        if (!new_networks) {
            ctl_error(ctx, "%s: Invalid networks configured", lrp_name);
            return;
        }
        struct sset *orig_networks = lrp_network_sset(
            (const char **)lrp->networks, lrp->n_networks);
        if (!orig_networks) {
            ctl_error(ctx, "%s: Existing port has invalid networks configured",
                      lrp_name);
            sset_destroy(new_networks);
            free(new_networks);
            return;
        }

        bool same_networks = sset_equals(orig_networks, new_networks);
        sset_destroy(orig_networks);
        free(orig_networks);
        sset_destroy(new_networks);
        free(new_networks);
        if (!same_networks) {
            ctl_error(ctx, "%s: port already exists with different network",
                      lrp_name);
            return;
        }

        /* Special-case sanity-check of peer ports. */
        const char *peer = NULL;
        for (int i = 0; i < n_settings; i++) {
            if (!strncmp(settings[i], "peer=", 5)) {
                peer = settings[i] + 5;
                break;
            }
        }

        if ((!peer != !lrp->peer) ||
                (lrp->peer && strcmp(peer, lrp->peer))) {
            ctl_error(ctx, "%s: port already exists with mismatching peer",
                      lrp_name);
            return;
        }

        return;
    }

    for (int i = 0; i < n_networks; i++) {
        ovs_be32 ipv4;
        unsigned int plen;
        error = ip_parse_cidr(networks[i], &ipv4, &plen);
        if (error) {
            free(error);
            struct in6_addr ipv6;
            error = ipv6_parse_cidr(networks[i], &ipv6, &plen);
            if (error) {
                free(error);
                ctl_error(ctx, "%s: invalid network address: %s", lrp_name,
                          networks[i]);
                return;
            }
        }
    }

    /* Create the logical port. */
    lrp = nbrec_logical_router_port_insert(ctx->txn);
    nbrec_logical_router_port_set_name(lrp, lrp_name);
    nbrec_logical_router_port_set_mac(lrp, mac);
    nbrec_logical_router_port_set_networks(lrp, networks, n_networks);

    for (int i = 0; i < n_settings; i++) {
        error = ctl_set_column("Logical_Router_Port", &lrp->header_,
                               settings[i], ctx->symtab);
        if (error) {
            ctx->error = error;
            return;
        }
    }

    /* Insert the logical port into the logical router. */
    nbrec_logical_router_update_ports_addvalue(lr, lrp);

    /* Updating runtime cache. */
    shash_add(&nbctx->lrp_to_lr_map, lrp->name, lr);
}

/* Removes logical router port 'lrp' from logical router 'lr'. */
static void
remove_lrp(struct ctl_context *ctx,
           const struct nbrec_logical_router *lr,
           const struct nbrec_logical_router_port *lrp)
{
    struct nbctl_context *nbctx = nbctl_context_get(ctx);

    /* Updating runtime cache. */
    shash_find_and_delete(&nbctx->lrp_to_lr_map, lrp->name);

    /* First remove 'lrp' from the array of ports.  This is what will
     * actually cause the logical port to be deleted when the transaction is
     * sent to the database server (due to garbage collection). */
    nbrec_logical_router_update_ports_delvalue(lr, lrp);

    /* Delete 'lrp' from the IDL.  This won't have a real effect on
     * the database server (the IDL will suppress it in fact) but it
     * means that it won't show up when we iterate with
     * NBREC_LOGICAL_ROUTER_PORT_FOR_EACH later. */
    nbrec_logical_router_port_delete(lrp);
}

static void
nbctl_pre_lrp_del(struct ctl_context *ctx)
{
    nbctl_pre_context(ctx);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_name);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_ports);
}

static void
nbctl_lrp_del(struct ctl_context *ctx)
{
    bool must_exist = !shash_find(&ctx->options, "--if-exists");
    const struct nbrec_logical_router_port *lrp = NULL;

    char *error = lrp_by_name_or_uuid(ctx, ctx->argv[1], must_exist, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lrp) {
        return;
    }

    /* Find the router that contains 'lrp', then delete it. */
    const struct nbrec_logical_router *lr;

    error = lrp_to_lr(ctx, lrp, &lr);
    if (error) {
        ctx->error = error;
        return;
    }
    remove_lrp(ctx, lr, lrp);
}

static void
nbctl_pre_lrp_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_ports);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_name);
}

/* Print a list of logical router ports. */
static void
nbctl_lrp_list(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router *lr;
    struct smap lrps;
    size_t i;

    char *error = lr_by_name_or_uuid(ctx, id, true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    smap_init(&lrps);
    for (i = 0; i < lr->n_ports; i++) {
        const struct nbrec_logical_router_port *lrp = lr->ports[i];
        smap_add_format(&lrps, lrp->name, UUID_FMT " (%s)",
                        UUID_ARGS(&lrp->header_.uuid), lrp->name);
    }
    const struct smap_node **nodes = smap_sort(&lrps);
    for (i = 0; i < smap_count(&lrps); i++) {
        const struct smap_node *node = nodes[i];
        ds_put_format(&ctx->output, "%s\n", node->value);
    }
    smap_destroy(&lrps);
    free(nodes);
}

static void
nbctl_pre_lrp_enabled(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_enabled);
}

/* Set the logical router port admin-enabled state. */
static void
nbctl_lrp_set_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *state = ctx->argv[2];
    const struct nbrec_logical_router_port *lrp = NULL;

    char *error = lrp_by_name_or_uuid(ctx, id, true, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lrp) {
        return;
    }

    bool enabled;
    error = parse_enabled(state, &enabled);
    if (error) {
        ctx->error = error;
        return;
    }
    nbrec_logical_router_port_set_enabled(lrp, &enabled, 1);
}

/* Print admin-enabled state for logical router port. */
static void
nbctl_lrp_get_enabled(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router_port *lrp = NULL;

    char *error = lrp_by_name_or_uuid(ctx, id, true, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }
    if (!lrp) {
        return;
    }

    ds_put_format(&ctx->output, "%s\n",
                  !lrp->enabled ||
                  *lrp->enabled ? "enabled" : "disabled");
}

static void
nbctl_pre_lrp_redirect_type(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_port_col_options);
}

/* Set the logical router port redirect type. */
static void
nbctl_lrp_set_redirect_type(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const char *type = ctx->argv[2];
    const struct nbrec_logical_router_port *lrp = NULL;
    struct smap lrp_options;

    char *error = lrp_by_name_or_uuid(ctx, id, true, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }

    if (strcasecmp(type, "bridged") && strcasecmp(type, "overlay")) {
        error = xasprintf("Invalid redirect type: %s", type);
        ctx->error = error;
        return;
    }

    smap_init(&lrp_options);
    smap_clone(&lrp_options, &lrp->options);

    if (smap_get(&lrp_options, "redirect-type")) {
        smap_replace(&lrp_options, "redirect-type", type);
    } else {
        smap_add(&lrp_options, "redirect-type", type);
    }

    nbrec_logical_router_port_set_options(lrp, &lrp_options);

    smap_destroy(&lrp_options);
}

static void
nbctl_lrp_get_redirect_type(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_logical_router_port *lrp = NULL;

    char *error = lrp_by_name_or_uuid(ctx, id, true, &lrp);
    if (error) {
        ctx->error = error;
        return;
    }

    const char *redirect_type = smap_get(&lrp->options, "redirect-type");
    ds_put_format(&ctx->output, "%s\n",
                  !redirect_type ? "overlay": redirect_type);
}

static const struct nbrec_forwarding_group *
fwd_group_by_name_or_uuid(struct ctl_context *ctx, const char *id)
{
    const struct nbrec_forwarding_group *fwd_group = NULL;
    struct uuid fwd_uuid;

    bool is_uuid = uuid_from_string(&fwd_uuid, id);
    if (is_uuid) {
        fwd_group = nbrec_forwarding_group_get_for_uuid(ctx->idl, &fwd_uuid);
    }

    if (!fwd_group) {
        NBREC_FORWARDING_GROUP_FOR_EACH (fwd_group, ctx->idl) {
            if (!strcmp(fwd_group->name, id)) {
                break;
            }
        }
    }

    return fwd_group;
}

static const struct nbrec_logical_switch *
fwd_group_to_logical_switch(struct ctl_context *ctx,
                            const struct nbrec_forwarding_group *fwd_group)
{
    if (!fwd_group) {
        return NULL;
    }

    const struct nbrec_logical_switch_port *lsp;
    char *error = lsp_by_name_or_uuid(ctx, fwd_group->child_port[0],
                                      false, &lsp);
    if (error) {
        ctx->error = error;
        return NULL;
    }
    if (!lsp) {
        return NULL;
    }

    const struct nbrec_logical_switch *ls;
    error = lsp_to_ls(ctx, lsp, &ls);
    if (error) {
        ctx->error = error;
        return NULL;
    }

    if (!ls) {
        return NULL;
    }

    return ls;
}

static void
nbctl_pre_fwd_group_add(struct ctl_context *ctx)
{
    nbctl_pre_context(ctx);

    ovsdb_idl_add_column(ctx->idl, &nbrec_forwarding_group_col_name);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_switch_col_forwarding_groups);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
}

static void
nbctl_fwd_group_add(struct ctl_context *ctx)
{
    if (ctx->argc <= 5) {
        ctl_error(ctx, "Usage : ovn-nbctl fwd-group-add group switch vip vmac "
                  "child_ports...");
        return;
    }

    /* Check if the forwarding group already exists */
    const char *fwd_group_name = ctx->argv[1];
    if (fwd_group_by_name_or_uuid(ctx, fwd_group_name)) {
        ctl_error(ctx, "%s: a forwarding group by this name already exists",
                  fwd_group_name);
        return;
    }

    /* Check if the logical switch exists */
    const char *ls_name = ctx->argv[2];
    const struct nbrec_logical_switch *ls = NULL;
    char *error = ls_by_name_or_uuid(ctx, ls_name, true, &ls);
    if (error) {
        ctx->error = error;
        return;
    }

    /* Virtual IP for the group */
    ovs_be32 ipv4 = 0;
    const char *fwd_group_vip = ctx->argv[3];
    if (!ip_parse(fwd_group_vip, &ipv4)) {
        ctl_error(ctx, "invalid ip address %s", fwd_group_vip);
        return;
    }

    /* Virtual MAC for the group */
    const char *fwd_group_vmac = ctx->argv[4];
    struct eth_addr ea;
    if (!eth_addr_from_string(fwd_group_vmac, &ea)) {
        ctl_error(ctx, "invalid mac address %s", fwd_group_vmac);
        return;
    }

    /* Create the forwarding group */
    struct nbrec_forwarding_group *fwd_group = NULL;
    fwd_group = nbrec_forwarding_group_insert(ctx->txn);
    nbrec_forwarding_group_set_name(fwd_group, fwd_group_name);
    nbrec_forwarding_group_set_vip(fwd_group, fwd_group_vip);
    nbrec_forwarding_group_set_vmac(fwd_group, fwd_group_vmac);

    int n_child_port = ctx->argc - 5;
    const char **child_port = (const char **)&ctx->argv[5];

    /* Verify that child ports belong to the logical switch specified */
    for (int i = 5; i < ctx->argc; ++i) {
        const struct nbrec_logical_switch_port *lsp;
        const char *lsp_name = ctx->argv[i];
        error = lsp_by_name_or_uuid(ctx, lsp_name, false, &lsp);
        if (error) {
            ctx->error = error;
            return;
        }
        if (lsp) {
            error = lsp_to_ls(ctx, lsp, &ls);
            if (error) {
                ctx->error = error;
                return;
            }
            if (strcmp(ls->name, ls_name)) {
                ctl_error(ctx, "%s: port already exists but in logical "
                          "switch %s", lsp_name, ls->name);
                return;
            }
        } else {
            ctl_error(ctx, "%s: logical switch port does not exist", lsp_name);
            return;
        }
    }
    nbrec_forwarding_group_set_child_port(fwd_group, child_port, n_child_port);

    /* Liveness option */
    bool liveness = shash_find(&ctx->options, "--liveness") != NULL;
    if (liveness) {
      nbrec_forwarding_group_set_liveness(fwd_group, true);
    }

    nbrec_logical_switch_update_forwarding_groups_addvalue(ls, fwd_group);
}

static void
nbctl_pre_fwd_group_del(struct ctl_context *ctx)
{
    nbctl_pre_context(ctx);

    ovsdb_idl_add_column(ctx->idl, &nbrec_forwarding_group_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_forwarding_group_col_child_port);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_switch_col_forwarding_groups);
}

static void
nbctl_fwd_group_del(struct ctl_context *ctx)
{
    const char *id = ctx->argv[1];
    const struct nbrec_forwarding_group *fwd_group = NULL;

    fwd_group = fwd_group_by_name_or_uuid(ctx, id);
    if (!fwd_group) {
        return;
    }

    const struct nbrec_logical_switch *ls = NULL;
    ls = fwd_group_to_logical_switch(ctx, fwd_group);
    if (!ls) {
      return;
    }

    for (int i = 0; i < ls->n_forwarding_groups; ++i) {
        if (!strcmp(ls->forwarding_groups[i]->name, fwd_group->name)) {
            nbrec_logical_switch_update_forwarding_groups_delvalue(
                ls, ls->forwarding_groups[i]);
            nbrec_forwarding_group_delete(fwd_group);
            return;
        }
    }
}

static void
nbctl_pre_fwd_group_list(struct ctl_context *ctx)
{
    nbctl_pre_context(ctx);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_col_name);

    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);

    ovsdb_idl_add_column(ctx->idl, &nbrec_forwarding_group_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_forwarding_group_col_child_port);
    ovsdb_idl_add_column(ctx->idl, &nbrec_forwarding_group_col_vip);
    ovsdb_idl_add_column(ctx->idl, &nbrec_forwarding_group_col_vmac);
}

static void
fwd_group_list_all(struct ctl_context *ctx, const char *ls_name)
{
    const struct nbrec_logical_switch *ls;
    struct ds *s = &ctx->output;
    const struct nbrec_forwarding_group *fwd_group = NULL;

    if (ls_name) {
        char *error = ls_by_name_or_uuid(ctx, ls_name, true, &ls);
        if (error) {
            ctx->error = error;
            return;
        }
        if (!ls) {
            ctl_error(
                ctx, "%s: a logical switch with this name does not exist",
                ls_name);
            return;
        }
    }

    ds_put_format(s, "%-16.16s%-14.16s%-16.7s%-22.21s%s\n",
                  "FWD_GROUP", "LS", "VIP", "VMAC", "CHILD_PORTS");

    NBREC_FORWARDING_GROUP_FOR_EACH (fwd_group, ctx->idl) {
        ls = fwd_group_to_logical_switch(ctx, fwd_group);
        if (!ls) {
            continue;
        }

        if (ls_name && (strcmp(ls->name, ls_name))) {
            continue;
        }

        ds_put_format(s, "%-16.16s%-14.18s%-15.16s%-9.18s     ",
                      fwd_group->name, ls->name,
                      fwd_group->vip, fwd_group->vmac);
        for (int i = 0; i < fwd_group->n_child_port; ++i) {
            ds_put_format(s, " %s", fwd_group->child_port[i]);
        }
        ds_put_char(s, '\n');
    }
}

static void
nbctl_fwd_group_list(struct ctl_context *ctx)
{
    if (ctx->argc == 1) {
        fwd_group_list_all(ctx, NULL);
    } else if (ctx->argc == 2) {
        fwd_group_list_all(ctx, ctx->argv[1]);
    }
}


static int
route_cmp_details(const struct nbrec_logical_router_static_route *r1,
                  const struct nbrec_logical_router_static_route *r2)
{
    int ret = strcmp(r1->nexthop, r2->nexthop);
    if (ret) {
        return ret;
    }
    if (r1->output_port && r2->output_port) {
        ret = strcmp(r1->output_port, r2->output_port);
        if (ret) {
            return ret;
        }
        return 0;
    }
    if (!r1->output_port && !r2->output_port) {
        return 0;
    }
    return r1->output_port ? 1 : -1;
}
struct ipv4_route {
    int priority;
    ovs_be32 addr;
    const struct nbrec_logical_router_static_route *route;
};

static int
__ipv4_route_cmp(const struct ipv4_route *r1, const struct ipv4_route *r2)
{
    if (r1->priority != r2->priority) {
        return r1->priority > r2->priority ? -1 : 1;
    }
    if (r1->addr != r2->addr) {
        return ntohl(r1->addr) < ntohl(r2->addr) ? -1 : 1;
    }
    return 0;
}

static int
ipv4_route_cmp(const void *route1_, const void *route2_)
{
    const struct ipv4_route *route1p = route1_;
    const struct ipv4_route *route2p = route2_;

    int ret = __ipv4_route_cmp(route1p, route2p);
    if (ret) {
        return ret;
    }
    return route_cmp_details(route1p->route, route2p->route);
}

struct ipv6_route {
    int priority;
    struct in6_addr addr;
    const struct nbrec_logical_router_static_route *route;
};

static int
__ipv6_route_cmp(const struct ipv6_route *r1, const struct ipv6_route *r2)
{
    if (r1->priority != r2->priority) {
        return r1->priority > r2->priority ? -1 : 1;
    }
    return memcmp(&r1->addr, &r2->addr, sizeof(r1->addr));
}

static int
ipv6_route_cmp(const void *route1_, const void *route2_)
{
    const struct ipv6_route *route1p = route1_;
    const struct ipv6_route *route2p = route2_;

    int ret = __ipv6_route_cmp(route1p, route2p);
    if (ret) {
        return ret;
    }
    return route_cmp_details(route1p->route, route2p->route);
}

static void
print_route(const struct nbrec_logical_router_static_route *route,
            struct ds *s, bool ecmp)
{

    char *prefix = normalize_prefix_str(route->ip_prefix);
    char *next_hop = !strcmp(route->nexthop, "discard")
        ? xasprintf("discard")
        : normalize_prefix_str(route->nexthop);
    ds_put_format(s, "%25s %25s", prefix, next_hop);
    free(prefix);
    free(next_hop);

    if (route->policy) {
        ds_put_format(s, " %s", route->policy);
    } else {
        ds_put_format(s, " %s", "dst-ip");
    }

    if (route->output_port) {
        ds_put_format(s, " %s", route->output_port);
    }

    if (smap_get(&route->external_ids, "ic-learned-route")) {
        ds_put_format(s, " (learned)");
    }

    if (ecmp) {
        ds_put_cstr(s, " ecmp");
    }

    if (smap_get_bool(&route->options, "ecmp_symmetric_reply", false)) {
        ds_put_cstr(s, " ecmp-symmetric-reply");
    }

    if (route->bfd) {
        ds_put_cstr(s, " bfd");
    }

    ds_put_char(s, '\n');
}

static void
nbctl_pre_lr_route_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_router_col_static_routes);

    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_policy);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_ip_prefix);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_nexthop);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_output_port);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_external_ids);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_options);
    ovsdb_idl_add_column(ctx->idl,
                         &nbrec_logical_router_static_route_col_bfd);
}

static void
nbctl_lr_route_list(struct ctl_context *ctx)
{
    const struct nbrec_logical_router *lr;
    struct ipv4_route *ipv4_routes;
    struct ipv6_route *ipv6_routes;
    size_t n_ipv4_routes = 0;
    size_t n_ipv6_routes = 0;

    char *error = lr_by_name_or_uuid(ctx, ctx->argv[1], true, &lr);
    if (error) {
        ctx->error = error;
        return;
    }

    ipv4_routes = xmalloc(sizeof *ipv4_routes * lr->n_static_routes);
    ipv6_routes = xmalloc(sizeof *ipv6_routes * lr->n_static_routes);

    for (int i = 0; i < lr->n_static_routes; i++) {
        const struct nbrec_logical_router_static_route *route
            = lr->static_routes[i];
        unsigned int plen;
        ovs_be32 ipv4;
        const char *policy = route->policy ? route->policy : "dst-ip";
        error = ip_parse_cidr(route->ip_prefix, &ipv4, &plen);
        if (!error) {
            ipv4_routes[n_ipv4_routes].priority = !strcmp(policy, "dst-ip")
                                                    ? (2 * plen) + 1
                                                    : 2 * plen;
            ipv4_routes[n_ipv4_routes].addr = ipv4;
            ipv4_routes[n_ipv4_routes].route = route;
            n_ipv4_routes++;
        } else {
            free(error);

            struct in6_addr ipv6;
            error = ipv6_parse_cidr(route->ip_prefix, &ipv6, &plen);
            if (!error) {
                ipv6_routes[n_ipv6_routes].priority = !strcmp(policy, "dst-ip")
                                                        ? (2 * plen) + 1
                                                        : 2 * plen;
                ipv6_routes[n_ipv6_routes].addr = ipv6;
                ipv6_routes[n_ipv6_routes].route = route;
                n_ipv6_routes++;
            } else {
                /* Invalid prefix. */
                VLOG_WARN("router "UUID_FMT" (%s) has invalid prefix: %s",
                          UUID_ARGS(&lr->header_.uuid), lr->name,
                          route->ip_prefix);
                free(error);
                continue;
            }
        }
    }

    qsort(ipv4_routes, n_ipv4_routes, sizeof *ipv4_routes, ipv4_route_cmp);
    qsort(ipv6_routes, n_ipv6_routes, sizeof *ipv6_routes, ipv6_route_cmp);

    if (n_ipv4_routes) {
        ds_put_cstr(&ctx->output, "IPv4 Routes\n");
    }
    for (int i = 0; i < n_ipv4_routes; i++) {
        bool ecmp = false;
        if (i < n_ipv4_routes - 1 &&
            !__ipv4_route_cmp(&ipv4_routes[i], &ipv4_routes[i + 1])) {
            ecmp = true;
        } else if (i > 0 &&
                   !__ipv4_route_cmp(&ipv4_routes[i],
                                     &ipv4_routes[i - 1])) {
            ecmp = true;
        }
        print_route(ipv4_routes[i].route, &ctx->output, ecmp);
    }

    if (n_ipv6_routes) {
        ds_put_format(&ctx->output, "%sIPv6 Routes\n",
                      n_ipv4_routes ?  "\n" : "");
    }
    for (int i = 0; i < n_ipv6_routes; i++) {
        bool ecmp = false;
        if (i < n_ipv6_routes - 1 &&
            !__ipv6_route_cmp(&ipv6_routes[i], &ipv6_routes[i + 1])) {
            ecmp = true;
        } else if (i > 0 &&
                   !__ipv6_route_cmp(&ipv6_routes[i],
                                     &ipv6_routes[i - 1])) {
            ecmp = true;
        }
        print_route(ipv6_routes[i].route, &ctx->output, ecmp);
    }

    free(ipv4_routes);
    free(ipv6_routes);
}

static void
verify_connections(struct ctl_context *ctx)
{
    const struct nbrec_nb_global *nb_global = nbrec_nb_global_first(ctx->idl);
    const struct nbrec_connection *conn;

    nbrec_nb_global_verify_connections(nb_global);

    NBREC_CONNECTION_FOR_EACH(conn, ctx->idl) {
        nbrec_connection_verify_target(conn);
    }
}

static void
pre_connection(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_nb_global_col_connections);
    ovsdb_idl_add_column(ctx->idl, &nbrec_connection_col_target);
    ovsdb_idl_add_column(ctx->idl, &nbrec_connection_col_inactivity_probe);
}

static void
cmd_get_connection(struct ctl_context *ctx)
{
    const struct nbrec_connection *conn;
    struct svec targets;
    size_t i;

    verify_connections(ctx);

    /* Print the targets in sorted order for reproducibility. */
    svec_init(&targets);

    NBREC_CONNECTION_FOR_EACH(conn, ctx->idl) {
        svec_add(&targets, conn->target);
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
    const struct nbrec_nb_global *nb_global = nbrec_nb_global_first(ctx->idl);
    const struct nbrec_connection *conn, *next;

    /* Delete Manager rows pointed to by 'connection_options' column. */
    NBREC_CONNECTION_FOR_EACH_SAFE(conn, next, ctx->idl) {
        nbrec_connection_delete(conn);
    }

    /* Delete 'Manager' row refs in 'manager_options' column. */
    nbrec_nb_global_set_connections(nb_global, NULL, 0);
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
    const struct nbrec_nb_global *nb_global = nbrec_nb_global_first(ctx->idl);
    struct nbrec_connection **connections;
    size_t i, conns=0;
    const char *inactivity_probe = shash_find_data(&ctx->options,
                                                   "--inactivity-probe");

    /* Insert each connection in a new row in Connection table. */
    connections = xmalloc(n * sizeof *connections);
    for (i = 0; i < n; i++) {
        if (stream_verify_name(targets[i]) &&
                   pstream_verify_name(targets[i])) {
            VLOG_WARN("target type \"%s\" is possibly erroneous", targets[i]);
        }

        connections[conns] = nbrec_connection_insert(ctx->txn);
        nbrec_connection_set_target(connections[conns], targets[i]);
        if (inactivity_probe) {
            int64_t msecs = atoll(inactivity_probe);
            nbrec_connection_set_inactivity_probe(connections[conns],
                                                  &msecs, 1);
        }
        conns++;
    }

    /* Store uuids of new connection rows in 'connection' column. */
    nbrec_nb_global_set_connections(nb_global, connections, conns);
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
    ovsdb_idl_add_column(ctx->idl, &nbrec_nb_global_col_ssl);

    ovsdb_idl_add_column(ctx->idl, &nbrec_ssl_col_private_key);
    ovsdb_idl_add_column(ctx->idl, &nbrec_ssl_col_certificate);
    ovsdb_idl_add_column(ctx->idl, &nbrec_ssl_col_ca_cert);
    ovsdb_idl_add_column(ctx->idl, &nbrec_ssl_col_bootstrap_ca_cert);
}

static void
cmd_get_ssl(struct ctl_context *ctx)
{
    const struct nbrec_nb_global *nb_global = nbrec_nb_global_first(ctx->idl);
    const struct nbrec_ssl *ssl = nbrec_ssl_first(ctx->idl);

    nbrec_nb_global_verify_ssl(nb_global);
    if (ssl) {
        nbrec_ssl_verify_private_key(ssl);
        nbrec_ssl_verify_certificate(ssl);
        nbrec_ssl_verify_ca_cert(ssl);
        nbrec_ssl_verify_bootstrap_ca_cert(ssl);

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
    ovsdb_idl_add_column(ctx->idl, &nbrec_nb_global_col_ssl);
}

static void
cmd_del_ssl(struct ctl_context *ctx)
{
    const struct nbrec_nb_global *nb_global = nbrec_nb_global_first(ctx->idl);
    const struct nbrec_ssl *ssl = nbrec_ssl_first(ctx->idl);

    if (ssl) {
        nbrec_nb_global_verify_ssl(nb_global);
        nbrec_ssl_delete(ssl);
        nbrec_nb_global_set_ssl(nb_global, NULL);
    }
}

static void
pre_cmd_set_ssl(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_nb_global_col_ssl);
}

static void
cmd_set_ssl(struct ctl_context *ctx)
{
    bool bootstrap = shash_find(&ctx->options, "--bootstrap");
    const struct nbrec_nb_global *nb_global = nbrec_nb_global_first(ctx->idl);
    const struct nbrec_ssl *ssl = nbrec_ssl_first(ctx->idl);

    nbrec_nb_global_verify_ssl(nb_global);
    if (ssl) {
        nbrec_ssl_delete(ssl);
    }
    ssl = nbrec_ssl_insert(ctx->txn);

    nbrec_ssl_set_private_key(ssl, ctx->argv[1]);
    nbrec_ssl_set_certificate(ssl, ctx->argv[2]);
    nbrec_ssl_set_ca_cert(ssl, ctx->argv[3]);

    nbrec_ssl_set_bootstrap_ca_cert(ssl, bootstrap);

    if (ctx->argc == 5) {
        nbrec_ssl_set_ssl_protocols(ssl, ctx->argv[4]);
    } else if (ctx->argc == 6) {
        nbrec_ssl_set_ssl_protocols(ssl, ctx->argv[4]);
        nbrec_ssl_set_ssl_ciphers(ssl, ctx->argv[5]);
    }

    nbrec_nb_global_set_ssl(nb_global, ssl);
}

static char *
set_ports_on_pg(struct ctl_context *ctx, const struct nbrec_port_group *pg,
                char **new_ports, size_t num_new_ports)
{
    struct nbrec_logical_switch_port **lports;
    lports = xmalloc(sizeof *lports * num_new_ports);

    size_t i;
    char *error = NULL;
    for (i = 0; i < num_new_ports; i++) {
        const struct nbrec_logical_switch_port *lsp;
        error = lsp_by_name_or_uuid(ctx, new_ports[i], true, &lsp);
        if (error) {
            goto out;
        }
        lports[i] = (struct nbrec_logical_switch_port *) lsp;
    }

    nbrec_port_group_set_ports(pg, lports, num_new_ports);

out:
    free(lports);
    return error;
}

static void
cmd_pre_pg_add(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);
}

static void
cmd_pg_add(struct ctl_context *ctx)
{
    const struct nbrec_port_group *pg;

    pg = nbrec_port_group_insert(ctx->txn);
    nbrec_port_group_set_name(pg, ctx->argv[1]);
    if (ctx->argc > 2) {
        ctx->error = set_ports_on_pg(ctx, pg, ctx->argv + 2, ctx->argc - 2);
    }
}

static void
cmd_pre_pg_set_ports(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_logical_switch_port_col_name);

    ovsdb_idl_add_column(ctx->idl, &nbrec_port_group_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_port_group_col_ports);
}

static void
cmd_pg_set_ports(struct ctl_context *ctx)
{
    const struct nbrec_port_group *pg;

    char *error;
    error = pg_by_name_or_uuid(ctx, ctx->argv[1], true, &pg);
    if (error) {
        ctx->error = error;
        return;
    }

    ctx->error = set_ports_on_pg(ctx, pg, ctx->argv + 2, ctx->argc - 2);
}

static void
cmd_pre_pg_del(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_port_group_col_name);
}

static void
cmd_pg_del(struct ctl_context *ctx)
{
    const struct nbrec_port_group *pg;

    char *error;
    error = pg_by_name_or_uuid(ctx, ctx->argv[1], true, &pg);
    if (error) {
        ctx->error = error;
        return;
    }

    nbrec_port_group_delete(pg);
}

static const struct nbrec_ha_chassis_group*
ha_chassis_group_by_name_or_uuid(struct ctl_context *ctx, const char *id,
                                 bool must_exist)
{
    struct uuid ch_grp_uuid;
    const struct nbrec_ha_chassis_group *ha_ch_grp = NULL;
    bool is_uuid = uuid_from_string(&ch_grp_uuid, id);
    if (is_uuid) {
        ha_ch_grp = nbrec_ha_chassis_group_get_for_uuid(ctx->idl,
                                                        &ch_grp_uuid);
    }

    if (!ha_ch_grp) {
        const struct nbrec_ha_chassis_group *iter;
        NBREC_HA_CHASSIS_GROUP_FOR_EACH (iter, ctx->idl) {
            if (!strcmp(iter->name, id)) {
                ha_ch_grp = iter;
                break;
            }
        }
    }

    if (!ha_ch_grp && must_exist) {
        ctx->error = xasprintf("%s: ha_chassi_group %s not found",
                               id, is_uuid ? "UUID" : "name");
    }

    return ha_ch_grp;
}

static void
cmd_ha_ch_grp_add(struct ctl_context *ctx)
{
    const char *name = ctx->argv[1];
    struct nbrec_ha_chassis_group *ha_ch_grp =
        nbrec_ha_chassis_group_insert(ctx->txn);
    nbrec_ha_chassis_group_set_name(ha_ch_grp, name);
}

static void
pre_ha_ch_grp_del(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_group_col_name);
}

static void
cmd_ha_ch_grp_del(struct ctl_context *ctx)
{
    const char *name_or_id = ctx->argv[1];

    const struct nbrec_ha_chassis_group *ha_ch_grp =
        ha_chassis_group_by_name_or_uuid(ctx, name_or_id, true);

    if (ha_ch_grp) {
        nbrec_ha_chassis_group_delete(ha_ch_grp);
    }
}

static void
pre_ha_ch_grp_list(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_group_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_group_col_ha_chassis);

    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_col_chassis_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_col_priority);
}

static void
cmd_ha_ch_grp_list(struct ctl_context *ctx)
{
    const struct nbrec_ha_chassis_group *ha_ch_grp;

    NBREC_HA_CHASSIS_GROUP_FOR_EACH (ha_ch_grp, ctx->idl) {
        ds_put_format(&ctx->output, UUID_FMT " (%s)\n",
                      UUID_ARGS(&ha_ch_grp->header_.uuid), ha_ch_grp->name);
        const struct nbrec_ha_chassis *ha_ch;
        for (size_t i = 0; i < ha_ch_grp->n_ha_chassis; i++) {
            ha_ch = ha_ch_grp->ha_chassis[i];
            ds_put_format(&ctx->output,
                          "    "UUID_FMT " (%s)\n"
                          "    priority %"PRId64"\n\n",
                          UUID_ARGS(&ha_ch->header_.uuid), ha_ch->chassis_name,
                          ha_ch->priority);
        }
        ds_put_cstr(&ctx->output, "\n");
    }
}

static void
pre_ha_ch_grp_add_chassis(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_group_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_group_col_ha_chassis);

    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_col_chassis_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_col_priority);
}

static void
cmd_ha_ch_grp_add_chassis(struct ctl_context *ctx)
{
    const struct nbrec_ha_chassis_group *ha_ch_grp =
        ha_chassis_group_by_name_or_uuid(ctx, ctx->argv[1], true);

    if (!ha_ch_grp) {
        return;
    }

    const char *chassis_name = ctx->argv[2];
    int64_t priority;
    char *error = parse_priority(ctx->argv[3], &priority);
    if (error) {
        ctx->error = error;
        return;
    }

    struct nbrec_ha_chassis *ha_chassis = NULL;
    for (size_t i = 0; i < ha_ch_grp->n_ha_chassis; i++) {
        if (!strcmp(ha_ch_grp->ha_chassis[i]->chassis_name, chassis_name)) {
            ha_chassis = ha_ch_grp->ha_chassis[i];
            break;
        }
    }

    if (ha_chassis) {
        nbrec_ha_chassis_set_priority(ha_chassis, priority);
        return;
    }

    ha_chassis = nbrec_ha_chassis_insert(ctx->txn);
    nbrec_ha_chassis_set_chassis_name(ha_chassis, chassis_name);
    nbrec_ha_chassis_set_priority(ha_chassis, priority);

    nbrec_ha_chassis_group_update_ha_chassis_addvalue(ha_ch_grp, ha_chassis);
}

static void
pre_ha_ch_grp_remove_chassis(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_group_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_group_col_ha_chassis);

    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_col_chassis_name);
}

static void
cmd_ha_ch_grp_remove_chassis(struct ctl_context *ctx)
{
    const struct nbrec_ha_chassis_group *ha_ch_grp =
        ha_chassis_group_by_name_or_uuid(ctx, ctx->argv[1], true);

    if (!ha_ch_grp) {
        return;
    }

    const char *chassis_name = ctx->argv[2];
    struct nbrec_ha_chassis *ha_chassis = NULL;
    for (size_t i = 0; i < ha_ch_grp->n_ha_chassis; i++) {
        if (!strcmp(ha_ch_grp->ha_chassis[i]->chassis_name, chassis_name)) {
            ha_chassis = ha_ch_grp->ha_chassis[i];
            break;
        }
    }

    if (!ha_chassis) {
        ctx->error = xasprintf("%s: ha chassis not found in %s ha "
                               "chassis group", chassis_name, ctx->argv[1]);
        return;
    }

    nbrec_ha_chassis_group_update_ha_chassis_delvalue(ha_ch_grp, ha_chassis);
    nbrec_ha_chassis_delete(ha_chassis);
}

static void
pre_ha_ch_grp_set_chassis_prio(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_group_col_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_group_col_ha_chassis);

    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_col_chassis_name);
    ovsdb_idl_add_column(ctx->idl, &nbrec_ha_chassis_col_priority);
}

static void
cmd_ha_ch_grp_set_chassis_prio(struct ctl_context *ctx)
{
    const struct nbrec_ha_chassis_group *ha_ch_grp =
        ha_chassis_group_by_name_or_uuid(ctx, ctx->argv[1], true);

    if (!ha_ch_grp) {
        return;
    }

    int64_t priority;
    char *error = parse_priority(ctx->argv[3], &priority);
    if (error) {
        ctx->error = error;
        return;
    }

    const char *chassis_name = ctx->argv[2];
    struct nbrec_ha_chassis *ha_chassis = NULL;

    for (size_t i = 0; i < ha_ch_grp->n_ha_chassis; i++) {
        if (!strcmp(ha_ch_grp->ha_chassis[i]->chassis_name, chassis_name)) {
            ha_chassis = ha_ch_grp->ha_chassis[i];
            break;
        }
    }

    if (!ha_chassis) {
        ctx->error = xasprintf("%s: ha chassis not found in %s ha "
                               "chassis group", chassis_name, ctx->argv[1]);
        return;
    }

    nbrec_ha_chassis_set_priority(ha_chassis, priority);
}

static const struct ctl_table_class tables[NBREC_N_TABLES] = {
    [NBREC_TABLE_DHCP_OPTIONS].row_ids
    = {{&nbrec_logical_switch_port_col_name, NULL,
        &nbrec_logical_switch_port_col_dhcpv4_options},
       {&nbrec_logical_switch_port_col_external_ids,
        "neutron:port_name", &nbrec_logical_switch_port_col_dhcpv4_options},
       {&nbrec_logical_switch_port_col_name, NULL,
        &nbrec_logical_switch_port_col_dhcpv6_options},
       {&nbrec_logical_switch_port_col_external_ids,
        "neutron:port_name", &nbrec_logical_switch_port_col_dhcpv6_options}},

    [NBREC_TABLE_LOGICAL_SWITCH].row_ids
    = {{&nbrec_logical_switch_col_name, NULL, NULL},
       {&nbrec_logical_switch_col_external_ids, "neutron:network_name", NULL}},

    [NBREC_TABLE_LOGICAL_SWITCH_PORT].row_ids
    = {{&nbrec_logical_switch_port_col_name, NULL, NULL},
       {&nbrec_logical_switch_port_col_external_ids,
        "neutron:port_name", NULL}},

    [NBREC_TABLE_LOGICAL_ROUTER].row_ids
    = {{&nbrec_logical_router_col_name, NULL, NULL},
       {&nbrec_logical_router_col_external_ids, "neutron:router_name", NULL}},

    [NBREC_TABLE_LOGICAL_ROUTER_PORT].row_ids[0]
    = {&nbrec_logical_router_port_col_name, NULL, NULL},

    [NBREC_TABLE_ADDRESS_SET].row_ids[0]
    = {&nbrec_address_set_col_name, NULL, NULL},

    [NBREC_TABLE_PORT_GROUP].row_ids[0]
    = {&nbrec_port_group_col_name, NULL, NULL},

    [NBREC_TABLE_ACL].row_ids[0] = {&nbrec_acl_col_name, NULL, NULL},

    [NBREC_TABLE_HA_CHASSIS].row_ids[0]
    = {&nbrec_ha_chassis_col_chassis_name, NULL, NULL},

    [NBREC_TABLE_HA_CHASSIS_GROUP].row_ids[0]
    = {&nbrec_ha_chassis_group_col_name, NULL, NULL},

    [NBREC_TABLE_LOAD_BALANCER].row_ids[0]
    = {&nbrec_load_balancer_col_name, NULL, NULL},

    [NBREC_TABLE_LOAD_BALANCER_HEALTH_CHECK].row_ids[0]
    = {&nbrec_load_balancer_health_check_col_vip, NULL, NULL},

    [NBREC_TABLE_FORWARDING_GROUP].row_ids[0]
    = {&nbrec_forwarding_group_col_name, NULL, NULL},

    [NBREC_TABLE_METER].row_ids[0]
    = {&nbrec_meter_col_name, NULL, NULL},

    [NBREC_TABLE_NAT].row_ids[0]
    = {&nbrec_nat_col_external_ip, NULL, NULL},

    [NBREC_TABLE_CONNECTION].row_ids[0]
    = {&nbrec_connection_col_target, NULL, NULL},
};

static const struct ctl_command_syntax nbctl_commands[] = {
    { "init", 0, 0, "", NULL, nbctl_init, NULL, "", RW },
    { "sync", 0, 0, "", nbctl_pre_sync, nbctl_sync, NULL, "", RO },
    { "show", 0, 1, "[SWITCH]", nbctl_pre_show, nbctl_show, NULL, "", RO },

    /* logical switch commands. */
    { "ls-add", 0, 1, "[SWITCH]", nbctl_pre_ls_add, nbctl_ls_add, NULL,
      "--may-exist,--add-duplicate", RW },
    { "ls-del", 1, 1, "SWITCH", nbctl_pre_ls_del, nbctl_ls_del, NULL, "--if-exists", RW },
    { "ls-list", 0, 0, "", nbctl_pre_ls_list, nbctl_ls_list, NULL, "", RO },

    /* acl commands. */
    { "acl-add", 5, 6, "{SWITCH | PORTGROUP} DIRECTION PRIORITY MATCH ACTION",
      nbctl_pre_acl, nbctl_acl_add, NULL,
      "--log,--may-exist,--type=,--name=,--severity=,--meter=", RW },
    { "acl-del", 1, 4, "{SWITCH | PORTGROUP} [DIRECTION [PRIORITY MATCH]]",
      nbctl_pre_acl, nbctl_acl_del, NULL, "--type=", RW },
    { "acl-list", 1, 1, "{SWITCH | PORTGROUP}",
      nbctl_pre_acl_list, nbctl_acl_list, NULL, "--type=", RO },

    /* qos commands. */
    { "qos-add", 5, 7,
      "SWITCH DIRECTION PRIORITY MATCH [rate=RATE [burst=BURST]] [dscp=DSCP]",
      nbctl_pre_qos_add, nbctl_qos_add, NULL, "--may-exist", RW },
    { "qos-del", 1, 4, "SWITCH [{DIRECTION | UUID} [PRIORITY MATCH]]",
      nbctl_pre_qos_del, nbctl_qos_del, NULL, "", RW },
    { "qos-list", 1, 1, "SWITCH", nbctl_pre_qos_list, nbctl_qos_list,
      NULL, "", RO },

    /* meter commands. */
    { "meter-add", 4, 5, "NAME ACTION RATE UNIT [BURST]", nbctl_pre_meter_add,
      nbctl_meter_add, NULL, "--fair", RW },
    { "meter-del", 0, 1, "[NAME]", nbctl_pre_meter_del, nbctl_meter_del,
      NULL, "", RW },
    { "meter-list", 0, 0, "", nbctl_pre_meter_list, nbctl_meter_list,
      NULL, "", RO },

    /* logical switch port commands. */
    { "lsp-add", 2, 4, "SWITCH PORT [PARENT] [TAG]",
      nbctl_pre_lsp_add, nbctl_lsp_add, NULL, "--may-exist", RW },
    { "lsp-del", 1, 1, "PORT", nbctl_pre_lsp_del, nbctl_lsp_del,
      NULL, "--if-exists", RW },
    { "lsp-list", 1, 1, "SWITCH", nbctl_pre_lsp_list, nbctl_lsp_list,
      NULL, "", RO },
    { "lsp-get-parent", 1, 1, "PORT", nbctl_pre_lsp_get_parent,
      nbctl_lsp_get_parent, NULL, "", RO },
    { "lsp-get-tag", 1, 1, "PORT", nbctl_pre_lsp_get_tag, nbctl_lsp_get_tag,
      NULL, "", RO },
    { "lsp-set-addresses", 1, INT_MAX, "PORT [ADDRESS]...",
      nbctl_pre_lsp_set_addresses, nbctl_lsp_set_addresses, NULL, "", RW },
    { "lsp-get-addresses", 1, 1, "PORT", nbctl_pre_lsp_get_addresses,
      nbctl_lsp_get_addresses, NULL, "", RO },
    { "lsp-set-port-security", 0, INT_MAX, "PORT [ADDRS]...",
      nbctl_pre_lsp_port_security, nbctl_lsp_set_port_security,
      NULL, "", RW },
    { "lsp-get-port-security", 1, 1, "PORT", nbctl_pre_lsp_port_security,
      nbctl_lsp_get_port_security, NULL, "", RO },
    { "lsp-get-up", 1, 1, "PORT", nbctl_pre_lsp_get_up, nbctl_lsp_get_up,
      NULL, "", RO },
    { "lsp-set-enabled", 2, 2, "PORT STATE", nbctl_pre_lsp_enabled,
      nbctl_lsp_set_enabled, NULL, "", RW },
    { "lsp-get-enabled", 1, 1, "PORT", nbctl_pre_lsp_enabled,
      nbctl_lsp_get_enabled, NULL, "", RO },
    { "lsp-set-type", 2, 2, "PORT TYPE", nbctl_pre_lsp_type,
      nbctl_lsp_set_type, NULL, "", RW },
    { "lsp-get-type", 1, 1, "PORT", nbctl_pre_lsp_type,
      nbctl_lsp_get_type, NULL, "", RO },
    { "lsp-set-options", 1, INT_MAX, "PORT KEY=VALUE [KEY=VALUE]...",
      nbctl_pre_lsp_options, nbctl_lsp_set_options, NULL, "", RW },
    { "lsp-get-options", 1, 1, "PORT", nbctl_pre_lsp_options,
      nbctl_lsp_get_options, NULL, "", RO },
    { "lsp-set-dhcpv4-options", 1, 2, "PORT [DHCP_OPT_UUID]",
      nbctl_pre_lsp_dhcpv4_options, nbctl_lsp_set_dhcpv4_options,
      NULL, "", RW },
    { "lsp-get-dhcpv4-options", 1, 1, "PORT", nbctl_pre_lsp_dhcpv4_options,
      nbctl_lsp_get_dhcpv4_options, NULL, "", RO },
    { "lsp-set-dhcpv6-options", 1, 2, "PORT [DHCP_OPT_UUID]",
      nbctl_pre_lsp_dhcpv6_options, nbctl_lsp_set_dhcpv6_options,
      NULL, "", RW },
    { "lsp-get-dhcpv6-options", 1, 1, "PORT", nbctl_pre_lsp_dhcpv6_options,
      nbctl_lsp_get_dhcpv6_options, NULL, "", RO },
    { "lsp-get-ls", 1, 1, "PORT", nbctl_pre_lsp_get_ls, nbctl_lsp_get_ls,
      NULL, "", RO },

    /* forwarding group commands. */
    { "fwd-group-add", 4, INT_MAX, "SWITCH GROUP VIP VMAC PORT...",
      nbctl_pre_fwd_group_add, nbctl_fwd_group_add, NULL, "--liveness", RW },
    { "fwd-group-del", 1, 1, "GROUP", nbctl_pre_fwd_group_del,
      nbctl_fwd_group_del, NULL, "--if-exists", RW },
    { "fwd-group-list", 0, 1, "[GROUP]", nbctl_pre_fwd_group_list,
      nbctl_fwd_group_list, NULL, "", RO },

    /* logical router commands. */
    { "lr-add", 0, 1, "[ROUTER]", nbctl_pre_lr_add, nbctl_lr_add, NULL,
      "--may-exist,--add-duplicate", RW },
    { "lr-del", 1, 1, "ROUTER", nbctl_pre_lr_del, nbctl_lr_del,
      NULL, "--if-exists", RW },
    { "lr-list", 0, 0, "", nbctl_pre_lr_list, nbctl_lr_list, NULL, "", RO },

    /* logical router port commands. */
    { "lrp-add", 4, INT_MAX,
      "ROUTER PORT MAC NETWORK... [COLUMN[:KEY]=VALUE]...",
      nbctl_pre_lrp_add, nbctl_lrp_add, NULL, "--may-exist", RW },
    { "lrp-set-gateway-chassis", 2, 3,
      "PORT CHASSIS [PRIORITY]",
      nbctl_pre_lrp_set_gateway_chassis, nbctl_lrp_set_gateway_chassis,
      NULL, "--may-exist", RW },
    { "lrp-del-gateway-chassis", 2, 2, "PORT CHASSIS",
      nbctl_pre_lrp_del_gateway_chassis, nbctl_lrp_del_gateway_chassis,
      NULL, "", RW },
    { "lrp-get-gateway-chassis", 1, 1, "PORT",
      nbctl_pre_lrp_get_gateway_chassis, nbctl_lrp_get_gateway_chassis,
      NULL, "", RO },
    { "lrp-del", 1, 1, "PORT", nbctl_pre_lrp_del, nbctl_lrp_del,
      NULL, "--if-exists", RW },
    { "lrp-list", 1, 1, "ROUTER", nbctl_pre_lrp_list, nbctl_lrp_list,
      NULL, "", RO },
    { "lrp-set-enabled", 2, 2, "PORT STATE", nbctl_pre_lrp_enabled,
      nbctl_lrp_set_enabled, NULL, "", RW },
    { "lrp-get-enabled", 1, 1, "PORT", nbctl_pre_lrp_enabled,
      nbctl_lrp_get_enabled, NULL, "", RO },
    { "lrp-set-redirect-type", 2, 2, "PORT TYPE",
      nbctl_pre_lrp_redirect_type, nbctl_lrp_set_redirect_type,
      NULL, "", RW },
    { "lrp-get-redirect-type", 1, 1, "PORT", nbctl_pre_lrp_redirect_type,
      nbctl_lrp_get_redirect_type, NULL, "", RO },

    /* logical router route commands. */
    { "lr-route-add", 3, 4, "ROUTER PREFIX NEXTHOP [PORT]",
      nbctl_pre_lr_route_add, nbctl_lr_route_add, NULL,
      "--may-exist,--ecmp,--ecmp-symmetric-reply,--policy=,--bfd?", RW },
    { "lr-route-del", 1, 4, "ROUTER [PREFIX [NEXTHOP [PORT]]]",
      nbctl_pre_lr_route_del, nbctl_lr_route_del, NULL,
      "--if-exists,--policy=", RW },
    { "lr-route-list", 1, 1, "ROUTER", nbctl_pre_lr_route_list,
      nbctl_lr_route_list, NULL, "", RO },

    /* Policy commands */
    { "lr-policy-add", 4, INT_MAX,
     "ROUTER PRIORITY MATCH ACTION [NEXTHOP] [OPTIONS - KEY=VALUE ...]",
     nbctl_pre_lr_policy_add, nbctl_lr_policy_add, NULL, "--may-exist", RW },
    { "lr-policy-del", 1, 3, "ROUTER [{PRIORITY | UUID} [MATCH]]",
      nbctl_pre_lr_policy_del, nbctl_lr_policy_del, NULL, "--if-exists", RW },
    { "lr-policy-list", 1, 1, "ROUTER", nbctl_pre_lr_policy_list,
      nbctl_lr_policy_list, NULL, "", RO },

    /* NAT commands. */
    { "lr-nat-add", 4, 7,
      "ROUTER TYPE EXTERNAL_IP LOGICAL_IP"
      "[LOGICAL_PORT EXTERNAL_MAC] [EXTERNAL_PORT_RANGE]",
      nbctl_pre_lr_nat_add, nbctl_lr_nat_add,
      NULL, "--may-exist,--stateless,--portrange", RW },
    { "lr-nat-del", 1, 3, "ROUTER [TYPE [IP]]",
      nbctl_pre_lr_nat_del, nbctl_lr_nat_del, NULL, "--if-exists", RW },
    { "lr-nat-list", 1, 1, "ROUTER", nbctl_pre_lr_nat_list,
      nbctl_lr_nat_list, NULL, "", RO },
    { "lr-nat-update-ext-ip", 4, 4, "ROUTER TYPE IP ADDRESS_SET",
      nbctl_pre_lr_nat_set_ext_ips, nbctl_lr_nat_set_ext_ips,
      NULL, "--is-exempted", RW},
    /* load balancer commands. */
    { "lb-add", 3, 4, "LB VIP[:PORT] IP[:PORT]... [PROTOCOL]",
      nbctl_pre_lb_add, nbctl_lb_add, NULL,
      "--may-exist,--add-duplicate,--reject,--event", RW },
    { "lb-del", 1, 2, "LB [VIP]", nbctl_pre_lb_del, nbctl_lb_del, NULL,
        "--if-exists", RW },
    { "lb-list", 0, 1, "[LB]", nbctl_pre_lb_list, nbctl_lb_list, NULL, "", RO },
    { "lr-lb-add", 2, 2, "ROUTER LB", nbctl_pre_lr_lb_add,
      nbctl_lr_lb_add, NULL, "--may-exist", RW },
    { "lr-lb-del", 1, 2, "ROUTER [LB]", nbctl_pre_lr_lb_del,
      nbctl_lr_lb_del, NULL, "--if-exists", RW },
    { "lr-lb-list", 1, 1, "ROUTER", nbctl_pre_lr_lb_list,
      nbctl_lr_lb_list, NULL, "", RO },
    { "ls-lb-add", 2, 2, "SWITCH LB", nbctl_pre_ls_lb_add,
      nbctl_ls_lb_add, NULL, "--may-exist", RW },
    { "ls-lb-del", 1, 2, "SWITCH [LB]", nbctl_pre_ls_lb_del,
      nbctl_ls_lb_del, NULL, "--if-exists", RW },
    { "ls-lb-list", 1, 1, "SWITCH", nbctl_pre_ls_lb_list, nbctl_ls_lb_list,
      NULL, "", RO },

    /* DHCP_Options commands */
    {"dhcp-options-create", 1, INT_MAX, "CIDR [EXTERNAL:IDS]",
     NULL, nbctl_dhcp_options_create, NULL, "", RW },
    {"dhcp-options-del", 1, 1, "DHCP_OPT_UUID", nbctl_pre_dhcp_options_del,
     nbctl_dhcp_options_del, NULL, "", RW},
    {"dhcp-options-list", 0, 0, "", nbctl_pre_dhcp_options_list,
     nbctl_dhcp_options_list, NULL, "", RO},
    {"dhcp-options-set-options", 1, INT_MAX, "DHCP_OPT_UUID KEY=VALUE [KEY=VALUE]...",
    nbctl_pre_dhcp_options_options, nbctl_dhcp_options_set_options,
    NULL, "", RW },
    {"dhcp-options-get-options", 1, 1, "DHCP_OPT_UUID",
     nbctl_pre_dhcp_options_options, nbctl_dhcp_options_get_options,
     NULL, "", RO },

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

    /* Port Group Commands */
    {"pg-add", 1, INT_MAX, "", cmd_pre_pg_add, cmd_pg_add, NULL, "", RW },
    {"pg-set-ports", 2, INT_MAX, "", cmd_pre_pg_set_ports, cmd_pg_set_ports,
     NULL, "", RW },
    {"pg-del", 1, 1, "", cmd_pre_pg_del, cmd_pg_del, NULL, "", RW },

    /* HA chassis group commands. */
    {"ha-chassis-group-add", 1, 1, "[CHASSIS GROUP]",
     NULL, cmd_ha_ch_grp_add, NULL, "", RW },
    {"ha-chassis-group-del", 1, 1, "[CHASSIS GROUP]",
     pre_ha_ch_grp_del, cmd_ha_ch_grp_del, NULL, "", RW },
    {"ha-chassis-group-list", 0, 0, "[CHASSIS GROUP]",
     pre_ha_ch_grp_list, cmd_ha_ch_grp_list, NULL, "", RO },
    {"ha-chassis-group-add-chassis", 3, 3, "[CHASSIS GROUP]",
     pre_ha_ch_grp_add_chassis, cmd_ha_ch_grp_add_chassis, NULL, "", RW },
    {"ha-chassis-group-remove-chassis", 2, 2, "[CHASSIS GROUP]",
     pre_ha_ch_grp_remove_chassis, cmd_ha_ch_grp_remove_chassis, NULL, "", RW },
    {"ha-chassis-group-set-chassis-prio", 3, 3, "[CHASSIS GROUP]",
     pre_ha_ch_grp_set_chassis_prio, cmd_ha_ch_grp_set_chassis_prio, NULL,
     "", RW },

    {NULL, 0, 0, NULL, NULL, NULL, NULL, "", RO},
};

int
main(int argc, char *argv[])
{
    struct ovn_dbctl_options dbctl_options = {
        .db_version = nbrec_get_db_version(),
        .default_db = default_nb_db(),
        .allow_wait = true,

        .options_env_var_name = "OVN_NBCTL_OPTIONS",
        .daemon_env_var_name = "OVN_NB_DAEMON",

        .idl_class = &nbrec_idl_class,
        .tables = tables,
        .cmd_show_table = NULL,
        .commands = nbctl_commands,

        .usage = nbctl_usage,
        .add_base_prerequisites = nbctl_add_base_prerequisites,
        .pre_execute = nbctl_pre_execute,
        .post_execute = nbctl_post_execute,

        .ctx_create = nbctl_ctx_create,
        .ctx_destroy = nbctl_ctx_destroy,
    };

    return ovn_dbctl_main(argc, argv, &dbctl_options);
}
