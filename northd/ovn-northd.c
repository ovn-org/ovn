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
#include <stdlib.h>
#include <stdio.h>

#include "lib/chassis-index.h"
#include "command-line.h"
#include "daemon.h"
#include "fatal-signal.h"
#include "inc-proc-northd.h"
#include "lib/ip-mcast-index.h"
#include "lib/mcast-group-index.h"
#include "memory.h"
#include "northd.h"
#include "ovs-numa.h"
#include "ovsdb-idl.h"
#include "lib/ovn-l7.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "openvswitch/poll-loop.h"
#include "simap.h"
#include "stopwatch.h"
#include "lib/stopwatch-names.h"
#include "stream.h"
#include "stream-ssl.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "lib/ovn-parallel-hmap.h"

VLOG_DEFINE_THIS_MODULE(ovn_northd);

static unixctl_cb_func ovn_northd_exit;
static unixctl_cb_func ovn_northd_pause;
static unixctl_cb_func ovn_northd_resume;
static unixctl_cb_func ovn_northd_is_paused;
static unixctl_cb_func ovn_northd_status;
static unixctl_cb_func cluster_state_reset_cmd;
static unixctl_cb_func ovn_northd_set_thread_count_cmd;
static unixctl_cb_func ovn_northd_get_thread_count_cmd;

struct northd_state {
    bool had_lock;
    bool paused;
};

#define OVN_MAX_SUPPORTED_THREADS 256

static const char *ovnnb_db;
static const char *ovnsb_db;
static const char *unixctl_path;

/* SSL options */
static const char *ssl_private_key_file;
static const char *ssl_certificate_file;
static const char *ssl_ca_cert_file;

/* Default probe interval for NB and SB DB connections. */
#define DEFAULT_PROBE_INTERVAL_MSEC 5000
static int northd_probe_interval_nb = 0;
static int northd_probe_interval_sb = 0;

static const char *rbac_chassis_auth[] =
    {"name"};
static const char *rbac_chassis_update[] =
    {"nb_cfg", "external_ids", "encaps", "vtep_logical_switches",
     "other_config", "transport_zones"};

static const char *rbac_chassis_private_auth[] =
    {"name"};
static const char *rbac_chassis_private_update[] =
    {"nb_cfg", "nb_cfg_timestamp", "chassis", "external_ids"};

static const char *rbac_encap_auth[] =
    {"chassis_name"};
static const char *rbac_encap_update[] =
    {"type", "options", "ip"};

static const char *rbac_controller_event_auth[] =
    {""};
static const char *rbac_controller_event_update[] =
    {"chassis", "event_info", "event_type", "seq_num"};


static const char *rbac_fdb_auth[] =
    {""};
static const char *rbac_fdb_update[] =
    {"dp_key", "mac", "port_key"};

static const char *rbac_port_binding_auth[] =
    {""};
static const char *rbac_port_binding_update[] =
    {"chassis", "additional_chassis",
     "encap", "additional_encap",
     "up", "virtual_parent",
     /* NOTE: we only need to update the additional-chassis-activated key,
      * but RBAC_Role doesn't support mutate operation for subkeys. */
     "options"};

static const char *rbac_mac_binding_auth[] =
    {""};
static const char *rbac_mac_binding_update[] =
    {"logical_port", "ip", "mac", "datapath"};

static const char *rbac_svc_monitor_auth[] =
    {""};
static const char *rbac_svc_monitor_auth_update[] =
    {"status"};
static const char *rbac_igmp_group_auth[] =
    {""};
static const char *rbac_igmp_group_update[] =
    {"address", "chassis", "datapath", "ports"};

static struct rbac_perm_cfg {
    const char *table;
    const char **auth;
    int n_auth;
    bool insdel;
    const char **update;
    int n_update;
    const struct sbrec_rbac_permission *row;
} rbac_perm_cfg[] = {
    {
        .table = "Chassis",
        .auth = rbac_chassis_auth,
        .n_auth = ARRAY_SIZE(rbac_chassis_auth),
        .insdel = true,
        .update = rbac_chassis_update,
        .n_update = ARRAY_SIZE(rbac_chassis_update),
        .row = NULL
    },{
        .table = "Chassis_Private",
        .auth = rbac_chassis_private_auth,
        .n_auth = ARRAY_SIZE(rbac_chassis_private_auth),
        .insdel = true,
        .update = rbac_chassis_private_update,
        .n_update = ARRAY_SIZE(rbac_chassis_private_update),
        .row = NULL
    },{
        .table = "Controller_Event",
        .auth = rbac_controller_event_auth,
        .n_auth = ARRAY_SIZE(rbac_controller_event_auth),
        .insdel = true,
        .update = rbac_controller_event_update,
        .n_update = ARRAY_SIZE(rbac_controller_event_update),
        .row = NULL
    },{
        .table = "Encap",
        .auth = rbac_encap_auth,
        .n_auth = ARRAY_SIZE(rbac_encap_auth),
        .insdel = true,
        .update = rbac_encap_update,
        .n_update = ARRAY_SIZE(rbac_encap_update),
        .row = NULL
    },{
        .table = "FDB",
        .auth = rbac_fdb_auth,
        .n_auth = ARRAY_SIZE(rbac_fdb_auth),
        .insdel = true,
        .update = rbac_fdb_update,
        .n_update = ARRAY_SIZE(rbac_fdb_update),
        .row = NULL
    },{
        .table = "Port_Binding",
        .auth = rbac_port_binding_auth,
        .n_auth = ARRAY_SIZE(rbac_port_binding_auth),
        .insdel = false,
        .update = rbac_port_binding_update,
        .n_update = ARRAY_SIZE(rbac_port_binding_update),
        .row = NULL
    },{
        .table = "MAC_Binding",
        .auth = rbac_mac_binding_auth,
        .n_auth = ARRAY_SIZE(rbac_mac_binding_auth),
        .insdel = true,
        .update = rbac_mac_binding_update,
        .n_update = ARRAY_SIZE(rbac_mac_binding_update),
        .row = NULL
    },{
        .table = "Service_Monitor",
        .auth = rbac_svc_monitor_auth,
        .n_auth = ARRAY_SIZE(rbac_svc_monitor_auth),
        .insdel = false,
        .update = rbac_svc_monitor_auth_update,
        .n_update = ARRAY_SIZE(rbac_svc_monitor_auth_update),
        .row = NULL
    },{
        .table = "IGMP_Group",
        .auth = rbac_igmp_group_auth,
        .n_auth = ARRAY_SIZE(rbac_igmp_group_auth),
        .insdel = true,
        .update = rbac_igmp_group_update,
        .n_update = ARRAY_SIZE(rbac_igmp_group_update),
        .row = NULL
    },{
        .table = NULL,
        .auth = NULL,
        .n_auth = 0,
        .insdel = false,
        .update = NULL,
        .n_update = 0,
        .row = NULL
    }
};

static struct gen_opts_map supported_dhcp_opts[] = {
    OFFERIP,
    DHCP_OPT_NETMASK,
    DHCP_OPT_ROUTER,
    DHCP_OPT_DNS_SERVER,
    DHCP_OPT_LOG_SERVER,
    DHCP_OPT_LPR_SERVER,
    DHCP_OPT_SWAP_SERVER,
    DHCP_OPT_POLICY_FILTER,
    DHCP_OPT_ROUTER_SOLICITATION,
    DHCP_OPT_NIS_SERVER,
    DHCP_OPT_NTP_SERVER,
    DHCP_OPT_SERVER_ID,
    DHCP_OPT_TFTP_SERVER,
    DHCP_OPT_CLASSLESS_STATIC_ROUTE,
    DHCP_OPT_MS_CLASSLESS_STATIC_ROUTE,
    DHCP_OPT_IP_FORWARD_ENABLE,
    DHCP_OPT_ROUTER_DISCOVERY,
    DHCP_OPT_ETHERNET_ENCAP,
    DHCP_OPT_DEFAULT_TTL,
    DHCP_OPT_TCP_TTL,
    DHCP_OPT_MTU,
    DHCP_OPT_LEASE_TIME,
    DHCP_OPT_T1,
    DHCP_OPT_T2,
    DHCP_OPT_WPAD,
    DHCP_OPT_BOOTFILE,
    DHCP_OPT_PATH_PREFIX,
    DHCP_OPT_TFTP_SERVER_ADDRESS,
    DHCP_OPT_HOSTNAME,
    DHCP_OPT_DOMAIN_NAME,
    DHCP_OPT_ARP_CACHE_TIMEOUT,
    DHCP_OPT_TCP_KEEPALIVE_INTERVAL,
    DHCP_OPT_DOMAIN_SEARCH_LIST,
    DHCP_OPT_BOOTFILE_ALT,
    DHCP_OPT_BROADCAST_ADDRESS,
    DHCP_OPT_NETBIOS_NAME_SERVER,
    DHCP_OPT_NETBIOS_NODE_TYPE,
    DHCP_OPT_NEXT_SERVER,
};

static struct gen_opts_map supported_dhcpv6_opts[] = {
    DHCPV6_OPT_IA_ADDR,
    DHCPV6_OPT_SERVER_ID,
    DHCPV6_OPT_DOMAIN_SEARCH,
    DHCPV6_OPT_DNS_SERVER
};

static bool
ovn_rbac_validate_perm(const struct sbrec_rbac_permission *perm)
{
    struct rbac_perm_cfg *pcfg;
    int i, j, n_found;

    for (pcfg = rbac_perm_cfg; pcfg->table; pcfg++) {
        if (!strcmp(perm->table, pcfg->table)) {
            break;
        }
    }
    if (!pcfg->table) {
        return false;
    }
    if (perm->n_authorization != pcfg->n_auth ||
        perm->n_update != pcfg->n_update) {
        return false;
    }
    if (perm->insert_delete != pcfg->insdel) {
        return false;
    }
    /* verify perm->authorization vs. pcfg->auth */
    n_found = 0;
    for (i = 0; i < pcfg->n_auth; i++) {
        for (j = 0; j < perm->n_authorization; j++) {
            if (!strcmp(pcfg->auth[i], perm->authorization[j])) {
                n_found++;
                break;
            }
        }
    }
    if (n_found != pcfg->n_auth) {
        return false;
    }

    /* verify perm->update vs. pcfg->update */
    n_found = 0;
    for (i = 0; i < pcfg->n_update; i++) {
        for (j = 0; j < perm->n_update; j++) {
            if (!strcmp(pcfg->update[i], perm->update[j])) {
                n_found++;
                break;
            }
        }
    }
    if (n_found != pcfg->n_update) {
        return false;
    }

    /* Success, db state matches expected state */
    pcfg->row = perm;
    return true;
}

static void
ovn_rbac_create_perm(struct rbac_perm_cfg *pcfg,
                     struct ovsdb_idl_txn *ovnsb_txn,
                     const struct sbrec_rbac_role *rbac_role)
{
    struct sbrec_rbac_permission *rbac_perm;

    rbac_perm = sbrec_rbac_permission_insert(ovnsb_txn);
    sbrec_rbac_permission_set_table(rbac_perm, pcfg->table);
    sbrec_rbac_permission_set_authorization(rbac_perm,
                                            pcfg->auth,
                                            pcfg->n_auth);
    sbrec_rbac_permission_set_insert_delete(rbac_perm, pcfg->insdel);
    sbrec_rbac_permission_set_update(rbac_perm,
                                     pcfg->update,
                                     pcfg->n_update);
    sbrec_rbac_role_update_permissions_setkey(rbac_role, pcfg->table,
                                              rbac_perm);
}

static void
check_and_update_rbac(struct ovsdb_idl_txn *ovnsb_txn,
                      struct ovsdb_idl *ovnsb_idl)
{
    const struct sbrec_rbac_role *rbac_role = NULL;
    const struct sbrec_rbac_permission *perm_row;
    const struct sbrec_rbac_role *role_row;
    struct rbac_perm_cfg *pcfg;

    for (pcfg = rbac_perm_cfg; pcfg->table; pcfg++) {
        pcfg->row = NULL;
    }

    SBREC_RBAC_PERMISSION_FOR_EACH_SAFE (perm_row, ovnsb_idl) {
        if (!ovn_rbac_validate_perm(perm_row)) {
            sbrec_rbac_permission_delete(perm_row);
        }
    }
    SBREC_RBAC_ROLE_FOR_EACH_SAFE (role_row, ovnsb_idl) {
        if (strcmp(role_row->name, "ovn-controller")) {
            sbrec_rbac_role_delete(role_row);
        } else {
            rbac_role = role_row;
        }
    }

    if (!rbac_role) {
        rbac_role = sbrec_rbac_role_insert(ovnsb_txn);
        sbrec_rbac_role_set_name(rbac_role, "ovn-controller");
    }

    for (pcfg = rbac_perm_cfg; pcfg->table; pcfg++) {
        if (!pcfg->row) {
            ovn_rbac_create_perm(pcfg, ovnsb_txn, rbac_role);
        }
    }
}

static void
check_and_add_supported_dhcp_opts_to_sb_db(struct ovsdb_idl_txn *ovnsb_txn,
                                           struct ovsdb_idl *ovnsb_idl)
{
    struct hmap dhcp_opts_to_add = HMAP_INITIALIZER(&dhcp_opts_to_add);
    for (size_t i = 0; (i < sizeof(supported_dhcp_opts) /
                            sizeof(supported_dhcp_opts[0])); i++) {
        hmap_insert(&dhcp_opts_to_add, &supported_dhcp_opts[i].hmap_node,
                    dhcp_opt_hash(supported_dhcp_opts[i].name));
    }

    const struct sbrec_dhcp_options *opt_row;
    SBREC_DHCP_OPTIONS_FOR_EACH_SAFE (opt_row, ovnsb_idl) {
        struct gen_opts_map *dhcp_opt =
            dhcp_opts_find(&dhcp_opts_to_add, opt_row->name);
        if (dhcp_opt) {
            if (!strcmp(dhcp_opt->type, opt_row->type) &&
                 dhcp_opt->code == opt_row->code) {
                hmap_remove(&dhcp_opts_to_add, &dhcp_opt->hmap_node);
            } else {
                sbrec_dhcp_options_delete(opt_row);
            }
        } else {
            sbrec_dhcp_options_delete(opt_row);
        }
    }

    struct gen_opts_map *opt;
    HMAP_FOR_EACH (opt, hmap_node, &dhcp_opts_to_add) {
        struct sbrec_dhcp_options *sbrec_dhcp_option =
            sbrec_dhcp_options_insert(ovnsb_txn);
        sbrec_dhcp_options_set_name(sbrec_dhcp_option, opt->name);
        sbrec_dhcp_options_set_code(sbrec_dhcp_option, opt->code);
        sbrec_dhcp_options_set_type(sbrec_dhcp_option, opt->type);
    }

    hmap_destroy(&dhcp_opts_to_add);
}

static void
check_and_add_supported_dhcpv6_opts_to_sb_db(struct ovsdb_idl_txn *ovnsb_txn,
                                             struct ovsdb_idl *ovnsb_idl)
{
    struct hmap dhcpv6_opts_to_add = HMAP_INITIALIZER(&dhcpv6_opts_to_add);
    for (size_t i = 0; (i < sizeof(supported_dhcpv6_opts) /
                            sizeof(supported_dhcpv6_opts[0])); i++) {
        hmap_insert(&dhcpv6_opts_to_add, &supported_dhcpv6_opts[i].hmap_node,
                    dhcp_opt_hash(supported_dhcpv6_opts[i].name));
    }

    const struct sbrec_dhcpv6_options *opt_row;
    SBREC_DHCPV6_OPTIONS_FOR_EACH_SAFE(opt_row, ovnsb_idl) {
        struct gen_opts_map *dhcp_opt =
            dhcp_opts_find(&dhcpv6_opts_to_add, opt_row->name);
        if (dhcp_opt) {
            hmap_remove(&dhcpv6_opts_to_add, &dhcp_opt->hmap_node);
        } else {
            sbrec_dhcpv6_options_delete(opt_row);
        }
    }

    struct gen_opts_map *opt;
    HMAP_FOR_EACH (opt, hmap_node, &dhcpv6_opts_to_add) {
        struct sbrec_dhcpv6_options *sbrec_dhcpv6_option =
            sbrec_dhcpv6_options_insert(ovnsb_txn);
        sbrec_dhcpv6_options_set_name(sbrec_dhcpv6_option, opt->name);
        sbrec_dhcpv6_options_set_code(sbrec_dhcpv6_option, opt->code);
        sbrec_dhcpv6_options_set_type(sbrec_dhcpv6_option, opt->type);
    }

    hmap_destroy(&dhcpv6_opts_to_add);
}

/* Updates the nb_cfg, sb_cfg and hv_cfg columns in NB/SB databases. */
static void
update_sequence_numbers(int64_t loop_start_time,
                        struct ovsdb_idl *ovnnb_idl,
                        struct ovsdb_idl *ovnsb_idl,
                        struct ovsdb_idl_txn *ovnnb_idl_txn,
                        struct ovsdb_idl_txn *ovnsb_idl_txn,
                        struct ovsdb_idl_loop *sb_loop)
{
    /* Create rows in global tables if neccessary */
    const struct nbrec_nb_global *nb = nbrec_nb_global_first(ovnnb_idl);
    if (!nb) {
        nb = nbrec_nb_global_insert(ovnnb_idl_txn);
    }
    const struct sbrec_sb_global *sb = sbrec_sb_global_first(ovnsb_idl);
    if (!sb) {
        sb = sbrec_sb_global_insert(ovnsb_idl_txn);
    }

    /* Copy nb_cfg from northbound to southbound database.
     * Also set up to update sb_cfg once our southbound transaction commits. */
    if (nb->nb_cfg != sb->nb_cfg) {
        sbrec_sb_global_set_nb_cfg(sb, nb->nb_cfg);
        nbrec_nb_global_set_nb_cfg_timestamp(nb, loop_start_time);
    }
    sb_loop->next_cfg = nb->nb_cfg;

    /* Update northbound sb_cfg if appropriate. */
    int64_t sb_cfg = sb_loop->cur_cfg;
    if (nb && sb_cfg && nb->sb_cfg != sb_cfg) {
        nbrec_nb_global_set_sb_cfg(nb, sb_cfg);
        nbrec_nb_global_set_sb_cfg_timestamp(nb, loop_start_time);
    }

    /* Update northbound hv_cfg if appropriate. */
    if (nb) {
        /* Find minimum nb_cfg among all chassis. */
        const struct sbrec_chassis_private *chassis_priv;
        int64_t hv_cfg = nb->nb_cfg;
        int64_t hv_cfg_ts = 0;
        SBREC_CHASSIS_PRIVATE_FOR_EACH (chassis_priv, ovnsb_idl) {
            const struct sbrec_chassis *chassis = chassis_priv->chassis;
            if (chassis) {
                if (smap_get_bool(&chassis->other_config,
                                  "is-remote", false)) {
                    /* Skip remote chassises. */
                    continue;
                }
            } else {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "Chassis does not exist for "
                             "Chassis_Private record, name: %s",
                             chassis_priv->name);
            }

            if (chassis_priv->nb_cfg < hv_cfg) {
                hv_cfg = chassis_priv->nb_cfg;
                hv_cfg_ts = chassis_priv->nb_cfg_timestamp;
            } else if (chassis_priv->nb_cfg == hv_cfg &&
                       chassis_priv->nb_cfg_timestamp > hv_cfg_ts) {
                hv_cfg_ts = chassis_priv->nb_cfg_timestamp;
            }
        }

        /* Update hv_cfg. */
        if (nb->hv_cfg != hv_cfg) {
            nbrec_nb_global_set_hv_cfg(nb, hv_cfg);
            nbrec_nb_global_set_hv_cfg_timestamp(nb, hv_cfg_ts);
        }
    }
}

static void
usage(void)
{
    printf("\
%s: OVN northbound management daemon\n\
usage: %s [OPTIONS]\n\
\n\
Options:\n\
  --ovnnb-db=DATABASE       connect to ovn-nb database at DATABASE\n\
                            (default: %s)\n\
  --ovnsb-db=DATABASE       connect to ovn-sb database at DATABASE\n\
                            (default: %s)\n\
  --dry-run                 start in paused state (do not commit db changes)\n\
  --n-threads=N             specify number of threads\n\
  --unixctl=SOCKET          override default control socket name\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_nb_db(), default_sb_db());
    daemon_usage();
    vlog_usage();
    stream_usage("database", true, true, false);
}

static void
parse_options(int argc OVS_UNUSED, char *argv[] OVS_UNUSED,
              bool *paused, int *n_threads)
{
    enum {
        OVN_DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
        OPT_DRY_RUN,
        OPT_N_THREADS,
    };
    static const struct option long_options[] = {
        {"ovnsb-db", required_argument, NULL, 'd'},
        {"ovnnb-db", required_argument, NULL, 'D'},
        {"unixctl", required_argument, NULL, 'u'},
        {"help", no_argument, NULL, 'h'},
        {"options", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        {"dry-run", no_argument, NULL, OPT_DRY_RUN},
        {"n-threads", required_argument, NULL, OPT_N_THREADS},
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

        case OPT_N_THREADS:
            *n_threads = strtoul(optarg, NULL, 10);
            if (*n_threads < 1) {
                *n_threads = 1;
                VLOG_WARN("Setting n_threads to %d as --n-threads option was "
                    "set to : [%s]", *n_threads, optarg);
            }
            if (*n_threads > OVN_MAX_SUPPORTED_THREADS) {
                *n_threads = OVN_MAX_SUPPORTED_THREADS;
                VLOG_WARN("Setting n_threads to %d as --n-threads option was "
                    "set to : [%s]", *n_threads, optarg);
            }
            if (*n_threads != 1) {
                VLOG_INFO("Using %d threads", *n_threads);
            }
            break;

        case OPT_DRY_RUN:
            *paused = true;
            break;

        default:
            break;
        }
    }

    if (!ovnsb_db || !ovnsb_db[0]) {
        ovnsb_db = default_sb_db();
    }

    if (!ovnnb_db || !ovnnb_db[0]) {
        ovnnb_db = default_nb_db();
    }

    free(short_options);
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

static int
get_probe_interval(const char *db, const struct nbrec_nb_global *nb)
{
    int default_interval = (db && !stream_or_pstream_needs_probes(db)
                            ? 0 : DEFAULT_PROBE_INTERVAL_MSEC);
    int interval = smap_get_int(&nb->options,
                                "northd_probe_interval", default_interval);

    if (interval > 0 && interval < 1000) {
        interval = 1000;
    }
    return interval;
}

int
main(int argc, char *argv[])
{
    int res = EXIT_SUCCESS;
    struct unixctl_server *unixctl;
    int retval;
    bool exiting;
    int n_threads = 1;
    struct northd_state state = {
        .had_lock = false,
        .paused = false
    };

    fatal_ignore_sigpipe();
    ovs_cmdl_proctitle_init(argc, argv);
    ovn_set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv, &state.paused, &n_threads);

    daemonize_start(false);

    char *abs_unixctl_path = get_abs_unix_ctl_path(unixctl_path);
    retval = unixctl_server_create(abs_unixctl_path, &unixctl);
    free(abs_unixctl_path);

    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_northd_exit, &exiting);
    unixctl_command_register("pause", "", 0, 0, ovn_northd_pause, &state);
    unixctl_command_register("resume", "", 0, 0, ovn_northd_resume, &state);
    unixctl_command_register("is-paused", "", 0, 0, ovn_northd_is_paused,
                             &state);
    unixctl_command_register("status", "", 0, 0, ovn_northd_status, &state);

    bool reset_ovnsb_idl_min_index = false;
    unixctl_command_register("sb-cluster-state-reset", "", 0, 0,
                             cluster_state_reset_cmd,
                             &reset_ovnsb_idl_min_index);

    bool reset_ovnnb_idl_min_index = false;
    unixctl_command_register("nb-cluster-state-reset", "", 0, 0,
                             cluster_state_reset_cmd,
                             &reset_ovnnb_idl_min_index);
    unixctl_command_register("parallel-build/set-n-threads", "N_THREADS", 1, 1,
                             ovn_northd_set_thread_count_cmd,
                             NULL);
    unixctl_command_register("parallel-build/get-n-threads", "", 0, 0,
                             ovn_northd_get_thread_count_cmd,
                             NULL);

    daemonize_complete();

    /* We want to detect (almost) all changes to the ovn-nb db. */
    struct ovsdb_idl_loop ovnnb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnnb_db, &nbrec_idl_class, true, true));
    ovsdb_idl_track_add_all(ovnnb_idl_loop.idl);
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl,
                         &nbrec_nb_global_col_nb_cfg_timestamp);
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl, &nbrec_nb_global_col_sb_cfg);
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl,
                         &nbrec_nb_global_col_sb_cfg_timestamp);
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl, &nbrec_nb_global_col_hv_cfg);
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl,
                         &nbrec_nb_global_col_hv_cfg_timestamp);

    unixctl_command_register("nb-connection-status", "", 0, 0,
                             ovn_conn_show, ovnnb_idl_loop.idl);

    /* We want to detect all changes to the ovn-sb db so enable change
     * tracking but, for performance reasons, and because northd
     * reconciles all database changes, also configure the IDL to only
     * write columns that actually change value.
     */
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnsb_db, &sbrec_idl_class, true, true));
    ovsdb_idl_track_add_all(ovnsb_idl_loop.idl);
    ovsdb_idl_set_write_changed_only_all(ovnsb_idl_loop.idl, true);

    /* Disable alerting for pure write-only columns. */
    ovsdb_idl_omit_alert(ovnsb_idl_loop.idl, &sbrec_sb_global_col_nb_cfg);

    unixctl_command_register("sb-connection-status", "", 0, 0,
                             ovn_conn_show, ovnsb_idl_loop.idl);

    char *ovn_version = ovn_get_internal_version();
    VLOG_INFO("OVN internal version is : [%s]", ovn_version);
    free(ovn_version);

    stopwatch_create(NORTHD_LOOP_STOPWATCH_NAME, SW_MS);
    stopwatch_create(OVNNB_DB_RUN_STOPWATCH_NAME, SW_MS);
    stopwatch_create(OVNSB_DB_RUN_STOPWATCH_NAME, SW_MS);
    stopwatch_create(BUILD_LFLOWS_CTX_STOPWATCH_NAME, SW_MS);
    stopwatch_create(CLEAR_LFLOWS_CTX_STOPWATCH_NAME, SW_MS);
    stopwatch_create(BUILD_LFLOWS_STOPWATCH_NAME, SW_MS);
    stopwatch_create(LFLOWS_DATAPATHS_STOPWATCH_NAME, SW_MS);
    stopwatch_create(LFLOWS_PORTS_STOPWATCH_NAME, SW_MS);
    stopwatch_create(LFLOWS_LBS_STOPWATCH_NAME, SW_MS);
    stopwatch_create(LFLOWS_IGMP_STOPWATCH_NAME, SW_MS);
    stopwatch_create(LFLOWS_DP_GROUPS_STOPWATCH_NAME, SW_MS);

    /* Initialize incremental processing engine for ovn-northd */
    inc_proc_northd_init(&ovnnb_idl_loop, &ovnsb_idl_loop);

    unsigned int ovnnb_cond_seqno = UINT_MAX;
    unsigned int ovnsb_cond_seqno = UINT_MAX;

    run_update_worker_pool(n_threads);

    /* Main loop. */
    exiting = false;

    bool recompute = false;
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
                /* Ensure that only a single ovn-northd is active in the
                 * deployment by acquiring a lock called "ovn_northd" on the
                 * southbound database and then only performing DB transactions
                 * if the lock is held.
                 */
                ovsdb_idl_set_lock(ovnsb_idl_loop.idl, "ovn_northd");
            }

            struct ovsdb_idl_txn *ovnnb_txn =
                        ovsdb_idl_loop_run(&ovnnb_idl_loop);
            unsigned int new_ovnnb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovnnb_idl_loop.idl);
            if (new_ovnnb_cond_seqno != ovnnb_cond_seqno) {
                if (!new_ovnnb_cond_seqno) {
                    VLOG_INFO("OVN NB IDL reconnected, force recompute.");
                    recompute = true;
                }
                ovnnb_cond_seqno = new_ovnnb_cond_seqno;
            }

            struct ovsdb_idl_txn *ovnsb_txn =
                        ovsdb_idl_loop_run(&ovnsb_idl_loop);
            unsigned int new_ovnsb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovnsb_idl_loop.idl);
            if (new_ovnsb_cond_seqno != ovnsb_cond_seqno) {
                if (!new_ovnsb_cond_seqno) {
                    VLOG_INFO("OVN SB IDL reconnected, force recompute.");
                    recompute = true;
                }
                ovnsb_cond_seqno = new_ovnsb_cond_seqno;
            }

            if (!state.had_lock && ovsdb_idl_has_lock(ovnsb_idl_loop.idl)) {
                VLOG_INFO("ovn-northd lock acquired. "
                        "This ovn-northd instance is now active.");
                state.had_lock = true;
            } else if (state.had_lock &&
                       !ovsdb_idl_has_lock(ovnsb_idl_loop.idl))
            {
                VLOG_INFO("ovn-northd lock lost. "
                        "This ovn-northd instance is now on standby.");
                state.had_lock = false;
            }

            if (ovsdb_idl_has_lock(ovnsb_idl_loop.idl)) {
                int64_t loop_start_time = time_wall_msec();
                inc_proc_northd_run(ovnnb_txn, ovnsb_txn, recompute);
                recompute = false;
                if (ovnsb_txn) {
                    check_and_add_supported_dhcp_opts_to_sb_db(
                                 ovnsb_txn, ovnsb_idl_loop.idl);
                    check_and_add_supported_dhcpv6_opts_to_sb_db(
                                 ovnsb_txn, ovnsb_idl_loop.idl);
                    check_and_update_rbac(
                                 ovnsb_txn, ovnsb_idl_loop.idl);
                }

                if (ovnnb_txn && ovnsb_txn) {
                    update_sequence_numbers(loop_start_time,
                                            ovnnb_idl_loop.idl,
                                            ovnsb_idl_loop.idl,
                                            ovnnb_txn, ovnsb_txn,
                                            &ovnsb_idl_loop);
                }

                /* If there are any errors, we force a full recompute in order
                 * to ensure we handle all changes. */
                if (!ovsdb_idl_loop_commit_and_wait(&ovnnb_idl_loop)) {
                    VLOG_INFO("OVNNB commit failed, "
                              "force recompute next time.");
                    recompute = true;
                }

                if (!ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop)) {
                    VLOG_INFO("OVNSB commit failed, "
                              "force recompute next time.");
                    recompute = true;
                }
            } else {
                /* Make sure we send any pending requests, e.g., lock. */
                ovsdb_idl_loop_commit_and_wait(&ovnnb_idl_loop);
                ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);

                /* Force a full recompute next time we become active. */
                recompute = true;
            }
        } else {
            /* ovn-northd is paused
             *    - we still want to handle any db updates and update the
             *      local IDL. Otherwise, when it is resumed, the local IDL
             *      copy will be out of sync.
             *    - but we don't want to create any txns.
             * */
            if (ovsdb_idl_has_lock(ovnsb_idl_loop.idl) ||
                ovsdb_idl_is_lock_contended(ovnsb_idl_loop.idl))
            {
                /* make sure we don't hold the lock while paused */
                VLOG_INFO("This ovn-northd instance is now paused.");
                ovsdb_idl_set_lock(ovnsb_idl_loop.idl, NULL);
                state.had_lock = false;
            }

            ovsdb_idl_run(ovnnb_idl_loop.idl);
            ovsdb_idl_run(ovnsb_idl_loop.idl);
            ovsdb_idl_wait(ovnnb_idl_loop.idl);
            ovsdb_idl_wait(ovnsb_idl_loop.idl);

            /* Force a full recompute next time we become active. */
            recompute = true;
        }

        ovsdb_idl_track_clear(ovnnb_idl_loop.idl);
        ovsdb_idl_track_clear(ovnsb_idl_loop.idl);

        unixctl_server_run(unixctl);
        unixctl_server_wait(unixctl);
        memory_wait();
        if (exiting) {
            poll_immediate_wake();
        }

        const struct nbrec_nb_global *nb =
            nbrec_nb_global_first(ovnnb_idl_loop.idl);
        /* Update the probe interval. */
        if (nb) {
            northd_probe_interval_nb = get_probe_interval(ovnnb_db, nb);
            northd_probe_interval_sb = get_probe_interval(ovnsb_db, nb);
        }
        ovsdb_idl_set_probe_interval(ovnnb_idl_loop.idl,
                                     northd_probe_interval_nb);
        ovsdb_idl_set_probe_interval(ovnsb_idl_loop.idl,
                                     northd_probe_interval_sb);

        if (reset_ovnsb_idl_min_index) {
            VLOG_INFO("Resetting southbound database cluster state");
            ovsdb_idl_reset_min_index(ovnsb_idl_loop.idl);
            reset_ovnsb_idl_min_index = false;
        }

        if (reset_ovnnb_idl_min_index) {
            VLOG_INFO("Resetting northbound database cluster state");
            ovsdb_idl_reset_min_index(ovnnb_idl_loop.idl);
            reset_ovnnb_idl_min_index = false;
        }

        stopwatch_stop(NORTHD_LOOP_STOPWATCH_NAME, time_msec());
        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
        stopwatch_start(NORTHD_LOOP_STOPWATCH_NAME, time_msec());
    }
    inc_proc_northd_cleanup();

    unixctl_server_destroy(unixctl);
    ovsdb_idl_loop_destroy(&ovnnb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);
    service_stop();

    exit(res);
}

static void
ovn_northd_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_northd_pause(struct unixctl_conn *conn, int argc OVS_UNUSED,
                const char *argv[] OVS_UNUSED, void *state_)
{
    struct northd_state  *state = state_;
    state->paused = true;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_northd_resume(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *state_)
{
    struct northd_state *state = state_;
    state->paused = false;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_northd_is_paused(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *state_)
{
    struct northd_state *state = state_;
    if (state->paused) {
        unixctl_command_reply(conn, "true");
    } else {
        unixctl_command_reply(conn, "false");
    }
}

static void
ovn_northd_status(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *state_)
{
    struct northd_state *state = state_;
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

static void
cluster_state_reset_cmd(struct unixctl_conn *conn, int argc OVS_UNUSED,
               const char *argv[] OVS_UNUSED, void *idl_reset_)
{
    bool *idl_reset = idl_reset_;

    *idl_reset = true;
    poll_immediate_wake();
    unixctl_command_reply(conn, NULL);
}

static void
ovn_northd_set_thread_count_cmd(struct unixctl_conn *conn, int argc OVS_UNUSED,
               const char *argv[], void *aux OVS_UNUSED)
{
    int n_threads = atoi(argv[1]);

    if ((n_threads < 1) || (n_threads > OVN_MAX_SUPPORTED_THREADS)) {
        struct ds s = DS_EMPTY_INITIALIZER;
        ds_put_format(&s, "invalid n_threads: %d\n", n_threads);
        unixctl_command_reply_error(conn, ds_cstr(&s));
        ds_destroy(&s);
    } else {
        run_update_worker_pool(n_threads);
        unixctl_command_reply(conn, NULL);
    }
}

static void
ovn_northd_get_thread_count_cmd(struct unixctl_conn *conn, int argc OVS_UNUSED,
               const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "%"PRIuSIZE"\n", get_worker_pool_size());
    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}
