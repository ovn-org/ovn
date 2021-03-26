/* Copyright (c) 2015, 2016, 2017 Nicira, Inc.
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

#include "ovn-controller.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "bfd.h"
#include "binding.h"
#include "chassis.h"
#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "encaps.h"
#include "fatal-signal.h"
#include "ip-mcast.h"
#include "openvswitch/hmap.h"
#include "lflow.h"
#include "lflow-cache.h"
#include "lib/vswitch-idl.h"
#include "lport.h"
#include "memory.h"
#include "ofctrl.h"
#include "ofctrl-seqno.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "ovn/actions.h"
#include "lib/chassis-index.h"
#include "lib/extend-table.h"
#include "lib/ip-mcast-index.h"
#include "lib/mcast-group-index.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "patch.h"
#include "physical.h"
#include "pinctrl.h"
#include "openvswitch/poll-loop.h"
#include "lib/bitmap.h"
#include "lib/hash.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "stream-ssl.h"
#include "stream.h"
#include "unixctl.h"
#include "util.h"
#include "timeval.h"
#include "timer.h"
#include "stopwatch.h"
#include "lib/inc-proc-eng.h"
#include "hmapx.h"

VLOG_DEFINE_THIS_MODULE(main);

static unixctl_cb_func ovn_controller_exit;
static unixctl_cb_func ct_zone_list;
static unixctl_cb_func extend_table_list;
static unixctl_cb_func inject_pkt;
static unixctl_cb_func engine_recompute_cmd;
static unixctl_cb_func cluster_state_reset_cmd;
static unixctl_cb_func debug_pause_execution;
static unixctl_cb_func debug_resume_execution;
static unixctl_cb_func debug_status_execution;
static unixctl_cb_func lflow_cache_flush_cmd;
static unixctl_cb_func lflow_cache_show_stats_cmd;
static unixctl_cb_func debug_delay_nb_cfg_report;

#define DEFAULT_BRIDGE_NAME "br-int"
#define DEFAULT_PROBE_INTERVAL_MSEC 5000
#define OFCTRL_DEFAULT_PROBE_INTERVAL_SEC 0

#define CONTROLLER_LOOP_STOPWATCH_NAME "ovn-controller-flow-generation"

#define OVS_NB_CFG_NAME "ovn-nb-cfg"

static char *parse_options(int argc, char *argv[]);
OVS_NO_RETURN static void usage(void);

/* By default don't set an upper bound for the lflow cache. */
#define DEFAULT_LFLOW_CACHE_MAX_ENTRIES UINT32_MAX
#define DEFAULT_LFLOW_CACHE_MAX_MEM_KB (UINT64_MAX / 1024)

struct controller_engine_ctx {
    struct lflow_cache *lflow_cache;
};

/* Pending packet to be injected into connected OVS. */
struct pending_pkt {
    /* Setting 'conn' indicates that a request is pending. */
    struct unixctl_conn *conn;
    char *flow_s;
};

/* Registered ofctrl seqno type for nb_cfg propagation. */
static size_t ofctrl_seq_type_nb_cfg;

struct local_datapath *
get_local_datapath(const struct hmap *local_datapaths, uint32_t tunnel_key)
{
    struct hmap_node *node = hmap_first_with_hash(local_datapaths, tunnel_key);
    return (node
            ? CONTAINER_OF(node, struct local_datapath, hmap_node)
            : NULL);
}

uint32_t
get_tunnel_type(const char *name)
{
    if (!strcmp(name, "geneve")) {
        return GENEVE;
    } else if (!strcmp(name, "stt")) {
        return STT;
    } else if (!strcmp(name, "vxlan")) {
        return VXLAN;
    }

    return 0;
}

const struct ovsrec_bridge *
get_bridge(const struct ovsrec_bridge_table *bridge_table, const char *br_name)
{
    const struct ovsrec_bridge *br;
    OVSREC_BRIDGE_TABLE_FOR_EACH (br, bridge_table) {
        if (!strcmp(br->name, br_name)) {
            return br;
        }
    }
    return NULL;
}

static unsigned int
update_sb_monitors(struct ovsdb_idl *ovnsb_idl,
                   const struct sbrec_chassis *chassis,
                   const struct sset *local_ifaces,
                   struct hmap *local_datapaths,
                   bool monitor_all)
{
    /* Monitor Port_Bindings rows for local interfaces and local datapaths.
     *
     * Monitor Logical_Flow, MAC_Binding, Multicast_Group, and DNS tables for
     * local datapaths.
     *
     * Monitor Controller_Event rows for local chassis.
     *
     * Monitor IP_Multicast for local datapaths.
     *
     * Monitor IGMP_Groups for local chassis.
     *
     * We always monitor patch ports because they allow us to see the linkages
     * between related logical datapaths.  That way, when we know that we have
     * a VIF on a particular logical switch, we immediately know to monitor all
     * the connected logical routers and logical switches. */
    struct ovsdb_idl_condition pb = OVSDB_IDL_CONDITION_INIT(&pb);
    struct ovsdb_idl_condition lf = OVSDB_IDL_CONDITION_INIT(&lf);
    struct ovsdb_idl_condition ldpg = OVSDB_IDL_CONDITION_INIT(&ldpg);
    struct ovsdb_idl_condition mb = OVSDB_IDL_CONDITION_INIT(&mb);
    struct ovsdb_idl_condition mg = OVSDB_IDL_CONDITION_INIT(&mg);
    struct ovsdb_idl_condition dns = OVSDB_IDL_CONDITION_INIT(&dns);
    struct ovsdb_idl_condition ce =  OVSDB_IDL_CONDITION_INIT(&ce);
    struct ovsdb_idl_condition ip_mcast = OVSDB_IDL_CONDITION_INIT(&ip_mcast);
    struct ovsdb_idl_condition igmp = OVSDB_IDL_CONDITION_INIT(&igmp);
    struct ovsdb_idl_condition chprv = OVSDB_IDL_CONDITION_INIT(&chprv);

    if (monitor_all) {
        ovsdb_idl_condition_add_clause_true(&pb);
        ovsdb_idl_condition_add_clause_true(&lf);
        ovsdb_idl_condition_add_clause_true(&ldpg);
        ovsdb_idl_condition_add_clause_true(&mb);
        ovsdb_idl_condition_add_clause_true(&mg);
        ovsdb_idl_condition_add_clause_true(&dns);
        ovsdb_idl_condition_add_clause_true(&ce);
        ovsdb_idl_condition_add_clause_true(&ip_mcast);
        ovsdb_idl_condition_add_clause_true(&igmp);
        ovsdb_idl_condition_add_clause_true(&chprv);
        goto out;
    }

    sbrec_port_binding_add_clause_type(&pb, OVSDB_F_EQ, "patch");
    /* XXX: We can optimize this, if we find a way to only monitor
     * ports that have a Gateway_Chassis that point's to our own
     * chassis */
    sbrec_port_binding_add_clause_type(&pb, OVSDB_F_EQ, "chassisredirect");
    sbrec_port_binding_add_clause_type(&pb, OVSDB_F_EQ, "external");
    if (chassis) {
        /* This should be mostly redundant with the other clauses for port
         * bindings, but it allows us to catch any ports that are assigned to
         * us but should not be.  That way, we can clear their chassis
         * assignments. */
        sbrec_port_binding_add_clause_chassis(&pb, OVSDB_F_EQ,
                                              &chassis->header_.uuid);

        /* Ensure that we find out about l2gateway and l3gateway ports that
         * should be present on this chassis.  Otherwise, we might never find
         * out about those ports, if their datapaths don't otherwise have a VIF
         * in this chassis. */
        const char *id = chassis->name;
        const struct smap l2 = SMAP_CONST1(&l2, "l2gateway-chassis", id);
        sbrec_port_binding_add_clause_options(&pb, OVSDB_F_INCLUDES, &l2);
        const struct smap l3 = SMAP_CONST1(&l3, "l3gateway-chassis", id);
        sbrec_port_binding_add_clause_options(&pb, OVSDB_F_INCLUDES, &l3);

        sbrec_controller_event_add_clause_chassis(&ce, OVSDB_F_EQ,
                                                  &chassis->header_.uuid);
        sbrec_igmp_group_add_clause_chassis(&igmp, OVSDB_F_EQ,
                                            &chassis->header_.uuid);

        /* Monitors Chassis_Private record for current chassis only. */
        sbrec_chassis_private_add_clause_name(&chprv, OVSDB_F_EQ,
                                              chassis->name);
    } else {
        /* During initialization, we monitor all records in Chassis_Private so
         * that we don't try to recreate existing ones. */
        ovsdb_idl_condition_add_clause_true(&chprv);
    }

    if (local_ifaces) {
        const char *name;
        SSET_FOR_EACH (name, local_ifaces) {
            sbrec_port_binding_add_clause_logical_port(&pb, OVSDB_F_EQ, name);
            sbrec_port_binding_add_clause_parent_port(&pb, OVSDB_F_EQ, name);
        }
    }
    if (local_datapaths) {
        const struct local_datapath *ld;
        HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
            struct uuid *uuid = CONST_CAST(struct uuid *,
                                           &ld->datapath->header_.uuid);
            sbrec_port_binding_add_clause_datapath(&pb, OVSDB_F_EQ, uuid);
            sbrec_logical_flow_add_clause_logical_datapath(&lf, OVSDB_F_EQ,
                                                           uuid);
            sbrec_logical_dp_group_add_clause_datapaths(
                &ldpg, OVSDB_F_INCLUDES, &uuid, 1);
            sbrec_mac_binding_add_clause_datapath(&mb, OVSDB_F_EQ, uuid);
            sbrec_multicast_group_add_clause_datapath(&mg, OVSDB_F_EQ, uuid);
            sbrec_dns_add_clause_datapaths(&dns, OVSDB_F_INCLUDES, &uuid, 1);
            sbrec_ip_multicast_add_clause_datapath(&ip_mcast, OVSDB_F_EQ,
                                                   uuid);
        }

        /* Updating conditions to receive logical flows that references
         * datapath groups containing local datapaths. */
        const struct sbrec_logical_dp_group *group;
        SBREC_LOGICAL_DP_GROUP_FOR_EACH (group, ovnsb_idl) {
            struct uuid *uuid = CONST_CAST(struct uuid *,
                                           &group->header_.uuid);
            size_t i;

            for (i = 0; i < group->n_datapaths; i++) {
                if (get_local_datapath(local_datapaths,
                                       group->datapaths[i]->tunnel_key)) {
                    sbrec_logical_flow_add_clause_logical_dp_group(
                        &lf, OVSDB_F_EQ, uuid);
                    break;
                }
            }
        }
    }

out:;
    unsigned int cond_seqnos[] = {
        sbrec_port_binding_set_condition(ovnsb_idl, &pb),
        sbrec_logical_flow_set_condition(ovnsb_idl, &lf),
        sbrec_logical_dp_group_set_condition(ovnsb_idl, &ldpg),
        sbrec_mac_binding_set_condition(ovnsb_idl, &mb),
        sbrec_multicast_group_set_condition(ovnsb_idl, &mg),
        sbrec_dns_set_condition(ovnsb_idl, &dns),
        sbrec_controller_event_set_condition(ovnsb_idl, &ce),
        sbrec_ip_multicast_set_condition(ovnsb_idl, &ip_mcast),
        sbrec_igmp_group_set_condition(ovnsb_idl, &igmp),
        sbrec_chassis_private_set_condition(ovnsb_idl, &chprv),
    };

    unsigned int expected_cond_seqno = 0;
    for (size_t i = 0; i < ARRAY_SIZE(cond_seqnos); i++) {
        expected_cond_seqno = MAX(expected_cond_seqno, cond_seqnos[i]);
    }

    ovsdb_idl_condition_destroy(&pb);
    ovsdb_idl_condition_destroy(&lf);
    ovsdb_idl_condition_destroy(&ldpg);
    ovsdb_idl_condition_destroy(&mb);
    ovsdb_idl_condition_destroy(&mg);
    ovsdb_idl_condition_destroy(&dns);
    ovsdb_idl_condition_destroy(&ce);
    ovsdb_idl_condition_destroy(&ip_mcast);
    ovsdb_idl_condition_destroy(&igmp);
    ovsdb_idl_condition_destroy(&chprv);
    return expected_cond_seqno;
}

static const char *
br_int_name(const struct ovsrec_open_vswitch *cfg)
{
    return smap_get_def(&cfg->external_ids, "ovn-bridge", DEFAULT_BRIDGE_NAME);
}

static const struct ovsrec_bridge *
create_br_int(struct ovsdb_idl_txn *ovs_idl_txn,
              const struct ovsrec_open_vswitch_table *ovs_table)
{
    if (!ovs_idl_txn) {
        return NULL;
    }

    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_table_first(ovs_table);
    if (!cfg) {
        return NULL;
    }
    const char *bridge_name = br_int_name(cfg);

    ovsdb_idl_txn_add_comment(ovs_idl_txn,
            "ovn-controller: creating integration bridge '%s'", bridge_name);

    struct ovsrec_interface *iface;
    iface = ovsrec_interface_insert(ovs_idl_txn);
    ovsrec_interface_set_name(iface, bridge_name);
    ovsrec_interface_set_type(iface, "internal");

    struct ovsrec_port *port;
    port = ovsrec_port_insert(ovs_idl_txn);
    ovsrec_port_set_name(port, bridge_name);
    ovsrec_port_set_interfaces(port, &iface, 1);

    struct ovsrec_bridge *bridge;
    bridge = ovsrec_bridge_insert(ovs_idl_txn);
    ovsrec_bridge_set_name(bridge, bridge_name);
    ovsrec_bridge_set_fail_mode(bridge, "secure");
    ovsrec_bridge_set_ports(bridge, &port, 1);

    struct smap oc = SMAP_INITIALIZER(&oc);
    smap_add(&oc, "disable-in-band", "true");

    /* When a first non-local port is added to the integration bridge, it
     * results in the recalculation of datapath-id by ovs-vswitchd forcing all
     * active connections to the controllers to reconnect.
     *
     * We can avoid the disconnection by setting the 'other_config:hwaddr' for
     * the integration bridge. ovs-vswitchd uses this hwaddr to calculate the
     * datapath-id and it doesn't recalculate the datapath-id later when the
     * first non-local port is added.
     *
     * So generate a random mac and set the 'hwaddr' option in the
     * other_config.
     * */
    struct eth_addr br_hwaddr;
    eth_addr_random(&br_hwaddr);
    char ea_s[ETH_ADDR_STRLEN + 1];
    snprintf(ea_s, sizeof ea_s, ETH_ADDR_FMT,
             ETH_ADDR_ARGS(br_hwaddr));
    smap_add(&oc, "hwaddr", ea_s);

    ovsrec_bridge_set_other_config(bridge, &oc);
    smap_destroy(&oc);

    struct ovsrec_bridge **bridges;
    size_t bytes = sizeof *bridges * cfg->n_bridges;
    bridges = xmalloc(bytes + sizeof *bridges);
    memcpy(bridges, cfg->bridges, bytes);
    bridges[cfg->n_bridges] = bridge;
    ovsrec_open_vswitch_verify_bridges(cfg);
    ovsrec_open_vswitch_set_bridges(cfg, bridges, cfg->n_bridges + 1);
    free(bridges);

    return bridge;
}

static const struct ovsrec_bridge *
get_br_int(const struct ovsrec_bridge_table *bridge_table,
           const struct ovsrec_open_vswitch_table *ovs_table)
{
    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_table_first(ovs_table);
    if (!cfg) {
        return NULL;
    }

    return get_bridge(bridge_table, br_int_name(cfg));
}

static const struct ovsrec_bridge *
process_br_int(struct ovsdb_idl_txn *ovs_idl_txn,
               const struct ovsrec_bridge_table *bridge_table,
               const struct ovsrec_open_vswitch_table *ovs_table)
{
    const struct ovsrec_bridge *br_int = get_br_int(bridge_table,
                                                    ovs_table);
    if (!br_int) {
        br_int = create_br_int(ovs_idl_txn, ovs_table);
    }
    if (br_int && ovs_idl_txn) {
        const struct ovsrec_open_vswitch *cfg;
        cfg = ovsrec_open_vswitch_table_first(ovs_table);
        ovs_assert(cfg);
        const char *datapath_type = smap_get(&cfg->external_ids,
                                             "ovn-bridge-datapath-type");
        /* Check for the datapath_type and set it only if it is defined in
         * cfg. */
        if (datapath_type && strcmp(br_int->datapath_type, datapath_type)) {
            ovsrec_bridge_set_datapath_type(br_int, datapath_type);
        }
    }
    return br_int;
}

static const char *
get_ovs_chassis_id(const struct ovsrec_open_vswitch_table *ovs_table)
{
    const struct ovsrec_open_vswitch *cfg
        = ovsrec_open_vswitch_table_first(ovs_table);
    const char *chassis_id = cfg ? smap_get(&cfg->external_ids, "system-id")
                                 : NULL;

    if (!chassis_id) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "'system-id' in Open_vSwitch database is missing.");
    }

    return chassis_id;
}

/* Iterate address sets in the southbound database.  Create and update the
 * corresponding symtab entries as necessary. */
static void
addr_sets_init(const struct sbrec_address_set_table *address_set_table,
               struct shash *addr_sets)
{
    const struct sbrec_address_set *as;
    SBREC_ADDRESS_SET_TABLE_FOR_EACH (as, address_set_table) {
        expr_const_sets_add(addr_sets, as->name,
                            (const char *const *) as->addresses,
                            as->n_addresses, true);
    }
}

static void
addr_sets_update(const struct sbrec_address_set_table *address_set_table,
                 struct shash *addr_sets, struct sset *new,
                 struct sset *deleted, struct sset *updated)
{
    const struct sbrec_address_set *as;
    SBREC_ADDRESS_SET_TABLE_FOR_EACH_TRACKED (as, address_set_table) {
        if (sbrec_address_set_is_deleted(as)) {
            expr_const_sets_remove(addr_sets, as->name);
            sset_add(deleted, as->name);
        } else {
            expr_const_sets_add(addr_sets, as->name,
                                (const char *const *) as->addresses,
                                as->n_addresses, true);
            if (sbrec_address_set_is_new(as)) {
                sset_add(new, as->name);
            } else {
                sset_add(updated, as->name);
            }
        }
    }
}

/* Iterate port groups in the southbound database.  Create and update the
 * corresponding symtab entries as necessary. */
 static void
port_groups_init(const struct sbrec_port_group_table *port_group_table,
                 struct shash *port_groups)
{
    const struct sbrec_port_group *pg;
    SBREC_PORT_GROUP_TABLE_FOR_EACH (pg, port_group_table) {
        expr_const_sets_add(port_groups, pg->name,
                            (const char *const *) pg->ports,
                            pg->n_ports, false);
    }
}

static void
port_groups_update(const struct sbrec_port_group_table *port_group_table,
                   struct shash *port_groups, struct sset *new,
                   struct sset *deleted, struct sset *updated)
{
    const struct sbrec_port_group *pg;
    SBREC_PORT_GROUP_TABLE_FOR_EACH_TRACKED (pg, port_group_table) {
        if (sbrec_port_group_is_deleted(pg)) {
            expr_const_sets_remove(port_groups, pg->name);
            sset_add(deleted, pg->name);
        } else {
            expr_const_sets_add(port_groups, pg->name,
                                (const char *const *) pg->ports,
                                pg->n_ports, false);
            if (sbrec_port_group_is_new(pg)) {
                sset_add(new, pg->name);
            } else {
                sset_add(updated, pg->name);
            }
        }
    }
}

static void
update_ssl_config(const struct ovsrec_ssl_table *ssl_table)
{
    const struct ovsrec_ssl *ssl = ovsrec_ssl_table_first(ssl_table);

    if (ssl) {
        stream_ssl_set_key_and_cert(ssl->private_key, ssl->certificate);
        stream_ssl_set_ca_cert_file(ssl->ca_cert, ssl->bootstrap_ca_cert);
    }
}

static int
get_ofctrl_probe_interval(struct ovsdb_idl *ovs_idl)
{
    const struct ovsrec_open_vswitch *cfg = ovsrec_open_vswitch_first(ovs_idl);
    return !cfg ? OFCTRL_DEFAULT_PROBE_INTERVAL_SEC :
                  smap_get_int(&cfg->external_ids,
                               "ovn-openflow-probe-interval",
                               OFCTRL_DEFAULT_PROBE_INTERVAL_SEC);
}

/* Retrieves the pointer to the OVN Southbound database from 'ovs_idl' and
 * updates 'sbdb_idl' with that pointer. */
static void
update_sb_db(struct ovsdb_idl *ovs_idl, struct ovsdb_idl *ovnsb_idl,
             bool *monitor_all_p, bool *reset_ovnsb_idl_min_index,
             struct controller_engine_ctx *ctx,
             unsigned int *sb_cond_seqno)
{
    const struct ovsrec_open_vswitch *cfg = ovsrec_open_vswitch_first(ovs_idl);
    if (!cfg) {
        return;
    }

    /* Set remote based on user configuration. */
    const char *remote = smap_get(&cfg->external_ids, "ovn-remote");
    ovsdb_idl_set_remote(ovnsb_idl, remote, true);

    /* Set probe interval, based on user configuration and the remote. */
    int default_interval = (remote && !stream_or_pstream_needs_probes(remote)
                            ? 0 : DEFAULT_PROBE_INTERVAL_MSEC);
    int interval = smap_get_int(&cfg->external_ids,
                                "ovn-remote-probe-interval", default_interval);
    ovsdb_idl_set_probe_interval(ovnsb_idl, interval);

    bool monitor_all = smap_get_bool(&cfg->external_ids, "ovn-monitor-all",
                                     false);
    if (monitor_all) {
        /* Always call update_sb_monitors when monitor_all is true.
         * Otherwise, don't call it here, because there would be unnecessary
         * extra cost. Instead, it is called after the engine execution only
         * when it is necessary. */
        unsigned int next_cond_seqno =
            update_sb_monitors(ovnsb_idl, NULL, NULL, NULL, true);
        if (sb_cond_seqno) {
            *sb_cond_seqno = next_cond_seqno;
        }
    }
    if (monitor_all_p) {
        *monitor_all_p = monitor_all;
    }
    if (reset_ovnsb_idl_min_index && *reset_ovnsb_idl_min_index) {
        VLOG_INFO("Resetting southbound database cluster state");
        engine_set_force_recompute(true);
        ovsdb_idl_reset_min_index(ovnsb_idl);
        *reset_ovnsb_idl_min_index = false;
    }

    if (ctx) {
        lflow_cache_enable(ctx->lflow_cache,
                           smap_get_bool(&cfg->external_ids,
                                         "ovn-enable-lflow-cache",
                                         true),
                           smap_get_uint(&cfg->external_ids,
                                         "ovn-limit-lflow-cache",
                                         DEFAULT_LFLOW_CACHE_MAX_ENTRIES),
                           smap_get_ullong(&cfg->external_ids,
                                           "ovn-memlimit-lflow-cache-kb",
                                           DEFAULT_LFLOW_CACHE_MAX_MEM_KB));
    }
}

static void
add_pending_ct_zone_entry(struct shash *pending_ct_zones,
                          enum ct_zone_pending_state state,
                          int zone, bool add, const char *name)
{
    VLOG_DBG("%s ct zone %"PRId32" for '%s'",
             add ? "assigning" : "removing", zone, name);

    struct ct_zone_pending_entry *pending = xmalloc(sizeof *pending);
    pending->state = state; /* Skip flushing zone. */
    pending->zone = zone;
    pending->add = add;

    /* Its important that we add only one entry for the key 'name'.
     * Replace 'pending' with 'existing' and free up 'existing'.
     * Otherwise, we may end up in a continuous loop of adding
     * and deleting the zone entry in the 'external_ids' of
     * integration bridge.
     */
    struct ct_zone_pending_entry *existing =
        shash_replace(pending_ct_zones, name, pending);
    if (existing) {
        free(existing);
    }
}

static void
update_ct_zones(const struct sset *lports, const struct hmap *local_datapaths,
                struct simap *ct_zones, unsigned long *ct_zone_bitmap,
                struct shash *pending_ct_zones, struct hmapx *updated_dps)
{
    struct simap_node *ct_zone, *ct_zone_next;
    int scan_start = 1;
    const char *user;
    struct sset all_users = SSET_INITIALIZER(&all_users);
    struct simap req_snat_zones = SIMAP_INITIALIZER(&req_snat_zones);
    unsigned long unreq_snat_zones[BITMAP_N_LONGS(MAX_CT_ZONES)];

    SSET_FOR_EACH(user, lports) {
        sset_add(&all_users, user);
    }

    /* Local patched datapath (gateway routers) need zones assigned. */
    struct shash all_lds = SHASH_INITIALIZER(&all_lds);
    const struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
        /* XXX Add method to limit zone assignment to logical router
         * datapaths with NAT */
        char *dnat = alloc_nat_zone_key(&ld->datapath->header_.uuid, "dnat");
        char *snat = alloc_nat_zone_key(&ld->datapath->header_.uuid, "snat");
        sset_add(&all_users, dnat);
        sset_add(&all_users, snat);
        shash_add(&all_lds, dnat, ld);
        shash_add(&all_lds, snat, ld);

        int req_snat_zone = datapath_snat_ct_zone(ld->datapath);
        if (req_snat_zone >= 0) {
            simap_put(&req_snat_zones, snat, req_snat_zone);
        }
        free(dnat);
        free(snat);
    }

    /* Delete zones that do not exist in above sset. */
    SIMAP_FOR_EACH_SAFE(ct_zone, ct_zone_next, ct_zones) {
        if (!sset_contains(&all_users, ct_zone->name)) {
            VLOG_DBG("removing ct zone %"PRId32" for '%s'",
                     ct_zone->data, ct_zone->name);

            add_pending_ct_zone_entry(pending_ct_zones, CT_ZONE_DB_QUEUED,
                                      ct_zone->data, false, ct_zone->name);

            bitmap_set0(ct_zone_bitmap, ct_zone->data);
            simap_delete(ct_zones, ct_zone);
        } else if (!simap_find(&req_snat_zones, ct_zone->name)) {
            bitmap_set1(unreq_snat_zones, ct_zone->data);
        }
    }

    /* Prioritize requested CT zones */
    struct simap_node *snat_req_node;
    SIMAP_FOR_EACH (snat_req_node, &req_snat_zones) {
        struct simap_node *node = simap_find(ct_zones, snat_req_node->name);
        if (node) {
            if (node->data == snat_req_node->data) {
                /* No change to this request, so no action needed */
                continue;
            } else {
                /* Zone request has changed for this node. delete old entry */
                bitmap_set0(ct_zone_bitmap, node->data);
                simap_delete(ct_zones, node);
            }
        }

        /* Determine if someone already had this zone auto-assigned.
         * If so, then they need to give up their assignment since
         * that zone is being explicitly requested now.
         */
        if (bitmap_is_set(unreq_snat_zones, snat_req_node->data)) {
            struct simap_node *dup;
            struct simap_node *next;
            SIMAP_FOR_EACH_SAFE (dup, next, ct_zones) {
                if (dup != snat_req_node && dup->data == snat_req_node->data) {
                    simap_delete(ct_zones, dup);
                    break;
                }
            }
            /* Set this bit to 0 so that if multiple datapaths have requested
             * this zone, we don't needlessly double-detect this condition.
             */
            bitmap_set0(unreq_snat_zones, snat_req_node->data);
        }

        add_pending_ct_zone_entry(pending_ct_zones, CT_ZONE_OF_QUEUED,
                                  snat_req_node->data, true,
                                  snat_req_node->name);

        bitmap_set1(ct_zone_bitmap, snat_req_node->data);
        simap_put(ct_zones, snat_req_node->name, snat_req_node->data);
        struct shash_node *ld_node = shash_find(&all_lds, snat_req_node->name);
        if (ld_node) {
            struct local_datapath *dp = ld_node->data;
            hmapx_add(updated_dps, (void *) dp->datapath);
        }
    }

    /* xxx This is wasteful to assign a zone to each port--even if no
     * xxx security policy is applied. */

    /* Assign a unique zone id for each logical port and two zones
     * to a gateway router. */
    SSET_FOR_EACH(user, &all_users) {
        int zone;

        if (simap_contains(ct_zones, user)) {
            continue;
        }

        /* We assume that there are 64K zones and that we own them all. */
        zone = bitmap_scan(ct_zone_bitmap, 0, scan_start, MAX_CT_ZONES + 1);
        if (zone == MAX_CT_ZONES + 1) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "exhausted all ct zones");
            break;
        }
        scan_start = zone + 1;

        add_pending_ct_zone_entry(pending_ct_zones, CT_ZONE_OF_QUEUED,
                                  zone, true, user);

        bitmap_set1(ct_zone_bitmap, zone);
        simap_put(ct_zones, user, zone);

        struct shash_node *ld_node = shash_find(&all_lds, user);
        if (ld_node) {
            struct local_datapath *dp = ld_node->data;
            hmapx_add(updated_dps, (void *) dp->datapath);
        }
    }

    simap_destroy(&req_snat_zones);
    sset_destroy(&all_users);
    shash_destroy(&all_lds);
}

static void
commit_ct_zones(const struct ovsrec_bridge *br_int,
                struct shash *pending_ct_zones)
{
    struct shash_node *iter;
    SHASH_FOR_EACH(iter, pending_ct_zones) {
        struct ct_zone_pending_entry *ctzpe = iter->data;

        /* The transaction is open, so any pending entries in the
         * CT_ZONE_DB_QUEUED must be sent and any in CT_ZONE_DB_QUEUED
         * need to be retried. */
        if (ctzpe->state != CT_ZONE_DB_QUEUED
            && ctzpe->state != CT_ZONE_DB_SENT) {
            continue;
        }

        char *user_str = xasprintf("ct-zone-%s", iter->name);
        if (ctzpe->add) {
            char *zone_str = xasprintf("%"PRId32, ctzpe->zone);
            struct smap_node *node =
                smap_get_node(&br_int->external_ids, user_str);
            if (!node || strcmp(node->value, zone_str)) {
                ovsrec_bridge_update_external_ids_setkey(br_int,
                                                         user_str, zone_str);
            }
            free(zone_str);
        } else {
            if (smap_get(&br_int->external_ids, user_str)) {
                ovsrec_bridge_update_external_ids_delkey(br_int, user_str);
            }
        }
        free(user_str);

        ctzpe->state = CT_ZONE_DB_SENT;
    }
}

static void
restore_ct_zones(const struct ovsrec_bridge_table *bridge_table,
                 const struct ovsrec_open_vswitch_table *ovs_table,
                 struct simap *ct_zones, unsigned long *ct_zone_bitmap)
{
    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_table_first(ovs_table);
    if (!cfg) {
        return;
    }

    const struct ovsrec_bridge *br_int;
    br_int = get_bridge(bridge_table, br_int_name(cfg));
    if (!br_int) {
        /* If the integration bridge hasn't been defined, assume that
         * any existing ct-zone definitions aren't valid. */
        return;
    }

    struct smap_node *node;
    SMAP_FOR_EACH(node, &br_int->external_ids) {
        if (strncmp(node->key, "ct-zone-", 8)) {
            continue;
        }

        const char *user = node->key + 8;
        int zone = atoi(node->value);

        if (user[0] && zone) {
            VLOG_DBG("restoring ct zone %"PRId32" for '%s'", zone, user);
            bitmap_set1(ct_zone_bitmap, zone);
            simap_put(ct_zones, user, zone);
        }
    }
}

static uint64_t
get_nb_cfg(const struct sbrec_sb_global_table *sb_global_table,
           unsigned int cond_seqno, unsigned int expected_cond_seqno)
{
    static uint64_t nb_cfg = 0;

    /* Delay getting nb_cfg if there are monitor condition changes
     * in flight.  It might be that those changes would instruct the
     * server to send updates that happened before SB_Global.nb_cfg.
     */
    if (cond_seqno != expected_cond_seqno) {
        return nb_cfg;
    }

    const struct sbrec_sb_global *sb
        = sbrec_sb_global_table_first(sb_global_table);
    nb_cfg = sb ? sb->nb_cfg : 0;
    return nb_cfg;
}

/* Propagates the local cfg seqno, 'cur_cfg', to the chassis_private record
 * and to the local OVS DB.
 */
static void
store_nb_cfg(struct ovsdb_idl_txn *sb_txn, struct ovsdb_idl_txn *ovs_txn,
             const struct sbrec_chassis_private *chassis,
             const struct ovsrec_bridge *br_int,
             unsigned int delay_nb_cfg_report)
{
    struct ofctrl_acked_seqnos *acked_nb_cfg_seqnos =
        ofctrl_acked_seqnos_get(ofctrl_seq_type_nb_cfg);
    uint64_t cur_cfg = acked_nb_cfg_seqnos->last_acked;

    if (!cur_cfg) {
        goto done;
    }

    if (sb_txn && chassis && cur_cfg != chassis->nb_cfg) {
        sbrec_chassis_private_set_nb_cfg(chassis, cur_cfg);
        sbrec_chassis_private_set_nb_cfg_timestamp(chassis, time_wall_msec());

        if (delay_nb_cfg_report) {
            VLOG_INFO("Sleep for %u sec", delay_nb_cfg_report);
            xsleep(delay_nb_cfg_report);
        }
    }

    if (ovs_txn && br_int &&
            cur_cfg != smap_get_ullong(&br_int->external_ids,
                                       OVS_NB_CFG_NAME, 0)) {
        char *cur_cfg_str = xasprintf("%"PRId64, cur_cfg);
        ovsrec_bridge_update_external_ids_setkey(br_int, OVS_NB_CFG_NAME,
                                                 cur_cfg_str);
        free(cur_cfg_str);
    }

done:
    ofctrl_acked_seqnos_destroy(acked_nb_cfg_seqnos);
}

static const char *
get_transport_zones(const struct ovsrec_open_vswitch_table *ovs_table)
{
    const struct ovsrec_open_vswitch *cfg
        = ovsrec_open_vswitch_table_first(ovs_table);
    return smap_get_def(&cfg->external_ids, "ovn-transport-zones", "");
}

static void
ctrl_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    /* We do not monitor all tables by default, so modules must register
     * their interest explicitly. */
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_external_ids);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_bridges);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_bfd);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_bfd_status);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_type);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_options);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_external_ids);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_fail_mode);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_other_config);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_external_ids);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_ssl);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_bootstrap_ca_cert);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_ca_cert);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_certificate);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_private_key);
    chassis_register_ovs_idl(ovs_idl);
    encaps_register_ovs_idl(ovs_idl);
    binding_register_ovs_idl(ovs_idl);
    bfd_register_ovs_idl(ovs_idl);
    physical_register_ovs_idl(ovs_idl);
}

#define SB_NODES \
    SB_NODE(chassis, "chassis") \
    SB_NODE(encap, "encap") \
    SB_NODE(address_set, "address_set") \
    SB_NODE(port_group, "port_group") \
    SB_NODE(multicast_group, "multicast_group") \
    SB_NODE(datapath_binding, "datapath_binding") \
    SB_NODE(logical_dp_group, "logical_dp_group") \
    SB_NODE(port_binding, "port_binding") \
    SB_NODE(mac_binding, "mac_binding") \
    SB_NODE(logical_flow, "logical_flow") \
    SB_NODE(dhcp_options, "dhcp_options") \
    SB_NODE(dhcpv6_options, "dhcpv6_options") \
    SB_NODE(dns, "dns") \
    SB_NODE(load_balancer, "load_balancer") \
    SB_NODE(fdb, "fdb")

enum sb_engine_node {
#define SB_NODE(NAME, NAME_STR) SB_##NAME,
    SB_NODES
#undef SB_NODE
};

#define SB_NODE(NAME, NAME_STR) ENGINE_FUNC_SB(NAME);
    SB_NODES
#undef SB_NODE

#define OVS_NODES \
    OVS_NODE(open_vswitch, "open_vswitch") \
    OVS_NODE(bridge, "bridge") \
    OVS_NODE(port, "port") \
    OVS_NODE(interface, "interface") \
    OVS_NODE(qos, "qos")

enum ovs_engine_node {
#define OVS_NODE(NAME, NAME_STR) OVS_##NAME,
    OVS_NODES
#undef OVS_NODE
};

#define OVS_NODE(NAME, NAME_STR) ENGINE_FUNC_OVS(NAME);
    OVS_NODES
#undef OVS_NODE

struct ed_type_ofctrl_is_connected {
    bool connected;
};

static void *
en_ofctrl_is_connected_init(struct engine_node *node OVS_UNUSED,
                            struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_ofctrl_is_connected *data = xzalloc(sizeof *data);
    return data;
}

static void
en_ofctrl_is_connected_cleanup(void *data OVS_UNUSED)
{
}

static void
en_ofctrl_is_connected_run(struct engine_node *node, void *data)
{
    struct ed_type_ofctrl_is_connected *of_data = data;
    if (of_data->connected != ofctrl_is_connected()) {
        of_data->connected = !of_data->connected;

        /* Flush ofctrl seqno requests when the ofctrl connection goes down. */
        if (!of_data->connected) {
            ofctrl_seqno_flush();
            binding_seqno_flush();
        }
        engine_set_node_state(node, EN_UPDATED);
        return;
    }
    engine_set_node_state(node, EN_UNCHANGED);
}

struct ed_type_addr_sets {
    struct shash addr_sets;
    bool change_tracked;
    struct sset new;
    struct sset deleted;
    struct sset updated;
};

static void *
en_addr_sets_init(struct engine_node *node OVS_UNUSED,
                  struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_addr_sets *as = xzalloc(sizeof *as);

    shash_init(&as->addr_sets);
    as->change_tracked = false;
    sset_init(&as->new);
    sset_init(&as->deleted);
    sset_init(&as->updated);
    return as;
}

static void
en_addr_sets_cleanup(void *data)
{
    struct ed_type_addr_sets *as = data;
    expr_const_sets_destroy(&as->addr_sets);
    shash_destroy(&as->addr_sets);
    sset_destroy(&as->new);
    sset_destroy(&as->deleted);
    sset_destroy(&as->updated);
}

static void
en_addr_sets_run(struct engine_node *node, void *data)
{
    struct ed_type_addr_sets *as = data;

    sset_clear(&as->new);
    sset_clear(&as->deleted);
    sset_clear(&as->updated);
    expr_const_sets_destroy(&as->addr_sets);

    struct sbrec_address_set_table *as_table =
        (struct sbrec_address_set_table *)EN_OVSDB_GET(
            engine_get_input("SB_address_set", node));

    addr_sets_init(as_table, &as->addr_sets);

    as->change_tracked = false;
    engine_set_node_state(node, EN_UPDATED);
}

static bool
addr_sets_sb_address_set_handler(struct engine_node *node, void *data)
{
    struct ed_type_addr_sets *as = data;

    sset_clear(&as->new);
    sset_clear(&as->deleted);
    sset_clear(&as->updated);

    struct sbrec_address_set_table *as_table =
        (struct sbrec_address_set_table *)EN_OVSDB_GET(
            engine_get_input("SB_address_set", node));

    addr_sets_update(as_table, &as->addr_sets, &as->new,
                     &as->deleted, &as->updated);

    if (!sset_is_empty(&as->new) || !sset_is_empty(&as->deleted) ||
            !sset_is_empty(&as->updated)) {
        engine_set_node_state(node, EN_UPDATED);
    } else {
        engine_set_node_state(node, EN_UNCHANGED);
    }

    as->change_tracked = true;
    return true;
}

struct ed_type_port_groups{
    struct shash port_groups;
    bool change_tracked;
    struct sset new;
    struct sset deleted;
    struct sset updated;
};

static void *
en_port_groups_init(struct engine_node *node OVS_UNUSED,
                    struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_port_groups *pg = xzalloc(sizeof *pg);

    shash_init(&pg->port_groups);
    pg->change_tracked = false;
    sset_init(&pg->new);
    sset_init(&pg->deleted);
    sset_init(&pg->updated);
    return pg;
}

static void
en_port_groups_cleanup(void *data)
{
    struct ed_type_port_groups *pg = data;
    expr_const_sets_destroy(&pg->port_groups);
    shash_destroy(&pg->port_groups);
    sset_destroy(&pg->new);
    sset_destroy(&pg->deleted);
    sset_destroy(&pg->updated);
}

static void
en_port_groups_run(struct engine_node *node, void *data)
{
    struct ed_type_port_groups *pg = data;

    sset_clear(&pg->new);
    sset_clear(&pg->deleted);
    sset_clear(&pg->updated);
    expr_const_sets_destroy(&pg->port_groups);

    struct sbrec_port_group_table *pg_table =
        (struct sbrec_port_group_table *)EN_OVSDB_GET(
            engine_get_input("SB_port_group", node));

    port_groups_init(pg_table, &pg->port_groups);

    pg->change_tracked = false;
    engine_set_node_state(node, EN_UPDATED);
}

static bool
port_groups_sb_port_group_handler(struct engine_node *node, void *data)
{
    struct ed_type_port_groups *pg = data;

    sset_clear(&pg->new);
    sset_clear(&pg->deleted);
    sset_clear(&pg->updated);

    struct sbrec_port_group_table *pg_table =
        (struct sbrec_port_group_table *)EN_OVSDB_GET(
            engine_get_input("SB_port_group", node));

    port_groups_update(pg_table, &pg->port_groups, &pg->new,
                     &pg->deleted, &pg->updated);

    if (!sset_is_empty(&pg->new) || !sset_is_empty(&pg->deleted) ||
            !sset_is_empty(&pg->updated)) {
        engine_set_node_state(node, EN_UPDATED);
    } else {
        engine_set_node_state(node, EN_UNCHANGED);
    }

    pg->change_tracked = true;
    return true;
}

struct ed_type_runtime_data {
    /* Contains "struct local_datapath" nodes. */
    struct hmap local_datapaths;

    /* Contains "struct local_binding" nodes. */
    struct shash local_bindings;

    /* Contains the name of each logical port resident on the local
     * hypervisor.  These logical ports include the VIFs (and their child
     * logical ports, if any) that belong to VMs running on the hypervisor,
     * l2gateway ports for which options:l2gateway-chassis designates the
     * local hypervisor, and localnet ports. */
    struct sset local_lports;

    /* Contains the same ports as local_lports, but in the format:
     * <datapath-tunnel-key>_<port-tunnel-key> */
    struct sset local_lport_ids;
    struct sset active_tunnels;

    /* runtime data engine private data. */
    struct sset egress_ifaces;
    struct smap local_iface_ids;

    /* Tracked data. See below for more details and comments. */
    bool tracked;
    bool local_lports_changed;
    struct hmap tracked_dp_bindings;

    /* CT zone data. Contains datapaths that had updated CT zones */
    struct hmapx ct_updated_datapaths;
};

/* struct ed_type_runtime_data has the below members for tracking the
 * changes done to the runtime_data engine by the runtime_data engine
 * handlers. Since this engine is an input to the flow_output engine,
 * the flow output runtime data handler will make use of this tracked data.
 *
 *  ------------------------------------------------------------------------
 * |                      | This is a hmap of                               |
 * |                      | 'struct tracked_binding_datapath' defined in    |
 * |                      | binding.h. Runtime data handlers for OVS        |
 * |                      | Interface and Port Binding changes store the    |
 * | @tracked_dp_bindings | changed datapaths (datapaths added/removed from |
 * |                      | local_datapaths) and changed port bindings      |
 * |                      | (added/updated/deleted in 'local_bindings').    |
 * |                      | So any changes to the runtime data -            |
 * |                      | local_datapaths and local_bindings is captured  |
 * |                      | here.                                           |
 *  ------------------------------------------------------------------------
 * |                      | This is a bool which represents if the runtime  |
 * |                      | data 'local_lports' changed by the runtime data |
 * |                      | handlers for OVS Interface and Port Binding     |
 * |                      | changes. If 'local_lports' is updated and also  |
 * |                      | results in any port binding updates, it is      |
 * |@local_lports_changed | captured in the @tracked_dp_bindings. So there  |
 * |                      | is no need to capture the changes in the        |
 * |                      | local_lports. If @local_lports_changed is true  |
 * |                      | but without anydata in the @tracked_dp_bindings,|
 * |                      | it means we needto only update the SB monitor   |
 * |                      | clauses and there isno need for any flow        |
 * |                      | (re)computations.                               |
 *  ------------------------------------------------------------------------
 * |                      | This represents if the data was tracked or not  |
 * |                      | by the runtime data handlers during the engine  |
 * |   @tracked           | run. If the runtime data recompute is           |
 * |                      | triggered, it means there is no tracked data.   |
 *  ------------------------------------------------------------------------
 *
 *
 * The changes to the following runtime_data variables are not tracked.
 *
 *  ---------------------------------------------------------------------
 * | local_datapaths  | The changes to these runtime data is captured in |
 * | local_bindings   | the @tracked_dp_bindings indirectly and hence it |
 * | local_lport_ids  | is not tracked explicitly.                       |
 *  ---------------------------------------------------------------------
 * | local_iface_ids  | This is used internally within the runtime data  |
 * | egress_ifaces    | engine (used only in binding.c) and hence there  |
 * |                  | there is no need to track.                       |
 *  ---------------------------------------------------------------------
 * |                  | Active tunnels is built in the                   |
 * |                  | bfd_calculate_active_tunnels() for the tunnel    |
 * |                  | OVS interfaces. Any changes to non VIF OVS       |
 * |                  | interfaces results in triggering the full        |
 * | active_tunnels   | recompute of runtime data engine and hence there |
 * |                  | the tracked data doesn't track it. When we       |
 * |                  | support handling changes to non VIF OVS          |
 * |                  | interfaces we need to track the changes to the   |
 * |                  | active tunnels.                                  |
 *  ---------------------------------------------------------------------
 *
 */

static void
en_runtime_data_clear_tracked_data(void *data_)
{
    struct ed_type_runtime_data *data = data_;

    binding_tracked_dp_destroy(&data->tracked_dp_bindings);
    hmap_init(&data->tracked_dp_bindings);
    data->local_lports_changed = false;
    data->tracked = false;
}

static void *
en_runtime_data_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_runtime_data *data = xzalloc(sizeof *data);

    hmap_init(&data->local_datapaths);
    sset_init(&data->local_lports);
    sset_init(&data->local_lport_ids);
    sset_init(&data->active_tunnels);
    sset_init(&data->egress_ifaces);
    smap_init(&data->local_iface_ids);
    local_bindings_init(&data->local_bindings);

    /* Init the tracked data. */
    hmap_init(&data->tracked_dp_bindings);

    hmapx_init(&data->ct_updated_datapaths);

    return data;
}

static void
en_runtime_data_cleanup(void *data)
{
    struct ed_type_runtime_data *rt_data = data;

    sset_destroy(&rt_data->local_lports);
    sset_destroy(&rt_data->local_lport_ids);
    sset_destroy(&rt_data->active_tunnels);
    sset_destroy(&rt_data->egress_ifaces);
    smap_destroy(&rt_data->local_iface_ids);
    struct local_datapath *cur_node, *next_node;
    HMAP_FOR_EACH_SAFE (cur_node, next_node, hmap_node,
                        &rt_data->local_datapaths) {
        free(cur_node->peer_ports);
        hmap_remove(&rt_data->local_datapaths, &cur_node->hmap_node);
        free(cur_node);
    }
    hmap_destroy(&rt_data->local_datapaths);
    local_bindings_destroy(&rt_data->local_bindings);
    hmapx_destroy(&rt_data->ct_updated_datapaths);
}

static void
init_binding_ctx(struct engine_node *node,
                 struct ed_type_runtime_data *rt_data,
                 struct binding_ctx_in *b_ctx_in,
                 struct binding_ctx_out *b_ctx_out)
{
    struct ovsrec_open_vswitch_table *ovs_table =
        (struct ovsrec_open_vswitch_table *)EN_OVSDB_GET(
            engine_get_input("OVS_open_vswitch", node));
    struct ovsrec_bridge_table *bridge_table =
        (struct ovsrec_bridge_table *)EN_OVSDB_GET(
            engine_get_input("OVS_bridge", node));
    const char *chassis_id = get_ovs_chassis_id(ovs_table);
    const struct ovsrec_bridge *br_int = get_br_int(bridge_table, ovs_table);

    ovs_assert(br_int && chassis_id);

    struct ovsdb_idl_index *sbrec_chassis_by_name =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_chassis", node),
                "name");

    const struct sbrec_chassis *chassis
        = chassis_lookup_by_name(sbrec_chassis_by_name, chassis_id);
    ovs_assert(chassis);

    struct ovsrec_port_table *port_table =
        (struct ovsrec_port_table *)EN_OVSDB_GET(
            engine_get_input("OVS_port", node));

    struct ovsrec_interface_table *iface_table =
        (struct ovsrec_interface_table *)EN_OVSDB_GET(
            engine_get_input("OVS_interface", node));

    struct ovsrec_qos_table *qos_table =
        (struct ovsrec_qos_table *)EN_OVSDB_GET(
            engine_get_input("OVS_qos", node));

    struct sbrec_port_binding_table *pb_table =
        (struct sbrec_port_binding_table *)EN_OVSDB_GET(
            engine_get_input("SB_port_binding", node));

    struct ovsdb_idl_index *sbrec_datapath_binding_by_key =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_datapath_binding", node),
                "key");

    struct ovsdb_idl_index *sbrec_port_binding_by_name =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_port_binding", node),
                "name");

    struct ovsdb_idl_index *sbrec_port_binding_by_datapath =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_port_binding", node),
                "datapath");

    b_ctx_in->ovnsb_idl_txn = engine_get_context()->ovnsb_idl_txn;
    b_ctx_in->ovs_idl_txn = engine_get_context()->ovs_idl_txn;
    b_ctx_in->sbrec_datapath_binding_by_key = sbrec_datapath_binding_by_key;
    b_ctx_in->sbrec_port_binding_by_datapath = sbrec_port_binding_by_datapath;
    b_ctx_in->sbrec_port_binding_by_name = sbrec_port_binding_by_name;
    b_ctx_in->port_table = port_table;
    b_ctx_in->iface_table = iface_table;
    b_ctx_in->qos_table = qos_table;
    b_ctx_in->port_binding_table = pb_table;
    b_ctx_in->br_int = br_int;
    b_ctx_in->chassis_rec = chassis;
    b_ctx_in->active_tunnels = &rt_data->active_tunnels;
    b_ctx_in->bridge_table = bridge_table;
    b_ctx_in->ovs_table = ovs_table;

    b_ctx_out->local_datapaths = &rt_data->local_datapaths;
    b_ctx_out->local_lports = &rt_data->local_lports;
    b_ctx_out->local_lports_changed = false;
    b_ctx_out->local_lport_ids = &rt_data->local_lport_ids;
    b_ctx_out->local_lport_ids_changed = false;
    b_ctx_out->non_vif_ports_changed = false;
    b_ctx_out->egress_ifaces = &rt_data->egress_ifaces;
    b_ctx_out->local_bindings = &rt_data->local_bindings;
    b_ctx_out->local_iface_ids = &rt_data->local_iface_ids;
    b_ctx_out->tracked_dp_bindings = NULL;
    b_ctx_out->local_lports_changed = NULL;
}

static void
en_runtime_data_run(struct engine_node *node, void *data)
{
    struct ed_type_runtime_data *rt_data = data;
    struct hmap *local_datapaths = &rt_data->local_datapaths;
    struct sset *local_lports = &rt_data->local_lports;
    struct sset *local_lport_ids = &rt_data->local_lport_ids;
    struct sset *active_tunnels = &rt_data->active_tunnels;

    /* Clear the (stale) tracked data if any. Even though the tracked data
     * gets cleared in the beginning of engine_init_run(),
     * any of the runtime data handler might have set some tracked
     * data and later another runtime data handler might return false
     * resulting in full recompute of runtime engine and rendering the tracked
     * data stale.
     *
     * It's possible that engine framework can be enhanced to indicate
     * the node handlers (in this case flow_output_runtime_data_handler)
     * that its input node had a full recompute. However we would still
     * need to clear the tracked data, because we don't want the
     * stale tracked data to be accessed outside of the engine, since the
     * tracked data is cleared in the engine_init_run() and not at the
     * end of the engine run.
     * */
    en_runtime_data_clear_tracked_data(data);

    static bool first_run = true;
    if (first_run) {
        /* don't cleanup since there is no data yet */
        first_run = false;
    } else {
        struct local_datapath *cur_node, *next_node;
        HMAP_FOR_EACH_SAFE (cur_node, next_node, hmap_node, local_datapaths) {
            free(cur_node->peer_ports);
            hmap_remove(local_datapaths, &cur_node->hmap_node);
            free(cur_node);
        }
        hmap_clear(local_datapaths);
        local_bindings_destroy(&rt_data->local_bindings);
        sset_destroy(local_lports);
        sset_destroy(local_lport_ids);
        sset_destroy(active_tunnels);
        sset_destroy(&rt_data->egress_ifaces);
        smap_destroy(&rt_data->local_iface_ids);
        sset_init(local_lports);
        sset_init(local_lport_ids);
        sset_init(active_tunnels);
        sset_init(&rt_data->egress_ifaces);
        smap_init(&rt_data->local_iface_ids);
        local_bindings_init(&rt_data->local_bindings);
        hmapx_clear(&rt_data->ct_updated_datapaths);
    }

    struct binding_ctx_in b_ctx_in;
    struct binding_ctx_out b_ctx_out;
    init_binding_ctx(node, rt_data, &b_ctx_in, &b_ctx_out);

    struct ed_type_ofctrl_is_connected *ed_ofctrl_is_connected =
        engine_get_input_data("ofctrl_is_connected", node);
    if (ed_ofctrl_is_connected->connected) {
        /* Calculate the active tunnels only if have an an active
         * OpenFlow connection to br-int.
         * If we don't have a connection to br-int, it could mean
         * ovs-vswitchd is down for some reason and the BFD status
         * in the Interface rows could be stale. So its better to
         * consider 'active_tunnels' set to be empty if it's not
         * connected. */
        bfd_calculate_active_tunnels(b_ctx_in.br_int, active_tunnels);
    }

    binding_run(&b_ctx_in, &b_ctx_out);

    engine_set_node_state(node, EN_UPDATED);
}

static bool
runtime_data_ovs_interface_handler(struct engine_node *node, void *data)
{
    struct ed_type_runtime_data *rt_data = data;
    struct binding_ctx_in b_ctx_in;
    struct binding_ctx_out b_ctx_out;
    init_binding_ctx(node, rt_data, &b_ctx_in, &b_ctx_out);
    rt_data->tracked = true;
    b_ctx_out.tracked_dp_bindings = &rt_data->tracked_dp_bindings;

    if (!binding_handle_ovs_interface_changes(&b_ctx_in, &b_ctx_out)) {
        return false;
    }

    if (b_ctx_out.local_lports_changed) {
        engine_set_node_state(node, EN_UPDATED);
        rt_data->local_lports_changed = b_ctx_out.local_lports_changed;
    }

    return true;
}

static bool
runtime_data_sb_port_binding_handler(struct engine_node *node, void *data)
{
    struct ed_type_runtime_data *rt_data = data;
    struct binding_ctx_in b_ctx_in;
    struct binding_ctx_out b_ctx_out;
    init_binding_ctx(node, rt_data, &b_ctx_in, &b_ctx_out);
    if (!b_ctx_in.chassis_rec) {
        return false;
    }

    rt_data->tracked = true;
    b_ctx_out.tracked_dp_bindings = &rt_data->tracked_dp_bindings;

    if (!binding_handle_port_binding_changes(&b_ctx_in, &b_ctx_out)) {
        return false;
    }

    if (b_ctx_out.local_lport_ids_changed ||
            b_ctx_out.non_vif_ports_changed ||
            !hmap_is_empty(b_ctx_out.tracked_dp_bindings)) {
        engine_set_node_state(node, EN_UPDATED);
    }

    return true;
}

static bool
runtime_data_sb_datapath_binding_handler(struct engine_node *node OVS_UNUSED,
                                         void *data OVS_UNUSED)
{
    struct sbrec_datapath_binding_table *dp_table =
        (struct sbrec_datapath_binding_table *)EN_OVSDB_GET(
            engine_get_input("SB_datapath_binding", node));
    const struct sbrec_datapath_binding *dp;
    struct ed_type_runtime_data *rt_data = data;

    SBREC_DATAPATH_BINDING_TABLE_FOR_EACH_TRACKED (dp, dp_table) {
        if (sbrec_datapath_binding_is_deleted(dp)) {
            if (get_local_datapath(&rt_data->local_datapaths,
                                   dp->tunnel_key)) {
                return false;
            }
        }
    }

    return true;
}

/* Connection tracking zones. */
struct ed_type_ct_zones {
    unsigned long bitmap[BITMAP_N_LONGS(MAX_CT_ZONES)];
    struct shash pending;
    struct simap current;
};

static void *
en_ct_zones_init(struct engine_node *node, struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_ct_zones *data = xzalloc(sizeof *data);
    struct ovsrec_open_vswitch_table *ovs_table =
        (struct ovsrec_open_vswitch_table *)EN_OVSDB_GET(
            engine_get_input("OVS_open_vswitch", node));
    struct ovsrec_bridge_table *bridge_table =
        (struct ovsrec_bridge_table *)EN_OVSDB_GET(
            engine_get_input("OVS_bridge", node));

    shash_init(&data->pending);
    simap_init(&data->current);

    memset(data->bitmap, 0, sizeof data->bitmap);
    bitmap_set1(data->bitmap, 0); /* Zone 0 is reserved. */
    restore_ct_zones(bridge_table, ovs_table, &data->current, data->bitmap);
    return data;
}

static void
en_ct_zones_cleanup(void *data)
{
    struct ed_type_ct_zones *ct_zones_data = data;

    simap_destroy(&ct_zones_data->current);
    shash_destroy_free_data(&ct_zones_data->pending);
}

static void
en_ct_zones_run(struct engine_node *node, void *data)
{
    struct ed_type_ct_zones *ct_zones_data = data;
    struct ed_type_runtime_data *rt_data =
        engine_get_input_data("runtime_data", node);

    hmapx_clear(&rt_data->ct_updated_datapaths);
    update_ct_zones(&rt_data->local_lports, &rt_data->local_datapaths,
                    &ct_zones_data->current, ct_zones_data->bitmap,
                    &ct_zones_data->pending, &rt_data->ct_updated_datapaths);


    engine_set_node_state(node, EN_UPDATED);
}

/* The data in the ct_zones node is always valid (i.e., no stale pointers). */
static bool
en_ct_zones_is_valid(struct engine_node *node OVS_UNUSED)
{
    return true;
}

struct ed_type_mff_ovn_geneve {
    enum mf_field_id mff_ovn_geneve;
};

static void *
en_mff_ovn_geneve_init(struct engine_node *node OVS_UNUSED,
                       struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_mff_ovn_geneve *data = xzalloc(sizeof *data);
    return data;
}

static void
en_mff_ovn_geneve_cleanup(void *data OVS_UNUSED)
{
}

static void
en_mff_ovn_geneve_run(struct engine_node *node, void *data)
{
    struct ed_type_mff_ovn_geneve *ed_mff_ovn_geneve = data;
    enum mf_field_id mff_ovn_geneve = ofctrl_get_mf_field_id();
    if (ed_mff_ovn_geneve->mff_ovn_geneve != mff_ovn_geneve) {
        ed_mff_ovn_geneve->mff_ovn_geneve = mff_ovn_geneve;
        engine_set_node_state(node, EN_UPDATED);
        return;
    }
    engine_set_node_state(node, EN_UNCHANGED);
}

/* Engine node en_physical_flow_changes indicates whether
 * there is a need to
 *   - recompute only physical flows or
 *   - we can incrementally process the physical flows.
 *
 * en_physical_flow_changes is an input to flow_output engine node.
 * If the engine node 'en_physical_flow_changes' gets updated during
 * engine run, it means the handler for this -
 * flow_output_physical_flow_changes_handler() will either
 *    - recompute the physical flows by calling 'physical_run() or
 *    - incrementlly process some of the changes for physical flow
 *      calculation. Right now we handle OVS interfaces changes
 *      for physical flow computation.
 *
 * When ever a port binding happens, the follow up
 * activity is the zone id allocation for that port binding.
 * With this intermediate engine node, we avoid full recomputation.
 * Instead we do physical flow computation (either full recomputation
 * by calling physical_run() or handling the changes incrementally.
 *
 * Hence this is an intermediate engine node to indicate the
 * flow_output engine to recomputes/compute the physical flows.
 *
 * TODO 1. Ideally this engine node should recompute/compute the physical
 *         flows instead of relegating it to the flow_output node.
 *         But this requires splitting the flow_output node to
 *         logical_flow_output and physical_flow_output.
 *
 * TODO 2. We can further optimise the en_ct_zone changes to
 *         compute the phsyical flows for changed zone ids.
 *
 * TODO 3: physical.c has a global simap -localvif_to_ofport which stores the
 *         local OVS interfaces and the ofport numbers. Ideally this should be
 *         part of the engine data.
 */
struct ed_type_pfc_data {
    /* Both these variables are tracked and set in each engine run. */
    bool recompute_physical_flows;
    bool ovs_ifaces_changed;
};

static void
en_physical_flow_changes_clear_tracked_data(void *data_)
{
    struct ed_type_pfc_data *data = data_;
    data->recompute_physical_flows = false;
    data->ovs_ifaces_changed = false;
}

static void *
en_physical_flow_changes_init(struct engine_node *node OVS_UNUSED,
                              struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_pfc_data *data = xzalloc(sizeof *data);
    return data;
}

static void
en_physical_flow_changes_cleanup(void *data OVS_UNUSED)
{
}

/* Indicate to the flow_output engine that we need to recompute physical
 * flows. */
static void
en_physical_flow_changes_run(struct engine_node *node, void *data)
{
    struct ed_type_pfc_data *pfc_tdata = data;
    pfc_tdata->recompute_physical_flows = true;
    engine_set_node_state(node, EN_UPDATED);
}

/* ct_zone changes are not handled incrementally but a handler is required
 * to avoid skipping the ovs_iface incremental change handler.
 */
static bool
physical_flow_changes_ct_zones_handler(struct engine_node *node OVS_UNUSED,
                                       void *data OVS_UNUSED)
{
    return false;
}

/* There are OVS interface changes. Indicate to the flow_output engine
 * to handle these OVS interface changes for physical flow computations. */
static bool
physical_flow_changes_ovs_iface_handler(struct engine_node *node, void *data)
{
    struct ed_type_pfc_data *pfc_tdata = data;
    pfc_tdata->ovs_ifaces_changed = true;
    engine_set_node_state(node, EN_UPDATED);
    return true;
}

struct flow_output_persistent_data {
    uint32_t conj_id_ofs;
    struct lflow_cache *lflow_cache;
};

struct ed_type_flow_output {
    /* desired flows */
    struct ovn_desired_flow_table flow_table;
    /* group ids for load balancing */
    struct ovn_extend_table group_table;
    /* meter ids for QoS */
    struct ovn_extend_table meter_table;
    /* lflow resource cross reference */
    struct lflow_resource_ref lflow_resource_ref;

    /* Data which is persistent and not cleared during
     * full recompute. */
    struct flow_output_persistent_data pd;
};

static void init_physical_ctx(struct engine_node *node,
                              struct ed_type_runtime_data *rt_data,
                              struct physical_ctx *p_ctx)
{
    struct ovsdb_idl_index *sbrec_port_binding_by_name =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_port_binding", node),
                "name");

    struct sbrec_multicast_group_table *multicast_group_table =
        (struct sbrec_multicast_group_table *)EN_OVSDB_GET(
            engine_get_input("SB_multicast_group", node));

    struct sbrec_port_binding_table *port_binding_table =
        (struct sbrec_port_binding_table *)EN_OVSDB_GET(
            engine_get_input("SB_port_binding", node));

    struct sbrec_chassis_table *chassis_table =
        (struct sbrec_chassis_table *)EN_OVSDB_GET(
            engine_get_input("SB_chassis", node));

    struct ed_type_mff_ovn_geneve *ed_mff_ovn_geneve =
        engine_get_input_data("mff_ovn_geneve", node);

    struct ovsrec_open_vswitch_table *ovs_table =
        (struct ovsrec_open_vswitch_table *)EN_OVSDB_GET(
            engine_get_input("OVS_open_vswitch", node));
    struct ovsrec_bridge_table *bridge_table =
        (struct ovsrec_bridge_table *)EN_OVSDB_GET(
            engine_get_input("OVS_bridge", node));
    const struct ovsrec_bridge *br_int = get_br_int(bridge_table, ovs_table);
    const char *chassis_id = get_ovs_chassis_id(ovs_table);
    const struct sbrec_chassis *chassis = NULL;
    struct ovsdb_idl_index *sbrec_chassis_by_name =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_chassis", node),
                "name");
    if (chassis_id) {
        chassis = chassis_lookup_by_name(sbrec_chassis_by_name, chassis_id);
    }

    ovs_assert(br_int && chassis);

    struct ovsrec_interface_table *iface_table =
        (struct ovsrec_interface_table *)EN_OVSDB_GET(
            engine_get_input("OVS_interface", node));

    struct ed_type_ct_zones *ct_zones_data =
        engine_get_input_data("ct_zones", node);
    struct simap *ct_zones = &ct_zones_data->current;

    p_ctx->sbrec_port_binding_by_name = sbrec_port_binding_by_name;
    p_ctx->port_binding_table = port_binding_table;
    p_ctx->mc_group_table = multicast_group_table;
    p_ctx->br_int = br_int;
    p_ctx->chassis_table = chassis_table;
    p_ctx->iface_table = iface_table;
    p_ctx->chassis = chassis;
    p_ctx->active_tunnels = &rt_data->active_tunnels;
    p_ctx->local_datapaths = &rt_data->local_datapaths;
    p_ctx->local_lports = &rt_data->local_lports;
    p_ctx->ct_zones = ct_zones;
    p_ctx->mff_ovn_geneve = ed_mff_ovn_geneve->mff_ovn_geneve;
    p_ctx->local_bindings = &rt_data->local_bindings;
    p_ctx->ct_updated_datapaths = &rt_data->ct_updated_datapaths;
}

static void init_lflow_ctx(struct engine_node *node,
                           struct ed_type_runtime_data *rt_data,
                           struct ed_type_flow_output *fo,
                           struct lflow_ctx_in *l_ctx_in,
                           struct lflow_ctx_out *l_ctx_out)
{
    struct ovsdb_idl_index *sbrec_port_binding_by_name =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_port_binding", node),
                "name");

    struct ovsdb_idl_index *sbrec_logical_flow_by_dp =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_logical_flow", node),
                "logical_datapath");

    struct ovsdb_idl_index *sbrec_logical_flow_by_dp_group =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_logical_flow", node),
                "logical_dp_group");

    struct ovsdb_idl_index *sbrec_mc_group_by_name_dp =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_multicast_group", node),
                "name_datapath");

    struct sbrec_dhcp_options_table *dhcp_table =
        (struct sbrec_dhcp_options_table *)EN_OVSDB_GET(
            engine_get_input("SB_dhcp_options", node));

    struct sbrec_dhcpv6_options_table *dhcpv6_table =
        (struct sbrec_dhcpv6_options_table *)EN_OVSDB_GET(
            engine_get_input("SB_dhcpv6_options", node));

    struct sbrec_mac_binding_table *mac_binding_table =
        (struct sbrec_mac_binding_table *)EN_OVSDB_GET(
            engine_get_input("SB_mac_binding", node));

    struct sbrec_logical_flow_table *logical_flow_table =
        (struct sbrec_logical_flow_table *)EN_OVSDB_GET(
            engine_get_input("SB_logical_flow", node));

    struct sbrec_logical_dp_group_table *logical_dp_group_table =
        (struct sbrec_logical_dp_group_table *)EN_OVSDB_GET(
            engine_get_input("SB_logical_dp_group", node));

    struct sbrec_multicast_group_table *multicast_group_table =
        (struct sbrec_multicast_group_table *)EN_OVSDB_GET(
            engine_get_input("SB_multicast_group", node));

    struct sbrec_load_balancer_table *lb_table =
        (struct sbrec_load_balancer_table *)EN_OVSDB_GET(
            engine_get_input("SB_load_balancer", node));

    struct sbrec_fdb_table *fdb_table =
        (struct sbrec_fdb_table *)EN_OVSDB_GET(
            engine_get_input("SB_fdb", node));

    struct ovsrec_open_vswitch_table *ovs_table =
        (struct ovsrec_open_vswitch_table *)EN_OVSDB_GET(
            engine_get_input("OVS_open_vswitch", node));

    const char *chassis_id = get_ovs_chassis_id(ovs_table);
    const struct sbrec_chassis *chassis = NULL;
    struct ovsdb_idl_index *sbrec_chassis_by_name =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_chassis", node),
                "name");
    if (chassis_id) {
        chassis = chassis_lookup_by_name(sbrec_chassis_by_name, chassis_id);
    }

    ovs_assert(chassis);

    struct ed_type_addr_sets *as_data =
        engine_get_input_data("addr_sets", node);
    struct shash *addr_sets = &as_data->addr_sets;

    struct ed_type_port_groups *pg_data =
        engine_get_input_data("port_groups", node);
    struct shash *port_groups = &pg_data->port_groups;

    l_ctx_in->sbrec_multicast_group_by_name_datapath =
        sbrec_mc_group_by_name_dp;
    l_ctx_in->sbrec_logical_flow_by_logical_datapath =
        sbrec_logical_flow_by_dp;
    l_ctx_in->sbrec_logical_flow_by_logical_dp_group =
        sbrec_logical_flow_by_dp_group;
    l_ctx_in->sbrec_port_binding_by_name = sbrec_port_binding_by_name;
    l_ctx_in->dhcp_options_table  = dhcp_table;
    l_ctx_in->dhcpv6_options_table = dhcpv6_table;
    l_ctx_in->mac_binding_table = mac_binding_table;
    l_ctx_in->logical_flow_table = logical_flow_table;
    l_ctx_in->logical_dp_group_table = logical_dp_group_table;
    l_ctx_in->mc_group_table = multicast_group_table;
    l_ctx_in->fdb_table = fdb_table,
    l_ctx_in->chassis = chassis;
    l_ctx_in->lb_table = lb_table;
    l_ctx_in->local_datapaths = &rt_data->local_datapaths;
    l_ctx_in->addr_sets = addr_sets;
    l_ctx_in->port_groups = port_groups;
    l_ctx_in->active_tunnels = &rt_data->active_tunnels;
    l_ctx_in->local_lport_ids = &rt_data->local_lport_ids;

    l_ctx_out->flow_table = &fo->flow_table;
    l_ctx_out->group_table = &fo->group_table;
    l_ctx_out->meter_table = &fo->meter_table;
    l_ctx_out->lfrr = &fo->lflow_resource_ref;
    l_ctx_out->conj_id_ofs = &fo->pd.conj_id_ofs;
    l_ctx_out->lflow_cache = fo->pd.lflow_cache;
    l_ctx_out->conj_id_overflow = false;
}

static void *
en_flow_output_init(struct engine_node *node OVS_UNUSED,
                    struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_flow_output *data = xzalloc(sizeof *data);

    ovn_desired_flow_table_init(&data->flow_table);
    ovn_extend_table_init(&data->group_table);
    ovn_extend_table_init(&data->meter_table);
    data->pd.conj_id_ofs = 1;
    lflow_resource_init(&data->lflow_resource_ref);
    return data;
}

static void
en_flow_output_cleanup(void *data)
{
    struct ed_type_flow_output *flow_output_data = data;
    ovn_desired_flow_table_destroy(&flow_output_data->flow_table);
    ovn_extend_table_destroy(&flow_output_data->group_table);
    ovn_extend_table_destroy(&flow_output_data->meter_table);
    lflow_resource_destroy(&flow_output_data->lflow_resource_ref);
    lflow_cache_destroy(flow_output_data->pd.lflow_cache);
}

static void
en_flow_output_run(struct engine_node *node, void *data)
{
    struct ed_type_runtime_data *rt_data =
        engine_get_input_data("runtime_data", node);

    struct ovsrec_open_vswitch_table *ovs_table =
        (struct ovsrec_open_vswitch_table *)EN_OVSDB_GET(
            engine_get_input("OVS_open_vswitch", node));
    struct ovsrec_bridge_table *bridge_table =
        (struct ovsrec_bridge_table *)EN_OVSDB_GET(
            engine_get_input("OVS_bridge", node));
    const struct ovsrec_bridge *br_int = get_br_int(bridge_table, ovs_table);
    const char *chassis_id = get_ovs_chassis_id(ovs_table);

    struct ovsdb_idl_index *sbrec_chassis_by_name =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_chassis", node),
                "name");

    const struct sbrec_chassis *chassis = NULL;
    if (chassis_id) {
        chassis = chassis_lookup_by_name(sbrec_chassis_by_name, chassis_id);
    }

    ovs_assert(br_int && chassis);

    struct ed_type_flow_output *fo = data;
    struct ovn_desired_flow_table *flow_table = &fo->flow_table;
    struct ovn_extend_table *group_table = &fo->group_table;
    struct ovn_extend_table *meter_table = &fo->meter_table;
    struct lflow_resource_ref *lfrr = &fo->lflow_resource_ref;

    static bool first_run = true;
    if (first_run) {
        first_run = false;
    } else {
        ovn_desired_flow_table_clear(flow_table);
        ovn_extend_table_clear(group_table, false /* desired */);
        ovn_extend_table_clear(meter_table, false /* desired */);
        lflow_resource_clear(lfrr);
    }

    struct controller_engine_ctx *ctrl_ctx = engine_get_context()->client_ctx;

    fo->pd.lflow_cache = ctrl_ctx->lflow_cache;

    if (!lflow_cache_is_enabled(fo->pd.lflow_cache)) {
        fo->pd.conj_id_ofs = 1;
    }

    struct lflow_ctx_in l_ctx_in;
    struct lflow_ctx_out l_ctx_out;
    init_lflow_ctx(node, rt_data, fo, &l_ctx_in, &l_ctx_out);
    lflow_run(&l_ctx_in, &l_ctx_out);

    if (l_ctx_out.conj_id_overflow) {
        /* Conjunction ids overflow. There can be many holes in between.
         * Destroy lflow cache and call lflow_run() again. */
        ovn_desired_flow_table_clear(flow_table);
        ovn_extend_table_clear(group_table, false /* desired */);
        ovn_extend_table_clear(meter_table, false /* desired */);
        lflow_resource_clear(lfrr);
        fo->pd.conj_id_ofs = 1;
        lflow_cache_flush(fo->pd.lflow_cache);
        l_ctx_out.conj_id_overflow = false;
        lflow_run(&l_ctx_in, &l_ctx_out);
        if (l_ctx_out.conj_id_overflow) {
            VLOG_WARN("Conjunction id overflow.");
        }
    }

    struct physical_ctx p_ctx;
    init_physical_ctx(node, rt_data, &p_ctx);

    physical_run(&p_ctx, &fo->flow_table);

    engine_set_node_state(node, EN_UPDATED);
}

static bool
flow_output_sb_logical_flow_handler(struct engine_node *node, void *data)
{
    struct ed_type_runtime_data *rt_data =
        engine_get_input_data("runtime_data", node);
    struct ovsrec_open_vswitch_table *ovs_table =
        (struct ovsrec_open_vswitch_table *)EN_OVSDB_GET(
            engine_get_input("OVS_open_vswitch", node));
    struct ovsrec_bridge_table *bridge_table =
        (struct ovsrec_bridge_table *)EN_OVSDB_GET(
            engine_get_input("OVS_bridge", node));
    const struct ovsrec_bridge *br_int = get_br_int(bridge_table, ovs_table);
    ovs_assert(br_int);

    struct ed_type_flow_output *fo = data;
    struct lflow_ctx_in l_ctx_in;
    struct lflow_ctx_out l_ctx_out;
    init_lflow_ctx(node, rt_data, fo, &l_ctx_in, &l_ctx_out);

    bool handled = lflow_handle_changed_flows(&l_ctx_in, &l_ctx_out);

    engine_set_node_state(node, EN_UPDATED);
    return handled;
}

static bool
flow_output_sb_mac_binding_handler(struct engine_node *node, void *data)
{
    struct ovsdb_idl_index *sbrec_port_binding_by_name =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_port_binding", node),
                "name");

    struct sbrec_mac_binding_table *mac_binding_table =
        (struct sbrec_mac_binding_table *)EN_OVSDB_GET(
            engine_get_input("SB_mac_binding", node));

    struct ed_type_runtime_data *rt_data =
        engine_get_input_data("runtime_data", node);
    const struct hmap *local_datapaths = &rt_data->local_datapaths;

    struct ed_type_flow_output *fo = data;
    struct ovn_desired_flow_table *flow_table = &fo->flow_table;

    lflow_handle_changed_neighbors(sbrec_port_binding_by_name,
            mac_binding_table, local_datapaths, flow_table);

    engine_set_node_state(node, EN_UPDATED);
    return true;
}

static bool
flow_output_sb_port_binding_handler(struct engine_node *node,
                                    void *data)
{
    struct ed_type_runtime_data *rt_data =
        engine_get_input_data("runtime_data", node);

    struct ed_type_flow_output *fo = data;
    struct ovn_desired_flow_table *flow_table = &fo->flow_table;

    struct physical_ctx p_ctx;
    init_physical_ctx(node, rt_data, &p_ctx);

    /* We handle port-binding changes for physical flow processing
     * only. flow_output runtime data handler takes care of processing
     * logical flows for any port binding changes.
     */
    physical_handle_port_binding_changes(&p_ctx, flow_table);

    engine_set_node_state(node, EN_UPDATED);
    return true;
}

static bool
flow_output_sb_multicast_group_handler(struct engine_node *node, void *data)
{
    struct ed_type_runtime_data *rt_data =
        engine_get_input_data("runtime_data", node);

    struct ed_type_flow_output *fo = data;
    struct ovn_desired_flow_table *flow_table = &fo->flow_table;

    struct physical_ctx p_ctx;
    init_physical_ctx(node, rt_data, &p_ctx);

    physical_handle_mc_group_changes(&p_ctx, flow_table);

    engine_set_node_state(node, EN_UPDATED);
    return true;

}

static bool
_flow_output_resource_ref_handler(struct engine_node *node, void *data,
                                  enum ref_type ref_type)
{
    struct ed_type_runtime_data *rt_data =
        engine_get_input_data("runtime_data", node);

    struct ed_type_addr_sets *as_data =
        engine_get_input_data("addr_sets", node);

    struct ed_type_port_groups *pg_data =
        engine_get_input_data("port_groups", node);

    struct ovsrec_open_vswitch_table *ovs_table =
        (struct ovsrec_open_vswitch_table *)EN_OVSDB_GET(
            engine_get_input("OVS_open_vswitch", node));
    struct ovsrec_bridge_table *bridge_table =
        (struct ovsrec_bridge_table *)EN_OVSDB_GET(
            engine_get_input("OVS_bridge", node));
    const struct ovsrec_bridge *br_int = get_br_int(bridge_table, ovs_table);
    const char *chassis_id = get_ovs_chassis_id(ovs_table);

    struct ovsdb_idl_index *sbrec_chassis_by_name =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_chassis", node),
                "name");
    const struct sbrec_chassis *chassis = NULL;
    if (chassis_id) {
        chassis = chassis_lookup_by_name(sbrec_chassis_by_name, chassis_id);
    }

    ovs_assert(br_int && chassis);

    struct ed_type_flow_output *fo = data;

    struct lflow_ctx_in l_ctx_in;
    struct lflow_ctx_out l_ctx_out;
    init_lflow_ctx(node, rt_data, fo, &l_ctx_in, &l_ctx_out);

    bool changed;
    const char *ref_name;
    struct sset *new, *updated, *deleted;

    switch (ref_type) {
        case REF_TYPE_ADDRSET:
            /* XXX: The change_tracked check may be added to inc-proc
             * framework. */
            if (!as_data->change_tracked) {
                return false;
            }
            new = &as_data->new;
            updated = &as_data->updated;
            deleted = &as_data->deleted;
            break;
        case REF_TYPE_PORTGROUP:
            if (!pg_data->change_tracked) {
                return false;
            }
            new = &pg_data->new;
            updated = &pg_data->updated;
            deleted = &pg_data->deleted;
            break;

        /* This ref type is handled in the flow_output_runtime_data_handler. */
        case REF_TYPE_PORTBINDING:
        default:
            OVS_NOT_REACHED();
    }


    SSET_FOR_EACH (ref_name, deleted) {
        if (!lflow_handle_changed_ref(ref_type, ref_name, &l_ctx_in,
                                      &l_ctx_out, &changed)) {
            return false;
        }
        if (changed) {
            engine_set_node_state(node, EN_UPDATED);
        }
    }
    SSET_FOR_EACH (ref_name, updated) {
        if (!lflow_handle_changed_ref(ref_type, ref_name, &l_ctx_in,
                                      &l_ctx_out, &changed)) {
            return false;
        }
        if (changed) {
            engine_set_node_state(node, EN_UPDATED);
        }
    }
    SSET_FOR_EACH (ref_name, new) {
        if (!lflow_handle_changed_ref(ref_type, ref_name, &l_ctx_in,
                                      &l_ctx_out, &changed)) {
            return false;
        }
        if (changed) {
            engine_set_node_state(node, EN_UPDATED);
        }
    }

    return true;
}

static bool
flow_output_addr_sets_handler(struct engine_node *node, void *data)
{
    return _flow_output_resource_ref_handler(node, data, REF_TYPE_ADDRSET);
}

static bool
flow_output_port_groups_handler(struct engine_node *node, void *data)
{
    return _flow_output_resource_ref_handler(node, data, REF_TYPE_PORTGROUP);
}

static bool
flow_output_physical_flow_changes_handler(struct engine_node *node, void *data)
{
    struct ed_type_runtime_data *rt_data =
        engine_get_input_data("runtime_data", node);

    struct ed_type_flow_output *fo = data;
    struct physical_ctx p_ctx;
    init_physical_ctx(node, rt_data, &p_ctx);

    engine_set_node_state(node, EN_UPDATED);
    struct ed_type_pfc_data *pfc_data =
        engine_get_input_data("physical_flow_changes", node);

    /* If there are OVS interface changes. Try to handle them incrementally. */
    if (pfc_data->ovs_ifaces_changed) {
        if (!physical_handle_ovs_iface_changes(&p_ctx, &fo->flow_table)) {
            return false;
        }
    }

    if (pfc_data->recompute_physical_flows) {
        /* This indicates that we need to recompute the physical flows. */
        physical_clear_unassoc_flows_with_db(&fo->flow_table);
        physical_clear_dp_flows(&p_ctx, &rt_data->ct_updated_datapaths,
                                &fo->flow_table);
        physical_run(&p_ctx, &fo->flow_table);
        return true;
    }

    return true;
}

static bool
flow_output_runtime_data_handler(struct engine_node *node,
                                 void *data OVS_UNUSED)
{
    struct ed_type_runtime_data *rt_data =
        engine_get_input_data("runtime_data", node);

    /* There is no tracked data. Fall back to full recompute of
     * flow_output. */
    if (!rt_data->tracked) {
        return false;
    }

    struct hmap *tracked_dp_bindings = &rt_data->tracked_dp_bindings;
    if (hmap_is_empty(tracked_dp_bindings)) {
        if (rt_data->local_lports_changed) {
            engine_set_node_state(node, EN_UPDATED);
        }
        return true;
    }

    struct lflow_ctx_in l_ctx_in;
    struct lflow_ctx_out l_ctx_out;
    struct ed_type_flow_output *fo = data;
    init_lflow_ctx(node, rt_data, fo, &l_ctx_in, &l_ctx_out);

    struct physical_ctx p_ctx;
    init_physical_ctx(node, rt_data, &p_ctx);

    struct tracked_binding_datapath *tdp;
    HMAP_FOR_EACH (tdp, node, tracked_dp_bindings) {
        if (tdp->is_new) {
            if (!lflow_add_flows_for_datapath(tdp->dp, &l_ctx_in,
                                              &l_ctx_out)) {
                return false;
            }
        } else {
            struct shash_node *shash_node;
            SHASH_FOR_EACH (shash_node, &tdp->lports) {
                struct tracked_binding_lport *lport = shash_node->data;
                if (!lflow_handle_flows_for_lport(lport->pb, &l_ctx_in,
                                                  &l_ctx_out)) {
                    return false;
                }
            }
        }
    }

    engine_set_node_state(node, EN_UPDATED);
    return true;
}

static bool
flow_output_sb_load_balancer_handler(struct engine_node *node, void *data)
{
    struct ed_type_runtime_data *rt_data =
        engine_get_input_data("runtime_data", node);

    struct ed_type_flow_output *fo = data;
    struct lflow_ctx_in l_ctx_in;
    struct lflow_ctx_out l_ctx_out;
    init_lflow_ctx(node, rt_data, fo, &l_ctx_in, &l_ctx_out);

    bool handled = lflow_handle_changed_lbs(&l_ctx_in, &l_ctx_out);

    engine_set_node_state(node, EN_UPDATED);
    return handled;
}

static bool
flow_output_sb_fdb_handler(struct engine_node *node, void *data)
{
    struct ed_type_runtime_data *rt_data =
        engine_get_input_data("runtime_data", node);

    struct ed_type_flow_output *fo = data;
    struct lflow_ctx_in l_ctx_in;
    struct lflow_ctx_out l_ctx_out;
    init_lflow_ctx(node, rt_data, fo, &l_ctx_in, &l_ctx_out);

    bool handled = lflow_handle_changed_fdbs(&l_ctx_in, &l_ctx_out);

    engine_set_node_state(node, EN_UPDATED);
    return handled;
}

struct ovn_controller_exit_args {
    bool *exiting;
    bool *restart;
};

/* Returns false if the northd internal version stored in SB_Global
 * and ovn-controller internal version don't match.
 */
static bool
check_northd_version(struct ovsdb_idl *ovs_idl, struct ovsdb_idl *ovnsb_idl,
                     const char *version)
{
    static bool version_mismatch;

    const struct ovsrec_open_vswitch *cfg = ovsrec_open_vswitch_first(ovs_idl);
    if (!cfg || !smap_get_bool(&cfg->external_ids, "ovn-match-northd-version",
                               false)) {
        version_mismatch = false;
        return true;
    }

    const struct sbrec_sb_global *sb = sbrec_sb_global_first(ovnsb_idl);
    if (!sb) {
        version_mismatch = true;
        return false;
    }

    const char *northd_version =
        smap_get_def(&sb->options, "northd_internal_version", "");

    if (strcmp(northd_version, version)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "controller version - %s mismatch with northd "
                     "version - %s", version, northd_version);
        version_mismatch = true;
        return false;
    }

    /* If there used to be a mismatch and ovn-northd got updated, force a
     * full recompute.
     */
    if (version_mismatch) {
        engine_set_force_recompute(true);
    }
    version_mismatch = false;
    return true;
}

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    bool exiting;
    bool restart;
    struct ovn_controller_exit_args exit_args = {&exiting, &restart};
    int retval;

    ovs_cmdl_proctitle_init(argc, argv);
    ovn_set_program_name(argv[0]);
    service_start(&argc, &argv);
    char *ovs_remote = parse_options(argc, argv);
    fatal_ignore_sigpipe();

    daemonize_start(true);

    char *abs_unixctl_path = get_abs_unix_ctl_path(NULL);
    retval = unixctl_server_create(abs_unixctl_path, &unixctl);
    free(abs_unixctl_path);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 1, ovn_controller_exit,
                             &exit_args);

    daemonize_complete();

    /* Register ofctrl seqno types. */
    ofctrl_seq_type_nb_cfg = ofctrl_seqno_add_type();

    binding_init();
    patch_init();
    pinctrl_init();
    lflow_init();

    /* Connect to OVS OVSDB instance. */
    struct ovsdb_idl_loop ovs_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovs_remote, &ovsrec_idl_class, false, true));
    ctrl_register_ovs_idl(ovs_idl_loop.idl);
    ovsdb_idl_get_initial_snapshot(ovs_idl_loop.idl);

    /* Configure OVN SB database. */
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&sbrec_idl_class, true));
    ovsdb_idl_set_leader_only(ovnsb_idl_loop.idl, false);

    unixctl_command_register("connection-status", "", 0, 0,
                             ovn_conn_show, ovnsb_idl_loop.idl);

    struct ovsdb_idl_index *sbrec_chassis_by_name
        = chassis_index_create(ovnsb_idl_loop.idl);
    struct ovsdb_idl_index *sbrec_chassis_private_by_name
        = chassis_private_index_create(ovnsb_idl_loop.idl);
    struct ovsdb_idl_index *sbrec_multicast_group_by_name_datapath
        = mcast_group_index_create(ovnsb_idl_loop.idl);
    struct ovsdb_idl_index *sbrec_logical_flow_by_logical_datapath
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_logical_flow_col_logical_datapath);
    struct ovsdb_idl_index *sbrec_logical_flow_by_logical_dp_group
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_logical_flow_col_logical_dp_group);
    struct ovsdb_idl_index *sbrec_port_binding_by_name
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_port_binding_col_logical_port);
    struct ovsdb_idl_index *sbrec_port_binding_by_key
        = ovsdb_idl_index_create2(ovnsb_idl_loop.idl,
                                  &sbrec_port_binding_col_tunnel_key,
                                  &sbrec_port_binding_col_datapath);
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_port_binding_col_datapath);
    struct ovsdb_idl_index *sbrec_port_binding_by_type
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_port_binding_col_type);
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_datapath_binding_col_tunnel_key);
    struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip
        = ovsdb_idl_index_create2(ovnsb_idl_loop.idl,
                                  &sbrec_mac_binding_col_logical_port,
                                  &sbrec_mac_binding_col_ip);
    struct ovsdb_idl_index *sbrec_ip_multicast
        = ip_mcast_index_create(ovnsb_idl_loop.idl);
    struct ovsdb_idl_index *sbrec_igmp_group
        = igmp_group_index_create(ovnsb_idl_loop.idl);
    struct ovsdb_idl_index *sbrec_fdb_by_dp_key_mac
        = ovsdb_idl_index_create2(ovnsb_idl_loop.idl,
                                  &sbrec_fdb_col_mac,
                                  &sbrec_fdb_col_dp_key);

    ovsdb_idl_track_add_all(ovnsb_idl_loop.idl);
    ovsdb_idl_omit_alert(ovnsb_idl_loop.idl,
                         &sbrec_chassis_private_col_nb_cfg);
    ovsdb_idl_omit_alert(ovnsb_idl_loop.idl,
                         &sbrec_chassis_private_col_nb_cfg_timestamp);

    /* Omit the external_ids column of all the tables except for -
     *  - DNS. pinctrl.c uses the external_ids column of DNS,
     *    which it shouldn't. This should be removed.
     *
     *  - Datapath_binding - lflow.c is using this to check if the datapath
     *                       is switch or not. This should be removed.
     * */

    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_sb_global_col_external_ids);
    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_logical_flow_col_external_ids);
    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_port_binding_col_external_ids);
    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_ssl_col_external_ids);
    ovsdb_idl_omit(ovnsb_idl_loop.idl,
                   &sbrec_gateway_chassis_col_external_ids);
    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_ha_chassis_col_external_ids);
    ovsdb_idl_omit(ovnsb_idl_loop.idl,
                   &sbrec_ha_chassis_group_col_external_ids);

    /* We don't want to monitor Connection table at all. So omit all the
     * columns. */
    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_connection_col_external_ids);
    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_connection_col_inactivity_probe);
    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_connection_col_is_connected);
    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_connection_col_max_backoff);
    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_connection_col_other_config);
    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_connection_col_read_only);
    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_connection_col_role);
    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_connection_col_status);
    ovsdb_idl_omit(ovnsb_idl_loop.idl, &sbrec_connection_col_target);

    /* Omit alerts to the Chassis external_ids column, the configuration
     * from the local open_vswitch table has now being moved to the
     * other_config column so we no longer need to monitor it */
    ovsdb_idl_omit_alert(ovnsb_idl_loop.idl, &sbrec_chassis_col_external_ids);

    /* Do not monitor Chassis_Private external_ids */
    ovsdb_idl_omit(ovnsb_idl_loop.idl,
                   &sbrec_chassis_private_col_external_ids);

    update_sb_monitors(ovnsb_idl_loop.idl, NULL, NULL, NULL, false);

    stopwatch_create(CONTROLLER_LOOP_STOPWATCH_NAME, SW_MS);

    /* Define inc-proc-engine nodes. */
    ENGINE_NODE_CUSTOM_DATA(ct_zones, "ct_zones");
    ENGINE_NODE_WITH_CLEAR_TRACK_DATA(runtime_data, "runtime_data");
    ENGINE_NODE(mff_ovn_geneve, "mff_ovn_geneve");
    ENGINE_NODE(ofctrl_is_connected, "ofctrl_is_connected");
    ENGINE_NODE_WITH_CLEAR_TRACK_DATA(physical_flow_changes,
                                      "physical_flow_changes");
    ENGINE_NODE(flow_output, "flow_output");
    ENGINE_NODE(addr_sets, "addr_sets");
    ENGINE_NODE(port_groups, "port_groups");

#define SB_NODE(NAME, NAME_STR) ENGINE_NODE_SB(NAME, NAME_STR);
    SB_NODES
#undef SB_NODE

#define OVS_NODE(NAME, NAME_STR) ENGINE_NODE_OVS(NAME, NAME_STR);
    OVS_NODES
#undef OVS_NODE

    /* Add dependencies between inc-proc-engine nodes. */

    engine_add_input(&en_addr_sets, &en_sb_address_set,
                     addr_sets_sb_address_set_handler);
    engine_add_input(&en_port_groups, &en_sb_port_group,
                     port_groups_sb_port_group_handler);

    /* Engine node physical_flow_changes indicates whether
     * we can recompute only physical flows or we can
     * incrementally process the physical flows.
     *
     * Note: The order of inputs is important, all OVS interface changes must
     * be handled before any ct_zone changes.
     */
    engine_add_input(&en_physical_flow_changes, &en_ovs_interface,
                     physical_flow_changes_ovs_iface_handler);
    engine_add_input(&en_physical_flow_changes, &en_ct_zones,
                     physical_flow_changes_ct_zones_handler);

    engine_add_input(&en_flow_output, &en_addr_sets,
                     flow_output_addr_sets_handler);
    engine_add_input(&en_flow_output, &en_port_groups,
                     flow_output_port_groups_handler);
    engine_add_input(&en_flow_output, &en_runtime_data,
                     flow_output_runtime_data_handler);
    engine_add_input(&en_flow_output, &en_mff_ovn_geneve, NULL);
    engine_add_input(&en_flow_output, &en_physical_flow_changes,
                     flow_output_physical_flow_changes_handler);

    /* We need this input nodes for only data. Hence the noop handler. */
    engine_add_input(&en_flow_output, &en_ct_zones, engine_noop_handler);
    engine_add_input(&en_flow_output, &en_ovs_interface, engine_noop_handler);

    engine_add_input(&en_flow_output, &en_ovs_open_vswitch, NULL);
    engine_add_input(&en_flow_output, &en_ovs_bridge, NULL);

    engine_add_input(&en_flow_output, &en_sb_chassis, NULL);
    engine_add_input(&en_flow_output, &en_sb_encap, NULL);
    engine_add_input(&en_flow_output, &en_sb_multicast_group,
                     flow_output_sb_multicast_group_handler);
    engine_add_input(&en_flow_output, &en_sb_port_binding,
                     flow_output_sb_port_binding_handler);
    engine_add_input(&en_flow_output, &en_sb_mac_binding,
                     flow_output_sb_mac_binding_handler);
    engine_add_input(&en_flow_output, &en_sb_logical_flow,
                     flow_output_sb_logical_flow_handler);
    /* Using a noop handler since we don't really need any data from datapath
     * groups or a full recompute.  Update of a datapath group will put
     * logical flow into the tracked list, so the logical flow handler will
     * process all changes. */
    engine_add_input(&en_flow_output, &en_sb_logical_dp_group,
                     engine_noop_handler);
    engine_add_input(&en_flow_output, &en_sb_dhcp_options, NULL);
    engine_add_input(&en_flow_output, &en_sb_dhcpv6_options, NULL);
    engine_add_input(&en_flow_output, &en_sb_dns, NULL);
    engine_add_input(&en_flow_output, &en_sb_load_balancer,
                     flow_output_sb_load_balancer_handler);
    engine_add_input(&en_flow_output, &en_sb_fdb,
                     flow_output_sb_fdb_handler);

    engine_add_input(&en_ct_zones, &en_ovs_open_vswitch, NULL);
    engine_add_input(&en_ct_zones, &en_ovs_bridge, NULL);
    engine_add_input(&en_ct_zones, &en_sb_datapath_binding, NULL);
    engine_add_input(&en_ct_zones, &en_runtime_data, NULL);

    engine_add_input(&en_runtime_data, &en_ofctrl_is_connected, NULL);

    engine_add_input(&en_runtime_data, &en_ovs_open_vswitch, NULL);
    engine_add_input(&en_runtime_data, &en_ovs_bridge, NULL);
    engine_add_input(&en_runtime_data, &en_ovs_qos, NULL);

    engine_add_input(&en_runtime_data, &en_sb_chassis, NULL);
    engine_add_input(&en_runtime_data, &en_sb_datapath_binding,
                     runtime_data_sb_datapath_binding_handler);
    engine_add_input(&en_runtime_data, &en_sb_port_binding,
                     runtime_data_sb_port_binding_handler);

    /* The OVS interface handler for runtime_data changes MUST be executed
     * after the sb_port_binding_handler as port_binding deletes must be
     * processed first.
     */
    engine_add_input(&en_runtime_data, &en_ovs_port,
                     engine_noop_handler);
    engine_add_input(&en_runtime_data, &en_ovs_interface,
                     runtime_data_ovs_interface_handler);

    struct engine_arg engine_arg = {
        .sb_idl = ovnsb_idl_loop.idl,
        .ovs_idl = ovs_idl_loop.idl,
    };
    engine_init(&en_flow_output, &engine_arg);

    engine_ovsdb_node_add_index(&en_sb_chassis, "name", sbrec_chassis_by_name);
    engine_ovsdb_node_add_index(&en_sb_multicast_group, "name_datapath",
                                sbrec_multicast_group_by_name_datapath);
    engine_ovsdb_node_add_index(&en_sb_logical_flow, "logical_datapath",
                                sbrec_logical_flow_by_logical_datapath);
    engine_ovsdb_node_add_index(&en_sb_logical_flow, "logical_dp_group",
                                sbrec_logical_flow_by_logical_dp_group);
    engine_ovsdb_node_add_index(&en_sb_port_binding, "name",
                                sbrec_port_binding_by_name);
    engine_ovsdb_node_add_index(&en_sb_port_binding, "key",
                                sbrec_port_binding_by_key);
    engine_ovsdb_node_add_index(&en_sb_port_binding, "datapath",
                                sbrec_port_binding_by_datapath);
    engine_ovsdb_node_add_index(&en_sb_datapath_binding, "key",
                                sbrec_datapath_binding_by_key);

    struct ed_type_flow_output *flow_output_data =
        engine_get_internal_data(&en_flow_output);
    struct ed_type_ct_zones *ct_zones_data =
        engine_get_internal_data(&en_ct_zones);
    struct ed_type_runtime_data *runtime_data = NULL;

    ofctrl_init(&flow_output_data->group_table,
                &flow_output_data->meter_table,
                get_ofctrl_probe_interval(ovs_idl_loop.idl));
    ofctrl_seqno_init();

    unixctl_command_register("group-table-list", "", 0, 0,
                             extend_table_list,
                             &flow_output_data->group_table);

    unixctl_command_register("meter-table-list", "", 0, 0,
                             extend_table_list,
                             &flow_output_data->meter_table);

    unixctl_command_register("ct-zone-list", "", 0, 0,
                             ct_zone_list,
                             &ct_zones_data->current);

    struct pending_pkt pending_pkt = { .conn = NULL };
    unixctl_command_register("inject-pkt", "MICROFLOW", 1, 1, inject_pkt,
                             &pending_pkt);

    unixctl_command_register("recompute", "", 0, 0, engine_recompute_cmd,
                             NULL);
    unixctl_command_register("lflow-cache/flush", "", 0, 0,
                             lflow_cache_flush_cmd,
                             &flow_output_data->pd);
    /* Keep deprecated 'flush-lflow-cache' command for now. */
    unixctl_command_register("flush-lflow-cache", "[deprecated]", 0, 0,
                             lflow_cache_flush_cmd,
                             &flow_output_data->pd);
    unixctl_command_register("lflow-cache/show-stats", "", 0, 0,
                             lflow_cache_show_stats_cmd,
                             &flow_output_data->pd);

    bool reset_ovnsb_idl_min_index = false;
    unixctl_command_register("sb-cluster-state-reset", "", 0, 0,
                             cluster_state_reset_cmd,
                             &reset_ovnsb_idl_min_index);

    bool paused = false;
    unixctl_command_register("debug/pause", "", 0, 0, debug_pause_execution,
                             &paused);
    unixctl_command_register("debug/resume", "", 0, 0, debug_resume_execution,
                             &paused);
    unixctl_command_register("debug/status", "", 0, 0, debug_status_execution,
                             &paused);

    unsigned int delay_nb_cfg_report = 0;
    unixctl_command_register("debug/delay-nb-cfg-report", "SECONDS", 1, 1,
                             debug_delay_nb_cfg_report, &delay_nb_cfg_report);

    unsigned int ovs_cond_seqno = UINT_MAX;
    unsigned int ovnsb_cond_seqno = UINT_MAX;
    unsigned int ovnsb_expected_cond_seqno = UINT_MAX;

    struct controller_engine_ctx ctrl_engine_ctx = {
        .lflow_cache = lflow_cache_create(),
    };

    char *ovn_version = ovn_get_internal_version();
    VLOG_INFO("OVN internal version is : [%s]", ovn_version);

    /* Main loop. */
    exiting = false;
    restart = false;
    bool sb_monitor_all = false;
    while (!exiting) {
        memory_run();
        if (memory_should_report()) {
            struct simap usage = SIMAP_INITIALIZER(&usage);

            lflow_cache_get_memory_usage(ctrl_engine_ctx.lflow_cache, &usage);
            memory_report(&usage);
            simap_destroy(&usage);
        }

        /* If we're paused just run the unixctl server and skip most of the
         * processing loop.
         */
        if (paused) {
            unixctl_server_run(unixctl);
            unixctl_server_wait(unixctl);
            goto loop_done;
        }

        engine_init_run();

        struct ovsdb_idl_txn *ovs_idl_txn = ovsdb_idl_loop_run(&ovs_idl_loop);
        unsigned int new_ovs_cond_seqno
            = ovsdb_idl_get_condition_seqno(ovs_idl_loop.idl);
        if (new_ovs_cond_seqno != ovs_cond_seqno) {
            if (!new_ovs_cond_seqno) {
                VLOG_INFO("OVS IDL reconnected, force recompute.");
                engine_set_force_recompute(true);
            }
            ovs_cond_seqno = new_ovs_cond_seqno;
        }

        update_sb_db(ovs_idl_loop.idl, ovnsb_idl_loop.idl, &sb_monitor_all,
                     &reset_ovnsb_idl_min_index,
                     &ctrl_engine_ctx, &ovnsb_expected_cond_seqno);
        update_ssl_config(ovsrec_ssl_table_get(ovs_idl_loop.idl));
        ofctrl_set_probe_interval(get_ofctrl_probe_interval(ovs_idl_loop.idl));

        struct ovsdb_idl_txn *ovnsb_idl_txn
            = ovsdb_idl_loop_run(&ovnsb_idl_loop);
        unsigned int new_ovnsb_cond_seqno
            = ovsdb_idl_get_condition_seqno(ovnsb_idl_loop.idl);
        if (new_ovnsb_cond_seqno != ovnsb_cond_seqno) {
            if (!new_ovnsb_cond_seqno) {
                VLOG_INFO("OVNSB IDL reconnected, force recompute.");
                engine_set_force_recompute(true);
            }
            ovnsb_cond_seqno = new_ovnsb_cond_seqno;
        }

        struct engine_context eng_ctx = {
            .ovs_idl_txn = ovs_idl_txn,
            .ovnsb_idl_txn = ovnsb_idl_txn,
            .client_ctx = &ctrl_engine_ctx
        };

        engine_set_context(&eng_ctx);

        bool northd_version_match =
            check_northd_version(ovs_idl_loop.idl, ovnsb_idl_loop.idl,
                                 ovn_version);

        const struct ovsrec_bridge_table *bridge_table =
            ovsrec_bridge_table_get(ovs_idl_loop.idl);
        const struct ovsrec_open_vswitch_table *ovs_table =
            ovsrec_open_vswitch_table_get(ovs_idl_loop.idl);
        const struct ovsrec_bridge *br_int =
            process_br_int(ovs_idl_txn, bridge_table, ovs_table);

        if (ovsdb_idl_has_ever_connected(ovnsb_idl_loop.idl) &&
            northd_version_match) {

            /* Unconditionally remove all deleted lflows from the lflow
             * cache.
             */
            if (lflow_cache_is_enabled(ctrl_engine_ctx.lflow_cache)) {
                lflow_handle_cached_flows(
                    ctrl_engine_ctx.lflow_cache,
                    sbrec_logical_flow_table_get(ovnsb_idl_loop.idl));
            }

            /* Contains the transport zones that this Chassis belongs to */
            struct sset transport_zones = SSET_INITIALIZER(&transport_zones);
            sset_from_delimited_string(&transport_zones,
                get_transport_zones(ovsrec_open_vswitch_table_get(
                                    ovs_idl_loop.idl)), ",");

            const char *chassis_id = get_ovs_chassis_id(ovs_table);
            const struct sbrec_chassis *chassis = NULL;
            const struct sbrec_chassis_private *chassis_private = NULL;
            if (chassis_id) {
                chassis = chassis_run(ovnsb_idl_txn, sbrec_chassis_by_name,
                                      sbrec_chassis_private_by_name,
                                      ovs_table, chassis_id,
                                      br_int, &transport_zones,
                                      &chassis_private);
            }

            if (br_int) {
                ct_zones_data = engine_get_data(&en_ct_zones);
                if (ct_zones_data) {
                    ofctrl_run(br_int, &ct_zones_data->pending);
                }

                if (chassis) {
                    encaps_run(ovs_idl_txn,
                               bridge_table, br_int,
                               sbrec_chassis_table_get(ovnsb_idl_loop.idl),
                               chassis,
                               sbrec_sb_global_first(ovnsb_idl_loop.idl),
                               &transport_zones);

                    stopwatch_start(CONTROLLER_LOOP_STOPWATCH_NAME,
                                    time_msec());
                    if (ovnsb_idl_txn) {
                        if (!ofctrl_can_put()) {
                            /* When there are in-flight messages pending to
                             * ovs-vswitchd, we should hold on recomputing so
                             * that the previous flow installations won't be
                             * delayed.  However, we still want to try if
                             * recompute is not needed and we can quickly
                             * incrementally process the new changes, to avoid
                             * unnecessarily forced recomputes later on.  This
                             * is because the OVSDB change tracker cannot
                             * preserve tracked changes across iterations.  If
                             * change tracking is improved, we can simply skip
                             * this round of engine_run and continue processing
                             * acculated changes incrementally later when
                             * ofctrl_can_put() returns true. */
                            engine_run(false);
                        } else {
                            engine_run(true);
                        }
                    } else {
                        /* Even if there's no SB DB transaction available,
                         * try to run the engine so that we can handle any
                         * incremental changes that don't require a recompute.
                         * If a recompute is required, the engine will abort,
                         * triggerring a full run in the next iteration.
                         */
                        engine_run(false);
                    }
                    stopwatch_stop(CONTROLLER_LOOP_STOPWATCH_NAME,
                                   time_msec());
                    ct_zones_data = engine_get_data(&en_ct_zones);
                    if (ovs_idl_txn) {
                        if (ct_zones_data) {
                            commit_ct_zones(br_int, &ct_zones_data->pending);
                        }
                        bfd_run(ovsrec_interface_table_get(ovs_idl_loop.idl),
                                br_int, chassis,
                                sbrec_ha_chassis_group_table_get(
                                    ovnsb_idl_loop.idl),
                                sbrec_sb_global_table_get(ovnsb_idl_loop.idl));
                    }

                    runtime_data = engine_get_data(&en_runtime_data);
                    if (runtime_data) {
                        patch_run(ovs_idl_txn,
                            sbrec_port_binding_by_type,
                            ovsrec_bridge_table_get(ovs_idl_loop.idl),
                            ovsrec_open_vswitch_table_get(ovs_idl_loop.idl),
                            ovsrec_port_table_get(ovs_idl_loop.idl),
                            br_int, chassis, &runtime_data->local_datapaths);
                        pinctrl_run(ovnsb_idl_txn,
                                    sbrec_datapath_binding_by_key,
                                    sbrec_port_binding_by_datapath,
                                    sbrec_port_binding_by_key,
                                    sbrec_port_binding_by_name,
                                    sbrec_mac_binding_by_lport_ip,
                                    sbrec_igmp_group,
                                    sbrec_ip_multicast,
                                    sbrec_fdb_by_dp_key_mac,
                                    sbrec_dns_table_get(ovnsb_idl_loop.idl),
                                    sbrec_controller_event_table_get(
                                        ovnsb_idl_loop.idl),
                                    sbrec_service_monitor_table_get(
                                        ovnsb_idl_loop.idl),
                                    sbrec_bfd_table_get(ovnsb_idl_loop.idl),
                                    br_int, chassis,
                                    &runtime_data->local_datapaths,
                                    &runtime_data->active_tunnels);
                        /* Updating monitor conditions if runtime data or
                         * logical datapath goups changed. */
                        if (engine_node_changed(&en_runtime_data)
                            || engine_node_changed(&en_sb_logical_dp_group)) {
                            ovnsb_expected_cond_seqno =
                                update_sb_monitors(
                                    ovnsb_idl_loop.idl, chassis,
                                    &runtime_data->local_lports,
                                    &runtime_data->local_datapaths,
                                    sb_monitor_all);
                        }
                    }

                    ofctrl_seqno_update_create(
                        ofctrl_seq_type_nb_cfg,
                        get_nb_cfg(sbrec_sb_global_table_get(
                                                       ovnsb_idl_loop.idl),
                                              ovnsb_cond_seqno,
                                              ovnsb_expected_cond_seqno));
                    if (runtime_data && ovs_idl_txn && ovnsb_idl_txn) {
                        binding_seqno_run(&runtime_data->local_bindings);
                    }

                    flow_output_data = engine_get_data(&en_flow_output);
                    if (flow_output_data && ct_zones_data) {
                        ofctrl_put(&flow_output_data->flow_table,
                                   &ct_zones_data->pending,
                                   sbrec_meter_table_get(ovnsb_idl_loop.idl),
                                   ofctrl_seqno_get_req_cfg(),
                                   engine_node_changed(&en_flow_output));
                    }
                    ofctrl_seqno_run(ofctrl_get_cur_cfg());
                    if (runtime_data && ovs_idl_txn && ovnsb_idl_txn) {
                        binding_seqno_install(&runtime_data->local_bindings);
                    }
                }

            }

            if (!engine_has_run()) {
                if (engine_need_run()) {
                    VLOG_DBG("engine did not run, force recompute next time: "
                             "br_int %p, chassis %p", br_int, chassis);
                    engine_set_force_recompute(true);
                    poll_immediate_wake();
                } else {
                    VLOG_DBG("engine did not run, and it was not needed"
                             " either: br_int %p, chassis %p",
                             br_int, chassis);
                }
            } else if (engine_aborted()) {
                VLOG_DBG("engine was aborted, force recompute next time: "
                         "br_int %p, chassis %p", br_int, chassis);
                engine_set_force_recompute(true);
                poll_immediate_wake();
            } else {
                engine_set_force_recompute(false);
            }

            store_nb_cfg(ovnsb_idl_txn, ovs_idl_txn, chassis_private,
                         br_int, delay_nb_cfg_report);

            if (pending_pkt.conn) {
                struct ed_type_addr_sets *as_data =
                    engine_get_data(&en_addr_sets);
                struct ed_type_port_groups *pg_data =
                    engine_get_data(&en_port_groups);
                if (br_int && chassis && as_data && pg_data) {
                    char *error = ofctrl_inject_pkt(br_int, pending_pkt.flow_s,
                        &as_data->addr_sets, &pg_data->port_groups);
                    if (error) {
                        unixctl_command_reply_error(pending_pkt.conn, error);
                        free(error);
                    } else {
                        unixctl_command_reply(pending_pkt.conn, NULL);
                    }
                } else {
                    VLOG_DBG("Pending_pkt conn but br_int %p or chassis "
                             "%p not ready.", br_int, chassis);
                    unixctl_command_reply_error(pending_pkt.conn,
                        "ovn-controller not ready.");
                }
                pending_pkt.conn = NULL;
                free(pending_pkt.flow_s);
            }

            sset_destroy(&transport_zones);

            if (br_int) {
                ofctrl_wait();
                pinctrl_wait(ovnsb_idl_txn);
            }
        }

        if (!northd_version_match && br_int) {
            /* Set the integration bridge name to pinctrl so that the pinctrl
             * thread can handle any packet-ins when we are not processing
             * any DB updates due to version mismatch. */
            pinctrl_set_br_int_name(br_int->name);
        }

        unixctl_server_run(unixctl);

        unixctl_server_wait(unixctl);
        if (exiting || pending_pkt.conn) {
            poll_immediate_wake();
        }

        if (!ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop)) {
            VLOG_INFO("OVNSB commit failed, force recompute next time.");
            engine_set_force_recompute(true);
        }

        if (ovsdb_idl_loop_commit_and_wait(&ovs_idl_loop) == 1) {
            ct_zones_data = engine_get_data(&en_ct_zones);
            if (ct_zones_data) {
                struct shash_node *iter, *iter_next;
                SHASH_FOR_EACH_SAFE (iter, iter_next,
                                     &ct_zones_data->pending) {
                    struct ct_zone_pending_entry *ctzpe = iter->data;
                    if (ctzpe->state == CT_ZONE_DB_SENT) {
                        shash_delete(&ct_zones_data->pending, iter);
                        free(ctzpe);
                    }
                }
            }
        }

        ovsdb_idl_track_clear(ovnsb_idl_loop.idl);
        ovsdb_idl_track_clear(ovs_idl_loop.idl);

loop_done:
        memory_wait();
        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
    }

    engine_set_context(NULL);
    engine_cleanup();

    /* It's time to exit.  Clean up the databases if we are not restarting */
    if (!restart) {
        bool done = !ovsdb_idl_has_ever_connected(ovnsb_idl_loop.idl);
        while (!done) {
            update_sb_db(ovs_idl_loop.idl, ovnsb_idl_loop.idl,
                         NULL, NULL, NULL, NULL);
            update_ssl_config(ovsrec_ssl_table_get(ovs_idl_loop.idl));

            struct ovsdb_idl_txn *ovs_idl_txn
                = ovsdb_idl_loop_run(&ovs_idl_loop);
            struct ovsdb_idl_txn *ovnsb_idl_txn
                = ovsdb_idl_loop_run(&ovnsb_idl_loop);

            const struct ovsrec_bridge_table *bridge_table
                = ovsrec_bridge_table_get(ovs_idl_loop.idl);
            const struct ovsrec_open_vswitch_table *ovs_table
                = ovsrec_open_vswitch_table_get(ovs_idl_loop.idl);

            const struct sbrec_port_binding_table *port_binding_table
                = sbrec_port_binding_table_get(ovnsb_idl_loop.idl);

            const struct ovsrec_bridge *br_int = get_br_int(bridge_table,
                                                            ovs_table);
            const char *chassis_id = get_ovs_chassis_id(ovs_table);
            const struct sbrec_chassis *chassis
                = (chassis_id
                   ? chassis_lookup_by_name(sbrec_chassis_by_name, chassis_id)
                   : NULL);

            const struct sbrec_chassis_private *chassis_private
                = (chassis_id
                   ? chassis_private_lookup_by_name(
                         sbrec_chassis_private_by_name, chassis_id)
                   : NULL);

            /* Run all of the cleanup functions, even if one of them returns
             * false. We're done if all of them return true. */
            done = binding_cleanup(ovnsb_idl_txn, port_binding_table, chassis);
            done = chassis_cleanup(ovnsb_idl_txn,
                                   chassis, chassis_private) && done;
            done = encaps_cleanup(ovs_idl_txn, br_int) && done;
            done = igmp_group_cleanup(ovnsb_idl_txn, sbrec_igmp_group) && done;
            if (done) {
                poll_immediate_wake();
            }

            ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);
            ovsdb_idl_loop_commit_and_wait(&ovs_idl_loop);
            poll_block();
        }
    }

    free(ovn_version);
    unixctl_server_destroy(unixctl);
    lflow_destroy();
    ofctrl_destroy();
    pinctrl_destroy();
    patch_destroy();

    ovsdb_idl_loop_destroy(&ovs_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);

    free(ovs_remote);
    service_stop();

    exit(retval);
}

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
            printf("SB DB Schema %s\n", sbrec_get_db_version());
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        OVN_DAEMON_OPTION_HANDLERS
        STREAM_SSL_OPTION_HANDLERS

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    char *ovs_remote;
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
    printf("%s: OVN controller\n"
           "usage %s [OPTIONS] [OVS-DATABASE]\n"
           "where OVS-DATABASE is a socket on which the OVS OVSDB server is listening.\n",
               program_name, program_name);
    stream_usage("OVS-DATABASE", true, false, true);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}

static void
ovn_controller_exit(struct unixctl_conn *conn, int argc,
             const char *argv[], void *exit_args_)
{
    struct ovn_controller_exit_args *exit_args = exit_args_;
    *exit_args->exiting = true;
    *exit_args->restart = argc == 2 && !strcmp(argv[1], "--restart");
    unixctl_command_reply(conn, NULL);
}

static void
ct_zone_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
             const char *argv[] OVS_UNUSED, void *ct_zones_)
{
    struct simap *ct_zones = ct_zones_;
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct simap_node *zone;

    SIMAP_FOR_EACH(zone, ct_zones) {
        ds_put_format(&ds, "%s %d\n", zone->name, zone->data);
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
extend_table_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
                 const char *argv[] OVS_UNUSED, void *extend_table_)
{
    struct ovn_extend_table *extend_table = extend_table_;
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct simap items = SIMAP_INITIALIZER(&items);

    struct ovn_extend_table_info *item;
    HMAP_FOR_EACH (item, hmap_node, &extend_table->existing) {
        simap_put(&items, item->name, item->table_id);
    }

    const struct simap_node **nodes = simap_sort(&items);
    size_t n_nodes = simap_count(&items);
    for (size_t i = 0; i < n_nodes; i++) {
        const struct simap_node *node = nodes[i];
        ds_put_format(&ds, "%s: %d\n", node->name, node->data);
    }

    free(nodes);
    simap_destroy(&items);

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
inject_pkt(struct unixctl_conn *conn, int argc OVS_UNUSED,
           const char *argv[], void *pending_pkt_)
{
    struct pending_pkt *pending_pkt = pending_pkt_;

    if (pending_pkt->conn) {
        unixctl_command_reply_error(conn, "already pending packet injection");
        return;
    }
    pending_pkt->conn = conn;
    pending_pkt->flow_s = xstrdup(argv[1]);
}

static void
engine_recompute_cmd(struct unixctl_conn *conn OVS_UNUSED, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *arg OVS_UNUSED)
{
    VLOG_INFO("User triggered force recompute.");
    engine_set_force_recompute(true);
    poll_immediate_wake();
    unixctl_command_reply(conn, NULL);
}

static void
lflow_cache_flush_cmd(struct unixctl_conn *conn OVS_UNUSED,
                      int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
                      void *arg_)
{
    VLOG_INFO("User triggered lflow cache flush.");
    struct flow_output_persistent_data *fo_pd = arg_;
    lflow_cache_flush(fo_pd->lflow_cache);
    fo_pd->conj_id_ofs = 1;
    engine_set_force_recompute(true);
    poll_immediate_wake();
    unixctl_command_reply(conn, NULL);
}

static void
lflow_cache_show_stats_cmd(struct unixctl_conn *conn, int argc OVS_UNUSED,
                           const char *argv[] OVS_UNUSED, void *arg_)
{
    struct flow_output_persistent_data *fo_pd = arg_;
    struct lflow_cache *lc = fo_pd->lflow_cache;
    struct ds ds = DS_EMPTY_INITIALIZER;

    lflow_cache_get_stats(lc, &ds);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
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
debug_pause_execution(struct unixctl_conn *conn, int argc OVS_UNUSED,
                      const char *argv[] OVS_UNUSED, void *paused_)
{
    bool *paused = paused_;

    VLOG_INFO("User triggered execution pause.");
    *paused = true;
    unixctl_command_reply(conn, NULL);
}

static void
debug_resume_execution(struct unixctl_conn *conn, int argc OVS_UNUSED,
                       const char *argv[] OVS_UNUSED, void *paused_)
{
    bool *paused = paused_;

    VLOG_INFO("User triggered execution resume.");
    *paused = false;
    poll_immediate_wake();
    unixctl_command_reply(conn, NULL);
}

static void
debug_status_execution(struct unixctl_conn *conn, int argc OVS_UNUSED,
                       const char *argv[] OVS_UNUSED, void *paused_)
{
    bool *paused = paused_;

    if (*paused) {
        unixctl_command_reply(conn, "paused");
    } else {
        unixctl_command_reply(conn, "running");
    }
}

static void
debug_delay_nb_cfg_report(struct unixctl_conn *conn, int argc OVS_UNUSED,
                          const char *argv[], void *delay_)
{
    unsigned int *delay = delay_;

    if (!str_to_uint(argv[1], 10, delay)) {
        unixctl_command_reply_error(conn, "unsigned integer required");
        return;
    }

    char *msg;
    if (*delay) {
        msg = xasprintf("delay nb_cfg report for %u seconds.", *delay);
        unixctl_command_reply(conn, msg);
        free(msg);
    } else {
        unixctl_command_reply(conn, "no delay for nb_cfg report.");
    }
}
