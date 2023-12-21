/* Copyright (c) 2015, 2016 Nicira, Inc.
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
#include "encaps.h"
#include "chassis.h"

#include "lib/hash.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovsdb-idl.h"
#include "ovn-controller.h"
#include "smap.h"

VLOG_DEFINE_THIS_MODULE(encaps);

/*
 * Given there could be multiple tunnels with different IPs to the same
 * chassis we annotate the external_ids:ovn-chassis-id in tunnel port with
 * <chassis_name>@<remote IP>%<local IP>. The external_id key
 * "ovn-chassis-id" is kept for backward compatibility.
 */
#define OVN_TUNNEL_ID "ovn-chassis-id"

static char *current_br_int_name = NULL;

void
encaps_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_external_ids);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_type);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_options);
}

/* Enough context to create a new tunnel, using tunnel_add(). */
struct tunnel_ctx {
    /* Maps from a tunnel-id (stored in external_ids:ovn-chassis-id) to
     * "struct tunnel_node *". */
    struct shash tunnel;

    /* Names of all ports in the bridge, to allow checking uniqueness when
     * adding a new tunnel. */
    struct sset port_names;

    struct ovsdb_idl_txn *ovs_txn;
    const struct ovsrec_open_vswitch_table *ovs_table;
    const struct ovsrec_bridge *br_int;
    const struct sbrec_chassis *this_chassis;
};

struct tunnel_node {
    const struct ovsrec_port *port;
    const struct ovsrec_bridge *bridge;
};

static char *
tunnel_create_name(struct tunnel_ctx *tc, const char *chassis_id)
{
    for (int i = 0; i < UINT16_MAX; i++) {
        const char *idx = get_chassis_idx(tc->ovs_table);
        char *port_name = xasprintf(
            "ovn%s-%.*s-%x", idx, idx[0] ? 5 : 6, chassis_id, i);

        if (!sset_contains(&tc->port_names, port_name)) {
            return port_name;
        }

        free(port_name);
    }

    return NULL;
}

/*
 * Returns a tunnel-id of the form chassis_id@remote_encap_ip%local_encap_ip.
 */
char *
encaps_tunnel_id_create(const char *chassis_id, const char *remote_encap_ip,
                        const char *local_encap_ip)
{
    return xasprintf("%s%c%s%c%s", chassis_id, '@', remote_encap_ip,
                     '%', local_encap_ip);
}

/*
 * Parses a 'tunnel_id' of the form <chassis_name>@<remote IP>%<local IP>.
 * If the 'chassis_id' argument is not NULL the function will allocate memory
 * and store the chassis_name part of the tunnel-id at '*chassis_id'.
 * Same for remote_encap_ip and local_encap_ip.
 */
bool
encaps_tunnel_id_parse(const char *tunnel_id, char **chassis_id,
                       char **remote_encap_ip, char **local_encap_ip)
{
    /* Find the @.  Fail if there is no @ or if any part is empty. */
    const char *d = strchr(tunnel_id, '@');
    if (d == tunnel_id || !d || !d[1]) {
        return false;
    }

    /* Find the %.  Fail if there is no % or if any part is empty. */
    const char *d2 = strchr(d + 1, '%');
    if (d2 == d + 1 || !d2 || !d2[1]) {
        return false;
    }

    if (chassis_id) {
        *chassis_id = xmemdup0(tunnel_id, d - tunnel_id);
    }

    if (remote_encap_ip) {
        *remote_encap_ip = xmemdup0(d + 1, d2 - (d + 1));
    }

    if (local_encap_ip) {
        *local_encap_ip = xstrdup(d2 + 1);
    }
    return true;
}

/*
 * Returns true if 'tunnel_id' in the format
 *      <chassis_id>@<remote_encap_ip>%<local_encap_ip>
 * contains 'chassis_id' and, if specified, the given 'remote_encap_ip' and
 * 'local_encap_ip'. Returns false otherwise.
 */
bool
encaps_tunnel_id_match(const char *tunnel_id, const char *chassis_id,
                       const char *remote_encap_ip, const char *local_encap_ip)
{
    char *tokstr = xstrdup(tunnel_id);
    char *saveptr = NULL;
    bool ret = false;

    char *token_chassis = strtok_r(tokstr, "@", &saveptr);
    if (!token_chassis || strcmp(token_chassis, chassis_id)) {
        goto out;
    }

    char *token_remote_ip = strtok_r(NULL, "%", &saveptr);
    if (remote_encap_ip &&
        (!token_remote_ip || strcmp(token_remote_ip, remote_encap_ip))) {
        goto out;
    }

    char *token_local_ip = strtok_r(NULL, "", &saveptr);
    if (local_encap_ip &&
        (!token_local_ip || strcmp(token_local_ip, local_encap_ip))) {
        goto out;
    }

    ret = true;
out:
    free(tokstr);
    return ret;
}

static void
tunnel_add(struct tunnel_ctx *tc, const struct sbrec_sb_global *sbg,
           const char *new_chassis_id, const struct sbrec_encap *encap,
           bool must_set_local_ip, const char *local_ip,
           const struct ovsrec_open_vswitch_table *ovs_table)
{
    struct smap options = SMAP_INITIALIZER(&options);
    smap_add(&options, "remote_ip", encap->ip);
    smap_add(&options, "key", "flow");
    const char *dst_port = smap_get(&encap->options, "dst_port");
    const char *csum = smap_get(&encap->options, "csum");
    char *tunnel_entry_id = NULL;

    /*
     * Since a chassis may have multiple encap-ip, we can't just add the
     * chassis name as the OVN_TUNNEL_ID for the port; we use the
     * combination of the chassis_name and the remote and local encap-ips to
     * identify a specific tunnel to the remote chassis.
     */
    tunnel_entry_id = encaps_tunnel_id_create(new_chassis_id, encap->ip,
                                              local_ip);
    if (csum && (!strcmp(csum, "true") || !strcmp(csum, "false"))) {
        smap_add(&options, "csum", csum);
    }
    if (dst_port) {
        smap_add(&options, "dst_port", dst_port);
    }

    const struct ovsrec_open_vswitch *cfg =
        ovsrec_open_vswitch_table_first(ovs_table);

    bool set_local_ip = must_set_local_ip;
    if (cfg) {
        /* If the tos option is configured, get it */
        const char *encap_tos =
            get_chassis_external_id_value(
                &cfg->external_ids, tc->this_chassis->name,
                "ovn-encap-tos", "none");

        if (encap_tos && strcmp(encap_tos, "none")) {
            smap_add(&options, "tos", encap_tos);
        }

        /* If the df_default option is configured, get it */
        const char *encap_df =
            get_chassis_external_id_value(
                &cfg->external_ids, tc->this_chassis->name,
                "ovn-encap-df_default", NULL);
        if (encap_df) {
            smap_add(&options, "df_default", encap_df);
        }

        if (!set_local_ip) {
            /* If ovn-set-local-ip option is configured, get it */
            set_local_ip =
                get_chassis_external_id_value_bool(
                    &cfg->external_ids, tc->this_chassis->name,
                    "ovn-set-local-ip", false);
        }
    }

    /* Add auth info if ipsec is enabled. */
    if (sbg->ipsec) {
        set_local_ip = true;
        smap_add(&options, "remote_name", new_chassis_id);

        /* Force NAT-T traversal via configuration */
        /* Two ipsec backends are supported: libreswan and strongswan */
        /* libreswan param: encapsulation; strongswan param: forceencaps */
        bool encapsulation;
        bool forceencaps;
        encapsulation = smap_get_bool(&sbg->options, "ipsec_encapsulation",
                                      false);
        forceencaps = smap_get_bool(&sbg->options, "ipsec_forceencaps", false);
        if (encapsulation) {
            smap_add(&options, "ipsec_encapsulation", "yes");
        }
        if (forceencaps) {
            smap_add(&options, "ipsec_forceencaps", "yes");
        }
    }

    if (set_local_ip) {
        smap_add(&options, "local_ip", local_ip);
    }

    /* If there's an existing tunnel record that does not need any change,
     * keep it.  Otherwise, create a new record (if there was an existing
     * record, the new record will supplant it and encaps_run() will delete
     * it). */
    struct tunnel_node *tunnel = shash_find_data(&tc->tunnel,
                                                 tunnel_entry_id);
    if (tunnel
        && tunnel->port->n_interfaces == 1
        && !strcmp(tunnel->port->interfaces[0]->type, encap->type)
        && smap_equal(&tunnel->port->interfaces[0]->options, &options)) {
        shash_find_and_delete(&tc->tunnel, tunnel_entry_id);
        free(tunnel);
        goto exit;
    }

    /* Choose a name for the new port.  If we're replacing an old port, reuse
     * its name, otherwise generate a new, unique name. */
    char *port_name = (tunnel
                       ? xstrdup(tunnel->port->name)
                       : tunnel_create_name(tc, new_chassis_id));
    if (!port_name) {
        VLOG_WARN("Unable to allocate unique name for '%s' tunnel",
                  new_chassis_id);
        goto exit;
    }

    struct ovsrec_interface *iface = ovsrec_interface_insert(tc->ovs_txn);
    ovsrec_interface_set_name(iface, port_name);
    ovsrec_interface_set_type(iface, encap->type);
    ovsrec_interface_set_options(iface, &options);

    struct ovsrec_port *port = ovsrec_port_insert(tc->ovs_txn);
    ovsrec_port_set_name(port, port_name);
    ovsrec_port_set_interfaces(port, &iface, 1);
    const struct smap id = SMAP_CONST1(&id, OVN_TUNNEL_ID, tunnel_entry_id);
    ovsrec_port_set_external_ids(port, &id);

    ovsrec_bridge_update_ports_addvalue(tc->br_int, port);

    sset_add_and_free(&tc->port_names, port_name);

exit:
    free(tunnel_entry_id);
    smap_destroy(&options);
}

static bool
chassis_has_type(const struct sbrec_chassis *chassis, uint32_t tun_type) {
    for (size_t i = 0; i < chassis->n_encaps; i++) {
        if (get_tunnel_type(chassis->encaps[i]->type) == tun_type) {
            return true;
        }
    }
    return false;
}

static struct sbrec_encap *
preferred_encap(const struct sbrec_chassis *chassis_rec,
                const struct sbrec_chassis *this_chassis)
{
    struct sbrec_encap *best_encap = NULL;
    uint32_t best_type = 0;

    for (size_t i = 0; i < chassis_rec->n_encaps; i++) {
        uint32_t tun_type = get_tunnel_type(chassis_rec->encaps[i]->type);
        if (tun_type > best_type && chassis_has_type(this_chassis, tun_type)) {
            best_type = tun_type;
            best_encap = chassis_rec->encaps[i];
        }
    }

    return best_encap;
}

/*
 * For each peer chassis, get a preferred tunnel type and create as many tunnels
 * as there are VTEP of that type (differentiated by remote_ip) on that chassis.
 */
static int
chassis_tunnel_add(const struct sbrec_chassis *chassis_rec,
                   const struct sbrec_sb_global *sbg,
                   const struct ovsrec_open_vswitch_table *ovs_table,
                   struct tunnel_ctx *tc,
                   const struct sbrec_chassis *this_chassis)
{
    struct sbrec_encap *encap = preferred_encap(chassis_rec, this_chassis);
    int tuncnt = 0;

    if (!encap) {
        VLOG_INFO("chassis_tunnel_add: No supported encaps for '%s'", chassis_rec->name);
        return tuncnt;
    }

    uint32_t pref_type = get_tunnel_type(encap->type);
    for (int i = 0; i < chassis_rec->n_encaps; i++) {
        uint32_t tun_type = get_tunnel_type(chassis_rec->encaps[i]->type);
        if (tun_type != pref_type) {
            continue;
        }

        /* Check if need to pass the local ip. We always set local ip if there
         * are multiple local IPs for the selected encap type. */
        int count = 0;
        bool set_local_ip = false;
        for (int j = 0; j < this_chassis->n_encaps; j++) {
            if (pref_type == get_tunnel_type(this_chassis->encaps[j]->type) &&
                count++ > 0) {
                set_local_ip = true;
                break;
            }
        }

        for (int j = 0; j < this_chassis->n_encaps; j++) {
            if (pref_type != get_tunnel_type(this_chassis->encaps[j]->type)) {
                continue;
            }
            VLOG_DBG("tunnel_add: '%s', local ip: %s", chassis_rec->name,
                     this_chassis->encaps[j]->ip);
            tunnel_add(tc, sbg, chassis_rec->name, chassis_rec->encaps[i],
                       set_local_ip, this_chassis->encaps[j]->ip, ovs_table);
            tuncnt++;
        }
    }
    return tuncnt;
}

/*
* Returns true if transport_zones and chassis_rec->transport_zones
* have at least one common transport zone.
*/
static bool
chassis_tzones_overlap(const struct sset *transport_zones,
                       const struct sbrec_chassis *chassis_rec)
{
    /* If neither Chassis belongs to any transport zones, return true to
     * form a tunnel between them */
    if (!chassis_rec->n_transport_zones && sset_is_empty(transport_zones)) {
        return true;
    }

    for (int i = 0; i < chassis_rec->n_transport_zones; i++) {
        if (sset_contains(transport_zones, chassis_rec->transport_zones[i])) {
            return true;
        }
    }
    return false;
}

static void
clear_old_tunnels(const struct ovsrec_bridge *old_br_int, const char *prefix,
                  size_t prefix_len)
{
    for (size_t i = 0; i < old_br_int->n_ports; i++) {
        const struct ovsrec_port *port = old_br_int->ports[i];
        const char *id = smap_get(&port->external_ids, OVN_TUNNEL_ID);
        if (id && !strncmp(port->name, prefix, prefix_len)) {
            VLOG_DBG("Clearing old tunnel port \"%s\" (%s) from bridge "
                     "\"%s\".", port->name, id, old_br_int->name);
            ovsrec_bridge_update_ports_delvalue(old_br_int, port);
        }
    }
}

void
encaps_run(struct ovsdb_idl_txn *ovs_idl_txn,
           const struct ovsrec_bridge *br_int,
           const struct sbrec_chassis_table *chassis_table,
           const struct sbrec_chassis *this_chassis,
           const struct sbrec_sb_global *sbg,
           const struct ovsrec_open_vswitch_table *ovs_table,
           const struct sset *transport_zones,
           const struct ovsrec_bridge_table *bridge_table)
{
    if (!ovs_idl_txn || !br_int) {
        return;
    }

    if (!current_br_int_name) {
        /* The controller has just started, we need to look through all
         * bridges for old tunnel ports. */
        char *tunnel_prefix = xasprintf("ovn%s-", get_chassis_idx(ovs_table));
        size_t prefix_len = strlen(tunnel_prefix);

        const struct ovsrec_bridge *br;
        OVSREC_BRIDGE_TABLE_FOR_EACH (br, bridge_table) {
            if (!strcmp(br->name, br_int->name)) {
                continue;
            }
            clear_old_tunnels(br, tunnel_prefix, prefix_len);
        }

        free(tunnel_prefix);
        current_br_int_name = xstrdup(br_int->name);
    } else if (strcmp(current_br_int_name, br_int->name)) {
        /* The integration bridge was changed, clear tunnel ports from
         * the old one. */
        const struct ovsrec_bridge *old_br_int =
            get_bridge(bridge_table, current_br_int_name);
        if (old_br_int) {
            clear_old_tunnels(old_br_int, "", 0);
        }

        free(current_br_int_name);
        current_br_int_name = xstrdup(br_int->name);
    }

    const struct sbrec_chassis *chassis_rec;

    struct tunnel_ctx tc = {
        .tunnel = SHASH_INITIALIZER(&tc.tunnel),
        .port_names = SSET_INITIALIZER(&tc.port_names),
        .br_int = br_int,
        .this_chassis = this_chassis,
        .ovs_table = ovs_table,
    };

    tc.ovs_txn = ovs_idl_txn;
    ovsdb_idl_txn_add_comment(tc.ovs_txn,
                              "ovn-controller: modifying OVS tunnels '%s'",
                              this_chassis->name);

    /* Collect all port names into tc.port_names.
     *
     * Collect all the OVN-created tunnels into tc.tunnel_hmap. */
    for (size_t i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port = br_int->ports[i];
        sset_add(&tc.port_names, port->name);

        const char *id = smap_get(&port->external_ids, OVN_TUNNEL_ID);
        if (id) {
            if (!shash_find(&tc.tunnel, id)) {
                struct tunnel_node *tunnel = xzalloc(sizeof *tunnel);
                tunnel->bridge = br_int;
                tunnel->port = port;
                shash_add_assert(&tc.tunnel, id, tunnel);
            } else {
                /* Duplicate port for tunnel-id.  Arbitrarily choose
                 * to delete this one. */
                ovsrec_bridge_update_ports_delvalue(br_int, port);
            }
        }
    }

    SBREC_CHASSIS_TABLE_FOR_EACH (chassis_rec, chassis_table) {
        if (strcmp(chassis_rec->name, this_chassis->name)) {
            /* Create tunnels to the other Chassis belonging to the
             * same transport zone */
            if (!chassis_tzones_overlap(transport_zones, chassis_rec)) {
                VLOG_DBG("Skipping encap creation for Chassis '%s' because "
                         "it belongs to different transport zones",
                         chassis_rec->name);
                continue;
            }

            if (smap_get_bool(&chassis_rec->other_config, "is-remote", false)
                && !smap_get_bool(&this_chassis->other_config, "is-interconn",
                                  false)) {
                VLOG_DBG("Skipping encap creation for Chassis '%s' because "
                         "it is remote but this chassis is not interconn.",
                         chassis_rec->name);
                continue;
            }

            if (chassis_tunnel_add(chassis_rec, sbg, ovs_table, &tc,
                                   this_chassis) == 0) {
                VLOG_INFO("Creating encap for '%s' failed", chassis_rec->name);
                continue;
            }
        }
    }

    /* Delete any existing OVN tunnels that were not still around. */
    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &tc.tunnel) {
        struct tunnel_node *tunnel = node->data;
        ovsrec_bridge_update_ports_delvalue(tunnel->bridge, tunnel->port);
        shash_delete(&tc.tunnel, node);
        free(tunnel);
    }
    shash_destroy(&tc.tunnel);
    sset_destroy(&tc.port_names);
}

/* Returns true if the database is all cleaned up, false if more work is
 * required. */
bool
encaps_cleanup(struct ovsdb_idl_txn *ovs_idl_txn,
               const struct ovsrec_bridge *br_int)
{
    if (!br_int) {
        return true;
    }

    /* Delete all the OVS-created tunnels from the integration bridge. */
    struct ovsrec_port **ports
        = xmalloc(sizeof *br_int->ports * br_int->n_ports);
    size_t n = 0;
    for (size_t i = 0; i < br_int->n_ports; i++) {
        if (!smap_get(&br_int->ports[i]->external_ids, OVN_TUNNEL_ID)) {
            ports[n++] = br_int->ports[i];
        }
    }

    bool any_changes = n != br_int->n_ports;
    if (any_changes && ovs_idl_txn) {
        ovsdb_idl_txn_add_comment(ovs_idl_txn,
                                  "ovn-controller: destroying tunnels");
        ovsrec_bridge_verify_ports(br_int);
        ovsrec_bridge_set_ports(br_int, ports, n);
    }
    free(ports);

    return !any_changes;
}

void
encaps_destroy(void)
{
    free(current_br_int_name);
}
