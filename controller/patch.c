
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

#include "patch.h"
#include "ovsport.h"

#include "hash.h"
#include "lflow.h"
#include "lib/vswitch-idl.h"
#include "local_data.h"
#include "lport.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "ovn-controller.h"
#include "sset.h"

VLOG_DEFINE_THIS_MODULE(patch);

/* Contains list of physical bridges that were missing. */
static struct sset missed_bridges;

void
patch_init(void)
{
    sset_init(&missed_bridges);
}

void
patch_destroy(void)
{
    sset_destroy(&missed_bridges);
}

static char *
patch_port_name(const char *src, const char *dst)
{
    return xasprintf("patch-%s-to-%s", src, dst);
}

/* Return true if 'port' is a patch port with the specified 'peer'. */
static bool
match_patch_port(const struct ovsrec_port *port, const char *peer)
{
    for (size_t i = 0; i < port->n_interfaces; i++) {
        struct ovsrec_interface *iface = port->interfaces[i];

        if (strcmp(iface->type, "patch")) {
            continue;
        }
        const char *iface_peer = smap_get(&iface->options, "peer");

        if (iface_peer && !strcmp(iface_peer, peer)) {
            return true;
        }
    }
    return false;
}

/* Creates a patch port in bridge 'src' named 'src_name', whose peer is
 * 'dst_name' in bridge 'dst'.  Initializes the patch port's external-ids:'key'
 * to 'key'.
 *
 * If such a patch port already exists, removes it from 'existing_ports'. */
static void
create_patch_port(struct ovsdb_idl_txn *ovs_idl_txn,
                  const char *key, const char *value,
                  const struct ovsrec_bridge *src, const char *src_name,
                  const struct ovsrec_bridge *dst, const char *dst_name,
                  struct shash *existing_ports)
{
    for (size_t i = 0; i < src->n_ports; i++) {
        if (match_patch_port(src->ports[i], dst_name)) {
            /* Patch port already exists on 'src'. */
            shash_find_and_delete(existing_ports, src->ports[i]->name);
            return;
        }
    }

    ovsdb_idl_txn_add_comment(ovs_idl_txn,
                              "ovn-controller: creating patch port '%s' from '%s' to '%s'",
                              src_name, src->name, dst->name);

    const struct smap if_options = SMAP_CONST1(&if_options, "peer", dst_name);
    const struct smap port_ids = SMAP_CONST1(&port_ids, key, value);

    ovsport_create(ovs_idl_txn, src, src_name, "patch", &port_ids, NULL,
                   &if_options, 0);
}

static void
remove_port(const struct ovsrec_bridge_table *bridge_table,
            const struct ovsrec_port *port)
{
    const struct ovsrec_bridge *bridge;

    /* We know the port we want to delete, but we have to find the bridge its
     * on to do so.  Note this only runs on a config change that should be
     * pretty rare. */
    OVSREC_BRIDGE_TABLE_FOR_EACH(bridge, bridge_table) {
        size_t i;

        for (i = 0; i < bridge->n_ports; i++) {
            if (bridge->ports[i] != port) {
                continue;
            }
            ovsport_remove(bridge, port);
            return;
        }
    }
}

void
add_ovs_bridge_mappings(const struct ovsrec_open_vswitch_table *ovs_table,
                        const struct ovsrec_bridge_table *bridge_table,
                        struct shash *bridge_mappings)
{
    const struct ovsrec_open_vswitch *cfg;

    cfg = ovsrec_open_vswitch_table_first(ovs_table);
    if (cfg) {
        const char *mappings_cfg;
        char *cur, *next, *start;

        mappings_cfg = smap_get(&cfg->external_ids, "ovn-bridge-mappings");
        if (!mappings_cfg || !mappings_cfg[0]) {
            return;
        }

        next = start = xstrdup(mappings_cfg);
        while ((cur = strsep(&next, ",")) && *cur) {
            const struct ovsrec_bridge *ovs_bridge;
            char *network, *bridge = cur;

            network = strsep(&bridge, ":");
            if (!bridge || !*network || !*bridge) {
                VLOG_ERR("Invalid ovn-bridge-mappings configuration: '%s'",
                         mappings_cfg);
                break;
            }

            ovs_bridge = get_bridge(bridge_table, bridge);
            if (!ovs_bridge) {
                VLOG_WARN("Bridge '%s' not found for network '%s'",
                          bridge, network);
                continue;
            }

            shash_add(bridge_mappings, network, ovs_bridge);
        }
        free(start);
    }
}

static void
add_bridge_mappings_by_type(struct ovsdb_idl_txn *ovs_idl_txn,
                            struct ovsdb_idl_index *sbrec_port_binding_by_type,
                            const struct ovsrec_bridge *br_int,
                            struct shash *existing_ports,
                            const struct sbrec_chassis *chassis,
                            struct shash *bridge_mappings,
                            const char *pb_type, const char *patch_port_id,
                            const struct hmap *local_datapaths,
                            bool log_missing_bridge)
{
    struct sbrec_port_binding *target =
        sbrec_port_binding_index_init_row(sbrec_port_binding_by_type);
    sbrec_port_binding_index_set_type(target, pb_type);

    const struct sbrec_port_binding *binding;

    SBREC_PORT_BINDING_FOR_EACH_EQUAL(binding, target,
                                      sbrec_port_binding_by_type) {
        /* When ovn-monitor-all is true, there can be port-bindings on
         * datapaths that are not related to this chassis. Ignore them. */
        if (!get_local_datapath(local_datapaths,
                                binding->datapath->tunnel_key)) {
            continue;
        }

        /* If needed, check if the port is bound to this chassis. */
        const struct sbrec_chassis *bchassis = binding->chassis;

        if (chassis && (!bchassis || strcmp(chassis->name, bchassis->name))) {
            continue;
        }

        const char *network = smap_get(&binding->options, "network_name");

        if (!network) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

            VLOG_ERR_RL(&rl, "%s port '%s' has no network name.",
                        binding->type, binding->logical_port);
            continue;
        }
        char *msg_key = xasprintf("%s;%s", binding->logical_port, network);
        struct ovsrec_bridge *br_ln =
            shash_find_data(bridge_mappings, network);
        if (!br_ln) {
            if (log_missing_bridge) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

                VLOG_ERR_RL(&rl, "bridge not found for %s port '%s' "
                            "with network name '%s'",
                            binding->type, binding->logical_port, network);
            } else if (!sset_contains(&missed_bridges, msg_key)) {
                VLOG_INFO("bridge not found for %s port '%s' with "
                          "network name '%s'; skipping",
                          binding->type, binding->logical_port, network);
                sset_add(&missed_bridges, msg_key);
            }
            free(msg_key);
            continue;
        }
        sset_find_and_delete(&missed_bridges, msg_key);
        free(msg_key);

        char *name1 = patch_port_name(br_int->name, binding->logical_port);
        char *name2 = patch_port_name(binding->logical_port, br_int->name);

        create_patch_port(ovs_idl_txn, patch_port_id, binding->logical_port,
                          br_int, name1, br_ln, name2, existing_ports);
        create_patch_port(ovs_idl_txn, patch_port_id, binding->logical_port,
                          br_ln, name2, br_int, name1, existing_ports);
        free(name1);
        free(name2);
    }
    sbrec_port_binding_index_destroy_row(target);
}

/* Obtains external-ids:ovn-bridge-mappings from OVSDB and adds patch ports for
 * the local bridge mappings.  Removes any patch ports for bridge mappings that
 * already existed from 'existing_ports'. */
static void
add_bridge_mappings(struct ovsdb_idl_txn *ovs_idl_txn,
                    struct ovsdb_idl_index *sbrec_port_binding_by_type,
                    const struct ovsrec_bridge_table *bridge_table,
                    const struct ovsrec_open_vswitch_table *ovs_table,
                    const struct ovsrec_bridge *br_int,
                    struct shash *existing_ports,
                    const struct sbrec_chassis *chassis,
                    const struct hmap *local_datapaths)
{
    /* Get ovn-bridge-mappings. */
    struct shash bridge_mappings = SHASH_INITIALIZER(&bridge_mappings);

    add_ovs_bridge_mappings(ovs_table, bridge_table, &bridge_mappings);

    add_bridge_mappings_by_type(ovs_idl_txn, sbrec_port_binding_by_type,
                                br_int, existing_ports, chassis,
                                &bridge_mappings, "l2gateway",
                                "ovn-l2gateway-port", local_datapaths, true);

    /* Since having localnet ports that are not mapped on some chassis is a
     * supported configuration used to implement multisegment switches with
     * fabric L3 routing between segments, log the following message once per
     * run but don't unnecessarily pollute the log file; pass
     * 'log_missing_bridge = false'. */
    add_bridge_mappings_by_type(ovs_idl_txn, sbrec_port_binding_by_type,
                                br_int, existing_ports, NULL,
                                &bridge_mappings, "localnet",
                                "ovn-localnet-port", local_datapaths, false);
    shash_destroy(&bridge_mappings);
}

void
patch_run(struct ovsdb_idl_txn *ovs_idl_txn,
          struct ovsdb_idl_index *sbrec_port_binding_by_type,
          const struct ovsrec_bridge_table *bridge_table,
          const struct ovsrec_open_vswitch_table *ovs_table,
          const struct ovsrec_port_table *port_table,
          const struct ovsrec_bridge *br_int,
          const struct sbrec_chassis *chassis,
          const struct hmap *local_datapaths)
{
    if (!ovs_idl_txn) {
        return;
    }

    /* Figure out what patch ports already exist. ovn-controller does not
     * create or use ports of type "ovn-l3gateway-port" or
     * "ovn-logical-patch-port", but older version did.  We still recognize
     * them here, so that we delete them at the end of this function, to avoid
     * leaving useless ports on upgrade. */
    struct shash existing_ports = SHASH_INITIALIZER(&existing_ports);
    const struct ovsrec_port *port;

    OVSREC_PORT_TABLE_FOR_EACH(port, port_table) {
        if (smap_get(&port->external_ids, "ovn-localnet-port")
            || smap_get(&port->external_ids, "ovn-l2gateway-port")
            || smap_get(&port->external_ids, "ovn-l3gateway-port")
            || smap_get(&port->external_ids, "ovn-logical-patch-port")) {
            shash_add(&existing_ports, port->name, port);
        }
    }

    /* Create in the database any patch ports that should exist.  Remove from
     * 'existing_ports' any patch ports that do exist in the database and
     * should be there. */
    add_bridge_mappings(ovs_idl_txn, sbrec_port_binding_by_type, bridge_table,
                        ovs_table, br_int, &existing_ports, chassis,
                        local_datapaths);

    /* Now 'existing_ports' only still contains patch ports that exist in the
     * database but shouldn't.  Delete them from the database. */
    struct shash_node *port_node;

    SHASH_FOR_EACH_SAFE(port_node, &existing_ports) {
        port = port_node->data;
        shash_delete(&existing_ports, port_node);
        remove_port(bridge_table, port);
    }
    shash_destroy(&existing_ports);
}
