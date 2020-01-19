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
#include "binding.h"
#include "ha-chassis.h"
#include "lflow.h"
#include "lport.h"
#include "patch.h"

#include "lib/bitmap.h"
#include "openvswitch/poll-loop.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "lib/netdev.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "lib/chassis-index.h"
#include "lib/ovn-sb-idl.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(binding);

#define OVN_QOS_TYPE "linux-htb"

struct qos_queue {
    struct hmap_node node;
    uint32_t queue_id;
    uint32_t max_rate;
    uint32_t burst;
};

void
binding_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_bridges);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_qos);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_external_ids);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_bfd);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_bfd_status);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_status);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_qos);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_qos_col_type);
}

static void
add_local_datapath__(struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                     struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                     struct ovsdb_idl_index *sbrec_port_binding_by_name,
                     const struct sbrec_datapath_binding *datapath,
                     bool has_local_l3gateway, int depth,
                     struct hmap *local_datapaths)
{
    uint32_t dp_key = datapath->tunnel_key;
    struct local_datapath *ld = get_local_datapath(local_datapaths, dp_key);
    if (ld) {
        if (has_local_l3gateway) {
            ld->has_local_l3gateway = true;
        }
        return;
    }

    ld = xzalloc(sizeof *ld);
    hmap_insert(local_datapaths, &ld->hmap_node, dp_key);
    ld->datapath = datapath;
    ld->localnet_port = NULL;
    ld->has_local_l3gateway = has_local_l3gateway;

    if (depth >= 100) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "datapaths nested too deep");
        return;
    }

    struct sbrec_port_binding *target =
        sbrec_port_binding_index_init_row(sbrec_port_binding_by_datapath);
    sbrec_port_binding_index_set_datapath(target, datapath);

    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, target,
                                       sbrec_port_binding_by_datapath) {
        if (!strcmp(pb->type, "patch") || !strcmp(pb->type, "l3gateway")) {
            const char *peer_name = smap_get(&pb->options, "peer");
            if (peer_name) {
                const struct sbrec_port_binding *peer;

                peer = lport_lookup_by_name(sbrec_port_binding_by_name,
                                            peer_name);

                if (peer && peer->datapath) {
                    if (!strcmp(pb->type, "patch")) {
                        /* Add the datapath to local datapath only for patch
                         * ports. For l3gateway ports, since gateway router
                         * resides on one chassis, we don't need to add.
                         * Otherwise, all other chassis might create patch
                         * ports between br-int and the provider bridge. */
                        add_local_datapath__(sbrec_datapath_binding_by_key,
                                             sbrec_port_binding_by_datapath,
                                             sbrec_port_binding_by_name,
                                             peer->datapath, false,
                                             depth + 1, local_datapaths);
                    }
                    ld->n_peer_ports++;
                    if (ld->n_peer_ports > ld->n_allocated_peer_ports) {
                        ld->peer_ports =
                            x2nrealloc(ld->peer_ports,
                                       &ld->n_allocated_peer_ports,
                                       sizeof *ld->peer_ports);
                    }
                    ld->peer_ports[ld->n_peer_ports - 1].local = pb;
                    ld->peer_ports[ld->n_peer_ports - 1].remote = peer;
                }
            }
        }
    }
    sbrec_port_binding_index_destroy_row(target);
}

static void
add_local_datapath(struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                   struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                   struct ovsdb_idl_index *sbrec_port_binding_by_name,
                   const struct sbrec_datapath_binding *datapath,
                   bool has_local_l3gateway, struct hmap *local_datapaths)
{
    add_local_datapath__(sbrec_datapath_binding_by_key,
                         sbrec_port_binding_by_datapath,
                         sbrec_port_binding_by_name,
                         datapath, has_local_l3gateway, 0, local_datapaths);
}

static void
get_qos_params(const struct sbrec_port_binding *pb, struct hmap *queue_map)
{
    uint32_t max_rate = smap_get_int(&pb->options, "qos_max_rate", 0);
    uint32_t burst = smap_get_int(&pb->options, "qos_burst", 0);
    uint32_t queue_id = smap_get_int(&pb->options, "qdisc_queue_id", 0);

    if ((!max_rate && !burst) || !queue_id) {
        /* Qos is not configured for this port. */
        return;
    }

    struct qos_queue *node = xzalloc(sizeof *node);
    hmap_insert(queue_map, &node->node, hash_int(queue_id, 0));
    node->max_rate = max_rate;
    node->burst = burst;
    node->queue_id = queue_id;
}

static const struct ovsrec_qos *
get_noop_qos(struct ovsdb_idl_txn *ovs_idl_txn,
             const struct ovsrec_qos_table *qos_table)
{
    const struct ovsrec_qos *qos;
    OVSREC_QOS_TABLE_FOR_EACH (qos, qos_table) {
        if (!strcmp(qos->type, "linux-noop")) {
            return qos;
        }
    }

    if (!ovs_idl_txn) {
        return NULL;
    }
    qos = ovsrec_qos_insert(ovs_idl_txn);
    ovsrec_qos_set_type(qos, "linux-noop");
    return qos;
}

static bool
set_noop_qos(struct ovsdb_idl_txn *ovs_idl_txn,
             const struct ovsrec_port_table *port_table,
             const struct ovsrec_qos_table *qos_table,
             struct sset *egress_ifaces)
{
    if (!ovs_idl_txn) {
        return false;
    }

    const struct ovsrec_qos *noop_qos = get_noop_qos(ovs_idl_txn, qos_table);
    if (!noop_qos) {
        return false;
    }

    const struct ovsrec_port *port;
    size_t count = 0;

    OVSREC_PORT_TABLE_FOR_EACH (port, port_table) {
        if (sset_contains(egress_ifaces, port->name)) {
            ovsrec_port_set_qos(port, noop_qos);
            count++;
        }
        if (sset_count(egress_ifaces) == count) {
            break;
        }
    }
    return true;
}

static void
set_qos_type(struct netdev *netdev, const char *type)
{
    int error = netdev_set_qos(netdev, type, NULL);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "%s: could not set qdisc type \"%s\" (%s)",
                     netdev_get_name(netdev), type, ovs_strerror(error));
    }
}

static void
setup_qos(const char *egress_iface, struct hmap *queue_map)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    struct netdev *netdev_phy;

    if (!egress_iface) {
        /* Queues cannot be configured. */
        return;
    }

    int error = netdev_open(egress_iface, NULL, &netdev_phy);
    if (error) {
        VLOG_WARN_RL(&rl, "%s: could not open netdev (%s)",
                     egress_iface, ovs_strerror(error));
        return;
    }

    /* Check current qdisc. */
    const char *qdisc_type;
    struct smap qdisc_details;

    smap_init(&qdisc_details);
    if (netdev_get_qos(netdev_phy, &qdisc_type, &qdisc_details) != 0 ||
        qdisc_type[0] == '\0') {
        smap_destroy(&qdisc_details);
        netdev_close(netdev_phy);
        /* Qos is not supported. */
        return;
    }
    smap_destroy(&qdisc_details);

    /* If we're not actually being requested to do any QoS:
     *
     *     - If the current qdisc type is OVN_QOS_TYPE, then we clear the qdisc
     *       type to "".  Otherwise, it's possible that our own leftover qdisc
     *       settings could cause strange behavior on egress.  Also, QoS is
     *       expensive and may waste CPU time even if it's not really in use.
     *
     *       OVN isn't the only software that can configure qdiscs, and
     *       physical interfaces are shared resources, so there is some risk in
     *       this strategy: we could disrupt some other program's QoS.
     *       Probably, to entirely avoid this possibility we would need to add
     *       a configuration setting.
     *
     *     - Otherwise leave the qdisc alone. */
    if (hmap_is_empty(queue_map)) {
        if (!strcmp(qdisc_type, OVN_QOS_TYPE)) {
            set_qos_type(netdev_phy, "");
        }
        netdev_close(netdev_phy);
        return;
    }

    /* Configure qdisc. */
    if (strcmp(qdisc_type, OVN_QOS_TYPE)) {
        set_qos_type(netdev_phy, OVN_QOS_TYPE);
    }

    /* Check and delete if needed. */
    struct netdev_queue_dump dump;
    unsigned int queue_id;
    struct smap queue_details;
    struct qos_queue *sb_info;
    struct hmap consistent_queues;

    smap_init(&queue_details);
    hmap_init(&consistent_queues);
    NETDEV_QUEUE_FOR_EACH (&queue_id, &queue_details, &dump, netdev_phy) {
        bool is_queue_needed = false;

        HMAP_FOR_EACH_WITH_HASH (sb_info, node, hash_int(queue_id, 0),
                                 queue_map) {
            is_queue_needed = true;
            if (sb_info->max_rate ==
                smap_get_int(&queue_details, "max-rate", 0)
                && sb_info->burst == smap_get_int(&queue_details, "burst", 0)) {
                /* This queue is consistent. */
                hmap_insert(&consistent_queues, &sb_info->node,
                            hash_int(queue_id, 0));
                break;
            }
        }

        if (!is_queue_needed) {
            error = netdev_delete_queue(netdev_phy, queue_id);
            if (error) {
                VLOG_WARN_RL(&rl, "%s: could not delete queue %u (%s)",
                             egress_iface, queue_id, ovs_strerror(error));
            }
        }
    }

    /* Create/Update queues. */
    HMAP_FOR_EACH (sb_info, node, queue_map) {
        if (hmap_contains(&consistent_queues, &sb_info->node)) {
            hmap_remove(&consistent_queues, &sb_info->node);
            continue;
        }

        smap_clear(&queue_details);
        smap_add_format(&queue_details, "max-rate", "%d", sb_info->max_rate);
        smap_add_format(&queue_details, "burst", "%d", sb_info->burst);
        error = netdev_set_queue(netdev_phy, sb_info->queue_id,
                                 &queue_details);
        if (error) {
            VLOG_WARN_RL(&rl, "%s: could not configure queue %u (%s)",
                         egress_iface, sb_info->queue_id, ovs_strerror(error));
        }
    }
    smap_destroy(&queue_details);
    hmap_destroy(&consistent_queues);
    netdev_close(netdev_phy);
}

static void
destroy_qos_map(struct hmap *qos_map)
{
    struct qos_queue *qos_queue;
    HMAP_FOR_EACH_POP (qos_queue, node, qos_map) {
        free(qos_queue);
    }

    hmap_destroy(qos_map);
}

static void
update_local_lport_ids(struct sset *local_lport_ids,
                       const struct sbrec_port_binding *pb)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "%"PRId64"_%"PRId64,
             pb->datapath->tunnel_key, pb->tunnel_key);
    sset_add(local_lport_ids, buf);
}

/*
 * Get the encap from the chassis for this port. The interface
 * may have an external_ids:encap-ip=<encap-ip> set; if so we
 * get the corresponding encap from the chassis.
 * If "encap-ip" external-ids is not set, we'll not bind the port
 * to any specific encap rec. and we'll pick up a tunnel port based on
 * the chassis name alone for the port.
 */
static struct sbrec_encap *
sbrec_get_port_encap(const struct sbrec_chassis *chassis_rec,
                     const struct ovsrec_interface *iface_rec)
{

    if (!iface_rec) {
        return NULL;
    }

    const char *encap_ip = smap_get(&iface_rec->external_ids, "encap-ip");
    if (!encap_ip) {
        return NULL;
    }

    struct sbrec_encap *best_encap = NULL;
    uint32_t best_type = 0;
    for (int i = 0; i < chassis_rec->n_encaps; i++) {
        if (!strcmp(chassis_rec->encaps[i]->ip, encap_ip)) {
            uint32_t tun_type = get_tunnel_type(chassis_rec->encaps[i]->type);
            if (tun_type > best_type) {
                best_type = tun_type;
                best_encap = chassis_rec->encaps[i];
            }
        }
    }
    return best_encap;
}

static void
add_localnet_egress_interface_mappings(
        const struct sbrec_port_binding *port_binding,
        struct shash *bridge_mappings, struct sset *egress_ifaces)
{
    const char *network = smap_get(&port_binding->options, "network_name");
    if (!network) {
        return;
    }

    struct ovsrec_bridge *br_ln = shash_find_data(bridge_mappings, network);
    if (!br_ln) {
        return;
    }

    /* Add egress-ifaces from the connected bridge */
    for (size_t i = 0; i < br_ln->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_ln->ports[i];

        for (size_t j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;

            iface_rec = port_rec->interfaces[j];
            bool is_egress_iface = smap_get_bool(&iface_rec->external_ids,
                                                 "ovn-egress-iface", false);
            if (!is_egress_iface) {
                continue;
            }
            sset_add(egress_ifaces, iface_rec->name);
        }
    }
}

static bool
is_network_plugged(const struct sbrec_port_binding *binding_rec,
                   struct shash *bridge_mappings)
{
    const char *network = smap_get(&binding_rec->options, "network_name");
    return network ? !!shash_find_data(bridge_mappings, network) : false;
}

static void
consider_localnet_port(const struct sbrec_port_binding *binding_rec,
                       struct shash *bridge_mappings,
                       struct sset *egress_ifaces,
                       struct hmap *local_datapaths)
{
    /* Ignore localnet ports for unplugged networks. */
    if (!is_network_plugged(binding_rec, bridge_mappings)) {
        return;
    }

    add_localnet_egress_interface_mappings(binding_rec,
            bridge_mappings, egress_ifaces);

    struct local_datapath *ld
        = get_local_datapath(local_datapaths,
                             binding_rec->datapath->tunnel_key);
    if (!ld) {
        return;
    }

    if (ld->localnet_port && strcmp(ld->localnet_port->logical_port,
                                    binding_rec->logical_port)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "localnet port '%s' already set for datapath "
                     "'%"PRId64"', skipping the new port '%s'.",
                     ld->localnet_port->logical_port,
                     binding_rec->datapath->tunnel_key,
                     binding_rec->logical_port);
        return;
    }
    ld->localnet_port = binding_rec;
}

/* Local bindings. binding.c module binds the logical port (represented by
 * Port_Binding rows) and sets the 'chassis' column when it sees the
 * OVS interface row (of type "" or "internal") with the
 * external_ids:iface-id=<logical_port name> set.
 *
 * This module also manages the other port_bindings.
 *
 * To better manage the local bindings with the associated OVS interfaces,
 * 'struct local_binding' is used. A shash of these local bindings is
 * maintained with the 'external_ids:iface-id' as the key to the shash.
 *
 * struct local_binding has 3 main fields:
 *    - type
 *    - OVS interface row object
 *    - Port_Binding row object
 *
 * An instance of 'struct local_binding' can be one of 3 types.
 *
 *  BT_VIF:     Represent a local binding for an OVS interface of
 *              type "" or "internal" with the external_ids:iface-id
 *              set.
 *
 *              This can be a
 *                 * probable local binding - external_ids:iface-id is
 *                   set, but the corresponding Port_Binding row is not
 *                   created or is not visible to the local ovn-controller
 *                   instance.
 *
 *                 * a local binding - external_ids:iface-id is set and
 *                   which is already bound to the corresponding Port_Binding
 *                   row.
 *
 *              It maintains a list of children
 *              (of type BT_CONTAINER/BT_VIRTUAL) if any.
 *
 *  BT_CONTAINER:   Represents a local binding which has a parent of type
 *                  BT_VIF. Its Port_Binding row's 'parent' column is set to
 *                  its parent's Port_Binding. It shares the OVS interface row
 *                  with the parent.
 *
 *  BT_VIRTUAL: Represents a local binding which has a parent of type BT_VIF.
 *              Its Port_Binding type is "virtual" and it shares the OVS
 *              interface row with the parent.
 *              Port_Binding of type "virtual" is claimed by pinctrl module
 *              when it sees the ARP packet from the parent's VIF.
 *
 */
enum local_binding_type {
    BT_VIF,
    BT_CONTAINER,
    BT_VIRTUAL
};

struct local_binding {
    char *name;
    enum local_binding_type type;
    const struct ovsrec_interface *iface;
    const struct sbrec_port_binding *pb;

    /* shash of 'struct local_binding' representing children. */
    struct shash children;
};

static struct local_binding *
local_binding_create(const char *name, const struct ovsrec_interface *iface,
                     const struct sbrec_port_binding *pb,
                     enum local_binding_type type)
{
    struct local_binding *lbinding = xzalloc(sizeof *lbinding);
    lbinding->name = xstrdup(name);
    lbinding->type = type;
    lbinding->pb = pb;
    lbinding->iface = iface;
    shash_init(&lbinding->children);
    return lbinding;
}

static void
local_binding_add(struct shash *local_bindings, struct local_binding *lbinding)
{
    shash_add(local_bindings, lbinding->name, lbinding);
}

static struct local_binding *
local_binding_find(struct shash *local_bindings, const char *name)
{
    return shash_find_data(local_bindings, name);
}

static void
local_binding_destroy(struct local_binding *lbinding)
{
    local_bindings_destroy(&lbinding->children);

    free(lbinding->name);
    free(lbinding);
}

void
local_bindings_init(struct shash *local_bindings)
{
    shash_init(local_bindings);
}

void
local_bindings_destroy(struct shash *local_bindings)
{
    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, local_bindings) {
        struct local_binding *lbinding = node->data;
        local_binding_destroy(lbinding);
        shash_delete(local_bindings, node);
    }

    shash_destroy(local_bindings);
}

static void
local_binding_add_child(struct local_binding *lbinding,
                        struct local_binding *child)
{
    local_binding_add(&lbinding->children, child);
}

static struct local_binding *
local_binding_find_child(struct local_binding *lbinding,
                         const char *child_name)
{
    return local_binding_find(&lbinding->children, child_name);
}

static bool
is_lport_vif(const struct sbrec_port_binding *pb)
{
    return !pb->type[0];
}

static bool
is_lport_container(const struct sbrec_port_binding *pb)
{
    return is_lport_vif(pb) && pb->parent_port && pb->parent_port[0];
}

/* Corresponds to each Port_Binding.type. */
enum en_lport_type {
    LP_UNKNOWN,
    LP_VIF,
    LP_PATCH,
    LP_L3GATEWAY,
    LP_LOCALNET,
    LP_LOCALPORT,
    LP_L2GATEWAY,
    LP_VTEP,
    LP_CHASSISREDIRECT,
    LP_VIRTUAL,
    LP_EXTERNAL,
    LP_REMOTE
};

static enum en_lport_type
get_lport_type(const struct sbrec_port_binding *pb)
{
    if (is_lport_vif(pb)) {
        return LP_VIF;
    } else if (!strcmp(pb->type, "patch")) {
        return LP_PATCH;
    } else if (!strcmp(pb->type, "chassisredirect")) {
        return LP_CHASSISREDIRECT;
    } else if (!strcmp(pb->type, "l3gateway")) {
        return LP_L3GATEWAY;
    } else if (!strcmp(pb->type, "localnet")) {
        return LP_LOCALNET;
    } else if (!strcmp(pb->type, "localport")) {
        return LP_LOCALPORT;
    } else if (!strcmp(pb->type, "l2gateway")) {
        return LP_L2GATEWAY;
    } else if (!strcmp(pb->type, "virtual")) {
        return LP_VIRTUAL;
    } else if (!strcmp(pb->type, "external")) {
        return LP_EXTERNAL;
    } else if (!strcmp(pb->type, "remote")) {
        return LP_REMOTE;
    } else if (!strcmp(pb->type, "vtep")) {
        return LP_VTEP;
    }

    return LP_UNKNOWN;
}

static void
claim_lport(const struct sbrec_port_binding *pb,
            const struct sbrec_chassis *chassis_rec,
            const struct ovsrec_interface *iface_rec)
{
    if (pb->chassis != chassis_rec) {
        if (pb->chassis) {
            VLOG_INFO("Changing chassis for lport %s from %s to %s.",
                    pb->logical_port, pb->chassis->name,
                    chassis_rec->name);
        } else {
            VLOG_INFO("Claiming lport %s for this chassis.", pb->logical_port);
        }
        for (int i = 0; i < pb->n_mac; i++) {
            VLOG_INFO("%s: Claiming %s", pb->logical_port, pb->mac[i]);
        }

        sbrec_port_binding_set_chassis(pb, chassis_rec);
    }

    /* Check if the port encap binding, if any, has changed */
    struct sbrec_encap *encap_rec =
        sbrec_get_port_encap(chassis_rec, iface_rec);
    if (encap_rec && pb->encap != encap_rec) {
        sbrec_port_binding_set_encap(pb, encap_rec);
    }
}

static void
release_lport(const struct sbrec_port_binding *pb)
{
    VLOG_INFO("Releasing lport %s from this chassis.", pb->logical_port);
    if (pb->encap) {
        sbrec_port_binding_set_encap(pb, NULL);
    }
    sbrec_port_binding_set_chassis(pb, NULL);

    if (pb->virtual_parent) {
        sbrec_port_binding_set_virtual_parent(pb, NULL);
    }
}

static bool
is_lbinding_set(struct local_binding *lbinding)
{
    return lbinding && lbinding->pb && lbinding->iface;
}

static bool
is_lbinding_this_chassis(struct local_binding *lbinding,
                         const struct sbrec_chassis *chassis)
{
    return lbinding && lbinding->pb && lbinding->pb->chassis == chassis;
}

static bool
can_bind_on_this_chassis(const struct sbrec_chassis *chassis_rec,
                         const char *requested_chassis)
{
    return !requested_chassis || !requested_chassis[0]
           || !strcmp(requested_chassis, chassis_rec->name)
           || !strcmp(requested_chassis, chassis_rec->hostname);
}

static void
consider_vif_lport_(const struct sbrec_port_binding *pb,
                    bool can_bind, const char *vif_chassis,
                    struct binding_ctx_in *b_ctx_in,
                    struct binding_ctx_out *b_ctx_out,
                    struct local_binding *lbinding,
                    struct hmap *qos_map)
{
    bool lbinding_set = is_lbinding_set(lbinding);
    if (lbinding_set) {
        if (can_bind) {
            /* We can claim the lport. */
            claim_lport(pb, b_ctx_in->chassis_rec, lbinding->iface);

            add_local_datapath(b_ctx_in->sbrec_datapath_binding_by_key,
                               b_ctx_in->sbrec_port_binding_by_datapath,
                               b_ctx_in->sbrec_port_binding_by_name,
                               pb->datapath, false,
                               b_ctx_out->local_datapaths);
            update_local_lport_ids(b_ctx_out->local_lport_ids, pb);
            if (lbinding->iface && qos_map && b_ctx_in->ovs_idl_txn) {
                get_qos_params(pb, qos_map);
            }
        } else {
            /* We could, but can't claim the lport. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_INFO_RL(&rl,
                             "Not claiming lport %s, chassis %s "
                             "requested-chassis %s",
                             pb->logical_port,
                             b_ctx_in->chassis_rec->name,
                             vif_chassis);
        }
    }

    if (pb->chassis == b_ctx_in->chassis_rec) {
        /* Release the lport if there is no lbinding. */
        if (!lbinding_set || !can_bind) {
            release_lport(pb);
        }
    }

}

static void
consider_vif_lport(const struct sbrec_port_binding *pb,
                   struct binding_ctx_in *b_ctx_in,
                   struct binding_ctx_out *b_ctx_out,
                   struct local_binding *lbinding,
                   struct hmap *qos_map)
{
    const char *vif_chassis = smap_get(&pb->options, "requested-chassis");
    bool can_bind = can_bind_on_this_chassis(b_ctx_in->chassis_rec,
                                             vif_chassis);

    if (!lbinding) {
        lbinding = local_binding_find(b_ctx_out->local_bindings,
                                      pb->logical_port);
    }

    if (lbinding) {
        lbinding->pb = pb;
    }

    consider_vif_lport_(pb, can_bind, vif_chassis, b_ctx_in,
                        b_ctx_out, lbinding, qos_map);
}

static void
consider_container_lport(const struct sbrec_port_binding *pb,
                         struct binding_ctx_in *b_ctx_in,
                         struct binding_ctx_out *b_ctx_out,
                         struct hmap *qos_map)
{
    struct local_binding *parent_lbinding;
    parent_lbinding = local_binding_find(b_ctx_out->local_bindings,
                                         pb->parent_port);

    if (parent_lbinding && !parent_lbinding->pb) {
        parent_lbinding->pb = lport_lookup_by_name(
            b_ctx_in->sbrec_port_binding_by_name, pb->parent_port);

        if (parent_lbinding->pb) {
            /* Its possible that the parent lport is not considered yet.
             * So call consider_vif_lport() to process it first. */
            consider_vif_lport(parent_lbinding->pb, b_ctx_in, b_ctx_out,
                               parent_lbinding, qos_map);
        }
    }

    if (!parent_lbinding || !parent_lbinding->pb) {
        /* Call release_lport, to release the container lport, if
         * it was bound earlier. */
        if (pb->chassis == b_ctx_in->chassis_rec) {
            release_lport(pb);
        }
        return;
    }

    struct local_binding *container_lbinding =
        local_binding_find_child(parent_lbinding, pb->logical_port);
    ovs_assert(!container_lbinding);

    container_lbinding = local_binding_create(pb->logical_port,
                                              parent_lbinding->iface,
                                              pb, BT_CONTAINER);
    local_binding_add_child(parent_lbinding, container_lbinding);

    const char *vif_chassis = smap_get(&parent_lbinding->pb->options,
                                       "requested-chassis");
    bool can_bind = can_bind_on_this_chassis(b_ctx_in->chassis_rec,
                                             vif_chassis);

    consider_vif_lport_(pb, can_bind, vif_chassis, b_ctx_in, b_ctx_out,
                        container_lbinding, qos_map);
}

static void
consider_virtual_lport(const struct sbrec_port_binding *pb,
                       struct binding_ctx_in *b_ctx_in,
                       struct binding_ctx_out *b_ctx_out,
                       struct hmap *qos_map)
{
    struct local_binding * parent_lbinding =
        pb->virtual_parent ? local_binding_find(b_ctx_out->local_bindings,
                                                pb->virtual_parent)
        : NULL;

    if (parent_lbinding && !parent_lbinding->pb) {
        parent_lbinding->pb = lport_lookup_by_name(
            b_ctx_in->sbrec_port_binding_by_name, pb->virtual_parent);

        if (parent_lbinding->pb) {
            /* Its possible that the parent lport is not considered yet.
             * So call consider_vif_lport() to process it first. */
            consider_vif_lport(parent_lbinding->pb, b_ctx_in, b_ctx_out,
                               parent_lbinding, qos_map);
        }
    }

    struct local_binding *virtual_lbinding = NULL;
    if (is_lbinding_this_chassis(parent_lbinding, b_ctx_in->chassis_rec)) {
        virtual_lbinding =
            local_binding_find_child(parent_lbinding, pb->logical_port);
        ovs_assert(!virtual_lbinding);
        virtual_lbinding = local_binding_create(pb->logical_port,
                                                parent_lbinding->iface,
                                                pb, BT_VIRTUAL);
        local_binding_add_child(parent_lbinding, virtual_lbinding);
    }

    return consider_vif_lport_(pb, true, NULL, b_ctx_in, b_ctx_out,
                               virtual_lbinding, qos_map);
}

/* Considers either claiming the lport or releasing the lport
 * for non VIF lports.
 */
static void
consider_nonvif_lport_(const struct sbrec_port_binding *pb,
                       bool our_chassis,
                       bool has_local_l3gateway,
                       struct binding_ctx_in *b_ctx_in,
                       struct binding_ctx_out *b_ctx_out)
{
    ovs_assert(b_ctx_in->ovnsb_idl_txn);
    if (our_chassis) {
        sset_add(b_ctx_out->local_lports, pb->logical_port);
        add_local_datapath(b_ctx_in->sbrec_datapath_binding_by_key,
                           b_ctx_in->sbrec_port_binding_by_datapath,
                           b_ctx_in->sbrec_port_binding_by_name,
                           pb->datapath, has_local_l3gateway,
                           b_ctx_out->local_datapaths);

        update_local_lport_ids(b_ctx_out->local_lport_ids, pb);
        claim_lport(pb, b_ctx_in->chassis_rec, NULL);
    } else if (pb->chassis == b_ctx_in->chassis_rec) {
        release_lport(pb);
    }
}

static void
consider_l2gw_lport(const struct sbrec_port_binding *pb,
                    struct binding_ctx_in *b_ctx_in,
                    struct binding_ctx_out *b_ctx_out)
{
    const char *chassis_id = smap_get(&pb->options, "l2gateway-chassis");
    bool our_chassis = chassis_id && !strcmp(chassis_id,
                                             b_ctx_in->chassis_rec->name);

    consider_nonvif_lport_(pb, our_chassis, false, b_ctx_in, b_ctx_out);
}

static void
consider_l3gw_lport(const struct sbrec_port_binding *pb,
                    struct binding_ctx_in *b_ctx_in,
                    struct binding_ctx_out *b_ctx_out)
{
    const char *chassis_id = smap_get(&pb->options, "l3gateway-chassis");
    bool our_chassis = chassis_id && !strcmp(chassis_id,
                                             b_ctx_in->chassis_rec->name);

    consider_nonvif_lport_(pb, our_chassis, true, b_ctx_in, b_ctx_out);
}

static void
consider_localnet_lport(const struct sbrec_port_binding *pb,
                        struct binding_ctx_in *b_ctx_in,
                        struct binding_ctx_out *b_ctx_out,
                        struct hmap *qos_map)
{
    /* Add all localnet ports to local_lports so that we allocate ct zones
     * for them. */
    sset_add(b_ctx_out->local_lports, pb->logical_port);
    if (qos_map && b_ctx_in->ovs_idl_txn) {
        get_qos_params(pb, qos_map);
    }

    update_local_lport_ids(b_ctx_out->local_lport_ids, pb);
}

static void
consider_ha_lport(const struct sbrec_port_binding *pb,
                  struct binding_ctx_in *b_ctx_in,
                  struct binding_ctx_out *b_ctx_out)
{
    bool our_chassis = false;
    bool is_ha_chassis = ha_chassis_group_contains(pb->ha_chassis_group,
                                                   b_ctx_in->chassis_rec);
    our_chassis = is_ha_chassis &&
                  ha_chassis_group_is_active(pb->ha_chassis_group,
                                             b_ctx_in->active_tunnels,
                                             b_ctx_in->chassis_rec);

    if (is_ha_chassis && !our_chassis) {
        /* If the chassis_rec is part of ha_chassis_group associated with
         * the port_binding 'pb', we need to add to the local_datapath
         * in even if its not active.
         *
         * If the chassis is active, consider_nonvif_lport_() takes care
         * of adding the datapath of this 'pb' to local datapaths.
         * */
        add_local_datapath(b_ctx_in->sbrec_datapath_binding_by_key,
                           b_ctx_in->sbrec_port_binding_by_datapath,
                           b_ctx_in->sbrec_port_binding_by_name,
                           pb->datapath, false,
                           b_ctx_out->local_datapaths);
    }

    consider_nonvif_lport_(pb, our_chassis, false, b_ctx_in, b_ctx_out);
}

static void
consider_cr_lport(const struct sbrec_port_binding *pb,
                  struct binding_ctx_in *b_ctx_in,
                  struct binding_ctx_out *b_ctx_out)
{
    consider_ha_lport(pb, b_ctx_in, b_ctx_out);
}

static void
consider_external_lport(const struct sbrec_port_binding *pb,
                        struct binding_ctx_in *b_ctx_in,
                        struct binding_ctx_out *b_ctx_out)
{
    return consider_ha_lport(pb, b_ctx_in, b_ctx_out);
}

/*
 * Builds local_bindings from the OVS interfaces.
 */
static void
build_local_bindings(struct binding_ctx_in *b_ctx_in,
                     struct binding_ctx_out *b_ctx_out)
{
    int i;
    for (i = 0; i < b_ctx_in->br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = b_ctx_in->br_int->ports[i];
        const char *iface_id;
        int j;

        if (!strcmp(port_rec->name, b_ctx_in->br_int->name)) {
            continue;
        }

        for (j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;

            iface_rec = port_rec->interfaces[j];
            iface_id = smap_get(&iface_rec->external_ids, "iface-id");
            int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;

            if (iface_id && ofport > 0) {
                struct local_binding *lbinding =
                    local_binding_find(b_ctx_out->local_bindings, iface_id);
                if (!lbinding) {
                    lbinding = local_binding_create(iface_id, iface_rec, NULL,
                                                    BT_VIF);
                    local_binding_add(b_ctx_out->local_bindings, lbinding);
                } else {
                    static struct vlog_rate_limit rl =
                        VLOG_RATE_LIMIT_INIT(1, 5);
                    VLOG_WARN_RL(
                        &rl,
                        "Invalid configuration: iface-id is configured on "
                        "interfaces : [%s] and [%s]. Ignoring the "
                        "configuration on interface [%s]",
                        lbinding->iface->name, iface_rec->name,
                        iface_rec->name);
                    ovs_assert(lbinding->type == BT_VIF);
                }

                sset_add(b_ctx_out->local_lports, iface_id);
            }

            /* Check if this is a tunnel interface. */
            if (smap_get(&iface_rec->options, "remote_ip")) {
                const char *tunnel_iface
                    = smap_get(&iface_rec->status, "tunnel_egress_iface");
                if (tunnel_iface) {
                    sset_add(b_ctx_out->egress_ifaces, tunnel_iface);
                }
            }
        }
    }
}

void
binding_run(struct binding_ctx_in *b_ctx_in, struct binding_ctx_out *b_ctx_out)
{
    if (!b_ctx_in->chassis_rec) {
        return;
    }

    struct shash bridge_mappings = SHASH_INITIALIZER(&bridge_mappings);
    struct hmap qos_map;

    hmap_init(&qos_map);
    if (b_ctx_in->br_int) {
        build_local_bindings(b_ctx_in, b_ctx_out);
    }

    struct hmap *qos_map_ptr =
        !sset_is_empty(b_ctx_out->egress_ifaces) ? &qos_map : NULL;

    struct ovs_list localnet_lports = OVS_LIST_INITIALIZER(&localnet_lports);

    struct localnet_lport {
        struct ovs_list list_node;
        const struct sbrec_port_binding *pb;
    };

    /* Run through each binding record to see if it is resident on this
     * chassis and update the binding accordingly.  This includes both
     * directly connected logical ports and children of those ports
     * (which also includes virtual ports).
     */
    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (pb,
                                       b_ctx_in->port_binding_table) {
        enum en_lport_type lport_type = get_lport_type(pb);

        switch (lport_type) {
        case LP_PATCH:
        case LP_LOCALPORT:
        case LP_VTEP:
            update_local_lport_ids(b_ctx_out->local_lport_ids, pb);
            break;

        case LP_VIF:
            if (is_lport_container(pb)) {
                consider_container_lport(pb, b_ctx_in, b_ctx_out, qos_map_ptr);
            } else {
                consider_vif_lport(pb, b_ctx_in, b_ctx_out, NULL, qos_map_ptr);
            }
            break;

        case LP_VIRTUAL:
            consider_virtual_lport(pb, b_ctx_in, b_ctx_out, qos_map_ptr);
            break;

        case LP_L2GATEWAY:
            consider_l2gw_lport(pb, b_ctx_in, b_ctx_out);
            break;

        case LP_L3GATEWAY:
            consider_l3gw_lport(pb, b_ctx_in, b_ctx_out);
            break;

        case LP_CHASSISREDIRECT:
            consider_cr_lport(pb, b_ctx_in, b_ctx_out);
            break;

        case LP_EXTERNAL:
            consider_external_lport(pb, b_ctx_in, b_ctx_out);
            break;

        case LP_LOCALNET: {
            consider_localnet_lport(pb, b_ctx_in, b_ctx_out, qos_map_ptr);
            struct localnet_lport *lnet_lport = xmalloc(sizeof *lnet_lport);
            lnet_lport->pb = pb;
            ovs_list_push_back(&localnet_lports, &lnet_lport->list_node);
            break;
        }

        case LP_REMOTE:
            /* Nothing to be done for REMOTE type. */
            break;

        case LP_UNKNOWN: {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl,
                         "Unknown port binding type [%s] for port binding "
                         "[%s]. Does the ovn-controller need an update ?",
                         pb->type, pb->logical_port);
            break;
        }
        }
    }

    add_ovs_bridge_mappings(b_ctx_in->ovs_table, b_ctx_in->bridge_table,
                            &bridge_mappings);

    /* Run through each localnet lport list to see if it is a localnet port
     * on local datapaths discovered from above loop, and update the
     * corresponding local datapath accordingly. */
    struct localnet_lport *lnet_lport;
    LIST_FOR_EACH_POP (lnet_lport, list_node, &localnet_lports) {
        consider_localnet_port(lnet_lport->pb, &bridge_mappings,
                               b_ctx_out->egress_ifaces,
                               b_ctx_out->local_datapaths);
        free(lnet_lport);
    }

    shash_destroy(&bridge_mappings);

    if (!sset_is_empty(b_ctx_out->egress_ifaces)
        && set_noop_qos(b_ctx_in->ovs_idl_txn, b_ctx_in->port_table,
                        b_ctx_in->qos_table, b_ctx_out->egress_ifaces)) {
        const char *entry;
        SSET_FOR_EACH (entry, b_ctx_out->egress_ifaces) {
            setup_qos(entry, &qos_map);
        }
    }

    destroy_qos_map(&qos_map);
}

/* Returns true if port-binding changes potentially require flow changes on
 * the current chassis. Returns false if we are sure there is no impact. */
bool
binding_evaluate_port_binding_changes(struct binding_ctx_in *b_ctx_in,
                                      struct binding_ctx_out *b_ctx_out)
{
    if (!b_ctx_in->chassis_rec) {
        return true;
    }

    bool changed = false;

    const struct sbrec_port_binding *binding_rec;
    SBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (binding_rec,
                                               b_ctx_in->port_binding_table) {
        /* XXX: currently OVSDB change tracking doesn't support getting old
         * data when the operation is update, so if a port-binding moved from
         * this chassis to another, there is no easy way to find out the
         * change. To workaround this problem, we just makes sure if
         * any port *related to* this chassis has any change, then trigger
         * recompute.
         *
         * - If a regular VIF is unbound from this chassis, the local ovsdb
         *   interface table will be updated, which will trigger recompute.
         *
         * - If the port is not a regular VIF, always trigger recompute. */
        if (binding_rec->chassis == b_ctx_in->chassis_rec) {
            changed = true;
            break;
        }

        if (!strcmp(binding_rec->type, "remote")) {
            continue;
        }

        if (strcmp(binding_rec->type, "")) {
            changed = true;
            break;
        }

        struct local_binding *lbinding = NULL;
        if (!binding_rec->parent_port || !binding_rec->parent_port[0]) {
            lbinding = local_binding_find(b_ctx_out->local_bindings,
                                          binding_rec->logical_port);
        } else {
            lbinding = local_binding_find(b_ctx_out->local_bindings,
                                          binding_rec->parent_port);
        }

        if (lbinding) {
            changed = true;
            break;
        }
    }

    return changed;
}

/* Returns true if the database is all cleaned up, false if more work is
 * required. */
bool
binding_cleanup(struct ovsdb_idl_txn *ovnsb_idl_txn,
                const struct sbrec_port_binding_table *port_binding_table,
                const struct sbrec_chassis *chassis_rec)
{
    if (!ovnsb_idl_txn) {
        return false;
    }
    if (!chassis_rec) {
        return true;
    }

    const struct sbrec_port_binding *binding_rec;
    bool any_changes = false;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (binding_rec, port_binding_table) {
        if (binding_rec->chassis == chassis_rec) {
            if (binding_rec->encap)
                sbrec_port_binding_set_encap(binding_rec, NULL);
            sbrec_port_binding_set_chassis(binding_rec, NULL);
            any_changes = true;
        }
    }

    if (any_changes) {
        ovsdb_idl_txn_add_comment(
            ovnsb_idl_txn,
            "ovn-controller: removing all port bindings for '%s'",
            chassis_rec->name);
    }

    return !any_changes;
}
