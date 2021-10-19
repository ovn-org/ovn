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

/* OVS includes. */
#include "lib/bitmap.h"
#include "openvswitch/poll-loop.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "lib/netdev.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "binding.h"
#include "ha-chassis.h"
#include "if-status.h"
#include "lflow.h"
#include "lib/chassis-index.h"
#include "lib/ovn-sb-idl.h"
#include "local_data.h"
#include "lport.h"
#include "ovn-controller.h"
#include "patch.h"

VLOG_DEFINE_THIS_MODULE(binding);

/* External ID to be set in the OVS.Interface record when the OVS interface
 * is ready for use, i.e., is bound to an OVN port and its corresponding
 * flows have been installed.
 */
#define OVN_INSTALLED_EXT_ID "ovn-installed"
#define OVN_INSTALLED_TS_EXT_ID "ovn-installed-ts"

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

static void update_lport_tracking(const struct sbrec_port_binding *pb,
                                  struct hmap *tracked_dp_bindings,
                                  bool claimed);

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
update_ld_external_ports(const struct sbrec_port_binding *binding_rec,
                         struct hmap *local_datapaths)
{
    struct local_datapath *ld = get_local_datapath(
        local_datapaths, binding_rec->datapath->tunnel_key);
    if (ld) {
        shash_replace(&ld->external_ports, binding_rec->logical_port,
                      binding_rec);
    }
}

static void
update_ld_localnet_port(const struct sbrec_port_binding *binding_rec,
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

/* Add an interface ID (usually taken from port_binding->name or
 * ovs_interface->external_ids:iface-id) to the set of local lports.
 * Also track if the set has changed.
 */
static void
update_local_lports(const char *iface_id, struct binding_ctx_out *b_ctx)
{
    if (sset_add(b_ctx->local_lports, iface_id) != NULL) {
        b_ctx->local_lports_changed = true;
    }
}

/* Remove an interface ID from the set of local lports. Also track if the
 * set has changed.
 */
static void
remove_local_lports(const char *iface_id, struct binding_ctx_out *b_ctx)
{
    if (sset_find_and_delete(b_ctx->local_lports, iface_id)) {
        b_ctx->local_lports_changed = true;
    }
}

/* Add a port binding to the set of locally relevant lports.
 * Also track if the set has changed.
 */
static void
update_related_lport(const struct sbrec_port_binding *pb,
                     struct binding_ctx_out *b_ctx)
{
    char buf[16];
    get_unique_lport_key(pb->datapath->tunnel_key, pb->tunnel_key,
                         buf, sizeof(buf));
    if (sset_add(&b_ctx->related_lports->lport_ids, buf) != NULL) {
        b_ctx->related_lports_changed = true;

        if (b_ctx->tracked_dp_bindings) {
            /* Add the 'pb' to the tracked_datapaths. */
            tracked_datapath_lport_add(pb, TRACKED_RESOURCE_NEW,
                                       b_ctx->tracked_dp_bindings);
        }
    }
    sset_add(&b_ctx->related_lports->lport_names, pb->logical_port);
}

/* Remove a port binding id from the set of locally relevant lports.
 * Also track if the set has changed.
 */
static void
remove_related_lport(const struct sbrec_port_binding *pb,
                     struct binding_ctx_out *b_ctx)
{
    char buf[16];
    get_unique_lport_key(pb->datapath->tunnel_key, pb->tunnel_key,
                         buf, sizeof(buf));
    sset_find_and_delete(&b_ctx->related_lports->lport_names,
                         pb->logical_port);
    if (sset_find_and_delete(&b_ctx->related_lports->lport_ids, buf)) {
        b_ctx->related_lports_changed = true;

        if (b_ctx->tracked_dp_bindings) {
            /* Add the 'pb' to the tracked_datapaths. */
            tracked_datapath_lport_add(pb, TRACKED_RESOURCE_REMOVED,
                                       b_ctx->tracked_dp_bindings);
        }
    }
}

static void
update_active_pb_ras_pd(const struct sbrec_port_binding *pb,
                        struct hmap *local_datapaths,
                        struct shash *map, const char *conf)
{
    bool ras_pd_conf = smap_get_bool(&pb->options, conf, false);
    struct shash_node *iter = shash_find(map, pb->logical_port);
    struct pb_ld_binding *ras_pd = iter ? iter->data : NULL;

    if (iter && !ras_pd_conf) {
        shash_delete(map, iter);
        free(ras_pd);
        return;
    }
    if (ras_pd_conf) {
        if (!ras_pd) {
            ras_pd = xzalloc(sizeof *ras_pd);
            ras_pd->pb = pb;
            shash_add(map, pb->logical_port, ras_pd);
        }
        ovs_assert(ras_pd);
        ras_pd->ld = get_local_datapath(local_datapaths,
                                        pb->datapath->tunnel_key);
    }
}

/* This structure represents a logical port (or port binding)
 * which is associated with 'struct local_binding'.
 *
 * An instance of 'struct binding_lport' is created for a logical port
 *  - If the OVS interface's iface-id corresponds to the logical port.
 *  - If it is a container or virtual logical port and its parent
 *    has a 'local binding'.
 *
 */
struct binding_lport {
    struct ovs_list list_node; /* Node in local_binding.binding_lports. */

    char *name;
    const struct sbrec_port_binding *pb;
    struct local_binding *lbinding;
    enum en_lport_type type;
};

static struct local_binding *local_binding_create(
    const char *name, const struct ovsrec_interface *);
static void local_binding_add(struct shash *local_bindings,
                              struct local_binding *);
static void local_binding_destroy(struct local_binding *,
                                  struct shash *binding_lports);
static void local_binding_delete(struct local_binding *,
                                 struct shash *local_bindings,
                                 struct shash *binding_lports,
                                 struct if_status_mgr *if_mgr);
static struct binding_lport *local_binding_add_lport(
    struct shash *binding_lports,
    struct local_binding *,
    const struct sbrec_port_binding *,
    enum en_lport_type);
static struct binding_lport *local_binding_get_primary_lport(
    struct local_binding *);
static struct binding_lport *local_binding_get_first_lport(
    struct local_binding *lbinding);
static struct binding_lport *local_binding_get_primary_or_localport_lport(
    struct local_binding *lbinding);

static bool local_binding_handle_stale_binding_lports(
    struct local_binding *lbinding, struct binding_ctx_in *b_ctx_in,
    struct binding_ctx_out *b_ctx_out, struct hmap *qos_map);

static struct binding_lport *binding_lport_create(
    const struct sbrec_port_binding *,
    struct local_binding *, enum en_lport_type);
static void binding_lport_destroy(struct binding_lport *);
static void binding_lport_delete(struct shash *binding_lports,
                                 struct binding_lport *);
static void binding_lport_add(struct shash *binding_lports,
                              struct binding_lport *);
static void binding_lport_set_up(struct binding_lport *, bool sb_readonly);
static void binding_lport_set_down(struct binding_lport *, bool sb_readonly);
static struct binding_lport *binding_lport_find(
    struct shash *binding_lports, const char *lport_name);
static const struct sbrec_port_binding *binding_lport_get_parent_pb(
    struct binding_lport *b_lprt);
static struct binding_lport *binding_lport_check_and_cleanup(
    struct binding_lport *, struct shash *b_lports);

static char *get_lport_type_str(enum en_lport_type lport_type);
static bool ovs_iface_matches_lport_iface_id_ver(
    const struct ovsrec_interface *,
    const struct sbrec_port_binding *);

void
related_lports_init(struct related_lports *rp)
{
    sset_init(&rp->lport_names);
    sset_init(&rp->lport_ids);
}

void
related_lports_destroy(struct related_lports *rp)
{
    sset_destroy(&rp->lport_names);
    sset_destroy(&rp->lport_ids);
}

void
local_binding_data_init(struct local_binding_data *lbinding_data)
{
    shash_init(&lbinding_data->bindings);
    shash_init(&lbinding_data->lports);
}

void
local_binding_data_destroy(struct local_binding_data *lbinding_data)
{
    struct shash_node *node, *next;

    SHASH_FOR_EACH_SAFE (node, next, &lbinding_data->lports) {
        struct binding_lport *b_lport = node->data;
        binding_lport_destroy(b_lport);
        shash_delete(&lbinding_data->lports, node);
    }

    SHASH_FOR_EACH_SAFE (node, next, &lbinding_data->bindings) {
        struct local_binding *lbinding = node->data;
        local_binding_destroy(lbinding, &lbinding_data->lports);
        shash_delete(&lbinding_data->bindings, node);
    }

    shash_destroy(&lbinding_data->lports);
    shash_destroy(&lbinding_data->bindings);
}

const struct sbrec_port_binding *
local_binding_get_primary_pb(struct shash *local_bindings,
                             const char *pb_name)
{
    struct local_binding *lbinding =
        local_binding_find(local_bindings, pb_name);
    struct binding_lport *b_lport = local_binding_get_primary_lport(lbinding);

    return b_lport ? b_lport->pb : NULL;
}

ofp_port_t
local_binding_get_lport_ofport(const struct shash *local_bindings,
                               const char *pb_name)
{
    struct local_binding *lbinding =
        local_binding_find(local_bindings, pb_name);
    struct binding_lport *b_lport =
        local_binding_get_primary_or_localport_lport(lbinding);

    return (b_lport && lbinding->iface && lbinding->iface->n_ofport) ?
            u16_to_ofp(lbinding->iface->ofport[0]) : 0;
}

bool
local_binding_is_up(struct shash *local_bindings, const char *pb_name)
{
    struct local_binding *lbinding =
        local_binding_find(local_bindings, pb_name);
    struct binding_lport *b_lport = local_binding_get_primary_lport(lbinding);
    if (lbinding && b_lport && lbinding->iface) {
        if (b_lport->pb->n_up && !b_lport->pb->up[0]) {
            return false;
        }
        return smap_get_bool(&lbinding->iface->external_ids,
                             OVN_INSTALLED_EXT_ID, false);
    }
    return false;
}

bool
local_binding_is_down(struct shash *local_bindings, const char *pb_name)
{
    struct local_binding *lbinding =
        local_binding_find(local_bindings, pb_name);

    struct binding_lport *b_lport = local_binding_get_primary_lport(lbinding);

    if (!lbinding) {
        return true;
    }

    if (lbinding->iface && smap_get_bool(&lbinding->iface->external_ids,
                                         OVN_INSTALLED_EXT_ID, false)) {
        return false;
    }

    if (b_lport && b_lport->pb->n_up && b_lport->pb->up[0]) {
        return false;
    }

    return true;
}

void
local_binding_set_up(struct shash *local_bindings, const char *pb_name,
                     const char *ts_now_str, bool sb_readonly,
                     bool ovs_readonly)
{
    struct local_binding *lbinding =
        local_binding_find(local_bindings, pb_name);
    struct binding_lport *b_lport = local_binding_get_primary_lport(lbinding);

    if (!ovs_readonly && lbinding && lbinding->iface
            && !smap_get_bool(&lbinding->iface->external_ids,
                              OVN_INSTALLED_EXT_ID, false)) {
        VLOG_INFO("Setting lport %s ovn-installed in OVS", pb_name);
        ovsrec_interface_update_external_ids_setkey(lbinding->iface,
                                                    OVN_INSTALLED_EXT_ID,
                                                    "true");
        ovsrec_interface_update_external_ids_setkey(lbinding->iface,
                                                    OVN_INSTALLED_TS_EXT_ID,
                                                    ts_now_str);
    }

    if (!sb_readonly && lbinding && b_lport && b_lport->pb->n_up
            && !b_lport->pb->up[0]) {
        VLOG_INFO("Setting lport %s up in Southbound", pb_name);
        binding_lport_set_up(b_lport, sb_readonly);
        LIST_FOR_EACH (b_lport, list_node, &lbinding->binding_lports) {
            binding_lport_set_up(b_lport, sb_readonly);
        }
    }
}

void
local_binding_set_down(struct shash *local_bindings, const char *pb_name,
                       bool sb_readonly, bool ovs_readonly)
{
    struct local_binding *lbinding =
        local_binding_find(local_bindings, pb_name);
    struct binding_lport *b_lport = local_binding_get_primary_lport(lbinding);

    if (!ovs_readonly && lbinding && lbinding->iface
            && smap_get_bool(&lbinding->iface->external_ids,
                             OVN_INSTALLED_EXT_ID, false)) {
        VLOG_INFO("Removing lport %s ovn-installed in OVS", pb_name);
        ovsrec_interface_update_external_ids_delkey(lbinding->iface,
                                                    OVN_INSTALLED_EXT_ID);
    }

    if (!sb_readonly && b_lport && b_lport->pb->n_up && b_lport->pb->up[0]) {
        VLOG_INFO("Setting lport %s down in Southbound", pb_name);
        binding_lport_set_down(b_lport, sb_readonly);
        LIST_FOR_EACH (b_lport, list_node, &lbinding->binding_lports) {
            binding_lport_set_down(b_lport, sb_readonly);
        }
    }
}

void
binding_dump_local_bindings(struct local_binding_data *lbinding_data,
                            struct ds *out_data)
{
    const struct shash_node **nodes;

    nodes = shash_sort(&lbinding_data->bindings);
    size_t n = shash_count(&lbinding_data->bindings);

    ds_put_cstr(out_data, "Local bindings:\n");
    for (size_t i = 0; i < n; i++) {
        const struct shash_node *node = nodes[i];
        struct local_binding *lbinding = node->data;
        size_t num_lports = ovs_list_size(&lbinding->binding_lports);
        ds_put_format(out_data, "name: [%s], OVS interface name : [%s], "
                      "num binding lports : [%"PRIuSIZE"]\n",
                      lbinding->name,
                      lbinding->iface ? lbinding->iface->name : "NULL",
                      num_lports);

        if (num_lports) {
            struct shash child_lports = SHASH_INITIALIZER(&child_lports);
            struct binding_lport *primary_lport = NULL;
            struct binding_lport *localport_lport = NULL;
            struct binding_lport *b_lport;
            bool first_elem = true;

            LIST_FOR_EACH (b_lport, list_node, &lbinding->binding_lports) {
                if (first_elem && b_lport->type == LP_VIF) {
                    primary_lport = b_lport;
                } else if (first_elem && b_lport->type == LP_LOCALPORT) {
                    localport_lport = b_lport;
                } else {
                    shash_add(&child_lports, b_lport->name, b_lport);
                }
                first_elem = false;
            }

            if (primary_lport) {
                ds_put_format(out_data, "primary lport : [%s]\n",
                              primary_lport->name);
            } else if (localport_lport) {
                ds_put_format(out_data, "localport lport : [%s]\n",
                              localport_lport->name);
            } else {
                ds_put_format(out_data, "no primary lport\n");
            }

            if (!shash_is_empty(&child_lports)) {
                const struct shash_node **c_nodes =
                    shash_sort(&child_lports);
                for (size_t j = 0; j < shash_count(&child_lports); j++) {
                    b_lport = c_nodes[j]->data;
                    ds_put_format(out_data, "child lport[%"PRIuSIZE"] : [%s], "
                                  "type : [%s]\n", j + 1, b_lport->name,
                                  get_lport_type_str(b_lport->type));
                }
                free(c_nodes);
            }
            shash_destroy(&child_lports);
        }

        ds_put_cstr(out_data, "----------------------------------------\n");
    }

    free(nodes);
}

static bool
is_lport_vif(const struct sbrec_port_binding *pb)
{
    return !pb->type[0];
}

enum en_lport_type
get_lport_type(const struct sbrec_port_binding *pb)
{
    if (is_lport_vif(pb)) {
        if (pb->parent_port && pb->parent_port[0]) {
            return LP_CONTAINER;
        }
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

static char *
get_lport_type_str(enum en_lport_type lport_type)
{
    switch (lport_type) {
    case LP_VIF:
        return "VIF";
    case LP_CONTAINER:
        return "CONTAINER";
    case LP_VIRTUAL:
        return "VIRTUAL";
    case LP_PATCH:
        return "PATCH";
    case LP_CHASSISREDIRECT:
        return "CHASSISREDIRECT";
    case LP_L3GATEWAY:
        return "L3GATEWAT";
    case LP_LOCALNET:
        return "PATCH";
    case LP_LOCALPORT:
        return "LOCALPORT";
    case LP_L2GATEWAY:
        return "L2GATEWAY";
    case LP_EXTERNAL:
        return "EXTERNAL";
    case LP_REMOTE:
        return "REMOTE";
    case LP_VTEP:
        return "VTEP";
    case LP_UNKNOWN:
        return "UNKNOWN";
    }

    OVS_NOT_REACHED();
}

/* For newly claimed ports, if 'notify_up' is 'false':
 * - set the 'pb.up' field to true if 'pb' has no 'parent_pb'.
 * - set the 'pb.up' field to true if 'parent_pb.up' is 'true' (e.g., for
 *   container and virtual ports).
 * Otherwise request a notification to be sent when the OVS flows
 * corresponding to 'pb' have been installed.
 *
 * Note:
 *   Updates (directly or through a notification) the 'pb->up' field only if
 *   it's explicitly set to 'false'.
 *   This is to ensure compatibility with older versions of ovn-northd.
 */
static void
claimed_lport_set_up(const struct sbrec_port_binding *pb,
                     const struct sbrec_port_binding *parent_pb,
                     const struct sbrec_chassis *chassis_rec,
                     bool notify_up, struct if_status_mgr *if_mgr)
{
    if (!notify_up) {
        bool up = true;
        if (!parent_pb || (parent_pb->n_up && parent_pb->up[0])) {
            sbrec_port_binding_set_up(pb, &up, 1);
        }
        return;
    }

    if (pb->chassis != chassis_rec || (pb->n_up && !pb->up[0])) {
        if_status_mgr_claim_iface(if_mgr, pb->logical_port);
    }
}

/* Returns false if lport is not claimed due to 'sb_readonly'.
 * Returns true otherwise.
 */
static bool
claim_lport(const struct sbrec_port_binding *pb,
            const struct sbrec_port_binding *parent_pb,
            const struct sbrec_chassis *chassis_rec,
            const struct ovsrec_interface *iface_rec,
            bool sb_readonly, bool notify_up,
            struct hmap *tracked_datapaths,
            struct if_status_mgr *if_mgr)
{
    if (!sb_readonly) {
        claimed_lport_set_up(pb, parent_pb, chassis_rec, notify_up, if_mgr);
    }

    if (pb->chassis != chassis_rec) {
        if (sb_readonly) {
            return false;
        }

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

        if (tracked_datapaths) {
            update_lport_tracking(pb, tracked_datapaths, true);
        }
    }

    /* Check if the port encap binding, if any, has changed */
    struct sbrec_encap *encap_rec =
        sbrec_get_port_encap(chassis_rec, iface_rec);
    if (encap_rec && pb->encap != encap_rec) {
        if (sb_readonly) {
            return false;
        }
        sbrec_port_binding_set_encap(pb, encap_rec);
    }

    return true;
}

/* Returns false if lport is not released due to 'sb_readonly'.
 * Returns true otherwise.
 *
 * This function assumes that the the 'pb' was claimed
 * earlier i.e port binding's chassis is set to this chassis.
 * Caller should make sure that this is the case.
 */
static bool
release_lport_(const struct sbrec_port_binding *pb, bool sb_readonly)
{
    if (pb->encap) {
        if (sb_readonly) {
            return false;
        }
        sbrec_port_binding_set_encap(pb, NULL);
    }

    if (pb->chassis) {
        if (sb_readonly) {
            return false;
        }
        sbrec_port_binding_set_chassis(pb, NULL);
    }

    if (pb->virtual_parent) {
        if (sb_readonly) {
            return false;
        }
        sbrec_port_binding_set_virtual_parent(pb, NULL);
    }

    VLOG_INFO("Releasing lport %s from this chassis.", pb->logical_port);
    return true;
}

static bool
release_lport(const struct sbrec_port_binding *pb, bool sb_readonly,
              struct hmap *tracked_datapaths, struct if_status_mgr *if_mgr)
{
    if (!release_lport_(pb, sb_readonly)) {
        return false;
    }

    update_lport_tracking(pb, tracked_datapaths, false);
    if_status_mgr_release_iface(if_mgr, pb->logical_port);
    return true;
}

static bool
is_lbinding_set(struct local_binding *lbinding)
{
    return lbinding && lbinding->iface;
}

static bool
is_binding_lport_this_chassis(struct binding_lport *b_lport,
                              const struct sbrec_chassis *chassis)
{
    return (b_lport && b_lport->pb && chassis &&
            b_lport->pb->chassis == chassis);
}

/* Returns 'true' if the 'lbinding' has binding lports of type LP_CONTAINER,
 * 'false' otherwise. */
static bool
is_lbinding_container_parent(struct local_binding *lbinding)
{
    struct binding_lport *b_lport;
    LIST_FOR_EACH (b_lport, list_node, &lbinding->binding_lports) {
        if (b_lport->type == LP_CONTAINER) {
            return true;
        }
    }

    return false;
}

static bool
release_binding_lport(const struct sbrec_chassis *chassis_rec,
                      struct binding_lport *b_lport, bool sb_readonly,
                      struct binding_ctx_out *b_ctx_out)
{
    if (is_binding_lport_this_chassis(b_lport, chassis_rec)) {
        remove_related_lport(b_lport->pb, b_ctx_out);
        if (!release_lport(b_lport->pb, sb_readonly,
                           b_ctx_out->tracked_dp_bindings,
                           b_ctx_out->if_mgr)) {
            return false;
        }
        binding_lport_set_down(b_lport, sb_readonly);
    }

    return true;
}

static bool
consider_vif_lport_(const struct sbrec_port_binding *pb,
                    bool can_bind,
                    struct binding_ctx_in *b_ctx_in,
                    struct binding_ctx_out *b_ctx_out,
                    struct binding_lport *b_lport,
                    struct hmap *qos_map)
{
    bool lbinding_set = b_lport && is_lbinding_set(b_lport->lbinding);

    if (lbinding_set) {
        if (can_bind) {
            /* We can claim the lport. */
            const struct sbrec_port_binding *parent_pb =
                binding_lport_get_parent_pb(b_lport);

            if (!claim_lport(pb, parent_pb, b_ctx_in->chassis_rec,
                             b_lport->lbinding->iface,
                             !b_ctx_in->ovnsb_idl_txn,
                             !parent_pb, b_ctx_out->tracked_dp_bindings,
                             b_ctx_out->if_mgr)){
                return false;
            }

            add_local_datapath(b_ctx_in->sbrec_datapath_binding_by_key,
                               b_ctx_in->sbrec_port_binding_by_datapath,
                               b_ctx_in->sbrec_port_binding_by_name,
                               pb->datapath, b_ctx_in->chassis_rec,
                               b_ctx_out->local_datapaths,
                               b_ctx_out->tracked_dp_bindings);
            update_related_lport(pb, b_ctx_out);
            update_local_lports(pb->logical_port, b_ctx_out);
            if (b_lport->lbinding->iface && qos_map && b_ctx_in->ovs_idl_txn) {
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
                             pb->requested_chassis ?
                             pb->requested_chassis->name : "(option points at "
                                                           "non-existent "
                                                           "chassis)");
        }
    }

    if (pb->chassis == b_ctx_in->chassis_rec) {
        /* Release the lport if there is no lbinding. */
        if (!lbinding_set || !can_bind) {
            return release_lport(pb, !b_ctx_in->ovnsb_idl_txn,
                                 b_ctx_out->tracked_dp_bindings,
                                 b_ctx_out->if_mgr);
        }
    }

    return true;
}

static bool
consider_vif_lport(const struct sbrec_port_binding *pb,
                   struct binding_ctx_in *b_ctx_in,
                   struct binding_ctx_out *b_ctx_out,
                   struct local_binding *lbinding,
                   struct hmap *qos_map)
{
    bool can_bind = lport_can_bind_on_this_chassis(b_ctx_in->chassis_rec, pb);

    if (!lbinding) {
        lbinding = local_binding_find(&b_ctx_out->lbinding_data->bindings,
                                      pb->logical_port);
    }

    struct binding_lport *b_lport = NULL;
    if (lbinding) {
        /* Make sure that the pb's iface-id-ver if set matches with the
         * lbinding ovs iface's iface-id-ver. */
        if (lbinding->iface &&
                !ovs_iface_matches_lport_iface_id_ver(lbinding->iface, pb)) {
            /* We can't associate the b_lport for this local_binding
             * because the iface-id-ver doesn't match.  Check if there is
             * a primary lport for this lbinding.  If so, delete it. */
            b_lport = local_binding_get_primary_lport(lbinding);
            if (b_lport) {
                binding_lport_delete(&b_ctx_out->lbinding_data->lports,
                                     b_lport);
                b_lport = NULL;
            }
        } else {
            struct shash *binding_lports =
                &b_ctx_out->lbinding_data->lports;
            b_lport = local_binding_add_lport(binding_lports, lbinding, pb,
                                              LP_VIF);
        }
    }

    return consider_vif_lport_(pb, can_bind, b_ctx_in, b_ctx_out,
                               b_lport, qos_map);
}

static bool
consider_container_lport(const struct sbrec_port_binding *pb,
                         struct binding_ctx_in *b_ctx_in,
                         struct binding_ctx_out *b_ctx_out,
                         struct hmap *qos_map)
{
    struct shash *local_bindings = &b_ctx_out->lbinding_data->bindings;
    struct local_binding *parent_lbinding;
    parent_lbinding = local_binding_find(local_bindings, pb->parent_port);

    if (!parent_lbinding) {
        /* There is no local_binding for parent port. Create it
         * without OVS interface row. This is the only exception
         * for creating the 'struct local_binding' object without
         * corresponding OVS interface row.
         *
         * This is required for the following reasons:
         *   - If a logical port P1 is created and then
         *     few container ports - C1, C2, .. are created first by CMS.
         *   - And later when OVS interface row  is created for P1, then
         *     we want the these container ports also be claimed by the
         *     chassis.
         * */
        parent_lbinding = local_binding_create(pb->parent_port, NULL);
        local_binding_add(local_bindings, parent_lbinding);
    }

    struct shash *binding_lports = &b_ctx_out->lbinding_data->lports;
    struct binding_lport *b_lport =
        binding_lport_find(binding_lports, pb->logical_port);

    if (b_lport && b_lport->lbinding != parent_lbinding) {
        /* The container lport's parent has changed.  So remove it from
         * the related_lports so that it is tracked. */
        remove_related_lport(b_lport->pb, b_ctx_out);
    }

    struct binding_lport *container_b_lport =
        local_binding_add_lport(binding_lports, parent_lbinding, pb,
                                LP_CONTAINER);

    struct binding_lport *parent_b_lport =
        binding_lport_find(binding_lports, pb->parent_port);

    bool can_consider_c_lport = true;
    if (!parent_b_lport || !parent_b_lport->pb) {
        const struct sbrec_port_binding *parent_pb = lport_lookup_by_name(
            b_ctx_in->sbrec_port_binding_by_name, pb->parent_port);

        if (parent_pb && get_lport_type(parent_pb) == LP_VIF) {
            /* Its possible that the parent lport is not considered yet.
             * So call consider_vif_lport() to process it first. */
            consider_vif_lport(parent_pb, b_ctx_in, b_ctx_out,
                               parent_lbinding, qos_map);
            parent_b_lport = binding_lport_find(binding_lports,
                                                pb->parent_port);
        } else {
            /* The parent lport doesn't exist.  Cannot consider the container
             * lport for binding. */
            can_consider_c_lport = false;
        }
    }

    if (parent_b_lport && parent_b_lport->type != LP_VIF) {
        can_consider_c_lport = false;
    }

    if (!can_consider_c_lport) {
        /* Call release_lport() to release the container lport,
         * if it was bound earlier. */
        if (is_binding_lport_this_chassis(container_b_lport,
                                          b_ctx_in->chassis_rec)) {
            return release_lport(pb, !b_ctx_in->ovnsb_idl_txn,
                                 b_ctx_out->tracked_dp_bindings,
                                 b_ctx_out->if_mgr);
        }

        return true;
    }

    ovs_assert(parent_b_lport && parent_b_lport->pb);
    bool can_bind = lport_can_bind_on_this_chassis(b_ctx_in->chassis_rec, pb);

    return consider_vif_lport_(pb, can_bind, b_ctx_in, b_ctx_out,
                               container_b_lport, qos_map);
}

static bool
consider_virtual_lport(const struct sbrec_port_binding *pb,
                       struct binding_ctx_in *b_ctx_in,
                       struct binding_ctx_out *b_ctx_out,
                       struct hmap *qos_map)
{
    struct shash *local_bindings = &b_ctx_out->lbinding_data->bindings;
    struct local_binding *parent_lbinding =
        pb->virtual_parent ? local_binding_find(local_bindings,
                                                pb->virtual_parent)
        : NULL;

    struct binding_lport *virtual_b_lport = NULL;
    /* Unlike container lports, we don't have to create parent_lbinding if
     * it is NULL. This is because, if parent_lbinding is not present, it
     * means the virtual port can't bind in this chassis.
     * Note: pinctrl module binds the virtual lport when it sees ARP
     * packet from the parent lport. */
    if (parent_lbinding) {
        struct shash *binding_lports = &b_ctx_out->lbinding_data->lports;

        struct binding_lport *parent_b_lport =
            binding_lport_find(binding_lports, pb->virtual_parent);

        if (!parent_b_lport || !parent_b_lport->pb) {
            const struct sbrec_port_binding *parent_pb = lport_lookup_by_name(
                b_ctx_in->sbrec_port_binding_by_name, pb->virtual_parent);

            if (parent_pb && get_lport_type(parent_pb) == LP_VIF) {
                /* Its possible that the parent lport is not considered yet.
                 * So call consider_vif_lport() to process it first. */
                consider_vif_lport(parent_pb, b_ctx_in, b_ctx_out,
                                   parent_lbinding, qos_map);
            }
        }

        parent_b_lport = local_binding_get_primary_lport(parent_lbinding);
        if (is_binding_lport_this_chassis(parent_b_lport,
                                          b_ctx_in->chassis_rec)) {
            virtual_b_lport =
                local_binding_add_lport(binding_lports, parent_lbinding, pb,
                                        LP_VIRTUAL);
        }
    }

    if (!consider_vif_lport_(pb, true, b_ctx_in, b_ctx_out,
                             virtual_b_lport, qos_map)) {
        return false;
    }

    /* If the virtual lport is not bound to this chassis, then remove
     * its entry from the local_lport_ids if present.  This is required
     * when a virtual port moves from one chassis to other.*/
    if (!virtual_b_lport) {
        remove_related_lport(pb, b_ctx_out);
    }

    return true;
}

static bool
consider_localport(const struct sbrec_port_binding *pb,
                   struct binding_ctx_in *b_ctx_in,
                   struct binding_ctx_out *b_ctx_out)
{
    struct shash *local_bindings = &b_ctx_out->lbinding_data->bindings;
    struct local_binding *lbinding = local_binding_find(local_bindings,
                                                        pb->logical_port);

    if (!lbinding) {
        return true;
    }

    local_binding_add_lport(&b_ctx_out->lbinding_data->lports, lbinding, pb,
                            LP_LOCALPORT);

    /* If the port binding is claimed, then release it as localport is claimed
     * by any ovn-controller. */
    if (pb->chassis == b_ctx_in->chassis_rec) {
        if (!release_lport_(pb, !b_ctx_in->ovnsb_idl_txn)) {
            return false;
        }

        remove_related_lport(pb, b_ctx_out);
    }

    update_related_lport(pb, b_ctx_out);
    return true;
}

/* Considers either claiming the lport or releasing the lport
 * for non VIF lports.
 */
static bool
consider_nonvif_lport_(const struct sbrec_port_binding *pb,
                       bool our_chassis,
                       struct binding_ctx_in *b_ctx_in,
                       struct binding_ctx_out *b_ctx_out)
{
    if (our_chassis) {
        update_local_lports(pb->logical_port, b_ctx_out);
        add_local_datapath(b_ctx_in->sbrec_datapath_binding_by_key,
                           b_ctx_in->sbrec_port_binding_by_datapath,
                           b_ctx_in->sbrec_port_binding_by_name,
                           pb->datapath, b_ctx_in->chassis_rec,
                           b_ctx_out->local_datapaths,
                           b_ctx_out->tracked_dp_bindings);

        update_related_lport(pb, b_ctx_out);
        return claim_lport(pb, NULL, b_ctx_in->chassis_rec, NULL,
                           !b_ctx_in->ovnsb_idl_txn, false,
                           b_ctx_out->tracked_dp_bindings,
                           b_ctx_out->if_mgr);
    } else if (pb->chassis == b_ctx_in->chassis_rec) {
        return release_lport(pb, !b_ctx_in->ovnsb_idl_txn,
                             b_ctx_out->tracked_dp_bindings,
                             b_ctx_out->if_mgr);
    }

    return true;
}

static bool
consider_l2gw_lport(const struct sbrec_port_binding *pb,
                    struct binding_ctx_in *b_ctx_in,
                    struct binding_ctx_out *b_ctx_out)
{
    const char *chassis_id = smap_get(&pb->options, "l2gateway-chassis");
    bool our_chassis = chassis_id && !strcmp(chassis_id,
                                             b_ctx_in->chassis_rec->name);

    return consider_nonvif_lport_(pb, our_chassis, b_ctx_in, b_ctx_out);
}

static bool
consider_l3gw_lport(const struct sbrec_port_binding *pb,
                    struct binding_ctx_in *b_ctx_in,
                    struct binding_ctx_out *b_ctx_out)
{
    const char *chassis_id = smap_get(&pb->options, "l3gateway-chassis");
    bool our_chassis = chassis_id && !strcmp(chassis_id,
                                             b_ctx_in->chassis_rec->name);

    return consider_nonvif_lport_(pb, our_chassis, b_ctx_in, b_ctx_out);
}

static void
consider_localnet_lport(const struct sbrec_port_binding *pb,
                        struct binding_ctx_in *b_ctx_in,
                        struct binding_ctx_out *b_ctx_out,
                        struct hmap *qos_map)
{
    /* Add all localnet ports to local_ifaces so that we allocate ct zones
     * for them. */
    update_local_lports(pb->logical_port, b_ctx_out);

    if (qos_map && b_ctx_in->ovs_idl_txn) {
        get_qos_params(pb, qos_map);
    }

    update_related_lport(pb, b_ctx_out);
}

static bool
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
                           pb->datapath, b_ctx_in->chassis_rec,
                           b_ctx_out->local_datapaths,
                           b_ctx_out->tracked_dp_bindings);
        update_related_lport(pb, b_ctx_out);
    }

    return consider_nonvif_lport_(pb, our_chassis, b_ctx_in, b_ctx_out);
}

static bool
consider_cr_lport(const struct sbrec_port_binding *pb,
                  struct binding_ctx_in *b_ctx_in,
                  struct binding_ctx_out *b_ctx_out)
{
    return consider_ha_lport(pb, b_ctx_in, b_ctx_out);
}

static bool
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

        struct shash *local_bindings =
            &b_ctx_out->lbinding_data->bindings;
        for (j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;

            iface_rec = port_rec->interfaces[j];
            iface_id = smap_get(&iface_rec->external_ids, "iface-id");
            int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;

            if (iface_id && ofport > 0) {
                struct local_binding *lbinding =
                    local_binding_find(local_bindings, iface_id);
                if (!lbinding) {
                    lbinding = local_binding_create(iface_id, iface_rec);
                    local_binding_add(local_bindings, lbinding);
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
                }

                update_local_lports(iface_id, b_ctx_out);
                smap_replace(b_ctx_out->local_iface_ids, iface_rec->name,
                             iface_id);
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
    struct ovs_list external_lports = OVS_LIST_INITIALIZER(&external_lports);

    struct lport {
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
        update_active_pb_ras_pd(pb, b_ctx_out->local_datapaths,
                                b_ctx_out->local_active_ports_ipv6_pd,
                                "ipv6_prefix_delegation");
        update_active_pb_ras_pd(pb, b_ctx_out->local_datapaths,
                                b_ctx_out->local_active_ports_ras,
                                "ipv6_ra_send_periodic");

        enum en_lport_type lport_type = get_lport_type(pb);

        switch (lport_type) {
        case LP_PATCH:
        case LP_VTEP:
            update_related_lport(pb, b_ctx_out);
            break;

        case LP_LOCALPORT:
            consider_localport(pb, b_ctx_in, b_ctx_out);
            break;

        case LP_VIF:
            consider_vif_lport(pb, b_ctx_in, b_ctx_out, NULL, qos_map_ptr);
            break;

        case LP_CONTAINER:
            consider_container_lport(pb, b_ctx_in, b_ctx_out, qos_map_ptr);
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
            struct lport *ext_lport = xmalloc(sizeof *ext_lport);
            ext_lport->pb = pb;
            ovs_list_push_back(&external_lports, &ext_lport->list_node);
            break;

        case LP_LOCALNET: {
            consider_localnet_lport(pb, b_ctx_in, b_ctx_out, &qos_map);
            struct lport *lnet_lport = xmalloc(sizeof *lnet_lport);
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
    struct lport *lnet_lport;
    LIST_FOR_EACH_POP (lnet_lport, list_node, &localnet_lports) {
        update_ld_localnet_port(lnet_lport->pb, &bridge_mappings,
                                b_ctx_out->egress_ifaces,
                                b_ctx_out->local_datapaths);
        free(lnet_lport);
    }

    /* Run through external lport list to see if these are external ports
     * on local datapaths discovered from above loop, and update the
     * corresponding local datapath accordingly. */
    struct lport *ext_lport;
    LIST_FOR_EACH_POP (ext_lport, list_node, &external_lports) {
        update_ld_external_ports(ext_lport->pb, b_ctx_out->local_datapaths);
        free(ext_lport);
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
            if (binding_rec->encap) {
                sbrec_port_binding_set_encap(binding_rec, NULL);
            }
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

static void
remove_pb_from_local_datapath(const struct sbrec_port_binding *pb,
                              struct binding_ctx_out *b_ctx_out,
                              struct local_datapath *ld)
{
    remove_related_lport(pb, b_ctx_out);
    if (!strcmp(pb->type, "patch") ||
        !strcmp(pb->type, "l3gateway")) {
        remove_local_datapath_peer_port(pb, ld, b_ctx_out->local_datapaths);
    } else if (!strcmp(pb->type, "localnet")) {
        if (ld->localnet_port && !strcmp(ld->localnet_port->logical_port,
                                         pb->logical_port)) {
            ld->localnet_port = NULL;
        }
    } else if (!strcmp(pb->type, "external")) {
        shash_find_and_delete(&ld->external_ports, pb->logical_port);
    }
}

static void
update_lport_tracking(const struct sbrec_port_binding *pb,
                      struct hmap *tracked_dp_bindings,
                      bool claimed)
{
    if (!tracked_dp_bindings) {
        return;
    }

    tracked_datapath_lport_add(
        pb, claimed ? TRACKED_RESOURCE_NEW : TRACKED_RESOURCE_REMOVED,
        tracked_dp_bindings);
}

/* Considers the ovs iface 'iface_rec' for claiming.
 * This function should be called if the external_ids:iface-id
 * and 'ofport' are set for the 'iface_rec'.
 *
 * If the local_binding for this 'iface_rec' already exists and its
 * already claimed, then this function will be no-op.
 */
static bool
consider_iface_claim(const struct ovsrec_interface *iface_rec,
                     const char *iface_id,
                     struct binding_ctx_in *b_ctx_in,
                     struct binding_ctx_out *b_ctx_out,
                     struct hmap *qos_map)
{
    update_local_lports(iface_id, b_ctx_out);
    smap_replace(b_ctx_out->local_iface_ids, iface_rec->name, iface_id);

    struct shash *local_bindings = &b_ctx_out->lbinding_data->bindings;
    struct local_binding *lbinding = local_binding_find(local_bindings,
                                                        iface_id);

    if (!lbinding) {
        lbinding = local_binding_create(iface_id, iface_rec);
        local_binding_add(local_bindings, lbinding);
    } else {
        lbinding->iface = iface_rec;
    }

    struct binding_lport *b_lport =
        local_binding_get_primary_or_localport_lport(lbinding);
    const struct sbrec_port_binding *pb = NULL;
    if (!b_lport) {
        pb = lport_lookup_by_name(b_ctx_in->sbrec_port_binding_by_name,
                                  lbinding->name);
    } else {
        pb = b_lport->pb;
    }

    if (!pb) {
        /* There is no port_binding row for this local binding. */
        return true;
    }

    enum en_lport_type lport_type = get_lport_type(pb);
    if (lport_type == LP_LOCALPORT) {
        return consider_localport(pb, b_ctx_in, b_ctx_out);
    }

    if (lport_type == LP_VIF &&
        !consider_vif_lport(pb, b_ctx_in, b_ctx_out, lbinding, qos_map)) {
        return false;
    }

    /* Get the (updated) b_lport again for the lbinding. */
    b_lport = local_binding_get_primary_lport(lbinding);

    /* Update the child local_binding's iface (if any children) and try to
     *  claim the container lbindings. */
    LIST_FOR_EACH (b_lport, list_node, &lbinding->binding_lports) {
        if (b_lport->type == LP_CONTAINER) {
            if (!consider_container_lport(b_lport->pb, b_ctx_in, b_ctx_out,
                                          qos_map)) {
                return false;
            }
        }
    }

    return true;
}

/* Considers the ovs interface 'iface_rec' for
 * releasing from this chassis if local_binding for this
 * 'iface_rec' (with 'iface_id' as key) already exists and
 * it is claimed by the chassis.
 *
 * The 'iface_id' could be cleared from the 'iface_rec'
 * and hence it is passed separately.
 *
 * This fuction should be called if
 *   - OVS interface 'iface_rec' is deleted.
 *   - OVS interface 'iface_rec' external_ids:iface-id is updated
 *     (with the old value being 'iface_id'.)
 *   - OVS interface ofport is reset to 0.
 * */
static bool
consider_iface_release(const struct ovsrec_interface *iface_rec,
                       const char *iface_id,
                       struct binding_ctx_in *b_ctx_in,
                       struct binding_ctx_out *b_ctx_out)
{
    struct local_binding *lbinding;
    struct shash *local_bindings = &b_ctx_out->lbinding_data->bindings;
    struct shash *binding_lports = &b_ctx_out->lbinding_data->lports;

    lbinding = local_binding_find(local_bindings, iface_id);
    struct binding_lport *b_lport =
        local_binding_get_primary_or_localport_lport(lbinding);
    if (is_binding_lport_this_chassis(b_lport, b_ctx_in->chassis_rec)) {
        struct local_datapath *ld =
            get_local_datapath(b_ctx_out->local_datapaths,
                               b_lport->pb->datapath->tunnel_key);
        if (ld) {
            remove_pb_from_local_datapath(b_lport->pb,
                                          b_ctx_out, ld);
        }

        /* Release the primary binding lport and other children lports if
         * any. */
        LIST_FOR_EACH (b_lport, list_node, &lbinding->binding_lports) {
            if (!release_binding_lport(b_ctx_in->chassis_rec, b_lport,
                                       !b_ctx_in->ovnsb_idl_txn,
                                       b_ctx_out)) {
                return false;
            }
        }

    } else if (lbinding && b_lport && b_lport->type == LP_LOCALPORT) {
        /* lbinding is associated with a localport.  Remove it from the
         * related lports. */
        remove_related_lport(b_lport->pb, b_ctx_out);
    }

    if (lbinding) {
        /* Clear the iface of the local binding. */
        lbinding->iface = NULL;
    }

    /* Check if the lbinding has children of type PB_CONTAINER.
     * If so, don't delete the local_binding. */
    if (lbinding && !is_lbinding_container_parent(lbinding)) {
        local_binding_delete(lbinding, local_bindings, binding_lports,
                             b_ctx_out->if_mgr);
    }

    remove_local_lports(iface_id, b_ctx_out);
    smap_remove(b_ctx_out->local_iface_ids, iface_rec->name);

    return true;
}

static bool
is_iface_vif(const struct ovsrec_interface *iface_rec)
{
    if (iface_rec->type && iface_rec->type[0] &&
        strcmp(iface_rec->type, "internal")) {
        return false;
    }

    return true;
}

static bool
is_iface_in_int_bridge(const struct ovsrec_interface *iface,
                       const struct ovsrec_bridge *br_int)
{
    for (size_t i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *p = br_int->ports[i];
        for (size_t j = 0; j < p->n_interfaces; j++) {
            if (!strcmp(iface->name, p->interfaces[j]->name)) {
                return true;
            }
        }
    }
    return false;
}

/* Returns true if the ovs interface changes were handled successfully,
 * false otherwise.
 */
bool
binding_handle_ovs_interface_changes(struct binding_ctx_in *b_ctx_in,
                                     struct binding_ctx_out *b_ctx_out)
{
    if (!b_ctx_in->chassis_rec) {
        return false;
    }

    bool handled = true;

    /* Run the tracked interfaces loop twice. One to handle deleted
     * changes. And another to handle add/update changes.
     * This will ensure correctness.
     *     *
     * We consider an OVS interface for release if one of the following
     * happens:
     *   1. OVS interface is deleted.
     *   2. external_ids:iface-id is cleared in which case we need to
     *      release the port binding corresponding to the previously set
     *      'old-iface-id' (which is stored in the smap
     *      'b_ctx_out->local_iface_ids').
     *   3. external_ids:iface-id is updated with a different value
     *      in which case we need to release the port binding corresponding
     *      to the previously set 'old-iface-id' (which is stored in the smap
     *      'b_ctx_out->local_iface_ids').
     *   4. ofport of the OVS interface is 0.
     *
     */
    const struct ovsrec_interface *iface_rec;
    OVSREC_INTERFACE_TABLE_FOR_EACH_TRACKED (iface_rec,
                                             b_ctx_in->iface_table) {
        if (!is_iface_vif(iface_rec)) {
            /* Right now we are not handling ovs_interface changes of
             * other types. This can be enhanced to handle of
             * types - patch and tunnel. */
            handled = false;
            break;
        }

        if (smap_get(&iface_rec->external_ids, "ovn-egress-iface") ||
            sset_contains(b_ctx_out->egress_ifaces, iface_rec->name)) {
            handled = false;
            break;
        }

        const char *iface_id = smap_get(&iface_rec->external_ids, "iface-id");
        const char *old_iface_id = smap_get(b_ctx_out->local_iface_ids,
                                            iface_rec->name);
        const char *cleared_iface_id = NULL;
        if (!ovsrec_interface_is_deleted(iface_rec)) {
            int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;
            if (iface_id) {
                /* Check if iface_id is changed. If so we need to
                 * release the old port binding and associate this
                 * inteface to new port binding. */
                if (old_iface_id && strcmp(iface_id, old_iface_id)) {
                    cleared_iface_id = old_iface_id;
                } else if (ofport <= 0) {
                    /* If ofport is <= 0, we need to release the iface if
                     * already claimed. */
                    cleared_iface_id = iface_id;
                }
            } else if (old_iface_id) {
                cleared_iface_id = old_iface_id;
            }
        } else {
            cleared_iface_id = iface_id;
        }

        if (cleared_iface_id) {
            handled = consider_iface_release(iface_rec, cleared_iface_id,
                                             b_ctx_in, b_ctx_out);
        }

        if (!handled) {
            break;
        }
    }

    if (!handled) {
        /* This can happen if any non vif OVS interface is in the tracked
         * list or if consider_iface_release() returned false.
         * There is no need to process further. */
        return false;
    }

    struct hmap qos_map = HMAP_INITIALIZER(&qos_map);
    struct hmap *qos_map_ptr =
        sset_is_empty(b_ctx_out->egress_ifaces) ? NULL : &qos_map;

    /*
     * We consider an OVS interface for claiming if the following
     * 2 conditions are met:
     *   1. external_ids:iface-id is set.
     *   2. ofport of the OVS interface is > 0.
     *
     * So when an update of an OVS interface happens we see if these
     * conditions are still true. If so consider this interface for
     * claiming. This would be no-op if the update of the OVS interface
     * didn't change the above two fields.
     */
    OVSREC_INTERFACE_TABLE_FOR_EACH_TRACKED (iface_rec,
                                             b_ctx_in->iface_table) {
        /* Loop to handle create and update changes only. */
        if (ovsrec_interface_is_deleted(iface_rec)) {
            continue;
        }

        const char *iface_id = smap_get(&iface_rec->external_ids, "iface-id");
        int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;
        if (iface_id && ofport > 0 &&
                is_iface_in_int_bridge(iface_rec, b_ctx_in->br_int)) {
            handled = consider_iface_claim(iface_rec, iface_id, b_ctx_in,
                                           b_ctx_out, qos_map_ptr);
            if (!handled) {
                break;
            }
        }
    }

    if (handled && qos_map_ptr && set_noop_qos(b_ctx_in->ovs_idl_txn,
                                               b_ctx_in->port_table,
                                               b_ctx_in->qos_table,
                                               b_ctx_out->egress_ifaces)) {
        const char *entry;
        SSET_FOR_EACH (entry, b_ctx_out->egress_ifaces) {
            setup_qos(entry, &qos_map);
        }
    }

    destroy_qos_map(&qos_map);
    return handled;
}

static void
handle_deleted_lport(const struct sbrec_port_binding *pb,
                     struct binding_ctx_in *b_ctx_in,
                     struct binding_ctx_out *b_ctx_out)
{
    /* If the binding is local, remove it. */
    struct local_datapath *ld =
        get_local_datapath(b_ctx_out->local_datapaths,
                           pb->datapath->tunnel_key);
    if (ld) {
        remove_pb_from_local_datapath(pb,
                                      b_ctx_out, ld);
        return;
    }

    /* If the binding is not local, if 'pb' is a L3 gateway port, we should
     * remove its peer, if that one is local.
     */
    pb = lport_get_l3gw_peer(pb, b_ctx_in->sbrec_port_binding_by_name);
    if (pb) {
        ld = get_local_datapath(b_ctx_out->local_datapaths,
                                pb->datapath->tunnel_key);
        if (ld) {
            remove_pb_from_local_datapath(pb, b_ctx_out,
                                          ld);
        }
    }
}

static bool
handle_deleted_vif_lport(const struct sbrec_port_binding *pb,
                         enum en_lport_type lport_type,
                         struct binding_ctx_in *b_ctx_in,
                         struct binding_ctx_out *b_ctx_out)
{
    struct local_binding *lbinding = NULL;
    bool bound = false;

    struct shash *binding_lports = &b_ctx_out->lbinding_data->lports;
    struct binding_lport *b_lport = binding_lport_find(binding_lports, pb->logical_port);
    if (b_lport) {
        lbinding = b_lport->lbinding;
        bound = is_binding_lport_this_chassis(b_lport, b_ctx_in->chassis_rec);

         /* Remove b_lport from local_binding. */
         binding_lport_delete(binding_lports, b_lport);
    }

    if (bound && lbinding && lport_type == LP_VIF) {
        /* We need to release the container/virtual binding lports (if any) if
         * deleted 'pb' type is LP_VIF. */
        struct binding_lport *c_lport;
        LIST_FOR_EACH (c_lport, list_node, &lbinding->binding_lports) {
            if (!release_binding_lport(b_ctx_in->chassis_rec, c_lport,
                                       !b_ctx_in->ovnsb_idl_txn,
                                       b_ctx_out)) {
                return false;
            }
        }
    }

    /* If its a container lport, then delete its entry from local_lports
     * if present.
     * Note: If a normal lport is deleted, we don't want to remove
     * it from local_lports if there is a VIF entry.
     * consider_iface_release() takes care of removing from the local_lports
     * when the interface change happens. */
    if (lport_type == LP_CONTAINER) {
        remove_local_lports(pb->logical_port, b_ctx_out);
    }

    handle_deleted_lport(pb, b_ctx_in, b_ctx_out);
    return true;
}

static bool
handle_updated_vif_lport(const struct sbrec_port_binding *pb,
                         enum en_lport_type lport_type,
                         struct binding_ctx_in *b_ctx_in,
                         struct binding_ctx_out *b_ctx_out,
                         struct hmap *qos_map)
{
    bool claimed = (pb->chassis == b_ctx_in->chassis_rec);
    bool handled = true;

    if (lport_type == LP_VIRTUAL) {
        handled = consider_virtual_lport(pb, b_ctx_in, b_ctx_out, qos_map);
    } else if (lport_type == LP_CONTAINER) {
        handled = consider_container_lport(pb, b_ctx_in, b_ctx_out, qos_map);
    } else {
        handled = consider_vif_lport(pb, b_ctx_in, b_ctx_out, NULL, qos_map);
    }

    if (!handled) {
        return false;
    }

    bool now_claimed = (pb->chassis == b_ctx_in->chassis_rec);

    if (lport_type == LP_VIRTUAL || lport_type == LP_CONTAINER ||
            claimed == now_claimed) {
        return true;
    }

    struct shash *local_bindings = &b_ctx_out->lbinding_data->bindings;
    struct local_binding *lbinding = local_binding_find(local_bindings,
                                                        pb->logical_port);

    /* If the ovs port backing this binding previously was removed in the
     * meantime, we won't have a local_binding for it.
     */
    if (!lbinding) {
        ovs_assert(!now_claimed);
        return true;
    }

    struct binding_lport *b_lport;
    LIST_FOR_EACH (b_lport, list_node, &lbinding->binding_lports) {
        if (b_lport->type == LP_CONTAINER) {
            handled = consider_container_lport(b_lport->pb, b_ctx_in,
                                               b_ctx_out, qos_map);
            if (!handled) {
                return false;
            }
        }
    }

    return true;
}

static void
consider_patch_port_for_local_datapaths(const struct sbrec_port_binding *pb,
                                        struct binding_ctx_in *b_ctx_in,
                                        struct binding_ctx_out *b_ctx_out)
{
    struct local_datapath *ld =
        get_local_datapath(b_ctx_out->local_datapaths,
                           pb->datapath->tunnel_key);

    if (!ld) {
        /* If 'ld' for this lport is not present, then check if
         * there is a peer for this lport. If peer is present
         * and peer's datapath is already in the local datapaths,
         * then add this lport's datapath to the local_datapaths.
         * */
        const struct sbrec_port_binding *peer;
        struct local_datapath *peer_ld = NULL;
        peer = lport_get_peer(pb, b_ctx_in->sbrec_port_binding_by_name);
        if (peer) {
            peer_ld =
                get_local_datapath(b_ctx_out->local_datapaths,
                                   peer->datapath->tunnel_key);
        }
        if (peer_ld && need_add_patch_peer_to_local(
                b_ctx_in->sbrec_port_binding_by_name, peer,
                b_ctx_in->chassis_rec)) {
            add_local_datapath(
                b_ctx_in->sbrec_datapath_binding_by_key,
                b_ctx_in->sbrec_port_binding_by_datapath,
                b_ctx_in->sbrec_port_binding_by_name,
                pb->datapath, b_ctx_in->chassis_rec,
                b_ctx_out->local_datapaths,
                b_ctx_out->tracked_dp_bindings);
        }
    } else {
        /* Add the peer datapath to the local datapaths if it's
         * not present yet.
         */
        if (need_add_patch_peer_to_local(
                b_ctx_in->sbrec_port_binding_by_name, pb,
                b_ctx_in->chassis_rec)) {
            add_local_datapath_peer_port(
                pb, b_ctx_in->chassis_rec,
                b_ctx_in->sbrec_datapath_binding_by_key,
                b_ctx_in->sbrec_port_binding_by_datapath,
                b_ctx_in->sbrec_port_binding_by_name,
                ld, b_ctx_out->local_datapaths,
                b_ctx_out->tracked_dp_bindings);
        }
    }
}

/* Returns true if the port binding changes resulted in local binding
 * updates, false otherwise.
 */
bool
binding_handle_port_binding_changes(struct binding_ctx_in *b_ctx_in,
                                    struct binding_ctx_out *b_ctx_out)
{
    /* Run the tracked port binding loop twice to ensure correctness:
     * 1. First to handle deleted changes.  This is split in four sub-parts
     *    because child local bindings must be cleaned up first:
     *    a. Container ports first.
     *    b. Then virtual ports.
     *    c. Then regular VIFs.
     *    d. Last other ports.
     * 2. Second to handle add/update changes.
     */
    struct shash deleted_container_pbs =
        SHASH_INITIALIZER(&deleted_container_pbs);
    struct shash deleted_virtual_pbs =
        SHASH_INITIALIZER(&deleted_virtual_pbs);
    struct shash deleted_vif_pbs =
        SHASH_INITIALIZER(&deleted_vif_pbs);
    struct shash deleted_localport_pbs =
        SHASH_INITIALIZER(&deleted_localport_pbs);
    struct shash deleted_other_pbs =
        SHASH_INITIALIZER(&deleted_other_pbs);
    const struct sbrec_port_binding *pb;
    bool handled = true;

    SBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (pb,
                                               b_ctx_in->port_binding_table) {
        if (!sbrec_port_binding_is_deleted(pb)) {
            continue;
        }

        enum en_lport_type lport_type = get_lport_type(pb);

        struct binding_lport *b_lport =
            binding_lport_find(&b_ctx_out->lbinding_data->lports,
                               pb->logical_port);
        if (b_lport) {
            /* If the 'b_lport->type' and 'lport_type' don't match, then update
             * the b_lport->type to the updated 'lport_type'.  The function
             * binding_lport_check_and_cleanup() will cleanup the 'b_lport'
             * if required. */
            if (b_lport->type != lport_type) {
                b_lport->type = lport_type;
            }
            b_lport = binding_lport_check_and_cleanup(
                b_lport, &b_ctx_out->lbinding_data->lports);
        }

        if (lport_type == LP_VIF) {
            shash_add(&deleted_vif_pbs, pb->logical_port, pb);
        } else if (lport_type == LP_CONTAINER) {
            shash_add(&deleted_container_pbs, pb->logical_port, pb);
        } else if (lport_type == LP_VIRTUAL) {
            shash_add(&deleted_virtual_pbs, pb->logical_port, pb);
        } else if (lport_type == LP_LOCALPORT) {
            shash_add(&deleted_localport_pbs, pb->logical_port, pb);
        } else {
            shash_add(&deleted_other_pbs, pb->logical_port, pb);
        }
    }

    struct shash_node *node;
    struct shash_node *node_next;
    SHASH_FOR_EACH_SAFE (node, node_next, &deleted_container_pbs) {
        handled = handle_deleted_vif_lport(node->data, LP_CONTAINER, b_ctx_in,
                                           b_ctx_out);
        shash_delete(&deleted_container_pbs, node);
        if (!handled) {
            goto delete_done;
        }
    }

    SHASH_FOR_EACH_SAFE (node, node_next, &deleted_virtual_pbs) {
        handled = handle_deleted_vif_lport(node->data, LP_VIRTUAL, b_ctx_in,
                                           b_ctx_out);
        shash_delete(&deleted_virtual_pbs, node);
        if (!handled) {
            goto delete_done;
        }
    }

    SHASH_FOR_EACH_SAFE (node, node_next, &deleted_vif_pbs) {
        handled = handle_deleted_vif_lport(node->data, LP_VIF, b_ctx_in,
                                           b_ctx_out);
        shash_delete(&deleted_vif_pbs, node);
        if (!handled) {
            goto delete_done;
        }
    }

    SHASH_FOR_EACH_SAFE (node, node_next, &deleted_localport_pbs) {
        handle_deleted_vif_lport(node->data, LP_LOCALPORT, b_ctx_in,
                                 b_ctx_out);
        shash_delete(&deleted_localport_pbs, node);
    }

    SHASH_FOR_EACH_SAFE (node, node_next, &deleted_other_pbs) {
        handle_deleted_lport(node->data, b_ctx_in, b_ctx_out);
        shash_delete(&deleted_other_pbs, node);
    }

delete_done:
    shash_destroy(&deleted_container_pbs);
    shash_destroy(&deleted_virtual_pbs);
    shash_destroy(&deleted_vif_pbs);
    shash_destroy(&deleted_localport_pbs);
    shash_destroy(&deleted_other_pbs);

    if (!handled) {
        return false;
    }

    struct hmap qos_map = HMAP_INITIALIZER(&qos_map);
    struct hmap *qos_map_ptr =
        sset_is_empty(b_ctx_out->egress_ifaces) ? NULL : &qos_map;

    SBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (pb,
                                               b_ctx_in->port_binding_table) {
        /* Loop to handle create and update changes only. */
        if (sbrec_port_binding_is_deleted(pb)) {
            continue;
        }

        update_active_pb_ras_pd(pb, b_ctx_out->local_datapaths,
                                b_ctx_out->local_active_ports_ipv6_pd,
                                "ipv6_prefix_delegation");

        update_active_pb_ras_pd(pb, b_ctx_out->local_datapaths,
                                b_ctx_out->local_active_ports_ras,
                                "ipv6_ra_send_periodic");

        enum en_lport_type lport_type = get_lport_type(pb);

        struct binding_lport *b_lport =
            binding_lport_find(&b_ctx_out->lbinding_data->lports,
                               pb->logical_port);
        if (b_lport) {
            ovs_assert(b_lport->pb == pb);

            if (b_lport->type != lport_type) {
                b_lport->type = lport_type;
            }

            if (b_lport->lbinding) {
                handled = local_binding_handle_stale_binding_lports(
                    b_lport->lbinding, b_ctx_in, b_ctx_out, qos_map_ptr);
                if (!handled) {
                    /* Backout from the handling. */
                    break;
                }
            }
        }

        switch (lport_type) {
        case LP_VIF:
        case LP_CONTAINER:
        case LP_VIRTUAL:
            handled = handle_updated_vif_lport(pb, lport_type, b_ctx_in,
                                               b_ctx_out, qos_map_ptr);
            break;

        case LP_LOCALPORT:
            handled = consider_localport(pb, b_ctx_in, b_ctx_out);
            break;

        case LP_PATCH:
            update_related_lport(pb, b_ctx_out);
            consider_patch_port_for_local_datapaths(pb, b_ctx_in, b_ctx_out);
            break;

        case LP_VTEP:
            update_related_lport(pb, b_ctx_out);
            /* VTEP lports are claimed/released by ovn-controller-vteps.
             * We are not sure what changed. */
            b_ctx_out->non_vif_ports_changed = true;
            break;

        case LP_L2GATEWAY:
            handled = consider_l2gw_lport(pb, b_ctx_in, b_ctx_out);
            break;

        case LP_L3GATEWAY:
            handled = consider_l3gw_lport(pb, b_ctx_in, b_ctx_out);
            break;

        case LP_CHASSISREDIRECT:
            handled = consider_cr_lport(pb, b_ctx_in, b_ctx_out);
            if (!handled) {
                break;
            }
            const char *distributed_port = smap_get(&pb->options,
                                                    "distributed-port");
            if (!distributed_port) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "No distributed-port option set for "
                             "chassisredirect port %s", pb->logical_port);
                break;
            }
            const struct sbrec_port_binding *distributed_pb
                = lport_lookup_by_name(b_ctx_in->sbrec_port_binding_by_name,
                                       distributed_port);
            if (!distributed_pb) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "No port binding record for distributed "
                             "port %s referred by chassisredirect port %s",
                             distributed_port, pb->logical_port);
                break;
            }
            consider_patch_port_for_local_datapaths(distributed_pb, b_ctx_in,
                                                    b_ctx_out);
            break;

        case LP_EXTERNAL:
            handled = consider_external_lport(pb, b_ctx_in, b_ctx_out);
            update_ld_external_ports(pb, b_ctx_out->local_datapaths);
            break;

        case LP_LOCALNET: {
            consider_localnet_lport(pb, b_ctx_in, b_ctx_out, qos_map_ptr);

            struct shash bridge_mappings =
                SHASH_INITIALIZER(&bridge_mappings);
            add_ovs_bridge_mappings(b_ctx_in->ovs_table,
                                    b_ctx_in->bridge_table,
                                    &bridge_mappings);
            update_ld_localnet_port(pb, &bridge_mappings,
                                    b_ctx_out->egress_ifaces,
                                    b_ctx_out->local_datapaths);
            shash_destroy(&bridge_mappings);
            break;
        }

        case LP_REMOTE:
        case LP_UNKNOWN:
            break;
        }

        if (!handled) {
            break;
        }
    }

    if (handled && qos_map_ptr && set_noop_qos(b_ctx_in->ovs_idl_txn,
                                               b_ctx_in->port_table,
                                               b_ctx_in->qos_table,
                                               b_ctx_out->egress_ifaces)) {
        const char *entry;
        SSET_FOR_EACH (entry, b_ctx_out->egress_ifaces) {
            setup_qos(entry, &qos_map);
        }
    }

    destroy_qos_map(&qos_map);
    return handled;
}

/* Static functions for local_lbindind and binding_lport. */
static struct local_binding *
local_binding_create(const char *name, const struct ovsrec_interface *iface)
{
    struct local_binding *lbinding = xzalloc(sizeof *lbinding);
    lbinding->name = xstrdup(name);
    lbinding->iface = iface;
    ovs_list_init(&lbinding->binding_lports);

    return lbinding;
}

struct local_binding *
local_binding_find(const struct shash *local_bindings, const char *name)
{
    return shash_find_data(local_bindings, name);
}

static void
local_binding_add(struct shash *local_bindings, struct local_binding *lbinding)
{
    shash_add(local_bindings, lbinding->name, lbinding);
}

static void
local_binding_destroy(struct local_binding *lbinding,
                      struct shash *binding_lports)
{
    struct binding_lport *b_lport;
    LIST_FOR_EACH_POP (b_lport, list_node, &lbinding->binding_lports) {
        b_lport->lbinding = NULL;
        binding_lport_delete(binding_lports, b_lport);
    }

    free(lbinding->name);
    free(lbinding);
}

static void
local_binding_delete(struct local_binding *lbinding,
                     struct shash *local_bindings,
                     struct shash *binding_lports,
                     struct if_status_mgr *if_mgr)
{
    shash_find_and_delete(local_bindings, lbinding->name);
    if_status_mgr_delete_iface(if_mgr, lbinding->name);
    local_binding_destroy(lbinding, binding_lports);
}

static struct binding_lport *
local_binding_get_first_lport(struct local_binding *lbinding)
{
    if (!lbinding) {
        return NULL;
    }

    if (!ovs_list_is_empty(&lbinding->binding_lports)) {
        struct binding_lport *b_lport = NULL;
        b_lport = CONTAINER_OF(ovs_list_front(&lbinding->binding_lports),
                               struct binding_lport, list_node);

        return b_lport;
    }

    return NULL;
}

/* Returns the primary binding lport if present in lbinding's
 * binding lports list.  A binding lport is considered primary
 * if binding lport's type is LP_VIF and the name matches
 * with the 'lbinding'.
 */
static struct binding_lport *
local_binding_get_primary_lport(struct local_binding *lbinding)
{
    if (!lbinding) {
        return NULL;
    }

    struct binding_lport *b_lport = local_binding_get_first_lport(lbinding);
    if (b_lport && b_lport->type == LP_VIF &&
            !strcmp(lbinding->name, b_lport->name)) {
        return b_lport;
    }

    return NULL;
}

static struct binding_lport *
local_binding_get_primary_or_localport_lport(struct local_binding *lbinding)
{
    if (!lbinding) {
        return NULL;
    }

    struct binding_lport *b_lport = local_binding_get_first_lport(lbinding);
    if (b_lport && (b_lport->type == LP_VIF || b_lport->type == LP_LOCALPORT)
            && !strcmp(lbinding->name, b_lport->name)) {
        return b_lport;
    }

    return NULL;
}

static struct binding_lport *
local_binding_add_lport(struct shash *binding_lports,
                        struct local_binding *lbinding,
                        const struct sbrec_port_binding *pb,
                        enum en_lport_type b_type)
{
    struct binding_lport *b_lport =
        binding_lport_find(binding_lports, pb->logical_port);
    bool add_to_lport_list = false;
    if (!b_lport) {
        b_lport = binding_lport_create(pb, lbinding, b_type);
        binding_lport_add(binding_lports, b_lport);
        add_to_lport_list = true;
    } else if (b_lport->lbinding != lbinding) {
        add_to_lport_list = true;
        if (!ovs_list_is_empty(&b_lport->list_node)) {
            ovs_list_remove(&b_lport->list_node);
        }
        b_lport->lbinding = lbinding;
        b_lport->type = b_type;
    }

    if (add_to_lport_list) {
        if (b_type == LP_VIF) {
            ovs_list_push_front(&lbinding->binding_lports, &b_lport->list_node);
        } else {
            ovs_list_push_back(&lbinding->binding_lports, &b_lport->list_node);
        }
    }

    return b_lport;
}

/* This function handles the stale binding lports of 'lbinding' if 'lbinding'
 * doesn't have a primary binding lport.
 */
static bool
local_binding_handle_stale_binding_lports(struct local_binding *lbinding,
                                          struct binding_ctx_in *b_ctx_in,
                                          struct binding_ctx_out *b_ctx_out,
                                          struct hmap *qos_map)
{
    /* Check if this lbinding has a primary binding_lport or
     * localport binding_lport or not. */
    struct binding_lport *p_lport =
        local_binding_get_primary_or_localport_lport(lbinding);
    if (p_lport) {
        /* Nothing to be done. */
        return true;
    }

    bool handled = true;
    struct binding_lport *b_lport, *next;
    const struct sbrec_port_binding *pb;
    LIST_FOR_EACH_SAFE (b_lport, next, list_node, &lbinding->binding_lports) {
        /* Get the lport type again from the pb.  Its possible that the
         * pb type has changed. */
        enum en_lport_type pb_lport_type = get_lport_type(b_lport->pb);
        if (b_lport->type == LP_VIRTUAL && pb_lport_type == LP_VIRTUAL) {
            pb = b_lport->pb;
            binding_lport_delete(&b_ctx_out->lbinding_data->lports,
                                 b_lport);
            handled = consider_virtual_lport(pb, b_ctx_in, b_ctx_out, qos_map);
        } else if (b_lport->type == LP_CONTAINER &&
                   pb_lport_type == LP_CONTAINER) {
            /* For container lport, binding_lport is preserved so that when
             * the parent port is created, it can be considered.
             * consider_container_lport() creates the binding_lport for the parent
             * port (with iface set to NULL). */
            handled = consider_container_lport(b_lport->pb, b_ctx_in, b_ctx_out, qos_map);
        } else {
            /* This can happen when the lport type changes from one type
             * to another. Eg. from normal lport to external.  Release the
             * lport if it was claimed earlier and delete the b_lport. */
            handled = release_binding_lport(b_ctx_in->chassis_rec, b_lport,
                                            !b_ctx_in->ovnsb_idl_txn,
                                            b_ctx_out);
            binding_lport_delete(&b_ctx_out->lbinding_data->lports,
                                 b_lport);
        }

        if (!handled) {
            return false;
        }
    }

    return handled;
}

static struct binding_lport *
binding_lport_create(const struct sbrec_port_binding *pb,
                     struct local_binding *lbinding,
                     enum en_lport_type type)
{
    struct binding_lport *b_lport = xzalloc(sizeof *b_lport);
    b_lport->name = xstrdup(pb->logical_port);
    b_lport->pb = pb;
    b_lport->type = type;
    b_lport->lbinding = lbinding;
    ovs_list_init(&b_lport->list_node);

    return b_lport;
}

static void
binding_lport_add(struct shash *binding_lports, struct binding_lport *b_lport)
{
    shash_add(binding_lports, b_lport->pb->logical_port, b_lport);
}

static struct binding_lport *
binding_lport_find(struct shash *binding_lports, const char *lport_name)
{
    if (!lport_name) {
        return NULL;
    }

    return shash_find_data(binding_lports, lport_name);
}

static void
binding_lport_destroy(struct binding_lport *b_lport)
{
    if (!ovs_list_is_empty(&b_lport->list_node)) {
        ovs_list_remove(&b_lport->list_node);
    }

    free(b_lport->name);
    free(b_lport);
}

static void
binding_lport_delete(struct shash *binding_lports,
                     struct binding_lport *b_lport)
{
    shash_find_and_delete(binding_lports, b_lport->name);
    binding_lport_destroy(b_lport);
}

static void
binding_lport_set_up(struct binding_lport *b_lport, bool sb_readonly)
{
    if (sb_readonly || !b_lport || !b_lport->pb->n_up || b_lport->pb->up[0]) {
        return;
    }

    bool up = true;
    sbrec_port_binding_set_up(b_lport->pb, &up, 1);
}

static void
binding_lport_set_down(struct binding_lport *b_lport, bool sb_readonly)
{
    if (sb_readonly || !b_lport || !b_lport->pb->n_up || !b_lport->pb->up[0]) {
        return;
    }

    bool up = false;
    sbrec_port_binding_set_up(b_lport->pb, &up, 1);
}

static const struct sbrec_port_binding *
binding_lport_get_parent_pb(struct binding_lport *b_lport)
{
    if (!b_lport) {
        return NULL;
    }

    if (b_lport->type == LP_VIF) {
        return NULL;
    }

    struct local_binding *lbinding = b_lport->lbinding;
    ovs_assert(lbinding);

    struct binding_lport *parent_b_lport =
        local_binding_get_primary_lport(lbinding);

    return parent_b_lport ? parent_b_lport->pb : NULL;
}

/* This function checks and cleans up the 'b_lport' if it is
 * not in the correct state.
 *
 * If the 'b_lport' type is LP_VIF, then its name and its lbinding->name
 * should match.  Otherwise this should be cleaned up.
 *
 * If the 'b_lport' type is LP_CONTAINER, then its parent_port name should
 * be the same as its lbinding's name.  Otherwise this should be
 * cleaned up.
 *
 * If the 'b_lport' type is LP_VIRTUAL, then its virtual parent name
 * should be the same as its lbinding's name.  Otherwise this
 * should be cleaned up.
 *
 * If the 'b_lport' type is not LP_VIF, LP_CONTAINER or LP_VIRTUAL, it
 * should be cleaned up.  This can happen if the CMS changes
 * the port binding type.
 */
static struct binding_lport *
binding_lport_check_and_cleanup(struct binding_lport *b_lport,
                                struct shash *binding_lports)
{
    bool cleanup_blport = false;

    if (!b_lport->lbinding) {
        cleanup_blport = true;
        goto cleanup;
    }

    switch (b_lport->type) {
    case LP_VIF:
    case LP_LOCALPORT:
        if (strcmp(b_lport->name, b_lport->lbinding->name)) {
            cleanup_blport = true;
        }
        break;

    case LP_CONTAINER:
        if (strcmp(b_lport->pb->parent_port, b_lport->lbinding->name)) {
            cleanup_blport = true;
        }
        break;

    case LP_VIRTUAL:
        if (!b_lport->pb->virtual_parent ||
            strcmp(b_lport->pb->virtual_parent, b_lport->lbinding->name)) {
            cleanup_blport = true;
        }
        break;

    case LP_PATCH:
    case LP_VTEP:
    case LP_L2GATEWAY:
    case LP_L3GATEWAY:
    case LP_CHASSISREDIRECT:
    case LP_EXTERNAL:
    case LP_LOCALNET:
    case LP_REMOTE:
    case LP_UNKNOWN:
        cleanup_blport = true;
    }

cleanup:
    if (cleanup_blport) {
        binding_lport_delete(binding_lports, b_lport);
        return NULL;
    }

    return b_lport;
}


static bool
ovs_iface_matches_lport_iface_id_ver(const struct ovsrec_interface *iface,
                                     const struct sbrec_port_binding *pb)
{
    const char *pb_iface_id_ver = smap_get(&pb->options, "iface-id-ver");

    if (pb_iface_id_ver) {
        const char *iface_id_ver = smap_get(&iface->external_ids,
                                            "iface-id-ver");
        if (!iface_id_ver || strcmp(pb_iface_id_ver, iface_id_ver)) {
            return false;
        }
    }

    return true;
}
