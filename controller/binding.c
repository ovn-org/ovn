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
#include "ovsport.h"

VLOG_DEFINE_THIS_MODULE(binding);

/* External ID to be set in the OVS.Interface record when the OVS interface
 * is ready for use, i.e., is bound to an OVN port and its corresponding
 * flows have been installed.
 */
#define OVN_INSTALLED_EXT_ID "ovn-installed"
#define OVN_INSTALLED_TS_EXT_ID "ovn-installed-ts"

#define OVN_QOS_TYPE "linux-htb"

#define CLAIM_TIME_THRESHOLD_MS 500

struct claimed_port {
    long long int last_claimed;
};

static struct shash _claimed_ports = SHASH_INITIALIZER(&_claimed_ports);
static struct sset _postponed_ports = SSET_INITIALIZER(&_postponed_ports);

static void
remove_additional_chassis(const struct sbrec_port_binding *pb,
                          const struct sbrec_chassis *chassis_rec);

struct sset *
get_postponed_ports(void)
{
    return &_postponed_ports;
}

static long long int
get_claim_timestamp(const char *port_name)
{
    struct claimed_port *cp = shash_find_data(&_claimed_ports, port_name);
    return cp ? cp->last_claimed : 0;
}

static void
register_claim_timestamp(const char *port_name, long long int t)
{
    struct claimed_port *cp = shash_find_data(&_claimed_ports, port_name);
    if (!cp) {
        cp = xzalloc(sizeof *cp);
        shash_add(&_claimed_ports, port_name, cp);
    }
    cp->last_claimed = t;
}

static void
cleanup_claimed_port_timestamps(void)
{
    long long int now = time_msec();
    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &_claimed_ports) {
        struct claimed_port *cp = (struct claimed_port *) node->data;
        if (now - cp->last_claimed >= 5 * CLAIM_TIME_THRESHOLD_MS) {
            free(cp);
            shash_delete(&_claimed_ports, node);
        }
    }
}

/* Schedule any pending binding work. Runs with in the main ovn-controller
 * thread context.*/
void
binding_wait(void)
{
    const char *port_name;
    SSET_FOR_EACH (port_name, &_postponed_ports) {
        long long int t = get_claim_timestamp(port_name);
        if (t) {
            poll_timer_wait_until(t + CLAIM_TIME_THRESHOLD_MS);
        }
    }
}

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

struct qos_queue {
    struct hmap_node node;

    char *network;
    char *port;

    uint32_t queue_id;
    unsigned long long min_rate;
    unsigned long long max_rate;
    unsigned long long burst;
};

static struct qos_queue *
find_qos_queue(struct hmap *queue_map, uint32_t hash, const char *port)
{
    struct qos_queue *q;
    HMAP_FOR_EACH_WITH_HASH (q, node, hash, queue_map) {
        if (!strcmp(q->port, port)) {
            return q;
        }
    }
    return NULL;
}

static void
qos_queue_erase_entry(struct qos_queue *q)
{
    free(q->network);
    free(q->port);
    free(q);
}

void
destroy_qos_map(struct hmap *qos_map)
{
    struct qos_queue *q;
    HMAP_FOR_EACH_POP (q, node, qos_map) {
        qos_queue_erase_entry(q);
    }
    hmap_destroy(qos_map);
}

static const struct ovsrec_interface *
get_qos_egress_port_interface(struct shash *bridge_mappings,
                              const struct ovsrec_port **pport,
                              const char *network)
{
    struct ovsrec_bridge *br_ln = shash_find_data(bridge_mappings, network);
    if (!br_ln) {
        return NULL;
    }

    /* Add egress-ifaces from the connected bridge */
    for (size_t i = 0; i < br_ln->n_ports; i++) {
        const struct ovsrec_port *port = br_ln->ports[i];
        for (size_t j = 0; j < port->n_interfaces; j++) {
            const struct ovsrec_interface *iface = port->interfaces[j];

            if (smap_get(&iface->external_ids, "iface-id")) {
                continue;
            }

            if (smap_get_bool(&iface->external_ids,
                              "ovn-egress-iface", false) ||
                !strcmp(iface->type, "")) {
                *pport = port;
                return iface;
            }
        }
    }

    return NULL;
}

/* 34359738360 == (2^32 - 1) * 8.  netdev_set_qos() doesn't support
 * 64-bit rate netlink attributes, so the maximum value is 2^32 - 1
 * bytes. The 'max-rate' config option is in bits, so multiplying by 8.
 * Without setting max-rate the reported link speed will be used, which
 * can be unrecognized for certain NICs or reported too low for virtual
 * interfaces. */
#define OVN_QOS_MAX_RATE    34359738360ULL
static void
add_ovs_qos_table_entry(struct ovsdb_idl_txn *ovs_idl_txn,
                        const struct ovsrec_port *port,
                        unsigned long long min_rate,
                        unsigned long long max_rate,
                        unsigned long long burst,
                        uint32_t queue_id, const char *ovn_port)
{
    struct smap external_ids = SMAP_INITIALIZER(&external_ids);
    struct smap other_config = SMAP_INITIALIZER(&other_config);

    const struct ovsrec_qos *qos = port->qos;
    if (qos && !smap_get_bool(&qos->external_ids, "ovn_qos", false)) {
        /* External configured QoS, do not overwrite it. */
        return;
    }

    if (!qos) {
        qos = ovsrec_qos_insert(ovs_idl_txn);
        ovsrec_qos_set_type(qos, OVN_QOS_TYPE);
        ovsrec_port_set_qos(port, qos);
        smap_add_format(&other_config, "max-rate", "%lld", OVN_QOS_MAX_RATE);
        ovsrec_qos_set_other_config(qos, &other_config);
        smap_clear(&other_config);

        smap_add(&external_ids, "ovn_qos", "true");
        ovsrec_qos_set_external_ids(qos, &external_ids);
        smap_clear(&external_ids);
    }

    struct ovsrec_queue *queue;
    size_t i;
    for (i = 0; i < qos->n_queues; i++) {
        queue = qos->value_queues[i];

        const char *p = smap_get(&queue->external_ids, "ovn_port");
        if (p && !strcmp(p, ovn_port)) {
            break;
        }
    }

    if (i == qos->n_queues) {
        queue = ovsrec_queue_insert(ovs_idl_txn);
        ovsrec_qos_update_queues_setkey(qos, queue_id, queue);
    }

    smap_add_format(&other_config, "max-rate", "%llu", max_rate);
    smap_add_format(&other_config, "min-rate", "%llu", min_rate);
    smap_add_format(&other_config, "burst", "%llu", burst);
    ovsrec_queue_verify_other_config(queue);
    ovsrec_queue_set_other_config(queue, &other_config);
    smap_destroy(&other_config);

    smap_add(&external_ids, "ovn_port", ovn_port);
    ovsrec_queue_verify_external_ids(queue);
    ovsrec_queue_set_external_ids(queue, &external_ids);
    smap_destroy(&external_ids);
}

static void
remove_stale_qos_entry(struct ovsdb_idl_txn *ovs_idl_txn,
                       const struct sbrec_port_binding *pb,
                       struct ovsdb_idl_index *ovsrec_port_by_qos,
                       const struct ovsrec_qos_table *qos_table,
                       struct hmap *queue_map)
{
    if (!ovs_idl_txn) {
        return;
    }

    struct qos_queue *q = find_qos_queue(
            queue_map, hash_string(pb->logical_port, 0),
            pb->logical_port);
    if (!q) {
        return;
    }

    const struct ovsrec_qos *qos;
    OVSREC_QOS_TABLE_FOR_EACH (qos, qos_table) {
        for (size_t i = 0; i < qos->n_queues; i++) {
            struct ovsrec_queue *queue = qos->value_queues[i];
            if (!queue) {
                continue;
            }

            const char *ovn_port = smap_get(
                    &queue->external_ids, "ovn_port");
            if (!ovn_port || strcmp(ovn_port, q->port)) {
                continue;
            }

            ovsrec_qos_update_queues_delkey(qos, qos->key_queues[i]);
            ovsrec_queue_delete(queue);

            if (qos->n_queues == 1) {
                const struct ovsrec_port *port =
                    ovsport_lookup_by_qos(ovsrec_port_by_qos, qos);
                if (port) {
                    ovsrec_port_set_qos(port, NULL);
                }
                ovsrec_qos_delete(qos);
            }

            hmap_remove(queue_map, &q->node);
            qos_queue_erase_entry(q);

            return;
        }
    }
}

static void
configure_qos(const struct sbrec_port_binding *pb,
              struct binding_ctx_in *b_ctx_in,
              struct binding_ctx_out *b_ctx_out)
{
    unsigned long long min_rate = smap_get_ullong(
            &pb->options, "qos_min_rate", 0);
    unsigned long long max_rate = smap_get_ullong(
            &pb->options, "qos_max_rate", 0);
    unsigned long long burst = smap_get_ullong(
            &pb->options, "qos_burst", 0);
    uint32_t queue_id = smap_get_int(&pb->options, "qdisc_queue_id", 0);

    if ((!min_rate && !max_rate && !burst) || !queue_id) {
        /* Qos is not configured for this port. */
        remove_stale_qos_entry(b_ctx_in->ovs_idl_txn, pb,
                               b_ctx_in->ovsrec_port_by_qos,
                               b_ctx_in->qos_table, b_ctx_out->qos_map);
        return;
    }

    const char *network = smap_get(&pb->options, "qos_physical_network");
    uint32_t hash = hash_string(pb->logical_port, 0);
    struct qos_queue *q = find_qos_queue(b_ctx_out->qos_map, hash,
                                         pb->logical_port);
    if (!q || q->min_rate != min_rate || q->max_rate != max_rate ||
        q->burst != burst || (network && strcmp(network, q->network))) {
        struct shash bridge_mappings = SHASH_INITIALIZER(&bridge_mappings);
        add_ovs_bridge_mappings(b_ctx_in->ovs_table, b_ctx_in->bridge_table,
                                &bridge_mappings);

        const struct ovsrec_port *port = NULL;
        const struct ovsrec_interface *iface = NULL;
        if (network) {
             iface = get_qos_egress_port_interface(&bridge_mappings, &port,
                                                   network);
        }
        if (iface) {
            /* Add new QoS entries. */
            add_ovs_qos_table_entry(b_ctx_in->ovs_idl_txn, port, min_rate,
                                    max_rate, burst, queue_id,
                                    pb->logical_port);
            if (!q) {
                q = xzalloc(sizeof *q);
                hmap_insert(b_ctx_out->qos_map, &q->node, hash);
                q->port = xstrdup(pb->logical_port);
                q->queue_id = queue_id;
            }
            free(q->network);
            q->network = network ? xstrdup(network) : NULL;
            q->min_rate = min_rate;
            q->max_rate = max_rate;
            q->burst = burst;
        }
        shash_destroy(&bridge_mappings);
    }
}

static const struct ovsrec_queue *
find_qos_queue_by_external_ids(const struct smap *external_ids,
    struct ovsdb_idl_index *ovsrec_queue_by_external_ids)
{
    const struct ovsrec_queue *queue =
        ovsrec_queue_index_init_row(ovsrec_queue_by_external_ids);
    ovsrec_queue_index_set_external_ids(queue, external_ids);
    const struct ovsrec_queue *retval =
        ovsrec_queue_index_find(ovsrec_queue_by_external_ids, queue);
    ovsrec_queue_index_destroy_row(queue);
    return retval;
}

static void
ovs_qos_entries_gc(struct ovsdb_idl_txn *ovs_idl_txn,
                   struct ovsdb_idl_index *ovsrec_port_by_qos,
                   struct ovsdb_idl_index *ovsrec_queue_by_external_ids,
                   const struct ovsrec_qos_table *qos_table,
                   struct hmap *queue_map)
{
    if (!ovs_idl_txn) {
        return;
    }

    const struct ovsrec_qos *qos, *qos_next;
    OVSREC_QOS_TABLE_FOR_EACH_SAFE (qos, qos_next, qos_table) {
        int n_queue_deleted = 0, n_queues = qos->n_queues;
        for (size_t i = 0; i < n_queues; i++) {
            struct ovsrec_queue *queue = qos->value_queues[i];
            if (!queue) {
                continue;
            }
            const struct ovsrec_queue *ovsrec_queue =
                find_qos_queue_by_external_ids(&queue->external_ids,
                                               ovsrec_queue_by_external_ids);
            if (!ovsrec_queue) {
                VLOG_DBG("queue already deleted !");
                continue;
            }

            const char *port = smap_get(&queue->external_ids, "ovn_port");
            if (!port) {
                continue;
            }

            struct qos_queue *q = find_qos_queue(queue_map,
                                                 hash_string(port, 0), port);
            if (!q) {
                ovsrec_qos_update_queues_delkey(qos, qos->key_queues[i]);
                ovsrec_queue_delete(queue);
                n_queue_deleted++;
            }
        }

        if (n_queue_deleted && n_queue_deleted == n_queues) {
            const struct ovsrec_port *port =
                ovsport_lookup_by_qos(ovsrec_port_by_qos, qos);
            if (port) {
                ovsrec_port_set_qos(port, NULL);
            }
            ovsrec_qos_delete(qos);
        }
    }
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
        add_local_datapath_external_port(ld, binding_rec->logical_port,
                                         binding_rec);
    }
}

static void
update_ld_multichassis_ports(const struct sbrec_port_binding *binding_rec,
                             struct hmap *local_datapaths)
{
    struct local_datapath *ld = get_local_datapath(
        local_datapaths, binding_rec->datapath->tunnel_key);
    if (!ld) {
        return;
    }
    if (binding_rec->additional_chassis) {
        add_local_datapath_multichassis_port(ld, binding_rec->logical_port,
                                             binding_rec);
    } else {
        remove_local_datapath_multichassis_port(ld, binding_rec->logical_port);
    }
}

static void
update_ld_localnet_port(const struct sbrec_port_binding *binding_rec,
                        struct shash *bridge_mappings,
                        struct hmap *local_datapaths)
{
    /* Ignore localnet ports for unplugged networks. */
    if (!is_network_plugged(binding_rec, bridge_mappings)) {
        return;
    }

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

/*
 * Update local_datapath peers when port type changed
 * and remove irrelevant ports from this list.
 */
static void
update_ld_peers(const struct sbrec_port_binding *pb,
                 struct hmap *local_datapaths)
{
    struct local_datapath *ld =
        get_local_datapath(local_datapaths, pb->datapath->tunnel_key);

    if (!ld) {
        return;
    }

    /*
     * This will handle cases where the pb type was explicitly
     * changed from router type to any other port type and will
     * remove it from the ld peers list.
     */
    enum en_lport_type type = get_lport_type(pb);
    int num_peers = ld->n_peer_ports;
    if (type != LP_PATCH) {
        remove_local_datapath_peer_port(pb, ld, local_datapaths);
        if (num_peers != ld->n_peer_ports) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_DBG_RL(&rl,
                        "removing lport %s from the ld peers list",
                        pb->logical_port);
        }
    }
}

static void
delete_active_pb_ras_pd(const struct sbrec_port_binding *pb,
                        struct shash *ras_pd_map)
{
    shash_find_and_delete(ras_pd_map, pb->logical_port);
}

static void
update_active_pb_ras_pd(const struct sbrec_port_binding *pb,
                        struct shash *map, const char *conf)
{
    bool ras_pd_conf = smap_get_bool(&pb->options, conf, false);
    struct shash_node *iter = shash_find(map, pb->logical_port);

    if (!ras_pd_conf && iter) {
        shash_delete(map, iter);
    } else if (ras_pd_conf && !iter) {
        shash_add(map, pb->logical_port, pb);
    }
}

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
    struct binding_ctx_out *b_ctx_out);

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
static bool binding_lport_has_port_sec_changed(
    struct binding_lport *, const struct sbrec_port_binding *);
static void binding_lport_clear_port_sec(struct binding_lport *);
static bool binding_lport_update_port_sec(
    struct binding_lport *, const struct sbrec_port_binding *);

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
    struct shash_node *node;

    SHASH_FOR_EACH_SAFE (node, &lbinding_data->lports) {
        struct binding_lport *b_lport = node->data;
        binding_lport_destroy(b_lport);
        shash_delete(&lbinding_data->lports, node);
    }

    SHASH_FOR_EACH_SAFE (node, &lbinding_data->bindings) {
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
local_binding_is_ovn_installed(struct shash *local_bindings,
                               const char *pb_name)
{
    struct local_binding *lbinding =
        local_binding_find(local_bindings, pb_name);
    if (lbinding && lbinding->iface) {
        return smap_get_bool(&lbinding->iface->external_ids,
                             OVN_INSTALLED_EXT_ID, false);
    }
    return false;
}

bool
local_binding_is_up(struct shash *local_bindings, const char *pb_name,
                    const struct sbrec_chassis *chassis_rec)
{
    struct local_binding *lbinding =
        local_binding_find(local_bindings, pb_name);
    struct binding_lport *b_lport = local_binding_get_primary_lport(lbinding);

    if (b_lport && b_lport->pb->chassis != chassis_rec) {
        return false;
    }

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
local_binding_is_down(struct shash *local_bindings, const char *pb_name,
                      const struct sbrec_chassis *chassis_rec)
{
    struct local_binding *lbinding =
        local_binding_find(local_bindings, pb_name);

    struct binding_lport *b_lport = local_binding_get_primary_lport(lbinding);

    if (b_lport) {
        if (b_lport->pb->chassis == chassis_rec) {
            return false;
        } else if (b_lport->pb->chassis) {
            VLOG_DBG("lport %s already claimed by other chassis",
                     b_lport->pb->logical_port);
            return true;
        }
    }

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
                     const struct sbrec_chassis *chassis_rec,
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

    if (!sb_readonly && lbinding && b_lport && b_lport->pb->n_up &&
            !b_lport->pb->up[0] && b_lport->pb->chassis == chassis_rec) {
        VLOG_INFO("Setting lport %s up in Southbound", pb_name);
        binding_lport_set_up(b_lport, sb_readonly);
        LIST_FOR_EACH (b_lport, list_node, &lbinding->binding_lports) {
            binding_lport_set_up(b_lport, sb_readonly);
        }
    }
}

void
local_binding_remove_ovn_installed(
        struct shash *local_bindings,
        const struct ovsrec_interface_table *iface_table,
        const char *pb_name, bool ovs_readonly)
{
    if (ovs_readonly) {
        return;
    }
    struct local_binding *lbinding =
        local_binding_find(local_bindings, pb_name);
    if (lbinding && lbinding->iface) {
        const struct uuid *iface_uuid = &lbinding->iface->header_.uuid;
        remove_ovn_installed_for_uuid(iface_table, iface_uuid);
    }
}

void
remove_ovn_installed_for_uuid(const struct ovsrec_interface_table *iface_table,
                              const struct uuid *iface_uuid)
{
    const struct ovsrec_interface *iface_rec =
        ovsrec_interface_table_get_for_uuid(iface_table, iface_uuid);
    if (iface_rec && smap_get_bool(&iface_rec->external_ids,
                                   OVN_INSTALLED_EXT_ID, false)) {
        VLOG_INFO("Removing iface %s ovn-installed in OVS",
                  iface_rec->name);
        ovsrec_interface_update_external_ids_delkey(iface_rec,
                                                    OVN_INSTALLED_EXT_ID);
    }
}

void
local_binding_set_down(struct shash *local_bindings, const char *pb_name,
                       const struct sbrec_chassis *chassis_rec,
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

    if (!sb_readonly && b_lport && b_lport->pb->n_up && b_lport->pb->up[0] &&
            (!b_lport->pb->chassis || b_lport->pb->chassis == chassis_rec)) {
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
        return "L3GATEWAY";
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

void
set_pb_chassis_in_sbrec(const struct sbrec_port_binding *pb,
                        const struct sbrec_chassis *chassis_rec,
                        bool is_set)
{
    if (pb->chassis != chassis_rec) {
         if (is_set) {
            if (pb->chassis) {
                VLOG_INFO("Changing chassis for lport %s from %s to %s.",
                          pb->logical_port, pb->chassis->name,
                          chassis_rec->name);
            } else {
                VLOG_INFO("Claiming lport %s for this chassis.",
                          pb->logical_port);
            }
            for (int i = 0; i < pb->n_mac; i++) {
                VLOG_INFO("%s: Claiming %s", pb->logical_port, pb->mac[i]);
            }
            sbrec_port_binding_set_chassis(pb, chassis_rec);
        }
    } else if (!is_set) {
        sbrec_port_binding_set_chassis(pb, NULL);
    }
}

void
set_pb_additional_chassis_in_sbrec(const struct sbrec_port_binding *pb,
                                   const struct sbrec_chassis *chassis_rec,
                                   bool is_set)
{
    if (!is_additional_chassis(pb, chassis_rec)) {
        VLOG_INFO("Claiming lport %s for this additional chassis.",
                  pb->logical_port);
        for (size_t i = 0; i < pb->n_mac; i++) {
            VLOG_INFO("%s: Claiming %s", pb->logical_port, pb->mac[i]);
        }
        sbrec_port_binding_update_additional_chassis_addvalue(pb, chassis_rec);
        if (pb->chassis == chassis_rec) {
            sbrec_port_binding_set_chassis(pb, NULL);
        }
    } else if (!is_set) {
        remove_additional_chassis(pb, chassis_rec);
    }
}

bool
local_bindings_pb_chassis_is_set(struct shash *local_bindings,
                                 const char *pb_name,
                                 const struct sbrec_chassis *chassis_rec)
{
    struct local_binding *lbinding =
        local_binding_find(local_bindings, pb_name);
    struct binding_lport *b_lport = local_binding_get_primary_lport(lbinding);

    if (b_lport && b_lport->pb &&
       ((b_lport->pb->chassis == chassis_rec) ||
         is_additional_chassis(b_lport->pb, chassis_rec))) {
        return true;
    }
    return false;
}

void
local_binding_set_pb(struct shash *local_bindings, const char *pb_name,
                     const struct sbrec_chassis *chassis_rec,
                     struct hmap *tracked_datapaths, bool is_set,
                     enum can_bind bind_type)
{
    struct local_binding *lbinding =
        local_binding_find(local_bindings, pb_name);
    struct binding_lport *b_lport = local_binding_get_primary_lport(lbinding);

    if (b_lport) {
        if (bind_type == CAN_BIND_AS_MAIN) {
            set_pb_chassis_in_sbrec(b_lport->pb, chassis_rec, is_set);
        } else  if (bind_type == CAN_BIND_AS_ADDITIONAL) {
            set_pb_additional_chassis_in_sbrec(b_lport->pb, chassis_rec,
                                               is_set);
        }
        if (tracked_datapaths) {
            update_lport_tracking(b_lport->pb, tracked_datapaths, true);
        }
    }
}

/* For newly claimed ports:
 * - set the 'pb.up' field to true if 'pb' has no 'parent_pb'.
 * - set the 'pb.up' field to true if 'parent_pb.up' is 'true' (e.g., for
 *   container and virtual ports).
 *
 * Returns false if lport is not claimed due to 'sb_readonly'.
 * Returns true otherwise.
 *
 * Note:
 *   Updates the 'pb->up' field only if it's explicitly set to 'false'.
 *   This is to ensure compatibility with older versions of ovn-northd.
 */
static bool
claimed_lport_set_up(const struct sbrec_port_binding *pb,
                     const struct sbrec_port_binding *parent_pb,
                     bool sb_readonly)
{
    /* When notify_up is false in claim_port(), no state is created
     * by if_status_mgr. In such cases, return false (i.e. trigger recompute)
     * if we can't update sb (because it is readonly).
     */
    bool up = true;
    if (!parent_pb || (parent_pb->n_up && parent_pb->up[0])) {
        if (!sb_readonly) {
            if (pb->n_up) {
                sbrec_port_binding_set_up(pb, &up, 1);
            }
        } else if (pb->n_up && !pb->up[0]) {
            return false;
        }
    }
    return true;
}

typedef void (*set_func)(const struct sbrec_port_binding *pb,
                         const struct sbrec_encap *);

static bool
update_port_encap_if_needed(const struct sbrec_port_binding *pb,
                            const struct sbrec_chassis *chassis_rec,
                            const struct ovsrec_interface *iface_rec,
                            bool sb_readonly)
{
    const struct sbrec_encap *encap_rec =
        sbrec_get_port_encap(chassis_rec, iface_rec);
    if ((encap_rec && pb->encap != encap_rec) ||
        (!encap_rec && pb->encap)) {
        if (sb_readonly) {
            return false;
        }
        sbrec_port_binding_set_encap(pb, encap_rec);
    }
    return true;
}

static void
remove_additional_encap_for_chassis(const struct sbrec_port_binding *pb,
                                    const struct sbrec_chassis *chassis_rec)
{
    for (size_t i = 0; i < pb->n_additional_encap; i++) {
        if (!strcmp(pb->additional_encap[i]->chassis_name,
                    chassis_rec->name)) {
            sbrec_port_binding_update_additional_encap_delvalue(
                pb, pb->additional_encap[i]);
        }
    }
}

static bool
update_port_additional_encap_if_needed(
    const struct sbrec_port_binding *pb,
    const struct sbrec_chassis *chassis_rec,
    const struct ovsrec_interface *iface_rec,
    bool sb_readonly)
{
    const struct sbrec_encap *encap_rec =
        sbrec_get_port_encap(chassis_rec, iface_rec);
    if (encap_rec) {
        for (size_t i = 0; i < pb->n_additional_encap; i++) {
            if (pb->additional_encap[i] == encap_rec) {
                return true;
            }
        }
        if (sb_readonly) {
            return false;
        }
        sbrec_port_binding_update_additional_encap_addvalue(pb, encap_rec);
    }
    return true;
}

bool
is_additional_chassis(const struct sbrec_port_binding *pb,
                      const struct sbrec_chassis *chassis_rec)
{
    for (size_t i = 0; i < pb->n_additional_chassis; i++) {
        if (pb->additional_chassis[i] == chassis_rec) {
            return true;
        }
    }
    return false;
}

static void
remove_additional_chassis(const struct sbrec_port_binding *pb,
                          const struct sbrec_chassis *chassis_rec)
{
    sbrec_port_binding_update_additional_chassis_delvalue(pb, chassis_rec);
    remove_additional_encap_for_chassis(pb, chassis_rec);
}

bool
lport_maybe_postpone(const char *port_name, long long int now,
                     struct sset *postponed_ports)
{
    long long int last_claimed = get_claim_timestamp(port_name);
    if (now - last_claimed >= CLAIM_TIME_THRESHOLD_MS) {
        return false;
    }

    sset_add(postponed_ports, port_name);
    VLOG_DBG("Postponed claim on logical port %s.", port_name);

    return true;
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
            struct if_status_mgr *if_mgr,
            struct sset *postponed_ports)
{
    enum can_bind can_bind = lport_can_bind_on_this_chassis(chassis_rec, pb);
    bool update_tracked = false;

    if (can_bind == CAN_BIND_AS_MAIN) {
        if (pb->chassis != chassis_rec) {
            long long int now = time_msec();
            if (pb->chassis) {
                if (lport_maybe_postpone(pb->logical_port, now,
                                         postponed_ports)) {
                    return true;
                }
            }
            if (is_additional_chassis(pb, chassis_rec)) {
                if (sb_readonly) {
                    return false;
                }
                remove_additional_chassis(pb, chassis_rec);
            }
            update_tracked = true;

            if (!notify_up) {
                if (!claimed_lport_set_up(pb, parent_pb, sb_readonly)) {
                    return false;
                }
                if (sb_readonly) {
                    return false;
                }
                set_pb_chassis_in_sbrec(pb, chassis_rec, true);
            } else {
                if_status_mgr_claim_iface(if_mgr, pb, chassis_rec, iface_rec,
                                          sb_readonly, can_bind);
            }
            register_claim_timestamp(pb->logical_port, now);
            sset_find_and_delete(postponed_ports, pb->logical_port);
        } else {
            update_tracked = true;
            if (!notify_up) {
                if (!claimed_lport_set_up(pb, parent_pb, sb_readonly)) {
                    return false;
                }
            } else {
                if ((pb->n_up && !pb->up[0]) ||
                    !smap_get_bool(&iface_rec->external_ids,
                                   OVN_INSTALLED_EXT_ID, false)) {
                    if_status_mgr_claim_iface(if_mgr, pb, chassis_rec,
                                              iface_rec, sb_readonly,
                                              can_bind);
                }
            }
        }
    } else if (can_bind == CAN_BIND_AS_ADDITIONAL) {
        if (!is_additional_chassis(pb, chassis_rec)) {
            if_status_mgr_claim_iface(if_mgr, pb, chassis_rec, iface_rec,
                                      sb_readonly, can_bind);
            update_tracked = true;
        }
    }

    if (update_tracked) {
        if (tracked_datapaths) {
            update_lport_tracking(pb, tracked_datapaths, true);
        }
    }

    /* Check if the port encap binding, if any, has changed */
    if (can_bind == CAN_BIND_AS_MAIN) {
        return update_port_encap_if_needed(
            pb, chassis_rec, iface_rec, sb_readonly);
    } else if (can_bind == CAN_BIND_AS_ADDITIONAL) {
        return update_port_additional_encap_if_needed(
            pb, chassis_rec, iface_rec, sb_readonly);
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
release_lport_main_chassis(const struct sbrec_port_binding *pb,
                           bool sb_readonly,
                           struct if_status_mgr *if_mgr)
{
    if (pb->encap) {
        if (sb_readonly) {
            return false;
        }
        sbrec_port_binding_set_encap(pb, NULL);
    }

    /* If sb is readonly, pb->chassis is unset through if-status if present. */

    if (pb->chassis) {
        if (!sb_readonly) {
            sbrec_port_binding_set_chassis(pb, NULL);
        } else if (!if_status_mgr_iface_is_present(if_mgr, pb->logical_port)) {
            return false;
        }
    }

    if (pb->virtual_parent) {
        if (sb_readonly) {
            return false;
        }
        sbrec_port_binding_set_virtual_parent(pb, NULL);
    }

    VLOG_INFO("Releasing lport %s from this chassis (sb_readonly=%d)",
              pb->logical_port, sb_readonly);

    return true;
}

static bool
release_lport_additional_chassis(const struct sbrec_port_binding *pb,
                                 const struct sbrec_chassis *chassis_rec,
                                 bool sb_readonly)
{
    if (pb->additional_encap) {
        if (sb_readonly) {
            return false;
        }
        remove_additional_encap_for_chassis(pb, chassis_rec);
    }

    if (is_additional_chassis(pb, chassis_rec)) {
        if (sb_readonly) {
            return false;
        }
        remove_additional_chassis(pb, chassis_rec);
    }

    VLOG_INFO("Releasing lport %s from this additional chassis.",
              pb->logical_port);
    return true;
}

static bool
release_lport(const struct sbrec_port_binding *pb,
              const struct sbrec_chassis *chassis_rec, bool sb_readonly,
              struct hmap *tracked_datapaths, struct if_status_mgr *if_mgr)
{
    if (pb->chassis == chassis_rec) {
        if (!release_lport_main_chassis(pb, sb_readonly, if_mgr)) {
            return false;
        }
    } else if (is_additional_chassis(pb, chassis_rec)) {
        if (!release_lport_additional_chassis(pb, chassis_rec, sb_readonly)) {
            return false;
        }
    } else {
        VLOG_INFO("Releasing lport %s", pb->logical_port);
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
            (b_lport->pb->chassis == chassis
             || is_additional_chassis(b_lport->pb, chassis)));
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
        if (!release_lport(b_lport->pb, chassis_rec, sb_readonly,
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
                    struct binding_lport *b_lport)
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
                             b_ctx_out->if_mgr,
                             b_ctx_out->postponed_ports)) {
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
            if (binding_lport_update_port_sec(b_lport, pb) &&
                    b_ctx_out->tracked_dp_bindings) {
                tracked_datapath_lport_add(pb, TRACKED_RESOURCE_UPDATED,
                                           b_ctx_out->tracked_dp_bindings);
            }
            if (b_lport->lbinding->iface && b_ctx_in->ovs_idl_txn) {
                configure_qos(pb, b_ctx_in, b_ctx_out);
            }
        } else {
            /* We could, but can't claim the lport. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            const char *requested_chassis_option = smap_get(
                &pb->options, "requested-chassis");
            VLOG_INFO_RL(&rl,
                "Not claiming lport %s, chassis %s requested-chassis %s "
                "pb->chassis %s",
                pb->logical_port, b_ctx_in->chassis_rec->name,
                requested_chassis_option ? requested_chassis_option : "[]",
                pb->chassis ? pb->chassis->name: "");
        }
    }

    if (pb->chassis == b_ctx_in->chassis_rec
            || is_additional_chassis(pb, b_ctx_in->chassis_rec)
            || if_status_is_port_claimed(b_ctx_out->if_mgr,
                                         pb->logical_port)) {
        /* Release the lport if there is no lbinding. */
       if (lbinding_set && !can_bind) {
            if_status_mgr_remove_ovn_installed(b_ctx_out->if_mgr,
                               b_lport->lbinding->iface->name,
                               &b_lport->lbinding->iface->header_.uuid);
        }

        if (!lbinding_set || !can_bind) {
            return release_lport(pb, b_ctx_in->chassis_rec,
                                 !b_ctx_in->ovnsb_idl_txn,
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
                   struct local_binding *lbinding)
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

    return consider_vif_lport_(pb, can_bind, b_ctx_in, b_ctx_out, b_lport);
}

static bool
consider_container_lport(const struct sbrec_port_binding *pb,
                         struct binding_ctx_in *b_ctx_in,
                         struct binding_ctx_out *b_ctx_out)
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
                               parent_lbinding);
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
            return release_lport(pb, b_ctx_in->chassis_rec,
                                 !b_ctx_in->ovnsb_idl_txn,
                                 b_ctx_out->tracked_dp_bindings,
                                 b_ctx_out->if_mgr);
        }

        return true;
    }

    ovs_assert(parent_b_lport && parent_b_lport->pb);
    /* cannot bind to this chassis if the parent_port cannot be bounded. */
    bool can_bind = lport_can_bind_on_this_chassis(b_ctx_in->chassis_rec,
                                                   parent_b_lport->pb) &&
                    lport_can_bind_on_this_chassis(b_ctx_in->chassis_rec, pb);

    return consider_vif_lport_(pb, can_bind, b_ctx_in, b_ctx_out,
                               container_b_lport);
}

static bool
consider_virtual_lport(const struct sbrec_port_binding *pb,
                       struct binding_ctx_in *b_ctx_in,
                       struct binding_ctx_out *b_ctx_out)
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
                                   parent_lbinding);
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
                             virtual_b_lport)) {
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
    enum can_bind can_bind = lport_can_bind_on_this_chassis(
        b_ctx_in->chassis_rec, pb);
    if (can_bind == CAN_BIND_AS_MAIN) {
        if (!release_lport_main_chassis(pb, !b_ctx_in->ovnsb_idl_txn,
            b_ctx_out->if_mgr)) {
            return false;
        }
    } else if (can_bind == CAN_BIND_AS_ADDITIONAL) {
        if (!release_lport_additional_chassis(pb, b_ctx_in->chassis_rec,
                                              !b_ctx_in->ovnsb_idl_txn)) {
            return false;
        }
    }

    if (can_bind) {
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
                           b_ctx_out->if_mgr,
                           b_ctx_out->postponed_ports);
    }

    if (pb->chassis == b_ctx_in->chassis_rec ||
            is_additional_chassis(pb, b_ctx_in->chassis_rec)) {
        return release_lport(pb, b_ctx_in->chassis_rec,
                             !b_ctx_in->ovnsb_idl_txn,
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
                        struct binding_ctx_out *b_ctx_out)
{
    bool pb_localnet_learn_fdb = smap_get_bool(&pb->options,
                                               "localnet_learn_fdb", false);
    if (pb_localnet_learn_fdb != b_ctx_out->localnet_learn_fdb) {
        b_ctx_out->localnet_learn_fdb = pb_localnet_learn_fdb;
        if (b_ctx_out->tracked_dp_bindings) {
            b_ctx_out->localnet_learn_fdb_changed = true;
            tracked_datapath_lport_add(pb, TRACKED_RESOURCE_UPDATED,
                                       b_ctx_out->tracked_dp_bindings);
        }
    }

    /* Add all localnet ports to local_ifaces so that we allocate ct zones
     * for them. */
    update_local_lports(pb->logical_port, b_ctx_out);

    if (b_ctx_in->ovs_idl_txn) {
        configure_qos(pb, b_ctx_in, b_ctx_out);
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
                    lbinding->multiple_bindings = true;
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
            } else if (smap_get_bool(&iface_rec->external_ids,
                       OVN_INSTALLED_EXT_ID, false)) {
                /* Interface should not be claimed (ovn_installed).
                 * This can happen if iface-id was removed as we recompute.
                 */
                if_status_mgr_remove_ovn_installed(b_ctx_out->if_mgr,
                                                   iface_rec->name,
                                                   &iface_rec->header_.uuid);
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

    if (b_ctx_in->br_int) {
        build_local_bindings(b_ctx_in, b_ctx_out);
    }

    struct ovs_list localnet_lports = OVS_LIST_INITIALIZER(&localnet_lports);
    struct ovs_list external_lports = OVS_LIST_INITIALIZER(&external_lports);
    struct ovs_list multichassis_ports = OVS_LIST_INITIALIZER(
                                                        &multichassis_ports);

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
        update_active_pb_ras_pd(pb, b_ctx_out->local_active_ports_ipv6_pd,
                                "ipv6_prefix_delegation");
        update_active_pb_ras_pd(pb, b_ctx_out->local_active_ports_ras,
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
            consider_vif_lport(pb, b_ctx_in, b_ctx_out, NULL);
            if (pb->additional_chassis) {
                struct lport *multichassis_lport = xmalloc(
                    sizeof *multichassis_lport);
                multichassis_lport->pb = pb;
                ovs_list_push_back(&multichassis_ports,
                                   &multichassis_lport->list_node);
            }
            break;

        case LP_CONTAINER:
            consider_container_lport(pb, b_ctx_in, b_ctx_out);
            break;

        case LP_VIRTUAL:
            consider_virtual_lport(pb, b_ctx_in, b_ctx_out);
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
            consider_localnet_lport(pb, b_ctx_in, b_ctx_out);
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
                                b_ctx_out->local_datapaths);
        free(lnet_lport);
    }

    /* Run through external lport list to see if there are external ports
     * on local datapaths discovered from above loop, and update the
     * corresponding local datapath accordingly. */
    struct lport *ext_lport;
    LIST_FOR_EACH_POP (ext_lport, list_node, &external_lports) {
        update_ld_external_ports(ext_lport->pb, b_ctx_out->local_datapaths);
        free(ext_lport);
    }

    /* Run through multichassis lport list to see if there are ports
     * on local datapaths discovered from above loop, and update the
     * corresponding local datapath accordingly. */
    struct lport *multichassis_lport;
    LIST_FOR_EACH_POP (multichassis_lport, list_node, &multichassis_ports) {
        update_ld_multichassis_ports(multichassis_lport->pb,
                                     b_ctx_out->local_datapaths);
        free(multichassis_lport);
    }

    shash_destroy(&bridge_mappings);
    /* Remove stale QoS entries. */
    ovs_qos_entries_gc(b_ctx_in->ovs_idl_txn, b_ctx_in->ovsrec_port_by_qos,
                       b_ctx_in->ovsrec_queue_by_external_ids,
                       b_ctx_in->qos_table, b_ctx_out->qos_map);

    cleanup_claimed_port_timestamps();
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
        if (is_additional_chassis(binding_rec, chassis_rec)) {
            remove_additional_chassis(binding_rec, chassis_rec);
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
        remove_local_datapath_external_port(ld, pb->logical_port);
    }
    remove_local_datapath_multichassis_port(ld, pb->logical_port);
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
                     struct binding_ctx_out *b_ctx_out)
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
        if (lbinding->iface && lbinding->iface != iface_rec) {
            lbinding->multiple_bindings = true;
            b_ctx_out->local_lports_changed = true;
        }
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

    /* If multiple bindings to the same port, remove the "old" binding.
     * This ensures that change tracking is correct.
     */
    if (lbinding->multiple_bindings) {
        remove_related_lport(pb, b_ctx_out);
    }

    enum en_lport_type lport_type = get_lport_type(pb);
    if (lport_type == LP_LOCALPORT) {
        return consider_localport(pb, b_ctx_in, b_ctx_out);
    }

    if (lport_type == LP_VIF &&
        !consider_vif_lport(pb, b_ctx_in, b_ctx_out, lbinding)) {
        return false;
    }

    /* Get the (updated) b_lport again for the lbinding. */
    b_lport = local_binding_get_primary_lport(lbinding);

    /*
     * Update the tracked_dp_bindings whenever an ofport
     * on a specific ovs port changes.
     * This update will trigger flow recomputation during
     * the incremental processing run which updates the local
     * flows in_port filed.
     */
    if (b_lport && ovsrec_interface_is_updated(iface_rec,
                                    OVSREC_INTERFACE_COL_OFPORT)) {
        tracked_datapath_lport_add(b_lport->pb, TRACKED_RESOURCE_UPDATED,
                                   b_ctx_out->tracked_dp_bindings);
        b_ctx_out->local_lports_changed = true;
    }


    /* Update the child local_binding's iface (if any children) and try to
     *  claim the container lbindings. */
    LIST_FOR_EACH (b_lport, list_node, &lbinding->binding_lports) {
        if (b_lport->type == LP_CONTAINER) {
            if (!consider_container_lport(b_lport->pb, b_ctx_in, b_ctx_out)) {
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

   if (lbinding) {
        if (lbinding->multiple_bindings) {
            VLOG_INFO("Multiple bindings for %s: force recompute to clean up",
                      iface_id);
            return false;
        } else {
            int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;
            if (lbinding->iface != iface_rec && !ofport) {
                /* If external_ids:iface-id is set within the same transaction
                 * as adding an interface to a bridge, ovn-controller is
                 * usually initially notified of ovs interface changes with
                 * ofport == 0. If the lport was bound to a different interface
                 * we do not want to release it.
                 */
                VLOG_DBG("Not releasing lport %s as %s was claimed "
                         "and %s was never bound)", iface_id, lbinding->iface ?
                         lbinding->iface->name : "", iface_rec->name);
                return true;
            }
        }
    }

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

        remove_stale_qos_entry(b_ctx_in->ovs_idl_txn, b_lport->pb,
                               b_ctx_in->ovsrec_port_by_qos,
                               b_ctx_in->qos_table, b_ctx_out->qos_map);

        /* Release the primary binding lport and other children lports if
         * any. */
        LIST_FOR_EACH (b_lport, list_node, &lbinding->binding_lports) {
            if (!release_binding_lport(b_ctx_in->chassis_rec, b_lport,
                                       !b_ctx_in->ovnsb_idl_txn,
                                       b_ctx_out)) {
                return false;
            }
        }
        if (lbinding->iface && lbinding->iface->name) {
            if_status_mgr_remove_ovn_installed(b_ctx_out->if_mgr,
                                               lbinding->iface->name,
                                               &lbinding->iface->header_.uuid);
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

static bool
is_ext_id_changed(const struct smap *a, const struct smap *b, const char *key)
{
    const char *value_a = smap_get(a, key);
    const char *value_b = smap_get(b, key);
    if ((value_a && !value_b)
        || (!value_a && value_b)
        || (value_a && value_b && strcmp(value_a, value_b))) {
        return true;
    }
    return false;
}

/* Check if the change in 'iface_rec' is something we are interested in from
 * port binding perspective.  Return true if the change needs to be handled,
 * otherwise return false.
 *
 * The 'iface_rec' must be change tracked, i.e. iterator from
 * OVSREC_INTERFACE_TABLE_FOR_EACH_TRACKED. */
static bool
ovs_interface_change_need_handle(const struct ovsrec_interface *iface_rec,
                                 struct shash *iface_table_external_ids_old)
{
    if (ovsrec_interface_is_updated(iface_rec,
                                    OVSREC_INTERFACE_COL_NAME)) {
        return true;
    }
    if (ovsrec_interface_is_updated(iface_rec,
                                    OVSREC_INTERFACE_COL_OFPORT)) {
        return true;
    }
    if (ovsrec_interface_is_updated(iface_rec,
                                    OVSREC_INTERFACE_COL_TYPE)) {
        return true;
    }
    if (ovsrec_interface_is_updated(iface_rec,
                                    OVSREC_INTERFACE_COL_EXTERNAL_IDS)) {
        /* Compare the external_ids that we are interested in with the old
         * values:
         * - iface-id
         * - iface-id-ver
         * - encap-ip
         * For any other changes, such as ovn-installed, ovn-installed-ts, etc,
         * we don't need to handle. */
        struct smap *external_ids_old =
            shash_find_data(iface_table_external_ids_old, iface_rec->name);
        if (!external_ids_old) {
            return true;
        }
        if (is_ext_id_changed(&iface_rec->external_ids, external_ids_old,
                              "iface-id")) {
            return true;
        }
        if (is_ext_id_changed(&iface_rec->external_ids, external_ids_old,
                              "iface-id-ver")) {
            return true;
        }
        if (is_ext_id_changed(&iface_rec->external_ids, external_ids_old,
                              "encap-ip")) {
            return true;
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

        if (!ovs_interface_change_need_handle(
            iface_rec, b_ctx_in->iface_table_external_ids_old)) {
            continue;
        }

        const char *iface_id = smap_get(&iface_rec->external_ids, "iface-id");
        int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;
        if (iface_id && ofport > 0 &&
                is_iface_in_int_bridge(iface_rec, b_ctx_in->br_int)) {
            handled = consider_iface_claim(iface_rec, iface_id, b_ctx_in,
                                           b_ctx_out);
            if (!handled) {
                break;
            }
        }
    }

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
        /* Only try to release the port if it was ever claimed.
         * If a port was added and deleted within the same ovn-controller loop,
         * it is seen as never claimed.
         */
        if (if_status_is_port_claimed(b_ctx_out->if_mgr, pb->logical_port)) {
            if_status_mgr_release_iface(b_ctx_out->if_mgr, pb->logical_port);
        }
        return;
    }

    /*
     * Remove localport that was part of local datapath that is not
     * considered to be local anymore.
     */
    if (!ld && !strcmp(pb->type, "localport") &&
        sset_find(&b_ctx_out->related_lports->lport_names, pb->logical_port)) {
        remove_related_lport(pb, b_ctx_out);
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
        if (if_status_is_port_claimed(b_ctx_out->if_mgr, pb->logical_port)) {
            if_status_mgr_release_iface(b_ctx_out->if_mgr, pb->logical_port);
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
    if (lbinding && lbinding->iface && lbinding->iface->name) {
        if_status_mgr_remove_ovn_installed(b_ctx_out->if_mgr,
                                           lbinding->iface->name,
                                           &lbinding->iface->header_.uuid);
    }
    return true;
}

static bool
handle_updated_vif_lport(const struct sbrec_port_binding *pb,
                         enum en_lport_type lport_type,
                         struct binding_ctx_in *b_ctx_in,
                         struct binding_ctx_out *b_ctx_out)
{
    bool claimed = (pb->chassis == b_ctx_in->chassis_rec);
    bool handled = true;

    if (lport_type == LP_VIRTUAL) {
        handled = consider_virtual_lport(pb, b_ctx_in, b_ctx_out);
    } else if (lport_type == LP_CONTAINER) {
        handled = consider_container_lport(pb, b_ctx_in, b_ctx_out);
    } else {
        handled = consider_vif_lport(pb, b_ctx_in, b_ctx_out, NULL);
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
                                               b_ctx_out);
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
        if (peer_ld && need_add_peer_to_local(
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
        if (need_add_peer_to_local(
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

static bool
handle_updated_port(struct binding_ctx_in *b_ctx_in,
                    struct binding_ctx_out *b_ctx_out,
                    const struct sbrec_port_binding *pb)
{
    update_active_pb_ras_pd(pb, b_ctx_out->local_active_ports_ipv6_pd,
                            "ipv6_prefix_delegation");

    update_active_pb_ras_pd(pb, b_ctx_out->local_active_ports_ras,
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
            if (!local_binding_handle_stale_binding_lports(
                    b_lport->lbinding, b_ctx_in, b_ctx_out)) {
                return false;
            }
        }
    }

    bool handled = true;

    switch (lport_type) {
    case LP_VIF:
    case LP_CONTAINER:
    case LP_VIRTUAL:
        update_ld_multichassis_ports(pb, b_ctx_out->local_datapaths);
        handled = handle_updated_vif_lport(pb, lport_type, b_ctx_in,
                                           b_ctx_out);
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
        consider_localnet_lport(pb, b_ctx_in, b_ctx_out);

        struct shash bridge_mappings =
            SHASH_INITIALIZER(&bridge_mappings);
        add_ovs_bridge_mappings(b_ctx_in->ovs_table,
                                b_ctx_in->bridge_table,
                                &bridge_mappings);
        update_ld_localnet_port(pb, &bridge_mappings,
                                b_ctx_out->local_datapaths);
        shash_destroy(&bridge_mappings);
        break;
    }

    case LP_REMOTE:
    case LP_UNKNOWN:
        break;
    }

    return handled;
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

        delete_active_pb_ras_pd(pb, b_ctx_out->local_active_ports_ipv6_pd);
        delete_active_pb_ras_pd(pb, b_ctx_out->local_active_ports_ras);

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

        remove_stale_qos_entry(b_ctx_in->ovs_idl_txn, pb,
                               b_ctx_in->ovsrec_port_by_qos,
                               b_ctx_in->qos_table, b_ctx_out->qos_map);
    }

    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &deleted_container_pbs) {
        handled = handle_deleted_vif_lport(node->data, LP_CONTAINER, b_ctx_in,
                                           b_ctx_out);
        shash_delete(&deleted_container_pbs, node);
        if (!handled) {
            goto delete_done;
        }
    }

    SHASH_FOR_EACH_SAFE (node, &deleted_virtual_pbs) {
        handled = handle_deleted_vif_lport(node->data, LP_VIRTUAL, b_ctx_in,
                                           b_ctx_out);
        shash_delete(&deleted_virtual_pbs, node);
        if (!handled) {
            goto delete_done;
        }
    }

    SHASH_FOR_EACH_SAFE (node, &deleted_vif_pbs) {
        handled = handle_deleted_vif_lport(node->data, LP_VIF, b_ctx_in,
                                           b_ctx_out);
        shash_delete(&deleted_vif_pbs, node);
        if (!handled) {
            goto delete_done;
        }
    }

    SHASH_FOR_EACH_SAFE (node, &deleted_localport_pbs) {
        handle_deleted_vif_lport(node->data, LP_LOCALPORT, b_ctx_in,
                                 b_ctx_out);
        shash_delete(&deleted_localport_pbs, node);
    }

    SHASH_FOR_EACH_SAFE (node, &deleted_other_pbs) {
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

    SBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (pb,
                                               b_ctx_in->port_binding_table) {
        /* Loop to handle create and update changes only. */
        if (sbrec_port_binding_is_deleted(pb)) {
            continue;
        }

        if (sbrec_port_binding_is_updated(pb, SBREC_PORT_BINDING_COL_TYPE)) {
            update_ld_peers(pb, b_ctx_out->local_datapaths);
        }

        handled = handle_updated_port(b_ctx_in, b_ctx_out, pb);
        if (!handled) {
            break;
        }
    }

    /* Also handle any postponed (throttled) ports. */
    const char *port_name;
    struct sset postponed_ports = SSET_INITIALIZER(&postponed_ports);
    sset_clone(&postponed_ports, b_ctx_out->postponed_ports);
    SSET_FOR_EACH (port_name, &postponed_ports) {
        pb = lport_lookup_by_name(b_ctx_in->sbrec_port_binding_by_name,
                                  port_name);
        if (!pb) {
            sset_find_and_delete(b_ctx_out->postponed_ports, port_name);
            continue;
        }
        handled = handle_updated_port(b_ctx_in, b_ctx_out, pb);
        if (!handled) {
            break;
        }
    }
    sset_destroy(&postponed_ports);
    cleanup_claimed_port_timestamps();

    if (handled) {
        /* There may be new local datapaths added by the above handling, so go
         * through each port_binding of newly added local datapaths to update
         * related local_datapaths if needed. */
        struct shash bridge_mappings =
            SHASH_INITIALIZER(&bridge_mappings);
        add_ovs_bridge_mappings(b_ctx_in->ovs_table,
                                b_ctx_in->bridge_table,
                                &bridge_mappings);
        struct tracked_datapath *t_dp;
        HMAP_FOR_EACH (t_dp, node, b_ctx_out->tracked_dp_bindings) {
            if (t_dp->tracked_type != TRACKED_RESOURCE_NEW) {
                continue;
            }
            struct sbrec_port_binding *target =
                sbrec_port_binding_index_init_row(
                    b_ctx_in->sbrec_port_binding_by_datapath);
            sbrec_port_binding_index_set_datapath(target, t_dp->dp);

            SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, target,
                b_ctx_in->sbrec_port_binding_by_datapath) {
                enum en_lport_type lport_type = get_lport_type(pb);
                if (lport_type == LP_LOCALNET) {
                    update_ld_localnet_port(pb, &bridge_mappings,
                                            b_ctx_out->local_datapaths);
                } else if (lport_type == LP_EXTERNAL) {
                    update_ld_external_ports(pb, b_ctx_out->local_datapaths);
                } else if (pb->n_additional_chassis) {
                    update_ld_multichassis_ports(pb,
                                                 b_ctx_out->local_datapaths);
                }
            }
            sbrec_port_binding_index_destroy_row(target);
        }

        shash_destroy(&bridge_mappings);
    }

    return handled;
}

/* Static functions for local_lbindind and binding_lport. */
static struct local_binding *
local_binding_create(const char *name, const struct ovsrec_interface *iface)
{
    struct local_binding *lbinding = xzalloc(sizeof *lbinding);
    lbinding->name = xstrdup(name);
    lbinding->iface = iface;
    lbinding->multiple_bindings = false;
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
                                          struct binding_ctx_out *b_ctx_out)
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
    struct binding_lport *b_lport;
    const struct sbrec_port_binding *pb;
    LIST_FOR_EACH_SAFE (b_lport, list_node, &lbinding->binding_lports) {
        /* Get the lport type again from the pb.  Its possible that the
         * pb type has changed. */
        enum en_lport_type pb_lport_type = get_lport_type(b_lport->pb);
        if (b_lport->type == LP_VIRTUAL && pb_lport_type == LP_VIRTUAL) {
            pb = b_lport->pb;
            binding_lport_delete(&b_ctx_out->lbinding_data->lports,
                                 b_lport);
            handled = consider_virtual_lport(pb, b_ctx_in, b_ctx_out);
        } else if (b_lport->type == LP_CONTAINER &&
                   pb_lport_type == LP_CONTAINER) {
            /* For container lport, binding_lport is preserved so that when
             * the parent port is created, it can be considered.
             * consider_container_lport() creates the binding_lport for the parent
             * port (with iface set to NULL). */
            handled = consider_container_lport(b_lport->pb, b_ctx_in,
                                               b_ctx_out);
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

    binding_lport_clear_port_sec(b_lport);
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

void
port_binding_set_down(const struct sbrec_chassis *chassis_rec,
                      const struct sbrec_port_binding_table *pb_table,
                      const char *iface_id,
                      const struct uuid *pb_uuid)
{
        const struct sbrec_port_binding *pb =
            sbrec_port_binding_table_get_for_uuid(pb_table, pb_uuid);
        if (!pb) {
            VLOG_DBG("port_binding already deleted for %s", iface_id);
        } else if (pb->n_up && pb->up[0]) {
            bool up = false;
            sbrec_port_binding_set_up(pb, &up, 1);
            VLOG_INFO("Setting lport %s down in Southbound", pb->logical_port);
            set_pb_chassis_in_sbrec(pb, chassis_rec, false);
        }
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
    VLOG_INFO("Setting lport %s down in Southbound", b_lport->name);

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
binding_lport_has_port_sec_changed(struct binding_lport *b_lport,
                                   const struct sbrec_port_binding *pb)
{
    if (b_lport->n_port_security != pb->n_port_security) {
        return true;
    }

    for (size_t i = 0; i < b_lport->n_port_security; i++) {
        if (strcmp(b_lport->port_security[i], pb->port_security[i])) {
            return true;
        }
    }

    return false;
}

static void
binding_lport_clear_port_sec(struct binding_lport *b_lport)
{
    for (size_t i = 0; i < b_lport->n_port_security; i++) {
        free(b_lport->port_security[i]);
    }
    free(b_lport->port_security);
    b_lport->n_port_security = 0;
}

static bool
binding_lport_update_port_sec(struct binding_lport *b_lport,
                              const struct sbrec_port_binding *pb)
{
    if (binding_lport_has_port_sec_changed(b_lport, pb)) {
        binding_lport_clear_port_sec(b_lport);
        b_lport->port_security =
            pb->n_port_security ?
            xmalloc(pb->n_port_security * sizeof *b_lport->port_security) :
            NULL;

        b_lport->n_port_security = pb->n_port_security;
        for (size_t i = 0; i < pb->n_port_security; i++) {
            b_lport->port_security[i] = xstrdup(pb->port_security[i]);
        }

        return true;
    }

    return false;
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
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(&rl, "Mismatch iface-id-ver for lport %s, "
                         "expected %s, found %s", pb->logical_port,
                         pb_iface_id_ver,
                         iface_id_ver ? iface_id_ver : "<empty>");
            return false;
        }
    }

    return true;
}

void
binding_destroy(void)
{
    shash_destroy_free_data(&_claimed_ports);
    sset_clear(&_postponed_ports);
}
