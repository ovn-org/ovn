/* Copyright (c) 2022 Red Hat, Inc.
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
#include <unistd.h>

/* library headers */
#include "lib/sset.h"
#include "lib/util.h"

/* OVS includes. */
#include "lib/vswitch-idl.h"
#include "lib/socket-util.h"
#include "include/openvswitch/shash.h"
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "binding.h"
#include "lib/ovn-sb-idl.h"
#include "mirror.h"

VLOG_DEFINE_THIS_MODULE(port_mirror);

struct ovn_mirror {
    char *name;
    const struct sbrec_mirror *sb_mirror;
    const struct ovsrec_mirror *ovs_mirror;
    struct ovs_list mirror_src_lports;
    struct ovs_list mirror_dst_lports;
};

struct mirror_lport {
    struct ovs_list list_node;

    struct local_binding *lbinding;
};

static struct ovn_mirror *ovn_mirror_create(char *mirror_name);
static void ovn_mirror_add(struct shash *ovn_mirrors,
                           struct ovn_mirror *);
static struct ovn_mirror *ovn_mirror_find(struct shash *ovn_mirrors,
                                          const char *mirror_name);
static void ovn_mirror_delete(struct ovn_mirror *);
static void ovn_mirror_add_lport(struct ovn_mirror *, struct local_binding *);
static void sync_ovn_mirror(struct ovn_mirror *, struct ovsdb_idl_txn *,
                            const struct ovsrec_bridge *,
                            struct shash *ovs_mirror_ports);

static void create_ovs_mirror(struct ovn_mirror *, struct ovsdb_idl_txn *,
                              const struct ovsrec_bridge *,
                              struct shash *ovs_mirror_ports);
static struct ovsrec_port *create_mirror_port(struct ovn_mirror *,
                                              struct ovsdb_idl_txn *,
                                              const struct ovsrec_bridge *);
static void sync_ovs_mirror_ports(struct ovn_mirror *,
                                  const struct ovsrec_bridge *);
static void delete_ovs_mirror(struct ovn_mirror *,
                              const struct ovsrec_bridge *);
static bool should_delete_ovs_mirror(struct ovn_mirror *);
static void set_mirror_iface_options(struct ovsrec_interface *,
                                     const struct sbrec_mirror *);

static const struct ovsrec_port *get_iface_port(
    const struct ovsrec_interface *, const struct ovsrec_bridge *);

char *get_mirror_tunnel_type(const struct sbrec_mirror *);

static void build_ovs_mirror_ports(const struct ovsrec_bridge *,
                                   struct shash *ovs_mirror_ports);

void
mirror_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_mirrors);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_mirror);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_mirror_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_mirror_col_output_port);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_mirror_col_select_dst_port);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_mirror_col_select_src_port);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_mirror_col_external_ids);
}


void
queue_init(void)
{
}

void
queue_destroy(void)
{
}



/* 34359738360 == (2^32 - 1) * 8.  netdev_set_qos() doesn't support
 * 64-bit rate netlink attributes, so the maximum value is 2^32 - 1
 * bytes. The 'max-rate' config option is in bits, so multiplying by 8.
 * Without setting max-rate the reported link speed will be used, which
 * can be unrecognized for certain NICs or reported too low for virtual
 * interfaces. */
#define OVN_QOS_MAX_RATE    34359738360ULL
static void
mod_ovs_qos_table_entry_queue(const struct ovsrec_port *port,const struct sbrec_port_binding *pb, const char *iface_id)
{
    struct smap external_ids = SMAP_INITIALIZER(&external_ids);
    struct smap other_config = SMAP_INITIALIZER(&other_config);
    
    const struct ovsrec_qos *qos = port->qos;
    if (qos && !smap_get_bool(&qos->external_ids, "ovn_qos", false)) {
        /* External configured QoS, do not overwrite it. */
        // VLOG_INFO("External QoS...............");
        return;
    }

    if (!qos) {
        return;
        
    }
    // VLOG_INFO("mod");

    unsigned long long curr_max_rate = 0;
    bool new_def_rate = false;
    struct ovsrec_queue *queue_qos;
    for (size_t i = 0; i < qos->n_queues; i++) {
        // bool check_queue = false;
        queue_qos = qos->value_queues[i];
        if (!queue_qos) {
            continue;
        }
        struct sbrec_queue *queue;
        for (size_t k = 0; k < pb->n_queue_rules; k++) { 
            if(strcmp(iface_id,pb->logical_port)){
                continue;
            }
            queue = pb->queue_rules[k];
         
            int64_t queue_id = queue->id_queue;
            unsigned long long queue_max_rate = smap_get_ullong(
            &queue_qos->other_config, "max-rate", 0);
            if(curr_max_rate < queue_max_rate){
                curr_max_rate = queue_max_rate;
                new_def_rate = true;
            }

            // VLOG_INFO("Port_qos: %ld, Sb_queue: %ld",queue_id,queue->id_queue);
            if (queue_id != qos->key_queues[i])
                continue;
            // check_queue = true;

            char *match = queue->match;
            const char *match_queue = smap_get(
            &queue_qos->other_config, "match");

            if(strcmp(match,match_queue))
                continue;

            
            unsigned long long  min_rate = queue->value_bandwidth_min[0];
            unsigned long long  max_rate = queue->value_bandwidth_max[0];
            unsigned long long   burst = queue->value_bandwidth_max[1];



            
            unsigned long long queue_min_rate = smap_get_ullong(
            &queue_qos->other_config, "min-rate", 0);
            unsigned long long queue_burst = smap_get_ullong(
            &queue_qos->other_config, "burst", 0);
            if (max_rate == queue_max_rate && min_rate == queue_min_rate && burst == queue_burst )
                continue;

            

            smap_add_format(&other_config, "max-rate", "%llu", max_rate);
            smap_add_format(&other_config, "min-rate", "%llu", min_rate);
            smap_add_format(&other_config, "burst", "%llu", burst);
            smap_add_format(&other_config, "match", "%s", match);
            ovsrec_queue_verify_other_config(queue_qos);
            ovsrec_queue_set_other_config(queue_qos, &other_config);
            smap_add(&external_ids, "ovn_port", pb->logical_port);
            ovsrec_queue_verify_external_ids(queue_qos);
            ovsrec_queue_set_external_ids(queue_qos, &external_ids);

            smap_clear(&other_config);
            smap_clear(&external_ids);
            VLOG_INFO("mod config");



            break;
        }
        //     if (!check_queue){
        //         ovsrec_qos_update_queues_delkey(qos, qos->key_queues[i]);
        //         ovsrec_queue_delete(queue_qos);
        // }
        // return;
    }
    if(new_def_rate){
        smap_add_format(&other_config, "max-rate", "%lld", curr_max_rate);
        ovsrec_qos_set_other_config(qos, &other_config);
        smap_clear(&other_config);

        smap_add(&external_ids, "ovn_qos", "true");
        ovsrec_qos_set_external_ids(qos, &external_ids);
        smap_clear(&external_ids);
    }

}

static void
del_ovs_qos_table_entry_queue(const struct ovsrec_port *port)
{
    struct smap external_ids = SMAP_INITIALIZER(&external_ids);
    struct smap other_config = SMAP_INITIALIZER(&other_config);

    

    const struct ovsrec_qos *qos = port->qos;
    if (qos && !smap_get_bool(&qos->external_ids, "ovn_qos", false)) {
        /* External configured QoS, do not overwrite it. */
        // VLOG_INFO("External QoS...............");
        return;
    }

    if (!qos) {
        return;
        
    }
    for (size_t i = 0; i < qos->n_queues; i++) {
            struct ovsrec_queue *queue = qos->value_queues[i];
            if (!queue) {
                continue;
            }
            ovsrec_qos_update_queues_delkey(qos, qos->key_queues[i]);
            ovsrec_queue_delete(queue);

            
            // return;
        }
  
    VLOG_INFO("NUmber of qos queue ??: %ld",qos->n_queues);

    if (qos->n_queues == 1) {
       
            ovsrec_port_set_qos(port, NULL);
            ovsrec_qos_delete(qos);
        }
    if (qos->n_queues == 0){
        ovsrec_port_set_qos(port, NULL);
        ovsrec_qos_delete(qos);

    }

}


void
qos_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_qos);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_qos);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_qos_col_external_ids);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_qos_col_other_config);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_qos_col_queues);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_qos_col_type);
}
    


void
queue_run(struct ovsdb_idl_txn *ovs_idl_txn,
             const struct sbrec_port_binding_table *sbrec_pb_table,
             const struct ovsrec_bridge *br_int)
{   
    if (!ovs_idl_txn) {
        return;
    }
    // struct shash ovs_queues = SHASH_INITIALIZER(&sb_queovs_queuesues);

    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (pb, sbrec_pb_table) {
        if ( pb->n_queue_rules == 0){
            size_t i;
            for (i = 0; i < br_int->n_ports; i++) {
                    const struct ovsrec_port *port_rec = br_int->ports[i];
                    const char *iface_id;
                    size_t j;
                    // bool qos_install = false;

                    if (!strcmp(port_rec->name, br_int->name)) {
                        continue;
                    }
                    
                    for (j = 0; j < port_rec->n_interfaces; j++) {
                        const struct ovsrec_interface *iface_rec;

                        iface_rec = port_rec->interfaces[j];
                        iface_id = smap_get(&iface_rec->external_ids, "iface-id");
                        int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;
                        if (iface_id && ofport > 0 && !strcmp(iface_id,pb->logical_port)) {
                            del_ovs_qos_table_entry_queue(port_rec);
                            // VLOG_INFO("Logical: %s",pb->logical_port);
                            // qos_install = true;
                            // break;
                        }
                    }
                    // if(qos_install==true){
                    //     break;
                    // }
                }
            continue;
        }
    
            size_t i;
            for (i = 0; i < br_int->n_ports; i++) {
                    const struct ovsrec_port *port_rec = br_int->ports[i];
                    const char *iface_id;
                    size_t j;


                    if (!strcmp(port_rec->name, br_int->name)) {
                        continue;
                    }
                    
                    for (j = 0; j < port_rec->n_interfaces; j++) {
                        const struct ovsrec_interface *iface_rec;

                        iface_rec = port_rec->interfaces[j];
                        iface_id = smap_get(&iface_rec->external_ids, "iface-id");
                        int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;
                        if (iface_id && ofport > 0) {
                            mod_ovs_qos_table_entry_queue(port_rec,pb,iface_id);
                            // VLOG_INFO("Logical: %s",pb->logical_port);

                        }
                    }
                    
                }

        
        
    }

}



// void
// queue_run(struct ovsdb_idl_txn *ovs_idl_txn,
//              const struct ovsrec_bridge *br_int,
//              struct shash *local_bindings)
// {   
//     if (!ovs_idl_txn) {
//         return;
//     }
//     // struct shash ovs_queues = SHASH_INITIALIZER(&sb_queovs_queuesues);

//     struct shash_node *node;
//     SHASH_FOR_EACH (node, local_bindings) {
//         struct local_binding *lbinding = node->data;
//         const struct sbrec_port_binding *pb =
//             local_binding_get_primary_pb(local_bindings, lbinding->name);
//         if (!pb) {
//             continue;
//         }
//         if ( pb->n_queue_rules == 0){
//             size_t i;
//             for (i = 0; i < br_int->n_ports; i++) {
//                     const struct ovsrec_port *port_rec = br_int->ports[i];
//                     const char *iface_id;
//                     size_t j;
//                     // bool qos_install = false;

//                     // if (!strcmp(port_rec->name, br_int->name)) {
//                     //     continue;
//                     // }
                    
//                     for (j = 0; j < port_rec->n_interfaces; j++) {
//                         const struct ovsrec_interface *iface_rec;

//                         iface_rec = port_rec->interfaces[j];
//                         iface_id = smap_get(&iface_rec->external_ids, "iface-id");
//                         // int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;
//                         if (iface_id && !strcmp(iface_id,pb->logical_port)) {
//                             del_ovs_qos_table_entry_queue(port_rec);
//                             // qos_install = true;
//                             // break;
//                         }
//                     }
//                     // if(qos_install==true){
//                     //     break;
//                     // }
//                 }
//             return;
//         }
    
//             size_t i;
//             for (i = 0; i < br_int->n_ports; i++) {
//                     const struct ovsrec_port *port_rec = br_int->ports[i];
//                     const char *iface_id;
//                     size_t j;


//                     if (!strcmp(port_rec->name, br_int->name)) {
//                         continue;
//                     }
                    
//                     for (j = 0; j < port_rec->n_interfaces; j++) {
//                         const struct ovsrec_interface *iface_rec;

//                         iface_rec = port_rec->interfaces[j];
//                         iface_id = smap_get(&iface_rec->external_ids, "iface-id");
//                         int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;
//                         if (iface_id && ofport > 0) {
//                             mod_ovs_qos_table_entry_queue(port_rec,pb,iface_id);
//                             VLOG_INFO("MOD OR DEL QUEUE");

//                         }
//                     }
                    
//                 }


//     }

        
        
    

// }





void
mirror_init(void)
{
}

void
mirror_destroy(void)
{
}

void
mirror_run(struct ovsdb_idl_txn *ovs_idl_txn,
           const struct ovsrec_mirror_table *ovs_mirror_table,
           const struct sbrec_mirror_table *sb_mirror_table,
           const struct ovsrec_bridge *br_int,
           struct shash *local_bindings)
{
    if (!ovs_idl_txn) {
        return;
    }

    struct shash ovn_mirrors = SHASH_INITIALIZER(&ovn_mirrors);
    struct shash ovs_local_mirror_ports =
        SHASH_INITIALIZER(&ovs_local_mirror_ports);

    /* Iterate through sb mirrors and build the 'ovn_mirrors'. */
    const struct sbrec_mirror *sb_mirror;
    SBREC_MIRROR_TABLE_FOR_EACH (sb_mirror, sb_mirror_table) {
        struct ovn_mirror *m = ovn_mirror_create(sb_mirror->name);
        m->sb_mirror = sb_mirror;
        ovn_mirror_add(&ovn_mirrors, m);
    }

    /* Iterate through ovs mirrors and add to the 'ovn_mirrors'. */
    const struct ovsrec_mirror *ovs_mirror;
    OVSREC_MIRROR_TABLE_FOR_EACH (ovs_mirror, ovs_mirror_table) {
        bool ovn_owned_mirror = smap_get_bool(&ovs_mirror->external_ids,
                                              "ovn-owned", false);
        if (!ovn_owned_mirror) {
            continue;
        }

        struct ovn_mirror *m = ovn_mirror_find(&ovn_mirrors, ovs_mirror->name);
        if (!m) {
            m = ovn_mirror_create(ovs_mirror->name);
            ovn_mirror_add(&ovn_mirrors, m);
        }
        m->ovs_mirror = ovs_mirror;
    }

    if (shash_is_empty(&ovn_mirrors)) {
        shash_destroy(&ovn_mirrors);
        return;
    }

    build_ovs_mirror_ports(br_int, &ovs_local_mirror_ports);

    /* Iterate through the local bindings and if the local binding's 'pb' has
     * mirrors associated, add it to the ovn_mirror. */
    struct shash_node *node;
    SHASH_FOR_EACH (node, local_bindings) {
        struct local_binding *lbinding = node->data;
        const struct sbrec_port_binding *pb =
            local_binding_get_primary_pb(local_bindings, lbinding->name);
        if (!pb || !pb->n_mirror_rules) {
            continue;
        }

        for (size_t i = 0; i < pb->n_mirror_rules; i++) {
            struct ovn_mirror *m = ovn_mirror_find(&ovn_mirrors,
                                                   pb->mirror_rules[i]->name);
            ovs_assert(m);
            ovn_mirror_add_lport(m, lbinding);
        }
    }

    /* Iterate through the built 'ovn_mirrors' and
     * sync with the local ovsdb i.e.
     * create/update or delete the ovsrec mirror(s). */
     SHASH_FOR_EACH (node, &ovn_mirrors) {
        struct ovn_mirror *m = node->data;
        sync_ovn_mirror(m, ovs_idl_txn, br_int, &ovs_local_mirror_ports);
     }

    SHASH_FOR_EACH_SAFE (node, &ovn_mirrors) {
        ovn_mirror_delete(node->data);
        shash_delete(&ovn_mirrors, node);
    }

    shash_destroy(&ovn_mirrors);
    shash_destroy(&ovs_local_mirror_ports);
}

/* Static functions. */

/* Builds mapping from mirror-id to ovsrec_port.
 */
static void
build_ovs_mirror_ports(const struct ovsrec_bridge *br_int,
                       struct shash *ovs_mirror_ports)
{
    int i;
    for (i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_int->ports[i];
        int j;

        if (!strcmp(port_rec->name, br_int->name)) {
            continue;
        }

        for (j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;

            iface_rec = port_rec->interfaces[j];
            const char *mirror_id = smap_get(&iface_rec->external_ids,
                                             "mirror-id");
            if (mirror_id) {
                const struct ovsrec_port *p = shash_find_data(ovs_mirror_ports,
                                                              mirror_id);
                if (!p) {
                    shash_add(ovs_mirror_ports, mirror_id, port_rec);
                } else {
                    static struct vlog_rate_limit rl =
                        VLOG_RATE_LIMIT_INIT(1, 5);
                    VLOG_WARN_RL(
                        &rl,
                        "Invalid configuration: same mirror-id [%s] is "
                        "configured on interfaces of ports: [%s] and [%s]. "
                        "Ignoring the configuration on interface [%s]",
                        mirror_id, port_rec->name, p->name, iface_rec->name);
                }
            }
        }
    }
}

static struct ovn_mirror *
ovn_mirror_create(char *mirror_name)
{
    struct ovn_mirror *m = xzalloc(sizeof *m);
    m->name = xstrdup(mirror_name);
    ovs_list_init(&m->mirror_src_lports);
    ovs_list_init(&m->mirror_dst_lports);
    return m;
}

static void
ovn_mirror_add(struct shash *ovn_mirrors, struct ovn_mirror *m)
{
    shash_add(ovn_mirrors, m->name, m);
}

static struct ovn_mirror *
ovn_mirror_find(struct shash *ovn_mirrors, const char *mirror_name)
{
    return shash_find_data(ovn_mirrors, mirror_name);
}

static void
ovn_mirror_delete(struct ovn_mirror *m)
{
    free(m->name);
    struct mirror_lport *m_lport;
    LIST_FOR_EACH_POP (m_lport, list_node, &m->mirror_src_lports) {
        free(m_lport);
    }

    LIST_FOR_EACH_POP (m_lport, list_node, &m->mirror_dst_lports) {
        free(m_lport);
    }

    free(m);
}

static void
ovn_mirror_add_lport(struct ovn_mirror *m, struct local_binding *lbinding)
{
    if (!strcmp(m->sb_mirror->filter, "from-lport") ||
        !strcmp(m->sb_mirror->filter, "both")) {
        struct mirror_lport *m_lport = xzalloc(sizeof *m_lport);
        m_lport->lbinding = lbinding;
        ovs_list_push_back(&m->mirror_src_lports, &m_lport->list_node);
    }

    if (!strcmp(m->sb_mirror->filter, "to-lport") ||
        !strcmp(m->sb_mirror->filter, "both")) {
        struct mirror_lport *m_lport = xzalloc(sizeof *m_lport);
        m_lport->lbinding = lbinding;
        ovs_list_push_back(&m->mirror_dst_lports, &m_lport->list_node);
    }
}

static void
set_mirror_iface_options(struct ovsrec_interface *iface,
                         const struct sbrec_mirror *sb_mirror)
{
    struct smap options = SMAP_INITIALIZER(&options);
    char *key;

    key = xasprintf("%ld", (long int) sb_mirror->index);
    smap_add(&options, "remote_ip", sb_mirror->sink);
    smap_add(&options, "key", key);
    if (!strcmp(sb_mirror->type, "erspan")) {
        /* Set the ERSPAN index */
        smap_add(&options, "erspan_idx", key);
        smap_add(&options, "erspan_ver", "1");
    }
    ovsrec_interface_set_options(iface, &options);

    free(key);
    smap_destroy(&options);
}

char *
get_mirror_tunnel_type(const struct sbrec_mirror *sb_mirror)
{
    bool is_ipv6 = addr_is_ipv6(sb_mirror->sink);

    return xasprintf(is_ipv6 ? "ip6%s" : "%s", sb_mirror->type);
}

static void
check_and_update_interface_table(struct ovn_mirror *m,
                                 struct ovsdb_idl_txn *ovs_idl_txn,
                                 const struct ovsrec_bridge *br_int)
{
    if (!m->ovs_mirror->output_port) {
        const struct ovsrec_port *mirror_port =
            create_mirror_port(m, ovs_idl_txn, br_int);
        ovsrec_mirror_set_output_port(m->ovs_mirror, mirror_port);
        return;
    }
    struct ovsrec_interface *iface = m->ovs_mirror->output_port->interfaces[0];
    char *type = get_mirror_tunnel_type(m->sb_mirror);

    if (strcmp(type, iface->type)) {
        ovsrec_interface_set_type(iface, type);
    }
    set_mirror_iface_options(iface, m->sb_mirror);
    free(type);
}

static void
sync_ovn_mirror(struct ovn_mirror *m, struct ovsdb_idl_txn *ovs_idl_txn,
                const struct ovsrec_bridge *br_int,
                struct shash *ovs_mirror_ports)
{
    if (should_delete_ovs_mirror(m)) {
        /* Delete the ovsrec mirror. */
        delete_ovs_mirror(m, br_int);
        return;
    }

    if (ovs_list_is_empty(&m->mirror_src_lports) &&
            ovs_list_is_empty(&m->mirror_dst_lports)) {
        /* Nothing to do. */
        return;
    }

    if (m->sb_mirror && !m->ovs_mirror) {
        create_ovs_mirror(m, ovs_idl_txn, br_int, ovs_mirror_ports);
        if (!m->ovs_mirror) {
            return;
        }
    } else if (strcmp(m->sb_mirror->type, "local")) {
        check_and_update_interface_table(m, ovs_idl_txn, br_int);

        /* For upgradability, set the "ovn-owned" in case it was not set when
         * the port was created. */
        if (!smap_get_bool(&m->ovs_mirror->output_port->external_ids,
                                   "ovn-owned", false)) {
            ovsrec_port_update_external_ids_setkey(m->ovs_mirror->output_port,
                                                   "ovn-owned", "true");
        }
    } else {
        /* type is local, check mirror-id */
        const struct ovsrec_port *mirror_port =
            shash_find_data(ovs_mirror_ports, m->sb_mirror->sink);
        if (!mirror_port) {
            delete_ovs_mirror(m, br_int);
            return;
        }
        if (mirror_port != m->ovs_mirror->output_port) {
            ovsrec_mirror_set_output_port(m->ovs_mirror, mirror_port);
        }
    }

    sync_ovs_mirror_ports(m, br_int);
}

static bool
should_delete_ovs_mirror(struct ovn_mirror *m)
{
    if (!m->ovs_mirror) {
        return false;
    }

    if (m->ovs_mirror && !m->sb_mirror) {
        return true;
    }

    return (ovs_list_is_empty(&m->mirror_src_lports) &&
            ovs_list_is_empty(&m->mirror_dst_lports));
}

static const struct ovsrec_port *
get_iface_port(const struct ovsrec_interface *iface,
               const struct ovsrec_bridge *br_int)
{
    for (size_t i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *p = br_int->ports[i];
        for (size_t j = 0; j < p->n_interfaces; j++) {
            if (!strcmp(iface->name, p->interfaces[j]->name)) {
                return p;
            }
        }
    }
    return NULL;
}

static struct ovsrec_port *
create_mirror_port(struct ovn_mirror *m, struct ovsdb_idl_txn *ovs_idl_txn,
                   const struct ovsrec_bridge *br_int)
{
    struct ovsrec_interface *iface = ovsrec_interface_insert(ovs_idl_txn);
    char *port_name = xasprintf("ovn-%s", m->name);

    ovsrec_interface_set_name(iface, port_name);

    char *type = get_mirror_tunnel_type(m->sb_mirror);
    ovsrec_interface_set_type(iface, type);
    set_mirror_iface_options(iface, m->sb_mirror);
    free(type);

    struct ovsrec_port *port = ovsrec_port_insert(ovs_idl_txn);
    ovsrec_port_set_name(port, port_name);
    ovsrec_port_set_interfaces(port, &iface, 1);
    ovsrec_bridge_update_ports_addvalue(br_int, port);

    const struct smap port_external_ids =
        SMAP_CONST1(&port_external_ids, "ovn-owned", "true");
    ovsrec_port_set_external_ids(port, &port_external_ids);

    free(port_name);
    return port;
}

static void
create_ovs_mirror(struct ovn_mirror *m, struct ovsdb_idl_txn *ovs_idl_txn,
                  const struct ovsrec_bridge *br_int,
                  struct shash *ovs_mirror_ports)
{
    const struct ovsrec_port *mirror_port;
    if (!strcmp(m->sb_mirror->type, "local")) {
        mirror_port = shash_find_data(ovs_mirror_ports, m->sb_mirror->sink);
        if (!mirror_port) {
            return;
        }
    } else {
        mirror_port = create_mirror_port(m, ovs_idl_txn, br_int);
    }

    m->ovs_mirror = ovsrec_mirror_insert(ovs_idl_txn);
    ovsrec_mirror_set_name(m->ovs_mirror, m->name);
    ovsrec_mirror_set_output_port(m->ovs_mirror, mirror_port);

    const struct smap external_ids =
        SMAP_CONST1(&external_ids, "ovn-owned", "true");
    ovsrec_mirror_set_external_ids(m->ovs_mirror, &external_ids);

    ovsrec_bridge_update_mirrors_addvalue(br_int, m->ovs_mirror);
}

static void
sync_ovs_mirror_ports(struct ovn_mirror *m, const struct ovsrec_bridge *br_int)
{
    struct mirror_lport *m_lport;

    if (ovs_list_is_empty(&m->mirror_src_lports)) {
        ovsrec_mirror_set_select_src_port(m->ovs_mirror, NULL, 0);
    } else {
        size_t n_lports = ovs_list_size(&m->mirror_src_lports);
        struct ovsrec_port **ovs_ports = xmalloc(sizeof *ovs_ports * n_lports);

        size_t i = 0;
        LIST_FOR_EACH (m_lport, list_node, &m->mirror_src_lports) {
            const struct ovsrec_port *p =
                get_iface_port(m_lport->lbinding->iface, br_int);
            ovs_assert(p);
            ovs_ports[i++] = (struct ovsrec_port *) p;
        }

        ovsrec_mirror_set_select_src_port(m->ovs_mirror, ovs_ports, n_lports);
        free(ovs_ports);
    }

    if (ovs_list_is_empty(&m->mirror_dst_lports)) {
        ovsrec_mirror_set_select_dst_port(m->ovs_mirror, NULL, 0);
    } else {
        size_t n_lports = ovs_list_size(&m->mirror_dst_lports);
        struct ovsrec_port **ovs_ports = xmalloc(sizeof *ovs_ports * n_lports);

        size_t i = 0;
        LIST_FOR_EACH (m_lport, list_node, &m->mirror_dst_lports) {
            const struct ovsrec_port *p =
                get_iface_port(m_lport->lbinding->iface, br_int);
            ovs_assert(p);
            ovs_ports[i++] = (struct ovsrec_port *) p;
        }

        ovsrec_mirror_set_select_dst_port(m->ovs_mirror, ovs_ports, n_lports);
        free(ovs_ports);
    }
}

static void
delete_ovs_mirror(struct ovn_mirror *m, const struct ovsrec_bridge *br_int)
{
    ovsrec_bridge_update_mirrors_delvalue(br_int, m->ovs_mirror);
    if (m->ovs_mirror->output_port) {
        bool ovn_owned =
            smap_get_bool(&m->ovs_mirror->output_port->external_ids,
                          "ovn-owned", false);
        if (ovn_owned) {
            ovsrec_bridge_update_ports_delvalue(br_int,
                                                m->ovs_mirror->output_port);
            ovsrec_port_delete(m->ovs_mirror->output_port);
        }
    }
    ovsrec_mirror_delete(m->ovs_mirror);
}
