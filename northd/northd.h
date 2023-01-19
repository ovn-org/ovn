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
#ifndef NORTHD_H
#define NORTHD_H 1

#include "ovsdb-idl.h"

#include "openvswitch/hmap.h"

struct northd_input {
    /* Northbound table references */
    const struct nbrec_nb_global_table *nbrec_nb_global_table;
    const struct nbrec_logical_switch_table *nbrec_logical_switch;
    const struct nbrec_logical_router_table *nbrec_logical_router;
    const struct nbrec_load_balancer_table *nbrec_load_balancer_table;
    const struct nbrec_port_group_table *nbrec_port_group_table;
    const struct nbrec_address_set_table *nbrec_address_set_table;
    const struct nbrec_meter_table *nbrec_meter_table;
    const struct nbrec_acl_table *nbrec_acl_table;

    /* Southbound table references */
    const struct sbrec_sb_global_table *sbrec_sb_global_table;
    const struct sbrec_datapath_binding_table *sbrec_datapath_binding_table;
    const struct sbrec_port_binding_table *sbrec_port_binding_table;
    const struct sbrec_mac_binding_table *sbrec_mac_binding_table;
    const struct sbrec_ha_chassis_group_table *sbrec_ha_chassis_group_table;
    const struct sbrec_chassis_table *sbrec_chassis;
    const struct sbrec_fdb_table *sbrec_fdb_table;
    const struct sbrec_load_balancer_table *sbrec_load_balancer_table;
    const struct sbrec_service_monitor_table *sbrec_service_monitor_table;
    const struct sbrec_address_set_table *sbrec_address_set_table;
    const struct sbrec_port_group_table *sbrec_port_group_table;
    const struct sbrec_meter_table *sbrec_meter_table;
    const struct sbrec_dns_table *sbrec_dns_table;
    const struct sbrec_ip_multicast_table *sbrec_ip_multicast_table;
    const struct sbrec_chassis_private_table *sbrec_chassis_private_table;

    /* Indexes */
    struct ovsdb_idl_index *sbrec_chassis_by_name;
    struct ovsdb_idl_index *sbrec_chassis_by_hostname;
    struct ovsdb_idl_index *sbrec_ha_chassis_grp_by_name;
    struct ovsdb_idl_index *sbrec_ip_mcast_by_dp;
};

struct chassis_features {
    bool ct_no_masked_label;
    bool ct_lb_related;
};

struct northd_data {
    /* Global state for 'en-northd'. */
    struct hmap datapaths;
    struct hmap ports;
    struct hmap port_groups;
    struct shash meter_groups;
    struct hmap lbs;
    struct hmap bfd_connections;
    struct ovs_list lr_list;
    bool ovn_internal_version_changed;
    struct chassis_features features;
};

struct lflow_input {
    /* Northbound table references */
    const struct nbrec_bfd_table *nbrec_bfd_table;

    /* Southbound table references */
    const struct sbrec_bfd_table *sbrec_bfd_table;
    const struct sbrec_logical_flow_table *sbrec_logical_flow_table;
    const struct sbrec_multicast_group_table *sbrec_multicast_group_table;
    const struct sbrec_igmp_group_table *sbrec_igmp_group_table;

    /* Indexes */
    struct ovsdb_idl_index *sbrec_mcast_group_by_name_dp;

    const struct hmap *datapaths;
    const struct hmap *ports;
    const struct hmap *port_groups;
    const struct shash *meter_groups;
    const struct hmap *lbs;
    const struct hmap *bfd_connections;
    const struct chassis_features *features;
    bool ovn_internal_version_changed;
};

void northd_run(struct northd_input *input_data,
                struct northd_data *data,
                struct ovsdb_idl_txn *ovnnb_txn,
                struct ovsdb_idl_txn *ovnsb_txn);
void northd_destroy(struct northd_data *data);
void northd_init(struct northd_data *data);
void northd_indices_create(struct northd_data *data,
                           struct ovsdb_idl *ovnsb_idl);
void build_lflows(struct lflow_input *input_data,
                  struct ovsdb_idl_txn *ovnsb_txn);
void build_bfd_table(struct lflow_input *input_data,
                     struct ovsdb_idl_txn *ovnsb_txn,
                     struct hmap *bfd_connections, struct hmap *ports);
void bfd_cleanup_connections(struct lflow_input *input_data,
                             struct hmap *bfd_map);

#endif /* NORTHD_H */
