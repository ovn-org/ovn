
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

#ifndef PINCTRL_H
#define PINCTRL_H 1

#include <stdint.h>

#include "lib/sset.h"
#include "openvswitch/list.h"
#include "openvswitch/meta-flow.h"

struct hmap;
struct shash;
struct lport_index;
struct ovsdb_idl;
struct ovsdb_idl_index;
struct ovsdb_idl_txn;
struct ovsrec_bridge;
struct ovsrec_open_vswitch_table;
struct sbrec_chassis;
struct sbrec_dns_table;
struct sbrec_controller_event_table;
struct sbrec_service_monitor_table;
struct sbrec_bfd_table;
struct sbrec_port_binding;
struct sbrec_mac_binding_table;

void pinctrl_init(void);
void pinctrl_run(struct ovsdb_idl_txn *ovnsb_idl_txn,
                 struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                 struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                 struct ovsdb_idl_index *sbrec_port_binding_by_key,
                 struct ovsdb_idl_index *sbrec_port_binding_by_name,
                 struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                 struct ovsdb_idl_index *sbrec_igmp_groups,
                 struct ovsdb_idl_index *sbrec_ip_multicast_opts,
                 struct ovsdb_idl_index *sbrec_fdb_by_dp_key_mac,
                 const struct sbrec_dns_table *,
                 const struct sbrec_controller_event_table *,
                 const struct sbrec_service_monitor_table *,
                 const struct sbrec_mac_binding_table *,
                 const struct sbrec_bfd_table *,
                 const struct ovsrec_bridge *, const struct sbrec_chassis *,
                 const struct hmap *local_datapaths,
                 const struct sset *active_tunnels,
                 const struct shash *local_active_ports_ipv6_pd,
                 const struct shash *local_active_ports_ras,
                 const struct ovsrec_open_vswitch_table *ovs_table);
void pinctrl_wait(struct ovsdb_idl_txn *ovnsb_idl_txn);
void pinctrl_destroy(void);
void pinctrl_set_br_int_name(const char *br_int_name);
void pinctrl_update(const struct ovsdb_idl *idl, const char *br_int_name);

struct activated_port {
    uint32_t dp_key;
    uint32_t port_key;
    struct ovs_list list;
};

void tag_port_as_activated_in_engine(struct activated_port *ap);
struct ovs_list *get_ports_to_activate_in_engine(void);
bool pinctrl_is_port_activated(int64_t dp_key, int64_t port_key);
#endif /* controller/pinctrl.h */
