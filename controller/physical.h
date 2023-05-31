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

#ifndef OVN_PHYSICAL_H
#define OVN_PHYSICAL_H 1

/* Logical/Physical Translation
 * ============================
 *
 * This module implements physical-to-logical and logical-to-physical
 * translation as separate OpenFlow tables that run before the ingress pipeline
 * and after the egress pipeline, respectively, as well as to connect the
 * two pipelines.
 */

#include "openvswitch/meta-flow.h"

struct hmap;
struct ovsdb_idl_index;
struct ovsrec_bridge;
struct simap;
struct sbrec_multicast_group_table;
struct sbrec_port_binding_table;
struct sset;
struct local_nonvif_data;

/* OVN Geneve option information.
 *
 * Keep these in sync with the documentation in ovn-architecture(7). */
#define OVN_GENEVE_CLASS 0x0102  /* Assigned Geneve class for OVN. */
#define OVN_GENEVE_TYPE 0x80     /* Critical option. */
#define OVN_GENEVE_LEN 4

struct physical_debug {
    uint32_t collector_set_id;
    uint32_t obs_domain_id;
};

struct physical_ctx {
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath;
    const struct sbrec_port_binding_table *port_binding_table;
    const struct ovsrec_interface_table *ovs_interface_table;
    const struct sbrec_multicast_group_table *mc_group_table;
    const struct ovsrec_bridge *br_int;
    const struct sbrec_chassis_table *chassis_table;
    const struct sbrec_chassis *chassis;
    const struct sset *active_tunnels;
    const struct if_status_mgr *if_mgr;
    struct hmap *local_datapaths;
    struct sset *local_lports;
    const struct simap *ct_zones;
    enum mf_field_id mff_ovn_geneve;
    struct shash *local_bindings;
    struct simap *patch_ofports;
    struct hmap *chassis_tunnels;
    struct physical_debug debug;
};

void physical_register_ovs_idl(struct ovsdb_idl *);
void physical_run(struct physical_ctx *,
                  struct ovn_desired_flow_table *);
void physical_handle_mc_group_changes(struct physical_ctx *,
                                      struct ovn_desired_flow_table *);
bool physical_handle_flows_for_lport(const struct sbrec_port_binding *,
                                     bool removed,
                                     struct physical_ctx *,
                                     struct ovn_desired_flow_table *);
#endif /* controller/physical.h */
