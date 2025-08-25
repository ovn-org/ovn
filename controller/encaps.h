/* Copyright (c) 2015 Nicira, Inc.
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

#ifndef OVN_ENCAPS_H
#define OVN_ENCAPS_H 1

#include <stdbool.h>

/*
 * Given there could be multiple tunnels with different IPs to the same
 * chassis we annotate the external_ids:ovn-chassis-id in tunnel port with
 * <chassis_name>@<remote IP>%<local IP>. The external_id key
 * "ovn-chassis-id" is kept for backward compatibility.
 *
 * For flow-based tunnels, we use the special value "flow" to identify
 * shared tunnel ports that handle dynamic endpoint resolution.
 */
#define OVN_TUNNEL_ID "ovn-chassis-id"

struct ovsdb_idl;
struct ovsdb_idl_txn;
struct ovsrec_bridge;
struct ovsrec_bridge_table;
struct sbrec_chassis_table;
struct sbrec_chassis;
struct sbrec_sb_global;
struct ovsrec_open_vswitch_table;
struct sset;

void encaps_register_ovs_idl(struct ovsdb_idl *);
void encaps_run(struct ovsdb_idl_txn *ovs_idl_txn,
                struct ovsdb_idl_txn *ovnsb_idl_txn,
                const struct ovsrec_bridge *br_int,
                const struct sbrec_chassis_table *,
                const struct sbrec_chassis *,
                const struct sbrec_sb_global *,
                const struct ovsrec_open_vswitch_table *,
                const struct sset *transport_zones,
                const struct ovsrec_bridge_table *bridge_table);

bool is_flow_based_tunnels_enabled(
    const struct ovsrec_open_vswitch_table *ovs_table,
    const struct sbrec_chassis *chassis);

bool encaps_cleanup(struct ovsdb_idl_txn *ovs_idl_txn,
                    const struct ovsrec_bridge *br_int);

char *encaps_tunnel_id_create(const char *chassis_id,
                              const char *remote_encap_ip,
                              const char *local_encap_ip);
bool  encaps_tunnel_id_parse(const char *tunnel_id, char **chassis_id,
                             char **remote_encap_ip, char **local_encap_ip);
bool  encaps_tunnel_id_match(const char *tunnel_id, const char *chassis_id,
                             const char *remote_encap_ip,
                             const char *local_encap_ip);

void encaps_destroy(void);

#endif /* controller/encaps.h */
