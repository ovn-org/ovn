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

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

/* OVS includes. */
#include "include/openvswitch/hmap.h"
#include "include/openvswitch/shash.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "en-bridge-data.h"
#include "lib/ovn-br-idl.h"

VLOG_DEFINE_THIS_MODULE(en_bridge_data);

static void ovn_bridges_init(struct shash *);
static void ovn_bridges_cleanup(struct shash *);
static void ovn_bridges_run(const struct ovnbrrec_bridge_table *,
                            struct shash *bridges,
                            struct ovsdb_idl_index *);
static void ovn_bridge_destroy(struct ovn_bridge *);
static const struct ovsrec_bridge *ovsbridge_lookup_by_name(
    struct ovsdb_idl_index *ovsrec_bridge_by_name,
    const char *name);
static void build_ovn_bridge_iface_simap(struct ovn_bridge *);

void *
en_bridge_data_init(struct engine_node *node OVS_UNUSED,
                    struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_bridge_data *data = xzalloc(sizeof *data);
    ovn_bridges_init(&data->bridges);

    return data;
}

void
en_bridge_data_cleanup(void *data_)
{
    struct ed_type_bridge_data *data = data_;
    ovn_bridges_cleanup(&data->bridges);
}

enum engine_node_state
en_bridge_data_run(struct engine_node *node, void *data_)
{
    const struct ovnbrrec_bridge_table *ovnbrrec_br_table =
        EN_OVSDB_GET(engine_get_input("BR_bridge", node));
    struct ovsdb_idl_index *ovsrec_bridge_by_name =
        engine_ovsdb_node_get_index(engine_get_input("OVS_bridge", node),
                                    "name");
    struct ed_type_bridge_data *data = data_;

    ovn_bridges_cleanup(&data->bridges);
    ovn_bridges_init(&data->bridges);
    ovn_bridges_run(ovnbrrec_br_table, &data->bridges, ovsrec_bridge_by_name);

    return EN_UPDATED;
}

/* Static functions. */
static void
ovn_bridges_init(struct shash *bridges)
{
    shash_init(bridges);
}

static void
ovn_bridges_cleanup(struct shash *bridges)
{
    struct shash_node *shash_node;
    SHASH_FOR_EACH_SAFE (shash_node, bridges) {
        ovn_bridge_destroy(shash_node->data);
    }
    shash_destroy(bridges);
}

static void
ovn_bridges_run(const struct ovnbrrec_bridge_table *br_table,
               struct shash *bridges,
               struct ovsdb_idl_index *ovsrec_bridge_by_name)
{
    const struct ovnbrrec_bridge *db_br;
    OVNBRREC_BRIDGE_TABLE_FOR_EACH (db_br, br_table) {
        struct ovn_bridge *br = xzalloc(sizeof *br);
        br->db_br = db_br;
        br->key = db_br->header_.uuid;
        simap_init(&br->ovs_ifaces);
        shash_add(bridges, db_br->name, br);

        const struct ovsrec_bridge *ovs_br =
            ovsbridge_lookup_by_name(ovsrec_bridge_by_name, db_br->name);

        if (!ovs_br) {
            continue;
        }

        br->ovs_br = ovs_br;
        build_ovn_bridge_iface_simap(br);
    }
}

static void
ovn_bridge_destroy(struct ovn_bridge *br)
{
    simap_destroy(&br->ovs_ifaces);
    free(br);
}

static const struct ovsrec_bridge *
ovsbridge_lookup_by_name(struct ovsdb_idl_index *ovsrec_bridge_by_name,
                         const char *name)
{
    struct ovsrec_bridge *target =
        ovsrec_bridge_index_init_row(ovsrec_bridge_by_name);
    ovsrec_bridge_index_set_name(target, name);

    const struct ovsrec_bridge *retval =
        ovsrec_bridge_index_find(ovsrec_bridge_by_name, target);
    ovsrec_bridge_index_destroy_row(target);

    return retval;
}

static void
build_ovn_bridge_iface_simap(struct ovn_bridge *br)
{
    ovs_assert(br->ovs_br);
    for (size_t i = 0; i < br->ovs_br->n_ports; i++) {
        const struct ovsrec_port *port_rec = br->ovs_br->ports[i];

        for (size_t j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;

            iface_rec = port_rec->interfaces[j];
            int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;
            if (ofport) {
                simap_put(&br->ovs_ifaces, iface_rec->name, ofport);
            }
        }
    }
}
