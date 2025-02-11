/* Copyright (c) 2025, Red Hat, Inc.
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

#include "hash.h"
#include "lib/mac-binding-index.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "northd.h"
#include "openvswitch/hmap.h"
#include "util.h"

#include "en-global-config.h"
#include "en-ecmp-nexthop.h"
#include "en-northd.h"

struct ovsdb_idl_index *
ecmp_nexthop_index_create(struct ovsdb_idl *idl)
{
    return ovsdb_idl_index_create2(idl, &sbrec_ecmp_nexthop_col_nexthop,
                                   &sbrec_ecmp_nexthop_col_port);
}

struct ecmp_nexthop_data {
    struct hmap_node hmap_node;
    const struct sbrec_ecmp_nexthop *sb_ecmp_nh;
};

static struct ecmp_nexthop_data *
ecmp_nexthop_insert_entry(const struct sbrec_ecmp_nexthop *sb_ecmp_nh,
                          struct hmap *map)
{
    struct ecmp_nexthop_data *e = xmalloc(sizeof *e);
    e->sb_ecmp_nh = sb_ecmp_nh;

    uint32_t hash = hash_string(sb_ecmp_nh->nexthop, 0);
    hash = hash_add(hash, hash_int(sb_ecmp_nh->port->tunnel_key, 0));
    hmap_insert(map, &e->hmap_node, hash);

    return e;
}

static struct ecmp_nexthop_data *
ecmp_nexthop_find_entry(const char *nexthop,
                        const struct sbrec_port_binding *port,
                        struct hmap *map)
{
    uint32_t hash = hash_string(nexthop, 0);
    hash = hash_add(hash, hash_int(port->tunnel_key, 0));

    struct ecmp_nexthop_data *e;
    HMAP_FOR_EACH_WITH_HASH (e, hmap_node, hash, map) {
        const char *sb_port = e->sb_ecmp_nh->port->logical_port;
        const char *sb_nexthop = e->sb_ecmp_nh->nexthop;
        if (!strcmp(sb_nexthop, nexthop) && sb_port == port->logical_port) {
            return e;
        }
    }
    return NULL;
}

static void
build_ecmp_nexthop_table(
        struct ovsdb_idl_txn *ovnsb_txn,
        struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
        const struct hmap *routes,
        const struct sbrec_ecmp_nexthop_table *sbrec_ecmp_nexthop_table)
{
    struct hmap sb_nexthops_map = HMAP_INITIALIZER(&sb_nexthops_map);
    const struct sbrec_ecmp_nexthop *sb_ecmp_nexthop;
    SBREC_ECMP_NEXTHOP_TABLE_FOR_EACH (sb_ecmp_nexthop,
                                       sbrec_ecmp_nexthop_table) {
        ecmp_nexthop_insert_entry(sb_ecmp_nexthop, &sb_nexthops_map);
    }

    struct parsed_route *pr;
    HMAP_FOR_EACH (pr, key_node, routes) {
        if (!pr->ecmp_symmetric_reply) {
            continue;
        }

        if (!pr->out_port || !pr->out_port->sb) {
            continue;
        }

        /* This route has ecmp-symmetric-reply configured, it must be a
         * static route. */
        ovs_assert(pr->source == ROUTE_SOURCE_STATIC);

        struct ds nexthop_str = DS_EMPTY_INITIALIZER;
        ipv6_format_mapped(pr->nexthop, &nexthop_str);
        const char *nexthop = ds_cstr(&nexthop_str);

        struct ecmp_nexthop_data *e = ecmp_nexthop_find_entry(
                nexthop, pr->out_port->sb, &sb_nexthops_map);
        if (!e) {
            sb_ecmp_nexthop = sbrec_ecmp_nexthop_insert(ovnsb_txn);
            sbrec_ecmp_nexthop_set_nexthop(sb_ecmp_nexthop, nexthop);
            sbrec_ecmp_nexthop_set_port(sb_ecmp_nexthop, pr->out_port->sb);
            sbrec_ecmp_nexthop_set_datapath(sb_ecmp_nexthop,
                                            pr->out_port->sb->datapath);
            const struct sbrec_mac_binding *smb =
                mac_binding_lookup(sbrec_mac_binding_by_lport_ip,
                                   pr->out_port->sb->logical_port,
                                   nexthop);
            if (smb) {
                sbrec_ecmp_nexthop_set_mac(sb_ecmp_nexthop, smb->mac);
            }
        } else {
            hmap_remove(&sb_nexthops_map, &e->hmap_node);
            free(e);
        }
        ds_destroy(&nexthop_str);
    }

    struct ecmp_nexthop_data *e;
    HMAP_FOR_EACH_POP (e, hmap_node, &sb_nexthops_map) {
        sbrec_ecmp_nexthop_delete(e->sb_ecmp_nh);
        free(e);
    }
    hmap_destroy(&sb_nexthops_map);
}

static struct sbrec_ecmp_nexthop *
ecmp_nexthop_lookup(struct ovsdb_idl_index *sbrec_ecmp_by_nexthop,
                    const char *nexthop, const struct sbrec_port_binding *pb)
{
    struct sbrec_ecmp_nexthop *ecmp_nh =
            sbrec_ecmp_nexthop_index_init_row(sbrec_ecmp_by_nexthop);
    sbrec_ecmp_nexthop_index_set_nexthop(ecmp_nh, nexthop);
    sbrec_ecmp_nexthop_index_set_port(ecmp_nh, pb);
    struct sbrec_ecmp_nexthop *retval =
            sbrec_ecmp_nexthop_index_find(sbrec_ecmp_by_nexthop, ecmp_nh);
    sbrec_ecmp_nexthop_index_destroy_row(ecmp_nh);

    return retval;
}

bool
ecmp_nexthop_mac_binding_handler(struct engine_node *node,
                                 void *data OVS_UNUSED)
{
    const struct sbrec_mac_binding_table *mac_binding_table =
        EN_OVSDB_GET(engine_get_input("SB_mac_binding", node));
    struct ovsdb_idl_index *sbrec_port_binding_by_name =
        engine_ovsdb_node_get_index(engine_get_input("SB_port_binding", node),
                                    "sbrec_port_binding_by_name");
    struct ovsdb_idl_index *sbrec_ecmp_by_nexthop =
        engine_ovsdb_node_get_index(engine_get_input("SB_ecmp_nexthop", node),
                                    "sbrec_ecmp_nexthop_by_ip_and_port");

    const struct sbrec_mac_binding *smb;
    SBREC_MAC_BINDING_TABLE_FOR_EACH_TRACKED (smb, mac_binding_table) {
        if (sbrec_mac_binding_is_deleted(smb)) {
            continue;
        }
        const struct sbrec_port_binding *pb = lport_lookup_by_name(
                sbrec_port_binding_by_name, smb->logical_port);
        if (!pb) {
            continue;
        }
        struct sbrec_ecmp_nexthop *ecmp_nh = ecmp_nexthop_lookup(
                sbrec_ecmp_by_nexthop, smb->ip, pb);
        if (ecmp_nh) {
            sbrec_ecmp_nexthop_set_mac(ecmp_nh, smb->mac);
        }
    }

    return true;
}

void *
en_ecmp_nexthop_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_ecmp_nexthop_cleanup(void *data OVS_UNUSED)
{
}

void
en_ecmp_nexthop_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct routes_data *routes_data = engine_get_input_data("routes", node);
    const struct sbrec_ecmp_nexthop_table *sbrec_ecmp_nexthop_table =
        EN_OVSDB_GET(engine_get_input("SB_ecmp_nexthop", node));
    struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip =
        engine_ovsdb_node_get_index(engine_get_input("SB_mac_binding", node),
                                    "sbrec_mac_binding_by_lport_ip");
    struct ed_type_global_config *global_config =
        engine_get_input_data("global_config", node);
    bool ecmp_nexthop_monitor_en = smap_get_bool(&global_config->nb_options,
                                                 "ecmp_nexthop_monitor_enable",
                                                 false);

    if (ecmp_nexthop_monitor_en) {
        build_ecmp_nexthop_table(eng_ctx->ovnsb_idl_txn,
                                 sbrec_mac_binding_by_lport_ip,
                                 &routes_data->parsed_routes,
                                 sbrec_ecmp_nexthop_table);
    } else {
        const struct sbrec_ecmp_nexthop *sb_ecmp_nexthop;
        SBREC_ECMP_NEXTHOP_TABLE_FOR_EACH_SAFE (sb_ecmp_nexthop,
                                                sbrec_ecmp_nexthop_table) {
            sbrec_ecmp_nexthop_delete(sb_ecmp_nexthop);
        }
    }
    engine_set_node_state(node, EN_UPDATED);
}

