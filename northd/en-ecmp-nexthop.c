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
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "northd.h"
#include "openvswitch/hmap.h"
#include "util.h"

#include "en-ecmp-nexthop.h"
#include "en-northd.h"

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
        struct ovsdb_idl_txn *ovnsb_txn, const struct hmap *routes,
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

        const struct nbrec_logical_router_static_route *r = pr->route;
        struct ecmp_nexthop_data *e = ecmp_nexthop_find_entry(
                r->nexthop, pr->out_port->sb, &sb_nexthops_map);
        if (!e) {
            sb_ecmp_nexthop = sbrec_ecmp_nexthop_insert(ovnsb_txn);
            sbrec_ecmp_nexthop_set_nexthop(sb_ecmp_nexthop, r->nexthop);
            sbrec_ecmp_nexthop_set_port(sb_ecmp_nexthop, pr->out_port->sb);
            sbrec_ecmp_nexthop_set_datapath(sb_ecmp_nexthop,
                                            pr->out_port->sb->datapath);
        } else {
            hmap_remove(&sb_nexthops_map, &e->hmap_node);
            free(e);
        }
    }

    struct ecmp_nexthop_data *e;
    HMAP_FOR_EACH_POP (e, hmap_node, &sb_nexthops_map) {
        sbrec_ecmp_nexthop_delete(e->sb_ecmp_nh);
        free(e);
    }
    hmap_destroy(&sb_nexthops_map);
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

    build_ecmp_nexthop_table(eng_ctx->ovnsb_idl_txn,
                             &routes_data->parsed_routes,
                             sbrec_ecmp_nexthop_table);
    engine_set_node_state(node, EN_UPDATED);
}

