/*
 * Copyright (c) 2025, Canonical, Ltd.
 * Copyright (c) 2025, STACKIT GmbH & Co. KG
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

#include <net/if.h>

#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"

#include "lib/ovn-sb-idl.h"

#include "binding.h"
#include "ha-chassis.h"
#include "local_data.h"
#include "route.h"

VLOG_DEFINE_THIS_MODULE(exchange);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

bool
route_exchange_relevant_port(const struct sbrec_port_binding *pb)
{
    return pb && smap_get_bool(&pb->options, "dynamic-routing", false);
}

uint32_t
advertise_route_hash(const struct in6_addr *dst, unsigned int plen)
{
    uint32_t hash = hash_bytes(dst->s6_addr, 16, 0);
    return hash_int(plen, hash);
}

static const struct sbrec_port_binding*
find_route_exchange_pb(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                       const struct sbrec_chassis *chassis,
                       const struct sset *active_tunnels,
                       const struct sbrec_port_binding *pb)
{
    if (!pb) {
        return NULL;
    }
    if (route_exchange_relevant_port(pb)) {
        return pb;
    }
    const char *crp = smap_get(&pb->options, "chassis-redirect-port");
    if (!crp) {
        return NULL;
    }
    if (!lport_is_chassis_resident(sbrec_port_binding_by_name, chassis,
                                   active_tunnels, crp)) {
        return NULL;
    }
    const struct sbrec_port_binding *crpbp = lport_lookup_by_name(
        sbrec_port_binding_by_name, crp);
    if (route_exchange_relevant_port(crpbp)) {
        return crpbp;
    }
    return NULL;
}

static void
advertise_datapath_cleanup(struct advertise_datapath_entry *ad)
{
    struct advertise_route_entry *ar;
    HMAP_FOR_EACH_SAFE (ar, node, &ad->routes) {
        hmap_remove(&ad->routes, &ar->node);
        free(ar);
    }
    hmap_destroy(&ad->routes);
    sset_destroy(&ad->bound_ports);
    free(ad);
}

static struct advertise_datapath_entry*
advertise_datapath_find(const struct hmap *datapaths,
                        const struct sbrec_datapath_binding *db)
{
    struct advertise_datapath_entry *ade;
    HMAP_FOR_EACH_WITH_HASH (ade, node, db->tunnel_key, datapaths) {
        if (ade->db == db) {
            return ade;
        }
    }
    return NULL;
}

void
route_run(struct route_ctx_in *r_ctx_in,
          struct route_ctx_out *r_ctx_out)
{
    struct advertise_datapath_entry *ad;
    const struct local_datapath *ld;

    HMAP_FOR_EACH (ld, hmap_node, r_ctx_in->local_datapaths) {
        if (!ld->n_peer_ports || ld->is_switch) {
            continue;
        }

        ad = xzalloc(sizeof(*ad));
        ad->db = ld->datapath;
        hmap_init(&ad->routes);
        sset_init(&ad->bound_ports);

        /* This is a LR datapath, find LRPs with route exchange options
         * that are bound locally. */
        for (size_t i = 0; i < ld->n_peer_ports; i++) {
            const struct sbrec_port_binding *local_peer
                = ld->peer_ports[i].local;
            const struct sbrec_port_binding *repb =
                find_route_exchange_pb(r_ctx_in->sbrec_port_binding_by_name,
                                       r_ctx_in->chassis,
                                       r_ctx_in->active_tunnels,
                                       local_peer);
            if (!repb) {
                continue;
            }

            ad->maintain_vrf |=
                smap_get_bool(&repb->options,
                              "dynamic-routing-maintain-vrf",
                              false);
            sset_add(&ad->bound_ports, local_peer->logical_port);
        }

        if (sset_is_empty(&ad->bound_ports)) {
            advertise_datapath_cleanup(ad);
            continue;
        }
        tracked_datapath_add(ld->datapath, TRACKED_RESOURCE_NEW,
                             r_ctx_out->tracked_re_datapaths);

        hmap_insert(r_ctx_out->announce_routes, &ad->node, ad->db->tunnel_key);
    }

    const struct sbrec_advertised_route *route;
    SBREC_ADVERTISED_ROUTE_TABLE_FOR_EACH (route,
                                           r_ctx_in->advertised_route_table) {
        ad = advertise_datapath_find(r_ctx_out->announce_routes,
                                     route->datapath);
        if (!ad) {
            continue;
        }

        struct in6_addr prefix;
        unsigned int plen;
        if (!ip46_parse_cidr(route->ip_prefix, &prefix, &plen)) {
            VLOG_WARN_RL(&rl, "bad 'ip_prefix' %s in route "
                         UUID_FMT, route->ip_prefix,
                         UUID_ARGS(&route->header_.uuid));
            continue;
        }

        struct advertise_route_entry *ar = xmalloc(sizeof *ar);
        ar->addr = prefix;
        ar->plen = plen;
        hmap_insert(&ad->routes, &ar->node,
                    advertise_route_hash(&prefix, plen));
    }
}

void
route_cleanup(struct hmap *announce_routes)
{
    struct advertise_datapath_entry *ad;
    HMAP_FOR_EACH_POP (ad, node, announce_routes) {
        advertise_datapath_cleanup(ad);
    }
}
