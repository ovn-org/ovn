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

#include "vswitch-idl.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "openvswitch/ofp-parse.h"

#include "lib/ovn-sb-idl.h"

#include "binding.h"
#include "ha-chassis.h"
#include "local_data.h"
#include "route.h"

VLOG_DEFINE_THIS_MODULE(exchange);

#define PRIORITY_DEFAULT 1000
#define PRIORITY_LOCAL_BOUND 100

static bool
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

const struct sbrec_port_binding*
route_exchange_find_port(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                         const struct sbrec_chassis *chassis,
                         const struct sbrec_port_binding *pb)
{
    if (!pb) {
        return NULL;
    }
    if (route_exchange_relevant_port(pb)) {
        return pb;
    }

    const struct sbrec_port_binding *cr_pb =
        lport_get_cr_port(sbrec_port_binding_by_name, pb, NULL);

    if (!cr_pb) {
        return NULL;
    }

    if (!lport_pb_is_chassis_resident(chassis, cr_pb)) {
        return NULL;
    }

    if (route_exchange_relevant_port(cr_pb)) {
        return cr_pb;
    }
    return NULL;
}

static void
build_port_mapping(struct smap *mapping, const char *port_mapping)
{
    if (!port_mapping) {
        return;
    }

    char *tokstr, *orig, *key, *value;

    orig = tokstr = xstrdup(port_mapping);
    while (ofputil_parse_key_value(&tokstr, &key, &value)) {
        if (!*value) {
          static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
          VLOG_WARN_RL(&rl, "dynamic-routing-port-mapping setting '%s' is "
                            "not valid.", tokstr);
          break;
        }
        smap_add(mapping, key, value);
    }
    free(orig);
}

static const char *
ifname_from_port_name(const struct smap *port_mapping,
                      struct shash *local_bindings,
                      const struct sbrec_chassis *chassis,
                      const char *port_name)
{
    const char *iface = smap_get(port_mapping, port_name);
    if (iface) {
        return iface;
    }

    if (!local_binding_is_up(local_bindings, port_name, chassis)) {
        return NULL;
    }

    struct local_binding *binding = local_binding_find(local_bindings,
                                                       port_name);
    return binding->iface->name;
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
    smap_destroy(&ad->bound_ports);
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
    struct smap port_mapping = SMAP_INITIALIZER(&port_mapping);

    build_port_mapping(&port_mapping, r_ctx_in->dynamic_routing_port_mapping);

    HMAP_FOR_EACH (ld, hmap_node, r_ctx_in->local_datapaths) {
        if (vector_is_empty(&ld->peer_ports) || ld->is_switch) {
            continue;
        }
        ad = NULL;

        /* This is a LR datapath, find LRPs with route exchange options
         * that are bound locally. */
        const struct peer_ports *peers;
        VECTOR_FOR_EACH_PTR (&ld->peer_ports, peers) {
            const struct sbrec_port_binding *local_peer = peers->local;
            const struct sbrec_port_binding *repb =
                route_exchange_find_port(r_ctx_in->sbrec_port_binding_by_name,
                                         r_ctx_in->chassis,
                                         local_peer);
            if (!repb) {
                continue;
            }

            if (!ad) {
                ad = xzalloc(sizeof(*ad));
                ad->db = ld->datapath;
                hmap_init(&ad->routes);
                smap_init(&ad->bound_ports);
            }

            ad->maintain_vrf |=
                smap_get_bool(&repb->options,
                              "dynamic-routing-maintain-vrf",
                              false);

            const char *vrf_name = smap_get(&repb->options,
                                            "dynamic-routing-vrf-name");
            if (vrf_name && strlen(vrf_name) >= IFNAMSIZ) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
                VLOG_WARN_RL(&rl, "Ignoring vrf name %s, since it is too long."
                             "Maximum length is %d characters", vrf_name,
                             IFNAMSIZ);
                vrf_name = NULL;
            }
            if (vrf_name) {
                memcpy(ad->vrf_name, vrf_name, strlen(vrf_name) + 1);
            } else {
                snprintf(ad->vrf_name, sizeof ad->vrf_name, "ovnvrf%"PRIi64,
                         ad->db->tunnel_key);
            }

            const char *port_name = smap_get(&repb->options,
                                            "dynamic-routing-port-name");
            if (!port_name) {
                /* No port-name set, so we learn routes from all ports. */
                smap_add_nocopy(&ad->bound_ports,
                                xstrdup(local_peer->logical_port), NULL);
            } else {
                /* If a port_name is set the we filter for the name as set in
                 * the port-mapping or the interface name of the local
                 * binding. If the port is not in the port_mappings and not
                 * bound locally we will not learn routes for this port. */
                const char *ifname = ifname_from_port_name(
                    &port_mapping, r_ctx_in->local_bindings,
                    r_ctx_in->chassis, port_name);
                if (ifname) {
                    smap_add(&ad->bound_ports, local_peer->logical_port,
                             ifname);
                }
            }
        }

        if (ad) {
            tracked_datapath_add(ld->datapath, TRACKED_RESOURCE_NEW,
                                 r_ctx_out->tracked_re_datapaths);
            hmap_insert(r_ctx_out->announce_routes, &ad->node,
                        ad->db->tunnel_key);
        }
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
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
            VLOG_WARN_RL(&rl, "bad 'ip_prefix' %s in route "
                         UUID_FMT, route->ip_prefix,
                         UUID_ARGS(&route->header_.uuid));
            continue;
        }

        unsigned int priority = PRIORITY_DEFAULT;
        if (route->tracked_port) {
            bool redistribute_local_bound_only =
                smap_get_bool(&route->logical_port->options,
                              "dynamic-routing-redistribute-local-only",
                              false);
            if (lport_is_local(r_ctx_in->sbrec_port_binding_by_name,
                               r_ctx_in->chassis,
                               route->tracked_port->logical_port)) {
                priority = PRIORITY_LOCAL_BOUND;
                sset_add(r_ctx_out->tracked_ports_local,
                         route->tracked_port->logical_port);
            } else {
                sset_add(r_ctx_out->tracked_ports_remote,
                         route->tracked_port->logical_port);
                if (redistribute_local_bound_only) {
                    /* We're not advertising routes whose 'tracked_port' is
                     * not local, skip this route. */
                    continue;
                }
            }
        }

        struct advertise_route_entry *ar = xmalloc(sizeof(*ar));
        ar->addr = prefix;
        ar->plen = plen;
        ar->priority = priority;
        hmap_insert(&ad->routes, &ar->node,
                    advertise_route_hash(&prefix, plen));
    }

    smap_destroy(&port_mapping);
}

void
route_cleanup(struct hmap *announce_routes)
{
    struct advertise_datapath_entry *ad;
    HMAP_FOR_EACH_POP (ad, node, announce_routes) {
        advertise_datapath_cleanup(ad);
    }
}
