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

#include "flow.h"
#include "local_data.h"
#include "neighbor-exchange.h"
#include "openvswitch/vlog.h"
#include "ovn-sb-idl.h"
#include "unixctl.h"
#include "vec.h"
#include "vswitch-idl.h"

#include "evpn-binding.h"

VLOG_DEFINE_THIS_MODULE(evpn_binding);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

static void collect_evpn_datapaths(const struct hmap *local_datapaths,
                                   struct hmap *evpn_datapaths);

struct evpn_tunnel {
    uint16_t dst_port;
    ofp_port_t ofport;
};

static struct vector collect_evpn_tunnel_interfaces(
    const struct ovsrec_bridge *br_int);
static const struct evpn_tunnel *evpn_tunnel_find(
    const struct vector *evpn_tunnels, uint16_t dst_port);

static struct evpn_binding *evpn_binding_add(
    struct hmap *evpn_bindings, const struct evpn_remote_vtep *vtep,
    uint32_t binding_key);
static uint32_t evpn_binding_hash(const struct in6_addr *remote_ip,
                                  uint32_t vni);
static struct evpn_multicast_group *evpn_multicast_group_find(
    const struct hmap *evpn_mc_groups, uint32_t vni);
static struct evpn_multicast_group *evpn_multicast_group_add(
    struct hmap *evpn_mc_groups, uint32_t vni);

void
evpn_binding_run(const struct evpn_binding_ctx_in *b_ctx_in,
                 struct evpn_binding_ctx_out *b_ctx_out)
{
    struct vector tunnels = collect_evpn_tunnel_interfaces(b_ctx_in->br_int);
    struct hmapx stale_bindings = HMAPX_INITIALIZER(&stale_bindings);
    struct hmapx stale_mc_groups = HMAPX_INITIALIZER(&stale_mc_groups);
    uint32_t hint = OVN_MIN_EVPN_KEY;

    collect_evpn_datapaths(b_ctx_in->local_datapaths, b_ctx_out->datapaths);

    struct evpn_binding *binding;
    HMAP_FOR_EACH (binding, hmap_node, b_ctx_out->bindings) {
        hmapx_add(&stale_bindings, binding);
    }

    struct evpn_multicast_group *mc_group;
    HMAP_FOR_EACH (mc_group, hmap_node, b_ctx_out->multicast_groups) {
        hmapx_add(&stale_mc_groups, mc_group);
    }

    const struct evpn_remote_vtep *vtep;
    HMAP_FOR_EACH (vtep, hmap_node, b_ctx_in->remote_vteps) {
        const struct evpn_tunnel *tun = evpn_tunnel_find(&tunnels, vtep->port);
        if (!tun) {
            VLOG_WARN_RL(&rl, "Couldn't find EVPN tunnel for %"PRIu16
                         " destination port.", vtep->port);
            continue;
        }

        const struct evpn_datapath *edp =
            evpn_datapath_find(b_ctx_out->datapaths, vtep->vni);
        if (!edp) {
            VLOG_WARN_RL(&rl, "Couldn't find EVPN datapath for %"PRIu16" VNI",
                         vtep->vni);
            continue;
        }

        binding = evpn_binding_find(b_ctx_out->bindings, &vtep->ip, vtep->vni);
        if (!binding) {
            uint32_t tunnel_key =
                ovn_allocate_tnlid(b_ctx_out->tunnel_keys, "evpn-binding",
                                   OVN_MIN_EVPN_KEY, OVN_MAX_EVPN_KEY, &hint);
            if (!tunnel_key) {
                continue;
            }

            binding = evpn_binding_add(b_ctx_out->bindings, vtep, tunnel_key);
        }

        mc_group = evpn_multicast_group_find(b_ctx_out->multicast_groups,
                                             vtep->vni);
        if (!mc_group) {
            mc_group = evpn_multicast_group_add(b_ctx_out->multicast_groups,
                                                vtep->vni);
        }

        bool updated = false;
        if (binding->tunnel_ofport != tun->ofport) {
            binding->tunnel_ofport = tun->ofport;
            updated = true;
        }

        if (binding->dp_key != edp->ldp->datapath->tunnel_key) {
            binding->dp_key = edp->ldp->datapath->tunnel_key;
            updated = true;
        }

        if (updated) {
            hmapx_add(b_ctx_out->updated_bindings, binding);

            hmapx_add(&mc_group->bindings, binding);
            hmapx_add(b_ctx_out->updated_multicast_groups, mc_group);
        }

        hmapx_find_and_delete(&stale_bindings, binding);
        hmapx_find_and_delete(&stale_mc_groups, mc_group);
    }

    struct hmapx_node *node;
    HMAPX_FOR_EACH (node, &stale_mc_groups) {
        mc_group = node->data;

        uuidset_insert(b_ctx_out->removed_multicast_groups,
                       &mc_group->flow_uuid);
        hmap_remove(b_ctx_out->multicast_groups, &mc_group->hmap_node);
        free(mc_group);
    }

    HMAPX_FOR_EACH (node, &stale_bindings) {
        binding = node->data;

        mc_group = evpn_multicast_group_find(b_ctx_out->multicast_groups,
                                             binding->vni);
        if (mc_group) {
            hmapx_find_and_delete(&mc_group->bindings, binding);
            hmapx_add(b_ctx_out->updated_multicast_groups, mc_group);
        }
        uuidset_insert(b_ctx_out->removed_bindings, &binding->flow_uuid);
        hmap_remove(b_ctx_out->bindings, &binding->hmap_node);
        free(binding);
    }

    vector_destroy(&tunnels);
    hmapx_destroy(&stale_bindings);
    hmapx_destroy(&stale_mc_groups);
}

struct evpn_binding *
evpn_binding_find(const struct hmap *evpn_bindings,
                  const struct in6_addr *remote_ip, uint32_t vni)
{
    uint32_t hash = evpn_binding_hash(remote_ip, vni);

    struct evpn_binding *binding;
    HMAP_FOR_EACH_WITH_HASH (binding, hmap_node, hash, evpn_bindings) {
        if (ipv6_addr_equals(&binding->remote_ip, remote_ip) &&
            binding->vni == vni) {
            return binding;
        }
    }

    return NULL;
}

void
evpn_bindings_destroy(struct hmap *bindings)
{
    struct evpn_binding *binding;
    HMAP_FOR_EACH_POP (binding, hmap_node, bindings) {
        free(binding);
    }
    hmap_destroy(bindings);
}

void
evpn_vtep_binding_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
                        const char *argv[] OVS_UNUSED, void *data_)
{
    struct hmap *bindings = data_;
    struct ds ds = DS_EMPTY_INITIALIZER;

    const struct evpn_binding *binding;
    HMAP_FOR_EACH (binding, hmap_node, bindings) {
        ds_put_format(&ds, "UUID: "UUID_FMT", Remote IP: ",
                      UUID_ARGS(&binding->flow_uuid));
        ipv6_format_mapped(&binding->remote_ip, &ds);
        ds_put_format(&ds, ", vni: %"PRIu32", binding_key: %#"PRIx32", "
                      "tunnel_ofport: %"PRIu32", dp_key: %"PRIu32,
                      binding->vni, binding->binding_key,
                      binding->tunnel_ofport, binding->dp_key);
        ds_put_char(&ds, '\n');
    }

    unixctl_command_reply(conn, ds_cstr_ro(&ds));
    ds_destroy(&ds);
}

const struct evpn_datapath *
evpn_datapath_find(const struct hmap *evpn_datapaths, uint32_t vni)
{
    const struct evpn_datapath *edp;
    HMAP_FOR_EACH_WITH_HASH (edp, hmap_node, vni, evpn_datapaths) {
        if (edp->vni == vni) {
            return edp;
        }
    }

    return NULL;
}

void
evpn_datapaths_clear(struct hmap *evpn_datapaths)
{
    struct evpn_datapath *edp;
    HMAP_FOR_EACH_POP (edp, hmap_node, evpn_datapaths) {
        free(edp);
    }
}

void
evpn_datapaths_destroy(struct hmap *evpn_datapaths)
{
    evpn_datapaths_clear(evpn_datapaths);
    hmap_destroy(evpn_datapaths);
}

void
evpn_multicast_groups_destroy(struct hmap *multicast_groups)
{
    struct evpn_multicast_group *mc_group;
    HMAP_FOR_EACH_POP (mc_group, hmap_node, multicast_groups) {
        hmapx_destroy(&mc_group->bindings);
        free(mc_group);
    }
    hmap_destroy(multicast_groups);
}

void
evpn_multicast_group_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
                           const char *argv[] OVS_UNUSED, void *data_)
{
    struct hmap *mc_groups = data_;
    struct ds ds = DS_EMPTY_INITIALIZER;

    const struct evpn_multicast_group *mc_group;
    HMAP_FOR_EACH (mc_group, hmap_node, mc_groups) {
        ds_put_format(&ds, "UUID: "UUID_FMT", Remote IPs: ",
                      UUID_ARGS(&mc_group->flow_uuid));

        struct hmapx_node *node;
        HMAPX_FOR_EACH (node, &mc_group->bindings) {
            const struct evpn_binding *binding = node->data;
            ipv6_format_mapped(&binding->remote_ip, &ds);
            ds_put_cstr(&ds, ", ");
        }

        ds_put_format(&ds, "vni: %"PRIu32, mc_group->vni);
        ds_put_char(&ds, '\n');
    }

    unixctl_command_reply(conn, ds_cstr_ro(&ds));
    ds_destroy(&ds);
}

static void
collect_evpn_datapaths(const struct hmap *local_datapaths,
                       struct hmap *evpn_datapaths)
{
    struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
        if (!ld->is_switch) {
            continue;
        }

        int64_t vni = ovn_smap_get_llong(&ld->datapath->external_ids,
                                         "dynamic-routing-vni", -1);
        if (!ovn_is_valid_vni(vni)) {
            continue;
        }

        if (evpn_datapath_find(evpn_datapaths, vni)) {
            VLOG_WARN_RL(&rl, "Datapath "UUID_FMT" with duplicate VNI %"PRIi64,
                         UUID_ARGS(&ld->datapath->header_.uuid), vni);
            continue;
        }

        struct evpn_datapath *edp = xmalloc(sizeof *edp);
        *edp = (struct evpn_datapath) {
            .ldp = ld,
            .vni = vni,
        };

        hmap_insert(evpn_datapaths, &edp->hmap_node, edp->vni);
    }
}

static struct vector
collect_evpn_tunnel_interfaces(const struct ovsrec_bridge *br_int)
{
    struct vector evpn_tunnels = VECTOR_EMPTY_INITIALIZER(struct evpn_tunnel);

    for (size_t i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port = br_int->ports[i];
        if (!smap_get_bool(&port->external_ids, "ovn-evpn-tunnel", false)) {
            continue;
        }

        const struct ovsrec_interface *iface = port->interfaces[0];
        if (iface->n_ofport != 1) {
            continue;
        }

        const char *dst_port_str =
            smap_get_def(&iface->options, "dst_port",
                         OVS_STRINGIZE(DEFAULT_VXLAN_PORT));
        unsigned int dst_port;
        if (!str_to_uint(dst_port_str, 10, &dst_port)) {
            VLOG_WARN_RL(&rl, "Couldn't parse \"dst_port\" %s for tunnel"
                         " interface %s", dst_port_str, iface->name);
            continue;
        }

        struct evpn_tunnel tun = {
            .dst_port = dst_port,
            .ofport = u16_to_ofp(iface->ofport[0]),
        };
        vector_push(&evpn_tunnels, &tun);
    }

    return evpn_tunnels;
}

static const struct evpn_tunnel *
evpn_tunnel_find(const struct vector *evpn_tunnels, uint16_t dst_port)
{
    const struct evpn_tunnel *tun;
    VECTOR_FOR_EACH_PTR (evpn_tunnels, tun) {
        if (tun->dst_port == dst_port) {
            return tun;
        }
    }

    return NULL;
}

static uint32_t
evpn_binding_hash(const struct in6_addr *remote_ip, uint32_t vni)
{
    uint32_t hash = 0;
    hash = hash_add_in6_addr(hash, remote_ip);
    hash = hash_add(hash, vni);

    return hash_finish(hash, 20);
}

static struct evpn_binding *
evpn_binding_add(struct hmap *evpn_bindings,
                 const struct evpn_remote_vtep *vtep, uint32_t binding_key)
{
    struct evpn_binding *binding = xmalloc(sizeof *binding);
    *binding = (struct evpn_binding) {
        .flow_uuid = uuid_random(),
        .remote_ip = vtep->ip,
        .vni = vtep->vni,
        .binding_key = binding_key,
        .tunnel_ofport = OFPP_NONE,
        .dp_key = 0,
    };

    uint32_t hash = evpn_binding_hash(&vtep->ip, vtep->vni);
    hmap_insert(evpn_bindings, &binding->hmap_node, hash);

    return binding;
}

static struct evpn_multicast_group *
evpn_multicast_group_find(const struct hmap *evpn_mc_groups, uint32_t vni)
{
    uint32_t hash = hash_int(vni, 4);

    struct evpn_multicast_group *mc_group;
    HMAP_FOR_EACH_WITH_HASH (mc_group, hmap_node, hash, evpn_mc_groups) {
        if (mc_group->vni == vni) {
            return mc_group;
        }
    }

    return NULL;
}

static struct evpn_multicast_group *
evpn_multicast_group_add(struct hmap *evpn_mc_groups, uint32_t vni)
{
    struct evpn_multicast_group *mc_group = xmalloc(sizeof *mc_group);
    *mc_group = (struct evpn_multicast_group) {
        .flow_uuid = uuid_random(),
        .bindings = HMAPX_INITIALIZER(&mc_group->bindings),
        .vni = vni,
    };

    uint32_t hash = hash_int(vni, 4);
    hmap_insert(evpn_mc_groups, &mc_group->hmap_node, hash);

    return mc_group;
}
