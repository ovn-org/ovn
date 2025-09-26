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

#include "evpn-binding.h"
#include "neighbor-exchange.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovn-sb-idl.h"
#include "packets.h"
#include "unixctl.h"

#include "evpn-arp.h"

VLOG_DEFINE_THIS_MODULE(evpn_arp);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

static struct evpn_arp *evpn_arp_add(struct hmap *evpn_arps, struct eth_addr,
                                     const struct in6_addr *, uint32_t vni);
static struct evpn_arp *evpn_arp_find(const struct hmap *evpn_arps,
                                      struct eth_addr,
                                      const struct in6_addr *,
                                      uint32_t vni);
static uint32_t evpn_arp_hash(const struct eth_addr *, const struct in6_addr *,
                              uint32_t vni);

void
evpn_arp_run(const struct evpn_arp_ctx_in *arp_ctx_in,
             struct evpn_arp_ctx_out *arp_ctx_out)
{
    struct hmapx stale_arps = HMAPX_INITIALIZER(&stale_arps);

    struct evpn_arp *arp;
    HMAP_FOR_EACH (arp, hmap_node, arp_ctx_out->arps) {
        hmapx_add(&stale_arps, arp);
    }

    const struct evpn_static_entry *static_arp;
    HMAP_FOR_EACH (static_arp, hmap_node, arp_ctx_in->static_arps) {
        const struct evpn_datapath *edp =
            evpn_datapath_find(arp_ctx_in->datapaths, static_arp->vni);
        if (!edp) {
            char addr_s[INET6_ADDRSTRLEN + 1];
            VLOG_WARN_RL(&rl, "Couldn't find EVPN datapath for ARP entry: "
                              "VNI: %"PRIu32" MAC: "ETH_ADDR_FMT" IP: %s.",
                         static_arp->vni, ETH_ADDR_ARGS(static_arp->mac),
                         ipv6_string_mapped(addr_s, &static_arp->ip)
                         ? addr_s : "(invalid)");
            continue;
        }

        arp = evpn_arp_find(arp_ctx_out->arps, static_arp->mac,
                            &static_arp->ip, static_arp->vni);
        if (!arp) {
            arp = evpn_arp_add(arp_ctx_out->arps, static_arp->mac,
                               &static_arp->ip, static_arp->vni);
        }

        bool updated = false;
        if (arp->ldp != edp->ldp) {
            arp->ldp = edp->ldp;
            updated = true;
        }

        enum neigh_of_rule_prio priority =
            smap_get_bool(&arp->ldp->datapath->external_ids,
                          "dynamic-routing-arp-prefer-local",
                          false)
            ? NEIGH_OF_EVPN_MAC_BINDING_LOW_PRIO
            : NEIGH_OF_EVPN_MAC_BINDING_HIGH_PRIO;
        if (arp->priority != priority) {
            arp->priority = priority;
            updated = true;
        }

        if (updated) {
            hmapx_add(arp_ctx_out->updated_arps, arp);
        }

        hmapx_find_and_delete(&stale_arps, arp);
    }

    struct hmapx_node *node;
    HMAPX_FOR_EACH (node, &stale_arps) {
        arp = node->data;

        uuidset_insert(arp_ctx_out->removed_arps, &arp->flow_uuid);
        hmap_remove(arp_ctx_out->arps, &arp->hmap_node);
        free(arp);
    }

    hmapx_destroy(&stale_arps);
}

void
evpn_arps_destroy(struct hmap *arps)
{
    struct evpn_arp *arp;
    HMAP_FOR_EACH_POP (arp, hmap_node, arps) {
        free(arp);
    }
    hmap_destroy(arps);
}

void
evpn_arp_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[] OVS_UNUSED, void *data_)
{
    struct hmap *arps = data_;
    struct ds ds = DS_EMPTY_INITIALIZER;

    const struct evpn_arp *arp;
    HMAP_FOR_EACH (arp, hmap_node, arps) {
        char addr_s[INET6_ADDRSTRLEN + 1];
        ds_put_format(&ds, "UUID: "UUID_FMT", VNI: %"PRIu32", "
                           "MAC: "ETH_ADDR_FMT", IP: %s, "
                           "dp_key: %"PRId64"\n",
                      UUID_ARGS(&arp->flow_uuid), arp->vni,
                      ETH_ADDR_ARGS(arp->mac),
                      ipv6_string_mapped(addr_s, &arp->ip)
                      ? addr_s : "(invalid)",
                      arp->ldp->datapath->tunnel_key);
    }

    unixctl_command_reply(conn, ds_cstr_ro(&ds));
    ds_destroy(&ds);
}

static struct evpn_arp *
evpn_arp_add(struct hmap *evpn_arps, struct eth_addr mac,
             const struct in6_addr *ip, uint32_t vni)
{
    struct evpn_arp *arp = xmalloc(sizeof *arp);
    *arp = (struct evpn_arp) {
        .flow_uuid = uuid_random(),
        .mac = mac,
        .ip = *ip,
        .vni = vni,
    };

    hmap_insert(evpn_arps, &arp->hmap_node, evpn_arp_hash(&mac, ip, vni));

    return arp;
}

static struct evpn_arp *
evpn_arp_find(const struct hmap *evpn_arps, struct eth_addr mac,
              const struct in6_addr *ip, uint32_t vni)
{
    uint32_t hash = evpn_arp_hash(&mac, ip, vni);

    struct evpn_arp *arp;
    HMAP_FOR_EACH_WITH_HASH (arp, hmap_node, hash, evpn_arps) {
        if (arp->vni == vni && eth_addr_equals(arp->mac, mac) &&
                ipv6_addr_equals(&arp->ip, ip)) {
            return arp;
        }
    }

    return NULL;
}

static uint32_t
evpn_arp_hash(const struct eth_addr *mac, const struct in6_addr *ip,
              uint32_t vni)
{
    uint32_t hash = 0;
    hash = hash_bytes(mac, sizeof *mac, hash);
    hash = hash_add_in6_addr(hash, ip);
    hash = hash_add(hash, vni);

    return hash_finish(hash, 26);
}
