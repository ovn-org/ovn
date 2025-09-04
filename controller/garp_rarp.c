/*
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

#include "controller/local_data.h"
#include "lport.h"
#include "mac-binding-index.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "ovn/lex.h"
#include "garp_rarp.h"
#include "ovn-sb-idl.h"
#include "if-status.h"

VLOG_DEFINE_THIS_MODULE(garp_rarp);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

#define GARP_RARP_DEF_MAX_TIMEOUT    16000

static bool garp_rarp_data_has_changed = false;
static struct garp_rarp_data garp_rarp_data;

struct laddrs_port {
    struct lport_addresses laddrs;
    char *lport;
};

/* Get localnet vifs, local l3gw ports and ofport for localnet patch ports. */
static void
get_localnet_vifs_l3gwports(
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    const struct sbrec_chassis *chassis,
    const struct hmap *local_datapaths,
    struct sset *localnet_vifs,
    struct sset *local_l3gw_ports)
{
    struct sbrec_port_binding *target = sbrec_port_binding_index_init_row(
        sbrec_port_binding_by_datapath);

    const struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
        const struct sbrec_port_binding *pb;

        if (!ld->localnet_port) {
            continue;
        }

        sbrec_port_binding_index_set_datapath(target, ld->datapath);
        SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, target,
                                           sbrec_port_binding_by_datapath) {
            /* Get l3gw ports. Consider port bindings with type "l3gateway"
             * that connect to gateway routers (if local), and consider port
             * bindings of type "patch" since they might connect to
             * distributed gateway ports with NAT addresses. */
            if ((!strcmp(pb->type, "l3gateway") && pb->chassis == chassis)
                || !strcmp(pb->type, "patch")) {
                sset_add(local_l3gw_ports, pb->logical_port);
            }

            /* Get all vifs that are directly connected to a localnet port. */
            if (!strcmp(pb->type, "") && pb->chassis == chassis) {
                sset_add(localnet_vifs, pb->logical_port);
            }
        }
    }
    sbrec_port_binding_index_destroy_row(target);
}

/* Extracts the mac, IPv4 and IPv6 addresses, and logical port from
 * 'addresses' which should be of the format 'MAC [IP1 IP2 ..]
 * [is_chassis_resident("LPORT_NAME")]', where IPn should be a valid IPv4
 * or IPv6 address, and stores them in the 'ipv4_addrs' and 'ipv6_addrs'
 * fields of 'laddrs'.  The logical port name is stored in 'lport'.
 *
 * Returns true if at least 'MAC' is found in 'address', false otherwise.
 *
 * The caller must call destroy_lport_addresses() and free(*lport). */
static bool
extract_addresses_with_port(const char *addresses,
                            struct lport_addresses *laddrs,
                            char **lport)
{
    int ofs;
    if (!extract_addresses(addresses, laddrs, &ofs)) {
        return false;
    } else if (!addresses[ofs]) {
        return true;
    }

    struct lexer lexer;
    lexer_init(&lexer, addresses + ofs);
    lexer_get(&lexer);

    if (lexer.error || lexer.token.type != LEX_T_ID
        || !lexer_match_id(&lexer, "is_chassis_resident")) {
        VLOG_INFO_RL(&rl, "invalid syntax '%s' in address", addresses);
        lexer_destroy(&lexer);
        return true;
    }

    if (!lexer_match(&lexer, LEX_T_LPAREN)) {
        VLOG_INFO_RL(&rl, "Syntax error: expecting '(' after "
                          "'is_chassis_resident' in address '%s'", addresses);
        lexer_destroy(&lexer);
        return false;
    }

    if (lexer.token.type != LEX_T_STRING) {
        VLOG_INFO_RL(&rl,
                    "Syntax error: expecting quoted string after "
                    "'is_chassis_resident' in address '%s'", addresses);
        lexer_destroy(&lexer);
        return false;
    }

    *lport = xstrdup(lexer.token.s);

    lexer_get(&lexer);
    if (!lexer_match(&lexer, LEX_T_RPAREN)) {
        VLOG_INFO_RL(&rl, "Syntax error: expecting ')' after quoted string in "
                          "'is_chassis_resident()' in address '%s'",
                          addresses);
        lexer_destroy(&lexer);
        return false;
    }

    lexer_destroy(&lexer);
    return true;
}

static void
consider_nat_address(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                     const char *nat_address,
                     const struct sbrec_port_binding *pb,
                     struct sset *nat_address_keys,
                     const struct sbrec_chassis *chassis,
                     struct shash *nat_addresses,
                     struct sset *non_local_lports,
                     struct sset *local_lports)
{
    struct laddrs_port *laddrs_port = xmalloc(sizeof *laddrs_port);
    struct lport_addresses *laddrs = &laddrs_port->laddrs;
    char *lport = NULL;
    bool rc = extract_addresses_with_port(nat_address, laddrs, &lport);
    if (!rc
        || (!lport && !strcmp(pb->type, "patch"))) {
        destroy_lport_addresses(laddrs);
        free(lport);
        free(laddrs_port);
        return;
    }
    if (lport) {
        if (!lport_is_chassis_resident(sbrec_port_binding_by_name,
                                       chassis, lport)) {
            sset_add(non_local_lports, lport);
            destroy_lport_addresses(laddrs);
            free(lport);
            free(laddrs_port);
            return;
        } else {
            sset_add(local_lports, lport);
        }
    }

    for (size_t i = 0; i < laddrs->n_ipv4_addrs; i++) {
        char *name = xasprintf("%s-%s", pb->logical_port,
                                        laddrs->ipv4_addrs[i].addr_s);
        sset_add(nat_address_keys, name);
        free(name);
    }
    if (laddrs->n_ipv4_addrs == 0) {
        char *name = xasprintf("%s-noip", pb->logical_port);
        sset_add(nat_address_keys, name);
        free(name);
    }
    laddrs_port->lport = lport;
    shash_add(nat_addresses, pb->logical_port, laddrs_port);
}

static void
get_nat_addresses_and_keys(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                           struct sset *nat_address_keys,
                           struct sset *local_l3gw_ports,
                           const struct sbrec_chassis *chassis,
                           struct shash *nat_addresses,
                           struct sset *non_local_lports,
                           struct sset *local_lports)
{
    const char *gw_port;
    SSET_FOR_EACH (gw_port, local_l3gw_ports) {
        const struct sbrec_port_binding *pb;

        pb = lport_lookup_by_name(sbrec_port_binding_by_name, gw_port);
        if (!pb) {
            continue;
        }

        if (pb->n_nat_addresses) {
            for (size_t i = 0; i < pb->n_nat_addresses; i++) {
                consider_nat_address(sbrec_port_binding_by_name,
                                     pb->nat_addresses[i], pb,
                                     nat_address_keys, chassis,
                                     nat_addresses,
                                     non_local_lports,
                                     local_lports);
            }
        } else {
            /* Continue to support options:nat-addresses for version
             * upgrade. */
            const char *nat_addresses_options = smap_get(&pb->options,
                                                         "nat-addresses");
            if (nat_addresses_options) {
                consider_nat_address(sbrec_port_binding_by_name,
                                     nat_addresses_options, pb,
                                     nat_address_keys, chassis,
                                     nat_addresses,
                                     non_local_lports,
                                     local_lports);
            }
        }
    }
}

static uint32_t
garp_rarp_node_hash(const struct eth_addr *ea, uint32_t dp_key,
                    uint32_t port_key)
{
    return hash_bytes(ea, sizeof *ea, hash_2words(dp_key, port_key));
}

static uint32_t
garp_rarp_node_hash_struct(const struct garp_rarp_node *n)
{
    return garp_rarp_node_hash(&n->ea, n->dp_key, n->port_key);
}

/* Searches for a given garp_rarp_node in a hmap. Ignores the announce_time
 * and backoff field since they might be different based on runtime. */
static struct garp_rarp_node *
garp_rarp_lookup(const struct eth_addr ea, ovs_be32 ipv4, uint32_t dp_key,
                 uint32_t port_key)
{
    struct garp_rarp_node *grn;
    uint32_t hash = garp_rarp_node_hash(&ea, dp_key, port_key);
    CMAP_FOR_EACH_WITH_HASH (grn, cmap_node, hash, &garp_rarp_data.data) {
        if (!eth_addr_equals(ea, grn->ea)) {
            continue;
        }

        if (ipv4 != grn->ipv4) {
            continue;
        }

        if (dp_key != grn->dp_key) {
            continue;
        }

        if (port_key != grn->port_key) {
            continue;
        }

        return grn;
    }
    return NULL;
}

void
garp_rarp_node_reset_timers(const char *logical_port)
{
    struct garp_rarp_node *grn;
    CMAP_FOR_EACH (grn, cmap_node, &garp_rarp_data.data) {
        if (grn->logical_port && !strcmp(grn->logical_port, logical_port)) {
            atomic_store(&grn->announce_time, time_msec() + 1000);
            atomic_store(&grn->backoff, 1000);
        }
    }
}

static void
reset_timers_for_claimed_cr(struct if_status_mgr *mgr)
{
    struct sset *claimed_cr = get_claimed_cr(mgr);
    const char *cr_logical_port;
    SSET_FOR_EACH_SAFE (cr_logical_port, claimed_cr) {
        garp_rarp_node_reset_timers(cr_logical_port);
        sset_delete(claimed_cr, SSET_NODE_FROM_NAME(cr_logical_port));
    }

}

static void
garp_rarp_node_add(const struct eth_addr ea, ovs_be32 ip,
                   uint32_t dp_key, uint32_t port_key,
                   const char *logical_port)
{
    struct garp_rarp_node *grn = garp_rarp_lookup(ea, ip, dp_key, port_key);
    if (grn) {
        grn->stale = false;
        return;
    }

    grn = xmalloc(sizeof *grn);
    grn->ea = ea;
    grn->ipv4 = ip;
    atomic_store(&grn->announce_time, time_msec() + 1000);
    atomic_store(&grn->backoff, 1000); /* msec. */
    grn->dp_key = dp_key;
    grn->port_key = port_key;
    grn->logical_port = nullable_xstrdup(logical_port);
    grn->stale = false;
    cmap_insert(&garp_rarp_data.data, &grn->cmap_node,
                garp_rarp_node_hash_struct(grn));
    garp_rarp_data_has_changed = true;
}

/* Simulate the effect of a GARP on local datapaths, i.e., create MAC_Bindings
 * on peer router datapaths.
 */
static void
send_garp_locally(const struct garp_rarp_ctx_in *r_ctx_in,
                  const struct sbrec_port_binding *in_pb,
                  struct eth_addr ea, ovs_be32 ip)
{
    if (!r_ctx_in->ovnsb_idl_txn) {
        return;
    }

    const struct local_datapath *ldp =
        get_local_datapath(r_ctx_in->local_datapaths,
                           in_pb->datapath->tunnel_key);

    ovs_assert(ldp);
    const struct peer_ports *peers;
    VECTOR_FOR_EACH_PTR (&ldp->peer_ports, peers) {
        const struct sbrec_port_binding *local = peers->local;
        const struct sbrec_port_binding *remote = peers->remote;

        /* Skip "ingress" port. */
        if (local == in_pb) {
            continue;
        }

        bool update_only = !smap_get_bool(&remote->datapath->external_ids,
                                          "always_learn_from_arp_request",
                                          true);

        struct ds ip_s = DS_EMPTY_INITIALIZER;

        ip_format_masked(ip, OVS_BE32_MAX, &ip_s);
        mac_binding_add_to_sb(r_ctx_in->ovnsb_idl_txn,
                              r_ctx_in->sbrec_mac_binding_by_lport_ip,
                              remote->logical_port, remote->datapath,
                              ea, ds_cstr(&ip_s), update_only);
        ds_destroy(&ip_s);
    }
}

/* Add or update a vif for which GARPs need to be announced. */
static void
send_garp_rarp_update(const struct garp_rarp_ctx_in *r_ctx_in,
                      const struct sbrec_port_binding *binding_rec,
                      struct shash *nat_addresses)
{
    /* Skip localports as they don't need to be announced */
    if (!strcmp(binding_rec->type, "localport")) {
        return;
    }

    /* Update GARP for NAT IP if it exists.  Consider port bindings with type
     * "l3gateway" for logical switch ports attached to gateway routers, and
     * port bindings with type "patch" for logical switch ports attached to
     * distributed gateway ports. */
    if (!strcmp(binding_rec->type, "l3gateway")
        || !strcmp(binding_rec->type, "patch")) {
        struct laddrs_port *laddrs_port = NULL;
        while ((laddrs_port = shash_find_and_delete(nat_addresses,
                                               binding_rec->logical_port))) {
            struct lport_addresses *laddrs = &laddrs_port->laddrs;
            for (size_t i = 0; i < laddrs->n_ipv4_addrs; i++) {
                garp_rarp_node_add(laddrs->ea, laddrs->ipv4_addrs[i].addr,
                                   binding_rec->datapath->tunnel_key,
                                   binding_rec->tunnel_key,
                                   laddrs_port->lport);
                send_garp_locally(r_ctx_in, binding_rec, laddrs->ea,
                                  laddrs->ipv4_addrs[i].addr);
            }
            /*
             * Send RARPs even if we do not have a ipv4 address as it e.g.
             * happens on ipv6 only ports.
             */
            if (laddrs->n_ipv4_addrs == 0) {
                garp_rarp_node_add(laddrs->ea, 0,
                                   binding_rec->datapath->tunnel_key,
                                   binding_rec->tunnel_key,
                                   laddrs_port->lport);
            }
            destroy_lport_addresses(laddrs);
            free(laddrs_port->lport);
            free(laddrs_port);
        }
        return;
    }

    /* Add GARP for new vif. */
    for (size_t i = 0; i < binding_rec->n_mac; i++) {
        struct lport_addresses laddrs;
        ovs_be32 ip = 0;
        if (!extract_lsp_addresses(binding_rec->mac[i], &laddrs)) {
            continue;
        }

        if (laddrs.n_ipv4_addrs) {
            ip = laddrs.ipv4_addrs[0].addr;
        }

        garp_rarp_node_add(laddrs.ea, ip,
                           binding_rec->datapath->tunnel_key,
                           binding_rec->tunnel_key, NULL);
        if (ip) {
            send_garp_locally(r_ctx_in, binding_rec, laddrs.ea, ip);
        }

        destroy_lport_addresses(&laddrs);
        break;
    }
}

static void
garp_rarp_clear(struct garp_rarp_ctx_in *r_ctx_in)
{
    sset_clear(&r_ctx_in->data->non_local_lports);
    sset_clear(&r_ctx_in->data->local_lports);
}

static bool
garp_rarp_is_enabled(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                     const struct sbrec_port_binding *pb)
{
    if (smap_get_bool(&pb->options, "disable_garp_rarp", false)) {
        return false;
    }

    /* Check if GARP probing is disabled on the peer logical router. */
    const struct sbrec_port_binding *peer = lport_get_peer(
            pb, sbrec_port_binding_by_name);
    if (peer && smap_get_bool(&peer->datapath->external_ids,
                              "disable_garp_rarp", false)) {
        return false;
    }

    return true;
}

void
garp_rarp_run(struct garp_rarp_ctx_in *r_ctx_in)
{
    garp_rarp_clear(r_ctx_in);

    struct sset localnet_vifs = SSET_INITIALIZER(&localnet_vifs);
    struct sset local_l3gw_ports = SSET_INITIALIZER(&local_l3gw_ports);
    struct sset nat_ip_keys = SSET_INITIALIZER(&nat_ip_keys);
    struct shash nat_addresses = SHASH_INITIALIZER(&nat_addresses);

    struct garp_rarp_node *grn;
    CMAP_FOR_EACH (grn, cmap_node, &garp_rarp_data.data) {
        grn->stale = true;
    }

    reset_timers_for_claimed_cr(r_ctx_in->mgr);
    get_localnet_vifs_l3gwports(r_ctx_in->sbrec_port_binding_by_datapath,
                                r_ctx_in->chassis,
                                r_ctx_in->local_datapaths,
                                &localnet_vifs, &local_l3gw_ports);

    get_nat_addresses_and_keys(r_ctx_in->sbrec_port_binding_by_name,
                               &nat_ip_keys, &local_l3gw_ports,
                               r_ctx_in->chassis, &nat_addresses,
                               &r_ctx_in->data->non_local_lports,
                               &r_ctx_in->data->local_lports);

    /* Update send_garp_rarp_data. */
    const char *iface_id;
    SSET_FOR_EACH (iface_id, &localnet_vifs) {
        const struct sbrec_port_binding *pb = lport_lookup_by_name(
            r_ctx_in->sbrec_port_binding_by_name, iface_id);
        if (pb &&
            garp_rarp_is_enabled(r_ctx_in->sbrec_port_binding_by_name, pb)) {
            send_garp_rarp_update(r_ctx_in, pb, &nat_addresses);
        }
    }

    /* Update send_garp_rarp_data for nat-addresses. */
    const char *gw_port;
    SSET_FOR_EACH (gw_port, &local_l3gw_ports) {
        const struct sbrec_port_binding *pb = lport_lookup_by_name(
            r_ctx_in->sbrec_port_binding_by_name, gw_port);
        if (pb &&
            garp_rarp_is_enabled(r_ctx_in->sbrec_port_binding_by_name, pb)) {
            send_garp_rarp_update(r_ctx_in, pb, &nat_addresses);
        }
    }

    sset_destroy(&localnet_vifs);
    sset_destroy(&local_l3gw_ports);

    struct shash_node *iter;
    SHASH_FOR_EACH_SAFE (iter, &nat_addresses) {
        struct laddrs_port *laddrs_port = iter->data;
        destroy_lport_addresses(&laddrs_port->laddrs);
        shash_delete(&nat_addresses, iter);
        free(laddrs_port->lport);
        free(laddrs_port);
    }
    shash_destroy(&nat_addresses);

    sset_destroy(&nat_ip_keys);

    unsigned long long garp_rarp_max_timeout = smap_get_ullong(
            &r_ctx_in->cfg->external_ids,
            "garp-max-timeout-sec", 0) * 1000;
    bool garp_rarp_continuous = !!garp_rarp_max_timeout;
    if (!garp_rarp_max_timeout) {
        garp_rarp_max_timeout = GARP_RARP_DEF_MAX_TIMEOUT;
    }

    bool reset_timers = (
        garp_rarp_max_timeout != garp_rarp_data.max_timeout ||
        garp_rarp_continuous != garp_rarp_data.continuous);

    CMAP_FOR_EACH (grn, cmap_node, &garp_rarp_data.data) {
        if (grn->stale) {
            cmap_remove(&garp_rarp_data.data, &grn->cmap_node,
                        garp_rarp_node_hash_struct(grn));
            ovsrcu_postpone(garp_rarp_node_free, grn);
        } else if (reset_timers) {
            atomic_store(&grn->announce_time, time_msec() + 1000);
            atomic_store(&grn->backoff, 1000);
        }
    }

    garp_rarp_data.max_timeout = garp_rarp_max_timeout;
    garp_rarp_data.continuous = garp_rarp_continuous;
}

const struct garp_rarp_data *
garp_rarp_get_data(void)
{
    return &garp_rarp_data;
}

bool
garp_rarp_data_changed(void) {
    bool ret = garp_rarp_data_has_changed;
    garp_rarp_data_has_changed = true;
    return ret;
}

void
garp_rarp_node_free(struct garp_rarp_node *garp_rarp)
{
    free(garp_rarp->logical_port);
    free(garp_rarp);
}

struct ed_type_garp_rarp *
garp_rarp_init(void)
{
    cmap_init(&garp_rarp_data.data);
    garp_rarp_data.max_timeout = GARP_RARP_DEF_MAX_TIMEOUT;
    garp_rarp_data.continuous = false;

    struct ed_type_garp_rarp *gr = xmalloc(sizeof *gr);
    sset_init(&gr->non_local_lports);
    sset_init(&gr->local_lports);
    return gr;
}

void
garp_rarp_cleanup(struct ed_type_garp_rarp *data)
{
    struct garp_rarp_node *grn;
    CMAP_FOR_EACH (grn, cmap_node, &garp_rarp_data.data) {
        cmap_remove(&garp_rarp_data.data, &grn->cmap_node,
                    garp_rarp_node_hash_struct(grn));
        garp_rarp_node_free(grn);
    }
    cmap_destroy(&garp_rarp_data.data);
    sset_destroy(&data->non_local_lports);
    sset_destroy(&data->local_lports);
}
