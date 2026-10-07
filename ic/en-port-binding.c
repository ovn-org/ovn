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

#include "en-az.h"
#include "en-port-binding.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "openvswitch/vlog.h"
#include "ovn-ic.h"
#include "ovsdb-idl.h"
#include "smap.h"
#include "sset.h"

VLOG_DEFINE_THIS_MODULE(en_ic_port_binding);

static const struct nbrec_logical_router *
find_tr_in_nb(struct ic_context *ctx, char *tr_name)
{
    const struct nbrec_logical_router *key =
        nbrec_logical_router_index_init_row(ctx->nbrec_lr_by_name);
    nbrec_logical_router_index_set_name(key, tr_name);

    const struct nbrec_logical_router *lr;
    bool found = false;
    NBREC_LOGICAL_ROUTER_FOR_EACH_EQUAL (lr, key, ctx->nbrec_lr_by_name) {
        if (smap_get(&lr->options, "interconn-tr")) {
            found = true;
            break;
        }
    }

    nbrec_logical_router_index_destroy_row(key);
    if (found) {
        return lr;
    }

    return NULL;
}

static const struct sbrec_port_binding *
find_peer_port(struct ic_context *ctx,
               const struct sbrec_port_binding *sb_pb)
{
    const char *peer_name = smap_get(&sb_pb->options, "peer");
    if (!peer_name) {
        return NULL;
    }

    return find_sb_pb_by_name(ctx->sbrec_port_binding_by_name, peer_name);
}

static const struct sbrec_port_binding *
find_crp_from_lrp(struct ic_context *ctx,
                  const struct sbrec_port_binding *lrp_pb)
{
    char *crp_name = ovn_chassis_redirect_name(lrp_pb->logical_port);

    const struct sbrec_port_binding *pb =
        find_sb_pb_by_name(ctx->sbrec_port_binding_by_name, crp_name);

    free(crp_name);
    return pb;
}

static const struct sbrec_port_binding *
find_crp_for_sb_pb(struct ic_context *ctx,
                   const struct sbrec_port_binding *sb_pb)
{
    const struct sbrec_port_binding *peer = find_peer_port(ctx, sb_pb);
    if (!peer) {
        return NULL;
    }

    return find_crp_from_lrp(ctx, peer);
}

static const char *
get_lp_address_for_sb_pb(struct ic_context *ctx,
                         const struct sbrec_port_binding *sb_pb)
{
    const struct nbrec_logical_switch_port *nb_lsp;

    nb_lsp = get_lsp_by_ts_port_name(ctx, sb_pb->logical_port);
    if (!nb_lsp) {
        /* The SB Port_Binding's logical_port does not correspond to any NB
         * logical switch port (e.g. an out-of-band record with a bogus
         * logical_port).  There is no address to derive. */
        return NULL;
    }
    if (!strcmp(nb_lsp->type, "switch")) {
        /* Switches always have implicit "unknown" address, and IC-SB port
         * binding can only have one address specified. */
        return "unknown";
    }

    const struct sbrec_port_binding *peer = find_peer_port(ctx, sb_pb);
    if (!peer) {
        return NULL;
    }

    return peer->n_mac ? *peer->mac : NULL;
}

static void
sync_lsp_tnl_key(const struct nbrec_logical_switch_port *lsp,
                 int64_t isb_tnl_key)
{
    int64_t tnl_key = smap_get_int(&lsp->options, "requested-tnl-key", 0);
    if (tnl_key != isb_tnl_key) {
        VLOG_DBG("Set options:requested-tnl-key %"PRId64
                 " for lsp %s in NB.", isb_tnl_key, lsp->name);
        char *tnl_key_str = xasprintf("%"PRId64, isb_tnl_key);
        nbrec_logical_switch_port_update_options_setkey(lsp,
                                                        "requested-tnl-key",
                                                        tnl_key_str);
        free(tnl_key_str);
    }

}

static inline void
sync_lrp_tnl_key(const struct nbrec_logical_router_port *lrp,
                 int64_t isb_tnl_key)
{
    int64_t tnl_key = smap_get_int(&lrp->options, "requested-tnl-key", 0);
    if (tnl_key != isb_tnl_key) {
        VLOG_DBG("Set options:requested-tnl-key %" PRId64 " for lrp %s in NB.",
                 isb_tnl_key, lrp->name);
        char *tnl_key_str = xasprintf("%"PRId64, isb_tnl_key);
        nbrec_logical_router_port_update_options_setkey(
            lrp, "requested-tnl-key", tnl_key_str);
        free(tnl_key_str);
    }
}

static bool
get_router_uuid_by_sb_pb(struct ic_context *ctx,
                         const struct sbrec_port_binding *sb_pb,
                         struct uuid *router_uuid)
{
    const struct sbrec_port_binding *router_pb = find_peer_port(ctx, sb_pb);
    if (!router_pb || !router_pb->datapath) {
        return false;
    }

    return datapath_get_nb_uuid(router_pb->datapath, router_uuid);
}

static void
update_isb_pb_external_ids(struct ic_context *ctx,
                           const struct sbrec_port_binding *sb_pb,
                           const struct icsbrec_port_binding *isb_pb)
{
    struct uuid lr_uuid;
    if (!get_router_uuid_by_sb_pb(ctx, sb_pb, &lr_uuid)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Can't get router uuid for transit switch port %s.",
                     isb_pb->logical_port);
        return;
    }

    struct uuid current_lr_uuid;
    if (smap_get_uuid(&isb_pb->external_ids, "router-id", &current_lr_uuid) &&
        uuid_equals(&lr_uuid, &current_lr_uuid)) {
        return;
    }

    char *uuid_s = xasprintf(UUID_FMT, UUID_ARGS(&lr_uuid));
    icsbrec_port_binding_update_external_ids_setkey(isb_pb, "router-id",
                                                    uuid_s);
    free(uuid_s);
}

/* Sync a local port's fields from TSP INB->ISB. */
static void
sync_tsp_pb(const struct icnbrec_transit_switch_port *tsp,
            const struct icsbrec_port_binding *isb_pb)
{
    if (!isb_pb) {
        return;
    }

    /* Sync address to ISB. */
    if (!tsp->n_addresses && isb_pb->address[0]) {
        icsbrec_port_binding_set_address(isb_pb, "");
    } else if (tsp->n_addresses &&
               strcmp(tsp->addresses[0], isb_pb->address)) {
        icsbrec_port_binding_set_address(isb_pb, tsp->addresses[0]);
    }

    /* Sync gateway to ISB. */
    if (strcmp(tsp->chassis, isb_pb->gateway)) {
        icsbrec_port_binding_set_gateway(isb_pb, tsp->chassis);
    }
}

/* Sync a transit router port's fields from ICNB->ISB. */
static void
sync_trp_pb(const struct icnbrec_transit_router_port *trp,
            const struct icsbrec_port_binding *isb_pb)
{
    if (!isb_pb) {
        return;
    }

    /* Sync address to ISB. */
    if (strcmp(trp->mac, isb_pb->address)) {
        icsbrec_port_binding_set_address(isb_pb, trp->mac);
    }
}

/* For each local port:
 *   - Sync from NB to ISB.
 *   - Sync gateway from SB to ISB.
 *   - Sync tunnel key from ISB to NB.
 */
static void
sync_local_port(struct ic_context *ctx,
                const struct icsbrec_port_binding *isb_pb,
                const struct sbrec_port_binding *sb_pb,
                const struct nbrec_logical_switch_port *lsp)
{
    /* Sync address from NB to ISB */
    const char *address = get_lp_address_for_sb_pb(ctx, sb_pb);
    if (!address) {
        VLOG_DBG("Can't get router/switch port address for logical"
                 " switch port %s", sb_pb->logical_port);
        if (isb_pb->address[0]) {
            icsbrec_port_binding_set_address(isb_pb, "");
        }
    } else {
        if (strcmp(address, isb_pb->address)) {
            icsbrec_port_binding_set_address(isb_pb, address);
        }
    }

    /* Sync gateway from SB to ISB */
    const struct sbrec_port_binding *crp = find_crp_for_sb_pb(ctx, sb_pb);
    if (crp && crp->chassis) {
        if (strcmp(crp->chassis->name, isb_pb->gateway)) {
            icsbrec_port_binding_set_gateway(isb_pb, crp->chassis->name);
        }
    } else if (!strcmp(lsp->type, "switch") && sb_pb->chassis) {
        if (strcmp(sb_pb->chassis->name, isb_pb->gateway)) {
            icsbrec_port_binding_set_gateway(isb_pb, sb_pb->chassis->name);
        }
    } else {
        if (isb_pb->gateway[0]) {
            icsbrec_port_binding_set_gateway(isb_pb, "");
        }
    }

    /* Sync external_ids:router-id to ISB */
    update_isb_pb_external_ids(ctx, sb_pb, isb_pb);

    /* Sync back tunnel key from ISB to NB */
    sync_lsp_tnl_key(lsp, isb_pb->tunnel_key);
}

static void
sync_tsp_router_peer(const struct icnbrec_transit_switch_port *tsp,
                     const struct nbrec_logical_switch_port *lsp)
{
    /* Clear the peer for router port type. */
    if (lsp->peer && lsp->peer[0]) {
        nbrec_logical_switch_port_set_peer(lsp, NULL);
    }

    if (tsp->peer[0]) {
        const char *rp = smap_get(&lsp->options, "router-port");
        if (!rp || strcmp(rp, tsp->peer)) {
            nbrec_logical_switch_port_update_options_setkey(
                lsp, "router-port", tsp->peer);
        }
    } else if (smap_get(&lsp->options, "router-port")) {
        nbrec_logical_switch_port_update_options_delkey(lsp, "router-port");
    }
}

static void
sync_tsp_non_router_peer(const struct icnbrec_transit_switch_port *tsp,
                         const struct nbrec_logical_switch_port *lsp)
{
    /* Clear router-port setting for non-routers. */
    if (smap_get(&lsp->options, "router-port")) {
        nbrec_logical_switch_port_update_options_delkey(lsp, "router-port");
    }

    if (tsp->peer[0]) {
        if (!lsp->peer || strcmp(lsp->peer, tsp->peer)) {
            nbrec_logical_switch_port_set_peer(lsp, tsp->peer);
        }
    } else if (lsp->peer && lsp->peer[0]) {
        nbrec_logical_switch_port_set_peer(lsp, NULL);
    }
}

static void
sync_tsp_common(const struct icnbrec_transit_switch_port *tsp,
                const struct icsbrec_port_binding *isb_pb,
                const struct nbrec_logical_switch_port *lsp)
{
    /* Sync addresses from TSP to NB. */
    nbrec_logical_switch_port_set_addresses(
        lsp, (const char **) tsp->addresses, tsp->n_addresses);

    if (tsp->chassis[0]) {
        const char *current = smap_get(&lsp->options, "requested-chassis");
        if (!current || strcmp(current, tsp->chassis)) {
            nbrec_logical_switch_port_update_options_setkey(
                lsp, "requested-chassis", tsp->chassis);
        }
    } else if (smap_get(&lsp->options, "requested-chassis")) {
        nbrec_logical_switch_port_update_options_delkey(
            lsp, "requested-chassis");
    }

    /* Sync tunnel key from ISB to NB. */
    sync_lsp_tnl_key(lsp, isb_pb->tunnel_key);

    if (!strcmp(tsp->type, "router")) {
        sync_tsp_router_peer(tsp, lsp);
    } else {
        sync_tsp_non_router_peer(tsp, lsp);
    }
}

static void
sync_tsp_local(const struct icnbrec_transit_switch_port *tsp,
               const struct icsbrec_port_binding *isb_pb,
               const struct nbrec_logical_switch_port *lsp)
{
    if (strcmp(lsp->type, tsp->type)) {
        nbrec_logical_switch_port_set_type(lsp, tsp->type);
    }
    sync_tsp_common(tsp, isb_pb, lsp);
}

static void
sync_tsp_remote(const struct icnbrec_transit_switch_port *tsp,
                const struct icsbrec_port_binding *isb_pb,
                const struct nbrec_logical_switch_port *lsp)
{
    if (strcmp(lsp->type, "remote")) {
        nbrec_logical_switch_port_set_type(lsp, "remote");
    }
    sync_tsp_common(tsp, isb_pb, lsp);
}

/* For each remote port:
 *   - Sync from ISB to NB
 *   - Sync gateway from ISB to SB
 */
static void
sync_remote_port(struct ic_context *ctx,
                 const struct icsbrec_port_binding *isb_pb,
                 const struct nbrec_logical_switch_port *lsp,
                 const struct sbrec_port_binding *sb_pb)
{
    /* Sync address from ISB to NB */
    if (isb_pb->address[0]) {
        if (lsp->n_addresses != 1 ||
            strcmp(isb_pb->address, lsp->addresses[0])) {
            nbrec_logical_switch_port_set_addresses(
                lsp, (const char **)&isb_pb->address, 1);
        }
    } else {
        if (lsp->n_addresses != 0) {
            nbrec_logical_switch_port_set_addresses(lsp, NULL, 0);
        }
    }

    /* Sync tunnel key from ISB to NB */
    sync_lsp_tnl_key(lsp, isb_pb->tunnel_key);

    /* Skip port binding if it is already requested by the CMS. */
    if (smap_get(&lsp->options, "requested-chassis")) {
        return;
    }

    /* Sync gateway from ISB to SB */
    if (isb_pb->gateway[0]) {
        if (!sb_pb->chassis || strcmp(sb_pb->chassis->name, isb_pb->gateway)) {
            const struct sbrec_chassis *chassis =
                find_sb_chassis(ctx, isb_pb->gateway);
            if (!chassis) {
                VLOG_DBG("Chassis %s is not found in SB, syncing from ISB "
                         "to SB skipped for logical port %s.",
                         isb_pb->gateway, lsp->name);
                return;
            }
            sbrec_port_binding_set_chassis(sb_pb, chassis);
        }
    } else {
        if (sb_pb->chassis) {
            sbrec_port_binding_set_chassis(sb_pb, NULL);
        }
    }
}

/* For each remote port:
 *   - Sync from ISB to NB
 */
static void
sync_router_port(const struct icsbrec_port_binding *isb_pb,
                 const struct icnbrec_transit_router_port *trp,
                 const struct nbrec_logical_router_port *lrp)
{
    /* Sync from ICNB to NB */
    if (trp->chassis[0]) {
        const char *chassis_name =
            smap_get_def(&lrp->options, "requested-chassis", "");
        if (strcmp(trp->chassis, chassis_name)) {
            nbrec_logical_router_port_update_options_setkey(
                lrp, "requested-chassis", trp->chassis);
        }
    } else if (smap_get(&lrp->options, "requested-chassis")) {
        nbrec_logical_router_port_update_options_delkey(
            lrp, "requested-chassis");
    }

    if (strcmp(trp->mac, lrp->mac)) {
        nbrec_logical_router_port_set_mac(lrp, trp->mac);
    }

    bool sync_networks = false;
    if (trp->n_networks != lrp->n_networks) {
        sync_networks = true;
    } else {
        for (size_t i = 0; i < trp->n_networks; i++) {
            if (strcmp(trp->networks[i], lrp->networks[i])) {
                sync_networks = true;
                break;
            }
        }
    }

    if (sync_networks) {
        nbrec_logical_router_port_set_networks(
            lrp, (const char **) trp->networks, trp->n_networks);
    }

    /* Sync tunnel key from ISB to NB */
    sync_lrp_tnl_key(lrp, isb_pb->tunnel_key);
}

static void
create_nb_lsp(struct ic_context *ctx,
              const struct icsbrec_port_binding *isb_pb,
              const struct nbrec_logical_switch *ls)
{
    const struct nbrec_logical_switch_port *lsp =
        nbrec_logical_switch_port_insert(ctx->ovnnb_txn);
    nbrec_logical_switch_port_set_name(lsp, isb_pb->logical_port);
    nbrec_logical_switch_port_set_type(lsp, "remote");

    bool up = true;
    nbrec_logical_switch_port_set_up(lsp, &up, 1);

    if (isb_pb->address[0]) {
        nbrec_logical_switch_port_set_addresses(
            lsp, (const char **)&isb_pb->address, 1);
    }
    sync_lsp_tnl_key(lsp, isb_pb->tunnel_key);
    nbrec_logical_switch_update_ports_addvalue(ls, lsp);
}

static uint32_t
allocate_port_key(struct hmap *pb_tnlids)
{
    static uint32_t hint;
    return ovn_allocate_tnlid(pb_tnlids, "transit port",
                              1, (1u << 15) - 1, &hint);
}

/* Look up a transit switch / router by name through an index instead of
 * scanning every IC-NB row, so a scoped reconcile is O(scope) rather than
 * O(all transit switches/routers). */
static const struct icnbrec_transit_switch *
find_transit_switch_by_name(struct ic_context *ctx, const char *name)
{
    const struct icnbrec_transit_switch *key =
        icnbrec_transit_switch_index_init_row(
            ctx->icnbrec_transit_switch_by_name);
    icnbrec_transit_switch_index_set_name(key, name);
    const struct icnbrec_transit_switch *ts =
        icnbrec_transit_switch_index_find(ctx->icnbrec_transit_switch_by_name,
                                          key);
    icnbrec_transit_switch_index_destroy_row(key);
    return ts;
}

static const struct icnbrec_transit_router *
find_transit_router_by_name(struct ic_context *ctx, const char *name)
{
    const struct icnbrec_transit_router *key =
        icnbrec_transit_router_index_init_row(
            ctx->icnbrec_transit_router_by_name);
    icnbrec_transit_router_index_set_name(key, name);
    const struct icnbrec_transit_router *tr =
        icnbrec_transit_router_index_find(ctx->icnbrec_transit_router_by_name,
                                          key);
    icnbrec_transit_router_index_destroy_row(key);
    return tr;
}

static const struct icsbrec_port_binding *
create_isb_pb(struct ovsdb_idl_txn *isb_txn, const char *logical_port,
              const struct icsbrec_availability_zone *az, const char *ts_name,
              const struct uuid *nb_ic_uuid, const char *type,
              struct hmap *pb_tnlids)
{
    uint32_t pb_tnl_key = allocate_port_key(pb_tnlids);
    if (!pb_tnl_key) {
        return NULL;
    }

    const struct icsbrec_port_binding *isb_pb =
        icsbrec_port_binding_insert(isb_txn);
    icsbrec_port_binding_set_availability_zone(isb_pb, az);
    icsbrec_port_binding_set_transit_switch(isb_pb, ts_name);
    icsbrec_port_binding_set_logical_port(isb_pb, logical_port);
    icsbrec_port_binding_set_tunnel_key(isb_pb, pb_tnl_key);
    icsbrec_port_binding_set_nb_ic_uuid(isb_pb, nb_ic_uuid, 1);
    icsbrec_port_binding_set_type(isb_pb, type);
    return isb_pb;
}

static bool
chassis_is_remote(struct ic_context *ctx, const char *chassis_name)
{
    if (chassis_name) {
        const struct sbrec_chassis *chassis =
            find_sb_chassis(ctx, chassis_name);
        if (chassis) {
            return smap_get_bool(&chassis->other_config, "is-remote", false);
        } else {
            return true;
        }
    }

    return false;
}

static struct nbrec_logical_router_port *
lrp_create(struct ic_context *ctx, const struct nbrec_logical_router *lr,
           const struct icnbrec_transit_router_port *trp)
{
    /* An LRP with this name may already exist as an uncommitted insert from an
     * earlier change handler in this same engine iteration: the engine can run
     * change handlers and then recompute the node in one iteration (a later
     * input handler returning EN_UNHANDLED triggers run() without rolling back
     * the earlier handlers' NB writes - see inc-proc-eng engine_recompute()).
     * That row is invisible to the caller's lr->ports scan (the pending
     * addvalue is not reflected until commit) but is present in the by-name
     * index, so reuse it instead of inserting a duplicate, which would violate
     * the Logical_Router_Port name uniqueness index and abort the txn. */
    const struct nbrec_logical_router_port *existing =
        get_lrp_by_lrp_name(ctx, trp->name);
    if (existing) {
        return CONST_CAST(struct nbrec_logical_router_port *, existing);
    }

    struct nbrec_logical_router_port *lrp =
        nbrec_logical_router_port_insert(ctx->ovnnb_txn);
    nbrec_logical_router_port_set_name(lrp, trp->name);

    nbrec_logical_router_port_update_options_setkey(lrp, "interconn-tr",
                                                    trp->name);
    nbrec_logical_router_update_ports_addvalue(lr, lrp);
    return lrp;
}

static void
sync_ts_isb_pb(struct ic_context *ctx, const struct sbrec_port_binding *sb_pb,
               const struct icsbrec_port_binding *isb_pb)
{
    const char *address = get_lp_address_for_sb_pb(ctx, sb_pb);
    if (address) {
        icsbrec_port_binding_set_address(isb_pb, address);
    }

    const struct sbrec_port_binding *crp = find_crp_for_sb_pb(ctx, sb_pb);
    if (crp && crp->chassis) {
        icsbrec_port_binding_set_gateway(isb_pb, crp->chassis->name);
    }

    update_isb_pb_external_ids(ctx, sb_pb, isb_pb);

    /* Sync encap so that multiple encaps can be used for the same
     * gateway.  However, it is not needed for now, since we don't yet
     * support specifying encap type/ip for gateway chassis or ha-chassis
     * for logical router port in NB DB, and now encap should always be
     * empty.  The sync can be added if we add such support for gateway
     * chassis/ha-chassis in NB DB. */
}

static struct nbrec_logical_switch_port *
lsp_create(struct ic_context *ctx, const struct nbrec_logical_switch *ls,
           const struct icnbrec_transit_switch_port *tsp)
{
    /* Reuse an LSP already inserted (uncommitted) by an earlier change handler
     * in this same engine iteration: the engine can run change handlers and
     * then recompute the node in one iteration, and the pending row is
     * invisible to the caller's ls->ports scan but present in the by-name
     * index.  Inserting a duplicate would violate the name uniqueness index.
     * See the note in lrp_create(). */
    const struct nbrec_logical_switch_port *existing =
        get_lsp_by_ts_port_name(ctx, tsp->name);
    if (existing) {
        return CONST_CAST(struct nbrec_logical_switch_port *, existing);
    }

    struct nbrec_logical_switch_port *lsp =
        nbrec_logical_switch_port_insert(ctx->ovnnb_txn);
    nbrec_logical_switch_port_set_name(lsp, tsp->name);

    nbrec_logical_switch_port_update_options_setkey(lsp, "interconn-tsp",
                                                    tsp->name);
    nbrec_logical_switch_update_ports_addvalue(ls, lsp);
    return lsp;
}

static const struct sbrec_port_binding *
find_lsp_in_sb(struct ic_context *ctx,
               const struct nbrec_logical_switch_port *lsp)
{
    return find_sb_pb_by_name(ctx->sbrec_port_binding_by_name, lsp->name);
}

/* Reconcile the IC-SB and NB port bindings of a single transit switch 'ts'
 * (against its NB logical-switch mirror).  Local IC-SB ports that are matched
 * to an existing transit-switch port are removed from 'switch_all_local_pbs'
 * so the caller can delete the leftovers as orphans.
 *
 * The tunnel-key pool is built here, per transit switch, from every
 * binding on this switch -- both this AZ's (local) and the other AZs'
 * (remote).  The IC-SB uniqueness constraint is on (transit_switch,
 * tunnel_key) across all AZs, so a per-AZ pool could hand out a key already
 * used by a remote AZ on the same switch and the commit would fail.  Seeding
 * from the per-switch 'by_ts' scan (which this function already performs)
 * makes allocations unique per switch as the constraint requires, and lets
 * keys be reused across switches so the 15-bit space is not exhausted. */
static void
port_binding_sync_ts(struct ic_context *ctx,
                     const struct icsbrec_availability_zone *runned_az,
                     const struct icnbrec_transit_switch *ts,
                     struct shash *switch_all_local_pbs)
{
    const struct nbrec_logical_switch *ls = find_ts_in_nb(ctx, ts->name);
    if (!ls) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Transit switch %s not found in NB.", ts->name);
        return;
    }

    struct shash nb_ports = SHASH_INITIALIZER(&nb_ports);
    struct shash old_nb_ports = SHASH_INITIALIZER(&old_nb_ports);
    struct shash local_pbs = SHASH_INITIALIZER(&local_pbs);
    struct shash remote_pbs = SHASH_INITIALIZER(&remote_pbs);
    struct hmap pb_tnlids = HMAP_INITIALIZER(&pb_tnlids);
    const struct icsbrec_port_binding *isb_pb;
    struct shash_node *node;

    for (size_t i = 0; i < ls->n_ports; i++) {
        const struct nbrec_logical_switch_port *lsp = ls->ports[i];
        if (smap_get(&lsp->options, "interconn-tsp")) {
            shash_add(&nb_ports, lsp->name, lsp);
        } else {
            shash_add(&old_nb_ports, lsp->name, lsp);
        }
    }

    const struct icsbrec_port_binding *isb_pb_key =
        icsbrec_port_binding_index_init_row(ctx->icsbrec_port_binding_by_ts);
    icsbrec_port_binding_index_set_transit_switch(isb_pb_key, ts->name);

    ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
                                         ctx->icsbrec_port_binding_by_ts) {
        if (isb_pb->availability_zone == runned_az) {
            shash_add(&local_pbs, isb_pb->logical_port, isb_pb);
            shash_find_and_delete(switch_all_local_pbs, isb_pb->logical_port);
        } else {
            /* One NB Logical_Switch_Port is created per entry below, and
             * the NB port name is unique, so deduplicate by logical_port:
             * two bindings naming the same port would otherwise become two
             * colliding inserts and fail the commit on every run. */
            shash_add_once(&remote_pbs, isb_pb->logical_port, isb_pb);
        }
        /* Reserve every key in use on this switch (local and remote). */
        ovn_add_tnlid(&pb_tnlids, isb_pb->tunnel_key);
    }
    icsbrec_port_binding_index_destroy_row(isb_pb_key);

    for (size_t i = 0; i < ts->n_ports; i++) {
        struct icnbrec_transit_switch_port *tsp = ts->ports[i];

        if (!tsp->chassis[0]) {
            isb_pb = shash_find_and_delete(&local_pbs, tsp->name);
            if (!isb_pb) {
                isb_pb = shash_find_and_delete(&remote_pbs, tsp->name);
            }

            if (ctx->ovnisb_txn && is_az_leader(ctx->ovnisb_txn)) {
                if (!isb_pb) {
                    isb_pb = create_isb_pb(
                        ctx->ovnisb_txn, tsp->name, runned_az,
                        ts->name, &ts->header_.uuid, "transit-switch-port",
                        &pb_tnlids);
                }
                sync_tsp_pb(tsp, isb_pb);
            }
        } else if (!chassis_is_remote(ctx, tsp->chassis)) {
            /* Create ISB port_binding as its chassis is local. */
            isb_pb = shash_find_and_delete(&local_pbs, tsp->name);
            if (!isb_pb) {
                isb_pb = create_isb_pb(ctx->ovnisb_unlocked_txn, tsp->name,
                                       runned_az,
                                       ts->name, &ts->header_.uuid,
                                       "transit-switch-port", &pb_tnlids);
            }
            sync_tsp_pb(tsp, isb_pb);
        } else {
            isb_pb = shash_find_and_delete(&remote_pbs, tsp->name);
        }

        if (!isb_pb) {
            continue;
        }

        const struct nbrec_logical_switch_port *lsp =
            shash_find_and_delete(&nb_ports, tsp->name);
        if (!lsp) {
            lsp = lsp_create(ctx, ls, tsp);
        }

        if (!tsp->chassis[0] || !chassis_is_remote(ctx, tsp->chassis)) {
            sync_tsp_local(tsp, isb_pb, lsp);
        } else {
            sync_tsp_remote(tsp, isb_pb, lsp);
        }
    }

    /* Support legacy way of adding transit switch ports. */
    const struct sbrec_port_binding *sb_pb;
    const struct nbrec_logical_switch_port *lsp;
    SHASH_FOR_EACH (node, &old_nb_ports) {
        lsp = node->data;

        if (!strcmp(lsp->type, "router")
            || !strcmp(lsp->type, "switch")) {
            /* The port is local. */
            sb_pb = find_lsp_in_sb(ctx, lsp);
            if (!sb_pb) {
                continue;
            }
            isb_pb = shash_find_and_delete(&local_pbs, lsp->name);
            if (!isb_pb) {
                isb_pb = create_isb_pb(
                    ctx->ovnisb_unlocked_txn, sb_pb->logical_port,
                    runned_az, ts->name, &ts->header_.uuid,
                    "transit-switch-port", &pb_tnlids);
                sync_ts_isb_pb(ctx, sb_pb, isb_pb);
            } else {
                sync_local_port(ctx, isb_pb, sb_pb, lsp);
            }

            if (isb_pb->type) {
                icsbrec_port_binding_set_type(isb_pb, "transit-switch-port");
            }

            if (isb_pb->nb_ic_uuid) {
                icsbrec_port_binding_set_nb_ic_uuid(isb_pb,
                                                    &ts->header_.uuid, 1);
            }
        } else if (!strcmp(lsp->type, "remote")) {
            /* The port is remote. */
            isb_pb = shash_find_and_delete(&remote_pbs, lsp->name);
            if (!isb_pb) {
                nbrec_logical_switch_update_ports_delvalue(ls, lsp);
            } else {
                sb_pb = find_lsp_in_sb(ctx, lsp);
                if (!sb_pb) {
                    continue;
                }
                sync_remote_port(ctx, isb_pb, lsp, sb_pb);
            }
        } else {
            VLOG_DBG("Ignore lsp %s on ts %s with type %s.",
                     lsp->name, ts->name, lsp->type);
        }
    }

    SHASH_FOR_EACH (node, &nb_ports) {
        nbrec_logical_switch_port_delete(node->data);
        nbrec_logical_switch_update_ports_delvalue(ls, node->data);
    }

    /* Delete extra port-binding from ISB */
    SHASH_FOR_EACH (node, &local_pbs) {
        icsbrec_port_binding_delete(node->data);
    }

    /* Create lsp in NB for remote ports */
    SHASH_FOR_EACH (node, &remote_pbs) {
        create_nb_lsp(ctx, node->data, ls);
    }

    ovn_destroy_tnlids(&pb_tnlids);
    shash_destroy(&nb_ports);
    shash_destroy(&local_pbs);
    shash_destroy(&remote_pbs);
    shash_destroy(&old_nb_ports);
}

/* Reconcile the IC-SB and NB port bindings of a single transit router 'tr'
 * (against its NB logical-router mirror).  Every local IC-SB port of 'tr' is
 * removed from 'router_all_local_pbs', so the caller only deletes the bindings
 * of routers that no longer exist; a local binding of 'tr' that no
 * transit-router port claims is deleted here.  New port tunnel keys are
 * allocated from a per-router pool seeded from every binding on this router
 * (local and remote) -- see the note on port_binding_sync_ts().
 *
 * A port without a chassis is local to every AZ: a single IC-SB binding,
 * created by the AZ leader, is shared by all the AZs so that they agree on its
 * tunnel key.  The other AZs pick it up as a remote binding once the leader's
 * IC-SB transaction lands (the IC-SB Port_Binding handler scopes 'tr'). */
static void
port_binding_sync_tr(struct ic_context *ctx,
                     const struct icsbrec_availability_zone *runned_az,
                     const struct icnbrec_transit_router *tr,
                     struct shash *router_all_local_pbs)
{
    const struct nbrec_logical_router *lr = find_tr_in_nb(ctx, tr->name);
    if (!lr) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Transit router %s not found in NB.", tr->name);
        return;
    }

    struct shash nb_ports = SHASH_INITIALIZER(&nb_ports);
    struct shash local_pbs = SHASH_INITIALIZER(&local_pbs);
    struct shash remote_pbs = SHASH_INITIALIZER(&remote_pbs);
    struct hmap pb_tnlids = HMAP_INITIALIZER(&pb_tnlids);
    const struct icsbrec_port_binding *isb_pb;
    struct shash_node *node;

    for (size_t i = 0; i < lr->n_ports; i++) {
        const struct nbrec_logical_router_port *lrp = lr->ports[i];
        if (smap_get(&lrp->options, "interconn-tr")) {
            shash_add(&nb_ports, lrp->name, lrp);
        }
    }

    const struct icsbrec_port_binding *isb_pb_key =
        icsbrec_port_binding_index_init_row(ctx->icsbrec_port_binding_by_ts);
    icsbrec_port_binding_index_set_transit_switch(isb_pb_key, tr->name);

    ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
                                         ctx->icsbrec_port_binding_by_ts) {
        if (isb_pb->availability_zone == runned_az) {
            shash_add(&local_pbs, isb_pb->logical_port, isb_pb);
            shash_find_and_delete(router_all_local_pbs, isb_pb->logical_port);
        } else {
            /* Deduplicate by logical_port, as for a transit switch above:
             * one NB Logical_Router_Port is created per entry and the NB
             * port name is unique. */
            shash_add_once(&remote_pbs, isb_pb->logical_port, isb_pb);
        }
        /* Reserve every key in use on this router (local and remote). */
        ovn_add_tnlid(&pb_tnlids, isb_pb->tunnel_key);
    }
    icsbrec_port_binding_index_destroy_row(isb_pb_key);

    for (size_t i = 0; i < tr->n_ports; i++) {
        const struct icnbrec_transit_router_port *trp = tr->ports[i];

        if (!trp->chassis[0]) {
            isb_pb = shash_find_and_delete(&local_pbs, trp->name);
            if (!isb_pb) {
                isb_pb = shash_find_and_delete(&remote_pbs, trp->name);
            }

            if (ctx->ovnisb_txn && is_az_leader(ctx->ovnisb_txn)) {
                if (!isb_pb) {
                    isb_pb = create_isb_pb(ctx->ovnisb_txn, trp->name,
                                           runned_az,
                                           tr->name, &tr->header_.uuid,
                                           "transit-router-port",
                                           &pb_tnlids);
                }
                sync_trp_pb(trp, isb_pb);
            }
        } else if (chassis_is_remote(ctx, trp->chassis)) {
            isb_pb = shash_find_and_delete(&remote_pbs, trp->name);
        } else {
            isb_pb = shash_find_and_delete(&local_pbs, trp->name);
            if (!isb_pb) {
                isb_pb = create_isb_pb(ctx->ovnisb_unlocked_txn, trp->name,
                                       runned_az,
                                       tr->name, &tr->header_.uuid,
                                       "transit-router-port", &pb_tnlids);
            }
            sync_trp_pb(trp, isb_pb);
        }

        /* Don't allow remote ports to create NB LRP until ICSB entry is
         * created in the appropriate AZ. */
        if (isb_pb) {
            const struct nbrec_logical_router_port *lrp =
                shash_find_and_delete(&nb_ports, trp->name);
            if (!lrp) {
                lrp = lrp_create(ctx, lr, trp);
            }

            sync_router_port(isb_pb, trp, lrp);
        }
    }

    SHASH_FOR_EACH (node, &nb_ports) {
        nbrec_logical_router_port_delete(node->data);
        nbrec_logical_router_update_ports_delvalue(lr, node->data);
    }

    /* Delete extra port-binding from ISB.  Any local port binding that is not
     * claimed by a transit router port above belongs to a port that has been
     * removed, or that is no longer local to this AZ. */
    SHASH_FOR_EACH (node, &local_pbs) {
        icsbrec_port_binding_delete(node->data);
    }

    ovn_destroy_tnlids(&pb_tnlids);
    shash_destroy(&nb_ports);
    shash_destroy(&local_pbs);
    shash_destroy(&remote_pbs);
}

/* Adds to 'gc' (keyed by logical_port) every local IC-SB port binding whose
 * transit_switch is one of the names in 'names'.  Used to build a transit-
 * switch/router-scoped garbage-collection set: the per-entity sync claims the
 * still-valid bindings and the caller deletes whatever remains. */
static void
collect_local_pbs_by_names(struct ic_context *ctx,
                           const struct icsbrec_availability_zone *runned_az,
                           const struct sset *names,
                           struct shash *gc)
{
    const char *name;
    SSET_FOR_EACH (name, names) {
        const struct icsbrec_port_binding *isb_pb;
        const struct icsbrec_port_binding *key =
            icsbrec_port_binding_index_init_row(
                ctx->icsbrec_port_binding_by_ts);
        icsbrec_port_binding_index_set_transit_switch(key, name);
        ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, key,
                                             ctx->icsbrec_port_binding_by_ts) {
            if (isb_pb->availability_zone == runned_az &&
                !shash_find(gc, isb_pb->logical_port)) {
                shash_add(gc, isb_pb->logical_port, isb_pb);
            }
        }
        icsbrec_port_binding_index_destroy_row(key);
    }
}

/* Synchronizes cross-AZ port bindings.  When both 'ts_scope' and 'tr_scope'
 * are NULL every transit switch and transit router in the AZ is reconciled
 * (full recompute).  Otherwise only the transit switches named in 'ts_scope'
 * and the transit routers named in 'tr_scope' are reconciled (each scope may
 * be a non-NULL empty set, meaning "no entity of that kind").  A name no
 * longer present in IC-NB (a deleted entity, or one whose NB mirror is gone)
 * is still honoured: its local bindings end up as garbage-collection leftovers
 * and are deleted, matching the full-recompute behaviour. */
static void
port_binding_sync_scope(struct ic_context *ctx,
                        const struct icsbrec_availability_zone *runned_az,
                        const struct sset *ts_scope,
                        const struct sset *tr_scope)
{
    if (!ctx->ovnisb_unlocked_txn || !ctx->ovnnb_txn || !ctx->ovnsb_txn) {
        return;
    }

    bool full = !ts_scope && !tr_scope;

    struct shash switch_all_local_pbs =
        SHASH_INITIALIZER(&switch_all_local_pbs);
    struct shash router_all_local_pbs =
        SHASH_INITIALIZER(&router_all_local_pbs);
    struct shash_node *node;

    /* Seed the garbage-collection sets with this AZ's local bindings.  Tunnel
     * keys are no longer pooled here: port_binding_sync_ts()/_tr() build a
     * per-entity key pool from every binding on that switch/router. */
    if (full) {
        const struct icsbrec_port_binding *isb_pb;
        const struct icsbrec_port_binding *isb_pb_key =
            icsbrec_port_binding_index_init_row(
                ctx->icsbrec_port_binding_by_az);
        icsbrec_port_binding_index_set_availability_zone(isb_pb_key,
                                                         runned_az);
        ICSBREC_PORT_BINDING_FOR_EACH_EQUAL (isb_pb, isb_pb_key,
                                             ctx->icsbrec_port_binding_by_az) {
            struct shash *gc = ic_pb_get_type(isb_pb) == IC_ROUTER_PORT
                               ? &router_all_local_pbs : &switch_all_local_pbs;
            shash_add(gc, isb_pb->logical_port, isb_pb);
        }
        icsbrec_port_binding_index_destroy_row(isb_pb_key);
    } else {
        if (ts_scope) {
            collect_local_pbs_by_names(ctx, runned_az, ts_scope,
                                       &switch_all_local_pbs);
        }
        if (tr_scope) {
            collect_local_pbs_by_names(ctx, runned_az, tr_scope,
                                       &router_all_local_pbs);
        }
    }

    /* Reconcile exactly the in-scope transit switches via an index
     * lookup, instead of scanning every transit switch on every call. */
    if (full) {
        const struct icnbrec_transit_switch *ts;
        ICNBREC_TRANSIT_SWITCH_FOR_EACH (ts, ctx->ovninb_idl) {
            port_binding_sync_ts(ctx, runned_az, ts, &switch_all_local_pbs);
        }
    } else if (ts_scope) {
        const char *name;
        SSET_FOR_EACH (name, ts_scope) {
            const struct icnbrec_transit_switch *ts =
                find_transit_switch_by_name(ctx, name);
            if (ts) {
                port_binding_sync_ts(ctx, runned_az, ts,
                                     &switch_all_local_pbs);
            }
        }
    }

    SHASH_FOR_EACH (node, &switch_all_local_pbs) {
        icsbrec_port_binding_delete(node->data);
    }
    shash_destroy(&switch_all_local_pbs);

    /* Same scope-driven reconcile for transit routers. */
    if (full) {
        const struct icnbrec_transit_router *tr;
        ICNBREC_TRANSIT_ROUTER_FOR_EACH (tr, ctx->ovninb_idl) {
            port_binding_sync_tr(ctx, runned_az, tr, &router_all_local_pbs);
        }
    } else if (tr_scope) {
        const char *name;
        SSET_FOR_EACH (name, tr_scope) {
            const struct icnbrec_transit_router *tr =
                find_transit_router_by_name(ctx, name);
            if (tr) {
                port_binding_sync_tr(ctx, runned_az, tr,
                                     &router_all_local_pbs);
            }
        }
    }

    SHASH_FOR_EACH (node, &router_all_local_pbs) {
        icsbrec_port_binding_delete(node->data);
    }

    shash_destroy(&router_all_local_pbs);
}

static void
port_binding_run(struct ic_context *ctx,
                 const struct icsbrec_availability_zone *runned_az)
{
    port_binding_sync_scope(ctx, runned_az, NULL, NULL);
}

/* Build once per handler invocation, a map from every NB transit-router-mirror
 * port name to its transit router name (the mirror logical router's name).
 * See port_binding_lsp_ts_map_init(). */
static void
port_binding_lrp_tr_map_init(struct ic_context *ctx, struct shash *map)
{
    shash_init(map);
    const struct nbrec_logical_router *lr;
    NBREC_LOGICAL_ROUTER_FOR_EACH (lr, ctx->ovnnb_idl) {
        if (!smap_get(&lr->options, "interconn-tr")) {
            continue;
        }
        for (size_t i = 0; i < lr->n_ports; i++) {
            shash_replace(map, lr->ports[i]->name, CONST_CAST(char *,
                          lr->name));
        }
    }
}

/* If 'lrp' is an interconnection port of a transit-router mirror, adds that
 * transit router's name (looked up in 'lrp_tr_map') to 'tr_scope'. */
static void
port_binding_collect_lrp_tr(const struct shash *lrp_tr_map,
                            const struct nbrec_logical_router_port *lrp,
                            struct sset *tr_scope)
{
    const char *tr_name = shash_find_data(lrp_tr_map, lrp->name);
    if (tr_name) {
        sset_add(tr_scope, tr_name);
    }
}

/* Builds 'map': a mapping from every SB port-binding name whose state a
 * transit-switch sync reads, to the owning transit switch's name.  For each
 * TS-mirror port this covers the port itself and, for router-typed ports, the
 * peer logical_router_port (its MAC/datapath) and that port's chassisredirect
 * (the gateway chassis) - i.e. exactly the SB rows read by sync_local_port() /
 * sync_ts_isb_pb().  Transit-router syncs do not read SB port bindings, so
 * only transit switches contribute.  Values are IC-NB-owned strings; destroy
 * with port_binding_sb_name_ts_map_destroy(). */
static void
port_binding_sb_name_ts_map_init(struct ic_context *ctx, struct shash *map)
{
    shash_init(map);

    const struct icnbrec_transit_switch *ts;
    ICNBREC_TRANSIT_SWITCH_FOR_EACH (ts, ctx->ovninb_idl) {
        const struct nbrec_logical_switch *ls = find_ts_in_nb(ctx, ts->name);
        if (!ls) {
            continue;
        }
        for (size_t i = 0; i < ls->n_ports; i++) {
            const struct nbrec_logical_switch_port *lsp = ls->ports[i];
            if (!shash_find(map, lsp->name)) {
                shash_add(map, lsp->name, ts->name);
            }
            if (strcmp(lsp->type, "router")) {
                continue;
            }
            const char *rport = smap_get(&lsp->options, "router-port");
            if (!rport) {
                continue;
            }
            if (!shash_find(map, rport)) {
                shash_add(map, rport, ts->name);
            }
            char *crp = ovn_chassis_redirect_name(rport);
            if (!shash_find(map, crp)) {
                shash_add(map, crp, ts->name);
            }
            free(crp);
        }
    }
}

static void
port_binding_sb_name_ts_map_destroy(struct shash *map)
{
    shash_destroy(map);
}

/* en_port_binding tracked data.  'synced_ts'/'synced_tr' hold the transit
 * switches / routers already reconciled during the current engine run.  Two
 * different input change handlers of this node can map their changes to the
 * same entity (e.g. an IC-SB port_binding change and the NB Logical_Switch
 * mirror change both point at the same transit switch), and reconciling it a
 * second time in the same NB transaction re-creates its NB ports: pending row
 * inserts are not visible on the IDL until the transaction commits, so the
 * second pass does not see the ports created by the first.  These sets make
 * each entity reconciled at most once per run.  Cleared between runs by
 * en_port_binding_clear_tracked_data(). */
struct ed_type_port_binding {
    struct sset synced_ts;
    struct sset synced_tr;
};

enum engine_node_state
en_port_binding_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    const struct ed_type_az *az = engine_get_input_data("az", node);

    /* runned_az is resolved by the upstream en_az node.  Without an AZ there
     * is nothing to sync (mirrors the previous main-loop gating). */
    if (!az->runned_az) {
        return EN_UNCHANGED;
    }

    port_binding_run(ctx, az->runned_az);

    return EN_UPDATED;
}

/* Returns the ic_context, or NULL when there is no availability zone yet (in
 * which case the caller should report EN_HANDLED_UNCHANGED).  On success, sets
 * '*runned_az' to the AZ resolved by the upstream en_az node. */
static struct ic_context *
port_binding_handler_ctx(struct engine_node *node,
                         const struct icsbrec_availability_zone **runned_az)
{
    struct ic_context *ctx = engine_get_context()->client_ctx;
    const struct ed_type_az *az = engine_get_input_data("az", node);
    *runned_az = az->runned_az;
    return az->runned_az ? ctx : NULL;
}

/* The change handlers translate a changed input row into the set of transit
 * switches ('ts_scope') and transit routers ('tr_scope') that must be
 * reconciled, then call port_binding_sync_scope() on those sets instead of
 * forcing a full recompute.  port_binding_sync_ts()/_tr() are already scoped
 * to a single entity, so reconciling only the affected ones is sufficient. */

/* Runs the scoped sync for the collected scopes and maps it to an engine
 * result.  When there is work to do but the transactions sync needs are not
 * available yet, returns EN_UNHANDLED so the change is retried. */
static enum engine_input_handler_result
port_binding_scope_finish(struct ic_context *ctx,
                          const struct icsbrec_availability_zone *runned_az,
                          struct sset *ts_scope,
                          struct sset *tr_scope, void *node_data)
{
    struct ed_type_port_binding *pb = node_data;

    /* Drop transit switches / routers already reconciled earlier in this
     * engine run: port_binding_sync_ts()/_tr() fully reconcile an entity, so a
     * repeat sync in the same NB transaction is redundant and, because pending
     * row inserts are not visible until commit, would re-create its NB ports
     * (duplicate insert -> constraint violation -> recompute -> abort).
     * See 'synced_ts'/'synced_tr'. */
    const char *name;
    SSET_FOR_EACH_SAFE (name, ts_scope) {
        if (sset_contains(&pb->synced_ts, name)) {
            sset_find_and_delete(ts_scope, name);
        }
    }
    SSET_FOR_EACH_SAFE (name, tr_scope) {
        if (sset_contains(&pb->synced_tr, name)) {
            sset_find_and_delete(tr_scope, name);
        }
    }

    if (sset_is_empty(ts_scope) && sset_is_empty(tr_scope)) {
        return EN_HANDLED_UNCHANGED;
    }
    if (!ctx->ovnisb_unlocked_txn || !ctx->ovnnb_txn || !ctx->ovnsb_txn) {
        return EN_UNHANDLED;
    }
    SSET_FOR_EACH (name, ts_scope) {
        sset_add(&pb->synced_ts, name);
    }
    SSET_FOR_EACH (name, tr_scope) {
        sset_add(&pb->synced_tr, name);
    }
    port_binding_sync_scope(ctx, runned_az, ts_scope, tr_scope);
    return EN_HANDLED_UPDATED;
}

/* IC-NB Transit_Switch: a new/deleted transit switch must have its port
 * bindings reconciled (a deletion is honoured via the scoped GC).  A rename
 * cannot be scoped (the tracked row only carries the new name, so the bindings
 * collected under the old one would leak) and falls back to a full
 * recompute. */
enum engine_input_handler_result
port_binding_icnb_transit_switch_handler(struct engine_node *node,
                                         void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = port_binding_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct icnbrec_transit_switch_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_switch", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    struct sset tr_scope = SSET_INITIALIZER(&tr_scope);
    const struct icnbrec_transit_switch *ts;
    bool unhandled = false;
    ICNBREC_TRANSIT_SWITCH_TABLE_FOR_EACH_TRACKED (ts, tbl) {
        if (!icnbrec_transit_switch_is_new(ts) &&
            !icnbrec_transit_switch_is_deleted(ts) &&
            ovsdb_idl_track_is_updated(&ts->header_,
                                       &icnbrec_transit_switch_col_name)) {
            unhandled = true;
            break;
        }
        sset_add(&ts_scope, ts->name);
    }

    enum engine_input_handler_result ret =
        unhandled ? EN_UNHANDLED
                  : port_binding_scope_finish(ctx, runned_az, &ts_scope,
                                              &tr_scope, data);
    sset_destroy(&ts_scope);
    sset_destroy(&tr_scope);
    return ret;
}

/* IC-NB Transit_Router: analogous to the transit-switch handler, including
 * the full-recompute fallback on a rename. */
enum engine_input_handler_result
port_binding_icnb_transit_router_handler(struct engine_node *node,
                                         void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = port_binding_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct icnbrec_transit_router_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_router", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    struct sset tr_scope = SSET_INITIALIZER(&tr_scope);
    const struct icnbrec_transit_router *tr;
    bool unhandled = false;
    ICNBREC_TRANSIT_ROUTER_TABLE_FOR_EACH_TRACKED (tr, tbl) {
        if (!icnbrec_transit_router_is_new(tr) &&
            !icnbrec_transit_router_is_deleted(tr) &&
            ovsdb_idl_track_is_updated(&tr->header_,
                                       &icnbrec_transit_router_col_name)) {
            unhandled = true;
            break;
        }
        sset_add(&tr_scope, tr->name);
    }

    enum engine_input_handler_result ret =
        unhandled ? EN_UNHANDLED
                  : port_binding_scope_finish(ctx, runned_az, &ts_scope,
                                              &tr_scope, data);
    sset_destroy(&ts_scope);
    sset_destroy(&tr_scope);
    return ret;
}

/* IC-NB Transit_Router_Port: a column change on an existing port reconciles
 * its owning transit router (resolved via tr_uuid).  Port creation/deletion
 * also updates the transit router's 'ports' column and is handled by the
 * transit-router handler; handling it here too would reconcile the same router
 * twice in one iteration and double-delete rows, so new/deleted ports are
 * skipped. */
enum engine_input_handler_result
port_binding_icnb_transit_router_port_handler(struct engine_node *node,
                                              void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = port_binding_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct icnbrec_transit_router_port_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_router_port", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    struct sset tr_scope = SSET_INITIALIZER(&tr_scope);
    const struct icnbrec_transit_router_port *trp;
    ICNBREC_TRANSIT_ROUTER_PORT_TABLE_FOR_EACH_TRACKED (trp, tbl) {
        if (icnbrec_transit_router_port_is_new(trp) ||
            icnbrec_transit_router_port_is_deleted(trp)) {
            continue;
        }
        const struct icnbrec_transit_router *tr =
            icnbrec_transit_router_get_for_uuid(ctx->ovninb_idl,
                                                &trp->tr_uuid);
        if (tr) {
            sset_add(&tr_scope, tr->name);
        }
    }

    enum engine_input_handler_result ret =
        port_binding_scope_finish(ctx, runned_az, &ts_scope, &tr_scope, data);
    sset_destroy(&ts_scope);
    sset_destroy(&tr_scope);
    return ret;
}

/* IC-NB Transit_Switch_Port: a column change on an existing port reconciles
 * its owning transit switch.  Unlike Transit_Router_Port (which back-
 * references its router via tr_uuid), Transit_Switch_Port has no owning-switch
 * column, so the owner is resolved by scanning every transit switch's 'ports'.
 * Port creation/deletion also updates the transit switch's 'ports' column and
 * is handled by the transit-switch handler; handling it here too would
 * reconcile the same switch twice in one iteration and double-delete rows, so
 * new/deleted ports are skipped. */
enum engine_input_handler_result
port_binding_icnb_transit_switch_port_handler(struct engine_node *node,
                                              void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = port_binding_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct icnbrec_transit_switch_port_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICNB_transit_switch_port", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    struct sset tr_scope = SSET_INITIALIZER(&tr_scope);

    /* Only a modify of an existing port needs owner resolution; a new/deleted
     * port is reconciled through the transit-switch handler.  Build the
     * reverse (port name -> transit switch name) map only if such a modify
     * exists. */
    bool need_map = false;
    const struct icnbrec_transit_switch_port *tsp;
    ICNBREC_TRANSIT_SWITCH_PORT_TABLE_FOR_EACH_TRACKED (tsp, tbl) {
        if (!icnbrec_transit_switch_port_is_new(tsp) &&
            !icnbrec_transit_switch_port_is_deleted(tsp)) {
            need_map = true;
            break;
        }
    }

    if (need_map) {
        struct shash tsp_to_ts = SHASH_INITIALIZER(&tsp_to_ts);
        const struct icnbrec_transit_switch *ts;
        ICNBREC_TRANSIT_SWITCH_FOR_EACH (ts, ctx->ovninb_idl) {
            for (size_t i = 0; i < ts->n_ports; i++) {
                shash_add_once(&tsp_to_ts, ts->ports[i]->name, ts->name);
            }
        }

        ICNBREC_TRANSIT_SWITCH_PORT_TABLE_FOR_EACH_TRACKED (tsp, tbl) {
            if (icnbrec_transit_switch_port_is_new(tsp) ||
                icnbrec_transit_switch_port_is_deleted(tsp)) {
                continue;
            }
            const char *ts_name = shash_find_data(&tsp_to_ts, tsp->name);
            if (ts_name) {
                sset_add(&ts_scope, ts_name);
            }
        }
        shash_destroy(&tsp_to_ts);
    }

    enum engine_input_handler_result ret =
        port_binding_scope_finish(ctx, runned_az, &ts_scope, &tr_scope, data);
    sset_destroy(&ts_scope);
    sset_destroy(&tr_scope);
    return ret;
}

/* IC-SB Port_Binding: the binding's transit_switch column names its entity;
 * ic_pb_get_type() tells whether it is a transit-switch or transit-router
 * port.  The address/gateway/external_ids write-backs by the sync are
 * idempotent (guarded by value comparisons), so they converge without a
 * feedback loop. */
enum engine_input_handler_result
port_binding_icsb_port_binding_handler(struct engine_node *node,
                                       void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = port_binding_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct icsbrec_port_binding_table *tbl =
        EN_OVSDB_GET(engine_get_input("ICSB_port_binding", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    struct sset tr_scope = SSET_INITIALIZER(&tr_scope);
    const struct icsbrec_port_binding *isb_pb;
    ICSBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (isb_pb, tbl) {
        if (ic_pb_get_type(isb_pb) == IC_ROUTER_PORT) {
            sset_add(&tr_scope, isb_pb->transit_switch);
        } else {
            sset_add(&ts_scope, isb_pb->transit_switch);
        }
    }

    enum engine_input_handler_result ret =
        port_binding_scope_finish(ctx, runned_az, &ts_scope, &tr_scope, data);
    sset_destroy(&ts_scope);
    sset_destroy(&tr_scope);
    return ret;
}

/* NB Logical_Switch: only transit-switch mirrors (other_config:interconn-ts)
 * are read by the sync.  A change to such a mirror (its ports, name, or its
 * deletion) reconciles the transit switch; tenant switches are irrelevant. */
enum engine_input_handler_result
port_binding_nb_logical_switch_handler(struct engine_node *node,
                                       void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = port_binding_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct nbrec_logical_switch_table *tbl =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    struct sset tr_scope = SSET_INITIALIZER(&tr_scope);
    const struct nbrec_logical_switch *ls;
    NBREC_LOGICAL_SWITCH_TABLE_FOR_EACH_TRACKED (ls, tbl) {
        if (smap_get(&ls->other_config, "interconn-ts")) {
            sset_add(&ts_scope, ls->name);
        }
    }

    enum engine_input_handler_result ret =
        port_binding_scope_finish(ctx, runned_az, &ts_scope, &tr_scope, data);
    sset_destroy(&ts_scope);
    sset_destroy(&tr_scope);
    return ret;
}

/* NB Logical_Switch_Port: a column change on an existing transit-switch port
 * reconciles its transit switch.  Port creation/deletion changes the mirror's
 * 'ports' column and is handled by the NB logical_switch handler. */
enum engine_input_handler_result
port_binding_nb_logical_switch_port_handler(struct engine_node *node,
                                            void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = port_binding_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct nbrec_logical_switch_port_table *tbl =
        EN_OVSDB_GET(engine_get_input("NB_logical_switch_port", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    struct sset tr_scope = SSET_INITIALIZER(&tr_scope);
    struct shash lsp_ts_map;
    port_binding_lsp_ts_map_init(ctx, &lsp_ts_map);
    const struct nbrec_logical_switch_port *lsp;
    NBREC_LOGICAL_SWITCH_PORT_TABLE_FOR_EACH_TRACKED (lsp, tbl) {
        if (nbrec_logical_switch_port_is_new(lsp) ||
            nbrec_logical_switch_port_is_deleted(lsp)) {
            continue;
        }
        port_binding_collect_lsp_ts(&lsp_ts_map, lsp, &ts_scope);
    }
    shash_destroy(&lsp_ts_map);

    enum engine_input_handler_result ret =
        port_binding_scope_finish(ctx, runned_az, &ts_scope, &tr_scope, data);
    sset_destroy(&ts_scope);
    sset_destroy(&tr_scope);
    return ret;
}

/* NB Logical_Router: only transit-router mirrors (options:interconn-tr) are
 * read by the sync. */
enum engine_input_handler_result
port_binding_nb_logical_router_handler(struct engine_node *node,
                                       void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = port_binding_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct nbrec_logical_router_table *tbl =
        EN_OVSDB_GET(engine_get_input("NB_logical_router", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    struct sset tr_scope = SSET_INITIALIZER(&tr_scope);
    const struct nbrec_logical_router *lr;
    NBREC_LOGICAL_ROUTER_TABLE_FOR_EACH_TRACKED (lr, tbl) {
        if (smap_get(&lr->options, "interconn-tr")) {
            sset_add(&tr_scope, lr->name);
        }
    }

    enum engine_input_handler_result ret =
        port_binding_scope_finish(ctx, runned_az, &ts_scope, &tr_scope, data);
    sset_destroy(&ts_scope);
    sset_destroy(&tr_scope);
    return ret;
}

/* NB Logical_Router_Port: a column change on an existing transit-router port
 * reconciles its transit router.  Port creation/deletion changes the mirror's
 * 'ports' column and is handled by the NB logical_router handler. */
enum engine_input_handler_result
port_binding_nb_logical_router_port_handler(struct engine_node *node,
                                            void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = port_binding_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct nbrec_logical_router_port_table *tbl =
        EN_OVSDB_GET(engine_get_input("NB_logical_router_port", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    struct sset tr_scope = SSET_INITIALIZER(&tr_scope);
    struct shash lrp_tr_map;
    port_binding_lrp_tr_map_init(ctx, &lrp_tr_map);
    const struct nbrec_logical_router_port *lrp;
    NBREC_LOGICAL_ROUTER_PORT_TABLE_FOR_EACH_TRACKED (lrp, tbl) {
        if (nbrec_logical_router_port_is_new(lrp) ||
            nbrec_logical_router_port_is_deleted(lrp)) {
            continue;
        }
        port_binding_collect_lrp_tr(&lrp_tr_map, lrp, &tr_scope);
    }
    shash_destroy(&lrp_tr_map);

    enum engine_input_handler_result ret =
        port_binding_scope_finish(ctx, runned_az, &ts_scope, &tr_scope, data);
    sset_destroy(&ts_scope);
    sset_destroy(&tr_scope);
    return ret;
}

/* SB Port_Binding: a transit-switch sync reads SB state of its ports (the port
 * itself, the peer router port's MAC/datapath, and the chassisredirect's
 * gateway chassis).  Map each changed SB port binding back to its transit
 * switch via the name map; SB bindings of no IC port are irrelevant.  Transit-
 * router syncs do not read SB port bindings. */
enum engine_input_handler_result
port_binding_sb_port_binding_handler(struct engine_node *node,
                                     void *data)
{
    const struct icsbrec_availability_zone *runned_az;
    struct ic_context *ctx = port_binding_handler_ctx(node, &runned_az);
    if (!ctx) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct sbrec_port_binding_table *tbl =
        EN_OVSDB_GET(engine_get_input("SB_port_binding", node));
    struct sset ts_scope = SSET_INITIALIZER(&ts_scope);
    struct sset tr_scope = SSET_INITIALIZER(&tr_scope);

    struct shash name_map;
    port_binding_sb_name_ts_map_init(ctx, &name_map);

    const struct sbrec_port_binding *sb_pb;
    SBREC_PORT_BINDING_TABLE_FOR_EACH_TRACKED (sb_pb, tbl) {
        const char *ts_name = shash_find_data(&name_map, sb_pb->logical_port);
        if (ts_name) {
            sset_add(&ts_scope, ts_name);
        }
    }
    port_binding_sb_name_ts_map_destroy(&name_map);

    enum engine_input_handler_result ret =
        port_binding_scope_finish(ctx, runned_az, &ts_scope, &tr_scope, data);
    sset_destroy(&ts_scope);
    sset_destroy(&tr_scope);
    return ret;
}

/* SB Chassis: the sync only reads a chassis' existence and its
 * other_config:is-remote flag (via chassis_is_remote()), plus its (immutable)
 * name for the gateway field.  A chassis being created or deleted, or its
 * other_config changing, can therefore change the output; any other column
 * change (the frequent heartbeat-style updates: nb_cfg, encaps, external_ids,
 * hostname, ...) cannot.  So recompute only on insert/delete or an
 * other_config change, and ignore the rest instead of forcing a full
 * recompute on every chassis update. */
enum engine_input_handler_result
port_binding_sb_chassis_handler(struct engine_node *node,
                                void *data OVS_UNUSED)
{
    const struct ed_type_az *az = engine_get_input_data("az", node);
    if (!az->runned_az) {
        return EN_HANDLED_UNCHANGED;
    }

    const struct sbrec_chassis_table *tbl =
        EN_OVSDB_GET(engine_get_input("SB_chassis", node));
    const struct sbrec_chassis *chassis;
    SBREC_CHASSIS_TABLE_FOR_EACH_TRACKED (chassis, tbl) {
        if (sbrec_chassis_is_new(chassis)
            || sbrec_chassis_is_deleted(chassis)
            || sbrec_chassis_is_updated(chassis,
                                        SBREC_CHASSIS_COL_OTHER_CONFIG)) {
            return EN_UNHANDLED;
        }
    }
    return EN_HANDLED_UNCHANGED;
}

void *
en_port_binding_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_port_binding *data = xzalloc(sizeof *data);
    sset_init(&data->synced_ts);
    sset_init(&data->synced_tr);
    return data;
}

void
en_port_binding_clear_tracked_data(void *data_)
{
    struct ed_type_port_binding *data = data_;
    sset_clear(&data->synced_ts);
    sset_clear(&data->synced_tr);
}

void
en_port_binding_cleanup(void *data_)
{
    struct ed_type_port_binding *data = data_;
    sset_destroy(&data->synced_ts);
    sset_destroy(&data->synced_tr);
}
