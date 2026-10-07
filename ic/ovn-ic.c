/*
 * Copyright (c) 2020 eBay Inc.
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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "bitmap.h"
#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "lib/ovn-ic-nb-idl.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "memory.h"
#include "openvswitch/poll-loop.h"
#include "ovsdb-idl.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "stream.h"
#include "stream-ssl.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"
#include "vec.h"
#include "inc-proc-ic.h"
#include "ovn-ic.h"

VLOG_DEFINE_THIS_MODULE(ovn_ic);

static unixctl_cb_func ovn_ic_exit;
static unixctl_cb_func ovn_ic_pause;
static unixctl_cb_func ovn_ic_resume;
static unixctl_cb_func ovn_ic_is_paused;
static unixctl_cb_func ovn_ic_status;

static const char *ovnnb_db;
static const char *ovnsb_db;
static const char *ovn_ic_nb_db;
static const char *ovn_ic_sb_db;
static const char *unixctl_path;

/* SSL/TLS options. */
static const char *ssl_private_key_file;
static const char *ssl_certificate_file;
static const char *ssl_ca_cert_file;


static void
usage(void)
{
    printf("\
%s: OVN interconnection management daemon\n\
usage: %s [OPTIONS]\n\
\n\
Options:\n\
  --ovnnb-db=DATABASE       connect to ovn-nb database at DATABASE\n\
                            (default: %s)\n\
  --ovnsb-db=DATABASE       connect to ovn-sb database at DATABASE\n\
                            (default: %s)\n\
  --ic-nb-db=DATABASE       connect to ovn-ic-nb database at DATABASE\n\
                            (default: %s)\n\
  --ic-sb-db=DATABASE       connect to ovn-ic-sb database at DATABASE\n\
                            (default: %s)\n\
  --unixctl=SOCKET          override default control socket name\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_nb_db(), default_sb_db(),
    default_ic_nb_db(), default_ic_sb_db());
    daemon_usage();
    vlog_usage();
    stream_usage("database", true, true, false);
}

uint32_t
allocate_dp_key(struct hmap *dp_tnlids, bool vxlan_mode, const char *name)
{
    uint32_t hint = vxlan_mode ? OVN_MIN_DP_VXLAN_KEY_GLOBAL
                               : OVN_MIN_DP_KEY_GLOBAL;
    return ovn_allocate_tnlid(dp_tnlids, name, hint,
            vxlan_mode ? OVN_MAX_DP_VXLAN_KEY_GLOBAL : OVN_MAX_DP_KEY_GLOBAL,
            &hint);
}

enum ic_datapath_type
ic_dp_get_type(const struct icsbrec_datapath_binding *isb_dp)
{
    if (isb_dp->type && !strcmp(isb_dp->type, "transit-router")) {
        return IC_ROUTER;
    }

    return IC_SWITCH;
}

enum ic_port_binding_type
ic_pb_get_type(const struct icsbrec_port_binding *isb_pb)
{
    if (isb_pb->type && !strcmp(isb_pb->type, "transit-router-port")) {
        return IC_ROUTER_PORT;
    }

    return IC_SWITCH_PORT;
}

/*
 * Check if the AZ is the leader by checking the lock.
 */
bool
is_az_leader(struct ovsdb_idl_txn *txn)
{
    struct ovsdb_idl *idl = ovsdb_idl_txn_get_idl(txn);
    return idl && ovsdb_idl_has_lock(idl);
}

/* Returns true if transit-switch datapaths must use the VXLAN tunnel-key
 * range: IC-NB requests vxlan_mode and the IC-SB actually has a VXLAN encap.
 *
 * Warning: ovnisb_unlocked should not be used to insert data on IC_SB which
 * can cause a constraint violation, as an example, inserting data to IC-SB
 * datapath_binding. */
bool
ic_ts_compute_vxlan_mode(struct ic_context *ctx)
{
    const struct icnbrec_ic_nb_global *ic_nb =
        icnbrec_ic_nb_global_first(ctx->ovninb_idl);

    if (ic_nb && smap_get_bool(&ic_nb->options, "vxlan_mode", false)) {
        const struct icsbrec_encap *encap;
        ICSBREC_ENCAP_FOR_EACH (encap, ctx->ovnisb_unlocked_idl) {
            if (!strcmp(encap->type, "vxlan")) {
                return true;
            }
        }
    }
    return false;
}

/* Keep other_config:ic-vxlan_mode on the transit switch's NB Logical_Switch
 * mirror in sync with the IC VXLAN mode.  northd reads the boolean value with
 * smap_get_bool() (northd/en-global-config.c), so writing "false" is correct
 * and does not affect the datapath tunnel-id range.  Only write when the value
 * actually differs to avoid needless transaction churn. */
static void
ts_set_ic_vxlan_mode(const struct nbrec_logical_switch *ls, bool vxlan_mode)
{
    const char *want = vxlan_mode ? "true" : "false";
    const char *cur = smap_get(&ls->other_config, "ic-vxlan_mode");
    if (!cur || strcmp(cur, want)) {
        nbrec_logical_switch_update_other_config_setkey(ls, "ic-vxlan_mode",
                                                        want);
    }
}

/* Reconciles a single transit switch 'ts's AZ NB Logical_Switch mirror:
 * creates it if missing, keeps other_config:ic-vxlan_mode in sync, and copies
 * the committed IC-SB Datapath_Binding tunnel key into
 * other_config:requested-tnl-key.  IC-SB Datapath_Binding creation/keying is
 * owned by en_tunnel_key.
 *
 * 'nb_gc' (keyed by transit-switch name) doubles as a garbage-collection set:
 * this function removes the mirror it claims, so whatever remains after every
 * in-scope switch has been reconciled is stale and deleted by the caller.
 * 'isb_gc' (the IC-SB Datapath_Binding map keyed by transit-switch name) is
 * read-only here. */
static void
ts_sync_one(struct ic_context *ctx, const struct icnbrec_transit_switch *ts,
            struct shash *isb_gc, struct shash *nb_gc, bool vxlan_mode)
{
    if (!nb_gc) {
        return;
    }

    const struct nbrec_logical_switch *ls =
        shash_find_and_delete(nb_gc, ts->name);
    if (!ls) {
        ls = nbrec_logical_switch_insert(ctx->ovnnb_txn);
        nbrec_logical_switch_set_name(ls, ts->name);

        /* Write other_config as a whole column rather than with per-key
         * partial map updates.  A partial update is only queued as a map
         * operation and is not reflected in 'ls->other_config' until the
         * transaction commits, so en_tunnel_key would not recognize this
         * brand-new row as a transit switch mirror and could not publish the
         * freshly allocated tunnel key to it in this same iteration.  northd
         * would then pick its own datapath tunnel key and flap it once
         * requested-tnl-key finally showed up. */
        struct smap other_config = SMAP_INITIALIZER(&other_config);
        smap_add(&other_config, "interconn-ts", ts->name);
        smap_add(&other_config, "ic-vxlan_mode",
                 vxlan_mode ? "true" : "false");
        nbrec_logical_switch_set_other_config(ls, &other_config);
        smap_destroy(&other_config);
    } else {
        ts_set_ic_vxlan_mode(ls, vxlan_mode);
    }

    const struct icsbrec_datapath_binding *isb_dp =
        shash_find_data(isb_gc, ts->name);
    if (isb_dp) {
        int64_t nb_tnl_key = smap_get_int(&ls->other_config,
                                          "requested-tnl-key", 0);
        if (nb_tnl_key != isb_dp->tunnel_key) {
            VLOG_DBG("Set other_config:requested-tnl-key %"PRId64
                     " for transit switch %s in NB.",
                     isb_dp->tunnel_key, ts->name);
            char *tnl_key_str = xasprintf("%"PRId64, isb_dp->tunnel_key);
            nbrec_logical_switch_update_other_config_setkey(
                ls, "requested-tnl-key", tnl_key_str);
            free(tnl_key_str);
        }
    }
}

/* Synchronizes transit switches to their AZ NB Logical_Switch mirrors.  When
 * 'ts_scope' is NULL every transit switch is reconciled (full recompute);
 * otherwise only the switches named in 'ts_scope' are.  A name still in scope
 * but no longer present in IC-NB (a deleted switch) is honoured: its mirror
 * ends up as a garbage-collection leftover and is deleted, matching
 * full-recompute behaviour.
 *
 * 'isb_ts_dps' (the IC-SB Datapath_Binding map keyed by transit-switch name)
 * is read only, to copy each committed tunnel key into the mirror's
 * requested-tnl-key.  IC-SB Datapath_Binding creation/keying/GC is owned by
 * en_tunnel_key, so this function neither allocates keys nor mutates
 * 'isb_ts_dps'. */
void
ts_sync_scope(struct ic_context *ctx, struct shash *isb_ts_dps,
              const struct sset *ts_scope)
{
    bool full = !ts_scope;
    bool vxlan_mode = ic_ts_compute_vxlan_mode(ctx);

    /* Build the NB Logical_Switch mirror GC set, keyed by transit-switch
     * name.  Only needed when an NB transaction is available. */
    struct shash nb_ts_mirrors = SHASH_INITIALIZER(&nb_ts_mirrors);
    struct shash *nb_gc = NULL;
    if (ctx->ovnnb_txn) {
        nb_gc = &nb_ts_mirrors;
        if (full) {
            const struct nbrec_logical_switch *ls;
            NBREC_LOGICAL_SWITCH_FOR_EACH (ls, ctx->ovnnb_idl) {
                const char *ts_name = smap_get(&ls->other_config,
                                               "interconn-ts");
                if (ts_name) {
                    shash_add(nb_gc, ts_name, ls);
                }
            }
        } else {
            const char *name;
            SSET_FOR_EACH (name, ts_scope) {
                const struct nbrec_logical_switch *ls =
                    find_ts_in_nb(ctx, CONST_CAST(char *, name));
                if (ls && !shash_find(nb_gc, name)) {
                    shash_add(nb_gc, name, ls);
                }
            }
        }
    }

    const struct icnbrec_transit_switch *ts;
    ICNBREC_TRANSIT_SWITCH_FOR_EACH (ts, ctx->ovninb_idl) {
        if (full || sset_contains(ts_scope, ts->name)) {
            ts_sync_one(ctx, ts, isb_ts_dps, nb_gc, vxlan_mode);
        }
    }

    /* Delete extra NB Logical_Switch with other_config:interconn-ts. */
    if (nb_gc) {
        struct shash_node *node;
        SHASH_FOR_EACH (node, nb_gc) {
            nbrec_logical_switch_delete(node->data);
        }
    }

    shash_destroy(&nb_ts_mirrors);
}

static void
nb_addr_set_apply_diff(const void *arg, const char *item, bool add)
{
    const struct nbrec_address_set *as = arg;
    if (add) {
        nbrec_address_set_update_addresses_addvalue(as, item);
    } else {
        nbrec_address_set_update_addresses_delvalue(as, item);
    }
}

static void
update_nb_addr_set(struct sset *addrs,
                   const struct nbrec_address_set *nb_as)
{
    struct sorted_array nb_addrs =
        sorted_array_from_dbrec(nb_as, addresses);
    struct sorted_array new_addrs = sorted_array_from_sset(addrs);
    sorted_array_apply_diff(&new_addrs, &nb_addrs,
                            nb_addr_set_apply_diff, nb_as);
    sorted_array_destroy(&new_addrs);
    sorted_array_destroy(&nb_addrs);
}

static void
icsb_addr_set_apply_diff(const void *arg, const char *item, bool add)
{
    const struct icsbrec_address_set *as = arg;
    if (add) {
        icsbrec_address_set_update_addresses_addvalue(as, item);
    } else {
        icsbrec_address_set_update_addresses_delvalue(as, item);
    }
}

static void
update_icsb_addr_set(struct sorted_array *nb_addrs,
                     const struct icsbrec_address_set *icsb_as)
{
    struct sorted_array icsb_addrs =
        sorted_array_from_dbrec(icsb_as, addresses);
    sorted_array_apply_diff(nb_addrs, &icsb_addrs,
                            icsb_addr_set_apply_diff, icsb_as);
    sorted_array_destroy(&icsb_addrs);
}

static void
sync_addr_set_to_icsb(struct ovsdb_idl_txn *ovnisb_txn,
                      const struct sbrec_address_set *sb_as,
                      const struct icsbrec_address_set *icsb_as,
                      const struct icsbrec_availability_zone *az)
{
    struct sorted_array addrs =
        sorted_array_from_dbrec(sb_as, addresses);
    if (!icsb_as) {
        icsb_as = icsbrec_address_set_insert(ovnisb_txn);
        icsbrec_address_set_set_name(icsb_as, sb_as->name);
        icsbrec_address_set_set_availability_zone(icsb_as, az);
        icsbrec_address_set_set_addresses(icsb_as, addrs.arr, addrs.n);
    } else {
        update_icsb_addr_set(&addrs, icsb_as);
    }
    sorted_array_destroy(&addrs);
}

static void
sync_addr_set_from_icsb(struct ovsdb_idl_txn *ovnnb_txn,
                        const char *name, struct sset *addrs)
{
    struct sorted_array sorted_addrs = sorted_array_from_sset(addrs);
    struct nbrec_address_set *nb_as = nbrec_address_set_insert(ovnnb_txn);
    nbrec_address_set_set_name(nb_as, name);
    nbrec_address_set_update_external_ids_setkey(nb_as, "ic-learnt", "true");
    nbrec_address_set_set_addresses(nb_as, sorted_addrs.arr, sorted_addrs.n);
    sorted_array_destroy(&sorted_addrs);
}

void
address_set_run(struct ic_context *ctx,
                const struct icsbrec_availability_zone *runned_az)
{
    if (!ctx->ovnisb_unlocked_txn || !ctx->ovnnb_txn || !ctx->ovnsb_txn) {
        return;
    }

    struct shash ic_local_as = SHASH_INITIALIZER(&ic_local_as);
    struct shash ic_remote_as = SHASH_INITIALIZER(&ic_remote_as);
    const struct icsbrec_address_set *ic_as;
    ICSBREC_ADDRESS_SET_FOR_EACH (ic_as, ctx->ovnisb_unlocked_idl) {
        if (ic_as->availability_zone == runned_az) {
            shash_add(&ic_local_as, ic_as->name, ic_as);
        } else {
            /* Merge addresses from all remote AZs that share the same
             * address-set name into a single sset so that duplicate names
             * across AZs are aggregated rather than colliding in the shash.
             */
            struct sset *addrs = shash_find_data(&ic_remote_as, ic_as->name);
            if (!addrs) {
                addrs = xmalloc(sizeof *addrs);
                sset_init(addrs);
                shash_add(&ic_remote_as, ic_as->name, addrs);
            }
            sset_add_array(addrs, ic_as->addresses, ic_as->n_addresses);
        }
    }

    const struct nbrec_nb_global *nb_global =
        nbrec_nb_global_first(ctx->ovnnb_idl);
    ovs_assert(nb_global);
    bool global_learn = smap_get_bool(&nb_global->options, "ic-as-learn",
                                      false);
    bool global_adv = smap_get_bool(&nb_global->options, "ic-as-adv", false);

    /* Advertise address set - from SB to IC-SB:
     * - Each SB address set that needs to be advertised (ic-adv option set),
     *   check if it is already present in IC-SB. If not, create new entry in
     *   IC-SB. Otherwise sync addresses from local address set to IC-SB entry.
     * - Delete extra address sets in IC-SB that were earlier learnt from this
     *   AZ, but is no longer present, or not enabled for advertisement.
     */
    if (global_adv) {
        const struct sbrec_address_set *sb_as;
        SBREC_ADDRESS_SET_FOR_EACH (sb_as, ctx->ovnsb_idl) {
            if (smap_get_bool(&sb_as->options, "ic-adv", false)) {
                const struct icsbrec_address_set *icsb_as;
                icsb_as = shash_find_and_delete(&ic_local_as, sb_as->name);
                sync_addr_set_to_icsb(ctx->ovnisb_unlocked_txn, sb_as, icsb_as,
                                      runned_az);
            }
        }
    }
    struct shash_node *node;
    SHASH_FOR_EACH (node, &ic_local_as) {
        icsbrec_address_set_delete(node->data);
    }
    shash_destroy(&ic_local_as);

    /* Learn address set - from IC-SB to NB:
     * - For each NB Address set entries that were earlier learnt from IC-SB
     *   (external-id "ic-learnt" set to true), check if it is still present
     *   in IC-SB. If not, delete local entry in NB. If yes, sync addresses
     *   from IC-SB to NB.
     * - Any remote address sets in IC-SB (AZ not same as local AZ) that is not
     *   present in local AZ, create local entry in NB with external-id
     *   "ic-learnt" set to true.
     */
    const struct nbrec_address_set *nb_as;
    NBREC_ADDRESS_SET_FOR_EACH_SAFE (nb_as, ctx->ovnnb_idl) {
        struct sset *addrs = shash_find_and_delete(&ic_remote_as, nb_as->name);
        if (smap_get_bool(&nb_as->external_ids, "ic-learnt", false)) {
            if (!addrs || !global_learn) {
                nbrec_address_set_delete(nb_as);
            } else {
                update_nb_addr_set(addrs, nb_as);
            }
        }
        if (addrs) {
            sset_destroy(addrs);
            free(addrs);
        }
    }

    if (global_learn) {
        SHASH_FOR_EACH (node, &ic_remote_as) {
            /* In case local address-set with same name exists, we
             * will not overwrite it because such address sets are already
             * removed from ic_remote_as in the loop above.
             */
            sync_addr_set_from_icsb(ctx->ovnnb_txn, node->name, node->data);
        }
    }
    SHASH_FOR_EACH (node, &ic_remote_as) {
        sset_destroy(node->data);
        free(node->data);
    }
    shash_destroy(&ic_remote_as);
}

const struct nbrec_logical_switch *
find_ts_in_nb(struct ic_context *ctx, char *ts_name)
{
    const struct nbrec_logical_switch *key =
        nbrec_logical_switch_index_init_row(ctx->nbrec_ls_by_name);
    nbrec_logical_switch_index_set_name(key, ts_name);

    const struct nbrec_logical_switch *ls;
    bool found = false;
    NBREC_LOGICAL_SWITCH_FOR_EACH_EQUAL (ls, key, ctx->nbrec_ls_by_name) {
        const char *ls_ts_name = smap_get(&ls->other_config, "interconn-ts");
        if (ls_ts_name && !strcmp(ts_name, ls_ts_name)) {
            found = true;
            break;
        }
    }
    nbrec_logical_switch_index_destroy_row(key);

    if (found) {
        return ls;
    }
    return NULL;
}

const struct sbrec_port_binding *
find_sb_pb_by_name(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                   const char *name)
{
    const struct sbrec_port_binding *key =
        sbrec_port_binding_index_init_row(sbrec_port_binding_by_name);
    sbrec_port_binding_index_set_logical_port(key, name);

    const struct sbrec_port_binding *pb =
        sbrec_port_binding_index_find(sbrec_port_binding_by_name, key);
    sbrec_port_binding_index_destroy_row(key);

    return pb;
}

const struct nbrec_logical_switch_port *
get_lsp_by_ts_port_name(struct ic_context *ctx, const char *ts_port_name)
{
    const struct nbrec_logical_switch_port *lsp, *key;

    key = nbrec_logical_switch_port_index_init_row(ctx->nbrec_port_by_name);
    nbrec_logical_switch_port_index_set_name(key, ts_port_name);
    lsp = nbrec_logical_switch_port_index_find(ctx->nbrec_port_by_name, key);
    nbrec_logical_switch_port_index_destroy_row(key);

    return lsp;
}

const struct sbrec_chassis *
find_sb_chassis(struct ic_context *ctx, const char *name)
{
    const struct sbrec_chassis *key =
        sbrec_chassis_index_init_row(ctx->sbrec_chassis_by_name);
    sbrec_chassis_index_set_name(key, name);

    const struct sbrec_chassis *chassis =
        sbrec_chassis_index_find(ctx->sbrec_chassis_by_name, key);
    sbrec_chassis_index_destroy_row(key);

    return chassis;
}

const struct nbrec_logical_router_port *
get_lrp_by_lrp_name(struct ic_context *ctx, const char *lrp_name)
{
    const struct nbrec_logical_router_port *lrp;
    const struct nbrec_logical_router_port *lrp_key =
        nbrec_logical_router_port_index_init_row(ctx->nbrec_lrp_by_name);
    nbrec_logical_router_port_index_set_name(lrp_key, lrp_name);
    lrp =
        nbrec_logical_router_port_index_find(ctx->nbrec_lrp_by_name, lrp_key);
    nbrec_logical_router_port_index_destroy_row(lrp_key);

    return lrp;
}

/* Build once per handler invocation, a map from every NB
 * transit-switch-mirror port name to its transit switch name, by walking the
 * logical switches directly.  This replaces the previous reverse lookup that
 * scanned every transit switch (with a per-switch index lookup) for each
 * changed port -- an O(changed-ports x transit-switches) cost that dominated
 * the profile (json_string / skiplist / compare_3way) and blocked the main
 * loop for minutes at large fan-out.  The values point into IDL-owned smaps
 * and are valid for the lifetime of the map; destroy with shash_destroy(). */
void
port_binding_lsp_ts_map_init(struct ic_context *ctx, struct shash *map)
{
    shash_init(map);
    const struct nbrec_logical_switch *ls;
    NBREC_LOGICAL_SWITCH_FOR_EACH (ls, ctx->ovnnb_idl) {
        const char *ts_name = smap_get(&ls->other_config, "interconn-ts");
        if (!ts_name) {
            continue;
        }
        for (size_t i = 0; i < ls->n_ports; i++) {
            shash_replace(map, ls->ports[i]->name, CONST_CAST(char *,
                                                              ts_name));
        }
    }
}

/* If 'lsp' is an interconnection port of a transit-switch mirror, adds that
 * transit switch's name (looked up in 'lsp_ts_map') to 'ts_scope'. */
void
port_binding_collect_lsp_ts(const struct shash *lsp_ts_map,
                            const struct nbrec_logical_switch_port *lsp,
                            struct sset *ts_scope)
{
    const char *ts_name = shash_find_data(lsp_ts_map, lsp->name);
    if (ts_name) {
        sset_add(ts_scope, ts_name);
    }
}

/*
 * This function implements a sequence number protocol that can be used by
 * the INB end user to verify that ISB is synced with all the changes that
 * are done be the user/AZs-controllers:
 *
 * Since we have multiple IC instances running in different regions
 * we can't rely on one of them to update the ISB and sync that update
 * to INB since other ICs can make changes in parallel.
 * So to have a sequence number protocol working properly we must
 * make sure that all the IC instances are synced with the ISB first
 * and then update the INB.
 *
 * To guarantee that all instances are synced with ISB first, each IC
 * will do the following steps:
 *
 * 1. when local ovn-ic sees that INB:nb_ic_cfg has updated we will set
 *    the ic_sb_loop->next_cfg to match the INB:nb_ic_cfg and increment
 *    the value of AZ:nb_ic_cfg and wait until we get confirmation from
 *    the server.
 *
 * 2. once this IC instance changes for ISB are committed successfully
 *    (next loop), the value of cur_cfg will be updated to match
 *    the INB:nb_ic_cfg that indicate that our local instance is up to date
 *    and no more changes need to be done for ISB.
 *
 * 3. validate that the AZ:nb_ic_cfg to match the INB:nb_ic_cfg.
 *
 * 4. Go through all the AZs and check if all have the same value of
 *    AZ:nb_ic_cfg that means all the AZs are done with ISB changes and ISB are
 *    up to date with INB, so we can set the values of ISB:nb_ic_cfg to
 *    INB:nb_ic_cfg and INB:sb_ic_cfg to INB:nb_ic_cfg.
 */
static void
update_sequence_numbers(struct ic_context *ctx,
                        const struct icsbrec_availability_zone *runned_az,
                        struct ovsdb_idl_loop *ic_sb_loop)
{
    if (!ctx->ovnisb_unlocked_txn || !ctx->ovninb_txn) {
        return;
    }

    const struct icnbrec_ic_nb_global *ic_nb = icnbrec_ic_nb_global_first(
                                               ctx->ovninb_idl);
    if (!ic_nb) {
        ic_nb = icnbrec_ic_nb_global_insert(ctx->ovninb_txn);
    }
    const struct icsbrec_ic_sb_global *ic_sb = icsbrec_ic_sb_global_first(
                                               ctx->ovnisb_unlocked_idl);
    if (!ic_sb) {
        ic_sb = icsbrec_ic_sb_global_insert(ctx->ovnisb_unlocked_txn);
    }

    if ((ic_nb->nb_ic_cfg != ic_sb->nb_ic_cfg) &&
                          (ic_nb->nb_ic_cfg != runned_az->nb_ic_cfg)) {
        /* Deal with potential overflows. */
        if (runned_az->nb_ic_cfg == INT64_MAX) {
            icsbrec_availability_zone_set_nb_ic_cfg(runned_az, 0);
        }
        ic_sb_loop->next_cfg = ic_nb->nb_ic_cfg;
        ovsdb_idl_txn_increment(ctx->ovnisb_unlocked_txn,
                                &runned_az->header_,
            &icsbrec_availability_zone_col_nb_ic_cfg, true);
        return;
    }

    /* handle cases where accidentally AZ:ic_nb_cfg exceeds
     * the INB:ic_nb_cfg.
     */
    if (runned_az->nb_ic_cfg != ic_sb_loop->cur_cfg) {
        icsbrec_availability_zone_set_nb_ic_cfg(runned_az,
                                                ic_sb_loop->cur_cfg);
        return;
    }

    const struct icsbrec_availability_zone *other_az;
    ICSBREC_AVAILABILITY_ZONE_FOR_EACH (other_az, ctx->ovnisb_unlocked_idl) {
        if (other_az->nb_ic_cfg != runned_az->nb_ic_cfg) {
            return;
        }
    }
    /* All the AZs are updated successfully, update SB/NB counter. */
    if (ic_nb->nb_ic_cfg != ic_sb->nb_ic_cfg) {
        icsbrec_ic_sb_global_set_nb_ic_cfg(ic_sb, runned_az->nb_ic_cfg);
        icnbrec_ic_nb_global_set_sb_ic_cfg(ic_nb, runned_az->nb_ic_cfg);
    }
}

static void
inc_proc_graph_dump(const char *end_node)
{
    struct ovsdb_idl_loop ovnnb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&nbrec_idl_class, true));
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&sbrec_idl_class, true));
    struct ovsdb_idl_loop ovninb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&icnbrec_idl_class, true));
    struct ovsdb_idl_loop ovnisb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&icsbrec_idl_class, true));

    inc_proc_ic_init(&ovnnb_idl_loop, &ovnsb_idl_loop,
                     &ovninb_idl_loop, &ovnisb_idl_loop);
    engine_dump_graph(end_node);

    ovsdb_idl_loop_destroy(&ovnnb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);
    ovsdb_idl_loop_destroy(&ovninb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnisb_idl_loop);
}

static void
parse_options(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum {
        OVN_DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
        OPT_DUMP_INC_PROC_GRAPH,
    };
    static const struct option long_options[] = {
        {"ovnsb-db", required_argument, NULL, 'd'},
        {"ovnnb-db", required_argument, NULL, 'D'},
        {"ic-sb-db", required_argument, NULL, 'i'},
        {"ic-nb-db", required_argument, NULL, 'I'},
        {"unixctl", required_argument, NULL, 'u'},
        {"help", no_argument, NULL, 'h'},
        {"options", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        {"dump-inc-proc-graph", optional_argument, NULL,
         OPT_DUMP_INC_PROC_GRAPH},
        OVN_DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        OVN_DAEMON_OPTION_HANDLERS;
        VLOG_OPTION_HANDLERS;

        case 'p':
            ssl_private_key_file = optarg;
            break;

        case 'c':
            ssl_certificate_file = optarg;
            break;

        case 'C':
            ssl_ca_cert_file = optarg;
            break;

        case OPT_SSL_PROTOCOLS:
            stream_ssl_set_protocols(optarg);
            break;

        case OPT_SSL_CIPHERS:
            stream_ssl_set_ciphers(optarg);
            break;

        case OPT_SSL_CIPHERSUITES:
            stream_ssl_set_ciphersuites(optarg);
            break;

        case OPT_SSL_SERVER_NAME:
            stream_ssl_set_server_name(optarg);
            break;

        case 'd':
            ovnsb_db = optarg;
            break;

        case 'D':
            ovnnb_db = optarg;
            break;

        case 'i':
            ovn_ic_sb_db = optarg;
            break;

        case 'I':
            ovn_ic_nb_db = optarg;
            break;

        case 'u':
            unixctl_path = optarg;
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'V':
            ovn_print_version(0, 0);
            exit(EXIT_SUCCESS);

        /* --dump-inc-proc-graph[=<i-p-node>]: Whether to dump the I-P engine
         * graph representation in DOT format to stdout.  Optionally only up
         * to <i-p-node>.
         */
        case OPT_DUMP_INC_PROC_GRAPH:
            inc_proc_graph_dump(optarg);
            exit(EXIT_SUCCESS);

        default:
            break;
        }
    }

    if (!ovnsb_db) {
        ovnsb_db = default_sb_db();
    }

    if (!ovnnb_db) {
        ovnnb_db = default_nb_db();
    }

    if (!ovn_ic_sb_db) {
        ovn_ic_sb_db = default_ic_sb_db();
    }

    if (!ovn_ic_nb_db) {
        ovn_ic_nb_db = default_ic_nb_db();
    }

    free(short_options);
}

static void OVS_UNUSED
add_column_noalert(struct ovsdb_idl *idl,
                   const struct ovsdb_idl_column *column)
{
    ovsdb_idl_add_column(idl, column);
    ovsdb_idl_omit_alert(idl, column);
}

static void
update_ssl_config(void)
{
    if (ssl_private_key_file && ssl_certificate_file) {
        stream_ssl_set_key_and_cert(ssl_private_key_file,
                                    ssl_certificate_file);
    }
    if (ssl_ca_cert_file) {
        stream_ssl_set_ca_cert_file(ssl_ca_cert_file, false);
    }
}

static void
update_idl_probe_interval(struct ovsdb_idl *ovn_sb_idl,
                          struct ovsdb_idl *ovn_nb_idl,
                          struct ovsdb_idl *ovn_icsb_idl,
                          struct ovsdb_idl *ovn_icsb_unlocked_idl,
                          struct ovsdb_idl *ovn_icnb_idl)
{
    const struct nbrec_nb_global *nb = nbrec_nb_global_first(ovn_nb_idl);
    int interval = -1;
    if (nb) {
        interval = smap_get_int(&nb->options, "ic_probe_interval", interval);
    }
    set_idl_probe_interval(ovn_sb_idl, ovnsb_db, interval);
    set_idl_probe_interval(ovn_nb_idl, ovnnb_db, interval);

    const struct icnbrec_ic_nb_global *icnb =
        icnbrec_ic_nb_global_first(ovn_icnb_idl);
    int ic_interval = -1;
    if (icnb) {
        ic_interval = smap_get_int(&icnb->options, "ic_probe_interval",
                                   ic_interval);
    }
    set_idl_probe_interval(ovn_icsb_idl, ovn_ic_sb_db, ic_interval);
    set_idl_probe_interval(ovn_icsb_unlocked_idl, ovn_ic_sb_db, ic_interval);
    set_idl_probe_interval(ovn_icnb_idl, ovn_ic_nb_db, ic_interval);
}

int
main(int argc, char *argv[])
{
    int res = EXIT_SUCCESS;
    struct unixctl_server *unixctl;
    int retval;
    bool exiting;
    struct ic_state state;

    fatal_ignore_sigpipe();
    ovs_cmdl_proctitle_init(argc, argv);
    ovn_set_program_name(argv[0]);
    parse_options(argc, argv);

    daemonize_start(false, false);

    char *abs_unixctl_path = get_abs_unix_ctl_path(unixctl_path);
    retval = unixctl_server_create(abs_unixctl_path, &unixctl);
    free(abs_unixctl_path);

    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_ic_exit, &exiting);
    unixctl_command_register("pause", "", 0, 0, ovn_ic_pause, &state);
    unixctl_command_register("resume", "", 0, 0, ovn_ic_resume, &state);
    unixctl_command_register("is-paused", "", 0, 0, ovn_ic_is_paused, &state);
    unixctl_command_register("status", "", 0, 0, ovn_ic_status, &state);

    daemonize_complete();

    /* ovn-ic-nb db. */
    struct ovsdb_idl_loop ovninb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovn_ic_nb_db, &icnbrec_idl_class, true, true));
    ovsdb_idl_track_add_all(ovninb_idl_loop.idl);

    /*
     * Each ovn-ic instance maintains two connections to the IC-SB database:
     * 1. Locked Connection: Competes for a global lock on IC-SB. Used for
     * writes that must be performed by only one active instance
     * (e.g., inserting a datapath_binding for a transit switch/router).
     *
     * 2. Unlocked Connection: Does not hold a lock. Used for writes that
     * can be safely performed by multiple instances simultaneously
     * (e.g., inserting a port_binding).
     *
     * This segregation prevents constraint violations and a full recompute
     * when writing to IC-SB.
     */
    /* ovn-ic-sb db without lock. */
    struct ovsdb_idl_loop ovnisb_unlocked_idl_loop =
        OVSDB_IDL_LOOP_INITIALIZER(ovsdb_idl_create(ovn_ic_sb_db,
                                                    &icsbrec_idl_class,
                                                    true, true));
    ovsdb_idl_track_add_all(ovnisb_unlocked_idl_loop.idl);

    /* ovn-ic-sb db with lock. */
    struct ovsdb_idl_loop ovnisb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovn_ic_sb_db, &icsbrec_idl_class, true, true));
    ovsdb_idl_track_add_all(ovnisb_idl_loop.idl);

    /* ovn-nb db. */
    struct ovsdb_idl_loop ovnnb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnnb_db, &nbrec_idl_class, false, true));

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_nb_global);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_nb_global_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_nb_global_col_options);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl,
                        &nbrec_table_logical_router_static_route);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_route_table);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_ip_prefix);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_nexthop);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_external_ids);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_options);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                    &nbrec_logical_router_static_route_col_policy);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_logical_router);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_static_routes);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_ports);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_options);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_external_ids);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_enabled);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_load_balancer);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_col_load_balancer_group);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_logical_router_port);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_mac);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_networks);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_external_ids);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_router_port_col_options);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_logical_switch);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_col_ports);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_col_other_config);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_col_external_ids);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_logical_switch_port);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_addresses);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_options);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_type);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_up);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_addresses);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_enabled);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_external_ids);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_logical_switch_port_col_peer);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_load_balancer);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_load_balancer_col_vips);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_load_balancer_group);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_load_balancer_group_col_load_balancer);

    ovsdb_idl_add_table(ovnnb_idl_loop.idl, &nbrec_table_address_set);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_address_set_col_name);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_address_set_col_addresses);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_address_set_col_options);
    ovsdb_idl_track_add_column(ovnnb_idl_loop.idl,
                               &nbrec_address_set_col_external_ids);

    /* ovn-sb db. */
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnsb_db, &sbrec_idl_class, false, true));

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_sb_global);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_sb_global_col_options);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_chassis);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_chassis_col_encaps);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_chassis_col_name);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_chassis_col_hostname);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_chassis_col_other_config);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_encap);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_encap_col_chassis_name);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_encap_col_type);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_encap_col_ip);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_encap_col_options);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_datapath_binding);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_datapath_binding_col_type);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_datapath_binding_col_external_ids);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_datapath_binding_col_nb_uuid);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_port_binding);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_datapath);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_mac);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_options);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_logical_port);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_external_ids);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_chassis);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_port_binding_col_up);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_service_monitor);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_chassis_name);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_external_ids);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_type);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_ip);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_logical_port);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_port);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_protocol);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_src_ip);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_src_mac);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_remote);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_ic_learned);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_status);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_service_monitor_col_options);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_learned_route);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_learned_route_col_ip_prefix);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_learned_route_col_datapath);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_address_set);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_address_set_col_name);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_address_set_col_addresses);
    ovsdb_idl_track_add_column(ovnsb_idl_loop.idl,
                               &sbrec_address_set_col_options);

    /* Create IDL indexes */
    struct ovsdb_idl_index *nbrec_ls_by_name
        = ovsdb_idl_index_create1(ovnnb_idl_loop.idl,
                                  &nbrec_logical_switch_col_name);
    struct ovsdb_idl_index *nbrec_lr_by_name = ovsdb_idl_index_create1(
        ovnnb_idl_loop.idl, &nbrec_logical_router_col_name);
    struct ovsdb_idl_index *nbrec_port_by_name
        = ovsdb_idl_index_create1(ovnnb_idl_loop.idl,
                                  &nbrec_logical_switch_port_col_name);
    struct ovsdb_idl_index *nbrec_lrp_by_name
        = ovsdb_idl_index_create1(ovnnb_idl_loop.idl,
                                  &nbrec_logical_router_port_col_name);
    struct ovsdb_idl_index *sbrec_port_binding_by_name
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_port_binding_col_logical_port);
    struct ovsdb_idl_index *sbrec_datapath_binding_by_nb_uuid
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_datapath_binding_col_nb_uuid);
    struct ovsdb_idl_index *sbrec_chassis_by_name
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_chassis_col_name);

    struct ovsdb_idl_index *sbrec_learned_route_by_datapath
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_learned_route_col_datapath);

    struct ovsdb_idl_index *sbrec_service_monitor_by_remote_type
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_service_monitor_col_remote);

    struct ovsdb_idl_index *sbrec_service_monitor_by_ic_learned
        = ovsdb_idl_index_create1(ovnsb_idl_loop.idl,
                                  &sbrec_service_monitor_col_ic_learned);

    struct ovsdb_idl_index *sbrec_service_monitor_by_remote_type_logical_port
        = ovsdb_idl_index_create2(ovnsb_idl_loop.idl,
                                  &sbrec_service_monitor_col_remote,
                                  &sbrec_service_monitor_col_logical_port);

    struct ovsdb_idl_index *icnbrec_transit_switch_by_name
        = ovsdb_idl_index_create1(ovninb_idl_loop.idl,
                                  &icnbrec_transit_switch_col_name);

    struct ovsdb_idl_index *icnbrec_transit_router_by_name
        = ovsdb_idl_index_create1(ovninb_idl_loop.idl,
                                  &icnbrec_transit_router_col_name);

    struct ovsdb_idl_index *icsbrec_port_binding_by_az
        = ovsdb_idl_index_create1(ovnisb_unlocked_idl_loop.idl,
                                  &icsbrec_port_binding_col_availability_zone);

    struct ovsdb_idl_index *icsbrec_port_binding_by_ts
        = ovsdb_idl_index_create1(ovnisb_unlocked_idl_loop.idl,
                                  &icsbrec_port_binding_col_transit_switch);

    struct ovsdb_idl_index *icsbrec_port_binding_by_ts_az
        = ovsdb_idl_index_create2(ovnisb_unlocked_idl_loop.idl,
                                  &icsbrec_port_binding_col_transit_switch,
                                  &icsbrec_port_binding_col_availability_zone);

    struct ovsdb_idl_index *icsbrec_route_by_az
        = ovsdb_idl_index_create1(ovnisb_unlocked_idl_loop.idl,
                                  &icsbrec_route_col_availability_zone);

    struct ovsdb_idl_index *icsbrec_route_by_ts
        = ovsdb_idl_index_create1(ovnisb_unlocked_idl_loop.idl,
                                  &icsbrec_route_col_transit_switch);

    struct ovsdb_idl_index *icsbrec_route_by_ts_az
        = ovsdb_idl_index_create2(ovnisb_unlocked_idl_loop.idl,
                                  &icsbrec_route_col_transit_switch,
                                  &icsbrec_route_col_availability_zone);

    struct ovsdb_idl_index *icsbrec_service_monitor_by_source_az
        = ovsdb_idl_index_create1(ovnisb_unlocked_idl_loop.idl,
            &icsbrec_service_monitor_col_source_availability_zone);

    struct ovsdb_idl_index *icsbrec_service_monitor_by_target_az
        = ovsdb_idl_index_create1(ovnisb_unlocked_idl_loop.idl,
            &icsbrec_service_monitor_col_target_availability_zone);

    struct ovsdb_idl_index *icsbrec_service_monitor_by_target_az_logical_port
        = ovsdb_idl_index_create2(ovnisb_unlocked_idl_loop.idl,
            &icsbrec_service_monitor_col_target_availability_zone,
            &icsbrec_service_monitor_col_logical_port);

    unixctl_command_register("nb-connection-status", "", 0, 0,
                             ovn_conn_show, ovnnb_idl_loop.idl);
    unixctl_command_register("sb-connection-status", "", 0, 0,
                             ovn_conn_show, ovnsb_idl_loop.idl);
    unixctl_command_register("ic-nb-connection-status", "", 0, 0,
                             ovn_conn_show, ovninb_idl_loop.idl);
    unixctl_command_register("ic-sb-connection-status", "", 0, 0,
                             ovn_conn_show, ovnisb_idl_loop.idl);

    /* Initialize incremental processing engine for ovn-northd */
    inc_proc_ic_init(&ovnnb_idl_loop, &ovnsb_idl_loop,
                     &ovninb_idl_loop, &ovnisb_unlocked_idl_loop);

    unsigned int ovnnb_cond_seqno = UINT_MAX;
    unsigned int ovnsb_cond_seqno = UINT_MAX;
    unsigned int ovninb_cond_seqno = UINT_MAX;
    unsigned int ovnisb_cond_seqno = UINT_MAX;
    unsigned int ovnisb_unlocked_cond_seqno = UINT_MAX;

    /* Main loop. */
    struct ic_engine_context  eng_ctx = {0};

    exiting = false;
    state.had_lock = false;
    state.had_isb_lock = false;
    state.paused = false;

    while (!exiting) {
        update_ssl_config();
        update_idl_probe_interval(ovnsb_idl_loop.idl, ovnnb_idl_loop.idl,
                                  ovnisb_idl_loop.idl,
                                  ovnisb_unlocked_idl_loop.idl,
                                  ovninb_idl_loop.idl);

        /* Postpone the next engine run by the length of the previous one, up
         * to this interval, to coalesce bursts of change-driven runs.  A
         * forced recompute (set_force_recompute) still runs immediately, so
         * this only throttles the natural, incremental path. */
        const struct icnbrec_ic_nb_global *ic_nb_global =
            icnbrec_ic_nb_global_first(ovninb_idl_loop.idl);
        eng_ctx.backoff_ms = ic_nb_global
            ? smap_get_uint(&ic_nb_global->options,
                            "ic-backoff-interval-ms", 0) : 0;

        memory_run();
        if (memory_should_report()) {
            struct simap usage = SIMAP_INITIALIZER(&usage);

            /* Nothing special to report yet. */
            memory_report(&usage);
            simap_destroy(&usage);
        }

        bool clear_idl_track = true;
        if (!state.paused) {
            if (!ovsdb_idl_has_lock(ovnsb_idl_loop.idl) &&
                !ovsdb_idl_is_lock_contended(ovnsb_idl_loop.idl))
            {
                /* Ensure that only a single ovn-ic is active in the deployment
                 * by acquiring a lock called "ovn_ic" on the southbound
                 * database and then only performing DB transactions if the
                 * lock is held. */
                ovsdb_idl_set_lock(ovnsb_idl_loop.idl, "ovn_ic");
            }

            struct ovsdb_idl_txn *ovnnb_txn =
                run_idl_loop(&ovnnb_idl_loop, "OVN_Northbound",
                             &eng_ctx.nb_idl_duration_ms);
            unsigned int new_ovnnb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovnnb_idl_loop.idl);
            if (new_ovnnb_cond_seqno != ovnnb_cond_seqno) {
                if (!new_ovnnb_cond_seqno) {
                    VLOG_INFO("OVN NB IDL reconnected, force recompute.");
                    inc_proc_ic_force_recompute();
                }
                ovnnb_cond_seqno = new_ovnnb_cond_seqno;
            }

            struct ovsdb_idl_txn *ovnsb_txn =
                run_idl_loop(&ovnsb_idl_loop, "OVN_Southbound",
                             &eng_ctx.sb_idl_duration_ms);
            unsigned int new_ovnsb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovnsb_idl_loop.idl);
            if (new_ovnsb_cond_seqno != ovnsb_cond_seqno) {
                if (!new_ovnsb_cond_seqno) {
                    VLOG_INFO("OVN SB IDL reconnected, force recompute.");
                    inc_proc_ic_force_recompute();
                }
                ovnsb_cond_seqno = new_ovnsb_cond_seqno;
            }

            if (ovsdb_idl_has_lock(ovnsb_idl_loop.idl)) {
                if (!ovsdb_idl_has_lock(ovnisb_idl_loop.idl) &&
                    !ovsdb_idl_is_lock_contended(ovnisb_idl_loop.idl)) {
                    /*
                     * Ensure that only a single ovn-ic has the permission to
                     * write to IC-SB. Only the instance that is active in
                     * its own AZ may request it: a standby instance never
                     * runs the engine, so if it held the IC-SB lock nobody
                     * would ever write to IC-SB.
                     */
                    VLOG_INFO("Acquiring OVN ISB lock.");
                    ovsdb_idl_set_lock(ovnisb_idl_loop.idl, "ovn_ic_sb");
                }
            } else {
                /* Release the IC-SB lock, or withdraw a pending request for
                 * it, as soon as the local SB lock is gone. */
                ovsdb_idl_set_lock(ovnisb_idl_loop.idl, NULL);
            }

            struct ovsdb_idl_txn *ovninb_txn =
                run_idl_loop(&ovninb_idl_loop, "OVN_IC_Northbound",
                             &eng_ctx.inb_idl_duration_ms);
            unsigned int new_ovninb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovninb_idl_loop.idl);
            if (new_ovninb_cond_seqno != ovninb_cond_seqno) {
                if (!new_ovninb_cond_seqno) {
                    VLOG_INFO("OVN INB IDL reconnected, force recompute.");
                    inc_proc_ic_force_recompute();
                }
                ovninb_cond_seqno = new_ovninb_cond_seqno;
            }

            struct ovsdb_idl_txn *ovnisb_txn =
                run_idl_loop(&ovnisb_idl_loop, "OVN_IC_Southbound",
                             &eng_ctx.isb_idl_duration_ms);
            unsigned int new_ovnisb_cond_seqno =
                        ovsdb_idl_get_condition_seqno(ovnisb_idl_loop.idl);
            if (new_ovnisb_cond_seqno != ovnisb_cond_seqno) {
                if (!new_ovnisb_cond_seqno) {
                    VLOG_INFO("OVN ISB IDL reconnected, force recompute.");
                    inc_proc_ic_force_recompute();
                }
                ovnisb_cond_seqno = new_ovnisb_cond_seqno;
            }

            struct ovsdb_idl_txn *ovnisb_unlocked_txn =
                run_idl_loop(&ovnisb_unlocked_idl_loop, "OVN_IC_Southbound",
                             &eng_ctx.isb_unlock_idl_duration_ms);
            unsigned int new_ovnisb_unlocked_cond_seqno =
                ovsdb_idl_get_condition_seqno(ovnisb_unlocked_idl_loop.idl);
            if (new_ovnisb_unlocked_cond_seqno != ovnisb_unlocked_cond_seqno) {
                if (!new_ovnisb_unlocked_cond_seqno) {
                    VLOG_INFO("OVN ISB IDL Unlocked reconnected, "
                              "force recompute.");
                    inc_proc_ic_force_recompute();
                }
                ovnisb_unlocked_cond_seqno = new_ovnisb_unlocked_cond_seqno;
            }

            struct ic_context ctx = {
                .ovnnb_idl = ovnnb_idl_loop.idl,
                .ovnnb_txn = ovnnb_txn,
                .ovnsb_idl = ovnsb_idl_loop.idl,
                .ovnsb_txn = ovnsb_txn,
                .ovninb_idl = ovninb_idl_loop.idl,
                .ovninb_txn = ovninb_txn,
                .ovnisb_idl = ovnisb_idl_loop.idl,
                .ovnisb_txn = ovnisb_txn,
                .ovnisb_unlocked_idl = ovnisb_unlocked_idl_loop.idl,
                .ovnisb_unlocked_txn = ovnisb_unlocked_txn,
                .nbrec_ls_by_name = nbrec_ls_by_name,
                .nbrec_lr_by_name = nbrec_lr_by_name,
                .nbrec_lrp_by_name = nbrec_lrp_by_name,
                .nbrec_port_by_name = nbrec_port_by_name,
                .sbrec_port_binding_by_name = sbrec_port_binding_by_name,
                .sbrec_datapath_binding_by_nb_uuid =
                    sbrec_datapath_binding_by_nb_uuid,
                .sbrec_chassis_by_name = sbrec_chassis_by_name,
                .sbrec_learned_route_by_datapath =
                  sbrec_learned_route_by_datapath,
                .sbrec_service_monitor_by_remote_type =
                    sbrec_service_monitor_by_remote_type,
                .sbrec_service_monitor_by_ic_learned =
                    sbrec_service_monitor_by_ic_learned,
                .sbrec_service_monitor_by_remote_type_logical_port =
                    sbrec_service_monitor_by_remote_type_logical_port,
                .icnbrec_transit_switch_by_name =
                    icnbrec_transit_switch_by_name,
                .icnbrec_transit_router_by_name =
                    icnbrec_transit_router_by_name,
                .icsbrec_port_binding_by_az = icsbrec_port_binding_by_az,
                .icsbrec_port_binding_by_ts = icsbrec_port_binding_by_ts,
                .icsbrec_port_binding_by_ts_az = icsbrec_port_binding_by_ts_az,
                .icsbrec_route_by_az = icsbrec_route_by_az,
                .icsbrec_route_by_ts = icsbrec_route_by_ts,
                .icsbrec_route_by_ts_az = icsbrec_route_by_ts_az,
                .icsbrec_service_monitor_by_source_az =
                    icsbrec_service_monitor_by_source_az,
                .icsbrec_service_monitor_by_target_az =
                    icsbrec_service_monitor_by_target_az,
                .icsbrec_service_monitor_by_target_az_logical_port =
                    icsbrec_service_monitor_by_target_az_logical_port,
            };

            if (!state.had_lock && ovsdb_idl_has_lock(ctx.ovnsb_idl)) {
                VLOG_INFO("ovn-ic lock acquired. "
                            "This ovn-ic instance is now active.");
                state.had_lock = true;
            } else if (state.had_lock &&
                       !ovsdb_idl_has_lock(ctx.ovnsb_idl)) {
                VLOG_INFO("ovn-ic lock lost. "
                            "This ovn-ic instance is now on standby.");
                state.had_lock = false;
            }

            if (!state.had_isb_lock && ovsdb_idl_has_lock(ctx.ovnisb_idl)) {
                VLOG_INFO("OVN ISB lock acquired. "
                          "This ovn-ic instance is now active.");
                state.had_isb_lock = true;
                inc_proc_ic_force_recompute_immediate();
            } else if (state.had_isb_lock &&
                       !ovsdb_idl_has_lock(ctx.ovnisb_idl)) {
                VLOG_INFO("OVN ISB lock lost.");
                state.had_isb_lock = false;
            }

            if (ovsdb_idl_has_lock(ctx.ovnsb_idl) &&
                ovsdb_idl_has_ever_connected(ctx.ovnnb_idl) &&
                ovsdb_idl_has_ever_connected(ctx.ovnsb_idl) &&
                ovsdb_idl_has_ever_connected(ctx.ovninb_idl) &&
                ovsdb_idl_has_ever_connected(ctx.ovnisb_idl) &&
                ovsdb_idl_has_ever_connected(ctx.ovnisb_unlocked_idl)) {
                if (ctx.ovnnb_txn && ctx.ovnsb_txn && ctx.ovninb_txn &&
                    ctx.ovnisb_unlocked_txn && inc_proc_ic_can_run(&eng_ctx)) {
                    /* The availability zone is now resolved by the en_az
                     * engine node.  The subsystem nodes skip their work when
                     * there is no AZ; the sequence-number bookkeeping below
                     * runs outside the engine, so it reads the resolved AZ via
                     * inc_proc_ic_get_runned_az(). */
                    (void) inc_proc_ic_run(&ctx, &eng_ctx);
                    const struct icsbrec_availability_zone *runned_az =
                        inc_proc_ic_get_runned_az();
                    if (runned_az) {
                        update_sequence_numbers(&ctx, runned_az,
                                                &ovnisb_unlocked_idl_loop);
                    }
                } else if (!inc_proc_ic_get_force_recompute()) {
                    clear_idl_track = false;
                }
                /* If there are any errors, we force a full recompute in order
                 * to ensure we handle all changes. */
                if (!ovsdb_idl_loop_commit_and_wait(&ovnnb_idl_loop)) {
                    VLOG_INFO("OVNNB commit failed, "
                                "force recompute next time.");
                    inc_proc_ic_force_recompute_immediate();
                }

                if (!ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop)) {
                    VLOG_INFO("OVNSB commit failed, "
                                "force recompute next time.");
                    inc_proc_ic_force_recompute_immediate();
                }

                if (!ovsdb_idl_loop_commit_and_wait(&ovninb_idl_loop)) {
                    VLOG_INFO("OVNINB commit failed, "
                                "force recompute next time.");
                    inc_proc_ic_force_recompute_immediate();
                }
                if (!ovsdb_idl_loop_commit_and_wait(
                                          &ovnisb_unlocked_idl_loop)) {
                    VLOG_INFO("OVNISB Unlocked commit failed, "
                                "force recompute next time.");
                    inc_proc_ic_force_recompute_immediate();
                }

                /*
                 * ovn-ic will only try to recompute a failed transaction from
                 * the locked connection IF the AZ has the lock.
                 */
                if (!ovsdb_idl_loop_commit_and_wait(&ovnisb_idl_loop) &&
                    ovsdb_idl_has_lock(ovnisb_idl_loop.idl)) {
                    VLOG_INFO("OVNISB commit failed, "
                              "force recompute next time.");
                    inc_proc_ic_force_recompute_immediate();
                }
            } else {
                /* Make sure we send any pending requests, e.g., lock. */
                int rc1 = ovsdb_idl_loop_commit_and_wait(&ovnnb_idl_loop);
                int rc2 = ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);
                int rc3 = ovsdb_idl_loop_commit_and_wait(&ovninb_idl_loop);
                int rc4 = ovsdb_idl_loop_commit_and_wait(&ovnisb_idl_loop);
                int rc5 =
                    ovsdb_idl_loop_commit_and_wait(&ovnisb_unlocked_idl_loop);
                if (!rc1 || !rc2 || !rc3 || !rc4 || !rc5) {
                    VLOG_DBG(" a transaction failed in: %s %s %s %s %s",
                            !rc1 ? "nb" : "", !rc2 ? "sb" : "",
                             !rc3 ? "ic_nb" : "", !rc4 ? "ic_sb" : "",
                             !rc5 ? "ic_sb_unlocked" : "");
                    /* A transaction failed. Wake up immediately to give
                    * opportunity to send the proper transaction
                    */
                }
                /* Force a full recompute next time we become active. */
                inc_proc_ic_force_recompute();
            }
        } else {
            /* ovn-ic is paused
             *    - we still want to handle any db updates and update the
             *      local IDL. Otherwise, when it is resumed, the local IDL
             *      copy will be out of sync.
             *    - but we don't want to create any txns.
             * */
            if (ovsdb_idl_has_lock(ovnisb_idl_loop.idl) ||
                ovsdb_idl_is_lock_contended(ovnisb_idl_loop.idl)) {
                VLOG_INFO("This ovn-ic instance is now paused. "
                          "Removing IC-SB lock.");
                ovsdb_idl_set_lock(ovnisb_idl_loop.idl, NULL);
                state.had_isb_lock = false;
            }

            if (ovsdb_idl_has_lock(ovnsb_idl_loop.idl) ||
                ovsdb_idl_is_lock_contended(ovnsb_idl_loop.idl)) {
                /* make sure we don't hold the lock while paused */
                VLOG_INFO("This ovn-ic instance is now paused.");
                ovsdb_idl_set_lock(ovnsb_idl_loop.idl, NULL);
                state.had_lock = false;
            }

            ovsdb_idl_run(ovnnb_idl_loop.idl);
            ovsdb_idl_run(ovnsb_idl_loop.idl);
            ovsdb_idl_run(ovninb_idl_loop.idl);
            ovsdb_idl_run(ovnisb_idl_loop.idl);
            ovsdb_idl_run(ovnisb_unlocked_idl_loop.idl);
            ovsdb_idl_wait(ovnnb_idl_loop.idl);
            ovsdb_idl_wait(ovnsb_idl_loop.idl);
            ovsdb_idl_wait(ovninb_idl_loop.idl);
            ovsdb_idl_wait(ovnisb_idl_loop.idl);
            ovsdb_idl_wait(ovnisb_unlocked_idl_loop.idl);

            /* Force a full recompute next time we become active. */
            inc_proc_ic_force_recompute();
        }

        if (clear_idl_track) {
            ovsdb_idl_track_clear(ovnnb_idl_loop.idl);
            ovsdb_idl_track_clear(ovnsb_idl_loop.idl);
            ovsdb_idl_track_clear(ovninb_idl_loop.idl);
            ovsdb_idl_track_clear(ovnisb_idl_loop.idl);
            ovsdb_idl_track_clear(ovnisb_unlocked_idl_loop.idl);
        }

        unixctl_server_run(unixctl);
        unixctl_server_wait(unixctl);
        memory_wait();
        if (exiting) {
            poll_immediate_wake();
        }

        poll_block();
    }
    inc_proc_ic_cleanup();

    unixctl_server_destroy(unixctl);
    ovsdb_idl_loop_destroy(&ovnnb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);
    ovsdb_idl_loop_destroy(&ovninb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnisb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnisb_unlocked_idl_loop);

    exit(res);
}

static void
ovn_ic_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
            const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_ic_pause(struct unixctl_conn *conn, int argc OVS_UNUSED,
             const char *argv[] OVS_UNUSED, void *state_)
{
    struct ic_state *state = state_;
    state->paused = true;

    poll_immediate_wake();
    unixctl_command_reply(conn, NULL);
}

static void
ovn_ic_resume(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[] OVS_UNUSED, void *state_)
{
    struct ic_state *state = state_;
    state->paused = false;
    poll_immediate_wake();
    unixctl_command_reply(conn, NULL);
}

static void
ovn_ic_is_paused(struct unixctl_conn *conn, int argc OVS_UNUSED,
                 const char *argv[] OVS_UNUSED, void *state_)
{
    struct ic_state *state = state_;
    if (state->paused) {
        unixctl_command_reply(conn, "true");
    } else {
        unixctl_command_reply(conn, "false");
    }
}

static void
ovn_ic_status(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[] OVS_UNUSED, void *state_)
{
    struct ic_state *state = state_;
    char *status;

    if (state->paused) {
        status = "paused";
    } else {
        status = state->had_lock ? "active" : "standby";
    }

    /*
     * Use a labelled formatted output so we can add more to the status command
     * later without breaking any consuming scripts
     */
    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "Status: %s\n", status);
    ds_put_format(&s, "IC-SB lock: %s\n",
                  state->had_isb_lock ? "held" : "not held");
    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}
