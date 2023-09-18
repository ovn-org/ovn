/* Copyright (c) 2021, Red Hat, Inc.
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

#include "binding.h"
#include "if-status.h"
#include "ofctrl-seqno.h"
#include "ovsport.h"
#include "simap.h"

#include "lib/hmapx.h"
#include "lib/util.h"
#include "timeval.h"
#include "openvswitch/vlog.h"
#include "lib/vswitch-idl.h"
#include "lib/ovn-sb-idl.h"

VLOG_DEFINE_THIS_MODULE(if_status);

/* This module implements an interface manager that maintains the state of
 * the interfaces wrt. their flows being completely installed in OVS and
 * their corresponding bindings being marked up/down.
 *
 * A state machine is maintained for each interface.
 *
 * Transitions are triggered between states by three types of events:
 * A. Events received from the binding module:
 * - interface is claimed: if_status_mgr_claim_iface()
 * - interface is released: if_status_mgr_release_iface()
 * - interface is deleted: if_status_mgr_delete_iface()
 *
 * B. At every iteration, based on SB/OVS updates, handled in
 *    if_status_mgr_update():
 * - an interface binding has been marked "up" both in the Southbound and OVS
 *   databases.
 * - an interface binding has been marked "down" both in the Southbound and OVS
 *   databases.
 * - new interface has been claimed.
 *
 * C. At every iteration, based on ofctrl_seqno updates, handled in
 *    if_status_mgr_run():
 * - the flows for a previously claimed interface have been installed in OVS.
 */

enum if_state {
    OIF_CLAIMED,          /* Newly claimed interface. pb->chassis update not
                             yet initiated. */
    OIF_INSTALL_FLOWS,    /* Claimed interface with pb->chassis update sent to
                           * SB (but update notification not confirmed, so the
                           * update may be resent in any of the following
                           * states and for which flows are still being
                           * installed.
                           */
    OIF_REM_OLD_OVN_INST, /* Interface with flows successfully installed in OVS
                           * but with ovn-installed still in OVSDB.
                           */
    OIF_MARK_UP,          /* Interface with flows successfully installed in OVS
                           * but not yet marked "up" in the binding module (in
                           * SB and OVS databases).
                           */
    OIF_INSTALLED,        /* Interface flows programmed in OVS and binding
                           * marked "up" in the binding module.
                           */
    OIF_MARK_DOWN,        /* Released interface but not yet marked "down" in
                           * the binding module (in SB and/or OVS databases).
                           */
    OIF_UPDATE_PORT,      /* Logical ports need to be set down, and pb->chassis
                           * removed.
                           */
    OIF_MAX,
};

static const char *if_state_names[] = {
    [OIF_CLAIMED]          = "CLAIMED",
    [OIF_INSTALL_FLOWS]    = "INSTALL_FLOWS",
    [OIF_REM_OLD_OVN_INST] = "REM_OLD_OVN_INST",
    [OIF_MARK_UP]          = "MARK_UP",
    [OIF_MARK_DOWN]        = "MARK_DOWN",
    [OIF_INSTALLED]        = "INSTALLED",
    [OIF_UPDATE_PORT]      = "UPDATE_PORT",
};

/*
 *       +----------------------+
 * +---> |                      |
 * | +-> |         NULL         |
 * | |   +----------------------+
 * | |     ^ release_iface   | claim_iface()
 * | |     |                 V - sbrec_update_chassis(if sb is rw)
 * | |   +----------------------+
 * | |   |                      | <------------------------------------------+
 * | |   |       CLAIMED        | <----------------------------------------+ |
 * | |   |                      | <--------------------------------------+ | |
 * | |   +----------------------+                                        | | |
 * | |                 |  V  ^                                           | | |
 * | |                 |  |  | handle_claims()                           | | |
 * | |                 |  |  | - sbrec_update_chassis(if sb is rw)       | | |
 * | |                 |  +--+                                           | | |
 * | |                 |                                                 | | |
 * | |                 | mgr_update(when sb is rw i.e. pb->chassis)      | | |
 * | |                 |            has been updated                     | | |
 * | | release_iface   | - request seqno                                 | | |
 * | |                 |                                                 | | |
 * | |                 V                                                 | | |
 * | |   +----------------------+                                        | | |
 * | +-- |                      |  mgr_run(seqno not rcvd)               | | |
 * |     |    INSTALL_FLOWS     |   - set port down in sb                | | |
 * |     |                      |   - remove ovn-installed from ovsdb    | | |
 * |     |                      |  mgr_update()                          | | |
 * |     +----------------------+   - sbrec_update_chassis if needed     | | |
 * |        |            |                                               | | |
 * |        |            +----------------------------------------+      | | |
 * |        |                                                     |      | | |
 * |        | mgr_run(seqno rcvd, ovn-installed present)          |      | | |
 * |        V                                                     |      | | |
 * |    +--------------------+                                    |      | | |
 * |    |                    |  mgr_run()                         |      | | |
 * +--- | REM_OLD_OVN_INST   |  - remove ovn-installed in ovs     |      | | |
 * |    +--------------------+                                    |      | | |
 * |               |                                              |      | | |
 * |               |                                              |      | | |
 * |               | mgr_update( ovn_installed not present)       |      | | |
 * |               |                                              |      | | |
 * |               |  +-------------------------------------------+      | | |
 * |               |  |                                                  | | |
 * |               |  |  mgr_run(seqno rcvd, ovn-installed not present)  | | |
 * |               |  |  - set port up in sb                             | | |
 * |               |  |  - set ovn-installed in ovs                      | | |
 * |release_iface  |  |                                                  | | |
 * |               V  V                                                  | | |
 * |   +----------------------+                                          | | |
 * |   |                      |  mgr_run()                               | | |
 * +---|       MARK_UP        |  - set port up in sb                     | | |
 * |   |                      |  - set ovn-installed in ovs              | | |
 * |   |                      |  mgr_update()                            | | |
 * |   +----------------------+  - sbrec_update_chassis if needed        | | |
 * |            |                                                        | | |
 * |            | mgr_update(rcvd port up / ovn_installed & chassis set) | | |
 * |            V                                                        | | |
 * |   +----------------------+                                          | | |
 * |   |      INSTALLED       | ------------> claim_iface ---------------+ | |
 * |   +----------------------+                                            | |
 * |                  |                                                    | |
 * |                  | release_iface                                      | |
 * |mgr_update(       |                                                    | |
 * |  rcvd port down) |                                                    | |
 * |                  V                                                    | |
 * |   +----------------------+                                            | |
 * |   |                      | ------------> claim_iface -----------------+ |
 * +---+      MARK_DOWN       | mgr_run()                                    |
 * |   |                      | - set port down in sb                        |
 * |   |                      | mgr_update(sb is rw)                         |
 * |   +----------------------+ - sbrec_update_chassis(NULL)                 |
 * |                  |                                                      |
 * |                  | mgr_update(local binding not found)                  |
 * |                  |                                                      |
 * |                  V                                                      |
 * |   +----------------------+                                              |
 * |   |                      | ------------> claim_iface -------------------+
 * +---+      UPDATE_PORT     | mgr_run()
 *     +----------------------+ - sbrec_update_chassis(NULL)
 */


struct ovs_iface {
    char *id;               /* Extracted from OVS external_ids.iface_id. */
    struct uuid pb_uuid;    /* Port_binding uuid */
    enum if_state state;    /* State of the interface in the state machine. */
    uint32_t install_seqno; /* Seqno at which this interface is expected to
                             * be fully programmed in OVS.  Only used in state
                             * OIF_INSTALL_FLOWS.
                             */
    uint16_t mtu;           /* Extracted from OVS interface.mtu field. */
    enum can_bind bind_type;/* CAN_BIND_AS_MAIN or CAN_BIND_AS_ADDITIONAL */
};

static uint64_t ifaces_usage;

/* State machine manager for all local OVS interfaces. */
struct if_status_mgr {
    /* All local interfaces, mapping from 'iface-id' to 'struct ovs_iface'. */
    struct shash ifaces;

    /* local interfaces which need ovn-install removal */
    struct shash ovn_uninstall_hash;

    /* All local interfaces, stored per state. */
    struct hmapx ifaces_per_state[OIF_MAX];

    /* Registered ofctrl seqno type for port_binding flow installation. */
    size_t iface_seq_type_pb_cfg;

    /* Interface specific seqno to be acked by ofctrl when flows for new
     * interfaces have been installed.
     */
    uint32_t iface_seqno;
};

static struct ovs_iface *
ovs_iface_create(struct if_status_mgr *, const char *iface_id,
                 const struct ovsrec_interface *iface_rec,
                 enum if_state);
static void add_to_ovn_uninstall_hash(struct if_status_mgr *, const char *,
                                      const struct uuid *);
static void ovs_iface_destroy(struct if_status_mgr *, struct ovs_iface *);
static void ovn_uninstall_hash_destroy(struct if_status_mgr *mgr, char *name);
static void ovs_iface_set_state(struct if_status_mgr *, struct ovs_iface *,
                                enum if_state);

static void if_status_mgr_update_bindings(
    struct if_status_mgr *mgr, struct local_binding_data *binding_data,
    const struct sbrec_chassis *,
    const struct ovsrec_interface_table *iface_table,
    bool sb_readonly, bool ovs_readonly);

static void ovn_uninstall_hash_account_mem(const char *name, bool erase);
struct if_status_mgr *
if_status_mgr_create(void)
{
    struct if_status_mgr *mgr = xzalloc(sizeof *mgr);

    mgr->iface_seq_type_pb_cfg = ofctrl_seqno_add_type();
    for (size_t i = 0; i < ARRAY_SIZE(mgr->ifaces_per_state); i++) {
        hmapx_init(&mgr->ifaces_per_state[i]);
    }
    shash_init(&mgr->ifaces);
    shash_init(&mgr->ovn_uninstall_hash);
    return mgr;
}

void
if_status_mgr_clear(struct if_status_mgr *mgr)
{
    struct shash_node *node;

    SHASH_FOR_EACH_SAFE (node, &mgr->ifaces) {
        ovs_iface_destroy(mgr, node->data);
    }
    ovs_assert(shash_is_empty(&mgr->ifaces));

    SHASH_FOR_EACH_SAFE (node, &mgr->ovn_uninstall_hash) {
        ovn_uninstall_hash_destroy(mgr, node->data);
    }
    ovs_assert(shash_is_empty(&mgr->ovn_uninstall_hash));

    for (size_t i = 0; i < ARRAY_SIZE(mgr->ifaces_per_state); i++) {
        ovs_assert(hmapx_is_empty(&mgr->ifaces_per_state[i]));
    }
}

void
if_status_mgr_destroy(struct if_status_mgr *mgr)
{
    if_status_mgr_clear(mgr);
    shash_destroy(&mgr->ifaces);
    shash_destroy(&mgr->ovn_uninstall_hash);
    for (size_t i = 0; i < ARRAY_SIZE(mgr->ifaces_per_state); i++) {
        hmapx_destroy(&mgr->ifaces_per_state[i]);
    }
    free(mgr);
}

void
if_status_mgr_claim_iface(struct if_status_mgr *mgr,
                          const struct sbrec_port_binding *pb,
                          const struct sbrec_chassis *chassis_rec,
                          const struct ovsrec_interface *iface_rec,
                          bool sb_readonly, enum can_bind bind_type)
{
    const char *iface_id = pb->logical_port;
    struct ovs_iface *iface = shash_find_data(&mgr->ifaces, iface_id);

    if (!iface) {
        iface = ovs_iface_create(mgr, iface_id, iface_rec, OIF_CLAIMED);
    }
    iface->bind_type = bind_type;

    memcpy(&iface->pb_uuid, &pb->header_.uuid, sizeof(iface->pb_uuid));
    if (!sb_readonly) {
        if (bind_type == CAN_BIND_AS_MAIN) {
            set_pb_chassis_in_sbrec(pb, chassis_rec, true);
        } else if (bind_type == CAN_BIND_AS_ADDITIONAL) {
            set_pb_additional_chassis_in_sbrec(pb, chassis_rec, true);
        }
    }

    switch (iface->state) {
    case OIF_CLAIMED:
    case OIF_INSTALL_FLOWS:
    case OIF_REM_OLD_OVN_INST:
    case OIF_MARK_UP:
        /* Nothing to do here. */
        break;
    case OIF_INSTALLED:
    case OIF_MARK_DOWN:
    case OIF_UPDATE_PORT:
        ovs_iface_set_state(mgr, iface, OIF_CLAIMED);
        break;
    case OIF_MAX:
        OVS_NOT_REACHED();
        break;
    }
}

bool
if_status_mgr_iface_is_present(struct if_status_mgr *mgr, const char *iface_id)
{
    return !!shash_find_data(&mgr->ifaces, iface_id);
}

void
if_status_mgr_release_iface(struct if_status_mgr *mgr, const char *iface_id)
{
    struct ovs_iface *iface = shash_find_data(&mgr->ifaces, iface_id);

    if (!iface) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Trying to release unknown interface %s", iface_id);
        return;
    }

    switch (iface->state) {
    case OIF_CLAIMED:
    case OIF_INSTALL_FLOWS:
        /* Not yet fully installed interfaces:
         * pb->chassis still need to be deleted.
         */
    case OIF_REM_OLD_OVN_INST:
    case OIF_MARK_UP:
    case OIF_INSTALLED:
        /* Properly mark interfaces "down" if their flows were already
         * programmed in OVS.
         */
        ovs_iface_set_state(mgr, iface, OIF_MARK_DOWN);
        break;
    case OIF_MARK_DOWN:
    case OIF_UPDATE_PORT:
        /* Nothing to do here. */
        break;
    case OIF_MAX:
        OVS_NOT_REACHED();
        break;
    }
}

void
if_status_mgr_delete_iface(struct if_status_mgr *mgr, const char *iface_id)
{
    struct ovs_iface *iface = shash_find_data(&mgr->ifaces, iface_id);

    if (!iface) {
        return;
    }

    switch (iface->state) {
    case OIF_CLAIMED:
    case OIF_INSTALL_FLOWS:
        /* Not yet fully installed interfaces:
         * pb->chassis still need to be deleted.
         */
    case OIF_REM_OLD_OVN_INST:
    case OIF_MARK_UP:
    case OIF_INSTALLED:
        /* Properly mark interfaces "down" if their flows were already
         * programmed in OVS.
         */
        ovs_iface_set_state(mgr, iface, OIF_MARK_DOWN);
        break;
    case OIF_MARK_DOWN:
    case OIF_UPDATE_PORT:
        /* Nothing to do here. */
        break;
    case OIF_MAX:
        OVS_NOT_REACHED();
        break;
    }
}

bool
if_status_handle_claims(struct if_status_mgr *mgr,
                        struct local_binding_data *binding_data,
                        const struct sbrec_chassis *chassis_rec,
                        struct hmap *tracked_datapath,
                        bool sb_readonly)
{
    if (!binding_data || sb_readonly) {
        return false;
    }

    struct shash *bindings = &binding_data->bindings;
    struct hmapx_node *node;

    bool rc = false;
    HMAPX_FOR_EACH (node, &mgr->ifaces_per_state[OIF_CLAIMED]) {
        struct ovs_iface *iface = node->data;
        VLOG_INFO("if_status_handle_claims for %s", iface->id);
        local_binding_set_pb(bindings, iface->id, chassis_rec,
                             tracked_datapath, true, iface->bind_type);
        rc = true;
    }
    return rc;
}

static void
clean_ovn_installed(struct if_status_mgr *mgr,
                    const struct ovsrec_interface_table *iface_table)
{
    struct shash_node *node;

    SHASH_FOR_EACH_SAFE (node, &mgr->ovn_uninstall_hash) {
        const struct uuid *iface_uuid = node->data;
        remove_ovn_installed_for_uuid(iface_table, iface_uuid);
        free(node->data);
        char *node_name = shash_steal(&mgr->ovn_uninstall_hash, node);
        ovn_uninstall_hash_account_mem(node_name, true);
        free(node_name);
    }
}

void
if_status_mgr_update(struct if_status_mgr *mgr,
                     struct local_binding_data *binding_data,
                     const struct sbrec_chassis *chassis_rec,
                     const struct ovsrec_interface_table *iface_table,
                     const struct sbrec_port_binding_table *pb_table,
                     bool ovs_readonly,
                     bool sb_readonly)
{
    if (!ovs_readonly) {
        clean_ovn_installed(mgr, iface_table);
    }
    if (!binding_data) {
        return;
    }

    struct shash *bindings = &binding_data->bindings;
    struct hmapx_node *node;

    /* Move all interfaces that have been confirmed without ovn-installed,
     * from OIF_REM_OLD_OVN_INST to OIF_MARK_UP.
     */
    HMAPX_FOR_EACH_SAFE (node, &mgr->ifaces_per_state[OIF_REM_OLD_OVN_INST]) {
        struct ovs_iface *iface = node->data;

        if (!local_binding_is_ovn_installed(bindings, iface->id)) {
            ovs_iface_set_state(mgr, iface, OIF_MARK_UP);
        }
    }

    /* Interfaces in OIF_MARK_UP/INSTALL_FLOWS state have already set their
     * pb->chassis. However, the update might still be in fly (confirmation
     * not received yet) or pb->chassis was overwitten by another chassis.
     */

    /* Move all interfaces that have been confirmed "up" by the binding module,
     * from OIF_MARK_UP to OIF_INSTALLED.
     */
    HMAPX_FOR_EACH_SAFE (node, &mgr->ifaces_per_state[OIF_MARK_UP]) {
        struct ovs_iface *iface = node->data;

        if (!local_bindings_pb_chassis_is_set(bindings, iface->id,
            chassis_rec)) {
            if (!sb_readonly) {
                long long int now = time_msec();
                if (lport_maybe_postpone(iface->id, now,
                                         get_postponed_ports())) {
                    continue;
                }
                local_binding_set_pb(bindings, iface->id, chassis_rec,
                                     NULL, true, iface->bind_type);
            } else {
                continue;
            }
        }
        if (local_binding_is_up(bindings, iface->id, chassis_rec)) {
            ovs_iface_set_state(mgr, iface, OIF_INSTALLED);
        }
    }

    /* Cleanup all interfaces that have been confirmed "down" by the binding
     * module.
     */
    HMAPX_FOR_EACH_SAFE (node, &mgr->ifaces_per_state[OIF_MARK_DOWN]) {
        struct ovs_iface *iface = node->data;

        if (!local_binding_find(bindings, iface->id)) {
            ovs_iface_set_state(mgr, iface, OIF_UPDATE_PORT);
            continue;
        }
        if (!sb_readonly) {
            local_binding_set_pb(bindings, iface->id, chassis_rec,
                                 NULL, false, iface->bind_type);
        }
        if (local_binding_is_down(bindings, iface->id, chassis_rec)) {
            ovs_iface_destroy(mgr, iface);
        }
    }

    /* Update pb->chassis in case it's not set (previous update still in fly
     * or pb->chassis was overwitten by another chassis.
     */
    if (!sb_readonly) {
        HMAPX_FOR_EACH_SAFE (node, &mgr->ifaces_per_state[OIF_INSTALL_FLOWS]) {
            struct ovs_iface *iface = node->data;
            if (!local_bindings_pb_chassis_is_set(bindings, iface->id,
                chassis_rec)) {
                long long int now = time_msec();
                if (lport_maybe_postpone(iface->id, now,
                                         get_postponed_ports())) {
                    continue;
                }
                local_binding_set_pb(bindings, iface->id, chassis_rec,
                                     NULL, true, iface->bind_type);
            }
        }
    }

    /* Move newly claimed interfaces from OIF_CLAIMED to OIF_INSTALL_FLOWS.
     */
    bool new_ifaces = false;
    if (!sb_readonly) {
        HMAPX_FOR_EACH_SAFE (node, &mgr->ifaces_per_state[OIF_CLAIMED]) {
            struct ovs_iface *iface = node->data;
            /* No need to to update pb->chassis as already done
             * in if_status_handle_claims or if_status_mgr_claim_iface
             */
            ovs_iface_set_state(mgr, iface, OIF_INSTALL_FLOWS);
            iface->install_seqno = mgr->iface_seqno + 1;
            new_ifaces = true;
        }
    } else {
        HMAPX_FOR_EACH_SAFE (node, &mgr->ifaces_per_state[OIF_CLAIMED]) {
            struct ovs_iface *iface = node->data;
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(&rl,
                         "Not updating pb chassis for %s now as "
                         "sb is readonly", iface->id);
        }
    }

    if (!sb_readonly) {
        HMAPX_FOR_EACH_SAFE (node, &mgr->ifaces_per_state[OIF_UPDATE_PORT]) {
            struct ovs_iface *iface = node->data;
            port_binding_set_down(chassis_rec, pb_table, iface->id,
                                  &iface->pb_uuid);
            ovs_iface_destroy(mgr, node->data);
        }
    } else {
        HMAPX_FOR_EACH_SAFE (node, &mgr->ifaces_per_state[OIF_UPDATE_PORT]) {
            struct ovs_iface *iface = node->data;
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(&rl, "Not setting lport %s down as sb is readonly",
                         iface->id);
        }
    }
    /* Register for a notification about flows being installed in OVS for all
     * newly claimed interfaces for which pb->chassis has been updated.
     * Request a seqno update when the flows for new interfaces have been
     * installed in OVS.
     */
    if (new_ifaces) {
        mgr->iface_seqno++;
        ofctrl_seqno_update_create(mgr->iface_seq_type_pb_cfg,
                                   mgr->iface_seqno);
        VLOG_DBG("Seqno requested: %"PRIu32, mgr->iface_seqno);
    }
}

void
if_status_mgr_remove_ovn_installed(struct if_status_mgr *mgr,
                                   const char *name,
                                   const struct uuid *uuid)
{
    VLOG_DBG("Adding %s to list of interfaces for which to remove "
              "ovn-installed", name);
    if (!shash_find_data(&mgr->ovn_uninstall_hash, name)) {
        add_to_ovn_uninstall_hash(mgr, name, uuid);
    }
}

void
if_status_mgr_run(struct if_status_mgr *mgr,
                  struct local_binding_data *binding_data,
                  const struct sbrec_chassis *chassis_rec,
                  const struct ovsrec_interface_table *iface_table,
                  bool sb_readonly, bool ovs_readonly)
{
    struct ofctrl_acked_seqnos *acked_seqnos =
            ofctrl_acked_seqnos_get(mgr->iface_seq_type_pb_cfg);
    struct hmapx_node *node;

    /* Move interfaces from state OIF_INSTALL_FLOWS to OIF_MARK_UP if a
     * notification has been received aabout their flows being installed
     * in OVS.
     */
    HMAPX_FOR_EACH_SAFE (node, &mgr->ifaces_per_state[OIF_INSTALL_FLOWS]) {
        struct ovs_iface *iface = node->data;

        if (!ofctrl_acked_seqnos_contains(acked_seqnos,
                                          iface->install_seqno)) {
            continue;
        }
        /* Wait for ovn-installed to be absent before moving to MARK_UP state.
         * Most of the times ovn-installed is already absent and hence we will
         * not have to wait.
         * If there is no binding_data, we can't determine if ovn-installed is
         * present or not; hence also go to the OIF_REM_OLD_OVN_INST state.
         */
        if (!binding_data ||
            local_binding_is_ovn_installed(&binding_data->bindings,
                                           iface->id)) {
            ovs_iface_set_state(mgr, iface, OIF_REM_OLD_OVN_INST);
        } else {
            ovs_iface_set_state(mgr, iface, OIF_MARK_UP);
        }
    }
    ofctrl_acked_seqnos_destroy(acked_seqnos);

    /* Update binding states. */
    if_status_mgr_update_bindings(mgr, binding_data, chassis_rec,
                                  iface_table,
                                  sb_readonly, ovs_readonly);
}

static void
ovs_iface_account_mem(const char *iface_id, bool erase)
{
    uint32_t size = (strlen(iface_id) + sizeof(struct ovs_iface) +
                     sizeof(struct shash_node));
    if (erase) {
        ifaces_usage -= size;
    } else {
        ifaces_usage += size;
    }
}

static void
ovn_uninstall_hash_account_mem(const char *name, bool erase)
{
    uint32_t size = (strlen(name) + sizeof(struct uuid) +
                     sizeof(struct shash_node));
    if (erase) {
        ifaces_usage -= size;
    } else {
        ifaces_usage += size;
    }
}

uint16_t
if_status_mgr_iface_get_mtu(const struct if_status_mgr *mgr,
                            const char *iface_id)
{
    const struct ovs_iface *iface = shash_find_data(&mgr->ifaces, iface_id);
    return iface ? iface->mtu : 0;
}

bool
if_status_mgr_iface_update(const struct if_status_mgr *mgr,
                           const struct ovsrec_interface *iface_rec)
{
    const char *iface_id = smap_get(&iface_rec->external_ids, "iface-id");
    if (!iface_id) {
        return false;
    }
    uint16_t mtu = get_iface_mtu(iface_rec);
    struct ovs_iface *iface = shash_find_data(&mgr->ifaces, iface_id);
    if (iface && iface->mtu != mtu) {
        iface->mtu = mtu;
        return true;
    }
    return false;
}

static struct ovs_iface *
ovs_iface_create(struct if_status_mgr *mgr, const char *iface_id,
                 const struct ovsrec_interface *iface_rec,
                 enum if_state state)
{
    struct ovs_iface *iface = xzalloc(sizeof *iface);

    VLOG_DBG("Interface %s create.", iface_id);
    iface->id = xstrdup(iface_id);
    shash_add_nocopy(&mgr->ifaces, iface->id, iface);
    ovs_iface_set_state(mgr, iface, state);
    ovs_iface_account_mem(iface_id, false);
    if_status_mgr_iface_update(mgr, iface_rec);
    return iface;
}

static void
add_to_ovn_uninstall_hash(struct if_status_mgr *mgr, const char *name,
                          const struct uuid *uuid)
{
    struct uuid *new_uuid = xzalloc(sizeof *new_uuid);
    memcpy(new_uuid, uuid, sizeof(*new_uuid));
    shash_add(&mgr->ovn_uninstall_hash, name, new_uuid);
    ovn_uninstall_hash_account_mem(name, false);
}

static void
ovs_iface_destroy(struct if_status_mgr *mgr, struct ovs_iface *iface)
{
    VLOG_DBG("Interface %s destroy: state %s", iface->id,
             if_state_names[iface->state]);
    hmapx_find_and_delete(&mgr->ifaces_per_state[iface->state], iface);
    struct shash_node *node = shash_find(&mgr->ifaces, iface->id);
    if (node) {
        shash_steal(&mgr->ifaces, node);
    }
    ovs_iface_account_mem(iface->id, true);
    free(iface->id);
    free(iface);
}

static void
ovn_uninstall_hash_destroy(struct if_status_mgr *mgr, char *name)
{
    struct shash_node *node = shash_find(&mgr->ovn_uninstall_hash, name);
    char *node_name = NULL;
    if (node) {
        free(node->data);
        VLOG_DBG("Interface name %s destroy", name);
        node_name = shash_steal(&mgr->ovn_uninstall_hash, node);
        ovn_uninstall_hash_account_mem(name, true);
        free(node_name);
    } else {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Interface name %s not found", name);
    }
}

static void
ovs_iface_set_state(struct if_status_mgr *mgr, struct ovs_iface *iface,
                    enum if_state state)
{
    VLOG_DBG("Interface %s set state: old %s, new %s", iface->id,
             if_state_names[iface->state],
             if_state_names[state]);

    hmapx_find_and_delete(&mgr->ifaces_per_state[iface->state], iface);
    iface->state = state;
    hmapx_add(&mgr->ifaces_per_state[iface->state], iface);
    iface->install_seqno = 0;
}

static void
if_status_mgr_update_bindings(struct if_status_mgr *mgr,
                              struct local_binding_data *binding_data,
                              const struct sbrec_chassis *chassis_rec,
                              const struct ovsrec_interface_table *iface_table,
                              bool sb_readonly, bool ovs_readonly)
{
    if (!binding_data) {
        return;
    }

    struct shash *bindings = &binding_data->bindings;
    struct hmapx_node *node;

    /* Notify the binding module to set "down" all bindings that are still
     * in the process of being installed in OVS, i.e., are not yet installed.
     */
    HMAPX_FOR_EACH (node, &mgr->ifaces_per_state[OIF_INSTALL_FLOWS]) {
        struct ovs_iface *iface = node->data;

        local_binding_set_down(bindings, iface->id, chassis_rec,
                               sb_readonly, ovs_readonly);
    }

    /* Notify the binding module to remove "ovn-installed" for all bindings
     * in the OIF_REM_OLD_OVN_INST state.
     */
    HMAPX_FOR_EACH (node, &mgr->ifaces_per_state[OIF_REM_OLD_OVN_INST]) {
        struct ovs_iface *iface = node->data;

        local_binding_remove_ovn_installed(bindings, iface_table, iface->id,
                                           ovs_readonly);
    }

    /* Notify the binding module to set "up" all bindings that have had
     * their flows installed but are not yet marked "up" in the binding
     * module.
     */
    char *ts_now_str = xasprintf("%lld", time_wall_msec());
    HMAPX_FOR_EACH (node, &mgr->ifaces_per_state[OIF_MARK_UP]) {
        struct ovs_iface *iface = node->data;

        local_binding_set_up(bindings, iface->id, chassis_rec, ts_now_str,
                             sb_readonly, ovs_readonly);
    }
    free(ts_now_str);

    /* Notify the binding module to set "down" all bindings that have been
     * released but are not yet marked as "down" in the binding module.
     */
    HMAPX_FOR_EACH (node, &mgr->ifaces_per_state[OIF_MARK_DOWN]) {
        struct ovs_iface *iface = node->data;

        local_binding_set_down(bindings, iface->id, chassis_rec,
                               sb_readonly, ovs_readonly);
    }
}

void
if_status_mgr_get_memory_usage(struct if_status_mgr *mgr,
                               struct simap *usage)
{
    uint64_t ifaces_state_usage = 0;
    for (size_t i = 0; i < ARRAY_SIZE(mgr->ifaces_per_state); i++) {
        ifaces_state_usage += sizeof(struct hmapx_node) *
                              hmapx_count(&mgr->ifaces_per_state[i]);
    }

    simap_increase(usage, "if_status_mgr_ifaces_usage-KB",
                   ROUND_UP(ifaces_usage, 1024) / 1024);
    simap_increase(usage, "if_status_mgr_ifaces_state_usage-KB",
                   ROUND_UP(ifaces_state_usage, 1024) / 1024);
}

bool
if_status_is_port_claimed(const struct if_status_mgr *mgr,
                          const char *iface_id)
{
    struct ovs_iface *iface = shash_find_data(&mgr->ifaces, iface_id);
    if (!iface || (iface->state > OIF_INSTALLED)) {
        return false;
    } else {
        return true;
    }
}

