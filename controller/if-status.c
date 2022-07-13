
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
#include "simap.h"

#include "lib/hmapx.h"
#include "lib/util.h"
#include "timeval.h"
#include "openvswitch/vlog.h"

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
    OIF_CLAIMED,                /* Newly claimed interface. */
    OIF_INSTALL_FLOWS,          /* Already claimed interface for which flows
                                 * are still being installed. */
    OIF_MARK_UP,                /* Interface with flows successfully installed 
                                 * in OVS but not yet marked "up" in the
                                 * binding module (in SB and OVS databases). */
    OIF_MARK_DOWN,              /* Released interface but not yet marked
                                 * "down" in the binding module (in SB and/or
                                 * OVS databases). */
    OIF_INSTALLED,              /* Interface flows programmed in OVS and
                                 * binding marked "up" in the binding module. */
    OIF_MAX,
};

static const char *if_state_names[] = {
    [OIF_CLAIMED] = "CLAIMED",
    [OIF_INSTALL_FLOWS] = "INSTALL_FLOWS",
    [OIF_MARK_UP] = "MARK_UP",
    [OIF_MARK_DOWN] = "MARK_DOWN",
    [OIF_INSTALLED] = "INSTALLED",
};

struct ovs_iface {
    char *id;                   /* Extracted from OVS external_ids.iface_id. */
    enum if_state state;        /* State of the interface in the state
                                 * machine. */
    uint32_t install_seqno;     /* Seqno at which this interface is expected
                                 * to be fully programmed in OVS.  Only used
                                 * in state OIF_INSTALL_FLOWS. */
};

static uint64_t ifaces_usage;

/* State machine manager for all local OVS interfaces. */
struct if_status_mgr {
    /* All local interfaces, mapping from 'iface-id' to 'struct ovs_iface'. */
    struct shash ifaces;

    /* All local interfaces, stored per state. */
    struct hmapx ifaces_per_state[OIF_MAX];

    /* Registered ofctrl seqno type for port_binding flow installation. */
    size_t iface_seq_type_pb_cfg;

    /* Interface specific seqno to be acked by ofctrl when flows for new
     * interfaces have been installed. */
    uint32_t iface_seqno;
};

static struct ovs_iface *ovs_iface_create(struct if_status_mgr *,
                                          const char *iface_id, enum if_state);
static void ovs_iface_destroy(struct if_status_mgr *, struct ovs_iface *);
static void ovs_iface_set_state(struct if_status_mgr *, struct ovs_iface *,
                                enum if_state);

static void if_status_mgr_update_bindings(struct if_status_mgr *mgr,
                                          struct local_binding_data
                                          *binding_data,
                                          const struct sbrec_chassis *,
                                          bool sb_readonly, bool ovs_readonly);

struct if_status_mgr *
if_status_mgr_create(void)
{
    struct if_status_mgr *mgr = xzalloc(sizeof *mgr);

    mgr->iface_seq_type_pb_cfg = ofctrl_seqno_add_type();
    for (size_t i = 0; i < ARRAY_SIZE(mgr->ifaces_per_state); i++) {
        hmapx_init(&mgr->ifaces_per_state[i]);
    }
    shash_init(&mgr->ifaces);
    return mgr;
}

void
if_status_mgr_clear(struct if_status_mgr *mgr)
{
    struct shash_node *node;

    SHASH_FOR_EACH_SAFE(node, &mgr->ifaces) {
        ovs_iface_destroy(mgr, node->data);
    }
    ovs_assert(shash_is_empty(&mgr->ifaces));

    for (size_t i = 0; i < ARRAY_SIZE(mgr->ifaces_per_state); i++) {
        ovs_assert(hmapx_is_empty(&mgr->ifaces_per_state[i]));
    }
}

void
if_status_mgr_destroy(struct if_status_mgr *mgr)
{
    if_status_mgr_clear(mgr);
    shash_destroy(&mgr->ifaces);
    for (size_t i = 0; i < ARRAY_SIZE(mgr->ifaces_per_state); i++) {
        hmapx_destroy(&mgr->ifaces_per_state[i]);
    }
    free(mgr);
}

void
if_status_mgr_claim_iface(struct if_status_mgr *mgr, const char *iface_id)
{
    struct ovs_iface *iface = shash_find_data(&mgr->ifaces, iface_id);

    if (!iface) {
        iface = ovs_iface_create(mgr, iface_id, OIF_CLAIMED);
    }

    switch (iface->state) {
    case OIF_CLAIMED:
    case OIF_INSTALL_FLOWS:
    case OIF_MARK_UP:
        /* Nothing to do here. */
        break;
    case OIF_INSTALLED:
    case OIF_MARK_DOWN:
        ovs_iface_set_state(mgr, iface, OIF_CLAIMED);
        break;
    case OIF_MAX:
        OVS_NOT_REACHED();
        break;
    }
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
        /* Not yet fully installed interfaces can be safely deleted. */
        ovs_iface_destroy(mgr, iface);
        break;
    case OIF_MARK_UP:
    case OIF_INSTALLED:
        /* Properly mark interfaces "down" if their flows were already
         * programmed in OVS. */
        ovs_iface_set_state(mgr, iface, OIF_MARK_DOWN);
        break;
    case OIF_MARK_DOWN:
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
        /* Not yet fully installed interfaces can be safely deleted. */
        ovs_iface_destroy(mgr, iface);
        break;
    case OIF_MARK_UP:
    case OIF_INSTALLED:
        /* Properly mark interfaces "down" if their flows were already
         * programmed in OVS. */
        ovs_iface_set_state(mgr, iface, OIF_MARK_DOWN);
        break;
    case OIF_MARK_DOWN:
        /* Nothing to do here. */
        break;
    case OIF_MAX:
        OVS_NOT_REACHED();
        break;
    }
}

void
if_status_mgr_update(struct if_status_mgr *mgr,
                     struct local_binding_data *binding_data)
{
    if (!binding_data) {
        return;
    }

    struct shash *bindings = &binding_data->bindings;
    struct hmapx_node *node;

    /* Move all interfaces that have been confirmed "up" by the binding
     * module, from OIF_MARK_UP to OIF_INSTALLED. */
    HMAPX_FOR_EACH_SAFE(node, &mgr->ifaces_per_state[OIF_MARK_UP]) {
        struct ovs_iface *iface = node->data;

        if (local_binding_is_up(bindings, iface->id)) {
            ovs_iface_set_state(mgr, iface, OIF_INSTALLED);
        }
    }

    /* Cleanup all interfaces that have been confirmed "down" by the binding
     * module. */
    HMAPX_FOR_EACH_SAFE(node, &mgr->ifaces_per_state[OIF_MARK_DOWN]) {
        struct ovs_iface *iface = node->data;

        if (local_binding_is_down(bindings, iface->id)) {
            ovs_iface_destroy(mgr, iface);
        }
    }

    /* Register for a notification about flows being installed in OVS for all
     * newly claimed interfaces. Move them from OIF_CLAIMED to
     * OIF_INSTALL_FLOWS. */
    bool new_ifaces = false;

    HMAPX_FOR_EACH_SAFE(node, &mgr->ifaces_per_state[OIF_CLAIMED]) {
        struct ovs_iface *iface = node->data;

        ovs_iface_set_state(mgr, iface, OIF_INSTALL_FLOWS);
        iface->install_seqno = mgr->iface_seqno + 1;
        new_ifaces = true;
    }

    /* Request a seqno update when the flows for new interfaces have been
     * installed in OVS. */
    if (new_ifaces) {
        mgr->iface_seqno++;
        ofctrl_seqno_update_create(mgr->iface_seq_type_pb_cfg,
                                   mgr->iface_seqno);
        VLOG_DBG("Seqno requested: %" PRIu32, mgr->iface_seqno);
    }
}

void
if_status_mgr_run(struct if_status_mgr *mgr,
                  struct local_binding_data *binding_data,
                  const struct sbrec_chassis *chassis_rec,
                  bool sb_readonly, bool ovs_readonly)
{
    struct ofctrl_acked_seqnos *acked_seqnos =
        ofctrl_acked_seqnos_get(mgr->iface_seq_type_pb_cfg);
    struct hmapx_node *node;

    /* Move interfaces from state OIF_INSTALL_FLOWS to OIF_MARK_UP if a
     * notification has been received aabout their flows being installed in
     * OVS. */
    HMAPX_FOR_EACH_SAFE(node, &mgr->ifaces_per_state[OIF_INSTALL_FLOWS]) {
        struct ovs_iface *iface = node->data;

        if (!ofctrl_acked_seqnos_contains(acked_seqnos, iface->install_seqno)) {
            continue;
        }
        ovs_iface_set_state(mgr, iface, OIF_MARK_UP);
    }
    ofctrl_acked_seqnos_destroy(acked_seqnos);

    /* Update binding states. */
    if_status_mgr_update_bindings(mgr, binding_data, chassis_rec,
                                  sb_readonly, ovs_readonly);
}

static void
ovs_iface_account_mem(const char *iface_id, bool erase)
{
    uint32_t size = (strlen(iface_id) + sizeof (struct ovs_iface) +
                     sizeof (struct shash_node));
    if (erase) {
        ifaces_usage -= size;
    } else {
        ifaces_usage += size;
    }
}

static struct ovs_iface *
ovs_iface_create(struct if_status_mgr *mgr, const char *iface_id,
                 enum if_state state)
{
    struct ovs_iface *iface = xzalloc(sizeof *iface);

    VLOG_DBG("Interface %s create.", iface_id);
    iface->id = xstrdup(iface_id);
    shash_add_nocopy(&mgr->ifaces, iface->id, iface);
    ovs_iface_set_state(mgr, iface, state);
    ovs_iface_account_mem(iface_id, false);
    return iface;
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
ovs_iface_set_state(struct if_status_mgr *mgr, struct ovs_iface *iface,
                    enum if_state state)
{
    VLOG_DBG("Interface %s set state: old %s, new %s", iface->id,
             if_state_names[iface->state], if_state_names[state]);

    hmapx_find_and_delete(&mgr->ifaces_per_state[iface->state], iface);
    iface->state = state;
    hmapx_add(&mgr->ifaces_per_state[iface->state], iface);
    iface->install_seqno = 0;
}

static void
if_status_mgr_update_bindings(struct if_status_mgr *mgr,
                              struct local_binding_data *binding_data,
                              const struct sbrec_chassis *chassis_rec,
                              bool sb_readonly, bool ovs_readonly)
{
    if (!binding_data) {
        return;
    }

    struct shash *bindings = &binding_data->bindings;
    struct hmapx_node *node;

    /* Notify the binding module to set "down" all bindings that are still in
     * the process of being installed in OVS, i.e., are not yet instsalled. */
    HMAPX_FOR_EACH(node, &mgr->ifaces_per_state[OIF_INSTALL_FLOWS]) {
        struct ovs_iface *iface = node->data;

        local_binding_set_down(bindings, iface->id, chassis_rec,
                               sb_readonly, ovs_readonly);
    }

    /* Notifiy the binding module to set "up" all bindings that have had their 
     * flows installed but are not yet marked "up" in the binding module. */
    char *ts_now_str = xasprintf("%lld", time_wall_msec());

    HMAPX_FOR_EACH(node, &mgr->ifaces_per_state[OIF_MARK_UP]) {
        struct ovs_iface *iface = node->data;

        local_binding_set_up(bindings, iface->id, chassis_rec, ts_now_str,
                             sb_readonly, ovs_readonly);
    }
    free(ts_now_str);

    /* Notify the binding module to set "down" all bindings that have been
     * released but are not yet marked as "down" in the binding module. */
    HMAPX_FOR_EACH(node, &mgr->ifaces_per_state[OIF_MARK_DOWN]) {
        struct ovs_iface *iface = node->data;

        local_binding_set_down(bindings, iface->id, chassis_rec,
                               sb_readonly, ovs_readonly);
    }
}

void
if_status_mgr_get_memory_usage(struct if_status_mgr *mgr, struct simap *usage)
{
    uint64_t ifaces_state_usage = 0;

    for (size_t i = 0; i < ARRAY_SIZE(mgr->ifaces_per_state); i++) {
        ifaces_state_usage += sizeof (struct hmapx_node) *
            hmapx_count(&mgr->ifaces_per_state[i]);
    }

    simap_increase(usage, "if_status_mgr_ifaces_usage-KB",
                   ROUND_UP(ifaces_usage, 1024) / 1024);
    simap_increase(usage, "if_status_mgr_ifaces_state_usage-KB",
                   ROUND_UP(ifaces_state_usage, 1024) / 1024);
}
