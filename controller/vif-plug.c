/*
 * Copyright (c) 2021 Canonical
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

/* OVS includes */
#include "lib/vswitch-idl.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"

/* OVN includes */
#include "binding.h"
#include "lib/ovn-sb-idl.h"
#include "lport.h"
#include "ovsport.h"
#include "vif-plug.h"
#include "vif-plug-provider.h"

VLOG_DEFINE_THIS_MODULE(vif_plug);

#define OVN_PLUGGED_EXT_ID "ovn-plugged"
#define VIF_PLUG_OPTION_TYPE "vif-plug-type"
#define VIF_PLUG_OPTION_MTU_REQUEST "vif-plug-mtu-request"

void
vif_plug_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_mtu_request);
}

/* Get the class level 'maintained_iface_options' set. */
const struct sset *
vif_plug_get_maintained_iface_options(
        const struct vif_plug_class *vif_plug_class)
{
    return vif_plug_class->vif_plug_get_maintained_iface_options ?
           vif_plug_class->vif_plug_get_maintained_iface_options() : NULL;
}

/* Prepare the logical port as identified by 'ctx_in' for port creation, update
 * or removal as specified by 'ctx_in->op_type'.
 *
 * When 'ctx_in->op_type' is PLUG_OP_CREATE the plug implementation must fill
 * 'ctx_out' with data to apply to the interface record maintained by OVN on
 * its behalf.
 *
 * When 'ctx_in_op_type' is PLUG_OP_REMOVE 'ctx_out' should be set to NULL and
 * the plug implementation must not attempt to use 'ctx_out'.
 *
 * The data in 'ctx_out' is owned by the plug implementation, and a call must
 * be made to vif_plug_port_ctx_destroy when done with it. */
bool
vif_plug_port_prepare(const struct vif_plug_class *vif_plug_class,
                      const struct vif_plug_port_ctx_in *ctx_in,
                      struct vif_plug_port_ctx_out *ctx_out)
{
    return vif_plug_class->vif_plug_port_prepare(ctx_in, ctx_out);
}

/* Notify the VIF plug implementation that a port creation, update or removal
 * has been committed to the database. */
void
vif_plug_port_finish(const struct vif_plug_class *vif_plug_class,
                     const struct vif_plug_port_ctx_in *ctx_in,
                     struct vif_plug_port_ctx_out *ctx_out)
{
    vif_plug_class->vif_plug_port_finish(ctx_in, ctx_out);
}

/* Free any data allocated to 'ctx_out' in a prevous call to
 * vif_plug_port_prepare. */
void
vif_plug_port_ctx_destroy(const struct vif_plug_class *vif_plug_class,
                          const struct vif_plug_port_ctx_in *ctx_in,
                          struct vif_plug_port_ctx_out *ctx_out)
{
    vif_plug_class->vif_plug_port_ctx_destroy(ctx_in, ctx_out);
}

static struct vif_plug_port_ctx *
build_port_ctx(const struct vif_plug_class *vif_plug,
                  const enum vif_plug_op_type op_type,
                  const struct vif_plug_ctx_in *vif_plug_ctx_in,
                  const struct sbrec_port_binding *pb,
                  const struct ovsrec_interface *iface,
                  const char *iface_id)
{
    struct vif_plug_port_ctx *new_ctx = xzalloc(
        sizeof *new_ctx);

    new_ctx->vif_plug = vif_plug;
    new_ctx->vif_plug_port_ctx_in.op_type = op_type;
    new_ctx->vif_plug_port_ctx_in.ovs_table = vif_plug_ctx_in->ovs_table;
    new_ctx->vif_plug_port_ctx_in.br_int = vif_plug_ctx_in->br_int;
    new_ctx->vif_plug_port_ctx_in.lport_name = pb ?
        xstrdup(pb->logical_port) : iface_id ? xstrdup(iface_id) : NULL;
    /* Prepare vif_plug_port_ctx_in smaps for use.
     *
     * Note that smap_init does not allocate memory.  Any memory allocated by
     * putting data into the vif_plug_port_ctx_in smaps will be destroyed by
     * calls to smap_destroy in destroy_port_ctx */
    smap_init(&new_ctx->vif_plug_port_ctx_in.lport_options);
    smap_init(&new_ctx->vif_plug_port_ctx_in.iface_options);

    if (pb) {
        smap_clone(&new_ctx->vif_plug_port_ctx_in.lport_options,
                   &pb->options);
    }

    if (iface) {
        new_ctx->vif_plug_port_ctx_in.iface_name = xstrdup(iface->name);
        new_ctx->vif_plug_port_ctx_in.iface_type = xstrdup(iface->type);
        smap_clone(&new_ctx->vif_plug_port_ctx_in.iface_options,
                   &iface->options);
    }

    /* Prepare vif_plug_port_ctx_out smaps for use.
     *
     * Note that smap_init does not allocate memory.  Any memory allocated by
     * putting data into the vif_plug_port_ctx_out smaps is the responsibility
     * of the VIF plug provider through a call to vif_plug_port_ctx_destroy. */
    smap_init(&new_ctx->vif_plug_port_ctx_out.iface_options);

    return new_ctx;
}

static void
destroy_port_ctx(struct vif_plug_port_ctx *ctx)
{
    smap_destroy(&ctx->vif_plug_port_ctx_in.lport_options);
    smap_destroy(&ctx->vif_plug_port_ctx_in.iface_options);
    if (ctx->vif_plug_port_ctx_in.lport_name) {
        free((char *)ctx->vif_plug_port_ctx_in.lport_name);
    }
    if (ctx->vif_plug_port_ctx_in.iface_name) {
        free((char *)ctx->vif_plug_port_ctx_in.iface_name);
    }
    if (ctx->vif_plug_port_ctx_in.iface_type) {
        free((char *)ctx->vif_plug_port_ctx_in.iface_type);
    }
    /* Note that data associated with ctx->vif_plug_port_ctx_out must be
     * destroyed by the plug provider implementation with a call to
     * vif_plug_port_ctx_destroy prior to calling this function */
    free(ctx);
}

/* Our contract with the VIF plug provider is that vif_plug_port_finish
 * will be called with vif_plug_port_ctx_* objects once the transaction
 * commits.  To handle this we keep track of in-flight deletions
 * and changes.  The tracking data will be cleared after commit at the end of
 * the ovn-controller main loop. */
static void
transact_delete_port(const struct vif_plug_ctx_in *vif_plug_ctx_in,
                     const struct vif_plug_ctx_out *vif_plug_ctx_out,
                     const struct vif_plug_port_ctx *vif_plug_port_ctx,
                     const struct ovsrec_port *port)
{
    shash_add(vif_plug_ctx_out->deleted_iface_ids,
              vif_plug_port_ctx->vif_plug_port_ctx_in.lport_name,
              vif_plug_port_ctx);
    ovsport_remove(vif_plug_ctx_in->br_int, port);
}

static void
transact_create_port(const struct vif_plug_ctx_in *vif_plug_ctx_in,
                     const struct vif_plug_ctx_out *vif_plug_ctx_out,
                     const struct vif_plug_port_ctx *vif_plug_port_ctx,
                     const struct smap *iface_external_ids,
                     const int64_t mtu_request)
{
    shash_add(vif_plug_ctx_out->changed_iface_ids,
              vif_plug_port_ctx->vif_plug_port_ctx_in.lport_name,
              vif_plug_port_ctx);
    ovsport_create(vif_plug_ctx_in->ovs_idl_txn, vif_plug_ctx_in->br_int,
                   vif_plug_port_ctx->vif_plug_port_ctx_out.name,
                   vif_plug_port_ctx->vif_plug_port_ctx_out.type,
                   NULL, iface_external_ids,
                   &vif_plug_port_ctx->vif_plug_port_ctx_out.iface_options,
                   mtu_request);
}

static void
transact_update_port(const struct ovsrec_interface *iface_rec,
                     const struct vif_plug_ctx_in *vif_plug_ctx_in OVS_UNUSED,
                     const struct vif_plug_ctx_out *vif_plug_ctx_out,
                     const struct vif_plug_port_ctx *vif_plug_port_ctx,
                     const struct smap *iface_external_ids,
                     const int64_t mtu_request)
{
    shash_add(vif_plug_ctx_out->changed_iface_ids,
              vif_plug_port_ctx->vif_plug_port_ctx_in.lport_name,
              vif_plug_port_ctx);
    ovsport_update_iface(
        iface_rec,
        vif_plug_port_ctx->vif_plug_port_ctx_out.type,
        iface_external_ids,
        NULL,
        &vif_plug_port_ctx->vif_plug_port_ctx_out.iface_options,
        vif_plug_get_maintained_iface_options(
            vif_plug_port_ctx->vif_plug),
        mtu_request);
}


static bool
consider_unplug_iface(const struct ovsrec_interface *iface,
                      const struct sbrec_port_binding *pb,
                      struct vif_plug_ctx_in *vif_plug_ctx_in,
                      struct vif_plug_ctx_out *vif_plug_ctx_out)
{
    const char *vif_plug_type = smap_get(&iface->external_ids,
                                         OVN_PLUGGED_EXT_ID);
    const char *iface_id = smap_get(&iface->external_ids, "iface-id");
    const struct ovsrec_port *port = ovsport_lookup_by_interface(
        vif_plug_ctx_in->ovsrec_port_by_interfaces,
        (struct ovsrec_interface *) iface);

    if (vif_plug_type && iface_id && port) {
        const struct vif_plug_class *vif_plug;
        if (!(vif_plug = vif_plug_provider_get(vif_plug_type))) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl,
                         "Unable to open VIF plug provider for "
                         "%s %s iface-id %s",
                         VIF_PLUG_OPTION_TYPE, vif_plug_type, iface_id);
            /* While we are unable to handle this, asking for a recompute
             * will not change that fact. */
            return true;
        }
        if (!vif_plug_ctx_in->chassis_rec || !vif_plug_ctx_in->br_int
            || !vif_plug_ctx_in->ovs_idl_txn)
        {
            /* Some of our prerequisites are not available, ask for a
             * recompute. */
            return false;
        }

        /* Our contract with the VIF plug provider is that vif_plug_port_finish
         * will be called with a vif_plug_port_ctx_in object once the
         * transaction commits.
         *
         * Since this happens asynchronously we need to allocate memory for
         * and duplicate any database references so that they stay valid.
         *
         * The data is freed with a call to destroy_port_ctx after the
         * transaction completes at the end of the ovn-controller main
         * loop. */
        struct vif_plug_port_ctx *vif_plug_port_ctx = build_port_ctx(
            vif_plug, PLUG_OP_REMOVE, vif_plug_ctx_in, pb, iface, iface_id);

        if (!vif_plug_port_prepare(vif_plug,
                                   &vif_plug_port_ctx->vif_plug_port_ctx_in,
                                   NULL)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(&rl,
                         "Not unplugging iface %s (iface-id %s) on direction "
                         "from VIF plug provider.",
                         iface->name, iface_id);
            destroy_port_ctx(vif_plug_port_ctx);
            return true;
        }
        VLOG_INFO("Unplugging port %s from %s for iface-id %s on this "
                  "chassis.",
                  port->name,
                  vif_plug_ctx_in->br_int->name,
                  iface_id);

        /* Add and track delete operation to the transaction */
        transact_delete_port(vif_plug_ctx_in, vif_plug_ctx_out,
                             vif_plug_port_ctx, port);
        return true;
    }
    return true;
}

static int64_t
get_plug_mtu_request(const struct smap *lport_options)
{
    return smap_get_int(lport_options, VIF_PLUG_OPTION_MTU_REQUEST, 0);
}

static bool
consider_plug_lport_create__(const struct vif_plug_class *vif_plug,
                             const struct smap *iface_external_ids,
                             const struct sbrec_port_binding *pb,
                             struct vif_plug_ctx_in *vif_plug_ctx_in,
                             struct vif_plug_ctx_out *vif_plug_ctx_out)
{
    if (!vif_plug_ctx_in->chassis_rec || !vif_plug_ctx_in->br_int
        || !vif_plug_ctx_in->ovs_idl_txn) {
        /* Some of our prerequisites are not available, ask for a recompute. */
        return false;
    }

    /* Our contract with the VIF plug provider is that vif_plug_port_finish
     * will be called with vif_plug_port_ctx_in and vif_plug_port_ctx_out
     * objects once the transaction commits.
     *
     * Since this happens asynchronously we need to allocate memory for
     * and duplicate any database references so that they stay valid.
     *
     * The data is freed with a call to destroy_port_ctx after the
     * transaction completes at the end of the ovn-controller main
     * loop. */
    struct vif_plug_port_ctx *vif_plug_port_ctx = build_port_ctx(
        vif_plug, PLUG_OP_CREATE, vif_plug_ctx_in, pb, NULL, NULL);

    if (!vif_plug_port_prepare(vif_plug,
                           &vif_plug_port_ctx->vif_plug_port_ctx_in,
                           &vif_plug_port_ctx->vif_plug_port_ctx_out)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_INFO_RL(&rl,
                     "Not plugging lport %s on direction from VIF plug "
                     "provider.",
                     pb->logical_port);
        destroy_port_ctx(vif_plug_port_ctx);
        return true;
    }

    VLOG_INFO("Plugging port %s into %s for lport %s on this "
              "chassis.",
              vif_plug_port_ctx->vif_plug_port_ctx_out.name,
              vif_plug_ctx_in->br_int->name,
              pb->logical_port);
    transact_create_port(vif_plug_ctx_in, vif_plug_ctx_out,
                         vif_plug_port_ctx,
                         iface_external_ids,
                         get_plug_mtu_request(&pb->options));
    return true;
}

static bool
consider_plug_lport_update__(const struct vif_plug_class *vif_plug,
                             const struct smap *iface_external_ids,
                             const struct sbrec_port_binding *pb,
                             struct local_binding *lbinding,
                             struct vif_plug_ctx_in *vif_plug_ctx_in,
                             struct vif_plug_ctx_out *vif_plug_ctx_out)
{
    if (!vif_plug_ctx_in->chassis_rec || !vif_plug_ctx_in->br_int
        || !vif_plug_ctx_in->ovs_idl_txn) {
        /* Some of our prerequisites are not available, ask for a recompute. */
        return false;
    }
    /* Our contract with the VIF plug provider is that vif_plug_port_finish
     * will be called with vif_plug_port_ctx_in and vif_plug_port_ctx_out
     * objects once the transaction commits.
     *
     * Since this happens asynchronously we need to allocate memory for
     * and duplicate any database references so that they stay valid.
     *
     * The data is freed with a call to destroy_port_ctx after the
     * transaction completes at the end of the ovn-controller main
     * loop. */
    struct vif_plug_port_ctx *vif_plug_port_ctx = build_port_ctx(
        vif_plug, PLUG_OP_CREATE, vif_plug_ctx_in, pb, NULL, NULL);

    if (!vif_plug_port_prepare(vif_plug,
                               &vif_plug_port_ctx->vif_plug_port_ctx_in,
                               &vif_plug_port_ctx->vif_plug_port_ctx_out)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_INFO_RL(&rl,
                     "Not updating lport %s on direction from VIF plug "
                     "provider.",
                     pb->logical_port);
        destroy_port_ctx(vif_plug_port_ctx);
        return true;
    }

    if (strcmp(lbinding->iface->name,
               vif_plug_port_ctx->vif_plug_port_ctx_out.name)) {
        VLOG_WARN("Attempt of incompatible change to existing "
                  "port detected, please recreate port: %s",
                   pb->logical_port);
        vif_plug_port_ctx_destroy(vif_plug,
                                  &vif_plug_port_ctx->vif_plug_port_ctx_in,
                                  &vif_plug_port_ctx->vif_plug_port_ctx_out);
        destroy_port_ctx(vif_plug_port_ctx);
        return false;
    }
    VLOG_DBG("updating iface for: %s", pb->logical_port);
    transact_update_port(lbinding->iface, vif_plug_ctx_in, vif_plug_ctx_out,
                         vif_plug_port_ctx, iface_external_ids,
                         get_plug_mtu_request(&pb->options));

    return true;
}

static bool
consider_plug_lport(const struct sbrec_port_binding *pb,
                    struct local_binding *lbinding,
                    struct vif_plug_ctx_in *vif_plug_ctx_in,
                    struct vif_plug_ctx_out *vif_plug_ctx_out)
{
    bool ret = true;
    if (lport_can_bind_on_this_chassis(vif_plug_ctx_in->chassis_rec, pb)
        && pb->requested_chassis == vif_plug_ctx_in->chassis_rec) {
        const char *vif_plug_type = smap_get(&pb->options,
                                             VIF_PLUG_OPTION_TYPE);
        if (!vif_plug_type) {
            /* Nothing for us to do and we don't need a recompute. */
            return true;
        }

        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        const struct vif_plug_class *vif_plug;
        if (!(vif_plug = vif_plug_provider_get(vif_plug_type))) {
            VLOG_WARN_RL(&rl,
                         "Unable to open VIF plug provider for %s: '%s' "
                         "lport %s",
                         VIF_PLUG_OPTION_TYPE,
                         vif_plug_type,
                         pb->logical_port);
            /* While we are unable to handle this, asking for a recompute will
             * not change that fact. */
            return true;
        }
        const struct smap iface_external_ids = SMAP_CONST2(
                &iface_external_ids,
                OVN_PLUGGED_EXT_ID, vif_plug_type,
                "iface-id", pb->logical_port);
        if (lbinding && lbinding->iface) {
            if (!smap_get(&lbinding->iface->external_ids,
                          OVN_PLUGGED_EXT_ID))
            {
                VLOG_WARN_RL(&rl,
                             "CMS requested plugging of lport %s, but a port "
                             "that is not maintained by OVN already exsist "
                             "in local vSwitch: "UUID_FMT,
                             pb->logical_port,
                             UUID_ARGS(&lbinding->iface->header_.uuid));
                return false;
            }
            ret = consider_plug_lport_update__(vif_plug, &iface_external_ids,
                                               pb, lbinding, vif_plug_ctx_in,
                                               vif_plug_ctx_out);
        } else {
            ret = consider_plug_lport_create__(vif_plug, &iface_external_ids,
                                               pb, vif_plug_ctx_in,
                                               vif_plug_ctx_out);
        }
    }

    return ret;
}

static bool
vif_plug_iface_touched_this_txn(
        const struct vif_plug_ctx_out *vif_plug_ctx_out,
        const char *iface_id)
{
    return shash_find(vif_plug_ctx_out->changed_iface_ids, iface_id)
           || shash_find(vif_plug_ctx_out->deleted_iface_ids, iface_id);
}

static bool
vif_plug_handle_lport_vif(const struct sbrec_port_binding *pb,
                          struct vif_plug_ctx_in *vif_plug_ctx_in,
                          struct vif_plug_ctx_out *vif_plug_ctx_out,
                          bool can_unplug)
{
    if (vif_plug_iface_touched_this_txn(vif_plug_ctx_out, pb->logical_port)) {
        return true;
    }
    bool handled = true;
    struct local_binding *lbinding = local_binding_find(
        vif_plug_ctx_in->local_bindings, pb->logical_port);

    if (lport_can_bind_on_this_chassis(vif_plug_ctx_in->chassis_rec, pb)) {
        handled &= consider_plug_lport(pb, lbinding,
                                       vif_plug_ctx_in, vif_plug_ctx_out);
    } else if (can_unplug && lbinding && lbinding->iface) {
        handled &= consider_unplug_iface(lbinding->iface, pb,
                                         vif_plug_ctx_in, vif_plug_ctx_out);
    }
    return handled;
}

static bool
vif_plug_handle_iface(const struct ovsrec_interface *iface_rec,
                      struct vif_plug_ctx_in *vif_plug_ctx_in,
                      struct vif_plug_ctx_out *vif_plug_ctx_out,
                      bool can_unplug)
{
    bool handled = true;
    const char *vif_plug_type = smap_get(&iface_rec->external_ids,
                                         OVN_PLUGGED_EXT_ID);
    const char *iface_id = smap_get(&iface_rec->external_ids, "iface-id");
    if (!vif_plug_type || !iface_id
        || vif_plug_iface_touched_this_txn(vif_plug_ctx_out, iface_id)) {
        return true;
    }
    struct local_binding *lbinding = local_binding_find(
        vif_plug_ctx_in->local_bindings, iface_id);
    const struct sbrec_port_binding *pb = lport_lookup_by_name(
        vif_plug_ctx_in->sbrec_port_binding_by_name, iface_id);
    if (pb && lbinding
        && lport_can_bind_on_this_chassis(vif_plug_ctx_in->chassis_rec, pb)) {
        /* Something changed on a interface we have previously plugged,
         * consider updating it */
        handled &= consider_plug_lport(pb, lbinding,
                                       vif_plug_ctx_in, vif_plug_ctx_out);
    } else if (can_unplug
               && (!pb
                   || !lport_can_bind_on_this_chassis(
                       vif_plug_ctx_in->chassis_rec, pb))) {
        /* No lport for this interface or it is destined for different chassis,
         * consuder unplugging it */
        handled &= consider_unplug_iface(iface_rec, pb,
                                         vif_plug_ctx_in, vif_plug_ctx_out);
    }
    return handled;
}

/* On initial startup or on IDL reconnect, several rounds of the main loop may
 * run before data is actually loaded in the IDL, primarily depending on
 * conditional monitoring status and other events that could trigger main loop
 * runs during this period.  Until we find a reliable way to determine the
 * completeness of the initial data downloading we need this counter so that we
 * do not erronously unplug ports because the data is just not loaded yet.
 */
void
vif_plug_run(struct vif_plug_ctx_in *vif_plug_ctx_in,
             struct vif_plug_ctx_out *vif_plug_ctx_out)
{
    bool delay_plug = daemon_started_recently();
    if (delay_plug) {
        VLOG_DBG("vif_plug_run: daemon started recently, will not unplug "
                 "ports in this iteration.");
    }

    if (!vif_plug_ctx_in->chassis_rec) {
        return;
    }
    const struct ovsrec_interface *iface_rec;
    OVSREC_INTERFACE_TABLE_FOR_EACH (iface_rec,
                                     vif_plug_ctx_in->iface_table) {
        vif_plug_handle_iface(iface_rec, vif_plug_ctx_in, vif_plug_ctx_out,
                              !delay_plug);
    }

    struct sbrec_port_binding *target =
        sbrec_port_binding_index_init_row(
            vif_plug_ctx_in->sbrec_port_binding_by_requested_chassis);
    sbrec_port_binding_index_set_requested_chassis(
        target,
        vif_plug_ctx_in->chassis_rec);
    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_FOR_EACH_EQUAL (
            pb, target,
            vif_plug_ctx_in->sbrec_port_binding_by_requested_chassis) {
        enum en_lport_type lport_type = get_lport_type(pb);
        if (lport_type == LP_VIF) {
            vif_plug_handle_lport_vif(pb, vif_plug_ctx_in, vif_plug_ctx_out,
                                      !delay_plug);
        }
    }
    sbrec_port_binding_index_destroy_row(target);
}

static void
vif_plug_finish_deleted__(struct shash *deleted_iface_ids, bool txn_success)
{
    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, deleted_iface_ids) {
        struct vif_plug_port_ctx *vif_plug_port_ctx = node->data;
        if (txn_success) {
            vif_plug_port_finish(vif_plug_port_ctx->vif_plug,
                             &vif_plug_port_ctx->vif_plug_port_ctx_in,
                             NULL);
        }
        shash_delete(deleted_iface_ids, node);
        destroy_port_ctx(vif_plug_port_ctx);
    }
}

void
vif_plug_clear_deleted(struct shash *deleted_iface_ids) {
    vif_plug_finish_deleted__(deleted_iface_ids, false);
}

void
vif_plug_finish_deleted(struct shash *deleted_iface_ids) {
    vif_plug_finish_deleted__(deleted_iface_ids, true);
}

static void
vif_plug_finish_changed__(struct shash *changed_iface_ids, bool txn_success)
{
    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, changed_iface_ids) {
        struct vif_plug_port_ctx *vif_plug_port_ctx = node->data;
        if (txn_success) {
            vif_plug_port_finish(vif_plug_port_ctx->vif_plug,
                                 &vif_plug_port_ctx->vif_plug_port_ctx_in,
                                 &vif_plug_port_ctx->vif_plug_port_ctx_out);
        }
        vif_plug_port_ctx_destroy(vif_plug_port_ctx->vif_plug,
                                  &vif_plug_port_ctx->vif_plug_port_ctx_in,
                                  &vif_plug_port_ctx->vif_plug_port_ctx_out);
        shash_delete(changed_iface_ids, node);
        destroy_port_ctx(vif_plug_port_ctx);
    }
}

void
vif_plug_clear_changed(struct shash *deleted_iface_ids) {
    vif_plug_finish_changed__(deleted_iface_ids, false);
}

void
vif_plug_finish_changed(struct shash *deleted_iface_ids) {
    vif_plug_finish_changed__(deleted_iface_ids, true);
}
