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

#ifndef VIF_PLUG_H
#define VIF_PLUG_H 1

/*
 * VIF Plug, the controller internal interface to the VIF plug provider
 * infrastructure.
 */

#include "openvswitch/shash.h"
#include "smap.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct vif_plug_ctx_in {
    struct ovsdb_idl_txn *ovs_idl_txn;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    struct ovsdb_idl_index *sbrec_port_binding_by_requested_chassis;
    struct ovsdb_idl_index *ovsrec_port_by_interfaces;
    const struct ovsrec_open_vswitch_table *ovs_table;
    const struct ovsrec_bridge *br_int;
    const struct ovsrec_interface_table *iface_table;
    const struct sbrec_chassis *chassis_rec;
    const struct shash *local_bindings;
};

struct vif_plug_ctx_out {
    struct shash *deleted_iface_ids;
    struct shash *changed_iface_ids;
};

struct vif_plug_class;
struct vif_plug_port_ctx_out;
struct vif_plug_port_ctx_in;

const struct sset * vif_plug_get_maintained_iface_options(
    const struct vif_plug_class *);

bool vif_plug_port_prepare(const struct vif_plug_class *,
                           const struct vif_plug_port_ctx_in *,
                           struct vif_plug_port_ctx_out *);
void vif_plug_port_finish(const struct vif_plug_class *,
                          const struct vif_plug_port_ctx_in *,
                          struct vif_plug_port_ctx_out *);
void vif_plug_port_ctx_destroy(const struct vif_plug_class *,
                           const struct vif_plug_port_ctx_in *,
                           struct vif_plug_port_ctx_out *);

struct ovsdb_idl;

void vif_plug_register_ovs_idl(struct ovsdb_idl *ovs_idl);
void vif_plug_run(struct vif_plug_ctx_in *, struct vif_plug_ctx_out *);
void vif_plug_clear_changed(struct shash *deleted_iface_ids);
void vif_plug_finish_changed(struct shash *changed_iface_ids);
void vif_plug_clear_deleted(struct shash *deleted_iface_ids);
void vif_plug_finish_deleted(struct shash *changed_iface_ids);
void vif_plug_reset_idl_prime_counter(void);

#ifdef  __cplusplus
}
#endif

#endif /* vif-plug.h */
