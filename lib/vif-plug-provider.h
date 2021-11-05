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

#ifndef VIF_PLUG_PROVIDER_H
#define VIF_PLUG_PROVIDER_H 1

/* Interface for VIF plug providers.
 *
 * A VIF plug provider implementation performs lookup and/or initialization of
 * ports, typically representor ports, using generic non-blocking hardware
 * interfaces.  This allows the ovn-controller to, upon the CMS's request,
 * create ports and interfaces in the chassis's Open vSwitch instances (also
 * known as vif plugging).
 *
 * This module contains the infrastructure for registering VIF plug providers
 * which may be hosted inside or outside the core OVN repository.
 */

#include <stdbool.h>

#include "smap.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vif_plug_class;
struct ovsdb_idl_txn;
struct ovsrec_bridge;

enum vif_plug_op_type {
    PLUG_OP_CREATE = 1, /* Port is created or updated */
    PLUG_OP_REMOVE,     /* Port is removed from this chassis */
};

struct vif_plug_port_ctx_in {
    /* Operation being performed */
    enum vif_plug_op_type op_type;

    /* These are provided so that the plug implementation may make decisions
     * based on environmental factors such as settings in the open-vswitch
     * table and datapath type settings on the integration bridge. */
    const struct ovsrec_open_vswitch_table *ovs_table;
    const struct ovsrec_bridge *br_int;

    /* Name of logical port, can be useful for plugging library to track any
     * per port resource initialization. */
    const char *lport_name;

    /* Logical port options, while OVN will forward the contents verbatim from
     * the Southbound database, the convention is for the plugging library to
     * only make decisions based on the vif-plug-* options. */
    struct smap lport_options;

    /* When OVN knows about an existing interface record associated with this
     * lport, these will be filled in with information about it. */
    const char *iface_name;
    const char *iface_type;
    struct smap iface_options;
};

struct vif_plug_port_ctx_out {
    /* The name to use for port and interface record. */
    char *name;

    /* Type of interface to create. */
    char *type;

    /* Options to set on the interface record. */
    struct smap iface_options;
};

struct vif_plug_port_ctx {
    const struct vif_plug_class *vif_plug;
    struct vif_plug_port_ctx_in vif_plug_port_ctx_in;
    struct vif_plug_port_ctx_out vif_plug_port_ctx_out;
};

struct vif_plug_class {
    /* Type of VIF plug provider in this class. */
    const char *type;

    /* Called when the VIF plug provider is registered, typically at program
     * startup.
     *
     * This function may be set to null if a VIF plug class needs no
     * initialization at registration time. */
    int (*init)(void);

    /* Called when the VIF plug provider is unregistered, typically at program
     * exit.
     *
     * This function may be set to null if a plug class needs no
     * de-initialization at unregister time.*/
    int (*destroy)(void);

    /* Performs periodic work needed by VIF plug provider, if any is necessary.
     * Returns 'true; if anything (i.e. lookup tables) changed, 'false'
     * otherwise. */
    bool (*run)(struct vif_plug_class *);

    /* Retrieve Interface options this VIF plug provider will maintain.  This
     * sset is used to know which items to remove when maintaining the database
     * record. */
    const struct sset * (*vif_plug_get_maintained_iface_options)(void);

    /* Pass vif_plug_port_ctx_in to VIF plug provider implementation to prepare
     * for port creation/update.
     *
     * The VIF plug provider implemantation can perform lookup or any per port
     * initialization and should fill vif_plug_port_ctx_out with data required
     * for port/interface creation.  The VIF plug implementation should return
     * 'true' if it wants the caller to create/update a port/interface, 'false'
     * otherwise.
     *
     * Data in the vif_plug_port_ctx_out struct is owned by the VIF plug
     * provider, and a call must be made to the vif_plug_port_ctx_destroy
     * callback to free up any allocations when done with port creation/update.
     */
    bool (*vif_plug_port_prepare)(const struct vif_plug_port_ctx_in *,
                                  struct vif_plug_port_ctx_out *);

    /* Notify VIF plug provider that port update is committed to OVSDB. */
    void (*vif_plug_port_finish)(const struct vif_plug_port_ctx_in *,
                                 struct vif_plug_port_ctx_out *);

    /* Free any allocations made by the vif_plug_port_prepare callback. */
    void (*vif_plug_port_ctx_destroy)(const struct vif_plug_port_ctx_in *,
                                      struct vif_plug_port_ctx_out *);
};

extern const struct vif_plug_class vif_plug_dummy_class;
#ifdef HAVE_VIF_PLUG_PROVIDER
extern const struct vif_plug_class *vif_plug_provider_classes[];
#endif

void vif_plug_provider_initialize(void);
int vif_plug_provider_register(const struct vif_plug_class *);
int vif_plug_provider_unregister(const char *type);
bool vif_plug_provider_has_providers(void);
const struct vif_plug_class * vif_plug_provider_get(const char *);
bool vif_plug_provider_run_all(void);
void vif_plug_provider_destroy_all(void);
void vif_plug_dummy_enable(void);

#ifdef  __cplusplus
}
#endif

#endif /* vif-plug-provider.h */
