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
#include "vif-plug-provider.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "openvswitch/vlog.h"
#include "openvswitch/shash.h"
#include "smap.h"
#include "sset.h"
#include "lib/inc-proc-eng.h"

VLOG_DEFINE_THIS_MODULE(vif_plug_provider);

#ifdef ENABLE_VIF_PLUG
static const struct vif_plug_class *base_vif_plug_classes[] = {
};
#endif

static struct shash vif_plug_classes = SHASH_INITIALIZER(&vif_plug_classes);

/* Protects the 'vif_plug_classes' shash. */
static struct ovs_mutex vif_plug_classes_mutex = OVS_MUTEX_INITIALIZER;

/* Initialize the the VIF plug infrastructure by registering known classes */
void
vif_plug_provider_initialize(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
#ifdef ENABLE_VIF_PLUG
        /* Register built-in VIF plug provider classes */
        for (int i = 0; i < ARRAY_SIZE(base_vif_plug_classes); i++) {
            vif_plug_provider_register(base_vif_plug_classes[i]);
        }
#endif
#ifdef HAVE_VIF_PLUG_PROVIDER
        /* Register external VIF plug provider classes.
         *
         * Note that we cannot use the ARRAY_SIZE macro here as
         * vif_plug_provider_classes is defined in external code which is not
         * available at compile time.  The convention is to use a
         * NULL-terminated array instead. */
        for (const struct vif_plug_class **pp = vif_plug_provider_classes;
             pp && *pp;
             pp++)
        {
            vif_plug_provider_register(*pp);
        }
#endif
        ovsthread_once_done(&once);
    }
}

static int
vif_plug_provider_register__(const struct vif_plug_class *new_class)
{
    struct vif_plug_class *vif_plug_class;
    int error;

    if (shash_find(&vif_plug_classes, new_class->type)) {
        VLOG_WARN("attempted to register duplicate VIF plug provider: %s",
                  new_class->type);
        return EEXIST;
    }

    error = new_class->init ? new_class->init() : 0;
    if (error) {
        VLOG_WARN("failed to initialize %s VIF plug provider class: %s",
                  new_class->type, ovs_strerror(error));
        return error;
    }

    vif_plug_class = xmalloc(sizeof *vif_plug_class);
    memcpy(vif_plug_class, new_class, sizeof *vif_plug_class);

    shash_add(&vif_plug_classes, new_class->type, vif_plug_class);

    return 0;
}

/* Register the new VIF plug provider referred to in 'new_class' and perform
 * any class level initialization as specified in its vif_plug_class. */
int
vif_plug_provider_register(const struct vif_plug_class *new_class)
{
    int error;

    ovs_mutex_lock(&vif_plug_classes_mutex);
    error = vif_plug_provider_register__(new_class);
    ovs_mutex_unlock(&vif_plug_classes_mutex);

    return error;
}

static int
vif_plug_provider_unregister__(const char *type)
{
    int error;
    struct shash_node *node;
    struct vif_plug_class *vif_plug_class;

    node = shash_find(&vif_plug_classes, type);
    if (!node) {
        return EINVAL;
    }

    vif_plug_class = node->data;
    error = vif_plug_class->destroy ? vif_plug_class->destroy() : 0;
    if (error) {
        VLOG_WARN("failed to destroy %s VIF plug class: %s",
                  vif_plug_class->type, ovs_strerror(error));
        return error;
    }

    shash_delete(&vif_plug_classes, node);
    free(vif_plug_class);

    return 0;
}

/* Unregister the VIF plug provider identified by 'type' and perform any class
 * level de-initialization as specified in its vif_plug_class. */
int
vif_plug_provider_unregister(const char *type)
{
    int error;

    ovs_mutex_lock(&vif_plug_classes_mutex);
    error = vif_plug_provider_unregister__(type);
    ovs_mutex_unlock(&vif_plug_classes_mutex);

    return error;
}

/* Check whether there are any VIF plug providers registered */
bool
vif_plug_provider_has_providers(void)
{
    return !shash_is_empty(&vif_plug_classes);
}

const struct vif_plug_class *
vif_plug_provider_get(const char *type)
{
    struct vif_plug_class *vif_plug_class;

    ovs_mutex_lock(&vif_plug_classes_mutex);
    vif_plug_class = shash_find_data(&vif_plug_classes, type);
    ovs_mutex_unlock(&vif_plug_classes_mutex);

    return vif_plug_class;
}

/* Iterate over VIF plug providers and call their run function.
 *
 * Returns 'true' if any of the providers run functions return 'true', 'false'
 * otherwise.
 *
 * A return value of 'true' means that data has changed. */
bool
vif_plug_provider_run_all(void)
{
    struct shash_node *node, *next;
    bool changed = false;

    SHASH_FOR_EACH_SAFE (node, next, &vif_plug_classes) {
        struct vif_plug_class *vif_plug_class = node->data;
        if (vif_plug_class->run && vif_plug_class->run(vif_plug_class)) {
            changed = true;
        }
    }
    return changed;
}

/* De-initialize and unregister the VIF plug provider classes. */
void
vif_plug_provider_destroy_all(void)
{
    struct shash_node *node, *next;

    SHASH_FOR_EACH_SAFE (node, next, &vif_plug_classes) {
        struct vif_plug_class *vif_plug_class = node->data;
        vif_plug_provider_unregister(vif_plug_class->type);
    }
}
