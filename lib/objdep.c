/* Copyright (c) 2015, 2016, 2017 Nicira, Inc.
 * Copyright (c) 2022, Red Hat, Inc.
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

#include "lib/objdep.h"
#include "lib/hash.h"
#include "lib/util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(resource_dep);

static void resource_node_destroy(struct resource_to_objects_node *);

void
objdep_mgr_init(struct objdep_mgr *mgr)
{
    hmap_init(&mgr->resource_to_objects_table);
    hmap_init(&mgr->object_to_resources_table);
}

void
objdep_mgr_destroy(struct objdep_mgr *mgr)
{
    objdep_mgr_clear(mgr);

    hmap_destroy(&mgr->resource_to_objects_table);
    hmap_destroy(&mgr->object_to_resources_table);
}

void
objdep_mgr_clear(struct objdep_mgr *mgr)
{
    struct resource_to_objects_node *resource_node;
    HMAP_FOR_EACH_SAFE (resource_node, node, &mgr->resource_to_objects_table) {
        struct object_to_resources_list_node *object_list_node;
        HMAP_FOR_EACH_SAFE (object_list_node, hmap_node,
                            &resource_node->objs) {
            ovs_list_remove(&object_list_node->list_node);
            hmap_remove(&resource_node->objs, &object_list_node->hmap_node);
            free(object_list_node);
        }
        hmap_remove(&mgr->resource_to_objects_table, &resource_node->node);
        resource_node_destroy(resource_node);
    }

    struct object_to_resources_node *object_node;
    HMAP_FOR_EACH_SAFE (object_node, node, &mgr->object_to_resources_table) {
        hmap_remove(&mgr->object_to_resources_table, &object_node->node);
        free(object_node);
    }
}

void
objdep_mgr_add(struct objdep_mgr *mgr, enum objdep_type type,
               const char *res_name, const struct uuid *obj_uuid)
{
    objdep_mgr_add_with_refcount(mgr, type, res_name, obj_uuid, 0);
}

void
objdep_mgr_add_with_refcount(struct objdep_mgr *mgr, enum objdep_type type,
                             const char *res_name, const struct uuid *obj_uuid,
                             size_t ref_count)
{
    struct resource_to_objects_node *resource_node =
        objdep_mgr_find_objs(mgr, type, res_name);
    struct object_to_resources_node *object_node =
        objdep_mgr_find_resources(mgr, obj_uuid);
    if (resource_node && object_node) {
        /* Check if the mapping already existed before adding a new one. */
        struct object_to_resources_list_node *n;
        HMAP_FOR_EACH_WITH_HASH (n, hmap_node, uuid_hash(obj_uuid),
                                 &resource_node->objs) {
            if (uuid_equals(&n->obj_uuid, obj_uuid)) {
                return;
            }
        }
    }

    /* Create the resource node if we didn't have one already (for a
     * different object). */
    if (!resource_node) {
        resource_node = xzalloc(sizeof *resource_node);
        resource_node->node.hash = hash_string(res_name, type);
        resource_node->type = type;
        resource_node->res_name = xstrdup(res_name);
        hmap_init(&resource_node->objs);
        hmap_insert(&mgr->resource_to_objects_table,
                    &resource_node->node,
                    resource_node->node.hash);
    }

    /* Create the object node if we didn't have one already (for a
     * different resource). */
    if (!object_node) {
        object_node = xzalloc(sizeof *object_node);
        object_node->node.hash = uuid_hash(obj_uuid);
        object_node->obj_uuid = *obj_uuid;
        ovs_list_init(&object_node->resources_head);
        hmap_insert(&mgr->object_to_resources_table,
                    &object_node->node,
                    object_node->node.hash);
    }

    struct object_to_resources_list_node *resource_list_node =
        xzalloc(sizeof *resource_list_node);
    resource_list_node->obj_uuid = *obj_uuid;
    resource_list_node->ref_count = ref_count;
    resource_list_node->resource_node = resource_node;
    hmap_insert(&resource_node->objs, &resource_list_node->hmap_node,
                uuid_hash(obj_uuid));
    ovs_list_push_back(&object_node->resources_head,
                       &resource_list_node->list_node);
}

void
objdep_mgr_remove_obj(struct objdep_mgr *mgr, const struct uuid *obj_uuid)
{
    struct object_to_resources_node *object_node =
        objdep_mgr_find_resources(mgr, obj_uuid);
    if (!object_node) {
        return;
    }

    hmap_remove(&mgr->object_to_resources_table, &object_node->node);

    struct object_to_resources_list_node *resource_list_node;
    LIST_FOR_EACH_SAFE (resource_list_node, list_node,
                        &object_node->resources_head) {
        struct resource_to_objects_node *resource_node =
            resource_list_node->resource_node;
        ovs_list_remove(&resource_list_node->list_node);
        hmap_remove(&resource_node->objs, &resource_list_node->hmap_node);

        /* Clean up the node in ref_obj_table if the resource is not
         * referred by any logical flows. */
        if (hmap_is_empty(&resource_node->objs)) {
            hmap_remove(&mgr->resource_to_objects_table, &resource_node->node);
            resource_node_destroy(resource_list_node->resource_node);
        }

        free(resource_list_node);
    }
    free(object_node);
}

struct resource_to_objects_node *
objdep_mgr_find_objs(struct objdep_mgr *mgr, enum objdep_type type,
                     const char *res_name)
{
    struct resource_to_objects_node *resource_node;

    HMAP_FOR_EACH_WITH_HASH (resource_node, node, hash_string(res_name, type),
                             &mgr->resource_to_objects_table) {
        if (resource_node->type == type &&
                !strcmp(resource_node->res_name, res_name)) {
            return resource_node;
        }
    }
    return NULL;
}

struct object_to_resources_node *
objdep_mgr_find_resources(struct objdep_mgr *mgr,
                          const struct uuid *obj_uuid)
{
    struct object_to_resources_node *object_node;

    HMAP_FOR_EACH_WITH_HASH (object_node, node, uuid_hash(obj_uuid),
                             &mgr->object_to_resources_table) {
        if (uuid_equals(&object_node->obj_uuid, obj_uuid)) {
            return object_node;
        }
    }
    return NULL;
}

bool
objdep_mgr_contains_obj(struct objdep_mgr *mgr, const struct uuid *obj_uuid)
{
    return !!objdep_mgr_find_resources(mgr, obj_uuid);
}

bool
objdep_mgr_handle_change(struct objdep_mgr *mgr,
                         enum objdep_type type,
                         const char *res_name,
                         objdep_change_handler handler,
                         struct uuidset *objs_processed,
                         const void *in_arg, void *out_arg,
                         bool *changed)
{
    struct resource_to_objects_node *resource_node =
        objdep_mgr_find_objs(mgr, type, res_name);
    if (!resource_node) {
        *changed = false;
        return true;
    }
    VLOG_DBG("Handle changed object reference for resource type: %s,"
             " name: %s.", objdep_type_name(type), res_name);
    *changed = false;

    struct ovs_list objs_todo = OVS_LIST_INITIALIZER(&objs_todo);

    struct object_to_resources_list_node *resource_list_node;
    HMAP_FOR_EACH (resource_list_node, hmap_node, &resource_node->objs) {
        if (uuidset_find(objs_processed, &resource_list_node->obj_uuid)) {
            continue;
        }
        /* Use object_to_resources_list_node as list node to store the uuid.
         * Other fields are not used here. */
        struct object_to_resources_list_node *resource_list_node_uuid =
            xmalloc(sizeof *resource_list_node_uuid);
        resource_list_node_uuid->obj_uuid = resource_list_node->obj_uuid;
        ovs_list_push_back(&objs_todo, &resource_list_node_uuid->list_node);
    }
    if (ovs_list_is_empty(&objs_todo)) {
        return true;
    }
    *changed = true;

    /* This takes ownership of objs_todo. */
    return handler(type, res_name, &objs_todo, in_arg, out_arg);
}

const char *
objdep_type_name(enum objdep_type type)
{
    static const char *type_names[OBJDEP_TYPE_MAX] = {
        [OBJDEP_TYPE_ADDRSET] = "Address_Set",
        [OBJDEP_TYPE_PORTGROUP] = "Port_Group",
        [OBJDEP_TYPE_PORTBINDING] = "Port_Binding",
        [OBJDEP_TYPE_MC_GROUP] = "Multicast_Group",
        [OBJDEP_TYPE_TEMPLATE] = "Template",
    };

    ovs_assert(type < OBJDEP_TYPE_MAX);
    return type_names[type];
}

static void
resource_node_destroy(struct resource_to_objects_node *resource_node)
{
    free(resource_node->res_name);
    hmap_destroy(&resource_node->objs);
    free(resource_node);
}
