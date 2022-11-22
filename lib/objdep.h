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

#ifndef OVN_OBJDEP_H
#define OVN_OBJDEP_H 1

#include "lib/uuidset.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"

enum objdep_type {
    OBJDEP_TYPE_ADDRSET,
    OBJDEP_TYPE_PORTGROUP,
    OBJDEP_TYPE_PORTBINDING,
    OBJDEP_TYPE_MC_GROUP,
    OBJDEP_TYPE_TEMPLATE,
    OBJDEP_TYPE_MAX,
};

/* Callbacks provided by users to process changes to resources referred by
 * various objects.  They should return true if the change has been
 * handled successfully. */
typedef bool (*objdep_change_handler)(enum objdep_type,
                                      const char *res_name,
                                      struct ovs_list *ref_nodes,
                                      const void *in_arg, void *out_arg);

/* A node pointing to all objects that refer to a given resource. */
struct resource_to_objects_node {
    struct hmap_node node; /* node in objdep_mgr.resource_to_objects_table. */
    enum objdep_type type; /* key */
    char *res_name;        /* key */
    struct hmap objs;      /* Contains object_to_resources_list_node.
                            * Use hmap instead of list so
                            * that obj_resource_add() can check and avoid
                            * and redundant entries in O(1). */
};

#define RESOURCE_FOR_EACH_OBJ(NODE, MAP) \
    HMAP_FOR_EACH (NODE, hmap_node, &(MAP)->objs)

/* A node pointing to all resources used by a given object (specified by
 * uuid).
 */
struct object_to_resources_node {
    struct hmap_node node; /* node in objdep_mgr.object_to_resources_table. */
    struct uuid obj_uuid;  /* key */
    struct ovs_list resources_head; /* Contains elements of type
                                     * object_to_resources_list_node. */
};

/* Maintains the relationship for a pair of named resource and
 * an object, indexed by both resource_to_object_table and
 * object_to_resources_table. */
struct object_to_resources_list_node {
    /* node in object_to_resources_node.resources_head. */
    struct ovs_list list_node;
    struct hmap_node hmap_node; /* node in resource_to_objects_node.objs. */
    struct uuid obj_uuid;
    size_t ref_count; /* Reference count of the resource by this object.
                       * Currently only used for the resource type
                       * OBJDEP_TYPE_ADDRSET and for other types always
                       * set to 0. */
    struct resource_to_objects_node *resource_node;
};

struct objdep_mgr {
    /* A map from a referenced resource type & name (e.g. address_set AS1)
     * to a list of object UUIDs (e.g., lflow) that are referencing the named
     * resource. Data type of each node in this hmap is struct
     * resource_to_objects_node.  The objs in each node point
     * to a map of object_to_resources_list_node.ref_list. */
    struct hmap resource_to_objects_table;

    /* A map from a obj uuid to a list of named resources that are
     * referenced by the object. Data type of each node in this hmap is
     * struct object_to_resources_node. The resources_head in each node
     * points to a list of object_to_resources_list_node.obj_list. */
    struct hmap object_to_resources_table;
};

void objdep_mgr_init(struct objdep_mgr *);
void objdep_mgr_destroy(struct objdep_mgr *);
void objdep_mgr_clear(struct objdep_mgr *);

void objdep_mgr_add(struct objdep_mgr *, enum objdep_type,
                    const char *res_name, const struct uuid *);
void objdep_mgr_add_with_refcount(struct objdep_mgr *,
                                  enum objdep_type,
                                  const char *res_name,
                                  const struct uuid *,
                                  size_t ref_count);
void objdep_mgr_remove_obj(struct objdep_mgr *, const struct uuid *);

struct resource_to_objects_node *objdep_mgr_find_objs(
    struct objdep_mgr *, enum objdep_type, const char *res_name);
struct object_to_resources_node *objdep_mgr_find_resources(
    struct objdep_mgr *, const struct uuid *);
bool objdep_mgr_contains_obj(struct objdep_mgr *, const struct uuid *);

bool objdep_mgr_handle_change(struct objdep_mgr *, enum objdep_type,
                              const char *res_name,
                              objdep_change_handler handler,
                              struct uuidset *objs_processed,
                              const void *in_arg, void *out_arg,
                              bool *changed);

const char *objdep_type_name(enum objdep_type);

#endif /* lib/objdep.h */
