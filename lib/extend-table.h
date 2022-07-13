
/*
 * Copyright (c) 2017 DtDream Technology Co.,Ltd.
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

#ifndef EXTEND_TABLE_H
#define EXTEND_TABLE_H 1

#define MAX_EXT_TABLE_ID 65535
#define EXT_TABLE_ID_INVALID 0

#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/uuid.h"

/* Used to manage expansion tables associated with Flow table,
 * such as the Group Table or Meter Table. */
struct ovn_extend_table {
    unsigned long *table_ids;   /* Used as a bitmap with value set for
                                 * allocated group ids in either desired or
                                 * existing. */
    struct hmap desired;
    struct hmap lflow_to_desired;       /* Index for looking up desired table
                                         * items from given lflow uuid, with
                                         * ovn_extend_table_lflow_to_desired
                                         * nodes. */
    struct hmap existing;
};

struct ovn_extend_table_lflow_to_desired {
    struct hmap_node hmap_node; /* In ovn_extend_table.lflow_to_desired. */
    struct uuid lflow_uuid;
    struct ovs_list desired;    /* List of desired items used by the lflow. */
};

struct ovn_extend_table_info {
    struct hmap_node hmap_node;
    char *name;                 /* Name for the table entity. */
    uint32_t table_id;
    bool new_table_id;          /* 'True' if 'table_id' was reserved from
                                 * ovn_extend_table's 'table_ids' bitmap. */
    struct hmap references;     /* The lflows that are using this item, with
                                 * ovn_extend_table_lflow_ref nodes. Only
                                 * useful for items in
                                 * ovn_extend_table.desired. */
};

/* Maintains the link between a lflow and an ovn_extend_table_info item in
 * ovn_extend_table.desired, indexed by both
 * ovn_extend_table_lflow_to_desired.desired and
 * ovn_extend_table_info.references.
 *
 * The struct is allocated whenever a new reference happens.
 * It destroyed when a lflow is deleted (for all the desired table_info
 * used by it), or when the lflow_to_desired table is being cleared.
 * */
struct ovn_extend_table_lflow_ref {
    struct hmap_node hmap_node; /* In ovn_extend_table_info.references. */
    struct ovs_list list_node;  /* In
                                 * ovn_extend_table_lflow_to_desired.desired. */
    struct uuid lflow_uuid;
    struct ovn_extend_table_info *desired;
};

void ovn_extend_table_init(struct ovn_extend_table *);

void ovn_extend_table_destroy(struct ovn_extend_table *);

struct ovn_extend_table_info *ovn_extend_table_lookup(struct hmap *,
                                                      const struct
                                                      ovn_extend_table_info *);

void ovn_extend_table_clear(struct ovn_extend_table *, bool);

void ovn_extend_table_remove_existing(struct ovn_extend_table *,
                                      struct ovn_extend_table_info *);

void ovn_extend_table_remove_desired(struct ovn_extend_table *,
                                     const struct uuid *lflow_uuid);

/* Copy the contents of desired to existing. */
void ovn_extend_table_sync(struct ovn_extend_table *);

uint32_t ovn_extend_table_assign_id(struct ovn_extend_table *,
                                    const char *name, struct uuid lflow_uuid);

struct ovn_extend_table_info *ovn_extend_table_desired_lookup_by_name(struct
                                                                      ovn_extend_table
                                                                      *table,
                                                                      const
                                                                      char
                                                                      *name);

/* Iterates 'DESIRED' through all of the 'ovn_extend_table_info's in
 * 'TABLE'->desired that are not in 'TABLE'->existing.  (The loop body
 * presumably adds them.) */
#define EXTEND_TABLE_FOR_EACH_UNINSTALLED(DESIRED, TABLE) \
    HMAP_FOR_EACH (DESIRED, hmap_node, &(TABLE)->desired) \
        if (!ovn_extend_table_lookup(&(TABLE)->existing, DESIRED))

/* Iterates 'EXISTING' through all of the 'ovn_extend_table_info's in
 * 'TABLE'->existing that are not in 'TABLE'->desired.  (The loop body
 * presumably removes them.) */
#define EXTEND_TABLE_FOR_EACH_INSTALLED(EXISTING, TABLE)               \
    HMAP_FOR_EACH_SAFE (EXISTING, hmap_node, &(TABLE)->existing)        \
        if (!ovn_extend_table_lookup(&(TABLE)->desired, EXISTING))

#endif /* lib/extend-table.h */
