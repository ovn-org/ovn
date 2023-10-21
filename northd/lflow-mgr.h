    /*
 * Copyright (c) 2024, Red Hat, Inc.
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
#ifndef LFLOW_MGR_H
#define LFLOW_MGR_H 1

#include "include/openvswitch/hmap.h"
#include "include/openvswitch/uuid.h"

#include "northd.h"

struct ovsdb_idl_txn;
struct ovn_datapath;
struct ovsdb_idl_row;

/* lflow map which stores the logical flows. */
struct lflow_table;
struct lflow_table *lflow_table_alloc(void);
void lflow_table_init(struct lflow_table *);
void lflow_table_clear(struct lflow_table *);
void lflow_table_destroy(struct lflow_table *);
void lflow_table_expand(struct lflow_table *);
void lflow_table_set_size(struct lflow_table *, size_t);
void lflow_table_sync_to_sb(struct lflow_table *,
                            struct ovsdb_idl_txn *ovnsb_txn,
                            const struct ovn_datapaths *ls_datapaths,
                            const struct ovn_datapaths *lr_datapaths,
                            bool ovn_internal_version_changed,
                            const struct sbrec_logical_flow_table *,
                            const struct sbrec_logical_dp_group_table *);
void lflow_table_destroy(struct lflow_table *);

void lflow_hash_lock_init(void);
void lflow_hash_lock_destroy(void);

/* lflow mgr manages logical flows for a resource (like logical port
 * or datapath). */
struct lflow_ref;

struct lflow_ref *lflow_ref_create(void);
void lflow_ref_destroy(struct lflow_ref *);
void lflow_ref_clear(struct lflow_ref *lflow_ref);
void lflow_ref_unlink_lflows(struct lflow_ref *);
bool lflow_ref_resync_flows(struct lflow_ref *,
                            struct lflow_table *lflow_table,
                            struct ovsdb_idl_txn *ovnsb_txn,
                            const struct ovn_datapaths *ls_datapaths,
                            const struct ovn_datapaths *lr_datapaths,
                            bool ovn_internal_version_changed,
                            const struct sbrec_logical_flow_table *,
                            const struct sbrec_logical_dp_group_table *);
bool lflow_ref_sync_lflows(struct lflow_ref *,
                           struct lflow_table *lflow_table,
                           struct ovsdb_idl_txn *ovnsb_txn,
                           const struct ovn_datapaths *ls_datapaths,
                           const struct ovn_datapaths *lr_datapaths,
                           bool ovn_internal_version_changed,
                           const struct sbrec_logical_flow_table *,
                           const struct sbrec_logical_dp_group_table *);


void lflow_table_add_lflow(struct lflow_table *, const struct ovn_datapath *,
                           const unsigned long *dp_bitmap,
                           size_t dp_bitmap_len, enum ovn_stage stage,
                           uint16_t priority, const char *match,
                           const char *actions, const char *io_port,
                           const char *ctrl_meter,
                           const struct ovsdb_idl_row *stage_hint,
                           const char *where, struct lflow_ref *);
void lflow_table_add_lflow_default_drop(struct lflow_table *,
                                        const struct ovn_datapath *,
                                        enum ovn_stage stage,
                                        const char *where,
                                        struct lflow_ref *);

/* Adds a row with the specified contents to the Logical_Flow table. */
#define ovn_lflow_add_with_hint__(LFLOW_TABLE, OD, STAGE, PRIORITY, MATCH, \
                                  ACTIONS, IN_OUT_PORT, CTRL_METER, \
                                  STAGE_HINT, LFLOW_REF) \
    lflow_table_add_lflow(LFLOW_TABLE, OD, NULL, 0, STAGE, PRIORITY, MATCH, \
                          ACTIONS, IN_OUT_PORT, CTRL_METER, STAGE_HINT, \
                          OVS_SOURCE_LOCATOR, LFLOW_REF)

#define ovn_lflow_add_with_hint(LFLOW_TABLE, OD, STAGE, PRIORITY, MATCH, \
                                ACTIONS, STAGE_HINT, LFLOW_REF) \
    lflow_table_add_lflow(LFLOW_TABLE, OD, NULL, 0, STAGE, PRIORITY, MATCH, \
                          ACTIONS, NULL, NULL, STAGE_HINT,  \
                          OVS_SOURCE_LOCATOR, LFLOW_REF)

#define ovn_lflow_add_with_dp_group(LFLOW_TABLE, DP_BITMAP, DP_BITMAP_LEN, \
                                    STAGE, PRIORITY, MATCH, ACTIONS, \
                                    STAGE_HINT, LFLOW_REF) \
    lflow_table_add_lflow(LFLOW_TABLE, NULL, DP_BITMAP, DP_BITMAP_LEN, STAGE, \
                          PRIORITY, MATCH, ACTIONS, NULL, NULL, STAGE_HINT, \
                          OVS_SOURCE_LOCATOR, LFLOW_REF)

#define ovn_lflow_add_default_drop(LFLOW_TABLE, OD, STAGE, LFLOW_REF)   \
    lflow_table_add_lflow_default_drop(LFLOW_TABLE, OD, STAGE, \
                                       OVS_SOURCE_LOCATOR, LFLOW_REF)


/* This macro is similar to ovn_lflow_add_with_hint, except that it requires
 * the IN_OUT_PORT argument, which tells the lport name that appears in the
 * MATCH, which helps ovn-controller to bypass lflows parsing when the lport is
 * not local to the chassis. The critiera of the lport to be added using this
 * argument:
 *
 * - For ingress pipeline, the lport that is used to match "inport".
 * - For egress pipeline, the lport that is used to match "outport".
 *
 * For now, only LS pipelines should use this macro.  */
#define ovn_lflow_add_with_lport_and_hint(LFLOW_TABLE, OD, STAGE, PRIORITY, \
                                          MATCH, ACTIONS, IN_OUT_PORT, \
                                          STAGE_HINT, LFLOW_REF) \
    lflow_table_add_lflow(LFLOW_TABLE, OD, NULL, 0, STAGE, PRIORITY, MATCH, \
                          ACTIONS, IN_OUT_PORT, NULL, STAGE_HINT, \
                          OVS_SOURCE_LOCATOR, LFLOW_REF)

#define ovn_lflow_add(LFLOW_TABLE, OD, STAGE, PRIORITY, MATCH, ACTIONS, \
                      LFLOW_REF) \
    lflow_table_add_lflow(LFLOW_TABLE, OD, NULL, 0, STAGE, PRIORITY, MATCH, \
                          ACTIONS, NULL, NULL, NULL, OVS_SOURCE_LOCATOR, \
                          LFLOW_REF)

#define ovn_lflow_metered(LFLOW_TABLE, OD, STAGE, PRIORITY, MATCH, ACTIONS, \
                          CTRL_METER, LFLOW_REF) \
    ovn_lflow_add_with_hint__(LFLOW_TABLE, OD, STAGE, PRIORITY, MATCH, \
                              ACTIONS, NULL, CTRL_METER, NULL, LFLOW_REF)

struct sbrec_logical_dp_group;

struct ovn_dp_group {
    unsigned long *bitmap;
    const struct sbrec_logical_dp_group *dp_group;
    struct uuid dpg_uuid;
    struct hmap_node node;
    size_t refcnt;
};

static inline void
ovn_dp_groups_init(struct hmap *dp_groups)
{
    hmap_init(dp_groups);
}

void ovn_dp_groups_clear(struct hmap *dp_groups);
void ovn_dp_groups_destroy(struct hmap *dp_groups);
struct ovn_dp_group *ovn_dp_group_get(struct hmap *dp_groups, size_t desired_n,
                                      const unsigned long *desired_bitmap,
                                      size_t bitmap_len);
struct ovn_dp_group *ovn_dp_group_create(
    struct ovsdb_idl_txn *ovnsb_txn, struct hmap *dp_groups,
    struct sbrec_logical_dp_group *sb_group,
    size_t desired_n, const unsigned long *desired_bitmap,
    size_t bitmap_len, bool is_switch,
    const struct ovn_datapaths *ls_datapaths,
    const struct ovn_datapaths *lr_datapaths);

static inline void
inc_ovn_dp_group_ref(struct ovn_dp_group *dpg)
{
    dpg->refcnt++;
}

static inline void
dec_ovn_dp_group_ref(struct hmap *dp_groups, struct ovn_dp_group *dpg)
{
    dpg->refcnt--;

    if (!dpg->refcnt) {
        hmap_remove(dp_groups, &dpg->node);
        free(dpg->bitmap);
        free(dpg);
    }
}

#endif /* LFLOW_MGR_H */