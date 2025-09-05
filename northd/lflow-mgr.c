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

#include <config.h>

/* OVS includes */
#include "include/openvswitch/thread.h"
#include "lib/bitmap.h"
#include "openvswitch/vlog.h"

/* OVN includes */
#include "debug.h"
#include "lflow-mgr.h"
#include "lib/ovn-parallel-hmap.h"
#include "lib/ovn-util.h"

VLOG_DEFINE_THIS_MODULE(lflow_mgr);

/* Static function declarations. */
struct ovn_lflow;

static void ovn_lflow_init(struct ovn_lflow *, struct ovn_datapath *od,
                           size_t dp_bitmap_len, enum ovn_stage stage,
                           uint16_t priority, char *match,
                           char *actions, char *io_port,
                           char *ctrl_meter, char *stage_hint,
                           const char *where, const char *flow_desc);
static struct ovn_lflow *ovn_lflow_find(const struct hmap *lflows,
                                        enum ovn_stage stage,
                                        uint16_t priority, const char *match,
                                        const char *actions,
                                        const char *ctrl_meter, uint32_t hash);
static void ovn_lflow_destroy(struct lflow_table *lflow_table,
                              struct ovn_lflow *lflow);
static char *ovn_lflow_hint(const struct ovsdb_idl_row *row);

static struct ovn_lflow *do_ovn_lflow_add(
    struct lflow_table *, size_t dp_bitmap_len, uint32_t hash,
    enum ovn_stage stage, uint16_t priority, const char *match,
    const char *actions, const char *io_port,
    const char *ctrl_meter,
    const struct ovsdb_idl_row *stage_hint,
    const char *where, const char *flow_desc);


static struct ovs_mutex *lflow_hash_lock(const struct hmap *lflow_table,
                                         uint32_t hash);
static void lflow_hash_unlock(struct ovs_mutex *hash_lock);

static struct sbrec_logical_dp_group *ovn_sb_insert_or_update_logical_dp_group(
    struct ovsdb_idl_txn *ovnsb_txn,
    struct sbrec_logical_dp_group *,
    const unsigned long *dpg_bitmap,
    const struct ovn_datapaths *);
static struct ovn_dp_group *ovn_dp_group_find(const struct hmap *dp_groups,
                                              const unsigned long *dpg_bitmap,
                                              size_t bitmap_len,
                                              uint32_t hash);
static void ovn_dp_group_use(struct ovn_dp_group *);
static void ovn_dp_group_release(struct hmap *dp_groups,
                                 struct ovn_dp_group *);
static void ovn_dp_group_destroy(struct ovn_dp_group *dpg);
static void ovn_dp_group_add_with_reference(struct ovn_lflow *,
                                            const struct ovn_datapath *od,
                                            const unsigned long *dp_bitmap,
                                            size_t bitmap_len);

static bool lflow_ref_sync_lflows__(
    struct lflow_ref  *, struct lflow_table *,
    struct ovsdb_idl_txn *ovnsb_txn,
    const struct ovn_datapaths *ls_datapaths,
    const struct ovn_datapaths *lr_datapaths,
    bool ovn_internal_version_changed,
    const struct sbrec_logical_flow_table *,
    const struct sbrec_logical_dp_group_table *);
static bool sync_lflow_to_sb(struct ovn_lflow *,
                             struct ovsdb_idl_txn *ovnsb_txn,
                             struct lflow_table *,
                             const struct ovn_datapaths *ls_datapaths,
                             const struct ovn_datapaths *lr_datapaths,
                             bool ovn_internal_version_changed,
                             const struct sbrec_logical_flow *sbflow,
                             const struct sbrec_logical_dp_group_table *);

/* TODO:  Move the parallization logic to this module to avoid accessing
 * and modifying in both northd.c and lflow-mgr.c. */
extern int parallelization_state;
extern thread_local size_t thread_lflow_counter;

struct dp_refcnt;
static struct dp_refcnt *dp_refcnt_find(struct hmap *dp_refcnts_map,
                                        size_t dp_index);
static void dp_refcnt_use(struct hmap *dp_refcnts_map, size_t dp_index);
static bool dp_refcnt_release(struct hmap *dp_refcnts_map, size_t dp_index);
static void ovn_lflow_clear_dp_refcnts_map(struct ovn_lflow *);
static struct lflow_ref_node *lflow_ref_node_find(struct hmap *lflow_ref_nodes,
                                                  struct ovn_lflow *lflow,
                                                  uint32_t lflow_hash);
static void lflow_ref_node_destroy(struct lflow_ref_node *);

static bool lflow_hash_lock_initialized = false;
/* The lflow_hash_lock is a mutex array that protects updates to the shared
 * lflow table across threads when parallel lflow build and dp-group are both
 * enabled. To avoid high contention between threads, a big array of mutexes
 * are used instead of just one. This is possible because when parallel build
 * is used we only use hmap_insert_fast() to update the hmap, which would not
 * touch the bucket array but only the list in a single bucket. We only need to
 * make sure that when adding lflows to the same hash bucket, the same lock is
 * used, so that no two threads can add to the bucket at the same time.  It is
 * ok that the same lock is used to protect multiple buckets, so a fixed sized
 * mutex array is used instead of 1-1 mapping to the hash buckets. This
 * simplies the implementation while effectively reduces lock contention
 * because the chance that different threads contending the same lock amongst
 * the big number of locks is very low. */
#define LFLOW_HASH_LOCK_MASK 0xFFFF
static struct ovs_mutex lflow_hash_locks[LFLOW_HASH_LOCK_MASK + 1];

/* Full thread safety analysis is not possible with hash locks, because
 * they are taken conditionally based on the 'parallelization_state' and
 * a flow hash.  Also, the order in which two hash locks are taken is not
 * predictable during the static analysis.
 *
 * Since the order of taking two locks depends on a random hash, to avoid
 * ABBA deadlocks, no two hash locks can be nested.  In that sense an array
 * of hash locks is similar to a single mutex.
 *
 * Using a fake mutex to partially simulate thread safety restrictions, as
 * if it were actually a single mutex.
 *
 * OVS_NO_THREAD_SAFETY_ANALYSIS below allows us to ignore conditional
 * nature of the lock.  Unlike other attributes, it applies to the
 * implementation and not to the interface.  So, we can define a function
 * that acquires the lock without analysing the way it does that.
 */
extern struct ovs_mutex fake_hash_mutex;

/* Represents a logical ovn flow (lflow).
 *
 * A logical flow with match 'M' and actions 'A' - L(M, A) is created
 * when lflow engine node (northd.c) calls lflow_table_add_lflow
 * (or one of the helper macros ovn_lflow_add_*).
 *
 * Each lflow is stored in the lflow_table (see 'struct lflow_table' below)
 * and possibly referenced by zero or more lflow_refs
 * (see 'struct lflow_ref' and 'struct lflow_ref_node' below).
 *
 * */
struct ovn_lflow {
    struct hmap_node hmap_node;

    struct ovn_datapath *od;     /* 'logical_datapath' in SB schema.  */
    unsigned long *dpg_bitmap;   /* Bitmap of all datapaths by their 'index'.*/
    enum ovn_stage stage;
    uint16_t priority;
    char *match;
    char *actions;
    char *io_port;
    char *stage_hint;
    char *ctrl_meter;
    size_t n_ods;                /* Number of datapaths referenced by 'od' and
                                  * 'dpg_bitmap'. */
    struct ovn_dp_group *dpg;    /* Link to unique Sb datapath group. */
    const char *where;
    const char *flow_desc;

    struct uuid sb_uuid;         /* SB DB row uuid, specified by northd. */
    struct ovs_list referenced_by;  /* List of struct lflow_ref_node. */
    struct hmap dp_refcnts_map; /* Maintains the number of times this ovn_lflow
                                 * is referenced by a given datapath.
                                 * Contains 'struct dp_refcnt' in the map. */
};

/* Logical flow table. */
struct lflow_table {
    struct hmap entries; /* hmap of lflows. */
    struct hmap ls_dp_groups; /* hmap of logical switch dp groups. */
    struct hmap lr_dp_groups; /* hmap of logical router dp groups. */
    ssize_t max_seen_lflow_size;
};

struct lflow_table *
lflow_table_alloc(void)
{
    struct lflow_table *lflow_table = xzalloc(sizeof *lflow_table);
    lflow_table->max_seen_lflow_size = 128;

    return lflow_table;
}

void
lflow_table_init(struct lflow_table *lflow_table)
{
    fast_hmap_size_for(&lflow_table->entries,
                       lflow_table->max_seen_lflow_size);
    ovn_dp_groups_init(&lflow_table->ls_dp_groups);
    ovn_dp_groups_init(&lflow_table->lr_dp_groups);
}

void
lflow_table_clear(struct lflow_table *lflow_table)
{
    struct ovn_lflow *lflow;
    HMAP_FOR_EACH_SAFE (lflow, hmap_node, &lflow_table->entries) {
        ovn_lflow_destroy(lflow_table, lflow);
    }

    ovn_dp_groups_clear(&lflow_table->ls_dp_groups);
    ovn_dp_groups_clear(&lflow_table->lr_dp_groups);
}

void
lflow_table_destroy(struct lflow_table *lflow_table)
{
    lflow_table_clear(lflow_table);
    hmap_destroy(&lflow_table->entries);
    ovn_dp_groups_destroy(&lflow_table->ls_dp_groups);
    ovn_dp_groups_destroy(&lflow_table->lr_dp_groups);
    free(lflow_table);
}

void
lflow_table_expand(struct lflow_table *lflow_table)
{
    hmap_expand(&lflow_table->entries);

    if (hmap_count(&lflow_table->entries) >
            lflow_table->max_seen_lflow_size) {
        lflow_table->max_seen_lflow_size = hmap_count(&lflow_table->entries);
    }
}

void
lflow_table_set_size(struct lflow_table *lflow_table, size_t size)
{
    lflow_table->entries.n = size;
}

void
lflow_table_sync_to_sb(struct lflow_table *lflow_table,
                       struct ovsdb_idl_txn *ovnsb_txn,
                       const struct ovn_datapaths *ls_datapaths,
                       const struct ovn_datapaths *lr_datapaths,
                       bool ovn_internal_version_changed,
                       const struct sbrec_logical_flow_table *sb_flow_table,
                       const struct sbrec_logical_dp_group_table *dpgrp_table)
{
    struct hmap lflows_temp = HMAP_INITIALIZER(&lflows_temp);
    struct hmap *lflows = &lflow_table->entries;
    struct ovn_lflow *lflow;

    fast_hmap_size_for(&lflows_temp,
                       lflow_table->max_seen_lflow_size);

    /* Push changes to the Logical_Flow table to database. */
    const struct sbrec_logical_flow *sbflow;
    SBREC_LOGICAL_FLOW_TABLE_FOR_EACH_SAFE (sbflow, sb_flow_table) {
        struct sbrec_logical_dp_group *dp_group = sbflow->logical_dp_group;
        struct ovn_datapath *logical_datapath_od = NULL;
        size_t i;

        /* Find one valid datapath to get the datapath type. */
        struct sbrec_datapath_binding *dp = sbflow->logical_datapath;
        if (dp) {
            logical_datapath_od = ovn_datapath_from_sbrec(
                &ls_datapaths->datapaths, &lr_datapaths->datapaths, dp);
            if (logical_datapath_od
                && ovn_datapath_is_stale(logical_datapath_od)) {
                logical_datapath_od = NULL;
            }
        }
        for (i = 0; dp_group && i < dp_group->n_datapaths; i++) {
            logical_datapath_od = ovn_datapath_from_sbrec(
                &ls_datapaths->datapaths, &lr_datapaths->datapaths,
                dp_group->datapaths[i]);
            if (logical_datapath_od
                && !ovn_datapath_is_stale(logical_datapath_od)) {
                break;
            }
            logical_datapath_od = NULL;
        }

        if (!logical_datapath_od) {
            /* This lflow has no valid logical datapaths. */
            sbrec_logical_flow_delete(sbflow);
            continue;
        }

        enum ovn_pipeline pipeline
            = !strcmp(sbflow->pipeline, "ingress") ? P_IN : P_OUT;

        lflow = ovn_lflow_find(
            lflows,
            ovn_stage_build(ovn_datapath_get_type(logical_datapath_od),
                            pipeline, sbflow->table_id),
            sbflow->priority, sbflow->match, sbflow->actions,
            sbflow->controller_meter, sbflow->hash);
        if (lflow) {
            sync_lflow_to_sb(lflow, ovnsb_txn, lflow_table, ls_datapaths,
                             lr_datapaths, ovn_internal_version_changed,
                             sbflow, dpgrp_table);

            hmap_remove(lflows, &lflow->hmap_node);
            hmap_insert(&lflows_temp, &lflow->hmap_node,
                        hmap_node_hash(&lflow->hmap_node));
        } else {
            sbrec_logical_flow_delete(sbflow);
        }
    }

    HMAP_FOR_EACH_SAFE (lflow, hmap_node, lflows) {
        sync_lflow_to_sb(lflow, ovnsb_txn, lflow_table, ls_datapaths,
                         lr_datapaths, ovn_internal_version_changed,
                         NULL, dpgrp_table);

        hmap_remove(lflows, &lflow->hmap_node);
        hmap_insert(&lflows_temp, &lflow->hmap_node,
                    hmap_node_hash(&lflow->hmap_node));
    }
    hmap_swap(lflows, &lflows_temp);
    hmap_destroy(&lflows_temp);
}

/* Logical flow sync using 'struct lflow_ref'
 * ==========================================
 * The 'struct lflow_ref' represents a collection of (or references to)
 * logical flows (struct ovn_lflow) which belong to a logical entity 'E'.
 * This entity 'E' is external to lflow manager (see northd.h and northd.c)
 * Eg. logical datapath (struct ovn_datapath), logical switch and router ports
 * (struct ovn_port), load balancer (struct lb_datapath) etc.
 *
 * General guidelines on using 'struct lflow_ref'.
 *   - For an entity 'E', create an instance of lflow_ref
 *           E->lflow_ref = lflow_ref_create();
 *
 *   - For each logical flow L(M, A) generated for the entity 'E'
 *     pass E->lflow_ref when adding L(M, A) to the lflow table.
 *     Eg. lflow_table_add_lflow(lflow_table, od_of_E, M, A, .., E->lflow_ref);
 *
 * If lflows L1, L2 and L3 are generated for 'E', then
 * E->lflow_ref stores these in its hmap.
 * i.e E->lflow_ref->lflow_ref_nodes = hmap[LRN(L1, E1), LRN(L2, E1),
 *                                          LRN(L3, E1)]
 *
 * LRN is an instance of 'struct lflow_ref_node'.
 * 'struct lflow_ref_node' is used to store a logical lflow L(M, A) as a
 * reference in the lflow_ref.  It is possible that an lflow L(M,A) can be
 * referenced by one or more lflow_ref's.  For each reference, an instance of
 * this struct 'lflow_ref_node' is created.
 *
 * For example, if entity E1 generates lflows L1, L2 and L3
 * and entity E2 generates lflows L1, L3, and L4 then
 * an instance of this struct is created for each entity.
 * For example LRN(L1, E1).
 *
 * Each logical flow's L also maintains a list of its references in the
 * ovn_lflow->referenced_by list.
 *
 *
 *
 *                L1            L2             L3             L4
 *                |             |  (list)      |              |
 *   (lflow_ref)  v             v              v              v
 *  ----------------------------------------------------------------------
 * | E1 (hmap) => LRN(L1,E1) => LRN(L2, E1) => LRN(L3, E1)    |           |
 * |              |                            |              |           |
 * |              v                            v              v           |
 * | E2 (hmap) => LRN(L1,E2) ================> LRN(L3, E2) => LRN(L4, E2) |
 *  ----------------------------------------------------------------------
 *
 *
 * Life cycle of 'struct lflow_ref_node'
 * =====================================
 * For a given logical flow L1 and entity E1's lflow_ref,
 *  1. LRN(L1, E1) is created in lflow_table_add_lflow() and its 'linked' flag
 *     is set to true.
 *  2. LRN(L1, E1) is stored in the hmap - E1->lflow_ref->lflow_ref_nodes.
 *  3. LRN(L1, E1) is also stored in the linked list L1->referenced_by.
 *  4. LRN(L1, E1)->linked is set to false when the client calls
 *     lflow_ref_unlink_lflows(E1->lflow_ref).
 *  5. LRN(L1, E1)->linked is set to true again when the client calls
 *     lflow_table_add_lflow(L1, ..., E1->lflow_ref) and LRN(L1, E1)
 *     is already present.
 *  6. LRN(L1, E1) is destroyed if LRN(L1, E1)->linked is false
 *     when the client calls lflow_ref_sync_lflows().
 *  7. LRN(L1, E1) is also destroyed in lflow_ref_clear(E1->lflow_ref).
 *
 *
 * Incremental lflow generation for a logical entity
 * =================================================
 * Lets take the above example again.
 *
 *
 *                L1            L2             L3             L4
 *                |             |  (list)      |              |
 *   (lflow_ref)  v             v              v              v
 *  ----------------------------------------------------------------------
 * | E1 (hmap) => LRN(L1,E1) => LRN(L2, E1) => LRN(L3, E1)    |           |
 * |              |                            |              |           |
 * |              v                            v              v           |
 * | E2 (hmap) => LRN(L1,E2) ================> LRN(L3, E2) => LRN(L4, E2) |
 *  ----------------------------------------------------------------------
 *
 *
 * L1 is referenced by E1 and E2
 * L2 is referenced by just E1
 * L3 is referenced by E1 and E2
 * L4 is referenced by just E2
 *
 * L1->dpg_bitmap = [E1->od->index, E2->od->index]
 * L2->dpg_bitmap = [E1->od->index]
 * L3->dpg_bitmap = [E1->od->index, E2->od->index]
 * L4->dpg_bitmap = [E2->od->index]
 *
 *
 * When 'E' gets updated,
 *   1.  the client should first call
 *       lflow_ref_unlink_lflows(E1->lflow_ref);
 *
 *       This function sets the 'linked' flag to false and clears the dp bitmap
 *       of linked lflows.
 *
 *       LRN(L1,E1)->linked = false;
 *       LRN(L2,E1)->linked = false;
 *       LRN(L3,E1)->linked = false;
 *
 *       bitmap status of all lflows in the lflows table
 *       -----------------------------------------------
 *       L1->dpg_bitmap = [E2->od->index]
 *       L2->dpg_bitmap = []
 *       L3->dpg_bitmap = [E2->od->index]
 *       L4->dpg_bitmap = [E2->od->index]
 *
 *   2.  In step (2), client should generate the logical flows again for 'E1'.
 *       Lets say it calls:
 *       lflow_table_add_lflow(lflow_table, L3, E1->lflow_ref)
 *       lflow_table_add_lflow(lflow_table, L5, E1->lflow_ref)
 *
 *       So, E1 generates the flows L3 and L5 and discards L1 and L2.
 *
 *       Below is the state of LRNs of E1
 *       LRN(L1,E1)->linked = false;
 *       LRN(L2,E1)->linked = false;
 *       LRN(L3,E1)->linked = true;
 *       LRN(L5,E1)->linked = true;
 *
 *       bitmap status of all lflows in the lflow table after end of step (2)
 *       --------------------------------------------------------------------
 *       L1->dpg_bitmap = [E2->od->index]
 *       L2->dpg_bitmap = []
 *       L3->dpg_bitmap = [E1->od->index, E2->od->index]
 *       L4->dpg_bitmap = [E2->od->index]
 *       L5->dpg_bitmap = [E1->od->index]
 *
 *   3.  In step (3), client should sync the E1's lflows by calling
 *       lflow_ref_sync_lflows(E1->lflow_ref,....);
 *
 *       Below is how the logical flows in SB DB gets updated:
 *       lflow L1:
 *              SB:L1->logical_dp_group = NULL;
 *              SB:L1->logical_datapath = E2->od;
 *
 *       lflow L2: L2 is deleted since no datapath is using it.
 *
 *       lflow L3: No changes
 *
 *       lflow L5: New row is created for this.
 *
 * After step (3)
 *
 *                L1            L5             L3             L4
 *                |             |  (list)      |              |
 *   (lflow_ref)  v             v              v              v
 *  ----------------------------------------------------------------------
 * | E1 (hmap) ===============> LRN(L2, E1) => LRN(L3, E1)    |           |
 * |              |                            |              |           |
 * |              v                            v              v           |
 * | E2 (hmap) => LRN(L1,E2) ================> LRN(L3, E2) => LRN(L4, E2) |
 *  ----------------------------------------------------------------------
 *
 * Thread safety in lflow_ref
 * ==========================
 * The function lflow_table_add_lflow() is not thread safe for lflow_ref.
 * Client should ensure that same instance of lflow_ref's are not used
 * by multiple threads when calling lflow_table_add_lflow().
 *
 * One way to ensure thread safety is to maintain array of hash locks
 * in each lflow_ref just like how we have static variable lflow_hash_locks
 * of type ovs_mutex. This would mean that client has to reconsile the
 * lflow_ref hmap lflow_ref_nodes (by calling hmap_expand()) after the
 * lflow generation is complete.  (See lflow_table_expand()).
 *
 * Presently the client of lflow manager (northd.c) doesn't call
 * lflow_table_add_lflow() in multiple threads for the same lflow_ref.
 * But it may change in the future and we may need to add the thread
 * safety support.
 *
 * Until then care should be taken by the contributors to avoid this
 * scenario.
 */
struct lflow_ref {
    /* hmap of lfow ref nodes. hmap_node is 'struct lflow_ref_node *'. */
    struct hmap lflow_ref_nodes;
};

struct lflow_ref_node {
    /* hmap node in the hmap - 'struct lflow_ref->lflow_ref_nodes' */
    struct hmap_node ref_node;
    struct lflow_ref *lflow_ref; /* pointer to 'lflow_ref' it is part of. */

    /* This list follows different objects that reference the same lflow. List
     * head is ovn_lflow->referenced_by. */
    struct ovs_list ref_list_node;
    /* The lflow. */
    struct ovn_lflow *lflow;

    /* Indicates whether the lflow was added with a dp_group using the
     * ovn_lflow_add_with_dp_group() macro. */
    bool dpgrp_lflow;
    /* dpgrp bitmap and bitmap length.  Valid only of dpgrp_lflow is true. */
    unsigned long *dpgrp_bitmap;
    size_t dpgrp_bitmap_len;

    /* Index id of the datapath this lflow_ref_node belongs to.
     * Valid only if dpgrp_lflow is false. */
    size_t dp_index;

    /* Indicates if the lflow_ref_node for an lflow - L(M, A) is linked
     * to datapath(s) or not.
     * It is set to true when an lflow L(M, A) is referenced by an lflow ref
     * in lflow_table_add_lflow().  It is set to false when it is unlinked
     * from the datapath when lflow_ref_unlink_lflows() is called. */
    bool linked;
};

struct lflow_ref *
lflow_ref_create(void)
{
    struct lflow_ref *lflow_ref = xzalloc(sizeof *lflow_ref);
    hmap_init(&lflow_ref->lflow_ref_nodes);
    return lflow_ref;
}

void
lflow_ref_clear(struct lflow_ref *lflow_ref)
{
    struct lflow_ref_node *lrn;
    HMAP_FOR_EACH_SAFE (lrn, ref_node, &lflow_ref->lflow_ref_nodes) {
        lflow_ref_node_destroy(lrn);
    }
}

void
lflow_ref_destroy(struct lflow_ref *lflow_ref)
{
    lflow_ref_clear(lflow_ref);
    hmap_destroy(&lflow_ref->lflow_ref_nodes);
    free(lflow_ref);
}

/* Unlinks the lflows referenced by the 'lflow_ref'.
 * For each lflow_ref_node (lrn) in the lflow_ref, it basically clears
 * the datapath id (lrn->dp_index) or all the datapath id bits in the
 * dp group bitmap (set when ovn_lflow_add_with_dp_group macro was used)
 * from the lrn->lflow's dpg bitmap
 */
void
lflow_ref_unlink_lflows(struct lflow_ref *lflow_ref)
{
    struct lflow_ref_node *lrn;

    HMAP_FOR_EACH (lrn, ref_node, &lflow_ref->lflow_ref_nodes) {
        if (lrn->dpgrp_lflow) {
            size_t index;
            BITMAP_FOR_EACH_1 (index, lrn->dpgrp_bitmap_len,
                               lrn->dpgrp_bitmap) {
                if (dp_refcnt_release(&lrn->lflow->dp_refcnts_map, index)) {
                    bitmap_set0(lrn->lflow->dpg_bitmap, index);
                }
            }
        } else {
            if (dp_refcnt_release(&lrn->lflow->dp_refcnts_map,
                                  lrn->dp_index)) {
                bitmap_set0(lrn->lflow->dpg_bitmap, lrn->dp_index);
            }
        }

        lrn->linked = false;
    }
}

bool
lflow_ref_resync_flows(struct lflow_ref *lflow_ref,
                       struct lflow_table *lflow_table,
                       struct ovsdb_idl_txn *ovnsb_txn,
                       const struct ovn_datapaths *ls_datapaths,
                       const struct ovn_datapaths *lr_datapaths,
                       bool ovn_internal_version_changed,
                       const struct sbrec_logical_flow_table *sbflow_table,
                       const struct sbrec_logical_dp_group_table *dpgrp_table)
{
    lflow_ref_unlink_lflows(lflow_ref);
    return lflow_ref_sync_lflows__(lflow_ref, lflow_table, ovnsb_txn,
                                   ls_datapaths, lr_datapaths,
                                   ovn_internal_version_changed, sbflow_table,
                                   dpgrp_table);
}

bool
lflow_ref_sync_lflows(struct lflow_ref *lflow_ref,
                      struct lflow_table *lflow_table,
                      struct ovsdb_idl_txn *ovnsb_txn,
                      const struct ovn_datapaths *ls_datapaths,
                      const struct ovn_datapaths *lr_datapaths,
                      bool ovn_internal_version_changed,
                      const struct sbrec_logical_flow_table *sbflow_table,
                      const struct sbrec_logical_dp_group_table *dpgrp_table)
{
    return lflow_ref_sync_lflows__(lflow_ref, lflow_table, ovnsb_txn,
                                   ls_datapaths, lr_datapaths,
                                   ovn_internal_version_changed, sbflow_table,
                                   dpgrp_table);
}

/* Adds a logical flow to the logical flow table for the match 'match'
 * and actions 'actions'.
 *
 * If a logical flow L(M, A) for the 'match' and 'actions' already exist then
 *   - It will be no-op if L(M,A) was already added for the same datapath.
 *   - if its a different datapath, then the datapath index (od->index)
 *     is set in the lflow dp group bitmap.
 *
 * If 'lflow_ref' is not NULL then
 *    - it first checks if the lflow is present in the lflow_ref or not
 *    - if present, then it does nothing
 *    - if not present, then it creates an lflow_ref_node object for
 *      the [L(M, A), dp index] and adds ito the lflow_ref hmap.
 *
 * Note that this function is not thread safe for 'lflow_ref'.
 * If 2 or more threads calls this function for the same 'lflow_ref',
 * then it may corrupt the hmap.  Caller should ensure thread safety
 * for such scenarios.
 */
void
lflow_table_add_lflow(struct lflow_table *lflow_table,
                      const struct ovn_datapath *od,
                      const unsigned long *dp_bitmap, size_t dp_bitmap_len,
                      enum ovn_stage stage, uint16_t priority,
                      const char *match, const char *actions,
                      const char *io_port, const char *ctrl_meter,
                      const struct ovsdb_idl_row *stage_hint,
                      const char *where, const char *flow_desc,
                      struct lflow_ref *lflow_ref)
    OVS_EXCLUDED(fake_hash_mutex)
{
    struct ovs_mutex *hash_lock;
    uint32_t hash;

    ovs_assert(!od ||
               ovn_stage_to_datapath_type(stage) == ovn_datapath_get_type(od));

    hash = ovn_logical_flow_hash(ovn_stage_get_table(stage),
                                 ovn_stage_get_pipeline(stage),
                                 priority, match,
                                 actions);

    hash_lock = lflow_hash_lock(&lflow_table->entries, hash);
    struct ovn_lflow *lflow =
        do_ovn_lflow_add(lflow_table,
                         od ? ods_size(od->datapaths) : dp_bitmap_len,
                         hash, stage, priority, match, actions,
                         io_port, ctrl_meter, stage_hint, where, flow_desc);

    if (lflow_ref) {
        struct lflow_ref_node *lrn =
            lflow_ref_node_find(&lflow_ref->lflow_ref_nodes, lflow, hash);
        if (!lrn) {
            lrn = xzalloc(sizeof *lrn);
            lrn->lflow = lflow;
            lrn->lflow_ref = lflow_ref;
            lrn->dpgrp_lflow = !od;
            if (lrn->dpgrp_lflow) {
                lrn->dpgrp_bitmap = bitmap_clone(dp_bitmap, dp_bitmap_len);
                lrn->dpgrp_bitmap_len = dp_bitmap_len;
            } else {
                lrn->dp_index = od->index;
            }
            ovs_list_insert(&lflow->referenced_by, &lrn->ref_list_node);
            hmap_insert(&lflow_ref->lflow_ref_nodes, &lrn->ref_node, hash);
        }

        if (!lrn->linked) {
            if (lrn->dpgrp_lflow) {
                ovs_assert(lrn->dpgrp_bitmap_len == dp_bitmap_len);
                size_t index;
                BITMAP_FOR_EACH_1 (index, dp_bitmap_len, dp_bitmap) {
                    /* Allocate a reference counter only if already used. */
                    if (bitmap_is_set(lflow->dpg_bitmap, index)) {
                        dp_refcnt_use(&lflow->dp_refcnts_map, index);
                    }
                }
            } else {
                /* Allocate a reference counter only if already used. */
                if (bitmap_is_set(lflow->dpg_bitmap, lrn->dp_index)) {
                    dp_refcnt_use(&lflow->dp_refcnts_map, lrn->dp_index);
                }
            }
        }
        lrn->linked = true;
    }

    ovn_dp_group_add_with_reference(lflow, od, dp_bitmap, dp_bitmap_len);

    lflow_hash_unlock(hash_lock);
}

struct ovn_dp_group *
ovn_dp_group_get(struct hmap *dp_groups, size_t desired_n,
                 const unsigned long *desired_bitmap,
                 size_t bitmap_len)
{
    uint32_t hash;

    hash = hash_int(desired_n, 0);
    return ovn_dp_group_find(dp_groups, desired_bitmap, bitmap_len, hash);
}

/* Creates a new datapath group and adds it to 'dp_groups'.
 * If 'sb_group' is provided, function will try to re-use this group by
 * either taking it directly, or by modifying, if it's not already in use.
 * Caller should first call ovn_dp_group_get() before calling this function. */
struct ovn_dp_group *
ovn_dp_group_create(struct ovsdb_idl_txn *ovnsb_txn,
                    struct hmap *dp_groups,
                    struct sbrec_logical_dp_group *sb_group,
                    size_t desired_n,
                    const unsigned long *desired_bitmap,
                    size_t bitmap_len,
                    bool is_switch,
                    const struct ovn_datapaths *ls_datapaths,
                    const struct ovn_datapaths *lr_datapaths)
{
    struct ovn_dp_group *dpg;

    bool update_dp_group = false, can_modify = false;
    unsigned long *dpg_bitmap;
    size_t i, n = 0;

    dpg_bitmap = sb_group ? bitmap_allocate(bitmap_len) : NULL;
    for (i = 0; sb_group && i < sb_group->n_datapaths; i++) {
        struct ovn_datapath *datapath_od;

        datapath_od = ovn_datapath_from_sbrec(
                        ls_datapaths ? &ls_datapaths->datapaths : NULL,
                        lr_datapaths ? &lr_datapaths->datapaths : NULL,
                        sb_group->datapaths[i]);
        if (!datapath_od || ovn_datapath_is_stale(datapath_od)) {
            break;
        }
        bitmap_set1(dpg_bitmap, datapath_od->index);
        n++;
    }
    if (!sb_group || i != sb_group->n_datapaths) {
        /* No group or stale group.  Not going to be used. */
        update_dp_group = true;
        can_modify = true;
    } else if (!bitmap_equal(dpg_bitmap, desired_bitmap, bitmap_len)) {
        /* The group in Sb is different. */
        update_dp_group = true;
        /* We can modify existing group if it's not already in use. */
        can_modify = !ovn_dp_group_find(dp_groups, dpg_bitmap,
                                        bitmap_len, hash_int(n, 0));
    }

    bitmap_free(dpg_bitmap);

    dpg = xzalloc(sizeof *dpg);
    dpg->bitmap = bitmap_clone(desired_bitmap, bitmap_len);
    if (!update_dp_group) {
        dpg->dp_group = sb_group;
    } else {
        dpg->dp_group = ovn_sb_insert_or_update_logical_dp_group(
                            ovnsb_txn,
                            can_modify ? sb_group : NULL,
                            desired_bitmap,
                            is_switch ? ls_datapaths : lr_datapaths);
    }
    dpg->dpg_uuid = dpg->dp_group->header_.uuid;
    hmap_insert(dp_groups, &dpg->node, hash_int(desired_n, 0));

    return dpg;
}

void
ovn_dp_groups_clear(struct hmap *dp_groups)
{
    struct ovn_dp_group *dpg;
    HMAP_FOR_EACH_POP (dpg, node, dp_groups) {
        ovn_dp_group_destroy(dpg);
    }
}

void
ovn_dp_groups_destroy(struct hmap *dp_groups)
{
    ovn_dp_groups_clear(dp_groups);
    hmap_destroy(dp_groups);
}

void
lflow_hash_lock_init(void)
{
    if (!lflow_hash_lock_initialized) {
        for (size_t i = 0; i < LFLOW_HASH_LOCK_MASK + 1; i++) {
            ovs_mutex_init(&lflow_hash_locks[i]);
        }
        lflow_hash_lock_initialized = true;
    }
}

void
lflow_hash_lock_destroy(void)
{
    if (lflow_hash_lock_initialized) {
        for (size_t i = 0; i < LFLOW_HASH_LOCK_MASK + 1; i++) {
            ovs_mutex_destroy(&lflow_hash_locks[i]);
        }
    }
    lflow_hash_lock_initialized = false;
}

/* static functions. */
static void
ovn_lflow_init(struct ovn_lflow *lflow, struct ovn_datapath *od,
               size_t dp_bitmap_len, enum ovn_stage stage, uint16_t priority,
               char *match, char *actions, char *io_port, char *ctrl_meter,
               char *stage_hint, const char *where,
               const char *flow_desc)
{
    lflow->dpg_bitmap = bitmap_allocate(dp_bitmap_len);
    lflow->od = od;
    lflow->stage = stage;
    lflow->priority = priority;
    lflow->match = match;
    lflow->actions = actions;
    lflow->io_port = io_port;
    lflow->stage_hint = stage_hint;
    lflow->ctrl_meter = ctrl_meter;
    lflow->flow_desc = flow_desc;
    lflow->dpg = NULL;
    lflow->where = where;
    lflow->sb_uuid = UUID_ZERO;
    hmap_init(&lflow->dp_refcnts_map);
    ovs_list_init(&lflow->referenced_by);
}

static struct ovs_mutex *
lflow_hash_lock(const struct hmap *lflow_table, uint32_t hash)
    OVS_ACQUIRES(fake_hash_mutex)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct ovs_mutex *hash_lock = NULL;

    if (parallelization_state == STATE_USE_PARALLELIZATION) {
        hash_lock =
            &lflow_hash_locks[hash & lflow_table->mask & LFLOW_HASH_LOCK_MASK];
        ovs_mutex_lock(hash_lock);
    }
    return hash_lock;
}

static void
lflow_hash_unlock(struct ovs_mutex *hash_lock)
    OVS_RELEASES(fake_hash_mutex)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    if (hash_lock) {
        ovs_mutex_unlock(hash_lock);
    }
}

static bool
ovn_lflow_equal(const struct ovn_lflow *a, enum ovn_stage stage,
                uint16_t priority, const char *match,
                const char *actions, const char *ctrl_meter)
{
    return (a->stage == stage
            && a->priority == priority
            && !strcmp(a->match, match)
            && !strcmp(a->actions, actions)
            && nullable_string_is_equal(a->ctrl_meter, ctrl_meter));
}

static struct ovn_lflow *
ovn_lflow_find(const struct hmap *lflows,
               enum ovn_stage stage, uint16_t priority,
               const char *match, const char *actions,
               const char *ctrl_meter, uint32_t hash)
{
    struct ovn_lflow *lflow;
    HMAP_FOR_EACH_WITH_HASH (lflow, hmap_node, hash, lflows) {
        if (ovn_lflow_equal(lflow, stage, priority, match, actions,
                            ctrl_meter)) {
            return lflow;
        }
    }
    return NULL;
}

static char *
ovn_lflow_hint(const struct ovsdb_idl_row *row)
{
    if (!row) {
        return NULL;
    }
    return xasprintf("%08x", row->uuid.parts[0]);
}

static void
ovn_lflow_destroy(struct lflow_table *lflow_table, struct ovn_lflow *lflow)
{
    hmap_remove(&lflow_table->entries, &lflow->hmap_node);
    bitmap_free(lflow->dpg_bitmap);
    free(lflow->match);
    free(lflow->actions);
    free(lflow->io_port);
    free(lflow->stage_hint);
    free(lflow->ctrl_meter);
    ovn_lflow_clear_dp_refcnts_map(lflow);
    struct lflow_ref_node *lrn;
    LIST_FOR_EACH_SAFE (lrn, ref_list_node, &lflow->referenced_by) {
        lflow_ref_node_destroy(lrn);
    }
    free(lflow);
}

static struct ovn_lflow *
do_ovn_lflow_add(struct lflow_table *lflow_table, size_t dp_bitmap_len,
                 uint32_t hash, enum ovn_stage stage, uint16_t priority,
                 const char *match, const char *actions,
                 const char *io_port, const char *ctrl_meter,
                 const struct ovsdb_idl_row *stage_hint,
                 const char *where, const char *flow_desc)
    OVS_REQUIRES(fake_hash_mutex)
{
    struct ovn_lflow *old_lflow;
    struct ovn_lflow *lflow;

    ovs_assert(dp_bitmap_len);

    old_lflow = ovn_lflow_find(&lflow_table->entries, stage,
                               priority, match, actions, ctrl_meter, hash);
    if (old_lflow) {
        return old_lflow;
    }

    lflow = xzalloc(sizeof *lflow);
    /* While adding new logical flows we're not setting single datapath, but
     * collecting a group.  'od' will be updated later for all flows with only
     * one datapath in a group, so it could be hashed correctly. */
    ovn_lflow_init(lflow, NULL, dp_bitmap_len, stage, priority,
                   xstrdup(match), xstrdup(actions),
                   io_port ? xstrdup(io_port) : NULL,
                   nullable_xstrdup(ctrl_meter),
                   ovn_lflow_hint(stage_hint), where,
                   flow_desc);

    if (parallelization_state != STATE_USE_PARALLELIZATION) {
        hmap_insert(&lflow_table->entries, &lflow->hmap_node, hash);
    } else {
        hmap_insert_fast(&lflow_table->entries, &lflow->hmap_node,
                         hash);
        thread_lflow_counter++;
    }

    return lflow;
}

static bool
sync_lflow_to_sb(struct ovn_lflow *lflow,
                 struct ovsdb_idl_txn *ovnsb_txn,
                 struct lflow_table *lflow_table,
                 const struct ovn_datapaths *ls_datapaths,
                 const struct ovn_datapaths *lr_datapaths,
                 bool ovn_internal_version_changed,
                 const struct sbrec_logical_flow *sbflow,
                 const struct sbrec_logical_dp_group_table *sb_dpgrp_table)
{
    struct sbrec_logical_dp_group *sbrec_dp_group = NULL;
    struct ovn_dp_group *pre_sync_dpg = lflow->dpg;
    struct ovn_datapath **datapaths_array;
    struct hmap *dp_groups;
    size_t n_datapaths;
    bool is_switch;

    if (ovn_stage_to_datapath_type(lflow->stage) == DP_SWITCH) {
        n_datapaths = ods_size(ls_datapaths);
        datapaths_array = vector_get_array(&ls_datapaths->dps);
        dp_groups = &lflow_table->ls_dp_groups;
        is_switch = true;
    } else {
        n_datapaths = ods_size(lr_datapaths);
        datapaths_array = vector_get_array(&lr_datapaths->dps);
        dp_groups = &lflow_table->lr_dp_groups;
        is_switch = false;
    }

    lflow->n_ods = bitmap_count1(lflow->dpg_bitmap, n_datapaths);
    ovs_assert(lflow->n_ods);

    if (lflow->n_ods == 1) {
        /* There is only one datapath, so it should be moved out of the
         * group to a single 'od'. */
        size_t index = bitmap_scan(lflow->dpg_bitmap, true, 0,
                                    n_datapaths);

        lflow->od = datapaths_array[index];
        lflow->dpg = NULL;
    } else {
        lflow->od = NULL;
    }

    if (!sbflow) {
        lflow->sb_uuid = uuid_random();
        sbflow = sbrec_logical_flow_insert_persist_uuid(ovnsb_txn,
                                                        &lflow->sb_uuid);
        const char *pipeline = ovn_stage_get_pipeline_name(lflow->stage);
        uint8_t table = ovn_stage_get_table(lflow->stage);
        sbrec_logical_flow_set_pipeline(sbflow, pipeline);
        sbrec_logical_flow_set_table_id(sbflow, table);
        sbrec_logical_flow_set_priority(sbflow, lflow->priority);
        sbrec_logical_flow_set_match(sbflow, lflow->match);
        sbrec_logical_flow_set_actions(sbflow, lflow->actions);
        sbrec_logical_flow_set_flow_desc(sbflow, lflow->flow_desc);
        if (lflow->io_port) {
            struct smap tags = SMAP_INITIALIZER(&tags);
            smap_add(&tags, "in_out_port", lflow->io_port);
            sbrec_logical_flow_set_tags(sbflow, &tags);
            smap_destroy(&tags);
        }
        sbrec_logical_flow_set_controller_meter(sbflow, lflow->ctrl_meter);

        /* Trim the source locator lflow->where, which looks something like
         * "ovn/northd/northd.c:1234", down to just the part following the
         * last slash, e.g. "northd.c:1234". */
        const char *slash = strrchr(lflow->where, '/');
#if _WIN32
        const char *backslash = strrchr(lflow->where, '\\');
        if (!slash || backslash > slash) {
            slash = backslash;
        }
#endif
        const char *where = slash ? slash + 1 : lflow->where;

        struct smap ids = SMAP_INITIALIZER(&ids);
        smap_add(&ids, "stage-name", ovn_stage_to_str(lflow->stage));
        smap_add(&ids, "source", where);
        if (lflow->stage_hint) {
            smap_add(&ids, "stage-hint", lflow->stage_hint);
        }
        sbrec_logical_flow_set_external_ids(sbflow, &ids);
        smap_destroy(&ids);

    } else {
        lflow->sb_uuid = sbflow->header_.uuid;
        sbrec_dp_group = sbflow->logical_dp_group;

        if (ovn_internal_version_changed) {
            const char *stage_name = smap_get_def(&sbflow->external_ids,
                                                  "stage-name", "");
            const char *stage_hint = smap_get_def(&sbflow->external_ids,
                                                  "stage-hint", "");
            const char *source = smap_get_def(&sbflow->external_ids,
                                              "source", "");

            if (strcmp(stage_name, ovn_stage_to_str(lflow->stage))) {
                sbrec_logical_flow_update_external_ids_setkey(
                    sbflow, "stage-name", ovn_stage_to_str(lflow->stage));
            }
            if (lflow->stage_hint) {
                if (strcmp(stage_hint, lflow->stage_hint)) {
                    sbrec_logical_flow_update_external_ids_setkey(
                        sbflow, "stage-hint", lflow->stage_hint);
                }
            }
            if (lflow->where) {

                /* Trim the source locator lflow->where, which looks something
                 * like "ovn/northd/northd.c:1234", down to just the part
                 * following the last slash, e.g. "northd.c:1234". */
                const char *slash = strrchr(lflow->where, '/');
#if _WIN32
                const char *backslash = strrchr(lflow->where, '\\');
                if (!slash || backslash > slash) {
                    slash = backslash;
                }
#endif
                const char *where = slash ? slash + 1 : lflow->where;

                if (strcmp(source, where)) {
                    sbrec_logical_flow_update_external_ids_setkey(
                        sbflow, "source", where);
                }
            }
        }
    }

    if (lflow->od) {
        sbrec_logical_flow_set_logical_datapath(sbflow, lflow->od->sdp->sb_dp);
        sbrec_logical_flow_set_logical_dp_group(sbflow, NULL);
    } else {
        sbrec_logical_flow_set_logical_datapath(sbflow, NULL);
        lflow->dpg = ovn_dp_group_get(dp_groups, lflow->n_ods,
                                      lflow->dpg_bitmap,
                                      n_datapaths);
        if (lflow->dpg) {
            /* Update the dpg's sb dp_group. */
            lflow->dpg->dp_group = sbrec_logical_dp_group_table_get_for_uuid(
                sb_dpgrp_table,
                &lflow->dpg->dpg_uuid);

            if (!lflow->dpg->dp_group) {
                /* Ideally this should not happen.  But it can still happen
                 * due to 2 reasons:
                 * 1. There is a bug in the dp_group management.  We should
                 *    perhaps assert here.
                 * 2. A User or CMS may delete the logical_dp_groups in SB DB
                 *    or clear the SB:Logical_flow.logical_dp_groups column
                 *    (intentionally or accidentally)
                 *
                 * Because of (2) it is better to return false instead of
                 * assert,so that we recover from th inconsistent SB DB.
                 */
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "SB Logical flow ["UUID_FMT"]'s "
                            "logical_dp_group column is not set "
                            "(which is unexpected).  It should have been "
                            "referencing the dp group ["UUID_FMT"]",
                            UUID_ARGS(&sbflow->header_.uuid),
                            UUID_ARGS(&lflow->dpg->dpg_uuid));
                return false;
            }
        } else {
            lflow->dpg = ovn_dp_group_create(
                                ovnsb_txn, dp_groups, sbrec_dp_group,
                                lflow->n_ods, lflow->dpg_bitmap,
                                n_datapaths, is_switch,
                                ls_datapaths,
                                lr_datapaths);
        }
        sbrec_logical_flow_set_logical_dp_group(sbflow,
                                                lflow->dpg->dp_group);
    }

    if (pre_sync_dpg != lflow->dpg) {
        ovn_dp_group_use(lflow->dpg);
        ovn_dp_group_release(dp_groups, pre_sync_dpg);
    }

    return true;
}

static struct ovn_dp_group *
ovn_dp_group_find(const struct hmap *dp_groups,
                  const unsigned long *dpg_bitmap, size_t bitmap_len,
                  uint32_t hash)
{
    struct ovn_dp_group *dpg;

    HMAP_FOR_EACH_WITH_HASH (dpg, node, hash, dp_groups) {
        if (bitmap_equal(dpg->bitmap, dpg_bitmap, bitmap_len)) {
            return dpg;
        }
    }
    return NULL;
}

static void
ovn_dp_group_use(struct ovn_dp_group *dpg)
{
    if (dpg) {
        dpg->refcnt++;
    }
}

static void
ovn_dp_group_release(struct hmap *dp_groups, struct ovn_dp_group *dpg)
{
    if (dpg && !--dpg->refcnt) {
        hmap_remove(dp_groups, &dpg->node);
        ovn_dp_group_destroy(dpg);
    }
}

/* Destroys the ovn_dp_group and frees the memory.
 * Caller should remove the dpg->node from the hmap before
 * calling this. */
static void
ovn_dp_group_destroy(struct ovn_dp_group *dpg)
{
    bitmap_free(dpg->bitmap);
    free(dpg);
}

static struct sbrec_logical_dp_group *
ovn_sb_insert_or_update_logical_dp_group(
                            struct ovsdb_idl_txn *ovnsb_txn,
                            struct sbrec_logical_dp_group *dp_group,
                            const unsigned long *dpg_bitmap,
                            const struct ovn_datapaths *datapaths)
{
    const struct sbrec_datapath_binding **sb;
    size_t n = 0, index;

    sb = xmalloc(bitmap_count1(dpg_bitmap, ods_size(datapaths)) * sizeof *sb);
    BITMAP_FOR_EACH_1 (index, ods_size(datapaths), dpg_bitmap) {
        struct ovn_datapath *od = vector_get(&datapaths->dps, index,
                                             struct ovn_datapath *);
        sb[n++] = od->sdp->sb_dp;
    }
    if (!dp_group) {
        struct uuid dpg_uuid = uuid_random();
        dp_group = sbrec_logical_dp_group_insert_persist_uuid(
            ovnsb_txn, &dpg_uuid);
    }
    sbrec_logical_dp_group_set_datapaths(
        dp_group, (struct sbrec_datapath_binding **) sb, n);
    free(sb);

    return dp_group;
}

/* Adds an OVN datapath to a datapath group of existing logical flow.
 * Version to use when hash bucket locking is NOT required or the corresponding
 * hash lock is already taken. */
static void
ovn_dp_group_add_with_reference(struct ovn_lflow *lflow_ref,
                                const struct ovn_datapath *od,
                                const unsigned long *dp_bitmap,
                                size_t bitmap_len)
    OVS_REQUIRES(fake_hash_mutex)
{
    if (od) {
        bitmap_set1(lflow_ref->dpg_bitmap, od->index);
    }
    if (dp_bitmap) {
        bitmap_or(lflow_ref->dpg_bitmap, dp_bitmap, bitmap_len);
    }
}

static bool
lflow_ref_sync_lflows__(struct lflow_ref  *lflow_ref,
                        struct lflow_table *lflow_table,
                        struct ovsdb_idl_txn *ovnsb_txn,
                        const struct ovn_datapaths *ls_datapaths,
                        const struct ovn_datapaths *lr_datapaths,
                        bool ovn_internal_version_changed,
                        const struct sbrec_logical_flow_table *sbflow_table,
                        const struct sbrec_logical_dp_group_table *dpgrp_table)
{
    struct lflow_ref_node *lrn;
    struct ovn_lflow *lflow;
    HMAP_FOR_EACH_SAFE (lrn, ref_node, &lflow_ref->lflow_ref_nodes) {
        lflow = lrn->lflow;
        const struct sbrec_logical_flow *sblflow =
            sbrec_logical_flow_table_get_for_uuid(sbflow_table,
                                                  &lflow->sb_uuid);

        struct hmap *dp_groups = NULL;
        size_t n_datapaths;
        if (ovn_stage_to_datapath_type(lflow->stage) == DP_SWITCH) {
            dp_groups = &lflow_table->ls_dp_groups;
            n_datapaths = ods_size(ls_datapaths);
        } else {
            dp_groups = &lflow_table->lr_dp_groups;
            n_datapaths = ods_size(lr_datapaths);
        }

        size_t n_ods = bitmap_count1(lflow->dpg_bitmap, n_datapaths);

        if (n_ods) {
            if (!sync_lflow_to_sb(lflow, ovnsb_txn, lflow_table, ls_datapaths,
                                  lr_datapaths, ovn_internal_version_changed,
                                  sblflow, dpgrp_table)) {
                return false;
            }
        }

        if (!lrn->linked) {
            lflow_ref_node_destroy(lrn);

            if (ovs_list_is_empty(&lflow->referenced_by)) {
                ovn_dp_group_release(dp_groups, lflow->dpg);
                ovn_lflow_destroy(lflow_table, lflow);
                if (sblflow) {
                    sbrec_logical_flow_delete(sblflow);
                }
            }
        }
    }

    return true;
}

/* Used for the datapath reference counting for a given 'struct ovn_lflow'.
 * See the hmap 'dp_refcnts_map in 'struct ovn_lflow'.
 * For a given lflow L(M, A) with match - M and actions - A, it can be
 * referenced by multiple lflow_refs for the same datapath
 * Eg. Two lflow_ref's - op->lflow_ref and op->stateful_lflow_ref of a
 * datapath can have a reference to the same lflow L (M, A).  In this it
 * is important to maintain this reference count so that the sync to the
 * SB DB logical_flow is correct. */
struct dp_refcnt {
    struct hmap_node key_node;

    size_t dp_index; /* datapath index.  Also used as hmap key. */
    size_t refcnt;   /* reference counter. */
};

static struct dp_refcnt *
dp_refcnt_find(struct hmap *dp_refcnts_map, size_t dp_index)
{
    struct dp_refcnt *dp_refcnt;
    HMAP_FOR_EACH_WITH_HASH (dp_refcnt, key_node, dp_index, dp_refcnts_map) {
        if (dp_refcnt->dp_index == dp_index) {
            return dp_refcnt;
        }
    }

    return NULL;
}

static void
dp_refcnt_use(struct hmap *dp_refcnts_map, size_t dp_index)
{
    struct dp_refcnt *dp_refcnt = dp_refcnt_find(dp_refcnts_map, dp_index);

    if (!dp_refcnt) {
        dp_refcnt = xmalloc(sizeof *dp_refcnt);
        dp_refcnt->dp_index = dp_index;
        /* Allocation is happening on the second (!) use. */
        dp_refcnt->refcnt = 1;

        hmap_insert(dp_refcnts_map, &dp_refcnt->key_node, dp_index);
    }

    dp_refcnt->refcnt++;
}

/* Decrements the datapath's refcnt from the 'dp_refcnts_map' if it exists
 * and returns true if the refcnt is 0 or if the dp refcnt doesn't exist. */
static bool
dp_refcnt_release(struct hmap *dp_refcnts_map, size_t dp_index)
{
    struct dp_refcnt *dp_refcnt = dp_refcnt_find(dp_refcnts_map, dp_index);
    if (!dp_refcnt) {
        return true;
    }

    if (!--dp_refcnt->refcnt) {
        hmap_remove(dp_refcnts_map, &dp_refcnt->key_node);
        free(dp_refcnt);
        return true;
    }

    return false;
}

static void
ovn_lflow_clear_dp_refcnts_map(struct ovn_lflow *lflow)
{
    struct dp_refcnt *dp_refcnt;

    HMAP_FOR_EACH_POP (dp_refcnt, key_node, &lflow->dp_refcnts_map) {
        free(dp_refcnt);
    }

    hmap_destroy(&lflow->dp_refcnts_map);
}

static struct lflow_ref_node *
lflow_ref_node_find(struct hmap *lflow_ref_nodes, struct ovn_lflow *lflow,
                    uint32_t lflow_hash)
{
    struct lflow_ref_node *lrn;
    HMAP_FOR_EACH_WITH_HASH (lrn, ref_node, lflow_hash, lflow_ref_nodes) {
        if (lrn->lflow == lflow) {
            return lrn;
        }
    }

    return NULL;
}

static void
lflow_ref_node_destroy(struct lflow_ref_node *lrn)
{
    hmap_remove(&lrn->lflow_ref->lflow_ref_nodes, &lrn->ref_node);
    ovs_list_remove(&lrn->ref_list_node);
    if (lrn->dpgrp_lflow) {
        bitmap_free(lrn->dpgrp_bitmap);
    }
    free(lrn);
}
