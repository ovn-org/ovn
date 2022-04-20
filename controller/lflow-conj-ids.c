/*
 * Copyright (c) 2021, NVIDIA CORPORATION.  All rights reserved.
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
#include "coverage.h"
#include "lflow-conj-ids.h"
#include "util.h"
#include "hash.h"
#include "openvswitch/list.h"

COVERAGE_DEFINE(lflow_conj_conflict);
COVERAGE_DEFINE(lflow_conj_alloc);
COVERAGE_DEFINE(lflow_conj_alloc_specified);
COVERAGE_DEFINE(lflow_conj_free);
COVERAGE_DEFINE(lflow_conj_free_unexpected);

/* Node in struct conj_ids.conj_id_allocations. */
struct conj_id_node {
    struct hmap_node hmap_node;
    uint32_t conj_id;
};

struct lflow_conj_node {
    struct hmap_node hmap_node; /* Node in struct conj_ids.lflow_conj_ids. */
    struct ovs_list list_node; /* Node in struct lflow_to_dps_node.dps. */
    struct uuid lflow_uuid;
    struct uuid dp_uuid;
    uint32_t start_conj_id;
    uint32_t n_conjs;
};

struct lflow_to_dps_node {
    struct hmap_node hmap_node; /* Node in struct conj_ids.lflow_to_dps. */
    struct uuid lflow_uuid;
    struct ovs_list dps; /* List of DPs the lflow belongs to. Each node is
                            struct lflow_conj_node.list_node. */
};

/* XXX: Figure out a way to avoid test_mode. */
static bool test_mode = false;

static void lflow_conj_ids_insert_(struct conj_ids *,
                                   const struct uuid *lflow_uuid,
                                   const struct uuid *dp_uuid,
                                   uint32_t start_conj_id, uint32_t n_conjs);
static struct lflow_conj_node *
lflow_conj_ids_find_(struct conj_ids *conj_ids, const struct uuid *lflow_uuid,
                     const struct uuid *dp_uuid);
static void lflow_conj_ids_free_(struct conj_ids *, struct lflow_conj_node *);
static void lflow_conj_ids_free_for_lflow_dp(struct conj_ids *,
                                             const struct uuid *lflow_uuid,
                                             const struct uuid *dp_uuid);
static struct lflow_to_dps_node *lflow_to_dps_find(struct conj_ids *,
                                                   const struct uuid *);
static inline uint32_t
hash_lflow_dp(const struct uuid *lflow_uuid, const struct uuid *dp_uuid)
{
    if (test_mode) {
        return lflow_uuid->parts[0];
    }

    return hash_int(uuid_hash(lflow_uuid), uuid_hash(dp_uuid));
}

/* For test purpose only. */
void
lflow_conj_ids_set_test_mode(bool mode)
{
    test_mode = mode;
}

/* Allocate n_conjs continuous conjuction ids from the conj_ids for the given
 * lflow_uuid and dp_uuid. (0 is never included in an allocated range)
 *
 * The first conjunction id is returned. If no conjunction ids available, or if
 * the input is invalid (n_conjs == 0), then 0 is returned.
 *
 * The algorithm tries to allocate the hash result of the combination of the
 * lflow_uuid and dp_uuid as the first conjunction id. If it is unavailable, or
 * any of the subsequent n_conjs - 1 ids are unavailable, iterate until the
 * next available n_conjs ids are found.  Given that n_conjs is very small (in
 * most cases will be 1), the algorithm should be efficient enough and in most
 * cases just return the hash value, which ensures conjunction ids are
 * consistent for the same logical flow + DP in most cases.
 *
 * The performance will degrade if most of the uint32_t are allocated because
 * conflicts will happen a lot. In practice this is not expected to happen in
 * reasonable scale. Otherwise, if the amount of logical flows is close to
 * this (4G logical flows that need conjunction ids) there are other parts of
 * the system expected to be suffered even before reaching to a scale much
 * smaller than this. */
uint32_t
lflow_conj_ids_alloc(struct conj_ids *conj_ids, const struct uuid *lflow_uuid,
                     const struct uuid *dp_uuid, uint32_t n_conjs)
{
    if (!n_conjs) {
        return 0;
    }
    lflow_conj_ids_free_for_lflow_dp(conj_ids, lflow_uuid, dp_uuid);

    COVERAGE_INC(lflow_conj_alloc);

    uint32_t start_conj_id = hash_lflow_dp(lflow_uuid, dp_uuid);
    if (start_conj_id == 0) {
        start_conj_id++;
    }
    uint32_t initial_id = start_conj_id;
    bool initial = true;
    while (true) {
        if (start_conj_id == 0) {
            start_conj_id++;
        }
        bool available = true;
        uint32_t conj_id = start_conj_id;
        for (uint32_t i = 0; i < n_conjs; i++) {
            if (conj_id == 0) {
                /* Overflow. Consider the current range as unavailable because
                 * we need a continuous range. Start over from 1 (0 is
                 * skipped). */
                available = false;
                break;
            }
            if (!initial && conj_id == initial_id) {
                /* It has checked all ids (extreme situation, not expected in
                 * real environment). */
                return 0;
            }
            initial = false;
            struct conj_id_node *conj_id_node;
            /* conj_id is both the key and the hash */
            HMAP_FOR_EACH_WITH_HASH (conj_id_node, hmap_node, conj_id,
                                     &conj_ids->conj_id_allocations) {
                if (conj_id_node->conj_id == conj_id) {
                    available = false;
                    COVERAGE_INC(lflow_conj_conflict);
                    break;
                }
            }
            if (!available) {
                break;
            }
            conj_id++;
        }
        if (available) {
            break;
        }
        start_conj_id = conj_id + 1;
    }
    lflow_conj_ids_insert_(conj_ids, lflow_uuid, dp_uuid, start_conj_id,
                           n_conjs);
    return start_conj_id;
}

/* Similar to lflow_conj_ids_alloc, except that it takes an extra parameter
 * start_conj_id, which specifies the desired conjunction ids to be allocated,
 * and if they are unavailable, return false directly without trying to find
 * the next available ones. It returns true if the specified range is
 * allocated successfully. */
bool
lflow_conj_ids_alloc_specified(struct conj_ids *conj_ids,
                               const struct uuid *lflow_uuid,
                               const struct uuid *dp_uuid,
                               uint32_t start_conj_id, uint32_t n_conjs)
{
    if (!n_conjs) {
        return false;
    }
    lflow_conj_ids_free_for_lflow_dp(conj_ids, lflow_uuid, dp_uuid);

    uint32_t conj_id = start_conj_id;
    for (uint32_t i = 0; i < n_conjs; i++) {
        if (!conj_id) {
            return false;
        }
        struct conj_id_node *conj_id_node;
        HMAP_FOR_EACH_WITH_HASH (conj_id_node, hmap_node, conj_id,
                                 &conj_ids->conj_id_allocations) {
            if (conj_id_node->conj_id == conj_id) {
                return false;
            }
        }
        conj_id++;
    }
    lflow_conj_ids_insert_(conj_ids, lflow_uuid, dp_uuid, start_conj_id,
                           n_conjs);
    COVERAGE_INC(lflow_conj_alloc_specified);

    return true;
}

/* Find and return the start id that is allocated to the logical flow for the
 * dp_uuid. Return 0 if not found. */
uint32_t
lflow_conj_ids_find(struct conj_ids *conj_ids, const struct uuid *lflow_uuid,
                    const struct uuid *dp_uuid)
{
    struct lflow_conj_node *lflow_conj = lflow_conj_ids_find_(conj_ids,
                                                              lflow_uuid,
                                                              dp_uuid);
    return lflow_conj ? lflow_conj->start_conj_id : 0;
}

/* Frees the conjunction IDs used by lflow_uuid. */
void
lflow_conj_ids_free(struct conj_ids *conj_ids, const struct uuid *lflow_uuid)
{
    struct lflow_to_dps_node *ltd = lflow_to_dps_find(conj_ids, lflow_uuid);
    if (!ltd) {
        return;
    }
    struct lflow_conj_node *lflow_conj;
    LIST_FOR_EACH_SAFE (lflow_conj, list_node, &ltd->dps) {
        lflow_conj_ids_free_(conj_ids, lflow_conj);
    }
    hmap_remove(&conj_ids->lflow_to_dps, &ltd->hmap_node);
    free(ltd);
}

void
lflow_conj_ids_init(struct conj_ids *conj_ids)
{
    hmap_init(&conj_ids->conj_id_allocations);
    hmap_init(&conj_ids->lflow_conj_ids);
    hmap_init(&conj_ids->lflow_to_dps);
}

void
lflow_conj_ids_destroy(struct conj_ids *conj_ids) {
    struct conj_id_node *conj_id_node;
    HMAP_FOR_EACH_SAFE (conj_id_node, hmap_node,
                        &conj_ids->conj_id_allocations) {
        hmap_remove(&conj_ids->conj_id_allocations, &conj_id_node->hmap_node);
        free(conj_id_node);
    }
    hmap_destroy(&conj_ids->conj_id_allocations);

    struct lflow_conj_node *lflow_conj;
    HMAP_FOR_EACH_SAFE (lflow_conj, hmap_node, &conj_ids->lflow_conj_ids) {
        hmap_remove(&conj_ids->lflow_conj_ids, &lflow_conj->hmap_node);
        ovs_list_remove(&lflow_conj->list_node);
        free(lflow_conj);
    }
    hmap_destroy(&conj_ids->lflow_conj_ids);

    struct lflow_to_dps_node *ltd;
    HMAP_FOR_EACH_SAFE (ltd, hmap_node, &conj_ids->lflow_to_dps) {
        hmap_remove(&conj_ids->lflow_to_dps, &ltd->hmap_node);
        free(ltd);
    }
    hmap_destroy(&conj_ids->lflow_to_dps);
}

void lflow_conj_ids_clear(struct conj_ids *conj_ids) {
    lflow_conj_ids_destroy(conj_ids);
    lflow_conj_ids_init(conj_ids);
}

void
lflow_conj_ids_dump(struct conj_ids *conj_ids, struct ds *out_data)
{
    struct lflow_conj_node *lflow_conj;
    size_t count = 0;

    ds_put_cstr(out_data, "Conjunction IDs allocations:\n");
    HMAP_FOR_EACH (lflow_conj, hmap_node, &conj_ids->lflow_conj_ids) {
        bool has_conflict =
            (lflow_conj->start_conj_id != lflow_conj->hmap_node.hash);
        ds_put_format(out_data, "lflow: "UUID_FMT", dp: "UUID_FMT", start: %"
                      PRIu32", n: %"PRIu32"%s\n",
                      UUID_ARGS(&lflow_conj->lflow_uuid),
                      UUID_ARGS(&lflow_conj->dp_uuid),
                      lflow_conj->start_conj_id,
                      lflow_conj->n_conjs,
                      has_conflict ? " (*)" : "");
        count += lflow_conj->n_conjs;
    }

    ds_put_cstr(out_data, "---\n");
    ds_put_format(out_data, "Total %"PRIuSIZE" IDs used.\n", count);

    size_t allocated = hmap_count(&conj_ids->conj_id_allocations);
    if (count != allocated) {
        ds_put_format(out_data, "WARNING: mismatch - %"PRIuSIZE" allocated\n",
                      allocated);
    }
}

static struct lflow_to_dps_node *
lflow_to_dps_find(struct conj_ids *conj_ids, const struct uuid *lflow_uuid)
{
    struct lflow_to_dps_node *ltd;
    HMAP_FOR_EACH_WITH_HASH (ltd, hmap_node, uuid_hash(lflow_uuid),
                             &conj_ids->lflow_to_dps) {
        if (uuid_equals(&ltd->lflow_uuid, lflow_uuid)) {
            return ltd;
        }
    }
    return NULL;
}

/* Insert n_conjs conjuntion ids starting from start_conj_id into the conj_ids,
 * assuming the ids are confirmed to be available. */
static void
lflow_conj_ids_insert_(struct conj_ids *conj_ids,
                       const struct uuid *lflow_uuid,
                       const struct uuid *dp_uuid,
                       uint32_t start_conj_id, uint32_t n_conjs)
{
    ovs_assert(n_conjs);
    uint32_t conj_id = start_conj_id;
    for (uint32_t i = 0; i < n_conjs; i++) {
        ovs_assert(conj_id);
        struct conj_id_node *node = xzalloc(sizeof *node);
        node->conj_id = conj_id;
        hmap_insert(&conj_ids->conj_id_allocations, &node->hmap_node, conj_id);
        conj_id++;
    }

    struct lflow_conj_node *lflow_conj = xzalloc(sizeof *lflow_conj);
    lflow_conj->lflow_uuid = *lflow_uuid;
    lflow_conj->dp_uuid = *dp_uuid;
    lflow_conj->start_conj_id = start_conj_id;
    lflow_conj->n_conjs = n_conjs;
    hmap_insert(&conj_ids->lflow_conj_ids, &lflow_conj->hmap_node,
                hash_lflow_dp(lflow_uuid, dp_uuid));

    struct lflow_to_dps_node *ltd = lflow_to_dps_find(conj_ids, lflow_uuid);
    if (!ltd) {
        ltd = xmalloc(sizeof *ltd);
        ltd->lflow_uuid = *lflow_uuid;
        ovs_list_init(&ltd->dps);
        hmap_insert(&conj_ids->lflow_to_dps, &ltd->hmap_node,
                    uuid_hash(lflow_uuid));
    }
    ovs_list_insert(&ltd->dps, &lflow_conj->list_node);
}

static struct lflow_conj_node *
lflow_conj_ids_find_(struct conj_ids *conj_ids,
                     const struct uuid *lflow_uuid,
                     const struct uuid *dp_uuid)
{
    struct lflow_conj_node *lflow_conj;
    HMAP_FOR_EACH_WITH_HASH (lflow_conj, hmap_node,
                             hash_lflow_dp(lflow_uuid, dp_uuid),
                             &conj_ids->lflow_conj_ids) {
        if (uuid_equals(&lflow_conj->lflow_uuid, lflow_uuid) &&
            uuid_equals(&lflow_conj->dp_uuid, dp_uuid)) {
            return lflow_conj;
        }
    }
    return NULL;
}

static void
lflow_conj_ids_free_(struct conj_ids *conj_ids,
                     struct lflow_conj_node *lflow_conj)
{
    ovs_assert(lflow_conj->n_conjs);
    COVERAGE_INC(lflow_conj_free);
    uint32_t conj_id = lflow_conj->start_conj_id;
    for (uint32_t i = 0; i < lflow_conj->n_conjs; i++) {
        ovs_assert(conj_id);
        struct conj_id_node *conj_id_node;
        HMAP_FOR_EACH_WITH_HASH (conj_id_node, hmap_node, conj_id,
                                 &conj_ids->conj_id_allocations) {
            if (conj_id_node->conj_id == conj_id) {
                hmap_remove(&conj_ids->conj_id_allocations,
                            &conj_id_node->hmap_node);
                free(conj_id_node);
                break;
            }
        }
        conj_id++;
    }

    hmap_remove(&conj_ids->lflow_conj_ids, &lflow_conj->hmap_node);
    ovs_list_remove(&lflow_conj->list_node);
    free(lflow_conj);
}

static void
lflow_conj_ids_free_for_lflow_dp(struct conj_ids *conj_ids,
                                 const struct uuid *lflow_uuid,
                                 const struct uuid *dp_uuid)
{
    struct lflow_conj_node *lflow_conj = lflow_conj_ids_find_(conj_ids,
                                                              lflow_uuid,
                                                              dp_uuid);
    if (!lflow_conj) {
        return;
    }

    /* It is unexpected that an entry is found because this is called only by
     * alloc/alloc_specified. Something may be wrong in the lflow module.
     */
    COVERAGE_INC(lflow_conj_free_unexpected);
    lflow_conj_ids_free_(conj_ids, lflow_conj);
}
