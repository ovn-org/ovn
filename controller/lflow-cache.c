/*
 * Copyright (c) 2015, 2016 Nicira, Inc.
 * Copyright (c) 2021, Red Hat, Inc.
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

#if HAVE_DECL_MALLOC_TRIM
#include <malloc.h>
#endif

#include "coverage.h"
#include "lflow-cache.h"
#include "lib/uuid.h"
#include "ovn/expr.h"

COVERAGE_DEFINE(lflow_cache_flush);
COVERAGE_DEFINE(lflow_cache_add_conj_id);
COVERAGE_DEFINE(lflow_cache_add_expr);
COVERAGE_DEFINE(lflow_cache_add_matches);
COVERAGE_DEFINE(lflow_cache_free_conj_id);
COVERAGE_DEFINE(lflow_cache_free_expr);
COVERAGE_DEFINE(lflow_cache_free_matches);
COVERAGE_DEFINE(lflow_cache_add);
COVERAGE_DEFINE(lflow_cache_hit);
COVERAGE_DEFINE(lflow_cache_miss);
COVERAGE_DEFINE(lflow_cache_delete);
COVERAGE_DEFINE(lflow_cache_full);
COVERAGE_DEFINE(lflow_cache_mem_full);
COVERAGE_DEFINE(lflow_cache_made_room);

static const char *lflow_cache_type_names[LCACHE_T_MAX] = {
    [LCACHE_T_CONJ_ID] = "cache-conj-id",
    [LCACHE_T_EXPR]    = "cache-expr",
    [LCACHE_T_MATCHES] = "cache-matches",
};

struct lflow_cache {
    struct hmap entries[LCACHE_T_MAX];
    uint32_t capacity;
    uint64_t mem_usage;
    uint64_t max_mem_usage;
    bool enabled;
};

struct lflow_cache_entry {
    struct hmap_node node;
    struct uuid lflow_uuid; /* key */
    size_t size;

    struct lflow_cache_value value;
};

static size_t lflow_cache_n_entries__(const struct lflow_cache *lc);
static bool lflow_cache_make_room__(struct lflow_cache *lc,
                                    enum lflow_cache_type type);
static struct lflow_cache_value *lflow_cache_add__(
    struct lflow_cache *lc, const struct uuid *lflow_uuid,
    enum lflow_cache_type type, uint64_t value_size);
static void lflow_cache_delete__(struct lflow_cache *lc,
                                 struct lflow_cache_entry *lce);

struct lflow_cache *
lflow_cache_create(void)
{
    struct lflow_cache *lc = xmalloc(sizeof *lc);

    for (size_t i = 0; i < LCACHE_T_MAX; i++) {
        hmap_init(&lc->entries[i]);
    }

    lc->enabled = true;
    lc->mem_usage = 0;
    return lc;
}

void
lflow_cache_flush(struct lflow_cache *lc)
{
    if (!lc) {
        return;
    }

    COVERAGE_INC(lflow_cache_flush);
    for (size_t i = 0; i < LCACHE_T_MAX; i++) {
        struct lflow_cache_entry *lce;
        struct lflow_cache_entry *lce_next;

        HMAP_FOR_EACH_SAFE (lce, lce_next, node, &lc->entries[i]) {
            lflow_cache_delete__(lc, lce);
        }
        hmap_shrink(&lc->entries[i]);
    }

#if HAVE_DECL_MALLOC_TRIM
    malloc_trim(0);
#endif
}

void
lflow_cache_destroy(struct lflow_cache *lc)
{
    if (!lc) {
        return;
    }

    lflow_cache_flush(lc);
    for (size_t i = 0; i < LCACHE_T_MAX; i++) {
        hmap_destroy(&lc->entries[i]);
    }
    free(lc);
}

void
lflow_cache_enable(struct lflow_cache *lc, bool enabled, uint32_t capacity,
                   uint64_t max_mem_usage_kb)
{
    if (!lc) {
        return;
    }

    uint64_t max_mem_usage = max_mem_usage_kb * 1024;

    if ((lc->enabled && !enabled)
            || capacity < lflow_cache_n_entries__(lc)
            || max_mem_usage < lc->mem_usage) {
        lflow_cache_flush(lc);
    }

    lc->enabled = enabled;
    lc->capacity = capacity;
    lc->max_mem_usage = max_mem_usage;
}

bool
lflow_cache_is_enabled(const struct lflow_cache *lc)
{
    return lc && lc->enabled;
}

void
lflow_cache_get_stats(const struct lflow_cache *lc, struct ds *output)
{
    if (!output) {
        return;
    }

    if (!lc) {
        ds_put_cstr(output, "Invalid arguments.");
        return;
    }

    ds_put_format(output, "Enabled: %s\n",
                  lflow_cache_is_enabled(lc) ? "true" : "false");
    for (size_t i = 0; i < LCACHE_T_MAX; i++) {
        ds_put_format(output, "%-16s: %"PRIuSIZE"\n",
                      lflow_cache_type_names[i],
                      hmap_count(&lc->entries[i]));
    }
    ds_put_format(output, "%-16s: %"PRIu64"\n", "Mem usage (KB)",
                  ROUND_UP(lc->mem_usage, 1024) / 1024);
}

void
lflow_cache_add_conj_id(struct lflow_cache *lc, const struct uuid *lflow_uuid,
                        uint32_t conj_id_ofs)
{
    struct lflow_cache_value *lcv =
        lflow_cache_add__(lc, lflow_uuid, LCACHE_T_CONJ_ID, 0);

    if (!lcv) {
        return;
    }
    COVERAGE_INC(lflow_cache_add_conj_id);
    lcv->conj_id_ofs = conj_id_ofs;
}

void
lflow_cache_add_expr(struct lflow_cache *lc, const struct uuid *lflow_uuid,
                     uint32_t conj_id_ofs, struct expr *expr, size_t expr_sz)
{
    struct lflow_cache_value *lcv =
        lflow_cache_add__(lc, lflow_uuid, LCACHE_T_EXPR, expr_sz);

    if (!lcv) {
        expr_destroy(expr);
        return;
    }
    COVERAGE_INC(lflow_cache_add_expr);
    lcv->conj_id_ofs = conj_id_ofs;
    lcv->expr = expr;
}

void
lflow_cache_add_matches(struct lflow_cache *lc, const struct uuid *lflow_uuid,
                        struct hmap *matches, size_t matches_sz)
{
    struct lflow_cache_value *lcv =
        lflow_cache_add__(lc, lflow_uuid, LCACHE_T_MATCHES, matches_sz);

    if (!lcv) {
        expr_matches_destroy(matches);
        free(matches);
        return;
    }
    COVERAGE_INC(lflow_cache_add_matches);
    lcv->expr_matches = matches;
}

struct lflow_cache_value *
lflow_cache_get(struct lflow_cache *lc, const struct uuid *lflow_uuid)
{
    if (!lflow_cache_is_enabled(lc)) {
        return NULL;
    }

    size_t hash = uuid_hash(lflow_uuid);

    for (size_t i = 0; i < LCACHE_T_MAX; i++) {
        struct lflow_cache_entry *lce;

        HMAP_FOR_EACH_WITH_HASH (lce, node, hash, &lc->entries[i]) {
            if (uuid_equals(&lce->lflow_uuid, lflow_uuid)) {
                COVERAGE_INC(lflow_cache_hit);
                return &lce->value;
            }
        }
    }
    COVERAGE_INC(lflow_cache_miss);
    return NULL;
}

void
lflow_cache_delete(struct lflow_cache *lc, const struct uuid *lflow_uuid)
{
    if (!lc) {
        return;
    }

    struct lflow_cache_value *lcv = lflow_cache_get(lc, lflow_uuid);
    if (lcv) {
        COVERAGE_INC(lflow_cache_delete);
        lflow_cache_delete__(lc, CONTAINER_OF(lcv, struct lflow_cache_entry,
                                              value));
    }
}

static size_t
lflow_cache_n_entries__(const struct lflow_cache *lc)
{
    size_t n_entries = 0;

    for (size_t i = 0; i < LCACHE_T_MAX; i++) {
        n_entries += hmap_count(&lc->entries[i]);
    }
    return n_entries;
}

static bool
lflow_cache_make_room__(struct lflow_cache *lc, enum lflow_cache_type type)
{
    /* When the cache becomes full, the rule is to prefer more "important"
     * cache entries over less "important" ones.  That is, evict entries of
     * type LCACHE_T_CONJ_ID if there's no room to add an entry of type
     * LCACHE_T_EXPR.  Similarly, evict entries of type LCACHE_T_CONJ_ID or
     * LCACHE_T_EXPR if there's no room to add an entry of type
     * LCACHE_T_MATCHES.
     */
    for (size_t i = 0; i < type; i++) {
        if (hmap_count(&lc->entries[i]) > 0) {
            struct lflow_cache_entry *lce =
                CONTAINER_OF(hmap_first(&lc->entries[i]),
                             struct lflow_cache_entry, node);

            lflow_cache_delete__(lc, lce);
            return true;
        }
    }
    return false;
}

void
lflow_cache_get_memory_usage(const struct lflow_cache *lc, struct simap *usage)
{
    for (size_t i = 0; i < LCACHE_T_MAX; i++) {
        char *counter_name = xasprintf("lflow-cache-entries-%s",
                                       lflow_cache_type_names[i]);
        simap_increase(usage, counter_name, hmap_count(&lc->entries[i]));
        free(counter_name);
    }
    simap_increase(usage, "lflow-cache-size-KB",
                   ROUND_UP(lc->mem_usage, 1024) / 1024);
}

static struct lflow_cache_value *
lflow_cache_add__(struct lflow_cache *lc, const struct uuid *lflow_uuid,
                  enum lflow_cache_type type, uint64_t value_size)
{
    if (!lflow_cache_is_enabled(lc) || !lflow_uuid) {
        return NULL;
    }

    struct lflow_cache_entry *lce;
    size_t size = sizeof *lce + value_size;
    if (size + lc->mem_usage > lc->max_mem_usage) {
        COVERAGE_INC(lflow_cache_mem_full);
        return NULL;
    }

    if (lflow_cache_n_entries__(lc) == lc->capacity) {
        if (!lflow_cache_make_room__(lc, type)) {
            COVERAGE_INC(lflow_cache_full);
            return NULL;
        } else {
            COVERAGE_INC(lflow_cache_made_room);
        }
    }

    lc->mem_usage += size;

    COVERAGE_INC(lflow_cache_add);
    lce = xzalloc(sizeof *lce);
    lce->lflow_uuid = *lflow_uuid;
    lce->size = size;
    lce->value.type = type;
    hmap_insert(&lc->entries[type], &lce->node, uuid_hash(lflow_uuid));
    return &lce->value;
}

static void
lflow_cache_delete__(struct lflow_cache *lc, struct lflow_cache_entry *lce)
{
    if (!lce) {
        return;
    }

    hmap_remove(&lc->entries[lce->value.type], &lce->node);
    switch (lce->value.type) {
    case LCACHE_T_NONE:
        OVS_NOT_REACHED();
        break;
    case LCACHE_T_CONJ_ID:
        COVERAGE_INC(lflow_cache_free_conj_id);
        break;
    case LCACHE_T_EXPR:
        COVERAGE_INC(lflow_cache_free_expr);
        expr_destroy(lce->value.expr);
        break;
    case LCACHE_T_MATCHES:
        COVERAGE_INC(lflow_cache_free_matches);
        expr_matches_destroy(lce->value.expr_matches);
        free(lce->value.expr_matches);
        break;
    }

    ovs_assert(lc->mem_usage >= lce->size);
    lc->mem_usage -= lce->size;
    free(lce);
}
