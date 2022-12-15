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
#include "memory-trim.h"
#include "openvswitch/vlog.h"
#include "ovn/expr.h"

VLOG_DEFINE_THIS_MODULE(lflow_cache);

COVERAGE_DEFINE(lflow_cache_flush);
COVERAGE_DEFINE(lflow_cache_add_expr);
COVERAGE_DEFINE(lflow_cache_add_matches);
COVERAGE_DEFINE(lflow_cache_free_expr);
COVERAGE_DEFINE(lflow_cache_free_matches);
COVERAGE_DEFINE(lflow_cache_add);
COVERAGE_DEFINE(lflow_cache_hit);
COVERAGE_DEFINE(lflow_cache_miss);
COVERAGE_DEFINE(lflow_cache_delete);
COVERAGE_DEFINE(lflow_cache_full);
COVERAGE_DEFINE(lflow_cache_mem_full);
COVERAGE_DEFINE(lflow_cache_made_room);
COVERAGE_DEFINE(lflow_cache_trim);

static const char *lflow_cache_type_names[LCACHE_T_MAX] = {
    [LCACHE_T_EXPR]    = "cache-expr",
    [LCACHE_T_MATCHES] = "cache-matches",
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

struct lflow_cache {
    struct hmap entries[LCACHE_T_MAX];
    struct memory_trimmer *mt;
    uint32_t n_entries;
    uint32_t high_watermark;
    uint32_t capacity;
    uint64_t mem_usage;
    uint64_t max_mem_usage;
    uint32_t trim_limit;
    uint32_t trim_wmark_perc;
    uint64_t trim_count;
    bool enabled;
};

struct lflow_cache_entry {
    struct hmap_node node;
    struct uuid lflow_uuid; /* key */
    size_t size;

    struct lflow_cache_value value;
};

static bool lflow_cache_make_room__(struct lflow_cache *lc,
                                    enum lflow_cache_type type);
static struct lflow_cache_value *lflow_cache_add__(
    struct lflow_cache *lc, const struct uuid *lflow_uuid,
    enum lflow_cache_type type, uint64_t value_size);
static void lflow_cache_delete__(struct lflow_cache *lc,
                                 struct lflow_cache_entry *lce);
static void lflow_cache_trim__(struct lflow_cache *lc, bool force);

struct lflow_cache *
lflow_cache_create(void)
{
    struct lflow_cache *lc = xzalloc(sizeof *lc);

    for (size_t i = 0; i < LCACHE_T_MAX; i++) {
        hmap_init(&lc->entries[i]);
    }
    lc->mt = memory_trimmer_create();

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

        HMAP_FOR_EACH_SAFE (lce, node, &lc->entries[i]) {
            lflow_cache_delete__(lc, lce);
        }
    }
    lflow_cache_trim__(lc, true);
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
    memory_trimmer_destroy(lc->mt);
    free(lc);
}

void
lflow_cache_enable(struct lflow_cache *lc, bool enabled, uint32_t capacity,
                   uint64_t max_mem_usage_kb, uint32_t lflow_trim_limit,
                   uint32_t trim_wmark_perc, uint32_t trim_timeout_ms)
{
    if (!lc) {
        return;
    }

    if (trim_wmark_perc > 100) {
        VLOG_WARN_RL(&rl, "Invalid requested trim watermark percentage: "
                     "requested %"PRIu32", using 100 instead",
                     trim_wmark_perc);
        trim_wmark_perc = 100;
    }

    uint64_t max_mem_usage = max_mem_usage_kb * 1024;
    bool need_flush = false;
    bool need_trim = false;

    if ((lc->enabled && !enabled)
            || capacity < lc->n_entries
            || max_mem_usage < lc->mem_usage) {
        need_flush = true;
    } else if (lc->enabled
                    && (lc->trim_limit != lflow_trim_limit
                        || lc->trim_wmark_perc != trim_wmark_perc)) {
        need_trim = true;
    }

    lc->enabled = enabled;
    lc->capacity = capacity;
    lc->max_mem_usage = max_mem_usage;
    lc->trim_limit = lflow_trim_limit;
    lc->trim_wmark_perc = trim_wmark_perc;
    memory_trimmer_set(lc->mt, trim_timeout_ms);

    if (need_flush) {
        memory_trimmer_record_activity(lc->mt);
        lflow_cache_flush(lc);
    } else if (need_trim) {
        memory_trimmer_record_activity(lc->mt);
        lflow_cache_trim__(lc, false);
    }
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
    ds_put_format(output, "%-16s: %"PRIu32"\n", "high-watermark",
                  lc->high_watermark);
    ds_put_format(output, "%-16s: %"PRIu32"\n", "total", lc->n_entries);
    for (size_t i = 0; i < LCACHE_T_MAX; i++) {
        ds_put_format(output, "%-16s: %"PRIuSIZE"\n",
                      lflow_cache_type_names[i],
                      hmap_count(&lc->entries[i]));
    }
    ds_put_format(output, "%-16s: %"PRIu64"\n", "trim count", lc->trim_count);
    ds_put_format(output, "%-16s: %"PRIu64"\n", "Mem usage (KB)",
                  ROUND_UP(lc->mem_usage, 1024) / 1024);
}

void
lflow_cache_add_expr(struct lflow_cache *lc, const struct uuid *lflow_uuid,
                     struct expr *expr, size_t expr_sz)
{
    struct lflow_cache_value *lcv =
        lflow_cache_add__(lc, lflow_uuid, LCACHE_T_EXPR, expr_sz);

    if (!lcv) {
        expr_destroy(expr);
        return;
    }
    COVERAGE_INC(lflow_cache_add_expr);
    lcv->expr = expr;
}

void
lflow_cache_add_matches(struct lflow_cache *lc, const struct uuid *lflow_uuid,
                        uint32_t conj_id_ofs, uint32_t n_conjs,
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
    lcv->n_conjs = n_conjs;
    lcv->conj_id_ofs = conj_id_ofs;
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
        lflow_cache_trim__(lc, false);
        memory_trimmer_record_activity(lc->mt);
    }
}

static bool
lflow_cache_make_room__(struct lflow_cache *lc, enum lflow_cache_type type)
{
    /* When the cache becomes full, the rule is to prefer more "important"
     * cache entries over less "important" ones.  That is, evict entries of
     * type LCACHE_T_EXPR if there's no room to add an entry of type
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

void
lflow_cache_run(struct lflow_cache *lc)
{
    if (memory_trimmer_can_run(lc->mt)) {
        lflow_cache_trim__(lc, true);
    }
}

void
lflow_cache_wait(struct lflow_cache *lc)
{
    memory_trimmer_wait(lc->mt);
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

    if (lc->n_entries == lc->capacity) {
        if (!lflow_cache_make_room__(lc, type)) {
            COVERAGE_INC(lflow_cache_full);
            return NULL;
        } else {
            COVERAGE_INC(lflow_cache_made_room);
        }
    }

    memory_trimmer_record_activity(lc->mt);
    lc->mem_usage += size;

    COVERAGE_INC(lflow_cache_add);
    lce = xzalloc(sizeof *lce);
    lce->lflow_uuid = *lflow_uuid;
    lce->size = size;
    lce->value.type = type;
    hmap_insert(&lc->entries[type], &lce->node, uuid_hash(lflow_uuid));
    lc->n_entries++;
    lc->high_watermark = MAX(lc->high_watermark, lc->n_entries);
    return &lce->value;
}

static void
lflow_cache_delete__(struct lflow_cache *lc, struct lflow_cache_entry *lce)
{
    ovs_assert(lc->n_entries > 0);
    hmap_remove(&lc->entries[lce->value.type], &lce->node);
    lc->n_entries--;
    switch (lce->value.type) {
    case LCACHE_T_NONE:
        OVS_NOT_REACHED();
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

static void
lflow_cache_trim__(struct lflow_cache *lc, bool force)
{
    /* Trim if we had at least 'TRIM_LIMIT' elements at some point and if the
     * current usage is less than half of 'high_watermark'.
     */
    uint32_t upper_trim_limit = lc->high_watermark * lc->trim_wmark_perc / 100;
    ovs_assert(lc->high_watermark >= lc->n_entries);
    if (!force
            && (lc->high_watermark <= lc->trim_limit
                || lc->n_entries > upper_trim_limit)) {
        return;
    }

    COVERAGE_INC(lflow_cache_trim);
    for (size_t i = 0; i < LCACHE_T_MAX; i++) {
        hmap_shrink(&lc->entries[i]);
    }

    memory_trimmer_trim(lc->mt);

    lc->high_watermark = lc->n_entries;
    lc->trim_count++;
}
