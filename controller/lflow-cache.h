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

#ifndef LFLOW_CACHE_H
#define LFLOW_CACHE_H 1

#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/uuid.h"
#include "simap.h"

struct lflow_cache;

/* Various lflow cache types which
 *  - store the conjunction id offset if the lflow matches
 *    results in conjunctive OpenvSwitch flows.
 *
 *  - Caches
 *     (1) expr tree if the logical flow doesn't have port group/address set
 *         references but has other references (such as lport).
 *     (2) expr matches if the logical flow doesn't have any references.
 */
enum lflow_cache_type {
    LCACHE_T_EXPR,    /* Expr tree of the logical flow is cached. */
    LCACHE_T_MATCHES, /* Expression matches are cached. */
    LCACHE_T_MAX,
    LCACHE_T_NONE = LCACHE_T_MAX, /* Not found in cache. */
};

struct lflow_cache_value {
    enum lflow_cache_type type;

    /* n_conjs and conj_id_ofs are used only for LCACHE_T_MATCHES.
     * They are saved together with the match, so that we can re-allocate the
     * same ids when reusing the cached match for a given lflow. */
    uint32_t n_conjs;
    uint32_t conj_id_ofs;

    union {
        struct hmap *expr_matches;
        struct expr *expr;
    };
};

struct lflow_cache *lflow_cache_create(void);
void lflow_cache_flush(struct lflow_cache *);
void lflow_cache_destroy(struct lflow_cache *);
void lflow_cache_enable(struct lflow_cache *, bool enabled, uint32_t capacity,
                        uint64_t max_mem_usage_kb, uint32_t lflow_trim_limit,
                        uint32_t trim_wmark_perc, uint32_t trim_timeout_ms);
bool lflow_cache_is_enabled(const struct lflow_cache *);
void lflow_cache_get_stats(const struct lflow_cache *, struct ds *output);

void lflow_cache_add_expr(struct lflow_cache *, const struct uuid *lflow_uuid,
                          struct expr *expr, size_t expr_sz);
void lflow_cache_add_matches(struct lflow_cache *,
                             const struct uuid *lflow_uuid,
                             uint32_t conj_id_ofs, uint32_t n_conjs,
                             struct hmap *matches, size_t matches_sz);

struct lflow_cache_value *lflow_cache_get(struct lflow_cache *,
                                          const struct uuid *lflow_uuid);
void lflow_cache_delete(struct lflow_cache *, const struct uuid *lflow_uuid);

void lflow_cache_get_memory_usage(const struct lflow_cache *,
                                  struct simap *usage);

void lflow_cache_run(struct lflow_cache *);
void lflow_cache_wait(struct lflow_cache *);

#endif /* controller/lflow-cache.h */
