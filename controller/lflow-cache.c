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

#include "lflow-cache.h"
#include "lib/uuid.h"
#include "ovn/expr.h"

struct lflow_cache {
    struct hmap entries[LCACHE_T_MAX];
    bool enabled;
};

struct lflow_cache_entry {
    struct hmap_node node;
    struct uuid lflow_uuid; /* key */

    struct lflow_cache_value value;
};

static struct lflow_cache_value *lflow_cache_add__(
    struct lflow_cache *lc, const struct uuid *lflow_uuid,
    enum lflow_cache_type type);
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
    return lc;
}

void
lflow_cache_flush(struct lflow_cache *lc)
{
    if (!lc) {
        return;
    }

    for (size_t i = 0; i < LCACHE_T_MAX; i++) {
        struct lflow_cache_entry *lce;
        struct lflow_cache_entry *lce_next;

        HMAP_FOR_EACH_SAFE (lce, lce_next, node, &lc->entries[i]) {
            lflow_cache_delete__(lc, lce);
        }
    }
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
lflow_cache_enable(struct lflow_cache *lc, bool enabled)
{
    if (!lc) {
        return;
    }

    if (lc->enabled && !enabled) {
        lflow_cache_flush(lc);
    }
    lc->enabled = enabled;
}

bool
lflow_cache_is_enabled(const struct lflow_cache *lc)
{
    return lc && lc->enabled;
}

void
lflow_cache_add_conj_id(struct lflow_cache *lc, const struct uuid *lflow_uuid,
                        uint32_t conj_id_ofs)
{
    struct lflow_cache_value *lcv =
        lflow_cache_add__(lc, lflow_uuid, LCACHE_T_CONJ_ID);

    if (!lcv) {
        return;
    }
    lcv->conj_id_ofs = conj_id_ofs;
}

void
lflow_cache_add_expr(struct lflow_cache *lc, const struct uuid *lflow_uuid,
                     uint32_t conj_id_ofs, struct expr *expr)
{
    struct lflow_cache_value *lcv =
        lflow_cache_add__(lc, lflow_uuid, LCACHE_T_EXPR);

    if (!lcv) {
        expr_destroy(expr);
        return;
    }
    lcv->conj_id_ofs = conj_id_ofs;
    lcv->expr = expr;
}

void
lflow_cache_add_matches(struct lflow_cache *lc, const struct uuid *lflow_uuid,
                        struct hmap *matches)
{
    struct lflow_cache_value *lcv =
        lflow_cache_add__(lc, lflow_uuid, LCACHE_T_MATCHES);

    if (!lcv) {
        expr_matches_destroy(matches);
        free(matches);
        return;
    }
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
                return &lce->value;
            }
        }
    }
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
        lflow_cache_delete__(lc, CONTAINER_OF(lcv, struct lflow_cache_entry,
                                              value));
    }
}

static struct lflow_cache_value *
lflow_cache_add__(struct lflow_cache *lc, const struct uuid *lflow_uuid,
                  enum lflow_cache_type type)
{
    if (!lflow_cache_is_enabled(lc) || !lflow_uuid) {
        return NULL;
    }

    struct lflow_cache_entry *lce = xzalloc(sizeof *lce);

    lce->lflow_uuid = *lflow_uuid;
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
        break;
    case LCACHE_T_EXPR:
        expr_destroy(lce->value.expr);
        break;
    case LCACHE_T_MATCHES:
        expr_matches_destroy(lce->value.expr_matches);
        free(lce->value.expr_matches);
        break;
    }
    free(lce);
}
