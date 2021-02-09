/* Copyright (c) 2021, Red Hat, Inc.
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

#include "lib/uuid.h"
#include "ovn/expr.h"
#include "tests/ovstest.h"
#include "tests/test-utils.h"
#include "util.h"

#include "lflow-cache.h"

/* Simulate 1KB large cache values. */
#define TEST_LFLOW_CACHE_VALUE_SIZE 1024

static void
test_lflow_cache_add__(struct lflow_cache *lc, const char *op_type,
                       const struct uuid *lflow_uuid,
                       unsigned int conj_id_ofs,
                       struct expr *e)
{
    printf("ADD %s:\n", op_type);
    printf("  conj-id-ofs: %u\n", conj_id_ofs);

    if (!strcmp(op_type, "conj-id")) {
        lflow_cache_add_conj_id(lc, lflow_uuid, conj_id_ofs);
    } else if (!strcmp(op_type, "expr")) {
        lflow_cache_add_expr(lc, lflow_uuid, conj_id_ofs, expr_clone(e),
                             TEST_LFLOW_CACHE_VALUE_SIZE);
    } else if (!strcmp(op_type, "matches")) {
        struct hmap *matches = xmalloc(sizeof *matches);
        ovs_assert(expr_to_matches(e, NULL, NULL, matches) == 0);
        ovs_assert(hmap_count(matches) == 1);
        lflow_cache_add_matches(lc, lflow_uuid, matches,
                                TEST_LFLOW_CACHE_VALUE_SIZE);
    } else {
        OVS_NOT_REACHED();
    }
}

static void
test_lflow_cache_lookup__(struct lflow_cache *lc,
                          const struct uuid *lflow_uuid)
{
    struct lflow_cache_value *lcv = lflow_cache_get(lc, lflow_uuid);

    printf("LOOKUP:\n");
    if (!lcv) {
        printf("  not found\n");
        return;
    }

    printf("  conj_id_ofs: %"PRIu32"\n", lcv->conj_id_ofs);
    switch (lcv->type) {
    case LCACHE_T_CONJ_ID:
        printf("  type: conj-id\n");
        break;
    case LCACHE_T_EXPR:
        printf("  type: expr\n");
        break;
    case LCACHE_T_MATCHES:
        printf("  type: matches\n");
        break;
    case LCACHE_T_NONE:
        OVS_NOT_REACHED();
        break;
    }
}

static void
test_lflow_cache_delete__(struct lflow_cache *lc,
                          const struct uuid *lflow_uuid)
{
    printf("DELETE\n");
    lflow_cache_delete(lc, lflow_uuid);
}

static void
test_lflow_cache_stats__(struct lflow_cache *lc)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    lflow_cache_get_stats(lc, &ds);
    printf("%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
test_lflow_cache_operations(struct ovs_cmdl_context *ctx)
{
    struct lflow_cache *lc = lflow_cache_create();
    struct expr *e = expr_create_boolean(true);
    bool enabled = !strcmp(ctx->argv[1], "true");
    unsigned int shift = 2;
    unsigned int n_ops;

    lflow_cache_enable(lc, enabled, UINT32_MAX, UINT32_MAX);
    test_lflow_cache_stats__(lc);

    if (!test_read_uint_value(ctx, shift++, "n_ops", &n_ops)) {
        goto done;
    }

    for (unsigned int i = 0; i < n_ops; i++) {
        const char *op = test_read_value(ctx, shift++, "op");

        if (!op) {
            goto done;
        }

        struct uuid lflow_uuid;
        uuid_generate(&lflow_uuid);

        if (!strcmp(op, "add")) {
            const char *op_type = test_read_value(ctx, shift++, "op_type");
            if (!op_type) {
                goto done;
            }

            unsigned int conj_id_ofs;
            if (!test_read_uint_value(ctx, shift++, "conj-id-ofs",
                                      &conj_id_ofs)) {
                goto done;
            }

            test_lflow_cache_add__(lc, op_type, &lflow_uuid, conj_id_ofs, e);
            test_lflow_cache_lookup__(lc, &lflow_uuid);
        } else if (!strcmp(op, "add-del")) {
            const char *op_type = test_read_value(ctx, shift++, "op_type");
            if (!op_type) {
                goto done;
            }

            unsigned int conj_id_ofs;
            if (!test_read_uint_value(ctx, shift++, "conj-id-ofs",
                                      &conj_id_ofs)) {
                goto done;
            }

            test_lflow_cache_add__(lc, op_type, &lflow_uuid, conj_id_ofs, e);
            test_lflow_cache_lookup__(lc, &lflow_uuid);
            test_lflow_cache_delete__(lc, &lflow_uuid);
            test_lflow_cache_lookup__(lc, &lflow_uuid);
        } else if (!strcmp(op, "enable")) {
            unsigned int limit;
            unsigned int mem_limit_kb;
            if (!test_read_uint_value(ctx, shift++, "limit", &limit)) {
                goto done;
            }
            if (!test_read_uint_value(ctx, shift++, "mem-limit",
                                      &mem_limit_kb)) {
                goto done;
            }
            printf("ENABLE\n");
            lflow_cache_enable(lc, true, limit, mem_limit_kb);
        } else if (!strcmp(op, "disable")) {
            printf("DISABLE\n");
            lflow_cache_enable(lc, false, UINT32_MAX, UINT32_MAX);
        } else if (!strcmp(op, "flush")) {
            printf("FLUSH\n");
            lflow_cache_flush(lc);
        } else {
            OVS_NOT_REACHED();
        }
        test_lflow_cache_stats__(lc);
    }
done:
    lflow_cache_destroy(lc);
    expr_destroy(e);
}

static void
test_lflow_cache_negative(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    lflow_cache_flush(NULL);
    lflow_cache_destroy(NULL);
    lflow_cache_enable(NULL, true, UINT32_MAX, UINT32_MAX);
    ovs_assert(!lflow_cache_is_enabled(NULL));

    struct ds ds = DS_EMPTY_INITIALIZER;
    lflow_cache_get_stats(NULL, &ds);
    ovs_assert(!strcmp(ds_cstr_ro(&ds), "Invalid arguments."));
    lflow_cache_get_stats(NULL, NULL);
    ds_destroy(&ds);

    struct lflow_cache *lcs[] = {
        NULL,
        lflow_cache_create(),
    };

    for (size_t i = 0; i < ARRAY_SIZE(lcs); i++) {
        struct expr *e = expr_create_boolean(true);
        struct hmap *matches = xmalloc(sizeof *matches);

        ovs_assert(expr_to_matches(e, NULL, NULL, matches) == 0);
        ovs_assert(hmap_count(matches) == 1);

        lflow_cache_add_conj_id(lcs[i], NULL, 0);
        lflow_cache_add_expr(lcs[i], NULL, 0, NULL, 0);
        lflow_cache_add_expr(lcs[i], NULL, 0, e, expr_size(e));
        lflow_cache_add_matches(lcs[i], NULL, NULL, 0);
        lflow_cache_add_matches(lcs[i], NULL, matches,
                                TEST_LFLOW_CACHE_VALUE_SIZE);
        lflow_cache_destroy(lcs[i]);
    }
}

static void
test_lflow_cache_main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    static const struct ovs_cmdl_command commands[] = {
        {"lflow_cache_operations", NULL, 3, INT_MAX,
         test_lflow_cache_operations, OVS_RO},
        {"lflow_cache_negative", NULL, 0, 0,
         test_lflow_cache_negative, OVS_RO},
        {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - 1;
    ctx.argv = argv + 1;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-lflow-cache", test_lflow_cache_main);
