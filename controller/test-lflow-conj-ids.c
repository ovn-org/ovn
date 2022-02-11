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

#include "tests/ovstest.h"
#include "tests/test-utils.h"
#include "util.h"
#include "lib/uuid.h"

#include "lflow-conj-ids.h"

static bool
parse_lflow_uuid(struct ovs_cmdl_context *ctx, unsigned int shift,
                 struct uuid *uuid)
{
    const char *uuid_s = test_read_value(ctx, shift++, "lflow_uuid");
    if (!uuid_s) {
        return false;
    }
    if (!uuid_from_string(uuid, uuid_s)) {
        printf("Expected uuid, got %s.\n", uuid_s);
        return false;
    }
    return true;
}

static void
test_conj_ids_operations(struct ovs_cmdl_context *ctx)
{
    unsigned int shift = 1;
    unsigned int n_ops;
    struct conj_ids conj_ids;
    struct uuid dp_uuid = UUID_ZERO;
    lflow_conj_ids_init(&conj_ids);
    lflow_conj_ids_set_test_mode(true);

    if (!test_read_uint_value(ctx, shift++, "n_ops", &n_ops)) {
        goto done;
    }

    for (unsigned int i = 0; i < n_ops; i++) {
        const char *op = test_read_value(ctx, shift++, "op");

        if (!op) {
            goto done;
        }

        if (!strcmp(op, "alloc")) {
            struct uuid uuid;
            if (!parse_lflow_uuid(ctx, shift++, &uuid)) {
                goto done;
            }

            unsigned int n_conjs;
            if (!test_read_uint_value(ctx, shift++, "n_conjs", &n_conjs)) {
                goto done;
            }

            uint32_t start_conj_id = lflow_conj_ids_alloc(&conj_ids, &uuid,
                                                          &dp_uuid, n_conjs);
            printf("alloc("UUID_FMT", %"PRIu32"): 0x%"PRIx32"\n",
                   UUID_ARGS(&uuid), n_conjs, start_conj_id);
        } else if (!strcmp(op, "alloc-specified")) {
            struct uuid uuid;
            if (!parse_lflow_uuid(ctx, shift++, &uuid)) {
                goto done;
            }

            unsigned int start_conj_id;
            if (!test_read_uint_hex_value(ctx, shift++, "start_conj_id",
                                          &start_conj_id)) {
                goto done;
            }

            unsigned int n_conjs;
            if (!test_read_uint_value(ctx, shift++, "n_conjs", &n_conjs)) {
                goto done;
            }

            bool ret = lflow_conj_ids_alloc_specified(&conj_ids, &uuid,
                                                      &dp_uuid, start_conj_id,
                                                      n_conjs);
            printf("alloc_specified("UUID_FMT", 0x%"PRIx32", %"PRIu32"): %s\n",
                   UUID_ARGS(&uuid), start_conj_id, n_conjs,
                   ret ? "true" : "false");
        } else if (!strcmp(op, "free")) {
            struct uuid uuid;
            if (!parse_lflow_uuid(ctx, shift++, &uuid)) {
                goto done;
            }
            lflow_conj_ids_free(&conj_ids, &uuid);
            printf("free("UUID_FMT")\n", UUID_ARGS(&uuid));
        } else {
            printf("Unknown operation: %s\n", op);
            goto done;
        }
    }
    struct ds conj_ids_dump = DS_EMPTY_INITIALIZER;
    lflow_conj_ids_dump(&conj_ids, &conj_ids_dump);
    printf("%s", ds_cstr(&conj_ids_dump));
    ds_destroy(&conj_ids_dump);

done:
    lflow_conj_ids_destroy(&conj_ids);
}

static void
test_lflow_conj_ids_main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    static const struct ovs_cmdl_command commands[] = {
        {"operations", NULL, 1, INT_MAX,
         test_conj_ids_operations, OVS_RO},
        {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - 1;
    ctx.argv = argv + 1;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-lflow-conj-ids", test_lflow_conj_ids_main);
