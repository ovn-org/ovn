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

#include "test-utils.h"

#include "util.h"

bool
test_read_uint_value(struct ovs_cmdl_context *ctx, unsigned int index,
                     const char *descr, unsigned int *result)
{
    if (index >= ctx->argc) {
        fprintf(stderr, "Missing %s argument\n", descr);
        return false;
    }

    const char *arg = ctx->argv[index];
    if (!str_to_uint(arg, 10, result)) {
        fprintf(stderr, "Invalid %s: %s\n", descr, arg);
        return false;
    }
    return true;
}

const char *
test_read_value(struct ovs_cmdl_context *ctx, unsigned int index,
                const char *descr)
{
    if (index >= ctx->argc) {
        fprintf(stderr, "Missing %s argument\n", descr);
        return NULL;
    }

    return ctx->argv[index];
}
