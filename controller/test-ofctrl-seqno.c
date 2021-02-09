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

#include "tests/ovstest.h"
#include "tests/test-utils.h"
#include "sort.h"
#include "util.h"

#include "ofctrl-seqno.h"

static void
test_init(void)
{
    ofctrl_seqno_init();
}

static int
test_seqno_compare(size_t a, size_t b, void *values_)
{
    uint64_t *values = values_;

    return values[a] == values[b] ? 0 : (values[a] < values[b] ? -1 : 1);
}

static void
test_seqno_swap(size_t a, size_t b, void *values_)
{
    uint64_t *values = values_;
    uint64_t tmp = values[a];

    values[a] = values[b];
    values[b] = tmp;
}

static void
test_dump_acked_seqnos(size_t seqno_type)
{
    struct ofctrl_acked_seqnos * acked_seqnos =
        ofctrl_acked_seqnos_get(seqno_type);

    printf("ofctrl-seqno-type: %"PRIuSIZE"\n", seqno_type);
    printf("  last-acked %"PRIu64"\n", acked_seqnos->last_acked);

    size_t n_acked = hmap_count(&acked_seqnos->acked);
    uint64_t *acked = xmalloc(n_acked * sizeof *acked);
    struct ofctrl_ack_seqno *ack_seqno;
    size_t i = 0;

    /* A bit hacky but ignoring overflows the "total of all seqno + 1" should
     * be a number that is not part of the acked seqnos.
     */
    uint64_t total_seqno = 1;
    HMAP_FOR_EACH (ack_seqno, node, &acked_seqnos->acked) {
        ovs_assert(ofctrl_acked_seqnos_contains(acked_seqnos,
                                                ack_seqno->seqno));
        total_seqno += ack_seqno->seqno;
        acked[i++] = ack_seqno->seqno;
    }
    ovs_assert(!ofctrl_acked_seqnos_contains(acked_seqnos, total_seqno));

    sort(n_acked, test_seqno_compare, test_seqno_swap, acked);

    for (i = 0; i < n_acked; i++) {
        printf("  %"PRIu64"\n", acked[i]);
    }

    free(acked);
    ofctrl_acked_seqnos_destroy(acked_seqnos);
}

static void
test_ofctrl_seqno_add_type(struct ovs_cmdl_context *ctx)
{
    unsigned int n_types;

    test_init();

    if (!test_read_uint_value(ctx, 1, "n_types", &n_types)) {
        return;
    }
    for (unsigned int i = 0; i < n_types; i++) {
        printf("%"PRIuSIZE"\n", ofctrl_seqno_add_type());
    }
}

static void
test_ofctrl_seqno_ack_seqnos(struct ovs_cmdl_context *ctx)
{
    unsigned int n_reqs = 0;
    unsigned int shift = 2;
    unsigned int n_types;
    unsigned int n_acks;

    test_init();
    bool batch_acks = !strcmp(ctx->argv[1], "true");

    if (!test_read_uint_value(ctx, shift++, "n_types", &n_types)) {
        return;
    }

    for (unsigned int i = 0; i < n_types; i++) {
        ovs_assert(ofctrl_seqno_add_type() == i);

        /* Read number of app specific seqnos. */
        unsigned int n_app_seqnos;

        if (!test_read_uint_value(ctx, shift++, "n_app_seqnos",
                                  &n_app_seqnos)) {
            return;
        }

        for (unsigned int j = 0; j < n_app_seqnos; j++, n_reqs++) {
            unsigned int app_seqno;

            if (!test_read_uint_value(ctx, shift++, "app_seqno", &app_seqno)) {
                return;
            }
            ofctrl_seqno_update_create(i, app_seqno);
        }
    }
    printf("ofctrl-seqno-req-cfg: %u\n", n_reqs);

    if (!test_read_uint_value(ctx, shift++, "n_acks", &n_acks)) {
        return;
    }
    for (unsigned int i = 0; i < n_acks; i++) {
        unsigned int ack_seqno;

        if (!test_read_uint_value(ctx, shift++, "ack_seqno", &ack_seqno)) {
            return;
        }
        ofctrl_seqno_run(ack_seqno);

        if (!batch_acks) {
            for (unsigned int st = 0; st < n_types; st++) {
                test_dump_acked_seqnos(st);
            }
        }
    }
    if (batch_acks) {
        for (unsigned int st = 0; st < n_types; st++) {
            test_dump_acked_seqnos(st);
        }
    }
}

static void
test_ofctrl_seqno_main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    static const struct ovs_cmdl_command commands[] = {
        {"ofctrl_seqno_add_type", NULL, 1, 1,
         test_ofctrl_seqno_add_type, OVS_RO},
        {"ofctrl_seqno_ack_seqnos", NULL, 2, INT_MAX,
         test_ofctrl_seqno_ack_seqnos, OVS_RO},
        {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - 1;
    ctx.argv = argv + 1;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-ofctrl-seqno", test_ofctrl_seqno_main);
