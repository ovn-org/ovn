/* Copyright (c) 2026, Red Hat, Inc.
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
#include <stdint.h>

#include "tests/ovstest.h"
#include "lib/ovn-util.h"
#include "lib/spsc-ring.h"

/* Basic push and pop with data integrity check. */
static void
test_basic(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct spsc_ring ring;
    spsc_ring_init(&ring, 16, sizeof(uint32_t));

    uint32_t val;

    /* Pop on empty ring returns false. */
    ovs_assert(!spsc_ring_pop(&ring, &val));

    /* Push one element and pop it. */
    val = 42;
    ovs_assert(spsc_ring_push(&ring, &val));
    val = 0;
    ovs_assert(spsc_ring_pop(&ring, &val));
    ovs_assert(val == 42);

    /* Ring is empty again. */
    ovs_assert(!spsc_ring_pop(&ring, &val));

    spsc_ring_destroy(&ring);
}

/* FIFO ordering: push a sequence, pop and verify order. */
static void
test_fifo(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct spsc_ring ring;
    spsc_ring_init(&ring, 64, sizeof(uint32_t));

    for (uint32_t i = 0; i < 50; i++) {
        ovs_assert(spsc_ring_push(&ring, &i));
    }

    for (uint32_t i = 0; i < 50; i++) {
        uint32_t val;
        ovs_assert(spsc_ring_pop(&ring, &val));
        ovs_assert(val == i);
    }

    uint32_t val;
    ovs_assert(!spsc_ring_pop(&ring, &val));

    spsc_ring_destroy(&ring);
}

/* Fill ring to capacity, verify push fails, pop one, push succeeds. */
static void
test_full(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct spsc_ring ring;
    spsc_ring_init(&ring, 8, sizeof(uint32_t));

    /* Fill all 8 slots. */
    for (uint32_t i = 0; i < 8; i++) {
        ovs_assert(spsc_ring_push(&ring, &i));
    }

    /* 9th push must fail. */
    uint32_t overflow = 99;
    ovs_assert(!spsc_ring_push(&ring, &overflow));

    /* Pop one element. */
    uint32_t val;
    ovs_assert(spsc_ring_pop(&ring, &val));
    ovs_assert(val == 0);

    /* Now push succeeds. */
    ovs_assert(spsc_ring_push(&ring, &overflow));

    /* Drain and verify: 1..7, then 99. */
    for (uint32_t i = 1; i <= 7; i++) {
        ovs_assert(spsc_ring_pop(&ring, &val));
        ovs_assert(val == i);
    }
    ovs_assert(spsc_ring_pop(&ring, &val));
    ovs_assert(val == 99);

    ovs_assert(!spsc_ring_pop(&ring, &val));

    spsc_ring_destroy(&ring);
}

/* Wraparound: push/pop many times to wrap head/tail past UINT32_MAX. */
static void
test_wraparound(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct spsc_ring ring;
    spsc_ring_init(&ring, 4, sizeof(uint32_t));

    /* Push and pop one-at-a-time many times to advance read/write.
     * After 2^32 iterations the indices would wrap, but we can't run
     * that many.  Instead, manually set read/write near UINT32_MAX to
     * test the wraparound arithmetic. */
    atomic_store(&ring.read, UINT32_MAX - 2);
    atomic_store(&ring.write, UINT32_MAX - 2);

    /* Push 4 elements (fills the ring, wrapping tail past UINT32_MAX). */
    for (uint32_t i = 0; i < 4; i++) {
        ovs_assert(spsc_ring_push(&ring, &i));
    }

    /* Ring is full. */
    uint32_t overflow = 99;
    ovs_assert(!spsc_ring_push(&ring, &overflow));

    /* Pop all 4, verify FIFO order. */
    for (uint32_t i = 0; i < 4; i++) {
        uint32_t val;
        ovs_assert(spsc_ring_pop(&ring, &val));
        ovs_assert(val == i);
    }

    /* Empty. */
    uint32_t val;
    ovs_assert(!spsc_ring_pop(&ring, &val));

    spsc_ring_destroy(&ring);
}

/* Test SPSC_RING_FOR_EACH_POP macro. */
static void
test_for_each_pop(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct spsc_ring ring;
    spsc_ring_init(&ring, 32, sizeof(uint32_t));

    for (uint32_t i = 0; i < 20; i++) {
        ovs_assert(spsc_ring_push(&ring, &i));
    }

    uint32_t count = 0;
    uint32_t val;
    SPSC_RING_FOR_EACH_POP (&ring, val) {
        ovs_assert(val == count);
        count++;
    }
    ovs_assert(count == 20);

    /* Ring is empty after iteration. */
    ovs_assert(!spsc_ring_pop(&ring, &val));

    spsc_ring_destroy(&ring);
}

/* Test with a multi-field struct. */
struct test_element {
    uint64_t key;
    uint32_t value;
    uint8_t  tag;
};

static void
test_struct(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct spsc_ring ring;
    spsc_ring_init(&ring, 16, sizeof(struct test_element));

    for (uint64_t i = 0; i < 10; i++) {
        struct test_element elem = {
            .key = i * 1000,
            .value = (uint32_t) i,
            .tag = (uint8_t) (i & 0xff),
        };
        ovs_assert(spsc_ring_push(&ring, &elem));
    }

    struct test_element out;
    uint64_t count = 0;
    SPSC_RING_FOR_EACH_POP (&ring, out) {
        ovs_assert(out.key == count * 1000);
        ovs_assert(out.value == (uint32_t) count);
        ovs_assert(out.tag == (uint8_t) (count & 0xff));
        count++;
    }
    ovs_assert(count == 10);

    spsc_ring_destroy(&ring);
}

static void
test_spsc_ring_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    ovn_set_program_name(argv[0]);
    static const struct ovs_cmdl_command commands[] = {
        {"basic", NULL, 0, 0, test_basic, OVS_RO},
        {"fifo", NULL, 0, 0, test_fifo, OVS_RO},
        {"full", NULL, 0, 0, test_full, OVS_RO},
        {"wraparound", NULL, 0, 0, test_wraparound, OVS_RO},
        {"for-each-pop", NULL, 0, 0, test_for_each_pop, OVS_RO},
        {"struct", NULL, 0, 0, test_struct, OVS_RO},
        {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - 1;
    ctx.argv = argv + 1;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-spsc-ring", test_spsc_ring_main);
