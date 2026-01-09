/* Copyright (c) 2025, Red Hat, Inc.
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

#include "lib/sparse-array.h"
#include "tests/ovstest.h"

struct array_elem {
    int int_member;
    const char * str;
};

static void
test_add(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    const struct tester {
        struct array_elem elem;
        size_t index;
        bool add_with_index;
        size_t expected_capacity;
    } test_vals[] = {
        /* The first 5 elements are added to the first available index. */
        {{0, "zero" },  0, false,  1},
        {{1, "one"  },  1, false,  2},
        {{2, "two"  },  2, false,  4},
        {{3, "three"},  3, false,  4},
        {{4, "four" },  4, false,  8},
        /* The final two elements are added with custom indexes. */
        {{5, "five" }, 15,  true, 16},
        {{6, "six"  }, 40,  true, 41},
    };
    const struct tester *iter;
    const struct array_elem *under_test;

    struct sparse_array test_array;
    sparse_array_init(&test_array, 0);
    ovs_assert(test_array.capacity == 0);

    for (size_t i = 0; i < ARRAY_SIZE(test_vals); i++) {
        size_t index;
        iter = &test_vals[i];
        under_test = &iter->elem;
        if (iter->add_with_index) {
            index = iter->index;
            sparse_array_add_at(&test_array, under_test, index);
        } else {
            index = sparse_array_add(&test_array, under_test);
        }

        ovs_assert(index == iter->index);
        ovs_assert(test_array.capacity == iter->expected_capacity);
        ovs_assert(test_array.bitmap.n_elems == (i + 1));
        ovs_assert(sparse_array_len(&test_array) == (test_vals[i].index + 1));
        under_test = sparse_array_get(&test_array, index);
        ovs_assert(under_test->int_member == iter->elem.int_member);
        ovs_assert(!strcmp(under_test->str, iter->elem.str));
    }

    /* Ensure iteration with a gap succeeds */
    size_t tester_index = 0;
    SPARSE_ARRAY_FOR_EACH (&test_array, under_test) {
        const struct array_elem *expected = &test_vals[tester_index].elem;
        ovs_assert(under_test->int_member == expected->int_member);
        ovs_assert(!strcmp(under_test->str, expected->str));
        tester_index++;
    }
    sparse_array_destroy(&test_array);
}

static struct array_elem *
allocate_array_elem(int int_member, const char * str)
{
    struct array_elem *elem = xmalloc(sizeof *elem);
    *elem = (struct array_elem) {
        .int_member = int_member,
        .str = str,
    };
    return elem;
}

static void
test_remove_replace(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct sparse_array test_array;

    struct array_elem *item_one = allocate_array_elem(1, "one");
    struct array_elem *item_two = allocate_array_elem(2, "two");
    struct array_elem *item_three = allocate_array_elem(3, "three");
    struct array_elem *item_four = allocate_array_elem(4, "four");
    struct array_elem *item_five = allocate_array_elem(5, "five");
    struct array_elem *under_test;

    sparse_array_init(&test_array, 0);

    /* The add() test already ensured basic initialization and addition
     * works, so we will only test values after removal or replacement.
     */
    sparse_array_add(&test_array, item_one);
    sparse_array_add(&test_array, item_two);
    sparse_array_add(&test_array, item_three);

    ovs_assert(test_array.bitmap.n_elems == 3);
    ovs_assert(sparse_array_len(&test_array) == 3);
    ovs_assert(sparse_array_get(&test_array, 0) == item_one);
    ovs_assert(sparse_array_get(&test_array, 1) == item_two);
    ovs_assert(sparse_array_get(&test_array, 2) == item_three);

    under_test = sparse_array_remove(&test_array, 1);
    ovs_assert(under_test == item_two);
    ovs_assert(test_array.bitmap.n_elems == 2);
    ovs_assert(sparse_array_len(&test_array) == 3);
    ovs_assert(sparse_array_get(&test_array, 0) == item_one);
    ovs_assert(sparse_array_get(&test_array, 1) == NULL);
    ovs_assert(sparse_array_get(&test_array, 2) == item_three);

    /* The sparse array has a hole in it. The next item we add should
     * fill in the hole.
     */
    sparse_array_add(&test_array, item_four);
    ovs_assert(test_array.bitmap.n_elems == 3);
    ovs_assert(sparse_array_len(&test_array) == 3);
    ovs_assert(sparse_array_get(&test_array, 0) == item_one);
    ovs_assert(sparse_array_get(&test_array, 1) == item_four);
    ovs_assert(sparse_array_get(&test_array, 2) == item_three);

    /* Replace the item at index 2. */
    under_test = sparse_array_add_at(&test_array, item_five, 2);
    ovs_assert(under_test == item_three);
    ovs_assert(test_array.bitmap.n_elems == 3);
    ovs_assert(sparse_array_len(&test_array) == 3);
    ovs_assert(sparse_array_get(&test_array, 0) == item_one);
    ovs_assert(sparse_array_get(&test_array, 1) == item_four);
    ovs_assert(sparse_array_get(&test_array, 2) == item_five);

    /* Test out of bounds retrieval/removal. */

    /* Ensure we don't have off-by-one errors. */
    under_test = sparse_array_get(&test_array, 3);
    ovs_assert(under_test == NULL);
    /* And test something that is beyond the array capacity. */
    under_test = sparse_array_get(&test_array, 100);
    ovs_assert(under_test == NULL);

    /* Test off-by-one again. */
    under_test = sparse_array_get(&test_array, 3);
    ovs_assert(under_test == NULL);
    /* Test a big value again. */
    under_test = sparse_array_get(&test_array, 100);
    ovs_assert(under_test == NULL);

    struct array_elem *elems[] = {
        item_one,
        item_four,
        item_five,
    };
    size_t test_index = 0;
    size_t n_elems = 3;
    SPARSE_ARRAY_FOR_EACH (&test_array, under_test) {
        struct array_elem *removed = sparse_array_remove(&test_array,
                                                         test_index);
        n_elems--;
        ovs_assert(removed == under_test);
        ovs_assert(under_test == elems[test_index]);
        ovs_assert(test_array.bitmap.n_elems == n_elems);
        ovs_assert(sparse_array_len(&test_array) == (n_elems ? 3 : 0));
        test_index++;
    }
    ovs_assert(test_array.bitmap.n_elems == 0);

    sparse_array_destroy(&test_array);
    free(item_one);
    free(item_two);
    free(item_three);
    free(item_four);
    free(item_five);
}

static void
test_sparse_array_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    ovn_set_program_name(argv[0]);
    static const struct ovs_cmdl_command commands[] = {
        {"add",            NULL, 0, 0, test_add,            OVS_RO},
        {"remove-replace", NULL, 0, 0, test_remove_replace, OVS_RO},
        {NULL,             NULL, 0, 0, NULL,                OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - 1;
    ctx.argv = argv + 1;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-sparse-array", test_sparse_array_main);
