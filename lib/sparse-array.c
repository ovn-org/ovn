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

#include "sparse-array.h"

void
sparse_array_init(struct sparse_array *array, size_t capacity)
{
    *array = (struct sparse_array) {
        .buffer = xmalloc(sizeof (void *) * capacity),
        .capacity = capacity,
    };
    dynamic_bitmap_alloc(&array->bitmap, capacity);
}

void
sparse_array_destroy(struct sparse_array *array)
{
    free(array->buffer);
    dynamic_bitmap_free(&array->bitmap);
}

static void
sparse_array_expand(struct sparse_array *array, size_t target)
{
    if (target <= array->capacity) {
        return;
    }

    size_t new_capacity =
        target <= array->capacity * 2 ?
        array->capacity * 2 :
        target;
    array->buffer = xrealloc(array->buffer, new_capacity * sizeof (void *));
    array->capacity = new_capacity;
    dynamic_bitmap_realloc(&array->bitmap, new_capacity);
    ovs_assert(array->capacity == array->bitmap.capacity);
}

static size_t
sparse_array_add__(struct sparse_array *array, const void *obj, size_t idx)
{
    sparse_array_expand(array, idx + 1);
    array->buffer[idx] = CONST_CAST(void *, obj);
    dynamic_bitmap_set1(&array->bitmap, idx);
    return idx;
}

size_t
sparse_array_add(struct sparse_array *array, const void *obj)
{
    size_t idx = dynamic_bitmap_scan(&array->bitmap, false, 0);
    return sparse_array_add__(array, obj, idx);
}

void *
sparse_array_remove(struct sparse_array *array, size_t idx)
{
    if (idx >= array->capacity ||
        !dynamic_bitmap_is_set(&array->bitmap, idx)) {
        return NULL;
    }

    void *ret = sparse_array_get(array, idx);
    dynamic_bitmap_set0(&array->bitmap, idx);

    return ret;
}

void *
sparse_array_add_at(struct sparse_array *array, const void *obj, size_t idx)
{
    void *ret;
    ret = sparse_array_remove(array, idx);
    sparse_array_add__(array, obj, idx);
    return ret;
}

void *
sparse_array_get(const struct sparse_array *array, size_t idx)
{
    if (idx >= array->capacity ||
        !dynamic_bitmap_is_set(&array->bitmap, idx)) {
        return NULL;
    }

    return array->buffer[idx];
}
