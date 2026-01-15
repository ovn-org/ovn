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

#ifndef SPARSE_ARRAY_H
#define SPARSE_ARRAY_H

#include <stddef.h>
#include "ovn-util.h"

struct sparse_array {
    struct dynamic_bitmap bitmap;
    void **buffer;
    /* The memory allocated for the buffer. */
    size_t capacity;
};

void sparse_array_init(struct sparse_array *, size_t capacity);
void sparse_array_destroy(struct sparse_array *);
size_t sparse_array_add(struct sparse_array *, const void *obj);
void *sparse_array_remove(struct sparse_array *, size_t index);
void *sparse_array_add_at(struct sparse_array *, const void *obj,
                          size_t index);
void *sparse_array_get(const struct sparse_array *, size_t index);

static inline size_t
sparse_array_len(const struct sparse_array *array)
{
    ssize_t idx = dynamic_bitmap_last_set(&array->bitmap);
    return idx > -1 ? (size_t) idx + 1 : 0;
}

/* It is safe to destroy array members during traversal, so there
 * is no need for a _SAFE variant
 */
#define SPARSE_ARRAY_FOR_EACH(ARRAY, MEMBER) \
    for (size_t ITER_VAR(IDX) = \
             dynamic_bitmap_scan(&(ARRAY)->bitmap, true, 0); \
         (MEMBER = sparse_array_get((ARRAY), ITER_VAR(IDX))) != NULL; \
         ITER_VAR(IDX) = \
             dynamic_bitmap_scan(&(ARRAY)->bitmap, true, ITER_VAR(IDX) + 1)) \

#endif /* SPARSE_ARRAY_H */
