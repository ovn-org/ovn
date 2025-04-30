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

#ifndef VEC_H
#define VEC_H


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct vector {
    void *buffer;    /* Data bytes. */
    size_t len;         /* Number of elements. */
    size_t esize;       /* Size of each element in bytes. */
    size_t capacity;    /* Element capacity. */
};

#define VECTOR_EMPTY_INITIALIZER(TYPE) \
    (struct vector) {                  \
        .buffer = NULL,                \
        .len = 0,                      \
        .esize = sizeof(TYPE),         \
        .capacity = 0                  \
    }

#define VECTOR_CAPACITY_INITIALIZER(TYPE, CAP)    \
    (struct vector) {                             \
        .buffer = xmalloc(sizeof (TYPE) * (CAP)), \
        .esize = sizeof(TYPE),                    \
        .len = 0,                                 \
        .capacity = (CAP),                        \
    }

/* Note that storing the returned pointer will result in UB, as the vector
 * might change the memory location during insert. */
#define VECTOR_FOR_EACH_PTR(VEC, NODE)                                        \
    for (INIT_MULTIVAR(NODE, 0, (VEC)->buffer, OVS_TYPEOF(*NODE));            \
         (ITER_VAR(NODE) - (OVS_TYPEOF(*NODE) *) (VEC)->buffer < (VEC)->len ? \
            (((NODE) = ITER_VAR(NODE)), 1) :                                  \
            0);                                                               \
         UPDATE_MULTIVAR(NODE, ITER_VAR(NODE) + 1))

/* Note that the iterator copies each element, this is useful for small sized
 * elements like pointers. */
#define VECTOR_FOR_EACH(VEC, NODE)                                            \
    for (INIT_MULTIVAR(NODE, 0, (VEC)->buffer, OVS_TYPEOF(NODE));             \
         (ITER_VAR(NODE) - (OVS_TYPEOF(NODE) *) (VEC)->buffer < (VEC)->len ?  \
            (((NODE) = *ITER_VAR(NODE)), 1) :                                 \
            0);                                                               \
         UPDATE_MULTIVAR(NODE, ITER_VAR(NODE) + 1))

/* Note that the returns element is copy of the element stored in the
 * vector. This is useful for small sized elements like pointers. */
#define vector_get(VEC, INDEX, TYPE) \
    (*(TYPE *) vector_get_ptr((VEC), (INDEX)))

bool vector_insert(struct vector *vec, size_t index, const void *element);
void vector_push_array(struct vector *vec, const void *src, size_t n);
bool vector_remove(struct vector *vec, size_t index, void *element);
bool vector_remove_fast(struct vector *vec, size_t index, void *element);
bool vector_remove_block(struct vector *vec, size_t start, size_t end);
void *vector_get_ptr(const struct vector *vec, size_t index);
void vector_shrink_to_fit(struct vector *vec);
struct vector vector_clone(struct vector *vec);
void vector_reserve(struct vector *vec, size_t n);

/* Pushes element into the end of the vector. */
static inline void
vector_push(struct vector *vec, const void *element)
{
    vector_insert(vec, vec->len, element);
}

/* Pops element from the end, the argument "element" is populated
 * with the data. */
static inline void
vector_pop(struct vector *vec, void *element)
{
    vector_remove(vec, vec->len - 1, element);
}

/* Clears the vector without deallocating the buffer. */
static inline void
vector_clear(struct vector *vec)
{
    vec->len = 0;
}

/* Initializes the vector as empty. */
static inline void
vector_init(struct vector *vec)
{
    vec->len = 0;
    vec->capacity = 0;
    vec->buffer = NULL;
}

/* Destroys the vector content. It doesn't free individual elements, that's up
 * to the caller. */
static inline void
vector_destroy(struct vector *vec)
{
    free(vec->buffer);
    vector_init(vec);
}

/* Returns the length in number of elements. */
static inline size_t
vector_len(const struct vector *vec)
{
    return vec->len;
}

/* Returns the capacity in number of elements. */
static inline size_t
vector_capacity(const struct vector *vec)
{
    return vec->capacity;
}

/* Return true if vector is empty. */
static inline bool
vector_is_empty(const struct vector * vec)
{
    return vec->len == 0;
}

/* Quick sort of all elements in the vector. */
static inline void
vector_qsort(struct vector *vec, int (*cmp)(const void *a, const void *b))
{
    if (vec->len) {
        qsort(vec->buffer, vec->len, vec->esize, cmp);
    }
}

/* Returns the size of allocated space for the vector elements in bytes. */
static inline size_t
vector_memory_usage(struct vector *vec)
{
    return vec->capacity * vec->esize;
}

/* Returns the array pointer. */
static inline void *
vector_get_array(const struct vector *vec)
{
    return vec->buffer;
}

/* Returns the array pointer, the vector is re-initialized. It is up to caller
 * to free the array. */
static inline void *
vector_steal_array(struct vector *vec)
{
    void *buffer = vec->buffer;
    vector_init(vec);
    return buffer;
}

#endif /* lib/vec.h */
