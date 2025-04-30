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

#include "vec.h"
#include "util.h"

#define BYTE_SIZE(VEC, N) ((VEC)->esize * (N))

static void vector_resize(struct vector *vec, size_t new_capacity);

/* Inerts element at index, the content at the index is shifted right.
 * Returns 'false' if the index is out of bounds. Note that the element
 * is pointer to the type being stored, e.g. in case of char *
 * char ** should be passed. */
bool
vector_insert(struct vector *vec, size_t index, const void *element)
{
    if (index > vec->len) {
        return false;
    }

    vector_reserve(vec, 1);
    uint8_t *dst = (uint8_t *) vec->buffer + BYTE_SIZE(vec, index);
    size_t shift_len = vec->len - index;
    memmove(dst + vec->esize, dst, BYTE_SIZE(vec, shift_len));
    memcpy(dst, element, vec->esize);
    vec->len++;

    return true;
}

/* Pushes array of n elements at the end of vector. */
void
vector_push_array(struct vector *vec, const void *src, size_t n)
{
    vector_reserve(vec, n);
    memcpy((uint8_t *) vec->buffer + BYTE_SIZE(vec, vec->len), src,
           BYTE_SIZE(vec, n));
    vec->len = vec->len + n;
}

/* Removes element at index, the argument "element" is populated with the
 * data. The content after index is shifted left. Returns 'false' if the index
 * is out of bounds. */
bool
vector_remove(struct vector *vec, size_t index, void *element)
{
    if (index >= vec->len || vec->len == 0) {
        return false;
    }

    uint8_t *dst = (uint8_t *) vec->buffer + BYTE_SIZE(vec, index);
    size_t shift_len = vec->len - index - 1;

    if (element) {
        memcpy(element, dst, vec->esize);
    }

    memmove(dst, dst + vec->esize, BYTE_SIZE(vec, shift_len));
    vec->len--;

    return true;
}

/* Removes element at index, the argument "element" is populated with the
 * data. The last element takes place of the element removed, this breaks the
 * original order of insert. Returns 'false' if the index is out of bounds. */
bool
vector_remove_fast(struct vector *vec, size_t index, void *element)
{
    if (index >= vec->len || vec->len == 0) {
        return false;
    }

    uint8_t *dst = (uint8_t *) vec->buffer + BYTE_SIZE(vec, index);
    uint8_t *last = (uint8_t *) vec->buffer + BYTE_SIZE(vec, vec->len - 1);

    if (element) {
        memcpy(element, dst, vec->esize);
    }

    memcpy(dst, last, vec->esize);
    vec->len--;

    return true;
}

/* Removes block of elements between start (inclusive) and end (exclusive),
 * The content at end is shifted left. Returns 'false' if the index
 * is out of bounds. */
bool
vector_remove_block(struct vector *vec, size_t start, size_t end)
{
    if (vec->len == 0) {
        return false;
    }

    if (start >= end) {
        return false;
    }

    if (start >= vec->len || end > vec->len) {
        return false;
    }

    uint8_t *dst = (uint8_t *) vec->buffer + BYTE_SIZE(vec, start);
    uint8_t *src = (uint8_t *) vec->buffer + BYTE_SIZE(vec, end);
    size_t shift_len = vec->len - end;
    memmove(dst, src, BYTE_SIZE(vec, shift_len));
    vec->len = vec->len + start - end;

    return true;
}

/* Gets pointer to the item at index. Note that holding pointer across inserts
 * can cause UB. */
void *
vector_get_ptr(const struct vector *vec, size_t index)
{
    if (index >= vec->len) {
        return NULL;
    }

    return (uint8_t *) vec->buffer + BYTE_SIZE(vec, index);
}

/* Reallocates the vector to fit exactly the length if that's not the case. */
void
vector_shrink_to_fit(struct vector *vec)
{
    if (vec->len == vec->capacity) {
        return;
    }

    vector_resize(vec, vec->len);
}

/* Clones the vector vec into new one, the content is memcopied. */
struct vector
vector_clone(struct vector *vec)
{
    struct vector clone = (struct vector) {
        .buffer = NULL,
        .esize = vec->esize,
        .len = vec->len,
        .capacity = vec->capacity,
    };

    if (vec->len) {
        clone.buffer = xmalloc(BYTE_SIZE(vec, vec->capacity));
        memcpy(clone.buffer, vec->buffer, BYTE_SIZE(vec, vec->len));
    }

    return clone;
}

/* Reserves additional space to fit extra n items. */
void
vector_reserve(struct vector *vec, size_t n)
{
    size_t new_len = vec->len + n;
    if (new_len <= vec->capacity) {
        return;
    }

    vector_resize(vec, new_len <= 2 * vec->capacity ?
                  2 * vec->capacity :
                  new_len);
}

static void
vector_resize(struct vector *vec, size_t new_capacity)
{
    if (!new_capacity) {
        vector_destroy(vec);
        return;
    }

    vec->buffer = xrealloc(vec->buffer, BYTE_SIZE(vec, new_capacity));
    vec->capacity = new_capacity;
}
