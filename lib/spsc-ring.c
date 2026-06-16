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
#include <string.h>

#include "spsc-ring.h"
#include "util.h"

/* Initializes the SPSC ring, the capacity must be power of 2. */
void
spsc_ring_init(struct spsc_ring *r, uint32_t capacity, size_t esize)
{
    ovs_assert(IS_POW2(capacity));
    r->buffer = xmalloc(capacity * esize);
    r->esize = esize;
    r->mask = capacity - 1;
    atomic_init(&r->read, 0);
    atomic_init(&r->write, 0);
}

void
spsc_ring_destroy(struct spsc_ring *r)
{
    free(r->buffer);
    r->buffer = NULL;
}

/* Producer: copy 'data' into the next available slot.
 * Returns true on success, false if the ring is full. */
bool
spsc_ring_push(struct spsc_ring *r, const void *data)
{
    uint32_t wr, rd;

    atomic_read(&r->write, &wr);
    atomic_read(&r->read, &rd);

    if (wr - rd > r->mask) {
        return false;
    }

    memcpy((uint8_t *) r->buffer + (wr & r->mask) * r->esize,
           data, r->esize);
    atomic_store(&r->write, wr + 1);
    return true;
}

/* Consumer: copy the oldest slot's data into 'data'.
 * Returns true on success, false if the ring is empty. */
bool
spsc_ring_pop(struct spsc_ring *r, void *data)
{
    uint32_t rd, wr;

    atomic_read(&r->read, &rd);
    atomic_read(&r->write, &wr);

    if (rd == wr) {
        return false;
    }

    memcpy(data,
           (uint8_t *) r->buffer + (rd & r->mask) * r->esize,
           r->esize);
    atomic_store(&r->read, rd + 1);
    return true;
}
