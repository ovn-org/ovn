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

#ifndef SPSC_RING_H
#define SPSC_RING_H

#include <stdbool.h>
#include <stdint.h>

#include "openvswitch/util.h"
#include "ovs-atomic.h"

/* Single-Producer, Single-Consumer lock-free ring buffer.
 *
 * Thread-safety
 * =============
 *
 * Exactly one thread (the producer) may call spsc_ring_push().
 * Exactly one thread (the consumer) may call spsc_ring_pop().
 * These two threads may be different and may operate concurrently
 * without any external synchronization.
 *
 * Memory ordering: sequential consistency (the default for OVS
 * atomic_read/atomic_store) on the read and write indices ensures
 * that slot data written by the producer is visible to the consumer
 * after it observes the updated write index (and vice versa for
 * read index updates freeing slots for reuse).
 *
 * Slot data is copied in and out by value (memcpy), so this is
 * best suited for small, fixed-size structs.
 *
 * Capacity must be a power of two.  The ring uses unsigned 32-bit
 * wraparound arithmetic on read/write indices, which is correct as
 * long as capacity is much smaller than 2^32.
 */
struct spsc_ring {
    void *buffer;           /* Pre-allocated slot array. */
    size_t esize;           /* Size of each element in bytes. */
    uint32_t mask;          /* capacity - 1 (for power-of-two modulo). */
    atomic_uint32_t read;   /* Next slot to consume (advanced by consumer). */
    atomic_uint32_t write;  /* Next slot to fill (advanced by producer). */
};

void spsc_ring_init(struct spsc_ring *, uint32_t capacity, size_t esize);
void spsc_ring_destroy(struct spsc_ring *);
bool spsc_ring_push(struct spsc_ring *, const void *data);
bool spsc_ring_pop(struct spsc_ring *, void *data);

/* Pop each element into VAR until the ring is empty. */
#define SPSC_RING_FOR_EACH_POP(RING, VAR)                          \
    for (bool ITER_VAR(VAR) = spsc_ring_pop(RING, &(VAR));         \
         ITER_VAR(VAR);                                            \
         ITER_VAR(VAR) = spsc_ring_pop(RING, &(VAR)))

#endif /* lib/spsc-ring.h */
