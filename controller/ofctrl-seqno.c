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

#include "hash.h"
#include "ofctrl-seqno.h"
#include "openvswitch/list.h"
#include "util.h"
#include "vec.h"

#define VECTOR_THRESHOLD 1024

/* A sequence number update request, i.e., when the barrier corresponding to
 * the 'flow_cfg' sequence number is replied to by OVS then it is safe
 * to inform the application that the 'req_cfg' seqno has been processed.
 */
struct ofctrl_seqno_update {
    size_t seqno_type;         /* Application specific seqno type.
                                * Relevant only for 'req_cfg'.
                                */
    uint64_t flow_cfg;         /* The seqno that needs to be acked by OVS
                                * before 'req_cfg' can be acked for the
                                * application.
                                */
    uint64_t req_cfg;          /* Application specific seqno. */
};

/* List of in flight sequence number updates. */
static struct vector ofctrl_seqno_updates =
    VECTOR_EMPTY_INITIALIZER(struct ofctrl_seqno_update);

/* Last sequence number request sent to OVS. */
static uint64_t ofctrl_req_seqno;

/* State of seqno requests for a given application seqno type. */
struct ofctrl_seqno_state {
    struct vector acked_cfgs;   /* Acked requests since the last time the
                                 * application consumed acked requests.
                                 */
    uint64_t cur_cfg;           /* Last acked application seqno. */
    uint64_t req_cfg;           /* Last requested application seqno. */
};

/* Per application seqno type states. */
static struct vector ofctrl_seqno_states =
    VECTOR_EMPTY_INITIALIZER(struct ofctrl_seqno_state);

/* ofctrl_seqno_state related static function prototypes. */
static struct ofctrl_seqno_state *ofctrl_seqno_state_get(size_t seqno_type);

/* Returns the collection of acked ofctrl_seqno_update requests of type
 * 'seqno_type'.  It's the responsibility of the caller to free memory by
 * calling ofctrl_acked_seqnos_destroy().
 */
struct ofctrl_acked_seqnos *
ofctrl_acked_seqnos_get(size_t seqno_type)
{
    struct ofctrl_seqno_state *state = ofctrl_seqno_state_get(seqno_type);

    struct ofctrl_acked_seqnos *acked_seqnos = xmalloc(sizeof *acked_seqnos);
    acked_seqnos->acked = vector_clone(&state->acked_cfgs);
    acked_seqnos->last_acked = state->cur_cfg;

    vector_clear(&state->acked_cfgs);
    if (vector_capacity(&state->acked_cfgs) >= VECTOR_THRESHOLD) {
        vector_shrink_to_fit(&state->acked_cfgs);
    }

    return acked_seqnos;
}

void
ofctrl_acked_seqnos_destroy(struct ofctrl_acked_seqnos *seqnos)
{
    if (!seqnos) {
        return;
    }

    vector_destroy(&seqnos->acked);
    free(seqnos);
}

/* Returns true if 'val' is one of the acked sequence numbers in 'seqnos'. */
bool
ofctrl_acked_seqnos_contains(const struct ofctrl_acked_seqnos *seqnos,
                             uint64_t val)
{
    if (vector_is_empty(&seqnos->acked)) {
        return false;
    }

    size_t low = 0;
    size_t high = vector_len(&seqnos->acked) -1;
    uint64_t *acked = vector_get_array(&seqnos->acked);

    while (low <= high) {
        size_t mid = low + (high - low) / 2;

        if (acked[mid] == val) {
            return true;
        }

        if (acked[mid] >= acked[low]) {
            if (val >= acked[low] && val < acked[mid]) {
                high = mid - 1;
            } else {
                low = mid + 1;
            }
        } else {
            if (val > acked[mid] && val <= acked[high]) {
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
    }

    return false;
}

/* Adds a new type of application specific seqno updates. */
size_t
ofctrl_seqno_add_type(void)
{
    size_t new_type = vector_len(&ofctrl_seqno_states);

    struct ofctrl_seqno_state state = (struct ofctrl_seqno_state) {
        .acked_cfgs = VECTOR_EMPTY_INITIALIZER(uint64_t),
        .cur_cfg = 0,
        .req_cfg = 0,
    };
    vector_push(&ofctrl_seqno_states, &state);

    return new_type;
}

/* Creates a new seqno update request for an application specific
 * 'seqno_type'.
 */
void
ofctrl_seqno_update_create(size_t seqno_type, uint64_t new_cfg)
{
    struct ofctrl_seqno_state *state = ofctrl_seqno_state_get(seqno_type);

    /* If new_cfg didn't change since the last request there should already
     * be an update pending.
     */
    if (new_cfg == state->req_cfg) {
        return;
    }

    state->req_cfg = new_cfg;

    ofctrl_req_seqno++;
    struct ofctrl_seqno_update update = (struct ofctrl_seqno_update) {
        .seqno_type = seqno_type,
        .flow_cfg = ofctrl_req_seqno,
        .req_cfg = new_cfg,
    };
    vector_push(&ofctrl_seqno_updates, &update);
}

/* Should be called when the application is certain that all OVS flow updates
 * corresponding to 'flow_cfg' were processed.  Populates the application
 * specific lists of acked requests in 'ofctrl_seqno_states'.
 */
void
ofctrl_seqno_run(uint64_t flow_cfg)
{
    size_t index = 0;

    struct ofctrl_seqno_update *update;
    VECTOR_FOR_EACH_PTR (&ofctrl_seqno_updates, update) {
        if (flow_cfg < update->flow_cfg) {
            break;
        }
        struct ofctrl_seqno_state *state =
            ofctrl_seqno_state_get(update->seqno_type);
        state->cur_cfg = update->req_cfg;
        vector_push(&state->acked_cfgs, &update->req_cfg);

        index++;
    }

    vector_remove_block(&ofctrl_seqno_updates, 0, index);

    if (vector_capacity(&ofctrl_seqno_updates) >= VECTOR_THRESHOLD) {
        vector_shrink_to_fit(&ofctrl_seqno_updates);
    }
}

/* Returns the seqno to be used when sending a barrier request to OVS. */
uint64_t
ofctrl_seqno_get_req_cfg(void)
{
    return ofctrl_req_seqno;
}

/* Should be called whenever the openflow connection to OVS is lost.  Flushes
 * all pending 'ofctrl_seqno_updates'.
 */
void
ofctrl_seqno_flush(void)
{
    vector_clear(&ofctrl_seqno_updates);

    struct ofctrl_seqno_state *state;
    VECTOR_FOR_EACH_PTR (&ofctrl_seqno_states, state) {
        vector_clear(&state->acked_cfgs);
    }

    ofctrl_req_seqno = 0;
}

void
ofctrl_seqno_destroy(void)
{
    vector_destroy(&ofctrl_seqno_updates);

    struct ofctrl_seqno_state *state;
    VECTOR_FOR_EACH_PTR (&ofctrl_seqno_states, state) {
        vector_destroy(&state->acked_cfgs);
    }
    vector_destroy(&ofctrl_seqno_states);
}

static struct ofctrl_seqno_state *
ofctrl_seqno_state_get(size_t seqno_type)
{
    ovs_assert(seqno_type < vector_len(&ofctrl_seqno_states));
    return vector_get_ptr(&ofctrl_seqno_states, seqno_type);
}
