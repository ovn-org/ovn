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

/* A sequence number update request, i.e., when the barrier corresponding to
 * the 'flow_cfg' sequence number is replied to by OVS then it is safe
 * to inform the application that the 'req_cfg' seqno has been processed.
 */
struct ofctrl_seqno_update {
    struct ovs_list list_node; /* In 'ofctrl_seqno_updates'. */
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
static struct ovs_list ofctrl_seqno_updates;

/* Last sequence number request sent to OVS. */
static uint64_t ofctrl_req_seqno;

/* State of seqno requests for a given application seqno type. */
struct ofctrl_seqno_state {
    struct ovs_list acked_cfgs; /* Acked requests since the last time the
                                 * application consumed acked requests.
                                 */
    uint64_t cur_cfg;           /* Last acked application seqno. */
    uint64_t req_cfg;           /* Last requested application seqno. */
};

/* Per application seqno type states. */
static size_t n_ofctrl_seqno_states;
static struct ofctrl_seqno_state *ofctrl_seqno_states;

/* ofctrl_acked_seqnos related static function prototypes. */
static void ofctrl_acked_seqnos_init(struct ofctrl_acked_seqnos *seqnos,
                                     uint64_t last_acked);
static void ofctrl_acked_seqnos_add(struct ofctrl_acked_seqnos *seqnos,
                                    uint64_t val);

/* ofctrl_seqno_update related static function prototypes. */
static void ofctrl_seqno_update_create__(size_t seqno_type, uint64_t req_cfg);
static void ofctrl_seqno_update_list_destroy(struct ovs_list *seqno_list);
static void ofctrl_seqno_cfg_run(size_t seqno_type,
                                 struct ofctrl_seqno_update *update);

/* Returns the collection of acked ofctrl_seqno_update requests of type
 * 'seqno_type'.  It's the responsibility of the caller to free memory by
 * calling ofctrl_acked_seqnos_destroy().
 */
struct ofctrl_acked_seqnos *
ofctrl_acked_seqnos_get(size_t seqno_type)
{
    struct ofctrl_acked_seqnos *acked_seqnos = xmalloc(sizeof *acked_seqnos);
    struct ofctrl_seqno_state *state = &ofctrl_seqno_states[seqno_type];
    struct ofctrl_seqno_update *update;

    ofctrl_acked_seqnos_init(acked_seqnos, state->cur_cfg);

    ovs_assert(seqno_type < n_ofctrl_seqno_states);
    LIST_FOR_EACH_POP (update, list_node, &state->acked_cfgs) {
        ofctrl_acked_seqnos_add(acked_seqnos, update->req_cfg);
        free(update);
    }
    return acked_seqnos;
}

void
ofctrl_acked_seqnos_destroy(struct ofctrl_acked_seqnos *seqnos)
{
    if (!seqnos) {
        return;
    }

    struct ofctrl_ack_seqno *seqno_node;
    HMAP_FOR_EACH_POP (seqno_node, node, &seqnos->acked) {
        free(seqno_node);
    }
    hmap_destroy(&seqnos->acked);
    free(seqnos);
}

/* Returns true if 'val' is one of the acked sequence numbers in 'seqnos'. */
bool
ofctrl_acked_seqnos_contains(const struct ofctrl_acked_seqnos *seqnos,
                             uint64_t val)
{
    struct ofctrl_ack_seqno *sn;

    HMAP_FOR_EACH_WITH_HASH (sn, node, hash_uint64(val), &seqnos->acked) {
        if (sn->seqno == val) {
            return true;
        }
    }
    return false;
}

void
ofctrl_seqno_init(void)
{
    ovs_list_init(&ofctrl_seqno_updates);
}

/* Adds a new type of application specific seqno updates. */
size_t
ofctrl_seqno_add_type(void)
{
    size_t new_type = n_ofctrl_seqno_states;
    n_ofctrl_seqno_states++;

    struct ofctrl_seqno_state *new_states =
        xzalloc(n_ofctrl_seqno_states * sizeof *new_states);

    for (size_t i = 0; i < n_ofctrl_seqno_states - 1; i++) {
        ovs_list_move(&new_states[i].acked_cfgs,
                      &ofctrl_seqno_states[i].acked_cfgs);
    }
    ovs_list_init(&new_states[new_type].acked_cfgs);

    free(ofctrl_seqno_states);
    ofctrl_seqno_states = new_states;
    return new_type;
}

/* Creates a new seqno update request for an application specific
 * 'seqno_type'.
 */
void
ofctrl_seqno_update_create(size_t seqno_type, uint64_t new_cfg)
{
    ovs_assert(seqno_type < n_ofctrl_seqno_states);

    struct ofctrl_seqno_state *state = &ofctrl_seqno_states[seqno_type];

    /* If new_cfg didn't change since the last request there should already
     * be an update pending.
     */
    if (new_cfg == state->req_cfg) {
        return;
    }

    state->req_cfg = new_cfg;
    ofctrl_seqno_update_create__(seqno_type, new_cfg);
}

/* Should be called when the application is certain that all OVS flow updates
 * corresponding to 'flow_cfg' were processed.  Populates the application
 * specific lists of acked requests in 'ofctrl_seqno_states'.
 */
void
ofctrl_seqno_run(uint64_t flow_cfg)
{
    struct ofctrl_seqno_update *update;
    LIST_FOR_EACH_SAFE (update, list_node, &ofctrl_seqno_updates) {
        if (flow_cfg < update->flow_cfg) {
            break;
        }

        ovs_list_remove(&update->list_node);
        ofctrl_seqno_cfg_run(update->seqno_type, update);
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
    for (size_t i = 0; i < n_ofctrl_seqno_states; i++) {
        ofctrl_seqno_update_list_destroy(&ofctrl_seqno_states[i].acked_cfgs);
    }
    ofctrl_seqno_update_list_destroy(&ofctrl_seqno_updates);
    ofctrl_req_seqno = 0;
}

static void
ofctrl_acked_seqnos_init(struct ofctrl_acked_seqnos *seqnos,
                         uint64_t last_acked)
{
    hmap_init(&seqnos->acked);
    seqnos->last_acked = last_acked;
}

static void
ofctrl_acked_seqnos_add(struct ofctrl_acked_seqnos *seqnos, uint64_t val)
{
    seqnos->last_acked = val;

    struct ofctrl_ack_seqno *sn = xmalloc(sizeof *sn);
    hmap_insert(&seqnos->acked, &sn->node, hash_uint64(val));
    sn->seqno = val;
}

static void
ofctrl_seqno_update_create__(size_t seqno_type, uint64_t req_cfg)
{
    struct ofctrl_seqno_update *update = xmalloc(sizeof *update);

    ofctrl_req_seqno++;
    ovs_list_push_back(&ofctrl_seqno_updates, &update->list_node);
    update->seqno_type = seqno_type;
    update->flow_cfg = ofctrl_req_seqno;
    update->req_cfg = req_cfg;
}

static void
ofctrl_seqno_update_list_destroy(struct ovs_list *seqno_list)
{
    struct ofctrl_seqno_update *update;

    LIST_FOR_EACH_POP (update, list_node, seqno_list) {
        free(update);
    }
}

static void
ofctrl_seqno_cfg_run(size_t seqno_type, struct ofctrl_seqno_update *update)
{
    ovs_assert(seqno_type < n_ofctrl_seqno_states);
    ovs_list_push_back(&ofctrl_seqno_states[seqno_type].acked_cfgs,
                       &update->list_node);
    ofctrl_seqno_states[seqno_type].cur_cfg = update->req_cfg;
}
