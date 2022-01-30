/*
 * Copyright (c) 2021, NVIDIA CORPORATION.  All rights reserved.
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

#ifndef LFLOW_CONJ_IDS_H
#define LFLOW_CONJ_IDS_H 1

#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "uuid.h"

struct conj_ids {
    /* Allocated conjunction ids. Contains struct conj_id_node. */
    struct hmap conj_id_allocations;
    /* A map from lflow + DP to the conjunction ids used. Contains struct
     * lflow_conj_node. */
    struct hmap lflow_conj_ids;
    /* A map from lflow to the list of DPs this lflow belongs to. Contains
     * struct lflow_to_dps_node. */
    struct hmap lflow_to_dps;
};

uint32_t lflow_conj_ids_alloc(struct conj_ids *, const struct uuid *lflow_uuid,
                              const struct uuid *dp_uuid, uint32_t n_conjs);
bool lflow_conj_ids_alloc_specified(struct conj_ids *,
                                    const struct uuid *lflow_uuid,
                                    const struct uuid *dp_uuid,
                                    uint32_t start_conj_id, uint32_t n_conjs);
void lflow_conj_ids_free(struct conj_ids *, const struct uuid *lflow_uuid);
uint32_t lflow_conj_ids_find(struct conj_ids *, const struct uuid *lflow_uuid,
                             const struct uuid *dp_uuid);
void lflow_conj_ids_init(struct conj_ids *);
void lflow_conj_ids_destroy(struct conj_ids *);
void lflow_conj_ids_clear(struct conj_ids *);
void lflow_conj_ids_dump(struct conj_ids *, struct ds *out_data);
void lflow_conj_ids_set_test_mode(bool);

#endif /* controller/lflow-conj-ids.h */
