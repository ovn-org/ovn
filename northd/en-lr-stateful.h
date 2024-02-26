/*
 * Copyright (c) 2024, Red Hat, Inc.
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
#ifndef EN_LR_STATEFUL_H
#define EN_LR_STATEFUL_H 1

#include <stdint.h>

/* OVS includes. */
#include "lib/hmapx.h"
#include "openvswitch/hmap.h"
#include "sset.h"

/* OVN includes. */
#include "lib/inc-proc-eng.h"
#include "lib/lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"

struct ovn_datapath;
struct lr_nat_record;
struct lflow_ref;

/* lr_stateful_table:  This represents a table of logical routers with
 *                     stateful related data.
 * stateful related data has two main components
 *     - NAT and
 *     - Load balancers.
 *
 * lr_stateful_record: It is a record in the lr_stateful_table for each
 *                     logical router.
 */

struct lr_stateful_record {
    struct hmap_node key_node; /* Index on 'nbr->header_.uuid'. */

    /* UUID of the NB Logical Router. */
    struct uuid nbr_uuid;

    /* Unique id of the logical router.  Note : This id is assigned
     * by the northd engine node for each logical router. */
    size_t lr_index;

    /* This lrnat_rec comes from the en_lrnat engine node data. */
    const struct lr_nat_record *lrnat_rec;

    bool has_lb_vip;

    /* Load Balancer vIPs relevant for this datapath. */
    struct ovn_lb_ip_set *lb_ips;

    /* 'lflow_ref' is used to reference logical flows generated for
     * this lr_stateful_record.
     *
     * This data is initialized and destroyed by the en_lr_stateful node,
     * but populated and used only by the en_lflow node. Ideally this data
     * should be maintained as part of en_lflow's data.  However, it would
     * be less efficient and more complex:
     *
     * 1. It would require an extra search (using the index) to find the
     * lflows.
     *
     * 2. Building the index needs to be thread-safe, using either a global
     * lock which is obviously less efficient, or hash-based lock array which
     * is more complex.
     *
     * Adding the lflow_ref here is more straightforward. The drawback is that
     * we need to keep in mind that this data belongs to en_lflow node, so
     * never access it from any other nodes.
     *
     * Note: lflow_ref is not thread safe.  Only one thread should
     * access lr_stateful_record->lflow_ref at any given time.
     */
    struct lflow_ref *lflow_ref;
};

struct lr_stateful_table {
    struct hmap entries;

    /* The array index of each element in 'entries'. */
    struct lr_stateful_record **array;
};

#define LR_STATEFUL_TABLE_FOR_EACH(LR_LB_NAT_REC, TABLE) \
    HMAP_FOR_EACH (LR_LB_NAT_REC, key_node, &(TABLE)->entries)

#define LR_STATEFUL_TABLE_FOR_EACH_IN_P(LR_STATEFUL_REC, JOBID, TABLE) \
    HMAP_FOR_EACH_IN_PARALLEL (LR_STATEFUL_REC, key_node, JOBID, \
                               &(TABLE)->entries)

struct lr_stateful_tracked_data {
    /* Created or updated logical router with LB and/or NAT data. */
    struct hmapx crupdated; /* Stores 'struct lr_stateful_record'. */
};

struct ed_type_lr_stateful {
    struct lr_stateful_table table;

    /* Node's tracked data. */
    struct lr_stateful_tracked_data trk_data;
};

struct lr_stateful_input {
    const struct ovn_datapaths *lr_datapaths;
    const struct hmap *lb_datapaths_map;
    const struct hmap *lbgrp_datapaths_map;
    const struct lr_nat_table *lr_nats;
};

void *en_lr_stateful_init(struct engine_node *, struct engine_arg *);
void en_lr_stateful_cleanup(void *data);
void en_lr_stateful_clear_tracked_data(void *data);
void en_lr_stateful_run(struct engine_node *, void *data);

bool lr_stateful_northd_handler(struct engine_node *, void *data);
bool lr_stateful_lr_nat_handler(struct engine_node *, void *data);
bool lr_stateful_lb_data_handler(struct engine_node *, void *data);

const struct lr_stateful_record *lr_stateful_table_find_by_index(
    const struct lr_stateful_table *, size_t od_index);

static inline bool
lr_stateful_has_tracked_data(struct lr_stateful_tracked_data *trk_data)
{
    return !hmapx_is_empty(&trk_data->crupdated);
}

static inline bool
lr_stateful_rec_has_lb_vip(const struct lr_stateful_record *lr_stateful_rec)
{
    return lr_stateful_rec && lr_stateful_rec->has_lb_vip;
}

#endif /* EN_lr_stateful_H */
