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
#ifndef EN_LS_STATEFUL_H
#define EN_LS_STATEFUL_H 1

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
#include "lib/stopwatch-names.h"

struct ls_stateful_record {
    struct hmap_node key_node;

    /* UUID of the NB Logical switch. */
    struct uuid nbs_uuid;

    /* Unique id of the logical switch.  Note : This id is assigned
     * by the northd engine node for each logical switch. */
    size_t ls_index;

    bool has_stateful_acl;
    bool has_lb_vip;
    bool has_acls;
    uint64_t max_acl_tier;
};

struct ls_stateful_table {
    struct hmap entries;
};

#define LS_STATEFUL_TABLE_FOR_EACH(LS_STATEFUL_REC, TABLE) \
    HMAP_FOR_EACH (LS_STATEFUL_REC, key_node, &(TABLE)->entries)

#define LS_STATEFUL_TABLE_FOR_EACH_IN_P(LS_STATEFUL_REC, JOBID, TABLE) \
    HMAP_FOR_EACH_IN_PARALLEL (LS_STATEFUL_REC, key_node, JOBID, \
                               &(TABLE)->entries)

struct ls_stateful_tracked_data {
    /* Created or updated logical switch with LB and ACL data. */
    struct hmapx crupdated; /* Stores 'struct ls_stateful_record'. */
};

struct ed_type_ls_stateful {
    struct ls_stateful_table table;
    struct ls_stateful_tracked_data trk_data;
};

void *en_ls_stateful_init(struct engine_node *, struct engine_arg *);
void en_ls_stateful_cleanup(void *data);
void en_ls_stateful_clear_tracked_data(void *data);
void en_ls_stateful_run(struct engine_node *, void *data);

bool ls_stateful_northd_handler(struct engine_node *, void *data);
bool ls_stateful_port_group_handler(struct engine_node *, void *data);

const struct ls_stateful_record *ls_stateful_table_find(
    const struct ls_stateful_table *, const struct nbrec_logical_switch *);

static inline bool
ls_stateful_has_tracked_data(struct ls_stateful_tracked_data *trk_data) {
    return !hmapx_is_empty(&trk_data->crupdated);
}

#endif /* EN_LS_STATEFUL_H */
