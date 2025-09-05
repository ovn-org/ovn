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
#include "lib/uuidset.h"
#include "openvswitch/hmap.h"
#include "sset.h"

/* OVN includes. */
#include "lib/inc-proc-eng.h"
#include "lib/lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"

struct lflow_ref;

struct acl_tier {
    uint64_t ingress_pre_lb;
    uint64_t ingress_post_lb;
    uint64_t egress;
};

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
    struct acl_tier max_acl_tier;

    /* Set of ACLs that are related to this LS. */
    struct uuidset related_acls;

    /* 'lflow_ref' is used to reference logical flows generated for
     * this ls_stateful record.
     *
     * This data is initialized and destroyed by the en_ls_stateful node,
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
     * access ls_stateful_record->lflow_ref at any given time.
     */
    struct lflow_ref *lflow_ref;
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
    struct hmapx deleted;
};

struct ed_type_ls_stateful {
    struct ls_stateful_table table;
    struct ls_stateful_tracked_data trk_data;
};

void *en_ls_stateful_init(struct engine_node *, struct engine_arg *);
void en_ls_stateful_cleanup(void *data);
void en_ls_stateful_clear_tracked_data(void *data);
enum engine_node_state en_ls_stateful_run(struct engine_node *, void *data);

enum engine_input_handler_result
ls_stateful_northd_handler(struct engine_node *, void *data);
enum engine_input_handler_result
ls_stateful_port_group_handler(struct engine_node *, void *data);
enum engine_input_handler_result
ls_stateful_acl_handler(struct engine_node *node, void *data);

const struct ls_stateful_record *ls_stateful_table_find(
    const struct ls_stateful_table *, const struct nbrec_logical_switch *);

static inline bool
ls_stateful_has_tracked_data(struct ls_stateful_tracked_data *trk_data) {
    return !hmapx_is_empty(&trk_data->crupdated) ||
           !hmapx_is_empty(&trk_data->deleted);
}

#endif /* EN_LS_STATEFUL_H */
