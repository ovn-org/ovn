/* Copyright (c) 2024 Red Hat, INc.
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

#ifndef OVN_ACL_IDS_H
#define OVN_ACL_IDS_H

#include <config.h>
#include "lib/inc-proc-eng.h"
#include "openvswitch/types.h"

void *en_acl_id_init(struct engine_node *, struct engine_arg *);
void en_acl_id_run(struct engine_node *, void *);
void en_acl_id_cleanup(void *);
bool en_acl_id_is_valid(struct engine_node *);

struct tracked_acl_ids;
struct ofp_header;
enum ofptype;
struct ovs_list;

void acl_ids_handle_barrier_reply(struct tracked_acl_ids *acl_ids,
                                  ovs_be32 barrier_xid);
bool acl_ids_handle_non_barrier_reply(const struct ofp_header *oh,
                                      enum ofptype type,
                                      struct tracked_acl_ids *acl_ids);
void acl_ids_flush_expired(struct tracked_acl_ids *acl_ids,
                           int rconn_version,
                           struct ovs_list *msgs);
void acl_ids_record_barrier_xid(struct tracked_acl_ids *acl_ids,
                                ovs_be32 barrier_xid);

#endif /* OVN_ACL_IDS_H */
