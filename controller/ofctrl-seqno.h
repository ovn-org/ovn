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

#ifndef OFCTRL_SEQNO_H
#define OFCTRL_SEQNO_H 1

#include <stdint.h>

#include <openvswitch/hmap.h>

/* Collection of acked ofctrl_seqno_update requests and the most recent
 * 'last_acked' value.
 */
struct ofctrl_acked_seqnos {
    struct hmap acked;
    uint64_t last_acked;
};

/* Acked application specific seqno.  Stored in ofctrl_acked_seqnos.acked. */
struct ofctrl_ack_seqno {
    struct hmap_node node;
    uint64_t seqno;
};

struct ofctrl_acked_seqnos *ofctrl_acked_seqnos_get(size_t seqno_type);
void ofctrl_acked_seqnos_destroy(struct ofctrl_acked_seqnos *seqnos);
bool ofctrl_acked_seqnos_contains(const struct ofctrl_acked_seqnos *seqnos,
                                  uint64_t val);

void ofctrl_seqno_init(void);
size_t ofctrl_seqno_add_type(void);
void ofctrl_seqno_update_create(size_t seqno_type, uint64_t new_cfg);
void ofctrl_seqno_run(uint64_t flow_cfg);
uint64_t ofctrl_seqno_get_req_cfg(void);
void ofctrl_seqno_flush(void);

#endif /* controller/ofctrl-seqno.h */
