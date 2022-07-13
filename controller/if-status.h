
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

#ifndef IF_STATUS_H
#define IF_STATUS_H 1

#include "openvswitch/shash.h"

#include "binding.h"

struct if_status_mgr;
struct simap;

struct if_status_mgr *if_status_mgr_create(void);
void if_status_mgr_clear(struct if_status_mgr *);
void if_status_mgr_destroy(struct if_status_mgr *);

void if_status_mgr_claim_iface(struct if_status_mgr *, const char *iface_id);
void if_status_mgr_release_iface(struct if_status_mgr *, const char *iface_id);
void if_status_mgr_delete_iface(struct if_status_mgr *, const char *iface_id);

void if_status_mgr_update(struct if_status_mgr *, struct local_binding_data *);
void if_status_mgr_run(struct if_status_mgr *mgr, struct local_binding_data *,
                       const struct sbrec_chassis *,
                       bool sb_readonly, bool ovs_readonly);
void if_status_mgr_get_memory_usage(struct if_status_mgr *mgr,
                                    struct simap *usage);

#endif /* controller/if-status.h */
