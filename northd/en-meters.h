/*
 * Copyright (c) 2023, Red Hat, Inc.
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
#ifndef EN_METERS_H
#define EN_METERS_H 1

#include "openvswitch/shash.h"

#include "lib/inc-proc-eng.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"

struct sync_meters_data {
    struct shash meter_groups;
};

void *en_sync_meters_init(struct engine_node *, struct engine_arg *);
void en_sync_meters_cleanup(void *data);
void en_sync_meters_run(struct engine_node *, void *data);

const struct nbrec_meter *fair_meter_lookup_by_name(
    const struct shash *meter_groups,
    const char *meter_name);

static inline char*
alloc_acl_log_unique_meter_name(const struct nbrec_acl *acl)
{
    return xasprintf("%s__" UUID_FMT,
                     acl->meter, UUID_ARGS(&acl->header_.uuid));
}

#endif /* EN_ACL_H */
