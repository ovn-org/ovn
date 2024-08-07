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
#ifndef EN_SAMPLING_APP_H
#define EN_SAMPLING_APP_H 1

/* OVS includes. */
#include "openvswitch/shash.h"

/* OVN includes. */
#include "lib/inc-proc-eng.h"
#include "lib/ovn-nb-idl.h"

/* Valid sample IDs are in the 1..255 interval. */
#define SAMPLING_APP_ID_NONE 0

/* Supported sampling applications. */
enum sampling_app {
    SAMPLING_APP_DROP_DEBUG,
    SAMPLING_APP_ACL_NEW,
    SAMPLING_APP_ACL_EST,
    SAMPLING_APP_MAX,
};

struct sampling_app_table {
    uint8_t app_ids[SAMPLING_APP_MAX];
};

struct ed_type_sampling_app_data {
    struct sampling_app_table apps;
};

void *en_sampling_app_init(struct engine_node *, struct engine_arg *);
void en_sampling_app_cleanup(void *data);
void en_sampling_app_run(struct engine_node *, void *data);
uint8_t sampling_app_get_id(const struct sampling_app_table *,
                            enum sampling_app);

#endif /* EN_SAMPLING_APP_H */
