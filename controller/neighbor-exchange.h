/* Copyright (c) 2025, Red Hat, Inc.
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

#ifndef NEIGHBOR_EXCHANGE_H
#define NEIGHBOR_EXCHANGE_H 1

#include "lib/sset.h"
#include "openvswitch/hmap.h"

struct neighbor_exchange_ctx_in {
    /* Contains struct neighbor_interface_monitor pointers. */
    const struct vector *monitored_interfaces;
};

struct neighbor_exchange_ctx_out {
    /* Contains struct neighbor_table_watch_request. */
    struct hmap neighbor_table_watches;
};

void neighbor_exchange_run(const struct neighbor_exchange_ctx_in *,
                           struct neighbor_exchange_ctx_out *);
int neighbor_exchange_status_run(void);

#endif  /* NEIGHBOR_EXCHANGE_H */
