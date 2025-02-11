/*
 * Copyright (c) 2025, STACKIT GmbH & Co. KG
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
#ifndef EN_ADVERTISED_ROUTE_SYNC_H
#define EN_ADVERTISED_ROUTE_SYNC_H 1

#include "lib/inc-proc-eng.h"
#include "lib/uuidset.h"

struct advertised_route_sync_data {
  /* Contains the uuids of all NB Logical Routers where we used a
   * lr_stateful_record during computation. */
  struct uuidset nb_lr;
  /* Contains the uuids of all NB Logical Switches where we rely on port
   * changes for host routes. */
  struct uuidset nb_ls;
};

bool advertised_route_sync_lr_stateful_change_handler(struct engine_node *,
                                                      void *data);
bool advertised_route_sync_northd_change_handler(struct engine_node *,
                                                 void *data);
void *en_advertised_route_sync_init(struct engine_node *, struct engine_arg *);
void en_advertised_route_sync_cleanup(void *data);
void en_advertised_route_sync_run(struct engine_node *, void *data);

#endif /* EN_ADVERTISED_ROUTE_SYNC_H */
