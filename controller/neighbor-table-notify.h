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

#ifndef NEIGHBOR_TABLE_NOTIFY_H
#define NEIGHBOR_TABLE_NOTIFY_H 1

#include <stdbool.h>
#include "openvswitch/hmap.h"

/* Returns true if any neighbor table has changed enough that we need
 * to learn new neighbor entries. */
bool neighbor_table_notify_run(void);
void neighbor_table_notify_wait(void);

/* Add a watch request to the hmap. The hmap should later be passed to
 * neighbor_table_notify_update_watches*/
void neighbor_table_add_watch_request(struct hmap *neighbor_table_watches,
                                      int32_t if_index, const char *if_name);

/* Cleanup all watch request in the provided hmap that where added using
 * neighbor_table_add_watch_request. */
void neighbor_table_watch_request_cleanup(
    struct hmap *neighbor_table_watches);

/* Updates the list of neighbor table watches that are currently active.
 * hmap should contain struct neighbor_table_watch_request */
void neighbor_table_notify_update_watches(
    const struct hmap *neighbor_table_watches);

/* Cleans up all neighbor table watches. */
void neighbor_table_notify_destroy(void);

#endif /* NEIGHBOR_TABLE_NOTIFY_H */
