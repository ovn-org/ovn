/* Copyright (c) 2023, Red Hat, Inc.
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

#ifndef STATCTRL_H
#define STATCTRL_H

#include "mac_cache.h"

void statctrl_init(void);
void statctrl_run(struct ovsdb_idl_txn *ovnsb_idl_txn,
                  struct mac_cache_data *mac_cache_data);
void statctrl_update(const char *br_int_name);
void statctrl_wait(struct ovsdb_idl_txn *ovnsb_idl_txn);
void statctrl_destroy(void);

#endif /* controller/statctrl.h */
