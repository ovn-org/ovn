/* Copyright (c) 2022 Red Hat, Inc.
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

#ifndef OVN_MIRROR_H
#define OVN_MIRROR_H 1

struct ovsdb_idl_txn;
struct ovsrec_mirror_table;
struct sbrec_mirror_table;
struct ovsrec_bridge;
struct shash;

void mirror_register_ovs_idl(struct ovsdb_idl *);
void mirror_init(void);
void mirror_destroy(void);
void mirror_run(struct ovsdb_idl_txn *ovs_idl_txn,
                const struct ovsrec_mirror_table *,
                const struct sbrec_mirror_table *,
                const struct ovsrec_bridge *,
                struct shash *local_bindings);
#endif
