/* Copyright (c) 2021
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

#ifndef OVN_STATIC_MAC_BINDING_INDEX_H
#define OVN_STATIC_MAC_BINDING_INDEX_H 1

struct ovsdb_idl;

struct ovsdb_idl_index *static_mac_binding_index_create(struct ovsdb_idl *);
const struct sbrec_static_mac_binding *static_mac_binding_lookup(
    struct ovsdb_idl_index *smb_index,
    const char *logical_port,
    const char *ip);

#endif /* lib/static-mac-binding-index.h */
