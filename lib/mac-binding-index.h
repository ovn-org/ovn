/* Copyright (c) 2022, Red Hat, Inc.
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

#ifndef OVN_MAC_BINDING_INDEX_H
#define OVN_MAC_BINDING_INDEX_H 1

#include "lib/ovn-sb-idl.h"

struct ovsdb_idl_index *mac_binding_by_datapath_index_create(
    struct ovsdb_idl *idl);
struct ovsdb_idl_index *mac_binding_by_lport_ip_index_create(
    struct ovsdb_idl *idl);

#endif /* lib/mac-binding-index.h */
