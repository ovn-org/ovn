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

#include <config.h>

#include "lib/static-mac-binding-index.h"
#include "lib/ovn-sb-idl.h"

struct ovsdb_idl_index *
static_mac_binding_index_create(struct ovsdb_idl *idl)
{
    return ovsdb_idl_index_create2(idl,
                                   &sbrec_static_mac_binding_col_logical_port,
                                   &sbrec_static_mac_binding_col_ip);
}

const struct sbrec_static_mac_binding *
static_mac_binding_lookup(struct ovsdb_idl_index *smb_index,
                          const char *logical_port, const char *ip)
{
    struct sbrec_static_mac_binding *target =
        sbrec_static_mac_binding_index_init_row(smb_index);
    sbrec_static_mac_binding_index_set_logical_port(target, logical_port);
    sbrec_static_mac_binding_index_set_ip(target, ip);

    struct sbrec_static_mac_binding *smb =
        sbrec_static_mac_binding_index_find(smb_index, target);
    sbrec_static_mac_binding_index_destroy_row(target);

    return smb;
}
