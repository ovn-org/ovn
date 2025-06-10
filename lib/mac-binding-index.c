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

#include <config.h>

#include "openvswitch/vlog.h"
#include "lib/mac-binding-index.h"
#include "lib/ovn-sb-idl.h"

VLOG_DEFINE_THIS_MODULE(mac_binding_index);

struct ovsdb_idl_index *
mac_binding_by_datapath_index_create(struct ovsdb_idl *idl)
{
    return ovsdb_idl_index_create1(idl, &sbrec_mac_binding_col_datapath);
}

struct ovsdb_idl_index *
mac_binding_by_lport_ip_index_create(struct ovsdb_idl *idl)
{
    return ovsdb_idl_index_create2(idl,
                                   &sbrec_mac_binding_col_logical_port,
                                   &sbrec_mac_binding_col_ip);
}

const struct sbrec_mac_binding *
mac_binding_lookup(struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                   const char *logical_port, const char *ip) {
    struct sbrec_mac_binding *mb =
            sbrec_mac_binding_index_init_row(sbrec_mac_binding_by_lport_ip);
    sbrec_mac_binding_index_set_logical_port(mb, logical_port);
    sbrec_mac_binding_index_set_ip(mb, ip);

    const struct sbrec_mac_binding *retval =
            sbrec_mac_binding_index_find(sbrec_mac_binding_by_lport_ip, mb);

    sbrec_mac_binding_index_destroy_row(mb);

    return retval;
}

/* Update or add an IP-MAC binding for 'logical_port'.
 * Caller should make sure that 'ovnsb_idl_txn' is valid. */
void
mac_binding_add_to_sb(struct ovsdb_idl_txn *ovnsb_idl_txn,
                      struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                      const char *logical_port,
                      const struct sbrec_datapath_binding *dp,
                      struct eth_addr ea, const char *ip,
                      bool update_only)
{
    /* Convert ethernet argument to string form for database. */
    char mac_string[ETH_ADDR_STRLEN + 1];
    snprintf(mac_string, sizeof mac_string, ETH_ADDR_FMT, ETH_ADDR_ARGS(ea));

    const struct sbrec_mac_binding *b =
            mac_binding_lookup(sbrec_mac_binding_by_lport_ip,
                               logical_port, ip);
    if (!b) {
        if (update_only) {
            return;
        }
        b = sbrec_mac_binding_insert(ovnsb_idl_txn);
        sbrec_mac_binding_set_logical_port(b, logical_port);
        sbrec_mac_binding_set_ip(b, ip);
        sbrec_mac_binding_set_datapath(b, dp);
    }

    if (strcmp(b->mac, mac_string)) {
        sbrec_mac_binding_set_mac(b, mac_string);

        /* For backward compatibility check if timestamp column is available
         * in SB DB. */
        if (sbrec_server_has_mac_binding_table_col_timestamp(
                ovsdb_idl_txn_get_idl(ovnsb_idl_txn))) {
            VLOG_DBG("Setting MAC binding timestamp for "
                     "ip:%s mac:%s port:%s to %lld",
                     b->ip, b->mac, logical_port, time_wall_msec());
            sbrec_mac_binding_set_timestamp(b, time_wall_msec());
        }
    }
}
