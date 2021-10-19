/* Copyright (c) 2021 Canonical
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
#include "ovsport.h"

#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovsport);

/* Create a port and interface record and add it to 'bridge' in the Open
 * vSwitch database represented by 'ovs_idl_txn'.
 *
 * 'name' is required and is used both for the name of the port and interface
 * records.  Depending on the contents of the optional 'iface_type' parameter
 * the name may need to refer to an existing interface in the system.  It is
 * the caller's responsibility to ensure that no other port with the desired
 * name already exists.
 *
 * 'iface_type' optionally specifies the type of interface, otherwise set it to
 * NULL.
 *
 * 'port_external_ids' - the contents of the map will be used to fill the
 * external_ids column of the created port record, otherwise set it to NULL.
 *
 * 'iface_external_ids' - the contents of the map will be used to fill the
 * external_ids column of the created interface record, otherwise set it to
 * NULL.
 *
 * 'iface_options' - the contents of the map will be used to fill the options
 * column of the created interface record, otherwise set it to NULL.
 *
 * 'iface_mtu_request' - if a value > 0 is provided it will be filled into the
 * mtu_request column of the created interface record. */
void
ovsport_create(struct ovsdb_idl_txn *ovs_idl_txn,
               const struct ovsrec_bridge *bridge,
               const char *name,
               const char *iface_type,
               const struct smap *port_external_ids,
               const struct smap *iface_external_ids,
               const struct smap *iface_options,
               const int64_t iface_mtu_request)
{
    struct ovsrec_interface *iface;
    iface = ovsrec_interface_insert(ovs_idl_txn);
    ovsrec_interface_set_name(iface, name);
    if (iface_type) {
        ovsrec_interface_set_type(iface, iface_type);
    }
    ovsrec_interface_set_external_ids(iface, iface_external_ids);
    ovsrec_interface_set_options(iface, iface_options);
    ovsrec_interface_set_mtu_request(
            iface, &iface_mtu_request, iface_mtu_request > 0);

    struct ovsrec_port *port;
    port = ovsrec_port_insert(ovs_idl_txn);
    ovsrec_port_set_name(port, name);
    ovsrec_port_set_interfaces(port, &iface, 1);
    ovsrec_port_set_external_ids(port, port_external_ids);

    ovsrec_bridge_verify_ports(bridge);
    ovsrec_bridge_update_ports_addvalue(bridge, port);
}

/* Remove 'port' from 'bridge' and delete the 'port' record and any records
 * with a weakRef to it. */
void
ovsport_remove(const struct ovsrec_bridge *bridge,
               const struct ovsrec_port *port)
{
    ovsrec_bridge_verify_ports(bridge);
    ovsrec_port_verify_interfaces(port);
    for (struct ovsrec_interface *iface = *port->interfaces;
         iface - *port->interfaces < port->n_interfaces;
         iface++) {
        ovsrec_interface_delete(iface);
    }
    ovsrec_bridge_update_ports_delvalue(bridge, port);
    ovsrec_port_delete(port);
}

static void update_interface_smap_column(
        const struct ovsrec_interface *, const struct smap *,
        const struct smap *, void (*fsetkey)(const struct ovsrec_interface *,
                                             const char *, const char *));
static void maintain_interface_smap_column(
        const struct ovsrec_interface *, const struct sset *,
        const struct smap *, const struct smap *,
        void (*fsetkey)(const struct ovsrec_interface *, const char *,
                        const char *),
        void (*fdelkey)(const struct ovsrec_interface *,
                         const char *));

/* Update interface record as represented by 'iface'.
 *
 * 'type' optionally specifies the type of interface, to unset type set to an
 * empty string, to not update type set to NULL.
 *
 * 'external_ids' optionally provide a map of external_ids to update, to not
 * update external_ids set to NULL.
 *
 * 'mnt_external_ids' optionally provide set of 'external_ids' to maintain.
 * When set the function will make sure that all keys in the 'mnt_external_ids'
 * set have values from the 'external_ids' map in the database.  Every key that
 * exists in 'mnt_external_ids' with no corresponding key in 'external_ids'
 * will be removed from the database if present.  Set to NULL to not maintain
 * the record in this way.
 *
 * 'options' optionally provide a map of options to update, to not
 * update options set to NULL.
 *
 * 'mnt_options' optionally provide set of 'options' to maintain.
 * When set the function will make sure that all keys in the 'mnt_options' set
 * have values from the 'options' map in the database.  Every key that exists
 * in 'mnt_options' with no corresponding key in 'options' will be removed from
 * the database if present.  Set to NULL to not maintain the record in this
 * way.
 *
 * 'iface_mtu_request' - if a value > 0 is provided it will be filled into the
 * mtu_request column of the created interface record. */
void
ovsport_update_iface(const struct ovsrec_interface *iface,
                     const char *type,
                     const struct smap *external_ids,
                     const struct sset *mnt_external_ids,
                     const struct smap *options,
                     const struct sset *mnt_options,
                     const int64_t mtu_request)
{
    if (type && strcmp(iface->type, type)) {
        ovsrec_interface_verify_type(iface);
        ovsrec_interface_set_type(iface, type);
    }

    if (external_ids && mnt_external_ids) {
        ovsrec_interface_verify_external_ids(iface);
        maintain_interface_smap_column(
                iface, mnt_external_ids, external_ids, &iface->external_ids,
                ovsrec_interface_update_external_ids_setkey,
                ovsrec_interface_update_external_ids_delkey);
    } else if (external_ids) {
        ovsrec_interface_verify_external_ids(iface);
        update_interface_smap_column(
                iface, external_ids, &iface->external_ids,
                ovsrec_interface_update_external_ids_setkey);
    }

    if (options && mnt_options) {
        ovsrec_interface_verify_options(iface);
        maintain_interface_smap_column(
                iface, mnt_options, options, &iface->options,
                ovsrec_interface_update_options_setkey,
                ovsrec_interface_update_options_delkey);
    } else if (options) {
        ovsrec_interface_verify_options(iface);
        update_interface_smap_column(
                iface, options, &iface->options,
                ovsrec_interface_update_options_setkey);
    }

    if (mtu_request > 0) {
        if ((iface->mtu_request && *iface->mtu_request != mtu_request)
            || !iface->mtu_request)
        {
            ovsrec_interface_verify_mtu_request(iface);
            ovsrec_interface_set_mtu_request(
                    iface, &mtu_request, mtu_request > 0);
        }
    } else if (iface->mtu_request) {
        ovsrec_interface_verify_mtu_request(iface);
        ovsrec_interface_update_mtu_request_delvalue(iface,
                                                     *iface->mtu_request);
    }
}

const struct ovsrec_port *
ovsport_lookup_by_interfaces(
        struct ovsdb_idl_index *ovsrec_port_by_interfaces,
        struct ovsrec_interface **interfaces,
        const size_t n_interfaces)
{
    struct ovsrec_port *port = ovsrec_port_index_init_row(
            ovsrec_port_by_interfaces);
    ovsrec_port_index_set_interfaces(port, interfaces, n_interfaces);

    const struct ovsrec_port *retval = ovsrec_port_index_find(
            ovsrec_port_by_interfaces, port);

    ovsrec_port_index_destroy_row(port);

    return retval;
}

const struct
ovsrec_port * ovsport_lookup_by_interface(
        struct ovsdb_idl_index *ovsrec_port_by_interfaces,
        struct ovsrec_interface *interface)
{
    struct ovsrec_interface *interfaces[] = {interface};

    return ovsport_lookup_by_interfaces(ovsrec_port_by_interfaces,
                                        interfaces, 1);
}

/* Update an interface map column with the key/value pairs present in the
 * provided smap, only applying changes when necessary. */
static void
update_interface_smap_column(
        const struct ovsrec_interface *iface,
        const struct smap *smap,
        const struct smap *db_smap,
        void (*fsetkey)(const struct ovsrec_interface *,
                         const char *, const char *))
{
    struct smap_node *node;

    SMAP_FOR_EACH (node, smap) {
        const char *db_value = smap_get(db_smap, node->key);

        if (!db_value || strcmp(db_value, node->value)) {
            fsetkey(iface, node->key, node->value);
        }
    }
}

/* Like update_interface_smap_column, but also takes an sset with all the keys
 * we want to maintain.  Any key present in the sset but not in the provided
 * smap will be removed from the database if present there. */
static void
maintain_interface_smap_column(
        const struct ovsrec_interface *iface,
        const struct sset *mnt_items,
        const struct smap *smap,
        const struct smap *db_smap,
        void (*fsetkey)(const struct ovsrec_interface *,
                         const char *, const char *),
        void (*fdelkey)(const struct ovsrec_interface *,
                         const char *))
{
    const char *ref_name;

    SSET_FOR_EACH (ref_name, mnt_items) {
        const char *value = smap_get(smap, ref_name);
        const char *db_value = smap_get(db_smap, ref_name);
        if (!value && db_value) {
            fdelkey(iface, ref_name);
        } else if (value && (!db_value || strcmp(db_value, value)))
        {
            fsetkey(iface, ref_name, value);
        }
    }
}
