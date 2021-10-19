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

#ifndef OVSPORT_H
#define OVSPORT_H 1

/* OVS Ports
 * =========
 *
 * This module contains utility functions for adding, removing and maintaining
 * ports and their interface records on OVS bridges. */

#include "smap.h"
#include "sset.h"

#include <stdbool.h>
#include <stdint.h>

struct ovsdb_idl_txn;
struct ovsrec_bridge;
struct ovsrec_port;
struct ovsrec_interface;
struct ovsdb_idl_index;

void ovsport_create(struct ovsdb_idl_txn *ovs_idl_txn,
                    const struct ovsrec_bridge *bridge,
                    const char *name,
                    const char *iface_type,
                    const struct smap *port_external_ids,
                    const struct smap *iface_external_ids,
                    const struct smap *iface_options,
                    const int64_t iface_mtu_request);
void ovsport_remove(const struct ovsrec_bridge *bridge,
                    const struct ovsrec_port *port);
void ovsport_update_iface(const struct ovsrec_interface *iface,
                          const char *type,
                          const struct smap *external_ids,
                          const struct sset *mnt_external_ids,
                          const struct smap *options,
                          const struct sset *mnt_options,
                          const int64_t mtu_request);
const struct ovsrec_port * ovsport_lookup_by_interfaces(
        struct ovsdb_idl_index *, struct ovsrec_interface **,
        const size_t n_interfaces);
const struct ovsrec_port * ovsport_lookup_by_interface(
        struct ovsdb_idl_index *, struct ovsrec_interface *);

#endif /* lib/ovsport.h */
