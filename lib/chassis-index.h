
/* Copyright (c) 2017, Red Hat, Inc.
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

#ifndef OVN_CHASSIS_INDEX_H
#define OVN_CHASSIS_INDEX_H 1

struct ovsdb_idl;

struct ovsdb_idl_index *chassis_index_create(struct ovsdb_idl *);
struct ovsdb_idl_index *chassis_hostname_index_create(struct ovsdb_idl *);

const struct sbrec_chassis *chassis_lookup_by_name(struct ovsdb_idl_index
                                                   *sbrec_chassis_by_name,
                                                   const char *name);
const struct sbrec_chassis *chassis_lookup_by_hostname(struct ovsdb_idl_index
                                                       *sbrec_chassis_by_hostname,
                                                       const char *hostname);

struct ovsdb_idl_index *chassis_private_index_create(struct ovsdb_idl *);

const struct sbrec_chassis_private *chassis_private_lookup_by_name(struct
                                                                   ovsdb_idl_index
                                                                   *sbrec_chassis_private_by_name,
                                                                   const char
                                                                   *name);

struct ovsdb_idl_index *ha_chassis_group_index_create(struct ovsdb_idl *idl);
const struct sbrec_ha_chassis_group *ha_chassis_group_lookup_by_name(struct
                                                                     ovsdb_idl_index
                                                                     *sbrec_ha_chassis_grp_by_name,
                                                                     const char
                                                                     *name);

#endif /* lib/chassis-index.h */
