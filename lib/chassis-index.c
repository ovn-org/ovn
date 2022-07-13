
/* Copyright (c) 2016, 2017 Red Hat, Inc.
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
#include "lib/chassis-index.h"
#include "lib/ovn-sb-idl.h"

struct ovsdb_idl_index *
chassis_index_create(struct ovsdb_idl *idl)
{
    return ovsdb_idl_index_create1(idl, &sbrec_chassis_col_name);
}

struct ovsdb_idl_index *
chassis_hostname_index_create(struct ovsdb_idl *idl)
{
    return ovsdb_idl_index_create1(idl, &sbrec_chassis_col_hostname);
}

/* Finds and returns the chassis with the given 'name', or NULL if no such
 * chassis exists. */
const struct sbrec_chassis *
chassis_lookup_by_name(struct ovsdb_idl_index *sbrec_chassis_by_name,
                       const char *name)
{
    struct sbrec_chassis *target =
        sbrec_chassis_index_init_row(sbrec_chassis_by_name);
    sbrec_chassis_index_set_name(target, name);

    struct sbrec_chassis *retval =
        sbrec_chassis_index_find(sbrec_chassis_by_name, target);

    sbrec_chassis_index_destroy_row(target);

    return retval;
}

/* Finds and returns the chassis with the given 'hostname', or NULL if no such
 * chassis exists. */
const struct sbrec_chassis *
chassis_lookup_by_hostname(struct ovsdb_idl_index *sbrec_chassis_by_hostname,
                           const char *hostname)
{
    struct sbrec_chassis *target =
        sbrec_chassis_index_init_row(sbrec_chassis_by_hostname);
    sbrec_chassis_index_set_hostname(target, hostname);

    struct sbrec_chassis *retval =
        sbrec_chassis_index_find(sbrec_chassis_by_hostname, target);

    sbrec_chassis_index_destroy_row(target);

    return retval;
}

struct ovsdb_idl_index *
chassis_private_index_create(struct ovsdb_idl *idl)
{
    return ovsdb_idl_index_create1(idl, &sbrec_chassis_private_col_name);
}

/* Finds and returns the chassis with the given 'name', or NULL if no such
 * chassis exists. */
const struct sbrec_chassis_private *
chassis_private_lookup_by_name(struct ovsdb_idl_index
                               *sbrec_chassis_private_by_name,
                               const char *name)
{
    struct sbrec_chassis_private *target =
        sbrec_chassis_private_index_init_row(sbrec_chassis_private_by_name);
    sbrec_chassis_private_index_set_name(target, name);

    struct sbrec_chassis_private *retval =
        sbrec_chassis_private_index_find(sbrec_chassis_private_by_name,
                                         target);

    sbrec_chassis_private_index_destroy_row(target);

    return retval;
}

struct ovsdb_idl_index *
ha_chassis_group_index_create(struct ovsdb_idl *idl)
{
    return ovsdb_idl_index_create1(idl, &sbrec_ha_chassis_group_col_name);
}

/* Finds and returns the HA chassis group with the given 'name', or NULL
 * if no such HA chassis group exists. */
const struct sbrec_ha_chassis_group *
ha_chassis_group_lookup_by_name(struct ovsdb_idl_index
                                *sbrec_ha_chassis_grp_by_name,
                                const char *name)
{
    struct sbrec_ha_chassis_group *target =
        sbrec_ha_chassis_group_index_init_row(sbrec_ha_chassis_grp_by_name);
    sbrec_ha_chassis_group_index_set_name(target, name);

    struct sbrec_ha_chassis_group *retval =
        sbrec_ha_chassis_group_index_find(sbrec_ha_chassis_grp_by_name,
                                          target);

    sbrec_ha_chassis_group_index_destroy_row(target);

    return retval;
}
