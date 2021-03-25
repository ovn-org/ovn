/*
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

#ifndef OVN_DBCTL_H
#define OVN_DBCTL_H 1

/* Common code for ovn-sbctl and ovn-nbctl. */

#include <stdbool.h>
#include "ovsdb-idl.h"

struct timer;

enum nbctl_wait_type {
    NBCTL_WAIT_NONE,            /* Do not wait. */
    NBCTL_WAIT_SB,              /* Wait for southbound database updates. */
    NBCTL_WAIT_HV               /* Wait for hypervisors to catch up. */
};

struct ovn_dbctl_options {
    const char *db_version;     /* Database schema version. */
    const char *default_db;     /* Default database remote. */
    bool allow_wait;            /* Allow --wait and related options? */

    /* Names of important environment variables. */
    const char *options_env_var_name; /* OVN_??_OPTIONS. */
    const char *daemon_env_var_name;  /* OVN_??_DAEMON. */

    const struct ovsdb_idl_class *idl_class;
    const struct ctl_table_class *tables;
    struct cmd_show_table *cmd_show_table;
    const struct ctl_command_syntax *commands;

    void (*usage)(void);

    void (*add_base_prerequisites)(struct ovsdb_idl *, enum nbctl_wait_type);
    void (*pre_execute)(struct ovsdb_idl *, struct ovsdb_idl_txn *,
                        enum nbctl_wait_type);
    char *(*post_execute)(struct ovsdb_idl *, struct ovsdb_idl_txn *,
                          enum ovsdb_idl_txn_status, enum nbctl_wait_type,
                          const struct timer *wait_timeout,
                          long long int start_time, bool print_wait_time);

    struct ctl_context *(*ctx_create)(void);
    void (*ctx_destroy)(struct ctl_context *);
};

int ovn_dbctl_main(int argc, char *argv[], const struct ovn_dbctl_options *);

#endif  /* ovn-dbctl.h */
