/*
 * Copyright (c) 2023, Red Hat, Inc.
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
#include "stopwatch.h"

#include "en-port-group.h"
#include "lib/stopwatch-names.h"
#include "northd.h"

VLOG_DEFINE_THIS_MODULE(en_port_group);

static struct ls_port_group *ls_port_group_create(
    struct ls_port_group_table *,
    const struct nbrec_logical_switch *,
    const struct sbrec_datapath_binding *);

static void ls_port_group_destroy(struct ls_port_group_table *,
                                  struct ls_port_group *);

static struct ls_port_group_record *ls_port_group_record_add(
    struct ls_port_group *,
    const struct nbrec_port_group *,
    const char *port_name);

static void ls_port_group_record_destroy(
    struct ls_port_group *,
    struct ls_port_group_record *);

void
ls_port_group_table_init(struct ls_port_group_table *table)
{
    *table = (struct ls_port_group_table) {
        .entries = HMAP_INITIALIZER(&table->entries),
    };
}

void
ls_port_group_table_clear(struct ls_port_group_table *table)
{
    struct ls_port_group *ls_pg;
    HMAP_FOR_EACH_SAFE (ls_pg, key_node, &table->entries) {
        ls_port_group_destroy(table, ls_pg);
    }
}

void
ls_port_group_table_destroy(struct ls_port_group_table *table)
{
    ls_port_group_table_clear(table);
    hmap_destroy(&table->entries);
}

struct ls_port_group *
ls_port_group_table_find(const struct ls_port_group_table *table,
                         const struct nbrec_logical_switch *nbs)
{
    struct ls_port_group *ls_pg;

    HMAP_FOR_EACH_WITH_HASH (ls_pg, key_node, uuid_hash(&nbs->header_.uuid),
                             &table->entries) {
        if (nbs == ls_pg->nbs) {
            return ls_pg;
        }
    }
    return NULL;
}

void
ls_port_group_table_build(struct ls_port_group_table *ls_port_groups,
                          const struct nbrec_port_group_table *pg_table,
                          const struct hmap *ls_ports)
{
    const struct nbrec_port_group *nb_pg;
    NBREC_PORT_GROUP_TABLE_FOR_EACH (nb_pg, pg_table) {
        for (size_t i = 0; i < nb_pg->n_ports; i++) {
            const char *port_name = nb_pg->ports[i]->name;
            const struct ovn_datapath *od =
                northd_get_datapath_for_port(ls_ports, port_name);

            if (!od) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_ERR_RL(&rl, "lport %s in port group %s not found.",
                            port_name, nb_pg->name);
                continue;
            }

            if (!od->nbs) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "lport %s in port group %s has no lswitch.",
                             nb_pg->ports[i]->name,
                             nb_pg->name);
                continue;
            }

            struct ls_port_group *ls_pg =
                ls_port_group_table_find(ls_port_groups, od->nbs);
            if (!ls_pg) {
                ls_pg = ls_port_group_create(ls_port_groups, od->nbs, od->sb);
            }
            ls_port_group_record_add(ls_pg, nb_pg, port_name);
        }
    }
}

/* Each port group in Port_Group table in OVN_Northbound has a corresponding
 * entry in Port_Group table in OVN_Southbound. In OVN_Northbound the entries
 * contains lport uuids, while in OVN_Southbound we store the lport names.
 */
void
ls_port_group_table_sync(
    const struct ls_port_group_table *ls_port_groups,
    const struct sbrec_port_group_table *sbrec_port_group_table,
    struct ovsdb_idl_txn *ovnsb_txn)
{
    struct shash sb_port_groups = SHASH_INITIALIZER(&sb_port_groups);

    const struct sbrec_port_group *sb_port_group;
    SBREC_PORT_GROUP_TABLE_FOR_EACH (sb_port_group, sbrec_port_group_table) {
        shash_add(&sb_port_groups, sb_port_group->name, sb_port_group);
    }

    struct ds sb_name = DS_EMPTY_INITIALIZER;

    struct ls_port_group *ls_pg;
    HMAP_FOR_EACH (ls_pg, key_node, &ls_port_groups->entries) {
        struct ls_port_group_record *ls_pg_rec;

        HMAP_FOR_EACH (ls_pg_rec, key_node, &ls_pg->nb_pgs) {
            get_sb_port_group_name(ls_pg_rec->nb_pg->name,
                                   ls_pg->sb_datapath_key,
                                   &sb_name);
            sb_port_group = shash_find_and_delete(&sb_port_groups,
                                                  ds_cstr(&sb_name));
            if (!sb_port_group) {
                sb_port_group = sbrec_port_group_insert(ovnsb_txn);
                sbrec_port_group_set_name(sb_port_group, ds_cstr(&sb_name));
            }

            const char **nb_port_names = sset_array(&ls_pg_rec->ports);
            sbrec_port_group_set_ports(sb_port_group,
                                       nb_port_names,
                                       sset_count(&ls_pg_rec->ports));
            free(nb_port_names);
        }
    }
    ds_destroy(&sb_name);

    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &sb_port_groups) {
        sbrec_port_group_delete(node->data);
        shash_delete(&sb_port_groups, node);
    }
    shash_destroy(&sb_port_groups);
}

static struct ls_port_group *
ls_port_group_create(struct ls_port_group_table *ls_port_groups,
                     const struct nbrec_logical_switch *nbs,
                     const struct sbrec_datapath_binding *dp)
{
    struct ls_port_group *ls_pg = xmalloc(sizeof *ls_pg);

    *ls_pg = (struct ls_port_group) {
        .nbs = nbs,
        .sb_datapath_key = dp->tunnel_key,
        .nb_pgs = HMAP_INITIALIZER(&ls_pg->nb_pgs),
    };
    hmap_insert(&ls_port_groups->entries, &ls_pg->key_node,
                uuid_hash(&nbs->header_.uuid));
    return ls_pg;
}

static void
ls_port_group_destroy(struct ls_port_group_table *ls_port_groups,
                      struct ls_port_group *ls_pg)
{
    if (ls_pg) {
        struct ls_port_group_record *ls_pg_rec;
        HMAP_FOR_EACH_SAFE (ls_pg_rec, key_node, &ls_pg->nb_pgs) {
            ls_port_group_record_destroy(ls_pg, ls_pg_rec);
        }
        hmap_destroy(&ls_pg->nb_pgs);
        hmap_remove(&ls_port_groups->entries, &ls_pg->key_node);
        free(ls_pg);
    }
}

static struct ls_port_group_record *
ls_port_group_record_add(struct ls_port_group *ls_pg,
                         const struct nbrec_port_group *nb_pg,
                         const char *port_name)
{
    struct ls_port_group_record *ls_pg_rec = NULL;
    size_t hash = uuid_hash(&nb_pg->header_.uuid);

    HMAP_FOR_EACH_WITH_HASH (ls_pg_rec, key_node, hash, &ls_pg->nb_pgs) {
        if (ls_pg_rec->nb_pg == nb_pg) {
            goto done;
        }
    }

    ls_pg_rec = xzalloc(sizeof *ls_pg_rec);
    *ls_pg_rec = (struct ls_port_group_record) {
        .nb_pg = nb_pg,
        .ports = SSET_INITIALIZER(&ls_pg_rec->ports),
    };
    hmap_insert(&ls_pg->nb_pgs, &ls_pg_rec->key_node, hash);
done:
    sset_add(&ls_pg_rec->ports, port_name);
    return ls_pg_rec;
}

static void
ls_port_group_record_destroy(struct ls_port_group *ls_pg,
                             struct ls_port_group_record *ls_pg_rec)
{
    if (ls_pg_rec) {
        hmap_remove(&ls_pg->nb_pgs, &ls_pg_rec->key_node);
        sset_destroy(&ls_pg_rec->ports);
        free(ls_pg_rec);
    }
}

/* Incremental processing implementation. */
static struct port_group_input
port_group_get_input_data(struct engine_node *node)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);

    return (struct port_group_input) {
        .nbrec_port_group_table =
            EN_OVSDB_GET(engine_get_input("NB_port_group", node)),
        .sbrec_port_group_table =
            EN_OVSDB_GET(engine_get_input("SB_port_group", node)),
        .ls_ports = &northd_data->ls_ports,
    };
}

void *
en_port_group_init(struct engine_node *node OVS_UNUSED,
                   struct engine_arg *arg OVS_UNUSED)
{
    struct port_group_data *pg_data = xmalloc(sizeof *pg_data);

    ls_port_group_table_init(&pg_data->ls_port_groups);
    return pg_data;
}

void
en_port_group_cleanup(void *data_)
{
    struct port_group_data *data = data_;

    ls_port_group_table_destroy(&data->ls_port_groups);
}

void
en_port_group_run(struct engine_node *node, void *data_)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct port_group_input input_data = port_group_get_input_data(node);
    struct port_group_data *data = data_;

    stopwatch_start(PORT_GROUP_RUN_STOPWATCH_NAME, time_msec());

    ls_port_group_table_clear(&data->ls_port_groups);
    ls_port_group_table_build(&data->ls_port_groups,
                              input_data.nbrec_port_group_table,
                              input_data.ls_ports);

    ls_port_group_table_sync(&data->ls_port_groups,
                             input_data.sbrec_port_group_table,
                             eng_ctx->ovnsb_idl_txn);

    stopwatch_stop(PORT_GROUP_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}
