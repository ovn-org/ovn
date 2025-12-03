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

static void ls_port_group_process(
    struct ls_port_group_table *,
    struct port_group_ls_table *,
    struct hmapx *,
    const struct hmap *ls_ports,
    const struct nbrec_port_group *,
    struct hmapx *updated_ls_port_groups,
    struct sset *pruned_ls_port_group_recs);

static void ls_port_group_record_clear(
    struct ls_port_group_table *,
    struct port_group_ls_record *,
    struct hmapx *cleared_ls_port_groups);

static bool ls_port_group_record_prune(
    struct ls_port_group *,
    const struct nbrec_port_group *,
    struct sset *);

static struct ls_port_group_record *ls_port_group_record_create(
    struct ls_port_group *,
    const struct nbrec_port_group *);

static struct ls_port_group_record *ls_port_group_record_find(
    struct ls_port_group *, const struct nbrec_port_group *nb_pg);

static void ls_port_group_record_destroy(
    struct ls_port_group *,
    struct ls_port_group_record *);

static struct port_group_ls_record *port_group_ls_record_create(
    struct port_group_ls_table *,
    const struct nbrec_port_group *);
static void port_group_ls_record_destroy(struct port_group_ls_table *,
                                         struct port_group_ls_record *);

static const struct sbrec_port_group *create_sb_port_group(
    struct ovsdb_idl_txn *ovnsb_txn, const char *sb_pg_name);
static void update_sb_port_group(struct sorted_array *nb_ports,
                                 const struct sbrec_port_group *sb_pg);
static const struct sbrec_port_group *sb_port_group_lookup_by_name(
    struct ovsdb_idl_index *sbrec_port_group_by_name, const char *name);

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
ls_port_group_table_build(
    struct ls_port_group_table *ls_port_groups,
    struct port_group_ls_table *port_group_lses,
    const struct nbrec_port_group_table *pg_table,
    const struct hmap *ls_ports)
{
    const struct nbrec_port_group *nb_pg;
    NBREC_PORT_GROUP_TABLE_FOR_EACH (nb_pg, pg_table) {
        ls_port_group_process(ls_port_groups, port_group_lses, NULL,
                              ls_ports, nb_pg, NULL, NULL);
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
            const char *sb_pg_name_cstr = ds_cstr(&sb_name);
            sb_port_group = shash_find_and_delete(&sb_port_groups,
                                                  sb_pg_name_cstr);
            if (!sb_port_group) {
                sb_port_group = create_sb_port_group(ovnsb_txn,
                                                     sb_pg_name_cstr);
            };

            struct sorted_array ports =
                sorted_array_from_sset(&ls_pg_rec->ports);
            update_sb_port_group(&ports, sb_port_group);
            sorted_array_destroy(&ports);
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

/* Process a NB.Port_Group record updated the ls_port_group_table and the
 * port_group_ls_table. Stores a few different updates
 *  1. Updated ls_port_groups are stored in updated_ls_port_groups so the I-P
 *     can update the Southbound database
 *  2. If a port_groups switch set changes the switch is stored in
 *     ls_port_groups_sets_changed so that later I-P nodes can recalculate
 *     lflows.
 *  3. If a port_group has a switch removed from it's switch set it is stored
 *     in pruned_ls_port_group_recs so that the SB entry can be deleted.
 */
static void
ls_port_group_process(struct ls_port_group_table *ls_port_groups,
                      struct port_group_ls_table *port_group_lses,
                      struct hmapx *ls_port_groups_sets_changed,
                      const struct hmap *ls_ports,
                      const struct nbrec_port_group *nb_pg,
                      struct hmapx *updated_ls_port_groups,
                      struct sset *pruned_ls_port_group_recs)
{
    struct hmapx cleared_ls_port_groups =
        HMAPX_INITIALIZER(&cleared_ls_port_groups);

    struct port_group_ls_record *pg_ls =
        port_group_ls_table_find(port_group_lses, nb_pg);
    if (!pg_ls) {
        pg_ls = port_group_ls_record_create(port_group_lses, nb_pg);
    } else {
        /* Clear all old records corresponding to this port group; we'll
         * reprocess it below. */
        ls_port_group_record_clear(ls_port_groups, pg_ls,
                                   &cleared_ls_port_groups);
    }

    if (!nbrec_port_group_is_deleted(nb_pg)) {

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
                ls_pg = ls_port_group_create(ls_port_groups, od->nbs,
                                             od->sdp->sb_dp);
            }

            struct ls_port_group_record *ls_pg_rec =
                ls_port_group_record_find(ls_pg, nb_pg);
            if (!ls_pg_rec) {
                ls_pg_rec = ls_port_group_record_create(ls_pg, nb_pg);
                if (ls_port_groups_sets_changed) {
                    hmapx_add(ls_port_groups_sets_changed,
                              CONST_CAST(struct nbrec_logical_switch *,
                                         od->nbs));
                }
            }
            sset_add(&ls_pg_rec->ports, port_name);

            hmapx_add(&pg_ls->switches,
                      CONST_CAST(struct nbrec_logical_switch *, od->nbs));
            if (updated_ls_port_groups) {
                hmapx_add(updated_ls_port_groups, ls_pg);
            }
        }
    }

    struct hmapx_node *node;
    HMAPX_FOR_EACH (node, &cleared_ls_port_groups) {
        struct ls_port_group *ls_pg = node->data;

        if (ls_port_group_record_prune(ls_pg,
                                       nb_pg,
                                       pruned_ls_port_group_recs)) {
            if (ls_port_groups_sets_changed) {
                hmapx_add(ls_port_groups_sets_changed,
                    CONST_CAST(struct nbrec_logical_switch *,ls_pg->nbs));
            }
            hmapx_find_and_delete(&pg_ls->switches, ls_pg->nbs);
        }

        if (hmap_is_empty(&ls_pg->nb_pgs)) {
            ls_port_group_destroy(ls_port_groups, ls_pg);
        }
    }
    hmapx_destroy(&cleared_ls_port_groups);
}

/* Destroys all the struct ls_port_group_record that might be associated to
 * northbound database logical switches.  Stores ls_port_groups that
 * were cleared in the 'cleared_ls_port_groups' map.
 */
static void
ls_port_group_record_clear(struct ls_port_group_table *ls_to_port_groups,
                           struct port_group_ls_record *pg_ls,
                           struct hmapx *cleared_ls_port_groups)
{
    struct hmapx_node *node;

    HMAPX_FOR_EACH (node, &pg_ls->switches) {
        const struct nbrec_logical_switch *nbs = node->data;

        struct ls_port_group *ls_pg =
            ls_port_group_table_find(ls_to_port_groups, nbs);
        ovs_assert(ls_pg);

        /* Clear ports in the port group record. */
        struct ls_port_group_record *ls_pg_rec =
            ls_port_group_record_find(ls_pg, pg_ls->nb_pg);
        ovs_assert(ls_pg_rec);

        sset_clear(&ls_pg_rec->ports);
        hmapx_add(cleared_ls_port_groups, ls_pg);
    }
}

static bool
ls_port_group_record_prune(struct ls_port_group *ls_pg,
                           const struct nbrec_port_group *nb_pg,
                           struct sset *pruned_ls_pg_rec)
{
    struct ls_port_group_record *ls_pg_rec;
    bool records_pruned = false;

    struct ds sb_pg_name = DS_EMPTY_INITIALIZER;
    ls_pg_rec = ls_port_group_record_find(ls_pg, nb_pg);
    if (sset_is_empty(&ls_pg_rec->ports) ||
        nbrec_port_group_is_deleted(ls_pg_rec->nb_pg)) {
        if (pruned_ls_pg_rec) {
            get_sb_port_group_name(ls_pg_rec->nb_pg->name,
                                   ls_pg->sb_datapath_key,
                                   &sb_pg_name);
            sset_add(pruned_ls_pg_rec, ds_cstr(&sb_pg_name));
        }
        ls_port_group_record_destroy(ls_pg, ls_pg_rec);
        records_pruned = true;
    }
    ds_destroy(&sb_pg_name);
    return records_pruned;
}

static struct ls_port_group_record *
ls_port_group_record_create(struct ls_port_group *ls_pg,
                            const struct nbrec_port_group *nb_pg)
{
    struct ls_port_group_record *ls_pg_rec = xmalloc(sizeof *ls_pg_rec);
    *ls_pg_rec = (struct ls_port_group_record) {
        .nb_pg = nb_pg,
        .ports = SSET_INITIALIZER(&ls_pg_rec->ports),
    };
    hmap_insert(&ls_pg->nb_pgs, &ls_pg_rec->key_node,
                uuid_hash(&nb_pg->header_.uuid));
    return ls_pg_rec;
}

static struct ls_port_group_record *
ls_port_group_record_find(struct ls_port_group *ls_pg,
                          const struct nbrec_port_group *nb_pg)
{
    size_t hash = uuid_hash(&nb_pg->header_.uuid);
    struct ls_port_group_record *ls_pg_rec;

    HMAP_FOR_EACH_WITH_HASH (ls_pg_rec, key_node, hash, &ls_pg->nb_pgs) {
        if (ls_pg_rec->nb_pg == nb_pg) {
            return ls_pg_rec;
        }
    }
    return NULL;
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

void
port_group_ls_table_init(struct port_group_ls_table *table)
{
    *table = (struct port_group_ls_table) {
        .entries = HMAP_INITIALIZER(&table->entries),
    };
}

void
port_group_ls_table_clear(struct port_group_ls_table *table)
{
    struct port_group_ls_record *pg_ls;
    HMAP_FOR_EACH_SAFE (pg_ls, key_node, &table->entries) {
        port_group_ls_record_destroy(table, pg_ls);
    }
}

void
port_group_ls_table_destroy(struct port_group_ls_table *table)
{
    port_group_ls_table_clear(table);
    hmap_destroy(&table->entries);
}

struct port_group_ls_record *
port_group_ls_table_find(const struct port_group_ls_table *table,
                         const struct nbrec_port_group *nb_pg)
{
    struct port_group_ls_record *pg_ls;

    HMAP_FOR_EACH_WITH_HASH (pg_ls, key_node, uuid_hash(&nb_pg->header_.uuid),
                             &table->entries) {
        if (nb_pg == pg_ls->nb_pg) {
            return pg_ls;
        }
    }
    return NULL;
}

static struct port_group_ls_record *
port_group_ls_record_create(struct port_group_ls_table *table,
                            const struct nbrec_port_group *nb_pg)
{
    struct port_group_ls_record *pg_ls = xmalloc(sizeof *pg_ls);

    *pg_ls = (struct port_group_ls_record) {
        .nb_pg = nb_pg,
        .switches = HMAPX_INITIALIZER(&pg_ls->switches),
    };
    hmap_insert(&table->entries, &pg_ls->key_node,
                uuid_hash(&nb_pg->header_.uuid));
    return pg_ls;
}

static void
port_group_ls_record_destroy(struct port_group_ls_table *table,
                             struct port_group_ls_record *pg_ls)
{
    if (pg_ls) {
        hmapx_destroy(&pg_ls->switches);
        hmap_remove(&table->entries, &pg_ls->key_node);
        free(pg_ls);
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
    *pg_data = (struct port_group_data) {
        .ls_port_groups_sets_changed =
            HMAPX_INITIALIZER(&pg_data->ls_port_groups_sets_changed),
    };

    ls_port_group_table_init(&pg_data->ls_port_groups);
    port_group_ls_table_init(&pg_data->port_groups_lses);
    return pg_data;
}

void
en_port_group_cleanup(void *data_)
{
    struct port_group_data *data = data_;

    ls_port_group_table_destroy(&data->ls_port_groups);
    port_group_ls_table_destroy(&data->port_groups_lses);
    hmapx_destroy(&data->ls_port_groups_sets_changed);
}

void
en_port_group_clear_tracked_data(void *data_)
{
    struct port_group_data *data = data_;

    hmapx_clear(&data->ls_port_groups_sets_changed);
}

enum engine_node_state
en_port_group_run(struct engine_node *node, void *data_)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct port_group_input input_data = port_group_get_input_data(node);
    struct port_group_data *data = data_;

    stopwatch_start(PORT_GROUP_RUN_STOPWATCH_NAME, time_msec());

    ls_port_group_table_clear(&data->ls_port_groups);
    port_group_ls_table_clear(&data->port_groups_lses);

    ls_port_group_table_build(&data->ls_port_groups,
                              &data->port_groups_lses,
                              input_data.nbrec_port_group_table,
                              input_data.ls_ports);

    ls_port_group_table_sync(&data->ls_port_groups,
                             input_data.sbrec_port_group_table,
                             eng_ctx->ovnsb_idl_txn);

    stopwatch_stop(PORT_GROUP_RUN_STOPWATCH_NAME, time_msec());
    return EN_UPDATED;
}

enum engine_input_handler_result
port_group_nb_port_group_handler(struct engine_node *node, void *data_)
{
    struct port_group_input input_data = port_group_get_input_data(node);
    const struct engine_context *eng_ctx = engine_get_context();
    struct port_group_data *data = data_;
    bool changed = false;

    const struct nbrec_port_group_table *nb_pg_table =
        EN_OVSDB_GET(engine_get_input("NB_port_group", node));
    const struct nbrec_port_group *nb_pg;

    struct hmapx updated_ls_port_groups =
        HMAPX_INITIALIZER(&updated_ls_port_groups);

    struct sset stale_sb_port_groups = SSET_INITIALIZER(&stale_sb_port_groups);
    NBREC_PORT_GROUP_TABLE_FOR_EACH_TRACKED (nb_pg, nb_pg_table) {
        ls_port_group_process(&data->ls_port_groups,
                              &data->port_groups_lses,
                              &data->ls_port_groups_sets_changed,
                              input_data.ls_ports,
                              nb_pg, &updated_ls_port_groups,
                              &stale_sb_port_groups);
        }

    /* Changes have been successfully processed incrementally now update
     * the SB too. */
    struct ovsdb_idl_index *sbrec_port_group_by_name =
        engine_ovsdb_node_get_index(
                engine_get_input("SB_port_group", node),
                "sbrec_port_group_by_name");
    struct ds sb_pg_name = DS_EMPTY_INITIALIZER;

    struct hmapx_node *updated_node;
    HMAPX_FOR_EACH (updated_node, &updated_ls_port_groups) {
        changed = true;
        const struct ls_port_group *ls_pg = updated_node->data;
        struct ls_port_group_record *ls_pg_rec;

        HMAP_FOR_EACH (ls_pg_rec, key_node, &ls_pg->nb_pgs) {
            get_sb_port_group_name(ls_pg_rec->nb_pg->name,
                                   ls_pg->sb_datapath_key,
                                   &sb_pg_name);

            const char *sb_pg_name_cstr = ds_cstr(&sb_pg_name);
            const struct sbrec_port_group *sb_pg =
                sb_port_group_lookup_by_name(sbrec_port_group_by_name,
                                             sb_pg_name_cstr);
            if (!sb_pg) {
                sb_pg = create_sb_port_group(eng_ctx->ovnsb_idl_txn,
                                             sb_pg_name_cstr);
            }
            struct sorted_array nb_ports =
                sorted_array_from_sset(&ls_pg_rec->ports);
            update_sb_port_group(&nb_ports, sb_pg);
            sorted_array_destroy(&nb_ports);
        }
    }
    ds_destroy(&sb_pg_name);

    const char *stale_sb_port_group_name;
    SSET_FOR_EACH (stale_sb_port_group_name, &stale_sb_port_groups) {
        changed = true;
        const struct sbrec_port_group *sb_pg =
            sb_port_group_lookup_by_name(sbrec_port_group_by_name,
                                         stale_sb_port_group_name);
        if (sb_pg) {
            sbrec_port_group_delete(sb_pg);
        }
    }

    sset_destroy(&stale_sb_port_groups);
    hmapx_destroy(&updated_ls_port_groups);
    return changed ? EN_HANDLED_UPDATED : EN_HANDLED_UNCHANGED;
}

static void
sb_port_group_apply_diff(const void *arg, const char *item, bool add)
{
    const struct sbrec_port_group *pg = arg;
    if (add) {
        sbrec_port_group_update_ports_addvalue(pg, item);
    } else {
        sbrec_port_group_update_ports_delvalue(pg, item);
    }
}

static const struct sbrec_port_group *
create_sb_port_group(struct ovsdb_idl_txn *ovnsb_txn, const char *sb_pg_name)
{
    struct sbrec_port_group *sb_port_group =
        sbrec_port_group_insert(ovnsb_txn);

    sbrec_port_group_set_name(sb_port_group, sb_pg_name);
    return sb_port_group;
}

static void
update_sb_port_group(struct sorted_array *nb_ports,
                     const struct sbrec_port_group *sb_pg)
{
    struct sorted_array sb_ports = sorted_array_from_dbrec(sb_pg, ports);
    sorted_array_apply_diff(nb_ports, &sb_ports,
                            sb_port_group_apply_diff, sb_pg);
    sorted_array_destroy(&sb_ports);
}

/* Finds and returns the port group set with the given 'name', or NULL
 * if no such port group exists. */
static const struct sbrec_port_group *
sb_port_group_lookup_by_name(struct ovsdb_idl_index *sbrec_port_group_by_name,
                             const char *name)
{
    struct sbrec_port_group *target = sbrec_port_group_index_init_row(
        sbrec_port_group_by_name);
    sbrec_port_group_index_set_name(target, name);

    struct sbrec_port_group *retval = sbrec_port_group_index_find(
        sbrec_port_group_by_name, target);

    sbrec_port_group_index_destroy_row(target);
    return retval;
}
