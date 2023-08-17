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

#include "en-meters.h"
#include "lib/stopwatch-names.h"

VLOG_DEFINE_THIS_MODULE(en_meters);

static void build_meter_groups(struct shash *meter_group,
                               const struct nbrec_meter_table *);
static void sync_meters(struct ovsdb_idl_txn *ovnsb_txn,
                        const struct nbrec_meter_table *,
                        const struct nbrec_acl_table *,
                        const struct sbrec_meter_table *,
                        struct shash *meter_groups);

void
*en_sync_meters_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct sync_meters_data *data = xmalloc(sizeof *data);

    *data = (struct sync_meters_data) {
        .meter_groups = SHASH_INITIALIZER(&data->meter_groups),
    };
    return data;
}

void
en_sync_meters_cleanup(void *data_)
{
    struct sync_meters_data *data = data_;

    shash_destroy(&data->meter_groups);
}

void
en_sync_meters_run(struct engine_node *node, void *data_)
{
    struct sync_meters_data *data = data_;

    const struct nbrec_acl_table *acl_table =
        EN_OVSDB_GET(engine_get_input("NB_acl", node));

    const struct nbrec_meter_table *nb_meter_table =
        EN_OVSDB_GET(engine_get_input("NB_meter", node));

    const struct sbrec_meter_table *sb_meter_table =
        EN_OVSDB_GET(engine_get_input("SB_meter", node));

    const struct engine_context *eng_ctx = engine_get_context();

    stopwatch_start(SYNC_METERS_RUN_STOPWATCH_NAME, time_msec());

    build_meter_groups(&data->meter_groups, nb_meter_table);

    sync_meters(eng_ctx->ovnsb_idl_txn, nb_meter_table, acl_table,
                sb_meter_table, &data->meter_groups);

    stopwatch_stop(SYNC_METERS_RUN_STOPWATCH_NAME, time_msec());
    engine_set_node_state(node, EN_UPDATED);
}

const struct nbrec_meter*
fair_meter_lookup_by_name(const struct shash *meter_groups,
                          const char *meter_name)
{
    const struct nbrec_meter *nb_meter =
        meter_name ? shash_find_data(meter_groups, meter_name) : NULL;
    if (nb_meter) {
        return (nb_meter->fair && *nb_meter->fair) ? nb_meter : NULL;
    }
    return NULL;
}

struct band_entry {
    int64_t rate;
    int64_t burst_size;
    const char *action;
};

static int
band_cmp(const void *band1_, const void *band2_)
{
    const struct band_entry *band1p = band1_;
    const struct band_entry *band2p = band2_;

    if (band1p->rate != band2p->rate) {
        return band1p->rate - band2p->rate;
    } else if (band1p->burst_size != band2p->burst_size) {
        return band1p->burst_size - band2p->burst_size;
    } else {
        return strcmp(band1p->action, band2p->action);
    }
}

static bool
bands_need_update(const struct nbrec_meter *nb_meter,
                  const struct sbrec_meter *sb_meter)
{
    if (nb_meter->n_bands != sb_meter->n_bands) {
        return true;
    }

    /* Place the Northbound entries in sorted order. */
    struct band_entry *nb_bands;
    nb_bands = xmalloc(sizeof *nb_bands * nb_meter->n_bands);
    for (size_t i = 0; i < nb_meter->n_bands; i++) {
        struct nbrec_meter_band *nb_band = nb_meter->bands[i];

        nb_bands[i].rate = nb_band->rate;
        nb_bands[i].burst_size = nb_band->burst_size;
        nb_bands[i].action = nb_band->action;
    }
    qsort(nb_bands, nb_meter->n_bands, sizeof *nb_bands, band_cmp);

    /* Place the Southbound entries in sorted order. */
    struct band_entry *sb_bands;
    sb_bands = xmalloc(sizeof *sb_bands * sb_meter->n_bands);
    for (size_t i = 0; i < sb_meter->n_bands; i++) {
        struct sbrec_meter_band *sb_band = sb_meter->bands[i];

        sb_bands[i].rate = sb_band->rate;
        sb_bands[i].burst_size = sb_band->burst_size;
        sb_bands[i].action = sb_band->action;
    }
    qsort(sb_bands, sb_meter->n_bands, sizeof *sb_bands, band_cmp);

    bool need_update = false;
    for (size_t i = 0; i < nb_meter->n_bands; i++) {
        if (band_cmp(&nb_bands[i], &sb_bands[i])) {
            need_update = true;
            break;
        }
    }

    free(nb_bands);
    free(sb_bands);

    return need_update;
}

static void
sync_meters_iterate_nb_meter(struct ovsdb_idl_txn *ovnsb_txn,
                             const char *meter_name,
                             const struct nbrec_meter *nb_meter,
                             struct shash *sb_meters,
                             struct sset *used_sb_meters)
{
    const struct sbrec_meter *sb_meter;
    bool new_sb_meter = false;

    sb_meter = shash_find_data(sb_meters, meter_name);
    if (!sb_meter) {
        sb_meter = sbrec_meter_insert(ovnsb_txn);
        sbrec_meter_set_name(sb_meter, meter_name);
        shash_add(sb_meters, sb_meter->name, sb_meter);
        new_sb_meter = true;
    }
    sset_add(used_sb_meters, meter_name);

    if (new_sb_meter || bands_need_update(nb_meter, sb_meter)) {
        struct sbrec_meter_band **sb_bands;
        sb_bands = xcalloc(nb_meter->n_bands, sizeof *sb_bands);
        for (size_t i = 0; i < nb_meter->n_bands; i++) {
            const struct nbrec_meter_band *nb_band = nb_meter->bands[i];

            sb_bands[i] = sbrec_meter_band_insert(ovnsb_txn);

            sbrec_meter_band_set_action(sb_bands[i], nb_band->action);
            sbrec_meter_band_set_rate(sb_bands[i], nb_band->rate);
            sbrec_meter_band_set_burst_size(sb_bands[i],
                                            nb_band->burst_size);
        }
        sbrec_meter_set_bands(sb_meter, sb_bands, nb_meter->n_bands);
        free(sb_bands);
    }

    sbrec_meter_set_unit(sb_meter, nb_meter->unit);
}

static void
sync_acl_fair_meter(struct ovsdb_idl_txn *ovnsb_txn,
                    struct shash *meter_groups,
                    const struct nbrec_acl *acl, struct shash *sb_meters,
                    struct sset *used_sb_meters)
{
    const struct nbrec_meter *nb_meter =
        fair_meter_lookup_by_name(meter_groups, acl->meter);

    if (!nb_meter) {
        return;
    }

    char *meter_name = alloc_acl_log_unique_meter_name(acl);
    sync_meters_iterate_nb_meter(ovnsb_txn, meter_name, nb_meter, sb_meters,
                                 used_sb_meters);
    free(meter_name);
}

static void
build_meter_groups(struct shash *meter_groups,
                   const struct nbrec_meter_table *nb_meter_table)
{
    const struct nbrec_meter *nb_meter;

    shash_clear(meter_groups);
    NBREC_METER_TABLE_FOR_EACH (nb_meter, nb_meter_table) {
        shash_add(meter_groups, nb_meter->name, nb_meter);
    }
}

/* Each entry in the Meter and Meter_Band tables in OVN_Northbound have
 * a corresponding entries in the Meter and Meter_Band tables in
 * OVN_Southbound. Additionally, ACL logs that use fair meters have
 * a private copy of its meter in the SB table.
 */
static void
sync_meters(struct ovsdb_idl_txn *ovnsb_txn,
            const struct nbrec_meter_table *nbrec_meter_table,
            const struct nbrec_acl_table *nbrec_acl_table,
            const struct sbrec_meter_table *sbrec_meter_table,
            struct shash *meter_groups)
{
    struct shash sb_meters = SHASH_INITIALIZER(&sb_meters);
    struct sset used_sb_meters = SSET_INITIALIZER(&used_sb_meters);

    const struct sbrec_meter *sb_meter;
    SBREC_METER_TABLE_FOR_EACH (sb_meter, sbrec_meter_table) {
        shash_add(&sb_meters, sb_meter->name, sb_meter);
    }

    const struct nbrec_meter *nb_meter;
    NBREC_METER_TABLE_FOR_EACH (nb_meter, nbrec_meter_table) {
        sync_meters_iterate_nb_meter(ovnsb_txn, nb_meter->name, nb_meter,
                                     &sb_meters, &used_sb_meters);
    }

    /*
     * In addition to creating Meters in the SB from the block above, check
     * and see if additional rows are needed to get ACLs logs individually
     * rate-limited.
     */
    const struct nbrec_acl *acl;
    NBREC_ACL_TABLE_FOR_EACH (acl, nbrec_acl_table) {
        sync_acl_fair_meter(ovnsb_txn, meter_groups, acl,
                            &sb_meters, &used_sb_meters);
    }

    const char *used_meter;
    SSET_FOR_EACH_SAFE (used_meter, &used_sb_meters) {
        shash_find_and_delete(&sb_meters, used_meter);
        sset_delete(&used_sb_meters, SSET_NODE_FROM_NAME(used_meter));
    }
    sset_destroy(&used_sb_meters);

    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &sb_meters) {
        sbrec_meter_delete(node->data);
        shash_delete(&sb_meters, node);
    }
    shash_destroy(&sb_meters);
}
