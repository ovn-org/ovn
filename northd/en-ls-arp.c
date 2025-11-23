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

#include <config.h>

/* OVS includes */
#include "include/openvswitch/hmap.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"
#include "stopwatch.h"

/* OVN includes */
#include "en-lr-nat.h"
#include "en-ls-arp.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "lib/stopwatch-names.h"
#include "lflow-mgr.h"
#include "northd.h"

VLOG_DEFINE_THIS_MODULE(en_ls_arp);

/* Static functions. */
struct ls_arp_input {
    const struct ovn_datapaths *ls_datapaths;
    const struct lr_nat_table *lr_nats;
};

static struct ls_arp_input
ls_arp_get_input_data(struct engine_node *node)
{
    const struct northd_data *northd_data =
        engine_get_input_data("northd", node);
    struct ed_type_lr_nat_data *lr_nat_data =
        engine_get_input_data("lr_nat", node);

    return (struct ls_arp_input) {
        .ls_datapaths = &northd_data->ls_datapaths,
        .lr_nats = &lr_nat_data->lr_nats,
    };
}

static void
ls_arp_record_clear(struct ls_arp_record *ls_arp_record)
{
    lflow_ref_destroy(ls_arp_record->lflow_ref);
    hmapx_destroy(&ls_arp_record->nat_records);
    free(ls_arp_record);
}

static void
ls_arp_table_clear(struct ls_arp_table *table)
{
    struct ls_arp_record *ls_arp_record;
    HMAP_FOR_EACH_POP (ls_arp_record, key_node, &table->entries) {
        ls_arp_record_clear(ls_arp_record);
    }
}

static inline bool
is_centralized_nat_record(const struct ovn_nat *nat_entry)
{
    return nat_entry->is_valid
           && nat_entry->l3dgw_port
           && nat_entry->l3dgw_port->peer
           && nat_entry->l3dgw_port->peer->od
           && !nat_entry->is_distributed;
}

static void
nat_record_data_create(struct ls_arp_record *ls_arp_record,
                       const struct ovn_datapath *od,
                       const struct lr_nat_table *lr_nats)
{
    struct ovn_port *op;
    VECTOR_FOR_EACH (&od->router_ports, op) {
        const struct ovn_datapath *lr_od = op->peer->od;
        const struct lr_nat_record *lrnat_rec =
            lr_nat_table_find_by_uuid(lr_nats, lr_od->key);

        if (!lrnat_rec) {
            continue;
        }

        for (size_t i = 0; i < lrnat_rec->n_nat_entries; i++) {
            const struct ovn_nat *nat_entry = &lrnat_rec->nat_entries[i];

            if (is_centralized_nat_record(nat_entry)) {
                hmapx_add(&ls_arp_record->nat_records,
                          (struct lrnat_rec *) lrnat_rec);
            }
        }
    }
}

static struct ls_arp_record *
ls_arp_record_lookup_by_od_(const struct ls_arp_table *table,
                            const struct ovn_datapath *od)
{
    struct ls_arp_record *ls_arp_record;
    HMAP_FOR_EACH_WITH_HASH (ls_arp_record, key_node,
                             uuid_hash(&od->nbs->header_.uuid),
                             &table->entries) {
        if (uuid_equals(&ls_arp_record->nbs_uuid,
                        &od->nbs->header_.uuid)) {
            return ls_arp_record;
        }
    }

    return NULL;
}

static struct ls_arp_record *
ls_arp_record_create(struct ls_arp_table *table,
                     const struct ovn_datapath *od,
                     const struct lr_nat_table *lr_nats)
{
    struct ls_arp_record *ls_arp_record = xzalloc(sizeof *ls_arp_record);

    ls_arp_record->ls_index = od->index;
    ls_arp_record->nbs_uuid = od->nbs->header_.uuid;

    hmapx_init(&ls_arp_record->nat_records);
    nat_record_data_create(ls_arp_record, od, lr_nats);

    ls_arp_record->lflow_ref = lflow_ref_create();

    hmap_insert(&table->entries, &ls_arp_record->key_node,
                uuid_hash(&od->nbs->header_.uuid));

    return ls_arp_record;
}

/* Public functions. */
void*
en_ls_arp_init(struct engine_node *node OVS_UNUSED,
               struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_ls_arp *data = xzalloc(sizeof *data);

    hmap_init(&data->table.entries);
    hmapx_init(&data->trk_data.crupdated);
    hmapx_init(&data->trk_data.deleted);

    return data;
}

void
en_ls_arp_clear_tracked_data(void *data_)
{
    struct ed_type_ls_arp *data = data_;
    hmapx_clear(&data->trk_data.crupdated);

    struct hmapx_node *n;
    HMAPX_FOR_EACH_SAFE (n, &data->trk_data.deleted) {
        ls_arp_record_clear(n->data);
        hmapx_delete(&data->trk_data.deleted, n);
    }
    hmapx_clear(&data->trk_data.deleted);
}

void
en_ls_arp_cleanup(void *data_)
{
    struct ed_type_ls_arp *data = data_;

    ls_arp_table_clear(&data->table);
    hmap_destroy(&data->table.entries);
    hmapx_destroy(&data->trk_data.crupdated);

    struct hmapx_node *n;
    HMAPX_FOR_EACH_SAFE (n, &data->trk_data.deleted) {
        ls_arp_record_clear(n->data);
        hmapx_delete(&data->trk_data.deleted, n);
    }
    hmapx_destroy(&data->trk_data.deleted);
}

enum engine_node_state
en_ls_arp_run(struct engine_node *node, void *data_)
{
    struct ls_arp_input input_data = ls_arp_get_input_data(node);
    struct ed_type_ls_arp *data = data_;

    stopwatch_start(LS_ARP_RUN_STOPWATCH_NAME, time_msec());

    ls_arp_table_clear(&data->table);

    const struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &input_data.ls_datapaths->datapaths) {
        /* Filtering ARP entries at logical switch works
         * when there are physical ports on the switch. */
        if (hmapx_is_empty(&od->phys_ports)) {
            continue;
        }

        ls_arp_record_create(&data->table, od, input_data.lr_nats);
    }

    stopwatch_stop(LS_ARP_RUN_STOPWATCH_NAME, time_msec());

    return EN_UPDATED;
}

/* Handler functions. */
enum engine_input_handler_result
ls_arp_northd_handler(struct engine_node *node, void *data_)
{
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    if (!northd_has_tracked_data(&northd_data->trk_data)) {
        return EN_UNHANDLED;
    }

    if (!northd_has_lswitches_in_tracked_data(&northd_data->trk_data)) {
        return EN_HANDLED_UNCHANGED;
    }

    struct northd_tracked_data *nd_changes = &northd_data->trk_data;
    struct ls_arp_input input_data = ls_arp_get_input_data(node);
    struct ed_type_ls_arp *data = data_;
    struct hmapx_node *hmapx_node;
    struct ls_arp_record *ls_arp_record;

    HMAPX_FOR_EACH (hmapx_node, &nd_changes->trk_switches.crupdated) {
        const struct ovn_datapath *od = hmapx_node->data;

        ls_arp_record = ls_arp_record_lookup_by_od_(&data->table, od);

        if (!ls_arp_record) {
            /* Filtering ARP entries at logical switch works
             * when there are physical ports on the switch. */
            if (hmapx_is_empty(&od->phys_ports)) {
                /* NOTE: If the switch used to have physical ports but those
                 * were removed the lr_nat node has recomputed and triggers
                 * the ls_arp_lr_nat_handler() which cannot incrementally
                 * process changes.  This implicitly triggers correct
                 * handling of the removal.*/
                continue;
            }
            ls_arp_record = ls_arp_record_create(&data->table,
                                                 od, input_data.lr_nats);
        } else {
            nat_record_data_create(ls_arp_record, od, input_data.lr_nats);
        }

        hmapx_add(&data->trk_data.crupdated, ls_arp_record);
    }

    HMAPX_FOR_EACH (hmapx_node, &nd_changes->trk_switches.deleted) {
        const struct ovn_datapath *od = hmapx_node->data;

        ls_arp_record = ls_arp_record_lookup_by_od_(&data->table, od);
        if (ls_arp_record) {
            hmap_remove(&data->table.entries, &ls_arp_record->key_node);
            hmapx_add(&data->trk_data.deleted, ls_arp_record);
        }
    }

    if (ls_arp_has_tracked_data(&data->trk_data)) {
        return EN_HANDLED_UPDATED;
    }

    return EN_HANDLED_UNCHANGED;
}

static void
nat_odmap_create(struct lr_nat_record *lrnat_rec,
                 struct hmapx *odmap)
{
    for (size_t i = 0; i < lrnat_rec->n_nat_entries; i++) {
        const struct ovn_nat *nat_entry = &lrnat_rec->nat_entries[i];

        if (is_centralized_nat_record(nat_entry)) {
            hmapx_add(odmap, nat_entry->l3dgw_port->peer->od);
        }
    }
}

enum engine_input_handler_result
ls_arp_lr_nat_handler(struct engine_node *node, void *data_)
{
    struct ed_type_lr_nat_data *lr_nat_data =
        engine_get_input_data("lr_nat", node);
    struct ls_arp_input input_data = ls_arp_get_input_data(node);

    if (!lr_nat_has_tracked_data(&lr_nat_data->trk_data)) {
        return EN_UNHANDLED;
    }

    struct ed_type_ls_arp *data = data_;

    struct hmapx_node *hmapx_node;
    struct ls_arp_record *ls_arp_record;
    HMAPX_FOR_EACH (hmapx_node, &lr_nat_data->trk_data.crupdated) {
        struct lr_nat_record *nat_record_p = hmapx_node->data;

        struct hmapx ls_links_map = HMAPX_INITIALIZER(&ls_links_map);
        nat_odmap_create(nat_record_p, &ls_links_map);

        LS_ARP_TABLE_FOR_EACH (ls_arp_record, &data->table) {
            struct hmapx_node *nr_node =
                hmapx_find(&ls_arp_record->nat_records, nat_record_p);

            if (nr_node) {
                hmapx_add(&data->trk_data.crupdated, ls_arp_record);
                hmapx_delete(&ls_arp_record->nat_records, nr_node);
            }
        }

        struct hmapx_node *crupdated_ls_hmapx;
        HMAPX_FOR_EACH (crupdated_ls_hmapx, &ls_links_map) {
            struct ovn_datapath *crupdated_ls = crupdated_ls_hmapx->data;
            ls_arp_record =
                ls_arp_record_lookup_by_od_(&data->table, crupdated_ls);

            if (!ls_arp_record) {
                ls_arp_record = ls_arp_record_create(&data->table,
                                                     crupdated_ls,
                                                     input_data.lr_nats);
            }

            hmapx_add(&data->trk_data.crupdated, ls_arp_record);
            hmapx_add(&ls_arp_record->nat_records, nat_record_p);
        }
        hmapx_destroy(&ls_links_map);
    }

    HMAPX_FOR_EACH (hmapx_node, &lr_nat_data->trk_data.deleted) {
        struct lr_nat_record *nr_cur = hmapx_node->data;

        struct ls_arp_record *ar;
        LS_ARP_TABLE_FOR_EACH (ar, &data->table) {
            struct hmapx_node *nr_node = hmapx_find(&ar->nat_records, nr_cur);

            if (nr_node) {
                hmapx_add(&data->trk_data.crupdated, ar);
                hmapx_delete(&ar->nat_records, nr_node);
            }
        }
    }

    if (ls_arp_has_tracked_data(&data->trk_data)) {
        return EN_HANDLED_UPDATED;
    }

    return EN_HANDLED_UNCHANGED;
}
