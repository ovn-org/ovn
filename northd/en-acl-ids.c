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

#include "en-acl-ids.h"
#include "lib/uuidset.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-nb-idl.h"
#include "lib/bitmap.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(northd_acl_ids);

#define MAX_ACL_ID 65535

void *
en_acl_id_init(struct engine_node *node OVS_UNUSED,
               struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

static bool
should_sync_to_sb(const struct nbrec_acl *nb_acl)
{
    return !strcmp(nb_acl->action, "allow-related") &&
           smap_get_bool(&nb_acl->options,
                         "persist-established",
                         false);
}

void
en_acl_id_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    const struct nbrec_acl_table *nb_acl_table =
        EN_OVSDB_GET(engine_get_input("NB_acl", node));
    const struct sbrec_acl_id_table *sb_acl_id_table =
        EN_OVSDB_GET(engine_get_input("SB_acl_id", node));
    struct uuidset visited = UUIDSET_INITIALIZER(&visited);
    unsigned long *id_bitmap = bitmap_allocate(MAX_ACL_ID);

    const struct nbrec_acl *nb_acl;
    const struct sbrec_acl_id *sb_id;
    SBREC_ACL_ID_TABLE_FOR_EACH_SAFE (sb_id, sb_acl_id_table) {
        nb_acl = nbrec_acl_table_get_for_uuid(nb_acl_table,
                                              &sb_id->header_.uuid);
        if (nb_acl && should_sync_to_sb(nb_acl)) {
            bitmap_set1(id_bitmap, sb_id->id);
            uuidset_insert(&visited, &sb_id->header_.uuid);
        } else {
            sbrec_acl_id_delete(sb_id);
        }
    }

    size_t scan_start = 1;
    size_t scan_end = MAX_ACL_ID;
    NBREC_ACL_TABLE_FOR_EACH (nb_acl, nb_acl_table) {
        if (uuidset_find_and_delete(&visited, &nb_acl->header_.uuid)) {
            continue;
        }
        if (!should_sync_to_sb(nb_acl)) {
            continue;
        }
        int64_t new_id = bitmap_scan(id_bitmap, 0,
                                     scan_start, scan_end + 1);
        if (new_id == scan_end + 1) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Exhausted all ACL IDs");
            break;
        }
        sb_id = sbrec_acl_id_insert_persist_uuid(eng_ctx->ovnsb_idl_txn,
                                                 &nb_acl->header_.uuid);
        sbrec_acl_id_set_id(sb_id, new_id);
        bitmap_set1(id_bitmap, new_id);
        scan_start = new_id + 1;
    }

    engine_set_node_state(node, EN_UPDATED);
    uuidset_destroy(&visited);
    bitmap_free(id_bitmap);
}

void
en_acl_id_cleanup(void *data OVS_UNUSED)
{
}
