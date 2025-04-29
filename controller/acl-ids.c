/* Copyright (c) 2024, Red Hat, Inc.
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

#include "openvswitch/hmap.h"
#include "openvswitch/rconn.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-ct.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/vlog.h"

#include "lib/ovn-sb-idl.h"
#include "ovn/features.h"
#include "acl-ids.h"

VLOG_DEFINE_THIS_MODULE(acl_ids);

enum acl_id_state {
    /* The ID exists in the SB DB. */
    ACTIVE,
    /* The ID has been removed from the DB and needs to have its conntrack
     * entries flushed.
     */
    SB_DELETED,
    /* We have sent the conntrack flush request to OVS for this ACL ID. */
    FLUSHING,
};

struct acl_id {
    int64_t id;
    struct uuid uuid;
    enum acl_id_state state;
    struct hmap_node hmap_node;
    ovs_be32 xid;
    ovs_be32 barrier_xid;
    int flush_count;
};

struct tracked_acl_ids {
    struct hmap ids;
};

static struct acl_id *
find_tracked_acl_id(struct tracked_acl_ids *tracked_ids,
                    const struct sbrec_acl_id *sb_id)
{
    uint32_t hash = hash_2words(uuid_hash(&sb_id->header_.uuid),
                                hash_uint64(sb_id->id));
    struct acl_id *acl_id;
    HMAP_FOR_EACH_WITH_HASH (acl_id, hmap_node, hash, &tracked_ids->ids) {
        if (acl_id->id == sb_id->id &&
            uuid_equals(&sb_id->header_.uuid, &acl_id->uuid)) {
            return acl_id;
        }
    }
    return NULL;
}

static void
acl_id_destroy(struct acl_id *acl_id)
{
    free(acl_id);
}

void *
en_acl_id_init(struct engine_node *node OVS_UNUSED,
               struct engine_arg *arg OVS_UNUSED)
{
    struct tracked_acl_ids *ids = xzalloc(sizeof *ids);
    hmap_init(&ids->ids);
    return ids;
}

enum engine_node_state
en_acl_id_run(struct engine_node *node, void *data)
{
    if (!ovs_feature_is_supported(OVS_CT_LABEL_FLUSH_SUPPORT)) {
        return EN_UNCHANGED;
    }

    const struct sbrec_acl_id_table *sb_acl_id_table =
        EN_OVSDB_GET(engine_get_input("SB_acl_id", node));
    const struct sbrec_acl_id *sb_id;

    struct tracked_acl_ids *ids = data;
    struct acl_id *id;

    /* Pre-mark each active ID as SB_DELETED. */
    HMAP_FOR_EACH (id, hmap_node, &ids->ids) {
        if (id->state == ACTIVE) {
            id->state = SB_DELETED;
        }
    }

    SBREC_ACL_ID_TABLE_FOR_EACH (sb_id, sb_acl_id_table) {
        id = find_tracked_acl_id(ids, sb_id);
        if (!id) {
            id = xzalloc(sizeof *id);
            id->id = sb_id->id;
            id->uuid = sb_id->header_.uuid;

            uint32_t hash = hash_2words(uuid_hash(&sb_id->header_.uuid),
                                        hash_uint64(sb_id->id));
            hmap_insert(&ids->ids, &id->hmap_node, hash);
        }
        id->state = ACTIVE;
    }

    return EN_UPDATED;
}

void
en_acl_id_cleanup(void *data)
{
    struct tracked_acl_ids *tracked_ids = data;
    struct acl_id *id;
    HMAP_FOR_EACH_POP (id, hmap_node, &tracked_ids->ids) {
        acl_id_destroy(id);
    }
    hmap_destroy(&tracked_ids->ids);
}

bool
en_acl_id_is_valid(struct engine_node *node OVS_UNUSED)
{
    return true;
}

void
acl_ids_handle_barrier_reply(struct tracked_acl_ids *tracked_acl_ids,
                             ovs_be32 barrier_xid)
{
    /* Since ofctrl_run() runs before engine_run(), there is a chance that
     * tracked_acl_ids may be NULL.
     */
    if (!tracked_acl_ids) {
        return;
    }
    struct acl_id *acl_id;
    HMAP_FOR_EACH_SAFE (acl_id, hmap_node, &tracked_acl_ids->ids) {
        if (acl_id->state != FLUSHING || acl_id->barrier_xid != barrier_xid) {
            continue;
        }
        hmap_remove(&tracked_acl_ids->ids, &acl_id->hmap_node);
        acl_id_destroy(acl_id);
    }
}

#define MAX_FLUSHES 3

bool
acl_ids_handle_non_barrier_reply(const struct ofp_header *oh,
                                 enum ofptype type,
                                 struct tracked_acl_ids *tracked_acl_ids)
{
    /* Since ofctrl_run() runs before engine_run(), there is a chance that
     * tracked_acl_ids may be NULL.
     */
    if (!tracked_acl_ids) {
        return false;
    }

    if (type != OFPTYPE_ERROR) {
        return false;
    }

    struct acl_id *acl_id;
    bool handled = false;
    HMAP_FOR_EACH_SAFE (acl_id, hmap_node, &tracked_acl_ids->ids) {
        if (acl_id->xid != oh->xid) {
            continue;
        }
        handled = true;

        /* Uh oh! It looks like one of the flushes failed :(
         * Let's find this particular one and move its state
         * back to SB_DELETED so we can retry the flush. Of
         * course, if this is a naughty little ID and has
         * been flushed unsuccessfully too many times, we'll
         * delete it since we are unlikely to be able to
         * successfully flush it.
         */
        acl_id->xid = 0;
        acl_id->barrier_xid = 0;
        acl_id->flush_count++;
        if (acl_id->flush_count >= MAX_FLUSHES) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Failed to flush conntrack entry for ACL id "
                         "%"PRId64".", acl_id->id);
            hmap_remove(&tracked_acl_ids->ids, &acl_id->hmap_node);
            acl_id_destroy(acl_id);
        } else {
            acl_id->state = SB_DELETED;
        }
        break;
    }

    return handled;
}

void
acl_ids_flush_expired(struct tracked_acl_ids *acl_ids, int rconn_version,
                      struct ovs_list *msgs)
{
    ovs_u128 mask = {
        /* ct_labels.label BITS[80-95] */
        .u64.hi = 0xffff0000,
    };
    struct acl_id *acl_id;
    HMAP_FOR_EACH (acl_id, hmap_node, &acl_ids->ids) {
        if (acl_id->state != SB_DELETED) {
            continue;
        }
        ovs_u128 ct_id = {
            .u64.hi = acl_id->id << 16,
        };
        VLOG_DBG("Flushing conntrack entry for ACL id %"PRId64".", acl_id->id);
        struct ofp_ct_match match = {
            .labels = ct_id,
            .labels_mask = mask,
        };
        struct ofpbuf *msg = ofp_ct_match_encode(&match, NULL,
                                                 rconn_version);
        const struct ofp_header *oh = msg->data;
        acl_id->xid = oh->xid;
        acl_id->state = FLUSHING;
        ovs_list_push_back(msgs, &msg->list_node);
    }
}

void
acl_ids_record_barrier_xid(struct tracked_acl_ids *acl_ids,
                           ovs_be32 barrier_xid)
{
    struct acl_id *acl_id;
    HMAP_FOR_EACH (acl_id, hmap_node, &acl_ids->ids) {
        if (acl_id->state == FLUSHING && !acl_id->barrier_xid) {
            acl_id->barrier_xid = barrier_xid;
        }
    }
}
