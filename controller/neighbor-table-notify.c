/* Copyright (c) 2025, Red Hat, Inc.
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

#include <linux/rtnetlink.h>
#include <net/if.h>

#include "hash.h"
#include "hmapx.h"
#include "lib/util.h"
#include "netlink-notifier.h"
#include "openvswitch/vlog.h"

#include "neighbor-exchange-netlink.h"
#include "neighbor-table-notify.h"

VLOG_DEFINE_THIS_MODULE(neighbor_table_notify);

struct neighbor_table_watch_request {
    struct hmap_node node;
    int32_t if_index;
    char if_name[IFNAMSIZ + 1];
};

struct neighbor_table_watch_entry {
    struct hmap_node node;
    int32_t if_index;
    char if_name[IFNAMSIZ + 1];
};

static struct hmap watches = HMAP_INITIALIZER(&watches);
static bool any_neighbor_table_changed;
static struct ne_table_msg nln_nmsg_change;

static struct nln *nl_neighbor_handle;
static struct nln_notifier *nl_neighbor_notifier;

static void neighbor_table_change(const void *change_, void *aux);

static void
neighbor_table_register_notifiers(void)
{
    VLOG_INFO("Adding neighbor table watchers.");
    ovs_assert(!nl_neighbor_handle);

    nl_neighbor_handle = nln_create(NETLINK_ROUTE, ne_table_parse,
                                    &nln_nmsg_change);
    ovs_assert(nl_neighbor_handle);

    nl_neighbor_notifier =
        nln_notifier_create(nl_neighbor_handle, RTNLGRP_NEIGH,
                            neighbor_table_change, NULL);
    if (!nl_neighbor_notifier) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Failed to create neighbor table watcher.");
    }
}

static void
neighbor_table_deregister_notifiers(void)
{
    VLOG_INFO("Removing neighbor table watchers.");
    ovs_assert(nl_neighbor_handle);

    nln_notifier_destroy(nl_neighbor_notifier);
    nln_destroy(nl_neighbor_handle);
    nl_neighbor_notifier = NULL;
    nl_neighbor_handle = NULL;
}

static uint32_t
neighbor_table_notify_hash_watch(int32_t if_index)
{
    /* To allow lookups triggered by netlink messages, don't include the
     * if_name in the hash.  The netlink updates only include if_index. */
    return hash_int(if_index, 0);
}

static void
add_watch_entry(int32_t if_index, const char *if_name)
{
   VLOG_DBG("Registering new neighbor table watcher "
            "for interface %s (%"PRId32").",
            if_name, if_index);

    struct neighbor_table_watch_entry *we;
    uint32_t hash = neighbor_table_notify_hash_watch(if_index);
    we = xzalloc(sizeof *we);
    we->if_index = if_index;
    ovs_strzcpy(we->if_name, if_name, sizeof we->if_name);
    hmap_insert(&watches, &we->node, hash);

    if (!nl_neighbor_handle) {
        neighbor_table_register_notifiers();
    }
}

static void
remove_watch_entry(struct neighbor_table_watch_entry *we)
{
    VLOG_DBG("Removing neighbor table watcher for interface %s (%"PRId32").",
             we->if_name, we->if_index);
    hmap_remove(&watches, &we->node);
    free(we);

    if (hmap_is_empty(&watches)) {
        neighbor_table_deregister_notifiers();
    }
}

bool
neighbor_table_notify_run(void)
{
    any_neighbor_table_changed = false;

    if (nl_neighbor_handle) {
        nln_run(nl_neighbor_handle);
    }

    return any_neighbor_table_changed;
}

void
neighbor_table_notify_wait(void)
{
    if (nl_neighbor_handle) {
        nln_wait(nl_neighbor_handle);
    }
}

void
neighbor_table_add_watch_request(struct hmap *neighbor_table_watches,
                                 int32_t if_index, const char *if_name)
{
    struct neighbor_table_watch_request *wr = xzalloc(sizeof *wr);

    wr->if_index = if_index;
    ovs_strzcpy(wr->if_name, if_name, sizeof wr->if_name);
    hmap_insert(neighbor_table_watches, &wr->node,
                neighbor_table_notify_hash_watch(wr->if_index));
}

void
neighbor_table_watch_request_cleanup(struct hmap *neighbor_table_watches)
{
    struct neighbor_table_watch_request *wr;
    HMAP_FOR_EACH_POP (wr, node, neighbor_table_watches) {
        free(wr);
    }
}

static struct neighbor_table_watch_entry *
find_watch_entry(int32_t if_index, const char *if_name)
{
    struct neighbor_table_watch_entry *we;
    uint32_t hash = neighbor_table_notify_hash_watch(if_index);
    HMAP_FOR_EACH_WITH_HASH (we, node, hash, &watches) {
        if (if_index == we->if_index && !strcmp(if_name, we->if_name)) {
            return we;
        }
    }
    return NULL;
}

static struct neighbor_table_watch_entry *
find_watch_entry_by_if_index(int32_t if_index)
{
    struct neighbor_table_watch_entry *we;
    uint32_t hash = neighbor_table_notify_hash_watch(if_index);
    HMAP_FOR_EACH_WITH_HASH (we, node, hash, &watches) {
        if (if_index == we->if_index) {
            return we;
        }
    }
    return NULL;
}

void
neighbor_table_notify_update_watches(const struct hmap *neighbor_table_watches)
{
    struct hmapx sync_watches = HMAPX_INITIALIZER(&sync_watches);
    struct neighbor_table_watch_entry *we;
    HMAP_FOR_EACH (we, node, &watches) {
        hmapx_add(&sync_watches, we);
    }

    struct neighbor_table_watch_request *wr;
    HMAP_FOR_EACH (wr, node, neighbor_table_watches) {
        we = find_watch_entry(wr->if_index, wr->if_name);
        if (we) {
            hmapx_find_and_delete(&sync_watches, we);
        } else {
            add_watch_entry(wr->if_index, wr->if_name);
        }
    }

    struct hmapx_node *node;
    HMAPX_FOR_EACH (node, &sync_watches) {
        remove_watch_entry(node->data);
    }

    hmapx_destroy(&sync_watches);
}

void
neighbor_table_notify_destroy(void)
{
    struct neighbor_table_watch_entry *we;
    HMAP_FOR_EACH_SAFE (we, node, &watches) {
        remove_watch_entry(we);
    }
}

static void
neighbor_table_change(const void *change_, void *aux OVS_UNUSED)
{
    /* We currently track whether at least one recent neighbor table change
     * was detected.  If that's the case already there's no need to
     * continue. */
    if (any_neighbor_table_changed) {
        return;
    }

    const struct ne_table_msg *change = change_;

    if (change && !ne_is_ovn_owned(&change->nd)) {
        if (find_watch_entry_by_if_index(change->nd.if_index)) {
            any_neighbor_table_changed = true;
        }
    }
}
