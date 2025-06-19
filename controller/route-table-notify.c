/*
 * Copyright (c) 2025, STACKIT GmbH & Co. KG
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

#include <net/if.h>
#include <linux/rtnetlink.h>

#include "netlink-notifier.h"
#include "openvswitch/vlog.h"

#include "binding.h"
#include "hash.h"
#include "hmapx.h"
#include "route-table.h"
#include "route.h"
#include "route-table-notify.h"
#include "route-exchange-netlink.h"

VLOG_DEFINE_THIS_MODULE(route_table_notify);

struct route_table_watch_request {
    struct hmap_node node;
    uint32_t table_id;
};

struct route_table_watch_entry {
    struct hmap_node node;
    uint32_t table_id;
};

static struct hmap watches = HMAP_INITIALIZER(&watches);
static bool any_route_table_changed;
static struct route_table_msg nln_rtmsg_change;

static struct nln *nl_route_handle;
static struct nln_notifier *nl_route_notifier_v4;
static struct nln_notifier *nl_route_notifier_v6;

static void route_table_change(const void *change_, void *aux);

static void
route_table_register_notifiers(void)
{
    VLOG_INFO("Adding route table watchers.");
    ovs_assert(!nl_route_handle);

    nl_route_handle = nln_create(NETLINK_ROUTE, route_table_parse,
                                 &nln_rtmsg_change);
    ovs_assert(nl_route_handle);

    nl_route_notifier_v4 =
        nln_notifier_create(nl_route_handle, RTNLGRP_IPV4_ROUTE,
                            route_table_change, NULL);
    if (!nl_route_notifier_v4) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Failed to create ipv4 route table watcher.");
    }

    nl_route_notifier_v6 =
        nln_notifier_create(nl_route_handle, RTNLGRP_IPV6_ROUTE,
                            route_table_change, NULL);
    if (!nl_route_notifier_v6) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Failed to create ipv6 route table watcher.");
    }
}

static void
route_table_deregister_notifiers(void)
{
    VLOG_INFO("Removing route table watchers.");
    ovs_assert(nl_route_handle);

    nln_notifier_destroy(nl_route_notifier_v4);
    nln_notifier_destroy(nl_route_notifier_v6);
    nln_destroy(nl_route_handle);
    nl_route_notifier_v4 = NULL;
    nl_route_notifier_v6 = NULL;
    nl_route_handle = NULL;
}

static uint32_t
route_table_notify_hash_watch(uint32_t table_id)
{
    return hash_add(0, table_id);
}

void
route_table_add_watch_request(struct hmap *route_table_watches,
                              uint32_t table_id)
{
    struct route_table_watch_request *wr = xzalloc(sizeof *wr);
    wr->table_id = table_id;
    hmap_insert(route_table_watches, &wr->node,
                route_table_notify_hash_watch(wr->table_id));
}

void
route_table_watch_request_cleanup(struct hmap *route_table_watches)
{
    struct route_table_watch_request *wr;
    HMAP_FOR_EACH_POP (wr, node, route_table_watches) {
        free(wr);
    }
}

static struct route_table_watch_entry *
find_watch_entry(uint32_t table_id)
{
    struct route_table_watch_entry *we;
    uint32_t hash = route_table_notify_hash_watch(table_id);
    HMAP_FOR_EACH_WITH_HASH (we, node, hash, &watches) {
        if (table_id == we->table_id) {
            return we;
        }
    }
    return NULL;
}

static void
route_table_change(const void *change_, void *aux OVS_UNUSED)
{
    /* We currently track whether at least one recent route table change
     * was detected.  If that's the case already there's no need to
     * continue. */
    if (any_route_table_changed) {
        return;
    }

    const struct route_table_msg *change = change_;
    if (change && change->rd.rtm_protocol != RTPROT_OVN) {
        if (find_watch_entry(change->rd.rta_table_id)) {
            any_route_table_changed = true;
        }
    }
}

static void
add_watch_entry(uint32_t table_id)
{
   VLOG_INFO("Registering new route table watcher for table %d.",
             table_id);

    struct route_table_watch_entry *we;
    uint32_t hash = route_table_notify_hash_watch(table_id);
    we = xzalloc(sizeof *we);
    we->table_id = table_id;
    hmap_insert(&watches, &we->node, hash);

    if (!nl_route_handle) {
        route_table_register_notifiers();
    }
}

static void
remove_watch_entry(struct route_table_watch_entry *we)
{
    VLOG_INFO("Removing route table watcher for table %d.", we->table_id);
    hmap_remove(&watches, &we->node);
    free(we);

    if (hmap_is_empty(&watches)) {
        route_table_deregister_notifiers();
    }
}

bool
route_table_notify_run(void)
{
    any_route_table_changed = false;

    if (nl_route_handle) {
        nln_run(nl_route_handle);
    }

    return any_route_table_changed;
}

void
route_table_notify_wait(void)
{
    if (nl_route_handle) {
        nln_wait(nl_route_handle);
    }
}

void
route_table_notify_update_watches(const struct hmap *route_table_watches)
{
    struct hmapx sync_watches = HMAPX_INITIALIZER(&sync_watches);
    struct route_table_watch_entry *we;
    HMAP_FOR_EACH (we, node, &watches) {
        hmapx_add(&sync_watches, we);
    }

    struct route_table_watch_request *wr;
    HMAP_FOR_EACH (wr, node, route_table_watches) {
        we = find_watch_entry(wr->table_id);
        if (we) {
            hmapx_find_and_delete(&sync_watches, we);
        } else {
            add_watch_entry(wr->table_id);
        }
    }

    struct hmapx_node *node;
    HMAPX_FOR_EACH (node, &sync_watches) {
        remove_watch_entry(node->data);
    }

    hmapx_destroy(&sync_watches);
}

void
route_table_notify_destroy(void)
{
    struct route_table_watch_entry *we;
    HMAP_FOR_EACH_SAFE (we, node, &watches) {
        remove_watch_entry(we);
    }
}
