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

#include "lib/rtnetlink.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"

#include "host-if-monitor.h"

VLOG_DEFINE_THIS_MODULE(host_if_monitor);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

struct host_if_monitor {
    struct nln_notifier *link_notifier;

    struct sset watched_interfaces;
    /* Maps interface names to struct host_if_monitor_link. */
    struct shash links;
    uint64_t last_link_generation;

    bool changes_detected;
};

static struct host_if_monitor monitor = (struct host_if_monitor) {
    .link_notifier = NULL,
    .watched_interfaces = SSET_INITIALIZER(&monitor.watched_interfaces),
    .links = SHASH_INITIALIZER(&monitor.links),
    .changes_detected = false,
};

static void if_notifier_cb(const struct rtnetlink_change *, void *aux);

void
host_if_monitor_wait(void)
{
    rtnetlink_wait();
}

bool
host_if_monitor_run(void)
{
    monitor.changes_detected = false;

    /* If any relevant interface if-index <-> if-name mapping changes are
     * dected, monitor.changes_detected will be updated accordingly by the
     * if_notifier_cb(). */
    rtnetlink_run();

    return monitor.changes_detected;
}

static void
host_if_monitor_set_link(const char *if_name, int32_t if_index)
{
    struct host_if_monitor_link *link = shash_find_data(&monitor.links,
                                                       if_name);
    if (!link) {
        link = xzalloc(sizeof *link);
        shash_add(&monitor.links, if_name, link);
    }
    if (link->if_index != if_index) {
        link->if_index = if_index;
        link->generation = ++monitor.last_link_generation;
    }
}

void
host_if_monitor_update_watches(const struct sset *if_names)
{
    struct sset new_if_names = SSET_INITIALIZER(&new_if_names);
    const char *if_name;

    /* The notifier only triggers the callback on interface updates.
     * For newly added ones we need to fetch the initial if_index ourselves.
     */
    SSET_FOR_EACH (if_name, if_names) {
        if (!sset_contains(&monitor.watched_interfaces, if_name)) {
            sset_add(&new_if_names, if_name);
        }
    }

    if (!sset_equals(&monitor.watched_interfaces, if_names)) {
        sset_destroy(&monitor.watched_interfaces);
        sset_clone(&monitor.watched_interfaces, if_names);

        /* Remove mappings for if_names that are not tracked anymore. */
        struct shash_node *node;
        SHASH_FOR_EACH_SAFE (node, &monitor.links) {
            if (!sset_contains(&monitor.watched_interfaces, node->name)) {
                free(node->data);
                shash_delete(&monitor.links, node);
            }
        }
    }

    if (!sset_is_empty(&monitor.watched_interfaces)) {
        if (!monitor.link_notifier) {
            VLOG_INFO_RL(&rl, "Enabling host interface monitor");
            monitor.link_notifier =
                rtnetlink_notifier_create(if_notifier_cb, &monitor);
        }
        /* Get initial state for new interfaces.
         *
         * NOTE: it's important that we have the initial state (if-index) for
         * newly watched interfaces because of two reasons:
         * - we need to be able to reconcile and preserve still valid learned
         *   remote FDB entries and remote VTEPs
         * - the if_notifier_cb is called only on updates of interfaces
         *   therefore if existing interfaces don't change the notifier
         *   callback is not called.
         */
        SSET_FOR_EACH (if_name, &new_if_names) {
            int32_t if_index = if_nametoindex(if_name);
            if (if_index) {
                host_if_monitor_set_link(if_name, if_index);
            }
        }
    } else {
        if (monitor.link_notifier) {
            VLOG_INFO_RL(&rl, "Disabling host interface monitor");
            rtnetlink_notifier_destroy(monitor.link_notifier);
            monitor.link_notifier = NULL;
        }
    }

    sset_destroy(&new_if_names);
}

struct host_if_monitor_link
host_if_monitor_get_link(const char *if_name)
{
    const struct host_if_monitor_link *link = shash_find_data(&monitor.links,
                                                             if_name);
    return link ? *link : (struct host_if_monitor_link) { 0 };
}

static void
if_notifier_cb(const struct rtnetlink_change *change, void *aux OVS_UNUSED)
{
    if (!change || change->irrelevant) {
        return;
    }

    if (change->nlmsg_type != RTM_NEWLINK
        && change->nlmsg_type != RTM_DELLINK) {
        return;
    }

    /* A rename event names the new link, which may not be watched.
     * Invalidate the old name by index so its generation cannot restore
     * observations to an interface that no longer matches the watch. */
    struct shash_node *node;
    SHASH_FOR_EACH_SAFE (node, &monitor.links) {
        const struct host_if_monitor_link *link = node->data;
        if (link->if_index == change->if_index
            && (change->nlmsg_type == RTM_DELLINK
                || strcmp(node->name, change->ifname))) {
            free(node->data);
            shash_delete(&monitor.links, node);
            monitor.changes_detected = true;
        }
    }

    if (change->nlmsg_type == RTM_NEWLINK && (change->ifi_flags & IFF_UP)
        && sset_contains(&monitor.watched_interfaces, change->ifname)) {
        host_if_monitor_set_link(change->ifname, change->if_index);
        monitor.changes_detected = true;
    }
}
