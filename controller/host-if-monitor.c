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
#include "lib/simap.h"
#include "openvswitch/vlog.h"

#include "host-if-monitor.h"

VLOG_DEFINE_THIS_MODULE(host_if_monitor);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

struct host_if_monitor {
    struct nln_notifier *link_notifier;

    struct sset watched_interfaces;
    struct simap ifname_to_ifindex;

    bool changes_detected;
};

static struct host_if_monitor monitor = (struct host_if_monitor) {
    .link_notifier = NULL,
    .watched_interfaces = SSET_INITIALIZER(&monitor.watched_interfaces),
    .ifname_to_ifindex = SIMAP_INITIALIZER(&monitor.ifname_to_ifindex),
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
        struct simap_node *sn;
        SIMAP_FOR_EACH_SAFE (sn, &monitor.ifname_to_ifindex) {
            if (!sset_contains(&monitor.watched_interfaces, sn->name)) {
                simap_delete(&monitor.ifname_to_ifindex, sn);
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
            simap_put(&monitor.ifname_to_ifindex, if_name,
                      if_nametoindex(if_name));
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

int32_t
host_if_monitor_ifname_toindex(const char *if_name)
{
    return simap_get(&monitor.ifname_to_ifindex, if_name);
}

static void
if_notifier_cb(const struct rtnetlink_change *change, void *aux OVS_UNUSED)
{
    if (!change || change->irrelevant) {
        return;
    }

    switch (change->nlmsg_type) {
    case RTM_NEWLINK:
        if ((change->ifi_flags & IFF_UP)
            && sset_find(&monitor.watched_interfaces, change->ifname)) {
            simap_put(&monitor.ifname_to_ifindex,
                      change->ifname, change->if_index);
            monitor.changes_detected = true;
        }
        break;
    case RTM_DELLINK:
        if (sset_find(&monitor.watched_interfaces, change->ifname)) {
            simap_find_and_delete(&monitor.ifname_to_ifindex, change->ifname);
            monitor.changes_detected = true;
        }
        break;
    default:
        break;
    }
}
