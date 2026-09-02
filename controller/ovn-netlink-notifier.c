/* Copyright (c) 2026, Red Hat, Inc.
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

#include "neighbor-exchange-netlink.h"
#include "nexthop-exchange.h"
#include "netlink-notifier.h"
#include "route-exchange-netlink.h"
#include "route-table.h"
#include "vec.h"

#include "openvswitch/vlog.h"

#include "ovn-netlink-notifier.h"

VLOG_DEFINE_THIS_MODULE(ovn_netlink_notifier);

#define NOTIFIER_MSGS_CAPACITY_THRESHOLD 1024

struct ovn_netlink_notifier {
    /* Group for which we want to receive the notification. */
    int group;
    /* The notifier pointers. */
    struct nln_notifier *nln_notifier;
    /* Messages received by given notifier. */
    struct vector msgs;
    /* Set when the kernel reported a change we could not read, in which case
     * 'msgs' does not describe everything that happened and the state derived
     * from it has to be built again from scratch. */
    bool lost;
    /* Notifier change handler. */
    nln_notify_func *change_handler;
    /* Name of the notifier. */
    const char *name;
};

union ovn_notifier_msg_change {
    struct route_table_msg route;
    struct ne_table_msg neighbor;
    struct nh_table_msg nexthop;
};

static void ovn_netlink_route_change_handler(const void *change_, void *aux);
static void ovn_netlink_neighbor_change_handler(const void *change_,
                                                void *aux);
static void ovn_netlink_nexthop_change_handler(const void *change_,
                                               void *aux);
static void ovn_netlink_notifier_report_lost(struct ovn_netlink_notifier *);

static struct ovn_netlink_notifier notifiers[OVN_NL_NOTIFIER_MAX] = {
    [OVN_NL_NOTIFIER_ROUTE_V4] = {
        .group = RTNLGRP_IPV4_ROUTE,
        .msgs = VECTOR_EMPTY_INITIALIZER(struct ovn_route_msg *),
        .change_handler = ovn_netlink_route_change_handler,
        .name = "route-ipv4",
    },
    [OVN_NL_NOTIFIER_ROUTE_V6] = {
        .group = RTNLGRP_IPV6_ROUTE,
        .msgs = VECTOR_EMPTY_INITIALIZER(struct ovn_route_msg *),
        .change_handler = ovn_netlink_route_change_handler,
        .name = "route-ipv6",
    },
    [OVN_NL_NOTIFIER_NEIGHBOR] = {
        .group = RTNLGRP_NEIGH,
        .msgs = VECTOR_EMPTY_INITIALIZER(struct ne_table_msg),
        .change_handler = ovn_netlink_neighbor_change_handler,
        .name = "neighbor",
    },
    [OVN_NL_NOTIFIER_NEXTHOP] = {
        .group = RTNLGRP_NEXTHOP,
        .msgs = VECTOR_EMPTY_INITIALIZER(struct nh_table_msg),
        .change_handler = ovn_netlink_nexthop_change_handler,
        .name = "nexthop",
    },
};

static struct nln *nln_handle;
static union ovn_notifier_msg_change nln_msg_change;

static int
ovn_netlink_notifier_parse(struct ofpbuf *buf, void *change_)
{
    struct nlmsghdr *nlmsg = ofpbuf_at(buf, 0, NLMSG_HDRLEN);
    if (!nlmsg) {
        return 0;
    }

    union ovn_notifier_msg_change *change = change_;
    if (nlmsg->nlmsg_type == RTM_NEWROUTE ||
        nlmsg->nlmsg_type == RTM_DELROUTE) {
        return route_table_parse(buf, &change->route);
    }

    if (nlmsg->nlmsg_type == RTM_NEWNEIGH ||
        nlmsg->nlmsg_type == RTM_DELNEIGH) {
        return ne_table_parse(buf, &change->neighbor);
    }

    if (nlmsg->nlmsg_type == RTM_NEWNEXTHOP ||
        nlmsg->nlmsg_type == RTM_DELNEXTHOP) {
        return nh_table_parse(buf, &change->nexthop);
    }

    return 0;
}

/* Records that the kernel told us that something changed without us being
 * able to tell what, which happens when the receive buffer overflows or when
 * a message cannot be parsed.  It is reported for every group, since the
 * notifiers share a single socket. */
static void
ovn_netlink_notifier_report_lost(struct ovn_netlink_notifier *notifier)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

    VLOG_INFO_RL(&rl, "Missed %s table notifications, resyncing.",
                 notifier->name);
    notifier->lost = true;
}

static void
ovn_netlink_route_change_handler(const void *change_, void *aux)
{
    struct ovn_netlink_notifier *notifier = aux;

    if (!change_) {
        ovn_netlink_notifier_report_lost(notifier);
        return;
    }

    union ovn_notifier_msg_change *change =
        CONST_CAST(union ovn_notifier_msg_change *, change_);

    struct route_data *rd = &change->route.rd;
    if (rd->rtm_protocol != RTPROT_OVN) {
        struct ovn_route_msg *msg =
            ovn_route_msg_from_route_data(change->route.nlmsg_type, rd);
        vector_push(&notifier->msgs, &msg);
    }

    route_data_destroy(rd);
}

static void
ovn_netlink_neighbor_change_handler(const void *change_, void *aux)
{
    struct ovn_netlink_notifier *notifier = aux;

    if (!change_) {
        ovn_netlink_notifier_report_lost(notifier);
        return;
    }

    const union ovn_notifier_msg_change *change = change_;

    if (!ne_is_ovn_owned(&change->neighbor.nd)) {
        vector_push(&notifier->msgs, &change->neighbor);
    }
}

static void
ovn_netlink_nexthop_change_handler(const void *change_, void *aux)
{
    struct ovn_netlink_notifier *notifier = aux;

    if (!change_) {
        ovn_netlink_notifier_report_lost(notifier);
        return;
    }

    const union ovn_notifier_msg_change *change = change_;
    vector_push(&notifier->msgs, &change->nexthop);
}

static void
ovn_netlink_register_notifier(enum ovn_netlink_notifier_type type)
{
    ovs_assert(type < OVN_NL_NOTIFIER_MAX);

    struct ovn_netlink_notifier *notifier = &notifiers[type];
    if (notifier->nln_notifier) {
        return;
    }

    VLOG_INFO("Adding %s table watchers.", notifier->name);
    if (!nln_handle) {
        nln_handle = nln_create(NETLINK_ROUTE, ovn_netlink_notifier_parse,
                                &nln_msg_change);
        ovs_assert(nln_handle);
    }

    notifier->nln_notifier = nln_notifier_create(nln_handle, notifier->group,
                                                 notifier->change_handler,
                                                 notifier);

    if (!notifier->nln_notifier) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Failed to create %s table watcher.",
                     notifier->name);
    }
}

static void
ovn_netlink_deregister_notifier(enum ovn_netlink_notifier_type type)
{
    ovs_assert(type < OVN_NL_NOTIFIER_MAX);

    struct ovn_netlink_notifier *notifier = &notifiers[type];
    if (!notifier->nln_notifier) {
        return;
    }

    VLOG_INFO("Removing %s table watchers.", notifier->name);
    nln_notifier_destroy(notifier->nln_notifier);
    notifier->nln_notifier = NULL;

    size_t i;
    for (i = 0; i < OVN_NL_NOTIFIER_MAX; i++) {
        if (notifiers[i].nln_notifier) {
            break;
        }
    }

    if (i == OVN_NL_NOTIFIER_MAX) {
        /* This was the last notifier, destroy the handle too. */
        nln_destroy(nln_handle);
        nln_handle = NULL;
    }

    ovn_netlink_notifier_flush(type);
}

void
ovn_netlink_update_notifier(enum ovn_netlink_notifier_type type, bool enabled)
{
    if (enabled) {
        ovn_netlink_register_notifier(type);
    } else {
        ovn_netlink_deregister_notifier(type);
    }
}

struct vector *
ovn_netlink_get_msgs(enum ovn_netlink_notifier_type type)
{
    ovs_assert(type < OVN_NL_NOTIFIER_MAX);
    return &notifiers[type].msgs;
}

/* Returns true if notifications were missed since the last flush, in which
 * case the messages of 'type' do not describe every change and the caller has
 * to read the table it tracks again. */
bool
ovn_netlink_notifier_lost(enum ovn_netlink_notifier_type type)
{
    ovs_assert(type < OVN_NL_NOTIFIER_MAX);
    return notifiers[type].lost;
}

void
ovn_netlink_notifier_flush(enum ovn_netlink_notifier_type type)
{
    ovs_assert(type < OVN_NL_NOTIFIER_MAX);
    struct ovn_netlink_notifier *notifier = &notifiers[type];

    switch (type) {
    case OVN_NL_NOTIFIER_NEXTHOP: {
        struct nh_table_msg *msg;
        VECTOR_FOR_EACH_PTR (&notifier->msgs, msg) {
            free(msg->nhe);
        }
        break;
    }
    case OVN_NL_NOTIFIER_ROUTE_V4:
    case OVN_NL_NOTIFIER_ROUTE_V6: {
        struct ovn_route_msg *msg;
        VECTOR_FOR_EACH (&notifier->msgs, msg) {
            free(msg);
        }
        break;
    }
    case OVN_NL_NOTIFIER_NEIGHBOR:
    case OVN_NL_NOTIFIER_MAX:
        break;
    }

    vector_clear(&notifier->msgs);
    notifier->lost = false;
}

void
ovn_netlink_notifiers_run(void)
{
    for (size_t i = 0; i < OVN_NL_NOTIFIER_MAX; i++) {
        if (vector_capacity(&notifiers[i].msgs) >
            NOTIFIER_MSGS_CAPACITY_THRESHOLD) {
            vector_shrink_to_fit(&notifiers[i].msgs);
        }
    }

    if (nln_handle) {
        nln_run(nln_handle);
    }
}

void
ovn_netlink_notifiers_wait(void)
{
    if (nln_handle) {
        nln_wait(nln_handle);
    }
}

void
ovn_netlink_notifiers_destroy(void)
{
    for (size_t i = 0; i < OVN_NL_NOTIFIER_MAX; i++) {
        ovn_netlink_deregister_notifier(i);
        vector_destroy(&notifiers[i].msgs);
    }
}
