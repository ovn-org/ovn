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
#include <errno.h>
#include <linux/rtnetlink.h>

#include "netlink.h"
#include "netlink-socket.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/hmap.h"
#include "route-table.h"
#include "packets.h"
#include "tests/ovstest.h"
#include "tests/test-utils.h"

#include "controller/host-if-monitor.h"
#include "controller/neighbor-exchange-netlink.h"
#include "controller/neighbor-exchange.h"
#include "controller/nexthop-exchange.h"
#include "controller/ovn-netlink-notifier.h"
#include "controller/neighbor.h"
#include "controller/route.h"
#include "controller/route-exchange-netlink.h"

/* Script the dump transport and neighbor transactions.  The normal
 * ovstest commands delegate to the real Netlink functions.  Production
 * binaries do not use these linker wrappers. */
static struct {
    bool active;
    bool started;
    bool current;
    int32_t if_index;
    bool finished;
    struct ofpbuf messages[4];
    uint16_t request_type;
    uint16_t done_flags;
    size_t n_messages;
    size_t next;
    int error;
    int transact_error;
    unsigned int adds;
    unsigned int deletes;
} nl_script;

static _Thread_local long long int poll_wakeup_at;

void __real_poll_timer_wait_until_at(long long int, const char *);
void __wrap_poll_timer_wait_until_at(long long int, const char *);

void
__wrap_poll_timer_wait_until_at(long long int when, const char *where)
{
    poll_wakeup_at = when;
    __real_poll_timer_wait_until_at(when, where);
}

void __real_nl_dump_start(struct nl_dump *, int, const struct ofpbuf *);
bool __real_nl_dump_next(struct nl_dump *, struct ofpbuf *, struct ofpbuf *);
int __real_nl_dump_done(struct nl_dump *);
int __real_nl_transact(int, const struct ofpbuf *, struct ofpbuf **);
void __wrap_nl_dump_start(struct nl_dump *, int, const struct ofpbuf *);
bool __wrap_nl_dump_next(struct nl_dump *, struct ofpbuf *, struct ofpbuf *);
int __wrap_nl_dump_done(struct nl_dump *);
int __wrap_nl_transact(int, const struct ofpbuf *, struct ofpbuf **);

void
__wrap_nl_dump_start(struct nl_dump *dump, int protocol,
                     const struct ofpbuf *request)
{
    nl_script.current = nl_script.active;
    if (nl_script.current && nl_script.if_index) {
        const struct nlattr *attr = nl_attr_find(
            request, NLMSG_HDRLEN + sizeof(struct ndmsg), NDA_IFINDEX);
        nl_script.current = attr && (nl_attr_get_u32(attr)
                                     == (uint32_t) nl_script.if_index);
    }
    if (!nl_script.current) {
        __real_nl_dump_start(dump, protocol, request);
        return;
    }
    ovs_assert(protocol == NETLINK_ROUTE);
    uint16_t type = nl_script.request_type ? nl_script.request_type
                                           : RTM_GETNEIGH;
    ovs_assert(nl_msg_nlmsghdr(request)->nlmsg_type == type);
    dump->nl_flags = 0;
    nl_script.next = 0;
    nl_script.finished = false;
    nl_script.started = true;
}

bool
__wrap_nl_dump_next(struct nl_dump *dump, struct ofpbuf *reply,
                    struct ofpbuf *buf)
{
    if (!nl_script.current) {
        return __real_nl_dump_next(dump, reply, buf);
    }
    ovs_assert(nl_script.started && !nl_script.finished);
    if (nl_script.next == nl_script.n_messages) {
        return false;
    }
    *reply = nl_script.messages[nl_script.next++];
    return true;
}

int
__wrap_nl_dump_done(struct nl_dump *dump)
{
    if (!nl_script.current) {
        return __real_nl_dump_done(dump);
    }
    ovs_assert(nl_script.started && !nl_script.finished);
    nl_script.finished = true;
    dump->nl_flags = nl_script.done_flags;
    return nl_script.error;
}

int
__wrap_nl_transact(int protocol, const struct ofpbuf *request,
                   struct ofpbuf **reply)
{
    if (!nl_script.current) {
        return __real_nl_transact(protocol, request, reply);
    }
    ovs_assert(protocol == NETLINK_ROUTE && !reply);
    const struct ndmsg *nd = ofpbuf_at(request, NLMSG_HDRLEN, sizeof *nd);
    ovs_assert(nd && nd->ndm_family == AF_INET);
    ovs_assert(nd->ndm_ifindex == (nl_script.if_index ? nl_script.if_index
                                                     : 42));
    switch (nl_msg_nlmsghdr(request)->nlmsg_type) {
    case RTM_NEWNEIGH:
        nl_script.adds++;
        break;
    case RTM_DELNEIGH:
        nl_script.deletes++;
        break;
    default:
        OVS_NOT_REACHED();
    }
    return nl_script.transact_error;
}

static struct ofpbuf *
neighbor_dump_message(void)
{
    ovs_assert(nl_script.n_messages < ARRAY_SIZE(nl_script.messages));
    struct ofpbuf *message =
        &nl_script.messages[nl_script.n_messages++];
    ofpbuf_init(message, 128);
    nl_msg_put_nlmsghdr(message, 0, RTM_NEWNEIGH, 0);
    return message;
}

static void
neighbor_dump_add(uint8_t family, int32_t if_index, uint16_t state,
                  uint8_t nd_flags, uint16_t nl_flags, size_t lladdr_len,
                  uint8_t last)
{
    struct ofpbuf *message = neighbor_dump_message();
    struct ndmsg *nd = ofpbuf_put_zeros(message, sizeof *nd);
    nd->ndm_family = family;
    nd->ndm_ifindex = if_index;
    nd->ndm_state = state;
    nd->ndm_flags = nd_flags;
    ovs_be32 ip = htonl(0xc0000200 | last);
    if (family == AF_INET) {
        nl_msg_put_be32(message, NDA_DST, ip);
    } else {
        struct in6_addr ip6 = in6_addr_mapped_ipv4(ip);
        nl_msg_put_in6_addr(message, NDA_DST, &ip6);
    }
    uint8_t mac[20] = { 0x02, 0, 0, 0, 0, last };
    ovs_assert(lladdr_len <= sizeof mac);
    nl_msg_put_unspec(message, NDA_LLADDR, mac, lladdr_len);
    struct nlmsghdr *header = nl_msg_nlmsghdr(message);
    header->nlmsg_flags = nl_flags;
    header->nlmsg_len = message->size;
}

static void
test_neighbor_exchange_retry(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    int32_t if_index = if_nametoindex("lo");
    ovs_assert(if_index);
    struct neighbor_interface_monitor mon = {
        .family = NEIGH_AF_INET,
        .if_name = "lo",
        .type = NEIGH_IFACE_LOOPBACK,
        .announced_neighbors = HMAP_INITIALIZER(&mon.announced_neighbors),
    };
    struct advertise_neighbor_entry desired = {
        .lladdr = ETH_ADDR_C(02,00,00,00,00,03),
        .addr = in6_addr_mapped_ipv4(htonl(0xc0000203)),
    };
    hmap_insert(&mon.announced_neighbors, &desired.node,
                advertise_neigh_hash(&desired.lladdr, &desired.addr));
    struct vector interfaces =
        VECTOR_EMPTY_INITIALIZER(struct neighbor_interface_monitor *);
    struct neighbor_interface_monitor *monp = &mon;
    vector_push(&interfaces, &monp);
    struct hmap arps = HMAP_INITIALIZER(&arps);
    struct hmap fdbs = HMAP_INITIALIZER(&fdbs);
    struct hmap vteps = HMAP_INITIALIZER(&vteps);
    struct vector watches = VECTOR_EMPTY_INITIALIZER(int32_t);
    const struct neighbor_exchange_ctx_in input = {
        .monitored_interfaces = &interfaces,
    };
    struct neighbor_exchange_ctx_out output = {
        .neighbor_table_watches = &watches,
        .static_arps = &arps,
        .static_fdbs = &fdbs,
        .remote_vteps = &vteps,
    };

    nl_script.active = true;
    nl_script.if_index = if_index;
    nl_script.transact_error = EIO;
    neighbor_dump_add(AF_INET, if_index, NUD_NOARP, 0, 0, ETH_ADDR_LEN, 2);
    long long int now = time_msec();
    poll_wakeup_at = 0;
    neighbor_exchange_run(&input, &output);
    long long int retry_at = poll_wakeup_at;
    ovs_assert(retry_at >= now + 1000 && retry_at <= time_msec() + 1000);
    ovs_assert(nl_script.adds == 1 && nl_script.deletes == 1);
    poll_wakeup_at = 0;
    ovs_assert(!neighbor_exchange_retry_due());
    ovs_assert(poll_wakeup_at == retry_at);
    long long int deadline = time_msec() + 3000;
    while (!neighbor_exchange_retry_due() && time_msec() < deadline) {
        poll_timer_wait_until(deadline);
        poll_block();
    }
    ovs_assert(neighbor_exchange_retry_due());

    /* A persistent write error must schedule another bounded retry. */
    now = time_msec();
    poll_wakeup_at = 0;
    neighbor_exchange_run(&input, &output);
    retry_at = poll_wakeup_at;
    ovs_assert(retry_at >= now + 1000 && retry_at <= time_msec() + 1000);
    ovs_assert(nl_script.adds == 2 && nl_script.deletes == 2);
    poll_wakeup_at = 0;
    ovs_assert(!neighbor_exchange_retry_due());
    ovs_assert(poll_wakeup_at == retry_at);

    /* Another engine input may run synchronization before the deadline. */
    nl_script.transact_error = 0;
    neighbor_exchange_run(&input, &output);
    ovs_assert(nl_script.adds == 3 && nl_script.deletes == 3);
    ovs_assert(!neighbor_exchange_retry_due());
    nl_script.active = false;
    ofpbuf_uninit(&nl_script.messages[0]);
    vector_destroy(&interfaces);
    vector_destroy(&watches);
    hmap_remove(&mon.announced_neighbors, &desired.node);
    hmap_destroy(&mon.announced_neighbors);
    hmap_destroy(&arps);
    hmap_destroy(&fdbs);
    hmap_destroy(&vteps);
    struct sset none = SSET_INITIALIZER(&none);
    host_if_monitor_update_watches(&none);
    sset_destroy(&none);
}

static void
test_neighbor_sync(struct ovs_cmdl_context *ctx)
{
    struct advertise_neighbor_entry *e;
    unsigned int n_neighs_to_add;
    unsigned int shift = 1;
    unsigned int if_index;

    const char *family_str = test_read_value(ctx, shift++, "address family");
    if (!family_str) {
        return;
    }
    enum neighbor_family family;
    if (!strcmp(family_str, "inet")) {
        family = NEIGH_AF_INET;
    } else if (!strcmp(family_str, "inet6")) {
        family = NEIGH_AF_INET6;
    } else if (!strcmp(family_str, "bridge")) {
        family = NEIGH_AF_BRIDGE;
    } else {
        fprintf(stderr, "Invalid address family %s\n", family_str);
        return;
    }

    if (!test_read_uint_value(ctx, shift++, "if_index", &if_index)) {
        return;
    }

    if (!test_read_uint_value(ctx, shift++, "number of neighbors to sync",
                              &n_neighs_to_add)) {
        return;
    }

    struct hmap neighbors_to_add = HMAP_INITIALIZER(&neighbors_to_add);
    struct vector received_neighbors =
        VECTOR_EMPTY_INITIALIZER(struct ne_nl_received_neigh);

    for (unsigned int i = 0; i < n_neighs_to_add; i++) {
        struct advertise_neighbor_entry *ane = xzalloc(sizeof *ane);
        if (!test_read_eth_addr_value(ctx, shift++, "MAC address",
                                      &ane->lladdr)) {
            free(ane);
            goto done;
        }
        if (shift < ctx->argc) {
            /* It might be that we're only adding L2 neighbors,
             * skip IP parsing then. */
            struct eth_addr ea;
            if (!eth_addr_from_string(ctx->argv[shift], &ea) &&
                !test_read_ipv6_mapped_value(ctx, shift++, "IP address",
                                             &ane->addr)) {
                free(ane);
                goto done;
            }
        }
        hmap_insert(&neighbors_to_add, &ane->node,
                    advertise_neigh_hash(&ane->lladdr, &ane->addr));
    }

    ovs_assert(ne_nl_sync_neigh(family, if_index, NEIGH_IFACE_UNSPECIFIED,
                                &neighbors_to_add, &received_neighbors) == 0);

    struct ne_nl_received_neigh *ne;
    VECTOR_FOR_EACH_PTR (&received_neighbors, ne) {
        char addr_s[INET6_ADDRSTRLEN + 1];
        printf("Neighbor ifindex=%"PRId32" vlan=%"PRIu16" "
               "eth=" ETH_ADDR_FMT " dst=%s port=%"PRIu16" "
               "nh_id=%"PRIu32"\n",
               ne->if_index, ne->vlan, ETH_ADDR_ARGS(ne->lladdr),
               ipv6_string_mapped(addr_s, &ne->addr) ? addr_s : "(invalid)",
               ne->port, ne->nh_id);
    }

done:
    HMAP_FOR_EACH_POP (e, node, &neighbors_to_add) {
        free(e);
    }
    hmap_destroy(&neighbors_to_add);
    vector_destroy(&received_neighbors);
}

static void
run_command_under_notifier(const char *cmd)
{
    ovn_netlink_notifiers_run();
    ovn_netlink_notifiers_wait();

    int rc = system(cmd);
    if (rc) {
        exit(rc);
    }

    ovn_netlink_notifiers_run();
}

static void
test_neighbor_table_notify(struct ovs_cmdl_context *ctx)
{
    unsigned int shift = 1;

    const char *cmd = test_read_value(ctx, shift++, "shell_command");
    if (!cmd) {
        return;
    }

    ovn_netlink_update_notifier(OVN_NL_NOTIFIER_NEIGHBOR, true);
    run_command_under_notifier(cmd);

    struct vector *msgs = ovn_netlink_get_msgs(OVN_NL_NOTIFIER_NEIGHBOR);

    struct ne_table_msg *msg;
    VECTOR_FOR_EACH_PTR (msgs, msg) {
        char addr_s[INET6_ADDRSTRLEN + 1];
        printf("%s neighbor ifindex=%"PRId32" vlan=%"PRIu16" "
               "eth=" ETH_ADDR_FMT " dst=%s port=%"PRIu16" "
               "nh_id=%"PRIu32"\n",
               msg->nlmsg_type == RTM_NEWNEIGH ? "Add" : "Delete",
               msg->nd.if_index, msg->nd.vlan, ETH_ADDR_ARGS(msg->nd.lladdr),
               ipv6_string_mapped(addr_s, &msg->nd.addr)
                   ? addr_s
                   : "(invalid)",
               msg->nd.port, msg->nd.nh_id);
    }

    ovn_netlink_notifiers_destroy();
}

static void
test_host_if_monitor(struct ovs_cmdl_context *ctx)
{
    unsigned int shift = 1;

    const char *if_name = test_read_value(ctx, shift++, "if_name");
    if (!if_name) {
        return;
    }

    const char *cmd = test_read_value(ctx, shift++, "shell_command");
    if (!cmd) {
        return;
    }

    const char *notify = test_read_value(ctx, shift++, "should_notify");
    bool expect_notify = notify && !strcmp(notify, "true");

    struct sset if_names = SSET_INITIALIZER(&if_names);
    sset_add(&if_names, if_name);
    host_if_monitor_update_watches(&if_names);

    host_if_monitor_run();
    host_if_monitor_wait();

    int rc = system(cmd);
    if (rc) {
        exit(rc);
    }
    ovs_assert(host_if_monitor_run() == expect_notify);
    printf("%"PRId32"\n", host_if_monitor_ifname_toindex(if_name));
    sset_destroy(&if_names);
}

static void
test_route_sync(struct ovs_cmdl_context *ctx)
{
    struct advertise_route_entry *e;
    unsigned int shift = 1;

    unsigned int table_id;
    if (!test_read_uint_value(ctx, shift++, "table id", &table_id)) {
        return;
    }

    struct hmap routes_to_advertise = HMAP_INITIALIZER(&routes_to_advertise);
    struct vector received_routes =
        VECTOR_EMPTY_INITIALIZER(struct re_nl_received_route_node);

    while (shift < ctx->argc) {
        struct advertise_route_entry *ar = xzalloc(sizeof *ar);
        if (!test_read_ipv6_cidr_mapped_value(ctx, shift++, "IP address",
                                              &ar->addr, &ar->plen)) {
            free(ar);
            goto done;
        }

        /* Check if we are adding only blackhole route. */
        if (shift + 1 < ctx->argc) {
            const char *via = test_read_value(ctx, shift++, "via");
            if (strcmp(via, "via")) {
                shift--;
                continue;
            }

            if (!test_read_ipv6_mapped_value(ctx, shift++, "IP address",
                                             &ar->nexthop)) {
                free(ar);
                goto done;
            }
        }
        hmap_insert(&routes_to_advertise, &ar->node,
                    advertise_route_hash(&ar->addr, &ar->nexthop, ar->plen));
    }

    ovs_assert(re_nl_sync_routes(table_id, &routes_to_advertise,
                                 &received_routes) == 0);

    struct ds msg = DS_EMPTY_INITIALIZER;

    struct re_nl_received_route_node *rr;
    VECTOR_FOR_EACH_PTR (&received_routes, rr) {
        re_route_format(&msg, table_id, &rr->prefix,
                        rr->plen, &rr->nexthop, 0);
        printf("Route %s\n", ds_cstr(&msg));
        ds_clear(&msg);
    }

done:
    HMAP_FOR_EACH_POP (e, node, &routes_to_advertise) {
        free(e);
    }
    hmap_destroy(&routes_to_advertise);
    vector_destroy(&received_routes);
    ds_destroy(&msg);
}

static void
test_route_table_notify(struct ovs_cmdl_context *ctx)
{
    unsigned int shift = 1;

    const char *cmd = test_read_value(ctx, shift++, "shell_command");
    if (!cmd) {
        return;
    }

    ovn_netlink_update_notifier(OVN_NL_NOTIFIER_ROUTE_V4, true);
    ovn_netlink_update_notifier(OVN_NL_NOTIFIER_ROUTE_V6, true);
    run_command_under_notifier(cmd);

    uint32_t table_id;

    struct vector *msgs = ovn_netlink_get_msgs(OVN_NL_NOTIFIER_ROUTE_V4);
    VECTOR_FOR_EACH (msgs, table_id) {
        printf("Notification v4 table_id=%"PRIu32"\n", table_id);
    }

    msgs = ovn_netlink_get_msgs(OVN_NL_NOTIFIER_ROUTE_V6);
    VECTOR_FOR_EACH (msgs, table_id) {
        printf("Notification v6 table_id=%"PRIu32"\n", table_id);
    }

    ovn_netlink_notifiers_destroy();
}

static void
test_nexthop_sync(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct hmap nexthops = HMAP_INITIALIZER(&nexthops);
    struct ds ds = DS_EMPTY_INITIALIZER;

    nexthops_sync(&nexthops);

    struct nexthop_entry *nhe;
    HMAP_FOR_EACH (nhe, hmap_node, &nexthops) {
        ds_clear(&ds);
        nexthop_entry_format(&ds, nhe);
        printf("Nexthop %s\n", ds_cstr(&ds));
    }

    HMAP_FOR_EACH_POP (nhe, hmap_node, &nexthops) {
        free(nhe);
    }

    ds_destroy(&ds);
    hmap_destroy(&nexthops);
}

static void
test_nexthop_table_notify(struct ovs_cmdl_context *ctx)
{
    unsigned int shift = 1;

    const char *cmd = test_read_value(ctx, shift++, "shell_command");
    if (!cmd) {
        return;
    }

    ovn_netlink_update_notifier(OVN_NL_NOTIFIER_NEXTHOP, true);
    run_command_under_notifier(cmd);

    struct vector *msgs = ovn_netlink_get_msgs(OVN_NL_NOTIFIER_NEXTHOP);
    struct ds ds = DS_EMPTY_INITIALIZER;

    struct nh_table_msg *msg;
    VECTOR_FOR_EACH_PTR (msgs, msg) {
        ds_clear(&ds);
        nexthop_entry_format(&ds, msg->nhe);
        printf("%s nexthop %s\n",
               msg->nlmsg_type == RTM_NEWNEXTHOP ? "Add" : "Delete",
               ds_cstr(&ds));
    }

    ds_destroy(&ds);
    ovn_netlink_notifiers_destroy();
}

/* Dumps the nexthop table after applying the changes caused by running
 * 'shell_command' to it.  Unlike "nexthop-sync", which builds the table from
 * scratch, this goes through the incremental update path. */
static void
test_nexthop_table_update(struct ovs_cmdl_context *ctx)
{
    unsigned int shift = 1;

    const char *cmd = test_read_value(ctx, shift++, "shell_command");
    if (!cmd) {
        return;
    }

    struct hmap nexthops = HMAP_INITIALIZER(&nexthops);
    struct ds ds = DS_EMPTY_INITIALIZER;

    ovn_netlink_update_notifier(OVN_NL_NOTIFIER_NEXTHOP, true);
    nexthops_sync(&nexthops);
    /* The table is up to date, anything reported so far is already in it. */
    ovn_netlink_notifier_flush(OVN_NL_NOTIFIER_NEXTHOP);

    run_command_under_notifier(cmd);

    nexthops_handle_changes(&nexthops,
                            ovn_netlink_get_msgs(OVN_NL_NOTIFIER_NEXTHOP));
    ovn_netlink_notifier_flush(OVN_NL_NOTIFIER_NEXTHOP);

    struct nexthop_entry *nhe;
    HMAP_FOR_EACH (nhe, hmap_node, &nexthops) {
        ds_clear(&ds);
        nexthop_entry_format(&ds, nhe);
        printf("Nexthop %s\n", ds_cstr(&ds));
    }

    ds_destroy(&ds);
    nexthops_destroy(&nexthops);
    hmap_destroy(&nexthops);
    ovn_netlink_notifiers_destroy();
}

static void
test_ovn_netlink(int argc, char *argv[])
{
    set_program_name(argv[0]);
    static const struct ovs_cmdl_command commands[] = {
        {"neighbor-sync", NULL, 2, INT_MAX, test_neighbor_sync, OVS_RO},
        {"neighbor-table-notify", NULL, 1, 1,
         test_neighbor_table_notify, OVS_RO},
        {"neighbor-exchange-retry", NULL, 0, 0,
         test_neighbor_exchange_retry, OVS_RO},
        {"host-if-monitor", NULL, 2, 3, test_host_if_monitor, OVS_RO},
        {"route-sync", NULL, 1, INT_MAX, test_route_sync, OVS_RO},
        {"route-table-notify", NULL, 1, 1,
         test_route_table_notify, OVS_RO},
        {"nexthop-sync", NULL, 0, 0, test_nexthop_sync, OVS_RO},
        {"nexthop-table-notify", NULL, 1, 1,
         test_nexthop_table_notify, OVS_RO},
        {"nexthop-table-update", NULL, 1, 1,
         test_nexthop_table_update, OVS_RO},
        {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - 1;
    ctx.argv = argv + 1;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-ovn-netlink", test_ovn_netlink);
