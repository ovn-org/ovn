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
#include <net/if.h>
#include <sys/resource.h>

#include "netlink.h"
#include "netlink-socket.h"
#include "openvswitch/hmap.h"
#include "openvswitch/poll-loop.h"
#include "route-table.h"
#include "packets.h"
#include "tests/ovstest.h"
#include "tests/test-utils.h"
#include "timeval.h"

#include "controller/host-if-monitor.h"
#include "controller/neighbor-exchange.h"
#include "controller/neighbor-exchange-netlink.h"
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
    ovs_assert(!nl_script.started);
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
test_neighbor_dump_script(struct ovs_cmdl_context *ctx)
{
    const char *scenario = ctx->argv[1];
    bool complete = !strcmp(scenario, "complete");
    bool write_error = !strcmp(scenario, "write-error");
    bool other_interface = !strcmp(scenario, "other-interface");
    bool other_family = !strcmp(scenario, "other-family");
    bool malformed = !strcmp(scenario, "malformed");
    bool filtered = !strcmp(scenario, "filtered-malformed");
    bool truncated = !strcmp(scenario, "truncated");
    bool late_error = !strcmp(scenario, "late-error");
    bool both_errors = !strcmp(scenario, "parse-and-dump-error");
    bool interrupted = !strcmp(scenario, "interrupted");
    bool record_interrupted = !strcmp(scenario, "record-interrupted");
    ovs_assert(complete || write_error || other_interface || other_family
               || malformed || filtered || truncated || late_error
               || interrupted || record_interrupted || both_errors);

    struct hmap neighbors = HMAP_INITIALIZER(&neighbors);
    struct advertise_neighbor_entry desired = {
        .lladdr = ETH_ADDR_C(02,00,00,00,00,03),
        .addr = in6_addr_mapped_ipv4(htonl(0xc0000203)),
    };
    hmap_insert(&neighbors, &desired.node,
                advertise_neigh_hash(&desired.lladdr, &desired.addr));
    struct vector learned =
        VECTOR_EMPTY_INITIALIZER(struct ne_nl_received_neigh);
    struct ne_nl_received_neigh sentinel = { .if_index = 17 };
    vector_push(&learned, &sentinel);

    memset(&nl_script, 0, sizeof nl_script);
    nl_script.active = true;
    /* A learned row and an obsolete OVN-owned row precede the fault.  A
     * successful sync must publish the former, add the desired row and
     * delete the latter; a failed dump must do none of those operations. */
    neighbor_dump_add(AF_INET, 42, NUD_REACHABLE, 0, 0, ETH_ADDR_LEN, 1);
    neighbor_dump_add(AF_INET, 42, NUD_NOARP, 0, 0, ETH_ADDR_LEN, 2);
    if (other_interface || other_family || malformed || filtered
        || both_errors) {
        neighbor_dump_add(other_family ? AF_INET6 : AF_INET,
                          other_interface ? 43 : 42, NUD_REACHABLE, 0,
                          filtered ? NLM_F_DUMP_FILTERED : 0,
                          other_interface || other_family ? ETH_ADDR_LEN : 20,
                          4);
    } else if (truncated) {
        struct ofpbuf *message = neighbor_dump_message();
        ofpbuf_put_zeros(message, sizeof(struct ndmsg) - 1);
        nl_msg_nlmsghdr(message)->nlmsg_len = message->size;
    } else if (record_interrupted) {
        /* Even an unrelated record marks the whole dump interrupted. */
        neighbor_dump_add(AF_INET, 43, NUD_REACHABLE, 0, NLM_F_DUMP_INTR,
                          ETH_ADDR_LEN, 4);
        neighbor_dump_add(AF_INET, 42, NUD_REACHABLE, 0, 0, ETH_ADDR_LEN, 5);
    }
    nl_script.error = late_error || both_errors ? EINTR : 0;
    nl_script.done_flags = interrupted ? NLM_F_DUMP_INTR : 0;

    nl_script.transact_error = write_error ? EIO : 0;

    bool dump_failed;
    int error = ne_nl_sync_neigh(AF_INET, 42, NEIGH_IFACE_UNSPECIFIED,
                                 &neighbors, &learned, &dump_failed);
    ovs_assert(nl_script.started && nl_script.finished);
    ovs_assert(nl_script.next == nl_script.n_messages);
    nl_script.active = false;
    bool success = !(late_error || interrupted || record_interrupted
                     || both_errors);
    ovs_assert(error == (success ? nl_script.transact_error : EINTR));
    ovs_assert(dump_failed == !success);
    ovs_assert(nl_script.adds == (success ? 1 : 0));
    ovs_assert(nl_script.deletes == (success ? 1 : 0));
    ovs_assert(hmap_count(&neighbors) == 1);
    ovs_assert(learned.len == (success ? 2 : 1));
    const struct ne_nl_received_neigh *rows = learned.buffer;
    ovs_assert(!memcmp(&rows[0], &sentinel, sizeof sentinel));
    if (success) {
        struct eth_addr mac = ETH_ADDR_C(02,00,00,00,00,01);
        struct in6_addr ip = in6_addr_mapped_ipv4(htonl(0xc0000201));
        ovs_assert(rows[1].if_index == 42 && rows[1].family == AF_INET);
        ovs_assert(rows[1].state == NUD_REACHABLE);
        ovs_assert(eth_addr_equals(rows[1].lladdr, mac));
        ovs_assert(ipv6_addr_equals(&rows[1].addr, &ip));
    }
    for (size_t i = 0; i < nl_script.n_messages; i++) {
        ofpbuf_uninit(&nl_script.messages[i]);
    }
    vector_destroy(&learned);
    hmap_destroy(&neighbors);
}

static void
neighbor_script_reset(int32_t if_index, int error)
{
    for (size_t i = 0; i < nl_script.n_messages; i++) {
        ofpbuf_uninit(&nl_script.messages[i]);
    }
    memset(&nl_script, 0, sizeof nl_script);
    nl_script.active = if_index != 0;
    nl_script.if_index = if_index;
    nl_script.error = error;
}

static bool
has_static_arp(const struct hmap *arps, uint32_t vni, uint8_t last)
{
    struct in6_addr ip = in6_addr_mapped_ipv4(htonl(0xc0000200 | last));
    struct eth_addr mac = ETH_ADDR_C(02,00,00,00,00,00);
    mac.ea[5] = last;
    struct evpn_static_entry *entry;
    HMAP_FOR_EACH (entry, hmap_node, arps) {
        if (entry->vni == vni && ipv6_addr_equals(&entry->ip, &ip)
            && eth_addr_equals(entry->mac, mac)) {
            return true;
        }
    }
    return false;
}

static void
test_neighbor_exchange_snapshot(struct ovs_cmdl_context *ctx)
{
    bool check_retry = !strcmp(ctx->argv[1], "retry");
    bool replace_link = !strcmp(ctx->argv[1], "replace");
    bool rename_link = !strcmp(ctx->argv[1], "rename");
    bool write_error = !strcmp(ctx->argv[1], "write-error");
    ovs_assert(check_retry || replace_link || rename_link || write_error
               || !strcmp(ctx->argv[1], "retention"));
    ovs_assert(ctx->argc == (replace_link ? 3 : 2));
    struct neighbor_interface_monitor first = {
        .family = NEIGH_AF_INET,
        .if_name = "dump-br1",
        .type = NEIGH_IFACE_BRIDGE,
        .vni = 101,
        .announced_neighbors = HMAP_INITIALIZER(&first.announced_neighbors),
    };
    struct neighbor_interface_monitor second = {
        .family = NEIGH_AF_INET,
        .if_name = "dump-br2",
        .type = NEIGH_IFACE_BRIDGE,
        .vni = 102,
        .announced_neighbors = HMAP_INITIALIZER(&second.announced_neighbors),
    };
    struct vector interfaces =
        VECTOR_EMPTY_INITIALIZER(struct neighbor_interface_monitor *);
    struct neighbor_interface_monitor *mon = &first;
    vector_push(&interfaces, &mon);
    if (check_retry) {
        /* The retry case only needs one dump target. */
        ovs_strlcpy(first.if_name, "lo", sizeof first.if_name);
        first.type = NEIGH_IFACE_LOOPBACK;
    } else {
        mon = &second;
        vector_push(&interfaces, &mon);
    }

    struct hmap snapshots = HMAP_INITIALIZER(&snapshots);
    struct hmap arps = HMAP_INITIALIZER(&arps);
    struct hmap fdbs = HMAP_INITIALIZER(&fdbs);
    struct hmap vteps = HMAP_INITIALIZER(&vteps);
    struct vector watches = VECTOR_EMPTY_INITIALIZER(int32_t);
    const struct neighbor_exchange_ctx_in input = {
        .monitored_interfaces = &interfaces,
    };
    struct neighbor_exchange_ctx_out output = {
        .neighbor_table_watches = &watches,
        .snapshots = &snapshots,
        .static_arps = &arps,
        .static_fdbs = &fdbs,
        .remote_vteps = &vteps,
    };

    int32_t if_index = if_nametoindex(first.if_name);
    ovs_assert(if_index);
    if (check_retry) {
        neighbor_script_reset(if_index, EIO);

        long long int now = time_msec();
        poll_wakeup_at = 0;
        neighbor_exchange_run(&input, &output);
        ovs_assert(nl_script.started && nl_script.finished);
        long long int retry_at = poll_wakeup_at;
        ovs_assert(retry_at >= now + 1000 && retry_at <= time_msec() + 1000);
        poll_wakeup_at = 0;
        ovs_assert(!neighbor_exchange_retry_due());
        ovs_assert(poll_wakeup_at == retry_at);
        long long int deadline = time_msec() + 3000;
        while (!neighbor_exchange_retry_due() && time_msec() < deadline) {
            poll_timer_wait_until(deadline);
            poll_block();
        }
        ovs_assert(neighbor_exchange_retry_due());

        neighbor_script_reset(if_index, 0);
        neighbor_exchange_run(&input, &output);
        ovs_assert(nl_script.started && nl_script.finished);
        ovs_assert(!neighbor_exchange_retry_due());
        goto cleanup;
    }

    /* The second interface uses the real Netlink transport. */
    neighbor_script_reset(if_index, 0);
    neighbor_dump_add(AF_INET, if_index, NUD_NOARP, NTF_EXT_LEARNED, 0,
                      ETH_ADDR_LEN, 1);
    neighbor_exchange_run(&input, &output);
    ovs_assert(nl_script.started && nl_script.finished);
    ovs_assert(hmap_count(&arps) == 2
               && has_static_arp(&arps, 101, 1)
               && has_static_arp(&arps, 102, 2));

    if (rename_link) {
        /* Rename a down bridge to a name outside the watch set. */
        ovs_assert(!system("ip link set dump-br1 name dump-renamed"));
        ovs_assert(if_nametoindex("dump-renamed") == (uint32_t) if_index);
        bool changed = host_if_monitor_run();
        neighbor_script_reset(if_index, EIO);
        neighbor_exchange_run(&input, &output);
        ovs_assert(hmap_count(&arps) == 1
                   && has_static_arp(&arps, 102, 2));
        ovs_assert(changed && !nl_script.started
                   && vector_len(&watches) == 1);
        goto cleanup;
    }

    if (replace_link) {
        /* Consume the deletion and creation in a single monitor run. */
        ovs_assert(!system(ctx->argv[2]));
        ovs_assert(host_if_monitor_run());
        ovs_assert(if_nametoindex(first.if_name) == (uint32_t) if_index);
    }

    if (write_error) {
        /* A successful dump replaces the cache even when a delete fails. */
        neighbor_script_reset(if_index, 0);
        nl_script.transact_error = EIO;
        neighbor_dump_add(AF_INET, if_index, NUD_NOARP, NTF_EXT_LEARNED, 0,
                          ETH_ADDR_LEN, 3);
        neighbor_dump_add(AF_INET, if_index, NUD_NOARP, 0, 0, ETH_ADDR_LEN, 4);
        poll_wakeup_at = 0;
        neighbor_exchange_run(&input, &output);
        ovs_assert(nl_script.started && nl_script.finished);
        ovs_assert(nl_script.deletes == 1 && !nl_script.adds);
        ovs_assert(poll_wakeup_at > 0 && !neighbor_exchange_retry_due());
        ovs_assert(hmap_count(&arps) == 2
                   && has_static_arp(&arps, 101, 3)
                   && has_static_arp(&arps, 102, 2));
    }

    /* The healthy interface still refreshes.  The partial dump must not
     * publish its observation or write to the kernel. */
    second.vni = 104;
    neighbor_script_reset(if_index, EIO);
    neighbor_dump_add(AF_INET, if_index, NUD_NOARP, NTF_EXT_LEARNED, 0,
                      ETH_ADDR_LEN, 5);
    neighbor_exchange_run(&input, &output);
    ovs_assert(nl_script.started && nl_script.finished);
    ovs_assert(!nl_script.deletes && !nl_script.adds);
    ovs_assert(hmap_count(&arps) == (replace_link ? 1 : 2)
               && has_static_arp(&arps, 104, 2));
    if (!replace_link) {
        ovs_assert(has_static_arp(&arps, 101, write_error ? 3 : 1));
    }
    ovs_assert(vector_len(&watches) == 2);

    /* Scope changes discard the old snapshot even during failure. */
    first.vni = 103;
    neighbor_script_reset(if_index, EIO);
    neighbor_exchange_run(&input, &output);
    ovs_assert(nl_script.started && nl_script.finished);
    ovs_assert(hmap_count(&arps) == 1
               && has_static_arp(&arps, 104, 2));

    /* Recovery publishes fresh data.  A complete empty dump withdraws it. */
    first.vni = 101;
    neighbor_script_reset(if_index, 0);
    neighbor_dump_add(AF_INET, if_index, NUD_NOARP, NTF_EXT_LEARNED, 0,
                      ETH_ADDR_LEN, 3);
    neighbor_exchange_run(&input, &output);
    ovs_assert(hmap_count(&arps) == 2
               && has_static_arp(&arps, 101, 3)
               && has_static_arp(&arps, 104, 2));
    neighbor_script_reset(if_index, 0);
    neighbor_exchange_run(&input, &output);
    ovs_assert(nl_script.started && nl_script.finished);
    ovs_assert(hmap_count(&arps) == 1
               && has_static_arp(&arps, 104, 2));
    ovs_assert(!neighbor_exchange_retry_due());

cleanup:
    neighbor_script_reset(0, 0);
    vector_clear(&interfaces);
    neighbor_exchange_run(&input, &output);
    ovs_assert(hmap_is_empty(&snapshots) && vector_is_empty(&watches));
    hmap_destroy(&snapshots);
    hmap_destroy(&arps);
    hmap_destroy(&fdbs);
    hmap_destroy(&vteps);
    vector_destroy(&watches);
    vector_destroy(&interfaces);
    hmap_destroy(&first.announced_neighbors);
    hmap_destroy(&second.announced_neighbors);
}

/* A failed dump must not be reported as successful synchronization. */
static void
test_neighbor_sync_error(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct hmap neighbors = HMAP_INITIALIZER(&neighbors);
    struct vector learned =
        VECTOR_EMPTY_INITIALIZER(struct ne_nl_received_neigh);
    struct ne_nl_received_neigh sentinel = { .if_index = 42 };
    vector_push(&learned, &sentinel);

    /* This command starts without pooled Netlink sockets.  Exhaust its file
     * descriptor allowance so the real dump fails before receiving data. */
    struct rlimit original;
    ovs_assert(!getrlimit(RLIMIT_NOFILE, &original));
    struct rlimit limited = original;
    limited.rlim_cur = 0;
    ovs_assert(!setrlimit(RLIMIT_NOFILE, &limited));
    bool dump_failed;
    int error = ne_nl_sync_neigh(AF_INET, 0, NEIGH_IFACE_UNSPECIFIED,
                                 &neighbors, &learned, &dump_failed);
    ovs_assert(!setrlimit(RLIMIT_NOFILE, &original));

    ovs_assert(error == EMFILE && dump_failed);
    ovs_assert(learned.len == 1);
    ovs_assert(!memcmp(learned.buffer, &sentinel, sizeof sentinel));
    vector_destroy(&learned);
    hmap_destroy(&neighbors);
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
    struct hmap snapshots = HMAP_INITIALIZER(&snapshots);
    struct hmap arps = HMAP_INITIALIZER(&arps);
    struct hmap fdbs = HMAP_INITIALIZER(&fdbs);
    struct hmap vteps = HMAP_INITIALIZER(&vteps);
    struct vector watches = VECTOR_EMPTY_INITIALIZER(int32_t);
    const struct neighbor_exchange_ctx_in input = {
        .monitored_interfaces = &interfaces,
    };
    struct neighbor_exchange_ctx_out output = {
        .neighbor_table_watches = &watches,
        .snapshots = &snapshots,
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
    nl_script.started = nl_script.finished = false;
    nl_script.next = 0;
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
    nl_script.started = nl_script.finished = false;
    nl_script.next = 0;
    neighbor_exchange_run(&input, &output);
    retry_at = poll_wakeup_at;
    ovs_assert(retry_at >= now + 1000 && retry_at <= time_msec() + 1000);
    ovs_assert(nl_script.adds == 2 && nl_script.deletes == 2);
    poll_wakeup_at = 0;
    ovs_assert(!neighbor_exchange_retry_due());
    ovs_assert(poll_wakeup_at == retry_at);

    /* Another engine input may run synchronization before the deadline. */
    nl_script.transact_error = 0;
    nl_script.started = nl_script.finished = false;
    nl_script.next = 0;
    neighbor_exchange_run(&input, &output);
    ovs_assert(nl_script.adds == 3 && nl_script.deletes == 3);
    ovs_assert(!neighbor_exchange_retry_due());
    nl_script.active = false;
    ofpbuf_uninit(&nl_script.messages[0]);
    vector_destroy(&interfaces);
    vector_destroy(&watches);
    hmap_remove(&mon.announced_neighbors, &desired.node);
    hmap_destroy(&mon.announced_neighbors);
    neighbor_exchange_snapshots_clear(&snapshots);
    hmap_destroy(&snapshots);
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

    bool dump_failed;
    ovs_assert(ne_nl_sync_neigh(family, if_index, NEIGH_IFACE_UNSPECIFIED,
                                &neighbors_to_add, &received_neighbors,
                                &dump_failed) == 0);

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
    printf("%"PRId32"\n", host_if_monitor_get_link(if_name).if_index);
    sset_destroy(&if_names);
}

/* Syncs the routes OVN advertises in 'table_id' and resolves the routes it
 * learns from it into 'received_routes', as route_exchange does. */
static int
sync_and_resolve_routes(uint32_t table_id,
                        const struct hmap *routes_to_advertise,
                        const struct hmap *nexthops,
                        struct vector *received_routes,
                        struct hmap *referenced_nhids)
{
    struct hmap learned_routes = HMAP_INITIALIZER(&learned_routes);
    struct vector route_tables =
        VECTOR_EMPTY_INITIALIZER(const struct hmap *);

    vector_push(&route_tables, &routes_to_advertise);

    int err = re_nl_sync_routes(table_id, &route_tables, &learned_routes);
    vector_destroy(&route_tables);

    const struct re_nl_cached_route *cr;
    HMAP_FOR_EACH (cr, node, &learned_routes) {
        re_nl_resolve_route(cr->msg, nexthops, received_routes,
                            referenced_nhids);
    }

    re_nl_cached_routes_clear(&learned_routes);
    hmap_destroy(&learned_routes);

    return err;
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
    struct hmap referenced_nhids = HMAP_INITIALIZER(&referenced_nhids);
    struct hmap nexthops = HMAP_INITIALIZER(&nexthops);
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

    /* Learned routes may reference their next hop through a nexthop id, which
     * can only be resolved against the kernel nexthop table. */
    nexthops_sync(&nexthops);

    ovs_assert(sync_and_resolve_routes(table_id, &routes_to_advertise,
                                       &nexthops, &received_routes,
                                       &referenced_nhids) == 0);

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
    nexthop_ids_clear(&referenced_nhids);
    hmap_destroy(&referenced_nhids);
    nexthops_destroy(&nexthops);
    hmap_destroy(&nexthops);
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

    static const char *families[] = {"v4", "v6"};
    static const enum ovn_netlink_notifier_type types[] = {
        OVN_NL_NOTIFIER_ROUTE_V4, OVN_NL_NOTIFIER_ROUTE_V6,
    };
    struct ds ds = DS_EMPTY_INITIALIZER;

    for (size_t i = 0; i < ARRAY_SIZE(types); i++) {
        struct vector *msgs = ovn_netlink_get_msgs(types[i]);
        struct ovn_route_msg *msg;

        VECTOR_FOR_EACH (msgs, msg) {
            ds_clear(&ds);
            ovn_route_msg_format(&ds, msg);
            printf("Notification %s %s route %s\n", families[i],
                   msg->nlmsg_type == RTM_NEWROUTE ? "add" : "delete",
                   ds_cstr(&ds));
        }
    }

    ds_destroy(&ds);
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

/* Reports the kernel nexthop objects that the routes learned from 'table_id'
 * depend on. */
static void
test_route_sync_nhids(struct ovs_cmdl_context *ctx)
{
    unsigned int table_id;

    if (!test_read_uint_value(ctx, 1, "table id", &table_id)) {
        return;
    }

    struct hmap routes_to_advertise = HMAP_INITIALIZER(&routes_to_advertise);
    struct hmap referenced_nhids = HMAP_INITIALIZER(&referenced_nhids);
    struct hmap nexthops = HMAP_INITIALIZER(&nexthops);
    struct vector received_routes =
        VECTOR_EMPTY_INITIALIZER(struct re_nl_received_route_node);

    nexthops_sync(&nexthops);
    ovs_assert(sync_and_resolve_routes(table_id, &routes_to_advertise,
                                       &nexthops, &received_routes,
                                       &referenced_nhids) == 0);

    const struct nexthop_id_node *node;
    HMAP_FOR_EACH (node, hmap_node, &referenced_nhids) {
        printf("Referenced nexthop id=%"PRIu32"\n", node->id);
    }

    nexthop_ids_clear(&referenced_nhids);
    hmap_destroy(&referenced_nhids);
    nexthops_destroy(&nexthops);
    hmap_destroy(&nexthops);
    hmap_destroy(&routes_to_advertise);
    vector_destroy(&received_routes);
}

/* Reports the routes of 'table_id' OVN learns from after applying the changes
 * caused by running 'shell_command' to them.  Unlike "route-sync", which reads
 * the whole table, this goes through the incremental update path. */
static void
test_route_table_update(struct ovs_cmdl_context *ctx)
{
    static const enum ovn_netlink_notifier_type types[] = {
        OVN_NL_NOTIFIER_ROUTE_V4, OVN_NL_NOTIFIER_ROUTE_V6,
    };
    unsigned int shift = 1;

    unsigned int table_id;
    if (!test_read_uint_value(ctx, shift++, "table id", &table_id)) {
        return;
    }

    const char *cmd = test_read_value(ctx, shift++, "shell_command");
    if (!cmd) {
        return;
    }

    struct hmap routes_to_advertise = HMAP_INITIALIZER(&routes_to_advertise);
    struct hmap learned_routes = HMAP_INITIALIZER(&learned_routes);
    struct vector route_tables =
        VECTOR_EMPTY_INITIALIZER(const struct hmap *);
    struct ds ds = DS_EMPTY_INITIALIZER;

    const struct hmap *routes = &routes_to_advertise;
    vector_push(&route_tables, &routes);

    for (size_t i = 0; i < ARRAY_SIZE(types); i++) {
        ovn_netlink_update_notifier(types[i], true);
    }
    ovs_assert(re_nl_sync_routes(table_id, &route_tables,
                                 &learned_routes) == 0);
    vector_destroy(&route_tables);
    /* The routes are up to date, anything reported so far is among them. */
    for (size_t i = 0; i < ARRAY_SIZE(types); i++) {
        ovn_netlink_notifier_flush(types[i]);
    }

    run_command_under_notifier(cmd);

    for (size_t i = 0; i < ARRAY_SIZE(types); i++) {
        struct vector *msgs = ovn_netlink_get_msgs(types[i]);
        struct ovn_route_msg *msg;

        VECTOR_FOR_EACH (msgs, msg) {
            if (msg->table_id != table_id) {
                continue;
            }

            printf("%s route %s\n",
                   re_nl_cached_routes_apply(&learned_routes, msg)
                   ? "Applied" : "Ignored",
                   msg->nlmsg_type == RTM_NEWROUTE ? "add" : "delete");
        }
        ovn_netlink_notifier_flush(types[i]);
    }

    const struct re_nl_cached_route *cr;
    HMAP_FOR_EACH (cr, node, &learned_routes) {
        ds_clear(&ds);
        ovn_route_msg_format(&ds, cr->msg);
        printf("Route %s\n", ds_cstr(&ds));
    }

    ds_destroy(&ds);
    re_nl_cached_routes_clear(&learned_routes);
    hmap_destroy(&learned_routes);
    hmap_destroy(&routes_to_advertise);
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
        {"neighbor-exchange-snapshot", NULL, 1, 2,
         test_neighbor_exchange_snapshot, OVS_RO},
        {"neighbor-dump-script", NULL, 1, 1,
         test_neighbor_dump_script, OVS_RO},
        {"neighbor-sync-error", NULL, 0, 0, test_neighbor_sync_error, OVS_RO},
        {"neighbor-sync", NULL, 2, INT_MAX, test_neighbor_sync, OVS_RO},
        {"neighbor-table-notify", NULL, 1, 1,
         test_neighbor_table_notify, OVS_RO},
        {"neighbor-exchange-retry", NULL, 0, 0,
         test_neighbor_exchange_retry, OVS_RO},
        {"host-if-monitor", NULL, 2, 3, test_host_if_monitor, OVS_RO},
        {"route-sync", NULL, 1, INT_MAX, test_route_sync, OVS_RO},
        {"route-sync-nhids", NULL, 1, 1, test_route_sync_nhids, OVS_RO},
        {"route-table-notify", NULL, 1, 1,
         test_route_table_notify, OVS_RO},
        {"route-table-update", NULL, 2, 2,
         test_route_table_update, OVS_RO},
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
