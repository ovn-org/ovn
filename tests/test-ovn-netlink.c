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

#include "openvswitch/hmap.h"
#include "route-table.h"
#include "packets.h"
#include "tests/ovstest.h"
#include "tests/test-utils.h"

#include "controller/host-if-monitor.h"
#include "controller/neighbor-exchange-netlink.h"
#include "controller/neighbor-table-notify.h"
#include "controller/neighbor.h"
#include "controller/route.h"
#include "controller/route-exchange-netlink.h"

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

    ovs_assert(ne_nl_sync_neigh(family, if_index, &neighbors_to_add,
                                &received_neighbors) == 0);

    struct ne_nl_received_neigh *ne;
    VECTOR_FOR_EACH_PTR (&received_neighbors, ne) {
        char addr_s[INET6_ADDRSTRLEN + 1];
        printf("Neighbor ifindex=%"PRId32" vlan=%"PRIu16" "
               "eth=" ETH_ADDR_FMT " dst=%s port=%"PRIu16"\n",
               ne->if_index, ne->vlan, ETH_ADDR_ARGS(ne->lladdr),
               ipv6_string_mapped(addr_s, &ne->addr) ? addr_s : "(invalid)",
               ne->port);
    }

done:
    HMAP_FOR_EACH_POP (e, node, &neighbors_to_add) {
        free(e);
    }
    hmap_destroy(&neighbors_to_add);
    vector_destroy(&received_neighbors);
}

static void
test_neighbor_table_notify(struct ovs_cmdl_context *ctx)
{
    unsigned int shift = 1;

    const char *if_name = test_read_value(ctx, shift++, "if_name");
    if (!if_name) {
        return;
    }

    unsigned int if_index;
    if (!test_read_uint_value(ctx, shift++, "if_index", &if_index)) {
        return;
    }

    const char *cmd = test_read_value(ctx, shift++, "shell_command");
    if (!cmd) {
        return;
    }

    const char *notify = test_read_value(ctx, shift++, "should_notify");
    bool expect_notify = notify && !strcmp(notify, "true");

    struct hmap table_watches = HMAP_INITIALIZER(&table_watches);
    neighbor_table_add_watch_request(&table_watches, if_index, if_name);
    neighbor_table_notify_update_watches(&table_watches);

    neighbor_table_notify_run();
    neighbor_table_notify_wait();

    int rc = system(cmd);
    if (rc) {
        exit(rc);
    }
    ovs_assert(neighbor_table_notify_run() == expect_notify);
    neighbor_table_watch_request_cleanup(&table_watches);
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
                                 &received_routes, NULL) == 0);

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
test_ovn_netlink(int argc, char *argv[])
{
    set_program_name(argv[0]);
    static const struct ovs_cmdl_command commands[] = {
        {"neighbor-sync", NULL, 2, INT_MAX, test_neighbor_sync, OVS_RO},
        {"neighbor-table-notify", NULL, 3, 4,
         test_neighbor_table_notify, OVS_RO},
        {"host-if-monitor", NULL, 2, 3, test_host_if_monitor, OVS_RO},
        {"route-sync", NULL, 1, INT_MAX, test_route_sync, OVS_RO},
        {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - 1;
    ctx.argv = argv + 1;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-ovn-netlink", test_ovn_netlink);
