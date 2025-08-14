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
#include "packets.h"
#include "tests/ovstest.h"
#include "tests/test-utils.h"

#include "controller/neighbor-exchange-netlink.h"
#include "controller/neighbor.h"

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
test_ovn_netlink(int argc, char *argv[])
{
    set_program_name(argv[0]);
    static const struct ovs_cmdl_command commands[] = {
        {"neighbor-sync", NULL, 2, INT_MAX, test_neighbor_sync, OVS_RO},
        {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - 1;
    ctx.argv = argv + 1;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-ovn-netlink", test_ovn_netlink);
