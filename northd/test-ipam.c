/*
 * Copyright (c) 2020 Red Hat, Inc.
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
#include "tests/ovstest.h"

#include "openvswitch/dynamic-string.h"
#include "smap.h"
#include "packets.h"
#include "bitmap.h"

#include "ipam.h"

static void
test_ipam_get_unused_ip(struct ovs_cmdl_context *ctx)
{
    struct ipam_info info;

    struct smap config = SMAP_INITIALIZER(&config);
    smap_add(&config, "subnet", ctx->argv[1]);
    int num_ips;
    str_to_int(ctx->argv[2], 0, &num_ips);
    if (ctx->argc > 3) {
        smap_add(&config, "exclude_ips", ctx->argv[3]);
    }
    init_ipam_info(&info, &config, "Unused IP test");

    bool fail = false;
    struct ds output = DS_EMPTY_INITIALIZER;
    struct ds err = DS_EMPTY_INITIALIZER;
    for (size_t i = 0; i < num_ips; i++) {
        uint32_t next_ip = ipam_get_unused_ip(&info);
        ds_put_format(&output, IP_FMT "\n", IP_ARGS(htonl(next_ip)));
        if (next_ip) {
            ovs_assert(ipam_insert_ip(&info, next_ip));
        }
    }

    printf("%s", ds_cstr(&output));
    if (fail) {
        fprintf(stderr, "%s", ds_cstr(&err));
    }

    smap_destroy(&config);
    destroy_ipam_info(&info);
    ds_destroy(&output);
    ds_destroy(&err);
}

static void
test_ipam_init_ipv4(struct ovs_cmdl_context *ctx)
{
    const char *subnet = ctx->argv[1];
    const char *exclude_ips = ctx->argc > 2 ? ctx->argv[2] : NULL;
    struct smap config = SMAP_INITIALIZER(&config);
    smap_add(&config, "subnet", subnet);
    if (exclude_ips) {
        smap_add(&config, "exclude_ips", exclude_ips);
    }
    struct ipam_info ipam;
    init_ipam_info(&ipam, &config, "IPv4 test");

    struct ds output = DS_EMPTY_INITIALIZER;
    ds_put_format(&output, "start_ipv4: " IP_FMT "\n",
                  IP_ARGS(htonl(ipam.start_ipv4)));
    ds_put_format(&output, "total_ipv4s: %" PRIuSIZE "\n", ipam.total_ipv4s);

    ds_put_cstr(&output, "allocated_ipv4s: ");
    if (ipam.allocated_ipv4s) {
        int start = 0;
        int end = ipam.total_ipv4s;
        for (size_t bit = bitmap_scan(ipam.allocated_ipv4s, true, start, end);
             bit != end;
             bit = bitmap_scan(ipam.allocated_ipv4s, true, bit + 1, end)) {
            ds_put_format(&output, IP_FMT " ",
                          IP_ARGS((htonl(ipam.start_ipv4 + bit))));
        }
    }
    ds_chomp(&output, ' ');
    ds_put_char(&output, '\n');

    printf("%s", ds_cstr(&output));

    destroy_ipam_info(&ipam);
    ds_destroy(&output);
    smap_destroy(&config);
}

static void
test_ipam_init_ipv6_prefix(struct ovs_cmdl_context *ctx)
{
    const char *prefix = ctx->argc > 1 ? ctx->argv[1] : NULL;
    struct smap config = SMAP_INITIALIZER(&config);
    if (prefix) {
        smap_add(&config, "ipv6_prefix", prefix);
    };
    struct ipam_info ipam;
    init_ipam_info(&ipam, &config, "IPv6 test");

    struct ds output = DS_EMPTY_INITIALIZER;
    ds_put_format(&output, "ipv6_prefix_set: %s\n",
                  ipam.ipv6_prefix_set ? "true" : "false");
    if (ipam.ipv6_prefix_set) {
        char ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ipam.ipv6_prefix,
                  ipv6, sizeof ipv6);
        ds_put_format(&output, "ipv6_prefix: %s\n", ipv6);
    }

    printf("%s", ds_cstr(&output));

    destroy_ipam_info(&ipam);
    ds_destroy(&output);
    smap_destroy(&config);
}

static void
test_ipam_main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    static const struct ovs_cmdl_command commands[] = {
        {"ipam_get_unused_ip", NULL, 2, 3, test_ipam_get_unused_ip, OVS_RO},
        {"ipam_init_ipv6_prefix", NULL, 0, 1, test_ipam_init_ipv6_prefix,
            OVS_RO},
        {"ipam_init_ipv4", NULL, 1, 2, test_ipam_init_ipv4,
            OVS_RO},
        {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - 1;
    ctx.argv = argv + 1;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-ipam", test_ipam_main);
