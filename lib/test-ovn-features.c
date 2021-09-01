/* Copyright (c) 2021, Red Hat, Inc.
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

#include "ovn/features.h"
#include "tests/ovstest.h"

static void
test_ovn_features(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    ovs_assert(!ovs_feature_is_supported(OVS_CT_ZERO_SNAT_SUPPORT));

    struct smap features = SMAP_INITIALIZER(&features);

    smap_add(&features, "ct_zero_snat", "false");
    ovs_assert(!ovs_feature_support_update(&features));
    ovs_assert(!ovs_feature_is_supported(OVS_CT_ZERO_SNAT_SUPPORT));

    smap_replace(&features, "ct_zero_snat", "true");
    ovs_assert(ovs_feature_support_update(&features));
    ovs_assert(ovs_feature_is_supported(OVS_CT_ZERO_SNAT_SUPPORT));

    smap_add(&features, "unknown_feature", "true");
    ovs_assert(!ovs_feature_support_update(&features));

    smap_destroy(&features);
}

static void
test_ovn_features_main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    static const struct ovs_cmdl_command commands[] = {
        {"run", NULL, 0, 0, test_ovn_features, OVS_RO},
        {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - 1;
    ctx.argv = argv + 1;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-ovn-features", test_ovn_features_main);
