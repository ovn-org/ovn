/* Copyright (c) 2021, Canonical
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

#include "vif-plug.h"
#include "vif-plug-provider.h"
#include "smap.h"
#include "sset.h"
#include "tests/ovstest.h"

static void
test_vif_plug(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    const struct vif_plug_class *vif_plug_class;

    ovs_assert(vif_plug_provider_unregister("dummy") == EINVAL);

    ovs_assert(!vif_plug_provider_register(&vif_plug_dummy_class));
    vif_plug_class = vif_plug_provider_get("dummy");
    ovs_assert(vif_plug_provider_register(&vif_plug_dummy_class) == EEXIST);

    ovs_assert(
        sset_contains(
            vif_plug_get_maintained_iface_options(vif_plug_class),
            "plug-dummy-option"));

    struct vif_plug_port_ctx_in ctx_in = {
        .op_type = PLUG_OP_CREATE,
        .lport_name = "lsp1",
        .lport_options = SMAP_INITIALIZER(&ctx_in.lport_options),
    };
    struct vif_plug_port_ctx_out ctx_out;
    vif_plug_port_prepare(vif_plug_class, &ctx_in, &ctx_out);
    ovs_assert(!strcmp(ctx_out.name, "lsp1"));
    ovs_assert(!strcmp(ctx_out.type, "internal"));
    ovs_assert(!strcmp(smap_get(
            &ctx_out.iface_options, "vif-plug-dummy-option"), "value"));

    vif_plug_port_finish(vif_plug_class, &ctx_in, &ctx_out);
    vif_plug_port_ctx_destroy(vif_plug_class, &ctx_in, &ctx_out);
    vif_plug_provider_destroy_all();
}

static void
test_vif_plug_main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    static const struct ovs_cmdl_command commands[] = {
        {"run", NULL, 0, 0, test_vif_plug, OVS_RO},
        {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - 1;
    ctx.argv = argv + 1;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-vif-plug", test_vif_plug_main);
