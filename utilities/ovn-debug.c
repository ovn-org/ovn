/* Copyright (c) 2024, Red Hat, Inc.
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
#include <getopt.h>
#include <stdint.h>

#include "command-line.h"
#include "controller/lflow.h"
#include "northd/northd.h"
#include "ovn-util.h"

struct ovn_lflow_stage {
    const char *name;
    uint8_t table_id;
    enum ovn_pipeline pipeline;
};

static const struct ovn_lflow_stage ovn_lflow_stages[] = {
#define PIPELINE_STAGE(DP_TYPE, PIPELINE, STAGE, TABLE, NAME)       \
        (struct ovn_lflow_stage) {                                  \
            .name = NAME,                                           \
            .table_id = TABLE,                                      \
            .pipeline = P_##PIPELINE,                               \
        },
        PIPELINE_STAGES
#undef PIPELINE_STAGE
};

static const struct ovn_lflow_stage *
ovn_lflow_stage_find_by_name(const char *name)
{

    for (size_t i = 0; i < ARRAY_SIZE(ovn_lflow_stages); i++) {
        const struct ovn_lflow_stage *stage = &ovn_lflow_stages[i];
        if (!strcmp(stage->name, name)) {
            return stage;
        }
    }

    return NULL;
}

static void
lflow_stage_to_table(struct ovs_cmdl_context *ctx)
{
    const char *name = ctx->argv[1];
    const struct ovn_lflow_stage *stage = ovn_lflow_stage_find_by_name(name);

    if (!stage) {
        ovs_fatal(0, "Couldn't find OVN logical flow stage with name \"%s\"",
                  name);
    }

    uint8_t table = stage->table_id;

    if (!strcmp("lflow-stage-to-oftable", ctx->argv[0])) {
        table += stage->pipeline == P_IN
                 ? OFTABLE_LOG_INGRESS_PIPELINE
                 : OFTABLE_LOG_EGRESS_PIPELINE;
    }

    printf("%"PRIu8"\n", table);
    exit(EXIT_SUCCESS);
}


static void
usage(void)
{
    printf("\
%s: OVN debug utility\n\
usage: %s COMMAND [ARG...]\n\
\n\
lflow-stage-to-ltable STAGE_NAME\n\
  Converts STAGE_NAME into logical flow table number.\n\
lflow-stage-to-oftable STAGE_NAME\n\
  Converts STAGE_NAME into OpenFlow table number.\n\
\n\
Options:\n\
  -h, --help                  display this help message\n\
  -V, --version               display version information\n",
    program_name, program_name);
    exit(EXIT_SUCCESS);
}

static void
help(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    usage();
}

int
main(int argc, char *argv[])
{
    static const struct option long_options[] = {
            {"help", no_argument, NULL, 'h'},
            {"version", no_argument, NULL, 'V'},
            {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    ovn_set_program_name(argv[0]);

    for (;;) {
        int option_index = 0;
        int c = getopt_long(argc, argv, short_options, long_options,
                            &option_index);

        if (c == -1) {
            break;
        }
        switch (c) {
        case 'V':
            ovn_print_version(0, 0);
            exit(EXIT_SUCCESS);

        case 'h':
            usage();
            /* fall through */

        case '?':
            exit(1);

        default:
            ovs_abort(0, "Invalid option.");
        }
    }
    free(short_options);

    static const struct ovs_cmdl_command commands[] = {
            {"lflow-stage-to-oftable", NULL, 1, 1, lflow_stage_to_table,
             OVS_RO},
            {"lflow-stage-to-ltable", NULL, 1, 1, lflow_stage_to_table,
             OVS_RO},
            { "help", NULL, 0, INT_MAX, help, OVS_RO },
            {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;
    ovs_cmdl_run_command(&ctx, commands);
}
