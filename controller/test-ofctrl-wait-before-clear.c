/* Copyright (c) 2026 Platform9 Systems Inc.
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
#include "tests/test-utils.h"
#include "ofctrl-wait-before-clear.h"
#include "util.h"

static const char *
reason_to_string(enum ofctrl_wait_before_clear_reason reason)
{
    switch (reason) {
    case OFCTRL_WBC_STILL_WAITING:
        return "still-waiting";
    case OFCTRL_WBC_DISABLED:
        return "disabled";
    case OFCTRL_WBC_EXPIRED:
        return "expired";
    case OFCTRL_WBC_FLOWS_READY:
        return "flows-ready";
    }
    OVS_NOT_REACHED();
}

/* Args: <initial_flows_ready> <wait_time> <expire> <now>
 * initial_flows_ready is "true" or "false"; the rest are integers. */
static void
test_ofctrl_wait_before_clear_decide(struct ovs_cmdl_context *ctx)
{
    bool initial_flows_ready = !strcmp(ctx->argv[1], "true");
    unsigned int wait_time;
    long long int expire;
    long long int now;

    if (!test_read_uint_value(ctx, 2, "wait_time", &wait_time)) {
        return;
    }
    if (!str_to_llong(ctx->argv[3], 10, &expire)) {
        ovs_fatal(0, "invalid expire value \"%s\"", ctx->argv[3]);
    }
    if (!str_to_llong(ctx->argv[4], 10, &now)) {
        ovs_fatal(0, "invalid now value \"%s\"", ctx->argv[4]);
    }

    enum ofctrl_wait_before_clear_reason reason =
        ofctrl_wait_before_clear_decide(initial_flows_ready, wait_time,
                                         expire, now);
    printf("%s\n", reason_to_string(reason));
}

/* Args: <lflow_output> <pflow_output> <ct_zones> <lb>
 *       <sb_cond_seqno> <sb_expected_cond_seqno>
 * The first four are "true" or "false"; the seqnos are unsigned integers. */
static void
test_ofctrl_initial_flows_ready(struct ovs_cmdl_context *ctx)
{
    bool lflow_output = !strcmp(ctx->argv[1], "true");
    bool pflow_output = !strcmp(ctx->argv[2], "true");
    bool ct_zones = !strcmp(ctx->argv[3], "true");
    bool lb = !strcmp(ctx->argv[4], "true");
    unsigned int sb_cond_seqno;
    unsigned int sb_expected_cond_seqno;

    if (!test_read_uint_value(ctx, 5, "sb_cond_seqno", &sb_cond_seqno)) {
        return;
    }
    if (!test_read_uint_value(ctx, 6, "sb_expected_cond_seqno",
                              &sb_expected_cond_seqno)) {
        return;
    }

    printf("%s\n",
           ofctrl_initial_flows_ready(lflow_output, pflow_output, ct_zones,
                                      lb, sb_cond_seqno,
                                      sb_expected_cond_seqno)
           ? "ready" : "not-ready");
}

static void
test_ofctrl_wait_before_clear_main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    static const struct ovs_cmdl_command commands[] = {
        {"ofctrl_wait_before_clear_decide", NULL, 4, 4,
         test_ofctrl_wait_before_clear_decide, OVS_RO},
        {"ofctrl_initial_flows_ready", NULL, 6, 6,
         test_ofctrl_initial_flows_ready, OVS_RO},
        {NULL, NULL, 0, 0, NULL, OVS_RO},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - 1;
    ctx.argv = argv + 1;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-ofctrl-wait-before-clear",
                  test_ofctrl_wait_before_clear_main);
