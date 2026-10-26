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

#ifndef OFCTRL_WAIT_BEFORE_CLEAR_H
#define OFCTRL_WAIT_BEFORE_CLEAR_H 1

#include <stdbool.h>

/* Pure decision logic for ofctrl.c's S_WAIT_BEFORE_CLEAR state, split out
 * into its own dependency-free module (no OVSDB IDL / vconn includes) so it
 * can be unit tested directly via ovstest, the same way ofctrl-seqno.c is -
 * ofctrl.c itself pulls in too much to link into the ovstest binary. */
enum ofctrl_wait_before_clear_reason {
    /* Keep waiting: wait_time hasn't elapsed and flows aren't ready yet. */
    OFCTRL_WBC_STILL_WAITING,
    /* ovn-ofctrl-wait-before-clear is configured as 0 ms: never wait. */
    OFCTRL_WBC_DISABLED,
    /* The configured wait_time has elapsed. */
    OFCTRL_WBC_EXPIRED,
    /* The engine produced a complete flow table before wait_time elapsed. */
    OFCTRL_WBC_FLOWS_READY,
};

enum ofctrl_wait_before_clear_reason ofctrl_wait_before_clear_decide(
    bool initial_flows_ready, unsigned int wait_time,
    long long int expire, long long int now);

/* Whether the engine's current output is a complete flow table that
 * S_WAIT_BEFORE_CLEAR may hand to the switch in place of the existing one -
 * the one input to ofctrl_set_initial_flows_ready().
 *
 * The four *_output flags are "that engine node has produced data". The two
 * seqnos are the southbound IDL's condition seqno as acked at the start of
 * the current ovn-controller main-loop iteration, and the one this chassis
 * most recently requested (update_sb_monitors() can bump the latter earlier
 * in the same iteration, e.g. a newly-bound local port needing rows it wasn't
 * monitoring before). Non-null outputs alone are not enough: they were
 * computed against the acked view, so with the seqnos unequal they can be a
 * real, internally-consistent table that is nonetheless missing rows the
 * switch needs. Only once both match has the IDL acked the condition this
 * chassis actually ended up requesting and the engine reprocessed against
 * it. */
bool ofctrl_initial_flows_ready(bool lflow_output, bool pflow_output,
                                bool ct_zones, bool lb,
                                unsigned int sb_cond_seqno,
                                unsigned int sb_expected_cond_seqno);

#endif /* controller/ofctrl-wait-before-clear.h */
