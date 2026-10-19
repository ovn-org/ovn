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

#endif /* controller/ofctrl-wait-before-clear.h */
