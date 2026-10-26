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

#include "ofctrl-wait-before-clear.h"

enum ofctrl_wait_before_clear_reason
ofctrl_wait_before_clear_decide(bool initial_flows_ready,
                                 unsigned int wait_time,
                                 long long int expire, long long int now)
{
    if (!wait_time) {
        return OFCTRL_WBC_DISABLED;
    }
    if (expire && now >= expire) {
        return OFCTRL_WBC_EXPIRED;
    }
    if (initial_flows_ready) {
        return OFCTRL_WBC_FLOWS_READY;
    }
    return OFCTRL_WBC_STILL_WAITING;
}

bool
ofctrl_initial_flows_ready(bool lflow_output, bool pflow_output,
                           bool ct_zones, bool lb,
                           unsigned int sb_cond_seqno,
                           unsigned int sb_expected_cond_seqno)
{
    return lflow_output && pflow_output && ct_zones && lb
           && sb_cond_seqno == sb_expected_cond_seqno;
}
