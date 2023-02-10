/*
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
#include <stdlib.h>
#include <stdio.h>

#include "openvswitch/util.h"

#include "en-northd-output.h"
#include "lib/inc-proc-eng.h"

void *
en_northd_output_init(struct engine_node *node OVS_UNUSED,
                      struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_northd_output_run(struct engine_node *node, void *data OVS_UNUSED)
{
    engine_set_node_state(node, EN_UPDATED);
}

void
en_northd_output_cleanup(void *data OVS_UNUSED)
{

}

bool
northd_output_sync_to_sb_handler(struct engine_node *node,
                                 void *data OVS_UNUSED)
{
    engine_set_node_state(node, EN_UPDATED);
    return true;
}

bool
northd_output_lflow_handler(struct engine_node *node, void *data OVS_UNUSED)
{
    engine_set_node_state(node, EN_UPDATED);
    return true;
}

bool
northd_output_mac_binding_aging_handler(struct engine_node *node,
                                        void *data OVS_UNUSED)
{
    engine_set_node_state(node, EN_UPDATED);
    return true;
}
