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

#ifndef OVN_ECMP_NEXT_HOP_MONITOR_H
#define OVN_ECMP_NEXT_HOP_MONITOR_H

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "lib/inc-proc-eng.h"

void en_ecmp_nexthop_run(struct engine_node *, void *data);
void *en_ecmp_nexthop_init(struct engine_node *, struct engine_arg *);
void en_ecmp_nexthop_cleanup(void *data);
#endif /* OVN_ECMP_NEXT_HOP_MONITOR_H */
