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

#ifndef BR_OFCTRL_H
#define BR_OFCTRL_H 1

struct ovn_bridge;
struct shash;

void br_ofctrls_init(void);
bool br_ofctrls_run(void);
void br_ofctrls_put(uint64_t req_cfg, bool lflows_changed,
                    bool pflows_changed);
void br_ofctrls_destroy(void);
void br_ofctrls_wait(void);

void br_ofctrls_add_or_update_bridge(struct ovn_bridge *);
void br_ofctrls_remove_bridge(const char *);
uint64_t br_ofctrl_get_cur_cfg(void);
void br_ofctrls_get_bridges(struct sset *);

#endif /* BR_OFCTRL_H */