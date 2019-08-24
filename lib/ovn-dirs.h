/*
 * Copyright (c) 2019.
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

#ifndef OVN_DIRS_H
#define OVN_DIRS_H 1

#ifdef  __cplusplus
extern "C" {
#endif

const char *ovn_sysconfdir(void); /* /usr/local/etc */
const char *ovn_pkgdatadir(void); /* /usr/local/share/ovn */
const char *ovn_rundir(void);     /* /usr/local/var/run/ovn */
const char *ovn_logdir(void);     /* /usr/local/var/log/ovn */
const char *ovn_dbdir(void);      /* /usr/local/etc/ovn */
const char *ovn_bindir(void);     /* /usr/local/bin */

#ifdef  __cplusplus
}
#endif

#endif /* OVN_DIRS_H */
