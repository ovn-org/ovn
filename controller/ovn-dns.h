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

#ifndef OVN_DNS_H
#define OVN_DNS_H

struct shash;
struct sbrec_dns_table;

void ovn_dns_cache_init(void);
void ovn_dns_cache_destroy(void);
void ovn_dns_sync_cache(const struct sbrec_dns_table *);
void ovn_dns_update_cache(const struct sbrec_dns_table *);
const char *ovn_dns_lookup(const char *query_name, uint64_t dp_key,
                           bool *ovn_owned);

#endif /* OVN_DNS_H */
