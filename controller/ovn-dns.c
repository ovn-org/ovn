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

/* OVS includes */
#include "include/openvswitch/shash.h"
#include "include/openvswitch/thread.h"
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "lib/ovn-sb-idl.h"
#include "ovn-dns.h"

VLOG_DEFINE_THIS_MODULE(ovndns);

/* Internal DNS cache entry for each SB DNS record. */
struct dns_data {
    uint64_t *dps;
    size_t n_dps;
    struct smap records;
    struct smap options;
    bool delete;
};

/* shash of 'struct dns_data'. */
static struct shash dns_cache_ = SHASH_INITIALIZER(&dns_cache_);

/* Mutex to protect dns_cache_. */
static struct ovs_mutex dns_cache_mutex = OVS_MUTEX_INITIALIZER;

static void update_cache_with_dns_rec(const struct sbrec_dns *,
                                      struct dns_data *,
                                      const char *dns_id,
                                      struct shash *dns_cache);
void
ovn_dns_cache_init(void)
{
}

void
ovn_dns_cache_destroy(void)
{
    ovs_mutex_lock(&dns_cache_mutex);
    struct shash_node *iter;
    SHASH_FOR_EACH_SAFE (iter, &dns_cache_) {
        struct dns_data *d = iter->data;
        shash_delete(&dns_cache_, iter);
        smap_destroy(&d->records);
        smap_destroy(&d->options);
        free(d->dps);
        free(d);
    }
    shash_destroy(&dns_cache_);
    ovs_mutex_unlock(&dns_cache_mutex);
}

void
ovn_dns_sync_cache(const struct sbrec_dns_table *dns_table)
{
    ovs_mutex_lock(&dns_cache_mutex);
    struct shash_node *iter;
    SHASH_FOR_EACH (iter, &dns_cache_) {
        struct dns_data *d = iter->data;
        d->delete = true;
    }

    const struct sbrec_dns *sbrec_dns;
    SBREC_DNS_TABLE_FOR_EACH (sbrec_dns, dns_table) {
        const char *dns_id = smap_get(&sbrec_dns->external_ids, "dns_id");
        if (!dns_id) {
            continue;
        }

        struct dns_data *dns_data = shash_find_data(&dns_cache_, dns_id);
        if (!dns_data) {
            dns_data = xmalloc(sizeof *dns_data);
            smap_init(&dns_data->records);
            smap_init(&dns_data->options);
            shash_add(&dns_cache_, dns_id, dns_data);
            dns_data->n_dps = 0;
            dns_data->dps = NULL;
        } else {
            free(dns_data->dps);
        }

        dns_data->delete = false;

        if (!smap_equal(&dns_data->records, &sbrec_dns->records)) {
            smap_destroy(&dns_data->records);
            smap_clone(&dns_data->records, &sbrec_dns->records);
        }

        if (!smap_equal(&dns_data->options, &sbrec_dns->options)) {
            smap_destroy(&dns_data->options);
            smap_clone(&dns_data->options, &sbrec_dns->options);
        }

        dns_data->n_dps = sbrec_dns->n_datapaths;
        dns_data->dps = xcalloc(dns_data->n_dps, sizeof(uint64_t));
        for (size_t i = 0; i < sbrec_dns->n_datapaths; i++) {
            dns_data->dps[i] = sbrec_dns->datapaths[i]->tunnel_key;
        }
    }

    SHASH_FOR_EACH_SAFE (iter, &dns_cache_) {
        struct dns_data *d = iter->data;
        if (d->delete) {
            shash_delete(&dns_cache_, iter);
            smap_destroy(&d->records);
            smap_destroy(&d->options);
            free(d->dps);
            free(d);
        }
    }
    ovs_mutex_unlock(&dns_cache_mutex);
}

void
ovn_dns_update_cache(const struct sbrec_dns_table *dns_table)
{
    ovs_mutex_lock(&dns_cache_mutex);

    const struct sbrec_dns *sbrec_dns;
    SBREC_DNS_TABLE_FOR_EACH_TRACKED (sbrec_dns, dns_table) {
        const char *dns_id = smap_get(&sbrec_dns->external_ids, "dns_id");
        if (!dns_id) {
            continue;
        }

        struct shash_node *shash_node = shash_find(&dns_cache_, dns_id);
        if (sbrec_dns_is_deleted(sbrec_dns)) {
            if (shash_node) {
                struct dns_data *dns_data = shash_node->data;
                shash_delete(&dns_cache_, shash_node);
                smap_destroy(&dns_data->records);
                smap_destroy(&dns_data->options);
                free(dns_data->dps);
                free(dns_data);
            }
        } else {
            update_cache_with_dns_rec(sbrec_dns,
                                      shash_node ? shash_node->data : NULL,
                                      dns_id, &dns_cache_);
        }
    }

    ovs_mutex_unlock(&dns_cache_mutex);
}

const char *
ovn_dns_lookup(const char *query_name, uint64_t dp_key, bool *ovn_owned)
{
    ovs_mutex_lock(&dns_cache_mutex);

    *ovn_owned = false;
    struct shash_node *iter;
    const char *answer_data = NULL;
    SHASH_FOR_EACH (iter, &dns_cache_) {
        struct dns_data *d = iter->data;
            for (size_t i = 0; i < d->n_dps; i++) {
            if (d->dps[i] == dp_key) {
                /* DNS records in SBDB are stored in lowercase. Convert to
                 * lowercase to perform case insensitive lookup
                 */
                char *query_name_lower = str_tolower(query_name);
                answer_data = smap_get(&d->records, query_name_lower);
                free(query_name_lower);
                if (answer_data) {
                    *ovn_owned = smap_get_bool(&d->options, "ovn-owned",
                                               false);
                    break;
                }
            }
        }

        if (answer_data) {
            break;
        }
    }

    ovs_mutex_unlock(&dns_cache_mutex);

    return answer_data;
}


/* Static functions. */
static void
update_cache_with_dns_rec(const struct sbrec_dns *sbrec_dns,
                          struct dns_data *dns_data,
                          const char *dns_id,
                          struct shash *dns_cache)
{
    if (!dns_data) {
        dns_data = xmalloc(sizeof *dns_data);
        smap_init(&dns_data->records);
        smap_init(&dns_data->options);
        shash_add(dns_cache, dns_id, dns_data);
        dns_data->n_dps = 0;
        dns_data->dps = NULL;
    } else {
        free(dns_data->dps);
    }

    if (!smap_equal(&dns_data->records, &sbrec_dns->records)) {
        smap_destroy(&dns_data->records);
        smap_clone(&dns_data->records, &sbrec_dns->records);
    }

    if (!smap_equal(&dns_data->options, &sbrec_dns->options)) {
        smap_destroy(&dns_data->options);
        smap_clone(&dns_data->options, &sbrec_dns->options);
    }

    dns_data->n_dps = sbrec_dns->n_datapaths;
    dns_data->dps = xcalloc(dns_data->n_dps, sizeof(uint64_t));
    for (size_t i = 0; i < sbrec_dns->n_datapaths; i++) {
        dns_data->dps[i] = sbrec_dns->datapaths[i]->tunnel_key;
    }
}
