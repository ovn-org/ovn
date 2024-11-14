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
    struct hmap_node hmap_node;
    struct uuid uuid;
    uint64_t *dps;
    size_t n_dps;
    struct smap records;
    struct smap options;
    bool delete;
};

/* shash of 'struct dns_data'. */
static struct hmap dns_cache_ = HMAP_INITIALIZER(&dns_cache_);

/* Mutex to protect dns_cache_. */
static struct ovs_mutex dns_cache_mutex = OVS_MUTEX_INITIALIZER;

static void update_cache_with_dns_rec(const struct sbrec_dns *,
                                      struct dns_data *,
                                      const struct uuid *uuid,
                                      struct hmap *dns_cache);
static struct dns_data *dns_data_find(const struct uuid *uuid);
static struct dns_data *dns_data_alloc(struct uuid uuid);
static void dns_data_destroy(struct dns_data *dns_data);

void
ovn_dns_cache_init(void)
{
}

void
ovn_dns_cache_destroy(void)
{
    ovs_mutex_lock(&dns_cache_mutex);
    struct dns_data *dns_data;
    HMAP_FOR_EACH_POP (dns_data, hmap_node, &dns_cache_) {
        dns_data_destroy(dns_data);
    }
    hmap_destroy(&dns_cache_);
    ovs_mutex_unlock(&dns_cache_mutex);
}

void
ovn_dns_sync_cache(const struct sbrec_dns_table *dns_table)
{
    ovs_mutex_lock(&dns_cache_mutex);
    struct dns_data *dns_data;
    HMAP_FOR_EACH (dns_data, hmap_node, &dns_cache_) {
        dns_data->delete = true;
    }

    const struct sbrec_dns *sbrec_dns;
    SBREC_DNS_TABLE_FOR_EACH (sbrec_dns, dns_table) {
        const struct uuid *uuid = &sbrec_dns->header_.uuid;
        dns_data = dns_data_find(uuid);
        if (!dns_data) {
            dns_data = dns_data_alloc(*uuid);
            hmap_insert(&dns_cache_, &dns_data->hmap_node, uuid_hash(uuid));
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

    HMAP_FOR_EACH_SAFE (dns_data, hmap_node, &dns_cache_) {
        if (dns_data->delete) {
            hmap_remove(&dns_cache_, &dns_data->hmap_node);
            dns_data_destroy(dns_data);
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
        const struct uuid *uuid = &sbrec_dns->header_.uuid;
        struct dns_data *dns_data = dns_data_find(uuid);

        if (sbrec_dns_is_deleted(sbrec_dns) && dns_data) {
            hmap_remove(&dns_cache_, &dns_data->hmap_node);
            dns_data_destroy(dns_data);
        } else {
            update_cache_with_dns_rec(sbrec_dns, dns_data, uuid, &dns_cache_);
        }
    }

    ovs_mutex_unlock(&dns_cache_mutex);
}

const char *
ovn_dns_lookup(const char *query_name, uint64_t dp_key, bool *ovn_owned)
{
    ovs_mutex_lock(&dns_cache_mutex);

    *ovn_owned = false;
    struct dns_data *dns_data;
    const char *answer_data = NULL;
    HMAP_FOR_EACH (dns_data, hmap_node, &dns_cache_) {
        for (size_t i = 0; i < dns_data->n_dps; i++) {
            if (dns_data->dps[i] == dp_key) {
                /* DNS records in SBDB are stored in lowercase. Convert to
                 * lowercase to perform case insensitive lookup
                 */
                char *query_name_lower = str_tolower(query_name);
                answer_data = smap_get(&dns_data->records, query_name_lower);
                free(query_name_lower);
                if (answer_data) {
                    *ovn_owned = smap_get_bool(&dns_data->options, "ovn-owned",
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
                          const struct uuid *uuid,
                          struct hmap *dns_cache)
{
    if (!dns_data) {
        dns_data = dns_data_alloc(*uuid);
        hmap_insert(dns_cache, &dns_data->hmap_node, uuid_hash(uuid));
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

static struct dns_data *
dns_data_find(const struct uuid *uuid)
{
    struct dns_data *dns_data;
    size_t hash = uuid_hash(uuid);
    HMAP_FOR_EACH_WITH_HASH (dns_data, hmap_node, hash, &dns_cache_) {
        if (uuid_equals(&dns_data->uuid, uuid)) {
            return dns_data;
        }
    }
    return NULL;
}

static struct dns_data *
dns_data_alloc(struct uuid uuid)
{
    struct dns_data *dns_data = xmalloc(sizeof *dns_data);
    *dns_data = (struct dns_data) {
        .uuid = uuid,
        .dps = NULL,
        .n_dps = 0,
        .records = SMAP_INITIALIZER(&dns_data->records),
        .options = SMAP_INITIALIZER(&dns_data->options),
    };

    return dns_data;
}

static void
dns_data_destroy(struct dns_data *dns_data)
{
    smap_destroy(&dns_data->records);
    smap_destroy(&dns_data->options);
    free(dns_data->dps);
    free(dns_data);
}
