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
#include "lib/cmap.h"
#include "openvswitch/vlog.h"

/* OVN includes. */
#include "lib/ovn-sb-idl.h"
#include "ovn-dns.h"

VLOG_DEFINE_THIS_MODULE(ovndns);

/* Internal DNS cache entry for each SB DNS record. */
struct dns_data {
    struct cmap_node cmap_node;
    struct uuid uuid;
    uint64_t *dps;
    size_t n_dps;
    struct smap records;
    struct smap options;
    bool delete;
};

/* shash of 'struct dns_data'. */
static struct cmap dns_cache_;

static void update_cache_with_dns_rec(const struct sbrec_dns *,
                                      struct dns_data *,
                                      const struct uuid *uuid,
                                      struct cmap *dns_cache);
static struct dns_data *dns_data_find(const struct uuid *uuid,
                                      const struct cmap *);
static struct dns_data *dns_data_alloc(struct uuid uuid);
static void dns_data_destroy(struct dns_data *dns_data);
static void destroy_dns_cache(struct cmap *dns_cache);

void
ovn_dns_cache_init(void)
{
    cmap_init(&dns_cache_);
}

void
ovn_dns_cache_destroy(void)
{
    destroy_dns_cache(&dns_cache_);
    cmap_destroy(&dns_cache_);
}

void
ovn_dns_sync_cache(const struct sbrec_dns_table *dns_table)
{
    const struct sbrec_dns *sbrec_dns;
    struct dns_data *existing;

    CMAP_FOR_EACH (existing, cmap_node, &dns_cache_) {
        existing->delete = true;
    }

    SBREC_DNS_TABLE_FOR_EACH (sbrec_dns, dns_table) {
        const struct uuid *uuid = &sbrec_dns->header_.uuid;
        existing = dns_data_find(uuid, &dns_cache_);
        update_cache_with_dns_rec(sbrec_dns, existing, uuid,
                                  &dns_cache_);
    }

    CMAP_FOR_EACH (existing, cmap_node, &dns_cache_) {
        if (existing->delete) {
            cmap_remove(&dns_cache_, &existing->cmap_node,
                        uuid_hash(&existing->uuid));
            ovsrcu_postpone(dns_data_destroy, existing);
        }
    }
}

void
ovn_dns_update_cache(const struct sbrec_dns_table *dns_table)
{
    const struct sbrec_dns *sbrec_dns;
    struct dns_data *existing;

    SBREC_DNS_TABLE_FOR_EACH_TRACKED (sbrec_dns, dns_table) {
        const struct uuid *uuid = &sbrec_dns->header_.uuid;

        existing = dns_data_find(uuid, &dns_cache_);
        if (sbrec_dns_is_deleted(sbrec_dns) && existing) {
            cmap_remove(&dns_cache_, &existing->cmap_node,
                        uuid_hash(&existing->uuid));
            ovsrcu_postpone(dns_data_destroy, existing);
        } else {
            update_cache_with_dns_rec(sbrec_dns, existing, uuid,
                                      &dns_cache_);
        }
    }
}

const char *
ovn_dns_lookup(const char *query_name, uint64_t dp_key, bool *ovn_owned)
{
    const char *answer_data = NULL;
    struct dns_data *dns_data;

    *ovn_owned = false;

    CMAP_FOR_EACH (dns_data, cmap_node, &dns_cache_) {
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

    return answer_data;
}


/* Static functions. */
static void
update_cache_with_dns_rec(const struct sbrec_dns *sbrec_dns,
                          struct dns_data *existing,
                          const struct uuid *uuid,
                          struct cmap *dns_cache)
{
    struct dns_data *dns_data = dns_data_alloc(*uuid);
    smap_clone(&dns_data->records, &sbrec_dns->records);
    smap_clone(&dns_data->options, &sbrec_dns->options);

    dns_data->n_dps = sbrec_dns->n_datapaths;
    dns_data->dps = xcalloc(dns_data->n_dps, sizeof(uint64_t));
    for (size_t i = 0; i < sbrec_dns->n_datapaths; i++) {
        dns_data->dps[i] = sbrec_dns->datapaths[i]->tunnel_key;
    }

    if (!existing) {
        cmap_insert(dns_cache, &dns_data->cmap_node, uuid_hash(uuid));
    } else {
        cmap_replace(dns_cache, &existing->cmap_node, &dns_data->cmap_node,
                     uuid_hash(uuid));
        ovsrcu_postpone(dns_data_destroy, existing);
    }
}

static struct dns_data *
dns_data_find(const struct uuid *uuid, const struct cmap *dns_cache)
{
    struct dns_data *dns_data;
    size_t hash = uuid_hash(uuid);
    CMAP_FOR_EACH_WITH_HASH (dns_data, cmap_node, hash, dns_cache) {
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

static void
destroy_dns_cache(struct cmap *dns_cache)
{
    struct dns_data *dns_data;
    CMAP_FOR_EACH (dns_data, cmap_node, dns_cache) {
        ovsrcu_postpone(dns_data_destroy, dns_data);
    }
}
