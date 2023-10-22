/* Copyright (c) 2022, Red Hat, Inc.
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

#include "lib/inc-proc-eng.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/timeval.h"
#include "northd/aging.h"
#include "northd/northd.h"
#include "openvswitch/hmap.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(mac_binding_aging);

#define AGING_BULK_REMOVAL_DELAY_MSEC 5000

struct aging_waker {
    bool should_schedule;
    long long next_wake_msec;
};

static void
aging_waker_schedule_next_wake(struct aging_waker *waker, int64_t next_wake_ms)
{
    waker->should_schedule = false;

    if (next_wake_ms < INT64_MAX) {
        waker->should_schedule = true;
        waker->next_wake_msec = time_msec() + next_wake_ms;
        poll_timer_wait_until(waker->next_wake_msec);
    }
}

struct threshold_entry {
    union {
        ovs_be32 ipv4;
        struct in6_addr ipv6;
    } prefix;
    bool is_v4;
    unsigned int plen;
    unsigned int threshold;
};

/* Contains CIDR-based aging threshold configuration parsed from
 * "Logical_Router:options:mac_binding_age_threshold".
 *
 * This struct is also used for non-CIDR-based threshold, e.g. the ones from
 * "NB_Global:other_config:fdb_age_threshold" for the common aging_context
 * interface.
 *
 * - The arrays `v4_entries` and `v6_entries` are populated with parsed entries
 *   for IPv4 and IPv6 CIDRs, respectively, along with their associated
 *   thresholds.  Entries within these arrays are sorted by prefix length,
 *   starting with the longest.
 *
 * - If a threshold is provided without an accompanying prefix, it's captured
 *   in `default_threshold`.  In cases with multiple unprefixed thresholds,
 *   `default_threshold` will only store the last one.  */
struct threshold_config {
    struct threshold_entry *v4_entries;
    size_t n_v4_entries;
    struct threshold_entry *v6_entries;
    size_t n_v6_entries;
    unsigned int default_threshold;
};

static int
compare_entries_by_prefix_length(const void *a, const void *b)
{
    const struct threshold_entry *entry_a = a;
    const struct threshold_entry *entry_b = b;

    return entry_b->plen - entry_a->plen;
}

/* Parse an ENTRY in the threshold option, with the format:
 * [CIDR:]THRESHOLD
 *
 * Returns true if successful, false if failed. */
static bool
parse_threshold_entry(const char *str, struct threshold_entry *entry)
{
    char *colon_ptr;
    unsigned int value;
    const char *threshold_str;

    colon_ptr = strrchr(str, ':');
    if (!colon_ptr) {
        threshold_str = str;
        entry->plen = 0;
    } else {
        threshold_str = colon_ptr + 1;
    }

    if (!str_to_uint(threshold_str, 10, &value)) {
        return false;
    }
    entry->threshold = value;

    if (!colon_ptr) {
        return true;
    }

    /* ":" was found, so parse the string before ":" as a cidr. */
    char ip_cidr[128];
    ovs_strzcpy(ip_cidr, str, MIN(colon_ptr - str + 1, sizeof ip_cidr));
    char *error = ip_parse_cidr(ip_cidr, &entry->prefix.ipv4, &entry->plen);
    if (!error) {
        entry->is_v4 = true;
        return true;
    }
    free(error);
    error = ipv6_parse_cidr(ip_cidr, &entry->prefix.ipv6, &entry->plen);
    if (!error) {
        entry->is_v4 = false;
        return true;
    }
    free(error);
    return false;
}

static void
threshold_config_destroy(struct threshold_config *config)
{
    free(config->v4_entries);
    free(config->v6_entries);
    config->v4_entries = config->v6_entries = NULL;
    config->n_v4_entries = config->n_v6_entries = 0;
    config->default_threshold = 0;
}

/* Parse the threshold option string, which has the format:
 * ENTRY[;ENTRY[...]]
 *
 * For the exact format of ENTRY, refer to the function
 * `parse_threshold_entry`.
 *
 * The parsed data is populated to the struct threshold_config.
 * See the comments of struct threshold_config for details.
 *
 * Return Values:
 * - Returns `false` if the input does not match the expected format.
 *   Consequently, no entries will be populated.
 * - Returns `true` upon successful parsing. The caller is responsible for
 *   releasing the allocated memory by calling threshold_config_destroy. */
static bool
parse_aging_threshold(const char *opt,
                      struct threshold_config *config)
{
    if (!opt) {
        return false;
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
    struct threshold_entry e;
    char *token, *saveptr = NULL;
    char *opt_copy = xstrdup(opt);
    bool result = true;

    memset(config, 0, sizeof *config);

    for (token = strtok_r(opt_copy, ";", &saveptr); token != NULL;
         token = strtok_r(NULL, ";", &saveptr)) {
        if (!parse_threshold_entry(token, &e)) {
            VLOG_WARN_RL(&rl, "Parsing aging threshold '%s' failed.", token);
            result = false;
            goto exit;
        }

        if (!e.plen) {
            config->default_threshold = e.threshold;
        } else if (e.is_v4) {
            config->n_v4_entries++;
            config->v4_entries = xrealloc(config->v4_entries,
                                          config->n_v4_entries * sizeof e);
            config->v4_entries[config->n_v4_entries - 1] = e;
        } else {
            config->n_v6_entries++;
            config->v6_entries = xrealloc(config->v6_entries,
                                          config->n_v6_entries * sizeof e);
            config->v6_entries[config->n_v6_entries - 1] = e;
        }
    }

    if (config->n_v4_entries > 0) {
        qsort(config->v4_entries, config->n_v4_entries, sizeof e,
              compare_entries_by_prefix_length);
    }

    if (config->n_v6_entries > 0) {
        qsort(config->v6_entries, config->n_v6_entries, sizeof e,
              compare_entries_by_prefix_length);
    }

exit:
    free(opt_copy);
    if (!result) {
        threshold_config_destroy(config);
    }
    return result;
}

static unsigned int
find_threshold_for_ip(const char *ip_str,
                      const struct threshold_config *config)
{
    if (!ip_str) {
        return config->default_threshold;
    }

    ovs_be32 ipv4;
    struct in6_addr ipv6;
    if (ip_parse(ip_str, &ipv4)) {
        for (int i = 0; i < config->n_v4_entries; i++) {
            ovs_be32 masked_ip = ipv4 &
                be32_prefix_mask(config->v4_entries[i].plen);
            if (masked_ip == config->v4_entries[i].prefix.ipv4) {
                return config->v4_entries[i].threshold;
            }
        }
    } else if (ipv6_parse(ip_str, &ipv6)) {
        for (int i = 0; i < config->n_v6_entries; i++) {
            struct in6_addr v6_mask =
                ipv6_create_mask(config->v6_entries[i].plen);
            struct in6_addr masked_ip = ipv6_addr_bitand(&ipv6, &v6_mask);
            if (ipv6_addr_equals(&masked_ip,
                                 &config->v6_entries[i].prefix.ipv6)) {
                return config->v6_entries[i].threshold;
            }
        }
    }
    return config->default_threshold;
}

/* Parse the threshold option string (see the comment of the function
 * parse_aging_threshold), and returns the smallest threshold. */
unsigned int
min_mac_binding_age_threshold(const char *opt)
{
    struct threshold_config config;
    if (!parse_aging_threshold(opt, &config)) {
        return 0;
    }

    unsigned int threshold = UINT_MAX;
    unsigned int t;

    for (int i = 0; i < config.n_v4_entries; i++) {
        t = config.v4_entries[i].threshold;
        if (t && t < threshold) {
            threshold = t;
        }
    }

    for (int i = 0; i < config.n_v6_entries; i++) {
        t = config.v6_entries[i].threshold;
        if (t && t < threshold) {
            threshold = t;
        }
    }

    t = config.default_threshold;
    if (t && t < threshold) {
        threshold = t;
    }

    threshold_config_destroy(&config);

    return threshold == UINT_MAX ? 0 : threshold;
}

struct aging_context {
    int64_t next_wake_ms;
    int64_t time_wall_now;
    uint32_t removal_limit;
    uint32_t n_removed;
    struct threshold_config *threshold;
};

static struct aging_context
aging_context_init(uint32_t removal_limit)
{
    struct aging_context ctx = {
           .next_wake_ms = INT64_MAX,
           .time_wall_now = time_wall_msec(),
           .removal_limit = removal_limit,
           .n_removed = 0,
           .threshold = NULL,
    };
    return ctx;
}

static void
aging_context_set_threshold(struct aging_context *ctx,
                            struct threshold_config *threshold)
{
    ctx->threshold = threshold;
}

static bool
aging_context_is_at_limit(struct aging_context *ctx)
{
    return ctx->removal_limit && ctx->n_removed == ctx->removal_limit;
}

static bool
aging_context_handle_timestamp(struct aging_context *ctx, int64_t timestamp,
                               const char *ip)
{
    int64_t elapsed = ctx->time_wall_now - timestamp;
    if (elapsed < 0) {
        return false;
    }

    ovs_assert(ctx->threshold);
    uint64_t threshold = 1000 * find_threshold_for_ip(ip, ctx->threshold);

    if (!threshold) {
        return false;
    }

    if (elapsed >= threshold) {
        ctx->n_removed++;
        return true;
    }

    ctx->next_wake_ms = MIN(ctx->next_wake_ms, (threshold - elapsed));
    return false;
}

static uint32_t
get_removal_limit(struct engine_node *node, const char *name)
{
    const struct nbrec_nb_global_table *nb_global_table =
            EN_OVSDB_GET(engine_get_input("NB_nb_global", node));
    const struct nbrec_nb_global *nb =
            nbrec_nb_global_table_first(nb_global_table);
    if (!nb) {
        return 0;
    }

    return smap_get_uint(&nb->options, name, 0);
}

/* MAC binding aging */
static void
mac_binding_aging_run_for_datapath(const struct sbrec_datapath_binding *dp,
                                   struct ovsdb_idl_index *mb_by_datapath,
                                   struct aging_context *ctx)
{
    if (!ctx->threshold) {
        return;
    }

    if (!ctx->threshold->n_v4_entries && !ctx->threshold->n_v6_entries
        && !ctx->threshold->default_threshold) {
        return;
    }

    struct sbrec_mac_binding *mb_index_row =
        sbrec_mac_binding_index_init_row(mb_by_datapath);
    sbrec_mac_binding_index_set_datapath(mb_index_row, dp);

    const struct sbrec_mac_binding *mb;
    SBREC_MAC_BINDING_FOR_EACH_EQUAL (mb, mb_index_row, mb_by_datapath) {
        if (aging_context_handle_timestamp(ctx, mb->timestamp, mb->ip)) {
            sbrec_mac_binding_delete(mb);
            if (aging_context_is_at_limit(ctx)) {
                break;
            }
        }
    }
    sbrec_mac_binding_index_destroy_row(mb_index_row);
}

void
en_mac_binding_aging_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    struct aging_waker *waker =
        engine_get_input_data("mac_binding_aging_waker", node);

    if (!eng_ctx->ovnsb_idl_txn ||
        !northd_data->features.mac_binding_timestamp ||
        time_msec() < waker->next_wake_msec) {
        return;
    }

    uint32_t limit = get_removal_limit(node, "mac_binding_removal_limit");
    struct aging_context ctx = aging_context_init(limit);

    struct ovsdb_idl_index *sbrec_mac_binding_by_datapath =
        engine_ovsdb_node_get_index(engine_get_input("SB_mac_binding", node),
                                    "sbrec_mac_binding_by_datapath");

    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &northd_data->lr_datapaths.datapaths) {
        ovs_assert(od->nbr);

        if (!od->sb) {
            continue;
        }

        struct threshold_config threshold_config;
        if (!parse_aging_threshold(smap_get(&od->nbr->options,
                                            "mac_binding_age_threshold"),
                                   &threshold_config)) {
            return;
        }

        aging_context_set_threshold(&ctx, &threshold_config);

        mac_binding_aging_run_for_datapath(od->sb,
                                           sbrec_mac_binding_by_datapath,
                                           &ctx);
        threshold_config_destroy(&threshold_config);

        if (aging_context_is_at_limit(&ctx)) {
            /* Schedule the next run after specified delay. */
            ctx.next_wake_ms = AGING_BULK_REMOVAL_DELAY_MSEC;
            break;
        }
    }

    aging_waker_schedule_next_wake(waker, ctx.next_wake_ms);

    engine_set_node_state(node, EN_UPDATED);
}

void *
en_mac_binding_aging_init(struct engine_node *node OVS_UNUSED,
                          struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_mac_binding_aging_cleanup(void *data OVS_UNUSED)
{
}

/* The waker node is an input node, but the data about when to wake up
 * the aging node are populated by the aging node.
 * The reason being that engine periodically runs input nodes to check
 * if we there are updates, so it could process the other nodes, however
 * the waker cannot be dependent on other node because it wouldn't be
 * input node anymore. */
void
en_mac_binding_aging_waker_run(struct engine_node *node, void *data)
{
    struct aging_waker *waker = data;

    engine_set_node_state(node, EN_UNCHANGED);

    if (!waker->should_schedule) {
        return;
    }

    if (time_msec() >= waker->next_wake_msec) {
        waker->should_schedule = false;
        engine_set_node_state(node, EN_UPDATED);
        return;
    }

    poll_timer_wait_until(waker->next_wake_msec);
}

void *
en_mac_binding_aging_waker_init(struct engine_node *node OVS_UNUSED,
                                struct engine_arg *arg OVS_UNUSED)
{
    struct aging_waker *waker = xmalloc(sizeof *waker);

    waker->should_schedule = false;
    waker->next_wake_msec = 0;

    return waker;
}

void
en_mac_binding_aging_waker_cleanup(void *data OVS_UNUSED)
{
}

/* FDB aging */
static void
fdb_run_for_datapath(const struct sbrec_datapath_binding *dp,
                     struct ovsdb_idl_index *fdb_by_dp_key,
                     struct aging_context *ctx)
{
    if (!ctx->threshold) {
        return;
    }

    struct sbrec_fdb *fdb_index_row = sbrec_fdb_index_init_row(fdb_by_dp_key);
    sbrec_fdb_index_set_dp_key(fdb_index_row, dp->tunnel_key);

    const struct sbrec_fdb *fdb;
    SBREC_FDB_FOR_EACH_EQUAL (fdb, fdb_index_row, fdb_by_dp_key) {
        if (aging_context_handle_timestamp(ctx, fdb->timestamp, NULL)) {
            sbrec_fdb_delete(fdb);
            if (aging_context_is_at_limit(ctx)) {
                break;
            }
        }
    }
    sbrec_fdb_index_destroy_row(fdb_index_row);
}

void
en_fdb_aging_run(struct engine_node *node, void *data OVS_UNUSED)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct northd_data *northd_data = engine_get_input_data("northd", node);
    struct aging_waker *waker = engine_get_input_data("fdb_aging_waker", node);

    if (!eng_ctx->ovnsb_idl_txn ||
        !northd_data->features.fdb_timestamp ||
        time_msec() < waker->next_wake_msec) {
        return;
    }

    uint32_t limit = get_removal_limit(node, "fdb_removal_limit");
    struct aging_context ctx = aging_context_init(limit);

    struct ovsdb_idl_index *sbrec_fdb_by_dp_key =
            engine_ovsdb_node_get_index(engine_get_input("SB_fdb", node),
                                        "fdb_by_dp_key");

    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, &northd_data->ls_datapaths.datapaths) {
        ovs_assert(od->nbs);

        if (!od->sb) {
            continue;
        }

        struct threshold_config threshold_config;
        memset(&threshold_config, 0, sizeof threshold_config);
        threshold_config.default_threshold =
            smap_get_uint(&od->nbs->other_config, "fdb_age_threshold", 0);
        aging_context_set_threshold(&ctx, &threshold_config);
        fdb_run_for_datapath(od->sb, sbrec_fdb_by_dp_key, &ctx);

        if (aging_context_is_at_limit(&ctx)) {
            /* Schedule the next run after specified delay. */
            ctx.next_wake_ms = AGING_BULK_REMOVAL_DELAY_MSEC;
            break;
        }
    }

    aging_waker_schedule_next_wake(waker, ctx.next_wake_ms);

    engine_set_node_state(node, EN_UPDATED);
}

void *
en_fdb_aging_init(struct engine_node *node OVS_UNUSED,
                  struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void
en_fdb_aging_cleanup(void *data OVS_UNUSED)
{
}

/* The waker node is an input node, but the data about when to wake up
 * the aging node are populated by the aging node.
 * The reason being that engine periodically runs input nodes to check
 * if we there are updates, so it could process the other nodes, however
 * the waker cannot be dependent on other node because it wouldn't be
 * input node anymore. */
void
en_fdb_aging_waker_run(struct engine_node *node, void *data)
{
    struct aging_waker *waker = data;

    engine_set_node_state(node, EN_UNCHANGED);

    if (!waker->should_schedule) {
        return;
    }

    if (time_msec() >= waker->next_wake_msec) {
        waker->should_schedule = false;
        engine_set_node_state(node, EN_UPDATED);
        return;
    }

    poll_timer_wait_until(waker->next_wake_msec);
}

void *
en_fdb_aging_waker_init(struct engine_node *node OVS_UNUSED,
                                struct engine_arg *arg OVS_UNUSED)
{
    struct aging_waker *waker = xmalloc(sizeof *waker);

    waker->should_schedule = false;
    waker->next_wake_msec = 0;

    return waker;
}

void
en_fdb_aging_waker_cleanup(void *data OVS_UNUSED)
{
}
