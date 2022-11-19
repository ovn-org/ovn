/* Copyright (c) 2020, Red Hat, Inc.
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

#include "lb.h"
#include "lib/ovn-nb-idl.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"

/* OpenvSwitch lib includes. */
#include "openvswitch/vlog.h"
#include "lib/smap.h"

VLOG_DEFINE_THIS_MODULE(lb);

struct ovn_lb_ip_set *
ovn_lb_ip_set_create(void)
{
    struct ovn_lb_ip_set *lb_ip_set = xzalloc(sizeof *lb_ip_set);

    sset_init(&lb_ip_set->ips_v4);
    sset_init(&lb_ip_set->ips_v4_routable);
    sset_init(&lb_ip_set->ips_v4_reachable);
    sset_init(&lb_ip_set->ips_v6);
    sset_init(&lb_ip_set->ips_v6_routable);
    sset_init(&lb_ip_set->ips_v6_reachable);

    return lb_ip_set;
}

void
ovn_lb_ip_set_destroy(struct ovn_lb_ip_set *lb_ip_set)
{
    if (!lb_ip_set) {
        return;
    }
    sset_destroy(&lb_ip_set->ips_v4);
    sset_destroy(&lb_ip_set->ips_v4_routable);
    sset_destroy(&lb_ip_set->ips_v4_reachable);
    sset_destroy(&lb_ip_set->ips_v6);
    sset_destroy(&lb_ip_set->ips_v6_routable);
    sset_destroy(&lb_ip_set->ips_v6_reachable);
    free(lb_ip_set);
}

struct ovn_lb_ip_set *
ovn_lb_ip_set_clone(struct ovn_lb_ip_set *lb_ip_set)
{
    struct ovn_lb_ip_set *clone = ovn_lb_ip_set_create();

    sset_clone(&clone->ips_v4, &lb_ip_set->ips_v4);
    sset_clone(&clone->ips_v4_routable, &lb_ip_set->ips_v4_routable);
    sset_clone(&clone->ips_v4_reachable, &lb_ip_set->ips_v4_reachable);
    sset_clone(&clone->ips_v6, &lb_ip_set->ips_v6);
    sset_clone(&clone->ips_v6_routable, &lb_ip_set->ips_v6_routable);
    sset_clone(&clone->ips_v6_reachable, &lb_ip_set->ips_v6_reachable);

    return clone;
}

static
bool ovn_lb_vip_init(struct ovn_lb_vip *lb_vip, const char *lb_key,
                     const char *lb_value)
{
    int addr_family;

    if (!ip_address_and_port_from_lb_key(lb_key, &lb_vip->vip_str,
                                         &lb_vip->vip, &lb_vip->vip_port,
                                         &addr_family)) {
        return false;
    }

    /* Format for backend ips: "IP1:port1,IP2:port2,...". */
    size_t n_backends = 0;
    size_t n_allocated_backends = 0;
    char *tokstr = xstrdup(lb_value);
    char *save_ptr = NULL;
    for (char *token = strtok_r(tokstr, ",", &save_ptr);
        token != NULL;
        token = strtok_r(NULL, ",", &save_ptr)) {

        if (n_backends == n_allocated_backends) {
            lb_vip->backends = x2nrealloc(lb_vip->backends,
                                          &n_allocated_backends,
                                          sizeof *lb_vip->backends);
        }

        struct ovn_lb_backend *backend = &lb_vip->backends[n_backends];
        int backend_addr_family;
        if (!ip_address_and_port_from_lb_key(token, &backend->ip_str,
                                             &backend->ip, &backend->port,
                                             &backend_addr_family)) {
            continue;
        }

        if (addr_family != backend_addr_family) {
            free(backend->ip_str);
            continue;
        }

        n_backends++;
    }
    free(tokstr);
    lb_vip->n_backends = n_backends;
    return true;
}

static
void ovn_lb_vip_destroy(struct ovn_lb_vip *vip)
{
    free(vip->vip_str);
    for (size_t i = 0; i < vip->n_backends; i++) {
        free(vip->backends[i].ip_str);
    }
    free(vip->backends);
}

static
void ovn_northd_lb_vip_init(struct ovn_northd_lb_vip *lb_vip_nb,
                            const struct ovn_lb_vip *lb_vip,
                            const struct nbrec_load_balancer *nbrec_lb,
                            const char *vip_port_str, const char *backend_ips)
{
    lb_vip_nb->backend_ips = xstrdup(backend_ips);
    lb_vip_nb->n_backends = lb_vip->n_backends;
    lb_vip_nb->backends_nb = xcalloc(lb_vip_nb->n_backends,
                                     sizeof *lb_vip_nb->backends_nb);

    struct nbrec_load_balancer_health_check *lb_health_check = NULL;
    if (nbrec_lb->protocol && !strcmp(nbrec_lb->protocol, "sctp")) {
        if (nbrec_lb->n_health_check > 0) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl,
                         "SCTP load balancers do not currently support "
                         "health checks. Not creating health checks for "
                         "load balancer " UUID_FMT,
                         UUID_ARGS(&nbrec_lb->header_.uuid));
        }
    } else {
        for (size_t j = 0; j < nbrec_lb->n_health_check; j++) {
            if (!strcmp(nbrec_lb->health_check[j]->vip, vip_port_str)) {
                lb_health_check = nbrec_lb->health_check[j];
                break;
            }
        }
    }

    lb_vip_nb->lb_health_check = lb_health_check;
}

static
void ovn_northd_lb_vip_destroy(struct ovn_northd_lb_vip *vip)
{
    free(vip->backend_ips);
    for (size_t i = 0; i < vip->n_backends; i++) {
        free(vip->backends_nb[i].svc_mon_src_ip);
    }
    free(vip->backends_nb);
}

static void
ovn_lb_get_hairpin_snat_ip(const struct uuid *lb_uuid,
                           const struct smap *lb_options,
                           struct lport_addresses *hairpin_addrs)
{
    const char *addresses = smap_get(lb_options, "hairpin_snat_ip");

    if (!addresses) {
        return;
    }

    if (!extract_ip_address(addresses, hairpin_addrs)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad hairpin_snat_ip %s in load balancer "UUID_FMT,
                     addresses, UUID_ARGS(lb_uuid));
    }
}

struct ovn_northd_lb *
ovn_northd_lb_create(const struct nbrec_load_balancer *nbrec_lb)
{
    bool is_udp = nullable_string_is_equal(nbrec_lb->protocol, "udp");
    bool is_sctp = nullable_string_is_equal(nbrec_lb->protocol, "sctp");
    struct ovn_northd_lb *lb = xzalloc(sizeof *lb);

    lb->nlb = nbrec_lb;
    lb->proto = is_udp ? "udp" : is_sctp ? "sctp" : "tcp";
    lb->n_vips = smap_count(&nbrec_lb->vips);
    lb->vips = xcalloc(lb->n_vips, sizeof *lb->vips);
    lb->vips_nb = xcalloc(lb->n_vips, sizeof *lb->vips_nb);
    lb->controller_event = smap_get_bool(&nbrec_lb->options, "event", false);
    lb->routable = smap_get_bool(&nbrec_lb->options, "add_route", false);
    lb->skip_snat = smap_get_bool(&nbrec_lb->options, "skip_snat", false);
    const char *mode =
        smap_get_def(&nbrec_lb->options, "neighbor_responder", "reachable");
    lb->neigh_mode = strcmp(mode, "all") ? LB_NEIGH_RESPOND_REACHABLE
                                         : LB_NEIGH_RESPOND_ALL;
    uint32_t affinity_timeout =
        smap_get_uint(&nbrec_lb->options, "affinity_timeout", 0);
    if (affinity_timeout > UINT16_MAX) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "max affinity_timeout timeout value is %u",
                     UINT16_MAX);
        affinity_timeout = UINT16_MAX;
    }
    lb->affinity_timeout = affinity_timeout;

    sset_init(&lb->ips_v4);
    sset_init(&lb->ips_v6);
    struct smap_node *node;
    size_t n_vips = 0;

    SMAP_FOR_EACH (node, &nbrec_lb->vips) {
        struct ovn_lb_vip *lb_vip = &lb->vips[n_vips];
        struct ovn_northd_lb_vip *lb_vip_nb = &lb->vips_nb[n_vips];

        lb_vip->empty_backend_rej = smap_get_bool(&nbrec_lb->options,
                                                  "reject", false);
        if (!ovn_lb_vip_init(lb_vip, node->key, node->value)) {
            continue;
        }
        ovn_northd_lb_vip_init(lb_vip_nb, lb_vip, nbrec_lb,
                               node->key, node->value);
        if (IN6_IS_ADDR_V4MAPPED(&lb_vip->vip)) {
            sset_add(&lb->ips_v4, lb_vip->vip_str);
        } else {
            sset_add(&lb->ips_v6, lb_vip->vip_str);
        }
        n_vips++;
    }

    /* It's possible that parsing VIPs fails.  Update the lb->n_vips to the
     * correct value.
     */
    lb->n_vips = n_vips;

    if (nbrec_lb->n_selection_fields) {
        char *proto = NULL;
        if (nbrec_lb->protocol && nbrec_lb->protocol[0]) {
            proto = nbrec_lb->protocol;
        }

        struct ds sel_fields = DS_EMPTY_INITIALIZER;
        for (size_t i = 0; i < lb->nlb->n_selection_fields; i++) {
            char *field = lb->nlb->selection_fields[i];
            if (!strcmp(field, "tp_src") && proto) {
                ds_put_format(&sel_fields, "%s_src,", proto);
            } else if (!strcmp(field, "tp_dst") && proto) {
                ds_put_format(&sel_fields, "%s_dst,", proto);
            } else {
                ds_put_format(&sel_fields, "%s,", field);
            }
        }
        ds_chomp(&sel_fields, ',');
        lb->selection_fields = ds_steal_cstr(&sel_fields);
    }
    return lb;
}

struct ovn_northd_lb *
ovn_northd_lb_find(const struct hmap *lbs, const struct uuid *uuid)
{
    struct ovn_northd_lb *lb;
    size_t hash = uuid_hash(uuid);
    HMAP_FOR_EACH_WITH_HASH (lb, hmap_node, hash, lbs) {
        if (uuid_equals(&lb->nlb->header_.uuid, uuid)) {
            return lb;
        }
    }
    return NULL;
}

void
ovn_northd_lb_add_lr(struct ovn_northd_lb *lb, size_t n,
                     struct ovn_datapath **ods)
{
    while (lb->n_allocated_nb_lr <= lb->n_nb_lr + n) {
        lb->nb_lr = x2nrealloc(lb->nb_lr, &lb->n_allocated_nb_lr,
                               sizeof *lb->nb_lr);
    }
    memcpy(&lb->nb_lr[lb->n_nb_lr], ods, n * sizeof *ods);
    lb->n_nb_lr += n;
}

void
ovn_northd_lb_add_ls(struct ovn_northd_lb *lb, size_t n,
                     struct ovn_datapath **ods)
{
    while (lb->n_allocated_nb_ls <= lb->n_nb_ls + n) {
        lb->nb_ls = x2nrealloc(lb->nb_ls, &lb->n_allocated_nb_ls,
                               sizeof *lb->nb_ls);
    }
    memcpy(&lb->nb_ls[lb->n_nb_ls], ods, n * sizeof *ods);
    lb->n_nb_ls += n;
}

void
ovn_northd_lb_destroy(struct ovn_northd_lb *lb)
{
    for (size_t i = 0; i < lb->n_vips; i++) {
        ovn_lb_vip_destroy(&lb->vips[i]);
        ovn_northd_lb_vip_destroy(&lb->vips_nb[i]);
    }
    free(lb->vips);
    free(lb->vips_nb);
    sset_destroy(&lb->ips_v4);
    sset_destroy(&lb->ips_v6);
    free(lb->selection_fields);
    free(lb->nb_lr);
    free(lb->nb_ls);
    free(lb);
}

/* Constructs a new 'struct ovn_lb_group' object from the Nb LB Group record
 * and a hash map of all existing 'struct ovn_northd_lb' objects.  Space will
 * be allocated for 'max_datapaths' logical switches and the same amount of
 * logical routers to which this LB Group is applied.  Can be filled later
 * with ovn_lb_group_add_ls() and ovn_lb_group_add_lr() respectively. */
struct ovn_lb_group *
ovn_lb_group_create(const struct nbrec_load_balancer_group *nbrec_lb_group,
                    const struct hmap *lbs, size_t max_datapaths)
{
    struct ovn_lb_group *lb_group;

    lb_group = xzalloc(sizeof *lb_group);
    lb_group->uuid = nbrec_lb_group->header_.uuid;
    lb_group->n_lbs = nbrec_lb_group->n_load_balancer;
    lb_group->lbs = xmalloc(lb_group->n_lbs * sizeof *lb_group->lbs);
    lb_group->ls = xmalloc(max_datapaths * sizeof *lb_group->ls);
    lb_group->lr = xmalloc(max_datapaths * sizeof *lb_group->lr);
    lb_group->lb_ips = ovn_lb_ip_set_create();

    for (size_t i = 0; i < nbrec_lb_group->n_load_balancer; i++) {
        const struct uuid *lb_uuid =
            &nbrec_lb_group->load_balancer[i]->header_.uuid;
        lb_group->lbs[i] = ovn_northd_lb_find(lbs, lb_uuid);
    }

    return lb_group;
}

void
ovn_lb_group_destroy(struct ovn_lb_group *lb_group)
{
    if (!lb_group) {
        return;
    }

    ovn_lb_ip_set_destroy(lb_group->lb_ips);
    free(lb_group->lbs);
    free(lb_group->ls);
    free(lb_group->lr);
    free(lb_group);
}

struct ovn_lb_group *
ovn_lb_group_find(const struct hmap *lb_groups, const struct uuid *uuid)
{
    struct ovn_lb_group *lb_group;
    size_t hash = uuid_hash(uuid);

    HMAP_FOR_EACH_WITH_HASH (lb_group, hmap_node, hash, lb_groups) {
        if (uuid_equals(&lb_group->uuid, uuid)) {
            return lb_group;
        }
    }
    return NULL;
}

struct ovn_controller_lb *
ovn_controller_lb_create(const struct sbrec_load_balancer *sbrec_lb)
{
    struct ovn_controller_lb *lb = xzalloc(sizeof *lb);

    lb->slb = sbrec_lb;
    lb->n_vips = smap_count(&sbrec_lb->vips);
    lb->vips = xcalloc(lb->n_vips, sizeof *lb->vips);

    struct smap_node *node;
    size_t n_vips = 0;

    SMAP_FOR_EACH (node, &sbrec_lb->vips) {
        struct ovn_lb_vip *lb_vip = &lb->vips[n_vips];

        if (!ovn_lb_vip_init(lb_vip, node->key, node->value)) {
            continue;
        }
        n_vips++;
    }

    /* It's possible that parsing VIPs fails.  Update the lb->n_vips to the
     * correct value.
     */
    lb->n_vips = n_vips;

    lb->hairpin_orig_tuple = smap_get_bool(&sbrec_lb->options,
                                           "hairpin_orig_tuple",
                                           false);
    ovn_lb_get_hairpin_snat_ip(&sbrec_lb->header_.uuid, &sbrec_lb->options,
                               &lb->hairpin_snat_ips);
    return lb;
}

void
ovn_controller_lb_destroy(struct ovn_controller_lb *lb)
{
    for (size_t i = 0; i < lb->n_vips; i++) {
        ovn_lb_vip_destroy(&lb->vips[i]);
    }
    free(lb->vips);
    destroy_lport_addresses(&lb->hairpin_snat_ips);
    free(lb);
}
