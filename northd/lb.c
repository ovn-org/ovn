/*
 * Copyright (c) 2024, Red Hat, Inc.
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
#include "lib/bitmap.h"
#include "openvswitch/vlog.h"
#include "socket-util.h"

/* OVN includes */
#include "lb.h"
#include "lflow-mgr.h"
#include "lib/lb.h"
#include "northd.h"
#include "ovn/lex.h"

VLOG_DEFINE_THIS_MODULE(northd_lb);

static const char *lb_neighbor_responder_mode_names[] = {
    [LB_NEIGH_RESPOND_REACHABLE] = "reachable",
    [LB_NEIGH_RESPOND_ALL] = "all",
    [LB_NEIGH_RESPOND_NONE] = "none",
};

static struct nbrec_load_balancer_health_check *
ovn_lb_get_health_check(const struct nbrec_load_balancer *nbrec_lb,
                        const char *vip_port_str, bool template);

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
void ovn_northd_lb_vip_init(struct ovn_northd_lb_vip *lb_vip_nb,
                            const struct ovn_lb_vip *lb_vip,
                            const struct nbrec_load_balancer *nbrec_lb,
                            const char *vip_port_str, const char *backend_ips,
                            bool template)
{
    lb_vip_nb->backend_ips = xstrdup(backend_ips);
    lb_vip_nb->n_backends = vector_len(&lb_vip->backends);
    lb_vip_nb->backends_nb = xcalloc(lb_vip_nb->n_backends,
                                     sizeof *lb_vip_nb->backends_nb);
    lb_vip_nb->lb_health_check =
        ovn_lb_get_health_check(nbrec_lb, vip_port_str, template);
}

/*
 * Initializes health check configuration for load balancer VIP
 * backends. Parses the ip_port_mappings in the format :
 * "ip:logical_port:src_ip[:az_name]".
 * If az_name is present and non-empty, it indicates this is a
 * remote service monitor (backend is in another availability zone),
 * it should be propogated to another AZ by interconnection processing.
 */
static void
ovn_lb_vip_backends_health_check_init(const struct ovn_northd_lb *lb,
                                      const struct ovn_lb_vip *lb_vip,
                                      struct ovn_northd_lb_vip *lb_vip_nb)
{
    struct ds key = DS_EMPTY_INITIALIZER;

    for (size_t j = 0; j < vector_len(&lb_vip->backends); j++) {
        const struct ovn_lb_backend *backend =
            vector_get_ptr(&lb_vip->backends, j);
        ds_clear(&key);
        ds_put_format(&key, IN6_IS_ADDR_V4MAPPED(&lb_vip->vip)
                      ? "%s" : "[%s]", backend->ip_str);

        const char *s = smap_get(&lb->nlb->ip_port_mappings, ds_cstr(&key));
        if (!s) {
            continue;
        }

        char *svc_mon_src_ip = NULL;
        char *az_name = NULL;
        bool is_remote = false;
        char *port_name = xstrdup(s);
        char *src_ip = NULL;

        char *first_colon = strchr(port_name, ':');
        if (!first_colon) {
            free(port_name);
            continue;
        }
        *first_colon = '\0';

        if (first_colon[1] == '[') {
            /* IPv6 case - format: port:[ipv6]:az or port:[ipv6] */
            char *ip_end = strchr(first_colon + 2, ']');
            if (!ip_end) {
                VLOG_WARN("Malformed IPv6 address in backend %s", s);
                free(port_name);
                continue;
            }

            src_ip = first_colon + 2;
            *ip_end = '\0';

            if (ip_end[1] == ':') {
                az_name = ip_end + 2;
                if (!*az_name) {
                    VLOG_WARN("Empty AZ name specified for backend %s",
                              port_name);
                    free(port_name);
                    continue;
                }
                is_remote = true;
            }
        } else {
            /* IPv4 case - format: port:ip:az or port:ip */
            src_ip = first_colon + 1;
            char *az_colon = strchr(src_ip, ':');
            if (az_colon) {
                *az_colon = '\0';
                az_name = az_colon + 1;
                if (!*az_name) {
                    VLOG_WARN("Empty AZ name specified for backend %s",
                              port_name);
                    free(port_name);
                    continue;
                }
            is_remote = true;
            }
        }

        struct sockaddr_storage svc_mon_src_addr;
        if (!src_ip || !inet_parse_address(src_ip, &svc_mon_src_addr)) {
            VLOG_WARN("Invalid svc mon src IP %s", src_ip ? src_ip : "NULL");
        } else {
            struct ds src_ip_s = DS_EMPTY_INITIALIZER;
            ss_format_address_nobracks(&svc_mon_src_addr, &src_ip_s);
            svc_mon_src_ip = ds_steal_cstr(&src_ip_s);
        }

        if (svc_mon_src_ip) {
            struct ovn_northd_lb_backend *backend_nb =
                &lb_vip_nb->backends_nb[j];
            backend_nb->health_check = true;
            backend_nb->logical_port = xstrdup(port_name);
            backend_nb->svc_mon_src_ip = svc_mon_src_ip;
            backend_nb->az_name = is_remote ? xstrdup(az_name) : NULL;
            backend_nb->remote_backend = is_remote;
        }
        free(port_name);
    }

    ds_destroy(&key);
}

static
void ovn_northd_lb_vip_destroy(struct ovn_northd_lb_vip *vip)
{
    free(vip->backend_ips);
    for (size_t i = 0; i < vip->n_backends; i++) {
        free(vip->backends_nb[i].logical_port);
        free(vip->backends_nb[i].svc_mon_src_ip);
        free(vip->backends_nb[i].az_name);
    }
    free(vip->backends_nb);
}

static bool
ovn_lb_get_routable_mode(const struct nbrec_load_balancer *nbrec_lb,
                         bool routable, bool template)
{
    if (template && routable) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "Template load balancer "UUID_FMT" does not suport "
                           "option 'add_route'.  Forcing it to disabled.",
                     UUID_ARGS(&nbrec_lb->header_.uuid));
        return false;
    }
    return routable;
}

static bool
ovn_lb_neigh_mode_is_valid(enum lb_neighbor_responder_mode mode, bool template)
{
    if (!template) {
        return true;
    }

    switch (mode) {
    case LB_NEIGH_RESPOND_REACHABLE:
        return false;
    case LB_NEIGH_RESPOND_ALL:
    case LB_NEIGH_RESPOND_NONE:
        return true;
    }
    return false;
}

static enum lb_neighbor_responder_mode
ovn_lb_get_neigh_mode(const struct nbrec_load_balancer *nbrec_lb,
                      const char *mode, bool template)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    enum lb_neighbor_responder_mode default_mode =
        template ? LB_NEIGH_RESPOND_NONE : LB_NEIGH_RESPOND_REACHABLE;

    if (!mode) {
        mode = lb_neighbor_responder_mode_names[default_mode];
    }

    for (size_t i = 0; i < ARRAY_SIZE(lb_neighbor_responder_mode_names); i++) {
        if (!strcmp(mode, lb_neighbor_responder_mode_names[i])) {
            if (ovn_lb_neigh_mode_is_valid(i, template)) {
                return i;
            }
            break;
        }
    }

    VLOG_WARN_RL(&rl, "Invalid neighbor responder mode %s for load balancer "
                       UUID_FMT", forcing it to %s",
                 mode, UUID_ARGS(&nbrec_lb->header_.uuid),
                 lb_neighbor_responder_mode_names[default_mode]);
    return default_mode;
}

static struct nbrec_load_balancer_health_check *
ovn_lb_get_health_check(const struct nbrec_load_balancer *nbrec_lb,
                        const char *vip_port_str, bool template)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

    if (!nbrec_lb->n_health_check) {
        return NULL;
    }

    if (nbrec_lb->protocol && !strcmp(nbrec_lb->protocol, "sctp")) {
        VLOG_WARN_RL(&rl,
                     "SCTP load balancers do not currently support "
                     "health checks. Not creating health checks for "
                     "load balancer " UUID_FMT,
                     UUID_ARGS(&nbrec_lb->header_.uuid));
        return NULL;
    }

    if (template) {
        VLOG_WARN_RL(&rl,
                     "Template load balancers do not currently support "
                     "health checks. Not creating health checks for "
                     "load balancer " UUID_FMT,
                     UUID_ARGS(&nbrec_lb->header_.uuid));
        return NULL;
    }

    for (size_t i = 0; i < nbrec_lb->n_health_check; i++) {
        if (!strcmp(nbrec_lb->health_check[i]->vip, vip_port_str)) {
            return nbrec_lb->health_check[i];
        }
    }
    return NULL;
}

static bool
validate_snap_ip_address(const char *snat_ip)
{
    ovs_be32 ip;

    return ip_parse(snat_ip, &ip);
}

static void
ovn_northd_lb_init(struct ovn_northd_lb *lb,
                   const struct nbrec_load_balancer *nbrec_lb)
{
    bool template = smap_get_bool(&nbrec_lb->options, "template", false);
    bool is_udp = nullable_string_is_equal(nbrec_lb->protocol, "udp");
    bool is_sctp = nullable_string_is_equal(nbrec_lb->protocol, "sctp");
    int address_family = !strcmp(smap_get_def(&nbrec_lb->options,
                                              "address-family", "ipv4"),
                                 "ipv4")
                         ? AF_INET
                         : AF_INET6;

    lb->nlb = nbrec_lb;
    lb->proto = is_udp ? "udp" : is_sctp ? "sctp" : "tcp";
    lb->n_vips = smap_count(&nbrec_lb->vips);
    lb->vips = xcalloc(lb->n_vips, sizeof *lb->vips);
    lb->vips_nb = xcalloc(lb->n_vips, sizeof *lb->vips_nb);
    smap_init(&lb->template_vips);
    lb->controller_event = smap_get_bool(&nbrec_lb->options, "event", false);

    bool routable = smap_get_bool(&nbrec_lb->options, "add_route", false);
    lb->routable = ovn_lb_get_routable_mode(nbrec_lb, routable, template);

    lb->skip_snat = smap_get_bool(&nbrec_lb->options, "skip_snat", false);
    lb->template = template;

    const char *mode = smap_get(&nbrec_lb->options, "neighbor_responder");
    lb->neigh_mode = ovn_lb_get_neigh_mode(nbrec_lb, mode, template);

    uint32_t affinity_timeout =
        smap_get_uint(&nbrec_lb->options, "affinity_timeout", 0);
    if (affinity_timeout > UINT16_MAX) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "max affinity_timeout timeout value is %u",
                     UINT16_MAX);
        affinity_timeout = UINT16_MAX;
    }
    lb->affinity_timeout = affinity_timeout;

    const char *snat_ip = smap_get(&nbrec_lb->options, "hairpin_snat_ip");

    if (snat_ip && validate_snap_ip_address(snat_ip)) {
        lb->hairpin_snat_ip = xstrdup(snat_ip);
    }

    sset_init(&lb->ips_v4);
    sset_init(&lb->ips_v6);
    struct smap_node *node;
    size_t n_vips = 0;

    SMAP_FOR_EACH (node, &nbrec_lb->vips) {
        struct ovn_lb_vip *lb_vip = &lb->vips[n_vips];
        struct ovn_northd_lb_vip *lb_vip_nb = &lb->vips_nb[n_vips];

        char *error = ovn_lb_vip_init(lb_vip, node->key, node->value,
                                      template, address_family);
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Failed to initialize LB VIP: %s", error);
            ovn_lb_vip_destroy(lb_vip);
            free(error);
            continue;
        }
        lb_vip->empty_backend_rej = smap_get_bool(&nbrec_lb->options,
                                                  "reject", false);
        ovn_northd_lb_vip_init(lb_vip_nb, lb_vip, nbrec_lb,
                               node->key, node->value, template);
        if (lb_vip_nb->lb_health_check) {
            lb->health_checks = true;
        }

        if (IN6_IS_ADDR_V4MAPPED(&lb_vip->vip)) {
            sset_add(&lb->ips_v4, lb_vip->vip_str);
        } else {
            sset_add(&lb->ips_v6, lb_vip->vip_str);
        }

        if (lb->template && address_family == AF_INET6) {
            smap_add_nocopy(&lb->template_vips,
                            ovn_lb_vip6_template_format_internal(lb_vip),
                            xstrdup(node->value));
        }
        n_vips++;

        if (lb_vip_nb->lb_health_check) {
            ovn_lb_vip_backends_health_check_init(lb, lb_vip, lb_vip_nb);
        }
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
}

struct ovn_northd_lb *
ovn_northd_lb_create(const struct nbrec_load_balancer *nbrec_lb)
{
    struct ovn_northd_lb *lb = xzalloc(sizeof *lb);
    ovn_northd_lb_init(lb, nbrec_lb);
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

const struct smap *
ovn_northd_lb_get_vips(const struct ovn_northd_lb *lb)
{
    if (!smap_is_empty(&lb->template_vips)) {
        return &lb->template_vips;
    }
    return &lb->nlb->vips;
}

static void
ovn_northd_lb_cleanup(struct ovn_northd_lb *lb)
{
    for (size_t i = 0; i < lb->n_vips; i++) {
        ovn_lb_vip_destroy(&lb->vips[i]);
        ovn_northd_lb_vip_destroy(&lb->vips_nb[i]);
    }
    free(lb->vips);
    free(lb->vips_nb);
    lb->vips = NULL;
    lb->vips_nb = NULL;
    smap_destroy(&lb->template_vips);
    sset_destroy(&lb->ips_v4);
    sset_destroy(&lb->ips_v6);
    free(lb->selection_fields);
    free(lb->hairpin_snat_ip);
    lb->selection_fields = NULL;
    lb->health_checks = false;
}

void
ovn_northd_lb_destroy(struct ovn_northd_lb *lb)
{
    ovn_northd_lb_cleanup(lb);
    free(lb);
}

void
ovn_northd_lb_reinit(struct ovn_northd_lb *lb,
                     const struct nbrec_load_balancer *nbrec_lb)
{
    ovn_northd_lb_cleanup(lb);
    ovn_northd_lb_init(lb, nbrec_lb);
}

static void
ovn_lb_group_init(struct ovn_lb_group *lb_group,
                  const struct nbrec_load_balancer_group *nbrec_lb_group,
                  const struct hmap *lbs)
{
    lb_group->n_lbs = nbrec_lb_group->n_load_balancer;
    lb_group->lbs = xmalloc(lb_group->n_lbs * sizeof *lb_group->lbs);
    lb_group->lb_ips = ovn_lb_ip_set_create();

    for (size_t i = 0; i < nbrec_lb_group->n_load_balancer; i++) {
        const struct uuid *lb_uuid =
            &nbrec_lb_group->load_balancer[i]->header_.uuid;
        lb_group->lbs[i] = ovn_northd_lb_find(lbs, lb_uuid);
        lb_group->has_routable_lb |= lb_group->lbs[i]->routable;
    }
}

/* Constructs a new 'struct ovn_lb_group' object from the Nb LB Group record
 * and an array of 'struct ovn_northd_lb' objects for its associated
 * load balancers. */
struct ovn_lb_group *
ovn_lb_group_create(const struct nbrec_load_balancer_group *nbrec_lb_group,
                    const struct hmap *lbs)
{
    struct ovn_lb_group *lb_group = xzalloc(sizeof *lb_group);
    lb_group->uuid = nbrec_lb_group->header_.uuid;
    ovn_lb_group_init(lb_group, nbrec_lb_group, lbs);
    return lb_group;
}

static void
ovn_lb_group_cleanup(struct ovn_lb_group *lb_group)
{
    ovn_lb_ip_set_destroy(lb_group->lb_ips);
    lb_group->lb_ips = NULL;
    lb_group->has_routable_lb = false;
    free(lb_group->lbs);
}

void
ovn_lb_group_destroy(struct ovn_lb_group *lb_group)
{
    if (!lb_group) {
        return;
    }

    ovn_lb_group_cleanup(lb_group);
    free(lb_group);
}

void
ovn_lb_group_reinit(struct ovn_lb_group *lb_group,
                    const struct nbrec_load_balancer_group *nbrec_lb_group,
                    const struct hmap *lbs)
{
    ovn_lb_group_cleanup(lb_group);
    ovn_lb_group_init(lb_group, nbrec_lb_group, lbs);
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

void
build_lrouter_lb_ips(struct ovn_lb_ip_set *lb_ips,
                     const struct ovn_northd_lb *lb)
{
    add_ips_to_lb_ip_set(lb_ips, lb->routable, &lb->ips_v4, &lb->ips_v6);
}

void
add_ips_to_lb_ip_set(struct ovn_lb_ip_set *lb_ips,
                     bool is_routable,
                     const struct sset *lb_ips_v4,
                     const struct sset *lb_ips_v6)
{
    const char *ip_address;

    SSET_FOR_EACH (ip_address, lb_ips_v4) {
        sset_add(&lb_ips->ips_v4, ip_address);
        if (is_routable) {
            sset_add(&lb_ips->ips_v4_routable, ip_address);
        }
    }
    SSET_FOR_EACH (ip_address, lb_ips_v6) {
        sset_add(&lb_ips->ips_v6, ip_address);
        if (is_routable) {
            sset_add(&lb_ips->ips_v6_routable, ip_address);
        }
    }
}

void
remove_ips_from_lb_ip_set(struct ovn_lb_ip_set *lb_ips,
                          bool is_routable,
                          const struct sset *lb_ips_v4,
                          const struct sset *lb_ips_v6)
{
    const char *ip_address;

    SSET_FOR_EACH (ip_address, lb_ips_v4) {
        sset_find_and_delete(&lb_ips->ips_v4, ip_address);
        if (is_routable) {
            sset_find_and_delete(&lb_ips->ips_v4_routable, ip_address);
        }
    }
    SSET_FOR_EACH (ip_address, lb_ips_v6) {
        sset_find_and_delete(&lb_ips->ips_v6, ip_address);
        if (is_routable) {
            sset_find_and_delete(&lb_ips->ips_v6_routable, ip_address);
        }
    }
}

/* lb datapaths functions */
struct  ovn_lb_datapaths *
ovn_lb_datapaths_create(const struct ovn_northd_lb *lb, size_t n_ls_datapaths,
                        size_t n_lr_datapaths)
{
    struct ovn_lb_datapaths *lb_dps = xzalloc(sizeof *lb_dps);
    lb_dps->lb = lb;
    dynamic_bitmap_alloc(&lb_dps->nb_ls_map, n_ls_datapaths);
    dynamic_bitmap_alloc(&lb_dps->nb_lr_map, n_lr_datapaths);
    lb_dps->lflow_ref = lflow_ref_create();
    hmapx_init(&lb_dps->ls_lb_with_stateless_mode);
    return lb_dps;
}

void
ovn_lb_datapaths_destroy(struct ovn_lb_datapaths *lb_dps)
{
    dynamic_bitmap_free(&lb_dps->nb_lr_map);
    dynamic_bitmap_free(&lb_dps->nb_ls_map);
    lflow_ref_destroy(lb_dps->lflow_ref);
    hmapx_destroy(&lb_dps->ls_lb_with_stateless_mode);
    free(lb_dps);
}

void
ovn_lb_datapaths_add_lr(struct ovn_lb_datapaths *lb_dps, size_t n,
                        struct ovn_datapath **ods,
                        size_t n_lr_datapaths)
{
    dynamic_bitmap_realloc(&lb_dps->nb_lr_map, n_lr_datapaths);
    for (size_t i = 0; i < n; i++) {
        dynamic_bitmap_set1(&lb_dps->nb_lr_map, ods[i]->index);
    }
}

void
ovn_lb_datapaths_add_ls(struct ovn_lb_datapaths *lb_dps, size_t n,
                        struct ovn_datapath **ods,
                        size_t n_ls_datapaths)
{
    dynamic_bitmap_realloc(&lb_dps->nb_ls_map, n_ls_datapaths);
    for (size_t i = 0; i < n; i++) {
        dynamic_bitmap_set1(&lb_dps->nb_ls_map, ods[i]->index);
    }
}

struct ovn_lb_datapaths *
ovn_lb_datapaths_find(const struct hmap *lb_dps_map,
                      const struct uuid *lb_uuid)
{
    struct ovn_lb_datapaths *lb_dps;
    size_t hash = uuid_hash(lb_uuid);
    HMAP_FOR_EACH_WITH_HASH (lb_dps, hmap_node, hash, lb_dps_map) {
        if (uuid_equals(&lb_dps->lb->nlb->header_.uuid, lb_uuid)) {
            return lb_dps;
        }
    }
    return NULL;
}

struct ovn_lb_group_datapaths *
ovn_lb_group_datapaths_create(const struct ovn_lb_group *lb_group,
                              size_t max_ls_datapaths,
                              size_t max_lr_datapaths)
{
    struct ovn_lb_group_datapaths *lb_group_dps =
        xzalloc(sizeof *lb_group_dps);
    lb_group_dps->lb_group = lb_group;
    lb_group_dps->ls = VECTOR_CAPACITY_INITIALIZER(struct ovn_datapath *,
                                                   max_ls_datapaths);
    lb_group_dps->lr = VECTOR_CAPACITY_INITIALIZER(struct ovn_datapath *,
                                                   max_lr_datapaths);

    return lb_group_dps;
}

void
ovn_lb_group_datapaths_destroy(struct ovn_lb_group_datapaths *lb_group_dps)
{
    vector_destroy(&lb_group_dps->ls);
    vector_destroy(&lb_group_dps->lr);
    free(lb_group_dps);
}

struct ovn_lb_group_datapaths *
ovn_lb_group_datapaths_find(const struct hmap *lb_group_dps_map,
                            const struct uuid *lb_group_uuid)
{
    struct ovn_lb_group_datapaths *lb_group_dps;
    size_t hash = uuid_hash(lb_group_uuid);

    HMAP_FOR_EACH_WITH_HASH (lb_group_dps, hmap_node, hash, lb_group_dps_map) {
        if (uuid_equals(&lb_group_dps->lb_group->uuid, lb_group_uuid)) {
            return lb_group_dps;
        }
    }
    return NULL;
}
