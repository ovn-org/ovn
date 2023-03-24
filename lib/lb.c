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
#include "northd/northd.h"
#include "ovn/lex.h"

/* OpenvSwitch lib includes. */
#include "openvswitch/vlog.h"
#include "lib/bitmap.h"
#include "lib/smap.h"

VLOG_DEFINE_THIS_MODULE(lb);

static const char *lb_neighbor_responder_mode_names[] = {
    [LB_NEIGH_RESPOND_REACHABLE] = "reachable",
    [LB_NEIGH_RESPOND_ALL] = "all",
    [LB_NEIGH_RESPOND_NONE] = "none",
};

static struct nbrec_load_balancer_health_check *
ovn_lb_get_health_check(const struct nbrec_load_balancer *nbrec_lb,
                        const char *vip_port_str, bool template);
static void ovn_lb_backends_clear(struct ovn_lb_vip *vip);

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

/* Format for backend ips: "IP1:port1,IP2:port2,...". */
static char *
ovn_lb_backends_init_explicit(struct ovn_lb_vip *lb_vip, const char *value)
{
    struct ds errors = DS_EMPTY_INITIALIZER;
    size_t n_allocated_backends = 0;
    char *tokstr = xstrdup(value);
    char *save_ptr = NULL;
    lb_vip->n_backends = 0;

    for (char *token = strtok_r(tokstr, ",", &save_ptr);
        token != NULL;
        token = strtok_r(NULL, ",", &save_ptr)) {

        if (lb_vip->n_backends == n_allocated_backends) {
            lb_vip->backends = x2nrealloc(lb_vip->backends,
                                          &n_allocated_backends,
                                          sizeof *lb_vip->backends);
        }

        struct ovn_lb_backend *backend = &lb_vip->backends[lb_vip->n_backends];
        int backend_addr_family;
        if (!ip_address_and_port_from_lb_key(token, &backend->ip_str,
                                             &backend->ip, &backend->port,
                                             &backend_addr_family)) {
            if (lb_vip->port_str) {
                ds_put_format(&errors, "%s: should be an IP address and a "
                                       "port number with : as a separator, ",
                              token);
            } else {
                ds_put_format(&errors, "%s: should be an IP address, ", token);
            }
            continue;
        }

        if (lb_vip->address_family != backend_addr_family) {
            free(backend->ip_str);
            ds_put_format(&errors, "%s: IP address family is different from "
                                   "VIP %s, ",
                          token, lb_vip->vip_str);
            continue;
        }

        if (lb_vip->port_str) {
            if (!backend->port) {
                free(backend->ip_str);
                ds_put_format(&errors, "%s: should be an IP address and "
                                       "a port number with : as a separator, ",
                              token);
                continue;
            }
        } else {
            if (backend->port) {
                free(backend->ip_str);
                ds_put_format(&errors, "%s: should be an IP address, ", token);
                continue;
            }
        }

        backend->port_str =
            backend->port ? xasprintf("%"PRIu16, backend->port) : NULL;
        lb_vip->n_backends++;
    }
    free(tokstr);

    if (ds_last(&errors) != EOF) {
        ds_chomp(&errors, ' ');
        ds_chomp(&errors, ',');
        ds_put_char(&errors, '.');
        return ds_steal_cstr(&errors);
    }
    return NULL;
}

static
char *ovn_lb_vip_init_explicit(struct ovn_lb_vip *lb_vip, const char *lb_key,
                               const char *lb_value)
{
    if (!ip_address_and_port_from_lb_key(lb_key, &lb_vip->vip_str,
                                         &lb_vip->vip, &lb_vip->vip_port,
                                         &lb_vip->address_family)) {
        return xasprintf("%s: should be an IP address (or an IP address "
                         "and a port number with : as a separator).", lb_key);
    }

    lb_vip->port_str = lb_vip->vip_port
                       ? xasprintf("%"PRIu16, lb_vip->vip_port)
                       : NULL;

    return ovn_lb_backends_init_explicit(lb_vip, lb_value);
}

/* Parses backends of a templated LB VIP.
 * For now only the following template forms are supported:
 * A.
 *   ^backendip_variable1[:^port_variable1|:port],
 *   ^backendip_variable2[:^port_variable2|:port]
 *
 * B.
 *   ^backends_variable1,^backends_variable2 is also a thing
 *      where 'backends_variable1' may expand to IP1_1:PORT1_1 on chassis-1
 *                                               IP1_2:PORT1_2 on chassis-2
 *        and 'backends_variable2' may expand to IP2_1:PORT2_1 on chassis-1
 *                                               IP2_2:PORT2_2 on chassis-2
 */
static char *
ovn_lb_backends_init_template(struct ovn_lb_vip *lb_vip, const char *value_)
{
    struct ds errors = DS_EMPTY_INITIALIZER;
    char *value = xstrdup(value_);
    char *save_ptr = NULL;
    size_t n_allocated_backends = 0;
    lb_vip->n_backends = 0;

    for (char *backend = strtok_r(value, ",", &save_ptr); backend;
         backend = strtok_r(NULL, ",", &save_ptr)) {

        char *atom = xstrdup(backend);
        char *save_ptr2 = NULL;
        bool success = false;
        char *backend_ip = NULL;
        char *backend_port = NULL;

        for (char *subatom = strtok_r(atom, ":", &save_ptr2); subatom;
             subatom = strtok_r(NULL, ":", &save_ptr2)) {
            if (backend_ip && backend_port) {
                success = false;
                break;
            }
            success = true;
            if (!backend_ip) {
                backend_ip = xstrdup(subatom);
            } else {
                backend_port = xstrdup(subatom);
            }
        }

        if (success) {
            if (lb_vip->n_backends == n_allocated_backends) {
                lb_vip->backends = x2nrealloc(lb_vip->backends,
                                              &n_allocated_backends,
                                              sizeof *lb_vip->backends);
            }

            struct ovn_lb_backend *lb_backend =
                &lb_vip->backends[lb_vip->n_backends];
            lb_backend->ip_str = backend_ip;
            lb_backend->port_str = backend_port;
            lb_backend->port = 0;
            lb_vip->n_backends++;
        } else {
            ds_put_format(&errors, "%s: should be a template of the form: "
                          "'^backendip_variable1[:^port_variable1|:port]', ",
                          atom);
            free(backend_port);
            free(backend_ip);
        }
        free(atom);
    }

    free(value);
    if (ds_last(&errors) != EOF) {
        ds_chomp(&errors, ' ');
        ds_chomp(&errors, ',');
        ds_put_char(&errors, '.');
        return ds_steal_cstr(&errors);
    }
    return NULL;
}

/* Parses a VIP of a templated LB.
 * For now only the following template forms are supported:
 *   ^vip_variable[:^port_variable|:port]
 */
static char *
ovn_lb_vip_init_template(struct ovn_lb_vip *lb_vip, const char *lb_key_,
                         const char *lb_value, int address_family)
{
    char *save_ptr = NULL;
    char *lb_key = xstrdup(lb_key_);
    bool success = false;

    for (char *atom = strtok_r(lb_key, ":", &save_ptr); atom;
         atom = strtok_r(NULL, ":", &save_ptr)) {
        if (lb_vip->vip_str && lb_vip->port_str) {
            success = false;
            break;
        }
        success = true;
        if (!lb_vip->vip_str) {
            lb_vip->vip_str = xstrdup(atom);
        } else {
            lb_vip->port_str = xstrdup(atom);
        }
    }
    free(lb_key);

    if (!success) {
        return xasprintf("%s: should be a template of the form: "
                         "'^vip_variable[:^port_variable|:port]'.",
                         lb_key_);
    }

    /* Backends can either be templates or explicit IPs and ports. */
    lb_vip->address_family = address_family;
    lb_vip->template_backends = true;
    char *template_error = ovn_lb_backends_init_template(lb_vip, lb_value);

    if (template_error) {
        lb_vip->template_backends = false;
        ovn_lb_backends_clear(lb_vip);

        char *explicit_error = ovn_lb_backends_init_explicit(lb_vip, lb_value);
        if (explicit_error) {
            char *error =
                xasprintf("invalid backend: template (%s) OR explicit (%s)",
                          template_error, explicit_error);
            free(explicit_error);
            free(template_error);
            return error;
        }
        free(template_error);
    }
    return NULL;
}

/* Returns NULL on success, an error string on failure.  The caller is
 * responsible for destroying 'lb_vip' in all cases.
 */
char *
ovn_lb_vip_init(struct ovn_lb_vip *lb_vip, const char *lb_key,
                const char *lb_value, bool template, int address_family)
{
    memset(lb_vip, 0, sizeof *lb_vip);

    return !template
           ?  ovn_lb_vip_init_explicit(lb_vip, lb_key, lb_value)
           :  ovn_lb_vip_init_template(lb_vip, lb_key, lb_value,
                                       address_family);
}

static void
ovn_lb_backends_destroy(struct ovn_lb_vip *vip)
{
    for (size_t i = 0; i < vip->n_backends; i++) {
        free(vip->backends[i].ip_str);
        free(vip->backends[i].port_str);
    }
}

static void
ovn_lb_backends_clear(struct ovn_lb_vip *vip)
{
    ovn_lb_backends_destroy(vip);
    vip->backends = NULL;
    vip->n_backends = 0;
}

void
ovn_lb_vip_destroy(struct ovn_lb_vip *vip)
{
    free(vip->vip_str);
    free(vip->port_str);
    ovn_lb_backends_destroy(vip);
    free(vip->backends);
}

static void
ovn_lb_vip_format__(const struct ovn_lb_vip *vip, struct ds *s,
                    bool needs_brackets)
{
    if (needs_brackets) {
        ds_put_char(s, '[');
    }
    ds_put_cstr(s, vip->vip_str);
    if (needs_brackets) {
        ds_put_char(s, ']');
    }
    if (vip->port_str) {
        ds_put_format(s, ":%s", vip->port_str);
    }
}

/* Formats the VIP in the way the ovn-controller expects it, that is,
 * template IPv6 variables need to be between brackets too.
 */
static char *
ovn_lb_vip6_template_format_internal(const struct ovn_lb_vip *vip)
{
    struct ds s = DS_EMPTY_INITIALIZER;

    if (vip->vip_str && *vip->vip_str == LEX_TEMPLATE_PREFIX) {
        ovn_lb_vip_format__(vip, &s, true);
    } else {
        ovn_lb_vip_format(vip, &s, !!vip->port_str);
    }
    return ds_steal_cstr(&s);
}

void
ovn_lb_vip_format(const struct ovn_lb_vip *vip, struct ds *s, bool template)
{
    bool needs_brackets = vip->address_family == AF_INET6 && vip->port_str
                          && !template;
    ovn_lb_vip_format__(vip, s, needs_brackets);
}

void
ovn_lb_vip_backends_format(const struct ovn_lb_vip *vip, struct ds *s)
{
    bool needs_brackets = vip->address_family == AF_INET6 && vip->port_str
                          && !vip->template_backends;
    for (size_t i = 0; i < vip->n_backends; i++) {
        struct ovn_lb_backend *backend = &vip->backends[i];

        if (needs_brackets) {
            ds_put_char(s, '[');
        }
        ds_put_cstr(s, backend->ip_str);
        if (needs_brackets) {
            ds_put_char(s, ']');
        }
        if (backend->port_str) {
            ds_put_format(s, ":%s", backend->port_str);
        }
        if (i != vip->n_backends - 1) {
            ds_put_char(s, ',');
        }
    }
}

static
void ovn_northd_lb_vip_init(struct ovn_northd_lb_vip *lb_vip_nb,
                            const struct ovn_lb_vip *lb_vip,
                            const struct nbrec_load_balancer *nbrec_lb,
                            const char *vip_port_str, const char *backend_ips,
                            bool template)
{
    lb_vip_nb->backend_ips = xstrdup(backend_ips);
    lb_vip_nb->n_backends = lb_vip->n_backends;
    lb_vip_nb->backends_nb = xcalloc(lb_vip_nb->n_backends,
                                     sizeof *lb_vip_nb->backends_nb);
    lb_vip_nb->lb_health_check =
        ovn_lb_get_health_check(nbrec_lb, vip_port_str, template);
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

struct ovn_northd_lb *
ovn_northd_lb_create(const struct nbrec_load_balancer *nbrec_lb,
                     size_t n_ls_datapaths, size_t n_lr_datapaths)
{
    bool template = smap_get_bool(&nbrec_lb->options, "template", false);
    bool is_udp = nullable_string_is_equal(nbrec_lb->protocol, "udp");
    bool is_sctp = nullable_string_is_equal(nbrec_lb->protocol, "sctp");
    struct ovn_northd_lb *lb = xzalloc(sizeof *lb);
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

    lb->nb_ls_map = bitmap_allocate(n_ls_datapaths);
    lb->nb_lr_map = bitmap_allocate(n_lr_datapaths);

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

const struct smap *
ovn_northd_lb_get_vips(const struct ovn_northd_lb *lb)
{
    if (!smap_is_empty(&lb->template_vips)) {
        return &lb->template_vips;
    }
    return &lb->nlb->vips;
}

void
ovn_northd_lb_add_lr(struct ovn_northd_lb *lb, size_t n,
                     struct ovn_datapath **ods)
{
    for (size_t i = 0; i < n; i++) {
        bitmap_set1(lb->nb_lr_map, ods[i]->index);
    }
}

void
ovn_northd_lb_add_ls(struct ovn_northd_lb *lb, size_t n,
                     struct ovn_datapath **ods)
{
    for (size_t i = 0; i < n; i++) {
        bitmap_set1(lb->nb_ls_map, ods[i]->index);
    }
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
    smap_destroy(&lb->template_vips);
    sset_destroy(&lb->ips_v4);
    sset_destroy(&lb->ips_v6);
    free(lb->selection_fields);
    bitmap_free(lb->nb_lr_map);
    bitmap_free(lb->nb_ls_map);
    free(lb);
}

/* Constructs a new 'struct ovn_lb_group' object from the Nb LB Group record
 * and a hash map of all existing 'struct ovn_northd_lb' objects.  Space will
 * be allocated for 'max_ls_datapaths' logical switches and 'max_lr_datapaths'
 * logical routers to which this LB Group is applied.  Can be filled later
 * with ovn_lb_group_add_ls() and ovn_lb_group_add_lr() respectively. */
struct ovn_lb_group *
ovn_lb_group_create(const struct nbrec_load_balancer_group *nbrec_lb_group,
                    const struct hmap *lbs, size_t max_ls_datapaths,
                    size_t max_lr_datapaths)
{
    struct ovn_lb_group *lb_group;

    lb_group = xzalloc(sizeof *lb_group);
    lb_group->uuid = nbrec_lb_group->header_.uuid;
    lb_group->n_lbs = nbrec_lb_group->n_load_balancer;
    lb_group->lbs = xmalloc(lb_group->n_lbs * sizeof *lb_group->lbs);
    lb_group->ls = xmalloc(max_ls_datapaths * sizeof *lb_group->ls);
    lb_group->lr = xmalloc(max_lr_datapaths * sizeof *lb_group->lr);
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
ovn_controller_lb_create(const struct sbrec_load_balancer *sbrec_lb,
                         const struct smap *template_vars,
                         struct sset *template_vars_ref)
{
    struct ovn_controller_lb *lb = xzalloc(sizeof *lb);
    bool template = smap_get_bool(&sbrec_lb->options, "template", false);

    lb->slb = sbrec_lb;
    lb->n_vips = smap_count(&sbrec_lb->vips);
    lb->vips = xcalloc(lb->n_vips, sizeof *lb->vips);

    struct smap_node *node;
    size_t n_vips = 0;

    SMAP_FOR_EACH (node, &sbrec_lb->vips) {
        struct ovn_lb_vip *lb_vip = &lb->vips[n_vips];

        struct lex_str key_s = template
                               ? lexer_parse_template_string(node->key,
                                                             template_vars,
                                                             template_vars_ref)
                               : lex_str_use(node->key);
        struct lex_str value_s = template
                               ? lexer_parse_template_string(node->value,
                                                             template_vars,
                                                             template_vars_ref)
                               : lex_str_use(node->value);
        char *error = ovn_lb_vip_init_explicit(lb_vip,
                                               lex_str_get(&key_s),
                                               lex_str_get(&value_s));
        if (error) {
            free(error);
        } else {
            n_vips++;
        }
        lex_str_free(&key_s);
        lex_str_free(&value_s);
    }

    lb->proto = IPPROTO_TCP;
    if (sbrec_lb->protocol && sbrec_lb->protocol[0]) {
        if (!strcmp(sbrec_lb->protocol, "udp")) {
            lb->proto = IPPROTO_UDP;
        } else if (!strcmp(sbrec_lb->protocol, "sctp")) {
            lb->proto = IPPROTO_SCTP;
        }
    }

    /* It's possible that parsing VIPs fails.  Update the lb->n_vips to the
     * correct value.
     */
    lb->n_vips = n_vips;

    lb->hairpin_orig_tuple = smap_get_bool(&sbrec_lb->options,
                                           "hairpin_orig_tuple",
                                           false);
    lb->ct_flush = smap_get_bool(&sbrec_lb->options, "ct_flush", false);
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

void
ovn_controller_lbs_destroy(struct hmap *ovn_controller_lbs)
{
    struct ovn_controller_lb *lb;
    HMAP_FOR_EACH_POP (lb, hmap_node, ovn_controller_lbs) {
        ovn_controller_lb_destroy(lb);
    }

    hmap_destroy(ovn_controller_lbs);
}

struct ovn_controller_lb *
ovn_controller_lb_find(const struct hmap *ovn_controller_lbs,
                       const struct uuid *uuid)
{
    struct ovn_controller_lb *lb;
    size_t hash = uuid_hash(uuid);
    HMAP_FOR_EACH_WITH_HASH (lb, hmap_node, hash, ovn_controller_lbs) {
        if (uuid_equals(&lb->slb->header_.uuid, uuid)) {
            return lb;
        }
    }
    return NULL;
}

static uint32_t
ovn_lb_5tuple_hash(const struct ovn_lb_5tuple *tuple)
{
    uint32_t hash = 0;

    hash = hash_add_in6_addr(hash, &tuple->vip_ip);
    hash = hash_add_in6_addr(hash, &tuple->backend_ip);

    hash = hash_add(hash, tuple->vip_port);
    hash = hash_add(hash, tuple->backend_port);

    hash = hash_add(hash, tuple->proto);

    return hash_finish(hash, 0);

}

void
ovn_lb_5tuple_init(struct ovn_lb_5tuple *tuple, const struct ovn_lb_vip *vip,
                   const struct ovn_lb_backend *backend, uint8_t proto)
{
    tuple->vip_ip = vip->vip;
    tuple->vip_port = vip->vip_port;
    tuple->backend_ip = backend->ip;
    tuple->backend_port = backend->port;
    tuple->proto = vip->vip_port ? proto : 0;
}

void
ovn_lb_5tuple_add(struct hmap *tuples, const struct ovn_lb_vip *vip,
                  const struct ovn_lb_backend *backend, uint8_t proto)
{
    struct ovn_lb_5tuple *tuple = xmalloc(sizeof *tuple);
    ovn_lb_5tuple_init(tuple, vip, backend, proto);
    hmap_insert(tuples, &tuple->hmap_node, ovn_lb_5tuple_hash(tuple));
}

void
ovn_lb_5tuple_find_and_delete(struct hmap *tuples,
                              const struct ovn_lb_5tuple *tuple)
{
    uint32_t hash = ovn_lb_5tuple_hash(tuple);

    struct ovn_lb_5tuple *node;
    HMAP_FOR_EACH_WITH_HASH (node, hmap_node, hash, tuples) {
        if (ipv6_addr_equals(&tuple->vip_ip, &node->vip_ip) &&
            ipv6_addr_equals(&tuple->backend_ip, &node->backend_ip) &&
            tuple->vip_port == node->vip_port &&
            tuple->backend_port == node->backend_port &&
            tuple->proto == node->proto) {
            hmap_remove(tuples, &node->hmap_node);
            free(node);
            return;
        }
    }
}

void
ovn_lb_5tuples_destroy(struct hmap *tuples)
{
    struct ovn_lb_5tuple *tuple;
    HMAP_FOR_EACH_POP (tuple, hmap_node, tuples) {
        free(tuple);
    }

    hmap_destroy(tuples);
}
