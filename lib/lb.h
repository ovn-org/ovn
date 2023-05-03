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


#ifndef OVN_LIB_LB_H
#define OVN_LIB_LB_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include "lib/smap.h"
#include "openvswitch/hmap.h"
#include "ovn-util.h"
#include "sset.h"
#include "uuid.h"

struct nbrec_load_balancer;
struct nbrec_load_balancer_group;
struct sbrec_load_balancer;
struct sbrec_datapath_binding;
struct ovn_datapath;
struct ovn_dp_group;
struct ovn_port;
struct uuid;

enum lb_neighbor_responder_mode {
    LB_NEIGH_RESPOND_REACHABLE,
    LB_NEIGH_RESPOND_ALL,
    LB_NEIGH_RESPOND_NONE,
};

/* The "routable" ssets are subsets of the load balancer IPs for which IP
 * routes and ARP resolution flows are automatically added. */
struct ovn_lb_ip_set {
    struct sset ips_v4;
    struct sset ips_v4_routable;
    struct sset ips_v4_reachable;
    struct sset ips_v6;
    struct sset ips_v6_routable;
    struct sset ips_v6_reachable;
};

struct ovn_lb_ip_set *ovn_lb_ip_set_create(void);
void ovn_lb_ip_set_destroy(struct ovn_lb_ip_set *);
struct ovn_lb_ip_set *ovn_lb_ip_set_clone(struct ovn_lb_ip_set *);

struct ovn_northd_lb {
    struct hmap_node hmap_node;

    const struct nbrec_load_balancer *nlb; /* May be NULL. */
    const struct sbrec_load_balancer *slb; /* May be NULL. */
    const char *proto;
    char *selection_fields;
    struct ovn_lb_vip *vips;
    struct ovn_northd_lb_vip *vips_nb;
    struct smap template_vips; /* Slightly changed template VIPs, populated
                                * if needed.  Until now it's only required
                                * for IPv6 template load balancers. */
    size_t n_vips;

    enum lb_neighbor_responder_mode neigh_mode;
    bool controller_event;
    bool routable;
    bool skip_snat;
    bool template;
    uint16_t affinity_timeout;

    struct sset ips_v4;
    struct sset ips_v6;

    size_t n_nb_ls;
    unsigned long *nb_ls_map;

    size_t n_nb_lr;
    unsigned long *nb_lr_map;

    struct ovn_dp_group *dpg;
};

struct ovn_lb_vip {
    struct in6_addr vip; /* Only used in ovn-controller. */
    char *vip_str;       /* Actual VIP string representation (without port).
                          * To be used in ovn-northd.
                          */
    uint16_t vip_port;   /* Only used in ovn-controller. */
    char *port_str;      /* Actual port string representation.  To be used
                          * in ovn-northd.
                          */
    struct ovn_lb_backend *backends;
    size_t n_backends;
    bool template_backends; /* True if the backends are templates. False if
                             * they're explicitly specified.
                             */
    bool empty_backend_rej;
    int address_family;
};

struct ovn_lb_backend {
    struct in6_addr ip;  /* Only used in ovn-controller. */
    char *ip_str;        /* Actual IP string representation. To be used in
                          * ovn-northd.
                          */
    uint16_t port;       /* Mostly used in ovn-controller but also for
                          * healthcheck in ovn-northd.
                          */
    char *port_str;      /* Actual port string representation. To be used
                          * in ovn-northd.
                          */
};

/* ovn-northd specific backend information. */
struct ovn_northd_lb_vip {
    char *backend_ips;
    struct ovn_northd_lb_backend *backends_nb;
    size_t n_backends;

    struct nbrec_load_balancer_health_check *lb_health_check;
};

struct ovn_northd_lb_backend {
    struct ovn_port *op; /* Logical port to which the ip belong to. */
    bool health_check;
    char *svc_mon_src_ip; /* Source IP to use for monitoring. */
    const struct sbrec_service_monitor *sbrec_monitor;
};

struct ovn_northd_lb *ovn_northd_lb_create(const struct nbrec_load_balancer *,
                                           size_t n_ls_datapaths,
                                           size_t n_lr_datapaths);
struct ovn_northd_lb *ovn_northd_lb_find(const struct hmap *,
                                         const struct uuid *);
const struct smap *ovn_northd_lb_get_vips(const struct ovn_northd_lb *);
void ovn_northd_lb_destroy(struct ovn_northd_lb *);
void ovn_northd_lb_add_lr(struct ovn_northd_lb *lb, size_t n,
                          struct ovn_datapath **ods);
void ovn_northd_lb_add_ls(struct ovn_northd_lb *lb, size_t n,
                          struct ovn_datapath **ods);

struct ovn_lb_group {
    struct hmap_node hmap_node;
    struct uuid uuid;
    size_t n_lbs;
    struct ovn_northd_lb **lbs;
    struct ovn_lb_ip_set *lb_ips;

    /* Datapaths to which this LB group is applied. */
    size_t n_ls;
    struct ovn_datapath **ls;
    size_t n_lr;
    struct ovn_datapath **lr;
};

struct ovn_lb_group *ovn_lb_group_create(
    const struct nbrec_load_balancer_group *,
    const struct hmap *lbs,
    size_t max_ls_datapaths,
    size_t max_lr_datapaths);
void ovn_lb_group_destroy(struct ovn_lb_group *lb_group);
struct ovn_lb_group *ovn_lb_group_find(const struct hmap *lb_groups,
                                       const struct uuid *);

static inline void
ovn_lb_group_add_ls(struct ovn_lb_group *lb_group, size_t n,
                    struct ovn_datapath **ods)
{
    memcpy(&lb_group->ls[lb_group->n_ls], ods, n * sizeof *ods);
    lb_group->n_ls += n;
}

static inline void
ovn_lb_group_add_lr(struct ovn_lb_group *lb_group, struct ovn_datapath *lr)
{
    lb_group->lr[lb_group->n_lr++] = lr;
}

struct ovn_controller_lb {
    struct hmap_node hmap_node;

    const struct sbrec_load_balancer *slb; /* May be NULL. */

    uint8_t proto;

    struct ovn_lb_vip *vips;
    size_t n_vips;
    bool hairpin_orig_tuple; /* True if ovn-northd stores the original
                              * destination tuple in registers.
                              */
    bool ct_flush; /* True if we should flush CT after backend removal. */

    struct lport_addresses hairpin_snat_ips; /* IP (v4 and/or v6) to be used
                                              * as source for hairpinned
                                              * traffic.
                                              */
};

struct ovn_controller_lb *ovn_controller_lb_create(
    const struct sbrec_load_balancer *,
    const struct smap *template_vars,
    struct sset *template_vars_ref);
void ovn_controller_lb_destroy(struct ovn_controller_lb *);
void ovn_controller_lbs_destroy(struct hmap *ovn_controller_lbs);
struct ovn_controller_lb *ovn_controller_lb_find(
    const struct hmap *ovn_controller_lbs,
    const struct uuid *uuid);

char *ovn_lb_vip_init(struct ovn_lb_vip *lb_vip, const char *lb_key,
                      const char *lb_value, bool template, int address_family);
void ovn_lb_vip_destroy(struct ovn_lb_vip *vip);
void ovn_lb_vip_format(const struct ovn_lb_vip *vip, struct ds *s,
                       bool template);
void ovn_lb_vip_backends_format(const struct ovn_lb_vip *vip, struct ds *s);

struct ovn_lb_5tuple {
    struct hmap_node hmap_node;

    struct in6_addr vip_ip;
    uint16_t vip_port;

    struct in6_addr backend_ip;
    uint16_t backend_port;

    uint8_t proto;
};

void ovn_lb_5tuple_init(struct ovn_lb_5tuple *tuple,
                        const struct ovn_lb_vip *vip,
                        const struct ovn_lb_backend *backend, uint8_t proto);
void ovn_lb_5tuple_add(struct hmap *tuples, const struct ovn_lb_vip *vip,
                       const struct ovn_lb_backend *backend, uint8_t proto);
void ovn_lb_5tuple_find_and_delete(struct hmap *tuples,
                                   const struct ovn_lb_5tuple *tuple);
void ovn_lb_5tuples_destroy(struct hmap *tuples);

#endif /* OVN_LIB_LB_H 1 */
