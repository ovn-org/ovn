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
#include "openvswitch/hmap.h"
#include "ovn-util.h"
#include "sset.h"
#include "uuid.h"

struct nbrec_load_balancer;
struct nbrec_load_balancer_group;
struct sbrec_load_balancer;
struct sbrec_datapath_binding;
struct ovn_datapath;
struct ovn_port;
struct uuid;

enum lb_neighbor_responder_mode {
    LB_NEIGH_RESPOND_REACHABLE,
    LB_NEIGH_RESPOND_ALL,
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
    size_t n_vips;

    enum lb_neighbor_responder_mode neigh_mode;
    bool controller_event;
    bool routable;
    bool skip_snat;

    struct sset ips_v4;
    struct sset ips_v6;

    size_t n_nb_ls;
    size_t n_allocated_nb_ls;
    struct ovn_datapath **nb_ls;

    size_t n_nb_lr;
    size_t n_allocated_nb_lr;
    struct ovn_datapath **nb_lr;
};

struct ovn_lb_vip {
    struct in6_addr vip;
    char *vip_str;
    uint16_t vip_port;

    struct ovn_lb_backend *backends;
    size_t n_backends;
    bool empty_backend_rej;
};

struct ovn_lb_backend {
    struct in6_addr ip;
    char *ip_str;
    uint16_t port;
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

struct ovn_northd_lb *ovn_northd_lb_create(const struct nbrec_load_balancer *);
struct ovn_northd_lb *ovn_northd_lb_find(const struct hmap *,
                                         const struct uuid *);
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
    size_t max_datapaths);
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
    const struct sbrec_load_balancer *slb; /* May be NULL. */

    struct ovn_lb_vip *vips;
    size_t n_vips;
    bool hairpin_orig_tuple; /* True if ovn-northd stores the original
                              * destination tuple in registers.
                              */

    struct lport_addresses hairpin_snat_ips; /* IP (v4 and/or v6) to be used
                                              * as source for hairpinned
                                              * traffic.
                                              */
};

struct ovn_controller_lb *ovn_controller_lb_create(
    const struct sbrec_load_balancer *);
void ovn_controller_lb_destroy(struct ovn_controller_lb *);

#endif /* OVN_LIB_LB_H 1 */
