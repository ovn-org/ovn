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

#ifndef OVN_NORTHD_LB_H
#define OVN_NORTHD_LB_H 1

#include "openvswitch/hmap.h"
#include "hmapx.h"
#include "uuid.h"

#include "lib/lb.h"

struct nbrec_load_balancer;
struct nbrec_load_balancer_group;
struct ovn_datapath;

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

    /* Indicates if the load balancer has health checks configured. */
    bool health_checks;

    char *hairpin_snat_ip;
};

/* ovn-northd specific backend information. */
struct ovn_northd_lb_vip {
    char *backend_ips;
    struct ovn_northd_lb_backend *backends_nb;
    size_t n_backends;

    struct nbrec_load_balancer_health_check *lb_health_check;
};

struct ovn_northd_lb_backend {
    bool health_check;
     /* Set to true if port does not locate in local AZ. */
    bool remote_backend;
    /* Logical port to which the ip belong to. */
    char *logical_port;
    /* Source IP address to be used for service monitoring. */
    char *svc_mon_src_ip;
    /* Target Availability Zone name for service monitoring. */
    char *az_name;
};

struct ovn_northd_lb *ovn_northd_lb_create(const struct nbrec_load_balancer *);
struct ovn_northd_lb *ovn_northd_lb_find(const struct hmap *,
                                         const struct uuid *);
const struct smap *ovn_northd_lb_get_vips(const struct ovn_northd_lb *);
void ovn_northd_lb_destroy(struct ovn_northd_lb *);
void ovn_northd_lb_reinit(struct ovn_northd_lb *,
                          const struct nbrec_load_balancer *);

void build_lrouter_lb_ips(struct ovn_lb_ip_set *,
                          const struct ovn_northd_lb *);
void add_ips_to_lb_ip_set(struct ovn_lb_ip_set *lb_ips,
                          bool is_routable,
                          const struct sset *lb_ips_v4,
                          const struct sset *lb_ips_v6);
void remove_ips_from_lb_ip_set(struct ovn_lb_ip_set *lb_ips,
                               bool is_routable,
                               const struct sset *lb_ips_v4,
                               const struct sset *lb_ips_v6);

struct ovn_lb_group {
    struct hmap_node hmap_node;
    struct uuid uuid;
    size_t n_lbs;
    struct ovn_northd_lb **lbs;
    struct ovn_lb_ip_set *lb_ips;
    bool has_routable_lb;
};

struct ovn_lb_group *ovn_lb_group_create(
    const struct nbrec_load_balancer_group *,
    const struct hmap *lbs);
void ovn_lb_group_destroy(struct ovn_lb_group *lb_group);
struct ovn_lb_group *ovn_lb_group_find(const struct hmap *lb_groups,
                                       const struct uuid *);
void ovn_lb_group_reinit(
    struct ovn_lb_group *lb_group,
    const struct nbrec_load_balancer_group *,
    const struct hmap *lbs);

struct lflow_ref;
struct ovn_lb_datapaths {
    struct hmap_node hmap_node;

    const struct ovn_northd_lb *lb;

    struct dynamic_bitmap nb_ls_map;
    struct dynamic_bitmap nb_lr_map;

    struct hmapx ls_lb_with_stateless_mode;

    /* Reference of lflows generated for this load balancer.
     *
     * This data is initialized and destroyed by the en_northd node, but
     * populated and used only by the en_lflow node. Ideally this data should
     * be maintained as part of en_lflow's data (struct lflow_data): a hash
     * index from ovn_port key to lflows.  However, it would be less efficient
     * and more complex:
     *
     * 1. It would require an extra search (using the index) to find the
     * lflows.
     *
     * 2. Building the index needs to be thread-safe, using either a global
     * lock which is obviously less efficient, or hash-based lock array which
     * is more complex.
     *
     * Maintaining the lflow_ref here is more straightforward. The drawback is
     * that we need to keep in mind that this data belongs to en_lflow node,
     * so never access it from any other nodes.
     *
     * 'lflow_ref' is used to reference logical flows generated for this
     *  load balancer.
     *
     * Note: lflow_ref is not thread safe.  Only one thread should
     * access ovn_lb_datapaths->lflow_ref at any given time.
     */
    struct lflow_ref *lflow_ref;
};

struct ovn_lb_datapaths *ovn_lb_datapaths_create(const struct ovn_northd_lb *,
                                                 size_t n_ls_datapaths,
                                                 size_t n_lr_datapaths);
struct ovn_lb_datapaths *ovn_lb_datapaths_find(const struct hmap *,
                                               const struct uuid *);
void ovn_lb_datapaths_destroy(struct ovn_lb_datapaths *);

void ovn_lb_datapaths_add_lr(struct ovn_lb_datapaths *, size_t n,
                             struct ovn_datapath **,
                             size_t n_lr_datapaths);
void ovn_lb_datapaths_add_ls(struct ovn_lb_datapaths *, size_t n,
                             struct ovn_datapath **,
                             size_t n_ls_datapaths);

struct ovn_lb_group_datapaths {
    struct hmap_node hmap_node;

    const struct ovn_lb_group *lb_group;

    /* Datapaths to which 'lb_group' is applied. */
    struct vector ls;
    struct vector lr;
};

struct ovn_lb_group_datapaths *ovn_lb_group_datapaths_create(
    const struct ovn_lb_group *, size_t max_ls_datapaths,
    size_t max_lr_datapaths);

void ovn_lb_group_datapaths_destroy(struct ovn_lb_group_datapaths *);
struct ovn_lb_group_datapaths *ovn_lb_group_datapaths_find(
    const struct hmap *lb_group_dps, const struct uuid *);

static inline void
ovn_lb_group_datapaths_add_ls(struct ovn_lb_group_datapaths *lbg_dps, size_t n,
                              struct ovn_datapath **ods)
{
    vector_push_array(&lbg_dps->ls, ods, n);
}

static inline void
ovn_lb_group_datapaths_add_lr(struct ovn_lb_group_datapaths *lbg_dps,
                              struct ovn_datapath *lr)
{
    vector_push(&lbg_dps->lr, &lr);
}

#endif /* OVN_NORTHD_LB_H */
