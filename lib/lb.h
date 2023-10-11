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

struct uuid;

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

char *ovn_lb_vip_init(struct ovn_lb_vip *lb_vip, const char *lb_key,
                      const char *lb_value, bool template, int address_family);
char *ovn_lb_vip_init_explicit(struct ovn_lb_vip *lb_vip, const char *lb_key,
                               const char *lb_value);
void ovn_lb_vip_destroy(struct ovn_lb_vip *vip);
void ovn_lb_vip_format(const struct ovn_lb_vip *vip, struct ds *s,
                       bool template);
void ovn_lb_vip_backends_format(const struct ovn_lb_vip *vip, struct ds *s);
char *ovn_lb_vip6_template_format_internal(const struct ovn_lb_vip *vip);

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
