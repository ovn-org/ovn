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

/* OpenvSwitch lib includes. */
#include "openvswitch/vlog.h"
#include "lib/smap.h"

/* OVN includes */
#include "lb.h"
#include "lib/ovn-sb-idl.h"
#include "ovn/lex.h"

VLOG_DEFINE_THIS_MODULE(controller_lb);

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

