/* Copyright (c) 2021, Red Hat, Inc.
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
#include <stdlib.h>

#include "openvswitch/shash.h"
#include "db-ctl-base.h"
#include "smap.h"
#include "lib/ovn-nb-idl.h"
#include "lib/copp.h"

static char *copp_proto_names[COPP_PROTO_MAX] = {
    [COPP_ARP]           = "arp",
    [COPP_ARP_RESOLVE]   = "arp-resolve",
    [COPP_DHCPV4_OPTS]   = "dhcpv4-opts",
    [COPP_DHCPV6_OPTS]   = "dhcpv6-opts",
    [COPP_DNS]           = "dns",
    [COPP_EVENT_ELB]     = "event-elb",
    [COPP_ICMP4_ERR]     = "icmp4-error",
    [COPP_ICMP6_ERR]     = "icmp6-error",
    [COPP_IGMP]          = "igmp",
    [COPP_ND_NA]         = "nd-na",
    [COPP_ND_NS]         = "nd-ns",
    [COPP_ND_NS_RESOLVE] = "nd-ns-resolve",
    [COPP_ND_RA_OPTS]    = "nd-ra-opts",
    [COPP_TCP_RESET]     = "tcp-reset",
    [COPP_REJECT]        = "reject",
    [COPP_SVC_MONITOR]   = "svc-monitor",
    [COPP_BFD]           = "bfd",
};

static const char *
copp_proto_get_name(enum copp_proto proto)
{
    if (proto >= COPP_PROTO_MAX) {
        return "<Invalid control protocol ID>";
    }
    return copp_proto_names[proto];
}

const char *
copp_meter_get(enum copp_proto proto, const struct nbrec_copp *copp,
               const struct shash *meter_groups)
{
    if (!copp || proto >= COPP_PROTO_MAX) {
        return NULL;
    }

    const char *meter = smap_get(&copp->meters, copp_proto_names[proto]);

    if (meter && shash_find(meter_groups, meter)) {
        return meter;
    }

    return NULL;
}

void
copp_meter_list(struct ctl_context *ctx, const struct nbrec_copp *copp)
{
    if (!copp) {
        return;
    }

    struct smap_node *node;

    SMAP_FOR_EACH (node, &copp->meters) {
        ds_put_format(&ctx->output, "%s: %s\n", node->key, node->value);
    }
}

const struct nbrec_copp *
copp_meter_add(struct ctl_context *ctx, const struct nbrec_copp *copp,
               const char *proto_name, const char *meter)
{
    if (!copp) {
        copp = nbrec_copp_insert(ctx->txn);
    }

    struct smap meters;
    smap_init(&meters);
    smap_clone(&meters, &copp->meters);
    smap_replace(&meters, proto_name, meter);
    nbrec_copp_set_meters(copp, &meters);
    smap_destroy(&meters);

    return copp;
}

void
copp_meter_del(const struct nbrec_copp *copp, const char *proto_name)
{
    if (!copp) {
        return;
    }

    if (proto_name) {
        if (smap_get(&copp->meters, proto_name)) {
            struct smap meters;
            smap_init(&meters);
            smap_clone(&meters, &copp->meters);
            smap_remove(&meters, proto_name);
            nbrec_copp_set_meters(copp, &meters);
            smap_destroy(&meters);
        }
        if (smap_is_empty(&copp->meters)) {
            nbrec_copp_delete(copp);
        }
    } else {
        nbrec_copp_delete(copp);
    }
}

char *
copp_proto_validate(const char *proto_name)
{
    for (size_t i = COPP_PROTO_FIRST; i < COPP_PROTO_MAX; i++) {
        if (!strcmp(proto_name, copp_proto_get_name(i))) {
            return NULL;
        }
    }

    struct ds usage = DS_EMPTY_INITIALIZER;

    ds_put_cstr(&usage, "Invalid control protocol. Allowed values: ");
    for (size_t i = COPP_PROTO_FIRST; i < COPP_PROTO_MAX; i++) {
        ds_put_format(&usage, "%s, ", copp_proto_get_name(i));
    }
    ds_chomp(&usage, ' ');
    ds_chomp(&usage, ',');
    ds_put_cstr(&usage, ".");

    return ds_steal_cstr(&usage);
}

char * OVS_WARN_UNUSED_RESULT
copp_by_name_or_uuid(struct ctl_context *ctx, const char *id, bool must_exist,
                     const struct nbrec_copp **copp_p)
{
    const struct nbrec_copp *copp = NULL;
    struct uuid uuid;
    bool is_uuid = uuid_from_string(&uuid, id);

    *copp_p = NULL;
    if (is_uuid) {
        copp = nbrec_copp_get_for_uuid(ctx->idl, &uuid);
    }

    if (!copp) {
        const struct nbrec_copp *iter;
        NBREC_COPP_FOR_EACH (iter, ctx->idl) {
            if (!strcmp(iter->name, id)) {
                copp = iter;
                break;
            }
        }
    }

    if (!copp && must_exist) {
        return xasprintf("%s: copp %s not found",
                         id, is_uuid ? "UUID" : "name");
    }

    *copp_p = copp;
    return NULL;
}
