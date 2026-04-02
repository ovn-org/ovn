/* Copyright (c) 2026, Red Hat, Inc.
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
#include <linux/rtnetlink.h>
#include <linux/nexthop.h>

#include "lib/netlink.h"
#include "lib/netlink-socket.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "packets.h"

#include "nexthop-exchange.h"

VLOG_DEFINE_THIS_MODULE(nexthop_exchange);

#define NETNL_REQ_BUFFER_SIZE 128

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static int nh_table_parse__(struct ofpbuf *, size_t ofs,
                            const struct nlmsghdr *,
                            struct nh_table_msg *);
static void nh_populate_grp_pointers(struct nexthop_entry *, struct hmap *);
static uint32_t nexthop_entry_hash(uint32_t id);

/* The following definition should be available in Linux 6.12 and might be
 * missing if we have older headers. */
#ifndef HAVE_NH_GRP_WEIGHT
static uint16_t
nexthop_grp_weight(const struct nexthop_grp *entry)
{
    return entry->weight + 1;
}
#endif

/* Populates 'nexthops' with all nexthop entries
 * (struct nexthop_entry) with fdb flag set that exist in the table. */
void
nexthops_sync(struct hmap *nexthops)
{
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct ofpbuf request, reply, buf;
    struct nl_dump dump;

    uint8_t request_stub[NETNL_REQ_BUFFER_SIZE];
    ofpbuf_use_stub(&request, request_stub, sizeof request_stub);

    nl_msg_put_nlmsghdr(&request, sizeof(struct nhmsg),
                        RTM_GETNEXTHOP, NLM_F_REQUEST);
    ofpbuf_put_zeros(&request, sizeof(struct nhmsg));
    nl_dump_start(&dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);
    while (nl_dump_next(&dump, &reply, &buf)) {
        struct nh_table_msg msg;

        if (!nh_table_parse(&reply, &msg)) {
            continue;
        }

        hmap_insert(nexthops, &msg.nhe->hmap_node,
                    nexthop_entry_hash(msg.nhe->id));
    }
    ofpbuf_uninit(&buf);
    nl_dump_done(&dump);

    struct nexthop_entry *nhe;
    HMAP_FOR_EACH (nhe, hmap_node, nexthops) {
        nh_populate_grp_pointers(nhe, nexthops);
    }
}

void
nexthop_entry_format(struct ds *ds, const struct nexthop_entry *nhe)
{
    ds_put_format(ds, "id=%"PRIu32", ", nhe->id);
    if (!nhe->n_grps) {
        ds_put_cstr(ds, "address=");
        ipv6_format_mapped(&nhe->addr, ds);
    } else {
        ds_put_cstr(ds, "group=[");
        for (size_t i = 0; i < nhe->n_grps; i++) {
            const struct nexthop_grp_entry *grp = &nhe->grps[i];
            ds_put_format(ds, "%"PRIu32";", grp->id);
            if (grp->gateway) {
                ipv6_format_mapped(&grp->gateway->addr, ds);
                ds_put_char(ds, ';');
            }
            ds_put_format(ds, "%"PRIu16", ", grp->weight);
        }

        ds_truncate(ds, ds->length - 2);
        ds_put_char(ds, ']');
    }
}

/* Parse Netlink message in buf, which is expected to contain a UAPI nhmsg
 * header and associated nexthop attributes. This will allocate
 * 'struct nexthop_entry' which needs to be freed by the caller.
 *
 * Return RTNLGRP_NEXTHOP on success, and 0 on a parse error. */
int
nh_table_parse(struct ofpbuf *buf, struct nh_table_msg *change)
{
    struct nlmsghdr *nlmsg = ofpbuf_at(buf, 0, NLMSG_HDRLEN);
    struct nhmsg *nh = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *nh);

    if (!nlmsg || !nh) {
        return 0;
    }

    return nh_table_parse__(buf, NLMSG_HDRLEN + sizeof *nh,
                            nlmsg, change);
}

static int
nh_table_parse__(struct ofpbuf *buf, size_t ofs, const struct nlmsghdr *nlmsg,
                 struct nh_table_msg *change)
{
    bool parsed;

    static const struct nl_policy policy[] = {
        [NHA_ID] = { .type = NL_A_U32 },
        [NHA_FDB] = { .type = NL_A_FLAG, .optional = true },
        [NHA_GROUP] = { .type = NL_A_UNSPEC, .optional = true,
                        .min_len = sizeof(struct nexthop_grp) },
        [NHA_GATEWAY] = { .type = NL_A_UNSPEC, .optional = true,
                          .min_len = sizeof(struct in_addr),
                          .max_len = sizeof(struct in6_addr) },
    };

    struct nlattr *attrs[ARRAY_SIZE(policy)];
    parsed = nl_policy_parse(buf, ofs, policy, attrs, ARRAY_SIZE(policy));

    if (!parsed) {
        VLOG_DBG_RL(&rl, "received unparseable rtnetlink nexthop message");
        return 0;
    }

    if (!nl_attr_get_flag(attrs[NHA_FDB])) {
        return 0;
    }

    const struct nexthop_grp *grps = NULL;
    struct in6_addr addr = in6addr_any;
    size_t n_grps = 0;

    if (attrs[NHA_GATEWAY]) {
        size_t nda_dst_size = nl_attr_get_size(attrs[NHA_GATEWAY]);

        switch (nda_dst_size) {
        case sizeof(uint32_t):
            in6_addr_set_mapped_ipv4(&addr,
                                     nl_attr_get_be32(attrs[NHA_GATEWAY]));
            break;
        case sizeof(struct in6_addr):
            addr = nl_attr_get_in6_addr(attrs[NHA_GATEWAY]);
            break;
        default:
            VLOG_DBG_RL(&rl,
                        "nexthop message contains non-IPv4/IPv6 NHA_GATEWAY");
            return 0;
        }
    } else if (attrs[NHA_GROUP]) {
        n_grps = nl_attr_get_size(attrs[NHA_GROUP]) / sizeof *grps;
        grps = nl_attr_get(attrs[NHA_GROUP]);
    } else {
        VLOG_DBG_RL(&rl, "missing group or gateway nexthop attribute");
        return 0;
    }

    size_t grp_size = n_grps * sizeof(struct nexthop_grp_entry);
    change->nlmsg_type = nlmsg->nlmsg_type;
    change->nhe = xmalloc(sizeof *change->nhe + grp_size);
    *change->nhe = (struct nexthop_entry) {
        .id = nl_attr_get_u32(attrs[NHA_ID]),
        .addr = addr,
        .n_grps = n_grps,
    };

    for (size_t i = 0; i < n_grps; i++) {
        const struct nexthop_grp *grp = &grps[i];
        change->nhe->grps[i] = (struct nexthop_grp_entry) {
            .id = grp->id,
            .weight = nexthop_grp_weight(grp),
            /* We need to parse all entries first before adjusting
             * the references in 'nh_populate_grp_pointers()' */
            .gateway = NULL,
        };
    }

    /* Success. */
    return RTNLGRP_NEXTHOP;
}

static uint32_t
nexthop_entry_hash(uint32_t id)
{
    return hash_int(id, 0);
}

static struct nexthop_entry *
nexthop_find(struct hmap *nexthops, uint32_t id)
{
    uint32_t hash = nexthop_entry_hash(id);
    struct nexthop_entry *nhe;
    HMAP_FOR_EACH_WITH_HASH (nhe, hmap_node, hash, nexthops) {
        if (nhe->id == id) {
            return nhe;
        }
    }

    return NULL;
}

static void
nh_populate_grp_pointers(struct nexthop_entry *nhe, struct hmap *nexthops)
{
    for (size_t i = 0; i < nhe->n_grps; i++) {
        struct nexthop_grp_entry *grp = &nhe->grps[i];
        grp->gateway = nexthop_find(nexthops, grp->id);
    }
}
