/* Copyright (c) 2025, Red Hat, Inc.
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
#include <stdbool.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>

#include "hmapx.h"
#include "lib/netlink.h"
#include "lib/netlink-socket.h"
#include "lib/packets.h"
#include "openvswitch/vlog.h"

#include "neighbor-exchange-netlink.h"
#include "neighbor.h"

VLOG_DEFINE_THIS_MODULE(neighbor_exchange_netlink);

#define NETNL_REQ_BUFFER_SIZE 128

/* NTF_EXT_LEARNED was introduced in Linux v3.19, define it if
 * not available. */
#ifndef NTF_EXT_LEARNED
#define NTF_EXT_LEARNED (1 << 4)
#endif

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

/* Inspired from route_table_dump_one_table() in OVS. */
typedef void ne_table_handle_msg_callback(const struct ne_table_msg *,
                                          void *aux);
static void ne_table_dump_one_ifindex(unsigned char address_family,
                                      int32_t if_index,
                                      ne_table_handle_msg_callback *,
                                      void *aux);
struct ne_msg_handle_data {
    /* Stores 'struct advertise_neighbor_entry'. */
    struct hmapx *neighbors_to_advertise;

    /* Stores 'struct ne_nl_received_neigh'. */
    struct vector *learned_neighbors;

    /* Stores 'struct ne_nl_received_neigh'. */
    struct vector *stale_neighbors;

    /* Stores 'struct advertise_neighbor_entry'. */
    const struct hmap *neighbors;

    /* Non-zero error code if any netlink operation failed. */
    int ret;
};

static void handle_ne_msg(const struct ne_table_msg *, void *data);

static int ne_table_parse__(struct ofpbuf *, size_t ofs,
                            const struct nlmsghdr *,
                            const struct ndmsg *,
                            struct ne_table_msg *);
static int ne_nl_add_neigh(int32_t if_index, uint8_t family,
                           uint16_t state, uint8_t flags,
                           const struct eth_addr *,
                           const struct in6_addr *,
                           uint16_t port, uint16_t vlan);
static int ne_nl_del_neigh(int32_t if_index, uint8_t family,
                           const struct eth_addr *,
                           const struct in6_addr *,
                           uint16_t port, uint16_t vlan);

/* Inserts all neigh entries listed in 'neighbors' (of type
 * 'struct advertise_neighbor_entry') in the table associated to
 * 'if_index'.  Populates 'learned_neighbors' with all neigh entries
 * (struct ne_nl_received_neigh) that exist in the table associated to
 * 'if_index'.
 *
 * Returns 0 on success, errno on failure. */
int
ne_nl_sync_neigh(uint8_t family, int32_t if_index,
                 const struct hmap *neighbors,
                 struct vector *learned_neighbors)
{
    struct hmapx neighbors_to_advertise =
        HMAPX_INITIALIZER(&neighbors_to_advertise);
    struct vector stale_neighbors =
        VECTOR_EMPTY_INITIALIZER(struct ne_nl_received_neigh);
    struct advertise_neighbor_entry *an;
    int ret;

    HMAP_FOR_EACH (an, node, neighbors) {
        hmapx_add(&neighbors_to_advertise, an);
    }

    struct ne_msg_handle_data data = {
        .neighbors_to_advertise = &neighbors_to_advertise,
        .learned_neighbors = learned_neighbors,
        .stale_neighbors = &stale_neighbors,
        .neighbors = neighbors,
    };
    ne_table_dump_one_ifindex(family, if_index, handle_ne_msg, &data);
    ret = data.ret;

    /* Add any remaining neighbors in the neighbors_to_advertise hmapx to the
     * system table. */
    struct hmapx_node *hn;
    HMAPX_FOR_EACH (hn, &neighbors_to_advertise) {
        an = hn->data;
        int err = ne_nl_add_neigh(if_index, family,
                                  NUD_NOARP,        /* state = static */
                                  0,                /* flags */
                                  &an->lladdr, &an->addr,
                                  0,                /* port */
                                  0);               /* vlan */
        if (err) {
            char addr_s[INET6_ADDRSTRLEN + 1];
            VLOG_WARN_RL(&rl, "Add neigh ifindex=%"PRId32
                              " eth=" ETH_ADDR_FMT " dst=%s"
                              " failed: %s",
                         if_index, ETH_ADDR_ARGS(an->lladdr),
                         ipv6_string_mapped(
                             addr_s, &an->addr) ? addr_s : "(invalid)",
                         ovs_strerror(err));
            if (!ret) {
                /* Report the first error value to the caller. */
                ret = err;
            }
        }
    }

    /* Remove any stale neighbors from the system table. */
    struct ne_nl_received_neigh *ne;
    VECTOR_FOR_EACH_PTR (&stale_neighbors, ne) {
        int err = ne_nl_del_neigh(ne->if_index, ne->family,
                                  &ne->lladdr, &ne->addr,
                                  ne->port, ne->vlan);
        if (err) {
            char addr_s[INET6_ADDRSTRLEN + 1];
            VLOG_WARN_RL(&rl, "Delete neigh ifindex=%"PRId32" vlan=%"PRIu16
                              " eth=" ETH_ADDR_FMT " dst=%s port=%"PRIu16
                              " failed: %s",
                         ne->if_index, ne->vlan, ETH_ADDR_ARGS(ne->lladdr),
                         ipv6_string_mapped(addr_s, &ne->addr)
                         ? addr_s : "(invalid)",
                         ne->port,
                         ovs_strerror(err));
            if (!ret) {
                /* Report the first error value to the caller. */
                ret = err;
            }
        }
    }

    hmapx_destroy(&neighbors_to_advertise);
    vector_destroy(&stale_neighbors);
    return ret;
}

/* OVN expects all static entries added on this ifindex to be OVN-owned.
 * Everything else must be learnt. */
bool
ne_is_ovn_owned(const struct ne_nl_received_neigh *nd)
{
    return !(nd->state & NUD_PERMANENT) && (nd->state & NUD_NOARP)
           && !(nd->flags & NTF_EXT_LEARNED);
}

static void
ne_table_dump_one_ifindex(unsigned char address_family, int32_t if_index,
                          ne_table_handle_msg_callback *handle_msg_cb,
                          void *aux)
{
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct ofpbuf request, reply, buf;
    struct ndmsg *rq_msg;
    struct nl_dump dump;

    uint8_t request_stub[NETNL_REQ_BUFFER_SIZE];
    ofpbuf_use_stub(&request, request_stub, sizeof request_stub);

    nl_msg_put_nlmsghdr(&request, sizeof *rq_msg, RTM_GETNEIGH, NLM_F_REQUEST);
    rq_msg = ofpbuf_put_zeros(&request, sizeof *rq_msg);
    rq_msg->ndm_family = address_family;
    if (if_index) {
        nl_msg_put_u32(&request, NDA_IFINDEX, if_index);
    }

    nl_dump_start(&dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);
    while (nl_dump_next(&dump, &reply, &buf)) {
        struct ne_table_msg msg;

        if (ne_table_parse(&reply, &msg)) {
            struct nlmsghdr *nlmsghdr = nl_msg_nlmsghdr(&reply);

            /* Older kernels do not support filtering.  If so, we
             * filter ourselves. */
            if (!(nlmsghdr->nlmsg_flags & NLM_F_DUMP_FILTERED)) {
                if (msg.nd.family != address_family
                    || (if_index && msg.nd.if_index != if_index)) {
                    continue;
                }
            }
            handle_msg_cb(&msg, aux);
        }
    }
    ofpbuf_uninit(&buf);
    nl_dump_done(&dump);
}

static int
ne_table_parse__(struct ofpbuf *buf, size_t ofs, const struct nlmsghdr *nlmsg,
                 const struct ndmsg *nd, struct ne_table_msg *change)
{
    bool parsed;

    static const struct nl_policy policy[] = {
        [NDA_DST] = { .type = NL_A_U32, .optional = true },
        [NDA_LLADDR] = { .type = NL_A_LL_ADDR, .optional = true },
        [NDA_PORT] = { .type = NL_A_U16, .optional = true },
    };

    static const struct nl_policy policy6[] = {
        [NDA_DST] = { .type = NL_A_IPV6, .optional = true },
        [NDA_LLADDR] = { .type = NL_A_LL_ADDR, .optional = true },
        [NDA_PORT] = { .type = NL_A_U16, .optional = true },
    };

    static const struct nl_policy policy_bridge[] = {
        [NDA_DST] = { .type = NL_A_UNSPEC, .optional = true,
                      .min_len = sizeof(struct in_addr),
                      .max_len = sizeof(struct in6_addr)},
        [NDA_LLADDR] = { .type = NL_A_LL_ADDR, .optional = true },
        [NDA_PORT] = { .type = NL_A_U16, .optional = true },
        [NDA_VLAN] = { .type = NL_A_U16, .optional = true },
    };

    BUILD_ASSERT(ARRAY_SIZE(policy) == ARRAY_SIZE(policy6));
    BUILD_ASSERT(ARRAY_SIZE(policy) == ARRAY_SIZE(policy_bridge));
    struct nlattr *attrs[ARRAY_SIZE(policy)];

    if (nd->ndm_family == AF_INET) {
        parsed = nl_policy_parse(buf, ofs, policy, attrs,
                                 ARRAY_SIZE(policy));
    } else if (nd->ndm_family == AF_INET6) {
        parsed = nl_policy_parse(buf, ofs, policy6, attrs,
                                 ARRAY_SIZE(policy6));
    } else if (nd->ndm_family == AF_BRIDGE) {
        parsed = nl_policy_parse(buf, ofs, policy_bridge, attrs,
                                 ARRAY_SIZE(policy_bridge));
    } else {
        VLOG_WARN_RL(&rl, "received non AF_INET/AF_INET6/AF_BRIDGE rtnetlink "
                          "neigh message");
        return 0;
    }

    if (parsed) {
        *change = (struct ne_table_msg) {
            .nlmsg_type = nlmsg->nlmsg_type,
            .nd.if_index = nd->ndm_ifindex,
            .nd.family = nd->ndm_family,
            .nd.state = nd->ndm_state,
            .nd.flags = nd->ndm_flags,
            .nd.type = nd->ndm_type,
        };

        if (attrs[NDA_DST]) {
            size_t nda_dst_size = nl_attr_get_size(attrs[NDA_DST]);

            switch (nda_dst_size) {
            case sizeof(uint32_t):
                in6_addr_set_mapped_ipv4(&change->nd.addr,
                                         nl_attr_get_be32(attrs[NDA_DST]));
                break;
            case sizeof(struct in6_addr):
                change->nd.addr = nl_attr_get_in6_addr(attrs[NDA_DST]);
                break;
            default:
                VLOG_DBG_RL(&rl,
                            "neigh message contains non-IPv4/IPv6 NDA_DST");
                return 0;
            }
        }

        if (attrs[NDA_LLADDR]) {
            if (nl_attr_get_size(attrs[NDA_LLADDR]) != ETH_ALEN) {
                VLOG_DBG_RL(&rl, "neigh message contains non-ETH NDA_LLADDR");
                return 0;
            }
            change->nd.lladdr = nl_attr_get_eth_addr(attrs[NDA_LLADDR]);
        }

        if (attrs[NDA_PORT]) {
            change->nd.port = ntohs(nl_attr_get_be16(attrs[NDA_PORT]));
        }

        if (attrs[NDA_VLAN]) {
            change->nd.vlan = nl_attr_get_u16(attrs[NDA_VLAN]);
        }
    } else {
        VLOG_DBG_RL(&rl, "received unparseable rtnetlink neigh message");
        return 0;
    }

    /* Success. */
    return RTNLGRP_NEIGH;
}

static void
handle_ne_msg(const struct ne_table_msg *msg, void *data)
{
    struct ne_msg_handle_data *handle_data = data;
    const struct ne_nl_received_neigh *nd = &msg->nd;

    /* OVN only manages VLAN 0 entries. */
    if (nd->vlan) {
        return;
    }

    if (!ne_is_ovn_owned(nd)) {
        if (!handle_data->learned_neighbors) {
            return;
        }

        /* Learn the non-OVN entry. */
        vector_push(handle_data->learned_neighbors, nd);
        return;
    }

    /* This neighbor was presumably added by OVN, see if it's still valid.
     * OVN only adds neighbors with port set to 0, all others can be
     * removed. */
    if (!nd->port && handle_data->neighbors_to_advertise) {
        struct advertise_neighbor_entry *an =
            advertise_neigh_find(handle_data->neighbors, nd->lladdr,
                                 &nd->addr);
        if (an) {
            hmapx_find_and_delete(handle_data->neighbors_to_advertise, an);
            return;
        }
    }

    /* Store the entry for deletion. */
    if (handle_data->stale_neighbors) {
        vector_push(handle_data->stale_neighbors, nd);
    }
}

static int
ne_nl_add_neigh(int32_t if_index, uint8_t family,
                uint16_t state, uint8_t flags,
                const struct eth_addr *lladdr,
                const struct in6_addr *addr,
                uint16_t port, uint16_t vlan)
{
    uint32_t nl_flags = NLM_F_REQUEST | NLM_F_ACK |
                        NLM_F_CREATE | NLM_F_REPLACE;
    bool dst_set = !ipv6_is_zero(addr);
    struct ofpbuf request;
    uint8_t request_stub[NETNL_REQ_BUFFER_SIZE];
    ofpbuf_use_stub(&request, request_stub, sizeof request_stub);

    nl_msg_put_nlmsghdr(&request, 0, RTM_NEWNEIGH, nl_flags);

    struct ndmsg *nd = ofpbuf_put_zeros(&request, sizeof *nd);
    *nd = (struct ndmsg) {
        .ndm_family = family,
        .ndm_ifindex = if_index,
        .ndm_state = state,
        .ndm_flags = flags,
    };

    nl_msg_put_unspec(&request, NDA_LLADDR, lladdr, sizeof *lladdr);
    if (dst_set) {
        if (IN6_IS_ADDR_V4MAPPED(addr)) {
            nl_msg_put_be32(&request, NDA_DST, in6_addr_get_mapped_ipv4(addr));
        } else {
            nl_msg_put_in6_addr(&request, NDA_DST, addr);
        }
    }
    if (port) {
        nl_msg_put_u16(&request, NDA_PORT, port);
    }
    if (vlan) {
        nl_msg_put_u16(&request, NDA_VLAN, vlan);
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        ds_put_format(&msg, "Adding neighbor ifindex %"PRId32 " for eth "
                            ETH_ADDR_FMT " port %"PRIu16" vlan %"PRIu16,
                            if_index, ETH_ADDR_ARGS(*lladdr),
                            port, vlan);
        if (dst_set) {
            ipv6_format_mapped(addr, &msg);
        }
        VLOG_DBG("%s", ds_cstr(&msg));
        ds_destroy(&msg);
    }

    int err = nl_transact(NETLINK_ROUTE, &request, NULL);

    ofpbuf_uninit(&request);
    return err;
}

static int
ne_nl_del_neigh(int32_t if_index, uint8_t family,
                const struct eth_addr *lladdr,
                const struct in6_addr *addr,
                uint16_t port, uint16_t vlan)
{
    uint32_t flags = NLM_F_REQUEST | NLM_F_ACK;
    bool dst_set = !ipv6_is_zero(addr);
    struct ofpbuf request;
    uint8_t request_stub[NETNL_REQ_BUFFER_SIZE];
    ofpbuf_use_stub(&request, request_stub, sizeof request_stub);

    nl_msg_put_nlmsghdr(&request, 0, RTM_DELNEIGH, flags);

    struct ndmsg *nd = ofpbuf_put_zeros(&request, sizeof *nd);
    *nd = (struct ndmsg) {
        .ndm_family = family,
        .ndm_ifindex = if_index,
    };

    nl_msg_put_unspec(&request, NDA_LLADDR, lladdr, sizeof *lladdr);
    if (dst_set) {
        if (IN6_IS_ADDR_V4MAPPED(addr)) {
            nl_msg_put_be32(&request, NDA_DST, in6_addr_get_mapped_ipv4(addr));
        } else {
            nl_msg_put_in6_addr(&request, NDA_DST, addr);
        }
    }
    if (port) {
        nl_msg_put_u16(&request, NDA_PORT, port);
    }
    if (vlan) {
        nl_msg_put_u16(&request, NDA_VLAN, vlan);
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        ds_put_format(&msg, "Removing neighbor ifindex %"PRId32 " for eth "
                            ETH_ADDR_FMT " port %"PRIu16" vlan %"PRIu16,
                            if_index, ETH_ADDR_ARGS(*lladdr),
                            port, vlan);
        if (dst_set) {
            ds_put_char(&msg, ' ');
            ipv6_format_mapped(addr, &msg);
        }
        VLOG_DBG("%s", ds_cstr(&msg));
        ds_destroy(&msg);
    }

    int err = nl_transact(NETLINK_ROUTE, &request, NULL);

    ofpbuf_uninit(&request);
    return err;
}

/* Parse Netlink message in buf, which is expected to contain a UAPI ndmsg
 * header and associated neighbor attributes.
 *
 * Return RTNLGRP_NEIGH on success, and 0 on a parse error. */
int
ne_table_parse(struct ofpbuf *buf, void *change)
{
    struct nlmsghdr *nlmsg = ofpbuf_at(buf, 0, NLMSG_HDRLEN);
    struct ndmsg *nd = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *nd);

    if (!nlmsg || !nd) {
        return 0;
    }

    return ne_table_parse__(buf, NLMSG_HDRLEN + sizeof *nd,
                            nlmsg, nd, change);
}
