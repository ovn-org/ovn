/*
 * Copyright (c) 2025 Canonical, Ltd.
 * Copyright (c) 2025, STACKIT GmbH & Co. KG
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

#include <errno.h>
#include <inttypes.h>
#include <net/if.h>
#include <netinet/in.h>

#include "netlink-socket.h"
#include "openvswitch/hmap.h"
#include "hmapx.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovn-util.h"
#include "route-table.h"
#include "route.h"
#include "vec.h"

#include "route-exchange-netlink.h"

VLOG_DEFINE_THIS_MODULE(route_exchange_netlink);

#define NETNL_REQ_BUFFER_SIZE 128

static void re_nl_encode_nexthop(struct ofpbuf *, bool dst_is_ipv4,
                                 const struct in6_addr *);

int
re_nl_create_vrf(const char *ifname, uint32_t table_id)
{
    if (!TABLE_ID_VALID(table_id)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
        VLOG_WARN_RL(&rl,
                     "attempt to create VRF using invalid table id %"PRIu32,
                     table_id);
        return EINVAL;
    }

    size_t linkinfo_off, infodata_off;
    struct ifinfomsg *ifinfo;
    int err;

    struct ofpbuf request;
    uint8_t request_stub[NETNL_REQ_BUFFER_SIZE];
    ofpbuf_use_stub(&request, request_stub, sizeof(request_stub));

    nl_msg_put_nlmsghdr(&request, 0, RTM_NEWLINK,
                        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
    ifinfo = ofpbuf_put_zeros(&request, sizeof *ifinfo);
    nl_msg_put_string(&request, IFLA_IFNAME, ifname);

    ifinfo->ifi_change = ifinfo->ifi_flags = IFF_UP;
    linkinfo_off = nl_msg_start_nested(&request, IFLA_LINKINFO);
    nl_msg_put_string(&request, IFLA_INFO_KIND, "vrf");
    infodata_off = nl_msg_start_nested(&request, IFLA_INFO_DATA);
    nl_msg_put_u32(&request, IFLA_VRF_TABLE, table_id);
    nl_msg_end_nested(&request, infodata_off);
    nl_msg_end_nested(&request, linkinfo_off);

    err = nl_transact(NETLINK_ROUTE, &request, NULL);

    ofpbuf_uninit(&request);
    return err;
}

int
re_nl_delete_vrf(const char *ifname)
{
    struct ifinfomsg *ifinfo;
    int err;

    struct ofpbuf request;
    uint8_t request_stub[NETNL_REQ_BUFFER_SIZE];
    ofpbuf_use_stub(&request, request_stub, sizeof(request_stub));

    nl_msg_put_nlmsghdr(&request, 0, RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
    ifinfo = ofpbuf_put_zeros(&request, sizeof *ifinfo);
    nl_msg_put_string(&request, IFLA_IFNAME, ifname);
    err = nl_transact(NETLINK_ROUTE, &request, NULL);

    ofpbuf_uninit(&request);
    return err;
}

void
re_route_format(struct ds *ds, uint32_t table_id, const struct in6_addr *dst,
                unsigned int plen, const struct in6_addr *nexthop, int err)
{
    ds_put_format(ds, "table_id=%"PRIu32" dst=", table_id);
    ipv6_format_mapped(dst, ds);
    ds_put_format(ds, " plen=%u nexthop=", plen);
    if (ipv6_is_zero(nexthop)) {
        ds_put_cstr(ds, "(blackhole)");
    } else {
        ipv6_format_mapped(nexthop, ds);
    }

    if (err) {
        ds_put_format(ds, " failed: %s", ovs_strerror(err));
    }
}

static int
modify_route(uint32_t type, uint32_t flags_arg, uint32_t table_id,
             const struct advertise_route_entry *re)
{
    uint32_t flags = NLM_F_REQUEST | NLM_F_ACK;
    bool is_ipv4 = IN6_IS_ADDR_V4MAPPED(&re->addr);
    bool nexthop_unspec = ipv6_is_zero(&re->nexthop);
    struct rtmsg *rt;
    int err;

    flags |= flags_arg;

    struct ofpbuf request;
    uint8_t request_stub[NETNL_REQ_BUFFER_SIZE];
    ofpbuf_use_stub(&request, request_stub, sizeof(request_stub));

    nl_msg_put_nlmsghdr(&request, 0, type, flags);
    rt = ofpbuf_put_zeros(&request, sizeof *rt);
    rt->rtm_family = is_ipv4 ? AF_INET : AF_INET6;
    rt->rtm_table = RT_TABLE_UNSPEC; /* RTA_TABLE attribute allows id > 256 */
    /* Manage only OVN routes */
    rt->rtm_protocol = RTPROT_OVN;
    rt->rtm_type = nexthop_unspec ? RTN_BLACKHOLE : RTN_UNICAST;
    rt->rtm_scope = RT_SCOPE_UNIVERSE;
    rt->rtm_dst_len = re->plen;

    nl_msg_put_u32(&request, RTA_TABLE, table_id);
    nl_msg_put_u32(&request, RTA_PRIORITY, re->priority);

    if (is_ipv4) {
        nl_msg_put_be32(&request, RTA_DST,
                        in6_addr_get_mapped_ipv4(&re->addr));
    } else {
        nl_msg_put_in6_addr(&request, RTA_DST, &re->addr);
    }

    if (!nexthop_unspec) {
        re_nl_encode_nexthop(&request, is_ipv4, &re->nexthop);
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        re_route_format(&msg, table_id, &re->addr, re->plen, &re->nexthop, 0);
        VLOG_DBG("%s route %s", type == RTM_DELROUTE ? "Removing" : "Adding",
                 ds_cstr(&msg));
        ds_destroy(&msg);
    }

    err = nl_transact(NETLINK_ROUTE, &request, NULL);

    ofpbuf_uninit(&request);
    return err;
}

int
re_nl_add_route(uint32_t table_id, const struct advertise_route_entry *re)
{
    if (!TABLE_ID_VALID(table_id)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
        VLOG_WARN_RL(&rl,
                     "attempt to add route using invalid table id %"PRIu32,
                     table_id);
        return EINVAL;
    }

    return modify_route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, table_id, re);
}

int
re_nl_delete_route(uint32_t table_id, const struct advertise_route_entry *re)
{
    if (!TABLE_ID_VALID(table_id)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
        VLOG_WARN_RL(&rl,
                     "attempt to delete route using invalid table id %"PRIu32,
                     table_id);
        return EINVAL;
    }

    return modify_route(RTM_DELROUTE, 0, table_id, re);
}

struct route_msg_handle_data {
    const struct sbrec_datapath_binding *db;
    struct hmapx *routes_to_advertise;
    struct vector *learned_routes;
    struct vector *stale_routes;
    const struct hmap *routes;
    uint32_t table_id; /* requested table id. */
};

static void
handle_route_msg(const struct route_table_msg *msg, void *data)
{
    struct route_msg_handle_data *handle_data = data;
    const struct route_data *rd = &msg->rd;
    struct advertise_route_entry *ar;

    if (handle_data->table_id != rd->rta_table_id) {
        /* We do not have the NLM_F_DUMP_FILTERED info here, so check if the
         * reported table_id matches the requested one.
         */
        return;
    }

    /* This route is not from us, learn it only if it's > RTPROT_STATIC,
     * those protocol values are used by dynamic routing protocols.
     * This should prevent us from learning static routes installed
     * by users in the VRF. */
    if (rd->rtm_protocol != RTPROT_OVN) {
        if (rd->rtm_protocol <= RTPROT_STATIC) {
            return;
        }
        if (!handle_data->learned_routes) {
            return;
        }
        if (prefix_is_link_local(&rd->rta_dst, rd->rtm_dst_len)) {
            return;
        }
        struct route_data_nexthop *nexthop;
        LIST_FOR_EACH (nexthop, nexthop_node, &rd->nexthops) {
            if (ipv6_is_zero(&nexthop->addr)) {
                /* This is most likely an address on the local link.
                 * As we just want to learn remote routes we do not need it.*/
                continue;
            }
            struct re_nl_received_route_node rr;
            rr = (struct re_nl_received_route_node) {
                .db = handle_data->db,
                .prefix = rd->rta_dst,
                .plen = rd->rtm_dst_len,
                .nexthop = nexthop->addr,
            };
            memcpy(rr.ifname, nexthop->ifname, IFNAMSIZ);
            rr.ifname[IFNAMSIZ] = '\0';

            vector_push(handle_data->learned_routes, &rr);
        }
        return;
    }

    const struct advertise_route_entry re =
            advertise_route_from_route_data(rd);
    if (handle_data->routes_to_advertise) {
        uint32_t hash = advertise_route_hash(&re.addr, &re.nexthop, re.plen);
        HMAP_FOR_EACH_WITH_HASH (ar, node, hash, handle_data->routes) {
            if (ipv6_addr_equals(&ar->addr, &re.addr)
                    && ar->plen == re.plen
                    && ipv6_addr_equals(&ar->nexthop, &re.nexthop)
                    && ar->priority == re.priority) {
                hmapx_find_and_delete(handle_data->routes_to_advertise, ar);
                return;
            }
        }
    }

    if (handle_data->stale_routes) {
        vector_push(handle_data->stale_routes, &re);
    }
}

static int
re_nl_delete_stale_routes(uint32_t table_id, const struct vector *stale_routes)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    struct ds ds = DS_EMPTY_INITIALIZER;
    int ret = 0;

    const struct advertise_route_entry *re;
    VECTOR_FOR_EACH_PTR (stale_routes, re) {
        int err = re_nl_delete_route(table_id, re);
        if (err) {
            re_route_format(&ds, table_id, &re->addr,
                            re->plen, &re->nexthop, err);
            VLOG_WARN_RL(&rl, "Delete route %s", ds_cstr(&ds));
            ds_clear(&ds);
            if (!ret) {
                ret = err;
            }
        }
    }

    ds_destroy(&ds);
    return ret;
}

static void
re_nl_encode_nexthop(struct ofpbuf *request, bool dst_is_ipv4,
                     const struct in6_addr *nexthop)
{
    bool nh_is_ipv4 = IN6_IS_ADDR_V4MAPPED(nexthop);
    size_t len = nh_is_ipv4 ? sizeof(ovs_be32) : sizeof(struct in6_addr);

    ovs_be32 nexthop4 = in6_addr_get_mapped_ipv4(nexthop);
    void *nl_attr_dst = nh_is_ipv4 ? (void *) &nexthop4 : (void *) nexthop;

    if (dst_is_ipv4 != nh_is_ipv4) {
        struct rtvia *via = nl_msg_put_unspec_uninit(request, RTA_VIA,
                                                     sizeof *via + len);
        via->rtvia_family = nh_is_ipv4 ? AF_INET : AF_INET6;
        memcpy(via->rtvia_addr, nl_attr_dst, len);
    } else {
        nl_msg_put_unspec(request, RTA_GATEWAY, nl_attr_dst, len);
    }
}

int
re_nl_sync_routes(uint32_t table_id, const struct hmap *routes,
                  struct vector *learned_routes,
                  const struct sbrec_datapath_binding *db)
{
    struct hmapx routes_to_advertise = HMAPX_INITIALIZER(&routes_to_advertise);
    struct vector stale_routes =
        VECTOR_EMPTY_INITIALIZER(struct advertise_route_entry);
    struct advertise_route_entry *ar;

    HMAP_FOR_EACH (ar, node, routes) {
        hmapx_add(&routes_to_advertise, ar);
    }

    /* Remove routes from the system that are not in the routes hmap and
     * remove entries from routes hmap that match routes already installed
     * in the system. */
    struct route_msg_handle_data data = {
        .routes = routes,
        .routes_to_advertise = &routes_to_advertise,
        .learned_routes = learned_routes,
        .stale_routes = &stale_routes,
        .db = db,
        .table_id = table_id,
    };
    route_table_dump_one_table(table_id, handle_route_msg, &data);

    int ret = re_nl_delete_stale_routes(table_id, &stale_routes);

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    struct ds ds = DS_EMPTY_INITIALIZER;

    /* Add any remaining routes in the routes_to_advertise hmapx to the
     * system routing table. */
    struct hmapx_node *hn;
    HMAPX_FOR_EACH (hn, &routes_to_advertise) {
        ar = hn->data;
        int err = re_nl_add_route(table_id, ar);
        if (err) {
            re_route_format(&ds, table_id, &ar->addr, ar->plen,
                            &ar->nexthop, err);
            VLOG_WARN_RL(&rl, "Add route %s", ds_cstr(&ds));
            ds_clear(&ds);
            if (!ret) {
                /* Report the first error value to the caller. */
                ret = err;
            }
        }
    }

    hmapx_destroy(&routes_to_advertise);
    vector_destroy(&stale_routes);
    ds_destroy(&ds);

    return ret;
}

int
re_nl_cleanup_routes(uint32_t table_id)
{
    struct vector stale_routes =
        VECTOR_EMPTY_INITIALIZER(struct advertise_route_entry);
    /* Remove routes from the system that are not in the host_routes hmap and
     * remove entries from host_routes hmap that match routes already installed
     * in the system. */
    struct route_msg_handle_data data = {
        .routes_to_advertise = NULL,
        .learned_routes = NULL,
        .stale_routes = &stale_routes,
        .table_id = table_id,
    };
    route_table_dump_one_table(table_id, handle_route_msg, &data);

    int ret = re_nl_delete_stale_routes(table_id, &stale_routes);
    vector_destroy(&stale_routes);

    return ret;
}
