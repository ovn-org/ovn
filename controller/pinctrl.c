/* Copyright (c) 2015, 2016, 2017 Red Hat, Inc.
 * Copyright (c) 2017 Nicira, Inc.
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

#include "pinctrl.h"

#include "coverage.h"
#include "csum.h"
#include "dirs.h"
#include "dp-packet.h"
#include "encaps.h"
#include "flow.h"
#include "ha-chassis.h"
#include "local_data.h"
#include "lport.h"
#include "mac-learn.h"
#include "nx-match.h"
#include "ofctrl.h"
#include "latch.h"
#include "lib/packets.h"
#include "lib/sset.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-packet.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-switch.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/vlog.h"
#include "lib/random.h"
#include "lib/crc32c.h"

#include "lib/dhcp.h"
#include "ovn-controller.h"
#include "ovn/actions.h"
#include "ovn/lex.h"
#include "lib/acl-log.h"
#include "lib/ip-mcast-index.h"
#include "lib/mcast-group-index.h"
#include "lib/ovn-l7.h"
#include "lib/ovn-util.h"
#include "ovn/logical-fields.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/rconn.h"
#include "socket-util.h"
#include "seq.h"
#include "timeval.h"
#include "vswitch-idl.h"
#include "lflow.h"
#include "ip-mcast.h"

VLOG_DEFINE_THIS_MODULE(pinctrl);

/* pinctrl module creates a thread - pinctrl_handler to handle
 * the packet-ins from ovs-vswitchd. Some of the OVN actions
 * are translated to OF 'controller' actions. See include/ovn/actions.h
 * for more details.
 *
 * pinctrl_handler thread doesn't access the Southbound IDL object. But
 * some of the OVN actions which gets translated to 'controller'
 * OF action, require data from Southbound DB.  Below are the details
 * on how these actions are implemented.
 *
 * pinctrl_run() function is called by ovn-controller main thread.
 * A Mutex - 'pinctrl_mutex' is used between the pinctrl_handler() thread
 * and pinctrl_run().
 *
 *   - dns_lookup -     In order to do a DNS lookup, this action needs
 *                      to access the 'DNS' table. pinctrl_run() builds a
 *                      local DNS cache - 'dns_cache'. See sync_dns_cache()
 *                      for more details.
 *                      The function 'pinctrl_handle_dns_lookup()' (which is
 *                      called with in the pinctrl_handler thread) looks into
 *                      the local DNS cache to resolve the DNS requests.
 *
 *   - put_arp/put_nd - These actions stores the IPv4/IPv6 and MAC addresses
 *                      in the 'MAC_Binding' table.
 *                      The function 'pinctrl_handle_put_mac_binding()' (which
 *                      is called with in the pinctrl_handler thread), stores
 *                      the IPv4/IPv6 and MAC addresses in the
 *                      hmap - put_mac_bindings.
 *
 *                      pinctrl_run(), reads these mac bindings from the hmap
 *                      'put_mac_bindings' and writes to the 'MAC_Binding'
 *                      table in the Southbound DB.
 *
 *   - arp/nd_ns      - These actions generate an ARP/IPv6 Neighbor solicit
 *                      requests. The original packets are buffered and
 *                      injected back when put_arp/put_nd resolves
 *                      corresponding ARP/IPv6 Neighbor solicit requests.
 *                      When pinctrl_run(), writes the mac bindings from the
 *                      'put_mac_bindings' hmap to the MAC_Binding table in
 *                      SB DB, run_buffered_binding will add the buffered
 *                      packets to buffered_mac_bindings and notify
 *                      pinctrl_handler.
 *
 *                      The pinctrl_handler thread calls the function -
 *                      send_mac_binding_buffered_pkts(), which uses
 *                      the hmap - 'buffered_mac_bindings' and reinjects the
 *                      buffered packets.
 *
 *    - igmp          - This action punts an IGMP packet to the controller
 *                      which maintains multicast group information. The
 *                      multicast groups (mcast_snoop_map) are synced to
 *                      the 'IGMP_Group' table by ip_mcast_sync().
 *                      ip_mcast_sync() also reads the 'IP_Multicast'
 *                      (snooping and querier) configuration and builds a
 *                      local configuration mcast_cfg_map.
 *                      ip_mcast_snoop_run() which runs in the
 *                      pinctrl_handler() thread configures the per datapath
 *                      mcast_snoop_map entries according to mcast_cfg_map.
 *
 * pinctrl module also periodically sends IPv6 Router Solicitation requests
 * and gARPs (for the router gateway IPs and configured NAT addresses).
 *
 * IPv6 RA handling - pinctrl_run() prepares the IPv6 RA information
 *                    (see prepare_ipv6_ras()) in the shash 'ipv6_ras' by
 *                    looking into the Southbound DB table - Port_Binding.
 *
 *                    pinctrl_handler thread sends the periodic IPv6 RAs using
 *                    the shash - 'ipv6_ras'
 *
 * g/rARP handling    - pinctrl_run() prepares the g/rARP information
 *                     (see send_garp_rarp_prepare()) in the shash
 *                     'send_garp_rarp_data' by looking into the
 *                     Southbound DB table Port_Binding.
 *                     pinctrl_handler() thread sends these gARPs using the
 *                     shash 'send_garp_rarp_data'.
 *
 * IGMP Queries     - pinctrl_run() prepares the IGMP queries (at most one
 *                    per local datapath) based on the mcast_snoop_map
 *                    contents and stores them in mcast_query_list.
 *
 *                    pinctrl_handler thread sends the periodic IGMP queries
 *                    by walking the mcast_query_list.
 *
 * Notification between pinctrl_handler() and pinctrl_run()
 * -------------------------------------------------------
 * 'struct seq' is used for notification between pinctrl_handler() thread
 *  and pinctrl_run().
 *  'pinctrl_handler_seq' is used by pinctrl_run() to
 *  wake up pinctrl_handler thread from poll_block() if any changes happened
 *  in 'send_garp_rarp_data', 'ipv6_ras', 'ports_to_activate_in_db' and
 *  'buffered_mac_bindings' structures.
 *
 *  'pinctrl_main_seq' is used by pinctrl_handler() thread to wake up
 *  the main thread from poll_block() when mac bindings/igmp groups need to
 *  be updated in the Southboubd DB.
 * */

static struct ovs_mutex pinctrl_mutex = OVS_MUTEX_INITIALIZER;
static struct seq *pinctrl_handler_seq;
static struct seq *pinctrl_main_seq;

#define GARP_RARP_DEF_MAX_TIMEOUT    16000
static long long int garp_rarp_max_timeout = GARP_RARP_DEF_MAX_TIMEOUT;
static bool garp_rarp_continuous;

static void *pinctrl_handler(void *arg);

struct pinctrl {
    char *br_int_name;
    pthread_t pinctrl_thread;
    /* Latch to destroy the 'pinctrl_thread' */
    struct latch pinctrl_thread_exit;
    bool mac_binding_can_timestamp;
    bool fdb_can_timestamp;
    bool dns_supports_ovn_owned;
};

static struct pinctrl pinctrl;

static void init_buffered_packets_ctx(void);
static void destroy_buffered_packets_ctx(void);
static void
run_buffered_binding(const struct sbrec_mac_binding_table *mac_binding_table,
                     struct ovsdb_idl_index *sbrec_port_binding_by_key,
                     struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                     struct ovsdb_idl_index *sbrec_port_binding_by_name,
                     struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip)
    OVS_REQUIRES(pinctrl_mutex);

static void pinctrl_handle_put_mac_binding(const struct flow *md,
                                           const struct flow *headers,
                                           bool is_arp)
    OVS_REQUIRES(pinctrl_mutex);
static void init_put_mac_bindings(void);
static void destroy_put_mac_bindings(void);
static void run_put_mac_bindings(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_key,
    struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip)
    OVS_REQUIRES(pinctrl_mutex);
static void wait_put_mac_bindings(struct ovsdb_idl_txn *ovnsb_idl_txn);
static void send_mac_binding_buffered_pkts(struct rconn *swconn)
    OVS_REQUIRES(pinctrl_mutex);

static void pinctrl_rarp_activation_strategy_handler(const struct match *md);

static void pinctrl_mg_split_buff_handler(
        struct rconn *swconn, struct dp_packet *pkt,
        const struct match *md, struct ofpbuf *userdata);

static void init_activated_ports(void);
static void destroy_activated_ports(void);
static void wait_activated_ports(void);
static void run_activated_ports(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct sbrec_chassis *chassis);

static void init_send_garps_rarps(void);
static void destroy_send_garps_rarps(void);
static void send_garp_rarp_wait(long long int send_garp_rarp_time);
static void send_garp_rarp_prepare(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
    const struct ovsrec_bridge *,
    const struct sbrec_chassis *,
    const struct hmap *local_datapaths,
    const struct sset *active_tunnels,
    const struct ovsrec_open_vswitch_table *ovs_table)
    OVS_REQUIRES(pinctrl_mutex);
static void send_garp_rarp_run(struct rconn *swconn,
                               long long int *send_garp_rarp_time)
    OVS_REQUIRES(pinctrl_mutex);
static void pinctrl_handle_nd_na(struct rconn *swconn,
                                 const struct flow *ip_flow,
                                 const struct match *md,
                                 struct ofpbuf *userdata,
                                 bool is_router);
static void reload_metadata(struct ofpbuf *ofpacts,
                            const struct match *md);
static void pinctrl_handle_put_nd_ra_opts(
    struct rconn *swconn,
    const struct flow *ip_flow, struct dp_packet *pkt_in,
    struct ofputil_packet_in *pin, struct ofpbuf *userdata,
    struct ofpbuf *continuation);
static void pinctrl_handle_nd_ns(struct rconn *swconn,
                                 const struct flow *ip_flow,
                                 struct dp_packet *pkt_in,
                                 const struct match *md,
                                 struct ofpbuf *userdata);
static void pinctrl_handle_put_icmp_frag_mtu(struct rconn *swconn,
                                             const struct flow *in_flow,
                                             struct dp_packet *pkt_in,
                                             struct ofputil_packet_in *pin,
                                             struct ofpbuf *userdata,
                                             struct ofpbuf *continuation);
static void
pinctrl_handle_event(struct ofpbuf *userdata)
    OVS_REQUIRES(pinctrl_mutex);
static void wait_controller_event(struct ovsdb_idl_txn *ovnsb_idl_txn);
static void init_ipv6_ras(void);
static void destroy_ipv6_ras(void);
static void ipv6_ra_wait(long long int send_ipv6_ra_time);
static void prepare_ipv6_ras(
        const struct shash *local_active_ports_ras,
        struct ovsdb_idl_index *sbrec_port_binding_by_name)
    OVS_REQUIRES(pinctrl_mutex);
static void send_ipv6_ras(struct rconn *swconn,
                          long long int *send_ipv6_ra_time)
    OVS_REQUIRES(pinctrl_mutex);

static void ip_mcast_snoop_init(void);
static void ip_mcast_snoop_destroy(void);
static void ip_mcast_snoop_run(void)
    OVS_REQUIRES(pinctrl_mutex);
static void ip_mcast_querier_run(struct rconn *swconn,
                                 long long int *query_time);
static void ip_mcast_querier_wait(long long int query_time);
static void ip_mcast_sync(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    const struct sbrec_chassis *chassis,
    const struct hmap *local_datapaths,
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_key,
    struct ovsdb_idl_index *sbrec_igmp_groups,
    struct ovsdb_idl_index *sbrec_ip_multicast)
    OVS_REQUIRES(pinctrl_mutex);
static void pinctrl_ip_mcast_handle(
    struct rconn *swconn,
    const struct flow *ip_flow,
    struct dp_packet *pkt_in,
    const struct match *md,
    struct ofpbuf *userdata);

static void init_ipv6_prefixd(void);

static bool may_inject_pkts(void);

static void init_put_vport_bindings(void);
static void destroy_put_vport_bindings(void);
static void run_put_vport_bindings(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
    struct ovsdb_idl_index *sbrec_port_binding_by_key,
    const struct sbrec_chassis *chassis)
    OVS_REQUIRES(pinctrl_mutex);
static void wait_put_vport_bindings(struct ovsdb_idl_txn *ovnsb_idl_txn);
static void pinctrl_handle_bind_vport(const struct flow *md,
                                      struct ofpbuf *userdata);
static void pinctrl_handle_svc_check(struct rconn *swconn,
                                     const struct flow *ip_flow,
                                     struct dp_packet *pkt_in,
                                     const struct match *md);
static void init_svc_monitors(void);
static void destroy_svc_monitors(void);
static void sync_svc_monitors(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    const struct sbrec_service_monitor_table *svc_mon_table,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct sbrec_chassis *our_chassis)
    OVS_REQUIRES(pinctrl_mutex);
static void svc_monitors_run(struct rconn *swconn,
                             long long int *svc_monitors_next_run_time)
    OVS_REQUIRES(pinctrl_mutex);
static void svc_monitors_wait(long long int svc_monitors_next_run_time);

static void pinctrl_compose_ipv4(struct dp_packet *packet,
                                 struct eth_addr eth_src,
                                 struct eth_addr eth_dst, ovs_be32 ipv4_src,
                                 ovs_be32 ipv4_dst, uint8_t ip_proto,
                                 uint8_t ttl, uint16_t ip_payload_len);
static void pinctrl_compose_ipv6(struct dp_packet *packet,
                                 struct eth_addr eth_src,
                                 struct eth_addr eth_dst,
                                 struct in6_addr *ipv6_src,
                                 struct in6_addr *ipv6_dst,
                                 uint8_t ip_proto, uint8_t ttl,
                                 uint16_t ip_payload_len);

static void
put_load(uint64_t value, enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts);

static void notify_pinctrl_main(void);
static void notify_pinctrl_handler(void);

static bool bfd_monitor_should_inject(void);
static void bfd_monitor_wait(long long int timeout);
static void bfd_monitor_init(void);
static void bfd_monitor_destroy(void);
static void bfd_monitor_send_msg(struct rconn *swconn, long long int *bfd_time)
                                 OVS_REQUIRES(pinctrl_mutex);
static void
pinctrl_handle_bfd_msg(struct rconn *swconn, const struct flow *ip_flow,
                       struct dp_packet *pkt_in)
                       OVS_REQUIRES(pinctrl_mutex);
static void bfd_monitor_run(struct ovsdb_idl_txn *ovnsb_idl_txn,
                            const struct sbrec_bfd_table *bfd_table,
                            struct ovsdb_idl_index *sbrec_port_binding_by_name,
                            const struct sbrec_chassis *chassis,
                            const struct sset *active_tunnels)
                            OVS_REQUIRES(pinctrl_mutex);
static void init_fdb_entries(void);
static void destroy_fdb_entries(void);
static const struct sbrec_fdb *fdb_lookup(
    struct ovsdb_idl_index *sbrec_fdb_by_dp_key_mac,
    uint32_t dp_key, const char *mac);
static void run_put_fdb(struct ovsdb_idl_txn *ovnsb_idl_txn,
                        struct ovsdb_idl_index *sbrec_fdb_by_dp_key_mac,
            struct ovsdb_idl_index *sbrec_port_binding_by_key,
            struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                        const struct fdb_entry *fdb_e)
                        OVS_REQUIRES(pinctrl_mutex);
static void run_put_fdbs(struct ovsdb_idl_txn *ovnsb_idl_txn,
            struct ovsdb_idl_index *sbrec_port_binding_by_key,
            struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                        struct ovsdb_idl_index *sbrec_fdb_by_dp_key_mac)
                        OVS_REQUIRES(pinctrl_mutex);
static void wait_put_fdbs(struct ovsdb_idl_txn *ovnsb_idl_txn);
static void pinctrl_handle_put_fdb(const struct flow *md,
                                   const struct flow *headers)
                                   OVS_REQUIRES(pinctrl_mutex);

COVERAGE_DEFINE(pinctrl_drop_put_mac_binding);
COVERAGE_DEFINE(pinctrl_drop_buffered_packets_map);
COVERAGE_DEFINE(pinctrl_drop_controller_event);
COVERAGE_DEFINE(pinctrl_drop_put_vport_binding);
COVERAGE_DEFINE(pinctrl_notify_main_thread);
COVERAGE_DEFINE(pinctrl_total_pin_pkts);

struct empty_lb_backends_event {
    struct hmap_node hmap_node;
    long long int timestamp;

    char *vip;
    char *protocol;
    char *load_balancer;
};

static struct hmap event_table[OVN_EVENT_MAX];
static int64_t event_seq_num;

static void
init_event_table(void)
{
    for (size_t i = 0; i < OVN_EVENT_MAX; i++) {
        hmap_init(&event_table[i]);
    }
}

#define EVENT_TIMEOUT   10000
static void
empty_lb_backends_event_gc(bool flush)
{
    struct empty_lb_backends_event *cur_ce;
    long long int now = time_msec();

    HMAP_FOR_EACH_SAFE (cur_ce, hmap_node,
                        &event_table[OVN_EVENT_EMPTY_LB_BACKENDS]) {
        if ((now < cur_ce->timestamp + EVENT_TIMEOUT) && !flush) {
            continue;
        }

        free(cur_ce->vip);
        free(cur_ce->protocol);
        free(cur_ce->load_balancer);
        hmap_remove(&event_table[OVN_EVENT_EMPTY_LB_BACKENDS],
                    &cur_ce->hmap_node);
        free(cur_ce);
    }
}

static void
event_table_gc(bool flush)
{
    empty_lb_backends_event_gc(flush);
}

static void
event_table_destroy(void)
{
    event_table_gc(true);
    for (size_t i = 0; i < OVN_EVENT_MAX; i++) {
        hmap_destroy(&event_table[i]);
    }
}

static struct empty_lb_backends_event *
pinctrl_find_empty_lb_backends_event(char *vip, char *protocol,
                                     char *load_balancer, uint32_t hash)
{
    struct empty_lb_backends_event *ce;
    HMAP_FOR_EACH_WITH_HASH (ce, hmap_node, hash,
                             &event_table[OVN_EVENT_EMPTY_LB_BACKENDS]) {
        if (!strcmp(ce->vip, vip) &&
            !strcmp(ce->protocol, protocol) &&
            !strcmp(ce->load_balancer, load_balancer)) {
            return ce;
        }
    }
    return NULL;
}

static const struct sbrec_controller_event *
empty_lb_backends_lookup(struct empty_lb_backends_event *event,
                         const struct sbrec_controller_event_table *ce_table,
                         const struct sbrec_chassis *chassis)
{
    const struct sbrec_controller_event *sbrec_event;
    const char *event_type = event_to_string(OVN_EVENT_EMPTY_LB_BACKENDS);
    char ref_uuid[UUID_LEN + 1];
    sprintf(ref_uuid, UUID_FMT, UUID_ARGS(&chassis->header_.uuid));

    SBREC_CONTROLLER_EVENT_TABLE_FOR_EACH (sbrec_event, ce_table) {
        if (strcmp(sbrec_event->event_type, event_type)) {
            continue;
        }

        char chassis_uuid[UUID_LEN + 1];
        sprintf(chassis_uuid, UUID_FMT,
                UUID_ARGS(&sbrec_event->chassis->header_.uuid));
        if (strcmp(ref_uuid, chassis_uuid)) {
            continue;
        }

        const char *vip = smap_get(&sbrec_event->event_info, "vip");
        const char *protocol = smap_get(&sbrec_event->event_info, "protocol");
        const char *load_balancer = smap_get(&sbrec_event->event_info,
                                             "load_balancer");

        if (!strcmp(event->vip, vip) &&
            !strcmp(event->protocol, protocol) &&
            !strcmp(event->load_balancer, load_balancer)) {
            return sbrec_event;
        }
    }

    return NULL;
}

static void
controller_event_run(struct ovsdb_idl_txn *ovnsb_idl_txn,
                     const struct sbrec_controller_event_table *ce_table,
                     const struct sbrec_chassis *chassis)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (!ovnsb_idl_txn) {
        goto out;
    }

    struct empty_lb_backends_event *empty_lbs;
    HMAP_FOR_EACH (empty_lbs, hmap_node,
                   &event_table[OVN_EVENT_EMPTY_LB_BACKENDS]) {
        const struct sbrec_controller_event *event;

        event = empty_lb_backends_lookup(empty_lbs, ce_table, chassis);
        if (!event) {
            struct smap event_info = SMAP_INITIALIZER(&event_info);

            smap_add(&event_info, "vip", empty_lbs->vip);
            smap_add(&event_info, "protocol", empty_lbs->protocol);
            smap_add(&event_info, "load_balancer", empty_lbs->load_balancer);

            event = sbrec_controller_event_insert(ovnsb_idl_txn);
            sbrec_controller_event_set_event_type(event,
                    event_to_string(OVN_EVENT_EMPTY_LB_BACKENDS));
            sbrec_controller_event_set_seq_num(event, ++event_seq_num);
            sbrec_controller_event_set_event_info(event, &event_info);
            sbrec_controller_event_set_chassis(event, chassis);
            smap_destroy(&event_info);
        }
    }

out:
    event_table_gc(!!ovnsb_idl_txn);
}

void
pinctrl_init(void)
{
    init_put_mac_bindings();
    init_send_garps_rarps();
    init_ipv6_ras();
    init_ipv6_prefixd();
    init_buffered_packets_ctx();
    init_activated_ports();
    init_event_table();
    ip_mcast_snoop_init();
    init_put_vport_bindings();
    init_svc_monitors();
    bfd_monitor_init();
    init_fdb_entries();
    pinctrl.br_int_name = NULL;
    pinctrl.mac_binding_can_timestamp = false;
    pinctrl_handler_seq = seq_create();
    pinctrl_main_seq = seq_create();

    latch_init(&pinctrl.pinctrl_thread_exit);
    pinctrl.pinctrl_thread = ovs_thread_create("ovn_pinctrl", pinctrl_handler,
                                                &pinctrl);
}

static ovs_be32
queue_msg(struct rconn *swconn, struct ofpbuf *msg)
{
    const struct ofp_header *oh = msg->data;
    ovs_be32 xid = oh->xid;

    rconn_send(swconn, msg, NULL);
    return xid;
}

/* Sets up 'swconn', a newly (re)connected connection to a switch. */
static void
pinctrl_setup(struct rconn *swconn)
{
    /* Fetch the switch configuration.  The response later will allow us to
     * change the miss_send_len to UINT16_MAX, so that we can enable
     * asynchronous messages. */
    queue_msg(swconn, ofpraw_alloc(OFPRAW_OFPT_GET_CONFIG_REQUEST,
                                   rconn_get_version(swconn), 0));

    /* Set a packet-in format that supports userdata.  */
    queue_msg(swconn,
              ofputil_encode_set_packet_in_format(rconn_get_version(swconn),
                                                  OFPUTIL_PACKET_IN_NXT2));
}

static void
set_switch_config(struct rconn *swconn,
                  const struct ofputil_switch_config *config)
{
    enum ofp_version version = rconn_get_version(swconn);
    struct ofpbuf *request = ofputil_encode_set_config(config, version);
    queue_msg(swconn, request);
}

static void
set_actions_and_enqueue_msg(struct rconn *swconn,
                            const struct dp_packet *packet,
                            const struct match *md,
                            struct ofpbuf *userdata)
{
    /* Copy metadata from 'md' into the packet-out via "set_field"
     * actions, then add actions from 'userdata'.
     */
    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);

    reload_metadata(&ofpacts, md);
    enum ofperr error = ofpacts_pull_openflow_actions(userdata, userdata->size,
                                                      version, NULL, NULL,
                                                      &ofpacts);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "failed to parse actions from userdata (%s)",
                     ofperr_to_string(error));
        ofpbuf_uninit(&ofpacts);
        return;
    }

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(packet),
        .packet_len = dp_packet_size(packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    ofpbuf_uninit(&ofpacts);
}

/* Forwards a packet to 'out_port_key' even if that's on a remote
 * hypervisor, i.e., the packet is re-injected in table OFTABLE_OUTPUT_INIT.
 */
static void
pinctrl_forward_pkt(struct rconn *swconn, int64_t dp_key,
                    int64_t in_port_key, int64_t out_port_key,
                    const struct dp_packet *pkt)
{
    /* Reinject the packet and flood it to all registered mrouters. */
    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);
    put_load(dp_key, MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(in_port_key, MFF_LOG_INPORT, 0, 32, &ofpacts);
    put_load(out_port_key, MFF_LOG_OUTPORT, 0, 32, &ofpacts);

    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_OUTPUT_INIT;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(pkt),
        .packet_len = dp_packet_size(pkt),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    ofpbuf_uninit(&ofpacts);
}

static struct shash ipv6_prefixd;

enum {
    PREFIX_SOLICIT,
    PREFIX_REQUEST,
    PREFIX_PENDING,
    PREFIX_DONE,
    PREFIX_RENEW,
    PREFIX_REBIND,
};

/* According to RFC 8415, section 11:
 *   A DUID consists of a 2-octet type code represented in network byte
 *   order, followed by a variable number of octets that make up the
 *   actual identifier.  The length of the DUID (not including the type
 *   code) is at least 1 octet and at most 128 octets.
*/
#define DHCPV6_MAX_DUID_LEN 130

struct ipv6_prefixd_state {
    long long int next_announce;
    long long int last_complete;
    long long int last_used;
    /* IPv6 PD server info */
    struct in6_addr server_addr;
    struct eth_addr sa;
    /* server_id_info */
    struct {
        uint8_t data[DHCPV6_MAX_DUID_LEN];
        uint8_t len;
    } uuid;
    struct in6_addr ipv6_addr;
    struct eth_addr ea;
    struct eth_addr cmac;
    int64_t port_key;
    int64_t metadata;
    struct in6_addr prefix;
    uint32_t plife_time;
    uint32_t vlife_time;
    uint32_t aid;
    uint32_t t1;
    uint32_t t2;
    uint32_t plen;
    int state;
};

static void
init_ipv6_prefixd(void)
{
    shash_init(&ipv6_prefixd);
}

static void
destroy_ipv6_prefixd(void)
{
    struct shash_node *iter;
    SHASH_FOR_EACH_SAFE (iter, &ipv6_prefixd) {
        struct ipv6_prefixd_state *pfd = iter->data;
        free(pfd);
        shash_delete(&ipv6_prefixd, iter);
    }
    shash_destroy(&ipv6_prefixd);
}

static struct ipv6_prefixd_state *
pinctrl_find_prefixd_state(const struct flow *ip_flow, unsigned aid)
{
    struct shash_node *iter;

    SHASH_FOR_EACH (iter, &ipv6_prefixd) {
        struct ipv6_prefixd_state *pfd = iter->data;
        if (IN6_ARE_ADDR_EQUAL(&pfd->ipv6_addr, &ip_flow->ipv6_dst) &&
            eth_addr_equals(pfd->ea, ip_flow->dl_dst) &&
            pfd->aid == aid) {
            return pfd;
        }
    }
    return NULL;
}

static void
pinctrl_parse_dhcpv6_advt(struct rconn *swconn, const struct flow *ip_flow,
                          struct dp_packet *pkt_in, const struct match *md)
{
    struct udp_header *udp_in = dp_packet_l4(pkt_in);
    size_t dlen = MIN(ntohs(udp_in->udp_len), dp_packet_l4_size(pkt_in));
    unsigned char *in_dhcpv6_data = (unsigned char *)(udp_in + 1);
    uint8_t *data, *end = (uint8_t *)udp_in + dlen;
    int len = 0, aid = 0;

    data = xmalloc(dlen);
    /* skip DHCPv6 common header */
    in_dhcpv6_data += 4;
    while (in_dhcpv6_data < end) {
        struct dhcpv6_opt_header *in_opt =
             (struct dhcpv6_opt_header *)in_dhcpv6_data;
        int opt_len = sizeof *in_opt + ntohs(in_opt->len);

        if (dlen < opt_len + len) {
            goto out;
        }

        switch (ntohs(in_opt->code)) {
        case DHCPV6_OPT_IA_PD: {
            struct dhcpv6_opt_ia_na *ia_na = (struct dhcpv6_opt_ia_na *)in_opt;
            int orig_len = len, hdr_len = 0, size = sizeof *in_opt + 12;
            uint32_t t1 = ntohl(ia_na->t1), t2 = ntohl(ia_na->t2);

            if (t1 > t2 && t2 > 0) {
                goto out;
            }

            aid = ntohl(ia_na->iaid);
            memcpy(&data[len], in_opt, size);
            in_opt = (struct dhcpv6_opt_header *)(in_dhcpv6_data + size);
            len += size;

            while (size < opt_len) {
                int flen = sizeof *in_opt + ntohs(in_opt->len);

                if (dlen < flen + len) {
                    goto out;
                }

                if (ntohs(in_opt->code) == DHCPV6_OPT_IA_PREFIX) {
                    struct dhcpv6_opt_ia_prefix *ia_hdr =
                        (struct dhcpv6_opt_ia_prefix *)in_opt;
                    uint32_t plife_time = ntohl(ia_hdr->plife_time);
                    uint32_t vlife_time = ntohl(ia_hdr->vlife_time);

                    if (plife_time > vlife_time) {
                        goto out;
                    }

                    memcpy(&data[len], in_opt, flen);
                    hdr_len += flen;
                    len += flen;
                }
                if (ntohs(in_opt->code) == DHCPV6_OPT_STATUS_CODE) {
                   struct dhcpv6_opt_status *status;

                   status = (struct dhcpv6_opt_status *)in_opt;
                   if (ntohs(status->status_code)) {
                       goto out;
                   }
                }
                size += flen;
                in_opt = (struct dhcpv6_opt_header *)(in_dhcpv6_data + size);
            }
            in_opt = (struct dhcpv6_opt_header *)&data[orig_len];
            in_opt->len = htons(hdr_len + 12);
            break;
        }
        case DHCPV6_OPT_SERVER_ID_CODE:
        case DHCPV6_OPT_CLIENT_ID_CODE:
            memcpy(&data[len], in_opt, opt_len);
            len += opt_len;
            break;
        default:
            break;
        }
        in_dhcpv6_data += opt_len;
    }

    struct ipv6_prefixd_state *pfd = pinctrl_find_prefixd_state(ip_flow, aid);
    if (!pfd) {
        goto out;
    }

    pfd->state = PREFIX_REQUEST;

    char ip6_s[INET6_ADDRSTRLEN + 1];
    if (ipv6_string_mapped(ip6_s, &ip_flow->ipv6_src)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(20, 40);
        VLOG_DBG_RL(&rl, "Received DHCPv6 advt from %s with aid %d"
                    " sending DHCPv6 request", ip6_s, aid);
    }

    uint64_t packet_stub[256 / 8];
    struct dp_packet packet;

    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    eth_compose(&packet, ip_flow->dl_src, ip_flow->dl_dst, ETH_TYPE_IPV6,
                IPV6_HEADER_LEN);

    struct udp_header *udp_h = compose_ipv6(&packet, IPPROTO_UDP,
                                            &ip_flow->ipv6_dst,
                                            &ip_flow->ipv6_src, 0, 0, 255,
                                            len + UDP_HEADER_LEN + 4);
    udp_h->udp_len = htons(len + UDP_HEADER_LEN + 4);
    udp_h->udp_csum = 0;
    packet_set_udp_port(&packet, htons(546), htons(547));

    unsigned char *dhcp_hdr = (unsigned char *)(udp_h + 1);
    *dhcp_hdr = DHCPV6_MSG_TYPE_REQUEST;
    memcpy(dhcp_hdr + 4, data, len);

    uint32_t csum = packet_csum_pseudoheader6(dp_packet_l3(&packet));
    csum = csum_continue(csum, udp_h, dp_packet_size(&packet) -
                         ((const unsigned char *)udp_h -
                          (const unsigned char *)dp_packet_eth(&packet)));
    udp_h->udp_csum = csum_finish(csum);
    if (!udp_h->udp_csum) {
        udp_h->udp_csum = htons(0xffff);
    }

    if (ip_flow->vlans[0].tci & htons(VLAN_CFI)) {
        eth_push_vlan(&packet, htons(ETH_TYPE_VLAN_8021Q),
                      ip_flow->vlans[0].tci);
    }

    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);
    put_load(ntohll(md->flow.metadata), MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(md->flow.regs[MFF_LOG_INPORT - MFF_REG0], MFF_LOG_OUTPORT,
             0, 32, &ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_OUTPUT_INIT;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);

out:
    free(data);
}

static void
pinctrl_prefixd_state_handler(const struct flow *ip_flow,
                              struct in6_addr addr, unsigned aid,
                              struct eth_addr sa, struct in6_addr server_addr,
                              char prefix_len, unsigned t1, unsigned t2,
                              unsigned plife_time, unsigned vlife_time,
                              const uint8_t *uuid, uint8_t uuid_len)
{
    struct ipv6_prefixd_state *pfd;

    pfd = pinctrl_find_prefixd_state(ip_flow, aid);
    if (pfd) {
        pfd->state = PREFIX_PENDING;
        pfd->server_addr = server_addr;
        pfd->sa = sa;
        memcpy(pfd->uuid.data, uuid, uuid_len);
        pfd->uuid.len = uuid_len;
        pfd->plife_time = plife_time * 1000;
        pfd->vlife_time = vlife_time * 1000;
        pfd->plen = prefix_len;
        pfd->prefix = addr;
        pfd->t1 = t1 * 1000;
        pfd->t2 = t2 * 1000;
        notify_pinctrl_main();
    }
}

static void
pinctrl_parse_dhcpv6_reply(struct dp_packet *pkt_in,
                           const struct flow *ip_flow)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct eth_header *eth = dp_packet_eth(pkt_in);
    struct ovs_16aligned_ip6_hdr *in_ip = dp_packet_l3(pkt_in);
    struct in6_addr ip6_src;
    memcpy(&ip6_src, &in_ip->ip6_src, sizeof ip6_src);
    struct udp_header *udp_in = dp_packet_l4(pkt_in);
    unsigned char *in_dhcpv6_data = (unsigned char *)(udp_in + 1);
    size_t dlen = MIN(ntohs(udp_in->udp_len), dp_packet_l4_size(pkt_in));
    unsigned t1 = 0, t2 = 0, vlife_time = 0, plife_time = 0;
    uint8_t *end = (uint8_t *) udp_in + dlen;
    uint8_t prefix_len = 0, uuid_len = 0;
    uint8_t uuid[DHCPV6_MAX_DUID_LEN];
    struct in6_addr ipv6 = in6addr_any;
    bool status = false;
    unsigned aid = 0;

    /* skip DHCPv6 common header */
    in_dhcpv6_data += 4;

    while (in_dhcpv6_data < end) {
        struct dhcpv6_opt_header *in_opt =
             (struct dhcpv6_opt_header *)in_dhcpv6_data;
        int opt_len = sizeof *in_opt + ntohs(in_opt->len);

        if (in_dhcpv6_data + opt_len > end) {
            break;
        }

        switch (ntohs(in_opt->code)) {
        case DHCPV6_OPT_IA_PD: {
            int size = sizeof *in_opt + 12;
            in_opt = (struct dhcpv6_opt_header *)(in_dhcpv6_data + size);
            struct dhcpv6_opt_ia_na *ia_na =
                (struct dhcpv6_opt_ia_na *)in_dhcpv6_data;

            aid = ntohl(ia_na->iaid);
            t1 = ntohl(ia_na->t1);
            t2 = ntohl(ia_na->t2);
            if (t1 > t2 && t2 > 0) {
                break;
            }

            while (size < opt_len) {
                if (ntohs(in_opt->code) == DHCPV6_OPT_IA_PREFIX) {
                    struct dhcpv6_opt_ia_prefix *ia_hdr =
                        (struct dhcpv6_opt_ia_prefix *)(in_dhcpv6_data + size);

                    plife_time = ntohl(ia_hdr->plife_time);
                    vlife_time = ntohl(ia_hdr->vlife_time);
                    if (plife_time > vlife_time) {
                        break;
                    }
                    prefix_len = ia_hdr->plen;
                    memcpy(&ipv6, &ia_hdr->ipv6, sizeof (struct in6_addr));
                    status = true;
                }
                if (ntohs(in_opt->code) == DHCPV6_OPT_STATUS_CODE) {
                   struct dhcpv6_opt_status *status_hdr;

                   status_hdr = (struct dhcpv6_opt_status *)in_opt;
                   if (ntohs(status_hdr->status_code)) {
                       status = false;
                   }
                }
                size += sizeof *in_opt + ntohs(in_opt->len);
                in_opt = (struct dhcpv6_opt_header *)(in_dhcpv6_data + size);
            }
            break;
        }
        case DHCPV6_OPT_SERVER_ID_CODE:
            uuid_len = MIN(ntohs(in_opt->len), DHCPV6_MAX_DUID_LEN);
            memcpy(uuid, in_opt + 1, uuid_len);
            break;
        default:
            break;
        }
        in_dhcpv6_data += opt_len;
    }
    if (status) {
        char prefix[INET6_ADDRSTRLEN + 1];
        char ip6_s[INET6_ADDRSTRLEN + 1];
        if (ipv6_string_mapped(ip6_s, &ip_flow->ipv6_src) &&
            ipv6_string_mapped(prefix, &ipv6)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(20, 40);
            VLOG_DBG_RL(&rl, "Received DHCPv6 reply from %s with prefix %s/%d"
                        " aid %d", ip6_s, prefix, prefix_len, aid);
        }
        pinctrl_prefixd_state_handler(ip_flow, ipv6, aid, eth->eth_src,
                                      ip6_src, prefix_len, t1, t2,
                                      plife_time, vlife_time, uuid, uuid_len);
    }
}

static void
pinctrl_handle_dhcp6_server(struct rconn *swconn, const struct flow *ip_flow,
                            struct dp_packet *pkt_in, const struct match *md)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (ip_flow->dl_type != htons(ETH_TYPE_IPV6) ||
        ip_flow->nw_proto != IPPROTO_UDP) {
        return;
    }

    struct udp_header *udp_in = dp_packet_l4(pkt_in);
    unsigned char *dhcp_hdr = (unsigned char *)(udp_in + 1);

    switch (*dhcp_hdr) {
    case DHCPV6_MSG_TYPE_ADVT:
        pinctrl_parse_dhcpv6_advt(swconn, ip_flow, pkt_in, md);
        break;
    case DHCPV6_MSG_TYPE_REPLY:
        pinctrl_parse_dhcpv6_reply(pkt_in, ip_flow);
        break;
    default:
        break;
    }
}

static void
compose_prefixd_packet(struct dp_packet *b, struct ipv6_prefixd_state *pfd)
{
    struct in6_addr ipv6_dst;
    struct eth_addr eth_dst;

    int payload = sizeof(struct dhcpv6_opt_server_id) +
                  sizeof(struct dhcpv6_opt_ia_na);
    if (pfd->uuid.len) {
        payload += pfd->uuid.len + sizeof(struct dhcpv6_opt_header);
        ipv6_dst = pfd->server_addr;
        eth_dst = pfd->sa;
    } else {
        eth_dst = (struct eth_addr) ETH_ADDR_C(33,33,00,01,00,02);
        ipv6_parse("ff02::1:2", &ipv6_dst);
    }
    if (ipv6_addr_is_set(&pfd->prefix)) {
        payload += sizeof(struct dhcpv6_opt_ia_prefix);
    }

    eth_compose(b, eth_dst, pfd->ea, ETH_TYPE_IPV6, IPV6_HEADER_LEN);

    int len = UDP_HEADER_LEN + 4 + payload;
    struct udp_header *udp_h = compose_ipv6(b, IPPROTO_UDP, &pfd->ipv6_addr,
                                            &ipv6_dst, 0, 0, 255, len);
    udp_h->udp_len = htons(len);
    udp_h->udp_csum = 0;
    packet_set_udp_port(b, htons(546), htons(547));

    unsigned char *dhcp_hdr = (unsigned char *)(udp_h + 1);
    if (pfd->state == PREFIX_RENEW) {
        *dhcp_hdr = DHCPV6_MSG_TYPE_RENEW;
    } else if (pfd->state == PREFIX_REBIND) {
        *dhcp_hdr = DHCPV6_MSG_TYPE_REBIND;
    } else {
        *dhcp_hdr = DHCPV6_MSG_TYPE_SOLICIT;
    }
    dhcp_hdr += 4;

    struct dhcpv6_opt_server_id opt_client_id = {
        .opt.code = htons(DHCPV6_OPT_CLIENT_ID_CODE),
        .opt.len = htons(sizeof(struct dhcpv6_opt_server_id) -
                         sizeof(struct dhcpv6_opt_header)),
        .duid_type = htons(DHCPV6_DUID_LL),
        .hw_type = htons(DHCPV6_HW_TYPE_ETH),
        .mac = pfd->cmac,
    };
    memcpy(dhcp_hdr, &opt_client_id, sizeof(struct dhcpv6_opt_server_id));
    dhcp_hdr += sizeof(struct dhcpv6_opt_server_id);

    if (pfd->uuid.len) {
        struct dhcpv6_opt_header *in_opt =
            (struct dhcpv6_opt_header *) dhcp_hdr;
        in_opt->code = htons(DHCPV6_OPT_SERVER_ID_CODE);
        in_opt->len = htons(pfd->uuid.len);

        dhcp_hdr += sizeof *in_opt;
        memcpy(dhcp_hdr, pfd->uuid.data, pfd->uuid.len);
        dhcp_hdr += pfd->uuid.len;
    }

    if (!ipv6_addr_is_set(&pfd->prefix)) {
        pfd->aid = random_uint16();
    }
    struct dhcpv6_opt_ia_na *ia_pd = (struct dhcpv6_opt_ia_na *) dhcp_hdr;
    ia_pd->opt.code = htons(DHCPV6_OPT_IA_PD);
    int opt_len = sizeof(struct dhcpv6_opt_ia_na) -
                  sizeof(struct dhcpv6_opt_header);
    if (ipv6_addr_is_set(&pfd->prefix)) {
        opt_len += sizeof(struct dhcpv6_opt_ia_prefix);
    }
    ia_pd->opt.len = htons(opt_len);
    ia_pd->iaid = htonl(pfd->aid);
    ia_pd->t1 = OVS_BE32_MAX;
    ia_pd->t2 = OVS_BE32_MAX;
    if (ipv6_addr_is_set(&pfd->prefix)) {
        struct dhcpv6_opt_ia_prefix *ia_prefix =
            (struct dhcpv6_opt_ia_prefix *)(ia_pd + 1);
        ia_prefix->opt.code = htons(DHCPV6_OPT_IA_PREFIX);
        ia_prefix->opt.len = htons(sizeof(struct dhcpv6_opt_ia_prefix) -
                                   sizeof(struct dhcpv6_opt_header));
        ia_prefix->plife_time = OVS_BE32_MAX;
        ia_prefix->vlife_time = OVS_BE32_MAX;
        ia_prefix->plen = pfd->plen;
        ia_prefix->ipv6 = pfd->prefix;
    }

    uint32_t csum = packet_csum_pseudoheader6(dp_packet_l3(b));
    csum = csum_continue(csum, udp_h, dp_packet_size(b) -
                         ((const unsigned char *)udp_h -
                          (const unsigned char *)dp_packet_eth(b)));
    udp_h->udp_csum = csum_finish(csum);
    if (!udp_h->udp_csum) {
        udp_h->udp_csum = htons(0xffff);
    }
}

#define IPV6_PREFIXD_TIMEOUT    3000LL
static long long int
ipv6_prefixd_send(struct rconn *swconn, struct ipv6_prefixd_state *pfd)
{
    long long int cur_time = time_msec();
    if (cur_time < pfd->next_announce) {
        return pfd->next_announce;
    }

    if (pfd->state == PREFIX_DONE) {
        goto out;
    }

    uint64_t packet_stub[256 / 8];
    struct dp_packet packet;

    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    compose_prefixd_packet(&packet, pfd);

    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);

    /* Set MFF_LOG_DATAPATH and MFF_LOG_INPORT. */
    uint32_t dp_key = pfd->metadata;
    uint32_t port_key = pfd->port_key;
    put_load(dp_key, MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(port_key, MFF_LOG_INPORT, 0, 32, &ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_LOG_INGRESS_PIPELINE;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };

    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);

out:
    pfd->next_announce = cur_time + random_range(IPV6_PREFIXD_TIMEOUT);

    return pfd->next_announce;
}

static bool ipv6_prefixd_should_inject(void)
{
    struct shash_node *iter;

    SHASH_FOR_EACH (iter, &ipv6_prefixd) {
        struct ipv6_prefixd_state *pfd = iter->data;
        long long int cur_time = time_msec();

        if (pfd->state == PREFIX_SOLICIT) {
            return true;
        }
        if (pfd->state == PREFIX_DONE &&
            cur_time > pfd->last_complete + pfd->t1) {
            pfd->state = PREFIX_RENEW;
            return true;
        }
        if (pfd->state == PREFIX_RENEW &&
            cur_time > pfd->last_complete + pfd->t2) {
            pfd->state = PREFIX_REBIND;
            pfd->uuid.len = 0;
            return true;
        }
        if (pfd->state == PREFIX_REBIND &&
            cur_time > pfd->last_complete + pfd->vlife_time) {
            pfd->state = PREFIX_SOLICIT;
            return true;
        }
    }
    return false;
}

static void
ipv6_prefixd_wait(long long int timeout)
{
    if (ipv6_prefixd_should_inject()) {
        poll_timer_wait_until(timeout);
    }
}

static void
send_ipv6_prefixd(struct rconn *swconn, long long int *send_prefixd_time)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct shash_node *iter;

    *send_prefixd_time = LLONG_MAX;
    SHASH_FOR_EACH (iter, &ipv6_prefixd) {
        struct ipv6_prefixd_state *pfd = iter->data;
        long long int next_msg = ipv6_prefixd_send(swconn, pfd);
        if (*send_prefixd_time > next_msg) {
            *send_prefixd_time = next_msg;
        }
    }
}

static bool
fill_ipv6_prefix_state(struct ovsdb_idl_txn *ovnsb_idl_txn,
                       const struct local_datapath *ld,
                       struct eth_addr ea, struct in6_addr ipv6_addr,
                       int64_t tunnel_key, int64_t dp_tunnel_key)
    OVS_REQUIRES(pinctrl_mutex)
{
    bool changed = false;

    for (size_t i = 0; i < ld->n_peer_ports; i++) {
        const struct sbrec_port_binding *pb = ld->peer_ports[i].local;
        struct ipv6_prefixd_state *pfd;

        if (!smap_get_bool(&pb->options, "ipv6_prefix", false)) {
            pfd = shash_find_and_delete(&ipv6_prefixd, pb->logical_port);
            if (pfd) {
                free(pfd);
            }
            continue;
        }

        struct lport_addresses c_addrs;
        for (size_t j = 0; j < pb->n_mac; j++) {
            if (extract_lsp_addresses(pb->mac[j], &c_addrs)) {
                    break;
            }
        }

        pfd = shash_find_data(&ipv6_prefixd, pb->logical_port);
        if (!pfd) {
            pfd = xzalloc(sizeof *pfd);
            pfd->ipv6_addr = ipv6_addr;
            pfd->ea = ea;
            pfd->cmac = c_addrs.ea;
            pfd->metadata = dp_tunnel_key;
            pfd->port_key = tunnel_key;
            shash_add(&ipv6_prefixd, pb->logical_port, pfd);
            pfd->next_announce = time_msec() +
                                 random_range(IPV6_PREFIXD_TIMEOUT);
            changed = true;

            char prefix_s[IPV6_SCAN_LEN + 6];
            const char *ipv6_pd_list = smap_get(&pb->options,
                                                "ipv6_ra_pd_list");
            if (!ipv6_pd_list ||
                !ovs_scan(ipv6_pd_list, "%u:"IPV6_SCAN_FMT"/%d",
                          &pfd->aid, prefix_s, &pfd->plen) ||
                !ipv6_parse(prefix_s, &pfd->prefix)) {
                pfd->prefix = in6addr_any;
            }
        } else if (pfd->state == PREFIX_PENDING && ovnsb_idl_txn) {
            char prefix_str[INET6_ADDRSTRLEN + 1] = {0};
            if (!ipv6_string_mapped(prefix_str, &pfd->prefix)) {
                goto out;
            }
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(20, 40);
            VLOG_DBG_RL(&rl, "updating port_binding for %s with prefix %s/%d"
                        " aid %d", pb->logical_port, prefix_str, pfd->plen,
                        pfd->aid);

            pfd->state = PREFIX_DONE;
            pfd->last_complete = time_msec();
            pfd->next_announce = pfd->last_complete + pfd->t1;
            struct smap options;
            smap_clone(&options, &pb->options);
            smap_remove(&options, "ipv6_ra_pd_list");
            smap_add_format(&options, "ipv6_ra_pd_list", "%d:%s/%d",
                            pfd->aid, prefix_str, pfd->plen);
            sbrec_port_binding_set_options(pb, &options);
            smap_destroy(&options);
        }
out:
        pfd->last_used = time_msec();
        destroy_lport_addresses(&c_addrs);
    }

    return changed;
}

#define IPV6_PREFIXD_STALE_TIMEOUT  180000LL
static void
prepare_ipv6_prefixd(struct ovsdb_idl_txn *ovnsb_idl_txn,
                     struct ovsdb_idl_index *sbrec_port_binding_by_name,
                     const struct shash *local_active_ports_ipv6_pd,
                     const struct sbrec_chassis *chassis,
                     const struct sset *active_tunnels,
                     const struct hmap *local_datapaths)
    OVS_REQUIRES(pinctrl_mutex)
{
    bool changed = false;

    struct shash_node *iter;
    SHASH_FOR_EACH (iter, local_active_ports_ipv6_pd) {
        const struct sbrec_port_binding *pb = iter->data;
        const struct local_datapath *ld =
            get_local_datapath(local_datapaths, pb->datapath->tunnel_key);
        int j;

        if (!ld) {
            continue;
        }

        const char *peer_s = smap_get(&pb->options, "peer");
        if (!peer_s) {
            continue;
        }

        const struct sbrec_port_binding *peer
            = lport_lookup_by_name(sbrec_port_binding_by_name, peer_s);
        if (!peer) {
            continue;
        }

        char *redirect_name = xasprintf("cr-%s", pb->logical_port);
        bool resident = lport_is_chassis_resident(
                sbrec_port_binding_by_name, chassis, active_tunnels,
                redirect_name);
        free(redirect_name);
        if ((strcmp(pb->type, "l3gateway") || pb->chassis != chassis) &&
            !resident) {
            continue;
        }

        struct in6_addr ip6_addr;
        struct eth_addr ea = eth_addr_zero;
        for (j = 0; j < pb->n_mac; j++) {
            struct lport_addresses laddrs;

            if (!extract_lsp_addresses(pb->mac[j], &laddrs)) {
                continue;
            }

            ea = laddrs.ea;
            if (laddrs.n_ipv6_addrs > 0) {
                ip6_addr = laddrs.ipv6_addrs[0].addr;
                destroy_lport_addresses(&laddrs);
                break;
            }
            destroy_lport_addresses(&laddrs);
        }

        if (eth_addr_is_zero(ea)) {
            continue;
        }

        if (j == pb->n_mac) {
            in6_generate_lla(ea, &ip6_addr);
        }

        changed |= fill_ipv6_prefix_state(ovnsb_idl_txn, ld,
                                          ea, ip6_addr,
                                          peer->tunnel_key,
                                          peer->datapath->tunnel_key);
    }

    SHASH_FOR_EACH_SAFE (iter, &ipv6_prefixd) {
        struct ipv6_prefixd_state *pfd = iter->data;
        if (pfd->last_used + IPV6_PREFIXD_STALE_TIMEOUT < time_msec()) {
            shash_delete(&ipv6_prefixd, iter);
            free(pfd);
        }
    }

    if (changed) {
        notify_pinctrl_handler();
    }
}

static struct buffered_packets_ctx buffered_packets_ctx;

static void
init_buffered_packets_ctx(void)
{
    ovn_buffered_packets_ctx_init(&buffered_packets_ctx);
}

static void
destroy_buffered_packets_ctx(void)
{
    ovn_buffered_packets_ctx_destroy(&buffered_packets_ctx);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_buffered_packets(struct dp_packet *pkt_in,
                                const struct match *md, bool is_arp)
OVS_REQUIRES(pinctrl_mutex)
{
    struct in6_addr ip;
    uint64_t dp_key = ntohll(md->flow.metadata);
    uint64_t oport_key = md->flow.regs[MFF_LOG_OUTPORT - MFF_REG0];

    if (is_arp) {
        ip = in6_addr_mapped_ipv4(htonl(md->flow.regs[0]));
    } else {
        ovs_be128 ip6 = hton128(flow_get_xxreg(&md->flow, 0));
        memcpy(&ip, &ip6, sizeof ip);
    }

    struct buffered_packets *bp =
        ovn_buffered_packets_add(&buffered_packets_ctx, dp_key, oport_key, ip);
    if (!bp) {
        COVERAGE_INC(pinctrl_drop_buffered_packets_map);
        return;
    }

    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 4096);
    reload_metadata(&ofpacts, md);
    /* reload pkt_mark field */
    const struct mf_field *pkt_mark_field = mf_from_id(MFF_PKT_MARK);
    union mf_value pkt_mark_value;
    mf_get_value(pkt_mark_field, &md->flow, &pkt_mark_value);
    ofpact_put_set_field(&ofpacts, pkt_mark_field, &pkt_mark_value, NULL);

    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_OUTPUT_INIT;

    struct packet_data *pd = ovn_packet_data_create(ofpacts, pkt_in);
    ovn_buffered_packets_packet_data_enqueue(bp, pd);

    /* There is a chance that the MAC binding was already created. */
    notify_pinctrl_main();
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_arp(struct rconn *swconn, const struct flow *ip_flow,
                   struct dp_packet *pkt_in,
                   const struct match *md, struct ofpbuf *userdata)
{
    /* This action only works for IP packets, and the switch should only send
     * us IP packets this way, but check here just to be sure. */
    if (ip_flow->dl_type != htons(ETH_TYPE_IP)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "ARP action on non-IP packet (Ethertype %"PRIx16")",
                     ntohs(ip_flow->dl_type));
        return;
    }

    ovs_mutex_lock(&pinctrl_mutex);
    pinctrl_handle_buffered_packets(pkt_in, md, true);
    ovs_mutex_unlock(&pinctrl_mutex);

    /* Compose an ARP packet. */
    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    compose_arp__(&packet);

    struct eth_header *eth = dp_packet_eth(&packet);
    eth->eth_dst = ip_flow->dl_dst;
    eth->eth_src = ip_flow->dl_src;

    struct arp_eth_header *arp = dp_packet_l3(&packet);
    arp->ar_op = htons(ARP_OP_REQUEST);
    arp->ar_sha = ip_flow->dl_src;
    put_16aligned_be32(&arp->ar_spa, ip_flow->nw_src);
    arp->ar_tha = eth_addr_zero;
    put_16aligned_be32(&arp->ar_tpa, ip_flow->nw_dst);

    if (ip_flow->vlans[0].tci & htons(VLAN_CFI)) {
        eth_push_vlan(&packet, htons(ETH_TYPE_VLAN_8021Q),
                      ip_flow->vlans[0].tci);
    }

    set_actions_and_enqueue_msg(swconn, &packet, md, userdata);
    dp_packet_uninit(&packet);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_icmp(struct rconn *swconn, const struct flow *ip_flow,
                    struct dp_packet *pkt_in,
                    const struct match *md, struct ofpbuf *userdata,
                    bool set_icmp_code, bool loopback)
{
    /* This action only works for IP packets, and the switch should only send
     * us IP packets this way, but check here just to be sure. */
    if (ip_flow->dl_type != htons(ETH_TYPE_IP) &&
        ip_flow->dl_type != htons(ETH_TYPE_IPV6)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl,
                     "ICMP action on non-IP packet (eth_type 0x%"PRIx16")",
                     ntohs(ip_flow->dl_type));
        return;
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;

    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    struct eth_addr eth_src = loopback ? ip_flow->dl_dst : ip_flow->dl_src;
    struct eth_addr eth_dst = loopback ? ip_flow->dl_src : ip_flow->dl_dst;

    if (get_dl_type(ip_flow) == htons(ETH_TYPE_IP)) {
        struct ip_header *in_ip = dp_packet_l3(pkt_in);
        uint16_t in_ip_len = ntohs(in_ip->ip_tot_len);
        if (in_ip_len < IP_HEADER_LEN) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl,
                        "ICMP action on IP packet with invalid length (%u)",
                        in_ip_len);
            return;
        }

        ovs_be32 nw_src = loopback ? ip_flow->nw_dst : ip_flow->nw_src;
        ovs_be32 nw_dst = loopback ? ip_flow->nw_src : ip_flow->nw_dst;

        /* RFC 1122: 3.2.2	MUST send at least the IP header and 8 bytes
         * of header. MAY send more.
         * RFC says return as much as we can without exceeding 576
         * bytes.
         * So, lets return as much as we can. */

        /* Calculate available room to include the original IP + data. */
        uint16_t room = 576 - (sizeof(struct eth_header)
                               + sizeof(struct ip_header)
                               + sizeof(struct icmp_header));
        if (in_ip_len > room) {
            in_ip_len = room;
        }

        uint16_t ip_total_len = sizeof(struct icmp_header) + in_ip_len;

        pinctrl_compose_ipv4(&packet, eth_src, eth_dst, nw_src, nw_dst,
                             IPPROTO_ICMP, 255, ip_total_len);

        uint8_t icmp_code = 1;
        if (set_icmp_code && in_ip->ip_proto == IPPROTO_UDP) {
            icmp_code = 3;
        }

        struct icmp_header *ih = dp_packet_l4(&packet);

        /* The packet's L4 data was allocated and will never be NULL, inform
         * the compiler about that.
         */
        ovs_assert(ih);

        packet_set_icmp(&packet, ICMP4_DST_UNREACH, icmp_code);

        /* Include original IP + data. */
        void *data = ih + 1;
        memcpy(data, in_ip, in_ip_len);

        ih->icmp_csum = 0;
        ih->icmp_csum = csum(ih, sizeof *ih + in_ip_len);
    } else {
        struct ovs_16aligned_ip6_hdr *in_ip = dp_packet_l3(pkt_in);
        uint16_t in_ip_len = (uint16_t) sizeof *in_ip + ntohs(in_ip->ip6_plen);

        const struct in6_addr *ip6_src =
            loopback ? &ip_flow->ipv6_dst : &ip_flow->ipv6_src;
        const struct in6_addr *ip6_dst =
            loopback ? &ip_flow->ipv6_src : &ip_flow->ipv6_dst;

        /* RFC 4443: 3.1.
         *
         * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |     Type      |     Code      |          Checksum             |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |                             Unused                            |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |                    As much of invoking packet                 |
         * +                as possible without the ICMPv6 packet          +
         * |                exceeding the minimum IPv6 MTU [IPv6]          |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        uint16_t room = 1280 - (sizeof(struct eth_header)
                                + sizeof(struct ip6_hdr)
                                + ICMP6_DATA_HEADER_LEN);
        if (in_ip_len > room) {
            in_ip_len = room;
        }

        uint16_t ip_total_len =
            sizeof(struct icmp6_data_header) + in_ip_len;
        pinctrl_compose_ipv6(&packet, eth_src, eth_dst,
                             CONST_CAST(struct in6_addr *, ip6_src),
                             CONST_CAST(struct in6_addr *, ip6_dst),
                             IPPROTO_ICMPV6, 255, ip_total_len);

        struct icmp6_data_header *ih = dp_packet_l4(&packet);
        ih->icmp6_base.icmp6_type = ICMP6_DST_UNREACH;
        ih->icmp6_base.icmp6_code = 1;

        if (set_icmp_code && in_ip->ip6_nxt == IPPROTO_UDP) {
            ih->icmp6_base.icmp6_code = ICMP6_DST_UNREACH_NOPORT;
        }
        ih->icmp6_base.icmp6_cksum = 0;

        void *data = ih + 1;
        memcpy(data, in_ip, in_ip_len);
        uint32_t icmpv6_csum =
            packet_csum_pseudoheader6(dp_packet_l3(&packet));
        ih->icmp6_base.icmp6_cksum = csum_finish(
            csum_continue(icmpv6_csum, ih,
                          in_ip_len + ICMP6_DATA_HEADER_LEN));
    }

    if (ip_flow->vlans[0].tci & htons(VLAN_CFI)) {
        eth_push_vlan(&packet, htons(ETH_TYPE_VLAN_8021Q),
                      ip_flow->vlans[0].tci);
    }

    set_actions_and_enqueue_msg(swconn, &packet, md, userdata);
    dp_packet_uninit(&packet);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_tcp_reset(struct rconn *swconn, const struct flow *ip_flow,
                         struct dp_packet *pkt_in,
                         const struct match *md, struct ofpbuf *userdata,
                         bool loopback)
{
    /* This action only works for TCP segments, and the switch should only send
     * us TCP segments this way, but check here just to be sure. */
    if (ip_flow->nw_proto != IPPROTO_TCP) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "TCP_RESET action on non-TCP packet");
        return;
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;

    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);

    struct eth_addr eth_src = loopback ? ip_flow->dl_dst : ip_flow->dl_src;
    struct eth_addr eth_dst = loopback ? ip_flow->dl_src : ip_flow->dl_dst;

    if (get_dl_type(ip_flow) == htons(ETH_TYPE_IPV6)) {
        const struct in6_addr *ip6_src =
            loopback ? &ip_flow->ipv6_dst : &ip_flow->ipv6_src;
        const struct in6_addr *ip6_dst =
            loopback ? &ip_flow->ipv6_src : &ip_flow->ipv6_dst;
        pinctrl_compose_ipv6(&packet, eth_src, eth_dst,
                             (struct in6_addr *) ip6_src,
                             (struct in6_addr *) ip6_dst,
                             IPPROTO_TCP, 63, TCP_HEADER_LEN);
    } else {
        ovs_be32 nw_src = loopback ? ip_flow->nw_dst : ip_flow->nw_src;
        ovs_be32 nw_dst = loopback ? ip_flow->nw_src : ip_flow->nw_dst;
        pinctrl_compose_ipv4(&packet, eth_src, eth_dst, nw_src, nw_dst,
                             IPPROTO_TCP, 63, TCP_HEADER_LEN);
    }

    struct tcp_header *th = dp_packet_l4(&packet);

    th->tcp_csum = 0;
    th->tcp_dst = ip_flow->tp_src;
    th->tcp_src = ip_flow->tp_dst;

    th->tcp_ctl = htons((5 << 12) | TCP_RST | TCP_ACK);
    put_16aligned_be32(&th->tcp_seq, 0);

    struct tcp_header *tcp_in = dp_packet_l4(pkt_in);
    uint32_t tcp_seq = ntohl(get_16aligned_be32(&tcp_in->tcp_seq)) + 1;
    put_16aligned_be32(&th->tcp_ack, htonl(tcp_seq));

    uint32_t csum;
    if (get_dl_type(ip_flow) == htons(ETH_TYPE_IPV6)) {
        csum = packet_csum_pseudoheader6(dp_packet_l3(&packet));
    } else {
        csum = packet_csum_pseudoheader(dp_packet_l3(&packet));
    }
    csum = csum_continue(csum, th, dp_packet_size(&packet) -
                        ((const unsigned char *)th -
                        (const unsigned char *)dp_packet_eth(&packet)));
    th->tcp_csum = csum_finish(csum);

    set_actions_and_enqueue_msg(swconn, &packet, md, userdata);
    dp_packet_uninit(&packet);
}

static void
pinctrl_handle_sctp_abort(struct rconn *swconn, const struct flow *ip_flow,
                         struct dp_packet *pkt_in,
                         const struct match *md, struct ofpbuf *userdata,
                         bool loopback)
{
    if (ip_flow->nw_proto != IPPROTO_SCTP) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "SCTP_ABORT action on non-SCTP packet");
        return;
    }

    struct sctp_header *sh_in = dp_packet_l4(pkt_in);
    if (!sh_in) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "SCTP_ABORT action on malformed SCTP packet");
        return;
    }

    const struct sctp_chunk_header *sh_in_chunk =
        dp_packet_get_sctp_payload(pkt_in);
    if (!sh_in_chunk) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "SCTP_ABORT action on SCTP packet with no chunks");
        return;
    }

    if (sh_in_chunk->type == SCTP_CHUNK_TYPE_ABORT) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "sctp_abort action on incoming SCTP ABORT.");
        return;
    }

    const struct sctp_16aligned_init_chunk *sh_in_init = NULL;
    if (sh_in_chunk->type == SCTP_CHUNK_TYPE_INIT) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        sh_in_init = dp_packet_at(pkt_in, pkt_in->l4_ofs +
                                          SCTP_HEADER_LEN +
                                          SCTP_CHUNK_HEADER_LEN,
                                  SCTP_INIT_CHUNK_LEN);
        if (!sh_in_init) {
            VLOG_WARN_RL(&rl, "Incomplete SCTP INIT chunk. Ignoring packet.");
            return;
        }
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;

    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);

    struct eth_addr eth_src = loopback ? ip_flow->dl_dst : ip_flow->dl_src;
    struct eth_addr eth_dst = loopback ? ip_flow->dl_src : ip_flow->dl_dst;

    if (get_dl_type(ip_flow) == htons(ETH_TYPE_IPV6)) {
        const struct in6_addr *ip6_src =
            loopback ? &ip_flow->ipv6_dst : &ip_flow->ipv6_src;
        const struct in6_addr *ip6_dst =
            loopback ? &ip_flow->ipv6_src : &ip_flow->ipv6_dst;
        pinctrl_compose_ipv6(&packet, eth_src, eth_dst,
                             (struct in6_addr *) ip6_src,
                             (struct in6_addr *) ip6_dst,
                             IPPROTO_SCTP, 63, SCTP_HEADER_LEN +
                                               SCTP_CHUNK_HEADER_LEN);
    } else {
        ovs_be32 nw_src = loopback ? ip_flow->nw_dst : ip_flow->nw_src;
        ovs_be32 nw_dst = loopback ? ip_flow->nw_src : ip_flow->nw_dst;
        pinctrl_compose_ipv4(&packet, eth_src, eth_dst, nw_src, nw_dst,
                             IPPROTO_SCTP, 63, SCTP_HEADER_LEN +
                                               SCTP_CHUNK_HEADER_LEN);
    }

    struct sctp_header *sh = dp_packet_l4(&packet);
    sh->sctp_dst = ip_flow->tp_src;
    sh->sctp_src = ip_flow->tp_dst;
    put_16aligned_be32(&sh->sctp_csum, 0);

    bool tag_reflected;
    if (get_16aligned_be32(&sh_in->sctp_vtag) == 0 && sh_in_init) {
        /* See RFC 4960 Section 8.4, item 3. */
        sh->sctp_vtag = sh_in_init->initiate_tag;
        tag_reflected = false;
    } else {
        /* See RFC 4960 Section 8.4, item 8. */
        sh->sctp_vtag = sh_in->sctp_vtag;
        tag_reflected = true;
    }

    struct sctp_chunk_header *ah =
        ALIGNED_CAST(struct sctp_chunk_header *, sh + 1);
    ah->type = SCTP_CHUNK_TYPE_ABORT;
    ah->flags = tag_reflected ? SCTP_ABORT_CHUNK_FLAG_T : 0,
    ah->length = htons(SCTP_CHUNK_HEADER_LEN),

    put_16aligned_be32(&sh->sctp_csum, crc32c((void *) sh,
                                              dp_packet_l4_size(&packet)));

    set_actions_and_enqueue_msg(swconn, &packet, md, userdata);
    dp_packet_uninit(&packet);
}

static bool
pinctrl_handle_reject_ignore_pkt(const struct flow *ip_flow,
                                 struct dp_packet *pkt_in)
{
    if (ip_flow->nw_proto == IPPROTO_TCP) {
        struct tcp_header *th = dp_packet_l4(pkt_in);
        if (!th || (TCP_FLAGS(th->tcp_ctl) & TCP_RST)) {
            return true;
        }
    } else {
        if (is_icmpv4(ip_flow, NULL)) {
            struct icmp_header *ih = dp_packet_l4(pkt_in);
            if (!ih || (ih->icmp_type == ICMP4_DST_UNREACH)) {
                return true;
            }
        } else if (is_icmpv6(ip_flow, NULL)) {
            struct icmp6_data_header *ih = dp_packet_l4(pkt_in);
            if (!ih || (ih->icmp6_base.icmp6_type == ICMP6_DST_UNREACH)) {
                return true;
            }
        }
    }
    return false;
}

static void
pinctrl_handle_reject(struct rconn *swconn, const struct flow *ip_flow,
                      struct dp_packet *pkt_in,
                      const struct match *md, struct ofpbuf *userdata)
{
    if (pinctrl_handle_reject_ignore_pkt(ip_flow, pkt_in)) {
        return;
    }

    if (ip_flow->nw_proto == IPPROTO_TCP) {
        pinctrl_handle_tcp_reset(swconn, ip_flow, pkt_in, md, userdata, true);
    } else if (ip_flow->nw_proto == IPPROTO_SCTP) {
        pinctrl_handle_sctp_abort(swconn, ip_flow, pkt_in, md, userdata, true);
    } else {
        pinctrl_handle_icmp(swconn, ip_flow, pkt_in, md, userdata, true, true);
    }
}

static bool
is_dhcp_flags_broadcast(ovs_be16 flags)
{
    return flags & htons(DHCP_BROADCAST_FLAG);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_put_dhcp_opts(
    struct rconn *swconn,
    struct dp_packet *pkt_in, struct ofputil_packet_in *pin,
    struct flow *in_flow, struct ofpbuf *userdata,
    struct ofpbuf *continuation)
{
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out_ptr = NULL;
    struct ofpbuf *dhcp_inform_reply_buf = NULL;
    uint32_t success = 0;

    /* Parse result field. */
    const struct mf_field *f;
    enum ofperr ofperr = nx_pull_header(userdata, NULL, &f, NULL);
    if (ofperr) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "bad result OXM (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    /* Parse result offset and offer IP. */
    ovs_be32 *ofsp = ofpbuf_try_pull(userdata, sizeof *ofsp);
    ovs_be32 *offer_ip = ofpbuf_try_pull(userdata, sizeof *offer_ip);
    if (!ofsp || !offer_ip) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "offset or offer_ip not present in the userdata");
        goto exit;
    }

    /* Check that the result is valid and writable. */
    struct mf_subfield dst = { .field = f, .ofs = ntohl(*ofsp), .n_bits = 1 };
    ofperr = mf_check_dst(&dst, NULL);
    if (ofperr) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "bad result bit (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    if (!userdata->size) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "DHCP options not present in the userdata");
        goto exit;
    }

    /* Validate the DHCP request packet.
     * Format of the DHCP packet is
     * ------------------------------------------------------------------------
     *| UDP HEADER  | DHCP HEADER  | 4 Byte DHCP Cookie | DHCP OPTIONS(var len)|
     * ------------------------------------------------------------------------
     */

    const char *end = (char *)dp_packet_l4(pkt_in) + dp_packet_l4_size(pkt_in);
    const char *in_dhcp_ptr = dp_packet_get_udp_payload(pkt_in);
    if (!in_dhcp_ptr) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Invalid or incomplete DHCP packet received");
        goto exit;
    }

    const struct dhcp_header *in_dhcp_data
        = (const struct dhcp_header *) in_dhcp_ptr;
    in_dhcp_ptr += sizeof *in_dhcp_data;
    if (in_dhcp_ptr > end) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Invalid or incomplete DHCP packet received, "
                     "bad data length");
        goto exit;
    }
    if (in_dhcp_data->op != DHCP_OP_REQUEST) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Invalid opcode in the DHCP packet: %d",
                     in_dhcp_data->op);
        goto exit;
    }

    /* DHCP options follow the DHCP header. The first 4 bytes of the DHCP
     * options is the DHCP magic cookie followed by the actual DHCP options.
     */
    ovs_be32 magic_cookie = htonl(DHCP_MAGIC_COOKIE);
    if (in_dhcp_ptr + sizeof magic_cookie > end ||
        get_unaligned_be32((const void *) in_dhcp_ptr) != magic_cookie) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "DHCP magic cookie not present in the DHCP packet");
        goto exit;
    }
    in_dhcp_ptr += sizeof magic_cookie;

    bool ipxe_req = false;
    const uint8_t *in_dhcp_msg_type = NULL;
    ovs_be32 request_ip = in_dhcp_data->ciaddr;
    while (in_dhcp_ptr < end) {
        const struct dhcp_opt_header *in_dhcp_opt =
            (const struct dhcp_opt_header *)in_dhcp_ptr;
        if (in_dhcp_opt->code == DHCP_OPT_END) {
            break;
        }
        if (in_dhcp_opt->code == DHCP_OPT_PAD) {
            in_dhcp_ptr += 1;
            continue;
        }
        in_dhcp_ptr += sizeof *in_dhcp_opt;
        if (in_dhcp_ptr > end) {
            break;
        }
        in_dhcp_ptr += in_dhcp_opt->len;
        if (in_dhcp_ptr > end) {
            break;
        }

        switch (in_dhcp_opt->code) {
        case DHCP_OPT_MSG_TYPE:
            if (in_dhcp_opt->len == 1) {
                in_dhcp_msg_type = DHCP_OPT_PAYLOAD(in_dhcp_opt);
            }
            break;
        case DHCP_OPT_REQ_IP:
            if (in_dhcp_opt->len == 4) {
                request_ip = get_unaligned_be32(DHCP_OPT_PAYLOAD(in_dhcp_opt));
            }
            break;
        case DHCP_OPT_ETHERBOOT:
            ipxe_req = true;
            break;
        default:
            break;
        }
    }

    /* Check that the DHCP Message Type (opt 53) is present or not with
     * valid values - DHCP_MSG_DISCOVER or DHCP_MSG_REQUEST.
     */
    if (!in_dhcp_msg_type) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Missing DHCP message type");
        goto exit;
    }

    struct ofpbuf *reply_dhcp_opts_ptr = userdata;
    uint8_t msg_type = 0;

    switch (*in_dhcp_msg_type) {
    case DHCP_MSG_DISCOVER:
        msg_type = DHCP_MSG_OFFER;
        if (in_flow->nw_dst != htonl(INADDR_BROADCAST)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "DHCP DISCOVER must be Broadcast");
            goto exit;
        }
        break;
    case DHCP_MSG_REQUEST: {
        msg_type = DHCP_MSG_ACK;
        if (request_ip != *offer_ip) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "DHCPREQUEST requested IP "IP_FMT" does not "
                         "match offer "IP_FMT, IP_ARGS(request_ip),
                         IP_ARGS(*offer_ip));
            msg_type = DHCP_MSG_NAK;
        }
        break;
    }
    case OVN_DHCP_MSG_RELEASE: {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(20, 40);
        const struct eth_header *l2 = dp_packet_eth(pkt_in);
        VLOG_INFO_RL(&rl, "DHCPRELEASE "ETH_ADDR_FMT " "IP_FMT"",
                     ETH_ADDR_ARGS(l2->eth_src),
                     IP_ARGS(in_dhcp_data->ciaddr));
        break;
    }
    case OVN_DHCP_MSG_INFORM: {
        /* RFC 2131 section 3.4.
         * Remove all the offer ip related dhcp options and
         * all the time related dhcp options.
         * Loop through the dhcp option defined in the userdata buffer
         * and copy all the options into dhcp_inform_reply_buf skipping
         * the not required ones.
         * */
        msg_type = DHCP_MSG_ACK;
        in_dhcp_ptr = userdata->data;
        end = (const char *)userdata->data + userdata->size;

        /* The buf size cannot be greater > userdata->size. */
        dhcp_inform_reply_buf = ofpbuf_new(userdata->size);

        reply_dhcp_opts_ptr = dhcp_inform_reply_buf;
        while (in_dhcp_ptr < end) {
            const struct dhcp_opt_header *in_dhcp_opt =
                (const struct dhcp_opt_header *)in_dhcp_ptr;

            switch (in_dhcp_opt->code) {
            case OVN_DHCP_OPT_CODE_NETMASK:
            case OVN_DHCP_OPT_CODE_LEASE_TIME:
            case OVN_DHCP_OPT_CODE_T1:
            case OVN_DHCP_OPT_CODE_T2:
                break;
            default:
                /* Copy the dhcp option to reply_dhcp_opts_ptr. */
                ofpbuf_put(reply_dhcp_opts_ptr, in_dhcp_opt,
                           in_dhcp_opt->len + sizeof *in_dhcp_opt);
                break;
            }

            in_dhcp_ptr += sizeof *in_dhcp_opt;
            if (in_dhcp_ptr > end) {
                break;
            }
            in_dhcp_ptr += in_dhcp_opt->len;
            if (in_dhcp_ptr > end) {
                break;
            }
        }

        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(20, 40);
        VLOG_INFO_RL(&rl, "DHCPINFORM from "ETH_ADDR_FMT " "IP_FMT"",
                     ETH_ADDR_ARGS(in_flow->dl_src),
                     IP_ARGS(in_flow->nw_src));

        break;
    }
    case OVN_DHCP_MSG_DECLINE:
        if (request_ip == *offer_ip) {
            VLOG_INFO("DHCPDECLINE from "ETH_ADDR_FMT ", "IP_FMT" duplicated",
                      ETH_ADDR_ARGS(in_flow->dl_src), IP_ARGS(*offer_ip));
        }
        goto exit;
    default: {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Invalid DHCP message type: %d", *in_dhcp_msg_type);
        goto exit;
    }
    }

    if (!msg_type) {
        goto exit;
    }

    /* Frame the DHCP reply packet
     * Total DHCP options length will be options stored in the
     * reply_dhcp_opts_ptr + 16 bytes. Note that the DHCP options stored in
     * reply_dhcp_opts_ptr are not included in DHCPNAK messages.
     *
     * --------------------------------------------------------------
     *| 4 Bytes (dhcp cookie) | 3 Bytes (option type) | DHCP options |
     * --------------------------------------------------------------
     *| 4 Bytes padding | 1 Byte (option end 0xFF ) | 4 Bytes padding|
     * --------------------------------------------------------------
     */
    ovs_be32 next_server = in_dhcp_data->siaddr;
    bool bootfile_name_set = false;
    in_dhcp_ptr = reply_dhcp_opts_ptr->data;
    end = (const char *)reply_dhcp_opts_ptr->data + reply_dhcp_opts_ptr->size;

    while (in_dhcp_ptr < end) {
        struct dhcp_opt_header *in_dhcp_opt =
            (struct dhcp_opt_header *)in_dhcp_ptr;

        switch (in_dhcp_opt->code) {
        case DHCP_OPT_NEXT_SERVER_CODE:
            next_server = get_unaligned_be32(DHCP_OPT_PAYLOAD(in_dhcp_opt));
            break;
        case DHCP_OPT_BOOTFILE_CODE: ;
            unsigned char *ptr = (unsigned char *)in_dhcp_opt;
            int len = sizeof *in_dhcp_opt + in_dhcp_opt->len;
            struct dhcp_opt_header *next_dhcp_opt =
                (struct dhcp_opt_header *)(ptr + len);

            if (next_dhcp_opt->code == DHCP_OPT_BOOTFILE_ALT_CODE) {
                if (!ipxe_req) {
                    ofpbuf_pull(reply_dhcp_opts_ptr, len);
                    next_dhcp_opt->code = DHCP_OPT_BOOTFILE_CODE;
                } else {
                    char *buf = xmalloc(len);

                    memcpy(buf, in_dhcp_opt, len);
                    ofpbuf_pull(reply_dhcp_opts_ptr,
                                sizeof *in_dhcp_opt + next_dhcp_opt->len);
                    memcpy(reply_dhcp_opts_ptr->data, buf, len);
                    free(buf);
                }
            }
            bootfile_name_set = true;
            break;
        case DHCP_OPT_BOOTFILE_ALT_CODE:
            if (!bootfile_name_set) {
                in_dhcp_opt->code = DHCP_OPT_BOOTFILE_CODE;
            }
            break;
        }

        in_dhcp_ptr += sizeof *in_dhcp_opt;
        if (in_dhcp_ptr > end) {
            break;
        }
        in_dhcp_ptr += in_dhcp_opt->len;
        if (in_dhcp_ptr > end) {
            break;
        }
    }

    uint16_t new_l4_size = UDP_HEADER_LEN + DHCP_HEADER_LEN + 16;
    if (msg_type != DHCP_MSG_NAK) {
        new_l4_size += reply_dhcp_opts_ptr->size;
    }
    size_t new_packet_size = pkt_in->l4_ofs + new_l4_size;

    struct dp_packet pkt_out;
    dp_packet_init(&pkt_out, new_packet_size);
    dp_packet_clear(&pkt_out);
    dp_packet_prealloc_tailroom(&pkt_out, new_packet_size);
    pkt_out_ptr = &pkt_out;

    /* Copy the L2 and L3 headers from the pkt_in as they would remain same*/
    dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, pkt_in->l4_ofs), pkt_in->l4_ofs);

    pkt_out.l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out.l2_pad_size = pkt_in->l2_pad_size;
    pkt_out.l3_ofs = pkt_in->l3_ofs;
    pkt_out.l4_ofs = pkt_in->l4_ofs;

    struct udp_header *udp = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, UDP_HEADER_LEN), UDP_HEADER_LEN);

    struct dhcp_header *dhcp_data = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, DHCP_HEADER_LEN), DHCP_HEADER_LEN);
    dhcp_data->op = DHCP_OP_REPLY;

    if (*in_dhcp_msg_type != OVN_DHCP_MSG_INFORM) {
        dhcp_data->yiaddr = (msg_type == DHCP_MSG_NAK) ? 0 : *offer_ip;
        dhcp_data->siaddr = (msg_type == DHCP_MSG_NAK) ? 0 : next_server;
    } else {
        dhcp_data->yiaddr = 0;
    }

    dp_packet_put(&pkt_out, &magic_cookie, sizeof(ovs_be32));

    uint16_t out_dhcp_opts_size = 12;
    if (msg_type != DHCP_MSG_NAK) {
      out_dhcp_opts_size += reply_dhcp_opts_ptr->size;
    }
    uint8_t *out_dhcp_opts = dp_packet_put_zeros(&pkt_out,
                                                 out_dhcp_opts_size);
    /* DHCP option - type */
    out_dhcp_opts[0] = DHCP_OPT_MSG_TYPE;
    out_dhcp_opts[1] = 1;
    out_dhcp_opts[2] = msg_type;
    out_dhcp_opts += 3;

    if (msg_type != DHCP_MSG_NAK) {
        memcpy(out_dhcp_opts, reply_dhcp_opts_ptr->data,
               reply_dhcp_opts_ptr->size);
        out_dhcp_opts += reply_dhcp_opts_ptr->size;
    }

    /* Padding */
    out_dhcp_opts += 4;
    /* End */
    out_dhcp_opts[0] = DHCP_OPT_END;

    udp->udp_len = htons(new_l4_size);

    /* Send a broadcast IP frame when BROADCAST flag is set. */
    struct ip_header *out_ip = dp_packet_l3(&pkt_out);
    ovs_be32 ip_dst;
    if (!is_dhcp_flags_broadcast(dhcp_data->flags)) {
        ip_dst = *offer_ip;
    } else {
        ip_dst = htonl(0xffffffff);
    }
    put_16aligned_be32(&out_ip->ip_dst, ip_dst);

    out_ip->ip_tot_len = htons(pkt_out.l4_ofs - pkt_out.l3_ofs + new_l4_size);
    udp->udp_csum = 0;
    /* Checksum needs to be initialized to zero. */
    out_ip->ip_csum = 0;
    out_ip->ip_csum = csum(out_ip, sizeof *out_ip);

    pin->packet = dp_packet_data(&pkt_out);
    pin->packet_len = dp_packet_size(&pkt_out);

    /* Log the response. */
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(20, 40);
    const struct eth_header *l2 = dp_packet_eth(&pkt_out);
    VLOG_INFO_RL(&rl, "DHCP%s "ETH_ADDR_FMT" "IP_FMT"",
                 msg_type == DHCP_MSG_OFFER ? "OFFER" :
                   (msg_type == DHCP_MSG_ACK ? "ACK": "NAK"),
                 ETH_ADDR_ARGS(l2->eth_src), IP_ARGS(*offer_ip));

    success = 1;
exit:
    if (!ofperr) {
        union mf_subvalue sv;
        sv.u8_val = success;
        mf_write_subfield(&dst, &sv, &pin->flow_metadata);
    }
    queue_msg(swconn, ofputil_encode_resume(pin, continuation, proto));
    if (pkt_out_ptr) {
        dp_packet_uninit(pkt_out_ptr);
    }

    if (dhcp_inform_reply_buf) {
        ofpbuf_delete(dhcp_inform_reply_buf);
    }
}

static void
encode_dhcpv6_server_id_opt(struct ofpbuf *opts, struct eth_addr *mac)
{
    /* The Server Identifier option carries a DUID
     * identifying a server between a client and a server.
     * See RFC 3315 Sec 9 and Sec 22.3.
     *
     * We use DUID Based on Link-layer Address [DUID-LL].
     */
    struct dhcpv6_opt_server_id *server_id =
            ofpbuf_put_zeros(opts, sizeof *server_id);
    *server_id = (struct dhcpv6_opt_server_id) {
            .opt.code = htons(DHCPV6_OPT_SERVER_ID_CODE),
            .opt.len = htons(DHCP6_OPT_SERVER_ID_LEN - DHCP6_OPT_HEADER_LEN),
            .duid_type = htons(DHCPV6_DUID_LL),
            .hw_type = htons(DHCPV6_HW_TYPE_ETH),
            .mac = *mac
    };
}

static bool
compose_out_dhcpv6_opts(struct ofpbuf *userdata,
                        struct ofpbuf *out_dhcpv6_opts,
                        ovs_be32 iaid, bool ipxe_req, uint8_t fqdn_flags)
{
    while (userdata->size) {
        struct dhcpv6_opt_header *userdata_opt = ofpbuf_try_pull(
            userdata, sizeof *userdata_opt);
        if (!userdata_opt) {
            return false;
        }

        size_t size = ntohs(userdata_opt->len);
        void *userdata_opt_data = ofpbuf_try_pull(userdata, size);
        if (!userdata_opt_data) {
            return false;
        }

        switch (ntohs(userdata_opt->code)) {
        case DHCPV6_OPT_SERVER_ID_CODE:
            encode_dhcpv6_server_id_opt(out_dhcpv6_opts, userdata_opt_data);
            break;

        case DHCPV6_OPT_IA_ADDR_CODE:
        {
            if (size != sizeof(struct in6_addr)) {
                return false;
            }

            if (!iaid) {
                /* If iaid is None, it means its an DHCPv6 information request.
                 * Don't put IA_NA option in the response. */
                 break;
            }
            /* IA Address option is used to specify IPv6 addresses associated
             * with an IA_NA or IA_TA. The IA Address option must be
             * encapsulated in the Options field of an IA_NA or IA_TA option.
             *
             * We will encapsulate the IA Address within the IA_NA option.
             * Please see RFC 3315 section 22.5 and 22.6
             */
            struct dhcpv6_opt_ia_na *opt_ia_na = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_ia_na);
            opt_ia_na->opt.code = htons(DHCPV6_OPT_IA_NA_CODE);
            /* IA_NA length (in bytes)-
             *  IAID - 4
             *  T1   - 4
             *  T2   - 4
             *  IA Address - sizeof(struct dhcpv6_opt_ia_addr)
             */
            opt_ia_na->opt.len = htons(12 + sizeof(struct dhcpv6_opt_ia_addr));
            opt_ia_na->iaid = iaid;
            /* Set the lifetime of the address(es) to infinity */
            opt_ia_na->t1 = OVS_BE32_MAX;
            opt_ia_na->t2 = OVS_BE32_MAX;

            struct dhcpv6_opt_ia_addr *opt_ia_addr = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_ia_addr);
            opt_ia_addr->opt.code = htons(DHCPV6_OPT_IA_ADDR_CODE);
            opt_ia_addr->opt.len = htons(size + 8);
            memcpy(opt_ia_addr->ipv6.s6_addr, userdata_opt_data, size);
            opt_ia_addr->t1 = OVS_BE32_MAX;
            opt_ia_addr->t2 = OVS_BE32_MAX;
            break;
        }

        case DHCPV6_OPT_DNS_SERVER_CODE:
        {
            struct dhcpv6_opt_header *opt_dns = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_dns);
            opt_dns->code = htons(DHCPV6_OPT_DNS_SERVER_CODE);
            opt_dns->len = htons(size);
            ofpbuf_put(out_dhcpv6_opts, userdata_opt_data, size);
            break;
        }

        case DHCPV6_OPT_DOMAIN_SEARCH_CODE:
        {
            struct dhcpv6_opt_header *opt_dsl = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_dsl);
            opt_dsl->code = htons(DHCPV6_OPT_DOMAIN_SEARCH_CODE);
            opt_dsl->len = htons(size + 2);
            uint8_t *data = ofpbuf_put_zeros(out_dhcpv6_opts, size + 2);
            *data = size;
            memcpy(data + 1, userdata_opt_data, size);
            break;
        }

        case DHCPV6_OPT_BOOT_FILE_URL:
            if (ipxe_req) {
                struct dhcpv6_opt_header *opt_dsl = ofpbuf_put_zeros(
                    out_dhcpv6_opts, sizeof *opt_dsl);
                opt_dsl->code = htons(DHCPV6_OPT_BOOT_FILE_URL);
                opt_dsl->len = htons(size);
                ofpbuf_put(out_dhcpv6_opts, userdata_opt_data, size);
            }
            break;

        case DHCPV6_OPT_BOOT_FILE_URL_ALT: {
            if (!ipxe_req) {
                struct dhcpv6_opt_header *opt_dsl = ofpbuf_put_zeros(
                    out_dhcpv6_opts, sizeof *opt_dsl);
                opt_dsl->code = htons(DHCPV6_OPT_BOOT_FILE_URL);
                opt_dsl->len = htons(size);
                ofpbuf_put(out_dhcpv6_opts, userdata_opt_data, size);
            }
            break;
        }

        case DHCPV6_OPT_FQDN_CODE: {
            if (fqdn_flags != DHCPV6_FQDN_FLAGS_UNDEFINED) {
                struct dhcpv6_opt_header *header =
                        ofpbuf_put_zeros(out_dhcpv6_opts, sizeof *header);
                header->code = htons(DHCPV6_OPT_FQDN_CODE);
                header->len = htons(size + 1);
                uint8_t *flags = ofpbuf_put_zeros(out_dhcpv6_opts, 1);
                /* Always set N to 1, if client requested S inform him that it
                 * was overwritten by the server. */
                *flags |= DHCPV6_FQDN_FLAGS_N;
                if (fqdn_flags & DHCPV6_FQDN_FLAGS_S) {
                    *flags |= DHCPV6_FQDN_FLAGS_O;
                }
                ofpbuf_put(out_dhcpv6_opts, userdata_opt_data, size);
            }
            break;
        }

        default:
            return false;
        }
    }
    return true;
}

static bool
compose_dhcpv6_status(struct ofpbuf *userdata, struct ofpbuf *opts)
{
    while (userdata->size) {
        struct dhcpv6_opt_header *userdata_opt = ofpbuf_try_pull(
                userdata, sizeof *userdata_opt);
        if (!userdata_opt) {
            return false;
        }

        size_t size = ntohs(userdata_opt->len);
        void *userdata_opt_data = ofpbuf_try_pull(userdata, size);
        if (!userdata_opt_data) {
            return false;
        }

        /* We care only about server id. Ignore everything else. */
        if (ntohs(userdata_opt->code) == DHCPV6_OPT_SERVER_ID_CODE) {
            encode_dhcpv6_server_id_opt(opts, userdata_opt_data);
            break;
        }
    }

    /* Put success status code to the end. */
    struct dhcpv6_opt_status *status = ofpbuf_put_zeros(opts, sizeof *status);
    *status = (struct dhcpv6_opt_status) {
        .opt.code = htons(DHCPV6_OPT_STATUS_CODE),
        .opt.len = htons(DHCP6_OPT_STATUS_LEN - DHCP6_OPT_HEADER_LEN),
        .status_code = htons(DHCPV6_STATUS_CODE_SUCCESS),
    };

    return true;
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_put_dhcpv6_opts(
    struct rconn *swconn,
    struct dp_packet *pkt_in, struct ofputil_packet_in *pin,
    struct ofpbuf *userdata, struct ofpbuf *continuation OVS_UNUSED)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out_ptr = NULL;
    uint32_t success = 0;

    /* Parse result field. */
    const struct mf_field *f;
    enum ofperr ofperr = nx_pull_header(userdata, NULL, &f, NULL);
    if (ofperr) {
       VLOG_WARN_RL(&rl, "bad result OXM (%s)", ofperr_to_string(ofperr));
       goto exit;
    }

    /* Parse result offset. */
    ovs_be32 *ofsp = ofpbuf_try_pull(userdata, sizeof *ofsp);
    if (!ofsp) {
        VLOG_WARN_RL(&rl, "offset not present in the userdata");
        goto exit;
    }

    /* Check that the result is valid and writable. */
    struct mf_subfield dst = { .field = f, .ofs = ntohl(*ofsp), .n_bits = 1 };
    ofperr = mf_check_dst(&dst, NULL);
    if (ofperr) {
        VLOG_WARN_RL(&rl, "bad result bit (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    if (!userdata->size) {
        VLOG_WARN_RL(&rl, "DHCPv6 options not present in the userdata");
        goto exit;
    }

    struct udp_header *in_udp = dp_packet_l4(pkt_in);
    const uint8_t *in_dhcpv6_data = dp_packet_get_udp_payload(pkt_in);
    if (!in_udp || !in_dhcpv6_data) {
        VLOG_WARN_RL(&rl, "truncated dhcpv6 packet");
        goto exit;
    }

    uint8_t out_dhcpv6_msg_type;
    uint8_t in_dhcpv6_msg_type = *in_dhcpv6_data;
    bool status_only = false;
    switch (in_dhcpv6_msg_type) {
    case DHCPV6_MSG_TYPE_SOLICIT:
        out_dhcpv6_msg_type = DHCPV6_MSG_TYPE_ADVT;
        break;

    case DHCPV6_MSG_TYPE_REQUEST:
    case DHCPV6_MSG_TYPE_CONFIRM:
    case DHCPV6_MSG_TYPE_DECLINE:
    case DHCPV6_MSG_TYPE_INFO_REQ:
        out_dhcpv6_msg_type = DHCPV6_MSG_TYPE_REPLY;
        break;

    case DHCPV6_MSG_TYPE_RELEASE:
        out_dhcpv6_msg_type = DHCPV6_MSG_TYPE_REPLY;
        status_only = true;
        break;

    default:
        /* Invalid or unsupported DHCPv6 message type */
        goto exit;
    }
    /* Skip 4 bytes (message type (1 byte) + transaction ID (3 bytes). */
    in_dhcpv6_data += 4;
    /* We need to extract IAID from the IA-NA option of the client's DHCPv6
     * solicit/request/confirm packet and copy the same IAID in the Server's
     * response.
     * DHCPv6 information packet (for stateless request will not have IA-NA
     * option. So we don't need to copy that in the Server's response.
     * */
    ovs_be32 iaid = 0;
    struct dhcpv6_opt_header const *in_opt_client_id = NULL;
    size_t udp_len = ntohs(in_udp->udp_len);
    size_t l4_len = dp_packet_l4_size(pkt_in);
    uint8_t *end = (uint8_t *)in_udp + MIN(udp_len, l4_len);
    bool ipxe_req = false;
    uint8_t fqdn_flags = DHCPV6_FQDN_FLAGS_UNDEFINED;
    while (in_dhcpv6_data < end) {
        struct dhcpv6_opt_header const *in_opt =
             (struct dhcpv6_opt_header *)in_dhcpv6_data;
        switch(ntohs(in_opt->code)) {
        case DHCPV6_OPT_IA_NA_CODE:
        {
            struct dhcpv6_opt_ia_na *opt_ia_na = (
                struct dhcpv6_opt_ia_na *)in_opt;
            iaid = opt_ia_na->iaid;
            break;
        }

        case DHCPV6_OPT_CLIENT_ID_CODE:
            in_opt_client_id = in_opt;
            break;

        case DHCPV6_OPT_USER_CLASS: {
            char *user_class = (char *)(in_opt + 1);
            if (!strcmp(user_class + 2, "iPXE")) {
                ipxe_req = true;
            }
            break;
        }

        case DHCPV6_OPT_FQDN_CODE:
            fqdn_flags = *(in_dhcpv6_data + sizeof *in_opt);
            break;

        default:
            break;
        }
        in_dhcpv6_data += sizeof *in_opt + ntohs(in_opt->len);
    }

    if (!in_opt_client_id) {
        VLOG_WARN_RL(&rl, "DHCPv6 option - Client id not present in the "
                     "DHCPv6 packet");
        goto exit;
    }

    if (!iaid && in_dhcpv6_msg_type != DHCPV6_MSG_TYPE_INFO_REQ) {
        VLOG_WARN_RL(&rl, "DHCPv6 option - IA NA not present in the "
                     "DHCPv6 packet");
        goto exit;
    }

    uint64_t out_ofpacts_dhcpv6_opts_stub[256 / 8];
    struct ofpbuf out_dhcpv6_opts =
        OFPBUF_STUB_INITIALIZER(out_ofpacts_dhcpv6_opts_stub);

    bool compose = false;
    if (status_only) {
        compose = compose_dhcpv6_status(userdata, &out_dhcpv6_opts);
    } else {
        compose = compose_out_dhcpv6_opts(userdata, &out_dhcpv6_opts, iaid,
                                          ipxe_req, fqdn_flags);
    }

    if (!compose) {
        VLOG_WARN_RL(&rl, "Invalid userdata");
        goto exit;
    }

    uint16_t new_l4_size
        = (UDP_HEADER_LEN + 4 + sizeof *in_opt_client_id +
           ntohs(in_opt_client_id->len) + out_dhcpv6_opts.size);
    size_t new_packet_size = pkt_in->l4_ofs + new_l4_size;

    struct dp_packet pkt_out;
    dp_packet_init(&pkt_out, new_packet_size);
    dp_packet_clear(&pkt_out);
    dp_packet_prealloc_tailroom(&pkt_out, new_packet_size);
    pkt_out_ptr = &pkt_out;

    /* Copy L2 and L3 headers from pkt_in. */
    dp_packet_put(&pkt_out, dp_packet_pull(pkt_in, pkt_in->l4_ofs),
                  pkt_in->l4_ofs);

    pkt_out.l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out.l2_pad_size = pkt_in->l2_pad_size;
    pkt_out.l3_ofs = pkt_in->l3_ofs;
    pkt_out.l4_ofs = pkt_in->l4_ofs;

    /* Pull the DHCPv6 message type and transaction id from the pkt_in.
     * Need to preserve the transaction id in the DHCPv6 reply packet. */
    struct udp_header *out_udp = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, UDP_HEADER_LEN), UDP_HEADER_LEN);
    uint8_t *out_dhcpv6 = dp_packet_put(&pkt_out, dp_packet_pull(pkt_in, 4), 4);

    /* Set the proper DHCPv6 message type. */
    *out_dhcpv6 = out_dhcpv6_msg_type;

    /* Copy the Client Identifier. */
    dp_packet_put(&pkt_out, in_opt_client_id,
                  sizeof *in_opt_client_id + ntohs(in_opt_client_id->len));

    /* Copy the DHCPv6 Options. */
    dp_packet_put(&pkt_out, out_dhcpv6_opts.data, out_dhcpv6_opts.size);
    out_udp->udp_len = htons(new_l4_size);
    out_udp->udp_csum = 0;

    struct ovs_16aligned_ip6_hdr *out_ip6 = dp_packet_l3(&pkt_out);
    out_ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = out_udp->udp_len;

    uint32_t csum;
    csum = packet_csum_pseudoheader6(dp_packet_l3(&pkt_out));
    csum = csum_continue(csum, out_udp, dp_packet_size(&pkt_out) -
                         ((const unsigned char *)out_udp -
                         (const unsigned char *)dp_packet_eth(&pkt_out)));
    out_udp->udp_csum = csum_finish(csum);
    if (!out_udp->udp_csum) {
        out_udp->udp_csum = htons(0xffff);
    }

    pin->packet = dp_packet_data(&pkt_out);
    pin->packet_len = dp_packet_size(&pkt_out);
    ofpbuf_uninit(&out_dhcpv6_opts);
    success = 1;
exit:
    if (!ofperr) {
        union mf_subvalue sv;
        sv.u8_val = success;
        mf_write_subfield(&dst, &sv, &pin->flow_metadata);
    }
    queue_msg(swconn, ofputil_encode_resume(pin, continuation, proto));
    dp_packet_uninit(pkt_out_ptr);
}

static void
put_be16(struct ofpbuf *buf, ovs_be16 x)
{
    ofpbuf_put(buf, &x, sizeof x);
}

static void
put_be32(struct ofpbuf *buf, ovs_be32 x)
{
    ofpbuf_put(buf, &x, sizeof x);
}

struct dns_data {
    uint64_t *dps;
    size_t n_dps;
    struct smap records;
    struct smap options;
    bool delete;
};

static struct shash dns_cache = SHASH_INITIALIZER(&dns_cache);

/* Called by pinctrl_run(). Runs within the main ovn-controller
 * thread context. */
static void
sync_dns_cache(const struct sbrec_dns_table *dns_table)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct shash_node *iter;
    SHASH_FOR_EACH (iter, &dns_cache) {
        struct dns_data *d = iter->data;
        d->delete = true;
    }

    const struct sbrec_dns *sbrec_dns;
    SBREC_DNS_TABLE_FOR_EACH (sbrec_dns, dns_table) {
        const char *dns_id = smap_get(&sbrec_dns->external_ids, "dns_id");
        if (!dns_id) {
            continue;
        }

        struct dns_data *dns_data = shash_find_data(&dns_cache, dns_id);
        if (!dns_data) {
            dns_data = xmalloc(sizeof *dns_data);
            smap_init(&dns_data->records);
            smap_init(&dns_data->options);
            shash_add(&dns_cache, dns_id, dns_data);
            dns_data->n_dps = 0;
            dns_data->dps = NULL;
        } else {
            free(dns_data->dps);
        }

        dns_data->delete = false;

        if (!smap_equal(&dns_data->records, &sbrec_dns->records)) {
            smap_destroy(&dns_data->records);
            smap_clone(&dns_data->records, &sbrec_dns->records);
        }

        if (pinctrl.dns_supports_ovn_owned
            && !smap_equal(&dns_data->options, &sbrec_dns->options)) {
            smap_destroy(&dns_data->options);
            smap_clone(&dns_data->options, &sbrec_dns->options);
        }

        dns_data->n_dps = sbrec_dns->n_datapaths;
        dns_data->dps = xcalloc(dns_data->n_dps, sizeof(uint64_t));
        for (size_t i = 0; i < sbrec_dns->n_datapaths; i++) {
            dns_data->dps[i] = sbrec_dns->datapaths[i]->tunnel_key;
        }
    }

    SHASH_FOR_EACH_SAFE (iter, &dns_cache) {
        struct dns_data *d = iter->data;
        if (d->delete) {
            shash_delete(&dns_cache, iter);
            smap_destroy(&d->records);
            smap_destroy(&d->options);
            free(d->dps);
            free(d);
        }
    }
}

static void
destroy_dns_cache(void)
{
    struct shash_node *iter;
    SHASH_FOR_EACH_SAFE (iter, &dns_cache) {
        struct dns_data *d = iter->data;
        shash_delete(&dns_cache, iter);
        smap_destroy(&d->records);
        smap_destroy(&d->options);
        free(d->dps);
        free(d);
    }
}

/* Populates dns_answer struct with base data.
 * Copy the answer section
 * Format of the answer section is
 *  - NAME     -> The domain name
 *  - TYPE     -> 2 octets containing one of the RR type codes
 *  - CLASS    -> 2 octets which specify the class of the data
 *                in the RDATA field.
 *  - TTL      -> 32 bit unsigned int specifying the time
 *                interval (in secs) that the resource record
 *                 may be cached before it should be discarded.
 *  - RDLENGTH -> 16 bit integer specifying the length of the
 *                RDATA field.
 *  - RDATA    -> a variable length string of octets that
 *                describes the resource.
 */
static void
dns_build_base_answer(
    struct ofpbuf *dns_answer, const uint8_t *in_queryname,
    uint16_t query_length, int query_type)
{
    ofpbuf_put(dns_answer, in_queryname, query_length);
    put_be16(dns_answer, htons(query_type));
    put_be16(dns_answer, htons(DNS_CLASS_IN));
    put_be32(dns_answer, htonl(DNS_DEFAULT_RR_TTL));
}

/* Populates dns_answer struct with a TYPE A answer. */
static void
dns_build_a_answer(
    struct ofpbuf *dns_answer, const uint8_t *in_queryname,
    uint16_t query_length, const ovs_be32 addr)
{
    dns_build_base_answer(dns_answer, in_queryname, query_length,
                          DNS_QUERY_TYPE_A);
    put_be16(dns_answer, htons(sizeof(ovs_be32)));
    put_be32(dns_answer, addr);
}

/* Populates dns_answer struct with a TYPE AAAA answer. */
static void
dns_build_aaaa_answer(
    struct ofpbuf *dns_answer, const uint8_t *in_queryname,
    uint16_t query_length, const struct in6_addr *addr)
{
    dns_build_base_answer(dns_answer, in_queryname, query_length,
                          DNS_QUERY_TYPE_AAAA);
    put_be16(dns_answer, htons(sizeof(*addr)));
    ofpbuf_put(dns_answer, addr, sizeof(*addr));
}

/* Populates dns_answer struct with a TYPE PTR answer. */
static void
dns_build_ptr_answer(
    struct ofpbuf *dns_answer, const uint8_t *in_queryname,
    uint16_t query_length, const char *answer_data)
{
    dns_build_base_answer(dns_answer, in_queryname, query_length,
                          DNS_QUERY_TYPE_PTR);

    size_t encoded_len = 0;
    char *encoded = encode_fqdn_string(answer_data, &encoded_len);

    put_be16(dns_answer, htons(encoded_len));
    ofpbuf_put(dns_answer, encoded, encoded_len);

    free(encoded);
}

#define DNS_RCODE_SERVER_REFUSE 0x5

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_dns_lookup(
    struct rconn *swconn,
    struct dp_packet *pkt_in, struct ofputil_packet_in *pin,
    struct ofpbuf *userdata, struct ofpbuf *continuation)
    OVS_REQUIRES(pinctrl_mutex)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out_ptr = NULL;
    uint32_t success = 0;
    bool send_refuse = false;

    /* Parse result field. */
    const struct mf_field *f;
    enum ofperr ofperr = nx_pull_header(userdata, NULL, &f, NULL);
    if (ofperr) {
       VLOG_WARN_RL(&rl, "bad result OXM (%s)", ofperr_to_string(ofperr));
       goto exit;
    }

    /* Parse result offset. */
    ovs_be32 *ofsp = ofpbuf_try_pull(userdata, sizeof *ofsp);
    if (!ofsp) {
        VLOG_WARN_RL(&rl, "offset not present in the userdata");
        goto exit;
    }

    /* Check that the result is valid and writable. */
    struct mf_subfield dst = { .field = f, .ofs = ntohl(*ofsp), .n_bits = 1 };
    ofperr = mf_check_dst(&dst, NULL);
    if (ofperr) {
        VLOG_WARN_RL(&rl, "bad result bit (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    /* Check that the packet stores at least the minimal headers. */
    if (dp_packet_l4_size(pkt_in) < (UDP_HEADER_LEN + DNS_HEADER_LEN)) {
        VLOG_WARN_RL(&rl, "truncated dns packet");
        goto exit;
    }

    /* Extract the DNS header */
    struct dns_header const *in_dns_header = dp_packet_get_udp_payload(pkt_in);
    if (!in_dns_header) {
        VLOG_WARN_RL(&rl, "truncated dns packet");
        goto exit;
    }

    /* Check if it is DNS request or not */
    if (in_dns_header->lo_flag & 0x80) {
        /* It's a DNS response packet which we are not interested in */
        goto exit;
    }

    /* Check if at least one query request is present */
    if (!in_dns_header->qdcount) {
        goto exit;
    }

    /* Check if there is an additional record present, which is unsupported */
    if (in_dns_header->arcount) {
        VLOG_DBG_RL(&rl, "Received DNS query with additional records, which"
                    " is unsupported");
        goto exit;
    }

    struct udp_header *in_udp = dp_packet_l4(pkt_in);
    size_t udp_len = ntohs(in_udp->udp_len);
    size_t l4_len = dp_packet_l4_size(pkt_in);
    uint8_t *end = (uint8_t *)in_udp + MIN(udp_len, l4_len);
    uint8_t *in_dns_data = (uint8_t *)(in_dns_header + 1);
    uint8_t *in_queryname = in_dns_data;
    uint16_t idx = 0;
    struct ds query_name;
    ds_init(&query_name);
    /* Extract the query_name. If the query name is - 'www.ovn.org' it would be
     * encoded as (in hex) - 03 77 77 77 03 6f 76 63 03 6f 72 67 00.
     */
    while ((in_dns_data + idx) < end && in_dns_data[idx]) {
        uint8_t label_len = in_dns_data[idx++];
        if (in_dns_data + idx + label_len > end) {
            ds_destroy(&query_name);
            goto exit;
        }
        ds_put_buffer(&query_name, (const char *) in_dns_data + idx, label_len);
        idx += label_len;
        ds_put_char(&query_name, '.');
    }

    idx++;
    ds_chomp(&query_name, '.');
    in_dns_data += idx;

    /* Query should have TYPE and CLASS fields */
    if (in_dns_data + (2 * sizeof(ovs_be16)) > end) {
        ds_destroy(&query_name);
        goto exit;
    }

    uint16_t query_type = ntohs(get_unaligned_be16((void *) in_dns_data));
    /* Supported query types - A, AAAA, ANY and PTR */
    if (!(query_type == DNS_QUERY_TYPE_A || query_type == DNS_QUERY_TYPE_AAAA
          || query_type == DNS_QUERY_TYPE_ANY
          || query_type == DNS_QUERY_TYPE_PTR)) {
        ds_destroy(&query_name);
        goto exit;
    }

    uint64_t dp_key = ntohll(pin->flow_metadata.flow.metadata);
    const char *answer_data = NULL;
    bool ovn_owned = false;
    struct shash_node *iter;
    SHASH_FOR_EACH (iter, &dns_cache) {
        struct dns_data *d = iter->data;
        ovn_owned = smap_get_bool(&d->options, "ovn-owned", false);
        for (size_t i = 0; i < d->n_dps; i++) {
            if (d->dps[i] == dp_key) {
                /* DNS records in SBDB are stored in lowercase. Convert to
                 * lowercase to perform case insensitive lookup
                 */
                char *query_name_lower = str_tolower(ds_cstr(&query_name));
                answer_data = smap_get(&d->records, query_name_lower);
                free(query_name_lower);
                if (answer_data) {
                    break;
                }
            }
        }

        if (answer_data) {
            break;
        }
    }

    ds_destroy(&query_name);
    if (!answer_data) {
        goto exit;
    }


    uint16_t ancount = 0;
    uint64_t dns_ans_stub[128 / 8];
    struct ofpbuf dns_answer = OFPBUF_STUB_INITIALIZER(dns_ans_stub);

    if (query_type == DNS_QUERY_TYPE_PTR) {
        dns_build_ptr_answer(&dns_answer, in_queryname, idx, answer_data);
        ancount++;
    } else {
        struct lport_addresses ip_addrs;
        if (!extract_ip_addresses(answer_data, &ip_addrs)) {
            goto exit;
        }

        if (query_type == DNS_QUERY_TYPE_A ||
            query_type == DNS_QUERY_TYPE_ANY) {
            for (size_t i = 0; i < ip_addrs.n_ipv4_addrs; i++) {
                dns_build_a_answer(&dns_answer, in_queryname, idx,
                                   ip_addrs.ipv4_addrs[i].addr);
                ancount++;
            }
        }

        if (query_type == DNS_QUERY_TYPE_AAAA ||
            query_type == DNS_QUERY_TYPE_ANY) {
            for (size_t i = 0; i < ip_addrs.n_ipv6_addrs; i++) {
                dns_build_aaaa_answer(&dns_answer, in_queryname, idx,
                                      &ip_addrs.ipv6_addrs[i].addr);
                ancount++;
            }
        }

        /* DNS is configured with a record for this domain with
         * an IPv4/IPV6 only, so instead of ignoring this A/AAAA query,
         * we can reply with  RCODE = 5 (server refuses) and that
         * will speed up the DNS process by not letting the customer
         * wait for a timeout.
         */
        if (ovn_owned && (query_type == DNS_QUERY_TYPE_AAAA ||
            query_type == DNS_QUERY_TYPE_A) && !ancount) {
            send_refuse = true;
        }

        destroy_lport_addresses(&ip_addrs);
    }

    if (!ancount && !send_refuse) {
        ofpbuf_uninit(&dns_answer);
        goto exit;
    }

    uint16_t new_l4_size = ntohs(in_udp->udp_len) +  dns_answer.size;
    size_t new_packet_size = pkt_in->l4_ofs + new_l4_size;
    struct dp_packet pkt_out;
    dp_packet_init(&pkt_out, new_packet_size);
    dp_packet_clear(&pkt_out);
    dp_packet_prealloc_tailroom(&pkt_out, new_packet_size);
    pkt_out_ptr = &pkt_out;

    /* Copy the L2 and L3 headers from the pkt_in as they would remain same.*/
    dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, pkt_in->l4_ofs), pkt_in->l4_ofs);

    pkt_out.l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out.l2_pad_size = pkt_in->l2_pad_size;
    pkt_out.l3_ofs = pkt_in->l3_ofs;
    pkt_out.l4_ofs = pkt_in->l4_ofs;

    struct udp_header *out_udp = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, UDP_HEADER_LEN), UDP_HEADER_LEN);

    /* Copy the DNS header. */
    struct dns_header *out_dns_header = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, sizeof *out_dns_header),
        sizeof *out_dns_header);

    /* Set the response bit to 1 in the flags. */
    out_dns_header->lo_flag |= 0x80;

    /* Set the answer RRs. */
    out_dns_header->ancount = htons(ancount);
    if (send_refuse) {
        /* set RCODE = 5 (server refuses). */
        out_dns_header->hi_flag |= DNS_RCODE_SERVER_REFUSE;
    }
    out_dns_header->arcount = 0;

    /* Copy the Query section. */
    dp_packet_put(&pkt_out, dp_packet_data(pkt_in), dp_packet_size(pkt_in));

    /* Copy the answer sections. */
    dp_packet_put(&pkt_out, dns_answer.data, dns_answer.size);
    ofpbuf_uninit(&dns_answer);

    out_udp->udp_len = htons(new_l4_size);
    out_udp->udp_csum = 0;

    struct eth_header *eth = dp_packet_data(&pkt_out);
    if (eth->eth_type == htons(ETH_TYPE_IP)) {
        struct ip_header *out_ip = dp_packet_l3(&pkt_out);
        out_ip->ip_tot_len = htons(pkt_out.l4_ofs - pkt_out.l3_ofs
                                   + new_l4_size);
        /* Checksum needs to be initialized to zero. */
        out_ip->ip_csum = 0;
        out_ip->ip_csum = csum(out_ip, sizeof *out_ip);
    } else {
        struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(&pkt_out);
        nh->ip6_plen = htons(new_l4_size);

        /* IPv6 needs UDP checksum calculated */
        uint32_t csum;
        csum = packet_csum_pseudoheader6(nh);
        csum = csum_continue(csum, out_udp, dp_packet_size(&pkt_out) -
                             ((const unsigned char *)out_udp -
                             (const unsigned char *)eth));
        out_udp->udp_csum = csum_finish(csum);
        if (!out_udp->udp_csum) {
            out_udp->udp_csum = htons(0xffff);
        }
    }

    pin->packet = dp_packet_data(&pkt_out);
    pin->packet_len = dp_packet_size(&pkt_out);

    success = 1;
exit:
    if (!ofperr) {
        union mf_subvalue sv;
        sv.u8_val = success;
        mf_write_subfield(&dst, &sv, &pin->flow_metadata);
    }
    queue_msg(swconn, ofputil_encode_resume(pin, continuation, proto));
    dp_packet_uninit(pkt_out_ptr);
}

/* Called with in the pinctrl_handler thread context. */
static void
process_packet_in(struct rconn *swconn, const struct ofp_header *msg)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    struct ofputil_packet_in pin;
    struct ofpbuf continuation;
    enum ofperr error = ofputil_decode_packet_in(msg, true, NULL, NULL, &pin,
                                                 NULL, NULL, &continuation);

    if (error) {
        VLOG_WARN_RL(&rl, "error decoding packet-in: %s",
                     ofperr_to_string(error));
        return;
    }
    if (pin.reason != OFPR_ACTION) {
        return;
    }

    struct ofpbuf userdata = ofpbuf_const_initializer(pin.userdata,
                                                      pin.userdata_len);
    const struct action_header *ah = ofpbuf_pull(&userdata, sizeof *ah);
    if (!ah) {
        VLOG_WARN_RL(&rl, "packet-in userdata lacks action header");
        return;
    }

    struct dp_packet packet;
    dp_packet_use_const(&packet, pin.packet, pin.packet_len);
    struct flow headers;
    flow_extract(&packet, &headers);

    switch (ntohl(ah->opcode)) {
    case ACTION_OPCODE_ARP:
        pinctrl_handle_arp(swconn, &headers, &packet, &pin.flow_metadata,
                           &userdata);
        break;
    case ACTION_OPCODE_IGMP:
        pinctrl_ip_mcast_handle(swconn, &headers, &packet, &pin.flow_metadata,
                                &userdata);
        break;

    case ACTION_OPCODE_PUT_ARP:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_put_mac_binding(&pin.flow_metadata.flow, &headers,
                                       true);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    case ACTION_OPCODE_PUT_DHCP_OPTS:
        pinctrl_handle_put_dhcp_opts(swconn, &packet, &pin, &headers,
                                     &userdata, &continuation);
        break;

    case ACTION_OPCODE_ND_NA:
        pinctrl_handle_nd_na(swconn, &headers, &pin.flow_metadata, &userdata,
                             false);
        break;

    case ACTION_OPCODE_ND_NA_ROUTER:
        pinctrl_handle_nd_na(swconn, &headers, &pin.flow_metadata, &userdata,
                             true);
        break;

    case ACTION_OPCODE_PUT_ND:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_put_mac_binding(&pin.flow_metadata.flow, &headers,
                                       false);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    case ACTION_OPCODE_PUT_FDB:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_put_fdb(&pin.flow_metadata.flow, &headers);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    case ACTION_OPCODE_PUT_DHCPV6_OPTS:
        pinctrl_handle_put_dhcpv6_opts(swconn, &packet, &pin, &userdata,
                                       &continuation);
        break;

    case ACTION_OPCODE_DNS_LOOKUP:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_dns_lookup(swconn, &packet, &pin, &userdata,
                                  &continuation);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    case ACTION_OPCODE_LOG:
        handle_acl_log(&headers, &userdata,
                       pin.table_id < OFTABLE_LOG_EGRESS_PIPELINE
                       ? "from-lport" : "to-lport");
        break;

    case ACTION_OPCODE_PUT_ND_RA_OPTS:
        pinctrl_handle_put_nd_ra_opts(swconn, &headers, &packet, &pin,
                                      &userdata, &continuation);
        break;

    case ACTION_OPCODE_ND_NS:
        pinctrl_handle_nd_ns(swconn, &headers, &packet, &pin.flow_metadata,
                             &userdata);
        break;

    case ACTION_OPCODE_ICMP:
        pinctrl_handle_icmp(swconn, &headers, &packet, &pin.flow_metadata,
                            &userdata, true, false);
        break;

    case ACTION_OPCODE_ICMP4_ERROR:
    case ACTION_OPCODE_ICMP6_ERROR:
        pinctrl_handle_icmp(swconn, &headers, &packet, &pin.flow_metadata,
                            &userdata, false, false);
        break;

    case ACTION_OPCODE_TCP_RESET:
        pinctrl_handle_tcp_reset(swconn, &headers, &packet, &pin.flow_metadata,
                                 &userdata, false);
        break;

    case ACTION_OPCODE_SCTP_ABORT:
        pinctrl_handle_sctp_abort(swconn, &headers, &packet,
                                  &pin.flow_metadata, &userdata, false);
        break;

    case ACTION_OPCODE_REJECT:
        pinctrl_handle_reject(swconn, &headers, &packet, &pin.flow_metadata,
                              &userdata);
        break;

    case ACTION_OPCODE_PUT_ICMP4_FRAG_MTU:
    case ACTION_OPCODE_PUT_ICMP6_FRAG_MTU:
        pinctrl_handle_put_icmp_frag_mtu(swconn, &headers, &packet, &pin,
                                         &userdata, &continuation);
        break;

    case ACTION_OPCODE_EVENT:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_event(&userdata);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    case ACTION_OPCODE_BIND_VPORT:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_bind_vport(&pin.flow_metadata.flow, &userdata);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;
    case ACTION_OPCODE_DHCP6_SERVER:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_dhcp6_server(swconn, &headers, &packet,
                                    &pin.flow_metadata);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    case ACTION_OPCODE_HANDLE_SVC_CHECK:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_svc_check(swconn, &headers, &packet,
                                 &pin.flow_metadata);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    case ACTION_OPCODE_BFD_MSG:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_handle_bfd_msg(swconn, &headers, &packet);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    case ACTION_OPCODE_ACTIVATION_STRATEGY_RARP:
        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_rarp_activation_strategy_handler(&pin.flow_metadata);
        ovs_mutex_unlock(&pinctrl_mutex);
        break;

    case ACTION_OPCODE_MG_SPLIT_BUF:
        pinctrl_mg_split_buff_handler(swconn, &packet, &pin.flow_metadata,
                                      &userdata);
        break;

    default:
        VLOG_WARN_RL(&rl, "unrecognized packet-in opcode %"PRIu32,
                     ntohl(ah->opcode));
        break;
    }


    if (VLOG_IS_DBG_ENABLED()) {
        struct ds pin_str = DS_EMPTY_INITIALIZER;
        char * opc_str = ovnact_op_to_string(ntohl(ah->opcode));

        ds_put_format(&pin_str, "pinctrl received  packet-in | opcode=%s",
                      opc_str);

        ds_put_format(&pin_str, "| OF_Table_ID=%u", pin.table_id);
        ds_put_format(&pin_str, "| OF_Cookie_ID=0x%"PRIx64,
                      ntohll(pin.cookie));

        if (pin.flow_metadata.flow.in_port.ofp_port) {
            ds_put_format(&pin_str, "| in-port=%u",
                          pin.flow_metadata.flow.in_port.ofp_port);
        }

        ds_put_format(&pin_str, "| src-mac="ETH_ADDR_FMT",",
                      ETH_ADDR_ARGS(headers.dl_src));
        ds_put_format(&pin_str, " dst-mac="ETH_ADDR_FMT,
                      ETH_ADDR_ARGS(headers.dl_dst));
        if (headers.dl_type != htons(ETH_TYPE_IPV6)) {
            ds_put_format(&pin_str, "| src-ip="IP_FMT",",
                          IP_ARGS(headers.nw_src));
            ds_put_format(&pin_str, " dst-ip="IP_FMT,
                          IP_ARGS(headers.nw_dst));
        }

        VLOG_DBG("%s \n", ds_cstr(&pin_str));
        ds_destroy(&pin_str);
        free(opc_str);
    }
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_recv(struct rconn *swconn, const struct ofp_header *oh,
             enum ofptype type)
{
    if (type == OFPTYPE_ECHO_REQUEST) {
        queue_msg(swconn, ofputil_encode_echo_reply(oh));
    } else if (type == OFPTYPE_GET_CONFIG_REPLY) {
        /* Enable asynchronous messages */
        struct ofputil_switch_config config;

        ofputil_decode_get_config_reply(oh, &config);
        config.miss_send_len = UINT16_MAX;
        set_switch_config(swconn, &config);
    } else if (type == OFPTYPE_PACKET_IN) {
        COVERAGE_INC(pinctrl_total_pin_pkts);
        process_packet_in(swconn, oh);
    } else {
        if (VLOG_IS_DBG_ENABLED()) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

            char *s = ofp_to_string(oh, ntohs(oh->length), NULL, NULL, 2);

            VLOG_DBG_RL(&rl, "OpenFlow packet ignored: %s", s);
            free(s);
        }
    }
}

/* Called with in the main ovn-controller thread context. */
static void
notify_pinctrl_handler(void)
{
    seq_change(pinctrl_handler_seq);
}

/* Called with in the pinctrl_handler thread context. */
static void
notify_pinctrl_main(void)
{
    COVERAGE_INC(pinctrl_notify_main_thread);
    seq_change(pinctrl_main_seq);
}

static void
pinctrl_rconn_setup(struct rconn *swconn, const char *br_int_name)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (br_int_name) {
        char *target = xasprintf("unix:%s/%s.mgmt", ovs_rundir(), br_int_name);

        if (strcmp(target, rconn_get_target(swconn))) {
            VLOG_INFO("%s: connecting to switch", target);
            rconn_connect(swconn, target, target);
        }
        free(target);
    } else {
        rconn_disconnect(swconn);
    }
}

/* pinctrl_handler pthread function. */
static void *
pinctrl_handler(void *arg_)
{
    struct pinctrl *pctrl = arg_;
    /* OpenFlow connection to the switch. */
    struct rconn *swconn;
    /* Last seen sequence number for 'swconn'.  When this differs from
     * rconn_get_connection_seqno(rconn), 'swconn' has reconnected. */
    unsigned int conn_seq_no = 0;

    uint64_t new_seq;

    /* Next IPV6 RA in seconds. */
    static long long int send_ipv6_ra_time = LLONG_MAX;
    /* Next GARP/RARP announcement in ms. */
    static long long int send_garp_rarp_time = LLONG_MAX;
    /* Next multicast query (IGMP) in ms. */
    static long long int send_mcast_query_time = LLONG_MAX;
    static long long int svc_monitors_next_run_time = LLONG_MAX;
    static long long int send_prefixd_time = LLONG_MAX;

    swconn = rconn_create(0, 0, DSCP_DEFAULT, 1 << OFP15_VERSION);

    while (!latch_is_set(&pctrl->pinctrl_thread_exit)) {
        long long int bfd_time = LLONG_MAX;

        ovs_mutex_lock(&pinctrl_mutex);
        pinctrl_rconn_setup(swconn, pctrl->br_int_name);
        ip_mcast_snoop_run();
        ovs_mutex_unlock(&pinctrl_mutex);

        rconn_run(swconn);
        new_seq = seq_read(pinctrl_handler_seq);
        if (rconn_is_connected(swconn)) {
            if (conn_seq_no != rconn_get_connection_seqno(swconn)) {
                pinctrl_setup(swconn);
                conn_seq_no = rconn_get_connection_seqno(swconn);
            }

            for (int i = 0; i < 50; i++) {
                struct ofpbuf *msg = rconn_recv(swconn);
                if (!msg) {
                    break;
                }

                const struct ofp_header *oh = msg->data;
                enum ofptype type;

                ofptype_decode(&type, oh);
                pinctrl_recv(swconn, oh, type);
                ofpbuf_delete(msg);
            }

            if (may_inject_pkts()) {
                ovs_mutex_lock(&pinctrl_mutex);
                send_garp_rarp_run(swconn, &send_garp_rarp_time);
                send_ipv6_ras(swconn, &send_ipv6_ra_time);
                send_ipv6_prefixd(swconn, &send_prefixd_time);
                send_mac_binding_buffered_pkts(swconn);
                bfd_monitor_send_msg(swconn, &bfd_time);
                ovs_mutex_unlock(&pinctrl_mutex);

                ip_mcast_querier_run(swconn, &send_mcast_query_time);
            }

            ovs_mutex_lock(&pinctrl_mutex);
            svc_monitors_run(swconn, &svc_monitors_next_run_time);
            ovs_mutex_unlock(&pinctrl_mutex);
        }

        rconn_run_wait(swconn);
        rconn_recv_wait(swconn);
        send_garp_rarp_wait(send_garp_rarp_time);
        ipv6_ra_wait(send_ipv6_ra_time);
        ip_mcast_querier_wait(send_mcast_query_time);
        svc_monitors_wait(svc_monitors_next_run_time);
        ipv6_prefixd_wait(send_prefixd_time);
        bfd_monitor_wait(bfd_time);

        seq_wait(pinctrl_handler_seq, new_seq);

        latch_wait(&pctrl->pinctrl_thread_exit);
        poll_block();
    }

    rconn_destroy(swconn);
    return NULL;
}

static void
pinctrl_set_br_int_name_(const char *br_int_name)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (br_int_name && (!pinctrl.br_int_name || strcmp(pinctrl.br_int_name,
                                                       br_int_name))) {
        free(pinctrl.br_int_name);
        pinctrl.br_int_name = xstrdup(br_int_name);
        /* Notify pinctrl_handler that integration bridge is
         * set/changed. */
        notify_pinctrl_handler();
    }
}

void
pinctrl_set_br_int_name(const char *br_int_name)
{
    ovs_mutex_lock(&pinctrl_mutex);
    pinctrl_set_br_int_name_(br_int_name);
    ovs_mutex_unlock(&pinctrl_mutex);
}

void
pinctrl_update(const struct ovsdb_idl *idl, const char *br_int_name)
{
    ovs_mutex_lock(&pinctrl_mutex);
    pinctrl_set_br_int_name_(br_int_name);

    bool can_mb_timestamp =
            sbrec_server_has_mac_binding_table_col_timestamp(idl);
    if (can_mb_timestamp != pinctrl.mac_binding_can_timestamp) {
        pinctrl.mac_binding_can_timestamp = can_mb_timestamp;

        /* Notify pinctrl_handler that mac binding timestamp column
         * availability has changed. */
        notify_pinctrl_handler();
    }

    bool can_fdb_timestamp = sbrec_server_has_fdb_table_col_timestamp(idl);
    if (can_fdb_timestamp != pinctrl.fdb_can_timestamp) {
        pinctrl.fdb_can_timestamp = can_fdb_timestamp;

        /* Notify pinctrl_handler that fdb timestamp column
       * availability has changed. */
        notify_pinctrl_handler();
    }

    bool dns_supports_ovn_owned = sbrec_server_has_dns_table_col_options(idl);
    if (dns_supports_ovn_owned != pinctrl.dns_supports_ovn_owned) {
        pinctrl.dns_supports_ovn_owned = dns_supports_ovn_owned;

        /* Notify pinctrl_handler that fdb timestamp column
       * availability has changed. */
        notify_pinctrl_handler();
    }

    ovs_mutex_unlock(&pinctrl_mutex);
}

/* Called by ovn-controller. */
void
pinctrl_run(struct ovsdb_idl_txn *ovnsb_idl_txn,
            struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
            struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
            struct ovsdb_idl_index *sbrec_port_binding_by_key,
            struct ovsdb_idl_index *sbrec_port_binding_by_name,
            struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
            struct ovsdb_idl_index *sbrec_igmp_groups,
            struct ovsdb_idl_index *sbrec_ip_multicast_opts,
            struct ovsdb_idl_index *sbrec_fdb_by_dp_key_mac,
            const struct sbrec_dns_table *dns_table,
            const struct sbrec_controller_event_table *ce_table,
            const struct sbrec_service_monitor_table *svc_mon_table,
            const struct sbrec_mac_binding_table *mac_binding_table,
            const struct sbrec_bfd_table *bfd_table,
            const struct ovsrec_bridge *br_int,
            const struct sbrec_chassis *chassis,
            const struct hmap *local_datapaths,
            const struct sset *active_tunnels,
            const struct shash *local_active_ports_ipv6_pd,
            const struct shash *local_active_ports_ras,
            const struct ovsrec_open_vswitch_table *ovs_table)
{
    ovs_mutex_lock(&pinctrl_mutex);
    run_put_mac_bindings(ovnsb_idl_txn, sbrec_datapath_binding_by_key,
                         sbrec_port_binding_by_key,
                         sbrec_mac_binding_by_lport_ip);
    run_put_vport_bindings(ovnsb_idl_txn, sbrec_datapath_binding_by_key,
                           sbrec_port_binding_by_key, chassis);
    send_garp_rarp_prepare(ovnsb_idl_txn, sbrec_port_binding_by_datapath,
                           sbrec_port_binding_by_name,
                           sbrec_mac_binding_by_lport_ip, br_int, chassis,
                           local_datapaths, active_tunnels, ovs_table);
    prepare_ipv6_ras(local_active_ports_ras, sbrec_port_binding_by_name);
    prepare_ipv6_prefixd(ovnsb_idl_txn, sbrec_port_binding_by_name,
                         local_active_ports_ipv6_pd, chassis,
                         active_tunnels, local_datapaths);
    sync_dns_cache(dns_table);
    controller_event_run(ovnsb_idl_txn, ce_table, chassis);
    ip_mcast_sync(ovnsb_idl_txn, chassis, local_datapaths,
                  sbrec_datapath_binding_by_key,
                  sbrec_port_binding_by_key,
                  sbrec_igmp_groups,
                  sbrec_ip_multicast_opts);
    run_buffered_binding(mac_binding_table, sbrec_port_binding_by_key,
                         sbrec_datapath_binding_by_key,
                         sbrec_port_binding_by_name,
                         sbrec_mac_binding_by_lport_ip);
    sync_svc_monitors(ovnsb_idl_txn, svc_mon_table, sbrec_port_binding_by_name,
                      chassis);
    bfd_monitor_run(ovnsb_idl_txn, bfd_table, sbrec_port_binding_by_name,
                    chassis, active_tunnels);
    run_put_fdbs(ovnsb_idl_txn, sbrec_port_binding_by_key,
                 sbrec_datapath_binding_by_key, sbrec_fdb_by_dp_key_mac);
    run_activated_ports(ovnsb_idl_txn, sbrec_datapath_binding_by_key,
                        sbrec_port_binding_by_key, chassis);
    ovs_mutex_unlock(&pinctrl_mutex);
}

/* Table of ipv6_ra_state structures, keyed on logical port name.
 * Protected by pinctrl_mutex. */
static struct shash ipv6_ras;

struct ipv6_ra_config {
    time_t min_interval;
    time_t max_interval;
    struct eth_addr eth_src;
    struct eth_addr eth_dst;
    struct in6_addr ipv6_src;
    struct in6_addr ipv6_dst;
    int32_t mtu;
    uint8_t mo_flags; /* Managed/Other flags for RAs */
    uint8_t la_flags; /* On-link/autonomous flags for address prefixes */
    struct lport_addresses prefixes;
    struct in6_addr rdnss;
    bool has_rdnss;
    struct ds dnssl;
    struct ds route_info;
};

struct ipv6_ra_state {
    long long int next_announce;
    struct ipv6_ra_config *config;
    int64_t port_key;
    int64_t metadata;
    bool delete_me;
};

static void
init_ipv6_ras(void)
{
    shash_init(&ipv6_ras);
}

static void
ipv6_ra_config_delete(struct ipv6_ra_config *config)
{
    if (config) {
        destroy_lport_addresses(&config->prefixes);
        ds_destroy(&config->dnssl);
        ds_destroy(&config->route_info);
        free(config);
    }
}

static void
ipv6_ra_delete(struct ipv6_ra_state *ra)
{
    if (ra) {
        ipv6_ra_config_delete(ra->config);
        free(ra);
    }
}

static void
destroy_ipv6_ras(void)
{
    struct shash_node *iter;
    SHASH_FOR_EACH_SAFE (iter, &ipv6_ras) {
        struct ipv6_ra_state *ra = iter->data;
        ipv6_ra_delete(ra);
        shash_delete(&ipv6_ras, iter);
    }
    shash_destroy(&ipv6_ras);
}

static struct ipv6_ra_config *
ipv6_ra_update_config(const struct sbrec_port_binding *pb)
{
    struct ipv6_ra_config *config;

    config = xzalloc(sizeof *config);

    config->max_interval = smap_get_int(&pb->options, "ipv6_ra_max_interval",
            ND_RA_MAX_INTERVAL_DEFAULT);
    config->min_interval = smap_get_int(&pb->options, "ipv6_ra_min_interval",
            nd_ra_min_interval_default(config->max_interval));
    config->mtu = smap_get_int(&pb->options, "ipv6_ra_mtu", ND_MTU_DEFAULT);
    config->la_flags = IPV6_ND_RA_OPT_PREFIX_ON_LINK;
    ds_init(&config->dnssl);
    ds_init(&config->route_info);

    const char *address_mode = smap_get(&pb->options, "ipv6_ra_address_mode");
    if (!address_mode) {
        VLOG_WARN("No address mode specified");
        goto fail;
    }
    if (!strcmp(address_mode, "dhcpv6_stateless")) {
        config->mo_flags |= IPV6_ND_RA_FLAG_OTHER_ADDR_CONFIG;
        config->la_flags |= IPV6_ND_RA_OPT_PREFIX_AUTONOMOUS;
    } else if (!strcmp(address_mode, "dhcpv6_stateful")) {
        config->mo_flags |= IPV6_ND_RA_FLAG_MANAGED_ADDR_CONFIG;
    } else if (!strcmp(address_mode, "slaac")) {
        config->la_flags |= IPV6_ND_RA_OPT_PREFIX_AUTONOMOUS;
    } else {
        VLOG_WARN("Invalid address mode %s", address_mode);
        goto fail;
    }

    const char *prf = smap_get(&pb->options, "ipv6_ra_prf");
    if (!strcmp(prf, "HIGH")) {
        config->mo_flags |= IPV6_ND_RA_OPT_PRF_HIGH;
    } else if (!strcmp(prf, "LOW")) {
        config->mo_flags |= IPV6_ND_RA_OPT_PRF_LOW;
    }

    const char *prefixes = smap_get(&pb->options, "ipv6_ra_prefixes");
    if (prefixes && !extract_ip_addresses(prefixes, &config->prefixes)) {
        VLOG_WARN("Invalid IPv6 prefixes: %s", prefixes);
        goto fail;
    }

    /* All nodes multicast addresses */
    config->eth_dst = (struct eth_addr) ETH_ADDR_C(33,33,00,00,00,01);
    ipv6_parse("ff02::1", &config->ipv6_dst);

    const char *eth_addr = smap_get(&pb->options, "ipv6_ra_src_eth");
    if (!eth_addr || !eth_addr_from_string(eth_addr, &config->eth_src)) {
        VLOG_WARN("Invalid ethernet source %s", eth_addr);
        goto fail;
    }
    const char *ip_addr = smap_get(&pb->options, "ipv6_ra_src_addr");
    if (!ip_addr || !ipv6_parse(ip_addr, &config->ipv6_src)) {
        VLOG_WARN("Invalid IP source %s", ip_addr);
        goto fail;
    }
    const char *rdnss = smap_get(&pb->options, "ipv6_ra_rdnss");
    if (rdnss && !ipv6_parse(rdnss, &config->rdnss)) {
        VLOG_WARN("Invalid RDNSS source %s", rdnss);
        goto fail;
    }
    config->has_rdnss = !!rdnss;

    const char *dnssl = smap_get(&pb->options, "ipv6_ra_dnssl");
    if (dnssl) {
        ds_put_cstr(&config->dnssl, dnssl);
    }

    const char *route_info = smap_get(&pb->options, "ipv6_ra_route_info");
    if (route_info) {
        ds_put_cstr(&config->route_info, route_info);
    }

    return config;

fail:
    ipv6_ra_config_delete(config);
    return NULL;
}

static long long int
ipv6_ra_calc_next_announce(time_t min_interval, time_t max_interval)
{
    long long int min_interval_ms = min_interval * 1000LL;
    long long int max_interval_ms = max_interval * 1000LL;

    return time_msec() + min_interval_ms +
        random_range(max_interval_ms - min_interval_ms);
}

static void
put_load(uint64_t value, enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts,
                                                       mf_from_id(dst), NULL,
                                                       NULL);
    ovs_be64 n_value = htonll(value);
    bitwise_copy(&n_value, 8, 0, sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(ofpact_set_field_mask(sf), sf->field->n_bytes, ofs, n_bits);
}

static void
packet_put_ra_rdnss_opt(struct dp_packet *b, uint8_t num,
                        ovs_be32 lifetime, const struct in6_addr *dns)
{
    size_t prev_l4_size = dp_packet_l4_size(b);
    struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(b);
    size_t len = 2 * num + 1;

    nh->ip6_plen = htons(prev_l4_size + len * 8);

    struct nd_rdnss_opt *nd_rdnss = dp_packet_put_uninit(b, sizeof *nd_rdnss);
    nd_rdnss->type = ND_OPT_RDNSS;
    nd_rdnss->len = len;
    nd_rdnss->reserved = 0;
    put_16aligned_be32(&nd_rdnss->lifetime, lifetime);

    for (int i = 0; i < num; i++) {
        dp_packet_put(b, &dns[i], sizeof(ovs_be32[4]));
    }

    struct ovs_ra_msg *ra = dp_packet_l4(b);
    ra->icmph.icmp6_cksum = 0;
    uint32_t icmp_csum = packet_csum_pseudoheader6(dp_packet_l3(b));
    ra->icmph.icmp6_cksum = csum_finish(csum_continue(icmp_csum, ra,
                                                      prev_l4_size + len * 8));
}

static void
packet_put_ra_dnssl_opt(struct dp_packet *b, ovs_be32 lifetime,
                        char *dnssl_data)
{
    size_t prev_l4_size = dp_packet_l4_size(b);
    char dnssl[255] = {0};
    int size;

    size = encode_ra_dnssl_opt(dnssl_data, dnssl, sizeof(dnssl));
    if (size < 0) {
        return;
    }

    struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(b);
    nh->ip6_plen = htons(prev_l4_size + size);

    struct ovs_nd_dnssl *nd_dnssl = dp_packet_put_uninit(b, sizeof *nd_dnssl);
    nd_dnssl->type = ND_OPT_DNSSL;
    nd_dnssl->len = size / 8;
    nd_dnssl->reserved = 0;
    put_16aligned_be32(&nd_dnssl->lifetime, lifetime);

    dp_packet_put(b, dnssl, size - sizeof *nd_dnssl);

    struct ovs_ra_msg *ra = dp_packet_l4(b);
    ra->icmph.icmp6_cksum = 0;
    uint32_t icmp_csum = packet_csum_pseudoheader6(dp_packet_l3(b));
    ra->icmph.icmp6_cksum = csum_finish(csum_continue(icmp_csum, ra,
                                                      prev_l4_size + size));
}

static void
packet_put_ra_route_info_opt(struct dp_packet *b, ovs_be32 lifetime,
                             char *route_data)
{
    size_t prev_l4_size = dp_packet_l4_size(b);
    char *route_list, *t0, *r0 = NULL;
    size_t size = 0;

    route_list = xstrdup(route_data);

    for (t0 = strtok_r(route_list, ",", &r0); t0;
         t0 = strtok_r(NULL, ",", &r0)) {
        struct ovs_nd_route_info nd_rinfo;
        char *t1, *r1 = NULL;
        int index;

        for (t1 = strtok_r(t0, "-", &r1), index = 0; t1;
             t1 = strtok_r(NULL, "-", &r1), index++) {

            nd_rinfo.type = ND_OPT_ROUTE_INFO_TYPE;
            nd_rinfo.route_lifetime = lifetime;

            switch (index) {
            case 0:
                if (!strcmp(t1, "HIGH")) {
                    nd_rinfo.flags = IPV6_ND_RA_OPT_PRF_HIGH;
                } else if (!strcmp(t1, "LOW")) {
                    nd_rinfo.flags = IPV6_ND_RA_OPT_PRF_LOW;
                } else {
                    nd_rinfo.flags = IPV6_ND_RA_OPT_PRF_NORMAL;
                }
                break;
            case 1: {
                struct lport_addresses route;
                uint8_t plen;

                if (!extract_ip_addresses(t1, &route)) {
                    goto out;
                }
                if (!route.n_ipv6_addrs) {
                    destroy_lport_addresses(&route);
                    goto out;
                }

                nd_rinfo.prefix_len = route.ipv6_addrs->plen;
                plen = DIV_ROUND_UP(nd_rinfo.prefix_len, 64);
                nd_rinfo.len = 1 + plen;
                dp_packet_put(b, &nd_rinfo, sizeof(struct ovs_nd_route_info));
                dp_packet_put(b, &route.ipv6_addrs->network, plen * 8);
                size += sizeof(struct ovs_nd_route_info) + plen * 8;

                destroy_lport_addresses(&route);
                index = 0;
                break;
            }
            default:
                goto out;
            }
        }
    }

    struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(b);
    nh->ip6_plen = htons(prev_l4_size + size);
    struct ovs_ra_msg *ra = dp_packet_l4(b);
    ra->icmph.icmp6_cksum = 0;
    uint32_t icmp_csum = packet_csum_pseudoheader6(dp_packet_l3(b));
    ra->icmph.icmp6_cksum = csum_finish(csum_continue(icmp_csum, ra,
                                                      prev_l4_size + size));
out:
    free(route_list);
}

/* Called with in the pinctrl_handler thread context. */
static long long int
ipv6_ra_send(struct rconn *swconn, struct ipv6_ra_state *ra)
{
    if (time_msec() < ra->next_announce) {
        return ra->next_announce;
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    uint16_t router_lt = IPV6_ND_RA_LIFETIME;

    if (!router_lt) {
        /* Reset PRF to MEDIUM if router lifetime is not set */
        ra->config->mo_flags &= ~IPV6_ND_RA_OPT_PRF_LOW;
    }

    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    compose_nd_ra(&packet, ra->config->eth_src, ra->config->eth_dst,
            &ra->config->ipv6_src, &ra->config->ipv6_dst,
            255, ra->config->mo_flags, htons(router_lt), 0, 0,
            ra->config->mtu);

    for (int i = 0; i < ra->config->prefixes.n_ipv6_addrs; i++) {
        ovs_be128 addr;
        memcpy(&addr, &ra->config->prefixes.ipv6_addrs[i].addr, sizeof addr);
        packet_put_ra_prefix_opt(&packet,
            ra->config->prefixes.ipv6_addrs[i].plen,
            ra->config->la_flags, htonl(IPV6_ND_RA_OPT_PREFIX_VALID_LIFETIME),
            htonl(IPV6_ND_RA_OPT_PREFIX_PREFERRED_LIFETIME), addr);
    }
    if (ra->config->has_rdnss) {
        packet_put_ra_rdnss_opt(&packet, 1, htonl(0xffffffff),
                                &ra->config->rdnss);
    }
    if (ra->config->dnssl.length) {
        packet_put_ra_dnssl_opt(&packet, htonl(0xffffffff),
                                ds_cstr(&ra->config->dnssl));
    }
    if (ra->config->route_info.length) {
        packet_put_ra_route_info_opt(&packet, htonl(0xffffffff),
                                     ds_cstr(&ra->config->route_info));
    }

    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);

    /* Set MFF_LOG_DATAPATH and MFF_LOG_INPORT. */
    uint32_t dp_key = ra->metadata;
    uint32_t port_key = ra->port_key;
    put_load(dp_key, MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(port_key, MFF_LOG_INPORT, 0, 32, &ofpacts);
    put_load(1, MFF_LOG_FLAGS, MLF_LOCAL_ONLY_BIT, 1, &ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_LOG_INGRESS_PIPELINE;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };

    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);

    ra->next_announce = ipv6_ra_calc_next_announce(ra->config->min_interval,
            ra->config->max_interval);

    return ra->next_announce;
}

/* Called with in the pinctrl_handler thread context. */
static void
ipv6_ra_wait(long long int send_ipv6_ra_time)
{
    /* Set the poll timer for next IPv6 RA only if IPv6 RAs needs to
     * be sent. */
    if (!shash_is_empty(&ipv6_ras)) {
        poll_timer_wait_until(send_ipv6_ra_time);
    }
}

/* Called with in the pinctrl_handler thread context. */
static void
send_ipv6_ras(struct rconn *swconn, long long int *send_ipv6_ra_time)
    OVS_REQUIRES(pinctrl_mutex)
{
    *send_ipv6_ra_time = LLONG_MAX;
    struct shash_node *iter;
    SHASH_FOR_EACH (iter, &ipv6_ras) {
        struct ipv6_ra_state *ra = iter->data;
        long long int next_ra = ipv6_ra_send(swconn, ra);
        if (*send_ipv6_ra_time > next_ra) {
            *send_ipv6_ra_time = next_ra;
        }
    }
}

/* Called by pinctrl_run(). Runs with in the main ovn-controller
 * thread context. */
static void
prepare_ipv6_ras(const struct shash *local_active_ports_ras,
                 struct ovsdb_idl_index *sbrec_port_binding_by_name)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct shash_node *iter;

    SHASH_FOR_EACH (iter, &ipv6_ras) {
        struct ipv6_ra_state *ra = iter->data;
        ra->delete_me = true;
    }

    bool changed = false;
    SHASH_FOR_EACH (iter, local_active_ports_ras) {
        const struct sbrec_port_binding *pb = iter->data;

        const char *peer_s = smap_get(&pb->options, "peer");
        if (!peer_s) {
            continue;
        }

        const struct sbrec_port_binding *peer
            = lport_lookup_by_name(sbrec_port_binding_by_name, peer_s);
        if (!peer) {
            continue;
        }

        struct ipv6_ra_config *config = ipv6_ra_update_config(pb);
        if (!config) {
            continue;
        }

        struct ipv6_ra_state *ra
            = shash_find_data(&ipv6_ras, pb->logical_port);
        if (!ra) {
            ra = xzalloc(sizeof *ra);
            ra->config = config;
            ra->next_announce = ipv6_ra_calc_next_announce(
                ra->config->min_interval,
                ra->config->max_interval);
            shash_add(&ipv6_ras, pb->logical_port, ra);
            changed = true;
        } else {
            if (config->min_interval != ra->config->min_interval ||
                config->max_interval != ra->config->max_interval)
                ra->next_announce = ipv6_ra_calc_next_announce(
                    config->min_interval,
                    config->max_interval);
            ipv6_ra_config_delete(ra->config);
            ra->config = config;
        }

        /* Peer is the logical switch port that the logical
         * router port is connected to. The RA is injected
         * into that logical switch port.
         */
        ra->port_key = peer->tunnel_key;
        ra->metadata = peer->datapath->tunnel_key;
        ra->delete_me = false;

        /* pinctrl_handler thread will send the IPv6 RAs. */
    }

    /* Remove those that are no longer in the SB database */
    SHASH_FOR_EACH_SAFE (iter, &ipv6_ras) {
        struct ipv6_ra_state *ra = iter->data;
        if (ra->delete_me) {
            shash_delete(&ipv6_ras, iter);
            ipv6_ra_delete(ra);
        }
    }

    if (changed) {
        notify_pinctrl_handler();
    }

}

/* Called by pinctrl_run(). Runs with in the main ovn-controller
 * thread context. */
void
pinctrl_wait(struct ovsdb_idl_txn *ovnsb_idl_txn)
{
    ovs_mutex_lock(&pinctrl_mutex);
    wait_put_mac_bindings(ovnsb_idl_txn);
    wait_controller_event(ovnsb_idl_txn);
    wait_put_vport_bindings(ovnsb_idl_txn);
    int64_t new_seq = seq_read(pinctrl_main_seq);
    seq_wait(pinctrl_main_seq, new_seq);
    wait_put_fdbs(ovnsb_idl_txn);
    wait_activated_ports();
    ovs_mutex_unlock(&pinctrl_mutex);
}

/* Called by ovn-controller. */
void
pinctrl_destroy(void)
{
    latch_set(&pinctrl.pinctrl_thread_exit);
    pthread_join(pinctrl.pinctrl_thread, NULL);
    latch_destroy(&pinctrl.pinctrl_thread_exit);
    free(pinctrl.br_int_name);
    destroy_send_garps_rarps();
    destroy_ipv6_ras();
    destroy_ipv6_prefixd();
    destroy_buffered_packets_ctx();
    destroy_activated_ports();
    event_table_destroy();
    destroy_put_mac_bindings();
    destroy_put_vport_bindings();
    destroy_dns_cache();
    ip_mcast_snoop_destroy();
    destroy_svc_monitors();
    bfd_monitor_destroy();
    destroy_fdb_entries();
    seq_destroy(pinctrl_main_seq);
    seq_destroy(pinctrl_handler_seq);
}

/* Implementation of the "put_arp" and "put_nd" OVN actions.  These
 * actions send a packet to ovn-controller, using the flow as an API
 * (see actions.h for details).  This code implements the actions by
 * updating the MAC_Binding table in the southbound database.
 *
 * This code could be a lot simpler if the database could always be updated,
 * but in fact we can only update it when 'ovnsb_idl_txn' is nonnull.  Thus,
 * we buffer up a few put_mac_bindings (but we don't keep them longer
 * than 1 second) and apply them whenever a database transaction is
 * available. */

/* Buffered "put_mac_binding" operation. */

#define MAX_MAC_BINDING_DELAY_MSEC 50
#define MAX_MAC_BINDINGS           1000

/* Contains "struct mac_binding"s. */
static struct mac_bindings_map put_mac_bindings;

static void
init_put_mac_bindings(void)
{
    ovn_mac_bindings_map_init(&put_mac_bindings, MAX_MAC_BINDINGS);
}

static void
destroy_put_mac_bindings(void)
{
    ovn_mac_bindings_map_destroy(&put_mac_bindings);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_put_mac_binding(const struct flow *md,
                               const struct flow *headers,
                               bool is_arp)
    OVS_REQUIRES(pinctrl_mutex)
{
    uint32_t dp_key = ntohll(md->metadata);
    uint32_t port_key = md->regs[MFF_LOG_INPORT - MFF_REG0];
    struct in6_addr ip_key;

    if (is_arp) {
        ip_key = in6_addr_mapped_ipv4(htonl(md->regs[0]));
    } else {
        ovs_be128 ip6 = hton128(flow_get_xxreg(md, 0));
        memcpy(&ip_key, &ip6, sizeof ip_key);
    }

    /* If the ARP reply was unicast we should not delay it,
     * there won't be any race. */
    uint32_t delay = eth_addr_is_multicast(headers->dl_dst)
                     ? random_range(MAX_MAC_BINDING_DELAY_MSEC) + 1
                     : 0;
    struct mac_binding *mb = ovn_mac_binding_add(&put_mac_bindings, dp_key,
                                                 port_key, &ip_key,
                                                 headers->dl_src, delay);
    if (!mb) {
        COVERAGE_INC(pinctrl_drop_put_mac_binding);
        return;
    }

    /* We can send the buffered packet once the main ovn-controller
     * thread calls pinctrl_run() and it writes the mac_bindings stored
     * in 'put_mac_bindings' hmap into the Southbound MAC_Binding table. */
    notify_pinctrl_main();
}

/* Called with in the pinctrl_handler thread context. */
static void
send_mac_binding_buffered_pkts(struct rconn *swconn)
    OVS_REQUIRES(pinctrl_mutex)
{
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);

    struct packet_data *pd;
    LIST_FOR_EACH_POP (pd, node, &buffered_packets_ctx.ready_packets_data) {
        struct ofputil_packet_out po = {
            .packet = dp_packet_data(pd->p),
            .packet_len = dp_packet_size(pd->p),
            .buffer_id = UINT32_MAX,
            .ofpacts = pd->ofpacts.data,
            .ofpacts_len = pd->ofpacts.size,
        };
        match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
        queue_msg(swconn, ofputil_encode_packet_out(&po, proto));

        ovn_packet_data_destroy(pd);
    }

    ovs_list_init(&buffered_packets_ctx.ready_packets_data);
}

/* Update or add an IP-MAC binding for 'logical_port'.
 * Caller should make sure that 'ovnsb_idl_txn' is valid. */
static void
mac_binding_add_to_sb(struct ovsdb_idl_txn *ovnsb_idl_txn,
                      struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                      const char *logical_port,
                      const struct sbrec_datapath_binding *dp,
                      struct eth_addr ea, const char *ip,
                      bool update_only)
{
    /* Convert ethernet argument to string form for database. */
    char mac_string[ETH_ADDR_STRLEN + 1];
    snprintf(mac_string, sizeof mac_string, ETH_ADDR_FMT, ETH_ADDR_ARGS(ea));

    const struct sbrec_mac_binding *b =
        ovn_mac_binding_lookup(sbrec_mac_binding_by_lport_ip,
                               logical_port, ip);
    if (!b) {
        if (update_only) {
            return;
        }
        b = sbrec_mac_binding_insert(ovnsb_idl_txn);
        sbrec_mac_binding_set_logical_port(b, logical_port);
        sbrec_mac_binding_set_ip(b, ip);
        sbrec_mac_binding_set_datapath(b, dp);
    }

    if (strcmp(b->mac, mac_string)) {
        sbrec_mac_binding_set_mac(b, mac_string);

        /* For backward compatibility check if timestamp column is available
         * in SB DB. */
        if (pinctrl.mac_binding_can_timestamp) {
            sbrec_mac_binding_set_timestamp(b, time_wall_msec());
        }
    }
}

/* Simulate the effect of a GARP on local datapaths, i.e., create MAC_Bindings
 * on peer router datapaths.
 */
static void
send_garp_locally(struct ovsdb_idl_txn *ovnsb_idl_txn,
                  struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                  const struct hmap *local_datapaths,
                  const struct sbrec_port_binding *in_pb,
                  struct eth_addr ea, ovs_be32 ip)
{
    if (!ovnsb_idl_txn) {
        return;
    }

    const struct local_datapath *ldp =
        get_local_datapath(local_datapaths, in_pb->datapath->tunnel_key);

    ovs_assert(ldp);
    for (size_t i = 0; i < ldp->n_peer_ports; i++) {
        const struct sbrec_port_binding *local = ldp->peer_ports[i].local;
        const struct sbrec_port_binding *remote = ldp->peer_ports[i].remote;

        /* Skip "ingress" port. */
        if (local == in_pb) {
            continue;
        }

        bool update_only = !smap_get_bool(&remote->datapath->external_ids,
                                          "always_learn_from_arp_request",
                                          true);

        struct ds ip_s = DS_EMPTY_INITIALIZER;

        ip_format_masked(ip, OVS_BE32_MAX, &ip_s);
        mac_binding_add_to_sb(ovnsb_idl_txn, sbrec_mac_binding_by_lport_ip,
                              remote->logical_port, remote->datapath,
                              ea, ds_cstr(&ip_s), update_only);
        ds_destroy(&ip_s);
    }
}

static void
run_put_mac_binding(struct ovsdb_idl_txn *ovnsb_idl_txn,
                    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                    struct ovsdb_idl_index *sbrec_port_binding_by_key,
                    struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                    const struct mac_binding *mb)
{
    /* Convert logical datapath and logical port key into lport. */
    const struct sbrec_port_binding *pb = lport_lookup_by_key(
        sbrec_datapath_binding_by_key, sbrec_port_binding_by_key,
        mb->dp_key, mb->port_key);
    if (!pb) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_WARN_RL(&rl, "unknown logical port with datapath %"PRIu32" "
                     "and port %"PRIu32, mb->dp_key, mb->port_key);
        return;
    }

    /* Convert ethernet argument to string form for database. */
    char mac_string[ETH_ADDR_STRLEN + 1];
    snprintf(mac_string, sizeof mac_string,
             ETH_ADDR_FMT, ETH_ADDR_ARGS(mb->mac));

    struct ds ip_s = DS_EMPTY_INITIALIZER;
    ipv6_format_mapped(&mb->ip, &ip_s);
    mac_binding_add_to_sb(ovnsb_idl_txn, sbrec_mac_binding_by_lport_ip,
                          pb->logical_port, pb->datapath, mb->mac,
                          ds_cstr(&ip_s), false);
    ds_destroy(&ip_s);
}

/* Called by pinctrl_run(). Runs with in the main ovn-controller
 * thread context. */
static void
run_put_mac_bindings(struct ovsdb_idl_txn *ovnsb_idl_txn,
                     struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                     struct ovsdb_idl_index *sbrec_port_binding_by_key,
                     struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (!ovnsb_idl_txn) {
        return;
    }

    long long now = time_msec();

    struct mac_binding *mb;
    HMAP_FOR_EACH_SAFE (mb, hmap_node, &put_mac_bindings.map) {
        if (ovn_mac_binding_timed_out(mb, now)) {
            run_put_mac_binding(ovnsb_idl_txn,
                                sbrec_datapath_binding_by_key,
                                sbrec_port_binding_by_key,
                                sbrec_mac_binding_by_lport_ip, mb);
            ovn_mac_binding_remove(mb, &put_mac_bindings);
        }
    }
}

static void
run_buffered_binding(const struct sbrec_mac_binding_table *mac_binding_table,
                     struct ovsdb_idl_index *sbrec_port_binding_by_key,
                     struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                     struct ovsdb_idl_index *sbrec_port_binding_by_name,
                     struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (!ovn_buffered_packets_ctx_has_packets(&buffered_packets_ctx)) {
        return;
    }

    struct mac_bindings_map recent_mbs;
    ovn_mac_bindings_map_init(&recent_mbs, 0);

    const struct sbrec_mac_binding *smb;
    SBREC_MAC_BINDING_TABLE_FOR_EACH_TRACKED (smb, mac_binding_table) {
        const struct sbrec_port_binding *pb = lport_lookup_by_name(
            sbrec_port_binding_by_name, smb->logical_port);
        if (!pb || !pb->datapath) {
            continue;
        }

        struct in6_addr ip;
        if (!ip46_parse(smb->ip, &ip)) {
            continue;
        }

        struct eth_addr mac;
        if (!eth_addr_from_string(smb->mac, &mac)) {
            continue;
        }

        ovn_mac_binding_add(&recent_mbs, smb->datapath->tunnel_key,
                            pb->tunnel_key, &ip, mac, 0);

        const char *redirect_port =
            smap_get(&pb->options, "chassis-redirect-port");
        if (!redirect_port) {
            continue;
        }

        pb = lport_lookup_by_name(sbrec_port_binding_by_name, redirect_port);
        if (!pb || pb->datapath->tunnel_key != smb->datapath->tunnel_key ||
            strcmp(pb->type, "chassisredirect")) {
            continue;
        }

        /* Add the same entry also for chassisredirect port as the buffered
         * traffic might be buffered on the cr port. */
        ovn_mac_binding_add(&recent_mbs, smb->datapath->tunnel_key,
                            pb->tunnel_key, &ip, mac, 0);
    }

    ovn_buffered_packets_ctx_run(&buffered_packets_ctx, &recent_mbs,
                                 sbrec_port_binding_by_key,
                                 sbrec_datapath_binding_by_key,
                                 sbrec_port_binding_by_name,
                                 sbrec_mac_binding_by_lport_ip);

    ovn_mac_bindings_map_destroy(&recent_mbs);

    if (ovn_buffered_packets_ctx_is_ready_to_send(&buffered_packets_ctx)) {
        notify_pinctrl_handler();
    }
}

static void
wait_put_mac_bindings(struct ovsdb_idl_txn *ovnsb_idl_txn)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (ovnsb_idl_txn) {
        ovn_mac_bindings_map_wait(&put_mac_bindings);
    }
}


/*
 * Send gratuitous/reverse ARP for vif on localnet.
 *
 * When a new vif on localnet is added, gratuitous/reverse ARPs are sent
 * announcing the port's mac,ip mapping.  On localnet, such announcements
 * are needed for switches and routers on the broadcast segment to update
 * their port-mac and ARP tables.
 */
struct garp_rarp_data {
    struct eth_addr ea;          /* Ethernet address of port. */
    ovs_be32 ipv4;               /* Ipv4 address of port. */
    long long int announce_time; /* Next announcement in ms. */
    int backoff;                 /* Backoff timeout for the next
                                  * announcement (in msecs). */
    uint32_t dp_key;             /* Datapath used to output this GARP. */
    uint32_t port_key;           /* Port to inject the GARP into. */
};

/* Contains GARPs/RARPs to be sent. Protected by pinctrl_mutex*/
static struct shash send_garp_rarp_data;

static void
init_send_garps_rarps(void)
{
    shash_init(&send_garp_rarp_data);
}

static void
destroy_send_garps_rarps(void)
{
    shash_destroy_free_data(&send_garp_rarp_data);
}

/* Runs with in the main ovn-controller thread context. */
static void
add_garp_rarp(const char *name, const struct eth_addr ea, ovs_be32 ip,
              uint32_t dp_key, uint32_t port_key)
{
    struct garp_rarp_data *garp_rarp = xmalloc(sizeof *garp_rarp);
    garp_rarp->ea = ea;
    garp_rarp->ipv4 = ip;
    garp_rarp->announce_time = time_msec() + 1000;
    garp_rarp->backoff = 1000; /* msec. */
    garp_rarp->dp_key = dp_key;
    garp_rarp->port_key = port_key;
    shash_add(&send_garp_rarp_data, name, garp_rarp);

    /* Notify pinctrl_handler so that it can wakeup and process
     * these GARP/RARP requests. */
    notify_pinctrl_handler();
}

/* Add or update a vif for which GARPs need to be announced. */
static void
send_garp_rarp_update(struct ovsdb_idl_txn *ovnsb_idl_txn,
                      struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                      const struct hmap *local_datapaths,
                      const struct sbrec_port_binding *binding_rec,
                      struct shash *nat_addresses,
                      long long int garp_max_timeout,
                      bool garp_continuous)
{
    volatile struct garp_rarp_data *garp_rarp = NULL;

    /* Skip localports as they don't need to be announced */
    if (!strcmp(binding_rec->type, "localport")) {
        return;
    }

    /* Update GARP for NAT IP if it exists.  Consider port bindings with type
     * "l3gateway" for logical switch ports attached to gateway routers, and
     * port bindings with type "patch" for logical switch ports attached to
     * distributed gateway ports. */
    if (!strcmp(binding_rec->type, "l3gateway")
        || !strcmp(binding_rec->type, "patch")) {
        struct lport_addresses *laddrs = NULL;
        while ((laddrs = shash_find_and_delete(nat_addresses,
                                               binding_rec->logical_port))) {
            int i;
            for (i = 0; i < laddrs->n_ipv4_addrs; i++) {
                char *name = xasprintf("%s-%s", binding_rec->logical_port,
                                                laddrs->ipv4_addrs[i].addr_s);
                garp_rarp = shash_find_data(&send_garp_rarp_data, name);
                if (garp_rarp) {
                    garp_rarp->dp_key = binding_rec->datapath->tunnel_key;
                    garp_rarp->port_key = binding_rec->tunnel_key;
                    if (garp_max_timeout != garp_rarp_max_timeout ||
                        garp_continuous != garp_rarp_continuous) {
                        /* reset backoff */
                        garp_rarp->announce_time = time_msec() + 1000;
                        garp_rarp->backoff = 1000; /* msec. */
                    }
                } else {
                    add_garp_rarp(name, laddrs->ea,
                                  laddrs->ipv4_addrs[i].addr,
                                  binding_rec->datapath->tunnel_key,
                                  binding_rec->tunnel_key);
                    send_garp_locally(ovnsb_idl_txn,
                                      sbrec_mac_binding_by_lport_ip,
                                      local_datapaths, binding_rec, laddrs->ea,
                                      laddrs->ipv4_addrs[i].addr);

                }
                free(name);
            }
            /*
             * Send RARPs even if we do not have a ipv4 address as it e.g.
             * happens on ipv6 only ports.
             */
            if (laddrs->n_ipv4_addrs == 0) {
                    char *name = xasprintf("%s-noip",
                                           binding_rec->logical_port);
                    garp_rarp = shash_find_data(&send_garp_rarp_data, name);
                    if (garp_rarp) {
                        garp_rarp->dp_key = binding_rec->datapath->tunnel_key;
                        garp_rarp->port_key = binding_rec->tunnel_key;
                        if (garp_max_timeout != garp_rarp_max_timeout ||
                            garp_continuous != garp_rarp_continuous) {
                            /* reset backoff */
                            garp_rarp->announce_time = time_msec() + 1000;
                            garp_rarp->backoff = 1000; /* msec. */
                        }
                    } else {
                        add_garp_rarp(name, laddrs->ea,
                                      0, binding_rec->datapath->tunnel_key,
                                      binding_rec->tunnel_key);
                    }
                    free(name);
            }
            destroy_lport_addresses(laddrs);
            free(laddrs);
        }
        return;
    }

    /* Update GARP for vif if it exists. */
    garp_rarp = shash_find_data(&send_garp_rarp_data,
                                binding_rec->logical_port);
    if (garp_rarp) {
        garp_rarp->dp_key = binding_rec->datapath->tunnel_key;
        garp_rarp->port_key = binding_rec->tunnel_key;
        if (garp_max_timeout != garp_rarp_max_timeout ||
            garp_continuous != garp_rarp_continuous) {
            /* reset backoff */
            garp_rarp->announce_time = time_msec() + 1000;
            garp_rarp->backoff = 1000; /* msec. */
        }
        return;
    }

    /* Add GARP for new vif. */
    int i;
    for (i = 0; i < binding_rec->n_mac; i++) {
        struct lport_addresses laddrs;
        ovs_be32 ip = 0;
        if (!extract_lsp_addresses(binding_rec->mac[i], &laddrs)) {
            continue;
        }

        if (laddrs.n_ipv4_addrs) {
            ip = laddrs.ipv4_addrs[0].addr;
        }

        add_garp_rarp(binding_rec->logical_port,
                      laddrs.ea, ip,
                      binding_rec->datapath->tunnel_key,
                      binding_rec->tunnel_key);
        if (ip) {
            send_garp_locally(ovnsb_idl_txn, sbrec_mac_binding_by_lport_ip,
                              local_datapaths, binding_rec, laddrs.ea, ip);
        }

        destroy_lport_addresses(&laddrs);
        break;
    }
}

/* Remove a vif from GARP announcements. */
static void
send_garp_rarp_delete(const char *lport)
{
    struct garp_rarp_data *garp_rarp = shash_find_and_delete
                                       (&send_garp_rarp_data, lport);
    free(garp_rarp);
    notify_pinctrl_handler();
}

/* Called with in the pinctrl_handler thread context. */
static long long int
send_garp_rarp(struct rconn *swconn, struct garp_rarp_data *garp_rarp,
               long long int current_time)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (current_time < garp_rarp->announce_time) {
        return garp_rarp->announce_time;
    }

    /* Compose a GARP request packet. */
    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    if (garp_rarp->ipv4) {
        compose_arp(&packet, ARP_OP_REQUEST, garp_rarp->ea, eth_addr_zero,
                    true, garp_rarp->ipv4, garp_rarp->ipv4);
    } else {
        compose_rarp(&packet, garp_rarp->ea);
    }

    /* Inject GARP request. */
    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);
    put_load(garp_rarp->dp_key, MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(garp_rarp->port_key, MFF_LOG_INPORT, 0, 32, &ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_LOG_INGRESS_PIPELINE;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);

    /* Set the next announcement.  At most 5 announcements are sent for a
     * vif if garp_rarp_max_timeout is not specified otherwise cap the max
     * timeout to garp_rarp_max_timeout. */
    if (garp_rarp_continuous || garp_rarp->backoff < garp_rarp_max_timeout) {
        garp_rarp->announce_time = current_time + garp_rarp->backoff;
    } else {
        garp_rarp->announce_time = LLONG_MAX;
    }
    garp_rarp->backoff = MIN(garp_rarp_max_timeout, garp_rarp->backoff * 2);

    return garp_rarp->announce_time;
}

static void
pinctrl_compose_ipv4(struct dp_packet *packet, struct eth_addr eth_src,
                     struct eth_addr eth_dst, ovs_be32 ipv4_src,
                     ovs_be32 ipv4_dst, uint8_t ip_proto, uint8_t ttl,
                     uint16_t ip_payload_len)
{
    struct ip_header *nh;
    size_t ip_tot_len = sizeof *nh + ip_payload_len;

    /* Need to deal with odd-sized IP length while making sure that the
     * packet is still aligned.  Reserve 2 bytes for potential VLAN tags.
     */
    dp_packet_reserve(packet,
                      sizeof(struct eth_header) + ROUND_UP(ip_tot_len, 2) + 2);
    nh = eth_compose(packet, eth_dst, eth_src, ETH_TYPE_IP, ip_tot_len);
    nh->ip_ihl_ver = IP_IHL_VER(5, 4);
    nh->ip_tot_len = htons(sizeof *nh + ip_payload_len);
    nh->ip_tos = IP_DSCP_CS6;
    nh->ip_proto = ip_proto;
    nh->ip_frag_off = htons(IP_DF);

    packet_set_ipv4(packet, ipv4_src, ipv4_dst, 0, ttl);

    nh->ip_csum = 0;
    nh->ip_csum = csum(nh, sizeof *nh);
    dp_packet_set_l4(packet, nh + 1);
}

static void
pinctrl_compose_ipv6(struct dp_packet *packet, struct eth_addr eth_src,
                     struct eth_addr eth_dst, struct in6_addr *ipv6_src,
                     struct in6_addr *ipv6_dst, uint8_t ip_proto, uint8_t ttl,
                     uint16_t ip_payload_len)
{
    struct ip6_hdr *nh;
    size_t ip_tot_len = sizeof *nh + ip_payload_len;

    /* Need to deal with odd-sized IP length while making sure that the
     * packet is still aligned.  Reserve 2 bytes for potential VLAN tags.
     */
    dp_packet_reserve(packet,
                      sizeof(struct eth_header) + ROUND_UP(ip_tot_len, 2) + 2);
    nh = eth_compose(packet, eth_dst, eth_src, ETH_TYPE_IPV6, ip_tot_len);
    nh->ip6_vfc = 0x60;
    nh->ip6_nxt = ip_proto;
    nh->ip6_plen = htons(ip_payload_len);

    dp_packet_set_l4(packet, nh + 1);
    packet_set_ipv6(packet, ipv6_src, ipv6_dst, 0, 0, ttl);
}

/*
 * Multicast snooping configuration.
 */
struct ip_mcast_snoop_cfg {
    bool enabled;
    bool querier_v4_enabled;
    bool querier_v6_enabled;

    uint32_t table_size;       /* Max number of allowed multicast groups. */
    uint32_t idle_time_s;      /* Idle timeout for multicast groups. */
    uint32_t query_interval_s; /* Multicast query interval. */
    uint32_t query_max_resp_s; /* Multicast query max-response field. */
    uint32_t seq_no;           /* Used for flushing learnt groups. */

    struct eth_addr query_eth_src;    /* Src ETH address used for queries. */
    struct eth_addr query_eth_v4_dst; /* Dst ETH address used for IGMP
                                       * queries.
                                       */
    struct eth_addr query_eth_v6_dst; /* Dst ETH address used for MLD
                                       * queries.
                                       */

    ovs_be32 query_ipv4_src; /* Src IPv4 address used for queries. */
    ovs_be32 query_ipv4_dst; /* Dsc IPv4 address used for queries. */

    struct in6_addr query_ipv6_src; /* Src IPv6 address used for queries. */
    struct in6_addr query_ipv6_dst; /* Dsc IPv6 address used for queries. */
};

/*
 * Holds per-datapath information about multicast snooping. Maintained by
 * pinctrl_handler().
 */
struct ip_mcast_snoop {
    struct hmap_node hmap_node;    /* Linkage in the hash map. */
    struct ovs_list query_node;    /* Linkage in the query list. */
    struct ip_mcast_snoop_cfg cfg; /* Multicast configuration. */
    struct mcast_snooping *ms;     /* Multicast group state. */
    int64_t dp_key;                /* Datapath running the snooping. */

    long long int query_time_ms;   /* Next query time in ms. */
};

/*
 * Holds the per-datapath multicast configuration state. Maintained by
 * pinctrl_run().
 */
struct ip_mcast_snoop_state {
    struct hmap_node hmap_node;
    int64_t dp_key;
    struct ip_mcast_snoop_cfg cfg;
};

/* Only default vlan supported for now. */
#define IP_MCAST_VLAN 1

/* MLD router-alert IPv6 extension header value. */
static const uint8_t mld_router_alert[4] = {0x05, 0x02, 0x00, 0x00};

/* Multicast snooping information stored independently by datapath key.
 * Protected by pinctrl_mutex. pinctrl_handler has RW access and pinctrl_main
 * has RO access.
 */
static struct hmap mcast_snoop_map OVS_GUARDED_BY(pinctrl_mutex);

/* Contains multicast queries to be sent. Only used by pinctrl_handler so no
 * locking needed.
 */
static struct ovs_list mcast_query_list;

/* Multicast config information stored independently by datapath key.
 * Protected by pinctrl_mutex. pinctrl_handler has RO access and pinctrl_main
 * has RW access. Read accesses from pinctrl_ip_mcast_handle() can be
 * performed without taking the lock as they are executed in the pinctrl_main
 * thread.
 */
static struct hmap mcast_cfg_map OVS_GUARDED_BY(pinctrl_mutex);

static void
ip_mcast_snoop_cfg_load(struct ip_mcast_snoop_cfg *cfg,
                        const struct sbrec_ip_multicast *ip_mcast)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    memset(cfg, 0, sizeof *cfg);
    cfg->enabled =
        (ip_mcast->enabled && ip_mcast->enabled[0]);
    bool querier_enabled =
        (cfg->enabled && ip_mcast->querier && ip_mcast->querier[0]);
    cfg->querier_v4_enabled = querier_enabled;
    cfg->querier_v6_enabled = querier_enabled;

    if (ip_mcast->table_size) {
        cfg->table_size = ip_mcast->table_size[0];
    } else {
        cfg->table_size = OVN_MCAST_DEFAULT_MAX_ENTRIES;
    }

    if (ip_mcast->idle_timeout) {
        cfg->idle_time_s = ip_mcast->idle_timeout[0];
    } else {
        cfg->idle_time_s = OVN_MCAST_DEFAULT_IDLE_TIMEOUT_S;
    }

    if (ip_mcast->query_interval) {
        cfg->query_interval_s = ip_mcast->query_interval[0];
    } else {
        cfg->query_interval_s = cfg->idle_time_s / 2;
        if (cfg->query_interval_s < OVN_MCAST_MIN_QUERY_INTERVAL_S) {
            cfg->query_interval_s = OVN_MCAST_MIN_QUERY_INTERVAL_S;
        }
    }

    if (ip_mcast->query_max_resp) {
        cfg->query_max_resp_s = ip_mcast->query_max_resp[0];
    } else {
        cfg->query_max_resp_s = OVN_MCAST_DEFAULT_QUERY_MAX_RESPONSE_S;
    }

    cfg->seq_no = ip_mcast->seq_no;

    if (querier_enabled) {
        /* Try to parse the source IPv4 address. */
        if (cfg->querier_v4_enabled) {
            if (!ip_mcast->ip4_src || !ip_mcast->ip4_src[0]) {
                cfg->querier_v4_enabled = false;
            } else if (!ip_parse(ip_mcast->ip4_src, &cfg->query_ipv4_src)) {
                VLOG_WARN_RL(&rl,
                            "IGMP Querier enabled with invalid IPv4 "
                            "src address");
                /* Failed to parse the IPv4 source address. Disable the
                 * querier.
                 */
                cfg->querier_v4_enabled = false;
            }

            /* IGMP queries must be sent to 224.0.0.1. */
            cfg->query_eth_v4_dst =
                (struct eth_addr)ETH_ADDR_C(01, 00, 5E, 00, 00, 01);
            cfg->query_ipv4_dst = htonl(0xe0000001);
        }

        /* Try to parse the source IPv6 address. */
        if (cfg->querier_v6_enabled) {
            if (!ip_mcast->ip6_src || !ip_mcast->ip6_src[0]) {
                cfg->querier_v6_enabled = false;
            } else if (!ipv6_parse(ip_mcast->ip6_src, &cfg->query_ipv6_src)) {
                VLOG_WARN_RL(&rl,
                            "MLD Querier enabled with invalid IPv6 "
                            "src address");
                /* Failed to parse the IPv6 source address. Disable the
                 * querier.
                 */
                cfg->querier_v6_enabled = false;
            }

            /* MLD queries must be sent to ALL-HOSTS (ff02::1). */
            cfg->query_eth_v6_dst =
                (struct eth_addr)ETH_ADDR_C(33, 33, 00, 00, 00, 00);
            cfg->query_ipv6_dst =
                (struct in6_addr)IN6ADDR_ALL_HOSTS_INIT;
        }

        if (!cfg->querier_v4_enabled && !cfg->querier_v6_enabled) {
            VLOG_WARN_RL(&rl,
                         "IGMP Querier enabled without a valid IPv4 or IPv6 "
                         "address");
        }

        /* Try to parse the source ETH address. */
        if (!ip_mcast->eth_src ||
                !eth_addr_from_string(ip_mcast->eth_src,
                                      &cfg->query_eth_src)) {
            VLOG_WARN_RL(&rl,
                         "IGMP Querier enabled with invalid ETH src address");
            /* Failed to parse the ETH source address. Disable the querier. */
            cfg->querier_v4_enabled = false;
            cfg->querier_v6_enabled = false;
        }
    }
}

static uint32_t
ip_mcast_snoop_hash(int64_t dp_key)
{
    return hash_uint64(dp_key);
}

static struct ip_mcast_snoop_state *
ip_mcast_snoop_state_add(int64_t dp_key)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct ip_mcast_snoop_state *ms_state = xmalloc(sizeof *ms_state);

    ms_state->dp_key = dp_key;
    hmap_insert(&mcast_cfg_map, &ms_state->hmap_node,
                ip_mcast_snoop_hash(dp_key));
    return ms_state;
}

static struct ip_mcast_snoop_state *
ip_mcast_snoop_state_find(int64_t dp_key)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct ip_mcast_snoop_state *ms_state;
    uint32_t hash = ip_mcast_snoop_hash(dp_key);

    HMAP_FOR_EACH_WITH_HASH (ms_state, hmap_node, hash, &mcast_cfg_map) {
        if (ms_state->dp_key == dp_key) {
            return ms_state;
        }
    }
    return NULL;
}

/* Updates the ip_mcast_snoop_cfg for a logical datapath specified by
 * 'dp_key'.  Also sets 'needs_flush' to 'true' if the config change should
 * to trigger flushing of the existing IGMP_Groups.
 *
 * Returns 'true' if any changes happened to the configuration.
 */
static bool
ip_mcast_snoop_state_update(int64_t dp_key,
                            const struct ip_mcast_snoop_cfg *cfg,
                            bool *needs_flush)
    OVS_REQUIRES(pinctrl_mutex)
{
    bool notify = false;
    struct ip_mcast_snoop_state *ms_state = ip_mcast_snoop_state_find(dp_key);

    if (!ms_state) {
        ms_state = ip_mcast_snoop_state_add(dp_key);
        notify = true;
    } else if (memcmp(cfg, &ms_state->cfg, sizeof *cfg)) {
        if (ms_state->cfg.seq_no != cfg->seq_no) {
            *needs_flush = true;
        }
        notify = true;
    }

    ms_state->cfg = *cfg;
    return notify;
}

static void
ip_mcast_snoop_state_remove(struct ip_mcast_snoop_state *ms_state)
    OVS_REQUIRES(pinctrl_mutex)
{
    hmap_remove(&mcast_cfg_map, &ms_state->hmap_node);
    free(ms_state);
}

static bool
ip_mcast_snoop_enable(struct ip_mcast_snoop *ip_ms)
{
    if (ip_ms->cfg.enabled) {
        return true;
    }

    ip_ms->ms = mcast_snooping_create();
    return ip_ms->ms != NULL;
}

static void
ip_mcast_snoop_flush(struct ip_mcast_snoop *ip_ms)
{
    if (!ip_ms->cfg.enabled) {
        return;
    }

    mcast_snooping_flush(ip_ms->ms);
}

static void
ip_mcast_snoop_disable(struct ip_mcast_snoop *ip_ms)
{
    if (!ip_ms->cfg.enabled) {
        return;
    }

    mcast_snooping_unref(ip_ms->ms);
    ip_ms->ms = NULL;
}

static bool
ip_mcast_snoop_configure(struct ip_mcast_snoop *ip_ms,
                         const struct ip_mcast_snoop_cfg *cfg)
{
    bool old_querier_enabled =
        (ip_ms->cfg.querier_v4_enabled || ip_ms->cfg.querier_v6_enabled);

    bool querier_enabled =
        (cfg->querier_v4_enabled || cfg->querier_v6_enabled);

    if (old_querier_enabled && !querier_enabled) {
        ovs_list_remove(&ip_ms->query_node);
    } else if (!old_querier_enabled && querier_enabled) {
        ovs_list_push_back(&mcast_query_list, &ip_ms->query_node);
    }

    if (cfg->enabled) {
        if (!ip_mcast_snoop_enable(ip_ms)) {
            return false;
        }
        if (ip_ms->cfg.seq_no != cfg->seq_no) {
            ip_mcast_snoop_flush(ip_ms);
        }
    } else {
        ip_mcast_snoop_disable(ip_ms);
        goto set_fields;
    }

    ovs_rwlock_wrlock(&ip_ms->ms->rwlock);
    if (cfg->table_size != ip_ms->cfg.table_size) {
        mcast_snooping_set_max_entries(ip_ms->ms, cfg->table_size);
    }

    if (cfg->idle_time_s != ip_ms->cfg.idle_time_s) {
        mcast_snooping_set_idle_time(ip_ms->ms, cfg->idle_time_s);
    }
    ovs_rwlock_unlock(&ip_ms->ms->rwlock);

    if (cfg->query_interval_s != ip_ms->cfg.query_interval_s) {
        long long int now = time_msec();

        if (ip_ms->query_time_ms > now + cfg->query_interval_s * 1000) {
            ip_ms->query_time_ms = now;
        }
    }

set_fields:
    memcpy(&ip_ms->cfg, cfg, sizeof ip_ms->cfg);
    return true;
}

static struct ip_mcast_snoop *
ip_mcast_snoop_add(int64_t dp_key, const struct ip_mcast_snoop_cfg *cfg)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct ip_mcast_snoop *ip_ms = xzalloc(sizeof *ip_ms);

    ip_ms->dp_key = dp_key;
    if (!ip_mcast_snoop_configure(ip_ms, cfg)) {
        free(ip_ms);
        return NULL;
    }

    hmap_insert(&mcast_snoop_map, &ip_ms->hmap_node,
                ip_mcast_snoop_hash(dp_key));
    return ip_ms;
}

static struct ip_mcast_snoop *
ip_mcast_snoop_find(int64_t dp_key)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct ip_mcast_snoop *ip_ms;

    HMAP_FOR_EACH_WITH_HASH (ip_ms, hmap_node, ip_mcast_snoop_hash(dp_key),
                             &mcast_snoop_map) {
        if (ip_ms->dp_key == dp_key) {
            return ip_ms;
        }
    }
    return NULL;
}

static void
ip_mcast_snoop_remove(struct ip_mcast_snoop *ip_ms)
    OVS_REQUIRES(pinctrl_mutex)
{
    hmap_remove(&mcast_snoop_map, &ip_ms->hmap_node);

    if (ip_ms->cfg.querier_v4_enabled || ip_ms->cfg.querier_v6_enabled) {
        ovs_list_remove(&ip_ms->query_node);
    }

    ip_mcast_snoop_disable(ip_ms);
    free(ip_ms);
}

static void
ip_mcast_snoop_init(void)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    hmap_init(&mcast_snoop_map);
    ovs_list_init(&mcast_query_list);
    hmap_init(&mcast_cfg_map);
}

static void
ip_mcast_snoop_destroy(void)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct ip_mcast_snoop *ip_ms;

    HMAP_FOR_EACH_SAFE (ip_ms, hmap_node, &mcast_snoop_map) {
        ip_mcast_snoop_remove(ip_ms);
    }
    hmap_destroy(&mcast_snoop_map);

    struct ip_mcast_snoop_state *ip_ms_state;

    HMAP_FOR_EACH_POP (ip_ms_state, hmap_node, &mcast_cfg_map) {
        free(ip_ms_state);
    }
}

static void
ip_mcast_snoop_run(void)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct ip_mcast_snoop *ip_ms;

    /* First read the config updated by pinctrl_main. If there's any new or
     * updated config then apply it.
     */
    struct ip_mcast_snoop_state *ip_ms_state;

    HMAP_FOR_EACH (ip_ms_state, hmap_node, &mcast_cfg_map) {
        ip_ms = ip_mcast_snoop_find(ip_ms_state->dp_key);

        if (!ip_ms) {
            ip_mcast_snoop_add(ip_ms_state->dp_key, &ip_ms_state->cfg);
        } else if (memcmp(&ip_ms_state->cfg, &ip_ms->cfg,
                          sizeof ip_ms_state->cfg)) {
            ip_mcast_snoop_configure(ip_ms, &ip_ms_state->cfg);
        }
    }

    bool notify = false;

    /* Then walk the multicast snoop instances. */
    HMAP_FOR_EACH_SAFE (ip_ms, hmap_node, &mcast_snoop_map) {

        /* Delete the stale ones. */
        if (!ip_mcast_snoop_state_find(ip_ms->dp_key)) {
            ip_mcast_snoop_remove(ip_ms);
            continue;
        }

        /* If enabled run the snooping instance to timeout old groups. */
        if (ip_ms->cfg.enabled) {
            if (mcast_snooping_run(ip_ms->ms)) {
                notify = true;
            }

            mcast_snooping_wait(ip_ms->ms);
        }
    }

    if (notify) {
        notify_pinctrl_main();
    }
}

/* Flushes all IGMP_Groups installed by the local chassis for the logical
 * datapath specified by 'dp_key'.
 */
static void
ip_mcast_flush_groups(int64_t dp_key, const struct sbrec_chassis *chassis,
                      struct ovsdb_idl_index *sbrec_igmp_groups)
{
    const struct sbrec_igmp_group *sbrec_igmp;

    SBREC_IGMP_GROUP_FOR_EACH_BYINDEX (sbrec_igmp, sbrec_igmp_groups) {
        if (!sbrec_igmp->datapath ||
                sbrec_igmp->datapath->tunnel_key != dp_key ||
                sbrec_igmp->chassis != chassis) {
            continue;
        }
        igmp_group_delete(sbrec_igmp);
    }
}

/*
 * This runs in the pinctrl main thread, so it has access to the southbound
 * database. It reads the IP_Multicast table and updates the local multicast
 * configuration. Then writes to the southbound database the updated
 * IGMP_Groups.
 */
static void
ip_mcast_sync(struct ovsdb_idl_txn *ovnsb_idl_txn,
              const struct sbrec_chassis *chassis,
              const struct hmap *local_datapaths,
              struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
              struct ovsdb_idl_index *sbrec_port_binding_by_key,
              struct ovsdb_idl_index *sbrec_igmp_groups,
              struct ovsdb_idl_index *sbrec_ip_multicast)
    OVS_REQUIRES(pinctrl_mutex)
{
    bool notify = false;

    if (!ovnsb_idl_txn || !chassis) {
        return;
    }

    struct sbrec_ip_multicast *ip_mcast;
    struct ip_mcast_snoop_state *ip_ms_state;

    /* First read and update our own local multicast configuration for the
     * local datapaths.
     */
    SBREC_IP_MULTICAST_FOR_EACH_BYINDEX (ip_mcast, sbrec_ip_multicast) {

        int64_t dp_key = ip_mcast->datapath->tunnel_key;
        struct ip_mcast_snoop_cfg cfg;
        bool flush_groups = false;

        ip_mcast_snoop_cfg_load(&cfg, ip_mcast);
        if (ip_mcast_snoop_state_update(dp_key, &cfg, &flush_groups)) {
            notify = true;
        }
        if (flush_groups) {
            ip_mcast_flush_groups(dp_key, chassis, sbrec_igmp_groups);
        }
    }

    /* Then delete the old entries. */
    HMAP_FOR_EACH_SAFE (ip_ms_state, hmap_node, &mcast_cfg_map) {
        if (!get_local_datapath(local_datapaths, ip_ms_state->dp_key)) {
            ip_mcast_snoop_state_remove(ip_ms_state);
            notify = true;
        }
    }

    const struct sbrec_igmp_group *sbrec_ip_mrouter;
    const struct sbrec_igmp_group *sbrec_igmp;

    /* Then flush any IGMP_Group entries that are not needed anymore:
     * - either multicast snooping was disabled on the datapath
     * - or the group has expired.
     */
    SBREC_IGMP_GROUP_FOR_EACH_BYINDEX (sbrec_igmp, sbrec_igmp_groups) {
        struct in6_addr group_addr;

        if (!sbrec_igmp->datapath) {
            continue;
        }

        /* Skip non-local records. */
        if (sbrec_igmp->chassis != chassis) {
            continue;
        }

        /* Skip non-local datapaths. */
        int64_t dp_key = sbrec_igmp->datapath->tunnel_key;
        if (!get_local_datapath(local_datapaths, dp_key)) {
            continue;
        }

        struct ip_mcast_snoop *ip_ms = ip_mcast_snoop_find(dp_key);

        /* If the datapath doesn't exist anymore or IGMP snooping was disabled
         * on it then delete the IGMP_Group entry.
         */
        if (!ip_ms || !ip_ms->cfg.enabled) {
            igmp_group_delete(sbrec_igmp);
            continue;
        }

        if (!strcmp(sbrec_igmp->address, OVN_IGMP_GROUP_MROUTERS)) {
            continue;
        } else if (!ip46_parse(sbrec_igmp->address, &group_addr)) {
            continue;
        }

        ovs_rwlock_rdlock(&ip_ms->ms->rwlock);
        struct mcast_group *mc_group =
            mcast_snooping_lookup(ip_ms->ms, &group_addr, IP_MCAST_VLAN);

        if (!mc_group || ovs_list_is_empty(&mc_group->bundle_lru)) {
            igmp_group_delete(sbrec_igmp);
        }
        ovs_rwlock_unlock(&ip_ms->ms->rwlock);
    }

    struct ip_mcast_snoop *ip_ms;

    /* Last: write new IGMP_Groups to the southbound DB and update existing
     * ones (if needed). We also flush any old per-datapath multicast snoop
     * structures.
     */
    HMAP_FOR_EACH_SAFE (ip_ms, hmap_node, &mcast_snoop_map) {
        /* Flush any non-local snooping datapaths (e.g., stale). */
        struct local_datapath *local_dp =
            get_local_datapath(local_datapaths, ip_ms->dp_key);

        if (!local_dp) {
            continue;
        }

        /* Skip datapaths on which snooping is disabled. */
        if (!ip_ms->cfg.enabled) {
            continue;
        }

        struct mcast_group *mc_group;

        ovs_rwlock_rdlock(&ip_ms->ms->rwlock);

        /* Groups. */
        LIST_FOR_EACH (mc_group, group_node, &ip_ms->ms->group_lru) {
            if (ovs_list_is_empty(&mc_group->bundle_lru)) {
                continue;
            }
            sbrec_igmp = igmp_group_lookup(sbrec_igmp_groups, &mc_group->addr,
                                           local_dp->datapath, chassis);
            if (!sbrec_igmp) {
                sbrec_igmp = igmp_group_create(ovnsb_idl_txn, &mc_group->addr,
                                               local_dp->datapath, chassis);
            }

            igmp_group_update_ports(sbrec_igmp, sbrec_datapath_binding_by_key,
                                    sbrec_port_binding_by_key, ip_ms->ms,
                                    mc_group);
        }

        /* Mrouters. */
        sbrec_ip_mrouter = igmp_mrouter_lookup(sbrec_igmp_groups,
                                               local_dp->datapath,
                                               chassis);
        if (!sbrec_ip_mrouter) {
            sbrec_ip_mrouter = igmp_mrouter_create(ovnsb_idl_txn,
                                                   local_dp->datapath,
                                                   chassis);
        }
        igmp_mrouter_update_ports(sbrec_ip_mrouter,
                                  sbrec_datapath_binding_by_key,
                                  sbrec_port_binding_by_key, ip_ms->ms);

        ovs_rwlock_unlock(&ip_ms->ms->rwlock);
    }

    if (notify) {
        notify_pinctrl_handler();
    }
}

/* Reinject the packet and flood it to all registered mrouters (also those
 * who are not local to this chassis). */
static void
ip_mcast_forward_report(struct rconn *swconn, struct ip_mcast_snoop *ip_ms,
                        uint32_t orig_in_port_key,
                        const struct dp_packet *report)
{
    pinctrl_forward_pkt(swconn, ip_ms->dp_key, orig_in_port_key,
                        OVN_MCAST_MROUTER_FLOOD_TUNNEL_KEY, report);
}


static void
ip_mcast_forward_query(struct rconn *swconn, struct ip_mcast_snoop *ip_ms,
                       uint32_t orig_in_port_key,
                       const struct dp_packet *query)
{
    pinctrl_forward_pkt(swconn, ip_ms->dp_key, orig_in_port_key,
                        OVN_MCAST_FLOOD_L2_TUNNEL_KEY, query);
}

static bool
pinctrl_ip_mcast_handle_igmp(struct rconn *swconn,
                             struct ip_mcast_snoop *ip_ms,
                             const struct flow *ip_flow,
                             struct dp_packet *pkt_in,
                             uint32_t in_port_key)
{
    void *port_key_data = (void *)(uintptr_t)in_port_key;
    const struct igmp_header *igmp;
    size_t offset;

    offset = (char *) dp_packet_l4(pkt_in) - (char *) dp_packet_data(pkt_in);
    igmp = dp_packet_at(pkt_in, offset, IGMP_HEADER_LEN);
    if (!igmp || csum(igmp, dp_packet_l4_size(pkt_in)) != 0) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "multicast snooping received bad IGMP checksum");
        return false;
    }

    ovs_be32 ip4 = ip_flow->igmp_group_ip4;
    bool group_change = false;

    /* Only default VLAN is supported for now. */
    ovs_rwlock_wrlock(&ip_ms->ms->rwlock);
    switch (ntohs(ip_flow->tp_src)) {
    case IGMP_HOST_MEMBERSHIP_REPORT:
    case IGMPV2_HOST_MEMBERSHIP_REPORT:
        group_change =
            mcast_snooping_add_group4(ip_ms->ms, ip4, IP_MCAST_VLAN,
                                      port_key_data);
        break;
    case IGMP_HOST_LEAVE_MESSAGE:
        group_change =
            mcast_snooping_leave_group4(ip_ms->ms, ip4, IP_MCAST_VLAN,
                                        port_key_data);
        break;
    case IGMP_HOST_MEMBERSHIP_QUERY:
        group_change =
            mcast_snooping_add_mrouter(ip_ms->ms, IP_MCAST_VLAN,
                                       port_key_data);
        break;
    case IGMPV3_HOST_MEMBERSHIP_REPORT:
        group_change =
            mcast_snooping_add_report(ip_ms->ms, pkt_in, IP_MCAST_VLAN,
                                      port_key_data);
        break;
    }
    ovs_rwlock_unlock(&ip_ms->ms->rwlock);

    /* Forward reports to all registered mrouters and flood queries to
     * the whole L2 domain.
     */
    if (mcast_snooping_is_membership(ip_flow->tp_src)) {
        ip_mcast_forward_report(swconn, ip_ms, in_port_key, pkt_in);
    } else if (mcast_snooping_is_query(ip_flow->tp_src)) {
        ip_mcast_forward_query(swconn, ip_ms, in_port_key, pkt_in);
    }
    return group_change;
}

static bool
pinctrl_ip_mcast_handle_mld(struct rconn *swconn,
                            struct ip_mcast_snoop *ip_ms,
                            const struct flow *ip_flow,
                            struct dp_packet *pkt_in,
                            uint32_t in_port_key)
{
    void *port_key_data = (void *)(uintptr_t)in_port_key;
    const struct mld_header *mld;
    size_t offset;

    offset = (char *) dp_packet_l4(pkt_in) - (char *) dp_packet_data(pkt_in);
    mld = dp_packet_at(pkt_in, offset, MLD_HEADER_LEN);

    if (!mld || packet_csum_upperlayer6(dp_packet_l3(pkt_in),
                                        mld, IPPROTO_ICMPV6,
                                        dp_packet_l4_size(pkt_in)) != 0) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl,
                     "multicast snooping received bad MLD checksum");
        return false;
    }

    bool group_change = false;

    /* Only default VLAN is supported for now. */
    ovs_rwlock_wrlock(&ip_ms->ms->rwlock);
    switch (ntohs(ip_flow->tp_src)) {
    case MLD_QUERY:
        /* Shouldn't be receiving any of these since we are the multicast
         * router. Store them for now.
         */
        if (!ipv6_addr_equals(&ip_flow->ipv6_src, &in6addr_any)) {
            group_change =
                mcast_snooping_add_mrouter(ip_ms->ms, IP_MCAST_VLAN,
                                           port_key_data);
        }
        break;
    case MLD_REPORT:
    case MLD_DONE:
    case MLD2_REPORT:
        group_change =
            mcast_snooping_add_mld(ip_ms->ms, pkt_in, IP_MCAST_VLAN,
                                   port_key_data);
        break;
    }
    ovs_rwlock_unlock(&ip_ms->ms->rwlock);

    /* Forward reports to all registered mrouters and flood queries to
     * the whole L2 domain.
     */
    if (is_mld_report(ip_flow, NULL)) {
        ip_mcast_forward_report(swconn, ip_ms, in_port_key, pkt_in);
    } else if (is_mld_query(ip_flow, NULL)) {
        ip_mcast_forward_query(swconn, ip_ms, in_port_key, pkt_in);
    }
    return group_change;
}

static void
pinctrl_ip_mcast_handle(struct rconn *swconn,
                        const struct flow *ip_flow,
                        struct dp_packet *pkt_in,
                        const struct match *md,
                        struct ofpbuf *userdata OVS_UNUSED)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    uint16_t dl_type = ntohs(ip_flow->dl_type);

    /* This action only works for IP packets, and the switch should only send
     * us IP packets this way, but check here just to be sure.
     */
    if (dl_type != ETH_TYPE_IP && dl_type != ETH_TYPE_IPV6) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl,
                     "IGMP action on non-IP packet (eth_type 0x%"PRIx16")",
                     dl_type);
        return;
    }

    int64_t dp_key = ntohll(md->flow.metadata);

    struct ip_mcast_snoop *ip_ms = ip_mcast_snoop_find(dp_key);
    if (!ip_ms || !ip_ms->cfg.enabled) {
        /* IGMP snooping is not configured or is disabled. */
        return;
    }

    uint32_t port_key = md->flow.regs[MFF_LOG_INPORT - MFF_REG0];

    switch (dl_type) {
    case ETH_TYPE_IP:
        if (pinctrl_ip_mcast_handle_igmp(swconn, ip_ms, ip_flow, pkt_in,
                                         port_key)) {
            notify_pinctrl_main();
        }
        break;
    case ETH_TYPE_IPV6:
        if (pinctrl_ip_mcast_handle_mld(swconn, ip_ms, ip_flow, pkt_in,
                                        port_key)) {
            notify_pinctrl_main();
        }
        break;
    default:
        OVS_NOT_REACHED();
        break;
    }
}

static void
ip_mcast_querier_send_igmp(struct rconn *swconn, struct ip_mcast_snoop *ip_ms)
{
    /* Compose a multicast query. */
    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;

    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    pinctrl_compose_ipv4(&packet, ip_ms->cfg.query_eth_src,
                         ip_ms->cfg.query_eth_v4_dst,
                         ip_ms->cfg.query_ipv4_src,
                         ip_ms->cfg.query_ipv4_dst,
                         IPPROTO_IGMP, 1, sizeof(struct igmpv3_query_header));

    /* IGMP query max-response in tenths of seconds. */
    uint8_t max_response = ip_ms->cfg.query_max_resp_s * 10;
    uint8_t qqic = max_response;
    packet_set_igmp3_query(&packet, max_response, 0, false, 0, qqic);

    /* Inject multicast query. */
    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);
    put_load(ip_ms->dp_key, MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(OVN_MCAST_FLOOD_TUNNEL_KEY, MFF_LOG_OUTPORT, 0, 32, &ofpacts);
    put_load(1, MFF_LOG_FLAGS, MLF_LOCAL_ONLY, 1, &ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_LOCAL_OUTPUT;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);
}

static void
ip_mcast_querier_send_mld(struct rconn *swconn, struct ip_mcast_snoop *ip_ms)
{
    /* Compose a multicast query. */
    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;

    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    pinctrl_compose_ipv6(&packet, ip_ms->cfg.query_eth_src,
                         ip_ms->cfg.query_eth_v6_dst,
                         &ip_ms->cfg.query_ipv6_src,
                         &ip_ms->cfg.query_ipv6_dst,
                         IPPROTO_HOPOPTS, 1,
                         IPV6_EXT_HEADER_LEN + MLD_QUERY_HEADER_LEN);

    struct ipv6_ext_header *ext_hdr = dp_packet_l4(&packet);
    packet_set_ipv6_ext_header(ext_hdr, IPPROTO_ICMPV6, 0, mld_router_alert,
                               ARRAY_SIZE(mld_router_alert));

    /* MLD query max-response in milliseconds. */
    uint16_t max_response = ip_ms->cfg.query_max_resp_s * 1000;
    uint8_t qqic = ip_ms->cfg.query_max_resp_s;
    struct in6_addr unspecified = { { { 0 } } };
    packet_set_mld_query(&packet, max_response, &unspecified, false, 0, qqic);

    /* Inject multicast query. */
    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);
    put_load(ip_ms->dp_key, MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(OVN_MCAST_FLOOD_TUNNEL_KEY, MFF_LOG_OUTPORT, 0, 32, &ofpacts);
    put_load(1, MFF_LOG_FLAGS, MLF_LOCAL_ONLY, 1, &ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_LOCAL_OUTPUT;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);
}

static long long int
ip_mcast_querier_send(struct rconn *swconn, struct ip_mcast_snoop *ip_ms,
                      long long int current_time)
{
    if (current_time < ip_ms->query_time_ms) {
        return ip_ms->query_time_ms;
    }

    if (ip_ms->cfg.querier_v4_enabled) {
        ip_mcast_querier_send_igmp(swconn, ip_ms);
    }

    if (ip_ms->cfg.querier_v6_enabled) {
        ip_mcast_querier_send_mld(swconn, ip_ms);
    }

    /* Set the next query time. */
    ip_ms->query_time_ms = current_time + ip_ms->cfg.query_interval_s * 1000;
    return ip_ms->query_time_ms;
}

static void
ip_mcast_querier_run(struct rconn *swconn, long long int *query_time)
{
    if (ovs_list_is_empty(&mcast_query_list)) {
        return;
    }

    /* Send multicast queries and update the next query time. */
    long long int current_time = time_msec();
    *query_time = LLONG_MAX;

    struct ip_mcast_snoop *ip_ms;

    LIST_FOR_EACH (ip_ms, query_node, &mcast_query_list) {
        long long int next_query_time =
            ip_mcast_querier_send(swconn, ip_ms, current_time);
        if (*query_time > next_query_time) {
            *query_time = next_query_time;
        }
    }
}

static void
ip_mcast_querier_wait(long long int query_time)
{
    if (!ovs_list_is_empty(&mcast_query_list)) {
        poll_timer_wait_until(query_time);
    }
}

/* Get localnet vifs, local l3gw ports and ofport for localnet patch ports. */
static void
get_localnet_vifs_l3gwports(
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    struct ovsdb_idl_index *sbrec_port_binding_by_name,
    const struct ovsrec_bridge *br_int,
    const struct sbrec_chassis *chassis,
    const struct hmap *local_datapaths,
    struct sset *localnet_vifs,
    struct sset *local_l3gw_ports)
{
    for (int i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_int->ports[i];
        if (!strcmp(port_rec->name, br_int->name)) {
            continue;
        }
        const char *tunnel_id = smap_get(&port_rec->external_ids,
                                          "ovn-chassis-id");
        if (tunnel_id &&
                encaps_tunnel_id_match(tunnel_id, chassis->name, NULL)) {
            continue;
        }
        const char *localnet = smap_get(&port_rec->external_ids,
                                        "ovn-localnet-port");
        if (localnet) {
            continue;
        }
        for (int j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec = port_rec->interfaces[j];
            if (!iface_rec->n_ofport) {
                continue;
            }
            /* Get localnet vif. */
            const char *iface_id = smap_get(&iface_rec->external_ids,
                                            "iface-id");
            if (!iface_id) {
                continue;
            }
            const struct sbrec_port_binding *pb
                = lport_lookup_by_name(sbrec_port_binding_by_name, iface_id);
            if (!pb || pb->chassis != chassis) {
                continue;
            }
            struct local_datapath *ld
                = get_local_datapath(local_datapaths,
                                     pb->datapath->tunnel_key);
            if (ld && ld->localnet_port) {
                sset_add(localnet_vifs, iface_id);
            }
        }
    }

    struct sbrec_port_binding *target = sbrec_port_binding_index_init_row(
        sbrec_port_binding_by_datapath);

    const struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
        const struct sbrec_port_binding *pb;

        if (!ld->localnet_port) {
            continue;
        }

        /* Get l3gw ports.  Consider port bindings with type "l3gateway"
         * that connect to gateway routers (if local), and consider port
         * bindings of type "patch" since they might connect to
         * distributed gateway ports with NAT addresses. */

        sbrec_port_binding_index_set_datapath(target, ld->datapath);
        SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, target,
                                           sbrec_port_binding_by_datapath) {
            if ((!strcmp(pb->type, "l3gateway") && pb->chassis == chassis)
                || !strcmp(pb->type, "patch")) {
                sset_add(local_l3gw_ports, pb->logical_port);
            }
        }
    }
    sbrec_port_binding_index_destroy_row(target);
}


/* Extracts the mac, IPv4 and IPv6 addresses, and logical port from
 * 'addresses' which should be of the format 'MAC [IP1 IP2 ..]
 * [is_chassis_resident("LPORT_NAME")]', where IPn should be a valid IPv4
 * or IPv6 address, and stores them in the 'ipv4_addrs' and 'ipv6_addrs'
 * fields of 'laddrs'.  The logical port name is stored in 'lport'.
 *
 * Returns true if at least 'MAC' is found in 'address', false otherwise.
 *
 * The caller must call destroy_lport_addresses() and free(*lport). */
static bool
extract_addresses_with_port(const char *addresses,
                            struct lport_addresses *laddrs,
                            char **lport)
{
    int ofs;
    if (!extract_addresses(addresses, laddrs, &ofs)) {
        return false;
    } else if (!addresses[ofs]) {
        return true;
    }

    struct lexer lexer;
    lexer_init(&lexer, addresses + ofs);
    lexer_get(&lexer);

    if (lexer.error || lexer.token.type != LEX_T_ID
        || !lexer_match_id(&lexer, "is_chassis_resident")) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl, "invalid syntax '%s' in address", addresses);
        lexer_destroy(&lexer);
        return true;
    }

    if (!lexer_match(&lexer, LEX_T_LPAREN)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl, "Syntax error: expecting '(' after "
                          "'is_chassis_resident' in address '%s'", addresses);
        lexer_destroy(&lexer);
        return false;
    }

    if (lexer.token.type != LEX_T_STRING) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl,
                    "Syntax error: expecting quoted string after "
                    "'is_chassis_resident' in address '%s'", addresses);
        lexer_destroy(&lexer);
        return false;
    }

    *lport = xstrdup(lexer.token.s);

    lexer_get(&lexer);
    if (!lexer_match(&lexer, LEX_T_RPAREN)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl, "Syntax error: expecting ')' after quoted string in "
                          "'is_chassis_resident()' in address '%s'",
                          addresses);
        lexer_destroy(&lexer);
        return false;
    }

    lexer_destroy(&lexer);
    return true;
}

static void
consider_nat_address(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                     const char *nat_address,
                     const struct sbrec_port_binding *pb,
                     struct sset *nat_address_keys,
                     const struct sbrec_chassis *chassis,
                     const struct sset *active_tunnels,
                     struct shash *nat_addresses)
{
    struct lport_addresses *laddrs = xmalloc(sizeof *laddrs);
    char *lport = NULL;
    if (!extract_addresses_with_port(nat_address, laddrs, &lport)
        || (!lport && !strcmp(pb->type, "patch"))
        || (lport && !lport_is_chassis_resident(
                sbrec_port_binding_by_name, chassis,
                active_tunnels, lport))) {
        destroy_lport_addresses(laddrs);
        free(laddrs);
        free(lport);
        return;
    }
    free(lport);

    int i;
    for (i = 0; i < laddrs->n_ipv4_addrs; i++) {
        char *name = xasprintf("%s-%s", pb->logical_port,
                                        laddrs->ipv4_addrs[i].addr_s);
        sset_add(nat_address_keys, name);
        free(name);
    }
    if (laddrs->n_ipv4_addrs == 0) {
        char *name = xasprintf("%s-noip", pb->logical_port);
        sset_add(nat_address_keys, name);
        free(name);
    }
    shash_add(nat_addresses, pb->logical_port, laddrs);
}

static void
get_nat_addresses_and_keys(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                           struct sset *nat_address_keys,
                           struct sset *local_l3gw_ports,
                           const struct sbrec_chassis *chassis,
                           const struct sset *active_tunnels,
                           struct shash *nat_addresses)
{
    const char *gw_port;
    SSET_FOR_EACH(gw_port, local_l3gw_ports) {
        const struct sbrec_port_binding *pb;

        pb = lport_lookup_by_name(sbrec_port_binding_by_name, gw_port);
        if (!pb) {
            continue;
        }

        if (pb->n_nat_addresses) {
            for (int i = 0; i < pb->n_nat_addresses; i++) {
                consider_nat_address(sbrec_port_binding_by_name,
                                     pb->nat_addresses[i], pb,
                                     nat_address_keys, chassis,
                                     active_tunnels,
                                     nat_addresses);
            }
        } else {
            /* Continue to support options:nat-addresses for version
             * upgrade. */
            const char *nat_addresses_options = smap_get(&pb->options,
                                                         "nat-addresses");
            if (nat_addresses_options) {
                consider_nat_address(sbrec_port_binding_by_name,
                                     nat_addresses_options, pb,
                                     nat_address_keys, chassis,
                                     active_tunnels,
                                     nat_addresses);
            }
        }
    }
}

static void
send_garp_rarp_wait(long long int send_garp_rarp_time)
{
    /* Set the poll timer for next garp/rarp only if there is data to
     * be sent. */
    if (!shash_is_empty(&send_garp_rarp_data)) {
        poll_timer_wait_until(send_garp_rarp_time);
    }
}

/* Called with in the pinctrl_handler thread context. */
static void
send_garp_rarp_run(struct rconn *swconn, long long int *send_garp_rarp_time)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (shash_is_empty(&send_garp_rarp_data)) {
        return;
    }

    /* Send GARPs, and update the next announcement. */
    struct shash_node *iter;
    long long int current_time = time_msec();
    *send_garp_rarp_time = LLONG_MAX;
    SHASH_FOR_EACH (iter, &send_garp_rarp_data) {
        long long int next_announce = send_garp_rarp(swconn, iter->data,
                                                     current_time);
        if (*send_garp_rarp_time > next_announce) {
            *send_garp_rarp_time = next_announce;
        }
    }
}

/* Called by pinctrl_run(). Runs with in the main ovn-controller
 * thread context. */
static void
send_garp_rarp_prepare(struct ovsdb_idl_txn *ovnsb_idl_txn,
                       struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
                       struct ovsdb_idl_index *sbrec_port_binding_by_name,
                       struct ovsdb_idl_index *sbrec_mac_binding_by_lport_ip,
                       const struct ovsrec_bridge *br_int,
                       const struct sbrec_chassis *chassis,
                       const struct hmap *local_datapaths,
                       const struct sset *active_tunnels,
                       const struct ovsrec_open_vswitch_table *ovs_table)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct sset localnet_vifs = SSET_INITIALIZER(&localnet_vifs);
    struct sset local_l3gw_ports = SSET_INITIALIZER(&local_l3gw_ports);
    struct sset nat_ip_keys = SSET_INITIALIZER(&nat_ip_keys);
    struct shash nat_addresses;
    unsigned long long garp_max_timeout = GARP_RARP_DEF_MAX_TIMEOUT;
    bool garp_continuous = false;
    const struct ovsrec_open_vswitch *cfg =
        ovsrec_open_vswitch_table_first(ovs_table);
    if (cfg) {
        garp_max_timeout = smap_get_ullong(
                &cfg->external_ids, "garp-max-timeout-sec", 0) * 1000;
        garp_continuous = !!garp_max_timeout;
        if (!garp_max_timeout) {
            garp_max_timeout = GARP_RARP_DEF_MAX_TIMEOUT;
        }
    }

    shash_init(&nat_addresses);

    get_localnet_vifs_l3gwports(sbrec_port_binding_by_datapath,
                                sbrec_port_binding_by_name,
                                br_int, chassis, local_datapaths,
                                &localnet_vifs, &local_l3gw_ports);

    get_nat_addresses_and_keys(sbrec_port_binding_by_name,
                               &nat_ip_keys, &local_l3gw_ports,
                               chassis, active_tunnels,
                               &nat_addresses);
    /* For deleted ports and deleted nat ips, remove from
     * send_garp_rarp_data. */
    struct shash_node *iter;
    SHASH_FOR_EACH_SAFE (iter, &send_garp_rarp_data) {
        if (!sset_contains(&localnet_vifs, iter->name) &&
            !sset_contains(&nat_ip_keys, iter->name)) {
            send_garp_rarp_delete(iter->name);
        }
    }

    /* Update send_garp_rarp_data. */
    const char *iface_id;
    SSET_FOR_EACH (iface_id, &localnet_vifs) {
        const struct sbrec_port_binding *pb = lport_lookup_by_name(
            sbrec_port_binding_by_name, iface_id);
        if (pb) {
            send_garp_rarp_update(ovnsb_idl_txn,
                                  sbrec_mac_binding_by_lport_ip,
                                  local_datapaths, pb, &nat_addresses,
                                  garp_max_timeout, garp_continuous);
        }
    }

    /* Update send_garp_rarp_data for nat-addresses. */
    const char *gw_port;
    SSET_FOR_EACH (gw_port, &local_l3gw_ports) {
        const struct sbrec_port_binding *pb
            = lport_lookup_by_name(sbrec_port_binding_by_name, gw_port);
        if (pb) {
            send_garp_rarp_update(ovnsb_idl_txn, sbrec_mac_binding_by_lport_ip,
                                  local_datapaths, pb, &nat_addresses,
                                  garp_max_timeout, garp_continuous);
        }
    }

    /* pinctrl_handler thread will send the GARPs. */

    sset_destroy(&localnet_vifs);
    sset_destroy(&local_l3gw_ports);

    SHASH_FOR_EACH_SAFE (iter, &nat_addresses) {
        struct lport_addresses *laddrs = iter->data;
        destroy_lport_addresses(laddrs);
        shash_delete(&nat_addresses, iter);
        free(laddrs);
    }
    shash_destroy(&nat_addresses);

    sset_destroy(&nat_ip_keys);

    garp_rarp_max_timeout = garp_max_timeout;
    garp_rarp_continuous = garp_continuous;
}

static bool
may_inject_pkts(void)
{
    return (!shash_is_empty(&ipv6_ras) ||
            !shash_is_empty(&send_garp_rarp_data) ||
            ipv6_prefixd_should_inject() ||
            !ovs_list_is_empty(&mcast_query_list) ||
            ovn_buffered_packets_ctx_is_ready_to_send(&buffered_packets_ctx) ||
            bfd_monitor_should_inject());
}

static void
reload_metadata(struct ofpbuf *ofpacts, const struct match *md)
{
    enum mf_field_id md_fields[] = {
#if FLOW_N_REGS == 16
        MFF_REG0,
        MFF_REG1,
        MFF_REG2,
        MFF_REG3,
        MFF_REG4,
        MFF_REG5,
        MFF_REG6,
        MFF_REG7,
        MFF_REG8,
        MFF_REG9,
        MFF_REG10,
        MFF_REG11,
        MFF_REG12,
        MFF_REG13,
        MFF_REG14,
        MFF_REG15,
#else
#error
#endif
        MFF_METADATA,
    };
    for (size_t i = 0; i < ARRAY_SIZE(md_fields); i++) {
        const struct mf_field *field = mf_from_id(md_fields[i]);
        if (!mf_is_all_wild(field, &md->wc)) {
            union mf_value value;
            mf_get_value(field, &md->flow, &value);
            ofpact_put_set_field(ofpacts, field, &value, NULL);
        }
    }
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_nd_na(struct rconn *swconn, const struct flow *ip_flow,
                     const struct match *md,
                     struct ofpbuf *userdata, bool is_router)
{
    /* This action only works for IPv6 ND packets, and the switch should only
     * send us ND packets this way, but check here just to be sure. */
    if (!is_nd(ip_flow, NULL)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "NA action on non-ND packet");
        return;
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);

    /* These flags are not exactly correct.  Look at section 7.2.4
     * of RFC 4861. */
    uint32_t rso_flags = ND_RSO_SOLICITED | ND_RSO_OVERRIDE;
    if (is_router) {
        rso_flags |= ND_RSO_ROUTER;
    }
    compose_nd_na(&packet, ip_flow->dl_dst, ip_flow->dl_src,
                  &ip_flow->nd_target, &ip_flow->ipv6_src,
                  htonl(rso_flags));

    /* Reload previous packet metadata and set actions from userdata. */
    set_actions_and_enqueue_msg(swconn, &packet, md, userdata);
    dp_packet_uninit(&packet);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_nd_ns(struct rconn *swconn, const struct flow *ip_flow,
                     struct dp_packet *pkt_in,
                     const struct match *md, struct ofpbuf *userdata)
{
    /* This action only works for IPv6 packets. */
    if (get_dl_type(ip_flow) != htons(ETH_TYPE_IPV6)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "NS action on non-IPv6 packet");
        return;
    }

    ovs_mutex_lock(&pinctrl_mutex);
    pinctrl_handle_buffered_packets(pkt_in, md, false);
    ovs_mutex_unlock(&pinctrl_mutex);

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    struct in6_addr ipv6_src;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);

    in6_generate_lla(ip_flow->dl_src, &ipv6_src);
    compose_nd_ns(&packet, ip_flow->dl_src, &ipv6_src,
                  &ip_flow->ipv6_dst);

    /* Reload previous packet metadata and set actions from userdata. */
    set_actions_and_enqueue_msg(swconn, &packet, md, userdata);
    dp_packet_uninit(&packet);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_put_nd_ra_opts(
    struct rconn *swconn,
    const struct flow *in_flow, struct dp_packet *pkt_in,
    struct ofputil_packet_in *pin, struct ofpbuf *userdata,
    struct ofpbuf *continuation)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out_ptr = NULL;
    uint32_t success = 0;

    /* Parse result field. */
    const struct mf_field *f;
    enum ofperr ofperr = nx_pull_header(userdata, NULL, &f, NULL);
    if (ofperr) {
       VLOG_WARN_RL(&rl, "bad result OXM (%s)", ofperr_to_string(ofperr));
       goto exit;
    }

    /* Parse result offset. */
    ovs_be32 *ofsp = ofpbuf_try_pull(userdata, sizeof *ofsp);
    if (!ofsp) {
        VLOG_WARN_RL(&rl, "offset not present in the userdata");
        goto exit;
    }

    /* Check that the result is valid and writable. */
    struct mf_subfield dst = { .field = f, .ofs = ntohl(*ofsp), .n_bits = 1 };
    ofperr = mf_check_dst(&dst, NULL);
    if (ofperr) {
        VLOG_WARN_RL(&rl, "bad result bit (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    if (!userdata->size) {
        VLOG_WARN_RL(&rl, "IPv6 ND RA options not present in the userdata");
        goto exit;
    }

    if (!is_icmpv6(in_flow, NULL) || in_flow->tp_dst != htons(0) ||
        in_flow->tp_src != htons(ND_ROUTER_SOLICIT)) {
        VLOG_WARN_RL(&rl, "put_nd_ra action on invalid or unsupported packet");
        goto exit;
    }

    size_t new_packet_size = pkt_in->l4_ofs + userdata->size;
    struct dp_packet pkt_out;
    dp_packet_init(&pkt_out, new_packet_size);
    dp_packet_clear(&pkt_out);
    /* Properly align after the ethernet header */
    dp_packet_reserve(&pkt_out, 2);
    dp_packet_prealloc_tailroom(&pkt_out, new_packet_size);
    pkt_out_ptr = &pkt_out;

    /* Copy L2 and L3 headers from pkt_in. */
    dp_packet_put(&pkt_out, dp_packet_pull(pkt_in, pkt_in->l4_ofs),
                  pkt_in->l4_ofs);

    pkt_out.l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out.l2_pad_size = pkt_in->l2_pad_size;
    pkt_out.l3_ofs = pkt_in->l3_ofs;
    pkt_out.l4_ofs = pkt_in->l4_ofs;

    /* Copy the ICMPv6 Router Advertisement data from 'userdata' field. */
    dp_packet_put(&pkt_out, userdata->data, userdata->size);

    /* Set the IPv6 payload length and calculate the ICMPv6 checksum. */
    struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(&pkt_out);

    /* Set the source to "ff02::1" if the original source is "::". */
    if (!memcmp(&nh->ip6_src, &in6addr_any, sizeof in6addr_any)) {
        memcpy(&nh->ip6_src, &in6addr_all_hosts, sizeof in6addr_all_hosts);
    }

    nh->ip6_plen = htons(userdata->size);
    struct ovs_ra_msg *ra = dp_packet_l4(&pkt_out);
    ra->icmph.icmp6_cksum = 0;
    uint32_t icmp_csum = packet_csum_pseudoheader6(nh);
    ra->icmph.icmp6_cksum = csum_finish(csum_continue(
        icmp_csum, ra, userdata->size));
    pin->packet = dp_packet_data(&pkt_out);
    pin->packet_len = dp_packet_size(&pkt_out);
    success = 1;

exit:
    if (!ofperr) {
        union mf_subvalue sv;
        sv.u8_val = success;
        mf_write_subfield(&dst, &sv, &pin->flow_metadata);
    }
    queue_msg(swconn, ofputil_encode_resume(pin, continuation, proto));
    dp_packet_uninit(pkt_out_ptr);
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_put_icmp_frag_mtu(struct rconn *swconn,
                                 const struct flow *in_flow,
                                 struct dp_packet *pkt_in,
                                 struct ofputil_packet_in *pin,
                                 struct ofpbuf *userdata,
                                 struct ofpbuf *continuation)
{
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out = NULL;

    /* This action only works for ICMPv4/v6 packets. */
    if (!is_icmpv4(in_flow, NULL) && !is_icmpv6(in_flow, NULL)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl,
                     "put_icmp(4/6)_frag_mtu action on non-ICMPv4/v6 packet");
        goto exit;
    }

    pkt_out = dp_packet_clone(pkt_in);
    pkt_out->l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out->l2_pad_size = pkt_in->l2_pad_size;
    pkt_out->l3_ofs = pkt_in->l3_ofs;
    pkt_out->l4_ofs = pkt_in->l4_ofs;

    if (is_icmpv4(in_flow, NULL)) {
        ovs_be16 *mtu = ofpbuf_try_pull(userdata, sizeof *mtu);
        if (!mtu) {
            goto exit;
        }

        struct ip_header *nh = dp_packet_l3(pkt_out);
        struct icmp_header *ih = dp_packet_l4(pkt_out);
        ovs_be16 old_frag_mtu = ih->icmp_fields.frag.mtu;
        ih->icmp_fields.frag.mtu = *mtu;
        ih->icmp_csum = recalc_csum16(ih->icmp_csum, old_frag_mtu, *mtu);
        nh->ip_csum = 0;
        nh->ip_csum = csum(nh, sizeof *nh);
    } else {
        ovs_be32 *mtu = ofpbuf_try_pull(userdata, sizeof *mtu);
        if (!mtu) {
            goto exit;
        }

        struct icmp6_data_header *ih = dp_packet_l4(pkt_out);
        put_16aligned_be32(ih->icmp6_data.be32, *mtu);

        /* compute checksum and set correct mtu */
        ih->icmp6_base.icmp6_cksum = 0;
        uint32_t csum = packet_csum_pseudoheader6(dp_packet_l3(pkt_out));
        uint32_t size = (uint8_t *)dp_packet_tail(pkt_out) - (uint8_t *)ih;
        ih->icmp6_base.icmp6_cksum = csum_finish(
                csum_continue(csum, ih, size));
    }

    pin->packet = dp_packet_data(pkt_out);
    pin->packet_len = dp_packet_size(pkt_out);

exit:
    queue_msg(swconn, ofputil_encode_resume(pin, continuation, proto));
    if (pkt_out) {
        dp_packet_delete(pkt_out);
    }
}

static void
wait_controller_event(struct ovsdb_idl_txn *ovnsb_idl_txn)
{
    if (!ovnsb_idl_txn) {
        return;
    }

    for (size_t i = 0; i < OVN_EVENT_MAX; i++) {
        if (!hmap_is_empty(&event_table[i])) {
            poll_immediate_wake();
            break;
        }
    }
}

static bool
pinctrl_handle_empty_lb_backends_opts(struct ofpbuf *userdata)
{
    struct controller_event_opt_header opt_hdr;
    void *userdata_opt;
    uint32_t hash = 0;
    char *vip = NULL;
    char *protocol = NULL;
    char *load_balancer = NULL;

    while (userdata->size) {
        userdata_opt = ofpbuf_try_pull(userdata, sizeof opt_hdr);
        if (!userdata_opt) {
            return false;
        }
        memcpy(&opt_hdr, userdata_opt, sizeof opt_hdr);

        size_t size = ntohs(opt_hdr.size);
        char *userdata_opt_data = ofpbuf_try_pull(userdata, size);
        if (!userdata_opt_data) {
            return false;
        }
        switch (ntohs(opt_hdr.opt_code)) {
        case EMPTY_LB_VIP:
            vip = xmemdup0(userdata_opt_data, size);
            break;
        case EMPTY_LB_PROTOCOL:
            protocol = xmemdup0(userdata_opt_data, size);
            break;
        case EMPTY_LB_LOAD_BALANCER:
            load_balancer = xmemdup0(userdata_opt_data, size);
            break;
        default:
            OVS_NOT_REACHED();
        }
        hash = hash_bytes(userdata_opt_data, size, hash);
    }
    if (!vip || !protocol || !load_balancer) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "missing lb parameters in userdata");
        free(vip);
        free(protocol);
        free(load_balancer);
        return false;
    }

    struct empty_lb_backends_event *event;

    event = pinctrl_find_empty_lb_backends_event(vip, protocol,
                                                 load_balancer, hash);
    if (!event) {
        if (hmap_count(&event_table[OVN_EVENT_EMPTY_LB_BACKENDS]) >= 1000) {
            COVERAGE_INC(pinctrl_drop_controller_event);
            return false;
        }

        event = xzalloc(sizeof *event);
        hmap_insert(&event_table[OVN_EVENT_EMPTY_LB_BACKENDS],
                    &event->hmap_node, hash);
        event->vip = vip;
        event->protocol = protocol;
        event->load_balancer = load_balancer;
        event->timestamp = time_msec();
        notify_pinctrl_main();
    } else {
        free(vip);
        free(protocol);
        free(load_balancer);
    }
    return true;
}

static void
pinctrl_handle_event(struct ofpbuf *userdata)
    OVS_REQUIRES(pinctrl_mutex)
{
    ovs_be32 *pevent;

    pevent = ofpbuf_try_pull(userdata, sizeof *pevent);
    if (!pevent) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "event not present in the userdata");
        return;
    }

    switch (ntohl(*pevent)) {
    case OVN_EVENT_EMPTY_LB_BACKENDS:
        pinctrl_handle_empty_lb_backends_opts(userdata);
        break;
    default:
        return;
    }
}

struct put_vport_binding {
    struct hmap_node hmap_node;

    /* Key and value. */
    uint32_t dp_key;
    uint32_t vport_key;

    uint32_t vport_parent_key;
};

/* Contains "struct put_vport_binding"s. */
static struct hmap put_vport_bindings;

static void
init_put_vport_bindings(void)
{
    hmap_init(&put_vport_bindings);
}

static void
flush_put_vport_bindings(void)
{
    struct put_vport_binding *vport_b;
    HMAP_FOR_EACH_POP (vport_b, hmap_node, &put_vport_bindings) {
        free(vport_b);
    }
}

static void
destroy_put_vport_bindings(void)
{
    flush_put_vport_bindings();
    hmap_destroy(&put_vport_bindings);
}

static void
wait_put_vport_bindings(struct ovsdb_idl_txn *ovnsb_idl_txn)
{
    if (ovnsb_idl_txn && !hmap_is_empty(&put_vport_bindings)) {
        poll_immediate_wake();
    }
}

static struct put_vport_binding *
pinctrl_find_put_vport_binding(uint32_t dp_key, uint32_t vport_key,
                               uint32_t hash)
{
    struct put_vport_binding *vpb;
    HMAP_FOR_EACH_WITH_HASH (vpb, hmap_node, hash, &put_vport_bindings) {
        if (vpb->dp_key == dp_key && vpb->vport_key == vport_key) {
            return vpb;
        }
    }
    return NULL;
}

static void
run_put_vport_binding(struct ovsdb_idl_txn *ovnsb_idl_txn OVS_UNUSED,
                      struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                      struct ovsdb_idl_index *sbrec_port_binding_by_key,
                      const struct sbrec_chassis *chassis,
                      const struct put_vport_binding *vpb)
{
    /* Convert logical datapath and logical port key into lport. */
    const struct sbrec_port_binding *pb = lport_lookup_by_key(
        sbrec_datapath_binding_by_key, sbrec_port_binding_by_key,
        vpb->dp_key, vpb->vport_key);
    if (!pb) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_WARN_RL(&rl, "unknown logical port with datapath %"PRIu32" "
                     "and port %"PRIu32, vpb->dp_key, vpb->vport_key);
        return;
    }

    /* pinctrl module updates the port binding only for type 'virtual'. */
    if (!strcmp(pb->type, "virtual")) {
        const struct sbrec_port_binding *parent = lport_lookup_by_key(
        sbrec_datapath_binding_by_key, sbrec_port_binding_by_key,
        vpb->dp_key, vpb->vport_parent_key);
        if (parent) {
            VLOG_INFO("Claiming virtual lport %s for this chassis "
                       "with the virtual parent %s",
                       pb->logical_port, parent->logical_port);
            sbrec_port_binding_set_chassis(pb, chassis);
            sbrec_port_binding_set_virtual_parent(pb, parent->logical_port);
        }
    }
}

/* Called by pinctrl_run(). Runs with in the main ovn-controller
 * thread context. */
static void
run_put_vport_bindings(struct ovsdb_idl_txn *ovnsb_idl_txn,
                      struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                      struct ovsdb_idl_index *sbrec_port_binding_by_key,
                      const struct sbrec_chassis *chassis)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (!ovnsb_idl_txn) {
        return;
    }

    const struct put_vport_binding *vpb;
    HMAP_FOR_EACH (vpb, hmap_node, &put_vport_bindings) {
        run_put_vport_binding(ovnsb_idl_txn, sbrec_datapath_binding_by_key,
                              sbrec_port_binding_by_key, chassis, vpb);
    }

    flush_put_vport_bindings();
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_bind_vport(
    const struct flow *md, struct ofpbuf *userdata)
    OVS_REQUIRES(pinctrl_mutex)
{
    /* Get the datapath key from the packet metadata. */
    uint32_t dp_key = ntohll(md->metadata);
    uint32_t vport_parent_key = md->regs[MFF_LOG_INPORT - MFF_REG0];

    /* Get the virtual port key from the userdata buffer. */
    ovs_be32 *vp_key = ofpbuf_try_pull(userdata, sizeof *vp_key);

    if (!vp_key) {
        return;
    }

    uint32_t vport_key = ntohl(*vp_key);
    uint32_t hash = hash_2words(dp_key, vport_key);

    struct put_vport_binding *vpb
        = pinctrl_find_put_vport_binding(dp_key, vport_key, hash);
    if (!vpb) {
        if (hmap_count(&put_vport_bindings) >= 1000) {
            COVERAGE_INC(pinctrl_drop_put_vport_binding);
            return;
        }

        vpb = xmalloc(sizeof *vpb);
        hmap_insert(&put_vport_bindings, &vpb->hmap_node, hash);
    }

    vpb->dp_key = dp_key;
    vpb->vport_key = vport_key;
    vpb->vport_parent_key = vport_parent_key;

    notify_pinctrl_main();
}

enum svc_monitor_state {
    SVC_MON_S_INIT,
    SVC_MON_S_WAITING,
    SVC_MON_S_ONLINE,
    SVC_MON_S_OFFLINE,
};

enum svc_monitor_status {
    SVC_MON_ST_UNKNOWN,
    SVC_MON_ST_OFFLINE,
    SVC_MON_ST_ONLINE,
};

enum svc_monitor_protocol {
    SVC_MON_PROTO_TCP,
    SVC_MON_PROTO_UDP,
};

/* Service monitor health checks. */
struct svc_monitor {
    struct hmap_node hmap_node;
    struct ovs_list list_node;

    /* Should be accessed only with in the main ovn-controller
     * thread. */
    const struct sbrec_service_monitor *sb_svc_mon;

    /* key */
    struct in6_addr ip;
    uint32_t dp_key;
    uint32_t port_key;
    uint32_t proto_port; /* tcp/udp port */

    struct eth_addr ea;
    long long int timestamp;
    bool is_ip6;

    long long int wait_time;
    long long int next_send_time;

    struct smap options;
    /* The interval, in milli seconds, between service monitor checks. */
    int interval;

    /* The time, in milli seconds, after which the service monitor check
     * times out. */
    int svc_timeout;

    /* The number of successful checks after which the service is
     * considered online. */
    int success_count;
    int n_success;

    /* The number of failure checks after which the service is
     * considered offline. */
    int failure_count;
    int n_failures;

    enum svc_monitor_protocol protocol;
    enum svc_monitor_state state;
    enum svc_monitor_status status;
    struct dp_packet pkt;

    uint32_t seq_no;
    ovs_be16 tp_src;

    bool delete;
};

static struct hmap svc_monitors_map;
static struct ovs_list svc_monitors;

static void
init_svc_monitors(void)
{
    hmap_init(&svc_monitors_map);
    ovs_list_init(&svc_monitors);
}

static void
destroy_svc_monitors(void)
{
    struct svc_monitor *svc;
    HMAP_FOR_EACH_POP (svc, hmap_node, &svc_monitors_map) {

    }

    hmap_destroy(&svc_monitors_map);

    LIST_FOR_EACH_POP (svc, list_node, &svc_monitors) {
        smap_destroy(&svc->options);
        free(svc);
    }
}


static struct svc_monitor *
pinctrl_find_svc_monitor(uint32_t dp_key, uint32_t port_key,
                         const struct in6_addr *ip_key, uint32_t port,
                         enum svc_monitor_protocol protocol,
                         uint32_t hash)
{
    struct svc_monitor *svc;
    HMAP_FOR_EACH_WITH_HASH (svc, hmap_node, hash, &svc_monitors_map) {
        if (svc->dp_key == dp_key
            && svc->port_key == port_key
            && svc->proto_port == port
            && IN6_ARE_ADDR_EQUAL(&svc->ip, ip_key)
            && svc->protocol == protocol) {
            return svc;
        }
    }
    return NULL;
}

static void
sync_svc_monitors(struct ovsdb_idl_txn *ovnsb_idl_txn,
                  const struct sbrec_service_monitor_table *svc_mon_table,
                  struct ovsdb_idl_index *sbrec_port_binding_by_name,
                  const struct sbrec_chassis *our_chassis)
    OVS_REQUIRES(pinctrl_mutex)
{
    bool changed = false;
    struct svc_monitor *svc_mon;

    LIST_FOR_EACH (svc_mon, list_node, &svc_monitors) {
        svc_mon->delete = true;
    }

    const struct sbrec_service_monitor *sb_svc_mon;
    SBREC_SERVICE_MONITOR_TABLE_FOR_EACH (sb_svc_mon, svc_mon_table) {
        const struct sbrec_port_binding *pb
            = lport_lookup_by_name(sbrec_port_binding_by_name,
                                   sb_svc_mon->logical_port);
        if (!pb) {
            continue;
        }

        if (pb->chassis != our_chassis) {
            continue;
        }

        struct in6_addr ip_addr;
        ovs_be32 ip4;
        bool is_ipv4 = ip_parse(sb_svc_mon->ip, &ip4);
        if (is_ipv4) {
            ip_addr = in6_addr_mapped_ipv4(ip4);
        } else if (!ipv6_parse(sb_svc_mon->ip, &ip_addr)) {
            continue;
        }

        struct eth_addr ea;
        bool mac_found = false;
        for (size_t i = 0; i < pb->n_mac && !mac_found; i++) {
            struct lport_addresses laddrs;

            if (!extract_lsp_addresses(pb->mac[i], &laddrs)) {
                continue;
            }

            if (is_ipv4) {
                for (size_t j = 0; j < laddrs.n_ipv4_addrs; j++) {
                    if (ip4 == laddrs.ipv4_addrs[j].addr) {
                        ea = laddrs.ea;
                        mac_found = true;
                        break;
                    }
                }
            } else {
                for (size_t j = 0; j < laddrs.n_ipv6_addrs; j++) {
                    if (IN6_ARE_ADDR_EQUAL(&ip_addr,
                                           &laddrs.ipv6_addrs[j].addr)) {
                        ea = laddrs.ea;
                        mac_found = true;
                        break;
                    }
                }
            }

            if (!mac_found && !laddrs.n_ipv4_addrs && !laddrs.n_ipv6_addrs) {
                /* IP address(es) are not configured. Use the first mac. */
                ea = laddrs.ea;
                mac_found = true;
            }

            destroy_lport_addresses(&laddrs);
        }

        if (!mac_found) {
            continue;
        }

        uint32_t dp_key = pb->datapath->tunnel_key;
        uint32_t port_key = pb->tunnel_key;
        uint32_t hash =
            hash_bytes(&ip_addr, sizeof ip_addr,
                       hash_3words(dp_key, port_key, sb_svc_mon->port));

        enum svc_monitor_protocol protocol;
        if (!sb_svc_mon->protocol || strcmp(sb_svc_mon->protocol, "udp")) {
            protocol = SVC_MON_PROTO_TCP;
        } else {
            protocol = SVC_MON_PROTO_UDP;
        }

        svc_mon = pinctrl_find_svc_monitor(dp_key, port_key, &ip_addr,
                                           sb_svc_mon->port, protocol, hash);

        if (!svc_mon) {
            svc_mon = xmalloc(sizeof *svc_mon);
            svc_mon->dp_key = dp_key;
            svc_mon->port_key = port_key;
            svc_mon->proto_port = sb_svc_mon->port;
            svc_mon->ip = ip_addr;
            svc_mon->is_ip6 = !is_ipv4;
            svc_mon->state = SVC_MON_S_INIT;
            svc_mon->status = SVC_MON_ST_UNKNOWN;
            svc_mon->protocol = protocol;

            smap_init(&svc_mon->options);
            svc_mon->interval =
                smap_get_int(&svc_mon->options, "interval", 5) * 1000;
            svc_mon->svc_timeout =
                smap_get_int(&svc_mon->options, "timeout", 3) * 1000;
            svc_mon->success_count =
                smap_get_int(&svc_mon->options, "success_count", 1);
            svc_mon->failure_count =
                smap_get_int(&svc_mon->options, "failure_count", 1);
            svc_mon->n_success = 0;
            svc_mon->n_failures = 0;

            hmap_insert(&svc_monitors_map, &svc_mon->hmap_node, hash);
            ovs_list_push_back(&svc_monitors, &svc_mon->list_node);
            changed = true;
        }

        svc_mon->sb_svc_mon = sb_svc_mon;
        svc_mon->ea = ea;
        if (!smap_equal(&svc_mon->options, &sb_svc_mon->options)) {
            smap_destroy(&svc_mon->options);
            smap_clone(&svc_mon->options, &sb_svc_mon->options);
            svc_mon->interval =
                smap_get_int(&svc_mon->options, "interval", 5) * 1000;
            svc_mon->svc_timeout =
                smap_get_int(&svc_mon->options, "timeout", 3) * 1000;
            svc_mon->success_count =
                smap_get_int(&svc_mon->options, "success_count", 1);
            svc_mon->failure_count =
                smap_get_int(&svc_mon->options, "failure_count", 1);
            changed = true;
        }

        svc_mon->delete = false;
    }

    LIST_FOR_EACH_SAFE (svc_mon, list_node, &svc_monitors) {
        if (svc_mon->delete) {
            hmap_remove(&svc_monitors_map, &svc_mon->hmap_node);
            ovs_list_remove(&svc_mon->list_node);
            smap_destroy(&svc_mon->options);
            free(svc_mon);
            changed = true;
        } else if (ovnsb_idl_txn) {
            /* Update the status of the service monitor. */
            if (svc_mon->status != SVC_MON_ST_UNKNOWN) {
                if (svc_mon->status == SVC_MON_ST_ONLINE) {
                    sbrec_service_monitor_set_status(svc_mon->sb_svc_mon,
                                                     "online");
                } else {
                    sbrec_service_monitor_set_status(svc_mon->sb_svc_mon,
                                                     "offline");
                }
            }
        }
    }

    if (changed) {
        notify_pinctrl_handler();
    }

}

enum bfd_state {
    BFD_STATE_ADMIN_DOWN,
    BFD_STATE_DOWN,
    BFD_STATE_INIT,
    BFD_STATE_UP,
};

enum bfd_flags {
    BFD_FLAG_MULTIPOINT = 1 << 0,
    BFD_FLAG_DEMAND = 1 << 1,
    BFD_FLAG_AUTH = 1 << 2,
    BFD_FLAG_CTL = 1 << 3,
    BFD_FLAG_FINAL = 1 << 4,
    BFD_FLAG_POLL = 1 << 5
};

#define BFD_FLAGS_MASK  0x3f

static char *
bfd_get_status(enum bfd_state state)
{
    switch (state) {
    case BFD_STATE_ADMIN_DOWN:
        return "admin_down";
    case BFD_STATE_DOWN:
        return "down";
    case BFD_STATE_INIT:
        return "init";
    case BFD_STATE_UP:
        return "up";
    default:
        return "";
    }
}

static struct hmap bfd_monitor_map;

#define BFD_UPDATE_BATCH_TH     10
static uint16_t bfd_pending_update;
#define BFD_UPDATE_TIMEOUT      5000LL
static long long bfd_last_update;

struct bfd_entry {
    struct hmap_node node;
    bool erase;

    /* L2 source address */
    struct eth_addr src_mac;
    /* IP source address */
    struct in6_addr ip_src;
    /* IP destination address */
    struct in6_addr ip_dst;
    /* RFC 5881 section 4
     * The source port MUST be in the range 49152 through 65535.
     * The same UDP source port number MUST be used for all BFD
     * Control packets associated with a particular session.
     * The source port number SHOULD be unique among all BFD
     * sessions on the system
     */
    uint16_t udp_src;
    ovs_be32 local_disc;
    ovs_be32 remote_disc;

    uint32_t local_min_tx;
    uint32_t local_min_rx;
    uint32_t remote_min_rx;

    bool remote_demand_mode;

    uint8_t local_mult;

    int64_t port_key;
    int64_t metadata;

    enum bfd_state state;
    bool change_state;

    uint32_t detection_timeout;
    long long int last_rx;
    long long int next_tx;
};

static void
bfd_monitor_init(void)
{
    hmap_init(&bfd_monitor_map);
    bfd_last_update = time_msec();
}

static void
bfd_monitor_destroy(void)
{
    struct bfd_entry *entry;
    HMAP_FOR_EACH_POP (entry, node, &bfd_monitor_map) {
        free(entry);
    }
    hmap_destroy(&bfd_monitor_map);
}

static struct bfd_entry *
pinctrl_find_bfd_monitor_entry_by_port(char *ip, uint16_t port)
{
    struct bfd_entry *entry;
    HMAP_FOR_EACH_WITH_HASH (entry, node, hash_string(ip, 0),
                             &bfd_monitor_map) {
        if (entry->udp_src == port) {
            return entry;
        }
    }
    return NULL;
}

static struct bfd_entry *
pinctrl_find_bfd_monitor_entry_by_disc(const char *ip,
                                       const ovs_16aligned_be32 *disc)
{
    struct bfd_entry *ret = NULL, *entry;

    HMAP_FOR_EACH_WITH_HASH (entry, node, hash_string(ip, 0),
                             &bfd_monitor_map) {
        if (entry->local_disc == get_16aligned_be32(disc)) {
            ret = entry;
            break;
        }
    }
    return ret;
}

static bool
bfd_monitor_should_inject(void)
{
    long long int cur_time = time_msec();
    struct bfd_entry *entry;

    HMAP_FOR_EACH (entry, node, &bfd_monitor_map) {
        if (entry->next_tx < cur_time) {
            return true;
        }
    }
    return false;
}

static void
bfd_monitor_wait(long long int timeout)
{
    if (!hmap_is_empty(&bfd_monitor_map)) {
        poll_timer_wait_until(timeout);
    }
}

static void
bfd_monitor_put_bfd_msg(struct bfd_entry *entry, struct dp_packet *packet,
                        bool final)
{
    int payload_len = sizeof(struct udp_header) + sizeof(struct bfd_msg);

    if (IN6_IS_ADDR_V4MAPPED(&entry->ip_src)) {
        ovs_be32 ip_src = in6_addr_get_mapped_ipv4(&entry->ip_src);
        ovs_be32 ip_dst = in6_addr_get_mapped_ipv4(&entry->ip_dst);
        pinctrl_compose_ipv4(packet, entry->src_mac, eth_addr_broadcast,
                             ip_src, ip_dst, IPPROTO_UDP, MAXTTL, payload_len);
    } else {
        pinctrl_compose_ipv6(packet, entry->src_mac, eth_addr_broadcast,
                             &entry->ip_src, &entry->ip_dst, IPPROTO_UDP,
                             MAXTTL, payload_len);
    }

    struct udp_header *udp = dp_packet_l4(packet);
    udp->udp_len = htons(payload_len);
    udp->udp_csum = 0;
    udp->udp_src = htons(entry->udp_src);
    udp->udp_dst = htons(BFD_DEST_PORT);

    struct bfd_msg *msg = ALIGNED_CAST(struct bfd_msg *, udp + 1);
    msg->vers_diag = (BFD_VERSION << 5);
    msg->mult = entry->local_mult;
    msg->length = BFD_PACKET_LEN;
    msg->flags = final ? BFD_FLAG_FINAL : 0;
    msg->flags |= entry->state << 6;
    put_16aligned_be32(&msg->my_disc, entry->local_disc);
    put_16aligned_be32(&msg->your_disc, entry->remote_disc);
    /* min_tx and min_rx are in us - RFC 5880 page 9 */
    put_16aligned_be32(&msg->min_tx, htonl(entry->local_min_tx * 1000));
    put_16aligned_be32(&msg->min_rx, htonl(entry->local_min_rx * 1000));

    if (!IN6_IS_ADDR_V4MAPPED(&entry->ip_src)) {
        /* IPv6 needs UDP checksum calculated */
        uint32_t csum = packet_csum_pseudoheader6(dp_packet_l3(packet));
        int len = (uint8_t *)udp - (uint8_t *)dp_packet_eth(packet);
        csum = csum_continue(csum, udp, dp_packet_size(packet) - len);
        udp->udp_csum = csum_finish(csum);
        if (!udp->udp_csum) {
            udp->udp_csum = htons(0xffff);
        }
    }
}

static void
pinctrl_send_bfd_tx_msg(struct rconn *swconn, struct bfd_entry *entry,
                        bool final)
{
    uint64_t packet_stub[256 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    bfd_monitor_put_bfd_msg(entry, &packet, final);

    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);

    /* Set MFF_LOG_DATAPATH and MFF_LOG_INPORT. */
    uint32_t dp_key = entry->metadata;
    uint32_t port_key = entry->port_key;
    put_load(dp_key, MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(port_key, MFF_LOG_INPORT, 0, 32, &ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_LOG_INGRESS_PIPELINE;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };

    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto =
        ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);
}


static bool
bfd_monitor_need_update(void)
{
    long long int cur_time = time_msec();

    if (bfd_pending_update == BFD_UPDATE_BATCH_TH) {
        goto update;
    }

    if (bfd_pending_update &&
        bfd_last_update + BFD_UPDATE_TIMEOUT < cur_time) {
        goto update;
    }
    return false;

update:
    bfd_last_update = cur_time;
    bfd_pending_update = 0;
    return true;
}

static void
bfd_check_detection_timeout(struct bfd_entry *entry)
{
    if (entry->state == BFD_STATE_ADMIN_DOWN ||
        entry->state == BFD_STATE_DOWN) {
        return;
    }

    if (!entry->detection_timeout) {
        return;
    }

    long long int cur_time = time_msec();
    if (cur_time < entry->last_rx + entry->detection_timeout) {
        return;
    }

    entry->state = BFD_STATE_DOWN;
    entry->change_state = true;
    bfd_last_update = cur_time;
    bfd_pending_update = 0;
    notify_pinctrl_main();
}

static void
bfd_monitor_send_msg(struct rconn *swconn, long long int *bfd_time)
    OVS_REQUIRES(pinctrl_mutex)
{
    long long int cur_time = time_msec();
    struct bfd_entry *entry;

    if (bfd_monitor_need_update()) {
        notify_pinctrl_main();
    }

    HMAP_FOR_EACH (entry, node, &bfd_monitor_map) {
        unsigned long tx_timeout;

        bfd_check_detection_timeout(entry);

        if (cur_time < entry->next_tx) {
            goto next;
        }

        if (!entry->remote_min_rx) {
            continue;
        }

        if (entry->state == BFD_STATE_ADMIN_DOWN) {
            continue;
        }

        if (entry->remote_demand_mode) {
            continue;
        }

        pinctrl_send_bfd_tx_msg(swconn, entry, false);

        tx_timeout = MAX(entry->local_min_tx, entry->remote_min_rx);
        if (tx_timeout >= 4) {
            tx_timeout -= random_range(tx_timeout / 4);
        }
        entry->next_tx = cur_time + tx_timeout;
next:
        if (*bfd_time > entry->next_tx) {
            *bfd_time = entry->next_tx;
        }
    }
}

static bool
pinctrl_check_bfd_msg(const struct flow *ip_flow, struct dp_packet *pkt_in)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 30);
    if (ip_flow->dl_type != htons(ETH_TYPE_IP) &&
        ip_flow->dl_type != htons(ETH_TYPE_IPV6)) {
        VLOG_DBG_RL(&rl, "BFD action on non-IP packet (%"PRIx16")",
                    ntohs(ip_flow->dl_type));
        return false;
    }

    if (ip_flow->nw_proto != IPPROTO_UDP) {
        VLOG_DBG_RL(&rl, "BFD action on non-UDP packet %02x",
                    ip_flow->nw_proto);
        return false;
    }

    struct udp_header *udp_hdr = dp_packet_l4(pkt_in);
    if (udp_hdr->udp_dst != htons(BFD_DEST_PORT)) {
        VLOG_DBG_RL(&rl, "BFD action on wrong UDP dst port (%"PRIx16")",
                    ntohs(udp_hdr->udp_dst));
        return false;
    }

    const struct bfd_msg *msg = dp_packet_get_udp_payload(pkt_in);
    uint8_t version = msg->vers_diag >> 5;
    if (version != BFD_VERSION) {
        VLOG_DBG_RL(&rl, "BFD action: unsupported version %d", version);
        return false;
    }

    enum bfd_flags flags = msg->flags & BFD_FLAGS_MASK;
    if (flags & BFD_FLAG_AUTH) {
        /* AUTH not supported yet */
        VLOG_DBG_RL(&rl, "BFD action: AUTH not supported yet");
        return false;
    }

    if (msg->length < BFD_PACKET_LEN) {
        VLOG_DBG_RL(&rl, "BFD action: packet is too short %d", msg->length);
        return false;
    }

    if (!msg->mult) {
        VLOG_DBG_RL(&rl, "BFD action: multiplier not set");
        return false;
    }

    if (flags & BFD_FLAG_MULTIPOINT) {
        VLOG_DBG_RL(&rl, "BFD action: MULTIPOINT not supported yet");
        return false;
    }

    if (!get_16aligned_be32(&msg->my_disc)) {
        VLOG_DBG_RL(&rl, "BFD action: my_disc not set");
        return false;
    }

    if ((flags & BFD_FLAG_FINAL) && (flags & BFD_FLAG_POLL)) {
        VLOG_DBG_RL(&rl, "BFD action: wrong flags combination %08x", flags);
        return false;
    }

    enum bfd_state peer_state = msg->flags >> 6;
    if (peer_state >= BFD_STATE_INIT
        && !get_16aligned_be32(&msg->your_disc)) {
        VLOG_DBG_RL(&rl,
                    "BFD action: remote state is %s and your_disc is not set",
                    bfd_get_status(peer_state));
        return false;
    }

    return true;
}

static void
pinctrl_handle_bfd_msg(struct rconn *swconn, const struct flow *ip_flow,
                       struct dp_packet *pkt_in)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (!pinctrl_check_bfd_msg(ip_flow, pkt_in)) {
        return;
    }

    char *ip_src;
    if (ip_flow->dl_type == htons(ETH_TYPE_IP)) {
        ip_src = normalize_ipv4_prefix(ip_flow->nw_src, 32);
    } else {
        ip_src = normalize_ipv6_prefix(&ip_flow->ipv6_src, 128);
    }

    const struct bfd_msg *msg = dp_packet_get_udp_payload(pkt_in);
    struct bfd_entry *entry =
        pinctrl_find_bfd_monitor_entry_by_disc(ip_src, &msg->your_disc);

    if (!entry) {
        free(ip_src);
        return;
    }

    bool change_state = false;
    entry->remote_disc = get_16aligned_be32(&msg->my_disc);
    uint32_t remote_min_tx = ntohl(get_16aligned_be32(&msg->min_tx)) / 1000;
    entry->remote_min_rx = ntohl(get_16aligned_be32(&msg->min_rx)) / 1000;
    entry->detection_timeout = msg->mult * MAX(remote_min_tx,
                                               entry->local_min_rx);

    enum bfd_state peer_state = msg->flags >> 6;

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 30);
    VLOG_DBG_RL(&rl, "rx BFD packets from %s, remote state %s, local state %s",
                ip_src, bfd_get_status(peer_state),
                bfd_get_status(entry->state));
    free(ip_src);

    if (peer_state == BFD_STATE_ADMIN_DOWN &&
        entry->state >= BFD_STATE_INIT) {
        entry->state = BFD_STATE_DOWN;
        entry->last_rx = time_msec();
        change_state = true;
        goto out;
    }

    /* bfd state machine */
    switch (entry->state) {
    case BFD_STATE_DOWN:
        if (peer_state == BFD_STATE_DOWN) {
            entry->state = BFD_STATE_INIT;
            change_state = true;
        }
        if (peer_state == BFD_STATE_INIT) {
            entry->state = BFD_STATE_UP;
            change_state = true;
        }
        entry->last_rx = time_msec();
        break;
    case BFD_STATE_INIT:
        if (peer_state == BFD_STATE_INIT ||
            peer_state == BFD_STATE_UP) {
            entry->state = BFD_STATE_UP;
            change_state = true;
        }
        if (peer_state == BFD_STATE_ADMIN_DOWN) {
            entry->state = BFD_STATE_DOWN;
            change_state = true;
        }
        entry->last_rx = time_msec();
        break;
    case BFD_STATE_UP:
        if (peer_state == BFD_STATE_ADMIN_DOWN ||
            peer_state == BFD_STATE_DOWN) {
            entry->state = BFD_STATE_DOWN;
            change_state = true;
        }
        entry->last_rx = time_msec();
        break;
    case BFD_STATE_ADMIN_DOWN:
    default:
        break;
    }

    if (entry->state == BFD_STATE_UP &&
        (msg->flags & BFD_FLAG_DEMAND)) {
        entry->remote_demand_mode = true;
    }

    if (msg->flags & BFD_FLAG_POLL) {
        pinctrl_send_bfd_tx_msg(swconn, entry, true);
    }

out:
    /* let's try to bacth db updates */
    if (change_state) {
        entry->change_state = true;
        bfd_pending_update++;
    }
    if (bfd_monitor_need_update()) {
        notify_pinctrl_main();
    }
}

static void
bfd_monitor_check_sb_conf(const struct sbrec_bfd *sb_bt,
                          struct bfd_entry *entry)
{
    struct lport_addresses dst_addr;

    if (extract_ip_addresses(sb_bt->dst_ip, &dst_addr)) {
        struct in6_addr addr;

        if (dst_addr.n_ipv6_addrs > 0) {
            addr = dst_addr.ipv6_addrs[0].addr;
        } else {
            addr = in6_addr_mapped_ipv4(dst_addr.ipv4_addrs[0].addr);
        }

        if (!ipv6_addr_equals(&addr, &entry->ip_dst)) {
            entry->ip_dst = addr;
        }
        destroy_lport_addresses(&dst_addr);
    }

    if (sb_bt->min_tx != entry->local_min_tx) {
        entry->local_min_tx = sb_bt->min_tx;
    }

    if (sb_bt->min_rx != entry->local_min_rx) {
        entry->local_min_rx = sb_bt->min_rx;
    }

    if (sb_bt->detect_mult != entry->local_mult) {
        entry->local_mult = sb_bt->detect_mult;
    }
}

static void
bfd_monitor_run(struct ovsdb_idl_txn *ovnsb_idl_txn,
                const struct sbrec_bfd_table *bfd_table,
                struct ovsdb_idl_index *sbrec_port_binding_by_name,
                const struct sbrec_chassis *chassis,
                const struct sset *active_tunnels)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct bfd_entry *entry;
    long long int cur_time = time_msec();
    bool changed = false;

    HMAP_FOR_EACH (entry, node, &bfd_monitor_map) {
        entry->erase = true;
    }

    const struct sbrec_bfd *bt;
    SBREC_BFD_TABLE_FOR_EACH (bt, bfd_table) {
        const struct sbrec_port_binding *pb
            = lport_lookup_by_name(sbrec_port_binding_by_name,
                                   bt->logical_port);
        if (!pb) {
            continue;
        }

        const char *peer_s = smap_get(&pb->options, "peer");
        if (!peer_s) {
            continue;
        }

        const struct sbrec_port_binding *peer
            = lport_lookup_by_name(sbrec_port_binding_by_name, peer_s);
        if (!peer) {
            continue;
        }

        char *redirect_name = xasprintf("cr-%s", pb->logical_port);
        bool resident = lport_is_chassis_resident(
                sbrec_port_binding_by_name, chassis, active_tunnels,
                redirect_name);
        free(redirect_name);
        if ((strcmp(pb->type, "l3gateway") || pb->chassis != chassis) &&
            !resident) {
            continue;
        }

        entry = pinctrl_find_bfd_monitor_entry_by_port(
                bt->dst_ip, bt->src_port);
        if (!entry) {
            struct eth_addr ea = eth_addr_zero;
            struct lport_addresses dst_addr;
            struct in6_addr ip_src, ip_dst;
            int i;

            ip_dst = in6_addr_mapped_ipv4(htonl(BFD_DEFAULT_DST_IP));
            ip_src = in6_addr_mapped_ipv4(htonl(BFD_DEFAULT_SRC_IP));

            if (!extract_ip_addresses(bt->dst_ip, &dst_addr)) {
                continue;
            }

            for (i = 0; i < pb->n_mac; i++) {
                struct lport_addresses laddrs;

                if (!extract_lsp_addresses(pb->mac[i], &laddrs)) {
                    continue;
                }

                ea = laddrs.ea;
                if (dst_addr.n_ipv6_addrs > 0 && laddrs.n_ipv6_addrs > 0) {
                    ip_dst = dst_addr.ipv6_addrs[0].addr;
                    ip_src = laddrs.ipv6_addrs[0].addr;
                    destroy_lport_addresses(&laddrs);
                    break;
                } else if (laddrs.n_ipv4_addrs > 0) {
                    ip_dst = in6_addr_mapped_ipv4(dst_addr.ipv4_addrs[0].addr);
                    ip_src = in6_addr_mapped_ipv4(laddrs.ipv4_addrs[0].addr);
                    destroy_lport_addresses(&laddrs);
                    break;
                }
                destroy_lport_addresses(&laddrs);
            }
            destroy_lport_addresses(&dst_addr);

            if (eth_addr_is_zero(ea)) {
                continue;
            }

            entry = xzalloc(sizeof *entry);
            entry->src_mac = ea;
            entry->ip_src = ip_src;
            entry->ip_dst = ip_dst;
            entry->udp_src = bt->src_port;
            entry->local_disc = htonl(bt->disc);
            entry->next_tx = cur_time;
            entry->last_rx = cur_time;
            entry->detection_timeout = 30000;
            entry->metadata = pb->datapath->tunnel_key;
            entry->port_key = pb->tunnel_key;
            entry->state = BFD_STATE_ADMIN_DOWN;
            entry->local_min_tx = bt->min_tx;
            entry->local_min_rx = bt->min_rx;
            entry->remote_min_rx = 1; /* RFC5880 page 29 */
            entry->local_mult = bt->detect_mult;

            uint32_t hash = hash_string(bt->dst_ip, 0);
            hmap_insert(&bfd_monitor_map, &entry->node, hash);
        } else if (!strcmp(bt->status, "admin_down") &&
                   entry->state != BFD_STATE_ADMIN_DOWN) {
            entry->state = BFD_STATE_ADMIN_DOWN;
            entry->change_state = false;
            entry->remote_disc = 0;
        } else if (strcmp(bt->status, "admin_down") &&
                   entry->state == BFD_STATE_ADMIN_DOWN) {
            entry->state = BFD_STATE_DOWN;
            entry->change_state = false;
            entry->remote_disc = 0;
            changed = true;
        } else if (entry->change_state && ovnsb_idl_txn) {
            if (entry->state == BFD_STATE_DOWN) {
                entry->remote_disc = 0;
            }
            sbrec_bfd_set_status(bt, bfd_get_status(entry->state));
            entry->change_state = false;
        }
        bfd_monitor_check_sb_conf(bt, entry);
        entry->erase = false;
    }

    HMAP_FOR_EACH_SAFE (entry, node, &bfd_monitor_map) {
        if (entry->erase) {
            hmap_remove(&bfd_monitor_map, &entry->node);
            free(entry);
        }
    }

    if (changed) {
        notify_pinctrl_handler();
    }
}

static uint16_t
get_random_src_port(void)
{
    uint16_t random_src_port = random_uint16();
    while (random_src_port < 1024) {
        random_src_port = random_uint16();
    }

    return random_src_port;
}

static void
svc_monitor_send_tcp_health_check__(struct rconn *swconn,
                                    struct svc_monitor *svc_mon,
                                    uint16_t ctl_flags,
                                    ovs_be32 tcp_seq,
                                    ovs_be32 tcp_ack,
                                    ovs_be16 tcp_src)
{
    /* Compose a TCP-SYN packet. */
    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);

    struct eth_addr eth_src;
    eth_addr_from_string(svc_mon->sb_svc_mon->src_mac, &eth_src);
    if (svc_mon->is_ip6) {
        struct in6_addr ip6_src;
        ipv6_parse(svc_mon->sb_svc_mon->src_ip, &ip6_src);
        pinctrl_compose_ipv6(&packet, eth_src, svc_mon->ea,
                             &ip6_src, &svc_mon->ip, IPPROTO_TCP,
                             63, TCP_HEADER_LEN);
    } else {
        ovs_be32 ip4_src;
        ip_parse(svc_mon->sb_svc_mon->src_ip, &ip4_src);
        pinctrl_compose_ipv4(&packet, eth_src, svc_mon->ea,
                             ip4_src, in6_addr_get_mapped_ipv4(&svc_mon->ip),
                             IPPROTO_TCP, 63, TCP_HEADER_LEN);
    }

    struct tcp_header *th = dp_packet_l4(&packet);
    dp_packet_set_l4(&packet, th);
    th->tcp_csum = 0;
    th->tcp_dst = htons(svc_mon->proto_port);
    th->tcp_src = tcp_src;

    th->tcp_ctl = htons((5 << 12) | ctl_flags);
    put_16aligned_be32(&th->tcp_seq, tcp_seq);
    put_16aligned_be32(&th->tcp_ack, tcp_ack);

    th->tcp_winsz = htons(65160);

    uint32_t csum;
    if (svc_mon->is_ip6) {
        csum = packet_csum_pseudoheader6(dp_packet_l3(&packet));
    } else {
        csum = packet_csum_pseudoheader(dp_packet_l3(&packet));
    }
    csum = csum_continue(csum, th, dp_packet_size(&packet) -
                         ((const unsigned char *)th -
                         (const unsigned char *)dp_packet_eth(&packet)));
    th->tcp_csum = csum_finish(csum);

    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);
    put_load(svc_mon->dp_key, MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(svc_mon->port_key, MFF_LOG_OUTPORT, 0, 32, &ofpacts);
    put_load(1, MFF_LOG_FLAGS, MLF_LOCAL_ONLY, 1, &ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_LOCAL_OUTPUT;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);
}

static void
svc_monitor_send_udp_health_check(struct rconn *swconn,
                                  struct svc_monitor *svc_mon,
                                  ovs_be16 udp_src)
{
    struct eth_addr eth_src;
    eth_addr_from_string(svc_mon->sb_svc_mon->src_mac, &eth_src);

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);

    if (svc_mon->is_ip6) {
        struct in6_addr ip6_src;
        ipv6_parse(svc_mon->sb_svc_mon->src_ip, &ip6_src);
        pinctrl_compose_ipv6(&packet, eth_src, svc_mon->ea,
                             &ip6_src, &svc_mon->ip, IPPROTO_UDP,
                             63, UDP_HEADER_LEN + 8);
    } else {
        ovs_be32 ip4_src;
        ip_parse(svc_mon->sb_svc_mon->src_ip, &ip4_src);
        pinctrl_compose_ipv4(&packet, eth_src, svc_mon->ea,
                             ip4_src, in6_addr_get_mapped_ipv4(&svc_mon->ip),
                             IPPROTO_UDP, 63, UDP_HEADER_LEN + 8);
    }

    struct udp_header *uh = dp_packet_l4(&packet);
    dp_packet_set_l4(&packet, uh);
    uh->udp_dst = htons(svc_mon->proto_port);
    uh->udp_src = udp_src;
    uh->udp_len = htons(UDP_HEADER_LEN + 8);
    uh->udp_csum = 0;
    if (svc_mon->is_ip6) {
        uint32_t csum = packet_csum_pseudoheader6(dp_packet_l3(&packet));
        csum = csum_continue(csum, uh, dp_packet_size(&packet) -
                             ((const unsigned char *) uh -
                              (const unsigned char *) dp_packet_eth(&packet)));
        uh->udp_csum = csum_finish(csum);
        if (!uh->udp_csum) {
            uh->udp_csum = htons(0xffff);
        }
    }

    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);
    put_load(svc_mon->dp_key, MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(svc_mon->port_key, MFF_LOG_OUTPORT, 0, 32, &ofpacts);
    put_load(1, MFF_LOG_FLAGS, MLF_LOCAL_ONLY, 1, &ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_LOCAL_OUTPUT;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);
}

static void
svc_monitor_send_health_check(struct rconn *swconn,
                              struct svc_monitor *svc_mon)
{
    if (svc_mon->protocol == SVC_MON_PROTO_TCP) {
        svc_mon->seq_no = random_uint32();
        svc_mon->tp_src = htons(get_random_src_port());
        svc_monitor_send_tcp_health_check__(swconn, svc_mon,
                                            TCP_SYN,
                                            htonl(svc_mon->seq_no), htonl(0),
                                            svc_mon->tp_src);
    } else {
        if (!svc_mon->tp_src) {
            svc_mon->tp_src = htons(get_random_src_port());
        }
        svc_monitor_send_udp_health_check(swconn, svc_mon, svc_mon->tp_src);
    }

    svc_mon->wait_time = time_msec() + svc_mon->svc_timeout;
    svc_mon->state = SVC_MON_S_WAITING;
}

static void
svc_monitors_run(struct rconn *swconn,
                 long long int *svc_monitors_next_run_time)
    OVS_REQUIRES(pinctrl_mutex)
{
    *svc_monitors_next_run_time = LLONG_MAX;
    struct svc_monitor *svc_mon;
    LIST_FOR_EACH (svc_mon, list_node, &svc_monitors) {
        char ip_[INET6_ADDRSTRLEN + 1];
        memset(ip_, 0, INET6_ADDRSTRLEN + 1);
        ipv6_string_mapped(ip_, &svc_mon->ip);

        long long int current_time = time_msec();
        long long int next_run_time = LLONG_MAX;
        enum svc_monitor_status old_status = svc_mon->status;
        switch (svc_mon->state) {
        case SVC_MON_S_INIT:
            svc_monitor_send_health_check(swconn, svc_mon);
            next_run_time = svc_mon->wait_time;
            break;

        case SVC_MON_S_WAITING:
            if (current_time > svc_mon->wait_time) {
                if (svc_mon->protocol ==  SVC_MON_PROTO_TCP) {
                    svc_mon->n_failures++;
                    svc_mon->state = SVC_MON_S_OFFLINE;
                } else {
                    svc_mon->n_success++;
                    svc_mon->state = SVC_MON_S_ONLINE;
                }
                svc_mon->next_send_time = current_time + svc_mon->interval;
                next_run_time = svc_mon->next_send_time;
            } else {
                next_run_time = svc_mon->wait_time;
            }
            break;

        case SVC_MON_S_ONLINE:
            if (svc_mon->n_success >= svc_mon->success_count) {
                svc_mon->status = SVC_MON_ST_ONLINE;
                svc_mon->n_success = 0;
                svc_mon->n_failures = 0;
            }

            if (current_time >= svc_mon->next_send_time) {
                svc_monitor_send_health_check(swconn, svc_mon);
                next_run_time = svc_mon->wait_time;
            } else {
                next_run_time = svc_mon->next_send_time;
            }
            break;

        case SVC_MON_S_OFFLINE:
            if (svc_mon->n_failures >= svc_mon->failure_count) {
                svc_mon->status = SVC_MON_ST_OFFLINE;
                svc_mon->n_success = 0;
                svc_mon->n_failures = 0;
            }

            if (current_time >= svc_mon->next_send_time) {
                svc_monitor_send_health_check(swconn, svc_mon);
                next_run_time = svc_mon->wait_time;
            } else {
                next_run_time = svc_mon->next_send_time;
            }
            break;

        default:
            OVS_NOT_REACHED();
        }

        if (*svc_monitors_next_run_time > next_run_time) {
            *svc_monitors_next_run_time = next_run_time;
        }

        if (old_status != svc_mon->status) {
            /* Notify the main thread to update the status in the SB DB. */
            notify_pinctrl_main();
        }
    }
}

static void
svc_monitors_wait(long long int svc_monitors_next_run_time)
{
    if (!ovs_list_is_empty(&svc_monitors)) {
        poll_timer_wait_until(svc_monitors_next_run_time);
    }
}

static bool
pinctrl_handle_tcp_svc_check(struct rconn *swconn,
                             struct dp_packet *pkt_in,
                             struct svc_monitor *svc_mon)
{
    struct tcp_header *th = dp_packet_l4(pkt_in);

    if (!th) {
        return false;
    }

    uint32_t tcp_ack = ntohl(get_16aligned_be32(&th->tcp_ack));

    if (th->tcp_dst != svc_mon->tp_src) {
       return false;
    }

    if (tcp_ack != (svc_mon->seq_no + 1)) {
        return false;
    }

    /* Check for SYN flag and Ack flag. */
    if ((TCP_FLAGS(th->tcp_ctl) & (TCP_SYN | TCP_ACK))
         == (TCP_SYN | TCP_ACK)) {
        svc_mon->n_success++;
        svc_mon->state = SVC_MON_S_ONLINE;

        /* Send RST packet. */
        svc_monitor_send_tcp_health_check__(swconn, svc_mon, TCP_RST,
                                            htonl(tcp_ack),
                                            htonl(0), th->tcp_dst);
        /* Calculate next_send_time. */
        svc_mon->next_send_time = time_msec() + svc_mon->interval;
        return true;
    }

    /* Check if RST flag is set. */
    if (TCP_FLAGS(th->tcp_ctl) & TCP_RST) {
        svc_mon->n_failures++;
        svc_mon->state = SVC_MON_S_OFFLINE;

        /* Calculate next_send_time. */
        svc_mon->next_send_time = time_msec() + svc_mon->interval;
        return false;
    }

    return false;
}

static void
pinctrl_handle_svc_check(struct rconn *swconn, const struct flow *ip_flow,
                         struct dp_packet *pkt_in, const struct match *md)
{
    uint32_t dp_key = ntohll(md->flow.metadata);
    uint32_t port_key = md->flow.regs[MFF_LOG_INPORT - MFF_REG0];
    struct in6_addr ip_addr;
    struct eth_header *in_eth = dp_packet_data(pkt_in);
    uint8_t ip_proto;

    if (in_eth->eth_type == htons(ETH_TYPE_IP)) {
        struct ip_header *in_ip = dp_packet_l3(pkt_in);
        uint16_t in_ip_len = ntohs(in_ip->ip_tot_len);
        if (in_ip_len < IP_HEADER_LEN) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl,
                         "IP packet with invalid length (%u)",
                         in_ip_len);
            return;
        }

        ip_addr = in6_addr_mapped_ipv4(ip_flow->nw_src);
        ip_proto = in_ip->ip_proto;
    } else {
        struct ovs_16aligned_ip6_hdr *in_ip = dp_packet_l3(pkt_in);
        ip_addr = ip_flow->ipv6_src;
        ip_proto = in_ip->ip6_nxt;
    }

    if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_ICMP &&
        ip_proto != IPPROTO_ICMPV6) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl,
                     "handle service check: Unsupported protocol - [%x]",
                     ip_proto);
        return;
    }


    if (ip_proto == IPPROTO_TCP) {
        uint32_t hash =
            hash_bytes(&ip_addr, sizeof ip_addr,
                       hash_3words(dp_key, port_key, ntohs(ip_flow->tp_src)));

        struct svc_monitor *svc_mon =
            pinctrl_find_svc_monitor(dp_key, port_key, &ip_addr,
                                     ntohs(ip_flow->tp_src),
                                     SVC_MON_PROTO_TCP, hash);
        if (!svc_mon) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "handle service check: Service monitor "
                         "not found");
            return;
        }
        pinctrl_handle_tcp_svc_check(swconn, pkt_in, svc_mon);
    } else {
        struct udp_header *orig_uh;
        const char *end =
            (char *)dp_packet_l4(pkt_in) + dp_packet_l4_size(pkt_in);

        void *l4h = dp_packet_l4(pkt_in);
        if (!l4h) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "ICMP packet with invalid header");
            return;
        }

        const void *in_ip = dp_packet_get_icmp_payload(pkt_in);
        if (!in_ip) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "Original IP datagram not present in "
                         "ICMP packet");
            return;
        }

        if (in_eth->eth_type == htons(ETH_TYPE_IP)) {
            struct icmp_header *ih = l4h;
            /* It's ICMP packet. */
            if (ih->icmp_type != ICMP4_DST_UNREACH || ih->icmp_code != 3) {
                return;
            }

            const struct ip_header *orig_ip_hr = in_ip;
            if (ntohs(orig_ip_hr->ip_tot_len) !=
                (IP_HEADER_LEN + UDP_HEADER_LEN + 8)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_WARN_RL(&rl, "Invalid original IP datagram length "
                             "present in ICMP packet");
                return;
            }

            orig_uh = (struct udp_header *) (orig_ip_hr + 1);
            if ((char *) orig_uh >= end) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_WARN_RL(&rl, "Invalid UDP header in the original "
                             "IP datagram");
                return;
            }
        } else {
            struct icmp6_header *ih6 = l4h;
            if (ih6->icmp6_type != 1 || ih6->icmp6_code != 4) {
                return;
            }

            const struct ovs_16aligned_ip6_hdr *ip6_hdr = in_ip;
            if (ntohs(ip6_hdr->ip6_plen) != UDP_HEADER_LEN + 8) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_WARN_RL(&rl, "Invalid original IP datagram length "
                             "present in ICMP packet");
            }

            orig_uh = (struct udp_header *) (ip6_hdr + 1);
            if ((char *) orig_uh >= end) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_WARN_RL(&rl, "Invalid UDP header in the original "
                             "IP datagram");
                return;
            }
        }

        uint32_t hash =
            hash_bytes(&ip_addr, sizeof ip_addr,
                       hash_3words(dp_key, port_key, ntohs(orig_uh->udp_dst)));

        struct svc_monitor *svc_mon =
            pinctrl_find_svc_monitor(dp_key, port_key, &ip_addr,
                                     ntohs(orig_uh->udp_dst),
                                     SVC_MON_PROTO_UDP, hash);
        if (!svc_mon) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "handle service check: Service monitor not "
                         "found for ICMP packet");
            return;
        }

        if (orig_uh->udp_src != svc_mon->tp_src) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "handle service check: UDP src port doesn't "
                         "match in the Original IP datagram of ICMP packet");
            return;
        }

        /* The UDP service monitor is down. */
        svc_mon->n_failures++;
        svc_mon->state = SVC_MON_S_OFFLINE;

        /* Calculate next_send_time. */
        svc_mon->next_send_time = time_msec() + svc_mon->interval;
    }
}

static struct ovs_list ports_to_activate_in_db = OVS_LIST_INITIALIZER(
    &ports_to_activate_in_db);
static struct ovs_list ports_to_activate_in_engine = OVS_LIST_INITIALIZER(
    &ports_to_activate_in_engine);

struct ovs_list *
get_ports_to_activate_in_engine(void)
{
    ovs_mutex_lock(&pinctrl_mutex);
    if (ovs_list_is_empty(&ports_to_activate_in_engine)) {
        ovs_mutex_unlock(&pinctrl_mutex);
        return NULL;
    }

    struct ovs_list *ap = xmalloc(sizeof *ap);
    ovs_list_init(ap);
    struct activated_port *pp;
    LIST_FOR_EACH (pp, list, &ports_to_activate_in_engine) {
        struct activated_port *new = xmalloc(sizeof *new);
        new->dp_key = pp->dp_key;
        new->port_key = pp->port_key;
        ovs_list_push_front(ap, &new->list);
    }
    ovs_mutex_unlock(&pinctrl_mutex);
    return ap;
}

static void
init_activated_ports(void)
    OVS_REQUIRES(pinctrl_mutex)
{
    ovs_list_init(&ports_to_activate_in_db);
    ovs_list_init(&ports_to_activate_in_engine);
}

static void
destroy_activated_ports(void)
    OVS_REQUIRES(pinctrl_mutex)
{
    struct activated_port *pp;
    LIST_FOR_EACH_POP (pp, list, &ports_to_activate_in_db) {
        free(pp);
    }
    LIST_FOR_EACH_POP (pp, list, &ports_to_activate_in_engine) {
        free(pp);
    }
}

static void
wait_activated_ports(void)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (!ovs_list_is_empty(&ports_to_activate_in_engine)) {
        poll_immediate_wake();
    }
}

bool pinctrl_is_port_activated(int64_t dp_key, int64_t port_key)
{
    const struct activated_port *pp;
    ovs_mutex_lock(&pinctrl_mutex);
    LIST_FOR_EACH (pp, list, &ports_to_activate_in_db) {
        if (pp->dp_key == dp_key && pp->port_key == port_key) {
            ovs_mutex_unlock(&pinctrl_mutex);
            return true;
        }
    }
    LIST_FOR_EACH (pp, list, &ports_to_activate_in_engine) {
        if (pp->dp_key == dp_key && pp->port_key == port_key) {
            ovs_mutex_unlock(&pinctrl_mutex);
            return true;
        }
    }
    ovs_mutex_unlock(&pinctrl_mutex);
    return false;
}

static void
run_activated_ports(struct ovsdb_idl_txn *ovnsb_idl_txn,
                    struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
                    struct ovsdb_idl_index *sbrec_port_binding_by_key,
                    const struct sbrec_chassis *chassis)
    OVS_REQUIRES(pinctrl_mutex)
{
    if (!ovnsb_idl_txn) {
        return;
    }

    struct activated_port *pp;
    LIST_FOR_EACH_SAFE (pp, list, &ports_to_activate_in_db) {
        const struct sbrec_port_binding *pb = lport_lookup_by_key(
            sbrec_datapath_binding_by_key, sbrec_port_binding_by_key,
            pp->dp_key, pp->port_key);
        if (!pb || lport_is_activated_by_activation_strategy(pb, chassis)) {
            ovs_list_remove(&pp->list);
            free(pp);
            continue;
        }
        const char *activated_chassis = smap_get(
            &pb->options, "additional-chassis-activated");
        char *activated_str;
        if (activated_chassis) {
            activated_str = xasprintf(
                "%s,%s", activated_chassis, chassis->name);
            sbrec_port_binding_update_options_setkey(
                pb, "additional-chassis-activated", activated_str);
            free(activated_str);
        } else {
            sbrec_port_binding_update_options_setkey(
                pb, "additional-chassis-activated", chassis->name);
        }
    }
}

void
tag_port_as_activated_in_engine(struct activated_port *ap) {
    ovs_mutex_lock(&pinctrl_mutex);
    struct activated_port *pp;
    LIST_FOR_EACH_SAFE (pp, list, &ports_to_activate_in_engine) {
        if (pp->dp_key == ap->dp_key && pp->port_key == ap->port_key) {
            ovs_list_remove(&pp->list);
            free(pp);
        }
    }
    ovs_mutex_unlock(&pinctrl_mutex);
}

static void
pinctrl_rarp_activation_strategy_handler(const struct match *md)
    OVS_REQUIRES(pinctrl_mutex)
{
    /* Tag the port as activated in-memory. */
    struct activated_port *pp = xmalloc(sizeof *pp);
    pp->port_key = md->flow.regs[MFF_LOG_INPORT - MFF_REG0];
    pp->dp_key = ntohll(md->flow.metadata);
    ovs_list_push_front(&ports_to_activate_in_db, &pp->list);

    pp = xmalloc(sizeof *pp);
    pp->port_key = md->flow.regs[MFF_LOG_INPORT - MFF_REG0];
    pp->dp_key = ntohll(md->flow.metadata);
    ovs_list_push_front(&ports_to_activate_in_engine, &pp->list);

    /* Notify main thread on pending additional-chassis-activated updates. */
    notify_pinctrl_main();
}

static void
pinctrl_mg_split_buff_handler(struct rconn *swconn, struct dp_packet *pkt,
                              const struct match *md, struct ofpbuf *userdata)
{
    ovs_be32 *index = ofpbuf_try_pull(userdata, sizeof *index);
    if (!index) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "%s: missing index field", __func__);
        return;
    }

    ovs_be32 *mg = ofpbuf_try_pull(userdata, sizeof *mg);
    if (!mg) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "%s: missing multicast group field", __func__);
        return;
    }

    uint8_t *table_id = ofpbuf_try_pull(userdata, sizeof *table_id);
    if (!table_id) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "%s: missing table_id field", __func__);
        return;
    }

    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 4096);
    reload_metadata(&ofpacts, md);

    /* reload pkt_mark field */
    const struct mf_field *pkt_mark_field = mf_from_id(MFF_PKT_MARK);
    union mf_value pkt_mark_value;
    mf_get_value(pkt_mark_field, &md->flow, &pkt_mark_value);
    ofpact_put_set_field(&ofpacts, pkt_mark_field, &pkt_mark_value, NULL);

    put_load(ntohl(*index), MFF_REG6, 0, 32, &ofpacts);
    put_load(ntohl(*mg), MFF_LOG_OUTPORT, 0, 32, &ofpacts);

    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = *table_id;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(pkt),
        .packet_len = dp_packet_size(pkt),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(swconn, ofputil_encode_packet_out(&po, proto));

    ofpbuf_uninit(&ofpacts);
}

static struct hmap put_fdbs;

/* MAC learning (fdb) related functions.  Runs within the main
 * ovn-controller thread context. */

static void
init_fdb_entries(void)
{
    ovn_fdb_init(&put_fdbs);
}

static void
destroy_fdb_entries(void)
{
    ovn_fdbs_destroy(&put_fdbs);
}

static const struct sbrec_fdb *
fdb_lookup(struct ovsdb_idl_index *sbrec_fdb_by_dp_key_mac, uint32_t dp_key,
           const char *mac)
{
    struct sbrec_fdb *fdb = sbrec_fdb_index_init_row(sbrec_fdb_by_dp_key_mac);
    sbrec_fdb_index_set_dp_key(fdb, dp_key);
    sbrec_fdb_index_set_mac(fdb, mac);

    const struct sbrec_fdb *retval
        = sbrec_fdb_index_find(sbrec_fdb_by_dp_key_mac, fdb);

    sbrec_fdb_index_destroy_row(fdb);

    return retval;
}

static void
run_put_fdb(struct ovsdb_idl_txn *ovnsb_idl_txn,
            struct ovsdb_idl_index *sbrec_fdb_by_dp_key_mac,
            struct ovsdb_idl_index *sbrec_port_binding_by_key,
            struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
            const struct fdb_entry *fdb_e)
{
    /* Convert ethernet argument to string form for database. */
    char mac_string[ETH_ADDR_STRLEN + 1];
    snprintf(mac_string, sizeof mac_string,
             ETH_ADDR_FMT, ETH_ADDR_ARGS(fdb_e->mac));

    /* Update or add an FDB entry. */
    const struct sbrec_port_binding *sb_entry_pb = NULL;
    const struct sbrec_port_binding *new_entry_pb = NULL;
    const struct sbrec_fdb *sb_fdb =
        fdb_lookup(sbrec_fdb_by_dp_key_mac, fdb_e->dp_key, mac_string);
    if (!sb_fdb) {
        sb_fdb = sbrec_fdb_insert(ovnsb_idl_txn);
        sbrec_fdb_set_dp_key(sb_fdb, fdb_e->dp_key);
        sbrec_fdb_set_mac(sb_fdb, mac_string);
    } else {
        /* check whether sb_fdb->port_key is vif or localnet type */
        sb_entry_pb = lport_lookup_by_key(
            sbrec_datapath_binding_by_key, sbrec_port_binding_by_key,
            sb_fdb->dp_key, sb_fdb->port_key);
        new_entry_pb = lport_lookup_by_key(
            sbrec_datapath_binding_by_key, sbrec_port_binding_by_key,
            fdb_e->dp_key, fdb_e->port_key);
    }
    /* Do not have localnet overwrite a previous vif entry */
    if (!sb_entry_pb || !new_entry_pb || strcmp(sb_entry_pb->type, "") ||
        strcmp(new_entry_pb->type, "localnet")) {
        sbrec_fdb_set_port_key(sb_fdb, fdb_e->port_key);
    }

    /* For backward compatibility check if timestamp column is available
     * in SB DB. */
    if (pinctrl.fdb_can_timestamp) {
        sbrec_fdb_set_timestamp(sb_fdb, time_wall_msec());
    }
}

static void
run_put_fdbs(struct ovsdb_idl_txn *ovnsb_idl_txn,
             struct ovsdb_idl_index *sbrec_port_binding_by_key,
             struct ovsdb_idl_index *sbrec_datapath_binding_by_key,
             struct ovsdb_idl_index *sbrec_fdb_by_dp_key_mac)
             OVS_REQUIRES(pinctrl_mutex)
{
    if (!ovnsb_idl_txn) {
        return;
    }

    const struct fdb_entry *fdb_e;
    HMAP_FOR_EACH (fdb_e, hmap_node, &put_fdbs) {
        run_put_fdb(ovnsb_idl_txn, sbrec_fdb_by_dp_key_mac,
                    sbrec_port_binding_by_key,
                    sbrec_datapath_binding_by_key, fdb_e);
    }
    ovn_fdbs_flush(&put_fdbs);
}


static void
wait_put_fdbs(struct ovsdb_idl_txn *ovnsb_idl_txn)
{
    if (ovnsb_idl_txn && !hmap_is_empty(&put_fdbs)) {
        poll_immediate_wake();
    }
}

/* Called with in the pinctrl_handler thread context. */
static void
pinctrl_handle_put_fdb(const struct flow *md, const struct flow *headers)
                       OVS_REQUIRES(pinctrl_mutex)
{
    uint32_t dp_key = ntohll(md->metadata);
    uint32_t port_key = md->regs[MFF_LOG_INPORT - MFF_REG0];

    ovn_fdb_add(&put_fdbs, dp_key, headers->dl_src, port_key);
    notify_pinctrl_main();
}
