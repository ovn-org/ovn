/* Copyright (c) 2015, 2016, 2017 Nicira, Inc.
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
#include "binding.h"
#include "coverage.h"
#include "byte-order.h"
#include "encaps.h"
#include "flow.h"
#include "ha-chassis.h"
#include "lflow.h"
#include "local_data.h"
#include "lport.h"
#include "chassis.h"
#include "lib/bundle.h"
#include "openvswitch/poll-loop.h"
#include "lib/uuid.h"
#include "ofctrl.h"
#include "openvswitch/list.h"
#include "openvswitch/hmap.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "openvswitch/ofp-parse.h"
#include "ovn-controller.h"
#include "lib/chassis-index.h"
#include "lib/mcast-group-index.h"
#include "lib/ovn-sb-idl.h"
#include "lib/ovn-util.h"
#include "physical.h"
#include "openvswitch/shash.h"
#include "simap.h"
#include "smap.h"
#include "sset.h"
#include "util.h"
#include "vswitch-idl.h"
#include "hmapx.h"

VLOG_DEFINE_THIS_MODULE(physical);

COVERAGE_DEFINE(physical_run);

/* Datapath zone IDs for connection tracking and NAT */
struct zone_ids {
    int ct;                     /* MFF_LOG_CT_ZONE. */
    int dnat;                   /* MFF_LOG_DNAT_ZONE. */
    int snat;                   /* MFF_LOG_SNAT_ZONE. */
};

static void
load_logical_ingress_metadata(const struct sbrec_port_binding *binding,
                              const struct zone_ids *zone_ids,
                              struct ofpbuf *ofpacts_p);
static int64_t get_vxlan_port_key(int64_t port_key);

/* UUID to identify OF flows not associated with ovsdb rows. */
static struct uuid *hc_uuid = NULL;

#define CHASSIS_MAC_TO_ROUTER_MAC_CONJID        100

void
physical_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_external_ids);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_external_ids);
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
put_move(enum mf_field_id src, int src_ofs,
         enum mf_field_id dst, int dst_ofs,
         int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_reg_move *move = ofpact_put_REG_MOVE(ofpacts);
    move->src.field = mf_from_id(src);
    move->src.ofs = src_ofs;
    move->src.n_bits = n_bits;
    move->dst.field = mf_from_id(dst);
    move->dst.ofs = dst_ofs;
    move->dst.n_bits = n_bits;
}

static void
put_resubmit(uint8_t table_id, struct ofpbuf *ofpacts)
{
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(ofpacts);
    resubmit->in_port = OFPP_IN_PORT;
    resubmit->table_id = table_id;
}

/*
 * For a port binding, get the corresponding ovn-chassis-id tunnel port
 * from the associated encap.
 */
static struct chassis_tunnel *
get_port_binding_tun(const struct sbrec_port_binding *binding,
                     const struct hmap *chassis_tunnels)
{
    struct sbrec_encap *encap = binding->encap;
    struct sbrec_chassis *chassis = binding->chassis;
    struct chassis_tunnel *tun = NULL;

    if (encap) {
        tun = chassis_tunnel_find(chassis_tunnels, chassis->name, encap->ip);
    }
    if (!tun) {
        tun = chassis_tunnel_find(chassis_tunnels, chassis->name, NULL);
    }
    return tun;
}

static void
put_encapsulation(enum mf_field_id mff_ovn_geneve,
                  const struct chassis_tunnel *tun,
                  const struct sbrec_datapath_binding *datapath,
                  uint16_t outport, bool is_ramp_switch,
                  struct ofpbuf *ofpacts)
{
    if (tun->type == GENEVE) {
        put_load(datapath->tunnel_key, MFF_TUN_ID, 0, 24, ofpacts);
        put_load(outport, mff_ovn_geneve, 0, 32, ofpacts);
        put_move(MFF_LOG_INPORT, 0, mff_ovn_geneve, 16, 15, ofpacts);
    } else if (tun->type == STT) {
        put_load(datapath->tunnel_key | ((uint64_t) outport << 24),
                 MFF_TUN_ID, 0, 64, ofpacts);
        put_move(MFF_LOG_INPORT, 0, MFF_TUN_ID, 40, 15, ofpacts);
    } else if (tun->type == VXLAN) {
        uint64_t vni = datapath->tunnel_key;
        if (!is_ramp_switch) {
            /* Map southbound 16-bit port key to limited 12-bit range
             * available for VXLAN, which differs for multicast groups. */
            vni |= get_vxlan_port_key(outport) << 12;
        }
        put_load(vni, MFF_TUN_ID, 0, 24, ofpacts);
    } else {
        OVS_NOT_REACHED();
    }
}

static void
put_stack(enum mf_field_id field, struct ofpact_stack *stack)
{
    stack->subfield.field = mf_from_id(field);
    stack->subfield.ofs = 0;
    stack->subfield.n_bits = stack->subfield.field->n_bits;
}

static const struct sbrec_port_binding *
get_localnet_port(const struct hmap *local_datapaths, int64_t tunnel_key)
{
    const struct local_datapath *ld = get_local_datapath(local_datapaths,
                                                         tunnel_key);
    return ld ? ld->localnet_port : NULL;
}


static struct zone_ids
get_zone_ids(const struct sbrec_port_binding *binding,
             const struct simap *ct_zones)
{
    struct zone_ids zone_ids;

    zone_ids.ct = simap_get(ct_zones, binding->logical_port);

    const struct uuid *key = &binding->datapath->header_.uuid;

    char *dnat = alloc_nat_zone_key(key, "dnat");
    zone_ids.dnat = simap_get(ct_zones, dnat);
    free(dnat);

    char *snat = alloc_nat_zone_key(key, "snat");
    zone_ids.snat = simap_get(ct_zones, snat);
    free(snat);

    return zone_ids;
}

static void
put_remote_port_redirect_bridged(const struct
                                 sbrec_port_binding *binding,
                                 const struct hmap *local_datapaths,
                                 struct local_datapath *ld,
                                 struct match *match,
                                 struct ofpbuf *ofpacts_p,
                                 struct ovn_desired_flow_table *flow_table)
{
        if (strcmp(binding->type, "chassisredirect")) {
            /* bridged based redirect is only supported for chassisredirect
             * type remote ports. */
            return;
        }

        struct eth_addr binding_mac;
        bool  is_valid_mac = extract_sbrec_binding_first_mac(binding,
                                                             &binding_mac);
        if (!is_valid_mac) {
            return;
        }

        uint32_t ls_dp_key = 0;
        for (int i = 0; i < ld->n_peer_ports; i++) {
            const struct sbrec_port_binding *sport_binding =
                ld->peer_ports[i].remote;
            const char *sport_peer_name =
                smap_get(&sport_binding->options, "peer");
            const char *distributed_port =
                smap_get(&binding->options, "distributed-port");

            if (!strcmp(sport_peer_name, distributed_port)) {
                ls_dp_key = sport_binding->datapath->tunnel_key;
                break;
            }
        }

        if (!ls_dp_key) {
            return;
        }

        union mf_value value;
        struct ofpact_mac *src_mac;
        const struct sbrec_port_binding *ls_localnet_port;

        ls_localnet_port = get_localnet_port(local_datapaths, ls_dp_key);
        if (!ls_localnet_port) {
            return;
        }

        src_mac = ofpact_put_SET_ETH_SRC(ofpacts_p);
        src_mac->mac = binding_mac;

        value.be64 = htonll(ls_dp_key);

        ofpact_put_set_field(ofpacts_p, mf_from_id(MFF_METADATA),
                             &value, NULL);

        value.be32 = htonl(ls_localnet_port->tunnel_key);
        ofpact_put_set_field(ofpacts_p, mf_from_id(MFF_REG15),
                             &value, NULL);

        put_resubmit(OFTABLE_LOG_TO_PHY, ofpacts_p);
        ofctrl_add_flow(flow_table, OFTABLE_LOCAL_OUTPUT, 100,
                        binding->header_.uuid.parts[0],
                        match, ofpacts_p, &binding->header_.uuid);

}

static void
put_remote_port_redirect_overlay(const struct
                                 sbrec_port_binding *binding,
                                 bool is_ha_remote,
                                 struct ha_chassis_ordered *ha_ch_ordered,
                                 enum mf_field_id mff_ovn_geneve,
                                 const struct chassis_tunnel *tun,
                                 uint32_t port_key,
                                 struct match *match,
                                 struct ofpbuf *ofpacts_p,
                                 const struct hmap *chassis_tunnels,
                                 struct ovn_desired_flow_table *flow_table)
{
    if (!is_ha_remote) {
        /* Setup encapsulation */
        const struct chassis_tunnel *rem_tun =
            get_port_binding_tun(binding, chassis_tunnels);
        if (!rem_tun) {
            return;
        }
        put_encapsulation(mff_ovn_geneve, tun, binding->datapath, port_key,
                          !strcmp(binding->type, "vtep"),
                          ofpacts_p);
        /* Output to tunnel. */
        ofpact_put_OUTPUT(ofpacts_p)->port = rem_tun->ofport;
    } else {
        /* Make sure all tunnel endpoints use the same encapsulation,
         * and set it up */
        for (size_t i = 0; i < ha_ch_ordered->n_ha_ch; i++) {
            const struct sbrec_chassis *ch = ha_ch_ordered->ha_ch[i].chassis;
            if (!ch) {
                continue;
            }
            if (!tun) {
                tun = chassis_tunnel_find(chassis_tunnels, ch->name, NULL);
            } else {
                struct chassis_tunnel *chassis_tunnel =
                    chassis_tunnel_find(chassis_tunnels, ch->name, NULL);
                if (chassis_tunnel &&
                    tun->type != chassis_tunnel->type) {
                    static struct vlog_rate_limit rl =
                                  VLOG_RATE_LIMIT_INIT(1, 1);
                    VLOG_ERR_RL(&rl, "Port %s has Gateway_Chassis "
                                "with mixed encapsulations, only "
                                "uniform encapsulations are "
                                "supported.", binding->logical_port);
                    return;
                }
            }
        }
        if (!tun) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_ERR_RL(&rl, "No tunnel endpoint found for HA chassis in "
                        "HA chassis group of port %s",
                        binding->logical_port);
            return;
        }

        put_encapsulation(mff_ovn_geneve, tun, binding->datapath, port_key,
                          !strcmp(binding->type, "vtep"),
                          ofpacts_p);

        /* Output to tunnels with active/backup */
        struct ofpact_bundle *bundle = ofpact_put_BUNDLE(ofpacts_p);

        for (size_t i = 0; i < ha_ch_ordered->n_ha_ch; i++) {
            const struct sbrec_chassis *ch =
                ha_ch_ordered->ha_ch[i].chassis;
            if (!ch) {
                continue;
            }
            tun = chassis_tunnel_find(chassis_tunnels, ch->name, NULL);
            if (!tun) {
                continue;
            }
            if (bundle->n_members >= BUNDLE_MAX_MEMBERS) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "Remote endpoints for port beyond "
                             "BUNDLE_MAX_MEMBERS");
                break;
            }
            ofpbuf_put(ofpacts_p, &tun->ofport, sizeof tun->ofport);
            bundle = ofpacts_p->header;
            bundle->n_members++;
        }

        bundle->algorithm = NX_BD_ALG_ACTIVE_BACKUP;
        /* Although ACTIVE_BACKUP bundle algorithm seems to ignore
         * the next two fields, those are always set */
        bundle->basis = 0;
        bundle->fields = NX_HASH_FIELDS_ETH_SRC;
        ofpact_finish_BUNDLE(ofpacts_p, &bundle);
    }
    ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 100,
                    binding->header_.uuid.parts[0],
                    match, ofpacts_p, &binding->header_.uuid);
}


static struct hmap remote_chassis_macs =
    HMAP_INITIALIZER(&remote_chassis_macs);

/* Maps from a physical network name to the chassis macs of remote chassis. */
struct remote_chassis_mac {
    struct hmap_node hmap_node;
    char *chassis_mac;
    char *chassis_id;
    uint32_t chassis_sb_cookie;
};

static void
populate_remote_chassis_macs(const struct sbrec_chassis *my_chassis,
                             const struct sbrec_chassis_table *chassis_table)
{
    const struct sbrec_chassis *chassis;
    SBREC_CHASSIS_TABLE_FOR_EACH (chassis, chassis_table) {

        /* We want only remote chassis macs. */
        if (!strcmp(my_chassis->name, chassis->name)) {
            continue;
        }

        const char *tokens
            = get_chassis_mac_mappings(&chassis->other_config);

        if (!strlen(tokens)) {
            continue;
        }

        char *save_ptr = NULL;
        char *token;
        char *tokstr = xstrdup(tokens);

        /* Format for a chassis mac configuration is:
         * ovn-chassis-mac-mappings="bridge-name1:MAC1,bridge-name2:MAC2"
         */
        for (token = strtok_r(tokstr, ",", &save_ptr);
             token != NULL;
             token = strtok_r(NULL, ",", &save_ptr)) {
            char *save_ptr2 = NULL;
            char *chassis_mac_bridge = strtok_r(token, ":", &save_ptr2);
            char *chassis_mac_str = strtok_r(NULL, "", &save_ptr2);
            struct remote_chassis_mac *remote_chassis_mac = NULL;
            remote_chassis_mac = xmalloc(sizeof *remote_chassis_mac);
            hmap_insert(&remote_chassis_macs, &remote_chassis_mac->hmap_node,
                        hash_string(chassis_mac_bridge, 0));
            remote_chassis_mac->chassis_mac = xstrdup(chassis_mac_str);
            remote_chassis_mac->chassis_id = xstrdup(chassis->name);
            remote_chassis_mac->chassis_sb_cookie =
                chassis->header_.uuid.parts[0];
        }
        free(tokstr);
    }
}

static void
free_remote_chassis_macs(void)
{
    struct remote_chassis_mac *mac, *next_mac;

    HMAP_FOR_EACH_SAFE (mac, next_mac, hmap_node, &remote_chassis_macs) {
        hmap_remove(&remote_chassis_macs, &mac->hmap_node);
        free(mac->chassis_mac);
        free(mac->chassis_id);
        free(mac);
    }
}

static void
put_chassis_mac_conj_id_flow(const struct sbrec_chassis_table *chassis_table,
                             const struct sbrec_chassis *chassis,
                             struct ofpbuf *ofpacts_p,
                             struct ovn_desired_flow_table *flow_table)
{
    struct match match;
    struct remote_chassis_mac *mac;

    populate_remote_chassis_macs(chassis, chassis_table);

    HMAP_FOR_EACH (mac, hmap_node, &remote_chassis_macs) {
        struct eth_addr chassis_mac;
        char *err_str = NULL;
        struct ofpact_conjunction *conj;

        if ((err_str = str_to_mac(mac->chassis_mac, &chassis_mac))) {
            free(err_str);
            free_remote_chassis_macs();
            return;
        }

        ofpbuf_clear(ofpacts_p);
        match_init_catchall(&match);


        match_set_dl_src(&match, chassis_mac);

        conj = ofpact_put_CONJUNCTION(ofpacts_p);
        conj->id = CHASSIS_MAC_TO_ROUTER_MAC_CONJID;
        conj->n_clauses = 2;
        conj->clause = 0;
        ofctrl_add_flow(flow_table, OFTABLE_PHY_TO_LOG, 180,
                        mac->chassis_sb_cookie,
                        &match, ofpacts_p, hc_uuid);
    }

    free_remote_chassis_macs();
}

static void
put_replace_chassis_mac_flows(const struct simap *ct_zones,
                              const struct
                              sbrec_port_binding *localnet_port,
                              const struct hmap *local_datapaths,
                              struct ofpbuf *ofpacts_p,
                              ofp_port_t ofport,
                              struct ovn_desired_flow_table *flow_table)
{
    /* Packets arriving on localnet port, could have been routed on
     * source chassis and hence will have a chassis mac.
     * conj_match will match source mac with chassis macs conjunction
     * and replace it with corresponding router port mac.
     */
    struct local_datapath *ld = get_local_datapath(local_datapaths,
                                                   localnet_port->datapath->
                                                   tunnel_key);
    ovs_assert(ld);

    int tag = localnet_port->tag ? *localnet_port->tag : 0;
    struct zone_ids zone_ids = get_zone_ids(localnet_port, ct_zones);

    for (int i = 0; i < ld->n_peer_ports; i++) {
        const struct sbrec_port_binding *rport_binding =
            ld->peer_ports[i].remote;
        struct eth_addr router_port_mac;
        char *err_str = NULL;
        struct match match;
        struct ofpact_mac *replace_mac;

        ovs_assert(rport_binding->n_mac == 1);
        if ((err_str = str_to_mac(rport_binding->mac[0], &router_port_mac))) {
            /* Parsing of mac failed. */
            VLOG_WARN("Parsing or router port mac failed for router port: %s, "
                    "with error: %s", rport_binding->logical_port, err_str);
            free(err_str);
            return;
        }
        ofpbuf_clear(ofpacts_p);
        match_init_catchall(&match);

        /* Add flow, which will match on conjunction id and will
         * replace source with router port mac */

        /* Match on ingress port, vlan_id and conjunction id */
        match_set_in_port(&match, ofport);
        match_set_conj_id(&match, CHASSIS_MAC_TO_ROUTER_MAC_CONJID);

        if (tag) {
            match_set_dl_vlan(&match, htons(tag), 0);
        } else {
            match_set_dl_tci_masked(&match, 0, htons(VLAN_CFI));
        }

        /* Actions */

        if (tag) {
            ofpact_put_STRIP_VLAN(ofpacts_p);
        }
        load_logical_ingress_metadata(localnet_port, &zone_ids, ofpacts_p);
        replace_mac = ofpact_put_SET_ETH_SRC(ofpacts_p);
        replace_mac->mac = router_port_mac;

        /* Resubmit to first logical ingress pipeline table. */
        put_resubmit(OFTABLE_LOG_INGRESS_PIPELINE, ofpacts_p);
        ofctrl_add_flow(flow_table, OFTABLE_PHY_TO_LOG, 180,
                        rport_binding->header_.uuid.parts[0],
                        &match, ofpacts_p, hc_uuid);

        /* Provide second search criteria, i.e localnet port's
         * vlan ID for conjunction flow */
        struct ofpact_conjunction *conj;
        ofpbuf_clear(ofpacts_p);
        match_init_catchall(&match);

        if (tag) {
            match_set_dl_vlan(&match, htons(tag), 0);
        } else {
            match_set_dl_tci_masked(&match, 0, htons(VLAN_CFI));
        }

        conj = ofpact_put_CONJUNCTION(ofpacts_p);
        conj->id = CHASSIS_MAC_TO_ROUTER_MAC_CONJID;
        conj->n_clauses = 2;
        conj->clause = 1;
        ofctrl_add_flow(flow_table, OFTABLE_PHY_TO_LOG, 180,
                        rport_binding->header_.uuid.parts[0],
                        &match, ofpacts_p, hc_uuid);
    }
}

#define VLAN_80211AD_ETHTYPE 0x88a8
#define VLAN_80211Q_ETHTYPE 0x8100

static void
ofpact_put_push_vlan(struct ofpbuf *ofpacts, const struct smap *options, int tag)
{
    const char *ethtype_opt = options ? smap_get(options, "ethtype") : NULL;

    int ethtype = VLAN_80211Q_ETHTYPE;
    if (ethtype_opt) {
        if (!strcasecmp(ethtype_opt, "802.11ad")) {
            ethtype = VLAN_80211AD_ETHTYPE;
        } else if (strcasecmp(ethtype_opt, "802.11q")) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Unknown port ethtype: %s", ethtype_opt);
        }
    }

    struct ofpact_push_vlan *push_vlan;
    push_vlan = ofpact_put_PUSH_VLAN(ofpacts);
    push_vlan->ethertype = htons(ethtype);

    struct ofpact_vlan_vid *vlan_vid;
    vlan_vid = ofpact_put_SET_VLAN_VID(ofpacts);
    vlan_vid->vlan_vid = tag;
    vlan_vid->push_vlan_if_needed = false;
}

static void
put_replace_router_port_mac_flows(struct ovsdb_idl_index
                                  *sbrec_port_binding_by_name,
                                  const struct
                                  sbrec_port_binding *localnet_port,
                                  const struct sbrec_chassis *chassis,
                                  const struct sset *active_tunnels,
                                  const struct hmap *local_datapaths,
                                  struct ofpbuf *ofpacts_p,
                                  ofp_port_t ofport,
                                  struct ovn_desired_flow_table *flow_table)
{
    struct local_datapath *ld = get_local_datapath(local_datapaths,
                                                   localnet_port->datapath->
                                                   tunnel_key);
    ovs_assert(ld);

    uint32_t dp_key = localnet_port->datapath->tunnel_key;
    uint32_t port_key = localnet_port->tunnel_key;
    int tag = localnet_port->tag ? *localnet_port->tag : 0;
    const char *network = smap_get(&localnet_port->options, "network_name");
    struct eth_addr chassis_mac;

    if (!network) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "Physical network not configured for datapath:"
                     "%"PRId64" with localnet port",
                     localnet_port->datapath->tunnel_key);
        return;
    }

    /* Get chassis mac */
    if (!chassis_get_mac(chassis, network, &chassis_mac)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        /* Keeping the log level low for backward compatibility.
         * Chassis mac is a new configuration.
         */
        VLOG_DBG_RL(&rl, "Could not get chassis mac for network: %s", network);
        return;
    }

    for (int i = 0; i < ld->n_peer_ports; i++) {
        const struct sbrec_port_binding *rport_binding =
            ld->peer_ports[i].remote;
        struct eth_addr router_port_mac;
        struct match match;
        struct ofpact_mac *replace_mac;
        char *cr_peer_name = xasprintf("cr-%s", rport_binding->logical_port);
        if (lport_is_chassis_resident(sbrec_port_binding_by_name,
                                      chassis, active_tunnels,
                                      cr_peer_name)) {
            /* If a router port's chassisredirect port is
             * resident on this chassis, then we need not do mac replace. */
            free(cr_peer_name);
            continue;
        }
        free(cr_peer_name);

        /* Table 65, priority 150.
         * =======================
         *
         * Implements output to localnet port.
         * a. Flow replaces ingress router port mac with a chassis mac.
         * b. Flow appends the vlan id localnet port is configured with.
         */
        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);

        ovs_assert(rport_binding->n_mac == 1);
        char *err_str = str_to_mac(rport_binding->mac[0], &router_port_mac);
        if (err_str) {
            /* Parsing of mac failed. */
            VLOG_WARN("Parsing or router port mac failed for router port: %s, "
                      "with error: %s", rport_binding->logical_port, err_str);
            free(err_str);
            return;
        }

        /* Replace Router mac flow */
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);
        match_set_dl_src(&match, router_port_mac);

        replace_mac = ofpact_put_SET_ETH_SRC(ofpacts_p);
        replace_mac->mac = chassis_mac;

        if (tag) {
            ofpact_put_push_vlan(ofpacts_p, &localnet_port->options, tag);
        }

        ofpact_put_OUTPUT(ofpacts_p)->port = ofport;

        ofctrl_add_flow(flow_table, OFTABLE_LOG_TO_PHY, 150,
                        localnet_port->header_.uuid.parts[0],
                        &match, ofpacts_p, &localnet_port->header_.uuid);
    }
}

static void
put_local_common_flows(uint32_t dp_key,
                       const struct sbrec_port_binding *pb,
                       const struct sbrec_port_binding *parent_pb,
                       const struct zone_ids *zone_ids,
                       struct ofpbuf *ofpacts_p,
                       struct ovn_desired_flow_table *flow_table)
{
    struct match match;

    uint32_t port_key = pb->tunnel_key;

    /* Table 38, priority 100.
     * =======================
     *
     * Implements output to local hypervisor.  Each flow matches a
     * logical output port on the local hypervisor, and resubmits to
     * table 39.
     */

    match_init_catchall(&match);
    ofpbuf_clear(ofpacts_p);

    /* Match MFF_LOG_DATAPATH, MFF_LOG_OUTPORT. */
    match_set_metadata(&match, htonll(dp_key));
    match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);

    if (zone_ids) {
        if (zone_ids->ct) {
            put_load(zone_ids->ct, MFF_LOG_CT_ZONE, 0, 32, ofpacts_p);
        }
        if (zone_ids->dnat) {
            put_load(zone_ids->dnat, MFF_LOG_DNAT_ZONE, 0, 32, ofpacts_p);
        }
        if (zone_ids->snat) {
            put_load(zone_ids->snat, MFF_LOG_SNAT_ZONE, 0, 32, ofpacts_p);
        }
    }

    /* Resubmit to table 39. */
    put_resubmit(OFTABLE_CHECK_LOOPBACK, ofpacts_p);
    ofctrl_add_flow(flow_table, OFTABLE_LOCAL_OUTPUT, 100,
                    pb->header_.uuid.parts[0], &match, ofpacts_p,
                    &pb->header_.uuid);

    /* Table 39, Priority 100.
     * =======================
     *
     * Drop packets whose logical inport and outport are the same
     * and the MLF_ALLOW_LOOPBACK flag is not set. */
    match_init_catchall(&match);
    ofpbuf_clear(ofpacts_p);
    match_set_metadata(&match, htonll(dp_key));
    match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                         0, MLF_ALLOW_LOOPBACK);
    match_set_reg(&match, MFF_LOG_INPORT - MFF_REG0, port_key);
    match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);
    ofctrl_add_flow(flow_table, OFTABLE_CHECK_LOOPBACK, 100,
                    pb->header_.uuid.parts[0], &match, ofpacts_p,
                    &pb->header_.uuid);

    /* Table 64, Priority 100.
     * =======================
     *
     * If the packet is supposed to hair-pin because the
     *   - "loopback" flag is set
     *   - or if the destination is a nested container
     *   - or if "nested_container" flag is set and the destination is the
     *     parent port,
     * temporarily set the in_port to OFPP_NONE, resubmit to
     * table 65 for logical-to-physical translation, then restore
     * the port number.
     *
     * If 'parent_pb' is not NULL, then the 'pb' represents a nested
     * container.
     *
     * Note:We can set in_port to 0 too. But if recirculation happens
     * later (eg. clone action to enter peer pipeline and a subsequent
     * ct action), ovs-vswitchd will drop the packet if the frozen metadata
     * in_port is 0.
     * */

    bool nested_container = parent_pb ? true: false;
    match_init_catchall(&match);
    ofpbuf_clear(ofpacts_p);
    match_set_metadata(&match, htonll(dp_key));
    match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);
    if (!nested_container) {
        match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                             MLF_ALLOW_LOOPBACK, MLF_ALLOW_LOOPBACK);
    }

    put_stack(MFF_IN_PORT, ofpact_put_STACK_PUSH(ofpacts_p));
    put_load(ofp_to_u16(OFPP_NONE), MFF_IN_PORT, 0, 16, ofpacts_p);
    put_resubmit(OFTABLE_LOG_TO_PHY, ofpacts_p);
    put_stack(MFF_IN_PORT, ofpact_put_STACK_POP(ofpacts_p));
    ofctrl_add_flow(flow_table, OFTABLE_SAVE_INPORT, 100,
                    pb->header_.uuid.parts[0], &match, ofpacts_p,
                    &pb->header_.uuid);

    if (nested_container) {
        /* It's a nested container and when the packet from the nested
         * container is to be sent to the parent port, "nested_container"
         * flag will be set. We need to temporarily set the in_port to
         * OFPP_NONE as mentioned in the comment above.
         *
         * If a parent port has multiple child ports, then this if condition
         * will be hit multiple times, but we want to add only one flow.
         * ofctrl_add_flow() logs a warning message for duplicate flows.
         * So use the function 'ofctrl_check_and_add_flow_metered' which
         * doesn't log a warning.
         *
         * Other option is to add this flow for all the ports which are not
         * nested containers. In which case we will add this flow for all the
         * ports even if they don't have any child ports which is
         * unnecessary.
         */
        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0,
                      parent_pb->tunnel_key);
        match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                             MLF_NESTED_CONTAINER, MLF_NESTED_CONTAINER);

        put_stack(MFF_IN_PORT, ofpact_put_STACK_PUSH(ofpacts_p));
        put_load(ofp_to_u16(OFPP_NONE), MFF_IN_PORT, 0, 16, ofpacts_p);
        put_resubmit(OFTABLE_LOG_TO_PHY, ofpacts_p);
        put_stack(MFF_IN_PORT, ofpact_put_STACK_POP(ofpacts_p));
        ofctrl_check_and_add_flow_metered(flow_table, OFTABLE_SAVE_INPORT, 100,
                                          0, &match, ofpacts_p, hc_uuid,
                                          NX_CTLR_NO_METER, false);
    }
}

static void
load_logical_ingress_metadata(const struct sbrec_port_binding *binding,
                              const struct zone_ids *zone_ids,
                              struct ofpbuf *ofpacts_p)
{
    if (zone_ids) {
        if (zone_ids->ct) {
            put_load(zone_ids->ct, MFF_LOG_CT_ZONE, 0, 32, ofpacts_p);
        }
        if (zone_ids->dnat) {
            put_load(zone_ids->dnat, MFF_LOG_DNAT_ZONE, 0, 32, ofpacts_p);
        }
        if (zone_ids->snat) {
            put_load(zone_ids->snat, MFF_LOG_SNAT_ZONE, 0, 32, ofpacts_p);
        }
    }

    /* Set MFF_LOG_DATAPATH and MFF_LOG_INPORT. */
    uint32_t dp_key = binding->datapath->tunnel_key;
    uint32_t port_key = binding->tunnel_key;
    put_load(dp_key, MFF_LOG_DATAPATH, 0, 64, ofpacts_p);
    put_load(port_key, MFF_LOG_INPORT, 0, 32, ofpacts_p);
}

static const struct sbrec_port_binding *
get_binding_peer(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                 const struct sbrec_port_binding *binding)
{
    const char *peer_name = smap_get(&binding->options, "peer");
    if (!peer_name) {
        return NULL;
    }

    const struct sbrec_port_binding *peer = lport_lookup_by_name(
        sbrec_port_binding_by_name, peer_name);
    if (!peer || strcmp(peer->type, binding->type)) {
        return NULL;
    }
    const char *peer_peer_name = smap_get(&peer->options, "peer");
    if (!peer_peer_name || strcmp(peer_peer_name, binding->logical_port)) {
        return NULL;
    }

    return peer;
}

static void
consider_port_binding(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                      enum mf_field_id mff_ovn_geneve,
                      const struct simap *ct_zones,
                      const struct sset *active_tunnels,
                      const struct hmap *local_datapaths,
                      const struct shash *local_bindings,
                      const struct simap *patch_ofports,
                      const struct hmap *chassis_tunnels,
                      const struct sbrec_port_binding *binding,
                      const struct sbrec_chassis *chassis,
                      struct ovn_desired_flow_table *flow_table,
                      struct ofpbuf *ofpacts_p)
{
    uint32_t dp_key = binding->datapath->tunnel_key;
    uint32_t port_key = binding->tunnel_key;
    struct local_datapath *ld;
    if (!(ld = get_local_datapath(local_datapaths, dp_key))) {
        return;
    }

    struct match match;
    if (!strcmp(binding->type, "patch")
        || (!strcmp(binding->type, "l3gateway")
            && binding->chassis == chassis)) {

        const struct sbrec_port_binding *peer = get_binding_peer(
                sbrec_port_binding_by_name, binding);
        if (!peer) {
            return;
        }

        struct zone_ids binding_zones = get_zone_ids(binding, ct_zones);
        put_local_common_flows(dp_key, binding, NULL, &binding_zones,
                               ofpacts_p, flow_table);

        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);

        size_t clone_ofs = ofpacts_p->size;
        struct ofpact_nest *clone = ofpact_put_CLONE(ofpacts_p);
        ofpact_put_CT_CLEAR(ofpacts_p);
        put_load(0, MFF_LOG_DNAT_ZONE, 0, 32, ofpacts_p);
        put_load(0, MFF_LOG_SNAT_ZONE, 0, 32, ofpacts_p);
        put_load(0, MFF_LOG_CT_ZONE, 0, 32, ofpacts_p);
        struct zone_ids peer_zones = get_zone_ids(peer, ct_zones);
        load_logical_ingress_metadata(peer, &peer_zones, ofpacts_p);
        put_load(0, MFF_LOG_FLAGS, 0, 32, ofpacts_p);
        put_load(0, MFF_LOG_OUTPORT, 0, 32, ofpacts_p);
        for (int i = 0; i < MFF_N_LOG_REGS; i++) {
            put_load(0, MFF_LOG_REG0 + i, 0, 32, ofpacts_p);
        }
        put_resubmit(OFTABLE_LOG_INGRESS_PIPELINE, ofpacts_p);
        clone = ofpbuf_at_assert(ofpacts_p, clone_ofs, sizeof *clone);
        ofpacts_p->header = clone;
        ofpact_finish_CLONE(ofpacts_p, &clone);

        ofctrl_add_flow(flow_table, OFTABLE_LOG_TO_PHY, 100,
                        binding->header_.uuid.parts[0],
                        &match, ofpacts_p, &binding->header_.uuid);
        return;
    }

    struct ha_chassis_ordered *ha_ch_ordered
        = ha_chassis_get_ordered(binding->ha_chassis_group);

    if (!strcmp(binding->type, "chassisredirect")
        && (binding->chassis == chassis
            || ha_chassis_group_is_active(binding->ha_chassis_group,
                                          active_tunnels, chassis))) {

        /* Table 38, priority 100.
         * =======================
         *
         * Implements output to local hypervisor.  Each flow matches a
         * logical output port on the local hypervisor, and resubmits to
         * table 39.  For ports of type "chassisredirect", the logical
         * output port is changed from the "chassisredirect" port to the
         * underlying distributed port. */

        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);

        const char *distributed_port = smap_get_def(&binding->options,
                                                    "distributed-port", "");
        const struct sbrec_port_binding *distributed_binding
            = lport_lookup_by_name(sbrec_port_binding_by_name,
                                   distributed_port);

        if (!distributed_binding) {
            /* Packet will be dropped. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "No port binding record for distributed "
                         "port %s referred by chassisredirect port %s",
                         distributed_port,
                         binding->logical_port);
        } else if (binding->datapath !=
                   distributed_binding->datapath) {
            /* Packet will be dropped. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl,
                         "chassisredirect port %s refers to "
                         "distributed port %s in wrong datapath",
                         binding->logical_port,
                         distributed_port);
        } else {
            put_load(distributed_binding->tunnel_key,
                     MFF_LOG_OUTPORT, 0, 32, ofpacts_p);

            struct zone_ids zone_ids = get_zone_ids(distributed_binding,
                                                    ct_zones);
            if (zone_ids.ct) {
                put_load(zone_ids.ct, MFF_LOG_CT_ZONE, 0, 32, ofpacts_p);
            }
            if (zone_ids.dnat) {
                put_load(zone_ids.dnat, MFF_LOG_DNAT_ZONE, 0, 32, ofpacts_p);
            }
            if (zone_ids.snat) {
                put_load(zone_ids.snat, MFF_LOG_SNAT_ZONE, 0, 32, ofpacts_p);
            }

            /* Resubmit to table 39. */
            put_resubmit(OFTABLE_CHECK_LOOPBACK, ofpacts_p);
        }

        ofctrl_add_flow(flow_table, OFTABLE_LOCAL_OUTPUT, 100,
                        binding->header_.uuid.parts[0],
                        &match, ofpacts_p, &binding->header_.uuid);

        goto out;
    }

    /* Find the OpenFlow port for the logical port, as 'ofport'.  This is
     * one of:
     *
     *     - If the port is a VIF on the chassis we're managing, the
     *       OpenFlow port for the VIF.  'tun' will be NULL.
     *
     *       The same logic handles ports that OVN implements as Open vSwitch
     *       patch ports, that is, "localnet" and "l2gateway" ports.
     *
     *       For a container nested inside a VM and accessible via a VLAN,
     *       'tag' is the VLAN ID; otherwise 'tag' is 0.
     *
     *       For a localnet or l2gateway patch port, if a VLAN ID was
     *       configured, 'tag' is set to that VLAN ID; otherwise 'tag' is 0.
     *
     *     - If the port is on a remote chassis, the OpenFlow port for a
     *       tunnel to the VIF's remote chassis.  'tun' identifies that
     *       tunnel.
     */

    int tag = 0;
    bool nested_container = false;
    const struct sbrec_port_binding *parent_port = NULL;
    ofp_port_t ofport;
    bool is_remote = false;
    if (binding->parent_port && *binding->parent_port) {
        if (!binding->tag) {
            goto out;
        }
        ofport = local_binding_get_lport_ofport(local_bindings,
                                                binding->parent_port);
        if (ofport) {
            tag = *binding->tag;
            nested_container = true;
            parent_port = lport_lookup_by_name(
                sbrec_port_binding_by_name, binding->parent_port);
        }
    } else if (!strcmp(binding->type, "localnet")
             || !strcmp(binding->type, "l2gateway")) {

        ofport = u16_to_ofp(simap_get(patch_ofports,
                                      binding->logical_port));
        if (ofport && binding->tag) {
            tag = *binding->tag;
        }
    } else {
        ofport = local_binding_get_lport_ofport(local_bindings,
                                                binding->logical_port);
        if (ofport && !lport_can_bind_on_this_chassis(chassis, binding)) {
            /* Even though there is an ofport for this port_binding, it is
             * requested on a different chassis. So ignore this ofport.
             */
            ofport = 0;
        }
    }

    bool is_ha_remote = false;
    const struct chassis_tunnel *tun = NULL;
    const struct sbrec_port_binding *localnet_port =
        get_localnet_port(local_datapaths, dp_key);
    if (!ofport) {
        /* It is remote port, may be reached by tunnel or localnet port */
        is_remote = true;
        if (localnet_port) {
            ofport = u16_to_ofp(simap_get(patch_ofports,
                                          localnet_port->logical_port));
            if (!ofport) {
                goto out;
            }
        } else {
            if (!ha_ch_ordered || ha_ch_ordered->n_ha_ch < 2) {
                /* It's on a single remote chassis */
                if (!binding->chassis) {
                    goto out;
                }
                tun = chassis_tunnel_find(chassis_tunnels,
                                          binding->chassis->name, NULL);
                if (!tun) {
                    goto out;
                }
                ofport = tun->ofport;
            } else {
                /* It's distributed across the chassis belonging to
                 * an HA chassis group. */
                is_ha_remote = true;
            }
        }
    }

    if (!is_remote) {
        /* Packets that arrive from a vif can belong to a VM or
         * to a container located inside that VM. Packets that
         * arrive from containers have a tag (vlan) associated with them.
         */

        struct zone_ids zone_ids = get_zone_ids(binding, ct_zones);
        /* Pass the parent port binding if the port is a nested
         * container. */
        put_local_common_flows(dp_key, binding, parent_port, &zone_ids,
                               ofpacts_p, flow_table);

        /* Table 0, Priority 150 and 100.
         * ==============================
         *
         * Priority 150 is for tagged traffic. This may be containers in a
         * VM or a VLAN on a local network. For such traffic, match on the
         * tags and then strip the tag.
         *
         * Priority 100 is for traffic belonging to VMs or untagged locally
         * connected networks.
         *
         * For both types of traffic: set MFF_LOG_INPORT to the logical
         * input port, MFF_LOG_DATAPATH to the logical datapath, and
         * resubmit into the logical ingress pipeline starting at table
         * 16. */
        ofpbuf_clear(ofpacts_p);
        match_init_catchall(&match);
        match_set_in_port(&match, ofport);

        /* Match a VLAN tag and strip it, including stripping priority tags
         * (e.g. VLAN ID 0).  In the latter case we'll add a second flow
         * for frames that lack any 802.1Q header later. */
        if (tag || !strcmp(binding->type, "localnet")
            || !strcmp(binding->type, "l2gateway")) {
            if (nested_container) {
                /* When a packet comes from a container sitting behind a
                 * parent_port, we should let it loopback to other containers
                 * or the parent_port itself. Indicate this by setting the
                 * MLF_NESTED_CONTAINER_BIT in MFF_LOG_FLAGS.*/
                put_load(1, MFF_LOG_FLAGS, MLF_NESTED_CONTAINER_BIT, 1,
                         ofpacts_p);
            }

            /* For vlan-passthru switch ports that are untagged, skip
             * matching/stripping VLAN header that originates from the VIF
             * itself. */
            bool passthru = smap_get_bool(&binding->options,
                                          "vlan-passthru", false);
            if (!passthru || tag) {
                match_set_dl_vlan(&match, htons(tag), 0);
                ofpact_put_STRIP_VLAN(ofpacts_p);
            }
        }

        /* Remember the size with just strip vlan added so far,
         * as we're going to remove this with ofpbuf_pull() later. */
        uint32_t ofpacts_orig_size = ofpacts_p->size;

        load_logical_ingress_metadata(binding, &zone_ids, ofpacts_p);

        if (!strcmp(binding->type, "localport")) {
            /* mark the packet as incoming from a localport */
            put_load(1, MFF_LOG_FLAGS, MLF_LOCALPORT_BIT, 1, ofpacts_p);
        }

        /* Resubmit to first logical ingress pipeline table. */
        put_resubmit(OFTABLE_LOG_INGRESS_PIPELINE, ofpacts_p);
        ofctrl_add_flow(flow_table, OFTABLE_PHY_TO_LOG,
                        tag ? 150 : 100, binding->header_.uuid.parts[0],
                        &match, ofpacts_p, &binding->header_.uuid);

        if (!tag && (!strcmp(binding->type, "localnet")
                     || !strcmp(binding->type, "l2gateway"))) {

            /* Add a second flow for frames that lack any 802.1Q
             * header.  For these, drop the OFPACT_STRIP_VLAN
             * action. */
            ofpbuf_pull(ofpacts_p, ofpacts_orig_size);
            match_set_dl_tci_masked(&match, 0, htons(VLAN_CFI));
            ofctrl_add_flow(flow_table, 0, 100,
                            binding->header_.uuid.parts[0], &match, ofpacts_p,
                            &binding->header_.uuid);
        }

        if (!strcmp(binding->type, "localnet")) {
            put_replace_chassis_mac_flows(ct_zones, binding, local_datapaths,
                                          ofpacts_p, ofport, flow_table);
        }

        /* Table 65, Priority 100.
         * =======================
         *
         * Deliver the packet to the local vif. */
        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);
        if (tag) {
            /* For containers sitting behind a local vif, tag the packets
             * before delivering them. */
            ofpact_put_push_vlan(
                ofpacts_p, localnet_port ? &localnet_port->options : NULL,
                tag);
        }
        ofpact_put_OUTPUT(ofpacts_p)->port = ofport;
        if (tag) {
            /* Revert the tag added to the packets headed to containers
             * in the previous step. If we don't do this, the packets
             * that are to be broadcasted to a VM in the same logical
             * switch will also contain the tag. */
            ofpact_put_STRIP_VLAN(ofpacts_p);
        }
        ofctrl_add_flow(flow_table, OFTABLE_LOG_TO_PHY, 100,
                        binding->header_.uuid.parts[0],
                        &match, ofpacts_p, &binding->header_.uuid);

        if (!strcmp(binding->type, "localnet")) {
            put_replace_router_port_mac_flows(sbrec_port_binding_by_name,
                                              binding, chassis, active_tunnels,
                                              local_datapaths, ofpacts_p,
                                              ofport, flow_table);
        }

        /* Table 39, priority 160.
         * =======================
         *
         * Do not forward local traffic from a localport to a localnet port.
         */
        if (!strcmp(binding->type, "localnet")) {
            /* do not forward traffic from localport to localnet port */
            match_init_catchall(&match);
            ofpbuf_clear(ofpacts_p);
            match_set_metadata(&match, htonll(dp_key));
            match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);
            match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                                 MLF_LOCALPORT, MLF_LOCALPORT);
            ofctrl_add_flow(flow_table, OFTABLE_CHECK_LOOPBACK, 160,
                            binding->header_.uuid.parts[0], &match,
                            ofpacts_p, &binding->header_.uuid);

            /* Drop LOCAL_ONLY traffic leaking through localnet ports. */
            match_init_catchall(&match);
            ofpbuf_clear(ofpacts_p);
            match_set_metadata(&match, htonll(dp_key));
            match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);
            match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                                 MLF_LOCAL_ONLY, MLF_LOCAL_ONLY);
            ofctrl_add_flow(flow_table, OFTABLE_CHECK_LOOPBACK, 160,
                            binding->header_.uuid.parts[0], &match,
                            ofpacts_p, &binding->header_.uuid);

            /* localport traffic directed to external is *not* local */
            struct shash_node *node;
            SHASH_FOR_EACH (node, &ld->external_ports) {
                const struct sbrec_port_binding *pb = node->data;

                /* skip ports that are not claimed by this chassis */
                if (!pb->chassis) {
                    continue;
                }
                if (strcmp(pb->chassis->name, chassis->name)) {
                    continue;
                }

                ofpbuf_clear(ofpacts_p);
                for (int i = 0; i < MFF_N_LOG_REGS; i++) {
                    put_load(0, MFF_REG0 + i, 0, 32, ofpacts_p);
                }
                put_resubmit(OFTABLE_LOG_EGRESS_PIPELINE, ofpacts_p);

                /* allow traffic directed to external MAC address */
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                for (int i = 0; i < pb->n_mac; i++) {
                    char *err_str;
                    struct eth_addr peer_mac;
                    if ((err_str = str_to_mac(pb->mac[i], &peer_mac))) {
                        VLOG_WARN_RL(
                            &rl, "Parsing MAC failed for external port: %s, "
                                 "with error: %s", pb->logical_port, err_str);
                        free(err_str);
                        continue;
                    }

                    match_init_catchall(&match);
                    match_set_metadata(&match, htonll(dp_key));
                    match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0,
                                  port_key);
                    match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                                         MLF_LOCALPORT, MLF_LOCALPORT);
                    match_set_dl_dst(&match, peer_mac);

                    ofctrl_add_flow(flow_table, OFTABLE_CHECK_LOOPBACK, 170,
                                    binding->header_.uuid.parts[0], &match,
                                    ofpacts_p, &binding->header_.uuid);
                }
            }
        }

    } else if (!tun && !is_ha_remote) {
        /* Remote port connected by localnet port */
        /* Table 38, priority 100.
         * =======================
         *
         * Implements switching to localnet port. Each flow matches a
         * logical output port on remote hypervisor, switch the output port
         * to connected localnet port and resubmits to same table.
         */

        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);

        /* Match MFF_LOG_DATAPATH, MFF_LOG_OUTPORT. */
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);

        put_load(localnet_port->tunnel_key, MFF_LOG_OUTPORT, 0, 32, ofpacts_p);

        /* Resubmit to table 38. */
        put_resubmit(OFTABLE_LOCAL_OUTPUT, ofpacts_p);
        ofctrl_add_flow(flow_table, OFTABLE_LOCAL_OUTPUT, 100,
                        binding->header_.uuid.parts[0],
                        &match, ofpacts_p, &binding->header_.uuid);
    } else {

        const char *redirect_type = smap_get(&binding->options,
                                             "redirect-type");

        /* Remote port connected by tunnel */

        /* Table 38, priority 100.
         * =======================
         *
         * Handles traffic that needs to be sent to a remote hypervisor.  Each
         * flow matches an output port that includes a logical port on a remote
         * hypervisor, and tunnels the packet to that hypervisor.
         */
        match_init_catchall(&match);
        ofpbuf_clear(ofpacts_p);

        /* Match MFF_LOG_DATAPATH, MFF_LOG_OUTPORT. */
        match_set_metadata(&match, htonll(dp_key));
        match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, port_key);

        if (redirect_type && !strcasecmp(redirect_type, "bridged")) {
            put_remote_port_redirect_bridged(binding, local_datapaths,
                                             ld, &match, ofpacts_p,
                                             flow_table);
        } else {
            put_remote_port_redirect_overlay(binding, is_ha_remote,
                                             ha_ch_ordered, mff_ovn_geneve,
                                             tun, port_key, &match, ofpacts_p,
                                             chassis_tunnels, flow_table);
        }
    }
out:
    if (ha_ch_ordered) {
        ha_chassis_destroy_ordered(ha_ch_ordered);
    }
}

static int64_t
get_vxlan_port_key(int64_t port_key)
{
    if (port_key >= OVN_MIN_MULTICAST) {
        /* 0b1<11 least significant bits> */
        return OVN_VXLAN_MIN_MULTICAST |
            (port_key & (OVN_VXLAN_MIN_MULTICAST - 1));
    }
    return port_key;
}

static void
fanout_to_chassis(enum mf_field_id mff_ovn_geneve,
                  struct sset *remote_chassis,
                  const struct hmap *chassis_tunnels,
                  const struct sbrec_datapath_binding *datapath,
                  uint16_t outport, bool is_ramp_switch,
                  struct ofpbuf *remote_ofpacts)
{
    const char *chassis_name;
    const struct chassis_tunnel *prev = NULL;
    SSET_FOR_EACH (chassis_name, remote_chassis) {
        const struct chassis_tunnel *tun
            = chassis_tunnel_find(chassis_tunnels, chassis_name, NULL);
        if (!tun) {
            continue;
        }

        if (!prev || tun->type != prev->type) {
            put_encapsulation(mff_ovn_geneve, tun, datapath,
                              outport, is_ramp_switch, remote_ofpacts);
            prev = tun;
        }
        ofpact_put_OUTPUT(remote_ofpacts)->port = tun->ofport;
    }
}

static void
consider_mc_group(struct ovsdb_idl_index *sbrec_port_binding_by_name,
                  enum mf_field_id mff_ovn_geneve,
                  const struct simap *ct_zones,
                  const struct hmap *local_datapaths,
                  struct shash *local_bindings,
                  struct simap *patch_ofports,
                  const struct sbrec_chassis *chassis,
                  const struct sbrec_multicast_group *mc,
                  const struct hmap *chassis_tunnels,
                  struct ovn_desired_flow_table *flow_table)
{
    uint32_t dp_key = mc->datapath->tunnel_key;
    if (!get_local_datapath(local_datapaths, dp_key)) {
        return;
    }

    struct sset remote_chassis = SSET_INITIALIZER(&remote_chassis);
    struct sset vtep_chassis = SSET_INITIALIZER(&vtep_chassis);
    struct match match;

    match_init_catchall(&match);
    match_set_metadata(&match, htonll(dp_key));
    match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, mc->tunnel_key);

    /* Go through all of the ports in the multicast group:
     *
     *    - For remote ports, add the chassis to 'remote_chassis' or
     *      'vtep_chassis'.
     *
     *    - For local ports (other than logical patch ports), add actions
     *      to 'ofpacts' to set the output port and resubmit.
     *
     *    - For logical patch ports, add actions to 'remote_ofpacts'
     *      instead.  (If we put them in 'ofpacts', then the output
     *      would happen on every hypervisor in the multicast group,
     *      effectively duplicating the packet.)
     *
     *    - For chassisredirect ports, add actions to 'ofpacts' to
     *      set the output port to be the router patch port for which
     *      the redirect port was added.
     */
    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 0);
    struct ofpbuf remote_ofpacts;
    ofpbuf_init(&remote_ofpacts, 0);
    for (size_t i = 0; i < mc->n_ports; i++) {
        struct sbrec_port_binding *port = mc->ports[i];

        if (port->datapath != mc->datapath) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, UUID_FMT": multicast group contains ports "
                         "in wrong datapath",
                         UUID_ARGS(&mc->header_.uuid));
            continue;
        }

        int zone_id = simap_get(ct_zones, port->logical_port);
        if (zone_id) {
            put_load(zone_id, MFF_LOG_CT_ZONE, 0, 32, &ofpacts);
        }

        const char *lport_name = (port->parent_port && *port->parent_port) ?
                                  port->parent_port : port->logical_port;

        if (!strcmp(port->type, "patch") || !strcmp(port->type, "localport")) {
            put_load(port->tunnel_key, MFF_LOG_OUTPORT, 0, 32,
                     &remote_ofpacts);
            put_resubmit(OFTABLE_CHECK_LOOPBACK, &remote_ofpacts);
        } else if (local_binding_get_primary_pb(local_bindings, lport_name)
                   || simap_contains(patch_ofports, port->logical_port)
                   || (!strcmp(port->type, "l3gateway")
                       && port->chassis == chassis)) {
            put_load(port->tunnel_key, MFF_LOG_OUTPORT, 0, 32, &ofpacts);
            put_resubmit(OFTABLE_CHECK_LOOPBACK, &ofpacts);
        } else if (!strcmp(port->type, "chassisredirect")
                   && port->chassis == chassis) {
            const char *distributed_port = smap_get(&port->options,
                                                    "distributed-port");
            if (distributed_port) {
                const struct sbrec_port_binding *distributed_binding
                    = lport_lookup_by_name(sbrec_port_binding_by_name,
                                           distributed_port);
                if (distributed_binding
                    && port->datapath == distributed_binding->datapath) {
                    put_load(distributed_binding->tunnel_key, MFF_LOG_OUTPORT,
                             0, 32, &ofpacts);
                    put_resubmit(OFTABLE_CHECK_LOOPBACK, &ofpacts);
                }
            }
        } else if (port->chassis && !get_localnet_port(
                local_datapaths, mc->datapath->tunnel_key)) {
            /* Add remote chassis only when localnet port not exist,
             * otherwise multicast will reach remote ports through localnet
             * port. */
            if (smap_get_bool(&port->chassis->other_config,
                              "is-vtep", false)) {
                sset_add(&vtep_chassis, port->chassis->name);
            } else {
                sset_add(&remote_chassis, port->chassis->name);
            }
        }
    }

    /* Table 38, priority 100.
     * =======================
     *
     * Handle output to the local logical ports in the multicast group, if
     * any. */
    bool local_ports = ofpacts.size > 0;
    if (local_ports) {
        /* Following delivery to local logical ports, restore the multicast
         * group as the logical output port. */
        put_load(mc->tunnel_key, MFF_LOG_OUTPORT, 0, 32, &ofpacts);

        ofctrl_add_flow(flow_table, OFTABLE_LOCAL_OUTPUT, 100,
                        mc->header_.uuid.parts[0],
                        &match, &ofpacts, &mc->header_.uuid);
    }

    /* Table 37, priority 100.
     * =======================
     *
     * Handle output to the remote chassis in the multicast group, if
     * any. */
    if (!sset_is_empty(&remote_chassis) ||
            !sset_is_empty(&vtep_chassis) || remote_ofpacts.size > 0) {
        if (remote_ofpacts.size > 0) {
            /* Following delivery to logical patch ports, restore the
             * multicast group as the logical output port. */
            put_load(mc->tunnel_key, MFF_LOG_OUTPORT, 0, 32,
                     &remote_ofpacts);
        }

        fanout_to_chassis(mff_ovn_geneve, &remote_chassis, chassis_tunnels,
                          mc->datapath, mc->tunnel_key, false,
                          &remote_ofpacts);
        fanout_to_chassis(mff_ovn_geneve, &vtep_chassis, chassis_tunnels,
                          mc->datapath, mc->tunnel_key, true,
                          &remote_ofpacts);

        if (remote_ofpacts.size) {
            if (local_ports) {
                put_resubmit(OFTABLE_LOCAL_OUTPUT, &remote_ofpacts);
            }
            ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 100,
                            mc->header_.uuid.parts[0],
                            &match, &remote_ofpacts, &mc->header_.uuid);
        }
    }
    ofpbuf_uninit(&ofpacts);
    ofpbuf_uninit(&remote_ofpacts);
    sset_destroy(&remote_chassis);
    sset_destroy(&vtep_chassis);
}

bool
physical_handle_flows_for_lport(const struct sbrec_port_binding *pb,
                                bool removed, struct physical_ctx *p_ctx,
                                struct ovn_desired_flow_table *flow_table)
{
    if (!strcmp(pb->type, "vtep")) {
        /* Cannot handle changes to vtep lports (yet). */
        return false;
    }

    ofctrl_remove_flows(flow_table, &pb->header_.uuid);

    if (!strcmp(pb->type, "external")) {
        /* External lports have a dependency on the localnet port.
         * We need to remove the flows of the localnet port as well
         * and re-consider adding the flows for it.
         */
        struct local_datapath *ldp =
            get_local_datapath(p_ctx->local_datapaths,
                               pb->datapath->tunnel_key);
        if (ldp && ldp->localnet_port) {
            struct ofpbuf ofpacts;
            ofctrl_remove_flows(flow_table, &ldp->localnet_port->header_.uuid);
            ofpbuf_init(&ofpacts, 0);
            consider_port_binding(p_ctx->sbrec_port_binding_by_name,
                                  p_ctx->mff_ovn_geneve, p_ctx->ct_zones,
                                  p_ctx->active_tunnels,
                                  p_ctx->local_datapaths,
                                  p_ctx->local_bindings,
                                  p_ctx->patch_ofports,
                                  p_ctx->chassis_tunnels,
                                  ldp->localnet_port, p_ctx->chassis,
                                  flow_table, &ofpacts);
            ofpbuf_uninit(&ofpacts);
        }
    }

    if (!removed) {
        struct ofpbuf ofpacts;
        ofpbuf_init(&ofpacts, 0);
        consider_port_binding(p_ctx->sbrec_port_binding_by_name,
                              p_ctx->mff_ovn_geneve, p_ctx->ct_zones,
                              p_ctx->active_tunnels, p_ctx->local_datapaths,
                              p_ctx->local_bindings,
                              p_ctx->patch_ofports,
                              p_ctx->chassis_tunnels, pb,
                              p_ctx->chassis, flow_table, &ofpacts);
        ofpbuf_uninit(&ofpacts);
    }

    return true;
}

void
physical_handle_mc_group_changes(struct physical_ctx *p_ctx,
                                 struct ovn_desired_flow_table *flow_table)
{
    const struct sbrec_multicast_group *mc;
    SBREC_MULTICAST_GROUP_TABLE_FOR_EACH_TRACKED (mc, p_ctx->mc_group_table) {
        if (sbrec_multicast_group_is_deleted(mc)) {
            ofctrl_remove_flows(flow_table, &mc->header_.uuid);
        } else {
            if (!sbrec_multicast_group_is_new(mc)) {
                ofctrl_remove_flows(flow_table, &mc->header_.uuid);
            }
            consider_mc_group(p_ctx->sbrec_port_binding_by_name,
                              p_ctx->mff_ovn_geneve, p_ctx->ct_zones,
                              p_ctx->local_datapaths, p_ctx->local_bindings,
                              p_ctx->patch_ofports,
                              p_ctx->chassis, mc,
                              p_ctx->chassis_tunnels,
                              flow_table);
        }
    }
}

void
physical_run(struct physical_ctx *p_ctx,
             struct ovn_desired_flow_table *flow_table)
{
    COVERAGE_INC(physical_run);

    if (!hc_uuid) {
        hc_uuid = xmalloc(sizeof(struct uuid));
        uuid_generate(hc_uuid);
    }

    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 0);

    put_chassis_mac_conj_id_flow(p_ctx->chassis_table, p_ctx->chassis,
                                 &ofpacts, flow_table);

    /* Set up flows in table 0 for physical-to-logical translation and in table
     * 64 for logical-to-physical translation. */
    const struct sbrec_port_binding *binding;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (binding, p_ctx->port_binding_table) {
        consider_port_binding(p_ctx->sbrec_port_binding_by_name,
                              p_ctx->mff_ovn_geneve, p_ctx->ct_zones,
                              p_ctx->active_tunnels, p_ctx->local_datapaths,
                              p_ctx->local_bindings,
                              p_ctx->patch_ofports,
                              p_ctx->chassis_tunnels, binding,
                              p_ctx->chassis, flow_table, &ofpacts);
    }

    /* Handle output to multicast groups, in tables 37 and 38. */
    const struct sbrec_multicast_group *mc;
    SBREC_MULTICAST_GROUP_TABLE_FOR_EACH (mc, p_ctx->mc_group_table) {
        consider_mc_group(p_ctx->sbrec_port_binding_by_name,
                          p_ctx->mff_ovn_geneve, p_ctx->ct_zones,
                          p_ctx->local_datapaths, p_ctx->local_bindings,
                          p_ctx->patch_ofports, p_ctx->chassis,
                          mc, p_ctx->chassis_tunnels,
                          flow_table);
    }

    /* Table 0, priority 100.
     * ======================
     *
     * Process packets that arrive from a remote hypervisor (by matching
     * on tunnel in_port). */

    /* Add flows for Geneve, STT and VXLAN encapsulations.  Geneve and STT
     * encapsulations have metadata about the ingress and egress logical ports.
     * VXLAN encapsulations have metadata about the egress logical port only.
     * We set MFF_LOG_DATAPATH, MFF_LOG_INPORT, and MFF_LOG_OUTPORT from the
     * tunnel key data where possible, then resubmit to table 38 to handle
     * packets to the local hypervisor. */
    struct chassis_tunnel *tun;
    HMAP_FOR_EACH (tun, hmap_node, p_ctx->chassis_tunnels) {
        struct match match = MATCH_CATCHALL_INITIALIZER;
        match_set_in_port(&match, tun->ofport);

        ofpbuf_clear(&ofpacts);
        if (tun->type == GENEVE) {
            put_move(MFF_TUN_ID, 0,  MFF_LOG_DATAPATH, 0, 24, &ofpacts);
            put_move(p_ctx->mff_ovn_geneve, 16, MFF_LOG_INPORT, 0, 15,
                     &ofpacts);
            put_move(p_ctx->mff_ovn_geneve, 0, MFF_LOG_OUTPORT, 0, 16,
                     &ofpacts);
        } else if (tun->type == STT) {
            put_move(MFF_TUN_ID, 40, MFF_LOG_INPORT,   0, 15, &ofpacts);
            put_move(MFF_TUN_ID, 24, MFF_LOG_OUTPORT,  0, 16, &ofpacts);
            put_move(MFF_TUN_ID,  0, MFF_LOG_DATAPATH, 0, 24, &ofpacts);
        } else if (tun->type == VXLAN) {
            /* Add flows for non-VTEP tunnels. Split VNI into two 12-bit
             * sections and use them for datapath and outport IDs. */
            put_move(MFF_TUN_ID, 12, MFF_LOG_OUTPORT,  0, 12, &ofpacts);
            put_move(MFF_TUN_ID, 0, MFF_LOG_DATAPATH, 0, 12, &ofpacts);
        } else {
            OVS_NOT_REACHED();
        }

        put_resubmit(OFTABLE_LOCAL_OUTPUT, &ofpacts);

        ofctrl_add_flow(flow_table, OFTABLE_PHY_TO_LOG, 100, 0, &match,
                        &ofpacts, hc_uuid);
    }

    /* Add VXLAN specific rules to transform port keys
     * from 12 bits to 16 bits used elsewhere. */
    HMAP_FOR_EACH (tun, hmap_node, p_ctx->chassis_tunnels) {
        if (tun->type == VXLAN) {
            ofpbuf_clear(&ofpacts);

            struct match match = MATCH_CATCHALL_INITIALIZER;
            match_set_in_port(&match, tun->ofport);
            ovs_be64 mcast_bits = htonll((OVN_VXLAN_MIN_MULTICAST << 12));
            match_set_tun_id_masked(&match, mcast_bits, mcast_bits);

            put_load(1, MFF_LOG_OUTPORT, 15, 1, &ofpacts);
            put_move(MFF_TUN_ID, 12, MFF_LOG_OUTPORT,  0, 11, &ofpacts);
            put_move(MFF_TUN_ID, 0, MFF_LOG_DATAPATH, 0, 12, &ofpacts);
            put_resubmit(OFTABLE_LOCAL_OUTPUT, &ofpacts);

            ofctrl_add_flow(flow_table, OFTABLE_PHY_TO_LOG, 105, 0,
                            &match, &ofpacts, hc_uuid);
        }
    }

    /* Handle ramp switch encapsulations. */
    HMAP_FOR_EACH (tun, hmap_node, p_ctx->chassis_tunnels) {
        if (tun->type != VXLAN) {
            continue;
        }

        SBREC_PORT_BINDING_TABLE_FOR_EACH (binding,
                                           p_ctx->port_binding_table) {
            if (strcmp(binding->type, "vtep")) {
                continue;
            }

            if (!binding->chassis ||
                !encaps_tunnel_id_match(tun->chassis_id,
                                        binding->chassis->name, NULL)) {
                continue;
            }

            struct match match = MATCH_CATCHALL_INITIALIZER;
            match_set_in_port(&match, tun->ofport);
            ofpbuf_clear(&ofpacts);

            /* Add flows for ramp switches.  The VNI is used to populate
             * MFF_LOG_DATAPATH.  The gateway's logical port is set to
             * MFF_LOG_INPORT.  Then the packet is resubmitted to table 8
             * to determine the logical egress port. */
            match_set_tun_id(&match, htonll(binding->datapath->tunnel_key));

            put_move(MFF_TUN_ID, 0,  MFF_LOG_DATAPATH, 0, 24, &ofpacts);
            put_load(binding->tunnel_key, MFF_LOG_INPORT, 0, 15, &ofpacts);
            /* For packets received from a ramp tunnel, set a flag to that
             * effect. */
            put_load(1, MFF_LOG_FLAGS, MLF_RCV_FROM_RAMP_BIT, 1, &ofpacts);
            put_resubmit(OFTABLE_LOG_INGRESS_PIPELINE, &ofpacts);

            ofctrl_add_flow(flow_table, OFTABLE_PHY_TO_LOG, 110,
                            binding->header_.uuid.parts[0],
                            &match, &ofpacts, hc_uuid);
        }
    }

    /* Table 37, priority 150.
     * =======================
     *
     * Handles packets received from a VXLAN tunnel which get resubmitted to
     * OFTABLE_LOG_INGRESS_PIPELINE due to lack of needed metadata in VXLAN,
     * explicitly skip sending back out any tunnels and resubmit to table 38
     * for local delivery.
     */
    struct match match;
    match_init_catchall(&match);
    match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                         MLF_RCV_FROM_RAMP, MLF_RCV_FROM_RAMP);

    /* Resubmit to table 38. */
    ofpbuf_clear(&ofpacts);
    put_resubmit(OFTABLE_LOCAL_OUTPUT, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 150, 0,
                    &match, &ofpacts, hc_uuid);

    /* Table 37, priority 150.
     * =======================
     *
     * Packets that should not be sent to other hypervisors.
     */
    match_init_catchall(&match);
    match_set_reg_masked(&match, MFF_LOG_FLAGS - MFF_REG0,
                         MLF_LOCAL_ONLY, MLF_LOCAL_ONLY);
    /* Resubmit to table 38. */
    ofpbuf_clear(&ofpacts);
    put_resubmit(OFTABLE_LOCAL_OUTPUT, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 150, 0,
                    &match, &ofpacts, hc_uuid);

    /* Table 37, priority 150.
     * =======================
     *
     * Handles packets received from ports of type "localport".  These ports
     * are present on every hypervisor.  Traffic that originates at one should
     * never go over a tunnel to a remote hypervisor, so resubmit them to table
     * 38 for local delivery. */
    match_init_catchall(&match);
    ofpbuf_clear(&ofpacts);
    put_resubmit(OFTABLE_LOCAL_OUTPUT, &ofpacts);
    const char *localport;
    SSET_FOR_EACH (localport, p_ctx->local_lports) {
        /* Iterate over all local logical ports and insert a drop
         * rule with higher priority for every localport in this
         * datapath. */
        const struct sbrec_port_binding *pb = lport_lookup_by_name(
            p_ctx->sbrec_port_binding_by_name, localport);
        if (pb && !strcmp(pb->type, "localport")) {
            match_set_reg(&match, MFF_LOG_INPORT - MFF_REG0, pb->tunnel_key);
            match_set_metadata(&match, htonll(pb->datapath->tunnel_key));
            ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 150,
                            pb->header_.uuid.parts[0],
                            &match, &ofpacts, hc_uuid);
        }
    }

    /* Table 37, Priority 0.
     * =======================
     *
     * Resubmit packets that are not directed at tunnels or part of a
     * multicast group to the local output table. */
    match_init_catchall(&match);
    ofpbuf_clear(&ofpacts);
    put_resubmit(OFTABLE_LOCAL_OUTPUT, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_REMOTE_OUTPUT, 0, 0, &match,
                    &ofpacts, hc_uuid);

    /* Table 39, Priority 0.
     * =======================
     *
     * Resubmit packets that don't output to the ingress port (already checked
     * in table 38) to the logical egress pipeline, clearing the logical
     * registers (for consistent behavior with packets that get tunneled). */
    match_init_catchall(&match);
    ofpbuf_clear(&ofpacts);
    for (int i = 0; i < MFF_N_LOG_REGS; i++) {
        put_load(0, MFF_REG0 + i, 0, 32, &ofpacts);
    }
    put_resubmit(OFTABLE_LOG_EGRESS_PIPELINE, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_CHECK_LOOPBACK, 0, 0, &match,
                    &ofpacts, hc_uuid);

    /* Table 64, Priority 0.
     * =======================
     *
     * Resubmit packets that do not have the MLF_ALLOW_LOOPBACK flag set
     * to table 65 for logical-to-physical translation. */
    match_init_catchall(&match);
    ofpbuf_clear(&ofpacts);
    put_resubmit(OFTABLE_LOG_TO_PHY, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_SAVE_INPORT, 0, 0, &match,
                    &ofpacts, hc_uuid);

    ofpbuf_uninit(&ofpacts);
}
