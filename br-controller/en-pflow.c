/*
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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

/* OVS includes. */
#include "lib/coverage.h"
#include "lib/flow.h"
#include "lib/simap.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/ofp-parse.h"

#include "openvswitch/vlog.h"
#include "openvswitch/uuid.h"

/* OVN includes. */
#include "br-flow-mgr.h"
#include "en-lflow.h"
#include "en-pflow.h"
#include "en-bridge-data.h"
#include "include/ovn/logical-fields.h"
#include "lib/ovn-br-idl.h"

VLOG_DEFINE_THIS_MODULE(en_pflow);


static void pflow_run(const struct shash *ovn_bridges);
static void physical_flows_add(const struct ovn_bridge *);

static void put_load(uint64_t value, enum mf_field_id dst, int ofs, int n_bits,
                     struct ofpbuf *);
static void put_resubmit(uint8_t table_id, struct ofpbuf *);
static void put_stack(enum mf_field_id, struct ofpact_stack *);

static void add_interface_flows(const char *bridge,
                                const struct ovsrec_interface *iface_rec,
                                int64_t, struct ofpbuf *);

/* Public functions. */
void *en_pflow_output_init(struct engine_node *node OVS_UNUSED,
                           struct engine_arg *arg OVS_UNUSED)
{
    return NULL;
}

void en_pflow_output_cleanup(void *data_ OVS_UNUSED)
{
}

enum engine_node_state
en_pflow_output_run(struct engine_node *node, void *data_  OVS_UNUSED)
{
    struct ed_type_bridge_data *br_data =
        engine_get_input_data("bridge_data", node);

    pflow_run(&br_data->bridges);

    return EN_UPDATED;
}

/* Static functions. */
static void
pflow_run(const struct shash *ovn_bridges)
{
    br_flow_switch_physical_oflow_tables();
    struct shash_node *shash_node;
    SHASH_FOR_EACH (shash_node, ovn_bridges) {
        physical_flows_add(shash_node->data);
    }
}

static void
physical_flows_add(const struct ovn_bridge *br)
{
    if (!br->ovs_br) {
        return;
    }

    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 0);

    struct match match = MATCH_CATCHALL_INITIALIZER;

    /* Table 0 and 121, priority 0, actions=NORMAL
     * ===================================
     *
     */
    ofpact_put_OUTPUT(&ofpacts)->port = OFPP_NORMAL;
    br_flow_add_physical_oflow(br->db_br->name, BR_OFTABLE_PHY_TO_LOG, 0,
                               br->ovs_br->header_.uuid.parts[0],
                               &match, &ofpacts, &br->ovs_br->header_.uuid);
    br_flow_add_physical_oflow(br->db_br->name, BR_OFTABLE_LOG_TO_PHY, 0,
                               br->ovs_br->header_.uuid.parts[0],
                               &match, &ofpacts, &br->ovs_br->header_.uuid);

    /* Priority-0 action to advance the packet from table 120 to 121. */
    ofpbuf_clear(&ofpacts);
    put_resubmit(BR_OFTABLE_LOG_TO_PHY, &ofpacts);
    br_flow_add_physical_oflow(br->db_br->name, BR_OFTABLE_SAVE_INPORT, 0,
                               br->ovs_br->header_.uuid.parts[0],
                               &match, &ofpacts, &br->ovs_br->header_.uuid);

    for (size_t i = 0; i < br->ovs_br->n_ports; i++) {
        const struct ovsrec_port *port_rec = br->ovs_br->ports[i];

        for (size_t j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;

            iface_rec = port_rec->interfaces[j];
            int64_t ofport = iface_rec->n_ofport ? *iface_rec->ofport : 0;
            if (ofport > 0 && ofport != ofp_to_u16(OFPP_LOCAL) &&
                smap_get_bool(&iface_rec->external_ids,
                              "ovnbr-managed", true)) {
                add_interface_flows(br->db_br->name, iface_rec,
                                    ofport, &ofpacts);
            }
        }
    }

    ofpbuf_uninit(&ofpacts);
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
put_resubmit(uint8_t table_id, struct ofpbuf *ofpacts)
{
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(ofpacts);
    resubmit->in_port = OFPP_IN_PORT;
    resubmit->table_id = table_id;
}

static void
put_stack(enum mf_field_id field, struct ofpact_stack *stack)
{
    stack->subfield.field = mf_from_id(field);
    stack->subfield.ofs = 0;
    stack->subfield.n_bits = stack->subfield.field->n_bits;
}

static void
add_interface_flows(const char *bridge,
                    const struct ovsrec_interface *iface_rec,
                    int64_t ofport, struct ofpbuf *ofpacts_p)
{
    struct match match = MATCH_CATCHALL_INITIALIZER;
    match_set_in_port(&match, u16_to_ofp(ofport));

    ofpbuf_clear(ofpacts_p);
    put_load(ofport, MFF_LOG_INPORT, 0, 32, ofpacts_p);

    uint32_t iface_metadata =
        smap_get_uint(&iface_rec->external_ids, "ovn-iface-metadata", 0);
    if (iface_metadata) {
        put_load(iface_metadata, MFF_METADATA, 0, 32, ofpacts_p);
    }

    put_resubmit(BR_OFTABLE_LOG_INGRESS_PIPELINE, ofpacts_p);
    br_flow_add_physical_oflow(bridge, BR_OFTABLE_PHY_TO_LOG, 100,
                               iface_rec->header_.uuid.parts[0],
                               &match, ofpacts_p,
                               &iface_rec->header_.uuid);


    match_init_catchall(&match);
    match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, ofport);

    ofpbuf_clear(ofpacts_p);
    ofpact_put_OUTPUT(ofpacts_p)->port = u16_to_ofp(ofport);
    br_flow_add_physical_oflow(bridge, BR_OFTABLE_LOG_TO_PHY, 100,
                               iface_rec->header_.uuid.parts[0],
                               &match, ofpacts_p,
                               &iface_rec->header_.uuid);

    /* Priority-100 flow in table BR_OFTABLE_SAVE_INPORT to match on
     * both inport and outport to the interface's ofport number and
     * clear the in_port to OFPP_NONE before advancing the packet to
     * the next table - BR_OFTABLE_LOG_TO_PHY.
     * This is requires for the hairpinned packets.
     */
    match_init_catchall(&match);
    match_set_reg(&match, MFF_LOG_INPORT - MFF_REG0, ofport);
    match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, ofport);

    ofpbuf_clear(ofpacts_p);
    put_stack(MFF_IN_PORT, ofpact_put_STACK_PUSH(ofpacts_p));
    put_load(ofp_to_u16(OFPP_NONE), MFF_IN_PORT, 0, 16, ofpacts_p);
    put_resubmit(BR_OFTABLE_LOG_TO_PHY, ofpacts_p);
    put_stack(MFF_IN_PORT, ofpact_put_STACK_POP(ofpacts_p));
    br_flow_add_physical_oflow(bridge, BR_OFTABLE_SAVE_INPORT, 100,
                               iface_rec->header_.uuid.parts[0],
                               &match, ofpacts_p, &iface_rec->header_.uuid);
}
