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

#ifndef EN_IC_DP_ENUM_H
#define EN_IC_DP_ENUM_H 1

#include "lib/inc-proc-eng.h"
#include "openvswitch/hmap.h"
#include "openvswitch/shash.h"

/* Data maintained by the "dp_enum" engine node: the result of enumerating the
 * IC-SB datapath bindings.  It is the explicit, engine-visible form of the
 * state that used to be built on the stack by enumerate_datapaths() inside
 * ovn_db_run().  The transit-switch (en_ts) and transit-router (en_tr) nodes
 * consume this data instead of rebuilding it themselves, which also keeps the
 * shared 'dp_tnlids' tunnel-key allocator consistent between them. */
struct ed_type_dp_enum {
    /* Set of tunnel keys already in use by IC-SB datapath bindings.  Holds
     * 'struct tnlid_node *' entries owned by this node. */
    struct hmap dp_tnlids;
    /* Transit-switch datapath bindings, keyed by transit switch name.  Values
     * are 'const struct icsbrec_datapath_binding *' owned by the IDL. */
    struct shash isb_ts_dps;
    /* Transit-router datapath bindings, keyed by NB IC UUID string.  Values
     * are 'const struct icsbrec_datapath_binding *' owned by the IDL. */
    struct shash isb_tr_dps;
};

enum engine_node_state en_dp_enum_run(struct engine_node *node, void *data);
void *en_dp_enum_init(struct engine_node *node, struct engine_arg *arg);
void en_dp_enum_cleanup(void *data);

#endif /* EN_IC_DP_ENUM_H */
