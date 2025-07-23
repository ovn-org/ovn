#ifndef EN_RUNTIME_DATA_H
#define EN_RUNTIME_DATA_H 1

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

/* OVS includes. */
#include "lib/simap.h"
#include "include/openvswitch/shash.h"
#include "lib/uuid.h"

/* OVN includes. */
#include "lib/inc-proc-eng.h"

struct ovnbrrec_bridge;
struct ovsrec_bridge;

struct ovn_bridge {
    struct uuid key; /* ovnbrrec_bridge->header_.uuid */

    const struct ovnbrrec_bridge *db_br;
    const struct ovsrec_bridge *ovs_br;

    /* simap of ovs interface names to ofport numbers. */
    struct simap ovs_ifaces;
};

struct ed_type_bridge_data {
    struct shash bridges;
};

enum engine_node_state en_bridge_data_run(struct engine_node *, void *data);
void *en_bridge_data_init(struct engine_node *node, struct engine_arg *arg);
void en_bridge_data_cleanup(void *data);

#endif /* EN_RUNTIME_DATA_H */
