#ifndef EN_NORTHD_LB_DATA_H
#define EN_NORTHD_LB_DATA_H 1

#include <config.h>

#include "openvswitch/hmap.h"

#include "lib/inc-proc-eng.h"

/* struct which maintains the data of the engine node lb_data. */
struct ed_type_lb_data {
    /* hmap of load balancers.  hmap node is 'struct ovn_northd_lb *' */
    struct hmap lbs;

    /* hmap of load balancer groups.  hmap node is 'struct ovn_lb_group *' */
    struct hmap lb_groups;
};

void *en_lb_data_init(struct engine_node *, struct engine_arg *);
void en_lb_data_run(struct engine_node *, void *data);
void en_lb_data_cleanup(void *data);

#endif /* end of EN_NORTHD_LB_DATA_H */
