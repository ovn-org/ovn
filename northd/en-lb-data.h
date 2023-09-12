#ifndef EN_NORTHD_LB_DATA_H
#define EN_NORTHD_LB_DATA_H 1

#include <config.h>

#include "openvswitch/hmap.h"
#include "include/openvswitch/list.h"
#include "lib/hmapx.h"

#include "lib/inc-proc-eng.h"

struct ovn_northd_lb;
struct ovn_lb_group;

struct crupdated_lb {
    struct hmap_node hmap_node;

    struct ovn_northd_lb *lb;
};

struct crupdated_lbgrp {
    struct hmap_node hmap_node;

    struct ovn_lb_group *lbgrp;
    /* hmapx of newly associated lbs to this lb group.
     * hmapx node is 'struct ovn_northd_lb *' */
    struct hmapx assoc_lbs;
};

struct tracked_lb_data {
    /* Both created and updated lbs. hmapx node is 'struct crupdated_lb *'. */
    struct hmap crupdated_lbs;

    /* Deleted lbs. */
    struct hmapx deleted_lbs;

    /* Both created and updated lb_groups. hmap node is
     * 'struct crupdated_lbgrp'. */
    struct hmap crupdated_lbgrps;

    /* Deleted lb_groups. hmapx node is  'struct ovn_lb_group *'. */
    struct hmapx deleted_lbgrps;

    /* Indicates if any of the tracked lb has health checks enabled. */
    bool has_health_checks;

    /* Indicates if any lb got disassociated from a lb group
     * but not deleted. */
    bool has_dissassoc_lbs_from_lbgrps;
};

/* struct which maintains the data of the engine node lb_data. */
struct ed_type_lb_data {
    /* hmap of load balancers.  hmap node is 'struct ovn_northd_lb *' */
    struct hmap lbs;

    /* hmap of load balancer groups.  hmap node is 'struct ovn_lb_group *' */
    struct hmap lbgrps;

    /* tracked data*/
    bool tracked;
    struct tracked_lb_data tracked_lb_data;
};

void *en_lb_data_init(struct engine_node *, struct engine_arg *);
void en_lb_data_run(struct engine_node *, void *data);
void en_lb_data_cleanup(void *data);
void en_lb_data_clear_tracked_data(void *data);

bool lb_data_load_balancer_handler(struct engine_node *, void *data);
bool lb_data_load_balancer_group_handler(struct engine_node *, void *data);

#endif /* end of EN_NORTHD_LB_DATA_H */
