#ifndef EN_NORTHD_LB_DATA_H
#define EN_NORTHD_LB_DATA_H 1

#include <config.h>

#include "openvswitch/hmap.h"
#include "include/openvswitch/list.h"
#include "lib/hmapx.h"
#include "lib/sset.h"
#include "lib/uuidset.h"

#include "lib/inc-proc-eng.h"

struct ovn_northd_lb;
struct ovn_lb_group;

struct crupdated_lb {
    struct hmap_node hmap_node;

    struct ovn_northd_lb *lb;
    struct sset inserted_vips_v4;
    struct sset inserted_vips_v6;
    struct sset deleted_vips_v4;
    struct sset deleted_vips_v6;
};

struct crupdated_lbgrp {
    struct hmap_node hmap_node;

    struct ovn_lb_group *lbgrp;
    /* hmapx of newly associated lbs to this lb group.
     * hmapx node is 'struct ovn_northd_lb *' */
    struct hmapx assoc_lbs;
};

struct crupdated_od_lb_data {
    struct ovs_list list_node;

    struct uuid od_uuid;
    struct uuidset assoc_lbs;
    struct uuidset assoc_lbgrps;
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

    /* List of logical switch <-> lb changes. List node is
     * 'struct crupdated_od_lb_data' */
    struct ovs_list crupdated_ls_lbs;

    /* List of logical router <-> lb changes. List node is
     * 'struct crupdated_od_lb_data' */
    struct ovs_list crupdated_lr_lbs;

    /* hmapx of deleted logical switches which have load balancer or lb groups
     * associated with it.  hmapx_node is 'struct od_lb_data'. */
    struct hmapx deleted_od_lb_data;

    /* Indicates if any of the tracked lb has health checks enabled. */
    bool has_health_checks;

    /* Indicates if any lb got disassociated from a lb group
     * but not deleted. */
    bool has_dissassoc_lbs_from_lbgrps;

    /* Indicates if a lb was disassociated from a logical switch. */
    bool has_dissassoc_lbs_from_od;

    /* Indicates if a lb group was disassociated from a logical switch. */
    bool has_dissassoc_lbgrps_from_od;

    /* Indicates if any lb (in the tracked data) has 'routable' flag set. */
    bool has_routable_lb;
};

/* Datapath (logical switch) to lb/lbgrp association data. */
struct od_lb_data {
    struct hmap_node hmap_node;
    struct uuid od_uuid;
    struct uuidset *lbs;
    struct uuidset *lbgrps;
};

/* struct which maintains the data of the engine node lb_data. */
struct ed_type_lb_data {
    /* hmap of load balancers.  hmap node is 'struct ovn_northd_lb *' */
    struct hmap lbs;

    /* hmap of load balancer groups.  hmap node is 'struct ovn_lb_group *' */
    struct hmap lbgrps;

    /* hmap of ls to lb map.  hmap node is 'struct od_lb_data'. */
    struct hmap ls_lb_map;
    struct hmap lr_lb_map;

    /* tracked data*/
    bool tracked;
    struct tracked_lb_data tracked_lb_data;
};

void *en_lb_data_init(struct engine_node *, struct engine_arg *);
enum engine_node_state en_lb_data_run(struct engine_node *, void *data);
void en_lb_data_cleanup(void *data);
void en_lb_data_clear_tracked_data(void *data);

enum engine_input_handler_result
lb_data_load_balancer_handler(struct engine_node *, void *data);
enum engine_input_handler_result
lb_data_load_balancer_group_handler(struct engine_node *, void *data);
enum engine_input_handler_result
lb_data_synced_logical_switch_handler(struct engine_node *, void *data);
enum engine_input_handler_result
lb_data_synced_logical_router_handler(struct engine_node *, void *data);

#endif /* end of EN_NORTHD_LB_DATA_H */
