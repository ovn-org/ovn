#ifndef EN_NORTHD_H
#define EN_NORTHD_H 1

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "lib/inc-proc-eng.h"

void en_northd_run(struct engine_node *node OVS_UNUSED, void *data OVS_UNUSED);
void *en_northd_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg);
void en_northd_cleanup(void *data);
void en_northd_clear_tracked_data(void *data);
bool northd_global_config_handler(struct engine_node *, void *data OVS_UNUSED);
bool northd_nb_logical_switch_handler(struct engine_node *, void *data);
bool northd_nb_logical_router_handler(struct engine_node *, void *data);
bool northd_sb_port_binding_handler(struct engine_node *, void *data);
bool northd_lb_data_handler(struct engine_node *, void *data);
bool northd_sb_fdb_change_handler(struct engine_node *node, void *data);
void *en_static_routes_init(struct engine_node *node OVS_UNUSED,
                            struct engine_arg *arg OVS_UNUSED);
void en_route_policies_cleanup(void *data);
bool route_policies_northd_change_handler(struct engine_node *node,
                                          void *data OVS_UNUSED);
void en_route_policies_run(struct engine_node *node, void *data);
void *en_route_policies_init(struct engine_node *node OVS_UNUSED,
                             struct engine_arg *arg OVS_UNUSED);
void en_static_routes_cleanup(void *data);
bool static_routes_northd_change_handler(struct engine_node *node,
                                         void *data OVS_UNUSED);
void en_static_routes_run(struct engine_node *node, void *data);
void *en_bfd_init(struct engine_node *node OVS_UNUSED,
                  struct engine_arg *arg OVS_UNUSED);
void en_bfd_cleanup(void *data);
void en_bfd_run(struct engine_node *node, void *data);
void *en_bfd_sync_init(struct engine_node *node OVS_UNUSED,
                       struct engine_arg *arg OVS_UNUSED);
bool bfd_sync_northd_change_handler(struct engine_node *node,
                                    void *data OVS_UNUSED);
void en_bfd_sync_run(struct engine_node *node, void *data);
void en_bfd_sync_cleanup(void *data OVS_UNUSED);
void en_ecmp_nexthop_run(struct engine_node *node, void *data);
void *en_ecmp_nexthop_init(struct engine_node *node OVS_UNUSED,
                           struct engine_arg *arg OVS_UNUSED);
void en_ecmp_nexthop_cleanup(void *data);

#endif /* EN_NORTHD_H */
