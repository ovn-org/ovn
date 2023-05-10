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
bool northd_nb_nb_global_handler(struct engine_node *, void *data OVS_UNUSED);
bool northd_nb_logical_switch_handler(struct engine_node *, void *data);
bool northd_sb_port_binding_handler(struct engine_node *, void *data);

#endif /* EN_NORTHD_H */
