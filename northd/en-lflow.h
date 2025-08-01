#ifndef EN_LFLOW_H
#define EN_LFLOW_H 1

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "lib/inc-proc-eng.h"

struct lflow_table;

struct lflow_data {
    struct lflow_table *lflow_table;
};

enum engine_node_state en_lflow_run(struct engine_node *node, void *data);
void *en_lflow_init(struct engine_node *node, struct engine_arg *arg);
void en_lflow_cleanup(void *data);
enum engine_input_handler_result lflow_northd_handler(struct engine_node *,
                                                      void *data);
enum engine_input_handler_result
lflow_lr_stateful_handler(struct engine_node *, void *data);
enum engine_input_handler_result
lflow_ls_stateful_handler(struct engine_node *node, void *data);
enum engine_input_handler_result
lflow_multicast_igmp_handler(struct engine_node *node, void *data);
enum engine_input_handler_result
lflow_group_ecmp_route_change_handler(struct engine_node *node, void *data);

#endif /* EN_LFLOW_H */
