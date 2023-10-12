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

void en_lflow_run(struct engine_node *node, void *data);
void *en_lflow_init(struct engine_node *node, struct engine_arg *arg);
void en_lflow_cleanup(void *data);
bool lflow_northd_handler(struct engine_node *, void *data);
bool lflow_port_group_handler(struct engine_node *, void *data);
bool lflow_lr_stateful_handler(struct engine_node *, void *data);
bool lflow_ls_stateful_handler(struct engine_node *node, void *data);

#endif /* EN_LFLOW_H */
