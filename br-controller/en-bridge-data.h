#ifndef EN_RUNTIME_DATA_H
#define EN_RUNTIME_DATA_H 1

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "lib/inc-proc-eng.h"

enum engine_node_state en_bridge_data_run(struct engine_node *, void *data);
void *en_bridge_data_init(struct engine_node *node, struct engine_arg *arg);
void en_bridge_data_cleanup(void *data);

#endif /* EN_RUNTIME_DATA_H */
