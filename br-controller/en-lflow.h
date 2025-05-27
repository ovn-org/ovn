#ifndef EN_LFLOW_H
#define EN_LFLOW_H 1

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "lib/inc-proc-eng.h"

enum engine_node_state en_lflow_output_run(struct engine_node *, void *data);
void *en_lflow_output_init(struct engine_node *node, struct engine_arg *arg);
void en_lflow_output_cleanup(void *data);

#endif /* EN_LFLOW_H */
