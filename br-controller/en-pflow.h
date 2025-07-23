#ifndef EN_PFLOW_H
#define EN_PFLOW_H 1

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "lib/inc-proc-eng.h"

enum engine_node_state en_pflow_output_run(struct engine_node *, void *data);
void *en_pflow_output_init(struct engine_node *node, struct engine_arg *arg);
void en_pflow_output_cleanup(void *data);

#endif /* EN_PFLOW_H */
