#ifndef EN_LFLOW_H
#define EN_LFLOW_H 1

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "lib/inc-proc-eng.h"

#define BR_OFTABLE_LOG_INGRESS_PIPELINE      8
#define BR_OFTABLE_SAVE_INPORT               64

enum engine_node_state en_lflow_output_run(struct engine_node *, void *data);
void *en_lflow_output_init(struct engine_node *node, struct engine_arg *arg);
void en_lflow_output_cleanup(void *data);

#endif /* EN_LFLOW_H */
