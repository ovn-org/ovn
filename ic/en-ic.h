#ifndef EN_IC_H
#define EN_IC_H 1

#include <config.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "lib/inc-proc-eng.h"

enum engine_node_state en_ic_run(struct engine_node *node OVS_UNUSED,
                                 void *data OVS_UNUSED);
void *en_ic_init(struct engine_node *node OVS_UNUSED,
                 struct engine_arg *arg);
void en_ic_cleanup(void *data);

#endif /* EN_IC_H */
