#ifndef EN_ACL_IDS_H
#define EN_ACL_IDS_H

#include <config.h>
#include <stdbool.h>

#include "lib/inc-proc-eng.h"

bool northd_acl_id_handler(struct engine_node *node, void *data);
void *en_acl_id_init(struct engine_node *, struct engine_arg *);
void en_acl_id_run(struct engine_node *, void *data);
void en_acl_id_cleanup(void *data);
#endif
