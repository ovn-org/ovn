#ifndef INC_PROC_NORTHD_H
#define INC_PROC_NORTHD_H 1

#include <config.h>

#include "northd.h"
#include "ovsdb-idl.h"

void inc_proc_northd_init(struct ovsdb_idl_loop *nb,
                          struct ovsdb_idl_loop *sb);
void inc_proc_northd_run(struct northd_context *ctx,
                         bool recompute);
void inc_proc_northd_cleanup(void);

#endif /* INC_PROC_NORTHD */
