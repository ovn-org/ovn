#ifndef INC_PROC_NORTHD_H
#define INC_PROC_NORTHD_H 1

#include <config.h>

#include "northd.h"
#include "ovsdb-idl.h"

#define IDL_LOOP_MAX_DURATION_MS 500

struct northd_engine_context {
    int64_t next_run_ms;
    uint64_t nb_idl_duration_ms;
    uint64_t sb_idl_duration_ms;
    uint32_t backoff_ms;
    bool recompute;
};

void inc_proc_northd_init(struct ovsdb_idl_loop *nb,
                          struct ovsdb_idl_loop *sb);
bool inc_proc_northd_run(struct ovsdb_idl_txn *ovnnb_txn,
                         struct ovsdb_idl_txn *ovnsb_txn,
                         struct northd_engine_context *ctx);
void inc_proc_northd_cleanup(void);
bool inc_proc_northd_can_run(struct northd_engine_context *ctx);

#endif /* INC_PROC_NORTHD */
