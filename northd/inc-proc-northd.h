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
};

void inc_proc_northd_init(struct ovsdb_idl_loop *nb,
                          struct ovsdb_idl_loop *sb);
bool inc_proc_northd_run(struct ovsdb_idl_txn *ovnnb_txn,
                         struct ovsdb_idl_txn *ovnsb_txn,
                         struct northd_engine_context *ctx);
void inc_proc_northd_cleanup(void);
bool inc_proc_northd_can_run(struct northd_engine_context *ctx);

static inline void
inc_proc_northd_force_recompute(void)
{
        engine_set_force_recompute();
}

static inline void
inc_proc_northd_force_recompute_immediate(void)
{
    engine_set_force_recompute_immediate();
}

static inline bool
inc_proc_northd_get_force_recompute(void)
{
    return engine_get_force_recompute();
}

#endif /* INC_PROC_NORTHD */
