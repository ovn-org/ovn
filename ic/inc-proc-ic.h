#ifndef INC_PROC_IC_H
#define INC_PROC_IC_H 1

#include <config.h>

#include "ovn-ic.h"
#include "ovsdb-idl.h"
#include "lib/inc-proc-eng.h"

struct ic_engine_context {
    int64_t next_run_ms;
    uint64_t nb_idl_duration_ms;
    uint64_t sb_idl_duration_ms;
    uint64_t inb_idl_duration_ms;
    uint64_t isb_idl_duration_ms;
    uint32_t backoff_ms;
};

void inc_proc_ic_init(struct ovsdb_idl_loop *nb,
                      struct ovsdb_idl_loop *sb,
                      struct ovsdb_idl_loop *icnb,
                      struct ovsdb_idl_loop *icsb);

bool inc_proc_ic_run(struct ic_context *ctx,
                     struct ic_engine_context *ic_eng_ctx);

void inc_proc_ic_cleanup(void);
bool inc_proc_ic_can_run(struct ic_engine_context *ctx);

static inline void
inc_proc_ic_force_recompute(void)
{
    engine_set_force_recompute();
}

static inline void
inc_proc_ic_force_recompute_immediate(void)
{
    engine_set_force_recompute_immediate();
}

static inline bool
inc_proc_ic_get_force_recompute(void)
{
    return engine_get_force_recompute();
}

#endif /* INC_PROC_IC */
