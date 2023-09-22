/*
 * Copyright (c) 2022, Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <config.h>

#if HAVE_DECL_MALLOC_TRIM
#include <malloc.h>
#endif

#include "memory-trim.h"

#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(memory_trim);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

struct memory_trimmer {
    uint32_t trim_timeout_ms;
    long long int last_active_ms;
    bool recently_active;
};

struct memory_trimmer *
memory_trimmer_create(void)
{
    struct memory_trimmer *mt = xzalloc(sizeof *mt);
    return mt;
}

void
memory_trimmer_destroy(struct memory_trimmer *mt)
{
    free(mt);
}

void
memory_trimmer_set(struct memory_trimmer *mt, uint32_t trim_timeout_ms)
{
    if (trim_timeout_ms < 1000) {
        VLOG_WARN_RL(&rl, "Invalid requested trim timeout: "
                     "requested %"PRIu32" ms, using 1000 ms instead",
                     trim_timeout_ms);
        trim_timeout_ms = 1000;
    }
    mt->trim_timeout_ms = trim_timeout_ms;
}

/* Returns true if trimming due to inactivity should happen. */
bool
memory_trimmer_can_run(struct memory_trimmer *mt)
{
    if (!mt->recently_active) {
        return false;
    }

    long long int now = time_msec();
    if (now < mt->last_active_ms) {
        VLOG_WARN_RL(&rl, "Detected last active timestamp overflow");
        mt->recently_active = false;
        return true;
    }

    if (now > mt->trim_timeout_ms
        && now - mt->trim_timeout_ms >= mt->last_active_ms) {
        VLOG_INFO_RL(&rl, "Detected inactivity "
                    "(last active %lld ms ago): trimming memory",
                    now - mt->last_active_ms);
        mt->recently_active = false;
        return true;
    }

    return false;
}

void
memory_trimmer_wait(struct memory_trimmer *mt)
{
    if (!mt->recently_active) {
        return;
    }
    poll_timer_wait_until(mt->last_active_ms + mt->trim_timeout_ms);
}

void
memory_trimmer_trim(struct memory_trimmer *mt OVS_UNUSED)
{
#if HAVE_DECL_MALLOC_TRIM
        malloc_trim(0);
#endif
}

void
memory_trimmer_record_activity(struct memory_trimmer *mt)
{
    mt->last_active_ms = time_msec();
    mt->recently_active = true;
}
