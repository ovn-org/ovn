/* Copyright (c) 2024, Red Hat, Inc.
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

#ifndef OVN_CT_ZONE_H
#define OVN_CT_ZONE_H

#include <stdbool.h>

#include "bitmap.h"
#include "openvswitch/hmap.h"
#include "openvswitch/shash.h"
#include "openvswitch/types.h"
#include "ovn-sb-idl.h"
#include "simap.h"
#include "vswitch-idl.h"

/* Linux supports a maximum of 64K zones, which seems like a fine default. */
#define MAX_CT_ZONES 65535
#define BITMAP_SIZE BITMAP_N_LONGS(MAX_CT_ZONES)

/* Context of CT zone assignment. */
struct ct_zone_ctx {
    unsigned long bitmap[BITMAP_SIZE]; /* Bitmap indication of allocated
                                        * zones. */
    struct shash pending;              /* Pending entries,
                                        * 'struct ct_zone_pending_entry'
                                        * by name. */
    struct simap current;              /* Current CT zones mapping
                                        * (zone id by name). */
};

/* States to move through when a new conntrack zone has been allocated. */
enum ct_zone_pending_state {
    CT_ZONE_OF_QUEUED,    /* Waiting to send conntrack flush command. */
    CT_ZONE_OF_SENT,      /* Sent and waiting for confirmation on flush. */
    CT_ZONE_DB_QUEUED,    /* Waiting for DB transaction to open. */
    CT_ZONE_DB_SENT,      /* Sent and waiting for confirmation from DB. */
};

struct ct_zone_pending_entry {
    int zone;
    bool add;             /* Is the entry being added? */
    ovs_be32 of_xid;      /* Transaction id for barrier. */
    enum ct_zone_pending_state state;
};

void ct_zones_restore(struct ct_zone_ctx *ctx,
                      const struct ovsrec_open_vswitch_table *ovs_table,
                      const struct sbrec_datapath_binding_table *dp_table,
                      const struct ovsrec_bridge *br_int);
bool ct_zone_assign_unused(struct ct_zone_ctx *ctx, const char *zone_name,
                           int *scan_start);
bool ct_zone_remove(struct ct_zone_ctx *ctx, const char *name);
void ct_zones_update(const struct sset *local_lports,
                     const struct hmap *local_datapaths,
                     struct ct_zone_ctx *ctx);
void ct_zones_commit(const struct ovsrec_bridge *br_int,
                     struct shash *pending_ct_zones);
int ct_zone_get_snat(const struct sbrec_datapath_binding *dp);
void ct_zones_pending_clear_commited(struct shash *pending);

#endif /* controller/ct-zone.h */
