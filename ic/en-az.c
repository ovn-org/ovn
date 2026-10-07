/*
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

#include "en-az.h"
#include "lib/inc-proc-eng.h"
#include "lib/ovn-ic-sb-idl.h"
#include "lib/ovn-nb-idl.h"
#include "openvswitch/vlog.h"
#include "ovn-ic.h"
#include "ovsdb-idl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(en_ic_az);

/* Resolves (and, if needed, registers) the availability zone for this ovn-ic
 * instance.  This node has no engine inputs: like the former az_run() helper
 * it runs on every engine iteration and reads the NB Global and IC-SB
 * Availability_Zone tables directly.  The resolved AZ is stored in this node's
 * own data (struct ed_type_az): dependent nodes declare en_az as an input and
 * read it with engine_get_input_data("az", node), and the main loop reads it
 * with inc_proc_ic_get_runned_az() after inc_proc_ic_run().  It reports
 * EN_UPDATED only when the resolved AZ identity changes so dependent nodes do
 * not recompute on every iteration. */
enum engine_node_state
en_az_run(struct engine_node *node OVS_UNUSED, void *data_)
{
    const struct engine_context *eng_ctx = engine_get_context();
    struct ic_context *ctx = eng_ctx->client_ctx;
    struct ed_type_az *data = data_;
    const struct icsbrec_availability_zone *old_az = data->runned_az;
    const struct icsbrec_availability_zone *az;

    data->runned_az = NULL;

    const struct nbrec_nb_global *nb_global =
        nbrec_nb_global_first(ctx->ovnnb_idl);
    if (!nb_global) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "NB Global does not exist.");
        goto out;
    }

    /* Update old AZ if name changes.  Note: if name changed when ovn-ic
     * is not running, one has to manually delete/update the old AZ with:
     * "ovn-ic-sbctl destroy avail <az>". */
    if (ctx->ovnisb_unlocked_txn && data->az_name
        && strcmp(data->az_name, nb_global->name)) {
        ICSBREC_AVAILABILITY_ZONE_FOR_EACH (az, ctx->ovnisb_unlocked_idl) {
            /* AZ name update locally need to update az in ISB. */
            if (nb_global->name[0] && !strcmp(az->name, data->az_name)) {
                icsbrec_availability_zone_set_name(az, nb_global->name);
                break;
            } else if (!nb_global->name[0]
                       && !strcmp(az->name, data->az_name)) {
                icsbrec_availability_zone_delete(az);
                break;
            }
        }
        free(data->az_name);
        data->az_name = NULL;
    }

    if (!nb_global->name[0]) {
        goto out;
    }

    if (!data->az_name) {
        data->az_name = xstrdup(nb_global->name);
    }

    if (ctx->ovnisb_unlocked_txn) {
        ovsdb_idl_txn_add_comment(ctx->ovnisb_unlocked_txn, "AZ %s",
                                  data->az_name);
    }

    ICSBREC_AVAILABILITY_ZONE_FOR_EACH (az, ctx->ovnisb_unlocked_idl) {
        if (!strcmp(az->name, data->az_name)) {
            data->runned_az = az;
            goto out;
        }
    }

    /* Create AZ in ISB */
    if (ctx->ovnisb_unlocked_txn) {
        VLOG_INFO("Register AZ %s to interconnection DB.", data->az_name);
        az = icsbrec_availability_zone_insert(ctx->ovnisb_unlocked_txn);
        icsbrec_availability_zone_set_name(az, data->az_name);
        data->runned_az = az;
    }

out: {
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
    VLOG_DBG_RL(&rl, "Availability zone: %s",
                data->runned_az ? data->runned_az->name : "not created yet.");

    return data->runned_az == old_az ? EN_UNCHANGED : EN_UPDATED;
}
}

void *
en_az_init(struct engine_node *node OVS_UNUSED,
           struct engine_arg *arg OVS_UNUSED)
{
    return xzalloc(sizeof(struct ed_type_az));
}

void
en_az_cleanup(void *data_)
{
    struct ed_type_az *data = data_;

    free(data->az_name);
    data->az_name = NULL;
}
