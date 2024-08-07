/*
 * Copyright (c) 2024, Red Hat, Inc.
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

#include "openvswitch/vlog.h"

#include "en-sampling-app.h"

VLOG_DEFINE_THIS_MODULE(en_sampling_app);

/* Static function declarations. */
static void sampling_app_table_add(struct sampling_app_table *,
                                   const struct nbrec_sampling_app *);
static uint8_t sampling_app_table_get_id(const struct sampling_app_table *,
                                         enum sampling_app);
static void sampling_app_table_reset(struct sampling_app_table *);
static enum sampling_app sampling_app_get_by_type(const char *app_type);

void *
en_sampling_app_init(struct engine_node *node OVS_UNUSED,
                     struct engine_arg *arg OVS_UNUSED)
{
    struct ed_type_sampling_app_data *data = xzalloc(sizeof *data);
    sampling_app_table_reset(&data->apps);
    return data;
}

void
en_sampling_app_cleanup(void *data OVS_UNUSED)
{
}

void
en_sampling_app_run(struct engine_node *node, void *data_)
{
    const struct nbrec_sampling_app_table *nb_sampling_app_table =
        EN_OVSDB_GET(engine_get_input("NB_sampling_app", node));
    struct ed_type_sampling_app_data *data = data_;

    sampling_app_table_reset(&data->apps);

    const struct nbrec_sampling_app *sa;
    NBREC_SAMPLING_APP_TABLE_FOR_EACH (sa, nb_sampling_app_table) {
        sampling_app_table_add(&data->apps, sa);
    }

    engine_set_node_state(node, EN_UPDATED);
}

uint8_t
sampling_app_get_id(const struct sampling_app_table *app_table,
                    enum sampling_app app)
{
    return sampling_app_table_get_id(app_table, app);
}

/* Static functions. */
static void
sampling_app_table_add(struct sampling_app_table *table,
                       const struct nbrec_sampling_app *sa)
{
    enum sampling_app app = sampling_app_get_by_type(sa->type);

    if (app == SAMPLING_APP_MAX) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "Unexpected Sampling_App type: %s", sa->type);
        return;
    }
    table->app_ids[app] = sa->id;
}

static uint8_t
sampling_app_table_get_id(const struct sampling_app_table *table,
                          enum sampling_app app)
{
    ovs_assert(app < SAMPLING_APP_MAX);
    return table->app_ids[app];
}

static void
sampling_app_table_reset(struct sampling_app_table *table)
{
    for (size_t i = 0; i < SAMPLING_APP_MAX; i++) {
        table->app_ids[i] = SAMPLING_APP_ID_NONE;
    }
}

static const char *app_types[] = {
    [SAMPLING_APP_DROP_DEBUG] = "drop",
    [SAMPLING_APP_ACL_NEW] = "acl-new",
    [SAMPLING_APP_ACL_EST] = "acl-est",
};

static enum sampling_app
sampling_app_get_by_type(const char *app_type)
{
    for (size_t app = 0; app < ARRAY_SIZE(app_types); app++) {
        if (!strcmp(app_type, app_types[app])) {
            return app;
        }
    }
    return SAMPLING_APP_MAX;
}
