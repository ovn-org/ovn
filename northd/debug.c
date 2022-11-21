#include <config.h>

#include <string.h>

#include "debug.h"

#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "smap.h"

VLOG_DEFINE_THIS_MODULE(debug)

struct debug_config {
    bool enabled;
    uint32_t collector_set_id;
    uint32_t observation_domain_id;
    struct ds drop_action;
};

static struct debug_config config;

static bool
debug_enabled(void)
{
    return config.collector_set_id != 0;
}

void
init_debug_config(const struct nbrec_nb_global *nb)
{

    const struct smap *options = &nb->options;
    uint32_t collector_set_id = smap_get_uint(options,
                                              "debug_drop_collector_set",
                                              0);
    uint32_t observation_domain_id = smap_get_uint(options,
                                                   "debug_drop_domain_id",
                                                   0);

    if (collector_set_id != config.collector_set_id ||
        observation_domain_id != config.observation_domain_id ||
        !config.drop_action.length) {

        if (observation_domain_id >= UINT8_MAX) {
            VLOG_ERR("Observation domain id must be an 8-bit number");
            return;
        }

        config.collector_set_id = collector_set_id;
        config.observation_domain_id = observation_domain_id;

        ds_clear(&config.drop_action);

        if (debug_enabled()) {
            ds_put_format(&config.drop_action,
                          "sample(probability=65535,"
                          "collector_set=%d,"
                          "obs_domain=%d,"
                          "obs_point=$cookie); ",
                          config.collector_set_id,
                          config.observation_domain_id);

            ds_put_cstr(&config.drop_action, "/* drop */");
            VLOG_DBG("Debug drop sampling: enabled");
        } else {
            ds_put_cstr(&config.drop_action, "drop;");
            VLOG_DBG("Debug drop sampling: disabled");
        }
    }
}

void
destroy_debug_config(void)
{
    if (config.drop_action.string) {
        ds_destroy(&config.drop_action);
        ds_init(&config.drop_action);
    }
}

const char *
debug_drop_action(void) {
    if (OVS_UNLIKELY(debug_enabled())) {
        return ds_cstr_ro(&config.drop_action);
    } else {
        return "drop;";
    }
}

const char *
debug_implicit_drop_action(void)
{
    if (OVS_UNLIKELY(debug_enabled())) {
        return ds_cstr_ro(&config.drop_action);
    } else {
        return "/* drop */";
    }
}
