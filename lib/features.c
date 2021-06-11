/* Copyright (c) 2021, Red Hat, Inc.
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
#include <stdint.h>
#include <stdlib.h>

#include "lib/util.h"
#include "openvswitch/vlog.h"
#include "ovn/features.h"

VLOG_DEFINE_THIS_MODULE(features);

struct ovs_feature {
    enum ovs_feature_value value;
    const char *name;
};

static struct ovs_feature all_ovs_features[] = {
    {
        .value = OVS_CT_ZERO_SNAT_SUPPORT,
        .name = "ct_zero_snat"
    },
};

/* A bitmap of OVS features that have been detected as 'supported'. */
static uint32_t supported_ovs_features;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

static bool
ovs_feature_is_valid(enum ovs_feature_value feature)
{
    switch (feature) {
    case OVS_CT_ZERO_SNAT_SUPPORT:
        return true;
    default:
        return false;
    }
}

bool
ovs_feature_is_supported(enum ovs_feature_value feature)
{
    ovs_assert(ovs_feature_is_valid(feature));
    return supported_ovs_features & feature;
}

/* Returns 'true' if the set of tracked OVS features has been updated. */
bool
ovs_feature_support_update(const struct smap *ovs_capabilities)
{
    bool updated = false;

    for (size_t i = 0; i < ARRAY_SIZE(all_ovs_features); i++) {
        enum ovs_feature_value value = all_ovs_features[i].value;
        const char *name = all_ovs_features[i].name;
        bool old_state = supported_ovs_features & value;
        bool new_state = smap_get_bool(ovs_capabilities, name, false);
        if (new_state != old_state) {
            updated = true;
            if (new_state) {
                supported_ovs_features |= value;
            } else {
                supported_ovs_features &= ~value;
            }
            VLOG_INFO_RL(&rl, "OVS Feature: %s, state: %s", name,
                         new_state ? "supported" : "not supported");
        }
    }
    return updated;
}
