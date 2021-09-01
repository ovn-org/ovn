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

#ifndef OVN_FEATURES_H
#define OVN_FEATURES_H 1

#include <stdbool.h>

#include "smap.h"

/* ovn-controller supported feature names. */
#define OVN_FEATURE_PORT_UP_NOTIF "port-up-notif"

/* OVS datapath supported features.  Based on availability OVN might generate
 * different types of openflows.
 */
enum ovs_feature_support_bits {
    OVS_CT_ZERO_SNAT_SUPPORT_BIT,
};

enum ovs_feature_value {
    OVS_CT_ZERO_SNAT_SUPPORT = (1 << OVS_CT_ZERO_SNAT_SUPPORT_BIT),
};

bool ovs_feature_is_supported(enum ovs_feature_value feature);
bool ovs_feature_support_update(const struct smap *ovs_capabilities);

#endif
