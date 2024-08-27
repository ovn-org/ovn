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
#define OVN_FEATURE_PORT_UP_NOTIF      "port-up-notif"
#define OVN_FEATURE_CT_NO_MASKED_LABEL "ct-no-masked-label"
#define OVN_FEATURE_MAC_BINDING_TIMESTAMP "mac-binding-timestamp"
#define OVN_FEATURE_CT_LB_RELATED "ovn-ct-lb-related"
#define OVN_FEATURE_FDB_TIMESTAMP "fdb-timestamp"
#define OVN_FEATURE_LS_DPG_COLUMN "ls-dpg-column"
#define OVN_FEATURE_CT_COMMIT_NAT_V2 "ct-commit-nat-v2"
#define OVN_FEATURE_CT_COMMIT_TO_ZONE "ct-commit-to-zone"
#define OVN_FEATURE_SAMPLE_WITH_REGISTERS "ovn-sample-with-registers"
#define OVN_FEATURE_CT_NEXT_ZONE "ct-next-zone"

/* OVS datapath supported features.  Based on availability OVN might generate
 * different types of openflows.
 */
enum ovs_feature_support_bits {
    OVS_CT_ZERO_SNAT_SUPPORT_BIT,
    OVS_DP_METER_SUPPORT_BIT,
    OVS_CT_TUPLE_FLUSH_BIT,
    OVS_DP_HASH_L4_SYM_BIT,
    OVS_OF_GROUP_SUPPORT_BIT,
    OVS_SAMPLE_REG_SUPPORT_BIT,
};

enum ovs_feature_value {
    OVS_CT_ZERO_SNAT_SUPPORT = (1 << OVS_CT_ZERO_SNAT_SUPPORT_BIT),
    OVS_DP_METER_SUPPORT = (1 << OVS_DP_METER_SUPPORT_BIT),
    OVS_CT_TUPLE_FLUSH_SUPPORT = (1 << OVS_CT_TUPLE_FLUSH_BIT),
    OVS_DP_HASH_L4_SYM_SUPPORT = (1 << OVS_DP_HASH_L4_SYM_BIT),
    OVS_OF_GROUP_SUPPORT = (1 << OVS_OF_GROUP_SUPPORT_BIT),
    OVS_SAMPLE_REG_SUPPORT = (1 << OVS_SAMPLE_REG_SUPPORT_BIT),
};

void ovs_feature_support_destroy(void);
bool ovs_feature_is_supported(enum ovs_feature_value feature);
bool ovs_feature_support_run(const struct smap *ovs_capabilities,
                             const char *conn_target, int probe_interval);
bool ovs_feature_set_discovered(void);
uint32_t ovs_feature_max_meters_get(void);
uint32_t ovs_feature_max_select_groups_get(void);

#endif
