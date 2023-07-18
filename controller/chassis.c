/* Copyright (c) 2015, 2016 Nicira, Inc.
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
#include <unistd.h>

#include "chassis.h"

#include "lib/smap.h"
#include "lib/sset.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "openvswitch/ofp-parse.h"
#include "lib/chassis-index.h"
#include "lib/ovn-sb-idl.h"
#include "ovn-controller.h"
#include "lib/util.h"
#include "ovn/features.h"

VLOG_DEFINE_THIS_MODULE(chassis);

#ifndef HOST_NAME_MAX
/* For windows. */
#define HOST_NAME_MAX 255
#endif /* HOST_NAME_MAX */

char *cli_system_id = NULL;
char *file_system_id = NULL;

/*
 * Structure for storing the chassis config parsed from the ovs table.
 */
struct ovs_chassis_cfg {
    /* Single string fields parsed from external-ids. */
    const char *hostname;
    const char *bridge_mappings;
    const char *datapath_type;
    const char *encap_csum;
    const char *cms_options;
    const char *monitor_all;
    const char *chassis_macs;
    const char *enable_lflow_cache;
    const char *limit_lflow_cache;
    const char *memlimit_lflow_cache;
    const char *trim_limit_lflow_cache;
    const char *trim_wmark_perc_lflow_cache;
    const char *trim_timeout_ms;

    /* Set of encap types parsed from the 'ovn-encap-type' external-id. */
    struct sset encap_type_set;
    /* Set of encap IPs parsed from the 'ovn-encap-type' external-id. */
    struct sset encap_ip_set;
    /* Interface type list formatted in the OVN-SB Chassis required format. */
    struct ds iface_types;
    /* Is this chassis an interconnection gateway. */
    bool is_interconn;
};

static void
ovs_chassis_cfg_init(struct ovs_chassis_cfg *cfg)
{
    sset_init(&cfg->encap_type_set);
    sset_init(&cfg->encap_ip_set);
    ds_init(&cfg->iface_types);
}

static void
ovs_chassis_cfg_destroy(struct ovs_chassis_cfg *cfg)
{
    sset_destroy(&cfg->encap_type_set);
    sset_destroy(&cfg->encap_ip_set);
    ds_destroy(&cfg->iface_types);
}

void
chassis_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_external_ids);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_iface_types);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_datapath_type);
}

static const char *
get_hostname(const struct smap *ext_ids, const char *chassis_id)
{
    const char *hostname = get_chassis_external_id_value(ext_ids, chassis_id,
                                                         "hostname", NULL);

    if (!hostname) {
        static char hostname_[HOST_NAME_MAX + 1];

        if (gethostname(hostname_, sizeof(hostname_))) {
            hostname_[0] = 0;
        }

        return &hostname_[0];
    }

    return hostname;
}

static const char *
get_bridge_mappings(const struct smap *ext_ids, const char *chassis_id)
{
    return get_chassis_external_id_value(ext_ids, chassis_id,
                                         "ovn-bridge-mappings", "");
}

const char *
get_chassis_mac_mappings(const struct smap *ext_ids, const char *chassis_id)
{
    return get_chassis_external_id_value(ext_ids, chassis_id,
                                         "ovn-chassis-mac-mappings", "");
}

static const char *
get_cms_options(const struct smap *ext_ids, const char *chassis_id)
{
    return get_chassis_external_id_value(ext_ids, chassis_id,
                                         "ovn-cms-options", "");
}

static const char *
get_monitor_all(const struct smap *ext_ids, const char *chassis_id)
{
    return get_chassis_external_id_value(ext_ids, chassis_id,
                                         "ovn-monitor-all", "false");
}

static const char *
get_enable_lflow_cache(const struct smap *ext_ids, const char *chassis_id)
{
    return get_chassis_external_id_value(ext_ids, chassis_id,
                                         "ovn-enable-lflow-cache", "true");
}

static const char *
get_limit_lflow_cache(const struct smap *ext_ids, const char *chassis_id)
{
    return get_chassis_external_id_value(ext_ids, chassis_id,
                                         "ovn-limit-lflow-cache", "");
}

static const char *
get_memlimit_lflow_cache(const struct smap *ext_ids, const char *chassis_id)
{
    return get_chassis_external_id_value(ext_ids, chassis_id,
                                         "ovn-memlimit-lflow-cache-kb", "");
}

static const char *
get_trim_limit_lflow_cache(const struct smap *ext_ids, const char *chassis_id)
{
    return get_chassis_external_id_value(ext_ids, chassis_id,
                                         "ovn-trim-limit-lflow-cache", "");
}

static const char *
get_trim_wmark_perc_lflow_cache(const struct smap *ext_ids,
                                const char *chassis_id)
{
    return get_chassis_external_id_value(
        ext_ids, chassis_id, "ovn-trim-wmark-perc-lflow-cache", "");
}

static const char *
get_trim_timeout(const struct smap *ext_ids, const char *chassis_id)
{
    return get_chassis_external_id_value(ext_ids, chassis_id,
                                         "ovn-trim-timeout-ms", "");
}

static const char *
get_encap_csum(const struct smap *ext_ids, const char *chassis_id)
{
    return get_chassis_external_id_value(ext_ids, chassis_id,
                                         "ovn-encap-csum", "true");
}

static const char *
get_datapath_type(const struct ovsrec_bridge *br_int)
{
    if (br_int && br_int->datapath_type) {
        return br_int->datapath_type;
    }

    return "";
}

static bool
get_is_interconn(const struct smap *ext_ids, const char *chassis_id)
{
    return get_chassis_external_id_value_bool(ext_ids, chassis_id,
                                              "ovn-is-interconn", false);
}

static void
update_chassis_transport_zones(const struct sset *transport_zones,
                               const struct sbrec_chassis *chassis_rec)
{
    struct sset chassis_tzones_set = SSET_INITIALIZER(&chassis_tzones_set);
    for (int i = 0; i < chassis_rec->n_transport_zones; i++) {
        sset_add(&chassis_tzones_set, chassis_rec->transport_zones[i]);
    }

    /* Only update the transport zones if something changed */
    if (!sset_equals(transport_zones, &chassis_tzones_set)) {
        const char **ls_arr = sset_array(transport_zones);
        sbrec_chassis_set_transport_zones(chassis_rec, ls_arr,
                                          sset_count(transport_zones));
        free(ls_arr);
    }

    sset_destroy(&chassis_tzones_set);
}

/*
 * Parse an ovs 'encap_type' string and stores the resulting types in the
 * 'encap_type_set' string set.
 */
static void
chassis_parse_ovs_encap_type(const char *encap_type,
                             struct sset *encap_type_set)
{
    sset_from_delimited_string(encap_type_set, encap_type, ",");

    const char *type;

    SSET_FOR_EACH (type, encap_type_set) {
        if (!get_tunnel_type(type)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_INFO_RL(&rl, "Unknown tunnel type: %s", type);
        }
    }
}

/*
 * Parse an ovs 'encap_ip' string and stores the resulting IP representations
 * in the 'encap_ip_set' string set.
 */
static void
chassis_parse_ovs_encap_ip(const char *encap_ip, struct sset *encap_ip_set)
{
    sset_from_delimited_string(encap_ip_set, encap_ip, ",");
}

/*
 * Parse the ovs 'iface_types' and store them in the format required by the
 * Chassis record.
 */
static void
chassis_parse_ovs_iface_types(char **iface_types, size_t n_iface_types,
                              struct ds *iface_types_str)
{
    for (size_t i = 0; i < n_iface_types; i++) {
        ds_put_format(iface_types_str, "%s,", iface_types[i]);
    }
    ds_chomp(iface_types_str, ',');
}

/*
 * Parse the 'ovs_table' entry and populate 'ovs_cfg'.
 */
static bool
chassis_parse_ovs_config(const struct ovsrec_open_vswitch_table *ovs_table,
                         const struct ovsrec_bridge *br_int,
                         struct ovs_chassis_cfg *ovs_cfg)
{
    const struct ovsrec_open_vswitch *cfg =
        ovsrec_open_vswitch_table_first(ovs_table);

    if (!cfg) {
        VLOG_INFO("No Open_vSwitch row defined.");
        return false;
    }

    const char *chassis_id = get_ovs_chassis_id(ovs_table);
    const char *encap_type =
        get_chassis_external_id_value(&cfg->external_ids, chassis_id,
                                      "ovn-encap-type", NULL);

    const char *encap_ips =
        get_chassis_external_id_value(&cfg->external_ids, chassis_id,
                                      "ovn-encap-ip", NULL);
    if (!encap_type || !encap_ips) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_INFO_RL(&rl, "Need to specify an encap type and ip");
        return false;
    }

    ovs_cfg->hostname = get_hostname(&cfg->external_ids, chassis_id);
    ovs_cfg->bridge_mappings =
        get_bridge_mappings(&cfg->external_ids, chassis_id);
    ovs_cfg->datapath_type = get_datapath_type(br_int);
    ovs_cfg->encap_csum = get_encap_csum(&cfg->external_ids, chassis_id);
    ovs_cfg->cms_options = get_cms_options(&cfg->external_ids, chassis_id);
    ovs_cfg->monitor_all = get_monitor_all(&cfg->external_ids, chassis_id);
    ovs_cfg->chassis_macs =
        get_chassis_mac_mappings(&cfg->external_ids, chassis_id);
    ovs_cfg->enable_lflow_cache =
        get_enable_lflow_cache(&cfg->external_ids, chassis_id);
    ovs_cfg->limit_lflow_cache =
        get_limit_lflow_cache(&cfg->external_ids, chassis_id);
    ovs_cfg->memlimit_lflow_cache =
        get_memlimit_lflow_cache(&cfg->external_ids, chassis_id);
    ovs_cfg->trim_limit_lflow_cache =
        get_trim_limit_lflow_cache(&cfg->external_ids, chassis_id);
    ovs_cfg->trim_wmark_perc_lflow_cache =
        get_trim_wmark_perc_lflow_cache(&cfg->external_ids, chassis_id);
    ovs_cfg->trim_timeout_ms =
        get_trim_timeout(&cfg->external_ids, chassis_id);

    chassis_parse_ovs_encap_type(encap_type, &ovs_cfg->encap_type_set);

    /* 'ovn-encap-ip' can accept a comma-delimited list of IP addresses instead
     * of a single IP address. Although this is undocumented, it can be used
     * to enable certain hardware-offloaded use cases in which a host has
     * multiple NICs and is assigning SR-IOV VFs to a guest (as logical ports).
     */
    chassis_parse_ovs_encap_ip(encap_ips, &ovs_cfg->encap_ip_set);

    chassis_parse_ovs_iface_types(cfg->iface_types, cfg->n_iface_types,
                                  &ovs_cfg->iface_types);

    ovs_cfg->is_interconn = get_is_interconn(&cfg->external_ids, chassis_id);

    return true;
}

static void
chassis_build_other_config(const struct ovs_chassis_cfg *ovs_cfg,
                           struct smap *config)
{
    smap_replace(config, "ovn-bridge-mappings", ovs_cfg->bridge_mappings);
    smap_replace(config, "datapath-type", ovs_cfg->datapath_type);
    smap_replace(config, "ovn-cms-options", ovs_cfg->cms_options);
    smap_replace(config, "ovn-monitor-all", ovs_cfg->monitor_all);
    smap_replace(config, "ovn-enable-lflow-cache",
                 ovs_cfg->enable_lflow_cache);
    smap_replace(config, "ovn-limit-lflow-cache", ovs_cfg->limit_lflow_cache);
    smap_replace(config, "ovn-memlimit-lflow-cache-kb",
                 ovs_cfg->memlimit_lflow_cache);
    smap_replace(config, "ovn-trim-limit-lflow-cache",
                 ovs_cfg->trim_limit_lflow_cache);
    smap_replace(config, "ovn-trim-wmark-perc-lflow-cache",
                 ovs_cfg->trim_wmark_perc_lflow_cache);
    smap_replace(config, "ovn-trim-timeout-ms", ovs_cfg->trim_timeout_ms);
    smap_replace(config, "iface-types", ds_cstr_ro(&ovs_cfg->iface_types));
    smap_replace(config, "ovn-chassis-mac-mappings", ovs_cfg->chassis_macs);
    smap_replace(config, "is-interconn",
                 ovs_cfg->is_interconn ? "true" : "false");
    smap_replace(config, OVN_FEATURE_PORT_UP_NOTIF, "true");
    smap_replace(config, OVN_FEATURE_CT_NO_MASKED_LABEL, "true");
    smap_replace(config, OVN_FEATURE_MAC_BINDING_TIMESTAMP, "true");
    smap_replace(config, OVN_FEATURE_CT_LB_RELATED, "true");
}

/*
 * Returns true if any external-id doesn't match the values in 'chassis-rec'.
 */
static bool
chassis_other_config_changed(const struct ovs_chassis_cfg *ovs_cfg,
                             const struct sbrec_chassis *chassis_rec)
{
    const char *chassis_bridge_mappings =
        get_bridge_mappings(&chassis_rec->other_config, chassis_rec->name);

    if (strcmp(ovs_cfg->bridge_mappings, chassis_bridge_mappings)) {
        return true;
    }

    const char *chassis_datapath_type =
        smap_get_def(&chassis_rec->other_config, "datapath-type", "");

    if (strcmp(ovs_cfg->datapath_type, chassis_datapath_type)) {
        return true;
    }

    const char *chassis_cms_options =
        get_cms_options(&chassis_rec->other_config, chassis_rec->name);

    if (strcmp(ovs_cfg->cms_options, chassis_cms_options)) {
        return true;
    }

    const char *chassis_monitor_all =
        get_monitor_all(&chassis_rec->other_config, chassis_rec->name);

    if (strcmp(ovs_cfg->monitor_all, chassis_monitor_all)) {
        return true;
    }

    const char *chassis_enable_lflow_cache =
        get_enable_lflow_cache(&chassis_rec->other_config, chassis_rec->name);

    if (strcmp(ovs_cfg->enable_lflow_cache, chassis_enable_lflow_cache)) {
        return true;
    }

    const char *chassis_limit_lflow_cache =
        get_limit_lflow_cache(&chassis_rec->other_config, chassis_rec->name);

    if (strcmp(ovs_cfg->limit_lflow_cache, chassis_limit_lflow_cache)) {
        return true;
    }

    const char *chassis_memlimit_lflow_cache =
        get_memlimit_lflow_cache(&chassis_rec->other_config,
                                 chassis_rec->name);

    if (strcmp(ovs_cfg->memlimit_lflow_cache, chassis_memlimit_lflow_cache)) {
        return true;
    }

    const char *chassis_trim_limit_lflow_cache =
        get_trim_limit_lflow_cache(&chassis_rec->other_config,
                                   chassis_rec->name);

    if (strcmp(ovs_cfg->trim_limit_lflow_cache,
               chassis_trim_limit_lflow_cache)) {
        return true;
    }

    const char *chassis_trim_wmark_perc_lflow_cache =
        get_trim_wmark_perc_lflow_cache(
            &chassis_rec->other_config, chassis_rec->name);

    if (strcmp(ovs_cfg->trim_wmark_perc_lflow_cache,
               chassis_trim_wmark_perc_lflow_cache)) {
        return true;
    }

    const char *chassis_trim_timeout_ms =
        get_trim_timeout(&chassis_rec->other_config, chassis_rec->name);

    if (strcmp(ovs_cfg->trim_timeout_ms, chassis_trim_timeout_ms)) {
        return true;
    }

    const char *chassis_mac_mappings =
        get_chassis_mac_mappings(&chassis_rec->other_config,
                                 chassis_rec->name);
    if (strcmp(ovs_cfg->chassis_macs, chassis_mac_mappings)) {
        return true;
    }

    const char *chassis_iface_types =
        smap_get_def(&chassis_rec->other_config, "iface-types", "");

    if (strcmp(ds_cstr_ro(&ovs_cfg->iface_types), chassis_iface_types)) {
        return true;
    }

    bool chassis_is_interconn =
        smap_get_bool(&chassis_rec->other_config, "is-interconn", false);
    if (chassis_is_interconn != ovs_cfg->is_interconn) {
        return true;
    }

    if (!smap_get_bool(&chassis_rec->other_config, OVN_FEATURE_PORT_UP_NOTIF,
                       false)) {
        return true;
    }

    if (!smap_get_bool(&chassis_rec->other_config,
                       OVN_FEATURE_CT_NO_MASKED_LABEL,
                       false)) {
        return true;
    }

    if (!smap_get_bool(&chassis_rec->other_config,
                       OVN_FEATURE_MAC_BINDING_TIMESTAMP,
                       false)) {
        return true;
    }

    if (!smap_get_bool(&chassis_rec->other_config,
                       OVN_FEATURE_CT_LB_RELATED,
                       false)) {
        return true;
    }

    return false;
}

/*
 * Returns true if the tunnel config obtained by combining 'encap_type_set'
 * with 'encap_ip_set' and 'encap_csum' doesn't match the values in
 * 'chassis-rec'.
 */
static bool
chassis_tunnels_changed(const struct sset *encap_type_set,
                        const struct sset *encap_ip_set,
                        const char *encap_csum,
                        const struct sbrec_chassis *chassis_rec)
{
    struct sset chassis_rec_encap_type_set =
        SSET_INITIALIZER(&chassis_rec_encap_type_set);
    bool  changed = false;

    for (size_t i = 0; i < chassis_rec->n_encaps; i++) {
        if (strcmp(chassis_rec->name, chassis_rec->encaps[i]->chassis_name)) {
            return true;
        }

        if (!sset_contains(encap_type_set, chassis_rec->encaps[i]->type)) {
            changed = true;
            break;
        }
        sset_add(&chassis_rec_encap_type_set, chassis_rec->encaps[i]->type);

        if (!sset_contains(encap_ip_set, chassis_rec->encaps[i]->ip)) {
            changed = true;
            break;
        }

        if (strcmp(smap_get_def(&chassis_rec->encaps[i]->options, "csum", ""),
                   encap_csum)) {
            changed = true;
            break;
        }
    }

    if (!changed) {
        size_t tunnel_count =
            sset_count(encap_type_set) * sset_count(encap_ip_set);

        if (tunnel_count != chassis_rec->n_encaps) {
            changed = true;
        }
    }

    if (!changed) {
        if (sset_count(encap_type_set) !=
                sset_count(&chassis_rec_encap_type_set)) {
            changed = true;
        }
    }

    sset_destroy(&chassis_rec_encap_type_set);
    return changed;
}

/*
 * Build the new encaps config (full mesh of 'encap_type_set' and
 * 'encap_ip_set'). Allocates and stores the new 'n_encap' Encap records in
 * 'encaps'.
 */
static struct sbrec_encap **
chassis_build_encaps(struct ovsdb_idl_txn *ovnsb_idl_txn,
                     const struct sset *encap_type_set,
                     const struct sset *encap_ip_set,
                     const char *chassis_id,
                     const char *encap_csum,
                     size_t *n_encap)
{
    size_t tunnel_count = 0;

    struct sbrec_encap **encaps =
        xmalloc(sset_count(encap_type_set) * sset_count(encap_ip_set) *
                sizeof(*encaps));
    const struct smap options = SMAP_CONST1(&options, "csum", encap_csum);

    const char *encap_ip;
    const char *encap_type;

    SSET_FOR_EACH (encap_ip, encap_ip_set) {
        SSET_FOR_EACH (encap_type, encap_type_set) {
            struct sbrec_encap *encap = sbrec_encap_insert(ovnsb_idl_txn);

            sbrec_encap_set_type(encap, encap_type);
            sbrec_encap_set_ip(encap, encap_ip);
            sbrec_encap_set_options(encap, &options);
            sbrec_encap_set_chassis_name(encap, chassis_id);

            encaps[tunnel_count] = encap;
            tunnel_count++;
        }
    }

    *n_encap = tunnel_count;
    return encaps;
}

/* 'struct sset' of all supported options in other_confing. Anything missing
 * in this set will be removed from the chassis configuration. */
static void
update_supported_sset(struct sset *supported)
{
    /* OvS external_ids. */
    sset_add(supported, "ovn-bridge-mappings");
    sset_add(supported, "datapath-type");
    sset_add(supported, "ovn-cms-options");
    sset_add(supported, "ovn-monitor-all");
    sset_add(supported, "ovn-enable-lflow-cache");
    sset_add(supported, "ovn-limit-lflow-cache");
    sset_add(supported, "ovn-memlimit-lflow-cache-kb");
    sset_add(supported, "ovn-trim-limit-lflow-cache");
    sset_add(supported, "ovn-trim-wmark-perc-lflow-cache");
    sset_add(supported, "ovn-trim-timeout-ms");
    sset_add(supported, "iface-types");
    sset_add(supported, "ovn-chassis-mac-mappings");
    sset_add(supported, "is-interconn");

    /* Internal options. */
    sset_add(supported, "is-vtep");
    sset_add(supported, "is-remote");
    sset_add(supported, OVN_FEATURE_PORT_UP_NOTIF);
    sset_add(supported, OVN_FEATURE_CT_NO_MASKED_LABEL);
    sset_add(supported, OVN_FEATURE_MAC_BINDING_TIMESTAMP);
    sset_add(supported, OVN_FEATURE_CT_LB_RELATED);
}

static void
remove_unsupported_options(const struct sbrec_chassis *chassis_rec,
                           bool *updated)
{
    struct sset supported_options = SSET_INITIALIZER(&supported_options);
    update_supported_sset(&supported_options);

    const struct smap_node *node;
    SMAP_FOR_EACH (node, &chassis_rec->other_config) {
        if (!sset_contains(&supported_options, node->key)) {
            VLOG_WARN("Removing unsupported key \"%s\" from chassis record.",
                      node->key);
            sbrec_chassis_update_other_config_delkey(chassis_rec, node->key);
            *updated = true;
        }
    }

    sset_destroy(&supported_options);
}

/* If this is a chassis config update after we initialized the record once
 * then we should always be able to find it with the ID we saved in
 * chassis_state.
 * Otherwise (i.e., first time we create the record or if the system-id
 * changed) we create a new record.
 *
 * Sets '*chassis_rec' to point to the local chassis record.
 * Returns true if this record was already in the database, false if it was
 * just inserted.
 */
static bool
chassis_get_record(struct ovsdb_idl_txn *ovnsb_idl_txn,
                   struct ovsdb_idl_index *sbrec_chassis_by_name,
                   const char *chassis_id,
                   const struct sbrec_chassis **chassis_rec)
{
    const struct sbrec_chassis *chassis =
        chassis_lookup_by_name(sbrec_chassis_by_name, chassis_id);

    if (!chassis && ovnsb_idl_txn) {
        /* Create the chassis record. */
        VLOG_DBG("Could not find Chassis, will create it: %s", chassis_id);
        *chassis_rec = sbrec_chassis_insert(ovnsb_idl_txn);
        return false;
    }

    *chassis_rec = chassis;
    return true;
}

/* Update a Chassis record based on the config in the ovs config.
 * Returns true if 'chassis_rec' was updated, false otherwise.
 */
static bool
chassis_update(const struct sbrec_chassis *chassis_rec,
               struct ovsdb_idl_txn *ovnsb_idl_txn,
               const struct ovs_chassis_cfg *ovs_cfg,
               const char *chassis_id,
               const struct sset *transport_zones)
{
    bool updated = false;

    if (strcmp(chassis_id, chassis_rec->name)) {
        sbrec_chassis_set_name(chassis_rec, chassis_id);
        updated = true;
    }

    if (strcmp(ovs_cfg->hostname, chassis_rec->hostname)) {
        sbrec_chassis_set_hostname(chassis_rec, ovs_cfg->hostname);
        updated = true;
    }

    if (chassis_other_config_changed(ovs_cfg, chassis_rec)) {
        struct smap other_config;

        smap_clone(&other_config, &chassis_rec->other_config);
        chassis_build_other_config(ovs_cfg, &other_config);
        sbrec_chassis_verify_other_config(chassis_rec);
        sbrec_chassis_set_other_config(chassis_rec, &other_config);
        smap_destroy(&other_config);
        updated = true;
    }

    update_chassis_transport_zones(transport_zones, chassis_rec);

    remove_unsupported_options(chassis_rec, &updated);

    /* If any of the encaps should change, update them. */
    bool tunnels_changed =
        chassis_tunnels_changed(&ovs_cfg->encap_type_set,
                                &ovs_cfg->encap_ip_set, ovs_cfg->encap_csum,
                                chassis_rec);
    if (!tunnels_changed) {
        return updated;
    }

    struct sbrec_encap **encaps;
    size_t n_encap;

    encaps =
        chassis_build_encaps(ovnsb_idl_txn, &ovs_cfg->encap_type_set,
                             &ovs_cfg->encap_ip_set, chassis_id,
                             ovs_cfg->encap_csum, &n_encap);
    sbrec_chassis_set_encaps(chassis_rec, encaps, n_encap);
    free(encaps);
    return true;
}

/* If this is a chassis_private config update after we initialized the record
 * once then we should always be able to find it with the ID we saved in
 * chassis_state.
 * Otherwise (i.e., first time we created the chassis record or if the
 * system-id changed) we create a new record.
 *
 * Returns the local chassis record.
 */
static const struct sbrec_chassis_private *
chassis_private_get_record(
    struct ovsdb_idl_txn *ovnsb_idl_txn,
    struct ovsdb_idl_index *sbrec_chassis_pvt_by_name,
    const char *chassis_id)
{
    const struct sbrec_chassis_private *chassis_p =
            chassis_private_lookup_by_name(sbrec_chassis_pvt_by_name,
                                           chassis_id);

    if (!chassis_p) {
        return sbrec_chassis_private_insert(ovnsb_idl_txn);
    }

    return chassis_p;
}

static void
chassis_private_update(const struct sbrec_chassis_private *chassis_pvt,
                       const struct sbrec_chassis *chassis,
                       const char *chassis_id)
{
    if (!chassis_pvt->name || strcmp(chassis_pvt->name, chassis_id)) {
        sbrec_chassis_private_set_name(chassis_pvt, chassis_id);
    }

    if (chassis_pvt->chassis != chassis) {
        sbrec_chassis_private_set_chassis(chassis_pvt, chassis);
    }
}

/* Returns this chassis's Chassis record, if it is available. */
const struct sbrec_chassis *
chassis_run(struct ovsdb_idl_txn *ovnsb_idl_txn,
            struct ovsdb_idl_index *sbrec_chassis_by_name,
            struct ovsdb_idl_index *sbrec_chassis_private_by_name,
            const struct ovsrec_open_vswitch_table *ovs_table,
            const char *chassis_id,
            const struct ovsrec_bridge *br_int,
            const struct sset *transport_zones,
            const struct sbrec_chassis_private **chassis_private)
{
    struct ovs_chassis_cfg ovs_cfg;

    *chassis_private = NULL;

    /* Get the chassis config from the ovs table. */
    ovs_chassis_cfg_init(&ovs_cfg);
    if (!chassis_parse_ovs_config(ovs_table, br_int, &ovs_cfg)) {
        return NULL;
    }

    const struct sbrec_chassis *chassis_rec = NULL;
    bool existed = chassis_get_record(ovnsb_idl_txn, sbrec_chassis_by_name,
                                      chassis_id, &chassis_rec);

    /* If we found (or created) a record, update it with the correct config
     * and store the current chassis_id for fast lookup in case it gets
     * modified in the ovs table.
     */
    if (chassis_rec && ovnsb_idl_txn) {
        bool updated = chassis_update(chassis_rec, ovnsb_idl_txn, &ovs_cfg,
                                      chassis_id, transport_zones);

        if (!existed || updated) {
            ovsdb_idl_txn_add_comment(ovnsb_idl_txn,
                                      "ovn-controller: %s chassis '%s'",
                                      !existed ? "registering" : "updating",
                                      chassis_id);
        }

        *chassis_private =
            chassis_private_get_record(ovnsb_idl_txn,
                                       sbrec_chassis_private_by_name,
                                       chassis_id);
        if (*chassis_private) {
            chassis_private_update(*chassis_private, chassis_rec, chassis_id);
        }
    }

    ovs_chassis_cfg_destroy(&ovs_cfg);
    return existed ? chassis_rec : NULL;
}

bool
chassis_get_mac(const struct sbrec_chassis *chassis_rec,
                const char *bridge_mapping,
                struct eth_addr *chassis_mac)
{
    const char *tokens =
        get_chassis_mac_mappings(&chassis_rec->other_config,
                                 chassis_rec->name);
    if (!tokens[0]) {
       return false;
    }

    char *save_ptr = NULL;
    bool ret = false;
    char *tokstr = xstrdup(tokens);

    /* Format for a chassis mac configuration is:
     * ovn-chassis-mac-mappings="bridge-name1:MAC1,bridge-name2:MAC2"
     */
    for (char *token = strtok_r(tokstr, ",", &save_ptr);
         token != NULL;
         token = strtok_r(NULL, ",", &save_ptr)) {
        char *save_ptr2 = NULL;
        char *chassis_mac_bridge = strtok_r(token, ":", &save_ptr2);
        char *chassis_mac_str = strtok_r(NULL, "", &save_ptr2);

        if (!strcmp(chassis_mac_bridge, bridge_mapping)) {
            struct eth_addr temp_mac;

            /* Return the first chassis mac. */
            char *err_str = str_to_mac(chassis_mac_str, &temp_mac);
            if (err_str) {
                free(err_str);
                continue;
            }

            ret = true;
            *chassis_mac = temp_mac;
            break;
        }
    }

    free(tokstr);
    return ret;
}

const char *
get_ovs_chassis_id(const struct ovsrec_open_vswitch_table *ovs_table)
{
    if (cli_system_id) {
        return cli_system_id;
    }

    if (file_system_id) {
        return file_system_id;
    }

    const struct ovsrec_open_vswitch *cfg
        = ovsrec_open_vswitch_table_first(ovs_table);
    const char *chassis_id = cfg ? smap_get(&cfg->external_ids, "system-id")
                                 : NULL;

    if (!chassis_id) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "'system-id' in Open_vSwitch database is missing.");
    }

    return chassis_id;
}

static bool
is_chassis_idx_stored(const struct ovsrec_open_vswitch_table *ovs_table)
{
    const struct ovsrec_open_vswitch *cfg =
        ovsrec_open_vswitch_table_first(ovs_table);
    const char *chassis_id = get_ovs_chassis_id(ovs_table);
    if (!chassis_id) {
        return false;
    }
    char *idx_key = xasprintf(CHASSIS_IDX_PREFIX "%s", chassis_id);
    const char *idx = smap_get(&cfg->other_config, idx_key);
    free(idx_key);
    return !!idx;
}

const char *get_chassis_idx(const struct ovsrec_open_vswitch_table *ovs_table)
{
    const struct ovsrec_open_vswitch *cfg =
        ovsrec_open_vswitch_table_first(ovs_table);
    const char *chassis_id = get_ovs_chassis_id(ovs_table);
    if (!chassis_id) {
        return "";
    }
    char *idx_key = xasprintf(CHASSIS_IDX_PREFIX "%s", chassis_id);
    const char *idx = smap_get_def(&cfg->other_config, idx_key, "");
    free(idx_key);
    return idx;
}

void
store_chassis_index_if_needed(
        const struct ovsrec_open_vswitch_table *ovs_table)
{
    const struct ovsrec_open_vswitch *cfg =
        ovsrec_open_vswitch_table_first(ovs_table);
    const char *chassis_id = get_ovs_chassis_id(ovs_table);

    char *idx_key = xasprintf(CHASSIS_IDX_PREFIX "%s", chassis_id);
    const char *chassis_idx = smap_get(&cfg->other_config, idx_key);
    if (!chassis_idx) {
        /* Collect all indices so far consumed by other chassis. */
        struct sset used_indices = SSET_INITIALIZER(&used_indices);
        struct smap_node *node;
        SMAP_FOR_EACH (node, &cfg->other_config) {
            if (!strncmp(node->key, CHASSIS_IDX_PREFIX,
                    sizeof(CHASSIS_IDX_PREFIX) - 1)) {
                sset_add(&used_indices, node->value);
            }
        }
        /* First chassis on the host: use an empty string to avoid adding an
         * unnecessary index character to tunnel port names when a single
         * controller is running on the host (the most common case). */
        if (!sset_contains(&used_indices, "")) {
            ovsrec_open_vswitch_update_other_config_setkey(
                cfg, idx_key, "");
            goto out;
        }
        /* Next chassis gets an alphanum index allocated. */
        char idx[] = "0";
        for (char i = '0'; i <= '9'; i++) {
            idx[0] = i;
            if (!sset_contains(&used_indices, idx)) {
                ovsrec_open_vswitch_update_other_config_setkey(
                    cfg, idx_key, idx);
                goto out;
            }
        }
        for (char i = 'a'; i <= 'z'; i++) {
            idx[0] = i;
            if (!sset_contains(&used_indices, idx)) {
                ovsrec_open_vswitch_update_other_config_setkey(
                    cfg, idx_key, idx);
                goto out;
            }
        }
        /* All indices consumed: it's safer to just abort. */
        VLOG_ERR("All unique controller indices consumed. Exiting.");
        exit(EXIT_FAILURE);
    }
out:
    free(idx_key);
}

static void
clear_chassis_index_if_needed(
        const struct ovsrec_open_vswitch_table *ovs_table)
{
    const struct ovsrec_open_vswitch *cfg =
        ovsrec_open_vswitch_table_first(ovs_table);
    const char *chassis_id = get_ovs_chassis_id(ovs_table);
    char *idx_key = xasprintf(CHASSIS_IDX_PREFIX "%s", chassis_id);
    if (smap_get(&cfg->other_config, idx_key)) {
        ovsrec_open_vswitch_update_other_config_delkey(cfg, idx_key);
    }
    free(idx_key);
}

/* Returns true if the database is all cleaned up, false if more work is
 * required. */
bool
chassis_cleanup(struct ovsdb_idl_txn *ovs_idl_txn,
                struct ovsdb_idl_txn *ovnsb_idl_txn,
                const struct ovsrec_open_vswitch_table *ovs_table,
                const struct sbrec_chassis *chassis_rec,
                const struct sbrec_chassis_private *chassis_private_rec)
{
    if (!chassis_rec && !chassis_private_rec &&
            !is_chassis_idx_stored(ovs_table)) {
        return true;
    }

    const char *chassis_name = get_ovs_chassis_id(ovs_table);
    if (ovs_idl_txn) {
        ovsdb_idl_txn_add_comment(
            ovs_idl_txn,
            "ovn-controller: unregistering chassis index for '%s'",
            chassis_name);
        clear_chassis_index_if_needed(ovs_table);
    }

    if (ovnsb_idl_txn) {
        ovsdb_idl_txn_add_comment(ovnsb_idl_txn,
                                  "ovn-controller: unregistering chassis '%s'",
                                  chassis_name);
        if (chassis_rec) {
            sbrec_chassis_delete(chassis_rec);
        }
        if (chassis_private_rec) {
            sbrec_chassis_private_delete(chassis_private_rec);
        }
    }
    return false;
}
