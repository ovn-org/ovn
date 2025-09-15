#ifndef EN_GLOBAL_CONFIG_H
#define EN_GLOBAL_CONFIG_H 1

#include <config.h>

/* OVS includes. */
#include "lib/packets.h"
#include "lib/smap.h"

/* OVN includes. */
#include "lib/inc-proc-eng.h"

struct nbrec_nb_global;
struct sbrec_sb_global;

struct chassis_features {
    bool mac_binding_timestamp;
    bool fdb_timestamp;
    bool ls_dpg_column;
    bool ct_commit_nat_v2;
    bool ct_commit_to_zone;
    bool sample_with_reg;
    bool ct_next_zone;
    bool ct_label_flush;
    bool ct_state_save;
};

struct global_config_tracked_data {
    bool nb_options_changed;
    bool chassis_features_changed;
};

/* struct which maintains the data of the engine node global_config. */
struct ed_type_global_config {
    struct smap nb_options;
    struct smap sb_options;
    const struct nbrec_nb_global *nb_global;
    const struct sbrec_sb_global *sb_global;

    /* MAC allocated for service monitor usage. Just one pair is allocated
     * for this purpose and ovn-controller's on each chassis will make use
     * of this pair when sending out the packets to monitor the services
     * defined in Service_Monitor Southbound table. Since these packets
     * are locally handled, having just one pair is good enough. */
    char svc_monitor_mac[ETH_ADDR_STRLEN + 1];
    struct eth_addr svc_monitor_mac_ea;
    char svc_monitor_mac_dst[ETH_ADDR_STRLEN + 1];
    struct eth_addr svc_monitor_mac_ea_dst;

    /* IP addresses configured for NF service monitor usage. */
    char *svc_monitor_ip;
    char *svc_monitor_ip_dst;

    struct chassis_features features;

    bool ovn_internal_version_changed;

    bool vxlan_mode;
    uint32_t max_dp_tunnel_id;

    bool tracked;
    struct global_config_tracked_data tracked_data;
};

void *en_global_config_init(struct engine_node *, struct engine_arg *);
enum engine_node_state en_global_config_run(struct engine_node *, void *data);
void en_global_config_cleanup(void *data);
void en_global_config_clear_tracked_data(void *data);

enum engine_input_handler_result
global_config_nb_global_handler(struct engine_node *, void *data);
enum engine_input_handler_result
global_config_sb_global_handler(struct engine_node *, void *data);
enum engine_input_handler_result
global_config_sb_chassis_handler(struct engine_node *, void *data);
enum engine_input_handler_result
global_config_nb_logical_switch_handler(struct engine_node *node, void *data);

/* generic global config handler for any engine node which has global_config
 * has an input node . */
enum engine_input_handler_result
node_global_config_handler(struct engine_node *, void *data);

#endif /* EN_GLOBAL_CONFIG_H */
