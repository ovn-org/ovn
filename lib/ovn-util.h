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


#ifndef OVN_UTIL_H
#define OVN_UTIL_H 1

#include "ovsdb-idl.h"
#include "lib/packets.h"
#include "lib/sset.h"
#include "lib/svec.h"
#include "include/ovn/version.h"

#define ovn_set_program_name(name) \
    ovs_set_program_name(name, OVN_PACKAGE_VERSION)

#define ovn_print_version(MIN_OFP, MAX_OFP) \
    ovs_print_version(MIN_OFP, MAX_OFP)

#define ROUTE_ORIGIN_CONNECTED "connected"
#define ROUTE_ORIGIN_STATIC "static"

#define ETH_CRC_LENGTH 4
#define ETHERNET_OVERHEAD (ETH_HEADER_LEN + ETH_CRC_LENGTH)

#define GENEVE_TUNNEL_OVERHEAD 38
#define STT_TUNNEL_OVERHEAD 18
#define VXLAN_TUNNEL_OVERHEAD 30

struct eth_addr;
struct nbrec_logical_router_port;
struct ovsrec_flow_sample_collector_set_table;
struct sbrec_datapath_binding;
struct sbrec_logical_flow;
struct sbrec_port_binding;
struct smap;
struct svec;
struct uuid;
struct unixctl_conn;

struct ipv4_netaddr {
    ovs_be32 addr;            /* 192.168.10.123 */
    ovs_be32 mask;            /* 255.255.255.0 */
    ovs_be32 network;         /* 192.168.10.0 */
    unsigned int plen;        /* CIDR Prefix: 24. */

    char addr_s[INET_ADDRSTRLEN + 1];     /* "192.168.10.123" */
    char network_s[INET_ADDRSTRLEN + 1];  /* "192.168.10.0" */
    char bcast_s[INET_ADDRSTRLEN + 1];    /* "192.168.10.255" */
};

struct ipv6_netaddr {
    struct in6_addr addr;     /* fc00::1 */
    struct in6_addr mask;     /* ffff:ffff:ffff:ffff:: */
    struct in6_addr sn_addr;  /* ff02:1:ff00::1 */
    struct in6_addr network;  /* fc00:: */
    unsigned int plen;        /* CIDR Prefix: 64 */

    char addr_s[INET6_ADDRSTRLEN + 1];    /* "fc00::1" */
    char sn_addr_s[INET6_ADDRSTRLEN + 1]; /* "ff02:1:ff00::1" */
    char network_s[INET6_ADDRSTRLEN + 1]; /* "fc00::" */
};

struct lport_addresses {
    char ea_s[ETH_ADDR_STRLEN + 1];
    struct eth_addr ea;
    size_t n_ipv4_addrs;
    struct ipv4_netaddr *ipv4_addrs;
    size_t n_ipv6_addrs;
    struct ipv6_netaddr *ipv6_addrs;
};

static inline bool
ipv6_is_all_router(const struct in6_addr *addr)
{
    return ipv6_addr_equals(addr, &in6addr_all_routers);
}

static const struct in6_addr in6addr_all_site_routers = {{{
    0xff,0x05,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
}}};

static inline bool
ipv6_is_all_site_router(const struct in6_addr *addr)
{
    return ipv6_addr_equals(addr, &in6addr_all_site_routers);
}

bool is_dynamic_lsp_address(const char *address);
bool extract_addresses(const char *address, struct lport_addresses *,
                       int *ofs);
bool extract_lsp_addresses(const char *address, struct lport_addresses *);
bool extract_ip_addresses(const char *address, struct lport_addresses *);
bool extract_ip_address(const char *address, struct lport_addresses *);
bool extract_lrp_networks(const struct nbrec_logical_router_port *,
                          struct lport_addresses *);
bool extract_sbrec_binding_first_mac(const struct sbrec_port_binding *binding,
                                     struct eth_addr *ea);

bool extract_lrp_networks__(char *mac, char **networks, size_t n_networks,
                            struct lport_addresses *laddrs);

bool lport_addresses_is_empty(struct lport_addresses *);
void destroy_lport_addresses(struct lport_addresses *);
const char *find_lport_address(const struct lport_addresses *laddrs,
                               const char *ip_s);

void split_addresses(const char *addresses, struct svec *ipv4_addrs,
                     struct svec *ipv6_addrs);

char *alloc_nat_zone_key(const char *name, const char *type);

const char *default_nb_db(void);
const char *default_sb_db(void);
const char *default_ic_nb_db(void);
const char *default_ic_sb_db(void);
char *get_abs_unix_ctl_path(const char *path);

struct ovsdb_idl_table_class;
const char *db_table_usage(struct ds *tables,
                           const struct ovsdb_idl_table_class *class,
                           int n_tables);

bool ovn_is_known_nb_lsp_type(const char *type);

/* The two pipelines in an OVN logical flow table. */
enum ovn_pipeline {
    P_IN,                       /* Ingress pipeline. */
    P_OUT                       /* Egress pipeline. */
};

uint32_t sbrec_logical_flow_hash(const struct sbrec_logical_flow *);
uint32_t ovn_logical_flow_hash(uint8_t table_id, enum ovn_pipeline pipeline,
                               uint16_t priority,
                               const char *match, const char *actions);
uint32_t ovn_logical_flow_hash_datapath(const struct uuid *logical_datapath,
                                        uint32_t hash);
void ovn_conn_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *idl_);

void set_idl_probe_interval(struct ovsdb_idl *idl, const char *remote,
                            int interval);

#define OVN_MAX_DP_KEY ((1u << 24) - 1)
#define OVN_MAX_DP_GLOBAL_NUM ((1u << 16) - 1)
#define OVN_MIN_DP_KEY_LOCAL 1
#define OVN_MAX_DP_KEY_LOCAL (OVN_MAX_DP_KEY - OVN_MAX_DP_GLOBAL_NUM)
#define OVN_MIN_DP_KEY_GLOBAL (OVN_MAX_DP_KEY_LOCAL + 1)
#define OVN_MAX_DP_KEY_GLOBAL OVN_MAX_DP_KEY

#define OVN_MAX_DP_VXLAN_KEY ((1u << 12) - 1)
#define OVN_MAX_DP_VXLAN_KEY_LOCAL (OVN_MAX_DP_KEY - OVN_MAX_DP_GLOBAL_NUM)

struct hmap;
void ovn_destroy_tnlids(struct hmap *tnlids);
bool ovn_add_tnlid(struct hmap *set, uint32_t tnlid);
bool ovn_tnlid_present(struct hmap *tnlids, uint32_t tnlid);
uint32_t ovn_allocate_tnlid(struct hmap *set, const char *name, uint32_t min,
                            uint32_t max, uint32_t *hint);
bool ovn_free_tnlid(struct hmap *tnlids, uint32_t tnlid);

static inline void
get_unique_lport_key(uint64_t dp_tunnel_key, uint64_t lport_tunnel_key,
                     char *buf, size_t buf_size)
{
    snprintf(buf, buf_size, "%"PRId64"_%"PRId64, dp_tunnel_key,
             lport_tunnel_key);
}

static inline void
get_mc_group_key(const char *mg_name, int64_t dp_tunnel_key,
                 struct ds *mg_key)
{
    ds_clear(mg_key);
    ds_put_format(mg_key, "%"PRId64"_%s", dp_tunnel_key, mg_name);
}

static inline void
get_sb_port_group_name(const char *nb_pg_name, int64_t dp_tunnel_key,
                       struct ds *sb_pg_name)
{
    ds_clear(sb_pg_name);
    ds_put_format(sb_pg_name, "%"PRId64"_%s", dp_tunnel_key, nb_pg_name);
}

char *ovn_chassis_redirect_name(const char *port_name);
void ovn_set_pidfile(const char *name);

bool ip46_parse_cidr(const char *str, struct in6_addr *prefix,
                     unsigned int *plen);
bool ip46_parse(const char *ip_str, struct in6_addr *ip);

char *normalize_ipv4_prefix(ovs_be32 ipv4, unsigned int plen);
char *normalize_ipv6_prefix(const struct in6_addr *ipv6, unsigned int plen);
char *normalize_v46_prefix(const struct in6_addr *prefix, unsigned int plen);

/* Temporary util function until ovs library has smap_get_unit. */
unsigned int ovn_smap_get_uint(const struct smap *smap, const char *key,
                               unsigned int def);

/* Returns a lowercase copy of orig.
 * Caller must free the returned string.
 */
char *str_tolower(const char *orig);

/* OVN daemon options. Taken from ovs/lib/daemon.h. */
#define OVN_DAEMON_OPTION_ENUMS                     \
    OVN_OPT_DETACH,                                 \
    OVN_OPT_NO_SELF_CONFINEMENT,                    \
    OVN_OPT_NO_CHDIR,                               \
    OVN_OPT_OVERWRITE_PIDFILE,                      \
    OVN_OPT_PIDFILE,                                \
    OVN_OPT_MONITOR,                                \
    OVN_OPT_USER_GROUP

#define OVN_DAEMON_LONG_OPTIONS                                              \
        {"detach",            no_argument, NULL, OVN_OPT_DETACH},            \
        {"no-self-confinement", no_argument, NULL,                           \
         OVN_OPT_NO_SELF_CONFINEMENT},                                       \
        {"no-chdir",          no_argument, NULL, OVN_OPT_NO_CHDIR},          \
        {"pidfile",           optional_argument, NULL, OVN_OPT_PIDFILE},     \
        {"overwrite-pidfile", no_argument, NULL, OVN_OPT_OVERWRITE_PIDFILE}, \
        {"monitor",           no_argument, NULL, OVN_OPT_MONITOR},           \
        {"user",              required_argument, NULL, OVN_OPT_USER_GROUP}

#define OVN_DAEMON_OPTION_HANDLERS                  \
        case OVN_OPT_DETACH:                        \
            set_detach();                           \
            break;                                  \
                                                    \
        case OVN_OPT_NO_SELF_CONFINEMENT:           \
            daemon_disable_self_confinement();      \
            break;                                  \
                                                    \
        case OVN_OPT_NO_CHDIR:                      \
            set_no_chdir();                         \
            break;                                  \
                                                    \
        case OVN_OPT_PIDFILE:                       \
            ovn_set_pidfile(optarg);                \
            break;                                  \
                                                    \
        case OVN_OPT_OVERWRITE_PIDFILE:             \
            ignore_existing_pidfile();              \
            break;                                  \
                                                    \
        case OVN_OPT_MONITOR:                       \
            daemon_set_monitor();                   \
            break;                                  \
                                                    \
        case OVN_OPT_USER_GROUP:                    \
            daemon_set_new_user(optarg);            \
            break;

#define OVN_DAEMON_OPTION_CASES                     \
        case OVN_OPT_DETACH:                        \
        case OVN_OPT_NO_SELF_CONFINEMENT:           \
        case OVN_OPT_NO_CHDIR:                      \
        case OVN_OPT_PIDFILE:                       \
        case OVN_OPT_OVERWRITE_PIDFILE:             \
        case OVN_OPT_MONITOR:                       \
        case OVN_OPT_USER_GROUP:

bool ip_address_and_port_from_lb_key(const char *key, char **ip_address,
                                     struct in6_addr *ip, uint16_t *port,
                                     int *addr_family);

/* Returns the internal OVN version. The caller must free the returned
 * value. */
char *ovn_get_internal_version(void);

/* OVN Packet definitions. These may eventually find a home in OVS's
 * packets.h file. For the time being, they live here because OVN uses them
 * and OVS does not.
 */

#define SCTP_INIT_CHUNK_LEN 16
struct sctp_16aligned_init_chunk {
    ovs_16aligned_be32 initiate_tag;
    ovs_16aligned_be32 a_rwnd;
    ovs_be16 num_outbound_streams;
    ovs_be16 num_inbound_streams;
    ovs_16aligned_be32 initial_tsn;
};
BUILD_ASSERT_DECL(
    SCTP_INIT_CHUNK_LEN == sizeof(struct sctp_16aligned_init_chunk)
);

/* These are the only SCTP chunk types that OVN cares about.
 * There is no need to define the other chunk types until they are
 * needed.
 */
#define SCTP_CHUNK_TYPE_INIT  1
#define SCTP_CHUNK_TYPE_ABORT 6

/* See RFC 4960 Sections 3.3.7 and 8.5.1 for information on this flag. */
#define SCTP_ABORT_CHUNK_FLAG_T (1 << 0)

/* The number of tables for the ingress and egress pipelines. */
#define LOG_PIPELINE_LEN 29

#ifdef DDLOG
void ddlog_warn(const char *msg);
void ddlog_err(const char *msg);
#endif

static inline uint32_t
hash_add_in6_addr(uint32_t hash, const struct in6_addr *addr)
{
    for (uint8_t i = 0; i < 4; i++) {
#ifdef s6_addr32
        hash = hash_add(hash, addr->s6_addr32[i]);
#else
        uint8_t index = i * 4;
        uint32_t part = (uint32_t) addr->s6_addr[index]
            | (uint32_t) addr->s6_addr[index + 1] << 8
            | (uint32_t) addr->s6_addr[index + 2] << 16
            | (uint32_t) addr->s6_addr[index + 3] << 24;
        hash = hash_add(hash, part);
#endif
    }
    return hash;
}

/* Must be a bit-field ordered from most-preferred (higher number) to
 * least-preferred (lower number). */
enum chassis_tunnel_type {
    GENEVE = 1 << 2,
    STT    = 1 << 1,
    VXLAN  = 1 << 0
};

uint32_t get_tunnel_type(const char *name);

struct ovsrec_bridge_table;
const struct ovsrec_bridge *get_bridge(const struct ovsrec_bridge_table *,
                                       const char *br_name);

void daemon_started_recently_countdown(void);
void daemon_started_recently_ignore(void);
bool daemon_started_recently(void);
int64_t daemon_startup_ts(void);

char *lr_lb_address_set_name(uint32_t lr_tunnel_key, int addr_family);
char *lr_lb_address_set_ref(uint32_t lr_tunnel_key, int addr_family);

const char *
get_chassis_external_id_value(const struct smap *,
                              const char *chassis_id,
                              const char *option_key,
                              const char *def);
int
get_chassis_external_id_value_int(const struct smap *,
                                  const char *chassis_id,
                                  const char *option_key,
                                  int def);
unsigned int
get_chassis_external_id_value_uint(const struct smap *,
                                   const char *chassis_id,
                                   const char *option_key,
                                   unsigned int def);
unsigned long long int
get_chassis_external_id_value_ullong(const struct smap *external_ids,
                                     const char *chassis_id,
                                     const char *option_key,
                                     unsigned long long int def);
bool
get_chassis_external_id_value_bool(const struct smap *,
                                   const char *chassis_id,
                                   const char *option_key,
                                   bool def);

/* flow_collector_ids is a helper struct used to store and lookup
 * Flow_Sample_Collector_Set ids. */
struct flow_collector_id {
    struct ovs_list node;  /* In flow_collector_ids->list */
    uint64_t id;
};
struct flow_collector_ids {
    struct ovs_list list;
};
void flow_collector_ids_init(struct flow_collector_ids *);
void flow_collector_ids_init_from_table(struct flow_collector_ids *,
    const struct ovsrec_flow_sample_collector_set_table *);
void flow_collector_ids_add(struct flow_collector_ids *, uint64_t);
bool flow_collector_ids_lookup(const struct flow_collector_ids *, uint32_t);
void flow_collector_ids_destroy(struct flow_collector_ids *);
void flow_collector_ids_clear(struct flow_collector_ids *);

/* The DNS format is 2 bytes longer than the "domain".
 * It replaces every '.' with len of the next name.
 * The returned pointer has to be freed by caller. */
char *encode_fqdn_string(const char *fqdn, size_t *len);

/* Corresponds to each Port_Binding.type. */
enum en_lport_type {
    LP_UNKNOWN,
    LP_VIF,
    LP_CONTAINER,
    LP_PATCH,
    LP_L3GATEWAY,
    LP_LOCALNET,
    LP_LOCALPORT,
    LP_L2GATEWAY,
    LP_VTEP,
    LP_CHASSISREDIRECT,
    LP_VIRTUAL,
    LP_EXTERNAL,
    LP_REMOTE
};

enum en_lport_type get_lport_type(const struct sbrec_port_binding *);
char *get_lport_type_str(enum en_lport_type lport_type);
bool is_pb_router_type(const struct sbrec_port_binding *);

/* A wrapper that holds sorted arrays of strings. */
struct sorted_array {
    const char **arr;
    bool owns_array;
    size_t n;
};

static inline struct sorted_array
sorted_array_create(const char **sorted_data, size_t n, bool take_ownership)
{
    return (struct sorted_array) {
        .arr = sorted_data,
        .owns_array = take_ownership,
        .n = n,
    };
}

static inline void
sorted_array_destroy(struct sorted_array *a)
{
    if (a->owns_array) {
        free(a->arr);
    }
}

static inline struct sorted_array
sorted_array_from_svec(struct svec *v)
{
    svec_sort(v);
    return sorted_array_create((const char **) v->names, v->n, false);
}

static inline struct sorted_array
sorted_array_from_sset(struct sset *s)
{
    return sorted_array_create(sset_sort(s), sset_count(s), true);
}

/* DB set columns are already sorted, just wrap them into a sorted array. */
#define sorted_array_from_dbrec(dbrec, column)           \
    sorted_array_create((const char **) (dbrec)->column, \
                        (dbrec)->n_##column, false)

void sorted_array_apply_diff(const struct sorted_array *a1,
                             const struct sorted_array *a2,
                             void (*apply_callback)(const void *arg,
                                                    const char *item,
                                                    bool add),
                             const void *arg);

/* Utilities around properly handling exit command. */
struct ovn_exit_args {
    struct unixctl_conn **conns;
    size_t n_conns;
    bool exiting;
    bool restart;
};

void ovn_exit_command_callback(struct unixctl_conn *conn, int argc,
                               const char *argv[], void *exit_args_);
void ovn_exit_args_finish(struct ovn_exit_args *exit_args);

#endif /* OVN_UTIL_H */
