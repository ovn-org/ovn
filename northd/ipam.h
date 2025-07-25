#ifndef NORTHD_IPAM_H
#define NORTHD_IPAM_H 1

#include <stdint.h>
#include <stdbool.h>

#include "openvswitch/types.h"
#include "lib/vec.h"
#include "lib/ovn-util.h"

struct ipam_info {
    uint32_t start_ipv4;
    size_t total_ipv4s;
    unsigned long *allocated_ipv4s; /* A bitmap of allocated IPv4s */
    bool ipv6_prefix_set;
    struct in6_addr ipv6_prefix;
    bool mac_only;
    const char *id;
};

struct smap;
struct ovn_datapath;
struct ovn_port;


enum dynamic_update_type {
    NONE,    /* No change to the address */
    REMOVE,  /* Address is no longer dynamic */
    STATIC,  /* Use static address (MAC only) */
    DYNAMIC, /* Assign a new dynamic address */
};

struct dynamic_address_update {
    struct ovn_datapath *od;
    struct ovn_port *op;

    struct lport_addresses current_addresses;
    struct eth_addr static_mac;
    ovs_be32 static_ip;
    struct in6_addr static_ipv6;
    enum dynamic_update_type mac;
    enum dynamic_update_type ipv4;
    enum dynamic_update_type ipv6;
};

void init_ipam_info(struct ipam_info *info, const struct smap *config,
                    const char *id);


void init_ipam_info_for_datapath(struct ovn_datapath *od);

void destroy_ipam_info(struct ipam_info *info);

bool ipam_insert_ip(struct ipam_info *info, uint32_t ip, bool dynamic);

uint32_t ipam_get_unused_ip(struct ipam_info *info);

void ipam_insert_mac(struct eth_addr *ea, bool check);

uint64_t ipam_get_unused_mac(ovs_be32 ip);

void cleanup_macam(void);

struct eth_addr get_mac_prefix(void);

const char *set_mac_prefix(const char *hint);

void update_ipam_ls(struct ovn_datapath *, struct vector *, bool);

void update_dynamic_addresses(struct dynamic_address_update *);

void ipam_add_port_addresses(struct ovn_datapath *, struct ovn_port *);

#endif /* NORTHD_IPAM_H */
