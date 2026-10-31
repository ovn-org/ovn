#!/usr/bin/env python3
"""OVN memory and performance regression testing tool.

Creates a broad OVN topology, then exercises incremental engine paths
by adding, modifying, and deleting resources.  Designed to be run via
ovn-benchmark.sh, which measures peak memory, per-phase timing, and
checks for unexpected engine recomputes.  (Run ./ovn-benchmark.sh
--help to see usage).

Topology (simulates the default ovn-kubernetes topology):

         lsp-0-*            lsp-1-*          (Workload ports)
            |                  |
         ls-0               ls-1             (Logical Switches)
            |                  |
         s2c-0/c2s-0        s2c-1/c2s-1
              \\               /
         +--- cluster (LR) ---+              (Cluster Router)
                    |
                sjc/rcj
                    |
         +----  join (LS)  ----+              (Join Switch)
              /               \\
         j2gw-0/gw2j-0     j2gw-1/gw2j-1
            |                  |
         gw-0               gw-1             (Gateway Routers)

  Chassis binding (with batch size B, default n/10):
    chassis-1: c2s-[0..B), gw-[0..B)    (matches sandbox system-id)
    chassis-2: c2s-[B..2B), gw-[B..2B)
    ...

Each node creates a dual-stack gateway router + logical switch pair
with:
  - Dual-stack addressing (IPv4 10.x.x.x/24, IPv6 fd00:x::/64)
  - NAT (SNAT/DNAT/DNAT_AND_SNAT), static routes, routing policies
  - Configurable ports per switch with port security
  - Security: Address sets, port groups, ACLs
  - Services: DHCP, DHCPv6, DNS, load balancers
  - QoS: Bandwidth limiting, DSCP marking

Note: Uses explicit (non-templated) load balancers to maximize memory
usage for regression testing. For templated LB testing, see
ovn-lb-benchmark.py.
"""

import argparse
import sys

import ovs.db.idl
import ovs.poller
import ovs.vlog
from ovs.db import error

vlog = ovs.vlog.Vlog('ovn-benchmark')
vlog.set_levels_from_string('console:warn')
vlog.init(None)

SCHEMA = '../ovn-nb.ovsschema'


def die(msg):
    sys.stderr.write(f'\nError: {msg}\n')
    sys.exit(1)


def ip_node(i):
    """Convert node index to two IP octets, supporting up to 65535 nodes."""
    return f'{i >> 8}.{i & 0xff}'


def ip6_node(i):
    """Convert node index to an IPv6 hextet for ULA addresses."""
    return f'{i:x}'


def create_address_sets(idl, n):
    """Create address sets for security groups."""
    vlog.info(f'Creating address sets: web_servers ({n} v4 + {n} v6), '
              f'db_servers ({n} v4 + {n} v6), app_servers ({n} v4 + {n} v6), '
              f'trusted_networks_v4, trusted_networks_v6')
    txn = ovs.db.idl.Transaction(idl)

    web_as = txn.insert(idl.tables['Address_Set'])
    web_as.name = 'web_servers'
    web_as.addresses = (
        [f'10.{ip_node(i)}.10' for i in range(n)]
        + [f'fd00:{ip6_node(i)}::a' for i in range(n)])

    db_as = txn.insert(idl.tables['Address_Set'])
    db_as.name = 'db_servers'
    db_as.addresses = (
        [f'10.{ip_node(i)}.20' for i in range(n)]
        + [f'fd00:{ip6_node(i)}::14' for i in range(n)])

    app_as = txn.insert(idl.tables['Address_Set'])
    app_as.name = 'app_servers'
    app_as.addresses = (
        [f'10.{ip_node(i)}.30' for i in range(n)]
        + [f'fd00:{ip6_node(i)}::1e' for i in range(n)])

    trusted_as_v4 = txn.insert(idl.tables['Address_Set'])
    trusted_as_v4.name = 'trusted_networks_v4'
    trusted_as_v4.addresses = ['192.168.0.0/16', '172.16.0.0/12']

    trusted_as_v6 = txn.insert(idl.tables['Address_Set'])
    trusted_as_v6.name = 'trusted_networks_v6'
    trusted_as_v6.addresses = ['fc00::/7']

    if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
        die(f'Failed to create address sets ({txn.get_error()})')


def create_port_groups(idl):
    """Create port groups for security group implementation."""
    vlog.info('Creating port groups: web_tier, db_tier, app_tier')
    txn = ovs.db.idl.Transaction(idl)

    web_pg = txn.insert(idl.tables['Port_Group'])
    web_pg.name = 'web_tier'

    db_pg = txn.insert(idl.tables['Port_Group'])
    db_pg.name = 'db_tier'

    app_pg = txn.insert(idl.tables['Port_Group'])
    app_pg.name = 'app_tier'

    if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
        die(f'Failed to create port groups ({txn.get_error()})')


def create_dhcp_options(idl, n):
    """Create DHCP options for each subnet."""
    for i in range(n):
        vlog.info(f'Creating DHCP options for node {i}: '
                  f'10.{ip_node(i)}.0/24, fd00:{ip6_node(i)}::/64')
        txn = ovs.db.idl.Transaction(idl)
        dhcp_opts = txn.insert(idl.tables['DHCP_Options'])
        dhcp_opts.cidr = f'10.{ip_node(i)}.0/24'
        dhcp_opts.setkey('options', 'server_id', f'10.{ip_node(i)}.1')
        dhcp_opts.setkey('options', 'server_mac', '00:00:00:00:00:01')
        dhcp_opts.setkey('options', 'lease_time', '3600')
        dhcp_opts.setkey('options', 'router', f'10.{ip_node(i)}.1')
        dhcp_opts.setkey('options', 'dns_server', f'10.{ip_node(i)}.2')
        dhcp_opts.setkey('options', 'domain_name', '"example.com"')
        dhcp_opts.setkey('options', 'mtu', '1500')
        dhcp_opts.setkey('external_ids', 'subnet', f'ls-{i}')

        dhcpv6_opts = txn.insert(idl.tables['DHCP_Options'])
        dhcpv6_opts.cidr = f'fd00:{ip6_node(i)}::/64'
        dhcpv6_opts.setkey('options', 'server_id',
                           '00:00:00:00:00:01')
        dhcpv6_opts.setkey('options', 'dns_server',
                           f'fd00:{ip6_node(i)}::2')
        dhcpv6_opts.setkey('options', 'domain_search',
                           '"example.com"')
        dhcpv6_opts.setkey('external_ids', 'subnet',
                           f'ls-{i}-v6')

        if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
            die(f'Failed to create DHCP options for node {i} '
                f'({txn.get_error()})')


def create_dhcp_assignments(idl, n):
    """Assign DHCP options to logical switch ports."""
    dhcp4 = {}
    dhcp6 = {}
    for row in idl.tables['DHCP_Options'].rows.values():
        subnet = row.external_ids.get('subnet', '')
        if subnet.endswith('-v6'):
            dhcp6[subnet[:-3]] = row
        else:
            dhcp4[subnet] = row

    for i in range(n):
        vlog.info(f'Assigning DHCP options for node {i}: '
                  f'ls-{i} ports -> 10.{ip_node(i)}.0/24 + '
                  f'fd00:{ip6_node(i)}::/64')
        txn = ovs.db.idl.Transaction(idl)
        opts4 = dhcp4.get(f'ls-{i}')
        opts6 = dhcp6.get(f'ls-{i}')
        for row in idl.tables['Logical_Switch_Port'].rows.values():
            if row.name.startswith(f'lsp-{i}-'):
                if opts4:
                    row.dhcpv4_options = opts4.uuid
                if opts6:
                    row.dhcpv6_options = opts6.uuid
        if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
            die(f'Failed to assign DHCP options for node {i} '
                f'({txn.get_error()})')


def create_qos_rules(idl, n, switches):
    """Create QoS rules for bandwidth limiting and DSCP marking."""
    for i in range(n):
        vlog.info(f'Creating QoS rules for node {i}: '
                  f'rate-limit on lsp-{i}-0, DSCP/mark on ls-{i}')
        txn = ovs.db.idl.Transaction(idl)

        ls = switches.get(f'ls-{i}')
        if not ls:
            die(f'Missing switch ls-{i}')

        qos_bw = txn.insert(idl.tables['QoS'])
        qos_bw.priority = 100
        qos_bw.direction = 'to-lport'
        qos_bw.match = f'inport == "lsp-{i}-0"'
        qos_bw.setkey('bandwidth', 'rate', 1000)
        qos_bw.setkey('bandwidth', 'burst', 100)
        qos_bw.setkey('external_ids', 'type', 'rate-limit')
        ls.addvalue('qos_rules', qos_bw.uuid)

        qos_dscp = txn.insert(idl.tables['QoS'])
        qos_dscp.priority = 200
        qos_dscp.direction = 'from-lport'
        qos_dscp.match = 'ip4 && tcp.dst == 22'
        qos_dscp.setkey('action', 'dscp', 46)
        qos_dscp.setkey('external_ids', 'type', 'dscp-marking')
        ls.addvalue('qos_rules', qos_dscp.uuid)

        qos_mark = txn.insert(idl.tables['QoS'])
        qos_mark.priority = 150
        qos_mark.direction = 'from-lport'
        qos_mark.match = 'ip4 && udp'
        qos_mark.setkey('action', 'mark', 1)
        qos_mark.setkey('external_ids', 'type', 'packet-marking')
        ls.addvalue('qos_rules', qos_mark.uuid)

        qos_dscp_v6 = txn.insert(idl.tables['QoS'])
        qos_dscp_v6.priority = 200
        qos_dscp_v6.direction = 'from-lport'
        qos_dscp_v6.match = 'ip6 && tcp.dst == 22'
        qos_dscp_v6.setkey('action', 'dscp', 46)
        qos_dscp_v6.setkey('external_ids', 'type',
                           'dscp-marking-v6')
        ls.addvalue('qos_rules', qos_dscp_v6.uuid)

        qos_mark_v6 = txn.insert(idl.tables['QoS'])
        qos_mark_v6.priority = 150
        qos_mark_v6.direction = 'from-lport'
        qos_mark_v6.match = 'ip6 && udp'
        qos_mark_v6.setkey('action', 'mark', 1)
        qos_mark_v6.setkey('external_ids', 'type',
                           'packet-marking-v6')
        ls.addvalue('qos_rules', qos_mark_v6.uuid)

        if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
            die(f'Failed to create QoS rules for node {i} ({txn.get_error()})')


def create_acls_for_port_group(idl, port_groups, pg_name, allowed_ports):
    """Create ACLs for a specific port group."""
    txn = ovs.db.idl.Transaction(idl)

    pg = port_groups.get(pg_name)
    if not pg:
        die(f'Missing port group {pg_name}')

    acl_allow_est = txn.insert(idl.tables['ACL'])
    acl_allow_est.priority = 1100
    acl_allow_est.direction = 'to-lport'
    acl_allow_est.match = 'ct.est && !ct.rel && !ct.new && !ct.inv'
    acl_allow_est.action = 'allow-related'
    pg.addvalue('acls', acl_allow_est.uuid)

    acl_allow_rel = txn.insert(idl.tables['ACL'])
    acl_allow_rel.priority = 1100
    acl_allow_rel.direction = 'to-lport'
    acl_allow_rel.match = 'ct.rel && !ct.est && !ct.new && !ct.inv'
    acl_allow_rel.action = 'allow-related'
    pg.addvalue('acls', acl_allow_rel.uuid)

    for port in allowed_ports:
        acl_new = txn.insert(idl.tables['ACL'])
        acl_new.priority = 1050
        acl_new.direction = 'to-lport'
        acl_new.match = f'ct.new && tcp.dst == {port}'
        acl_new.action = 'allow-related'
        pg.addvalue('acls', acl_new.uuid)

    acl_drop = txn.insert(idl.tables['ACL'])
    acl_drop.priority = 1000
    acl_drop.direction = 'to-lport'
    acl_drop.match = f'outport == @{pg_name}'
    acl_drop.action = 'drop'
    pg.addvalue('acls', acl_drop.uuid)

    acl_arp = txn.insert(idl.tables['ACL'])
    acl_arp.priority = 1010
    acl_arp.direction = 'to-lport'
    acl_arp.match = 'arp || nd'
    acl_arp.action = 'allow'
    pg.addvalue('acls', acl_arp.uuid)

    if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
        die(f'Failed to create ACLs for {pg_name} ({txn.get_error()})')


def create_acls(idl, port_groups):
    """Create comprehensive ACLs for port groups.

    ACL Priority Allocation:
      2500-2999: Security enforcement (anti-spoofing, etc.)
      2000-2499: Management access (SSH, ICMP, DHCP)
      1000-1499: Port group ACLs (security groups)
         1100: Connection tracking (established, related)
         1050: New connection per-port rules
         1010: ARP/ND allow
         1000: Default drop

    Switch ACLs (higher priority) can override port-group ACLs, with
    security enforcement (anti-spoofing) taking highest priority.
    """
    vlog.info('Creating ACLs for port groups')
    create_acls_for_port_group(idl, port_groups, 'web_tier', [80, 443])
    create_acls_for_port_group(idl, port_groups, 'app_tier', [8080, 9000])
    create_acls_for_port_group(idl, port_groups, 'db_tier', [5432, 3306])


def _add_acl(txn, idl, ls, priority, direction, match, action,
             description=None):
    """Create an ACL and attach it to a logical switch."""
    acl = txn.insert(idl.tables['ACL'])
    acl.priority = priority
    acl.direction = direction
    acl.match = match
    acl.action = action
    if description:
        acl.setkey('external_ids', 'description', description)
    ls.addvalue('acls', acl.uuid)


def create_switch_acls(idl, switch_name, node_id, switches):
    """Create ACLs on a logical switch.

    Creates switch-level ACLs for SSH, ICMP, anti-spoofing, and DHCP.
    Anti-spoofing (priority 2500) prevents VMs from using IPs outside
    their assigned subnet, blocking IP address spoofing attacks.
    """
    txn = ovs.db.idl.Transaction(idl)

    ls = switches.get(switch_name)
    if not ls:
        die(f'Missing switch {switch_name}')

    _add_acl(txn, idl, ls, 2000, 'from-lport',
             'tcp.dst == 22 && ip4.src == 10.0.0.0/8',
             'allow', 'Allow SSH from internal')
    _add_acl(txn, idl, ls, 1500, 'from-lport',
             'icmp4 || icmp6', 'allow')
    _add_acl(txn, idl, ls, 2500, 'from-lport',
             f'ip4.src != 10.{ip_node(node_id)}.0/24',
             'drop', 'Anti-spoofing')
    _add_acl(txn, idl, ls, 2000, 'from-lport',
             'udp.src == 68 && udp.dst == 67', 'allow')

    _add_acl(txn, idl, ls, 2000, 'from-lport',
             'tcp.dst == 22 && ip6.src == fd00::/16',
             'allow', 'Allow SSH from internal (IPv6)')
    _add_acl(txn, idl, ls, 2500, 'from-lport',
             f'ip6.src != fd00:{ip6_node(node_id)}::/64',
             'drop', 'Anti-spoofing (IPv6)')
    _add_acl(txn, idl, ls, 2000, 'from-lport',
             'udp.src == 546 && udp.dst == 547', 'allow')

    _add_acl(txn, idl, ls, 1800, 'to-lport',
             'ip4.dst == $web_servers && tcp.dst == 80',
             'allow-related', 'Allow HTTP to web servers')
    _add_acl(txn, idl, ls, 1800, 'to-lport',
             'ip4.dst == $db_servers && tcp.dst == 5432',
             'allow-related', 'Allow Postgres to DB servers')
    _add_acl(txn, idl, ls, 1800, 'to-lport',
             'ip4.dst == $app_servers && tcp.dst == 8080',
             'allow-related', 'Allow HTTP to app servers')

    if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
        die(f'Failed to create ACLs on switch {switch_name} '
            f'({txn.get_error()})')


def create_dns_records(idl, n, switches):
    """Create DNS records in the NB database."""
    for i in range(n):
        vlog.info(f'Creating DNS records for node {i}: '
                  f'web-{i}.example.com -> 10.{ip_node(i)}.10, '
                  f'app-{i}.example.com -> 10.{ip_node(i)}.30, '
                  f'db-{i}.example.com -> 10.{ip_node(i)}.20')
        txn = ovs.db.idl.Transaction(idl)
        dns = txn.insert(idl.tables['DNS'])
        dns.setkey('records', f'web-{i}.example.com',
                   f'10.{ip_node(i)}.10 '
                   f'fd00:{ip6_node(i)}::a')
        dns.setkey('records', f'app-{i}.example.com',
                   f'10.{ip_node(i)}.30 '
                   f'fd00:{ip6_node(i)}::1e')
        dns.setkey('records', f'db-{i}.example.com',
                   f'10.{ip_node(i)}.20 '
                   f'fd00:{ip6_node(i)}::14')
        dns.setkey('external_ids', 'zone', f'zone-{i}')

        ls = switches.get(f'ls-{i}')
        if not ls:
            die(f'Missing switch ls-{i}')
        ls.addvalue('dns_records', dns.uuid)

        if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
            die(f'Failed to create DNS records for node {i} '
                f'({txn.get_error()})')


def create_nat_rules(idl, n, routers):
    """Create NAT rules on routers.

    Creates SNAT, DNAT, and DNAT_AND_SNAT rules to exercise all NAT code paths.
    """
    for i in range(n):
        vlog.info(f'Creating NAT rules on router gw-{i}: '
                  f'snat 10.{ip_node(i)}.0/24 -> 192.{ip_node(i)}.1, '
                  f'dnat .10 -> .10, dnat_and_snat .20 -> .20')
        vlog.info(f'  IPv6: snat fd00:{ip6_node(i)}::/64 -> '
                  f'fd01:{ip6_node(i)}::1, '
                  f'dnat ::a -> ::a, dnat_and_snat ::14 -> ::14')
        txn = ovs.db.idl.Transaction(idl)

        lr = routers.get(f'gw-{i}')
        if not lr:
            die(f'Missing router gw-{i}')

        nat_snat = txn.insert(idl.tables['NAT'])
        nat_snat.type = 'snat'
        nat_snat.logical_ip = f'10.{ip_node(i)}.0/24'
        nat_snat.external_ip = f'192.{ip_node(i)}.1'
        lr.addvalue('nat', nat_snat.uuid)

        nat_dnat = txn.insert(idl.tables['NAT'])
        nat_dnat.type = 'dnat'
        nat_dnat.logical_ip = f'10.{ip_node(i)}.10'
        nat_dnat.external_ip = f'192.{ip_node(i)}.10'
        nat_dnat.setkey('external_ids', 'service', 'web')
        lr.addvalue('nat', nat_dnat.uuid)

        nat_dnat_and_snat = txn.insert(idl.tables['NAT'])
        nat_dnat_and_snat.type = 'dnat_and_snat'
        nat_dnat_and_snat.logical_ip = f'10.{ip_node(i)}.20'
        nat_dnat_and_snat.external_ip = f'192.{ip_node(i)}.20'
        nat_dnat_and_snat.setkey('external_ids', 'service', 'db')
        lr.addvalue('nat', nat_dnat_and_snat.uuid)

        nat_snat_v6 = txn.insert(idl.tables['NAT'])
        nat_snat_v6.type = 'snat'
        nat_snat_v6.logical_ip = f'fd00:{ip6_node(i)}::/64'
        nat_snat_v6.external_ip = f'fd01:{ip6_node(i)}::1'
        lr.addvalue('nat', nat_snat_v6.uuid)

        nat_dnat_v6 = txn.insert(idl.tables['NAT'])
        nat_dnat_v6.type = 'dnat'
        nat_dnat_v6.logical_ip = f'fd00:{ip6_node(i)}::a'
        nat_dnat_v6.external_ip = f'fd01:{ip6_node(i)}::a'
        nat_dnat_v6.setkey('external_ids',
                           'service', 'web-v6')
        lr.addvalue('nat', nat_dnat_v6.uuid)

        nat_ds_v6 = txn.insert(idl.tables['NAT'])
        nat_ds_v6.type = 'dnat_and_snat'
        nat_ds_v6.logical_ip = f'fd00:{ip6_node(i)}::14'
        nat_ds_v6.external_ip = f'fd01:{ip6_node(i)}::14'
        nat_ds_v6.setkey('external_ids',
                         'service', 'db-v6')
        lr.addvalue('nat', nat_ds_v6.uuid)

        if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
            die(f'Failed to create NAT rules for node {i} '
                f'({txn.get_error()})')


def create_static_routes(idl, n, routers):
    """Create static routes on routers."""
    for i in range(n):
        vlog.info(f'Creating static routes on router gw-{i}: '
                  f'default 0.0.0.0/0 -> 100.64.0.1, '
                  f'172.{ip_node(i)}.0/24 -> 10.{ip_node(i)}.254, '
                  f'192.0.2.0/24 -> discard')
        vlog.info(f'  IPv6: ::/0 -> fd01::1, '
                  f'fd02:{ip6_node(i)}::/64 -> fd00:{ip6_node(i)}::fe, '
                  f'2001:db8::/32 -> discard')
        txn = ovs.db.idl.Transaction(idl)

        lr = routers.get(f'gw-{i}')
        if not lr:
            die(f'Missing router gw-{i}')

        route_default = txn.insert(
            idl.tables['Logical_Router_Static_Route'])
        route_default.ip_prefix = '0.0.0.0/0'
        route_default.nexthop = '100.64.0.1'
        route_default.setkey('external_ids', 'type', 'default')
        lr.addvalue('static_routes', route_default.uuid)

        route_specific = txn.insert(
            idl.tables['Logical_Router_Static_Route'])
        route_specific.ip_prefix = f'172.{ip_node(i)}.0/24'
        route_specific.nexthop = f'10.{ip_node(i)}.254'
        route_specific.setkey('external_ids', 'type', 'specific')
        lr.addvalue('static_routes', route_specific.uuid)

        route_discard = txn.insert(
            idl.tables['Logical_Router_Static_Route'])
        route_discard.ip_prefix = '192.0.2.0/24'
        route_discard.nexthop = 'discard'
        route_discard.setkey('external_ids', 'type', 'blackhole')
        lr.addvalue('static_routes', route_discard.uuid)

        route_default_v6 = txn.insert(
            idl.tables['Logical_Router_Static_Route'])
        route_default_v6.ip_prefix = '::/0'
        route_default_v6.nexthop = 'fd01::1'
        route_default_v6.setkey('external_ids', 'type',
                                'default-v6')
        lr.addvalue('static_routes', route_default_v6.uuid)

        route_specific_v6 = txn.insert(
            idl.tables['Logical_Router_Static_Route'])
        route_specific_v6.ip_prefix = (
            f'fd02:{ip6_node(i)}::/64')
        route_specific_v6.nexthop = (
            f'fd00:{ip6_node(i)}::fe')
        route_specific_v6.setkey('external_ids', 'type',
                                 'specific-v6')
        lr.addvalue('static_routes',
                    route_specific_v6.uuid)

        route_discard_v6 = txn.insert(
            idl.tables['Logical_Router_Static_Route'])
        route_discard_v6.ip_prefix = '2001:db8::/32'
        route_discard_v6.nexthop = 'discard'
        route_discard_v6.setkey('external_ids', 'type',
                                'blackhole-v6')
        lr.addvalue('static_routes',
                    route_discard_v6.uuid)

        if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
            die(f'Failed to create static routes for node {i} '
                f'({txn.get_error()})')


def create_routing_policies(idl, n, routers):
    """Create routing policies on routers."""
    for i in range(n):
        vlog.info(f'Creating routing policies on router gw-{i}: '
                  f'reroute 10.{ip_node(i)}.0/24 -> '
                  f'10.{ip_node((i + 1) % n)}.1, '
                  f'allow $trusted_networks_v4')
        vlog.info(f'  IPv6: reroute fd00:{ip6_node(i)}::/64 -> '
                  f'fd00:{ip6_node((i + 1) % n)}::1, '
                  f'allow $trusted_networks_v6')
        txn = ovs.db.idl.Transaction(idl)

        lr = routers.get(f'gw-{i}')
        if not lr:
            die(f'Missing router gw-{i}')

        policy_reroute = txn.insert(idl.tables['Logical_Router_Policy'])
        policy_reroute.priority = 100
        policy_reroute.match = f'ip4.src == 10.{ip_node(i)}.0/24'
        policy_reroute.action = 'reroute'
        policy_reroute.nexthops = [f'10.{ip_node((i + 1) % n)}.1']
        policy_reroute.setkey('external_ids', 'policy',
                              'traffic-engineering')
        lr.addvalue('policies', policy_reroute.uuid)

        policy_allow = txn.insert(idl.tables['Logical_Router_Policy'])
        policy_allow.priority = 50
        policy_allow.match = 'ip4.dst == $trusted_networks_v4'
        policy_allow.action = 'allow'
        lr.addvalue('policies', policy_allow.uuid)

        policy_reroute_v6 = txn.insert(
            idl.tables['Logical_Router_Policy'])
        policy_reroute_v6.priority = 100
        policy_reroute_v6.match = (
            f'ip6.src == fd00:{ip6_node(i)}::/64')
        policy_reroute_v6.action = 'reroute'
        policy_reroute_v6.nexthops = [
            f'fd00:{ip6_node((i + 1) % n)}::1']
        policy_reroute_v6.setkey(
            'external_ids', 'policy',
            'traffic-engineering-v6')
        lr.addvalue('policies',
                    policy_reroute_v6.uuid)

        policy_allow_v6 = txn.insert(
            idl.tables['Logical_Router_Policy'])
        policy_allow_v6.priority = 50
        policy_allow_v6.match = (
            'ip6.dst == $trusted_networks_v6')
        policy_allow_v6.action = 'allow'
        lr.addvalue('policies', policy_allow_v6.uuid)

        if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
            die(f'Failed to create routing policies for node {i} '
                f'({txn.get_error()})')


def _add_ports(txn, idl, s, i, ports_per_switch):
    for p in range(ports_per_switch):
        lsp = txn.insert(idl.tables['Logical_Switch_Port'])
        lsp.name = f'lsp-{i}-{p}'
        # Offset by 10 to match the IP's +10 offset; wraps at 256 but
        # the port cap (244) means this only matters at the boundary.
        mac_byte = (p + 10) % 256
        mac = (f'00:00:{i >> 8:02x}:{i & 0xff:02x}'
               f':{p:02x}:{mac_byte:02x}')
        ip = f'10.{ip_node(i)}.{10 + p}'
        ip6 = f'fd00:{ip6_node(i)}::{10 + p:x}'
        lsp.addresses = [f'{mac} {ip} {ip6}']
        lsp.port_security = [f'{mac} {ip} {ip6}']
        vlog.info(f'  lsp-{i}-{p}: {mac} {ip} {ip6}')
        lsp.setkey('external_ids', 'vm-id', f'vm-{i}-{p}')

        if p % 3 == 0:
            lsp.setkey('external_ids', 'tier', 'web')
        elif p % 3 == 1:
            lsp.setkey('external_ids', 'tier', 'app')
        else:
            lsp.setkey('external_ids', 'tier', 'db')

        s.addvalue('ports', lsp.uuid)


def _add_node(txn, idl, i, chassis, cluster_rtr, join_sw, lbg,
              ports_per_switch):
    gwr = txn.insert(idl.tables['Logical_Router'])
    gwr.name = f'gw-{i}'
    gwr.addvalue('load_balancer_group', lbg.uuid)
    gwr.setkey('options', 'chassis', chassis)

    gwr2join = txn.insert(idl.tables['Logical_Router_Port'])
    gwr2join.name = f'gw2j-{i}'
    gwr2join.mac = f'00:00:01:{i >> 8:02x}:{i & 0xff:02x}:01'
    gwr2join.networks = [f'100.64.{ip_node(i)}/16',
                         f'fd01:{ip6_node(i)}::1/48']
    gwr.addvalue('ports', gwr2join.uuid)

    join2gwr = txn.insert(idl.tables['Logical_Switch_Port'])
    join2gwr.name = f'j2gw-{i}'
    join2gwr.type = 'router'
    join2gwr.addresses = ['router']
    join2gwr.setkey('options', 'router-port', gwr2join.name)
    join_sw.addvalue('ports', join2gwr.uuid)

    s = txn.insert(idl.tables['Logical_Switch'])
    s.name = f'ls-{i}'
    s.addvalue('load_balancer_group', lbg.uuid)
    s.setkey('other_config', 'subnet', f'10.{ip_node(i)}.0/24')
    s.setkey('other_config', 'mcast_snoop', 'true')

    cluster2s = txn.insert(idl.tables['Logical_Router_Port'])
    cluster2s.name = f'c2s-{i}'
    cluster2s.mac = '00:00:00:00:00:01'
    cluster2s.networks = [f'10.{ip_node(i)}.1/24',
                          f'fd00:{ip6_node(i)}::1/64']
    cluster_rtr.addvalue('ports', cluster2s.uuid)

    gw_chassis = txn.insert(idl.tables['Gateway_Chassis'])
    gw_chassis.name = f'{cluster2s.name}-{chassis}'
    gw_chassis.chassis_name = chassis
    gw_chassis.priority = 1
    cluster2s.addvalue('gateway_chassis', gw_chassis.uuid)

    s2cluster = txn.insert(idl.tables['Logical_Switch_Port'])
    s2cluster.name = f's2c-{i}'
    s2cluster.type = 'router'
    s2cluster.addresses = ['router']
    s2cluster.setkey('options', 'router-port', cluster2s.name)
    s.addvalue('ports', s2cluster.uuid)

    _add_ports(txn, idl, s, i, ports_per_switch)


def create_topology(idl, n, ports_per_switch, batch_size):
    """Create the basic topology with routers, switches, and ports."""
    vlog.info('Creating topology')
    txn = ovs.db.idl.Transaction(idl)
    lbg = txn.insert(idl.tables['Load_Balancer_Group'])
    lbg.name = 'lbg'

    vlog.info('Creating join switch')
    join_sw = txn.insert(idl.tables['Logical_Switch'])
    join_sw.name = 'join'

    cluster_rtr = txn.insert(idl.tables['Logical_Router'])
    cluster_rtr.name = 'cluster'

    rcj = txn.insert(idl.tables['Logical_Router_Port'])
    rcj.name = 'rcj'
    rcj.mac = '00:00:00:00:00:01'
    rcj.networks = ['100.64.0.1/16', 'fd01::1/48']
    cluster_rtr.addvalue('ports', rcj.uuid)

    sjc = txn.insert(idl.tables['Logical_Switch_Port'])
    sjc.name = 'sjc'
    sjc.type = 'router'
    sjc.addresses = ['router']
    sjc.setkey('options', 'router-port', 'rcj')
    join_sw.addvalue('ports', sjc.uuid)

    for i in range(n):
        chassis = f'chassis-{i // batch_size + 1}'
        vlog.info(f'Provisioning node {i}: gw-{i} + ls-{i}, '
                  f'10.{ip_node(i)}.0/24, fd00:{ip6_node(i)}::/64, '
                  f'{chassis}')
        _add_node(txn, idl, i, chassis, cluster_rtr, join_sw, lbg,
                  ports_per_switch)

    if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
        die(f'Failed to create topology ({txn.get_error()})')


def create_port_group_assignments(idl, port_groups):
    """Assign logical switch ports to port groups based on tier."""
    tier_ports = {'web': [], 'app': [], 'db': []}

    for row in idl.tables['Logical_Switch_Port'].rows.values():
        tier = row.external_ids.get('tier')
        if tier in tier_ports:
            tier_ports[tier].append(row.uuid)

    vlog.info(f'Assigning ports to port groups: '
              f'{len(tier_ports["web"])} web, '
              f'{len(tier_ports["app"])} app, '
              f'{len(tier_ports["db"])} db')

    txn = ovs.db.idl.Transaction(idl)
    tier_to_group = {'web': 'web_tier', 'app': 'app_tier', 'db': 'db_tier'}
    for tier, group_name in tier_to_group.items():
        pg = port_groups.get(group_name)
        if not pg:
            die(f'Missing port group {group_name}')
        for port_uuid in tier_ports[tier]:
            pg.addvalue('ports', port_uuid)

    if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
        die(f'Failed to assign ports to groups ({txn.get_error()})')


def create_explicit_lbs(idl, n, n_vips, n_backends, routers, switches):
    """Create explicit (non-templated) load balancers.

    Uses explicit (non-templated) LBs to maximize memory usage for
    regression testing.  Each LB is added to the 'lbg' load balancer
    group as well as directly to the router and switch.
    """
    lbg = None
    for row in idl.tables['Load_Balancer_Group'].rows.values():
        if row.name == 'lbg':
            lbg = row
            break
    if not lbg:
        die('Missing load balancer group lbg')

    for i in range(n):
        lr = routers.get(f'gw-{i}')
        ls = switches.get(f'ls-{i}')
        if not lr or not ls:
            die(f'Missing router or switch for node {i}')
        for j in range(n_vips):
            txn = ovs.db.idl.Transaction(idl)
            port = j + 1
            vlog.info(f'Creating LB lb-{j}-{i}: '
                      f'42.42.{ip_node(i)}:{port} -> '
                      f'{n_backends} backends')
            # Spread VIP index across two octets to stay within 0-249.
            # Unlike ip_node() which uses >>8/&0xff for node addresses,
            # this uses //250/%250 because VIP counts are small and 250
            # avoids addresses that look like broadcast/network octets.
            # Backend addresses depend only on j (not i), so every node
            # shares the same backend set -- intentional, since we are
            # testing memory, not realistic traffic distribution.
            j1 = (j + 1) // 250
            j2 = (j + 1) % 250

            lb = txn.insert(idl.tables['Load_Balancer'])
            lb.name = f'lb-{j}-{i}'
            lb.setkey('vips', f'42.42.{ip_node(i)}:{port}',
                      ','.join(f'42.{k}.{j1}.{j2}:{port}'
                               for k in range(n_backends)))
            lb.setkey(
                'vips',
                f'[fd42::{ip6_node(i)}:{j:x}]:{port}',
                ','.join(f'[fd42:{k:x}::{j1:x}:{j2:x}]:{port}'
                         for k in range(n_backends)))
            lb.protocol = 'tcp'
            lbg.addvalue('load_balancer', lb.uuid)
            lr.addvalue('load_balancer', lb.uuid)
            ls.addvalue('load_balancer', lb.uuid)
            if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
                die(f'Failed to create LB ({txn.get_error()})')


def connect_idl(remote):
    """Connect to the NB database and return the IDL."""
    schema_helper = ovs.db.idl.SchemaHelper(SCHEMA)
    schema_helper.register_all()
    idl = ovs.db.idl.Idl(remote, schema_helper, leader_only=False)

    while idl.change_seqno == 0 and not idl.run():
        poller = ovs.poller.Poller()
        idl.wait(poller)
        poller.block()
    return idl


def commit(txn, description):
    """Commit a transaction, accepting both SUCCESS and UNCHANGED."""
    status = txn.commit_block()
    if status not in (ovs.db.idl.Transaction.SUCCESS,
                      ovs.db.idl.Transaction.UNCHANGED):
        die(f'{description} ({txn.get_error()})')


def add_lsps(idl, n, ports_per_switch):
    """Add one new port to ~10% of switches."""
    if ports_per_switch < 1:
        vlog.info('Skipping add_lsps: ports_per_switch is 0')
        return
    count = max(1, n // 10)
    switches = {row.name: row
                for row in idl.tables['Logical_Switch'].rows.values()}
    txn = ovs.db.idl.Transaction(idl)
    added = 0
    p = ports_per_switch
    for i in range(count):
        ls = switches.get(f'ls-{i}')
        if not ls:
            continue
        lsp = txn.insert(idl.tables['Logical_Switch_Port'])
        lsp.name = f'lsp-{i}-{p}'
        mac_byte = (p + 10) % 256
        mac = (f'00:00:{i >> 8:02x}:{i & 0xff:02x}'
               f':{p:02x}:{mac_byte:02x}')
        ip = f'10.{ip_node(i)}.{10 + p}'
        ip6 = f'fd00:{ip6_node(i)}::{10 + p:x}'
        lsp.addresses = [f'{mac} {ip} {ip6}']
        lsp.port_security = [f'{mac} {ip} {ip6}']
        lsp.setkey('external_ids', 'vm-id', f'vm-{i}-{p}')
        lsp.setkey('external_ids', 'tier', 'web')
        ls.addvalue('ports', lsp.uuid)
        added += 1
    commit(txn, f'Failed to add {count} LSPs')
    vlog.info(f'Added {added} LSPs '
              f'(lsp-0-{p}..lsp-{count-1}-{p}, '
              f'10.x.x.{10 + p})')


def add_nat(idl, n):
    """Add one DNAT rule to ~10% of routers."""
    count = max(1, n // 10)
    routers = {row.name: row
               for row in idl.tables['Logical_Router'].rows.values()}
    txn = ovs.db.idl.Transaction(idl)
    added = 0
    for i in range(count):
        lr = routers.get(f'gw-{i}')
        if not lr:
            continue
        nat = txn.insert(idl.tables['NAT'])
        nat.type = 'dnat'
        nat.logical_ip = f'10.{ip_node(i)}.30'
        nat.external_ip = f'192.{ip_node(i)}.30'
        nat.setkey('external_ids', 'service', 'bench')
        lr.addvalue('nat', nat.uuid)
        added += 1
    commit(txn, f'Failed to add {count} NAT rules (service=bench)')
    vlog.info(f'Added {added} DNAT rules '
              f'(service=bench, .30 -> .30)')


def add_routes(idl, n):
    """Add one specific route to ~10% of routers."""
    count = max(1, n // 10)
    routers = {row.name: row
               for row in idl.tables['Logical_Router'].rows.values()}
    txn = ovs.db.idl.Transaction(idl)
    added = 0
    for i in range(count):
        lr = routers.get(f'gw-{i}')
        if not lr:
            continue
        route = txn.insert(
            idl.tables['Logical_Router_Static_Route'])
        route.ip_prefix = f'10.{ip_node(i)}.128/25'
        route.nexthop = f'10.{ip_node(i)}.254'
        route.setkey('external_ids', 'type', 'bench')
        lr.addvalue('static_routes', route.uuid)
        added += 1
    commit(txn, f'Failed to add {count} static routes (type=bench)')
    vlog.info(f'Added {added} static routes '
              f'(10.x.x.128/25 -> 10.x.x.254)')


def add_policies(idl, n):
    """Add one allow policy to ~10% of routers."""
    count = max(1, n // 10)
    routers = {row.name: row
               for row in idl.tables['Logical_Router'].rows.values()}
    txn = ovs.db.idl.Transaction(idl)
    added = 0
    for i in range(count):
        lr = routers.get(f'gw-{i}')
        if not lr:
            continue
        policy = txn.insert(idl.tables['Logical_Router_Policy'])
        policy.priority = 75
        policy.match = f'ip4.src == 10.{ip_node(i)}.128/25'
        policy.action = 'allow'
        policy.setkey('external_ids', 'source', 'bench')
        lr.addvalue('policies', policy.uuid)
        added += 1
    commit(txn, f'Failed to add {count} routing policies (source=bench)')
    vlog.info(f'Added {added} routing policies '
              f'(priority=75, allow 10.x.x.128/25)')


def modify_nat(idl, n):
    """Change external_ip on IPv4 SNAT rules for ~10% of routers."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    modified = 0
    for row in idl.tables['NAT'].rows.values():
        if modified >= count:
            break
        if row.type == 'snat' and row.logical_ip.startswith('10.'):
            prefix, last_octet = row.external_ip.rsplit('.', 1)
            row.external_ip = f'{prefix}.{int(last_octet) + 1}'
            modified += 1
    commit(txn, f'Failed to modify {count} SNAT external_ips (.1 -> .2)')
    vlog.info(f'Modified {modified} SNAT external_ips (.1 -> .2)')


def modify_routes(idl, n):
    """Change nexthop on IPv4 default routes for ~10% of routers."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    modified = 0
    for row in idl.tables[
            'Logical_Router_Static_Route'].rows.values():
        if modified >= count:
            break
        if (row.external_ids.get('type') == 'default'
                and row.ip_prefix == '0.0.0.0/0'):
            row.nexthop = '100.64.0.2'
            modified += 1
    commit(txn,
           f'Failed to modify {count} default routes '
           f'(nexthop 100.64.0.1 -> .2)')
    vlog.info(f'Modified {modified} default route nexthops '
              f'(100.64.0.1 -> 100.64.0.2)')


def modify_lbs(idl, n):
    """Change protocol on first LB for ~10% of nodes."""
    count = max(1, n // 10)
    targets = set(f'lb-0-{i}' for i in range(count))
    txn = ovs.db.idl.Transaction(idl)
    modified = 0
    for row in idl.tables['Load_Balancer'].rows.values():
        if row.name in targets:
            row.protocol = 'udp' if row.protocol == 'tcp' else 'tcp'
            modified += 1
    commit(txn,
           f'Failed to modify {count} LB protocols (tcp <-> udp)')
    vlog.info(f'Modified {modified} LB protocols '
              f'(lb-0-0..lb-0-{count-1}, tcp <-> udp)')


def modify_addr_sets(idl, n):
    """Add ~10% of n addresses to the web_servers address set."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    added = 0
    for row in idl.tables['Address_Set'].rows.values():
        if row.name == 'web_servers':
            for i in range(count):
                row.addvalue('addresses', f'10.{ip_node(i)}.200')
            added = count
            break
    commit(txn, f'Failed to modify web_servers address set '
           f'(+= {count} addresses)')
    vlog.info(f'Added {added} addresses to web_servers '
              f'(10.0.0.200..10.{ip_node(count-1)}.200)')


def modify_port_groups(idl, n):
    """Add ~10% of app-tier ports to the web_tier port group."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    added = 0
    app_ports = []
    for row in idl.tables['Logical_Switch_Port'].rows.values():
        if row.external_ids.get('tier') == 'app':
            app_ports.append(row)
            if len(app_ports) >= count:
                break
    web_tier = None
    for row in idl.tables['Port_Group'].rows.values():
        if row.name == 'web_tier':
            web_tier = row
            break
    if web_tier:
        for port in app_ports:
            web_tier.addvalue('ports', port.uuid)
            added += 1
    commit(txn, f'Failed to modify web_tier port group '
           f'(+= {count} ports)')
    vlog.info(f'Added {added} app-tier ports to web_tier')


def modify_port_security(idl, n):
    """Add an extra IP to port_security on ~10% of LSPs."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    modified = 0
    for row in idl.tables['Logical_Switch_Port'].rows.values():
        if modified >= count:
            break
        if not row.name.startswith('lsp-') or not row.name.endswith('-1'):
            continue
        parts = row.name.split('-')
        i = int(parts[1])
        if i >= count:
            continue
        ps = list(row.port_security)
        if ps:
            ps[0] = ps[0] + f' 10.{ip_node(i)}.200'
            row.port_security = ps
            modified += 1
    commit(txn,
           f'Failed to modify {count} LSP port_security '
           f'(+= 10.x.x.200)')
    vlog.info(f'Modified {modified} LSP port_security '
              f'(lsp-0-1..lsp-{count-1}-1, += 10.x.x.200)')


def modify_dhcp(idl, n):
    """Change lease_time on ~10% of DHCPv4 option sets."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    modified = 0
    for row in idl.tables['DHCP_Options'].rows.values():
        if modified >= count:
            break
        subnet = row.external_ids.get('subnet', '')
        if subnet.startswith('ls-') and not subnet.endswith('-v6'):
            parts = subnet.split('-')
            i = int(parts[1])
            if i < count:
                row.setkey('options', 'lease_time', '7200')
                modified += 1
    commit(txn,
           f'Failed to modify {count} DHCP lease_time '
           f'(3600 -> 7200)')
    vlog.info(f'Modified {modified} DHCP lease_time '
              f'(3600 -> 7200)')


def modify_dns(idl, n):
    """Add a DNS record to ~10% of nodes."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    modified = 0
    for row in idl.tables['DNS'].rows.values():
        if modified >= count:
            break
        zone = row.external_ids.get('zone', '')
        if zone.startswith('zone-'):
            i = int(zone.split('-')[1])
            if i < count:
                row.setkey('records', f'bench-{i}.example.com',
                           f'10.{ip_node(i)}.200')
                modified += 1
    commit(txn,
           f'Failed to modify {count} DNS records '
           f'(+= bench-x.example.com)')
    vlog.info(f'Modified {modified} DNS records '
              f'(+= bench-x.example.com -> 10.x.x.200)')


def delete_acls(idl, n):
    """Delete 'Allow SSH from internal' ACL from ~10% of switches."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    deleted = 0
    for row in list(idl.tables['ACL'].rows.values()):
        if deleted >= count:
            break
        desc = row.external_ids.get('description', '')
        if desc == 'Allow SSH from internal':
            row.delete()
            deleted += 1
    commit(txn,
           f'Failed to delete {count} ACLs '
           f'(Allow SSH from internal)')
    vlog.info(f'Deleted {deleted} ACLs '
              f'(Allow SSH from internal)')


def delete_policies(idl, n):
    """Delete IPv4 allow policies from ~10% of routers."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    deleted = 0
    for row in list(
            idl.tables['Logical_Router_Policy'].rows.values()):
        if deleted >= count:
            break
        if (row.priority == 50
                and 'trusted_networks_v4' in row.match):
            row.delete()
            deleted += 1
    commit(txn,
           f'Failed to delete {count} routing policies '
           f'(priority=50, trusted_networks_v4)')
    vlog.info(f'Deleted {deleted} routing policies '
              f'(priority=50, trusted_networks_v4)')


def delete_qos(idl, n):
    """Delete rate-limit QoS rules from ~10% of switches."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    deleted = 0
    for row in list(idl.tables['QoS'].rows.values()):
        if deleted >= count:
            break
        if row.external_ids.get('type') == 'rate-limit':
            row.delete()
            deleted += 1
    commit(txn,
           f'Failed to delete {count} QoS rules (type=rate-limit)')
    vlog.info(f'Deleted {deleted} QoS rules (type=rate-limit)')


def modify_lsps(idl, n):
    """Modify addresses on ~10% of LSPs to exercise incremental processing."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    modified = 0
    for row in idl.tables['Logical_Switch_Port'].rows.values():
        if modified >= count:
            break
        name = row.name
        if not name.startswith('lsp-') or not name.endswith('-0'):
            continue
        parts = name.split('-')
        i = int(parts[1])
        if i >= count:
            continue
        mac = f'00:00:{i >> 8:02x}:{i & 0xff:02x}:00:0a'
        ip = f'10.{ip_node(i)}.210'
        ip6 = f'fd00:{ip6_node(i)}::d2'
        row.addresses = [f'{mac} {ip} {ip6}']
        row.port_security = [f'{mac} {ip} {ip6}']
        modified += 1
    commit(txn, f'Failed to modify {count} LSP addresses (.10 -> .210)')
    vlog.info(f'Modified {modified} LSP addresses '
              f'(lsp-0-0..lsp-{count-1}-0, .10 -> .210)')


def modify_acls(idl, n):
    """Modify anti-spoofing ACLs on ~10% of switches."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    modified = 0
    for row in idl.tables['ACL'].rows.values():
        if modified >= count:
            break
        desc = row.external_ids.get('description', '')
        if desc == 'Anti-spoofing' and '/24' in row.match:
            row.match = row.match.replace('/24', '/23')
            modified += 1
    commit(txn, f'Failed to modify {count} anti-spoofing ACLs (/24 -> /23)')
    vlog.info(f'Modified {modified} anti-spoofing ACLs (/24 -> /23)')


def delete_lsps(idl, n, ports_per_switch):
    """Delete the last port from ~10% of switches."""
    if ports_per_switch < 1:
        vlog.info('Skipping delete_lsps: no ports to delete')
        return
    count = max(1, n // 10)
    last_port = ports_per_switch - 1
    targets = set(f'lsp-{i}-{last_port}' for i in range(count))
    txn = ovs.db.idl.Transaction(idl)
    deleted = 0
    for row in list(idl.tables['Logical_Switch_Port'].rows.values()):
        if row.name in targets:
            row.delete()
            deleted += 1
    commit(txn, f'Failed to delete {count} LSPs '
           f'(lsp-0-{last_port}..lsp-{count-1}-{last_port})')
    vlog.info(f'Deleted {deleted} LSPs '
              f'(lsp-0-{last_port}..lsp-{count-1}-{last_port})')


def delete_nat(idl, n):
    """Delete IPv4 DNAT rules from ~10% of routers."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    deleted = 0
    for row in list(idl.tables['NAT'].rows.values()):
        if deleted >= count:
            break
        if (row.type == 'dnat'
                and row.external_ids.get('service') == 'web'):
            row.delete()
            deleted += 1
    commit(txn, f'Failed to delete {count} IPv4 DNAT rules (service=web)')
    vlog.info(f'Deleted {deleted} IPv4 DNAT rules (service=web)')


def delete_routes(idl, n):
    """Delete IPv4 specific routes from ~10% of routers."""
    count = max(1, n // 10)
    txn = ovs.db.idl.Transaction(idl)
    deleted = 0
    for row in list(
            idl.tables['Logical_Router_Static_Route'].rows.values()):
        if deleted >= count:
            break
        if row.external_ids.get('type') == 'specific':
            row.delete()
            deleted += 1
    commit(txn, f'Failed to delete {count} IPv4 specific routes')
    vlog.info(f'Deleted {deleted} IPv4 specific routes')


def delete_lbs(idl, n):
    """Delete one load balancer from ~10% of nodes."""
    count = max(1, n // 10)
    targets = set(f'lb-0-{i}' for i in range(count))
    txn = ovs.db.idl.Transaction(idl)
    deleted = 0
    for row in list(idl.tables['Load_Balancer'].rows.values()):
        if row.name in targets:
            row.delete()
            deleted += 1
    commit(txn, f'Failed to delete {count} load balancers '
           f'(lb-0-0..lb-0-{count-1})')
    vlog.info(f'Deleted {deleted} load balancers '
              f'(lb-0-0..lb-0-{count-1})')


def run(remote, n, n_vips, n_backends, ports_per_switch, batch_size):
    """Main execution function."""
    idl = connect_idl(remote)

    # Check if database is clean before proceeding
    if (len(idl.tables['Load_Balancer_Group'].rows) > 0 or
        len(idl.tables['Logical_Switch'].rows) > 0 or
        len(idl.tables['Logical_Router'].rows) > 0):
        die('Database is not empty. Please restart the sandbox or clear the '
            'database before running this script.')

    create_topology(idl, n, ports_per_switch, batch_size)

    # Build lookup dictionaries for O(1) access to switches and routers
    switches = {row.name: row
                for row in idl.tables['Logical_Switch'].rows.values()}
    routers = {row.name: row
               for row in idl.tables['Logical_Router'].rows.values()}

    create_address_sets(idl, n)
    create_port_groups(idl)
    port_groups = {row.name: row
                   for row in idl.tables['Port_Group'].rows.values()}
    create_port_group_assignments(idl, port_groups)
    create_dhcp_options(idl, n)
    create_dhcp_assignments(idl, n)
    create_dns_records(idl, n, switches)
    create_nat_rules(idl, n, routers)
    create_static_routes(idl, n, routers)
    create_acls(idl, port_groups)
    for i in range(n):
        create_switch_acls(idl, f'ls-{i}', i, switches)
    create_qos_rules(idl, n, switches)
    create_routing_policies(idl, n, routers)
    create_explicit_lbs(idl, n, n_vips, n_backends, routers, switches)


PHASES = [
    'create',
    'add-lsps', 'add-nat', 'add-routes', 'add-policies',
    'modify-lsps', 'modify-acls', 'modify-nat', 'modify-routes',
    'modify-lbs', 'modify-addr-sets', 'modify-pg', 'modify-port-sec',
    'modify-dhcp', 'modify-dns',
    'delete-lsps', 'delete-nat', 'delete-routes', 'delete-lbs',
    'delete-acls', 'delete-policies', 'delete-qos',
]


def main():
    """Parse arguments and run the benchmark."""
    parser = argparse.ArgumentParser(
        description='OVN benchmark: create topology, then exercise '
                    'incremental engine with add/modify/delete operations'
    )
    parser.add_argument(
        'phase', nargs='?', default='create', choices=PHASES,
        help='Benchmark phase to run (default: create)',
    )
    parser.add_argument(
        '-r', '--remote', required=True, help='NB connection string'
    )
    parser.add_argument(
        '-n', '--nodes', type=int, required=True, help='Number of nodes'
    )
    parser.add_argument(
        '-p',
        '--ports-per-switch',
        type=int,
        default=9,
        help='Number of logical switch ports per switch (default: 9, '
             'provides 3 ports per tier)',
    )
    parser.add_argument(
        '-v', '--vips', type=int, default=5,
        help='Number of LB VIPs per node (default: 5)'
    )
    parser.add_argument(
        '-B',
        '--backends',
        type=int,
        default=5,
        help='Number backends per VIP (default: 5)',
    )
    parser.add_argument(
        '-b',
        '--batch-size',
        type=int,
        default=0,
        help='Nodes per chassis (default: n/10)',
    )
    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        help='Enable debug output (show info messages)',
    )
    args = parser.parse_args()

    if args.batch_size <= 0:
        args.batch_size = max(1, args.nodes // 10)

    if args.nodes < 1:
        die('node count must be at least 1')
    # Node index is split across two IP octets via ip_node(), so the
    # maximum is 2^16 - 1.
    if args.nodes > 65535:
        die('maximum supported node count is 65535')

    if args.ports_per_switch < 0:
        die('ports per switch must not be negative')
    # Port IPs start at 10.x.y.10 (see _add_ports), so the highest
    # address is 10.x.y.(10 + ports_per_switch - 1).  Cap at 245 to
    # keep that <= 254 (valid IPv4 octet).
    if args.ports_per_switch > 245:
        die('maximum supported ports per switch is 245')

    if args.vips < 0:
        die('VIP count must not be negative')
    # VIP index is split via (j+1)//250 and (j+1)%250; the quotient
    # must fit in one octet, so max VIPs = 250 * 256 - 1 = 63999.
    if args.vips > 63999:
        die('maximum supported VIPs is 63999')

    if args.backends < 0:
        die('backend count must not be negative')
    # Backend addresses use 42.{k}.j1.j2; k must fit in one octet.
    if args.backends > 255:
        die('maximum supported backends is 255')

    if args.debug:
        vlog.set_levels_from_string('console:info')

    if args.phase == 'create':
        n_chassis = ((args.nodes + args.batch_size - 1)
                     // args.batch_size)
        print(f'\n=== OVN Benchmark Configuration ===')
        print(f'Nodes:                        {args.nodes}'
              f' ({args.nodes} routers + {args.nodes} switches)')
        print(f'Ports per switch:             {args.ports_per_switch} '
              f'({args.ports_per_switch * args.nodes} total ports)')
        print(f'Load balancer VIPs per node:  {args.vips} '
              f'({args.vips * args.nodes} total VIPs)')
        print(f'Backends per VIP:             {args.backends}')
        print(f'Total load balancers:         '
              f'{args.nodes * args.vips}')
        print(f'Nodes per chassis (batch):    '
              f'{args.batch_size} '
              f'({n_chassis} chassis)')
        print(f'Debug logging:                '
              f'{"enabled" if args.debug else "disabled"}')
        print('===================================\n')

        run(args.remote, args.nodes, args.vips, args.backends,
            args.ports_per_switch, args.batch_size)
    else:
        idl = connect_idl(args.remote)
        n = args.nodes
        if args.phase == 'add-lsps':
            add_lsps(idl, n, args.ports_per_switch)
        elif args.phase == 'add-nat':
            add_nat(idl, n)
        elif args.phase == 'add-routes':
            add_routes(idl, n)
        elif args.phase == 'add-policies':
            add_policies(idl, n)
        elif args.phase == 'modify-lsps':
            modify_lsps(idl, n)
        elif args.phase == 'modify-acls':
            modify_acls(idl, n)
        elif args.phase == 'modify-nat':
            modify_nat(idl, n)
        elif args.phase == 'modify-routes':
            modify_routes(idl, n)
        elif args.phase == 'modify-lbs':
            modify_lbs(idl, n)
        elif args.phase == 'modify-addr-sets':
            modify_addr_sets(idl, n)
        elif args.phase == 'modify-pg':
            modify_port_groups(idl, n)
        elif args.phase == 'modify-port-sec':
            modify_port_security(idl, n)
        elif args.phase == 'modify-dhcp':
            modify_dhcp(idl, n)
        elif args.phase == 'modify-dns':
            modify_dns(idl, n)
        elif args.phase == 'delete-lsps':
            delete_lsps(idl, n, args.ports_per_switch)
        elif args.phase == 'delete-nat':
            delete_nat(idl, n)
        elif args.phase == 'delete-routes':
            delete_routes(idl, n)
        elif args.phase == 'delete-lbs':
            delete_lbs(idl, n)
        elif args.phase == 'delete-acls':
            delete_acls(idl, n)
        elif args.phase == 'delete-policies':
            delete_policies(idl, n)
        elif args.phase == 'delete-qos':
            delete_qos(idl, n)


if __name__ == '__main__':
    try:
        main()
    except error.Error as e:
        sys.stderr.write(f'{e}\n')
        sys.exit(1)
