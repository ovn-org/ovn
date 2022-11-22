#!/usr/bin/env python3
import argparse
import sys

import ovs.db.idl
import ovs.poller
import ovs.stream
import ovs.vlog
from ovs.db import error

vlog = ovs.vlog.Vlog('template-lb-stress')
vlog.set_levels_from_string('console:info')
vlog.init(None)

SCHEMA = '../ovn-nb.ovsschema'


def die(msg):
    vlog.warn(f'Fatal error encountered: {msg}')
    sys.exit(1)


def create_topology(idl, n):
    vlog.info('Creating topology')
    txn = ovs.db.idl.Transaction(idl)
    lbg = txn.insert(idl.tables['Load_Balancer_Group'])
    lbg.name = 'lbg'

    vlog.info('Adding join switch')
    join_sw = txn.insert(idl.tables['Logical_Switch'])
    join_sw.name = 'join'

    cluster_rtr = txn.insert(idl.tables['Logical_Router'])
    cluster_rtr.name = 'cluster'

    rcj = txn.insert(idl.tables['Logical_Router_Port'])
    rcj.name = 'rcj'
    rcj.mac = '00:00:00:00:00:01'
    rcj.networks = ['10.0.0.1/8']
    cluster_rtr.addvalue('ports', rcj.uuid)

    sjc = txn.insert(idl.tables['Logical_Switch_Port'])
    sjc.name = 'sjc'
    sjc.type = 'router'
    sjc.addresses = ['router']
    sjc.setkey('options', 'router-port', 'rcj')
    join_sw.addvalue('ports', sjc.uuid)

    for i in range(n):
        vlog.info(f'Provisioning node {i}')
        chassis = f'chassis-{i}'
        gwr = txn.insert(idl.tables['Logical_Router'])
        gwr.name = f'lr-{i}'
        gwr.addvalue('load_balancer_group', lbg.uuid)
        gwr.setkey('options', 'chassis', chassis)

        gwr2join = txn.insert(idl.tables['Logical_Router_Port'])
        gwr2join.name = f'lr2j-{i}'
        gwr2join.mac = '00:00:00:00:00:01'
        gwr2join.networks = ['10.0.0.1/8']
        gwr.addvalue('ports', gwr2join.uuid)

        join2gwr = txn.insert(idl.tables['Logical_Switch_Port'])
        join2gwr.name = f'j2lr-{i}'
        join2gwr.type = 'router'
        join2gwr.addresses = ['router']
        join2gwr.setkey('options', 'router-port', gwr2join.name)
        join_sw.addvalue('ports', join2gwr.uuid)

        s = txn.insert(idl.tables['Logical_Switch'])
        s.name = f'ls-{i}'
        s.addvalue('load_balancer_group', lbg.uuid)

        cluster2s = txn.insert(idl.tables['Logical_Router_Port'])
        cluster2s.name = f'c2s-{i}'
        cluster2s.mac = '00:00:00:00:00:01'
        cluster2s.networks = ['10.0.0.1/8']
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

        lsp = txn.insert(idl.tables['Logical_Switch_Port'])
        lsp.name = f'lsp-{i}'
        s.addvalue('ports', lsp.uuid)

    if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
        die(f'Failed to create topology ({txn.get_error()}')


def add_template_lbs(idl, n, n_vips):
    lbg = next(iter(idl.tables['Load_Balancer_Group'].rows.values()))

    for i in range(n_vips):
        vlog.info(f'Adding LB {i}')
        txn = ovs.db.idl.Transaction(idl)
        lb = txn.insert(idl.tables['Load_Balancer'])
        lb.name = f'lb-{i}'
        lb.setkey('options', 'template', 'true')
        lb.setkey('options', 'address-family', 'ipv4')
        lb.setkey('vips', f'^vip:{i}', f'^backends{i}')
        lb.protocol = 'tcp'
        lbg.addvalue('load_balancer', lb.uuid)
        if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
            die(f'Failed to add LB ({txn.get_error()}')


def add_chassis_template_vars(idl, n, n_vips, n_backends):
    for i in range(n):
        vlog.info(f'Adding LB vars for node {i}')
        txn = ovs.db.idl.Transaction(idl)
        tv = txn.insert(idl.tables['Chassis_Template_Var'])
        tv.chassis = f'chassis-{i}'
        tv.setkey('variables', 'vip', f'42.42.42.{i}')

        for j in range(n_vips):
            port = j + 1
            j1 = (j + 1) // 250
            j2 = (j + 1) % 250
            backends = [f'42.{k}.{j1}.{j2}:{port}' for k in range(n_backends)]
            tv.setkey('variables', f'backends{j}', ','.join(backends))
        if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
            die(f'Failed to add template vars ({txn.get_error()}')


def find_by_name(idl, table, name):
    for row in idl.tables[table].rows.values():
        if row.name == name:
            return row
    return None


def add_explicit_lbs(idl, n, n_vips, n_backends):
    for i in range(n):
        lr = find_by_name(idl, 'Logical_Router', f'lr-{i}')
        ls = find_by_name(idl, 'Logical_Switch', f'ls-{i}')
        for j in range(n_vips):
            vlog.info(f'Adding LB {j} for node {i}')
            txn = ovs.db.idl.Transaction(idl)
            port = j + 1
            j1 = (j + 1) // 250
            j2 = (j + 1) % 250
            backends = [f'42.{k}.{j1}.{j2}:{port}' for k in range(n_backends)]

            lb = txn.insert(idl.tables['Load_Balancer'])
            lb.name = f'lb-{j}-{i}'
            lb.setkey('vips', f'42.42.42.{i}:{port}', f'{",".join(backends)}')
            lb.protocol = 'tcp'
            lr.addvalue('load_balancer', lb.uuid)
            ls.addvalue('load_balancer', lb.uuid)
            if txn.commit_block() != ovs.db.idl.Transaction.SUCCESS:
                die(f'Failed to add LB ({txn.get_error()}')


def run(remote, n, n_vips, n_backends, templates):
    schema_helper = ovs.db.idl.SchemaHelper(SCHEMA)
    schema_helper.register_all()
    idl = ovs.db.idl.Idl(remote, schema_helper, leader_only=False)

    seqno = 0

    error, stream = ovs.stream.Stream.open_block(
        ovs.stream.Stream.open(remote), 2000
    )
    if error:
        sys.stderr.write(f'failed to connect to \"{remote}\"')
        sys.exit(1)

    if not stream:
        sys.stderr.write(f'failed to connect to \"{remote}\"')
        sys.exit(1)
    rpc = ovs.jsonrpc.Connection(stream)

    while idl.change_seqno == seqno and not idl.run():
        rpc.run()

        poller = ovs.poller.Poller()
        idl.wait(poller)
        rpc.wait(poller)
        poller.block()

    create_topology(idl, n)
    if templates:
        add_template_lbs(idl, n, n_vips)
        add_chassis_template_vars(idl, n, n_vips, n_backends)
    else:
        add_explicit_lbs(idl, n, n_vips, n_backends)


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-n', '--nodes', type=int, required=True, help='Number of nodes'
    )
    parser.add_argument(
        '-v', '--vips', type=int, required=True, help='Number of LB VIPs'
    )
    parser.add_argument(
        '-b',
        '--backends',
        type=int,
        required=True,
        help='Number backends per VIP',
    )
    parser.add_argument(
        '-r', '--remote', required=True, help='NB connection string'
    )
    parser.add_argument(
        '-t',
        '--template',
        action='store_true',
        help='Use LB Templates?',
    )
    parser.set_defaults(template=False)
    args = parser.parse_args()
    run(args.remote, args.nodes, args.vips, args.backends, args.template)


if __name__ == '__main__':
    try:
        main(sys.argv)
    except error.Error as e:
        sys.stderr.write(f'{e}\n')
        sys.exit(1)
