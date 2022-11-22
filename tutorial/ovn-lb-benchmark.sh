#!/bin/bash

usage() {
    echo "Usage: $1 <n_routers> <n_lbs> <n_backends_per_lb> <use_template>"
    exit 0
}

([ "${1:-"--usage"}" = "--usage" ] || [ "$#" -ne "4" ]) && usage $0

nrtr=$1
nlb=$2
nbackends=$3
use_template=$4

echo "ROUTERS        : $nrtr"
echo "LBS            : $nlb"
echo "BACKENDS PER LB: $nbackends"
echo "USE TEMPLATE   : ${use_template}"

if [ "${use_template}" = "yes" ]; then
    templates=-t
else
    templates=
fi

python ovn-lb-benchmark.py -n $nrtr -v $nlb -b $nbackends \
    -r unix:$PWD/sandbox/nb1.ovsdb $templates

# Bind a port from the first LS locally.
ovs-vsctl add-port br-int lsp-1 \
    -- set interface lsp-1 external_ids:iface-id=lsp-1

# Ensure everything was propagated to SB.
ovn-nbctl --wait=sb sync

# Compact resulting DBs.
ovs-appctl -t $PWD/sandbox/nb1 ovsdb-server/compact
ovs-appctl -t $PWD/sandbox/sb1 ovsdb-server/compact
