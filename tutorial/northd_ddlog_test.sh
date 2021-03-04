#!/bin/bash

ddlog_running () {
    test -e sandbox/ovn-north-ddlog.pid
}

rm -f sandbox/profile-[0-9]*.txt
if ddlog_running; then 
    ovs-appctl -t ovn-northd-ddlog enable-cpu-profiling
fi

export OVN_NB_DAEMON=$(ovn-nbctl --pidfile --detach)
export OVN_SB_DAEMON=$(ovn-sbctl --pidfile --detach)
trap 'kill $(cat $OVN_RUNDIR/ovn-nbctl.pid) $(cat $OVN_RUNDIR/ovn-sbctl.pid)' 0

ovn-nbctl set NB_Global . options:northd_probe_interval=180000

ovn-nbctl pg-add portGroupDefDeny
ovn-nbctl pg-add portGroupMultiDefDeny
ovn-nbctl lr-add cluster_router

step () {
    lswitch_name=lswitch_17.${i}.0.0/16
    ext_switch=ext_ls_2.${i}.0.0/16
    ext_lrouter=ext_lr_2.${i}.0.0/16
    j=2
    port_name=lp_17.${i}.0.${j}
    port_ip=17.${i}.0.${j}
    np=networkPolicy-$i-$j
    ns=nameSpace-$i-$j
    mg=mcastPortGroup_$ns
    ovn-sbctl chassis-add ch$i geneve 128.0.0.$i
    ovn-nbctl --wait=sb \
        ls-add ${lswitch_name} -- \
        lrp-add cluster_router lr-$lswitch_name 00:00:00:00:ff:$i 17.${i}.0.254/16 -- \
        lsp-add $lswitch_name $lswitch_name-lr -- \
        lsp-set-type $lswitch_name-lr router -- \
        lsp-set-addresses $lswitch_name-lr router -- \
        lsp-set-options $lswitch_name-lr router-port=lr-$lswitch_name -- \
        ls-add $ext_switch -- \
        lr-add $ext_lrouter -- \
        lrp-add $ext_lrouter extlr-$lswitch_name 00:00:00:10:af:$i 2.${i}.0.254/16 -- \
        lsp-add $ext_switch $ext_switch-lr_2.$i -- \
        lsp-set-type $ext_switch-lr_2.$i router -- \
        lsp-set-addresses $ext_switch-lr_2.$i router -- \
        lsp-set-options $ext_switch-lr_2.$i router-port=extlr-$lswitch_name -- \
        lr-nat-add $ext_lrouter snat 2.${i}.0.100 17.${i}.0.0/16 -- \
        lr-route-add $ext_lrouter 17.${i}.1.0/16 20.0.0.2 -- \
        --policy="src-ip" lr-route-add $ext_lrouter 192.168.2.0/24 20.0.0.3 -- \
        --policy="src-ip" lr-route-add cluster_router 17.${i}.1.0/16 20.0.0.4 -- \
        set logical_router $ext_lrouter options:chassis=ch$i -- \
        lsp-add ${lswitch_name}  ${port_name} -- \
        lsp-set-addresses ${port_name} "dynamic ${port_ip}" -- \
        --id=@lsp get logical_switch_port ${port_name} -- \
        add port_group portGroupDefDeny  ports @lsp -- \
        add port_group portGroupMultiDefDeny ports @lsp -- \
        pg-add $np $port_name -- \
        create Address_Set name=${np}_ingress_as addresses=$port_ip -- \
        create Address_Set name=${np}_egress_as addresses=$port_ip -- \
        acl-add $np from-lport 1010 "inport == @$np && ip4.src == ${np}_ingress_as" allow -- \
        acl-add $np from-lport 1009 "inport == @$np && ip4" allow-related -- \
        acl-add $np to-lport 1010 "outport == @$np && ip4.dst == ${np}_egress_as" allow -- \
        acl-add $np to-lport 1009 "outport == @$np && ip4" allow -- \
        create Address_Set name=$ns addresses=$port_ip -- \
        pg-add $mg $port_name -- \
        acl-add $mg from-lport 1012 "inport == @${mg} && ip4.mcast" allow -- \
        acl-add $mg to-lport 1012 "outport == @${mg} && ip4.mcast" allow >/dev/null
    ovn-sbctl lsp-bind $port_name ch$i

    if ddlog_running; then
        ovs-appctl -t ovn-northd-ddlog profile > sandbox/profile-$i.txt
    fi
}

rm -f timings
i=1
while [ $i -lt 255 ]
do
    printf "step $i: "; TIMEFORMAT=%R; time step
    i=$((i+1))
done
