..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in OVN documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

=========================================
Integration Guide for Centralized Control
=========================================

HA for OVN DB servers using pacemaker
-------------------------------------

The ovsdb servers can work in either active or backup mode. In backup mode, db
server will be connected to an active server and replicate the active servers
contents. At all times, the data can be transacted only from the active server.
When the active server dies for some reason, entire OVN operations will be
stalled.

`Pacemaker <http://clusterlabs.org/pacemaker.html>`__ is a cluster resource
manager which can manage a defined set of resource across a set of clustered
nodes. Pacemaker manages the resource with the help of the resource agents.
One among the resource agent is `OCF
<http://www.linux-ha.org/wiki/OCF_Resource_Agents>`__

OCF is nothing but a shell script which accepts a set of actions and returns an
appropriate status code.

With the help of the OCF resource agent ovn/utilities/ovndb-servers.ocf, one
can defined a resource for the pacemaker such that pacemaker will always
maintain one running active server at any time.

After creating a pacemaker cluster, use the following commands to create one
active and multiple backup servers for OVN databases::

    $ pcs resource create ovndb_servers ocf:ovn:ovndb-servers \
         master_ip=x.x.x.x \
         ovn_ctl=<path of the ovn-ctl script> \
         op monitor interval="10s" \
         op monitor role=Master interval="15s"
    $ pcs resource master ovndb_servers-master ovndb_servers \
        meta notify="true"

The `master_ip` and `ovn_ctl` are the parameters that will be used by the OCF
script. `ovn_ctl` is optional, if not given, it assumes a default value of
/usr/share/openvswitch/scripts/ovn-ctl. `master_ip` is the IP address on which
the active database server is expected to be listening, the slave node uses it
to connect to the master node. You can add the optional parameters
'nb_master_port', 'nb_master_protocol', 'sb_master_port', 'sb_master_protocol'
to set the protocol and port.

Whenever the active server dies, pacemaker is responsible to promote one of the
backup servers to be active. Both ovn-controller and ovn-northd needs the
ip-address at which the active server is listening. With pacemaker changing the
node at which the active server is run, it is not efficient to instruct all the
ovn-controllers and the ovn-northd to listen to the latest active server's
ip-address.

This problem can be solved by two ways:

1. By using a native ocf resource agent ``ocf:heartbeat:IPaddr2``.  The IPAddr2
resource agent is just a resource with an ip-address. When we colocate this
resource with the active server, pacemaker will enable the active server to be
connected with a single ip-address all the time. This is the ip-address that
needs to be given as the parameter while creating the `ovndb_servers` resource.

Use the following command to create the IPAddr2 resource and colocate it
with the active server::

    $ pcs resource create VirtualIP ocf:heartbeat:IPaddr2 ip=x.x.x.x \
        op monitor interval=30s
    $ pcs constraint order promote ovndb_servers-master then VirtualIP
    $ pcs constraint colocation add VirtualIP with master ovndb_servers-master \
        score=INFINITY

2. Using load balancer vip ip as a master_ip.  In order to use this feature,
one needs to use listen_on_master_ip_only to no.  Current code for load
balancer have been tested to work with tcp protocol and needs to be
tested/enchanced for ssl. Using load balancer, standby nodes will not listen on
nb and sb db ports so that load balancer will always communicate to the active
node and all the traffic will be sent to active node only.  Standby will
continue to sync using LB VIP IP in this case.

Use the following command to create pcs resource using LB VIP IP::

    $ pcs resource create ovndb_servers ocf:ovn:ovndb-servers \
         master_ip="<load_balance_vip_ip>" \
         listen_on_master_ip_only="no" \
         ovn_ctl=<path of the ovn-ctl script> \
         op monitor interval="10s" \
         op monitor role=Master interval="15s"
    $ pcs resource master ovndb_servers-master ovndb_servers \
        meta notify="true"
