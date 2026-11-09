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

==================
Replicated Gateway
==================

A *replicated gateway* is a group of two or more physical nodes that present
themselves to OVN as a single chassis. Every node of the group runs its own
``ovn-controller``, but all of them are configured with the same chassis name
(``external_ids:system-id``) and with the same encapsulation IP
(``external_ids:ovn-encap-ip``). The encapsulation IP is an anycast address,
it is announced into the underlay (statically or by a routing protocol) by all
the nodes of the group, and the underlay load-balances the tunnel traffic
between them with ECMP.

::

                        underlay with ECMP to 10.0.0.1

    +-------------------+                       +----------------------+
    |                   |  nexthop via gw-1     |  gateway node 1      |
    |   hypervisor      +---------------------->|  system-id: vgw      |
    |                   |                       |  ovn-encap-ip:       |
    |   ovn-encap-ip:   |                       |          10.0.0.1    |
    |     192.168.0.10  |                       +----------+-----------+
    |                   |                                  |
    |                   |  nexthop via gw-2     +----------+-----------+
    |                   +---------------------->|  gateway node 2      |
    |                   |                       |  system-id: vgw      |
    +-------------------+                       |  ovn-encap-ip:       |
                                                |          10.0.0.1    |
                                                +----------+-----------+
                                                           |
                                       physical network    |
    -------------------------------------------------------+------------

From the point of view of the OVN databases there is a single chassis: a single
``Chassis`` record, a single ``Encap`` record, and a single binding for every
port that is placed on the replicated gateway (for example the chassisredirect
port of a distributed gateway port). ``ovn-northd`` and the other
``ovn-controller`` instances do not know, and do not need to know, how many
physical nodes are behind that chassis. A hypervisor keeps a single tunnel to
the anycast encapsulation IP, and the underlay decides which node of the group
terminates a given flow.

There is no coordination and no leader election between the nodes of the
group while writing to SBDB: every ``ovn-controller`` independently does the
full bookkeeping for that one chassis, and it is the idempotence of those
writes that keeps them from fighting each other.

Two consequences follow from this.  First, the columns that OVN derives from
the local node rather than from the configuration must be forced to the same
value on every node.  More detailed information on this is provided in the
``Identical OVS and OVN configuration and features`` section below.  Second,
the nodes do not share any runtime state, so nothing that relies on conntrack
can be used on a replicated gateway, see the
``Only stateless traffic is supported`` section below.

Use case
--------
This is useful when the capacity or the availability of a single gateway node
is not enough: the group scales horizontally, and losing one node only means
that the underlay stops using one of the ECMP nexthops, without any change in
the OVN databases and without the gateway having to be rescheduled to another
chassis.

A typical deployment looks as follows:

* Two (or more) gateway nodes are installed with the same OVN and OVS
  versions and with an identical ``ovn-controller`` configuration. Each of
  them configures the anycast encapsulation IP locally, e.g. on the loopback
  interface, so that the kernel accepts the tunnel packets destined to it::

      $ ovs-vsctl set open . external-ids:system-id=vgw
      $ ovs-vsctl set open . external-ids:ovn-encap-ip=10.0.0.1
      $ ovs-vsctl set open . external-ids:ovn-encap-type=geneve
      $ ip address add 10.0.0.1/32 dev lo

* The anycast address is reachable in the underlay through the physical
  addresses of all the nodes of the group. On the hypervisors, and on any
  other node that has to reach the replicated gateway, this is an ECMP route::

      $ ip route replace 10.0.0.1/32 \
            nexthop via 192.168.0.1 dev eth0 \
            nexthop via 192.168.0.2 dev eth0

  In a real deployment the route is normally learned from the fabric, with the
  gateway nodes advertising the anycast ip.

* The logical topology is configured as usual, referring to the chassis by its
  single name, e.g.::

      $ ovn-nbctl lrp-set-gateway-chassis lr0-public vgw 10

Requirements and restrictions
-----------------------------

The nodes of a replicated gateway are not independent chassis, they are one
chassis that happens to run on several machines. Everything that OVN stores
per chassis is therefore shared, and everything that OVN computes per chassis
must produce the same result on every node of the group. This leads to the
following requirements.

Identical OVS and OVN configuration and features
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All the nodes of the group must run the same OVS and OVN versions and must
expose the same set of features. ``ovn-controller`` reports the capabilities
of the local OVS instance in the ``Chassis`` record (``other_config``, for
example the supported datapath interface types, and the various
``ovn-chassis-feature`` entries), and ``ovn-northd`` generates the logical
flows for the chassis based on those values. If the nodes disagree, the
``Chassis`` record will keep flapping between the values reported by each node,
``ovn-northd`` will keep recomputing, and the node whose capabilities do not
match the ones currently published may not be able to process the flows it
receives.

For the same reason, every chassis scoped configuration option has to be
identical on all the nodes, including, for example: ``external_ids:hostname``,
``external_ids:ovn-bridge-mappings`` and all others.

Only stateless traffic is supported
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The nodes of a replicated gateway do not share any runtime state, and in
particular they do not share conntrack. The underlay picks one of them per
flow, and nothing guarantees that the two directions of a connection, or the
packets of a connection before and after a change of the ECMP nexthops (a node
being added, removed, rebooted or simply an ECMP rehash), are handled by the
same node. Any feature that needs the connection state to be on the node that
processes the packet is therefore not supported on a replicated gateway:

* load balancers,
* stateful NAT, that is ``snat`` and ``dnat_and_snat`` (unless configured as
  stateless), and NAT with ``ct-commit-all`` enabled,
* stateful ACLs, and anything else that relies on conntrack, for example
  load balancer hairpinning or ECMP routes with
  ``options:ecmp_symmetric_reply`` set.

Only stateless forwarding, e.g. plain routing and switching, stateless NAT and
stateless ACLs, behaves correctly, because every packet can be handled
independently by any node of the group.

Example
-------

The ``ovn multinode replicated gateway`` test in ``tests/multinode.at`` sets up
a complete example of a two node replicated gateway with an underlay ECMP route
to the anycast encapsulation IP, a hypervisor with a VM behind the gateway
and an external node that does not run OVN at all.
