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

======================================
Dynamic Routing Configuration Examples
======================================

Introduction
------------

This document provides configuration examples for OVN's dynamic routing
feature.  For the underlying architecture, data flow, and full description
of each option, see :doc:`/topics/dynamic-routing/architecture` and
``ovn-nb``\(5).

Configuration Examples
----------------------

The following examples demonstrate complete configurations for common
deployment scenarios.

Example: Gateway Router with BGP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A centralized gateway router pinned to a specific chassis, peering
with an external BGP speaker to advertise connected and static
routes.

::

    External BGP Peer
              |
              | BGP peering
              |
    +---------+---------+
    | LS-Fabric         |
    | 192.168.1.0/24    |
    +---------+---------+
              |
    +---------+---------+
    | Gateway Router    |  (lr-gw, pinned to chassis-1)
    | 10.0.0.1/24       |  dynamic-routing = true
    +---------+---------+
              |
    +---------+---------+
    | Logical Switch    |  (ls-internal)
    | 10.0.0.0/24       |
    +---------+---------+
              |
        VM1  VM2  VM3

**Create the logical topology.**
::

    $ ovn-nbctl lr-add lr-gw
    $ ovn-nbctl ls-add ls-internal
    $ ovn-nbctl ls-add ls-fabric

    # Router port toward the internal network.
    $ ovn-nbctl lrp-add lr-gw lrp-internal \
        00:00:00:00:00:01 10.0.0.1/24
    $ ovn-nbctl lsp-add-router-port ls-internal \
        lsp-internal-to-gw lrp-internal

    # Router port toward the fabric.
    $ ovn-nbctl lrp-add lr-gw lrp-fabric \
        00:00:00:00:00:02 192.168.1.1/24
    $ ovn-nbctl lsp-add-router-port ls-fabric \
        lsp-fabric-to-gw lrp-fabric

    # Localnet port for physical connectivity.
    $ ovn-nbctl lsp-add-localnet-port ls-fabric \
        lsp-fabric-ln physnet-fabric

**Pin the router to a chassis and enable dynamic routing.**

Enable IP route exchange on this logical router with
``dynamic-routing=true``.  The ``dynamic-routing-redistribute`` option
controls which route types are advertised to external peers ---
``connected`` advertises the subnet prefixes of the router's ports
and ``static`` advertises all configured static routes.  Set an
explicit ``dynamic-routing-vrf-id`` so the VRF table ID is
predictable in FRR configuration.

::

    $ ovn-nbctl set Logical_Router lr-gw \
        options:chassis=chassis-1 \
        options:dynamic-routing=true \
        options:dynamic-routing-redistribute=connected,static \
        options:dynamic-routing-vrf-id=100

**Configure VRF management and routing protocol redirect.**

Setting ``dynamic-routing-maintain-vrf=true`` on the fabric-facing
port lets ``ovn-controller`` create and delete the VRF automatically
when the port is bound or unbound.

A dedicated logical switch port (``lsp-bgp``) is added for the BGP
daemon.  The ``routing-protocols`` and ``routing-protocol-redirect``
options on the router port tell OVN to forward BGP (TCP 179) and BFD
(UDP 3784) control plane traffic to that switch port, so FRR can peer
using the router port's IP addresses.

Periodic IPv6 Router Advertisements are enabled to support BGP
unnumbered (RFC 5549), where the link-local nexthop is discovered
automatically.

::

    # Let ovn-controller create/delete the VRF automatically.
    $ ovn-nbctl set Logical_Router_Port lrp-fabric \
        options:dynamic-routing-maintain-vrf=true

    # Add a logical switch port for the BGP daemon.
    $ ovn-nbctl lsp-add ls-fabric lsp-bgp
    $ ovn-nbctl lsp-set-addresses lsp-bgp unknown

    # Redirect BGP and BFD control plane traffic to lsp-bgp.
    $ ovn-nbctl set Logical_Router_Port lrp-fabric \
        options:routing-protocols=BGP,BFD \
        options:routing-protocol-redirect=lsp-bgp

    # Enable periodic RAs for BGP unnumbered peer discovery.
    $ ovn-nbctl set Logical_Router_Port lrp-fabric \
        ipv6_ra_configs:send_periodic=true \
        ipv6_ra_configs:address_mode=slaac \
        ipv6_ra_configs:max_interval=10 \
        ipv6_ra_configs:min_interval=5

**Bind the BGP interface on the chassis.**
::

    # Create an OVS internal port bound to the BGP LSP.
    $ ovs-vsctl add-port br-int ext0-bgp -- \
        set Interface ext0-bgp type=internal \
        external-ids:iface-id=lsp-bgp

    # Place the interface into the VRF.
    $ ip link set dev ext0-bgp master ovnvrf100
    $ ip link set dev ext0-bgp up

**Configure FRR on the chassis.**
::

    configure terminal

    vrf ovnvrf100
    exit-vrf

    router bgp 65000 vrf ovnvrf100
      bgp router-id 192.168.1.1
      neighbor ext0-bgp interface remote-as external
      address-family ipv4 unicast
        redistribute kernel
      exit-address-family
      address-family ipv6 unicast
        redistribute kernel
        neighbor ext0-bgp activate
      exit-address-family

Example: Distributed Router with Gateway Ports
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A distributed logical router with a distributed gateway port,
advertising connected, NAT, and load balancer routes.  The
``local-only`` option ensures host routes are announced only from the
chassis hosting the workload.

::

            External BGP Peer
                  |
                  | BGP peering
                  |
        +---------+---------+
        | LS-Fabric         |
        | 172.16.0.0/24     |
        +---------+---------+
                  |
    +-------------+-------------------+
    |   Distributed LR                |
    |   (lr-dist)                     |
    |   dynamic-routing = true        |
    |   NAT: 172.16.0.10 -> 10.0.1.10 |
    |   LB VIP: 172.16.0.100          |
    +--------+----------+-------------+
             |          |
       +-----+------+ +-+---------+
       | LS-A       | | LS-B      |
       | 10.0.1/24  | | 10.0.2/24 |
       +-----+------+ +-----+-----+
             |               |
           VM-A1           VM-B1
        (chassis-1)     (chassis-2)

**Create the distributed router with a gateway port.**
::

    $ ovn-nbctl lr-add lr-dist
    $ ovn-nbctl ls-add ls-a
    $ ovn-nbctl ls-add ls-b
    $ ovn-nbctl ls-add ls-fabric

    # Internal ports.
    $ ovn-nbctl lrp-add lr-dist lrp-a \
        00:00:00:00:01:01 10.0.1.1/24
    $ ovn-nbctl lsp-add-router-port ls-a lsp-a-to-lr lrp-a

    $ ovn-nbctl lrp-add lr-dist lrp-b \
        00:00:00:00:01:02 10.0.2.1/24
    $ ovn-nbctl lsp-add-router-port ls-b lsp-b-to-lr lrp-b

    # Distributed gateway port.
    $ ovn-nbctl lrp-add lr-dist lrp-gw \
        00:00:00:00:02:01 172.16.0.1/24
    $ ovn-nbctl lsp-add-router-port ls-fabric \
        lsp-fabric-to-lr lrp-gw

    # Configure HA chassis group for the gateway port.
    $ ovn-nbctl ha-chassis-group-add ha-gw
    $ ovn-nbctl ha-chassis-group-add-chassis ha-gw \
        chassis-1 10
    $ ovn-nbctl ha-chassis-group-add-chassis ha-gw \
        chassis-2 5
    $ GRP=$(ovn-nbctl --bare --columns=_uuid \
        find HA_Chassis_Group name=ha-gw)
    $ ovn-nbctl set Logical_Router_Port lrp-gw \
        ha_chassis_group=$GRP

**Add NAT and load balancer.**
::

    $ ovn-nbctl lr-nat-add lr-dist dnat_and_snat \
        172.16.0.10 10.0.1.10
    $ ovn-nbctl lb-add lb-web 172.16.0.100:80 \
        10.0.1.10:8080,10.0.2.10:8080
    $ ovn-nbctl lr-lb-add lr-dist lb-web

**Enable dynamic routing with NAT and LB redistribution.**

Here ``dynamic-routing-redistribute`` includes ``nat`` (NAT external
IPs) and ``lb`` (load balancer VIPs) in addition to ``connected``
subnets.  Setting ``dynamic-routing-redistribute-local-only=true`` on
the gateway port ensures these host routes are only advertised from
the chassis where the tracked workload port is locally bound,
avoiding unnecessary traffic tromboning.

::

    $ ovn-nbctl set Logical_Router lr-dist \
        options:dynamic-routing=true \
        options:dynamic-routing-redistribute=connected,nat,lb \
        options:dynamic-routing-vrf-id=200

    $ ovn-nbctl set Logical_Router_Port lrp-gw \
        options:dynamic-routing-maintain-vrf=true \
        options:dynamic-routing-redistribute-local-only=true

With ``local-only`` enabled, NAT and LB host routes are only
advertised on the chassis where their traffic is processed,
ensuring optimal traffic forwarding.

**Set up routing protocol redirect and FRR** (same pattern as the
gateway router example above).

Verification
------------

Checking OVN State
~~~~~~~~~~~~~~~~~~

Verify that ``ovn-northd`` has populated the ``Advertised_Route``
table::

    $ ovn-sbctl list Advertised_Route

Check for learned routes from external peers::

    $ ovn-sbctl list Learned_Route

Checking the VRF and Kernel Routes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Verify the VRF exists and is up::

    $ ip link show type vrf

List routes in the VRF table.  Routes marked ``proto ovn`` were
installed by ``ovn-controller``; routes with other protocol values
(e.g., ``proto bgp``) were learned from the routing daemon::

    $ ip route show table 100

Checking FRR State
~~~~~~~~~~~~~~~~~~

Verify BGP peering is established::

    $ vtysh -c "show bgp summary"

Check received and advertised routes::

    $ vtysh -c "show bgp ipv4 unicast"
    $ vtysh -c "show bgp ipv6 unicast"

Best Practices
--------------

**Use explicit VRF IDs.**
Set ``dynamic-routing-vrf-id`` rather than relying on the datapath
tunnel key.  Explicit IDs make the VRF configuration predictable and
easier to reference in FRR configurations and monitoring.

**Use local-only for host routes.**
When using ``connected-as-host`` redistribution, combine it with
``dynamic-routing-redistribute-local-only=true`` to ensure host
routes are only announced from the chassis that owns the workload.
This provides optimal traffic forwarding and avoids unnecessary
traffic tromboning.

**Let ovn-controller manage VRFs when possible.**
Set ``dynamic-routing-maintain-vrf=true`` on the logical router port
to let ``ovn-controller`` handle VRF creation and deletion.  This
simplifies chassis provisioning and ensures VRF lifecycle matches
port binding.

**Configure BFD for fast failure detection.**
Include ``BFD`` in the ``routing-protocols`` option and enable BFD
in FRR for sub-second failure detection.  This significantly improves
convergence time compared to relying on BGP hold timers alone.

**Use per-port redistribution for multi-homed setups.**
When a chassis has multiple fabric links, use per-port
``dynamic-routing-redistribute`` and ``dynamic-routing-port-name`` to
control exactly which routes are advertised and learned on each link.

See Also
--------

- :doc:`/topics/dynamic-routing/architecture` --- Architecture and
  internal design of the dynamic routing feature.

- ``ovn-nb``\(5) --- Full reference for all ``Logical_Router``
  and ``Logical_Router_Port`` dynamic routing options.

- ``ovn-sb``\(5) --- Documentation of the ``Advertised_Route``
  and ``Learned_Route`` tables.

- ``ovn-controller``\(8) --- Controller-side configuration options
  including ``dynamic-routing-port-mapping``.
