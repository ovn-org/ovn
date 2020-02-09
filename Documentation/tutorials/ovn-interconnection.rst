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

===================
OVN Interconnection
===================

This document provides a guide for interconnecting multiple OVN deployements
with OVN managed tunneling.  More details about the OVN Interconnectiong design
can be found in ``ovn-architecture``\(7) manpage.

This document assumes two or more OVN deployments are setup and runs normally,
possibly at different data-centers, and the gateway chassises of each OVN
are with IP addresses that are reachable between each other.

Setup Interconnection Databases
-------------------------------

To interconnect different OVNs, you need to create global OVSDB databases that
store interconnection data.  The databases can be setup on any nodes that are
accessible from all the central nodes of each OVN deployment.  It is
recommended that the global databases are setup with HA, with nodes in
different avaialbility zones, to avoid single point of failure.

1. Install OVN packages on each global database node.

2. Start OVN IC-NB and IC-SB databases.

   On each global database node ::

    $ ovn-ctl [options] start_ic_ovsdb

   Options depends on the HA mode you use.  To start standalone mode with TCP
   connections, use ::

    $ ovn-ctl --db-ic-nb-create-insecure-remote=yes \
              --db-ic-sb-create-insecure-remote=yes start_ic_ovsdb

   This command starts IC database servers that accept both unix socket and
   TCP connections.  For other modes, see more details with ::

    $ ovn-ctl --help

Register OVN to Interconnection Databases
-----------------------------------------

For each OVN deployment, set an availability zone name ::

    $ ovn-nbctl set NB_Global . name=<availability zone name>

The name should be unique across all OVN deployments, e.g. ovn-east,
ovn-west, etc.

For each OVN deployment, start the ``ovn-ic`` daemon on central nodes ::

    $ ovn-ctl --ovn-ic-nb-db=<IC-NB> --ovn-ic-sb-db=<IC-SB> \
              --ovn-northd-nb-db=<NB> --ovn-northd-sb-db=<SB> [more options] start_ic

An example of ``<IC-NB>`` is ``tcp:<global db hostname>:6645``, or for
clustered DB: ``tcp:<node1>:6645,tcp:<node2>:6645,tcp:<node3>:6645``.
``<IC-SB>`` is similar, but usually with a different port number, typically,
6646.

For ``<NB>`` and ``<SB>``, use same connection methods as for starting
``northd``.

Verify each OVN registration from global IC-SB database, using
``ovn-ic-sbctl``, either on a global DB node or other nodes but with property
DB connection method specified in options ::

    $ ovn-ic-sbctl show

Configure Gateways
------------------

For each OVN deployment, specify some chassises as interconnection gateways.
The number of gateways you need depends on the scale and bandwidth you need for
the traffic between the OVN deployments.

For a node to work as an interconnection gateway, it must firstly be installed
and configured as a regular OVN chassis, with OVS and ``ovn-controller``
running.  To make a chassis as an interconnection gateway, simply run the
command on the chassis ::

    $ ovs-vsctl set open_vswitch . external_ids:ovn-is-interconn=true

After configuring gateways, verify from the global IC-SB database ::

    $ ovn-ic-sbctl show

Create Transit Logical Switches
-------------------------------

Transit Logical Switches, or Transit Switches, are virtual switches for
connecting logical routers in different OVN setups. ::

    $ ovn-ic-nbctl ts-add <name>

After creating a transit switch, it can be seen from each OVN deployment's
Northbound database, which can be seen using ::

    $ ovn-nbctl find logical_switch other_config:interconn-ts=<name>

You will also see it with simply ``ovn-nbctl ls-list``.

If there are multiple tenants that require traffic being isolated from each
other, then multiple transit switches can be created accordingly.

Connect Logical Routers to Transit Switches
-------------------------------------------

Connect logical routers from each OVN deployment to the desired transit
switches just as if they are regular logical switches, which includes below
steps (from each OVN, for each logical router you want to connect).

Assume a transit switch named ``ts1`` is already created in ``IC-NB`` and a
logical router ``lr1`` created in current OVN deployment.

1. Create a logical router port. ::

    $ ovn-nbctl lrp-add lr1 lrp-lr1-ts1 aa:aa:aa:aa:aa:01 169.254.100.1/24

   (The mac and IP are examples.)

2. Create a logical switch port on the transit switch and peer with the logical
   router port. ::

    $ ovn-nbctl lsp-add ts1 lsp-ts1-lr1 -- \
            lsp-set-addresses lsp-ts1-lr1 router -- \
            lsp-set-type lsp-ts1-lr1 router -- \
            lsp-set-options lsp-ts1-lr1 router-port=lrp-lr1-ts1

3. Assign gateway(s) for the logical router port. ::

    $ ovn-nbctl lrp-set-gateway-chassis lrp-lr1-ts1 <gateway name> [priority]

   Optionally, you can assign more gateways and specify priorities, to achieve
   HA, just as usual for a distributed gateway port.

Similarly in another OVN deployment, you can connect a logical router (e.g.
lr2) to the same transit switch the same way, with a different IP (e.g.
169.254.100.2) on the same subnet.

The ports connected to transit switches will be automatically populated to
``IC-SB`` database, which can be verified by ::

    $ ovn-ic-sbctl show

Create Static Routes
--------------------

Now that you have all the physical and logical topologies ready, simply create
static routes between the OVN deployments so that packets can be forwarded by
the logical routers through transit switches to the remote OVN.

For example, in ovn-east, there are workloads using 10.0.1.0/24 under lr1, and
in ovn-west, there are workloads using 10.0.2.0/24 under lr2.

In ovn-east, add below route ::

    $ ovn-nbctl lr-route-add lr1 10.0.2.0/24 169.254.100.2

In ovn-west, add below route ::

    $ ovn-nbctl lr-route-add lr2 10.0.1.0/24 169.254.100.1

Now the traffic should be able to go through between the workloads through
tunnels crossing gateway nodes of ovn-east and ovn-west.

Route Advertisement
-------------------

Alternatively, you can avoid the above manual static route configuration by
enabling route advertisement and learning on each OVN deployment ::

    $ ovn-nbctl set NB_Global . options:ic-route-adv=true \
                                options:ic-route-learn=true

With this setting, the above routes will be automatically learned and
configured in Northbound DB in each deployment.  For example, in ovn-east, you
will see the route ::

    $ ovn-nbctl lr-route-list lr1
    IPv4 Routes
                 10.0.2.0/24             169.254.100.2 dst-ip (learned)

In ovn-west you will see ::

    $ ovn-nbctl lr-route-list lr2
    IPv4 Routes
                 10.0.1.0/24             169.254.100.1 dst-ip (learned)

Static routes configured in the routers can be advertised and learned as well.
For more details of router advertisement and its configure options, please
see <code>ovn-nb</code>(5).
