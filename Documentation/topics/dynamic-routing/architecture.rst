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

===========================
Dynamic Routing Integration
===========================

Introduction
------------

OVN integrates with dynamic routing protocols to enable automatic exchange
of routing information between OVN logical networks and the physical
network fabric.  A key design principle is that OVN does not implement any
routing protocol stack itself.  Instead, OVN relies on external routing
protocol daemons --- such as FRR (Free Range Routing) --- running on each
hypervisor (chassis) to handle the protocol control plane.  OVN is not
intended to ever implement routing protocols (BGP, OSPF, or others)
directly.

The routing protocol control plane lives entirely outside OVN.  OVN
interacts with these external daemons indirectly through the Linux kernel
networking stack.  Specifically, ``ovn-controller`` exchanges routes with
the kernel via Netlink and monitors network interfaces for neighbor
information.  This separation of concerns keeps OVN focused on logical
network management while leveraging mature, feature-rich routing
implementations for protocol handling.

OVN supports two main categories of dynamic routing integration:

- **IP Route Exchange** --- Learning routes from and advertising routes to
  external routing peers through VRF routing tables on each chassis.

- **EVPN (Ethernet VPN)** --- Extending Layer 2 and Layer 3 connectivity
  across the fabric by learning remote VTEPs, MAC addresses, and IP
  neighbors through EVPN-capable routing daemons.

Architecture Overview
---------------------

IP Route Exchange
~~~~~~~~~~~~~~~~~

The following diagram shows the interaction between components involved in
dynamic IP route exchange.  The routing protocol daemon (e.g., FRR) and
``ovn-controller`` both operate on each chassis.  They communicate
indirectly through the kernel routing table in a VRF associated with each
logical router that has dynamic routing enabled.

::

    Chassis (Hypervisor)
    +------------------------------------------------------------------+
    |                                                                  |
    |  +---------------------+        +-----------------------------+  |
    |  | Routing Daemon      |        | ovn-controller              |  |
    |  | (e.g., FRR)         |        |                             |  |
    |  |                     |        |                             |  |
    |  |  Speaks BGP, OSPF,  |        |  Monitors VRF tables via    |  |
    |  |  etc. with external |        |  Netlink for learned routes |  |
    |  |  peers              |        |                             |  |
    |  |                     |        |  Installs advertised routes |  |
    |  |  Installs learned   |        |  into VRF tables via        |  |
    |  |  routes into VRF    |        |  Netlink (RTPROT_OVN)       |  |
    |  |  tables             |        |                             |  |
    |  |                     |        |                             |  |
    |  +----------+----------+        +-----+--+--------------------+  |
    |             |                         |  |                       |
    |             | Netlink                 |  | Netlink               |
    |             | (install routes)        |  | (read/write routes)   |
    |             |                         |  |                       |
    |  +----------v-------------------------v--v--------------------+  |
    |  | Linux Kernel - VRF Routing Table                           |  |
    |  | (dynamic-routing-vrf-id / datapath tunnel key)             |  |
    |  +------------------------------------------------------------+  |
    |                                                                  |
    +------------------------------------------------------------------+
                                      |
                                      |
    +------------------------------------------------------------------+
    |                        OVN Southbound Database                   |
    |                                                                  |
    |  +-------------------------+   +------------------------------+  |
    |  | Learned_Route           |   | Advertised_Route             |  |
    |  |                         |   |                              |  |
    |  | Populated by            |   | Populated by ovn-northd      |  |
    |  | ovn-controller with     |   | based on LR config:          |  |
    |  | routes learned from     |   |  - connected routes          |  |
    |  | the VRF routing table   |   |  - connected-as-host routes  |  |
    |  | (dynamic protocols      |   |  - static routes             |  |
    |  |  only, not RTPROT_OVN)  |   |  - NAT external IPs          |  |
    |  |                         |   |  - Load Balancer VIPs        |  |
    |  +-------------------------+   +------------------------------+  |
    |                                                                  |
    +------------------------------------------------------------------+
                                      |
                                      |
    +------------------------------------------------------------------+
    |                          ovn-northd                              |
    |                                                                  |
    |  Reads Learned_Route records and generates logical flows in the  |
    |  IP routing stage of the logical router pipeline.                |
    |                                                                  |
    |  Reads NB Logical_Router configuration and populates             |
    |  Advertised_Route records in the SB database.                    |
    |                                                                  |
    +------------------------------------------------------------------+

EVPN (Ethernet VPN)
~~~~~~~~~~~~~~~~~~~

EVPN integration follows a different pattern from IP route exchange.  An
important distinction is that dynamically learned EVPN information (remote
VTEPs, MAC addresses, IP neighbors) is **not** stored in the OVN
Southbound database.  Instead, each ``ovn-controller`` instance processes
this information locally, in memory, based on what it learns through
Netlink from the kernel.

::

    Chassis (Hypervisor)
    +------------------------------------------------------------------+
    |                                                                  |
    |  +---------------------+        +-----------------------------+  |
    |  | Routing Daemon      |        | ovn-controller              |  |
    |  | (e.g., FRR)         |        |                             |  |
    |  |                     |        |  Monitors bridge/vxlan/     |  |
    |  |  Speaks BGP EVPN    |        |  advertise interfaces for   |  |
    |  |  with peers         |        |  EVPN-enabled LSes          |  |
    |  |                     |        |                             |  |
    |  |  Populates bridge   |        |  Learns:                    |  |
    |  |  FDB, ARP/ND neigh  |        |   - Remote VTEPs (per VNI)  |  |
    |  |  entries, and VXLAN |        |   - FDB entries (MAC addrs) |  |
    |  |  FDB via kernel     |        |   - ARP/ND entries (IPs)    |  |
    |  |                     |        |                             |  |
    |  +----------+----------+        |  Creates OVS VXLAN tunnels  |  |
    |             |                   |  (flow-based) in br-int     |  |
    |             | Netlink           |                             |  |
    |             | (FDB/neighbor     |  Installs bridge FDB and    |  |
    |             |  entries)         |  ARP/ND entries for local   |  |
    |             |                   |  workloads (advertise)      |  |
    |  +----------v-----------+       |                             |  |
    |  | Linux Kernel         |       +------+--+-------------------+  |
    |  |                      |<-- Netlink --+  |                      |
    |  | - Bridge FDB table   |   (monitor)     | OVS VXLAN tunnels    |
    |  | - ARP/ND neigh table |                 |                      |
    |  | - VXLAN interfaces   |       +---------v------------------+   |
    |  +----------------------+       | OVS br-int                 |   |
    |                                 |  - VXLAN tunnel ports      |   |
    |                                 |  - OpenFlow rules for      |   |
    |                                 |    encap/decap per VNI     |   |
    |                                 +----------------------------+   |
    |                                                                  |
    +------------------------------------------------------------------+

IP Route Exchange
-----------------

Deployment Scenario
~~~~~~~~~~~~~~~~~~~

The following diagram illustrates a typical deployment where a logical
router has dynamic routing enabled.  The router is connected to multiple
logical switches hosting workloads, has NAT rules, load balancers, and
static routes configured.  Through dynamic routing, OVN advertises
selected prefixes to the external fabric and learns external routes from
routing peers.

::

              External Network / Fabric
                       |
                       | BGP/OSPF peering
                       |
    +------------------+-------------------+
    |          Routing Daemon (FRR)        |
    |          on Chassis                  |
    +------------------+-------------------+
                       |
                  VRF table
              (Netlink exchange)
                       |
    +------------------+-----------------------------------------------+
    |              ovn-controller                                      |
    |                                                                  |
    |  Advertises routes         Learns routes from VRF                |
    |  into VRF table            and writes to SB Learned_Route        |
    +------------------+-----------------------------------------------+
                       |
                 OVN SB Database
         (Advertised_Route / Learned_Route)
                       |
    +------------------+------------------------------------------------+
    |                       ovn-northd                                  |
    +-------------------------------------------------------------------+
    |                                                                   |
    |                  Logical Router (LR1)                             |
    |                  dynamic-routing = true                           |
    |                  dynamic-routing-redistribute =                   |
    |                      connected,static,nat,lb                      |
    |                                                                   |
    |   Advertised prefixes:               Learned routes:              |
    |                                                                   |
    |   connected:                         From external peers:         |
    |     10.0.1.0/24 (from LS1)             203.0.113.0/24             |
    |     10.0.2.0/24 (from LS2)               via 192.168.1.1          |
    |     10.0.3.0/24 (from LS3)             198.51.100.0/24            |
    |                                          via 192.168.1.2          |
    |   static:                                                         |
    |     172.16.0.0/16                                                 |
    |       via 10.0.1.1                                                |
    |                                                                   |
    |   nat (external IPs):                                             |
    |     192.168.50.10/32 (DNAT+SNAT)                                  |
    |     192.168.50.20/32 (SNAT)                                       |
    |                                                                   |
    |   lb (VIPs):                                                      |
    |     192.168.60.100/32 (LB VIP)                                    |
    |                                                                   |
    +--------+----------------+-----------------+-----------------------+
             |                |                 |
    +--------+-------+ +------+--------+ +------+--------+
    | Logical Switch | | Logical Switch| | Logical Switch|
    |     LS1        | |     LS2       | |     LS3       |
    | 10.0.1.0/24    | | 10.0.2.0/24   | | 10.0.3.0/24   |
    |                | |               | |               |
    | VM1  VM2  VM3  | | VM4  VM5      | | VM6           |
    +----------------+ +---------------+ +---------------+

In this scenario ``ovn-northd`` populates the SB ``Advertised_Route``
table with entries for each prefix type selected by
``dynamic-routing-redistribute``.  On each chassis, ``ovn-controller``
reads these records and installs the corresponding routes (as blackhole
by default, or with a specific nexthop if
``dynamic-routing-v4/v6-prefix-nexthop`` is set) into the VRF routing
table associated with the logical router.  The routing daemon picks up
these routes and advertises them to external peers.

Conversely, when the routing daemon learns routes from external peers, it
installs them into the same VRF table.  ``ovn-controller`` detects these
new routes via Netlink (filtering out routes it installed itself using the
``RTPROT_OVN`` protocol marker) and creates corresponding
``Learned_Route`` records in the SB database.  ``ovn-northd`` then
generates logical flows in the IP routing pipeline stage to implement
forwarding for these learned routes.

IP Route Advertisement
----------------------

When a logical router has ``dynamic-routing`` set to ``true``, ``ovn-northd``
examines the router configuration and populates the ``Advertised_Route``
table in the OVN Southbound database. The types of routes that are
advertised depend on the ``dynamic-routing-redistribute`` option, which
accepts a comma-separated list of the following values:

- ``connected`` --- Subnet prefixes directly connected to the logical
  router ports (e.g., 10.0.1.0/24 for a port with address 10.0.1.1/24).

- ``connected-as-host`` --- Individual host routes (/32 for IPv4, /128
  for IPv6) for each IP address on logical switch ports, router ports,
  and NAT entries associated with this router.

- ``static`` --- All ``Logical_Router_Static_Route`` entries configured on
  the router.

- ``nat`` --- The external IP of each NAT rule on this router and
  neighboring routers that share a distributed gateway port.

- ``lb`` --- The VIP address of each load balancer associated with this
  router and neighboring routers.

These options can also be set per logical router port, overriding the
router-level setting for routes associated with that specific port.

Each ``Advertised_Route`` record includes:

- ``datapath`` --- The logical router datapath this route belongs to.
- ``logical_port`` --- The port binding this route is associated with.
- ``ip_prefix`` --- The IP prefix of this route (e.g., 192.168.100.0/24).
- ``tracked_port`` --- Tracks the port OVN will forward packets for this
  destination to.  An announcing chassis can use this to check if the
  destination is local and adjust route priorities accordingly.

Route Installation on the Chassis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On each chassis, ``ovn-controller`` reads the ``Advertised_Route``
records from the Southbound database and installs corresponding routes
into the Linux VRF routing table associated with the logical router.

Routes are installed via Netlink with the ``RTPROT_OVN`` protocol marker
so that ``ovn-controller`` can distinguish OVN-managed routes from routes
installed by other sources.  By default, advertised routes are installed
as **blackhole** routes (to attract traffic into OVN for processing).  If
``dynamic-routing-v4-prefix-nexthop`` or ``dynamic-routing-v6-prefix-nexthop``
is set on the logical router, routes are installed with the specified
nexthop address instead.

Route Priority
~~~~~~~~~~~~~~

When the ``tracked_port`` field is set on an ``Advertised_Route`` record,
``ovn-controller`` adjusts the route metric based on whether the tracked
port is locally bound on this chassis.  Routes for locally bound ports
receive a higher priority (lower metric value), which causes the routing
daemon to prefer the chassis that actually hosts the workload.  This
mechanism is particularly useful for host routes generated by the
``connected-as-host`` redistribution mode.

The ``dynamic-routing-redistribute-local-only`` option further refines
this behavior: when set to ``true``, ``ovn-controller`` only installs
routes on the chassis where the ``tracked_port`` is locally bound,
preventing other chassis from advertising the route at all.

IP Route Learning
-----------------

``ovn-controller`` monitors the VRF routing tables associated with
dynamic-routing-enabled logical routers for routes installed by external
routing daemons.  This monitoring is performed via Netlink route
notifications (``RTNLGRP_IPV4_ROUTE`` and ``RTNLGRP_IPV6_ROUTE``).

When a route change is detected in a watched VRF table,
``ovn-controller`` dumps the table contents and processes each route.
The following filtering rules apply:

- Routes with protocol ``RTPROT_OVN`` are **skipped** because they were
  installed by ``ovn-controller`` itself (advertised routes).

- Routes with protocol ``RTPROT_STATIC`` or lower are **skipped** because
  they are not dynamic routing protocol routes.

- Only routes installed by dynamic routing protocols (protocol value
  greater than ``RTPROT_STATIC``) are considered for learning.

- Link-local prefixes are **skipped**.

For each qualifying route, ``ovn-controller`` creates a ``Learned_Route``
record in the Southbound database containing the datapath, logical port,
IP prefix, and nexthop.

Flow Generation by ovn-northd
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``ovn-northd`` reads the ``Learned_Route`` table and generates logical
flows in the IP routing stage of the logical router processing pipeline.
These flows implement longest-prefix-match forwarding for the learned
routes.  Learned routes receive a lower priority than static routes,
ensuring that explicitly configured routes always take precedence.

Disabling Route Learning
~~~~~~~~~~~~~~~~~~~~~~~~

Route learning can be disabled on a per-router or per-port basis by
setting the ``dynamic-routing-no-learning`` option to ``true``.  When
this option is enabled, ``ovn-controller`` does not create
``Learned_Route`` records for the affected router or port and removes any
previously learned routes.

VRF Management
--------------

Each logical router with dynamic routing enabled is associated with a
Linux VRF (Virtual Routing and Forwarding) instance on each chassis.
The VRF provides an isolated routing table where ``ovn-controller`` and
the external routing daemon exchange routes.

VRF Table ID
~~~~~~~~~~~~

The VRF routing table ID is determined by one of the following, in order
of precedence:

1. The ``dynamic-routing-vrf-id`` option on the logical router, if set to
   a valid integer (1-4294967295, excluding reserved table IDs such as
   ``RT_TABLE_MAIN`` and ``RT_TABLE_LOCAL``).

2. The tunnel key of the logical router datapath, used as a fallback
   when ``dynamic-routing-vrf-id`` is not configured.

VRF Naming
~~~~~~~~~~

The VRF interface name is determined by the ``dynamic-routing-vrf-name``
option on the logical router.  If not set, the name defaults to
``ovnvrf`` followed by the VRF table ID (e.g., ``ovnvrf42``).  The
name must be a valid Linux network interface name.

VRF Lifecycle
~~~~~~~~~~~~~

When the ``dynamic-routing-maintain-vrf`` option is set to ``true`` on
a logical router port, ``ovn-controller`` creates and manages the VRF
interface on the chassis where the port is bound.  This includes:

- Creating the VRF interface via a ``RTM_NEWLINK`` Netlink message with
  ``IFLA_LINKINFO`` kind ``vrf`` and the appropriate ``IFLA_VRF_TABLE``
  value.

- Deleting the VRF interface when dynamic routing is disabled or the
  port is unbound.

If ``dynamic-routing-maintain-vrf`` is ``false`` (the default), the VRF
is expected to already exist on the chassis, managed by external tooling
or configuration management.

EVPN (Ethernet VPN) Integration
-------------------------------

EVPN extends OVN logical switches across the physical fabric using VXLAN
encapsulation and BGP EVPN for control-plane signaling.  EVPN is enabled
on a logical switch by setting the ``dynamic-routing-vni`` option to a
valid VNI (VXLAN Network Identifier) value (0--16777215).

When EVPN is enabled on a logical switch, the following interface names
must also be configured:

- ``dynamic-routing-bridge-ifname`` --- The Linux bridge interface
  associated with the EVPN domain.

- ``dynamic-routing-vxlan-ifname`` --- One or more VXLAN device interface
  names used for EVPN integration.

- ``dynamic-routing-advertise-ifname`` --- The interface used for
  advertising local MAC and IP bindings to the routing daemon.

Deployment Scenario
~~~~~~~~~~~~~~~~~~~

The following diagram illustrates a deployment with an EVPN-enabled
logical switch.  The logical switch is assigned a VNI (VXLAN Network
Identifier) and is associated with bridge, VXLAN, and advertise
interfaces on each chassis.  Through EVPN, OVN discovers remote VTEPs and
learns remote MAC and IP addresses without storing this information in the
Southbound database.

::

    Chassis A                              Chassis B
    +-------------------------------+      +-------------------------------+
    |                               |      |                               |
    | ovn-controller                |      | ovn-controller                |
    |                               |      |                               |
    | Logical Switch (LS-EVPN)      |      | Logical Switch (LS-EVPN)      |
    | dynamic-routing-vni = 1000    |      | dynamic-routing-vni = 1000    |
    | dynamic-routing-redistribute  |      | dynamic-routing-redistribute  |
    |   = fdb,ip                    |      |   = fdb,ip                    |
    |                               |      |                               |
    | Local workloads:              |      | Local workloads:              |
    |  VM-A1: MAC-A1, 10.0.1.10     |      |  VM-B1: MAC-B1, 10.0.1.20     |
    |  VM-A2: MAC-A2, 10.0.1.11     |      |  VM-B2: MAC-B2, 10.0.1.21     |
    |                               |      |                               |
    | Interfaces configured:        |      | Interfaces configured:        |
    |  bridge-ifname: br-evpn       |      |  bridge-ifname: br-evpn       |
    |  vxlan-ifname:  vxlan1000     |      |  vxlan-ifname:  vxlan1000     |
    |  advertise-ifname: adv-evpn   |      |  advertise-ifname: adv-evpn   |
    |                               |      |                               |
    +-------+-----------+-----------+      +-----------+-----------+-------+
            |           |                              |           |
            |           |                              |           |
    +-------v-----------v-----------+      +-----------v-----------v-------+
    | Linux Kernel                  |      | Linux Kernel                  |
    |                               |      |                               |
    |  br-evpn   (bridge)           |      |  br-evpn   (bridge)           |
    |  vxlan1000 (VXLAN VNI 1000)   |      |  vxlan1000 (VXLAN VNI 1000)   |
    |  adv-evpn  (advertise device) |      |  adv-evpn  (advertise device) |
    |                               |      |                               |
    |  FDB: MAC-A1, MAC-A2 (local)  |      |  FDB: MAC-B1, MAC-B2 (local)  |
    |  Neigh: 10.0.1.10, .11        |      |  Neigh: 10.0.1.20, .21        |
    |                               |      |                               |
    +-------+-----------------------+      +-----------------------+-------+
            |                                                      |
    +-------v-----------------------+      +-----------------------v-------+
    | FRR (BGP EVPN)                |      | FRR (BGP EVPN)                |
    |                               |      |                               |
    |  Reads local FDB/neigh        |      |  Reads local FDB/neigh        |
    |  entries and advertises       |      |  entries and advertises       |
    |  Type-2 (MAC+IP) routes       |      |  Type-2 (MAC+IP) routes       |
    |  to peers                     |      |  to peers                     |
    |                               |      |                               |
    |  Learns remote entries        |      |  Learns remote entries        |
    |  from peers and installs      |      |  from peers and installs      |
    |  them into kernel FDB/neigh   |      |  them into kernel FDB/neigh   |
    |                               |      |                               |
    +-------+-----------------------+      +-----------------------+-------+
            |                                                      |
            |             BGP EVPN peering                         |
            +------------------------------------------------------+

On Chassis A, ``ovn-controller`` installs static bridge FDB entries and
ARP/ND neighbor entries for local workloads (VM-A1, VM-A2) into the
kernel via Netlink on the advertise interface.  FRR reads these entries
and advertises them as EVPN Type-2 routes to its peers.

When FRR on Chassis A learns remote entries from Chassis B (MAC-B1,
MAC-B2, and their IPs), it installs them into the kernel bridge FDB and
neighbor tables.  ``ovn-controller`` on Chassis A monitors the VXLAN and
bridge interfaces via Netlink to discover:

- Remote VTEPs: the tunnel endpoints on Chassis B for VNI 1000.
- Remote MACs: FDB entries for MAC-B1 and MAC-B2.
- Remote IPs: ARP/ND entries for 10.0.1.20 and 10.0.1.21.

``ovn-controller`` creates one flow-based OVS VXLAN tunnel port in
``br-int`` for each configured EVPN VXLAN port and installs OpenFlow
rules to encapsulate traffic destined for remote MACs/IPs using the
appropriate VNI and VTEP destination.

Remote VTEP Discovery
~~~~~~~~~~~~~~~~~~~~~

``ovn-controller`` monitors the VXLAN interfaces configured for each
EVPN-enabled logical switch via Netlink neighbor table notifications.
When the routing daemon (e.g., FRR) learns about remote VTEPs through
BGP EVPN peering, it installs neighbor entries in the kernel for the
VXLAN device.  ``ovn-controller`` detects these entries and extracts the
remote VTEP IP address, destination port, and VNI.

``ovn-controller`` creates one flow-based OVS VXLAN tunnel port in
``br-int`` for each configured EVPN VXLAN port (configured via
``ovn-evpn-vxlan-ports`` in the ``Open_vSwitch`` table).

For each discovered remote VTEP, ``ovn-controller``:

1. Allocates a tunnel key for the binding.

2. Installs OpenFlow rules to encapsulate outbound traffic with the
   correct VNI and VTEP destination, and to decapsulate inbound traffic
   from the remote VTEP.

3. Creates multicast groups per VNI for BUM (Broadcast, Unknown unicast,
   Multicast) traffic flooding to all remote VTEPs in the same EVPN
   domain.

FDB and Neighbor Learning
~~~~~~~~~~~~~~~~~~~~~~~~~

In addition to remote VTEP discovery, ``ovn-controller`` monitors the
bridge and VXLAN interfaces for:

- **FDB (Forwarding Database) entries** --- MAC addresses learned
  through EVPN Type-2 routes, indicating which remote VTEP a given MAC
  address is reachable through.

- **ARP/ND neighbor entries** --- IP-to-MAC bindings learned through
  EVPN Type-2 MAC+IP routes, which ``ovn-controller`` injects into the
  adjacent logical router pipeline for L3 forwarding.

The ``dynamic-routing-fdb-prefer-local`` option controls the lookup
order for FDB entries: when set to ``true``, OVN first checks the
Southbound FDB table (populated through normal OVN mechanisms) before
falling back to the locally learned EVPN FDB cache.  By default, the
EVPN-learned entries take precedence.

Similarly, the ``dynamic-routing-arp-prefer-local`` option controls the
lookup order for ARP/ND entries: when set to ``true``, the Southbound
``MAC_Binding`` table is checked before the EVPN-learned neighbor cache.

Unlike IP route exchange, dynamically learned EVPN information
(remote VTEPs, FDB entries, and ARP/ND neighbors) is **not** stored
in the OVN Southbound database.  Each ``ovn-controller`` instance
processes this information locally, in memory.  This design avoids
the overhead of synchronizing high-volume, rapidly changing L2/L3
state through the centralized database.

Local MAC and IP Advertisement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``dynamic-routing-redistribute`` option on EVPN-enabled logical
switches controls what local information ``ovn-controller`` advertises
to the routing daemon by installing static entries into the kernel:

- ``fdb`` --- ``ovn-controller`` installs static bridge FDB entries for
  all local workloads (VIF ports, container ports, virtual ports,
  distributed gateway ports, and gateway router ports) on the advertise
  interface.  The routing daemon reads these entries and advertises them
  as EVPN Type-2 MAC routes to its peers.

- ``ip`` --- ``ovn-controller`` installs static ARP/ND neighbor entries
  for all local IP-to-MAC bindings (VIF ports and router ports) on the
  advertise interface.  The routing daemon advertises these as EVPN
  Type-2 MAC+IP routes.

Advertised MAC Binding
~~~~~~~~~~~~~~~~~~~~~~

The ``Advertised_MAC_Binding`` table in the Southbound database is
populated by ``ovn-northd`` for EVPN-enabled logical switches.  It
contains the IP and MAC address pairs that should be announced to the
external network fabric.  Each record includes:

- ``datapath`` --- The logical switch this binding belongs to.
- ``logical_port`` --- The port binding this entry is associated with.
- ``ip`` --- The IP address to announce.
- ``mac`` --- The MAC address to announce.

``ovn-controller`` reads these records and installs the corresponding
static FDB and neighbor entries on the appropriate kernel interfaces,
making them available to the routing daemon for EVPN advertisement.

EVPN Source IP Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``ovn-evpn-local-ip`` option in the ``Open_vSwitch`` table
``external_ids`` configures the source IP addresses used for EVPN VXLAN
tunnels.  The format supports per-VNI IP assignment:

``vni0-IPv4,vni1-IPv4,vni1-IPv6,IPv4,IPv6``

If no VNI-specific address is provided, the default IP address is used
for all VNIs.
