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

==============
OVN To-do List
==============

* Refactor ovn-northd code to have separate functions to add logical flows
  for gateway logical routers and logical routers with distributed gateway
  port.

* VLAN trunk ports.

  Russell Bryant: "Today that would require creating 4096 ports for the VM and
  attach to 4096 OVN networks, so doable, but not quite ideal."

* Service function chaining.

* Hitless upgrade, especially for data plane.

* Dynamic IP to MAC binding enhancements.

  OVN has basic support for establishing IP to MAC bindings dynamically, using
  ARP.

  * Table size limiting.

    The table of MAC bindings must not be allowed to grow unreasonably large.

* MTU handling (fragmentation on output)

* Support multiple tunnel encapsulations in Chassis.

  So far, both ovn-controller and ovn-controller-vtep only allow chassis to
  have one tunnel encapsulation entry.  We should extend the implementation
  to support multiple tunnel encapsulations.

* Update learned MAC addresses from VTEP to OVN

  The VTEP gateway stores all MAC addresses learned from its physical
  interfaces in the 'Ucast_Macs_Local' and the 'Mcast_Macs_Local' tables.
  ovn-controller-vtep should be able to update that information back to
  ovn-sb database, so that other chassis know where to send packets destined
  to the extended external network instead of broadcasting.

* Translate ovn-sb Multicast_Group table into VTEP config

  The ovn-controller-vtep daemon should be able to translate the
  Multicast_Group table entry in ovn-sb database into Mcast_Macs_Remote table
  configuration in VTEP database.

* OVN OCF pacemaker script to support Active / Passive HA for OVN dbs provides
  the option to configure the inactivity_probe value. The default 5 seconds
  inactivity_probe value is not sufficient and ovsdb-server drops the client
  IDL connections for openstack deployments when the neutron server is heavily
  loaded.

  We need to find a proper solution to solve this issue instead of increasing
  the inactivity_probe value.

* ACL

  * Support FTP ALGs.

* OVN Interconnection

  * Packaging for Debian.

* IP Multicast Relay

  * When connecting bridged logical switches (localnet) to logical routers
    with IP Multicast Relay enabled packets might get duplicated. We need
    to find a way of determining if routing has already been executed (on a
    different hypervisor) for the IP multicast packet being processed locally
    in the router pipeline.

* ovn-controller Incremental processing

  * Implement I-P for datapath groups.
  * Implement I-P for route exchange relevant ports.

* ovn-northd parallel logical flow processing

  * Multi-threaded logical flow computation was optimized for the case
    when datapath groups are disabled.  Datpath groups are always enabled
    now so northd parallel processing should be revisited.

* ovn-controller daemon module

  * Dumitru Ceara: Add a new module e.g. ovn/lib/daemon-ovn.c that wraps
    OVS' daemonize_start() call and initializes the additional things, like
    the unixctl commands. Or, we should move the APIs such as
    daemon_started_recently() to OVS's lib/daemon.

* Chassis_Template_Var

  * Support template variables when tracing packets with ovn-trace.

* Load Balancer templates

  * Support combining the VIP IP and port into a single template variable.

* ovn-controller conditional monitoring

  * Improve sub-ports (with parent_port set) conditional monitoring; these
    are currently unconditionally monitored, even if ovn-monitor-all is
    set to false.

* ovn-northd parallel build

  * Move the lflow build parallel processing from northd.c to lflow-mgr.c
    This would also ensure that the variables declared in northd.c
    (eg. thread_lflow_counter) are not externed in lflow-mgr.c.

* Remove flows with `check_pkt_larger` when userspace datapath can handle
  PMTUD. (https://issues.redhat.com/browse/FDP-256)

* Remove ssl_ciphersuites workaround for clustered databases from ovn-ctl
  after 26.03 release, assuming it will be an LTS release.

* Dynamic Routing

  * Add incremental processing of en_dynamic_routes for stateful configuration
    changes.

  * The ovn-controller currently loads all Advertised_Route entries on startup.
    This is to prevent deleting our routes on restart. If we defer updating
    routes until we are sure to have loaded all necessary Advertised_Routes
    this could be changed.

  * Improve handling of the Learned_Route table in ovn-controller conditional
    monitoring; once a new local datapath is added we need to wait for
    monitoring conditions to update before we actually try to learn routes.
    Otherwise we could try to add duplicated Learned_Routes and the ovnsb
    commit would fail.

  * Allow ovn-evpn-local-ip to accept list of
    $VNI1:$LOCAL_IP1,$VNI2:$LOCAL_IP2 combinations which will be properly
    reflected in physical flows for given LS with VNI.

  * Learn FDBs dynamically from the incoming traffic for EVPN. The same way
    we do for other traffic passing through LS.

  * Add support for EVPN L3, that involves MAC Binding learning and
    advertisement.

* Datapath sync nodes

  * Migrate data stored in the ovn\_datapath structure to
    ovn\_synced\_logical_router and ovn\_synced\_logical\_switch. This will
    allow for the eventual removal of the ovn\_datapath structure from the
    codebase.

* Logical Router Policies

  * Add support for configuring output\_port for reroute router policies that
    have more than one nexthop (ECMP).  This probably requires a redesign of
    the Northbound Logical_Router_Policy database schema.

* CI

  * ovn-kubernetes: Only a subset of the ovn-kubernetes features is currently
    tested in GitHub CI.  We should extend our testing to support
    OVN_ENABLE_INTERCONNECT=true and potentially more of the CI lanes
    ovn-kubernetes/ovn-kubernetes defines in its GitHub project.

==============
OVN Deprecation plan
==============

The following section contains deprecation plan for certain internal features
and actions. For each OVN version it contains ``Deprecated`` and ``Removed``.
``Deprecated`` means that the internal action will print a warning on usage,
but it will still be parsed and processed. There should be also clearly stated
when the feature/action will move from ``Deprecated`` to ``Removed``.
``Removed`` will print a warning and won't be processed further.

* 26.03 Deprecated

  * ``ct_lb`` action, should be removed in 26.09.

* 26.03 Removed

  * ``PUT_ICMP4_FRAG_MTU`` action
  * ``PUT_ICMP6_FRAG_MTU`` action

* 24.09 Deprecated

  * ``OVN_FEATURE_PORT_UP_NOTIF`` feature, should be removed in 26.09.
  * ``OVN_FEATURE_CT_NO_MASKED_LABEL``, should be removed in 26.09.
  * ``OVN_FEATURE_CT_LB_RELATED``, should be removed in 26.09.
  * ``PUT_ICMP4_FRAG_MTU`` action, should be removed in 26.03
  * ``PUT_ICMP6_FRAG_MTU`` action, should be removed in 26.03.
