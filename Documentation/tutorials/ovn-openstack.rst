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

======================
OVN OpenStack Tutorial
======================

This tutorial demonstrates how OVN works in an OpenStack "DevStack"
environment.  It was originally written and tested with the "master"
branches of DevStack and Open vSwitch near the beginning of Oct 2026.
Anyone using a different version is likely to encounter some
differences.

.. note::

  The logical flow table numbers, stage names, and sample outputs shown
  in this tutorial reflect the OVN version at the time of writing and
  will differ from current OVN.  The concepts and tools demonstrated
  remain valid; follow along with your own output rather than expecting
  an exact match.

The goal of this tutorial is to demonstrate OVN in an end-to-end way,
that is, to show how it works from the cloud management system at the
top (in this case, OpenStack and specifically its Neutron networking
subsystem), through the OVN northbound and southbound databases, to
the bottom at the OVN local controller and Open vSwitch data plane.
We hope that this demonstration makes it easier for users and
potential users to understand how OVN works and how to debug and
troubleshoot it.

In addition to new material, this tutorial incorporates content from
``ovn_devstack.rst`` in OpenStack neutron, by Russell Bryant and
others.  Without that example, this tutorial could not have been
written.

We provide enough details in the tutorial that you should be able to
fully follow along, by creating a DevStack VM and cloning DevStack and
so on.  If you want to do this, start out from `Setting Up DevStack`_
below.

Setting Up DevStack
-------------------

This section explains how to install DevStack, a kind of OpenStack
packaging for developers, in a way that allows you to follow along
with the tutorial in full.

Unless you have a spare computer laying about, it's easiest to install
DevStack in a virtual machine.  This tutorial was built using a VM
implemented by KVM and managed by virt-manager.  I recommend
configuring the VM configured for the x86-64 architecture, 6 GB RAM, 2
VCPUs, and a 20 GB virtual disk.

.. note::
   Since we will be creating VMs inside this VM, it is important to have
   nesting configured properly. See
   https://github.com/openstack/devstack/blob/master/doc/source/guides/devstack-with-nested-kvm.rst
   for details on that.

   Also, if you happen to run your Linux-based host with 32-bit userspace,
   then you will have some special issues, even if you use a 64-bit
   kernel:

   * You may find that you can get 32-bit DevStack VMs to work to some
     extent, but I personally got tired of finding workarounds.  I
     recommend running your VMs in 64-bit mode.  To get this to work,
     I had to go to the CPUs tab for the VM configuration in
     virt-manager and change the CPU model from the one originally
     listed to "Hypervisor Default' (it is curious that this is not
     the default!).

   * On a host with 32-bit userspace, KVM supports VMs with at most
     2047 MB RAM.  This is adequate, barely, to start DevStack, but it
     is not enough to run multiple (nested) VMs.  To prevent
     out-of-memory failures, set up extra swap space in the guest.
     For example, to add 2 GB swap::

       $ sudo dd if=/dev/zero of=/swapfile bs=1M count=2048
       $ sudo mkswap /swapfile
       $ sudo swapon /swapfile

     and then add a line like this to ``/etc/fstab`` to add the new
     swap automatically upon reboot::

       /swapfile swap swap defaults 0 0

Here are step-by-step instructions to get started:

1. Install a VM.

   I tested these instructions with Centos 10.  Download the "Stream
   boot install" ISO and booted it.  The install is straightforward.
   Be sure to enable networking, and set a host name, such as
   "ovn-devstack-1".  Add a regular (non-root) user, and check the box
   "Make this user administrator".  Also, set your time zone.

2. You can SSH into the DevStack VM, instead of running from a
   console.  I recommend it because it's easier to cut and paste
   commands into a terminal than a VM console.  You might also
   consider using a very wide terminal, perhaps 160 columns, to keep
   tables from wrapping.

   To improve convenience further, you can make it easier to log in
   with the following steps, which are optional:

   a. On your host, edit your ``~/.ssh/config``, adding lines like
      the following::

        Host ovn-devstack-1
              Hostname VMIP
              User VMUSER

      where VMIP is the VM's IP address and VMUSER is your username
      inside the VM.  (You can omit the ``User`` line if your
      username is the same in the host and the VM.)  After you do
      this, you can SSH to the VM by name, e.g. ``ssh
      ovn-devstack-1``, and if command-line completion is set up in
      your host shell, you can shorten that to something like ``ssh
      ovn`` followed by hitting the Tab key.

   b. If you have SSH public key authentication set up, with an SSH
      agent, run on your host::

        $ ssh-copy-id ovn-devstack-1

      and type your password once.  Afterward, you can log in without
      typing your password again.

      (If you don't already use SSH public key authentication and an
      agent, consider looking into it--it will save you time in the
      long run.)

   c. Optionally, inside the VM, append the following to your
      ``~/.bash_profile``::

        . $HOME/devstack/openrc admin

      It will save you running it by hand each time you log in.  But
      it also prints garbage to the console, which can screw up
      services like ``ssh-copy-id``, so be careful.

2. Boot into the installed system and log in as the regular user, then
   install Git::

     $ sudo yum install git

   .. note::

      Support for `Centos 7 in Devstack <https://review.opendev.org/#/c/688799/>`_
      is long gone, but the same caveat applies to every later release:
      to make Centos 8, 9 or 10 work with Devstack you will explicitly
      have to install these packages as well::

           $ sudo yum install python3 python3-devel

      If you installed a 32-bit i386 guest (against the advice above),
      install a non-PAE kernel and reboot into it at this point::

           $ sudo yum install kernel-core kernel-devel
           $ sudo reboot

      Be sure to select the non-PAE kernel from the list at boot.
      Without this step, DevStack will fail to install properly later.

3. Get copies of DevStack and Neutron and set them up::

     $ git clone https://opendev.org/openstack/devstack.git
     $ git clone https://opendev.org/openstack/neutron.git
     $ cd devstack
     $ cp ../neutron/devstack/ovn-local.conf.sample local.conf

   .. note::

      Depending on the name of the network device used by the VM, devstack
      may be unable to automatically obtain its IP address. If that happens,
      edit ``local.conf`` and explicitly provide it (X marks the spot)::

        HOST_IP=X

      If you installed a 32-bit i386 guest (against the advice above),
      at this point edit ``local.conf`` to add the following line::

        CIRROS_ARCH=i386

4. Initialize DevStack::

     $ ./stack.sh

   This will spew many screenfuls of text, and the first time you run
   it, it will download lots of software from the Internet.  The
   output should eventually end with something like this::

     This is your host IP address: 172.16.189.6
     This is your host IPv6 address: ::1
     Horizon is now available at http://172.16.189.6/dashboard
     Keystone is serving at http://172.16.189.6/identity/
     The default users are: admin and demo
     The password: password
     2017-03-09 15:10:54.117 | stack.sh completed in 2110 seconds.

   If there's some kind of failure, you can restart by running
   ``./stack.sh`` again.  It won't restart exactly where it left off,
   but steps up to the one where it failed will skip the download
   steps.  (Sometimes blindly restarting after a failure will allow it
   to succeed.)  If you reboot your VM, you need to rerun this
   command.  (If you run into trouble with ``stack.sh`` after
   rebooting your VM, try running ``./unstack.sh``.)

   At this point you can navigate a web browser on your host to the
   Horizon dashboard URL.  Many OpenStack operations can be initiated
   from this UI.  Feel free to explore, but this tutorial focuses on
   the alternative command-line interfaces because they are easier to
   explain and to cut and paste.

5. The firewall in the VM by default allows SSH access but not HTTP.
   You will probably want HTTP access to use the OpenStack web
   interface.  The following command enables that.  (It also enables
   every other kind of network access, so if you're concerned about
   security then you might want to find a more targeted approach.)

   ::

      $ sudo iptables -F

   (You need to re-run this if you reboot the VM.)

6. To use OpenStack command line utilities in the tutorial, run::

     $ . ~/devstack/openrc admin

   This needs to be re-run each time you log in (but see the following
   section).

DevStack preliminaries
----------------------

Before we really jump in, let's set up a couple of things in DevStack.
This is the first real test that DevStack is working, so if you get
errors from any of these commands, it's a sign that ``stack.sh``
didn't finish properly, or perhaps that you didn't run the ``openrc
admin`` command at the end of the previous instructions.

If you stop and restart DevStack via ``unstack.sh`` followed by
``stack.sh``, you have to rerun these steps.

1. For SSH access to the VMs we're going to create, we'll need a SSH
   keypair.  Later on, we'll get OpenStack to install this keypair
   into VMs.  Create one with::

     $ openstack keypair create demo > ~/id_rsa_demo
     $ chmod 600 ~/id_rsa_demo

2. By default, DevStack security groups drop incoming traffic, but to
   test networking in a reasonable way we need to enable it.  You only
   need to actually edit one particular security group, but DevStack
   creates multiple and it's somewhat difficult to figure out which
   one is important because all of them are named "default".  So, the
   following adds rules to allow SSH and ICMP traffic into **every**
   security group::

     $ for group in $(openstack security group list -f value -c ID); do \
     openstack security group rule create --ingress --ethertype IPv4 --dst-port 22 --protocol tcp $group; \
     openstack security group rule create --ingress --ethertype IPv4 --protocol ICMP $group; \
     done

3. Later on, we're going to create some VMs and we'll need an
   operating system image to install.  DevStack comes with a very
   simple image built-in, called "cirros", which works fine.  We need
   to get the UUID for this image.  Our later commands assume shell
   variable ``IMAGE_ID`` holds this UUID.  You can set this by hand,
   e.g.::

     $ openstack image list
     +--------------------------------------+--------------------------+--------+
     | ID                                   | Name                     | Status |
     +--------------------------------------+--------------------------+--------+
     | 77f37d2c-3d6b-4e99-a01b-1fa5d78d1fa1 | cirros-0.3.5-x86_64-disk | active |
     +--------------------------------------+--------------------------+--------+
     $ IMAGE_ID=73ca34f3-63c4-4c10-a62f-4540afc24eaa

   or by parsing CLI output::

     $ IMAGE_ID=$(openstack image list -f value -c ID)

   .. note::

      Your image ID will differ from the one above, as will every UUID
      in this tutorial.  They will also change every time you run
      ``stack.sh``.  The UUIDs are generated randomly.

Shortening UUIDs
----------------

OpenStack, OVN, and Open vSwitch all really like UUIDs.  These are
great for uniqueness, but 36-character strings are terrible for
readability.  Statistically, just the first few characters are enough
for uniqueness in small environments, so let's define a helper to make
things more readable::

  $ abbrev() { a='[0-9a-fA-F]' b=$a$a c=$b$b; sed "s/$b-$c-$c-$c-$c$c$c//g"; }

You can use this as a filter to abbreviate UUIDs.  For example, use it
to abbreviate the above image list::

  $ openstack image list -f yaml | abbrev
  - ID: 77f37d
    Name: cirros-0.3.5-x86_64-disk
    Status: active

The command above also adds ``-f yaml`` to switch to YAML output
format, because abbreviating UUIDs screws up the default table-based
formatting and because YAML output doesn't produce wrap columns across
lines and therefore is easier to cut and paste.

Overview
--------

Now that DevStack is ready, with OVN set up as the networking
back-end, here's an overview of what we're going to do in the
remainder of the demo, all via OpenStack:

1. Switching: Create an OpenStack network ``n1`` and VMs ``a`` and
   ``b`` attached to it.

   An OpenStack network is a virtual switch; it corresponds to an OVN
   logical switch.

2. Routing: Create a second OpenStack network ``n2`` and VM ``c``
   attached to it, then connect it to network ``n1`` by creating an
   OpenStack router and attaching ``n1`` and ``n2`` to it.

3. Gateways: Make VMs ``a`` and ``b`` available via an external network.

4. IPv6: Add IPv6 addresses to our VMs to demonstrate OVN support for
   IPv6 routing.

5. ACLs: Add and modify OpenStack stateless and stateful rules in
   security groups.

6. DHCP: How it works in OVN.

7. Further directions: Adding more compute nodes.

At each step, we will take a look at how the features in question work
from OpenStack's Neutron networking layer at the top to the data plane
layer at the bottom.  From the highest to lowest level, these layers
and the software components that connect them are:

* OpenStack Neutron, which as the top level in the system is the
  authoritative source of the virtual network configuration.

  We will use OpenStack's ``openstack`` utility to observe and modify
  Neutron and other OpenStack configuration.

* The ML2/OVN driver (formerly known as networking-ovn), the Neutron
  mechanism driver that interfaces with OVN and translates the internal
  Neutron representation of the virtual network into OVN's
  representation and pushes that representation down the OVN northbound
  database.

  In this tutorial it's rarely worth distinguishing Neutron from
  ML2/OVN, so we usually don't break out this layer separately.

* The OVN Northbound database, aka NB DB.  This is an instance of
  OVSDB, a simple general-purpose database that is used for multiple
  purposes in Open vSwitch and OVN.  The NB DB's schema is in terms of
  networking concepts such as switches and routers.  The NB DB serves
  the purpose that in other systems might be filled by some kind of
  API; for example, in place of calling an API to create or delete a
  logical switch, ML2/OVN performs these operations by
  inserting or deleting a row in the NB DB's Logical_Switch table.

  We will use OVN's ``ovn-nbctl`` utility to observe the NB DB.  (We
  won't directly modify data at this layer or below.  Because
  configuration trickles down from Neutron through the stack, the
  right way to make changes is to use the ``openstack`` utility or
  another OpenStack interface and then wait for them to percolate
  through to lower layers.)

* The ovn-northd daemon, a program that runs centrally and translates
  the NB DB's network representation into the lower-level
  representation used by the OVN Southbound database in the next
  layer.  The details of this daemon are usually not of interest,
  although without it OVN will not work, so this tutorial does not
  often mention it.

* The OVN Southbound database, aka SB DB, which is also an OVSDB
  database.  Its schema is very different from the NB DB.  Instead of
  familiar networking concepts, the SB DB defines the network in terms
  of collections of match-action rules called "logical flows", which
  while similar in concept to OpenFlow flows use logical concepts, such
  as virtual machine instances, in place of physical concepts like
  physical Ethernet ports.

  We will use OVN's ``ovn-sbctl`` utility to observe the SB DB.

* The ovn-controller daemon.  A copy of ovn-controller runs on each
  hypervisor.  It reads logical flows from the SB DB, translates them
  into OpenFlow flows, and sends them to Open vSwitch's ovs-vswitchd
  daemon.  Like ovn-northd, usually the details of what this daemon
  are not of interest, even though it's important to the operation of
  the system.

* ovs-vswitchd.  This program runs on each hypervisor.  It is the core
  of Open vSwitch, which processes packets according to the OpenFlow
  flows set up by ovn-controller.

* Open vSwitch datapath.  This is essentially a cache designed to
  accelerate packet processing.  Open vSwitch includes a few different
  datapaths but OVN installations typically use one based on the Open
  vSwitch Linux kernel module.

Switching
---------

Switching is the basis of networking in the real world and in virtual
networking as well.  OpenStack calls its concept of a virtual switch a
"network", and OVN calls its corresponding concept a "logical switch".

In this step, we'll create an OpenStack network ``n1``, then create
VMs ``a`` and ``b`` and attach them to ``n1``.

Creating network ``n1``
~~~~~~~~~~~~~~~~~~~~~~~

Let's start by creating the network::

  $ openstack network create --provider-network-type geneve n1

OpenStack needs to know the subnets that a network serves.  We inform
it by creating subnet objects.  To keep it simple, let's give our
network a single subnet for the 10.1.1.0/24 network.  We have to give
it a name, in this case ``n1subnet``::

  $ openstack subnet create --subnet-range 10.1.1.0/24 --network n1 n1subnet

If you ask Neutron to show us the available networks, we see ``n1`` as
well as the two networks that DevStack creates by default::

  $ openstack network list -f yaml | abbrev
  - ID: 68cb3a
    Name: n1
    Subnets:
    - a375e9
  - ID: 6cad57
    Name: public
    Subnets:
    - 1bcea0
    - 405845
  - ID: 71160a
    Name: shared
    Subnets:
    - 39e0b5
  - ID: 935ec0
    Name: private
    Subnets:
    - 88706f
    - 9d19ae

Neutron pushes this network setup down to the OVN northbound
database.  We can use ``ovn-nbctl show`` to see an overview of what's
in the NB DB::

  $ sudo ovn-nbctl show | abbrev
  switch 6cad57 (neutron-6cad57) (aka public)
      port 2d86c4
          type: localport
          addresses: ["fa:16:3e:a9:47:00"]
      port 09c087
          type: router
          router-port: lrp-09c087
      port provnet-2deb4b
          type: localnet
          addresses: ["unknown"]
  switch 71160a (neutron-71160a) (aka shared)
      port 882366
          type: localport
          addresses: ["fa:16:3e:94:e7:c6 192.168.233.2"]
  switch 68cb3a (neutron-68cb3a) (aka n1)
      port 465a58
          type: localport
          addresses: ["fa:16:3e:cb:26:d5 10.1.1.2"]
  switch 935ec0 (neutron-935ec0) (aka private)
      port 4bcc8f
          type: router
          router-port: lrp-4bcc8f
      port f87782
          type: router
          router-port: lrp-f87782
      port 6344ee
          type: localport
          addresses: ["fa:16:3e:da:bb:9e 10.0.0.2 fd8a:9a83:ed81:0:f816:3eff:feda:bb9e"]
  router 95152d (neutron-d99ace) (aka router1)
      port lrp-f87782
          mac: "fa:16:3e:93:8f:4d"
          ipv6-lla: "fe80::f816:3eff:fe93:8f4d"
          networks: ["10.0.0.1/26"]
      port lrp-4bcc8f
          mac: "fa:16:3e:8c:31:06"
          ipv6-lla: "fe80::f816:3eff:fe8c:3106"
          networks: ["fd8a:9a83:ed81::1/64"]
      port lrp-09c087
          mac: "fa:16:3e:48:c3:6b"
          ipv6-lla: "fe80::f816:3eff:fe48:c36b"
          networks: ["172.24.4.37/24", "2001:db8::287/64"]
      nat 930592
          external ip: "172.24.4.37"
          logical ip: "0.0.0.0/0"
          type: "snat"

This output shows that OVN has four logical switches, each of which
corresponds to a Neutron network, and a logical router that
corresponds to the Neutron router that DevStack creates by default.
The logical switch that corresponds to our new network ``n1`` has no
ports yet, because we haven't added any.  The ``public`` and
``private`` networks that DevStack creates by default have router
ports that connect to the logical router.

Using ovn-northd, OVN translates the NB DB's high-level switch and
router concepts into lower-level concepts of "logical datapaths" and
logical flows.  There's one logical datapath for each logical switch
or router::

  $ sudo ovn-sbctl list datapath_binding | abbrev
  ...
  _uuid               : d802e0
  external_ids        : {always_learn_from_arp_request="false", disable_garp_rarp="false", logical-router="95152d", mac_binding_age_threshold="300", name=neutron-d99ace, name2=router1}
  load_balancers      : []
  nb_uuid             : 95152d
  tunnel_key          : 2
  type                : logical-router

  _uuid               : 8ade2d
  external_ids        : {fdb_age_threshold="300", logical-switch="6cad57", name=neutron-6cad57, name2=public}
  load_balancers      : []
  nb_uuid             : 6cad57
  tunnel_key          : 3
  type                : logical-switch

  _uuid               : 8b6e64
  external_ids        : {logical-switch="68cb3a", name=neutron-68cb3a, name2=n1}
  load_balancers      : []
  nb_uuid             : 68cb3a
  tunnel_key          : 5
  type                : logical-switch

  _uuid               : 77472e
  external_ids        : {logical-switch="935ec0", name=neutron-935ec0, name2=private}
  load_balancers      : []
  nb_uuid             : 935ec0
  tunnel_key          : 1
  type                : logical-switch

This output lists the NB DB UUIDs in external_ids:logical-switch and
Neutron UUIDs in external_ids:name.  We can dive in deeper by viewing
the OVN logical flows that implement a logical switch.  Our new
logical switch is a simple and almost pathological example given that
it doesn't yet have any ports attached to it.  We'll look at the
details a bit later::

  $ sudo ovn-sbctl lflow-list n1 | abbrev
  Datapath: "neutron-68cb3a" aka "n1" (8b6e64)  Pipeline: ingress
    table=0 (ls_in_check_port_sec), priority=110  , match=(((ip4 && icmp4.type == 3 && icmp4.code == 4) || (ip6 && icmp6.type == 2 && icmp6.code == 0)) && eth.src == fa:16:3e:cb:26:d5 && outport == "465a58" && !is_chassis_resident("465a58") && flags.tunnel_rx == 1), action=(outport <-> inport; next;)
    table=0 (ls_in_check_port_sec), priority=105  , match=(((ip4 && icmp4.type == 3 && icmp4.code == 4) || (ip6 && icmp6.type == 2 && icmp6.code == 0)) && flags.tunnel_rx == 1), action=(drop;)
    table=0 (ls_in_check_port_sec), priority=100  , match=(eth.src[40]), action=(drop;)
    table=0 (ls_in_check_port_sec), priority=100  , match=(vlan.present), action=(drop;)
    table=0 (ls_in_check_port_sec), priority=50   , match=(1), action=(reg0[15] = check_in_port_sec(); next;)

  ...
  Datapath: "neutron-68cb3a" aka "n1" (8b6e64)  Pipeline: egress
    table=0 (ls_out_lookup_fdb  ), priority=0    , match=(1), action=(next;)
    table=1 (ls_out_put_fdb     ), priority=0    , match=(1), action=(next;)

  ...

We have one hypervisor (aka "compute node", in OpenStack parlance),
which is the one where we're running all these commands.  On this
hypervisor, ovn-controller is translating OVN logical flows into
OpenFlow flows ("physical flows").  It makes sense to go deeper, to
see the OpenFlow flows that get generated from this datapath.  By
adding ``--ovs`` to the ``ovn-sbctl`` command, we can see OpenFlow
flows listed just below their logical flows.  We also need to use
``sudo`` because connecting to Open vSwitch is privileged.  Go ahead
and try it::

  $ sudo ovn-sbctl --ovs lflow-list n1 | abbrev
  Datapath: "neutron-68cb3a23-dcea-4153-850d-cd6177ab7aa0" aka "n1" (8b6e6412-06af-4860-b929-3a90c85171c4)  Pipeline: ingress
    table=0 (ls_in_check_port_sec), priority=110  , match=(((ip4 && icmp4.type == 3 && icmp4.code == 4) || (ip6 && icmp6.type == 2 && icmp6.code == 0)) && eth.src == fa:16:3e:cb:26:d5 && outport == "465a58ea-6638-4d33-a213-fb4c080ddec6" && !is_chassis_resident("465a58ea-6638-4d33-a213-fb4c080ddec6") && flags.tunnel_rx == 1), action=(outport <-> inport; next;)
    table=0 (ls_in_check_port_sec), priority=105  , match=(((ip4 && icmp4.type == 3 && icmp4.code == 4) || (ip6 && icmp6.type == 2 && icmp6.code == 0)) && flags.tunnel_rx == 1), action=(drop;)
      table=8 icmp,reg10=0x10000/0x10000,metadata=0x1,icmp_type=3,icmp_code=4 actions=drop
      table=8 icmp6,reg10=0x10000/0x10000,metadata=0x3,icmp_type=2,icmp_code=0 actions=drop
      table=8 icmp,reg10=0x10000/0x10000,metadata=0x3,icmp_type=3,icmp_code=4 actions=drop
      table=8 icmp6,reg10=0x10000/0x10000,metadata=0x1,icmp_type=2,icmp_code=0 actions=drop
    table=0 (ls_in_check_port_sec), priority=100  , match=(eth.src[40]), action=(drop;)
      table=8 metadata=0x1,dl_src=01:00:00:00:00:00/01:00:00:00:00:00 actions=drop
      table=8 metadata=0x3,dl_src=01:00:00:00:00:00/01:00:00:00:00:00 actions=drop
    table=0 (ls_in_check_port_sec), priority=100  , match=(vlan.present), action=(drop;)
      table=8 metadata=0x1,vlan_tci=0x1000/0x1000 actions=drop
      table=8 metadata=0x3,vlan_tci=0x1000/0x1000 actions=drop
    table=0 (ls_in_check_port_sec), priority=50   , match=(1), action=(reg0[15] = check_in_port_sec(); next;)
      table=8 metadata=0x1 actions=set_field:0/0x1000->reg10,resubmit(,73),move:NXM_NX_REG10[12]->NXM_NX_XXREG0[111],resubmit(,9)
      table=8 metadata=0x3 actions=set_field:0/0x1000->reg10,resubmit(,73),move:NXM_NX_REG10[12]->NXM_NX_XXREG0[111],resubmit(,9)

  ...
  Datapath: "neutron-68cb3a23-dcea-4153-850d-cd6177ab7aa0" aka "n1" (8b6e6412-06af-4860-b929-3a90c85171c4)  Pipeline: egress
    table=0 (ls_out_lookup_fdb  ), priority=0    , match=(1), action=(next;)
      table=48 metadata=0x1 actions=resubmit(,49)
      table=48 metadata=0x3 actions=resubmit(,49)
    table=1 (ls_out_put_fdb     ), priority=0    , match=(1), action=(next;)
      table=49 metadata=0x1 actions=resubmit(,50)
      table=49 metadata=0x3 actions=resubmit(,50)
  ...

You can see that some logical flows now have OpenFlow flows
(indented below them).  These are global rules that OVN installs
for every logical datapath: port security checks that drop invalid
packets (multicast source MACs, VLAN-tagged frames, untrusted
ICMP errors) and forwarding database operations.  For a richer
example with per-port flows, you can try ``ovn-sbctl --ovs`` on
one of the other logical datapaths that already have ports, such
as ``private``.

Attaching VMs
~~~~~~~~~~~~~

A switch without any ports is not very interesting.  Let's create a
couple of VMs and attach them to the switch.  Run the following
commands, which create VMs named ``a`` and ``b`` and attaches them to
our network ``n1`` with IP addresses 10.1.1.5 and 10.1.1.6,
respectively.  It is not actually necessary to manually assign IP
address assignments, since OpenStack is perfectly happy to assign them
itself from the subnet's IP address range, but predictable addresses
are useful for our discussion::

  $ openstack server create --nic net-id=n1,v4-fixed-ip=10.1.1.5 --flavor m1.nano --image $IMAGE_ID --key-name demo a
  $ openstack server create --nic net-id=n1,v4-fixed-ip=10.1.1.6 --flavor m1.nano --image $IMAGE_ID --key-name demo b

These commands return before the VMs are really finished being built.
You can run ``openstack server list`` a few times until each of them
is shown in the state ACTIVE, which means that they're not just built
but already running on the local hypervisor.

These operations had the side effect of creating separate "port"
objects, but without giving those ports any easy-to-read names.  It'll
be easier to deal with them later if we can refer to them by name, so
let's name ``a``'s port ``ap`` and ``b``'s port ``bp``::

  $ openstack port set --name ap $(openstack port list --server a -f value -c ID)
  $ openstack port set --name bp $(openstack port list --server b -f value -c ID)

We'll need to refer to these ports' MAC addresses a few times, so
let's put them in variables::

  $ AP_MAC=$(openstack port show -f value -c mac_address ap)
  $ BP_MAC=$(openstack port show -f value -c mac_address bp)

At this point you can log into the consoles of the VMs if you like.
You can do that from the OpenStack web interface or get a direct URL
to paste into a web browser using a command like::

  $ openstack console url show -f yaml a

(The option ``-f yaml`` keeps the URL in the output from being broken
into noncontiguous pieces on a 80-column console.)

The VMs don't have many tools in them but ``ping`` and ``ssh`` from
one to the other should work fine.  The VMs do not have any external
network access or DNS configuration.

Let's chase down what's changed in OVN.  Start with the NB DB at the
top of the system.  It's clear that our logical switch now has the two
logical ports attached to it::

  $ sudo ovn-nbctl show | abbrev
  ...
  switch 68cb3a (neutron-68cb3a) (aka n1)
      port f93fab (aka bp)
          addresses: ["fa:16:3e:3c:e2:c6 10.1.1.6"]
      port 2ecc01 (aka ap)
          addresses: ["fa:16:3e:ef:64:b6 10.1.1.5"]
  ...

We can get some more details on each of these by looking at their NB
DB records in the Logical_Switch_Port table.  Each port has addressing
information, port security enabled, and a pointer to DHCP
configuration (which we'll look at much later in `DHCP`_)::

  $ sudo ovn-nbctl list logical_switch_port ap bp | abbrev
  _uuid               : f013b5
  addresses           : ["fa:16:3e:ef:64:b6 10.1.1.5"]
  dhcpv4_options      : a7de4a
  dhcpv6_options      : []
  dynamic_addresses   : []
  enabled             : true
  external_ids        : {"neutron:cidrs"="10.1.1.5/24", "neutron:device_id"="91df4e", "neutron:device_owner"="compute:nova", "neutron:host_id"=localhost.localdomain, "neutron:mtu"="", "neutron:network_name"=neutron-68cb3a, "neutron:port_capabilities"="", "neutron:port_name"=ap, "neutron:project_id"="584a7ea8c2fd4b9582945443de262f65", "neutron:revision_number"="6", "neutron:security_group_ids"="a9fa0a", "neutron:subnet_pool_addr_scope4"="", "neutron:subnet_pool_addr_scope6"="", "neutron:vnic_type"=normal}
  ha_chassis_group    : []
  health_checks       : []
  mirror_rules        : []
  name                : "2ecc01"
  options             : {requested-chassis=localhost.localdomain}
  parent_name         : []
  peer                : []
  port_security       : ["fa:16:3e:ef:64:b6 10.1.1.5"]
  tag                 : []
  tag_request         : []
  type                : ""
  up                  : true

  _uuid               : 9b6b71
  addresses           : ["fa:16:3e:3c:e2:c6 10.1.1.6"]
  dhcpv4_options      : a7de4a
  dhcpv6_options      : []
  dynamic_addresses   : []
  enabled             : true
  external_ids        : {"neutron:cidrs"="10.1.1.6/24", "neutron:device_id"="5c060f", "neutron:device_owner"="compute:nova", "neutron:host_id"=localhost.localdomain, "neutron:mtu"="", "neutron:network_name"=neutron-68cb3a, "neutron:port_capabilities"="", "neutron:port_name"=bp, "neutron:project_id"="584a7ea8c2fd4b9582945443de262f65", "neutron:revision_number"="6", "neutron:security_group_ids"="a9fa0a", "neutron:subnet_pool_addr_scope4"="", "neutron:subnet_pool_addr_scope6"="", "neutron:vnic_type"=normal}
  ha_chassis_group    : []
  health_checks       : []
  mirror_rules        : []
  name                : "f93fab"
  options             : {requested-chassis=localhost.localdomain}
  parent_name         : []
  peer                : []
  port_security       : ["fa:16:3e:3c:e2:c6 10.1.1.6"]
  tag                 : []
  tag_request         : []
  type                : ""
  up                  : true

Now that the logical switch is less pathological, it's worth taking
another look at the SB DB logical flow table.  Try a command like
this::

  $ sudo ovn-sbctl lflow-list n1 | abbrev | less -S

and then glance through the flows.  Packets that egress a VM into the
logical switch travel through the flow table's ingress pipeline
starting from table 0.  At each table, the switch finds the
highest-priority logical flow that matches and executes its actions,
or if there's no matching flow then the packet is dropped.  The
``ovn-sb``\(5) manpage gives all the details, but with a little
thought it's possible to guess a lot without reading the manpage.  For
example, consider the flows in ingress pipeline table 0, which are the
first flows encountered by a packet traversing the switch::

  table=0 (ls_in_check_port_sec), priority=110  , match=(((ip4 && icmp4.type == 3 && icmp4.code == 4) || (ip6 && icmp6.type == 2 && icmp6.code == 0)) && eth.src == fa:16:3e:3c:e2:c6 && outport == "f93fab" && !is_chassis_resident("f93fab") && flags.tunnel_rx == 1), action=(outport <-> inport; next;)
  table=0 (ls_in_check_port_sec), priority=110  , match=(((ip4 && icmp4.type == 3 && icmp4.code == 4) || (ip6 && icmp6.type == 2 && icmp6.code == 0)) && eth.src == fa:16:3e:cb:26:d5 && outport == "465a58" && !is_chassis_resident("465a58") && flags.tunnel_rx == 1), action=(outport <-> inport; next;)
  table=0 (ls_in_check_port_sec), priority=110  , match=(((ip4 && icmp4.type == 3 && icmp4.code == 4) || (ip6 && icmp6.type == 2 && icmp6.code == 0)) && eth.src == fa:16:3e:ef:64:b6 && outport == "2ecc01" && !is_chassis_resident("2ecc01") && flags.tunnel_rx == 1), action=(outport <-> inport; next;)
  table=0 (ls_in_check_port_sec), priority=105  , match=(((ip4 && icmp4.type == 3 && icmp4.code == 4) || (ip6 && icmp6.type == 2 && icmp6.code == 0)) && flags.tunnel_rx == 1), action=(drop;)
  table=0 (ls_in_check_port_sec), priority=100  , match=(eth.src[40]), action=(drop;)
  table=0 (ls_in_check_port_sec), priority=100  , match=(vlan.present), action=(drop;)
  table=0 (ls_in_check_port_sec), priority=50   , match=(1), action=(reg0[15] = check_in_port_sec(); next;)

The three priority-110 flows handle ICMP "packet too big" (PMTUD)
messages that arrive over an overlay tunnel on behalf of a port that
is not resident on this chassis: each one swaps ``inport`` and
``outport`` so that the error is processed in the direction the
original packet was travelling.  The priority-105 flow drops any
other tunnelled PMTUD message.  The next two flows, with priority
100, immediately drop two kinds of invalid packets: those with a
multicast or broadcast Ethernet source address (since multicast is
only for packet destinations) and those with a VLAN tag (because OVN
doesn't yet support VLAN tags inside logical networks).  The final
priority-50 flow runs the per-port L2 and L3 port security checks
with the ``check_in_port_sec()`` action, storing the result in
``reg0[15]``; the next table, ``ls_in_apply_port_sec``, drops the
packet if that bit is set.

The logical flow table includes many other flows, some of which we
will look at later.  For now, it's most worth looking at ingress table
32, the L2 lookup stage::

  table=32(ls_in_l2_lkup      ), priority=110  , match=(eth.dst == $svc_monitor_mac && (tcp || icmp || icmp6)), action=(handle_svc_check(inport);)
  table=32(ls_in_l2_lkup      ), priority=100  , match=(reg8[23] == 1), action=(output;)
  table=32(ls_in_l2_lkup      ), priority=72   , match=(eth.mcast && (nd_na || nd_rs || nd_ra)), action=(outport = "_MC_flood"; output;)
  table=32(ls_in_l2_lkup      ), priority=71   , match=(eth.mcast && arp), action=(outport = "_MC_flood"; output;)
  table=32(ls_in_l2_lkup      ), priority=71   , match=(eth.mcast && ip), action=(outport = "_MC_flood_l2"; output;)
  table=32(ls_in_l2_lkup      ), priority=70   , match=(eth.mcast), action=(outport = "_MC_flood_l2"; output;)
  table=32(ls_in_l2_lkup      ), priority=50   , match=(eth.dst == fa:16:3e:3c:e2:c6), action=(outport = "f93fab"; output;)
  table=32(ls_in_l2_lkup      ), priority=50   , match=(eth.dst == fa:16:3e:cb:26:d5), action=(outport = "465a58"; output;)
  table=32(ls_in_l2_lkup      ), priority=50   , match=(eth.dst == fa:16:3e:ef:64:b6), action=(outport = "2ecc01"; output;)
  table=32(ls_in_l2_lkup      ), priority=0    , match=(1), action=(outport = get_fdb(eth.dst); next;)

The first few flows handle multicast and broadcast traffic by
outputting to special flood ports.  The priority-50 flows perform
unicast L2 lookup: each matches a known destination MAC address and
outputs to the corresponding logical port.  The priority-0 fallback
uses ``get_fdb`` to look up dynamically learned MAC addresses.

(It's common for an OVN logical switch to know all the MAC addresses
supported by its logical ports, like this one.  That's why there's no
logic here for MAC learning or flooding packets to unknown MAC
addresses.  OVN does support unknown MAC handling but that's not in
play in our example.)

.. note::

  If you're interested in the details for the multicast group, you can
  run a command like the following and then look at the row for the
  correct datapath::

    $ sudo ovn-sbctl find multicast_group name=_MC_flood | abbrev

Now if you want to look at the OpenFlow flows, you can actually see
them.  For example, here's the beginning of the output that lists the
first four logical flows, which we already looked at above, and their
corresponding OpenFlow flows.  If you want to know more about the
syntax, the ``ovs-fields``\(7) manpage explains OpenFlow matches and
``ovs-ofctl``\(8) explains OpenFlow actions::

  $ sudo ovn-sbctl --ovs lflow-list n1 | abbrev
  Datapath: "neutron-68cb3a" aka "n1" (8b6e64)  Pipeline: ingress
    table=0 (ls_in_check_port_sec), priority=110  , match=(((ip4 && icmp4.type == 3 && icmp4.code == 4) || (ip6 && icmp6.type == 2 && icmp6.code == 0)) && eth.src == fa:16:3e:3c:e2:c6 && outport == "f93fab" && !is_chassis_resident("f93fab") && flags.tunnel_rx == 1), action=(outport <-> inport; next;)
    table=0 (ls_in_check_port_sec), priority=110  , match=(((ip4 && icmp4.type == 3 && icmp4.code == 4) || (ip6 && icmp6.type == 2 && icmp6.code == 0)) && eth.src == fa:16:3e:cb:26:d5 && outport == "465a58" && !is_chassis_resident("465a58") && flags.tunnel_rx == 1), action=(outport <-> inport; next;)
      table=8 icmp,reg10=0x10000/0x10000,reg15=0x1,metadata=0x5,dl_src=fa:16:3e:cb:26:d5,icmp_type=3,icmp_code=4 actions=push:NXM_NX_REG14[],push:NXM_NX_REG15[],pop:NXM_NX_REG14[],pop:NXM_NX_REG15[],resubmit(,9)
      table=8 icmp6,reg10=0x10000/0x10000,reg15=0x1,metadata=0x5,dl_src=fa:16:3e:cb:26:d5,icmp_type=2,icmp_code=0 actions=push:NXM_NX_REG14[],push:NXM_NX_REG15[],pop:NXM_NX_REG14[],pop:NXM_NX_REG15[],resubmit(,9)
    table=0 (ls_in_check_port_sec), priority=110  , match=(((ip4 && icmp4.type == 3 && icmp4.code == 4) || (ip6 && icmp6.type == 2 && icmp6.code == 0)) && eth.src == fa:16:3e:ef:64:b6 && outport == "2ecc01" && !is_chassis_resident("2ecc01") && flags.tunnel_rx == 1), action=(outport <-> inport; next;)
    table=0 (ls_in_check_port_sec), priority=105  , match=(((ip4 && icmp4.type == 3 && icmp4.code == 4) || (ip6 && icmp6.type == 2 && icmp6.code == 0)) && flags.tunnel_rx == 1), action=(drop;)
      table=8 icmp,reg10=0x10000/0x10000,metadata=0x1,icmp_type=3,icmp_code=4 actions=drop
      table=8 icmp6,reg10=0x10000/0x10000,metadata=0x5,icmp_type=2,icmp_code=0 actions=drop
      table=8 icmp,reg10=0x10000/0x10000,metadata=0x5,icmp_type=3,icmp_code=4 actions=drop
      table=8 icmp6,reg10=0x10000/0x10000,metadata=0x3,icmp_type=2,icmp_code=0 actions=drop
      table=8 icmp,reg10=0x10000/0x10000,metadata=0x3,icmp_type=3,icmp_code=4 actions=drop
      table=8 icmp6,reg10=0x10000/0x10000,metadata=0x1,icmp_type=2,icmp_code=0 actions=drop

  ...

Logical Tracing
+++++++++++++++

Let's go a level deeper.  So far, everything we've done has been
fairly general.  We can also look at something more specific: the path
that a particular packet would take through OVN, logically, and Open
vSwitch, physically.

Let's use OVN's ovn-trace utility to see what happens to packets from
a logical point of view.  The ``ovn-trace``\(8) manpage has a lot of
detail on how to do that, but let's just start by building up from a
simple example.  You can start with a command that just specifies the
logical datapath, an input port, and nothing else; unspecified fields
default to all-zeros.  This doesn't do much::

  $ sudo ovn-trace n1 'inport == "ap"'
  ...

  ingress(dp="n1", inport="ap")
  -----------------------------
   0. ls_in_check_port_sec (northd.c:10254): 1, priority 50, uuid 9f12c419
      reg0[15] = check_in_port_sec();
      next;
   1. ls_in_apply_port_sec (northd.c:10258): reg0[15] == 1, priority 50, uuid 94843ccc
      drop;

We see that the packet was dropped in logical table 1,
"ls_in_apply_port_sec", the L2 port security stage (as we discussed
earlier).  That's because we didn't use the right Ethernet source
address for ``a``.  Let's see what happens if we do::

  $ sudo ovn-trace n1 'inport == "ap" && eth.src == '$AP_MAC
  ingress(dp="n1", inport="ap")
  -----------------------------
   0. ls_in_check_port_sec (northd.c:10254): 1, priority 50, uuid 9f12c419
      reg0[15] = check_in_port_sec();
      next;
  ...
  32. ls_in_l2_lkup (northd.c:6251): 1, priority 0, uuid 17a9905e
      outport = get_fdb(eth.dst);
      next;
  33. ls_in_l2_unknown (northd.c:10196): outport == "none", priority 50, uuid 86bde6cc
      drop;

Now the packet passes through L2 port security and skips through
several other tables until it gets dropped in the L2 lookup stage
(because the destination is unknown).  Let's add the Ethernet
destination for ``b``::

  $ sudo ovn-trace n1 'inport == "ap" && eth.src == '$AP_MAC' && eth.dst == '$BP_MAC
  ingress(dp="n1", inport="ap")
  -----------------------------
   0. ls_in_check_port_sec (northd.c:10254): 1, priority 50, uuid 9f12c419
      reg0[15] = check_in_port_sec();
      next;
  ...
  32. ls_in_l2_lkup (northd.c:11291): eth.dst == fa:16:3e:3c:e2:c6, priority 50, uuid d10bc6f5
      outport = "bp";
      output;

  egress(dp="n1", inport="ap", outport="bp")
  ------------------------------------------
   5. ls_out_acl_hint (northd.c:6843): !ct.trk, priority 5, uuid 8b134147
      reg0[8] = 1;
      reg0[9] = 1;
      next;
   8. ls_out_acl_action (northd.c:7804): 1, priority 0, uuid 615c6e6d
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  14. ls_out_check_port_sec (northd.c:6272): 1, priority 0, uuid f60d0449
      reg0[15] = check_out_port_sec();
      next;
  15. ls_out_apply_port_sec (northd.c:6279): 1, priority 0, uuid 7644229a
      output;

You can see that in this case the packet gets properly switched from
``a`` to ``b``.

Physical Tracing for Hypothetical Packets
+++++++++++++++++++++++++++++++++++++++++

ovn-trace showed us how a hypothetical packet would travel through the
system in a logical fashion, that is, without regard to how VMs are
distributed across the physical network.  This is a convenient
representation for understanding how OVN is **supposed** to work
abstractly, but sometimes we might want to know more about how it
actually works in the real systems where it is running.  For this, we
can use the tracing tool that Open vSwitch provides, which traces
a hypothetical packet through the OpenFlow tables.

We can actually get two levels of detail.  Let's start with the
version that's easier to interpret, by physically tracing a packet
that looks like the one we logically traced before.  One obstacle is
that we need to know the OpenFlow port number of the input port.  One
way to do that is to look for a port whose "attached-mac" is the one
we expect and print its ofport number::

  $ AP_PORT=$(sudo ovs-vsctl --bare --columns=ofport find  interface external-ids:attached-mac=\"$AP_MAC\")
  $ echo $AP_PORT
  3

(You could also just do a plain ``ovs-vsctl list interface`` and then
look through for the right row and pick its ``ofport`` value.)

Now we can feed this input port number into ``ovs-appctl
ofproto/trace`` along with the correct Ethernet source and
destination addresses and get a physical trace::

  $ sudo ovs-appctl ofproto/trace br-int in_port=$AP_PORT,dl_src=$AP_MAC,dl_dst=$BP_MAC,dl_type=0x0800,nw_src=10.1.1.5,nw_dst=10.1.1.6

This prints a lot of output, which you can read through if you like,
but the important part is the last few lines::

  65. reg15=0x3,metadata=0x5, priority 100, cookie 0xebf36591
      output:4

which means that the packet is ultimately being output to OpenFlow
port 4.  That's port ``b``, which you can confirm with::

  $ sudo ovs-vsctl find interface ofport=4
  _uuid               : 840a5aca-ea8d-4c16-a11b-a94e0f408091
  admin_state         : up
  bfd                 : {}
  bfd_status          : {}
  cfm_fault           : []
  cfm_fault_status    : []
  cfm_flap_count      : []
  cfm_health          : []
  cfm_mpid            : []
  cfm_remote_mpids    : []
  cfm_remote_opstate  : []
  duplex              : full
  error               : []
  external_ids        : {attached-mac="fa:16:3e:99:7a:17", iface-id="c29d4120-20a4-4c44-bd83-8d91f5f447fd", iface-status=active, vm-id="2db969ca-ca2a-4d9a-b49e-f287d39c5645"}
  ifindex             : 9
  ingress_policing_burst: 0
  ingress_policing_rate: 0
  lacp_current        : []
  link_resets         : 1
  link_speed          : 10000000
  link_state          : up
  lldp                : {}
  mac                 : []
  mac_in_use          : "fe:16:3e:99:7a:17"
  mtu                 : 1500
  mtu_request         : []
  name                : "tapc29d4120-20"
  ofport              : 4
  ofport_request      : []
  options             : {}
  other_config        : {}
  statistics          : {collisions=0, rx_bytes=4254, rx_crc_err=0, rx_dropped=0, rx_errors=0, rx_frame_err=0, rx_over_err=0, rx_packets=39, tx_bytes=4188, tx_dropped=0, tx_errors=0, tx_packets=39}
  status              : {driver_name=tun, driver_version="1.6", firmware_version=""}
  type                : ""

or::

  $ BP_PORT=$(ovs-vsctl --bare --columns=ofport find  interface external-ids:attached-mac=\"$BP_MAC\")
  $ echo $BP_PORT
  4

Physical Tracing for Real Packets
+++++++++++++++++++++++++++++++++

In the previous sections we traced a hypothetical L2 packet, one
that's honestly not very realistic.  We could refine our packet so that it becomes a more
realistic TCP or UDP or ICMP, etc. packet, but let's try a different
approach: working from a real packet.

Pull up a console for VM ``a`` and start ``ping 10.1.1.6``, then leave
it running for the rest of our experiment.

Now go back to your DevStack session and run::

  $ sudo watch ovs-dpctl dump-flows

We're working with a new program.  ovs-dpctl is an interface to Open
vSwitch datapaths, in this case to the Linux kernel datapath.  Its
``dump-flows`` command displays the contents of the in-kernel flow
cache, and by running it under the ``watch`` program we see a new
snapshot of the flow table every 2 seconds.

Look through the output for a flow that begins with ``recirc_id(0)``
and matches the Ethernet source address for ``a``.  There is one flow
per line, but the lines are very long, so it's easier to read if you
make the window very wide.  This flow's packet counter should be
increasing at a rate of 1 packet per second.  It looks something like
this::

  recirc_id(0),in_port(3),eth(src=fa:16:3e:ef:64:b6,dst=fa:16:3e:3c:e2:c6),eth_type(0x0800),ipv4(src=10.1.1.5,proto=1,frag=no), packets:5, bytes:490, used:0.679s, actions:ct(zone=10),recirc(0x21)

.. note::

  Flows in the datapath can expire quickly and the ``watch`` command
  mentioned above may be too slow to catch it. If that is your
  case, stop the ``ping 10.1.1.6`` session and re-start it a few
  seconds after this command::

    $ sudo conntrack -F ; rm -f /tmp/flows.txt ; \
         for _ in $(seq 100) ; do \
         sudo ovs-dpctl dump-flows >> /tmp/flows.txt ; \
         sleep 0.1 ; done

  Then, look for ``recirc_id(0)`` in flows.txt after ping command was issued::

    $ sort --uniq /tmp/flows.txt | grep zone

Now we can feed the header fields from that real kernel flow into
``ofproto/trace``.  We need to specify the bridge name, the input
port, and enough header fields for port security to pass: the same
Ethernet and IP addresses and the same protocol that the kernel flow
matched on.  Be sure to include ``nw_dst`` as well, so that egress
port security accepts the packet::

  $ sudo ovs-appctl ofproto/trace br-int "in_port=$AP_PORT,dl_src=$AP_MAC,dl_dst=$BP_MAC,dl_type=0x0800,nw_proto=1,nw_src=10.1.1.5,nw_dst=10.1.1.6"

The output is long because ``ofproto/trace`` automatically follows
every recirculation.  Here is an abbreviated walkthrough of the three
phases.

The first phase is the initial ingress into the switch.  Table 0
sets up the logical datapath metadata, table 8 runs port security,
and table 15 sends the packet to the kernel connection tracker for
``a``'s outgoing firewall::

  Flow: icmp,in_port=2,...,dl_src=fa:16:3e:ef:64:b6,dl_dst=fa:16:3e:3c:e2:c6,nw_src=10.1.1.5,nw_dst=10.1.1.6,...

  bridge("br-int")
  ----------------
   0. in_port=2, priority 100, cookie 0x2f4619d3
      set_field:0x5->metadata
      set_field:0x2->reg14
      ...
      resubmit(,8)
   8. metadata=0x5, priority 50, cookie 0x9f12c419
      ...
  15. ip,reg0=0x1/0x1,metadata=0x5, priority 100, cookie 0x15e4fe9
      ct(table=16,zone=NXM_NX_REG13[0..15])
  ...
  Datapath actions: ct(zone=10),recirc(0xaf)

The ``ct`` action sends the packet through connection tracking and
``recirc`` brings it back for a second pass.  The second phase
resumes at table 16 where ACL evaluation allows the packet through
``a``'s outgoing firewall (table 17), commits the connection to
conntrack (table 32), performs L2 lookup (table 40) which selects
port ``b`` as the output, and then sends the packet through
connection tracking a second time for ``b``'s incoming firewall::

  recirc(0xaf) - resume conntrack with default ct_state=trk|new
  ...
  17. ip,reg0=0x80/0x80,reg14=0x2,metadata=0x5, priority 2002, cookie 0xa30da438
      ...
  32. ip,reg0=0x2/0x2002,metadata=0x5, priority 100, cookie 0x82d02cb5
      ct(commit,zone=NXM_NX_REG13[0..15],nat(src),...)
      ...
  40. metadata=0x5,dl_dst=fa:16:3e:3c:e2:c6, priority 50, cookie 0xd10bc6f5
      set_field:0x3->reg15
      ...
  52. ip,reg0=0x1/0x1,metadata=0x5, priority 100, cookie 0xe8d6e468
      ct(table=53,zone=NXM_NX_REG13[0..15])
  ...
  Datapath actions: ct(commit,zone=10,...,nat(src)),ct(zone=13),recirc(0x4c)

The third phase resumes at table 53 for ``b``'s incoming firewall.
The ACL evaluation allows the ICMP packet (table 54), the connection
is committed (table 60), egress port security passes (table 62/75),
and the packet is finally output::

  recirc(0xb0) - resume conntrack with default ct_state=trk|new
  ...
  54. icmp,reg0=0x80/0x80,reg15=0x3,metadata=0x5, priority 2002, cookie 0x6b1e184f
      ...
  60. ip,reg0=0x2/0x2002,metadata=0x5, priority 100, cookie 0xcc273017
      ct(commit,zone=NXM_NX_REG13[0..15],nat(src),...)
      ...
  65. reg15=0x3,metadata=0x5, priority 100, cookie 0xebf36591
      output:4

  Datapath actions: ct(commit,zone=13,...,nat(src)),5

The final ``output:4`` is OpenFlow port 4, which is ``b``'s tap
interface.  The ``Datapath actions`` end with ``5``, which is the
datapath port for the same interface.

You can relate the OpenFlow flows from traces back to OVN logical
flows.  For individual flows, cut and paste a "cookie" value from
``ofproto/trace`` output into ``ovn-sbctl lflow-list``, e.g.::

  $ sudo ovn-sbctl lflow-list 0x2f4619d3 | abbrev

Or, you can pipe ``ofproto/trace`` output through ``ovn-detrace`` to
annotate every flow::

  $ sudo ovs-appctl ofproto/trace br-int "in_port=$AP_PORT,dl_src=$AP_MAC,dl_dst=$BP_MAC,dl_type=0x0800,nw_proto=1,nw_src=10.1.1.5,nw_dst=10.1.1.6" | ovn-detrace
  ...

Routing
-------

Previously we set up a pair of VMs ``a`` and ``b`` on a network ``n1``
and demonstrated how packets make their way between them.  In this
step, we'll set up a second network ``n2`` with a new VM ``c``,
connect a router ``r`` to both networks, and demonstrate how routing
works in OVN.

There's nothing really new for the network and the VM so let's just go
ahead and create them::

  $ openstack network create --provider-network-type geneve n2
  $ openstack subnet create --subnet-range 10.1.2.0/24 --network n2 n2subnet
  $ openstack server create --nic net-id=n2,v4-fixed-ip=10.1.2.7 --flavor m1.nano --image $IMAGE_ID --key-name demo c
  $ openstack port set --name cp $(openstack port list --server c -f value -c ID)
  $ CP_MAC=$(openstack port show -f value -c mac_address cp)

The new network ``n2`` is not yet connected to ``n1`` in any way.  You
can try tracing a packet from ``a`` to see, for example, that it doesn’t
make it to ``c``. Instead, it will end up as ``multicast unknown``
in ``n1``::

  $ sudo ovn-trace n1 'inport == "ap" && eth.src == '$AP_MAC' && eth.dst == '$CP_MAC
  ...

Now create an OpenStack router and connect it to ``n1`` and ``n2``::

  $ openstack router create r
  $ openstack router add subnet r n1subnet
  $ openstack router add subnet r n2subnet

Now ``a``, ``b``, and ``c`` should all be able to reach other.  You
can get some verification that routing is taking place by running you
``ping`` between ``c`` and one of the other VMs: the reported TTL
should be one less than between ``a`` and ``b`` (63 instead of 64).

Observe via ``ovn-nbctl`` the new OVN logical switch and router and
then ports that connect them together::

  $ sudo ovn-nbctl show|abbrev
  ...
  switch 665f3a (neutron-665f3a) (aka n2)
      port 76b779
          type: router
          router-port: lrp-76b779
      port 6355f3
          type: localport
          addresses: ["fa:16:3e:46:a6:d4 10.1.2.2"]
      port fd81da (aka cp)
          addresses: ["fa:16:3e:a2:ea:b5 10.1.2.7"]
  switch 68cb3a (neutron-68cb3a) (aka n1)
      port f93fab (aka bp)
          addresses: ["fa:16:3e:3c:e2:c6 10.1.1.6"]
      port 2ecc01 (aka ap)
          addresses: ["fa:16:3e:ef:64:b6 10.1.1.5"]
      port 465a58
          type: localport
          addresses: ["fa:16:3e:cb:26:d5 10.1.1.2"]
      port 070ccd
          type: router
          router-port: lrp-070ccd
  ...
  router d06b40 (neutron-3f6409) (aka r)
      port lrp-76b779
          mac: "fa:16:3e:53:b0:b7"
          ipv6-lla: "fe80::f816:3eff:fe53:b0b7"
          networks: ["10.1.2.1/24"]
      port lrp-070ccd
          mac: "fa:16:3e:74:4f:58"
          ipv6-lla: "fe80::f816:3eff:fe74:4f58"
          networks: ["10.1.1.1/24"]

We have not yet looked at the logical flows for an OVN logical router.
You might find it of interest to look at them on your own::

  $ sudo ovn-sbctl lflow-list r | abbrev | less -S
  ...

Let's grab the ``n1subnet`` router porter MAC address to simplify
later commands::

  $ N1SUBNET_MAC=$(sudo ovn-nbctl --bare --columns=mac find logical_router_port networks=10.1.1.1/24)

Let's see what happens at the logical flow level for an ICMP packet
from ``a`` to ``c``.  This generates a long trace but an interesting
one, so we'll look at it bit by bit.  The first three stanzas in the
output show the packet's ingress into ``n1`` and processing through
the firewall on that side (via the "ct_next" connection-tracking
action), and then the selection of the port that leads to router ``r``
as the output port::

  $ sudo ovn-trace n1 'inport == "ap" && eth.src == '$AP_MAC' && eth.dst == '$N1SUBNET_MAC' && ip4.src == 10.1.1.5 && ip4.dst == 10.1.2.7 && ip.ttl == 64 && icmp4.type == 8'
  ...
  ingress(dp="n1", inport="ap")
  -----------------------------
   0. ls_in_check_port_sec (northd.c:10254): 1, priority 50, uuid 9f12c419
      reg0[15] = check_in_port_sec();
      next;
   5. ls_in_pre_acl (northd.c:6496): ip, priority 100, uuid 6dd78063
      reg0[0] = 1;
      next;
   7. ls_in_pre_stateful (northd.c:6761): reg0[0] == 1, priority 100, uuid 015e4fe9
      ct_next(dnat);

  ct_next(ct_state=est|trk /* default (use --ct to customize) */)
  ---------------------------------------------------------------
   8. ls_in_acl_hint (northd.c:6856): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid f90cb568
      reg0[8] = 1;
      reg0[10] = 1;
      next;
   9. ls_in_acl_eval (northd.c:7586): reg0[8] == 1 && (inport == @pg_a9fa0a9b_5c81_4462_a360_b154ea031dff && ip4), priority 2002, uuid 8579ab9d
      reg8[16] = 1;
      next;
  11. ls_in_acl_action (northd.c:7782): reg8[16] == 1, priority 1000, uuid 44123029
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  22. ls_in_acl_after_lb_action (northd.c:7804): 1, priority 0, uuid 723f4e46
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  32. ls_in_l2_lkup (northd.c:11281): eth.dst == fa:16:3e:74:4f:58, priority 50, uuid fb665f90
      outport = "070ccd";
      output;

  egress(dp="n1", inport="ap", outport="070ccd")
  ----------------------------------------------
   2. ls_out_pre_acl (northd.c:6312): ip && outport == "070ccd", priority 110, uuid 3edee410
      next;
   3. ls_out_pre_lb (northd.c:6312): ip && outport == "070ccd", priority 110, uuid a68736c3
      next;
   5. ls_out_acl_hint (northd.c:6856): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid bd84dd49
      reg0[8] = 1;
      reg0[10] = 1;
      next;
   8. ls_out_acl_action (northd.c:7804): 1, priority 0, uuid 615c6e6d
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  14. ls_out_check_port_sec (northd.c:6272): 1, priority 0, uuid f60d0449
      reg0[15] = check_out_port_sec();
      next;
  15. ls_out_apply_port_sec (northd.c:6279): 1, priority 0, uuid 7644229a
      output;
      /* output to "070ccd", type "patch" */

The packet exits logical switch ``n1`` via patch port ``070ccd`` and
enters logical router ``r``. Table 16 performs IP routing: it
recognizes the packet is destined for an attached subnet (10.1.2.0/24),
decrements the TTL, updates the source MAC to the router's interface
MAC (fa:16:3e:53:b0:b7), and selects the output port. Table 22 then
resolves the destination MAC via ARP lookup before the packet is
delivered to logical switch ``n2`` via patch port ``lrp-76b779``::

  ingress(dp="r", inport="lrp-070ccd")
  ------------------------------------
   0. lr_in_admission (northd.c:14532): eth.dst == fa:16:3e:74:4f:58 && inport == "lrp-070ccd", priority 50, uuid f79681c8
      xreg0[0..47] = fa:16:3e:74:4f:58;
      next;
   1. lr_in_lookup_neighbor (northd.c:14740): 1, priority 0, uuid e715bbe9
      reg9[2] = 1;
      next;
   2. lr_in_learn_neighbor (northd.c:14750): reg9[2] == 1 || reg9[3] == 0, priority 100, uuid da0264cc
      mac_cache_use;
      next;
  15. lr_in_ip_routing_pre (northd.c:15048): 1, priority 0, uuid 7366247a
      reg7 = 0;
      next;
  16. lr_in_ip_routing (northd.c:12864): ip4.dst == 10.1.2.0/24, priority 198, uuid b5dcfb57
      ip.ttl--;
      reg8[0..15] = 0;
      reg0 = ip4.dst;
      reg5 = 10.1.2.1;
      eth.src = fa:16:3e:53:b0:b7;
      outport = "lrp-76b779";
      flags.loopback = 1;
      reg9[9] = 1;
      next;
  17. lr_in_ip_routing_ecmp (northd.c:15061): reg8[0..15] == 0, priority 150, uuid 33ade7cb
      next;
  18. lr_in_policy (northd.c:15455): 1, priority 0, uuid f8be1f7f
      reg8[0..15] = 0;
      next;
  19. lr_in_policy_ecmp (northd.c:15458): reg8[0..15] == 0, priority 150, uuid 23b1bd72
      next;
  22. lr_in_arp_resolve (northd.c:15882): outport == "lrp-76b779" && reg0 == 10.1.2.7, priority 100, uuid 9f2cc785
      eth.dst = fa:16:3e:a2:ea:b5;
      next;
  26. lr_in_network_id (northd.c:16431): outport == "lrp-76b779" && ip4 && reg0 == 10.1.2.1/24, priority 110, uuid dad4dd60
      flags.network_id = 0;
      next;
  28. lr_in_ecmp_stateful_egr (northd.c:16392): 1, priority 0, uuid 88e8e455
      output;

  egress(dp="r", inport="lrp-070ccd", outport="lrp-76b779")
  ---------------------------------------------------------
   0. lr_out_chk_dnat_local (northd.c:18024): 1, priority 0, uuid 964e8e6c
      reg9[4] = 0;
      next;
   6. lr_out_delivery (northd.c:16527): outport == "lrp-76b779", priority 100, uuid c45c42c0
      output;
      /* output to "lrp-76b779", type "patch" */

Finally the logical switch for ``n2`` runs through the same logic as
``n1`` and the packet is delivered to VM ``c``::

  ingress(dp="n2", inport="76b779")
  ---------------------------------
   0. ls_in_check_port_sec (northd.c:6191): inport == "76b779", priority 70, uuid 7ebebf93
      reg0[18] = 1;
      next;
   5. ls_in_pre_acl (northd.c:6309): ip && inport == "76b779", priority 110, uuid 61493ddd
      next;
   6. ls_in_pre_lb (northd.c:6309): ip && inport == "76b779", priority 110, uuid 02a02bff
      next;
   8. ls_in_acl_hint (northd.c:6856): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid f90cb568
      reg0[8] = 1;
      reg0[10] = 1;
      next;
  11. ls_in_acl_action (northd.c:7804): 1, priority 0, uuid 109cb3ac
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  22. ls_in_acl_after_lb_action (northd.c:7804): 1, priority 0, uuid 723f4e46
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  32. ls_in_l2_lkup (northd.c:11291): eth.dst == fa:16:3e:a2:ea:b5, priority 50, uuid a68752c5
      outport = "cp";
      output;

  egress(dp="n2", inport="76b779", outport="cp")
  ----------------------------------------------
   2. ls_out_pre_acl (northd.c:6499): ip, priority 100, uuid 0c984d09
      reg0[0] = 1;
      next;
   4. ls_out_pre_stateful (northd.c:6765): reg0[0] == 1, priority 100, uuid e8d6e468
      ct_next(dnat);

  ct_next(ct_state=est|trk /* default (use --ct to customize) */)
  ---------------------------------------------------------------
   5. ls_out_acl_hint (northd.c:6856): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid bd84dd49
      reg0[8] = 1;
      reg0[10] = 1;
      next;
   6. ls_out_acl_eval (northd.c:7586): reg0[8] == 1 && (outport == @pg_a9fa0a9b_5c81_4462_a360_b154ea031dff && ip4 && ip4.src == 0.0.0.0/0 && icmp4), priority 2002, uuid 5f2c2403
      reg8[16] = 1;
      next;
   8. ls_out_acl_action (northd.c:7782): reg8[16] == 1, priority 1000, uuid 1ef90f41
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;

Physical Tracing
~~~~~~~~~~~~~~~~

It's possible to use ``ofproto/trace``, just as before, to trace a
packet through OpenFlow tables, either for a hypothetical packet or
one that you get from a real test case using ``ovs-dpctl``.  The
process is just the same as before and the output is almost the same,
too.  Using a router doesn't actually introduce any interesting new
wrinkles, so we'll skip over this for this case and for the remainder
of the tutorial, but you can follow the steps on your own if you like.

Adding a Gateway
----------------

The VMs that we've created can access each other but they are isolated
from the physical world.  In OpenStack, the dominant way to connect a
VM to external networks is by creating what is called a "floating IP
address", which uses network address translation to connect an
external address to an internal one.

DevStack created a pair of networks named "private" and "public".  To
use a floating IP address from a VM, we first add a port to the VM
with an IP address from the "private" network, then we create a
floating IP address on the "public" network, then we associate the
port with the floating IP address.

Let's add a new VM ``d`` with a floating IP::

  $ openstack server create --nic net-id=private --flavor m1.nano --image $IMAGE_ID --key-name demo d
  $ openstack port set --name dp $(openstack port list --server d -f value -c ID)
  $ DP_MAC=$(openstack port show -f value -c mac_address dp)
  $ openstack floating ip create --floating-ip-address 172.24.4.8 public
  $ openstack server add floating ip d 172.24.4.8

(We specified a particular floating IP address to make the examples
easier to follow, but without that OpenStack will automatically
allocate one.)

It's also necessary to configure the "public" network because DevStack
does not do it automatically::

  $ sudo ip link set br-ex up
  $ sudo ip addr add 172.24.4.1/24 dev br-ex

Now you should be able to "ping" VM ``d`` from the OpenStack host::

  $ ping 172.24.4.8
  PING 172.24.4.8 (172.24.4.8) 56(84) bytes of data.
  64 bytes from 172.24.4.8: icmp_seq=1 ttl=63 time=56.0 ms
  64 bytes from 172.24.4.8: icmp_seq=2 ttl=63 time=1.44 ms
  64 bytes from 172.24.4.8: icmp_seq=3 ttl=63 time=1.04 ms
  64 bytes from 172.24.4.8: icmp_seq=4 ttl=63 time=0.403 ms
  ^C
  --- 172.24.4.8 ping statistics ---
  4 packets transmitted, 4 received, 0% packet loss, time 3003ms
  rtt min/avg/max/mdev = 0.403/14.731/56.028/23.845 ms

You can also SSH in with the key that we created during setup::

  $ ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
    -i ~/id_rsa_demo cirros@172.24.4.8

Let's dive in and see how this gets implemented in OVN.  First, the
relevant parts of the NB DB for the "public" and "private" networks
and the router between them::

  $ sudo ovn-nbctl show | abbrev
  switch 6cad57 (neutron-6cad57) (aka public)
      port 2d86c4
          type: localport
          addresses: ["fa:16:3e:a9:47:00"]
      port 09c087
          type: router
          router-port: lrp-09c087
      port provnet-2deb4b
          type: localnet
          addresses: ["unknown"]
  switch 71160a (neutron-71160a) (aka shared)
      port 882366
          type: localport
          addresses: ["fa:16:3e:94:e7:c6 192.168.233.2"]
  ...
  switch 935ec0 (neutron-935ec0) (aka private)
      port 4bcc8f
          type: router
          router-port: lrp-4bcc8f
      port f87782
          type: router
          router-port: lrp-f87782
      port 5facc2 (aka dp)
          addresses: ["fa:16:3e:81:74:ac 10.0.0.45 fd8a:9a83:ed81:0:f816:3eff:fe81:74ac"]
      port 6344ee
          type: localport
          addresses: ["fa:16:3e:da:bb:9e 10.0.0.2 fd8a:9a83:ed81:0:f816:3eff:feda:bb9e"]
  ...
  router 95152d (neutron-d99ace) (aka router1)
      port lrp-f87782
          mac: "fa:16:3e:93:8f:4d"
          ipv6-lla: "fe80::f816:3eff:fe93:8f4d"
          networks: ["10.0.0.1/26"]
      port lrp-4bcc8f
          mac: "fa:16:3e:8c:31:06"
          ipv6-lla: "fe80::f816:3eff:fe8c:3106"
          networks: ["fd8a:9a83:ed81::1/64"]
      port lrp-09c087
          mac: "fa:16:3e:48:c3:6b"
          ipv6-lla: "fe80::f816:3eff:fe48:c36b"
          networks: ["172.24.4.37/24", "2001:db8::287/64"]
      nat 0cdf3f
          external ip: "172.24.4.8"
          logical ip: "10.0.0.45"
          type: "dnat_and_snat"
      nat 930592
          external ip: "172.24.4.37"
          logical ip: "0.0.0.0/0"
          type: "snat"
  ...

What we see is:

* VM ``d`` is on the "private" switch under its private IP address
  10.0.0.45.  The "private" switch is connected to "router1" via two
  router ports (one for IPv4, one for IPv6).

* The "public" switch is connected to "router1" and to the physical
  network via a "localnet" port.

* "router1" is in the middle between "private" and "public".  In
  addition to the router ports that connect to these switches, it has
  "nat" entries that direct network address translation.  The
  translation between floating IP address 172.24.4.8 and private
  address 10.0.0.45 makes perfect sense.

When the NB DB gets translated into logical flows at the southbound
layer, the "nat" entries get translated into IP matches that then
invoke "ct_snat" and "ct_dnat" actions.  The details are intricate,
but you can get some of the idea by just looking for relevant flows::

  $ sudo ovn-sbctl lflow-list router1 | abbrev | grep nat | grep -E '172.24.4.8'
    table=5 (lr_in_unsnat       ), priority=100  , match=(ip && ip4.dst == 172.24.4.8 && inport == "lrp-09c087" && is_chassis_resident("cr-lrp-09c087")), action=(ct_snat;)
    table=10(lr_in_dnat         ), priority=100  , match=(ip && ip4.dst == 172.24.4.8 && inport == "lrp-09c087" && is_chassis_resident("cr-lrp-09c087")), action=(ct_dnat(10.0.0.45);)
    table=3 (lr_out_snat        ), priority=161  , match=(ip && ip4.src == 10.0.0.45 && outport == "lrp-09c087" && is_chassis_resident("cr-lrp-09c087") && (!ct.trk || !ct.rpl)), action=(ct_snat(172.24.4.8);)

Let's take a look at how a packet passes through this whole gauntlet.
The first two stanzas just show the packet traveling through the
"public" network and being forwarded to the "router1" network::

  $ sudo ovn-trace public 'inport == "provnet-2deb4bdc-df0c-49a8-840a-d8dff5a0ab6b" && eth.src == 00:01:02:03:04:05 && eth.dst == fa:16:3e:48:c3:6b && ip4.src == 172.24.4.1 && ip4.dst == 172.24.4.8 && ip.ttl == 64 && icmp4.type==8'
  ...
  ingress(dp="public", inport="provnet-2deb4b")
  ---------------------------------------------
   0. ls_in_check_port_sec (northd.c:10254): 1, priority 50, uuid 9f12c419
      reg0[15] = check_in_port_sec();
      next;
   3. ls_in_lookup_fdb (northd.c:10322): inport == "provnet-2deb4b", priority 50, uuid 451cefb7
      flags.localnet = 1;
      next;
   6. ls_in_pre_lb (northd.c:6309): ip && inport == "provnet-2deb4b", priority 110, uuid e2dec5a1
      next;
  32. ls_in_l2_lkup (northd.c:11281): eth.dst == fa:16:3e:48:c3:6b && is_chassis_resident("cr-lrp-09c087"), priority 50, uuid f0e839d4
      outport = "09c087";
      output;

  egress(dp="public", inport="provnet-2deb4b", outport="09c087")
  --------------------------------------------------------------
   3. ls_out_pre_lb (northd.c:6312): ip && outport == "09c087", priority 110, uuid 116f0d4c
      flags.pkt_sampled = 0;
      ct_clear;
      next;
  14. ls_out_check_port_sec (northd.c:6272): 1, priority 0, uuid f60d0449
      reg0[15] = check_out_port_sec();
      next;
  15. ls_out_apply_port_sec (northd.c:6279): 1, priority 0, uuid 7644229a
      output;
      /* output to "09c087", type "patch" */

In "router1", first the ``ct_snat`` action without an argument
attempts to "un-SNAT" the packet.  ovn-trace treats this as a no-op,
because it doesn't have any state for tracking connections.  As an
alternative, it invokes ``ct_dnat(10.0.0.45)`` to NAT the destination
IP::

  ingress(dp="router1", inport="lrp-09c087")
  ------------------------------------------
   0. lr_in_admission (northd.c:14532): eth.dst == fa:16:3e:48:c3:6b && inport == "lrp-09c087" && is_chassis_resident("cr-lrp-09c087"), priority 50, uuid a00eb7d2
      reg9[1] = check_pkt_larger(1456);
      xreg0[0..47] = fa:16:3e:48:c3:6b;
      next;
   1. lr_in_lookup_neighbor (northd.c:14740): 1, priority 0, uuid e715bbe9
      reg9[2] = 1;
      next;
   2. lr_in_learn_neighbor (northd.c:14750): reg9[2] == 1 || reg9[3] == 0, priority 100, uuid da0264cc
      mac_cache_use;
      next;
   5. lr_in_unsnat (northd.c:17487): ip && ip4.dst == 172.24.4.8 && inport == "lrp-09c087" && is_chassis_resident("cr-lrp-09c087"), priority 100, uuid 39ebd86d
      ct_snat;

  ct_snat /* assuming no un-snat entry, so no change */ /* default (use --ct to customize) */
  -------------------------------------------------------------------------------------------
  10. lr_in_dnat (northd.c:17566): ip && ip4.dst == 172.24.4.8 && inport == "lrp-09c087" && is_chassis_resident("cr-lrp-09c087"), priority 100, uuid f8ba0d1c
      ct_dnat(10.0.0.45);

Still in "router1", the routing and output steps transmit the packet
to the "private" network::

  ct_dnat(ip4.dst=10.0.0.45)
  --------------------------
  15. lr_in_ip_routing_pre (northd.c:15048): 1, priority 0, uuid 7366247a
      reg7 = 0;
      next;
  16. lr_in_ip_routing (northd.c:12864): ip4.dst == 10.0.0.0/26, priority 214, uuid 8bdb8da7
      ip.ttl--;
      reg8[0..15] = 0;
      reg0 = ip4.dst;
      reg5 = 10.0.0.1;
      eth.src = fa:16:3e:93:8f:4d;
      outport = "lrp-f87782";
      flags.loopback = 1;
      reg9[9] = 1;
      next;
  17. lr_in_ip_routing_ecmp (northd.c:15061): reg8[0..15] == 0, priority 150, uuid 33ade7cb
      next;
  18. lr_in_policy (northd.c:15455): 1, priority 0, uuid f8be1f7f
      reg8[0..15] = 0;
      next;
  19. lr_in_policy_ecmp (northd.c:15458): reg8[0..15] == 0, priority 150, uuid 23b1bd72
      next;
  22. lr_in_arp_resolve (northd.c:15882): outport == "lrp-f87782" && reg0 == 10.0.0.45, priority 100, uuid b88625f8
      eth.dst = fa:16:3e:81:74:ac;
      next;
  26. lr_in_network_id (northd.c:16431): outport == "lrp-f87782" && ip4 && reg0 == 10.0.0.1/26, priority 110, uuid 0328960b
      flags.network_id = 0;
      next;
  28. lr_in_ecmp_stateful_egr (northd.c:16392): 1, priority 0, uuid 88e8e455
      output;

  egress(dp="router1", inport="lrp-09c087", outport="lrp-f87782")
  ---------------------------------------------------------------
   0. lr_out_chk_dnat_local (northd.c:18024): 1, priority 0, uuid 964e8e6c
      reg9[4] = 0;
      next;
   3. lr_out_snat (northd.c:17873): ip && ip4.dst == 10.0.0.45 && inport == "lrp-09c087" && is_chassis_resident("cr-lrp-09c087") && (!ct.trk || !ct.rpl), priority 166, uuid 8f3b8342
      ct_dnat;

  ct_dnat /* assuming no un-dnat entry, so no change */
  -----------------------------------------------------
   6. lr_out_delivery (northd.c:16527): outport == "lrp-f87782", priority 100, uuid 2c123c40
      output;
      /* output to "lrp-f87782", type "patch" */

In the "private" network, the packet passes through VM ``d``'s
firewall and is output to ``d``::

  ingress(dp="private", inport="f87782")
  --------------------------------------
   0. ls_in_check_port_sec (northd.c:6191): inport == "f87782", priority 70, uuid 523f85a2
      reg0[18] = 1;
      next;
   5. ls_in_pre_acl (northd.c:6309): ip && inport == "f87782", priority 110, uuid 2aee2328
      next;
   6. ls_in_pre_lb (northd.c:6309): ip && inport == "f87782", priority 110, uuid a0bcac76
      next;
   8. ls_in_acl_hint (northd.c:6856): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid f90cb568
      reg0[8] = 1;
      reg0[10] = 1;
      next;
  11. ls_in_acl_action (northd.c:7804): 1, priority 0, uuid 109cb3ac
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  22. ls_in_acl_after_lb_action (northd.c:7804): 1, priority 0, uuid 723f4e46
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  32. ls_in_l2_lkup (northd.c:11291): eth.dst == fa:16:3e:81:74:ac, priority 50, uuid ceeed558
      outport = "dp";
      output;

  egress(dp="private", inport="f87782", outport="dp")
  ---------------------------------------------------
   2. ls_out_pre_acl (northd.c:6499): ip, priority 100, uuid 0c984d09
      reg0[0] = 1;
      next;
   4. ls_out_pre_stateful (northd.c:6765): reg0[0] == 1, priority 100, uuid e8d6e468
      ct_next(dnat);

  ct_next(ct_state=est|trk /* default (use --ct to customize) */)
  ---------------------------------------------------------------
   5. ls_out_acl_hint (northd.c:6856): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid bd84dd49
      reg0[8] = 1;
      reg0[10] = 1;
      next;
   6. ls_out_acl_eval (northd.c:7586): reg0[8] == 1 && (outport == @pg_a9fa0a9b_5c81_4462_a360_b154ea031dff && ip4 && ip4.src == 0.0.0.0/0 && icmp4), priority 2002, uuid 5f2c2403
      reg8[16] = 1;
      next;
   8. ls_out_acl_action (northd.c:7782): reg8[16] == 1, priority 1000, uuid 1ef90f41
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  14. ls_out_check_port_sec (northd.c:6272): 1, priority 0, uuid f60d0449
      reg0[15] = check_out_port_sec();
      next;
  15. ls_out_apply_port_sec (northd.c:6279): 1, priority 0, uuid 7644229a
      output;
      /* output to "dp", type "" */

IPv6
----

OVN supports IPv6 logical routing.  Let's try it out.

The first step is to add an IPv6 subnet to networks ``n1`` and ``n2``,
then attach those subnets to our router ``r``.  As usual, though
OpenStack can assign addresses itself, we use fixed ones to make the
discussion easier::

  $ openstack subnet create --ip-version 6 --subnet-range fc11::/64 --network n1 n1subnet6
  $ openstack subnet create --ip-version 6 --subnet-range fc22::/64 --network n2 n2subnet6
  $ openstack router add subnet r n1subnet6
  $ openstack router add subnet r n2subnet6

Then we add an IPv6 address to each of our VMs::

  $ A_PORT_ID=$(openstack port list --server a -f value -c ID)
  $ openstack port set --fixed-ip subnet=n1subnet6,ip-address=fc11::5 $A_PORT_ID
  $ B_PORT_ID=$(openstack port list --server b -f value -c ID)
  $ openstack port set --fixed-ip subnet=n1subnet6,ip-address=fc11::6 $B_PORT_ID
  $ C_PORT_ID=$(openstack port list --server c -f value -c ID)
  $ openstack port set --fixed-ip subnet=n2subnet6,ip-address=fc22::7 $C_PORT_ID

At least for me, the new IPv6 addresses didn't automatically get
propagated into the VMs.  To do it by hand, pull up the console for
``a`` and run::

  $ sudo ip addr add fc11::5/64 dev eth0
  $ sudo ip route add via fc11::1

Then in ``b``::

  $ sudo ip addr add fc11::6/64 dev eth0
  $ sudo ip route add via fc11::1

Finally in ``c``::

  $ sudo ip addr add fc22::7/64 dev eth0
  $ sudo ip route add via fc22::1

Now you should have working IPv6 routing through router ``r``.  The
relevant parts of the NB DB look like the following.  The interesting
parts are the new ``fc11::`` and ``fc22::`` addresses on the ports in
``n1`` and ``n2`` and the new IPv6 router ports in ``r``::

  $ sudo ovn-nbctl show | abbrev
  ...
  switch 68cb3a (neutron-68cb3a) (aka n1)
      port f93fab (aka bp)
          addresses: ["fa:16:3e:3c:e2:c6 10.1.1.6 fc11::6"]
      port 070ccd
          type: router
          router-port: lrp-070ccd
      port 0db813
          type: router
          router-port: lrp-0db813
      port 2ecc01 (aka ap)
          addresses: ["fa:16:3e:ef:64:b6 10.1.1.5 fc11::5"]
      port 465a58
          type: localport
          addresses: ["fa:16:3e:cb:26:d5 10.1.1.2"]
  ...
  switch 665f3a (neutron-665f3a) (aka n2)
      port 76b779
          type: router
          router-port: lrp-76b779
      port 6355f3
          type: localport
          addresses: ["fa:16:3e:46:a6:d4 10.1.2.2"]
      port fd81da (aka cp)
          addresses: ["fa:16:3e:a2:ea:b5 10.1.2.7 fc22::7"]
      port 398d1f
          type: router
          router-port: lrp-398d1f
  ...
  router d06b40 (neutron-3f6409) (aka r)
      port lrp-76b779
          mac: "fa:16:3e:53:b0:b7"
          ipv6-lla: "fe80::f816:3eff:fe53:b0b7"
          networks: ["10.1.2.1/24"]
      port lrp-070ccd
          mac: "fa:16:3e:74:4f:58"
          ipv6-lla: "fe80::f816:3eff:fe74:4f58"
          networks: ["10.1.1.1/24"]
      port lrp-398d1f
          mac: "fa:16:3e:f4:b3:12"
          ipv6-lla: "fe80::f816:3eff:fef4:b312"
          networks: ["fc22::/64"]
      port lrp-0db813
          mac: "fa:16:3e:02:43:29"
          ipv6-lla: "fe80::f816:3eff:fe02:4329"
          networks: ["fc11::/64"]

Try tracing a packet from ``a`` to ``c``.  The results correspond
closely to those for IPv4 which we already discussed back under
`Routing`_::

  $ N1SUBNET6_MAC=$(sudo ovn-nbctl --bare --columns=mac find logical_router_port 'networks{>=}"fc11::/64"')
  $ sudo ovn-trace n1 'inport == "ap" && eth.src == '$AP_MAC' && eth.dst == '$N1SUBNET6_MAC' && ip6.src == fc11::5 && ip6.dst == fc22::7 && ip.ttl == 64 && icmp6.type == 8'
  ...
  ingress(dp="n1", inport="ap")
  -----------------------------
   0. ls_in_check_port_sec (northd.c:10254): 1, priority 50, uuid 9f12c419
      reg0[15] = check_in_port_sec();
      next;
   5. ls_in_pre_acl (northd.c:6496): ip, priority 100, uuid 6dd78063
      reg0[0] = 1;
      next;
   7. ls_in_pre_stateful (northd.c:6761): reg0[0] == 1, priority 100, uuid 015e4fe9
      ct_next(dnat);

  ct_next(ct_state=est|trk /* default (use --ct to customize) */)
  ---------------------------------------------------------------
   8. ls_in_acl_hint (northd.c:6856): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid f90cb568
      reg0[8] = 1;
      reg0[10] = 1;
      next;
   9. ls_in_acl_eval (northd.c:7586): reg0[8] == 1 && (inport == @pg_a9fa0a9b_5c81_4462_a360_b154ea031dff && ip6), priority 2002, uuid a5c6815e
      reg8[16] = 1;
      next;
  11. ls_in_acl_action (northd.c:7782): reg8[16] == 1, priority 1000, uuid 44123029
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  22. ls_in_acl_after_lb_action (northd.c:7804): 1, priority 0, uuid 723f4e46
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  32. ls_in_l2_lkup (northd.c:11281): eth.dst == fa:16:3e:02:43:29, priority 50, uuid 497d95ad
      outport = "0db813";
      output;

  egress(dp="n1", inport="ap", outport="0db813")
  ----------------------------------------------
   2. ls_out_pre_acl (northd.c:6312): ip && outport == "0db813", priority 110, uuid 5dd24dd8
      next;
   3. ls_out_pre_lb (northd.c:6312): ip && outport == "0db813", priority 110, uuid bada3ee6
      next;
   5. ls_out_acl_hint (northd.c:6856): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid bd84dd49
      reg0[8] = 1;
      reg0[10] = 1;
      next;
   8. ls_out_acl_action (northd.c:7804): 1, priority 0, uuid 615c6e6d
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  14. ls_out_check_port_sec (northd.c:6272): 1, priority 0, uuid f60d0449
      reg0[15] = check_out_port_sec();
      next;
  15. ls_out_apply_port_sec (northd.c:6279): 1, priority 0, uuid 7644229a
      output;
      /* output to "0db813", type "patch" */

  ingress(dp="r", inport="lrp-0db813")
  ------------------------------------
   0. lr_in_admission (northd.c:14532): eth.dst == fa:16:3e:02:43:29 && inport == "lrp-0db813", priority 50, uuid 6530fbf0
      xreg0[0..47] = fa:16:3e:02:43:29;
      next;
   1. lr_in_lookup_neighbor (northd.c:14740): 1, priority 0, uuid e715bbe9
      reg9[2] = 1;
      next;
   2. lr_in_learn_neighbor (northd.c:14750): reg9[2] == 1 || reg9[3] == 0, priority 100, uuid da0264cc
      mac_cache_use;
      next;
  15. lr_in_ip_routing_pre (northd.c:15048): 1, priority 0, uuid 7366247a
      reg7 = 0;
      next;
  16. lr_in_ip_routing (northd.c:12864): ip6.dst == fc22::/64, priority 518, uuid 6a35627f
      ip.ttl--;
      reg8[0..15] = 0;
      xxreg0 = ip6.dst;
      xxreg1 = fc22::;
      eth.src = fa:16:3e:f4:b3:12;
      outport = "lrp-398d1f";
      flags.loopback = 1;
      reg9[9] = 0;
      next;
  17. lr_in_ip_routing_ecmp (northd.c:15061): reg8[0..15] == 0, priority 150, uuid 33ade7cb
      next;
  18. lr_in_policy (northd.c:15455): 1, priority 0, uuid f8be1f7f
      reg8[0..15] = 0;
      next;
  19. lr_in_policy_ecmp (northd.c:15458): reg8[0..15] == 0, priority 150, uuid 23b1bd72
      next;
  22. lr_in_arp_resolve (northd.c:15911): outport == "lrp-398d1f" && xxreg0 == fc22::7, priority 100, uuid 7fa4ce34
      eth.dst = fa:16:3e:a2:ea:b5;
      next;
  26. lr_in_network_id (northd.c:16465): outport == "lrp-398d1f" && ip6 && xxreg0 == fc22::/64, priority 110, uuid 25229b3f
      flags.network_id = 0;
      next;
  28. lr_in_ecmp_stateful_egr (northd.c:16392): 1, priority 0, uuid 88e8e455
      output;

  egress(dp="r", inport="lrp-0db813", outport="lrp-398d1f")
  ---------------------------------------------------------
   0. lr_out_chk_dnat_local (northd.c:18024): 1, priority 0, uuid 964e8e6c
      reg9[4] = 0;
      next;
   6. lr_out_delivery (northd.c:16527): outport == "lrp-398d1f", priority 100, uuid 98d18d34
      output;
      /* output to "lrp-398d1f", type "patch" */

  ingress(dp="n2", inport="398d1f")
  ---------------------------------
   0. ls_in_check_port_sec (northd.c:6191): inport == "398d1f", priority 70, uuid fce56793
      reg0[18] = 1;
      next;
   5. ls_in_pre_acl (northd.c:6309): ip && inport == "398d1f", priority 110, uuid f0c769b3
      next;
   6. ls_in_pre_lb (northd.c:6309): ip && inport == "398d1f", priority 110, uuid 91a17fbb
      next;
   8. ls_in_acl_hint (northd.c:6856): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid f90cb568
      reg0[8] = 1;
      reg0[10] = 1;
      next;
  11. ls_in_acl_action (northd.c:7804): 1, priority 0, uuid 109cb3ac
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  22. ls_in_acl_after_lb_action (northd.c:7804): 1, priority 0, uuid 723f4e46
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  32. ls_in_l2_lkup (northd.c:11291): eth.dst == fa:16:3e:a2:ea:b5, priority 50, uuid a68752c5
      outport = "cp";
      output;

  egress(dp="n2", inport="398d1f", outport="cp")
  ----------------------------------------------
   2. ls_out_pre_acl (northd.c:6499): ip, priority 100, uuid 0c984d09
      reg0[0] = 1;
      next;
   4. ls_out_pre_stateful (northd.c:6765): reg0[0] == 1, priority 100, uuid e8d6e468
      ct_next(dnat);

  ct_next(ct_state=est|trk /* default (use --ct to customize) */)
  ---------------------------------------------------------------
   5. ls_out_acl_hint (northd.c:6856): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid bd84dd49
      reg0[8] = 1;
      reg0[10] = 1;
      next;
   6. ls_out_acl_eval (northd.c:7586): reg0[8] == 1 && (outport == @pg_a9fa0a9b_5c81_4462_a360_b154ea031dff && ip6 && ip6.src == $pg_a9fa0a9b_5c81_4462_a360_b154ea031dff_ip6), priority 2002, uuid ccdb6a7f
      reg8[16] = 1;
      next;
   8. ls_out_acl_action (northd.c:7782): reg8[16] == 1, priority 1000, uuid 1ef90f41
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  14. ls_out_check_port_sec (northd.c:6272): 1, priority 0, uuid f60d0449
      reg0[15] = check_out_port_sec();
      next;
  15. ls_out_apply_port_sec (northd.c:6279): 1, priority 0, uuid 7644229a
      output;
      /* output to "cp", type "" */

ACLs
----

Let's explore how ACLs work in OpenStack and OVN.  In OpenStack, ACL
rules are part of "security groups", which are "default deny", that
is, packets are not allowed by default and the rules added to security
groups serve to allow different classes of packets.  The default group
(named "default") that is assigned to each of our VMs so far allows
all traffic from our other VMs, which isn't very interesting for
testing.  So, let's create a new security group, which we'll name
"custom", add rules to it that allow incoming SSH and ICMP traffic,
and apply this security group to VM ``c``::

  $ openstack security group create custom
  $ openstack security group rule create --protocol tcp --dst-port 22 custom
  $ openstack security group rule create --protocol icmp custom
  $ openstack server remove security group c default
  $ openstack server add security group c custom

Now we can do some experiments to test security groups.  From the
console on ``a`` or ``b``, it should now be possible to "ping" ``c``
or to SSH to it, but attempts to initiate connections on other ports
should be blocked.  (You can try to connect on another port with
``ssh -p PORT IP`` or ``nc IP PORT -vv``.)  Connection attempts should
time out rather than receive the "connection refused" or "connection
reset" error that you would see between ``a`` and ``b``.

It's also possible to test ACLs via ovn-trace, with one new wrinkle.
ovn-trace can't simulate connection tracking state in the network, so
by default it assumes that every packet represents an established
connection.  That's good enough for what we've been doing so far, but
for checking properties of security groups we want to look at more
detail.

If you look back at the VM-to-VM traces we've done until now, you can
see that they execute two ``ct_next`` actions:

* The first of these is for the packet passing outward through the
  source VM's firewall.  We can tell ovn-trace to treat the packet as
  starting a new connection or adding to an established connection by
  adding a ``--ct`` option: ``--ct new`` or ``--ct est``,
  respectively.  The latter is the default and therefore what we've
  been using so far.  We can also use ``--ct est,rpl``, which in
  addition to ``--ct est`` means that the connection was initiated by
  the destination VM rather than by the VM sending this packet.

* The second is for the packet passing inward through the destination
  VM's firewall.  For this one, it makes sense to tell ovn-trace that
  the packet is starting a new connection, with ``--ct new``, or that
  it is a packet sent in reply to a connection established by the
  destination VM, with ``--ct est,rpl``.

ovn-trace uses the ``--ct`` options in order, so if we want to
override the second ``ct_next`` behavior we have to specify two
options.

Another useful ovn-trace option for this testing is ``--minimal``,
which reduces the amount of output.  In this case we're really just
interested in finding out whether the packet reaches the destination
VM, that is, whether there's an eventual ``output`` action to ``c``,
so ``--minimal`` works fine and the output is easier to read.

Try a few traces.  For example:

First, obtain the mac address of logical router's IPv4 interface
on ``n1``::

    $ N1SUBNET4_MAC=$(sudo ovn-nbctl --bare --columns=mac \
      find logical_router_port networks=\"10.1.1.1/24\")

* VM ``a`` initiates a new SSH connection to ``c``::

    $ sudo ovn-trace --ct new --ct new --minimal n1 'inport == "ap" &&
      eth.src == '$AP_MAC' && eth.dst == '$N1SUBNET4_MAC' &&
      ip4.src == 10.1.1.5 && ip4.dst == 10.1.2.7 && ip.ttl == 64 &&
      tcp.dst == 22'
    ...
    ct_next(ct_state=new|trk) {
        ip.ttl--;
        eth.src = fa:16:3e:53:b0:b7;
        eth.dst = fa:16:3e:a2:ea:b5;
        ct_next(ct_state=new|trk) {
            output("cp");
        };
    };

  This succeeds, as you can see since there is an ``output`` action.

* VM ``a`` initiates a new Telnet connection to ``c``::

    $ sudo ovn-trace --ct new --ct new --minimal n1 'inport == "ap" &&
      eth.src == '$AP_MAC' && eth.dst == '$N1SUBNET4_MAC' &&
      ip4.src == 10.1.1.5 && ip4.dst == 10.1.2.7 && ip.ttl == 64 &&
      tcp.dst == 23'
    ct_next(ct_state=new|trk) {
        ip.ttl--;
        eth.src = fa:16:3e:53:b0:b7;
        eth.dst = fa:16:3e:a2:ea:b5;
        ct_next(ct_state=new|trk);
    };

  This fails, as you can see from the lack of an ``output`` action.

* VM ``a`` replies to a packet that is part of a Telnet connection
  originally initiated by ``c``::

    $ sudo ovn-trace --ct est,rpl --ct est,rpl --minimal n1 'inport == "ap" &&
      eth.src == '$AP_MAC' && eth.dst == '$N1SUBNET4_MAC' &&
      ip4.src == 10.1.1.5 && ip4.dst == 10.1.2.7 && ip.ttl == 64 &&
      tcp.dst == 23'
    ...
    ct_next(ct_state=est|rpl|trk) {
        ip.ttl--;
        eth.src = fa:16:3e:53:b0:b7;
        eth.dst = fa:16:3e:a2:ea:b5;
        ct_next(ct_state=est|rpl|trk) {
            output("cp");
        };
    };

  This succeeds, as you can see from the ``output`` action, since
  traffic received in reply to an outgoing connection is always
  allowed.

DHCP
----

As a final demonstration of the OVN architecture, let's examine the
DHCP implementation.  Like switching, routing, and NAT, the OVN
implementation of DHCP involves configuration in the NB DB and logical
flows in the SB DB.

Let's look at the DHCP support for ``a``'s port ``ap``.  The port's
Logical_Switch_Port record shows that ``ap`` has DHCPv4 options::

  $ sudo ovn-nbctl list logical_switch_port ap | abbrev
  _uuid               : f013b5
  addresses           : ["fa:16:3e:ef:64:b6 10.1.1.5 fc11::5"]
  dhcpv4_options      : a7de4a
  dhcpv6_options      : 109d93
  dynamic_addresses   : []
  enabled             : true
  external_ids        : {"neutron:cidrs"="10.1.1.5/24 fc11::5/64", "neutron:device_id"="91df4e", "neutron:device_owner"="compute:nova", "neutron:host_id"=localhost.localdomain, "neutron:mtu"="", "neutron:network_name"=neutron-68cb3a, "neutron:port_capabilities"="", "neutron:port_name"=ap, "neutron:project_id"="584a7ea8c2fd4b9582945443de262f65", "neutron:revision_number"="7", "neutron:security_group_ids"="a9fa0a", "neutron:subnet_pool_addr_scope4"="", "neutron:subnet_pool_addr_scope6"="", "neutron:vnic_type"=normal}
  ha_chassis_group    : []
  health_checks       : []
  mirror_rules        : []
  name                : "2ecc01"
  options             : {requested-chassis=localhost.localdomain}
  parent_name         : []
  peer                : []
  port_security       : ["fa:16:3e:ef:64:b6 10.1.1.5 fc11::5"]
  tag                 : []
  tag_request         : []
  type                : ""
  up                  : true

We can then list them either by UUID or, more easily, by port name::

  $ sudo ovn-nbctl list dhcp_options ap | abbrev
  _uuid               : a7de4a
  cidr                : "10.1.1.0/24"
  external_ids        : {"neutron:network_id"="68cb3a", "neutron:revision_number"="0", subnet_id="a375e9"}
  options             : {classless_static_route="{169.254.169.254/32,10.1.1.2, 0.0.0.0/0,10.1.1.1}", dns_server="{8.8.8.8}", domain_name="\"openstackgate.local\"", lease_time="43200", mtu="1442", router="10.1.1.1", server_id="10.1.1.1", server_mac="fa:16:3e:27:21:15"}

These options show the basic DHCP configuration for the subnet.  They
do not include the IP address itself, which comes from the
Logical_Switch_Port record.  This allows a whole Neutron subnet to
share a single DHCP_Options record.  You can see this sharing in
action, if you like, by listing the record for port ``bp``, which is
on the same subnet as ``ap``, and see that it is the same record as before::

  $ sudo ovn-nbctl list dhcp_options bp | abbrev
  _uuid               : a7de4a
  cidr                : "10.1.1.0/24"
  external_ids        : {"neutron:network_id"="68cb3a", "neutron:revision_number"="0", subnet_id="a375e9"}
  options             : {classless_static_route="{169.254.169.254/32,10.1.1.2, 0.0.0.0/0,10.1.1.1}", dns_server="{8.8.8.8}", domain_name="\"openstackgate.local\"", lease_time="43200", mtu="1442", router="10.1.1.1", server_id="10.1.1.1", server_mac="fa:16:3e:27:21:15"}

You can take another look at the southbound flow table if you like,
but the best demonstration is to trace a DHCP packet.  The following
is a trace of a DHCP request inbound from ``ap``.  The first part is
just the usual travel through the port security check and the ACL
evaluation::

  $ sudo ovn-trace n1 'inport == "ap" && eth.src == '$AP_MAC' && eth.dst == ff:ff:ff:ff:ff:ff && ip4.dst == 255.255.255.255 && udp.src == 68 && udp.dst == 67 && ip.ttl == 1'
  ...
  ingress(dp="n1", inport="ap")
  -----------------------------
   0. ls_in_check_port_sec (northd.c:10254): 1, priority 50, uuid 9f12c419
      reg0[15] = check_in_port_sec();
      next;
   5. ls_in_pre_acl (northd.c:6475): eth.mcast, priority 110, uuid c527dd21
      next;
   6. ls_in_pre_lb (northd.c:6614): eth.mcast, priority 110, uuid 93c37b59
      next;
   8. ls_in_acl_hint (northd.c:6843): !ct.trk, priority 5, uuid 4f8e902f
      reg0[8] = 1;
      reg0[9] = 1;
      next;
   9. ls_in_acl_eval (northd.c:7586): reg0[8] == 1 && (inport == @pg_a9fa0a9b_5c81_4462_a360_b154ea031dff && ip4), priority 2002, uuid 8579ab9d
      reg8[16] = 1;
      next;
  11. ls_in_acl_action (northd.c:7782): reg8[16] == 1, priority 1000, uuid 44123029
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  22. ls_in_acl_after_lb_action (northd.c:7804): 1, priority 0, uuid 723f4e46
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;

The next part is the interesting part.  In table 27, the special
``put_dhcp_opts`` action replaces a DHCPDISCOVER or DHCPREQUEST packet
by a reply.  Table 28 flips the packet's source and destination and
sends it back the way it came in::

  27. ls_in_dhcp_options (northd.c:9856): inport == "ap" && eth.src == fa:16:3e:ef:64:b6 && (ip4.src == {10.1.1.5, 0.0.0.0} && ip4.dst == {10.1.1.1, 255.255.255.255}) && udp.src == 68 && udp.dst == 67, priority 100, uuid be293a58
      reg0[3] = put_dhcp_opts(offerip = 10.1.1.5, classless_static_route = {169.254.169.254/32, 10.1.1.2, 0.0.0.0/0, 10.1.1.1}, dns_server = {8.8.8.8}, domain_name = "openstackgate.local", lease_time = 43200, mtu = 1442, netmask = 255.255.255.0, router = 10.1.1.1, server_id = 10.1.1.1);
      /* We assume that this packet is DHCPDISCOVER or DHCPREQUEST. */
      next;
  28. ls_in_dhcp_response (northd.c:9878): inport == "ap" && eth.src == fa:16:3e:ef:64:b6 && ip4 && udp.src == 68 && udp.dst == 67 && reg0[3], priority 100, uuid 652299cb
      eth.dst = eth.src;
      eth.src = fa:16:3e:27:21:15;
      ip4.src = 10.1.1.1;
      udp.src = 67;
      udp.dst = 68;
      outport = inport;
      flags.loopback = 1;
      output;

Then the last part is just traveling back through the firewall to VM
``a``::

  egress(dp="n1", inport="ap", outport="ap")
  ------------------------------------------
   2. ls_out_pre_acl (northd.c:6499): ip, priority 100, uuid 0c984d09
      reg0[0] = 1;
      next;
   4. ls_out_pre_stateful (northd.c:6765): reg0[0] == 1, priority 100, uuid e8d6e468
      ct_next(dnat);

  ct_next(ct_state=est|trk /* default (use --ct to customize) */)
  ---------------------------------------------------------------
   5. ls_out_acl_hint (northd.c:6856): !ct.new && ct.est && !ct.rpl && ct_mark.blocked == 0, priority 4, uuid bd84dd49
      reg0[8] = 1;
      reg0[10] = 1;
      next;
   6. ls_out_acl_eval (northd.c:9905): outport == "ap" && eth.src == fa:16:3e:27:21:15 && ip4.src == 10.1.1.1 && udp && udp.src == 67 && udp.dst == 68, priority 34000, uuid 9a4b4716
      reg8[16] = 1;
      next;
   8. ls_out_acl_action (northd.c:7782): reg8[16] == 1, priority 1000, uuid 1ef90f41
      reg8[16] = 0;
      reg8[17] = 0;
      reg8[18] = 0;
      next;
  14. ls_out_check_port_sec (northd.c:6272): 1, priority 0, uuid f60d0449
      reg0[15] = check_out_port_sec();
      next;
  15. ls_out_apply_port_sec (northd.c:6279): 1, priority 0, uuid 7644229a
      output;
      /* output to "ap", type "" */

Further Directions
------------------

We've looked at a fair bit of how OVN works and how it interacts with
OpenStack.  If you still have some interest, then you might want to
explore some of these directions:

* Adding more than one hypervisor ("compute node", in OpenStack
  parlance).  OVN connects compute nodes by tunneling packets with the
  Geneve protocol.  OVN scales to 1000 compute nodes or more,
  but two compute nodes demonstrate the principle.  All of the tools
  and techniques we demonstrated also work with multiple compute
  nodes.

* Container support.  OVN supports seamlessly connecting VMs to
  containers, whether the containers are hosted on "bare metal" or
  nested inside VMs.  OpenStack support for containers, however, is
  still evolving, and too difficult to incorporate into the tutorial
  at this point.

* Other kinds of gateways.  In addition to floating IPs with NAT, OVN
  supports directly attaching VMs to a physical network and connecting
  logical switches to VTEP hardware.
