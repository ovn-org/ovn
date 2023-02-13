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

============
OVN Upgrades
============

Since OVN is a distributed system, special consideration must be given to
the process used to upgrade OVN across a deployment.  This document discusses
the two recommended `Upgrade procedures`_, `Rolling upgrade`_ and `Fail-safe
upgrade`_.

Which one to choose depends on whether you are running a version of OVN that is
within range of upstream support for upgrades to the version of OVN you want to
upgrade to.

Release Notes
-------------

You should always check the OVS and OVN release notes (NEWS file) for any
release specific notes on upgrades.

OVS
---

OVN depends on and is included with OVS.  It's expected that OVS and OVN are
upgraded together, partly for convenience.  OVN is included in OVS releases
so it's easiest to upgrade them together.  OVN may also make use of new
features of OVS only available in that release.

Upgrade procedures
------------------

Rolling upgrade
~~~~~~~~~~~~~~~

1. `Upgrade ovn-controller`_

2. `Upgrade OVN Databases and ovn-northd`_

3. `Upgrade OVN Integration`_

In order to successfully perform a rolling upgrade, the ovn-controller process
needs to understand the structure of the database for the version you are
upgrading from and to simultaneously.

To avoid buildup of complexity and technical debt we limit the span of versions
supported for a rolling upgrade on :ref:`long-term-support` (LTS), and it
should always be possible to upgrade from the previous LTS version to the next.

The first LTS version of OVN was 22.03.  If you want to upgrade between other
versions, you can use the `Fail-safe upgrade`_ procedure.

Fail-safe upgrade
~~~~~~~~~~~~~~~~~

1. Upgrade to the most recent point release or package version available for
   the major version of OVN you are upgrading from.

2. Enable the version pinning feature in the ovn-controller by setting the
   ``external_ids:ovn-match-northd-version`` flag to 'true' as documented in
   the `ovn-controller man page`_.

3. If the version of OVN you are upgrading from does not have the `version
   pinning check in the incremental processing engine`_, you must stop
   ovn-northd and manually change the northd_internal_version to ensure the
   controllers go into fail-safe mode before processing changes induced by the
   upgrade.

    $ sudo /usr/share/ovn/scripts/ovn-ctl stop_northd --ovn-manage-ovsdb=no
    $ sudo ovn-sbctl set sb-global . options:northd_internal_version="foo"

4. `Upgrade OVN Databases and ovn-northd`_

5. `Upgrade ovn-controller`_

6. `Upgrade OVN Integration`_

When upgrading between a span of versions that is not supported, you may be at
risk for the new ovn-controller process not understanding the structure of the
old database, which may lead to data plane downtime for running instances.

To avoid this there is a fail safe approach, which involves making the
ovn-controller process refrain from making changes to the local flow state when
a version mismatch between the ovn-controller and ovn-northd is detected.

Steps
-----

This section documents individual steps in a upgrade procedure in no particular
order.  For information on ordering of the steps, please refer to the `Upgrade
procedures`_ section.

Upgrade ovn-controller
~~~~~~~~~~~~~~~~~~~~~~

You should start by upgrading ovn-controller on each host it's running on.
First, you upgrade the OVS and OVN packages.  Then, restart the
ovn-controller service.  You can restart with ovn-ctl::

    $ sudo /usr/share/ovn/scripts/ovn-ctl restart_controller

or with systemd::

    $ sudo systemd restart ovn-controller

Upgrade OVN Databases and ovn-northd
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The OVN databases and ovn-northd should be upgraded next.  Since ovn-controller
has already been upgraded, it will be ready to operate on any new functionality
specified by the database or logical flows created by ovn-northd.

Upgrading the OVN packages installs everything needed for an upgrade.  The only
step required after upgrading the packages is to restart ovn-northd, which
automatically restarts the databases and upgrades the database schema, as well.

You may perform this restart using the ovn-ctl script::

    $ sudo /usr/share/ovn/scripts/ovn-ctl restart_northd

or if you're using a Linux distribution with systemd::

    $ sudo systemctl restart ovn-northd

In case your deployment utilizes OVN Interconnection (OVN IC) functionality,
it is also needed to restart ovn-ic daemons and separately restart ovn-ic
databases.

You may perform this restart using the ovn-ctl script::

    $ sudo /usr/share/openvswitch/scripts/ovn-ctl restart_ic
    $ sudo /usr/share/openvswitch/scripts/ovn-ctl restart_ic_ovsdb

or if you're using a Linux distribution with systemd::

    $ sudo systemctl restart ovn-ic
    $ sudo systemctl restart ovn-ic-db

Schema Change
+++++++++++++

During database upgrading, if there is schema change, the DB file will be
converted to the new schema automatically, if the schema change is backward
compatible.  OVN tries the best to keep the DB schemas backward compatible.

However, there can be situations that an incompatible change is reasonble.  An
example of such case is to add constraints in the table to ensure correctness.
If there were already data that violates the new constraints got added somehow,
it will result in DB upgrade failures.  In this case, user should manually
correct data using ovn-nbctl (for north-bound DB) or ovn-sbctl (for south-
bound DB), and then upgrade again following previous steps.  Below is a list
of known impactible schema changes and how to fix when error encountered.

#. Release 2.11: index [type, ip] added for Encap table of south-bound DB to
   prevent duplicated IPs being used for same tunnel type.  If there are
   duplicated data added already (e.g. due to improper chassis management),
   a convenient way to fix is to find the chassis that is using the IP
   with command::

    $ ovn-sbctl show

   Then delete the chassis with command::

    $ ovn-sbctl chassis-del <chassis>

#. Release 22.12: index [transit_switch, availability_zone, route_table,
   ip_prefix, nexthop] added for OVN Interconnection Southbound DB table Route.
   If there are duplicated records in this table, users are adviced to upgrade
   ovn-ic daemons in all availability zones first and after that convert OVS
   schema (restart ovn-ic database daemon).


Upgrade OVN Integration
~~~~~~~~~~~~~~~~~~~~~~~

Lastly, you may also want to upgrade integration with OVN that you may be
using.  For example, this could be the OpenStack Neutron driver or
ovn-kubernetes.

OVN's northbound database schema is a backwards compatible interface, so
you should be able to safely complete an OVN upgrade before upgrading
any integration in use.

.. LINKS
.. _ovn-controller man page:
   https://www.ovn.org/support/dist-docs/ovn-controller.8.html
.. _version pinning check in the incremental processing engine:
   https://github.com/ovn-org/ovn/commit/c2eeb2c98ea8
