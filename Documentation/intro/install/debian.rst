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

============================================
Debian/Ubuntu Packaging for OVN
============================================

This document provides instructions for installing OVN on Debian and
Ubuntu, either from distribution packages or by building ``.deb``
packages from source.  Instructions for installing OVN from source
without packaging can be found in the :doc:`general`.

The steps below are practically the same for Debian and Ubuntu.

Installing from Packages
------------------------

Debian and Ubuntu provide pre-built OVN packages.  You can install them
using ``apt-get`` as superuser.

For a central node (runs OVN databases, ovn-northd and ovn-ic)::

    $ sudo apt-get install ovn-central

For each host/hypervisor (runs ovn-controller)::

    $ sudo apt-get install ovn-host

Additional packages::

    $ sudo apt-get install ovn-common              # shared components
    $ sudo apt-get install ovn-controller-vtep     # VTEP gateway support

.. note::
  The packaged version available in distributions may not be the latest
  OVN release.

Building .deb Packages from Source
----------------------------------

Build Requirements
~~~~~~~~~~~~~~~~~~

Install the standard Debian packaging tools and the OVN build
dependencies.  On Debian/Ubuntu::

    $ sudo apt-get install build-essential fakeroot devscripts
    $ sudo apt-get install graphviz autoconf automake bzip2 \
        debhelper dh-autoreconf dh-python libssl-dev libtool \
        openssl procps python3-all python3-sphinx \
        python3-twisted python3-zope.interface \
        libunbound-dev libunwind-dev

The second set of packages corresponds to the ``Build-Depends``
list in the ``debian/control`` file of the OVN source tree.

Bootstrapping
~~~~~~~~~~~~~

Refer to :ref:`general-bootstrapping`.

Configuring
~~~~~~~~~~~

Refer to :ref:`general-configuring`.

The Debian build rules configure OVN with ``--enable-ssl``,
``--enable-shared``, and ``--with-ovs-source``.  If you are building
manually, make sure to prepare the OVS sources first as described in the
bootstrapping section.

Building
~~~~~~~~

The ``OVSDIR`` environment variable must point to a fully configured
and built OVS source tree (i.e., one where ``./boot.sh``,
``./configure``, and ``make`` have been run) before building the
packages::

    $ export OVSDIR=/path/to/built/ovs

You can then build the ``.deb`` packages using ``dpkg-buildpackage``::

    $ dpkg-buildpackage -us -uc

Or using debuild::

    $ debuild -us -uc

Both methods use the ``debian/rules`` file which takes care of
configuring, building, and packaging.

This produces the following ``.deb`` packages:

- ``ovn-common``: Shared OVN components (ovn-nbctl, ovn-sbctl,
  ovn-trace, ovn-appctl, ovn-detrace, ovn-ctl, man pages).
- ``ovn-central``: OVN DB servers, ovn-northd and ovn-ic for the
  central node.
- ``ovn-host``: ovn-controller for each host/hypervisor.
- ``ovn-controller-vtep``: ovn-controller-vtep for VTEP gateways.

Installing
~~~~~~~~~~

Install the packages using ``dpkg``::

    $ sudo dpkg -i ovn-common_*.deb
    $ sudo dpkg -i ovn-central_*.deb     # on central node
    $ sudo dpkg -i ovn-host_*.deb        # on each host

.. note::
  ``dpkg`` does not automatically resolve dependencies.  If you
  encounter dependency errors, run ``sudo apt-get install -f``
  to install the missing dependencies.

Reporting Bugs
--------------

Report problems to https://github.com/ovn-org/ovn/issues or
discuss@openvswitch.org.
