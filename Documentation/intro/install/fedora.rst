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
Fedora, RHEL 8.x+ Packaging for OVN
======================================

This document provides instructions for installing OVN on Fedora,
RHEL 8.x and later, and CentOS Stream, either from distribution
packages or by building RPM packages from source.  Instructions for
installing OVN from source without packaging can be found in the
:doc:`general`.

Installing from Packages
-------------------------

Fedora provides ``ovn``, ``ovn-central``, ``ovn-host``,
``ovn-vtep``, and ``ovn-br-controller`` RPM packages.  Use ``dnf``
to install them as superuser.

For a central node (runs OVN databases and ovn-northd)::

    $ sudo dnf install ovn-central

For each host/hypervisor (runs ovn-controller)::

    $ sudo dnf install ovn-host

Additional packages::

    $ sudo dnf install ovn                 # shared components
    $ sudo dnf install ovn-vtep            # VTEP gateway support
    $ sudo dnf install ovn-br-controller   # bridge controller

For RHEL and CentOS Stream, the OVN packages may be available through
EPEL or the distribution's own repositories.

.. note::
  The packaged version available in distributions may not be the latest
  OVN release.

Building RPM Packages from Source
---------------------------------

Build Requirements
~~~~~~~~~~~~~~~~~~

Install RPM tools and generic build dependencies::

    $ sudo dnf install @'Development Tools' rpm-build dnf-plugins-core

Then install OVN-specific build dependencies.  The dependencies are
listed in the SPEC file, but first it is necessary to replace the
VERSION tag to be a valid SPEC.

The command below will create a temporary SPEC file::

    $ sed -e 's/@VERSION@/0.0.1/' rhel/ovn-fedora.spec.in \
      > /tmp/ovn.spec

And to install the specific dependencies::

    $ sudo dnf builddep /tmp/ovn.spec

Once that is completed, remove the file ``/tmp/ovn.spec``.

Bootstrapping
~~~~~~~~~~~~~

Refer to :ref:`general-bootstrapping`.

Configuring
~~~~~~~~~~~

Refer to :ref:`general-configuring`.

Building
~~~~~~~~

To build OVN RPMs, first generate the OVS source tarball in the OVS
source directory (the OVS submodule must be built first, as described
in :ref:`general-bootstrapping`)::

    $ make -C ovs dist

Then execute the following from the OVN source directory (in which
``./configure`` was executed)::

    $ make rpm-fedora

This will create the RPMs ``ovn``, ``ovn-central``, ``ovn-host``,
``ovn-vtep``, ``ovn-docker``, and ``ovn-br-controller``, along with
their debuginfo variants.

You can also have the above commands automatically run the OVN unit
tests.  This can take several minutes::

    $ make rpm-fedora RPMBUILD_OPT="--with check"

Installing
~~~~~~~~~~

RPM packages can be installed by using the command ``rpm -i``.
Package installation requires superuser privileges::

    $ sudo rpm -i ovn-*.rpm

Or install specific packages::

    $ sudo rpm -i ovn-<version>.rpm              # shared components
    $ sudo rpm -i ovn-central-<version>.rpm      # on central node
    $ sudo rpm -i ovn-host-<version>.rpm         # on each host

Reporting Bugs
--------------

Report problems to https://github.com/ovn-org/ovn/issues or
discuss@openvswitch.org.
