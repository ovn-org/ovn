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
OVN on Linux, FreeBSD and NetBSD
=========================================

This document describes how to build and install OVN on a generic
Linux, FreeBSD, or NetBSD host. For specifics around installation on a specific
platform, refer to one of the other installation guides listed in :doc:`index`.

Obtaining OVN Sources
---------------------

The canonical location for OVN source code is its Git
repository, which you can clone into a directory named "ovn" with::

    $ git clone https://github.com/ovn-org/ovn.git

Cloning the repository leaves the "master" branch initially checked
out.  This is the right branch for general development.
If, on the other hand, if you want to build a particular released
version, you can check it out by running a command such as the
following from the "ovn" directory::

    $ git checkout v20.09.0

The repository also has a branch for each release series.  For
example, to obtain the latest fixes in the OVN 20.09.x release series,
which might include bug fixes that have not yet been in any released
version, you can check it out from the "ovn" directory with::

    $ git checkout origin/branch-20.09

If you do not want to use Git, you can also obtain tarballs for `OVN
release versions <https://www.ovn.org/en/releases/>`, or download a
ZIP file for any snapshot from the `GitHub web interface
<https://github.com/ovn-org/ovn>`.

.. _general-build-reqs:

Build Requirements
------------------

To compile the userspace programs in the OVN distribution, you will
need the following software:

- Open vSwitch (https://docs.openvswitch.org/en/latest/intro/install/).
  Open vSwitch is included as a submodule in the OVN source code. It is
  kept at the minimum recommended version for OVN to build and operate
  optimally.  See below for instructions about how to use a different OVS
  source location.

  .. note::

     These OVS sources used as a set of libraries to build OVN binaries, so
     OVS submodule is only recommended to build OVN and *not recommended*
     to be used as a source for OVS build.  To actually build/run OVS binaries
     (``ovs-vswitchd``, ``ovsdb-server``) use `released versions of
     Open vSwitch <https://www.openvswitch.org/download/>`_ or packages
     provided in your distribution.

- GNU make

- One of the following C compilers:

  - GCC 4.6 or later.

  - Clang 3.4 or later.

  - MSVC 2013. Refer to :doc:`windows` for additional Windows build
    instructions.

- libssl, from OpenSSL, is optional but recommended if you plan to connect the
  OVN services to the OVN DB ovsdb-servers securely. If libssl is installed,
  then OVN will automatically build with support for it.

- Unbound library, from http://www.unbound.net, is optional but recommended if
  you want to enable ovn-northd, ovn-controller and other utilities to use
  DNS names when specifying OVSDB remotes. If unbound library is already
  installed, then OVN will automatically build with support for it.
  The environment variable OVS_RESOLV_CONF can be used to specify DNS server
  configuration file (the default file on Linux is /etc/resolv.conf).

- `DDlog <https://github.com/vmware/differential-datalog>`, if you
  want to build ``ovn-northd-ddlog``, an alternate implementation of
  ``ovn-northd`` that scales better to large deployments.  The NEWS
  file specifies the right version of DDlog to use with this release.
  Building with DDlog supports requires Rust to be installed (see
  https://www.rust-lang.org/tools/install).

If you are working from a Git tree or snapshot (instead of from a distribution
tarball), or if you modify the OVN build system or the database
schema, you will also need the following software:

- Autoconf version 2.63 or later.

- Automake version 1.10 or later.

- libtool version 2.4 or later. (Older versions might work too.)

The OVN manpages will include an E-R diagram, in formats
other than plain text, only if you have the following:

- dot from graphviz (http://www.graphviz.org/).

If you are going to extensively modify OVN, consider installing the
following to obtain better warnings:

- "sparse" version 0.5.1 or later
  (https://git.kernel.org/pub/scm/devel/sparse/sparse.git/).

- GNU make.

- clang, version 3.4 or later

- flake8 along with the hacking flake8 plugin (for Python code). The automatic
  flake8 check that runs against Python code has some warnings enabled that
  come from the "hacking" flake8 plugin. If it's not installed, the warnings
  just won't occur until it's run on a system with "hacking" installed.

You may find the ovs-dev script found in ``ovs/utilities/ovs-dev.py`` useful.

.. _general-install-reqs:

Installation Requirements
-------------------------

The machine you build OVN on may not be the one you run it on.
To simply install and run OVN you require the following software:

- Shared libraries compatible with those used for the build.

On Linux you should ensure that ``/dev/urandom`` exists. To support TAP
devices, you must also ensure that ``/dev/net/tun`` exists.

.. _general-bootstrapping:

Bootstrapping
-------------

This step is not needed if you have downloaded a released tarball. If
you pulled the sources directly from an OVN Git tree or got a Git tree
snapshot, then run boot.sh in the top source directory to build
the "configure" script::

    $ ./boot.sh

Before configuring OVN, prepare Open vSwitch sources. The easiest way to do
this is to use the included OVS submodule in the OVN source tree::

    $ git submodule update --init
    $ cd ovs
    $ ./boot.sh
    $ ./configure
    $ make
    $ cd ..

It is not required to build with the included OVS submodule; however the OVS
submodule is guaranteed to include minimum recommended version of OVS libraries
to ensure OVN's build and optimal operation. If you wish to build with OVS
source code from a different location on the file system, then be sure to
configure and build it before building OVN.

.. _general-configuring:

Configuring
-----------

Then configure the package by running the configure script::

    $ ./configure

If your OVS source directory is not the included OVS submodule, specify the
location of the OVS source code using --with-ovs-source::

    $ ./configure --with-ovs-source=/path/to/ovs/source

If you have built Open vSwitch in a separate directory from its source
code, then you need to provide that path in the option - --with-ovs-build.

By default all files are installed under ``/usr/local``. OVN expects to find
its database in ``/usr/local/etc/ovn`` by default.
If you want to install all files into, e.g., ``/usr`` and ``/var`` instead of
``/usr/local`` and ``/usr/local/var`` and expect to use ``/etc/ovn`` as
the default database directory, add options as shown here::

    $ ./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc

.. note::

  OVN installed with packages like .rpm (e.g. via
  ``yum install`` or ``rpm -ivh``) and .deb (e.g. via
  ``apt-get install`` or ``dpkg -i``) use the above configure options.

To build with DDlog support, add ``--with-ddlog=<path to ddlog>/lib``
to the ``configure`` command line.  Building with DDLog adds a few
minutes to the build because the Rust compiler is slow.  To speed this
up by about 2x, also add ``--enable-ddlog-fast-build``.  This disables
some Rust compiler optimizations, making a much slower
``ovn-northd-ddlog`` executable, so it should not be used for
production builds or for profiling.

By default, static libraries are built and linked against. If you want to use
shared libraries instead::

    $ ./configure --enable-shared

To use a specific C compiler for compiling Open vSwitch user programs, also
specify it on the configure command line, like so::

    $ ./configure CC=gcc-4.2

To use 'clang' compiler::

    $ ./configure CC=clang

To supply special flags to the C compiler, specify them as ``CFLAGS`` on the
configure command line. If you want the default CFLAGS, which include ``-g`` to
build debug symbols and ``-O2`` to enable optimizations, you must include them
yourself. For example, to build with the default CFLAGS plus ``-mssse3``, you
might run configure as follows::

    $ ./configure CFLAGS="-g -O2 -mssse3"

For efficient hash computation special flags can be passed to leverage built-in
intrinsics. For example on X86_64 with SSE4.2 instruction set support, CRC32
intrinsics can be used by passing ``-msse4.2``::

    $ ./configure CFLAGS="-g -O2 -msse4.2"`

Also builtin popcnt instruction can be used to speedup the counting of the
bits set in an integer. For example on X86_64 with POPCNT support, it can be
enabled by passing ``-mpopcnt``::

    $ ./configure CFLAGS="-g -O2 -mpopcnt"`

If you are on a different processor and don't know what flags to choose, it is
recommended to use ``-march=native`` settings::

    $ ./configure CFLAGS="-g -O2 -march=native"

With this, GCC will detect the processor and automatically set appropriate
flags for it. This should not be used if you are compiling OVS outside the
target machine.

.. note::
  CFLAGS are not applied when building the Linux kernel module. Custom CFLAGS
  for the kernel module are supplied using the ``EXTRA_CFLAGS`` variable when
  running make. For example::

      $ make EXTRA_CFLAGS="-Wno-error=date-time"

If you are a developer and want to enable Address Sanitizer for debugging
purposes, at about a 2x runtime cost, you can add
``-fsanitize=address -fno-omit-frame-pointer -fno-common`` to CFLAGS.  For
example::

    $ ./configure CFLAGS="-g -O2 -fsanitize=address -fno-omit-frame-pointer -fno-common"

To build the Linux kernel module, so that you can run the kernel-based switch,
pass the location of the kernel build directory on ``--with-linux``. For
example, to build for a running instance of Linux::

    $ ./configure --with-linux=/lib/modules/$(uname -r)/build

.. note::
  If ``--with-linux`` requests building for an unsupported version of Linux,
  then ``configure`` will fail with an error message. Refer to the
  :doc:`/faq/index` for advice in that case.

If you plan to do much OVN development, you might want to add
``--enable-Werror``, which adds the ``-Werror`` option to the compiler command
line, turning warnings into errors. That makes it impossible to miss warnings
generated by the build. For example::

    $ ./configure --enable-Werror

If you're building with GCC, then, for improved warnings, install ``sparse``
(see "Prerequisites") and enable it for the build by adding
``--enable-sparse``.  Use this with ``--enable-Werror`` to avoid missing both
compiler and ``sparse`` warnings, e.g.::

    $ ./configure --enable-Werror --enable-sparse

To build with gcov code coverage support, add ``--enable-coverage``::

    $ ./configure --enable-coverage

The configure script accepts a number of other options and honors additional
environment variables. For a full list, invoke configure with the ``--help``
option::

    $ ./configure --help

You can also run configure from a separate build directory. This is helpful if
you want to build OVN in more than one way from a single source
directory, e.g. to try out both GCC and Clang builds. For example::

    $ mkdir _gcc && (cd _gcc && ./configure CC=gcc)
    $ mkdir _clang && (cd _clang && ./configure CC=clang)

Under certain loads the ovsdb-server and other components perform better when
using the jemalloc memory allocator, instead of the glibc memory allocator. If
you wish to link with jemalloc add it to LIBS::

    $ ./configure LIBS=-ljemalloc

Example usage::
    $ # Clone OVS repo
    $cd /home/foo/ovs
    $./boot.sh
    $mkdir _gcc
    $cd _gcc && ../configure && cd ..
    $make -C _gcc

    $ # Clone OVN repo
    $cd /home/foo/ovn
    $./boot.sh
    $./configure --with-ovs-source=/home/foo/ovs/ --with-ovs-build=/home/foo/ovs/_gcc

It is expected to configure both Open vSwitch and OVN with the same prefix.

.. _general-building:

Building
--------

1. Run GNU make in the build directory, e.g.::

       $ make

   or if GNU make is installed as "gmake"::

       $ gmake

   If you used a separate build directory, run make or gmake from that
   directory, e.g.::

       $ make -C _gcc
       $ make -C _clang

   .. note::
     Some versions of Clang and ccache are not completely compatible. If you
     see unusual warnings when you use both together, consider disabling
     ccache.

2. Consider running the testsuite. Refer to :doc:`/topics/testing` for
   instructions.

3. Run ``make install`` to install the executables and manpages into the
   running system, by default under ``/usr/local``::

       $ make install

.. _general-starting:

Starting
--------

Before starting the OVN, start the Open vSwitch daemons. Refer to the
Open vSwitch documentation for more details on how to start OVS.

On Unix-alike systems, such as BSDs and Linux, starting the OVN
suite of daemons is a simple process.  OVN includes a shell script,
called ovn-ctl which automates much of the tasks for starting
and stopping ovn-northd, ovn-controller and ovsdb-servers. After installation,
the daemons can be started by using the ovn-ctl utility.  This will take care
to setup initial conditions, and start the daemons in the correct order.
The ovn-ctl utility is located in '$(pkgdatadir)/scripts', and defaults to
'/usr/local/share/ovn/scripts'.  ovn-ctl utility requires the 'ovs-lib'
helper shell script which is present in '/usr/local/share/openvswitch/scripts'.
So invoking ovn-ctl as "./ovn-ctl" will fail.

An example after install might be::

    $ export PATH=$PATH:/usr/local/share/ovn/scripts
    $ ovn-ctl start_northd
    $ ovn-ctl start_controller

If you built with DDlog support, then you can start
``ovn-northd-ddlog`` instead of ``ovn-northd`` by adding
``--ovn-northd-ddlog=yes``, e.g.::

    $ export PATH=$PATH:/usr/local/share/ovn/scripts
    $ ovn-ctl --ovn-northd-ddlog=yes start_northd
    $ ovn-ctl start_controller

Starting OVN Central services
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

OVN central services includes ovn-northd, Northbound and
Southbound ovsdb-server.

    $ export PATH=$PATH:/usr/local/share/ovn/scripts
    $ ovn-ctl start_northd

Refer to ovn-ctl(8) for more information and the supported options.

You may wish to manually start the OVN central daemons.
Before starting ovn-northd you need to start OVN Northbound and Southbound
ovsdb-servers. Before ovsdb-servers can be started,
configure the Northbound and Southbound databases::

       $ mkdir -p /usr/local/etc/ovn
       $ ovsdb-tool create /usr/local/etc/ovn/ovnnb_db.db \
         ovn-nb.ovsschema
       $ ovsdb-tool create /usr/local/etc/ovn/ovnsb_db.db \
         ovn-sb.ovsschema

Configure ovsdb-servers to use databases created above, to listen on a Unix
domain socket and to use the SSL configuration in the database::

   $ mkdir -p /usr/local/var/run/ovn
   $ ovsdb-server /usr/local/etc/ovn/ovnnb_db.db --remote=punix:/usr/local/var/run/ovn/ovnnb_db.sock \
        --remote=db:OVN_Northbound,NB_Global,connections \
        --private-key=db:OVN_Northbound,SSL,private_key \
        --certificate=db:OVN_Northbound,SSL,certificate \
        --bootstrap-ca-cert=db:OVN_Northbound,SSL,ca_cert \
        --pidfile=/usr/local/var/run/ovn/ovnnb-server.pid --detach --log-file=/usr/local/var/log/ovn/ovnnb-server.log
   $ ovsdb-server /usr/local/etc/ovn/ovnsb_db.db --remote=punix:/usr/local/var/run/ovn/ovnsb_db.sock \
        --remote=db:OVN_Southbound,SB_Global,connections \
        --private-key=db:OVN_Southbound,SSL,private_key \
        --certificate=db:OVN_Southbound,SSL,certificate \
        --bootstrap-ca-cert=db:OVN_Southbound,SSL,ca_cert \
        --pidfile=/usr/local/var/run/ovn/ovnsb-server.pid --detach --log-file=/usr/local/var/log/ovn/ovnsb-server.log

.. note::
  If you built OVN without SSL support, then omit ``--private-key``,
  ``--certificate``, and ``--bootstrap-ca-cert``.)

Initialize the databases using ovn-nbctl and ovn-sbctl. This is only necessary
the first time after you create the databases with ovsdb-tool, though running
it at any time is harmless::

    $ ovn-nbctl --no-wait init
    $ ovn-sbctl --no-wait init

Start ``ovn-northd``, telling it to connect to the OVN db servers same
Unix domain socket::

    $ ovn-northd --pidfile --detach --log-file

If you built with DDlog support, you can start ``ovn-northd-ddlog``
instead, the same way::

    $ ovn-northd-ddlog --pidfile --detach --log-file

Starting OVN Central services in containers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For OVN central node, we dont need to load ovs kernel modules on host.
Hence, OVN central containers OS need not depend on host OS.

Also we can leverage deploying entire OVN control plane in a pod spec for use
cases like OVN-kubernetes

Export following variables in .env  and place it under
project root::

    $ OVN_BRANCH=<BRANCH>
    $ OVN_VERSION=<VERSION>
    $ DISTRO=<LINUX_DISTRO>
    $ KERNEL_VERSION=<LINUX_KERNEL_VERSION>
    $ GITHUB_SRC=<GITHUB_URL>
    $ DOCKER_REPO=<REPO_TO_PUSH_IMAGE>

To build ovn modules::

    $ cd utilities/docker
    $ make build

Compiled Modules will be tagged with docker image

To Push ovn modules::

    $ make push

OVN docker image will be pushed to specified docker repo.

Start OVN containers using below command::

    $ docker run -itd --net=host --name=ovn-nb \
      <docker_repo>:<tag> ovn-nb-tcp

    $ docker run -itd --net=host --name=ovn-sb \
      <docker_repo>:<tag> ovn-sb-tcp

    $ docker run -itd --net=host --name=ovn-northd \
      <docker_repo>:<tag> ovn-northd-tcp

Start OVN containers in cluster mode for a 3 node cluster using below command
on node1::

    $ docker run -e "host_ip=<host_ip>" -e "nb_db_port=<port>" -itd \
      --name=ovn-nb-raft --net=host --privileged <docker_repo>:<tag> \
      ovn-nb-cluster-create

    $ docker run -e "host_ip=<host_ip>" -e "sb_db_port=<port>" -itd \
      --name=ovn-sb-raft --net=host --privileged <docker_repo>:<tag> \
      ovn-sb-cluster-create

    $ docker run -e "OVN_NB_DB=tcp:<node1>:6641,tcp:<node2>:6641,\
      tcp:<node3>:6641" -e "OVN_SB_DB=tcp:<node1>:6642,tcp:<node2>:6642,\
      tcp:<node3>:6642" -itd --name=ovn-northd-raft <docker_repo>:<tag> \
      ovn-northd-cluster

Start OVN containers in cluster mode using below command on node2 and node3 \
to make them join the peer using below command::

    $ docker run -e "host_ip=<host_ip>" -e "remote_host=<remote_host_ip>" \
      -e "nb_db_port=<port>" -itd --name=ovn-nb-raft --net=host \
      --privileged <docker_repo>:<tag> ovn-nb-cluster-join

    $ docker run -e "host_ip=<host_ip>" -e "remote_host=<remote_host_ip>" \
      -e "sb_db_port=<port>" -itd --name=ovn-sb-raft --net=host \
      --privileged <docker_repo>:<tag> ovn-sb-cluster-join

    $ docker run -e "OVN_NB_DB=tcp:<node1>:6641,tcp:<node2>:6641,\
      tcp:<node3>:6641" -e "OVN_SB_DB=tcp:<node1>:6642,tcp:<node2>:6642,\
      tcp:<node3>:6642" -itd --name=ovn-northd-raft <docker_repo>:<tag> \
      ovn-northd-cluster

Start OVN containers using unix socket::

    $ docker run -itd --net=host --name=ovn-nb \
      -v /var/run/ovn/:/var/run/ovn/ \
      <docker_repo>:<tag> ovn-nb

    $ docker run -itd --net=host --name=ovn-sb \
      -v /var/run/ovn/:/var/run/ovn/
      <docker_repo>:<tag> ovn-sb

    $ docker run -itd --net=host --name=ovn-northd \
      -v /var/run/ovn/:/var/run/ovn/
      <docker_repo>:<tag> ovn-northd

.. note::
    Current ovn central components comes up in docker image in a standalone
    and cluster mode with protocol tcp.

    The debian docker file use ubuntu 16.04 as a base image for reference.

    User can use any other base image for debian, e.g. u14.04, etc.

    RHEL based docker support is now added with centos7 as a base image.

Starting OVN host service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On each chassis, ovn-controller service should be started.
ovn-controller assumes it gets configuration information from the
Open_vSwitch table of the local OVS instance. Refer to the
ovn-controller(8) for the configuration keys.

Below are the required keys to be configured on each chassis.

1. external_ids:system-id

2. external_ids:ovn-remote

3. external_ids:ovn-encap-type

4. external_ids:ovn-encap-ip

You may wish to manually start the ovn-controller service on each
chassis.

Start the ovn-controller, telling it to connect to the local ovsdb-server Unix
domain socket::

    $ ovn-controller --pidfile --detach --log-file

Starting OVN host service in containers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For OVN host too, we dont need to load ovs kernel modules on host.
Hence, OVN host container OS need not depend on host OS.

Also we can leverage deploying OVN host in a pod spec for use cases like
OVN-kubernetes to manage OVS which can be running as a service on host or in
container.

Start ovsdb-server and ovs-vswitchd components as per
http://docs.openvswitch.org/en/latest/intro/install/general/

start local ovn-controller with below command if ovs is also running in
container::

    $ docker run -itd --net=host --name=ovn-controller \
      --volumes-from=ovsdb-server \
      <docker_repo>:<tag> ovn-controller

start local ovn-controller with below command if ovs is running as a service::

    $ docker run -itd --net=host --name=ovn-controller \
      -v /var/run/openvswitch/:/var/run/openvswitch/ \
      <docker_repo>:<tag> ovn-controller

Validating
----------

At this point you can use ovn-nbctl on the central node to set up logical
switches and ports and other OVN logical entities. For example, to create a
logical switch ``sw0`` and add logical port ``sw0-p1`` ::

    $ ovn-nbctl ls-add sw0
    $ ovn-nbctl lsp-add sw0 sw0-p1
    $ ovn-nbctl show

Refer to ovn-nbctl(8) and ovn-sbctl (8) for more details.

When using ovn in container, exec to container to run above commands::

    $ docker exec -it <ovn-nb/ovn-sb/ovn-northd/ovn-controller> /bin/bash

Reporting Bugs
--------------

Report problems to bugs@openvswitch.org.
