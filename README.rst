.. NOTE(stephenfin): If making changes to this file, ensure that the line
   numbers found in 'Documentation/intro/what-is-ovs' are kept up-to-date.

===
OVN
===

What is OVN?
---------------------

OVN (Open Virtual Network) is a series of daemons that translates virtual
network configuration into OpenFlow, and installs them into Open vSwitch.
It is licensed under the open source Apache 2 license.

OVN provides a higher-layer abstraction then Open vSwitch, working with logical
routers and logical switches, rather than flows. OVN is intended to be used by
cloud management software (CMS). For details about the architecture of OVN, see
the ovn-architecture manpage. Some high-level features offered by OVN include:

* Distributed virtual routers
* Distributed logical switches
* Access Control Lists
* DHCP
* DNS server

Like Open vSwitch, OVN is written in platform-independent C. OVN runs entirely
in userspace and therefore requires no kernel modules to be installed.

Until recently, OVN code lived within the Open vSwitch codebase. OVN has
recently been split into its own repo. There is much to do to complete this
split entirely. See the TODO_SPLIT.rst file for a list of known tasks that
need to be completed.

What's here?
------------

The main components of this distribution are:

- ovn-northd, a centralized daemon that translates northbound configuration
  from a CMS into logical flows for the southbound database.
- ovn-controller, a daemon that runs on every hypervisor in the cluster. It
  translates the logical flows in the southbound database into OpenFlow for
  Open vSwitch. It also handles certain traffic, such as DHCP and DNS.
- ovn-nbctl, a tool for interfacing with the northbound database.
- ovn-sbctl, a tool for interfacing with the southbound database.
- ovn-trace, a debugging utility that allows for tracing of packets through
  the logical network.
- Scripts and specs for building RPMs.

What other documentation is available?
--------------------------------------

.. TODO(stephenfin): Update with a link to the hosting site of the docs, once
   we know where that is

To install OVN on a regular Linux or FreeBSD host, please read the
`installation guide <Documentation/intro/install/general.rst>`__. For specifics
around installation on a specific platform, refer to one of the `other
installation guides <Documentation/intro/install/index.rst>`__

For answers to common questions, refer to the `FAQ <Documentation/faq>`__.

To learn about some advanced features of the Open vSwitch software switch, read
the tutorial_.

.. _tutorial: https://github.com/openvswitch/ovs/blob/master/Documentation/tutorials/ovs-advanced.rst

Each OVN program is accompanied by a manpage.  Many of the manpages are customized
to your configuration as part of the build process, so we recommend building OVN
before reading the manpages.

License
-------

The following is a summary of the licensing of files in this distribution.
As mentioned, OVN is licensed under the open source Apache 2 license. Some
files may be marked specifically with a different license, in which case that
license applies to the file in question.

File build-aux/cccl is licensed under the GNU General Public License, version 2.

Files under the xenserver directory are licensed on a file-by-file basis.
Refer to each file for details.

Contact
-------

bugs@openvswitch.org
