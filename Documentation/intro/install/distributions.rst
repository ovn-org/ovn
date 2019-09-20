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

====================================
Distributions packaging Open vSwitch
====================================

This document lists various popular distributions packaging OVN.

.. note::
  The packaged version available with distributions may not be latest
  OVN release.

Debian
-------

You can use ``apt-get`` or ``aptitude`` to install the .deb packages and must
be superuser. Debian has ``ovn-common``, ``ovn-host``, ``ovn-central`` and
``ovn-vtep`` .deb packages.

Fedora
------

Fedora provides ``ovn``, ``ovn-host``, ``ovn-central``
and ``ovn-vtep`` rpm packages. Use ``yum`` or ``dnf`` to install
the rpm packages and must be superuser.

OpenSuSE
--------

OpenSUSE provides ``openvswitch-ovn-common``, ```openvswitch-ovn-host``,
```openvswitch-ovn-central`` and ```openvswitch-ovn-vtep`` rpm packages.
