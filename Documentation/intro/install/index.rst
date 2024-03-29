..
      Copyright (c) 2016, Stephen Finucane <stephen@that.guru>

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

=====================================
Installing Open Virtual Network (OVN)
=====================================

A collection of guides detailing how to install OVN in a variety of
different environments and using different configurations.

Installation from Source
------------------------

.. TODO(stephenfin): Based on the title alone, the NetBSD doc should probably
   be merged into the general install doc

.. toctree::
   :maxdepth: 2

   general
   windows

Installation from Packages
--------------------------

OVN is packaged on a variety of distributions. The tooling required to
build these packages is included in the OVN tree. The instructions are
provided below.

.. toctree::
   :maxdepth: 2

   distributions
   debian
   fedora

Upgrades
--------

.. toctree::
   :maxdepth: 2

   ovn-upgrades

Others
------

.. toctree::
   :maxdepth: 2

   documentation
