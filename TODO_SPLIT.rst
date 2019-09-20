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

========================
OVN/OVS Split To-do List
========================

Immediate tasks
---------------------------

* There are likely many unused files throughout the source tree
  since they pertain to OVS rather than OVN. These can also be removed from the
  repo.

* Someone with a decent ability to write should give the README.rst file some
  polish (or even just rewrite it. I won't be offended).

* Cleanup the acinclude.m4 and m4 folder

Immediate to Short-term tasks
-----------------------------

* The Documentation/ directory can use an overhaul. Non-OVN content can be
  removed. The installation guide and tutorials should be reworked to be
  geared towards OVN specifically instead of OVS.

* The tests/ directory contains copies of all "utility" files from the ovs
  repo. These files could be removed in favor of using the files directly
  from the ovs repo instead of the copy. As an example, ofproto-macros.at could
  be removed from the tests/ directory, and we could reference the version in
  the ovs repo instead. There are many other files that this could be done with.

* The ovs-sandbox is in a similar state to the tests directory. That is, the
  tutorial/ directory contains a copy of the ovs-sandbox script. Rather than
  copying the script wholesale, it probably makes more sense to refer to the
  ovs version of the script from the ovn repo. Running the sandbox should
  also be altered so that the base ovs-sandbox script doesn't do anything
  ovn-related. Rather, the ovn repo can start the sandbox by calling into
  ovs and then start the ovn parts after.

* OVN code needs to be removed from the OVS repo. This should be mostly
  straightforward with a couple of exceptions. There is an include/ovn/
  directory in the ovs repo that should be moved to the ovn repo instead of
  being removed. The other challenge is updating the ovsdb clustering tests.
  They currently make use of the OVN database schemas. They will need to be
  updated not to rely on something from OVN.

* The rhel/ and debian/ directories need updating and testing so that they can
  build ovn. They also need to be modified so that they no longer can build ovs
  packages.

Short to Medium-term tasks
--------------------------

* There are several non-code subdirectories in the ovn repo that have not
  been updated from how they existed in the OVS repo. It should be evaluated
  if there is potential use to modify these to be useful for OVN or if they
  should just be removed. Examples include the poc/ and xenserver/ directories.

Medium to Long-term tasks
-------------------------

* The goal is to eventually not require having ovs as a subtree in the ovn
  repo. Using variables in Makefiles goes a short way towards realizing
  this goal, but it only partially gets us there. We still
  refer to the ovs subtree directly in certain areas, most notably the
  tests/ directory. Getting rid of the ovs subtree can be thought of as a
  two-step process:

  1) Remove all direct references to the ovs subtree from the build system. By
  doing this, it will be possible to have an ovs source repo checked out at
  some other location and have ovn refer to that by using variables.

  2) Alter ovs's build so that it places headers, utilities, etc. in known
  locations on disk when it installs. This way, rather than referring to
  an ovs source repo, we can refer to installation directories in the ovn
  build system. This way, it could be possible to build ovn just by installing
  the development package of ovs as a prerequisite.

* A plan needs to be developed for compatibility between OVN and OVS. There
  are several facets to this

  1) We need to try to determine a policy with regards to what OVS versions
  OVN will be compatible with.

  2) The ovs subtree in ovn currently is the master branch of ovs at the time
  that the ovn repo was split off. It likely will result in a more stable
  environment to use a released version of ovs as our basis instead of an
  arbitrary commit from mid-release.

  3) While ovn was housed in the ovs repo, it was sometimes necessary to
  update ovs or ovsdb code in order to facilitate a new ovn feature. Or it
  might be necessary to fix a bug in ovs in order to fix a bug in ovn. With ovn
  split away, there needs to be a way that ovn developers can contribute changes
  to ovs when necessary but also not have to wait for those changes to be
  available in an ovs release to be able to use them in ovn.
