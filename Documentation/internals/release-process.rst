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

===================
OVN Release Process
===================

This document describes the process ordinarily used for OVN development and
release.  Exceptions are sometimes necessary, so all of the statements here
should be taken as subject to change through rough consensus of OVN
contributors, obtained through public discussion on, e.g., ovs-dev or the
#openvswitch IRC channel.

Release Strategy
----------------

OVN feature development takes place on the "main" branch. Ordinarily, new
features are rebased against main and applied directly.  For features that
take significant development, sometimes it is more appropriate to merge a
separate branch into main; please discuss this on ovs-dev in advance.

The process of making a release has the following stages.  See `Release
Scheduling`_ for the timing of each stage:

1. "Soft freeze" of the main branch.

   During the freeze, we ask committers to refrain from applying patches that
   add new features unless those patches were already being publicly discussed
   and reviewed before the freeze began.  Bug fixes are welcome at any time.
   Please propose and discuss exceptions on ovs-dev.
 
2. Fork a release branch from main, named for the expected release number,
   e.g. "branch-2019.10" for the branch that will yield OVN 2019.10.x.

   Release branches are intended for testing and stabilization.  At this stage
   and in later stages, they should receive only bug fixes, not new features.
   Bug fixes applied to release branches should be backports of corresponding
   bug fixes to the main branch, except for bugs present only on release
   branches (which are rare in practice).

   At this stage, sometimes there can be exceptions to the rule that a release
   branch receives only bug fixes.  Like bug fixes, new features on release
   branches should be backports of the corresponding commits on the main
   branch.  Features to be added to release branches should be limited in scope
   and risk and discussed on ovs-dev before creating the branch.

   In order to keep the CI stable on the new release branch, the Ubuntu
   container should be pinned to the current LTS version in the Dockerfile
   e.g. registry.hub.docker.com/library/ubuntu:22.04.

3. When committers come to rough consensus that the release is ready, they
   release the .0 release on its branch, e.g. 2019.10.0 for branch-2019.10.  To
   make the actual release, a committer pushes a signed tag named, e.g.
   v2019.10.0, to the OVN repository, makes a release tarball available on
   openvswitch.org, and posts a release announcement to ovs-announce.

4. As bug fixes accumulate, or after important bugs or vulnerabilities are
   fixed, committers may make additional releases from a branch: 2019.10.1,
   2019.10.2, and so on.  The process is the same for these additional release
   as for a .0 release.

.. _long-term-support:

Long-term Support Releases
--------------------------

The OVN project will periodically designate a release as "long-term support" or
LTS for short. An LTS release has the distinction of being maintained for
longer than a standard release.

LTS releases will receive bug fixes until the point that another LTS is
released. At that point, the old LTS will receive an additional year of
critical and security fixes. Critical fixes are those that are required to
ensure basic operation (e.g. memory leak fixes, crash fixes). Security fixes
are those that address concerns about exploitable flaws in OVN and that have a
corresponding CVE report.

LTS releases are scheduled to be released once every two years. This means
that any given LTS will receive bug fix support for two years, followed by
one year of critical bug fixes and security fixes.

The current LTS version is documented on the `Long Term Support Releases`__
page of `ovn.org`__.

Release Numbering
-----------------

The version number on main should normally end in .90.  This indicates that
the OVN version is "almost" the next version to branch.

Forking main into branch-x.y requires two commits to main.  The first is
titled "Prepare for x.y.0" and increments the version number to x.y.  This is
the initial commit on branch-x.y.  The second is titled "Prepare for post-x.y.0
(x.y.90)" and increments the version number to x.y.90.

The version number on a release branch is x.y.z, where x is the current year, y
is the month of the release, and z is initially 0. Making a release requires two
commits.  The first is titled *Set release dates for x.y.z.* and updates NEWS
and debian/changelog to specify the release date of the new release.  This
commit is the one made into a tarball and tagged. The second is titled *Prepare
for x.y.(z+1).* and increments the version number and adds a blank item to NEWS
with an unspecified date.

Release Scheduling
------------------

OVN makes releases at the following three-month cadence.  All dates are
approximate:

+---------------+---------------------+--------------------------------------+
| Time (months) | Example Dates       | Stage                                |
+---------------+---------------------+--------------------------------------+
| T             | Dec 1, Mar 1, ...   | Begin x.y release cycle              |
+---------------+---------------------+--------------------------------------+
| T + 2         | Feb 1, May 1, ...   | "Soft freeze" main for x.y release   |
+---------------+---------------------+--------------------------------------+
| T + 2.5       | Feb 15, May 15, ... | Fork branch-x.y from main            |
+---------------+---------------------+--------------------------------------+
| T + 3         | Mar 1, Jun 1, ...   | Release version x.y.0                |
+---------------+---------------------+--------------------------------------+

Release Calendar
----------------

The 2023 timetable is shown below. Note that these dates are not set in stone.
If extenuating circumstances arise, a release may be delayed from its target
date.

+---------+-------------+-----------------+---------+
| Release | Soft Freeze | Branch Creation | Release |
+---------+-------------+-----------------+---------+
| 23.03.0 | Feb 3       | Feb 17          | Mar 3   |
+---------+-------------+-----------------+---------+
| 23.06.0 | May 5       | May 19          | Jun 2   |
+---------+-------------+-----------------+---------+
| 23.09.0 | Aug 4       | Aug 18          | Sep 1   |
+---------+-------------+-----------------+---------+
| 23.12.0 | Nov 3       | Nov 17          | Dec 1   |
+---------+-------------+-----------------+---------+

Below is the 2024 timetable

+---------+-------------+-----------------+---------+
| Release | Soft Freeze | Branch Creation | Release |
+---------+-------------+-----------------+---------+
| 24.03.0 | Feb 2       | Feb 16          | Mar 1   |
+---------+-------------+-----------------+---------+
| 24.06.0 | May 10      | May 24          | Jun 7   |
+---------+-------------+-----------------+---------+
| 24.09.0 | Aug 9       | Aug 23          | Sep 6   |
+---------+-------------+-----------------+---------+
| 24.12.0 | Nov 8       | Nov 22          | Dec 6   |
+---------+-------------+-----------------+---------+

Contact
-------

Use dev@openvswitch.org to discuss the OVN development and release process.

__ https://www.ovn.org/en/releases/#long-term-support
__ https://www.ovn.org
