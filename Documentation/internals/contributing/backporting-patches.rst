..
      Copyright (c) 2017 Nicira, Inc.

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
Backporting patches
===================

.. note::

    This is an advanced topic for developers and maintainers. Readers should
    familiarize themselves with building and running OVN, with the git
    tool, and with the OVN patch submission process.

The backporting of patches from one git tree to another takes multiple forms
within OVN, but is broadly applied in the following fashion:

- Contributors submit their proposed changes to the latest development branch
- Contributors and maintainers provide feedback on the patches
- When the change is satisfactory, maintainers apply the patch to the
  development branch.
- Maintainers backport changes from a development branch to release branches.

With regards to OVN user space code and code that does not comprise
the Linux datapath and compat code, the development branch is `master` in the
OVN repository. Patches are applied first to this branch, then to the
most recent `branch-X.Y`, then earlier `branch-X.Z`, and so on. The most common
kind of patch in this category is a bugfix which affects master and other
branches.

Changes to userspace components
-------------------------------

Patches which are fixing bugs should be considered for backporting from
`master` to release branches. OVN contributors submit their patches
targeted to the `master` branch, using the ``Fixes`` tag described in
:doc:`submitting-patches`. The maintainer first applies the patch to `master`,
then backports the patch to each older affected tree, as far back as it goes or
at least to all currently supported branches. This is usually each branch back
to the most recent LTS release branch.

If the fix only affects a particular branch and not `master`, contributors
should submit the change with the target branch listed in the subject line of
the patch. Contributors should list all versions that the bug affects. The
``git format-patch`` argument ``--subject-prefix`` may be used when posting the
patch, for example:

::

    $ git format-patch -1 --subject-prefix="PATCH ovn branch-21.06"

If a maintainer is backporting a change to older branches and the backport is
not a trivial cherry-pick, then the maintainer may opt to submit the backport
for the older branch on the mailing list for further review. This should be done
in the same manner as described above.

Submission
~~~~~~~~~~

Once the patches are all assembled and working on the OVN tree, they
need to be formatted again using ``git format-patch``. The common format for
commit messages for Linux backport patches is as follows:

::

    datapath: Remove incorrect WARN_ONCE().

    Upstream commit:
        commit c6b2aafffc6934be72d96855c9a1d88970597fbc
        Author: Jarno Rajahalme <jarno@ovn.org>
        Date:   Mon Aug 1 19:08:29 2016 -0700

        openvswitch: Remove incorrect WARN_ONCE().

        ovs_ct_find_existing() issues a warning if an existing conntrack entry
        classified as IP_CT_NEW is found, with the premise that this should
        not happen.  However, a newly confirmed, non-expected conntrack entry
        remains IP_CT_NEW as long as no reply direction traffic is seen.  This
        has resulted into somewhat confusing kernel log messages.  This patch
        removes this check and warning.

        Fixes: 289f2253 ("openvswitch: Find existing conntrack entry after upcall.")
        Suggested-by: Joe Stringer <joe@ovn.org>
        Signed-off-by: Jarno Rajahalme <jarno@ovn.org>
        Acked-by: Joe Stringer <joe@ovn.org>

    Signed-off-by: Jarno Rajahalme <jarno@ovn.org>

The upstream commit SHA should be the one that appears in Linus' tree so that
reviewers can compare the backported patch with the one upstream.  Note that
the subject line for the backported patch replaces the original patch's
``openvswitch`` prefix with ``datapath``. Patches which only affect the
``datapath/linux/compat`` directory should be prefixed with ``compat``.

The contents of a backport should be equivalent to the changes made by the
original patch; explain any variations from the original patch in the commit
message - For instance if you rolled in a bugfix. Reviewers will verify that
the changes made by the backport patch are the same as the changes made in the
original commit which the backport is based upon. Patch submission should
otherwise follow the regular steps described in :doc:`submitting-patches`.
