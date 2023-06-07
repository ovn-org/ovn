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

The development branch is `main` in the OVN repository. Patches are applied
first to this branch, then to the most recent `branch-X.Y`, then earlier
`branch-X.Z`, and so on. The most common kind of patch in this category is
a bugfix which affects main and other branches.

Backport Policy
---------------

Patches which are fixing bugs should be considered for backporting from
`main` to release branches. OVN contributors submit their patches
targeted to the `main` branch, using the ``Fixes`` tag desribed in
:doc:`submitting-patches`. The maintainer first applies the patch to `main`,
then backports the patch to each older affected tree, as far back as it goes
or at least to all currently supported branches. This is usually each branch
back to the most recent LTS release branch.

If the fix only affects a particular branch and not `main`, contributors
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

Supported Versions
~~~~~~~~~~~~~~~~~~

As documented in :doc:`release-process`, standard term support branches receive
regular releases for a year, and LTS branches receive regular releases for two
years, plus an additional year of critical and security fixes.

To make things easy, maintainers should simply backport all bugfixes to the
previous four branches before main. This is guaranteed to get the fix into all
supported standard-support branches as well as the current LTS branch. This
will mean that maintainers will backport bugfixes to branches representing
branches that are not currently supported.

Critical and security fixes should be handled differently. Maintainers should
determine what is the oldest LTS branch that currently is supported for
critical and security fixes. Maintainers should backport these fixes to all
branches between main and that LTS branch. This will mean that maintainers
will backport critical and security fixes into branches for which no further
releases are being made.

The reason for backporting fixes into unsupported branches is twofold:

- Backporting bugfixes into unsupported branches likely makes it easier to
  backport critical and security fixes into older branches when necessary.
- Backporting critical and security fixes into unsupported branches allows for
  users that are not ready to upgrade to a version in a supported branch to
  continue using the branch tip until they are ready to fully upgrade.

Example
+++++++

Consider the following release timeline.

+---------+----------+--------------+
| Branch  | Date     | Release Type |
+---------+----------+--------------+
| 24.03   | Mar 2024 | LTS          |
+---------+----------+--------------+
| 24.09   | Sep 2024 | Standard     |
+---------+----------+--------------+
| 25.03   | Mar 2025 | Standard     |
+---------+----------+--------------+
| 25.09   | Sep 2025 | Standard     |
+---------+----------+--------------+
| 26.03   | Mar 2026 | LTS          |
+---------+----------+--------------+
| 26.09   | Sep 2026 | Standard     |
+---------+----------+--------------+

In our hypothetical world it is October 2026, so the current status of each
release is:

+---------+------------------------------+
| Branch  | Support Status               |
+---------+------------------------------+
| 24.03   | Critical/Security fixes only |
+---------+------------------------------+
| 24.09   | Unsupported since Sep 2025   |
+---------+------------------------------+
| 25.03   | Unsupported since Mar 2026   |
+---------+------------------------------+
| 25.09   | Unsupported since Sep 2026   |
+---------+------------------------------+
| 26.03   | Supported                    |
+---------+------------------------------+
| 26.09   | Supported                    |
+---------+------------------------------+

Let's say that a bug fix is committed to main. Our policy would be to backport
the fix to 26.09, 26.03, 25.09, and 25.03. The fix will eventually appear in
releases of 26.03 and 26.09. Even though the fix is in the development branches
for 25.03 and 25.09, the fix will never appear in a release.

Now let's say that a security issue is committed to main. Our policy would be
to backport the fix to 24.03, 24.09, 25.03, 25.09, 26.03, and 26.09. 24.03 is
the oldest LTS branch that still is receiving critical and security fixes, so
we backport the fix to all branches between main and that branch. The security
fix will appear in releases of 24.03, 26.03, and 26.09. The security fix will
be present in the 24.09, 25.03, and 25.09 development branches, but will never
appear in a release.


Submission
~~~~~~~~~~

Once the patches are all assembled and working on the OVN tree, they
need to be formatted again using ``git format-patch``.

The contents of a backport should be equivalent to the changes made by the
original patch; explain any variations from the original patch in the commit
message - For instance if you rolled in a bugfix. Reviewers will verify that
the changes made by the backport patch are the same as the changes made in the
original commit which the backport is based upon. Patch submission should
otherwise follow the regular steps described in :doc:`submitting-patches`.
