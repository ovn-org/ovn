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

=============
OVS Submodule
=============

Prior to 2020, OVN did not exist as its own repo. Instead, OVN was a
subdirectory within OVS. OVN grew up being closely intertwined with OVS.
Compiling OVS would also compile OVN. OVN used OVS libraries directly, and
there was no concern about trying to maintain any level of compatibility
between OVS and OVN since they were the same codebase.

In 2020, OVN was split off from OVS. This meant that it became necessary to
consider compatibility between OVS and OVN. At compile time, we use a submodule
to ensure that OVS libraries that OVN relies on will behave as expected.
Runtime compatibility is a separate topic outside the scope of this document.

Developing with the OVS submodule
---------------------------------

Most OVN development will happen independently of the OVS submodule. However,
there may be times that in order to make a change in OVN, an accompanying
change is required in OVS as well. For instance, it may be that a change to
OVSDB's client API is required for OVN to fix a bug.

In this situation, make the necessary OVS change first and submit this fix to
OVS based on their current code submission guidelines. Once the change has been
accepted by OVS, then you can submit an OVN patch that includes changing the
submodule to point at the OVS commit where your change was accepted.

Submodules for releases
-----------------------

For OVN releases, it is preferred for the OVS submodule to point to a stable
release branch of OVS. Therefore, as part of the release process for OVN, we
will point the submodule to the latest stable branch of OVS before releasing.

The exception to this is if the current OVS submodule is pointing to a commit
that is not in a current stable branch of OVS. In that case, the submodule
will continue to point to that particular commit. We may, however, bump the
submodule to the next stable branch of OVS at a later time.

As an example, let's assume that the OVS commit history looks something like
this in the main branch:

::

    (Newest)
    Commit 3
       |
       |
    Commit 2 (used to create OVS branch-Y)
       |
       |
    Commit 1
    (Oldest)

Let's say that we are planning to release OVN version X. At this point, the
submodule is pointing to Commit 1. As part of the release process, we will bump
the OVS submodule in OVN to point to Commit 2, or more likely the tip of OVS
branch-Y. This way, the released version of OVN is based on a stable release
branch of OVS, and it has all of the necessary changes that we require.

What if the OVS submodule currently points to Commit 3, though? There is no
stable branch that exists after this commit. In this case, we have two choices:

# Create OVN release X and point the OVS submodule to Commit 3. At a later
  time, if it makes sense to do so, we may bump the submodule to OVS branch-Z
  when it is released, since Commit 3 will be included in that branch.
# If Commit 3 is a bug fix in OVS, then we can try to ensure that Commit 3 gets
  backported to OVS branch-Y, and then point the submodule commit to the tip of
  OVS branch-Y.

For choice 1, the decision of whether to update the submodule commit to OVS
branch-Z is based on several factors.

- Is OVN release X still being supported?
- Is there any known benefit to updating the submodule? E.g., are there
  performance improvements we could take advantage of by updating the
  submodule?
- Is there risk in updating the submodule?

For an LTS of OVN, we might update the submodule several times during its
lifetime as more new OVS branches are released. For a standard release, it is
less likely that we will update the OVS submodule during the standard release's
lifetime.
