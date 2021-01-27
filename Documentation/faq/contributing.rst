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

===========
Development
===========

Q: How do I apply patches from email?

   A: You can use ``git am`` on raw email contents, either from a file saved by
   or piped from an email client.  In ``mutt``, for example, when you are
   viewing a patch, you can apply it to the tree in ~/ovs by issuing the
   command ``|cd ~/ovs && git am``.  If you are an OVS committer, you might
   want to add ``-s`` to sign off on the patch as part of applying it.  If you
   do this often, then you can make the keystrokes ``,a`` shorthand for it by
   adding the following line to your ``.muttrc``:

     macro index,pager ,a "<pipe-message>cd ~/ovs && git am -s" "apply patch"

   ``git am`` has a problem with some email messages from the ovs-dev list for
   which the mailing list manager edits the From: address, replacing it by the
   list's own address.  The mailing list manager must do this for messages
   whose sender's email domain has DMARC configured, because receivers will
   otherwise discard these messages when they do not come directly from the
   sender's email domain.  This editing makes the patches look like they come
   from the mailing list instead of the author.  To work around this problem,
   one can use the following wrapper script for ``git am``::

     #! /bin/sh
     tmp=$(mktemp)
     cat >$tmp
     if grep '^From:.*via dev.*' "$tmp" >/dev/null 2>&1; then
        sed '/^From:.*via dev.*/d
             s/^[Rr]eply-[tT]o:/From:/' $tmp
     else
        cat "$tmp"
     fi | git am "$@"
     rm "$tmp"

   Another way to apply emailed patches is to use the ``pwclient`` program,
   which can obtain patches from patchwork and apply them directly.  Download
   ``pwclient`` at https://patchwork.ozlabs.org/project/ovn/.  You probably
   want to set up a ``.pwclientrc`` that looks something like this::

     [options]
     default=ovn
     signoff=true

     [ovn]
     url=https://patchwork.ozlabs.org/xmlrpc/

   After you install ``pwclient``, you can apply a patch from patchwork with
   ``pwclient git-am #``, where # is the patch's number.  (This fails with
   certain patches that contain form-feeds, due to a limitation of the protocol
   underlying ``pwclient``.)

   Another way to apply patches directly from patchwork which supports applying
   patch series is to use the ``git-pw`` program. It can be obtained with
   ``pip install git-pw``. Alternative installation instructions and general
   documentation can be found at
   https://patchwork.readthedocs.io/projects/git-pw/en/latest/. You need to
   use your ovn patchwork login or create one at
   https://patchwork.ozlabs.org/register/. The following can then be set on
   the command line with ``git config`` or through a ``.gitconfig`` like this::

     [pw]
     server=https://patchwork.ozlabs.org/api/1.0
     project=ovn
     username=<username>
     password=<password>

   Patch series can be listed with ``git-pw series list`` and applied with
   ``git-pw series apply #``, where # is the series number. Individual patches
   can be applied with ``git-pw patch apply #``, where # is the patch number.
