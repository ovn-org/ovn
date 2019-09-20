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

=======
Testing
=======

It is possible to test OVN using both tooling provided with Open
vSwitch and using a variety of third party tooling.

Built-in Tooling
----------------

OVN provides a number of different test suites and other tooling for
validating basic functionality of OVN. Before running any of the tests
described here, you must bootstrap, configure and build OVN as
described in :doc:`/intro/install/general`. You do not need to install
OVN, Open vSwitch or to build or load the kernel module to run these test
suites.You do not need supervisor privilege to run these test suites.

Unit Tests
~~~~~~~~~~

OVN includes a suite of self-tests. Before you submit patches
upstream, we advise that you run the tests and ensure that they pass. If you
add new features to OVN, then adding tests for those features will
ensure your features don't break as developers modify other areas of OVN.

To run all the unit tests in OVN, one at a time, run::

    $ make check

This takes under 5 minutes on a modern desktop system.

To run all the unit tests in OVN in parallel, run::

    $ make check TESTSUITEFLAGS=-j8

You can run up to eight threads. This takes under a minute on a modern 4-core
desktop system.

To see a list of all the available tests, run::

    $ make check TESTSUITEFLAGS=--list

To run only a subset of tests, e.g. test 123 and tests 477 through 484, run::

    $ make check TESTSUITEFLAGS='123 477-484'

Tests do not have inter-dependencies, so you may run any subset.

To run tests matching a keyword, e.g. ``ovsdb``, run::

    $ make check TESTSUITEFLAGS='-k ovsdb'

To see a complete list of test options, run::

    $ make check TESTSUITEFLAGS=--help

The results of a testing run are reported in ``tests/testsuite.log``. Report
report test failures as bugs and include the ``testsuite.log`` in your report.

.. note::
  Sometimes a few tests may fail on some runs but not others. This is usually a
  bug in the testsuite, not a bug in Open vSwitch itself. If you find that a
  test fails intermittently, please report it, since the developers may not
  have noticed. You can make the testsuite automatically rerun tests that fail,
  by adding ``RECHECK=yes`` to the ``make`` command line, e.g.::

      $ make check TESTSUITEFLAGS=-j8 RECHECK=yes

.. _testing-coverage:

Coverage
~~~~~~~~

If the build was configured with ``--enable-coverage`` and the ``lcov`` utility
is installed, you can run the testsuite and generate a code coverage report by
using the ``check-lcov`` target::

    $ make check-lcov

All the same options are available via TESTSUITEFLAGS. For example::

    $ make check-lcov TESTSUITEFLAGS='-j8 -k ovn'

.. _testing-valgrind:

Valgrind
~~~~~~~~

If you have ``valgrind`` installed, you can run the testsuite under
valgrind by using the ``check-valgrind`` target::

    $ make check-valgrind

When you do this, the "valgrind" results for test ``<N>`` are reported in files
named ``tests/testsuite.dir/<N>/valgrind.*``.

To test the testsuite of kernel datapath under valgrind, you can use the
``check-kernel-valgrind`` target and find the "valgrind" results under
directory ``tests/system-kmod-testsuite.dir/``.

All the same options are available via TESTSUITEFLAGS.

.. hint::
  You may find that the valgrind results are easier to interpret if you put
  ``-q`` in ``~/.valgrindrc``, since that reduces the amount of output.

Static Code Analysis
~~~~~~~~~~~~~~~~~~~~

Static Analysis is a method of debugging Software by examining code rather than
actually executing it. This can be done through 'scan-build' commandline
utility which internally uses clang (or) gcc to compile the code and also
invokes a static analyzer to do the code analysis. At the end of the build, the
reports are aggregated in to a common folder and can later be analyzed using
'scan-view'.

OVN includes a Makefile target to trigger static code analysis::

    $ ./boot.sh
    $ ./configure CC=clang  # clang
    # or
    $ ./configure CC=gcc CFLAGS="-std=gnu99"  # gcc
    $ make clang-analyze

You should invoke scan-view to view analysis results. The last line of output
from ``clang-analyze`` will list the command (containing results directory)
that you should invoke to view the results on a browser.

Continuous Integration with Travis CI
-------------------------------------

A .travis.yml file is provided to automatically build OVN with various
build configurations and run the testsuite using Travis CI. Builds will be
performed with gcc, sparse and clang with the -Werror compiler flag included,
therefore the build will fail if a new warning has been introduced.

The CI build is triggered via git push (regardless of the specific branch) or
pull request against any Open vSwitch GitHub repository that is linked to
travis-ci.

Instructions to setup travis-ci for your GitHub repository:

1. Go to https://travis-ci.org/ and sign in using your GitHub ID.
2. Go to the "Repositories" tab and enable the ovs repository. You may disable
   builds for pushes or pull requests.
3. In order to avoid forks sending build failures to the upstream mailing list,
   the notification email recipient is encrypted. If you want to receive email
   notification for build failures, replace the the encrypted string:

   1. Install the travis-ci CLI (Requires ruby >=2.0): gem install travis
   2. In your Open vSwitch repository: travis encrypt mylist@mydomain.org
   3. Add/replace the notifications section in .travis.yml and fill in the
      secure string as returned by travis encrypt::

          notifications:
            email:
              recipients:
                - secure: "....."

  .. note::
    You may remove/omit the notifications section to fall back to default
    notification behaviour which is to send an email directly to the author and
    committer of the failing commit. Note that the email is only sent if the
    author/committer have commit rights for the particular GitHub repository.

4. Pushing a commit to the repository which breaks the build or the
   testsuite will now trigger a email sent to mylist@mydomain.org
