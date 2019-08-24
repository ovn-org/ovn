#!/bin/bash

set -o errexit

CFLAGS="-Werror $CFLAGS"
EXTRA_OPTS=""

function configure_ovs()
{
    git clone https://github.com/openvswitch/ovs.git ovs_src
    pushd ovs_src
    ./boot.sh && ./configure $*
    make -j4
    popd
}

function configure_ovn()
{
    configure_ovs $*
    ./boot.sh && ./configure $* --with-ovs-source=$PWD/ovs_src
}

configure_ovn $EXTRA_OPTS $*

if [ "$CC" = "clang" ]; then
    make CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument"
else
    make CFLAGS="$CFLAGS $BUILD_ENV"
fi
if [ "$TESTSUITE" ] && [ "$CC" != "clang" ]; then
    export DISTCHECK_CONFIGURE_FLAGS="$EXTRA_OPTS --with-ovs-source=$PWD/ovs_src"
    if ! make distcheck RECHECK=yes; then
        # testsuite.log is necessary for debugging.
        cat */_build/tests/testsuite.log
        exit 1
    fi
fi

exit 0
