#!/bin/bash

set -o errexit
set -x

CFLAGS="-Werror"
SPARSE_FLAGS=""
EXTRA_OPTS=""
TARGET="x86_64-native-linuxapp-gcc"

function configure_ovs()
{
    ./boot.sh && ./configure $* || { cat config.log; exit 1; }
}

OPTS="$EXTRA_OPTS $*"

if [ "$CC" = "clang" ]; then
    export OVS_CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument"
elif [[ $BUILD_ENV =~ "-m32" ]]; then
    # Disable sparse for 32bit builds on 64bit machine
    export OVS_CFLAGS="$CFLAGS $BUILD_ENV"
else
    OPTS="$OPTS --enable-sparse"
    export OVS_CFLAGS="$CFLAGS $BUILD_ENV $SPARSE_FLAGS"
fi

if [ "$TESTSUITE" ]; then
    # 'distcheck' will reconfigure with required options.
    # Now we only need to prepare the Makefile without sparse-wrapped CC.
    configure_ovs

    export DISTCHECK_CONFIGURE_FLAGS="$OPTS"
    if ! make distcheck -j4 TESTSUITEFLAGS="-j4 -k ovn" RECHECK=yes; then
        # testsuite.log is necessary for debugging.
        cat */_build/tests/testsuite.log
        exit 1
    fi
else
    configure_ovs $OPTS
    make selinux-policy

    make -j4
fi

exit 0
