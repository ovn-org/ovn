#!/bin/bash

set -o errexit
set -x

CFLAGS="-Werror"
SPARSE_FLAGS=""
EXTRA_OPTS=""
TARGET="x86_64-native-linuxapp-gcc"

function configure_ovs()
{
    git clone https://github.com/openvswitch/ovs.git ovs_src
    pushd ovs_src
    ./boot.sh && ./configure $* || { cat config.log; exit 1; }
    make -j4 || { cat config.log; exit 1; }
    popd
}

function configure_ovn()
{
    configure_ovs $*
    ./boot.sh && ./configure --with-ovs-source=$PWD/ovs_src $* || \
    { cat config.log; exit 1; }
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
    configure_ovn

    export DISTCHECK_CONFIGURE_FLAGS="$OPTS --with-ovs-source=$PWD/ovs_src"
    if ! make distcheck -j4 TESTSUITEFLAGS="-j4 -k ovn" RECHECK=yes; then
        # testsuite.log is necessary for debugging.
        cat */_build/sub/tests/testsuite.log
        exit 1
    fi
else
    configure_ovn $OPTS
    make selinux-policy

    make -j4 || { cat config.log; exit 1; }
fi

exit 0
