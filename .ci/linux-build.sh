#!/bin/bash

set -o errexit
set -x

CFLAGS=""
SPARSE_FLAGS=""
EXTRA_OPTS="--enable-Werror"

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

save_OPTS="${OPTS} $*"
OPTS="${EXTRA_OPTS} ${save_OPTS}"

if [ "$CC" = "clang" ]; then
    export OVS_CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument"
elif [ "$M32" ]; then
    # Not using sparse for 32bit builds on 64bit machine.
    # Adding m32 flag directly to CC to avoid any posiible issues with API/ABI
    # difference on 'configure' and 'make' stages.
    export CC="$CC -m32"
else
    OPTS="$OPTS --enable-sparse"
    export OVS_CFLAGS="$CFLAGS $SPARSE_FLAGS"
fi

if [ "$TESTSUITE" ]; then
    # 'distcheck' will reconfigure with required options.
    # Now we only need to prepare the Makefile without sparse-wrapped CC.
    configure_ovn

    export DISTCHECK_CONFIGURE_FLAGS="$OPTS --with-ovs-source=$PWD/ovs_src"
    if ! make distcheck -j4 TESTSUITEFLAGS="-j4" RECHECK=yes; then
        # testsuite.log is necessary for debugging.
        cat */_build/sub/tests/testsuite.log
        exit 1
    fi
else
    configure_ovn $OPTS
    make -j4 || { cat config.log; exit 1; }
fi

exit 0
