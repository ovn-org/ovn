#!/bin/bash

set -o errexit
set -x

CFLAGS=""
OVN_CFLAGS=""
SPARSE_FLAGS=""
EXTRA_OPTS="--enable-Werror"

function configure_ovs()
{
    pushd ovs
    ./boot.sh && ./configure $* || { cat config.log; exit 1; }
    make -j4 || { cat config.log; exit 1; }
    popd
}

function configure_ovn()
{
    configure_ovs $*

    export OVS_CFLAGS="${OVS_CFLAGS} ${OVN_CFLAGS}"
    ./boot.sh && ./configure $* || \
    { cat config.log; exit 1; }
}

save_OPTS="${OPTS} $*"
OPTS="${EXTRA_OPTS} ${save_OPTS}"

# If AddressSanitizer is requested, enable it, but only for OVN, not for OVS.
# However, disable some optimizations for OVS, to make AddressSanitizer
# reports user friendly.
if [ "$ASAN" ]; then
    CFLAGS="-fno-omit-frame-pointer -fno-common"
    OVN_CFLAGS="-fsanitize=address"
fi

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

    export DISTCHECK_CONFIGURE_FLAGS="$OPTS"
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
