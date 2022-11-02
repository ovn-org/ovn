#!/bin/bash

set -o errexit
set -x

COMMON_CFLAGS=""
OVN_CFLAGS=""
EXTRA_OPTS="--enable-Werror"

function configure_ovs()
{
    pushd ovs
    ./boot.sh && ./configure CFLAGS="${COMMON_CFLAGS}" $* || \
    { cat config.log; exit 1; }
    make -j4 || { cat config.log; exit 1; }
    popd
}

function configure_ovn()
{
    configure_ovs $*
    ./boot.sh && ./configure CFLAGS="${COMMON_CFLAGS} ${OVN_CFLAGS}" $* || \
    { cat config.log; exit 1; }
}

save_OPTS="${OPTS} $*"
OPTS="${EXTRA_OPTS} ${save_OPTS}"

# If AddressSanitizer and UndefinedBehaviorSanitizer are requested, enable them,
# but only for OVN, not for OVS.  However, disable some optimizations for
# OVS, to make sanitizer reports user friendly.
if [ "$SANITIZERS" ]; then
    # Use the default options configured in tests/atlocal.in, in UBSAN_OPTIONS.
    COMMON_CFLAGS="${COMMON_CFLAGS} -O1 -fno-omit-frame-pointer -fno-common -g"
    OVN_CFLAGS="${OVN_CFLAGS} -fsanitize=address,undefined"
fi

if [ "$CC" = "clang" ]; then
    COMMON_CFLAGS="${COMMON_CFLAGS} -Wno-error=unused-command-line-argument"
elif [ "$M32" ]; then
    # Not using sparse for 32bit builds on 64bit machine.
    # Adding m32 flag directly to CC to avoid any possible issues with API/ABI
    # difference on 'configure' and 'make' stages.
    export CC="$CC -m32"
else
    OPTS="$OPTS --enable-sparse"
fi

if [ "$TESTSUITE" ]; then
    if [ "$TESTSUITE" = "system-test" ]; then
        configure_ovn $OPTS
        make -j4 || { cat config.log; exit 1; }
        if ! sudo make -j4 check-kernel TESTSUITEFLAGS="$TEST_RANGE" RECHECK=yes; then
            # system-kmod-testsuite.log is necessary for debugging.
            cat tests/system-kmod-testsuite.log
            exit 1
        fi
    else
        # 'distcheck' will reconfigure with required options.
        # Now we only need to prepare the Makefile without sparse-wrapped CC.
        configure_ovn

        export DISTCHECK_CONFIGURE_FLAGS="$OPTS"
        if ! make distcheck CFLAGS="${COMMON_CFLAGS} ${OVN_CFLAGS}" -j4 \
            TESTSUITEFLAGS="-j4 $TEST_RANGE" RECHECK=yes
        then
            # testsuite.log is necessary for debugging.
            cat */_build/sub/tests/testsuite.log
            exit 1
        fi
    fi
else
    configure_ovn $OPTS
    make -j4 || { cat config.log; exit 1; }
fi

exit 0
