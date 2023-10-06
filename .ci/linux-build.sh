#!/bin/bash

set -o errexit
set -x

ARCH=${ARCH:-"x86_64"}
USE_SPARSE=${USE_SPARSE:-"yes"}
COMMON_CFLAGS=""
OVN_CFLAGS=""
OPTS="$OPTS --enable-Werror"
JOBS=${JOBS:-"-j4"}

function configure_ovs()
{
    pushd ovs
    ./boot.sh && ./configure CFLAGS="${COMMON_CFLAGS}" $* || \
    { cat config.log; exit 1; }
    make $JOBS || { cat config.log; exit 1; }
    popd
}

function configure_ovn()
{
    configure_ovs $*
    ./boot.sh && ./configure CFLAGS="${COMMON_CFLAGS} ${OVN_CFLAGS}" $* || \
    { cat config.log; exit 1; }
}

function configure_gcc()
{
    if [ "$ARCH" = "x86_64" ] && [ "$USE_SPARSE" = "yes" ]; then
        # Enable sparse only for x86_64 architecture.
        OPTS="$OPTS --enable-sparse"
    elif [ "$ARCH" = "x86" ]; then
        # Adding m32 flag directly to CC to avoid any possible issues
        # with API/ABI difference on 'configure' and 'make' stages.
        export CC="$CC -m32"
        if which apt; then
            # We should install gcc-multilib for x86 build, we cannot
            # do it directly because gcc-multilib is not available
            # for arm64
            sudo apt update && sudo apt install -y gcc-multilib
        fi
    fi
}

function configure_clang()
{
    # If AddressSanitizer and UndefinedBehaviorSanitizer are requested,
    # enable them, but only for OVN, not for OVS.  However, disable some
    # optimizations for OVS, to make sanitizer reports user friendly.
    if [ "$SANITIZERS" ]; then
       # Use the default options configured in tests/atlocal.in,
       # in UBSAN_OPTIONS.
       COMMON_CFLAGS="${COMMON_CFLAGS} -O1 -fno-omit-frame-pointer -fno-common -g"
       OVN_CFLAGS="${OVN_CFLAGS} -fsanitize=address,undefined"
    fi
    COMMON_CFLAGS="${COMMON_CFLAGS} -Wno-error=unused-command-line-argument"
}

function execute_tests()
{
    # 'distcheck' will reconfigure with required options.
    # Now we only need to prepare the Makefile without sparse-wrapped CC.
    configure_ovn

    export DISTCHECK_CONFIGURE_FLAGS="$OPTS"
    if ! make distcheck CFLAGS="${COMMON_CFLAGS} ${OVN_CFLAGS}" $JOBS \
        TESTSUITEFLAGS="$JOBS $TEST_RANGE" RECHECK=yes
    then
        # testsuite.log is necessary for debugging.
        cat */_build/sub/tests/testsuite.log
        exit 1
    fi
}

function execute_system_tests()
{
      type=$1
      log_file=$2

      configure_ovn $OPTS
      make $JOBS || { cat config.log; exit 1; }
      if ! sudo make $JOBS $type TESTSUITEFLAGS="$TEST_RANGE" RECHECK=yes; then
          # $log_file is necessary for debugging.
          cat tests/$log_file
          exit 1
      fi
}

configure_$CC

if [ "$TESTSUITE" ]; then
    case "$TESTSUITE" in
        "test")
        execute_tests
        ;;

        "system-test")
        execute_system_tests "check-kernel" "system-kmod-testsuite.log"
        ;;

        "system-test-userspace")
        execute_system_tests "check-system-userspace" \
            "system-userspace-testsuite.log"
        ;;
    esac
else
    configure_ovn $OPTS
    make $JOBS || { cat config.log; exit 1; }
fi

exit 0
