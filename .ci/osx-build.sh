#!/bin/bash

set -o errexit

CFLAGS="-Werror $CFLAGS"
EXTRA_OPTS=""

function configure_ovs()
{
    pushd ovs
    ./boot.sh && ./configure $*
    make -j4 || { cat config.log; exit 1; }
    popd
}

function configure_ovn()
{
    configure_ovs $*
    ./boot.sh && ./configure $*
}

configure_ovn $EXTRA_OPTS $*

if [ "$CC" = "clang" ]; then
    set make CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument"
else
    set make CFLAGS="$CFLAGS $BUILD_ENV"
fi
if ! "$@"; then
    cat config.log
    exit 1
fi
if [ "$TESTSUITE" ] && [ "$CC" != "clang" ]; then
    export DISTCHECK_CONFIGURE_FLAGS="$EXTRA_OPTS"
    if ! make distcheck RECHECK=yes; then
        # testsuite.log is necessary for debugging.
        cat */_build/sub/tests/testsuite.log
        exit 1
    fi
fi

exit 0
