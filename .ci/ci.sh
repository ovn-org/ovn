#!/bin/bash -xe
# Copyright (c) 2022, Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

OVN_PATH=${OVN_PATH:-$PWD}
OVS_PATH=${OVS_PATH:-$OVN_PATH/ovs}
CONTAINER_CMD=${CONTAINER_CMD:-podman}
CONTAINER_WORKSPACE="/workspace"
CONTAINER_WORKDIR="/workspace/ovn-tmp"
IMAGE_NAME=${IMAGE_NAME:-"ovn-org/ovn-tests"}

# Test variables
ARCH=${ARCH:-$(uname -m)}
CC=${CC:-gcc}


test -t 1 && USE_TTY="t"

function container_exec() {
    ${CONTAINER_CMD} exec "-i$USE_TTY" "$CONTAINER_ID" /bin/bash -c "$1"
}

function container_shell() {
    ${CONTAINER_CMD} exec "-i$USE_TTY" "$CONTAINER_ID" /bin/bash
}

function archive_logs() {
    if [ -z "$archive_logs" ]; then
        return 0;
    fi

    log_dir=$CONTAINER_WORKSPACE/logs/
    container_exec "
        mkdir $log_dir \
        && \
        cp $CONTAINER_WORKDIR/config.log $log_dir \
        && \
        cp -r $CONTAINER_WORKDIR/*/_build/sub/tests/testsuite.* \
        $log_dir || true \
        && \
        cp -r $CONTAINER_WORKDIR/tests/system-*-testsuite.* \
        $log_dir || true \
        && \
        chmod -R +r $log_dir \
        &&
        tar -czvf $CONTAINER_WORKSPACE/logs.tgz $log_dir
    "
    ${CONTAINER_CMD} cp "$CONTAINER_ID:/$CONTAINER_WORKSPACE/logs.tgz" logs.tgz
}

function remove_container() {
    res=$?
    if [  "$res" -ne 0  ]; then
        archive_logs
        echo "*** ERROR: $res ***"
    fi

    ${CONTAINER_CMD} rm -f "$CONTAINER_ID"
}

function copy_sources_to_workdir() {
    container_exec "
        mkdir -p $CONTAINER_WORKDIR \
        && \
        cp -a $CONTAINER_WORKSPACE/ovn/. $CONTAINER_WORKDIR \
        && \
        rm -rf $CONTAINER_WORKDIR/ovs \
        && \
        cp -a $CONTAINER_WORKSPACE/ovs/. $CONTAINER_WORKDIR/ovs \
        && \
        git config --global --add safe.directory $CONTAINER_WORKDIR
    "
}

function overwrite_jobs() {
    container_exec "
        sed -i s/-j[0-9]/-j$jobs/ $CONTAINER_WORKDIR/.ci/linux-build.sh
    "
}

function run_tests() {
    container_exec "
        cd $CONTAINER_WORKDIR \
        && \
        ARCH=$ARCH CC=$CC LIBS=$LIBS OPTS=$OPTS TESTSUITE=$TESTSUITE \
        TEST_RANGE=$TEST_RANGE SANITIZERS=$SANITIZERS \
        ./.ci/linux-build.sh
    "
}

function check_clang_version_ge() {
    lower=$1
    version=$(clang --version | head -n1 | cut -d' ' -f3)
    if ! echo -e "$lower\n$version" | sort -CV; then
      return 1
    fi

    return 0
}

options=$(getopt --options "" \
    --long help,shell,archive-logs,jobs:,ovn-path:,ovs-path:,image-name:\
    -- "${@}")
eval set -- "$options"
while true; do
    case "$1" in
    --shell)
        shell="1"
        ;;
    --jobs)
        shift
        jobs="$1"
        ;;
    --ovn-path)
        shift
        OVN_PATH="$1"
        ;;
    --ovs-path)
        shift
        OVS_PATH="$1"
        ;;
    --image-name)
        shift
        IMAGE_NAME="$1"
        ;;
    --archive-logs)
        archive_logs="1"
        ;;
    --help)
        set +x
        printf "$0 [--shell] [--help] [--archive-logs] [--jobs=<JOBS>] "
        printf "[--ovn-path=<OVN_PATH>] [--ovs-path=<OVS_PATH>] "
        printf "[--image-name=<IMAGE_NAME>]\n"
        exit
        ;;
    --)
        shift
        break
        ;;
    esac
    shift
done

# Workaround for https://bugzilla.redhat.com/2153359
if [ "$ARCH" = "aarch64" ] && ! check_clang_version_ge "16.0.0"; then
    ASAN_OPTIONS="detect_leaks=0"
fi

CONTAINER_ID="$($CONTAINER_CMD run --privileged -d \
    --pids-limit=-1 \
    --env ASAN_OPTIONS=$ASAN_OPTIONS \
    -v /lib/modules/$(uname -r):/lib/modules/$(uname -r):ro \
    -v $OVN_PATH:$CONTAINER_WORKSPACE/ovn:Z \
    -v $OVS_PATH:$CONTAINER_WORKSPACE/ovs:Z \
    $IMAGE_NAME)"
trap remove_container EXIT

copy_sources_to_workdir

if [ -n "$jobs" ]; then
    overwrite_jobs
fi

if [ -n "$shell" ];then
    container_shell
    exit 0
fi

run_tests
