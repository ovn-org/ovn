#!/bin/bash

set -ev

ovnk8s_path=$1
env_path=$2
topdir=$PWD

function extract_ci_var() {
    local name=$1

    grep "$name:" .github/workflows/test.yml | awk '{print $2}' | tr -d '"'
}

pushd ${ovnk8s_path}

# Add here any custom operations that need to performed on the
# ovn-kubernetes cloned repo, e.g., custom patches.

# Set up the right GO_VERSION and K8S_VERSION.
echo "GO_VERSION=$(extract_ci_var GO_VERSION)" >> $env_path
echo "K8S_VERSION=$(extract_ci_var K8S_VERSION)" >> $env_path

# git apply --allow-empty is too new so not all git versions from major
# distros support it, just check if the custom patch file is not empty
# before applying it.
[ -s ${topdir}/.ci/ovn-kubernetes/custom.patch ] && \
    git apply -v ${topdir}/.ci/ovn-kubernetes/custom.patch

popd # ${ovnk8s_path}
exit 0
