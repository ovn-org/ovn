#!/bin/bash

set -ev

ovnk8s_path=$1
topdir=$PWD

pushd ${ovnk8s_path}

# Add here any custom operations that need to performed on the
# ovn-kubernetes cloned repo, e.g., custom patches.

# git apply --allow-empty is too new so not all git versions from major
# distros support it, just check if the custom patch file is not empty
# before applying it.
[ -s ${topdir}/.ci/ovn-kubernetes/custom.patch ] && \
    git apply -v ${topdir}/.ci/ovn-kubernetes/custom.patch

popd # ${ovnk8s_path}
exit 0
