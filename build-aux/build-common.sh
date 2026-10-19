# Common configuration and helpers for pf9 OVN/OVS builds.
# Source this file; do not execute directly.

TEAMCITY_ROOT="$(pwd)"
ROOT="$(pwd)/pf9-ovn"

OVS_BASE="3.3.6"
OVN_BASE="24.03.6"

pf9_git_setup() {
    git config --global --add safe.directory '*'
    git config --global url."https://github.com/".insteadOf "git@github.com:"
}

pf9_submodule_update() {
    git -C "$ROOT" submodule update --init --recursive
}

pf9_patch_ovn_binary_version() {
    # Fail loudly if PF9_OVN_VERSION (pf9-version.rc) and OVN_BASE above have
    # silently drifted apart - e.g. a release bumped the OVN suffix in
    # PF9_OVN_VERSION without rebasing the OVN source actually checked into
    # this repo, or vice versa. PF9_OVN_VERSION looks like
    # "2026.9.0-v24.03.6"; the part after "-v" is expected to equal OVN_BASE
    # exactly.
    ovn_version_suffix="${PF9_OVN_VERSION#*-v}"
    if [ "$ovn_version_suffix" = "$PF9_OVN_VERSION" ] || \
       [ "$ovn_version_suffix" != "$OVN_BASE" ]; then
        echo "FATAL: PF9_OVN_VERSION ('${PF9_OVN_VERSION}') does not encode" \
             "OVN_BASE ('${OVN_BASE}') - pf9-version.rc and build-common.sh" \
             "have drifted apart. Update one to match the other." >&2
        exit 1
    fi

    # Dots throughout, no epoch, no OS suffix — identical on all platforms.
    # configure.ac carries this into OVN_PACKAGE_VERSION and thus ovn-appctl version.
    PF9_OVN_BINARY_VERSION=${OVN_BASE}.pf9.${PF9_VERSION}.${BUILD_NUMBER}
    sed -i "s/__PF9_OVN_BUILD_VERSION__/${PF9_OVN_BINARY_VERSION}/g" "$ROOT/configure.ac"
}

pf9_build_reset() {
    cd "$ROOT"
    git reset HEAD --hard
    git clean -fdx

    cd "$ROOT/ovs"
    git reset HEAD --hard
    git clean -fdx
}
