# Common configuration and helpers for pf9 OVN/OVS builds.
# Source this file; do not execute directly.

TEAMCITY_ROOT="$(pwd)"
ROOT="$(pwd)/pf9-ovn"

OVS_BASE="3.3.6"
OVN_BASE="24.03.6"

# PF9_DEBUG_SYMBOLS (TeamCity parameter env.PF9_DEBUG_SYMBOLS, default false): when true,
# the builds also publish the debug-symbol packages the toolchain already generates
# (-dbgsym .ddeb on Ubuntu, -debuginfo/-debugsource RPMs on Rocky) into a separate
# pkgs/<os>-dbgsym or pkgs/<os>-debuginfo directory, so perf/gdb can symbolize exactly
# this build. They stay out of pkgs/<os> (the hostagent repo and container image input).
pf9_debug_symbols_enabled() {
    case "${PF9_DEBUG_SYMBOLS:-false}" in
        true|TRUE|True|1|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

pf9_git_setup() {
    git config --global --add safe.directory '*'
    git config --global url."https://github.com/".insteadOf "git@github.com:"
}

pf9_submodule_update() {
    git -C "$ROOT" submodule update --init --recursive
}

pf9_patch_ovn_binary_version() {
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
