set -x
set -e

source pf9-version/pf9-version.rc
source "$(dirname "$0")/build-common.sh"

# Install dependencies
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  fakeroot build-essential autoconf automake bzip2 debhelper devscripts dpkg-dev \
  debhelper-compat dh-exec dh-python dh-sequence-python3 dh-sequence-sphinxdoc \
  graphviz iproute2 libcap-ng-dev libnuma-dev libpcap-dev libssl-dev libtool \
  libunbound-dev openssl pkg-config procps python3-all-dev python3-setuptools \
  python3-sortedcontainers python3-sphinx libjson-c-dev libevent-dev \
  libsystemd-dev python3 python3-pip curl python3-twisted python3-zope.interface \
  libunwind-dev git strongswan kmod uuid-runtime python3-netifaces

pf9_git_setup

# Cleanup: Remove previous build artifacts
if [ -f "$ROOT/Makefile" ]; then
    make -C "$ROOT" distclean
fi
rm -rf "$ROOT/dist"

UBUNTU_VERSION=$1

if [ "$UBUNTU_VERSION" != "u22" ] && [ "$UBUNTU_VERSION" != "u24" ] && [ -n "$UBUNTU_VERSION" ]; then
    echo "Error: Invalid Ubuntu version '$UBUNTU_VERSION'. Expected 'u22' or 'u24'."
    exit 1
fi

pf9_submodule_update

# --- OVN CONFIGURATION ---
PF9_OVN_BUILD_VERSION=1:${OVN_BASE}-pf9-$PF9_VERSION-$BUILD_NUMBER+${UBUNTU_VERSION}
printf '%s\n' "1:${OVN_BASE}-pf9-${PF9_VERSION}-${BUILD_NUMBER}" > $TEAMCITY_ROOT/ovn-deb-version.txt

# debian/changelog gets the full epoch-prefixed version for apt dependency resolution
# configure.ac gets the dot-separated binary version via pf9_patch_ovn_binary_version
sed -i "s/__PF9_OVN_BUILD_VERSION__/$PF9_OVN_BUILD_VERSION/g" "$ROOT/debian/changelog"

pf9_patch_ovn_binary_version

# --- OVS CONFIGURATION ---
# Static version (no build counter): only bump manually when OVS code changes.
# Epoch 1 beats upstream; omitting build counter means existing CI-versioned
# installs (e.g. 1:3.3.x-pf9-YYYY.M.P-NNN) are already >= this and won't upgrade.
PF9_OVS_BUILD_VERSION=1:${OVS_BASE}-pf9+${UBUNTU_VERSION}
printf '%s' "1:${OVS_BASE}-pf9" >> $TEAMCITY_ROOT/ovn-deb-version.txt

# Update OVS Changelog
sed -i "s/${OVS_BASE}-1/$PF9_OVS_BUILD_VERSION/g" "$ROOT/ovs/debian/changelog"

# Python setuptools sanitization (PEP 440)
# Strip epoch and +UBUNTU_VERSION before converting to dot-notation, then re-add + for local segment
PF9_OVS_PYTHON_VERSION=$(echo "$PF9_OVS_BUILD_VERSION" | sed "s/^1://; s/+[^-]*$//; s/-/./g; s/${OVS_BASE}./${OVS_BASE}+/")
sed -i "s/${OVS_BASE}/$PF9_OVS_PYTHON_VERSION/g" "$ROOT/ovs/configure.ac"

# --- BUILD OVS ---
# Note: Artifacts from make debian-deb usually land in the directory ABOVE the build dir.
# Since we build in $ROOT/ovs, debs land in $ROOT.
( cd "$ROOT/ovs" && ./boot.sh )
( cd "$ROOT/ovs" && ./configure --prefix=/usr --libdir=/usr/lib/x86_64-linux-gnu --enable-ssl --enable-shared )
( cd "$ROOT/ovs" && make debian && make debian-deb)

# Install OVS dependencies required for OVN build
cd "$ROOT"
dpkg -i "$ROOT"/openvswitch-*.deb "$ROOT"/python3-openvswitch_*.deb \
       "$ROOT"/openvswitch-common_*.deb "$ROOT"/openvswitch-switch_*.deb \
       "$ROOT"/openvswitch-ipsec_*.deb "$ROOT"/openvswitch-vtep_*.deb \
       "$ROOT"/openvswitch-testcontroller_*.deb "$ROOT"/openvswitch-pki_*.deb \
       "$ROOT"/openvswitch-doc_*.deb "$ROOT"/openvswitch-source_*.deb || true

# --- BUILD OVN ---
cd "$ROOT"
./boot.sh || true

OVSDIR=$ROOT/ovs
OVSBUILDDIR="$OVSDIR/_debian"

# Sanity check
test -f "$OVSBUILDDIR/config.status" || { echo "OVS not configured at $OVSBUILDDIR"; exit 1; }

export OVSDIR OVSBUILDDIR EXTRA_CONFIGURE_OPTS="--with-ovs-build=$OVSBUILDDIR"

# Build OVN Debs (Artifacts land in parent of $ROOT, i.e., $ROOT/../)
DEB_BUILD_OPTIONS=nocheck dpkg-buildpackage -b -us -uc

# --- DEBUG SYMBOLS (optional, PF9_DEBUG_SYMBOLS=true) ---
# dh_strip always generates -dbgsym packages, but Ubuntu's debhelper writes them as
# *.ddeb, which the *.deb globs below never match, and pf9_build_reset would wipe the OVS
# ones. When enabled, collect them before anything is deleted.
if pf9_debug_symbols_enabled; then
    DBGSYM_DIR="$TEAMCITY_ROOT/pkgs/${UBUNTU_VERSION}-dbgsym"
    mkdir -p "$DBGSYM_DIR"
    find "$ROOT" "$TEAMCITY_ROOT" -maxdepth 1 \( -name "*-dbgsym_*.ddeb" -o -name "*-dbgsym_*.deb" \) \
        -exec mv -v {} "$DBGSYM_DIR" \;
    ls -la "$DBGSYM_DIR"
fi

# Remove bloat packages before artifact collection
find "$ROOT" "$TEAMCITY_ROOT" -maxdepth 1 -name "*.deb" \
    \( -name "*-doc_*" -o -name "*-source_*" -o -name "*-test_*" \
       -o -name "*-testcontroller_*" -o -name "*-dbgsym_*" \) \
    -delete -print

# --- ARTIFACT COLLECTION ---
ARTIFACT_DIR="$TEAMCITY_ROOT/pkgs/$UBUNTU_VERSION"
mkdir -p "$ARTIFACT_DIR"

# Move OVS debs (exclude doc/source/test/dbgsym)
find "$ROOT" -maxdepth 1 -name "*.deb" \
    ! -name "*-doc_*" ! -name "*-source_*" \
    ! -name "*-test_*" ! -name "*-testcontroller_*" ! -name "*-dbgsym_*" \
    -exec mv -v {} "$ARTIFACT_DIR" \;

# Move OVN debs (from ROOT/../, exclude doc/source/test/dbgsym)
find "$TEAMCITY_ROOT" -maxdepth 1 -name "*.deb" \
    ! -name "*-doc_*" ! -name "*-source_*" \
    ! -name "*-test_*" ! -name "*-testcontroller_*" ! -name "*-dbgsym_*" \
    -exec mv -v {} "$ARTIFACT_DIR" \;


# --- CLEANUP ---
pf9_build_reset

cd "$ARTIFACT_DIR"
dpkg-scanpackages . /dev/null | gzip -9c > Packages.gz