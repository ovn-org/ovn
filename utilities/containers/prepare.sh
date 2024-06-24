#!/bin/bash -xe

DPDK_GIT=https://dpdk.org/git/dpdk
DPDK_VER=23.11

function compile_sparse()
{
    git clone git://git.kernel.org/pub/scm/devel/sparse/sparse.git \
        /workspace/sparse

    pushd sparse
    make -j4 PREFIX=/usr HAVE_LLVM= HAVE_SQLITE= install
    popd
}

function compile_openbfdd()
{
    git clone https://github.com/dyninc/OpenBFDD.git \
        /workspace/OpenBFDD

    pushd OpenBFDD
    git apply /tmp/openbfdd.patch
    ./autogen.sh
    ./configure --enable-silent-rules
    make
    make install
    popd
}

function install_python_dep()
{
    # The --user should be removed once pip can be upgraded on Ubuntu.
    python3 -m pip install --user --upgrade pip
    python3 -m pip install wheel
    python3 -m pip install -r /tmp/py-requirements.txt
}

function build_dpdk()
{
      local DPDK_OPTS=""
      local DPDK_INSTALL_DIR="$(pwd)/dpdk-dir"
      local VERSION_FILE="$DPDK_INSTALL_DIR/cached-version"

      if [ "${DPDK_VER##refs/*/}" != "${DPDK_VER}" ]; then
          git clone --single-branch $DPDK_GIT dpdk-src \
              -b "${DPDK_VER##refs/*/}"
          pushd dpdk-src
          git log -1 --oneline
      else
          curl -O https://fast.dpdk.org/rel/dpdk-$DPDK_VER.tar.xz
          tar --no-same-owner -xvf dpdk-$DPDK_VER.tar.xz > /dev/null
          DIR_NAME=$(tar -tf dpdk-$DPDK_VER.tar.xz | head -1 | cut -f1 -d"/")
          mv ${DIR_NAME} dpdk-src
          pushd dpdk-src
      fi

      # Switching to 'default' machine to make the dpdk cache usable on
      # different CPUs. We can't be sure that all CI machines are exactly same.
      DPDK_OPTS="$DPDK_OPTS -Dmachine=default"

      # Disable building DPDK unit tests. Not needed for OVS build or tests.
      DPDK_OPTS="$DPDK_OPTS -Dtests=false"

      # Disable DPDK developer mode, this results in less build checks and less
      # meson verbose outputs.
      DPDK_OPTS="$DPDK_OPTS -Ddeveloper_mode=disabled"

      # OVS compilation and the "ovn-system-dpdk" unit tests (run in the CI)
      # only depend on virtio/tap drivers.
      # We can disable all remaining drivers to save compilation time.
      DPDK_OPTS="$DPDK_OPTS -Denable_drivers=net/null,net/tap,net/virtio"
      # OVS depends on the vhost library (and its dependencies).
      # net/tap depends on the gso library.
      DPDK_OPTS="$DPDK_OPTS -Denable_libs=cryptodev,dmadev,gso,vhost"

      # Install DPDK using prefix.
      DPDK_OPTS="$DPDK_OPTS --prefix=$DPDK_INSTALL_DIR"

      meson $DPDK_OPTS build
      ninja -C build
      ninja -C build install
      popd

      # Remove examples sources.
      rm -rf $DPDK_INSTALL_DIR/share/dpdk/examples

      echo "${DPDK_VER}" > ${VERSION_FILE}
}

compile_sparse
compile_openbfdd
install_python_dep
build_dpdk
