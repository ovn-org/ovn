#!/bin/bash -xe

function compile_sparse()
{
    git clone git://git.kernel.org/pub/scm/devel/sparse/sparse.git \
        /workspace/sparse

    pushd sparse
    make -j4 PREFIX=/usr HAVE_LLVM= HAVE_SQLITE= install
    popd
}

function install_python_dep()
{
    # The --user should be removed once pip can be upgraded on Ubuntu.
    python3 -m pip install --user --upgrade pip
    python3 -m pip install wheel
    python3 -m pip install -r /tmp/py-requirements.txt
}

compile_sparse
install_python_dep
