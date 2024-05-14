FROM registry.hub.docker.com/library/ubuntu:24.04

ARG CONTAINERS_PATH

# Update distro, install packages and clean any possible leftovers
RUN apt update -y \
    && \
    apt upgrade -y \
    && \
    apt install -y \
        automake \
        bc \
        clang \
        curl \
        ethtool \
        gcc \
        git \
        init \
        iproute2 \
        iputils-arping \
        iputils-ping \
        isc-dhcp-server \
        kmod \
        libelf-dev \
        libjemalloc2 \
        libjemalloc-dev \
        libnuma-dev \
        libpcap-dev \
        libssl-dev \
        libtool \
        libunbound-dev \
        libunwind-dev \
        llvm-dev \
        ncat \
        net-tools \
        python3-dev \
        python3-pip \
        selinux-policy-dev \
        sudo \
        tcpdump \
        tzdata \
        wget \
    && \
    apt autoremove \
    && \
    apt clean

# Compile sparse from source
WORKDIR /workspace/sparse

RUN git clone git://git.kernel.org/pub/scm/devel/sparse/sparse.git \
    /workspace/sparse \
    && \
    make -j4 PREFIX=/usr HAVE_LLVM= HAVE_SQLITE= install

# Compile OpenBFDD from source
WORKDIR /workspace/OpenBFDD

COPY $CONTAINERS_PATH/openbfdd.patch /tmp/openbfdd.patch

RUN git clone https://github.com/dyninc/OpenBFDD.git \
    /workspace/OpenBFDD \
    && \
    git apply /tmp/openbfdd.patch \
    && \
    ./autogen.sh \
    && \
    ./configure --enable-silent-rules \
    && \
    make \
    && \
    make install

WORKDIR /workspace

COPY $CONTAINERS_PATH/py-requirements.txt /tmp/py-requirements.txt

# Ubuntu 24.04 marks the Python installation as externally managed, allow pip
# to install the packages despite that.
ENV PIP_BREAK_SYSTEM_PACKAGES 1

# Update and install pip dependencies
RUN python3 -m pip install --upgrade pip \
    && \
    python3 -m pip install wheel \
    && \
    python3 -m pip install -r /tmp/py-requirements.txt

# The Python Babel fails to detect timezone when it is set to UTC only.
ENV TZ Etc/UTC

CMD ["/sbin/init"]
