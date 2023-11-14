FROM registry.hub.docker.com/library/ubuntu:22.04

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

WORKDIR /workspace

COPY $CONTAINERS_PATH/py-requirements.txt /tmp/py-requirements.txt

# Update and install pip dependencies
RUN python3 -m pip install --upgrade pip \
    && \
    python3 -m pip install wheel \
    && \
    python3 -m pip install -r /tmp/py-requirements.txt

CMD ["/sbin/init"]
