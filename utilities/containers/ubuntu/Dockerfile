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
        nftables \
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

WORKDIR /workspace

COPY $CONTAINERS_PATH/py-requirements.txt /tmp/py-requirements.txt

COPY $CONTAINERS_PATH/prepare.sh /tmp/prepare.sh

RUN /tmp/prepare.sh

CMD ["/sbin/init"]
