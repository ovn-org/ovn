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
        ninja-build \
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

WORKDIR /workspace

COPY $CONTAINERS_PATH/openbfdd.patch /tmp/openbfdd.patch

COPY $CONTAINERS_PATH/py-requirements.txt /tmp/py-requirements.txt

COPY $CONTAINERS_PATH/prepare.sh /tmp/prepare.sh

# Ubuntu 24.04 marks the Python installation as externally managed, allow pip
# to install the packages despite that.
ENV PIP_BREAK_SYSTEM_PACKAGES 1

# The Python Babel fails to detect timezone when it is set to UTC only.
ENV TZ Etc/UTC

RUN /tmp/prepare.sh

CMD ["/sbin/init"]
