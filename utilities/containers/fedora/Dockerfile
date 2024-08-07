FROM quay.io/fedora/fedora:40

ARG CONTAINERS_PATH

# Update distro, install packages and clean any possible leftovers
RUN dnf -y update \
    && \
    dnf -y install \
        autoconf \
        automake \
        checkpolicy \
        clang \
        curl \
        dhcp-server \
        ethtool \
        gcc \
        gcc-c++ \
        git \
        glibc-langpack-en \
        groff \
        iproute \
        iproute-tc \
        iputils \
        jemalloc-devel \
        kernel-devel \
        kmod \
        libcap-ng-devel \
        libtool \
        net-tools \
        nfdump \
        ninja-build \
        nmap-ncat \
        numactl-devel \
        openssl \
        openssl-devel \
        procps-ng \
        python3-devel \
        python3-pip \
        rpmdevtools \
        rsync \
        selinux-policy-devel \
        tcpdump \
        unbound \
        unbound-devel \
        wget \
        which \
    && \
    dnf clean all

WORKDIR /workspace

COPY $CONTAINERS_PATH/openbfdd.patch /tmp/openbfdd.patch

COPY $CONTAINERS_PATH/py-requirements.txt /tmp/py-requirements.txt

COPY $CONTAINERS_PATH/prepare.sh /tmp/prepare.sh

RUN /tmp/prepare.sh

CMD ["/usr/sbin/init"]
