FROM quay.io/fedora/fedora:38

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
        nmap-ncat \
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

CMD ["/usr/sbin/init"]
