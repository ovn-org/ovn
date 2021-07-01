ARG OVNKUBE_COMMIT=master

FROM fedora:33 AS ovnbuilder

USER root

ENV PYTHONDONTWRITEBYTECODE yes

# install needed rpms - openvswitch must be 2.10.4 or higher
RUN INSTALL_PKGS=" \
    python3-pyyaml bind-utils procps-ng openssl numactl-libs firewalld-filesystem \
    libpcap hostname \
    python3-openvswitch python3-pyOpenSSL \
    autoconf automake libtool g++ gcc fedora-packager rpmdevtools \
    unbound unbound-devel groff python3-sphinx graphviz openssl openssl-devel \
    checkpolicy libcap-ng-devel selinux-policy-devel" && \
    dnf install --best --refresh -y --setopt=tsflags=nodocs $INSTALL_PKGS && \
    dnf clean all && rm -rf /var/cache/dnf/*

# Build OVS and OVN rpms from current folder
RUN mkdir /tmp/ovn
COPY . /tmp/ovn
WORKDIR /tmp/ovn/ovs

RUN ./boot.sh
RUN ./configure -v
RUN make && make rpm-fedora
RUN rm rpm/rpmbuild/RPMS/x86_64/*debug*
RUN rm rpm/rpmbuild/RPMS/x86_64/*devel*

WORKDIR /tmp/ovn
RUN ./boot.sh
RUN ./configure
RUN make && make rpm-fedora
RUN rm rpm/rpmbuild/RPMS/x86_64/*debug*
RUN rm rpm/rpmbuild/RPMS/x86_64/*docker*

# Build ovn-kubernetes
FROM golang:1.16 as ovnkubebuilder
ARG OVNKUBE_COMMIT
# Clone OVN Kubernetes and build the binary based on the commit passed as argument
WORKDIR /root
RUN git clone https://github.com/ovn-org/ovn-kubernetes.git
WORKDIR /root/ovn-kubernetes/go-controller
RUN git checkout ${OVNKUBE_COMMIT} && make

# Build the final image
FROM fedora:33

# install needed dependencies
RUN INSTALL_PKGS=" \
    iptables iproute iputils hostname unbound-libs kubernetes-client kmod" && \
    dnf install --best --refresh -y --setopt=tsflags=nodocs $INSTALL_PKGS && \
    dnf clean all && rm -rf /var/cache/dnf/*

RUN mkdir -p /var/run/openvswitch

# install openvswitch and ovn rpms built in previous stages
COPY --from=ovnbuilder /tmp/ovn/rpm/rpmbuild/RPMS/x86_64/*rpm ./
COPY --from=ovnbuilder /tmp/ovn/ovs/rpm/rpmbuild/RPMS/x86_64/*rpm ./
RUN dnf install -y *.rpm && rm -f *.rpm

# install ovn-kubernetes binaries built in previous stage
RUN mkdir -p /usr/libexec/cni/
COPY --from=ovnkubebuilder /root/ovn-kubernetes/go-controller/_output/go/bin/ovnkube /usr/bin/
COPY --from=ovnkubebuilder /root/ovn-kubernetes/go-controller/_output/go/bin/ovn-kube-util /usr/bin/
COPY --from=ovnkubebuilder /root/ovn-kubernetes/go-controller/_output/go/bin/ovndbchecker /usr/bin/
COPY --from=ovnkubebuilder /root/ovn-kubernetes/go-controller/_output/go/bin/ovn-k8s-cni-overlay /usr/libexec/cni/ovn-k8s-cni-overlay

# ovnkube.sh is the entry point. This script examines environment
# variables to direct operation and configure ovn
COPY --from=ovnkubebuilder /root/ovn-kubernetes/dist/images/ovnkube.sh /root/
COPY --from=ovnkubebuilder /root/ovn-kubernetes/dist/images/ovndb-raft-functions.sh /root/
COPY --from=ovnkubebuilder /root/ovn-kubernetes/dist/images/iptables-scripts /usr/sbin/

LABEL io.k8s.display-name="ovn-kubernetes" \
    io.k8s.description="This is a Kubernetes network plugin that provides an overlay network using OVN." \
    maintainer="ovn team"

WORKDIR /root
ENTRYPOINT /root/ovnkube.sh
