ARG OVNKUBE_COMMIT=master
ARG GO_VERSION

FROM fedora:37 AS ovnbuilder

USER root

ENV PYTHONDONTWRITEBYTECODE yes

# install needed rpms - openvswitch must be 2.10.4 or higher
RUN INSTALL_PKGS=" rpm-build dnf-plugins-core" && \
    dnf install --best --refresh -y --setopt=tsflags=nodocs $INSTALL_PKGS

# Build OVS and OVN rpms from current folder
RUN mkdir /tmp/ovn
COPY . /tmp/ovn
WORKDIR /tmp/ovn/ovs

RUN sed -e 's/@VERSION@/0.0.1/' rhel/openvswitch-fedora.spec.in > /tmp/ovs.spec
RUN dnf builddep -y /tmp/ovs.spec
RUN ./boot.sh
RUN ./configure -v
RUN make rpm-fedora
RUN rm rpm/rpmbuild/RPMS/x86_64/*debug*
RUN rm rpm/rpmbuild/RPMS/x86_64/*devel*

WORKDIR /tmp/ovn
RUN sed -e 's/@VERSION@/0.0.1/' rhel/ovn-fedora.spec.in > /tmp/ovn.spec
RUN dnf builddep -y /tmp/ovn.spec
RUN ./boot.sh
RUN ./configure
RUN make rpm-fedora
RUN rm rpm/rpmbuild/RPMS/x86_64/*debug*
RUN rm rpm/rpmbuild/RPMS/x86_64/*docker*

# Build ovn-kubernetes
ARG GO_VERSION
FROM golang:$GO_VERSION as ovnkubebuilder
ARG OVNKUBE_COMMIT

# Clone OVN Kubernetes and build the binary based on the commit passed as argument
WORKDIR /root
RUN git clone https://github.com/ovn-org/ovn-kubernetes.git
WORKDIR /root/ovn-kubernetes
RUN git checkout ${OVNKUBE_COMMIT} && git log -n 1

# Copy the ovn-kubernetes scripts from the OVN sources and apply any
# custom changes if needed.
RUN mkdir -p /tmp/ovn/.ci/ovn-kubernetes
COPY .ci/ovn-kubernetes /tmp/ovn/.ci/ovn-kubernetes
WORKDIR /tmp/ovn
RUN .ci/ovn-kubernetes/prepare.sh /root/ovn-kubernetes /dev/null

WORKDIR /root/ovn-kubernetes/go-controller
# Get a working version of libovsdb (for modelgen).
RUN GO111MODULE=on go install github.com/ovn-org/libovsdb/cmd/modelgen@$( \
    go list -mod=mod -m -f '{{ .Version }}' github.com/ovn-org/libovsdb \
)

# Make sure we use the OVN NB/SB schema from the local code.
COPY --from=ovnbuilder /tmp/ovn/ovn-nb.ovsschema pkg/nbdb/ovn-nb.ovsschema
COPY --from=ovnbuilder /tmp/ovn/ovn-sb.ovsschema pkg/sbdb/ovn-sb.ovsschema
RUN go generate ./pkg/nbdb && go generate ./pkg/sbdb && make

# Build the final image
FROM fedora:37

# install needed dependencies
RUN INSTALL_PKGS=" \
    iptables iproute iputils hostname unbound-libs kubernetes-client kmod socat" && \
    dnf install --best --refresh -y --setopt=tsflags=nodocs $INSTALL_PKGS

RUN mkdir -p /var/run/openvswitch

# install openvswitch and ovn rpms built in previous stages
COPY --from=ovnbuilder /tmp/ovn/rpm/rpmbuild/RPMS/x86_64/*rpm ./
COPY --from=ovnbuilder /tmp/ovn/ovs/rpm/rpmbuild/RPMS/x86_64/*rpm ./
COPY --from=ovnbuilder /tmp/ovn/ovs/rpm/rpmbuild/RPMS/noarch/*rpm ./
RUN dnf install -y *.rpm && rm -f *.rpm

# install ovn-kubernetes binaries built in previous stage
RUN mkdir -p /usr/libexec/cni/
COPY --from=ovnkubebuilder /root/ovn-kubernetes/go-controller/_output/go/bin/ovnkube /usr/bin/
COPY --from=ovnkubebuilder /root/ovn-kubernetes/go-controller/_output/go/bin/ovnkube-identity /usr/bin/
COPY --from=ovnkubebuilder /root/ovn-kubernetes/go-controller/_output/go/bin/ovn-kube-util /usr/bin/
COPY --from=ovnkubebuilder /root/ovn-kubernetes/go-controller/_output/go/bin/ovndbchecker /usr/bin/
COPY --from=ovnkubebuilder /root/ovn-kubernetes/go-controller/_output/go/bin/ovn-k8s-cni-overlay /usr/libexec/cni/ovn-k8s-cni-overlay

# ovnkube.sh is the entry point. This script examines environment
# variables to direct operation and configure ovn
COPY --from=ovnkubebuilder /root/ovn-kubernetes/dist/images/ovnkube.sh /root/
COPY --from=ovnkubebuilder /root/ovn-kubernetes/dist/images/ovndb-raft-functions.sh /root/
COPY --from=ovnkubebuilder /root/ovn-kubernetes/dist/images/iptables-scripts /usr/sbin/

# Make some room.
RUN REMOVE_PKGS="llvm-libs clang-libs" && \
    dnf remove -y $REMOVE_PKGS && dnf clean all && rm -rf /var/cache/dnf/*

LABEL io.k8s.display-name="ovn-kubernetes" \
    io.k8s.description="This is a Kubernetes network plugin that provides an overlay network using OVN." \
    maintainer="ovn team"

WORKDIR /root
ENTRYPOINT /root/ovnkube.sh
