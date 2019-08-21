FROM ubuntu:16.04
MAINTAINER "Aliasgar Ginwala" <aginwala@ebay.com>

ARG OVN_BRANCH
ARG KERNEL_VERSION
ARG GITHUB_SRC
ARG DISTRO

copy $DISTRO/build.sh /build.sh
RUN /build.sh $KERNEL_VERSION $OVN_BRANCH $GITHUB_SRC

COPY create_ovn_dbs.sh /etc/openvswitch/create_ovn_dbs.sh
RUN /etc/openvswitch/create_ovn_dbs.sh

COPY ovn_default_nb_port /etc/openvswitch/ovn_default_nb_port
COPY ovn_default_sb_port /etc/openvswitch/ovn_default_sb_port
COPY ovn_default_northd_host /etc/openvswitch/ovn_default_northd_host

COPY start-ovn /bin/start-ovn
VOLUME ["/var/log/openvswitch", \
"/var/lib/openvswitch", "/var/run/openvswitch", "/etc/openvswitch"]
ENTRYPOINT ["start-ovn"]
