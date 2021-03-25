scripts_SCRIPTS += \
    utilities/ovn-ctl \
    utilities/ovndb-servers.ocf
scripts_DATA += utilities/ovn-lib

man_MANS += \
    utilities/ovn-ctl.8 \
    utilities/ovn-nbctl.8 \
    utilities/ovn-sbctl.8 \
    utilities/ovn-ic-nbctl.8 \
    utilities/ovn-ic-sbctl.8 \
    utilities/ovn-trace.8 \
    utilities/ovn-detrace.1 \
    utilities/ovn-appctl.8

MAN_ROOTS += \
    utilities/ovn-detrace.1.in

# Docker drivers
bin_SCRIPTS += \
    utilities/ovn-docker-overlay-driver \
    utilities/ovn-docker-underlay-driver \
    utilities/ovn-detrace

EXTRA_DIST += \
    utilities/ovn-ctl \
    utilities/ovn-lib.in \
    utilities/ovn-ctl.8.xml \
    utilities/ovn-docker-overlay-driver.in \
    utilities/ovn-docker-underlay-driver.in \
    utilities/ovn-nbctl.8.xml \
    utilities/ovn-sbctl.8.xml \
    utilities/ovn-ic-nbctl.8.xml \
    utilities/ovn-ic-sbctl.8.xml \
    utilities/ovn-appctl.8.xml \
    utilities/ovn-trace.8.xml \
    utilities/ovn-detrace.in \
    utilities/ovndb-servers.ocf \
    utilities/checkpatch.py \
    utilities/docker/Makefile \
    utilities/docker/start-ovn \
    utilities/docker/ovn_default_nb_port \
    utilities/docker/ovn_default_sb_port \
    utilities/docker/ovn_default_northd_host \
    utilities/docker/debian/Dockerfile \
    utilities/docker/debian/build.sh \
    utilities/docker/rhel/Dockerfile \
    utilities/docker/rhel/build.sh \
    utilities/docker/install_ovn.sh

CLEANFILES += \
    utilities/ovn-ctl.8 \
    utilities/ovn-lib \
    utilities/ovn-docker-overlay-driver \
    utilities/ovn-docker-underlay-driver \
    utilities/ovn-nbctl.8 \
    utilities/ovn-sbctl.8 \
    utilities/ovn-ic-nbctl.8 \
    utilities/ovn-ic-sbctl.8 \
    utilities/ovn-trace.8 \
    utilities/ovn-detrace.1 \
    utilities/ovn-detrace \
    utilities/ovn-appctl.8 \
    utilities/ovn-appctl \
    utilities/ovn-sim

EXTRA_DIST += utilities/ovn-sim.in
noinst_SCRIPTS += utilities/ovn-sim

utilities/ovn-lib: $(top_builddir)/config.status

# ovn-nbctl
bin_PROGRAMS += utilities/ovn-nbctl
utilities_ovn_nbctl_SOURCES = \
    utilities/ovn-dbctl.c \
    utilities/ovn-dbctl.h \
    utilities/ovn-nbctl.c
utilities_ovn_nbctl_LDADD = lib/libovn.la $(OVSDB_LIBDIR)/libovsdb.la $(OVS_LIBDIR)/libopenvswitch.la

# ovn-sbctl
bin_PROGRAMS += utilities/ovn-sbctl
utilities_ovn_sbctl_SOURCES = \
    utilities/ovn-dbctl.c \
    utilities/ovn-dbctl.h \
    utilities/ovn-sbctl.c
utilities_ovn_sbctl_LDADD = lib/libovn.la $(OVSDB_LIBDIR)/libovsdb.la $(OVS_LIBDIR)/libopenvswitch.la

# ovn-ic-nbctl
bin_PROGRAMS += utilities/ovn-ic-nbctl
utilities_ovn_ic_nbctl_SOURCES = utilities/ovn-ic-nbctl.c
utilities_ovn_ic_nbctl_LDADD = lib/libovn.la $(OVSDB_LIBDIR)/libovsdb.la $(OVS_LIBDIR)/libopenvswitch.la

# ovn-ic-sbctl
bin_PROGRAMS += utilities/ovn-ic-sbctl
utilities_ovn_ic_sbctl_SOURCES = utilities/ovn-ic-sbctl.c
utilities_ovn_ic_sbctl_LDADD = lib/libovn.la $(OVSDB_LIBDIR)/libovsdb.la $(OVS_LIBDIR)/libopenvswitch.la

# ovn-trace
bin_PROGRAMS += utilities/ovn-trace
utilities_ovn_trace_SOURCES = utilities/ovn-trace.c
utilities_ovn_trace_LDADD = lib/libovn.la $(OVSDB_LIBDIR)/libovsdb.la $(OVS_LIBDIR)/libopenvswitch.la

# ovn-nbctl
bin_PROGRAMS += utilities/ovn-appctl
utilities_ovn_appctl_SOURCES = utilities/ovn-appctl.c
utilities_ovn_appctl_LDADD = lib/libovn.la $(OVSDB_LIBDIR)/libovsdb.la $(OVS_LIBDIR)/libopenvswitch.la

include utilities/bugtool/automake.mk
