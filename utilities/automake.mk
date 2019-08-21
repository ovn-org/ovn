scripts_SCRIPTS += \
    utilities/ovn-ctl \
    utilities/ovndb-servers.ocf

man_MANS += \
    utilities/ovn-ctl.8 \
    utilities/ovn-nbctl.8 \
    utilities/ovn-sbctl.8 \
    utilities/ovn-trace.8 \
    utilities/ovn-detrace.1

MAN_ROOTS += \
    utilities/ovn-sbctl.8.in \
    utilities/ovn-detrace.1.in

# Docker drivers
bin_SCRIPTS += \
    utilities/ovn-docker-overlay-driver \
    utilities/ovn-docker-underlay-driver \
    utilities/ovn-detrace

EXTRA_DIST += \
    utilities/ovn-ctl \
    utilities/ovn-ctl.8.xml \
    utilities/ovn-docker-overlay-driver.in \
    utilities/ovn-docker-underlay-driver.in \
    utilities/ovn-nbctl.8.xml \
    utilities/ovn-trace.8.xml \
    utilities/ovn-detrace.in \
    utilities/ovndb-servers.ocf \
    utilities/checkpatch.py

CLEANFILES += \
    utilities/ovn-ctl.8 \
    utilities/ovn-docker-overlay-driver \
    utilities/ovn-docker-underlay-driver \
    utilities/ovn-nbctl.8 \
    utilities/ovn-sbctl.8 \
    utilities/ovn-trace.8 \
    utilities/ovn-detrace.1 \
    utilities/ovn-detrace

# ovn-nbctl
bin_PROGRAMS += utilities/ovn-nbctl
utilities_ovn_nbctl_SOURCES = utilities/ovn-nbctl.c
utilities_ovn_nbctl_LDADD = lib/libovn.la $(OVSDB_LIBDIR)/libovsdb.la $(OVS_LIBDIR)/libopenvswitch.la

# ovn-sbctl
bin_PROGRAMS += utilities/ovn-sbctl
utilities_ovn_sbctl_SOURCES = utilities/ovn-sbctl.c
utilities_ovn_sbctl_LDADD = lib/libovn.la $(OVSDB_LIBDIR)/libovsdb.la $(OVS_LIBDIR)/libopenvswitch.la

# ovn-trace
bin_PROGRAMS += utilities/ovn-trace
utilities_ovn_trace_SOURCES = utilities/ovn-trace.c
utilities_ovn_trace_LDADD = lib/libovn.la $(OVSDB_LIBDIR)/libovsdb.la $(OVS_LIBDIR)/libopenvswitch.la

include utilities/bugtool/automake.mk
