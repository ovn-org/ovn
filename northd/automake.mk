# ovn-northd
bin_PROGRAMS += northd/ovn-northd
northd_ovn_northd_SOURCES = \
	northd/aging.c \
	northd/aging.h \
	northd/debug.c \
	northd/debug.h \
	northd/northd.c \
	northd/northd.h \
	northd/ovn-northd.c \
	northd/en-northd.c \
	northd/en-northd.h \
	northd/en-lflow.c \
	northd/en-lflow.h \
	northd/en-meters.c \
	northd/en-meters.h \
	northd/en-northd-output.c \
	northd/en-northd-output.h \
	northd/en-port-group.c \
	northd/en-port-group.h \
	northd/en-sync-sb.c \
	northd/en-sync-sb.h \
	northd/en-sync-from-sb.c \
	northd/en-sync-from-sb.h \
	northd/en-lb-data.c \
	northd/en-lb-data.h \
	northd/en-lr-nat.c \
	northd/en-lr-nat.h \
	northd/en-lr-stateful.c \
	northd/en-lr-stateful.h \
	northd/en-ls-stateful.c \
	northd/en-ls-stateful.h \
	northd/inc-proc-northd.c \
	northd/inc-proc-northd.h \
	northd/ipam.c \
	northd/ipam.h
northd_ovn_northd_LDADD = \
	lib/libovn.la \
	$(OVSDB_LIBDIR)/libovsdb.la \
	$(OVS_LIBDIR)/libopenvswitch.la
man_MANS += northd/ovn-northd.8
EXTRA_DIST += northd/ovn-northd.8.xml
CLEANFILES += northd/ovn-northd.8
