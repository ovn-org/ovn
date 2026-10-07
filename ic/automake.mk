# ovn-ic
bin_PROGRAMS += ic/ovn-ic
ic_ovn_ic_SOURCES = ic/ovn-ic.c \
	ic/ovn-ic.h \
	ic/en-ic.c \
	ic/en-ic.h \
	ic/en-az.c \
	ic/en-az.h \
	ic/en-gateway.c \
	ic/en-gateway.h \
	ic/en-ts.c \
	ic/en-ts.h \
	ic/en-tr.c \
	ic/en-tr.h \
	ic/en-tunnel-key.c \
	ic/en-tunnel-key.h \
	ic/en-port-binding.c \
	ic/en-port-binding.h \
	ic/en-route.c \
	ic/en-route.h \
	ic/en-service-monitor.c \
	ic/en-service-monitor.h \
	ic/en-address-set.c \
	ic/en-address-set.h \
	ic/inc-proc-ic.c \
	ic/inc-proc-ic.h
ic_ovn_ic_LDADD = \
	lib/libovn.la \
	$(OVSDB_LIBDIR)/libovsdb.la \
	$(OVS_LIBDIR)/libopenvswitch.la
man_MANS += ic/ovn-ic.8
EXTRA_DIST += ic/ovn-ic.8.xml
CLEANFILES += ic/ovn-ic.8
