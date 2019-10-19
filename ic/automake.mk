# ovn-ic
bin_PROGRAMS += ic/ovn-ic
ic_ovn_ic_SOURCES = ic/ovn-ic.c
ic_ovn_ic_LDADD = \
	lib/libovn.la \
	$(OVSDB_LIBDIR)/libovsdb.la \
	$(OVS_LIBDIR)/libopenvswitch.la
man_MANS += ic/ovn-ic.8
EXTRA_DIST += ic/ovn-ic.8.xml
CLEANFILES += ic/ovn-ic.8
