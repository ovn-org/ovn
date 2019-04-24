# ovn-northd
bin_PROGRAMS += northd/ovn-northd
northd_ovn_northd_SOURCES = northd/ovn-northd.c
northd_ovn_northd_LDADD = \
	lib/libovn.la \
	ovs/ovsdb/libovsdb.la \
	ovs/lib/libopenvswitch.la
man_MANS += northd/ovn-northd.8
EXTRA_DIST += northd/ovn-northd.8.xml
CLEANFILES += northd/ovn-northd.8
