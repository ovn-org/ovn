bin_PROGRAMS += br-controller/ovn-br-controller
br_controller_ovn_br_controller_SOURCES = \
	br-controller/ovn-br-controller.c

br_controller_ovn_br_controller_LDADD = lib/libovn.la $(OVS_LIBDIR)/libopenvswitch.la
man_MANS += br-controller/ovn-br-controller.8
EXTRA_DIST += br-controller/ovn-br-controller.8.xml
CLEANFILES += br-controller/ovn-br-controller.8
