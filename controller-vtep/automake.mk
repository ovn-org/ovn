bin_PROGRAMS += controller-vtep/ovn-controller-vtep
controller_vtep_ovn_controller_vtep_SOURCES = \
	controller-vtep/binding.c \
	controller-vtep/binding.h \
	controller-vtep/gateway.c \
	controller-vtep/gateway.h \
	controller-vtep/ovn-controller-vtep.c \
	controller-vtep/ovn-controller-vtep.h \
	controller-vtep/vtep.c \
	controller-vtep/vtep.h
controller_vtep_ovn_controller_vtep_LDADD = lib/libovn.la $(OVS_LIBDIR)/libopenvswitch.la $(OVSBUILDDIR)/vtep/libvtep.la
man_MANS += controller-vtep/ovn-controller-vtep.8
EXTRA_DIST += controller-vtep/ovn-controller-vtep.8.xml
CLEANFILES += controller-vtep/ovn-controller-vtep.8
