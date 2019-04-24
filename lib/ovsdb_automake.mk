# ovsdb-idlc
noinst_SCRIPTS += ovs/ovsdb/ovsdb-idlc
EXTRA_DIST += ovs/ovsdb/ovsdb-idlc.in
MAN_ROOTS += ovs/ovsdb/ovsdb-idlc.1
CLEANFILES += ovs/ovsdb/ovsdb-idlc
SUFFIXES += .ovsidl .ovsschema
OVSDB_IDLC = $(run_python) $(srcdir)/ovs/ovsdb/ovsdb-idlc.in
.ovsidl.c:
	$(AM_V_GEN)$(OVSDB_IDLC) c-idl-source $< > $@.tmp && mv $@.tmp $@
.ovsidl.h:
	$(AM_V_GEN)$(OVSDB_IDLC) c-idl-header $< > $@.tmp && mv $@.tmp $@

BUILT_SOURCES += $(OVSIDL_BUILT)
CLEANFILES += $(OVSIDL_BUILT)

# This must be done late: macros in targets are expanded when the
# target line is read, so if this file were to be included before some
# other file that added to OVSIDL_BUILT, then those files wouldn't get
# the dependency.
#
# However, current versions of Automake seem to output all variable
# assignments before any targets, so it doesn't seem to be a problem,
# at least for now.
$(OVSIDL_BUILT): ovs/ovsdb/ovsdb-idlc.in

