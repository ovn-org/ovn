lib_LTLIBRARIES += lib/libovn.la
lib_libovn_la_LDFLAGS = \
        $(OVS_LTINFO) \
        -Wl,--version-script=$(top_builddir)/lib/libovn.sym \
        $(AM_LDFLAGS)
lib_libovn_la_SOURCES = \
	lib/acl-log.c \
	lib/acl-log.h \
	lib/actions.c \
	lib/chassis-index.c \
	lib/chassis-index.h \
	lib/ovn-dirs.h \
	lib/expr.c \
	lib/extend-table.h \
	lib/extend-table.c \
	lib/features.c \
	lib/ovn-parallel-hmap.h \
	lib/ovn-parallel-hmap.c \
	lib/ip-mcast-index.c \
	lib/ip-mcast-index.h \
	lib/mcast-group-index.c \
	lib/mcast-group-index.h \
	lib/lex.c \
	lib/ovn-l7.h \
	lib/ovn-l7.c \
	lib/ovn-util.c \
	lib/ovn-util.h \
	lib/logical-fields.c \
	lib/inc-proc-eng.c \
	lib/inc-proc-eng.h \
	lib/lb.c \
	lib/lb.h
nodist_lib_libovn_la_SOURCES = \
	lib/ovn-dirs.c \
	lib/ovn-nb-idl.c \
	lib/ovn-nb-idl.h \
	lib/ovn-sb-idl.c \
	lib/ovn-sb-idl.h \
	lib/ovn-ic-nb-idl.c \
	lib/ovn-ic-nb-idl.h \
	lib/ovn-ic-sb-idl.c \
	lib/ovn-ic-sb-idl.h

CLEANFILES += $(nodist_lib_libovn_la_SOURCES)

# ovn-sb IDL
OVSIDL_BUILT += \
	lib/ovn-sb-idl.c \
	lib/ovn-sb-idl.h \
	lib/ovn-sb-idl.ovsidl
EXTRA_DIST += \
	lib/ovn-sb-idl.ann \
	lib/ovn-dirs.c.in

lib/ovn-dirs.c: lib/ovn-dirs.c.in Makefile
	$(AM_V_GEN)($(ro_c) && sed < $(srcdir)/lib/ovn-dirs.c.in \
		-e 's,[@]srcdir[@],$(srcdir),g' \
		-e 's,[@]LOGDIR[@],"$(LOGDIR)",g' \
		-e 's,[@]OVN_RUNDIR[@],"$(OVN_RUNDIR)",g' \
		-e 's,[@]DBDIR[@],"$(DBDIR)",g' \
		-e 's,[@]bindir[@],"$(bindir)",g' \
		-e 's,[@]sysconfdir[@],"$(sysconfdir)",g' \
		-e 's,[@]pkgdatadir[@],"$(pkgdatadir)",g') \
	     > lib/ovn-dirs.c.tmp && \
	mv lib/ovn-dirs.c.tmp lib/ovn-dirs.c

OVN_SB_IDL_FILES = \
	$(srcdir)/ovn-sb.ovsschema \
	$(srcdir)/lib/ovn-sb-idl.ann
lib/ovn-sb-idl.ovsidl: $(OVN_SB_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(OVN_SB_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@

# ovn-nb IDL
OVSIDL_BUILT += \
	lib/ovn-nb-idl.c \
	lib/ovn-nb-idl.h \
	lib/ovn-nb-idl.ovsidl
EXTRA_DIST += lib/ovn-nb-idl.ann
OVN_NB_IDL_FILES = \
	$(srcdir)/ovn-nb.ovsschema \
	$(srcdir)/lib/ovn-nb-idl.ann
lib/ovn-nb-idl.ovsidl: $(OVN_NB_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(OVN_NB_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@

# ovn-ic-nb IDL
OVSIDL_BUILT += \
	lib/ovn-ic-nb-idl.c \
	lib/ovn-ic-nb-idl.h \
	lib/ovn-ic-nb-idl.ovsidl
EXTRA_DIST += lib/ovn-ic-nb-idl.ann
OVN_IC_NB_IDL_FILES = \
	$(srcdir)/ovn-ic-nb.ovsschema \
	$(srcdir)/lib/ovn-ic-nb-idl.ann
lib/ovn-ic-nb-idl.ovsidl: $(OVN_IC_NB_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(OVN_IC_NB_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@

# ovn-ic-sb IDL
OVSIDL_BUILT += \
	lib/ovn-ic-sb-idl.c \
	lib/ovn-ic-sb-idl.h \
	lib/ovn-ic-sb-idl.ovsidl
EXTRA_DIST += lib/ovn-ic-sb-idl.ann
OVN_IC_SB_IDL_FILES = \
	$(srcdir)/ovn-ic-sb.ovsschema \
	$(srcdir)/lib/ovn-ic-sb-idl.ann
lib/ovn-ic-sb-idl.ovsidl: $(OVN_IC_SB_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(OVN_IC_SB_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@
