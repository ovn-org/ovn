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
	lib/expr.c \
	lib/extend-table.h \
	lib/extend-table.c \
	lib/lex.c \
	lib/ovn-l7.h \
	lib/ovn-util.c \
	lib/ovn-util.h \
	lib/logical-fields.c
nodist_lib_libovn_la_SOURCES = \
	lib/ovn-nb-idl.c \
	lib/ovn-nb-idl.h \
	lib/ovn-sb-idl.c \
	lib/ovn-sb-idl.h

# ovn-sb IDL
OVSIDL_BUILT += \
	lib/ovn-sb-idl.c \
	lib/ovn-sb-idl.h \
	lib/ovn-sb-idl.ovsidl
EXTRA_DIST += lib/ovn-sb-idl.ann
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

