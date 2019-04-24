# libovsdb
lib_LTLIBRARIES += ovs/ovsdb/libovsdb.la
ovs_ovsdb_libovsdb_la_LDFLAGS = \
        $(OVS_LTINFO) \
        -Wl,--version-script=$(top_builddir)/ovs/sovsdb/libovsdb.sym \
        $(AM_LDFLAGS)
ovs_ovsdb_libovsdb_la_SOURCES = \
	ovs/ovsdb/column.c \
	ovs/ovsdb/column.h \
	ovs/ovsdb/condition.c \
	ovs/ovsdb/condition.h \
	ovs/ovsdb/execution.c \
	ovs/ovsdb/file.c \
	ovs/ovsdb/file.h \
	ovs/ovsdb/jsonrpc-server.c \
	ovs/ovsdb/jsonrpc-server.h \
	ovs/ovsdb/log.c \
	ovs/ovsdb/log.h \
	ovs/ovsdb/mutation.c \
	ovs/ovsdb/mutation.h \
	ovs/ovsdb/ovsdb.c \
	ovs/ovsdb/ovsdb.h \
	ovs/ovsdb/monitor.c \
	ovs/ovsdb/monitor.h \
	ovs/ovsdb/query.c \
	ovs/ovsdb/query.h \
	ovs/ovsdb/raft.c \
	ovs/ovsdb/raft.h \
	ovs/ovsdb/raft-private.c \
	ovs/ovsdb/raft-private.h \
	ovs/ovsdb/raft-rpc.c \
	ovs/ovsdb/raft-rpc.h \
	ovs/ovsdb/rbac.c \
	ovs/ovsdb/rbac.h \
	ovs/ovsdb/replication.c \
	ovs/ovsdb/replication.h \
	ovs/ovsdb/row.c \
	ovs/ovsdb/row.h \
	ovs/ovsdb/server.c \
	ovs/ovsdb/server.h \
	ovs/ovsdb/storage.c \
	ovs/ovsdb/storage.h \
	ovs/ovsdb/table.c \
	ovs/ovsdb/table.h \
	ovs/ovsdb/trigger.c \
	ovs/ovsdb/trigger.h \
	ovs/ovsdb/transaction.c \
	ovs/ovsdb/transaction.h \
	ovs/ovsdb/ovsdb-util.c \
	ovs/ovsdb/ovsdb-util.h
ovs_ovsdb_libovsdb_la_CFLAGS = $(AM_CFLAGS)
ovs_ovsdb_libovsdb_la_CPPFLAGS = $(AM_CPPFLAGS)

pkgconfig_DATA += \
	ovs/ovsdb/libovsdb.pc

MAN_FRAGMENTS += ovs/ovsdb/ovsdb-schemas.man

# ovsdb-tool
bin_PROGRAMS += ovs/ovsdb/ovsdb-tool
ovs_ovsdb_ovsdb_tool_SOURCES = ovs/ovsdb/ovsdb-tool.c
ovs_ovsdb_ovsdb_tool_LDADD = ovs/ovsdb/libovsdb.la ovs/lib/libopenvswitch.la
# ovsdb-tool.1
man_MANS += ovs/ovsdb/ovsdb-tool.1
CLEANFILES += ovs/ovsdb/ovsdb-tool.1
MAN_ROOTS += ovs/ovsdb/ovsdb-tool.1.in

# ovsdb-client
bin_PROGRAMS += ovs/ovsdb/ovsdb-client
ovs_ovsdb_ovsdb_client_SOURCES = ovs/ovsdb/ovsdb-client.c
ovs_ovsdb_ovsdb_client_LDADD = ovs/ovsdb/libovsdb.la ovs/lib/libopenvswitch.la
# ovsdb-client.1
man_MANS += ovs/ovsdb/ovsdb-client.1
CLEANFILES += ovs/ovsdb/ovsdb-client.1
MAN_ROOTS += ovs/ovsdb/ovsdb-client.1.in

# ovsdb-server
sbin_PROGRAMS += ovs/ovsdb/ovsdb-server
ovs_ovsdb_ovsdb_server_SOURCES = ovs/ovsdb/ovsdb-server.c
ovs_ovsdb_ovsdb_server_LDADD = ovs/ovsdb/libovsdb.la ovs/lib/libopenvswitch.la
# ovsdb-server.1
man_MANS += ovs/ovsdb/ovsdb-server.1
CLEANFILES += ovs/ovsdb/ovsdb-server.1
MAN_ROOTS += ovs/ovsdb/ovsdb-server.1.in

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

# ovsdb-doc
EXTRA_DIST += ovs/ovsdb/ovsdb-doc
OVSDB_DOC = $(run_python) $(srcdir)/ovs/ovsdb/ovsdb-doc

# ovsdb-dot
EXTRA_DIST += ovs/ovsdb/ovsdb-dot.in ovs/ovsdb/dot2pic
noinst_SCRIPTS += ovs/ovsdb/ovsdb-dot
CLEANFILES += ovs/ovsdb/ovsdb-dot
OVSDB_DOT = $(run_python) $(srcdir)/ovs/ovsdb/ovsdb-dot.in

EXTRA_DIST += ovs/ovsdb/_server.ovsschema
CLEANFILES += ovs/ovsdb/_server.ovsschema.inc
ovsdb/ovsdb-server.$(OBJEXT): ovs/ovsdb/_server.ovsschema.inc
ovsdb/_server.ovsschema.inc: ovs/ovsdb/_server.ovsschema $(srcdir)/build-aux/text2c
	$(AM_V_GEN)$(run_python) $(srcdir)/build-aux/text2c < $< > $@.tmp
	$(AM_V_at)mv $@.tmp $@

# Version checking for _server.ovsschema.
ALL_LOCAL += ovs/ovsdb/_server.ovsschema.stamp
ovs/ovsdb/_server.ovsschema.stamp: ovs/ovsdb/_server.ovsschema
	$(srcdir)/ovs/build-aux/cksum-schema-check $? $@
CLEANFILES += ovs/ovsdb/_server.ovsschema.stamp

# _Server schema documentation
EXTRA_DIST += ovs/ovsdb/_server.xml
CLEANFILES += ovs/ovsdb/ovsdb-server.5
man_MANS += ovs/ovsdb/ovsdb-server.5
ovs/ovsdb/ovsdb-server.5: \
	ovs/ovsdb/ovsdb-doc ovs/ovsdb/_server.xml ovs/ovsdb/_server.ovsschema
	$(AM_V_GEN)$(OVSDB_DOC) \
		--version=$(VERSION) \
		$(srcdir)/ovs/ovsdb/_server.ovsschema \
		$(srcdir)/ovs/ovsdb/_server.xml > $@.tmp && \
	mv $@.tmp $@

EXTRA_DIST += ovs/ovsdb/TODO.rst
