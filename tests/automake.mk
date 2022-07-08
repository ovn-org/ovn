EXTRA_DIST += \
	$(COMMON_MACROS_AT) \
	$(TESTSUITE_AT) \
	$(SYSTEM_TESTSUITE_AT) \
	$(SYSTEM_KMOD_TESTSUITE_AT) \
	$(SYSTEM_USERSPACE_TESTSUITE_AT) \
	$(PERF_TESTSUITE_AT) \
	$(TESTSUITE) \
	$(SYSTEM_KMOD_TESTSUITE) \
	$(SYSTEM_USERSPACE_TESTSUITE) \
	$(PERF_TESTSUITE) \
	tests/atlocal.in \
	$(srcdir)/package.m4 \
	$(srcdir)/tests/testsuite \
	$(srcdir)/tests/testsuite.patch

COMMON_MACROS_AT = \
	tests/ovsdb-macros.at \
	tests/ovs-macros.at \
	tests/ofproto-macros.at

TESTSUITE_AT = \
	tests/testsuite.at \
	tests/checkpatch.at \
	tests/network-functions.at \
	tests/ovn.at \
	tests/ovn-northd.at \
	tests/ovn-nbctl.at \
	tests/ovn-sbctl.at \
	tests/ovn-ic-nbctl.at \
	tests/ovn-ic-sbctl.at \
	tests/ovn-controller.at \
	tests/ovn-controller-vtep.at \
	tests/ovn-ic.at \
	tests/ovn-macros.at \
	tests/ovn-performance.at \
	tests/ovn-ofctrl-seqno.at \
	tests/ovn-ipam.at \
	tests/ovn-features.at \
	tests/ovn-lflow-cache.at \
	tests/ovn-lflow-conj-ids.at \
	tests/ovn-ipsec.at \
	tests/ovn-vif-plug.at

SYSTEM_KMOD_TESTSUITE_AT = \
	tests/system-common-macros.at \
	tests/system-kmod-testsuite.at \
	tests/system-kmod-macros.at

SYSTEM_USERSPACE_TESTSUITE_AT = \
	tests/system-userspace-testsuite.at \
	tests/system-ovn.at \
	tests/system-userspace-macros.at

SYSTEM_TESTSUITE_AT = \
	tests/system-common-macros.at \
	tests/system-ovn.at \
	tests/system-ovn-kmod.at

PERF_TESTSUITE_AT = \
	tests/perf-testsuite.at \
	tests/perf-northd.at

check_SCRIPTS += tests/atlocal

TESTSUITE = $(srcdir)/tests/testsuite
TESTSUITE_PATCH = $(srcdir)/tests/testsuite.patch
TESTSUITE_DIR = $(abs_top_builddir)/tests/testsuite.dir
SYSTEM_KMOD_TESTSUITE = $(srcdir)/tests/system-kmod-testsuite
SYSTEM_USERSPACE_TESTSUITE = $(srcdir)/tests/system-userspace-testsuite
PERF_TESTSUITE = $(srcdir)/tests/perf-testsuite
PERF_TESTSUITE_DIR = $(abs_top_builddir)/tests/perf-testsuite.dir
PERF_TESTSUITE_RESULTS = $(PERF_TESTSUITE_DIR)/results
DISTCLEANFILES += tests/atconfig tests/atlocal

AUTOTEST_PATH = $(ovs_builddir)/utilities:$(ovs_builddir)/vswitchd:$(ovs_builddir)/ovsdb:$(ovs_builddir)/vtep:tests:$(PTHREAD_WIN32_DIR_DLL):$(SSL_DIR):controller-vtep:northd:utilities:controller:ic

export ovs_srcdir

check-local:
	set $(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH=$(AUTOTEST_PATH); \
	"$$@" $(TESTSUITEFLAGS) || \
	(test -z "$$(find $(TESTSUITE_DIR) -name 'sanitizers.*')" && \
	 test X'$(RECHECK)' = Xyes && "$$@" --recheck)

# Python Coverage support.
# Requires coverage.py http://nedbatchelder.com/code/coverage/.

COVERAGE = coverage
COVERAGE_FILE='$(abs_srcdir)/.coverage'
check-pycov: all clean-pycov
	PYTHONDONTWRITEBYTECODE=yes COVERAGE_FILE=$(COVERAGE_FILE) PYTHON='$(COVERAGE) run -p' $(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH=$(AUTOTEST_PATH) $(TESTSUITEFLAGS)
	@cd $(srcdir) && $(COVERAGE) combine && COVERAGE_FILE=$(COVERAGE_FILE) $(COVERAGE) annotate
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Annotated coverage source has the ",cover" extension.'
	@echo '----------------------------------------------------------------------'
	@echo
	@COVERAGE_FILE=$(COVERAGE_FILE) $(COVERAGE) report

# lcov support
# Requires build with --enable-coverage and lcov/genhtml in $PATH
CLEAN_LOCAL += clean-lcov
clean-lcov:
	rm -fr tests/lcov

LCOV_OPTS = -b $(abs_top_builddir) -d $(abs_top_builddir) -q -c --rc lcov_branch_coverage=1
GENHTML_OPTS = -q --branch-coverage --num-spaces 4
check-lcov: all $(check_DATA) clean-lcov
	find . -name '*.gcda' | xargs -n1 rm -f
	-set $(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH=$(AUTOTEST_PATH); \
	"$$@" $(TESTSUITEFLAGS) || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)
	$(MKDIR_P) tests/lcov
	lcov $(LCOV_OPTS) -o tests/lcov/coverage.info
	genhtml $(GENHTML_OPTS) -o tests/lcov tests/lcov/coverage.info
	@echo "coverage report generated at tests/lcov/index.html"

# valgrind support

valgrind_wrappers = \
	tests/valgrind/ovn-controller \
	tests/valgrind/ovn-controller-vtep \
	tests/valgrind/ovn-nbctl \
	tests/valgrind/ovn-northd \
	tests/valgrind/ovn-sbctl \
	tests/valgrind/ovn-ic-nbctl \
	tests/valgrind/ovn-ic-sbctl \
	tests/valgrind/ovn-ic \
	tests/valgrind/ovs-appctl \
	tests/valgrind/ovs-ofctl \
	tests/valgrind/ovs-vsctl \
	tests/valgrind/ovs-vswitchd \
	tests/valgrind/ovsdb-client \
	tests/valgrind/ovsdb-server \
	tests/valgrind/ovsdb-tool \
	tests/valgrind/ovstest \
	tests/valgrind/test-ovsdb \
	tests/valgrind/test-skiplist \
	tests/valgrind/test-strtok_r \
	tests/valgrind/test-type-props

$(valgrind_wrappers): tests/valgrind-wrapper.in
	@$(MKDIR_P) tests/valgrind
	$(AM_V_GEN) sed -e 's,[@]wrap_program[@],$@,' \
		$(top_srcdir)/tests/valgrind-wrapper.in > $@.tmp && \
	chmod +x $@.tmp && \
	mv $@.tmp $@
CLEANFILES += $(valgrind_wrappers)
EXTRA_DIST += tests/valgrind-wrapper.in

VALGRIND = valgrind --log-file=valgrind.%p \
	--leak-check=full --track-origins=yes \
	--suppressions=$(abs_top_srcdir)/tests/glibc.supp \
	--suppressions=$(abs_top_srcdir)/tests/openssl.supp --num-callers=20
HELGRIND = valgrind --log-file=helgrind.%p --tool=helgrind \
	--suppressions=$(abs_top_srcdir)/tests/glibc.supp \
	--suppressions=$(abs_top_srcdir)/tests/openssl.supp --num-callers=20
EXTRA_DIST += tests/glibc.supp tests/openssl.supp
check-valgrind: all $(valgrind_wrappers) $(check_DATA)
	$(SHELL) '$(TESTSUITE)' -C tests CHECK_VALGRIND=true VALGRIND='$(VALGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS)
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Valgrind output can be found in tests/testsuite.dir/*/valgrind.*'
	@echo '----------------------------------------------------------------------'
check-userspace-valgrind: all $(valgrind_wrappers) $(check_DATA)
	$(SHELL) '$(SYSTEM_USERSPACE_TESTSUITE)' -C tests VALGRIND='$(VALGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS) -j1
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Valgrind output can be found in tests/system-userspace-testsuite.dir/*/valgrind.*'
	@echo '----------------------------------------------------------------------'
check-helgrind: all $(valgrind_wrappers) $(check_DATA)
	-$(SHELL) '$(TESTSUITE)' -C tests CHECK_VALGRIND=true VALGRIND='$(HELGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS)

# Run kmod tests. Assume kernel modules has been installed or linked into the kernel
check-kernel: all
	set $(SHELL) '$(SYSTEM_KMOD_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)'; \
	$(SUDO) "$$@" $(TESTSUITEFLAGS) -j1 || (test X'$(RECHECK)' = Xyes && $(SUDO) "$$@" --recheck)


check-system-userspace: all
	set $(SHELL) '$(SYSTEM_USERSPACE_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)'; \
	$(SUDO) "$$@" $(TESTSUITEFLAGS) -j1 || (test X'$(RECHECK)' = Xyes && $(SUDO) "$$@" --recheck)

clean-local:
	test ! -f '$(TESTSUITE)' || $(SHELL) '$(TESTSUITE)' -C tests --clean

check-perf: all
	@mkdir -p $(PERF_TESTSUITE_DIR)
	@echo  > $(PERF_TESTSUITE_RESULTS)
	set $(SHELL) '$(PERF_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)'; \
	"$$@" $(TESTSUITEFLAGS) -j1 || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)
	@echo
	@echo  '## -------------------- ##'
	@echo  '##  Performance Results ##'
	@echo  '## -------------------- ##'
	@cat $(PERF_TESTSUITE_RESULTS)
	@echo
	@echo "Results can be found in $(PERF_TESTSUITE_RESULTS)"


AUTOTEST = $(AUTOM4TE) --language=autotest

if WIN32
$(TESTSUITE): package.m4 $(TESTSUITE_AT) $(COMMON_MACROS_AT) $(TESTSUITE_PATCH)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o testsuite.tmp $@.at
	patch -p0 testsuite.tmp $(TESTSUITE_PATCH)
	$(AM_V_at)mv testsuite.tmp $@
else
$(TESTSUITE): package.m4 $(TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@
endif

$(SYSTEM_KMOD_TESTSUITE): package.m4 $(SYSTEM_TESTSUITE_AT) $(SYSTEM_KMOD_TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@

$(SYSTEM_USERSPACE_TESTSUITE): package.m4 $(SYSTEM_TESTSUITE_AT) $(SYSTEM_USERSPACE_TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@

$(PERF_TESTSUITE): package.m4 $(PERF_TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	$(AM_V_GEN):;{ \
	  echo '# Signature of the current package.' && \
	  echo 'm4_define([AT_PACKAGE_NAME],      [$(PACKAGE_NAME)])' && \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [$(PACKAGE_TARNAME)])' && \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [$(PACKAGE_VERSION)])' && \
	  echo 'm4_define([AT_PACKAGE_STRING],    [$(PACKAGE_STRING)])' && \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [$(PACKAGE_BUGREPORT)])'; \
	} >'$(srcdir)/package.m4'


noinst_PROGRAMS += tests/ovstest
tests_ovstest_SOURCES = \
	include/ovn/features.h \
	tests/ovstest.c \
	tests/ovstest.h \
	tests/test-utils.c \
	tests/test-utils.h \
	tests/test-ovn.c \
	controller/test-lflow-cache.c \
	controller/test-lflow-conj-ids.c \
	controller/test-ofctrl-seqno.c \
	controller/test-vif-plug.c \
	lib/test-ovn-features.c \
	northd/test-ipam.c

tests_ovstest_LDADD = $(OVS_LIBDIR)/daemon.lo \
    $(OVS_LIBDIR)/libopenvswitch.la lib/libovn.la \
	controller/binding.$(OBJEXT) \
	controller/encaps.$(OBJEXT) \
	controller/ha-chassis.$(OBJEXT) \
	controller/if-status.$(OBJEXT) \
	controller/lflow-cache.$(OBJEXT) \
	controller/lflow-conj-ids.$(OBJEXT) \
	controller/local_data.$(OBJEXT) \
	controller/lport.$(OBJEXT) \
	controller/ofctrl-seqno.$(OBJEXT) \
	controller/ovsport.$(OBJEXT) \
	controller/patch.$(OBJEXT) \
	controller/vif-plug.$(OBJEXT) \
	northd/ipam.$(OBJEXT)

# Python tests.
CHECK_PYFILES = \
	tests/test-l7.py \
	tests/uuidfilt.py \
	tests/test-tcp-rst.py \
	tests/check_acl_log.py

EXTRA_DIST += $(CHECK_PYFILES)
PYCOV_CLEAN_FILES += $(CHECK_PYFILES:.py=.py,cover) .coverage

FLAKE8_PYFILES += $(CHECK_PYFILES)

if HAVE_OPENSSL
OVS_PKI_DIR = $(CURDIR)/tests/pki
# NOTE: Certificate generation has to be done serially, and each one adds a few
# seconds to the test run. Please try to re-use one of the many CNs already
# used in the existing tests.
TESTPKI_CNS = test test2 main hv hv-foo hv1 hv2 hv3 hv4 hv5 hv6 hv7 hv8 hv9 hv10 hv-1 hv-2 hv-10-1 hv-10-2 hv-20-1 hv-20-2 vtep hv_gw pbr-hv gw1 gw2 gw3 gw4 gw5 ext1
TESTPKI_FILES = $(shell \
	for cn in $(TESTPKI_CNS); do \
		echo tests/testpki-$$cn-cert.pem ; \
		echo tests/testpki-$$cn-privkey.pem ; \
		echo tests/testpki-$$cn-req.pem ; \
	done)

tests/testpki-cacert.pem: tests/pki/stamp
	$(AM_V_GEN)cp $(OVS_PKI_DIR)/switchca/cacert.pem $@

$(TESTPKI_FILES): tests/pki/stamp
	$(AM_V_GEN)cp $(OVS_PKI_DIR)/$(notdir $(subst testpki-,,$@)) $@

check_DATA += tests/testpki-cacert.pem
check_DATA += $(TESTPKI_FILES)
CLEANFILES += tests/testpki-cacert.pem
CLEANFILES += $(TESTPKI_FILES)


OVS_PKI = $(SHELL) $(ovs_srcdir)/utilities/ovs-pki.in --dir=$(OVS_PKI_DIR) --log=tests/ovs-pki.log
tests/pki/stamp:
	$(AM_V_at)rm -f tests/pki/stamp
	$(AM_V_at)rm -rf tests/pki
	$(AM_V_GEN)$(OVS_PKI) init && \
	cd tests/pki && \
	for cn in $(TESTPKI_CNS); do \
		$(OVS_PKI) -u req+sign $$cn; \
	done && \
	cd ../../ && \
	: > tests/pki/stamp
CLEANFILES += tests/ovs-pki.log

CLEAN_LOCAL += clean-pki
clean-pki:
	rm -f tests/pki/stamp
	rm -rf tests/pki
endif
