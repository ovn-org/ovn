# Copyright (C) 2009, 2010, 2011, 2012, 2014 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

EXTRA_DIST += \
	rhel/README.RHEL.rst \
	rhel/automake.mk \
	rhel/etc_logrotate.d_ovn \
	rhel/ovn-fedora.spec \
	rhel/ovn-fedora.spec.in \
	rhel/usr_lib_systemd_system_ovn-controller.service \
	rhel/usr_lib_systemd_system_ovn-controller-vtep.service \
	rhel/usr_lib_systemd_system_ovn-ic.service \
	rhel/usr_lib_systemd_system_ovn-ic-db.service \
	rhel/usr_lib_systemd_system_ovn-northd.service \
	rhel/usr_lib_firewalld_services_ovn-central-firewall-service.xml \
	rhel/usr_lib_firewalld_services_ovn-host-firewall-service.xml \
	rhel/usr_share_ovn_scripts_systemd_sysconfig.template

update_rhel_spec = \
  $(AM_V_GEN)($(ro_shell) && sed -e 's,[@]VERSION[@],$(VERSION),g') \
    < $(srcdir)/rhel/$(@F).in > $(@F).tmp || exit 1; \
  if cmp -s $(@F).tmp $@; then touch $@; rm $(@F).tmp; else mv $(@F).tmp $@; fi

RPMBUILD_TOP := $(abs_top_builddir)/rpm/rpmbuild
RPMBUILD_OPT ?= --without check

rpm-fedora: dist $(srcdir)/rhel/ovn-fedora.spec
	${MKDIR_P} ${RPMBUILD_TOP}/SOURCES
	cp ${DIST_ARCHIVES} ${RPMBUILD_TOP}/SOURCES
	cp $(ovs_builddir)/openvswitch-$(OVSVERSION).tar.gz ${RPMBUILD_TOP}/SOURCES
	rpmbuild ${RPMBUILD_OPT} \
                 -D "_topdir ${RPMBUILD_TOP}" \
                 -ba $(srcdir)/rhel/ovn-fedora.spec

