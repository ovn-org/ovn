EXTRA_DIST += \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/copyright \
	debian/copyright.in \
	debian/ovn-central.default \
	debian/ovn-central.install \
	debian/ovn-central.manpages \
	debian/ovn-central.ovn-northd.service \
	debian/ovn-central.ovn-ovsdb-server-nb.service \
	debian/ovn-central.ovn-ovsdb-server-sb.service \
	debian/ovn-central.postrm \
	debian/ovn-central.service \
	debian/ovn-common.dirs \
	debian/ovn-common.docs \
	debian/ovn-common.install \
	debian/ovn-common.logrotate \
	debian/ovn-common.manpages \
	debian/ovn-common.postinst \
	debian/ovn-common.postrm \
	debian/ovn-controller-vtep.install \
	debian/ovn-controller-vtep.manpages \
	debian/ovn-controller-vtep.service \
	debian/ovn-doc.doc-base \
	debian/ovn-doc.install \
	debian/ovn-docker.install \
	debian/ovn-host.default \
	debian/ovn-host.install \
	debian/ovn-host.manpages \
	debian/ovn-host.ovn-controller.service \
	debian/ovn-host.postrm \
	debian/ovn-host.service \
	debian/ovn-ic-db.install \
	debian/ovn-ic-db.manpages \
	debian/ovn-ic-db.ovn-ovsdb-server-ic-nb.service \
	debian/ovn-ic-db.ovn-ovsdb-server-ic-sb.service \
	debian/ovn-ic-db.service \
	debian/ovn-ic.install \
	debian/ovn-ic.manpages \
	debian/ovn-ic.service \
	debian/rules \
	debian/source/format \
	debian/watch

check-debian-changelog-version:
	@DEB_VERSION=`echo '$(VERSION)' | sed 's/pre/~pre/'`;		     \
	if $(FGREP) '($(DEB_VERSION)' $(srcdir)/debian/changelog >/dev/null; \
	then								     \
	  :;								     \
	else								     \
	  echo "Update debian/changelog to mention version $(VERSION)";	     \
	  exit 1;							     \
	fi
ALL_LOCAL += check-debian-changelog-version
DIST_HOOKS += check-debian-changelog-version

$(srcdir)/debian/copyright: AUTHORS.rst debian/copyright.in
	$(AM_V_GEN) \
	{ sed -n -e '/%AUTHORS%/q' -e p < $(srcdir)/debian/copyright.in;   \
	  sed '34,/^$$/d' $(srcdir)/AUTHORS.rst |			   \
		sed -n -e '/^$$/q' -e 's/^/  /p';			   \
	  sed -e '34,/%AUTHORS%/d' $(srcdir)/debian/copyright.in;	   \
	} > $@
