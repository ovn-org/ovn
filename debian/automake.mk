EXTRA_DIST += \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/copyright.in \
	debian/dirs \
	debian/ovn-central.dirs \
	debian/ovn-central.init \
	debian/ovn-central.install \
	debian/ovn-central.manpages \
	debian/ovn-central.postinst \
	debian/ovn-central.postrm \
	debian/ovn-central.template \
	debian/ovn-controller-vtep.init \
	debian/ovn-controller-vtep.install \
	debian/ovn-controller-vtep.manpages \
	debian/ovn-common.install \
	debian/ovn-common.manpages \
	debian/ovn-common.postinst \
	debian/ovn-common.postrm \
	debian/ovn-host.dirs \
	debian/ovn-host.init \
	debian/ovn-host.install \
	debian/ovn-host.manpages \
	debian/ovn-host.postinst \
	debian/ovn-host.postrm \
	debian/ovn-host.template \
	debian/rules \
	debian/source/format

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

CLEANFILES += debian/copyright
