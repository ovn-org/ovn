EXTRA_DIST += \
	tutorial/ovs-sandbox \
	tutorial/ovn-setup.sh \
	tutorial/ovn-lb-benchmark.sh \
	tutorial/ovn-lb-benchmark.py
sandbox: all
	cd $(srcdir)/tutorial && MAKE=$(MAKE) HAVE_OPENSSL=$(HAVE_OPENSSL) \
		./ovs-sandbox -b $(abs_builddir) --ovs-src $(ovs_srcdir) --ovs-build $(ovs_builddir) $(SANDBOXFLAGS)
