bugtool_plugins = \
	utilities/bugtool/plugins/network-status/ovn.xml

bugtool_scripts = \
	utilities/bugtool/ovn-bugtool-nbctl-show \
	utilities/bugtool/ovn-bugtool-sbctl-show \
	utilities/bugtool/ovn-bugtool-sbctl-lflow-list

scripts_SCRIPTS += $(bugtool_scripts)

bugtoolpluginsdir = $(pkgdatadir)/bugtool-plugins
INSTALL_DATA_LOCAL += bugtool-install-data-local
bugtool-install-data-local:
	for plugin in $(bugtool_plugins); do \
	  stem=`echo "$$plugin" | sed 's,ovn/,,'`; \
	  stem=`echo "$$stem" | sed 's,utilities/bugtool/plugins/,,'`; \
	  dir=`expr "$$stem" : '\(.*\)/[^/]*$$'`; \
	  $(MKDIR_P) "$(DESTDIR)$(bugtoolpluginsdir)/$$dir"; \
	  $(INSTALL_DATA) "$(srcdir)/$$plugin" "$(DESTDIR)$(bugtoolpluginsdir)/$$stem"; \
	done

UNINSTALL_LOCAL += bugtool-uninstall-local
bugtool-uninstall-local:
	for plugin in $(bugtool_plugins); do \
	  stem=`echo "$$plugin" | sed 's,ovn/,,'`; \
	  stem=`echo "$$stem" | sed 's,utilities/bugtool/plugins/,,'`; \
	  rm -f "$(DESTDIR)$(bugtoolpluginsdir)/$$stem"; \
	done
	for plugin in $(bugtool_plugins); do \
	  stem=`echo "$$plugin" | sed 's,ovn/,,'`; \
	  stem=`echo "$$stem" | sed 's,utilities/bugtool/plugins/,,'`; \
	  dir=`expr "$$stem" : '\(.*\)/[^/]*$$'`; \
	  if [ ! -z "$$dir" ]; then \
	    rm -rf "$(DESTDIR)$(bugtoolpluginsdir)/$$dir"; \
	  fi \
	done; exit 0

EXTRA_DIST += \
	$(bugtool_plugins) \
	$(bugtool_scripts)
