# ovn-northd
bin_PROGRAMS += northd/ovn-northd
northd_ovn_northd_SOURCES = northd/ovn-northd.c
northd_ovn_northd_LDADD = \
	lib/libovn.la \
	$(OVSDB_LIBDIR)/libovsdb.la \
	$(OVS_LIBDIR)/libopenvswitch.la
man_MANS += northd/ovn-northd.8
EXTRA_DIST += northd/ovn-northd.8.xml
CLEANFILES += northd/ovn-northd.8

EXTRA_DIST += \
	northd/ovn-northd northd/ovn-northd.8.xml \
	northd/ovn_northd.dl northd/ovn.dl northd/ovn.rs \
	northd/ovn.toml northd/lswitch.dl northd/lrouter.dl \
	northd/helpers.dl northd/ipam.dl \
	northd/docs/design.md  northd/docs/debugging.md

if DDLOG
BUILT_SOURCES += northd/ovn_northd_ddlog/ddlog.h

bin_PROGRAMS += northd/ovn-northd-ddlog
northd_ovn_northd_ddlog_SOURCES = \
	northd/ovn-northd-ddlog.c \
	northd/ovn_northd_ddlog/ddlog.h
northd_ovn_northd_ddlog_LDADD = \
	lib/libovn.la \
	$(OVSDB_LIBDIR)/libovsdb.la \
	$(OVS_LIBDIR)/libopenvswitch.la \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.la

northd/OVN_Northbound.dl: ovn-nb.ovsschema
	ovsdb2ddlog -f ovn-nb.ovsschema         \
				-o Logical_Switch_Port          \
				-k Logical_Switch_Port.name     \
				-o NB_Global                    \
				--ro NB_Global.nb_cfg           \
				--ro NB_Global.external_ids     \
				--ro NB_Global.connections      \
				--ro NB_Global.ssl              \
				> $@

northd/OVN_Southbound.dl: ovn-sb.ovsschema
	ovsdb2ddlog -f ovn-sb.ovsschema \
				-o SB_Global        	\
				-o Logical_Flow     	\
				-o Multicast_Group  	\
				-o Meter            	\
				-o Meter_Band       	\
				-o Datapath_Binding 	\
				-o Port_Binding     	\
				-o Gateway_Chassis  	\
				-o Port_Group       	\
				-o MAC_Binding      	\
				-o DHCP_Options     	\
				-o DHCPv6_Options   	\
				-o Address_Set      	\
				-o DNS              	\
				-o RBAC_Role        	\
				-o RBAC_Permission  	\
				-p Datapath_Binding 	\
				-p Port_Binding     	\
				--ro Port_Binding.chassis       \
				--ro Port_Binding.encap         \
				--ro SB_Global.ssl              \
				--ro SB_Global.connections      \
				--ro SB_Global.external_ids     \
				-k Multicast_Group.datapath     \
				-k Multicast_Group.name         \
				-k Multicast_Group.tunnel_key   \
				-k Port_Binding.logical_port    \
				-k DNS.external_ids             \
				-k Datapath_Binding.external_ids\
				-k RBAC_Role.name               \
				-k Address_Set.name             \
				-k Port_Group.name              \
				-k Meter.name                   \
				-k Logical_Flow.logical_datapath\
				-k Logical_Flow.pipeline		\
				-k Logical_Flow.table_id		\
				-k Logical_Flow.priority		\
				-k Logical_Flow.match			\
				-k Logical_Flow.actions			\
				> $@

CLEANFILES += northd/OVN_Northbound.dl northd/OVN_Southbound.dl

northd/ovn_northd_ddlog/ddlog.h: \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a

northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.la: \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a

northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a: \
	northd/ovn_northd.dl	 \
	northd/lswitch.dl	 	 \
	northd/lrouter.dl	 	 \
	northd/ipam.dl			 \
	northd/ovn.dl			 \
	northd/ovn.rs			 \
	northd/helpers.dl		 \
	northd/OVN_Northbound.dl \
	northd/OVN_Southbound.dl \
	lib/libovn.la            \
	$(OVS_LIBDIR)/libopenvswitch.la
	$(AM_V_GEN)ddlog -i $< -L @DDLOG_LIB@
	$(AM_V_at)cd northd/ovn_northd_ddlog && \
		RUSTFLAGS="-L ../../lib/.libs -L $(OVS_LIBDIR)/.libs -lssl -lcrypto \
		-Awarnings $(DDLOG_EXTRA_RUSTFLAGS)" cargo build --release \
		$(DDLOG_NORTHD_LIB_ONLY)

CLEAN_LOCAL += clean-ddlog
clean-ddlog:
	rm -rf northd/ovn_northd_ddlog

CLEANFILES += \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.la \
	northd/ovn_northd_ddlog/ddlog.h \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a \
	northd/ovn_northd_ddlog/target/release/ovn_northd_cli
endif
