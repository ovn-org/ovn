# ovn-northd
bin_PROGRAMS += ovn/northd/ovn-northd
ovn_northd_ovn_northd_SOURCES = ovn/northd/ovn-northd.c
ovn_northd_ovn_northd_LDADD = \
	ovn/lib/libovn.la \
	ovsdb/libovsdb.la \
	lib/libopenvswitch.la
man_MANS += ovn/northd/ovn-northd.8
EXTRA_DIST += \
	ovn/northd/ovn-northd ovn/northd/ovn-northd.8.xml \
	ovn/northd/ovn_northd.dl ovn/northd/ovn.dl ovn/northd/ovn.rs \
	ovn/northd/ovn.toml ovn/northd/lswitch.dl ovn/northd/lrouter.dl \
	ovn/northd/helpers.dl ovn/northd/ipam.dl \
	ovn/northd/docs/design.md  ovn/northd/docs/debugging.md

CLEANFILES += ovn/northd/ovn-northd.8

if DDLOG
BUILT_SOURCES += ovn/northd/ovn_northd_ddlog/ddlog.h

bin_PROGRAMS += ovn/northd/ovn-northd-ddlog
ovn_northd_ovn_northd_ddlog_SOURCES = \
	ovn/northd/ovn-northd-ddlog.c \
	ovn/northd/ovn_northd_ddlog/ddlog.h
ovn_northd_ovn_northd_ddlog_LDADD = \
	ovn/lib/libovn.la \
	ovsdb/libovsdb.la \
	lib/libopenvswitch.la \
	ovn/northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.la

ovn/northd/OVN_Northbound.dl: ovn/ovn-nb.ovsschema
	ovsdb2ddlog -f ovn/ovn-nb.ovsschema         \
				-o Logical_Switch_Port          \
				-k Logical_Switch_Port.name     \
				-o NB_Global                    \
				--ro NB_Global.nb_cfg           \
				--ro NB_Global.external_ids     \
				--ro NB_Global.connections      \
				--ro NB_Global.ssl              \
				-k NB_Global.ipsec              \
				> $@

ovn/northd/OVN_Southbound.dl: ovn/ovn-sb.ovsschema
	ovsdb2ddlog -f ovn/ovn-sb.ovsschema \
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

CLEANFILES += ovn/northd/OVN_Northbound.dl ovn/northd/OVN_Southbound.dl

ovn/northd/ovn_northd_ddlog/ddlog.h: \
	ovn/northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a

ovn/northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.la: \
	ovn/northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a

ovn/northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a: \
	ovn/northd/ovn_northd.dl	 \
	ovn/northd/lswitch.dl	 	 \
	ovn/northd/lrouter.dl	 	 \
	ovn/northd/ipam.dl			 \
	ovn/northd/ovn.dl			 \
	ovn/northd/ovn.rs			 \
	ovn/northd/helpers.dl		 \
	ovn/northd/OVN_Northbound.dl \
	ovn/northd/OVN_Southbound.dl
	$(AM_V_GEN)ddlog -i $< -L @DDLOG_LIB@
	$(AM_V_at)cd ovn/northd/ovn_northd_ddlog && \
		RUSTFLAGS="-L ../../lib/.libs -L ../../../lib/.libs -lssl -lcrypto \
		-Awarnings $(DDLOG_EXTRA_RUSTFLAGS)" cargo build --release \
		$(DDLOG_NORTHD_LIB_ONLY)

CLEAN_LOCAL += clean-ddlog
clean-ddlog:
	rm -rf ovn/northd/ovn_northd_ddlog

CLEANFILES += \
	ovn/northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.la \
	ovn/northd/ovn_northd_ddlog/ddlog.h \
	ovn/northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a \
	ovn/northd/ovn_northd_ddlog/target/release/ovn_northd_cli
endif
