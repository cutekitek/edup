include $(TOPDIR)/rules.mk

PKG_NAME:=edup-client
PKG_VERSION:=0.2.0
PKG_RELEASE:=3
PKG_LICENSE:=MIT OR Apache-2.0

include $(INCLUDE_DIR)/package.mk

# The static executable is built outside the SDK by scripts/build-openwrt.sh:
# its embedded eBPF object needs a nightly Rust toolchain and bpf-linker.
EDUP_BINARY ?= $(CURDIR)/edup-client

define Package/edup-client
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=edup tunnel client with eBPF routing for LAN clients
  DEPENDS:=@aarch64
  # Runtime only: nothing here is compiled against them.
  EXTRA_DEPENDS:=kmod-tun (>=0), kmod-veth (>=0), ip-full (>=0), ucode (>=0), ucode-mod-fs (>=0), ucode-mod-uci (>=0), ucode-mod-ubus (>=0)
endef

define Package/edup-client/description
  Client for the edup IP-over-UDP tunnel in XDP mode: eBPF on the WAN interface
  carries tunnels to one or more servers, and per-device and destination rules
  choose the server, or none, for each LAN client.
  Configured through /etc/config/edup.
endef

define Package/edup-client/conffiles
/etc/config/edup
endef

define Build/Compile
endef

define Package/edup-client/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config $(1)/etc/uci-defaults $(1)/usr/share/edup
	# Rule-set files uploaded through LuCI, kept across firmware upgrades.
	$(INSTALL_DIR) $(1)/etc/edup/rule-sets $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) ./files/edup.keep $(1)/lib/upgrade/keep.d/edup-client
	$(INSTALL_BIN) $(EDUP_BINARY) $(1)/usr/bin/edup-client
	$(INSTALL_BIN) ./files/edup.init $(1)/etc/init.d/edup
	$(INSTALL_CONF) ./files/edup.config $(1)/etc/config/edup
	# Moves an earlier version's single server into a server section.
	$(INSTALL_BIN) ./files/edup.defaults $(1)/etc/uci-defaults/90-edup-servers
	$(INSTALL_DATA) ./files/genconfig.uc $(1)/usr/share/edup/genconfig.uc
endef

$(eval $(call BuildPackage,edup-client))
