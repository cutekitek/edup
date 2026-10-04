include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-edup
PKG_VERSION:=0.1.0
PKG_RELEASE:=2
PKG_LICENSE:=MIT OR Apache-2.0

include $(INCLUDE_DIR)/package.mk

# Plain files, without luci.mk: building it would compile LuCI itself.
define Package/luci-app-edup
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI pages for the edup VPN client
  PKGARCH:=all
  EXTRA_DEPENDS:=luci-base (>=0), edup-client (>=0.1.0)
endef

define Package/luci-app-edup/description
  Per-device VPN modes, traffic rules and tunnel settings for edup-client.
endef

define Build/Compile
endef

define Package/luci-app-edup/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/edup
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/edup/*.js \
		$(1)/www/luci-static/resources/view/edup/
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-edup.json $(1)/usr/share/luci/menu.d/
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-edup.json $(1)/usr/share/rpcd/acl.d/
endef

define Package/luci-app-edup/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	killall -HUP rpcd 2>/dev/null
}
exit 0
endef

$(eval $(call BuildPackage,luci-app-edup))
