include $(TOPDIR)/rules.mk

PKG_NAME:=eap_proxy
PKG_VERSION:=1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/eap_proxy
	SECTION=:net
 	CATEGORY:=Network
	TITLE:=Proxy EAP packets between interfaces
  	URL:=https://github.com/jaysoffian/eap_proxy
	DEPENDS:=+python3-ctypes +python3-logging
	PKGARCH:=all
endef

define Package/eap_proxy/description
Python EAP proxy for rediecting EAP packets

endef

define Package/eap_proxy/conffiles
/etc/config/eap_proxy
endef

define Build/Prepare
	$(Build/Prepare/Default)
endef

define Build/Configure
	sed -i 's,!/usr/bin/env python,!/usr/bin/env python3,' ./files/eap_proxy.py
endef

define Build/Compile
endef

define Package/eap_proxy/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/eap_proxy.py $(1)/usr/bin/eap_proxy

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/eap_proxy.init $(1)/etc/init.d/eap_proxy

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/eap_proxy.conf $(1)/etc/config/eap_proxy
endef

$(eval $(call BuildPackage,eap_proxy))
