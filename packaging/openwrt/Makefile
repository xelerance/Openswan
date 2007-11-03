
include $(TOPDIR)/rules.mk

PKG_NAME:=openswan
PKG_VERSION:=2.4.9
PKG_RELEASE:=7
PKG_MD5SUM:=c6f3714bf39b91a80633ec3aa7fce298

PKG_SOURCE_URL:=http://www.openswan.org/download
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_CAT:=zcat
PKG_IPK:=$(PACKAGE_DIR)/$(PKG_NAME)_$(PKG_VERSION)-$(PKG_RELEASE)_$(ARCH).ipk
PKG_IPK_DIR:=$(PKG_BUILD_DIR)/ipkg

$(DL_DIR)/$(PKG_SOURCE):
	$(SCRIPT_DIR)/download.pl $(DL_DIR) $(PKG_SOURCE) $(PKG_MD5SUM) $(PKG_SOURCE_URL)

$(PKG_BUILD_DIR)/.patched: $(DL_DIR)/$(PKG_SOURCE)
	$(PKG_CAT) $(DL_DIR)/$(PKG_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	$(PATCH) $(PKG_BUILD_DIR) ./patches
	touch $(PKG_BUILD_DIR)/.patched

FLAGS := $(TARGET_CFLAGS) -I$(PKG_BUILD_DIR)/linux/include -L$(STAGING_DIR)/usr/lib -I$(STAGING_DIR)/usr/include

$(PKG_BUILD_DIR)/$(PKG_NAME): $(PKG_BUILD_DIR)/.patched
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		KERNELSRC="$(LINUX_DIR)" \
		ARCH="mips" \
		USERCOMPILE="$(FLAGS)" \
		module
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		KERNELSRC="$(LINUX_DIR)" \
		ARCH="mips" \
		USERCOMPILE="$(FLAGS)" \
		EXTRA_INCLUDE="-I$(STAGING_DIR)/usr/include" \
		EXTRA_LIBS="-L$(STAGING_DIR)/usr/lib" \
		IPSECDIR="/usr/lib/ipsec" \
		INC_USRLOCAL="/usr" \
		INC_RCDEFAULT="/etc/init.d" \
		MODPROBE="/sbin/insmod" \
		programs

$(PKG_IPK): $(PKG_BUILD_DIR)/$(PKG_NAME)
	$(SCRIPT_DIR)/make-ipkg-dir.sh $(PKG_IPK_DIR) $(PKG_NAME).control $(PKG_VERSION)-$(PKG_RELEASE) $(ARCH)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		DESTDIR="$(PKG_IPK_DIR)" \
		KERNELSRC="$(LINUX_DIR)" \
		ARCH="mips" \
		USERCOMPILE="$(FLAGS)" \
		IPSECDIR="/usr/lib/ipsec" \
		INC_USRLOCAL="/usr" \
		INC_RCDEFAULT="/etc/init.d" \
		MODPROBE="/sbin/insmod" \
		install
	-$(STRIP) $(IDIR_OPENSWAN)/usr/lib/ipsec/*
	-$(STRIP) $(IDIR_OPENSWAN)/usr/libexec/ipsec/*
	rm -rf $(IDIR_OPENSWAN)/usr/share
	rm -rf $(IDIR_OPENSWAN)/usr/man
	rm -rf $(IDIR_OPENSWAN)/var
	rm -rf $(IDIR_OPENSWAN)/etc/rc.d/rc*.d
	mkdir -p $(IDIR_OPENSWAN)/etc/init.d
	ln -sf ipsec $(IDIR_OPENSWAN)/etc/init.d/S60ipsec
	find $(PKG_BUILD_DIR) -name \*.old | xargs rm -rf
	mkdir -p $(PACKAGE_DIR)
	find $(PKG_BUILD_DIR) -name \*.old | xargs rm -rf
	$(IPKG_BUILD) $(PKG_IPK_DIR) $(PACKAGE_DIR)

$(IPKG_STATE_DIR)/info/$(PKG_NAME).list: $(PKG_IPK)
	$(IPKG) install $(PKG_IPK)

source: $(DL_DIR)/$(PKG_SOURCE)
prepare: $(PKG_BUILD_DIR)/.patched
compile: $(PKG_IPK)
install: $(IPKG_STATE_DIR)/info/$(PKG_NAME).list

clean:
	rm -rf $(PKG_BUILD_DIR)
	rm -f $(PKG_IPK)
