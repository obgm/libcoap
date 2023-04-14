PKG_NAME=libcoap
PKG_URL=https://github.com/mrdeep1/libcoap
PKG_VERSION=3ce58786c6a87176afc0cea2148cc8888da5153a
PKG_LICENSE=BSD-2-Clause

LIBCOAP_BUILD_DIR=$(BINDIR)/pkg/$(PKG_NAME)
LIBCOAP_SOURCE_DIR=$(RIOTBASE)/build/pkg/$(PKG_NAME)
LIBCOAP_INCLUDE_DIR=$(RIOTBASE)/build/pkg/$(PKG_NAME)/include/coap3

include $(RIOTBASE)/pkg/pkg.mk

all:
	@cp $(LIBCOAP_SOURCE_DIR)/coap_config.h.riot $(LIBCOAP_SOURCE_DIR)/coap_config.h
	@cp $(LIBCOAP_INCLUDE_DIR)/coap.h.riot $(LIBCOAP_INCLUDE_DIR)/coap.h
	"$(MAKE)" -C $(LIBCOAP_SOURCE_DIR)/src -f $(CURDIR)/Makefile.libcoap
