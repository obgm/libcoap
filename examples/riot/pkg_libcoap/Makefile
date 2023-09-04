PKG_NAME=libcoap
PKG_URL=https://github.com/obgm/libcoap
PKG_VERSION=9e24d22ce9459b6a8765248234a77bcdefd26b25
PKG_LICENSE=BSD-2-Clause

LIBCOAP_BUILD_DIR=$(BINDIR)/pkg/$(PKG_NAME)
LIBCOAP_SOURCE_DIR=$(RIOTBASE)/build/pkg/$(PKG_NAME)
LIBCOAP_INCLUDE_DIR=$(RIOTBASE)/build/pkg/$(PKG_NAME)/include/coap3

include $(RIOTBASE)/pkg/pkg.mk

all:
	@cp $(LIBCOAP_SOURCE_DIR)/coap_config.h.riot $(LIBCOAP_SOURCE_DIR)/coap_config.h
	@cp $(LIBCOAP_INCLUDE_DIR)/coap.h.riot $(LIBCOAP_INCLUDE_DIR)/coap.h
	"$(MAKE)" -C $(LIBCOAP_SOURCE_DIR)/src -f $(CURDIR)/Makefile.libcoap
