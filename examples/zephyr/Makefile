ZEPHYR_PROJECT?=~/zephyrproject

all: coap-client

coap-client: client-src/src/main.c client-src/*
	@LIBCOAP_DIR=`pwd`/../.. ;\
	(if [ -f $(ZEPHYR_PROJECT)/.venv/bin/activate ]; then \
	  . $(ZEPHYR_PROJECT)/.venv/bin/activate ;\
	fi ;\
	cp $${LIBCOAP_DIR}/zephyr/config-mbedtls-libcoap.h $(ZEPHYR_PROJECT)/zephyr/include/ ;\
	cd $(ZEPHYR_PROJECT)/zephyr ;\
	west build -p always -b native_sim \
		$${LIBCOAP_DIR}/examples/zephyr/client-src -- \
		-DCONF_FILE=prj.conf \
		-DEXTRA_ZEPHYR_MODULES=$${LIBCOAP_DIR} \
		-DEXTRA_CONF_FILE=$${LIBCOAP_DIR}/zephyr/libcoap-mbedtls.conf)
	@cp -f $(ZEPHYR_PROJECT)/zephyr/build/zephyr/zephyr.exe coap-client

clean:
	@rm -rf $(ZEPHYR_PROJECT)/zephyr/build
	@rm -f coap-client
