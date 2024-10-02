ZEPHYR_PROJECT?=~/zephyrproject

all: coap-client

coap-client: client-src/src/main.c client-src/*
	LIBCOAP_DIR=`pwd`/../.. ;\
	(. $(ZEPHYR_PROJECT)/.venv/bin/activate ;\
	cd $(ZEPHYR_PROJECT)/zephyr ;\
	west build -p always -b native_sim \
		$${LIBCOAP_DIR}/examples/zephyr/client-src -- \
		-DCONF_FILE=prj.conf \
		-DEXTRA_ZEPHYR_MODULES=$${LIBCOAP_DIR} \
		-DEXTRA_CONF_FILE=$${LIBCOAP_DIR}/zephyr/libcoap-mbedtls.conf \
		--fresh ;\
	deactivate) ;\
	cp -f $(ZEPHYR_PROJECT)/zephyr/build/zephyr/zephyr.exe coap-client
