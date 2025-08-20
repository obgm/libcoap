ZEPHYR_PROJECT?=zephyrproject

all: $(ZEPHYR_PROJECT) coap-client coap-cpp-test

${ZEPHYR_PROJECT}:
	python3 -m venv ${ZEPHYR_PROJECT}/.venv ;\
	ls -l ${ZEPHYR_PROJECT}/.venv/bin/activate ;\
	. ${ZEPHYR_PROJECT}/.venv/bin/activate ;\
	pip install west ;\
	west init ${ZEPHYR_PROJECT} ;\
	cd ${ZEPHYR_PROJECT} ;\
	west update -n ;\
	west zephyr-export ;\
	west packages pip --install ;\
	cd zephyr ;\
	if [ "${GITHUB_WORKSPACE}"a = "a" ] ; then \
		west sdk install --install-base=$(ZEPHYR_PROJECT)/../ ;\
	else \
		west sdk install --install-base=$(ZEPHYR_PROJECT)/../ -t x86_64-zephyr-elf ;\
	fi ;\
        cd ../../ ;\
	deactivate

coap-client: client-src/src/main.c client-src/* ../../src/*.c ../../include/*/*
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
	@rm -rf $(ZEPHYR_PROJECT)/zephyr/build

coap-cpp-test: test-cpp-src/src/test.cpp test-cpp-src/* ../../src/*.c ../../include/*/*
	@LIBCOAP_DIR=`pwd`/../.. ;\
	(if [ -f $(ZEPHYR_PROJECT)/.venv/bin/activate ]; then \
	  . $(ZEPHYR_PROJECT)/.venv/bin/activate ;\
	fi ;\
	cd $(ZEPHYR_PROJECT)/zephyr ;\
	west build -p always -b native_sim \
		$${LIBCOAP_DIR}/examples/zephyr/test-cpp-src -- \
		-DCONF_FILE=prj.conf \
		-DEXTRA_ZEPHYR_MODULES=$${LIBCOAP_DIR})
	@cp -f $(ZEPHYR_PROJECT)/zephyr/build/zephyr/zephyr.exe coap-cpp-test
	@rm -rf $(ZEPHYR_PROJECT)/zephyr/build
clean:
	@rm -rf $(ZEPHYR_PROJECT)/zephyr/build
	@rm -f coap-client coap-cpp-test
