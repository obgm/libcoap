ZEPHYR_PROJECT?=zephyrproject

# Keep in sync with .github/workflows/main.yml
WITH_ZEPHYR_BRANCH?=v4.3.0

export LCWD := $(shell pwd)

all: $(ZEPHYR_PROJECT) check-version coap-client coap-cpp-test

${ZEPHYR_PROJECT}:
	python3 -m venv ${ZEPHYR_PROJECT}/.venv ;\
	ls -l ${ZEPHYR_PROJECT}/.venv/bin/activate ;\
	. ${ZEPHYR_PROJECT}/.venv/bin/activate ;\
	pip install west ;\
	west init --mr ${WITH_ZEPHYR_BRANCH} ${ZEPHYR_PROJECT} ;\
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
	cd $(LPWD) ;\
	deactivate

check-version:
	@(if [ -d $(ZEPHYR_PROJECT)/zephyr ] ; then \
		cd $(ZEPHYR_PROJECT)/zephyr ; \
		TAG=`git describe --tags --all`; \
		if [ "$$TAG" != ${WITH_ZEPHYR_BRANCH} -a "$$TAG" != "tags/${WITH_ZEPHYR_BRANCH}" ] ; then \
			git checkout ${WITH_ZEPHYR_BRANCH} ;\
			TAG=`git describe --tags --all`; \
			cd $(LPWD) ;\
			if [ "$$TAG" != ${WITH_ZEPHYR_BRANCH} -a "$$TAG" != "tags/${WITH_ZEPHYR_BRANCH}" ] ; then \
				echo "Updating zephyr to ${WITH_ZEPHYR_BRANCH}" ; \
				cd $(ZEPHYR_PROJECT)/.. ; \
				rm -rf $(ZEPHYR_PROJECT) ; \
        			cd $(LPWD) ;\
				${MAKE}; \
			else \
				. ${ZEPHYR_PROJECT}/.venv/bin/activate ;\
				cd ${ZEPHYR_PROJECT} ;\
				west update -n ;\
				west zephyr-export ;\
				deactivate ;\
			fi ; \
		fi ; \
		cd $(LPWD) ;\
	fi)

coap-client: client-src/src/main.c client-src/* ../../src/*.c ../../include/*/*
	@LIBCOAP_DIR=`pwd`/../.. ;\
	(if [ -f $(ZEPHYR_PROJECT)/.venv/bin/activate ]; then \
	  . $(ZEPHYR_PROJECT)/.venv/bin/activate ;\
	fi ;\
	cd $(ZEPHYR_PROJECT)/zephyr ;\
	west build -p always -b native_sim \
		$${LIBCOAP_DIR}/examples/zephyr/client-src -- \
		-DCONF_FILE=prj.conf \
		-DEXTRA_ZEPHYR_MODULES=$${LIBCOAP_DIR} \
		-DCMAKE_C_FLAGS="-DMBEDTLS_VERSION_C -Werror" \
		-DEXTRA_CONF_FILE=libcoap-mbedtls.conf)
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
		-DCMAKE_C_FLAGS="-Werror" \
		-DEXTRA_ZEPHYR_MODULES=$${LIBCOAP_DIR})
	@cp -f $(ZEPHYR_PROJECT)/zephyr/build/zephyr/zephyr.exe coap-cpp-test
	@rm -rf $(ZEPHYR_PROJECT)/zephyr/build
clean:
	@rm -rf $(ZEPHYR_PROJECT)/zephyr/build
	@rm -f coap-client coap-cpp-test
