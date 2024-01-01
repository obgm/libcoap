# Makefile
#
#  Copyright (C) 2010-2024 Olaf Bergmann <bergmann@tzi.org> and others
#
# SPDX-License-Identifier: BSD-2-Clause
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

RIOT=RIOT
TARGET?=native

all: RIOT pkg examples client server tests

RIOT:
	git clone --depth 1 https://github.com/RIOT-OS/RIOT.git $@

pkg:
	@IN_GIT=`git rev-parse --is-inside-work-tree` ; \
	if [ "$${IN_GIT}" = "true" ] ; then \
		rm -rf pkg_libcoap/patches ; \
		mkdir -p pkg_libcoap/patches ; \
		RIOT_HASH=`grep PKG_VERSION= pkg_libcoap/Makefile | cut -d= -f2` ; \
		git pull --unshallow > /dev/null 2>&1 ; \
		if [ ! -z "$${RIOT_HASH}" ] ; then \
			(cd pkg_libcoap/patches ; git format-patch -n $${RIOT_HASH}) ; \
		fi \
	fi
	rm -rf RIOT/pkg/libcoap && mkdir RIOT/pkg/libcoap
	cd pkg_libcoap && cp -r * ../RIOT/pkg/libcoap
	@HAVE_KCONFIG=`grep libcoap/Kconfig RIOT/pkg/Kconfig | wc -l` ; \
	if [ "$${HAVE_KCONFIG}" = 0 ] ; then \
		sed -i '/rsource "libcose\/Kconfig"/irsource "libcoap\/Kconfig"' RIOT/pkg/Kconfig ; \
	fi

examples:
	rm -rf RIOT/examples/libcoap-client && mkdir RIOT/examples/libcoap-client
	cd examples_libcoap_client && cp -r * ../RIOT/examples/libcoap-client
	rm -rf RIOT/examples/libcoap-server && mkdir RIOT/examples/libcoap-server
	cd examples_libcoap_server && cp -r * ../RIOT/examples/libcoap-server
	rm -rf RIOT/tests/pkg/libcoap && mkdir -p RIOT/tests/pkg/libcoap
	cd tests_pkg_libcoap && cp -r * ../RIOT/tests/pkg/libcoap

client:	RIOT pkg examples
	$(MAKE) -C RIOT/examples/libcoap-client/ RIOT_CI_BUILD=1

server:	RIOT pkg examples
	$(MAKE) -C RIOT/examples/libcoap-server/ RIOT_CI_BUILD=1

tests:	RIOT pkg examples
	$(MAKE) -C RIOT/tests/pkg/libcoap/ RIOT_CI_BUILD=1

run_tests:
	$(MAKE) -C RIOT/tests/pkg/libcoap/ test

clean:
	rm -rf RIOT/pkg/libcoap
	rm -rf RIOT/examples/libcoap-client
	rm -rf RIOT/examples/libcoap-server
	rm -rf RIOT/tests/pkg/libcoap
