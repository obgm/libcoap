# Makefile
#
#  Copyright (C) 2010-2023 Olaf Bergmann <bergmann@tzi.org> and others
#
# SPDX-License-Identifier: BSD-2-Clause
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

RIOT=RIOT
TARGET?=native

all: RIOT pkg examples client server

RIOT:
	git clone --depth 1 https://github.com/RIOT-OS/RIOT.git $@

pkg:
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

client:	RIOT pkg examples
	$(MAKE) -C RIOT/examples/libcoap-client/ RIOT_CI_BUILD=1

server:	RIOT pkg examples
	$(MAKE) -C RIOT/examples/libcoap-server/ RIOT_CI_BUILD=1

clean:
	rm -rf RIOT/pkg/libcoap
	rm -rf RIOT/examples/libcoap-client
	rm -rf RIOT/examples/libcoap-server
