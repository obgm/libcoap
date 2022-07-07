# Makefile
#
# Copyright (C)      2015 Carsten Schoenert <c.schoenert@t-online.de>
# Copyright (C) 2018-2022 Jon Shallow <supjps-libcoap@jpshallow.com>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

LIBCOAP_API_VERSION = $(shell sed -ne 's/^LIBCOAP_API_VERSION=\([0-9]\+\).*$$/\1/p' libcoap/configure.ac)

coap_include_dir = libcoap/include/coap$(LIBCOAP_API_VERSION)

WITH_LWIP_BRANCH=STABLE-2_1_3_RELEASE
WITH_LWIP_CONTRIB_BRANCH=STABLE-2_1_0_RELEASE

# Need to determine which library clock_gettime() resides in (as found by ./autogen.sh)
LDLIBS := $(shell if [ libcoap/config.log ] ; then grep ac_cv_search_clock_gettime=- libcoap/config.log|cut -d= -f2 ; fi)

LDLIBS += -lpthread

all: lwip lwip-contrib check_tinydtls check_version $(coap_include_dir)/coap.h coap-client coap-server coap-rd

lwip:
	git clone --depth 1 git://git.savannah.nongnu.org/lwip.git -b $(WITH_LWIP_BRANCH)
	(cd lwip ; git checkout $(WITH_LWIP_BRANCH))
	$(MAKE)

lwip-contrib:
	git clone --depth 1 git://git.savannah.nongnu.org/lwip/lwip-contrib.git -b $(WITH_LWIP_CONTRIB_BRANCH)
	(cd lwip-contrib ; git checkout $(WITH_LWIP_CONTRIB_BRANCH))
	$(MAKE)

check_version:
	@(if [ -d lwip ] ; then cd lwip ; TAG=`git describe --tags`; if [ "$$TAG" != ${WITH_LWIP_BRANCH} ] ; then echo "Updating lwip from $$TAG to ${WITH_LWIP_BRANCH}" ; git checkout $(WITH_LWIP_BRANCH); fi; fi )
	@(if [ -d lwip-contrib ] ; then cd lwip-contrib ; TAG=`git describe --tags`; if [ "$$TAG" != ${WITH_LWIP_CONTRIB_BRANCH} ] ; then echo "Updating lwip-contib from $$TAG to ${WITH_LWIP_CONTRIB_BRANCH}" ; git checkout $(WITH_LWIP_CONTRIB_BRANCH); fi; fi )

check_tinydtls:
	@(cd ../.. ; git submodule init ; git submodule update)

# lwip and coap opts (include early to shadow the lwip-contrib/ports/unix/proj/minimal/ file and any ../../config.h)
CFLAGS += -DWITH_LWIP -iquote./config

# LwIP library

LWIPOBJS = def.o init.o libcoap_tapif.o etharp.o netif.o timeouts.o stats.o mem.o memp.o udp.o tcp.o pbuf.o ip4_addr.o ip4.o inet_chksum.o tcp_in.o tcp_out.o icmp.o raw.o ip4_frag.o sys_arch.o ethernet.o ip.o sockets.o netdb.o api_lib.o tcpip.o igmp.o dns.o netbuf.o api_msg.o err.o
vpath %.c lwip/src/core/ lwip/src/api/ lwip/src/netif/ lwip/src/core/ipv4/ lwip/contrib/ports/unix/port/ lwip-contrib/ports/unix/port/ src

# if ipv6 is used
vpath %.c lwip/src/core/ipv6/
LWIPOBJS += mld6.o ip6.o icmp6.o ethip6.o nd6.o ip6_addr.o ip6_frag.o

# CoAP library

CFLAGS += -std=gnu99

CFLAGS += -Ilibcoap/include -I$(coap_include_dir)

vpath %.c libcoap/src

COAPOBJS = net.o coap_cache.o coap_debug.o coap_option.o resource.o pdu.o encode.o coap_subscribe.o coap_io.o block.o uri.o str.o coap_session.o coap_notls.o coap_hashkey.o coap_address.o coap_tcp.o coap_async.o coap_event.o coap_mem.o coap_tinydtls.o coap_asn1.o

CFLAGS += -g3 -Wall -Wextra -pedantic -O0
# Warning options not sorted out yet
CFLAGS += -Wno-unused-parameter -Wcast-qual -Wformat-security -Wstrict-prototypes -Wunused -Wmissing-declarations -Wmissing-prototypes

CFLAGS += -Ilwip/src/include/ -Ilwip-contrib/ports/unix/port/include/ -Ilwip/src/include/compat/posix/

$(coap_include_dir)/coap.h:
	@echo "Error: $@ not present. Run the autotools chain (\`./autogen.sh && ./configure\`) in the project root directory to build the required coap.h file."
	@exit 1

# TinyDTLS library

TINYDTLSOBJS = dtls.o dtls_debug.o crypto.o dtls_time.o hmac.o sha2.o session.o peer.o netq.o rijndael_wrap.o rijndael.o ecc.o ccm.o dtls_prng.o
vpath %.c tinydtls tinydtls/sha2 tinydtls/aes tinydtls/ecc

CFLAGS += -I. -Itinydtls -DDTLSv12 -DWITH_SHA256 -DSHA2_USE_INTTYPES_H -DDTLS_CHECK_CONTENTTYPE

vpath %.c libcoap/examples

coap-server: ${LWIPOBJS} ${COAPOBJS} ${TINYDTLSOBJS} coap-server.o

coap-client: ${LWIPOBJS} ${COAPOBJS} ${TINYDTLSOBJS} coap-client.o

coap-rd: ${LWIPOBJS} ${COAPOBJS} ${TINYDTLSOBJS} coap-rd.o

clean:
	rm -f *.o coap-client coap-server coap-rd

.PHONY: clean
