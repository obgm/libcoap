# Makefile
#
#  Copyright (C) 2010-2023 Olaf Bergmann <bergmann@tzi.org> and others
#
# SPDX-License-Identifier: BSD-2-Clause
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

libcoap_dir = ../..

LIBCOAP_API_VERSION = $(shell if [ -f $(libcoap_dir)/configure.ac ];  then \
          sed -ne 's/^LIBCOAP_API_VERSION=\([0-9]\+\).*$$/\1/p' $(libcoap_dir)/configure.ac; \
	  else echo -n "3"; fi)

coap_include_dir = $(libcoap_dir)/include/coap$(LIBCOAP_API_VERSION)

WITH_LWIP_BRANCH=STABLE-2_1_3_RELEASE
WITH_LWIP_CONTRIB_BRANCH=STABLE-2_1_0_RELEASE
# Update to latest TinyDTLS submodule as defined for libcoap
WITH_TINYDTLS_BRANCH=f1d47d533b70ac10e4ff0ae3a088dfe4f265d242

# Need to determine which library clock_gettime() resides in (as found by ./autogen.sh)
LDLIBS := $(shell if [ -f $(libcoap_dir)/config.log ] ; then \
          grep ac_cv_search_clock_gettime=- $(libcoap_dir)/config.log|cut -d= -f2 ; fi)

#
# Remove the 4 -dtls checks from "all" if you do not want DTLS included in
# some of the built objects.
#
all: lwip \
     lwip-contrib \
     check-version \
     check-tinydtls \
     $(coap_include_dir)/coap.h \
     lib-server \
     server \
     lib-client \
     client \
     lib-server-dtls \
     server-dtls \
     lib-client-dtls \
     client-dtls

lwip:
	git clone --depth 1 https://git.savannah.nongnu.org/git/lwip.git -b $(WITH_LWIP_BRANCH)
	(cd lwip ; git checkout $(WITH_LWIP_BRANCH))
	$(MAKE)

lwip-contrib:
	git clone --depth 1 https://git.savannah.nongnu.org/git/lwip/lwip-contrib.git -b $(WITH_LWIP_CONTRIB_BRANCH)
	(cd lwip-contrib ; git checkout $(WITH_LWIP_CONTRIB_BRANCH))
	$(MAKE)

check-version:
	@(if [ -d lwip ] ; then \
		cd lwip ; \
		TAG=`git describe --tags --all`; \
		if [ "$$TAG" != ${WITH_LWIP_BRANCH} ] ; then \
			if [ "$$TAG" != "tags/${WITH_LWIP_BRANCH}" ] ; then \
				echo "Updating lwip to ${WITH_LWIP_BRANCH}" ; \
				cd .. ; \
				rm -rf lwip ; \
				${MAKE}; \
			fi ; \
		fi ; \
	fi)
	@(if [ -d lwip-contrib ] ; then \
		cd lwip-contrib ; \
		TAG=`git describe --tags`; \
		if [ "$$TAG" != ${WITH_LWIP_CONTRIB_BRANCH} ] ; then \
			if [ "$$TAG" != "tags/${WITH_LWIP_CONTRIB_BRANCH}" ] ; then \
				echo "Updating lwip-contib to ${WITH_LWIP_CONTRIB_BRANCH}" ; \
				cd .. ; \
				rm -rf lwip-contrib ; \
				${MAKE}; \
			fi ; \
		fi ; \
	fi)

# base libcoap git has empty ext/tinydtls
check-tinydtls:
	@(if [ ! -d $(libcoap_dir)/ext/tinydtls ] ; then \
		mkdir -p $(libcoap_dir)/ext ; \
		(cd $(libcoap_dir)/ext ; git clone https://github.com/eclipse/tinydtls.git) ; \
		(cd $(libcoap_dir)/ext/tinydtls ; git checkout ${WITH_TINYDTLS_BRANCH}) ; \
	fi ; \
	if [ ! -f $(libcoap_dir)/ext/tinydtls/dtls.c ] ; then \
		IN_GIT=`git rev-parse --is-inside-work-tree` ; \
		if [ "$$IN_GIT" = "true" ] ; then \
			(cd $(libcoap_dir) ; git submodule init ; git submodule update) ; \
		else \
			(cd $(libcoap_dir)/ext ; git clone https://github.com/eclipse/tinydtls.git) ; \
			(cd $(libcoap_dir)/ext/tinydtls ; git checkout ${WITH_TINYDTLS_BRANCH}) ; \
		fi ; \
		if [ ! -f $(libcoap_dir)/ext/tinydtls/dtls.c ] ; then \
			exit 1 ; \
		fi ; \
	fi ; \
	IN_GIT=`git rev-parse --is-inside-work-tree` ; \
	if [ "$$IN_GIT" = "true" ] ; then \
		PWDDIR=`pwd` ; \
		cd $(libcoap_dir) ; TAG=`git ls-tree HEAD ext/tinydtls | cut -d\  -f3 | cut -f1` ;\
		if [ ! -z "$$TAG" ] ; then \
			if [ "$$TAG" != ${WITH_TINYDTLS_BRANCH} ] ; then \
				echo "Update WITH_TINYDTLS_BRANCH in Makefile to $$TAG" >&2 ; \
				exit 1 ; \
			fi ;\
		fi ;\
		cd $$PWDDIR ; \
	fi ;\
	if [ ! -f $(libcoap_dir)/ext/tinydtls/dtls_config.h ] ; then \
		(cd $(libcoap_dir)/ext/tinydtls ; ./autogen.sh ; ./configure) ; \
		${MAKE} ; \
	fi)

# lwip and coap opts (include early to shadow the lwip-contrib/ports/unix/proj/minimal/ file and any ../../config.h)
CFLAGS += -DWITH_LWIP -iquote./config $(EXTRA_CFLAGS)

# lwip library

CFLAGS += -Ilwip/src/include/ -Ilwip/src/include/ipv4/ \
	  -Ilwip-contrib/ports/unix/port/include/ \
	  -Ilwip-contrib/ports/unix/proj/minimal/

LWIP_SRC = def.c init.c tapif.c etharp.c netif.c timeouts.c stats.c udp.c \
	   tcp.c pbuf.c ip4_addr.c ip4.c inet_chksum.c tcp_in.c tcp_out.c \
	   icmp.c raw.c ip4_frag.c sys_arch.c ethernet.c ip.c mem.c memp.c
vpath %.c lwip/src/core/ lwip-contrib/ports/unix/proj/minimal/ \
	  lwip/src/netif/ lwip/src/core/ipv4/ lwip-contrib/ports/unix/port/ \
	  lwip-contrib/ports/unix/port/netif/
# CFLAGS += -DLWIP_UNIX_LINUX

# if ipv6 is used
vpath %.c lwip/src/core/ipv6/
LWIP_SRC += mld6.c ip6.c icmp6.c ethip6.c nd6.c ip6_addr.c ip6_frag.c

CN_LWIP_OBJ =$(patsubst %.c,lib-client/%.o,$(LWIP_SRC))
SN_LWIP_OBJ =$(patsubst %.c,lib-server/%.o,$(LWIP_SRC))
CD_LWIP_OBJ =$(patsubst %.c,lib-client-dtls/%.o,$(LWIP_SRC))
SD_LWIP_OBJ =$(patsubst %.c,lib-server-dtls/%.o,$(LWIP_SRC))

# coap library

CFLAGS += -std=gnu99

CFLAGS += -I$(libcoap_dir)/include

vpath %.c $(libcoap_dir)/src

COAP_SRC = coap_address.c \
	   coap_asn1.c \
	   coap_async.c \
	   coap_block.c \
	   coap_cache.c \
	   coap_debug.c \
	   coap_dtls.c \
	   coap_encode.c \
	   coap_hashkey.c \
	   coap_io.c \
	   coap_io_lwip.c \
	   coap_layers.c \
	   coap_net.c \
	   coap_netif.c \
	   coap_notls.c \
	   coap_option.c \
	   coap_oscore.c \
	   coap_pdu.c \
	   coap_resource.c \
	   coap_session.c \
	   coap_subscribe.c \
	   coap_tinydtls.c \
	   coap_str.c \
	   coap_tcp.c \
	   coap_uri.c \
	   coap_ws.c

CN_COAP_OBJ =$(patsubst %.c,lib-client/%.o,$(COAP_SRC))
SN_COAP_OBJ =$(patsubst %.c,lib-server/%.o,$(COAP_SRC))
CD_COAP_OBJ =$(patsubst %.c,lib-client-dtls/%.o,$(COAP_SRC))
SD_COAP_OBJ =$(patsubst %.c,lib-server-dtls/%.o,$(COAP_SRC))

# tinydtls library

vpath %.c $(libcoap_dir)/ext/tinydtls $(libcoap_dir)/ext/tinydtls/sha2 $(libcoap_dir)/ext/tinydtls/aes $(libcoap_dir)/ext/tinydtls/ecc

TINYDTLS_CFLAGS = -I. -I$(libcoap_dir)/ext -I$(libcoap_dir)/ext/tinydtls -DDTLSv12 -DWITH_SHA256 -DSHA2_USE_INTTYPES_H -DDTLS_CHECK_CONTENTTYPE -DCOAP_WITH_LIBTINYDTLS -DHAVE_DTLS_SET_LOG_HANDLER=1

DTLS_SRC = dtls.c \
           dtls_debug.c \
           crypto.c \
           dtls_time.c \
           hmac.c \
           sha2.c \
           session.c \
           peer.c \
           netq.c \
           rijndael_wrap.c \
           rijndael.c \
           ecc.c \
           ccm.c \
           dtls_prng.c

CN_DTLS_OBJ =$(patsubst %.c,lib-client/%.o,$(DTLS_SRC))
SN_DTLS_OBJ =$(patsubst %.c,lib-server/%.o,$(DTLS_SRC))
CD_DTLS_OBJ =$(patsubst %.c,lib-client-dtls/%.o,$(DTLS_SRC))
SD_DTLS_OBJ =$(patsubst %.c,lib-server-dtls/%.o,$(DTLS_SRC))

CFLAGS += -g3 -Wall -Wextra -pedantic -O0

CN_APP_OBJ =$(patsubst %.c,lib-client/%.o,client.c client-coap.c)
SN_APP_OBJ =$(patsubst %.c,lib-server/%.o,server.c server-coap.c)
CD_APP_OBJ =$(patsubst %.c,lib-client-dtls/%.o,client.c client-coap.c)
SD_APP_OBJ =$(patsubst %.c,lib-server-dtls/%.o,server.c server-coap.c)


CN_OBJS = ${CN_APP_OBJ} ${CN_LWIP_OBJ} ${CN_COAP_OBJ}
SN_OBJS = ${SN_APP_OBJ} ${SN_LWIP_OBJ} ${SN_COAP_OBJ}
CD_OBJS = ${CD_APP_OBJ} ${CD_LWIP_OBJ} ${CD_COAP_OBJ} ${CD_DTLS_OBJ}
SD_OBJS = ${SD_APP_OBJ} ${SD_LWIP_OBJ} ${SD_COAP_OBJ} ${SD_DTLS_OBJ}

$(coap_include_dir)/coap.h:
	@(if [ ! -f $(coap_include_dir)/coap.h  ] ; then \
		(cd $(libcoap_dir) ; ./autogen.sh ; ./configure --disable-dtls --disable-man) ; \
		${MAKE}; \
	fi)

${SN_OBJS} ${SD_OBJS}: $(coap_include_dir)/coap.h server-coap.h

server: ${SN_OBJS}
	$(CC) $(CFLAGS) ${SN_OBJS} -o server ${LDLIBS}

server-dtls: ${SD_OBJS}
	$(CC) $(CFLAGS) ${SD_OBJS} -o server-dtls ${LDLIBS}

${CN_OBJS} ${CD_OBJS}: $(coap_include_dir)/coap.h client-coap.h

client: ${CN_OBJS}
	$(CC) $(CFLAGS) ${CN_OBJS} -o client ${LDLIBS}

client-dtls: ${CD_OBJS}
	$(CC) $(CFLAGS) ${CD_OBJS} -o client-dtls ${LDLIBS}

lib-server:
	@mkdir -p $@

lib-server/%.o: %.c config/lwipopts.h config/lwippools.h config/coap_config.h
	$(CC) ${CFLAGS} -DCOAP_SERVER_SUPPORT -c $< -o $@

lib-server-dtls:
	@mkdir -p $@

lib-server-dtls/%.o: %.c config/lwipopts.h config/lwippools.h config/coap_config.h
	$(CC) ${CFLAGS} ${TINYDTLS_CFLAGS} -DCOAP_SERVER_SUPPORT -c $< -o $@

lib-client:
	@mkdir -p $@

lib-client/%.o: %.c config/lwipopts.h config/lwippools.h config/coap_config.h
	$(CC) ${CFLAGS} -DCOAP_CLIENT_SUPPORT -c $< -o $@

lib-client-dtls:
	@mkdir -p $@

lib-client-dtls/%.o: %.c config/lwipopts.h config/lwippools.h config/coap_config.h
	$(CC) ${CFLAGS} ${TINYDTLS_CFLAGS} -DCOAP_CLIENT_SUPPORT -c $< -o $@

clean:
	rm -rf server server-dtls client client-dtls \
	${CN_OBJS} ${SN_OBJS} ${CD_OBJS} ${SD_OBJS} \
	lib-server lib-server-dtls lib-client lib-client-dtls

.PHONY: all clean
