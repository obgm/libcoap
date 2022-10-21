# Makefile
#
#  Copyright (C) 2010-2022 Olaf Bergmann <bergmann@tzi.org> and others
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

# Need to determine which library clock_gettime() resides in (as found by ./autogen.sh)
LDLIBS := $(shell if [ -f $(libcoap_dir)/config.log ] ; then \
          grep ac_cv_search_clock_gettime=- $(libcoap_dir)/config.log|cut -d= -f2 ; fi)

all: lib-server lib-client lwip lwip-contrib check-version \
     $(coap_include_dir)/coap.h server client

lwip:
	git clone --depth 1 git://git.savannah.nongnu.org/lwip.git -b $(WITH_LWIP_BRANCH)
	(cd lwip ; git checkout $(WITH_LWIP_BRANCH))
	$(MAKE)

lwip-contrib:
	git clone --depth 1 git://git.savannah.nongnu.org/lwip/lwip-contrib.git -b $(WITH_LWIP_CONTRIB_BRANCH)
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

# lwip and coap opts (include early to shadow the lwip-contrib/ports/unix/proj/minimal/ file and any ../../config.h)
CFLAGS += -DWITH_LWIP -iquote./config

# lwip library

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

C_LWIP_OBJ =$(patsubst %.c,lib-client/%.o,$(LWIP_SRC))
S_LWIP_OBJ =$(patsubst %.c,lib-server/%.o,$(LWIP_SRC))
# coap library

CFLAGS += -std=gnu99

CFLAGS += -I$(libcoap_dir)/include

vpath %.c $(libcoap_dir)/src

COAP_SRC = coap_address.c \
	   coap_async.c \
	   block.c \
	   coap_cache.c \
	   coap_debug.c \
	   encode.c \
	   coap_hashkey.c \
	   coap_io.c \
	   coap_io_lwip.c \
	   net.c \
	   coap_notls.c \
	   coap_option.c \
	   pdu.c \
	   resource.c \
	   coap_session.c \
	   coap_subscribe.c \
	   str.c \
	   coap_tcp.c \
	   uri.c

C_COAP_OBJ =$(patsubst %.c,lib-client/%.o,$(COAP_SRC))
S_COAP_OBJ =$(patsubst %.c,lib-server/%.o,$(COAP_SRC))

CFLAGS += -g3 -Wall -Wextra -pedantic -O0

CFLAGS += -Ilwip/src/include/ -Ilwip/src/include/ipv4/ \
	  -Ilwip-contrib/ports/unix/port/include/ \
	  -Ilwip-contrib/ports/unix/proj/minimal/

SOBJS = server.o server-coap.o ${S_LWIP_OBJ} ${S_COAP_OBJ}

COBJS = client.o client-coap.o ${C_LWIP_OBJ} ${C_COAP_OBJ}

$(coap_include_dir)/coap.h:
	@echo "Error: $@ not present. Run the autotools chain (\`./autogen.sh && ./configure\`) in the project root directory to build the required coap.h file."
	@exit 1

${SOBJS}: $(coap_include_dir)/coap.h server-coap.h

server: ${SOBJS}

${COBJS}: $(coap_include_dir)/coap.h client-coap.h

client: ${COBJS}

lib-server:
	@mkdir -p $@

lib-server/%.o: %.c config/lwipopts.h config/lwippools.h config/coap_config.h
	$(CC) ${CFLAGS} -DCOAP_SERVER_SUPPORT -c $< -o $@

lib-client:
	@mkdir -p $@

lib-client/%.o: %.c config/lwipopts.h config/lwippools.h config/coap_config.h
	$(CC) ${CFLAGS} -DCOAP_CLIENT_SUPPORT -c $< -o $@

clean:
	rm -rf server client ${COBJS} ${SOBJS} lib-server lib-client

.PHONY: all clean
