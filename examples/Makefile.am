# examples/Makefile.am
#
# Copyright (C)      2015 Carsten Schoenert <c.schoenert@t-online.de>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

# just do nothing if 'BUILD_EXAMPLES' isn't defined
if BUILD_EXAMPLES

# picking up the default warning CFLAGS into AM_CFLAGS
AM_CFLAGS = -I$(top_builddir)/include -I$(top_srcdir)/include \
            -I$(top_srcdir)/include/coap$(LIBCOAP_API_VERSION) \
            $(WARNING_CFLAGS) $(DTLS_CFLAGS) -std=c99

# etsi_iot_01 and tiny are missing
bin_PROGRAMS = coap-client coap-server coap-rd

coap_client_SOURCES = client.c
coap_client_LDADD =  $(top_builddir)/.libs/libcoap-$(LIBCOAP_NAME_SUFFIX).la

coap_server_SOURCES = coap-server.c
coap_server_LDADD = $(top_builddir)/.libs/libcoap-$(LIBCOAP_NAME_SUFFIX).la

coap_rd_SOURCES = coap-rd.c
coap_rd_LDADD = $(top_builddir)/.libs/libcoap-$(LIBCOAP_NAME_SUFFIX).la

endif # BUILD_EXAMPLES
