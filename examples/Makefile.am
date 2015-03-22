# doc/Makefile.am
#
# Copyright (C)      2015 Carsten Schoenert <c.schoenert@t-online.de>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

# just do nothing if 'BUILD_EXAMPLES' isn't defined
if BUILD_EXAMPLES

# picking up the default warning CFLAGS into AM_CFLAGS
AM_CFLAGS = -isystem@top_builddir@/include/coap/ $(WARNING_CFLAGS) -std=c99

# etsi_iot_01 and tiny are missing
bin_PROGRAMS = coap-client coap-server rd

coap_client_SOURCES = client.c coap_list.c
coap_client_LDADD = @top_builddir@/.libs/libcoap-$(LIBCOAP_API_VERSION).la

coap_server_SOURCES = server.c
coap_server_LDADD = @top_builddir@/.libs/libcoap-$(LIBCOAP_API_VERSION).la

rd_SOURCES = rd.c
rd_LDADD = @top_builddir@/.libs/libcoap-$(LIBCOAP_API_VERSION).la

endif # BUILD_EXAMPLES
