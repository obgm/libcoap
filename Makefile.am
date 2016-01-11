# Makefile.am for libcoap
#
# Copyright (C) 2010-2015 Olaf Bergmann <bergmann@tzi.org>
#           (C)      2015 Carsten Schoenert <c.schoenert@t-online.de>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

## Additional files for the distribution archive
EXTRA_DIST = \
  CONTRIBUTE \
  TODO \
  $(pkgconfig_DATA).in \
  libcoap-$(LIBCOAP_API_VERSION).map \
  libcoap-$(LIBCOAP_API_VERSION).sym \
  examples/coap_list.h \
  tests/test_options.h \
  tests/test_pdu.h \
  tests/test_error_response.h \
  tests/test_sendqueue.h \
  tests/test_uri.h \
  tests/test_wellknown.h

AM_CFLAGS = -I @top_builddir@/include/coap/ $(WARNING_CFLAGS) -std=c99

SUBDIRS = . $(DOC_DIR) tests examples

## Define a libtool archive target "libcoap-@LIBCOAP_API_VERSION@.la", with
## @LIBCOAP_API_VERSION@ substituted into the generated Makefile at configure
## time.
## The libtool archive file (.la) will be installed into the directory named
## by the predefined variable $(bindir), along with the actual shared library
## file (.so).
lib_LTLIBRARIES = libcoap-@LIBCOAP_API_VERSION@.la

libcoap_@LIBCOAP_API_VERSION@_la_CFLAGS = \
  -fPIC \
  -fPIE \
  $(AM_CFLAGS)

## Define the source file list for the "libcoap.la" target.
## Note that it is not necessary to list header files which are already listed
## elsewhere in a _HEADERS variable assignment.
libcoap_@LIBCOAP_API_VERSION@_la_SOURCES = \
  src/address.c \
  src/async.c \
  src/block.c \
  src/coap_io.c \
  src/coap_time.c \
  src/debug.c \
  src/encode.c \
  src/hashkey.c \
  src/mem.c \
  src/net.c \
  src/option.c \
  src/pdu.c \
  src/resource.c \
  src/str.c \
  src/subscribe.c \
  src/uri.c

## Define the list of public header files and their install location.
## The list defined here will be used within the include/Makefile.am
## and is only a variable because the content is needed also for the
## generating of the symbol mapping file.
libcoap_includedir = $(includedir)/coap/
libcoap_include_HEADERS = \
   include/coap/address.h \
   include/coap/async.h \
   include/coap/bits.h \
   include/coap/block.h \
   include/coap/coap.h \
   include/coap/coap_io.h \
   include/coap/coap_time.h \
   include/coap/debug.h \
   include/coap/encode.h \
   include/coap/hashkey.h \
   include/coap/libcoap.h \
   include/coap/mem.h \
   include/coap/net.h \
   include/coap/option.h \
   include/coap/pdu.h \
   include/coap/prng.h \
   include/coap/resource.h \
   include/coap/str.h \
   include/coap/subscribe.h \
   include/coap/uri.h \
   include/coap/uthash.h \
   include/coap/utlist.h

# If there is a API change to something $(LIBCOAP_API_VERSION) > 1 the install
# prefix for the header files has to change to not conflict the older version
# if the user want's to install both versions. There will be something used like
# libcoap_include_HEADERS = \
#   include/coap-$(LIBCOAP_API_VERSION)/*


## Instruct libtool to include API version information in the generated shared
## library file (.so). The library ABI version will later defined in configure.ac,
## so that all version information is kept in one place.
libcoap_@LIBCOAP_API_VERSION@_la_LDFLAGS =					\
  -version-info $(LT_LIBCOAP_CURRENT):$(LT_LIBCOAP_REVISION):$(LT_LIBCOAP_AGE)	\
  @libcoap_SYMBOLS@ \
  -pie

CTAGS_IGNORE=-I "coap_packet_extract_pbuf coap_pdu_from_pbuf"

.PHONY:	update-map-file check_ctags

# This helper is called by libcoap-$(LIBCOAP_API_VERSION).{map,sym} to see if
# configure has detected a usable version of the ctags program and aborts if not.
check_ctags:
	@if [ "$(CTAGS_PROG)" = "" ]; then \
		echo ;\
		echo "There was no ctags program found by the configure script!" ;\
		echo "ctags is needed for running this target! Please note the warning about the missed ctags program of the configure script." ;\
		echo ;\
		exit 1;\
	fi

## Helper target to generate the symbol table needed by libtool.
## The .map format is used when ld supports linker scripts, otherwise
## it must fall back to a plain symbol file.
update-map-file: libcoap-$(LIBCOAP_API_VERSION).map libcoap-$(LIBCOAP_API_VERSION).sym

libcoap-$(LIBCOAP_API_VERSION).map: check_ctags $(libcoap_include_HEADERS)
	( echo "VER_$(LIBCOAP_API_VERSION) {" ; \
	echo "global:" ; \
	ctags $(CTAGS_IGNORE) -f - --c-kinds=p $(libcoap_include_HEADERS) | awk '/^coap_/ { print "  " $$1 ";" }' | sort ; \
	echo "local:" ; \
	echo "  *;" ; \
	echo "};" ) > $@.new
	mv $@.new $@

libcoap-$(LIBCOAP_API_VERSION).sym: check_ctags $(libcoap_include_HEADERS)
	( ctags $(CTAGS_IGNORE) -f - --c-kinds=p $(libcoap_include_HEADERS) | awk '/^coap_/ { print $$1 }' | sort ) \
	> $@.new
	mv $@.new $@

## Install the generated pkg-config file (.pc) into the expected location for
## architecture-dependent package configuration information.  Occasionally,
## pkg-config files are also used for architecture-independent data packages,
## in which case the correct install location would be $(datadir)/pkgconfig.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcoap-$(LIBCOAP_API_VERSION).pc

## Define an independent executable script for inclusion in the distribution
## archive.  However, it will not be installed on an end user's system due to
## the noinst_ prefix.
dist_noinst_SCRIPTS = autogen.sh

