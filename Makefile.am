# Makefile.am for libcoap
#
# Copyright (C) 2010-2024 Olaf Bergmann <bergmann@tzi.org>
# Copyright (C) 2015-2017 Carsten Schoenert <c.schoenert@t-online.de>
# Copyright (C) 2018-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

LIBCOAP_PACKAGE_BUILD = @DOLLAR_SIGN@(shell git describe --tags --dirty --always 2>/dev/null || echo @PACKAGE_VERSION@)

## Source files specifically for OSCORE
libcoap_OSCORE_sources = \
  src/oscore/oscore.c \
  src/oscore/oscore_cbor.c \
  src/oscore/oscore_context.c \
  src/oscore/oscore_cose.c \
  src/oscore/oscore_crypto.c

## Additional files for the distribution archive
EXTRA_DIST = \
  BUILDING \
  CONTRIBUTE \
  TODO \
  LICENSE \
  CMakeLists.txt \
  cmake_coap_config.h.in \
  cmake/Config.cmake.in \
  cmake/FindMbedTLS.cmake \
  cmake/FindTinyDTLS.cmake \
  coap_config.h.contiki \
  coap_config.h.riot \
  coap_config.h.windows \
  libcoap-$(LIBCOAP_API_VERSION).pc.in \
  libcoap-$(LIBCOAP_API_VERSION).map \
  libcoap-$(LIBCOAP_API_VERSION).sym \
  examples/coap_list.h \
  examples/getopt.c \
  examples/contiki/coap_config.h \
  examples/contiki/Makefile \
  examples/contiki/Makefile.contiki \
  examples/contiki/project-conf.h \
  examples/contiki/README \
  examples/contiki/server.c \
  examples/lwip/client.c \
  examples/lwip/client-coap.c \
  examples/lwip/client-coap.h \
  examples/lwip/Makefile \
  examples/lwip/README \
  examples/lwip/server.c \
  examples/lwip/server-coap.c \
  examples/lwip/server-coap.h \
  examples/lwip/config/coap_config.h \
  examples/lwip/config/coap_config.h.in \
  examples/lwip/config/lwipopts.h \
  examples/lwip/config/lwippools.h \
  examples/riot/examples_libcoap_client/client-coap.c \
  examples/riot/examples_libcoap_client/client-coap.h \
  examples/riot/examples_libcoap_client/Kconfig \
  examples/riot/examples_libcoap_client/main.c \
  examples/riot/examples_libcoap_client/Makefile \
  examples/riot/examples_libcoap_client/Makefile.ci \
  examples/riot/examples_libcoap_client/README.md \
  examples/riot/examples_libcoap_server/main.c \
  examples/riot/examples_libcoap_server/Makefile \
  examples/riot/examples_libcoap_server/Makefile.ci \
  examples/riot/examples_libcoap_server/README.md \
  examples/riot/examples_libcoap_server/server-coap.c \
  examples/riot/examples_libcoap_server/server-coap.h \
  examples/riot/examples_libcoap_server/Kconfig \
  examples/riot/Makefile \
  examples/riot/pkg_libcoap/Kconfig \
  examples/riot/pkg_libcoap/Makefile \
  examples/riot/pkg_libcoap/Makefile.dep \
  examples/riot/pkg_libcoap/Makefile.include \
  examples/riot/pkg_libcoap/Makefile.libcoap \
  examples/riot/tests_pkg_libcoap/app.config \
  examples/riot/tests_pkg_libcoap/Kconfig \
  examples/riot/tests_pkg_libcoap/libcoap-test.c \
  examples/riot/tests_pkg_libcoap/libcoap-test.h \
  examples/riot/tests_pkg_libcoap/main.c \
  examples/riot/tests_pkg_libcoap/Makefile \
  examples/riot/tests_pkg_libcoap/Makefile.ci \
  examples/riot/tests_pkg_libcoap/README.md \
  examples/riot/tests_pkg_libcoap/tests/01-run.py \
  examples/riot/README \
  Makefile.libcoap \
  include/coap$(LIBCOAP_API_VERSION)/coap_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_riot.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_asn1_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_async_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_block_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_cache_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_crypto_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_debug_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_dtls_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_hashkey_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_io_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_layers_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_mutex_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_net_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_netif_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_oscore_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_pdu_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_resource_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_session_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_sha1_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_subscribe_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_tcp_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_threadsafe_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_uri_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_uthash_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_utlist_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap_ws_internal.h \
  include/coap$(LIBCOAP_API_VERSION)/coap.h.in \
  include/coap$(LIBCOAP_API_VERSION)/coap.h.riot \
  include/coap$(LIBCOAP_API_VERSION)/coap.h.riot.in \
  include/coap$(LIBCOAP_API_VERSION)/coap.h.windows \
  include/coap$(LIBCOAP_API_VERSION)/coap.h.windows.in \
  include/oscore/oscore_cbor.h \
  include/oscore/oscore_context.h \
  include/oscore/oscore_cose.h \
  include/oscore/oscore_crypto.h \
  include/oscore/oscore.h \
  src/coap_io_contiki.c \
  src/coap_io_lwip.c \
  src/coap_io_riot.c \
  tests/test_error_response.h \
  tests/test_encode.h \
  tests/test_options.h \
  tests/test_oscore.h \
  tests/test_pdu.h \
  tests/test_sendqueue.h \
  tests/test_session.h \
  tests/test_tls.h \
  tests/test_uri.h \
  tests/test_wellknown.h \
  win32/coap-client/coap-client.vcxproj \
  win32/coap-client/coap-client.vcxproj.filters \
  win32/coap-rd/coap-rd.vcxproj \
  win32/coap-rd/coap-rd.vcxproj.filters \
  win32/coap-server/coap-server.vcxproj \
  win32/coap-server/coap-server.vcxproj.filters \
  win32/libcoap.sln \
  win32/libcoap.vcxproj \
  win32/libcoap.vcxproj.filters \
  win32/testdriver/testdriver.vcxproj \
  win32/testdriver/testdriver.vcxproj.filters \
  win32/testdriver/testdriver.vcxproj.user

# This is a mirror of files depending on COAP_OSCORE_SUPPORT included in src as per
# libcoap_@LIBCOAP_NAME_SUFFIX@_la_SOURCES
if !COAP_OSCORE_SUPPORT
EXTRA_DIST += $(libcoap_OSCORE_sources)

endif # !COAP_OSCORE_SUPPORT

AM_CFLAGS = -I$(top_builddir)/include -I$(top_srcdir)/include $(WARNING_CFLAGS) \
            $(DTLS_CFLAGS) -std=c99 $(EXTRA_CFLAGS) \
            -DLIBCOAP_PACKAGE_BUILD='"$(LIBCOAP_PACKAGE_BUILD)"'

SUBDIRS = $(subdirs) . man doc tests examples

## Define a libtool archive target "libcoap-@LIBCOAP_NAME_SUFFIX@.la", with
## @LIBCOAP_NAME_SUFFIX@ substituted into the generated Makefile at configure
## time.
## The libtool archive file (.la) will be installed into the directory named
## by the predefined variable $(bindir), along with the actual shared library
## file (.so).
lib_LTLIBRARIES = libcoap-@LIBCOAP_NAME_SUFFIX@.la

libcoap_@LIBCOAP_NAME_SUFFIX@_la_CFLAGS = \
  -fPIC \
  -fPIE \
  $(AM_CFLAGS)

## Define the source file list for the "libcoap.la" target.
## Note that it is not necessary to list header files which are already listed
## elsewhere in a _HEADERS variable assignment.
libcoap_@LIBCOAP_NAME_SUFFIX@_la_SOURCES = \
  src/coap_address.c \
  src/coap_asn1.c \
  src/coap_async.c \
  src/coap_block.c \
  src/coap_cache.c \
  src/coap_debug.c \
  src/coap_dtls.c \
  src/coap_encode.c \
  src/coap_event.c \
  src/coap_hashkey.c \
  src/coap_gnutls.c \
  src/coap_io.c \
  src/coap_layers.c \
  src/coap_mbedtls.c \
  src/coap_mem.c \
  src/coap_net.c \
  src/coap_netif.c \
  src/coap_notls.c \
  src/coap_openssl.c \
  src/coap_option.c \
  src/coap_oscore.c \
  src/coap_pdu.c \
  src/coap_prng.c \
  src/coap_resource.c \
  src/coap_session.c \
  src/coap_sha1.c \
  src/coap_str.c \
  src/coap_subscribe.c \
  src/coap_tcp.c \
  src/coap_threadsafe.c \
  src/coap_time.c \
  src/coap_tinydtls.c \
  src/coap_uri.c \
  src/coap_ws.c

if COAP_OSCORE_SUPPORT
libcoap_@LIBCOAP_NAME_SUFFIX@_la_SOURCES += $(libcoap_OSCORE_sources)

endif # COAP_OSCORE_SUPPORT

## Define the list of public header files and their install location.
## The API version is appended to the install folder to being able to
## co-install various versions of libcoap.
libcoap_includedir = $(includedir)/coap$(LIBCOAP_API_VERSION)/

# If there is a API change to something $(LIBCOAP_API_VERSION) > 1 the install
# prefix for the header files has to change to not conflict the older version
# if the user want's to install both versions. There will be something used like
# libcoap_include_HEADERS = \
#  $(top_srcdir)/include/coap-$(LIBCOAP_API_VERSION)/*

libcoap_include_HEADERS = \
  $(top_builddir)/include/coap$(LIBCOAP_API_VERSION)/coap.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/libcoap.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_address.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_async.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_block.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_cache.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_debug.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_dtls.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_encode.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_event.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_forward_decls.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_io.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_mem.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_net.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_option.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_oscore.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_pdu.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_prng.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_resource.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_session.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_str.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_subscribe.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_time.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_uri.h \
  $(top_srcdir)/include/coap$(LIBCOAP_API_VERSION)/coap_ws.h

## Instruct libtool to include API version information in the generated shared
## library file (.so). The library ABI version will later defined in configure.ac,
## so that all version information is kept in one place.
libcoap_@LIBCOAP_NAME_SUFFIX@_la_LDFLAGS =					\
  -version-info $(LT_LIBCOAP_CURRENT):$(LT_LIBCOAP_REVISION):$(LT_LIBCOAP_AGE)	\
  @libcoap_SYMBOLS@ \
  $(DTLS_LIBS) \
  -pie

## Collect symbols here we want to ignore while building the helper files
## libcoap-$(LIBCOAP_API_VERSION).{map,sym} for the linker.
CTAGS_IGNORE=-I " \
coap_pdu_from_pbuf \
coap_lwip_dump_memory_pools \
coap_lwip_set_input_wait_handler \
coap_print_contiki_prefix \
"

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
	$(CTAGS_PROG) $(CTAGS_IGNORE) -f - --c-kinds=p $(libcoap_include_HEADERS) | awk '/^coap_/ { print "  " $$1 ";" }' | LC_ALL=C sort -u ; \
	echo "local:" ; \
	echo "  *;" ; \
	echo "};" ) > $(top_builddir)/$@.new
	mv $(top_builddir)/$@.new $(top_builddir)/$@

libcoap-$(LIBCOAP_API_VERSION).sym: check_ctags $(libcoap_include_HEADERS)
	( $(CTAGS_PROG) $(CTAGS_IGNORE) -f - --c-kinds=p $(libcoap_include_HEADERS) | awk '/^coap_/ { print $$1 }' | LC_ALL=C sort -u ) \
	> $(top_builddir)/$@.new
	mv $(top_builddir)/$@.new $(top_builddir)/$@

## Install the generated pkg-config file (.pc) into the expected location for
## architecture-dependent package configuration information.  Occasionally,
## pkg-config files are also used for architecture-independent data packages,
## in which case the correct install location would be $(datadir)/pkgconfig.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcoap-$(LIBCOAP_NAME_SUFFIX).pc

## Define an independent executable script for inclusion in the distribution
## archive.  However, it will not be installed on an end user's system due to
## the noinst_ prefix.
dist_noinst_SCRIPTS = autogen.sh

## Set up a common library that causes linking against the common library
## to link with the actual library with (D)TLS support
if BUILD_ADD_DEFAULT_NAMES
install-exec-hook:
	(cd $(DESTDIR)$(libdir) ; \
	if [ -f libcoap-$(LIBCOAP_NAME_SUFFIX).so ] ; then \
		rm -f libcoap-$(LIBCOAP_API_VERSION).so ; \
		$(LN_S) libcoap-$(LIBCOAP_NAME_SUFFIX).so libcoap-$(LIBCOAP_API_VERSION).so ; \
	fi ; \
	rm -f libcoap-$(LIBCOAP_API_VERSION).a ; \
	rm -f libcoap-$(LIBCOAP_API_VERSION).la ; \
	$(LN_S) libcoap-$(LIBCOAP_NAME_SUFFIX).a libcoap-$(LIBCOAP_API_VERSION).a ; \
	$(LN_S) libcoap-$(LIBCOAP_NAME_SUFFIX).la libcoap-$(LIBCOAP_API_VERSION).la ; \
	$(MKDIR_P) $(DESTDIR)$(pkgconfigdir) ; \
	cd $(DESTDIR)$(pkgconfigdir) ; \
	rm -f libcoap-$(LIBCOAP_API_VERSION).pc ; \
	$(LN_S) libcoap-$(LIBCOAP_NAME_SUFFIX).pc libcoap-$(LIBCOAP_API_VERSION).pc)

uninstall-hook:
	(cd $(DESTDIR)$(libdir) ; \
	rm -f libcoap-$(LIBCOAP_API_VERSION).a ; \
	rm -f libcoap-$(LIBCOAP_API_VERSION).la ; \
	rm -f libcoap-$(LIBCOAP_API_VERSION).so ; \
	cd $(DESTDIR)$(pkgconfigdir) ; \
	rm -f libcoap-$(LIBCOAP_API_VERSION).pc)
endif # BUILD_ADD_DEFAULT_NAMES

## various *-local targets
## Remove the helper files for the linker and the pkg-config file if there
## is 'make distclean' called. NOTE: To re create the *.{map,sym} files you
## need to call the target update-map-file after the configure script was
## running!
clean-local:
	-find \( -name '*.gcda' -o -name '*.gcno' -o -name '*.gcov' \) -delete

distclean-local:
	@rm -f src/*.o src/*.lo
	rm -f libcoap-$(LIBCOAP_API_VERSION).map
	rm -f libcoap-$(LIBCOAP_API_VERSION).sym
	rm -f libcoap-$(LIBCOAP_NAME_SUFFIX).pc
	@echo
	@echo "     ---> Please note the following important advice! <---"
	@echo "     The files libcoap-$(LIBCOAP_API_VERSION).{map,sym} are removed by the distclean target!"
	@echo "     To regenerate this two files you need to call 'make update-map-file' first before any"
	@echo "     other Make target. Otherwise the build of libcoap will fail!"
	@echo

## Ensure we have actual *.{map,sym} files if we create a release tarball.
dist-local: update-map-file

## Finaly some phony targets, just to ensure those targets are always buildable
## no matter if the user has created same called files.
.PHONY: update-map-file check_ctags

