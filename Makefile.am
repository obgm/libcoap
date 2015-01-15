# Makefile.am for libcoap
#
# Copyright (C) 2010-2015 Olaf Bergmann <bergmann@tzi.org>
#           (C)      2015 Carsten Schoenert <c.schoenert@t-online.de>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.

SUBDIRS = include

## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

## default CFLAGS
DEFAULT_CFLAGS = -D_GNU_SOURCE -DWITH_POSIX -Wall -Wextra -Wunused -Wunused-result -Wlogical-op -Winline -Wswitch-default -Wswitch-enum -fPIC -pedantic -Wformat -Wformat-security -fPIE -pie

AM_CFLAGS = -I @top_builddir@/include/coap/ $(DEFAULT_CFLAGS) -std=c99

## The libtool archive file (.la) will be installed into the directory named
## by the predefined variable $(bindir), along with the actual shared library
## file (.so).
lib_LTLIBRARIES = libcoap.la

## Define the source file list for the "libcoap.la" target.
## Note that it is not necessary to list header files which are already listed
## elsewhere in a _HEADERS variable assignment.
libcoap_la_SOURCES = \
  src/async.c \
  src/block.c \
  src/coap_io.c \
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

## Instruct libtool to add the library version '0.0.0' into the shared library
## file (.so). This will be changed later to a substituted version via variables.
libcoap_la_LDFLAGS = -version-info 0

## Install the generated pkg-config file (.pc) into the expected location for
## architecture-dependent package configuration information.  Occasionally,
## pkg-config files are also used for architecture-independent data packages,
## in which case the correct install location would be $(datadir)/pkgconfig.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcoap.pc

## Define an independent executable script for inclusion in the distribution
## archive.  However, it will not be installed on an end user's system due to
## the noinst_ prefix.
dist_noinst_SCRIPTS = autogen.sh

