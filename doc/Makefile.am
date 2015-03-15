# doc/Makefile.am
#
# Copyright (C)      2015 Carsten Schoenert <c.schoenert@t-online.de>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.


# We can only perfom the targets in this directory if doxygen is present.

if HAVE_DOXYGEN

dist_pkgdata_DATA = doxyfile.stamp

CLEANFILES = \
  doxyfile.stamp \
  doxygen_sqlite3.db

doxyfile.stamp:
	$(DOXYGEN) Doxyfile
	echo Timestamp > doxyfile.stamp

all-local: doxyfile.stamp

clean-local:
	rm -rf $(srcdir)/html

install-data-am: all-local
	$(MKDIR_P) $(htmldir)/html || exit 1
	cp -a $(srcdir)/html $(htmldir)

.PHONY: doxyfile.stamp

endif # HAVE_DOXYGEN
