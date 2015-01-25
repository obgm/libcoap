# doc/Makefile.am
#
# Copyright (C)      2015 Carsten Schoenert <c.schoenert@t-online.de>
#
# This file is part of the CoAP C library libcoap. Please see README and
# COPYING for terms of use.


# We can only perfom the targets in this directory if doxygen is present.

if HAVE_DOXYGEN
directory = $(builddir)/html

dist_man_MANS = $(directory)/html
$(directory)/html: doxyfile.stamp
	$(directory): doxyfile.stamp

doxyfile.stamp:
	$(DOXYGEN) Doxyfile
	echo Timestamp > doxyfile.stamp

CLEANFILES = doxyfile.stamp doxygen_sqlite3.db

all-local: doxyfile.stamp

clean-local:
	rm -rf $(directory)

install-exec-am: all-local
	$(MKDIR_P) $(htmldir)/html || exit 1
	cp -a $(directory) $(htmldir)

endif # HAVE_DOXYGEN
