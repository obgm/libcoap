#!/bin/sh -e

PROJECT="libcoap"

AUTOGEN_FILES="INSTALL \
		aclocal.m4 ar-lib \
		coap_config.h coap_config.h.in* compile config.guess config.h* config.log config.status config.sub configure \
		depcomp \
		install-sh \
		libtool ltmain.sh \
		missing \
		Makefile Makefile.in \
		stamp-h1 src/.dirstamp libcoap*.la* src/*.lo"

AUTOGEN_DIRS=".deps .libs autom4te.cache/ m4/ src/.libs/ src/.deps/"

if [ "$1" = "--clean" ]; then
    echo "removing autogerated files ..."
    rm -rf $AUTOGEN_FILES $AUTOGEN_DIRS
    echo "done"
    exit
else
    echo "[HINT] You can run 'autogen.sh --clean' to remove all generated files by the autotools."
    echo
fi

test -n "$srcdir" || srcdir=`dirname "$0"`
test -n "$srcdir" || srcdir=.

echo "Generating needed autotools files for $PROJECT by running autoreconf ..."
autoreconf --force --install --verbose "$srcdir"

echo
echo "You can now run 'configure --help' to see possible configuration options."
echo "Otherwise process the configure script to create the makefiles and generated helper files."
echo
