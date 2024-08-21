#! /bin/sh

# This script creates a libcoap archive, unpacks it and does an
# out-of-tree build and installation afterwards.
#
# Copyright (C) 2021-2024 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of the CoAP C library libcoap. Please see README
# and COPYING for terms of use.
#

PREFIX=--prefix=`pwd`/libcoap-install
ARCHIVE=`ls -1t libcoap-*.tar.bz2 |head -1`
err=$?
echo $ARCHIVE
if test $err = 0 -a "x$ARCHIVE" != "x"; then
    DIR=`pwd`/`tar taf $ARCHIVE |cut -d/ -f1|head -1`
    tar xaf $ARCHIVE && cd $DIR
    err=$terr

    # LwIP
    make -C $DIR/examples/lwip EXTRA_CFLAGS=-Werror
    terr=$?
    if [ $err = 0 ] ; then
        err=$terr
    fi

    # Contiki
    make -C $DIR/examples/contiki
    terr=$?
    if [ $err = 0 ] ; then
        err=$terr
    fi

    # RIOT
    make -C $DIR/examples/riot
    terr=$?
    if [ $err = 0 ] ; then
        err=$terr
    fi

    # Standard build
    $DIR/configure $PREFIX --enable-tests  --enable-silent-rules --enable-documentation --enable-examples --disable-dtls && \
    make EXTRA_CFLAGS=-Werror && make install EXTRA_CFLAGS=-Werror
    terr=$?
    if [ $err = 0 ] ; then
        err=$terr
    fi
fi

exit $err
