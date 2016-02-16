#! /bin/sh

if test "x$TESTS" = "xyes" -o "x$TESTS" = "xtrue" ; then
    WITH_TESTS=--enable-tests
fi
     
config() {
    echo "./configure $*"
    ./configure $*
}

case "${PLATFORM}" in
    contiki) config "--disable-tests --disable-documentation --disable-examples" && \
               make -C examples/contiki
             ;;
    lwip)    config "--disable-tests --disable-documentation --disable-examples" && \
               make -C examples/lwip lwip lwip-contrib all
             ;;
    posix|*) config "$WITH_TESTS --enable-documentation --enable-examples" && \
               make
             ;;
esac

err=$?
if test $err = 0 -a -n "$WITH_TESTS" ; then
    tests/testdriver
    err=$?
fi

exit $err
