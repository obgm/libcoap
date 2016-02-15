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
               (cd examples/contiki && make V=1 contiki all)
             ;;
    lwip)    config "--disable-tests --disable-documentation --disable-examples" && \
               (cd examples/lwip && make lwip lwip-contrib all)
             ;;
    posix|*) config "$WITH_TESTS --enable-documentation --enable-examples" && make
             ;;
esac

if test -n "$WITH_TESTS" ; then
    tests/testdriver
fi
