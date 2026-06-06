#
# SYNOPSIS
#
#   AX_PKG_CHECK_MBEDTLS(VARIABLE-PREFIX, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
#
# DESCRIPTION
#
#   This m4 file contains helper functions for checking the version and libraries
#   for MbedTLS which does not always have a pkg-config file.
#
# LICENSE
#
#   Copyright (c) 2026 Jon Shallow <supjps-libcoap@jpshallow.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

AC_DEFUN([AX_PKG_CHECK_MBEDTLS], [
AC_REQUIRE([PKG_PROG_PKG_CONFIG])
AC_REQUIRE([AC_PROG_CC])
AC_ARG_VAR([MbedTLS_CFLAGS], [C compiler flags for MbedTLS, overriding pkg-config])
AC_ARG_VAR([MbedTLS_LIBS], [linker flags for MbedTLS, overriding pkg-config])
AC_LANG_PUSH([C])

if test "x${MbedTLS_CFLAGS+set}" = "xset"; then
    mbedtls_cflags_overridden="yes"
else
    mbedtls_cflags_overridden="no"
fi

if test "x${MbedTLS_LIBS+set}" = "xset"; then
    mbedtls_libs_overridden="yes"
else
    mbedtls_libs_overridden="no"
fi

# If MbedTLS_CFLAGS and MbedTLS_LIBS are overridden, pkg-config will always assume the library was found, even
# though MbedTLS doesn't necessarily have a pkg-config file. Therefore, we might as well use the "old" way to
# determine whether we can link MbedTLS (and which version we have).
if test "x$mbedtls_libs_overridden" = "xyes" -a "x$mbedtls_cflags_overridden" = "xyes"; then
    have_$2="no"
    have_mbedtls="no"
    mbedtls_has_pkgconfig="no"
else
    # Attempt to find MbedTLS using pkg-config.

    # When statically linking against libcoap, all transitive dependencies need to be specified as linker flags
    # as well. Use pkg-config --static for that.
    if test "x$enable_static" = "xyes"; then
      KEEP_PKG_CONFIG=$PKG_CONFIG
      PKG_CONFIG="$PKG_CONFIG --static"
      PKG_CHECK_MODULES([MbedTLS],
                        [mbedtls],
                        [_have_mbedtls="yes"; $3; mbedtls_has_pkgconfig="yes"],
                        [_have_mbedtls="no" ; $4; mbedtls_has_pkgconfig="no"])
      PKG_CONFIG=$KEEP_PKG_CONFIG
    else
        PKG_CHECK_MODULES([MbedTLS],
                          [mbedtls],
                          [_have_mbedtls="yes"; $3; mbedtls_has_pkgconfig="yes"],
                          [_have_mbedtls="no" ; $4; mbedtls_has_pkgconfig="no"])
    fi
fi

if test "x$_have_mbedtls" = "xno"; then
    # Attempt to find mbedtls without pkg-config.

    # default linker flags (default CFLAGS are empty, so they don't need to be set).
    if test "x$mbedtls_libs_overridden" == "xno"; then
        MbedTLS_LIBS="-lmbedtls -lmbedcrypto -lmbedx509"
    fi

    # check whether we can find MbedTLS
    local_MbedTLS_save_CFLAGS=$CFLAGS
    CFLAGS="$MbedTLS_CFLAGS $CFLAGS"
    local_MbedTLS_save_LIBS=$LIBS
    LIBS="$MbedTLS_LIBS $LIBS"
    AC_CHECK_LIB(mbedtls, mbedtls_version_get_string,
                 [_have_mbedtls="yes"; $3],
                 [_have_mbedtls="no" ; $4])
    LIBS=$local_MbedTLS_save_LIBS
    CFLAGS=$local_MbedTLS_save_CFLAGS
fi

# here, we know whether we can find MbedTLS, but need to determine the version.
if test "x$_have_mbedtls" = "xyes"; then
    if test "x$mbedtls_has_pkgconfig" = "xyes"; then
        # If pkg-config found mbedtls, use it to determine the version.
        mbedtls_version=`$PKG_CONFIG --modversion mbedtls` ;
    elif test "x$cross_compiling" = "xyes" ; then
        # Have no option but to do this
        mbedtls_version=$mbedtls_version_required
    else
        # Get actual library version by compiling a test program.
        local_MbedTLS_save_CFLAGS=$CFLAGS
        CFLAGS="$MbedTLS_CFLAGS $CFLAGS"
        local_MbedTLS_save_LIBS=$LIBS
        LIBS="$MbedTLS_LIBS $LIBS"
        AC_LINK_IFELSE([
                AC_LANG_SOURCE(
                    [[#include <stdio.h>
                     #include <mbedtls/version.h>
                     int main () {
                       char str[20];
                       mbedtls_version_get_string(str);
                       fprintf(stdout,"%s\n",str);
                       return 0;
                     }]])],
               [mbedtls_version=$(./conftest$EXEEXT)],
               [AC_MSG_WARN(Failed to determine Mbed TLS version)
                $4])
        LIBS=$local_MbedTLS_save_LIBS
        CFLAGS=$local_MbedTLS_save_CFLAGS
    fi
fi
AC_LANG_POP
]) dnl AX_PKG_CHECK_MBEDTLS
