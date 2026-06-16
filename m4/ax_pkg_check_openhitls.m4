#
# SYNOPSIS
#
#   AX_PKG_CHECK_OPENHITLS(MODE, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
#
# DESCRIPTION
#
#   This m4 file contains helper functions for checking the headers and
#   libraries for openHiTLS which does not always have a pkg-config file.
#
# LICENSE
#
#   Copyright (c) 2026 openHiTLS Project
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

AC_DEFUN([AX_PKG_CHECK_OPENHITLS], [
AC_REQUIRE([PKG_PROG_PKG_CONFIG])
AC_REQUIRE([AC_PROG_CC])
AC_ARG_VAR([OpenHiTLS_CFLAGS], [C compiler flags for openHiTLS, overriding pkg-config])
AC_ARG_VAR([OpenHiTLS_LIBS], [linker flags for openHiTLS, overriding pkg-config])
AC_LANG_PUSH([C])

if test "x$1" != "xdtls" -a "x$1" != "xoscore"; then
    AC_MSG_ERROR([==> Invalid openHiTLS check mode '$1'.])
fi

# pkg-config module name and manual fallback flags per mode. openHiTLS does not
# yet ship a .pc file, so the pkg-config probe below normally fails and we fall
# back to the default flags.
# pkg-config metadata. Update openhitls_pc_module when that name is known.
if test "x$1" = "xdtls"; then
    openhitls_pc_module="hitls"
    if test -d /usr/local/include/hitls ; then
      openhitls_default_cflags="-I/usr/local/include -I/usr/local/include/hitls/tls -I/usr/local/include/hitls/bsl -I/usr/local/include/hitls/crypto -I/usr/local/include/hitls/pki"
    else
      openhitls_default_cflags="-I/usr/include/hitls/tls -I/usr/include/hitls/bsl -I/usr/include/hitls/crypto -I/usr/include/hitls/pki"
    fi
    openhitls_default_libs="-lhitls_tls -lhitls_crypto -lhitls_pki -lhitls_bsl -ldl"
else
    openhitls_pc_module="hitls_crypto"
    if test -d /usr/local/include/hitls ; then
      openhitls_default_cflags="-I/usr/local/include -I/usr/local/include/hitls/bsl -I/usr/local/include/hitls/crypto"
    else
      openhitls_default_cflags="-I/usr/include/hitls/bsl -I/usr/include/hitls/crypto"
    fi
    openhitls_default_libs="-lhitls_crypto -lhitls_bsl -ldl"
fi

if test "x${OpenHiTLS_CFLAGS+set}" = "xset"; then
    openhitls_cflags_overridden="yes"
else
    openhitls_cflags_overridden="no"
fi
if test "x${OpenHiTLS_LIBS+set}" = "xset"; then
    openhitls_libs_overridden="yes"
else
    openhitls_libs_overridden="no"
fi

# If OpenHiTLS_CFLAGS and OpenHiTLS_LIBS are overridden, pkg-config would always
# assume the library was found, so skip it and use the supplied flags directly.
openhitls_has_pkgconfig="no"
if test "x$openhitls_libs_overridden" = "xyes" -a "x$openhitls_cflags_overridden" = "xyes"; then
    openhitls_has_pkgconfig="no"
else
    # When statically linking against libcoap, all transitive dependencies need
    # to be specified as linker flags as well. Use pkg-config --static for that.
    if test "x$enable_static" = "xyes"; then
        KEEP_PKG_CONFIG=$PKG_CONFIG
        PKG_CONFIG="$PKG_CONFIG --static"
        PKG_CHECK_MODULES([OpenHiTLS],
                          [$openhitls_pc_module],
                          [openhitls_has_pkgconfig="yes"],
                          [openhitls_has_pkgconfig="no"])
        PKG_CONFIG=$KEEP_PKG_CONFIG
    else
        PKG_CHECK_MODULES([OpenHiTLS],
                          [$openhitls_pc_module],
                          [openhitls_has_pkgconfig="yes"],
                          [openhitls_has_pkgconfig="no"])
    fi
fi

# Fall back to the default flags when pkg-config did not provide them.
openhitls_lib_dir=""
if test "x$OpenHiTLS_CFLAGS" = "x"; then
    OpenHiTLS_CFLAGS="$openhitls_default_cflags"
    openhitls_lib_dir="-L/usr/local/lib -L/usr/local/lib64"
fi

if test "x$OpenHiTLS_LIBS" = "x"; then
    OpenHiTLS_LIBS="$openhitls_lib_dir $openhitls_default_libs"
fi
openhitls_version="openHiTLS"

coap_OpenHiTLS_save_CFLAGS="$CFLAGS"
coap_OpenHiTLS_save_LIBS="$LIBS"
CFLAGS="$CFLAGS $OpenHiTLS_CFLAGS"
LIBS="$OpenHiTLS_LIBS $LIBS"
AX_CHECK_OPENHITLS_VERSION
if test "x$openhitls_version_check_result" != "xyes"; then
    openhitls_check_result="no"
elif test "x$1" = "xdtls"; then
    AC_MSG_CHECKING([for openHiTLS DTLS/TLS backend APIs])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <hitls/crypto/crypt_eal_init.h>
#include <hitls/tls/hitls.h>
]], [[
  (void)CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
  (void)HITLS_New(NULL);
  return 0;
]])],
                   [openhitls_check_result="yes"],
                   [openhitls_check_result="no"])
    AC_MSG_RESULT([$openhitls_check_result])
else
    AC_MSG_CHECKING([for openHiTLS OSCORE backend APIs])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <hitls/crypto/crypt_eal_init.h>
]], [[
  (void)CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
  return 0;
]])],
                   [openhitls_check_result="yes"],
                   [openhitls_check_result="no"])
    AC_MSG_RESULT([$openhitls_check_result])
fi
CFLAGS="$coap_OpenHiTLS_save_CFLAGS"
LIBS="$coap_OpenHiTLS_save_LIBS"
if test "x$openhitls_check_result" = "xyes"; then
    $2
else
    $3
fi
AC_LANG_POP
]) dnl AX_PKG_CHECK_OPENHITLS
