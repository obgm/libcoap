#
# SYNOPSIS
#
#   AX_CHECK_{GNUTLS|OPENSSL|MBEDTLS|WOLFSSL|TINYDTLS|OPENHITLS}_VERSION
#
# DESCRIPTION
#
#   This m4 file contains helper functions for checking the version of the
#   respective cryptographic library version of GnuTLS, OpenSSL, Mbed TLS,
#   WolfSSL and TinyDTLS on the host. The variables '$gnutls_version_required',
#   '$mbedtls_version_required' and '$openssl_version_required' etc. hold the
#   minimum required version and are set up externally in configure.ac.
#
#   Example:
#
#     AX_CHECK_GNUTLS_VERSION
#    or
#     AX_CHECK_OPENSSL_VERSION
#
# LICENSE
#
#   Copyright (c) 2017 Carsten Schoenert <c.schoenert@t-online.de>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

AC_DEFUN([AX_CHECK_GNUTLS_VERSION],
         [AC_MSG_CHECKING([for compatible GnuTLS version (>= $gnutls_version_required)])
          AS_VERSION_COMPARE([$gnutls_version],
                             [$gnutls_version_required],
                             [AC_MSG_RESULT([no])
                              GNUTLSV=""],
                             [AC_MSG_RESULT([yes $gnutls_version])
                              GNUTLSV="$gnutls_version"],
                             [AC_MSG_RESULT([yes $gnutls_version])
                              GNUTLSV="$gnutls_version"])
          if test "x$GNUTLSV" = "x"; then
              AC_MSG_ERROR([==> GnuTLS $gnutls_version too old. GnuTLS >= $gnutls_version_required required for suitable DTLS support build.])
          fi
]) dnl AX_CHECK_GNUTLS_VERSION

AC_DEFUN([AX_CHECK_OPENSSL_VERSION],
         [AC_MSG_CHECKING([for compatible OpenSSL version (>= $openssl_version_required)])
          AS_VERSION_COMPARE([$openssl_version], [$openssl_version_required],
                             [AC_MSG_RESULT([no])
                              OPENSSLV=""],
                             [AC_MSG_RESULT([yes $openssl_version])
                              OPENSSLV="$openssl_version"],
                             [AC_MSG_RESULT([yes $openssl_version])
                              OPENSSLV="$openssl_version"])
          if test "x$OPENSSLV" = "x"; then
              AC_MSG_ERROR([==> OpenSSL $openssl_version too old. OpenSSL >= $openssl_version_required required for suitable DTLS support build.])
          fi
]) dnl AX_CHECK_OPENSSL_VERSION

AC_DEFUN([AX_CHECK_MBEDTLS_VERSION],
         [AC_MSG_CHECKING([for compatible Mbed TLS version (>= $mbedtls_version_required)])
          AS_VERSION_COMPARE([$mbedtls_version], [$mbedtls_version_required],
                             [AC_MSG_RESULT([no])
                              MBEDTLSV=""],
                             [AC_MSG_RESULT([yes $mbedtls_version])
                              MBEDTLSV="$mbedtls_version"],
                             [AC_MSG_RESULT([yes $mbedtls_version])
                              MBEDTLSV="$mbedtls_version"])
          if test "x$MBEDTLSV" = "x"; then
              AC_MSG_ERROR([==> Mbed TLS $mbedtls_version too old. Mbed TLS >= $mbedtls_version_required required for suitable DTLS support build.])
          fi
]) dnl AX_CHECK_MBEDTLS_VERSION

AC_DEFUN([AX_CHECK_WOLFSSL_VERSION],
         [AC_MSG_CHECKING([for compatible wolfSSL version (>= $wolfssl_version_required)])
          AS_VERSION_COMPARE([$wolfssl_version], [$wolfssl_version_required],
                             [AC_MSG_RESULT([no])
                              WOLFSSLV=""],
                             [AC_MSG_RESULT([yes $wolfssl_version])
                              WOLFSSLV="$wolfssl_version"],
                             [AC_MSG_RESULT([yes $wolfssl_version])
                              WOLFSSLV="$wolfssl_version"])
          if test "x$WOLFSSLV" = "x"; then
              AC_MSG_ERROR([==> wolfSSL $wolfssl_version too old. wolfSSL >= $wolfssl_version_required required for suitable DTLS support build.])
          fi
]) dnl AX_CHECK_WOLFSSL_VERSION

AC_DEFUN([AX_CHECK_TINYDTLS_VERSION],
    [AC_MSG_CHECKING([for compatible TinyDTLS version (>= $tinydtls_version_required)])
    AS_VERSION_COMPARE([$tinydtls_version], [$tinydtls_version_required],
        [AC_MSG_RESULT([no])
        TINYDTLSV=""],
        [AC_MSG_RESULT([yes $tinydtls_version])
        TINYDTLSV="$tinydtls_version"],
        [AC_MSG_RESULT([yes $tinydtls_version])
        TINYDTLSV="$tinydtls_version"])
    if test "x$TINYDTLSV" = "x"; then
        AC_MSG_ERROR([==> TinyDTLS $tinydtls_version too old. TinyDTLS >= $tinydtls_version_required required for suitable DTLS support build.])
    fi
]) dnl AX_CHECK_TINYDTLS_VERSION

AC_DEFUN([AX_CHECK_OPENHITLS_VERSION],
         [openhitls_version_check_result="no"
          AC_MSG_CHECKING([for openHiTLS headers])
          AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <hitls/bsl/bsl_version.h>
#ifndef OPENHITLS_VERSION_I
#error OPENHITLS_VERSION_I missing
#endif
]], [[]])],
                            [AC_MSG_RESULT([yes])
                             openhitls_version_check_result="yes"],
                            [AC_MSG_RESULT([no])])
          if test "x$openhitls_version_check_result" = "xyes"; then
              AC_COMPUTE_INT([openhitls_version_i],
                             [OPENHITLS_VERSION_I],
                             [[#include <hitls/bsl/bsl_version.h>]],
                             [openhitls_version_i=0])
              if test "x$openhitls_version_i" = "x0"; then
                  openhitls_version="unknown"
              else
                  openhitls_version_major=`expr $openhitls_version_i / 268435456`
                  openhitls_version_minor=`expr \( $openhitls_version_i % 268435456 \) / 1048576`
                  openhitls_version_patch=`expr \( $openhitls_version_i % 1048576 \) / 65536`
                  openhitls_version="$openhitls_version_major.$openhitls_version_minor.$openhitls_version_patch"
              fi
              AC_MSG_CHECKING([for compatible openHiTLS version (>= $openhitls_version_required)])
              openhitls_version_required_major=`printf '%s\n' "$openhitls_version_required" | sed -n 's/^\([[0-9]][[0-9]]*\)\.\([[0-9]][[0-9]]*\)\.\([[0-9]][[0-9]]*\)$/\1/p'`
              openhitls_version_required_minor=`printf '%s\n' "$openhitls_version_required" | sed -n 's/^\([[0-9]][[0-9]]*\)\.\([[0-9]][[0-9]]*\)\.\([[0-9]][[0-9]]*\)$/\2/p'`
              openhitls_version_required_patch=`printf '%s\n' "$openhitls_version_required" | sed -n 's/^\([[0-9]][[0-9]]*\)\.\([[0-9]][[0-9]]*\)\.\([[0-9]][[0-9]]*\)$/\3/p'`
              if test "x$openhitls_version_required_major" = "x" ||
                 test "x$openhitls_version_required_minor" = "x" ||
                 test "x$openhitls_version_required_patch" = "x"; then
                  AC_MSG_ERROR([==> Invalid openHiTLS required version '$openhitls_version_required'.])
              fi
              openhitls_version_required_i=`expr \( $openhitls_version_required_major \* 268435456 \) + \( $openhitls_version_required_minor \* 1048576 \) + \( $openhitls_version_required_patch \* 65536 \)`
              AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <hitls/bsl/bsl_version.h>
#if OPENHITLS_VERSION_I < $openhitls_version_required_i
#error openHiTLS version too old
#endif
]], [[]])],
                                [AC_MSG_RESULT([yes])],
                                [AC_MSG_RESULT([no])
                                 openhitls_version_check_result="no"])
          fi
]) dnl AX_CHECK_OPENHITLS_VERSION
