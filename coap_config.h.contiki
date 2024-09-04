/*
 * coap_config.h.contiki -- Contiki configuration for libcoap
 *
 * Copyright (C) 2021-2024 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_CONFIG_H_
#define COAP_CONFIG_H_

/* Define to 1 if libcoap supports client mode code. */
#define COAP_CLIENT_SUPPORT 1

/* Define to 1 if libcoap supports server mode code. */
#define COAP_SERVER_SUPPORT 1

#if COAP_CLIENT_SUPPORT && COAP_SERVER_SUPPORT
/* Define to 1 if libcoap supports proxy code. */
#define COAP_PROXY_SUPPORT 1
#endif /* COAP_CLIENT_SUPPORT && COAP_SERVER_SUPPORT */

/* Define to 1 if the system has small stack size. */
#define COAP_CONSTRAINED_STACK 1

/* Define to 1 to build without TCP support. */
#define COAP_DISABLE_TCP 1

/* Define to 1 to build support for IPv4 packets. */
/* #undef COAP_IPV4_SUPPORT 1 */

/* Define to 1 to build support for IPv6 packets. */
#define COAP_IPV6_SUPPORT 1

/* Define to 1 to build support for Unix socket packets. */
/* #undef COAP_AF_UNIX_SUPPORT 1 */

/* Define to 1 to build with support for async separate responses. */
#define COAP_ASYNC_SUPPORT 1

/* Define to 1 to build support for persisting observes. */
/* #undef COAP_WITH_OBSERVE_PERSIST 1 */

/* Define to 1 to build with WebSockets support. */
/* #undef COAP_WS_SUPPORT 1 */

/* Define to 1 to build with Q-Block (RFC9177) support. */
/* #undef COAP_Q_BLOCK_SUPPORT 1 */

/* Define to 1 to build with thread recursive lock detection support. */
/* #undef COAP_THREAD_RECURSIVE_CHECK 1 */

/* Define to 1 if libcoap has thread safe support. */
/* #undef COAP_THREAD_SAFE 1 */

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strnlen' function. */
#define HAVE_STRNLEN 1

/* Define to 1 if you have the `strrchr' function. */
#define HAVE_STRRCHR 1

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

#ifndef PACKAGE_BUGREPORT
/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "libcoap-developers@lists.sourceforge.net"
#endif /* PACKAGE_BUGREPORT */

#ifndef PACKAGE_NAME
/* Define to the full name of this package. */
#define PACKAGE_NAME "libcoap"
#endif /* PACKAGE_NAME */

#ifndef PACKAGE_STRING
/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libcoap 4.3.5"
#endif /* PACKAGE_STRING */

#ifndef PACKAGE_TARNAME
/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libcoap"
#endif /* PACKAGE_TARNAME */

#ifndef PACKAGE_URL
/* Define to the home page for this package. */
#define PACKAGE_URL "https://libcoap.net/"
#endif /* PACKAGE_URL */

#ifndef PACKAGE_VERSION
/* Define to the version of this package. */
#define PACKAGE_VERSION "4.3.5"
#endif /* PACKAGE_VERSION */

#define WITH_CONTIKI 1

#define HASH_NONFATAL_OOM 1

#ifndef HEAPMEM_CONF_ARENA_SIZE
#define HEAPMEM_CONF_ARENA_SIZE 6144
#endif

#endif /* COAP_CONFIG_H_ */
