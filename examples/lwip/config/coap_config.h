/*
 * coap_config.h -- LwIP configuration for libcoap
 *
 * [coap_config.h is re-built from coap_config.h.in by the
 *  libcoap ./configure command, so make any permanent changes to libcoap's
 *  examples/lwip/config/coap_config.h.in for a libcoap Pull Request]
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

#include <lwip/opt.h>
#include <lwip/debug.h>
#include <lwip/def.h> /* provide ntohs, htons */

#define WITH_LWIP 1

#if LWIP_IPV4
#define COAP_IPV4_SUPPORT 1
#endif /* LWIP_IPV4 */

#if LWIP_IPV6
#define COAP_IPV6_SUPPORT 1
#endif /* LWIP_IPV6 */

#ifndef COAP_CONSTRAINED_STACK
/* Define to 1 to minimize stack usage. */
#define COAP_CONSTRAINED_STACK 1
#endif

#ifndef COAP_DISABLE_TCP
/* Define to 1 to build without TCP support. */
#if LWIP_TCP
#define COAP_DISABLE_TCP 0
#else /* ! LWIP_TCP */
#define COAP_DISABLE_TCP 1
#endif /* ! LWIP_TCP */
#endif

#ifndef COAP_ASYNC_SUPPORT
/* Define to 1 to build with support for async separate responses. */
#define COAP_ASYNC_SUPPORT 1
#endif

#ifndef COAP_WITH_OBSERVE_PERSIST
/* Define to 1 to build support for persisting observes. */
#define COAP_WITH_OBSERVE_PERSIST 0
#endif

#ifndef COAP_WS_SUPPORT
/* Define to 1 to build with WebSockets support. */
#define COAP_WS_SUPPORT 0
#endif

#ifndef COAP_Q_BLOCK_SUPPORT
/* Define to 1 to build with Q-Block (RFC9177) support. */
#define COAP_Q_BLOCK_SUPPORT 0
#endif

#ifndef COAP_THREAD_SAFE
/* Define to 1 if libcoap has thread safe support. */
#define COAP_THREAD_SAFE 0
#endif

#ifndef COAP_THREAD_RECURSIVE_CHECK
/* Define to 1 to build with thread recursive lock detection support. */
#define COAP_THREAD_RECURSIVE_CHECK 0
#endif

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
#define PACKAGE_STRING "libcoap 4.3.4"
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
#define PACKAGE_VERSION "4.3.4"
#endif /* PACKAGE_VERSION */

#ifndef assert
#define assert(x) LWIP_ASSERT("CoAP assert failed", x)
#endif /* assert */

/* it's just provided by libc. i hope we don't get too many of those, as
 * actually we'd need autotools again to find out what environment we're
 * building in */
#define HAVE_STRNLEN 1

#define HAVE_LIMITS_H

#define HAVE_NETDB_H

#define HAVE_SNPRINTF

#define HAVE_ERRNO_H

#endif /* COAP_CONFIG_H_ */
