/*
 * libcoap.h -- platform specific header file for CoAP stack
 *
 * Copyright (C) 2015 Carsten Schoenert <c.schoenert@t-online.de>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file libcoap.h
 * @brief Platform specific header file for CoAP stack
 */

#ifndef COAP_LIBCOAP_H_
#define COAP_LIBCOAP_H_

/* The non posix embedded platforms like Contiki-NG, TinyOS, RIOT, ... don't have
 * a POSIX compatible header structure so we have to slightly do some platform
 * related things. Currently there is only Contiki-NG available so we check for a
 * CONTIKI environment and do *not* include the POSIX related network stuff. If
 * there are other platforms in future there need to be analogous environments.
 *
 * The CONTIKI variable is within the Contiki-NG build environment! */

#if defined(_WIN32)
#include <ws2tcpip.h>
#if !defined(__MINGW32__)
#pragma comment(lib,"Ws2_32.lib")
#ifndef _SSIZE_T_DECLARED
typedef SSIZE_T ssize_t;
#define        _SSIZE_T_DECLARED
#endif
#ifndef _IN_PORT_T_DECLARED
typedef USHORT in_port_t;
#define        _IN_PORT_T_DECLARED
#endif
#endif /* !defined(__MINGW32__) */
#elif !defined (CONTIKI) && !defined (WITH_LWIP)
#include <netinet/in.h>
#include <sys/socket.h>
#endif /* ! CONTIKI && ! WITH_LWIP */

#ifndef COAP_STATIC_INLINE
#  if defined(__cplusplus)
#    define COAP_STATIC_INLINE inline
#  else
#    if defined(_MSC_VER)
#      define COAP_STATIC_INLINE static __inline
#    else
#      define COAP_STATIC_INLINE static inline
#    endif
#  endif
#endif
#ifndef COAP_DEPRECATED
#  if defined(_MSC_VER)
#    define COAP_DEPRECATED __declspec(deprecated)
#  else
#    define COAP_DEPRECATED __attribute__ ((deprecated))
#  endif
#endif
#ifndef COAP_UNUSED
#  ifdef __GNUC__
#    define COAP_UNUSED __attribute__((unused))
#  else /* __GNUC__ */
#    define COAP_UNUSED
#  endif /* __GNUC__ */
#endif /* COAP_UNUSED */

void coap_startup(void);

void coap_cleanup(void);

#endif /* COAP_LIBCOAP_H_ */
