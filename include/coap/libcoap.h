/*
 * libcoap.h -- platform specific header file for CoAP stack
 *
 * Copyright (C) 2015 Carsten Schoenert <c.schoenert@t-online.de>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef _LIBCOAP_H_
#define _LIBCOAP_H_

/* The non posix embedded platforms like Contiki, TinyOS, RIOT, ... doesn't have
 * a POSIX compatible header structure so we have to slightly do some platform
 * related things. Currently there is only Contiki available so we check for a
 * CONTIKI environment and do *not* include the POSIX related network stuff. If
 * there are other platforms in future there need to be analogous environments.
 *
 * The CONTIKI variable is within the Contiki build environment! */

#if defined(_WIN32)
#pragma comment(lib,"Ws2_32.lib")
#include <ws2tcpip.h>
typedef SSIZE_T ssize_t;
typedef USHORT in_port_t;
#elif !defined (CONTIKI)
#include <netinet/in.h>
#include <sys/socket.h>
#endif /* CONTIKI */

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

void coap_startup(void);

void coap_cleanup(void);

#endif /* _LIBCOAP_H_ */
