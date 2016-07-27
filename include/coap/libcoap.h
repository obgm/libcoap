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

#include "coap_config.h"

/* The non posix embedded platforms like Contiki, TinyOS, RIOT, ... doesn't have
 * a POSIX compatible header structure so we have to slightly do some platform
 * related things. Currently there is only Contiki available so we check for a
 * CONTIKI environment and do *not* include the POSIX related network stuff. If
 * there are other platforms in future there need to be analogous environments.
 *
 * The CONTIKI variable is within the Contiki build environment! */

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#endif /* _LIBCOAP_H_ */
