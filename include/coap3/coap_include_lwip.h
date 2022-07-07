/*
 * coap_include_lwip.h -- #include list specifically for LwIP Apps
 *
 * Copyright (C) 2022 Olaf Bergmann <bergmann@tzi.org>
 *               2022 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef COAP_INCLUDE_LWIP_H_
#define COAP_INCLUDE_LWIP_H_

#include "lwipopts.h"

#define LWIP_PROVIDE_ERRNO
#define assert(x) LWIP_ASSERT("CoAP assert failed", x)

#define NI_MAXHOST      1025
#define NI_MAXSERV      32

#include <lwip/opt.h>
#include <lwip/memp.h>
#include <lwip/sockets.h>
#include <lwip/netif.h>
#include <lwip/netdb.h>
#include <lwip/errno.h>
#include <lwip/debug.h>
#include <lwip/def.h>

#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#undef IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(a) (((__const uint8_t *) (a))[0] == 0xff)
#undef IN6_IS_ADDR_V4MAPPED
#define IN6_IS_ADDR_V4MAPPED(a) \
        ((((__const uint32_t *) (a))[0] == 0)                                 \
         && (((__const uint32_t *) (a))[1] == 0)                              \
         && (((__const uint32_t *) (a))[2] == htonl (0xffff)))

#endif /* COAP_INCLUDE_LWIP_H_ */
