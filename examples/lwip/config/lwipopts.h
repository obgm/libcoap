/*
 * lwipopts.h -- LwIP example
 *
 * Copyright (C) 2013-2016 Christian Amsüss <chrysn@fsfe.org>
 * Copyright (C) 2018-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/*
 * NO_SYS = 0
 *  Use lwIP OS-awareness (multi threaded, semaphores, mutexes and mboxes).
 *
 * NO_SYS = 1
 *  Use lwIP without OS-awareness (no thread, semaphores, mutexes or mboxes).
 */
#define NO_SYS                     0
#define LWIP_SOCKET                (NO_SYS==0)
#define LWIP_NETCONN               (NO_SYS==0)
#define LWIP_NETIF_API             (NO_SYS==0)

#define LWIP_IPV4                       1

#define LWIP_IPV6                       1
#define LWIP_IPV6_REASS                 0

#define LWIP_IPV6_MLD                   0
#define LWIP_ICMP6                 (LWIP_IPV6==1)

/* Set to 1 if TCP support is required */
#define LWIP_TCP                        0

#ifndef netif_get_index
#define netif_get_index(netif)      ((u8_t)((netif)->num + 1))
#endif

#if NO_SYS
#define LOCK_TCPIP_CORE()
#define UNLOCK_TCPIP_CORE()
#else
#define COAP_THREAD_SAFE 1
#define COAP_THREAD_RECURSIVE_CHECK 0
#define LWIP_TCPIP_CORE_LOCKING 1
#endif

#define MEMP_NUM_SYS_TIMEOUT    10

#define MEMP_USE_CUSTOM_POOLS 1
#define MEM_SIZE (4 * 1024)
/* Support a 1500 MTU packet */
#define PBUF_POOL_BUFSIZE LWIP_MEM_ALIGN_SIZE(2*6 + 2 + 1500)

/* Set if space is to be reserved for a response PDU */
#define MEMP_STATS                      1

/*
 * Set to display (with COAP_LOG_DEBUG) custom pools information
 * (Needs MEMP_STATS set) when coap_free_context() is called.
 */
#define LWIP_STATS_DISPLAY              1
