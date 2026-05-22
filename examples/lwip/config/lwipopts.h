/*
 * lwipopts.h -- LwIP example
 *
 * Copyright (C) 2013-2016 Christian Amsüss <chrysn@fsfe.org>
 * Copyright (C) 2018-2026 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef LWIPOPTS_H_
#define LWIPOPTS_H_

/*
 * NO_SYS = 0
 *  Use lwIP OS-awareness (multi threaded, semaphores, mutexes and mboxes).
 *
 * NO_SYS = 1
 *  Use lwIP without OS-awareness (no thread, semaphores, mutexes or mboxes).
 */
#define NO_SYS                     0
#define LWIP_SOCKET                0
#define LWIP_NETCONN               0
#define LWIP_NETIF_API             (NO_SYS==0)

#define LWIP_IPV4                       1

#define LWIP_IPV6                       1
#define LWIP_IPV6_REASS                 0

#define LWIP_ICMP6                 (LWIP_IPV6==1)

/* Set to 0 if TCP support is not required */
#define LWIP_TCP                        1

#if LWIP_IPV4
/* Set to 1 if Multicast registration support is required for IPv4 */
#define LWIP_IGMP                       0
#endif

#if LWIP_IPV6
/* Set to 1 if Multicast registration support is required for IPv6 */
#define LWIP_IPV6_MLD                   0
#endif

/*
 * Set to 1 for DNS resolution support
 */
#if 1
#define LWIP_DNS                        1
#endif

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

#define MEMP_NUM_SYS_TIMEOUT  10

/* Set to 0 if custom pools not required (and maybe set MEM_LIBC_MALLOC instead */
#define MEMP_USE_CUSTOM_POOLS  1
#define MEM_SIZE (4 * 1024)

#if MEMP_USE_CUSTOM_POOLS
/*
 * Set to 0 if defined memory pools is not required, only custom pools.
 * Memory pools are only used for COAP_SRING type mmemory allocations.
 *
 * [Update the LWIP_MALLOC_MEMPOOL definitions in lwippools.h.]
 */
#define MEM_USE_POOLS 1
#endif

#if ! MEMP_USE_CUSTOM_POOLS
/* Set if you want to use the standard libc for malloc */
#define MEM_LIBC_MALLOC        1
#endif

#if MEM_LIBC_MALLOC
#define HAVE_MALLOC            1
#endif

/*
 * Set to display (with COAP_LOG_DEBUG) memory pools information
 * (Needs MEMP_STATS set for MEMP_USE_CUSTOM_POOLS) when coap_free_context() is called.
 */
#define LWIP_STATS_DISPLAY     1

#if LWIP_STATS_DISPLAY
#if MEMP_USE_CUSTOM_POOLS
#define MEMP_STATS             1
#else
#define COAP_MEMORY_TYPE_TRACK 1
#endif
#endif

/* Support a 1500 MTU packet */
#define PBUF_POOL_BUFSIZE LWIP_MEM_ALIGN_SIZE(2*6 + 2 + 1500)

/*
 * Set to 1 for debugging UDP traffic
 */
#if 0
#define LWIP_DEBUG 1
#define UDP_DEBUG LWIP_DBG_ON
#endif

/*
 * Set to 1 for debugging TCP traffic and LWIP_DBG_ON where appropriate
 */
#if 0
#ifndef LWIP_DEBUG
#define LWIP_DEBUG 1
#endif
#define TCP_DEBUG            LWIP_DBG_ON
#define TCP_INPUT_DEBUG      LWIP_DBG_ON
#define TCP_OUTPUT_DEBUG     LWIP_DBG_ON
#define TCP_RTO_DEBUG        LWIP_DBG_ON
#define TCP_CWND_DEBUG       LWIP_DBG_ON
#define TCP_WND_DEBUG        LWIP_DBG_ON
#define TCP_FR_DEBUG         LWIP_DBG_ON
#define TCP_QLEN_DEBUG       LWIP_DBG_ON
#define TCP_RST_DEBUG        LWIP_DBG_ON
#endif

#endif /* LWIPOPTS_H_ */
