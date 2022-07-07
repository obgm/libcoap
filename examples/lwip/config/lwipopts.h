/*
 * lwipopts.h -- LwIP example
 *
 * Copyright (C) 2013-2016 Christian Amsüss <chrysn@fsfe.org>
 * Copyright (C) 2018-2022 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#define NO_SYS                     0
#define LWIP_SOCKET                (NO_SYS==0)
#define LWIP_NETCONN               (NO_SYS==0)
#define LWIP_NETIF_API             (NO_SYS==0)

#define LWIP_IPV4                       1
#define LWIP_IPV6                       1
#define LWIP_IPV6_REASS                 0
#define LWIP_IGMP                       1
#define LWIP_DNS                        1
#define LWIP_HAVE_LOOPIF                0
#define LWIP_NETBUF_RECVINFO            1
#define LWIP_TCPIP_CORE_LOCKING         1

#ifndef LWIP_RAND
#define LWIP_RAND() ((u32_t)rand())
#endif

#ifndef netif_get_index
#define netif_get_index(netif)      ((u8_t)((netif)->num + 1))
#endif

#define gai_strerror(x) "gai_strerror() not supported"

#if NO_SYS
#include <pthread.h>
extern pthread_mutex_t lwprot_mutex;
extern pthread_t lwprot_thread;
extern int lwprot_count;
#endif /*  NO_SYS */

#if !NO_SYS
void sys_check_core_locking(void);
#define LWIP_ASSERT_CORE_LOCKED()  sys_check_core_locking()
void sys_mark_tcpip_thread(void);
#define LWIP_MARK_TCPIP_THREAD()   sys_mark_tcpip_thread()

#if LWIP_TCPIP_CORE_LOCKING
void sys_lock_tcpip_core(void);
#define LOCK_TCPIP_CORE()          sys_lock_tcpip_core()
void sys_unlock_tcpip_core(void);
#define UNLOCK_TCPIP_CORE()        sys_unlock_tcpip_core()
#endif /* LWIP_TCPIP_CORE_LOCKING */

#endif /* ! NO_SYS */

#define MEM_LIBC_MALLOC 1
#define HAVE_MALLOC 1
#define LWIP_POSIX_SOCKETS_IO_NAMES 1
#define SO_REUSE 1
