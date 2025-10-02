/* coap_io_lwip.c -- Network I/O functions for libcoap using LwIP
 *
 * Copyright (C) 2012,2014 Olaf Bergmann <bergmann@tzi.org>
 *               2014      chrysn <chrysn@fsfe.org>
 *               2022-2025 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_io_lwip.c
 * @brief LwIP specific Network I/O functions
 */

#include "coap3/coap_libcoap_build.h"

#if defined(WITH_LWIP)

#include <lwip/udp.h>
#include <lwip/timeouts.h>
#include <lwip/tcpip.h>

void
coap_lwip_dump_memory_pools(coap_log_t log_level) {
#if MEMP_STATS && LWIP_STATS_DISPLAY && MEMP_USE_CUSTOM_POOLS
  int i;

  /* Save time if not needed */
  if (log_level > coap_get_log_level())
    return;

  coap_log(log_level, "*   LwIP custom memory pools information\n");
  /*
   * Make sure LwIP and libcoap have been built with the same
   * -DCOAP_CLIENT_ONLY or -DCOAP_SERVER_ONLY options for
   * MEMP_MAX to be correct.
   */
  for (i = 0; i < MEMP_MAX; i++) {
    coap_log(log_level, "*    %-17s avail %3d  in-use %3d  peak %3d failed %3d\n",
             memp_pools[i]->stats->name, memp_pools[i]->stats->avail,
             memp_pools[i]->stats->used, memp_pools[i]->stats->max,
             memp_pools[i]->stats->err);
  }
#else /* !( MEMP_STATS && LWIP_STATS_DISPLAY && MEMP_USE_CUSTOM_POOLS) */
  (void)log_level;
#endif /* !( MEMP_STATS && LWIP_STATS_DISPLAY && MEMP_USE_CUSTOM_POOLS) */
}

void
coap_lwip_set_input_wait_handler(coap_context_t *context,
                                 coap_lwip_input_wait_handler_t handler,
                                 void *input_arg) {
  context->input_wait = handler;
  context->input_arg = input_arg;
}

#if NO_SYS == 0
sys_sem_t coap_io_timeout_sem;
#endif /* NO_SYS == 0 */

void
coap_io_lwip_init(void) {
#if NO_SYS == 0
  if (sys_sem_new(&coap_io_timeout_sem, 0) != ERR_OK)
    coap_log_warn("coap_io_lwip_init: Failed to set up semaphore\n");
#endif /* NO_SYS == 0 */
}

void
coap_io_lwip_cleanup(void) {
#if NO_SYS == 0
  sys_sem_free(&coap_io_timeout_sem);
#endif /* NO_SYS == 0 */
}

void
coap_io_process_timeout(void *arg) {
  (void)arg;
#if NO_SYS == 0
  sys_sem_signal(&coap_io_timeout_sem);
#endif /* NO_SYS == 0 */
}

int
coap_io_process(coap_context_t *ctx, uint32_t timeout_ms) {
  int ret;

  coap_lock_lock(return 0);
  ret = coap_io_process_lkd(ctx, timeout_ms);
  coap_lock_unlock();
  return ret;
}

int
coap_io_process_lkd(coap_context_t *context, uint32_t timeout_ms) {
  coap_tick_t before;
  coap_tick_t now;
  unsigned int num_sockets;
  unsigned int timeout;

  coap_lock_check_locked();
  coap_ticks(&before);
  timeout = coap_io_prepare_io_lkd(context, NULL, 0, &num_sockets, before);
  if (timeout == 0 || (timeout_ms != COAP_IO_WAIT && timeout_ms < timeout))
    timeout = timeout_ms;

  if (timeout_ms == COAP_IO_NO_WAIT)
    timeout = 1;

  coap_lock_invert(LOCK_TCPIP_CORE(),
                   UNLOCK_TCPIP_CORE(); return 0);

  if (context->timer_configured) {
    sys_untimeout(coap_io_process_timeout, (void *)context);
    context->timer_configured = 0;
  }
#ifdef COAP_DEBUG_WAKEUP_TIMES
  coap_log_info("****** Next wakeup msecs %u (2)\n",
                timeout);
#endif /* COAP_DEBUG_WAKEUP_TIMES */
  if (timeout) {
    sys_timeout(timeout, coap_io_process_timeout, context);
    context->timer_configured = 1;
  }

  UNLOCK_TCPIP_CORE();

  if (context->input_wait) {
    coap_lock_callback_release(context->input_wait(context->input_arg, timeout),
                               return 0);
#if NO_SYS == 0
  } else {
    coap_lock_callback_release(sys_arch_sem_wait(&coap_io_timeout_sem, timeout),
                               return 0);
#endif /* NO_SYS == 0 */
  }

  coap_lock_invert(LOCK_TCPIP_CORE(),
                   UNLOCK_TCPIP_CORE(); return 0);

  sys_check_timeouts();

  UNLOCK_TCPIP_CORE();

  coap_ticks(&now);
  return (int)(((now - before) * 1000) / COAP_TICKS_PER_SECOND);
}

int
coap_is_mcast(const coap_address_t *a) {
  if (!a)
    return 0;

  /* Treat broadcast in same way as multicast */
  if (coap_is_bcast(a))
    return 1;

  return ip_addr_ismulticast(&(a)->addr);
}

#ifndef COAP_BCST_CNT
#define COAP_BCST_CNT 15
#endif /* COAP_BCST_CNT */

/* How frequently to refresh the list of valid IPv4 broadcast addresses */
#ifndef COAP_BCST_REFRESH_SECS
#define COAP_BCST_REFRESH_SECS 30
#endif /* COAP_BCST_REFRESH_SECS */

#if COAP_IPV4_SUPPORT
static int bcst_cnt = -1;
static coap_tick_t last_refresh;
static uint32_t b_ipv4[COAP_BCST_CNT];
#endif /* COAP_IPV4_SUPPORT */

int
coap_is_bcast(const coap_address_t *a) {
#if COAP_IPV4_SUPPORT
  int i;
  coap_tick_t now;
  const ip4_addr_t *ipv4;
#endif /* COAP_IPV4_SUPPORT */

  if (!a)
    return 0;

  if (IP_IS_V6(&(a)->addr))
    return 0;

#if COAP_IPV4_SUPPORT
#ifndef INADDR_BROADCAST
#define INADDR_BROADCAST ((uint32_t)0xffffffffUL)
#endif /* !INADDR_BROADCAST */
  ipv4 = ip_2_ip4(&(a)->addr);
  if (ipv4->addr == INADDR_BROADCAST)
    return 1;

  coap_ticks(&now);
  if (bcst_cnt == -1 ||
      (now - last_refresh) > (COAP_BCST_REFRESH_SECS * COAP_TICKS_PER_SECOND)) {
    /* Determine the list of broadcast interfaces */
    struct netif *netif;

    bcst_cnt = 0;
    last_refresh = now;

    LWIP_ASSERT_CORE_LOCKED();

    NETIF_FOREACH(netif) {
      if (bcst_cnt < COAP_BCST_CNT) {
        const ip4_addr_t *ip_addr;
        const ip4_addr_t *netmask;

        ip_addr = ip_2_ip4(&netif->ip_addr);
        netmask = ip_2_ip4(&netif->netmask);
        if (netmask->addr != 0xffffffff) {
          b_ipv4[bcst_cnt] = ip_addr->addr | ~(netmask->addr);
          bcst_cnt++;
        }
      }
    }

    if (bcst_cnt == COAP_BCST_CNT) {
      coap_log_warn("coap_is_bcst: Insufficient space for broadcast addresses\n");
    }
  }
  for (i = 0; i < bcst_cnt; i++) {
    if (ipv4->addr == b_ipv4[i])
      return 1;
  }
#endif /* COAP_IPV4_SUPPORT */
  return 0;
}

/**
 * Checks if given address @p a denotes a AF_UNIX address. This function
 * returns @c 1 if @p a is of type AF_UNIX, @c 0 otherwise.
 */
int
coap_is_af_unix(const coap_address_t *a) {
  (void)a;
  return 0;
}

#else /* ! WITH_LWIP */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* ! WITH_LWIP */
