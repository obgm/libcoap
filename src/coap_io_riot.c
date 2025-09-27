/* coap_io_riot.c -- Default network I/O functions for libcoap on RIOT
 *
 * Copyright (C) 2019-2025 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_io_riot.c
 * @brief RIOT specific Network I/O functions
 */

#include "coap3/coap_libcoap_build.h"

#if defined(RIOT_VERSION)

#include "net/gnrc.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/netreg.h"
#include "net/udp.h"
#include "net/sock/async.h"

#include "coap3/coap_riot.h"

#define COAP_SELECT_THREAD_FLAG (1U << 4)

int
coap_io_process(coap_context_t *ctx, uint32_t timeout_ms) {
  int ret;

  coap_lock_lock(return 0);
  ret = coap_io_process_lkd(ctx, timeout_ms);
  coap_lock_unlock();
  return ret;
}

int
coap_io_process_lkd(coap_context_t *ctx, uint32_t timeout_ms) {
  coap_tick_t before, now;
  uint32_t timeout;
  coap_socket_t *sockets[1];
  unsigned int max_sockets = sizeof(sockets)/sizeof(sockets[0]);
  unsigned int num_sockets;
  ztimer64_t timeout_timer;
  thread_flags_t tflags;

  coap_lock_check_locked();

  coap_ticks(&before);
  /* Use the common logic */
  timeout = coap_io_prepare_io_lkd(ctx, sockets, max_sockets, &num_sockets, before);

  if (timeout_ms == COAP_IO_NO_WAIT) {
    timeout = 0;
  } else if (timeout == 0 && timeout_ms == COAP_IO_WAIT) {
    timeout = UINT32_MAX/1000;
  } else {
    if (timeout == 0 || (timeout_ms != COAP_IO_WAIT && timeout_ms < timeout))
      timeout = timeout_ms;
  }

  if (timeout > 0) {
    ztimer64_set_timeout_flag(ZTIMER64_USEC, &timeout_timer, timeout*1000);
    ctx->selecting_thread = thread_get_active();

    /* Unlock so that other threads can lock/update ctx */
    coap_lock_unlock();

    tflags = thread_flags_wait_any(COAP_SELECT_THREAD_FLAG |
                                   THREAD_FLAG_TIMEOUT);
    /* Take control of ctx again */
    coap_lock_lock(return -1);

    if (tflags & THREAD_FLAG_TIMEOUT) {
      errno = EINTR;
    }

    ztimer64_remove(ZTIMER64_USEC, &timeout_timer);
  }

  coap_ticks(&now);
  coap_io_do_io_lkd(ctx, now);

#if COAP_SERVER_SUPPORT
  coap_expire_cache_entries(ctx);
#endif /* COAP_SERVER_SUPPORT */
  coap_ticks(&now);
#if COAP_ASYNC_SUPPORT
  /* Check to see if we need to send off any Async requests as delay might
     have been updated */
  coap_check_async(ctx, now, NULL);
  coap_ticks(&now);
#endif /* COAP_ASYNC_SUPPORT */

  return (int)(((now - before) * 1000) / COAP_TICKS_PER_SECOND);
}

static msg_t _msg_q[LIBCOAP_MSG_QUEUE_SIZE];

void
coap_riot_startup(void) {
  msg_init_queue(_msg_q, LIBCOAP_MSG_QUEUE_SIZE);
}

#else /* ! RIOT_VERSION */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* ! RIOT_VERSION */
