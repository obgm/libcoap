/* coap_io_contiki.c -- Network I/O functions for libcoap on Contiki-NG
 *
 * Copyright (C) 2012,2014,2024-2025 Olaf Bergmann <bergmann@tzi.org>
 *               2014      chrysn <chrysn@fsfe.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_io_contiki.c
 * @brief Contiki-NG Netowrk specific functions
 */

#include "coap3/coap_libcoap_build.h"

#if defined(WITH_CONTIKI)

#include "contiki-net.h"

static void prepare_io(coap_context_t *ctx);
PROCESS(libcoap_io_process, "libcoap I/O");

void
coap_start_io_process(void) {
  process_start(&libcoap_io_process, NULL);
}

void
coap_stop_io_process(void) {
  process_exit(&libcoap_io_process);
}

static void
on_io_timer_expired(void *ptr) {
  PROCESS_CONTEXT_BEGIN(&libcoap_io_process);
  prepare_io((coap_context_t *)ptr);
  PROCESS_CONTEXT_END(&libcoap_io_process);
}

void
coap_update_io_timer(coap_context_t *ctx, coap_tick_t delay) {
  coap_tick_t now;

  if (!ctimer_expired(&ctx->io_timer)) {
    ctimer_stop(&ctx->io_timer);
  }
  if (!delay) {
    process_post(&libcoap_io_process, PROCESS_EVENT_POLL, ctx);
  } else {
    ctimer_set(&ctx->io_timer,
               CLOCK_SECOND * delay / 1000,
               on_io_timer_expired,
               ctx);
  }
  coap_ticks(&now);
  if (ctx->next_timeout == 0 || ctx->next_timeout > now + delay) {
    ctx->next_timeout = now + delay;
  }
}

static void
prepare_io(coap_context_t *ctx) {
  coap_tick_t now;
  coap_socket_t *sockets[1];
  static const unsigned int max_sockets = sizeof(sockets)/sizeof(sockets[0]);
  unsigned int num_sockets;
  unsigned next_io;

  coap_ticks(&now);
  next_io = coap_io_prepare_io_lkd(ctx, sockets, max_sockets, &num_sockets, now);
  if (next_io) {
    coap_update_io_timer(ctx, next_io);
  }
}

PROCESS_THREAD(libcoap_io_process, ev, data) {
  PROCESS_EXITHANDLER(goto exit);
  PROCESS_BEGIN();

  while (1) {
    PROCESS_WAIT_EVENT();
    if (ev == tcpip_event) {
      coap_socket_t *coap_socket = (coap_socket_t *)data;
      if (!coap_socket) {
        coap_log_crit("libcoap_io_process: coap_socket should never be NULL\n");
        continue;
      }
      if (uip_newdata()) {
        coap_tick_t now;

        coap_socket->flags |= COAP_SOCKET_CAN_READ;
        coap_ticks(&now);
        coap_io_do_io_lkd(coap_socket->context, now);
      }
    }
    if (ev == PROCESS_EVENT_POLL) {
      coap_context_t *ctx = (coap_context_t *)data;
      if (!ctx) {
        coap_log_crit("libcoap_io_process: ctx should never be NULL\n");
        continue;
      }
      prepare_io(ctx);
    }
  }
exit:
  coap_log_info("libcoap_io_process: stopping\n");
  PROCESS_END();
}

int
coap_io_process_lkd(coap_context_t *ctx, uint32_t timeout_ms) {
  coap_tick_t before, now;

  coap_lock_check_locked();
  if (timeout_ms != COAP_IO_NO_WAIT) {
    coap_log_err("coap_io_process_lkd() must be called with COAP_IO_NO_WAIT\n");
    return -1;
  }

  coap_ticks(&before);
  PROCESS_CONTEXT_BEGIN(&libcoap_io_process);
  prepare_io(ctx);
  coap_io_do_io_lkd(ctx, before);
  PROCESS_CONTEXT_END(&libcoap_io_process);
  coap_ticks(&now);
  return (int)(((now - before) * 1000) / COAP_TICKS_PER_SECOND);
}

#else /* ! WITH_CONTIKI */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* ! WITH_CONTIKI */
