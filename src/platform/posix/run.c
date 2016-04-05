/* run.c -- CoAP main loop
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"
#include "coap.h"

#include <errno.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#else
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif /* HAVE_SYS_SELECT_H */

int
coap_run_once(coap_context_t *ctx, unsigned int timeout_ms) {
  fd_set readfds;
  struct timeval tv;
  coap_endpoint_t *ep;
  coap_queue_t *nextpdu;
  coap_tick_t now;
  unsigned long max_wait;
  int maxfd = -1;
  int result;

  FD_ZERO(&readfds);
  LL_FOREACH(ctx->endpoint, ep) {
    FD_SET(ep->handle.fd, &readfds);
    if (maxfd < ep->handle.fd) {
      maxfd = ep->handle.fd;
    }
  }

  coap_ticks(&now);

  max_wait = timeout_ms * COAP_TICKS_PER_SECOND / 1000;
  while (1) {
    nextpdu = coap_peek_next(ctx);

    while (nextpdu && nextpdu->t <= now - ctx->sendqueue_basetime) {
      coap_retransmit(ctx, coap_pop_next(ctx));
      nextpdu = coap_peek_next(ctx);
    }

    if (nextpdu && ((max_wait == 0) || nextpdu->t < max_wait)) {
      /* set timeout if there is a pdu to send */
      tv.tv_usec = ((nextpdu->t) % COAP_TICKS_PER_SECOND) * 1000000 / COAP_TICKS_PER_SECOND;
      tv.tv_sec = (nextpdu->t) / COAP_TICKS_PER_SECOND;
    } else {
      tv.tv_usec = (max_wait % COAP_TICKS_PER_SECOND) * 1000000 / COAP_TICKS_PER_SECOND;
      tv.tv_sec = max_wait / COAP_TICKS_PER_SECOND;
    }

    result = select(maxfd + 1, &readfds, 0, 0, (nextpdu || (max_wait > 0)) ? &tv : NULL);

    if (result < 0) {   /* error */
      if (errno != EINTR) {
        coap_log(LOG_DEBUG, strerror(errno));
      }
      return -1;
    } else if (result > 0) {  /* read from socket */
      coap_tick_t past = now;
      LL_FOREACH(ctx->endpoint, ep) {
        if (FD_ISSET(ep->handle.fd, &readfds)) {
          ep->flags |= 0x1000;  /* COAP_ENDPOINT_HAS_DATA */
        }
      }
      coap_read(ctx);           /* read received data */
      coap_ticks(&now);
      return ((now - past) * 1000) / COAP_TICKS_PER_SECOND;
    } else { /* timeout */
      coap_tick_t past = now;
      coap_ticks(&now);
      if (past + max_wait <= now) {
        return (now - past);
      } else {
        max_wait -= (now - past);
      }
    }
  }

  /* never reached */
}

void
coap_run(coap_context_t *ctx) {
  while (1) {
    coap_run_once(ctx, 0);
  }
}
