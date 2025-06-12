/* coap_async.c -- state management for asynchronous messages
 *
 * Copyright (C) 2010,2011,2021-2025 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_async.c
 * @brief State handling for asynchronous messages
 */

#include "coap3/coap_libcoap_build.h"

#if COAP_ASYNC_SUPPORT
#include <stdio.h>

/* utlist-style macros for searching pairs in linked lists */
#define SEARCH_PAIR(head,out,field1,val1,field2,val2,field3,val3)   \
  SEARCH_PAIR3(head,out,field1,val1,field2,val2,field3,val3,next)

#define SEARCH_PAIR3(head,out,field1,val1,field2,val2,field3,val3,next) \
  do {                                                                  \
    LL_FOREACH2(head,out,next) {                                        \
      if ((out)->field1 == (val1) && (out)->field2 == (val2) &&         \
          ((val2) == 0 || memcmp((out)->field3, (val3), (val2)) == 0)) break; \
    }                                                                   \
  } while(0)

int
coap_async_is_supported(void) {
  return 1;
}

COAP_API coap_async_t *
coap_register_async(coap_session_t *session,
                    const coap_pdu_t *request, coap_tick_t delay) {
  coap_async_t *async;

  coap_lock_lock(return NULL);
  async = coap_register_async_lkd(session, request, delay);
  coap_lock_unlock();
  return async;
}

coap_async_t *
coap_register_async_lkd(coap_session_t *session,
                        const coap_pdu_t *request, coap_tick_t delay) {
  coap_async_t *s;
  size_t len;
  const uint8_t *data;

  coap_lock_check_locked();
  if (!COAP_PDU_IS_REQUEST(request))
    return NULL;

  SEARCH_PAIR(session->context->async_state, s,
              session, session,
              pdu->actual_token.length, request->actual_token.length,
              pdu->actual_token.s, request->actual_token.s);

  if (s != NULL) {
    size_t i;
    char outbuf[2*8 + 1];
    size_t outbuflen;

    outbuf[0] = '\000';
    for (i = 0; i < request->actual_token.length; i++) {
      /* Output maybe truncated */
      outbuflen = strlen(outbuf);
      snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,
               "%02x", request->token[i]);
    }
    coap_log_debug("asynchronous state for token '%s' already registered\n", outbuf);
    return NULL;
  }

  /* store information for handling the asynchronous task */
  s = (coap_async_t *)coap_malloc_type(COAP_STRING, sizeof(coap_async_t));
  if (!s) {
    coap_log_crit("coap_register_async: insufficient memory\n");
    return NULL;
  }

  memset(s, 0, sizeof(coap_async_t));
  LL_PREPEND(session->context->async_state, s);

  /* Note that this generates a new MID */
  s->pdu = coap_pdu_duplicate_lkd(request, session, request->actual_token.length,
                                  request->actual_token.s, NULL);
  if (s->pdu == NULL) {
    coap_free_async_lkd(session, s);
    coap_log_crit("coap_register_async: insufficient memory\n");
    return NULL;
  }

  if (coap_get_data(request, &len, &data)) {
    coap_add_data(s->pdu, len, data);
  }

  s->session = coap_session_reference_lkd(session);

  coap_async_set_delay_lkd(s, delay);

  return s;
}

COAP_API void
coap_async_trigger(coap_async_t *async) {
  coap_lock_lock(return);
  coap_async_trigger_lkd(async);
  coap_lock_unlock();
}

void
coap_async_trigger_lkd(coap_async_t *async) {
  assert(async != NULL);
  coap_lock_check_locked();
  coap_ticks(&async->delay);

  coap_log_debug("   %s: Async request triggered\n",
                 coap_session_str(async->session));
  coap_update_io_timer(async->session->context, 0);
}

COAP_API void
coap_async_set_delay(coap_async_t *async, coap_tick_t delay) {
  coap_lock_lock(return);
  coap_async_set_delay_lkd(async, delay);
  coap_lock_unlock();
}

void
coap_async_set_delay_lkd(coap_async_t *async, coap_tick_t delay) {
  coap_tick_t now;

  coap_lock_check_locked();
  assert(async != NULL);
  coap_ticks(&now);

  if (delay) {
    async->delay = now + delay;
    coap_update_io_timer(async->session->context, delay);
    coap_log_debug("   %s: Async request delayed for %u.%03u secs\n",
                   coap_session_str(async->session),
                   (unsigned int)(delay / COAP_TICKS_PER_SECOND),
                   (unsigned int)((delay % COAP_TICKS_PER_SECOND) *
                                  1000 / COAP_TICKS_PER_SECOND));
  } else {
    async->delay = 0;
    coap_log_debug("   %s: Async request indefinately delayed\n",
                   coap_session_str(async->session));
  }
}

COAP_API coap_async_t *
coap_find_async(coap_session_t *session, coap_bin_const_t token) {
  coap_async_t *tmp;

  coap_lock_lock(return NULL);
  tmp = coap_find_async_lkd(session, token);
  coap_lock_unlock();
  return tmp;
}

coap_async_t *
coap_find_async_lkd(coap_session_t *session, coap_bin_const_t token) {
  coap_async_t *tmp;

  coap_lock_check_locked();
  SEARCH_PAIR(session->context->async_state, tmp,
              session, session,
              pdu->actual_token.length, token.length,
              pdu->actual_token.s, token.s);
  return tmp;
}

static void
coap_free_async_sub(coap_context_t *context, coap_async_t *async) {
  if (async) {
    LL_DELETE(context->async_state,async);
    if (async->session) {
      coap_session_release_lkd(async->session);
      async->session = NULL;
    }
    if (async->pdu) {
      coap_delete_pdu_lkd(async->pdu);
      async->pdu = NULL;
    }
    if (async->app_cb && async->app_data) {
      coap_lock_callback(async->app_cb(async->app_data));
    }
    coap_free_type(COAP_STRING, async);
  }
}

COAP_API void
coap_free_async(coap_session_t *session, coap_async_t *async) {
  coap_lock_lock(return);
  coap_free_async_lkd(session, async);
  coap_lock_unlock();
}

void
coap_free_async_lkd(coap_session_t *session, coap_async_t *async) {
  coap_free_async_sub(session->context, async);
}

void
coap_delete_all_async(coap_context_t *context) {
  coap_async_t *astate, *tmp;

  LL_FOREACH_SAFE(context->async_state, astate, tmp) {
    coap_free_async_sub(context, astate);
  }
  context->async_state = NULL;
}

COAP_API void
coap_async_set_app_data(coap_async_t *async_entry, void *app_data) {
  coap_lock_lock(return);
  coap_async_set_app_data2_lkd(async_entry, app_data, NULL);
  coap_lock_unlock();
}

COAP_API void *
coap_async_set_app_data2(coap_async_t *async_entry, void *app_data,
                         coap_app_data_free_callback_t callback) {
  void *old_data;

  coap_lock_lock(return NULL);
  old_data = coap_async_set_app_data2_lkd(async_entry, app_data, callback);
  coap_lock_unlock();
  return old_data;
}

void *
coap_async_set_app_data2_lkd(coap_async_t *async_entry, void *app_data,
                             coap_app_data_free_callback_t callback) {
  void *old_data = async_entry->app_data;

  async_entry->app_data = app_data;
  async_entry->app_cb = app_data ? callback : NULL;
  return old_data;
}

void *
coap_async_get_app_data(const coap_async_t *async) {
  return async->app_data;
}

#else /* ! COAP_ASYNC_SUPPORT */

int
coap_async_is_supported(void) {
  return 0;
}

coap_async_t *
coap_register_async(coap_session_t *session,
                    const coap_pdu_t *request,
                    coap_tick_t delay) {
  (void)session;
  (void)request;
  (void)delay;
  return NULL;
}

void
coap_async_set_delay(coap_async_t *async, coap_tick_t delay) {
  (void)async;
  (void)delay;
}

void
coap_free_async(coap_session_t *session, coap_async_t *async) {
  (void)session;
  (void)async;
}

coap_async_t *
coap_find_async(coap_session_t *session,
                coap_bin_const_t token) {
  (void)session;
  (void)token;
  return NULL;
}

COAP_API void
coap_async_set_app_data(coap_async_t *async, void *app_data) {
  (void)async;
  (void)app_data;
}

COAP_API void *
coap_async_set_app_data2(coap_async_t *async, void *app_data,
                         coap_app_data_free_callback_t callback) {
  (void)async;
  (void)app_data;
  (void)callback;
  return NULL;
}

void *
coap_async_get_app_data(const coap_async_t *async) {
  (void)async;
  return NULL;
}

#endif /* ! COAP_ASYNC_SUPPORT */
