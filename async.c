/* async.c -- state management for asynchronous messages
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

/** 
 * @file async.c
 * @brief state management for asynchronous messages
 */

#ifndef WITHOUT_ASYNC

#include "mem.h"
#include "async.h"

coap_async_state_t *
coap_new_async_state(coap_context_t *context, coap_address_t *peer,
		     unsigned char *token, size_t tokenlen,
		     unsigned char flags, void *data) {
  coap_async_state_t *s;
  s = (coap_async_state_t *)coap_malloc(sizeof(coap_async_state_t) + tokenlen);
  if (s) {
    memset(s, 0, sizeof(coap_address_t));
    memcpy(&s->peer, peer, sizeof(coap_address_t));
    memcpy(s->token, token, tokenlen);
    s->tokenlen = tokenlen;
  }
  return s;
}

void 
coap_async_state_free(coap_async_state_t *s) {
  if (s && (s->flags & COAP_ASYNC_RELEASE_DATA) != 0)
    coap_free(s->appdata);
  coap_free(s); 
}

#endif /* WITHOUT_ASYNC */
