/*
 * coap_event.c -- libcoap Event API
 *
 * Copyright (C) 2016-2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_event.c
 * @brief Event handling
 */

#include "coap3/coap_libcoap_build.h"

/*
 * This replaces coap_set_event_handler() so that handler registration is
 * consistent in the naming.
 */
void
coap_register_event_handler(coap_context_t *context,
                            coap_event_handler_t hnd) {
  context->handle_event = hnd;
}

void
coap_set_event_handler(coap_context_t *context,
                       coap_event_handler_t hnd) {
  context->handle_event = hnd;
}

void
coap_clear_event_handler(coap_context_t *context) {
  context->handle_event = NULL;
}
