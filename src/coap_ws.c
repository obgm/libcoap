/*
 * coap_ws.c -- WebSockets functions for libcoap
 *
 * Copyright (C) 2023 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_ws.c
 * @brief CoAP WebSocket handling functions
 */

#include "coap3/coap_internal.h"

#if COAP_WS_SUPPORT

#else /* !COAP_WS_SUPPORT */

int
coap_ws_is_supported(void) {
  return 0;
}

int
coap_wss_is_supported(void) {
  return 0;
}

int
coap_ws_set_host_request(coap_session_t *session, coap_str_const_t *ws_host) {
  (void)session;
  (void)ws_host;
  return 0;
}

#endif /* !COAP_WS_SUPPORT */
