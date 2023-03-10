/*
 * coap_dtls.c -- (D)TLS functions for libcoap
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
 * @file coap_dtls.c
 * @brief CoAP (D)TLS handling functions
 */

#include "coap3/coap_internal.h"

void
coap_dtls_establish(coap_session_t *session) {
  assert(session->proto == COAP_PROTO_DTLS);
#if COAP_CLIENT_SUPPORT
  if (session->type == COAP_SESSION_TYPE_CLIENT)
    session->tls = coap_dtls_new_client_session(session);
#endif /* COAP_CLIENT_SUPPORT */
#if COAP_SERVER_SUPPORT
  if (session->type != COAP_SESSION_TYPE_CLIENT)
    session->tls = coap_dtls_new_server_session(session);
#endif /* COAP_SERVER_SUPPORT */

  if (session->tls) {
    session->state = COAP_SESSION_STATE_HANDSHAKE;
  } else {
    coap_session_disconnected(session, COAP_NACK_TLS_LAYER_FAILED);
    return;
  }
  coap_ticks(&session->last_rx_tx);
  return;
}

void
coap_dtls_close(coap_session_t *session) {
  if (session->tls)
    coap_dtls_free_session(session);
  if (coap_netif_available(session))
    coap_netif_close(session);
}

#if !COAP_DISABLE_TCP
void
coap_tls_establish(coap_session_t *session) {
  int connected = 0;

  assert(session->proto == COAP_PROTO_TLS);
#if COAP_CLIENT_SUPPORT
  if (session->type == COAP_SESSION_TYPE_CLIENT)
    session->tls = coap_tls_new_client_session(session, &connected);
#endif /* COAP_CLIENT_SUPPORT */
#if COAP_SERVER_SUPPORT
  if (session->type != COAP_SESSION_TYPE_CLIENT)
    session->tls = coap_tls_new_server_session(session, &connected);
#endif /* COAP_SERVER_SUPPORT */

  if (session->tls) {
    session->state = COAP_SESSION_STATE_HANDSHAKE;
    if (connected) {
      coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
      coap_session_establish(session);
    }
  } else {
    coap_session_disconnected(session, COAP_NACK_TLS_LAYER_FAILED);
    return;
  }
  coap_ticks(&session->last_rx_tx);
  return;
}

void
coap_tls_close(coap_session_t *session) {
  if (session->tls)
    coap_tls_free_session(session);
  if (coap_netif_available(session))
    coap_netif_close(session);
}
#endif /* COAP_DISABLE_TCP */
