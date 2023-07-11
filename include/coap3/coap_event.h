/*
 * coap_event.h -- libcoap Event API
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021-2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_event.h
 * @brief Event handling
 */

#ifndef COAP_EVENT_H_
#define COAP_EVENT_H_

#include "libcoap.h"

/**
 * @ingroup application_api
 * @defgroup events Event Handling
 * API for event delivery from lower-layer library functions.
 * @{
 */

/**
 * Scalar type to represent different events, e.g. DTLS events or
 * retransmission timeouts.
 */
typedef enum {
  /*
   * (D)TLS events for COAP_PROTO_DTLS and COAP_PROTO_TLS
   */
  /** Triggerred when (D)TLS session closed */
  COAP_EVENT_DTLS_CLOSED       = 0x0000,
  /** Triggered when (D)TLS session connected */
  COAP_EVENT_DTLS_CONNECTED    = 0x01DE,
  /** Triggered when (D)TLS session renegotiated */
  COAP_EVENT_DTLS_RENEGOTIATE  = 0x01DF,
  /** Triggered when (D)TLS error occurs */
  COAP_EVENT_DTLS_ERROR        = 0x0200,

  /*
   * TCP events for COAP_PROTO_TCP and COAP_PROTO_TLS
   */
  /** Triggered when TCP layer connects */
  COAP_EVENT_TCP_CONNECTED     = 0x1001,
  /** Triggered when TCP layer is closed */
  COAP_EVENT_TCP_CLOSED        = 0x1002,
  /** Triggered when TCP layer fails for some reason */
  COAP_EVENT_TCP_FAILED        = 0x1003,

  /*
   * CSM exchange events for reliable protocols only
   */
  /** Triggered when TCP layer completes exchange of CSM information */
  COAP_EVENT_SESSION_CONNECTED = 0x2001,
  /** Triggered when TCP layer closes following exchange of CSM information */
  COAP_EVENT_SESSION_CLOSED    = 0x2002,
  /** Triggered when TCP layer fails  following exchange of CSM information */
  COAP_EVENT_SESSION_FAILED    = 0x2003,

  /*
   * (Q-)Block errors
   */
  /** Triggered when not all of a large body has been received */
  COAP_EVENT_PARTIAL_BLOCK     = 0x3001,
  /** Triggered when not all of a large body has been transmitted */
  COAP_EVENT_XMIT_BLOCK_FAIL   = 0x3002,

  /*
   * Server session events
   */
  /**
   * Called in the CoAP IO loop if a new *server-side* session is created due
   * to an incoming connection.
   *
   * Note that the session might not be a fully established connection yet,
   * it might also refer to, e.g., a DTLS session in a handshake stage.
   */
  COAP_EVENT_SERVER_SESSION_NEW = 0x4001,

  /**
   * Called in the CoAP IO loop if a server session is deleted (e.g., due to
   * inactivity or because the maximum number of idle sessions was exceeded).
   *
   * The session will still contain valid data when the event handler is
   * called.
   */
  COAP_EVENT_SERVER_SESSION_DEL = 0x4002,

  /*
   * Message receive and transmit events
   */
  /** Triggered when badly formatted packet received */
  COAP_EVENT_BAD_PACKET         = 0x5001,
  /** Triggered when a message is retransmitted */
  COAP_EVENT_MSG_RETRANSMITTED  = 0x5002,

  /*
   * OSCORE events
   */
  /** Triggered when there is an OSCORE decryption failure */
  COAP_EVENT_OSCORE_DECRYPTION_FAILURE = 0x6001,
  /** Triggered when trying to use OSCORE to decrypt, but it is not enabled */
  COAP_EVENT_OSCORE_NOT_ENABLED,
  /** Triggered when there is no OSCORE encrypted payload provided */
  COAP_EVENT_OSCORE_NO_PROTECTED_PAYLOAD,
  /** Triggered when there is no OSCORE security definition found */
  COAP_EVENT_OSCORE_NO_SECURITY,
  /** Triggered when there is an OSCORE internal error i.e malloc failed */
  COAP_EVENT_OSCORE_INTERNAL_ERROR,
  /** Triggered when there is an OSCORE decode of OSCORE option failure */
  COAP_EVENT_OSCORE_DECODE_ERROR,
  /*
   * WebSocket events
   */
  /** Triggered when there is an oversize WebSockets packet */
  COAP_EVENT_WS_PACKET_SIZE = 0x7001,
  /** Triggered when the WebSockets layer is up */
  COAP_EVENT_WS_CONNECTED,
  /** Triggered when the WebSockets layer is closed */
  COAP_EVENT_WS_CLOSED,
  /*
   * Keepalive events
   */
  /** Triggered when no response to a keep alive (ping) packet */
  COAP_EVENT_KEEPALIVE_FAILURE = 0x8001,
} coap_event_t;

/**
 * Type for event handler functions that can be registered with a CoAP
 * context using the function coap_set_event_handler(). When called by
 * the library, the first argument will be the current coap_session_t object
 * which is associated with the original CoAP context. The second parameter
 * is the event type.
 */
typedef int (*coap_event_handler_t)(coap_session_t *session,
                                    const coap_event_t event);

/**
 * Registers the function @p hnd as callback for events from the given
 * CoAP context @p context. Any event handler that has previously been
 * registered with @p context will be overwritten by this operation.
 *
 * @param context The CoAP context to register the event handler with.
 * @param hnd     The event handler to be registered.  @c NULL if to be
 *                de-registered.
 */
void coap_register_event_handler(coap_context_t *context,
                                 coap_event_handler_t hnd);

/** @} */

/**
 * Registers the function @p hnd as callback for events from the given
 * CoAP context @p context. Any event handler that has previously been
 * registered with @p context will be overwritten by this operation.
 *
 * @deprecated Use coap_register_event_handler() instead.
 *
 * @param context The CoAP context to register the event handler with.
 * @param hnd     The event handler to be registered.
 */
COAP_DEPRECATED
void coap_set_event_handler(coap_context_t *context,
                            coap_event_handler_t hnd);

/**
 * Clears the event handler registered with @p context.
 *
 * @deprecated Use coap_register_event_handler() instead with NULL for handler.
 *
 * @param context The CoAP context whose event handler is to be removed.
 */
COAP_DEPRECATED
void coap_clear_event_handler(coap_context_t *context);

#endif /* COAP_EVENT_H */
