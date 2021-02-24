/*
 * coap_session_internal.h -- Structures, Enums & Functions that are not
 * exposed to application programming
 *
 * Copyright (C) 2010-2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_session_internal.h
 * @brief COAP session internal information
 */

#ifndef COAP_SESSION_INTERNAL_H_
#define COAP_SESSION_INTERNAL_H_

#include "coap_io_internal.h"

#define COAP_DEFAULT_SESSION_TIMEOUT 300
#define COAP_PARTIAL_SESSION_TIMEOUT_TICKS (30 * COAP_TICKS_PER_SECOND)
#define COAP_DEFAULT_MAX_HANDSHAKE_SESSIONS 100

/**
 * @defgroup session_internal Sessions (Internal)
 * CoAP Session Structures, Enums and Functions that are not exposed to
 * applications
 * @{
 */

/**
 * Only used for servers for hashing incoming packets. Cannot have local IP
 * address as this may be an initial multicast and subsequent unicast address
 */
struct coap_addr_hash_t {
  coap_address_t remote;       /**< remote address and port */
  uint16_t lport;              /**< local port */
  coap_proto_t proto;          /**< CoAP protocol */
};

/**
 * Abstraction of virtual session that can be attached to coap_context_t
 * (client) or coap_endpoint_t (server).
 */
struct coap_session_t {
  coap_proto_t proto;               /**< protocol used */
  coap_session_type_t type;         /**< client or server side socket */
  coap_session_state_t state;       /**< current state of relationaship with
                                         peer */
  unsigned ref;                     /**< reference count from queues */
  size_t tls_overhead;              /**< overhead of TLS layer */
  size_t mtu;                       /**< path or CSM mtu */
  coap_addr_hash_t addr_hash;  /**< Address hash for server incoming packets */
  UT_hash_handle hh;
  coap_addr_tuple_t addr_info;      /**< key: remote/local address info */
  int ifindex;                      /**< interface index */
  coap_socket_t sock;               /**< socket object for the session, if
                                         any */
  coap_endpoint_t *endpoint;        /**< session's endpoint */
  coap_context_t *context;          /**< session's context */
  void *tls;                        /**< security parameters */
  uint16_t tx_mid;                  /**< the last message id that was used in
                                         this session */
  uint8_t con_active;               /**< Active CON request sent */
  uint8_t csm_block_supported;      /**< CSM TCP blocks supported */
  coap_mid_t last_ping_mid;         /**< the last keepalive message id that was
                                         used in this session */
  coap_queue_t *delayqueue;         /**< list of delayed messages waiting to
                                         be sent */
  coap_lg_xmit_t *lg_xmit;          /**< list of large transmissions */
  coap_lg_crcv_t *lg_crcv;       /**< Client list of expected large receives */
  coap_lg_srcv_t *lg_srcv;       /**< Server list of expected large receives */
  size_t partial_write;             /**< if > 0 indicates number of bytes
                                         already written from the pdu at the
                                         head of sendqueue */
  uint8_t read_header[8];           /**< storage space for header of incoming
                                         message header */
  size_t partial_read;              /**< if > 0 indicates number of bytes
                                         already read for an incoming message */
  coap_pdu_t *partial_pdu;          /**< incomplete incoming pdu */
  coap_tick_t last_rx_tx;
  coap_tick_t last_tx_rst;
  coap_tick_t last_ping;
  coap_tick_t last_pong;
  coap_tick_t csm_tx;
  coap_dtls_cpsk_t cpsk_setup_data; /**< client provided PSK initial setup
                                         data */
  coap_bin_const_t *psk_identity;   /**< If client, this field contains the
                                      current identity for server; When this
                                      field is NULL, the current identity is
                                      contained in cpsk_setup_data

                                      If server, this field contains the client
                                      provided identity.

                                      Value maintained internally */
  coap_bin_const_t *psk_key;        /**< If client, this field contains the
                                      current pre-shared key for server;
                                      When this field is NULL, the current
                                      key is contained in cpsk_setup_data

                                      If server, this field contains the
                                      client's current key.

                                      Value maintained internally */
  coap_bin_const_t *psk_hint;       /**< If client, this field contains the
                                      server provided identity hint.

                                      If server, this field contains the
                                      current hint for the client; When this
                                      field is NULL, the current hint is
                                      contained in context->spsk_setup_data

                                      Value maintained internally */
  void *app;                        /**< application-specific data */
  uint8_t block_mode;             /**< Zero or more COAP_BLOCK_ or'd options */
  coap_pdu_t *saved_pdu;          /**< Saved PDU when testing for remote
                                       feature */
  coap_fixed_point_t ack_timeout;   /**< timeout waiting for ack
                                         (default 2.0 secs) */
  coap_fixed_point_t ack_random_factor; /**< ack random factor backoff (default
                                             1.5) */
  uint16_t max_retransmit;          /**< maximum re-transmit count
                                         (default 4) */
  uint16_t nstart;                  /**< maximum concurrent confirmable xmits
                                         (default 1) */
  coap_fixed_point_t default_leisure; /**< Mcast leisure time
                                           (default 5.0 secs) */
  uint32_t probing_rate;            /**< Max transfer wait when remote is not
                                         respoding (default 1 byte/sec) */
  uint16_t max_payloads;            /**< maximum Q-BlockX payloads before delay
                                         (default 10) */
  uint16_t non_max_retransmit;      /**< maximum Q-BlockX non re-transmit count
                                         (default 4) */
  coap_fixed_point_t non_timeout;   /**< Q-BlockX timeout waiting for response
                                         (default 2.0 secs) */
  coap_fixed_point_t non_receive_timeout;  /**< Q-BlockX receive timeout before
                                         requesting missing packets.
                                         (default 4.0 secs) */
  coap_fixed_point_t non_probing_wait_base; /**< Q-BlockX max wait time base
                                              while probing
                                             (default 247.0 secs) */
  coap_fixed_point_t non_partial_timeout; /**< Q-BlockX time to wait before
                                           discarding partial data for a body.
                                           (default 247.0 secs) */
  unsigned int dtls_timeout_count;      /**< dtls setup retry counter */
  int dtls_event;                       /**< Tracking any (D)TLS events on this
                                             sesison */
  uint64_t tx_token;              /**< Next token number to use */
  uint64_t tx_rtag;               /**< Next Request-Tag number to use */
};

/**
 * Abstraction of virtual endpoint that can be attached to coap_context_t. The
 * keys (port, bind_addr) must uniquely identify this endpoint.
 */
struct coap_endpoint_t {
  struct coap_endpoint_t *next;
  coap_context_t *context;        /**< endpoint's context */
  coap_proto_t proto;             /**< protocol used on this interface */
  uint16_t default_mtu;           /**< default mtu for this interface */
  coap_socket_t sock;             /**< socket object for the interface, if
                                       any */
  coap_address_t bind_addr;       /**< local interface address */
  coap_session_t *sessions;       /**< hash table or list of active sessions */
};

coap_fixed_point_t coap_multi_fixed_fixed(coap_fixed_point_t fp1,
                                          coap_fixed_point_t fp2);

coap_fixed_point_t coap_multi_fixed_uint(coap_fixed_point_t fp1,
                                         uint32_t u2);

coap_fixed_point_t coap_add_fixed_fixed(coap_fixed_point_t fp1,
                                       coap_fixed_point_t fp2);

coap_fixed_point_t coap_add_fixed_uint(coap_fixed_point_t fp1,
                                       uint32_t u2);

coap_fixed_point_t coap_sub_fixed_uint(coap_fixed_point_t fp1,
                                       uint32_t u2);

coap_fixed_point_t coap_div_fixed_uint(coap_fixed_point_t fp1, uint32_t u2);

coap_fixed_point_t coap_get_non_timeout_random(coap_session_t *session);

coap_tick_t coap_get_non_timeout_random_ticks(coap_session_t *session);


/**
 * Notify session transport has just connected and CSM exchange can now start.
 *
 * @param session The CoAP session.
 */
void coap_session_send_csm(coap_session_t *session);

/**
 * Notify session that it has just connected or reconnected.
 *
 * @param session The CoAP session.
 */
void coap_session_connected(coap_session_t *session);

/**
 * Refresh the session's current Identity Hint (PSK).
 * Note: A copy of @p psk_hint is maintained in the session by libcoap.
 *
 * @param session  The current coap_session_t object.
 * @param psk_hint If NULL, the Identity Hint will revert to the
 *                 initial Identity Hint used at session setup.
 *
 * @return @c 1 if successful, else @c 0.
 */
int coap_session_refresh_psk_hint(coap_session_t *session,
                                  const coap_bin_const_t *psk_hint);

/**
 * Refresh the session's current pre-shared key (PSK).
 * Note: A copy of @p psk_key is maintained in the session by libcoap.
 *
 * @param session  The current coap_session_t object.
 * @param psk_key  If NULL, the pre-shared key will revert to the
 *                 initial pre-shared key used as session setup.
 *
 * @return @c 1 if successful, else @c 0.
 */
int coap_session_refresh_psk_key(coap_session_t *session,
                                 const coap_bin_const_t *psk_key);

/**
 * Creates a new server session for the specified endpoint.
 * @param ctx The CoAP context.
 * @param ep An endpoint where an incoming connection request is pending.
 *
 * @return A new CoAP session or NULL if failed. Call coap_session_release to
 * add to unused queue.
 */
coap_session_t *coap_new_server_session(
  coap_context_t *ctx,
  coap_endpoint_t *ep
);

/**
 * Function interface for datagram data transmission. This function returns
 * the number of bytes that have been transmitted, or a value less than zero
 * on error.
 *
 * @param session          Session to send data on.
 * @param data             The data to send.
 * @param datalen          The actual length of @p data.
 *
 * @return                 The number of bytes written on success, or a value
 *                         less than zero on error.
 */
ssize_t coap_session_send(coap_session_t *session,
  const uint8_t *data, size_t datalen);

/**
 * Function interface for stream data transmission. This function returns
 * the number of bytes that have been transmitted, or a value less than zero
 * on error. The number of bytes written may be less than datalen because of
 * congestion control.
 *
 * @param session          Session to send data on.
 * @param data             The data to send.
 * @param datalen          The actual length of @p data.
 *
 * @return                 The number of bytes written on success, or a value
 *                         less than zero on error.
 */
ssize_t coap_session_write(coap_session_t *session,
  const uint8_t *data, size_t datalen);

/**
 * Send a pdu according to the session's protocol. This function returns
 * the number of bytes that have been transmitted, or a value less than zero
 * on error.
 *
 * @param session          Session to send pdu on.
 * @param pdu              The pdu to send.
 *
 * @return                 The number of bytes written on success, or a value
 *                         less than zero on error.
 */
ssize_t coap_session_send_pdu(coap_session_t *session, coap_pdu_t *pdu);

ssize_t
coap_session_delay_pdu(coap_session_t *session, coap_pdu_t *pdu,
                       coap_queue_t *node);

/**
 * Lookup the server session for the packet received on an endpoint, or create
 * a new one.
 *
 * @param endpoint Active endpoint the packet was received on.
 * @param packet Received packet.
 * @param now The current time in ticks.
 * @return The CoAP session or @c NULL if error.
 */
coap_session_t *coap_endpoint_get_session(coap_endpoint_t *endpoint,
  const coap_packet_t *packet, coap_tick_t now);

/**
 * Create a new DTLS session for the @p session.
 * Note: the @p session is released if no DTLS server session can be created.
 *
 * @ingroup dtls_internal
 *
 * @param session   Session to add DTLS session to
 * @param now       The current time in ticks.
 *
 * @return CoAP session or @c NULL if error.
 */
coap_session_t *coap_session_new_dtls_session(coap_session_t *session,
  coap_tick_t now);

void coap_session_free(coap_session_t *session);
void coap_session_mfree(coap_session_t *session);

#define COAP_SESSION_REF(s) s->ref

/* RFC7252 */
#define COAP_ACK_TIMEOUT(s) (s)->ack_timeout
#define COAP_ACK_RANDOM_FACTOR(s) (s)->ack_random_factor
#define COAP_MAX_RETRANSMIT(s) (s)->max_retransmit
#define COAP_NSTART(s) (s)->nstart
#define COAP_DEFAULT_LEISURE(s) (s)->default_leisure
#define COAP_PROBING_RATE(s) (s)->probing_rate
/* draft-ietf-core-new-block */
#define COAP_MAX_PAYLOADS(s) (s)->max_payloads
#define COAP_NON_MAX_RETRANSMIT(s) (s)->non_max_retransmit
#define COAP_NON_TIMEOUT(s) (s)->non_timeout
#define COAP_NON_TIMEOUT_TICKS(s) \
   (COAP_NON_TIMEOUT(s).integer_part * COAP_TICKS_PER_SECOND + \
    COAP_NON_TIMEOUT(s).fractional_part * COAP_TICKS_PER_SECOND / 1000)
#define COAP_NON_RECEIVE_TIMEOUT(s) (s)->non_receive_timeout
#define COAP_NON_PROBING_WAIT_BASE(s) (s)->non_probing_wait_base
#define COAP_NON_PARTIAL_TIMEOUT(s) (s)->non_partial_timeout

  /**
   * The DEFAULT_LEISURE definition for the session (s).
   *
   * RFC 7252, Section 4.8
   * Initial value 5.0 seconds
   */
#define COAP_DEFAULT_LEISURE_TICKS(s) \
     (COAP_DEFAULT_LEISURE(s).integer_part * COAP_TICKS_PER_SECOND + \
      COAP_DEFAULT_LEISURE(s).fractional_part * COAP_TICKS_PER_SECOND / 1000)
  /**
   * The MAX_TRANSMIT_SPAN definition for the session (s).
   *
   * RFC 7252, Section 4.8.2 Calculation of MAX_TRAMSMIT_SPAN
   *  ACK_TIMEOUT * ((2 ** (MAX_RETRANSMIT)) - 1) * ACK_RANDOM_FACTOR
   */
#define COAP_MAX_TRANSMIT_SPAN(s) \
 ((s->ack_timeout.integer_part * 1000 + s->ack_timeout.fractional_part) * \
  ((1 << (s->max_retransmit)) -1) * \
  (s->ack_random_factor.integer_part * 1000 + \
   s->ack_random_factor.fractional_part) \
  / 1000000)

  /**
   * The MAX_TRANSMIT_WAIT definition for the session (s).
   *
   * RFC 7252, Section 4.8.2 Calculation of MAX_TRAMSMIT_WAIT
   *  ACK_TIMEOUT * ((2 ** (MAX_RETRANSMIT + 1)) - 1) * ACK_RANDOM_FACTOR
   */
#define COAP_MAX_TRANSMIT_WAIT(s) \
 ((s->ack_timeout.integer_part * 1000 + s->ack_timeout.fractional_part) * \
  ((1 << (s->max_retransmit + 1)) -1) * \
  (s->ack_random_factor.integer_part * 1000 + \
   s->ack_random_factor.fractional_part) \
  / 1000000)

  /**
   * The PROCESSING_DELAY definition for the session (s).
   *
   * RFC 7252, Section 4.8.2 Calculation of PROCESSING_DELAY
   *  PROCESSING_DELAY set to ACK_TIMEOUT
   */
#define COAP_PROCESSING_DELAY(s) \
 ((s->ack_timeout.integer_part * 1000 + s->ack_timeout.fractional_part + 500) \
  / 1000)

  /**
   * The MAX_RTT definition for the session (s).
   *
   * RFC 7252, Section 4.8.2 Calculation of MAX_RTT
   *  (2 * MAX_LATENCY) + PROCESSING_DELAY
   */
#define COAP_MAX_RTT(s) \
 ((2 * COAP_DEFAULT_MAX_LATENCY) + COAP_PROCESSING_DELAY(s))

  /**
   * The EXCHANGE_LIFETIME definition for the session (s).
   *
   * RFC 7252, Section 4.8.2 Calculation of EXCHANGE_LIFETIME
   *  MAX_TRANSMIT_SPAN + (2 * MAX_LATENCY) + PROCESSING_DELAY
   */
#define COAP_EXCHANGE_LIFETIME(s) \
 (COAP_MAX_TRANSMIT_SPAN(s) + (2 * COAP_MAX_LATENCY) + COAP_PROCESSING_DELAY(s))

  /**
   * The NON_LIFETIME definition for the session (s).
   *
   * RFC 7252, Section 4.8.2 Calculation of NON_LIFETIME
   *  MAX_TRANSMIT_SPAN + MAX_LATENCY
   */
#define COAP_NON_LIFETIME(s) \
 (COAP_MAX_TRANSMIT_SPAN(s) + COAP_DEFAULT_MAX_LATENCY)

  /**
   * The NON_RECEIVE_TIMEOUT definition for the session (s).
   *
   * draft-ietf-core-new-block, Section 6.2
   * 2 * NON_TIMEOUT
   */
#define COAP_NON_RECEIVE_TIMEOUT_TICKS(s) ( \
   COAP_NON_RECEIVE_TIMEOUT(s).integer_part * COAP_TICKS_PER_SECOND + \
   COAP_NON_RECEIVE_TIMEOUT(s).fractional_part * COAP_TICKS_PER_SECOND / 1000)

  /**
   * The NON_PROBING_WAIT definition for the session (s).
   *
   * draft-ietf-core-new-block, Section 6.2
   *  NON_PROBING_WAIT = NON_TIMEOUT * ((2 ** NON_MAX_RETRANSMIT) - 1) *
   *  ACK_RANDOM_FACTOR + (2 * MAX_LATENCY) + NON_TIMEOUT_RANDOM
   * Default is 247-248 seconds
   */
#define COAP_NON_PROBING_WAIT(s) \
   coap_add_fixed_fixed(COAP_NON_PROBING_WAIT_BASE(s), \
                        COAP_NON_TIMEOUT_RANDOM(s))

#define COAP_NON_PROBING_WAIT_TICKS(s) \
     (COAP_NON_PROBING_WAIT(s).integer_part * COAP_TICKS_PER_SECOND + \
      COAP_NON_PROBING_WAIT(s).fractional_part * COAP_TICKS_PER_SECOND / 1000)

  /**
   * The NON_PARTIAL_TIMEOUT definition for the session (s).
   *
   * draft-ietf-core-new-block, Section 6.2
   * Initial value EXCHANGE_LIFETIME (247 seconds)
   */
#define COAP_NON_PARTIAL_TIMEOUT_TICKS(s) \
     (COAP_NON_PARTIAL_TIMEOUT(s).integer_part * COAP_TICKS_PER_SECOND + \
   COAP_NON_PARTIAL_TIMEOUT(s).fractional_part * COAP_TICKS_PER_SECOND / 1000)

  /**
   * The NON_TIMEOUT_RANDOM definition for the session (s).
   *
   * draft-ietf-core-new-block, Section 6.2
   * Default is 2-3 seconds
   */
#define COAP_NON_TIMEOUT_RANDOM(s) \
   coap_get_non_timeout_random(s)

/** @} */

#define SESSIONS_ADD(e, obj) \
  HASH_ADD(hh, (e), addr_hash, sizeof((obj)->addr_hash), (obj))

#define SESSIONS_DELETE(e, obj) \
  HASH_DELETE(hh, (e), (obj))

#define SESSIONS_ITER(e, el, rtmp)  \
  HASH_ITER(hh, (e), el, rtmp)

#define SESSIONS_ITER_SAFE(e, el, rtmp) \
for ((el) = (e); (el) && ((rtmp) = (el)->hh.next, 1); (el) = (rtmp))

#define SESSIONS_FIND(e, k, res) {                     \
    HASH_FIND(hh, (e), &(k), sizeof(k), (res)); \
  }

#endif /* COAP_SESSION_INTERNAL_H_ */
