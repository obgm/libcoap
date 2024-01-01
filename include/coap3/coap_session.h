/* coap_session.h -- Session management for libcoap
 *
 * Copyright (C) 2017 Jean-Claue Michelou <jcm@spinetix.com>
 * Copyright (C) 2023-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
*/

/**
 * @file coap_session.h
 * @brief Defines the application visible session information
 */

#ifndef COAP_SESSION_H_
#define COAP_SESSION_H_

/**
 * @ingroup application_api
 * @defgroup session Sessions
 * API for CoAP Session access
 * @{
 */

/**
* Abstraction of a fixed point number that can be used where necessary instead
* of a float.  1,000 fractional bits equals one integer
*/
typedef struct coap_fixed_point_t {
  uint16_t integer_part;    /**< Integer part of fixed point variable */
  uint16_t fractional_part; /**< Fractional part of fixed point variable
                                1/1000 (3 points) precision */
} coap_fixed_point_t;

#define COAP_PROTO_NOT_RELIABLE(p) ((p)==COAP_PROTO_UDP || (p)==COAP_PROTO_DTLS)
#define COAP_PROTO_RELIABLE(p) ((p)==COAP_PROTO_TCP || (p)==COAP_PROTO_TLS || \
                                (p)==COAP_PROTO_WS || (p)==COAP_PROTO_WSS)

/**
 * coap_session_type_t values
 */
typedef enum coap_session_type_t {
  COAP_SESSION_TYPE_NONE = 0, /**< Not defined */
  COAP_SESSION_TYPE_CLIENT,   /**< client-side */
  COAP_SESSION_TYPE_SERVER,   /**< server-side */
  COAP_SESSION_TYPE_HELLO,    /**< server-side ephemeral session for
                                   responding to a client hello */
} coap_session_type_t;

/**
 * coap_session_state_t values
 */
typedef enum coap_session_state_t {
  COAP_SESSION_STATE_NONE = 0,
  COAP_SESSION_STATE_CONNECTING,
  COAP_SESSION_STATE_HANDSHAKE,
  COAP_SESSION_STATE_CSM,
  COAP_SESSION_STATE_ESTABLISHED,
} coap_session_state_t;

/**
 * Increment reference counter on a session.
 *
 * @param session The CoAP session.
 * @return same as session
 */
coap_session_t *coap_session_reference(coap_session_t *session);

/**
 * Decrement reference counter on a session.
 * Note that the session may be deleted as a result and should not be used
 * after this call.
 *
 * @param session The CoAP session.
 */
void coap_session_release(coap_session_t *session);

/**
 * Notify session that it has failed.  This cleans up any outstanding / queued
 * transmissions, observations etc..
 *
 * @param session The CoAP session.
 * @param reason The reason why the session was disconnected.
 */
void coap_session_disconnected(coap_session_t *session,
                               coap_nack_reason_t reason);

/**
 * Stores @p data with the given session. This function overwrites any value
 * that has previously been stored with @p session.
 *
 * @param session The CoAP session.
 * @param data The pointer to the data to store.
 */
void coap_session_set_app_data(coap_session_t *session, void *data);

/**
 * Returns any application-specific data that has been stored with @p
 * session using the function coap_session_set_app_data(). This function will
 * return @c NULL if no data has been stored.
 *
 * @param session The CoAP session.
 *
 * @return Pointer to the stored data or @c NULL.
 */
void *coap_session_get_app_data(const coap_session_t *session);

/**
 * Get the remote IP address and port from the session.
 *
 * Note: For clients, this can be the responding IP address for a multicast
 * request before the next coap_send() is called when the multicast address
 * is restored.
 *
 * @param session The CoAP session.
 *
 * @return The session's remote address or @c NULL on failure.
 */
const coap_address_t *coap_session_get_addr_remote(
    const coap_session_t *session);

/**
 * Get the remote multicast IP address and port from the session if the
 * original target IP was multicast.
 *
 * Note: This is only available for a client.
 *
 * @param session The CoAP session.
 *
 * @return The session's remote multicast address or @c NULL on failure or if
 *         this is not a multicast session.
 */
const coap_address_t *coap_session_get_addr_mcast(
    const coap_session_t *session);

/**
 * Get the local IP address and port from the session.
 *
 * @param session The CoAP session.
 *
 * @return The session's local address or @c NULL on failure.
 */
const coap_address_t *coap_session_get_addr_local(
    const coap_session_t *session);

/**
 * Get the session protocol type
 *
 * @param session The CoAP session.
 *
 * @return The session's protocol type
 */
coap_proto_t coap_session_get_proto(const coap_session_t *session);

/**
 * Get the session type
 *
 * @param session The CoAP session.
 *
 * @return The session's type
 */
coap_session_type_t coap_session_get_type(const coap_session_t *session);

/**
 * Get the session state
 *
 * @param session The CoAP session.
 *
 * @return The session's state
 */
coap_session_state_t coap_session_get_state(const coap_session_t *session);

/**
 * Get the session if index
 *
 * @param session The CoAP session.
 *
 * @return The session's if index, or @c -1 on error.
 */
int coap_session_get_ifindex(const coap_session_t *session);

/**
 * Get the session TLS security ptr (TLS type dependent)
 *
 * OpenSSL:  SSL*
 * GnuTLS:   gnutls_session_t (implicit *)
 * Mbed TLS: mbedtls_ssl_context*
 * TinyDTLS: struct dtls_context*
 *
 * @param session The CoAP session.
 * @param tls_lib Updated with the library type.
 *
 * @return The session TLS ptr or @c NULL if not set up
 */
void *coap_session_get_tls(const coap_session_t *session,
                           coap_tls_library_t *tls_lib);

/**
 * Get the session context
 *
 * @param session The CoAP session.
 *
 * @return The session's context
 */
coap_context_t *coap_session_get_context(const coap_session_t *session);

/**
 * Set the session type to client. Typically used in a call-home server.
 * The session needs to be of type COAP_SESSION_TYPE_SERVER.
 * Note: If this function is successful, the session reference count is
 * incremented and a subsequent coap_session_release() taking the
 * reference count to 0 will cause the session to be freed off.
 *
 * @param session The CoAP session.
 *
 * @return @c 1 if updated, @c 0 on failure.
 */
int coap_session_set_type_client(coap_session_t *session);

/**
 * Set the session MTU. This is the maximum message size that can be sent,
 * excluding IP and UDP overhead.
 *
 * @param session The CoAP session.
 * @param mtu maximum message size
 */
void coap_session_set_mtu(coap_session_t *session, unsigned mtu);

/**
 * Get maximum acceptable PDU size
 *
 * @param session The CoAP session.
 *
 * @return maximum PDU size, not including header (but including token).
 */
size_t coap_session_max_pdu_size(const coap_session_t *session);

/**
* Creates a new client session to the designated server.
* @param ctx The CoAP context.
* @param local_if Address of local interface. It is recommended to use NULL to let the operating system choose a suitable local interface. If an address is specified, the port number should be zero, which means that a free port is automatically selected.
* @param server The server's address. If the port number is zero, the default port for the protocol will be used.
* @param proto Protocol.
*
* @return A new CoAP session or NULL if failed. Call coap_session_release to free.
*/
coap_session_t *coap_new_client_session(
    coap_context_t *ctx,
    const coap_address_t *local_if,
    const coap_address_t *server,
    coap_proto_t proto
);

/**
* Creates a new client session to the designated server with PSK credentials
 *
 * @deprecated Use coap_new_client_session_psk2() instead.
 *
* @param ctx The CoAP context.
* @param local_if Address of local interface. It is recommended to use NULL to let the operating system choose a suitable local interface. If an address is specified, the port number should be zero, which means that a free port is automatically selected.
* @param server The server's address. If the port number is zero, the default port for the protocol will be used.
* @param proto Protocol.
* @param identity PSK client identity
* @param key PSK shared key
* @param key_len PSK shared key length
*
* @return A new CoAP session or NULL if failed. Call coap_session_release to free.
*/
coap_session_t *coap_new_client_session_psk(
    coap_context_t *ctx,
    const coap_address_t *local_if,
    const coap_address_t *server,
    coap_proto_t proto,
    const char *identity,
    const uint8_t *key,
    unsigned key_len
);

/**
* Creates a new client session to the designated server with PSK credentials
* @param ctx The CoAP context.
* @param local_if Address of local interface. It is recommended to use NULL to
*                 let the operating system choose a suitable local interface.
*                 If an address is specified, the port number should be zero,
*                 which means that a free port is automatically selected.
* @param server The server's address. If the port number is zero, the default
*               port for the protocol will be used.
* @param proto CoAP Protocol.
* @param setup_data PSK parameters.
*
* @return A new CoAP session or NULL if failed. Call coap_session_release()
*         to free.
*/
coap_session_t *coap_new_client_session_psk2(
    coap_context_t *ctx,
    const coap_address_t *local_if,
    const coap_address_t *server,
    coap_proto_t proto,
    coap_dtls_cpsk_t *setup_data
);

/**
 * Get the server session's current Identity Hint (PSK).
 *
 * @param session  The current coap_session_t object.
 *
 * @return @c hint if successful, else @c NULL.
 */
const coap_bin_const_t *coap_session_get_psk_hint(
    const coap_session_t *session);

/**
 * Get the server session's current PSK identity (PSK).
 *
 * @param session  The current coap_session_t object.
 *
 * @return PSK identity if successful, else @c NULL.
 */
const coap_bin_const_t *coap_session_get_psk_identity(
    const coap_session_t *session);
/**
 * Get the session's current pre-shared key (PSK).
 *
 * @param session  The current coap_session_t object.
 *
 * @return @c psk_key if successful, else @c NULL.
 */
const coap_bin_const_t *coap_session_get_psk_key(
    const coap_session_t *session);

/**
* Creates a new client session to the designated server with PKI credentials
* @param ctx The CoAP context.
* @param local_if Address of local interface. It is recommended to use NULL to
*                 let the operating system choose a suitable local interface.
*                 If an address is specified, the port number should be zero,
*                 which means that a free port is automatically selected.
* @param server The server's address. If the port number is zero, the default
*               port for the protocol will be used.
* @param proto CoAP Protocol.
* @param setup_data PKI parameters.
*
* @return A new CoAP session or NULL if failed. Call coap_session_release()
*         to free.
*/
coap_session_t *coap_new_client_session_pki(
    coap_context_t *ctx,
    const coap_address_t *local_if,
    const coap_address_t *server,
    coap_proto_t proto,
    coap_dtls_pki_t *setup_data
);

/**
 * Initializes the token value to use as a starting point.
 *
 * @param session The current coap_session_t object.
 * @param length  The length of the token (0 - 8 bytes).
 * @param token   The token data.
 *
 */
void coap_session_init_token(coap_session_t *session, size_t length,
                             const uint8_t *token);

/**
 * Creates a new token for use.
 *
 * @param session The current coap_session_t object.
 * @param length  Updated with the length of the new token.
 * @param token   Updated with the new token data (must be 8 bytes long).
 *
 */
void coap_session_new_token(coap_session_t *session, size_t *length,
                            uint8_t *token);

/**
 * @ingroup logging
 * Get session description.
 *
 * @param session  The CoAP session.
 * @return description string.
 */
const char *coap_session_str(const coap_session_t *session);

/**
 * Create a new endpoint for communicating with peers.
 *
 * @param context     The coap context that will own the new endpoint,
 * @param listen_addr Address the endpoint will listen for incoming requests
 *                    on or originate outgoing requests from. Use NULL to
 *                    specify that no incoming request will be accepted and
 *                    use a random endpoint.
 * @param proto       Protocol used on this endpoint,
 *
 * @return The new endpoint or @c NULL on failure.
 */
coap_endpoint_t *coap_new_endpoint(coap_context_t *context, const coap_address_t *listen_addr,
                                   coap_proto_t proto);

/**
 * Set the endpoint's default MTU. This is the maximum message size that can be
 * sent, excluding IP and UDP overhead.
 *
 * @param endpoint The CoAP endpoint.
 * @param mtu maximum message size
 */
void coap_endpoint_set_default_mtu(coap_endpoint_t *endpoint, unsigned mtu);

/**
 * Release an endpoint and all the structures associated with it.
 *
 * @param endpoint The endpoint to release.
 */
void coap_free_endpoint(coap_endpoint_t *endpoint);

/**
 * Get the session associated with the specified @p remote_addr and @p index.
 *
 * @param context The context to search.
 * @param remote_addr The remote (peer) address to search for.
 * @param ifindex The Interface index that is used to access remote_addr.
 *
 * @return The found session or @c NULL if not found.
 */
coap_session_t *coap_session_get_by_peer(const coap_context_t *context,
                                         const coap_address_t *remote_addr,
                                         int ifindex);

/** @} */

/**
 * @ingroup logging
* Get endpoint description.
*
* @param endpoint  The CoAP endpoint.
* @return description string.
*/
const char *coap_endpoint_str(const coap_endpoint_t *endpoint);

/**
 * @ingroup application_api
 * @defgroup cc Rate Control
 * API for updating transmission parameters for CoAP rate control.
 * The transmission parameters for CoAP rate control ("Congestion
 * Control" in stream-oriented protocols) are defined in
 * https://rfc-editor.org/rfc/rfc7252#section-4.8 and
 * https://rfc-editor.org/rfc/rfc9177#section-6.2
 * @{
 */

/**
 * Number of seconds when to expect an ACK or a response to an
 * outstanding CON message.
 * RFC 7252, Section 4.8 Default value of ACK_TIMEOUT is 2
 *
 * Configurable using coap_session_set_ack_timeout()
 */
#define COAP_DEFAULT_ACK_TIMEOUT ((coap_fixed_point_t){2,0})

/**
 * A factor that is used to randomize the wait time before a message
 * is retransmitted to prevent synchronization effects.
 * RFC 7252, Section 4.8 Default value of ACK_RANDOM_FACTOR is 1.5
 *
 * Configurable using coap_session_set_ack_random_factor()
 */
#define COAP_DEFAULT_ACK_RANDOM_FACTOR ((coap_fixed_point_t){1,500})

/**
 * Number of message retransmissions before message sending is stopped.
 * RFC 7252, Section 4.8 Default value of MAX_RETRANSMIT is 4
 *
 * Configurable using coap_session_set_max_retransmit()
 */
#define COAP_DEFAULT_MAX_RETRANSMIT  (4U)

/**
 * The number of simultaneous outstanding interactions that a client
 * maintains to a given server.
 * RFC 7252, Section 4.8 Default value of NSTART is 1
 *
 * Configurable using coap_session_set_nstart()
 */
#define COAP_DEFAULT_NSTART (1U)

/**
 * The number of seconds to use as bounds for multicast traffic
 * RFC 7252, Section 4.8 Default value of DEFAULT_LEISURE is 5.0
 *
 * Configurable using coap_session_set_default_leisure()
 */
#define COAP_DEFAULT_DEFAULT_LEISURE ((coap_fixed_point_t){5,0})

/**
 * The number of bytes/second allowed when there is no response
 * RFC 7252, Section 4.8 Default value of PROBING_RATE is 1
 *
 * Configurable using coap_session_set_probing_rate()
 */
#define COAP_DEFAULT_PROBING_RATE (1U)

/**
 * Number of Q-Block1 or Q-Block2 payloads that can be sent in a burst
 * before a delay has to kick in.
 * RFC9177 Section 6.2 Default value of MAX_PAYLOAD is 10
 *
 * Configurable using coap_session_set_max_payloads()
 */
#define COAP_DEFAULT_MAX_PAYLOADS (10U)

/**
 * The number of times for requests for re-transmission of missing Q-Block1
 * when no response has been received.
 * RFC9177 Section 6.2 Default value of NON_MAX_RETRANSMIT is 4
 *
 * Configurable using coap_session_set_non_max_retransmit()
 */
#define COAP_DEFAULT_NON_MAX_RETRANSMIT (4U)

/**
 * The delay (+ ACK_RANDOM_FACTOR) to introduce once NON MAX_PAYLOADS
 * Q-Block1 or Q-Block2 have been sent to reduce congestion control.
 * RFC9177 Section 6.2 Default value of NON_TIMEOUT is 2.
 *
 * Configurable using coap_session_set_non_timeout()
 */
#define COAP_DEFAULT_NON_TIMEOUT ((coap_fixed_point_t){2,0})

/**
 * The time to wait for any missing Q-Block1 or Q-Block2 packets before
 * requesting re-transmission of missing packets.
 * RFC9177 Section 6.2 Default value of NON_RECEIVE_TIMEOUT is 4.
 *
 * Configurable using coap_session_set_non_receive_timeout()
 */
#define COAP_DEFAULT_NON_RECEIVE_TIMEOUT ((coap_fixed_point_t){4,0})

/**
 * The MAX_LATENCY definition.
 * RFC 7252, Section 4.8.2 MAX_LATENCY is 100.
 */
#define COAP_DEFAULT_MAX_LATENCY (100U)

/**
* Set the CoAP initial ack response timeout before the next re-transmit
*
* Number of seconds when to expect an ACK or a response to an
* outstanding CON message.
* RFC7252 ACK_TIMEOUT
*
* @param session The CoAP session.
* @param value The value to set to. The default is 2.0 and should not normally
*              get changed.
*/
void coap_session_set_ack_timeout(coap_session_t *session,
                                  coap_fixed_point_t value);

/**
* Get the CoAP initial ack response timeout before the next re-transmit
*
* Number of seconds when to expect an ACK or a response to an
* outstanding CON message.
* RFC7252 ACK_TIMEOUT
*
* @param session The CoAP session.
*
* @return Current ack response timeout value
*/
coap_fixed_point_t coap_session_get_ack_timeout(const coap_session_t *session);

/**
* Set the CoAP ack randomize factor
*
* A factor that is used to randomize the wait time before a message
* is retransmitted to prevent synchronization effects.
* RFC7252 ACK_RANDOM_FACTOR
*
* @param session The CoAP session.
* @param value The value to set to. The default is 1.5 and should not normally
*              get changed.
*/
void coap_session_set_ack_random_factor(coap_session_t *session,
                                        coap_fixed_point_t value);

/**
* Get the CoAP ack randomize factor
*
* A factor that is used to randomize the wait time before a message
* is retransmitted to prevent synchronization effects.
* RFC7252 ACK_RANDOM_FACTOR
*
* @param session The CoAP session.
*
* @return Current ack randomize value
*/
coap_fixed_point_t coap_session_get_ack_random_factor(
    const coap_session_t *session);

/**
* Set the CoAP maximum retransmit count before failure
*
* Number of message retransmissions before message sending is stopped
* RFC7252 MAX_RETRANSMIT
*
* @param session The CoAP session.
* @param value The value to set to. The default is 4 and should not normally
*              get changed.
*/
void coap_session_set_max_retransmit(coap_session_t *session,
                                     uint16_t value);

/**
* Get the CoAP maximum retransmit before failure
*
* Number of message retransmissions before message sending is stopped
* RFC7252 MAX_RETRANSMIT
*
* @param session The CoAP session.
*
* @return Current maximum retransmit value
*/
uint16_t coap_session_get_max_retransmit(const coap_session_t *session);

/**
* Set the CoAP maximum concurrent transmission count of Confirmable messages
* RFC7252 NSTART
*
* @param session The CoAP session.
* @param value The value to set to. The default is 1 and should not normally
*              get changed.
*/
void coap_session_set_nstart(coap_session_t *session,
                             uint16_t value);

/**
* Get the CoAP maximum concurrent transmission count of Confirmable messages
* RFC7252 NSTART
*
* @param session The CoAP session.
*
* @return Current nstart value
*/
uint16_t coap_session_get_nstart(const coap_session_t *session);

/**
* Set the CoAP default leisure time (for multicast)
* RFC7252 DEFAULT_LEISURE
*
* @param session The CoAP session.
* @param value The value to set to. The default is 5.0 and should not normally
*              get changed.
*/
void coap_session_set_default_leisure(coap_session_t *session,
                                      coap_fixed_point_t value);

/**
* Get the CoAP default leisure time
* RFC7252 DEFAULT_LEISURE
*
* @param session The CoAP session.
*
* @return Current default_leisure value
*/
coap_fixed_point_t coap_session_get_default_leisure(
    const coap_session_t *session);

/**
* Set the CoAP probing rate when there is no response
* RFC7252 PROBING_RATE
*
* @param session The CoAP session.
* @param value The value to set to. The default is 1 and should not normally
*              get changed.
*/
void coap_session_set_probing_rate(coap_session_t *session, uint32_t value);

/**
* Get the CoAP probing rate when there is no response
* RFC7252 PROBING_RATE
*
* @param session The CoAP session.
*
* @return Current probing_rate value
*/
uint32_t coap_session_get_probing_rate(const coap_session_t *session);

/**
* Set the CoAP maximum payloads count of Q-Block1 or Q-Block2 before delay
* is introduced
* RFC9177 MAX_PAYLOADS
*
* @param session The CoAP session.
* @param value The value to set to. The default is 10 and should not normally
*              get changed.
*/
void coap_session_set_max_payloads(coap_session_t *session,
                                   uint16_t value);

/**
* Get the CoAP maximum payloads count of Q-Block1 or Q-Block2 before delay
* is introduced
* RFC9177 MAX_PAYLOADS
*
* @param session The CoAP session.
*
* @return Current maximum payloads value
*/
uint16_t coap_session_get_max_payloads(const coap_session_t *session);

/**
* Set the CoAP NON maximum retransmit count of missing Q-Block1 or Q-Block2
* requested before there is any response
* RFC9177 NON_MAX_RETRANSMIT
*
* @param session The CoAP session.
* @param value The value to set to. The default is 4 and should not normally
*              get changed.
*/
void coap_session_set_non_max_retransmit(coap_session_t *session,
                                         uint16_t value);

/**
* Get the CoAP NON maximum retransmit count of missing Q-Block1 or Q-Block2
* requested before there is any response
* RFC9177 NON_MAX_RETRANSMIT
*
* @param session The CoAP session.
*
* @return Current maximum NON max retransmit value
*/
uint16_t coap_session_get_non_max_retransmit(const coap_session_t *session);

/**
* Set the CoAP non timeout delay timeout
*
* Number of seconds to delay (+ ACK_RANDOM_FACTOR) before sending off the next
* set of NON MAX_PAYLOADS
* RFC9177 NON_TIMEOUT
*
* @param session The CoAP session.
* @param value The value to set to. The default is 2.0 and should not normally
*              get changed.
*/
void coap_session_set_non_timeout(coap_session_t *session,
                                  coap_fixed_point_t value);

/**
* Get the CoAP MAX_PAYLOADS limit delay timeout
*
* Number of seconds to delay (+ ACK_RANDOM_FACTOR) before sending off the next
* set of NON MAX_PAYLOADS
* RFC9177 NON_TIMEOUT
*
* @param session The CoAP session.
*
* @return NON MAX_PAYLOADS delay
*/
coap_fixed_point_t coap_session_get_non_timeout(const coap_session_t *session);

/**
* Set the CoAP non receive timeout delay timeout
*
* Number of seconds to delay before requesting missing packets
* RFC9177 NON_RECEIVE_TIMEOUT
*
* @param session The CoAP session.
* @param value The value to set to. The default is 4.0 and should not normally
*              get changed.  Must be 1 sec greater than NON_TIMEOUT_RANDOM
*/
void coap_session_set_non_receive_timeout(coap_session_t *session,
                                          coap_fixed_point_t value);

/**
* Get the CoAP non receive timeout delay timeout
*
* Number of seconds to delay before requesting missing packets
* RFC9177 NON_RECEIVE_TIMEOUT
*
* @param session The CoAP session.
*
* @return NON_RECEIVE_TIMEOUT delay
*/
coap_fixed_point_t coap_session_get_non_receive_timeout(
    const coap_session_t *session);

/** @} */
/**
 * Send a ping message for the session.
 * @param session The CoAP session.
 *
 * @return COAP_INVALID_MID if there is an error
 */
coap_mid_t coap_session_send_ping(coap_session_t *session);

/**
 * Disable client automatically sending observe cancel on session close
 *
 * @param session The CoAP session.
 */
void coap_session_set_no_observe_cancel(coap_session_t *session);

#endif  /* COAP_SESSION_H */
