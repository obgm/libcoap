/*
 * coap_dtls.h -- (Datagram) Transport Layer Support for libcoap
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2017 Jean-Claude Michelou <jcm@spinetix.com>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef _COAP_DTLS_H_
#define _COAP_DTLS_H_

#include "net.h"
#include "coap_session.h"
#include "pdu.h"

/**
 * @defgroup dtls DTLS Support
 * API functions for interfacing with DTLS libraries.
 * @{
 */

/** Returns 1 if support for DTLS is enabled, or 0 otherwise. */
int coap_dtls_is_supported(void);

/** Returns 1 if support for TLS is enabled, or 0 otherwise. */
int coap_tls_is_supported( void );

/** Sets the log level to the specified value. */
void coap_dtls_set_log_level(int level);

/** Returns the current log level. */
int coap_dtls_get_log_level(void);

/**
 * Creates a new DTLS context for the given @p coap_context. This function
 * returns a pointer to a new DTLS context object or NULL on error.
 *
 * @param coap_context The CoAP context where the DTLS object shall be used.
 * @return A DTLS context object or NULL on error;
 */
void *
coap_dtls_new_context(struct coap_context_t *coap_context);

/** Releases the storage allocated for @p dtls_context. */
void coap_dtls_free_context(void *dtls_context);

/**
 * Create a new client-side session. This should send a HELLO to the server.
 *
 * @param session   The CoAP session
 * @return Opaque handle to underlying TLS library object containing security parameters for the session.
*/
void *coap_dtls_new_client_session(coap_session_t *session);

/**
* Create a new server-side session.
* Called after coap_dtls_hello() has returned 1, signalling that a validated HELLO was received from a client.
* This should send a HELLO to the server.
*
* @param session   The CoAP session
* @return Opaque handle to underlying TLS library object containing security parameters for the session.
*/
void *coap_dtls_new_server_session(coap_session_t *session);

/**
 * Terminates the DTLS session (may send an ALERT if necessary) then frees the underlying TLS library object containing security parameters for the session.
 *
 * @param session   The CoAP session
 */
void coap_dtls_free_session(coap_session_t *session);

/**
 * Notify of a change in the session's MTU, e.g. after a PMTU update.
 *
 * @param session   The CoAP session
 */
void coap_dtls_session_update_mtu(coap_session_t *session);

/**
 * Send data to a DTLS peer.
 *
 * @param session   The CoAP session
 * @param data      pointer to data
 * @param size      number of bytes to send
 * @return 0 if this would be blocking, -1 if there is an error or the number of cleartext bytes sent
 */
int coap_dtls_send(coap_session_t *session,
                   const uint8_t *data,
                   size_t data_len);

/**
* Check if timeout is handled per session or per context.
*
* @param dtls_context The DTLS context
* @return 1 of timeout and retransmit is per context, 0 if it is per session.
*/
int coap_dtls_is_context_timeout(void);

/**
 * Do all pending retransmits and get next timeout
 * 
 * @param dtls_context The DTLS context
 * @return 0 If no event is pending or date of the next retransmit.
 */
coap_tick_t coap_dtls_get_context_timeout(void *dtls_context);

/**
 * Get next timeout for this session.
 *
 * @param session The CoAP session
 * @return 0 If no event is pending or date of the next retransmit.
 */
coap_tick_t coap_dtls_get_timeout(coap_session_t *session);

/**
 * Handle a DTLS timeout expiration.
 *
 * @param session The CoAP session
 */
void coap_dtls_handle_timeout(coap_session_t *session);

/**
* Handling incoming data from a DTLS peer.
*
* @param session   The CoAP session
* @param data      Encrypted datagram
* @param data_len  Encrypted datagram size
* @return result of coap_handle_dgram on the decrypted CoAP PDU or -1 for error.
*/
int coap_dtls_receive(coap_session_t *session,
                      const uint8_t *data,
                      size_t data_len);

/**
* Handling client HELLO messages from a new candiate peer.
* Note that session->tls is empty.
*
* @param session   The CoAP session
* @param data      Encrypted datagram
* @param data_len  Encrypted datagram size
* @return 0 if a cookie verification message has been sent, 1 if the HELLO contains a valid cookie and a server session should be created, -1 if the message is invalid.
*/
int coap_dtls_hello(coap_session_t *session,
                    const uint8_t *data,
                    size_t data_len);

/**
 * Get DTLS overhead over cleartext PDUs.
 *
 * @param session   The CoAP session
 * @return maximum number of bytes added by DTLS layer.
 */

unsigned int coap_dtls_get_overhead(coap_session_t *session);

/**
 * Create a new client-side session.
 *
 * @param session   The CoAP session
 * @return Opaque handle to underlying TLS library object containing security parameters for the session.
*/
void *coap_tls_new_client_session(coap_session_t *session, int *connected);

/**
* Create a new server-side session.
*
* @param session   The CoAP session
* @return Opaque handle to underlying TLS library object containing security parameters for the session.
*/
void *coap_tls_new_server_session(coap_session_t *session, int *connected);

/**
* Terminates the TLS session (may send an ALERT if necessary) then frees the
* underlying TLS library object containing security parameters for the session.
*
* @param session   The CoAP session
*/
void coap_tls_free_session( coap_session_t *session );

/**
 * Send data to a TLS peer, with implicit flush.
 *
 * @param session   The CoAP session
 * @param data      pointer to data
 * @param size      number of bytes to send
 * @return          0 if this should be retried, -1 if there is an error or
 *                  the number of cleartext bytes sent.
 */
ssize_t coap_tls_write(coap_session_t *session,
                       const uint8_t *data,
                       size_t data_len
                       );
  
/**
 * Read some data from a TLS peer.
 *
 * @param session   The CoAP session
 * @param data      pointer to data
 * @param size      maximum number of bytes to read
 * @return          0 if this should be retried, -1 if there is an error or
 *                  the number of cleartext bytes read.
 */
ssize_t coap_tls_read(coap_session_t *session,
                      uint8_t *data,
                      size_t data_len
                      );

/** @} */

void coap_dtls_startup( void );

#endif /* COAP_DTLS_H */
