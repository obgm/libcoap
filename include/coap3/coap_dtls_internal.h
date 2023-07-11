/*
 * coap_dtls_internal.h -- (Datagram) Transport Layer Support for libcoap
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2017 Jean-Claude Michelou <jcm@spinetix.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_dtls_internal.h
 * @brief Internal CoAP DTLS support
 */

#ifndef COAP_DTLS_INTERNAL_H_
#define COAP_DTLS_INTERNAL_H_

#include "coap_internal.h"

/**
 * @ingroup internal_api
 * @defgroup dtls_internal DTLS Support
 * Internal API for DTLS Support
 * @{
 */

/* https://rfc-editor.org/rfc/rfc6347#section-4.2.4.1 */
#ifndef COAP_DTLS_RETRANSMIT_MS
#define COAP_DTLS_RETRANSMIT_MS 1000
#endif
#ifndef COAP_DTLS_RETRANSMIT_TOTAL_MS
#define COAP_DTLS_RETRANSMIT_TOTAL_MS 60000
#endif

#define COAP_DTLS_RETRANSMIT_COAP_TICKS (COAP_DTLS_RETRANSMIT_MS * COAP_TICKS_PER_SECOND / 1000)

/* For RFC9146 Connection ID support */
#ifndef COAP_DTLS_CID_LENGTH
#define COAP_DTLS_CID_LENGTH 6
#endif

/**
 * Creates a new DTLS context for the given @p coap_context. This function
 * returns a pointer to a new DTLS context object or @c NULL on error.
 *
 * @param coap_context The CoAP context where the DTLS object shall be used.
 *
 * @return A DTLS context object or @c NULL on error.
 */
void *coap_dtls_new_context(coap_context_t *coap_context);

#if COAP_SERVER_SUPPORT
/**
 * Set the DTLS context's default server PSK information.
 * This does the PSK specifics following coap_dtls_new_context().
 *
 * @param coap_context The CoAP context.
 * @param setup_data A structure containing setup data originally passed into
 *                   coap_context_set_psk2().
 *
 * @return @c 1 if successful, else @c 0.
 */

int coap_dtls_context_set_spsk(coap_context_t *coap_context,
                               coap_dtls_spsk_t *setup_data);
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
/**
 * Set the DTLS context's default client PSK information.
 * This does the PSK specifics following coap_dtls_new_context().
 *
 * @param coap_context The CoAP context.
 * @param setup_data A structure containing setup data originally passed into
 *                   coap_new_client_session_psk2().
 *
 * @return @c 1 if successful, else @c 0.
 */

int coap_dtls_context_set_cpsk(coap_context_t *coap_context,
                               coap_dtls_cpsk_t *setup_data);
#endif /* COAP_CLIENT_SUPPORT */

/**
 * Set the DTLS context's default server PKI information.
 * This does the PKI specifics following coap_dtls_new_context().
 * If @p COAP_DTLS_ROLE_SERVER, then the information will get put into the
 * TLS library's context (from which sessions are derived).
 * If @p COAP_DTLS_ROLE_CLIENT, then the information will get put into the
 * TLS library's session.
 *
 * @param coap_context The CoAP context.
 * @param setup_data     Setup information defining how PKI is to be setup.
 *                       Required parameter.  If @p NULL, PKI will not be
 *                       set up.
 * @param role  One of @p COAP_DTLS_ROLE_CLIENT or @p COAP_DTLS_ROLE_SERVER
 *
 * @return @c 1 if successful, else @c 0.
 */

int coap_dtls_context_set_pki(coap_context_t *coap_context,
                              const coap_dtls_pki_t *setup_data,
                              const coap_dtls_role_t role);

/**
 * Set the dtls context's default Root CA information for a client or server.
 *
 * @param coap_context   The current coap_context_t object.
 * @param ca_file        If not @p NULL, is the full path name of a PEM encoded
 *                       file containing all the Root CAs to be used.
 * @param ca_dir         If not @p NULL, points to a directory containing PEM
 *                       encoded files containing all the Root CAs to be used.
 *
 * @return @c 1 if successful, else @c 0.
 */

int coap_dtls_context_set_pki_root_cas(coap_context_t *coap_context,
                                       const char *ca_file,
                                       const char *ca_dir);

/**
 * Check whether one of the coap_dtls_context_set_{psk|pki}() functions have
 * been called.
 *
 * @param coap_context The current coap_context_t object.
 *
 * @return @c 1 if coap_dtls_context_set_{psk|pki}() called, else @c 0.
 */

int coap_dtls_context_check_keys_enabled(coap_context_t *coap_context);

/**
 * Releases the storage allocated for @p dtls_context.
 *
 * @param dtls_context The DTLS context as returned by coap_dtls_new_context().
 */
void coap_dtls_free_context(void *dtls_context);

#if COAP_CLIENT_SUPPORT
/**
 * Create a new client-side session. This should send a HELLO to the server.
 *
 * @param coap_session   The CoAP session.
 *
 * @return Opaque handle to underlying TLS library object containing security
 *         parameters for the session.
*/
void *coap_dtls_new_client_session(coap_session_t *coap_session);
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
/**
 * Create a new DTLS server-side session.
 * Called after coap_dtls_hello() has returned @c 1, signalling that a validated
 * HELLO was received from a client.
 * This should send a HELLO to the server.
 *
 * @param coap_session   The CoAP session.
 *
 * @return Opaque handle to underlying TLS library object containing security
 *         parameters for the DTLS session.
 */
void *coap_dtls_new_server_session(coap_session_t *coap_session);
#endif /* COAP_SERVER_SUPPORT */

/**
 * Terminates the DTLS session (may send an ALERT if necessary) then frees the
 * underlying TLS library object containing security parameters for the session.
 *
 * @param coap_session   The CoAP session.
 */
void coap_dtls_free_session(coap_session_t *coap_session);

/**
 * Notify of a change in the CoAP session's MTU, for example after
 * a PMTU update.
 *
 * @param coap_session   The CoAP session.
 */
void coap_dtls_session_update_mtu(coap_session_t *coap_session);

/**
 * Send data to a DTLS peer.
 *
 * @param coap_session The CoAP session.
 * @param data      pointer to data.
 * @param data_len  Number of bytes to send.
 *
 * @return @c 0 if this would be blocking, @c -1 if there is an error or the
 *         number of cleartext bytes sent.
 */
ssize_t coap_dtls_send(coap_session_t *coap_session,
                       const uint8_t *data,
                       size_t data_len);

/**
 * Check if timeout is handled per CoAP session or per CoAP context.
 *
 * @return @c 1 of timeout and retransmit is per context, @c 0 if it is
 *         per session.
 */
int coap_dtls_is_context_timeout(void);

/**
 * Do all pending retransmits and get next timeout
 *
 * @param dtls_context The DTLS context.
 *
 * @return @c 0 if no event is pending or date of the next retransmit.
 */
coap_tick_t coap_dtls_get_context_timeout(void *dtls_context);

/**
 * Get next timeout for this session.
 *
 * @param coap_session The CoAP session.
 * @param now The current time in ticks.
 *
 * @return @c 0 If no event is pending or ticks time of the next retransmit.
 */
coap_tick_t coap_dtls_get_timeout(coap_session_t *coap_session,
                                  coap_tick_t now);

/**
 * Handle a DTLS timeout expiration.
 *
 * @param coap_session The CoAP session.
 *
 * @return @c 1 timed out or @c 0 still timing out
 */
int coap_dtls_handle_timeout(coap_session_t *coap_session);

/**
 * Handling incoming data from a DTLS peer.
 *
 * @param coap_session The CoAP session.
 * @param data      Encrypted datagram.
 * @param data_len  Encrypted datagram size.
 *
 * @return Result of coap_handle_dgram on the decrypted CoAP PDU
 *         or @c -1 for error.
 */
int coap_dtls_receive(coap_session_t *coap_session,
                      const uint8_t *data,
                      size_t data_len);

#if COAP_SERVER_SUPPORT
/**
 * Handling client HELLO messages from a new candiate peer.
 * Note that session->tls is empty.
 *
 * @param coap_session The CoAP session.
 * @param data      Encrypted datagram.
 * @param data_len  Encrypted datagram size.
 *
 * @return @c 0 if a cookie verification message has been sent, @c 1 if the
 *        HELLO contains a valid cookie and a server session should be created,
 *        @c -1 if the message is invalid.
 */
int coap_dtls_hello(coap_session_t *coap_session,
                    const uint8_t *data,
                    size_t data_len);
#endif /* COAP_SERVER_SUPPORT */

/**
 * Layer function interface for layer below DTLS connect being
 * established.
 *
 * If this layer is properly established on invocation, then the next layer
 * must get called by calling
 *   session->lfunc[COAP_LAYER_TLS].establish(session)
 * (or done at any point when DTLS is established).
 *
 * @param session Session that the lower layer connect was done on.
 *
 */
void coap_dtls_establish(coap_session_t *session);

/**
 * Layer function interface for DTLS close for a session.
 *
 * @param session  Session to do the DTLS close on.
 */
void coap_dtls_close(coap_session_t *session);

/**
 * Get DTLS overhead over cleartext PDUs.
 *
 * @param coap_session The CoAP session.
 *
 * @return Maximum number of bytes added by DTLS layer.
 */
unsigned int coap_dtls_get_overhead(coap_session_t *coap_session);

#if COAP_CLIENT_SUPPORT
/**
 * Create a new TLS client-side session.
 *
 * @param coap_session The CoAP session.
 *
 * @return Opaque handle to underlying TLS library object containing security
 *         parameters for the session.
*/
void *coap_tls_new_client_session(coap_session_t *coap_session);
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
/**
 * Create a TLS new server-side session.
 *
 * @param coap_session The CoAP session.
 *
 * @return Opaque handle to underlying TLS library object containing security
 *         parameters for the session.
 */
void *coap_tls_new_server_session(coap_session_t *coap_session);
#endif /* COAP_SERVER_SUPPORT */

/**
 * Terminates the TLS session (may send an ALERT if necessary) then frees the
 * underlying TLS library object containing security parameters for the session.
 *
 * @param coap_session The CoAP session.
 */
void coap_tls_free_session(coap_session_t *coap_session);

/**
 * Send data to a TLS peer, with implicit flush.
 *
 * @param coap_session The CoAP session.
 * @param data      Pointer to data.
 * @param data_len  Number of bytes to send.
 *
 * @return          @c 0 if this should be retried, @c -1 if there is an error
 *                  or the number of cleartext bytes sent.
 */
ssize_t coap_tls_write(coap_session_t *coap_session,
                       const uint8_t *data,
                       size_t data_len
                      );

/**
 * Read some data from a TLS peer.
 *
 * @param coap_session The CoAP session.
 * @param data      Pointer to data.
 * @param data_len  Maximum number of bytes to read.
 *
 * @return          @c 0 if this should be retried, @c -1 if there is an error
 *                  or the number of cleartext bytes read.
 */
ssize_t coap_tls_read(coap_session_t *coap_session,
                      uint8_t *data,
                      size_t data_len
                     );

/**
 * Layer function interface for layer below TLS accept/connect being
 *  established. This function initiates an accept/connect at the TLS layer.
 *
 * If this layer is properly established on invocation, then the next layer
 * must get called by calling
 *   session->lfunc[COAP_LAYER_TLS].establish(session)
 * (or done at any point when TLS is established).
 *
 * @param session Session that the lower layer accept/connect was done on.
 *
 */
void coap_tls_establish(coap_session_t *session);

/**
 * Layer function interface for TLS close for a session.
 *
 * @param session  Session to do the TLS close on.
 */
void coap_tls_close(coap_session_t *session);

/**
 * Get the current client's PSK key.
 *
 * @param coap_session The CoAP session.
 *
 * @return          @c NULL if no key, else a pointer the current key.
 */
const coap_bin_const_t *coap_get_session_client_psk_key(
    const coap_session_t *coap_session);

/**
 * Get the current client's PSK identity.
 *
 * @param coap_session The CoAP session.
 *
 * @return          @c NULL if no identity, else a pointer the current identity.
 */
const coap_bin_const_t *coap_get_session_client_psk_identity(
    const coap_session_t *coap_session);

/**
 * Get the current server's PSK key.
 *
 * @param coap_session The CoAP session.
 *
 * @return          @c NULL if no key, else a pointer the current key.
 */
const coap_bin_const_t *coap_get_session_server_psk_key(
    const coap_session_t *coap_session);

/**
 * Get the current server's PSK identity hint.
 *
 * @param coap_session The CoAP session.
 *
 * @return          @c NULL if no hint, else a pointer the current hint.
 */
const coap_bin_const_t *coap_get_session_server_psk_hint(
    const coap_session_t *coap_session);

/**
 * Initialize the underlying (D)TLS Library layer.
 *
 */
void coap_dtls_startup(void);

/**
 * Close down the underlying (D)TLS Library layer.
 *
 */
void coap_dtls_shutdown(void);

/**
 * Get the actual (D)TLS object for the session.
 *
 * @param session The session.
 * @param tls_lib Updated with the library type.
 *
 * @return The TLS information.
 */
void *coap_dtls_get_tls(const coap_session_t *session,
                        coap_tls_library_t *tls_lib);

/** @} */

#endif /* COAP_DTLS_INTERNAL_H */
