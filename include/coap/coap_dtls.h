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

#define COAP_TLS_LIBRARY_NOTLS 0
#define COAP_TLS_LIBRARY_TINYDTLS 1
#define COAP_TLS_LIBRARY_OPENSSL 2
#define COAP_TLS_LIBRARY_GNUTLS 3

typedef struct coap_tls_version_t {
  uint64_t version; /* Library Version */
  int type; /* One of COAP_TLS_LIBRARY_* */
} coap_tls_version_t;

/**
 * Returns the version and type of library libcoap was compiled against
 */
coap_tls_version_t *coap_get_tls_library_version(void);

/** Sets the log level to the specified value. */
void coap_dtls_set_log_level(int level);

/** Returns the current log level. */
int coap_dtls_get_log_level(void);

struct coap_dtls_pki_t;

/**
 * Security setup handler that is used as call-back in coap_context_set_pki()
 * Typically, this will be calling additonal functions like
 * SSL_CTX_set_tlsext_servername_callback() etc.
 *
 * @param context The security context definition - e.g. SSL_CTX * for OpenSSL. 
 *              This will be dependent on the underlying TLS library
 *              - see coap_get_tls_library_version()
 * @param setup_data A structure containing setup data originally passed into
 *                  coap_context_set_pki() or coap_new_client_session_pki().
 * @return 1 if successful, else 0
 */
typedef int (*coap_dtls_security_setup_t)(void *context,
                                        struct coap_dtls_pki_t *setup_data);

typedef enum coap_asn1_privatekey_type_t {
  COAP_ASN1_PKEY_NONE,
  COAP_ASN1_PKEY_RSA,
  COAP_ASN1_PKEY_RSA2,
  COAP_ASN1_PKEY_DSA,
  COAP_ASN1_PKEY_DSA1,
  COAP_ASN1_PKEY_DSA2,
  COAP_ASN1_PKEY_DSA3,
  COAP_ASN1_PKEY_DSA4,
  COAP_ASN1_PKEY_DH,
  COAP_ASN1_PKEY_DHX,
  COAP_ASN1_PKEY_EC,
  COAP_ASN1_PKEY_HMAC,
  COAP_ASN1_PKEY_CMAC,
  COAP_ASN1_PKEY_TLS1_PRF,
  COAP_ASN1_PKEY_HKDF
} coap_asn1_privatekey_type_t;

/** The structure used for defining the PKI setup data to be used */
typedef struct coap_dtls_pki_t {
  /* Optional CallBack for additional setup */
  coap_dtls_security_setup_t call_back;
  /* Alternative 1: Name of file on disk */
  const char *ca_file;
  const char *public_cert;
  const char *private_key;
  /* Alternative 2: ASN1 version */
  const uint8_t *asn1_ca_file;
  const uint8_t *asn1_public_cert;
  const uint8_t *asn1_private_key;
  int asn1_ca_file_len;
  int asn1_public_cert_len;
  int asn1_private_key_len;
  coap_asn1_privatekey_type_t asn1_private_key_type;
} coap_dtls_pki_t;

/**
 * Creates a new DTLS context for the given @p coap_context. This function
 * returns a pointer to a new DTLS context object or NULL on error.
 *
 * @param coap_context The CoAP context where the DTLS object shall be used.
 * @return A DTLS context object or NULL on error;
 */
void *
coap_dtls_new_context(struct coap_context_t *coap_context);

/**
 * Set the dtls context's default server PSK hint and/or key.
 * This does the PSK specifics for coap_dtls_new_context()
 *
 * @param ctx The CoAP context.
 * @param hint    The default PSK server hint sent to a client. If NULL, PSK
 *                authentication is disabled. Empty string is a valid hint.
 * @param key     The default PSK key. If NULL, PSK authentication will fail.
 * @param key_len The default PSK key's lenght. If 0, PSK authentication will
 *                fail.
 *
 * @return 1 if successful, else 0
 */

int coap_dtls_context_set_psk(struct coap_context_t *ctx, const char *hint,
                           const uint8_t *key, size_t key_len );

/**
 * Set the dtls context's default server PKI information.
 * This does the PKI specifics for coap_dtls_new_context()
 * The Callback is called to set up the appropriate information.
 *
 * @param ctx The CoAP context.
 * @param setup_data     If NULL, PKI authentication will fail. Certificate
 *                       information required.
 *
 * @return 1 if successful, else 0
 */

int coap_dtls_context_set_pki(struct coap_context_t *ctx,
                           coap_dtls_pki_t* setup_data);

/**
 * Check whether one of the coap_dtls_context_set_*() functions have been
 * called.
 *
 * @return 1 if coap_dtls_context_set_*() called, else 0
 */

int coap_dtls_context_check_keys_enabled(struct coap_context_t *ctx);

/** Releases the storage allocated for @p dtls_context. */
void coap_dtls_free_context(void *dtls_context);

/**
 * Create a new client-side session. This should send a HELLO to the server.
 *
 * @param session   The CoAP session
 * @return Opaque handle to underlying TLS library object containing security
 * parameters for the session.
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
