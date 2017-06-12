/*
 * coap_dtls.h -- Datagram Transport Layer Support for libcoap
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef _COAP_DTLS_H_
#define _COAP_DTLS_H_

#include "net.h"
#include "pdu.h"

/**
 * @defgroup dtls DTLS Support
 * API functions for interfacing with DTLS libraries.
 * @{
 */

/**
 * The maximum expected size of a DTLS record. This constant is used
 * to allocate storage in the sendqueue for a DTLS session in case the
 * data cannot be sent immediately.
 */
#define COAP_DTLS_MAX_PACKET_SIZE COAP_MAX_PDU_SIZE

struct coap_dtls_context_t;
struct coap_dtls_session_t;

/** Returns 1 if support for DTLS is enabled, or 0 otherwise. */
int coap_dtls_is_supported(void);

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
struct coap_dtls_context_t *coap_dtls_new_context(struct coap_context_t *coap_context);

/** Releases the storage allocated for @p dtls_context. */
void coap_dtls_free_context(struct coap_dtls_context_t *dtls_context);

struct coap_dtls_session_t *
coap_dtls_new_session(struct coap_dtls_context_t *dtls_context,
                      const coap_endpoint_t *local_interface,
                      const coap_address_t *remote);

void coap_dtls_free_session(struct coap_dtls_context_t *dtls_context,
                            struct coap_dtls_session_t *session);

struct coap_dtls_session_t *
coap_dtls_get_session(struct coap_context_t *coap_context,
                      const coap_endpoint_t *local_interface,
                      const coap_address_t *dst);

int coap_dtls_send(struct coap_context_t *coap_context,
                   struct coap_dtls_session_t *session,
                   const coap_pdu_t *pdu);

int coap_dtls_handle_message(struct coap_context_t *coap_context,
                             const coap_endpoint_t *local_interface,
                             const coap_address_t *dst,
                             const unsigned char *data,
                             size_t data_len);

/** @} */

#endif /* COAP_DTLS_H */
