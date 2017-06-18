/*
* coap_notls.c -- Stub Datagram Transport Layer Support for libcoap
*
* Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
*
* This file is part of the CoAP library libcoap. Please see README for terms
* of use.
*/

#include "coap_config.h"

#if !defined(HAVE_LIBTINYDTLS) && !defined(HAVE_OPENSSL)

#include "coap_dtls.h"

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else /* __GNUC__ */
#define UNUSED
#endif /* __GNUC__ */

int
coap_dtls_is_supported( void ) {
  return 0;
}

static int dtls_log_level = 0;

void
coap_dtls_set_log_level( int level ) {
  dtls_log_level = level;
}

int
coap_dtls_get_log_level( void ) {
  return dtls_log_level;
}

struct coap_dtls_context_t *
  coap_dtls_new_context( struct coap_context_t *coap_context UNUSED ) {
  return NULL;
}

void
coap_dtls_free_context( struct coap_dtls_context_t *dtls_context ) {
}

struct coap_dtls_session_t *
  coap_dtls_get_session( struct coap_context_t *coap_context UNUSED,
    const coap_endpoint_t *local_interface UNUSED,
    const coap_address_t *dst UNUSED ) {
  return NULL;
}

int
coap_dtls_send( struct coap_context_t *coap_context,
  struct coap_dtls_session_t *session,
  const coap_pdu_t *pdu ) {
  return -1;
}

struct coap_dtls_session_t *
  coap_dtls_new_session( struct coap_dtls_context_t *dtls_context,
    const coap_endpoint_t *local_interface,
    const coap_address_t *remote ) {
  return NULL;
}

struct coap_dtls_session_t;
void
coap_dtls_free_session( struct coap_dtls_context_t *dtls_context,
  struct coap_dtls_session_t *session ) {
}

int
coap_dtls_handle_message( struct coap_context_t *coap_context UNUSED,
  coap_session_t *session UNUSED,
  const unsigned char *data UNUSED,
  size_t data_len UNUSED ) {
  return -1;
}

#undef UNUSED

#endif /* !HAVE_LIBTINYDTLS && !HAVE_OPENSSL */
