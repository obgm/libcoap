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

void coap_dtls_startup( void ) {
}

void
coap_dtls_set_log_level( int level ) {
  dtls_log_level = level;
}

int
coap_dtls_get_log_level( void ) {
  return dtls_log_level;
}

void *
coap_dtls_new_context( struct coap_context_t *coap_context UNUSED ) {
  return NULL;
}

void
coap_dtls_free_context( void *handle UNUSED ) {
}

void *coap_dtls_new_server_session( coap_session_t *session UNUSED ) {
  return NULL;
}

void *coap_dtls_new_client_session( coap_session_t *session UNUSED ) {
  return NULL;
}

void
coap_dtls_free_session( coap_session_t *coap_session UNUSED ) {
}

int
coap_dtls_send( coap_session_t *session UNUSED,
  const uint8_t *data UNUSED,
  size_t data_len UNUSED
) {
  return -1;
}

int coap_dtls_get_context_timeout( void *dtls_context UNUSED ) {
  return -1;
}

int coap_dtls_get_timeout( coap_session_t *session UNUSED ) {
  return -1;
}

void coap_dtls_handle_timeout( coap_session_t *session UNUSED ) {
  return 0;
}

int
coap_dtls_receive( coap_session_t *session UNUSED,
  const uint8_t *data UNUSED,
  size_t data_len UNUSED
) {
  return -1;
}

int
coap_dtls_hello( coap_session_t *session UNUSED,
  const uint8_t *data UNUSED,
  size_t data_len UNUSED
) {
  return 0;
}

#undef UNUSED

#endif /* !HAVE_LIBTINYDTLS && !HAVE_OPENSSL */
