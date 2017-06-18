/*
* coap_tinydtls.c -- Datagram Transport Layer Support for libcoap with openssl
*
* Copyright (C) 2017 Jean-Claude Michelou <jcm@spinetix.com>
*
* This file is part of the CoAP library libcoap. Please see README for terms
* of use.
*/

#include "coap_config.h"

#ifdef HAVE_OPENSSL

#include "coap_dtls.h"
#include "mem.h"
#include "debug.h"
#include "prng.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

/* This structure encapsulates the OpenSSL context object. */
typedef struct coap_dtls_context_t {
  SSL_CTX *ctx;
  SSL *ssl;	/* OpenSSL object for listening to connection requests */
  HMAC_CTX *cookie_hmac;
  BIO_METHOD *meth;
  BIO_ADDR *bio_addr;
} coap_dtls_context_t;

int coap_dtls_is_supported( void ) {
  return 1;
}

static int dtls_log_level = 0;

void coap_dtls_set_log_level( int level ) {
  level = dtls_log_level;
}

int coap_dtls_get_log_level( void ) {
  return dtls_log_level;
}

typedef struct coap_ssl_st {
  coap_session_t *session;
  const void *pdu;
  unsigned pdu_len;
  unsigned mtu;
  unsigned peekmode;
} coap_ssl_data;

static int coap_dgram_create( BIO *a ) {
  coap_ssl_data *data = NULL;
  data = malloc( sizeof( coap_ssl_data ) );
  if ( data == NULL )
    return 0;
  BIO_set_init( a, 1 );
  BIO_set_data( a, data );
  memset( data, 0x00, sizeof( coap_ssl_data ) );
  data->mtu = 1280 - 40 - 8;
  return 1;
}

static int coap_dgram_destroy( BIO *a ) {
  coap_ssl_data *data;
  if ( a == NULL )
    return 0;
  data = (coap_ssl_data *)BIO_get_data( a );
  if ( data != NULL )
    free( data );
  return 1;
}

static int coap_dgram_read( BIO *a, char *out, int outl ) {
  int ret = 0;
  coap_ssl_data *data = (coap_ssl_data *)BIO_get_data( a );

  if ( out != NULL ) {
    if ( data != NULL && data->pdu_len > 0 ) {
      if ( outl < (int)data->pdu_len ) {
	memcpy( out, data->pdu, outl );
	ret = outl;
      } else {
	memcpy( out, data->pdu, data->pdu_len );
	ret = (int)data->pdu_len;
      }
      if ( !data->peekmode ) {
	data->pdu_len = 0;
	data->pdu = NULL;
      }
    } else {
      ret = -1;
    }
    BIO_clear_retry_flags( a );
    if ( ret < 0 )
      BIO_set_retry_read( a );
  }
  return ret;
}

static int coap_dgram_write( BIO *a, const char *in, int inl ) {
  int ret = 0;
  coap_ssl_data *data = (coap_ssl_data *)BIO_get_data( a );

  if ( data->session ) {
    ret = (int)coap_session_send( data->session, (unsigned char*)in, (size_t)inl );
    BIO_clear_retry_flags( a );
    if ( ret <= 0 )
      BIO_set_retry_write( a );
  } else {
    BIO_clear_retry_flags( a );
    ret = -1;
  }
  return ret;
}

static int coap_dgram_puts( BIO *a, const char *str ) {
  return coap_dgram_write( a, str, (int)strlen( str ) );
}

static const uint8_t in6_v4mapped[12] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff };

static long dgram_get_mtu_overhead( const coap_ssl_data *data ) {
  if ( data->session && data->session->remote_addr.addr.sa.sa_family == AF_INET6 && memcmp( &data->session->remote_addr.addr.sin6.sin6_addr, in6_v4mapped, sizeof( in6_v4mapped ) ) != 0 )
    return 48;
  return 28;
}

static long coap_dgram_ctrl( BIO *a, int cmd, long num, void *ptr ) {
  long ret = 1;
  struct sockaddr *to = NULL;
  coap_ssl_data *data = BIO_get_data( a );

  switch ( cmd ) {
  case BIO_CTRL_GET_CLOSE:
    ret = BIO_get_shutdown( a );
    break;
  case BIO_CTRL_SET_CLOSE:
    BIO_set_shutdown( a, (int)num );
    break;
    ret = 0;
    break;
  case BIO_CTRL_DGRAM_QUERY_MTU:
  case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
    ret = -dgram_get_mtu_overhead( data );
    if ( data->session && data->session->remote_addr.addr.sa.sa_family == AF_INET6 && memcmp( &data->session->remote_addr.addr.sin6.sin6_addr, in6_v4mapped, sizeof( in6_v4mapped ) ) != 0 )
      ret += 1280;
    else
      ret += 576;
    break;
  case BIO_CTRL_DGRAM_GET_MTU:
    return (long)data->mtu;
  case BIO_CTRL_DGRAM_SET_MTU:
    data->mtu = (unsigned)num;
    ret = num;
    break;
  case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
    ret = dgram_get_mtu_overhead( data );
    break;
  case BIO_CTRL_DGRAM_SET_PEEK_MODE:
    data->peekmode = (unsigned)num;
    break;
  case BIO_CTRL_DGRAM_CONNECT:
  case BIO_C_SET_FD:
  case BIO_C_GET_FD:
  case BIO_CTRL_DGRAM_SET_DONT_FRAG:
    ret = -1;
    break;
  case BIO_CTRL_DUP:
  case BIO_CTRL_FLUSH:
  case BIO_CTRL_DGRAM_MTU_DISCOVER:
  case BIO_CTRL_DGRAM_SET_CONNECTED:
  case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
    ret = 1;
    break;
  case BIO_CTRL_RESET:
  case BIO_C_FILE_SEEK:
  case BIO_C_FILE_TELL:
  case BIO_CTRL_INFO:
  case BIO_CTRL_PENDING:
  case BIO_CTRL_WPENDING:
  case BIO_CTRL_DGRAM_GET_PEER:
  case BIO_CTRL_DGRAM_SET_PEER:
  case BIO_CTRL_DGRAM_SET_RECV_TIMEOUT:
  case BIO_CTRL_DGRAM_GET_RECV_TIMEOUT:
  case BIO_CTRL_DGRAM_SET_SEND_TIMEOUT:
  case BIO_CTRL_DGRAM_GET_SEND_TIMEOUT:
  case BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP:
  case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
  case BIO_CTRL_DGRAM_MTU_EXCEEDED:
  default:
    ret = 0;
    break;
  }
  return ret;
}

static int coap_dtls_verify_cert( int ok, X509_STORE_CTX *ctx ) {
  if ( dtls_log_level <= LOG_WARNING )
    coap_log( LOG_WARNING, "cannot accept DTLS connection with certificate.\n" );
  return 0;	/* For now, trust no one */
}

static int coap_dtls_generate_cookie( SSL *ssl, unsigned char *cookie, unsigned int *cookie_len ) {
  coap_dtls_context_t *dtls = (coap_dtls_context_t *)SSL_CTX_get_app_data( SSL_get_SSL_CTX( ssl ) );
  coap_ssl_data *data = (coap_ssl_data*)BIO_get_data( SSL_get_rbio( ssl ) );
  int r = HMAC_Init_ex( dtls->cookie_hmac, NULL, 0, NULL, NULL );
  r &= HMAC_Update( dtls->cookie_hmac, (const uint8_t*)&data->session->local_addr.addr, (size_t)data->session->local_addr.size );
  r &= HMAC_Update( dtls->cookie_hmac, (const uint8_t*)&data->session->remote_addr.addr, (size_t)data->session->remote_addr.size );
  r &= HMAC_Final( dtls->cookie_hmac, cookie, cookie_len );
  return r;
}

static int coap_dtls_verify_cookie( SSL *ssl, const unsigned char *cookie, unsigned int cookie_len ) {
  uint8_t hmac[32];
  unsigned len = 32;
  if ( coap_dtls_generate_cookie( ssl, hmac, &len ) && cookie_len == len && memcmp( cookie, hmac, len ) == 0 )
    return 1;
  else
    return 0;
}

static unsigned coap_dtls_psk_client_callback( SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *buf, unsigned max_len ) {
  coap_ssl_data *data = (coap_ssl_data*)BIO_get_data( SSL_get_rbio( ssl ) );

  if ( !hint )
    hint = "";

  if ( dtls_log_level <= LOG_DEBUG )
    coap_log( LOG_DEBUG, "got psk_identity_hint: '%s'\n", hint );

  if ( data->session == NULL || data->session->context == NULL || data->session->context->get_client_psk == NULL )
    return 0;

  return data->session->context->get_client_psk( data->session, hint, identity, max_identity_len, buf, max_len );
}

static unsigned coap_dtls_psk_server_callback( SSL *ssl, const char *identity, unsigned char *buf, unsigned max_len ) {
  coap_ssl_data *data = (coap_ssl_data*)BIO_get_data( SSL_get_rbio( ssl ) );

  if ( dtls_log_level <= LOG_DEBUG )
    coap_log( LOG_DEBUG, "got psk_identity: '%s'\n", identity );

  if ( data->session == NULL || data->session->context == NULL || data->session->context->get_server_psk == NULL )
    return 0;

  return data->session->context->get_server_psk( data->session, identity, buf, max_len );
}

static void coap_dtls_info_callback( const SSL *ssl, int where, int ret ) {
  const char *str;
  int w = where &~ SSL_ST_MASK;

  if ( w & SSL_ST_CONNECT )
    str = "SSL_connect";
  else if ( w & SSL_ST_ACCEPT )
    str = "SSL_accept";
  else
    str = "undefined";

  if ( where & SSL_CB_LOOP ) {
    if ( dtls_log_level <= LOG_INFO )
      coap_log( LOG_INFO, "%s:%s\n", str, SSL_state_string_long( ssl ) );
  } else if ( where & SSL_CB_ALERT ) {
    str = ( where & SSL_CB_READ ) ? "read" : "write";
    if ( dtls_log_level <= LOG_WARNING )
      coap_log( LOG_WARNING, "SSL3 alert %s:%s:%s\n", str, SSL_alert_type_string_long( ret ), SSL_alert_desc_string_long( ret ) );
  } else if ( where & SSL_CB_EXIT ) {
    if ( ret == 0 ) {
      if ( dtls_log_level <= LOG_WARNING ) {
	long e;
	coap_log( LOG_WARNING, "%s:failed in %s\n", str, SSL_state_string_long( ssl ) );
	while ( ( e = ERR_get_error() ) )
	  coap_log( LOG_WARNING, "  %s at %s:%s\n", ERR_reason_error_string( e ), ERR_lib_error_string( e ), ERR_func_error_string( e ) );
      }
    } else if ( ret < 0 ) {
      if ( dtls_log_level <= LOG_WARNING ) {
	int err = SSL_get_error( ssl, ret );
	if ( err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_CONNECT && err != SSL_ERROR_WANT_ACCEPT && err != SSL_ERROR_WANT_X509_LOOKUP ) {
	  long e;
	  coap_log( LOG_WARNING, "%s:error in %s\n", str, SSL_state_string_long( ssl ) );
	  while ( ( e = ERR_get_error() ) )
	    coap_log( LOG_WARNING, "  %s at %s:%s\n", ERR_reason_error_string( e ), ERR_lib_error_string( e ), ERR_func_error_string( e ) );
	}
      }
    }
  }

  if ( where == SSL_CB_HANDSHAKE_START && SSL_get_state( ssl ) == TLS_ST_OK ) {
    coap_session_t *session = (coap_session_t *)SSL_get_app_data( ssl );
    if ( session && session->context )
      coap_handle_event( session->context, COAP_EVENT_DTLS_RENEGOTIATE, session );
  }
}

static int ssl_library_loaded = 0;

struct coap_dtls_context_t *coap_dtls_new_context( struct coap_context_t *coap_context ) {
  struct coap_dtls_context_t *context;

  if ( !ssl_library_loaded ) {
    SSL_load_error_strings();
    SSL_library_init();
    ssl_library_loaded = 1;
  }

  context = ( struct coap_dtls_context_t * )coap_malloc( sizeof( struct coap_dtls_context_t ) );
  if ( context ) {
    BIO *bio;
    uint8_t cookie_secret[32];
    memset( context, 0, sizeof( struct coap_dtls_context_t ) );
    context->ctx = SSL_CTX_new( DTLSv1_2_method() );
    if ( !context->ctx )
      goto error;
    SSL_CTX_set_app_data( context->ctx, context );
    SSL_CTX_set_read_ahead( context->ctx, 1 );
    SSL_CTX_set_cipher_list( context->ctx, "TLSv1.2:TLSv1.0" );
    if ( !RAND_bytes( cookie_secret, ( int )sizeof( cookie_secret ) ) ) {
      if ( dtls_log_level <= LOG_WARNING )
	coap_log( LOG_WARNING, "Insufficient entropy for random cookie generation" );
      prng( cookie_secret, sizeof( cookie_secret ) );
    }
    context->cookie_hmac = HMAC_CTX_new();
    if ( !HMAC_Init_ex( context->cookie_hmac, cookie_secret, ( int )sizeof( cookie_secret ), EVP_sha256(), NULL ) )
      goto error;
    /*SSL_CTX_set_verify( context->ctx, SSL_VERIFY_PEER, coap_dtls_verify_cert );*/
    SSL_CTX_set_cookie_generate_cb( context->ctx, coap_dtls_generate_cookie );
    SSL_CTX_set_cookie_verify_cb( context->ctx, coap_dtls_verify_cookie );
    SSL_CTX_set_info_callback( context->ctx, coap_dtls_info_callback );
    SSL_CTX_set_psk_client_callback( context->ctx, coap_dtls_psk_client_callback );
    SSL_CTX_set_psk_server_callback( context->ctx, coap_dtls_psk_server_callback );
    SSL_CTX_use_psk_identity_hint( context->ctx, "" );
    context->meth = BIO_meth_new( BIO_TYPE_DGRAM, "coapdgram" );
    if ( !context->meth )
      goto error;
    context->bio_addr = BIO_ADDR_new();
    if ( !context->bio_addr )
      goto error;
    BIO_meth_set_write( context->meth, coap_dgram_write );
    BIO_meth_set_read( context->meth, coap_dgram_read );
    BIO_meth_set_puts( context->meth, coap_dgram_puts );
    BIO_meth_set_ctrl( context->meth, coap_dgram_ctrl );
    BIO_meth_set_create( context->meth, coap_dgram_create );
    BIO_meth_set_destroy( context->meth, coap_dgram_destroy );
    context->ssl = SSL_new( context->ctx );
    if ( !context->ssl )
      goto error;
    bio = BIO_new( context->meth );
    if ( !bio )
      goto error;
    SSL_set_bio( context->ssl, bio, bio );
    SSL_set_app_data( context->ssl, NULL );
    SSL_set_options( context->ssl, SSL_OP_COOKIE_EXCHANGE );
  }

  return context;

error:
  coap_dtls_free_context( context );
  return NULL;
}

void coap_dtls_free_context( struct coap_dtls_context_t *context ) {
  if ( context->ssl )
    SSL_free( context->ssl );
  if ( context->ctx )
    SSL_CTX_free( context->ctx );
  if ( context->cookie_hmac )
    HMAC_CTX_free( context->cookie_hmac );
  if ( context->meth )
    BIO_meth_free( context->meth );
  if ( context->bio_addr )
    BIO_ADDR_free( context->bio_addr );
  coap_free( context );
}

void * coap_dtls_new_server_session( coap_session_t *session ) {
  BIO *nbio = NULL;
  SSL *nssl = NULL, *ssl = NULL;
  coap_ssl_data *data;
  coap_dtls_context_t *dtls = session->context->dtls_context;
  int r;

  nssl = SSL_new( dtls->ctx );
  if ( !nssl )
    goto error;
  nbio = BIO_new( dtls->meth );
  if ( !nbio )
    goto error;
  SSL_set_bio( nssl, nbio, nbio );
  SSL_set_app_data( nssl, NULL );
  SSL_set_options( nssl, SSL_OP_COOKIE_EXCHANGE );
  ssl = dtls->ssl;
  dtls->ssl = nssl;
  nssl = NULL;
  SSL_set_app_data( ssl, session );

  data = (coap_ssl_data*)BIO_get_data( SSL_get_rbio( ssl ) );
  data->session = session;

  if ( session->context->get_server_hint ) {
    char hint[128] = "";
    if ( session->context->get_server_hint( session, hint, sizeof( hint ) ) )
      SSL_use_psk_identity_hint( ssl, hint );
  }

  r = SSL_accept( ssl );
  if ( r == -1 ) {
    int err = SSL_get_error( ssl, r );
    if ( err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE )
      r = 0;
  }

  if ( r == 0 ) {
    SSL_free( ssl );
    return NULL;
  }

  return ssl;

error:
  if ( nssl )
    SSL_free( nssl );
  return NULL;
}

void *coap_dtls_new_client_session( coap_session_t *session ) {
  BIO *bio = NULL;
  SSL *ssl = NULL;
  coap_ssl_data *data;
  int r;
  coap_dtls_context_t *dtls = session->context->dtls_context;

  ssl = SSL_new( dtls->ctx );
  if ( !ssl )
    goto error;
  bio = BIO_new( dtls->meth );
  if ( !bio )
    goto error;
  data = (coap_ssl_data *)BIO_get_data( bio );
  data->session = session;
  SSL_set_bio( ssl, bio, bio );
  SSL_set_app_data( ssl, session );
  SSL_set_options( ssl, SSL_OP_COOKIE_EXCHANGE );

  r = SSL_connect( ssl );
  if ( r == -1 ) {
    int ret = SSL_get_error( ssl, r );
    if ( ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE )
      r = 0;
  }

  if ( r == 0 )
    goto error;

  return ssl;

error:
  if ( ssl )
    SSL_free( ssl );
  return NULL;
}

void coap_dtls_free_session( coap_session_t *session ) {
  SSL *ssl = (SSL *)session->tls;
  if ( ssl ) {
    if ( !( SSL_get_shutdown( ssl ) & SSL_SENT_SHUTDOWN ) )
      SSL_shutdown( ssl );
    SSL_free( ssl );
  }
}

int coap_dtls_send( coap_session_t *session,
                    const uint8_t *data, size_t data_len )
{
  int r;
  SSL *ssl = (SSL *)session->tls;

  assert( ssl != NULL );

  r = SSL_write( ssl, data, (int)data_len );

  if ( r <= 0 ) {
    int err = SSL_get_error( ssl, r );
    if ( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) {
      r = 0;
    } else {
      if ( dtls_log_level <= LOG_WARNING )
	coap_log( LOG_WARNING, "coap_dtls_send: cannot send PDU\n" );
      if ( r == SSL_ERROR_ZERO_RETURN ) {
	coap_handle_event( session->context, COAP_EVENT_DTLS_CLOSED, session );
	coap_session_disconnected( session );
      } else {
	coap_handle_event( session->context, COAP_EVENT_DTLS_ERROR, session );
      }
      r = -1;
    }
  }

  return r;
}

int coap_dtls_hello( coap_session_t *session,
                     const uint8_t *data, size_t data_len )
{
  struct coap_dtls_context_t *ctx = session->context->dtls_context;
  coap_ssl_data *ssl_data;
  int r;

  ssl_data = (coap_ssl_data*)BIO_get_data( SSL_get_rbio( ctx->ssl ) );
  ssl_data->session = session;
  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;
  r = DTLSv1_listen( ctx->ssl, ctx->bio_addr );
  if ( r <= 0 ) {
    int err = SSL_get_error( ctx->ssl, r );
    if ( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) {
      /* Got a ClientHello, sent-out a VerifyRequest */
      r = 0;
    }
  } else {
    /* Got a valid answer to a VerifyRequest */
    r = 1;
  }

  return r;
}

int coap_dtls_receive( coap_session_t *session,
                       const uint8_t *data, size_t data_len )
{
  coap_ssl_data *ssl_data;
  SSL *ssl = (SSL *)session->tls;
  int r;

  assert( ssl != NULL );

  int in_init = SSL_in_init( ssl );
  uint8_t pdu[COAP_MAX_PDU_SIZE];
  ssl_data = (coap_ssl_data*)BIO_get_data( SSL_get_rbio( ssl ) );
  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;

  r = SSL_read( ssl, pdu, COAP_MAX_PDU_SIZE );
  if ( r > 0 ) {
    return coap_handle_message( session->context, session, pdu, (size_t)r );
  } else {
    int err = SSL_get_error( ssl, r );
    if ( err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ) {
      if ( in_init && SSL_is_init_finished( ssl ) ) {
	coap_handle_event( session->context, COAP_EVENT_DTLS_CONNECTED, session );
	coap_session_connected( session );
      }
      r = 0;
    } else if ( err == SSL_ERROR_ZERO_RETURN ) {
      /* Got a close notify alert from the remote side */
      SSL_shutdown( ssl );
      coap_handle_event( session->context, COAP_EVENT_DTLS_CLOSED, session );
      coap_session_disconnected( session );
      r = -1;
    } else {
      coap_handle_event( session->context, COAP_EVENT_DTLS_ERROR, session );
      r = -1;
    }
  }

  return r;
}

#endif /* HAVE_OPENSSL */
