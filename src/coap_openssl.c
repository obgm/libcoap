/*
* coap_openssl.c -- Datagram Transport Layer Support for libcoap with openssl
*
* Copyright (C) 2017 Jean-Claude Michelou <jcm@spinetix.com>
*
* This file is part of the CoAP library libcoap. Please see README for terms
* of use.
*/

#include "coap_config.h"

#ifdef HAVE_OPENSSL

#include "net.h"
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

typedef struct coap_tls_context_t {
  SSL_CTX *ctx;
  BIO_METHOD *meth;
} coap_tls_context_t;

typedef struct coap_openssl_context_t {
  coap_dtls_context_t dtls;
  coap_tls_context_t tls;
  int psk_pki_enabled;
} coap_openssl_context_t;

int coap_dtls_is_supported(void) {
  if (SSLeay() < 0x10100000L) {
    coap_log(LOG_WARNING, "OpenSSL version 1.1.0 or later is required\n");
    return 0;
  }
  return 1;
}

int coap_tls_is_supported(void) {
  if (SSLeay() < 0x10100000L) {
    coap_log(LOG_WARNING, "OpenSSL version 1.1.0 or later is required\n");
    return 0;
  }
  return 1;
}

coap_tls_version_t *
coap_get_tls_library_version(void) {
  static coap_tls_version_t version;
  version.version = SSLeay();
  version.type = COAP_TLS_LIBRARY_OPENSSL;
  return &version;
}

void coap_dtls_startup(void) {
  SSL_load_error_strings();
  SSL_library_init();
}

static int dtls_log_level = 0;

void coap_dtls_set_log_level(int level) {
  dtls_log_level = level;
}

int coap_dtls_get_log_level(void) {
  return dtls_log_level;
}

typedef struct coap_ssl_st {
  coap_session_t *session;
  const void *pdu;
  unsigned pdu_len;
  unsigned peekmode;
  coap_tick_t timeout;
} coap_ssl_data;

static int coap_dgram_create(BIO *a) {
  coap_ssl_data *data = NULL;
  data = malloc(sizeof(coap_ssl_data));
  if (data == NULL)
    return 0;
  BIO_set_init(a, 1);
  BIO_set_data(a, data);
  memset(data, 0x00, sizeof(coap_ssl_data));
  return 1;
}

static int coap_dgram_destroy(BIO *a) {
  coap_ssl_data *data;
  if (a == NULL)
    return 0;
  data = (coap_ssl_data *)BIO_get_data(a);
  if (data != NULL)
    free(data);
  return 1;
}

static int coap_dgram_read(BIO *a, char *out, int outl) {
  int ret = 0;
  coap_ssl_data *data = (coap_ssl_data *)BIO_get_data(a);

  if (out != NULL) {
    if (data != NULL && data->pdu_len > 0) {
      if (outl < (int)data->pdu_len) {
	memcpy(out, data->pdu, outl);
	ret = outl;
      } else {
	memcpy(out, data->pdu, data->pdu_len);
	ret = (int)data->pdu_len;
      }
      if (!data->peekmode) {
	data->pdu_len = 0;
	data->pdu = NULL;
      }
    } else {
      ret = -1;
    }
    BIO_clear_retry_flags(a);
    if (ret < 0)
      BIO_set_retry_read(a);
  }
  return ret;
}

static int coap_dgram_write(BIO *a, const char *in, int inl) {
  int ret = 0;
  coap_ssl_data *data = (coap_ssl_data *)BIO_get_data(a);

  if (data->session) {
    if (data->session->sock.flags == COAP_SOCKET_EMPTY && data->session->endpoint == NULL) {
      /* socket was closed on client due to error */
      BIO_clear_retry_flags(a);
      return -1;
    }
    ret = (int)coap_session_send(data->session, (unsigned char*)in, (size_t)inl);
    BIO_clear_retry_flags(a);
    if (ret <= 0)
      BIO_set_retry_write(a);
  } else {
    BIO_clear_retry_flags(a);
    ret = -1;
  }
  return ret;
}

static int coap_dgram_puts(BIO *a, const char *pstr) {
  return coap_dgram_write(a, pstr, (int)strlen(pstr));
}

static long coap_dgram_ctrl(BIO *a, int cmd, long num, void *ptr) {
  long ret = 1;
  coap_ssl_data *data = BIO_get_data(a);

  (void)ptr;

  switch (cmd) {
  case BIO_CTRL_GET_CLOSE:
    ret = BIO_get_shutdown(a);
    break;
  case BIO_CTRL_SET_CLOSE:
    BIO_set_shutdown(a, (int)num);
    ret = 1;
    break;
  case BIO_CTRL_DGRAM_SET_PEEK_MODE:
    data->peekmode = (unsigned)num;
    break;
  case BIO_CTRL_DGRAM_CONNECT:
  case BIO_C_SET_FD:
  case BIO_C_GET_FD:
  case BIO_CTRL_DGRAM_SET_DONT_FRAG:
  case BIO_CTRL_DGRAM_GET_MTU:
  case BIO_CTRL_DGRAM_SET_MTU:
  case BIO_CTRL_DGRAM_QUERY_MTU:
  case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
    ret = -1;
    break;
  case BIO_CTRL_DUP:
  case BIO_CTRL_FLUSH:
  case BIO_CTRL_DGRAM_MTU_DISCOVER:
  case BIO_CTRL_DGRAM_SET_CONNECTED:
    ret = 1;
    break;
  case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
    data->timeout = coap_ticks_from_rt_us((uint64_t)((struct timeval*)ptr)->tv_sec * 1000000 + ((struct timeval*)ptr)->tv_usec);
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
  case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
  default:
    ret = 0;
    break;
  }
  return ret;
}

static int coap_dtls_generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
  coap_dtls_context_t *dtls = (coap_dtls_context_t *)SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
  coap_ssl_data *data = (coap_ssl_data*)BIO_get_data(SSL_get_rbio(ssl));
  int r = HMAC_Init_ex(dtls->cookie_hmac, NULL, 0, NULL, NULL);
  r &= HMAC_Update(dtls->cookie_hmac, (const uint8_t*)&data->session->local_addr.addr, (size_t)data->session->local_addr.size);
  r &= HMAC_Update(dtls->cookie_hmac, (const uint8_t*)&data->session->remote_addr.addr, (size_t)data->session->remote_addr.size);
  r &= HMAC_Final(dtls->cookie_hmac, cookie, cookie_len);
  return r;
}

static int coap_dtls_verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
  uint8_t hmac[32];
  unsigned len = 32;
  if (coap_dtls_generate_cookie(ssl, hmac, &len) && cookie_len == len && memcmp(cookie, hmac, len) == 0)
    return 1;
  else
    return 0;
}

static unsigned coap_dtls_psk_client_callback(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *buf, unsigned max_len) {
  size_t hint_len = 0, identity_len = 0, psk_len;
  coap_session_t *session = (coap_session_t*)SSL_get_app_data(ssl);

  if (hint)
    hint_len = strlen(hint);
  else
    hint = "";

  coap_log(LOG_DEBUG, "got psk_identity_hint: '%.*s'\n", (int)hint_len, hint);

  if (session == NULL || session->context == NULL || session->context->get_client_psk == NULL)
    return 0;

  psk_len = session->context->get_client_psk(session, (const uint8_t*)hint, hint_len, (uint8_t*)identity, &identity_len, max_identity_len - 1, (uint8_t*)buf, max_len);
  if (identity_len < max_identity_len)
    identity[identity_len] = 0;
  return (unsigned)psk_len;
}

static unsigned coap_dtls_psk_server_callback(SSL *ssl, const char *identity, unsigned char *buf, unsigned max_len) {
  size_t identity_len = 0;
  coap_session_t *session = (coap_session_t*)SSL_get_app_data(ssl);

  if (identity)
    identity_len = strlen(identity);
  else
    identity = "";

  coap_log(LOG_DEBUG, "got psk_identity: '%.*s'\n", (int)identity_len, identity);

  if (session == NULL || session->context == NULL || session->context->get_server_psk == NULL)
    return 0;

  return (unsigned)session->context->get_server_psk(session, (const uint8_t*)identity, identity_len, (uint8_t*)buf, max_len);
}

static int dtls_event = 0;

static void coap_dtls_info_callback(const SSL *ssl, int where, int ret) {
  const char *pstr;
  int w = where &~SSL_ST_MASK;

  if (w & SSL_ST_CONNECT)
    pstr = "SSL_connect";
  else if (w & SSL_ST_ACCEPT)
    pstr = "SSL_accept";
  else
    pstr = "undefined";

  if (where & SSL_CB_LOOP) {
    if (dtls_log_level >= LOG_DEBUG)
      coap_log(LOG_DEBUG, "%s:%s\n", pstr, SSL_state_string_long(ssl));
  } else if (where & SSL_CB_ALERT) {
    pstr = (where & SSL_CB_READ) ? "read" : "write";
    if (dtls_log_level >= LOG_INFO)
      coap_log(LOG_INFO, "SSL3 alert %s:%s:%s\n", pstr, SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
    if ((where & SSL_CB_WRITE) && (ret >> 8) == SSL3_AL_FATAL)
      dtls_event = COAP_EVENT_DTLS_ERROR;
  } else if (where & SSL_CB_EXIT) {
    if (ret == 0) {
      if (dtls_log_level >= LOG_WARNING) {
	unsigned long e;
	coap_log(LOG_WARNING, "%s:failed in %s\n", pstr, SSL_state_string_long(ssl));
	while ((e = ERR_get_error()))
	  coap_log(LOG_WARNING, "  %s at %s:%s\n", ERR_reason_error_string(e), ERR_lib_error_string(e), ERR_func_error_string(e));
      }
    } else if (ret < 0) {
      if (dtls_log_level >= LOG_WARNING) {
	int err = SSL_get_error(ssl, ret);
	if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_CONNECT && err != SSL_ERROR_WANT_ACCEPT && err != SSL_ERROR_WANT_X509_LOOKUP) {
	  long e;
	  coap_log(LOG_WARNING, "%s:error in %s\n", pstr, SSL_state_string_long(ssl));
	  while ((e = ERR_get_error()))
	    coap_log(LOG_WARNING, "  %s at %s:%s\n", ERR_reason_error_string(e), ERR_lib_error_string(e), ERR_func_error_string(e));
	}
      }
    }
  }

  if (where == SSL_CB_HANDSHAKE_START && SSL_get_state(ssl) == TLS_ST_OK)
    dtls_event = COAP_EVENT_DTLS_RENEGOTIATE;
}

static int coap_sock_create(BIO *a) {
  BIO_set_init(a, 1);
  return 1;
}

static int coap_sock_destroy(BIO *a) {
  (void)a;
  return 1;
}

static int coap_sock_read(BIO *a, char *out, int outl) {
  int ret = 0;
  coap_session_t *session = (coap_session_t *)BIO_get_data(a);

  if (out != NULL) {
    ret = (int)coap_socket_read(&session->sock, (uint8_t*)out, (size_t)outl);
    if (ret == 0) {
      BIO_set_retry_read(a);
      ret = -1;
    } else {
      BIO_clear_retry_flags(a);
    }
  }
  return ret;
}

static int coap_sock_write(BIO *a, const char *in, int inl) {
  int ret = 0;
  coap_session_t *session = (coap_session_t *)BIO_get_data(a);

  ret = (int)coap_socket_write(&session->sock, (const uint8_t*)in, (size_t)inl);
  BIO_clear_retry_flags(a);
  if (ret == 0) {
    BIO_set_retry_read(a);
    ret = -1;
  } else {
    BIO_clear_retry_flags(a);
  }
  return ret;
}

static int coap_sock_puts(BIO *a, const char *pstr) {
  return coap_sock_write(a, pstr, (int)strlen(pstr));
}

static long coap_sock_ctrl(BIO *a, int cmd, long num, void *ptr) {
  int r = 1;
  (void)a;
  (void)ptr;
  (void)num;

  switch (cmd) {
  case BIO_C_SET_FD:
  case BIO_C_GET_FD:
    r = -1;
    break;
  case BIO_CTRL_SET_CLOSE:
  case BIO_CTRL_DUP:
  case BIO_CTRL_FLUSH:
    r = 1;
    break;
  default:
  case BIO_CTRL_GET_CLOSE:
    r = 0;
    break;
  }
  return r;
}

void *coap_dtls_new_context(struct coap_context_t *coap_context) {
  coap_openssl_context_t *context;
  (void)coap_context;

  context = (coap_openssl_context_t *)coap_malloc(sizeof(coap_openssl_context_t));
  if (context) {
    uint8_t cookie_secret[32];

    memset(context, 0, sizeof(coap_openssl_context_t));

    /* Set up DTLS context */
    context->dtls.ctx = SSL_CTX_new(DTLS_method());
    if (!context->dtls.ctx)
      goto error;
    SSL_CTX_set_min_proto_version(context->dtls.ctx, DTLS1_2_VERSION);
    SSL_CTX_set_app_data(context->dtls.ctx, &context->dtls);
    SSL_CTX_set_read_ahead(context->dtls.ctx, 1);
    SSL_CTX_set_cipher_list(context->dtls.ctx, "TLSv1.2:TLSv1.0");
    if (!RAND_bytes(cookie_secret, (int)sizeof(cookie_secret))) {
      if (dtls_log_level >= LOG_WARNING)
	coap_log(LOG_WARNING, "Insufficient entropy for random cookie generation");
      prng(cookie_secret, sizeof(cookie_secret));
    }
    context->dtls.cookie_hmac = HMAC_CTX_new();
    if (!HMAC_Init_ex(context->dtls.cookie_hmac, cookie_secret, (int)sizeof(cookie_secret), EVP_sha256(), NULL))
      goto error;
    /*SSL_CTX_set_verify(context->dtls.ctx, SSL_VERIFY_PEER, coap_dtls_verify_cert );*/
    SSL_CTX_set_cookie_generate_cb(context->dtls.ctx, coap_dtls_generate_cookie);
    SSL_CTX_set_cookie_verify_cb(context->dtls.ctx, coap_dtls_verify_cookie);
    SSL_CTX_set_info_callback(context->dtls.ctx, coap_dtls_info_callback);
    SSL_CTX_set_options(context->dtls.ctx, SSL_OP_NO_QUERY_MTU);
    context->dtls.meth = BIO_meth_new(BIO_TYPE_DGRAM, "coapdgram");
    if (!context->dtls.meth)
      goto error;
    context->dtls.bio_addr = BIO_ADDR_new();
    if (!context->dtls.bio_addr)
      goto error;
    BIO_meth_set_write(context->dtls.meth, coap_dgram_write);
    BIO_meth_set_read(context->dtls.meth, coap_dgram_read);
    BIO_meth_set_puts(context->dtls.meth, coap_dgram_puts);
    BIO_meth_set_ctrl(context->dtls.meth, coap_dgram_ctrl);
    BIO_meth_set_create(context->dtls.meth, coap_dgram_create);
    BIO_meth_set_destroy(context->dtls.meth, coap_dgram_destroy);

    /* Set up TLS context */
    context->tls.ctx = SSL_CTX_new(TLS_method());
    if (!context->tls.ctx)
      goto error;
    SSL_CTX_set_app_data(context->tls.ctx, &context->tls);
    SSL_CTX_set_min_proto_version(context->tls.ctx, TLS1_VERSION);
    SSL_CTX_set_cipher_list(context->tls.ctx, "TLSv1.2:TLSv1.0");
    /*SSL_CTX_set_verify(context->tls.ctx, SSL_VERIFY_PEER, coap_dtls_verify_cert);*/
    SSL_CTX_set_info_callback(context->tls.ctx, coap_dtls_info_callback);
    context->tls.meth = BIO_meth_new(BIO_TYPE_SOCKET, "coapsock");
    if (!context->tls.meth)
      goto error;
    BIO_meth_set_write(context->tls.meth, coap_sock_write);
    BIO_meth_set_read(context->tls.meth, coap_sock_read);
    BIO_meth_set_puts(context->tls.meth, coap_sock_puts);
    BIO_meth_set_ctrl(context->tls.meth, coap_sock_ctrl);
    BIO_meth_set_create(context->tls.meth, coap_sock_create);
    BIO_meth_set_destroy(context->tls.meth, coap_sock_destroy);
  }

  return context;

error:
  coap_dtls_free_context(context);
  return NULL;
}

int coap_dtls_context_set_psk(coap_context_t *ctx,
  const char *hint,
  const uint8_t *key, size_t key_len
) {
  (void)key;
  (void)key_len;
  coap_openssl_context_t *context = ((coap_openssl_context_t *)ctx->dtls_context);
  BIO *bio;
  SSL_CTX_set_psk_client_callback(context->dtls.ctx, coap_dtls_psk_client_callback);
  SSL_CTX_set_psk_server_callback(context->dtls.ctx, coap_dtls_psk_server_callback);
  SSL_CTX_use_psk_identity_hint(context->dtls.ctx, hint ? hint : "");
  SSL_CTX_set_psk_client_callback(context->tls.ctx, coap_dtls_psk_client_callback);
  SSL_CTX_set_psk_server_callback(context->tls.ctx, coap_dtls_psk_server_callback);
  SSL_CTX_use_psk_identity_hint(context->tls.ctx, hint);
  if (!context->dtls.ssl) {
    context->dtls.ssl = SSL_new(context->dtls.ctx);
    if (!context->dtls.ssl)
      return 0;
    bio = BIO_new(context->dtls.meth);
    if (!bio) {
      SSL_free (context->dtls.ssl);
      context->dtls.ssl = NULL;
      return 0;
    }
    SSL_set_bio(context->dtls.ssl, bio, bio);
    SSL_set_app_data(context->dtls.ssl, NULL);
    SSL_set_options(context->dtls.ssl, SSL_OP_COOKIE_EXCHANGE);
    SSL_set_mtu(context->dtls.ssl, COAP_DEFAULT_MTU);
  }
  context->psk_pki_enabled = 1;
  return 1;
}

int coap_dtls_context_set_pki( coap_context_t *ctx,
  coap_dtls_pki_t* setup_data
) {
  coap_openssl_context_t *context = ((coap_openssl_context_t *)ctx->dtls_context);
  BIO *bio;
  if (context->dtls.ctx) {
    if (setup_data->public_cert && setup_data->public_cert[0]) {
      if (!(SSL_CTX_use_certificate_file(context->dtls.ctx, setup_data->public_cert, SSL_FILETYPE_PEM))) {
        coap_log(LOG_WARNING, "*** coap_dtls_context_set_pki: DTLS: %s: Unable to configure Server Certificate\n", setup_data->public_cert);
        return 0;
      }
    }
    else if (setup_data->asn1_public_cert && setup_data->asn1_public_cert_len > 0) {
      if (!(SSL_CTX_use_certificate_ASN1(context->dtls.ctx, setup_data->asn1_public_cert_len, setup_data->asn1_public_cert))) {
        coap_log(LOG_WARNING, "*** coap_dtls_context_set_pki: DTLS: %s: Unable to configure Server Certificate\n", "ASN1");
        return 0;
      }
    }
    else {
      coap_log(LOG_ERR, "*** coap_dtls_context_set_pki: DTLS: No Server Certificate defined\n");
    }
    if (setup_data->private_key && setup_data->private_key[0]) {
      if (!(SSL_CTX_use_PrivateKey_file(context->dtls.ctx, setup_data->private_key, SSL_FILETYPE_PEM))) {
        coap_log(LOG_WARNING, "*** coap_dtls_context_set_pki: DTLS: %s: Unable to configure Server Private Key\n", setup_data->private_key);
        return 0;
      }
    }
    else if (setup_data->asn1_private_key && setup_data->asn1_private_key_len > 0) {
      int pkey_type;
      switch (setup_data->asn1_private_key_type) {
      case COAP_ASN1_PKEY_NONE:
        pkey_type = EVP_PKEY_NONE;
        break;
      case COAP_ASN1_PKEY_RSA:
        pkey_type = EVP_PKEY_RSA;
        break;
      case COAP_ASN1_PKEY_RSA2:
        pkey_type = EVP_PKEY_RSA2;
        break;
      case COAP_ASN1_PKEY_DSA:
        pkey_type = EVP_PKEY_DSA;
        break;
      case COAP_ASN1_PKEY_DSA1:
        pkey_type = EVP_PKEY_DSA1;
        break;
      case COAP_ASN1_PKEY_DSA2:
        pkey_type = EVP_PKEY_DSA2;
        break;
      case COAP_ASN1_PKEY_DSA3:
        pkey_type = EVP_PKEY_DSA3;
        break;
      case COAP_ASN1_PKEY_DSA4:
        pkey_type = EVP_PKEY_DSA4;
        break;
      case COAP_ASN1_PKEY_DH:
        pkey_type = EVP_PKEY_DH;
        break;
      case COAP_ASN1_PKEY_DHX:
        pkey_type = EVP_PKEY_DHX;
        break;
      case COAP_ASN1_PKEY_EC:
        pkey_type = EVP_PKEY_EC;
        break;
      case COAP_ASN1_PKEY_HMAC:
        pkey_type = EVP_PKEY_HMAC;
        break;
      case COAP_ASN1_PKEY_CMAC:
        pkey_type = EVP_PKEY_CMAC;
        break;
      case COAP_ASN1_PKEY_TLS1_PRF:
        pkey_type = EVP_PKEY_TLS1_PRF;
        break;
      case COAP_ASN1_PKEY_HKDF:
        pkey_type = EVP_PKEY_HKDF;
        break;
      default:
        coap_log(LOG_WARNING,
      "*** coap_dtls_context_set_pki: DTLS: Unknown Private Key type %d for ASN1\n",
                 setup_data->asn1_private_key_type);
        return 0;
      }
      if (!(SSL_CTX_use_PrivateKey_ASN1(pkey_type, context->dtls.ctx, setup_data->asn1_private_key, setup_data->asn1_private_key_len))) {
        coap_log(LOG_WARNING, "*** coap_dtls_context_set_pki: DTLS: %s: Unable to configure Server Private Key\n", "ASN1");
        return 0;
      }
    }
    else {
      coap_log(LOG_ERR, "*** coap_dtls_context_set_pki: DTLS: No Server Private Key defined\n");
    }
  }
  if (context->tls.ctx) {
    if (setup_data->public_cert && setup_data->public_cert[0]) {
      if (!(SSL_CTX_use_certificate_file(context->tls.ctx, setup_data->public_cert, SSL_FILETYPE_PEM))) {
        coap_log(LOG_WARNING, "*** coap_dtls_context_set_pki: TLS: %s: Unable to configure Server Certificate\n", setup_data->public_cert);
        return 0;
      }
    }
    else if (setup_data->asn1_public_cert && setup_data->asn1_public_cert_len > 0) {
      if (!(SSL_CTX_use_certificate_ASN1(context->tls.ctx, setup_data->asn1_public_cert_len, setup_data->asn1_public_cert))) {
        coap_log(LOG_WARNING, "*** coap_dtls_context_set_pki: TLS: %s: Unable to configure Server Certificate\n", "ASN1");
        return 0;
      }
    }
    else {
      coap_log(LOG_ERR, "*** coap_dtls_context_set_pki: TLS: No Server Certificate defined\n");
    }
    if (setup_data->private_key && setup_data->private_key[0]) {
      if (!(SSL_CTX_use_PrivateKey_file(context->tls.ctx, setup_data->private_key, SSL_FILETYPE_PEM))) {
        coap_log(LOG_WARNING, "*** coap_dtls_context_set_pki: TLS: %s: Unable to configure Server Private Key\n", setup_data->private_key);
        return 0;
      }
    }
    else if (setup_data->asn1_private_key && setup_data->asn1_private_key_len > 0) {
      if (!(SSL_CTX_use_PrivateKey_ASN1(setup_data->asn1_private_key_type, context->tls.ctx, setup_data->asn1_private_key, setup_data->asn1_private_key_len))) {
        coap_log(LOG_WARNING, "*** coap_dtls_context_set_pki: TLS: %s: Unable to configure Server Private Key\n", "ASN1");
        return 0;
      }
    }
    else {
      coap_log(LOG_ERR, "*** coap_dtls_context_set_pki: TLS: No Server Private Key defined\n");
    }
  }

  if (setup_data->call_back) {
    if (!setup_data->call_back(context->dtls.ctx, setup_data)) return 0;
    if (!setup_data->call_back(context->tls.ctx, setup_data)) return 0;;
  }
  if (!context->dtls.ssl) {
    context->dtls.ssl = SSL_new(context->dtls.ctx);
    if (!context->dtls.ssl)
      return 0;
    bio = BIO_new(context->dtls.meth);
    if (!bio) {
      SSL_free (context->dtls.ssl);
      context->dtls.ssl = NULL;
      return 0;
    }
    SSL_set_bio(context->dtls.ssl, bio, bio);
    SSL_set_app_data(context->dtls.ssl, NULL);
    SSL_set_options(context->dtls.ssl, SSL_OP_COOKIE_EXCHANGE);
    SSL_set_mtu(context->dtls.ssl, COAP_DEFAULT_MTU);
  }
  context->psk_pki_enabled = 1;
  return 1;
}

int coap_dtls_context_check_keys_enabled(coap_context_t *ctx)
{
  coap_openssl_context_t *context = ((coap_openssl_context_t *)ctx->dtls_context);
  return context->psk_pki_enabled;
}


void coap_dtls_free_context(void *handle) {
  coap_openssl_context_t *context = (coap_openssl_context_t *)handle;
  if (context->dtls.ssl)
    SSL_free(context->dtls.ssl);
  if (context->dtls.ctx)
    SSL_CTX_free(context->dtls.ctx);
  if (context->dtls.cookie_hmac)
    HMAC_CTX_free(context->dtls.cookie_hmac);
  if (context->dtls.meth)
    BIO_meth_free(context->dtls.meth);
  if (context->dtls.bio_addr)
    BIO_ADDR_free(context->dtls.bio_addr);
  if ( context->tls.ctx )
      SSL_CTX_free( context->tls.ctx );
  if ( context->tls.meth )
      BIO_meth_free( context->tls.meth );
  coap_free(context);
}

void * coap_dtls_new_server_session(coap_session_t *session) {
  BIO *nbio = NULL;
  SSL *nssl = NULL, *ssl = NULL;
  coap_ssl_data *data;
  coap_dtls_context_t *dtls = &((coap_openssl_context_t *)session->context->dtls_context)->dtls;
  int r;

  nssl = SSL_new(dtls->ctx);
  if (!nssl)
    goto error;
  nbio = BIO_new(dtls->meth);
  if (!nbio)
    goto error;
  SSL_set_bio(nssl, nbio, nbio);
  SSL_set_app_data(nssl, NULL);
  SSL_set_options(nssl, SSL_OP_COOKIE_EXCHANGE);
  SSL_set_mtu(nssl, session->mtu);
  ssl = dtls->ssl;
  dtls->ssl = nssl;
  nssl = NULL;
  SSL_set_app_data(ssl, session);

  data = (coap_ssl_data*)BIO_get_data(SSL_get_rbio(ssl));
  data->session = session;

  if (session->context->get_server_hint) {
    char hint[128] = "";
    size_t hint_len = session->context->get_server_hint(session, (uint8_t*)hint, sizeof(hint) - 1);
    if (hint_len > 0 && hint_len < sizeof(hint)) {
      hint[hint_len] = 0;
      SSL_use_psk_identity_hint(ssl, hint);
    }
  }

  r = SSL_accept(ssl);
  if (r == -1) {
    int err = SSL_get_error(ssl, r);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
      r = 0;
  }

  if (r == 0) {
    SSL_free(ssl);
    return NULL;
  }

  return ssl;

error:
  if (nssl)
    SSL_free(nssl);
  return NULL;
}

void *coap_dtls_new_client_session(coap_session_t *session) {
  BIO *bio = NULL;
  SSL *ssl = NULL;
  coap_ssl_data *data;
  int r;
  coap_openssl_context_t *context = ((coap_openssl_context_t *)session->context->dtls_context);
  coap_dtls_context_t *dtls = &context->dtls;

  if (!context->psk_pki_enabled)
    goto error;
  ssl = SSL_new(dtls->ctx);
  if (!ssl)
    goto error;
  bio = BIO_new(dtls->meth);
  if (!bio)
    goto error;
  data = (coap_ssl_data *)BIO_get_data(bio);
  data->session = session;
  SSL_set_bio(ssl, bio, bio);
  SSL_set_app_data(ssl, session);
  SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
  SSL_set_mtu(ssl, session->mtu);

  session->dtls_timeout_count = 0;

  r = SSL_connect(ssl);
  if (r == -1) {
    int ret = SSL_get_error(ssl, r);
    if (ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE)
      r = 0;
  }

  if (r == 0)
    goto error;

  return ssl;

error:
  if (ssl)
    SSL_free(ssl);
  return NULL;
}

void coap_dtls_session_update_mtu(coap_session_t *session) {
  SSL *ssl = (SSL *)session->tls;
  if (ssl)
    SSL_set_mtu(ssl, session->mtu);
}

void coap_dtls_free_session(coap_session_t *session) {
  SSL *ssl = (SSL *)session->tls;
  if (ssl) {
    if (!(SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN))
      SSL_shutdown(ssl);
    SSL_free(ssl);
  }
}

int coap_dtls_send(coap_session_t *session,
  const uint8_t *data, size_t data_len) {
  int r;
  SSL *ssl = (SSL *)session->tls;

  assert(ssl != NULL);

  dtls_event = -1;
  r = SSL_write(ssl, data, (int)data_len);

  if (r <= 0) {
    int err = SSL_get_error(ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      r = 0;
    } else {
      coap_log(LOG_WARNING, "coap_dtls_send: cannot send PDU\n");
      if (err == SSL_ERROR_ZERO_RETURN)
	dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == SSL_ERROR_SSL)
	dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
  }

  if (dtls_event >= 0) {
    coap_handle_event(session->context, dtls_event, session);
    if (dtls_event == COAP_EVENT_DTLS_ERROR || dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
      r = -1;
    }
  }

  return r;
}

int coap_dtls_is_context_timeout(void) {
  return 0;
}

coap_tick_t coap_dtls_get_context_timeout(void *dtls_context) {
  (void)dtls_context;
  return 0;
}

coap_tick_t coap_dtls_get_timeout(coap_session_t *session) {
  SSL *ssl = (SSL *)session->tls;
  coap_ssl_data *ssl_data;

  assert(ssl != NULL);
  ssl_data = (coap_ssl_data*)BIO_get_data(SSL_get_rbio(ssl));
  return ssl_data->timeout;
}

void coap_dtls_handle_timeout(coap_session_t *session) {
  SSL *ssl = (SSL *)session->tls;

  assert(ssl != NULL);
  if (((session->state == COAP_SESSION_STATE_HANDSHAKE) &&
       (++session->dtls_timeout_count > session->max_retransmit)) || 
      (DTLSv1_handle_timeout(ssl) < 0)) {
    /* Too many retries */
    coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
  }
}

int coap_dtls_hello(coap_session_t *session,
  const uint8_t *data, size_t data_len) {
  coap_dtls_context_t *dtls = &((coap_openssl_context_t *)session->context->dtls_context)->dtls;
  coap_ssl_data *ssl_data;
  int r;

  SSL_set_mtu(dtls->ssl, session->mtu);
  ssl_data = (coap_ssl_data*)BIO_get_data(SSL_get_rbio(dtls->ssl));
  ssl_data->session = session;
  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;
  r = DTLSv1_listen(dtls->ssl, dtls->bio_addr);
  if (r <= 0) {
    int err = SSL_get_error(dtls->ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      /* Got a ClientHello, sent-out a VerifyRequest */
      r = 0;
    }
  } else {
    /* Got a valid answer to a VerifyRequest */
    r = 1;
  }

  return r;
}

int coap_dtls_receive(coap_session_t *session,
  const uint8_t *data, size_t data_len) {
  coap_ssl_data *ssl_data;
  SSL *ssl = (SSL *)session->tls;
  int r;

  assert(ssl != NULL);

  int in_init = SSL_in_init(ssl);
  uint8_t pdu[COAP_RXBUFFER_SIZE];
  ssl_data = (coap_ssl_data*)BIO_get_data(SSL_get_rbio(ssl));
  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;

  dtls_event = -1;
  r = SSL_read(ssl, pdu, (int)sizeof(pdu));
  if (r > 0) {
    return coap_handle_dgram(session->context, session, pdu, (size_t)r);
  } else {
    int err = SSL_get_error(ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      if (in_init && SSL_is_init_finished(ssl)) {
	coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
	coap_session_connected(session);
      }
      r = 0;
    } else {
      if (err == SSL_ERROR_ZERO_RETURN)	/* Got a close notify alert from the remote side */
	dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == SSL_ERROR_SSL)
	dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
    if (dtls_event >= 0) {
      coap_handle_event(session->context, dtls_event, session);
      if (dtls_event == COAP_EVENT_DTLS_ERROR || dtls_event == COAP_EVENT_DTLS_CLOSED) {
	coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
	r = -1;
      }
    }
  }

  return r;
}

unsigned int coap_dtls_get_overhead(coap_session_t *session) {
  unsigned int overhead = 37;
  const SSL_CIPHER *s_ciph = NULL;
  if (session->tls != NULL)
    s_ciph = SSL_get_current_cipher(session->tls);
  if ( s_ciph ) {
    unsigned int ivlen, maclen, blocksize = 1, pad = 0;
    
    const EVP_CIPHER *e_ciph;
    const EVP_MD *e_md;
    char cipher[128];

    e_ciph = EVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(s_ciph));

    switch (EVP_CIPHER_mode(e_ciph)) {
    case EVP_CIPH_GCM_MODE:
      ivlen = EVP_GCM_TLS_EXPLICIT_IV_LEN;
      maclen = EVP_GCM_TLS_TAG_LEN;
      break;

    case EVP_CIPH_CCM_MODE:
      ivlen = EVP_CCM_TLS_EXPLICIT_IV_LEN;
      SSL_CIPHER_description(s_ciph, cipher, sizeof(cipher));
      if (strstr(cipher, "CCM8"))
	maclen = 8;
      else
	maclen = 16;
      break;

    case EVP_CIPH_CBC_MODE:
      e_md = EVP_get_digestbynid(SSL_CIPHER_get_digest_nid(s_ciph));
      blocksize = EVP_CIPHER_block_size(e_ciph);
      ivlen = EVP_CIPHER_iv_length(e_ciph);
      pad = 1;
      maclen = EVP_MD_size(e_md);
      break;

    case EVP_CIPH_STREAM_CIPHER:
      /* Seen with PSK-CHACHA20-POLY1305 */
      ivlen = 8;
      maclen = 8;
      break;

    default:
      SSL_CIPHER_description(s_ciph, cipher, sizeof(cipher));
      coap_log(LOG_WARNING, "Unknown overhead for DTLS with cipher %s\n", cipher);
      ivlen = 8;
      maclen = 16;
      break;
    }
    overhead = DTLS1_RT_HEADER_LENGTH + ivlen + maclen + blocksize - 1 + pad;
  }
  return overhead;
}

void *coap_tls_new_client_session(coap_session_t *session, int *connected) {
  BIO *bio = NULL;
  SSL *ssl = NULL;
  int r;
  coap_openssl_context_t *context = ((coap_openssl_context_t *)session->context->dtls_context);
  coap_tls_context_t *tls = &context->tls;

  if (!context->psk_pki_enabled)
    goto error;
  *connected = 0;
  ssl = SSL_new(tls->ctx);
  if (!ssl)
    goto error;
  bio = BIO_new(tls->meth);
  if (!bio)
    goto error;
  BIO_set_data(bio, session);
  SSL_set_bio(ssl, bio, bio);
  SSL_set_app_data(ssl, session);

  r = SSL_connect(ssl);
  if (r == -1) {
    int ret = SSL_get_error(ssl, r);
    if (ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE)
      r = 0;
    if (ret == SSL_ERROR_WANT_READ)
      session->sock.flags |= COAP_SOCKET_WANT_READ;
    if (ret == SSL_ERROR_WANT_WRITE)
      session->sock.flags |= COAP_SOCKET_WANT_WRITE;
  }

  if (r == 0)
    goto error;

  *connected = SSL_is_init_finished(ssl);

  return ssl;

error:
  if (ssl)
    SSL_free(ssl);
  return NULL;
}

void *coap_tls_new_server_session(coap_session_t *session, int *connected) {
  BIO *bio = NULL;
  SSL *ssl = NULL;
  coap_tls_context_t *tls = &((coap_openssl_context_t *)session->context->dtls_context)->tls;
  int r;

  *connected = 0;
  ssl = SSL_new(tls->ctx);
  if (!ssl)
    goto error;
  bio = BIO_new(tls->meth);
  if (!bio)
    goto error;
  BIO_set_data(bio, session);
  SSL_set_bio(ssl, bio, bio);
  SSL_set_app_data(ssl, session);

  if (session->context->get_server_hint) {
    char hint[128] = "";
    size_t hint_len = session->context->get_server_hint(session, (uint8_t*)hint, sizeof(hint) - 1);
    if (hint_len > 0 && hint_len < sizeof(hint)) {
      hint[hint_len] = 0;
      SSL_use_psk_identity_hint(ssl, hint);
    }
  }

  r = SSL_accept(ssl);
  if (r == -1) {
    int err = SSL_get_error(ssl, r);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
      r = 0;
    if (err == SSL_ERROR_WANT_READ)
      session->sock.flags |= COAP_SOCKET_WANT_READ;
    if (err == SSL_ERROR_WANT_WRITE)
      session->sock.flags |= COAP_SOCKET_WANT_WRITE;
  }

  if (r == 0)
    goto error;

  *connected = SSL_is_init_finished(ssl);

  return ssl;

error:
  if (ssl)
    SSL_free(ssl);
  return NULL;
}

void coap_tls_free_session(coap_session_t *session) {
  SSL *ssl = (SSL *)session->tls;
  if (ssl) {
    if (!(SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN))
      SSL_shutdown(ssl);
    SSL_free(ssl);
  }
}

ssize_t coap_tls_write(coap_session_t *session,
                       const uint8_t *data,
                       size_t data_len
) {
  SSL *ssl = (SSL *)session->tls;
  int r, in_init;

  if (ssl == NULL)
    return -1;

  in_init = !SSL_is_init_finished(ssl);
  dtls_event = -1;
  r = SSL_write(ssl, data, (int)data_len);

  if (r <= 0) {
    int err = SSL_get_error(ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      if (in_init && SSL_is_init_finished(ssl)) {
        coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
        coap_session_send_csm(session);
      }
      if (err == SSL_ERROR_WANT_READ)
	session->sock.flags |= COAP_SOCKET_WANT_READ;
      if (err == SSL_ERROR_WANT_WRITE)
	session->sock.flags |= COAP_SOCKET_WANT_WRITE;
      r = 0;
    } else {
      coap_log(LOG_WARNING, "coap_tls_write: cannot send PDU\n");
      if (err == SSL_ERROR_ZERO_RETURN)
	dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == SSL_ERROR_SSL)
	dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
  } else if (in_init && SSL_is_init_finished(ssl)) {
    coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
    coap_session_send_csm(session);
  }

  if (dtls_event >= 0) {
    coap_handle_event(session->context, dtls_event, session);
    if (dtls_event == COAP_EVENT_DTLS_ERROR || dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
      r = -1;
    }
  }

  return r;
}

ssize_t coap_tls_read(coap_session_t *session,
                      uint8_t *data,
                      size_t data_len
) {
  SSL *ssl = (SSL *)session->tls;
  int r, in_init;

  if (ssl == NULL)
    return -1;

  in_init = !SSL_is_init_finished(ssl);
  dtls_event = -1;
  r = SSL_read(ssl, data, (int)data_len);
  if (r <= 0) {
    int err = SSL_get_error(ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      if (in_init && SSL_is_init_finished(ssl)) {
	coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
	coap_session_send_csm(session);
      }
      if (err == SSL_ERROR_WANT_READ)
	session->sock.flags |= COAP_SOCKET_WANT_READ;
      if (err == SSL_ERROR_WANT_WRITE)
	session->sock.flags |= COAP_SOCKET_WANT_WRITE;
      r = 0;
    } else {
      if (err == SSL_ERROR_ZERO_RETURN)	/* Got a close notify alert from the remote side */
	dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == SSL_ERROR_SSL)
	dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
  } else if (in_init && SSL_is_init_finished(ssl)) {
    coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
    coap_session_send_csm(session);
  }

  if (dtls_event >= 0) {
    coap_handle_event(session->context, dtls_event, session);
    if (dtls_event == COAP_EVENT_DTLS_ERROR || dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
      r = -1;
    }
  }

  return r;
}

#else /* !HAVE_OPENSSL */

/* make compilers happy that do not like empty modules */
static inline void dummy(void) {
}

#endif /* HAVE_OPENSSL */
