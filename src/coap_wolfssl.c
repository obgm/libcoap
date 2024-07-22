/*
 * coap_wolfssl.c -- wolfSSL Transport Layer Support for libcoap
 *
 * Copyright (C) 2017      Jean-Claude Michelou <jcm@spinetix.com>
 * Copyright (C) 2023      Javier Blanco <frblanco@pa.uc3m.es>
 * Copyright (C) 2018-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_wolfssl.c
 * @brief wolfSSL specific interface functions.
 */

#include "coap3/coap_libcoap_build.h"

#ifdef COAP_WITH_LIBWOLFSSL

/*
 * Implemented using wolfSSL's OpenSSL compatibility layer based on coap_openssl.c.
 *
 * It is possible to override the Ciphers, define the Algorithms or Groups
 * to use for the SSL negotiations at compile time. This is done by the adding
 * of the appropriate -D option to the CFLAGS parameter that is used on the
 * ./configure command line.
 * E.g.  ./configure CFLAGS="-DXX='\"YY\"' -DUU='\"VV\"'"
 * The parameter value is case-sensitive and needs the extra " wrapper so that
 * it includes the "text" with quotes in the defined parameter..
 *
 * The (client) PKI ciphers can be overridden with (example)
 *  CFLAGS="-DCOAP_WOLFSSL_PKI_CIPHERS='\"TLS13-AES128-GCM-SHA256\"'"
 *
 * The (client) PSK ciphers can be overridden with (example)
 *  CFLAGS="-DCOAP_WOLFSSL_PSK_CIPHERS='\"PSK-AES128-CCM\"'"
 *
 * The Algorithms can be defined by (example)
 *  CFLAGS="-DCOAP_WOLFSSL_SIGALGS='\"RSA+SHA256\"'"
 *
 * The Groups (including post-quantum ones, if wolfSSL has been built with liboqs
 * and DTLS 1.3 enabled) can be defined using the following example:
 *  CFLAGS="-DCOAP_WOLFSSL_GROUPS=\"\\\"P-384:P-256:KYBER_LEVEL1\\\"\"" ./configure ...
 *
 * wolfSSL library building (not libcoap library building)
 *
 * If wolfSSL is going to interoperate with TinyDTLS, then the wolfSSL library
 * needs to be build with
 *  $ ./configure CFLAGS="-DBUILD_TLS_PSK_WITH_AES_128_CCM"
 * as TinyDTLS currently only supports CCM.
 *
 * If wolfSSL debug logging is required, then the wolfSSL library needs to be built with
 *  $ ./configure --enable-debug
 *
 * For extra TLS debugging
 *  $./configure --enable-debug CFLAGS="-DWOLFSSL_DEBUG_TLS"
 *
 * If wolfSSL dtls1.3 support is required, then the wolfSSL library needs to be built with
 *  $ ./configure --enable-dtls13
 *
 * If wolfSSL RPK support is required, then the wolfSSL library needs to be built with
 *  $ ./configure CFLAGS="-DHAVE_RPK"
 *
 * If wolfSSL CID support is required, then the wolfSSL library needs to be built with
 *  $ ./configure --enable-dtls13 --enable-dtlscid CFLAGS="-DDTLS_CID_MAX_SIZE=8"
 * NOTE: For interoperability with MbedTLS, https://github.com/wolfSSL/wolfssl/pull/7841
 * needs to be installed.
 *
 * When building the wolfSSL library from scratch, it is suggested that the library
 * built with
 *  $ ./configure --enable-all
 * to get the needed common options, or perhaps
 *  $ ./configure --enable-all --enable-dtls13 CFLAGS="-DBUILD_TLS_PSK_WITH_AES_128_CCM -DHAVE_RPK"
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/x509v3.h>

#ifdef COAP_EPOLL_SUPPORT
# include <sys/epoll.h>
#endif /* COAP_EPOLL_SUPPORT */

#if LIBWOLFSSL_VERSION_HEX < 0x05002000
#error Must be compiled against wolfSSL 5.2.0 or later
#endif

#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif

/* missing definitions */
#define WOLFSSL3_AL_FATAL 2
#define WOLFSSL_TLSEXT_ERR_OK 0

/* This structure encapsulates the wolfSSL context object. */
typedef struct coap_dtls_context_t {
  WOLFSSL_CTX *ctx;
  WOLFSSL_HMAC_CTX *cookie_hmac;
} coap_dtls_context_t;

typedef struct coap_tls_context_t {
  WOLFSSL_CTX *ctx;
} coap_tls_context_t;

#define IS_PSK 0x1
#define IS_PKI 0x2

typedef struct coap_wolfssl_context_t {
  coap_dtls_context_t dtls;
#if !COAP_DISABLE_TCP
  coap_tls_context_t tls;
#endif /* !COAP_DISABLE_TCP */
  coap_dtls_pki_t setup_data;
  int psk_pki_enabled;
  char *root_ca_file;
  char *root_ca_dir;
} coap_wolfssl_context_t;

typedef struct coap_ssl_data_t {
  coap_session_t *session;
  const void *pdu;
  unsigned pdu_len;
  unsigned peekmode;
} coap_ssl_data_t;

typedef struct coap_wolfssl_env_t {
  WOLFSSL *ssl;
  coap_tick_t last_timeout;
  unsigned int retry_scalar;
  coap_ssl_data_t data;
  int done_psk_check;
  coap_dtls_role_t role;
} coap_wolfssl_env_t;

typedef enum coap_enc_method_t {
  COAP_ENC_PSK,
  COAP_ENC_PKI,
} coap_enc_method_t;

static void *
wolfssl_malloc(size_t size) {
  void *ret = XMALLOC(size, NULL, DYNAMIC_TYPE_TMP_BUFFER);

  return ret;
}

static void
wolfssl_free(void *ptr) {
  if (ptr)
    XFREE(ptr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

static char *
wolfssl_strdup(const char *str) {
  char *ret = (char *)wolfssl_malloc(strlen(str) + 1);

  if (ret) {
    strcpy(ret, str);
  }
  return ret;
}

static char *
wolfssl_strndup(const char *str, size_t n) {
  size_t len = strnlen(str, n);
  char *ret = (char *)wolfssl_malloc(len + 1);

  if (ret) {
    strncpy(ret, str, len);
    ret[len] = '\0';
  }
  return ret;
}

static coap_wolfssl_env_t *
coap_dtls_new_wolfssl_env(coap_session_t *c_session, coap_dtls_role_t role) {
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)c_session->tls;

  assert(w_env == NULL);
  w_env = (coap_wolfssl_env_t *)wolfssl_malloc(sizeof(coap_wolfssl_env_t));
  if (!w_env) {
    return NULL;
  }
  memset(w_env, 0, sizeof(coap_wolfssl_env_t));
  w_env->role = role;
  return w_env;
}

static void
coap_dtls_free_wolfssl_env(coap_wolfssl_env_t *w_env) {
  if (w_env) {
    wolfssl_free(w_env);
  }
}

#if COAP_CLIENT_SUPPORT
#ifndef WOLFSSL_CIPHER_LIST_MAX_SIZE
#define WOLFSSL_CIPHER_LIST_MAX_SIZE 4096
#endif /* WOLFSSL_CIPHER_LIST_MAX_SIZE */

#ifdef COAP_WOLFSSL_PSK_CIPHERS
static char psk_ciphers[] = COAP_WOLFSSL_PSK_CIPHERS;
#else /* ! COAP_WOLFSSL_PSK_CIPHERS */
static char psk_ciphers[WOLFSSL_CIPHER_LIST_MAX_SIZE];
#endif /* ! COAP_WOLFSSL_PSK_CIPHERS */

#ifdef COAP_WOLFSSL_PKI_CIPHERS
static char pki_ciphers[] = COAP_WOLFSSL_PKI_CIPHERS;
#else /* ! COAP_WOLFSSL_PKI_CIPHERS */
static char pki_ciphers[WOLFSSL_CIPHER_LIST_MAX_SIZE];
#endif /* ! COAP_WOLFSSL_PKI_CIPHERS */

static void
set_ciphersuites(WOLFSSL *ssl, coap_enc_method_t method) {
#if ! defined(COAP_WOLFSSL_PSK_CIPHERS) || ! defined(COAP_WOLFSSL_PKI_CIPHERS)
  static int processed_ciphers = 0;

  if (!processed_ciphers) {
    static char ciphers[WOLFSSL_CIPHER_LIST_MAX_SIZE];
    char *ciphers_ofs = ciphers;
    char *cp;
#if ! defined(COAP_WOLFSSL_PSK_CIPHERS)
    char *psk_ofs = psk_ciphers;
#endif /* ! COAP_WOLFSSL_PSK_CIPHERS */
#if ! defined(COAP_WOLFSSL_PKI_CIPHERS)
    char *pki_ofs = pki_ciphers;
#endif /* ! COAP_WOLFSSL_PKI_CIPHERS */

    if (wolfSSL_get_ciphers(ciphers, (int)sizeof(ciphers)) != WOLFSSL_SUCCESS) {
      coap_log_warn("set_ciphersuites: Failed to get ciphers\n");
      return;
    }

    while (ciphers_ofs) {
      cp = strchr(ciphers_ofs, ':');
      if (cp)
        *cp = '\000';
      if (strstr(ciphers_ofs, "NULL")) {
        /* NULL type not required */
        goto next_a;
      }
      if (strcmp(ciphers_ofs, "RENEGOTIATION-INFO") == 0) {
        /* Skip for now - adding to end */
        goto next_a;
      } else if (strstr(ciphers_ofs, "PSK")) {
#if ! defined(COAP_WOLFSSL_PSK_CIPHERS)
        if (psk_ofs != psk_ciphers) {
          psk_ofs[0] = ':';
          psk_ofs++;
        }
        strcpy(psk_ofs, ciphers_ofs);
        psk_ofs += strlen(ciphers_ofs);
        psk_ofs[0] = '\000';
#endif /* ! COAP_WOLFSSL_PSK_CIPHERS */
      } else {
#if ! defined(COAP_WOLFSSL_PKI_CIPHERS)
        if (pki_ofs != pki_ciphers) {
          pki_ofs[0] = ':';
          pki_ofs++;
        }
        strcpy(pki_ofs, ciphers_ofs);
        pki_ofs += strlen(ciphers_ofs);
        pki_ofs[0] = '\000';
#endif /* ! COAP_WOLFSSL_PKI_CIPHERS */
      }
next_a:
      if (cp)
        ciphers_ofs = cp + 1;
      else
        ciphers_ofs = NULL;
    }
#ifndef HAVE_SECURE_RENEGOTIATION
    /*
     * Need to add in dummy "RENEGOTIATION-INFO" at end.
     * This addition will get ignored if the complied library does not
     * support it.
     */
#if ! defined(COAP_WOLFSSL_PSK_CIPHERS)
    if (psk_ofs != psk_ciphers) {
      psk_ofs[0] = ':';
      psk_ofs++;
    }
    strcpy(psk_ofs, "RENEGOTIATION-INFO");
    psk_ofs += strlen("RENEGOTIATION-INFO");
    psk_ofs[0] = '\000';
#endif /* ! COAP_WOLFSSL_PSK_CIPHERS */
#if ! defined(COAP_WOLFSSL_PKI_CIPHERS)
    if (pki_ofs != pki_ciphers) {
      pki_ofs[0] = ':';
      pki_ofs++;
    }
    strcpy(pki_ofs, "RENEGOTIATION-INFO");
    pki_ofs += strlen("RENEGOTIATION-INFO");
    pki_ofs[0] = '\000';
#endif /* ! COAP_WOLFSSL_PSK_CIPHERS */
#endif /* ! HAVE_SECURE_RENEGOTIATION */

    processed_ciphers = 1;
  }
#endif /* ! COAP_WOLFSSL_PSK_CIPHERS || ! COAP_WOLFSSL_PKI_CIPHERS */

  if (method == COAP_ENC_PSK) {
    wolfSSL_set_cipher_list(ssl, psk_ciphers);
  } else {
    wolfSSL_set_cipher_list(ssl, pki_ciphers);
  }
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
static int psk_tls_server_name_call_back(WOLFSSL *ssl, int *sd, void *arg);
#endif /* COAP_SERVER_SUPPORT */
static int tls_verify_call_back(int preverify_ok, WOLFSSL_X509_STORE_CTX *ctx);

int
coap_dtls_is_supported(void) {
  if (wolfSSL_lib_version_hex() < 0x05002000) {
    coap_log_warn("wolfSSL version 5.2.0 or later is required\n");
    return 0;
  }
  return 1;
}

int
coap_tls_is_supported(void) {
#if !COAP_DISABLE_TCP
  if (wolfSSL_lib_version_hex() < 0x05002000) {
    coap_log_warn("wolfSSL version 5.2.0 or later is required\n");
    return 0;
  }
  return 1;
#else /* COAP_DISABLE_TCP */
  return 0;
#endif /* COAP_DISABLE_TCP */
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_psk_is_supported(void) {
  return 1;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_pki_is_supported(void) {
  return 1;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_pkcs11_is_supported(void) {
  return 0;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_rpk_is_supported(void) {
  return 0;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_cid_is_supported(void) {
#if defined(HAVE_RPK) && LIBWOLFSSL_VERSION_HEX >= 0x05006004
  return 1;
#else /* ! HAVE_RPK || LIBWOLFSSL_VERSION_HEX < 0x05006004 */
  return 0;
#endif /* ! HAVE_RPK || LIBWOLFSSL_VERSION_HEX < 0x05006004 */
}

#if COAP_CLIENT_SUPPORT
int
coap_dtls_set_cid_tuple_change(coap_context_t *c_context, uint8_t every) {
#if defined(WOLFSSL_DTLS_CID)
  c_context->testing_cids = every;
  return 1;
#else /* ! WOLFSSL_DTLS_CID */
  (void)c_context;
  (void)every;
  return 0;
#endif /* ! WOLFSSL_DTLS_CID */
}
#endif /* COAP_CLIENT_SUPPORT */

coap_tls_version_t *
coap_get_tls_library_version(void) {
  static coap_tls_version_t version;
  version.version = wolfSSL_lib_version_hex();
  version.built_version = LIBWOLFSSL_VERSION_HEX;
  version.type = COAP_TLS_LIBRARY_WOLFSSL;

  return &version;
}

static void
coap_wolfssl_log_func(int level, const char *text) {
  int use_level;

  switch ((int)level) {
  case ERROR_LOG:
    use_level = COAP_LOG_DEBUG;
    break;
  case INFO_LOG:
    use_level = COAP_LOG_INFO;
    break;
  case ENTER_LOG:
    use_level = COAP_LOG_INFO;
    break;
  case LEAVE_LOG:
    use_level = COAP_LOG_INFO;
    break;
  case OTHER_LOG:
    use_level = COAP_LOG_DEBUG;
    break;
  default:
    use_level = COAP_LOG_DEBUG;
    break;
  }
  coap_dtls_log(use_level, "%s\n", text);
}

void
coap_dtls_startup(void) {
  if (wolfSSL_library_init() != WOLFSSL_SUCCESS) {
    coap_log_err("wolfSSL_library_init: Fail\n");
    return;
  }
  wolfSSL_load_error_strings();
  wolfSSL_SetLoggingCb(coap_wolfssl_log_func);
  wolfSSL_Debugging_ON();
}

void
coap_dtls_shutdown(void) {
  wolfSSL_ERR_free_strings();
  coap_dtls_set_log_level(COAP_LOG_EMERG);
  wolfSSL_Debugging_OFF();
}

void *
coap_dtls_get_tls(const coap_session_t *c_session,
                  coap_tls_library_t *tls_lib) {
  if (tls_lib)
    *tls_lib = COAP_TLS_LIBRARY_WOLFSSL;
  if (c_session) {
    coap_wolfssl_env_t *w_env;

    /* To get around const issue */
    memcpy(&w_env, &c_session->tls, sizeof(w_env));

    return (void *)&w_env->ssl;
  }
  return NULL;
}

/*
 * Logging levels use the standard CoAP logging levels
 */
static coap_log_t dtls_log_level = COAP_LOG_EMERG;

void
coap_dtls_set_log_level(coap_log_t level) {
  dtls_log_level = level;
}

coap_log_t
coap_dtls_get_log_level(void) {
  return dtls_log_level;
}

static int
coap_dgram_read(WOLFSSL *ssl, char *out, int outl, void *ctx) {
  int ret = 0;
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)ctx;
  coap_ssl_data_t *data = w_env ? &w_env->data : NULL;
  coap_tick_t now;

  (void)ssl;
  if (w_env && !w_env->done_psk_check && w_env->ssl) {
    if (wolfSSL_SSL_in_init(w_env->ssl)) {
      const char *name = wolfSSL_get_cipher_name(w_env->ssl);

      if (name) {
        coap_dtls_log(COAP_LOG_DEBUG," Cipher Suite: %s\n", name);

        if (strstr(name, "PSK") &&  w_env->role == COAP_DTLS_ROLE_SERVER) {
          wolfSSL_set_verify(w_env->ssl, WOLFSSL_VERIFY_NONE, tls_verify_call_back);
          w_env->done_psk_check = 1;
        }
      }
    }
  }
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
      coap_ticks(&now);
      w_env->last_timeout = now;
    } else {
      ret = WANT_READ;
    }
  }
  return ret;
}

static int
coap_dgram_write(WOLFSSL *ssl, char *in, int inl, void *ctx) {
  int ret = 0;
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)ctx;
  coap_ssl_data_t *data = w_env ? &w_env->data : NULL;
  coap_tick_t now;

  (void)ssl;
  assert(data);
  if (data->session) {
    if (!coap_netif_available(data->session)
#if COAP_SERVER_SUPPORT
        && data->session->endpoint == NULL
#endif /* COAP_SERVER_SUPPORT */
       ) {
      /* socket was closed on client due to error */
      errno = ECONNRESET;
      return -1;
    }
    ret = (int)data->session->sock.lfunc[COAP_LAYER_TLS].l_write(data->session,
          (const uint8_t *)in,
          inl);
    if (ret > 0) {
      coap_ticks(&now);
      w_env->last_timeout = now;
    }
  } else {
    ret = -1;
  }
  return ret;
}

#if COAP_CLIENT_SUPPORT
static unsigned int
coap_dtls_psk_client_callback(WOLFSSL *ssl,
                              const char *hint,
                              char *identity,
                              unsigned int max_identity_len,
                              unsigned char *psk,
                              unsigned int max_psk_len) {
  coap_session_t *c_session;
  coap_wolfssl_context_t *w_context;
  coap_dtls_cpsk_t *setup_data;
  const coap_dtls_cpsk_info_t *cpsk_info;
  const coap_bin_const_t *psk_key;
  const coap_bin_const_t *psk_identity;

  c_session = (coap_session_t *)wolfSSL_get_app_data(ssl);
  if (c_session == NULL)
    return 0;
  w_context = (coap_wolfssl_context_t *)c_session->context->dtls_context;
  if (w_context == NULL)
    return 0;
  setup_data = &c_session->cpsk_setup_data;

  if (setup_data->validate_ih_call_back) {
    coap_bin_const_t temp;
    coap_str_const_t lhint;

    temp.s = hint ? (const uint8_t *)hint : (const uint8_t *)"";
    temp.length = strlen((const char *)temp.s);
    coap_session_refresh_psk_hint(c_session, &temp);

    coap_log_debug("got psk_identity_hint: '%.*s'\n", (int)temp.length,
                   (const char *)temp.s);


    lhint.s = temp.s;
    lhint.length = temp.length;
    coap_lock_callback_ret(cpsk_info, c_session->context,
                           setup_data->validate_ih_call_back(&lhint,
                                                             c_session,
                                                             setup_data->ih_call_back_arg));

    if (cpsk_info == NULL)
      return 0;

    coap_session_refresh_psk_identity(c_session, &cpsk_info->identity);
    coap_session_refresh_psk_key(c_session, &cpsk_info->key);
    psk_identity = &cpsk_info->identity;
    psk_key = &cpsk_info->key;
  } else {
    psk_identity = coap_get_session_client_psk_identity(c_session);
    psk_key = coap_get_session_client_psk_key(c_session);
  }

  if (psk_identity == NULL || psk_key == NULL) {
    coap_log_warn("no PSK available\n");
    return 0;
  }

  /* identity has to be NULL terminated */
  if (!max_identity_len)
    return 0;
  max_identity_len--;
  if (psk_identity->length > max_identity_len) {
    coap_log_warn("psk_identity too large, truncated to %d bytes\n",
                  max_identity_len);
  } else {
    /* Reduce to match */
    max_identity_len = (unsigned int)psk_identity->length;
  }
  memcpy(identity, psk_identity->s, max_identity_len);
  identity[max_identity_len] = '\000';

  if (psk_key->length > max_psk_len) {
    coap_log_warn("psk_key too large, truncated to %d bytes\n",
                  max_psk_len);
  } else {
    /* Reduce to match */
    max_psk_len = (unsigned int)psk_key->length;
  }
  memcpy(psk, psk_key->s, max_psk_len);
  return max_psk_len;
}

static unsigned int
coap_dtls_psk_client_cs_callback(WOLFSSL *ssl, const char *hint,
                                 char *identity, unsigned int max_identity_len,
                                 unsigned char *psk, unsigned int max_psk_len,
                                 const char *ciphersuite) {
  int key_len = coap_dtls_psk_client_callback(ssl,
                                              hint,
                                              identity,
                                              max_identity_len,
                                              psk,
                                              max_psk_len);

  (void)ciphersuite;
  return key_len;
}

#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
static unsigned int
coap_dtls_psk_server_callback(
    WOLFSSL *ssl,
    const char *identity,
    unsigned char *psk,
    unsigned int max_psk_len) {
  coap_session_t *c_session;
  coap_dtls_spsk_t *setup_data;
  coap_bin_const_t lidentity;
  const coap_bin_const_t *psk_key;

  c_session = (coap_session_t *)wolfSSL_get_app_data(ssl);
  if (c_session == NULL)
    return 0;

  setup_data = &c_session->context->spsk_setup_data;

  /* Track the Identity being used */
  lidentity.s = identity ? (const uint8_t *)identity : (const uint8_t *)"";
  lidentity.length = strlen((const char *)lidentity.s);
  coap_session_refresh_psk_identity(c_session, &lidentity);

  coap_log_debug("got psk_identity: '%.*s'\n",
                 (int)lidentity.length, (const char *)lidentity.s);

  if (setup_data->validate_id_call_back) {
    psk_key = setup_data->validate_id_call_back(&lidentity,
                                                c_session,
                                                setup_data->id_call_back_arg);

    coap_session_refresh_psk_key(c_session, psk_key);
  } else {
    psk_key = coap_get_session_server_psk_key(c_session);
  }

  if (psk_key == NULL)
    return 0;

  if (psk_key->length > max_psk_len) {
    coap_log_warn("psk_key too large, truncated to %d bytes\n",
                  max_psk_len);
  } else {
    /* Reduce to match */
    max_psk_len = (unsigned int)psk_key->length;
  }
  memcpy(psk, psk_key->s, max_psk_len);
  return max_psk_len;
}
#endif /* COAP_SERVER_SUPPORT */

static const char *
ssl_function_definition(unsigned long e) {
  static char buff[80];

  snprintf(buff, sizeof(buff), " at %s:%s",
           wolfSSL_ERR_lib_error_string(e), wolfSSL_ERR_func_error_string(e));
  return buff;
}

static void
coap_dtls_info_callback(const WOLFSSL *ssl, int where, int ret) {
  coap_session_t *session = (coap_session_t *)wolfSSL_get_app_data(ssl);
  const char *pstr;
  int w = where &~SSL_ST_MASK;

  if (w & SSL_ST_CONNECT)
    pstr = "wolfSSL_connect";
  else if (w & SSL_ST_ACCEPT)
    pstr = "wolfSSL_accept";
  else
    pstr = "undefined";

  if (where & SSL_CB_LOOP) {
    coap_dtls_log(COAP_LOG_DEBUG, "*  %s: %s:%s\n",
                  coap_session_str(session), pstr, wolfSSL_state_string_long(ssl));
  } else if (where & SSL_CB_ALERT) {
    coap_log_t log_level = COAP_LOG_INFO;
    pstr = (where & SSL_CB_READ) ? "read" : "write";
    if ((where & (SSL_CB_WRITE|SSL_CB_READ)) && (ret >> 8) == WOLFSSL3_AL_FATAL) {
      session->dtls_event = COAP_EVENT_DTLS_ERROR;
      if ((ret & 0xff) != close_notify)
        log_level = COAP_LOG_WARN;
    }

    /* Need to let CoAP logging know why this session is dying */
    coap_log(log_level, "*  %s: SSL3 alert %s:%s:%s\n",
             coap_session_str(session),
             pstr,
             wolfSSL_alert_type_string_long(ret),
             wolfSSL_alert_desc_string_long(ret));
  } else if (where & SSL_CB_EXIT) {
    if (ret == 0) {
      if (dtls_log_level >= COAP_LOG_WARN) {
        unsigned long e;
        coap_dtls_log(COAP_LOG_WARN, "*  %s: %s:failed in %s\n",
                      coap_session_str(session), pstr, wolfSSL_state_string_long(ssl));
        while ((e = wolfSSL_ERR_get_error()))
          coap_dtls_log(COAP_LOG_WARN, "*  %s: %s%s\n",
                        coap_session_str(session), wolfSSL_ERR_reason_error_string(e),
                        ssl_function_definition(e));
      }
    } else if (ret < 0) {
      if (dtls_log_level >= COAP_LOG_WARN) {
        WOLFSSL *rw_ssl;

        /* Need to do this to not get a compiler warning about const parameters */
        memcpy(&rw_ssl, &ssl, sizeof(rw_ssl));
        int err = wolfSSL_get_error(rw_ssl, ret);
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE &&
            err != WOLFSSL_ERROR_WANT_CONNECT && err != WOLFSSL_ERROR_WANT_ACCEPT &&
            err != WOLFSSL_ERROR_WANT_X509_LOOKUP) {
          long e;
          coap_dtls_log(COAP_LOG_WARN, "*  %s: %s:error in %s\n",
                        coap_session_str(session), pstr, wolfSSL_state_string_long(ssl));
          while ((e = wolfSSL_ERR_get_error()))
            coap_dtls_log(COAP_LOG_WARN, "*  %s: %s%s\n",
                          coap_session_str(session), wolfSSL_ERR_reason_error_string(e),
                          ssl_function_definition(e));
        }
      }
    }
  }

  if (where == SSL_CB_HANDSHAKE_START) {
    WOLFSSL *rw_ssl;

    /* Need to do this to not get a compiler warning about const parameters */
    memcpy(&rw_ssl, &ssl, sizeof(rw_ssl));
    if (wolfSSL_is_init_finished(rw_ssl))
      session->dtls_event = COAP_EVENT_DTLS_RENEGOTIATE;
  }
}

/*
 * strm
 * return +ve data amount
 *        0   no more
 *        -1  error
 */
static int
coap_sock_read(WOLFSSL *ssl, char *out, int outl, void *ctx) {
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)ctx;
  int ret = 0;
  coap_session_t *session = w_env ? w_env->data.session : NULL;

  (void)ssl;
  assert(session);
  if (w_env && !w_env->done_psk_check && w_env->ssl &&
      w_env->role == COAP_DTLS_ROLE_SERVER) {
    if (wolfSSL_SSL_in_init(w_env->ssl)) {
      const char *name = wolfSSL_get_cipher_name(w_env->ssl);

      if (name) {
        coap_dtls_log(COAP_LOG_DEBUG,"Cipher Suite: %s\n", name);

        if (strstr(name, "PSK")) {
          wolfSSL_set_verify(w_env->ssl, WOLFSSL_VERIFY_NONE, tls_verify_call_back);
          w_env->done_psk_check = 1;
        }
      }
    }
  }
  if (out != NULL) {
    ret =(int)session->sock.lfunc[COAP_LAYER_TLS].l_read(session, (u_char *)out,
                                                         outl);
    if (ret == 0) {
      ret = WANT_READ;
    }
  }
  return ret;
}

/*
 * strm
 * return +ve data amount
 *        0   no more
 *        -1  error (error in errno)
 */
static int
coap_sock_write(WOLFSSL *ssl, char *in, int inl, void *ctx) {
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)ctx;
  int ret = 0;
  coap_session_t *session = w_env ? w_env->data.session : NULL;

  (void)ssl;
  assert(session);
  ret = (int)session->sock.lfunc[COAP_LAYER_TLS].l_write(session,
                                                         (const uint8_t *)in,
                                                         inl);
  /* Translate layer what returns into what wolfSSL expects */
  if (ret == 0) {
    ret = -1;
  } else {
    if (ret == -1) {
      if ((session->state == COAP_SESSION_STATE_CSM ||
           session->state == COAP_SESSION_STATE_HANDSHAKE) &&
          (errno == EPIPE || errno == ECONNRESET)) {
        /*
         * Need to handle a TCP timing window where an agent continues with
         * the sending of the next handshake or a CSM.
         * However, the peer does not like a certificate and so sends a
         * fatal alert and closes the TCP session.
         * The sending of the next handshake or CSM may get terminated because
         * of the closed TCP session, but there is still an outstanding alert
         * to be read in and reported on.
         * In this case, pretend that sending the info was fine so that the
         * alert can be read (which effectively is what happens with DTLS).
         */
        ret = inl;
      }
    }
  }
  return ret;
}

static void
coap_set_user_prefs(WOLFSSL_CTX *ctx) {
  (void)ctx;

#ifdef COAP_WOLFSSL_SIGALGS
  wolfSSL_CTX_set1_sigalgs_list(ctx, COAP_WOLFSSL_SIGALGS);
#endif
#ifdef COAP_WOLFSSL_GROUPS
  int ret;
  ret = wolfSSL_CTX_set1_groups_list(ctx,
                                     (char *) COAP_WOLFSSL_GROUPS);
  if (ret != WOLFSSL_SUCCESS) {
    coap_log_debug("Failed to set group list\n");
  }
#endif
}

/* Set up DTLS context if not alread done */
static int
setup_dtls_context(coap_wolfssl_context_t *w_context) {
  if (!w_context->dtls.ctx) {
    uint8_t cookie_secret[32];

    /* Set up DTLS context */
    w_context->dtls.ctx = wolfSSL_CTX_new(wolfDTLS_method());
    if (!w_context->dtls.ctx)
      goto error;
    wolfSSL_CTX_set_min_proto_version(w_context->dtls.ctx,
                                      DTLS1_2_VERSION);
    wolfSSL_CTX_set_ex_data(w_context->dtls.ctx, 0, &w_context->dtls);
    coap_set_user_prefs(w_context->dtls.ctx);
    memset(cookie_secret, 0, sizeof(cookie_secret));
    if (!wolfSSL_RAND_bytes(cookie_secret, (int)sizeof(cookie_secret))) {
      coap_dtls_log(COAP_LOG_WARN,
                    "Insufficient entropy for random cookie generation");
      coap_prng_lkd(cookie_secret, sizeof(cookie_secret));
    }
    w_context->dtls.cookie_hmac = wolfSSL_HMAC_CTX_new();
    if (!wolfSSL_HMAC_Init_ex(w_context->dtls.cookie_hmac, cookie_secret, (int)sizeof(cookie_secret),
                              wolfSSL_EVP_sha256(), NULL))
      goto error;

    wolfSSL_CTX_set_info_callback(w_context->dtls.ctx, coap_dtls_info_callback);
    wolfSSL_CTX_set_options(w_context->dtls.ctx, SSL_OP_NO_QUERY_MTU);
    wolfSSL_SetIORecv(w_context->dtls.ctx, coap_dgram_read);
    wolfSSL_SetIOSend(w_context->dtls.ctx, coap_dgram_write);
#ifdef WOLFSSL_DTLS_MTU
    wolfSSL_CTX_dtls_set_mtu(w_context->dtls.ctx, COAP_DEFAULT_MTU);
#endif /* WOLFSSL_DTLS_MTU */
    if (w_context->root_ca_file || w_context->root_ca_dir) {
      if (!wolfSSL_CTX_load_verify_locations_ex(w_context->dtls.ctx,
                                                w_context->root_ca_file,
                                                w_context->root_ca_dir,
                                                w_context->setup_data.allow_expired_certs ?
                                                WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY : 0)) {
        coap_log_warn("Unable to install root CAs (%s/%s)\n",
                      w_context->root_ca_file ? w_context->root_ca_file : "NULL",
                      w_context->root_ca_dir ? w_context->root_ca_dir : "NULL");
        goto error;
      }
    }
    /* Verify Peer */
    if (w_context->setup_data.verify_peer_cert)
      wolfSSL_CTX_set_verify(w_context->dtls.ctx,
                             WOLFSSL_VERIFY_PEER |
                             WOLFSSL_VERIFY_CLIENT_ONCE |
                             WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                             tls_verify_call_back);
    else
      wolfSSL_CTX_set_verify(w_context->dtls.ctx, WOLFSSL_VERIFY_NONE, tls_verify_call_back);
  }
  return 1;

error:
  coap_log_warn("wolfssl: unable to set up DTLS context\n");
  return 0;
}

#if !COAP_DISABLE_TCP

/* Set up TLS context if not alread done */
static int
setup_tls_context(coap_wolfssl_context_t *w_context) {
  if (!w_context->tls.ctx) {
    /* Set up TLS context */
    w_context->tls.ctx = wolfSSL_CTX_new(wolfSSLv23_method());
    if (!w_context->tls.ctx)
      goto error;
    wolfSSL_CTX_set_ex_data(w_context->tls.ctx, 0, &w_context->tls);
    wolfSSL_CTX_set_min_proto_version(w_context->tls.ctx, TLS1_VERSION);
    coap_set_user_prefs(w_context->tls.ctx);
    wolfSSL_CTX_set_info_callback(w_context->tls.ctx, coap_dtls_info_callback);
    wolfSSL_SetIORecv(w_context->tls.ctx, coap_sock_read);
    wolfSSL_SetIOSend(w_context->tls.ctx, coap_sock_write);
#if COAP_CLIENT_SUPPORT
    if (w_context->psk_pki_enabled & IS_PSK) {
      wolfSSL_CTX_set_psk_client_cs_callback(w_context->tls.ctx,
                                             coap_dtls_psk_client_cs_callback);
    }
#endif /* COAP_CLIENT_SUPPORT */
    if (w_context->root_ca_file || w_context->root_ca_dir) {
      if (!wolfSSL_CTX_load_verify_locations_ex(w_context->tls.ctx,
                                                w_context->root_ca_file,
                                                w_context->root_ca_dir,
                                                w_context->setup_data.allow_expired_certs ?
                                                WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY : 0)) {
        coap_log_warn("Unable to install root CAs (%s/%s)\n",
                      w_context->root_ca_file ? w_context->root_ca_file : "NULL",
                      w_context->root_ca_dir ? w_context->root_ca_dir : "NULL");
        goto error;
      }
    }
    /* Verify Peer */
    if (w_context->setup_data.verify_peer_cert)
      wolfSSL_CTX_set_verify(w_context->tls.ctx,
                             WOLFSSL_VERIFY_PEER |
                             WOLFSSL_VERIFY_CLIENT_ONCE |
                             WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                             tls_verify_call_back);
    else
      wolfSSL_CTX_set_verify(w_context->tls.ctx, WOLFSSL_VERIFY_NONE, tls_verify_call_back);
  }
  return 1;

error:
  coap_log_warn("wolfssl: unable to set up TLS context\n");
  return 0;
}
#endif /* ! COAP_DISABLE_TCP */

void *
coap_dtls_new_context(coap_context_t *c_context) {
  coap_wolfssl_context_t *w_context;
  (void)c_context;

  w_context = (coap_wolfssl_context_t *)wolfssl_malloc(sizeof(coap_wolfssl_context_t));
  if (w_context) {
    memset(w_context, 0, sizeof(coap_wolfssl_context_t));
  }

  return w_context;
}

#if COAP_SERVER_SUPPORT
int
coap_dtls_context_set_spsk(coap_context_t *c_context,
                           coap_dtls_spsk_t *setup_data
                          ) {
  coap_wolfssl_context_t *w_context =
      ((coap_wolfssl_context_t *)c_context->dtls_context);

  if (!setup_data || !w_context)
    return 0;

  if (!setup_dtls_context(w_context))
    return 0;
#if !COAP_DISABLE_TCP
  if (!setup_tls_context(w_context))
    return 0;
#endif /* !COAP_DISABLE_TCP */

  wolfSSL_CTX_set_psk_server_callback(w_context->dtls.ctx,
                                      coap_dtls_psk_server_callback);

#if !COAP_DISABLE_TCP
  wolfSSL_CTX_set_psk_server_callback(w_context->tls.ctx,
                                      coap_dtls_psk_server_callback);
#endif /* !COAP_DISABLE_TCP */
  if (setup_data->psk_info.hint.s) {
    char hint[COAP_DTLS_HINT_LENGTH];
    snprintf(hint, sizeof(hint), "%.*s", (int)setup_data->psk_info.hint.length,
             setup_data->psk_info.hint.s);
    wolfSSL_CTX_use_psk_identity_hint(w_context->dtls.ctx, hint);
#if !COAP_DISABLE_TCP
    wolfSSL_CTX_use_psk_identity_hint(w_context->tls.ctx, hint);
#endif /* !COAP_DISABLE_TCP */
  }
  if (setup_data->validate_sni_call_back) {
    wolfSSL_CTX_set_servername_arg(w_context->dtls.ctx,
                                   &c_context->spsk_setup_data);
    wolfSSL_CTX_set_tlsext_servername_callback(w_context->dtls.ctx,
                                               psk_tls_server_name_call_back);
#if !COAP_DISABLE_TCP
    wolfSSL_CTX_set_servername_arg(w_context->tls.ctx,
                                   &c_context->spsk_setup_data);
    wolfSSL_CTX_set_tlsext_servername_callback(w_context->tls.ctx,
                                               psk_tls_server_name_call_back);
#endif /* !COAP_DISABLE_TCP */
  }
  if (setup_data->ec_jpake) {
    coap_log_warn("wolfSSL has no EC-JPAKE support\n");
  }
  w_context->psk_pki_enabled |= IS_PSK;
  return 1;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
int
coap_dtls_context_set_cpsk(coap_context_t *c_context,
                           coap_dtls_cpsk_t *setup_data
                          ) {
  coap_wolfssl_context_t *w_context =
      ((coap_wolfssl_context_t *)c_context->dtls_context);

  if (!setup_data || !w_context)
    return 0;

  if (setup_data->ec_jpake) {
    coap_log_warn("wolfSSL has no EC-JPAKE support\n");
  }
  if (setup_data->use_cid) {
#if ! defined(WOLFSSL_DTLS_CID)
    coap_log_warn("wolfSSL has no Connection-ID support\n");
#endif /* ! WOLFSSL_DTLS_CID */
  }
  w_context->psk_pki_enabled |= IS_PSK;
  return 1;
}
#endif /* COAP_CLIENT_SUPPORT */

#if !COAP_DISABLE_TCP
static uint8_t coap_alpn[] = { 4, 'c', 'o', 'a', 'p' };

#if COAP_SERVER_SUPPORT
static int
server_alpn_callback(WOLFSSL *ssl COAP_UNUSED,
                     const unsigned char **out,
                     unsigned char *outlen,
                     const unsigned char *in,
                     unsigned int inlen,
                     void *arg COAP_UNUSED
                    ) {
  unsigned char *tout = NULL;
  int ret;
  if (inlen == 0)
    return SSL_TLSEXT_ERR_NOACK;
  ret = wolfSSL_select_next_proto(&tout,
                                  outlen,
                                  coap_alpn,
                                  sizeof(coap_alpn),
                                  in,
                                  inlen);
  *out = tout;
  return (ret != OPENSSL_NPN_NEGOTIATED) ? noack_return : WOLFSSL_TLSEXT_ERR_OK;
}
#endif /* COAP_SERVER_SUPPORT */
#endif /* !COAP_DISABLE_TCP */

static int
setup_pki_ssl(WOLFSSL *ssl,
              coap_dtls_pki_t *setup_data, coap_dtls_role_t role) {
  coap_dtls_key_t key;
  WOLFSSL_CTX *ctx = wolfSSL_get_SSL_CTX(ssl);

  /* Map over to the new define format to save code duplication */
  coap_dtls_map_key_type_to_define(setup_data, &key);

  assert(key.key_type == COAP_PKI_KEY_DEFINE);

  /*
   * Configure the Private Key
   */
  if (key.key.define.private_key.u_byte &&
      key.key.define.private_key.u_byte[0]) {
    switch (key.key.define.private_key_def) {
    case COAP_PKI_KEY_DEF_PEM: /* define private key */
      if (!(wolfSSL_use_PrivateKey_file(ssl,
                                        key.key.define.private_key.s_byte,
                                        WOLFSSL_FILETYPE_PEM))) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, 0);
      }
      break;
    case COAP_PKI_KEY_DEF_PEM_BUF: /* define private key */
      if (!(wolfSSL_use_PrivateKey_buffer(ssl,
                                          key.key.define.private_key.u_byte,
                                          (long)key.key.define.private_key_len,
                                          WOLFSSL_FILETYPE_PEM))) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, 0);
      }
      break;
    case COAP_PKI_KEY_DEF_RPK_BUF: /* define private key */
#if defined(HAVE_RPK) && LIBWOLFSSL_VERSION_HEX >= 0x05006004
      if (!(wolfSSL_use_PrivateKey_buffer(ssl,
                                          key.key.define.private_key.u_byte,
                                          (long)key.key.define.private_key_len,
                                          WOLFSSL_FILETYPE_PEM))) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, 0);
      }
      break;
#else /* ! HAVE_RPK || ! LIBWOLFSSL_VERSION_HEX >= 0x05006004 */
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                    &key, role, 0);
#endif /* ! HAVE_RPK || ! LIBWOLFSSL_VERSION_HEX >= 0x05006004 */
    case COAP_PKI_KEY_DEF_DER: /* define private key */
      if (!(wolfSSL_use_PrivateKey_file(ssl,
                                        key.key.define.private_key.s_byte,
                                        WOLFSSL_FILETYPE_ASN1))) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, 0);
      }
      break;
    case COAP_PKI_KEY_DEF_DER_BUF: /* define private key */
      if (!(wolfSSL_use_PrivateKey_buffer(ssl,
                                          key.key.define.private_key.u_byte,
                                          (long)key.key.define.private_key_len,
                                          WOLFSSL_FILETYPE_ASN1))) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, 0);
      }
      break;
    case COAP_PKI_KEY_DEF_PKCS11: /* define private key */
    case COAP_PKI_KEY_DEF_PKCS11_RPK: /* define private key */
    case COAP_PKI_KEY_DEF_ENGINE: /* define private key */
    default:
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                    &key, role, 0);
    }
  } else if (role == COAP_DTLS_ROLE_SERVER ||
             (key.key.define.public_cert.u_byte &&
              key.key.define.public_cert.u_byte[0])) {
    return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                  COAP_DEFINE_FAIL_NONE,
                                  &key, role, 0);
  }

  /*
   * Configure the Public Certificate / Key
   */
  if (key.key.define.public_cert.u_byte &&
      key.key.define.public_cert.u_byte[0]) {
    switch (key.key.define.public_cert_def) {
    case COAP_PKI_KEY_DEF_PEM: /* define public cert */
      if (!(wolfSSL_use_certificate_chain_file(ssl,
                                               key.key.define.public_cert.s_byte))) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, 0);
      }
      break;
    case COAP_PKI_KEY_DEF_PEM_BUF: /* define public cert */
      if (!(wolfSSL_use_certificate_chain_buffer(ssl,
                                                 key.key.define.private_key.u_byte,
                                                 (long)key.key.define.private_key_len))) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, 0);
      }
      break;
    case COAP_PKI_KEY_DEF_RPK_BUF: /* define public cert */
#if defined(HAVE_RPK) && LIBWOLFSSL_VERSION_HEX >= 0x05006004
      {
        unsigned char der_buff[512];
        int ret = -1;;
        char ctype[] = {WOLFSSL_CERT_TYPE_RPK};
        char stype[] = {WOLFSSL_CERT_TYPE_RPK};

        wolfSSL_set_client_cert_type(ssl, ctype, sizeof(ctype)/sizeof(ctype[0]));
        wolfSSL_set_server_cert_type(ssl, stype, sizeof(stype)/sizeof(stype[0]));

        ret = wolfSSL_PubKeyPemToDer(key.key.define.public_cert.u_byte,
                                     (int)key.key.define.public_cert_len,
                                     der_buff, (int)sizeof(der_buff));
        if (ret <= 0) {
          ret = wolfSSL_KeyPemToDer(key.key.define.public_cert.u_byte,
                                    (int)key.key.define.public_cert_len,
                                    der_buff, (int)sizeof(der_buff), NULL);
          if (ret > 0) {
            coap_binary_t *spki = get_asn1_spki(der_buff, ret);

            if (!spki) {
              return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                            COAP_DEFINE_FAIL_BAD,
                                            &key, role, 0);
            }
            if (!wolfSSL_use_PrivateKey_buffer(ssl, der_buff, ret, WOLFSSL_FILETYPE_ASN1)) {
              return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                            COAP_DEFINE_FAIL_BAD,
                                            &key, role, 0);
            }
            if (!wolfSSL_use_certificate_buffer(ssl, spki->s, spki->length, WOLFSSL_FILETYPE_ASN1)) {
              coap_delete_binary(spki);
              return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                            COAP_DEFINE_FAIL_BAD,
                                            &key, role, 0);
            }
            coap_delete_binary(spki);
            break;
          }
        }
        if (ret <= 0) {
          return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                        COAP_DEFINE_FAIL_BAD,
                                        &key, role, 0);
        }
        if (!wolfSSL_use_certificate_buffer(ssl, der_buff, ret, WOLFSSL_FILETYPE_ASN1)) {
          return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                        COAP_DEFINE_FAIL_BAD,
                                        &key, role, 0);
        }
      }
      break;
#else /* ! HAVE_RPK || ! LIBWOLFSSL_VERSION_HEX >= 0x05006004 */
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                    &key, role, 0);
#endif /* ! HAVE_RPK || ! LIBWOLFSSL_VERSION_HEX >= 0x05006004 */
    case COAP_PKI_KEY_DEF_DER: /* define public cert */
      if (!(wolfSSL_use_certificate_file(ssl,
                                         key.key.define.public_cert.s_byte,
                                         WOLFSSL_FILETYPE_ASN1))) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, 0);
      }
      break;
    case COAP_PKI_KEY_DEF_DER_BUF: /* define public cert */
      if (!(wolfSSL_use_certificate_buffer(ssl,
                                           key.key.define.public_cert.u_byte,
                                           (int)key.key.define.public_cert_len,
                                           WOLFSSL_FILETYPE_ASN1))) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, 0);
      }
      break;
    case COAP_PKI_KEY_DEF_PKCS11: /* define public cert */
    case COAP_PKI_KEY_DEF_PKCS11_RPK: /* define public cert */
    case COAP_PKI_KEY_DEF_ENGINE: /* define public cert */
    default:
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                    &key, role, 0);
    }
  } else if (role == COAP_DTLS_ROLE_SERVER ||
             (key.key.define.private_key.u_byte &&
              key.key.define.private_key.u_byte[0])) {
    return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                  COAP_DEFINE_FAIL_NONE,
                                  &key, role, 0);
  }
#if defined(HAVE_RPK) && LIBWOLFSSL_VERSION_HEX >= 0x05006004
  else {
    char stype[] = {WOLFSSL_CERT_TYPE_X509, WOLFSSL_CERT_TYPE_RPK};
    wolfSSL_set_server_cert_type(ssl, stype, sizeof(stype)/sizeof(stype[0]));
  }
#endif /* HAVE_RPK && LIBWOLFSSL_VERSION_HEX >= 0x05006004 */

  /*
   * Configure the CA
   */
  if (setup_data->check_common_ca && key.key.define.ca.u_byte &&
      key.key.define.ca.u_byte[0]) {
    switch (key.key.define.ca_def) {
    case COAP_PKI_KEY_DEF_PEM:
      if (!wolfSSL_CTX_load_verify_locations_ex(ctx,
                                                key.key.define.ca.s_byte,
                                                NULL,
                                                setup_data->allow_expired_certs ?
                                                WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY : 0)) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, 0);
      }
      break;
    case COAP_PKI_KEY_DEF_PEM_BUF: /* define ca */
      if (!wolfSSL_CTX_load_verify_buffer_ex(ctx,
                                             key.key.define.ca.u_byte,
                                             key.key.define.ca_len,
                                             SSL_FILETYPE_PEM,
                                             0,
                                             setup_data->allow_expired_certs ?
                                             WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY : 0)) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, 0);
      }
      break;
    case COAP_PKI_KEY_DEF_RPK_BUF: /* define ca */
      /* Ignore if set */
      break;
    case COAP_PKI_KEY_DEF_DER: /* define ca */
      if (!wolfSSL_CTX_load_verify_locations_ex(ctx,
                                                key.key.define.ca.s_byte,
                                                NULL,
                                                setup_data->allow_expired_certs ?
                                                WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY : 0)) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, 0);
      }
      break;
    case COAP_PKI_KEY_DEF_DER_BUF: /* define ca */
      if (!wolfSSL_CTX_load_verify_buffer_ex(ctx,
                                             key.key.define.ca.u_byte,
                                             key.key.define.ca_len,
                                             SSL_FILETYPE_ASN1,
                                             0,
                                             setup_data->allow_expired_certs ?
                                             WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY : 0)) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, 0);
      }
      break;
    case COAP_PKI_KEY_DEF_PKCS11: /* define ca */
    case COAP_PKI_KEY_DEF_PKCS11_RPK: /* define ca */
    case COAP_PKI_KEY_DEF_ENGINE: /* define ca */
    default:
      return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                    &key, role, 0);
    }
  }
  return 1;
}

static char *
get_san_or_cn_from_cert(WOLFSSL_X509 *x509) {
  if (x509) {
    char *cn;
    int n;
    WOLF_STACK_OF(WOLFSSL_GENERAL_NAME) *san_list;
    char buffer[256];

    buffer[0] = '\000';
    san_list = wolfSSL_X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
    if (san_list) {
      int san_count = wolfSSL_sk_GENERAL_NAME_num(san_list);

      for (n = 0; n < san_count; n++) {
        const WOLFSSL_GENERAL_NAME *name = wolfSSL_sk_GENERAL_NAME_value(san_list, n);

        if (name->type == GEN_DNS) {
          const char *dns_name = (const char *)wolfSSL_ASN1_STRING_get0_data(name->d.dNSName);

          /* Make sure that there is not an embedded NUL in the dns_name */
          if (wolfSSL_ASN1_STRING_length(name->d.dNSName) != (int)strlen(dns_name))
            continue;
          cn = wolfssl_strdup(dns_name);
          wolfSSL_sk_GENERAL_NAME_pop_free(san_list, wolfSSL_GENERAL_NAME_free);
          return cn;
        }
      }
      wolfSSL_sk_GENERAL_NAME_pop_free(san_list, wolfSSL_GENERAL_NAME_free);
    }
    /* Otherwise look for the CN= field */
    wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name((WOLFSSL_X509 *)(x509)), buffer,
                              sizeof(buffer));

    /* Need to emulate strcasestr() here.  Looking for CN= */
    n = (int)strlen(buffer) - 3;
    cn = buffer;
    while (n > 0) {
      if (((cn[0] == 'C') || (cn[0] == 'c')) &&
          ((cn[1] == 'N') || (cn[1] == 'n')) &&
          (cn[2] == '=')) {
        cn += 3;
        break;
      }
      cn++;
      n--;
    }
    if (n > 0) {
      char *ecn = strchr(cn, '/');
      if (ecn) {
        return wolfssl_strndup(cn, ecn-cn);
      } else {
        return wolfssl_strdup(cn);
      }
    }
  }
  return NULL;
}

static int
tls_verify_call_back(int preverify_ok, WOLFSSL_X509_STORE_CTX *ctx) {
  WOLFSSL *ssl = wolfSSL_X509_STORE_CTX_get_ex_data(ctx,
                                                    wolfSSL_get_ex_data_X509_STORE_CTX_idx());
  coap_session_t *session = wolfSSL_get_app_data(ssl);
  coap_wolfssl_context_t *w_context =
      ((coap_wolfssl_context_t *)session->context->dtls_context);
  coap_dtls_pki_t *setup_data = &w_context->setup_data;
  int depth = wolfSSL_X509_STORE_CTX_get_error_depth(ctx);
  int err = wolfSSL_X509_STORE_CTX_get_error(ctx);
  WOLFSSL_X509 *x509 = wolfSSL_X509_STORE_CTX_get_current_cert(ctx);
  char *cn = NULL;
  int keep_preverify_ok = preverify_ok;

  if (setup_data->is_rpk_not_cert) {
    cn = wolfssl_strdup("RPK");
  } else {
    cn = get_san_or_cn_from_cert(x509);
  }
  if (!preverify_ok) {
    switch (err) {
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case ASN_NO_SIGNER_E:
    case ASN_AFTER_DATE_E:
      if (setup_data->allow_expired_certs)
        preverify_ok = 1;
      break;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
      if (setup_data->allow_self_signed && !setup_data->check_common_ca)
        preverify_ok = 1;
      break;
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: /* Set if the CA is not known */
      if (!setup_data->verify_peer_cert)
        preverify_ok = 1;
      break;
    case X509_V_ERR_UNABLE_TO_GET_CRL:
      if (setup_data->allow_no_crl)
        preverify_ok = 1;
      break;
    case X509_V_ERR_CRL_NOT_YET_VALID:
    case X509_V_ERR_CRL_HAS_EXPIRED:
      if (setup_data->allow_expired_crl)
        preverify_ok = 1;
      break;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_AKID_SKID_MISMATCH:
      if (!setup_data->verify_peer_cert)
        preverify_ok = 1;
      break;
    default:
      break;
    }
    if (setup_data->cert_chain_validation &&
        depth > (setup_data->cert_chain_verify_depth + 1)) {
      preverify_ok = 0;
      err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
      wolfSSL_X509_STORE_CTX_set_error(ctx, err);
    }
    if (!preverify_ok) {
      if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
        coap_log_warn("   %s: %s: '%s' depth=%d\n",
                      coap_session_str(session),
                      "Unknown CA", cn ? cn : "?", depth);
      } else {
        coap_log_warn("   %s: %s: '%s' depth=%d\n",
                      coap_session_str(session),
                      wolfSSL_X509_verify_cert_error_string(err), cn ? cn : "?", depth);
      }
    } else {
      coap_log_info("   %s: %s: overridden: '%s' depth=%d\n",
                    coap_session_str(session),
                    wolfSSL_X509_verify_cert_error_string(err), cn ? cn : "?", depth);
    }
  }
  /* Certificate - depth == 0 is the Client Cert */
  if (setup_data->validate_cn_call_back && keep_preverify_ok) {
    int length = wolfSSL_i2d_X509(x509, NULL);

    if (length > 0) {
      uint8_t *base_buf;
      uint8_t *base_buf2 = base_buf = wolfssl_malloc(length);
      int ret;

      /* base_buf2 gets moved to the end */
      wolfSSL_i2d_X509(x509, &base_buf2);
      coap_lock_callback_ret(ret, session->context,
                             setup_data->validate_cn_call_back(cn, base_buf, length, session,
                                                               depth, preverify_ok,
                                                               setup_data->cn_call_back_arg));
      if (!ret) {
        if (depth == 0) {
          wolfSSL_X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
        } else {
          wolfSSL_X509_STORE_CTX_set_error(ctx, X509_V_ERR_INVALID_CA);
        }
        preverify_ok = 0;
      }
      wolfssl_free(base_buf);
    }
  }
  wolfssl_free(cn);
  return preverify_ok;
}

#if COAP_SERVER_SUPPORT

/*
 * During the SSL/TLS initial negotiations, tls_server_name_call_back() is
 * called so it is possible to set up an extra callback to determine whether
 * this is a PKI or PSK incoming request and adjust the ciphers if necessary
 *
 * Set up by SSL_CTX_set_tlsext_servername_callback() in
 * coap_dtls_context_set_pki()
 */
static int
tls_server_name_call_back(WOLFSSL *ssl,
                          int *sd COAP_UNUSED,
                          void *arg) {
  coap_dtls_pki_t *setup_data = (coap_dtls_pki_t *)arg;
  coap_session_t *session = (coap_session_t *)wolfSSL_get_app_data(ssl);
  coap_wolfssl_context_t *w_context =
      ((coap_wolfssl_context_t *)session->context->dtls_context);

  if (!ssl) {
    return noack_return;
  }

  if (setup_data->validate_sni_call_back) {
    /* SNI checking requested */
    const char *sni = wolfSSL_get_servername(ssl, WOLFSSL_SNI_HOST_NAME);
    coap_dtls_pki_t sni_setup_data;
    coap_dtls_key_t *new_entry;

    if (!sni || !sni[0]) {
      sni = "";
    }
    coap_lock_callback_ret(new_entry, session->context,
                           setup_data->validate_sni_call_back(sni,
                                                              setup_data->sni_call_back_arg));
    if (!new_entry) {
      return fatal_return;
    }
    sni_setup_data = *setup_data;
    sni_setup_data.pki_key = *new_entry;
    setup_pki_ssl(ssl, &sni_setup_data, COAP_DTLS_ROLE_SERVER);
  }

  if (w_context->psk_pki_enabled & IS_PSK) {
    wolfSSL_set_psk_server_callback(ssl, coap_dtls_psk_server_callback);
  }
  return SSL_TLSEXT_ERR_OK;
}

/*
 * During the SSL/TLS initial negotiations, psk_tls_server_name_call_back() is
 * called to see if SNI is being used.
 *
 * Set up by SSL_CTX_set_tlsext_servername_callback()
 * in coap_dtls_context_set_spsk()
 */
static int
psk_tls_server_name_call_back(WOLFSSL *ssl,
                              int *sd COAP_UNUSED,
                              void *arg
                             ) {
  coap_dtls_spsk_t *setup_data = (coap_dtls_spsk_t *)arg;
  coap_session_t *c_session = (coap_session_t *)wolfSSL_get_app_data(ssl);
  coap_wolfssl_context_t *w_context =
      ((coap_wolfssl_context_t *)c_session->context->dtls_context);

  if (!ssl) {
    return noack_return;
  }

  if (setup_data->validate_sni_call_back) {
    /* SNI checking requested */
    const char *sni = wolfSSL_get_servername(ssl, WOLFSSL_SNI_HOST_NAME);
    char lhint[COAP_DTLS_HINT_LENGTH];
    const coap_dtls_spsk_info_t *new_entry;

    if (!sni || !sni[0]) {
      sni = "";
    }
    coap_lock_callback_ret(new_entry, c_session->context,
                           setup_data->validate_sni_call_back(sni,
                                                              c_session,
                                                              setup_data->sni_call_back_arg));
    if (new_entry) {
      coap_session_refresh_psk_key(c_session, &new_entry->key);
      snprintf(lhint, sizeof(lhint), "%.*s",
               (int)new_entry->hint.length,
               new_entry->hint.s);
      wolfSSL_use_psk_identity_hint(ssl, lhint);
    }
  }

  if (w_context->psk_pki_enabled & IS_PSK) {
    wolfSSL_set_psk_server_callback(ssl, coap_dtls_psk_server_callback);
  }
  return SSL_TLSEXT_ERR_OK;
}
#endif /* COAP_SERVER_SUPPORT */

int
coap_dtls_context_set_pki(coap_context_t *ctx,
                          const coap_dtls_pki_t *setup_data,
                          const coap_dtls_role_t role) {
  coap_wolfssl_context_t *w_context =
      ((coap_wolfssl_context_t *)ctx->dtls_context);

  if (!setup_data)
    return 0;

  w_context->setup_data = *setup_data;
  if (!w_context->setup_data.verify_peer_cert) {
    /* Needs to be clear so that no CA DNs are transmitted */
    w_context->setup_data.check_common_ca = 0;
    if (w_context->setup_data.is_rpk_not_cert) {
      /* Disable all of these as they cannot be checked */
      w_context->setup_data.allow_self_signed = 0;
      w_context->setup_data.allow_expired_certs = 0;
      w_context->setup_data.cert_chain_validation = 0;
      w_context->setup_data.cert_chain_verify_depth = 0;
      w_context->setup_data.check_cert_revocation = 0;
      w_context->setup_data.allow_no_crl = 0;
      w_context->setup_data.allow_expired_crl = 0;
      w_context->setup_data.allow_bad_md_hash = 0;
      w_context->setup_data.allow_short_rsa_length = 0;
    } else {
      /* Allow all of these but warn if issue */
      w_context->setup_data.allow_self_signed = 1;
      w_context->setup_data.allow_expired_certs = 1;
      w_context->setup_data.cert_chain_validation = 1;
      w_context->setup_data.cert_chain_verify_depth = 10;
      w_context->setup_data.check_cert_revocation = 1;
      w_context->setup_data.allow_no_crl = 1;
      w_context->setup_data.allow_expired_crl = 1;
      w_context->setup_data.allow_bad_md_hash = 1;
      w_context->setup_data.allow_short_rsa_length = 1;
    }
  }
#if COAP_SERVER_SUPPORT
  if (role == COAP_DTLS_ROLE_SERVER) {
    if (!setup_dtls_context(w_context))
      return 0;
    if (w_context->dtls.ctx) {
#if defined(HAVE_RPK) && LIBWOLFSSL_VERSION_HEX >= 0x05006004
      char ctype[] = {WOLFSSL_CERT_TYPE_RPK};
      char stype[] = {WOLFSSL_CERT_TYPE_RPK};
#endif /* HAVE_RPK && LIBWOLFSSL_VERSION_HEX >= 0x05006004 */

      wolfSSL_CTX_set_servername_arg(w_context->dtls.ctx,
                                     &w_context->setup_data);
      wolfSSL_CTX_set_tlsext_servername_callback(w_context->dtls.ctx,
                                                 tls_server_name_call_back);

#if defined(HAVE_RPK) && LIBWOLFSSL_VERSION_HEX >= 0x05006004
      if (w_context->setup_data.is_rpk_not_cert) {
        wolfSSL_CTX_set_client_cert_type(w_context->dtls.ctx, ctype, sizeof(ctype)/sizeof(ctype[0]));
        wolfSSL_CTX_set_server_cert_type(w_context->dtls.ctx, stype, sizeof(stype)/sizeof(stype[0]));
      }
#endif /* HAVE_RPK && LIBWOLFSSL_VERSION_HEX >= 0x05006004 */
    }
#if !COAP_DISABLE_TCP
    if (!setup_tls_context(w_context))
      return 0;
    if (w_context->tls.ctx) {
      wolfSSL_CTX_set_servername_arg(w_context->tls.ctx,
                                     &w_context->setup_data);
      wolfSSL_CTX_set_tlsext_servername_callback(w_context->tls.ctx,
                                                 tls_server_name_call_back);

      /* For TLS only */
      wolfSSL_CTX_set_alpn_select_cb(w_context->tls.ctx,
                                     server_alpn_callback, NULL);
    }
#endif /* !COAP_DISABLE_TCP */
    /* Certificate Revocation */
    if (w_context->setup_data.check_cert_revocation) {
      WOLFSSL_X509_VERIFY_PARAM *param;

      param = wolfSSL_X509_VERIFY_PARAM_new();
      wolfSSL_X509_VERIFY_PARAM_set_flags(param, WOLFSSL_CRL_CHECK);
      wolfSSL_CTX_set1_param(w_context->dtls.ctx, param);
#if !COAP_DISABLE_TCP
      wolfSSL_CTX_set1_param(w_context->tls.ctx, param);
#endif /* !COAP_DISABLE_TCP */
      wolfSSL_X509_VERIFY_PARAM_free(param);
    }
    /* Verify Peer */
    if (w_context->setup_data.verify_peer_cert) {
      wolfSSL_CTX_set_verify(w_context->dtls.ctx,
                             WOLFSSL_VERIFY_PEER |
                             WOLFSSL_VERIFY_CLIENT_ONCE |
                             WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                             tls_verify_call_back);
#if !COAP_DISABLE_TCP
      wolfSSL_CTX_set_verify(w_context->tls.ctx,
                             WOLFSSL_VERIFY_PEER |
                             WOLFSSL_VERIFY_CLIENT_ONCE |
                             WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                             tls_verify_call_back);
#endif /* !COAP_DISABLE_TCP */
    } else {
      wolfSSL_CTX_set_verify(w_context->dtls.ctx,
                             WOLFSSL_VERIFY_NONE, tls_verify_call_back);
#if !COAP_DISABLE_TCP
      wolfSSL_CTX_set_verify(w_context->tls.ctx,
                             WOLFSSL_VERIFY_NONE, tls_verify_call_back);
#endif /* !COAP_DISABLE_TCP */
    }

    /* Check CA Chain */
    if (w_context->setup_data.cert_chain_validation) {
      wolfSSL_CTX_set_verify_depth(w_context->dtls.ctx,
                                   setup_data->cert_chain_verify_depth + 1);
#if !COAP_DISABLE_TCP
      wolfSSL_CTX_set_verify_depth(w_context->tls.ctx,
                                   setup_data->cert_chain_verify_depth + 1);
#endif /* !COAP_DISABLE_TCP */
    }
  }
#else /* ! COAP_SERVER_SUPPORT */
  (void)role;
#endif /* ! COAP_SERVER_SUPPORT */

  w_context->psk_pki_enabled |= IS_PKI;
  if (setup_data->use_cid) {
#if ! defined(WOLFSSL_DTLS_CID)
    coap_log_warn("wolfSSL has no Connection-ID support\n");
#endif /* ! WOLFSSL_DTLS_CID */
  }
  return 1;
}

int
coap_dtls_context_set_pki_root_cas(coap_context_t *ctx,
                                   const char *ca_file,
                                   const char *ca_dir) {
  coap_wolfssl_context_t *w_context =
      ((coap_wolfssl_context_t *)ctx->dtls_context);

  if (!w_context) {
    coap_log_warn("coap_context_set_pki_root_cas: (D)TLS environment "
                  "not set up\n");
    return 0;
  }
  if (ca_file == NULL && ca_dir == NULL) {
    coap_log_warn("coap_context_set_pki_root_cas: ca_file and/or ca_dir "
                  "not defined\n");
    return 0;
  }
  if (w_context->root_ca_file) {
    wolfssl_free(w_context->root_ca_file);
    w_context->root_ca_file = NULL;
  }
  if (ca_file) {
    w_context->root_ca_file = wolfssl_strdup(ca_file);
  }
  if (w_context->root_ca_dir) {
    wolfssl_free(w_context->root_ca_dir);
    w_context->root_ca_dir = NULL;
  }
  if (ca_dir) {
    w_context->root_ca_dir = wolfssl_strdup(ca_dir);
  }
  return 1;
}

int
coap_dtls_context_check_keys_enabled(coap_context_t *ctx) {
  coap_wolfssl_context_t *w_context =
      ((coap_wolfssl_context_t *)ctx->dtls_context);
  return w_context->psk_pki_enabled ? 1 : 0;
}


void
coap_dtls_free_context(void *handle) {
  coap_wolfssl_context_t *w_context = (coap_wolfssl_context_t *)handle;

  if (!w_context)
    return;
  wolfssl_free(w_context->root_ca_file);
  wolfssl_free(w_context->root_ca_dir);

  if (w_context->dtls.ctx)
    wolfSSL_CTX_free(w_context->dtls.ctx);
  if (w_context->dtls.cookie_hmac)
    wolfSSL_HMAC_CTX_free(w_context->dtls.cookie_hmac);

#if !COAP_DISABLE_TCP
  if (w_context->tls.ctx)
    wolfSSL_CTX_free(w_context->tls.ctx);
#endif /* !COAP_DISABLE_TCP */
  wolfssl_free(w_context);
}

#if COAP_SERVER_SUPPORT
void *
coap_dtls_new_server_session(coap_session_t *session) {
  coap_wolfssl_context_t *w_context =
      ((coap_wolfssl_context_t *)session->context->dtls_context);
  coap_dtls_context_t *dtls;
  WOLFSSL *ssl = NULL;
  int r;
  const coap_bin_const_t *psk_hint;
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)session->tls;
  coap_tick_t now;

  if (!w_env)
    goto error;

  if (!setup_dtls_context(w_context))
    goto error;
  dtls = &w_context->dtls;

  ssl = wolfSSL_new(dtls->ctx);
  if (!ssl) {
    goto error;
  }
  wolfSSL_set_app_data(ssl, NULL);
  wolfSSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
#ifdef WOLFSSL_DTLS_MTU
  wolfSSL_dtls_set_mtu(ssl, (long)session->mtu);
#endif /* WOLFSSL_DTLS_MTU */
  w_env->ssl = ssl;
  wolfSSL_SetIOWriteCtx(ssl, w_env);
  wolfSSL_SetIOReadCtx(ssl, w_env);
  wolfSSL_set_app_data(ssl, session);
  w_env->data.session = session;

#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SEND_HRR_COOKIE)
  if (wolfSSL_send_hrr_cookie(ssl, NULL, 0) != WOLFSSL_SUCCESS)
    coap_log_debug("Error: Unable to set cookie with Hello Retry Request\n");
#endif /* WOLFSSL_DTLS13 && WOLFSSL_SEND_HRR_COOKIE */

#ifdef HAVE_SERVER_RENEGOTIATION_INFO
  if (wolfSSL_UseSecureRenegotiation(ssl) != WOLFSSL_SUCCESS) {
    coap_log_debug("Error: wolfSSL_UseSecureRenegotiation failed\n");
  }
#endif /* HAVE_SERVER_RENEGOTIATION_INFO */

  if (w_context->psk_pki_enabled & IS_PSK) {
    /* hint may get updated if/when handling SNI callback */
    psk_hint = coap_get_session_server_psk_hint(session);
    if (psk_hint != NULL && psk_hint->length) {
      char *hint = wolfssl_malloc(psk_hint->length + 1);

      if (hint) {
        memcpy(hint, psk_hint->s, psk_hint->length);
        hint[psk_hint->length] = '\000';
        wolfSSL_use_psk_identity_hint(ssl, hint);
        wolfssl_free(hint);
      } else {
        coap_log_warn("hint malloc failure\n");
      }
    }
  }
  if (w_context->psk_pki_enabled & IS_PKI) {
    if (!setup_pki_ssl(ssl, &w_context->setup_data, COAP_DTLS_ROLE_SERVER))
      goto error;
  }

#if defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_DTLS13)
  if (wolfSSL_dtls13_allow_ch_frag(ssl, 1) != WOLFSSL_SUCCESS) {
    coap_log_debug("Error: wolfSSL_dtls13_allow_ch_frag failed\n");
  }
#endif /* WOLFSSL_DTLS_CH_FRAG && WOLFSSL_DTLS13 */

#if defined(WOLFSSL_DTLS_CID) && defined(WOLFSSL_DTLS13)

#if COAP_DTLS_CID_LENGTH > DTLS_CID_MAX_SIZE
#bad COAP_DTLS_CID_LENGTH > DTLS_CID_MAX_SIZE
#endif /* COAP_DTLS_CID_LENGTH > DTLS_CID_MAX_SIZE */

  if (wolfSSL_dtls_cid_use(ssl) != WOLFSSL_SUCCESS)
    goto error;
  u_char cid[COAP_DTLS_CID_LENGTH];
  /*
   * Enable server DTLS CID support.
   */
  coap_prng_lkd(cid, sizeof(cid));
  if (wolfSSL_dtls_cid_set(ssl, cid, sizeof(cid)) != WOLFSSL_SUCCESS)
    goto error;
  session->client_cid = coap_new_bin_const(cid, sizeof(cid));
#endif /* WOLFSSL_DTLS_CID && WOLFSSL_DTLS13 */

  coap_ticks(&now);
  w_env->last_timeout = now;
  w_env->ssl = ssl;

  r = wolfSSL_accept(ssl);
  if (r == -1) {
    int err = wolfSSL_get_error(ssl, r);
    if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE)
      r = 0;
  }

  if (r == 0) {
    goto error;
  }

  return w_env;

error:
  if (ssl)
    wolfSSL_free(ssl);
  coap_dtls_free_wolfssl_env(w_env);
  return NULL;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
static int
setup_client_ssl_session(coap_session_t *session, WOLFSSL *ssl) {
  coap_wolfssl_context_t *w_context =
      ((coap_wolfssl_context_t *)session->context->dtls_context);

  if (w_context->psk_pki_enabled & IS_PSK) {
    coap_dtls_cpsk_t *setup_data = &session->cpsk_setup_data;

    if (setup_data->validate_ih_call_back) {
      if (session->proto == COAP_PROTO_DTLS) {
        wolfSSL_set_max_proto_version(ssl,
                                      DTLS1_2_VERSION);
      }
#if !COAP_DISABLE_TCP
      else {
        wolfSSL_set_max_proto_version(ssl,
                                      TLS1_2_VERSION);
        wolfSSL_set_options(ssl, WOLFSSL_OP_NO_TLSv1_3);
      }
#endif /* !COAP_DISABLE_TCP */
      coap_log_debug("CoAP Client restricted to (D)TLS1.2 with Identity Hint callback\n");
    }
    set_ciphersuites(ssl, COAP_ENC_PSK);

    /* Issue SNI if requested */
    if (setup_data->client_sni &&
        wolfSSL_set_tlsext_host_name(ssl, setup_data->client_sni) != 1) {
      coap_log_warn("wolfSSL_set_tlsext_host_name: set '%s' failed",
                    setup_data->client_sni);
    }
    wolfSSL_set_psk_client_callback(ssl, coap_dtls_psk_client_callback);

#if defined(WOLFSSL_DTLS_CID) && defined(WOLFSSL_DTLS13)
    if (setup_data->use_cid) {
      if (wolfSSL_dtls_cid_use(ssl) != WOLFSSL_SUCCESS)
        return 0;
      /*
       * Enable client DTLS CID negotiation.
       */
      if (wolfSSL_dtls_cid_set(ssl, NULL, 0) != WOLFSSL_SUCCESS)
        return 0;
    }
#endif /* WOLFSSL_DTLS_CID && WOLFSSL_DTLS13 */
  }
  if (w_context->psk_pki_enabled & IS_PKI) {
    coap_dtls_pki_t *setup_data = &w_context->setup_data;

    set_ciphersuites(ssl, COAP_ENC_PKI);
    if (!setup_pki_ssl(ssl, setup_data, COAP_DTLS_ROLE_CLIENT))
      return 0;
    /* libcoap is managing (D)TLS connection based on setup_data options */
#if !COAP_DISABLE_TCP
    if (session->proto == COAP_PROTO_TLS)
      wolfSSL_set_alpn_protos(ssl, coap_alpn, sizeof(coap_alpn));
#endif /* !COAP_DISABLE_TCP */

    /* Issue SNI if requested */
    if (setup_data->client_sni &&
        wolfSSL_set_tlsext_host_name(ssl, setup_data->client_sni) != 1) {
      coap_log_warn("wolfSSL_set_tlsext_host_name: set '%s' failed",
                    setup_data->client_sni);
    }
    /* Certificate Revocation */
    if (setup_data->check_cert_revocation) {
      WOLFSSL_X509_VERIFY_PARAM *param;

      param = wolfSSL_X509_VERIFY_PARAM_new();
      wolfSSL_X509_VERIFY_PARAM_set_flags(param, WOLFSSL_CRL_CHECK);
      WOLFSSL_CTX *ctx = wolfSSL_get_SSL_CTX(ssl);
      /* TODO: we cannot set parameters at ssl level with wolfSSL, review*/
      wolfSSL_CTX_set1_param(ctx, param);
      wolfSSL_X509_VERIFY_PARAM_free(param);
    }
    /* Verify Peer */
    if (setup_data->verify_peer_cert)
      wolfSSL_set_verify(ssl,
                         WOLFSSL_VERIFY_PEER |
                         WOLFSSL_VERIFY_CLIENT_ONCE |
                         WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                         tls_verify_call_back);
    else
      wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, tls_verify_call_back);

    /* Check CA Chain */
    if (setup_data->cert_chain_validation)
      wolfSSL_set_verify_depth(ssl, setup_data->cert_chain_verify_depth + 1);

#if defined(WOLFSSL_DTLS_CID) && defined(WOLFSSL_DTLS13)
    if (setup_data->use_cid) {
      if (wolfSSL_dtls_cid_use(ssl) != WOLFSSL_SUCCESS)
        return 0;
      /*
       * Enable client DTLS CID negotiation.
       */
      if (wolfSSL_dtls_cid_set(ssl, NULL, 0) != WOLFSSL_SUCCESS)
        return 0;
    }
#endif /* WOLFSSL_DTLS_CID && WOLFSSL_DTLS13 */

  }
  return 1;
}

void *
coap_dtls_new_client_session(coap_session_t *session) {
  WOLFSSL *ssl = NULL;
  int r;
  coap_wolfssl_context_t *w_context =
      ((coap_wolfssl_context_t *)session->context->dtls_context);
  coap_dtls_context_t *dtls;
  coap_wolfssl_env_t *w_env =
      coap_dtls_new_wolfssl_env(session, COAP_DTLS_ROLE_CLIENT);
  coap_tick_t now;

  if (!w_env)
    goto error;

  if (!setup_dtls_context(w_context))
    goto error;
  dtls = &w_context->dtls;

  ssl = wolfSSL_new(dtls->ctx);
  if (!ssl) {
    goto error;
  }
  w_env->data.session = session;
  wolfSSL_set_app_data(ssl, session);
  wolfSSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
  wolfSSL_SetIOWriteCtx(ssl, w_env);
  wolfSSL_SetIOReadCtx(ssl, w_env);
#ifdef WOLFSSL_DTLS_MTU
  wolfSSL_dtls_set_mtu(ssl, (long)session->mtu);
#endif /* WOLFSSL_DTLS_MTU */

  if (!setup_client_ssl_session(session, ssl))
    goto error;
#ifdef HAVE_SERVER_RENEGOTIATION_INFO
  if (wolfSSL_UseSecureRenegotiation(ssl) != WOLFSSL_SUCCESS) {
    coap_log_debug("Error: wolfSSL_UseSecureRenegotiation failed\n");
  }
#endif /* HAVE_SERVER_RENEGOTIATION_INFO */

  session->dtls_timeout_count = 0;

#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SEND_HRR_COOKIE)
  wolfSSL_NoKeyShares(ssl);
#endif /* WOLFSSL_DTLS13 && WOLFSSL_SEND_HRR_COOKIE */
  r = wolfSSL_connect(ssl);
  if (r == -1) {
    int ret = wolfSSL_get_error(ssl, r);
    if (ret != WOLFSSL_ERROR_WANT_READ && ret != WOLFSSL_ERROR_WANT_WRITE)
      r = 0;
  }

  if (r == 0)
    goto error;

  coap_ticks(&now);
  w_env->last_timeout = now;
  w_env->ssl = ssl;
  return w_env;

error:
  if (ssl)
    wolfSSL_free(ssl);
  return NULL;
}

void
coap_dtls_session_update_mtu(coap_session_t *session) {
#ifdef WOLFSSL_DTLS_MTU
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)session->tls;
  WOLFSSL *ssl = w_env ? w_env->ssl : NULL;

  if (ssl)
    wolfSSL_dtls_set_mtu(ssl, (long)session->mtu); /* Instead of SSL_set_mtu */
#else /* ! WOLFSSL_DTLS_MTU */
  (void)session;
#endif /* ! WOLFSSL_DTLS_MTU */
}
#endif /* COAP_CLIENT_SUPPORT */

void
coap_dtls_free_session(coap_session_t *session) {
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)session->tls;
  WOLFSSL *ssl = w_env ? w_env->ssl : NULL;

  if (ssl) {
    if (!wolfSSL_SSL_in_init(ssl) && !(wolfSSL_get_shutdown(ssl) & WOLFSSL_SENT_SHUTDOWN)) {
      int r = wolfSSL_shutdown(ssl);
      if (r == 0)
        wolfSSL_shutdown(ssl);
    }
    w_env->ssl = NULL;
    wolfSSL_free(ssl);
    if (session->context)
      coap_handle_event_lkd(session->context, COAP_EVENT_DTLS_CLOSED, session);
  }
  coap_dtls_free_wolfssl_env(w_env);
}

ssize_t
coap_dtls_send(coap_session_t *session,
               const uint8_t *data, size_t data_len) {
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)session->tls;
  WOLFSSL *ssl = w_env ? w_env->ssl : NULL;
  int r;

  assert(ssl != NULL);

  session->dtls_event = -1;
  coap_log_debug("*  %s: dtls:  sent %4d bytes\n",
                 coap_session_str(session), (int)data_len);
  r = wolfSSL_write(ssl, data, (int)data_len);

  if (r <= 0) {
    int err = wolfSSL_get_error(ssl, r);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
      r = 0;
    } else {
      coap_log_warn("coap_dtls_send: cannot send PDU\n");
      if (err == WOLFSSL_ERROR_ZERO_RETURN)
        session->dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == WOLFSSL_ERROR_SSL)
        session->dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
  }

  if (session->dtls_event >= 0) {
    /* COAP_EVENT_DTLS_CLOSED event reported in coap_session_disconnected_lkd() */
    if (session->dtls_event != COAP_EVENT_DTLS_CLOSED)
      coap_handle_event_lkd(session->context, session->dtls_event, session);
    if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected_lkd(session, COAP_NACK_TLS_FAILED);
      r = -1;
    }
  }

  return r;
}

int
coap_dtls_is_context_timeout(void) {
  return 0;
}

coap_tick_t
coap_dtls_get_context_timeout(void *dtls_context) {
  (void)dtls_context;
  return 0;
}

coap_tick_t
coap_dtls_get_timeout(coap_session_t *session, coap_tick_t now) {
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)session->tls;
  unsigned int scalar;

  if (!w_env)
    return now;

  assert(session->state == COAP_SESSION_STATE_HANDSHAKE);

  scalar = 1 << w_env->retry_scalar;
  if (w_env->last_timeout + COAP_DTLS_RETRANSMIT_COAP_TICKS * scalar > now) {
    /* Need to indicate remaining timeout time */
    return w_env->last_timeout + COAP_DTLS_RETRANSMIT_COAP_TICKS * scalar;
  }
  return now;
}

/*
 * return 1 timed out
 *        0 still timing out
 */
int
coap_dtls_handle_timeout(coap_session_t *session) {
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)session->tls;
  WOLFSSL *ssl = w_env ? w_env->ssl : NULL;

  assert(ssl != NULL && session->state == COAP_SESSION_STATE_HANDSHAKE);
  w_env->retry_scalar++;
  if (++session->dtls_timeout_count > session->max_retransmit) {
    /* Too many retries */
    coap_session_disconnected_lkd(session, COAP_NACK_TLS_FAILED);
    return 1;
  }
  wolfSSL_dtls_retransmit(ssl);
  return 0;
}

#if COAP_SERVER_SUPPORT

int
coap_dtls_hello(coap_session_t *session,
                const uint8_t *data, size_t data_len) {
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)session->tls;
  coap_ssl_data_t *ssl_data;

  if (!w_env) {
    w_env = coap_dtls_new_wolfssl_env(session, COAP_DTLS_ROLE_SERVER);
    if (w_env) {
      session->tls = w_env;
    } else {
      /* error should have already been reported */
      return -1;
    }
  }

  ssl_data = w_env ? &w_env->data : NULL;
  assert(ssl_data != NULL);

  if (ssl_data->pdu_len) {
    coap_log_err("** %s: Previous data not read %u bytes\n",
                 coap_session_str(session), ssl_data->pdu_len);
  }

  ssl_data->session = session;
  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;

  return 1;
}

#endif /* COAP_SERVER_SUPPORT */

int
coap_dtls_receive(coap_session_t *session, const uint8_t *data, size_t data_len) {
  coap_ssl_data_t *ssl_data;
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)session->tls;
  WOLFSSL *ssl = w_env ? w_env->ssl : NULL;
  int r;
  int in_init = wolfSSL_SSL_in_init(ssl);
  uint8_t pdu[COAP_RXBUFFER_SIZE];

  assert(ssl != NULL);

  ssl_data = &w_env->data;

  if (ssl_data->pdu_len) {
    coap_log_err("** %s: Previous data not read %u bytes\n",
                 coap_session_str(session), ssl_data->pdu_len);
  }
  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;

  session->dtls_event = -1;
  r = wolfSSL_read(ssl, pdu, (int)sizeof(pdu));
  if (r > 0) {
    coap_log_debug("*  %s: dtls:  recv %4d bytes\n",
                   coap_session_str(session), r);
    r =  coap_handle_dgram(session->context, session, pdu, (size_t)r);
    goto finished;
  } else {
    int err = wolfSSL_get_error(ssl, r);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
      if (in_init && wolfSSL_is_init_finished(ssl)) {
        coap_dtls_log(COAP_LOG_INFO, "*  %s: Using cipher: %s\n",
                      coap_session_str(session), wolfSSL_get_cipher((ssl)));
#if defined(WOLFSSL_DTLS_CID) && defined(WOLFSSL_DTLS13) && COAP_CLIENT_SUPPORT
        if (session->type == COAP_SESSION_TYPE_CLIENT &&
            session->proto == COAP_PROTO_DTLS) {
          if (wolfSSL_dtls_cid_is_enabled(ssl)) {
            session->negotiated_cid = 1;
          } else {
            coap_log_info("** %s: CID was not negotiated\n", coap_session_str(session));
            session->negotiated_cid = 0;
          }
        }
#endif /* WOLFSSL_DTLS_CID && WOLFSSL_DTLS13 && COAP_CLIENT_SUPPORT */
        if (!strcmp(wolfSSL_get_version(ssl), "DTLSv1.3")) {
          session->is_dtls13 = 1;
        } else {
          session->is_dtls13 = 0;
        }
        coap_handle_event_lkd(session->context, COAP_EVENT_DTLS_CONNECTED, session);
        session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
      }
      r = 0;
    } else if (err == APP_DATA_READY) {
      r = wolfSSL_read(ssl, pdu, (int)sizeof(pdu));
      if (r > 0) {
        r =  coap_handle_dgram(session->context, session, pdu, (size_t)r);
        goto finished;
      }
      session->dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    } else {
      if (err == WOLFSSL_ERROR_ZERO_RETURN) {
        /* Got a close notify alert from the remote side */
        session->dtls_event = COAP_EVENT_DTLS_CLOSED;
      } else {
        session->dtls_event = COAP_EVENT_DTLS_ERROR;
        if (err == FATAL_ERROR) {
          WOLFSSL_ALERT_HISTORY h;

          if (wolfSSL_get_alert_history(ssl, &h) == WOLFSSL_SUCCESS) {
            if (h.last_rx.code != close_notify && h.last_rx.code != -1) {
              coap_log_warn("***%s: Alert '%d': %s\n",
                            coap_session_str(session), h.last_rx.code,
                            wolfSSL_alert_desc_string_long(h.last_rx.code));
            }
          }
        }
      }
      r = -1;
    }
    if (session->dtls_event >= 0) {
      /* COAP_EVENT_DTLS_CLOSED event reported in coap_session_disconnected_lkd() */
      if (session->dtls_event != COAP_EVENT_DTLS_CLOSED)
        coap_handle_event_lkd(session->context, session->dtls_event, session);
      if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
          session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
        coap_session_disconnected_lkd(session, COAP_NACK_TLS_FAILED);
        ssl_data = NULL;
        r = -1;
      }
    }
  }

finished:
  if (ssl_data && ssl_data->pdu_len) {
    /* pdu data is held on stack which will not stay there */
    coap_log_debug("coap_dtls_receive: ret %d: remaining data %u\n", r, ssl_data->pdu_len);
    ssl_data->pdu_len = 0;
    ssl_data->pdu = NULL;
  }
  return r;
}

unsigned int
coap_dtls_get_overhead(coap_session_t *session) {
  unsigned int overhead = 37;
  const WOLFSSL_CIPHER *s_ciph = NULL;
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)session->tls;
  WOLFSSL *ssl = w_env ? w_env->ssl : NULL;

  if (ssl != NULL)
    s_ciph = wolfSSL_get_current_cipher(ssl);
  if (s_ciph) {
    unsigned int ivlen, maclen, blocksize = 1, pad = 0;

    const WOLFSSL_EVP_CIPHER *e_ciph;
    const WOLFSSL_EVP_MD *e_md;
    char cipher[128];

    e_ciph = wolfSSL_EVP_get_cipherbynid(wolfSSL_CIPHER_get_cipher_nid(s_ciph));

    switch (WOLFSSL_EVP_CIPHER_mode(e_ciph)) {

    case WOLFSSL_EVP_CIPH_GCM_MODE:
#ifndef WOLFSSL_EVP_GCM_TLS_EXPLICIT_IV_LEN
#define WOLFSSL_EVP_GCM_TLS_EXPLICIT_IV_LEN 8
#endif
#ifndef WOLFSSL_EVP_GCM_TLS_TAG_LEN
#define WOLFSSL_EVP_GCM_TLS_TAG_LEN 16
#endif
      ivlen = WOLFSSL_EVP_GCM_TLS_EXPLICIT_IV_LEN;
      maclen = WOLFSSL_EVP_GCM_TLS_TAG_LEN;
      break;

    case WOLFSSL_EVP_CIPH_CCM_MODE:
#ifndef WOLFSSL_EVP_CCM_TLS_EXPLICIT_IV_LEN
#define WOLFSSL_EVP_CCM_TLS_EXPLICIT_IV_LEN 8
#endif
      ivlen = WOLFSSL_EVP_CCM_TLS_EXPLICIT_IV_LEN;
      wolfSSL_CIPHER_description(s_ciph, cipher, sizeof(cipher));
      if (strstr(cipher, "CCM8"))
        maclen = 8;
      else
        maclen = 16;
      break;

    case WOLFSSL_EVP_CIPH_CBC_MODE:
      e_md = wolfSSL_EVP_get_digestbynid(wolfSSL_CIPHER_get_digest_nid(s_ciph));
      blocksize = wolfSSL_EVP_CIPHER_block_size(e_ciph);
      ivlen = wolfSSL_EVP_CIPHER_iv_length(e_ciph);
      pad = 1;
      maclen = wolfSSL_EVP_MD_size(e_md);
      break;

    case WOLFSSL_EVP_CIPH_STREAM_CIPHER:
      /* Seen with PSK-CHACHA20-POLY1305 */
      ivlen = 8;
      maclen = 8;
      break;

    default:
      wolfSSL_CIPHER_description(s_ciph, cipher, sizeof(cipher));
      coap_log_warn("Unknown overhead for DTLS with cipher %s\n",
                    cipher);
      ivlen = 8;
      maclen = 16;
      break;
    }
#ifndef WOLFSSL_DTLS13_RT_HEADER_LENGTH
#define WOLFSSL_DTLS13_RT_HEADER_LENGTH 13
#endif
    overhead = WOLFSSL_DTLS13_RT_HEADER_LENGTH + ivlen + maclen + blocksize - 1 +
               pad;
  }
  return overhead;
}

#if !COAP_DISABLE_TCP
#if COAP_CLIENT_SUPPORT
void *
coap_tls_new_client_session(coap_session_t *session) {
  WOLFSSL *ssl = NULL;
  int r;
  coap_wolfssl_context_t *w_context =
      ((coap_wolfssl_context_t *)session->context->dtls_context);
  coap_tls_context_t *tls;
  coap_wolfssl_env_t *w_env =
      coap_dtls_new_wolfssl_env(session, COAP_DTLS_ROLE_CLIENT);
  coap_tick_t now;

  if (!w_env)
    goto error;

  if (!setup_tls_context(w_context))
    goto error;
  tls = &w_context->tls;

  ssl = wolfSSL_new(tls->ctx);
  if (!ssl)
    goto error;
  wolfSSL_SetIOWriteCtx(ssl, w_env);
  wolfSSL_SetIOReadCtx(ssl, w_env);
  wolfSSL_set_app_data(ssl, session);
  w_env->data.session = session;

  if (!setup_client_ssl_session(session, ssl))
    return 0;

  session->tls = w_env;
  w_env->ssl = ssl;
  r = wolfSSL_connect(ssl);
  if (r == -1) {
    int ret = wolfSSL_get_error(ssl, r);
    if (ret != WOLFSSL_ERROR_WANT_READ && ret != WOLFSSL_ERROR_WANT_WRITE)
      r = 0;
    if (ret == WOLFSSL_ERROR_WANT_READ)
      session->sock.flags |= COAP_SOCKET_WANT_READ;
    if (ret == WOLFSSL_ERROR_WANT_WRITE) {
      session->sock.flags |= COAP_SOCKET_WANT_WRITE;
#ifdef COAP_EPOLL_SUPPORT
      coap_epoll_ctl_mod(&session->sock,
                         EPOLLOUT |
                         ((session->sock.flags & COAP_SOCKET_WANT_READ) ?
                          EPOLLIN : 0),
                         __func__);
#endif /* COAP_EPOLL_SUPPORT */
    }
  }

  if (r == 0)
    goto error;

  coap_ticks(&now);
  w_env->last_timeout = now;
  if (wolfSSL_is_init_finished(ssl)) {
    coap_handle_event_lkd(session->context, COAP_EVENT_DTLS_CONNECTED, session);
    session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
  }

  return w_env;

error:
  coap_dtls_free_wolfssl_env(w_env);
  if (ssl)
    wolfSSL_free(ssl);
  return NULL;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
void *
coap_tls_new_server_session(coap_session_t *session) {
  WOLFSSL *ssl = NULL;
  coap_wolfssl_context_t *w_context =
      ((coap_wolfssl_context_t *)session->context->dtls_context);
  coap_tls_context_t *tls;
  int r;
  const coap_bin_const_t *psk_hint;
  coap_wolfssl_env_t *w_env =
      coap_dtls_new_wolfssl_env(session, COAP_DTLS_ROLE_SERVER);
  coap_tick_t now;

  if (!w_env)
    goto error;

  if (!setup_tls_context(w_context))
    goto error;
  tls = &w_context->tls;

  ssl = wolfSSL_new(tls->ctx);
  if (!ssl)
    goto error;
  wolfSSL_SetIOWriteCtx(ssl, w_env);
  wolfSSL_SetIOReadCtx(ssl, w_env);
  wolfSSL_set_app_data(ssl, session);

  wolfSSL_set_cipher_list(ssl, "ALL");

  if (w_context->psk_pki_enabled & IS_PSK) {
    psk_hint = coap_get_session_server_psk_hint(session);
    if (psk_hint != NULL && psk_hint->length) {
      char *hint = wolfssl_malloc(psk_hint->length + 1);

      if (hint) {
        memcpy(hint, psk_hint->s, psk_hint->length);
        hint[psk_hint->length] = '\000';
        wolfSSL_use_psk_identity_hint(ssl, hint);
        wolfssl_free(hint);
      } else {
        coap_log_warn("hint malloc failure\n");
      }
    }
  }
  if (w_context->psk_pki_enabled & IS_PKI) {
    if (!setup_pki_ssl(ssl, &w_context->setup_data, COAP_DTLS_ROLE_SERVER))
      goto error;
  }
#if defined(HAVE_RPK) && LIBWOLFSSL_VERSION_HEX >= 0x05006004
  if (w_context->setup_data.is_rpk_not_cert) {
    char stype[] = {WOLFSSL_CERT_TYPE_RPK};

    wolfSSL_set_server_cert_type(ssl, stype, sizeof(stype)/sizeof(stype[0]));
  }
#endif /* HAVE_RPK && LIBWOLFSSL_VERSION_HEX >= 0x05006004 */

  coap_ticks(&now);
  w_env->last_timeout = now;
  w_env->ssl = ssl;
  w_env->data.session = session;

  r = wolfSSL_accept(ssl);
  if (r == -1) {
    int err = wolfSSL_get_error(ssl, r);
    if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
      r = 0;
    }
    if (err == WOLFSSL_ERROR_WANT_READ) {
      session->sock.flags |= COAP_SOCKET_WANT_READ;
    }
    if (err == WOLFSSL_ERROR_WANT_WRITE) {
      session->sock.flags |= COAP_SOCKET_WANT_WRITE;
#ifdef COAP_EPOLL_SUPPORT
      coap_epoll_ctl_mod(&session->sock,
                         EPOLLOUT |
                         ((session->sock.flags & COAP_SOCKET_WANT_READ) ?
                          EPOLLIN : 0),
                         __func__);
#endif /* COAP_EPOLL_SUPPORT */
    }
  }

  if (r == 0)
    goto error;

  session->tls = w_env;
  if (wolfSSL_is_init_finished(ssl)) {
    coap_handle_event_lkd(session->context, COAP_EVENT_DTLS_CONNECTED, session);
    session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
  }

  return w_env;

error:
  if (ssl)
    wolfSSL_free(ssl);
  coap_dtls_free_wolfssl_env(w_env);
  return NULL;
}
#endif /* COAP_SERVER_SUPPORT */

void
coap_tls_free_session(coap_session_t *session) {
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)session->tls;
  WOLFSSL *ssl = w_env ? w_env->ssl : NULL;

  if (ssl) {
    if (!wolfSSL_SSL_in_init(ssl) && !(wolfSSL_get_shutdown(ssl) & WOLFSSL_SENT_SHUTDOWN)) {
      int r = wolfSSL_shutdown(ssl);
      if (r == 0)
        wolfSSL_shutdown(ssl);
    }
    wolfSSL_free(ssl);
    w_env->ssl = NULL;
    if (session->context)
      coap_handle_event_lkd(session->context, COAP_EVENT_DTLS_CLOSED, session);
  }
  coap_dtls_free_wolfssl_env(w_env);
}

/*
 * strm
 * return +ve Number of bytes written.
 *         -1 Error (error in errno).
 */
ssize_t
coap_tls_write(coap_session_t *session, const uint8_t *data, size_t data_len) {
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)session->tls;
  WOLFSSL *ssl = w_env ? w_env->ssl : NULL;
  int r, in_init;

  if (ssl == NULL)
    return -1;

  in_init = !wolfSSL_is_init_finished(ssl);
  session->dtls_event = -1;
  r = wolfSSL_write(ssl, data, (int)data_len);

  if (r <= 0) {
    int err = wolfSSL_get_error(ssl, r);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
      if (in_init && wolfSSL_is_init_finished(ssl)) {
        coap_dtls_log(COAP_LOG_INFO, "*  %s: Using cipher: %s\n",
                      coap_session_str(session), wolfSSL_get_cipher((ssl)));
        coap_handle_event_lkd(session->context, COAP_EVENT_DTLS_CONNECTED, session);
        session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
      }
      if (err == WOLFSSL_ERROR_WANT_READ)
        session->sock.flags |= COAP_SOCKET_WANT_READ;
      else if (err == WOLFSSL_ERROR_WANT_WRITE) {
        session->sock.flags |= COAP_SOCKET_WANT_WRITE;
#ifdef COAP_EPOLL_SUPPORT
        coap_epoll_ctl_mod(&session->sock,
                           EPOLLOUT |
                           ((session->sock.flags & COAP_SOCKET_WANT_READ) ?
                            EPOLLIN : 0),
                           __func__);
#endif /* COAP_EPOLL_SUPPORT */
      }
      r = 0;
    } else {
      coap_log_info("***%s: coap_tls_write: cannot send PDU\n",
                    coap_session_str(session));
      if (err == WOLFSSL_ERROR_ZERO_RETURN)
        session->dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == WOLFSSL_ERROR_SSL)
        session->dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
  } else if (in_init && wolfSSL_is_init_finished(ssl)) {
    coap_dtls_log(COAP_LOG_INFO, "*  %s: Using cipher: %s\n",
                  coap_session_str(session), wolfSSL_get_cipher((ssl)));
    coap_handle_event_lkd(session->context, COAP_EVENT_DTLS_CONNECTED, session);
    session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
  }

  if (session->dtls_event >= 0) {
    /* COAP_EVENT_DTLS_CLOSED event reported in coap_session_disconnected_lkd() */
    if (session->dtls_event != COAP_EVENT_DTLS_CLOSED)
      coap_handle_event_lkd(session->context, session->dtls_event, session);
    if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected_lkd(session, COAP_NACK_TLS_FAILED);
      r = -1;
    }
  }

  if (r >= 0) {
    if (r == (ssize_t)data_len)
      coap_log_debug("*  %s: tls:   sent %4d bytes\n",
                     coap_session_str(session), r);
    else
      coap_log_debug("*  %s: tls:   sent %4d of %4zd bytes\n",
                     coap_session_str(session), r, data_len);
  }
  return r;
}

/*
 * strm
 * return >=0 Number of bytes read.
 *         -1 Error (error in errno).
 */
ssize_t
coap_tls_read(coap_session_t *session, uint8_t *data, size_t data_len) {
  coap_wolfssl_env_t *w_env = (coap_wolfssl_env_t *)session->tls;
  WOLFSSL *ssl = w_env ? w_env->ssl : NULL;
  int r, in_init;

  if (ssl == NULL) {
    errno = ENXIO;
    return -1;
  }

  in_init = !wolfSSL_is_init_finished(ssl);
  session->dtls_event = -1;
  r = wolfSSL_read(ssl, data, (int)data_len);
  if (r <= 0) {
    int err = wolfSSL_get_error(ssl, r);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
      if (in_init && wolfSSL_is_init_finished(ssl)) {
        coap_dtls_log(COAP_LOG_INFO, "*  %s: Using cipher: %s\n",
                      coap_session_str(session), wolfSSL_get_cipher((ssl)));
        coap_handle_event_lkd(session->context, COAP_EVENT_DTLS_CONNECTED, session);
        session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
      }
      if (err == WOLFSSL_ERROR_WANT_READ)
        session->sock.flags |= COAP_SOCKET_WANT_READ;
      if (err == WOLFSSL_ERROR_WANT_WRITE) {
        session->sock.flags |= COAP_SOCKET_WANT_WRITE;
#ifdef COAP_EPOLL_SUPPORT
        coap_epoll_ctl_mod(&session->sock,
                           EPOLLOUT |
                           ((session->sock.flags & COAP_SOCKET_WANT_READ) ?
                            EPOLLIN : 0),
                           __func__);
#endif /* COAP_EPOLL_SUPPORT */
      }
      r = 0;
    } else {
      if (err == WOLFSSL_ERROR_ZERO_RETURN) {
        /* Got a close notify alert from the remote side */
        session->dtls_event = COAP_EVENT_DTLS_CLOSED;
      } else if (err == WOLFSSL_ERROR_SSL) {
        session->dtls_event = COAP_EVENT_DTLS_ERROR;
      } else if (err == FATAL_ERROR) {
        WOLFSSL_ALERT_HISTORY h;

        session->dtls_event = COAP_EVENT_DTLS_ERROR;
        if (wolfSSL_get_alert_history(ssl, &h) == WOLFSSL_SUCCESS) {
          if (h.last_rx.code != close_notify && h.last_rx.code != -1) {
            coap_log_warn("***%s: Alert '%d': %s\n",
                          coap_session_str(session), h.last_rx.code,
                          wolfSSL_alert_desc_string_long(h.last_rx.code));
          }
        }
      }
      r = -1;
    }
  } else if (in_init && wolfSSL_is_init_finished(ssl)) {
    coap_dtls_log(COAP_LOG_INFO, "*  %s: Using cipher: %s\n",
                  coap_session_str(session), wolfSSL_get_cipher((ssl)));
    coap_handle_event_lkd(session->context, COAP_EVENT_DTLS_CONNECTED, session);
    session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
  }

  if (session->dtls_event >= 0) {
    /* COAP_EVENT_DTLS_CLOSED event reported in coap_session_disconnected_lkd() */
    if (session->dtls_event != COAP_EVENT_DTLS_CLOSED)
      coap_handle_event_lkd(session->context, session->dtls_event, session);
    if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected_lkd(session, COAP_NACK_TLS_FAILED);
      r = -1;
    }
  }

  if (r > 0) {
    coap_log_debug("*  %s: tls:   recv %4d bytes\n",
                   coap_session_str(session), r);
  }
  return r;
}
#endif /* !COAP_DISABLE_TCP */

#if COAP_SERVER_SUPPORT
coap_digest_ctx_t *
coap_digest_setup(void) {
  WOLFSSL_EVP_MD_CTX *digest_ctx = wolfSSL_EVP_MD_CTX_new();

  if (digest_ctx) {
    wolfSSL_EVP_DigestInit_ex(digest_ctx, wolfSSL_EVP_sha256(), NULL);
  }
  return digest_ctx;
}

void
coap_digest_free(coap_digest_ctx_t *digest_ctx) {
  wolfSSL_EVP_MD_CTX_free(digest_ctx);
}

int
coap_digest_update(coap_digest_ctx_t *digest_ctx,
                   const uint8_t *data,
                   size_t data_len) {
  return wolfSSL_EVP_DigestUpdate(digest_ctx, data, data_len);
}

int
coap_digest_final(coap_digest_ctx_t *digest_ctx,
                  coap_digest_t *digest_buffer) {
  unsigned int size = sizeof(coap_digest_t);
  int ret = wolfSSL_EVP_DigestFinal_ex(digest_ctx, (uint8_t *)digest_buffer, &size);

  coap_digest_free(digest_ctx);
  return ret;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_WS_SUPPORT || COAP_OSCORE_SUPPORT
static void
coap_crypto_output_errors(const char *prefix) {
#if COAP_MAX_LOGGING_LEVEL < _COAP_LOG_WARN
  (void)prefix;
#else /* COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_WARN */
  unsigned long e;

  while ((e = wolfSSL_ERR_get_error()))
    coap_log_warn("%s: %s%s\n",
                  prefix,
                  wolfSSL_ERR_reason_error_string(e),
                  ssl_function_definition(e));
#endif /* COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_WARN */
}
#endif /* COAP_WS_SUPPORT || COAP_OSCORE_SUPPORT */

#if COAP_WS_SUPPORT
/*
 * The struct hash_algs and the function get_hash_alg() are used to
 * determine which hash type to use for creating the required hash object.
 */
static struct hash_algs {
  cose_alg_t alg;
  const WOLFSSL_EVP_MD *(*get_hash)(void);
  size_t length; /* in bytes */
} hashs[] = {
  {COSE_ALGORITHM_SHA_1, wolfSSL_EVP_sha1, 20},
  {COSE_ALGORITHM_SHA_256_64, wolfSSL_EVP_sha256, 8},
  {COSE_ALGORITHM_SHA_256_256, wolfSSL_EVP_sha256, 32},
  {COSE_ALGORITHM_SHA_512, wolfSSL_EVP_sha512, 64},
};

static const WOLFSSL_EVP_MD *
get_hash_alg(cose_alg_t alg, size_t *length) {
  size_t idx;

  for (idx = 0; idx < sizeof(hashs) / sizeof(struct hash_algs); idx++) {
    if (hashs[idx].alg == alg) {
      *length = hashs[idx].length;
      return hashs[idx].get_hash();
    }
  }
  coap_log_debug("get_hash_alg: COSE hash %d not supported\n", alg);
  return NULL;
}

int
coap_crypto_hash(cose_alg_t alg,
                 const coap_bin_const_t *data,
                 coap_bin_const_t **hash) {
  unsigned int length;
  const WOLFSSL_EVP_MD *evp_md;
  WOLFSSL_EVP_MD_CTX *evp_ctx = NULL;
  coap_binary_t *dummy = NULL;
  size_t hash_length;

  if ((evp_md = get_hash_alg(alg, &hash_length)) == NULL) {
    coap_log_debug("coap_crypto_hash: algorithm %d not supported\n", alg);
    return 0;
  }
  evp_ctx = wolfSSL_EVP_MD_CTX_new();
  if (evp_ctx == NULL)
    goto error;
  if (wolfSSL_EVP_DigestInit_ex(evp_ctx, evp_md, NULL) == 0)
    goto error;
  ;
  if (wolfSSL_EVP_DigestUpdate(evp_ctx, data->s, data->length) == 0)
    goto error;
  ;
  dummy = coap_new_binary(EVP_MAX_MD_SIZE);
  if (dummy == NULL)
    goto error;
  if (wolfSSL_EVP_DigestFinal_ex(evp_ctx, dummy->s, &length) == 0)
    goto error;
  dummy->length = length;
  if (hash_length < dummy->length)
    dummy->length = hash_length;
  *hash = (coap_bin_const_t *)(dummy);
  wolfSSL_EVP_MD_CTX_free(evp_ctx);
  return 1;

error:
  coap_crypto_output_errors("coap_crypto_hash");
  coap_delete_binary(dummy);
  if (evp_ctx)
    wolfSSL_EVP_MD_CTX_free(evp_ctx);
  return 0;
}
#endif /* COAP_WS_SUPPORT */

#if COAP_OSCORE_SUPPORT
#if LIBWOLFSSL_VERSION_HEX < 0x05006000
static const WOLFSSL_EVP_CIPHER *
EVP_aes_128_ccm(void) {
  return "AES-128-CCM";
}

static const WOLFSSL_EVP_CIPHER *
EVP_aes_256_ccm(void) {
  return "AES-256-CCM";
}
#endif /* LIBWOLFSSL_VERSION_HEX < 0x05006000 */

int
coap_oscore_is_supported(void) {
  return 1;
}

/*
 * The struct cipher_algs and the function get_cipher_alg() are used to
 * determine which cipher type to use for creating the required cipher
 * suite object.
 */
static struct cipher_algs {
  cose_alg_t alg;
  const WOLFSSL_EVP_CIPHER *(*get_cipher)(void);
} ciphers[] = {{COSE_ALGORITHM_AES_CCM_16_64_128, EVP_aes_128_ccm},
  {COSE_ALGORITHM_AES_CCM_16_64_256, EVP_aes_256_ccm}
};

static const WOLFSSL_EVP_CIPHER *
get_cipher_alg(cose_alg_t alg) {
  size_t idx;

  for (idx = 0; idx < sizeof(ciphers) / sizeof(struct cipher_algs); idx++) {
    if (ciphers[idx].alg == alg)
      return ciphers[idx].get_cipher();
  }
  coap_log_debug("get_cipher_alg: COSE cipher %d not supported\n", alg);
  return NULL;
}

/*
 * The struct hmac_algs and the function get_hmac_alg() are used to
 * determine which hmac type to use for creating the required hmac
 * suite object.
 */
static struct hmac_algs {
  cose_hmac_alg_t hmac_alg;
  const WOLFSSL_EVP_MD *(*get_hmac)(void);
} hmacs[] = {
  {COSE_HMAC_ALG_HMAC256_256, wolfSSL_EVP_sha256},
  {COSE_HMAC_ALG_HMAC384_384, wolfSSL_EVP_sha384},
  {COSE_HMAC_ALG_HMAC512_512, wolfSSL_EVP_sha512},
};

static const WOLFSSL_EVP_MD *
get_hmac_alg(cose_hmac_alg_t hmac_alg) {
  size_t idx;

  for (idx = 0; idx < sizeof(hmacs) / sizeof(struct hmac_algs); idx++) {
    if (hmacs[idx].hmac_alg == hmac_alg)
      return hmacs[idx].get_hmac();
  }
  coap_log_debug("get_hmac_alg: COSE HMAC %d not supported\n", hmac_alg);
  return NULL;
}

int
coap_crypto_check_cipher_alg(cose_alg_t alg) {
  return get_cipher_alg(alg) != NULL;
}

int
coap_crypto_check_hkdf_alg(cose_hkdf_alg_t hkdf_alg) {
  cose_hmac_alg_t hmac_alg;

  if (!cose_get_hmac_alg_for_hkdf(hkdf_alg, &hmac_alg))
    return 0;
  return get_hmac_alg(hmac_alg) != NULL;
}

#define C(Func)                                                                \
  if (1 != (Func)) {                                                           \
    goto error;                                                                \
  }

int
coap_crypto_aead_encrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {

  Aes aes;
  int ret;
  int result_len;
  int nonce_length;
  byte *authTag = NULL;
  const coap_crypto_aes_ccm_t *ccm;

  if (data == NULL)
    return 0;

  assert(params != NULL);
  if (!params)
    return 0;

  ccm = &params->params.aes;

  if (ccm->key.s == NULL || ccm->nonce == NULL)
    goto error;

  result_len = data->length;
  nonce_length = 15 - ccm->l;

  memset(&aes, 0, sizeof(aes));
  ret = wc_AesCcmSetKey(&aes, ccm->key.s, ccm->key.length);
  if (ret != 0)
    goto error;

  authTag = (byte *)malloc(ccm->tag_len * sizeof(byte));
  if (!authTag) {
    goto error;
  }
  ret = wc_AesCcmEncrypt(&aes, result, data->s, data->length, ccm->nonce,
                         nonce_length, authTag, ccm->tag_len,
                         aad->s, aad->length);

  if (ret != 0) {
    wolfssl_free(authTag);
    goto error;
  }

  memcpy(result + result_len, authTag, ccm->tag_len);
  result_len += sizeof(authTag);
  *max_result_len = result_len;
  wolfssl_free(authTag);

  return 1;
error:
  coap_crypto_output_errors("coap_crypto_aead_encrypt");
  return 0;
}


int
coap_crypto_aead_decrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {

  Aes aes;
  int ret;
  int len;
  const coap_crypto_aes_ccm_t *ccm;

  if (data == NULL)
    return 0;

  if (data == NULL)
    return 0;

  assert(params != NULL);
  if (!params)
    return 0;

  ccm = &params->params.aes;
  byte authTag[ccm->tag_len];

  if (data->length < ccm->tag_len) {
    return 0;
  } else {
    memcpy(authTag, data->s + data->length - ccm->tag_len, sizeof(authTag));
    data->length -= ccm->tag_len;
  }

  if (ccm->key.s == NULL || ccm->nonce == NULL)
    goto error;

  memset(&aes, 0, sizeof(aes));
  ret = wc_AesCcmSetKey(&aes, ccm->key.s, ccm->key.length);
  if (ret != 0)
    goto error;

  len = data->length;

  ret = wc_AesCcmDecrypt(&aes, result, data->s, len, ccm->nonce,
                         15 - ccm->l, authTag, sizeof(authTag),
                         aad->s, aad->length);

  if (ret != 0)
    goto error;

  *max_result_len = len;

  return 1;
error:
  coap_crypto_output_errors("coap_crypto_aead_decrypt");
  return 0;
}

int
coap_crypto_hmac(cose_hmac_alg_t hmac_alg,
                 coap_bin_const_t *key,
                 coap_bin_const_t *data,
                 coap_bin_const_t **hmac) {
  unsigned int result_len;
  const WOLFSSL_EVP_MD *evp_md;
  coap_binary_t *dummy = NULL;

  assert(key);
  assert(data);
  assert(hmac);

  if ((evp_md = get_hmac_alg(hmac_alg)) == 0) {
    coap_log_debug("coap_crypto_hmac: algorithm %d not supported\n", hmac_alg);
    return 0;
  }
  dummy = coap_new_binary(EVP_MAX_MD_SIZE);
  if (dummy == NULL)
    return 0;
  result_len = (unsigned int)dummy->length;
  if (wolfSSL_HMAC(evp_md,
                   key->s,
                   (int)key->length,
                   data->s,
                   (int)data->length,
                   dummy->s,
                   &result_len)) {
    dummy->length = result_len;
    *hmac = (coap_bin_const_t *)dummy;
    return 1;
  }

  coap_crypto_output_errors("coap_crypto_hmac");
  return 0;
}

#endif /* COAP_OSCORE_SUPPORT */

#else /* !COAP_WITH_LIBWOLFSSL */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* COAP_WITH_LIBWOLFSSL */
