/*
 * coap_openhitls.c -- openHiTLS Datagram Transport Layer Support for libcoap
 *
 * Copyright (C) 2026 openHiTLS Project.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_openhitls.c
 * @brief openHiTLS specific interface functions.
 */

#include "coap3/coap_libcoap_build.h"

#if COAP_WITH_LIBOPENHITLS || COAP_WITH_LIBOPENHITLS_OSCORE

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef COAP_EPOLL_SUPPORT
#include <sys/epoll.h>
#endif /* COAP_EPOLL_SUPPORT */

#include <hitls/bsl/bsl_err.h>
#include <hitls/bsl/bsl_errno.h>
#include <hitls/bsl/bsl_sal.h>
#include <hitls/bsl/bsl_uio.h>
#include <hitls/bsl/bsl_version.h>
#include <hitls/crypto/crypt_eal_cipher.h>
#include <hitls/crypto/crypt_eal_init.h>
#include <hitls/crypto/crypt_eal_mac.h>
#include <hitls/crypto/crypt_eal_md.h>
#include <hitls/crypto/crypt_eal_pkey.h>
#include <hitls/crypto/crypt_errno.h>
#if COAP_WITH_LIBOPENHITLS
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif /* defined(__GNUC__) */
#include <hitls/bsl/bsl_list.h>
#include <hitls/pki/hitls_pki_cert.h>
#include <hitls/pki/hitls_pki_errno.h>
#include <hitls/pki/hitls_pki_types.h>
#include <hitls/pki/hitls_pki_utils.h>
#include <hitls/pki/hitls_pki_x509.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif /* defined(__GNUC__) */
#include <hitls/tls/hitls.h>
#include <hitls/tls/hitls_alpn.h>
#include <hitls/tls/hitls_cert.h>
#include <hitls/tls/hitls_cert_init.h>
#include <hitls/tls/hitls_config.h>
#include <hitls/tls/hitls_cookie.h>
#include <hitls/tls/hitls_crypt_init.h>
#include <hitls/tls/hitls_debug.h>
#include <hitls/tls/hitls_error.h>
#include <hitls/tls/hitls_psk.h>
#include <hitls/tls/hitls_sni.h>
#endif /* COAP_WITH_LIBOPENHITLS */

#if COAP_WITH_LIBOPENHITLS
#define IS_PSK 0x01
#define IS_PKI 0x02
#define COAP_HITLS_DTLS_OVERHEAD 37
#define COAP_HITLS_IPV4_UDP_OVERHEAD 28
#define COAP_HITLS_IPV6_UDP_OVERHEAD 48
#define COAP_HITLS_COOKIE_SECRET_LEN 32
#define COAP_HITLS_COOKIE_LEN 32
/* +1 converts libcoap verify_depth to the intermediate-CA limit.
 * +2 adds the leaf certificate and trust anchor for openHiTLS maxDepth.
 */
#define COAP_HITLS_VERIFY_DEPTH_TO_MAX_CHAIN_DEPTH(depth) \
  ((depth) + 1 + 2)

typedef struct coap_hitls_context_t {
  coap_context_t *coap_context;
  coap_dtls_pki_t setup_data;
  char *root_ca_file;
  char *root_ca_dir;
  int psk_pki_enabled;
  int trust_store_defined;
  int cookie_secret_set;
  uint8_t cookie_secret[COAP_HITLS_COOKIE_SECRET_LEN];
} coap_hitls_context_t;

typedef struct coap_hitls_env_t {
  HITLS_Ctx *ctx;
  BSL_UIO *uio;
  BSL_UIO_Method *method;
  const uint8_t *pdu;
  size_t pdu_len;
  coap_session_t *session;
  int established;
  coap_dtls_role_t role;
  coap_proto_t proto;
  int hello_verify_sent;
  int mtu_exceeded;
  int had_fatal;
  coap_tick_t last_timeout;
} coap_hitls_env_t;

static coap_log_t dtls_log_level = COAP_LOG_EMERG;
#endif /* COAP_WITH_LIBOPENHITLS */
static int coap_hitls_started = 0;
#if COAP_WITH_LIBOPENHITLS
static const uint8_t coap_hitls_alpn[] = { 4, 'c', 'o', 'a', 'p' };
static const uint16_t coap_hitls_psk_cipher_suites[] = {
  HITLS_PSK_WITH_AES_128_GCM_SHA256,
  HITLS_PSK_WITH_AES_256_GCM_SHA384,
  HITLS_PSK_WITH_AES_256_CCM,
  HITLS_PSK_WITH_CHACHA20_POLY1305_SHA256
};
static const uint16_t coap_hitls_pki_cipher_suites[] = {
  HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
  HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384
};
static const uint16_t coap_hitls_psk_pki_cipher_suites[] = {
  HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
  HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
  HITLS_PSK_WITH_AES_128_GCM_SHA256,
  HITLS_PSK_WITH_AES_256_GCM_SHA384,
  HITLS_PSK_WITH_AES_256_CCM,
  HITLS_PSK_WITH_CHACHA20_POLY1305_SHA256
};

static void
coap_hitls_get_cipher_suites(int enabled, const uint16_t **cipher_suites,
                             uint32_t *cipher_suites_count) {
  if ((enabled & IS_PSK) && (enabled & IS_PKI)) {
    *cipher_suites = coap_hitls_psk_pki_cipher_suites;
    *cipher_suites_count =
        (uint32_t)(sizeof(coap_hitls_psk_pki_cipher_suites) /
                   sizeof(coap_hitls_psk_pki_cipher_suites[0]));
  } else if (enabled & IS_PKI) {
    *cipher_suites = coap_hitls_pki_cipher_suites;
    *cipher_suites_count =
        (uint32_t)(sizeof(coap_hitls_pki_cipher_suites) /
                   sizeof(coap_hitls_pki_cipher_suites[0]));
  } else {
    *cipher_suites = coap_hitls_psk_cipher_suites;
    *cipher_suites_count =
        (uint32_t)(sizeof(coap_hitls_psk_cipher_suites) /
                   sizeof(coap_hitls_psk_cipher_suites[0]));
  }
}

static void
coap_hitls_mark_fatal(coap_session_t *session) {
  coap_hitls_env_t *env = session ? (coap_hitls_env_t *)session->tls : NULL;

  if (env)
    env->had_fatal = 1;
}

static void
coap_hitls_log_err_stack(const coap_session_t *session) {
  int32_t e;

  while ((e = BSL_ERR_GetError()) != BSL_SUCCESS)
    coap_dtls_log(COAP_LOG_WARN, "*  %s: openHiTLS error 0x%08x\n",
                  coap_session_str(session), (unsigned int)e);
}

static void
coap_hitls_log_fatal_err_stack(coap_session_t *session) {
  coap_hitls_mark_fatal(session);
  coap_hitls_log_err_stack(session);
}

/* TLS alert levels and descriptions as defined by RFC 5246 / RFC 8446. */
enum {
  ALERT_LEVEL_WARNING = 1,
  ALERT_LEVEL_FATAL = 2,
  ALERT_CLOSE_NOTIFY = 0,
  ALERT_UNEXPECTED_MESSAGE = 10,
  ALERT_BAD_RECORD_MAC = 20,
  ALERT_RECORD_OVERFLOW = 22,
  ALERT_HANDSHAKE_FAILURE = 40,
  ALERT_BAD_CERTIFICATE = 42,
  ALERT_UNSUPPORTED_CERTIFICATE = 43,
  ALERT_CERTIFICATE_REVOKED = 44,
  ALERT_CERTIFICATE_EXPIRED = 45,
  ALERT_ILLEGAL_PARAMETER = 47,
  ALERT_UNKNOWN_CA = 48,
  ALERT_DECODE_ERROR = 50,
  ALERT_DECRYPT_ERROR = 51,
  ALERT_PROTOCOL_VERSION = 70,
  ALERT_INSUFFICIENT_SECURITY = 71,
  ALERT_INTERNAL_ERROR = 80,
  ALERT_INAPPROPRIATE_FALLBACK = 86,
  ALERT_NO_RENEGOTIATION = 100,
  ALERT_MISSING_EXTENSION = 109,
  ALERT_UNSUPPORTED_EXTENSION = 110,
  ALERT_UNRECOGNIZED_NAME = 112,
  ALERT_CERTIFICATE_REQUIRED = 116,
  ALERT_NO_APPLICATION_PROTOCOL = 120
};

static const char *
coap_hitls_alert_desc(int desc) {
  switch (desc) {
  case ALERT_CLOSE_NOTIFY:
    return "close_notify";
  case ALERT_UNEXPECTED_MESSAGE:
    return "unexpected_message";
  case ALERT_BAD_RECORD_MAC:
    return "bad_record_mac";
  case ALERT_RECORD_OVERFLOW:
    return "record_overflow";
  case ALERT_HANDSHAKE_FAILURE:
    return "handshake_failure";
  case ALERT_BAD_CERTIFICATE:
    return "bad_certificate";
  case ALERT_UNSUPPORTED_CERTIFICATE:
    return "unsupported_certificate";
  case ALERT_CERTIFICATE_REVOKED:
    return "certificate_revoked";
  case ALERT_CERTIFICATE_EXPIRED:
    return "certificate_expired";
  case ALERT_ILLEGAL_PARAMETER:
    return "illegal_parameter";
  case ALERT_UNKNOWN_CA:
    return "unknown_ca";
  case ALERT_DECODE_ERROR:
    return "decode_error";
  case ALERT_DECRYPT_ERROR:
    return "decrypt_error";
  case ALERT_PROTOCOL_VERSION:
    return "protocol_version";
  case ALERT_INSUFFICIENT_SECURITY:
    return "insufficient_security";
  case ALERT_INTERNAL_ERROR:
    return "internal_error";
  case ALERT_INAPPROPRIATE_FALLBACK:
    return "inappropriate_fallback";
  case ALERT_NO_RENEGOTIATION:
    return "no_renegotiation";
  case ALERT_MISSING_EXTENSION:
    return "missing_extension";
  case ALERT_UNSUPPORTED_EXTENSION:
    return "unsupported_extension";
  case ALERT_UNRECOGNIZED_NAME:
    return "unrecognized_name";
  case ALERT_CERTIFICATE_REQUIRED:
    return "certificate_required";
  case ALERT_NO_APPLICATION_PROTOCOL:
    return "no_application_protocol";
  default:
    return "unknown";
  }
}

/* The info callback packs the alert as (level << 8) | description. */
static void
coap_hitls_info_cb(const HITLS_Ctx *ctx, int32_t event_type, int32_t value) {
  coap_session_t *session = (coap_session_t *)HITLS_GetUserData(ctx);
  int alert_level = (value >> 8) & 0xff;
  int alert_desc = value & 0xff;
  const char *dir;

  if ((event_type & INDICATE_EVENT_ALERT) == 0 || !session)
    return;
  dir = (event_type & INDICATE_EVENT_READ) ? "received" : "sent";
  if (alert_level == ALERT_LEVEL_FATAL && alert_desc != ALERT_CLOSE_NOTIFY)
    coap_log_warn("*  %s: openHiTLS %s fatal alert: %s (%d)\n",
                  coap_session_str(session), dir,
                  coap_hitls_alert_desc(alert_desc), alert_desc);
  else
    coap_log_info("*  %s: openHiTLS %s alert: %s (%d)\n",
                  coap_session_str(session), dir,
                  coap_hitls_alert_desc(alert_desc), alert_desc);
}

static const char *
coap_hitls_verify_err_str(int32_t err) {
  switch (err) {
  case HITLS_X509_ERR_TIME_EXPIRED:
  case HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED:
    return "certificate expired";
  case HITLS_X509_ERR_TIME_FUTURE:
  case HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE:
    return "certificate not yet valid";
  case HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND:
    return "issuer certificate not found";
  case HITLS_X509_ERR_ROOT_CERT_NOT_FOUND:
    return "self-signed or root CA not found";
  case HITLS_X509_ERR_VFY_CRL_NOT_FOUND:
    return "CRL not found";
  case HITLS_X509_ERR_VFY_THISUPDATE_IN_FUTURE:
  case HITLS_X509_ERR_VFY_NEXTUPDATE_EXPIRED:
    return "CRL expired or not yet valid";
  case HITLS_X509_ERR_VFY_CHECK_SECBITS:
    return "certificate security strength too low";
  case HITLS_X509_ERR_VFY_HOSTNAME_FAIL:
    return "hostname mismatch";
  case HITLS_X509_ERR_VFY_GET_NOTBEFORE_FAIL:
    return "cannot read certificate validity start";
  case HITLS_X509_ERR_VFY_GET_NOTAFTER_FAIL:
    return "cannot read certificate validity end";
  case BSL_SAL_TIME_SYS_ERROR:
    return "system time unavailable";
  default:
    return "certificate verification failed";
  }
}
#endif /* COAP_WITH_LIBOPENHITLS */

static int
coap_hitls_startup(void) {
  if (!coap_hitls_started) {
    int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);

    if (ret != CRYPT_SUCCESS) {
      coap_log_err("CRYPT_EAL_Init() returned 0x%x\n", (unsigned int)ret);
      return 0;
    }
#if COAP_WITH_LIBOPENHITLS
    ret = HITLS_CertMethodInit();
    if (ret != HITLS_SUCCESS) {
      coap_log_err("HITLS_CertMethodInit() returned 0x%x\n",
                   (unsigned int)ret);
      CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
      return 0;
    }
    HITLS_CryptMethodInit();
#endif /* COAP_WITH_LIBOPENHITLS */
    coap_hitls_started = 1;
  }
  return coap_hitls_started;
}

#if COAP_WITH_LIBOPENHITLS
static char *
coap_hitls_strdup(const char *s) {
  size_t len;
  char *copy;

  if (!s)
    return NULL;
  len = strlen(s);
  copy = (char *)coap_malloc_type(COAP_STRING, len + 1);
  if (!copy)
    return NULL;
  memcpy(copy, s, len + 1);
  return copy;
}

static uint8_t *
coap_hitls_read_file(const char *file, uint32_t *buf_len) {
  FILE *fp;
  long file_len;
  uint8_t *buf = NULL;
  size_t read_len;

  if (!file || !buf_len)
    return NULL;

  fp = fopen(file, "rb");
  if (!fp)
    return NULL;

  if (fseek(fp, 0, SEEK_END) != 0)
    goto fail;
  file_len = ftell(fp);
  if (file_len <= 0 || (uintmax_t)file_len > UINT32_MAX)
    goto fail;
  if (fseek(fp, 0, SEEK_SET) != 0)
    goto fail;

  buf = (uint8_t *)coap_malloc_type(COAP_STRING, (size_t)file_len);
  if (!buf)
    goto fail;
  read_len = fread(buf, 1, (size_t)file_len, fp);
  if (read_len != (size_t)file_len) {
    coap_free_type(COAP_STRING, buf);
    buf = NULL;
    goto fail;
  }
  fclose(fp);
  *buf_len = (uint32_t)read_len;
  return buf;

fail:
  fclose(fp);
  return NULL;
}

static size_t
coap_hitls_strnlen(const uint8_t *s, size_t max_len) {
  size_t len = 0;

  if (!s)
    return 0;
  while (len < max_len && s[len])
    len++;
  return len;
}

static uint32_t
coap_hitls_copy_bin(uint8_t *dst, uint32_t dst_len,
                    const coap_bin_const_t *src, int add_nul) {
  size_t extra = add_nul ? 1 : 0;

  if (!dst || !src || !src->s ||
      extra > (size_t)dst_len || src->length > (size_t)dst_len - extra)
    return 0;
  memcpy(dst, src->s, src->length);
  if (add_nul)
    dst[src->length] = '\000';
  return (uint32_t)src->length;
}

#if COAP_SERVER_SUPPORT
static int
coap_hitls_cookie_mac(coap_session_t *session, uint8_t *cookie,
                      uint32_t *cookie_len) {
  static const uint8_t cookie_label[] = "libcoap openhitls dtls cookie";
  coap_hitls_context_t *context;
  CRYPT_EAL_MacCtx *ctx = NULL;
  uint32_t out_len;
  int ret = 0;

  if (!session || !session->context || !cookie || !cookie_len ||
      *cookie_len < COAP_HITLS_COOKIE_LEN ||
      session->addr_info.local.size == 0 ||
      session->addr_info.remote.size == 0)
    return 0;

  context = (coap_hitls_context_t *)session->context->dtls_context;
  if (!context || !context->cookie_secret_set)
    return 0;

  ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_HMAC_SHA256);
  if (!ctx)
    return 0;

  out_len = *cookie_len;
  if (CRYPT_EAL_MacInit(ctx, context->cookie_secret,
                        COAP_HITLS_COOKIE_SECRET_LEN) != CRYPT_SUCCESS)
    goto finish;
  if (CRYPT_EAL_MacUpdate(ctx, cookie_label,
                          (uint32_t)sizeof(cookie_label) - 1) != CRYPT_SUCCESS)
    goto finish;
  if (CRYPT_EAL_MacUpdate(ctx,
                          (const uint8_t *)&session->addr_info.local.addr,
                          (uint32_t)session->addr_info.local.size) != CRYPT_SUCCESS)
    goto finish;
  if (CRYPT_EAL_MacUpdate(ctx,
                          (const uint8_t *)&session->addr_info.remote.addr,
                          (uint32_t)session->addr_info.remote.size) != CRYPT_SUCCESS)
    goto finish;
  if (CRYPT_EAL_MacFinal(ctx, cookie, &out_len) != CRYPT_SUCCESS ||
      out_len != COAP_HITLS_COOKIE_LEN)
    goto finish;

  *cookie_len = out_len;
  ret = 1;

finish:
  CRYPT_EAL_MacFreeCtx(ctx);
  return ret;
}

static int
coap_hitls_cookie_equal(const uint8_t *a, const uint8_t *b, uint32_t len) {
  uint8_t diff = 0;
  uint32_t i;

  for (i = 0; i < len; i++)
    diff |= (uint8_t)(a[i] ^ b[i]);
  return diff == 0;
}

static int32_t
coap_hitls_cookie_gen_cb(HITLS_Ctx *ctx, uint8_t *cookie,
                         uint32_t *cookie_len) {
  coap_session_t *session = (coap_session_t *)HITLS_GetUserData(ctx);

  return coap_hitls_cookie_mac(session, cookie, cookie_len) ?
         HITLS_COOKIE_GENERATE_SUCCESS : HITLS_COOKIE_GENERATE_ERROR;
}

static int32_t
coap_hitls_cookie_verify_cb(HITLS_Ctx *ctx, const uint8_t *cookie,
                            uint32_t cookie_len) {
  uint8_t expected[COAP_HITLS_COOKIE_LEN];
  uint32_t expected_len = sizeof(expected);
  coap_session_t *session = (coap_session_t *)HITLS_GetUserData(ctx);

  if (!cookie || cookie_len != COAP_HITLS_COOKIE_LEN ||
      !coap_hitls_cookie_mac(session, expected, &expected_len) ||
      expected_len != cookie_len ||
      !coap_hitls_cookie_equal(cookie, expected, cookie_len))
    return HITLS_COOKIE_VERIFY_ERROR;
  return HITLS_COOKIE_VERIFY_SUCCESS;
}

static uint32_t
coap_hitls_u24(const uint8_t *p) {
  return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static int
coap_hitls_client_hello_cookie_valid(coap_session_t *session,
                                     const uint8_t *data, size_t data_len) {
  uint8_t expected[COAP_HITLS_COOKIE_LEN];
  uint32_t expected_len = sizeof(expected);
  size_t body_offset = 13 + 12;
  size_t body_end;
  size_t offset;
  uint32_t record_len;
  uint32_t hs_len;
  uint32_t frag_offset;
  uint32_t frag_len;
  uint8_t session_id_len;
  uint8_t cookie_len;

  if (!data || data_len < body_offset || data[0] != 22 || data[13] != 1)
    return -1;

  record_len = ((uint32_t)data[11] << 8) | data[12];
  hs_len = coap_hitls_u24(&data[14]);
  frag_offset = coap_hitls_u24(&data[19]);
  frag_len = coap_hitls_u24(&data[22]);
  if (record_len > data_len - 13 || hs_len > record_len - 12 ||
      frag_offset != 0 || frag_len != hs_len)
    return -1;

  body_end = body_offset + hs_len;
  if (body_end > data_len || body_end < body_offset + 35)
    return -1;

  offset = body_offset + 34;
  session_id_len = data[offset++];
  if (offset + session_id_len + 1 > body_end)
    return -1;
  offset += session_id_len;

  cookie_len = data[offset++];
  if (cookie_len == 0)
    return 0;
  if (offset + cookie_len > body_end ||
      cookie_len != COAP_HITLS_COOKIE_LEN ||
      !coap_hitls_cookie_mac(session, expected, &expected_len) ||
      expected_len != cookie_len)
    return -1;

  return coap_hitls_cookie_equal(&data[offset], expected, cookie_len) ? 1 : -1;
}
#endif /* COAP_SERVER_SUPPORT */

static int
coap_hitls_pki_len(const uint8_t *buf, size_t len, HITLS_ParseFormat format,
                   uint32_t *out_len) {
  if (!buf)
    return 0;
  if (format == TLS_PARSE_FORMAT_PEM && len && buf[len - 1] == '\000')
    len--;
  if (len > UINT32_MAX)
    return 0;
  *out_len = (uint32_t)len;
  return 1;
}

static int
coap_hitls_key_define_supported(coap_pki_define_t define) {
  switch (define) {
  case COAP_PKI_KEY_DEF_PEM:
  case COAP_PKI_KEY_DEF_PEM_BUF:
  case COAP_PKI_KEY_DEF_DER:
  case COAP_PKI_KEY_DEF_DER_BUF:
    return 1;
  case COAP_PKI_KEY_DEF_RPK_BUF:
  case COAP_PKI_KEY_DEF_PKCS11:
  case COAP_PKI_KEY_DEF_PKCS11_RPK:
  case COAP_PKI_KEY_DEF_ENGINE:
  default:
    return 0;
  }
}

static int
coap_hitls_check_define_key(coap_dtls_key_t *key, coap_define_issue_key_t type,
                            coap_pki_define_t define,
                            const coap_dtls_role_t role) {
  if (coap_hitls_key_define_supported(define))
    return 1;
  return coap_dtls_define_issue(type, COAP_DEFINE_FAIL_NOT_SUPPORTED, key,
                                role, 0);
}

static int
coap_hitls_check_pki_key_supported(const coap_dtls_pki_t *setup_data,
                                   const coap_dtls_role_t role) {
  coap_dtls_key_t key;

  if (setup_data->is_rpk_not_cert) {
    coap_log_warn("openHiTLS backend has no RPK support\n");
    return 0;
  }
  if (setup_data->pki_key.key_type == COAP_PKI_KEY_PKCS11) {
    coap_log_warn("openHiTLS backend has no PKCS11 support\n");
    return 0;
  }

  coap_dtls_map_key_type_to_define(setup_data, &key);
  if (key.key_type != COAP_PKI_KEY_DEFINE)
    return 0;

  return coap_hitls_check_define_key(&key, COAP_DEFINE_KEY_CA,
                                     key.key.define.ca_def, role) &&
         coap_hitls_check_define_key(&key, COAP_DEFINE_KEY_PUBLIC,
                                     key.key.define.public_cert_def, role) &&
         coap_hitls_check_define_key(&key, COAP_DEFINE_KEY_PRIVATE,
                                     key.key.define.private_key_def, role);
}

static int
coap_hitls_verify_error_allowed(const coap_dtls_pki_t *setup_data,
                                int32_t err_code) {
  if (err_code == HITLS_PKI_SUCCESS)
    return 1;
  if (!setup_data || !setup_data->verify_peer_cert)
    return 1;

  switch (err_code) {
  case HITLS_X509_ERR_TIME_EXPIRED:
  case HITLS_X509_ERR_TIME_FUTURE:
  case HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE:
  case HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED:
    return setup_data->allow_expired_certs;
  case HITLS_X509_ERR_VFY_CRL_NOT_FOUND:
    return !setup_data->check_cert_revocation || setup_data->allow_no_crl;
  case HITLS_X509_ERR_VFY_THISUPDATE_IN_FUTURE:
  case HITLS_X509_ERR_VFY_NEXTUPDATE_EXPIRED:
    return !setup_data->check_cert_revocation ||
           setup_data->allow_expired_crl;
  default:
    return 0;
  }
}

static int
coap_hitls_get_verify_session(HITLS_CERT_StoreCtx *store_ctx,
                              coap_session_t **session) {
  HITLS_Ctx *ctx = NULL;

  if (!store_ctx || !session)
    return 0;
  *session = NULL;
  if (HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
                              HITLS_X509_STORECTX_GET_USR_DATA,
                              &ctx, sizeof(ctx)) != HITLS_PKI_SUCCESS ||
      !ctx)
    return 0;
  *session = (coap_session_t *)HITLS_GetUserData(ctx);
  return *session != NULL;
}

static int
coap_hitls_get_verify_cert(HITLS_CERT_StoreCtx *store_ctx,
                           HITLS_X509_Cert **cert, int32_t *depth) {
  if (!store_ctx || !cert || !depth)
    return 0;

  *cert = NULL;
  *depth = 0;
  (void)HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
                                HITLS_X509_STORECTX_GET_CUR_DEPTH,
                                depth, sizeof(*depth));
  return HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
                                 HITLS_X509_STORECTX_GET_CUR_CERT,
                                 cert, sizeof(*cert)) == HITLS_PKI_SUCCESS &&
         *cert;
}

static int
coap_hitls_cert_is_self_signed(HITLS_X509_Cert *cert) {
  bool self_signed = false;

  return cert &&
         HITLS_X509_CertCtrl(cert, HITLS_X509_IS_SELF_SIGNED,
                             &self_signed,
                             sizeof(self_signed)) == HITLS_PKI_SUCCESS &&
         self_signed;
}

/*
 * The self-signed override bypasses the library chain verification, which is
 * where the validity period is normally checked. Apply the same check here,
 * using the library time helpers, so an expired or not-yet-valid self-signed
 * leaf is not accepted. Returns HITLS_PKI_SUCCESS or a specific failure code.
 */
static int32_t
coap_hitls_cert_time_valid(HITLS_X509_Cert *cert) {
  BSL_TIME not_before;
  BSL_TIME not_after;
  int64_t start;
  int64_t end;
  int64_t now = BSL_SAL_CurrentSysTimeGet();

  if (now <= 0)
    return BSL_SAL_TIME_SYS_ERROR;
  if (HITLS_X509_CertCtrl(cert, HITLS_X509_GET_BEFORE_TIME, &not_before,
                          sizeof(not_before)) != HITLS_PKI_SUCCESS ||
      BSL_SAL_DateToUtcTimeConvert(&not_before, &start) != BSL_SUCCESS)
    return HITLS_X509_ERR_VFY_GET_NOTBEFORE_FAIL;
  if (start > now)
    return HITLS_X509_ERR_VFY_NOTBEFORE_IN_FUTURE;
  if (HITLS_X509_CertCtrl(cert, HITLS_X509_GET_AFTER_TIME, &not_after,
                          sizeof(not_after)) != HITLS_PKI_SUCCESS ||
      BSL_SAL_DateToUtcTimeConvert(&not_after, &end) != BSL_SUCCESS)
    return HITLS_X509_ERR_VFY_GET_NOTAFTER_FAIL;
  if (end < now)
    return HITLS_X509_ERR_VFY_NOTAFTER_EXPIRED;
  return HITLS_PKI_SUCCESS;
}

static int
coap_hitls_get_peer_leaf_cert(HITLS_CERT_StoreCtx *store_ctx,
                              HITLS_X509_Cert **cert,
                              int32_t *chain_count) {
  HITLS_X509_List *peer_chain = NULL;

  if (!store_ctx || !cert || !chain_count)
    return 0;

  *cert = NULL;
  *chain_count = 0;
  if (HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
                              HITLS_X509_STORECTX_GET_PEER_CERT_CHAIN,
                              &peer_chain,
                              sizeof(peer_chain)) != HITLS_PKI_SUCCESS ||
      !peer_chain)
    return 0;

  *chain_count = BSL_LIST_COUNT(peer_chain);
  *cert = (HITLS_X509_Cert *)BSL_LIST_FIRST_ELMT(peer_chain);
  return *cert != NULL;
}

static int
coap_hitls_self_signed_leaf_allowed(const coap_dtls_pki_t *setup_data,
                                    HITLS_CERT_StoreCtx *store_ctx,
                                    HITLS_X509_Cert **leaf_cert) {
  HITLS_X509_Cert *cert = NULL;
  int32_t chain_count = 0;

  if (leaf_cert)
    *leaf_cert = NULL;
  if (!setup_data || !setup_data->allow_self_signed ||
      setup_data->check_common_ca)
    return 0;
  if (!coap_hitls_get_peer_leaf_cert(store_ctx, &cert, &chain_count) ||
      chain_count != 1 || !coap_hitls_cert_is_self_signed(cert))
    return 0;
  if (leaf_cert)
    *leaf_cert = cert;
  return 1;
}

static int
coap_hitls_verify_cb_self_signed_allowed(const coap_dtls_pki_t *setup_data,
                                         HITLS_CERT_StoreCtx *store_ctx) {
  HITLS_X509_Cert *cert = NULL;
  int32_t depth = 0;

  return setup_data && setup_data->allow_self_signed &&
         !setup_data->check_common_ca &&
         coap_hitls_get_verify_cert(store_ctx, &cert, &depth) &&
         depth == 0 && coap_hitls_cert_is_self_signed(cert);
}

static char *
coap_hitls_copy_name(const uint8_t *data, uint32_t data_len) {
  char *copy;
  size_t len = (size_t)data_len;

  if (data_len && !data)
    return NULL;
  copy = (char *)coap_malloc_type(COAP_STRING, len + 1);
  if (!copy)
    return NULL;
  if (len)
    memcpy(copy, data, len);
  copy[len] = '\000';
  return copy;
}

static char *
coap_hitls_get_san_from_cert(coap_session_t *session, HITLS_X509_Cert *cert,
                             const char *sni_match, int report_san) {
  HITLS_X509_ExtSan san = {0};
  char *dns_name = NULL;

  if (HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SAN, &san,
                          sizeof(san)) == HITLS_PKI_SUCCESS &&
      san.names) {
    int n = 0;

    for (BslListNode *name_node = BSL_LIST_FirstNode(san.names);
         name_node != NULL;
         name_node = BSL_LIST_GetNextNode(san.names, name_node)) {
      const HITLS_X509_GeneralName *name =
          (const HITLS_X509_GeneralName *)BSL_LIST_GetData(name_node);

      if (!name || name->type != HITLS_X509_GN_DNS)
        continue;
      if (name->value.dataLen &&
          memchr(name->value.data, '\000', name->value.dataLen))
        continue;
      if (report_san) {
        coap_log_debug("   %s: got DNS.%d '%*.*s'\n",
                       coap_session_str(session), n + 1, (int)name->value.dataLen, (int)name->value.dataLen,
                       name->value.data);
        n++;
        continue;
      }
      if (sni_match) {
        if (strlen(sni_match) != name->value.dataLen ||
            memcmp(name->value.data, sni_match, name->value.dataLen)) {
          continue;
        }
      }
      dns_name = coap_hitls_copy_name(name->value.data, name->value.dataLen);
      break;
    }
  }

  HITLS_X509_ClearSubjectAltName(&san);
  return dns_name;
}

static char *
coap_hitls_get_cn_from_cert(coap_session_t *session, HITLS_X509_Cert *cert, const char *sni_match) {
  BSL_Buffer cn = {0};
  char *cn_name = NULL;

  if (HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SUBJECT_CN_STR,
                          &cn, sizeof(cn)) == HITLS_PKI_SUCCESS) {
    if (cn.data && coap_pki_name_match_sni((char *)cn.data, cn.dataLen, sni_match)) {
      cn_name = coap_hitls_copy_name(cn.data, cn.dataLen);
    }
  }
  if (cn.data && !cn_name) {
    coap_log_debug("   %s: got CN '%*.*s'\n",
                   coap_session_str(session), (int)cn.dataLen, (int)cn.dataLen, cn.data);
  }
  if (cn.data)
    BSL_SAL_Free(cn.data);
  return cn_name;
}

static char *
coap_hitls_get_san_or_cn_from_cert(coap_session_t *session, HITLS_X509_Cert *cert,
                                   const char *sni_match) {
  char *name;

  if (!cert)
    return NULL;
  name = coap_hitls_get_san_from_cert(session, cert, sni_match, 0);
  if (name)
    return name;
  name = coap_hitls_get_cn_from_cert(session, cert, sni_match);
  if (!name) {
    name = coap_hitls_get_san_from_cert(session, cert, sni_match, 1);
  }
  return name;
}

static int
coap_hitls_validate_cn_cert(coap_session_t *session,
                            const coap_dtls_pki_t *setup_data,
                            HITLS_X509_Cert *cert,
                            unsigned depth,
                            int validated,
                            char **san_or_cn) {
  uint8_t *der = NULL;
  uint32_t der_len = 0;
  int ret = 1;

  (void)HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODELEN,
                            &der_len, sizeof(der_len));
  if (der_len)
    (void)HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODE,
                              &der, sizeof(der));
  if (!*san_or_cn)
    *san_or_cn = coap_hitls_get_san_or_cn_from_cert(session, cert, NULL);

  if (setup_data->validate_cn_call_back) {
    coap_lock_callback_ret(ret,
                           setup_data->validate_cn_call_back(
                               *san_or_cn ? *san_or_cn : "",
                               der, der_len, session, depth, validated,
                               setup_data->cn_call_back_arg));
  }
  return ret;
}

static int
coap_hitls_verify_cb(int32_t err_code, HITLS_CERT_StoreCtx *store_ctx) {
  coap_session_t *session = NULL;
  coap_hitls_context_t *context;
  coap_dtls_pki_t *setup_data;
  HITLS_X509_Cert *cert;
  int32_t depth;
  int allowed;
  char *san_or_cn = NULL;

  if (!coap_hitls_get_verify_session(store_ctx, &session) ||
      !session->context || !session->context->dtls_context)
    return err_code;

  context = (coap_hitls_context_t *)session->context->dtls_context;
  setup_data = &context->setup_data;

  if (!coap_hitls_get_verify_cert(store_ctx, &cert, &depth)) {
    return err_code;
  }
  if (!setup_data->allow_sni_cn_mismatch && depth <= 0 &&
      session->type == COAP_SESSION_TYPE_CLIENT && setup_data->client_sni) {

    san_or_cn = coap_hitls_get_san_or_cn_from_cert(session, cert, setup_data->client_sni);
    if (!san_or_cn) {
      /* No match on returned Cert for requested host */
      coap_log_warn("*  %s: SNI '%s' not returned in certificate\n",
                    coap_session_str(session),
                    setup_data->client_sni);
      return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    }
  }
  if (setup_data->validate_cn_call_back) {
    if (!coap_hitls_validate_cn_cert(session, setup_data, cert,
                                     depth < 0 ? 0 : (unsigned)depth,
                                     err_code == HITLS_PKI_SUCCESS, &san_or_cn)) {
      coap_log_warn("*  %s: certificate verification failed: %s\n",
                    coap_session_str(session),
                    coap_hitls_verify_err_str(HITLS_X509_ERR_VFY_HOSTNAME_FAIL));
      if (san_or_cn)
        coap_free_type(COAP_STRING, san_or_cn);
      return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    }
  }
  if (san_or_cn)
    coap_free_type(COAP_STRING, san_or_cn);

  if (err_code == HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND ||
      err_code == HITLS_X509_ERR_ROOT_CERT_NOT_FOUND) {
    allowed = coap_hitls_verify_cb_self_signed_allowed(setup_data,
                                                       store_ctx);
  } else {
    allowed = coap_hitls_verify_error_allowed(setup_data, err_code);
  }
  if (!allowed) {
    coap_log_warn("*  %s: certificate verification failed: %s (0x%x)\n",
                  coap_session_str(session),
                  coap_hitls_verify_err_str(err_code), (unsigned int)err_code);
    return err_code;
  }

  return HITLS_PKI_SUCCESS;
}

static int32_t
coap_hitls_app_verify_cb(HITLS_CERT_StoreCtx *store_ctx,
                         void *arg COAP_UNUSED) {
  coap_session_t *session = NULL;
  coap_hitls_context_t *context;
  coap_dtls_pki_t *setup_data;
  HITLS_X509_List *peer_chain = NULL;
  HITLS_X509_Cert *leaf_cert = NULL;
  int32_t ret;

  if (!coap_hitls_get_verify_session(store_ctx, &session) ||
      !session->context || !session->context->dtls_context)
    return HITLS_X509_ERR_INVALID_PARAM;

  if (HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store_ctx,
                              HITLS_X509_STORECTX_GET_PEER_CERT_CHAIN,
                              &peer_chain,
                              sizeof(peer_chain)) != HITLS_PKI_SUCCESS ||
      !peer_chain)
    return HITLS_X509_ERR_INVALID_PARAM;

  ret = HITLS_X509_CertVerify((HITLS_X509_StoreCtx *)store_ctx, peer_chain);
  if (ret == HITLS_PKI_SUCCESS)
    return HITLS_APP_VERIFY_CALLBACK_SUCCESS;

  context = (coap_hitls_context_t *)session->context->dtls_context;
  setup_data = &context->setup_data;
  if ((ret == HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND ||
       ret == HITLS_X509_ERR_ROOT_CERT_NOT_FOUND) &&
      coap_hitls_self_signed_leaf_allowed(setup_data, store_ctx,
                                          &leaf_cert)) {
    char *san_or_cn = NULL;
    if (!setup_data->allow_expired_certs) {
      int32_t time_ret = coap_hitls_cert_time_valid(leaf_cert);

      if (time_ret != HITLS_PKI_SUCCESS) {
        coap_log_warn("*  %s: certificate verification failed: %s\n",
                      coap_session_str(session),
                      coap_hitls_verify_err_str(time_ret));
        return time_ret;
      }
    }
    coap_log_info("   %s: %s: overridden: 'self-signed' depth=0\n",
                  coap_session_str(session),
                  coap_hitls_verify_err_str(ret));
    if (!coap_hitls_validate_cn_cert(session, setup_data, leaf_cert, 0, 0, &san_or_cn)) {
      if (san_or_cn)
        coap_free_type(COAP_STRING, san_or_cn);
      return HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    }
    if (san_or_cn)
      coap_free_type(COAP_STRING, san_or_cn);
    return HITLS_APP_VERIFY_CALLBACK_SUCCESS;
  }

  return ret;
}

static int
coap_hitls_is_retry(int32_t ret) {
  switch (ret) {
  case HITLS_WANT_CONNECT:
  case HITLS_WANT_ACCEPT:
  case HITLS_WANT_READ:
  case HITLS_WANT_WRITE:
  case HITLS_WANT_BACKUP:
  case HITLS_WANT_CLIENT_HELLO_CB:
  case HITLS_WANT_X509_LOOKUP:
  case HITLS_REC_NORMAL_IO_BUSY:
  case HITLS_REC_NORMAL_RECV_BUF_EMPTY:
    return 1;
  default:
    return 0;
  }
}

static int
coap_hitls_is_closed(int32_t ret) {
  return ret == HITLS_CM_LINK_CLOSED;
}

static uint8_t
coap_hitls_udp_overhead(const coap_hitls_env_t *env) {
#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI) && !defined(RIOT_VERSION)
  if (env && env->session) {
    switch (env->session->addr_info.remote.addr.sa.sa_family) {
#ifdef AF_INET6
    case AF_INET6:
      return COAP_HITLS_IPV6_UDP_OVERHEAD;
#endif /* AF_INET6 */
#ifdef AF_INET
    case AF_INET:
#endif /* AF_INET */
    default:
      break;
    }
  }
#else /* WITH_LWIP || WITH_CONTIKI || RIOT_VERSION */
  (void)env;
#endif /* WITH_LWIP || WITH_CONTIKI || RIOT_VERSION */
  return COAP_HITLS_IPV4_UDP_OVERHEAD;
}

static void
coap_hitls_set_connected(coap_session_t *session, coap_hitls_env_t *env) {
  if (env->established)
    return;

  env->established = 1;
  if (session->state == COAP_SESSION_STATE_HANDSHAKE) {
    coap_handle_event_lkd(session->context, COAP_EVENT_DTLS_CONNECTED,
                          session);
    session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
  }
}

static int
coap_hitls_check_handshake_done(coap_session_t *session,
                                coap_hitls_env_t *env) {
  uint8_t done = 0;

  if (HITLS_IsHandShakeDone(env->ctx, &done) == HITLS_SUCCESS && done) {
    coap_hitls_set_connected(session, env);
    return 1;
  }
  return 0;
}

static int
coap_hitls_handshake(coap_session_t *session, coap_hitls_env_t *env) {
  int32_t ret;

  BSL_ERR_ClearError();
  if (env->role == COAP_DTLS_ROLE_CLIENT)
    ret = HITLS_Connect(env->ctx);
  else
    ret = HITLS_Accept(env->ctx);

  if (ret == HITLS_SUCCESS)
    return coap_hitls_check_handshake_done(session, env);
  if (coap_hitls_check_handshake_done(session, env))
    return 1;
  if (coap_hitls_is_retry(ret))
    return 0;

  coap_log_warn("coap_hitls_handshake: returned 0x%x\n", (unsigned int)ret);
  coap_hitls_log_fatal_err_stack(session);
  session->dtls_event = COAP_EVENT_DTLS_ERROR;
  return -1;
}

static int32_t
coap_hitls_uio_write(BSL_UIO *uio, const void *buf, uint32_t len,
                     uint32_t *write_len) {
  coap_hitls_env_t *env = (coap_hitls_env_t *)BSL_UIO_GetUserData(uio);
  ssize_t ret;

  if (write_len)
    *write_len = 0;
  if (!env || !env->session || !buf || !write_len)
    return BSL_NULL_INPUT;
  if (!coap_netif_available(env->session)
#if COAP_SERVER_SUPPORT
      && env->session->endpoint == NULL
#endif /* COAP_SERVER_SUPPORT */
     ) {
    errno = ECONNRESET;
    return BSL_UIO_IO_EXCEPTION;
  }

  (void)BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
  ret = env->session->sock.lfunc[COAP_LAYER_TLS].l_write(env->session,
                                                         (const uint8_t *)buf, len);
  if (ret < 0) {
#ifdef EMSGSIZE
    if (errno == EMSGSIZE) {
      env->mtu_exceeded = 1;
      (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_WRITE | BSL_UIO_FLAGS_SHOULD_RETRY);
      return BSL_SUCCESS;
    }
#endif /* EMSGSIZE */
    if (errno == ENOTCONN || errno == ECONNREFUSED)
      env->session->dtls_event = COAP_EVENT_DTLS_ERROR;
    return BSL_UIO_IO_EXCEPTION;
  }
  if (ret == 0) {
    (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_WRITE | BSL_UIO_FLAGS_SHOULD_RETRY);
    return BSL_SUCCESS;
  }
  *write_len = (uint32_t)ret;
  return BSL_SUCCESS;
}

static int32_t
coap_hitls_uio_read(BSL_UIO *uio, void *buf, uint32_t len,
                    uint32_t *read_len) {
  coap_hitls_env_t *env = (coap_hitls_env_t *)BSL_UIO_GetUserData(uio);
  size_t copy_len;

  if (read_len)
    *read_len = 0;
  if (!env || !buf || !read_len)
    return BSL_NULL_INPUT;
  if (env->proto == COAP_PROTO_TLS) {
    ssize_t ret;

    (void)BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY);
    ret = env->session->sock.lfunc[COAP_LAYER_TLS].l_read(env->session,
                                                          (uint8_t *)buf, len);
    if (ret < 0)
      return errno == ECONNRESET ? BSL_UIO_IO_EOF : BSL_UIO_IO_EXCEPTION;
    if (ret == 0) {
      (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_READ | BSL_UIO_FLAGS_SHOULD_RETRY);
      return BSL_SUCCESS;
    }
    *read_len = (uint32_t)ret;
    return BSL_SUCCESS;
  }
  if (!env->pdu || env->pdu_len == 0) {
    (void)BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_READ | BSL_UIO_FLAGS_SHOULD_RETRY);
    return BSL_SUCCESS;
  }

  copy_len = env->pdu_len < len ? env->pdu_len : len;
  memcpy(buf, env->pdu, copy_len);
  env->pdu += copy_len;
  env->pdu_len -= copy_len;
  *read_len = (uint32_t)copy_len;
  return BSL_SUCCESS;
}

static int32_t
coap_hitls_uio_ctrl(BSL_UIO *uio, int32_t cmd, int32_t l_arg, void *parg) {
  coap_hitls_env_t *env = (coap_hitls_env_t *)BSL_UIO_GetUserData(uio);

  if (!env)
    return BSL_NULL_INPUT;

  switch (cmd) {
  case BSL_UIO_GET_FD:
    if (parg) {
#if defined(_WIN32)
      *(int32_t *)parg = -1;
#elif COAP_SERVER_SUPPORT
      *(int32_t *)parg = (int32_t)(COAP_PROTO_NOT_RELIABLE(env->session->proto) ?
                                   env->session->type != COAP_SESSION_TYPE_CLIENT ?
                                   env->session->endpoint->sock.fd :
                                   env->session->sock.fd :
                                   env->session->sock.fd);
#else /* ! _WIN32 && ! COAP_SERVER_SUPPORT */
      *(int32_t *)parg = (int32_t)env->session->sock.fd;
#endif /* ! _WIN32 */
    }
    return BSL_SUCCESS;
  case BSL_UIO_SET_FD:
  case BSL_UIO_SET_PEER_IP_ADDR:
  case BSL_UIO_UDP_SET_CONNECTED:
  case BSL_UIO_FLUSH:
  case BSL_UIO_RESET:
    return BSL_SUCCESS;
  case BSL_UIO_GET_PEER_IP_ADDR:
    if (!parg || !env->session)
      return BSL_NULL_INPUT;
    if (l_arg == (int32_t)sizeof(BSL_UIO_CtrlGetPeerIpAddrParam)) {
      BSL_UIO_CtrlGetPeerIpAddrParam *param =
          (BSL_UIO_CtrlGetPeerIpAddrParam *)parg;
      uint32_t addr_len = (uint32_t)env->session->addr_info.remote.size;

      if (!param->addr || param->size < addr_len)
        return BSL_INVALID_ARG;
      memcpy(param->addr, &env->session->addr_info.remote.addr.sa, addr_len);
      param->size = addr_len;
      return BSL_SUCCESS;
    }
    if (env->session->addr_info.remote.size > (socklen_t)l_arg)
      return BSL_INVALID_ARG;
    memcpy(parg, &env->session->addr_info.remote.addr.sa,
           env->session->addr_info.remote.size);
    return BSL_SUCCESS;
  case BSL_UIO_PENDING:
  case BSL_UIO_WPENDING:
    if (parg)
      *(uint64_t *)parg = cmd == BSL_UIO_PENDING ? env->pdu_len : 0;
    return BSL_SUCCESS;
  case BSL_UIO_UDP_GET_MTU_OVERHEAD:
    if (!parg)
      return BSL_NULL_INPUT;
    if (l_arg != (int32_t)sizeof(uint8_t))
      return BSL_INVALID_ARG;
    *(uint8_t *)parg = coap_hitls_udp_overhead(env);
    return BSL_SUCCESS;
  case BSL_UIO_UDP_QUERY_MTU:
    if (!parg)
      return BSL_NULL_INPUT;
    if (l_arg != (int32_t)sizeof(uint32_t))
      return BSL_INVALID_ARG;
    *(uint32_t *)parg = env->session->mtu > UINT32_MAX ?
                        UINT32_MAX : (uint32_t)env->session->mtu;
    return BSL_SUCCESS;
  case BSL_UIO_UDP_MTU_EXCEEDED:
    if (!parg)
      return BSL_NULL_INPUT;
    if (l_arg != (int32_t)sizeof(bool))
      return BSL_INVALID_ARG;
    *(bool *)parg = env->mtu_exceeded != 0;
    env->mtu_exceeded = 0;
    return BSL_SUCCESS;
  default:
    return BSL_SUCCESS;
  }
}

static int
coap_hitls_setup_uio(coap_hitls_env_t *env) {
  BSL_UIO *uio;
  BSL_UIO_TransportType type =
      env->proto == COAP_PROTO_DTLS ? BSL_UIO_UDP : BSL_UIO_TCP;

  env->method = BSL_UIO_NewMethod();
  if (!env->method)
    return 0;
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif /* defined(__GNUC__) */
  if (BSL_UIO_SetMethodType(env->method, type) != BSL_SUCCESS ||
      BSL_UIO_SetMethod(env->method, BSL_UIO_WRITE_CB,
                        (void *)coap_hitls_uio_write) != BSL_SUCCESS ||
      BSL_UIO_SetMethod(env->method, BSL_UIO_READ_CB,
                        (void *)coap_hitls_uio_read) != BSL_SUCCESS ||
      BSL_UIO_SetMethod(env->method, BSL_UIO_CTRL_CB,
                        (void *)coap_hitls_uio_ctrl) != BSL_SUCCESS) {
    BSL_UIO_FreeMethod(env->method);
    env->method = NULL;
    return 0;
  }
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif /* defined(__GNUC__) */

  uio = BSL_UIO_New(env->method);
  if (!uio)
    return 0;
  if (BSL_UIO_SetUserData(uio, env) != BSL_SUCCESS) {
    BSL_UIO_Free(uio);
    return 0;
  }
  BSL_UIO_SetInit(uio, true);
  if (HITLS_SetUio(env->ctx, uio) != HITLS_SUCCESS) {
    BSL_UIO_SetUserData(uio, NULL);
    BSL_UIO_Free(uio);
    return 0;
  }
  env->uio = HITLS_GetUio(env->ctx);
  BSL_UIO_Free(uio);
  return 1;
}

static void
coap_hitls_update_mtu(coap_hitls_env_t *env) {
  uint16_t mtu;
  int32_t ret;

  if (!env || !env->ctx || !env->session || env->proto != COAP_PROTO_DTLS)
    return;

  mtu = env->session->mtu > UINT16_MAX ? UINT16_MAX :
        (uint16_t)env->session->mtu;
  ret = HITLS_SetMtu(env->ctx, mtu);
  if (ret != HITLS_SUCCESS) {
    coap_log_warn("HITLS_SetMtu(%u) returned 0x%x\n", mtu,
                  (unsigned int)ret);
  }
}

#if COAP_CLIENT_SUPPORT
static uint32_t
coap_hitls_psk_client_cb(HITLS_Ctx *ctx, const uint8_t *hint,
                         uint8_t *identity, uint32_t max_identity_len,
                         uint8_t *psk, uint32_t max_psk_len) {
  coap_session_t *session = (coap_session_t *)HITLS_GetUserData(ctx);
  coap_dtls_cpsk_t *setup_data;
  const coap_dtls_cpsk_info_t *cpsk_info;
  const coap_bin_const_t *psk_identity;
  const coap_bin_const_t *psk_key;

  if (!session || !session->context)
    return 0;

  setup_data = &session->cpsk_setup_data;
  if (setup_data->validate_ih_call_back) {
    coap_bin_const_t temp;
    coap_str_const_t lhint;

    temp.s = hint ? hint : (const uint8_t *)"";
    temp.length = coap_hitls_strnlen(temp.s, COAP_DTLS_MAX_PSK_IDENTITY);
    coap_session_refresh_psk_hint(session, &temp);

    lhint.s = temp.s;
    lhint.length = temp.length;
    coap_lock_callback_ret(cpsk_info,
                           setup_data->validate_ih_call_back(&lhint,
                                                             session,
                                                             setup_data->ih_call_back_arg));
    if (!cpsk_info)
      return 0;
    coap_session_refresh_psk_identity(session, &cpsk_info->identity);
    coap_session_refresh_psk_key(session, &cpsk_info->key);
    psk_identity = &cpsk_info->identity;
    psk_key = &cpsk_info->key;
  } else {
    psk_identity = coap_get_session_client_psk_identity(session);
    psk_key = coap_get_session_client_psk_key(session);
  }

  if (coap_hitls_copy_bin(identity, max_identity_len, psk_identity, 1) == 0 ||
      coap_hitls_copy_bin(psk, max_psk_len, psk_key, 0) == 0)
    return 0;
  return (uint32_t)psk_key->length;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
static HITLS_Config *coap_hitls_new_server_sni_config(coap_session_t *session, coap_proto_t proto,
                                                      const coap_dtls_key_t *new_key);

static int32_t
coap_hitls_sni_cb(HITLS_Ctx *ctx, int *alert COAP_UNUSED,
                  void *arg COAP_UNUSED) {
  coap_session_t *session = (coap_session_t *)HITLS_GetUserData(ctx);
  coap_hitls_context_t *context =
      session && session->context ?
      (coap_hitls_context_t *)session->context->dtls_context : NULL;
  coap_dtls_pki_t *pki_setup_data = context ? &context->setup_data : NULL;
  coap_dtls_spsk_t *psk_setup_data;
  const char *sni;
  int accepted = 0;

  if (!session || !session->context)
    return HITLS_ACCEPT_SNI_ERR_ALERT_FATAL;
  sni = HITLS_GetServerName(ctx, HITLS_SNI_HOSTNAME_TYPE);
  if (!sni)
    sni = "";

  if (pki_setup_data && pki_setup_data->validate_sni_call_back) {
    coap_dtls_key_t *new_key;
    HITLS_Config *new_config;

    coap_lock_callback_ret(new_key,
                           pki_setup_data->validate_sni_call_back(
                               sni, pki_setup_data->sni_call_back_arg));
    if (!new_key)
      return HITLS_ACCEPT_SNI_ERR_ALERT_FATAL;
    new_config = coap_hitls_new_server_sni_config(session, session->proto,
                                                  new_key);
    if (!new_config)
      return HITLS_ACCEPT_SNI_ERR_ALERT_FATAL;
    if (!HITLS_SetNewConfig(ctx, new_config)) {
      HITLS_CFG_FreeConfig(new_config);
      return HITLS_ACCEPT_SNI_ERR_ALERT_FATAL;
    }
    HITLS_CFG_FreeConfig(new_config);
    accepted = 1;
  }

  psk_setup_data = &session->context->spsk_setup_data;
  if (psk_setup_data->validate_sni_call_back) {
    const coap_dtls_spsk_info_t *new_entry;

    coap_lock_callback_ret(new_entry,
                           psk_setup_data->validate_sni_call_back(
                               sni, session, psk_setup_data->sni_call_back_arg));
    if (!new_entry)
      return HITLS_ACCEPT_SNI_ERR_ALERT_FATAL;
    if (!coap_session_refresh_psk_hint(session, &new_entry->hint) ||
        !coap_session_refresh_psk_key(session, &new_entry->key))
      return HITLS_ACCEPT_SNI_ERR_ALERT_FATAL;
    if (new_entry->hint.s && new_entry->hint.length > 0 &&
        new_entry->hint.length <= UINT32_MAX &&
        HITLS_SetPskIdentityHint(ctx, new_entry->hint.s,
                                 (uint32_t)new_entry->hint.length) != HITLS_SUCCESS)
      return HITLS_ACCEPT_SNI_ERR_ALERT_FATAL;
    accepted = 1;
  }

  return accepted ? HITLS_ACCEPT_SNI_ERR_OK : HITLS_ACCEPT_SNI_ERR_NOACK;
}

static uint32_t
coap_hitls_psk_server_cb(HITLS_Ctx *ctx, const uint8_t *identity,
                         uint8_t *psk, uint32_t max_psk_len) {
  coap_session_t *session = (coap_session_t *)HITLS_GetUserData(ctx);
  coap_dtls_spsk_t *setup_data;
  coap_bin_const_t lidentity;
  const coap_bin_const_t *psk_key;

  if (!session || !session->context)
    return 0;

  setup_data = &session->context->spsk_setup_data;
  lidentity.s = identity ? identity : (const uint8_t *)"";
  lidentity.length = coap_hitls_strnlen(lidentity.s,
                                        COAP_DTLS_MAX_PSK_IDENTITY);
  coap_session_refresh_psk_identity(session, &lidentity);

  if (setup_data->validate_id_call_back) {
    coap_lock_callback_ret(psk_key,
                           setup_data->validate_id_call_back(&lidentity,
                                                             session,
                                                             setup_data->id_call_back_arg));
    coap_session_refresh_psk_key(session, psk_key);
  } else {
    psk_key = coap_get_session_server_psk_key(session);
  }

  if (coap_hitls_copy_bin(psk, max_psk_len, psk_key, 0) == 0)
    return 0;
  return (uint32_t)psk_key->length;
}
#endif /* COAP_SERVER_SUPPORT */

static int32_t
coap_hitls_alpn_select_cb(HITLS_Ctx *ctx COAP_UNUSED,
                          uint8_t **selected_proto,
                          uint8_t *selected_proto_len,
                          uint8_t *client_alpn_list,
                          uint32_t client_alpn_list_size,
                          void *user_data COAP_UNUSED) {
  if (HITLS_SelectAlpnProtocol(selected_proto, selected_proto_len,
                               coap_hitls_alpn, sizeof(coap_hitls_alpn),
                               client_alpn_list,
                               client_alpn_list_size) != HITLS_SUCCESS ||
      !selected_proto || !*selected_proto ||
      !selected_proto_len || *selected_proto_len != 4)
    return HITLS_ALPN_ERR_ALERT_FATAL;
  return HITLS_ALPN_ERR_OK;
}

static int
coap_hitls_load_ca(HITLS_Config *config, coap_dtls_key_t *key,
                   coap_dtls_role_t role) {
  coap_pki_key_define_t *define = &key->key.define;
  uint32_t len;
  uint8_t *buf;
  int32_t ret;

  switch (define->ca_def) {
  case COAP_PKI_KEY_DEF_PEM:
    if (!define->ca.s_byte || !define->ca.s_byte[0])
      return 1;
    if (HITLS_CFG_LoadVerifyFile(config, define->ca.s_byte) == HITLS_SUCCESS)
      return 1;
    return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                  COAP_DEFINE_FAIL_BAD, key, role, 0);
  case COAP_PKI_KEY_DEF_PEM_BUF:
    if (!define->ca.u_byte || !define->ca_len)
      return 1;
    if (!coap_hitls_pki_len(define->ca.u_byte, define->ca_len,
                            TLS_PARSE_FORMAT_PEM, &len))
      return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                    COAP_DEFINE_FAIL_BAD, key, role, 0);
    if (HITLS_CFG_LoadVerifyBuffer(config, define->ca.u_byte, len,
                                   TLS_PARSE_FORMAT_PEM) == HITLS_SUCCESS)
      return 1;
    return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                  COAP_DEFINE_FAIL_BAD, key, role, 0);
  case COAP_PKI_KEY_DEF_DER_BUF:
    if (!define->ca.u_byte || !define->ca_len)
      return 1;
    if (!coap_hitls_pki_len(define->ca.u_byte, define->ca_len,
                            TLS_PARSE_FORMAT_ASN1, &len))
      return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                    COAP_DEFINE_FAIL_BAD, key, role, 0);
    if (HITLS_CFG_LoadVerifyBuffer(config, define->ca.u_byte, len,
                                   TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS)
      return 1;
    return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                  COAP_DEFINE_FAIL_BAD, key, role, 0);
  case COAP_PKI_KEY_DEF_DER:
    if (!define->ca.s_byte || !define->ca.s_byte[0])
      return 1;
    buf = coap_hitls_read_file(define->ca.s_byte, &len);
    if (!buf)
      return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                    COAP_DEFINE_FAIL_BAD, key, role, 0);
    ret = HITLS_CFG_LoadVerifyBuffer(config, buf, len, TLS_PARSE_FORMAT_ASN1);
    coap_free_type(COAP_STRING, buf);
    if (ret == HITLS_SUCCESS)
      return 1;
    return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                  COAP_DEFINE_FAIL_BAD, key, role, ret);
  case COAP_PKI_KEY_DEF_RPK_BUF:
  case COAP_PKI_KEY_DEF_PKCS11:
  case COAP_PKI_KEY_DEF_PKCS11_RPK:
  case COAP_PKI_KEY_DEF_ENGINE:
    if (define->ca.u_byte && define->ca.u_byte[0])
      return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED, key,
                                    role, 0);
    return 1;
  default:
    return 1;
  }
}

static int
coap_hitls_load_public_cert(HITLS_Config *config, coap_dtls_key_t *key,
                            coap_dtls_role_t role) {
  coap_pki_key_define_t *define = &key->key.define;
  uint32_t len;

  switch (define->public_cert_def) {
  case COAP_PKI_KEY_DEF_PEM:
    if (!define->public_cert.s_byte || !define->public_cert.s_byte[0])
      return 1;
    /* A PEM buffer may hold leaf + intermediate CAs; load the whole chain. */
    if (HITLS_CFG_UseCertificateChainFile(config,
                                          define->public_cert.s_byte) == HITLS_SUCCESS)
      return 1;
    return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                  COAP_DEFINE_FAIL_BAD, key, role, 0);
  case COAP_PKI_KEY_DEF_DER:
    if (!define->public_cert.s_byte || !define->public_cert.s_byte[0])
      return 1;
    if (HITLS_CFG_LoadCertFile(config, define->public_cert.s_byte,
                               TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS)
      return 1;
    return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                  COAP_DEFINE_FAIL_BAD, key, role, 0);
  case COAP_PKI_KEY_DEF_PEM_BUF:
    if (!define->public_cert.u_byte || !define->public_cert_len)
      return 1;
    if (!coap_hitls_pki_len(define->public_cert.u_byte,
                            define->public_cert_len, TLS_PARSE_FORMAT_PEM,
                            &len))
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                    COAP_DEFINE_FAIL_BAD, key, role, 0);
    /* A PEM buffer may hold leaf + intermediate CAs; load the whole chain. */
    if (HITLS_CFG_UseCertificateChainBuffer(config, define->public_cert.u_byte,
                                            len, TLS_PARSE_FORMAT_PEM) == HITLS_SUCCESS)
      return 1;
    return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                  COAP_DEFINE_FAIL_BAD, key, role, 0);
  case COAP_PKI_KEY_DEF_DER_BUF:
    if (!define->public_cert.u_byte || !define->public_cert_len)
      return 1;
    if (!coap_hitls_pki_len(define->public_cert.u_byte,
                            define->public_cert_len, TLS_PARSE_FORMAT_ASN1,
                            &len))
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                    COAP_DEFINE_FAIL_BAD, key, role, 0);
    if (HITLS_CFG_LoadCertBuffer(config, define->public_cert.u_byte, len,
                                 TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS)
      return 1;
    return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                  COAP_DEFINE_FAIL_BAD, key, role, 0);
  case COAP_PKI_KEY_DEF_RPK_BUF:
  case COAP_PKI_KEY_DEF_PKCS11:
  case COAP_PKI_KEY_DEF_PKCS11_RPK:
  case COAP_PKI_KEY_DEF_ENGINE:
    if (define->public_cert.u_byte && define->public_cert.u_byte[0])
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED, key,
                                    role, 0);
    return 1;
  default:
    return 1;
  }
}

static int
coap_hitls_load_private_key(HITLS_Config *config, coap_dtls_key_t *key,
                            coap_dtls_role_t role) {
  coap_pki_key_define_t *define = &key->key.define;
  uint32_t len;

  switch (define->private_key_def) {
  case COAP_PKI_KEY_DEF_PEM:
    if (!define->private_key.s_byte || !define->private_key.s_byte[0])
      return 1;
    if (HITLS_CFG_LoadKeyFile(config, define->private_key.s_byte,
                              TLS_PARSE_FORMAT_PEM) == HITLS_SUCCESS)
      return 1;
    return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                  COAP_DEFINE_FAIL_BAD, key, role, 0);
  case COAP_PKI_KEY_DEF_DER:
    if (!define->private_key.s_byte || !define->private_key.s_byte[0])
      return 1;
    if (HITLS_CFG_LoadKeyFile(config, define->private_key.s_byte,
                              TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS)
      return 1;
    return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                  COAP_DEFINE_FAIL_BAD, key, role, 0);
  case COAP_PKI_KEY_DEF_PEM_BUF:
    if (!define->private_key.u_byte || !define->private_key_len)
      return 1;
    if (!coap_hitls_pki_len(define->private_key.u_byte,
                            define->private_key_len, TLS_PARSE_FORMAT_PEM,
                            &len))
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                    COAP_DEFINE_FAIL_BAD, key, role, 0);
    if (HITLS_CFG_LoadKeyBuffer(config, define->private_key.u_byte, len,
                                TLS_PARSE_FORMAT_PEM) == HITLS_SUCCESS)
      return 1;
    return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                  COAP_DEFINE_FAIL_BAD, key, role, 0);
  case COAP_PKI_KEY_DEF_DER_BUF:
    if (!define->private_key.u_byte || !define->private_key_len)
      return 1;
    if (!coap_hitls_pki_len(define->private_key.u_byte,
                            define->private_key_len, TLS_PARSE_FORMAT_ASN1,
                            &len))
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                    COAP_DEFINE_FAIL_BAD, key, role, 0);
    if (HITLS_CFG_LoadKeyBuffer(config, define->private_key.u_byte, len,
                                TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS)
      return 1;
    return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                  COAP_DEFINE_FAIL_BAD, key, role, 0);
  case COAP_PKI_KEY_DEF_RPK_BUF:
  case COAP_PKI_KEY_DEF_PKCS11:
  case COAP_PKI_KEY_DEF_PKCS11_RPK:
  case COAP_PKI_KEY_DEF_ENGINE:
    if (define->private_key.u_byte && define->private_key.u_byte[0])
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED, key,
                                    role, 0);
    return 1;
  default:
    return 1;
  }
}

static int
coap_hitls_load_root_cas(HITLS_Config *config, coap_hitls_context_t *context) {
  if (context->root_ca_file &&
      HITLS_CFG_LoadVerifyFile(config, context->root_ca_file) != HITLS_SUCCESS) {
    coap_log_warn("Unable to install root CA file '%s'\n",
                  context->root_ca_file);
    return 0;
  }
  if (context->root_ca_dir &&
      HITLS_CFG_LoadVerifyDir(config, context->root_ca_dir) != HITLS_SUCCESS) {
    coap_log_warn("Unable to install root CA directory '%s'\n",
                  context->root_ca_dir);
    return 0;
  }
  if (context->trust_store_defined &&
      HITLS_CFG_LoadDefaultCAPath(config) != HITLS_SUCCESS) {
    coap_log_warn("Unable to load trusted root CAs\n");
    return 0;
  }
  return 1;
}

static int
coap_hitls_configure_pki(HITLS_Config *config, coap_session_t *session,
                         coap_dtls_role_t role,
                         const coap_dtls_pki_t *pki_setup_data) {
  coap_hitls_context_t *context =
      session && session->context ?
      (coap_hitls_context_t *)session->context->dtls_context : NULL;
  coap_dtls_pki_t setup_data_copy;
  coap_dtls_pki_t *setup_data = context ? &context->setup_data : NULL;
  coap_dtls_key_t key;

  if (pki_setup_data) {
    setup_data_copy = *pki_setup_data;
    setup_data = &setup_data_copy;
  }
  if (!context || !setup_data)
    return 0;
  if (!coap_hitls_check_pki_key_supported(setup_data, role))
    return 0;

  coap_dtls_map_key_type_to_define(setup_data, &key);
  if (key.key_type != COAP_PKI_KEY_DEFINE)
    return 0;

  if (!coap_hitls_load_root_cas(config, context) ||
      !coap_hitls_load_ca(config, &key, role) ||
      !coap_hitls_load_public_cert(config, &key, role) ||
      !coap_hitls_load_private_key(config, &key, role))
    return 0;

  if (setup_data->cert_chain_validation &&
      HITLS_CFG_SetVerifyDepth(config,
                               COAP_HITLS_VERIFY_DEPTH_TO_MAX_CHAIN_DEPTH(
                                   setup_data->cert_chain_verify_depth)) !=
      HITLS_SUCCESS)
    return 0;
  if (setup_data->check_cert_revocation &&
      HITLS_CFG_SetVerifyFlags(config,
                               HITLS_X509_VFY_FLAG_CRL_ALL) != HITLS_SUCCESS)
    return 0;
  if (HITLS_CFG_SetVerifyCb(config, coap_hitls_verify_cb) != HITLS_SUCCESS)
    return 0;
  if (HITLS_CFG_SetCertVerifyCb(config, coap_hitls_app_verify_cb,
                                NULL) != HITLS_SUCCESS)
    return 0;

  if (role == COAP_DTLS_ROLE_CLIENT) {
    if (setup_data->client_sni && setup_data->client_sni[0] &&
        HITLS_CFG_SetServerName(config,
                                (uint8_t *)setup_data->client_sni,
                                (uint32_t)strlen(setup_data->client_sni)) != HITLS_SUCCESS)
      return 0;
  } else {
    if (HITLS_CFG_SetClientVerifySupport(config,
                                         setup_data->verify_peer_cert ? true : false) != HITLS_SUCCESS)
      return 0;
    if (setup_data->verify_peer_cert &&
        HITLS_CFG_SetNoClientCertSupport(config, false) != HITLS_SUCCESS)
      return 0;
  }

  if (HITLS_CFG_SetVerifyNoneSupport(config,
                                     setup_data->verify_peer_cert ? false : true) != HITLS_SUCCESS)
    return 0;
  return 1;
}

#if COAP_SERVER_SUPPORT
static HITLS_Config *
coap_hitls_new_server_sni_config(coap_session_t *session, coap_proto_t proto,
                                 const coap_dtls_key_t *new_key) {
  coap_hitls_context_t *context =
      session && session->context ?
      (coap_hitls_context_t *)session->context->dtls_context : NULL;
  const uint16_t *cipher_suites;
  uint32_t cipher_suites_count;
  int enabled = context && context->psk_pki_enabled ?
                context->psk_pki_enabled : IS_PKI;
  coap_dtls_pki_t pki_setup_data;
  HITLS_Config *config;

  if (!context || !new_key)
    return NULL;

  config = proto == COAP_PROTO_DTLS ? HITLS_CFG_NewDTLS12Config() :
           HITLS_CFG_NewTLS12Config();
  if (!config)
    return NULL;

  coap_hitls_get_cipher_suites(enabled, &cipher_suites, &cipher_suites_count);
  if (HITLS_CFG_SetCipherSuites(config, cipher_suites,
                                cipher_suites_count) != HITLS_SUCCESS) {
    HITLS_CFG_FreeConfig(config);
    return NULL;
  }
  if (proto == COAP_PROTO_DTLS &&
      (HITLS_CFG_SetFlightTransmitSwitch(config, true) != HITLS_SUCCESS ||
       HITLS_CFG_SetDtlsCookieExchangeSupport(config, true) != HITLS_SUCCESS ||
       HITLS_CFG_SetCookieGenCb(config,
                                coap_hitls_cookie_gen_cb) != HITLS_SUCCESS ||
       HITLS_CFG_SetCookieVerifyCb(config,
                                   coap_hitls_cookie_verify_cb) != HITLS_SUCCESS)) {
    HITLS_CFG_FreeConfig(config);
    return NULL;
  }
  if (proto == COAP_PROTO_TLS &&
      HITLS_CFG_SetAlpnProtosSelectCb(config, coap_hitls_alpn_select_cb,
                                      NULL) != HITLS_SUCCESS) {
    HITLS_CFG_FreeConfig(config);
    return NULL;
  }
  if (enabled & IS_PSK) {
    const coap_bin_const_t *hint = coap_get_session_server_psk_hint(session);

    if (hint && hint->s && hint->length <= UINT32_MAX &&
        HITLS_CFG_SetPskIdentityHint(config, hint->s,
                                     (uint32_t)hint->length) != HITLS_SUCCESS) {
      HITLS_CFG_FreeConfig(config);
      return NULL;
    }
    if (HITLS_CFG_SetPskServerCallback(config,
                                       coap_hitls_psk_server_cb) != HITLS_SUCCESS) {
      HITLS_CFG_FreeConfig(config);
      return NULL;
    }
  }

  pki_setup_data = context->setup_data;
  pki_setup_data.pki_key = *new_key;
  if (!coap_hitls_configure_pki(config, session, COAP_DTLS_ROLE_SERVER,
                                &pki_setup_data)) {
    HITLS_CFG_FreeConfig(config);
    return NULL;
  }

  (void)HITLS_CFG_SetInfoCb(config, coap_hitls_info_cb);
  return config;
}
#endif /* COAP_SERVER_SUPPORT */

static HITLS_Config *
coap_hitls_new_config(coap_session_t *session, coap_dtls_role_t role,
                      coap_proto_t proto) {
  coap_hitls_context_t *hitls_context =
      session && session->context ?
      (coap_hitls_context_t *)session->context->dtls_context : NULL;
  const uint16_t *cipher_suites;
  uint32_t cipher_suites_count;
  int enabled = hitls_context && hitls_context->psk_pki_enabled ?
                hitls_context->psk_pki_enabled : IS_PSK;
  HITLS_Config *config = proto == COAP_PROTO_DTLS ?
                         HITLS_CFG_NewDTLS12Config() :
                         HITLS_CFG_NewTLS12Config();

  if (!config)
    return NULL;

  coap_hitls_get_cipher_suites(enabled, &cipher_suites, &cipher_suites_count);

  if (HITLS_CFG_SetCipherSuites(config, cipher_suites,
                                cipher_suites_count) != HITLS_SUCCESS) {
    HITLS_CFG_FreeConfig(config);
    return NULL;
  }
  if (proto == COAP_PROTO_DTLS &&
      (HITLS_CFG_SetFlightTransmitSwitch(config, true) != HITLS_SUCCESS ||
       HITLS_CFG_SetDtlsCookieExchangeSupport(config,
                                              role == COAP_DTLS_ROLE_SERVER) != HITLS_SUCCESS)) {
    HITLS_CFG_FreeConfig(config);
    return NULL;
  }
#if COAP_SERVER_SUPPORT
  if (proto == COAP_PROTO_DTLS && role == COAP_DTLS_ROLE_SERVER &&
      (HITLS_CFG_SetCookieGenCb(config,
                                coap_hitls_cookie_gen_cb) != HITLS_SUCCESS ||
       HITLS_CFG_SetCookieVerifyCb(config,
                                   coap_hitls_cookie_verify_cb) != HITLS_SUCCESS)) {
    HITLS_CFG_FreeConfig(config);
    return NULL;
  }
#endif /* COAP_SERVER_SUPPORT */
  if (proto == COAP_PROTO_TLS &&
      ((role == COAP_DTLS_ROLE_CLIENT &&
        HITLS_CFG_SetAlpnProtos(config, coap_hitls_alpn,
                                sizeof(coap_hitls_alpn)) != HITLS_SUCCESS) ||
       (role == COAP_DTLS_ROLE_SERVER &&
        HITLS_CFG_SetAlpnProtosSelectCb(config,
                                        coap_hitls_alpn_select_cb,
                                        NULL) != HITLS_SUCCESS))) {
    HITLS_CFG_FreeConfig(config);
    return NULL;
  }

  if (role == COAP_DTLS_ROLE_CLIENT && (enabled & IS_PSK)) {
#if COAP_CLIENT_SUPPORT
    coap_dtls_cpsk_t *setup_data = &session->cpsk_setup_data;

    if (setup_data->client_sni && setup_data->client_sni[0] &&
        HITLS_CFG_SetServerName(config,
                                (uint8_t *)setup_data->client_sni,
                                (uint32_t)strlen(setup_data->client_sni)) != HITLS_SUCCESS) {
      HITLS_CFG_FreeConfig(config);
      return NULL;
    }
    if (HITLS_CFG_SetPskClientCallback(config,
                                       coap_hitls_psk_client_cb) != HITLS_SUCCESS) {
      HITLS_CFG_FreeConfig(config);
      return NULL;
    }
#else /* ! COAP_CLIENT_SUPPORT */
    (void)session;
    HITLS_CFG_FreeConfig(config);
    return NULL;
#endif /* ! COAP_CLIENT_SUPPORT */
  } else if (role == COAP_DTLS_ROLE_SERVER && (enabled & IS_PSK)) {
#if COAP_SERVER_SUPPORT
    const coap_bin_const_t *hint = coap_get_session_server_psk_hint(session);

    if (hint && hint->s && hint->length <= UINT32_MAX &&
        HITLS_CFG_SetPskIdentityHint(config, hint->s,
                                     (uint32_t)hint->length) != HITLS_SUCCESS) {
      HITLS_CFG_FreeConfig(config);
      return NULL;
    }
    if (HITLS_CFG_SetPskServerCallback(config,
                                       coap_hitls_psk_server_cb) != HITLS_SUCCESS) {
      HITLS_CFG_FreeConfig(config);
      return NULL;
    }
#else /* ! COAP_SERVER_SUPPORT */
    (void)session;
    HITLS_CFG_FreeConfig(config);
    return NULL;
#endif /* ! COAP_SERVER_SUPPORT */
  }

#if COAP_SERVER_SUPPORT
  if (role == COAP_DTLS_ROLE_SERVER) {
    int needs_sni = 0;

    if ((enabled & IS_PSK) && session && session->context &&
        session->context->spsk_setup_data.validate_sni_call_back)
      needs_sni = 1;
    if ((enabled & IS_PKI) && hitls_context &&
        hitls_context->setup_data.validate_sni_call_back)
      needs_sni = 1;
    if (needs_sni &&
        (HITLS_CFG_SetServerNameCb(config,
                                   coap_hitls_sni_cb) != HITLS_SUCCESS ||
         HITLS_CFG_SetServerNameArg(config, NULL) != HITLS_SUCCESS)) {
      HITLS_CFG_FreeConfig(config);
      return NULL;
    }
  }
#endif /* COAP_SERVER_SUPPORT */

  if ((enabled & IS_PKI) &&
      !coap_hitls_configure_pki(config, session, role, NULL)) {
    HITLS_CFG_FreeConfig(config);
    return NULL;
  }

  (void)HITLS_CFG_SetInfoCb(config, coap_hitls_info_cb);
  return config;
}

static void
coap_hitls_free_env(coap_hitls_env_t *env) {
  if (!env)
    return;
  if (env->ctx) {
    if (env->established && !env->had_fatal)
      (void)HITLS_Close(env->ctx);
    if (env->uio)
      BSL_UIO_SetUserData(env->uio, NULL);
    HITLS_Free(env->ctx);
  } else if (env->uio) {
    BSL_UIO_SetUserData(env->uio, NULL);
  }
  if (env->method)
    BSL_UIO_FreeMethod(env->method);
  coap_free_type(COAP_STRING, env);
}

static coap_hitls_env_t *
coap_hitls_live_env(coap_session_t *session, coap_hitls_env_t *env) {
  return session && session->tls == (void *)env ? env : NULL;
}

static void
coap_hitls_clear_pdu(coap_hitls_env_t *env) {
  if (env) {
    env->pdu = NULL;
    env->pdu_len = 0;
  }
}

static coap_hitls_env_t *
coap_hitls_new_env(coap_session_t *session, coap_dtls_role_t role,
                   coap_proto_t proto) {
  coap_hitls_env_t *env =
      (coap_hitls_env_t *)coap_malloc_type(COAP_STRING, sizeof(*env));
  coap_hitls_context_t *hitls_context =
      session && session->context ?
      (coap_hitls_context_t *)session->context->dtls_context : NULL;
  HITLS_Config *config;

  if (!env)
    return NULL;
  memset(env, 0, sizeof(*env));
  env->session = session;
  env->role = role;
  env->proto = proto;

  config = coap_hitls_new_config(session, role, proto);
  if (!config) {
    coap_free_type(COAP_STRING, env);
    return NULL;
  }

  env->ctx = HITLS_New(config);
  HITLS_CFG_FreeConfig(config);
  if (!env->ctx) {
    coap_free_type(COAP_STRING, env);
    return NULL;
  }
  if (HITLS_SetUserData(env->ctx, session) != HITLS_SUCCESS ||
      !coap_hitls_setup_uio(env)) {
    coap_hitls_free_env(env);
    return NULL;
  }
  coap_hitls_update_mtu(env);
  if (hitls_context && (hitls_context->psk_pki_enabled & IS_PKI) &&
      hitls_context->setup_data.additional_tls_setup_call_back &&
      !hitls_context->setup_data.additional_tls_setup_call_back(env->ctx,
          &hitls_context->setup_data)) {
    coap_hitls_free_env(env);
    return NULL;
  }

  return env;
}

int
coap_dtls_is_supported(void) {
  return 1;
}

int
coap_tls_is_supported(void) {
#if !COAP_DISABLE_TCP
  return 1;
#else /* COAP_DISABLE_TCP */
  return 0;
#endif /* COAP_DISABLE_TCP */
}

int
coap_dtls_psk_is_supported(void) {
  return 1;
}

int
coap_dtls_pki_is_supported(void) {
  return 1;
}

int
coap_dtls_pkcs11_is_supported(void) {
  return 0;
}

int
coap_dtls_rpk_is_supported(void) {
  return 0;
}

int
coap_dtls_cid_is_supported(void) {
  return 0;
}

#if COAP_CLIENT_SUPPORT
int
coap_dtls_set_cid_tuple_change(coap_context_t *c_context COAP_UNUSED,
                               uint8_t every COAP_UNUSED) {
  return 0;
}
#endif /* COAP_CLIENT_SUPPORT */

void
coap_dtls_set_log_level(coap_log_t level) {
  dtls_log_level = level;
}

coap_log_t
coap_dtls_get_log_level(void) {
  return dtls_log_level;
}
#endif /* COAP_WITH_LIBOPENHITLS */

coap_tls_version_t *
coap_get_tls_library_version(void) {
  static coap_tls_version_t version;

  version.version = HITLS_VersionNum();
  version.built_version = OPENHITLS_VERSION_I;
  version.type = COAP_TLS_LIBRARY_OPENHITLS;
  return &version;
}

void
coap_dtls_startup(void) {
  (void)coap_hitls_startup();
}

void
coap_dtls_shutdown(void) {
  if (coap_hitls_started) {
#if COAP_WITH_LIBOPENHITLS
    HITLS_CertMethodDeinit();
#endif /* COAP_WITH_LIBOPENHITLS */
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    coap_hitls_started = 0;
  }
  coap_dtls_set_log_level(COAP_LOG_EMERG);
}

void
coap_dtls_thread_shutdown(void) {
  BSL_ERR_RemoveErrorStack(false);
}

#if COAP_WITH_LIBOPENHITLS
void *
coap_dtls_get_tls(const coap_session_t *session, coap_tls_library_t *tls_lib) {
  coap_hitls_env_t *env = session ? (coap_hitls_env_t *)session->tls : NULL;

  if (tls_lib)
    *tls_lib = COAP_TLS_LIBRARY_OPENHITLS;
  return env ? env->ctx : NULL;
}

void *
coap_dtls_new_context(coap_context_t *coap_context) {
  coap_hitls_context_t *context =
      (coap_hitls_context_t *)coap_malloc_type(COAP_STRING, sizeof(*context));

  if (!context)
    return NULL;
  memset(context, 0, sizeof(*context));
  context->coap_context = coap_context;
  if (!coap_prng_lkd(context->cookie_secret,
                     sizeof(context->cookie_secret))) {
    coap_free_type(COAP_STRING, context);
    return NULL;
  }
  context->cookie_secret_set = 1;
  return context;
}

void
coap_dtls_free_context(void *dtls_context) {
  coap_hitls_context_t *context = (coap_hitls_context_t *)dtls_context;

  if (context) {
    if (context->root_ca_file)
      coap_free_type(COAP_STRING, context->root_ca_file);
    if (context->root_ca_dir)
      coap_free_type(COAP_STRING, context->root_ca_dir);
    memset(context->cookie_secret, 0, sizeof(context->cookie_secret));
    context->cookie_secret_set = 0;
    coap_free_type(COAP_STRING, context);
  }
}

#if COAP_SERVER_SUPPORT
int
coap_dtls_context_set_spsk(coap_context_t *coap_context,
                           coap_dtls_spsk_t *setup_data) {
  coap_hitls_context_t *context;

  if (!coap_context || !setup_data)
    return 0;
  context = (coap_hitls_context_t *)coap_context->dtls_context;
  if (!context)
    return 0;
  context->psk_pki_enabled |= IS_PSK;
  return 1;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
int
coap_dtls_context_set_cpsk(coap_context_t *coap_context,
                           coap_dtls_cpsk_t *setup_data) {
  coap_hitls_context_t *context;

  if (!coap_context || !setup_data)
    return 0;
  context = (coap_hitls_context_t *)coap_context->dtls_context;
  if (!context)
    return 0;
  context->psk_pki_enabled |= IS_PSK;
  return 1;
}
#endif /* COAP_CLIENT_SUPPORT */

int
coap_dtls_context_set_pki(coap_context_t *coap_context,
                          const coap_dtls_pki_t *setup_data,
                          const coap_dtls_role_t role) {
  coap_hitls_context_t *context;

  if (!coap_context || !setup_data)
    return 0;
  context = (coap_hitls_context_t *)coap_context->dtls_context;
  if (!context)
    return 0;
  if (!coap_hitls_check_pki_key_supported(setup_data, role))
    return 0;
  context->setup_data = *setup_data;
  if (!context->setup_data.verify_peer_cert) {
    /* Needs to be clear so that no CA DNs are transmitted */
    context->setup_data.check_common_ca = 0;
    /* Allow all of these but warn if issue */
    context->setup_data.allow_self_signed = 1;
    context->setup_data.allow_expired_certs = 1;
    context->setup_data.cert_chain_validation = 1;
    context->setup_data.cert_chain_verify_depth = 10;
    context->setup_data.check_cert_revocation = 1;
    context->setup_data.allow_no_crl = 1;
    context->setup_data.allow_expired_crl = 1;
    context->setup_data.allow_bad_md_hash = 1;
    context->setup_data.allow_short_rsa_length = 1;
  }
#if COAP_CLIENT_SUPPORT
  if (role == COAP_DTLS_ROLE_CLIENT)
    context->psk_pki_enabled &= ~IS_PSK;
#else /* ! COAP_CLIENT_SUPPORT */
  (void)role;
#endif /* ! COAP_CLIENT_SUPPORT */
  context->psk_pki_enabled |= IS_PKI;
  if (setup_data->use_cid)
    coap_log_warn("openHiTLS backend has no Connection-ID support\n");
  return 1;
}

int
coap_dtls_context_set_pki_root_cas(coap_context_t *coap_context,
                                   const char *ca_file,
                                   const char *ca_dir) {
  coap_hitls_context_t *context;
  char *new_ca_file = NULL;
  char *new_ca_dir = NULL;

  if (!coap_context || (!ca_file && !ca_dir))
    return 0;
  context = (coap_hitls_context_t *)coap_context->dtls_context;
  if (!context)
    return 0;
  if (ca_file) {
    new_ca_file = coap_hitls_strdup(ca_file);
    if (!new_ca_file)
      return 0;
  }
  if (ca_dir) {
    new_ca_dir = coap_hitls_strdup(ca_dir);
    if (!new_ca_dir) {
      if (new_ca_file)
        coap_free_type(COAP_STRING, new_ca_file);
      return 0;
    }
  }
  if (context->root_ca_file)
    coap_free_type(COAP_STRING, context->root_ca_file);
  if (context->root_ca_dir)
    coap_free_type(COAP_STRING, context->root_ca_dir);
  context->root_ca_file = new_ca_file;
  context->root_ca_dir = new_ca_dir;
  return 1;
}

int
coap_dtls_context_load_pki_trust_store(coap_context_t *coap_context) {
  coap_hitls_context_t *context =
      coap_context ? (coap_hitls_context_t *)coap_context->dtls_context : NULL;

  if (!context)
    return 0;
  context->trust_store_defined = 1;
  return 1;
}

int
coap_dtls_context_check_keys_enabled(coap_context_t *coap_context) {
  coap_hitls_context_t *context =
      coap_context ? (coap_hitls_context_t *)coap_context->dtls_context : NULL;

  return context && context->psk_pki_enabled;
}
#endif /* COAP_WITH_LIBOPENHITLS */

#if COAP_SERVER_SUPPORT
coap_digest_ctx_t *
coap_digest_setup(void) {
  CRYPT_EAL_MdCtx *digest_ctx;

  if (!coap_hitls_startup())
    return NULL;
  digest_ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
  if (!digest_ctx)
    return NULL;
  if (CRYPT_EAL_MdInit(digest_ctx) != CRYPT_SUCCESS) {
    CRYPT_EAL_MdFreeCtx(digest_ctx);
    return NULL;
  }
  return digest_ctx;
}

void
coap_digest_free(coap_digest_ctx_t *digest_ctx) {
  if (digest_ctx)
    CRYPT_EAL_MdFreeCtx((CRYPT_EAL_MdCtx *)digest_ctx);
}

int
coap_digest_update(coap_digest_ctx_t *digest_ctx,
                   const uint8_t *data,
                   size_t data_len) {
  CRYPT_EAL_MdCtx *ctx = (CRYPT_EAL_MdCtx *)digest_ctx;

  if (!ctx || (!data && data_len))
    return 0;
  while (data_len) {
    uint32_t chunk = data_len > UINT32_MAX ? UINT32_MAX : (uint32_t)data_len;

    if (CRYPT_EAL_MdUpdate(ctx, data, chunk) != CRYPT_SUCCESS)
      return 0;
    data += chunk;
    data_len -= chunk;
  }
  return 1;
}

int
coap_digest_final(coap_digest_ctx_t *digest_ctx,
                  coap_digest_t *digest_buffer) {
  CRYPT_EAL_MdCtx *ctx = (CRYPT_EAL_MdCtx *)digest_ctx;
  uint32_t len = sizeof(*digest_buffer);
  int ret;

  if (!ctx || !digest_buffer)
    return 0;
  ret = CRYPT_EAL_MdFinal(ctx, (uint8_t *)digest_buffer, &len) == CRYPT_SUCCESS &&
        len == sizeof(*digest_buffer);
  coap_digest_free(digest_ctx);
  return ret;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_WS_SUPPORT
static const struct {
  cose_alg_t alg;
  CRYPT_MD_AlgId md;
  uint32_t length;
} coap_hitls_hashs[] = {
  {COSE_ALGORITHM_SHA_1,       CRYPT_MD_SHA1,   20},
  {COSE_ALGORITHM_SHA_256_64,  CRYPT_MD_SHA256, 8},
  {COSE_ALGORITHM_SHA_256_256, CRYPT_MD_SHA256, 32},
  {COSE_ALGORITHM_SHA_512,     CRYPT_MD_SHA512, 64},
};

int
coap_crypto_hash(cose_alg_t alg,
                 const coap_bin_const_t *data,
                 coap_bin_const_t **hash) {
  coap_binary_t *digest;
  uint32_t len;
  size_t i;
  CRYPT_MD_AlgId md = CRYPT_MD_SHA1;
  uint32_t out_len = 0;

  if (!data || !hash || data->length > UINT32_MAX || !coap_hitls_startup())
    return 0;
  for (i = 0; i < sizeof(coap_hitls_hashs) / sizeof(coap_hitls_hashs[0]); i++) {
    if (coap_hitls_hashs[i].alg == alg) {
      md = coap_hitls_hashs[i].md;
      out_len = coap_hitls_hashs[i].length;
      break;
    }
  }
  if (out_len == 0) {
    coap_log_debug("coap_crypto_hash: algorithm %d not supported\n", alg);
    return 0;
  }

  len = CRYPT_EAL_MdGetDigestSize(md);
  digest = coap_new_binary(len);
  if (!digest)
    return 0;

  if (CRYPT_EAL_Md(md, data->s, (uint32_t)data->length,
                   digest->s, &len) != CRYPT_SUCCESS ||
      len != digest->length) {
    coap_delete_binary(digest);
    return 0;
  }
  if (out_len < digest->length)
    digest->length = out_len;

  *hash = (coap_bin_const_t *)digest;
  return 1;
}
#endif /* COAP_WS_SUPPORT */

#if COAP_OSCORE_SUPPORT

int
coap_oscore_is_supported(void) {
  return 1;
}

static int
coap_hitls_get_cipher_alg(cose_alg_t alg, CRYPT_CIPHER_AlgId *cipher_alg,
                          size_t *key_len) {
  switch ((int)alg) {
  case COSE_ALGORITHM_AES_CCM_16_64_128:
    if (cipher_alg)
      *cipher_alg = CRYPT_CIPHER_AES128_CCM;
    if (key_len)
      *key_len = 16;
    return 1;
  case COSE_ALGORITHM_AES_CCM_16_64_256:
    if (cipher_alg)
      *cipher_alg = CRYPT_CIPHER_AES256_CCM;
    if (key_len)
      *key_len = 32;
    return 1;
  default:
    coap_log_debug("coap_hitls_get_cipher_alg: COSE cipher %d not supported\n",
                   alg);
    return 0;
  }
}

static int
coap_hitls_get_hmac_alg(cose_hmac_alg_t hmac_alg, CRYPT_MAC_AlgId *mac_alg,
                        size_t *mac_len) {
  switch ((int)hmac_alg) {
  case COSE_HMAC_ALG_HMAC256_256:
    if (mac_alg)
      *mac_alg = CRYPT_MAC_HMAC_SHA256;
    if (mac_len)
      *mac_len = COSE_ALGORITHM_HMAC256_256_HASH_LEN;
    return 1;
  case COSE_HMAC_ALG_HMAC384_384:
    if (mac_alg)
      *mac_alg = CRYPT_MAC_HMAC_SHA384;
    if (mac_len)
      *mac_len = COSE_ALGORITHM_HMAC384_384_HASH_LEN;
    return 1;
  case COSE_HMAC_ALG_HMAC512_512:
    if (mac_alg)
      *mac_alg = CRYPT_MAC_HMAC_SHA512;
    if (mac_len)
      *mac_len = COSE_ALGORITHM_HMAC512_512_HASH_LEN;
    return 1;
  default:
    coap_log_debug("coap_hitls_get_hmac_alg: COSE HMAC %d not supported\n",
                   hmac_alg);
    return 0;
  }
}

int
coap_crypto_check_cipher_alg(cose_alg_t alg) {
  return coap_hitls_get_cipher_alg(alg, NULL, NULL);
}

int
coap_crypto_check_hkdf_alg(cose_hkdf_alg_t hkdf_alg) {
  cose_hmac_alg_t hmac_alg;

  if (!cose_get_hmac_alg_for_hkdf(hkdf_alg, &hmac_alg))
    return 0;
  return coap_hitls_get_hmac_alg(hmac_alg, NULL, NULL);
}

static int
coap_hitls_check_ccm_params(const coap_crypto_aes_ccm_t *ccm, size_t key_len) {
  if (!ccm || !ccm->key.s || !ccm->nonce || ccm->key.length != key_len)
    return 0;
  if (ccm->l == 0 || ccm->l > 8)
    return 0;
  if (ccm->tag_len == 0 || ccm->tag_len > UINT32_MAX)
    return 0;
  return 1;
}

static int
coap_hitls_aead_set_common(CRYPT_EAL_CipherCtx *ctx,
                           const coap_crypto_aes_ccm_t *ccm,
                           const coap_bin_const_t *aad, uint64_t msg_len) {
  uint32_t tag_len = (uint32_t)ccm->tag_len;
  uint32_t aad_len = 0;

  if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN,
                           &tag_len, sizeof(tag_len)) != CRYPT_SUCCESS)
    return 0;
  if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN,
                           &msg_len, sizeof(msg_len)) != CRYPT_SUCCESS)
    return 0;
  if (aad && aad->length) {
    if (aad->length > UINT32_MAX)
      return 0;
    aad_len = (uint32_t)aad->length;
  }
  return CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD,
                              aad_len ? (void *)(uintptr_t)aad->s : NULL,
                              aad_len) == CRYPT_SUCCESS;
}

int
coap_crypto_aead_encrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {
  CRYPT_CIPHER_AlgId cipher_alg;
  CRYPT_EAL_CipherCtx *ctx = NULL;
  const coap_crypto_aes_ccm_t *ccm;
  size_t key_len;
  uint32_t out_len;
  uint32_t tag_len;
  uint64_t msg_len;
  int ret = 0;

  if (!params || !data || !result || !max_result_len)
    return 0;
  if (!coap_hitls_get_cipher_alg(params->alg, &cipher_alg, &key_len))
    return 0;

  ccm = &params->params.aes;
  if (!coap_hitls_check_ccm_params(ccm, key_len) ||
      data->length > UINT32_MAX ||
      ccm->tag_len > *max_result_len ||
      data->length > *max_result_len - ccm->tag_len ||
      !coap_hitls_startup())
    return 0;

  ctx = CRYPT_EAL_CipherNewCtx(cipher_alg);
  if (!ctx)
    return 0;

  out_len = (uint32_t)data->length;
  tag_len = (uint32_t)ccm->tag_len;
  msg_len = data->length;
  if (CRYPT_EAL_CipherInit(ctx, ccm->key.s, (uint32_t)ccm->key.length,
                           ccm->nonce, (uint32_t)(15 - ccm->l),
                           true) != CRYPT_SUCCESS)
    goto finish;
  if (!coap_hitls_aead_set_common(ctx, ccm, aad, msg_len))
    goto finish;
  if (CRYPT_EAL_CipherUpdate(ctx, data->s, (uint32_t)data->length,
                             result, &out_len) != CRYPT_SUCCESS)
    goto finish;
  if (out_len != data->length)
    goto finish;
  if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG,
                           result + out_len, tag_len) != CRYPT_SUCCESS)
    goto finish;

  *max_result_len = (size_t)out_len + ccm->tag_len;
  ret = 1;

finish:
  CRYPT_EAL_CipherFreeCtx(ctx);
  return ret;
}

int
coap_crypto_aead_decrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {
  CRYPT_CIPHER_AlgId cipher_alg;
  CRYPT_EAL_CipherCtx *ctx = NULL;
  const coap_crypto_aes_ccm_t *ccm;
  const uint8_t *tag;
  size_t key_len;
  size_t cipher_len;
  uint32_t out_len;
  uint32_t final_len;
  uint32_t tag_len;
  uint64_t msg_len;
  int ret = 0;

  if (!params || !data || !result || !max_result_len)
    return 0;
  if (!coap_hitls_get_cipher_alg(params->alg, &cipher_alg, &key_len))
    return 0;

  ccm = &params->params.aes;
  if (!coap_hitls_check_ccm_params(ccm, key_len) ||
      data->length < ccm->tag_len ||
      data->length > UINT32_MAX ||
      !coap_hitls_startup())
    return 0;

  cipher_len = data->length - ccm->tag_len;
  if (*max_result_len < cipher_len)
    return 0;

  ctx = CRYPT_EAL_CipherNewCtx(cipher_alg);
  if (!ctx)
    return 0;

  tag = data->s + cipher_len;
  out_len = (uint32_t)cipher_len;
  final_len = 0;
  tag_len = (uint32_t)ccm->tag_len;
  msg_len = cipher_len;
  if (CRYPT_EAL_CipherInit(ctx, ccm->key.s, (uint32_t)ccm->key.length,
                           ccm->nonce, (uint32_t)(15 - ccm->l),
                           false) != CRYPT_SUCCESS)
    goto finish;
  if (!coap_hitls_aead_set_common(ctx, ccm, aad, msg_len))
    goto finish;
  if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAG,
                           (void *)(uintptr_t)tag, tag_len) != CRYPT_SUCCESS)
    goto finish;
  if (CRYPT_EAL_CipherUpdate(ctx, data->s, (uint32_t)cipher_len,
                             result, &out_len) != CRYPT_SUCCESS)
    goto finish;
  if (out_len != cipher_len)
    goto finish;
  if (CRYPT_EAL_CipherFinal(ctx, result, &final_len) != CRYPT_SUCCESS)
    goto finish;
  if (final_len != 0)
    goto finish;

  *max_result_len = out_len;
  ret = 1;

finish:
  CRYPT_EAL_CipherFreeCtx(ctx);
  return ret;
}

int
coap_crypto_hmac(cose_hmac_alg_t hmac_alg,
                 coap_bin_const_t *key,
                 coap_bin_const_t *data,
                 coap_bin_const_t **hmac) {
  CRYPT_MAC_AlgId mac_alg;
  CRYPT_EAL_MacCtx *ctx = NULL;
  coap_binary_t *dummy = NULL;
  size_t mac_len;
  uint32_t out_len;
  int ret = 0;

  if (!key || !data || !hmac ||
      key->length > UINT32_MAX || data->length > UINT32_MAX ||
      !coap_hitls_get_hmac_alg(hmac_alg, &mac_alg, &mac_len) ||
      !coap_hitls_startup())
    return 0;

  dummy = coap_new_binary(mac_len);
  if (!dummy)
    return 0;

  ctx = CRYPT_EAL_MacNewCtx(mac_alg);
  if (!ctx)
    goto finish;

  out_len = (uint32_t)dummy->length;
  if (CRYPT_EAL_MacInit(ctx, key->s, (uint32_t)key->length) != CRYPT_SUCCESS)
    goto finish;
  if (CRYPT_EAL_MacUpdate(ctx, data->s, (uint32_t)data->length) != CRYPT_SUCCESS)
    goto finish;
  if (CRYPT_EAL_MacFinal(ctx, dummy->s, &out_len) != CRYPT_SUCCESS ||
      out_len != dummy->length)
    goto finish;

  *hmac = (coap_bin_const_t *)dummy;
  dummy = NULL;
  ret = 1;

finish:
  CRYPT_EAL_MacFreeCtx(ctx);
  coap_delete_binary(dummy);
  return ret;
}

#endif /* COAP_OSCORE_SUPPORT */

#if COAP_WITH_LIBOPENHITLS
#if COAP_CLIENT_SUPPORT
void *
coap_dtls_new_client_session(coap_session_t *session) {
  coap_hitls_env_t *env =
      coap_hitls_new_env(session, COAP_DTLS_ROLE_CLIENT, COAP_PROTO_DTLS);

  session->tls = env;
  if (env && coap_hitls_handshake(session, env) < 0) {
    coap_hitls_free_env(env);
    session->tls = NULL;
    return NULL;
  }
  return env;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
void *
coap_dtls_new_server_session(coap_session_t *session) {
  coap_hitls_env_t *env = session ? (coap_hitls_env_t *)session->tls : NULL;

  if (!env)
    return NULL;
  if (coap_hitls_handshake(session, env) < 0) {
    coap_hitls_free_env(env);
    session->tls = NULL;
    return NULL;
  }
  return env;
}
#endif /* COAP_SERVER_SUPPORT */

void
coap_dtls_free_session(coap_session_t *session) {
  if (session && session->context && session->tls) {
    coap_hitls_free_env((coap_hitls_env_t *)session->tls);
    session->tls = NULL;
    coap_handle_event_lkd(session->context, COAP_EVENT_DTLS_CLOSED, session);
  }
}

void
coap_dtls_session_update_mtu(coap_session_t *session) {
  if (session)
    coap_hitls_update_mtu((coap_hitls_env_t *)session->tls);
}

ssize_t
coap_dtls_send(coap_session_t *session, const uint8_t *data, size_t data_len) {
  coap_hitls_env_t *env = (coap_hitls_env_t *)session->tls;
  uint32_t written = 0;
  int32_t ret;

  if (!env || data_len > UINT32_MAX)
    return -1;

  session->dtls_event = -1;
  coap_log_debug("*  %s: dtls:  sent %4d bytes\n",
                 coap_session_str(session), (int)data_len);
  if (!env->established) {
    ret = coap_hitls_handshake(session, env);
    if (ret == 1)
      return coap_dtls_send(session, data, data_len);
    return ret == 0 ? 0 : -1;
  }

  BSL_ERR_ClearError();
  ret = HITLS_Write(env->ctx, data, (uint32_t)data_len, &written);
  if (ret == HITLS_SUCCESS) {
    if (written == 0)
      return 0;
    return (ssize_t)written;
  }
  if (coap_hitls_is_retry(ret))
    return 0;

  session->dtls_event = coap_hitls_is_closed(ret) ?
                        COAP_EVENT_DTLS_CLOSED : COAP_EVENT_DTLS_ERROR;
  if (session->dtls_event == COAP_EVENT_DTLS_ERROR) {
    coap_log_warn("coap_dtls_send: returned 0x%x\n", (unsigned int)ret);
    coap_hitls_log_fatal_err_stack(session);
  }
  coap_handle_event_lkd(session->context, session->dtls_event, session);
  return -1;
}

int
coap_dtls_is_context_timeout(void) {
  return 0;
}

coap_tick_t
coap_dtls_get_context_timeout(void *dtls_context COAP_UNUSED) {
  return 0;
}

coap_tick_t
coap_dtls_get_timeout(coap_session_t *session, coap_tick_t now) {
  coap_hitls_env_t *env = session ? (coap_hitls_env_t *)session->tls : NULL;
  uint64_t timeout_us = 0;
  int32_t ret;

  if (!env)
    return 0;
  ret = HITLS_DtlsGetTimeout(env->ctx, &timeout_us);
  if (ret == HITLS_MSG_HANDLE_ERR_WITHOUT_TIMEOUT_ACTION)
    return 0;
  if (ret != HITLS_SUCCESS) {
    coap_log_warn("HITLS_DtlsGetTimeout() returned 0x%x\n",
                  (unsigned int)ret);
    return 0;
  }
  if (timeout_us == 0) {
    /*
     * Timer already due: pace it so one I/O cycle does not fire DTLS timeouts
     * back-to-back and exhaust dtls_timeout_count prematurely.
     */
    if (env->last_timeout + COAP_DTLS_RETRANSMIT_COAP_TICKS > now)
      return env->last_timeout + COAP_DTLS_RETRANSMIT_COAP_TICKS;
    env->last_timeout = now;
    return now;
  }
  return now + (coap_tick_t)((timeout_us * COAP_TICKS_PER_SECOND + 999999) /
                             1000000);
}

int
coap_dtls_handle_timeout(coap_session_t *session) {
  coap_hitls_env_t *env = (coap_hitls_env_t *)session->tls;
  int32_t ret;

  if (!env)
    return 1;
  if (++session->dtls_timeout_count > session->max_retransmit) {
    coap_session_disconnected_lkd(session, COAP_NACK_TLS_FAILED);
    return 1;
  }

  BSL_ERR_ClearError();
  ret = HITLS_DtlsProcessTimeout(env->ctx);
  if (ret == HITLS_SUCCESS ||
      ret == HITLS_MSG_HANDLE_DTLS_RETRANSMIT_NOT_TIMEOUT ||
      coap_hitls_is_retry(ret))
    return 0;

  coap_log_warn("HITLS_DtlsProcessTimeout() returned 0x%x\n",
                (unsigned int)ret);
  coap_hitls_log_fatal_err_stack(session);
  coap_session_disconnected_lkd(session, COAP_NACK_TLS_FAILED);
  return 1;
}

int
coap_dtls_receive(coap_session_t *session, const uint8_t *data,
                  size_t data_len) {
  coap_hitls_env_t *env = (coap_hitls_env_t *)session->tls;
  int ret = -1;

  if (!env)
    return -1;
  if (env->pdu_len)
    coap_log_err("** %s: Previous data not read %" PRIuS " bytes\n",
                 coap_session_str(session), env->pdu_len);

  session->dtls_event = -1;
  env->pdu = data;
  env->pdu_len = data_len;

  if (env->established) {
#if COAP_CONSTRAINED_STACK
    static uint8_t pdu[COAP_RXBUFFER_SIZE];
#else /* ! COAP_CONSTRAINED_STACK */
    uint8_t pdu[COAP_RXBUFFER_SIZE];
#endif /* ! COAP_CONSTRAINED_STACK */
    uint32_t read_len = 0;
    int32_t hret;

    BSL_ERR_ClearError();
    hret = HITLS_Read(env->ctx, pdu, sizeof(pdu), &read_len);

    if (hret == HITLS_SUCCESS && read_len > 0) {
      coap_log_debug("*  %s: dtls:  recv %4d bytes\n",
                     coap_session_str(session), (int)read_len);
      ret = coap_handle_dgram(session->context, session, pdu, read_len);
      goto finish;
    }
    if (hret == HITLS_SUCCESS || coap_hitls_is_retry(hret)) {
      ret = -1;
      goto finish;
    }
    session->dtls_event = coap_hitls_is_closed(hret) ?
                          COAP_EVENT_DTLS_CLOSED : COAP_EVENT_DTLS_ERROR;
    if (session->dtls_event == COAP_EVENT_DTLS_ERROR) {
      coap_log_warn("coap_dtls_receive: returned 0x%x (length %" PRIdS ")\n",
                    (unsigned int)hret, data_len);
      coap_hitls_log_fatal_err_stack(session);
    }
  } else {
    /*
     * On completion coap_hitls_set_connected() drives l_establish(); on error
     * session->dtls_event is set and handled below, so the handshake return
     * value is not needed here.
     */
    (void)coap_hitls_handshake(session, env);
    ret = -1;
  }

  if (session->dtls_event >= 0) {
    coap_handle_event_lkd(session->context, session->dtls_event, session);
    if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected_lkd(session, COAP_NACK_TLS_FAILED);
      ret = -1;
    }
  }

finish:
  coap_hitls_clear_pdu(coap_hitls_live_env(session, env));
  return ret;
}

#if COAP_SERVER_SUPPORT
int
coap_dtls_hello(coap_session_t *session, const uint8_t *data,
                size_t data_len) {
  coap_hitls_env_t *env = (coap_hitls_env_t *)session->tls;
  int32_t ret;
  int cookie_valid = 0;

  if (!env) {
    env = coap_hitls_new_env(session, COAP_DTLS_ROLE_SERVER, COAP_PROTO_DTLS);
    if (!env)
      return -1;
    session->tls = env;
  }

  env->pdu = data;
  env->pdu_len = data_len;

  if (!env->hello_verify_sent) {
    BSL_ERR_ClearError();
    ret = HITLS_Listen(env->ctx, &session->addr_info.remote.addr.sa);
    if (env->pdu_len) {
      coap_log_debug("coap_dtls_hello: ret 0x%x: remaining data %" PRIuS "\n",
                     (unsigned int)ret, env->pdu_len);
    }
    coap_hitls_clear_pdu(env);

    if (ret == HITLS_SUCCESS)
      return 1;
    if (coap_hitls_is_retry(ret)) {
      /* HITLS_Listen emits HelloVerifyRequest; Accept flushes it. */
      ret = coap_hitls_handshake(session, env);
      if (ret < 0)
        return -1;
      env = coap_hitls_live_env(session, env);
      if (!env)
        return -1;
      env->hello_verify_sent = 1;
      return 0;
    }

    coap_log_warn("coap_dtls_hello: returned 0x%x\n", (unsigned int)ret);
    coap_hitls_log_fatal_err_stack(session);
    session->dtls_event = COAP_EVENT_DTLS_ERROR;
    return -1;
  }

  cookie_valid = coap_hitls_client_hello_cookie_valid(session, data, data_len);
  ret = coap_hitls_handshake(session, env);
  env = coap_hitls_live_env(session, env);
  coap_hitls_clear_pdu(env);

  if (ret < 0 || !env)
    return -1;
  return cookie_valid == 1 ? 1 : 0;
}
#endif /* COAP_SERVER_SUPPORT */

unsigned int
coap_dtls_get_overhead(coap_session_t *session COAP_UNUSED) {
  return COAP_HITLS_DTLS_OVERHEAD;
}

#if !COAP_DISABLE_TCP
#if COAP_CLIENT_SUPPORT
void *
coap_tls_new_client_session(coap_session_t *session) {
  coap_hitls_env_t *env =
      coap_hitls_new_env(session, COAP_DTLS_ROLE_CLIENT, COAP_PROTO_TLS);

  session->tls = env;
  if (env && coap_hitls_handshake(session, env) < 0) {
    coap_hitls_free_env(env);
    session->tls = NULL;
    return NULL;
  }
  return env;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
void *
coap_tls_new_server_session(coap_session_t *session) {
  coap_hitls_env_t *env =
      coap_hitls_new_env(session, COAP_DTLS_ROLE_SERVER, COAP_PROTO_TLS);

  session->tls = env;
  if (env && coap_hitls_handshake(session, env) < 0) {
    coap_hitls_free_env(env);
    session->tls = NULL;
    return NULL;
  }
  return env;
}
#endif /* COAP_SERVER_SUPPORT */

void
coap_tls_free_session(coap_session_t *session) {
  coap_dtls_free_session(session);
}

static void
coap_hitls_tcp_want(coap_session_t *session, HITLS_Ctx *ctx) {
  uint8_t rwstate = HITLS_NOTHING;

  (void)HITLS_GetRwstate(ctx, &rwstate);
  if (rwstate == HITLS_WRITING) {
    session->sock.flags |= COAP_SOCKET_WANT_WRITE;
#ifdef COAP_EPOLL_SUPPORT
    coap_epoll_ctl_mod(&session->sock,
                       EPOLLOUT |
                       ((session->sock.flags & COAP_SOCKET_WANT_READ) ?
                        EPOLLIN : 0),
                       __func__);
#endif /* COAP_EPOLL_SUPPORT */
  } else {
    session->sock.flags |= COAP_SOCKET_WANT_READ;
  }
}

ssize_t
coap_tls_write(coap_session_t *session,
               const uint8_t *data,
               size_t data_len) {
  coap_hitls_env_t *env = session ? (coap_hitls_env_t *)session->tls : NULL;
  uint32_t written = 0;
  int32_t ret;

  if (!env || data_len > UINT32_MAX) {
    errno = ENXIO;
    return -1;
  }

  session->dtls_event = -1;
  if (!env->established) {
    ret = coap_hitls_handshake(session, env);
    if (ret < 0)
      return -1;
    if (ret == 0)
      coap_hitls_tcp_want(session, env->ctx);
    return 0;
  }

  BSL_ERR_ClearError();
  ret = HITLS_Write(env->ctx, data, (uint32_t)data_len, &written);
  if (ret == HITLS_SUCCESS) {
    if (written > 0) {
      if (written == data_len)
        coap_log_debug("*  %s: tls:   sent %4d bytes\n",
                       coap_session_str(session), (int)written);
      else
        coap_log_debug("*  %s: tls:   sent %4d of %4" PRIdS " bytes\n",
                       coap_session_str(session), (int)written, data_len);
    }
    return (ssize_t)written;
  }
  if (coap_hitls_is_retry(ret)) {
    coap_hitls_tcp_want(session, env->ctx);
    return 0;
  }

  session->dtls_event = coap_hitls_is_closed(ret) ?
                        COAP_EVENT_DTLS_CLOSED : COAP_EVENT_DTLS_ERROR;
  if (session->dtls_event == COAP_EVENT_DTLS_ERROR) {
    coap_log_warn("coap_tls_write: returned 0x%x\n", (unsigned int)ret);
    coap_hitls_log_fatal_err_stack(session);
  }
  coap_handle_event_lkd(session->context, session->dtls_event, session);
  return -1;
}

ssize_t
coap_tls_read(coap_session_t *session,
              uint8_t *data,
              size_t data_len) {
  coap_hitls_env_t *env = session ? (coap_hitls_env_t *)session->tls : NULL;
  uint32_t read_len = 0;
  int32_t ret;

  if (!env || data_len > UINT32_MAX) {
    errno = ENXIO;
    return -1;
  }

  session->dtls_event = -1;
  if (!env->established) {
    ret = coap_hitls_handshake(session, env);
    if (ret < 0)
      return -1;
    if (ret == 0)
      coap_hitls_tcp_want(session, env->ctx);
    return 0;
  }

  BSL_ERR_ClearError();
  ret = HITLS_Read(env->ctx, data, (uint32_t)data_len, &read_len);
  if (ret == HITLS_SUCCESS) {
    if (read_len > 0)
      coap_log_debug("*  %s: tls:   recv %4d bytes\n",
                     coap_session_str(session), (int)read_len);
    return (ssize_t)read_len;
  }
  if (coap_hitls_is_retry(ret)) {
    coap_hitls_tcp_want(session, env->ctx);
    errno = EAGAIN;
    return 0;
  }

  session->dtls_event = coap_hitls_is_closed(ret) ?
                        COAP_EVENT_DTLS_CLOSED : COAP_EVENT_DTLS_ERROR;
  if (session->dtls_event == COAP_EVENT_DTLS_ERROR) {
    coap_log_warn("coap_tls_read: returned 0x%x (length %" PRIdS ")\n",
                  (unsigned int)ret, data_len);
    coap_hitls_log_fatal_err_stack(session);
  }
  coap_handle_event_lkd(session->context, session->dtls_event, session);
  if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
      session->dtls_event == COAP_EVENT_DTLS_CLOSED)
    coap_session_disconnected_lkd(session, COAP_NACK_TLS_FAILED);
  return -1;
}
#endif /* !COAP_DISABLE_TCP */
#endif /* COAP_WITH_LIBOPENHITLS */

#endif /* COAP_WITH_LIBOPENHITLS || COAP_WITH_LIBOPENHITLS_OSCORE */
