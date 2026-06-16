/* libcoap unit tests
 *
 * Copyright (C) 2018,2022-2026 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "test_common.h"
#include "test_tls.h"

#undef HAVE_DTLS

#ifdef COAP_WITH_LIBTINYDTLS
#define HAVE_DTLS 1

/* Need to #undef these to stop compiler warnings when tinydtls.h is included */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_URL
#undef PACKAGE_VERSION

#include <tinydtls.h>
#include <dtls.h>
#include <dtls_debug.h>
#endif /* COAP_WITH_LIBTINYDTLS */

#ifdef COAP_WITH_LIBOPENSSL
#define HAVE_DTLS 1
#include <openssl/ssl.h>
#endif /* COAP_WITH_LIBOPENSSL */

#ifdef COAP_WITH_LIBOPENHITLS
#define HAVE_DTLS 1
#endif /* COAP_WITH_LIBOPENHITLS */

#if defined(COAP_WITH_LIBOPENHITLS) || COAP_WITH_LIBOPENHITLS_OSCORE
#include <hitls/bsl/bsl_version.h>
#endif /* COAP_WITH_LIBOPENHITLS || COAP_WITH_LIBOPENHITLS_OSCORE */

#ifdef COAP_WITH_LIBWOLFSSL
#define HAVE_DTLS 1
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#endif /* COAP_WITH_LIBWOLFSSL */

#ifdef COAP_WITH_LIBGNUTLS
#define HAVE_DTLS 1
#include <gnutls/gnutls.h>
#endif /* COAP_WITH_LIBGNUTLS */

#ifdef COAP_WITH_LIBMBEDTLS
#define HAVE_DTLS 1
#include <mbedtls/version.h>
#endif /* COAP_WITH_LIBMBEDTLS */

#if COAP_WITH_LIBMBEDTLS_OSCORE
#include <mbedtls/version.h>
#endif /* COAP_WITH_LIBMBEDTLS_OSCORE */

#define ReturnIf_CU_ASSERT_PTR_NOT_NULL(value) \
  CU_ASSERT_PTR_NOT_NULL(value); \
  if ((const void*)value == NULL) return;

static void
t_tls1(void) {
  int need_dtls = 0;
#ifdef HAVE_DTLS
  need_dtls = 1;
#endif /* HAVE_DTLS */

  CU_ASSERT(coap_dtls_is_supported() == need_dtls);
}

static void
t_tls2(void) {
  coap_tls_version_t *v = coap_get_tls_library_version();
  coap_tls_version_t version;

  memset(&version, 0, sizeof(coap_tls_version_t));

#if defined(COAP_WITH_LIBOPENSSL)
  version.version = SSLeay();
  version.type = COAP_TLS_LIBRARY_OPENSSL;
#elif defined(COAP_WITH_LIBWOLFSSL)
  version.version = wolfSSL_lib_version_hex();
  version.type = COAP_TLS_LIBRARY_WOLFSSL;
#elif defined(COAP_WITH_LIBTINYDTLS)
  const char *vers = dtls_package_version();
  version.version = 0;
  if (vers) {
    long int p1, p2 = 0, p3 = 0;
    char *endptr;

    p1 = strtol(vers, &endptr, 10);
    if (*endptr == '.') {
      p2 = strtol(endptr+1, &endptr, 10);
      if (*endptr == '.') {
        p3 = strtol(endptr+1, &endptr, 10);
      }
    }
    version.version = (p1 << 16) | (p2 << 8) | p3;
  }
  version.type = COAP_TLS_LIBRARY_TINYDTLS;
#elif defined(COAP_WITH_LIBGNUTLS)
  version.version = GNUTLS_VERSION_NUMBER;
  version.type = COAP_TLS_LIBRARY_GNUTLS;
#elif COAP_WITH_LIBMBEDTLS || COAP_WITH_LIBMBEDTLS_OSCORE
  version.version = MBEDTLS_VERSION_NUMBER;
  version.type = COAP_TLS_LIBRARY_MBEDTLS;
#elif defined(COAP_WITH_LIBOPENHITLS) || COAP_WITH_LIBOPENHITLS_OSCORE
  version.version = HITLS_VersionNum();
  version.type = COAP_TLS_LIBRARY_OPENHITLS;
#else /* no DTLS */
  version.version = 0;
  version.type = COAP_TLS_LIBRARY_NOTLS;
#endif /* COAP_WITH_LIBOPENSSL || COAP_WITH_LIBTINYDTLS */

  ReturnIf_CU_ASSERT_PTR_NOT_NULL(v);
  CU_ASSERT(version.version == v->version);
  CU_ASSERT(version.type == v->type);
}

static void
t_tls3(void) {
  char buffer[256];
  int have_dtls = coap_dtls_is_supported();
  int have_tls = coap_tls_is_supported();

  memset(buffer, 0, sizeof(buffer));
  CU_ASSERT_PTR_EQUAL(coap_string_tls_support(buffer, sizeof(buffer)), buffer);
  if (!have_dtls && !have_tls) {
    CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "No DTLS or TLS support"));
  } else {
    const char *transport = have_dtls ?
                            have_tls ? "DTLS and TLS support" :
                            "DTLS and no TLS support" :
                            "No DTLS and TLS support";

    CU_ASSERT_PTR_NOT_NULL(strstr(buffer, transport));
    CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "PSK"));
    CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "PKI"));
    CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "PKCS11"));
    CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "RPK"));
    CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "CID"));
  }
}

#if COAP_SERVER_SUPPORT
static void
t_tls4(void) {
  static const uint8_t key[] = "secret";
  coap_context_t *ctx;
  coap_dtls_spsk_t setup_data;

  if (!coap_dtls_psk_is_supported())
    return;

  memset(&setup_data, 0, sizeof(setup_data));
  setup_data.version = COAP_DTLS_SPSK_SETUP_VERSION;
  setup_data.psk_info.hint.s = (const uint8_t *)"hint";
  setup_data.psk_info.hint.length = strlen("hint");
  setup_data.psk_info.key.s = key;
  setup_data.psk_info.key.length = sizeof(key) - 1;

  ctx = coap_new_context(NULL);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(ctx);

  CU_ASSERT(coap_context_set_psk2(ctx, NULL) == 0);
  CU_ASSERT(coap_context_set_psk(ctx, "hint", key, sizeof(key) - 1) == 1);
  CU_ASSERT(ctx->spsk_setup_data.psk_info.hint.length == strlen("hint"));
  CU_ASSERT(memcmp(ctx->spsk_setup_data.psk_info.hint.s,
                   "hint", strlen("hint")) == 0);
  CU_ASSERT(ctx->spsk_setup_data.psk_info.key.length == sizeof(key) - 1);
  CU_ASSERT(memcmp(ctx->spsk_setup_data.psk_info.key.s,
                   key, sizeof(key) - 1) == 0);
  CU_ASSERT(coap_dtls_context_check_keys_enabled(ctx) != 0);

  coap_free_context(ctx);
}

static void
t_tls5(void) {
  static const struct {
    const char *name;
    uint8_t verify_peer_cert;
    uint8_t check_common_ca;
    uint8_t allow_self_signed;
    uint8_t allow_expired_certs;
    uint8_t cert_chain_validation;
    uint8_t cert_chain_verify_depth;
    uint8_t check_cert_revocation;
    uint8_t allow_no_crl;
    uint8_t allow_expired_crl;
    uint8_t allow_bad_md_hash;
    uint8_t allow_short_rsa_length;
  } pki_matrix[] = {
    /* Server PKI setup with peer verification disabled. */
    { "no-peer-verification", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* Full peer verification with CRL checking enabled. */
    { "strict-peer-verification", 1, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0 },
    /* Peer verification requiring a common trusted CA. */
    { "common-ca", 1, 1, 0, 0, 1, 3, 0, 0, 0, 0, 0 },
    /* Peer verification accepting self-signed certificates. */
    { "allow-self-signed", 1, 0, 1, 0, 1, 2, 0, 0, 0, 0, 0 },
    /* Peer verification accepting expired certificates. */
    { "allow-expired-certs", 1, 0, 0, 1, 1, 2, 0, 0, 0, 0, 0 },
    /* CRL checking with missing CRLs allowed. */
    { "allow-no-crl", 1, 0, 0, 0, 1, 2, 1, 1, 0, 0, 0 },
    /* CRL checking with expired CRLs allowed. */
    { "allow-expired-crl", 1, 0, 0, 0, 1, 2, 1, 0, 1, 0, 0 },
    /* Peer verification accepting weak certificate hashes. */
    { "allow-bad-md-hash", 1, 0, 0, 0, 1, 2, 0, 0, 0, 1, 0 },
    /* Peer verification accepting short RSA keys. */
    { "allow-short-rsa", 1, 0, 0, 0, 1, 2, 0, 0, 0, 0, 1 },
    /* Peer verification with chain-depth enforcement disabled. */
    { "disable-chain-depth", 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
  };
  coap_context_t *ctx;
  coap_dtls_pki_t setup_data;
  size_t i;

  if (!coap_dtls_pki_is_supported())
    return;

  memset(&setup_data, 0, sizeof(setup_data));
  setup_data.version = COAP_DTLS_PKI_SETUP_VERSION;
  setup_data.verify_peer_cert = 0;
  setup_data.pki_key.key_type = COAP_PKI_KEY_PEM;

  ctx = coap_new_context(NULL);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(ctx);

  CU_ASSERT(coap_context_set_pki(ctx, NULL) == 0);
  setup_data.version = 0;
  CU_ASSERT(coap_context_set_pki(ctx, &setup_data) == 0);
  CU_ASSERT(coap_context_set_pki_root_cas(ctx, NULL, NULL) == 0);

  setup_data.version = COAP_DTLS_PKI_SETUP_VERSION;
  CU_ASSERT(coap_context_set_pki(ctx, &setup_data) == 1);

  coap_free_context(ctx);

  for (i = 0; i < sizeof(pki_matrix) / sizeof(pki_matrix[0]); i++) {
    int ret;

    memset(&setup_data, 0, sizeof(setup_data));
    setup_data.version = COAP_DTLS_PKI_SETUP_VERSION;
    setup_data.verify_peer_cert = pki_matrix[i].verify_peer_cert;
    setup_data.check_common_ca = pki_matrix[i].check_common_ca;
    setup_data.allow_self_signed = pki_matrix[i].allow_self_signed;
    setup_data.allow_expired_certs = pki_matrix[i].allow_expired_certs;
    setup_data.cert_chain_validation = pki_matrix[i].cert_chain_validation;
    setup_data.cert_chain_verify_depth = pki_matrix[i].cert_chain_verify_depth;
    setup_data.check_cert_revocation = pki_matrix[i].check_cert_revocation;
    setup_data.allow_no_crl = pki_matrix[i].allow_no_crl;
    setup_data.allow_expired_crl = pki_matrix[i].allow_expired_crl;
    setup_data.allow_bad_md_hash = pki_matrix[i].allow_bad_md_hash;
    setup_data.allow_short_rsa_length = pki_matrix[i].allow_short_rsa_length;
    setup_data.pki_key.key_type = COAP_PKI_KEY_PEM;

    ctx = coap_new_context(NULL);
    ReturnIf_CU_ASSERT_PTR_NOT_NULL(ctx);
    ret = coap_context_set_pki(ctx, &setup_data);
    if (!ret)
      fprintf(stderr, "W: DTLS PKI matrix case '%s' failed\n",
              pki_matrix[i].name);
    CU_ASSERT(ret == 1);
    coap_free_context(ctx);
  }
}
#endif /* COAP_SERVER_SUPPORT */

static void
t_tls6(void) {
  coap_context_t *ctx;
  int support = coap_dtls_cid_is_supported();

  ctx = coap_new_context(NULL);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(ctx);

  CU_ASSERT(coap_context_set_cid_tuple_change(ctx, 0) == support);
  CU_ASSERT(coap_context_set_cid_tuple_change(ctx, 1) == support);

  coap_free_context(ctx);
}

static void
t_tls7(void) {
  CU_ASSERT(coap_tls_engine_configure(NULL) == 0);
  CU_ASSERT(coap_tls_engine_remove() == 0);
  coap_dtls_set_log_level(COAP_LOG_DEBUG);
  CU_ASSERT(coap_dtls_get_log_level() == COAP_LOG_DEBUG);
  coap_dtls_set_log_level(COAP_LOG_WARN);
  CU_ASSERT(coap_dtls_get_log_level() == COAP_LOG_WARN);
  coap_dtls_shutdown();
  CU_ASSERT(coap_dtls_get_log_level() == COAP_LOG_EMERG);
  coap_dtls_startup();
}

static void
t_tls8(void) {
  coap_tls_library_t tls_lib = COAP_TLS_LIBRARY_NOTLS;
  coap_tls_library_t expected_dtls_lib =
      coap_dtls_is_supported() ? coap_get_tls_library_version()->type
      : COAP_TLS_LIBRARY_NOTLS;

  CU_ASSERT_PTR_NULL(coap_session_get_tls(NULL, &tls_lib));
  CU_ASSERT(tls_lib == COAP_TLS_LIBRARY_NOTLS);
  CU_ASSERT_PTR_NULL(coap_dtls_get_tls(NULL, &tls_lib));
  CU_ASSERT(tls_lib == expected_dtls_lib);
}

#if COAP_SERVER_SUPPORT
static void
t_tls9(void) {
  static const uint8_t data[] = "digest input";
  coap_digest_ctx_t *digest_ctx;
  coap_digest_t digest;

  digest_ctx = coap_digest_setup();
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(digest_ctx);
  CU_ASSERT(coap_digest_update(digest_ctx, data, sizeof(data) - 1) == 1);
  CU_ASSERT(coap_digest_final(digest_ctx, &digest) == 1);
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_SERVER_SUPPORT && COAP_IPV4_SUPPORT
static void COAP_UNUSED
t_tls_init_address(coap_address_t *addr, uint16_t port) {
  coap_address_init(addr);
  addr->addr.sin.sin_family = AF_INET;
  addr->addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr->size = sizeof(addr->addr.sin);
  coap_address_set_port(addr, port);
}
#endif /* COAP_SERVER_SUPPORT && COAP_IPV4_SUPPORT */

#if COAP_CLIENT_SUPPORT
static ssize_t
t_tls_test_write_cb(coap_session_t *session COAP_UNUSED,
                    const uint8_t *data COAP_UNUSED,
                    size_t datalen) {
  return (ssize_t)datalen;
}

static coap_session_t *
t_tls_new_test_session(coap_context_t *ctx, coap_proto_t proto) {
  coap_session_t *session;

  session = coap_malloc_type(COAP_SESSION, sizeof(*session));
  if (!session)
    return NULL;
  memset(session, 0, sizeof(*session));
  session->proto = proto;
  session->type = COAP_SESSION_TYPE_CLIENT;
  session->context = ctx;
  session->mtu = COAP_DEFAULT_MTU;
  session->sock.flags = COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_CONNECTED;
  session->sock.lfunc[COAP_LAYER_TLS].l_write = t_tls_test_write_cb;
  return session;
}

static void
t_tls_free_test_session(coap_session_t *session) {
  if (!session)
    return;
  if (session->tls)
    coap_dtls_free_session(session);
  coap_free_type(COAP_SESSION, session);
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT && COAP_IPV4_SUPPORT
static unsigned int tls_hello_write_count;
static size_t tls_hello_write_len;
static int tls_hello_write_overflow;
static uint8_t tls_hello_write_data[512];

static void
t_tls_hello_write_reset(void) {
  tls_hello_write_count = 0;
  tls_hello_write_len = 0;
  tls_hello_write_overflow = 0;
  memset(tls_hello_write_data, 0, sizeof(tls_hello_write_data));
}

static ssize_t
t_tls_hello_write_cb(coap_session_t *session COAP_UNUSED,
                     const uint8_t *data,
                     size_t datalen) {
  if (tls_hello_write_count == 0) {
    tls_hello_write_len = datalen;
    if (datalen <= sizeof(tls_hello_write_data))
      memcpy(tls_hello_write_data, data, datalen);
    else
      tls_hello_write_overflow = 1;
  }
  tls_hello_write_count++;
  return (ssize_t)datalen;
}

static uint32_t
t_tls_u24(const uint8_t *p) {
  return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static void
t_tls_set_u16(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}

static void
t_tls_set_u24(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 16);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)v;
}

static int
t_tls_extract_hvr_cookie(const uint8_t *data, size_t data_len,
                         uint8_t *cookie, size_t cookie_size,
                         size_t *cookie_len) {
  size_t body_offset = 13 + 12;
  size_t body_end;
  size_t offset;
  uint32_t record_len;
  uint32_t hs_len;
  uint8_t len;

  if (!data || !cookie || !cookie_len ||
      data_len < body_offset || data[0] != 22 || data[13] != 3)
    return 0;

  record_len = ((uint32_t)data[11] << 8) | data[12];
  hs_len = t_tls_u24(&data[14]);
  if (record_len > data_len - 13 || hs_len > record_len - 12)
    return 0;

  body_end = body_offset + hs_len;
  if (body_end > data_len || body_end < body_offset + 3)
    return 0;

  offset = body_offset + 2;
  len = data[offset++];
  if (len == 0 || offset + len > body_end || len > cookie_size)
    return 0;

  memcpy(cookie, &data[offset], len);
  *cookie_len = len;
  return 1;
}

static int
t_tls_build_cookie_client_hello(const uint8_t *client_hello,
                                size_t client_hello_len,
                                const uint8_t *cookie,
                                size_t cookie_len,
                                uint8_t *out,
                                size_t *out_len) {
  size_t body_offset = 13 + 12;
  size_t body_end;
  size_t offset;
  size_t cookie_offset;
  size_t new_len;
  uint32_t record_len;
  uint32_t hs_len;
  uint8_t session_id_len;
  uint8_t old_cookie_len;

  if (!client_hello || !cookie || !out || !out_len ||
      cookie_len > 255 || client_hello_len < body_offset)
    return 0;

  record_len = ((uint32_t)client_hello[11] << 8) | client_hello[12];
  hs_len = t_tls_u24(&client_hello[14]);
  if (record_len > client_hello_len - 13 || hs_len > record_len - 12)
    return 0;

  body_end = body_offset + hs_len;
  if (body_end > client_hello_len || body_end < body_offset + 35)
    return 0;

  offset = body_offset + 34;
  session_id_len = client_hello[offset++];
  if (offset + session_id_len + 1 > body_end)
    return 0;
  offset += session_id_len;
  old_cookie_len = client_hello[offset];
  cookie_offset = offset + 1;
  if (cookie_offset + old_cookie_len > client_hello_len)
    return 0;

  new_len = client_hello_len - old_cookie_len + cookie_len;
  if (new_len > *out_len)
    return 0;

  memcpy(out, client_hello, cookie_offset);
  out[offset] = (uint8_t)cookie_len;
  memcpy(&out[cookie_offset], cookie, cookie_len);
  memcpy(&out[cookie_offset + cookie_len],
         &client_hello[cookie_offset + old_cookie_len],
         client_hello_len - cookie_offset - old_cookie_len);

  t_tls_set_u16(&out[11],
                record_len - old_cookie_len + (uint32_t)cookie_len);
  t_tls_set_u24(&out[14],
                hs_len - old_cookie_len + (uint32_t)cookie_len);
  t_tls_set_u16(&out[17], 1);
  t_tls_set_u24(&out[22],
                hs_len - old_cookie_len + (uint32_t)cookie_len);
  out[10] = 1;
  *out_len = new_len;
  return 1;
}

static void
t_tls10(void) {
  static const uint8_t client_hello[] = {
    0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x78, 0x01, 0x00, 0x00,
    0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x6c, 0xfe, 0xfd, 0x73, 0xf8, 0x35, 0x82, 0x43,
    0x39, 0xd4, 0x08, 0x0b, 0x8d, 0x23, 0x15, 0x8e,
    0xb6, 0xe5, 0x12, 0xc7, 0x6c, 0x3d, 0x2d, 0xcf,
    0x8e, 0x8a, 0xed, 0xf8, 0xc7, 0x4c, 0xd4, 0x5b,
    0xe6, 0xf5, 0xb4, 0x00, 0x00, 0x00, 0x0a, 0x00,
    0xa8, 0x00, 0xa9, 0xc0, 0xa5, 0xcc, 0xab, 0x00,
    0xff, 0x01, 0x00, 0x00, 0x38, 0x00, 0x0d, 0x00,
    0x28, 0x00, 0x26, 0x04, 0x03, 0x05, 0x03, 0x06,
    0x03, 0x08, 0x07, 0x08, 0x09, 0x08, 0x0a, 0x08,
    0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04,
    0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x03,
    0x01, 0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06,
    0x02, 0x00, 0x17, 0x00, 0x00, 0x00, 0x23, 0x00,
    0x00, 0x00, 0x16, 0x00, 0x00
  };
  static const uint8_t psk[] = "secretPSK";
  uint8_t cookie[64];
  uint8_t bad_cookie[64];
  size_t cookie_len = 0;
  uint8_t bad_client_hello[256];
  uint8_t second_client_hello[256];
  size_t bad_client_hello_len = sizeof(bad_client_hello);
  size_t second_client_hello_len = sizeof(second_client_hello);
  coap_context_t *ctx;
  coap_dtls_spsk_t setup_data;
  coap_endpoint_t endpoint;
  coap_session_t *session;
  coap_tls_version_t *version;
  int ret;

  if (!coap_dtls_is_supported() || !coap_dtls_psk_is_supported())
    return;
  version = coap_get_tls_library_version();
  if (version && version->type == COAP_TLS_LIBRARY_TINYDTLS)
    return;

  ctx = coap_new_context(NULL);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(ctx);

  memset(&setup_data, 0, sizeof(setup_data));
  setup_data.version = COAP_DTLS_SPSK_SETUP_VERSION;
  setup_data.psk_info.key.s = psk;
  setup_data.psk_info.key.length = sizeof(psk) - 1;
  CU_ASSERT(coap_context_set_psk2(ctx, &setup_data) == 1);

  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.context = ctx;
  endpoint.proto = COAP_PROTO_DTLS;
  endpoint.default_mtu = COAP_DEFAULT_MTU;
  t_tls_init_address(&endpoint.bind_addr, 5684);

  session = coap_malloc_type(COAP_SESSION, sizeof(*session));
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(session);
  memset(session, 0, sizeof(*session));
  session->proto = COAP_PROTO_DTLS;
  session->type = COAP_SESSION_TYPE_HELLO;
  session->state = COAP_SESSION_STATE_NONE;
  session->mtu = COAP_DEFAULT_MTU;
  session->context = ctx;
  session->endpoint = &endpoint;
  session->sock.lfunc[COAP_LAYER_TLS].l_write = t_tls_hello_write_cb;
  t_tls_init_address(&session->addr_info.local, 5684);
  t_tls_init_address(&session->addr_info.remote, 56840);

  t_tls_hello_write_reset();
  ret = coap_dtls_hello(session, client_hello, sizeof(client_hello));
  CU_ASSERT(ret == 0 || ret == 1);
  if (ret == 1)
    goto finish;
  CU_ASSERT(ret == 0);
  CU_ASSERT(tls_hello_write_count == 1);
  CU_ASSERT(tls_hello_write_len > 0);
  CU_ASSERT(tls_hello_write_overflow == 0);
  if (tls_hello_write_overflow)
    goto finish;
  CU_ASSERT(t_tls_extract_hvr_cookie(tls_hello_write_data,
                                     tls_hello_write_len,
                                     cookie, sizeof(cookie),
                                     &cookie_len) == 1);
  CU_ASSERT(cookie_len > 0);
  CU_ASSERT(cookie_len <= sizeof(bad_cookie));
  if (cookie_len == 0 || cookie_len > sizeof(bad_cookie))
    goto finish;
  CU_ASSERT(t_tls_build_cookie_client_hello(client_hello,
                                            sizeof(client_hello),
                                            cookie, cookie_len,
                                            second_client_hello,
                                            &second_client_hello_len) == 1);
  memcpy(bad_cookie, cookie, cookie_len);
  bad_cookie[0] ^= 0x01;
  CU_ASSERT(t_tls_build_cookie_client_hello(client_hello,
                                            sizeof(client_hello),
                                            bad_cookie, cookie_len,
                                            bad_client_hello,
                                            &bad_client_hello_len) == 1);

  t_tls_hello_write_reset();
  ret = coap_dtls_hello(session, bad_client_hello, bad_client_hello_len);
  CU_ASSERT(ret == 0);
  CU_ASSERT(tls_hello_write_count == 1);
  CU_ASSERT(tls_hello_write_len > 0);
  CU_ASSERT(t_tls_extract_hvr_cookie(tls_hello_write_data,
                                     tls_hello_write_len,
                                     cookie, sizeof(cookie),
                                     &cookie_len) == 1);

  t_tls_hello_write_reset();
  ret = coap_dtls_hello(session, second_client_hello,
                        second_client_hello_len);
  CU_ASSERT(ret == 1);

finish:
  if (session->tls)
    coap_dtls_free_session(session);
  coap_delete_bin_const(session->client_cid);
  coap_free_type(COAP_SESSION, session);
  coap_free_context(ctx);
}
#endif /* COAP_SERVER_SUPPORT && COAP_IPV4_SUPPORT */

#if COAP_CLIENT_SUPPORT
static coap_context_t *
t_tls_new_pki_context(const coap_dtls_pki_t *setup_data) {
  coap_context_t *ctx = coap_new_context(NULL);

  CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);
#if COAP_SERVER_SUPPORT
  CU_ASSERT(coap_context_set_pki(ctx, setup_data) == 1);
#else /* ! COAP_SERVER_SUPPORT */
  (void)setup_data;
#endif /* ! COAP_SERVER_SUPPORT */
  return ctx;
}

static void
t_tls_expect_pki_client_result(const coap_dtls_pki_t *setup_data,
                               int expect_tls) {
  coap_context_t *ctx = t_tls_new_pki_context(setup_data);
  coap_session_t *session = t_tls_new_test_session(ctx, COAP_PROTO_DTLS);
  void *tls;

  if (!session) {
    CU_ASSERT_PTR_NOT_NULL(session);
    coap_free_context(ctx);
    return;
  }
  tls = coap_dtls_new_client_session(session);
  if (tls && !session->tls)
    session->tls = tls;
  if (expect_tls > 0) {
    CU_ASSERT_PTR_NOT_NULL(tls);
  } else if (expect_tls == 0) {
    CU_ASSERT_PTR_NULL(tls);
  }
  t_tls_free_test_session(session);
  coap_free_context(ctx);
}

static void
t_tls11(void) {
  coap_dtls_pki_t setup_data;

  if (!coap_dtls_pki_is_supported())
    return;

  memset(&setup_data, 0, sizeof(setup_data));
  setup_data.version = COAP_DTLS_PKI_SETUP_VERSION;
  setup_data.verify_peer_cert = 0;
  setup_data.pki_key.key_type = COAP_PKI_KEY_DEFINE;
  setup_data.pki_key.key.define.ca_def = COAP_PKI_KEY_DEF_PEM_BUF;
  setup_data.pki_key.key.define.public_cert_def = COAP_PKI_KEY_DEF_PEM_BUF;
  setup_data.pki_key.key.define.private_key_def = COAP_PKI_KEY_DEF_PEM_BUF;
  t_tls_expect_pki_client_result(&setup_data, 1);

  setup_data.pki_key.key.define.ca_def = COAP_PKI_KEY_DEF_DER_BUF;
  setup_data.pki_key.key.define.public_cert_def = COAP_PKI_KEY_DEF_DER_BUF;
  setup_data.pki_key.key.define.private_key_def = COAP_PKI_KEY_DEF_DER_BUF;
  t_tls_expect_pki_client_result(&setup_data, 1);
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_OSCORE_SUPPORT
static void
t_tls12(void) {
  if (!coap_oscore_is_supported())
    return;

  CU_ASSERT(coap_crypto_check_cipher_alg(COSE_ALGORITHM_AES_CCM_16_64_128) != 0);
  CU_ASSERT(coap_crypto_check_cipher_alg(COSE_ALGORITHM_AES_CCM_64_64_128) == 0);
  CU_ASSERT(coap_crypto_check_cipher_alg((cose_alg_t)0) == 0);
  CU_ASSERT(coap_crypto_check_hkdf_alg(COSE_HKDF_ALG_HKDF_SHA_256) != 0);
  CU_ASSERT(coap_crypto_check_hkdf_alg((cose_hkdf_alg_t)0) == 0);
}

static void
t_tls13(void) {
  static const uint8_t key128[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };
  static const uint8_t nonce[COSE_ALGORITHM_AES_CCM_16_64_128_NONCE_LEN] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c
  };
  static const uint8_t plaintext[] = "tls-crypto";
  static const uint8_t aad_data[] = "aad";
  coap_crypto_param_t params;
  coap_bin_const_t data = { sizeof(plaintext) - 1, plaintext };
  coap_bin_const_t aad = { sizeof(aad_data) - 1, aad_data };
  coap_bin_const_t key = { sizeof(key128), key128 };
  coap_bin_const_t hmac_data = { sizeof(plaintext) - 1, plaintext };
  coap_bin_const_t *hmac = NULL;
  uint8_t encrypted[64];
  uint8_t decrypted[64];
  size_t encrypted_len = sizeof(encrypted);
  size_t decrypted_len = sizeof(decrypted);

  if (!coap_oscore_is_supported() ||
      !coap_crypto_check_cipher_alg(COSE_ALGORITHM_AES_CCM_16_64_128))
    return;

  memset(&params, 0, sizeof(params));
  params.alg = COSE_ALGORITHM_AES_CCM_16_64_128;
  params.params.aes.key.s = key128;
  params.params.aes.key.length = sizeof(key128);
  params.params.aes.nonce = nonce;
  params.params.aes.tag_len = COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;
  params.params.aes.l = 2;

  CU_ASSERT(coap_crypto_aead_encrypt(&params, &data, &aad, encrypted,
                                     &encrypted_len) == 1);
  CU_ASSERT(encrypted_len == data.length + params.params.aes.tag_len);

  data.s = encrypted;
  data.length = encrypted_len;
  CU_ASSERT(coap_crypto_aead_decrypt(&params, &data, &aad, decrypted,
                                     &decrypted_len) == 1);
  CU_ASSERT(decrypted_len == sizeof(plaintext) - 1);
  CU_ASSERT(memcmp(decrypted, plaintext, decrypted_len) == 0);

  encrypted[encrypted_len - 1] ^= 0x01;
  decrypted_len = sizeof(decrypted);
  CU_ASSERT(coap_crypto_aead_decrypt(&params, &data, &aad, decrypted,
                                     &decrypted_len) == 0);

  CU_ASSERT(coap_crypto_hmac(COSE_HMAC_ALG_HMAC256_256, &key, &hmac_data,
                             &hmac) == 1);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(hmac);
  CU_ASSERT(hmac->length == COSE_ALGORITHM_HMAC256_256_HASH_LEN);
  coap_delete_binary((coap_binary_t *)hmac);

  /* HMAC-384 and HMAC-512 are optional; verify the digest where supported. */
  hmac = NULL;
  if (coap_crypto_hmac(COSE_HMAC_ALG_HMAC384_384, &key, &hmac_data, &hmac) == 1) {
    ReturnIf_CU_ASSERT_PTR_NOT_NULL(hmac);
    CU_ASSERT(hmac->length == COSE_ALGORITHM_HMAC384_384_HASH_LEN);
    coap_delete_binary((coap_binary_t *)hmac);
  }
  hmac = NULL;
  if (coap_crypto_hmac(COSE_HMAC_ALG_HMAC512_512, &key, &hmac_data, &hmac) == 1) {
    ReturnIf_CU_ASSERT_PTR_NOT_NULL(hmac);
    CU_ASSERT(hmac->length == COSE_ALGORITHM_HMAC512_512_HASH_LEN);
    coap_delete_binary((coap_binary_t *)hmac);
  }
  /* An unknown COSE HMAC algorithm must be rejected. */
  hmac = NULL;
  CU_ASSERT(coap_crypto_hmac((cose_hmac_alg_t)0, &key, &hmac_data, &hmac) == 0);
}
#endif /* COAP_OSCORE_SUPPORT */

#if COAP_WS_SUPPORT
static void
t_tls14(void) {
  static const uint8_t hash_data[] = "abc";
  static const uint8_t sha1_digest[] = {
    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
    0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
    0x9c, 0xd0, 0xd8, 0x9d
  };
  coap_bin_const_t data = { sizeof(hash_data) - 1, hash_data };
  coap_bin_const_t *hash = NULL;

  CU_ASSERT(coap_crypto_hash(COSE_ALGORITHM_SHA_1, &data, &hash) == 1);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(hash);
  CU_ASSERT(hash->length == sizeof(sha1_digest));
  CU_ASSERT(memcmp(hash->s, sha1_digest, sizeof(sha1_digest)) == 0);
  coap_delete_binary((coap_binary_t *)hash);

#if COAP_WITH_LIBOPENSSL || COAP_WITH_LIBGNUTLS || \
    COAP_WITH_LIBMBEDTLS || COAP_WITH_LIBWOLFSSL || \
    COAP_WITH_LIBOPENHITLS
  {
    static const uint8_t sha256_digest[] = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
      0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
      0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
      0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    static const uint8_t sha512_digest[] = {
      0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
      0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
      0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
      0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
      0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
      0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
      0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
      0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
    };

    hash = NULL;
    if (coap_crypto_hash(COSE_ALGORITHM_SHA_256_256, &data, &hash) == 1) {
      ReturnIf_CU_ASSERT_PTR_NOT_NULL(hash);
      CU_ASSERT(hash->length == sizeof(sha256_digest));
      CU_ASSERT(memcmp(hash->s, sha256_digest, sizeof(sha256_digest)) == 0);
      coap_delete_binary((coap_binary_t *)hash);
    }

    /* SHA-256/64 keeps only the leading 8 bytes of the SHA-256 digest. */
    hash = NULL;
    if (coap_crypto_hash(COSE_ALGORITHM_SHA_256_64, &data, &hash) == 1) {
      ReturnIf_CU_ASSERT_PTR_NOT_NULL(hash);
      CU_ASSERT(hash->length == 8);
      CU_ASSERT(memcmp(hash->s, sha256_digest, 8) == 0);
      coap_delete_binary((coap_binary_t *)hash);
    }

    hash = NULL;
    if (coap_crypto_hash(COSE_ALGORITHM_SHA_512, &data, &hash) == 1) {
      ReturnIf_CU_ASSERT_PTR_NOT_NULL(hash);
      CU_ASSERT(hash->length == sizeof(sha512_digest));
      CU_ASSERT(memcmp(hash->s, sha512_digest, sizeof(sha512_digest)) == 0);
      coap_delete_binary((coap_binary_t *)hash);
    }
  }
#endif /* real-crypto backends */
}
#endif /* COAP_WS_SUPPORT */

#if COAP_SERVER_SUPPORT && COAP_CLIENT_SUPPORT && COAP_IPV4_SUPPORT
typedef struct {
  coap_context_t *server_ctx;
  coap_context_t *client_ctx;
  coap_session_t *server_session;
  int client_dtls_connected;
  int client_session_connected;
  int client_dtls_closed_or_error;
  int server_session_connected;
  unsigned int lower_write_calls;
} t_tls_write_error_state_t;

static t_tls_write_error_state_t tls_write_error_state;

static int
t_tls_write_error_event_handler(coap_session_t *session,
                                const coap_event_t event) {
  coap_context_t *ctx = coap_session_get_context(session);

  if (ctx == tls_write_error_state.client_ctx) {
    if (event == COAP_EVENT_DTLS_CONNECTED)
      tls_write_error_state.client_dtls_connected = 1;
    else if (event == COAP_EVENT_SESSION_CONNECTED)
      tls_write_error_state.client_session_connected = 1;
    else if (event == COAP_EVENT_DTLS_CLOSED ||
             event == COAP_EVENT_DTLS_ERROR)
      tls_write_error_state.client_dtls_closed_or_error = 1;
  } else if (ctx == tls_write_error_state.server_ctx) {
    if (event == COAP_EVENT_SERVER_SESSION_CONNECTED) {
      tls_write_error_state.server_session = session;
      tls_write_error_state.server_session_connected = 1;
    }
  }
  return 0;
}

static void
t_tls_io_process_pair(coap_context_t *server_ctx, coap_context_t *client_ctx,
                      unsigned int rounds, uint32_t timeout_ms) {
  unsigned int i;

  for (i = 0; i < rounds; i++) {
    (void)coap_io_process(client_ctx, timeout_ms);
    (void)coap_io_process(server_ctx, timeout_ms);
  }
}

#if !COAP_DISABLE_TCP
static int
t_tls_reset_server_socket(coap_session_t *session) {
#ifdef SO_LINGER
  struct linger linger_opt;

  if (!session || session->sock.fd == COAP_INVALID_SOCKET)
    return 0;

  memset(&linger_opt, 0, sizeof(linger_opt));
  linger_opt.l_onoff = 1;
  linger_opt.l_linger = 0;
  if (setsockopt(session->sock.fd, SOL_SOCKET, SO_LINGER,
                 (const void *)&linger_opt,
                 sizeof(linger_opt)) == COAP_SOCKET_ERROR)
    return 0;
  coap_socket_strm_close(&session->sock);
  return 1;
#else /* ! SO_LINGER */
  (void)session;
  return 0;
#endif /* ! SO_LINGER */
}

static void
t_tls15(void) {
  static const uint8_t psk[] = "secretPSK";
  static const uint8_t identity[] = "client";
  coap_context_t *server_ctx = NULL;
  coap_context_t *client_ctx = NULL;
  coap_endpoint_t *endpoint = NULL;
  coap_session_t *client_session = NULL;
  coap_address_t listen_addr;
  coap_address_t server_addr;
  coap_dtls_spsk_t spsk;
  coap_dtls_cpsk_t cpsk;
  coap_mid_t mid;
  unsigned int i;

  if (!coap_tls_is_supported() || !coap_dtls_psk_is_supported())
    return;

  memset(&tls_write_error_state, 0, sizeof(tls_write_error_state));
  server_ctx = coap_new_context(NULL);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(server_ctx);
  client_ctx = coap_new_context(NULL);
  if (!client_ctx) {
    CU_ASSERT_PTR_NOT_NULL(client_ctx);
    goto finish;
  }

  coap_register_event_handler(server_ctx, t_tls_write_error_event_handler);
  coap_register_event_handler(client_ctx, t_tls_write_error_event_handler);
  tls_write_error_state.server_ctx = server_ctx;
  tls_write_error_state.client_ctx = client_ctx;

  memset(&spsk, 0, sizeof(spsk));
  spsk.version = COAP_DTLS_SPSK_SETUP_VERSION;
  spsk.psk_info.key.s = psk;
  spsk.psk_info.key.length = sizeof(psk) - 1;
  CU_ASSERT(coap_context_set_psk2(server_ctx, &spsk) == 1);

  t_tls_init_address(&listen_addr, 0);
  endpoint = coap_new_endpoint(server_ctx, &listen_addr, COAP_PROTO_TLS);
  if (!endpoint) {
    CU_ASSERT_PTR_NOT_NULL(endpoint);
    goto finish;
  }
  coap_address_copy(&server_addr, &endpoint->bind_addr);

  memset(&cpsk, 0, sizeof(cpsk));
  cpsk.version = COAP_DTLS_CPSK_SETUP_VERSION;
  cpsk.psk_info.identity.s = identity;
  cpsk.psk_info.identity.length = sizeof(identity) - 1;
  cpsk.psk_info.key.s = psk;
  cpsk.psk_info.key.length = sizeof(psk) - 1;

  client_session = coap_new_client_session_psk3(client_ctx, NULL,
                                                &server_addr, COAP_PROTO_TLS,
                                                &cpsk, NULL, NULL, NULL);
  if (!client_session) {
    CU_ASSERT_PTR_NOT_NULL(client_session);
    goto finish;
  }

  for (i = 0; i < 200; i++) {
    t_tls_io_process_pair(server_ctx, client_ctx, 1, 10);
    if (tls_write_error_state.client_dtls_connected &&
        tls_write_error_state.client_session_connected &&
        tls_write_error_state.server_session_connected)
      break;
  }

  CU_ASSERT(tls_write_error_state.client_dtls_connected == 1);
  CU_ASSERT(tls_write_error_state.client_session_connected == 1);
  CU_ASSERT(tls_write_error_state.server_session_connected == 1);
  CU_ASSERT_PTR_NOT_NULL(tls_write_error_state.server_session);
  if (!tls_write_error_state.client_dtls_connected ||
      !tls_write_error_state.client_session_connected ||
      !tls_write_error_state.server_session_connected ||
      !tls_write_error_state.server_session)
    goto finish;

  CU_ASSERT(t_tls_reset_server_socket(tls_write_error_state.server_session) == 1);
  mid = coap_session_send_ping(client_session);
  CU_ASSERT(mid == COAP_INVALID_MID);
  CU_ASSERT(tls_write_error_state.client_dtls_closed_or_error == 1);

finish:
  if (client_session)
    coap_session_release(client_session);
  if (server_ctx)
    coap_free_context(server_ctx);
  if (client_ctx)
    coap_free_context(client_ctx);
}
#endif /* !COAP_DISABLE_TCP */

static ssize_t
t_tls_lower_write_error_cb(coap_session_t *session COAP_UNUSED,
                           const uint8_t *data COAP_UNUSED,
                           size_t datalen COAP_UNUSED) {
  tls_write_error_state.lower_write_calls++;
  errno = ECONNREFUSED;
  return -1;
}

static coap_session_t *
t_tls_new_dtls_psk_pair(coap_context_t **server_ctx,
                        coap_context_t **client_ctx) {
  static const uint8_t psk[] = "secretPSK";
  static const uint8_t identity[] = "client";
  coap_endpoint_t *endpoint;
  coap_session_t *client_session;
  coap_address_t listen_addr;
  coap_address_t server_addr;
  coap_dtls_spsk_t spsk;
  coap_dtls_cpsk_t cpsk;
  unsigned int i;

  *server_ctx = coap_new_context(NULL);
  if (!*server_ctx) {
    CU_ASSERT_PTR_NOT_NULL(*server_ctx);
    return NULL;
  }
  *client_ctx = coap_new_context(NULL);
  if (!*client_ctx) {
    CU_ASSERT_PTR_NOT_NULL(*client_ctx);
    goto fail;
  }

  coap_register_event_handler(*server_ctx, t_tls_write_error_event_handler);
  coap_register_event_handler(*client_ctx, t_tls_write_error_event_handler);
  tls_write_error_state.server_ctx = *server_ctx;
  tls_write_error_state.client_ctx = *client_ctx;

  memset(&spsk, 0, sizeof(spsk));
  spsk.version = COAP_DTLS_SPSK_SETUP_VERSION;
  spsk.psk_info.key.s = psk;
  spsk.psk_info.key.length = sizeof(psk) - 1;
  CU_ASSERT(coap_context_set_psk2(*server_ctx, &spsk) == 1);

  t_tls_init_address(&listen_addr, 0);
  endpoint = coap_new_endpoint(*server_ctx, &listen_addr, COAP_PROTO_DTLS);
  if (!endpoint) {
    CU_ASSERT_PTR_NOT_NULL(endpoint);
    goto fail;
  }
  coap_address_copy(&server_addr, &endpoint->bind_addr);

  memset(&cpsk, 0, sizeof(cpsk));
  cpsk.version = COAP_DTLS_CPSK_SETUP_VERSION;
  cpsk.psk_info.identity.s = identity;
  cpsk.psk_info.identity.length = sizeof(identity) - 1;
  cpsk.psk_info.key.s = psk;
  cpsk.psk_info.key.length = sizeof(psk) - 1;

  client_session = coap_new_client_session_psk3(*client_ctx, NULL,
                                                &server_addr, COAP_PROTO_DTLS,
                                                &cpsk, NULL, NULL, NULL);
  if (!client_session) {
    CU_ASSERT_PTR_NOT_NULL(client_session);
    goto fail;
  }

  for (i = 0; i < 300; i++) {
    t_tls_io_process_pair(*server_ctx, *client_ctx, 1, 10);
    if (client_session->state == COAP_SESSION_STATE_ESTABLISHED)
      break;
  }

  CU_ASSERT(client_session->state == COAP_SESSION_STATE_ESTABLISHED);
  if (client_session->state != COAP_SESSION_STATE_ESTABLISHED) {
    coap_session_release(client_session);
    goto fail;
  }

  return client_session;

fail:
  if (*server_ctx) {
    coap_free_context(*server_ctx);
    *server_ctx = NULL;
  }
  if (*client_ctx) {
    coap_free_context(*client_ctx);
    *client_ctx = NULL;
  }
  return NULL;
}

static void
t_tls16(void) {
  coap_context_t *server_ctx = NULL;
  coap_context_t *client_ctx = NULL;
  coap_session_t *client_session;
  coap_tls_version_t *version;
  coap_mid_t mid;

  if (!coap_dtls_is_supported() || !coap_dtls_psk_is_supported())
    return;
  version = coap_get_tls_library_version();
  if (version && version->type == COAP_TLS_LIBRARY_TINYDTLS)
    return;

  memset(&tls_write_error_state, 0, sizeof(tls_write_error_state));
  client_session = t_tls_new_dtls_psk_pair(&server_ctx, &client_ctx);
  if (!client_session)
    goto finish;
  tls_write_error_state.lower_write_calls = 0;
  client_session->sock.lfunc[COAP_LAYER_TLS].l_write =
      t_tls_lower_write_error_cb;
  mid = coap_session_send_ping(client_session);
  CU_ASSERT(mid == COAP_INVALID_MID);
  CU_ASSERT(tls_write_error_state.lower_write_calls > 0);
  CU_ASSERT(tls_write_error_state.client_dtls_closed_or_error == 1);
  coap_session_release(client_session);
  client_session = NULL;

finish:
  if (server_ctx)
    coap_free_context(server_ctx);
  if (client_ctx)
    coap_free_context(client_ctx);
}
#endif /* COAP_SERVER_SUPPORT && COAP_CLIENT_SUPPORT && COAP_IPV4_SUPPORT */

static int
t_tls_tests_create(void) {
  coap_startup();
  return 0;
}

CU_pSuite
t_init_tls_tests(void) {
  CU_pSuite suite;

  suite = CU_add_suite("TLS", t_tls_tests_create, NULL);
  if (!suite) {                        /* signal error */
    fprintf(stderr, "W: cannot add TLS test suite (%s)\n",
            CU_get_error_msg());

    return NULL;
  }

#define TLS_TEST(s,t)                                                      \
  if (!CU_ADD_TEST(s,t)) {                                              \
    fprintf(stderr, "W: cannot add TLS test (%s)\n",              \
            CU_get_error_msg());                                      \
  }

  TLS_TEST(suite, t_tls1);
  TLS_TEST(suite, t_tls2);
  TLS_TEST(suite, t_tls3);
#if COAP_SERVER_SUPPORT
  TLS_TEST(suite, t_tls4);
  TLS_TEST(suite, t_tls5);
#endif /* COAP_SERVER_SUPPORT */
  TLS_TEST(suite, t_tls6);
  TLS_TEST(suite, t_tls7);
  TLS_TEST(suite, t_tls8);
#if COAP_SERVER_SUPPORT
  TLS_TEST(suite, t_tls9);
#endif /* COAP_SERVER_SUPPORT */
#if COAP_SERVER_SUPPORT && COAP_IPV4_SUPPORT
  TLS_TEST(suite, t_tls10);
#endif /* COAP_SERVER_SUPPORT && COAP_IPV4_SUPPORT */
#if COAP_CLIENT_SUPPORT
  TLS_TEST(suite, t_tls11);
#endif /* COAP_CLIENT_SUPPORT */
#if COAP_OSCORE_SUPPORT
  TLS_TEST(suite, t_tls12);
  TLS_TEST(suite, t_tls13);
#endif /* COAP_OSCORE_SUPPORT */
#if COAP_WS_SUPPORT
  TLS_TEST(suite, t_tls14);
#endif /* COAP_WS_SUPPORT */
#if COAP_SERVER_SUPPORT && COAP_CLIENT_SUPPORT && !COAP_DISABLE_TCP && COAP_IPV4_SUPPORT
  TLS_TEST(suite, t_tls15);
#endif /* COAP_SERVER_SUPPORT && COAP_CLIENT_SUPPORT && !COAP_DISABLE_TCP && COAP_IPV4_SUPPORT */
#if COAP_SERVER_SUPPORT && COAP_CLIENT_SUPPORT && COAP_IPV4_SUPPORT
  TLS_TEST(suite, t_tls16);
#endif /* COAP_SERVER_SUPPORT && COAP_CLIENT_SUPPORT && COAP_IPV4_SUPPORT */

  return suite;
}
