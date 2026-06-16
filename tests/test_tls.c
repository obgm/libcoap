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
#include <bsl/bsl_log.h>
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
  version.version = BSL_LOG_GetVersionNum();
  version.type = COAP_TLS_LIBRARY_OPENHITLS;
#else /* no DTLS */
  version.version = 0;
  version.type = COAP_TLS_LIBRARY_NOTLS;
#endif /* COAP_WITH_LIBOPENSSL || COAP_WITH_LIBTINYDTLS */

  ReturnIf_CU_ASSERT_PTR_NOT_NULL(v);
  CU_ASSERT(version.version == v->version);
  CU_ASSERT(version.type == v->type);
}

typedef struct {
  coap_tls_library_t type;
  int dtls;
  int tls;
  int psk;
  int pki;
  int pkcs11;
  int rpk;
  int cid;
} t_tls_support_t;

static t_tls_support_t
t_tls_expected_support(void) {
  t_tls_support_t support;

  memset(&support, 0, sizeof(support));
  support.type = COAP_TLS_LIBRARY_NOTLS;
#ifdef HAVE_DTLS
  support.dtls = 1;
#endif /* HAVE_DTLS */

#if defined(COAP_WITH_LIBOPENSSL)
  support.type = COAP_TLS_LIBRARY_OPENSSL;
  support.psk = 1;
  support.pki = 1;
  support.pkcs11 = 1;
  support.tls = !COAP_DISABLE_TCP;
#elif defined(COAP_WITH_LIBWOLFSSL)
  support.type = COAP_TLS_LIBRARY_WOLFSSL;
  support.psk = 1;
  support.pki = 1;
  support.tls = !COAP_DISABLE_TCP;
#ifdef WOLFSSL_DTLS_CID
  support.cid = 1;
#endif /* WOLFSSL_DTLS_CID */
#elif defined(COAP_WITH_LIBTINYDTLS)
  support.type = COAP_TLS_LIBRARY_TINYDTLS;
#ifdef DTLS_PSK
  support.psk = 1;
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
  support.rpk = 1;
#endif /* DTLS_ECC */
#if defined(DTLS_MAX_CID_LENGTH) && DTLS_MAX_CID_LENGTH > 0
  support.cid = 1;
#endif /* defined(DTLS_MAX_CID_LENGTH) && DTLS_MAX_CID_LENGTH > 0 */
#elif defined(COAP_WITH_LIBGNUTLS)
  support.type = COAP_TLS_LIBRARY_GNUTLS;
  support.psk = 1;
  support.pki = 1;
  support.pkcs11 = 1;
  support.tls = !COAP_DISABLE_TCP;
#if GNUTLS_VERSION_NUMBER >= 0x030606
  support.rpk = 1;
#endif /* GNUTLS_VERSION_NUMBER >= 0x030606 */
#elif defined(COAP_WITH_LIBMBEDTLS)
  support.type = COAP_TLS_LIBRARY_MBEDTLS;
  support.psk = 1;
  support.pki = 1;
  support.tls = !COAP_DISABLE_TCP;
#ifdef MBEDTLS_SSL_DTLS_CONNECTION_ID
  support.cid = 1;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
#elif defined(COAP_WITH_LIBOPENHITLS)
  support.type = COAP_TLS_LIBRARY_OPENHITLS;
  support.psk = 1;
  support.pki = 1;
  support.tls = !COAP_DISABLE_TCP;
#elif COAP_WITH_LIBMBEDTLS_OSCORE
  support.type = COAP_TLS_LIBRARY_MBEDTLS;
#elif COAP_WITH_LIBOPENHITLS_OSCORE
  support.type = COAP_TLS_LIBRARY_OPENHITLS;
#endif /* COAP_WITH_LIBOPENSSL */

  return support;
}

static void
t_tls3(void) {
  const coap_tls_version_t *v = coap_get_tls_library_version();
  t_tls_support_t support = t_tls_expected_support();

  ReturnIf_CU_ASSERT_PTR_NOT_NULL(v);
  CU_ASSERT(v->type == support.type);
  CU_ASSERT(coap_dtls_is_supported() == support.dtls);
  CU_ASSERT(coap_tls_is_supported() == support.tls);
  CU_ASSERT(coap_dtls_psk_is_supported() == support.psk);
  CU_ASSERT(coap_dtls_pki_is_supported() == support.pki);
  CU_ASSERT(coap_dtls_pkcs11_is_supported() == support.pkcs11);
  CU_ASSERT(coap_dtls_rpk_is_supported() == support.rpk);
  CU_ASSERT(coap_dtls_cid_is_supported() == support.cid);
}

static void
t_tls4(void) {
  char buffer[256];

  memset(buffer, 0, sizeof(buffer));
  CU_ASSERT_PTR_EQUAL(coap_string_tls_support(buffer, sizeof(buffer)), buffer);
  CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "DTLS"));
  CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "TLS"));
  if (coap_dtls_is_supported() || coap_tls_is_supported()) {
    CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "PSK"));
    CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "PKI"));
    CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "PKCS11"));
    CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "RPK"));
    CU_ASSERT_PTR_NOT_NULL(strstr(buffer, "CID"));
  }
}

#if COAP_SERVER_SUPPORT
static void
t_tls5(void) {
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
#endif /* COAP_SERVER_SUPPORT */

static void
t_tls6(void) {
  coap_context_t *ctx;
  coap_dtls_pki_t setup_data;

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
}

static void
t_tls7(void) {
  coap_context_t *ctx;
  int support = coap_dtls_cid_is_supported();

  CU_ASSERT(coap_context_set_cid_tuple_change(NULL, 1) == 0);

  ctx = coap_new_context(NULL);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(ctx);

  CU_ASSERT(coap_context_set_cid_tuple_change(ctx, 0) == support);
  CU_ASSERT(coap_context_set_cid_tuple_change(ctx, 1) == support);

  coap_free_context(ctx);
}

static void
t_tls8(void) {
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
t_tls9(void) {
  coap_tls_library_t tls_lib = COAP_TLS_LIBRARY_NOTLS;
  t_tls_support_t support = t_tls_expected_support();
  coap_tls_library_t expected_dtls_lib =
      support.dtls ? support.type : COAP_TLS_LIBRARY_NOTLS;

  CU_ASSERT_PTR_NULL(coap_session_get_tls(NULL, &tls_lib));
  CU_ASSERT(tls_lib == COAP_TLS_LIBRARY_NOTLS);
  CU_ASSERT_PTR_NULL(coap_dtls_get_tls(NULL, &tls_lib));
  CU_ASSERT(tls_lib == expected_dtls_lib);
}

#if COAP_SERVER_SUPPORT
static void
t_tls10(void) {
  static const uint8_t data[] = "digest input";
  coap_digest_ctx_t *digest_ctx;
  coap_digest_t digest;

  digest_ctx = coap_digest_setup();
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(digest_ctx);
  CU_ASSERT(coap_digest_update(digest_ctx, data, sizeof(data) - 1) == 1);
  CU_ASSERT(coap_digest_final(digest_ctx, &digest) == 1);
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_SERVER_SUPPORT && (defined(COAP_WITH_LIBOPENSSL) || defined(COAP_WITH_LIBOPENHITLS))
static void
t_tls_init_address(coap_address_t *addr, uint16_t port) {
  coap_address_init(addr);
  addr->addr.sin.sin_family = AF_INET;
  addr->addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr->size = sizeof(addr->addr.sin);
  coap_address_set_port(addr, port);
}
#endif /* COAP_SERVER_SUPPORT && (COAP_WITH_LIBOPENSSL || COAP_WITH_LIBOPENHITLS) */

#if defined(COAP_WITH_LIBOPENHITLS) && COAP_CLIENT_SUPPORT
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
#endif /* COAP_WITH_LIBOPENHITLS && COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT && (defined(COAP_WITH_LIBOPENSSL) || defined(COAP_WITH_LIBOPENHITLS))
static unsigned int tls_hello_write_count;
static size_t tls_hello_write_len;
static uint8_t tls_hello_write_data[512];

static void
t_tls_hello_write_reset(void) {
  tls_hello_write_count = 0;
  tls_hello_write_len = 0;
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
t_tls11(void) {
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
  int ret;

  if (!coap_dtls_is_supported() || !coap_dtls_psk_is_supported())
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
  CU_ASSERT(ret == 0);
  CU_ASSERT(tls_hello_write_count == 1);
  CU_ASSERT(tls_hello_write_len > 0);
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
  coap_free_type(COAP_SESSION, session);
  coap_free_context(ctx);
}
#endif /* COAP_SERVER_SUPPORT && (COAP_WITH_LIBOPENSSL || COAP_WITH_LIBOPENHITLS) */

#if defined(COAP_WITH_LIBOPENHITLS) && COAP_CLIENT_SUPPORT
static coap_context_t *
t_tls_new_pki_context(const coap_dtls_pki_t *setup_data) {
  coap_context_t *ctx = coap_new_context(NULL);

  CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);
  CU_ASSERT(coap_context_set_pki(ctx, setup_data) == 1);
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
  if (expect_tls > 0) {
    CU_ASSERT_PTR_NOT_NULL(tls);
  } else if (expect_tls == 0) {
    CU_ASSERT_PTR_NULL(tls);
  }
  t_tls_free_test_session(session);
  coap_free_context(ctx);
}

static void
t_tls12(void) {
  static const uint8_t bad_pem[] = "not a pem certificate";
  static const uint8_t bad_der[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
  coap_dtls_pki_t setup_data;

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

  setup_data.pki_key.key.define.ca.u_byte = bad_pem;
  setup_data.pki_key.key.define.ca_len = sizeof(bad_pem);
  setup_data.pki_key.key.define.ca_def = COAP_PKI_KEY_DEF_PEM_BUF;
  setup_data.pki_key.key.define.public_cert.u_byte = NULL;
  setup_data.pki_key.key.define.public_cert_len = 0;
  setup_data.pki_key.key.define.public_cert_def = COAP_PKI_KEY_DEF_PEM_BUF;
  setup_data.pki_key.key.define.private_key.u_byte = NULL;
  setup_data.pki_key.key.define.private_key_len = 0;
  setup_data.pki_key.key.define.private_key_def = COAP_PKI_KEY_DEF_PEM_BUF;
  t_tls_expect_pki_client_result(&setup_data, 0);

  setup_data.pki_key.key.define.ca.u_byte = NULL;
  setup_data.pki_key.key.define.ca_len = 0;
  setup_data.pki_key.key.define.public_cert.u_byte = bad_pem;
  setup_data.pki_key.key.define.public_cert_len = sizeof(bad_pem);
  t_tls_expect_pki_client_result(&setup_data, 0);

  setup_data.pki_key.key.define.public_cert.u_byte = NULL;
  setup_data.pki_key.key.define.public_cert_len = 0;
  setup_data.pki_key.key.define.private_key.u_byte = bad_pem;
  setup_data.pki_key.key.define.private_key_len = sizeof(bad_pem);
  t_tls_expect_pki_client_result(&setup_data, 0);

  setup_data.pki_key.key.define.private_key.u_byte = NULL;
  setup_data.pki_key.key.define.private_key_len = 0;
  setup_data.pki_key.key.define.ca.u_byte = bad_der;
  setup_data.pki_key.key.define.ca_len = sizeof(bad_der);
  setup_data.pki_key.key.define.ca_def = COAP_PKI_KEY_DEF_DER_BUF;
  setup_data.pki_key.key.define.public_cert_def = COAP_PKI_KEY_DEF_DER_BUF;
  setup_data.pki_key.key.define.private_key_def = COAP_PKI_KEY_DEF_DER_BUF;
  t_tls_expect_pki_client_result(&setup_data, 0);
}
#endif /* COAP_WITH_LIBOPENHITLS && COAP_CLIENT_SUPPORT */

#if defined(COAP_WITH_LIBOPENHITLS) && COAP_CLIENT_SUPPORT
static int tls_security_setup_called;
static int tls_security_setup_result;

static int
t_tls_security_setup_cb(void *tls_session, coap_dtls_pki_t *setup_data) {
  CU_ASSERT_PTR_NOT_NULL(tls_session);
  CU_ASSERT_PTR_NOT_NULL(setup_data);
  tls_security_setup_called++;
  return tls_security_setup_result;
}
#endif /* COAP_WITH_LIBOPENHITLS && COAP_CLIENT_SUPPORT */

#if defined(COAP_WITH_LIBOPENHITLS) && COAP_CLIENT_SUPPORT
static void
t_tls13(void) {
  coap_context_t *ctx;
  coap_session_t *session;
  coap_dtls_pki_t setup_data;
  void *tls;

  if (!coap_dtls_pki_is_supported())
    return;

  ctx = coap_new_context(NULL);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(ctx);

  memset(&setup_data, 0, sizeof(setup_data));
  setup_data.version = COAP_DTLS_PKI_SETUP_VERSION;
  setup_data.verify_peer_cert = 0;
  setup_data.pki_key.key_type = COAP_PKI_KEY_PEM;
  setup_data.additional_tls_setup_call_back = t_tls_security_setup_cb;
  CU_ASSERT(coap_context_set_pki(ctx, &setup_data) == 1);

  session = t_tls_new_test_session(ctx, COAP_PROTO_DTLS);
  if (!session) {
    CU_ASSERT_PTR_NOT_NULL(session);
    coap_free_context(ctx);
    return;
  }

  tls_security_setup_called = 0;
  tls_security_setup_result = 1;
  tls = coap_dtls_new_client_session(session);
  CU_ASSERT_PTR_NOT_NULL(tls);
  CU_ASSERT(tls_security_setup_called == 1);
  t_tls_free_test_session(session);

  session = t_tls_new_test_session(ctx, COAP_PROTO_DTLS);
  if (!session) {
    CU_ASSERT_PTR_NOT_NULL(session);
    coap_free_context(ctx);
    return;
  }

  tls_security_setup_called = 0;
  tls_security_setup_result = 0;
  tls = coap_dtls_new_client_session(session);
  CU_ASSERT_PTR_NULL(tls);
  CU_ASSERT(tls_security_setup_called == 1);

  t_tls_free_test_session(session);
  coap_free_context(ctx);
}
#endif /* COAP_WITH_LIBOPENHITLS && COAP_CLIENT_SUPPORT */

#if COAP_OSCORE_SUPPORT
static void
t_tls14(void) {
  if (!coap_oscore_is_supported())
    return;

  CU_ASSERT(coap_crypto_check_cipher_alg(COSE_ALGORITHM_AES_CCM_16_64_128) != 0);
  CU_ASSERT(coap_crypto_check_cipher_alg(COSE_ALGORITHM_AES_CCM_64_64_128) == 0);
  CU_ASSERT(coap_crypto_check_cipher_alg((cose_alg_t)0) == 0);
  CU_ASSERT(coap_crypto_check_hkdf_alg(COSE_HKDF_ALG_HKDF_SHA_256) != 0);
  CU_ASSERT(coap_crypto_check_hkdf_alg((cose_hkdf_alg_t)0) == 0);
}

static void
t_tls15(void) {
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
}
#endif /* COAP_OSCORE_SUPPORT */

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
  TLS_TEST(suite, t_tls4);
#if COAP_SERVER_SUPPORT
  TLS_TEST(suite, t_tls5);
#endif /* COAP_SERVER_SUPPORT */
  TLS_TEST(suite, t_tls6);
  TLS_TEST(suite, t_tls7);
  TLS_TEST(suite, t_tls8);
  TLS_TEST(suite, t_tls9);
#if COAP_SERVER_SUPPORT
  TLS_TEST(suite, t_tls10);
#endif /* COAP_SERVER_SUPPORT */
#if COAP_SERVER_SUPPORT && (defined(COAP_WITH_LIBOPENSSL) || defined(COAP_WITH_LIBOPENHITLS))
  TLS_TEST(suite, t_tls11);
#endif /* COAP_SERVER_SUPPORT && (COAP_WITH_LIBOPENSSL || COAP_WITH_LIBOPENHITLS) */
#if defined(COAP_WITH_LIBOPENHITLS) && COAP_CLIENT_SUPPORT
  TLS_TEST(suite, t_tls12);
  TLS_TEST(suite, t_tls13);
#endif /* COAP_WITH_LIBOPENHITLS && COAP_CLIENT_SUPPORT */
#if COAP_OSCORE_SUPPORT
  TLS_TEST(suite, t_tls14);
  TLS_TEST(suite, t_tls15);
#endif /* COAP_OSCORE_SUPPORT */

  return suite;
}
