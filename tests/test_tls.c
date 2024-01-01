/* libcoap unit tests
 *
 * Copyright (C) 2018,2022-2024 Olaf Bergmann <bergmann@tzi.org>
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

#ifdef COAP_WITH_LIBGNUTLS
#define HAVE_DTLS 1
#include <gnutls/gnutls.h>
#endif /* COAP_WITH_LIBGNUTLS */

#ifdef COAP_WITH_LIBMBEDTLS
#define HAVE_DTLS 1
#include <mbedtls/version.h>
#endif /* COAP_WITH_LIBMBEDTLS */

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
#elif defined(COAP_WITH_LIBMBEDTLS)
  version.version = MBEDTLS_VERSION_NUMBER;
  version.type = COAP_TLS_LIBRARY_MBEDTLS;
#else /* no DTLS */
  version.version = 0;
  version.type = COAP_TLS_LIBRARY_NOTLS;
#endif /* COAP_WITH_LIBOPENSSL || COAP_WITH_LIBTINYDTLS */

  CU_ASSERT_PTR_NOT_NULL_FATAL(v);
  CU_ASSERT(version.version == v->version);
  CU_ASSERT(version.type == v->type);
}

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

  return suite;
}
