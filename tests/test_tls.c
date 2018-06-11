/* libcoap unit tests
 *
 * Copyright (C) 2018 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"
#include "test_tls.h"

#include <coap.h>

#undef HAVE_DTLS

#ifdef HAVE_LIBTINYDTLS
#define HAVE_DTLS 1

#include <tinydtls.h>
#include <dtls.h>
#endif /* HAVE_LIBTINYDTLS */

#ifdef HAVE_OPENSSL
#define HAVE_DTLS 1
#include <openssl/ssl.h>
#endif /* HAVE_OPENSSL */

#ifdef HAVE_GNUTLS
#define HAVE_DTLS 1
#include <gnutls/gnutls.h>
#endif /* HAVE_GNUTLS */

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

#if defined(HAVE_OPENSSL)
  version.version = SSLeay();
  version.type = COAP_TLS_LIBRARY_OPENSSL;
#elif defined(HAVE_LIBTINYDTLS)
  version.version = DTLS_VERSION;
  version.type = COAP_TLS_LIBRARY_TINYDTLS;
#elif defined(HAVE_GNUTLS)
  version.version = GNUTLS_VERSION_NUMBER;
  version.type = COAP_TLS_LIBRARY_GNUTLS;
#else /* no DTLS */
  version.version = 0;
  version.type = COAP_TLS_LIBRARY_NOTLS;
#endif /* HAVE_OPENSSL || HAVE_LIBTINYDTLS */

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
  if (!suite) {			/* signal error */
    fprintf(stderr, "W: cannot add TLS test suite (%s)\n",
	    CU_get_error_msg());

    return NULL;
  }

#define TLS_TEST(s,t)						      \
  if (!CU_ADD_TEST(s,t)) {					      \
    fprintf(stderr, "W: cannot add TLS test (%s)\n",	      \
	    CU_get_error_msg());				      \
  }

  TLS_TEST(suite, t_tls1);
  TLS_TEST(suite, t_tls2);

  return suite;
}

