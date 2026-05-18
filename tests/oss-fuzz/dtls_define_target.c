/* libFuzzer harness for libcoap's (D)TLS key-type / define mapping
 * (coap_dtls.c).
 *
 * coap_dtls_map_key_type_to_define() is reached when the application hands
 * libcoap a coap_dtls_pki_t setup blob and walks every key_type variant
 * (PEM / ASN1 / PEM_BUF / PKCS11 / DEFINE), each with their own subfields.
 * coap_dtls_define_issue() then formats a diagnostic for every
 * type+fail+role combination. None of the existing harnesses drive this
 * matrix.
 */

#include "coap3/coap_internal.h"
#include "coap3/coap.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static const coap_pki_key_t k_key_types[] = {
  COAP_PKI_KEY_PEM,
  COAP_PKI_KEY_ASN1,
  COAP_PKI_KEY_PEM_BUF,
  COAP_PKI_KEY_PKCS11,
  COAP_PKI_KEY_DEFINE,
};
#define K_KEY_TYPE_N (sizeof(k_key_types) / sizeof(k_key_types[0]))

static const coap_define_issue_key_t k_issue_keys[] = {
  COAP_DEFINE_KEY_CA,
  COAP_DEFINE_KEY_ROOT_CA,
  COAP_DEFINE_KEY_PUBLIC,
  COAP_DEFINE_KEY_PRIVATE,
};

static const coap_define_issue_fail_t k_issue_fails[] = {
  COAP_DEFINE_FAIL_BAD,
  COAP_DEFINE_FAIL_NOT_SUPPORTED,
  COAP_DEFINE_FAIL_NONE,
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4 || size > 1024)
    return 0;

  /* Build a NUL-terminated string copy of the fuzz buffer so we can use it
   * as PEM/PKCS11 path strings without overrunning. */
  char strbuf[256];
  size_t slen = size < sizeof(strbuf) - 1 ? size : sizeof(strbuf) - 1;
  memcpy(strbuf, data, slen);
  strbuf[slen] = '\0';

  /* Stop unnecessary logging output */
  coap_set_log_level(COAP_LOG_EMERG);

  /* The PKCS11 branch does strncasecmp(name, "pkcs11:", 7); about a quarter
   * of the time we want that string to actually match. */
  char pkcs11_str[sizeof(strbuf) + 8];
  snprintf(pkcs11_str, sizeof(pkcs11_str), "pkcs11:%s", strbuf);

  for (size_t i = 0; i < K_KEY_TYPE_N; i++) {
    coap_dtls_pki_t setup;
    memset(&setup, 0, sizeof(setup));
    setup.version = COAP_DTLS_PKI_SETUP_VERSION;
    setup.is_rpk_not_cert = (data[0] >> i) & 1;
    setup.pki_key.key_type = k_key_types[i];

    switch (k_key_types[i]) {
    case COAP_PKI_KEY_PEM:
      setup.pki_key.key.pem.ca_file = strbuf;
      setup.pki_key.key.pem.public_cert = strbuf;
      setup.pki_key.key.pem.private_key = strbuf;
      break;
    case COAP_PKI_KEY_ASN1:
      setup.pki_key.key.asn1.ca_cert = data;
      setup.pki_key.key.asn1.public_cert = data;
      setup.pki_key.key.asn1.private_key = data;
      setup.pki_key.key.asn1.ca_cert_len = size;
      setup.pki_key.key.asn1.public_cert_len = size;
      setup.pki_key.key.asn1.private_key_len = size;
      setup.pki_key.key.asn1.private_key_type =
          (coap_asn1_privatekey_type_t)(data[1] & 0x0f);
      break;
    case COAP_PKI_KEY_PEM_BUF:
      setup.pki_key.key.pem_buf.ca_cert = data;
      setup.pki_key.key.pem_buf.public_cert = data;
      setup.pki_key.key.pem_buf.private_key = data;
      setup.pki_key.key.pem_buf.ca_cert_len = size;
      setup.pki_key.key.pem_buf.public_cert_len = size;
      setup.pki_key.key.pem_buf.private_key_len = size;
      break;
    case COAP_PKI_KEY_PKCS11: {
      const char *which = (data[1] & 1) ? pkcs11_str : strbuf;
      setup.pki_key.key.pkcs11.ca = which;
      setup.pki_key.key.pkcs11.public_cert = which;
      setup.pki_key.key.pkcs11.private_key = which;
      setup.pki_key.key.pkcs11.user_pin = strbuf;
      break;
    }
    case COAP_PKI_KEY_DEFINE:
      setup.pki_key.key.define.ca.s_byte = strbuf;
      setup.pki_key.key.define.public_cert.s_byte = strbuf;
      setup.pki_key.key.define.private_key.s_byte = strbuf;
      setup.pki_key.key.define.ca_def = (coap_pki_define_t)(data[2] & 0x0f);
      setup.pki_key.key.define.public_cert_def =
          (coap_pki_define_t)(data[2] & 0x0f);
      setup.pki_key.key.define.private_key_def =
          (coap_pki_define_t)(data[2] & 0x0f);
      break;
    default:
      break;
    }

    coap_dtls_key_t mapped;
    memset(&mapped, 0, sizeof(mapped));
    coap_dtls_map_key_type_to_define(&setup, &mapped);

    /* Now exercise the diagnostic formatter over the full type x fail x
     * role matrix using the mapped key. */
    for (size_t t = 0; t < sizeof(k_issue_keys) / sizeof(k_issue_keys[0]);
         t++) {
      for (size_t f = 0;
           f < sizeof(k_issue_fails) / sizeof(k_issue_fails[0]); f++) {
        coap_dtls_define_issue(k_issue_keys[t], k_issue_fails[f], &mapped,
                               COAP_DTLS_ROLE_SERVER, 0);
        coap_dtls_define_issue(k_issue_keys[t], k_issue_fails[f], &mapped,
                               COAP_DTLS_ROLE_CLIENT, 0);
      }
    }
  }
  return 0;
}
