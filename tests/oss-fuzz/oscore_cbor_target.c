/* OSCORE CBOR fuzzer for libcoap.
 *
 * Drives the CBOR reader in src/oscore/oscore_cbor.c, which decodes OSCORE
 * material from untrusted sources: the persisted observe/OSCORE association
 * blob parsed in coap_subscribe.c and the kid_context of the OSCORE option
 * parsed in coap_oscore.c.
 *
 * Fuzzer bytes are walked as a stream of CBOR elements the same way those
 * consumers do -- peek the major type, then dispatch to the matching bounded
 * getter. This harness drives:
 *   - oscore_cbor_get_next_element     (major type)
 *   - oscore_cbor_get_element_size     (size / multi-byte length decoding)
 *   - oscore_cbor_get_number / _get_unsigned_integer / _get_negative_integer
 *   - oscore_cbor_get_simple_value
 *   - oscore_cbor_elem_contained
 *   - oscore_cbor_get_string_array / _get_string / _get_array
 *
 * The oscore_cbor_skip_value()/oscore_cbor_strip_value() pair is deliberately
 * not driven: their assert()s abort on truncated input under the
 * assert-enabled build.
 */

#include "coap3/coap_internal.h"

#include <stdint.h>
#include <stdlib.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
#if COAP_OSCORE_SUPPORT
  if (size == 0)
    return 0;

  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);

  /* Work on a private, non-const copy: the real callers decode CBOR out of
   * mutable buffers (oscore_association info / OSCORE option value), and it
   * keeps the cursor types identical to the decoder API (uint8_t *). */
  uint8_t *buf = (uint8_t *)malloc(size);
  if (buf == NULL) {
    coap_cleanup();
    return 0;
  }
  memcpy(buf, data, size);

  const uint8_t *p = buf;
  size_t len = size;
  uint8_t *const end = buf + size;
  int guard = 0;

  /* Walk the input as a stream of CBOR elements, mirroring the decode loops in
   * coap_subscribe.c / coap_oscore.c. The guard bounds the work per input. */
  while (len > 0 && guard++ < 4096) {
    const uint8_t *const p_before = p;
    const size_t len_before = len;

    /* Peek the major type (does not consume). */
    uint8_t type = oscore_cbor_get_next_element(&p, &len);

    switch (type) {
    case CBOR_UNSIGNED_INTEGER:
    case CBOR_NEGATIVE_INTEGER: {
      int64_t value = 0;
      oscore_cbor_get_number(&p, &len, &value);
      break;
    }

    case CBOR_SIMPLE_VALUE: {
      uint8_t value = 0;
      oscore_cbor_get_simple_value(&p, &len, &value);
      break;
    }

    case CBOR_BYTE_STRING:
    case CBOR_TEXT_STRING: {
      /* Exercise the containment check the same way callers guard a string
       * before reading it (uses a private copy of the length cursor). */
      size_t probe_len = len;
      oscore_cbor_elem_contained(p, &probe_len, end);

      /* Safe extraction: get_string_array() bounds *len against the remaining
       * buffer, allocates, and copies via get_string()/get_array(). */
      uint8_t *result = NULL;
      size_t result_len = 0;
      if (oscore_cbor_get_string_array(&p, &len, &result, &result_len) == 0)
        coap_free_type(COAP_STRING, result);
      break;
    }

    case CBOR_ARRAY:
    case CBOR_MAP:
    case CBOR_TAG:
    default:
      /* Consume the element header (count for array/map, value for tag,
       * multi-byte length decoding for large size fields). */
      (void)oscore_cbor_get_element_size(&p, &len);
      break;
    }

    /* Guarantee forward progress: if a decoder refused the element without
     * consuming anything, drop one byte so the loop always terminates. */
    if (p == p_before && len == len_before) {
      p++;
      len--;
    }
  }

  free(buf);
  coap_cleanup();
#else
  (void)data;
  (void)size;
#endif /* COAP_OSCORE_SUPPORT */
  return 0;
}
