#include "coap3/coap_internal.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int i;

  if (size < 1)
    return 0;

  for (i = 0; i < 256; i++) {
    coap_binary_t *tag = get_asn1_tag(i, data, size, NULL);

    coap_delete_binary(tag);
  }

  return 0;
}
