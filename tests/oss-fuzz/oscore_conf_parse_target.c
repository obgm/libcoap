#include "coap3/coap_internal.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  coap_oscore_conf_t *oscore_conf;
  coap_str_const_t conf_mem;
  cose_encrypt0_t cose[1];
  uint8_t *buf;

  if (size < 1)
    return 0;

  /* Initialize libcoap */
  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);

  /* The coap_new_oscore_conf() API expects null-terminated input data. */
  buf = (uint8_t *)malloc(size + 1);
  if (buf == NULL) {
    coap_cleanup();
    return 0;
  }
  memcpy(buf, data, size);
  buf[size] = '\0';

  /* Initialisation */
  conf_mem.s = buf;
  conf_mem.length = size + 1;

  /* Attempt to parse the fuzzer input as OSCORE configuration */
  oscore_conf = coap_new_oscore_conf(conf_mem, NULL, NULL, 0);

  /* Clean up if parsing succeeded */
  if (oscore_conf) {
    coap_delete_oscore_conf(oscore_conf);
  }

  free(buf);

  /* Attempt to decode OSCORE option value */
  cose_encrypt0_init(cose);
  oscore_decode_option_value(data, size, cose);

  coap_cleanup();
  return 0;
}
