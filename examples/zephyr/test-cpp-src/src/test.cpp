#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(coap_cpp_test, LOG_LEVEL_DBG);

#include <zephyr/kernel.h>
#include <errno.h>
#include "coap3/coap.h"
#include <stdio.h>

coap_str_const_t *xxx_libcoap_get_version() {
  coap_str_const_t *ver;

  ver = coap_make_str_const(LIBCOAP_PACKAGE_VERSION);
  printf("Version: %s\n", ver->s);
  return ver;
}

int main()
{
  xxx_libcoap_get_version();
  exit(0);
}
