/*
 * prng.c -- Pseudo Random Numbers
 *
 * Copyright (C) 2010-2011,2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include "prng.h"

#ifdef LWIP_RAND
int
coap_prng(unsigned char *buf, size_t len) {
  u32_t v = LWIP_RAND();
  while (len > sizeof(v)) {
    memcpy(buf, &v, sizeof(v));
    len -= sizeof(v);
    buf += sizeof(v);
    v = LWIP_RAND();
  }

  memcpy(buf, &v, len);
  return 1;
}

void
coap_prng_init(void *value) {
}
#else /* LWIP_RAND */
#include <stdlib.h>
#include <stdint.h>

int
coap_prng(unsigned char *buf, size_t len) {
  while (len--)
    *buf++ = rand() & 0xFF;
  return 1;
}

void
coap_prng_init(void *value) {
  srand((intptr_t)value);  
}
#endif /* LWIP_RAND */
