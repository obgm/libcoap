/*
 * prng.c -- Pseudo Random Numbers
 *
 * Copyright (C) 2010-2011,2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include <stdlib.h>
#include <stdint.h>

#include "prng.h"

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
