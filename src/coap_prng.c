/*
 * coap_prng.c -- random number generation
 *
 * Copyright (C) 2020 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README
 * for terms of use.
 */

#include "coap_internal.h"

#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#else /* !HAVE_GETRANDOM */
#include <stdlib.h>
#endif /* !HAVE_GETRANDOM */

static int
coap_prng_default(void *buf, size_t len) {
#ifdef HAVE_GETRANDOM
  return getrandom(buf, len, 0);
#else /* !HAVE_GETRANDOM */
  unsigned char *dst = (unsigned char *)buf;
  while (len--)
    *dst++ = rand() & 0xFF;
  return 1;
#endif /* !HAVE_GETRANDOM */
}

static coap_rand_func_t rand_func = coap_prng_default;

void
coap_set_prng(coap_rand_func_t rng) {
  rand_func = rng;
}

void
coap_prng_init(unsigned long seed) {
#ifdef HAVE_GETRANDOM
  /* No seed to seed the random source if getrandom() is used,
   * see dtls_prng(). */
  (void)seed;
#else /* !HAVE_GETRANDOM */
  srand(seed);
#endif /* !HAVE_GETRANDOM */
}

int
coap_prng(void *buf, size_t len) {
  if (!rand_func) {
    return 0;
  }

  rand_func(buf, len);
  return 1;
}
