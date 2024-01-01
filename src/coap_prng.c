/*
 * coap_prng.c -- random number generation
 *
 * Copyright (C) 2020-2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README
 * for terms of use.
 */

/**
 * @file coap_prng.c
 * @brief Pseudo Random Number functions
 */

#include "coap3/coap_internal.h"

#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#elif defined(WITH_CONTIKI)
#include "lib/csprng.h"
#else /* !WITH_CONTIKI */
#include <stdlib.h>
#endif /* !WITH_CONTIKI */

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
#include <entropy_poll.h>
#endif /* MBEDTLS_ENTROPY_HARDWARE_ALT */

#if defined(_WIN32)

errno_t __cdecl rand_s(_Out_ unsigned int *_RandomValue);
/**
 * Fills \p buf with \p len random bytes. This is the default implementation for
 * coap_prng(). You might want to change coap_prng_impl() to use a better
 * PRNG on your specific platform.
 */
COAP_STATIC_INLINE int
coap_prng_impl(unsigned char *buf, size_t len) {
  while (len != 0) {
    uint32_t r = 0;
    size_t i;

    if (rand_s(&r) != 0)
      return 0;
    for (i = 0; i < len && i < 4; i++) {
      *buf++ = (uint8_t)r;
      r >>= 8;
    }
    len -= i;
  }
  return 1;
}

#endif /* _WIN32 */

/*
 * This, or any user provided alternative, function is expected to
 * return 0 on failure and 1 on success.
 */
static int
coap_prng_default(void *buf, size_t len) {
#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
  /* mbedtls_hardware_poll() returns 0 on success */
  return (mbedtls_hardware_poll(NULL, buf, len, NULL) ? 0 : 1);

#elif defined(HAVE_GETRANDOM)
  return (getrandom(buf, len, 0) > 0) ? 1 : 0;

#elif defined(HAVE_RANDOM)
#define RAND_BYTES (RAND_MAX >= 0xffffff ? 3 : (RAND_MAX >= 0xffff ? 2 : 1))
  unsigned char *dst = (unsigned char *)buf;

  if (len) {
    uint8_t byte_counter = RAND_BYTES;
    uint32_t r_v = random();

    while (1) {
      *dst++ = r_v & 0xFF;
      if (!--len) {
        break;
      }
      if (--byte_counter) {
        r_v >>= 8;
      } else {
        r_v = random();
        byte_counter = RAND_BYTES;
      }
    }
  }
  return 1;
#elif defined(RIOT_VERSION)
#include <random.h>
  random_bytes(buf, len);
  return 1;

#elif defined(WITH_CONTIKI)
  return csprng_rand(buf, len);

#elif defined(_WIN32)
  return coap_prng_impl(buf,len);

#else /* !MBEDTLS_ENTROPY_HARDWARE_ALT && !HAVE_GETRANDOM &&
         !HAVE_RANDOM && !_WIN32 */
#error "CVE-2021-34430: using rand() for crypto randoms is not secure!"
#error "Please update you C-library and rerun the auto-configuration."
  unsigned char *dst = (unsigned char *)buf;
  while (len--)
    *dst++ = rand() & 0xFF;
  return 1;
#endif /* !MBEDTLS_ENTROPY_HARDWARE_ALT && !HAVE_GETRANDOM &&
          !HAVE_RANDOM && !_WIN32 */
}

static coap_rand_func_t rand_func = coap_prng_default;

#if defined(WITH_LWIP) && defined(LWIP_RAND)

#else

void
coap_set_prng(coap_rand_func_t rng) {
  rand_func = rng;
}

void
coap_prng_init(unsigned int seed) {
#ifdef HAVE_GETRANDOM
  /* No seed to seed the random source if getrandom() is used */
  (void)seed;
#elif defined(HAVE_RANDOM)
  srandom(seed);
#else /* !HAVE_GETRANDOM  && !HAVE_RANDOM */
  srand(seed);
#endif /* !HAVE_GETRANDOM */
}

int
coap_prng(void *buf, size_t len) {
  if (!rand_func) {
    return 0;
  }

  return rand_func(buf, len);
}

#endif
