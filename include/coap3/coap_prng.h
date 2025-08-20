/*
 * coap_prng.h -- Pseudo Random Numbers
 *
 * Copyright (C) 2010-2025 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_prng.h
 * @brief Pseudo Random Numbers
 */

#ifndef COAP_PRNG_H_
#define COAP_PRNG_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup application_api
 * @defgroup coap_prng Pseudo Random Numbers
 * API for generating pseudo random numbers
 * @{
 */

/**
 * Data type for random number generator function. The function must
 * fill @p len bytes of random data into the buffer starting at @p
 * out.  On success, the function should return 1, zero otherwise.
 */
typedef int (*coap_rand_func_t)(void *out, size_t len);

/**
 * Replaces the current random number generation function with the
 * default function @p rng.
 *
 * @param rng  The random number generation function to use.
 */
void coap_set_prng(coap_rand_func_t rng);

/**
 * Seeds the default random number generation function with the given
 * @p seed. The default random number generation function will use
 * getrandom() if available, ignoring the seed.
 *
 * @param seed  The seed for the pseudo random number generator.
 */
COAP_API void coap_prng_init(unsigned int seed);

/**
 * Fills @p buf with @p len random bytes using the default pseudo
 * random number generator. The default PRNG can be changed with
 * coap_set_prng(). This function returns 1 when @p len random bytes
 * have been written to @p buf, zero otherwise.
 *
 * @param buf  The buffer to fill with random bytes.
 * @param len  The number of random bytes to write into @p buf.
 *
 * @return 1 on success, 0 otherwise.
 */
COAP_API int coap_prng(void *buf, size_t len);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* COAP_PRNG_H_ */
