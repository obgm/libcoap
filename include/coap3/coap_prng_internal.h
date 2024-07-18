/*
 * coap_prng_internal.h -- Pseudo Random Numbers
 *
 * Copyright (C) 2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_prng_internal.h
 * @brief Internal Pseudo Random Numbers
 */

#ifndef COAP_PRNG_INTERNAL_H_
#define COAP_PRNG_INTERNAL_H_

/**
 * @ingroup internal_api
 * @defgroup coap_prng_internal Pseudo Random Numbers
 * Internal API for generating pseudo random numbers
 * @{
 */

/**
 * Seeds the default random number generation function with the given
 * @p seed. The default random number generation function will use
 * getrandom() if available, ignoring the seed.
 *
 * @param seed  The seed for the pseudo random number generator.
 */
void coap_prng_init_lkd(unsigned int seed);

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
int coap_prng_lkd(void *buf, size_t len);

/** @} */

#endif /* COAP_PRNG_H_ */
