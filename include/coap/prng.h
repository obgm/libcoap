/*
 * prng.h -- Pseudo Random Numbers
 *
 * Copyright (C) 2010-2011,2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file prng.h
 * @brief Pseudo Random Numbers
 */

#ifndef _COAP_PRNG_H_
#define _COAP_PRNG_H_

#include <stddef.h>

/**
 * @defgroup prng Pseudo Random Numbers
 * @{
 */

/**
 * Fills \p buf with \p len random bytes. This is the default implementation for
 * prng(). You might want to change prng() to use a better PRNG on your specific
 * platform.
 */
int coap_prng(unsigned char *buf, size_t len);

/**
 * Called to set the PRNG seed. You may want to re-define this to allow for a
 * better PRNG.
 *
 * @param seed Seed for platform-specific PRNG.
 */
void coap_prng_init(void *seed);

/** @} */

#endif /* _COAP_PRNG_H_ */
