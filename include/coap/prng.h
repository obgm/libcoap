/* prng.h -- Pseudo Random Numbers
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file prng.h
 * @brief Pseudo Random Numbers
 */

#ifndef _COAP_PRNG_H_
#define _COAP_PRNG_H_

#include <string.h>

/**
 * @defgroup prng Pseudo Random Numbers
 * @{
 */

/**
 * Fills \p buf with \p len bytes of random data.
 *
 * @hideinitializer
 */
int prng(unsigned char *buf, size_t len);

/**
 * Called to set the PRNG seed. You may want to re-define this to allow for a
 * better PRNG.
 *
 * @hideinitializer
 */
void prng_init(unsigned long value);

/** @} */

#endif /* _COAP_PRNG_H_ */
