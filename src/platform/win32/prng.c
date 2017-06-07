/*
 * prng.c -- Pseudo Random Numbers
 *
 * Copyright (C) 2010-2011,2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#define _CRT_RAND_S
#include <stdlib.h>
#include <stdint.h>

#include "prng.h"

int coap_prng( unsigned char *buf, size_t len ) {
	while ( len != 0 ) {
		uint32_t r = 0;
		size_t i;
		if ( rand_s( &r ) != 0 )
			return 0;
		for ( i = 0; i < len && i < 4; i++ ) {
			*buf++ = (uint8_t)r;
			r >>= 8;
		}
		len -= i;
	}
	return 1;
}

void coap_prng_init(void *value) {
}
