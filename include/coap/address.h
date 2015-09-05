/* address.h -- representation of network addresses
 *
 * Copyright (C) 2010,2011,2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file address.h
 * @brief Representation of network addresses
 */

#ifndef _COAP_ADDRESS_H_
#define _COAP_ADDRESS_H_

#ifdef HAVE_ASSERT_H
#include <assert.h>
#else
#ifndef assert
#warning "assertions are disabled"
#  define assert(x)
#endif
#endif

#include <string.h>
#include <stdint.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <sys/socket.h>
#endif

#include "coap_address.h"

typedef struct coap_address_t coap_address_t;

/**
 * Compares given address objects @p a and @p b. This function returns @c 1 if
 * addresses are equal, @c 0 otherwise. The parameters @p a and @p b must not be
 * @c NULL;
 */
int coap_address_equals(const coap_address_t *a, const coap_address_t *b);

/**
 * Checks if given address object @p a denotes the wildcard address. This
 * function returns @c 1 if this is the case, @c 0 otherwise. The parameters @p
 * a must not be @c NULL;
 */
int coap_address_isany(const coap_address_t *a);

/**
 * Checks if given address @p a denotes a multicast address. This function
 * returns @c 1 if @p a is multicast, @c 0 otherwise.
 */
int coap_is_mcast(const coap_address_t *a);

/**
 * Resets the given coap_address_t object @p addr to its default values. In
 * particular, the member size must be initialized to the available size for
 * storing addresses.
 *
 * @param addr The coap_address_t object to initialize.
 */
void coap_address_init(coap_address_t *addr);

#endif /* _COAP_ADDRESS_H_ */
