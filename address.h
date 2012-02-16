/* address.h -- representation of network addresses
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

/** 
 * @file address.h
 * @brief representation of network addresses
 */

#ifndef _COAP_ADDRESS_H_
#define _COAP_ADDRESS_H_

#include "config.h"

#ifdef HAVE_ASSERT_H
#include <assert.h>
#else
#ifndef assert
#warning "assertions are disabled"
#  define assert(x)
#endif
#endif

#include <string.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef WITH_CONTIKI
#include "uip.h"

typedef struct __coap_address_t {
  unsigned char size;
  uip_ipaddr_t addr;
  unsigned short port;
} __coap_address_t;

#define coap_address_t __coap_address_t

#define _coap_address_equals_impl(A,B)				\
  ((A)->size == (B)->size					\
    && (A)->port == (B)->port					\
   && uip_ipaddr_cmp((A),(B)))

#endif /* WITH_CONTIKI */

/** multi-purpose address abstraction */
#ifndef coap_address_t
typedef struct __coap_address_t {
  socklen_t size;		/**< size of addr */
  union {
    struct sockaddr     sa;
    struct sockaddr_storage st;
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;
  } addr;
} __coap_address_t;

#define coap_address_t __coap_address_t

/* FIXME: implement _coap_address_equals_impl(a, b);*/
#endif /* coap_address_t */

/** 
 * Resets the given coap_address_t object @p addr to its default
 * values.  In particular, the member size must be initialized to the
 * available size for storing addresses.
 * 
 * @param addr The coap_address_t object to initialize.
 */
static inline void
coap_address_init(coap_address_t *addr) {
  assert(addr);
  memset(addr, 0, sizeof(coap_address_t));
  addr->size = sizeof(addr->addr);
}

static inline int
coap_address_equals(const coap_address_t *a, const coap_address_t *b) {
  assert(a); assert(b);
  return _coap_address_equals_impl(a, b);
}

#endif /* _COAP_ADDRESS_H_ */
