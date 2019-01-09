/*
 * address.h -- representation of network addresses
 *
 * Copyright (C) 2010-2011,2015-2016,2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file address.h
 * @brief Representation of network addresses
 */

#ifndef COAP_ADDRESS_H_
#define COAP_ADDRESS_H_

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include "libcoap.h"

#if defined(WITH_LWIP)

#include <lwip/ip_addr.h>

typedef struct coap_address_t {
  uint16_t port;
  ip_addr_t addr;
} coap_address_t;

static inline int
coap_address_equals(const coap_address_t *a, const coap_address_t *b) {
  assert(a); assert(b);
  return (a->port == b->port) && (!!ip_addr_cmp(&a->addr,&b->addr));
}

static inline void
coap_address_copy(coap_address_t *dst, const coap_address_t *src) {
  memcpy(dst, src, sizeof(coap_address_t));
}

static inline int
coap_address_isany(const coap_address_t *a) {
  return a && ip_addr_isany(&a->addr);
}

static inline int
coap_is_mcast(const coap_address_t *a) {
  return a && ip_addr_ismulticast(&a->addr);
}
#elif defined(WITH_CONTIKI)

#include "uip.h"

typedef struct coap_address_t {
  uip_ipaddr_t addr;
  uint16_t port;
} coap_address_t;

static inline int
coap_address_equals(const coap_address_t *a, const coap_address_t *b) {
  return (a->port == b->port) && uip_ipaddr_cmp(&a->addr,&b->addr);
}

static inline void
coap_address_copy(coap_address_t *dst, const coap_address_t *src) {
  memcpy(dst, src, sizeof(coap_address_t));
}

/** @todo implementation of _coap_address_isany_impl() for Contiki */
static inline int
coap_address_isany(const coap_address_t *a) {
  return 0;
}

static inline int
coap_is_mcast(const coap_address_t *a) {
  return a && uip_is_addr_mcast(&a->addr);
}
#elif defined(RIOT_VERSION)
#include <net/ipv6/addr.h>

typedef struct coap_address_t {
  network_uint16_t port;
  ipv6_addr_t addr;
} coap_address_t;

static inline void coap_address_copy(coap_address_t *dst,
                                     const coap_address_t *src) {
  dst->port = src->port;
  dst->addr = src->addr;
}

static inline int coap_address_equals(coap_address_t *dst,
                                      const coap_address_t *src) {
  return (dst->port.u16 == src->port.u16)
    && ipv6_addr_equal(&dst->addr, &src->addr);
}

static inline int
coap_address_isany(const coap_address_t *a) {
  return ipv6_addr_is_unspecified(&a->addr);
}

static inline int
coap_is_mcast(const coap_address_t *a) {
  return ipv6_addr_is_multicast(&a->addr);
}
#else /* WITH_LWIP || WITH_CONTIKI || RIOT_VERSION */

 /** multi-purpose address abstraction */
typedef struct coap_address_t {
  socklen_t size;           /**< size of addr */
  union {
    struct sockaddr         sa;
    struct sockaddr_in      sin;
    struct sockaddr_in6     sin6;
  } addr;
} coap_address_t;

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
COAP_STATIC_INLINE int
coap_address_isany(const coap_address_t *a) {
  assert(a);
  /* need to compare only relevant parts of sockaddr_in6 */
  switch (a->addr.sa.sa_family) {
  case AF_INET:
    return a->addr.sin.sin_addr.s_addr == INADDR_ANY;
  case AF_INET6:
    return memcmp(&in6addr_any,
                  &a->addr.sin6.sin6_addr,
                  sizeof(in6addr_any)) == 0;
  default:
    ;
  }

  return 0;
}

/* Convenience function to copy IPv6 addresses without garbage. */

COAP_STATIC_INLINE void
coap_address_copy( coap_address_t *dst, const coap_address_t *src ) {
#if defined(WITH_LWIP) || defined(WITH_CONTIKI)
  memcpy( dst, src, sizeof( coap_address_t ) );
#else
  memset( dst, 0, sizeof( coap_address_t ) );
  dst->size = src->size;
  if ( src->addr.sa.sa_family == AF_INET6 ) {
    dst->addr.sin6.sin6_family = src->addr.sin6.sin6_family;
    dst->addr.sin6.sin6_addr = src->addr.sin6.sin6_addr;
    dst->addr.sin6.sin6_port = src->addr.sin6.sin6_port;
    dst->addr.sin6.sin6_scope_id = src->addr.sin6.sin6_scope_id;
  } else if ( src->addr.sa.sa_family == AF_INET ) {
    dst->addr.sin = src->addr.sin;
  } else {
    memcpy( &dst->addr, &src->addr, src->size );
  }
#endif
}

/**
 * Checks if given address @p a denotes a multicast address. This function
 * returns @c 1 if @p a is multicast, @c 0 otherwise.
 */
int coap_is_mcast(const coap_address_t *a);
#endif /* WITH_LWIP || WITH_CONTIKI || RIOT_VERSION */

/**
 * Resets the given coap_address_t object @p addr to its default values. In
 * particular, the member size must be initialized to the available size for
 * storing addresses.
 *
 * @param addr The coap_address_t object to initialize.
 */
COAP_STATIC_INLINE void
coap_address_init(coap_address_t *addr) {
  assert(addr);
  memset(addr, 0, sizeof(coap_address_t));
#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI) && !defined(RIOT_VERSION)
  /* lwip and Contiki have constant address sizes and doesn't need the .size part
   * RIOT support is IPv6-only for now.
   */
  addr->size = sizeof(addr->addr);
#endif
}

#endif /* COAP_ADDRESS_H_ */
