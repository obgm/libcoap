/*
 * coap_address.h -- representation of network addresses
 *
 * Copyright (C) 2010-2011,2015-2016,2022-2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_address.h
 * @brief Representation of network addresses
 */

#ifndef COAP_ADDRESS_H_
#define COAP_ADDRESS_H_

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include "libcoap.h"

#include "coap3/coap_pdu.h"

#if defined(WITH_LWIP)

#include <lwip/ip_addr.h>

struct coap_address_t {
  uint16_t port;
  ip_addr_t addr;
};

/**
 * Returns the port from @p addr in host byte order.
 */
COAP_STATIC_INLINE uint16_t
coap_address_get_port(const coap_address_t *addr) {
  return addr->port;
}

/**
 * Sets the port field of @p addr to @p port (in host byte order).
 */
COAP_STATIC_INLINE void
coap_address_set_port(coap_address_t *addr, uint16_t port) {
  addr->port = port;
}

#define _coap_address_equals_impl(A, B) \
  ((A)->port == (B)->port &&        \
   (!!ip_addr_cmp(&(A)->addr,&(B)->addr)))

#define _coap_address_isany_impl(A)  ip_addr_isany(&(A)->addr)

#define _coap_is_mcast_impl(Address) ip_addr_ismulticast(&(Address)->addr)

#elif defined(WITH_CONTIKI)

#include "uip.h"

struct coap_address_t {
  uip_ipaddr_t addr;
  uint16_t port;
};

/**
 * Returns the port from @p addr in host byte order.
 */
COAP_STATIC_INLINE uint16_t
coap_address_get_port(const coap_address_t *addr) {
  return uip_ntohs(addr->port);
}

/**
 * Sets the port field of @p addr to @p port (in host byte order).
 */
COAP_STATIC_INLINE void
coap_address_set_port(coap_address_t *addr, uint16_t port) {
  addr->port = uip_htons(port);
}

#define _coap_address_equals_impl(A,B) \
  ((A)->port == (B)->port &&     \
   uip_ipaddr_cmp(&((A)->addr),&((B)->addr)))

/** @todo implementation of _coap_address_isany_impl() for Contiki */
#define _coap_address_isany_impl(A)  0

#define _coap_is_mcast_impl(Address) uip_is_addr_mcast(&((Address)->addr))

#else /* ! WITH_LWIP && ! WITH_CONTIKI */

#ifdef _WIN32
#define sa_family_t short
#endif /* _WIN32 */

#define COAP_UNIX_PATH_MAX   (sizeof(struct sockaddr_in6) - sizeof(sa_family_t))

struct coap_sockaddr_un {
  sa_family_t sun_family; /* AF_UNIX */
  char sun_path[COAP_UNIX_PATH_MAX];   /* pathname max 26 with NUL byte */
};

/** Multi-purpose address abstraction */
struct coap_address_t {
  socklen_t size;           /**< size of addr */
  union {
    struct sockaddr         sa;
    struct sockaddr_in      sin;
    struct sockaddr_in6     sin6;
    struct coap_sockaddr_un cun; /* CoAP shortened special */
  } addr;
};

/**
 * Returns the port from @p addr in host byte order.
 */
uint16_t coap_address_get_port(const coap_address_t *addr);

/**
 * Set the port field of @p addr to @p port (in host byte order).
 */
void coap_address_set_port(coap_address_t *addr, uint16_t port);

/**
 * Compares given address objects @p a and @p b. This function returns @c 1 if
 * addresses are equal, @c 0 otherwise. The parameters @p a and @p b must not be
 * @c NULL;
 */
int coap_address_equals(const coap_address_t *a, const coap_address_t *b);

int _coap_address_isany_impl(const coap_address_t *a);
#endif /* ! WITH_LWIP && ! WITH_CONTIKI */

/** Resolved addresses information */
typedef struct coap_addr_info_t {
  struct coap_addr_info_t *next; /**< Next entry in the chain */
  coap_uri_scheme_t scheme;      /**< CoAP scheme to use */
  coap_proto_t proto;            /**< CoAP protocol to use */
  coap_address_t addr;           /**< The address to connect / bind to */
} coap_addr_info_t;

/**
 * Determine and set up scheme_hint_bits for a server that can be used in
 * a call to coap_resolve_address_info().
 *
 * @param have_pki_psk Set to @c 1 if PSK/PKI information is known else @c 0.
 * @param ws_check Set to @c 1 is WebSockets is to be included in the list
 *                  else @c 0.
 * @param use_unix_proto Set to the appropriate protocol to use for Unix
 *                       sockets, else set to COAP_PROTO_NONE for INET / INET6
 *                       sockets.
 * @return A bit mask of the available CoAP protocols (can be @c 0 if none)
 *         suitable for passing to coap_resolve_address_info().
 */
uint32_t coap_get_available_scheme_hint_bits(int have_pki_psk, int ws_check,
                                             coap_proto_t use_unix_proto);

/**
 * coap_resolve_type_t values
 */
typedef enum coap_resolve_type_t {
  COAP_RESOLVE_TYPE_LOCAL,   /**< local side of session */
  COAP_RESOLVE_TYPE_REMOTE,  /**< remote side of session */
} coap_resolve_type_t;

/**
 * Resolve the specified @p address into a set of coap_address_t that can
 * be used to bind() (local) or connect() (remote) to.
 *
 * @param address The Address to resolve.
 * @param port    The unsecured protocol port to use.
 * @param secure_port The secured protocol port to use.
 * @param ws_port The unsecured WebSockets port to use.
 * @param ws_secure_port The secured WebSockets port to use.
 * @param ai_hints_flags AI_* Hint flags to use for internal getaddrinfo().
 * @param scheme_hint_bits Which schemes to return information for. One or
 *                         more of COAP_URI_SCHEME_*_BIT or'd together.
 * @param type COAP_ADDRESS_TYPE_LOCAL or COAP_ADDRESS_TYPE_REMOTE
 *
 * @return One or more linked sets of coap_addr_info_t or @c NULL if error.
 */
coap_addr_info_t *coap_resolve_address_info(const coap_str_const_t *address,
                                            uint16_t port,
                                            uint16_t secure_port,
                                            uint16_t ws_port,
                                            uint16_t ws_secure_port,
                                            int ai_hints_flags,
                                            int scheme_hint_bits,
                                            coap_resolve_type_t type);

/**
 * Free off the one or more linked sets of coap_addr_info_t returned from
 * coap_resolve_address_info().
 *
 * @param info_list The set of coap_addr_info_t to free off.
 */
void coap_free_address_info(coap_addr_info_t *info_list);

/**
 * Resets the given coap_address_t object @p addr to its default values. In
 * particular, the member size must be initialized to the available size for
 * storing addresses.
 *
 * @param addr The coap_address_t object to initialize.
 */
void coap_address_init(coap_address_t *addr);

/**
 * Copy the parsed unix domain host into coap_address_t structure
 * translating %2F into / on the way. All other fields set as appropriate.
 *
 * @param addr coap_address_t to update.
 * @param host The parsed host from the CoAP URI with potential %2F encoding.
 * @param host_len The length of the parsed host from the CoAP URI with
 *                 potential %2F encoding.
 *
 * @return @c 1 success, @c 0 failure.
 */
int coap_address_set_unix_domain(coap_address_t *addr,
                                 const uint8_t *host, size_t host_len);

/* Convenience function to copy IPv6 addresses without garbage. */
#if defined(WITH_LWIP) || defined(WITH_CONTIKI)
COAP_STATIC_INLINE void
coap_address_copy(coap_address_t *dst, const coap_address_t *src) {
  memcpy(dst, src, sizeof(coap_address_t));
}
#else /* ! WITH_LWIP && ! WITH_CONTIKI */
void coap_address_copy(coap_address_t *dst, const coap_address_t *src);
#endif /* ! WITH_LWIP && ! WITH_CONTIKI */

#if defined(WITH_LWIP) || defined(WITH_CONTIKI)
/**
 * Compares given address objects @p a and @p b. This function returns @c 1 if
 * addresses are equal, @c 0 otherwise. The parameters @p a and @p b must not be
 * @c NULL;
 */
COAP_STATIC_INLINE int
coap_address_equals(const coap_address_t *a, const coap_address_t *b) {
  assert(a);
  assert(b);
  return _coap_address_equals_impl(a, b);
}
#endif

/**
 * Checks if given address object @p a denotes the wildcard address. This
 * function returns @c 1 if this is the case, @c 0 otherwise. The parameters @p
 * a must not be @c NULL;
 */
COAP_STATIC_INLINE int
coap_address_isany(const coap_address_t *a) {
  assert(a);
  return _coap_address_isany_impl(a);
}

#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)

/**
 * Checks if given address @p a denotes a multicast address. This function
 * returns @c 1 if @p a is multicast, @c 0 otherwise.
 */
int coap_is_mcast(const coap_address_t *a);

/**
 * Checks if given address @p a denotes a broadcast address. This function
 * returns @c 1 if @p a is broadcast, @c 0 otherwise.
 */
int coap_is_bcast(const coap_address_t *a);

/**
 * Checks if given address @p a denotes a AF_UNIX address. This function
 * returns @c 1 if @p a is of type AF_UNIX, @c 0 otherwise.
 */
int coap_is_af_unix(const coap_address_t *a);

#else /* WITH_LWIP || WITH_CONTIKI */

/**
 * Checks if given address @p a denotes a multicast address. This function
 * returns @c 1 if @p a is multicast, @c 0 otherwise.
 */
COAP_STATIC_INLINE int
coap_is_mcast(const coap_address_t *a) {
  return a && _coap_is_mcast_impl(a);
}

/**
 * Checks if given address @p a denotes a AF_UNIX address. This function
 * returns @c 1 if @p a is of type AF_UNIX, @c 0 otherwise.
 */
COAP_STATIC_INLINE int
coap_is_af_unix(const coap_address_t *a) {
  (void)a;
  return 0;
}

#endif /* WITH_LWIP || WITH_CONTIKI */

#endif /* COAP_ADDRESS_H_ */
