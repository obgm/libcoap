/* address.c -- representation of network addresses
 *
 * Copyright (C) 2015-2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_config.h"

#if defined(WITH_POSIX) || defined(HAVE_WS2TCPIP_H)
#include <assert.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#include "address.h"

int 
coap_address_equals(const coap_address_t *a, const coap_address_t *b) {
  assert(a); assert(b);

  if (a->size != b->size || a->addr.sa.sa_family != b->addr.sa.sa_family)
    return 0;
  
  /* need to compare only relevant parts of sockaddr_in6 */
 switch (a->addr.sa.sa_family) {
 case AF_INET:
   return 
     a->addr.sin.sin_port == b->addr.sin.sin_port && 
     memcmp(&a->addr.sin.sin_addr, &b->addr.sin.sin_addr, 
	    sizeof(struct in_addr)) == 0;
 case AF_INET6:
   return a->addr.sin6.sin6_port == b->addr.sin6.sin6_port && 
     memcmp(&a->addr.sin6.sin6_addr, &b->addr.sin6.sin6_addr, 
	    sizeof(struct in6_addr)) == 0;
 default: /* fall through and signal error */
   ;
 }
 return 0;
}

int coap_is_mcast(const coap_address_t *a) {
  if (!a)
    return 0;

 switch (a->addr.sa.sa_family) {
 case AF_INET:
   return IN_MULTICAST(ntohl(a->addr.sin.sin_addr.s_addr));
 case  AF_INET6:
   return IN6_IS_ADDR_MULTICAST(&a->addr.sin6.sin6_addr);
 default:  /* fall through and signal error */
   ;
  }
 return 0;
}
#else /* WITH_POSIX || HAVE_WS2TCPIP_H */

/* make compilers happy that do not like empty modules */
COAP_STATIC_INLINE void dummy()
{
}

#endif
