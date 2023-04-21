/* coap_address.c -- representation of network addresses
 *
 * Copyright (C) 2015-2016,2019-2023 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_address.c
 * @brief Handling of network addresses
 */

#include "coap3/coap_internal.h"

#if !defined(WITH_CONTIKI) && !defined(WITH_LWIP)
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

#ifdef RIOT_VERSION
/* FIXME */
#define IN_MULTICAST(Address) (0)
#endif /* RIOT_VERSION */

uint16_t
coap_address_get_port(const coap_address_t *addr) {
  assert(addr != NULL);
  switch (addr->addr.sa.sa_family) {
  case AF_INET: return ntohs(addr->addr.sin.sin_port);
  case AF_INET6: return ntohs(addr->addr.sin6.sin6_port);
  default: /* undefined */
    ;
  }
  return 0;
}

void
coap_address_set_port(coap_address_t *addr, uint16_t port) {
  assert(addr != NULL);
  switch (addr->addr.sa.sa_family) {
  case AF_INET:
    addr->addr.sin.sin_port = htons(port);
    break;
  case AF_INET6:
    addr->addr.sin6.sin6_port = htons(port);
    break;
  default: /* undefined */
    ;
  }
}

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
   return IN6_IS_ADDR_MULTICAST(&a->addr.sin6.sin6_addr) ||
       (IN6_IS_ADDR_V4MAPPED(&a->addr.sin6.sin6_addr) &&
           IN_MULTICAST(ntohl(a->addr.sin6.sin6_addr.s6_addr[12])));
 default:  /* fall through and signal error */
   ;
  }
 return 0;
}

#endif /* !defined(WITH_CONTIKI) && !defined(WITH_LWIP) */

void coap_address_init(coap_address_t *addr) {
  assert(addr);
  memset(addr, 0, sizeof(coap_address_t));
#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
  /* lwip and Contiki have constant address sizes and don't need the .size part */
  addr->size = sizeof(addr->addr);
#endif
}

#ifndef WITH_CONTIKI
int
coap_address_set_unix_domain(coap_address_t *addr,
                              const uint8_t *host, size_t host_len) {
#if !defined(WITH_LWIP)
  size_t i;
  size_t ofs = 0;

  coap_address_init(addr);
  addr->addr.cun.sun_family = AF_UNIX;
  for (i = 0; i < host_len; i++) {
    if ((host_len - i) >= 3 && host[i] == '%' && host[i+1] == '2' &&
        (host[i+2] == 'F' || host[i+2] == 'f')) {
      addr->addr.cun.sun_path[ofs++] = '/';
      i += 2;
    } else {
      addr->addr.cun.sun_path[ofs++] = host[i];
    }
    if (ofs == COAP_UNIX_PATH_MAX)
      break;
  }
  if (ofs < COAP_UNIX_PATH_MAX)
    addr->addr.cun.sun_path[ofs] = '\000';
  else
    addr->addr.cun.sun_path[ofs-1] = '\000';
  return 1;
#else /* WITH_LWIP */
  (void)addr;
  (void)host;
  (void)host_len;
  return 0;
#endif /* WITH_LWIP */
}

static void
update_port(coap_address_t *addr, uint16_t port, uint16_t default_port) {
  if (port == 0)
    port = default_port;

#if !defined(WITH_LWIP)
 if (addr->addr.sa.sa_family == AF_INET)
   addr->addr.sin.sin_port = htons(port);
 else if (addr->addr.sa.sa_family == AF_INET6)
   addr->addr.sin6.sin6_port = htons(port);
#else /* defined(WITH_LWIP) */
  addr->port = port;
#endif /* defined(WITH_LWIP) */
  return;
}

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

uint32_t
coap_get_available_scheme_hint_bits(int have_pki_psk, int ws_check,
                                    coap_proto_t use_unix_proto) {
  uint32_t scheme_hint_bits = 0;
  coap_uri_scheme_t scheme;

  for (scheme = 0; scheme < COAP_URI_SCHEME_LAST; scheme++) {
    switch (scheme) {
    case COAP_URI_SCHEME_COAP:
      scheme_hint_bits |= 1 << scheme;
      break;
    case COAP_URI_SCHEME_COAPS:
      if (!(coap_dtls_is_supported() && have_pki_psk))
        continue;
      scheme_hint_bits |= 1 << scheme;
      break;
    case COAP_URI_SCHEME_COAP_TCP:
      if (!coap_tcp_is_supported())
        continue;
      scheme_hint_bits |= 1 << scheme;
      break;
    case COAP_URI_SCHEME_COAPS_TCP:
      if (!(coap_tls_is_supported() && have_pki_psk))
        continue;
      scheme_hint_bits |= 1 << scheme;
      break;
    case COAP_URI_SCHEME_COAP_WS:
      if (!ws_check || !coap_ws_is_supported())
        continue;
      scheme_hint_bits |= 1 << scheme;
      break;
    case COAP_URI_SCHEME_COAPS_WS:
      if (!ws_check || !(coap_wss_is_supported() && have_pki_psk))
        continue;
      scheme_hint_bits |= 1 << scheme;
      break;
    case COAP_URI_SCHEME_HTTP:
    case COAP_URI_SCHEME_HTTPS:
    case COAP_URI_SCHEME_LAST:
    default:
      continue;
    }
  }

  switch (use_unix_proto) {
  /* For AF_UNIX, can only listen on a single endpoint */
  case COAP_PROTO_UDP:  scheme_hint_bits = 1 << COAP_URI_SCHEME_COAP; break;
  case COAP_PROTO_TCP:  scheme_hint_bits = 1 << COAP_URI_SCHEME_COAP_TCP; break;
  case COAP_PROTO_DTLS: scheme_hint_bits = 1 << COAP_URI_SCHEME_COAPS; break;
  case COAP_PROTO_TLS:  scheme_hint_bits = 1 << COAP_URI_SCHEME_COAPS_TCP; break;
  case COAP_PROTO_WS:   scheme_hint_bits = 1 << COAP_URI_SCHEME_COAP_WS; break;
  case COAP_PROTO_WSS:  scheme_hint_bits = 1 << COAP_URI_SCHEME_COAPS_WS; break;
  case COAP_PROTO_NONE: /* If use_unix_proto was not defined */
  case COAP_PROTO_LAST:
  default:
    break;
  }
  return scheme_hint_bits;
}

coap_addr_info_t *
coap_resolve_address_info(const coap_str_const_t *server,
                          uint16_t port,
                          uint16_t secure_port,
                          int ai_hints_flags,
                          int scheme_hint_bits) {

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error;
  coap_addr_info_t *info = NULL;
  coap_addr_info_t *info_prev = NULL;
  coap_addr_info_t *info_list = NULL;
  coap_uri_scheme_t scheme;
  coap_proto_t proto;

#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
  if (server && coap_host_is_unix_domain(server)) {
    /* There can only be one unique filename entry for AF_UNIX */
    if (server->length >= COAP_UNIX_PATH_MAX) {
      coap_log_err("Unix Domain host too long\n");
      return NULL;
    }
    /* Need to chose the first defined one  in scheme_hint_bits */
    for (scheme = 0; scheme < COAP_URI_SCHEME_LAST; scheme++) {
      if (scheme_hint_bits & (1 << scheme)) {
        break;
      }
    }
    if (scheme == COAP_URI_SCHEME_LAST) {
      return NULL;
    }
    switch (scheme) {
    case COAP_URI_SCHEME_COAP:
      proto = COAP_PROTO_UDP;
      break;
    case COAP_URI_SCHEME_COAPS:
      if (!coap_dtls_is_supported())
        return NULL;
      proto = COAP_PROTO_DTLS;
      break;
    case COAP_URI_SCHEME_COAP_TCP:
      if (!coap_tcp_is_supported())
        return NULL;
      proto = COAP_PROTO_TCP;
      break;
    case COAP_URI_SCHEME_COAPS_TCP:
      if (!coap_tls_is_supported())
        return NULL;
      proto = COAP_PROTO_TLS;
      break;
    case COAP_URI_SCHEME_HTTP:
      if (!coap_tcp_is_supported())
        return NULL;
      proto = COAP_PROTO_NONE;
      break;
    case COAP_URI_SCHEME_HTTPS:
      if (!coap_tls_is_supported())
        return NULL;
      proto = COAP_PROTO_NONE;
      break;
    case COAP_URI_SCHEME_COAP_WS:
      if (!coap_ws_is_supported())
        return NULL;
      proto = COAP_PROTO_WS;
      break;
    case COAP_URI_SCHEME_COAPS_WS:
      if (!coap_wss_is_supported())
        return NULL;
      proto = COAP_PROTO_WSS;
      break;
    case COAP_URI_SCHEME_LAST:
    default:
      return NULL;
    }
    info = coap_malloc_type(COAP_STRING, sizeof(coap_addr_info_t));
    if (info == NULL)
      return NULL;
    info->next = NULL;
    info->proto = proto;
    info->scheme = scheme;

    coap_address_init(&info->addr);
    if (!coap_address_set_unix_domain(&info->addr, server->s,
                                      server->length)) {
      coap_free_type(COAP_STRING, info);
      return NULL;
    }
    return info;
  }
#endif /* ! WITH_LWIP && ! WITH_CONTIKI */

  memset(addrstr, 0, sizeof(addrstr));
  if (server && server->length)
    memcpy(addrstr, server->s, server->length);
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = 0;
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = ai_hints_flags;

  error = getaddrinfo(addrstr, NULL, &hints, &res);

  if (error != 0) {
    coap_log_warn("getaddrinfo: %s\n", gai_strerror(error));
    return NULL;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
#if !defined(WITH_LWIP)
    if (ainfo->ai_addrlen > (socklen_t)sizeof(info->addr.addr))
      continue;
#endif /* ! WITH_LWIP */

    switch (ainfo->ai_family) {
    case AF_INET6:
    case AF_INET:
      for (scheme = 0; scheme < COAP_URI_SCHEME_LAST; scheme++) {
        if (scheme_hint_bits & (1 << scheme)) {
          switch (scheme) {
          case COAP_URI_SCHEME_COAP:
            proto = COAP_PROTO_UDP;
#if !defined(__MINGW32__)
            if (ainfo->ai_socktype != SOCK_DGRAM)
              continue;
#endif /* ! __MINGW32__ */
            break;
          case COAP_URI_SCHEME_COAPS:
            if (!coap_dtls_is_supported())
              continue;
            proto = COAP_PROTO_DTLS;
#if !defined(__MINGW32__)
            if (ainfo->ai_socktype != SOCK_DGRAM)
              continue;
#endif /* ! __MINGW32__ */
            break;
          case COAP_URI_SCHEME_COAP_TCP:
            if (!coap_tcp_is_supported())
              continue;
            proto = COAP_PROTO_TCP;
#if !defined(__MINGW32__)
            if (ainfo->ai_socktype != SOCK_STREAM)
              continue;
#endif /* ! __MINGW32__ */
            break;
          case COAP_URI_SCHEME_COAPS_TCP:
            if (!coap_tls_is_supported())
              continue;
            proto = COAP_PROTO_TLS;
#if !defined(__MINGW32__)
            if (ainfo->ai_socktype != SOCK_STREAM)
              continue;
#endif /* ! __MINGW32__ */
            break;
          case COAP_URI_SCHEME_HTTP:
            if (!coap_tcp_is_supported())
              continue;
            proto = COAP_PROTO_NONE;
#if !defined(__MINGW32__)
            if (ainfo->ai_socktype != SOCK_STREAM)
              continue;
#endif /* ! __MINGW32__ */
            break;
          case COAP_URI_SCHEME_HTTPS:
            if (!coap_tls_is_supported())
              continue;
            proto = COAP_PROTO_NONE;
#if !defined(__MINGW32__)
            if (ainfo->ai_socktype != SOCK_STREAM)
              continue;
#endif /* ! __MINGW32__ */
            break;
          case COAP_URI_SCHEME_COAP_WS:
            if (!coap_ws_is_supported())
              continue;
            proto = COAP_PROTO_WS;
#if !defined(__MINGW32__)
            if (ainfo->ai_socktype != SOCK_STREAM)
              continue;
#endif /* ! __MINGW32__ */
            break;
          case COAP_URI_SCHEME_COAPS_WS:
            if (!coap_wss_is_supported())
              continue;
            proto = COAP_PROTO_WSS;
#if !defined(__MINGW32__)
            if (ainfo->ai_socktype != SOCK_STREAM)
              continue;
#endif /* ! __MINGW32__ */
            break;
          case COAP_URI_SCHEME_LAST:
          default:
            continue;
          }

          info = coap_malloc_type(COAP_STRING, sizeof(coap_addr_info_t));
          if (info == NULL) {
            /* malloc failure - return what we have so far */
            return info_list;
          }
          info->next = NULL;
          /* Need to return in same order as getaddrinfo() */
          if (!info_prev) {
            info_list = info;
            info_prev = info;
          } else {
            info_prev->next = info;
            info_prev = info;
          }

          info->scheme = scheme;
          info->proto = proto;
          coap_address_init(&info->addr);
#if !defined(WITH_LWIP)
          info->addr.size = (socklen_t)ainfo->ai_addrlen;
          memcpy(&info->addr.addr, ainfo->ai_addr, ainfo->ai_addrlen);
#else /* defined(WITH_LWIP) */
          memset(&info->addr, 0, sizeof(info->addr));
          switch (ainfo->ai_family) {
            struct sockaddr_in *sock4;
            struct sockaddr_in6 *sock6;
          case AF_INET:
            sock4 = (struct sockaddr_in *)ainfo->ai_addr;
            info->addr.port = ntohs(sock4->sin_port);
            memcpy(&info->addr.addr, &sock4->sin_addr, 4);
#ifdef WITH_LWIP
            info->addr.addr.type = IPADDR_TYPE_V4;
#endif /* WITH_LWIP */
            break;
          case AF_INET6:
            sock6 = (struct sockaddr_in6 *)ainfo->ai_addr;
            info->addr.port = ntohs(sock6->sin6_port);
            memcpy(&info->addr.addr, &sock6->sin6_addr, 16);
#ifdef WITH_LWIP
            info->addr.addr.type = IPADDR_TYPE_V6;
#endif /* WITH_LWIP */
            break;
          default:
            ;
          }
#endif /* defined(WITH_LWIP) */
          switch (scheme) {
          case COAP_URI_SCHEME_COAP:
            update_port(&info->addr, port, 5683);
            break;
          case COAP_URI_SCHEME_COAPS:
            update_port(&info->addr, secure_port, 5684);
            break;
          case COAP_URI_SCHEME_COAP_TCP:
            update_port(&info->addr, port, 5683);
            break;
          case COAP_URI_SCHEME_COAPS_TCP:
            update_port(&info->addr, secure_port, 5684);
            break;
          case COAP_URI_SCHEME_HTTP:
            update_port(&info->addr, port, 80);
            break;
          case COAP_URI_SCHEME_HTTPS:
            update_port(&info->addr, secure_port, 443);
            break;
          case COAP_URI_SCHEME_COAP_WS:
            update_port(&info->addr, port, 80);
            break;
          case COAP_URI_SCHEME_COAPS_WS:
            update_port(&info->addr, secure_port, 443);
            break;
          case COAP_URI_SCHEME_LAST:
          default:
            break;
          }
        }
      }
      break;
    default:
      break;
    }
  }

  freeaddrinfo(res);
  return info_list;
}
#endif /* !WITH_CONTIKI */

void
coap_free_address_info(coap_addr_info_t *info) {
  while (info) {
    coap_addr_info_t *info_next = info->next;

    coap_free_type(COAP_STRING, info);
    info = info_next;
  }
}
