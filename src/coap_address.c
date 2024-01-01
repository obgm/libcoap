/* coap_address.c -- representation of network addresses
 *
 * Copyright (C) 2015-2016,2019-2024 Olaf Bergmann <bergmann@tzi.org>
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
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
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
#if COAP_IPV4_SUPPORT
  case AF_INET:
    return ntohs(addr->addr.sin.sin_port);
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
  case AF_INET6:
    return ntohs(addr->addr.sin6.sin6_port);
#endif /* COAP_IPV6_SUPPORT */
  default: /* undefined */
    ;
  }
  return 0;
}

void
coap_address_set_port(coap_address_t *addr, uint16_t port) {
  assert(addr != NULL);
  switch (addr->addr.sa.sa_family) {
#if COAP_IPV4_SUPPORT
  case AF_INET:
    addr->addr.sin.sin_port = htons(port);
    break;
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
  case AF_INET6:
    addr->addr.sin6.sin6_port = htons(port);
    break;
#endif /* COAP_IPV6_SUPPORT */
  default: /* undefined */
    ;
  }
}

int
coap_address_equals(const coap_address_t *a, const coap_address_t *b) {
  assert(a);
  assert(b);

  if (a->size != b->size || a->addr.sa.sa_family != b->addr.sa.sa_family)
    return 0;

  /* need to compare only relevant parts of sockaddr_in6 */
  switch (a->addr.sa.sa_family) {
#if COAP_IPV4_SUPPORT
  case AF_INET:
    return a->addr.sin.sin_port == b->addr.sin.sin_port &&
           memcmp(&a->addr.sin.sin_addr, &b->addr.sin.sin_addr,
                  sizeof(struct in_addr)) == 0;
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
  case AF_INET6:
    return a->addr.sin6.sin6_port == b->addr.sin6.sin6_port &&
           memcmp(&a->addr.sin6.sin6_addr, &b->addr.sin6.sin6_addr,
                  sizeof(struct in6_addr)) == 0;
#endif /* COAP_IPV6_SUPPORT */
  default: /* fall through and signal error */
    ;
  }
  return 0;
}

int
coap_is_af_unix(const coap_address_t *a) {
#if COAP_AF_UNIX_SUPPORT
  return a->addr.sa.sa_family == AF_UNIX;
#else /* ! COAP_AF_UNIX_SUPPORT */
  (void)a;
  return 0;
#endif /* ! COAP_AF_UNIX_SUPPORT */
}

int
coap_is_mcast(const coap_address_t *a) {
  if (!a)
    return 0;

  /* Treat broadcast in same way as multicast */
  if (coap_is_bcast(a))
    return 1;

  switch (a->addr.sa.sa_family) {
#if COAP_IPV4_SUPPORT
  case AF_INET:
    return IN_MULTICAST(ntohl(a->addr.sin.sin_addr.s_addr));
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
  case  AF_INET6:
#if COAP_IPV4_SUPPORT
    return IN6_IS_ADDR_MULTICAST(&a->addr.sin6.sin6_addr) ||
           (IN6_IS_ADDR_V4MAPPED(&a->addr.sin6.sin6_addr) &&
            IN_MULTICAST(ntohl(a->addr.sin6.sin6_addr.s6_addr[12])));
#else /* ! COAP_IPV4_SUPPORT */
    return a->addr.sin6.sin6_addr.s6_addr[0] == 0xff;
#endif /* ! COAP_IPV4_SUPPORT */
#endif /* COAP_IPV6_SUPPORT */
  default:  /* fall through and signal not multicast */
    ;
  }
  return 0;
}

#ifndef COAP_BCST_CNT
#define COAP_BCST_CNT 15
#endif /* COAP_BCST_CNT */

/* How frequently to refresh the list of valid IPv4 broadcast addresses */
#ifndef COAP_BCST_REFRESH_SECS
#define COAP_BCST_REFRESH_SECS 30
#endif /* COAP_BCST_REFRESH_SECS */

#if COAP_IPV4_SUPPORT && defined(HAVE_IFADDRS_H)
static int bcst_cnt = -1;
static coap_tick_t last_refresh;
static struct in_addr b_ipv4[COAP_BCST_CNT];
#endif /* COAP_IPV4_SUPPORT && HAVE_IFADDRS_H */

int
coap_is_bcast(const coap_address_t *a) {
#if COAP_IPV4_SUPPORT
  struct in_addr ipv4;
#if defined(HAVE_IFADDRS_H)
  int i;
  coap_tick_t now;
#endif /* HAVE_IFADDRS_H */
#endif /* COAP_IPV4_SUPPORT */

  if (!a)
    return 0;

  switch (a->addr.sa.sa_family) {
#if COAP_IPV4_SUPPORT
  case AF_INET:
    ipv4.s_addr = a->addr.sin.sin_addr.s_addr;
    break;
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
  case  AF_INET6:
#if COAP_IPV4_SUPPORT
    if (IN6_IS_ADDR_V4MAPPED(&a->addr.sin6.sin6_addr)) {
      memcpy(&ipv4, &a->addr.sin6.sin6_addr.s6_addr[12], sizeof(ipv4));
      break;
    }
#endif /* COAP_IPV4_SUPPORT */
    /* IPv6 does not support broadcast */
    return 0;
#endif /* COAP_IPV6_SUPPORT */
  default:
    return 0;
  }
#if COAP_IPV4_SUPPORT
#ifndef INADDR_BROADCAST
#define INADDR_BROADCAST ((uint32_t)0xffffffffUL)
#endif /* !INADDR_BROADCAST */
  if (ipv4.s_addr == INADDR_BROADCAST)
    return 1;

#if defined(HAVE_IFADDRS_H)
  coap_ticks(&now);
  if (bcst_cnt == -1 ||
      (now - last_refresh) > (COAP_BCST_REFRESH_SECS * COAP_TICKS_PER_SECOND)) {
    /* Determine the list of broadcast interfaces */
    struct ifaddrs *ifa = NULL;
    struct ifaddrs *ife;

    if (getifaddrs(&ifa) != 0) {
      coap_log_warn("coap_is_bcst: Cannot determine any broadcast addresses\n");
      return 0;
    }
    bcst_cnt = 0;
    last_refresh = now;
    ife = ifa;
    while (ife && bcst_cnt < COAP_BCST_CNT) {
      if (ife->ifa_addr && ife->ifa_addr->sa_family == AF_INET &&
          ife->ifa_flags & IFF_BROADCAST) {
        struct in_addr netmask;

        /*
         * Sometimes the broadcast IP is set to the IP address, even though
         * netmask is not set to 0xffffffff, so unsafe to use ifa_broadaddr.
         */
        netmask.s_addr = ((struct sockaddr_in *)ife->ifa_netmask)->sin_addr.s_addr;
        if (netmask.s_addr != 0xffffffff) {
          b_ipv4[bcst_cnt].s_addr = ((struct sockaddr_in *)ife->ifa_addr)->sin_addr.s_addr |
                                    ~netmask.s_addr;
          bcst_cnt++;
        }
      }
      ife = ife->ifa_next;
    }
    if (ife) {
      coap_log_warn("coap_is_bcst: Insufficient space for broadcast addresses\n");
    }
    freeifaddrs(ifa);
  }
  for (i = 0; i < bcst_cnt; i++) {
    if (ipv4.s_addr == b_ipv4[i].s_addr)
      return 1;
  }
#endif /* HAVE_IFADDRS_H */
  return 0;
#endif /* COAP_IPV4_SUPPORT */
}

#endif /* !defined(WITH_CONTIKI) && !defined(WITH_LWIP) */

void
coap_address_init(coap_address_t *addr) {
  assert(addr);
  memset(addr, 0, sizeof(coap_address_t));
#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
  /* lwip and Contiki have constant address sizes and don't need the .size part */
  addr->size = sizeof(addr->addr);
#endif
}

int
coap_address_set_unix_domain(coap_address_t *addr,
                             const uint8_t *host, size_t host_len) {
#if COAP_AF_UNIX_SUPPORT
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
#else /* ! COAP_AF_UNIX_SUPPORT */
  (void)addr;
  (void)host;
  (void)host_len;
  return 0;
#endif /* ! COAP_AF_UNIX_SUPPORT */
}

#if !defined(WITH_CONTIKI)
static void
update_port(coap_address_t *addr, uint16_t port, uint16_t default_port,
            int update_port0) {
  /* Client target port must be set if default of 0 */
  if (port == 0 && update_port0)
    port = default_port;

  coap_address_set_port(addr, port);
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
  case COAP_PROTO_UDP:
    scheme_hint_bits = 1 << COAP_URI_SCHEME_COAP;
    break;
  case COAP_PROTO_TCP:
    scheme_hint_bits = 1 << COAP_URI_SCHEME_COAP_TCP;
    break;
  case COAP_PROTO_DTLS:
    scheme_hint_bits = 1 << COAP_URI_SCHEME_COAPS;
    break;
  case COAP_PROTO_TLS:
    scheme_hint_bits = 1 << COAP_URI_SCHEME_COAPS_TCP;
    break;
  case COAP_PROTO_WS:
    scheme_hint_bits = 1 << COAP_URI_SCHEME_COAP_WS;
    break;
  case COAP_PROTO_WSS:
    scheme_hint_bits = 1 << COAP_URI_SCHEME_COAPS_WS;
    break;
  case COAP_PROTO_NONE: /* If use_unix_proto was not defined */
  case COAP_PROTO_LAST:
  default:
    break;
  }
  return scheme_hint_bits;
}

static coap_addr_info_t *
get_coap_addr_info(coap_uri_scheme_t scheme) {
  coap_addr_info_t *info = NULL;
  coap_proto_t proto = 0;

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
  return info;
}

static void
update_coap_addr_port(coap_uri_scheme_t scheme, coap_addr_info_t *info,
                      uint16_t port, uint16_t secure_port, uint16_t ws_port,
                      uint16_t ws_secure_port,
                      coap_resolve_type_t type) {
  switch (scheme) {
  case COAP_URI_SCHEME_COAP:
    update_port(&info->addr, port, COAP_DEFAULT_PORT,
                type == COAP_RESOLVE_TYPE_LOCAL);
    break;
  case COAP_URI_SCHEME_COAPS:
    update_port(&info->addr, secure_port, COAPS_DEFAULT_PORT,
                type == COAP_RESOLVE_TYPE_LOCAL);
    break;
  case COAP_URI_SCHEME_COAP_TCP:
    update_port(&info->addr, port, COAP_DEFAULT_PORT,
                type == COAP_RESOLVE_TYPE_LOCAL);
    break;
  case COAP_URI_SCHEME_COAPS_TCP:
    update_port(&info->addr, secure_port, COAPS_DEFAULT_PORT,
                type == COAP_RESOLVE_TYPE_LOCAL);
    break;
  case COAP_URI_SCHEME_HTTP:
    update_port(&info->addr, port, 80,
                type == COAP_RESOLVE_TYPE_LOCAL);
    break;
  case COAP_URI_SCHEME_HTTPS:
    update_port(&info->addr, secure_port, 443,
                type == COAP_RESOLVE_TYPE_LOCAL);
    break;
  case COAP_URI_SCHEME_COAP_WS:
    update_port(&info->addr, ws_port, 80,
                type == COAP_RESOLVE_TYPE_LOCAL);
    break;
  case COAP_URI_SCHEME_COAPS_WS:
    update_port(&info->addr, ws_secure_port, 443,
                type == COAP_RESOLVE_TYPE_LOCAL);
    break;
  case COAP_URI_SCHEME_LAST:
  default:
    break;
  }
}

coap_addr_info_t *
coap_resolve_address_info(const coap_str_const_t *address,
                          uint16_t port,
                          uint16_t secure_port,
                          uint16_t ws_port,
                          uint16_t ws_secure_port,
                          int ai_hints_flags,
                          int scheme_hint_bits,
                          coap_resolve_type_t type) {
#if !defined(RIOT_VERSION)

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error;
  coap_addr_info_t *info = NULL;
  coap_addr_info_t *info_prev = NULL;
  coap_addr_info_t *info_list = NULL;
  coap_addr_info_t *info_tmp;
  coap_uri_scheme_t scheme;

#if COAP_AF_UNIX_SUPPORT
  if (address && coap_host_is_unix_domain(address)) {
    /* There can only be one unique filename entry for AF_UNIX */
    if (address->length >= COAP_UNIX_PATH_MAX) {
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
    info = get_coap_addr_info(scheme);
    if (info == NULL) {
      return NULL;
    }

    if (!coap_address_set_unix_domain(&info->addr, address->s,
                                      address->length)) {
      coap_free_type(COAP_STRING, info);
      return NULL;
    }
    return info;
  }
#endif /* COAP_AF_UNIX_SUPPORT */

  memset(addrstr, 0, sizeof(addrstr));
  if (address && address->length)
    memcpy(addrstr, address->s, address->length);
  else
    memcpy(addrstr, "localhost", 9);

  memset((char *)&hints, 0, sizeof(hints));
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
#if COAP_IPV4_SUPPORT
    case AF_INET:
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
    case AF_INET6:
#endif /* COAP_IPV6_SUPPORT */
      for (scheme = 0; scheme < COAP_URI_SCHEME_LAST; scheme++) {
        if (scheme_hint_bits & (1 << scheme)) {
          info = get_coap_addr_info(scheme);
          if (info == NULL) {
            continue;
          }

#if !defined(WITH_LWIP)
          info->addr.size = (socklen_t)ainfo->ai_addrlen;
          memcpy(&info->addr.addr, ainfo->ai_addr, ainfo->ai_addrlen);
#else /* WITH_LWIP */
          memset(&info->addr, 0, sizeof(info->addr));
          switch (ainfo->ai_family) {
#if COAP_IPV6_SUPPORT
            struct sockaddr_in6 *sock6;
#endif /* COAP_IPV6_SUPPORT */
#if COAP_IPV4_SUPPORT
            struct sockaddr_in *sock4;
          case AF_INET:
            sock4 = (struct sockaddr_in *)ainfo->ai_addr;
            info->addr.port = ntohs(sock4->sin_port);
            memcpy(&info->addr.addr, &sock4->sin_addr, 4);
#if LWIP_IPV6
            info->addr.addr.type = IPADDR_TYPE_V4;
#endif /* LWIP_IPV6 */
            break;
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
          case AF_INET6:
            sock6 = (struct sockaddr_in6 *)ainfo->ai_addr;
            info->addr.port = ntohs(sock6->sin6_port);
            memcpy(&info->addr.addr, &sock6->sin6_addr, 16);
#if LWIP_IPV6 && LWIP_IPV4
            info->addr.addr.type = IPADDR_TYPE_V6;
#endif /* LWIP_IPV6 && LWIP_IPV4 */
            break;
#endif /* COAP_IPV6_SUPPORT */
          default:
            ;
          }
#endif /* WITH_LWIP */
          update_coap_addr_port(scheme, info, port, secure_port, ws_port,
                                ws_secure_port, type);

          /* Check there are no duplications */
          info_tmp = info_list;
          while (info_tmp) {
            if (info_tmp->proto == info->proto &&
                info_tmp->scheme == info->scheme &&
                coap_address_equals(&info_tmp->addr, &info->addr)) {
              break;
            }
            info_tmp = info_tmp->next;
          }

          if (info_tmp) {
            /* Duplicate */
            coap_free_type(COAP_STRING, info);
          } else {
            /* Need to return in same order as getaddrinfo() */
            if (!info_prev) {
              info_list = info;
              info_prev = info;
            } else {
              info_prev->next = info;
              info_prev = info;
            }
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
#else /* RIOT_VERSION */
#if COAP_IPV6_SUPPORT
#include "net/utils.h"
  ipv6_addr_t addr_ipv6;
  netif_t *netif = NULL;
  coap_addr_info_t *info = NULL;
  coap_addr_info_t *info_prev = NULL;
  coap_addr_info_t *info_list = NULL;
  coap_uri_scheme_t scheme;
  (void)ai_hints_flags;

  if (netutils_get_ipv6(&addr_ipv6, &netif, (const char *)address->s) >= 0) {
    for (scheme = 0; scheme < COAP_URI_SCHEME_LAST; scheme++) {
      if (scheme_hint_bits & (1 << scheme)) {
        info = get_coap_addr_info(scheme);
        if (info == NULL) {
          continue;
        }

        /* Need to return in same order as getaddrinfo() */
        if (!info_prev) {
          info_list = info;
          info_prev = info;
        } else {
          info_prev->next = info;
          info_prev = info;
        }

        info->addr.size = sizeof(struct sockaddr_in6);
        info->addr.addr.sin6.sin6_family = AF_INET6;
        memcpy(&info->addr.addr.sin6.sin6_addr, &addr_ipv6,
               sizeof(info->addr.addr.sin6.sin6_addr));
        info->addr.addr.sin6.sin6_scope_id =
            netif ? (uint32_t)netif_get_id(netif) : 0;

        update_coap_addr_port(scheme, info, port, secure_port, ws_port,
                              ws_secure_port, type);
      }
    }
    return info_list;
  }
#endif /* COAP_IPV6_SUPPORT */
  return NULL;
#endif /* RIOT_VERSION */
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

#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
void
coap_address_copy(coap_address_t *dst, const coap_address_t *src) {
#if defined(WITH_LWIP) || defined(WITH_CONTIKI)
  memcpy(dst, src, sizeof(coap_address_t));
#else
  memset(dst, 0, sizeof(coap_address_t));
  dst->size = src->size;
#if COAP_IPV6_SUPPORT
  if (src->addr.sa.sa_family == AF_INET6) {
    dst->addr.sin6.sin6_family = src->addr.sin6.sin6_family;
    dst->addr.sin6.sin6_addr = src->addr.sin6.sin6_addr;
    dst->addr.sin6.sin6_port = src->addr.sin6.sin6_port;
    dst->addr.sin6.sin6_scope_id = src->addr.sin6.sin6_scope_id;
  }
#endif /* COAP_IPV6_SUPPORT */
#if COAP_IPV4_SUPPORT && COAP_IPV6_SUPPORT
  else
#endif /* COAP_IPV4_SUPPORT && COAP_IPV6_SUPPORT */
#if COAP_IPV4_SUPPORT
    if (src->addr.sa.sa_family == AF_INET) {
      dst->addr.sin = src->addr.sin;
    }
#endif /* COAP_IPV4_SUPPORT */
    else {
      memcpy(&dst->addr, &src->addr, src->size);
    }
#endif
}

int
_coap_address_isany_impl(const coap_address_t *a) {
  /* need to compare only relevant parts of sockaddr_in6 */
  switch (a->addr.sa.sa_family) {
#if COAP_IPV4_SUPPORT
  case AF_INET:
    return a->addr.sin.sin_addr.s_addr == INADDR_ANY;
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
  case AF_INET6:
    return memcmp(&in6addr_any,
                  &a->addr.sin6.sin6_addr,
                  sizeof(in6addr_any)) == 0;
#endif /* COAP_IPV6_SUPPORT */
  default:
    ;
  }

  return 0;
}
#endif /* ! WITH_LWIP && ! WITH_CONTIKI */
