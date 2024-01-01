/* coap_debug.c -- debug utilities
 *
 * Copyright (C) 2010--2012,2014--2024 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_debug.c
 * @brief Debug utilities
 */

#include "coap3/coap_internal.h"

#if defined(HAVE_STRNLEN) && defined(__GNUC__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef WITH_LWIP
# define fprintf(fd, ...) LWIP_PLATFORM_DIAG((__VA_ARGS__))
# define fflush(...)
#endif

#ifdef WITH_CONTIKI
# define fprintf(fd, ...) { (void)fd; printf(__VA_ARGS__); }
# define fflush(...)
# define vfprintf(fd, ...) { (void)fd; printf(__VA_ARGS__); }

# ifndef LOG_CONF_LEVEL_COAP
#  define LOG_CONF_LEVEL_COAP 2 /* = LOG_LEVEL_WARN */
# endif
static coap_log_t maxlog = LOG_CONF_LEVEL_COAP == 0 ? /* = LOG_LEVEL_NONE */
                           COAP_LOG_EMERG :
                           (LOG_CONF_LEVEL_COAP == 1 ?  /* = LOG_LEVEL_ERR */
                            COAP_LOG_ERR :
                            (LOG_CONF_LEVEL_COAP == 2 ?  /* = LOG_LEVEL_WARN */
                             COAP_LOG_WARN :
                             (LOG_CONF_LEVEL_COAP == 3 ? /* = LOG_LEVEL_INFO */
                              COAP_LOG_INFO :
                              COAP_LOG_DEBUG)));
#else /* !WITH_CONTIKI */
static coap_log_t maxlog = COAP_LOG_WARN;  /* default maximum CoAP log level */
#endif /* !WITH_CONTIKI */

#ifdef RIOT_VERSION
#include "flash_utils.h"
#endif /* RIOT_VERSION */

static int use_fprintf_for_show_pdu = 1; /* non zero to output with fprintf */

const char *
coap_package_name(void) {
  return PACKAGE_NAME;
}

const char *
coap_package_version(void) {
  return PACKAGE_STRING;
}

const char *
coap_package_build(void) {
#ifdef LIBCOAP_PACKAGE_BUILD
  return LIBCOAP_PACKAGE_BUILD;
#else /* !LIBCOAP_PACKAGE_BUILD */
  return PACKAGE_STRING;
#endif /* !LIBCOAP_PACKAGE_BUILD */
}

void
coap_set_show_pdu_output(int use_fprintf) {
  use_fprintf_for_show_pdu = use_fprintf;
}

coap_log_t
coap_get_log_level(void) {
  return maxlog;
}

void
coap_set_log_level(coap_log_t level) {
  if (level > COAP_MAX_LOGGING_LEVEL)
    level = COAP_MAX_LOGGING_LEVEL;
  maxlog = level;
}

/* this array has the same order as the type coap_log_t with the (D)TLS
   entries added to the list with a COAP_LOG_DTLS_BASE offset */
static const char *loglevels[] = {
  /* General logging */
  "EMRG", "ALRT", "CRIT", "ERR ", "WARN", "NOTE", "INFO", "DEBG", "OSC ",
  /* (D)TLS logging */
  "Emrg", "Alrt", "Crit", "Err ", "Warn", "Note", "Info", "Debg"
};

const char *
coap_log_level_desc(coap_log_t level) {
  static char bad[8];
  if (level >= sizeof(loglevels)/sizeof(loglevels[0])) {
    snprintf(bad, sizeof(bad), "%4d", level);
    return bad;
  } else {
    return loglevels[level];
  }
}

#ifdef WITH_CONTIKI
void
coap_print_contiki_prefix(coap_log_t level) {
  printf("[%s: COAP      ] ", coap_log_level_desc(level));
}
#endif /* WITH_CONTIKI */

#ifdef HAVE_TIME_H

COAP_STATIC_INLINE size_t
print_timestamp(char *s, size_t len, coap_tick_t t) {
  struct tm *tmp;
  size_t lensofar;
  time_t now = coap_ticks_to_rt(t);
  tmp = localtime(&now);
  lensofar = strftime(s, len, "%b %d %H:%M:%S", tmp);
  if (len > lensofar + 4) {
    lensofar += snprintf(&s[lensofar], len-lensofar, ".%03u",
                         (unsigned int)((coap_ticks_to_rt_us(t) % 1000000)/1000));
  }
  return lensofar;
}

#else /* alternative implementation: just print the timestamp */

COAP_STATIC_INLINE size_t
print_timestamp(char *s, size_t len, coap_tick_t t) {
#ifdef HAVE_SNPRINTF
  return snprintf(s, len, "%u.%03u",
                  (unsigned int)coap_ticks_to_rt(t),
                  (unsigned int)((coap_ticks_to_rt_us(t) % 1000000)/1000));
#else /* HAVE_SNPRINTF */
  /* @todo do manual conversion of timestamp */
  return 0;
#endif /* HAVE_SNPRINTF */
}

#endif /* HAVE_TIME_H */

#if !defined(HAVE_STRNLEN) && !defined(__MINGW32__)
/**
 * A length-safe strlen() fake.
 *
 * @param s      The string to count characters != 0.
 * @param maxlen The maximum length of @p s.
 *
 * @return The length of @p s.
 */
static inline size_t
strnlen(const char *s, size_t maxlen) {
  size_t n = 0;
  while (*s++ && n < maxlen)
    ++n;
  return n;
}
#endif /* HAVE_STRNLEN && !__MINGW32__ */

static size_t
print_readable(const uint8_t *data, size_t len,
               unsigned char *result, size_t buflen, int encode_always) {
  const uint8_t hex[] = "0123456789ABCDEF";
  size_t cnt = 0;
  assert(data || len == 0);

  if (buflen == 0) { /* there is nothing we can do here but return */
    return 0;
  }

  while (len) {
    if (!encode_always && isprint(*data)) {
      if (cnt+1 < buflen) { /* keep one byte for terminating zero */
        *result++ = *data;
        ++cnt;
      } else {
        break;
      }
    } else {
      if (cnt+4 < buflen) { /* keep one byte for terminating zero */
        *result++ = '\\';
        *result++ = 'x';
        *result++ = hex[(*data & 0xf0) >> 4];
        *result++ = hex[*data & 0x0f];
        cnt += 4;
      } else
        break;
    }

    ++data;
    --len;
  }

  *result = '\0'; /* add a terminating zero */
  return cnt;
}

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
/*
 * Returned buf is always NULL terminated.
 * Returned size is number of characters, not including NULL terminator.
 */
size_t
coap_print_addr(const coap_address_t *addr, unsigned char *buf, size_t len) {
#if defined( HAVE_ARPA_INET_H ) || defined( HAVE_WS2TCPIP_H )
  char scratch[INET6_ADDRSTRLEN];

  assert(buf);
  assert(len);
  buf[0] = '\000';

  switch (addr->addr.sa.sa_family) {
#if COAP_IPV4_SUPPORT
  case AF_INET:
    snprintf((char *)buf, len, "%s:%d",
             coap_print_ip_addr(addr, scratch, sizeof(scratch)),
             coap_address_get_port(addr));
    break;
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
  case AF_INET6:
    snprintf((char *)buf, len, "[%s]:%d",
             coap_print_ip_addr(addr, scratch, sizeof(scratch)),
             coap_address_get_port(addr));
    break;
#endif /* COAP_IPV6_SUPPORT */
#if COAP_AF_UNIX_SUPPORT
  case AF_UNIX:
    snprintf((char *)buf, len, "'%s'", addr->addr.cun.sun_path);
    break;
#endif /* COAP_AF_UNIX_SUPPORT */
  default:
    /* Include trailing NULL if possible */
    memcpy(buf, "(unknown address type)", min(22+1, len));
    buf[len-1] = '\000';
    break;
  }
  return strlen((char *)buf);

#else /* HAVE_ARPA_INET_H */

# if WITH_CONTIKI

  char scratch[INET6_ADDRSTRLEN];
#ifdef HAVE_SNPRINTF

  snprintf((char *)buf, len, "[%s]:%d",
           coap_print_ip_addr(addr, scratch, sizeof(scratch)),
           coap_address_get_port(addr));
  return strlen((char *)buf);
#else /* HAVE_SNPRINTF */
  unsigned char *p = buf;
#  if NETSTACK_CONF_WITH_IPV6

  assert(buf);
  assert(len);
  buf[0] = '\000';
  if (len < 40 + 2 + 6)
    return 0;

  *p++ = '[';
  memcpy(p, coap_print_ip_addr(addr, scratch, sizeof(scratch)), 40);
  p += 40 - 1;
  *p++ = ']';
#  else /* WITH_UIP6 */
#   warning "IPv4 network addresses will not be included in debug output"

  if (len < 21) {
    *p = '\000';
    return 0;
  }
#  endif /* WITH_UIP6 */

  *p++ = ':';
  *p++ = '0' + (coap_address_get_port(addr) / 10000) % 10;
  *p++ = '0' + (coap_address_get_port(addr) / 1000) % 10;
  *p++ = '0' + (coap_address_get_port(addr) / 100) % 10;
  *p++ = '0' + (coap_address_get_port(addr) / 10) % 10;
  *p++ = '0' + coap_address_get_port(addr) % 10;
  *p = '\000';

  return strlen((char *)buf);
#endif /* HAVE_SNPRINTF */

# elif WITH_LWIP

  char scratch[INET6_ADDRSTRLEN];
#ifdef HAVE_SNPRINTF

  snprintf((char *)buf, len, "[%s]:%d",
           coap_print_ip_addr(addr, scratch, sizeof(scratch)),
           addr->port);
  return strlen((char *)buf);
#else /* HAVE_SNPRINTF */
  unsigned char *p = buf;

  assert(buf);
  assert(len);
  buf[0] = '\000';

  switch (IP_GET_TYPE(addr->addr)) {
  case IPADDR_TYPE_V4:
    if (len < IP4ADDR_STRLEN_MAX + 6)
      return 0;
    memcpy(buf, coap_print_ip_addr(addr, scratch, sizeof(scratch)), IP4ADDR_STRLEN_MAX);
    p += strlen((char *)buf);
    break;
#if LWIP_IPV6
  case IPADDR_TYPE_V6:
  case IPADDR_TYPE_ANY:
    if (len < 40 + 2 + 6)
      return 0;
    *p++ = '[';
    memcpy(p, coap_print_ip_addr(addr, scratch, sizeof(scratch)), 40);
    p += strlen((char *)buf);
    *p++ = ']';
    break;
#endif /* LWIP_IPV6 */
  }

  *p++ = ':';
  *p++ = '0' + (addr->port / 10000) % 10;
  *p++ = '0' + (addr->port / 1000) % 10;
  *p++ = '0' + (addr->port / 100) % 10;
  *p++ = '0' + (addr->port / 10) % 10;
  *p++ = '0' + addr->port % 10;
  *p = '\000';

  return strlen((char *)buf);
#endif /* HAVE_SNPRINTF */

# else /* ! WITH_CONTIKI && ! WITH_LWIP */

  (void)addr;
  (void)len;

  /* TODO: output addresses manually */
#   warning "inet_ntop() not available, network addresses will not be included in debug output"
# endif /* ! WITH_CONTIKI  && ! WITH_LWIP */
  buf[0] = '\000';
  return 0;
#endif
}

/*
 * Returned buf is always NULL terminated with as much as possible of the
 * IP address filled in.
 */
const char *
coap_print_ip_addr(const coap_address_t *addr, char *buf, size_t len) {
#if defined( HAVE_ARPA_INET_H ) || defined( HAVE_WS2TCPIP_H )
  const void *addrptr = NULL;

  assert(buf);
  assert(len);
  buf[0] = '\000';

  switch (addr->addr.sa.sa_family) {
#if COAP_IPV4_SUPPORT
  case AF_INET:
    if (len < INET_ADDRSTRLEN)
      return buf;
    addrptr = &addr->addr.sin.sin_addr;
    break;
#endif /* COAP_IPV4_SUPPORT */
#if COAP_IPV6_SUPPORT
  case AF_INET6:
    if (len < INET6_ADDRSTRLEN)
      return buf;
    addrptr = &addr->addr.sin6.sin6_addr;
    break;
#endif /* COAP_IPV6_SUPPORT */
#if COAP_AF_UNIX_SUPPORT
  case AF_UNIX:
    snprintf(buf, len, "'%s'", addr->addr.cun.sun_path);
    return buf;
#endif /* COAP_AF_UNIX_SUPPORT */
  default:
    /* Include trailing NULL if possible */
    memcpy(buf, "(unknown address type)", min(22+1, len));
    buf[len-1] = '\000';
    return buf;
  }

  /* Cast needed for Windows, since it doesn't have the correct API signature. */
  if (inet_ntop(addr->addr.sa.sa_family, addrptr, (char *)buf, len) == 0) {
    coap_log_err("coap_print_ip_addr: inet_ntop\n");
    buf[0] = '\000';
    return buf;
  }
  return buf;

#else /* HAVE_ARPA_INET_H */

# if WITH_CONTIKI
  char *p = buf;
  uint8_t i;
#  if NETSTACK_CONF_WITH_IPV6
  const char hex[] = "0123456789ABCDEF";

  assert(buf);
  assert(len);
  buf[0] = '\000';
  if (len < 40)
    return 0;

  for (i=0; i < 16; i += 2) {
    if (i) {
      *p++ = ':';
    }
    *p++ = hex[(addr->addr.u8[i] & 0xf0) >> 4];
    *p++ = hex[(addr->addr.u8[i] & 0x0f)];
    *p++ = hex[(addr->addr.u8[i+1] & 0xf0) >> 4];
    *p++ = hex[(addr->addr.u8[i+1] & 0x0f)];
  }
  *p = '\000';
#  else /* WITH_UIP6 */
#   warning "IPv4 network addresses will not be included in debug output"

  if (len < 21) {
    return buf;
  }
#  endif /* WITH_UIP6 */
  return buf;

# elif WITH_LWIP

  assert(buf);
  assert(len);
  buf[0] = '\000';

  switch (IP_GET_TYPE(&addr->addr)) {
#if LWIP_IPV4
  case IPADDR_TYPE_V4:
    if (len < IP4ADDR_STRLEN_MAX)
      return buf;
    memcpy(buf, ip4addr_ntoa(ip_2_ip4(&addr->addr)), IP4ADDR_STRLEN_MAX);
    break;
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
  case IPADDR_TYPE_V6:
  case IPADDR_TYPE_ANY:
    if (len < 40)
      return buf;
#if LWIP_IPV4
    memcpy(buf, ip6addr_ntoa(&addr->addr.u_addr.ip6), 40);
#else /* LWIP_IPV4 */
    memcpy(buf, ip6addr_ntoa(&addr->addr), 40);
#endif /* LWIP_IPV4 */
    break;
#endif /* LWIP_IPV6 */
  }
  return buf;

# else /* ! WITH_CONTIKI && ! WITH_LWIP */

  (void)addr;
  (void)len;

  /* TODO: output addresses manually */
#   warning "inet_ntop() not available, network addresses will not be included in debug output"
# endif /* WITH_CONTIKI */
  buf[0] = '\000';
  return buf;
#endif
}

/** Returns a textual description of the message type @p t. */
static const char *
msg_type_string(uint16_t t) {
  static const char *types[] = { "CON", "NON", "ACK", "RST", "???" };

  return types[min(t, sizeof(types)/sizeof(char *) - 1)];
}

/** Returns a textual description of the method or response code. */
static const char *
msg_code_string(uint16_t c) {
  static const char *methods[] = { "0.00", "GET", "POST", "PUT", "DELETE",
                                   "FETCH", "PATCH", "iPATCH"
                                 };
  static const char *signals[] = { "7.00", "CSM", "Ping", "Pong", "Release",
                                   "Abort"
                                 };
  static char buf[5];

  if (c < sizeof(methods)/sizeof(const char *)) {
    return methods[c];
  } else if (c >= 224 && c - 224 < (int)(sizeof(signals)/sizeof(const char *))) {
    return signals[c-224];
  } else {
    snprintf(buf, sizeof(buf), "%u.%02u", (c >> 5) & 0x7, c & 0x1f);
    return buf;
  }
}

/** Returns a textual description of the option name. */
static const char *
msg_option_string(uint8_t code, uint16_t option_type) {
  struct option_desc_t {
    uint16_t type;
    const char *name;
  };

  static struct option_desc_t options[] = {
    { COAP_OPTION_IF_MATCH, "If-Match" },
    { COAP_OPTION_URI_HOST, "Uri-Host" },
    { COAP_OPTION_ETAG, "ETag" },
    { COAP_OPTION_IF_NONE_MATCH, "If-None-Match" },
    { COAP_OPTION_OBSERVE, "Observe" },
    { COAP_OPTION_URI_PORT, "Uri-Port" },
    { COAP_OPTION_LOCATION_PATH, "Location-Path" },
    { COAP_OPTION_OSCORE, "Oscore" },
    { COAP_OPTION_URI_PATH, "Uri-Path" },
    { COAP_OPTION_CONTENT_FORMAT, "Content-Format" },
    { COAP_OPTION_MAXAGE, "Max-Age" },
    { COAP_OPTION_URI_QUERY, "Uri-Query" },
    { COAP_OPTION_HOP_LIMIT, "Hop-Limit" },
    { COAP_OPTION_ACCEPT, "Accept" },
    { COAP_OPTION_LOCATION_QUERY, "Location-Query" },
    { COAP_OPTION_BLOCK2, "Block2" },
    { COAP_OPTION_BLOCK1, "Block1" },
    { COAP_OPTION_SIZE2, "Size2" },
    { COAP_OPTION_PROXY_URI, "Proxy-Uri" },
    { COAP_OPTION_PROXY_SCHEME, "Proxy-Scheme" },
    { COAP_OPTION_SIZE1, "Size1" },
    { COAP_OPTION_ECHO, "Echo" },
    { COAP_OPTION_NORESPONSE, "No-Response" },
    { COAP_OPTION_RTAG, "Request-Tag" },
    { COAP_OPTION_Q_BLOCK1, "Q-Block1" },
    { COAP_OPTION_Q_BLOCK2, "Q-Block2" }
  };

  static struct option_desc_t options_csm[] = {
    { COAP_SIGNALING_OPTION_MAX_MESSAGE_SIZE, "Max-Message-Size" },
    { COAP_SIGNALING_OPTION_BLOCK_WISE_TRANSFER, "Block-Wise-Transfer" },
    { COAP_SIGNALING_OPTION_EXTENDED_TOKEN_LENGTH, "Extended-Token-Length" }
  };

  static struct option_desc_t options_pingpong[] = {
    { COAP_SIGNALING_OPTION_CUSTODY, "Custody" }
  };

  static struct option_desc_t options_release[] = {
    { COAP_SIGNALING_OPTION_ALTERNATIVE_ADDRESS, "Alternative-Address" },
    { COAP_SIGNALING_OPTION_HOLD_OFF, "Hold-Off" }
  };

  static struct option_desc_t options_abort[] = {
    { COAP_SIGNALING_OPTION_BAD_CSM_OPTION, "Bad-CSM-Option" }
  };

  static char buf[6];
  size_t i;

  if (code == COAP_SIGNALING_CSM) {
    for (i = 0; i < sizeof(options_csm)/sizeof(struct option_desc_t); i++) {
      if (option_type == options_csm[i].type) {
        return options_csm[i].name;
      }
    }
  } else if (code == COAP_SIGNALING_PING || code == COAP_SIGNALING_PONG) {
    for (i = 0; i < sizeof(options_pingpong)/sizeof(struct option_desc_t); i++) {
      if (option_type == options_pingpong[i].type) {
        return options_pingpong[i].name;
      }
    }
  } else if (code == COAP_SIGNALING_RELEASE) {
    for (i = 0; i < sizeof(options_release)/sizeof(struct option_desc_t); i++) {
      if (option_type == options_release[i].type) {
        return options_release[i].name;
      }
    }
  } else if (code == COAP_SIGNALING_ABORT) {
    for (i = 0; i < sizeof(options_abort)/sizeof(struct option_desc_t); i++) {
      if (option_type == options_abort[i].type) {
        return options_abort[i].name;
      }
    }
  } else {
    /* search option_type in list of known options */
    for (i = 0; i < sizeof(options)/sizeof(struct option_desc_t); i++) {
      if (option_type == options[i].type) {
        return options[i].name;
      }
    }
  }
  /* unknown option type, just print to buf */
  snprintf(buf, sizeof(buf), "%u", option_type);
  return buf;
}

static unsigned int
print_content_format(unsigned int format_type,
                     unsigned char *result, unsigned int buflen) {
  struct desc_t {
    unsigned int type;
    const char *name;
  };

  static struct desc_t formats[] = {
    { COAP_MEDIATYPE_TEXT_PLAIN, "text/plain" },
    { COAP_MEDIATYPE_APPLICATION_LINK_FORMAT, "application/link-format" },
    { COAP_MEDIATYPE_APPLICATION_XML, "application/xml" },
    { COAP_MEDIATYPE_APPLICATION_OCTET_STREAM, "application/octet-stream" },
    { COAP_MEDIATYPE_APPLICATION_RDF_XML, "application/rdf+xml" },
    { COAP_MEDIATYPE_APPLICATION_EXI, "application/exi" },
    { COAP_MEDIATYPE_APPLICATION_JSON, "application/json" },
    { COAP_MEDIATYPE_APPLICATION_CBOR, "application/cbor" },
    { COAP_MEDIATYPE_APPLICATION_CWT, "application/cwt" },
    { COAP_MEDIATYPE_APPLICATION_COAP_GROUP_JSON, "application/coap-group+json" },
    { COAP_MEDIATYPE_APPLICATION_COSE_SIGN, "application/cose; cose-type=\"cose-sign\"" },
    { COAP_MEDIATYPE_APPLICATION_COSE_SIGN1, "application/cose; cose-type=\"cose-sign1\"" },
    { COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT, "application/cose; cose-type=\"cose-encrypt\"" },
    { COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT0, "application/cose; cose-type=\"cose-encrypt0\"" },
    { COAP_MEDIATYPE_APPLICATION_COSE_MAC, "application/cose; cose-type=\"cose-mac\"" },
    { COAP_MEDIATYPE_APPLICATION_COSE_MAC0, "application/cose; cose-type=\"cose-mac0\"" },
    { COAP_MEDIATYPE_APPLICATION_COSE_KEY, "application/cose-key" },
    { COAP_MEDIATYPE_APPLICATION_COSE_KEY_SET, "application/cose-key-set" },
    { COAP_MEDIATYPE_APPLICATION_SENML_JSON, "application/senml+json" },
    { COAP_MEDIATYPE_APPLICATION_SENSML_JSON, "application/sensml+json" },
    { COAP_MEDIATYPE_APPLICATION_SENML_CBOR, "application/senml+cbor" },
    { COAP_MEDIATYPE_APPLICATION_SENSML_CBOR, "application/sensml+cbor" },
    { COAP_MEDIATYPE_APPLICATION_SENML_EXI, "application/senml-exi" },
    { COAP_MEDIATYPE_APPLICATION_SENSML_EXI, "application/sensml-exi" },
    { COAP_MEDIATYPE_APPLICATION_SENML_XML, "application/senml+xml" },
    { COAP_MEDIATYPE_APPLICATION_SENSML_XML, "application/sensml+xml" },
    { COAP_MEDIATYPE_APPLICATION_DOTS_CBOR, "application/dots+cbor" },
    { COAP_MEDIATYPE_APPLICATION_ACE_CBOR, "application/ace+cbor" },
    { COAP_MEDIATYPE_APPLICATION_MB_CBOR_SEQ, "application/missing-blocks+cbor-seq" },
    { COAP_MEDIATYPE_APPLICATION_OSCORE, "application/oscore" },
    { 75, "application/dcaf+cbor" }
  };

  size_t i;

  /* search format_type in list of known content formats */
  for (i = 0; i < sizeof(formats)/sizeof(struct desc_t); i++) {
    if (format_type == formats[i].type) {
      return snprintf((char *)result, buflen, "%s", formats[i].name);
    }
  }

  /* unknown content format, just print numeric value to buf */
  return snprintf((char *)result, buflen, "%d", format_type);
}

/**
 * Returns 1 if the given @p content_format is either unknown or known
 * to carry binary data. The return value @c 0 hence indicates
 * printable data which is also assumed if @p content_format is @c 01.
 */
COAP_STATIC_INLINE int
is_binary(int content_format) {
  return !(content_format == -1 ||
           content_format == COAP_MEDIATYPE_TEXT_PLAIN ||
           content_format == COAP_MEDIATYPE_APPLICATION_LINK_FORMAT ||
           content_format == COAP_MEDIATYPE_APPLICATION_XML ||
           content_format == COAP_MEDIATYPE_APPLICATION_JSON);
}

#define COAP_DO_SHOW_OUTPUT_LINE           \
  do {                                      \
    if (use_fprintf_for_show_pdu) {         \
      fprintf(COAP_DEBUG_FD, "%s", outbuf); \
    }                                       \
    else {                                  \
      coap_log(level, "%s", outbuf);        \
    }                                       \
  } while (0)

/*
 * It is possible to override the output debug buffer size and hence control
 * the amount of information printed out about a CoAP PDU.
 * Note: Adding a byte may be insufficient to output the next byte of the PDU.
 *
 * This is done by the adding of a -DCOAP_DEBUG_BUF_SIZE=nnnn option to the
 * CPPFLAGS parameter that is optionally used on the ./configure command line.
 *
 * E.g.  ./configure CPPFLAGS="-DCOAP_DEBUG_BUF_SIZE=4096"
 *
 */

#if COAP_DEBUG_BUF_SIZE < 5
#error "COAP_DEBUG_BUF_SIZE must be at least 5, should be >= 32 to be useful"
#endif /* COAP_DEBUG_BUF_SIZE < 5 */

void
coap_show_pdu(coap_log_t level, const coap_pdu_t *pdu) {
#if COAP_CONSTRAINED_STACK
  /* Proxy-Uri: can be 1034 bytes long */
  /* buf and outbuf protected by mutex m_show_pdu */
  static unsigned char buf[min(COAP_DEBUG_BUF_SIZE, 1035)];
  static char outbuf[COAP_DEBUG_BUF_SIZE];
#else /* ! COAP_CONSTRAINED_STACK */
  /* Proxy-Uri: can be 1034 bytes long */
  unsigned char buf[min(COAP_DEBUG_BUF_SIZE, 1035)];
  char outbuf[COAP_DEBUG_BUF_SIZE];
#endif /* ! COAP_CONSTRAINED_STACK */
  size_t buf_len = 0; /* takes the number of bytes written to buf */
  int encode = 0, have_options = 0;
  uint32_t i;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  int content_format = -1;
  size_t data_len;
  const uint8_t *data;
  uint32_t opt_len;
  const uint8_t *opt_val;
  size_t outbuflen = 0;
  int is_oscore_payload = 0;

  /* Save time if not needed */
  if (level > coap_get_log_level())
    return;

#if COAP_CONSTRAINED_STACK
  coap_mutex_lock(&m_show_pdu);
#endif /* COAP_CONSTRAINED_STACK */

  if (!pdu->session || COAP_PROTO_NOT_RELIABLE(pdu->session->proto)) {
    snprintf(outbuf, sizeof(outbuf), "v:%d t:%s c:%s i:%04x {",
             COAP_DEFAULT_VERSION, msg_type_string(pdu->type),
             msg_code_string(pdu->code), pdu->mid);
  } else if (pdu->session->proto == COAP_PROTO_WS ||
             pdu->session->proto == COAP_PROTO_WSS) {
    if (pdu->type != COAP_MESSAGE_CON)
      coap_log_alert("WebSocket: type != CON\n");
    snprintf(outbuf, sizeof(outbuf), "v:WebSocket c:%s {",
             msg_code_string(pdu->code));
  } else {
    if (pdu->type != COAP_MESSAGE_CON)
      coap_log_alert("Reliable: type != CON\n");
    snprintf(outbuf, sizeof(outbuf), "v:Reliable c:%s {",
             msg_code_string(pdu->code));
  }

  for (i = 0; i < pdu->actual_token.length; i++) {
    outbuflen = strlen(outbuf);
    snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,
             "%02x", pdu->actual_token.s[i]);
  }
  outbuflen = strlen(outbuf);
  snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  "}");

  /* show options, if any */
  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);

  outbuflen = strlen(outbuf);
  snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  " [");
  while ((option = coap_option_next(&opt_iter))) {
    buf[0] = '\000';
    if (!have_options) {
      have_options = 1;
    } else {
      outbuflen = strlen(outbuf);
      snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  ",");
    }

    if (pdu->code == COAP_SIGNALING_CODE_CSM) {
      switch (opt_iter.number) {
      case COAP_SIGNALING_OPTION_EXTENDED_TOKEN_LENGTH:
      case COAP_SIGNALING_OPTION_MAX_MESSAGE_SIZE:
        buf_len = snprintf((char *)buf, sizeof(buf), "%u",
                           coap_decode_var_bytes(coap_opt_value(option),
                                                 coap_opt_length(option)));
        break;
      default:
        buf_len = 0;
        break;
      }
    } else if (pdu->code == COAP_SIGNALING_CODE_PING ||
               pdu->code == COAP_SIGNALING_CODE_PONG) {
      buf_len = 0;
    } else if (pdu->code == COAP_SIGNALING_CODE_RELEASE) {
      switch (opt_iter.number) {
      case COAP_SIGNALING_OPTION_ALTERNATIVE_ADDRESS:
        buf_len = print_readable(coap_opt_value(option),
                                 coap_opt_length(option),
                                 buf, sizeof(buf), 0);
        break;
      case COAP_SIGNALING_OPTION_HOLD_OFF:
        buf_len = snprintf((char *)buf, sizeof(buf), "%u",
                           coap_decode_var_bytes(coap_opt_value(option),
                                                 coap_opt_length(option)));
        break;
      default:
        buf_len = 0;
        break;
      }
    } else if (pdu->code == COAP_SIGNALING_CODE_ABORT) {
      switch (opt_iter.number) {
      case COAP_SIGNALING_OPTION_BAD_CSM_OPTION:
        buf_len = snprintf((char *)buf, sizeof(buf), "%u",
                           coap_decode_var_bytes(coap_opt_value(option),
                                                 coap_opt_length(option)));
        break;
      default:
        buf_len = 0;
        break;
      }
    } else {
      switch (opt_iter.number) {
      case COAP_OPTION_CONTENT_FORMAT:
      case COAP_OPTION_ACCEPT:
        content_format = (int)coap_decode_var_bytes(coap_opt_value(option),
                                                    coap_opt_length(option));

        buf_len = print_content_format(content_format, buf, sizeof(buf));
        break;

      case COAP_OPTION_BLOCK1:
      case COAP_OPTION_BLOCK2:
      case COAP_OPTION_Q_BLOCK1:
      case COAP_OPTION_Q_BLOCK2:
        /* split block option into number/more/size where more is the
         * letter M if set, the _ otherwise */
        if (COAP_OPT_BLOCK_SZX(option) == 7) {
          if (coap_get_data(pdu, &data_len, &data))
            buf_len = snprintf((char *)buf, sizeof(buf), "%u/%c/BERT(%zu)",
                               coap_opt_block_num(option), /* block number */
                               COAP_OPT_BLOCK_MORE(option) ? 'M' : '_', /* M bit */
                               data_len);
          else
            buf_len = snprintf((char *)buf, sizeof(buf), "%u/%c/BERT",
                               coap_opt_block_num(option), /* block number */
                               COAP_OPT_BLOCK_MORE(option) ? 'M' : '_'); /* M bit */
        } else {
          buf_len = snprintf((char *)buf, sizeof(buf), "%u/%c/%u",
                             coap_opt_block_num(option), /* block number */
                             COAP_OPT_BLOCK_MORE(option) ? 'M' : '_', /* M bit */
                             (1 << (COAP_OPT_BLOCK_SZX(option) + 4))); /* block size */
        }

        break;

      case COAP_OPTION_OSCORE:
        opt_len = coap_opt_length(option);
        buf[0] = '\000';
        if (opt_len) {
          size_t ofs = 1;
          size_t cnt;

          opt_val = coap_opt_value(option);
          if (opt_val[0] & 0x20) {
            /* Group Flag */
            snprintf((char *)buf, sizeof(buf), "grp");
          }
          if (opt_val[0] & 0x07) {
            /* Partial IV */
            cnt = opt_val[0] & 0x07;
            if (cnt > opt_len - ofs)
              goto no_more;
            buf_len = strlen((char *)buf);
            snprintf((char *)&buf[buf_len], sizeof(buf)-buf_len, "%spIV=0x",
                     buf_len ? "," : "");
            for (i = 0; (uint32_t)i < cnt; i++) {
              buf_len = strlen((char *)buf);
              snprintf((char *)&buf[buf_len], sizeof(buf)-buf_len,
                       "%02x", opt_val[ofs + i]);
            }
            ofs += cnt;
          }
          if (opt_val[0] & 0x10) {
            /* kid context */
            if (ofs >= opt_len)
              goto no_more;
            cnt = opt_val[ofs];
            if (cnt > opt_len - ofs - 1)
              goto no_more;
            ofs++;
            buf_len = strlen((char *)buf);
            snprintf((char *)&buf[buf_len], sizeof(buf)-buf_len, "%skc=0x",
                     buf_len ? "," : "");
            for (i = 0; (uint32_t)i < cnt; i++) {
              buf_len = strlen((char *)buf);
              snprintf((char *)&buf[buf_len], sizeof(buf)-buf_len,
                       "%02x", opt_val[ofs + i]);
            }
            ofs += cnt;
          }
          if (opt_val[0] & 0x08) {
            /* kid */
            if (ofs >= opt_len)
              goto no_more;
            cnt = opt_len - ofs;
            buf_len = strlen((char *)buf);
            snprintf((char *)&buf[buf_len], sizeof(buf)-buf_len, "%skid=0x",
                     buf_len ? "," : "");
            for (i = 0; (uint32_t)i < cnt; i++) {
              buf_len = strlen((char *)buf);
              snprintf((char *)&buf[buf_len], sizeof(buf)-buf_len,
                       "%02x", opt_val[ofs + i]);
            }
          }
        }
no_more:
        buf_len = strlen((char *)buf);
        is_oscore_payload = 1;
        break;

      case COAP_OPTION_URI_PORT:
      case COAP_OPTION_MAXAGE:
      case COAP_OPTION_OBSERVE:
      case COAP_OPTION_SIZE1:
      case COAP_OPTION_SIZE2:
      case COAP_OPTION_HOP_LIMIT:
        if (coap_opt_length(option)) {
          /* show values as unsigned decimal value */
          buf_len = snprintf((char *)buf, sizeof(buf), "%u",
                             coap_decode_var_bytes(coap_opt_value(option),
                                                   coap_opt_length(option)));
        }
        break;

      case COAP_OPTION_IF_MATCH:
      case COAP_OPTION_ETAG:
      case COAP_OPTION_ECHO:
      case COAP_OPTION_NORESPONSE:
      case COAP_OPTION_RTAG:
        opt_len = coap_opt_length(option);
        opt_val = coap_opt_value(option);
        snprintf((char *)buf, sizeof(buf), "0x");
        for (i = 0; (uint32_t)i < opt_len; i++) {
          buf_len = strlen((char *)buf);
          snprintf((char *)&buf[buf_len], sizeof(buf)-buf_len,
                   "%02x", opt_val[i]);
        }
        buf_len = strlen((char *)buf);
        break;
      default:
        /* generic output function for all other option types */
        if (opt_iter.number == COAP_OPTION_URI_PATH ||
            opt_iter.number == COAP_OPTION_PROXY_URI ||
            opt_iter.number == COAP_OPTION_URI_HOST ||
            opt_iter.number == COAP_OPTION_LOCATION_PATH ||
            opt_iter.number == COAP_OPTION_LOCATION_QUERY ||
            opt_iter.number == COAP_OPTION_PROXY_SCHEME ||
            opt_iter.number == COAP_OPTION_URI_QUERY) {
          encode = 0;
        } else {
          encode = 1;
        }
        buf_len = print_readable(coap_opt_value(option),
                                 coap_opt_length(option),
                                 buf, sizeof(buf), encode);
      }
    }
    outbuflen = strlen(outbuf);
    snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,
             " %s:%.*s", msg_option_string(pdu->code, opt_iter.number),
             (int)buf_len, buf);
  }

  outbuflen = strlen(outbuf);
  snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  " ]");

  if (coap_get_data(pdu, &data_len, &data)) {

    outbuflen = strlen(outbuf);
    snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  " :: ");

    if (is_binary(content_format) || !isprint(data[0]) || is_oscore_payload) {
      size_t keep_data_len = data_len;
      const uint8_t *keep_data = data;

      outbuflen = strlen(outbuf);
      snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,
               "binary data length %zu\n", data_len);
      COAP_DO_SHOW_OUTPUT_LINE;
      /*
       * Output hex dump of binary data as a continuous entry
       */
      outbuf[0] = '\000';
      snprintf(outbuf, sizeof(outbuf),  "<<");
      while (data_len--) {
        outbuflen = strlen(outbuf);
        snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,
                 "%02x", *data++);
      }
      outbuflen = strlen(outbuf);
      snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  ">>");
      data_len = keep_data_len;
      data = keep_data;
      outbuflen = strlen(outbuf);
      if (outbuflen == sizeof(outbuf)-1)
        outbuflen--;
      snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  "\n");
      COAP_DO_SHOW_OUTPUT_LINE;
      /*
       * Output ascii readable (if possible), immediately under the
       * hex value of the character output above to help binary debugging
       */
      outbuf[0] = '\000';
      snprintf(outbuf, sizeof(outbuf),  "<<");
      while (data_len--) {
        outbuflen = strlen(outbuf);
        snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,
                 "%c ", isprint(*data) ? *data : '.');
        data++;
      }
      outbuflen = strlen(outbuf);
      snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  ">>");
    } else {
      size_t max_length;

      outbuflen = strlen(outbuf);
      max_length = sizeof(outbuf)-outbuflen;
      if (max_length > 1) {
        outbuf[outbuflen++] = '\'';
        outbuf[outbuflen] = '\000';
        max_length--;
      }
      if (max_length > 1) {
        outbuflen += print_readable(data, data_len,
                                    (unsigned char *)&outbuf[outbuflen],
                                    max_length, 0);
      }
      /* print_readable may be handling unprintables - hence headroom of 4 */
      if (outbuflen < sizeof(outbuf)-4-1) {
        outbuf[outbuflen++] = '\'';
        outbuf[outbuflen] = '\000';
      }
    }
  }

  outbuflen = strlen(outbuf);
  if (outbuflen == sizeof(outbuf)-1)
    outbuflen--;
  snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  "\n");
  COAP_DO_SHOW_OUTPUT_LINE;

#if COAP_CONSTRAINED_STACK
  coap_mutex_unlock(&m_show_pdu);
#endif /* COAP_CONSTRAINED_STACK */
}

void
coap_show_tls_version(coap_log_t level) {
  char buffer[128];
  coap_string_tls_version(buffer, sizeof(buffer));
  coap_log(level, "%s\n", buffer);
}

char *
coap_string_tls_version(char *buffer, size_t bufsize) {
  coap_tls_version_t *tls_version = coap_get_tls_library_version();
  char beta[8];
  char sub[2];
  char b_beta[8];
  char b_sub[2];

  switch (tls_version->type) {
  case COAP_TLS_LIBRARY_NOTLS:
    snprintf(buffer, bufsize, "TLS Library: None");
    break;
  case COAP_TLS_LIBRARY_TINYDTLS:
    snprintf(buffer, bufsize, "TLS Library: TinyDTLS - runtime %lu.%lu.%lu, "
             "libcoap built for %lu.%lu.%lu",
             (unsigned long)(tls_version->version >> 16),
             (unsigned long)((tls_version->version >> 8) & 0xff),
             (unsigned long)(tls_version->version & 0xff),
             (unsigned long)(tls_version->built_version >> 16),
             (unsigned long)((tls_version->built_version >> 8) & 0xff),
             (unsigned long)(tls_version->built_version & 0xff));
    break;
  case COAP_TLS_LIBRARY_OPENSSL:
    switch (tls_version->version &0xf) {
    case 0:
      strcpy(beta, "-dev");
      break;
    case 0xf:
      strcpy(beta, "");
      break;
    default:
      strcpy(beta, "-beta");
      beta[5] = (tls_version->version &0xf) + '0';
      beta[6] = '\000';
      break;
    }
    sub[0] = ((tls_version->version >> 4) & 0xff) ?
             ((tls_version->version >> 4) & 0xff) + 'a' -1 : '\000';
    sub[1] = '\000';
    switch (tls_version->built_version &0xf) {
    case 0:
      strcpy(b_beta, "-dev");
      break;
    case 0xf:
      strcpy(b_beta, "");
      break;
    default:
      strcpy(b_beta, "-beta");
      b_beta[5] = (tls_version->built_version &0xf) + '0';
      b_beta[6] = '\000';
      break;
    }
    b_sub[0] = ((tls_version->built_version >> 4) & 0xff) ?
               ((tls_version->built_version >> 4) & 0xff) + 'a' -1 : '\000';
    b_sub[1] = '\000';
    snprintf(buffer, bufsize, "TLS Library: OpenSSL - runtime "
             "%lu.%lu.%lu%s%s, libcoap built for %lu.%lu.%lu%s%s",
             (unsigned long)(tls_version->version >> 28),
             (unsigned long)((tls_version->version >> 20) & 0xff),
             (unsigned long)((tls_version->version >> 12) & 0xff), sub, beta,
             (unsigned long)(tls_version->built_version >> 28),
             (unsigned long)((tls_version->built_version >> 20) & 0xff),
             (unsigned long)((tls_version->built_version >> 12) & 0xff),
             b_sub, b_beta);
    break;
  case COAP_TLS_LIBRARY_GNUTLS:
    snprintf(buffer, bufsize, "TLS Library: GnuTLS - runtime %lu.%lu.%lu, "
             "libcoap built for %lu.%lu.%lu",
             (unsigned long)(tls_version->version >> 16),
             (unsigned long)((tls_version->version >> 8) & 0xff),
             (unsigned long)(tls_version->version & 0xff),
             (unsigned long)(tls_version->built_version >> 16),
             (unsigned long)((tls_version->built_version >> 8) & 0xff),
             (unsigned long)(tls_version->built_version & 0xff));
    break;
  case COAP_TLS_LIBRARY_MBEDTLS:
    snprintf(buffer, bufsize, "TLS Library: Mbed TLS - runtime %lu.%lu.%lu, "
             "libcoap built for %lu.%lu.%lu",
             (unsigned long)(tls_version->version >> 24),
             (unsigned long)((tls_version->version >> 16) & 0xff),
             (unsigned long)((tls_version->version >> 8) & 0xff),
             (unsigned long)(tls_version->built_version >> 24),
             (unsigned long)((tls_version->built_version >> 16) & 0xff),
             (unsigned long)((tls_version->built_version >> 8) & 0xff));
    break;
  default:
    snprintf(buffer, bufsize, "Library type %d unknown", tls_version->type);
    break;
  }
  return buffer;
}

char *
coap_string_tls_support(char *buffer, size_t bufsize) {
  const int have_tls = coap_tls_is_supported();
  const int have_dtls = coap_dtls_is_supported();
  const int have_psk = coap_dtls_psk_is_supported();
  const int have_pki = coap_dtls_pki_is_supported();
  const int have_pkcs11 = coap_dtls_pkcs11_is_supported();
  const int have_rpk = coap_dtls_rpk_is_supported();
  const int have_oscore = coap_oscore_is_supported();
  const int have_ws = coap_ws_is_supported();

  if (have_dtls == 0 && have_tls == 0) {
    snprintf(buffer, bufsize, "(No DTLS or TLS support)");
    return buffer;
  }
  snprintf(buffer, bufsize,
           "(%sDTLS and %sTLS support; %sPSK, %sPKI, %sPKCS11, and %sRPK support)\n(%sOSCORE)\n(%sWebSockets)",
           have_dtls ? "" : "No ",
           have_tls ? "" : "no ",
           have_psk ? "" : "no ",
           have_pki ? "" : "no ",
           have_pkcs11 ? "" : "no ",
           have_rpk ? "" : "no ",
           have_oscore ? "Have " : "No ",
           have_ws ? "Have " : "No ");
  return buffer;
}

static coap_log_handler_t log_handler = NULL;

void
coap_set_log_handler(coap_log_handler_t handler) {
  log_handler = handler;
}

void
coap_log_impl(coap_log_t level, const char *format, ...) {

  if (log_handler) {
#if COAP_CONSTRAINED_STACK
    /* message protected by mutex m_log_impl */
    static char message[COAP_DEBUG_BUF_SIZE];
#else /* ! COAP_CONSTRAINED_STACK */
    char message[COAP_DEBUG_BUF_SIZE];
#endif /* ! COAP_CONSTRAINED_STACK */
    va_list ap;
    va_start(ap, format);

#if COAP_CONSTRAINED_STACK
    coap_mutex_lock(&m_log_impl);
#endif /* COAP_CONSTRAINED_STACK */

#ifdef RIOT_VERSION
    flash_vsnprintf(message, sizeof(message), format, ap);
#else /* !RIOT_VERSION */
    vsnprintf(message, sizeof(message), format, ap);
#endif /* !RIOT_VERSION */
    va_end(ap);
    log_handler(level, message);
#if COAP_CONSTRAINED_STACK
    coap_mutex_unlock(&m_log_impl);
#endif /* COAP_CONSTRAINED_STACK */
  } else {
    char timebuf[32];
    coap_tick_t now;
    va_list ap;
    FILE *log_fd;
    size_t len;

    log_fd = level <= COAP_LOG_CRIT ? COAP_ERR_FD : COAP_DEBUG_FD;

    coap_ticks(&now);
    len = print_timestamp(timebuf,sizeof(timebuf), now);
    if (len)
      fprintf(log_fd, "%.*s ", (int)len, timebuf);

    fprintf(log_fd, "%s ", coap_log_level_desc(level));

    va_start(ap, format);
#ifdef RIOT_VERSION
    flash_vfprintf(log_fd, format, ap);
#else /* !RIOT_VERSION */
    vfprintf(log_fd, format, ap);
#endif /* !RIOT_VERSION */
    va_end(ap);
    fflush(log_fd);
  }
}

static struct packet_num_interval {
  int start;
  int end;
} packet_loss_intervals[10];
static int num_packet_loss_intervals = 0;
static uint16_t packet_loss_level = 0;
static int send_packet_count = 0;

int
coap_debug_set_packet_loss(const char *loss_level) {
  const char *p = loss_level;
  char *end = NULL;
  int n = (int)strtol(p, &end, 10), i = 0;
  if (end == p || n < 0)
    return 0;
  if (*end == '%') {
    if (n > 100)
      n = 100;
    packet_loss_level = n * 65536 / 100;
    coap_log_debug("packet loss level set to %d%%\n", n);
  } else {
    if (n <= 0)
      return 0;
    while (i < 10) {
      packet_loss_intervals[i].start = n;
      if (*end == '-') {
        p = end + 1;
        n = (int)strtol(p, &end, 10);
        if (end == p || n <= 0)
          return 0;
      }
      packet_loss_intervals[i++].end = n;
      if (*end == 0)
        break;
      if (*end != ',')
        return 0;
      p = end + 1;
      n = (int)strtol(p, &end, 10);
      if (end == p || n <= 0)
        return 0;
    }
    if (i == 10)
      return 0;
    num_packet_loss_intervals = i;
  }
  send_packet_count = 0;
  return 1;
}

int
coap_debug_send_packet(void) {
  ++send_packet_count;
  if (num_packet_loss_intervals > 0) {
    int i;
    for (i = 0; i < num_packet_loss_intervals; i++) {
      if (send_packet_count >= packet_loss_intervals[i].start &&
          send_packet_count <= packet_loss_intervals[i].end) {
        coap_log_debug("Packet %u dropped\n", send_packet_count);
        return 0;
      }
    }
  }
  if (packet_loss_level > 0) {
    uint16_t r = 0;
    coap_prng((uint8_t *)&r, 2);
    if (r < packet_loss_level) {
      coap_log_debug("Packet %u dropped\n", send_packet_count);
      return 0;
    }
  }
  return 1;
}

void
coap_debug_reset(void) {
  log_handler = NULL;
  maxlog = COAP_LOG_WARN;
  use_fprintf_for_show_pdu = 1;
  memset(&packet_loss_intervals, 0, sizeof(packet_loss_intervals));
  num_packet_loss_intervals = 0;
  packet_loss_level = 0;
  send_packet_count = 0;
}
