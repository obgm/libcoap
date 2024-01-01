/* coap_uri.c -- helper functions for URI treatment
 *
 * Copyright (C) 2010--2012,2015-2016,2022-2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_uri.c
 * @brief URI handling functions
 */

#include "coap3/coap_internal.h"

#if defined(HAVE_LIMITS_H)
#include <limits.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/**
 * A length-safe version of strchr(). This function returns a pointer
 * to the first occurrence of @p c  in @p s, or @c NULL if not found.
 *
 * @param s   The string to search for @p c.
 * @param len The length of @p s.
 * @param c   The character to search.
 *
 * @return A pointer to the first occurence of @p c, or @c NULL
 * if not found.
 */
COAP_STATIC_INLINE const uint8_t *
strnchr(const uint8_t *s, size_t len, unsigned char c) {
  while (len && *s++ != c)
    --len;

  return len ? s : NULL;
}

typedef enum coap_uri_check_t {
  COAP_URI_CHECK_URI,
  COAP_URI_CHECK_PROXY
} coap_uri_check_t;

coap_uri_info_t coap_uri_scheme[COAP_URI_SCHEME_LAST] = {
  { "coap",       COAP_DEFAULT_PORT,  0, COAP_URI_SCHEME_COAP },
  { "coaps",      COAPS_DEFAULT_PORT, 0, COAP_URI_SCHEME_COAPS },
  { "coap+tcp",   COAP_DEFAULT_PORT,  0, COAP_URI_SCHEME_COAP_TCP },
  { "coaps+tcp",  COAPS_DEFAULT_PORT, 0, COAP_URI_SCHEME_COAPS_TCP },
  { "http",         80,               1, COAP_URI_SCHEME_HTTP },
  { "https",       443,               1, COAP_URI_SCHEME_HTTPS },
  { "coap+ws",      80,               0, COAP_URI_SCHEME_COAP_WS },
  { "coaps+ws",    443,               0, COAP_URI_SCHEME_COAPS_WS }
};

static int
coap_split_uri_sub(const uint8_t *str_var,
                   size_t len,
                   coap_uri_t *uri,
                   coap_uri_check_t check_proxy) {
  const uint8_t *p, *q;
  int res = 0;
  size_t i;
  int is_unix_domain = 0;

  if (!str_var || !uri || len == 0)
    return -1;

  memset(uri, 0, sizeof(coap_uri_t));
  uri->port = COAP_DEFAULT_PORT;

  /* search for scheme */
  p = str_var;
  if (*p == '/') {
    /* no scheme, host or port */
    if (check_proxy == COAP_URI_CHECK_PROXY) {
      /* Must have ongoing host if proxy definition */
      return -1;
    }
    q = p;
    goto path;
  }

  /* find scheme terminating :// */
  while (len >= 3 && !(p[0] == ':' && p[1] == '/' && p[2] == '/')) {
    ++p;
    --len;
  }
  if (len < 3) {
    /* scheme not defined with a :// terminator */
    res = -2;
    goto error;
  }
  for (i = 0; i < COAP_URI_SCHEME_LAST; i++) {
    if ((p - str_var) == (int)strlen(coap_uri_scheme[i].name) &&
        memcmp(str_var, coap_uri_scheme[i].name, p - str_var) == 0) {
      if (check_proxy != COAP_URI_CHECK_PROXY && coap_uri_scheme[i].proxy_only) {
        coap_log_err("%.*s URI scheme not enabled (not a proxy)\n",
                     (int)(p - str_var), str_var);
        return -1;
      }
      uri->scheme = coap_uri_scheme[i].scheme;
      uri->port = coap_uri_scheme[i].port;
      break;
    }
  }
  if (i == COAP_URI_SCHEME_LAST) {
    /* scheme unknown */
    coap_log_err("%.*s URI scheme unknown\n", (int)(p - str_var), str_var);
    res = -1;
    goto error;
  }
  switch (uri->scheme) {
  case COAP_URI_SCHEME_COAP:
    break;
  case COAP_URI_SCHEME_COAPS:
    if (!coap_dtls_is_supported()) {
      coap_log_err("coaps URI scheme not supported in this version of libcoap\n");
      return -1;
    }
    break;
  case COAP_URI_SCHEME_COAP_TCP:
    if (!coap_tcp_is_supported()) {
      coap_log_err("coap+tcp URI scheme not supported in this version of libcoap\n");
      return -1;
    }
    break;
  case COAP_URI_SCHEME_COAPS_TCP:
    if (!coap_tcp_is_supported()) {
      coap_log_err("coaps+tcp URI scheme not supported in this version of libcoap\n");
      return -1;
    }
    break;
  case COAP_URI_SCHEME_COAP_WS:
    if (!coap_ws_is_supported()) {
      coap_log_err("coap+ws URI scheme not supported in this version of libcoap\n");
      return -1;
    }
    break;
  case COAP_URI_SCHEME_COAPS_WS:
    if (!coap_wss_is_supported()) {
      coap_log_err("coaps+ws URI scheme not supported in this version of libcoap\n");
      return -1;
    }
    break;
  case COAP_URI_SCHEME_HTTP:
  case COAP_URI_SCHEME_HTTPS:
  case COAP_URI_SCHEME_LAST:
  default:
    coap_log_warn("Unsupported URI type %d\n", uri->scheme);
    return -1;
  }
  /* skip :// */
  p += 3;
  len -= 3;

  /* p points to beginning of Uri-Host */
  q = p;
  if (len && *p == '[') {
    /* IPv6 address reference */
    ++p;

    while (len && *q != ']') {
      ++q;
      --len;
    }

    if (!len || *q != ']' || p == q) {
      res = -3;
      goto error;
    }

    COAP_SET_STR(&uri->host, q - p, p);
    ++q;
    --len;
  } else {
    /* IPv4 address, FQDN or Unix domain socket */
    if (len >= 3 && p[0] == '%' && p[1] == '2' &&
        (p[2] == 'F' || p[2] == 'f')) {
      /* Unix domain definition */
      uri->port = 0;
      is_unix_domain = 1;
    }
    while (len && *q != ':' && *q != '/' && *q != '?') {
      ++q;
      --len;
    }

    if (p == q) {
      res = -3;
      goto error;
    }

    COAP_SET_STR(&uri->host, q - p, p);
  }

  /* check for Uri-Port (invalid for Unix) */
  if (len && *q == ':') {
    if (is_unix_domain) {
      res = -5;
      goto error;
    }
    p = ++q;
    --len;

    while (len && isdigit(*q)) {
      ++q;
      --len;
    }

    if (p < q) {                /* explicit port number given */
      long uri_port = 0;

      while ((p < q) && (uri_port <= UINT16_MAX))
        uri_port = uri_port * 10 + (*p++ - '0');

      /* check if port number is in allowed range */
      if (uri_port > UINT16_MAX) {
        res = -4;
        goto error;
      }

      uri->port = (uint16_t)uri_port;
    }
  }

path:                 /* at this point, p must point to an absolute path */

  if (!len)
    goto end;

  if (*q == '/') {
    p = ++q;
    --len;

    while (len && *q != '?') {
      ++q;
      --len;
    }

    if (p < q) {
      COAP_SET_STR(&uri->path, q - p, p);
      p = q;
    }
  }

  /* Uri_Query */
  if (len && *p == '?') {
    ++p;
    --len;
    COAP_SET_STR(&uri->query, len, p);
    len = 0;
  }

end:
  return len ? -1 : 0;

error:
  return res;
}

int
coap_split_uri(const uint8_t *str_var, size_t len, coap_uri_t *uri) {
  return coap_split_uri_sub(str_var, len, uri, COAP_URI_CHECK_URI);
}

int
coap_split_proxy_uri(const uint8_t *str_var, size_t len, coap_uri_t *uri) {
  return coap_split_uri_sub(str_var, len, uri, COAP_URI_CHECK_PROXY);
}

int
coap_uri_into_options(const coap_uri_t *uri, const coap_address_t *dst,
                      coap_optlist_t **optlist_chain, int create_port_host_opt,
                      uint8_t *_buf, size_t _buflen) {
  int res;
  unsigned char *buf = _buf;
  size_t buflen = _buflen;

  if (create_port_host_opt && !coap_host_is_unix_domain(&uri->host)) {
    int add_option = 0;

    if (dst && uri->host.length) {
#if !defined(WITH_LWIP) && !defined(WITH_CONTIKI)
      char addr[INET6_ADDRSTRLEN];
#else /* WITH_LWIP || WITH_CONTIKI */
      char addr[40];
#endif /* WITH_LWIP || WITH_CONTIKI */

      /* Add in UriHost if not match (need to strip off &iface) */
      size_t uri_host_len = uri->host.length;
      const uint8_t *cp = uri->host.s;

      /* Unfortunately not null terminated */
      for (size_t i = 0; i < uri_host_len; i++) {
        if (cp[i] == '%') {
          /* %iface specified in host name */
          uri_host_len = i;
          break;
        }
      }

      if (coap_print_ip_addr(dst, addr, sizeof(addr)) &&
          (strlen(addr) != uri_host_len ||
           memcmp(addr, uri->host.s, uri_host_len) != 0)) {
        /* add Uri-Host */
        coap_insert_optlist(optlist_chain,
                            coap_new_optlist(COAP_OPTION_URI_HOST,
                                             uri->host.length,
                                             uri->host.s));
      }
    }
    /* Add in UriPort if not default */
    switch ((int)uri->scheme) {
    case COAP_URI_SCHEME_HTTP:
    case COAP_URI_SCHEME_COAP_WS:
      if (uri->port != 80)
        add_option = 1;
      break;
    case COAP_URI_SCHEME_HTTPS:
    case COAP_URI_SCHEME_COAPS_WS:
      if (uri->port != 443)
        add_option = 1;
      break;
    default:
      if (uri->port != (coap_uri_scheme_is_secure(uri) ? COAPS_DEFAULT_PORT :
                        COAP_DEFAULT_PORT))
        add_option = 1;
      break;
    }
    if (add_option)
      coap_insert_optlist(optlist_chain,
                          coap_new_optlist(COAP_OPTION_URI_PORT,
                                           coap_encode_var_safe(buf, 4,
                                                                (uri->port & 0xffff)),
                                           buf));
  }

  if (uri->path.length) {
    if (uri->path.length > buflen)
      coap_log_warn("URI path will be truncated (max buffer %zu)\n",
                    buflen);
    res = coap_split_path(uri->path.s, uri->path.length, buf, &buflen);
    if (res < 0)
      return -1;

    while (res--) {
      coap_insert_optlist(optlist_chain,
                          coap_new_optlist(COAP_OPTION_URI_PATH,
                                           coap_opt_length(buf),
                                           coap_opt_value(buf)));

      buf += coap_opt_size(buf);
    }
  }

  if (uri->query.length) {
    buflen = _buflen;
    buf = _buf;
    if (uri->query.length > buflen)
      coap_log_warn("URI query will be truncated (max buffer %zu)\n",
                    buflen);
    res = coap_split_query(uri->query.s, uri->query.length, buf, &buflen);
    if (res < 0)
      return -1;

    while (res--) {
      coap_insert_optlist(optlist_chain,
                          coap_new_optlist(COAP_OPTION_URI_QUERY,
                                           coap_opt_length(buf),
                                           coap_opt_value(buf)));

      buf += coap_opt_size(buf);
    }
  }
  return 0;
}

int
coap_host_is_unix_domain(const coap_str_const_t *host) {
  if (host->length >= 3 && host->s[0] == '%' &&
      host->s[1] == '2' &&
      (host->s[2] == 'F' || host->s[2] == 'f')) {
    return 1;
  }
  if (host->length >= 1 && host->s[0] == '/')
    return 1;
  return 0;
}

/**
 * Calculates decimal value from hexadecimal ASCII character given in
 * @p c. The caller must ensure that @p c actually represents a valid
 * heaxdecimal character, e.g. with isxdigit(3).
 *
 * @hideinitializer
 */
#define hexchar_to_dec(c) ((c) & 0x40 ? ((c) & 0x0F) + 9 : ((c) & 0x0F))

/**
 * Decodes percent-encoded characters while copying the string @p seg
 * of size @p length to @p buf. The caller of this function must
 * ensure that the percent-encodings are correct (i.e. the character
 * '%' is always followed by two hex digits. and that @p buf provides
 * sufficient space to hold the result. This function is supposed to
 * be called by make_decoded_option() only.
 *
 * @param seg     The segment to decode and copy.
 * @param length  Length of @p seg.
 * @param buf     The result buffer.
 */
static void
decode_segment(const uint8_t *seg, size_t length, unsigned char *buf) {

  while (length--) {

    if (*seg == '%') {
      *buf = (hexchar_to_dec(seg[1]) << 4) + hexchar_to_dec(seg[2]);

      seg += 2;
      length -= 2;
    } else {
      *buf = *seg;
    }

    ++buf;
    ++seg;
  }
}

/**
 * Runs through the given path (or query) segment and checks if
 * percent-encodings are correct. This function returns @c 0 on success
 * and @c -1 on error.
 */
static int
check_segment(const uint8_t *s, size_t length, size_t *segment_size) {
  size_t n = 0;

  while (length) {
    if (*s == '%') {
      if (length < 2 || !(isxdigit(s[1]) && isxdigit(s[2])))
        return -1;

      s += 2;
      length -= 2;
    }

    ++s;
    ++n;
    --length;
  }

  *segment_size = n;

  return 0;
}

/**
 * Writes a coap option from given string @p s to @p buf. @p s should
 * point to a (percent-encoded) path or query segment of a coap_uri_t
 * object.  The created option will have type @c 0, and the length
 * parameter will be set according to the size of the decoded string.
 * On success, this function returns @c 0 and sets @p optionsize to the option's
 * size. On error the function returns a value less than zero. This function
 * must be called from coap_split_path_impl() only.
 *
 * @param s           The string to decode.
 * @param length      The size of the percent-encoded string @p s.
 * @param buf         The buffer to store the new coap option.
 * @param buflen      The maximum size of @p buf.
 * @param optionsize  The option's size.
 *
 * @return @c 0 on success and @c -1 on error.
 *
 * @bug This function does not split segments that are bigger than 270
 * bytes.
 */
static int
make_decoded_option(const uint8_t *s, size_t length,
                    unsigned char *buf, size_t buflen, size_t *optionsize) {
  int res;
  size_t segmentlen;
  size_t written;

  if (!buflen) {
    coap_log_debug("make_decoded_option(): buflen is 0!\n");
    return -1;
  }

  res = check_segment(s, length, &segmentlen);
  if (res < 0)
    return -1;

  /* write option header using delta 0 and length res */
  written = coap_opt_setheader(buf, buflen, 0, segmentlen);

  assert(written <= buflen);

  if (!written)                        /* encoding error */
    return -1;

  buf += written;                /* advance past option type/length */
  buflen -= written;

  if (buflen < segmentlen) {
    coap_log_debug("buffer too small for option\n");
    return -1;
  }

  decode_segment(s, length, buf);

  *optionsize = written + segmentlen;

  return 0;
}


#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

typedef void (*segment_handler_t)(const uint8_t *, size_t, void *);

/**
 * Checks if path segment @p s consists of one or two dots.
 */
COAP_STATIC_INLINE int
dots(const uint8_t *s, size_t len) {
  return len && *s == '.' && (len == 1 || (len == 2 && *(s+1) == '.'));
}

/**
 * Splits the given string into segments. You should call one of the
 * macros coap_split_path() or coap_split_query() instead.
 *
 * @param s      The URI string to be tokenized.
 * @param length The length of @p s.
 * @param h      A handler that is called with every token.
 * @param data   Opaque data that is passed to @p h when called.
 *
 * @return The number of characters that have been parsed from @p s.
 */
static size_t
coap_split_path_impl(const uint8_t *s, size_t length,
                     segment_handler_t h, void *data) {

  const uint8_t *p, *q;

  p = q = s;
  while (length > 0 && !strnchr((const uint8_t *)"?#", 2, *q)) {
    if (*q == '/') {                /* start new segment */

      if (!dots(p, q - p)) {
        h(p, q - p, data);
      }

      p = q + 1;
    }

    q++;
    length--;
  }

  /* write last segment */
  if (!dots(p, q - p)) {
    h(p, q - p, data);
  }

  return q - s;
}

struct cnt_str {
  coap_string_t buf;
  int n;
};

static void
write_option(const uint8_t *s, size_t len, void *data) {
  struct cnt_str *state = (struct cnt_str *)data;
  int res;
  size_t optionsize;
  assert(state);

  res = make_decoded_option(s, len, state->buf.s, state->buf.length, &optionsize);
  if (res == 0) {
    state->buf.s += optionsize;
    state->buf.length -= optionsize;
    state->n++;
  }
}

int
coap_split_path(const uint8_t *s, size_t length,
                unsigned char *buf, size_t *buflen) {
  struct cnt_str tmp = { { *buflen, buf }, 0 };

  coap_split_path_impl(s, length, write_option, &tmp);

  *buflen = *buflen - tmp.buf.length;

  return tmp.n;
}

int
coap_split_query(const uint8_t *s, size_t length,
                 unsigned char *buf, size_t *buflen) {
  struct cnt_str tmp = { { *buflen, buf }, 0 };
  const uint8_t *p;

  p = s;
  while (length > 0 && *s != '#') {
    if (*s == '&') {                /* start new query element */
      write_option(p, s - p, &tmp);
      p = s + 1;
    }

    s++;
    length--;
  }

  /* write last query element */
  write_option(p, s - p, &tmp);

  *buflen = *buflen - tmp.buf.length;
  return tmp.n;
}

#define URI_DATA(uriobj) ((unsigned char *)(uriobj) + sizeof(coap_uri_t))

coap_uri_t *
coap_new_uri(const uint8_t *uri, unsigned int length) {
  uint8_t *result;
  coap_uri_t *out_uri;

  out_uri = (coap_uri_t *)coap_malloc_type(COAP_STRING, length + 1 + sizeof(coap_uri_t));

  if (!out_uri)
    return NULL;

  result = (uint8_t *)out_uri;
  memcpy(URI_DATA(result), uri, length);
  URI_DATA(result)[length] = '\0'; /* make it zero-terminated */

  if (coap_split_uri(URI_DATA(result), length, out_uri) < 0) {
    coap_free_type(COAP_STRING, out_uri);
    return NULL;
  }
  return out_uri;
}

coap_uri_t *
coap_clone_uri(const coap_uri_t *uri) {
  coap_uri_t *result;
  uint8_t *p;

  if (!uri)
    return  NULL;

  result = (coap_uri_t *)coap_malloc_type(COAP_STRING,  uri->query.length + uri->host.length +
                                          uri->path.length + sizeof(coap_uri_t) + 1);

  if (!result)
    return NULL;

  memset(result, 0, sizeof(coap_uri_t));

  result->port = uri->port;

  if (uri->host.length) {
    result->host.s = p = URI_DATA(result);
    result->host.length = uri->host.length;

    memcpy(p, uri->host.s, uri->host.length);
  }

  if (uri->path.length) {
    result->path.s = p = URI_DATA(result) + uri->host.length;
    result->path.length = uri->path.length;

    memcpy(p, uri->path.s, uri->path.length);
  }

  if (uri->query.length) {
    result->query.s = p = URI_DATA(result) + uri->host.length + uri->path.length;
    result->query.length = uri->query.length;

    memcpy(p, uri->query.s, uri->query.length);
  }

  return result;
}

void
coap_delete_uri(coap_uri_t *uri) {
  coap_free_type(COAP_STRING, uri);
}

COAP_STATIC_INLINE int
is_unescaped_in_path(const uint8_t c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
         c == '~' || c == '!' || c == '$' || c == '\'' || c == '(' ||
         c == ')' || c == '*' || c == '+' || c == ',' || c == ';' ||
         c=='=' || c==':' || c=='@' || c == '&';
}

COAP_STATIC_INLINE int
is_unescaped_in_query(const uint8_t c) {
  return is_unescaped_in_path(c) || c=='/' || c=='?';
}

coap_string_t *
coap_get_query(const coap_pdu_t *request) {
  coap_opt_iterator_t opt_iter;
  coap_opt_filter_t f;
  coap_opt_t *q;
  coap_string_t *query = NULL;
  size_t length = 0;
  static const uint8_t hex[] = "0123456789ABCDEF";

  coap_option_filter_clear(&f);
  coap_option_filter_set(&f, COAP_OPTION_URI_QUERY);
  coap_option_iterator_init(request, &opt_iter, &f);
  while ((q = coap_option_next(&opt_iter))) {
    uint16_t seg_len = coap_opt_length(q), i;
    const uint8_t *seg= coap_opt_value(q);
    for (i = 0; i < seg_len; i++) {
      if (is_unescaped_in_query(seg[i]))
        length += 1;
      else
        length += 3;
    }
    length += 1;
  }
  if (length > 0)
    length -= 1;
  if (length > 0) {
    query = coap_new_string(length);
    if (query) {
      query->length = length;
      unsigned char *s = query->s;
      coap_option_iterator_init(request, &opt_iter, &f);
      while ((q = coap_option_next(&opt_iter))) {
        if (s != query->s)
          *s++ = '&';
        uint16_t seg_len = coap_opt_length(q), i;
        const uint8_t *seg= coap_opt_value(q);
        for (i = 0; i < seg_len; i++) {
          if (is_unescaped_in_query(seg[i])) {
            *s++ = seg[i];
          } else {
            *s++ = '%';
            *s++ = hex[seg[i]>>4];
            *s++ = hex[seg[i]&0x0F];
          }
        }
      }
    }
  }
  return query;
}

coap_string_t *
coap_get_uri_path(const coap_pdu_t *request) {
  coap_opt_iterator_t opt_iter;
  coap_opt_filter_t f;
  coap_opt_t *q;
  coap_string_t *uri_path = NULL;
  size_t length = 0;
  static const uint8_t hex[] = "0123456789ABCDEF";

  q = coap_check_option(request, COAP_OPTION_PROXY_URI, &opt_iter);
  if (q) {
    coap_uri_t uri;

    if (coap_split_proxy_uri(coap_opt_value(q),
                             coap_opt_length(q), &uri) < 0) {
      return NULL;
    }
    uri_path = coap_new_string(uri.path.length);
    if (uri_path) {
      memcpy(uri_path->s, uri.path.s, uri.path.length);
    }
    return uri_path;
  }

  coap_option_filter_clear(&f);
  coap_option_filter_set(&f, COAP_OPTION_URI_PATH);
  coap_option_iterator_init(request, &opt_iter, &f);
  while ((q = coap_option_next(&opt_iter))) {
    uint16_t seg_len = coap_opt_length(q), i;
    const uint8_t *seg= coap_opt_value(q);
    for (i = 0; i < seg_len; i++) {
      if (is_unescaped_in_path(seg[i]))
        length += 1;
      else
        length += 3;
    }
    /* bump for the leading "/" */
    length += 1;
  }
  /* The first entry does not have a leading "/" */
  if (length > 0)
    length -= 1;

  /* if 0, either no URI_PATH Option, or the first one was empty */
  uri_path = coap_new_string(length);
  if (uri_path) {
    uri_path->length = length;
    unsigned char *s = uri_path->s;
    int n = 0;
    coap_option_iterator_init(request, &opt_iter, &f);
    while ((q = coap_option_next(&opt_iter))) {
      if (n++) {
        *s++ = '/';
      }
      uint16_t seg_len = coap_opt_length(q), i;
      const uint8_t *seg= coap_opt_value(q);
      for (i = 0; i < seg_len; i++) {
        if (is_unescaped_in_path(seg[i])) {
          *s++ = seg[i];
        } else {
          *s++ = '%';
          *s++ = hex[seg[i]>>4];
          *s++ = hex[seg[i]&0x0F];
        }
      }
    }
  }
  return uri_path;
}
