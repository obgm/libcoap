/*
 * coap_uri.h -- helper functions for URI treatment
 *
 * Copyright (C) 2010-2023 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_uri.h
 * @brief Helper functions for URI treatment
 */

#ifndef COAP_URI_H_
#define COAP_URI_H_

#include <stdint.h>

#include "coap_str.h"

/**
 * The scheme specifiers. Secure schemes have an odd numeric value,
 * others are even.
 */
typedef enum coap_uri_scheme_t {
  COAP_URI_SCHEME_COAP = 0,
  COAP_URI_SCHEME_COAPS,     /* 1 */
  COAP_URI_SCHEME_COAP_TCP,  /* 2 */
  COAP_URI_SCHEME_COAPS_TCP, /* 3 */
  COAP_URI_SCHEME_HTTP,      /* 4 Proxy-Uri only */
  COAP_URI_SCHEME_HTTPS,     /* 5 Proxy-Uri only */
  COAP_URI_SCHEME_COAP_WS,   /* 6 */
  COAP_URI_SCHEME_COAPS_WS,  /* 7 */
  COAP_URI_SCHEME_LAST       /* 8 Size of scheme */
} coap_uri_scheme_t;

/** This mask can be used to check if a parsed URI scheme is secure. */
#define COAP_URI_SCHEME_SECURE_MASK 0x01

#define COAP_URI_SCHEME_COAP_BIT       (1 << COAP_URI_SCHEME_COAP)
#define COAP_URI_SCHEME_COAPS_BIT      (1 << COAP_URI_SCHEME_COAPS)
#define COAP_URI_SCHEME_COAP_TCP_BIT   (1 << COAP_URI_SCHEME_COAP_TCP)
#define COAP_URI_SCHEME_COAPS_TCP_BIT  (1 << COAP_URI_SCHEME_COAPS_TCP)
#define COAP_URI_SCHEME_HTTP_BIT       (1 << COAP_URI_SCHEME_HTTP)
#define COAP_URI_SCHEME_HTTPS_BIT      (1 << COAP_URI_SCHEME_HTTPS)
#define COAP_URI_SCHEME_COAP_WS_BIT    (1 << COAP_URI_SCHEME_COAP_WS)
#define COAP_URI_SCHEME_COAPS_WS_BIT   (1 << COAP_URI_SCHEME_COAPS_WS)

#define COAP_URI_SCHEME_ALL_COAP_BITS (COAP_URI_SCHEME_COAP_BIT | \
                                       COAP_URI_SCHEME_COAPS_BIT | \
                                       COAP_URI_SCHEME_COAP_TCP_BIT | \
                                       COAP_URI_SCHEME_COAPS_TCP_BIT | \
                                       COAP_URI_SCHEME_COAP_WS_BIT | \
                                       COAP_URI_SCHEME_COAPS_WS_BIT)

/**
 * Representation of parsed URI. Components may be filled from a string with
 * coap_split_uri() or coap_split_proxy_uri() and can be used as input for
 * option-creation functions. Alternatively, coap_uri_into_options() can
 * be used to convert coap_uri_t into CoAP options.
 */
typedef struct {
  coap_str_const_t host;  /**< The host part of the URI */
  uint16_t port;          /**< The port in host byte order */
  coap_str_const_t path;  /**< The complete path if present or {0, NULL}.
                               Needs to be split using coap_split_path()
                               or coap_uri_into_options(). */
  coap_str_const_t query; /**< The complete query if present or {0, NULL}.
                               Needs to be split using coap_split_query()
                               or coap_uri_into_options(). */
  /** The parsed scheme specifier. */
  enum coap_uri_scheme_t scheme;
} coap_uri_t;

static inline int
coap_uri_scheme_is_secure(const coap_uri_t *uri) {
  return uri && ((uri->scheme & COAP_URI_SCHEME_SECURE_MASK) != 0);
}

/**
 * Determines from the @p host whether this is a Unix Domain socket
 * request.
 *
 * @param host    The host object.
 *
 * @return        @c 0 on failure, or @c 1 on success.
 *
 */
int coap_host_is_unix_domain(const coap_str_const_t *host);

/**
 * Creates a new coap_uri_t object from the specified URI. Returns the new
 * object or NULL on error. The memory allocated by the new coap_uri_t
 * should be released using coap_delete_uri().
 *
 * @param uri The URI path to copy.
 * @param length The length of uri.
 *
 * @return New URI object or NULL on error.
 */
coap_uri_t *coap_new_uri(const uint8_t *uri, unsigned int length);

/**
 * Clones the specified coap_uri_t object. This function allocates sufficient
 * memory to hold the coap_uri_t structure and its contents. The object should
 * be released with delete_uri().
 *
 * @param uri The coap_uri_t structure to copy.
 *
 * @return New URI object or NULL on error.
 */
coap_uri_t *coap_clone_uri(const coap_uri_t *uri);

/**
 * Removes the specified coap_uri_t object.
 *
 * @param uri The coap_uri_t structure to remove.
 */
void coap_delete_uri(coap_uri_t *uri);

/**
 * @ingroup application_api
 * @defgroup uri_parse URI Parsing Functions
 * API for parsing URIs.
 * CoAP PDUs contain normalized URIs with their path and query split into
 * multiple segments. The functions in this module help splitting strings.
 * @{
 */

/**
 * Parses a given string into URI components. The identified syntactic
 * components are stored in the result parameter @p uri. Optional URI
 * components that are not specified will be set to { 0, 0 }, except for the
 * port which is set to the default port for the protocol. This function
 * returns @p 0 if parsing succeeded, a value less than zero otherwise.
 *
 * @param str_var The string to split up.
 * @param len     The actual length of @p str_var
 * @param uri     The coap_uri_t object to store the result.
 *
 * @return        @c 0 on success, or < 0 on error.
 *
 */
int coap_split_uri(const uint8_t *str_var, size_t len, coap_uri_t *uri);

/**
 * Parses a given string into URI components. The identified syntactic
 * components are stored in the result parameter @p uri. Optional URI
 * components that are not specified will be set to { 0, 0 }, except for the
 * port which is set to default port for the protocol. This function returns
 * @p 0 if parsing succeeded, a value less than zero otherwise.
 * Note: This function enforces that the given string is in Proxy-Uri format
 *       as well as supports different schema such as http and https.
 *
 * @param str_var The string to split up.
 * @param len     The actual length of @p str_var
 * @param uri     The coap_uri_t object to store the result.
 *
 * @return        @c 0 on success, or < 0 on error.
 *
 */
int coap_split_proxy_uri(const uint8_t *str_var, size_t len, coap_uri_t *uri);

/**
 * Takes a coap_uri_t and then adds CoAP options into the @p optlist_chain.
 * If the port is not the default port and create_port_host_opt is not 0, then
 * the Port option is added to the @p optlist_chain.
 * If the dst defines an address that does not match the host in uri->host and
 * is not 0, then the Host option is added to the @p optlist_chain.
 * Any path or query are broken down into the individual segment Path or Query
 * options and added to the @p optlist_chain.
 *
 * @param uri     The coap_uri_t object.
 * @param dst     The destination, or NULL if URI_HOST not to be added.
 * @param optlist_chain Where to store the chain of options.
 * @param buf     Scratch buffer area (needs to be bigger than
 *                uri->path.length and uri->query.length)
 * @param buflen  Size of scratch buffer.
 * @param create_port_host_opt @c 1 if port/host option to be added
 *                             (if non-default) else @c 0
 *
 * @return        @c 0 on success, or < 0 on error.
 *
 */
int coap_uri_into_options(const coap_uri_t *uri, const coap_address_t *dst,
                          coap_optlist_t **optlist_chain,
                          int create_port_host_opt,
                          uint8_t *buf, size_t buflen);

/**
 * Splits the given URI path into segments. Each segment is preceded
 * by an option pseudo-header with delta-value 0 and the actual length
 * of the respective segment after percent-decoding.
 *
 * @param s      The path string to split.
 * @param length The actual length of @p s.
 * @param buf    Result buffer for parsed segments.
 * @param buflen Maximum length of @p buf. Will be set to the actual number
 *               of bytes written into buf on success.
 *
 * @return       The number of segments created or @c -1 on error.
 */
int coap_split_path(const uint8_t *s,
                    size_t length,
                    unsigned char *buf,
                    size_t *buflen);

/**
 * Splits the given URI query into segments. Each segment is preceded
 * by an option pseudo-header with delta-value 0 and the actual length
 * of the respective query term.
 *
 * @param s      The query string to split.
 * @param length The actual length of @p s.
 * @param buf    Result buffer for parsed segments.
 * @param buflen Maximum length of @p buf. Will be set to the actual number
 *               of bytes written into buf on success.
 *
 * @return       The number of segments created or @c -1 on error.
 *
 * @bug This function does not reserve additional space for delta > 12.
 */
int coap_split_query(const uint8_t *s,
                     size_t length,
                     unsigned char *buf,
                     size_t *buflen);

/**
 * Extract query string from request PDU according to escape rules in 6.5.8.
 * @param request Request PDU.
 * @return        Reconstructed and escaped query string part or @c NULL if
 *                no query was contained in @p request. The coap_string_t
 *                object returned by this function must be released with
 *                coap_delete_string.
 */
coap_string_t *coap_get_query(const coap_pdu_t *request);

/**
 * Extract uri_path string from request PDU
 * @param request Request PDU.
 * @return        Reconstructed and escaped uri path string part or @c NULL
 *                if no URI-Path was contained in @p request. The
 *                coap_string_t object returned by this function must be
 *                released with coap_delete_string.
 */
coap_string_t *coap_get_uri_path(const coap_pdu_t *request);

/** @} */

#endif /* COAP_URI_H_ */
