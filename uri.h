/* uri.h -- helper functions for URI treatment
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#ifndef _COAP_URI_H_
#define _COAP_URI_H_

#include "str.h"

/** Representation of parsed URI. Components may be filled from a
 * string with coap_split_uri() and can be used as input for
 * option-creation functions. */
typedef struct {
  str host;			/**< host part of the URI */
  unsigned short port;		/**< The port in host byte order */
  str path;			/**< Beginning of the first path segment. 
				   Use coap_split_path() to create Uri-Path options */
  str query;			/**<  The query part if present */
} coap_uri_t;

/** 
 * Parses a given string into URI components. The identified syntactic
 * components are stored in the result parameter @p uri. Optional URI
 * components that are not specified will be set to { 0, 0 }, except
 * for the port which is set to @c COAP_DEFAULT_PORT. This function
 * returns @p 0 if parsing succeeded, a value less than zero
 * otherwise.
 * 
 * @param str_var The string to split up.
 * @param len     The actual length of @p str_var
 * @param uri     The coap_uri_t object to store the result.
 * @return @c 0 on success, or < 0 on error.
 */
int
coap_split_uri(const unsigned char *str_var, size_t len, coap_uri_t *uri);

/** 
 * Splits the given string into segments. You should call one of the
 * macros coap_split_path() or coap_split_query() instead.
 * 
 * @param s      The string to split. 
 * @param is_path Set to @c 1 to split path segments, @c 0 for query segments.
 * @param length The actual length of @p uri.
 * @param buf    Result buffer for parsed segments. 
 * @param buflen Maximum length of @p buf.
 * 
 * @return The number of segments created or @c -1 on error.
 */
int coap_split_path_impl(unsigned char *s, size_t length, int is_path,
			 unsigned char *buf, size_t buflen);

/** 
 * Splits the given URI path into segments.
 * 
 * @param Path   The path string to split. 
 * @param Length The actual length of @p Path.
 * @param Buf    Result buffer for parsed segments. 
 * @param Buflen Maximum length of @p Buf.
 * 
 * @return The number of segments created or @c -1 on error.
 */
#define coap_split_path(Path, Length, Buf, Buflen) \
  coap_split_path_impl((Path), (Length), 1, (Buf), (Buflen))

/** 
 * Splits the given URI query into segments.
 * 
 * @param Query  The query string to split. 
 * @param Length The actual length of @p Query.
 * @param Buf    Result buffer for parsed segments. 
 * @param Buflen Maximum length of @p Buf.
 * 
 * @return The number of segments created or @c -1 on error.
 */
#define coap_split_query(Query, Length, Buf, Buflen) \
  coap_split_path_impl((Query), (Length), 0, (Buf), (Buflen))

/**
 * Creates a new coap_uri_t object from the specified URI. Returns the new
 * object or NULL on error. The memory allocated by the new coap_uri_t
 * must be released using coap_free().
 * @param uri The URI path to copy.
 * @para length The length of uri.
 * @return New URI object or NULL on error.
 *
 * @depreated This function has inconvenient storage allocation
 * characteristics to split URI path and query. Better do that
 * manually.
 */
coap_uri_t *coap_new_uri(const unsigned char *uri, unsigned int length);

/**
 * Clones the specified coap_uri_t object. Thie function allocates sufficient
 * memory to hold the coap_uri_t structure and its contents. The object must
 * be released with coap_free(). */
coap_uri_t *coap_clone_uri(const coap_uri_t *uri);

#endif /* _COAP_URI_H_ */
