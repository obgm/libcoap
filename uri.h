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
coap_split_uri(unsigned char *str_var, size_t len, coap_uri_t *uri);

/**
 * Creates a new coap_uri_t object from the specified URI. Returns the new
 * object or NULL on error. The memory allocated by the new coap_uri_t
 * must be released using coap_free().
 * @param uri The URI path to copy.
 * @para length The length of uri.
 * @return New URI object or NULL on error.
 */
coap_uri_t *coap_new_uri(const unsigned char *uri, unsigned int length);

/**
 * Clones the specified coap_uri_t object. Thie function allocates sufficient
 * memory to hold the coap_uri_t structure and its contents. The object must
 * be released with coap_free(). */
coap_uri_t *coap_clone_uri(const coap_uri_t *uri);

#endif /* _COAP_URI_H_ */
