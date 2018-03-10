/*
 * str.h -- strings to be used in the CoAP library
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#ifndef _COAP_STR_H_
#define _COAP_STR_H_

#include <string.h>

typedef struct coap_string_t {
  size_t length;    /* length of string */
  unsigned char *s; /* string data */
} coap_string_t;

/* For backwards compatability */
typedef coap_string_t str;

#define COAP_SET_STR(st,l,v) { (st)->length = (l), (st)->s = (v); }

/**
 * Returns a new string object with at least size+1 bytes storage allocated.
 * The string must be released using coap_delete_string();
 *
 * @param size The size to allocate for the binary string data
 *
 * @return       A pointer to the new object or @c NULL on error.
 */
coap_string_t *coap_new_string(size_t size);

/**
 * Deletes the given string and releases any memory allocated.
 *
 * @param string The string to free off
 */
void coap_delete_string(coap_string_t *string);

/**
 * Compares the two strings for equality
 *
 * @param string1 The first string
 * @param string2 The second string
 *
 * @return         @c 1 if the strings are equal
 *                 @c 0 otherwise.
 */
COAP_STATIC_INLINE int
coap_string_equal(coap_string_t *string1, coap_string_t *string2) {
  return string1->length == string2->length &&
         memcmp (string1->s, string2->s, string1->length) == 0;
}

#endif /* _COAP_STR_H_ */
