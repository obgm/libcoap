/* str.h -- strings to be used in the CoAP library
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#ifndef _COAP_STR_H_
#define _COAP_STR_H_

#include <string.h>

typedef struct {
  size_t length;		/* length of string */
  unsigned char *s;		/* string data */
} str;

/**
 * Returns a new string object with at least size bytes storage
 * allocated.  The string must be released using coap_delete_string();
 */ 
str *coap_new_string(size_t size);

/** Deletes the given string and releases any memory allocated. */
void coap_delete_string(str *);

#endif /* _COAP_STR_H_ */
