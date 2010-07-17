/* str.c -- strings to be used in the CoAP library
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#include <stdio.h>

#include "mem.h"
#include "str.h"

str *coap_new_string(size_t size) {
  str *s = coap_malloc(sizeof(str) + size + 1);
  if ( !s ) {
    perror("coap_new_string: malloc");
    return NULL;
  }
    
  memset(s, 0, sizeof(str) + size + 1);
  return s;
}

void coap_delete_string(str *s) {
  coap_free(s);
}

