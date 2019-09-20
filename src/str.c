/* str.c -- strings to be used in the CoAP library
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_internal.h"

#include <stdio.h>

coap_string_t *coap_new_string(size_t size) {
  coap_string_t *s =
            (coap_string_t *)coap_malloc_type(COAP_STRING, sizeof(coap_string_t) + size + 1);
  if ( !s ) {
    coap_log(LOG_CRIT, "coap_new_string: malloc: failed\n");
    return NULL;
  }

  memset(s, 0, sizeof(coap_string_t));
  s->s = ((unsigned char *)s) + sizeof(coap_string_t);
  s->s[size] = '\000';
  return s;
}

void coap_delete_string(coap_string_t *s) {
  coap_free_type(COAP_STRING, s);
}

coap_str_const_t *coap_new_str_const(const uint8_t *data, size_t size) {
  coap_string_t *s = coap_new_string(size);
  if (!s)
    return NULL;
  memcpy (s->s, data, size);
  s->length = size;
  return (coap_str_const_t *)s;
}

void coap_delete_str_const(coap_str_const_t *s) {
  coap_free_type(COAP_STRING, s);
}

coap_str_const_t *coap_make_str_const(const char *string)
{
  static int ofs = 0;
  static coap_str_const_t var[COAP_MAX_STR_CONST_FUNC];
  if (++ofs == COAP_MAX_STR_CONST_FUNC) ofs = 0;
  var[ofs].length = strlen(string);
  var[ofs].s = (const uint8_t *)string;
  return &var[ofs];
}

