/* str.c -- strings to be used in the CoAP library
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include "coap_config.h"

#include <stdio.h>

#include "libcoap.h"
#include "debug.h"
#include "mem.h"
#include "str.h"

coap_string_t *coap_new_string(size_t size) {
  coap_string_t *s =
            (coap_string_t *)coap_malloc_type(COAP_STRING, sizeof(coap_string_t) + size + 1);
  if ( !s ) {
#ifndef NDEBUG
    coap_log(LOG_CRIT, "coap_new_string: malloc\n");
#endif
    return NULL;
  }

  memset(s, 0, sizeof(coap_string_t));
  s->s = ((unsigned char *)s) + sizeof(coap_string_t);
  return s;
}

void coap_delete_string(coap_string_t *s) {
  coap_free_type(COAP_STRING, s);
}

