/* encode.c -- encoding and decoding of CoAP data types
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#ifndef NDEBUG
#  include <stdio.h>
#endif

#include "coap_config.h"
#include "encode.h"

#if defined(HAVE_ASSERT_H) && !defined(assert)
# include <assert.h>
#endif

/* Carsten suggested this when fls() is not available: */
#ifndef HAVE_FLS
int coap_fls(unsigned int i) {
  return coap_flsll(i);
}
#endif

#ifndef HAVE_FLSLL
int coap_flsll(long long i)
{
  int n;
  for (n = 0; i; n++)
    i >>= 1;
  return n;
}
#endif

unsigned int
coap_decode_var_bytes(unsigned char *buf,unsigned int len) {
  unsigned int i, n = 0;
  for (i = 0; i < len; ++i)
    n = (n << 8) + buf[i];

  return n;
}

unsigned int
coap_encode_var_bytes(unsigned char *buf, unsigned int val) {
  unsigned int n, i;

  for (n = 0, i = val; i && n < sizeof(val); ++n)
    i >>= 8;

  i = n;
  while (i--) {
    buf[i] = val & 0xff;
    val >>= 8;
  }

  return n;
}

bool
coap_is_var_bytes(coap_option_def_t* def) {
  assert (def);

  if ('u' == def->type) {
    return 1;
  } else {
    return 0;
  }
}
