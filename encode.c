/* encode.c -- encoding and decoding of CoAP data types
 *
 * (c) 2010 Carsten Bormann
 */

#ifndef NDEBUG
#  include <stdio.h>
#endif

#include "encode.h"

/* Carsten suggested this when fls() is not available: */
int coap_fls(unsigned int i) {
  int n;
  for (n = 0; i; n++)
    i >>= 1;
  return n;
}

