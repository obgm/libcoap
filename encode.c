/* encode.c -- encoding and decoding of CoAP data types
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#ifndef NDEBUG
#  include <stdio.h>
#endif

#include "encode.h"

unsigned int 
coap_pseudo_encode( unsigned int val ) {
  unsigned int e = 0;

  if ( val < HIBIT )
    return val;

  if ( val > MAX_VALUE ) {
#ifndef NDEBUG
    fprintf(stderr, "cannot encode value %u\n", val);
#endif
    return ( 1 << N ) - 1;
  }
  
  while ( HIBIT < (val & ~0xff) ) {
    val = val >> 1;
    e += 1;
  }

  return (val & ~EMASK) | e;
}
