/* encode.h -- encoding and decoding of CoAP data types
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#ifndef _COAP_ENCODE_H_
#define _COAP_ENCODE_H_

#include "encode.h"

#define N 8
#define E 4
#define HIBIT (1 << (N - 1))
#define EMASK ((1 << E) - 1)
#define MMASK ((1 << N) - 1 - EMASK)
#define MAX_VALUE ( (1 << N) - (1 << E) ) * (1 << ((1 << E) - 1))

/* internal function, better use macro COAP_PSEUDOFP_ENCODE() instead */
unsigned int coap_pseudo_encode( unsigned int val );

#define COAP_PSEUDOFP_ENCODE(r) coap_pseudo_encode( (r) )
#define COAP_PSEUDOFP_DECODE(r) (r < HIBIT ? r : (r & MMASK) << (r & EMASK))

#endif /* _COAP_ENCODE_H_ */
