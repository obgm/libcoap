/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in draft-ietf-core-coap-00
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "pdu.h"

#define options_start(p) ((coap_opt_t *) ( (p)->hdr + sizeof ( coap_hdr_t ) ))


void 
for_each_option(coap_pdu_t *pdu, 
		void (*f)(coap_opt_t *, unsigned char, unsigned int, const unsigned char *) ) {
  unsigned char cnt;
  coap_opt_t *opt;
  unsigned char opt_code = 0;
  
  if (! pdu )
    return;

  opt = options_start( pdu );
  for ( cnt = pdu->hdr->optcnt; cnt; --cnt ) {
    opt_code += opt->delta;

    if ( opt->length < 15 ) {
      f ( opt, opt_code, opt->length, opt->shortopt.value );
      opt += opt->length + 1;
    } else {
      f ( opt, opt_code, opt->longopt.length + 15, opt->longopt.value );
      opt += opt->longopt.length + 16;
    }
  }
}

void 
show( coap_opt_t *opt, unsigned char type, unsigned int len, const unsigned char *data ) {
  printf( "option %d (%d bytes): '%*s'\n", type, len, len, data );
}

int 
main(int argc, char **argv) {
  coap_pdu_t  *pdu = coap_new_pdu();
 
  if (! pdu )
    return -1;

  coap_add_option ( pdu, 2, 3, "foo" );
  coap_add_option ( pdu, 12, 16, "1234567890123456" );
  coap_add_option ( pdu, 13, 15, "123456789012345" );
  coap_add_option ( pdu, 21, 0, NULL );
  coap_add_option ( pdu, 33, 2, "ab" );

  for_each_option ( pdu, show );

  coap_delete_pdu ( pdu );
  
  return 0;
}
