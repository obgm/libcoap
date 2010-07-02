#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "pdu.h"


coap_pdu_t *
coap_new_pdu() {
  coap_pdu_t *pdu = malloc( sizeof(coap_pdu_t) + COAP_MAX_PDU_SIZE );
  if (!pdu) {
    perror("new_pdu: malloc");
    return NULL;
  }
  
  /* initialize PDU */
  memset(pdu, 0, sizeof(coap_pdu_t) + COAP_MAX_PDU_SIZE );
  pdu->hdr = (coap_hdr_t *) ( pdu + sizeof(coap_pdu_t) );

  /* data points after the header; when options are added, the data 
     pointer is moved to the back */
  pdu->data = (unsigned char *) ( pdu->hdr + sizeof(coap_hdr_t) );

  return pdu;
}

void 
coap_delete_pdu(coap_pdu_t *pdu) {
  free( pdu );
}

#define options_start(p) ((coap_opt_t *) ( (p)->hdr + sizeof ( coap_hdr_t ) ))

int 
coap_add_option(coap_pdu_t *pdu, unsigned char type, unsigned int len, const unsigned char *data) {
  unsigned char cnt;
  coap_opt_t *opt;
  unsigned char opt_code = 0;

  if (!pdu) 
    return -1;

  /* get last option from pdu to calculate the delta */
  
  opt = options_start( pdu );
  for ( cnt = pdu->hdr->optcnt; cnt; --cnt ) {
    opt_code += opt->delta;
    opt += (opt->length < 15 ? opt->length + 1 : opt->longopt.length + 16); 
  }

  if ( type < opt_code ) {
    fprintf(stderr, "options not added in correect order\n");
    return -1;
  }

  /* create new option after last existing option */
  pdu->hdr->optcnt += 1;
  opt->delta = type - opt_code;
  
  if ( len < 15 ) {		/* short form */
    opt->length = len;
    memcpy(opt->shortopt.value, data, len);

    pdu->data = (unsigned char *) ( opt + 1 + len );
  } else {			/* extended form */
    opt->length = 15;
    opt->longopt.length = len - 15;
    memcpy(opt->longopt.value, data, len);

    pdu->data = (unsigned char *) ( opt + 2 + len );
  }

  return len;
}
