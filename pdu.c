/* pdu.c -- CoAP message structure
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "debug.h"
#include "mem.h"
#include "pdu.h"
#include "option.h"
#include "encode.h"


coap_pdu_t *
coap_new_pdu() {
  coap_pdu_t *pdu = coap_malloc( sizeof(coap_pdu_t) + COAP_MAX_PDU_SIZE );
  if (!pdu) {
    perror("new_pdu: malloc");
    return NULL;
  }

  /* initialize PDU */
  memset(pdu, 0, sizeof(coap_pdu_t) + COAP_MAX_PDU_SIZE );
  pdu->hdr = (coap_hdr_t *) ( (unsigned char *)pdu + sizeof(coap_pdu_t) );
  pdu->hdr->version = COAP_DEFAULT_VERSION;
  pdu->hdr->id = ntohs( COAP_INVALID_TID );

  /* data points after the header; when options are added, the data
     pointer is moved to the back */
  pdu->length = sizeof(coap_hdr_t);
  pdu->data = (unsigned char *)pdu->hdr + pdu->length;

  return pdu;
}

void
coap_delete_pdu(coap_pdu_t *pdu) {
  coap_free( pdu );
}

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
    opt_code += COAP_OPT_DELTA(*opt);
    opt = (coap_opt_t *)( (unsigned char *)opt + COAP_OPT_SIZE(*opt) );
  }

  if ( type < opt_code ) {
#ifndef NDEBUG
    fprintf(stderr, "options not added in correct order\n");
#endif
    return -1;
  }

  /* Create new option after last existing option: First check if we
   * need fence posts between type and last opt_code (i.e. delta >
   * 15), and then add actual option.
   */

  while (type - opt_code > 15) {
    cnt = opt_code / COAP_OPTION_NOOP;

    /* add fence post */
    pdu->hdr->optcnt += 1;
    COAP_OPT_SETLENGTH( *opt, 0 );
    COAP_OPT_SETDELTA( *opt, (COAP_OPTION_NOOP * (cnt+1)) - opt_code );

    opt_code += COAP_OPT_DELTA(*opt);
    opt = (coap_opt_t *)( (unsigned char *)opt + COAP_OPT_SIZE(*opt) );
  }

  /* here, the actual option is added (delta <= 15) */
  pdu->hdr->optcnt += 1;
  COAP_OPT_SETDELTA( *opt, type - opt_code );

  COAP_OPT_SETLENGTH( *opt, len );
  memcpy(COAP_OPT_VALUE(*opt), data, len);
  pdu->data = (unsigned char *)COAP_OPT_VALUE(*opt) + len ;

  pdu->length = pdu->data - (unsigned char *)pdu->hdr;
  return len;
}

int
coap_add_data(coap_pdu_t *pdu, unsigned int len, const unsigned char *data) {
  if ( !pdu )
    return 0;

  if ( pdu->length + len > COAP_MAX_PDU_SIZE ) {
#ifndef NDEBUG
    fprintf(stderr, "coap_add_data: cannot add: data too large for PDU\n");
#endif
    return 0;
  }

  memcpy( (unsigned char *)pdu->hdr + pdu->length, data, len );
  pdu->length += len;
  return 1;
}

int
coap_get_data(coap_pdu_t *pdu, unsigned int *len, unsigned char **data) {
  if ( !pdu )
    return 0;

  if ( pdu->data < (unsigned char *)pdu->hdr + pdu->length ) {
    /* pdu contains data */

    *len = (unsigned char *)pdu->hdr + pdu->length - pdu->data;
    *data = pdu->data;
  } else {			/* no data, clear everything */
    *len = 0;
    *data = NULL;
  }

  return 1;
}

int
coap_get_request_uri(coap_pdu_t *pdu, coap_uri_t *result) {
  coap_opt_t *opt;
  coap_opt_iterator_t opt_iter;
  
  if (!pdu || !result)
    return 0;

  memset(result, 0, sizeof(*result));
    
  if ((opt = coap_check_option(pdu, COAP_OPTION_URI_HOST, &opt_iter)))
    COAP_SET_STR(&result->host, COAP_OPT_LENGTH(*opt), COAP_OPT_VALUE(*opt));

  if ((opt = coap_check_option(pdu, COAP_OPTION_URI_PORT, &opt_iter)))
    result->port = 
      coap_decode_var_bytes(COAP_OPT_VALUE(*opt), COAP_OPT_LENGTH(*opt));
  else
    result->port = COAP_DEFAULT_PORT;

  if ((opt = coap_check_option(pdu, COAP_OPTION_URI_PATH, &opt_iter))) {
    result->path.s = COAP_OPT_VALUE(*opt);
    result->path.length = COAP_OPT_LENGTH(*opt);

    while (coap_option_next(&opt_iter) && opt_iter.type == COAP_OPTION_URI_PATH) 
      result->path.length += COAP_OPT_SIZE(*opt_iter.option);
  }

  if ((opt = coap_check_option(pdu, COAP_OPTION_URI_QUERY, &opt_iter))) {
    result->query.s = COAP_OPT_VALUE(*opt);
    result->query.length = COAP_OPT_LENGTH(*opt);

    while (coap_option_next(&opt_iter) && opt_iter.type == COAP_OPTION_URI_QUERY) 
      result->query.length += COAP_OPT_SIZE(*opt_iter.option);
  }

  return 1;
}
