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
coap_pdu_init(unsigned char type, unsigned char code, 
	      unsigned short id, size_t size) {
  coap_pdu_t *pdu;

  /* Size must be large enough to fit the header. */
  if (size < sizeof(coap_hdr_t)) 
    return NULL;

  //size must be large enough for hdr
  pdu = coap_malloc(sizeof(coap_pdu_t) + size);
  if (pdu) {
    memset(pdu, 0, sizeof(coap_pdu_t) + size);
    pdu->max_size = size;
    pdu->hdr = (coap_hdr_t *)((unsigned char *)pdu + sizeof(coap_pdu_t));
    pdu->hdr->version = COAP_DEFAULT_VERSION;
    pdu->hdr->id = id;
    pdu->hdr->type = type;
    pdu->hdr->code = code;

    /* data points after the header; when options are added, the data
       pointer is moved to the back */
    pdu->length = sizeof(coap_hdr_t);
    pdu->data = (unsigned char *)pdu->hdr + pdu->length;
  }
  return pdu;
}

coap_pdu_t *
coap_new_pdu() {
  coap_pdu_t *pdu;
  
  pdu = coap_pdu_init(0, 0, ntohs(COAP_INVALID_TID), COAP_MAX_PDU_SIZE);

  if (!pdu)
    perror("coap_new_pdu: cannot allocate memory for new PDU");
  return pdu;
}

void
coap_delete_pdu(coap_pdu_t *pdu) {
  coap_free( pdu );
}

int
coap_add_option(coap_pdu_t *pdu, unsigned char type, unsigned int len, const unsigned char *data) {
  unsigned char cnt, optcnt;
  coap_opt_t *opt;
  unsigned char opt_code = 0;

  if (!pdu)
    return -1;

  /* get last option from pdu to calculate the delta */

  opt = options_start( pdu );
  for ( cnt = pdu->hdr->optcnt; cnt; --cnt ) {
    opt_code += COAP_OPT_DELTA(opt);
    opt = options_next(opt);
  }

  if ( type < opt_code ) {
#ifndef NDEBUG
    coap_log(LOG_WARN, "options not added in correct order\n");
#endif
    return -1;
  }
  
  optcnt = pdu->hdr->optcnt;
  /* Create new option after last existing option: First check if we
   * need fence posts between type and last opt_code (i.e. delta >
   * 15), and then add actual option.
   */

  while (type - opt_code > 15) {
    cnt = opt_code / COAP_OPTION_NOOP;

    if ((unsigned char *)opt + 1 > (unsigned char *)pdu->hdr + pdu->max_size) {
      debug("cannot add fencepost option\n");
      return -1;
    }

    /* add fence post */
    optcnt += 1;
    COAP_OPT_SETLENGTH( opt, 0 );
    COAP_OPT_SETDELTA( opt, (COAP_OPTION_NOOP * (cnt+1)) - opt_code );

    opt_code += COAP_OPT_DELTA(opt);
    opt = options_next(opt);
  }

  if ((unsigned char *)opt + len + (len > 14 ? 2 : 1) > 
      (unsigned char *)pdu->hdr + pdu->max_size) {
    debug("cannot add option\n");
    return -1;
  }

  /* here, the actual option is added (delta <= 15) */
  optcnt += 1;
  COAP_OPT_SETDELTA( opt, type - opt_code );

  COAP_OPT_SETLENGTH( opt, len );
  memcpy(COAP_OPT_VALUE(opt), data, len);
  pdu->data = (unsigned char *)COAP_OPT_VALUE(opt) + len ;

  pdu->hdr->optcnt = optcnt;
  pdu->length = pdu->data - (unsigned char *)pdu->hdr;
  return len;
}

int
coap_add_data(coap_pdu_t *pdu, unsigned int len, const unsigned char *data) {
  if ( !pdu )
    return 0;

  if ( pdu->length + len > pdu->max_size ) {
#ifndef NDEBUG
 coap_log(LOG_WARN, "coap_add_data: cannot add: data too large for PDU\n");
#endif
    return 0;
  }

  memcpy( (unsigned char *)pdu->hdr + pdu->length, data, len );
  pdu->length += len;
  return 1;
}

int
coap_get_data(coap_pdu_t *pdu, size_t *len, unsigned char **data) {
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

#ifndef SHORT_ERROR_RESPONSE
typedef struct {
  unsigned char code;
  char *phrase;
} error_desc_t;

/* if you change anything here, make sure, that the longest string does not 
 * exceed COAP_ERROR_PHRASE_LENGTH. */
error_desc_t coap_error[] = {
  { COAP_RESPONSE_CODE(65),  "2.01 Created" },
  { COAP_RESPONSE_CODE(66),  "2.02 Deleted" },
  { COAP_RESPONSE_CODE(67),  "2.03 Valid" },
  { COAP_RESPONSE_CODE(68),  "2.04 Changed" },
  { COAP_RESPONSE_CODE(69),  "2.05 Content" },
  { COAP_RESPONSE_CODE(400), "Bad Request" },
  { COAP_RESPONSE_CODE(401), "Unauthorized" },
  { COAP_RESPONSE_CODE(402), "Bad Option" },
  { COAP_RESPONSE_CODE(403), "Forbidden" },
  { COAP_RESPONSE_CODE(404), "Not Found" },
  { COAP_RESPONSE_CODE(405), "Method Not Allowed" },
  { COAP_RESPONSE_CODE(408), "Request Entity Incomplete" },
  { COAP_RESPONSE_CODE(413), "Request Entity Too Large" },
  { COAP_RESPONSE_CODE(415), "Unsupported Media Type" },
  { COAP_RESPONSE_CODE(500), "Internal Server Error" },
  { COAP_RESPONSE_CODE(501), "Not Implemented" },
  { COAP_RESPONSE_CODE(502), "Bad Gateway" },
  { COAP_RESPONSE_CODE(503), "Service Unavailable" },
  { COAP_RESPONSE_CODE(504), "Gateway Timeout" },
  { COAP_RESPONSE_CODE(505), "Proxying Not Supported" },
  { 0, NULL }			/* end marker */
};

char *
coap_response_phrase(unsigned char code) {
  int i;
  for (i = 0; coap_error[i].code; ++i) {
    if (coap_error[i].code == code)
      return coap_error[i].phrase;
  }
  return NULL;
}
#endif

#if 0
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
#endif
