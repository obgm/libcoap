/*
 * option.c -- helpers for handling options in CoAP PDUs
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */


#include "config.h"

#if defined(HAVE_ASSERT_H) && !defined(assert)
# include <assert.h>
#endif

#include <stdio.h>
#include <string.h>

#include "option.h"


const coap_opt_filter_t COAP_OPT_ALL = 
  { 0xff, 0xff, 0xff };	       /* must be sizeof(coap_opt_filter_t) */

coap_opt_iterator_t *
coap_option_iterator_init(coap_pdu_t *pdu, coap_opt_iterator_t *oi,
			  const coap_opt_filter_t filter) {
  assert(pdu); assert(oi);
  
  memset(oi, 0, sizeof(coap_opt_iterator_t));
  if (pdu->hdr->optcnt) {
    oi->optcnt = pdu->hdr->optcnt;
    oi->option = options_start(pdu);
    oi->type = COAP_OPT_DELTA(oi->option);
    memcpy(oi->filter, filter, sizeof(coap_opt_filter_t));
    return oi;
  } 
  
  return NULL;
}

#define IS_EMPTY_NOOP(Type,Option) \
  (((Type) % COAP_OPTION_NOOP == 0) && (COAP_OPT_LENGTH(Option) == 0))

#define opt_finished(oi) ((oi)->optcnt == COAP_OPT_LONG			\
			  ? ((oi)->option && *((oi)->option) == COAP_OPT_END) \
			  : (oi->n > (oi)->optcnt))

coap_opt_t *
coap_option_next(coap_opt_iterator_t *oi) {

  assert(oi);
  if (opt_finished(oi))
    return NULL;

  /* proceed to next option */
  if (oi->n++) {
    oi->option = options_next(oi->option);
    if (opt_finished(oi))
      return NULL;
    oi->type += COAP_OPT_DELTA(oi->option);
  }
  
  /* Skip subsequent options if it is an empty no-op (used for
   * fence-posting) or the filter bit is not set. */
  while (oi->option && (IS_EMPTY_NOOP(oi->type, oi->option)
			|| coap_option_getb(oi->filter, oi->type) == 0)) {
    oi->n++;
    oi->option = options_next(oi->option);

    if (!oi->option || opt_finished(oi))
      return NULL;

    oi->type += COAP_OPT_DELTA(oi->option);
  }
  
  return oi->option;
}

coap_opt_t *
coap_check_option(coap_pdu_t *pdu, unsigned char type, 
		  coap_opt_iterator_t *oi) {
  coap_opt_filter_t f;
  
  memset(f, 0, sizeof(coap_opt_filter_t));
  coap_option_setb(f, type);

  coap_option_iterator_init(pdu, oi, f);

  coap_option_next(oi);

  return oi->option && oi->type == type ? oi->option : NULL;
}

size_t
coap_opt_encode(coap_opt_t *opt, size_t n, unsigned short delta,
		unsigned char *val, unsigned short len) {
  size_t l = 1;
  size_t length = len; 
  unsigned int D = delta;
  coap_opt_t *O = opt;
  unsigned short N;

  /* option length must not exceed 1034 bytes */
  if (length > 1034)
    return 0;

  /* check for option jumps */

  if (delta < 15) { 
    /* no option jump required, proceed with normal encoding if
       sufficient space is available */
    if (n < length + 1)
      return 0;

    goto encode;
  } 

  if (delta < 30) {		/* encode with short option jump */
    /* check if sufficient storage space is available */
    if (n < length + 2)
      return 0;
    
    delta -= 15;
    l++;		       /* need one additional byte for 0xf1 */
    *opt++ = 0xf1;

    goto encode;
  } 

  /* Values up to 2070 can be encoded with a single jump value
   * (((0xff + 2) << 3) + 14) == 257 * 8 + 14 = 2070). For values 
   * below 2064, we use the last three bits from delta as the 
   * delta value and always encode N as (delta >> 3) - 2. Above
   * 2064, N will be (delta >> 3) - 3, and 
   * delta = delta - ((N + 2) << 3).
   */ 
  if (delta < 2071) {		/* longer option jump */
    /* check if sufficient storage space is available */
    if (n < length + 2)
      return 0;

    N = (delta >> 3) - 2;

    if (N > 255) {
      N--;
      delta = (delta + 8) & 0x0f;
    } else
      delta = (delta & 0x07);

    l += 2;		   /* need two additional bytes for 0xf2 nn */
    *opt++ = 0xf2;
    *opt++ = N & 0xff;

    goto encode;
  }

  /* longest option jump (delta <= 65535) */

  /* check if sufficient storage space is available */
  if (n < length + 3)
    return 0;

  N = (delta >> 3) - 258;
  delta = (delta & 0x07);

  l += 3;	      /* need three additional bytes for 0xf3 nn nn */
  *opt++ = 0xf3;
  *opt++ = (N >> 8) & 0xff;
  *opt++ = N & 0xff;

 encode:
  {
    size_t k;
    
    printf("delta(%d) = ", D);

    for (k = 0; k < l-1; ++k) {
      printf("%02x ", O[k]);
    }
    printf("%xx\n", delta & 0x0f);
  }
  return 0;
  if (length < 15) {
    *opt++ = (delta << 4) | (length & 0x0f);
    n--;
  } else {
    *opt = ((delta & 0x0f) << 4) | 0x0f;
    opt++; n--;
    length -= 15;

    while (255 <= length && len < n) {
      ++l;
      *opt++ = 0xff;
      length -= 255;
      n--;
    }

    if (len < n) {
      ++l;
      *opt++ = length & 0xff;
      n--;
    } else
      return 0;
  }
    
  memcpy(opt, val, len);
  return l + len;
}
