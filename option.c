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
#include "debug.h"

coap_opt_t *
options_start(coap_pdu_t *pdu) {

  if (pdu && pdu->hdr && 
      (pdu->hdr->token + pdu->hdr->token_length 
       < (unsigned char *)pdu->hdr + pdu->length)) {

    coap_opt_t *opt = pdu->hdr->token + pdu->hdr->token_length;
    return (*opt == COAP_PAYLOAD_START) ? NULL : opt;
  
  } else 
    return NULL;
}

size_t
coap_opt_parse(const coap_opt_t *opt, size_t length, coap_option_t *result) {

  const coap_opt_t *opt_start = opt; /* store where parsing starts  */

  assert(opt); assert(result);

#define ADVANCE_OPT(o,e,step) if ((e) < step) {			\
    debug("cannot advance opt past end\n");			\
    return 0;							\
  } else {							\
    (e) -= step;						\
    (o) = ((unsigned char *)(o)) + step;			\
  }

  if (length < 1)
    return 0;

  result->delta = (*opt & 0xf0) >> 4;
  result->length = *opt & 0x0f;

  switch(result->delta) {
  case 15:
    if (*opt == COAP_PAYLOAD_START)
      debug("found payload marker when expecting option\n");
    else
      debug("ignored reserved option delta 15\n");
    return 0;
  case 14:
    /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
     * After that, the option pointer is advanced to the LSB which is handled
     * just like case delta == 13. */
    ADVANCE_OPT(opt,length,1);
    result->delta = ((*opt & 0xff) << 8) + 269;
    if (result->delta < 269) {
      debug("delta too large\n");
      return 0;
    }
    /* fall through */
  case 13:
    ADVANCE_OPT(opt,length,1);
    result->delta += *opt & 0xff;
    break;
    
  default:
    ;
  }

  switch(result->length) {
  case 15:
    debug("found reserved option length 15\n");
    return 0;
  case 14:
    /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
     * After that, the option pointer is advanced to the LSB which is handled
     * just like case delta == 13. */
    ADVANCE_OPT(opt,length,1);
    result->length = ((*opt & 0xff) << 8) + 269;
    /* fall through */
  case 13:
    ADVANCE_OPT(opt,length,1);
    result->length += *opt & 0xff;
    break;
    
  default:
    ;
  }

  ADVANCE_OPT(opt,length,1);
  /* opt now points to value, if present */

  result->value = (unsigned char *)opt;
  if (length < result->length) {
    debug("invalid option length\n");
    return 0;
  }

#undef ADVANCE_OPT

  return (opt + result->length) - opt_start;
}

const coap_opt_filter_t COAP_OPT_ALL = 
  { 0xff, 0xff, 0xff };	       /* must be sizeof(coap_opt_filter_t) */

coap_opt_iterator_t *
coap_option_iterator_init(coap_pdu_t *pdu, coap_opt_iterator_t *oi,
			  const coap_opt_filter_t filter) {
  assert(pdu); assert(oi);
  
  memset(oi, 0, sizeof(coap_opt_iterator_t));

  oi->option = options_start(pdu);

  if (oi->option) {
    /* Note that we do not check if options exceed the length of @p
     * pdu. This must be checked before coap_option_iterator_init() is
     * called.
     */
    oi->length = pdu->length - 
      ((unsigned char *)oi->option - (unsigned char *)pdu->hdr);
    oi->type = coap_opt_delta(oi->option);
    memcpy(oi->filter, filter, sizeof(coap_opt_filter_t));
    return oi;
  } 
  
  return NULL;
}

#define opt_finished(oi) \
  ((oi)->length == 0 || *((oi)->option) == COAP_PAYLOAD_START)

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
    oi->type += coap_opt_delta(oi->option);
  }
  
  /* Skip subsequent options if the filter bit is not set. */
  while (oi->option && coap_option_getb(oi->filter, oi->type) == 0) {
    oi->n++;
    oi->option = options_next(oi->option);

    if (!oi->option || opt_finished(oi))
      return NULL;

    oi->type += coap_opt_delta(oi->option);
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

unsigned short
coap_opt_check_delta(coap_opt_t *opt, size_t maxlen) {
  unsigned short n = 0;

  if (!maxlen)			/* need to look at first byte */
    return 0;

  /* check for option jumps */
  switch (*opt) {
  case 0xf1: 
  case 0xf2: 
  case 0xf3:
    n += (*opt & 0x03);
    break;
  default:
    ;
  }
  
  return n < maxlen ? n+1 : 0;
}

unsigned short
coap_opt_delta(coap_opt_t *opt) {
  unsigned short n;

  n = *opt & 0xf0;

  switch (n) {
  case 15: /* error */
    warn("coap_opt_delta: illegal option delta\n");

    /* This case usually should not happen, hence we do not have a
     * proper way to indicate an error. */
    return 0;
  case 14: 
    /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
     * After that, the option pointer is advanced to the LSB which is handled
     * just like case delta == 13. */
    n = ((*opt & 0xff) << 8) + 269;
    ++opt;
    /* fall through */
  case 13:
    n += *opt & 0xff;
    break;
  default: /* n already contains the actual delta value */
    ;
  }

  return n;
}

/**
 * Skips the bytes that are used to encode an option jump. The caller
 * of this function must ensure that @p opt is still valid afterwards.
 */
#define COAP_SKIP_OPTION_JUMP(opt)		   \
  do {						   \
    switch (*(opt)) {				   \
    case 0xf1: case 0xf2: case 0xf3:		   \
      (opt) = PCHAR(opt) + (*(opt) & 0x03);	   \
      break;                    		   \
    default:					   \
      ;						   \
    }						   \
  } while (0)

unsigned short
coap_opt_length(const coap_opt_t *opt) {
  unsigned short length;

  COAP_SKIP_OPTION_JUMP(opt);

  if ((*opt & 0xf0) == 0xf0)	/* not an option -> length is 0 */
    return 0;

  if ((*opt & 0x0f) < 15)		/* 0..14 */
    return *opt & 0x0f;
  
  length = 15;

  /* add 255 for each 0xff byte */
  while (*++opt == 0xff && length < 780)
    length += 255;
    
  return length + (*opt & 0xff);
}

unsigned char *
coap_opt_value(coap_opt_t *opt) {
  unsigned char *p = opt;
  unsigned char n = 0;

  COAP_SKIP_OPTION_JUMP(p);

  if ((*p & 0xf0) == 0xf0) /* something we do not know, possibly encoding error */
    return NULL;
  
  if ((*p & 0x0f) < 15)		/* 0..14 */
    return ++p;
  
  while (*++p == 0xff && n++ < 3)
    ;

  return p;
}

size_t
coap_opt_size(coap_opt_t *opt) {
  unsigned char *opt_value = coap_opt_value(opt);
  if (opt_value)
    return (opt_value + coap_opt_length(opt)) - PCHAR(opt);
  else
    return 0;
}
 
size_t
coap_opt_setheader(coap_opt_t *opt, size_t maxlen, 
		   unsigned short delta, size_t length) {
  size_t skip = 0;

  assert(opt);

  if (maxlen == 0)		/* need at least one byte */
    return 0;

  if (delta < 13) {
    opt[0] = delta << 4;
  } else if (delta < 270) {
    if (maxlen < 2) {
      warn("insufficient space to encode option delta %d", delta);
      return 0;
    }

    opt[0] = 0xd0;
    opt[++skip] = delta - 13;
  } else {
    if (maxlen < 3) {
      warn("insufficient space to encode option delta %d", delta);
      return 0;
    }

    opt[0] = 0xe0;
    opt[++skip] = ((delta - 269) >> 8) & 0xff;
    opt[++skip] = (delta - 269) & 0xff;    
  }
    
  if (length < 13) {
    opt[0] |= length << 4;
  } else if (length < 270) {
    if (maxlen < skip + 1) {
      warn("insufficient space to encode option length %d", length);
      return 0;
    }
    
    opt[0] |= 0x0d;
    opt[++skip] = length - 13;
  } else {
    if (maxlen < skip + 2) {
      warn("insufficient space to encode option delta %d", delta);
      return 0;
    }

    opt[0] |= 0xe0;
    opt[++skip] = ((length - 269) >> 8) & 0xff;
    opt[++skip] = (length - 269) & 0xff;    
  }

  return skip + 1;
}

size_t
coap_opt_encode(coap_opt_t *opt, size_t maxlen, unsigned short delta,
		const unsigned char *val, size_t length) {
  size_t l = 1;
  unsigned short n = 0;

  /* FIXME: coap_opt_setheader */

  /* option length must not exceed 1034 bytes */
  if (length > 1034) {
    warn("coap_opt_encode(): option length must not exceed 1034 bytes\n");
    return 0;
  }

  /* "reserve" space for length encoding */
  n = length;
  while (n > 255 && maxlen) {
    n -= 255;
    --maxlen;
  }

  if (!maxlen) {
    warn("coap_opt_encode(): insufficient space to encode option length\n");
    return 0;
  }

  /* check for option jumps */

  if (delta < 15) { 
    /* no option jump required, proceed with normal encoding if
       sufficient space is available */
    if (maxlen < length + 1)
      return 0;

    goto encode;
  } 

  if (delta < 30) {		/* encode with short option jump */
    /* check if sufficient storage space is available */
    if (maxlen < length + 2)
      return 0;
    
    delta -= 15;
    l++;		       /* need one additional byte for 0xf1 */
    *opt++ = 0xf1;

    goto encode;
  } 

  /* Values up to 2070 can be encoded with a single jump value
   * (((0xff + 2) << 3) + 14) == 257 * 8 + 14 = 2070). For values 
   * below 2064, we use the last three bits from delta as the 
   * delta value and always encode n as (delta >> 3) - 2. Above
   * 2064, n will be (delta >> 3) - 3, and 
   * delta = delta - ((n + 2) << 3).
   */ 
  if (delta < 2071) {		/* longer option jump */
    /* check if sufficient storage space is available */
    if (maxlen < length + 2)
      return 0;

    n = (delta >> 3) - 2;

    if (n > 255) {
      n--;
      delta = (delta + 8) & 0x0f;
    } else
      delta = (delta & 0x07);

    l += 2;		   /* need two additional bytes for 0xf2 nn */
    *opt++ = 0xf2;
    *opt++ = n & 0xff;

    goto encode;
  }

  /* longest option jump (delta <= 65535) */

  /* check if sufficient storage space is available */
  if (maxlen < length + 3)
    return 0;

  n = (delta >> 3) - 258;
  delta = (delta & 0x07);

  l += 3;	      /* need three additional bytes for 0xf3 nn nn */
  *opt++ = 0xf3;
  *opt++ = (n >> 8) & 0xff;
  *opt++ = n & 0xff;

 encode:
  assert(length <= 1034);
  assert(length + l <= maxlen);

  /*
    FIXME: 
    opt = (delta << 4);
    n = coap_opt_setlength(opt, maxlen, length) + 1;
    opt += n;
   */

  if (length < 15) {
    *opt++ = (delta << 4) | (length & 0x0f);
  } else {
    *opt++ = (delta << 4) | 0x0f;

    /* We know that we have sufficient space for length encoding as
     * this has been checked at the very beginning of this
     * function. */
    
    n = length - 15;
    while (n > 255) {
      *opt++ = 0xff;
      n -= 255;
      ++l;
    }

    *opt++ = n & 0xff;
  }

  if (val)			/* better be safe here */
    memcpy(opt, val, length);

  return l + length;
}

