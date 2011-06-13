/* debug.c -- debug utilities
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#ifndef NDEBUG

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include "debug.h"
#include "net.h"

#ifdef HAVE_TIME_H

static inline size_t
print_timestamp(char *s, size_t len, coap_tick_t t) {
  struct tm *tmp;
  time_t now = clock_offset + (t / COAP_TICKS_PER_SECOND);
  tmp = localtime(&now);
  return strftime(s, len, "%b %d %H:%M:%S", tmp);
}

#else /* alternative implementation: just print the timestamp */

static inline size_t
print_timestamp(char *s, size_t len, coap_tick_t t) {
  return snprintf(s, len, "%u.%03u", 
		  clock_offset + (t / COAP_TICKS_PER_SECOND), 
		  t % COAP_TICKS_PER_SECOND);
}

#endif /* HAVE_TIME_H */

void debug(char *format, ...) {
  static char timebuf[32];

  coap_tick_t now;
  va_list ap;

  coap_ticks(&now);
  if (print_timestamp(timebuf,sizeof(timebuf), now))
    fprintf(COAP_DEBUG_FD, "%s ", timebuf);

  va_start(ap, format);
  vfprintf(COAP_DEBUG_FD, format, ap);
  va_end(ap);
  fflush(stdout);
}

unsigned int
print_readable( const unsigned char *data, unsigned int len,
		unsigned char *result, unsigned int buflen, int encode_always ) {
  static const unsigned char hex[] = "0123456789ABCDEF";
  unsigned int cnt = 0;
  while ( len && (cnt < buflen-1) ) {
    if ( !encode_always && isprint( *data ) ) {
      *result++ = *data;
      ++cnt;
    } else {
      if ( cnt+4 < buflen-1 ) {
	*result++ = '\\';
	*result++ = 'x';
	*result++ = hex[(*data & 0xf0) >> 4];
	*result++ = hex[*data & 0x0f ];
	cnt += 4;
      } else
	break;
    }

    ++data; --len;
  }

  *result = '\0';
  return cnt;
}

void
coap_show_pdu(const coap_pdu_t *pdu) {
  unsigned char buf[COAP_MAX_PDU_SIZE]; /* need some space for output creation */

  fprintf(COAP_DEBUG_FD, "pdu (%d bytes)", pdu->length);
  fprintf(COAP_DEBUG_FD, " v:%d t:%d oc:%d c:%d id:%u", 
	  pdu->hdr->version, pdu->hdr->type,
	  pdu->hdr->optcnt, pdu->hdr->code, ntohs(pdu->hdr->id));

  /* show options, if any */
  if (pdu->hdr->optcnt) {
    coap_opt_iterator_t opt_iter;
    coap_option_iterator_init((coap_pdu_t *)pdu, &opt_iter, COAP_OPT_ALL);

    fprintf(COAP_DEBUG_FD, " o:");
    while (coap_option_next(&opt_iter)) {

      if (print_readable(COAP_OPT_VALUE(opt_iter.option), 
			 COAP_OPT_LENGTH(opt_iter.option), 
			 buf, sizeof(buf), 0 ))
	fprintf(COAP_DEBUG_FD, " %d:%s", opt_iter.type, buf);
    }
  }
  
  if (pdu->data < (unsigned char *)pdu->hdr + pdu->length) {
    print_readable(pdu->data, 
		   (unsigned char *)pdu->hdr + pdu->length - pdu->data, 
		   buf, COAP_MAX_PDU_SIZE, 0 );
    fprintf(COAP_DEBUG_FD, " d:%s", buf);
  }
  fprintf(COAP_DEBUG_FD, "\n");
  fflush(COAP_DEBUG_FD);
}

#endif /* NDEBUG */
