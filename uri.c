/* uri.c -- helper functions for URI treatment
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "uri.h"

int
coap_split_uri( char *str, coap_uri_t *uri) {
  char *p;

  if ( !str || !uri )
    return -1;

  memset( uri, 0, sizeof(coap_uri_t) );

  /* find scheme */
  p = str;
  while ( isalnum(*p) )
    ++p;

  if ( *p != ':' ) {		/* no scheme, reset p */
    p = str;
  } else {			/* scheme found, look for network authority */
    *p++ = '\0';
    uri->scheme = str;
    if ( strncmp( p, "//", 2 ) == 0 ) { /* have network authority */
      p += 2;
      uri->na = p;

      /* skip NA and port so that p and str finally point to path */
      while ( *p && *p != '/' ) 
	++p;
      
      if ( *p )
	*p++ = '\0';

      str = p;
#if 0
      /* split server address and port */
      if ( *uri->na == '[' ) {	/* IPv6 address reference */
	p = ++uri->na;

	while ( *p && *p != ']' ) 
	  ++p;
	*p++ = '\0';
      } else {			/* IPv4 address or hostname */
	p = uri->na;
	while ( *p && *p != ':' ) 
	  ++p;
      }
    
      if ( *p == ':' ) {	/* handle port */
	*p++ = '\0';
	uri->port = p;
      }
#endif
    } else 
      str = p;			

    /* str now points to the path */
  }

  /* split path and query */
  if ( *str == '\0' )
    return 0;

#if 1
    uri->path = str;
#else
  if (*str != '?')
    uri->path = str++;

  while (*str && *str != '?')
    str++;

  if (*str == '?') {
    *str++ = '\0';

    if (*str)			/* we do not want to point query to an empty string */
      uri->query = str;
  }
#endif

  return 0;
}
