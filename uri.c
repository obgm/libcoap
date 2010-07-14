/* uri.c -- helper functions for URI treatment
 *
 * (c) 2010 Olaf Bergmann <bergmann@tzi.org>
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "mem.h"
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
  uri->path = *str == '/' ? ++str : str;
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

#define URI_DATA(uriobj) ((uriobj) + sizeof(coap_uri_t))

coap_uri_t *
coap_new_uri(const char *uri) {
  char *result = coap_malloc( strlen(uri) + 1 + sizeof(coap_uri_t) );
  if ( !result )
    return NULL;
  
  memcpy( URI_DATA(result), uri, strlen(uri) + 1 );
  
  coap_split_uri( URI_DATA(result), (coap_uri_t *)result );
  return (coap_uri_t *)result;
}

coap_uri_t *
coap_clone_uri( const coap_uri_t *uri) {
  unsigned int schemelen, nalen, pathlen;
  unsigned char *result;

  if ( !uri ) 
    return  NULL;

  schemelen = uri->scheme ? strlen(uri->scheme) + 1 : 0;
  nalen     = uri->na ? strlen(uri->na) + 1 : 0;
  pathlen   = uri->path ? strlen(uri->path) + 1 : 0;

  result = coap_malloc( schemelen + nalen + pathlen + sizeof(coap_uri_t) );

  if ( !result )
    return NULL;

  memset( result, 0, sizeof(coap_uri_t) );
  if ( schemelen ) {
    memcpy( URI_DATA(result), uri->scheme, schemelen );
    ((coap_uri_t *)result)->scheme = uri->scheme;
  }

  if ( nalen ) {
    memcpy( URI_DATA(result) + schemelen, uri->na, nalen );
    ((coap_uri_t *)result)->na = uri->na;
  }

  if ( pathlen ) {
    memcpy( URI_DATA(result) + schemelen + nalen, uri->path, pathlen );
    ((coap_uri_t *)result)->path = uri->path;
  }

  return (coap_uri_t *)result;
}
