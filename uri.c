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
coap_split_uri(unsigned char *str, coap_uri_t *uri) {
  unsigned char *p;

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
    COAP_SET_STR(&uri->scheme, p - str, str);
    *p++ = '\0';
    if ( strncmp( (char *)p, "//", 2 ) == 0 ) { /* have network authority */
      p += 2;
      uri->na.s = p;

      /* skip NA and port so that p and str finally point to path */
      while ( *p && *p != '/' ) 
	++p;
      
      uri->na.length = p - uri->na.s;
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
  uri->path.s = *str == '/' ? ++str : str;
  uri->path.length = strlen((char *)uri->path.s);
#else
  if (*str != '?')
    uri->path.s = str++;

  while (*str && *str != '?')
    str++;

  if (*str == '?') {
    uri->path.length = str - uri->path.s;
    *str++ = '\0';

    if (*str) {			/* we do not want to point query to an empty string */
      uri->query.s = str;
      uri->query.length = strlen(uri->query.s);
    }
  }
#endif

  return 0;
}

#define URI_DATA(uriobj) ((unsigned char *)(uriobj) + sizeof(coap_uri_t))

coap_uri_t *
coap_new_uri(const unsigned char *uri, unsigned int length) {
  unsigned char *result = coap_malloc(length + 1 + sizeof(coap_uri_t));
  if ( !result )
    return NULL;
  
  memcpy(URI_DATA(result), uri, length);
  URI_DATA(result)[length] = '\0'; /* make it zero-terminated */

  coap_split_uri( URI_DATA(result), (coap_uri_t *)result );
  return (coap_uri_t *)result;
}

coap_uri_t *
coap_clone_uri(const coap_uri_t *uri) {
  coap_uri_t *result;

  if ( !uri ) 
    return  NULL;

  result = (coap_uri_t *)coap_malloc( uri->scheme.length + uri->na.length + 
				      uri->path.length + sizeof(coap_uri_t) + 1);

  if ( !result )
    return NULL;

  memset( result, 0, sizeof(coap_uri_t) );
  if ( uri->scheme.length ) {
    result->scheme.s = URI_DATA(result);
    result->scheme.length = uri->scheme.length;

    memcpy(result->scheme.s, uri->scheme.s, uri->scheme.length);
  }

  if ( uri->na.length ) {
    result->na.s = URI_DATA(result) + uri->scheme.length;
    result->na.length = uri->na.length;

    memcpy(result->na.s, uri->na.s, uri->na.length);
  }

  if ( uri->path.length ) {
    result->path.s = URI_DATA(result) + uri->scheme.length + uri->na.length;
    result->path.length = uri->path.length;

    memcpy(result->path.s, uri->path.s, uri->path.length);
  }

  return result;
}
