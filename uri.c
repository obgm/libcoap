/* uri.c -- helper functions for URI treatment
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "mem.h"
#include "debug.h"
#include "pdu.h"
#include "uri.h"

int
coap_split_uri(unsigned char *str_var, size_t len, coap_uri_t *uri) {
  unsigned char *p, *q;
  int secure = 0, res = 0;

  if (!str_var || !uri)
    return -1;

  memset(uri, 0, sizeof(coap_uri_t));
  uri->port = COAP_DEFAULT_PORT;

  /* search for scheme */
  p = str_var;
  if (*p == '/')
    goto path;
  
  q = (unsigned char *)COAP_DEFAULT_SCHEME;
  while (len && *q && tolower(*p) == *q) {
    ++p; ++q; --len;
  }
  
  /* If q does not point to the string end marker '\0', the schema
   * identifier is wrong. */
  if (*q) {
    res = -1;
    goto error;
  }

  /* There might be an additional 's', indicating the secure version: */
  if ( len && (secure = tolower(*p) == 's') )
    ++p;

  q = (unsigned char *)"://";
  while (len && *q && tolower(*p) == *q) {
    ++p; ++q; --len;
  }

  if (*q) {
    res = -2;
    goto error;
  }

  /* p points to beginning of Uri-Host */
  q = p;
  if (len && *p == '[') {	/* IPv6 address reference */
    ++p;
    
    while (len && *q != ']') {
      ++q; --len;
    }

    if (!len || *q != ']' || p == q) {
      res = -3;
      goto error;
    } 

    COAP_SET_STR(&uri->host, q - p, p);
    ++q; --len;
  } else {			/* IPv4 address or FQDN */
    while (len && *q != ':' && *q != '/' && *q != '?') {
      *q = tolower(*q);
      ++q;
      --len;
    }

    if (p == q) {
      res = -3;
      goto error;
    }

    COAP_SET_STR(&uri->host, q - p, p);
  }

  /* check for Uri-Port */
  if (len && *q == ':') {
    p = ++q;
    --len;
    
    while (len && isdigit(*q)) {
      ++q;
      --len;
    }

    if (p < q) {		/* explicit port number given */
      int uri_port = 0;
    
      while (p < q)
	uri_port = uri_port * 10 + (*p++ - '0');

      uri->port = uri_port;
    } 
  }
  
 path:		 /* at this point, p must point to an absolute path */

  if (!len)
    goto end;
  
  if (*q == '/') {
    p = ++q;
    --len;

    while (len && *q != '?') {
      ++q;
      --len;
    }
  
    if (p < q) {
      COAP_SET_STR(&uri->path, q - p, p);
      p = q;
    }
  }

  /* Uri_Query */
  if (len && *p == '?') {
    ++p;
    COAP_SET_STR(&uri->query, len, p);
    len = 0;
  }

  end:
  return len ? -1 : 0;
  
  error:
  return res;
}

#define URI_DATA(uriobj) ((unsigned char *)(uriobj) + sizeof(coap_uri_t))

coap_uri_t *
coap_new_uri(const unsigned char *uri, unsigned int length) {
  unsigned char *result = coap_malloc(length + 1 + sizeof(coap_uri_t));
  if ( !result )
    return NULL;

  memcpy(URI_DATA(result), uri, length);
  URI_DATA(result)[length] = '\0'; /* make it zero-terminated */

  coap_split_uri( URI_DATA(result), length, (coap_uri_t *)result );
  return (coap_uri_t *)result;
}

coap_uri_t *
coap_clone_uri(const coap_uri_t *uri) {
  coap_uri_t *result;

  if ( !uri )
    return  NULL;

  result = (coap_uri_t *)coap_malloc( uri->query.length + uri->host.length +
				      uri->path.length + sizeof(coap_uri_t) + 1);

  if ( !result )
    return NULL;

  memset( result, 0, sizeof(coap_uri_t) );

  result->port = uri->port;

  if ( uri->host.length ) {
    result->host.s = URI_DATA(result);
    result->host.length = uri->host.length;

    memcpy(result->host.s, uri->host.s, uri->host.length);
  }

  if ( uri->path.length ) {
    result->path.s = URI_DATA(result) + uri->host.length;
    result->path.length = uri->path.length;

    memcpy(result->path.s, uri->path.s, uri->path.length);
  }

  if ( uri->query.length ) {
    result->query.s = URI_DATA(result) + uri->host.length + uri->path.length;
    result->query.length = uri->query.length;

    memcpy(result->query.s, uri->query.s, uri->query.length);
  }

  return result;
}
