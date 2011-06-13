/* resource.c -- generic resource handling
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include "utlist.h"
#include "debug.h"
#include "mem.h"
#include "resource.h"

coap_resource_t *
coap_resource_init(const unsigned char *uri, size_t len, int copy) {
  coap_resource_t *r;
  size_t size = sizeof(coap_resource_t);

  if (copy)
    size += len;

  r = (coap_resource_t *)coap_malloc(size);
  if (r) {
    memset(r, 0, sizeof(coap_resource_t));
    if (copy) {
      r->uri.s = (unsigned char *)r + sizeof(coap_resource_t);
      r->uri.length = len;

      memcpy(r->uri.s, uri, len);
    } else {
      r->uri.s = (unsigned char *)uri;
      r->uri.length = len;
    }
    
    coap_hash_path(r->uri.s, r->uri.length, r->key);
  } else {
    debug("coap_resource_init: no memory left\n");
  }

  return r;
}

coap_attr_t *
coap_add_attr(coap_resource_t *resource, 
	      const unsigned char *name, size_t nlen,
	      const unsigned char *val, size_t vlen,
	      int copy) {
  coap_attr_t *attr;
  size_t size;

  if (!resource || !name)
    return NULL;

  size = sizeof(coap_attr_t);

  /* additional storage is required if we have to copy the strings */
  if (copy) {
    size += nlen;
    if (val)
      size += vlen;
  }

  attr = (coap_attr_t *)coap_malloc(size);
  if (attr) {
    attr->name.length = nlen;
    attr->value.length = val ? vlen : 0;

    if (copy) {
      attr->name.s = (unsigned char *)attr + sizeof(coap_attr_t);
      memcpy(attr->name.s, name, nlen);

      if (val) {
	attr->value.s = attr->name.s + attr->name.length;
	memcpy(attr->value.s, val, vlen);
      } else {
	attr->value.s = NULL;      
      }
    } else {
      attr->name.s = (unsigned char *)name;
      attr->value.s = (unsigned char *)val;
    }

    /* add attribute to resource list */
    LL_PREPEND(resource->link_attr, attr);
    
  } else {
    debug("coap_add_attr: no memory left\n");
  }
  
  return attr;
}

void
coap_hash_request_uri(const coap_pdu_t *request, coap_key_t key) {
  coap_opt_iterator_t opt_iter;
  coap_opt_filter_t filter;

  memset(key, 0, sizeof(coap_key_t));

  coap_option_filter_clear(filter);
  coap_option_setb(filter, COAP_OPTION_URI_PATH);

  coap_option_iterator_init((coap_pdu_t *)request, &opt_iter, filter);
  while (coap_option_next(&opt_iter))
    coap_hash(COAP_OPT_VALUE(opt_iter.option), 
	      COAP_OPT_LENGTH(opt_iter.option), key);
}

int
coap_delete_resource(coap_context_t *context, coap_key_t key) {
  coap_resource_t *resource;
  coap_attr_t *attr;

  if (!context)
    return 0;

  resource = coap_get_resource_from_key(context, key);

  if (!resource) 
    return 0;
    
  HASH_DELETE(hh, context->resources, resource);

  /* delete registered attributes */
  LL_FOREACH(resource->link_attr, attr) coap_free(attr);

  coap_free(resource);

  return 1;
}

int
coap_print_link(const coap_resource_t *resource, 
		unsigned char *buf, size_t *len) {
  unsigned char *p = buf;
  coap_attr_t *attr;

  size_t written = resource->uri.length + 3;
  if (*len < written) 
    return 0;

  *p++ = '<';
  *p++ = '/';
  memcpy(p, resource->uri.s, resource->uri.length);
  p += resource->uri.length;
  *p++ = '>';

  LL_FOREACH(resource->link_attr, attr) {
    written += attr->name.length + 1;
    if (*len < written)
      return 0;

    *p++ = ';';
    memcpy(p, attr->name.s, attr->name.length);
    p += attr->name.length;

    if (attr->value.s) {
      written += attr->value.length + 1;
      if (*len < written)
	return 0;
      
      *p++ = '=';
      memcpy(p, attr->value.s, attr->value.length);
      p += attr->value.length;
    }
  }

  *len = written;
  return 1;
}
