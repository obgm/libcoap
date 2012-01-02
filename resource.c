/* resource.c -- generic resource handling
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include "config.h"
#include "net.h"
#ifndef WITH_CONTIKI
#include "utlist.h"
#endif /* WITH_CONTIKI */
#include "debug.h"
#include "mem.h"
#include "resource.h"

#ifdef WITH_CONTIKI
#include "memb.h"

MEMB(resource_storage, coap_resource_t, COAP_MAX_RESOURCES);
MEMB(attribute_storage, coap_attr_t, COAP_MAX_ATTRIBUTES);
#endif /* WITH_CONTIKI */

void
coap_resources_init() {
  memb_init(&resource_storage);
  memb_init(&attribute_storage);
}

/** 
 * Prints the names of all known resources to @p buf. This function
 * sets @p buflen to the number of bytes actually written and returns
 * @c 1 on succes. On error, the value in @p buflen is undefined and
 * the return value will be @c 0.
 * 
 * @param context The context with the resource map.
 * @param buf     The buffer to write the result.
 * @param buflen  Must be initialized to the maximum length of @p buf and will be
 *                set to the number of bytes written on return.
 * 
 * @return @c 0 on error or @c 1 on success.
 */
int
print_wellknown(coap_context_t *context, unsigned char *buf, size_t *buflen) {
  coap_resource_t *r;
  unsigned char *p = buf;
  size_t left, written = 0;
#ifndef WITH_CONTIKI
  coap_resource_t *tmp;

  HASH_ITER(hh, context->resources, r, tmp) {
#else /* WITH_CONTIKI */
  int i;

  r = (coap_resource_t *)resource_storage.mem;
  for (i = 0; i < resource_storage.num; ++i, ++r) {
    if (!resource_storage.count[i])
      continue;
#endif /* WITH_CONTIKI */

    left = *buflen - written;

    if (left < *buflen) {	/* this is not the first resource  */
      *p++ = ',';
      --left;
    }

    if (!coap_print_link(r, p, &left))
      return 0;
    
    p += left;
    written += left;
  }
  *buflen = p - buf;
  return 1;
}

coap_resource_t *
coap_resource_init(const unsigned char *uri, size_t len) {
  coap_resource_t *r;

#ifndef WITH_CONTIKI
  r = (coap_resource_t *)coap_malloc(sizeof(coap_resource_t));
#else /* WITH_CONTIKI */
  r = (coap_resource_t *)memb_alloc(&resource_storage);
#endif /* WITH_CONTIKI */
  if (r) {
    memset(r, 0, sizeof(coap_resource_t));
    r->uri.s = (unsigned char *)uri;
    r->uri.length = len;
    
    coap_hash_path(r->uri.s, r->uri.length, r->key);
  } else {
    debug("coap_resource_init: no memory left\n");
  }
  
  return r;
}

coap_attr_t *
coap_add_attr(coap_resource_t *resource, 
	      const unsigned char *name, size_t nlen,
	      const unsigned char *val, size_t vlen) {
  coap_attr_t *attr;

  if (!resource || !name)
    return NULL;

#ifndef WITH_CONTIKI
  attr = (coap_attr_t *)coap_malloc(sizeof(coap_attr_t));
#else /* WITH_CONTIKI */
  attr = (coap_attr_t *)memb_alloc(&attribute_storage);
#endif /* WITH_CONTIKI */

  if (attr) {
    attr->name.length = nlen;
    attr->value.length = val ? vlen : 0;

    attr->name.s = (unsigned char *)name;
    attr->value.s = (unsigned char *)val;

    /* add attribute to resource list */
#ifndef WITH_CONTIKI
    LL_PREPEND(resource->link_attr, attr);
#else /* WITH_CONTIKI */
    attr->next = resource->link_attr;
    resource->link_attr = attr;
#endif /* WITH_CONTIKI */    
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

void
coap_add_resource(coap_context_t *context, coap_resource_t *resource) {
#ifndef WITH_CONTIKI
  HASH_ADD(hh, context->resources, key, sizeof(coap_key_t), resource);
#endif /* WITH_CONTIKI */
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
    
#ifndef WITH_CONTIKI
  HASH_DELETE(hh, context->resources, resource);

  /* delete registered attributes */
  LL_FOREACH(resource->link_attr, attr) coap_free(attr);

  coap_free(resource);
#else /* WITH_CONTIKI */
  /* delete registered attributes */
  while (resource->link_attr) {
    attr = resource->link_attr;
    resource->link_attr = resource->link_attr->next;
    memb_free(&attribute_storage, attr);
  } 

  memb_free(&resource_storage, resource);
#endif /* WITH_CONTIKI */

  return 1;
}

coap_resource_t *
coap_get_resource_from_key(coap_context_t *context, coap_key_t key) {
#ifndef WITH_CONTIKI
  coap_resource_t *resource;
  HASH_FIND(hh, context->resources, key, sizeof(coap_key_t), resource);

  return resource;
#else /* WITH_CONTIKI */
  int i;
  coap_resource_t *ptr2;

  /* the search function is basically taken from memb.c */
  ptr2 = (coap_resource_t *)resource_storage.mem;
  for (i = 0; i < resource_storage.num; ++i) {
    if (resource_storage.count[i] && 
	(memcmp(ptr2->key, key, sizeof(coap_key_t)) == 0))
      return (coap_resource_t *)ptr2;
    ++ptr2;
  }

  return NULL;
#endif /* WITH_CONTIKI */
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

#ifndef WITH_CONTIKI
  LL_FOREACH(resource->link_attr, attr) {
#else /* WITH_CONTIKI */
  for (attr = resource->link_attr; attr; attr = attr->next) {
#endif /* WITH_CONTIKI */
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
