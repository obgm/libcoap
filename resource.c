/* resource.c -- generic resource handling
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include "resource.h"

int 
coap_add_resource(coap_context_t *context, 
		  const unsigned char *s, unsigned int len,
		  coap_resource_t *resource, coap_key_t *key) {

  if ( !context || !resource)
    return 0;

  memset(resource->key, 0, sizeof(coap_key_t));
  coap_hash(s, len, resource->key);

  HASH_ADD(hh, context->resources, key, sizeof(coap_key_t), resource);
  return 1;
}

int
coap_delete_resource(coap_context_t *context, coap_key_t key) {
  coap_resource_t *resource;

  if (!context)
    return 0;

  resource = coap_get_resource_from_key(context, key);

  if (!resource) 
    return 0;
    
  HASH_DELETE(hh, context->resources, resource);
  free(resource);

  return 1;
}

