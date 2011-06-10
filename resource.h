/* resource.h -- generic resource handling
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

/** 
 * @file resource.h
 * @brief generic resource handling
 */

#ifndef _COAP_RESOURCE_H_
#define _COAP_RESOURCE_H_

#ifdef HAVE_ASSERT_H
#include <assert.h>
#else
#define assert(...) 
#endif

#include "uthash.h"
#include "str.h"
#include "pdu.h"
#include "net.h"

typedef unsigned char coap_key_t[4];

#ifndef coap_hash
/** 
 * Calculates a fast hash over the given string @p s of length @p len
 * and stores the result into @p h. Depending on the exact
 * implementation, this function cannot be used as one-way function to
 * check message integrity or simlar.
 * 
 * @param s   The string used for hash calculation.
 * @param len The length of @p s.
 * @param h   The result buffer to store the calculated hash key.
 */
void coap_hash_impl(const unsigned char *s, unsigned int len, coap_key_t h);

#define coap_hash(String,Length,Result) \
  coap_hash_impl((String),(Length),(Result))
#endif /* coap_hash */

/** 
 * Calls coap_hash() with given @c str object as parameter.
 * 
 * @param Str Must contain a pointer to a coap string object.
 * @param H   A coap_key_t object to store the result.
 * 
 * @hideinitializer
 */
#define coap_str_hash(Str,H) {			\
    assert(Str);				\
    memset((H), 0, sizeof(coap_key_t));		\
    coap_hash((H), (Str)->s, (Str)->length);	\
  }

typedef struct coap_resource_t {
  unsigned int dirty:1;	      /**< set to 1 if resource has changed */
  unsigned int async:1;	      /**< is asynchronous */
  unsigned int observeable:1; /**< can be observed */
  unsigned int cacheable:1;   /**< can be cached */

#define METHOD_HANDLER(m)						\
  coap_pdu_t *(*handle_##m)(coap_context_t  *, struct coap_resource_t *, \
			    coap_address_t *, coap_pdu_t *)

  METHOD_HANDLER(get);
  METHOD_HANDLER(put);
  METHOD_HANDLER(post);
  METHOD_HANDLER(delete);

#undef METHOD_HANDLER

  UT_hash_handle hh;	/**< hash handle (for internal use only) */
  coap_key_t key;	/**< the actual key bytes for this resource */
} coap_resource_t;

/**
 * Registers the given @p resource for @p context. The storage
 * allocated for 
 * 
 * @param context  The context to use.
 * @param s        A string to identify this resource.
 * @param len      Length of @p s.
 * @param resource The resource to store.
 * @param key      A pointer to store the generated hash key.
 * 
 * @return @c 1 on success, @c 0 otherwise.
 */
int coap_add_resource(coap_context_t *context, 
		      const unsigned char *s, unsigned int len,
		      coap_resource_t *resource, coap_key_t *key); 

/** 
 * Deletes a resource identified by @p key. The storage allocated for
 * that resource is freed.
 * 
 * @param context  The context where the resources are stored.
 * @param key      The unique key for the resource to delete.
 * 
 * @return @c 1 if the resource was found (and destroyed), @c 0 otherwise.
 */
int coap_delete_resource(coap_context_t *context, coap_key_t key);

/** 
 * Returns the resource identified by the unique string @p key. If no
 * resource was found, this function returns @c NULL.
 * 
 * @param context  The context to look for this resource.
 * @param key      The unique key of the resource.
 * 
 * @return A pointer to the resource or @c NULL if not found.
 */
static inline coap_resource_t *
coap_get_resource_from_key(coap_context_t *context, coap_key_t key) {
  coap_resource_t *resource;

  HASH_FIND(hh, context->resources, key, sizeof(coap_key_t), resource);
  return resource;
}

/** 
 * Retrieves a resource that is identified by the given string @p s of
 * length @p len. This function calls coap_get_resource_from_key()
 * with a hash key that is calculated from @p s by coap_hash(). If no
 * resource was found, the function will return @c NULL, otherwise 
 * a pointer to the coap_resource_t object is returned.
 * 
 * @param context The context to use.
 * @param s       A string that identifies the resource.
 * @param len     The length of @p s.
 * 
 * @return A pointer to the resource or @c NULL if not found.
 */
static inline coap_resource_t *
coap_get_resource(coap_context_t *context,
		  const unsigned char *s, unsigned int len) {
  coap_key_t key;
  coap_hash(s,len,key);
  return coap_get_resource_from_key(context, key);
}

#endif /* _COAP_RESOURCE_H_ */
