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
# ifndef assert
#  define assert(...) 
# endif
#endif

#include "uthash.h"
#include "hashkey.h"
#include "async.h"
#include "str.h"
#include "pdu.h"
#include "net.h"

/** Definition of message handler function (@sa coap_resource_t). */
typedef void (*coap_method_handler_t)
  (coap_context_t  *, struct coap_resource_t *, coap_address_t *, coap_pdu_t *,
   coap_tid_t);

typedef struct coap_attr_t {
  struct coap_attr_t *next;
  str name;
  str value;
} coap_attr_t;

typedef struct coap_resource_t {
  unsigned int dirty:1;	      /**< set to 1 if resource has changed */
  unsigned int observeable:1; /**< can be observed */
  unsigned int cacheable:1;   /**< can be cached */

  /** 
   * Used to store handlers for the four coap methods @c GET, @c POST,
   * @c PUT, and @c DELETE. coap_dispatch() will pass incoming
   * requests to the handler that corresponds to its request method or
   * generate a 4.05 response if no handler is available.
   */
  coap_method_handler_t handler[4];

  UT_hash_handle hh;	/**< hash handle (for internal use only) */
  coap_key_t key;	/**< the actual key bytes for this resource */

  coap_attr_t *link_attr; /**< attributes to be included with the link format */

  /**
   * Request URI for this resource. This field will point into the
   * static memory unless @c copy was set in coap_resource_init(). */
  str uri;
} coap_resource_t;

/** 
 * Creates a new resource object and initializes the link field to the
 * string of length @p len given in @p link. If @p copy is set to @c
 * 0, only the pointers will be set. If @p copy is set to @c 1, the
 * contents of @p link will be copied to the new object. In either
 * case, the storage occupied by @p link will @b not be released on
 * destruction of this resource. If @p link is not set, this resource
 * will not be included in a link format description created by the default
 * handler for the URI @c .well-known/core.  This function returns the
 * new coap_resource_t object.
 * 
 * @param uri  The URI path of the new resource.
 * @param len  The length of @p uri.
 * @param copy Set to @c 1 if you want the @p uri to be copied into
 *             the resource, @c 0 otherwise.
 * 
 * @return A pointer to the new object or @c NULL on error.
 */
coap_resource_t *coap_resource_init(const unsigned char *uri, size_t len, int copy);

/**
 * Registers the given @p resource for @p context. The resource must
 * have been created by coap_resource_init(), the storage allocated
 * for the resource will be released by coap_delete_resource().
 * 
 * @param context  The context to use.
 * @param resource The resource to store.
 */
static inline void
coap_add_resource(coap_context_t *context, coap_resource_t *resource) {
  HASH_ADD(hh, context->resources, key, sizeof(coap_key_t), resource);
}

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
 * Registers a new attribute with the given @p resource. @p name and
 * @p value will be copied when @p copy is set. Otherwise, the
 * attributes str fields will point to @p name and @p val itself.
 * 
 * @param resource  The resource to register the attribute with.
 * @param name      The attribute's name.
 * @param nlen      Length of @p name.
 * @param val       The attribute's value or @c NULL if none.
 * @param vlen      Length of @p val if specified.
 * @param copy      If set, a local copy of @p name and @p val will 
 *                  be created.
 *
 * @return A pointer to the new attribute or @c NULL on error.
 */
coap_attr_t *coap_add_attr(coap_resource_t *resource, 
			   const unsigned char *name, size_t nlen,
			   const unsigned char *val, size_t vlen,
			   int copy);

/** 
 * Writes a description of this resource in link-format to given text
 * buffer. @p len must be initialized to the maximum length of @p buf
 * and will be set to the number of characters actually written if
 * successful.  This function returns @c 1 on success or @c 0 on
 * error.
 * 
 * @param resource The resource to describe.
 * @param buf      The output buffer to write the description to.
 * @param len      Must be initialized to the length of @p buf and 
 * will be set to the number of characters written on success.
 * 
 * @return @c 1 on success, or @c 0 on error. If @c 0, @p len is
 * undefined.
 */
int coap_print_link(const coap_resource_t *resource, 
		    unsigned char *buf, size_t *len);

/** 
 * Registers the specified @p handler as message handler for the request type
 * @p method 
 * 
 * @param resource The resource for which the handler shall be registered.
 * @param method   The CoAP request method to handle. 
 * @param handler  The handler to register with @p resource.
 */
static inline void
coap_register_handler(coap_resource_t *resource, 
		      unsigned char method, coap_method_handler_t handler) {
  assert(resource);
  assert(method > 0 && (size_t)(method-1) < sizeof(resource->handler)/sizeof(coap_method_handler_t));
  resource->handler[method-1] = handler;
}

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
 * Calculates the hash key for the resource requested by the
 * Uri-Options of @p request.  This function calls coap_hash() for
 * every path segment. 
 * 
 * @param context The context to use.
 * @param request The requesting pdu.
 */
void coap_hash_request_uri(const coap_pdu_t *request, coap_key_t key);

#endif /* _COAP_RESOURCE_H_ */
