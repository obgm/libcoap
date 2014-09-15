/* mem.h -- CoAP memory handling
 *
 * Copyright (C) 2010,2011,2014 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#ifndef _COAP_MEM_H_
#define _COAP_MEM_H_

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

/**
 * Initializes libcoap's memory management. This function must be
 * called once before coap_malloc() can be used on constrained
 * devices.
 */
void coap_memory_init(void);

/**
 * Type specifiers for coap_malloc_type(). Memory objects can be typed
 * to facilitate arrays of type objects to be used instead of dynamic
 * memory management on constrained devices.
 */
typedef enum { 
  COAP_STRING, COAP_ATTRIBUTE_NAME, COAP_ATTRIBUTE_VALUE 
} coap_memory_tag_t;

/**
 * Allocates a chunk of @p size bytes and returns a pointer to the
 * newly allocated memory. The @p type is used to select the
 * appropriate storage container on constrained devices. The storage
 * allocated by coap_malloc_type() must be released with
 * coap_free_type().
 *
 * @param type The type of object to be stored.
 * @param size The number of bytes requested.
 * @return A pointer to the allocated storage or @c NULL on error.
 */
void *coap_malloc_type(coap_memory_tag_t type, size_t size);

/**
 * Releases the memory that was allocated by coap_malloc_type().
 * The type tag @p type must be the same that was used for
 * allocating the object pointed to by @p.
 *
 * @param type The type of the object to release.
 * @param p A pointer to memory that was allocated by
 *          coap_malloc_type().
 */
void coap_free_type(coap_memory_tag_t type, void *p);

/**
 * Wrapper function to coap_malloc_type() for backwards compatibility.
 */
static inline void *coap_malloc(size_t size) {
  return coap_malloc_type(COAP_STRING, size);
}

/**
 * Wrapper function to coap_free_type() for backwards compatibility.
 */
static inline void coap_free(void *object) {
  coap_free_type(COAP_STRING, object);
}

#endif /* _COAP_MEM_H_ */
