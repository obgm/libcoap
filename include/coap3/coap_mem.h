/*
 * coap_mem.h -- CoAP memory handling
 *
 * Copyright (C) 2010-2011,2014-2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_mem.h
 * @brief CoAP memory handling
 */

#ifndef COAP_MEM_H_
#define COAP_MEM_H_

#include "coap3/coap_oscore.h"
#include <stdlib.h>

#ifndef WITH_LWIP
/**
 * Initializes libcoap's memory management.
 * This function must be called once before coap_malloc() can be used on
 * constrained devices.
 */
void coap_memory_init(void);
#endif /* WITH_LWIP */

/**
 * Type specifiers for coap_malloc_type(). Memory objects can be typed to
 * facilitate arrays of type objects to be used instead of dynamic memory
 * management on constrained devices.
 */
typedef enum {
  COAP_STRING,
  COAP_ATTRIBUTE_NAME,
  COAP_ATTRIBUTE_VALUE,
  COAP_PACKET,
  COAP_NODE,
  COAP_CONTEXT,
  COAP_ENDPOINT,
  COAP_PDU,
  COAP_PDU_BUF,
  COAP_RESOURCE,
  COAP_RESOURCEATTR,
  COAP_DTLS_SESSION,
  COAP_SESSION,
  COAP_OPTLIST,
  COAP_CACHE_KEY,
  COAP_CACHE_ENTRY,
  COAP_LG_XMIT,
  COAP_LG_CRCV,
  COAP_LG_SRCV,
  COAP_DIGEST_CTX,
  COAP_SUBSCRIPTION,
  COAP_DTLS_CONTEXT,
  COAP_OSCORE_COM,
  COAP_OSCORE_SEN,
  COAP_OSCORE_REC,
  COAP_OSCORE_EX,
  COAP_OSCORE_EP,
  COAP_OSCORE_BUF,
  COAP_COSE,
  COAP_MEM_TAG_LAST
} coap_memory_tag_t;

#ifndef WITH_LWIP

/**
 * Allocates a chunk of @p size bytes and returns a pointer to the newly
 * allocated memory. The @p type is used to select the appropriate storage
 * container on constrained devices. The storage allocated by coap_malloc_type()
 * must be released with coap_free_type().
 *
 * @param type The type of object to be stored.
 * @param size The number of bytes requested.
 * @return     A pointer to the allocated storage or @c NULL on error.
 */
void *coap_malloc_type(coap_memory_tag_t type, size_t size);

/**
 * Reallocates a chunk @p p of bytes created by coap_malloc_type() or
 * coap_realloc_type() and returns a pointer to the newly allocated memory of
 * @p size.
 * Only COAP_STRING type is supported.
 *
 * Note: If there is an error, @p p will separately need to be released by
 * coap_free_type().
 *
 * @param type The type of object to be stored.
 * @param p    A pointer to memory that was allocated by coap_malloc_type().
 * @param size The number of bytes requested.
 * @return     A pointer to the allocated storage or @c NULL on error.
 */
void *coap_realloc_type(coap_memory_tag_t type, void *p, size_t size);

/**
 * Releases the memory that was allocated by coap_malloc_type(). The type tag @p
 * type must be the same that was used for allocating the object pointed to by
 * @p .
 *
 * @param type The type of the object to release.
 * @param p    A pointer to memory that was allocated by coap_malloc_type().
 */
void coap_free_type(coap_memory_tag_t type, void *p);

/**
 * Dumps the current usage of malloc'd memory types.
 *
 * Requires COAP_MEMORY_TYPE_TRACK to be defined to 1.
 *
 * @param log_level The logging level to use.
 */
void coap_dump_memory_type_counts(coap_log_t log_level);

/**
 * Wrapper function to coap_malloc_type() for backwards compatibility.
 */
COAP_STATIC_INLINE void *
coap_malloc(size_t size) {
  return coap_malloc_type(COAP_STRING, size);
}

/**
 * Wrapper function to coap_free_type() for backwards compatibility.
 */
COAP_STATIC_INLINE void
coap_free(void *object) {
  coap_free_type(COAP_STRING, object);
}

#endif /* not WITH_LWIP */

#ifdef WITH_LWIP

#include <lwip/memp.h>

/* no initialization needed with lwip (or, more precisely: lwip must be
 * completely initialized anyway by the time coap gets active)  */
COAP_STATIC_INLINE void
coap_memory_init(void) {}

#if MEMP_STATS
COAP_STATIC_INLINE void *
coap_malloc_error(uint16_t *err) {
  (*err)++;
  return NULL;
}
#endif /* MEMP_STATS */
/* It would be nice to check that size equals the size given at the memp
 * declaration, but i currently don't see a standard way to check that without
 * sourcing the custom memp pools and becoming dependent of its syntax
 */
#if MEMP_STATS
#define coap_malloc_type(type, asize) \
  (((asize) <= memp_pools[MEMP_ ## type]->size) ? \
   memp_malloc(MEMP_ ## type) : coap_malloc_error(&memp_pools[MEMP_ ## type]->stats->err))
#else /* ! MEMP_STATS */
#define coap_malloc_type(type, asize) \
  (((asize) <= memp_pools[MEMP_ ## type]->size) ? \
   memp_malloc(MEMP_ ## type) : NULL)
#endif /* ! MEMP_STATS */
#define coap_free_type(type, p) memp_free(MEMP_ ## type, p)

/* As these are fixed size, return value if already defined */
#define coap_realloc_type(type, p, asize) \
  ((p) ? ((asize) <= memp_pools[MEMP_ ## type]->size) ? (p) : NULL : coap_malloc_type(type, asize))

/* Those are just here to make uri.c happy where string allocation has not been
 * made conditional.
 */
COAP_STATIC_INLINE void *
coap_malloc(size_t size) {
  (void)size;
  LWIP_ASSERT("coap_malloc must not be used in lwIP", 0);
}

COAP_STATIC_INLINE void
coap_free(void *pointer) {
  (void)pointer;
  LWIP_ASSERT("coap_free must not be used in lwIP", 0);
}

#define coap_dump_memory_type_counts(l) coap_lwip_dump_memory_pools(l)

#endif /* WITH_LWIP */

#endif /* COAP_MEM_H_ */
