/* mem.c -- CoAP memory handling
 *
 * Copyright (C) 2014 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */


#include "config.h"
#include "mem.h"
#include "debug.h"

#ifdef HAVE_ASSERT_H
#include <assert.h>
#else /* HAVE_ASSERT_H */
#define assert(...)
#endif /* HAVE_ASSERT_H */

#ifdef HAVE_MALLOC
#include <stdlib.h>

void
coap_memory_init(void) {
}

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__((unused))
#else
#define UNUSED_PARAM
#endif /* __GNUC__ */

void *
coap_malloc_type(coap_memory_tag_t type UNUSED_PARAM, size_t size) {
  return malloc(size);
}

void
coap_free_type(coap_memory_tag_t type UNUSED_PARAM, void *p) {
  free(p);
}

#else /* HAVE_MALLOC */

#ifdef WITH_CONTIKI
#define COAP_MAX_STRING_SIZE 12
#define COAP_MAX_STRINGS      8

struct coap_string_t {
  char data[COAP_MAX_STRING_SIZE];
};

MEMB(string_storage, struct coap_string_t, COAP_MAX_STRINGS);

static struct memb *
get_container(coap_memory_tag_t type) {
  switch(type) {
  default:
    return &string_storage;
  }
}

void
coap_memory_init(void) {
  memb_init(&string_storage);
}

void *
coap_malloc_type(coap_memory_tag_t type, size_t size) {
  struct memb *container =  get_container(type);
  
  assert(container);

  if (size > container->size) {
    debug("coap_malloc_type: Requested memory exceeds maximum object size\n");
    return NULL;
  }

  return memb_alloc(container);
}

void
coap_free_type(coap_memory_tag_t type, void *object) {
  memb_free(get_container(type), object);
}
#endif /* WITH_CONTIKI */

#endif /* HAVE_MALLOC */
