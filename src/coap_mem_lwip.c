/*
 * Copyright (C) 2012,2014 Olaf Bergmann <bergmann@tzi.org>
 *               2014      chrysn <chrysn@fsfe.org>
 *               2022-2026 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_dgrm_lwip.c
 * @brief LwIP Datagram (UDP) specific functions
 */

#include "coap3/coap_libcoap_build.h"

#if !defined(COAP_LWIP_USE_STDLIB_ALLOC)

#if defined(WITH_LWIP) && MEMP_USE_CUSTOM_POOLS

#if MEM_USE_POOLS

/* Need to handle COAP_STRING separately */

void *
coap_malloc_type_string(size_t size) {
  void *ptr = mem_malloc(size + sizeof(size_t));

  if (ptr) {
    unsigned int *s_ptr = (unsigned int *)ptr;
    u_char *b_ptr = (u_char *)ptr;

    *s_ptr = size;
    return b_ptr + sizeof(unsigned int);
  }
  return NULL;
}

void *
coap_realloc_type_string(void *p, size_t size) {
  void *new;
  unsigned int *s_ptr = (unsigned int *)p;

  if (*s_ptr <= size)
    return p;

  new = mem_malloc(size + sizeof(unsigned int));

  if (new) {
    u_char *b_ptr = (u_char *)new;

    s_ptr = (unsigned int *)new;
    *s_ptr = size;
    if (p) {
      unsigned int *o_ptr = (unsigned int *)p;

      o_ptr--;
      memcpy(b_ptr + sizeof(unsigned int), p, *o_ptr);
      coap_free_type_string(o_ptr);
    }
    return b_ptr + sizeof(unsigned int);
  }
  return NULL;
}

void
coap_free_type_string(void *p) {
  u_char *ptr = (u_char *)p;

  if (ptr) {
    mem_free(ptr - sizeof(unsigned int));
  }
}

#endif

void
coap_dump_memory_type_counts(coap_log_t log_level) {
#if MEMP_STATS && LWIP_STATS_DISPLAY && MEMP_USE_CUSTOM_POOLS
  int i;

  /* Save time if not needed */
  if (log_level > coap_get_log_level())
    return;

  coap_log(log_level, "*   LwIP custom memory pools information\n");
  /*
   * Make sure LwIP and libcoap have been built with the same
   * -DCOAP_CLIENT_ONLY or -DCOAP_SERVER_ONLY options for
   * MEMP_MAX to be correct.
   */
  for (i = 0; i < MEMP_MAX; i++) {
#if MEM_USE_POOLS
    if (!strcmp("COAP_STRING", memp_pools[i]->stats->name))
      continue;
#endif /* MEM_USE_POOLS */
    coap_log(log_level, "*    %-17s avail %3d  in-use %3d  peak %3d failed %3d\n",
             memp_pools[i]->stats->name, memp_pools[i]->stats->avail,
             memp_pools[i]->stats->used, memp_pools[i]->stats->max,
             memp_pools[i]->stats->err);
  }
#else /* !( MEMP_STATS && LWIP_STATS_DISPLAY && MEMP_USE_CUSTOM_POOLS) */
  (void)log_level;
#endif /* !( MEMP_STATS && LWIP_STATS_DISPLAY && MEMP_USE_CUSTOM_POOLS) */
}

#elif defined(WITH_LWIP) && ! MEMP_USE_CUSTOM_POOLS && ! MEM_LIBC_MALLOC

#include <lwip/mem.h>

#if COAP_MEMORY_TYPE_TRACK
static int track_counts[COAP_MEM_TAG_LAST];
static int peak_counts[COAP_MEM_TAG_LAST];
static int fail_counts[COAP_MEM_TAG_LAST];
#endif /* COAP_MEMORY_TYPE_TRACK */

void
coap_memory_init(void) {
}

void *
coap_malloc_type(coap_memory_tag_t type, size_t size) {
  void *ptr = mem_malloc(size + sizeof(size_t));

  (void)type;
#if COAP_MEMORY_TYPE_TRACK
  assert(type < COAP_MEM_TAG_LAST);
  if (ptr) {
    track_counts[type]++;
    if (track_counts[type] > peak_counts[type])
      peak_counts[type] = track_counts[type];
  } else {
    fail_counts[type]++;
  }
#endif /* COAP_MEMORY_TYPE_TRACK */
  if (ptr) {
    size_t *s_ptr = (size_t *)ptr;
    u_char *b_ptr = (u_char *)ptr;

    *s_ptr = size;
    return b_ptr + sizeof(size_t);
  }
  return NULL;
}

void *
coap_realloc_type(coap_memory_tag_t type, void *p, size_t size) {
  void *new = mem_malloc(size + sizeof(size_t));

  (void)type;
#if COAP_MEMORY_TYPE_TRACK
  if (new) {
    assert(type < COAP_MEM_TAG_LAST);
    if (!p)
      track_counts[type]++;
    if (track_counts[type] > peak_counts[type])
      peak_counts[type] = track_counts[type];
  } else {
    fail_counts[type]++;
  }
#endif /* COAP_MEMORY_TYPE_TRACK */
  if (new) {
    size_t *s_ptr = (size_t *)new;
    u_char *b_ptr = (u_char *)new;

    *s_ptr = size;
    if (p) {
      size_t *o_ptr = (size_t *)p;

      o_ptr--;
      memcpy(b_ptr + sizeof(size_t), p, *o_ptr);
    }
    return b_ptr + sizeof(size_t);
  }
  return NULL;
}

void
coap_free_type(coap_memory_tag_t type, void *p) {
  u_char *ptr = (u_char *)p;

  (void)type;
#if COAP_MEMORY_TYPE_TRACK
  assert(type < COAP_MEM_TAG_LAST);
  if (p)
    track_counts[type]--;
#endif /* COAP_MEMORY_TYPE_TRACK */
  if (ptr) {
    mem_free(ptr - sizeof(size_t));
  }
}

#define MAKE_CASE(n) case n: name = #n; break
void
coap_dump_memory_type_counts(coap_log_t level) {
#if COAP_MEMORY_TYPE_TRACK
  int i;

  coap_log(level, "*  Memory type counts\n");
  for (i = 0; i < COAP_MEM_TAG_LAST; i++) {
    const char *name = "?";


    switch (i) {
      MAKE_CASE(COAP_STRING);
      MAKE_CASE(COAP_ATTRIBUTE_NAME);
      MAKE_CASE(COAP_ATTRIBUTE_VALUE);
      MAKE_CASE(COAP_PACKET);
      MAKE_CASE(COAP_NODE);
      MAKE_CASE(COAP_CONTEXT);
      MAKE_CASE(COAP_ENDPOINT);
      MAKE_CASE(COAP_PDU);
      MAKE_CASE(COAP_PDU_BUF);
      MAKE_CASE(COAP_RESOURCE);
      MAKE_CASE(COAP_RESOURCEATTR);
      MAKE_CASE(COAP_DTLS_SESSION);
      MAKE_CASE(COAP_SESSION);
      MAKE_CASE(COAP_OPTLIST);
      MAKE_CASE(COAP_CACHE_KEY);
      MAKE_CASE(COAP_CACHE_ENTRY);
      MAKE_CASE(COAP_LG_XMIT);
      MAKE_CASE(COAP_LG_CRCV);
      MAKE_CASE(COAP_LG_SRCV);
      MAKE_CASE(COAP_DIGEST_CTX);
      MAKE_CASE(COAP_SUBSCRIPTION);
      MAKE_CASE(COAP_DTLS_CONTEXT);
      MAKE_CASE(COAP_OSCORE_COM);
      MAKE_CASE(COAP_OSCORE_SEN);
      MAKE_CASE(COAP_OSCORE_REC);
      MAKE_CASE(COAP_OSCORE_EX);
      MAKE_CASE(COAP_OSCORE_EP);
      MAKE_CASE(COAP_OSCORE_BUF);
      MAKE_CASE(COAP_COSE);
    case COAP_MEM_TAG_LAST:
    default:
      break;
    }
    coap_log(level, "*    %-20s in-use %3d peak %3d failed %2d\n",
             name, track_counts[i], peak_counts[i], fail_counts[i]);
  }
#else /* COAP_MEMORY_TYPE_TRACK */
  (void)level;
#endif /* COAP_MEMORY_TYPE_TRACK */
}

#endif /* WITH_LWIP && ! MEMP_USE_CUSTOM_POOLS && | MEM_LIBC_MALLOC */

#endif /* !COAP_LWIP_USE_STDLIB_ALLOC */
