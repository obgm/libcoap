/* coap_mem.c -- CoAP memory handling
 *
 * Copyright (C) 2014--2015,2019--2024 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_mem.c
 * @brief Memory handling functions
 */

#include "coap3/coap_internal.h"

#ifndef WITH_LWIP
#if COAP_MEMORY_TYPE_TRACK
static int track_counts[COAP_MEM_TAG_LAST];
static int peak_counts[COAP_MEM_TAG_LAST];
static int fail_counts[COAP_MEM_TAG_LAST];
#endif /* COAP_MEMORY_TYPE_TRACK */
#endif /* ! WITH_LWIP */

#if defined(RIOT_VERSION) && defined(MODULE_MEMARRAY)
#include <memarray.h>

#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <coap3/coap_session.h>
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "coap3/coap_session.h"
#include "coap3/coap_net.h"
#include "coap3/coap_pdu.h"
#include "coap3/coap_resource.h"

/**
 * The maximum size of a string on platforms that allocate fixed-size
 * memory blocks.
 */
#ifndef COAP_MAX_STRING_SIZE
#define COAP_MAX_STRING_SIZE     (64U)
#endif /* COAP_MAX_STRING_SIZE */

/**
 * The maximum number of strings on platforms that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_STRINGS
#define COAP_MAX_STRINGS         (16U)
#endif /* COAP_MAX_STRINGS */

/**
 * The maximum number of endpoints on platforms that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_ENDPOINTS
#if !COAP_DISABLE_TCP
#define COAP_MAX_ENDPOINTS          (4U)
#else /* COAP_DISABLE_TCP */
#define COAP_MAX_ENDPOINTS          (2U)
#endif /* COAP_DISABLE_TCP */
#endif /* COAP_MAX_ENDPOINTS */

/**
 * The maximum number of resources on platforms that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_RESOURCES
#define COAP_MAX_RESOURCES          (8U)
#endif /* COAP_MAX_RESOURCES */

/**
 * The maximum number of attributes on platforms that allocate
 * fixed-size memory blocks.  Default is #COAP_MAX_RESOURCES * 4.
 */
#ifndef COAP_MAX_ATTRIBUTES
#define COAP_MAX_ATTRIBUTES             \
  ((COAP_MAX_RESOURCES) * 4U)
#endif /* COAP_MAX_ATTRIBUTE_STRINGS */

/**
 * The maximum number of a strings that are used for attribute names
 * and values on platforms that allocate fixed-size memory blocks.
 * Default is #COAP_MAX_ATTRIBUTES, i.e. every attribute can have a
 * dynamic value.
 */
#ifndef COAP_MAX_ATTRIBUTE_STRINGS
#define COAP_MAX_ATTRIBUTE_STRINGS    (COAP_MAX_ATTRIBUTES)
#endif /* COAP_MAX_ATTRIBUTE_STRINGS */

/**
 * The maximum size of attribute names or values and values on
 * platforms that allocate fixed-size memory blocks.
 */
#ifndef COAP_MAX_ATTRIBUTE_SIZE
#define COAP_MAX_ATTRIBUTE_SIZE       (16U)
#endif /* COAP_MAX_ATTRIBUTE_SIZE */

/**
 * The maximum number of processed packets on platforms that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_PACKETS
#define COAP_MAX_PACKETS            (4U)
#endif /* COAP_MAX_PACKETS */

/**
 * The maximum number of nodes in retransmission queue on platforms
 * that allocate fixed-size memory blocks.
 */
#ifndef COAP_MAX_NODES
#define COAP_MAX_NODES           (COAP_MAX_PACKETS)
#endif /* COAP_MAX_NODES */

/**
 * The maximum number of CoAP contexts on platforms that allocate
 * fixed-size memory blocks. Default is 1.
 */
#ifndef COAP_MAX_CONTEXTS
#define COAP_MAX_CONTEXTS           (1U)
#endif /* COAP_MAX_CONTEXTS */

/**
 * The maximum number of CoAP PDUs processed in parallel on platforms
 * that allocate fixed-size memory blocks.
 */
#ifndef COAP_MAX_PDUS
#define COAP_MAX_PDUS               (4U)
#endif /* COAP_MAX_PDUS */

/**
 * The maximum number of DTLS sessions on platforms that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_DTLS_SESSIONS
#define COAP_MAX_DTLS_SESSIONS      (2U)
#endif /* COAP_MAX_CONTEXTS */

/**
 * The maximum number of DTLS sessions on platforms that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_SESSIONS
#define COAP_MAX_SESSIONS           (4U)
#endif /* COAP_MAX_CONTEXTS */

/**
 * The maximum number of optlist entries on platforms that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_OPTIONS
#define COAP_MAX_OPTIONS            (16U)
#endif /* COAP_MAX_CONTEXTS */

/**
 * The maximum size of option values on platforms that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_OPTION_SIZE
#define COAP_MAX_OPTION_SIZE        (16U)
#endif /* COAP_MAX_OPTION_SIZE */

/**
 * The maximum number of cache-key entries that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_CACHE_KEYS
#define COAP_MAX_CACHE_KEYS        (2U)
#endif /* COAP_MAX_CACHE_KEYS */

/**
 * The maximum number of cache-entry entries that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_CACHE_ENTRIES
#define COAP_MAX_CACHE_ENTRIES        (2U)
#endif /* COAP_MAX_CACHE_ENTRIES */

/**
 * The maximum number lg_crcv entries that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_LG_CRCVS
#if COAP_CLIENT_SUPPORT
#define COAP_MAX_LG_CRCVS        (1U)
#else /* ! COAP_CLIENT_SUPPORT */
#define COAP_MAX_LG_CRCVS        (0U)
#endif /* ! COAP_CLIENT_SUPPORT */
#endif /* COAP_MAX_LG_CRCVS */

/**
 * The maximum number lg_srcv entries that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_LG_SRCVS
#if COAP_SERVER_SUPPORT
#define COAP_MAX_LG_SRCVS        (2U)
#else /* ! COAP_SERVER_SUPPORT */
#define COAP_MAX_LG_SRCVS        (0U)
#endif /* ! COAP_SERVER_SUPPORT */
#endif /* COAP_MAX_LG_SRCVS */

/**
 * The maximum number lg_xmit entries that allocate
 * fixed-size memory blocks.
 */
#ifndef COAP_MAX_LG_XMITS
#if COAP_SERVER_SUPPORT
#define COAP_MAX_LG_XMITS        (2U)
#else /* ! COAP_SERVER_SUPPORT */
#define COAP_MAX_LG_XMITS        (1U)
#endif /* ! COAP_SERVER_SUPPORT */
#endif /* COAP_MAX_LG_XMITS */

/* The memstr is the storage for holding coap_string_t structure
 * together with its contents. */
union memstr_t {
  coap_string_t s;
  char buf[sizeof(coap_string_t) + COAP_MAX_STRING_SIZE];
};

/* The attrstr is the storage for holding coap_string_t structures to
 * serve as attribute names or values. As these are typically short,
 * they are stored in a different arena than generic strings. */
union attrstr_t {
  coap_string_t s;
  char buf[sizeof(coap_string_t) + COAP_MAX_ATTRIBUTE_SIZE];
};

static union memstr_t string_storage_data[COAP_MAX_STRINGS];
static memarray_t string_storage;

#if COAP_SERVER_SUPPORT
static coap_endpoint_t endpoint_storage_data[COAP_MAX_ENDPOINTS];
static memarray_t endpoint_storage;

static union attrstr_t attr_storage_data[COAP_MAX_ATTRIBUTE_STRINGS];
static memarray_t attr_storage;

static coap_attr_t resattr_storage_data[COAP_MAX_ATTRIBUTES];
static memarray_t resattr_storage;
#endif /* COAP_SERVER_SUPPORT */

static coap_packet_t pkt_storage_data[COAP_MAX_PACKETS];
static memarray_t pkt_storage;

static coap_queue_t node_storage_data[COAP_MAX_NODES];
static memarray_t node_storage;

static coap_context_t context_storage_data[COAP_MAX_CONTEXTS];
static memarray_t context_storage;

static coap_pdu_t pdu_storage_data[COAP_MAX_PDUS];
static memarray_t pdu_storage;

/* The pdubuf is the storage for holding the (assembled) PDU data in a
 * coap_pdu_t structure. */
union pdubuf_t {
  void *p; /* try to convince the compiler to word-align this structure  */
  char buf[COAP_DEFAULT_MAX_PDU_RX_SIZE];
};

static union pdubuf_t pdubuf_storage_data[COAP_MAX_PDUS];
static memarray_t pdubuf_storage;

#if COAP_SERVER_SUPPORT
static coap_resource_t resource_storage_data[COAP_MAX_RESOURCES];
static memarray_t resource_storage;
#endif /* COAP_SERVER_SUPPORT */

#ifdef COAP_WITH_LIBTINYDTLS
#undef PACKAGE_BUGREPORT
#include <session.h>
static session_t dtls_storage_data[COAP_MAX_DTLS_SESSIONS];
static memarray_t dtls_storage;
#endif /* COAP_WITH_LIBTINYDTLS */

static coap_session_t session_storage_data[COAP_MAX_SESSIONS];
static memarray_t session_storage;

/* The optbuf_t is the storage for holding optlist nodes. */
struct optbuf_t {
  coap_optlist_t optlist;
  char optbuf[COAP_MAX_OPTION_SIZE];
};
static struct optbuf_t option_storage_data[COAP_MAX_OPTIONS];
static memarray_t option_storage;

#if COAP_SERVER_SUPPORT
static coap_cache_key_t cache_key_storage_data[COAP_MAX_CACHE_KEYS];
static memarray_t cache_key_storage;

static coap_cache_entry_t cache_entry_storage_data[COAP_MAX_CACHE_ENTRIES];
static memarray_t cache_entry_storage;
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
static coap_lg_crcv_t cache_lg_crcv_storage_data[COAP_MAX_LG_CRCVS];
static memarray_t cache_lg_crcv_storage;
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
static coap_lg_srcv_t cache_lg_srcv_storage_data[COAP_MAX_LG_SRCVS];
static memarray_t cache_lg_srcv_storage;

static coap_lg_xmit_t cache_lg_xmit_storage_data[COAP_MAX_LG_XMITS];
static memarray_t cache_lg_xmit_storage;
#endif /* COAP_SERVER_SUPPORT */

#define INIT_STORAGE(Storage, Count)  \
  memarray_init(&(Storage ## _storage), (Storage ## _storage_data), sizeof(Storage ## _storage_data[0]), (Count));

#define STORAGE_PTR(Storage)  (&(Storage ## _storage))

void
coap_memory_init(void) {
  INIT_STORAGE(string, COAP_MAX_STRINGS);
#if COAP_SERVER_SUPPORT
  INIT_STORAGE(endpoint, COAP_MAX_ENDPOINTS);
  INIT_STORAGE(attr, COAP_MAX_ATTRIBUTE_STRINGS);
#endif /* COAP_SERVER_SUPPORT */
  INIT_STORAGE(pkt, COAP_MAX_PACKETS);
  INIT_STORAGE(node, COAP_MAX_NODES);
  INIT_STORAGE(context, COAP_MAX_CONTEXTS);
  INIT_STORAGE(pdu, COAP_MAX_PDUS);
  INIT_STORAGE(pdubuf, COAP_MAX_PDUS);
#if COAP_SERVER_SUPPORT
  INIT_STORAGE(resource, COAP_MAX_RESOURCES);
  INIT_STORAGE(resattr, COAP_MAX_ATTRIBUTES);
#endif /* COAP_SERVER_SUPPORT */
#ifdef COAP_WITH_LIBTINYDTLS
  INIT_STORAGE(dtls, COAP_MAX_DTLS_SESSIONS);
#endif
  INIT_STORAGE(session, COAP_MAX_SESSIONS);
  INIT_STORAGE(option, COAP_MAX_OPTIONS);
#if COAP_SERVER_SUPPORT
  INIT_STORAGE(cache_key, COAP_MAX_CACHE_KEYS);
  INIT_STORAGE(cache_entry, COAP_MAX_CACHE_ENTRIES);
#endif /* COAP_SERVER_SUPPORT */
#if COAP_CLIENT_SUPPORT
  INIT_STORAGE(cache_lg_crcv, COAP_MAX_LG_CRCVS);
#endif /* COAP_SERVER_SUPPORT */
#if COAP_SERVER_SUPPORT
  INIT_STORAGE(cache_lg_srcv, COAP_MAX_LG_SRCVS);
  INIT_STORAGE(cache_lg_xmit, COAP_MAX_LG_XMITS);
#endif /* COAP_SERVER_SUPPORT */
}

static memarray_t *
get_container(coap_memory_tag_t type) {
  switch (type) {
#if COAP_SERVER_SUPPORT
  case COAP_ATTRIBUTE_NAME:
  /* fall through */
  case COAP_ATTRIBUTE_VALUE:
    return &attr_storage;
#endif /* COAP_SERVER_SUPPORT */
  case COAP_PACKET:
    return &pkt_storage;
  case COAP_NODE:
    return &node_storage;
  case COAP_CONTEXT:
    return STORAGE_PTR(context);
#if COAP_SERVER_SUPPORT
  case COAP_ENDPOINT:
    return &endpoint_storage;
#endif /* COAP_SERVER_SUPPORT */
  case COAP_PDU:
    return &pdu_storage;
  case COAP_PDU_BUF:
    return &pdubuf_storage;
#if COAP_SERVER_SUPPORT
  case COAP_RESOURCE:
    return &resource_storage;
  case COAP_RESOURCEATTR:
    return &resattr_storage;
#endif /* COAP_SERVER_SUPPORT */
#ifdef COAP_WITH_LIBTINYDTLS
  case COAP_DTLS_SESSION:
    return &dtls_storage;
#endif
  case COAP_SESSION:
    return &session_storage;
  case COAP_OPTLIST:
    return &option_storage;
#if COAP_SERVER_SUPPORT
  case COAP_CACHE_KEY:
    return &cache_key_storage;
  case COAP_CACHE_ENTRY:
    return &cache_entry_storage;
#endif /* COAP_SERVER_SUPPORT */
#if COAP_CLIENT_SUPPORT
  case COAP_LG_CRCV:
    return &cache_lg_crcv_storage;
#endif /* COAP_CLIENT_SUPPORT */
#if COAP_SERVER_SUPPORT
  case COAP_LG_SRCV:
    return &cache_lg_srcv_storage;
  case COAP_LG_XMIT:
    return &cache_lg_xmit_storage;
#endif /* COAP_SERVER_SUPPORT */
  case COAP_STRING:
  /* fall through */
  default:
    return &string_storage;
  }
}

void *
coap_malloc_type(coap_memory_tag_t type, size_t size) {
  memarray_t *container = get_container(type);
  void *ptr;
  assert(container);

  if (size > container->size) {
    coap_log_warn("coap_malloc_type: Requested memory exceeds maximum object "
                  "size (type %d, size %zu, max %d)\n",
                  type, size, container->size);
    return NULL;
  }

  ptr = memarray_alloc(container);
  if (!ptr)
    coap_log_warn("coap_malloc_type: Failure (no free blocks) for type %d\n",
                  type);
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
  return ptr;
}

void
coap_free_type(coap_memory_tag_t type, void *object) {
#if COAP_MEMORY_TYPE_TRACK
  assert(type < COAP_MEM_TAG_LAST);
  if (object)
    track_counts[type]--;
#endif /* COAP_MEMORY_TYPE_TRACK */
  if (object != NULL)
    memarray_free(get_container(type), object);
}

void *
coap_realloc_type(coap_memory_tag_t type, void *p, size_t size) {
  memarray_t *container = get_container(type);

  assert(container);
  /* The fixed container is all we have to work with */
  if (p) {
    if (size > container->size) {
      coap_log_warn("coap_realloc_type: Requested memory exceeds maximum object "
                    "size (type %d, size %zu, max %d)\n",
                    type, size, container->size);
      return NULL;
    }
    if (size == 0) {
      coap_free_type(type, p);
      return NULL;
    }
    return p;
  }
  return coap_malloc_type(type, size);

}
#else /* ! RIOT_VERSION && ! MODULE_MEMARRAY */

#if defined(HAVE_MALLOC) || defined(__MINGW32__)
#include <stdlib.h>

void
coap_memory_init(void) {
}

void *
coap_malloc_type(coap_memory_tag_t type, size_t size) {
  void *ptr;

  (void)type;
  ptr = malloc(size);
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
  return ptr;
}

void *
coap_realloc_type(coap_memory_tag_t type, void *p, size_t size) {
  void *ptr;

  (void)type;
  ptr = realloc(p, size);
#if COAP_MEMORY_TYPE_TRACK
  if (ptr) {
    assert(type < COAP_MEM_TAG_LAST);
    if (!p)
      track_counts[type]++;
    if (track_counts[type] > peak_counts[type])
      peak_counts[type] = track_counts[type];
  } else {
    fail_counts[type]++;
  }
#endif /* COAP_MEMORY_TYPE_TRACK */
  return ptr;
}

void
coap_free_type(coap_memory_tag_t type, void *p) {
  (void)type;
#if COAP_MEMORY_TYPE_TRACK
  assert(type < COAP_MEM_TAG_LAST);
  if (p)
    track_counts[type]--;
#endif /* COAP_MEMORY_TYPE_TRACK */
  free(p);
}

#else /* ! HAVE_MALLOC  && !__MINGW32__ */

#ifdef WITH_CONTIKI
#include "lib/heapmem.h"

void
coap_memory_init(void) {
}

void *
coap_malloc_type(coap_memory_tag_t type, size_t size) {
  void *ptr = heapmem_alloc(size);

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
  return ptr;
}

void *
coap_realloc_type(coap_memory_tag_t type, void *p, size_t size) {
  void *ptr = heapmem_realloc(p, size);
#if COAP_MEMORY_TYPE_TRACK
  if (ptr) {
    assert(type < COAP_MEM_TAG_LAST);
    if (!p)
      track_counts[type]++;
    if (track_counts[type] > peak_counts[type])
      peak_counts[type] = track_counts[type];
  } else {
    fail_counts[type]++;
  }
#endif /* COAP_MEMORY_TYPE_TRACK */
  return ptr;
}

void
coap_free_type(coap_memory_tag_t type, void *ptr) {
#if COAP_MEMORY_TYPE_TRACK
  assert(type < COAP_MEM_TAG_LAST);
  if (ptr)
    track_counts[type]--;
#endif /* COAP_MEMORY_TYPE_TRACK */
  heapmem_free(ptr);
}

#endif /* WITH_CONTIKI */

#endif /* ! HAVE_MALLOC */

#endif /* ! RIOT_VERSION */

#ifndef WITH_LWIP
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
#endif /* !WITH_LWIP */
