/* coap_cache.c -- Caching of CoAP requests
*
* Copyright (C) 2020 Olaf Bergmann <bergmann@tzi.org>
*
* This file is part of the CoAP library libcoap. Please see
* README for terms of use.
*/

#include "coap_internal.h"

#include "murmur3.h"

/* Determines if the given option_type denotes an option type that can
 * be used as CacheKey. Options that can be cache keys are not Unsafe
 * and not marked explicitly as NoCacheKey. */
static int
is_cache_key(uint16_t option_type) {
  const uint16_t unsafe = 0x02;
  const uint16_t no_cache_key = 0x04;

  return (option_type & (unsafe | no_cache_key)) == 0;
}

coap_cache_key_t
coap_cache_key(const coap_pdu_t *pdu) {
  coap_opt_t *option;
  coap_opt_iterator_t opt_iter;
  murmur3_context_t mctx;

  if (!coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL)) {
    return COAP_CACHE_INVALID;
  }

  murmur3_32_init(&mctx);

  while ((option = coap_option_next(&opt_iter))) {
    if (is_cache_key(opt_iter.type)) {
      murmur3_32_update(&mctx, option, coap_opt_size(option));
    }
  }

  /* The body of a FETCH payload is part of the cache key,
   * see https://tools.ietf.org/html/rfc8132#section-2 */
  if (pdu->code == COAP_REQUEST_FETCH) {
    size_t len;
    uint8_t *data;
    if (coap_get_data(pdu, &len, &data)) {
      murmur3_32_update(&mctx, option, coap_opt_size(option));
    }
  }

  return murmur3_32_finalize(&mctx);
}

typedef struct coap_cache_entry_t {
  UT_hash_handle hh;
  const coap_pdu_t *pdu;
  coap_cache_key_t cache_key;
} coap_cache_entry_t;

/**
 * Marks a request for permanent storage. The request may be retrieved
 * through its cache-key.
 *
 * @param ctx     The context to use.
 * @param request The request to be stored.
 *
 * @return The cache key that corresponds to the newly stored
 *         request or @c COAP_CACHE_INVALID if the request could
 *         not be stored.
 */
coap_cache_key_t
coap_cache_mark_request(coap_context_t *ctx, const coap_pdu_t *request) {
  coap_cache_entry_t *entry = coap_malloc(sizeof(coap_cache_entry_t));
  if (!entry) {
    return COAP_CACHE_INVALID;
  }

  entry->pdu = request;
  entry->cache_key = coap_cache_key(request);
  HASH_ADD(hh, ctx->cache, cache_key, sizeof(coap_cache_key_t), entry);
  return entry->cache_key;
}

coap_cache_entry_t *
coap_cache_lookup_key(coap_context_t *ctx, coap_cache_key_t key) {
  coap_cache_entry_t *entry = NULL;
  if (key != COAP_CACHE_INVALID) {
    HASH_FIND(hh, ctx->cache, &key, sizeof(coap_cache_key_t), entry);
  }
  return entry;
}

coap_cache_entry_t *
coap_cache_lookup_request(coap_context_t *ctx, const coap_pdu_t *request) {
  return coap_cache_lookup_key(ctx, coap_cache_key(request));
}

/**
 * Clears a mark from a request.
 *
 * @param ctx        The context to use.
 * @param cache_key  The cache key for the request which can be
 *                   unmarked.
 */
void
coap_cache_unmark_request(coap_context_t *ctx, coap_cache_key_t cache_key) {
  (void)ctx;
  (void)cache_key;
}
