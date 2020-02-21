/* coap_cache.h -- Caching of CoAP requests
*
* Copyright (C) 2020 Olaf Bergmann <bergmann@tzi.org>
*
* This file is part of the CoAP library libcoap. Please see
* README for terms of use.
*/

/**
 * @file coap_cache.h
 * @brief Provides a simple request storage for CoAP requests
 */

#ifndef COAP_CACHE_H_
#define COAP_CACHE_H_

#include <limits.h>

#include "coap_forward_decls.h"

typedef enum {
              COAP_CACHE_INVALID=-1,
              COAP_CACHE_MAXKEY=INT_MAX
} coap_cache_key_t;

/**
 * Calculates a cache key for the given CoAP PDU. See
 * https://tools.ietf.org/html/rfc7252#section-5.6
 * for an explanation of CoAP cache keys.
 *
 * @param pdu The CoAP PDU for which a cache key is to be
 *            calculated.
 *
 * @return The calculcated cache key.
 */
coap_cache_key_t coap_cache_key(const coap_pdu_t *pdu);

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
coap_cache_key_t coap_cache_mark_request(coap_context_t *ctx,
                                         const coap_pdu_t *request);

/**
 * Clears a mark from a request.
 *
 * @param ctx        The context to use.
 * @param cache_key  The cache key for the request which can be
 *                   unmarked.
 */
void coap_cache_unmark_request(coap_context_t *ctx,
                               coap_cache_key_t cache_key);

/**
 * Searches for a cache entry identified by @p cache_key. This
 * function returns the corresponding cache entry or @c NULL
 * if not found.
 *
 * @param ctx        The context to use.
 * @param cache_key  The cache key to look up.
 *
 * @return The cache entry for @p cache_key or @c NULL if not found.
 */
struct coap_cache_entry_t *coap_cache_lookup_key(coap_context_t *ctx,
                                                 coap_cache_key_t cache_key);

/**
 * Searches for a cache entry corresponding to @p request. This
 * function returns the corresponding cache entry or @c NULL if not
 * found.
 *
 * @param ctx        The context to use.
 * @param request    The CoAP request to search for.
 *
 * @return The cache entry for @p request or @c NULL if not found.
 */
struct coap_cache_entry_t *coap_cache_lookup_request(coap_context_t *ctx,
                                                     const coap_pdu_t *request);


#endif  /* COAP_CACHE_H */
