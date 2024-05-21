/*
 * coap_cache_internal.h -- Cache functions for libcoap
 *
 * Copyright (C) 2019--2024 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_cache_internal.h
 * @brief CoAP cache internal information
 */

#ifndef COAP_CACHE_INTERNAL_H_
#define COAP_CACHE_INTERNAL_H_

#include "coap_internal.h"
#include "coap_io.h"
#include "coap_uthash_internal.h"

#if COAP_SERVER_SUPPORT
/**
 * @ingroup internal_api
 * @defgroup cache_internal Cache Support
 * Internal API for Cache-Key and Cache-Entry support
 * @{
 */

/* Holds a digest in binary typically sha256 except for notls */
typedef struct coap_digest_t {
  uint8_t key[32];
} coap_digest_t;

struct coap_cache_key_t {
  uint8_t key[32];
};

struct coap_cache_entry_t {
  UT_hash_handle hh;
  coap_cache_key_t *cache_key;
  coap_session_t *session;
  coap_pdu_t *pdu;
  void *app_data;
  coap_tick_t expire_ticks;
  unsigned int idle_timeout;
  coap_cache_app_data_free_callback_t callback;
};

/**
 * Expire coap_cache_entry_t entries
 *
 * Internal function.
 *
 * @param context The context holding the coap-entries to exire
 */
void coap_expire_cache_entries(coap_context_t *context);

/**
 * Searches for a cache-entry identified by @p cache_key. This
 * function returns the corresponding cache-entry or @c NULL
 * if not found.
 *
 * Note: This function must be called in the locked state.
 *
 * @param context    The context to use.
 * @param cache_key  The cache-key to get the hashed coap-entry.
 *
 * @return The cache-entry for @p cache_key or @c NULL if not found.
 */
coap_cache_entry_t *coap_cache_get_by_key_lkd(coap_context_t *context,
                                              const coap_cache_key_t *cache_key);

/**
 * Searches for a cache-entry corresponding to @p pdu. This
 * function returns the corresponding cache-entry or @c NULL if not
 * found.
 *
 * Note: This function must be called in the locked state.
 *
 * @param session    The session to use.
 * @param pdu        The CoAP request to search for.
 * @param session_based COAP_CACHE_IS_SESSION_BASED if session based
 *                     cache-key to be used, else COAP_CACHE_NOT_SESSION_BASED.
 *
 * @return The cache-entry for @p request or @c NULL if not found.
 */
coap_cache_entry_t *coap_cache_get_by_pdu_lkd(coap_session_t *session,
                                              const coap_pdu_t *pdu,
                                              coap_cache_session_based_t session_based);

/**
 * Define the CoAP options that are not to be included when calculating
 * the cache-key. Options that are defined as Non-Cache and the Observe
 * option are always ignored.
 *
 * Note: This function must be called in the locked state.
 *
 * @param context   The context to save the ignored options information in.
 * @param options   The array of options to ignore.
 * @param count     The number of options to ignore.  Use 0 to reset the
 *                  options matching.
 *
 * @return          @return @c 1 if successful, else @c 0.
 */
int coap_cache_ignore_options_lkd(coap_context_t *context,
                                  const uint16_t *options, size_t count);

/**
 * Create a new cache-entry hash keyed by cache-key derived from the PDU.
 *
 * If @p session_based is set, then this cache-entry will get deleted when
 * the session is freed off.
 * If @p record_pdu is set, then the copied PDU will get freed off when
 * this cache-entry is deleted.
 *
 * The cache-entry is maintained on a context hash list.
 *
 * Note: This function must be called in the locked state.
 *
 * @param session   The session to use to derive the context from.
 * @param pdu       The pdu to use to generate the cache-key.
 * @param record_pdu COAP_CACHE_RECORD_PDU if to take a copy of the PDU for
 *                   later use, else COAP_CACHE_NOT_RECORD_PDU.
 * @param session_based COAP_CACHE_IS_SESSION_BASED if to associate this
 *                      cache-entry with the the session (which is embedded
 *                      in the cache-entry), else COAP_CACHE_NOT_SESSION_BASED.
 * @param idle_time Idle time in seconds before cache-entry is expired.
 *                  If set to 0, it does not expire (but will get
 *                  deleted if the session is deleted and it is session_based).
 *
 * @return          The returned cache-key or @c NULL if failure.
 */
coap_cache_entry_t *coap_new_cache_entry_lkd(coap_session_t *session,
                                             const coap_pdu_t *pdu,
                                             coap_cache_record_pdu_t record_pdu,
                                             coap_cache_session_based_t session_based,
                                             unsigned int idle_time);

typedef void coap_digest_ctx_t;

/**
 * Initialize a coap_digest
 *
 * Internal function.
 *
 * @return          The digest context or @c NULL if failure.
 */
coap_digest_ctx_t *coap_digest_setup(void);

/**
 * Free off coap_digest_ctx_t. Always done by
 * coap_digest_final()
 *
 * Internal function.
 *
 * @param digest_ctx The coap_digest context.
 */
void coap_digest_free(coap_digest_ctx_t *digest_ctx);

/**
 * Update the coap_digest information with the next chunk of data
 *
 * Internal function.
 *
 * @param digest_ctx The coap_digest context.
 * @param data       Pointer to data.
 * @param data_len   Number of bytes.
 *
 * @return           @c 1 success, @c 0 failure.
 */
int coap_digest_update(coap_digest_ctx_t *digest_ctx,
                       const uint8_t *data,
                       size_t data_len
                      );

/**
 * Finalize the coap_digest information  into the provided
 * @p digest_buffer.
 *
 * Internal function.
 *
 * @param digest_ctx    The coap_digest context.
 * @param digest_buffer Pointer to digest buffer to update
 *
 * @return              @c 1 success, @c 0 failure.
 */
int coap_digest_final(coap_digest_ctx_t *digest_ctx,
                      coap_digest_t *digest_buffer);

/** @} */

#endif /* COAP_SERVER_SUPPORT */

#endif /* COAP_CACHE_INTERNAL_H_ */
