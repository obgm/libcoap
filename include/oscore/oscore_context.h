/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * Copyright (c) 2018, SICS, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * @file oscore_context.h
 * @brief An implementation of the Object Security for Constrained RESTful
 * Enviornments (RFC 8613).
 *
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * adapted to libcoap; added group communication
 *     Peter van der Stok <consultancy@vanderstok.org>
 *     on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 */

#ifndef _OSCORE_CONTEXT_H
#define _OSCORE_CONTEXT_H

#include "coap3/coap_internal.h"
#include "coap3/coap_uthash_internal.h"
#include <stdint.h>

/**
 * @ingroup internal_api
 * @addtogroup oscore_internal
 * @{
 */

#define CONTEXT_KEY_LEN         16
#define TOKEN_SEQ_NUM           2  /* to be set by application */
#define EP_CTX_NUM              10 /* to be set by application */
#define CONTEXT_INIT_VECT_LEN   13
#define CONTEXT_SEQ_LEN         sizeof(uint64_t)

#define ED25519_PRIVATE_KEY_LEN 32
#define ED25519_PUBLIC_KEY_LEN  32
#define ED25519_SEED_LEN        32
#define ED25519_SIGNATURE_LEN   64

#define OSCORE_SEQ_MAX (((uint64_t)1 << 40) - 1)

typedef enum {
  OSCORE_MODE_SINGLE = 0, /**< Vanilla RFC8613 support */
  OSCORE_MODE_GROUP,      /**< TODO draft-ietf-core-oscore-groupcomm */
  OSCORE_MODE_PAIRWISE    /**< TODO draft-ietf-core-oscore-groupcomm */
} oscore_mode_t;

typedef struct oscore_sender_ctx_t oscore_sender_ctx_t;
typedef struct oscore_recipient_ctx_t oscore_recipient_ctx_t;
typedef struct oscore_association_t oscore_association_t;

struct oscore_ctx_t {
  struct oscore_ctx_t *next;
  coap_bin_const_t *master_secret;
  coap_bin_const_t *master_salt;
  coap_bin_const_t *common_iv;  /**< Derived from Master Secret,
                                     Master Salt, and ID Context */
  coap_bin_const_t *id_context; /**< contains GID in case of group */
  oscore_sender_ctx_t *sender_context;
  oscore_recipient_ctx_t *recipient_chain;
  cose_alg_t aead_alg;
  cose_hkdf_alg_t hkdf_alg;
  oscore_mode_t mode;
  uint8_t rfc8613_b_1_2; /**< 1 if rfc8613 B.1.2 enabled else 0 */
  uint8_t rfc8613_b_2;   /**< 1 if rfc8613 B.2 protocol else 0 */
  uint32_t ssn_freq;     /**< Sender Seq Num update frequency */
  uint32_t replay_window_size;
  coap_oscore_save_seq_num_t save_seq_num_func; /**< Called every seq num
                                                     change */
  void *save_seq_num_func_param; /**< Passed to save_seq_num_func() */
};

struct oscore_sender_ctx_t {
  uint64_t seq;
  uint64_t next_seq; /**< Used for ssn_freq updating */
  coap_bin_const_t *sender_key;
  coap_bin_const_t *sender_id;
};

struct oscore_recipient_ctx_t {
  /* This field allows recipient chaining */
  oscore_recipient_ctx_t *next_recipient;
  oscore_ctx_t *osc_ctx;
  uint64_t last_seq;
  /*  uint64_t highest_seq; */
  uint64_t sliding_window;
  uint64_t rollback_sliding_window;
  uint64_t rollback_last_seq;
  coap_bin_const_t *recipient_key;
  coap_bin_const_t *recipient_id;
  uint8_t echo_value[8];
  uint8_t initial_state;
};

#define OSCORE_ASSOCIATIONS_ADD(r, obj)                                        \
  HASH_ADD(hh, (r), token->s[0], (obj)->token->length, (obj))

#define OSCORE_ASSOCIATIONS_DELETE(r, obj) HASH_DELETE(hh, (r), (obj))

#define OSCORE_ASSOCIATIONS_ITER(r, tmp)                                       \
  oscore_associations_t *tmp, *rtmp;                                           \
  HASH_ITER (hh, (r), tmp, rtmp)

#define OSCORE_ASSOCIATIONS_ITER_SAFE(e, el, rtmp)                             \
  for ((el) = (e); (el) && ((rtmp) = (el)->hh.next, 1); (el) = (rtmp))

#define OSCORE_ASSOCIATIONS_FIND(r, k, res)                                    \
  { HASH_FIND(hh, (r), (k)->s, (k)->length, (res)); }

struct oscore_association_t {
  UT_hash_handle hh;
  oscore_recipient_ctx_t *recipient_ctx;
  coap_pdu_t *sent_pdu;
  coap_bin_const_t *token;
  coap_bin_const_t *aad;
  coap_bin_const_t *nonce;
  coap_bin_const_t *partial_iv;
  coap_tick_t last_seen;
  uint8_t is_observe;
};

/**
 * oscore_derive_ctx - derive a osc_ctx from oscore_conf information
 *
 * @param c_context The CoAP context to associate OSCORE context with.
 * @param oscore_conf The OSCORE configuration to use.
 *
 * @return NULL if failure or derived OSCORE context linked onto
 *         @p c_context chain.
 */
oscore_ctx_t *oscore_derive_ctx(coap_context_t *c_context,
                                coap_oscore_conf_t *oscore_conf);

/**
 * oscore_duplicate_ctx - duplicate a osc_ctx
 *
 * @param c_context The CoAP context to associate OSCORE context with.
 * @param o_osc_ctx The OSCORE context to duplicate.
 * @param sender_id The Sender ID to use in the duplication.
 * @param recipient_id The Recipient ID to use in the duplication.
 * @param id_context The Context ID to use in the duplicate.
 *
 * @return NULL if failure or duplicated OSCORE context linked onto
 *         @p c_context chain.
 */
oscore_ctx_t *oscore_duplicate_ctx(coap_context_t *c_context,
                                   oscore_ctx_t *o_osc_ctx,
                                   coap_bin_const_t *sender_id,
                                   coap_bin_const_t *recipient_id,
                                   coap_bin_const_t *id_context);

/**
 * oscore_update_ctx - update a osc_ctx with a new id_context
 *
 * @param osc_ctx The OSCORE context to update.
 * @param id_context The Context ID to use in the duplicate.
 */
void oscore_update_ctx(oscore_ctx_t *osc_ctx, coap_bin_const_t *id_context);

void oscore_free_context(oscore_ctx_t *osc_ctx);

void oscore_free_contexts(coap_context_t *c_context);

int oscore_remove_context(coap_context_t *c_context, oscore_ctx_t *osc_ctx);

/**
 * oscore_add_recipient - add in recipient information
 *
 * @param ctx The OSCORE context to add to.
 * @param rid The recipient ID.
 * @param break_key @c 1 if testing for broken keys, else @c 0.
 *
 * @return NULL if failure or recipient context linked onto @p ctx chain.
 */
oscore_recipient_ctx_t *oscore_add_recipient(oscore_ctx_t *ctx,
                                             coap_bin_const_t *rid,
                                             uint32_t break_key);

int oscore_delete_recipient(oscore_ctx_t *osc_ctx, coap_bin_const_t *rid);

uint8_t oscore_bytes_equal(uint8_t *a_ptr,
                           uint8_t a_len,
                           uint8_t *b_ptr,
                           uint8_t b_len);

void oscore_convert_to_hex(const uint8_t *src,
                           size_t src_len,
                           char *dest,
                           size_t dst_len);

void oscore_log_hex_value(coap_log_t level,
                          const char *name,
                          coap_bin_const_t *value);

void oscore_log_int_value(coap_log_t level, const char *name, int value);

void oscore_log_char_value(coap_log_t level, const char *name,
                           const char *value);

/**
 *  oscore_find_context - Locate recipient context (and hence OSCORE context)
 *
 * @param c_context The CoAP COntext to search.
 * @param rcpkey_id The Recipient kid.
 * @param ctxkey_id The ID Context to match (or NULL if no check).
 * @param oscore_r2 Partial id_context to match against or NULL.
 * @param recipient_ctx The recipient context to update.
 *
 * return The OSCORE context and @p recipient_ctx updated, or NULL is error.
 */
oscore_ctx_t *oscore_find_context(const coap_context_t *c_context,
                                  const coap_bin_const_t rcpkey_id,
                                  const coap_bin_const_t *ctxkey_id,
                                  uint8_t *oscore_r2,
                                  oscore_recipient_ctx_t **recipient_ctx);

void oscore_free_association(oscore_association_t *association);

int oscore_new_association(coap_session_t *session,
                           coap_pdu_t *sent_pdu,
                           coap_bin_const_t *token,
                           oscore_recipient_ctx_t *recipient_ctx,
                           coap_bin_const_t *aad,
                           coap_bin_const_t *nonce,
                           coap_bin_const_t *partial_iv,
                           int is_observe);

oscore_association_t *oscore_find_association(coap_session_t *session,
                                              coap_bin_const_t *token);

int oscore_delete_association(coap_session_t *session,
                              oscore_association_t *association);

void oscore_delete_server_associations(coap_session_t *session);

int oscore_derive_keystream(oscore_ctx_t *osc_ctx,
                            cose_encrypt0_t *code,
                            uint8_t coap_request,
                            coap_bin_const_t *sender_key,
                            coap_bin_const_t *id_context,
                            size_t cs_size,
                            uint8_t *keystream,
                            size_t keystream_size);

/** @} */

#endif /* _OSCORE_CONTEXT_H */
