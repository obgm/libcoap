/* coap_block.c -- block transfer
 *
 * Copyright (C) 2010--2012,2015-2024 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_block.c
 * @brief CoAP Block handling
 */

#include "coap3/coap_libcoap_build.h"

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#define STATE_TOKEN_BASE(t) ((t) & 0xffffffffffffULL)
#define STATE_TOKEN_RETRY(t) ((uint64_t)(t) >> 48)
#define STATE_TOKEN_FULL(t,r) (STATE_TOKEN_BASE(t) + ((uint64_t)(r) << 48))

#if COAP_Q_BLOCK_SUPPORT
int
coap_q_block_is_supported(void) {
  return 1;
}
#else /* ! COAP_Q_BLOCK_SUPPORT */
int
coap_q_block_is_supported(void) {
  return 0;
}
#endif /* ! COAP_Q_BLOCK_SUPPORT */

unsigned int
coap_opt_block_num(const coap_opt_t *block_opt) {
  unsigned int num = 0;
  uint16_t len;

  len = coap_opt_length(block_opt);

  if (len == 0) {
    return 0;
  }

  if (len > 1) {
    num = coap_decode_var_bytes(coap_opt_value(block_opt),
                                coap_opt_length(block_opt) - 1);
  }

  return (num << 4) | ((COAP_OPT_BLOCK_END_BYTE(block_opt) & 0xF0) >> 4);
}

int
coap_get_block_b(const coap_session_t *session, const coap_pdu_t *pdu,
                 coap_option_num_t number, coap_block_b_t *block) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;

  assert(block);
  memset(block, 0, sizeof(coap_block_b_t));

  if (pdu && (option = coap_check_option(pdu, number, &opt_iter)) != NULL) {
    uint32_t num;

    if (COAP_OPT_BLOCK_MORE(option))
      block->m = 1;
    block->aszx = block->szx = COAP_OPT_BLOCK_SZX(option);
    if (block->szx == 7) {
      size_t length;
      const uint8_t *data;

      if (session == NULL || COAP_PROTO_NOT_RELIABLE(session->proto) ||
          !(session->csm_bert_rem_support && session->csm_bert_loc_support))
        /* No BERT support */
        return 0;

      block->szx = 6; /* BERT is 1024 block chunks */
      block->bert = 1;
      if (coap_get_data(pdu, &length, &data)) {
        if (block->m && (length % 1024) != 0) {
          coap_log_debug("block: Oversized packet - reduced to %zu from %zu\n",
                         length - (length % 1024), length);
          length -= length % 1024;
        }
        block->chunk_size = (uint32_t)length;
      } else
        block->chunk_size = 0;
    } else {
      block->chunk_size = (size_t)1 << (block->szx + 4);
    }
    block->defined = 1;

    /* The block number is at most 20 bits, so values above 2^20 - 1
     * are illegal. */
    num = coap_opt_block_num(option);
    if (num > 0xFFFFF) {
      return 0;
    }
    block->num = num;
    return 1;
  }

  return 0;
}

int
coap_get_block(const coap_pdu_t *pdu, coap_option_num_t number,
               coap_block_t *block) {
  coap_block_b_t block_b;

  assert(block);
  memset(block, 0, sizeof(coap_block_t));

  if (coap_get_block_b(NULL, pdu, number, &block_b)) {
    block->num = block_b.num;
    block->m   = block_b.m;
    block->szx = block_b.szx;
    return 1;
  }
  return 0;
}

static int
setup_block_b(coap_session_t *session, coap_pdu_t *pdu, coap_block_b_t *block,
              unsigned int num,
              unsigned int blk_size, size_t total) {
  size_t token_options = pdu->data ? (size_t)(pdu->data - pdu->token) : pdu->used_size;
  size_t avail = pdu->max_size - token_options;
  unsigned int start = num << (blk_size + 4);
  unsigned int can_use_bert = block->defined == 0 || block->bert;

  assert(start <= total);
  memset(block, 0, sizeof(*block));
  block->num = num;
  block->szx = block->aszx = blk_size;
  if (can_use_bert && blk_size == 6 && avail >= 1024 && session != NULL &&
      COAP_PROTO_RELIABLE(session->proto) &&
      session->csm_bert_rem_support && session->csm_bert_loc_support) {
    block->bert = 1;
    block->aszx = 7;
    block->chunk_size = (uint32_t)((avail / 1024) * 1024);
  } else {
    block->chunk_size = (size_t)1 << (blk_size + 4);
    if (avail < block->chunk_size && (total - start) >= avail) {
      /* Need to reduce block size */
      unsigned int szx;
      int new_blk_size;

      if (avail < 16) {         /* bad luck, this is the smallest block size */
        coap_log_debug("not enough space, even the smallest block does not fit (1)\n");
        return 0;
      }
      new_blk_size = coap_flsll((long long)avail) - 5;
      coap_log_debug("decrease block size for %zu to %d\n", avail, new_blk_size);
      szx = block->szx;
      block->szx = new_blk_size;
      block->num <<= szx - block->szx;
      block->chunk_size = (size_t)1 << (new_blk_size + 4);
    }
  }
  block->m = block->chunk_size < total - start;
  return 1;
}

int
coap_write_block_opt(coap_block_t *block, coap_option_num_t number,
                     coap_pdu_t *pdu, size_t data_length) {
  size_t start;
  unsigned char buf[4];
  coap_block_b_t block_b;

  assert(pdu);

  start = block->num << (block->szx + 4);
  if (block->num != 0 && data_length <= start) {
    coap_log_debug("illegal block requested\n");
    return -2;
  }

  assert(pdu->max_size > 0);

  block_b.defined = 1;
  block_b.bert = 0;
  if (!setup_block_b(NULL, pdu, &block_b, block->num,
                     block->szx, data_length))
    return -3;

  /* to re-encode the block option */
  coap_update_option(pdu, number, coap_encode_var_safe(buf, sizeof(buf),
                                                       ((block_b.num << 4) |
                                                        (block_b.m << 3) |
                                                        block_b.szx)),
                     buf);

  return 1;
}

int
coap_write_block_b_opt(coap_session_t *session, coap_block_b_t *block,
                       coap_option_num_t number,
                       coap_pdu_t *pdu, size_t data_length) {
  size_t start;
  unsigned char buf[4];

  assert(pdu);

  start = block->num << (block->szx + 4);
  if (block->num != 0 && data_length <= start) {
    coap_log_debug("illegal block requested\n");
    return -2;
  }

  assert(pdu->max_size > 0);

  if (!setup_block_b(session, pdu, block, block->num,
                     block->szx, data_length))
    return -3;

  /* to re-encode the block option */
  coap_update_option(pdu, number, coap_encode_var_safe(buf, sizeof(buf),
                                                       ((block->num << 4) |
                                                        (block->m << 3) |
                                                        block->aszx)),
                     buf);

  return 1;
}

int
coap_add_block(coap_pdu_t *pdu, size_t len, const uint8_t *data,
               unsigned int block_num, unsigned char block_szx) {
  unsigned int start;
  start = block_num << (block_szx + 4);

  if (len <= start)
    return 0;

  return coap_add_data(pdu,
                       min(len - start, ((size_t)1 << (block_szx + 4))),
                       data + start);
}

int
coap_add_block_b_data(coap_pdu_t *pdu, size_t len, const uint8_t *data,
                      coap_block_b_t *block) {
  unsigned int start = block->num << (block->szx + 4);
  size_t max_size;

  if (len <= start)
    return 0;

  if (block->bert) {
    size_t token_options = pdu->data ? (size_t)(pdu->data - pdu->token) : pdu->used_size;
    max_size = ((pdu->max_size - token_options) / 1024) * 1024;
  } else {
    max_size = (size_t)1 << (block->szx + 4);
  }
  block->chunk_size = (uint32_t)max_size;

  return coap_add_data(pdu,
                       min(len - start, max_size),
                       data + start);
}

/*
 * Note that the COAP_OPTION_ have to be added in the correct order
 */
void
coap_add_data_blocked_response(const coap_pdu_t *request,
                               coap_pdu_t *response,
                               uint16_t media_type,
                               int maxage,
                               size_t length,
                               const uint8_t *data
                              ) {
  coap_key_t etag;
  unsigned char buf[4];
  coap_block_t block2;
  int block2_requested = 0;

  memset(&block2, 0, sizeof(block2));
  /*
   * Need to check that a valid block is getting asked for so that the
   * correct options are put into the PDU.
   */
  if (request) {
    if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)) {
      block2_requested = 1;
      if (block2.num != 0 && length <= (block2.num << (block2.szx + 4))) {
        coap_log_debug("Illegal block requested (%d > last = %zu)\n",
                       block2.num,
                       length >> (block2.szx + 4));
        response->code = COAP_RESPONSE_CODE(400);
        goto error;
      }
    }
  }
  response->code = COAP_RESPONSE_CODE(205);

  /* add etag for the resource */
  memset(etag, 0, sizeof(etag));
  coap_hash(data, length, etag);
  coap_insert_option(response, COAP_OPTION_ETAG, sizeof(etag), etag);

  coap_insert_option(response, COAP_OPTION_CONTENT_FORMAT,
                     coap_encode_var_safe(buf, sizeof(buf),
                                          media_type),
                     buf);

  if (maxage >= 0) {
    coap_insert_option(response,
                       COAP_OPTION_MAXAGE,
                       coap_encode_var_safe(buf, sizeof(buf), maxage), buf);
  }

  if (block2_requested) {
    int res;

    res = coap_write_block_opt(&block2, COAP_OPTION_BLOCK2, response, length);

    switch (res) {
    case -2:                        /* illegal block (caught above) */
      response->code = COAP_RESPONSE_CODE(400);
      goto error;
    case -1:                        /* should really not happen */
      assert(0);
    /* fall through if assert is a no-op */
    case -3:                        /* cannot handle request */
      response->code = COAP_RESPONSE_CODE(500);
      goto error;
    default:                        /* everything is good */
      ;
    }

    coap_add_option_internal(response,
                             COAP_OPTION_SIZE2,
                             coap_encode_var_safe8(buf, sizeof(buf), length),
                             buf);

    coap_add_block(response, length, data,
                   block2.num, block2.szx);
    return;
  }

  /*
   * Block2 not requested
   */
  if (!coap_add_data(response, length, data)) {
    /*
     * Insufficient space to add in data - use block mode
     * set initial block size, will be lowered by
     * coap_write_block_opt() automatically
     */
    block2.num = 0;
    block2.szx = 6;
    coap_write_block_opt(&block2, COAP_OPTION_BLOCK2, response, length);

    coap_add_option_internal(response,
                             COAP_OPTION_SIZE2,
                             coap_encode_var_safe8(buf, sizeof(buf), length),
                             buf);

    coap_add_block(response, length, data,
                   block2.num, block2.szx);
  }
  return;

error:
  coap_add_data(response,
                strlen(coap_response_phrase(response->code)),
                (const unsigned char *)coap_response_phrase(response->code));
}

COAP_API void
coap_context_set_block_mode(coap_context_t *context,
                            uint32_t block_mode) {
  coap_lock_lock(context, return);
  coap_context_set_block_mode_lkd(context, block_mode);
  coap_lock_unlock(context);
}

void
coap_context_set_block_mode_lkd(coap_context_t *context,
                                uint32_t block_mode) {
  coap_lock_check_locked(context);
  if (!(block_mode & COAP_BLOCK_USE_LIBCOAP))
    block_mode = 0;
  context->block_mode &= ~COAP_BLOCK_SET_MASK;
  context->block_mode |= block_mode & COAP_BLOCK_SET_MASK;
#if ! COAP_Q_BLOCK_SUPPORT
  if (block_mode & (COAP_BLOCK_TRY_Q_BLOCK|COAP_BLOCK_USE_M_Q_BLOCK))
    coap_log_debug("Q-Block support not compiled in - ignored\n");
#endif /* ! COAP_Q_BLOCK_SUPPORT */
}

COAP_API int
coap_context_set_max_block_size(coap_context_t *context,
                                size_t max_block_size) {
  int ret;

  coap_lock_lock(context, return 0);
  ret = coap_context_set_max_block_size_lkd(context, max_block_size);
  coap_lock_unlock(context);
  return ret;
}

int
coap_context_set_max_block_size_lkd(coap_context_t *context, size_t max_block_size) {
  switch (max_block_size) {
  case 0:
  case 16:
  case 32:
  case 64:
  case 128:
  case 256:
  case 512:
  case 1024:
    break;
  default:
    coap_log_info("coap_context_set_max_block_size: Invalid max block size (%zu)\n",
                  max_block_size);
    return 0;
  }
  coap_lock_check_locked(context);
  max_block_size = (coap_fls((uint32_t)max_block_size >> 4) - 1) & 0x07;
  context->block_mode &= ~COAP_BLOCK_MAX_SIZE_MASK;
  context->block_mode |= COAP_BLOCK_MAX_SIZE_SET((uint32_t)max_block_size);
  return 1;
}

COAP_STATIC_INLINE int
full_match(const uint8_t *a, size_t alen,
           const uint8_t *b, size_t blen) {
  return alen == blen && (alen == 0 || memcmp(a, b, alen) == 0);
}

#if COAP_CLIENT_SUPPORT

COAP_API int
coap_cancel_observe(coap_session_t *session, coap_binary_t *token,
                    coap_pdu_type_t type) {
  int ret;

  coap_lock_lock(session->context, return 0);
  ret = coap_cancel_observe_lkd(session, token, type);
  coap_lock_unlock(session->context);
  return ret;
}

int
coap_cancel_observe_lkd(coap_session_t *session, coap_binary_t *token,
                        coap_pdu_type_t type) {
  coap_lg_crcv_t *lg_crcv, *q;

  assert(session);
  if (!session)
    return 0;

  coap_lock_check_locked(session->context);
  if (!(session->block_mode & COAP_BLOCK_USE_LIBCOAP)) {
    coap_log_debug("** %s: coap_cancel_observe: COAP_BLOCK_USE_LIBCOAP not enabled\n",
                   coap_session_str(session));
    return 0;
  }

  LL_FOREACH_SAFE(session->lg_crcv, lg_crcv, q) {
    if (lg_crcv->observe_set) {
      if ((!token && !lg_crcv->app_token->length) || (token &&
                                                      coap_binary_equal(token, lg_crcv->app_token))) {
        uint8_t buf[8];
        coap_mid_t mid;
        size_t size;
        const uint8_t *data;
#if COAP_Q_BLOCK_SUPPORT
        coap_block_b_t block;
        int using_q_block1 = coap_get_block_b(session, &lg_crcv->pdu,
                                              COAP_OPTION_Q_BLOCK1, &block);
#endif /* COAP_Q_BLOCK_SUPPORT */
        coap_bin_const_t *otoken = lg_crcv->obs_token ?
                                   lg_crcv->obs_token[0] ?
                                   lg_crcv->obs_token[0] :
                                   (coap_bin_const_t *)lg_crcv->app_token :
                                   (coap_bin_const_t *)lg_crcv->app_token;
        coap_pdu_t *pdu = coap_pdu_duplicate_lkd(&lg_crcv->pdu,
                                                 session,
                                                 otoken->length,
                                                 otoken->s,
                                                 NULL);

        lg_crcv->observe_set = 0;
        if (pdu == NULL)
          return 0;
        /* Need to make sure that this is the correct requested type */
        pdu->type = type;

        coap_update_option(pdu, COAP_OPTION_OBSERVE,
                           coap_encode_var_safe(buf, sizeof(buf),
                                                COAP_OBSERVE_CANCEL),
                           buf);
        if (lg_crcv->o_block_option) {
          coap_update_option(pdu, lg_crcv->o_block_option,
                             coap_encode_var_safe(buf, sizeof(buf),
                                                  lg_crcv->o_blk_size),
                             buf);
        }
        if (coap_get_data(&lg_crcv->pdu, &size, &data))
          coap_add_data_large_request_lkd(session, pdu, size, data, NULL, NULL);

        /*
         * Need to fix lg_xmit stateless token as using tokens from
         * observe setup
         */
        if (pdu->lg_xmit)
          pdu->lg_xmit->b.b1.state_token = lg_crcv->state_token;

#if COAP_Q_BLOCK_SUPPORT
        /* See if large xmit using Q-Block1 (but not testing Q-Block1) */
        if (using_q_block1) {
          mid = coap_send_q_block1(session, block, pdu, COAP_SEND_INC_PDU);
        } else {
          mid = coap_send_internal(session, pdu);
        }
#else /* ! COAP_Q_BLOCK_SUPPORT */
        mid = coap_send_internal(session, pdu);
#endif /* ! COAP_Q_BLOCK_SUPPORT */
        if (mid != COAP_INVALID_MID)
          return 1;
        break;
      }
    }
  }
  return 0;
}

#if COAP_OSCORE_SUPPORT
coap_mid_t
coap_retransmit_oscore_pdu(coap_session_t *session,
                           coap_pdu_t *pdu,
                           coap_opt_t *echo) {
  coap_lg_crcv_t *lg_crcv;
  uint64_t token_match =
      STATE_TOKEN_BASE(coap_decode_var_bytes8(pdu->actual_token.s,
                                              pdu->actual_token.length));
  uint8_t ltoken[8];
  size_t ltoken_len;
  uint64_t token;
  const uint8_t *data;
  size_t data_len;
  coap_pdu_t *resend_pdu;
  coap_block_b_t block;

  LL_FOREACH(session->lg_crcv, lg_crcv) {
    if (token_match != STATE_TOKEN_BASE(lg_crcv->state_token) &&
        !coap_binary_equal(&pdu->actual_token, lg_crcv->app_token)) {
      /* try out the next one */
      continue;
    }

    /* lg_crcv found */

    /* Re-send request with new token */
    token = STATE_TOKEN_FULL(lg_crcv->state_token,
                             ++lg_crcv->retry_counter);
    ltoken_len = coap_encode_var_safe8(ltoken, sizeof(token), token);
    /* There could be a Block option in pdu */
    resend_pdu = coap_pdu_duplicate_lkd(pdu, session, ltoken_len,
                                        ltoken, NULL);
    if (!resend_pdu)
      goto error;
    if (echo) {
      coap_insert_option(resend_pdu, COAP_OPTION_ECHO, coap_opt_length(echo),
                         coap_opt_value(echo));
    }
    if (coap_get_data(&lg_crcv->pdu, &data_len, &data)) {
      if (coap_get_block_b(session, resend_pdu, COAP_OPTION_BLOCK1, &block)) {
        if (data_len > block.chunk_size && block.chunk_size != 0) {
          data_len = block.chunk_size;
        }
      }
      coap_add_data(resend_pdu, data_len, data);
    }

    return coap_send_internal(session, resend_pdu);
  }
error:
  return COAP_INVALID_MID;
}
#endif /* COAP_OSCORE_SUPPORT */
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
/*
 * Find the response lg_xmit
 */
coap_lg_xmit_t *
coap_find_lg_xmit_response(const coap_session_t *session,
                           const coap_pdu_t *request,
                           const coap_resource_t *resource,
                           const coap_string_t *query) {
  coap_lg_xmit_t *lg_xmit;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *rtag_opt = coap_check_option(request,
                                           COAP_OPTION_RTAG,
                                           &opt_iter);
  size_t rtag_length = rtag_opt ? coap_opt_length(rtag_opt) : 0;
  const uint8_t *rtag = rtag_opt ? coap_opt_value(rtag_opt) : NULL;

  LL_FOREACH(session->lg_xmit, lg_xmit) {
    static coap_string_t empty = { 0, NULL};

    if (COAP_PDU_IS_REQUEST(&lg_xmit->pdu) ||
        resource != lg_xmit->b.b2.resource ||
        request->code != lg_xmit->b.b2.request_method ||
        !coap_string_equal(query ? query : &empty,
                           lg_xmit->b.b2.query ?
                           lg_xmit->b.b2.query : &empty)) {
      /* try out the next one */
      continue;
    }
    /* lg_xmit is a response */
    if (rtag_opt || lg_xmit->b.b2.rtag_set == 1) {
      if (!(rtag_opt && lg_xmit->b.b2.rtag_set == 1))
        continue;
      if (lg_xmit->b.b2.rtag_length != rtag_length ||
          memcmp(lg_xmit->b.b2.rtag, rtag, rtag_length) != 0)
        continue;
    }
    return lg_xmit;
  }
  return NULL;
}
#endif /* COAP_SERVER_SUPPORT */

static int
coap_add_data_large_internal(coap_session_t *session,
                             const coap_pdu_t *request,
                             coap_pdu_t *pdu,
                             coap_resource_t *resource,
                             const coap_string_t *query,
                             int maxage,
                             uint64_t etag,
                             size_t length,
                             const uint8_t *data,
                             coap_release_large_data_t release_func,
                             void *app_ptr,
                             int single_request, coap_pdu_code_t request_method) {

  ssize_t avail;
  coap_block_b_t block;
#if COAP_Q_BLOCK_SUPPORT
  coap_block_b_t alt_block;
#endif /* COAP_Q_BLOCK_SUPPORT */
  size_t chunk;
  coap_lg_xmit_t *lg_xmit = NULL;
  uint8_t buf[8];
  int have_block_defined = 0;
  uint8_t blk_size;
  uint8_t max_blk_size;
  uint16_t option;
  size_t token_options;
  coap_opt_t *opt;
  coap_opt_iterator_t opt_iter;
#if COAP_Q_BLOCK_SUPPORT
  uint16_t alt_option;
#endif /* COAP_Q_BLOCK_SUPPORT */

  assert(pdu);
  if (pdu->data) {
    coap_log_warn("coap_add_data_large: PDU already contains data\n");
    if (release_func)
      release_func(session, app_ptr);
    return 0;
  }

  if (!(session->block_mode & COAP_BLOCK_USE_LIBCOAP)) {
    coap_log_debug("** %s: coap_add_data_large: COAP_BLOCK_USE_LIBCOAP not enabled\n",
                   coap_session_str(session));
    goto add_data;
  }

  /* A lot of the reliable code assumes type is CON */
  if (COAP_PROTO_RELIABLE(session->proto) && pdu->type == COAP_MESSAGE_NON)
    pdu->type = COAP_MESSAGE_CON;

  /* Block NUM max 20 bits and block size is "2**(SZX + 4)"
     and using SZX max of 6 gives maximum size = 1,073,740,800
     CSM Max-Message-Size theoretical maximum = 4,294,967,295
     So, if using blocks, we are limited to 1,073,740,800.
   */
#define MAX_BLK_LEN (((1UL << 20) - 1) * (1 << (6 + 4)))

#if UINT_MAX > MAX_BLK_LEN
  if (length > MAX_BLK_LEN) {
    coap_log_warn("Size of large buffer restricted to 0x%lx bytes\n", MAX_BLK_LEN);
    length = MAX_BLK_LEN;
  }
#endif /* UINT_MAX > MAX_BLK_LEN */

  /* Determine the block size to use, adding in sensible options if needed */
  if (COAP_PDU_IS_REQUEST(pdu)) {
    coap_lg_xmit_t *q;

#if COAP_Q_BLOCK_SUPPORT
    if (session->block_mode & (COAP_BLOCK_HAS_Q_BLOCK|COAP_BLOCK_TRY_Q_BLOCK)) {
      option = COAP_OPTION_Q_BLOCK1;
      alt_option = COAP_OPTION_BLOCK1;
    } else {
      option = COAP_OPTION_BLOCK1;
      alt_option = COAP_OPTION_Q_BLOCK1;
    }
#else /* ! COAP_Q_BLOCK_SUPPORT */
    if (coap_get_block_b(session, pdu, COAP_OPTION_Q_BLOCK1, &block)) {
      coap_remove_option(pdu, COAP_OPTION_Q_BLOCK1);
    }
    option = COAP_OPTION_BLOCK1;
#endif /* ! COAP_Q_BLOCK_SUPPORT */

    /* See if this token is already in use for large bodies (unlikely) */
    LL_FOREACH_SAFE(session->lg_xmit, lg_xmit, q) {
      if (coap_binary_equal(&pdu->actual_token, lg_xmit->b.b1.app_token)) {
        /* Unfortunately need to free this off as potential size change */
        LL_DELETE(session->lg_xmit, lg_xmit);
        coap_block_delete_lg_xmit(session, lg_xmit);
        lg_xmit = NULL;
        coap_handle_event_lkd(session->context, COAP_EVENT_XMIT_BLOCK_FAIL, session);
        break;
      }
    }
  } else {
    /* Have to assume that it is a response even if code is 0.00 */
    assert(resource);
#if COAP_Q_BLOCK_SUPPORT
    if (session->block_mode & COAP_BLOCK_HAS_Q_BLOCK) {
      option = COAP_OPTION_Q_BLOCK2;
      alt_option = COAP_OPTION_BLOCK2;
    } else {
      option = COAP_OPTION_BLOCK2;
      alt_option = COAP_OPTION_Q_BLOCK2;
    }
#else /* ! COAP_Q_BLOCK_SUPPORT */
    if (coap_get_block_b(session, pdu, COAP_OPTION_Q_BLOCK2, &block)) {
      coap_remove_option(pdu, COAP_OPTION_Q_BLOCK2);
    }
    option = COAP_OPTION_BLOCK2;
#endif /* ! COAP_Q_BLOCK_SUPPORT */
#if COAP_SERVER_SUPPORT
    /*
     * Check if resource+query+rtag is already in use for large bodies
     * (unlikely)
     */
    lg_xmit = coap_find_lg_xmit_response(session, request, resource, query);
    if (lg_xmit) {
      /* Unfortunately need to free this off as potential size change */
      LL_DELETE(session->lg_xmit, lg_xmit);
      coap_block_delete_lg_xmit(session, lg_xmit);
      lg_xmit = NULL;
      coap_handle_event_lkd(session->context, COAP_EVENT_XMIT_BLOCK_FAIL, session);
    }
#endif /* COAP_SERVER_SUPPORT */
  }
#if COAP_OSCORE_SUPPORT
  if (session->oscore_encryption) {
    /* Need to convert Proxy-Uri to Proxy-Scheme option if needed */
    if (COAP_PDU_IS_REQUEST(pdu) && !coap_rebuild_pdu_for_proxy(pdu))
      goto fail;
  }
#endif /* COAP_OSCORE_SUPPORT */

  token_options = pdu->data ? (size_t)(pdu->data - pdu->token) : pdu->used_size;
  avail = pdu->max_size - token_options;
  /* There may be a response with Echo option */
  avail -= coap_opt_encode_size(COAP_OPTION_ECHO, 40);
#if COAP_OSCORE_SUPPORT
  avail -= coap_oscore_overhead(session, pdu);
#endif /* COAP_OSCORE_SUPPORT */
  /* May need token of length 8, so account for this */
  avail -= (pdu->actual_token.length < 8) ? 8 - pdu->actual_token.length : 0;
  blk_size = coap_flsll((long long)avail) - 4 - 1;
  if (blk_size > 6)
    blk_size = 6;

  max_blk_size = COAP_BLOCK_MAX_SIZE_GET(session->block_mode);
  if (max_blk_size && blk_size > max_blk_size)
    blk_size = max_blk_size;

  /* see if BlockX defined - if so update blk_size as given by app */
  if (coap_get_block_b(session, pdu, option, &block)) {
    if (block.szx < blk_size)
      blk_size = block.szx;
    have_block_defined = 1;
  }
#if COAP_Q_BLOCK_SUPPORT
  /* see if alternate BlockX defined */
  if (coap_get_block_b(session, pdu, alt_option, &alt_block)) {
    if (have_block_defined) {
      /* Cannot have both options set */
      coap_log_warn("Both BlockX and Q-BlockX cannot be set at the same time\n");
      coap_remove_option(pdu, alt_option);
    } else {
      block = alt_block;
      if (block.szx < blk_size)
        blk_size = block.szx;
      have_block_defined = 1;
      option = alt_option;
    }
  }
#endif /* COAP_Q_BLOCK_SUPPORT */

  if (avail < 16 && ((ssize_t)length > avail || have_block_defined)) {
    /* bad luck, this is the smallest block size */
    coap_log_debug("not enough space, even the smallest block does not fit (2)\n");
    goto fail;
  }

  chunk = (size_t)1 << (blk_size + 4);
  if ((have_block_defined && block.num != 0) || single_request ||
      ((session->block_mode & COAP_BLOCK_STLESS_BLOCK2) && session->type != COAP_SESSION_TYPE_CLIENT)) {
    /* App is defining a single block to send or we are stateless */
    size_t rem;

    if (length >= block.num * chunk) {
      if (session->block_mode & COAP_BLOCK_STLESS_BLOCK2 && session->type != COAP_SESSION_TYPE_CLIENT) {
#if COAP_SERVER_SUPPORT
        /* We are running server stateless */
        coap_update_option(pdu,
                           COAP_OPTION_SIZE2,
                           coap_encode_var_safe(buf, sizeof(buf),
                                                (unsigned int)length),
                           buf);
        if (etag == 0) {
          coap_digest_t digest;
          coap_digest_ctx_t *dctx =  coap_digest_setup();

          if (!dctx)
            goto fail;
          if (!coap_digest_update(dctx, data, length))
            goto fail;
          if (!coap_digest_final(dctx, &digest))
            goto fail;
          memcpy(&etag, digest.key, sizeof(etag));
        }
        coap_update_option(pdu,
                           COAP_OPTION_ETAG,
                           coap_encode_var_safe8(buf, sizeof(buf), etag),
                           buf);
        if (request) {
          if (!coap_get_block_b(session, request, option, &block))
            block.num = 0;
        }
        if (!setup_block_b(session, pdu, &block, block.num,
                           blk_size, length))
          goto fail;

        /* Add in with requested block num, more bit and block size */
        coap_update_option(pdu,
                           option,
                           coap_encode_var_safe(buf, sizeof(buf),
                                                (block.num << 4) | (block.m << 3) | block.aszx),
                           buf);
#endif /* COAP_SERVER_SUPPORT */
      }
      rem = chunk;
      if (chunk > length - block.num * chunk)
        rem = length - block.num * chunk;
      if (!coap_add_data(pdu, rem, &data[block.num * chunk]))
        goto fail;
    }
    if (release_func)
      release_func(session, app_ptr);
  } else if ((have_block_defined && length > chunk) || (ssize_t)length > avail) {
    /* Only add in lg_xmit if more than one block needs to be handled */
    size_t rem;

    lg_xmit = coap_malloc_type(COAP_LG_XMIT, sizeof(coap_lg_xmit_t));
    if (!lg_xmit)
      goto fail;

    /* Set up for displaying all the data in the pdu */
    pdu->body_data = data;
    pdu->body_length = length;
    coap_log_debug("PDU presented by app.\n");
    coap_show_pdu(COAP_LOG_DEBUG, pdu);
    pdu->body_data = NULL;
    pdu->body_length = 0;

    coap_log_debug("** %s: lg_xmit %p initialized\n",
                   coap_session_str(session), (void *)lg_xmit);
    /* Update lg_xmit with large data information */
    memset(lg_xmit, 0, sizeof(coap_lg_xmit_t));
    lg_xmit->blk_size = blk_size;
    lg_xmit->option = option;
    lg_xmit->data = data;
    lg_xmit->length = length;
#if COAP_Q_BLOCK_SUPPORT
    lg_xmit->non_timeout_random_ticks =
        coap_get_non_timeout_random_ticks(session);
#endif /* COAP_Q_BLOCK_SUPPORT */
    lg_xmit->release_func = release_func;
    lg_xmit->app_ptr = app_ptr;
    pdu->lg_xmit = lg_xmit;
    coap_ticks(&lg_xmit->last_obs);
    coap_ticks(&lg_xmit->last_sent);
    if (COAP_PDU_IS_REQUEST(pdu)) {
      /* Need to keep original token for updating response PDUs */
      lg_xmit->b.b1.app_token = coap_new_binary(pdu->actual_token.length);
      if (!lg_xmit->b.b1.app_token)
        goto fail;
      memcpy(lg_xmit->b.b1.app_token->s, pdu->actual_token.s,
             pdu->actual_token.length);
      /*
       * Need to set up new token for use during transmits
       * RFC9177#section-5
       */
      lg_xmit->b.b1.count = 1;
      lg_xmit->b.b1.state_token = STATE_TOKEN_FULL(++session->tx_token,
                                                   lg_xmit->b.b1.count);
      /*
       * Token will be updated in pdu later as original pdu may be needed in
       * coap_send()
       */
      coap_update_option(pdu,
                         COAP_OPTION_SIZE1,
                         coap_encode_var_safe(buf, sizeof(buf),
                                              (unsigned int)length),
                         buf);
      if (!coap_check_option(pdu, COAP_OPTION_RTAG, &opt_iter))
        coap_insert_option(pdu,
                           COAP_OPTION_RTAG,
                           coap_encode_var_safe(buf, sizeof(buf),
                                                ++session->tx_rtag),
                           buf);
    } else {
      /*
       * resource+query+rtag match is used for Block2 large body transmissions
       * token match is used for Block1 large body transmissions
       */
      lg_xmit->b.b2.resource = resource;
      if (query) {
        lg_xmit->b.b2.query = coap_new_string(query->length);
        if (lg_xmit->b.b2.query) {
          memcpy(lg_xmit->b.b2.query->s, query->s, query->length);
        }
      } else {
        lg_xmit->b.b2.query = NULL;
      }
      opt = coap_check_option(request, COAP_OPTION_RTAG, &opt_iter);
      if (opt) {
        lg_xmit->b.b2.rtag_length = (uint8_t)min(coap_opt_length(opt),
                                                 sizeof(lg_xmit->b.b2.rtag));
        memcpy(lg_xmit->b.b2.rtag, coap_opt_value(opt), coap_opt_length(opt));
        lg_xmit->b.b2.rtag_set = 1;
      } else {
        lg_xmit->b.b2.rtag_set = 0;
      }
      lg_xmit->b.b2.etag = etag;
      lg_xmit->b.b2.request_method = request_method;
      if (maxage >= 0) {
        coap_tick_t now;

        coap_ticks(&now);
        lg_xmit->b.b2.maxage_expire = coap_ticks_to_rt(now) + maxage;
      } else {
        lg_xmit->b.b2.maxage_expire = 0;
      }
      coap_update_option(pdu,
                         COAP_OPTION_SIZE2,
                         coap_encode_var_safe(buf, sizeof(buf),
                                              (unsigned int)length),
                         buf);
      if (etag == 0) {
        if (++session->context->etag == 0)
          ++session->context->etag;
        etag = session->context->etag;
      }
      coap_update_option(pdu,
                         COAP_OPTION_ETAG,
                         coap_encode_var_safe8(buf, sizeof(buf), etag),
                         buf);
    }

    if (!setup_block_b(session, pdu, &block, block.num,
                       blk_size, lg_xmit->length))
      goto fail;

    /* Add in with requested block num, more bit and block size */
    coap_update_option(pdu,
                       lg_xmit->option,
                       coap_encode_var_safe(buf, sizeof(buf),
                                            (block.num << 4) | (block.m << 3) | block.aszx),
                       buf);

    /* Set up skeletal PDU to use as a basis for all the subsequent blocks */
    memcpy(&lg_xmit->pdu, pdu, sizeof(lg_xmit->pdu));
    lg_xmit->pdu.token = coap_malloc_type(COAP_PDU_BUF,
                                          lg_xmit->pdu.used_size + lg_xmit->pdu.max_hdr_size);
    if (!lg_xmit->pdu.token)
      goto fail;

    lg_xmit->pdu.alloc_size = lg_xmit->pdu.used_size;
    lg_xmit->pdu.token += lg_xmit->pdu.max_hdr_size;
    memcpy(lg_xmit->pdu.token, pdu->token, lg_xmit->pdu.used_size);
    if (pdu->data)
      lg_xmit->pdu.data = lg_xmit->pdu.token + (pdu->data - pdu->token);
    lg_xmit->pdu.actual_token.s = lg_xmit->pdu.token + pdu->e_token_length -
                                  pdu->actual_token.length;
    lg_xmit->pdu.actual_token.length = pdu->actual_token.length;

    /* Check we still have space after adding in some options */
    token_options = pdu->data ? (size_t)(pdu->data - pdu->token) : pdu->used_size;
    avail = pdu->max_size - token_options;
    /* There may be a response with Echo option */
    avail -= coap_opt_encode_size(COAP_OPTION_ECHO, 40);
    /* May need token of length 8, so account for this */
    avail -= (pdu->actual_token.length < 8) ? 8 - pdu->actual_token.length : 0;
#if COAP_OSCORE_SUPPORT
    avail -= coap_oscore_overhead(session, pdu);
#endif /* COAP_OSCORE_SUPPORT */
    if (avail < (ssize_t)chunk) {
      /* chunk size change down */
      if (avail < 16) {
        coap_log_warn("not enough space, even the smallest block does not fit (3)\n");
        goto fail;
      }
      blk_size = coap_flsll((long long)avail) - 4 - 1;
      block.num = block.num << (lg_xmit->blk_size - blk_size);
      lg_xmit->blk_size = blk_size;
      chunk = (size_t)1 << (lg_xmit->blk_size + 4);
      block.chunk_size = (uint32_t)chunk;
      block.bert = 0;
      coap_update_option(pdu,
                         lg_xmit->option,
                         coap_encode_var_safe(buf, sizeof(buf),
                                              (block.num << 4) | (block.m << 3) | lg_xmit->blk_size),
                         buf);
    }

    rem = block.chunk_size;
    if (rem > lg_xmit->length - block.num * chunk)
      rem = lg_xmit->length - block.num * chunk;
    if (!coap_add_data(pdu, rem, &data[block.num * chunk]))
      goto fail;

    if (COAP_PDU_IS_REQUEST(pdu))
      lg_xmit->b.b1.bert_size = rem;

    lg_xmit->last_block = -1;

    /* Link the new lg_xmit in */
    LL_PREPEND(session->lg_xmit,lg_xmit);
  } else {
    /* No need to use blocks */
    if (etag) {
      coap_update_option(pdu,
                         COAP_OPTION_ETAG,
                         coap_encode_var_safe8(buf, sizeof(buf), etag),
                         buf);
    }
    if (have_block_defined) {
      coap_update_option(pdu,
                         option,
                         coap_encode_var_safe(buf, sizeof(buf),
                                              (0 << 4) | (0 << 3) | blk_size), buf);
    }
add_data:
    if (!coap_add_data(pdu, length, data))
      goto fail;

    if (release_func)
      release_func(session, app_ptr);
  }
  return 1;

fail:
  if (lg_xmit) {
    coap_block_delete_lg_xmit(session, lg_xmit);
  } else if (release_func) {
    release_func(session, app_ptr);
  }
  return 0;
}

#if COAP_CLIENT_SUPPORT
COAP_API int
coap_add_data_large_request(coap_session_t *session,
                            coap_pdu_t *pdu,
                            size_t length,
                            const uint8_t *data,
                            coap_release_large_data_t release_func,
                            void *app_ptr
                           ) {
  int ret;

  coap_lock_lock(session->context, return 0);
  ret = coap_add_data_large_request_lkd(session, pdu, length, data,
                                        release_func, app_ptr);
  coap_lock_unlock(session->context);
  return ret;
}

int
coap_add_data_large_request_lkd(coap_session_t *session,
                                coap_pdu_t *pdu,
                                size_t length,
                                const uint8_t *data,
                                coap_release_large_data_t release_func,
                                void *app_ptr) {
  /*
   * Delay if session->doing_first is set.
   * E.g. Reliable and CSM not in yet for checking block support
   */
  if (coap_client_delay_first(session) == 0) {
    if (release_func)
      release_func(session, app_ptr);
    return 0;
  }
  return coap_add_data_large_internal(session, NULL, pdu, NULL, NULL, -1, 0,
                                      length, data, release_func, app_ptr, 0, 0);
}
#endif /* ! COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
COAP_API int
coap_add_data_large_response(coap_resource_t *resource,
                             coap_session_t *session,
                             const coap_pdu_t *request,
                             coap_pdu_t *response,
                             const coap_string_t *query,
                             uint16_t media_type,
                             int maxage,
                             uint64_t etag,
                             size_t length,
                             const uint8_t *data,
                             coap_release_large_data_t release_func,
                             void *app_ptr
                            ) {
  int ret;

  coap_lock_lock(session->context, return 0);
  ret = coap_add_data_large_response_lkd(resource, session, request,
                                         response, query, media_type, maxage, etag,
                                         length, data, release_func, app_ptr);
  coap_lock_unlock(session->context);
  return ret;
}

int
coap_add_data_large_response_lkd(coap_resource_t *resource,
                                 coap_session_t *session,
                                 const coap_pdu_t *request,
                                 coap_pdu_t *response,
                                 const coap_string_t *query,
                                 uint16_t media_type,
                                 int maxage,
                                 uint64_t etag,
                                 size_t length,
                                 const uint8_t *data,
                                 coap_release_large_data_t release_func,
                                 void *app_ptr
                                ) {
  unsigned char buf[4];
  coap_block_b_t block;
  int block_requested = 0;
  int single_request = 0;
#if COAP_Q_BLOCK_SUPPORT
  uint32_t block_opt = (session->block_mode & COAP_BLOCK_HAS_Q_BLOCK) ?
                       COAP_OPTION_Q_BLOCK2 : COAP_OPTION_BLOCK2;
#else /* ! COAP_Q_BLOCK_SUPPORT */
  uint16_t block_opt = COAP_OPTION_BLOCK2;
#endif /* ! COAP_Q_BLOCK_SUPPORT */

  memset(&block, 0, sizeof(block));
  /*
   * Need to check that a valid block is getting asked for so that the
   * correct options are put into the PDU.
   */
  if (request) {
    if (coap_get_block_b(session, request, COAP_OPTION_BLOCK2, &block)) {
      block_requested = 1;
      if (block.num != 0 && length <= (block.num << (block.szx + 4))) {
        coap_log_debug("Illegal block requested (%d > last = %zu)\n",
                       block.num,
                       length >> (block.szx + 4));
        response->code = COAP_RESPONSE_CODE(400);
        goto error;
      }
    }
#if COAP_Q_BLOCK_SUPPORT
    else if (coap_get_block_b(session, request, COAP_OPTION_Q_BLOCK2, &block)) {
      block_requested = 1;
      if (block.num != 0 && length <= (block.num << (block.szx + 4))) {
        coap_log_debug("Illegal block requested (%d > last = %zu)\n",
                       block.num,
                       length >> (block.szx + 4));
        response->code = COAP_RESPONSE_CODE(400);
        goto error;
      }
      if (!(session->block_mode & COAP_BLOCK_HAS_Q_BLOCK)) {
        set_block_mode_has_q(session->block_mode);
        block_opt = COAP_OPTION_Q_BLOCK2;
      }
      if (block.m == 0)
        single_request = 1;
    }
#endif /* COAP_Q_BLOCK_SUPPORT */
  }

  coap_insert_option(response, COAP_OPTION_CONTENT_FORMAT,
                     coap_encode_var_safe(buf, sizeof(buf),
                                          media_type),
                     buf);

  if (maxage >= 0) {
    coap_insert_option(response,
                       COAP_OPTION_MAXAGE,
                       coap_encode_var_safe(buf, sizeof(buf), maxage), buf);
  }

  if (block_requested) {
    int res;

    res = coap_write_block_b_opt(session, &block, block_opt, response,
                                 length);

    switch (res) {
    case -2:                        /* illegal block (caught above) */
      response->code = COAP_RESPONSE_CODE(400);
      goto error;
    case -1:                        /* should really not happen */
      assert(0);
    /* fall through if assert is a no-op */
    case -3:                        /* cannot handle request */
      response->code = COAP_RESPONSE_CODE(500);
      goto error;
    default:                        /* everything is good */
      ;
    }
  }

  /* add data body */
  if (request &&
      !coap_add_data_large_internal(session, request, response, resource,
                                    query, maxage, etag, length, data,
                                    release_func, app_ptr, single_request,
                                    request->code)) {
    response->code = COAP_RESPONSE_CODE(500);
    goto error_released;
  }

  return 1;

error:
  if (release_func)
    release_func(session, app_ptr);
error_released:
#if COAP_ERROR_PHRASE_LENGTH > 0
  coap_add_data(response,
                strlen(coap_response_phrase(response->code)),
                (const unsigned char *)coap_response_phrase(response->code));
#endif /* COAP_ERROR_PHRASE_LENGTH > 0 */
  return 0;
}
#endif /* ! COAP_SERVER_SUPPORT */

/*
 * return 1 if there is a future expire time, else 0.
 * update tim_rem with remaining value if return is 1.
 */
int
coap_block_check_lg_xmit_timeouts(coap_session_t *session, coap_tick_t now,
                                  coap_tick_t *tim_rem) {
  coap_lg_xmit_t *p;
  coap_lg_xmit_t *q;
#if COAP_Q_BLOCK_SUPPORT
  coap_tick_t idle_timeout = 4 * COAP_NON_TIMEOUT_TICKS(session);
#else /* ! COAP_Q_BLOCK_SUPPORT */
  coap_tick_t idle_timeout = 8 * COAP_TICKS_PER_SECOND;
#endif /* ! COAP_Q_BLOCK_SUPPORT */
  coap_tick_t partial_timeout = COAP_MAX_TRANSMIT_WAIT_TICKS(session);
  int ret = 0;

  *tim_rem = -1;

  LL_FOREACH_SAFE(session->lg_xmit, p, q) {
    if (p->last_all_sent) {
      if (p->last_all_sent + idle_timeout <= now) {
        /* Expire this entry */
        LL_DELETE(session->lg_xmit, p);
        coap_block_delete_lg_xmit(session, p);
      } else {
        /* Delay until the lg_xmit needs to expire */
        if (*tim_rem > p->last_all_sent + idle_timeout - now) {
          *tim_rem = p->last_all_sent + idle_timeout - now;
          ret = 1;
        }
      }
    } else if (p->last_sent) {
      if (p->last_sent + partial_timeout <= now) {
        /* Expire this entry */
        LL_DELETE(session->lg_xmit, p);
        coap_block_delete_lg_xmit(session, p);
        coap_handle_event_lkd(session->context, COAP_EVENT_XMIT_BLOCK_FAIL, session);
      } else {
        /* Delay until the lg_xmit needs to expire */
        if (*tim_rem > p->last_sent + partial_timeout - now) {
          *tim_rem = p->last_sent + partial_timeout - now;
          ret = 1;
        }
      }
    }
  }
  return ret;
}

#if COAP_CLIENT_SUPPORT
#if COAP_Q_BLOCK_SUPPORT
static coap_pdu_t *
coap_build_missing_pdu(coap_session_t *session, coap_lg_crcv_t *p) {
  coap_pdu_t *pdu;
  coap_opt_filter_t drop_options;
  uint64_t token = STATE_TOKEN_FULL(p->state_token, ++p->retry_counter);
  uint8_t buf[8];
  size_t len = coap_encode_var_safe8(buf, sizeof(token), token);

  memset(&drop_options, 0, sizeof(coap_opt_filter_t));
  coap_option_filter_set(&drop_options, COAP_OPTION_Q_BLOCK2);
  coap_option_filter_set(&drop_options, COAP_OPTION_OBSERVE);
  pdu = coap_pdu_duplicate_lkd(&p->pdu, session, len, buf,
                               &drop_options);
  if (!pdu)
    return NULL;
  pdu->type = p->last_type;
  return pdu;
}

static void
coap_request_missing_q_block2(coap_session_t *session, coap_lg_crcv_t *lg_crcv) {
  uint8_t buf[8];
  uint32_t i;
  int block = -1; /* Last one seen */
  size_t sofar;
  size_t block_size;
  coap_pdu_t *pdu = NULL;
  int block_payload_set = -1;

  if (session->block_mode & COAP_BLOCK_USE_M_Q_BLOCK) {
    /*
     * See if it is safe to use the single 'M' block variant of request
     *
     * If any blocks seen, then missing blocks are after range[0].end and
     * terminate on the last block or before range[1].begin if set.
     * If not defined or range[1].begin is in a different payload set then
     * safe to use M bit.
     */
    if (lg_crcv->rec_blocks.used &&
        (lg_crcv->rec_blocks.used < 2 ||
         ((lg_crcv->rec_blocks.range[0].end + 1) / COAP_MAX_PAYLOADS(session) !=
          (lg_crcv->rec_blocks.range[1].begin -1) / COAP_MAX_PAYLOADS(session)))) {
      block = lg_crcv->rec_blocks.range[0].end + 1;
      block_size = (size_t)1 << (lg_crcv->szx + 4);
      sofar = block * block_size;
      if (sofar < lg_crcv->total_len) {
        /* Ask for missing blocks */
        if (pdu == NULL) {
          pdu = coap_build_missing_pdu(session, lg_crcv);
          if (!pdu)
            return;
        }
        coap_insert_option(pdu, COAP_OPTION_Q_BLOCK2,
                           coap_encode_var_safe(buf, sizeof(buf),
                                                (block << 4) | (1 << 3) | lg_crcv->szx),
                           buf);
        block_payload_set = block / COAP_MAX_PAYLOADS(session);
        goto send_it;
      }
    }
  }
  block = -1;
  for (i = 0; i < lg_crcv->rec_blocks.used; i++) {
    if (block < (int)lg_crcv->rec_blocks.range[i].begin &&
        lg_crcv->rec_blocks.range[i].begin != 0) {
      /* Ask for missing blocks */
      if (pdu == NULL) {
        pdu = coap_build_missing_pdu(session, lg_crcv);
        if (!pdu)
          continue;
      }
      block++;
      if (block_payload_set == -1)
        block_payload_set = block / COAP_MAX_PAYLOADS(session);
      for (; block < (int)lg_crcv->rec_blocks.range[i].begin &&
           block_payload_set == (block / COAP_MAX_PAYLOADS(session)); block++) {
        coap_insert_option(pdu, COAP_OPTION_Q_BLOCK2,
                           coap_encode_var_safe(buf, sizeof(buf),
                                                (block << 4) | (0 << 3) | lg_crcv->szx),
                           buf);
      }
    }
    if (block < (int)lg_crcv->rec_blocks.range[i].end) {
      block = lg_crcv->rec_blocks.range[i].end;
    }
  }
  block_size = (size_t)1 << (lg_crcv->szx + 4);
  sofar = (block + 1) * block_size;
  if (sofar < lg_crcv->total_len) {
    /* Ask for trailing missing blocks */
    if (pdu == NULL) {
      pdu = coap_build_missing_pdu(session, lg_crcv);
      if (!pdu)
        return;
    }
    sofar = (lg_crcv->total_len + block_size - 1)/block_size;
    block++;
    if (block_payload_set == -1)
      block_payload_set = block / COAP_MAX_PAYLOADS(session);
    for (; block < (ssize_t)sofar &&
         block_payload_set == (block / COAP_MAX_PAYLOADS(session)); block++) {
      coap_insert_option(pdu, COAP_OPTION_Q_BLOCK2,
                         coap_encode_var_safe(buf, sizeof(buf),
                                              (block << 4) | (0 << 3) | lg_crcv->szx),
                         buf);
    }
  }
send_it:
  if (pdu)
    coap_send_internal(session, pdu);
  lg_crcv->rec_blocks.retry++;
  if (block_payload_set != -1)
    lg_crcv->rec_blocks.processing_payload_set = block_payload_set;
  coap_ticks(&lg_crcv->rec_blocks.last_seen);
}
#endif /* COAP_Q_BLOCK_SUPPORT */

/*
 * return 1 if there is a future expire time, else 0.
 * update tim_rem with remaining value if return is 1.
 */
int
coap_block_check_lg_crcv_timeouts(coap_session_t *session, coap_tick_t now,
                                  coap_tick_t *tim_rem) {
  coap_lg_crcv_t *p;
  coap_lg_crcv_t *q;
  coap_tick_t partial_timeout;
#if COAP_Q_BLOCK_SUPPORT
  coap_tick_t receive_timeout = COAP_NON_RECEIVE_TIMEOUT_TICKS(session);
#endif /* COAP_Q_BLOCK_SUPPORT */
  int ret = 0;

  *tim_rem = -1;
#if COAP_Q_BLOCK_SUPPORT
  if (COAP_PROTO_NOT_RELIABLE(session->proto) &&
      session->block_mode & COAP_BLOCK_HAS_Q_BLOCK)
    partial_timeout = COAP_NON_PARTIAL_TIMEOUT_TICKS(session);
  else
#endif /* COAP_Q_BLOCK_SUPPORT */
    partial_timeout = COAP_MAX_TRANSMIT_WAIT_TICKS(session);

  LL_FOREACH_SAFE(session->lg_crcv, p, q) {
    if (COAP_PROTO_RELIABLE(session->proto) || p->last_type != COAP_MESSAGE_NON)
      goto check_expire;

#if COAP_Q_BLOCK_SUPPORT
    if (p->block_option == COAP_OPTION_Q_BLOCK2 && p->rec_blocks.used) {
      size_t scaled_timeout = receive_timeout *
                              ((size_t)1 << p->rec_blocks.retry);

      if (p->rec_blocks.retry >= COAP_NON_MAX_RETRANSMIT(session)) {
        /* Done NON_MAX_RETRANSMIT retries */
        coap_update_token(&p->pdu, p->app_token->length, p->app_token->s);
        coap_lock_callback(session->context,
                           session->context->nack_handler(session, &p->pdu,
                                                          COAP_NACK_TOO_MANY_RETRIES,
                                                          p->pdu.mid));
        goto expire;
      }
      if (p->rec_blocks.last_seen + scaled_timeout <= now) {
        coap_request_missing_q_block2(session, p);
      } else {
        if (*tim_rem > p->rec_blocks.last_seen + scaled_timeout - now) {
          *tim_rem = p->rec_blocks.last_seen + scaled_timeout - now;
          ret = 1;
        }
      }
    }
#endif /* COAP_Q_BLOCK_SUPPORT */
    /* Used for Block2 and Q-Block2 */
check_expire:
    if (!p->observe_set && p->last_used &&
        p->last_used + partial_timeout <= now) {
#if COAP_Q_BLOCK_SUPPORT
expire:
#endif /* COAP_Q_BLOCK_SUPPORT */
      /* Expire this entry */
      LL_DELETE(session->lg_crcv, p);
      coap_block_delete_lg_crcv(session, p);
    } else if (!p->observe_set && p->last_used) {
      /* Delay until the lg_crcv needs to expire */
      if (*tim_rem > p->last_used + partial_timeout - now) {
        *tim_rem = p->last_used + partial_timeout - now;
        ret = 1;
      }
    }
  }
  return ret;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
#if COAP_Q_BLOCK_SUPPORT
static coap_pdu_t *
pdu_408_build(coap_session_t *session, coap_lg_srcv_t *p) {
  coap_pdu_t *pdu;
  uint8_t buf[4];

  pdu = coap_pdu_init(COAP_MESSAGE_NON,
                      COAP_RESPONSE_CODE(408),
                      coap_new_message_id_lkd(session),
                      coap_session_max_pdu_size_lkd(session));
  if (!pdu)
    return NULL;
  if (p->last_token)
    coap_add_token(pdu, p->last_token->length, p->last_token->s);
  coap_add_option_internal(pdu, COAP_OPTION_CONTENT_TYPE,
                           coap_encode_var_safe(buf, sizeof(buf),
                                                COAP_MEDIATYPE_APPLICATION_MB_CBOR_SEQ),
                           buf);
  pdu->token[pdu->used_size++] = COAP_PAYLOAD_START;
  pdu->data = pdu->token + pdu->used_size;
  return pdu;
}

static int
add_408_block(coap_pdu_t *pdu, int block) {
  size_t len;
  uint8_t val[8];

  assert(block >= 0 && block < (1 << 20));

  if (block < 0 || block >= (1 << 20)) {
    return 0;
  } else if (block < 24) {
    len = 1;
    val[0] = block;
  } else if (block < 0x100) {
    len = 2;
    val[0] = 24;
    val[1] = block;
  } else if (block < 0x10000) {
    len = 3;
    val[0] = 25;
    val[1] = block >> 8;
    val[2] = block & 0xff;
  } else { /* Largest block number is 2^^20 - 1 */
    len = 4;
    val[0] = 26;
    val[1] = block >> 16;
    val[2] = (block >> 8) & 0xff;
    val[3] = block & 0xff;
  }
  if (coap_pdu_check_resize(pdu, pdu->used_size + len)) {
    memcpy(&pdu->token[pdu->used_size], val, len);
    pdu->used_size += len;
    return 1;
  }
  return 0;
}
#endif /* COAP_Q_BLOCK_SUPPORT */
#endif /* COAP_SERVER_SUPPORT */

static int
check_if_received_block(coap_rblock_t *rec_blocks, uint32_t block_num) {
  uint32_t i;

  for (i = 0; i < rec_blocks->used; i++) {
    if (block_num < rec_blocks->range[i].begin)
      return 0;
    if (block_num <= rec_blocks->range[i].end)
      return 1;
  }
  return 0;
}

#if COAP_SERVER_SUPPORT
static int
check_if_next_block(coap_rblock_t *rec_blocks, uint32_t block_num) {
  if (rec_blocks->used == 0) {
    return block_num == 0 ? 1 : 0;
  }
  if (rec_blocks->range[rec_blocks->used-1].end + 1 == block_num)
    return 1;

  return 0;
}
#endif /* COAP_SERVER_SUPPORT */

static int
check_all_blocks_in(coap_rblock_t *rec_blocks, size_t total_blocks) {
  uint32_t i;
  uint32_t block = 0;

  for (i = 0; i < rec_blocks->used; i++) {
    if (block < rec_blocks->range[i].begin)
      return 0;
    if (block < rec_blocks->range[i].end)
      block = rec_blocks->range[i].end;
  }
  /* total_blocks counts from 1 */
  if (block + 1 < total_blocks)
    return 0;

  return 1;
}

#if COAP_CLIENT_SUPPORT
#if COAP_Q_BLOCK_SUPPORT
static int
check_all_blocks_in_for_payload_set(coap_session_t *session,
                                    coap_rblock_t *rec_blocks) {
  if (rec_blocks->used &&
      (rec_blocks->range[0].end + 1) / COAP_MAX_PAYLOADS(session) >
      rec_blocks->processing_payload_set)
    return 1;
  return 0;
}

static int
check_any_blocks_next_payload_set(coap_session_t *session,
                                  coap_rblock_t *rec_blocks) {
  if (rec_blocks->used > 1 &&
      rec_blocks->range[1].begin / COAP_MAX_PAYLOADS(session) ==
      rec_blocks->processing_payload_set)
    return 1;
  return 0;
}
#endif /* COAP_Q_BLOCK_SUPPORT */
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
/*
 * return 1 if there is a future expire time, else 0.
 * update tim_rem with remaining value if return is 1.
 */
int
coap_block_check_lg_srcv_timeouts(coap_session_t *session, coap_tick_t now,
                                  coap_tick_t *tim_rem) {
  coap_lg_srcv_t *p;
  coap_lg_srcv_t *q;
  coap_tick_t partial_timeout;
#if COAP_Q_BLOCK_SUPPORT
  coap_tick_t receive_timeout = COAP_NON_RECEIVE_TIMEOUT_TICKS(session);
#endif /* COAP_Q_BLOCK_SUPPORT */
  int ret = 0;

  *tim_rem = -1;
#if COAP_Q_BLOCK_SUPPORT
  if (COAP_PROTO_NOT_RELIABLE(session->proto) &&
      session->block_mode & COAP_BLOCK_HAS_Q_BLOCK)
    partial_timeout = COAP_NON_PARTIAL_TIMEOUT_TICKS(session);
  else
#endif /* COAP_Q_BLOCK_SUPPORT */
    partial_timeout = COAP_MAX_TRANSMIT_WAIT_TICKS(session);

  LL_FOREACH_SAFE(session->lg_srcv, p, q) {
    if (COAP_PROTO_RELIABLE(session->proto) || p->last_type != COAP_MESSAGE_NON)
      goto check_expire;

#if COAP_Q_BLOCK_SUPPORT
    if (p->block_option == COAP_OPTION_Q_BLOCK1 && p->rec_blocks.used) {
      size_t scaled_timeout = receive_timeout *
                              ((size_t)1 << p->rec_blocks.retry);

      if (p->rec_blocks.retry >= COAP_NON_MAX_RETRANSMIT(session)) {
        /* Done NON_MAX_RETRANSMIT retries */
        goto expire;
      }
      if (p->rec_blocks.last_seen + scaled_timeout <= now) {
        uint32_t i;
        int block = -1; /* Last one seen */
        size_t block_size = (size_t)1 << (p->szx + 4);
        size_t final_block = (p->total_len + block_size - 1)/block_size - 1;
        size_t cur_payload;
        size_t last_payload_block;
        coap_pdu_t *pdu = NULL;
        size_t no_blocks = 0;

        /* Need to count the number of missing blocks */
        for (i = 0; i < p->rec_blocks.used; i++) {
          if (block < (int)p->rec_blocks.range[i].begin &&
              p->rec_blocks.range[i].begin != 0) {
            block++;
            no_blocks += p->rec_blocks.range[i].begin - block;
          }
          if (block < (int)p->rec_blocks.range[i].end) {
            block = p->rec_blocks.range[i].end;
          }
        }
        if (no_blocks == 0 && block == (int)final_block)
          goto expire;

        /* Include missing up to end of current payload or total amount */
        cur_payload = block / COAP_MAX_PAYLOADS(session);
        last_payload_block = (cur_payload + 1) * COAP_MAX_PAYLOADS(session) - 1;
        if (final_block > last_payload_block) {
          final_block = last_payload_block;
        }
        no_blocks += final_block - block;
        if (no_blocks == 0) {
          /* Add in the blocks out of the next payload */
          final_block = (p->total_len + block_size - 1)/block_size - 1;
          last_payload_block += COAP_MAX_PAYLOADS(session);
          if (final_block > last_payload_block) {
            final_block = last_payload_block;
          }
        }
        /* Ask for the missing blocks */
        block = -1;
        for (i = 0; i < p->rec_blocks.used; i++) {
          if (block < (int)p->rec_blocks.range[i].begin &&
              p->rec_blocks.range[i].begin != 0) {
            /* Report on missing blocks */
            if (pdu == NULL) {
              pdu = pdu_408_build(session, p);
              if (!pdu)
                continue;
            }
            block++;
            for (; block < (int)p->rec_blocks.range[i].begin; block++) {
              if (!add_408_block(pdu, block)) {
                break;
              }
            }
          }
          if (block < (int)p->rec_blocks.range[i].end) {
            block = p->rec_blocks.range[i].end;
          }
        }
        block++;
        for (; block <= (int)final_block; block++) {
          if (pdu == NULL) {
            pdu = pdu_408_build(session, p);
            if (!pdu)
              continue;
          }
          if (!add_408_block(pdu, block)) {
            break;
          }
        }
        if (pdu)
          coap_send_internal(session, pdu);
        p->rec_blocks.retry++;
        coap_ticks(&p->rec_blocks.last_seen);
      }
      if (*tim_rem > p->rec_blocks.last_seen + scaled_timeout - now) {
        *tim_rem = p->rec_blocks.last_seen + scaled_timeout - now;
        ret = 1;
      }
    }
#endif /* COAP_Q_BLOCK_SUPPORT */
    /* Used for Block1 and Q-Block1 */
check_expire:
    if (p->no_more_seen)
      partial_timeout = 10 * COAP_TICKS_PER_SECOND;
    if (p->last_used && p->last_used + partial_timeout <= now) {
#if COAP_Q_BLOCK_SUPPORT
expire:
#endif /* COAP_Q_BLOCK_SUPPORT */
      /* Expire this entry */
      if (p->no_more_seen && p->block_option == COAP_OPTION_BLOCK1) {
        /*
         * Need to send a separate 4.08 to indicate missing blocks
         * Using NON is permissable as per
         * https://datatracker.ietf.org/doc/html/rfc7252#section-5.2.3
         */
        coap_pdu_t *pdu;

        pdu = coap_pdu_init(COAP_MESSAGE_NON,
                            COAP_RESPONSE_CODE(408),
                            coap_new_message_id_lkd(session),
                            coap_session_max_pdu_size_lkd(session));
        if (pdu) {
          if (p->last_token)
            coap_add_token(pdu, p->last_token->length, p->last_token->s);
          coap_add_data(pdu, sizeof("Missing interim block")-1,
                        (const uint8_t *)"Missing interim block");
          coap_send_internal(session, pdu);
        }
      }
      LL_DELETE(session->lg_srcv, p);
      coap_block_delete_lg_srcv(session, p);
    } else if (p->last_used) {
      /* Delay until the lg_srcv needs to expire */
      if (*tim_rem > p->last_used + partial_timeout - now) {
        *tim_rem = p->last_used + partial_timeout - now;
        ret = 1;
      }
    }
  }
  return ret;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_Q_BLOCK_SUPPORT
/*
 * pdu is always released before return IF COAP_SEND_INC_PDU
 */
coap_mid_t
coap_send_q_blocks(coap_session_t *session,
                   coap_lg_xmit_t *lg_xmit,
                   coap_block_b_t block,
                   coap_pdu_t *pdu,
                   coap_send_pdu_t send_pdu) {
  coap_pdu_t *block_pdu = NULL;
  coap_opt_filter_t drop_options;
  coap_mid_t mid = COAP_INVALID_MID;
  uint64_t token;
  const uint8_t *ptoken;
  uint8_t ltoken[8];
  size_t ltoken_length;
  uint32_t delayqueue_cnt = 0;

  if (!lg_xmit) {
    if (send_pdu == COAP_SEND_INC_PDU)
      return coap_send_internal(session, pdu);
    return COAP_INVALID_MID;
  }

  if (pdu->type == COAP_MESSAGE_CON) {
    coap_queue_t *delayqueue;

    delayqueue_cnt = session->con_active +
                     (send_pdu == COAP_SEND_INC_PDU ? 1 : 0);
    LL_FOREACH(session->delayqueue, delayqueue) {
      delayqueue_cnt++;
    }
  }
  pdu->lg_xmit = lg_xmit;
  if (block.m &&
      ((pdu->type == COAP_MESSAGE_NON &&
        ((block.num + 1) % COAP_MAX_PAYLOADS(session)) + 1 !=
        COAP_MAX_PAYLOADS(session)) ||
       (pdu->type == COAP_MESSAGE_ACK &&
        lg_xmit->option == COAP_OPTION_Q_BLOCK2) ||
       (pdu->type == COAP_MESSAGE_CON &&
        delayqueue_cnt < COAP_NSTART(session)) ||
       COAP_PROTO_RELIABLE(session->proto))) {
    /* Allocate next pdu if there is headroom */
    if (COAP_PDU_IS_RESPONSE(pdu)) {
      ptoken = pdu->actual_token.s;
      ltoken_length = pdu->actual_token.length;
    } else {
      token = STATE_TOKEN_FULL(lg_xmit->b.b1.state_token,++lg_xmit->b.b1.count);
      ltoken_length = coap_encode_var_safe8(ltoken, sizeof(token), token);
      ptoken = ltoken;
    }

    memset(&drop_options, 0, sizeof(coap_opt_filter_t));
    coap_option_filter_set(&drop_options, lg_xmit->option);
    block_pdu = coap_pdu_duplicate_lkd(pdu, session,
                                       ltoken_length,
                                       ptoken, &drop_options);
    if (block_pdu->type == COAP_MESSAGE_ACK)
      block_pdu->type = COAP_MESSAGE_CON;
  }

  /* Send initial pdu (which deletes 'pdu') */
  if (send_pdu == COAP_SEND_INC_PDU &&
      (mid = coap_send_internal(session, pdu)) == COAP_INVALID_MID) {
    /* Not expected, underlying issue somewhere */
    coap_delete_pdu(block_pdu);
    return COAP_INVALID_MID;
  }

  while (block_pdu) {
    coap_pdu_t *t_pdu = NULL;
    uint8_t buf[8];
    size_t chunk = ((size_t)1 << (lg_xmit->blk_size + 4));

    block.num++;
    lg_xmit->offset = block.num * chunk;
    block.m = lg_xmit->offset + chunk < lg_xmit->length;
    if (block.m && ((block_pdu->type == COAP_MESSAGE_NON &&
                     (block.num % COAP_MAX_PAYLOADS(session)) + 1 !=
                     COAP_MAX_PAYLOADS(session)) ||
                    (block_pdu->type == COAP_MESSAGE_CON &&
                     delayqueue_cnt + 1 < COAP_NSTART(session)) ||
                    COAP_PROTO_RELIABLE(session->proto))) {
      /*
       * Send following block if
       *   NON and more in MAX_PAYLOADS
       *   CON and NSTART allows it (based on number in delayqueue)
       *   Reliable transport
       */
      if (COAP_PDU_IS_RESPONSE(block_pdu)) {
        ptoken = block_pdu->actual_token.s;
        ltoken_length = block_pdu->actual_token.length;
      } else {
        token = STATE_TOKEN_FULL(lg_xmit->b.b1.state_token,++lg_xmit->b.b1.count);
        ltoken_length = coap_encode_var_safe8(ltoken, sizeof(token), token);
        ptoken = ltoken;
      }
      t_pdu = coap_pdu_duplicate_lkd(block_pdu, session,
                                     ltoken_length, ptoken, &drop_options);
    }
    if (!coap_update_option(block_pdu, lg_xmit->option,
                            coap_encode_var_safe(buf,
                                                 sizeof(buf),
                                                 ((block.num) << 4) |
                                                 (block.m << 3) |
                                                 block.szx),
                            buf)) {
      coap_log_warn("Internal update issue option\n");
      coap_delete_pdu(block_pdu);
      coap_delete_pdu(t_pdu);
      break;
    }

    if (!coap_add_block(block_pdu,
                        lg_xmit->length,
                        lg_xmit->data,
                        block.num,
                        block.szx)) {
      coap_log_warn("Internal update issue data\n");
      coap_delete_pdu(block_pdu);
      coap_delete_pdu(t_pdu);
      break;
    }
    if (COAP_PDU_IS_RESPONSE(block_pdu)) {
      lg_xmit->last_block = block.num;
    }
    mid = coap_send_internal(session, block_pdu);
    if (mid == COAP_INVALID_MID) {
      /* Not expected, underlying issue somewhere */
      coap_delete_pdu(t_pdu);
      return COAP_INVALID_MID;
    }
    block_pdu = t_pdu;
  }
  if (!block.m) {
    lg_xmit->last_payload = 0;
    coap_ticks(&lg_xmit->last_all_sent);
  } else
    coap_ticks(&lg_xmit->last_payload);
  return mid;
}

#if COAP_CLIENT_SUPPORT
coap_tick_t
coap_block_check_q_block1_xmit(coap_session_t *session, coap_tick_t now) {
  coap_lg_xmit_t *lg_xmit;
  coap_lg_xmit_t *q;
  coap_tick_t timed_out;
  coap_tick_t tim_rem = (coap_tick_t)-1;

  LL_FOREACH_SAFE(session->lg_xmit, lg_xmit, q) {
    coap_tick_t non_timeout = lg_xmit->non_timeout_random_ticks;

    if (now < non_timeout)
      return non_timeout - now;
    timed_out = now - non_timeout;

    if (lg_xmit->last_payload) {
      if (lg_xmit->last_payload <= timed_out) {
        /* Send off the next MAX_PAYLOAD set */
        coap_block_b_t block;
        size_t chunk = (size_t)1 << (lg_xmit->blk_size + 4);

        memset(&block, 0, sizeof(block));
        block.num = (uint32_t)(lg_xmit->offset / chunk);
        block.m = lg_xmit->offset + chunk < lg_xmit->length;
        block.szx = lg_xmit->blk_size;
        coap_send_q_blocks(session, lg_xmit, block, &lg_xmit->pdu, COAP_SEND_SKIP_PDU);
        if (tim_rem > non_timeout)
          tim_rem = non_timeout;
      } else {
        /* Delay until the next MAX_PAYLOAD needs to be sent off */
        if (tim_rem > lg_xmit->last_payload - timed_out)
          tim_rem = lg_xmit->last_payload - timed_out;
      }
    } else if (lg_xmit->last_all_sent) {
      non_timeout = COAP_NON_TIMEOUT_TICKS(session);
      if (lg_xmit->last_all_sent + 4 * non_timeout <= now) {
        /* Expire this entry */
        LL_DELETE(session->lg_xmit, lg_xmit);
        coap_block_delete_lg_xmit(session, lg_xmit);
      } else {
        /* Delay until the lg_xmit needs to expire */
        if (tim_rem > lg_xmit->last_all_sent + 4 * non_timeout - now)
          tim_rem = lg_xmit->last_all_sent + 4 * non_timeout - now;
      }
    }
  }
  return tim_rem;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
coap_tick_t
coap_block_check_q_block2_xmit(coap_session_t *session, coap_tick_t now) {
  coap_lg_xmit_t *lg_xmit;
  coap_lg_xmit_t *q;
  coap_tick_t timed_out;
  coap_tick_t tim_rem = (coap_tick_t)-1;

  LL_FOREACH_SAFE(session->lg_xmit, lg_xmit, q) {
    coap_tick_t non_timeout = lg_xmit->non_timeout_random_ticks;

    if (now < non_timeout)
      return non_timeout - now;
    timed_out = now - non_timeout;

    if (lg_xmit->last_payload) {
      if (lg_xmit->last_payload <= timed_out) {
        /* Send off the next MAX_PAYLOAD set */
        coap_block_b_t block;
        size_t chunk = (size_t)1 << (lg_xmit->blk_size + 4);

        memset(&block, 0, sizeof(block));
        block.num = (uint32_t)(lg_xmit->offset / chunk);
        block.m = lg_xmit->offset + chunk < lg_xmit->length;
        block.szx = lg_xmit->blk_size;
        if (block.num == (uint32_t)lg_xmit->last_block)
          coap_send_q_blocks(session, lg_xmit, block, &lg_xmit->pdu, COAP_SEND_SKIP_PDU);
        if (tim_rem > non_timeout)
          tim_rem = non_timeout;
      } else {
        /* Delay until the next MAX_PAYLOAD needs to be sent off */
        if (tim_rem > lg_xmit->last_payload - timed_out)
          tim_rem = lg_xmit->last_payload - timed_out;
      }
    } else if (lg_xmit->last_all_sent) {
      non_timeout = COAP_NON_TIMEOUT_TICKS(session);
      if (lg_xmit->last_all_sent +  4 * non_timeout <= now) {
        /* Expire this entry */
        LL_DELETE(session->lg_xmit, lg_xmit);
        coap_block_delete_lg_xmit(session, lg_xmit);
      } else {
        /* Delay until the lg_xmit needs to expire */
        if (tim_rem > lg_xmit->last_all_sent + 4 * non_timeout - now)
          tim_rem = lg_xmit->last_all_sent + 4 * non_timeout - now;
      }
    }
  }
  return tim_rem;
}
#endif /* COAP_SERVER_SUPPORT */
#endif /* COAP_Q_BLOCK_SUPPORT */

#if COAP_CLIENT_SUPPORT
/*
 * If Observe = 0, save the token away and return NULL
 * Else If Observe = 1, return the saved token for this block
 * Else, return NULL
 */
static coap_bin_const_t *
track_fetch_observe(coap_pdu_t *pdu, coap_lg_crcv_t *lg_crcv,
                    uint32_t block_num, coap_bin_const_t *token) {
  /* Need to handle Observe for large FETCH */
  coap_opt_iterator_t opt_iter;
  coap_opt_t *opt = coap_check_option(pdu, COAP_OPTION_OBSERVE,
                                      &opt_iter);

  if (opt && lg_crcv) {
    int observe_action = -1;
    coap_bin_const_t **tmp;

    observe_action = coap_decode_var_bytes(coap_opt_value(opt),
                                           coap_opt_length(opt));
    if (observe_action == COAP_OBSERVE_ESTABLISH) {
      /* Save the token in lg_crcv */
      if (lg_crcv->obs_token_cnt <= block_num) {
        size_t i;

        tmp = coap_realloc_type(COAP_STRING, lg_crcv->obs_token,
                                (block_num + 1) * sizeof(lg_crcv->obs_token[0]));
        if (tmp == NULL)
          return NULL;
        lg_crcv->obs_token = tmp;
        for (i = lg_crcv->obs_token_cnt; i < block_num + 1; i++) {
          lg_crcv->obs_token[i] = NULL;
        }
      }
      coap_delete_bin_const(lg_crcv->obs_token[block_num]);

      lg_crcv->obs_token_cnt = block_num + 1;
      lg_crcv->obs_token[block_num] = coap_new_bin_const(token->s,
                                                         token->length);
      if (lg_crcv->obs_token[block_num] == NULL)
        return NULL;
    } else if (observe_action == COAP_OBSERVE_CANCEL) {
      /* Use the token in lg_crcv */
      if (block_num < lg_crcv->obs_token_cnt) {
        return lg_crcv->obs_token[block_num];
      }
    }
  }
  return NULL;
}

#if COAP_Q_BLOCK_SUPPORT
coap_mid_t
coap_send_q_block1(coap_session_t *session,
                   coap_block_b_t block,
                   coap_pdu_t *request,
                   coap_send_pdu_t send_request) {
  /* Need to send up to MAX_PAYLOAD blocks if this is a Q_BLOCK1 */
  coap_lg_xmit_t *lg_xmit;
  uint64_t token_match =
      STATE_TOKEN_BASE(coap_decode_var_bytes8(request->actual_token.s,
                                              request->actual_token.length));

  LL_FOREACH(session->lg_xmit, lg_xmit) {
    if (lg_xmit->option == COAP_OPTION_Q_BLOCK1 &&
        (token_match == STATE_TOKEN_BASE(lg_xmit->b.b1.state_token) ||
         token_match ==
         STATE_TOKEN_BASE(coap_decode_var_bytes8(lg_xmit->b.b1.app_token->s,
                                                 lg_xmit->b.b1.app_token->length))))
      break;
    /* try out the next one */
  }
  return coap_send_q_blocks(session, lg_xmit, block, request, send_request);
}
#endif /* COAP_Q_BLOCK_SUPPORT */
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
#if COAP_Q_BLOCK_SUPPORT
/*
 * response is always released before return IF COAP_SEND_INC_PDU
 */
coap_mid_t
coap_send_q_block2(coap_session_t *session,
                   coap_resource_t *resource,
                   const coap_string_t *query,
                   coap_pdu_code_t request_method,
                   coap_block_b_t block,
                   coap_pdu_t *response,
                   coap_send_pdu_t send_response) {
  /* Need to send up to MAX_PAYLOAD blocks if this is a Q_BLOCK2 */
  coap_lg_xmit_t *lg_xmit;
  coap_string_t empty = { 0, NULL};

  LL_FOREACH(session->lg_xmit, lg_xmit) {
    if (lg_xmit->option == COAP_OPTION_Q_BLOCK2 &&
        resource == lg_xmit->b.b2.resource &&
        request_method == lg_xmit->b.b2.request_method &&
        coap_string_equal(query ? query : &empty,
                          lg_xmit->b.b2.query ? lg_xmit->b.b2.query : &empty))
      break;
  }
  return coap_send_q_blocks(session, lg_xmit, block, response, send_response);
}
#endif /* COAP_Q_BLOCK_SUPPORT */
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
#if COAP_Q_BLOCK_SUPPORT
/*
 * Send out a test PDU for Q-Block.
 */
coap_mid_t
coap_block_test_q_block(coap_session_t *session, coap_pdu_t *actual) {
  coap_pdu_t *pdu;
  uint8_t token[8];
  size_t token_len;
  uint8_t buf[4];
  coap_mid_t mid;

#if NDEBUG
  (void)actual;
#endif /* NDEBUG */
  assert(session->block_mode & COAP_BLOCK_TRY_Q_BLOCK &&
         session->type == COAP_SESSION_TYPE_CLIENT &&
         COAP_PDU_IS_REQUEST(actual));

  coap_log_debug("Testing for Q-Block support\n");
  /* RFC9177 Section 4.1 when checking if available */
  pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET,
                      coap_new_message_id_lkd(session),
                      coap_session_max_pdu_size_lkd(session));
  if (!pdu) {
    return COAP_INVALID_MID;
  }

  coap_session_new_token(session, &token_len, token);
  coap_add_token(pdu, token_len, token);
  /* Use a resource that the server MUST support (.well-known/core) */
  coap_add_option(pdu, COAP_OPTION_URI_PATH,
                  11, (const u_char *)".well-known");
  coap_add_option(pdu, COAP_OPTION_URI_PATH,
                  4, (const u_char *)"core");
  /*
   * M needs to be unset as 'asking' for only the first block using
   * Q-Block2 as a test for server support.
   * See RFC9177 Section 4.4 Using the Q-Block2 Option.
   *
   * As the client is asking for 16 byte chunks, it is unlikely that
   * the .well-known/core response will be 16 bytes or less, so
   * if the server supports Q-Block, it will be forced to respond with
   * a Q-Block2, so the client can detect the server Q-Block support.
   */
  coap_insert_option(pdu, COAP_OPTION_Q_BLOCK2,
                     coap_encode_var_safe(buf, sizeof(buf),
                                          (0 << 4) | (0 << 3) | 0),
                     buf);
  set_block_mode_probe_q(session->block_mode);
  mid = coap_send_internal(session, pdu);
  if (mid == COAP_INVALID_MID)
    return COAP_INVALID_MID;
  session->remote_test_mid = mid;
  return mid;
}
#endif /* COAP_Q_BLOCK_SUPPORT */

coap_lg_crcv_t *
coap_block_new_lg_crcv(coap_session_t *session, coap_pdu_t *pdu,
                       coap_lg_xmit_t *lg_xmit) {
  coap_block_b_t block;
  coap_lg_crcv_t *lg_crcv;
  uint64_t state_token = STATE_TOKEN_FULL(++session->tx_token, 1);
  size_t token_options = pdu->data ? (size_t)(pdu->data - pdu->token) :
                         pdu->used_size;
  size_t data_len = lg_xmit ? lg_xmit->length :
                    pdu->data ?
                    pdu->used_size - (pdu->data - pdu->token) : 0;

  lg_crcv = coap_malloc_type(COAP_LG_CRCV, sizeof(coap_lg_crcv_t));

  if (lg_crcv == NULL)
    return NULL;

  coap_log_debug("** %s: lg_crcv %p initialized - stateless token xxxx%012llx\n",
                 coap_session_str(session), (void *)lg_crcv,
                 STATE_TOKEN_BASE(state_token));
  memset(lg_crcv, 0, sizeof(coap_lg_crcv_t));
  lg_crcv->initial = 1;
  coap_ticks(&lg_crcv->last_used);
  /* Set up skeletal PDU to use as a basis for all the subsequent blocks */
  memcpy(&lg_crcv->pdu, pdu, sizeof(lg_crcv->pdu));
  /* Make sure that there is space for increased token + option change */
  lg_crcv->pdu.max_size = token_options + data_len + 9;
  lg_crcv->pdu.used_size = token_options + data_len;
  lg_crcv->pdu.token = coap_malloc_type(COAP_PDU_BUF,
                                        token_options + data_len + lg_crcv->pdu.max_hdr_size);
  if (!lg_crcv->pdu.token) {
    coap_block_delete_lg_crcv(session, lg_crcv);
    return NULL;
  }
  lg_crcv->pdu.token += lg_crcv->pdu.max_hdr_size;
  memcpy(lg_crcv->pdu.token, pdu->token, token_options);
  if (lg_crcv->pdu.data) {
    lg_crcv->pdu.data = lg_crcv->pdu.token + token_options;
    assert(pdu->data);
    memcpy(lg_crcv->pdu.data, lg_xmit ? lg_xmit->data : pdu->data, data_len);
  }

  /* Need to keep original token for updating response PDUs */
  lg_crcv->app_token = coap_new_binary(pdu->actual_token.length);
  if (!lg_crcv->app_token) {
    coap_block_delete_lg_crcv(session, lg_crcv);
    return NULL;
  }
  memcpy(lg_crcv->app_token->s, pdu->actual_token.s, pdu->actual_token.length);

  /* Need to set up a base token for actual communications if retries needed */
  lg_crcv->retry_counter = 1;
  lg_crcv->state_token = state_token;

  if (pdu->code == COAP_REQUEST_CODE_FETCH) {
    coap_bin_const_t *new_token;

    /* Need to save/restore Observe Token for large FETCH */
    new_token = track_fetch_observe(pdu, lg_crcv, 0, &pdu->actual_token);
    if (new_token)
      coap_update_token(pdu, new_token->length, new_token->s);
  }

  if (coap_get_block_b(session, pdu, COAP_OPTION_BLOCK1, &block)) {
    /* In case it is there - must not be in continuing request PDUs */
    lg_crcv->o_block_option = COAP_OPTION_BLOCK1;
    lg_crcv->o_blk_size = block.aszx;
    coap_remove_option(&lg_crcv->pdu, COAP_OPTION_BLOCK1);
  }

  return lg_crcv;
}

void
coap_block_delete_lg_crcv(coap_session_t *session,
                          coap_lg_crcv_t *lg_crcv) {
  size_t i;

#if (COAP_MAX_LOGGING_LEVEL < _COAP_LOG_DEBUG)
  (void)session;
#endif
  if (lg_crcv == NULL)
    return;

  if (lg_crcv->pdu.token)
    coap_free_type(COAP_PDU_BUF, lg_crcv->pdu.token - lg_crcv->pdu.max_hdr_size);
  coap_free_type(COAP_STRING, lg_crcv->body_data);
  coap_log_debug("** %s: lg_crcv %p released\n",
                 coap_session_str(session), (void *)lg_crcv);
  coap_delete_binary(lg_crcv->app_token);
  for (i = 0; i < lg_crcv->obs_token_cnt; i++) {
    coap_delete_bin_const(lg_crcv->obs_token[i]);
  }
  coap_free_type(COAP_STRING, lg_crcv->obs_token);
  coap_free_type(COAP_LG_CRCV, lg_crcv);
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
void
coap_block_delete_lg_srcv(coap_session_t *session,
                          coap_lg_srcv_t *lg_srcv) {
#if (COAP_MAX_LOGGING_LEVEL < _COAP_LOG_DEBUG)
  (void)session;
#endif
  if (lg_srcv == NULL)
    return;

  coap_delete_str_const(lg_srcv->uri_path);
  coap_delete_bin_const(lg_srcv->last_token);
  coap_free_type(COAP_STRING, lg_srcv->body_data);
  coap_log_debug("** %s: lg_srcv %p released\n",
                 coap_session_str(session), (void *)lg_srcv);
  coap_free_type(COAP_LG_SRCV, lg_srcv);
}
#endif /* COAP_SERVER_SUPPORT */

void
coap_block_delete_lg_xmit(coap_session_t *session,
                          coap_lg_xmit_t *lg_xmit) {
  if (lg_xmit == NULL)
    return;

  if (lg_xmit->release_func) {
    lg_xmit->release_func(session, lg_xmit->app_ptr);
  }
  if (lg_xmit->pdu.token) {
    coap_free_type(COAP_PDU_BUF, lg_xmit->pdu.token - lg_xmit->pdu.max_hdr_size);
  }
  if (COAP_PDU_IS_REQUEST(&lg_xmit->pdu))
    coap_delete_binary(lg_xmit->b.b1.app_token);
  else
    coap_delete_string(lg_xmit->b.b2.query);

  coap_log_debug("** %s: lg_xmit %p released\n",
                 coap_session_str(session), (void *)lg_xmit);
  coap_free_type(COAP_LG_XMIT, lg_xmit);
}

#if COAP_SERVER_SUPPORT
typedef struct {
  uint32_t num;
  int is_continue;
} send_track;

static int
add_block_send(uint32_t num, int is_continue, send_track *out_blocks,
               uint32_t *count, uint32_t max_count) {
  uint32_t i;

  for (i = 0; i < *count && *count < max_count; i++) {
    if (num == out_blocks[i].num)
      return 0;
    else if (num < out_blocks[i].num) {
      if (*count - i > 1)
        memmove(&out_blocks[i], &out_blocks[i+1], *count - i -1);
      out_blocks[i].num = num;
      out_blocks[i].is_continue = is_continue;
      (*count)++;
      return 1;
    }
  }
  if (*count < max_count) {
    out_blocks[i].num = num;
    out_blocks[i].is_continue = is_continue;
    (*count)++;
    return 1;
  }
  return 0;
}

/*
 * Need to see if this is a request for the next block of a large body
 * transfer.  If so, need to initiate the response with the next blocks
 * and not trouble the application.
 *
 * If additional responses needed, then these are expicitly sent out and
 * 'response' is updated to be the last response to be sent.  There can be
 * multiple Q-Block2 in the request, as well as  the 'Continue' Q-Block2
 * request.
 *
 * This is set up using coap_add_data_large_response_lkd()
 *
 * Server is sending a large data response to GET / observe (Block2)
 *
 * Return: 0 Call application handler
 *         1 Do not call application handler - just send the built response
 */
int
coap_handle_request_send_block(coap_session_t *session,
                               coap_pdu_t *pdu,
                               coap_pdu_t *response,
                               coap_resource_t *resource,
                               coap_string_t *query) {
  coap_lg_xmit_t *p = NULL;
  coap_block_b_t block;
  coap_block_b_t alt_block;
  uint16_t block_opt = 0;
  send_track *out_blocks = NULL;
  const char *error_phrase;
  coap_opt_iterator_t opt_iter;
  size_t chunk;
  coap_opt_iterator_t opt_b_iter;
  coap_opt_t *option;
  uint32_t request_cnt, i;
  coap_opt_t *etag_opt = NULL;
  coap_pdu_t *out_pdu = response;
#if COAP_Q_BLOCK_SUPPORT
  size_t max_block;

  /* Is client indicating that it supports Q_BLOCK2 ? */
  if (coap_get_block_b(session, pdu, COAP_OPTION_Q_BLOCK2, &block)) {
    if (!(session->block_mode & COAP_BLOCK_HAS_Q_BLOCK))
      set_block_mode_has_q(session->block_mode);
    block_opt = COAP_OPTION_Q_BLOCK2;
  }
#endif /* COAP_Q_BLOCK_SUPPORT */
  if (coap_get_block_b(session, pdu, COAP_OPTION_BLOCK2, &alt_block)) {
    if (block_opt) {
      coap_log_warn("Block2 and Q-Block2 cannot be in the same request\n");
      coap_add_data(response, sizeof("Both Block2 and Q-Block2 invalid")-1,
                    (const uint8_t *)"Both Block2 and Q-Block2 invalid");
      response->code = COAP_RESPONSE_CODE(400);
      goto skip_app_handler;
    }
    block = alt_block;
    block_opt = COAP_OPTION_BLOCK2;
  }
  if (block_opt == 0)
    return 0;
  if (block.num == 0) {
    /* Get a fresh copy of the data */
    return 0;
  }
  p = coap_find_lg_xmit_response(session, pdu, resource, query);
  if (p == NULL)
    return 0;

#if COAP_Q_BLOCK_SUPPORT
  out_blocks = coap_malloc_type(COAP_STRING, sizeof(send_track) * COAP_MAX_PAYLOADS(session));
#else /* ! COAP_Q_BLOCK_SUPPORT */
  out_blocks = coap_malloc_type(COAP_STRING, sizeof(send_track));
#endif /* ! COAP_Q_BLOCK_SUPPORT */
  if (!out_blocks) {
    goto internal_issue;
  }

  /* lg_xmit (response) found */

  etag_opt = coap_check_option(pdu, COAP_OPTION_ETAG, &opt_iter);
  if (etag_opt) {
    uint64_t etag = coap_decode_var_bytes8(coap_opt_value(etag_opt),
                                           coap_opt_length(etag_opt));
    if (etag != p->b.b2.etag) {
      /* Not a match - pass up to a higher level */
      return 0;
    }
    out_pdu->code = COAP_RESPONSE_CODE(203);
    coap_ticks(&p->last_sent);
    goto skip_app_handler;
  } else {
    out_pdu->code = p->pdu.code;
  }
  coap_ticks(&p->last_obs);
  p->last_all_sent = 0;

  chunk = (size_t)1 << (p->blk_size + 4);
  if (block_opt) {
    if (block.bert) {
      coap_log_debug("found Block option, block is BERT, block nr. %u, M %d\n",
                     block.num, block.m);
    } else {
      coap_log_debug("found Block option, block size is %u, block nr. %u, M %d\n",
                     1 << (block.szx + 4), block.num, block.m);
    }
    if (block.bert == 0 && block.szx != p->blk_size) {
      if (block.num == 0) {
        if ((p->offset + chunk) % ((size_t)1 << (block.szx + 4)) == 0) {
          /*
           * Recompute the block number of the previous packet given
           * the new block size
           */
          block.num = (uint32_t)(((p->offset + chunk) >> (block.szx + 4)) - 1);
          p->blk_size = block.szx;
          chunk = (size_t)1 << (p->blk_size + 4);
          p->offset = block.num * chunk;
          coap_log_debug("new Block size is %u, block number %u completed\n",
                         1 << (block.szx + 4), block.num);
        } else {
          coap_log_debug("ignoring request to increase Block size, "
                         "next block is not aligned on requested block size "
                         "boundary. (%zu x %u mod %u = %zu (which is not 0)\n",
                         p->offset/chunk + 1, (1 << (p->blk_size + 4)),
                         (1 << (block.szx + 4)),
                         (p->offset + chunk) % ((size_t)1 << (block.szx + 4)));
        }
      } else {
        coap_log_debug("ignoring request to change Block size from %u to %u\n",
                       (1 << (p->blk_size + 4)), (1 << (block.szx + 4)));
        block.szx = block.aszx = p->blk_size;
      }
    }
  }

  /*
   * Need to check if there are multiple Q-Block2 requests.  If so, they
   * need to be sent out in order of requests with the final request being
   * handled as per singular Block 2 request.
   */
  request_cnt = 0;
#if COAP_Q_BLOCK_SUPPORT
  max_block = (p->length + chunk - 1)/chunk;
#endif /* COAP_Q_BLOCK_SUPPORT */
  coap_option_iterator_init(pdu, &opt_b_iter, COAP_OPT_ALL);
  while ((option = coap_option_next(&opt_b_iter))) {
    uint32_t num;
    if (opt_b_iter.number != p->option)
      continue;
    num = coap_opt_block_num(option);
    if (num > 0xFFFFF) /* 20 bits max for num */
      continue;
    if (block.aszx != COAP_OPT_BLOCK_SZX(option)) {
      coap_add_data(response,
                    sizeof("Changing blocksize during request invalid")-1,
                    (const uint8_t *)"Changing blocksize during request invalid");
      response->code = COAP_RESPONSE_CODE(400);
      goto skip_app_handler;
    }
#if COAP_Q_BLOCK_SUPPORT
    if (COAP_OPT_BLOCK_MORE(option) && p->option == COAP_OPTION_Q_BLOCK2) {
      if ((num % COAP_MAX_PAYLOADS(session)) == 0) {
        if (num == 0) {
          /* This is a repeat request for everything - hmm */
          goto call_app_handler;
        }
        /* 'Continue' request */
        for (i = 0; i < COAP_MAX_PAYLOADS(session) &&
             num + i < max_block; i++) {
          add_block_send(num + i, 1, out_blocks, &request_cnt,
                         COAP_MAX_PAYLOADS(session));
          p->last_block = num + i;
        }
      } else {
        /* Requesting remaining payloads in this MAX_PAYLOADS */
        for (i = 0; i < COAP_MAX_PAYLOADS(session) -
             num % COAP_MAX_PAYLOADS(session) &&
             num + i < max_block; i++) {
          add_block_send(num + i, 0, out_blocks, &request_cnt,
                         COAP_MAX_PAYLOADS(session));
        }
      }
    } else
      add_block_send(num, 0, out_blocks, &request_cnt,
                     COAP_MAX_PAYLOADS(session));
#else /* ! COAP_Q_BLOCK_SUPPORT */
    add_block_send(num, 0, out_blocks, &request_cnt, 1);
    break;
#endif /* ! COAP_Q_BLOCK_SUPPORT */
  }
  if (request_cnt == 0) {
    /* Block2 or Q-Block2 not found - give them the first block */
    block.szx = p->blk_size;
    p->offset = 0;
    out_blocks[0].num = 0;
    out_blocks[0].is_continue = 0;
    request_cnt = 1;
  }

  for (i = 0; i < request_cnt; i++) {
    uint8_t buf[8];

    block.num = out_blocks[i].num;
    p->offset = block.num * chunk;

    if (i + 1 < request_cnt) {
      /* Need to set up a copy of the pdu to send */
      coap_opt_filter_t drop_options;

      memset(&drop_options, 0, sizeof(coap_opt_filter_t));
      if (block.num != 0)
        coap_option_filter_set(&drop_options, COAP_OPTION_OBSERVE);
      if (out_blocks[i].is_continue) {
        out_pdu = coap_pdu_duplicate_lkd(&p->pdu, session, p->pdu.actual_token.length,
                                         p->pdu.actual_token.s, &drop_options);
      } else {
        out_pdu = coap_pdu_duplicate_lkd(&p->pdu, session, pdu->actual_token.length,
                                         pdu->actual_token.s, &drop_options);
      }
      if (!out_pdu) {
        goto internal_issue;
      }
    } else {
      if (out_blocks[i].is_continue)
        coap_update_token(response, p->pdu.actual_token.length,
                          p->pdu.actual_token.s);
      /*
       * Copy the options across and then fix the block option
       *
       * Need to drop Observe option if Block2 and block.num != 0
       */
      coap_option_iterator_init(&p->pdu, &opt_iter, COAP_OPT_ALL);
      while ((option = coap_option_next(&opt_iter))) {
        if (opt_iter.number == COAP_OPTION_OBSERVE && block.num != 0)
          continue;
        if (!coap_insert_option(response, opt_iter.number,
                                coap_opt_length(option),
                                coap_opt_value(option))) {
          goto internal_issue;
        }
      }
      out_pdu = response;
    }
    if (pdu->type == COAP_MESSAGE_NON)
      out_pdu->type = COAP_MESSAGE_NON;
    if (block.bert) {
      size_t token_options = pdu->data ? (size_t)(pdu->data - pdu->token) : pdu->used_size;
      block.m = (p->length - p->offset) >
                ((out_pdu->max_size - token_options) /1024) * 1024;
    } else {
      block.m = (p->offset + chunk) < p->length;
    }
    if (!coap_update_option(out_pdu, p->option,
                            coap_encode_var_safe(buf,
                                                 sizeof(buf),
                                                 (block.num << 4) |
                                                 (block.m << 3) |
                                                 block.aszx),
                            buf)) {
      goto internal_issue;
    }
    if (!(p->offset + chunk < p->length)) {
      /* Last block - keep in cache for 4 * ACK_TIMOUT */
      coap_ticks(&p->last_all_sent);
    }
    if (p->b.b2.maxage_expire) {
      coap_tick_t now;
      coap_time_t rem;

      if (!(p->offset + chunk < p->length)) {
        /* Last block - keep in cache for 4 * ACK_TIMOUT */
        coap_ticks(&p->last_all_sent);
      }
      coap_ticks(&now);
      rem = coap_ticks_to_rt(now);
      if (p->b.b2.maxage_expire > rem) {
        rem = p->b.b2.maxage_expire - rem;
      } else {
        rem = 0;
        /* Entry needs to be expired */
        coap_ticks(&p->last_all_sent);
      }
      if (!coap_update_option(out_pdu, COAP_OPTION_MAXAGE,
                              coap_encode_var_safe8(buf,
                                                    sizeof(buf),
                                                    rem),
                              buf)) {
        goto internal_issue;
      }
    }

    if (!etag_opt && !coap_add_block_b_data(out_pdu,
                                            p->length,
                                            p->data,
                                            &block)) {
      goto internal_issue;
    }
    if (i + 1 < request_cnt) {
      coap_ticks(&p->last_sent);
      coap_send_internal(session, out_pdu);
    }
  }
  coap_ticks(&p->last_payload);
  goto skip_app_handler;
#if COAP_Q_BLOCK_SUPPORT
call_app_handler:
  coap_free_type(COAP_STRING, out_blocks);
  return 0;
#endif /* COAP_Q_BLOCK_SUPPORT */

internal_issue:
  response->code = COAP_RESPONSE_CODE(500);
  error_phrase = coap_response_phrase(response->code);
  coap_add_data(response, strlen(error_phrase),
                (const uint8_t *)error_phrase);
  /* Keep in cache for 4 * ACK_TIMOUT incase of retry */
  if (p)
    coap_ticks(&p->last_all_sent);

skip_app_handler:
  coap_free_type(COAP_STRING, out_blocks);
  return 1;
}
#endif /* COAP_SERVER_SUPPORT */

static int
update_received_blocks(coap_rblock_t *rec_blocks, uint32_t block_num) {
  uint32_t i;

  /* Reset as there is activity */
  rec_blocks->retry = 0;

  for (i = 0; i < rec_blocks->used; i++) {
    if (block_num >= rec_blocks->range[i].begin &&
        block_num <= rec_blocks->range[i].end)
      break;

    if (block_num < rec_blocks->range[i].begin) {
      if (block_num + 1 == rec_blocks->range[i].begin) {
        rec_blocks->range[i].begin = block_num;
      } else {
        /* Need to insert a new range */
        if (rec_blocks->used == COAP_RBLOCK_CNT -1)
          /* Too many losses */
          return 0;
        memmove(&rec_blocks->range[i+1], &rec_blocks->range[i],
                (rec_blocks->used - i) * sizeof(rec_blocks->range[0]));
        rec_blocks->range[i].begin = rec_blocks->range[i].end = block_num;
        rec_blocks->used++;
      }
      break;
    }
    if (block_num == rec_blocks->range[i].end + 1) {
      rec_blocks->range[i].end = block_num;
      if (i + 1 < rec_blocks->used) {
        if (rec_blocks->range[i+1].begin == block_num + 1) {
          /* Merge the 2 ranges */
          rec_blocks->range[i].end = rec_blocks->range[i+1].end;
          if (i+2 < rec_blocks->used) {
            memmove(&rec_blocks->range[i+1], &rec_blocks->range[i+2],
                    (rec_blocks->used - (i+2)) * sizeof(rec_blocks->range[0]));
          }
          rec_blocks->used--;
        }
      }
      break;
    }
  }
  if (i == rec_blocks->used) {
    if (rec_blocks->used == COAP_RBLOCK_CNT -1)
      /* Too many losses */
      return 0;
    rec_blocks->range[i].begin = rec_blocks->range[i].end = block_num;
    rec_blocks->used++;
  }
  coap_ticks(&rec_blocks->last_seen);
  return 1;
}

#if COAP_SERVER_SUPPORT
/*
 * Need to check if this is a large PUT / POST etc. using multiple blocks
 *
 * Server receiving PUT/POST etc. of a large amount of data (Block1)
 *
 * Return: 0 Call application handler
 *         1 Do not call application handler - just send the built response
 */
int
coap_handle_request_put_block(coap_context_t *context,
                              coap_session_t *session,
                              coap_pdu_t *pdu,
                              coap_pdu_t *response,
                              coap_resource_t *resource,
                              coap_string_t *uri_path,
                              coap_opt_t *observe,
                              int *added_block,
                              coap_lg_srcv_t **pfree_lg_srcv) {
  size_t length = 0;
  const uint8_t *data = NULL;
  size_t offset = 0;
  size_t total = 0;
  coap_block_b_t block;
  coap_opt_iterator_t opt_iter;
  uint16_t block_option = 0;
  coap_lg_srcv_t *p;
  coap_opt_t *size_opt;
  coap_opt_t *fmt_opt;
  uint16_t fmt;
  coap_opt_t *rtag_opt;
  size_t rtag_length;
  const uint8_t *rtag;
  uint32_t max_block_szx;
  size_t chunk;
  int update_data;
  unsigned int saved_num;
  size_t saved_offset;

  *added_block = 0;
  *pfree_lg_srcv = NULL;
  coap_get_data_large(pdu, &length, &data, &offset, &total);
  pdu->body_offset = 0;
  pdu->body_total = length;

  if (coap_get_block_b(session, pdu, COAP_OPTION_BLOCK1, &block)) {
    block_option = COAP_OPTION_BLOCK1;
#if COAP_Q_BLOCK_SUPPORT
    if (coap_check_option(pdu, COAP_OPTION_Q_BLOCK1, &opt_iter)) {
      /* Cannot handle Q-Block1 as well */
      coap_add_data(response, sizeof("Block1 + Q-Block1 together")-1,
                    (const uint8_t *)"Block1 + Q-Block1 together");
      response->code = COAP_RESPONSE_CODE(402);
      goto skip_app_handler;
    }
#endif /* COAP_Q_BLOCK_SUPPORT */
  }
#if COAP_Q_BLOCK_SUPPORT
  else if (coap_get_block_b(session, pdu, COAP_OPTION_Q_BLOCK1, &block)) {
    block_option = COAP_OPTION_Q_BLOCK1;
    set_block_mode_has_q(session->block_mode);
  }
#endif /* COAP_Q_BLOCK_SUPPORT */
  if (!block_option ||
      (block_option == COAP_OPTION_BLOCK1 && block.num == 0 && block.m == 0)) {
    /* Not blocked, or a single block */
    goto call_app_handler;
  }

  size_opt = coap_check_option(pdu,
                               COAP_OPTION_SIZE1,
                               &opt_iter);
  fmt_opt = coap_check_option(pdu,
                              COAP_OPTION_CONTENT_FORMAT,
                              &opt_iter);
  fmt = fmt_opt ? coap_decode_var_bytes(coap_opt_value(fmt_opt),
                                        coap_opt_length(fmt_opt)) :
        COAP_MEDIATYPE_TEXT_PLAIN;
  rtag_opt = coap_check_option(pdu,
                               COAP_OPTION_RTAG,
                               &opt_iter);
  rtag_length = rtag_opt ? coap_opt_length(rtag_opt) : 0;
  rtag = rtag_opt ? coap_opt_value(rtag_opt) : NULL;

  if (length > block.chunk_size) {
    coap_log_debug("block: Oversized packet - reduced to %"PRIu32" from %zu\n",
                   block.chunk_size, length);
    length = block.chunk_size;
  } else if (!block.bert && block.m && length != block.chunk_size) {
    coap_log_info("block: Undersized packet chunk %"PRIu32" got %zu\n",
                  block.chunk_size, length);
    response->code = COAP_RESPONSE_CODE(400);
    goto skip_app_handler;
  }
  total = size_opt ? coap_decode_var_bytes(coap_opt_value(size_opt),
                                           coap_opt_length(size_opt)) : 0;
  offset = block.num << (block.szx + 4);

  if (!(session->block_mode &
#if COAP_Q_BLOCK_SUPPORT
        (COAP_BLOCK_SINGLE_BODY|COAP_BLOCK_HAS_Q_BLOCK|COAP_BLOCK_NOT_RANDOM_BLOCK1))
#else /* COAP_Q_BLOCK_SUPPORT */
        (COAP_BLOCK_SINGLE_BODY|COAP_BLOCK_NOT_RANDOM_BLOCK1))
#endif /* COAP_Q_BLOCK_SUPPORT */
      && !block.bert) {
    uint8_t buf[4];

    /* Ask for the next block */
    coap_insert_option(response, block_option,
                       coap_encode_var_safe(buf, sizeof(buf),
                                            (block.num << 4) |
                                            (block.m << 3) |
                                            block.aszx),
                       buf);
    /* Not re-assembling or checking for receipt order */
    pdu->body_data = data;
    pdu->body_length = length;
    pdu->body_offset = offset;
    if (total < (length + offset + (block.m ? 1 : 0)))
      total = length + offset + (block.m ? 1 : 0);
    pdu->body_total = total;
    *added_block = block.m;
    /* The application is responsible for returning the correct 2.01/2.04/2.31 etc. */
    goto call_app_handler;
  }

  /*
   * locate the lg_srcv
   */
  LL_FOREACH(session->lg_srcv, p) {
    if (rtag_opt || p->rtag_set == 1) {
      if (!(rtag_opt && p->rtag_set == 1))
        continue;
      if (p->rtag_length != rtag_length ||
          memcmp(p->rtag, rtag, rtag_length) != 0)
        continue;
    }
    if (resource == p->resource) {
      break;
    }
    if ((p->resource == context->unknown_resource ||
         resource == context->proxy_uri_resource) &&
        coap_string_equal(uri_path, p->uri_path))
      break;
  }

  if (!p && block.num != 0 && session->block_mode & COAP_BLOCK_NOT_RANDOM_BLOCK1) {
    coap_add_data(response, sizeof("Missing block 0")-1,
                  (const uint8_t *)"Missing block 0");
    response->code = COAP_RESPONSE_CODE(408);
    goto skip_app_handler;
  }

  if (!p) {
    /* Allocate lg_srcv to use for tracking */
    p = coap_malloc_type(COAP_LG_SRCV, sizeof(coap_lg_srcv_t));
    if (p == NULL) {
      coap_add_data(response, sizeof("Memory issue")-1,
                    (const uint8_t *)"Memory issue");
      response->code = COAP_RESPONSE_CODE(500);
      goto skip_app_handler;
    }
    coap_log_debug("** %s: lg_srcv %p initialized\n",
                   coap_session_str(session), (void *)p);
    memset(p, 0, sizeof(coap_lg_srcv_t));
    coap_ticks(&p->last_used);
    p->resource = resource;
    if (resource == context->unknown_resource ||
        resource == context->proxy_uri_resource)
      p->uri_path = coap_new_str_const(uri_path->s, uri_path->length);
    p->content_format = fmt;
    p->total_len = total;
    max_block_szx = COAP_BLOCK_MAX_SIZE_GET(session->block_mode);
    if (!block.bert && block.num == 0 && max_block_szx != 0 &&
        max_block_szx < block.szx) {
      p->szx = max_block_szx;
    } else {
      p->szx = block.szx;
    }
    p->block_option = block_option;
    if (observe) {
      p->observe_length = min(coap_opt_length(observe), 3);
      memcpy(p->observe, coap_opt_value(observe), p->observe_length);
      p->observe_set = 1;
    }
    if (rtag_opt) {
      p->rtag_length = coap_opt_length(rtag_opt);
      memcpy(p->rtag, coap_opt_value(rtag_opt), p->rtag_length);
      p->rtag_set = 1;
    }
    p->body_data = NULL;
    LL_PREPEND(session->lg_srcv, p);
  }

  if (block_option == COAP_OPTION_BLOCK1 &&
      session->block_mode & COAP_BLOCK_NOT_RANDOM_BLOCK1 &&
      !check_if_next_block(&p->rec_blocks, block.num)) {
    coap_add_data(response, sizeof("Missing interim block")-1,
                  (const uint8_t *)"Missing interim block");
    response->code = COAP_RESPONSE_CODE(408);
    goto skip_app_handler;
  }

  if (fmt != p->content_format) {
    coap_add_data(response, sizeof("Content-Format mismatch")-1,
                  (const uint8_t *)"Content-Format mismatch");
    response->code = COAP_RESPONSE_CODE(408);
    goto free_lg_srcv;
  }

#if COAP_Q_BLOCK_SUPPORT
  if (block_option == COAP_OPTION_Q_BLOCK1) {
    if (total != p->total_len) {
      coap_add_data(response, sizeof("Size1 mismatch")-1,
                    (const uint8_t *)"Size1 mismatch");
      response->code = COAP_RESPONSE_CODE(408);
      goto free_lg_srcv;
    }
    coap_delete_bin_const(p->last_token);
    p->last_token = coap_new_bin_const(pdu->actual_token.s,
                                       pdu->actual_token.length);
  }
#endif /* COAP_Q_BLOCK_SUPPORT */

  p->last_mid = pdu->mid;
  p->last_type = pdu->type;

  chunk = (size_t)1 << (block.szx + 4);
  update_data = 0;
  saved_num = block.num;
  saved_offset = offset;

  while (offset < saved_offset + length) {
    if (!check_if_received_block(&p->rec_blocks, block.num)) {
      /* Update list of blocks received */
      if (!update_received_blocks(&p->rec_blocks, block.num)) {
        coap_handle_event_lkd(context, COAP_EVENT_PARTIAL_BLOCK, session);
        coap_add_data(response, sizeof("Too many missing blocks")-1,
                      (const uint8_t *)"Too many missing blocks");
        response->code = COAP_RESPONSE_CODE(408);
        goto free_lg_srcv;
      }
      update_data = 1;
    }
    block.num++;
    offset = block.num << (block.szx + 4);
  }
  block.num--;

  if (update_data) {
    /* Update saved data */
#if COAP_Q_BLOCK_SUPPORT
    p->rec_blocks.processing_payload_set =
        block.num / COAP_MAX_PAYLOADS(session);
#endif /* COAP_Q_BLOCK_SUPPORT */
    if (p->total_len < saved_offset + length) {
      p->total_len = saved_offset + length;
    }
    p->body_data = coap_block_build_body(p->body_data, length, data,
                                         saved_offset, p->total_len);
    if (!p->body_data) {
      coap_add_data(response, sizeof("Memory issue")-1,
                    (const uint8_t *)"Memory issue");
      response->code = COAP_RESPONSE_CODE(500);
      goto skip_app_handler;
    }
  }

  if (block.m ||
      !check_all_blocks_in(&p->rec_blocks,
                           (uint32_t)(p->total_len + chunk -1)/chunk)) {
    /* Not all the payloads of the body have arrived */
    if (block.m) {
      uint8_t buf[4];

#if COAP_Q_BLOCK_SUPPORT
      if (block_option == COAP_OPTION_Q_BLOCK1) {
        if (check_all_blocks_in(&p->rec_blocks,
                                (uint32_t)(p->total_len + chunk -1)/chunk)) {
          goto give_app_data;
        }
        if (p->rec_blocks.used == 1 &&
            (p->rec_blocks.range[0].end % COAP_MAX_PAYLOADS(session)) + 1
            == COAP_MAX_PAYLOADS(session)) {
          /* Blocks could arrive in wrong order */
          block.num = p->rec_blocks.range[0].end;
        } else {
          /* The remote end will be sending the next one unless this
             is a MAX_PAYLOADS and all previous have been received */
          goto skip_app_handler;
        }
        if (COAP_PROTO_RELIABLE(session->proto) ||
            pdu->type != COAP_MESSAGE_NON)
          goto skip_app_handler;
      }
#endif /* COAP_Q_BLOCK_SUPPORT */

      /* Check to see if block size is getting forced down */
      max_block_szx = COAP_BLOCK_MAX_SIZE_GET(session->block_mode);
      if (!block.bert && saved_num == 0 && max_block_szx != 0 &&
          max_block_szx < block.aszx) {
        block.aszx = max_block_szx;
      }

      /*
       * If the last block has been seen, packets are coming in in
       * random order.  If all blocks are now in, then need to send
       * complete payload to application and acknowledge this current
       * block.
       */
      if (!check_all_blocks_in(&p->rec_blocks,
                               (uint32_t)(p->total_len + chunk -1)/chunk)) {
        /* Ask for the next block */
        coap_insert_option(response, block_option,
                           coap_encode_var_safe(buf, sizeof(buf),
                                                (saved_num << 4) |
                                                (block.m << 3) |
                                                block.aszx),
                           buf);
        response->code = COAP_RESPONSE_CODE(231);
      } else {
        /* Need to separately respond to this request */
        coap_pdu_t *tmp_pdu = coap_pdu_duplicate_lkd(response,
                                                     session,
                                                     response->actual_token.length,
                                                     response->actual_token.s,
                                                     NULL);
        if (tmp_pdu) {
          tmp_pdu->code = COAP_RESPONSE_CODE(231);
          coap_send_internal(session, tmp_pdu);
        }
        coap_update_token(response, p->last_token->length, p->last_token->s);
        coap_update_token(pdu, p->last_token->length, p->last_token->s);
        /* Pass the assembled pdu and body to the application */
        goto give_app_data;
      }
    } else {
      /* block.m Block More option not set.  Some outstanding blocks */
#if COAP_Q_BLOCK_SUPPORT
      if (block_option != COAP_OPTION_Q_BLOCK1) {
#endif /* COAP_Q_BLOCK_SUPPORT */
        /* Last chunk - but not all in */
        coap_ticks(&p->last_used);
        p->no_more_seen = 1;
        coap_delete_bin_const(p->last_token);
        p->last_token = coap_new_bin_const(pdu->actual_token.s,
                                           pdu->actual_token.length);

        /*
         * Need to just ACK (no response code) to handle client's NSTART.
         * When final missing block comes in, we will pass all the data
         * for processing so a 2.01, 2.04 etc. code can be generated
         * and responded to as a separate response "RFC7252 5.2.2. Separate"
         * If missing block(s) do not come in, then will generate a 4.08
         * when lg_srcv times out.
         * Fall through to skip_app_handler.
         */
#if COAP_Q_BLOCK_SUPPORT
      }
#endif /* COAP_Q_BLOCK_SUPPORT */
    }
    goto skip_app_handler;
  }

  /*
   * Entire payload received.
   * Remove the Block1 option as passing all of the data to
   * application layer. Add back in observe option if appropriate.
   * Adjust all other information.
   */
give_app_data:
  if (p->observe_set) {
    coap_update_option(pdu, COAP_OPTION_OBSERVE,
                       p->observe_length, p->observe);
  }
  coap_remove_option(pdu, block_option);
  pdu->body_data = p->body_data->s;
  pdu->body_length = p->total_len;
  pdu->body_offset = 0;
  pdu->body_total = p->total_len;
  coap_log_debug("Server app version of updated PDU\n");
  coap_show_pdu(COAP_LOG_DEBUG, pdu);
  *pfree_lg_srcv = p;

call_app_handler:
  return 0;

free_lg_srcv:
  LL_DELETE(session->lg_srcv, p);
  coap_block_delete_lg_srcv(session, p);

skip_app_handler:
  return 1;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
#if COAP_Q_BLOCK_SUPPORT
static uint32_t
derive_cbor_value(const uint8_t **bp, size_t rem_len) {
  uint32_t value = **bp & 0x1f;
  (*bp)++;
  if (value < 24) {
    return value;
  } else if (value == 24) {
    if (rem_len < 2)
      return (uint32_t)-1;
    value = **bp;
    (*bp)++;
    return value;
  } else if (value == 25) {
    if (rem_len < 3)
      return (uint32_t)-1;
    value = **bp << 8;
    (*bp)++;
    value |= **bp;
    (*bp)++;
    return value;
  }
  if (rem_len < 4)
    return (uint32_t)-1;
  value = **bp << 24;
  (*bp)++;
  value |= **bp << 16;
  (*bp)++;
  value |= **bp << 8;
  (*bp)++;
  value |= **bp;
  (*bp)++;
  return value;
}
#endif /* COAP_Q_BLOCK_SUPPORT */

static int
check_freshness(coap_session_t *session, coap_pdu_t *rcvd, coap_pdu_t *sent,
                coap_lg_xmit_t *lg_xmit, coap_lg_crcv_t *lg_crcv) {
  /* Check for Echo option for freshness */
  coap_opt_iterator_t opt_iter;
  coap_opt_t *opt = coap_check_option(rcvd, COAP_OPTION_ECHO, &opt_iter);

  if (opt) {
    if (sent || lg_xmit || lg_crcv) {
      /* Need to retransmit original request with Echo option added */
      coap_pdu_t *echo_pdu;
      coap_mid_t mid;
      const uint8_t *data;
      size_t data_len;
      int have_data = 0;
      uint8_t ltoken[8];
      size_t ltoken_len;
      uint64_t token;

      if (sent) {
        if (coap_get_data(sent, &data_len, &data))
          have_data = 1;
      } else if (lg_xmit) {
        sent = &lg_xmit->pdu;
        if (lg_xmit->length) {
          size_t blk_size = (size_t)1 << (lg_xmit->blk_size + 4);
          size_t offset = (lg_xmit->last_block + 1) * blk_size;
          have_data = 1;
          data = &lg_xmit->data[offset];
          data_len = (lg_xmit->length - offset) > blk_size ? blk_size :
                     lg_xmit->length - offset;
        }
      } else { /* lg_crcv */
        sent = &lg_crcv->pdu;
        if (coap_get_data(sent, &data_len, &data))
          have_data = 1;
      }
      if (lg_xmit) {
        token = STATE_TOKEN_FULL(lg_xmit->b.b1.state_token,
                                 ++lg_xmit->b.b1.count);
      } else {
        token = STATE_TOKEN_FULL(lg_crcv->state_token,
                                 ++lg_crcv->retry_counter);
      }
      ltoken_len = coap_encode_var_safe8(ltoken, sizeof(token), token);
      echo_pdu = coap_pdu_duplicate_lkd(sent, session, ltoken_len, ltoken, NULL);
      if (!echo_pdu)
        return 0;
      if (!coap_insert_option(echo_pdu, COAP_OPTION_ECHO,
                              coap_opt_length(opt), coap_opt_value(opt)))
        goto not_sent;
      if (have_data) {
        coap_add_data(echo_pdu, data_len, data);
      }
      /* Need to track Observe token change if Observe */
      track_fetch_observe(echo_pdu, lg_crcv, 0, &echo_pdu->actual_token);
#if COAP_OSCORE_SUPPORT
      if (session->oscore_encryption &&
          (opt = coap_check_option(echo_pdu, COAP_OPTION_OBSERVE, &opt_iter)) &&
          coap_decode_var_bytes(coap_opt_value(opt), coap_opt_length(opt) == 0)) {
        /* Need to update the base PDU's Token for closing down Observe */
        if (lg_xmit) {
          lg_xmit->b.b1.state_token = token;
        } else {
          lg_crcv->state_token = token;
        }
      }
#endif /* COAP_OSCORE_SUPPORT */
      mid = coap_send_internal(session, echo_pdu);
      if (mid == COAP_INVALID_MID)
        goto not_sent;
      return 1;
    } else {
      /* Need to save Echo option value to add to next reansmission */
not_sent:
      coap_delete_bin_const(session->echo);
      session->echo = coap_new_bin_const(coap_opt_value(opt),
                                         coap_opt_length(opt));
    }
  }
  return 0;
}

static void
track_echo(coap_session_t *session, coap_pdu_t *rcvd) {
  coap_opt_iterator_t opt_iter;
  coap_opt_t *opt = coap_check_option(rcvd, COAP_OPTION_ECHO, &opt_iter);

  if (opt) {
    coap_delete_bin_const(session->echo);
    session->echo = coap_new_bin_const(coap_opt_value(opt),
                                       coap_opt_length(opt));
  }
}

/*
 * Need to see if this is a response to a large body request transfer. If so,
 * need to initiate the request containing the next block and not trouble the
 * application.  Note that Token must unique per request/response.
 *
 * Client receives large data acknowledgement from server (Block1)
 *
 * This is set up using coap_add_data_large_request_lkd()
 *
 * Client is using GET etc.
 *
 * Return: 0 Call application handler
 *         1 Do not call application handler - just send the built response
 */
int
coap_handle_response_send_block(coap_session_t *session, coap_pdu_t *sent,
                                coap_pdu_t *rcvd) {
  coap_lg_xmit_t *p;
  coap_lg_xmit_t *q;
  uint64_t token_match =
      STATE_TOKEN_BASE(coap_decode_var_bytes8(rcvd->actual_token.s,
                                              rcvd->actual_token.length));
  coap_lg_crcv_t *lg_crcv = NULL;

  LL_FOREACH_SAFE(session->lg_xmit, p, q) {
    if (!COAP_PDU_IS_REQUEST(&p->pdu) ||
        (token_match != STATE_TOKEN_BASE(p->b.b1.state_token) &&
         token_match !=
         STATE_TOKEN_BASE(coap_decode_var_bytes8(p->b.b1.app_token->s,
                                                 p->b.b1.app_token->length)))) {
      /* try out the next one */
      continue;
    }
    /* lg_xmit found */
    size_t chunk = (size_t)1 << (p->blk_size + 4);
    coap_block_b_t block;

    if (COAP_RESPONSE_CLASS(rcvd->code) == 2 &&
        coap_get_block_b(session, rcvd, p->option, &block)) {

      if (block.bert) {
        coap_log_debug("found Block option, block is BERT, block nr. %u (%zu)\n",
                       block.num, p->b.b1.bert_size);
      } else {
        coap_log_debug("found Block option, block size is %u, block nr. %u\n",
                       1 << (block.szx + 4), block.num);
      }
      if (block.szx != p->blk_size) {
        if (block.szx > p->blk_size) {
          coap_log_info("ignoring request to increase Block size, "
                        "(%u > %u)\n",
                        1 << (block.szx + 4), 1 << (p->blk_size + 4));
        } else if ((p->offset + chunk) % ((size_t)1 << (block.szx + 4)) == 0) {
          /*
           * Recompute the block number of the previous packet given the
           * new block size
           */
          block.num = (uint32_t)(((p->offset + chunk) >> (block.szx + 4)) - 1);
          p->blk_size = block.szx;
          chunk = (size_t)1 << (p->blk_size + 4);
          p->offset = block.num * chunk;
          coap_log_debug("new Block size is %u, block number %u completed\n",
                         1 << (block.szx + 4), block.num);
          block.bert = 0;
          block.aszx = block.szx;
        } else {
          coap_log_debug("ignoring request to increase Block size, "
                         "next block is not aligned on requested block size boundary. "
                         "(%zu x %u mod %u = %zu != 0)\n",
                         p->offset/chunk + 1, (1 << (p->blk_size + 4)),
                         (1 << (block.szx + 4)),
                         (p->offset + chunk) % ((size_t)1 << (block.szx + 4)));
        }
      }
      track_echo(session, rcvd);
      if (p->last_block == (int)block.num &&
          p->option != COAP_OPTION_Q_BLOCK1) {
        /*
         * Duplicate Block1 ACK
         *
         * RFCs not clear here, but on a lossy connection, there could
         * be multiple Block1 ACKs, causing the client to retransmit the
         * same block multiple times, or the server retransmitting the
         * same ACK.
         *
         * Once a block has been ACKd, there is no need to retransmit it.
         */
        return 1;
      }
      if (block.bert)
        block.num += (unsigned int)(p->b.b1.bert_size / 1024 - 1);
      p->last_block = block.num;
      p->offset = (block.num + 1) * chunk;
      if (p->offset < p->length) {
        /* Build the next PDU request based off the skeletal PDU */
        uint8_t buf[8];
        coap_pdu_t *pdu;
        uint64_t token = STATE_TOKEN_FULL(p->b.b1.state_token, ++p->b.b1.count);
        size_t len = coap_encode_var_safe8(buf, sizeof(token), token);

        if (p->pdu.code == COAP_REQUEST_CODE_FETCH) {
          /* Need to handle Observe for large FETCH */
          LL_FOREACH(session->lg_crcv, lg_crcv) {
            if (coap_binary_equal(p->b.b1.app_token, lg_crcv->app_token)) {
              coap_bin_const_t *new_token;
              coap_bin_const_t ctoken = { len, buf };

              /* Need to save/restore Observe Token for large FETCH */
              new_token = track_fetch_observe(&p->pdu, lg_crcv, block.num + 1,
                                              &ctoken);
              if (new_token) {
                assert(len <= sizeof(buf));
                len = new_token->length;
                memcpy(buf, new_token->s, len);
              }
              break;
            }
          }
        }
        pdu = coap_pdu_duplicate_lkd(&p->pdu, session, len, buf, NULL);
        if (!pdu)
          goto fail_body;

        block.num++;
        if (block.bert) {
          size_t token_options = pdu->data ? (size_t)(pdu->data - pdu->token) :
                                 pdu->used_size;
          block.m = (p->length - p->offset) >
                    ((pdu->max_size - token_options) /1024) * 1024;
        } else {
          block.m = (p->offset + chunk) < p->length;
        }
        coap_update_option(pdu, p->option,
                           coap_encode_var_safe(buf, sizeof(buf),
                                                (block.num << 4) |
                                                (block.m << 3) |
                                                block.aszx),
                           buf);

        if (!coap_add_block_b_data(pdu,
                                   p->length,
                                   p->data,
                                   &block))
          goto fail_body;
        p->b.b1.bert_size = block.chunk_size;
        coap_ticks(&p->last_sent);
#if COAP_Q_BLOCK_SUPPORT
        if (p->option == COAP_OPTION_Q_BLOCK1 &&
            pdu->type == COAP_MESSAGE_NON) {
          if (coap_send_q_block1(session, block, pdu,
                                 COAP_SEND_INC_PDU) == COAP_INVALID_MID)
            goto fail_body;
          return 1;
        } else if (coap_send_internal(session, pdu) == COAP_INVALID_MID)
          goto fail_body;
#else /* ! COAP_Q_BLOCK_SUPPORT */
        if (coap_send_internal(session, pdu) == COAP_INVALID_MID)
          goto fail_body;
#endif /* ! COAP_Q_BLOCK_SUPPORT */
        return 1;
      }
    } else if (COAP_RESPONSE_CLASS(rcvd->code) == 2) {
      /*
       * Not a block response asking for the next block.
       * Could be an Observe response overlapping with block FETCH doing
       * Observe cancellation.
       */
      coap_opt_iterator_t opt_iter;
      coap_opt_t *obs_opt;
      int observe_action = -1;

      if (p->pdu.code != COAP_REQUEST_CODE_FETCH) {
        goto lg_xmit_finished;
      }
      obs_opt = coap_check_option(&p->pdu,
                                  COAP_OPTION_OBSERVE,
                                  &opt_iter);
      if (obs_opt) {
        observe_action = coap_decode_var_bytes(coap_opt_value(obs_opt),
                                               coap_opt_length(obs_opt));
      }
      if (observe_action != COAP_OBSERVE_CANCEL) {
        goto lg_xmit_finished;
      }
      obs_opt = coap_check_option(rcvd,
                                  COAP_OPTION_OBSERVE,
                                  &opt_iter);
      if (obs_opt) {
        return 0;
      }
      goto lg_xmit_finished;
    } else if (rcvd->code == COAP_RESPONSE_CODE(401)) {
      if (check_freshness(session, rcvd, sent, p, NULL))
        return 1;
#if COAP_Q_BLOCK_SUPPORT
    } else if (rcvd->code == COAP_RESPONSE_CODE(402)) {
      /* Q-Block1 or Q-Block2 not present in p - duplicate error ? */
      if (coap_get_block_b(session, rcvd, COAP_OPTION_Q_BLOCK2, &block) ||
          coap_get_block_b(session, rcvd, COAP_OPTION_Q_BLOCK1, &block))
        return 1;
    } else if (rcvd->code == COAP_RESPONSE_CODE(408) &&
               p->option == COAP_OPTION_Q_BLOCK1) {
      size_t length;
      const uint8_t *data;
      coap_opt_iterator_t opt_iter;
      coap_opt_t *fmt_opt = coap_check_option(rcvd,
                                              COAP_OPTION_CONTENT_FORMAT,
                                              &opt_iter);
      uint16_t fmt = fmt_opt ?
                     coap_decode_var_bytes(coap_opt_value(fmt_opt),
                                           coap_opt_length(fmt_opt)) :
                     COAP_MEDIATYPE_TEXT_PLAIN;

      if (fmt != COAP_MEDIATYPE_APPLICATION_MB_CBOR_SEQ)
        goto fail_body;

      if (COAP_PROTO_RELIABLE(session->proto) ||
          rcvd->type != COAP_MESSAGE_NON) {
        coap_log_debug("Unexpected 4.08 - protocol violation - ignore\n");
        return 1;
      }

      if (coap_get_data(rcvd, &length, &data)) {
        /* Need to decode CBOR to work out what blocks to re-send */
        const uint8_t *bp = data;
        uint32_t i;
        uint8_t buf[8];
        coap_pdu_t *pdu;
        uint64_t token;
        uint8_t ltoken[8];
        size_t ltoken_length;

        for (i = 0; (bp < data + length) &&
             i < COAP_MAX_PAYLOADS(session); i++) {
          if ((*bp & 0xc0) != 0x00) /* uint(value) */
            goto fail_cbor;
          block.num = derive_cbor_value(&bp, data + length - bp);
          coap_log_debug("Q-Block1: Missing block %d\n", block.num);
          if (block.num > (1 << 20) -1)
            goto fail_cbor;
          block.m = (block.num + 1) * chunk < p->length;
          block.szx = p->blk_size;

          /* Build the next PDU request based off the skeletal PDU */
          token = STATE_TOKEN_FULL(p->b.b1.state_token,++p->b.b1.count);
          ltoken_length = coap_encode_var_safe8(ltoken, sizeof(token), token);
          pdu = coap_pdu_duplicate_lkd(&p->pdu, session, ltoken_length,
                                       ltoken, NULL);
          if (!pdu)
            goto fail_body;

          coap_update_option(pdu, p->option,
                             coap_encode_var_safe(buf, sizeof(buf),
                                                  (block.num << 4) |
                                                  (block.m << 3) |
                                                  block.szx),
                             buf);

          if (!coap_add_block(pdu,
                              p->length,
                              p->data,
                              block.num,
                              block.szx))
            goto fail_body;
          if (coap_send_internal(session, pdu) == COAP_INVALID_MID)
            goto fail_body;
        }
        return 1;
      }
fail_cbor:
      coap_log_info("Invalid application/missing-blocks+cbor-seq\n");
#endif /* COAP_Q_BLOCK_SUPPORT */
    }
    goto lg_xmit_finished;
  } /* end of LL_FOREACH_SAFE */
  return 0;

fail_body:
  coap_handle_event_lkd(session->context, COAP_EVENT_XMIT_BLOCK_FAIL, session);
  /* There has been an internal error of some sort */
  rcvd->code = COAP_RESPONSE_CODE(500);
lg_xmit_finished:
  if (session->lg_crcv) {
    LL_FOREACH(session->lg_crcv, lg_crcv) {
      if (STATE_TOKEN_BASE(p->b.b1.state_token) ==
          STATE_TOKEN_BASE(lg_crcv->state_token)) {
        /* In case of observe */
        lg_crcv->state_token = p->b.b1.state_token;
        break;
      }
    }
  }
  if (!lg_crcv) {
    /* need to put back original token into rcvd */
    if (p->b.b1.app_token)
      coap_update_token(rcvd, p->b.b1.app_token->length,
                        p->b.b1.app_token->s);
    coap_log_debug("Client app version of updated PDU\n");
    coap_show_pdu(COAP_LOG_DEBUG, rcvd);
  } else {
    lg_crcv->pdu.lg_xmit = 0;
  }

  if (sent) {
    /* need to put back original token into sent */
    if (p->b.b1.app_token)
      coap_update_token(sent, p->b.b1.app_token->length,
                        p->b.b1.app_token->s);
    if (sent->lg_xmit)
      coap_remove_option(sent, sent->lg_xmit->option);
    sent->lg_xmit = NULL;
  }
  LL_DELETE(session->lg_xmit, p);
  coap_block_delete_lg_xmit(session, p);
  return 0;
}
#endif /* COAP_CLIENT_SUPPORT */

/*
 * Re-assemble payloads into a body
 */
coap_binary_t *
coap_block_build_body(coap_binary_t *body_data, size_t length,
                      const uint8_t *data, size_t offset, size_t total) {
  if (data == NULL)
    return NULL;
  if (body_data == NULL && total) {
    body_data = coap_new_binary(total);
  }
  if (body_data == NULL)
    return NULL;

  /* Update saved data */
  if (offset + length <= total && body_data->length >= total) {
    memcpy(&body_data->s[offset], data, length);
  } else {
    /*
     * total may be inaccurate as per
     * https://rfc-editor.org/rfc/rfc7959#section-4
     * o In a request carrying a Block1 Option, to indicate the current
     *   estimate the client has of the total size of the resource
     *   representation, measured in bytes ("size indication").
     * o In a response carrying a Block2 Option, to indicate the current
     *   estimate the server has of the total size of the resource
     *   representation, measured in bytes ("size indication").
     */
    coap_binary_t *new = coap_resize_binary(body_data, offset + length);

    if (new) {
      body_data = new;
      memcpy(&body_data->s[offset], data, length);
    } else {
      coap_delete_binary(body_data);
      return NULL;
    }
  }
  return body_data;
}

#if COAP_CLIENT_SUPPORT
/*
 * Need to see if this is a large body response to a request. If so,
 * need to initiate the request for the next block and not trouble the
 * application.  Note that Token must be unique per request/response.
 *
 * This is set up using coap_send()
 * Client receives large data from server ((Q-)Block2)
 *
 * Return: 0 Call application handler
 *         1 Do not call application handler - just sent the next request
 */
int
coap_handle_response_get_block(coap_context_t *context,
                               coap_session_t *session,
                               coap_pdu_t *sent,
                               coap_pdu_t *rcvd,
                               coap_recurse_t recursive) {
  coap_lg_crcv_t *p;
  coap_block_b_t block;
#if COAP_Q_BLOCK_SUPPORT
  coap_block_b_t qblock;
#endif /* COAP_Q_BLOCK_SUPPORT */
  int have_block = 0;
  uint16_t block_opt = 0;
  size_t offset;
  int ack_rst_sent = 0;
  uint64_t token_match =
      STATE_TOKEN_BASE(coap_decode_var_bytes8(rcvd->actual_token.s,
                                              rcvd->actual_token.length));

  memset(&block, 0, sizeof(block));
#if COAP_Q_BLOCK_SUPPORT
  memset(&qblock, 0, sizeof(qblock));
#endif /* COAP_Q_BLOCK_SUPPORT */
  LL_FOREACH(session->lg_crcv, p) {
    size_t chunk = 0;
    uint8_t buf[8];
    coap_opt_iterator_t opt_iter;

    if (token_match != STATE_TOKEN_BASE(p->state_token) &&
        !coap_binary_equal(&rcvd->actual_token, p->app_token)) {
      /* try out the next one */
      continue;
    }

    /* lg_crcv found */

    if (COAP_RESPONSE_CLASS(rcvd->code) == 2) {
      size_t length;
      const uint8_t *data;
      coap_opt_t *size_opt = coap_check_option(rcvd, COAP_OPTION_SIZE2,
                                               &opt_iter);
      size_t size2 = size_opt ?
                     coap_decode_var_bytes(coap_opt_value(size_opt),
                                           coap_opt_length(size_opt)) : 0;

      /* length and data are cleared on error */
      (void)coap_get_data(rcvd, &length, &data);
      rcvd->body_offset = 0;
      rcvd->body_total = length;
      if (coap_get_block_b(session, rcvd, COAP_OPTION_BLOCK2, &block)) {
        have_block = 1;
        block_opt = COAP_OPTION_BLOCK2;
      }
#if COAP_Q_BLOCK_SUPPORT
      if (coap_get_block_b(session, rcvd, COAP_OPTION_Q_BLOCK2, &qblock)) {
        if (have_block) {
          coap_log_warn("Both Block1 and Q-Block1 not supported in a response\n");
        }
        have_block = 1;
        block_opt = COAP_OPTION_Q_BLOCK2;
        block = qblock;
        /* server indicating that it supports Q_BLOCK */
        if (!(session->block_mode & COAP_BLOCK_HAS_Q_BLOCK)) {
          set_block_mode_has_q(session->block_mode);
        }
      }
#endif /* COAP_Q_BLOCK_SUPPORT */
      track_echo(session, rcvd);
      if (have_block && (block.m || length)) {
        coap_opt_t *fmt_opt = coap_check_option(rcvd,
                                                COAP_OPTION_CONTENT_FORMAT,
                                                &opt_iter);
        uint16_t fmt = fmt_opt ?
                       coap_decode_var_bytes(coap_opt_value(fmt_opt),
                                             coap_opt_length(fmt_opt)) :
                       COAP_MEDIATYPE_TEXT_PLAIN;
        coap_opt_t *etag_opt = coap_check_option(rcvd,
                                                 COAP_OPTION_ETAG,
                                                 &opt_iter);
        size_t saved_offset;
        int updated_block;

        if (length > block.chunk_size) {
          coap_log_debug("block: Oversized packet - reduced to %"PRIu32" from %zu\n",
                         block.chunk_size, length);
          length = block.chunk_size;
        }
        if (block.m && length != block.chunk_size) {
          coap_log_warn("block: Undersized packet - expected %"PRIu32", got %zu\n",
                        block.chunk_size, length);
          /* Unclear how to properly handle this */
          rcvd->code = COAP_RESPONSE_CODE(402);
          goto expire_lg_crcv;
        }
        /* Possibility that Size2 not sent, or is too small */
        chunk = (size_t)1 << (block.szx + 4);
        offset = block.num * chunk;
        if (size2 < (offset + length)) {
          if (block.m)
            size2 = offset + length + 1;
          else
            size2 = offset + length;
        }
        saved_offset = offset;

        if (p->initial) {
#if COAP_Q_BLOCK_SUPPORT
reinit:
#endif /* COAP_Q_BLOCK_SUPPORT */
          p->initial = 0;
          if (p->body_data) {
            coap_free_type(COAP_STRING, p->body_data);
            p->body_data = NULL;
          }
          if (etag_opt) {
            p->etag_length = coap_opt_length(etag_opt);
            memcpy(p->etag, coap_opt_value(etag_opt), p->etag_length);
            p->etag_set = 1;
          } else {
            p->etag_set = 0;
          }
          p->total_len = size2;
          p->content_format = fmt;
          p->szx = block.szx;
          p->block_option = block_opt;
          p->last_type = rcvd->type;
          p->rec_blocks.used = 0;
#if COAP_Q_BLOCK_SUPPORT
          p->rec_blocks.processing_payload_set = 0;
#endif /* COAP_Q_BLOCK_SUPPORT */
        }
        if (p->total_len < size2)
          p->total_len = size2;

        if (etag_opt) {
          if (!full_match(coap_opt_value(etag_opt),
                          coap_opt_length(etag_opt),
                          p->etag, p->etag_length)) {
            /* body of data has changed - need to restart request */
            coap_pdu_t *pdu;
            uint64_t token = STATE_TOKEN_FULL(p->state_token,
                                              ++p->retry_counter);
            size_t len = coap_encode_var_safe8(buf, sizeof(token), token);
            coap_opt_filter_t drop_options;

#if COAP_Q_BLOCK_SUPPORT
            if (block_opt == COAP_OPTION_Q_BLOCK2)
              goto reinit;
#endif /* COAP_Q_BLOCK_SUPPORT */

            coap_log_warn("Data body updated during receipt - new request started\n");
            if (!(session->block_mode & COAP_BLOCK_SINGLE_BODY))
              coap_handle_event_lkd(context, COAP_EVENT_PARTIAL_BLOCK, session);

            p->initial = 1;
            coap_free_type(COAP_STRING, p->body_data);
            p->body_data = NULL;

            coap_session_new_token(session, &len, buf);
            memset(&drop_options, 0, sizeof(coap_opt_filter_t));
            coap_option_filter_set(&drop_options, COAP_OPTION_OBSERVE);
            pdu = coap_pdu_duplicate_lkd(&p->pdu, session, len, buf, &drop_options);
            if (!pdu)
              goto fail_resp;

            coap_update_option(pdu, block_opt,
                               coap_encode_var_safe(buf, sizeof(buf),
                                                    (0 << 4) | (0 << 3) | block.aszx),
                               buf);

            if (coap_send_internal(session, pdu) == COAP_INVALID_MID)
              goto fail_resp;

            goto skip_app_handler;
          }
        } else if (p->etag_set) {
          /* Cannot handle this change in ETag to not being there */
          coap_log_warn("Not all blocks have ETag option\n");
          goto fail_resp;
        }

        if (fmt != p->content_format) {
          coap_log_warn("Content-Format option mismatch\n");
          goto fail_resp;
        }
#if COAP_Q_BLOCK_SUPPORT
        if (block_opt == COAP_OPTION_Q_BLOCK2 && size2 != p->total_len) {
          coap_log_warn("Size2 option mismatch\n");
          goto fail_resp;
        }
#endif /* COAP_Q_BLOCK_SUPPORT */
        if (block.num == 0) {
          coap_opt_t *obs_opt = coap_check_option(rcvd,
                                                  COAP_OPTION_OBSERVE,
                                                  &opt_iter);
          if (obs_opt) {
            p->observe_length = min(coap_opt_length(obs_opt), 3);
            memcpy(p->observe, coap_opt_value(obs_opt), p->observe_length);
            p->observe_set = 1;
          } else {
            p->observe_set = 0;
          }
        }
        updated_block = 0;
        while (offset < saved_offset + length) {
          if (!check_if_received_block(&p->rec_blocks, block.num)) {
#if COAP_Q_BLOCK_SUPPORT
            uint32_t this_payload_set = block.num / COAP_MAX_PAYLOADS(session);
#endif /* COAP_Q_BLOCK_SUPPORT */

            coap_log_debug("found Block option, block size is %u, block nr. %u\n",
                           1 << (block.szx + 4), block.num);
#if COAP_Q_BLOCK_SUPPORT
            if (block_opt == COAP_OPTION_Q_BLOCK2 && p->rec_blocks.used &&
                this_payload_set > p->rec_blocks.processing_payload_set &&
                this_payload_set != p->rec_blocks.latest_payload_set) {
              coap_request_missing_q_block2(session, p);
            }
            p->rec_blocks.latest_payload_set = this_payload_set;
#endif /* COAP_Q_BLOCK_SUPPORT */
            /* Update list of blocks received */
            if (!update_received_blocks(&p->rec_blocks, block.num)) {
              coap_handle_event_lkd(context, COAP_EVENT_PARTIAL_BLOCK, session);
              goto fail_resp;
            }
            updated_block = 1;
          }
          block.num++;
          offset = block.num << (block.szx + 4);
          if (!block.bert && block_opt != COAP_OPTION_Q_BLOCK2)
            break;
        }
        block.num--;
        /* Only process if not duplicate block */
        if (updated_block) {
          if ((session->block_mode & COAP_SINGLE_BLOCK_OR_Q) || block.bert) {
            if (size2 < saved_offset + length) {
              size2 = saved_offset + length;
            }
            p->body_data = coap_block_build_body(p->body_data, length, data,
                                                 saved_offset, size2);
            if (p->body_data == NULL) {
              goto fail_resp;
            }
          }
          if (block.m || !check_all_blocks_in(&p->rec_blocks,
                                              (size2 + chunk -1) / chunk)) {
            /* Not all the payloads of the body have arrived */
            size_t len;
            coap_pdu_t *pdu;
            uint64_t token;

            if (block.m) {
#if COAP_Q_BLOCK_SUPPORT
              if (block_opt == COAP_OPTION_Q_BLOCK2) {
                /* Blocks could arrive in wrong order */
                if (check_all_blocks_in(&p->rec_blocks,
                                        (size2 + chunk -1) / chunk)) {
                  goto give_to_app;
                }
                if (check_all_blocks_in_for_payload_set(session,
                                                        &p->rec_blocks)) {
                  block.num = p->rec_blocks.range[0].end;
                  /* Now requesting next payload */
                  p->rec_blocks.processing_payload_set =
                      block.num / COAP_MAX_PAYLOADS(session) + 1;
                  if (check_any_blocks_next_payload_set(session,
                                                        &p->rec_blocks)) {
                    /* Need to ask for them individually */
                    coap_request_missing_q_block2(session, p);
                    goto skip_app_handler;
                  }
                } else {
                  /* The remote end will be sending the next one unless this
                     is a MAX_PAYLOADS and all previous have been received */
                  goto skip_app_handler;
                }
                if (COAP_PROTO_RELIABLE(session->proto) ||
                    rcvd->type != COAP_MESSAGE_NON)
                  goto skip_app_handler;

              } else
#endif /* COAP_Q_BLOCK_SUPPORT */
                block.m = 0;

              /* Ask for the next block */
              token = STATE_TOKEN_FULL(p->state_token, ++p->retry_counter);
              len = coap_encode_var_safe8(buf, sizeof(token), token);
              pdu = coap_pdu_duplicate_lkd(&p->pdu, session, len, buf, NULL);
              if (!pdu)
                goto fail_resp;

              if (rcvd->type == COAP_MESSAGE_NON)
                pdu->type = COAP_MESSAGE_NON; /* Server is using NON */

              /* Only sent with the first block */
              coap_remove_option(pdu, COAP_OPTION_OBSERVE);

              coap_update_option(pdu, block_opt,
                                 coap_encode_var_safe(buf, sizeof(buf),
                                                      ((block.num + 1) << 4) |
                                                      (block.m << 3) | block.aszx),
                                 buf);

              if (session->block_mode & COAP_BLOCK_STLESS_FETCH && pdu->code == COAP_REQUEST_CODE_FETCH) {
                (void)coap_get_data(&p->pdu, &length, &data);
                coap_add_data_large_internal(session, NULL, pdu, NULL, NULL, -1, 0, length, data, NULL, NULL, 0, 0);
              }
              if (coap_send_internal(session, pdu) == COAP_INVALID_MID)
                goto fail_resp;
            }
            if ((session->block_mode & COAP_SINGLE_BLOCK_OR_Q) ||  block.bert)
              goto skip_app_handler;

            /* need to put back original token into rcvd */
            coap_update_token(rcvd, p->app_token->length, p->app_token->s);
            rcvd->body_offset = saved_offset;
#if COAP_Q_BLOCK_SUPPORT
            rcvd->body_total = block_opt == COAP_OPTION_Q_BLOCK2 ?
                               p->total_len : size2;
#else /* ! COAP_Q_BLOCK_SUPPORT */
            rcvd->body_total = size2;
#endif /* ! COAP_Q_BLOCK_SUPPORT */
            coap_log_debug("Client app version of updated PDU\n");
            coap_show_pdu(COAP_LOG_DEBUG, rcvd);

            if (sent) {
              /* need to put back original token into sent */
              if (p->app_token)
                coap_update_token(sent, p->app_token->length,
                                  p->app_token->s);
              coap_remove_option(sent, p->block_option);
            }
            goto call_app_handler;
          }
#if COAP_Q_BLOCK_SUPPORT
give_to_app:
#endif /* COAP_Q_BLOCK_SUPPORT */
          if ((session->block_mode & COAP_SINGLE_BLOCK_OR_Q) || block.bert) {
            /* Pretend that there is no block */
            coap_remove_option(rcvd, block_opt);
            if (p->observe_set) {
              coap_update_option(rcvd, COAP_OPTION_OBSERVE,
                                 p->observe_length, p->observe);
            }
            rcvd->body_data = p->body_data->s;
#if COAP_Q_BLOCK_SUPPORT
            rcvd->body_length = block_opt == COAP_OPTION_Q_BLOCK2 ?
                                p->total_len : saved_offset + length;
#else /* ! COAP_Q_BLOCK_SUPPORT */
            rcvd->body_length = saved_offset + length;
#endif /* ! COAP_Q_BLOCK_SUPPORT */
            rcvd->body_offset = 0;
            rcvd->body_total = rcvd->body_length;
          } else {
            rcvd->body_offset = saved_offset;
#if COAP_Q_BLOCK_SUPPORT
            rcvd->body_total = block_opt == COAP_OPTION_Q_BLOCK2 ?
                               p->total_len : size2;
#else /* ! COAP_Q_BLOCK_SUPPORT */
            rcvd->body_total = size2;
#endif /* ! COAP_Q_BLOCK_SUPPORT */
          }
          if (context->response_handler) {
            coap_response_t ret;

            /* need to put back original token into rcvd */
            if (!coap_binary_equal(&rcvd->actual_token, p->app_token)) {
              coap_update_token(rcvd, p->app_token->length, p->app_token->s);
              coap_log_debug("Client app version of updated PDU\n");
              coap_show_pdu(COAP_LOG_DEBUG, rcvd);
            }
            if (sent) {
              /* need to put back original token into sent */
              if (p->app_token)
                coap_update_token(sent, p->app_token->length,
                                  p->app_token->s);
              coap_remove_option(sent, p->block_option);
            }
            coap_lock_callback_ret_release(ret, session->context,
                                           context->response_handler(session, sent, rcvd,
                                                                     rcvd->mid),
                                           /* context is being freed off */
                                           assert(0));
            if (ret == COAP_RESPONSE_FAIL) {
              coap_send_rst_lkd(session, rcvd);
            } else {
              coap_send_ack_lkd(session, rcvd);
            }
          } else {
            coap_send_ack_lkd(session, rcvd);
          }
          ack_rst_sent = 1;
          if (p->observe_set == 0) {
            /* Expire this entry */
            LL_DELETE(session->lg_crcv, p);
            coap_block_delete_lg_crcv(session, p);
            goto skip_app_handler;
          }
          /* Set up for the next data body as observing */
          p->initial = 1;
          if (p->body_data) {
            coap_free_type(COAP_STRING, p->body_data);
            p->body_data = NULL;
          }
        }
        coap_ticks(&p->last_used);
        goto skip_app_handler;
      } else {
        coap_opt_t *obs_opt = coap_check_option(rcvd,
                                                COAP_OPTION_OBSERVE,
                                                &opt_iter);
        if (obs_opt) {
          p->observe_length = min(coap_opt_length(obs_opt), 3);
          memcpy(p->observe, coap_opt_value(obs_opt), p->observe_length);
          p->observe_set = 1;
        } else {
          p->observe_set = 0;
          if (!coap_binary_equal(&rcvd->actual_token, p->app_token)) {
            /* need to put back original token into rcvd */
            coap_update_token(rcvd, p->app_token->length, p->app_token->s);
            coap_log_debug("PDU presented to app.\n");
            coap_show_pdu(COAP_LOG_DEBUG, rcvd);
          }
          /* Expire this entry */
          goto expire_lg_crcv;
        }
      }
      coap_ticks(&p->last_used);
    } else if (rcvd->code == COAP_RESPONSE_CODE(401)) {
#if COAP_OSCORE_SUPPORT
      if (check_freshness(session, rcvd,
                          (session->oscore_encryption == 0) ? sent : NULL,
                          NULL, p))
#else /* !COAP_OSCORE_SUPPORT */
      if (check_freshness(session, rcvd, sent, NULL, p))
#endif /* !COAP_OSCORE_SUPPORT */
        goto skip_app_handler;
      goto expire_lg_crcv;
    } else {
      /* Not 2.xx or 4.01 - assume it is a failure of some sort */
      goto expire_lg_crcv;
    }
    if (!block.m && !p->observe_set) {
fail_resp:
      /* lg_crcv no longer required - cache it for 1 sec */
      coap_ticks(&p->last_used);
      p->last_used = p->last_used - COAP_MAX_TRANSMIT_WAIT_TICKS(session) +
                     COAP_TICKS_PER_SECOND;
    }
    /* need to put back original token into rcvd */
    if (!coap_binary_equal(&rcvd->actual_token, p->app_token)) {
      coap_update_token(rcvd, p->app_token->length, p->app_token->s);
      coap_log_debug("Client app version of updated PDU (3)\n");
      coap_show_pdu(COAP_LOG_DEBUG, rcvd);
    }
    break;
  } /* LL_FOREACH() */

  /* Check if receiving a block response and if blocks can be set up */
  if (recursive == COAP_RECURSE_OK && !p) {
    if (!sent) {
      if (coap_get_block_b(session, rcvd, COAP_OPTION_BLOCK2, &block)
#if COAP_Q_BLOCK_SUPPORT
          ||
          coap_get_block_b(session, rcvd, COAP_OPTION_Q_BLOCK2, &block)
#endif /* COAP_Q_BLOCK_SUPPORT */
         ) {
        coap_log_debug("** %s: large body receive internal issue\n",
                       coap_session_str(session));
        goto skip_app_handler;
      }
    } else if (COAP_RESPONSE_CLASS(rcvd->code) == 2) {
      if (coap_get_block_b(session, rcvd, COAP_OPTION_BLOCK2, &block)) {
#if COAP_Q_BLOCK_SUPPORT
        if (session->block_mode & COAP_BLOCK_PROBE_Q_BLOCK) {
          set_block_mode_drop_q(session->block_mode);
          coap_log_debug("Q-Block support disabled\n");
        }
#endif /* COAP_Q_BLOCK_SUPPORT */
        have_block = 1;
        if (block.num != 0) {
          /* Assume random access and just give the single response to app */
          size_t length;
          const uint8_t *data;
          size_t chunk = (size_t)1 << (block.szx + 4);

          coap_get_data(rcvd, &length, &data);
          rcvd->body_offset = block.num*chunk;
          rcvd->body_total = block.num*chunk + length + (block.m ? 1 : 0);
          goto call_app_handler;
        }
      }
#if COAP_Q_BLOCK_SUPPORT
      else if (coap_get_block_b(session, rcvd, COAP_OPTION_Q_BLOCK2, &block)) {
        have_block = 1;
        /* server indicating that it supports Q_BLOCK2 */
        if (!(session->block_mode & COAP_BLOCK_HAS_Q_BLOCK)) {
          set_block_mode_has_q(session->block_mode);
        }
      }
#endif /* COAP_Q_BLOCK_SUPPORT */
      if (have_block) {
        coap_lg_crcv_t *lg_crcv = coap_block_new_lg_crcv(session, sent, NULL);

        if (lg_crcv) {
          LL_PREPEND(session->lg_crcv, lg_crcv);
          return coap_handle_response_get_block(context, session, sent, rcvd,
                                                COAP_RECURSE_NO);
        }
      }
      track_echo(session, rcvd);
    } else if (rcvd->code == COAP_RESPONSE_CODE(401)) {
      coap_lg_crcv_t *lg_crcv = coap_block_new_lg_crcv(session, sent, NULL);

      if (lg_crcv) {
        LL_PREPEND(session->lg_crcv, lg_crcv);
        return coap_handle_response_get_block(context, session, sent, rcvd,
                                              COAP_RECURSE_NO);
      }
    }
  }
  return 0;

expire_lg_crcv:
  /* need to put back original token into rcvd */
  if (!coap_binary_equal(&rcvd->actual_token, p->app_token)) {
    coap_update_token(rcvd, p->app_token->length, p->app_token->s);
    coap_log_debug("Client app version of updated PDU\n");
    coap_show_pdu(COAP_LOG_DEBUG, rcvd);
  }

  if (sent) {
    /* need to put back original token into sent */
    if (p->app_token)
      coap_update_token(sent, p->app_token->length,
                        p->app_token->s);
    coap_remove_option(sent, p->block_option);
  }
  /* Expire this entry */
  LL_DELETE(session->lg_crcv, p);
  coap_block_delete_lg_crcv(session, p);

call_app_handler:
  return 0;

skip_app_handler:
  if (!ack_rst_sent)
    coap_send_ack_lkd(session, rcvd);
  return 1;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
/* Check if lg_xmit generated and update PDU code if so */
void
coap_check_code_lg_xmit(const coap_session_t *session,
                        const coap_pdu_t *request,
                        coap_pdu_t *response, const coap_resource_t *resource,
                        const coap_string_t *query) {
  coap_lg_xmit_t *lg_xmit;

  if (response->code == 0)
    return;
  lg_xmit = coap_find_lg_xmit_response(session, request, resource, query);
  if (lg_xmit && lg_xmit->pdu.code == 0) {
    lg_xmit->pdu.code = response->code;
    return;
  }
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
void
coap_check_update_token(coap_session_t *session, coap_pdu_t *pdu) {
  uint64_t token_match =
      STATE_TOKEN_BASE(coap_decode_var_bytes8(pdu->actual_token.s,
                                              pdu->actual_token.length));
  coap_lg_xmit_t *lg_xmit;
  coap_lg_crcv_t *lg_crcv;

  if (session->lg_crcv) {
    LL_FOREACH(session->lg_crcv, lg_crcv) {
      if (coap_binary_equal(&pdu->actual_token, lg_crcv->app_token))
        return;
      if (token_match == STATE_TOKEN_BASE(lg_crcv->state_token)) {
        coap_update_token(pdu, lg_crcv->app_token->length,
                          lg_crcv->app_token->s);
        coap_log_debug("Client app version of updated PDU\n");
        coap_show_pdu(COAP_LOG_DEBUG, pdu);
        return;
      }
    }
  }
  if (COAP_PDU_IS_REQUEST(pdu) && session->lg_xmit) {
    LL_FOREACH(session->lg_xmit, lg_xmit) {
      if (coap_binary_equal(&pdu->actual_token, lg_xmit->b.b1.app_token))
        return;
      if (token_match == STATE_TOKEN_BASE(lg_xmit->b.b1.state_token)) {
        coap_update_token(pdu, lg_xmit->b.b1.app_token->length,
                          lg_xmit->b.b1.app_token->s);
        coap_log_debug("Client app version of updated PDU\n");
        coap_show_pdu(COAP_LOG_DEBUG, pdu);
        return;
      }
    }
  }
}
#endif /* ! COAP_CLIENT_SUPPORT */
