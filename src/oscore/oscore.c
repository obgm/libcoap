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
 * @file oscore.c
 * @brief An implementation of the Object Security for Constrained RESTful
 * Enviornments (RFC 8613).
 *
 * \author Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * adapted to libcoap and major rewrite
 *     Peter van der Stok <consultancy@vanderstok.org>
 *     on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 */

#include "coap3/coap_internal.h"

/* oscore_cs_params
 * returns cbor array [[param_type], [paramtype, param]]
 */
uint8_t *
oscore_cs_params(int8_t param, int8_t param_type, size_t *len) {
  uint8_t buf[50];
  size_t rem_size = sizeof(buf);
  uint8_t *pt = buf;

  *len = 0;
  *len += oscore_cbor_put_array(&pt, &rem_size, 2);
  *len += oscore_cbor_put_array(&pt, &rem_size, 1);
  *len += oscore_cbor_put_number(&pt, &rem_size, param_type);
  *len += oscore_cbor_put_array(&pt, &rem_size, 2);
  *len += oscore_cbor_put_number(&pt, &rem_size, param_type);
  *len += oscore_cbor_put_number(&pt, &rem_size, param);
  uint8_t *result = coap_malloc_type(COAP_STRING, *len);
  memcpy(result, buf, *len);
  return result;
}

/* oscore_cs_key_params
 * returns cbor array [paramtype, param]
 */
uint8_t *
oscore_cs_key_params(cose_curve_t param, int8_t param_type, size_t *len) {
  uint8_t buf[50];
  size_t rem_size = sizeof(buf);
  uint8_t *pt = buf;

  *len = 0;
  *len += oscore_cbor_put_array(&pt, &rem_size, 2);
  *len += oscore_cbor_put_number(&pt, &rem_size, param_type);
  *len += oscore_cbor_put_number(&pt, &rem_size, param);
  uint8_t *result = coap_malloc_type(COAP_STRING, *len);
  memcpy(result, buf, *len);
  return result;
}

/*
 * Build the CBOR for external_aad
 *
 * external_aad = bstr .cbor aad_array
 *
 * No group mode
 * aad_array = [
 *   oscore_version : uint,
 *   algorithms : [ alg_aead : int / tstr ],
 *   request_kid : bstr,
 *   request_piv : bstr,
 *   options : bstr,
 * ]
 *
 * Group mode
 * aad_array = [
 *   oscore_version : uint,
 *   algorithms : [alg_aead : int / tstr / null,
 *                 alg_signature_enc : int / tstr / null,
 *                 alg_signature : int / tstr / null,
 *                 alg_pairwise_key_agreement : int / tstr / null],
 *   request_kid : bstr,
 *   request_piv : bstr,
 *   options : bstr,
 *   request_kid_context : bstr,
 *   OSCORE_option: bstr,
 *   sender_public_key: bstr,        (initiator's key)
 *   gm_public_key: bstr / null
 * ]
 */
size_t
oscore_prepare_e_aad(oscore_ctx_t *ctx,
                     cose_encrypt0_t *cose,
                     const uint8_t *oscore_option,
                     size_t oscore_option_len,
                     coap_bin_const_t *sender_public_key,
                     uint8_t *external_aad_ptr,
                     size_t external_aad_size) {
  size_t external_aad_len = 0;
  size_t rem_size = external_aad_size;

  (void)oscore_option;
  (void)oscore_option_len;
  (void)sender_public_key;

  if (ctx->mode != OSCORE_MODE_SINGLE)
    external_aad_len += oscore_cbor_put_array(&external_aad_ptr, &rem_size, 9);
  else
    external_aad_len += oscore_cbor_put_array(&external_aad_ptr, &rem_size, 5);

  /* oscore_version, always "1" */
  external_aad_len += oscore_cbor_put_unsigned(&external_aad_ptr, &rem_size, 1);

  if (ctx->mode == OSCORE_MODE_SINGLE) {
    /* Algoritms array with one item*/
    external_aad_len += oscore_cbor_put_array(&external_aad_ptr, &rem_size, 1);
    /* Encryption Algorithm   */
    external_aad_len +=
        oscore_cbor_put_number(&external_aad_ptr, &rem_size, ctx->aead_alg);
  }
  /* request_kid */
  external_aad_len += oscore_cbor_put_bytes(&external_aad_ptr,
                                            &rem_size,
                                            cose->key_id.s,
                                            cose->key_id.length);
  /* request_piv */
  external_aad_len += oscore_cbor_put_bytes(&external_aad_ptr,
                                            &rem_size,
                                            cose->partial_iv.s,
                                            cose->partial_iv.length);
  /* options */
  /* Put integrity protected options, at present there are none. */
  external_aad_len +=
      oscore_cbor_put_bytes(&external_aad_ptr, &rem_size, NULL, 0);

  return external_aad_len;
}

/*
 * oscore_encode_option_value
 */
size_t
oscore_encode_option_value(uint8_t *option_buffer,
                           size_t option_buf_len,
                           cose_encrypt0_t *cose,
                           uint8_t group_flag,
                           uint8_t appendix_b_2) {
  size_t offset = 1;
  size_t rem_space = option_buf_len;

  (void)group_flag;
  if (cose->partial_iv.length > 5) {
    return 0;
  }
  option_buffer[0] = 0;

  if (cose->partial_iv.length > 0 && cose->partial_iv.length <= 5 &&
      cose->partial_iv.s != NULL) {
    option_buffer[0] |= (0x07 & cose->partial_iv.length);
    memcpy(&(option_buffer[offset]),
           cose->partial_iv.s,
           cose->partial_iv.length);
    offset += cose->partial_iv.length;
    assert(rem_space > cose->partial_iv.length);
    rem_space -= cose->partial_iv.length;
  }

  if (cose->kid_context.length > 0 && cose->kid_context.s != NULL) {
    if (appendix_b_2) {
      /* Need to CBOR wrap kid_context - yuk! */
      uint8_t *ptr = &option_buffer[offset+1];

      option_buffer[0] |= 0x10;
      option_buffer[offset] = (uint8_t)oscore_cbor_put_bytes(&ptr, &rem_space,
                                                             cose->kid_context.s,
                                                             cose->kid_context.length);
      offset += option_buffer[offset] + 1;
    } else {
      option_buffer[0] |= 0x10;
      option_buffer[offset] = (uint8_t)cose->kid_context.length;
      offset++;
      memcpy(&(option_buffer[offset]),
             cose->kid_context.s,
             (uint8_t)cose->kid_context.length);
      offset += cose->kid_context.length;
      assert(rem_space > cose->kid_context.length);
      rem_space -= cose->kid_context.length;
    }
  }

  if (cose->key_id.s != NULL) {
    option_buffer[0] |= 0x08;
    if (cose->key_id.length) {
      memcpy(&(option_buffer[offset]), cose->key_id.s, cose->key_id.length);
      offset += cose->key_id.length;
      assert(rem_space > cose->key_id.length);
      rem_space -= cose->key_id.length;
    }
  }

  if (offset == 1 && option_buffer[0] == 0) {
    /* If option_value is 0x00 it should be empty. */
    offset = 0;
  }
  assert(offset <= option_buf_len);
  cose->oscore_option.s = option_buffer;
  cose->oscore_option.length = offset;
  return offset;
}

/*
 * oscore_decode_option_value
 * error: return 0
 * OK: return 1
 *
 * Basic assupmption is that all is preset to 0 or NULL on entry
 */
int
oscore_decode_option_value(const uint8_t *opt_value,
                           size_t option_len,
                           cose_encrypt0_t *cose) {
  uint8_t partial_iv_len = (opt_value[0] & 0x07);
  size_t offset = 1;

  cose->oscore_option.s = opt_value;
  cose->oscore_option.length = option_len;

  if (option_len == 0)
    return 1; /* empty option */

  if (option_len > 255 || partial_iv_len == 6 || partial_iv_len == 7 ||
      (opt_value[0] & 0xC0) != 0) {
    return 0;
  }

  if ((opt_value[0] & 0x20) != 0) {
    return 0;
  }

  if (partial_iv_len != 0) {
    coap_bin_const_t partial_iv;
    if (offset + partial_iv_len > option_len) {
      return 0;
    }
    partial_iv.s = &(opt_value[offset]);
    partial_iv.length = partial_iv_len;
    cose_encrypt0_set_partial_iv(cose, &partial_iv);
    offset += partial_iv_len;
  }

  if ((opt_value[0] & 0x10) != 0) {
    coap_bin_const_t kid_context;

    if (offset >= option_len)
      return 0;
    kid_context.length = opt_value[offset];
    offset++;
    if (offset + kid_context.length > option_len) {
      return 0;
    }
    kid_context.s = &(opt_value[offset]);
    cose_encrypt0_set_kid_context(cose, &kid_context);
    offset = offset + kid_context.length;
  }

  if ((opt_value[0] & 0x08) != 0) {
    coap_bin_const_t key_id;

    key_id.length = option_len - offset;
    if ((int)key_id.length < 0) {
      return 0;
    }
    key_id.s = &(opt_value[offset]);
    cose_encrypt0_set_key_id(cose, &key_id);
  }
  return 1;
}

/*
 * oscore_prepare_aad
 *
 * Creates and sets External AAD for encryption
 */
size_t
oscore_prepare_aad(const uint8_t *external_aad_buffer,
                   size_t external_aad_len,
                   uint8_t *aad_buffer,
                   size_t aad_size) {
  size_t ret = 0;
  size_t rem_size = aad_size;
  char encrypt0[] = "Encrypt0";

  (void)aad_size; /* TODO */
  /* Creating the AAD */
  ret += oscore_cbor_put_array(&aad_buffer, &rem_size, 3);
  /* 1. "Encrypt0" */
  ret +=
      oscore_cbor_put_text(&aad_buffer, &rem_size, encrypt0, strlen(encrypt0));
  /* 2. Empty h'' entry */
  ret += oscore_cbor_put_bytes(&aad_buffer, &rem_size, NULL, 0);
  /* 3. External AAD */
  ret += oscore_cbor_put_bytes(&aad_buffer,
                               &rem_size,
                               external_aad_buffer,
                               external_aad_len);

  return ret;
}

/*
 * oscore_generate_nonce
 *
 * Creates Nonce
 */
void
oscore_generate_nonce(cose_encrypt0_t *ptr,
                      oscore_ctx_t *ctx,
                      uint8_t *buffer,
                      uint8_t size) {
  memset(buffer, 0, size);
  buffer[0] = (uint8_t)(ptr->key_id.length);
  memcpy(&(buffer[((size - 5) - ptr->key_id.length)]),
         ptr->key_id.s,
         ptr->key_id.length);
  memcpy(&(buffer[size - ptr->partial_iv.length]),
         ptr->partial_iv.s,
         ptr->partial_iv.length);
  for (int i = 0; i < size; i++) {
    buffer[i] = buffer[i] ^ (uint8_t)ctx->common_iv->s[i];
  }
}

/*
 * oscore_validate_sender_seq
 *
 * Return 1 if OK, 0 otherwise
 */
uint8_t
oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx, cose_encrypt0_t *cose) {
  uint64_t incoming_seq =
      coap_decode_var_bytes8(cose->partial_iv.s, cose->partial_iv.length);

  if (incoming_seq >= OSCORE_SEQ_MAX) {
    coap_log_warn("OSCORE Replay protection, SEQ larger than SEQ_MAX.\n");
    return 0;
  }

  ctx->rollback_last_seq = ctx->last_seq;
  ctx->rollback_sliding_window = ctx->sliding_window;

  /* Special case since we do not use unsigned int for seq */
  if (ctx->initial_state == 1) {
    ctx->initial_state = 0;
    /* bitfield. B0 biggest seq seen.  B1 seq-1 seen, B2 seq-2 seen etc. */
    ctx->sliding_window = 1;
    ctx->last_seq = incoming_seq;
  } else if (incoming_seq > ctx->last_seq) {
    /* Update the replay window */
    uint64_t shift = incoming_seq - ctx->last_seq;
    ctx->sliding_window = ctx->sliding_window << shift;
    /* bitfield. B0 biggest seq seen.  B1 seq-1 seen, B2 seq-2 seen etc. */
    ctx->sliding_window |= 1;
    ctx->last_seq = incoming_seq;
  } else if (incoming_seq == ctx->last_seq) {
    coap_log_warn("OSCORE: Replay protection, replayed SEQ (%" PRIu64 ")\n",
                  incoming_seq);
    return 0;
  } else { /* incoming_seq < last_seq */
    uint64_t shift = ctx->last_seq - incoming_seq - 1;
    uint64_t pattern;

    if (shift > ctx->osc_ctx->replay_window_size || shift > 63) {
      coap_log_warn("OSCORE: Replay protection, SEQ outside of replay window (%"
                    PRIu64 " %" PRIu64 ")\n",
                    ctx->last_seq,
                    incoming_seq);
      return 0;
    }
    /* seq + replay_window_size > last_seq */
    pattern = 1ULL << shift;
    if (ctx->sliding_window & pattern) {
      coap_log_warn("OSCORE: Replay protection, replayed SEQ (%" PRIu64 ")\n",
                    incoming_seq);
      return 0;
    }
    /* bitfield. B0 biggest seq seen.  B1 seq-1 seen, B2 seq-2 seen etc. */
    ctx->sliding_window |= pattern;
  }
  coap_log_oscore("OSCORE: window 0x%" PRIx64 " seq-B0 %" PRIu64 " SEQ %"
                  PRIu64 "\n",
                  ctx->sliding_window,
                  ctx->last_seq,
                  incoming_seq);
  return 1;
}

/*
 * oscore_increment_sender_seq
 *
 * Return 0 if SEQ MAX, return 1 if OK
 */
uint8_t
oscore_increment_sender_seq(oscore_ctx_t *ctx) {
  ctx->sender_context->seq++;

  if (ctx->sender_context->seq >= OSCORE_SEQ_MAX) {
    return 0;
  } else {
    return 1;
  }
}

/*
 * oscore_roll_back_seq
 *
 * Restore the sequence number and replay-window to the previous state. This
 * is to be used when decryption fail.
 */
void
oscore_roll_back_seq(oscore_recipient_ctx_t *ctx) {

  if (ctx->rollback_sliding_window != 0) {
    ctx->sliding_window = ctx->rollback_sliding_window;
    ctx->rollback_sliding_window = 0;
  }
  if (ctx->rollback_last_seq != 0) {
    ctx->last_seq = ctx->rollback_last_seq;
    ctx->rollback_last_seq = 0;
  }
}
