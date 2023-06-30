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
 * @file oscore.h
 * @brief An implementation of the Object Security for Constrained RESTful
 * Environments (RFC 8613).
 *
 * \author Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * major rewrite for libcoap
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 */

#ifndef _OSCORE_H
#define _OSCORE_H

#include <coap3/coap_internal.h>
#include "oscore_cose.h"
#include "oscore_context.h"

/**
 * @ingroup internal_api
 * @addtogroup oscore_internal
 * @{
 */

/* Estimate your header size, especially when using Proxy-Uri. */
#define COAP_MAX_HEADER_SIZE 70

/* OSCORE error messages  (to be moved elsewhere  */
#define OSCORE_DECRYPTION_ERROR    100
#define PACKET_SERIALIZATION_ERROR 102

/* oscore_cs_params
 * returns cbor array [[param_type], [paramtype, param]]
 */
uint8_t *oscore_cs_params(int8_t param, int8_t param_type, size_t *len);

/* oscore_cs_key_params
 * returns cbor array [paramtype, param]
 */
uint8_t *oscore_cs_key_params(cose_curve_t param, int8_t param_type, size_t *len);

/*
 * oscore_encode_option_value
 */
size_t oscore_encode_option_value(uint8_t *option_buffer,
                                  size_t option_buf_len,
                                  cose_encrypt0_t *cose,
                                  uint8_t group,
                                  uint8_t appendix_b_2);

/*
 * Decodes the OSCORE option value and places decoded values into the provided
 * cose structure */
int oscore_decode_option_value(const uint8_t *option_value,
                               size_t option_len,
                               cose_encrypt0_t *cose);

/* Creates AAD, creates External AAD and serializes it into the complete AAD
 * structure. Returns serialized size. */
size_t oscore_prepare_aad(const uint8_t *external_aad_buffer,
                          size_t external_aad_len,
                          uint8_t *aad_buffer,
                          size_t aad_size);

size_t oscore_prepare_e_aad(oscore_ctx_t *ctx,
                            cose_encrypt0_t *cose,
                            const uint8_t *oscore_option,
                            size_t oscore_option_len,
                            coap_bin_const_t *sender_public_key,
                            uint8_t *external_aad_ptr,
                            size_t external_aad_size);

/* Creates Nonce */
void oscore_generate_nonce(cose_encrypt0_t *ptr,
                           oscore_ctx_t *ctx,
                           uint8_t *buffer,
                           uint8_t size);

/*Return 1 if OK, Error code otherwise */
uint8_t oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx,
                                   cose_encrypt0_t *cose);

/* Return 0 if SEQ MAX, return 1 if OK */
uint8_t oscore_increment_sender_seq(oscore_ctx_t *ctx);

/* Restore the sequence number and replay-window to the previous state. This is
 * to be used when decryption fail. */
void oscore_roll_back_seq(oscore_recipient_ctx_t *ctx);

/** @} */

#endif /* _OSCORE_H */
