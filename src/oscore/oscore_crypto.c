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
 * @file oscore_crypto.c
 * @brief An implementation of the Hash Based Key Derivation Function (RFC) and
 * wrappers for AES-CCM*.
 *
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * extended for libcoap
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 */

#include "coap3/coap_internal.h"
#include <string.h>

#include <stdio.h>

/*
 * return 0 fail
 *        1 OK
 */
int
oscore_hmac_hash(cose_hmac_alg_t hmac_alg,
                 coap_bin_const_t *key,
                 coap_bin_const_t *data,
                 coap_bin_const_t **hmac) {
  if (!coap_crypto_hmac(hmac_alg, key, data, hmac)) {
    coap_log_warn("oscore_hmac_hash: Failed hmac\n");
    return 0;
  }
  return 1;
}

/*
 * return 0 fail
 *        1 OK
 */
int
oscore_hkdf_extract(cose_hkdf_alg_t hkdf_alg,
                    coap_bin_const_t *salt,
                    coap_bin_const_t *ikm,
                    coap_bin_const_t **hkdf_extract) {
  cose_hmac_alg_t hmac_alg;

  assert(ikm);
  if (!cose_get_hmac_alg_for_hkdf(hkdf_alg, &hmac_alg))
    return 0;
  if (salt == NULL || salt->s == NULL) {
    uint8_t zeroes_data[32];
    coap_bin_const_t zeroes;

    memset(zeroes_data, 0, sizeof(zeroes_data));
    zeroes.s = zeroes_data;
    zeroes.length = sizeof(zeroes_data);

    return oscore_hmac_hash(hmac_alg, &zeroes, ikm, hkdf_extract);
  } else {
    return oscore_hmac_hash(hmac_alg, salt, ikm, hkdf_extract);
  }
}

/*
 * return 0 fail
 *        1 OK
 */
int
oscore_hkdf_expand(cose_hkdf_alg_t hkdf_alg,
                   coap_bin_const_t *prk,
                   uint8_t *info,
                   size_t info_len,
                   uint8_t *okm,
                   size_t okm_len) {
  size_t N = (okm_len + 32 - 1) / 32; /* ceil(okm_len/32) */
  uint8_t *aggregate_buffer = coap_malloc_type(COAP_STRING, 32 + info_len + 1);
  uint8_t *out_buffer =
      coap_malloc_type(COAP_STRING, (N + 1) * 32); /* 32 extra bytes to fit the last block */
  size_t i;
  coap_bin_const_t data;
  coap_bin_const_t *hkdf = NULL;
  cose_hmac_alg_t hmac_alg;

  if (!cose_get_hmac_alg_for_hkdf(hkdf_alg, &hmac_alg))
    goto fail;
  /* Compose T(1) */
  memcpy(aggregate_buffer, info, info_len);
  aggregate_buffer[info_len] = 0x01;

  data.s = aggregate_buffer;
  data.length = info_len + 1;
  if (!oscore_hmac_hash(hmac_alg, prk, &data, &hkdf))
    goto fail;
  memcpy(&out_buffer[0], hkdf->s, hkdf->length);
  coap_delete_bin_const(hkdf);

  /* Compose T(2) -> T(N) */
  memcpy(aggregate_buffer, &(out_buffer[0]), 32);
  for (i = 1; i < N; i++) {
    memcpy(&(aggregate_buffer[32]), info, info_len);
    aggregate_buffer[32 + info_len] = (uint8_t)(i + 1);
    data.s = aggregate_buffer;
    data.length = 32 + info_len + 1;
    if (!oscore_hmac_hash(hmac_alg, prk, &data, &hkdf))
      goto fail;
    memcpy(&out_buffer[i * 32], hkdf->s, hkdf->length);
    coap_delete_bin_const(hkdf);
    memcpy(aggregate_buffer, &(out_buffer[i * 32]), 32);
  }
  memcpy(okm, out_buffer, okm_len);
  coap_free_type(COAP_STRING, out_buffer);
  coap_free_type(COAP_STRING, aggregate_buffer);
  return 1;

fail:
  coap_free_type(COAP_STRING, out_buffer);
  coap_free_type(COAP_STRING, aggregate_buffer);
  return 0;
}

/*
 * return 0 fail
 *        1 OK
 */
int
oscore_hkdf(cose_hkdf_alg_t hkdf_alg,
            coap_bin_const_t *salt,
            coap_bin_const_t *ikm,
            uint8_t *info,
            size_t info_len,
            uint8_t *okm,
            size_t okm_len) {
  int ret;
  coap_bin_const_t *hkdf_extract = NULL;
  if (!oscore_hkdf_extract(hkdf_alg, salt, ikm, &hkdf_extract))
    return 0;
  ret =
      oscore_hkdf_expand(hkdf_alg, hkdf_extract, info, info_len, okm, okm_len);
  coap_delete_bin_const(hkdf_extract);
  return ret;
}
