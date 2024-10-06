/* oscore_crypto_contiki.c -- Crypto adapter for Contiki-NG
 *
 * Copyright (C) 2023 Uppsala universitet
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file oscore_crypto_contiki.c
 * @brief Crypto adapter for Contiki-NG
 */

#include "coap3/coap_internal.h"
#include <string.h>
#include <sys/types.h>

int
coap_oscore_is_supported(void) {
  return 1;
}

int
coap_crypto_check_cipher_alg(cose_alg_t alg) {
  switch (alg) {
  case COSE_ALGORITHM_AES_CCM_16_64_128:
  case COSE_ALGORITHM_AES_CCM_16_128_128:
    return 1;
  default:
    return 0;
  }
}

int
coap_crypto_check_hkdf_alg(cose_hkdf_alg_t hkdf_alg) {
  return hkdf_alg == COSE_HKDF_ALG_HKDF_SHA_256;
}

int
coap_crypto_aead_encrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {
  /* validate inputs */
  assert(params->params.aes.tag_len <= AES_128_BLOCK_SIZE);
  if ((data->length > UINT16_MAX) || (aad->length > UINT16_MAX)) {
    return 0;
  }
  size_t result_len = data->length + params->params.aes.tag_len;
  if (*max_result_len < result_len) {
    return 0;
  }

  /* set max_result_len */
  *max_result_len = result_len;

  /* copy plaintext */
  memcpy(result, data->s, data->length);

  /* encrypt */
  while (!AES_128.get_lock());
  if (!CCM_STAR.set_key(params->params.key.s)) {
    return 0;
  }
  if (!CCM_STAR.aead(params->params.aes.nonce,
                     result, data->length,
                     aad->s, aad->length,
                     result + data->length, params->params.aes.tag_len,
                     true)) {
    return 0;
  }
  AES_128.release_lock();

  return 1;
}

int
coap_crypto_aead_decrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {
  size_t result_len;
  uint8_t expected_tag[AES_128_BLOCK_SIZE];

  /* validate inputs */
  assert(params->params.aes.tag_len <= AES_128_BLOCK_SIZE);
  if (data->length < params->params.aes.tag_len) {
    return 0;
  }
  result_len = data->length - params->params.aes.tag_len;
  if (*max_result_len < result_len) {
    return 0;
  }
  if ((result_len > UINT16_MAX) || (aad->length > UINT16_MAX)) {
    return 0;
  }

  /* set max_result_len */
  *max_result_len = result_len;

  /* copy ciphertext */
  memcpy(result, data->s, result_len);

  /* decrypt */
  while (!AES_128.get_lock());
  if (!CCM_STAR.set_key(params->params.key.s)) {
    return 0;
  }
  if (!CCM_STAR.aead(params->params.aes.nonce,
                     result, result_len,
                     aad->s, aad->length,
                     expected_tag, params->params.aes.tag_len,
                     false)) {
    return 0;
  }
  AES_128.release_lock();

  return !memcmp(expected_tag,
                 data->s + result_len,
                 params->params.aes.tag_len);
}

int
coap_crypto_hmac(cose_hmac_alg_t hmac_alg,
                 coap_bin_const_t *key,
                 coap_bin_const_t *data,
                 coap_bin_const_t **hmac) {
  uint8_t hmac_bytes[SHA_256_DIGEST_LENGTH];

  assert(hmac_alg == COSE_HMAC_ALG_HMAC256_256);
  sha_256_hmac(key->s, key->length, data->s, data->length, hmac_bytes);
  *hmac = coap_new_bin_const(hmac_bytes, sizeof(hmac_bytes));
  return *hmac != NULL;
}
