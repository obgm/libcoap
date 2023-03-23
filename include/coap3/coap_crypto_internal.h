/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/*
 * coap_crypto_internal.h -- Structures, Enums & Functions that are not
 * exposed to application programming
 *
 * Copyright (C) 2017-2023 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021-2023 Jon Shallow <supjps-ietf@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_crypto_internal.h
 * @brief COAP crypto internal information
 */

#ifndef COAP_CRYPTO_INTERNAL_H_
#define COAP_CRYPTO_INTERNAL_H_

/**
 * @ingroup internal_api
 * @defgroup crypto_internal OSCORE Crypto Support
 * Internal API for interfacing with Crypto libraries
 * @{
 */

#include "oscore/oscore_cose.h"

#ifndef COAP_CRYPTO_MAX_KEY_SIZE
#define COAP_CRYPTO_MAX_KEY_SIZE (32)
#endif /* COAP_CRYPTO_MAX_KEY_SIZE */

#ifndef COAP_OSCORE_DEFAULT_REPLAY_WINDOW
#define COAP_OSCORE_DEFAULT_REPLAY_WINDOW 32
#endif /* COAP_OSCORE_DEFAULT_REPLAY_WINDOW */

/**
 * The structure that holds the Crypto Key.
 */
typedef coap_bin_const_t coap_crypto_key_t;

/**
 * The structure that holds the AES Crypto information
 */
typedef struct coap_crypto_aes_ccm_t {
  coap_crypto_key_t key; /**< The Key to use */
  const uint8_t *nonce;  /**< must be exactly 15 - l bytes */
  size_t tag_len;        /**< The size of the Tag */
  size_t l;              /**< The number of bytes in the length field */
} coap_crypto_aes_ccm_t;

/**
 * The common structure that holds the Crypto information
 */
typedef struct coap_crypto_param_t {
  cose_alg_t alg; /**< The COSE algorith to use */
  union {
    coap_crypto_aes_ccm_t aes; /**< Used if AES type encryption */
    coap_crypto_key_t key;     /**< The key to use */
  } params;
} coap_crypto_param_t;

/**
 * Check whether the defined cipher algorithm is supported by the underlying
 * crypto library.
 *
 * @param alg The COSE algorithm to check.
 *
 * @return @c 1 if there is support, else @c 0.
 */
int coap_crypto_check_cipher_alg(cose_alg_t alg);

/**
 * Check whether the defined hkdf algorithm is supported by the underlying
 * crypto library.
 *
 * @param hkdf_alg The COSE HKDF algorithm to check.
 *
 * @return @c 1 if there is support, else @c 0.
 */
int coap_crypto_check_hkdf_alg(cose_hkdf_alg_t hkdf_alg);

/**
 * Encrypt the provided plaintext data
 *
 * @param params The Encrypt/Decrypt/Hash paramaters.
 * @param data The data to encrypt.
 * @param aad The additional AAD information.
 * @param result Where to put the encrypted data.
 * @param max_result_len The maximum size for @p result
 *                       (updated with actual size).
 *
 * @return @c 1 if the data was successfully encrypted, else @c 0.
 */
int coap_crypto_aead_encrypt(const coap_crypto_param_t *params,
                             coap_bin_const_t *data,
                             coap_bin_const_t *aad,
                             uint8_t *result,
                             size_t *max_result_len);

/**
 * Decrypt the provided encrypted data into plaintext.
 *
 * @param params The Encrypt/Decrypt/Hash paramaters.
 * @param data The data to decrypt.
 * @param aad The additional AAD information.
 * @param result Where to put the decrypted data.
 * @param max_result_len The maximum size for @p result
 *                       (updated with actual size).
 *
 * @return @c 1 if the data was successfully decrypted, else @c 0.
 */
int coap_crypto_aead_decrypt(const coap_crypto_param_t *params,
                             coap_bin_const_t *data,
                             coap_bin_const_t *aad,
                             uint8_t *result,
                             size_t *max_result_len);

/**
 * Create a HMAC hash of the provided data.
 *
 * @param hmac_alg The COSE HMAC algorithm to use.
 * @param key The key to use for the hash.
 * @param data The data to hash.
 * @param hmac Where to put the created hmac result if successful.
 *
 * @return @c 1 if the hmac of the data was successful, else @c 0.
 *         It is the responsibility of the caller to release the
 *         created hmac.
 */
int coap_crypto_hmac(cose_hmac_alg_t hmac_alg,
                     coap_bin_const_t *key,
                     coap_bin_const_t *data,
                     coap_bin_const_t **hmac);

/**
 * Create a hash of the provided data.
 *
 * @param alg The hash algorithm.
 * @param data The data to hash.
 * @param hash Where to put the hash result if successful.
 *
 * @return @c 1 if the data was successfully hashed, else @c 0.
 *         It is the responsibility of the caller to release the
 *         created hash.
 */
int coap_crypto_hash(cose_alg_t alg,
                     const coap_bin_const_t *data,
                     coap_bin_const_t **hash);

/** @} */

#endif /* COAP_CRYPTO_INTERNAL_H_ */
