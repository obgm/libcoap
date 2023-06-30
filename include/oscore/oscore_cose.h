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
 * @file oscore_cose.h
 * @brief An implementation of the CBOR Object Signing and Encryption (RFC).
 *
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * adapted with sign1 function for libcoap
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 */

#ifndef _OSCORE_COSE_H
#define _OSCORE_COSE_H

#include <stdint.h>

/**
 * @ingroup internal_api
 * @defgroup oscore_cose_internal OSCORE COSE Support
 * Internal API for interfacing with OSCORE COSE
 * @{
 */

/* cose curves */

typedef enum {
  COSE_CURVE_P_256 = 1,     /* NIST P-256 known as secp256r1 */
  COSE_CURVE_X25519 = 4,    /* used with ECDH only      */
  COSE_CURVE_X448 = 5,      /* used with ECDH only      */
  COSE_CURVE_ED25519 = 6,   /* used with EdDSA only     */
  COSE_CURVE_ED448 = 7,     /* used with EdDSA only     */
  COSE_CURVE_SECP256K1 = 8, /* SECG secp256k1 curve */
} cose_curve_t;

typedef enum {
  COSE_KTY_UNKNOWN,
  COSE_KTY_OKP = 1,
  COSE_KTY_EC2 = 2,
  COSE_KTY_RSA = 3,
  COSE_KTY_SYMMETRIC = 4,
} cose_key_type_t;

#define COSE_ALGORITHM_ED25519_SIG_LEN      64
#define COSE_ALGORITHM_ED25519_PRIV_KEY_LEN 32
#define COSE_ALGORITHM_ED25519_PUB_KEY_LEN  32

#define COSE_ALGORITHM_AES_CCM_64_64_128_KEY_LEN 16
#define COSE_ALGORITHM_AES_CCM_64_64_128_NONCE_LEN  7
#define COSE_ALGORITHM_AES_CCM_64_64_128_TAG_LEN 8

#define COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN 16
#define COSE_ALGORITHM_AES_CCM_16_64_128_NONCE_LEN  13
#define COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN 8

#define COSE_ALGORITHM_AES_CCM_64_128_128_KEY_LEN 16
#define COSE_ALGORITHM_AES_CCM_64_128_128_NONCE_LEN  7
#define COSE_ALGORITHM_AES_CCM_64_128_128_TAG_LEN 16

#define COSE_ALGORITHM_AES_CCM_16_128_128_KEY_LEN 16
#define COSE_ALGORITHM_AES_CCM_16_128_128_NONCE_LEN  13
#define COSE_ALGORITHM_AES_CCM_16_128_128_TAG_LEN 16

#define COSE_ALGORITHM_ES256_PRIV_KEY_LEN  24
#define COSE_ALGORITHM_ES256_PUB_KEY_LEN   32
#define COSE_ALGORITHM_ES256_SIGNATURE_LEN 64
#define COSE_ALGORITHM_ES256_HASH_LEN      32

#define COSE_ALGORITHM_ES384_PRIV_KEY_LEN  24
#define COSE_ALGORITHM_ES384_PUB_KEY_LEN   32
#define COSE_ALGORITHM_ES384_SIGNATURE_LEN 64
#define COSE_ALGORITHM_ES384_HASH_LEN      48

#define COSE_ALGORITHM_ES512_PRIV_KEY_LEN  24
#define COSE_ALGORITHM_ES512_PUB_KEY_LEN   32
#define COSE_ALGORITHM_ES512_SIGNATURE_LEN 64
#define COSE_ALGORITHM_ES512_HASH_LEN      64

#define COSE_ALGORITHM_ECDH_PRIV_KEY_LEN 32
#define COSE_ALGORITHM_ECDH_PUB_KEY_LEN  32

#define COSE_ALGORITHM_SHA_512_LEN 64
#define COSE_ALGORITHM_SHA_512_256_LEN 32
#define COSE_ALGORITHM_SHA_256_256_LEN 32
#define COSE_ALGORITHM_SHA_256_64_LEN  8

#define COSE_ALGORITHM_HMAC256_64_HASH_LEN  16
#define COSE_ALGORITHM_HMAC256_256_HASH_LEN 32
#define COSE_ALGORITHM_HMAC384_384_HASH_LEN 48
#define COSE_ALGORITHM_HMAC512_512_HASH_LEN 64

/* cose algorithms */
typedef enum {
  COSE_ALGORITHM_ES256K = -47, /* with ECC known as secp256k1 */
  COSE_ALGORITHM_SHA_512 = -44,
  COSE_ALGORITHM_SHA_384 = -43,
  COSE_ALGORITHM_ES512 = -36, /* with ECDSA  */
  COSE_ALGORITHM_ES384 = -35, /* with ECDSA */
  COSE_ALGORITHM_ECDH_SS_HKDF_256 = -27,
  COSE_ALGORITHM_SHA_512_256 = -17,
  COSE_ALGORITHM_SHA_256_256 = -16,
  COSE_ALGORITHM_SHA_256_64 = -15,
  COSE_ALGORITHM_SHA_1 = -14,
  COSE_ALGORITHM_HKDF_SHA_512 = -11,
  COSE_ALGORITHM_HKDF_SHA_256 = -10,
  COSE_ALGORITHM_EDDSA = -8,
  COSE_ALGORITHM_ES256 = -7,     /* with ECC known as secp256r1 */
  COSE_ALGORITHM_HMAC256_64 = 4, /* truncated to 64 bits */
  COSE_ALGORITHM_HMAC256_256 = 5,
  COSE_ALGORITHM_HMAC384_384 = 6,
  COSE_ALGORITHM_HMAC512_512 = 7,
  COSE_ALGORITHM_AES_CCM_16_64_128 = 10,
  COSE_ALGORITHM_AES_CCM_16_64_256 = 11,
  COSE_ALGORITHM_AES_CCM_64_64_128 = 12,
  COSE_ALGORITHM_AES_CCM_64_64_256 = 13,
  COSE_ALGORITHM_CHACHA20_P1035 = 24,
  COSE_ALGORITHM_AES_CCM_16_128_128 = 30,
  COSE_ALGORITHM_AES_CCM_16_128_256 = 31,
  COSE_ALGORITHM_AES_CCM_64_128_128 = 32,
  COSE_ALGORITHM_AES_CCM_64_128_256 = 33,
} cose_alg_t;

/* cose HMAC specific algorithms */
typedef enum {
  COSE_HMAC_ALG_HMAC256_64 = 4, /* truncated to 64 bits */
  COSE_HMAC_ALG_HMAC256_256 = 5,
  COSE_HMAC_ALG_HMAC384_384 = 6,
  COSE_HMAC_ALG_HMAC512_512 = 7,
} cose_hmac_alg_t;

/* cose HKDF specific algorithms */
typedef enum {
  COSE_HKDF_ALG_HKDF_SHA_512 = -11,
  COSE_HKDF_ALG_HKDF_SHA_256 = -10,
} cose_hkdf_alg_t;

const char *cose_get_curve_name(cose_curve_t id, char *buffer, size_t buflen);
cose_curve_t cose_get_curve_id(const char *name);

const char *cose_get_alg_name(cose_alg_t id, char *buffer, size_t buflen);
cose_alg_t cose_get_alg_id(const char *name);

const char *cose_get_hkdf_alg_name(cose_hkdf_alg_t id, char *buffer,
                                   size_t buflen);

int cose_get_hmac_alg_for_hkdf(cose_hkdf_alg_t hkdf_alg,
                               cose_hmac_alg_t *hmac_alg);

/* parameter value functions */

/* return tag length belonging to cose algorithm */
size_t cose_tag_len(cose_alg_t cose_alg);

/* return hash length belonging to cose algorithm */
size_t cose_hash_len(cose_alg_t cose_alg);

/* return nonce length belonging to cose algorithm */
size_t cose_nonce_len(cose_alg_t cose_alg);

/* return key length belonging to cose algorithm */
size_t cose_key_len(cose_alg_t cose_alg);

/* COSE Encrypt0 Struct */
typedef struct cose_encrypt0_t {
  cose_alg_t alg;
  coap_bin_const_t key;
  uint8_t partial_iv_data[8];
  /* partial_iv.s will point back to partial_iv_data if set */
  coap_bin_const_t partial_iv;
  coap_bin_const_t key_id;
  coap_bin_const_t kid_context;
  coap_bin_const_t oscore_option;
  coap_bin_const_t nonce;
  coap_bin_const_t external_aad;
  coap_bin_const_t aad;
  coap_bin_const_t plaintext;
  coap_bin_const_t ciphertext;
} cose_encrypt0_t;

/* Return length */
size_t cose_encrypt0_encode(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size);

/*Return status */
int cose_encrypt0_decode(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size);

/* Initiate a new COSE Encrypt0 object. */
void cose_encrypt0_init(cose_encrypt0_t *ptr);

void cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg);

void cose_encrypt0_set_plaintext(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size);

void cose_encrypt0_set_ciphertext(cose_encrypt0_t *ptr,
                                  uint8_t *buffer,
                                  size_t size);

/* Return length */
int cose_encrypt0_get_plaintext(cose_encrypt0_t *ptr, uint8_t **buffer);

void cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr,
                                  coap_bin_const_t *partial_iv);

coap_bin_const_t cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr);

void cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, coap_bin_const_t *key_id);

/* Return length */
size_t cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, const uint8_t **buffer);

void cose_encrypt0_set_external_aad(cose_encrypt0_t *ptr,
                                    coap_bin_const_t *external_aad);

void cose_encrypt0_set_aad(cose_encrypt0_t *ptr, coap_bin_const_t *aad);

/* Return length */
size_t cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr,
                                     const uint8_t **buffer);

void cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr,
                                   coap_bin_const_t *kid_context);

/* Returns 1 if successfull, 0 if key is of incorrect length. */
int cose_encrypt0_set_key(cose_encrypt0_t *ptr, coap_bin_const_t *key);

void cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, coap_bin_const_t *nonce);

int cose_encrypt0_encrypt(cose_encrypt0_t *ptr,
                          uint8_t *ciphertext_buffer,
                          size_t ciphertext_len);

int cose_encrypt0_decrypt(cose_encrypt0_t *ptr,
                          uint8_t *plaintext_buffer,
                          size_t plaintext_len);

/** @} */

#endif /* _OSCORE_COSE_H */
