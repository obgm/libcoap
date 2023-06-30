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
 * @file oscore_cose.c
 * @brief An implementation of the CBOR Object Signing and Encryption (RFC).
 *
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * added sign1 addition for coaplib
 *      Peter van der Stok <consultancy@vanderstok.org >
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 */

#include "coap3/coap_internal.h"
#include "stdio.h"

struct cose_curve_desc {
  const char *name;
  cose_curve_t id;
};

static struct cose_curve_desc curve_mapping[] = {
  { "P-256", COSE_CURVE_P_256 },
  { "X25519", COSE_CURVE_X25519 },
  { "X448", COSE_CURVE_X448 },
  { "Ed25519", COSE_CURVE_ED25519 },
  { "Ed448", COSE_CURVE_ED448 },
  { "secp256k1", COSE_CURVE_SECP256K1 },
};

const char *
cose_get_curve_name(cose_curve_t id, char *buffer, size_t buflen) {
  for (size_t i = 0; i < sizeof(curve_mapping)/sizeof(curve_mapping[0]); i++) {
    if (id == curve_mapping[i].id) {
      snprintf(buffer, buflen, "%s (%d)", curve_mapping[i].name, id);
      return buffer;
    }
  }
  snprintf(buffer, buflen, "curve Fix me (%d)", id);
  return buffer;
}

cose_curve_t
cose_get_curve_id(const char *name) {
  for (size_t i = 0; i < sizeof(curve_mapping)/sizeof(curve_mapping[0]); i++) {
    if (strcmp(name, curve_mapping[i].name) == 0)
      return curve_mapping[i].id;
  }
  return 0;
}

struct cose_alg_desc {
  const char *name;
  cose_alg_t id;
};

static struct cose_alg_desc alg_mapping[] = {
  { "ES256K", COSE_ALGORITHM_ES256K },
  { "SHA-512", COSE_ALGORITHM_SHA_512 },
  { "SHA-384", COSE_ALGORITHM_SHA_384 },
  { "ES512", COSE_ALGORITHM_ES512 },
  { "ES384", COSE_ALGORITHM_ES384 },
  { "ECDH-SS + HKDF-256", COSE_ALGORITHM_ECDH_SS_HKDF_256 },
  { "SHA-512/256", COSE_ALGORITHM_SHA_512_256 },
  { "SHA-256", COSE_ALGORITHM_SHA_256_256 },
  { "SHA-256/64", COSE_ALGORITHM_SHA_256_64 },
  { "SHA-1", COSE_ALGORITHM_SHA_1 },
  { "direct+HKDF-SHA-512", COSE_ALGORITHM_HKDF_SHA_512 },
  { "direct+HKDF-SHA-256", COSE_ALGORITHM_HKDF_SHA_256 },
  { "EdDSA", COSE_ALGORITHM_EDDSA },
  { "ES256", COSE_ALGORITHM_ES256 },
  { "HMAC 256/64", COSE_ALGORITHM_HMAC256_64 },
  { "HMAC 256/256", COSE_ALGORITHM_HMAC256_256 },
  { "HMAC 384/384", COSE_ALGORITHM_HMAC384_384 },
  { "HMAC 512/512", COSE_ALGORITHM_HMAC512_512 },
  { "AES-CCM-16-64-128", COSE_ALGORITHM_AES_CCM_16_64_128 },
  { "AES-CCM-16-64-256", COSE_ALGORITHM_AES_CCM_16_64_256 },
  { "AES-CCM-64-64-128", COSE_ALGORITHM_AES_CCM_64_64_128 },
  { "AES-CCM-64-64-256", COSE_ALGORITHM_AES_CCM_64_64_256 },
  { "ChaCha20/Poly1305", COSE_ALGORITHM_CHACHA20_P1035 },
  { "AES-CCM-16-128-128", COSE_ALGORITHM_AES_CCM_16_128_128 },
  { "AES-CCM-16-128-256", COSE_ALGORITHM_AES_CCM_16_128_256 },
  { "AES-CCM-64-128-128", COSE_ALGORITHM_AES_CCM_64_128_128 },
  { "AES-CCM-64-128-256", COSE_ALGORITHM_AES_CCM_64_128_256 },
};

const char *
cose_get_alg_name(cose_alg_t id, char *buffer, size_t buflen) {
  for (size_t i = 0; i < sizeof(alg_mapping)/sizeof(alg_mapping[0]); i++) {
    if (id == alg_mapping[i].id) {
      snprintf(buffer, buflen, "%s (%d)", alg_mapping[i].name, id);
      return buffer;
    }
  }
  snprintf(buffer, buflen, "alg Fix me (%d)", id);
  return buffer;
}

cose_alg_t
cose_get_alg_id(const char *name) {
  for (size_t i = 0; i < sizeof(alg_mapping)/sizeof(alg_mapping[0]); i++) {
    if (strcmp(name, alg_mapping[i].name) == 0)
      return alg_mapping[i].id;
  }
  return 0;
}

struct cose_hkdf_alg_desc {
  const char *name;
  cose_hkdf_alg_t id;
};

static struct cose_hkdf_alg_desc hkdf_alg_mapping[] = {
  { "direct+HKDF-SHA-512", COSE_HKDF_ALG_HKDF_SHA_512 },
  { "direct+HKDF-SHA-256", COSE_HKDF_ALG_HKDF_SHA_256 },
};

const char *
cose_get_hkdf_alg_name(cose_hkdf_alg_t id, char *buffer, size_t buflen) {
  for (size_t i = 0; i < sizeof(hkdf_alg_mapping)/sizeof(hkdf_alg_mapping[0]); i++) {
    if (id == hkdf_alg_mapping[i].id) {
      snprintf(buffer, buflen, "%s (%d)", hkdf_alg_mapping[i].name, id);
      return buffer;
    }
  }
  snprintf(buffer, buflen, "hkdf_alg Fix me (%d)", id);
  return buffer;
}

/*
 * The struct hmac_algs and the function cose_get_hmac_alg_for_hkdf() are
 * used to determine which hmac type to use for the appropriate hkdf
 */
static struct hkdf_hmac_algs {
  cose_hkdf_alg_t hkdf_alg;
  cose_hmac_alg_t hmac_alg;
} hkdf_hmacs[] = {
  {COSE_HKDF_ALG_HKDF_SHA_256, COSE_HMAC_ALG_HMAC256_256},
  {COSE_HKDF_ALG_HKDF_SHA_512, COSE_HMAC_ALG_HMAC512_512},
};

/*
 * return 0 fail
 *        1 OK
 */
int
cose_get_hmac_alg_for_hkdf(cose_hkdf_alg_t hkdf_alg, cose_hmac_alg_t *hmac_alg) {
  size_t idx;

  for (idx = 0; idx < sizeof(hkdf_hmacs) / sizeof(struct hkdf_hmac_algs);
       idx++) {
    if (hkdf_hmacs[idx].hkdf_alg == hkdf_alg) {
      *hmac_alg = hkdf_hmacs[idx].hmac_alg;
      return 1;
    }
  }
  coap_log_debug("cose_get_hmac_alg_for_hkdf: COSE HKDF %d not supported\n",
                 hkdf_alg);
  return 0;
}

/* return tag length belonging to cose algorithm */
size_t
cose_tag_len(cose_alg_t cose_alg) {
  switch ((int)cose_alg) {
  case COSE_ALGORITHM_AES_CCM_16_64_128:
    return COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;
  case COSE_ALGORITHM_AES_CCM_64_64_128:
    return COSE_ALGORITHM_AES_CCM_64_64_128_TAG_LEN;
  case COSE_ALGORITHM_AES_CCM_16_128_128:
    return COSE_ALGORITHM_AES_CCM_16_128_128_TAG_LEN;
  case COSE_ALGORITHM_AES_CCM_64_128_128:
    return COSE_ALGORITHM_AES_CCM_64_128_128_TAG_LEN;
  default:
    return 0;
  }
}

/* return hash length belonging to cose algorithm */
size_t
cose_hash_len(cose_alg_t cose_alg) {
  switch ((int)cose_alg) {
  case COSE_ALGORITHM_ES256:
    return COSE_ALGORITHM_HMAC256_256_HASH_LEN;
  case COSE_ALGORITHM_ES512:
    return COSE_ALGORITHM_ES512_HASH_LEN;
  case COSE_ALGORITHM_ES384:
    return COSE_ALGORITHM_ES384_HASH_LEN;
  case COSE_ALGORITHM_HMAC256_64:
    return COSE_ALGORITHM_HMAC256_64_HASH_LEN;
  case COSE_ALGORITHM_HMAC256_256:
    return COSE_ALGORITHM_HMAC256_256_HASH_LEN;
  case COSE_ALGORITHM_HMAC384_384:
    return COSE_ALGORITHM_HMAC384_384_HASH_LEN;
  case COSE_ALGORITHM_HMAC512_512:
    return COSE_ALGORITHM_HMAC512_512_HASH_LEN;
  case COSE_ALGORITHM_SHA_256_64:
    return COSE_ALGORITHM_SHA_256_64_LEN;
  case COSE_ALGORITHM_SHA_256_256:
    return COSE_ALGORITHM_SHA_256_256_LEN;
  case COSE_ALGORITHM_SHA_512_256:
    return COSE_ALGORITHM_SHA_512_256_LEN;
  case COSE_ALGORITHM_SHA_512:
    return COSE_ALGORITHM_SHA_512_LEN;
  default:
    return 0;
  }
}

/* return nonce length belonging to cose algorithm */
size_t
cose_nonce_len(cose_alg_t cose_alg) {
  switch ((int)cose_alg) {
  case COSE_ALGORITHM_AES_CCM_16_64_128:
    return COSE_ALGORITHM_AES_CCM_16_64_128_NONCE_LEN;
  case COSE_ALGORITHM_AES_CCM_64_64_128:
    return COSE_ALGORITHM_AES_CCM_64_64_128_NONCE_LEN;
  case COSE_ALGORITHM_AES_CCM_16_128_128:
    return COSE_ALGORITHM_AES_CCM_16_128_128_NONCE_LEN;
  case COSE_ALGORITHM_AES_CCM_64_128_128:
    return COSE_ALGORITHM_AES_CCM_64_128_128_NONCE_LEN;
  default:
    return 0;
  }
}

/* return key length belonging to cose algorithm */
size_t
cose_key_len(cose_alg_t cose_alg) {
  switch ((int)cose_alg) {
  case COSE_ALGORITHM_AES_CCM_16_64_128:
    return COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN;
  case COSE_ALGORITHM_AES_CCM_64_64_128:
    return COSE_ALGORITHM_AES_CCM_64_64_128_KEY_LEN;
  case COSE_ALGORITHM_AES_CCM_16_128_128:
    return COSE_ALGORITHM_AES_CCM_16_128_128_KEY_LEN;
  case COSE_ALGORITHM_AES_CCM_64_128_128:
    return COSE_ALGORITHM_AES_CCM_64_128_128_KEY_LEN;
  default:
    return 0;
  }
}

/* Return length */
size_t
cose_encrypt0_encode(cose_encrypt0_t *ptr, uint8_t *buffer, size_t buf_len) {
  size_t ret = 0;
  size_t rem_size = buf_len;

  ret += oscore_cbor_put_array(&buffer, &rem_size, 3);
  ret += oscore_cbor_put_bytes(&buffer, &rem_size, NULL, 0);
  /* ret += cose encode attributyes */
  ret += oscore_cbor_put_bytes(&buffer,
                               &rem_size,
                               ptr->ciphertext.s,
                               ptr->ciphertext.length);
  return ret;
}

/*Return status */
int cose_encrypt0_decode(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size);

/* Initiate a new COSE Encrypt0 object. */
void
cose_encrypt0_init(cose_encrypt0_t *ptr) {
  memset(ptr, 0, sizeof(cose_encrypt0_t));
}

void
cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg) {
  ptr->alg = alg;
}

void
cose_encrypt0_set_ciphertext(cose_encrypt0_t *ptr,
                             uint8_t *buffer,
                             size_t size) {
  ptr->ciphertext.s = buffer;
  ptr->ciphertext.length = size;
}

void
cose_encrypt0_set_plaintext(cose_encrypt0_t *ptr,
                            uint8_t *buffer,
                            size_t size) {
  ptr->plaintext.s = buffer;
  ptr->plaintext.length = size;
}
/* Return length */
int cose_encrypt0_get_plaintext(cose_encrypt0_t *ptr, uint8_t **buffer);

void
cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr,
                             coap_bin_const_t *partial_iv) {
  if (partial_iv == NULL || partial_iv->length == 0) {
    ptr->partial_iv.s = NULL;
    ptr->partial_iv.length = 0;
  } else {
    if (partial_iv->length > (int)sizeof(ptr->partial_iv_data))
      partial_iv->length = sizeof(ptr->partial_iv_data);
    memcpy(ptr->partial_iv_data, partial_iv->s, partial_iv->length);
    ptr->partial_iv.s = ptr->partial_iv_data;
    ptr->partial_iv.length = partial_iv->length;
  }
}

/* Return length */
coap_bin_const_t
cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr) {
  return ptr->partial_iv;
}

void
cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, coap_bin_const_t *key_id) {
  if (key_id) {
    ptr->key_id = *key_id;
  } else {
    ptr->key_id.length = 0;
    ptr->key_id.s = NULL;
  }
}
/* Return length */
size_t
cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, const uint8_t **buffer) {
  *buffer = ptr->key_id.s;
  return ptr->key_id.length;
}

size_t
cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr, const uint8_t **buffer) {
  *buffer = ptr->kid_context.s;
  return ptr->kid_context.length;
}

void
cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr,
                              coap_bin_const_t *kid_context) {
  if (kid_context) {
    ptr->kid_context = *kid_context;
  } else {
    ptr->kid_context.length = 0;
    ptr->kid_context.s = NULL;
  }
}

void
cose_encrypt0_set_external_aad(cose_encrypt0_t *ptr,
                               coap_bin_const_t *external_aad) {
  if (external_aad) {
    ptr->external_aad = *external_aad;
  } else {
    ptr->external_aad.length = 0;
    ptr->external_aad.s = NULL;
  }
}

void
cose_encrypt0_set_aad(cose_encrypt0_t *ptr, coap_bin_const_t *aad) {
  if (aad) {
    ptr->aad = *aad;
  } else {
    ptr->aad.length = 0;
    ptr->aad.s = NULL;
  }
}

/* Returns 1 if successfull, 0 if key is of incorrect length. */
int
cose_encrypt0_set_key(cose_encrypt0_t *ptr, coap_bin_const_t *key) {
  if (key == NULL || key->length != 16) {
    return 0;
  }

  ptr->key = *key;
  return 1;
}

void
cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, coap_bin_const_t *nonce) {
  if (nonce) {
    ptr->nonce = *nonce;
  } else {
    ptr->nonce.length = 0;
    ptr->nonce.s = NULL;
  }
}

int
cose_encrypt0_encrypt(cose_encrypt0_t *ptr,
                      uint8_t *ciphertext_buffer,
                      size_t ciphertext_len) {
  coap_crypto_param_t params;
  size_t tag_len = cose_tag_len(ptr->alg);
  size_t max_result_len = ptr->plaintext.length + tag_len;

  if (ptr->key.s == NULL || ptr->key.length != (size_t)cose_key_len(ptr->alg)) {
    return -1;
  }
  if (ptr->nonce.s == NULL ||
      ptr->nonce.length != (size_t)cose_nonce_len(ptr->alg)) {
    return -2;
  }
  if (ptr->aad.s == NULL || ptr->aad.length == 0) {
    return -3;
  }
  if (ptr->plaintext.s == NULL ||
      (ptr->plaintext.length + tag_len) > ciphertext_len) {
    return -4;
  }

  memset(&params, 0, sizeof(params));
  params.alg = ptr->alg;
  params.params.aes.key = ptr->key;
  params.params.aes.nonce = ptr->nonce.s;
  params.params.aes.tag_len = tag_len;
  params.params.aes.l = 15 - ptr->nonce.length;
  if (!coap_crypto_aead_encrypt(&params,
                                &ptr->plaintext,
                                &ptr->aad,
                                ciphertext_buffer,
                                &max_result_len)) {
    return -5;
  }
  return (int)max_result_len;
}

int
cose_encrypt0_decrypt(cose_encrypt0_t *ptr,
                      uint8_t *plaintext_buffer,
                      size_t plaintext_len) {
  int ret_len = 0;
  coap_crypto_param_t params;
  size_t tag_len = cose_tag_len(ptr->alg);
  size_t max_result_len = ptr->ciphertext.length - tag_len;

  if (ptr->key.s == NULL || ptr->key.length != (size_t)cose_key_len(ptr->alg)) {
    return -1;
  }
  if (ptr->nonce.s == NULL ||
      ptr->nonce.length != (size_t)cose_nonce_len(ptr->alg)) {
    return -2;
  }
  if (ptr->aad.s == NULL || ptr->aad.length == 0) {
    return -3;
  }
  if (ptr->ciphertext.s == NULL ||
      ptr->ciphertext.length > (plaintext_len + tag_len)) {
    return -4;
  }

  memset(&params, 0, sizeof(params));
  params.alg = ptr->alg;
  params.params.aes.key = ptr->key;
  params.params.aes.nonce = ptr->nonce.s;
  params.params.aes.tag_len = tag_len;
  params.params.aes.l = 15 - ptr->nonce.length;
  if (!coap_crypto_aead_decrypt(&params,
                                &ptr->ciphertext,
                                &ptr->aad,
                                plaintext_buffer,
                                &max_result_len)) {
    return -5;
  }
  ret_len = (int)max_result_len;
  return ret_len;
}
