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
 * @file oscore_crypto.h
 * @brief An implementation of the Hash Based Key Derivation Function (RFC) and
 * wrappers for AES-CCM*.
 *
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 * adapted to libcoap
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 */

#ifndef _OSCORE_CRYPTO_H
#define _OSCORE_CRYPTO_H

#include <coap3/coap_internal.h>

/**
 * @ingroup internal_api
 * @addtogroup oscore_internal
 * @{
 */

#define HKDF_INFO_MAXLEN   25
#define HKDF_OUTPUT_MAXLEN 25
#define AES_CCM_TAG        8

/* Plaintext Maxlen and Tag Maxlen is quite generous. */
#define AEAD_PLAINTEXT_MAXLEN COAP_MAX_CHUNK_SIZE
#define AEAD_TAG_MAXLEN       COAP_MAX_CHUNK_SIZE

/**
 * Derive the hmac hash using HMAC-HASH() function.
 *
 * @param hmac_alg     The HMAC algorith to use (e.g. sha256).
 * @param key          The key to use.
 * @param data         The data to hash.
 * @param hmac         The result of the hash.
 *
 * @return @c 0 if failure, else @c 1.
 */
int oscore_hmac_hash(cose_hmac_alg_t hmac_alg,
                     coap_bin_const_t *key,
                     coap_bin_const_t *data,
                     coap_bin_const_t **hmac);

/**
 * Derive the pseudorandom key using HKDF-Extract() function.
 * Uses HMAC-HASH() function.
 *
 * @param hkdf_alg     The HKDF algorith to use (e.g. ed25519).
 * @param salt         The optional salt value to use.
 * @param ikm          The Input Keying material.
 * @param hkdf_extract The output pseudorandom key
 *                     (length determined by hkdf_alg).
 *
 * @return @c 0 if failure, else @c 1.
 */
int oscore_hkdf_extract(cose_hkdf_alg_t hkdf_alg,
                        coap_bin_const_t *salt,
                        coap_bin_const_t *ikm,
                        coap_bin_const_t **hkdf_extract);

/**
 * Derive the key using HKDF-Expand() function.
 * Uses HMAC-HASH() function.
 *
 * @param hkdf_alg The HKDF algorith to use (e.g. ed25519).
 * @param prk      Usually ouptut from HKDF-Extract().
 * @param info     Optional context / application specific information.
 * @param info_len Length of info (can be 0).
 * @param okm      Output key material.
 * @param okm_len  Length of output key material (L).
 *
 * @return @c 0 if failure, else @c 1.
 */
int oscore_hkdf_expand(cose_hkdf_alg_t hkdf_alg,
                       coap_bin_const_t *prk,
                       uint8_t *info,
                       size_t info_len,
                       uint8_t *okm,
                       size_t okm_len);

/**
 * Derive the key using HKDF() function.
 * Invokes the HKDF-Extract() and HKDF-Expand() functions.
 *
 * @param hkdf_alg The HKDF algorith to use (e.g. ed25519).
 * @param salt     The optional salt value to use.
 * @param ikm      The Input Keying material.
 * @param info     Optional context / application specific information.
 * @param info_len Length of info (can be 0).
 * @param okm      Output key material.
 * @param okm_len  Length of output key material (L).
 *
 * @return @c 0 if failure, else @c 1.
 */
int oscore_hkdf(cose_hkdf_alg_t hkdf_alg,
                coap_bin_const_t *salt,
                coap_bin_const_t *ikm,
                uint8_t *info,
                size_t info_len,
                uint8_t *okm,
                size_t okm_len);

/** @} */

#endif /* _OSCORE_CRYPTO_H */
