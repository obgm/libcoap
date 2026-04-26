/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* libcoap unit tests
 *
 * Copyright (C) 2021-2026 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "test_common.h"

#if COAP_OSCORE_SUPPORT && COAP_SERVER_SUPPORT
#include "test_oscore.h"
#include "oscore/oscore.h"
#include "oscore/oscore_context.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static coap_context_t *ctx; /* Holds the coap context for most tests */

#define CHECK_SAME(a,b) \
  (sizeof((a)) == (b)->length && memcmp((a), (b)->s, (b)->length) == 0)

#define FailIf_CU_ASSERT_PTR_NOT_NULL(value) CU_ASSERT_PTR_NOT_NULL(value); if ((void*)value == NULL) goto fail

/************************************************************************
 ** RFC8613 tests
 ************************************************************************/

/* C.1.1.  Test Vector 1: Key Derivation with Master Salt, Client */
static void
t_oscore_c_1_1(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "sender_id,hex,\"\"\n"
      "recipient_id,hex,\"01\"\n";
  static const uint8_t sender_key[] = {
    0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4,
    0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff
  };
  static const uint8_t recipient_key[] = {
    0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca,
    0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10
  };
  static const uint8_t common_iv[] = {
    0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
    0xee, 0xfb, 0x54, 0x98, 0x7c
  };
  static const uint8_t sender_nonce[] = {
    0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
    0xee, 0xfb, 0x54, 0x98, 0x7c
  };
  static const uint8_t recipient_nonce[] = {
    0x47, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x69,
    0xee, 0xfb, 0x54, 0x98, 0x7c
  };
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  cose_encrypt0_t cose[1];
  uint8_t nonce_buffer[13];
  coap_bin_const_t nonce = { 13, nonce_buffer };

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  CU_ASSERT(CHECK_SAME(sender_key, ctx->p_osc_ctx->sender_context->sender_key));
  CU_ASSERT(CHECK_SAME(recipient_key,
                       ctx->p_osc_ctx->recipient_chain->recipient_key));
  CU_ASSERT(CHECK_SAME(common_iv, ctx->p_osc_ctx->common_iv));

  cose_encrypt0_init(cose);
  cose_encrypt0_set_key_id(cose, ctx->p_osc_ctx->recipient_chain->recipient_id);
  cose_encrypt0_set_partial_iv(cose, NULL);
  oscore_generate_nonce(cose, ctx->p_osc_ctx, nonce_buffer, 13);
  CU_ASSERT(CHECK_SAME(recipient_nonce, &nonce));

  cose_encrypt0_init(cose);
  cose_encrypt0_set_key_id(cose, ctx->p_osc_ctx->sender_context->sender_id);
  cose_encrypt0_set_partial_iv(cose, NULL);
  oscore_generate_nonce(cose, ctx->p_osc_ctx, nonce_buffer, 13);
  CU_ASSERT(CHECK_SAME(sender_nonce, &nonce));

fail:
  oscore_free_contexts(ctx);
}

/* C.1.2.  Test Vector 1: Key Derivation with Master Salt, Server */
static void
t_oscore_c_1_2(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "sender_id,hex,\"01\"\n"
      "recipient_id,hex,\"\"\n";
  static const uint8_t sender_key[] = {
    0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca,
    0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10
  };
  static const uint8_t recipient_key[] = {
    0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4,
    0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff
  };
  static const uint8_t common_iv[] = {
    0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
    0xee, 0xfb, 0x54, 0x98, 0x7c
  };
  static const uint8_t sender_nonce[] = {
    0x47, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x69,
    0xee, 0xfb, 0x54, 0x98, 0x7c
  };
  static const uint8_t recipient_nonce[] = {
    0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
    0xee, 0xfb, 0x54, 0x98, 0x7c
  };
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  cose_encrypt0_t cose[1];
  uint8_t nonce_buffer[13];
  coap_bin_const_t nonce = { 13, nonce_buffer };

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  CU_ASSERT(CHECK_SAME(sender_key, ctx->p_osc_ctx->sender_context->sender_key));
  CU_ASSERT(CHECK_SAME(recipient_key,
                       ctx->p_osc_ctx->recipient_chain->recipient_key));
  CU_ASSERT(CHECK_SAME(common_iv, ctx->p_osc_ctx->common_iv));

  cose_encrypt0_init(cose);
  cose_encrypt0_set_key_id(cose, ctx->p_osc_ctx->recipient_chain->recipient_id);
  cose_encrypt0_set_partial_iv(cose, NULL);
  oscore_generate_nonce(cose, ctx->p_osc_ctx, nonce_buffer, 13);
  CU_ASSERT(CHECK_SAME(recipient_nonce, &nonce));

  cose_encrypt0_init(cose);
  cose_encrypt0_set_key_id(cose, ctx->p_osc_ctx->sender_context->sender_id);
  cose_encrypt0_set_partial_iv(cose, NULL);
  oscore_generate_nonce(cose, ctx->p_osc_ctx, nonce_buffer, 13);
  CU_ASSERT(CHECK_SAME(sender_nonce, &nonce));

fail:
  oscore_free_contexts(ctx);
}

/* C.2.1.  Test Vector 2: Key Derivation without Master Salt, Client */
static void
t_oscore_c_2_1(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,hex,\"00\"\n"
      "recipient_id,hex,\"01\"\n";
  static const uint8_t sender_key[] = {
    0x32, 0x1b, 0x26, 0x94, 0x32, 0x53, 0xc7, 0xff,
    0xb6, 0x00, 0x3b, 0x0b, 0x64, 0xd7, 0x40, 0x41
  };
  static const uint8_t recipient_key[] = {
    0xe5, 0x7b, 0x56, 0x35, 0x81, 0x51, 0x77, 0xcd,
    0x67, 0x9a, 0xb4, 0xbc, 0xec, 0x9d, 0x7d, 0xda
  };
  static const uint8_t common_iv[] = {
    0xbe, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9,
    0x10, 0xc5, 0x2e, 0x99, 0xf9
  };
  static const uint8_t sender_nonce[] = {
    0xbf, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9,
    0x10, 0xc5, 0x2e, 0x99, 0xf9
  };
  static const uint8_t recipient_nonce[] = {
    0xbf, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe8,
    0x10, 0xc5, 0x2e, 0x99, 0xf9
  };
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  cose_encrypt0_t cose[1];
  uint8_t nonce_buffer[13];
  coap_bin_const_t nonce = { 13, nonce_buffer };

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  CU_ASSERT(CHECK_SAME(sender_key, ctx->p_osc_ctx->sender_context->sender_key));
  CU_ASSERT(CHECK_SAME(recipient_key,
                       ctx->p_osc_ctx->recipient_chain->recipient_key));
  CU_ASSERT(CHECK_SAME(common_iv, ctx->p_osc_ctx->common_iv));

  cose_encrypt0_init(cose);
  cose_encrypt0_set_key_id(cose, ctx->p_osc_ctx->recipient_chain->recipient_id);
  cose_encrypt0_set_partial_iv(cose, NULL);
  oscore_generate_nonce(cose, ctx->p_osc_ctx, nonce_buffer, 13);
  CU_ASSERT(CHECK_SAME(recipient_nonce, &nonce));

  cose_encrypt0_init(cose);
  cose_encrypt0_set_key_id(cose, ctx->p_osc_ctx->sender_context->sender_id);
  cose_encrypt0_set_partial_iv(cose, NULL);
  oscore_generate_nonce(cose, ctx->p_osc_ctx, nonce_buffer, 13);
  CU_ASSERT(CHECK_SAME(sender_nonce, &nonce));

fail:
  oscore_free_contexts(ctx);
}

/* C.2.2.  Test Vector 2: Key Derivation without Master Salt, Server */
static void
t_oscore_c_2_2(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,hex,\"01\"\n"
      "recipient_id,hex,\"00\"\n";
  static const uint8_t sender_key[] = {
    0xe5, 0x7b, 0x56, 0x35, 0x81, 0x51, 0x77, 0xcd,
    0x67, 0x9a, 0xb4, 0xbc, 0xec, 0x9d, 0x7d, 0xda
  };
  static const uint8_t recipient_key[] = {
    0x32, 0x1b, 0x26, 0x94, 0x32, 0x53, 0xc7, 0xff,
    0xb6, 0x00, 0x3b, 0x0b, 0x64, 0xd7, 0x40, 0x41
  };
  static const uint8_t common_iv[] = {
    0xbe, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9,
    0x10, 0xc5, 0x2e, 0x99, 0xf9
  };
  static const uint8_t sender_nonce[] = {
    0xbf, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe8,
    0x10, 0xc5, 0x2e, 0x99, 0xf9
  };
  static const uint8_t recipient_nonce[] = {
    0xbf, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9,
    0x10, 0xc5, 0x2e, 0x99, 0xf9
  };
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  cose_encrypt0_t cose[1];
  uint8_t nonce_buffer[13];
  coap_bin_const_t nonce = { 13, nonce_buffer };

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  CU_ASSERT(CHECK_SAME(sender_key, ctx->p_osc_ctx->sender_context->sender_key));
  CU_ASSERT(CHECK_SAME(recipient_key,
                       ctx->p_osc_ctx->recipient_chain->recipient_key));
  CU_ASSERT(CHECK_SAME(common_iv, ctx->p_osc_ctx->common_iv));

  cose_encrypt0_init(cose);
  cose_encrypt0_set_key_id(cose, ctx->p_osc_ctx->recipient_chain->recipient_id);
  cose_encrypt0_set_partial_iv(cose, NULL);
  oscore_generate_nonce(cose, ctx->p_osc_ctx, nonce_buffer, 13);
  CU_ASSERT(CHECK_SAME(recipient_nonce, &nonce));

  cose_encrypt0_init(cose);
  cose_encrypt0_set_key_id(cose, ctx->p_osc_ctx->sender_context->sender_id);
  cose_encrypt0_set_partial_iv(cose, NULL);
  oscore_generate_nonce(cose, ctx->p_osc_ctx, nonce_buffer, 13);
  CU_ASSERT(CHECK_SAME(sender_nonce, &nonce));

fail:
  oscore_free_contexts(ctx);
}

/* C.3.1.  Test Vector 3: Key Derivation with ID Context, Client */
static void
t_oscore_c_3_1(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "id_context,hex,\"37cbf3210017a2d3\"\n"
      "sender_id,hex,\"\"\n"
      "recipient_id,hex,\"01\"\n";
  static const uint8_t sender_key[] = {
    0xaf, 0x2a, 0x13, 0x00, 0xa5, 0xe9, 0x57, 0x88,
    0xb3, 0x56, 0x33, 0x6e, 0xee, 0xcd, 0x2b, 0x92
  };
  static const uint8_t recipient_key[] = {
    0xe3, 0x9a, 0x0c, 0x7c, 0x77, 0xb4, 0x3f, 0x03,
    0xb4, 0xb3, 0x9a, 0xb9, 0xa2, 0x68, 0x69, 0x9f
  };
  static const uint8_t common_iv[] = {
    0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c,
    0x0b, 0x71, 0x81, 0xb8, 0x5e
  };
  static const uint8_t sender_nonce[] = {
    0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c,
    0x0b, 0x71, 0x81, 0xb8, 0x5e
  };
  static const uint8_t recipient_nonce[] = {
    0x2d, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1d,
    0x0b, 0x71, 0x81, 0xb8, 0x5e
  };
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  cose_encrypt0_t cose[1];
  uint8_t nonce_buffer[13];
  coap_bin_const_t nonce = { 13, nonce_buffer };

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  CU_ASSERT(CHECK_SAME(sender_key, ctx->p_osc_ctx->sender_context->sender_key));
  CU_ASSERT(CHECK_SAME(recipient_key,
                       ctx->p_osc_ctx->recipient_chain->recipient_key));
  CU_ASSERT(CHECK_SAME(common_iv, ctx->p_osc_ctx->common_iv));

  cose_encrypt0_init(cose);
  cose_encrypt0_set_key_id(cose, ctx->p_osc_ctx->recipient_chain->recipient_id);
  cose_encrypt0_set_partial_iv(cose, NULL);
  oscore_generate_nonce(cose, ctx->p_osc_ctx, nonce_buffer, 13);
  CU_ASSERT(CHECK_SAME(recipient_nonce, &nonce));

  cose_encrypt0_init(cose);
  cose_encrypt0_set_key_id(cose, ctx->p_osc_ctx->sender_context->sender_id);
  cose_encrypt0_set_partial_iv(cose, NULL);
  oscore_generate_nonce(cose, ctx->p_osc_ctx, nonce_buffer, 13);
  CU_ASSERT(CHECK_SAME(sender_nonce, &nonce));

fail:
  oscore_free_contexts(ctx);
}

/* C.3.2.  Test Vector 3: Key Derivation with ID Context, Server */
static void
t_oscore_c_3_2(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "id_context,hex,\"37cbf3210017a2d3\"\n"
      "sender_id,hex,\"01\"\n"
      "recipient_id,hex,\"\"\n";
  static const uint8_t sender_key[] = {
    0xe3, 0x9a, 0x0c, 0x7c, 0x77, 0xb4, 0x3f, 0x03,
    0xb4, 0xb3, 0x9a, 0xb9, 0xa2, 0x68, 0x69, 0x9f
  };
  static const uint8_t recipient_key[] = {
    0xaf, 0x2a, 0x13, 0x00, 0xa5, 0xe9, 0x57, 0x88,
    0xb3, 0x56, 0x33, 0x6e, 0xee, 0xcd, 0x2b, 0x92
  };
  static const uint8_t common_iv[] = {
    0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c,
    0x0b, 0x71, 0x81, 0xb8, 0x5e
  };
  static const uint8_t sender_nonce[] = {
    0x2d, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1d,
    0x0b, 0x71, 0x81, 0xb8, 0x5e
  };
  static const uint8_t recipient_nonce[] = {
    0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c,
    0x0b, 0x71, 0x81, 0xb8, 0x5e
  };
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  cose_encrypt0_t cose[1];
  uint8_t nonce_buffer[13];
  coap_bin_const_t nonce = { 13, nonce_buffer };

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  CU_ASSERT(CHECK_SAME(sender_key, ctx->p_osc_ctx->sender_context->sender_key));
  CU_ASSERT(CHECK_SAME(recipient_key,
                       ctx->p_osc_ctx->recipient_chain->recipient_key));
  CU_ASSERT(CHECK_SAME(common_iv, ctx->p_osc_ctx->common_iv));

  cose_encrypt0_init(cose);
  cose_encrypt0_set_key_id(cose, ctx->p_osc_ctx->recipient_chain->recipient_id);
  cose_encrypt0_set_partial_iv(cose, NULL);
  oscore_generate_nonce(cose, ctx->p_osc_ctx, nonce_buffer, 13);
  CU_ASSERT(CHECK_SAME(recipient_nonce, &nonce));

  cose_encrypt0_init(cose);
  cose_encrypt0_set_key_id(cose, ctx->p_osc_ctx->sender_context->sender_id);
  cose_encrypt0_set_partial_iv(cose, NULL);
  oscore_generate_nonce(cose, ctx->p_osc_ctx, nonce_buffer, 13);
  CU_ASSERT(CHECK_SAME(sender_nonce, &nonce));

fail:
  oscore_free_contexts(ctx);
}

/* C.4.  Test Vector 4: OSCORE Request, Client */
static void
t_oscore_c_4(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "sender_id,hex,\"\"\n"
      "recipient_id,hex,\"01\"\n";
  static const uint8_t unprotected_coap_request[] = {
    0x44, 0x01, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x83, 0x74, 0x76, 0x31
  };
  static const uint8_t protected_coap_request[] = {
    0x44, 0x02, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x62, 0x09, 0x14, 0xff, 0x61, 0x2f,
    0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c, 0x16, 0x68,
    0xb3, 0x82, 0x5e
  };
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  int result;
  coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU);
  coap_pdu_t *osc_pdu = NULL;
  coap_session_t *session = NULL;

  FailIf_CU_ASSERT_PTR_NOT_NULL(pdu);

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 20);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  result = coap_pdu_parse(COAP_PROTO_UDP, unprotected_coap_request,
                          sizeof(unprotected_coap_request), pdu);
  CU_ASSERT(result > 0);

  session = coap_malloc_type(COAP_SESSION, sizeof(coap_session_t));
  FailIf_CU_ASSERT_PTR_NOT_NULL(session);
  memset(session, 0, sizeof(coap_session_t));
  session->context = ctx;
  session->proto = COAP_PROTO_UDP;
  session->type = COAP_SESSION_TYPE_CLIENT;
  session->recipient_ctx = ctx->p_osc_ctx->recipient_chain;

  osc_pdu = coap_oscore_new_pdu_encrypted(session, pdu, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_pdu);

  result = coap_pdu_encode_header(osc_pdu, session->proto);
  CU_ASSERT(result != 0);
  CU_ASSERT(osc_pdu->hdr_size + osc_pdu->used_size ==
            sizeof(protected_coap_request));
  result = memcmp(&osc_pdu->token[-osc_pdu->hdr_size], protected_coap_request,
                  osc_pdu->hdr_size + osc_pdu->used_size);
  CU_ASSERT(result == 0);

fail:
  oscore_free_contexts(ctx);
  coap_delete_pdu(pdu);
  coap_delete_pdu(osc_pdu);
  oscore_delete_server_associations(session);
  coap_free(session);
}

/* C.5.  Test Vector 5: OSCORE Request, Client */
static void
t_oscore_c_5(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,hex,\"00\"\n"
      "recipient_id,hex,\"01\"\n";
  static const uint8_t unprotected_coap_request[] = {
    0x44, 0x01, 0x71, 0xc3, 0x00, 0x00, 0xb9, 0x32,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x83, 0x74, 0x76, 0x31
  };
  static const uint8_t protected[] = {
    0x44, 0x02, 0x71, 0xc3, 0x00, 0x00, 0xb9, 0x32,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x63, 0x09, 0x14, 0x00, 0xff, 0x4e,
    0xd3, 0x39, 0xa5, 0xa3, 0x79, 0xb0, 0xb8, 0xbc,
    0x73, 0x1f, 0xff, 0xb0
  };
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  int result;
  coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU);
  coap_pdu_t *osc_pdu = NULL;
  coap_session_t *session = NULL;

  FailIf_CU_ASSERT_PTR_NOT_NULL(pdu);

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 20);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  result = coap_pdu_parse(COAP_PROTO_UDP, unprotected_coap_request,
                          sizeof(unprotected_coap_request), pdu);
  CU_ASSERT(result > 0);

  session = coap_malloc_type(COAP_SESSION, sizeof(coap_session_t));
  FailIf_CU_ASSERT_PTR_NOT_NULL(session);
  memset(session, 0, sizeof(coap_session_t));
  session->context = ctx;
  session->proto = COAP_PROTO_UDP;
  session->type = COAP_SESSION_TYPE_CLIENT;
  session->recipient_ctx = ctx->p_osc_ctx->recipient_chain;

  osc_pdu = coap_oscore_new_pdu_encrypted(session, pdu, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_pdu);

  result = coap_pdu_encode_header(osc_pdu, session->proto);
  CU_ASSERT(result != 0);
  CU_ASSERT(osc_pdu->hdr_size + osc_pdu->used_size == sizeof(protected));
  result = memcmp(&osc_pdu->token[-osc_pdu->hdr_size], protected,
                  osc_pdu->hdr_size + osc_pdu->used_size);
  CU_ASSERT(result == 0);

fail:
  oscore_free_contexts(ctx);
  coap_delete_pdu(pdu);
  coap_delete_pdu(osc_pdu);
  oscore_delete_server_associations(session);
  coap_free(session);
}

/* C.6.  Test Vector 6: OSCORE Request, Client */
static void
t_oscore_c_6(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "id_context,hex,\"37cbf3210017a2d3\"\n"
      "sender_id,hex,\"\"\n"
      "recipient_id,hex,\"01\"\n";
  static const uint8_t unprotected_coap_request[] = {
    0x44, 0x01, 0x2f, 0x8e, 0xef, 0x9b, 0xbf, 0x7a,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x83, 0x74, 0x76, 0x31
  };
  static const uint8_t protected[] = {
    0x44, 0x02, 0x2f, 0x8e, 0xef, 0x9b, 0xbf, 0x7a,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x6b, 0x19, 0x14, 0x08, 0x37, 0xcb,
    0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3, 0xff, 0x72,
    0xcd, 0x72, 0x73, 0xfd, 0x33, 0x1a, 0xc4, 0x5c,
    0xff, 0xbe, 0x55, 0xc3
  };
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  int result;
  coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU);
  coap_pdu_t *osc_pdu = NULL;
  coap_session_t *session = NULL;

  FailIf_CU_ASSERT_PTR_NOT_NULL(pdu);

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 20);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  result = coap_pdu_parse(COAP_PROTO_UDP, unprotected_coap_request,
                          sizeof(unprotected_coap_request), pdu);
  CU_ASSERT(result > 0);

  session = coap_malloc_type(COAP_SESSION, sizeof(coap_session_t));
  FailIf_CU_ASSERT_PTR_NOT_NULL(session);
  memset(session, 0, sizeof(coap_session_t));
  session->context = ctx;
  session->proto = COAP_PROTO_UDP;
  session->type = COAP_SESSION_TYPE_CLIENT;
  session->recipient_ctx = ctx->p_osc_ctx->recipient_chain;

  osc_pdu = coap_oscore_new_pdu_encrypted(session, pdu, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_pdu);

  result = coap_pdu_encode_header(osc_pdu, session->proto);
  CU_ASSERT(result != 0);
  CU_ASSERT(osc_pdu->hdr_size + osc_pdu->used_size == sizeof(protected));
  result = memcmp(&osc_pdu->token[-osc_pdu->hdr_size], protected,
                  osc_pdu->hdr_size + osc_pdu->used_size);
  CU_ASSERT(result == 0);

fail:
  oscore_free_contexts(ctx);
  coap_delete_pdu(pdu);
  coap_delete_pdu(osc_pdu);
  oscore_delete_server_associations(session);
  coap_free(session);
}

/* C.7.  Test Vector 7: OSCORE Response, Server */
static void
t_oscore_c_7(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "sender_id,hex,\"01\"\n"
      "recipient_id,hex,\"\"\n";
  static const uint8_t protected_coap_request[] = {
    0x44, 0x02, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x62, 0x09, 0x14, 0xff, 0x61, 0x2f,
    0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c, 0x16, 0x68,
    0xb3, 0x82, 0x5e
  };
  static const uint8_t unprotected_coap_request[] = {
    0x44, 0x01, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x83, 0x74, 0x76, 0x31
  };
  static const uint8_t unprotected_coap_response[] = {
    0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57,
    0x6f, 0x72, 0x6c, 0x64, 0x21
  };
  static const uint8_t protected_coap_response[] = {
    0x64, 0x44, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x90, 0xff, 0xdb, 0xaa, 0xd1, 0xe9, 0xa7, 0xe7,
    0xb2, 0xa8, 0x13, 0xd3, 0xc3, 0x15, 0x24, 0x37,
    0x83, 0x03, 0xcd, 0xaf, 0xae, 0x11, 0x91, 0x06
  };
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  int result;
  coap_pdu_t *incoming_pdu = coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU);
  coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU);
  coap_pdu_t *osc_pdu = NULL;
  coap_session_t *session = NULL;

  FailIf_CU_ASSERT_PTR_NOT_NULL(incoming_pdu);
  FailIf_CU_ASSERT_PTR_NOT_NULL(pdu);

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  result = coap_pdu_parse(COAP_PROTO_UDP, protected_coap_request,
                          sizeof(protected_coap_request), incoming_pdu);
  CU_ASSERT(result > 0);

  result = coap_pdu_parse(COAP_PROTO_UDP, unprotected_coap_response,
                          sizeof(unprotected_coap_response), pdu);
  CU_ASSERT(result > 0);

  session = coap_malloc_type(COAP_SESSION, sizeof(coap_session_t));
  FailIf_CU_ASSERT_PTR_NOT_NULL(session);
  memset(session, 0, sizeof(coap_session_t));
  session->context = ctx;
  session->proto = COAP_PROTO_UDP;
  session->type = COAP_SESSION_TYPE_SERVER;
  session->recipient_ctx = ctx->p_osc_ctx->recipient_chain;
  session->recipient_ctx->initial_state = 0;
  session->context = ctx;

  /* First, decrypt incoming request to set up all variables for
     sending response */
  osc_pdu = coap_oscore_decrypt_pdu(session, incoming_pdu);
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_pdu);
  result = coap_pdu_encode_header(osc_pdu, session->proto);
  CU_ASSERT(result != 0);
  CU_ASSERT(osc_pdu->hdr_size + osc_pdu->used_size ==
            sizeof(unprotected_coap_request));
  result = memcmp(&osc_pdu->token[-osc_pdu->hdr_size], unprotected_coap_request,
                  osc_pdu->hdr_size + osc_pdu->used_size);
  CU_ASSERT(result == 0);
  coap_delete_pdu(osc_pdu);
  osc_pdu = NULL;
  coap_delete_pdu(incoming_pdu);
  incoming_pdu = NULL;

  /* Now encrypt the server's response */
  osc_pdu = coap_oscore_new_pdu_encrypted(session, pdu, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_pdu);

  result = coap_pdu_encode_header(osc_pdu, session->proto);
  CU_ASSERT(result != 0);
  CU_ASSERT(osc_pdu->hdr_size + osc_pdu->used_size ==
            sizeof(protected_coap_response));
  result = memcmp(&osc_pdu->token[-osc_pdu->hdr_size], protected_coap_response,
                  osc_pdu->hdr_size + osc_pdu->used_size);
  CU_ASSERT(result == 0);

fail:
  oscore_free_contexts(ctx);
  coap_delete_pdu(pdu);
  coap_delete_pdu(incoming_pdu);
  coap_delete_pdu(osc_pdu);
  oscore_delete_server_associations(session);
  coap_free(session);
}

/*
 * Decrypt the encrypted response from C.7 and check it matches input
 */
static void
t_oscore_c_7_2(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "sender_id,hex,\"\"\n"
      "recipient_id,hex,\"01\"\n";
  static const uint8_t unprotected_coap_request[] = {
    0x44, 0x01, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x83, 0x74, 0x76, 0x31
  };
  static const uint8_t protected_coap_request[] = {
    0x44, 0x02, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x62, 0x09, 0x14, 0xff, 0x61, 0x2f,
    0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c, 0x16, 0x68,
    0xb3, 0x82, 0x5e
  };
  static const uint8_t unprotected_coap_response[] = {
    0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57,
    0x6f, 0x72, 0x6c, 0x64, 0x21
  };
  static const uint8_t protected_coap_response[] = {
    0x64, 0x44, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x90, 0xff, 0xdb, 0xaa, 0xd1, 0xe9, 0xa7, 0xe7,
    0xb2, 0xa8, 0x13, 0xd3, 0xc3, 0x15, 0x24, 0x37,
    0x83, 0x03, 0xcd, 0xaf, 0xae, 0x11, 0x91, 0x06
  };
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  int result;
  coap_pdu_t *outgoing_pdu = coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU);
  coap_pdu_t *incoming_pdu = coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU);
  coap_pdu_t *osc_pdu = NULL;
  coap_session_t *session = NULL;

  FailIf_CU_ASSERT_PTR_NOT_NULL(outgoing_pdu);
  FailIf_CU_ASSERT_PTR_NOT_NULL(incoming_pdu);

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 20);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  result = coap_pdu_parse(COAP_PROTO_UDP, unprotected_coap_request,
                          sizeof(unprotected_coap_request), outgoing_pdu);
  CU_ASSERT(result > 0);
  result = coap_pdu_parse(COAP_PROTO_UDP, protected_coap_response,
                          sizeof(protected_coap_response), incoming_pdu);
  CU_ASSERT(result > 0);

  session = coap_malloc_type(COAP_SESSION, sizeof(coap_session_t));
  FailIf_CU_ASSERT_PTR_NOT_NULL(session);
  memset(session, 0, sizeof(coap_session_t));
  session->context = ctx;
  session->proto = COAP_PROTO_UDP;
  session->type = COAP_SESSION_TYPE_CLIENT;
  session->recipient_ctx = ctx->p_osc_ctx->recipient_chain;
  session->recipient_ctx->initial_state = 0;
  session->context = ctx;

  /* Send request, so that all associations etc. are correctly set up */

  osc_pdu = coap_oscore_new_pdu_encrypted(session, outgoing_pdu, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_pdu);

  result = coap_pdu_encode_header(osc_pdu, session->proto);
  CU_ASSERT(result != 0);
  CU_ASSERT(osc_pdu->hdr_size + osc_pdu->used_size ==
            sizeof(protected_coap_request));
  result = memcmp(&osc_pdu->token[-osc_pdu->hdr_size], protected_coap_request,
                  osc_pdu->hdr_size + osc_pdu->used_size);
  CU_ASSERT(result == 0);
  coap_delete_pdu(outgoing_pdu);
  outgoing_pdu = NULL;
  coap_delete_pdu(osc_pdu);
  osc_pdu = NULL;

  /* Decrypt the encrypted response */

  osc_pdu = coap_oscore_decrypt_pdu(session, incoming_pdu);
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_pdu);

  result = coap_pdu_encode_header(osc_pdu, session->proto);
  CU_ASSERT(result != 0);
  CU_ASSERT(osc_pdu->hdr_size + osc_pdu->used_size ==
            sizeof(unprotected_coap_response));
  result = memcmp(&osc_pdu->token[-osc_pdu->hdr_size],
                  unprotected_coap_response,
                  osc_pdu->hdr_size + osc_pdu->used_size);
  CU_ASSERT(result == 0);

fail:
  oscore_free_contexts(ctx);
  coap_delete_pdu(incoming_pdu);
  coap_delete_pdu(outgoing_pdu);
  coap_delete_pdu(osc_pdu);
  coap_free(session);
}

/* C.8.  Test Vector 8: OSCORE Response with Partial IV, Server */
static void
t_oscore_c_8(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "sender_id,hex,\"01\"\n"
      "recipient_id,hex,\"\"\n";
  static const uint8_t protected_coap_request[] = {
    0x44, 0x02, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x62, 0x09, 0x14, 0xff, 0x61, 0x2f,
    0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c, 0x16, 0x68,
    0xb3, 0x82, 0x5e
  };
  static const uint8_t unprotected_coap_request[] = {
    0x44, 0x01, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x83, 0x74, 0x76, 0x31
  };
  static const uint8_t unprotected_coap_response[] = {
    0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57,
    0x6f, 0x72, 0x6c, 0x64, 0x21
  };
  static const uint8_t protected_coap_response[] = {
    0x64, 0x44, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x92, 0x01, 0x00, 0xff, 0x4d, 0x4c, 0x13, 0x66,
    0x93, 0x84, 0xb6, 0x73, 0x54, 0xb2, 0xb6, 0x17,
    0x5f, 0xf4, 0xb8, 0x65, 0x8c, 0x66, 0x6a, 0x6c,
    0xf8, 0x8e
  };
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  int result;
  coap_pdu_t *incoming_pdu = coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU);
  coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU);
  coap_pdu_t *osc_pdu = NULL;
  coap_session_t *session = NULL;

  FailIf_CU_ASSERT_PTR_NOT_NULL(incoming_pdu);
  FailIf_CU_ASSERT_PTR_NOT_NULL(pdu);

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  result = coap_pdu_parse(COAP_PROTO_UDP, protected_coap_request,
                          sizeof(protected_coap_request), incoming_pdu);
  CU_ASSERT(result > 0);

  result = coap_pdu_parse(COAP_PROTO_UDP, unprotected_coap_response,
                          sizeof(unprotected_coap_response), pdu);
  CU_ASSERT(result > 0);

  session = coap_malloc_type(COAP_SESSION, sizeof(coap_session_t));
  FailIf_CU_ASSERT_PTR_NOT_NULL(session);
  memset(session, 0, sizeof(coap_session_t));
  session->context = ctx;
  session->proto = COAP_PROTO_UDP;
  session->type = COAP_SESSION_TYPE_SERVER;
  session->recipient_ctx = ctx->p_osc_ctx->recipient_chain;
  session->recipient_ctx->initial_state = 0;
  session->context = ctx;

  /* First, decrypt incoming request to set up all variables for
     sending response */
  osc_pdu = coap_oscore_decrypt_pdu(session, incoming_pdu);
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_pdu);
  result = coap_pdu_encode_header(osc_pdu, session->proto);
  CU_ASSERT(result != 0);
  CU_ASSERT(osc_pdu->hdr_size + osc_pdu->used_size ==
            sizeof(unprotected_coap_request));
  result = memcmp(&osc_pdu->token[-osc_pdu->hdr_size], unprotected_coap_request,
                  osc_pdu->hdr_size + osc_pdu->used_size);
  CU_ASSERT(result == 0);
  coap_delete_pdu(osc_pdu);
  osc_pdu = NULL;
  coap_delete_pdu(incoming_pdu);
  incoming_pdu = NULL;

  /* Now encrypt the server's response */
  osc_pdu = coap_oscore_new_pdu_encrypted(session, pdu, NULL, 1);
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_pdu);

  result = coap_pdu_encode_header(osc_pdu, session->proto);
  CU_ASSERT(result != 0);
  CU_ASSERT(osc_pdu->hdr_size + osc_pdu->used_size ==
            sizeof(protected_coap_response));
  result = memcmp(&osc_pdu->token[-osc_pdu->hdr_size], protected_coap_response,
                  osc_pdu->hdr_size + osc_pdu->used_size);
  CU_ASSERT(result == 0);

fail:
  oscore_free_contexts(ctx);
  coap_delete_pdu(pdu);
  coap_delete_pdu(incoming_pdu);
  coap_delete_pdu(osc_pdu);
  oscore_delete_server_associations(session);
  coap_free(session);
}

/*
 * Decrypt the encrypted response from C.8 and check it matches input
 */
static void
t_oscore_c_8_2(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "sender_id,hex,\"\"\n"
      "recipient_id,hex,\"01\"\n";
  static const uint8_t unprotected_coap_request[] = {
    0x44, 0x01, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x83, 0x74, 0x76, 0x31
  };
  static const uint8_t protected_coap_request[] = {
    0x44, 0x02, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x62, 0x09, 0x14, 0xff, 0x61, 0x2f,
    0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c, 0x16, 0x68,
    0xb3, 0x82, 0x5e
  };
  static const uint8_t unprotected_coap_response[] = {
    0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57,
    0x6f, 0x72, 0x6c, 0x64, 0x21
  };
  static const uint8_t protected_coap_response[] = {
    0x64, 0x44, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
    0x92, 0x01, 0x00, 0xff, 0x4d, 0x4c, 0x13, 0x66,
    0x93, 0x84, 0xb6, 0x73, 0x54, 0xb2, 0xb6, 0x17,
    0x5f, 0xf4, 0xb8, 0x65, 0x8c, 0x66, 0x6a, 0x6c,
    0xf8, 0x8e
  };
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  int result;
  coap_pdu_t *outgoing_pdu = coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU);
  coap_pdu_t *incoming_pdu = coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU);
  coap_pdu_t *osc_pdu = NULL;
  coap_session_t *session = NULL;

  FailIf_CU_ASSERT_PTR_NOT_NULL(outgoing_pdu);
  FailIf_CU_ASSERT_PTR_NOT_NULL(incoming_pdu);

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 20);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  result = coap_pdu_parse(COAP_PROTO_UDP, unprotected_coap_request,
                          sizeof(unprotected_coap_request), outgoing_pdu);
  CU_ASSERT(result > 0);
  result = coap_pdu_parse(COAP_PROTO_UDP, protected_coap_response,
                          sizeof(protected_coap_response), incoming_pdu);
  CU_ASSERT(result > 0);

  session = coap_malloc_type(COAP_SESSION, sizeof(coap_session_t));
  FailIf_CU_ASSERT_PTR_NOT_NULL(session);
  memset(session, 0, sizeof(coap_session_t));
  session->context = ctx;
  session->proto = COAP_PROTO_UDP;
  session->type = COAP_SESSION_TYPE_CLIENT;
  session->recipient_ctx = ctx->p_osc_ctx->recipient_chain;
  session->context = ctx;

  /* Send request, so that all associations etc. are correctly set up */

  osc_pdu = coap_oscore_new_pdu_encrypted(session, outgoing_pdu, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_pdu);

  result = coap_pdu_encode_header(osc_pdu, session->proto);
  CU_ASSERT(result != 0);
  CU_ASSERT(osc_pdu->hdr_size + osc_pdu->used_size ==
            sizeof(protected_coap_request));
  result = memcmp(&osc_pdu->token[-osc_pdu->hdr_size], protected_coap_request,
                  osc_pdu->hdr_size + osc_pdu->used_size);
  CU_ASSERT(result == 0);
  coap_delete_pdu(outgoing_pdu);
  /* CDI 1566477 */
  outgoing_pdu = NULL;
  coap_delete_pdu(osc_pdu);
  osc_pdu = NULL;

  /* Decrypt the encrypted response */

  osc_pdu = coap_oscore_decrypt_pdu(session, incoming_pdu);
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_pdu);

  result = coap_pdu_encode_header(osc_pdu, session->proto);
  CU_ASSERT(result != 0);
  CU_ASSERT(osc_pdu->hdr_size + osc_pdu->used_size ==
            sizeof(unprotected_coap_response));
  result = memcmp(&osc_pdu->token[-osc_pdu->hdr_size],
                  unprotected_coap_response,
                  osc_pdu->hdr_size + osc_pdu->used_size);
  CU_ASSERT(result == 0);

fail:
  oscore_free_contexts(ctx);
  coap_delete_pdu(incoming_pdu);
  coap_delete_pdu(outgoing_pdu);
  coap_delete_pdu(osc_pdu);
  coap_free(session);
}

/************************************************************************
 ** OSCORE credential storage tests
 ************************************************************************/

static void
t_convert_1(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "sender_id,ascii,\"server\"\n"
      "recipient_id,ascii,\"client\"\n"
      "recipient_id,ascii,\"client1\"\n"
      "recipient_id,ascii,\"client2\"\n"
      "replay_window,integer,30\n"
      "aead_alg,integer,10\n"
      "hkdf_alg,integer,-10\n";
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  oscore_ctx_t *osc_ctx;
  oscore_recipient_ctx_t *rcp;
  int rcp_count;

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  CU_ASSERT(coap_context_oscore_server(ctx, oscore_conf) == 1);

  osc_ctx = ctx->p_osc_ctx;
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_ctx);
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_ctx->sender_context);

  /* sender_id == "server" */
  CU_ASSERT(osc_ctx->sender_context->sender_id->length == 6);
  CU_ASSERT(memcmp(osc_ctx->sender_context->sender_id->s, "server", 6) == 0);

  /* 3 recipients in chain */
  rcp_count = 0;
  for (rcp = osc_ctx->recipient_chain; rcp; rcp = rcp->next_recipient)
    rcp_count++;
  CU_ASSERT(rcp_count == 3);

  CU_ASSERT(osc_ctx->aead_alg == 10);
  CU_ASSERT(osc_ctx->hkdf_alg == -10);
  CU_ASSERT(osc_ctx->replay_window_size == 30);

fail:
  oscore_free_contexts(ctx);
}

/* Common config for ref-counting tests */
#define REF_CONF_DATA \
  "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n" \
  "master_salt,hex,\"9e7ca92223786340\"\n" \
  "sender_id,ascii,\"server\"\n" \
  "recipient_id,ascii,\"client\"\n"

/*
 * t_ref_1: Context attached to coap_context.
 * Recipient ref is managed by session attach/release.
 * After all sessions release, recipient is freed but osc_ctx stays.
 */
static void
t_ref_1(void) {
  static const char conf_data[] = REF_CONF_DATA;
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  oscore_ctx_t *osc_ctx;
  oscore_recipient_ctx_t *rcp_ctx;

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  CU_ASSERT(coap_context_oscore_server(ctx, oscore_conf) == 1);

  osc_ctx = ctx->p_osc_ctx;
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_ctx);

  /* After enter_context, recipient ref == 1 */
  rcp_ctx = osc_ctx->recipient_chain;
  FailIf_CU_ASSERT_PTR_NOT_NULL(rcp_ctx);
  CU_ASSERT(rcp_ctx->ref == 1);

  /* Simulate session attaching recipient: ref becomes 2 */
  rcp_ctx->ref++;
  CU_ASSERT(rcp_ctx->ref == 2);

  /* oscore_free_contexts releases the enter_context ref (ref 2 -> 1) */
  oscore_free_contexts(ctx);

  /* Context detached but recipient still alive (ref == 1) */
  CU_ASSERT_PTR_NULL(ctx->p_osc_ctx);
  CU_ASSERT(rcp_ctx->ref == 1);

  /* Session releases its ref - recipient freed */
  oscore_release_recipient_ctx(&rcp_ctx);
  CU_ASSERT_PTR_NULL(rcp_ctx);
  return;

fail:
  oscore_free_contexts(ctx);
}

/*
 * t_ref_2: Context NOT attached to coap_context.
 * When the only session releases its recipient, both the
 * recipient and the oscore context should be freed.
 */
static void
t_ref_2(void) {
  static const char conf_data[] = REF_CONF_DATA;
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  oscore_ctx_t *osc_ctx;
  oscore_recipient_ctx_t *rcp_ctx;

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  CU_ASSERT(coap_context_oscore_server(ctx, oscore_conf) == 1);

  osc_ctx = ctx->p_osc_ctx;
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_ctx);
  rcp_ctx = osc_ctx->recipient_chain;
  FailIf_CU_ASSERT_PTR_NOT_NULL(rcp_ctx);

  /* Simulate session attach: ref 1 -> 2 */
  rcp_ctx->ref++;
  CU_ASSERT(rcp_ctx->ref == 2);

  /* Detach context from coap_context (simulates context teardown while
   * session still holds a ref). This decrements ref by 1 for each
   * recipient via oscore_context_release_recipients. */
  oscore_free_contexts(ctx);
  CU_ASSERT_PTR_NULL(ctx->p_osc_ctx);
  CU_ASSERT(rcp_ctx->ref == 1);

  /* osc_ctx is no longer attached (next == NULL) */
  CU_ASSERT_PTR_NULL(osc_ctx->next);

  /* Session releases - recipient AND context get freed
   * (oscore_release_recipient frees context when not attached and
   * recipient_chain becomes empty). */
  oscore_release_recipient_ctx(&rcp_ctx);
  CU_ASSERT_PTR_NULL(rcp_ctx);
  /* osc_ctx is now freed - no further access. */
  return;

fail:
  oscore_free_contexts(ctx);
}

/*
 * t_ref_3: Add/remove recipient via public API
 * (coap_new_oscore_recipient / coap_delete_oscore_recipient).
 * Verify ref counting is consistent.
 */
static void
t_ref_3(void) {
  static const char conf_data[] = REF_CONF_DATA;
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  oscore_ctx_t *osc_ctx;
  oscore_recipient_ctx_t *rcp_ctx;
  coap_bin_const_t *peer_id;
  coap_bin_const_t peer_id_cmp = { 5, (const uint8_t *)"peer1" };
  int rcp_count;

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  CU_ASSERT(coap_context_oscore_server(ctx, oscore_conf) == 1);

  osc_ctx = ctx->p_osc_ctx;
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_ctx);

  /* Initially 1 recipient ("client") with ref == 1 */
  CU_ASSERT_PTR_NOT_NULL(osc_ctx->recipient_chain);
  CU_ASSERT(osc_ctx->recipient_chain->ref == 1);

  /* Add "peer1" via public API - ownership of peer_id moves in */
  peer_id = coap_new_bin_const((const uint8_t *)"peer1", 5);
  FailIf_CU_ASSERT_PTR_NOT_NULL(peer_id);
  CU_ASSERT(coap_new_oscore_recipient(ctx, peer_id) == 1);

  rcp_count = 0;
  for (rcp_ctx = osc_ctx->recipient_chain; rcp_ctx; rcp_ctx = rcp_ctx->next_recipient)
    rcp_count++;
  CU_ASSERT(rcp_count == 2);

  /* Find peer1 and verify ref */
  for (rcp_ctx = osc_ctx->recipient_chain; rcp_ctx; rcp_ctx = rcp_ctx->next_recipient) {
    if (rcp_ctx->recipient_id->length == peer_id_cmp.length &&
        memcmp(rcp_ctx->recipient_id->s, peer_id_cmp.s, peer_id_cmp.length) == 0)
      break;
  }
  FailIf_CU_ASSERT_PTR_NOT_NULL(rcp_ctx);
  CU_ASSERT(rcp_ctx->ref == 1);

  /* Remove "peer1" via public API */
  CU_ASSERT(coap_delete_oscore_recipient(ctx, &peer_id_cmp) == 1);

  rcp_count = 0;
  for (rcp_ctx = osc_ctx->recipient_chain; rcp_ctx; rcp_ctx = rcp_ctx->next_recipient)
    rcp_count++;
  CU_ASSERT(rcp_count == 1);

  /* Original "client" still there */
  CU_ASSERT_PTR_NOT_NULL(osc_ctx->recipient_chain);

fail:
  oscore_free_contexts(ctx);
}

static int t_find_mode; /* 0 = single rcp, 1 = multi rcp, -1 = return NULL */

static coap_oscore_conf_t *
test_find_func(const coap_session_t *session,
               const coap_bin_const_t *rcpkey_id,
               const coap_bin_const_t *ctxkey_id) {
  static const char single_conf[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,ascii,\"server\"\n"
      "recipient_id,ascii,\"client\"\n";
  static const char multi_conf[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,ascii,\"server\"\n"
      "recipient_id,ascii,\"client\"\n"
      "recipient_id,ascii,\"client1\"\n"
      "recipient_id,ascii,\"client2\"\n";
  coap_str_const_t conf;

  (void)session;
  (void)rcpkey_id;
  (void)ctxkey_id;

  if (t_find_mode < 0)
    return NULL;

  if (t_find_mode > 0) {
    conf.s = (const uint8_t *)multi_conf;
    conf.length = sizeof(multi_conf) - 1;
  } else {
    conf.s = (const uint8_t *)single_conf;
    conf.length = sizeof(single_conf) - 1;
  }
  return coap_new_oscore_conf(conf, NULL, NULL, 0);
}

/*
 * t_find_1: External find with single recipient.
 * Temporary context is NOT attached to coap_context.
 * Freed when recipient is released.
 */
static void
t_find_1(void) {
  coap_session_t *session = NULL;
  oscore_ctx_t *osc_ctx;
  oscore_recipient_ctx_t *rcp_ctx = NULL;
  coap_bin_const_t rcpkey_id = { 6, (const uint8_t *)"client" };
  coap_bin_const_t ctxkey_id = { 0, (const uint8_t *)"" };

  session = coap_malloc_type(COAP_SESSION, sizeof(coap_session_t));
  FailIf_CU_ASSERT_PTR_NOT_NULL(session);
  memset(session, 0, sizeof(coap_session_t));
  session->context = ctx;
  session->proto = COAP_PROTO_UDP;
  session->type = COAP_SESSION_TYPE_CLIENT;

  t_find_mode = 0;
  ctx->oscore_find_cb = test_find_func;

  /* lock to pretend to run from inside coap_io_process */
  coap_lock_lock();
  osc_ctx = oscore_find_context(session, rcpkey_id, &ctxkey_id, NULL, &rcp_ctx);
  coap_lock_unlock();
  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_ctx);
  FailIf_CU_ASSERT_PTR_NOT_NULL(rcp_ctx);

  /* Temporary context NOT attached to coap_context */
  CU_ASSERT(!oscore_is_context_attached(osc_ctx));
  CU_ASSERT_PTR_NULL(ctx->p_osc_ctx);

  /* Single recipient returned */
  CU_ASSERT_PTR_NULL(rcp_ctx->next_recipient);
  CU_ASSERT(rcp_ctx->recipient_id->length == 6);
  CU_ASSERT(memcmp(rcp_ctx->recipient_id->s, "client", 6) == 0);

  /* Release - frees temporary context too (unattached, last recipient) */
  oscore_release_recipient_ctx(&rcp_ctx);
  CU_ASSERT_PTR_NULL(rcp_ctx);

fail:
  ctx->oscore_find_cb = NULL;
  coap_free(session);
}

/*
 * t_find_2: External find with multiple recipients.
 * Only the matching recipient is kept; others are freed.
 */
static void
t_find_2(void) {
  coap_session_t *session = NULL;
  oscore_ctx_t *osc_ctx;
  oscore_recipient_ctx_t *rcp_ctx = NULL;
  coap_bin_const_t rcpkey_id = { 7, (const uint8_t *)"client1" };
  coap_bin_const_t ctxkey_id = { 0, (const uint8_t *)"" };

  session = coap_malloc_type(COAP_SESSION, sizeof(coap_session_t));
  FailIf_CU_ASSERT_PTR_NOT_NULL(session);
  memset(session, 0, sizeof(coap_session_t));
  session->context = ctx;
  session->proto = COAP_PROTO_UDP;
  session->type = COAP_SESSION_TYPE_CLIENT;

  t_find_mode = 1;
  ctx->oscore_find_cb = test_find_func;

  coap_lock_lock();
  osc_ctx = oscore_find_context(session, rcpkey_id, &ctxkey_id, NULL, &rcp_ctx);
  coap_lock_unlock();

  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_ctx);
  FailIf_CU_ASSERT_PTR_NOT_NULL(rcp_ctx);

  /* Temporary context NOT attached */
  CU_ASSERT_PTR_NULL(osc_ctx->next);

  /* Only matching recipient "client1" kept */
  CU_ASSERT(rcp_ctx->recipient_id->length == 7);
  CU_ASSERT(memcmp(rcp_ctx->recipient_id->s, "client1", 7) == 0);
  CU_ASSERT_PTR_NULL(rcp_ctx->next_recipient);
  CU_ASSERT(osc_ctx->recipient_chain == rcp_ctx);

  oscore_release_recipient_ctx(&rcp_ctx);
  CU_ASSERT_PTR_NULL(rcp_ctx);

fail:
  ctx->oscore_find_cb = NULL;
  coap_free(session);
}

/*
 * t_find_3: External find returns NULL - falls through to internal storage.
 */
static void
t_find_3(void) {
  static const char conf_data[] = REF_CONF_DATA;
  const coap_str_const_t conf = { sizeof(conf_data)-1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;
  coap_session_t *session = NULL;
  oscore_ctx_t *osc_ctx;
  oscore_recipient_ctx_t *rcp_ctx = NULL;
  coap_bin_const_t rcpkey_id = { 6, (const uint8_t *)"client" };
  coap_bin_const_t ctxkey_id = { 0, (const uint8_t *)"" };

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  CU_ASSERT(coap_context_oscore_server(ctx, oscore_conf) == 1);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);

  session = coap_malloc_type(COAP_SESSION, sizeof(coap_session_t));
  FailIf_CU_ASSERT_PTR_NOT_NULL(session);
  memset(session, 0, sizeof(coap_session_t));
  session->context = ctx;
  session->proto = COAP_PROTO_UDP;
  session->type = COAP_SESSION_TYPE_CLIENT;

  t_find_mode = -1;
  ctx->oscore_find_cb = test_find_func;

  coap_lock_lock();
  osc_ctx = oscore_find_context(session, rcpkey_id, &ctxkey_id, NULL, &rcp_ctx);
  coap_lock_unlock();

  FailIf_CU_ASSERT_PTR_NOT_NULL(osc_ctx);

  /* Context from internal storage - IS attached */
  CU_ASSERT(osc_ctx == ctx->p_osc_ctx);
  CU_ASSERT_PTR_NOT_NULL(osc_ctx->next);

  /* Recipient found from internal storage */
  FailIf_CU_ASSERT_PTR_NOT_NULL(rcp_ctx);
  FailIf_CU_ASSERT_PTR_NOT_NULL(rcp_ctx->recipient_id);
  CU_ASSERT(rcp_ctx->recipient_id->length == 6);
  CU_ASSERT(memcmp(rcp_ctx->recipient_id->s, "client", 6) == 0);

fail:
  ctx->oscore_find_cb = NULL;
  oscore_free_contexts(ctx);
  coap_free(session);
}

/************************************************************************
 ** Per-recipient state (last_seq / sliding_window) in conf buffer
 ************************************************************************/

/* Basic: all three state fields populate the head of recipient_chain */
static void
t_rcp_state_basic(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "sender_id,hex,\"01\"\n"
      "complex_recipient,config,'"
      "recipient_id,hex,\"02\"\n"
      "last_seq,unsigned64,42\n"
      "sliding_window,unsigned64,1023\n"
      "'\n";
  const coap_str_const_t conf = { sizeof(conf_data) - 1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf = NULL;

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf->recipient_chain);

  CU_ASSERT(oscore_conf->recipient_chain->last_seq == 42);
  CU_ASSERT(oscore_conf->recipient_chain->sliding_window == 1023);
  CU_ASSERT(oscore_conf->recipient_chain->window_initialized == 1);

  coap_delete_oscore_conf(oscore_conf);
  return;

fail:
  if (oscore_conf)
    coap_delete_oscore_conf(oscore_conf);
}

/* Boundary: full uint64 range parses correctly */
static void
t_rcp_state_max_64bit(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,hex,\"01\"\n"
      "complex_recipient,config,'"
      "recipient_id,hex,\"02\"\n"
      "last_seq,unsigned64,18446744073709551614\n"
      "sliding_window,unsigned64,18446744073709551615\n"
      "'\n";
  const coap_str_const_t conf = { sizeof(conf_data) - 1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf = NULL;

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf->recipient_chain);

  CU_ASSERT(oscore_conf->recipient_chain->last_seq == 18446744073709551614ULL);
  CU_ASSERT(oscore_conf->recipient_chain->sliding_window == 18446744073709551615ULL);
  CU_ASSERT(oscore_conf->recipient_chain->window_initialized == 1);

  coap_delete_oscore_conf(oscore_conf);
  return;

fail:
  if (oscore_conf)
    coap_delete_oscore_conf(oscore_conf);
}

/* Only last_seq set: window_initialized still set */
static void
t_rcp_state_only_last_seq(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,hex,\"01\"\n"
      "complex_recipient,config,'"
      "recipient_id,hex,\"02\"\n"
      "last_seq,unsigned64,7\n"
      "'\n";
  const coap_str_const_t conf = { sizeof(conf_data) - 1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf = NULL;

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf->recipient_chain);

  CU_ASSERT(oscore_conf->recipient_chain->last_seq == 7);
  CU_ASSERT(oscore_conf->recipient_chain->sliding_window == 0);
  CU_ASSERT(oscore_conf->recipient_chain->window_initialized == 1);

  coap_delete_oscore_conf(oscore_conf);
  return;

fail:
  if (oscore_conf)
    coap_delete_oscore_conf(oscore_conf);
}

/* Only sliding_window: window_initialized set */
static void
t_rcp_state_only_sliding_window(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,hex,\"01\"\n"
      "complex_recipient,config,'"
      "recipient_id,hex,\"02\"\n"
      "sliding_window,unsigned64,15\n"
      "'\n";
  const coap_str_const_t conf = { sizeof(conf_data) - 1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf = NULL;

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf->recipient_chain);

  CU_ASSERT(oscore_conf->recipient_chain->last_seq == 0);
  CU_ASSERT(oscore_conf->recipient_chain->sliding_window == 15);
  CU_ASSERT(oscore_conf->recipient_chain->window_initialized == 1);

  coap_delete_oscore_conf(oscore_conf);
  return;

fail:
  if (oscore_conf)
    coap_delete_oscore_conf(oscore_conf);
}

/* No state lines: window_initialized stays 0 */
static void
t_rcp_state_no_state(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,hex,\"01\"\n"
      "recipient_id,hex,\"02\"\n";
  const coap_str_const_t conf = { sizeof(conf_data) - 1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf = NULL;

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf->recipient_chain);

  CU_ASSERT(oscore_conf->recipient_chain->last_seq == 0);
  CU_ASSERT(oscore_conf->recipient_chain->sliding_window == 0);
  CU_ASSERT(oscore_conf->recipient_chain->window_initialized == 0);

  coap_delete_oscore_conf(oscore_conf);
  return;

fail:
  if (oscore_conf)
    coap_delete_oscore_conf(oscore_conf);
}

/* State fields before any recipient_id must reject the conf */
static void
t_rcp_state_before_recipient_id(void) {
  coap_log_t level = coap_get_log_level();
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,hex,\"01\"\n"
      "complex_recipient,config,'"
      "last_seq,unsigned64,5\n"
      "recipient_id,hex,\"02\"\n"
      "'\n";
  const coap_str_const_t conf = { sizeof(conf_data) - 1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf;

  coap_set_log_level(COAP_LOG_CRIT);
  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  if (oscore_conf)
    coap_delete_oscore_conf(oscore_conf);
  coap_set_log_level(level);
}

/*
 * Multi-recipient: each state line applies to the most recently parsed
 * recipient_id (head of recipient_chain because the parser prepends).
 */
static void
t_rcp_state_multi_recipient(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,hex,\"01\"\n"
      "complex_recipient,config,'"
      "recipient_id,hex,\"02\"\n"
      "last_seq,unsigned64,11\n"
      "'\n"
      "complex_recipient,config,'"
      "recipient_id,hex,\"03\"\n"
      "last_seq,unsigned64,22\n"
      "'\n";
  const coap_str_const_t conf = { sizeof(conf_data) - 1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf = NULL;
  coap_oscore_rcp_conf_t *rcp;
  uint64_t last_seq_for_02 = 0;
  uint64_t last_seq_for_03 = 0;
  int found_02 = 0, found_03 = 0;

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);

  for (rcp = oscore_conf->recipient_chain; rcp; rcp = rcp->next_recipient) {
    if (rcp->recipient_id && rcp->recipient_id->length == 1) {
      if (rcp->recipient_id->s[0] == 0x02) {
        last_seq_for_02 = rcp->last_seq;
        found_02 = 1;
      } else if (rcp->recipient_id->s[0] == 0x03) {
        last_seq_for_03 = rcp->last_seq;
        found_03 = 1;
      }
    }
  }
  CU_ASSERT(found_02 && found_03);
  CU_ASSERT(last_seq_for_02 == 11);
  CU_ASSERT(last_seq_for_03 == 22);

  coap_delete_oscore_conf(oscore_conf);
  return;

fail:
  if (oscore_conf)
    coap_delete_oscore_conf(oscore_conf);
}

/* complex_recipient: basic state fields parsed correctly */
static void
t_rcp_state_complex_basic(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "sender_id,hex,\"01\"\n"
      "complex_recipient,config,'\n"
      "recipient_id,hex,\"02\"\n"
      "last_seq,unsigned64,99\n"
      "sliding_window,unsigned64,255\n"
      "'\n";
  const coap_str_const_t conf = { sizeof(conf_data) - 1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf = NULL;

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf->recipient_chain);

  CU_ASSERT(oscore_conf->recipient_chain->last_seq == 99);
  CU_ASSERT(oscore_conf->recipient_chain->sliding_window == 255);
  CU_ASSERT(oscore_conf->recipient_chain->window_initialized == 1);

  coap_delete_oscore_conf(oscore_conf);
  return;

fail:
  if (oscore_conf)
    coap_delete_oscore_conf(oscore_conf);
}

/* complex_recipient: only last_seq sets window_initialized */
static void
t_rcp_state_complex_only_last_seq(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,hex,\"01\"\n"
      "complex_recipient,config,'\n"
      "recipient_id,hex,\"02\"\n"
      "last_seq,unsigned64,5\n"
      "'\n";
  const coap_str_const_t conf = { sizeof(conf_data) - 1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf = NULL;

  oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf->recipient_chain);

  CU_ASSERT(oscore_conf->recipient_chain->last_seq == 5);
  CU_ASSERT(oscore_conf->recipient_chain->sliding_window == 0);
  CU_ASSERT(oscore_conf->recipient_chain->window_initialized == 1);

  coap_delete_oscore_conf(oscore_conf);
  return;

fail:
  if (oscore_conf)
    coap_delete_oscore_conf(oscore_conf);
}

/* Propagation: flat form - last_seq/sliding_window reach runtime ctx */
static void
t_propagate_flat(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "master_salt,hex,\"9e7ca92223786340\"\n"
      "sender_id,hex,\"01\"\n"
      "complex_recipient,config,'"
      "recipient_id,hex,\"02\"\n"
      "last_seq,unsigned64,77\n"
      "sliding_window,unsigned64,511\n"
      "'\n";
  const coap_str_const_t conf = { sizeof(conf_data) - 1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);

  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx->recipient_chain);

  CU_ASSERT(ctx->p_osc_ctx->recipient_chain->last_seq == 77);
  CU_ASSERT(ctx->p_osc_ctx->recipient_chain->sliding_window == 511);
fail:
  oscore_free_contexts(ctx);
}

/* Propagation: complex_recipient - state fields reach runtime ctx */
static void
t_propagate_complex(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,hex,\"01\"\n"
      "complex_recipient,config,'\n"
      "recipient_id,hex,\"02\"\n"
      "last_seq,unsigned64,99\n"
      "sliding_window,unsigned64,255\n"
      "'\n";
  const coap_str_const_t conf = { sizeof(conf_data) - 1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);

  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx->recipient_chain);

  CU_ASSERT(ctx->p_osc_ctx->recipient_chain->last_seq == 99);
  CU_ASSERT(ctx->p_osc_ctx->recipient_chain->sliding_window == 255);
fail:
  oscore_free_contexts(ctx);
}

/* Propagation: no state in conf - runtime ctx fields remain zero */
static void
t_propagate_no_state(void) {
  static const char conf_data[] =
      "master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
      "sender_id,hex,\"01\"\n"
      "recipient_id,hex,\"02\"\n";
  const coap_str_const_t conf = { sizeof(conf_data) - 1,
                                  (const uint8_t *)conf_data
                                };
  coap_oscore_conf_t *oscore_conf = coap_new_oscore_conf(conf, NULL, NULL, 0);

  FailIf_CU_ASSERT_PTR_NOT_NULL(oscore_conf);
  coap_context_oscore_server(ctx, oscore_conf);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx);
  FailIf_CU_ASSERT_PTR_NOT_NULL(ctx->p_osc_ctx->recipient_chain);

  CU_ASSERT(ctx->p_osc_ctx->recipient_chain->last_seq == 0);
  CU_ASSERT(ctx->p_osc_ctx->recipient_chain->sliding_window == 0);
fail:
  oscore_free_contexts(ctx);
}

/************************************************************************
 ** initialization
 ************************************************************************/

static int
t_oscore_tests_create(void) {
  ctx = coap_new_context(NULL);

  return (ctx == NULL);
}

static int
t_oscore_tests_remove(void) {
  coap_free_context(ctx);
  return 0;
}

CU_pSuite
t_init_oscore_tests(void) {
  CU_pSuite suite[5];

  suite[0] = CU_add_suite("RFC8613 Appendix C OSCORE tests",
                          t_oscore_tests_create, t_oscore_tests_remove);
  if (!suite[0]) {                        /* signal error */
    fprintf(stderr, "W: cannot add OSCORE test suite (%s)\n",
            CU_get_error_msg());

    return NULL;
  }

#define OSCORE_TEST(n)                                  \
  if (!CU_add_test(suite[0], #n, n)) {                  \
    fprintf(stderr, "W: cannot add OSCORE test (%s)\n", \
            CU_get_error_msg());                        \
  }

  if (coap_oscore_is_supported()) {
    OSCORE_TEST(t_oscore_c_1_1);
    OSCORE_TEST(t_oscore_c_1_2);
    OSCORE_TEST(t_oscore_c_2_1);
    OSCORE_TEST(t_oscore_c_2_2);
    OSCORE_TEST(t_oscore_c_3_1);
    OSCORE_TEST(t_oscore_c_3_2);
    OSCORE_TEST(t_oscore_c_4);
    OSCORE_TEST(t_oscore_c_5);
    OSCORE_TEST(t_oscore_c_6);
    OSCORE_TEST(t_oscore_c_7);
    OSCORE_TEST(t_oscore_c_7_2);
    OSCORE_TEST(t_oscore_c_8);
    OSCORE_TEST(t_oscore_c_8_2);

    OSCORE_TEST(t_convert_1);

    OSCORE_TEST(t_ref_1);
    OSCORE_TEST(t_ref_2);
    OSCORE_TEST(t_ref_3);

    OSCORE_TEST(t_find_1);
    OSCORE_TEST(t_find_2);
    OSCORE_TEST(t_find_3);

    OSCORE_TEST(t_rcp_state_basic);
    OSCORE_TEST(t_rcp_state_max_64bit);
    OSCORE_TEST(t_rcp_state_only_last_seq);
    OSCORE_TEST(t_rcp_state_only_sliding_window);
    OSCORE_TEST(t_rcp_state_no_state);
    OSCORE_TEST(t_rcp_state_before_recipient_id);
    OSCORE_TEST(t_rcp_state_multi_recipient);

    OSCORE_TEST(t_rcp_state_complex_basic);
    OSCORE_TEST(t_rcp_state_complex_only_last_seq);

    OSCORE_TEST(t_propagate_flat);
    OSCORE_TEST(t_propagate_complex);
    OSCORE_TEST(t_propagate_no_state);
  }

  return suite[0];
}

#else /* COAP_OSCORE_SUPPORT && COAP_SERVER_SUPPORT  */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* COAP_OSCORE_SUPPORT && COAP_SERVER_SUPPORT  */
