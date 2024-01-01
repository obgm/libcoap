/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* libcoap unit tests
 *
 * Copyright (C) 2021-2024 Jon Shallow <supjps-libcoap@jpshallow.com>
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
 ** initialization
 ************************************************************************/

static int
t_oscore_tests_create(void) {
  ctx = coap_new_context(NULL);

  if (ctx != NULL) {
    coap_lock_lock(ctx, return 1);
  }

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
