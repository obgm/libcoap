/* libcoap unit tests
 *
 * Copyright (C) 2026 Alejandro Pacheco <alepacheco99@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "test_common.h"
#include "test_block.h"

#if COAP_CLIENT_SUPPORT
#include <stdio.h>

#define ReturnIf_CU_ASSERT_PTR_NOT_NULL(value) \
  CU_ASSERT_PTR_NOT_NULL(value); \
  if ((void*)value == NULL) return;

#if COAP_SERVER_SUPPORT
static size_t large_app_calls;

static int
large_app_get_data(coap_session_t *s COAP_UNUSED, size_t max, size_t offset,
                   uint8_t *data, size_t *length, void *app_ptr COAP_UNUSED) {
  large_app_calls++;
  if (offset >= 4096)
    return 0;
  *length = max < 4096 - offset ? max : 4096 - offset;
  memset(data, 'x', *length);
  return 1;
}

/* A 4.01 with Echo for a request built by coap_add_data_large_request_app()
 * must get the re-sent block from the application callback. */
static void
t_block_echo_get_func(void) {
  coap_context_t *l_ctx;
  coap_session_t *l_session;
  coap_address_t saddr;
  coap_pdu_t *pdu;
  size_t calls;
  uint8_t token = 0x5a;
  uint8_t rsp[] = { 0x51, 0x81, 0x12, 0x34, 0x5a,
                    0xd8, 0xef, 1, 2, 3, 4, 5, 6, 7, 8
                  };

  coap_address_init(&saddr);
  saddr.size = sizeof(struct sockaddr_in6);
  saddr.addr.sin6.sin6_family = AF_INET6;
  saddr.addr.sin6.sin6_addr = in6addr_loopback;
  saddr.addr.sin6.sin6_port = htons(20011);

  l_ctx = coap_new_context(NULL);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(l_ctx);
  coap_context_set_block_mode(l_ctx, COAP_BLOCK_USE_LIBCOAP);
  /* Something to receive the request so that the re-send succeeds */
  CU_ASSERT_PTR_NOT_NULL(coap_new_endpoint(l_ctx, &saddr, COAP_PROTO_UDP));
  l_session = coap_new_client_session(l_ctx, NULL, &saddr, COAP_PROTO_UDP);
  CU_ASSERT_PTR_NOT_NULL(l_session);
  if (!l_session)
    goto done;

  pdu = coap_pdu_init(COAP_MESSAGE_NON, COAP_REQUEST_CODE_PUT,
                      coap_new_message_id(l_session),
                      coap_session_max_pdu_size(l_session));
  CU_ASSERT_PTR_NOT_NULL(pdu);
  if (!pdu)
    goto done;
  coap_add_token(pdu, 1, &token);
  CU_ASSERT(coap_add_data_large_request_app(l_session, pdu, 4096, NULL,
                                            large_app_get_data, NULL) == 1);
  CU_ASSERT(coap_send(l_session, pdu) != COAP_INVALID_MID);

  calls = large_app_calls;
  coap_lock_lock(goto done);
  coap_handle_dgram(l_ctx, l_session, rsp, sizeof(rsp));
  coap_lock_unlock();
  CU_ASSERT(large_app_calls > calls);

done:
  coap_free_context(l_ctx);
}

/* Cancelling an observe whose request body was built by
 * coap_add_data_large_request_app() must get the body from the
 * application callback again. */
static void
t_block_cancel_observe_get_func(void) {
  coap_context_t *l_ctx;
  coap_session_t *l_session;
  coap_address_t saddr;
  coap_pdu_t *pdu;
  coap_binary_t tok;
  size_t calls;
  uint8_t token = 0x5b;
  uint8_t obs = 0;
  /* NON 2.05, token 0x5b, Observe 1 */
  uint8_t rsp[] = { 0x51, 0x45, 0x12, 0x35, 0x5b, 0x61, 0x01 };

  coap_address_init(&saddr);
  saddr.size = sizeof(struct sockaddr_in6);
  saddr.addr.sin6.sin6_family = AF_INET6;
  saddr.addr.sin6.sin6_addr = in6addr_loopback;
  saddr.addr.sin6.sin6_port = htons(20012);

  l_ctx = coap_new_context(NULL);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(l_ctx);
  coap_context_set_block_mode(l_ctx, COAP_BLOCK_USE_LIBCOAP);
  /* Something to receive the requests so that the sends succeed */
  CU_ASSERT_PTR_NOT_NULL(coap_new_endpoint(l_ctx, &saddr, COAP_PROTO_UDP));
  l_session = coap_new_client_session(l_ctx, NULL, &saddr, COAP_PROTO_UDP);
  CU_ASSERT_PTR_NOT_NULL(l_session);
  if (!l_session)
    goto done;

  pdu = coap_pdu_init(COAP_MESSAGE_NON, COAP_REQUEST_CODE_GET,
                      coap_new_message_id(l_session),
                      coap_session_max_pdu_size(l_session));
  CU_ASSERT_PTR_NOT_NULL(pdu);
  if (!pdu)
    goto done;
  coap_add_token(pdu, 1, &token);
  coap_add_option(pdu, COAP_OPTION_OBSERVE, 0, &obs);
  CU_ASSERT(coap_add_data_large_request_app(l_session, pdu, 4096, NULL,
                                            large_app_get_data, NULL) == 1);
  CU_ASSERT(coap_send(l_session, pdu) != COAP_INVALID_MID);

  /* Observe is now established */
  coap_lock_lock(goto done);
  coap_handle_dgram(l_ctx, l_session, rsp, sizeof(rsp));
  coap_lock_unlock();

  calls = large_app_calls;
  tok.length = 1;
  tok.s = &token;
  CU_ASSERT(coap_cancel_observe(l_session, &tok, COAP_MESSAGE_NON) == 1);
  CU_ASSERT(large_app_calls > calls);

done:
  coap_free_context(l_ctx);
}

/* A request built by coap_add_data_large_request_app() for a single
 * block chosen by the application must get that block from the
 * application callback. */
static void
t_block_large_app_block_num(void) {
  coap_context_t *l_ctx;
  coap_session_t *l_session;
  coap_address_t saddr;
  coap_pdu_t *pdu;
  size_t calls;
  size_t len;
  const uint8_t *data;
  uint8_t token = 0x5c;
  uint8_t buf[4];

  coap_address_init(&saddr);
  saddr.size = sizeof(struct sockaddr_in6);
  saddr.addr.sin6.sin6_family = AF_INET6;
  saddr.addr.sin6.sin6_addr = in6addr_loopback;
  saddr.addr.sin6.sin6_port = htons(20013);

  l_ctx = coap_new_context(NULL);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(l_ctx);
  coap_context_set_block_mode(l_ctx, COAP_BLOCK_USE_LIBCOAP);
  l_session = coap_new_client_session(l_ctx, NULL, &saddr, COAP_PROTO_UDP);
  CU_ASSERT_PTR_NOT_NULL(l_session);
  if (!l_session)
    goto done;

  pdu = coap_pdu_init(COAP_MESSAGE_NON, COAP_REQUEST_CODE_PUT,
                      coap_new_message_id(l_session),
                      coap_session_max_pdu_size(l_session));
  CU_ASSERT_PTR_NOT_NULL(pdu);
  if (!pdu)
    goto done;
  coap_add_token(pdu, 1, &token);
  /* Block1 NUM 1, M 1, SZX 6 */
  coap_add_option(pdu, COAP_OPTION_BLOCK1,
                  coap_encode_var_safe(buf, sizeof(buf), (1 << 4) | (1 << 3) | 6),
                  buf);
  calls = large_app_calls;
  CU_ASSERT(coap_add_data_large_request_app(l_session, pdu, 4096, NULL,
                                            large_app_get_data, NULL) == 1);
  CU_ASSERT(large_app_calls > calls);
  CU_ASSERT(coap_get_data(pdu, &len, &data) && len > 0 && data[0] == 'x');
  coap_delete_pdu(pdu);

done:
  coap_free_context(l_ctx);
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_Q_BLOCK_SUPPORT
static size_t qblock2_len;
static unsigned int qblock2_calls;

static coap_response_t
qblock2_handler(coap_session_t *s COAP_UNUSED,
                const coap_pdu_t *sent COAP_UNUSED,
                const coap_pdu_t *received,
                const coap_mid_t mid COAP_UNUSED) {
  size_t len, offset, total;
  const uint8_t *data;

  qblock2_calls++;
  if (coap_get_data_large(received, &len, &data, &offset, &total))
    qblock2_len = len;
  return COAP_RESPONSE_OK;
}

static coap_pdu_t *
qblock2_response(coap_session_t *s, uint32_t blk, size_t size2) {
  static const uint8_t token[] = { 0x51, 0x42 };
  static const uint8_t etag[] = { 0x01 };
  uint8_t payload[16];
  uint8_t buf[4];
  coap_pdu_t *pdu;

  pdu = coap_pdu_init(COAP_MESSAGE_ACK, COAP_RESPONSE_CODE(205),
                      coap_new_message_id_lkd(s), 256);
  if (!pdu)
    return NULL;
  memset(payload, 'a', sizeof(payload));
  coap_add_token(pdu, sizeof(token), token);
  coap_add_option(pdu, COAP_OPTION_ETAG, sizeof(etag), etag);
  coap_add_option(pdu, COAP_OPTION_Q_BLOCK2,
                  coap_encode_var_safe(buf, sizeof(buf), blk), buf);
  coap_add_option(pdu, COAP_OPTION_SIZE2,
                  coap_encode_var_safe(buf, sizeof(buf), size2), buf);
  coap_add_data(pdu, sizeof(payload), payload);
  return pdu;
}

/* Two 16 byte Q-Block2 responses, with the Size2 of each */
static void
qblock2_get(size_t size2_first, size_t size2_last) {
  static const uint8_t token[] = { 0x51, 0x42 };
  coap_context_t *qctx;
  coap_session_t *qsession;
  coap_address_t addr;
  coap_pdu_t *sent;
  coap_pdu_t *rcvd;

  qblock2_len = 0;
  qblock2_calls = 0;

  coap_address_init(&addr);
  addr.size = sizeof(struct sockaddr_in6);
  addr.addr.sin6.sin6_family = AF_INET6;
  addr.addr.sin6.sin6_addr = in6addr_loopback;
  addr.addr.sin6.sin6_port = htons(20001);

  qctx = coap_new_context(NULL);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(qctx);
  coap_context_set_block_mode(qctx, COAP_BLOCK_USE_LIBCOAP |
                              COAP_BLOCK_SINGLE_BODY);
  coap_register_response_handler(qctx, qblock2_handler);
  qsession = coap_new_client_session(qctx, NULL, &addr, COAP_PROTO_UDP);
  if (!qsession) {
    CU_FAIL("no session");
    coap_free_context(qctx);
    return;
  }

  coap_lock_lock(return);
  sent = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET,
                       coap_new_message_id_lkd(qsession), 64);
  CU_ASSERT_PTR_NOT_NULL(sent);
  if (sent) {
    coap_add_token(sent, sizeof(token), token);
    coap_add_option(sent, COAP_OPTION_URI_PATH, 1, (const uint8_t *)"x");

    rcvd = qblock2_response(qsession, (0 << 4) | (1 << 3) | 0, size2_first);
    CU_ASSERT_PTR_NOT_NULL(rcvd);
    if (rcvd) {
      coap_handle_response_get_block(qctx, qsession, sent, rcvd,
                                     COAP_RECURSE_OK);
      coap_delete_pdu_lkd(rcvd);
    }
    rcvd = qblock2_response(qsession, (1 << 4) | (0 << 3) | 0, size2_last);
    CU_ASSERT_PTR_NOT_NULL(rcvd);
    if (rcvd) {
      coap_handle_response_get_block(qctx, qsession, sent, rcvd,
                                     COAP_RECURSE_OK);
      coap_delete_pdu_lkd(rcvd);
    }
    coap_delete_pdu_lkd(sent);
  }
  coap_lock_unlock();

  coap_session_release(qsession);
  coap_free_context(qctx);
}

/* A Q-Block2 body is only presented with the 32 bytes that were received */
static void
t_block_qblock2_size2(void) {
  /* Size2 changes on the last block */
  qblock2_get(32, 1000);
  CU_ASSERT(qblock2_len <= 32);
  /* Size2 larger than the body the last block ends */
  qblock2_get(1000, 1000);
  CU_ASSERT(qblock2_len <= 32);
  /* Consistent Size2 */
  qblock2_get(32, 32);
  CU_ASSERT(qblock2_calls == 1);
  CU_ASSERT(qblock2_len == 32);
}
#endif /* COAP_Q_BLOCK_SUPPORT */

#if COAP_SERVER_SUPPORT
static coap_pdu_t *
block1_request(coap_session_t *s, coap_option_num_t opt, uint32_t blk,
               size_t size1) {
  static const uint8_t token[] = { 0x42, 0x31 };
  static const uint8_t rtag[] = { 0x02 };
  uint8_t payload[16];
  uint8_t buf[4];
  coap_pdu_t *pdu;

  pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_PUT,
                      coap_new_message_id_lkd(s), 256);
  if (!pdu)
    return NULL;
  memset(payload, 'b', sizeof(payload));
  coap_add_token(pdu, sizeof(token), token);
  coap_add_option(pdu, COAP_OPTION_URI_PATH, 1, (const uint8_t *)"y");
  coap_add_option(pdu, opt, coap_encode_var_safe(buf, sizeof(buf), blk), buf);
  coap_add_option(pdu, COAP_OPTION_SIZE1,
                  coap_encode_var_safe(buf, sizeof(buf), size1), buf);
  coap_add_option(pdu, COAP_OPTION_RTAG, sizeof(rtag), rtag);
  coap_add_data(pdu, sizeof(payload), payload);
  return pdu;
}

/*
 * Sends 16 byte blocks with the given Block option values, all with the
 * given Size1. Returns what coap_handle_request_put_block() returns for
 * the last one, with the body length handed on and the response code.
 */
static int
block1_put(coap_option_num_t opt, const uint32_t *blks, size_t count,
           size_t size1, size_t *len, coap_pdu_code_t *code) {
  coap_context_t *sctx;
  coap_session_t *ssession;
  coap_resource_t *resource;
  coap_address_t addr;
  coap_lg_srcv_t *free_lg_srcv;
  coap_pdu_t *request;
  coap_pdu_t *response;
  size_t i;
  int added_block;
  int ret = -1;

  *len = 0;
  *code = 0;
  coap_address_init(&addr);
  addr.size = sizeof(struct sockaddr_in6);
  addr.addr.sin6.sin6_family = AF_INET6;
  addr.addr.sin6.sin6_addr = in6addr_loopback;
  addr.addr.sin6.sin6_port = htons(20002);

  sctx = coap_new_context(NULL);
  if (!sctx)
    return -1;
  coap_context_set_block_mode(sctx, COAP_BLOCK_USE_LIBCOAP |
                              COAP_BLOCK_SINGLE_BODY);
  ssession = coap_new_client_session(sctx, NULL, &addr, COAP_PROTO_UDP);
  if (!ssession) {
    coap_free_context(sctx);
    return -1;
  }

  coap_lock_lock(return -1);
  resource = coap_resource_init(coap_make_str_const("y"), 0);
  if (resource) {
    coap_add_resource_lkd(sctx, resource);

    for (i = 0; i < count; i++) {
      request = block1_request(ssession, opt, blks[i], size1);
      response = coap_pdu_init(COAP_MESSAGE_ACK, 0, 0, 256);
      ret = -1;
      *len = 0;
      if (request && response) {
        size_t offset, total;
        const uint8_t *data;

        ret = coap_handle_request_put_block(sctx, ssession, request, response,
                                            resource, NULL, &added_block,
                                            &free_lg_srcv);
        if (ret == 0)
          coap_get_data_large(request, len, &data, &offset, &total);
        *code = response->code;
      }
      coap_delete_pdu_lkd(request);
      coap_delete_pdu_lkd(response);
    }
  }
  coap_lock_unlock();

  coap_session_release(ssession);
  coap_free_context(sctx);
  return ret;
}

/* A Block1 body is presented with the length the last block ends at,
 * not the larger Size1 estimate */
static void
t_block_block1_size1(void) {
  static const uint32_t blks[] = { (0 << 4) | (1 << 3), (1 << 4) | (0 << 3) };
  coap_pdu_code_t code;
  size_t len;

  CU_ASSERT(block1_put(COAP_OPTION_BLOCK1, blks, 2, 1000, &len, &code) == 0);
  CU_ASSERT(len == 32);
#if COAP_Q_BLOCK_SUPPORT
  /* Q-Block1 Size1 is the body length, so must match the last block */
  CU_ASSERT(block1_put(COAP_OPTION_Q_BLOCK1, blks, 2, 1000, &len, &code) == 1);
  CU_ASSERT(code == COAP_RESPONSE_CODE(408));
#endif /* COAP_Q_BLOCK_SUPPORT */
}

/* Once the last Block1 block is in, no block can go past where it ends */
static void
t_block_block1_after_last(void) {
  static const uint32_t later[] = { (1 << 4) | (0 << 3), (2 << 4) | (1 << 3) };
  static const uint32_t shorter[] = { (2 << 4) | (0 << 3), (1 << 4) | (0 << 3) };
  static const uint32_t repeated[] = { (1 << 4) | (0 << 3), (1 << 4) | (0 << 3),
                                       (0 << 4) | (1 << 3)
                                     };
  coap_pdu_code_t code;
  size_t len;

  CU_ASSERT(block1_put(COAP_OPTION_BLOCK1, later, 2, 32, &len, &code) == 1);
  CU_ASSERT(code == COAP_RESPONSE_CODE(408));
  CU_ASSERT(block1_put(COAP_OPTION_BLOCK1, shorter, 2, 48, &len, &code) == 1);
  CU_ASSERT(code == COAP_RESPONSE_CODE(408));
  CU_ASSERT(block1_put(COAP_OPTION_BLOCK1, repeated, 3, 32, &len, &code) == 0);
  CU_ASSERT(len == 32);
}
#endif /* COAP_SERVER_SUPPORT */

CU_pSuite
t_init_block_tests(void) {
  CU_pSuite suite;

  suite = CU_add_suite("block", NULL, NULL);
  if (!suite) {                        /* signal error */
    fprintf(stderr, "W: cannot add block test suite (%s)\n",
            CU_get_error_msg());

    return NULL;
  }

#define BLOCK_TEST(s,t)                                                \
  if (!CU_ADD_TEST(s,t)) {                                              \
    fprintf(stderr, "W: cannot add block test (%s)\n",                \
            CU_get_error_msg());                                      \
  }

#if COAP_Q_BLOCK_SUPPORT
  BLOCK_TEST(suite, t_block_qblock2_size2);
#endif /* COAP_Q_BLOCK_SUPPORT */
#if COAP_SERVER_SUPPORT
  BLOCK_TEST(suite, t_block_echo_get_func);
  BLOCK_TEST(suite, t_block_cancel_observe_get_func);
  BLOCK_TEST(suite, t_block_large_app_block_num);
  BLOCK_TEST(suite, t_block_block1_size1);
  BLOCK_TEST(suite, t_block_block1_after_last);
#endif /* COAP_SERVER_SUPPORT */

  return suite;
}
#endif /* COAP_CLIENT_SUPPORT */
