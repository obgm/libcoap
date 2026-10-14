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

#if COAP_SERVER_SUPPORT
  BLOCK_TEST(suite, t_block_echo_get_func);
  BLOCK_TEST(suite, t_block_cancel_observe_get_func);
  BLOCK_TEST(suite, t_block_large_app_block_num);
#endif /* COAP_SERVER_SUPPORT */

  return suite;
}
#endif /* COAP_CLIENT_SUPPORT */
