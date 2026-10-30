/* libcoap unit tests
 *
 * Copyright (C) 2013,2015-2018,2022-2026 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "test_common.h"
#include "test_proxy.h"

#if COAP_CLIENT_SUPPORT
#include <stdio.h>

#define ReturnIf_CU_ASSERT_PTR_NOT_NULL(value) \
  CU_ASSERT_PTR_NOT_NULL(value); \
  if ((void*)value == NULL) return;

static coap_context_t *ctx; /* Holds the coap context for most tests */
static coap_session_t *session; /* Holds a reference-counted session object */

/*
 * A 5.08 response that already has Hop-Limit 1 (e.g. relayed by a proxy
 * from an upstream server) is freed by the loop check and must be dropped.
 */
static void
t_proxy_508_hop_limit(void) {
  coap_address_t addr;
  coap_session_t *s;
  coap_pdu_t *pdu;
  uint8_t hop_limit = 1;

  coap_address_init(&addr);
  addr.size = sizeof(struct sockaddr_in);
  addr.addr.sin.sin_family = AF_INET;
  addr.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.addr.sin.sin_port = htons(5697);
  s = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(s);
  pdu = coap_pdu_init(COAP_MESSAGE_NON, COAP_RESPONSE_CODE(508),
                      coap_new_message_id(s), 1152);
  if (!pdu) {
    CU_FAIL("no pdu");
    coap_session_release(s);
    return;
  }
  coap_add_option(pdu, COAP_OPTION_HOP_LIMIT, 1, &hop_limit);
  coap_add_data(pdu, 9, (const uint8_t *)"192.0.2.1");

  CU_ASSERT(coap_send(s, pdu) == COAP_DROPPED_RESPONSE);
  coap_session_release(s);
}

#if COAP_PROXY_SUPPORT
static coap_pdu_t *
t_proxy_request(const char *proxy_uri) {
  coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_NON, COAP_REQUEST_CODE_GET,
                                  0x1234, 1152);

  if (pdu) {
    coap_add_token(pdu, 1, (const uint8_t *)"p");
    coap_add_option(pdu, COAP_OPTION_PROXY_URI, strlen(proxy_uri),
                    (const uint8_t *)proxy_uri);
  }
  return pdu;
}

/*
 * Removing a tracked client session must drop its proxy requests from
 * every proxy entry, not just from the first one that tracks it.
 */
static void
t_proxy_remove(void) {
  coap_proxy_server_list_t server_list;
  coap_address_t addr;
  coap_session_t *incoming;
  coap_session_t *ongoing;
  coap_pdu_t *request;
  coap_pdu_t *response;
  coap_pdu_t *upstream_rsp;
  coap_bin_const_t token = { 0, NULL };
  size_t i;
  int found = 0;

  memset(&server_list, 0, sizeof(server_list));
  server_list.type = COAP_PROXY_FWD_DYNAMIC;
  server_list.track_client_session = 1;

  coap_address_init(&addr);
  addr.size = sizeof(struct sockaddr_in);
  addr.addr.sin.sin_family = AF_INET;
  addr.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.addr.sin.sin_port = htons(5699);
  incoming = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(incoming);
  response = coap_pdu_init(COAP_MESSAGE_ACK, 0, 0x1234, 1152);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(response);

  /*
   * A forward that fails (multicast not enabled) leaves a tracked entry
   * for incoming with no upstream session
   */
  request = t_proxy_request("coap://224.0.1.187/x");
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(request);
  CU_ASSERT(coap_proxy_forward_request(incoming, request, response, NULL,
                                       NULL, &server_list) == 0);
  coap_delete_pdu(request);

  /* A second upstream server, also tracked for incoming */
  request = t_proxy_request("coap://127.0.0.1:5698/y");
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(request);
  CU_ASSERT(coap_proxy_forward_request(incoming, request, response, NULL,
                                       NULL, &server_list) == 1);
  coap_delete_pdu(request);
  coap_delete_pdu(response);

  ReturnIf_CU_ASSERT_PTR_NOT_NULL(ctx->proxy_list);
  ongoing = NULL;
  for (i = 0; i < ctx->proxy_list_count; i++) {
    if (ctx->proxy_list[i].proxy_req) {
      ongoing = ctx->proxy_list[i].ongoing;
      token = *ctx->proxy_list[i].proxy_req->token_used;
    }
  }
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(ongoing);
  coap_session_reference(ongoing);
  upstream_rsp = coap_pdu_init(COAP_MESSAGE_NON, COAP_RESPONSE_CODE(205),
                               0x4321, 1152);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(upstream_rsp);
  coap_add_token(upstream_rsp, token.length, token.s);

  /* As done on COAP_EVENT_SERVER_SESSION_DEL */
  coap_lock_lock(return);
  coap_proxy_remove_association(incoming, 0);
  coap_lock_unlock();

  for (i = 0; i < ctx->proxy_list_count; i++) {
    coap_proxy_req_t *proxy_req;

    if (ctx->proxy_list[i].incoming == incoming)
      CU_ASSERT_PTR_NULL(ctx->proxy_list[i].ongoing);
    LL_FOREACH(ctx->proxy_list[i].proxy_req, proxy_req) {
      if (proxy_req->incoming == incoming)
        found = 1;
    }
  }
  CU_ASSERT(found == 0);

  coap_session_release(incoming);

  /* A late upstream response must be ignored */
  CU_ASSERT(coap_proxy_forward_response(ongoing, upstream_rsp, NULL) ==
            COAP_RESPONSE_OK);
  coap_delete_pdu(upstream_rsp);
  coap_session_release(ongoing);
}

/*
 * The forward proxy must hand the upstream transfer its own copy of the
 * request body, not the caller's buffer, because that buffer (the reassembled
 * lg_srcv body) is freed once the incoming request has been handled while the
 * upstream Block1 transfer still needs the data for later blocks.
 */
static void
t_proxy_body_copy(void) {
  coap_proxy_server_list_t server_list;
  coap_address_t addr;
  coap_session_t *incoming;
  coap_session_t *ongoing;
  coap_pdu_t *request;
  coap_pdu_t *response;
  const size_t body_len = 1600;
  uint8_t *body;
  size_t i;
  coap_pdu_t *t_pdu;
  uint8_t buf[4];

  coap_debug_set_packet_loss("1-10");
  body = coap_malloc_type(COAP_STRING, body_len);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(body);
  for (i = 0; i < body_len; i++)
    body[i] = (uint8_t)i;

  coap_context_set_block_mode(ctx,
                              COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);

  memset(&server_list, 0, sizeof(server_list));
  server_list.type = COAP_PROXY_FWD_DYNAMIC;
  server_list.track_client_session = 1;

  coap_address_init(&addr);
  addr.size = sizeof(struct sockaddr_in);
  addr.addr.sin.sin_family = AF_INET;
  addr.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.addr.sin.sin_port = htons(5697);
  incoming = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(incoming);
  response = coap_pdu_init(COAP_MESSAGE_ACK, 0, 0x1234, 1152);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(response);

  request = coap_pdu_init(COAP_MESSAGE_NON, COAP_REQUEST_CODE_POST, 0x1235, 1152);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(request);
  coap_add_token(request, 1, (const uint8_t *)"q");
  coap_add_option(request, COAP_OPTION_PROXY_URI,
                  strlen("coap://127.0.0.1:5696/z"),
                  (const uint8_t *)"coap://127.0.0.1:5696/z");
  /* Present the body as a single reassembled body owned outside the PDU */
  request->body_data = body;
  request->body_length = body_len;
  request->body_total = body_len;

  CU_ASSERT(coap_proxy_forward_request(incoming, request, response, NULL,
                                       NULL, &server_list) == 1);
  request->body_data = NULL;
  coap_delete_pdu(request);
  coap_delete_pdu(response);
  coap_free_type(COAP_STRING, body);

  ReturnIf_CU_ASSERT_PTR_NOT_NULL(ctx->proxy_list);
  ongoing = NULL;
  for (i = 0; i < ctx->proxy_list_count; i++) {
    if (ctx->proxy_list[i].proxy_req && ctx->proxy_list[i].ongoing &&
        ctx->proxy_list[i].ongoing->lg_xmit) {
      ongoing = ctx->proxy_list[i].ongoing;
      break;
    }
  }
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(ongoing);

  /* Fake a 2.31 response to send the second block */
  t_pdu = ctx->proxy_list[i].ongoing->lg_xmit->sent_pdu;
  response = coap_pdu_init(COAP_MESSAGE_NON, COAP_RESPONSE_CODE(231), 0, 1152);
  response->mid = t_pdu->mid;
  coap_add_token(response, t_pdu->actual_token.length, t_pdu->actual_token.s);
  coap_add_option(response, COAP_OPTION_BLOCK1, coap_encode_var_safe(buf, sizeof(buf),
                  (0 << 4) |
                  (1 << 3) |
                  6),
                  buf);

  coap_lock_lock(return);
  coap_dispatch(ctx, ongoing, response);
  coap_lock_unlock();
  coap_delete_pdu(response);

  coap_lock_lock(return);
  coap_proxy_remove_association(incoming, 0);
  coap_lock_unlock();
  coap_session_release(incoming);
  coap_debug_set_packet_loss("0%");
}
#endif /* COAP_PROXY_SUPPORT */

/* This function creates a set of nodes for testing. These nodes
 * will exist for all tests and are modified by coap_insert_node()
 * and coap_remove_from_queue().
 */
static int
t_proxy_tests_create(void) {
  coap_address_t addr;
  coap_address_init(&addr);

  addr.size = sizeof(struct sockaddr_in6);
  addr.addr.sin6.sin6_family = AF_INET6;
  addr.addr.sin6.sin6_addr = in6addr_loopback;
  addr.addr.sin6.sin6_port = htons(COAP_DEFAULT_PORT);

  ctx = coap_new_context(&addr);

  if (ctx != NULL) {
    session = coap_new_client_session(ctx, NULL, &addr, COAP_PROTO_UDP);
  }

  return (ctx == NULL) || (session == NULL);
}

static int
t_proxy_tests_remove(void) {
  coap_free_context(ctx);
  return 0;
}

CU_pSuite
t_init_proxy_tests(void) {
  CU_pSuite suite;

  suite = CU_add_suite("proxyon",
                       t_proxy_tests_create, t_proxy_tests_remove);
  if (!suite) {                        /* signal error */
    fprintf(stderr, "W: cannot add proxy test suite (%s)\n",
            CU_get_error_msg());

    return NULL;
  }

#define SESSION_TEST(s,t)                                              \
  if (!CU_ADD_TEST(s,t)) {                                              \
    fprintf(stderr, "W: cannot add session test (%s)\n",              \
            CU_get_error_msg());                                      \
  }

  SESSION_TEST(suite, t_proxy_508_hop_limit);
#if COAP_PROXY_SUPPORT
  SESSION_TEST(suite, t_proxy_remove);
  SESSION_TEST(suite, t_proxy_body_copy);
#endif /* COAP_PROXY_SUPPORT */

  return suite;
}
#endif /* COAP_CLIENT_SUPPORT */
