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
#include "test_session.h"

#if COAP_CLIENT_SUPPORT
#include <stdio.h>

/* The error threshold for timeout calculations. The precision of
 * coap_calc_timeout() is assumed to be sufficient if the resulting
 * value deviates at most FP_ERR_THRESHOLD percent from the value that
 * was calculated with double precision floating point arithmetic
 * instead of fixed point integers.
 */
#define FP_ERR_THRESHOLD (1.0)

/* The maximum number of bits for fixed point integer representation.
 * This number must be identical to the definition of MAX_BITS in
 * coap_net.c
 */
#define MAX_BITS 8

#define ReturnIf_CU_ASSERT_PTR_NOT_NULL(value) \
  CU_ASSERT_PTR_NOT_NULL(value); \
  if ((void*)value == NULL) return;

static coap_context_t *ctx; /* Holds the coap context for most tests */
static coap_session_t *session; /* Holds a reference-counted session object */

COAP_STATIC_INLINE int
fpeq(const coap_fixed_point_t a, const coap_fixed_point_t b) {
  return (a.integer_part == b.integer_part) &&
         (a.fractional_part == b.fractional_part);
}

#if COAP_SERVER_SUPPORT && COAP_ASYNC_SUPPORT
static coap_address_t observe_expected_local;
static coap_async_t *observe_async;
static unsigned int observe_calls;

static void
observe_address_handler(coap_resource_t *resource COAP_UNUSED,
                        coap_session_t *s,
                        const coap_pdu_t *request,
                        const coap_string_t *query COAP_UNUSED,
                        coap_pdu_t *response) {
  observe_calls++;
  CU_ASSERT(coap_address_equals(&s->addr_info.local, &observe_expected_local));
  observe_async = coap_register_async(s, request, 0);
  CU_ASSERT_PTR_NOT_NULL(observe_async);
  if (observe_async)
    CU_ASSERT(coap_address_equals(&observe_async->local_if, &observe_expected_local));
  coap_pdu_set_type(response, COAP_MESSAGE_NON);
}

static void
t_observe_local_address(void) {
  coap_address_t saved_local;
  coap_address_copy(&saved_local, &session->addr_info.local);
  for (unsigned int non = 0; non < 2; non++) {
    coap_resource_t *resource = coap_resource_init(coap_make_str_const("address-test"), 0);
    coap_pdu_t *request = coap_pdu_init(non ? COAP_MESSAGE_NON : COAP_MESSAGE_CON,
                                        COAP_REQUEST_CODE_GET, 1, 128);
    ReturnIf_CU_ASSERT_PTR_NOT_NULL(resource);
    ReturnIf_CU_ASSERT_PTR_NOT_NULL(request);
    coap_add_token(request, 1, (const uint8_t *)"t");
    coap_add_option(request, COAP_OPTION_OBSERVE, 0, NULL);
    coap_add_option(request, COAP_OPTION_URI_PATH, 12, (const uint8_t *)"address-test");
    coap_resource_set_get_observable(resource, 1);
    coap_register_request_handler(resource, COAP_REQUEST_GET, observe_address_handler);
    coap_add_resource(ctx, resource);
    coap_address_copy(&session->addr_info.local, &saved_local);
    coap_address_copy(&observe_expected_local, &saved_local);
    coap_lock_lock(return);
    coap_subscription_t *obs = coap_add_observer(resource, session, &request->actual_token, request);
    coap_lock_unlock();
    CU_ASSERT_PTR_NOT_NULL(obs);
    if (!obs)
      return;

    for (unsigned int renewal = 0; renewal < 2; renewal++) {
      if (renewal) {
        coap_address_set_port(&observe_expected_local, 12345);
        coap_address_copy(&session->addr_info.local, &observe_expected_local);
        coap_lock_lock(return);
        CU_ASSERT(coap_add_observer(resource, session, &request->actual_token, request) == obs);
        coap_lock_unlock();
      }
      /* Reproduce a multicast packet from the same peer overwriting the session. */
      session->addr_info.local.addr.sin6.sin6_addr = in6addr_any;
      session->addr_info.local.addr.sin6.sin6_addr.s6_addr[0] = 0xff;
      session->addr_info.local.addr.sin6.sin6_addr.s6_addr[1] = 0x02;
      session->addr_info.local.addr.sin6.sin6_addr.s6_addr[15] = 0xfd;
      observe_calls = 0;
      observe_async = NULL;
      coap_resource_notify_observers(resource, NULL);
      coap_check_notify(ctx);
      CU_ASSERT(observe_calls == 1);
      CU_ASSERT_PTR_NOT_NULL(observe_async);
      if (observe_async)
        coap_free_async(session, observe_async);
    }
    coap_delete_pdu(request);
    coap_delete_resource(ctx, resource);
  }
  coap_address_copy(&session->addr_info.local, &saved_local);
}
#endif

#if COAP_SERVER_SUPPORT
static void
notify_fail_handler(coap_resource_t *resource COAP_UNUSED,
                    coap_session_t *s COAP_UNUSED,
                    const coap_pdu_t *request COAP_UNUSED,
                    const coap_string_t *query COAP_UNUSED,
                    coap_pdu_t *response) {
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_add_data(response, 1, (const uint8_t *)"x");
}

/* A notification that cannot be sent disconnects the session, which removes
 * all of its observers while the list of observers is being walked (the
 * use of a removed observer is reported by ASan or valgrind) */
static void
t_session_notify_send_fail(void) {
  static const char *queries[] = { "a", "b", "c" };
  coap_context_t *nctx;
  coap_session_t *nsession;
  coap_resource_t *r;
  coap_address_t addr;
  coap_subscription_t *s;
  unsigned int count = 0;
  size_t i;

  coap_address_init(&addr);
  addr.size = sizeof(struct sockaddr_in6);
  addr.addr.sin6.sin6_family = AF_INET6;
  addr.addr.sin6.sin6_addr = in6addr_loopback;
  addr.addr.sin6.sin6_port = htons(20004);

  nctx = coap_new_context(NULL);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(nctx);
  r = coap_resource_init(coap_make_str_const("obs"), 0);
  if (!r) {
    CU_FAIL("no resource");
    coap_free_context(nctx);
    return;
  }
  coap_resource_set_get_observable(r, 1);
  coap_register_request_handler(r, COAP_REQUEST_GET, notify_fail_handler);
  coap_add_resource(nctx, r);
  nsession = coap_new_client_session(nctx, NULL, &addr, COAP_PROTO_UDP);
  if (!nsession) {
    CU_FAIL("no session");
    coap_free_context(nctx);
    return;
  }

  coap_lock_lock(return);
  for (i = 0; i < sizeof(queries) / sizeof(queries[0]); i++) {
    coap_pdu_t *request = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET,
                                        coap_new_message_id_lkd(nsession), 64);
    uint8_t token = (uint8_t)('1' + i);

    CU_ASSERT_PTR_NOT_NULL(request);
    if (!request)
      continue;
    coap_add_token(request, 1, &token);
    coap_add_option(request, COAP_OPTION_OBSERVE, 0, NULL);
    coap_add_option(request, COAP_OPTION_URI_PATH, 3, (const uint8_t *)"obs");
    coap_add_option(request, COAP_OPTION_URI_QUERY, 1,
                    (const uint8_t *)queries[i]);
    CU_ASSERT_PTR_NOT_NULL(coap_add_observer(r, nsession, &request->actual_token,
                                             request));
    coap_delete_pdu_lkd(request);
  }
  /* The second notification fails to be sent */
  coap_debug_set_packet_fail("2");
  coap_resource_notify_observers_lkd(r, COAP_NOT_DELETING_RESOURCE);
  coap_debug_set_packet_fail("0%");
  coap_lock_unlock();

  /* The failed send dropped the session's observers */
  LL_COUNT(r->subscribers, s, count);
  CU_ASSERT(count == 0);

  coap_session_release(nsession);
  coap_free_context(nctx);
}
#endif /* COAP_SERVER_SUPPORT */

static void
t_session1(void) {
  CU_ASSERT(session->ref == 1);

  coap_session_reference(session);
  CU_ASSERT(session->ref == 2);

  coap_session_release(session);
  CU_ASSERT(session->ref == 1);
}

static void
t_session2(void) {
  CU_ASSERT(session->max_retransmit == COAP_DEFAULT_MAX_RETRANSMIT);
  CU_ASSERT(fpeq(session->ack_timeout, COAP_DEFAULT_ACK_TIMEOUT));
  CU_ASSERT(fpeq(session->ack_random_factor, COAP_DEFAULT_ACK_RANDOM_FACTOR));

  CU_ASSERT(coap_session_get_max_retransmit(session) == COAP_DEFAULT_MAX_RETRANSMIT);
  CU_ASSERT(fpeq(coap_session_get_ack_timeout(session), COAP_DEFAULT_ACK_TIMEOUT));
  CU_ASSERT(fpeq(coap_session_get_ack_random_factor(session), COAP_DEFAULT_ACK_RANDOM_FACTOR));
}

COAP_STATIC_INLINE double
fp_to_double(const coap_fixed_point_t fp) {
  return fp.integer_part + fp.fractional_part/1000.0;
}

COAP_STATIC_INLINE double
q_to_double(uint8_t q) {
  return (double)(q) / (1 << MAX_BITS);
}

/* Calculates the timeout using the following formula:
 *
 * COAP_TICKS_PER_SECOND * ack_timeout * (1 + (ack_random_factor - 1) * r)
 *
 * where @p r is the randomization value represented as Q0.MAX_BITS.
 * This function returns the result as unsigned int to be
 * checked against the result of coap_calc_timeout().
 */
COAP_STATIC_INLINE unsigned int
timeout(const coap_fixed_point_t ack_timeout,
        const coap_fixed_point_t ack_random_factor,
        uint8_t r) {
  const unsigned int ctps = COAP_TICKS_PER_SECOND;
  double ato = fp_to_double(ack_timeout);
  double rnd = 1 + (fp_to_double(ack_random_factor) - 1.0) * q_to_double(r);

  return (unsigned int)(ctps * ato * rnd);
}

/* Checks if @p v is within FP_ERR_THRESHOLD percent of @p ref.  This
 * function returns 1 if it is within range, 0 otherwise.
 */
COAP_STATIC_INLINE int
good_enough(unsigned int v, unsigned int ref) {
#define delta(a,b) (((a) < (b)) ? ((b) - (a)) : ((a) - (b)))
  return (delta(v,ref) / 100.0) <= FP_ERR_THRESHOLD;
}

static void
t_session3(void) {
  const coap_fixed_point_t ato = COAP_DEFAULT_ACK_TIMEOUT;
  const coap_fixed_point_t arf = COAP_DEFAULT_ACK_RANDOM_FACTOR;

  CU_ASSERT(good_enough(coap_calc_timeout(session, 0), timeout(ato, arf, 0)));
  CU_ASSERT(good_enough(coap_calc_timeout(session, 12), timeout(ato, arf, 12)));
  CU_ASSERT(good_enough(coap_calc_timeout(session, 55), timeout(ato, arf, 55)));
  CU_ASSERT(good_enough(coap_calc_timeout(session, 83), timeout(ato, arf, 83)));
  CU_ASSERT(good_enough(coap_calc_timeout(session, 117), timeout(ato, arf, 117)));
  CU_ASSERT(good_enough(coap_calc_timeout(session, 210), timeout(ato, arf, 210)));
  CU_ASSERT(good_enough(coap_calc_timeout(session, 255), timeout(ato, arf, 255)));
}

static void
t_session4(void) {
  const coap_fixed_point_t ato = {8,300};
  const coap_fixed_point_t arf = {2,011};

  coap_session_set_ack_timeout(session, ato);
  coap_session_set_ack_random_factor(session, arf);

  CU_ASSERT(fpeq(coap_session_get_ack_timeout(session), ato));
  CU_ASSERT(fpeq(coap_session_get_ack_random_factor(session), arf));

  CU_ASSERT(good_enough(coap_calc_timeout(session, 0), timeout(ato, arf, 0)));
  CU_ASSERT(good_enough(coap_calc_timeout(session, 12), timeout(ato, arf, 12)));
  CU_ASSERT(good_enough(coap_calc_timeout(session, 55), timeout(ato, arf, 55)));
  CU_ASSERT(good_enough(coap_calc_timeout(session, 83), timeout(ato, arf, 83)));
  CU_ASSERT(good_enough(coap_calc_timeout(session, 117), timeout(ato, arf, 117)));
  CU_ASSERT(good_enough(coap_calc_timeout(session, 210), timeout(ato, arf, 210)));
  CU_ASSERT(good_enough(coap_calc_timeout(session, 255), timeout(ato, arf, 255)));
}

static void
t_session5(void) {
  coap_session_release(session);

  CU_ASSERT_PTR_NULL(ctx->sessions);
  session = NULL;
}

/* Test 6 creates a new session after the original session has been
 * released by test 5 */
static void
t_session6(void) {
  coap_address_t laddr, saddr;
  coap_address_init(&laddr);
  coap_address_init(&saddr);

  CU_ASSERT_PTR_NULL(session);

  laddr.size = sizeof(struct sockaddr_in6);
  laddr.addr.sin6.sin6_family = AF_INET6;
  laddr.addr.sin6.sin6_addr = in6addr_loopback;
  laddr.addr.sin6.sin6_port = htons(COAP_DEFAULT_PORT);

  coap_address_copy(&saddr, &laddr);
  saddr.addr.sin6.sin6_port = htons(20000);

  session = coap_new_client_session(ctx, &saddr, &laddr, COAP_PROTO_UDP);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(session);
  ReturnIf_CU_ASSERT_PTR_NOT_NULL(ctx->sessions);
  CU_ASSERT(session->state == COAP_SESSION_STATE_ESTABLISHED);
  coap_session_release(session);
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
t_session_proxy_remove(void) {
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
#endif /* COAP_PROXY_SUPPORT */

/* This function creates a set of nodes for testing. These nodes
 * will exist for all tests and are modified by coap_insert_node()
 * and coap_remove_from_queue().
 */
static int
t_session_tests_create(void) {
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
t_session_tests_remove(void) {
  coap_free_context(ctx);
  return 0;
}

CU_pSuite
t_init_session_tests(void) {
  CU_pSuite suite;

  suite = CU_add_suite("session",
                       t_session_tests_create, t_session_tests_remove);
  if (!suite) {                        /* signal error */
    fprintf(stderr, "W: cannot add session test suite (%s)\n",
            CU_get_error_msg());

    return NULL;
  }

#define SESSION_TEST(s,t)                                              \
  if (!CU_ADD_TEST(s,t)) {                                              \
    fprintf(stderr, "W: cannot add session test (%s)\n",              \
            CU_get_error_msg());                                      \
  }

#if COAP_SERVER_SUPPORT && COAP_ASYNC_SUPPORT
  SESSION_TEST(suite, t_observe_local_address);
#endif
  SESSION_TEST(suite, t_session1);
  SESSION_TEST(suite, t_session2);
  SESSION_TEST(suite, t_session3);
  SESSION_TEST(suite, t_session4);
  SESSION_TEST(suite, t_session5);
#if COAP_SERVER_SUPPORT
  SESSION_TEST(suite, t_session_notify_send_fail);
#endif /* COAP_SERVER_SUPPORT */
  SESSION_TEST(suite, t_session6);
#if COAP_PROXY_SUPPORT
  SESSION_TEST(suite, t_session_proxy_remove);
#endif /* COAP_PROXY_SUPPORT */

  return suite;
}
#endif /* COAP_CLIENT_SUPPORT */
